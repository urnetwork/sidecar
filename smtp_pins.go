//go:build !sidecar_http && !ios_extension

// §14.4's pins (D-SMTP-2, owner decision 438, QD-938): the best TLS level each MX host reached for each
// recipient domain, held SmtpSenderSettings.PinTimeout from the last send to that domain through that
// host that reached it, below which nothing is sent to the domain through the host while it holds.
// Beside them each MX host's post-TLS mode from its last session, and each recipient domain's last
// session, its host and mode, which SmtpSender.Check reports as the domain's mode for as long as a pin
// would hold (§14.5); and the envelope group count an MX host needed on the one retry after its replies
// overflowed every shape, kept beside its mode as long, so later sends to it start there (DESIGN-DETAILS
// 3.5, 3.7's SMTP-M9-08).
//
// A pin is keyed by the pair (recipient domain, MX host), both lowercase with no trailing dot, since TL1
// and TL2 are properties of the recipient domain: its MX RRset validating under DNSSEC before the host's
// TLSA counts, and its own MTA-STS policy. So a shared MX host that reached TL1 or TL2 for one domain
// refuses no other domain that publishes less, while a send to a domain through a host below the level
// it reached there is refused as a downgrade, a malicious edge stripping TLSA for a domain that reached
// TL1 included. A domain never sent to through a host carries no pin there, even where the host holds
// one for another domain. The mode stays the host's alone: it is what the host's post-TLS EHLO offered,
// whichever domain the session was for.
//
// A level is better the lower its number, TL1 first. Raising to a better level, or reaching the pinned
// one again, restarts the pair's 90 days; reaching a worse one is refused and changes nothing, and Raise
// makes that check and the raise one step, so two sends to one domain through one host cannot both pass
// a pin that one of them raises. A lapsed pin is no pin: the next send pins whatever it reaches. A TL4
// pin refuses nothing, and no TL4 allowance lifts a pin (SmtpTlsPolicy).
//
// Layout: one sealed file, tls-pins, in the sender's directory of the store (§5.9's <component>/), as
// JSON rewritten whole by Commit, so a kill leaves the old pins or the new ones: each pair's level
// (pins, domain beside mx_host), each host's mode (modes), each domain's last session (domains) and each
// host's envelope group count (group_counts, which a file written before it lacks, read as none).
// Hosts and domains are names this device mails, so they live inside the sealed file and never in a
// file's name, which the store keeps in the clear. A file that fails to open or parse is
// ErrSidecarStoreFailed, never read as no pins, since a pin read as absent would let a downgrade through
// (D-CORE-15), and a store that cannot answer holds the send. The one record dropped rather than refused
// is a pin that names no recipient domain, which only this format before pins were keyed by the pair
// wrote: no release holds such a file, so the format changed in place, and a host's level cannot be
// given to any domain, so load drops each one and logs how many, naming none, and the next write leaves
// them out. Writes serialize on writeLock, never taken under stateLock, and memory changes only once a
// write has landed. No error or log line names a host or domain (I-13).
//
// Each kind of record is bounded by PinMaxCount, pins counting pairs: past it the one closest to lapsing
// leaves first.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10). Safe for concurrent use.

package sidecar

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

// Format values of the sealed file.
const (
	// The file's name in the sender's directory.
	smtpPinFileName = "tls-pins"
	// Its format version. Keying pins by the pair changed version 1 in place (QD-938).
	smtpPinFileVersion = 1
)

var (
	// A level below the pin the recipient domain holds on the MX host: a downgrade, refused (D-SMTP-2).
	ErrSmtpPinBelow = errors.New("smtp pin: below the domain's pin on the host")
	// A host, domain, level or mode outside its form.
	errSmtpPinArgument = errors.New("smtp pin: invalid argument")
)

// One recipient domain's pin on one MX host, with the host's post-TLS mode.
type SmtpPin struct {
	// Lowercase, with no trailing dot.
	RecipientDomain string
	// Lowercase, with no trailing dot.
	MxHost string
	// The best level the host reached for the domain while the pin held, TL1 to TL4. Nothing below it is
	// sent to the domain through the host.
	Level SmtpTlsLevel
	// When the host last reached Level for the domain: the pin holds PinTimeout from here.
	PinTime time.Time
	// The post-TLS mode of the host's last session that reached its EHLO reply, whichever domain it was
	// for, unknown when none did.
	Mode SmtpMode
	// When Mode was seen. It reads as unknown PinTimeout after.
	ModeTime time.Time
	// The most commands one envelope group held on the host's last retry after its replies overflowed every
	// shape, 0 for none: SmtpProofJob.EnvelopeGroupMaxCount for later sends through it (DESIGN-DETAILS 3.5).
	EnvelopeGroupMaxCount int
}

// When the pin stops holding.
func (self *SmtpPin) ExpireTime(timeout time.Duration) time.Time {
	return self.PinTime.Add(timeout)
}

// A pin's key: both names lowercase, with no trailing dot.
type smtpPinPair struct {
	recipientDomain string
	mxHost          string
}

// The pair of recipientDomain and mxHost in their one form, and whether both are RFC 5321's Domain.
func smtpPinPairOf(recipientDomain string, mxHost string) (smtpPinPair, bool) {
	domain, domainOk := smtpTlsName(recipientDomain)
	host, hostOk := smtpTlsName(mxHost)
	return smtpPinPair{recipientDomain: domain, mxHost: host}, domainOk && hostOk
}

// By domain, then host: the order the file lists pairs in.
func (self smtpPinPair) compare(other smtpPinPair) int {
	return cmp.Or(strings.Compare(self.recipientDomain, other.recipientDomain), strings.Compare(self.mxHost, other.mxHost))
}

// One pair's pinned level.
type smtpPinLevel struct {
	level SmtpTlsLevel
	// when the pair last reached level
	pinTime time.Time
}

// Whether the level still holds at now.
func (self smtpPinLevel) heldAt(now time.Time, timeout time.Duration) bool {
	return now.Before(self.pinTime.Add(timeout))
}

// One MX host's post-TLS mode, from its last session.
type smtpPinMode struct {
	mode SmtpMode
	time time.Time
}

// One MX host's envelope group count, from the retry that needed it.
type smtpPinGroupCount struct {
	count int
	time  time.Time
}

// One recipient domain's last session.
type smtpPinDomain struct {
	mxHost string
	mode   SmtpMode
	time   time.Time
}

// The stored file.
type smtpPinFile struct {
	Version     int                        `json:"version"`
	Pins        []*smtpPinRecord           `json:"pins"`
	Modes       []*smtpPinModeRecord       `json:"modes"`
	Domains     []*smtpPinDomainRecord     `json:"domains"`
	GroupCounts []*smtpPinGroupCountRecord `json:"group_counts,omitempty"`
}

// A pin's stored form: one pair's level, and when the pair last reached it.
type smtpPinRecord struct {
	Domain    string `json:"domain"`
	MxHost    string `json:"mx_host"`
	Level     uint32 `json:"level"`
	PinTimeMs int64  `json:"pin_time_ms"`
}

// A host's mode's stored form.
type smtpPinModeRecord struct {
	MxHost     string `json:"mx_host"`
	Mode       uint32 `json:"mode"`
	ModeTimeMs int64  `json:"mode_time_ms"`
}

// A host's envelope group count's stored form.
type smtpPinGroupCountRecord struct {
	MxHost string `json:"mx_host"`
	Count  int    `json:"count"`
	TimeMs int64  `json:"time_ms"`
}

// A domain's stored form.
type smtpPinDomainRecord struct {
	Domain string `json:"domain"`
	MxHost string `json:"mx_host"`
	Mode   uint32 `json:"mode"`
	TimeMs int64  `json:"time_ms"`
}

// Every pin, mode and domain session, as memory holds them.
type smtpPinState struct {
	pairLevels        map[smtpPinPair]smtpPinLevel
	mxHostModes       map[string]smtpPinMode
	domainSessions    map[string]smtpPinDomain
	mxHostGroupCounts map[string]smtpPinGroupCount
}

// No pins, no modes and no sessions.
func newSmtpPinState() *smtpPinState {
	return &smtpPinState{
		pairLevels:        map[smtpPinPair]smtpPinLevel{},
		mxHostModes:       map[string]smtpPinMode{},
		domainSessions:    map[string]smtpPinDomain{},
		mxHostGroupCounts: map[string]smtpPinGroupCount{},
	}
}

// A copy whose maps share nothing with this one.
func (self *smtpPinState) clone() *smtpPinState {
	return &smtpPinState{
		pairLevels:        maps.Clone(self.pairLevels),
		mxHostModes:       maps.Clone(self.mxHostModes),
		domainSessions:    maps.Clone(self.domainSessions),
		mxHostGroupCounts: maps.Clone(self.mxHostGroupCounts),
	}
}

// pair's pin at level, with its host's mode as stored.
func (self *smtpPinState) pin(pair smtpPinPair, level smtpPinLevel) *SmtpPin {
	pin := &SmtpPin{RecipientDomain: pair.recipientDomain, MxHost: pair.mxHost, Level: level.level, PinTime: level.pinTime}
	if mode, ok := self.mxHostModes[pair.mxHost]; ok {
		pin.Mode, pin.ModeTime = mode.mode, mode.time
	}
	if groupCount, ok := self.mxHostGroupCounts[pair.mxHost]; ok {
		pin.EnvelopeGroupMaxCount = groupCount.count
	}
	return pin
}

// The pin that holds for pair at now, or nil.
func (self *smtpPinState) pinAt(pair smtpPinPair, now time.Time, timeout time.Duration) *SmtpPin {
	level, ok := self.pairLevels[pair]
	if !ok || !level.heldAt(now, timeout) {
		return nil
	}
	return self.pin(pair, level)
}

// The pins, host modes and domain sessions of one network's sender.
type SmtpPinStore struct {
	store    SidecarStore
	settings *SmtpSenderSettings
	clock    Clock
	log      Logger

	// serializes the load and every write, outside stateLock
	writeLock sync.Mutex

	stateLock sync.Mutex
	loaded    bool
	state     *smtpPinState
}

// The pins in store, the sender's directory, under settings, which must have passed validate, on clock
// (nil is real time), logging to log (nil is silence).
func NewSmtpPinStore(store SidecarStore, settings *SmtpSenderSettings, clock Clock, log Logger) *SmtpPinStore {
	if log == nil {
		log = NewNoopLogger()
	}
	return &SmtpPinStore{
		store:    store,
		settings: settings,
		clock:    clockOrReal(clock),
		log:      log,
		state:    newSmtpPinState(),
	}
}

// Whether level is one a pin can hold.
func smtpPinLevelValid(level SmtpTlsLevel) bool {
	return SmtpTlsLevelDane <= level && level <= SmtpTlsLevelUnauthenticated
}

// The plaintext of a sealed file, and false when nothing is stored there.
func smtpReadStoreFile(store SidecarStore, name string) ([]byte, bool, error) {
	reader, err := store.Open(name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// Replaces a sealed file durably.
func smtpWriteStoreFile(store SidecarStore, name string, data []byte) error {
	writer, err := store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// The pair and level a stored pin gives, or false for anything but this version's well-formed pin:
// both names in their one form, a level a pin can hold, and its time.
func (self *smtpPinRecord) level() (smtpPinPair, smtpPinLevel, bool) {
	pair, ok := smtpPinPairOf(self.Domain, self.MxHost)
	level := SmtpTlsLevel(self.Level)
	if !ok || pair.recipientDomain != self.Domain || pair.mxHost != self.MxHost || !smtpPinLevelValid(level) || self.PinTimeMs <= 0 {
		return smtpPinPair{}, smtpPinLevel{}, false
	}
	return pair, smtpPinLevel{level: level, pinTime: time.UnixMilli(self.PinTimeMs)}, true
}

// The file's state, and how many pins it dropped for naming no recipient domain (this file's header),
// refusing anything else but this version's well-formed records, each name's once: ErrSidecarStoreFailed.
func decodeSmtpPinFile(data []byte) (*smtpPinState, int, error) {
	file := &smtpPinFile{}
	if err := json.Unmarshal(data, file); err != nil || file.Version != smtpPinFileVersion {
		return nil, 0, fmt.Errorf("%w: smtp pins do not parse", ErrSidecarStoreFailed)
	}
	state := newSmtpPinState()
	droppedCount := 0
	for _, record := range file.Pins {
		if record == nil {
			return nil, 0, fmt.Errorf("%w: an smtp pin is malformed", ErrSidecarStoreFailed)
		}
		if record.Domain == "" {
			// the format before pins were keyed by the pair: a host's level, which no domain earned alone
			droppedCount += 1
			continue
		}
		pair, level, ok := record.level()
		if !ok {
			return nil, 0, fmt.Errorf("%w: an smtp pin is malformed", ErrSidecarStoreFailed)
		}
		if _, ok := state.pairLevels[pair]; ok {
			return nil, 0, fmt.Errorf("%w: an smtp pin is stored twice", ErrSidecarStoreFailed)
		}
		state.pairLevels[pair] = level
	}
	for _, record := range file.Modes {
		if record == nil {
			return nil, 0, fmt.Errorf("%w: an smtp host mode is malformed", ErrSidecarStoreFailed)
		}
		mxHost, ok := smtpTlsName(record.MxHost)
		mode := SmtpMode(record.Mode)
		if !ok || mxHost != record.MxHost || !mode.known() || mode == SmtpModeUnknown || record.ModeTimeMs <= 0 {
			return nil, 0, fmt.Errorf("%w: an smtp host mode is malformed", ErrSidecarStoreFailed)
		}
		if _, ok := state.mxHostModes[mxHost]; ok {
			return nil, 0, fmt.Errorf("%w: an smtp host mode is stored twice", ErrSidecarStoreFailed)
		}
		state.mxHostModes[mxHost] = smtpPinMode{mode: mode, time: time.UnixMilli(record.ModeTimeMs)}
	}
	for _, record := range file.Domains {
		if record == nil {
			return nil, 0, fmt.Errorf("%w: an smtp domain session is malformed", ErrSidecarStoreFailed)
		}
		pair, ok := smtpPinPairOf(record.Domain, record.MxHost)
		mode := SmtpMode(record.Mode)
		if !ok || pair.recipientDomain != record.Domain || pair.mxHost != record.MxHost || !mode.known() || mode == SmtpModeUnknown || record.TimeMs <= 0 {
			return nil, 0, fmt.Errorf("%w: an smtp domain session is malformed", ErrSidecarStoreFailed)
		}
		if _, ok := state.domainSessions[pair.recipientDomain]; ok {
			return nil, 0, fmt.Errorf("%w: an smtp domain session is stored twice", ErrSidecarStoreFailed)
		}
		state.domainSessions[pair.recipientDomain] = smtpPinDomain{mxHost: pair.mxHost, mode: mode, time: time.UnixMilli(record.TimeMs)}
	}
	for _, record := range file.GroupCounts {
		if record == nil {
			return nil, 0, fmt.Errorf("%w: an smtp host group count is malformed", ErrSidecarStoreFailed)
		}
		mxHost, ok := smtpTlsName(record.MxHost)
		if !ok || mxHost != record.MxHost || record.Count <= 0 || record.TimeMs <= 0 {
			return nil, 0, fmt.Errorf("%w: an smtp host group count is malformed", ErrSidecarStoreFailed)
		}
		if _, ok := state.mxHostGroupCounts[mxHost]; ok {
			return nil, 0, fmt.Errorf("%w: an smtp host group count is stored twice", ErrSidecarStoreFailed)
		}
		state.mxHostGroupCounts[mxHost] = smtpPinGroupCount{count: record.Count, time: time.UnixMilli(record.TimeMs)}
	}
	return state, droppedCount, nil
}

// The file's bytes, records sorted so one state always writes the same file.
func (self *smtpPinState) encode() ([]byte, error) {
	file := &smtpPinFile{
		Version: smtpPinFileVersion,
		Pins:    []*smtpPinRecord{},
		Modes:   []*smtpPinModeRecord{},
		Domains: []*smtpPinDomainRecord{},
	}
	for _, pair := range slices.SortedFunc(maps.Keys(self.pairLevels), smtpPinPair.compare) {
		level := self.pairLevels[pair]
		file.Pins = append(file.Pins, &smtpPinRecord{
			Domain:    pair.recipientDomain,
			MxHost:    pair.mxHost,
			Level:     uint32(level.level),
			PinTimeMs: level.pinTime.UnixMilli(),
		})
	}
	for _, mxHost := range slices.Sorted(maps.Keys(self.mxHostModes)) {
		mode := self.mxHostModes[mxHost]
		file.Modes = append(file.Modes, &smtpPinModeRecord{MxHost: mxHost, Mode: uint32(mode.mode), ModeTimeMs: mode.time.UnixMilli()})
	}
	for _, domain := range slices.Sorted(maps.Keys(self.domainSessions)) {
		session := self.domainSessions[domain]
		file.Domains = append(file.Domains, &smtpPinDomainRecord{
			Domain: domain,
			MxHost: session.mxHost,
			Mode:   uint32(session.mode),
			TimeMs: session.time.UnixMilli(),
		})
	}
	for _, mxHost := range slices.Sorted(maps.Keys(self.mxHostGroupCounts)) {
		groupCount := self.mxHostGroupCounts[mxHost]
		file.GroupCounts = append(file.GroupCounts, &smtpPinGroupCountRecord{MxHost: mxHost, Count: groupCount.count, TimeMs: groupCount.time.UnixMilli()})
	}
	return json.Marshal(file)
}

// Past maxCount, deletes the entries that sort first under compare: the ones closest to lapsing.
func smtpPinEvict[K comparable, V any](entries map[K]V, maxCount int, compare func(a K, b K) int) {
	overCount := len(entries) - maxCount
	if overCount <= 0 {
		return
	}
	for _, key := range slices.SortedFunc(maps.Keys(entries), compare)[:overCount] {
		delete(entries, key)
	}
}

// Drops what has lapsed at now, then past maxCount of each kind the entries closest to lapsing, ties
// by name: pins count pairs, so one host's pins for many domains count one each.
func (self *smtpPinState) prune(now time.Time, timeout time.Duration, maxCount int) {
	maps.DeleteFunc(self.pairLevels, func(pair smtpPinPair, level smtpPinLevel) bool {
		return !level.heldAt(now, timeout)
	})
	maps.DeleteFunc(self.mxHostModes, func(mxHost string, mode smtpPinMode) bool {
		return !now.Before(mode.time.Add(timeout))
	})
	maps.DeleteFunc(self.domainSessions, func(domain string, session smtpPinDomain) bool {
		return !now.Before(session.time.Add(timeout))
	})
	maps.DeleteFunc(self.mxHostGroupCounts, func(mxHost string, groupCount smtpPinGroupCount) bool {
		return !now.Before(groupCount.time.Add(timeout))
	})
	smtpPinEvict(self.pairLevels, maxCount, func(a smtpPinPair, b smtpPinPair) int {
		return cmp.Or(self.pairLevels[a].pinTime.Compare(self.pairLevels[b].pinTime), a.compare(b))
	})
	smtpPinEvict(self.mxHostModes, maxCount, func(a string, b string) int {
		return cmp.Or(self.mxHostModes[a].time.Compare(self.mxHostModes[b].time), strings.Compare(a, b))
	})
	smtpPinEvict(self.domainSessions, maxCount, func(a string, b string) int {
		return cmp.Or(self.domainSessions[a].time.Compare(self.domainSessions[b].time), strings.Compare(a, b))
	})
	smtpPinEvict(self.mxHostGroupCounts, maxCount, func(a string, b string) int {
		return cmp.Or(self.mxHostGroupCounts[a].time.Compare(self.mxHostGroupCounts[b].time), strings.Compare(a, b))
	})
}

// Whether the file has been loaded.
func (self *SmtpPinStore) isLoaded() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.loaded
}

// Loads the file once, and logs how many domainless pins it dropped. A store that cannot answer is an
// error, and the next call tries again.
func (self *SmtpPinStore) load() error {
	if self.isLoaded() {
		return nil
	}
	droppedCount, err := func() (int, error) {
		self.writeLock.Lock()
		defer self.writeLock.Unlock()
		// another call may have loaded it while this one waited
		if self.isLoaded() {
			return 0, nil
		}
		data, found, err := smtpReadStoreFile(self.store, smtpPinFileName)
		if err != nil {
			return 0, err
		}
		state := newSmtpPinState()
		droppedCount := 0
		if found {
			state, droppedCount, err = decodeSmtpPinFile(data)
			if err != nil {
				return 0, err
			}
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.state = state
		self.loaded = true
		return droppedCount, nil
	}()
	if err != nil {
		return err
	}
	if 0 < droppedCount {
		self.log.Infof("[smtp]tls pins dropped %d stored pins that name no recipient domain\n", droppedCount)
	}
	return nil
}

// Runs change on a copy of the state at now, prunes it, writes it, and only then takes it as the state.
// An error from change writes nothing.
func (self *SmtpPinStore) update(change func(state *smtpPinState, now time.Time) error) error {
	if err := self.load(); err != nil {
		return err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	now := self.clock.Now()
	next := func() *smtpPinState {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.state.clone()
	}()
	if err := change(next, now); err != nil {
		return err
	}
	next.prune(now, self.settings.PinTimeout, self.settings.PinMaxCount)
	data, err := next.encode()
	if err != nil {
		return fmt.Errorf("%w: smtp pins do not encode", ErrSidecarStoreFailed)
	}
	testHookBarrier("smtp.pin_write.before", "")
	if err := smtpWriteStoreFile(self.store, smtpPinFileName, data); err != nil {
		return err
	}
	testHookBarrier("smtp.pin_write.after", "")
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state = next
	return nil
}

// The pin that holds for recipientDomain on mxHost now, a copy with the host's mode, or nil when none
// does: never set, or lapsed. A pin the host holds for another domain is none of this one's. An error is
// the store's, and a caller holds the send on it.
func (self *SmtpPinStore) Pin(recipientDomain string, mxHost string) (*SmtpPin, error) {
	pair, ok := smtpPinPairOf(recipientDomain, mxHost)
	if !ok {
		return nil, errSmtpPinArgument
	}
	if err := self.load(); err != nil {
		return nil, err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state.pinAt(pair, now, self.settings.PinTimeout), nil
}

// Records that mxHost reached level (TL1 to TL4) for recipientDomain now: a better level than the
// pair's pin raises it, and an equal one restarts its PinTimeout; with no pin holding for the pair the
// level becomes its pin, whatever the host holds for other domains. A worse level than a holding pin
// answers ErrSmtpPinBelow and changes nothing. Returns the pin as it now stands, with the host's mode.
func (self *SmtpPinStore) Raise(recipientDomain string, mxHost string, level SmtpTlsLevel) (*SmtpPin, error) {
	pair, ok := smtpPinPairOf(recipientDomain, mxHost)
	if !ok || !smtpPinLevelValid(level) {
		return nil, errSmtpPinArgument
	}
	var raised *SmtpPin
	err := self.update(func(state *smtpPinState, now time.Time) error {
		if pinned, ok := state.pairLevels[pair]; ok && pinned.heldAt(now, self.settings.PinTimeout) && pinned.level < level {
			return fmt.Errorf("%w: level %d under a level %d pin", ErrSmtpPinBelow, level, pinned.level)
		}
		// a better or equal level than the pin, or no pin holding: the level and its time are the pair's
		state.pairLevels[pair] = smtpPinLevel{level: level, pinTime: now}
		raised = state.pin(pair, state.pairLevels[pair])
		return nil
	})
	if err != nil {
		return nil, err
	}
	return raised, nil
}

// Records the post-TLS mode, BDAT or DATA, of a session in which recipientDomain's mail reached
// mxHost's EHLO reply inside TLS: the host's mode, whichever domain the session was for, and the
// domain's last session, which Check reads. It pins no level. Unknown records nothing, since a session
// that ended before EHLO says nothing of the mode.
func (self *SmtpPinStore) RecordMode(recipientDomain string, mxHost string, mode SmtpMode) error {
	pair, ok := smtpPinPairOf(recipientDomain, mxHost)
	if !ok || !mode.known() {
		return errSmtpPinArgument
	}
	if mode == SmtpModeUnknown {
		return nil
	}
	return self.update(func(state *smtpPinState, now time.Time) error {
		state.mxHostModes[pair.mxHost] = smtpPinMode{mode: mode, time: now}
		state.domainSessions[pair.recipientDomain] = smtpPinDomain{mxHost: pair.mxHost, mode: mode, time: now}
		return nil
	})
}

// Keeps count, the envelope group bound a retry to mxHost needed after its replies overflowed every shape,
// beside the host's mode, for PinTimeout (DESIGN-DETAILS 3.5): recipientDomain's later sends start there.
func (self *SmtpPinStore) RecordEnvelopeGroupCount(recipientDomain string, mxHost string, count int) error {
	pair, ok := smtpPinPairOf(recipientDomain, mxHost)
	if !ok || count <= 0 {
		return errSmtpPinArgument
	}
	return self.update(func(state *smtpPinState, now time.Time) error {
		state.mxHostGroupCounts[pair.mxHost] = smtpPinGroupCount{count: count, time: now}
		return nil
	})
}

// The envelope group bound kept for the MX host of recipientDomain's last session, 0 when none is: what a send
// to the domain starts with, since the edge names its MX only after the preamble.
func (self *SmtpPinStore) EnvelopeGroupMaxCount(recipientDomain string) (int, error) {
	domain, ok := smtpTlsName(recipientDomain)
	if !ok {
		return 0, errSmtpPinArgument
	}
	if err := self.load(); err != nil {
		return 0, err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	session, ok := self.state.domainSessions[domain]
	if !ok || !now.Before(session.time.Add(self.settings.PinTimeout)) {
		return 0, nil
	}
	groupCount, ok := self.state.mxHostGroupCounts[session.mxHost]
	if !ok || !now.Before(groupCount.time.Add(self.settings.PinTimeout)) {
		return 0, nil
	}
	return groupCount.count, nil
}

// The mode of recipientDomain's last session, BDAT or DATA, while it is younger than PinTimeout, else
// unknown: what Check reports when no or/ outcome says more (§14.5).
func (self *SmtpPinStore) DomainMode(recipientDomain string) (SmtpMode, error) {
	domain, ok := smtpTlsName(recipientDomain)
	if !ok {
		return SmtpModeUnknown, errSmtpPinArgument
	}
	if err := self.load(); err != nil {
		return SmtpModeUnknown, err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	session, ok := self.state.domainSessions[domain]
	if !ok || !now.Before(session.time.Add(self.settings.PinTimeout)) {
		return SmtpModeUnknown, nil
	}
	return session.mode, nil
}

// Lowercase with no trailing dot, as every pin, policy and request compares names, and whether the
// result is RFC 5321's Domain.
func smtpTlsName(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return name, smtpDomainForm(name)
}
