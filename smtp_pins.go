//go:build !sidecar_http && !ios_extension

// §14.4's pins (D-SMTP-2): each MX host's best TLS level, held SmtpSenderSettings.PinTimeout from the
// last send that reached it, below which nothing is sent while it holds, and the post-TLS mode of the
// host's last session. Beside them each recipient domain's last session, its host and mode, is what
// SmtpSender.Check reports as the domain's mode for as long as a pin would hold (§14.5).
//
// A level is better the lower its number, TL1 first. Raising to a better level, or reaching the pinned
// one again, restarts the pin's 90 days; reaching a worse one is refused and changes nothing, and Raise
// makes that check and the raise one step, so two sends to one host cannot both pass a pin that one of
// them raises. A lapsed pin is no pin: the next send pins whatever it reaches. TL4 refuses nothing and
// is kept only for its mode.
//
// Pins are keyed by MX host alone, as §14.4 words them. Question smtp-m9-06-pin-key asks whether the
// key is (recipient domain, MX host), since TL1 and TL2 depend on the recipient domain and a shared MX
// host pinned by one domain refuses another; until it is answered this key, which only ever refuses
// more, stands.
//
// Layout: one sealed file, tls-pins, in the sender's directory of the store (§5.9's <component>/), as
// JSON rewritten whole by Commit, so a kill leaves the old pins or the new ones. Hosts and domains are
// names this device mails, so they live inside the sealed file and never in a file's name, which the
// store keeps in the clear. A file that fails to open or parse is ErrSidecarStoreFailed, never read as
// no pins, since a pin read as absent would let a downgrade through (D-CORE-15), and a store that cannot
// answer holds the send. Writes serialize on writeLock, never taken under stateLock, and memory changes
// only once a write has landed. Nothing here logs, and no error names a host or domain (I-13).
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10). Safe for concurrent use.

package sidecar

import (
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
	// Its format version.
	smtpPinFileVersion = 1
)

var (
	// A level below the host's pin: a downgrade, refused (D-SMTP-2).
	ErrSmtpPinBelow = errors.New("smtp pin: below the host's pin")
	// A host, domain, level or mode outside its form.
	errSmtpPinArgument = errors.New("smtp pin: invalid argument")
)

// One MX host's pin.
type SmtpPin struct {
	// Lowercase, with no trailing dot.
	MxHost string
	// The best level the host reached while its pin held, TL1 to TL4. Nothing below it is sent.
	Level SmtpTlsLevel
	// When the host last reached Level: the pin holds PinTimeout from here.
	PinTime time.Time
	// The post-TLS mode of the host's last session that reached its EHLO reply, unknown when none did.
	Mode SmtpMode
	// When Mode was seen. It reads as unknown PinTimeout after.
	ModeTime time.Time
}

// One recipient domain's last session.
type smtpPinDomain struct {
	mxHost string
	mode   SmtpMode
	time   time.Time
}

// The stored file.
type smtpPinFile struct {
	Version int                    `json:"version"`
	Pins    []*smtpPinRecord       `json:"pins"`
	Domains []*smtpPinDomainRecord `json:"domains"`
}

// A pin's stored form. Level 0 and no pin time is a host whose level lapsed or was never pinned and
// whose mode is still young.
type smtpPinRecord struct {
	MxHost     string `json:"mx_host"`
	Level      uint32 `json:"level,omitempty"`
	PinTimeMs  int64  `json:"pin_time_ms,omitempty"`
	Mode       uint32 `json:"mode,omitempty"`
	ModeTimeMs int64  `json:"mode_time_ms,omitempty"`
}

// A domain's stored form.
type smtpPinDomainRecord struct {
	Domain string `json:"domain"`
	MxHost string `json:"mx_host"`
	Mode   uint32 `json:"mode"`
	TimeMs int64  `json:"time_ms"`
}

// Every pin and domain record, as memory holds them.
type smtpPinState struct {
	mxHostPins     map[string]*SmtpPin
	domainSessions map[string]*smtpPinDomain
}

// No pins and no sessions.
func newSmtpPinState() *smtpPinState {
	return &smtpPinState{mxHostPins: map[string]*SmtpPin{}, domainSessions: map[string]*smtpPinDomain{}}
}

// A copy whose maps and entries share nothing with this one.
func (self *smtpPinState) clone() *smtpPinState {
	clone := newSmtpPinState()
	for mxHost, pin := range self.mxHostPins {
		pinCopy := *pin
		clone.mxHostPins[mxHost] = &pinCopy
	}
	for domain, session := range self.domainSessions {
		sessionCopy := *session
		clone.domainSessions[domain] = &sessionCopy
	}
	return clone
}

// The pins and domain sessions of one network's sender.
type SmtpPinStore struct {
	store    SidecarStore
	settings *SmtpSenderSettings
	clock    Clock

	// serializes the load and every write, outside stateLock
	writeLock sync.Mutex

	stateLock sync.Mutex
	loaded    bool
	state     *smtpPinState
}

// The pins in store, the sender's directory, under settings, which must have passed validate, on clock
// (nil is real time).
func NewSmtpPinStore(store SidecarStore, settings *SmtpSenderSettings, clock Clock) *SmtpPinStore {
	return &SmtpPinStore{
		store:    store,
		settings: settings,
		clock:    clockOrReal(clock),
		state:    newSmtpPinState(),
	}
}

// Whether level is one a pin can hold.
func smtpPinLevelValid(level SmtpTlsLevel) bool {
	return SmtpTlsLevelDane <= level && level <= SmtpTlsLevelUnauthenticated
}

// Whether the pin holds at now.
func (self *SmtpPin) heldAt(now time.Time, timeout time.Duration) bool {
	return smtpPinLevelValid(self.Level) && now.Before(self.PinTime.Add(timeout))
}

// The pin's mode at now, unknown once it is PinTimeout old.
func (self *SmtpPin) modeAt(now time.Time, timeout time.Duration) SmtpMode {
	if self.Mode == SmtpModeUnknown || !now.Before(self.ModeTime.Add(timeout)) {
		return SmtpModeUnknown
	}
	return self.Mode
}

// When the pin stops holding.
func (self *SmtpPin) ExpireTime(timeout time.Duration) time.Time {
	return self.PinTime.Add(timeout)
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

// The pin a stored record gives, or false for anything but this version's well-formed record: a held
// level with its time, a mode with its time, or both.
func (self *smtpPinRecord) pin() (*SmtpPin, bool) {
	mxHost, ok := smtpTlsName(self.MxHost)
	if !ok || mxHost != self.MxHost {
		return nil, false
	}
	pin := &SmtpPin{MxHost: mxHost, Level: SmtpTlsLevel(self.Level), Mode: SmtpMode(self.Mode)}
	switch {
	case self.Level == 0 && self.PinTimeMs == 0:
	case smtpPinLevelValid(pin.Level) && 0 < self.PinTimeMs:
		pin.PinTime = time.UnixMilli(self.PinTimeMs)
	default:
		return nil, false
	}
	switch {
	case pin.Mode == SmtpModeUnknown && self.ModeTimeMs == 0:
		if pin.Level == SmtpTlsLevelUnreached {
			// neither a level nor a mode: nothing a writer keeps
			return nil, false
		}
	case pin.Mode != SmtpModeUnknown && pin.Mode.known() && 0 < self.ModeTimeMs:
		pin.ModeTime = time.UnixMilli(self.ModeTimeMs)
	default:
		return nil, false
	}
	return pin, true
}

// The file's state, refusing anything but this version's well-formed records: ErrSidecarStoreFailed.
func decodeSmtpPinFile(data []byte) (*smtpPinState, error) {
	file := &smtpPinFile{}
	if err := json.Unmarshal(data, file); err != nil || file.Version != smtpPinFileVersion {
		return nil, fmt.Errorf("%w: smtp pins do not parse", ErrSidecarStoreFailed)
	}
	state := newSmtpPinState()
	for _, record := range file.Pins {
		if record == nil {
			return nil, fmt.Errorf("%w: an smtp pin is malformed", ErrSidecarStoreFailed)
		}
		pin, ok := record.pin()
		if !ok {
			return nil, fmt.Errorf("%w: an smtp pin is malformed", ErrSidecarStoreFailed)
		}
		state.mxHostPins[pin.MxHost] = pin
	}
	for _, record := range file.Domains {
		if record == nil {
			return nil, fmt.Errorf("%w: an smtp domain session is malformed", ErrSidecarStoreFailed)
		}
		domain, domainOk := smtpTlsName(record.Domain)
		mxHost, hostOk := smtpTlsName(record.MxHost)
		mode := SmtpMode(record.Mode)
		if !domainOk || domain != record.Domain || !hostOk || mxHost != record.MxHost || !mode.known() || mode == SmtpModeUnknown || record.TimeMs <= 0 {
			return nil, fmt.Errorf("%w: an smtp domain session is malformed", ErrSidecarStoreFailed)
		}
		state.domainSessions[domain] = &smtpPinDomain{mxHost: mxHost, mode: mode, time: time.UnixMilli(record.TimeMs)}
	}
	return state, nil
}

// The file's bytes, records sorted so one state always writes the same file.
func (self *smtpPinState) encode() ([]byte, error) {
	file := &smtpPinFile{Version: smtpPinFileVersion, Pins: []*smtpPinRecord{}, Domains: []*smtpPinDomainRecord{}}
	for _, mxHost := range slices.Sorted(maps.Keys(self.mxHostPins)) {
		pin := self.mxHostPins[mxHost]
		record := &smtpPinRecord{MxHost: pin.MxHost}
		if smtpPinLevelValid(pin.Level) {
			record.Level = uint32(pin.Level)
			record.PinTimeMs = pin.PinTime.UnixMilli()
		}
		if pin.Mode != SmtpModeUnknown {
			record.Mode = uint32(pin.Mode)
			record.ModeTimeMs = pin.ModeTime.UnixMilli()
		}
		file.Pins = append(file.Pins, record)
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
	return json.Marshal(file)
}

// Drops what has lapsed at now, then past maxCount the entries closest to lapsing.
func (self *smtpPinState) prune(now time.Time, timeout time.Duration, maxCount int) {
	for mxHost, pin := range self.mxHostPins {
		if !pin.heldAt(now, timeout) && pin.modeAt(now, timeout) == SmtpModeUnknown {
			delete(self.mxHostPins, mxHost)
		}
	}
	for domain, session := range self.domainSessions {
		if !now.Before(session.time.Add(timeout)) {
			delete(self.domainSessions, domain)
		}
	}
	// a pin's last word is the later of its level's time and its mode's
	pinLast := func(pin *SmtpPin) time.Time {
		if pin.ModeTime.After(pin.PinTime) {
			return pin.ModeTime
		}
		return pin.PinTime
	}
	if overCount := len(self.mxHostPins) - maxCount; 0 < overCount {
		mxHosts := slices.SortedFunc(maps.Keys(self.mxHostPins), func(a string, b string) int {
			return pinLast(self.mxHostPins[a]).Compare(pinLast(self.mxHostPins[b]))
		})
		for _, mxHost := range mxHosts[:overCount] {
			delete(self.mxHostPins, mxHost)
		}
	}
	if overCount := len(self.domainSessions) - maxCount; 0 < overCount {
		domains := slices.SortedFunc(maps.Keys(self.domainSessions), func(a string, b string) int {
			return self.domainSessions[a].time.Compare(self.domainSessions[b].time)
		})
		for _, domain := range domains[:overCount] {
			delete(self.domainSessions, domain)
		}
	}
}

// Loads the file once. A store that cannot answer is an error, and the next call tries again.
func (self *SmtpPinStore) load() error {
	loaded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loaded
	}()
	if loaded {
		return nil
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	data, found, err := smtpReadStoreFile(self.store, smtpPinFileName)
	if err != nil {
		return err
	}
	state := newSmtpPinState()
	if found {
		state, err = decodeSmtpPinFile(data)
		if err != nil {
			return err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.loaded {
		self.state = state
		self.loaded = true
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

// The pin that holds on mxHost now, a copy, or nil when none does: never set, or lapsed. An error is
// the store's, and a caller holds the send on it.
func (self *SmtpPinStore) Pin(mxHost string) (*SmtpPin, error) {
	mxHost, ok := smtpTlsName(mxHost)
	if !ok {
		return nil, errSmtpPinArgument
	}
	if err := self.load(); err != nil {
		return nil, err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	pin, ok := self.state.mxHostPins[mxHost]
	if !ok || !pin.heldAt(now, self.settings.PinTimeout) {
		return nil, nil
	}
	pinCopy := *pin
	return &pinCopy, nil
}

// Records that mxHost reached level now (TL1 to TL4): a better level than the pin raises it, and an
// equal one restarts its PinTimeout; with no pin holding, the level becomes the pin. A worse level
// than a holding pin answers ErrSmtpPinBelow and changes nothing. Returns the pin as it now stands.
func (self *SmtpPinStore) Raise(mxHost string, level SmtpTlsLevel) (*SmtpPin, error) {
	mxHost, ok := smtpTlsName(mxHost)
	if !ok || !smtpPinLevelValid(level) {
		return nil, errSmtpPinArgument
	}
	var raised SmtpPin
	err := self.update(func(state *smtpPinState, now time.Time) error {
		pin, ok := state.mxHostPins[mxHost]
		switch {
		case !ok:
			pin = &SmtpPin{MxHost: mxHost, Level: level, PinTime: now}
			state.mxHostPins[mxHost] = pin
		case !pin.heldAt(now, self.settings.PinTimeout):
			// the lapsed level goes, and the mode stays for as long as its own time holds it
			pin.Level, pin.PinTime = level, now
		case pin.Level < level:
			return fmt.Errorf("%w: level %d under a level %d pin", ErrSmtpPinBelow, level, pin.Level)
		default:
			pin.Level, pin.PinTime = level, now
		}
		raised = *pin
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &raised, nil
}

// Records the post-TLS mode, BDAT or DATA, of a session in which recipientDomain's mail reached
// mxHost's EHLO reply inside TLS: the host's mode, and the domain's last session, which Check reads.
// Unknown records nothing, since a session that ended before EHLO says nothing of the mode.
func (self *SmtpPinStore) RecordMode(recipientDomain string, mxHost string, mode SmtpMode) error {
	domain, domainOk := smtpTlsName(recipientDomain)
	mxHost, hostOk := smtpTlsName(mxHost)
	if !domainOk || !hostOk || !mode.known() {
		return errSmtpPinArgument
	}
	if mode == SmtpModeUnknown {
		return nil
	}
	return self.update(func(state *smtpPinState, now time.Time) error {
		pin, ok := state.mxHostPins[mxHost]
		if ok {
			pin.Mode, pin.ModeTime = mode, now
		} else {
			// a session that reached EHLO also passed VerifyPeer, which pinned the host, so this is a pin
			// that lapsed or left in between: its mode is still worth keeping, and it pins nothing
			state.mxHostPins[mxHost] = &SmtpPin{MxHost: mxHost, Mode: mode, ModeTime: now}
		}
		state.domainSessions[domain] = &smtpPinDomain{mxHost: mxHost, mode: mode, time: now}
		return nil
	})
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
