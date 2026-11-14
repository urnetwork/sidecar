//go:build !sidecar_http && !ios_extension

// §14.4's TL4 allowances (D-SMTP-2, owner decision 38, QD-729, plan-SMTP-small-readings#11): the recipient
// domains this device's user allowed mail to go to through an MX that cannot be authenticated, each
// until it ends. An allowance is the effect of one mail_tls_unauthenticated action that passed
// Sidecar.Authorize (I-8), kept with the effect key it was made under and its approval's id, so the
// gate's Lookup finds it after a restart. Nothing else writes one: a phone's message brings its own
// approval on its signed outbox entry, which a prover host honors for that message and never copies
// here.
//
// One allowance a domain: a later one replaces it, whichever way its end moves, since the later
// consent is the user's newer word. An allowance that has ended is no allowance and leaves at the next
// write. Past SmtpSenderSettings.TlsAllowanceMaxCount domains a new domain's allowance is refused
// rather than another's dropped, so consent a person gave never leaves but by its own end.
//
// Layout: one sealed file, tls-allowances, in the sender's directory of the store (§5.9's
// <component>/), as JSON rewritten whole by Commit, so a kill leaves the old allowances or the new
// ones. Domains are names this device mails, so they live inside the sealed file and never in a file's
// name. A file that fails to open or parse is ErrSidecarStoreFailed, which holds a TL4 send rather
// than refusing or allowing it (D-CORE-15). Writes serialize on writeLock, never taken under
// stateLock, and memory changes only once a write has landed. Nothing here logs, and no error names
// a domain (I-13).
//
// Trap: an effect key whose allowance a later one replaced is no longer found, so its Lookup answers
// uncertain, and running it again puts its allowance back over the later one. Both were approved.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"
)

// Format values of the sealed file.
const (
	// The file's name in the sender's directory.
	smtpTlsAllowanceFileName = "tls-allowances"
	// Its format version.
	smtpTlsAllowanceFileVersion = 1
)

var (
	// The store holds TlsAllowanceMaxCount domains' allowances, and this domain is not one of them.
	ErrSmtpTlsAllowanceFull = errors.New("smtp tls: no room for another domain's allowance")
	// The allowance asked for ends at or before now.
	ErrSmtpTlsAllowanceEnded = errors.New("smtp tls: the allowance has ended")
)

// One recipient domain's allowance to send at TL4.
type SmtpTlsAllowance struct {
	// Lowercase, with no trailing dot.
	RecipientDomain string
	// When it ends; the zero time for one that does not.
	ExpireTime time.Time
	// When the store took it.
	AllowTime time.Time
	// The approval it was spent from, nil under a standing grant, which spends none.
	ApprovalId *Id
	// §16.6's effect_key it was made under, empty under a standing grant
	effectKey []byte
}

// Whether the allowance holds at now.
func (self *SmtpTlsAllowance) heldAt(now time.Time) bool {
	return self.ExpireTime.IsZero() || now.Before(self.ExpireTime)
}

// A copy sharing nothing with this one.
func (self *SmtpTlsAllowance) clone() *SmtpTlsAllowance {
	clone := *self
	if self.ApprovalId != nil {
		approvalId := *self.ApprovalId
		clone.ApprovalId = &approvalId
	}
	clone.effectKey = bytes.Clone(self.effectKey)
	return &clone
}

// The reference the gate keeps of the effect: when the store took the allowance, in ms since the
// epoch, big-endian. It names no domain.
func (self *SmtpTlsAllowance) effectRef() []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(self.AllowTime.UnixMilli()))
}

// The stored file.
type smtpTlsAllowanceFile struct {
	Version    int                       `json:"version"`
	Allowances []*smtpTlsAllowanceRecord `json:"allowances"`
}

// An allowance's stored form. No expire time is an allowance that does not end.
type smtpTlsAllowanceRecord struct {
	Domain       string `json:"domain"`
	ExpireTimeMs int64  `json:"expire_time_ms,omitempty"`
	AllowTimeMs  int64  `json:"allow_time_ms"`
	ApprovalId   []byte `json:"approval_id,omitempty"`
	EffectKey    []byte `json:"effect_key,omitempty"`
}

// The allowance a stored record gives, or false for anything but this version's well-formed record.
func (self *smtpTlsAllowanceRecord) allowance() (*SmtpTlsAllowance, bool) {
	domain, ok := smtpTlsName(self.Domain)
	if !ok || domain != self.Domain || self.AllowTimeMs <= 0 || self.ExpireTimeMs < 0 {
		return nil, false
	}
	if len(self.EffectKey) != 0 && len(self.EffectKey) != sha256.Size {
		return nil, false
	}
	allowance := &SmtpTlsAllowance{
		RecipientDomain: domain,
		AllowTime:       time.UnixMilli(self.AllowTimeMs),
		effectKey:       bytes.Clone(self.EffectKey),
	}
	if 0 < self.ExpireTimeMs {
		allowance.ExpireTime = time.UnixMilli(self.ExpireTimeMs)
	}
	if len(self.ApprovalId) != 0 {
		approvalId, err := IdFromBytes(self.ApprovalId)
		if err != nil {
			return nil, false
		}
		allowance.ApprovalId = &approvalId
	}
	return allowance, true
}

// The file's allowances by domain, refusing anything but this version's well-formed records, each
// domain once: ErrSidecarStoreFailed.
func decodeSmtpTlsAllowanceFile(data []byte) (map[string]*SmtpTlsAllowance, error) {
	file := &smtpTlsAllowanceFile{}
	if err := json.Unmarshal(data, file); err != nil || file.Version != smtpTlsAllowanceFileVersion {
		return nil, fmt.Errorf("%w: smtp tls allowances do not parse", ErrSidecarStoreFailed)
	}
	domainAllowances := map[string]*SmtpTlsAllowance{}
	for _, record := range file.Allowances {
		if record == nil {
			return nil, fmt.Errorf("%w: an smtp tls allowance is malformed", ErrSidecarStoreFailed)
		}
		allowance, ok := record.allowance()
		if !ok {
			return nil, fmt.Errorf("%w: an smtp tls allowance is malformed", ErrSidecarStoreFailed)
		}
		if _, ok := domainAllowances[allowance.RecipientDomain]; ok {
			return nil, fmt.Errorf("%w: an smtp tls allowance is written twice", ErrSidecarStoreFailed)
		}
		domainAllowances[allowance.RecipientDomain] = allowance
	}
	return domainAllowances, nil
}

// The file's bytes, records sorted so one state always writes the same file.
func encodeSmtpTlsAllowanceFile(domainAllowances map[string]*SmtpTlsAllowance) ([]byte, error) {
	file := &smtpTlsAllowanceFile{Version: smtpTlsAllowanceFileVersion, Allowances: []*smtpTlsAllowanceRecord{}}
	for _, domain := range slices.Sorted(maps.Keys(domainAllowances)) {
		allowance := domainAllowances[domain]
		record := &smtpTlsAllowanceRecord{
			Domain:      allowance.RecipientDomain,
			AllowTimeMs: allowance.AllowTime.UnixMilli(),
			EffectKey:   allowance.effectKey,
		}
		if !allowance.ExpireTime.IsZero() {
			record.ExpireTimeMs = allowance.ExpireTime.UnixMilli()
		}
		if allowance.ApprovalId != nil {
			record.ApprovalId = allowance.ApprovalId.Bytes()
		}
		file.Allowances = append(file.Allowances, record)
	}
	return json.Marshal(file)
}

// The TL4 allowances of one network's sender.
type SmtpTlsAllowanceStore struct {
	store    SidecarStore
	settings *SmtpSenderSettings
	clock    Clock

	// serializes the load and every write, outside stateLock
	writeLock sync.Mutex

	stateLock        sync.Mutex
	loaded           bool
	domainAllowances map[string]*SmtpTlsAllowance
}

// The allowances in store, the sender's directory, under settings, which must have passed validate,
// on clock (nil is real time).
func NewSmtpTlsAllowanceStore(store SidecarStore, settings *SmtpSenderSettings, clock Clock) *SmtpTlsAllowanceStore {
	return &SmtpTlsAllowanceStore{
		store:            store,
		settings:         settings,
		clock:            clockOrReal(clock),
		domainAllowances: map[string]*SmtpTlsAllowance{},
	}
}

// Loads the file once. A store that cannot answer is an error, and the next call tries again.
func (self *SmtpTlsAllowanceStore) load() error {
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
	data, found, err := smtpReadStoreFile(self.store, smtpTlsAllowanceFileName)
	if err != nil {
		return err
	}
	domainAllowances := map[string]*SmtpTlsAllowance{}
	if found {
		domainAllowances, err = decodeSmtpTlsAllowanceFile(data)
		if err != nil {
			return err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.loaded {
		self.domainAllowances = domainAllowances
		self.loaded = true
	}
	return nil
}

// The allowance that holds for recipientDomain now, a copy, or nil when none does: never made, or
// ended. An error is the store's, and a caller holds a TL4 send on it.
func (self *SmtpTlsAllowanceStore) Allowance(recipientDomain string) (*SmtpTlsAllowance, error) {
	domain, ok := smtpTlsName(recipientDomain)
	if !ok {
		return nil, ErrSmtpTlsRequest
	}
	if err := self.load(); err != nil {
		return nil, err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	allowance, ok := self.domainAllowances[domain]
	if !ok || !allowance.heldAt(now) {
		return nil, nil
	}
	return allowance.clone(), nil
}

// Every allowance that holds now, copies, by domain.
func (self *SmtpTlsAllowanceStore) Allowances() ([]*SmtpTlsAllowance, error) {
	if err := self.load(); err != nil {
		return nil, err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	allowances := []*SmtpTlsAllowance{}
	for _, domain := range slices.Sorted(maps.Keys(self.domainAllowances)) {
		if allowance := self.domainAllowances[domain]; allowance.heldAt(now) {
			allowances = append(allowances, allowance.clone())
		}
	}
	return allowances, nil
}

// Whether an allowance for domain, already in its form, could be kept now: ErrSmtpTlsAllowanceFull
// when it is a new domain and the store holds its count of allowances that have not ended.
func (self *SmtpTlsAllowanceStore) checkRoom(domain string) error {
	if err := self.load(); err != nil {
		return err
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.domainAllowances[domain]; ok {
		return nil
	}
	heldCount := 0
	for _, allowance := range self.domainAllowances {
		if allowance.heldAt(now) {
			heldCount += 1
		}
	}
	if self.settings.TlsAllowanceMaxCount <= heldCount {
		return ErrSmtpTlsAllowanceFull
	}
	return nil
}

// The allowance made under effectKey, a copy, held or ended, or nil when the store has none: never
// made, or since replaced.
func (self *SmtpTlsAllowanceStore) effect(effectKey []byte) (*SmtpTlsAllowance, error) {
	if len(effectKey) == 0 {
		return nil, nil
	}
	if err := self.load(); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, allowance := range self.domainAllowances {
		if bytes.Equal(allowance.effectKey, effectKey) {
			return allowance.clone(), nil
		}
	}
	return nil, nil
}

// Keeps domain's allowance, already in its form, until expireTime, the zero time for no end, as the
// effect of the use effectKey names, spent from approvalId; both are empty under a standing grant. It
// is idempotent per key: a second call under the key the domain's allowance was made under answers
// that allowance and writes nothing. ErrSmtpTlsAllowanceEnded and ErrSmtpTlsAllowanceFull wrote
// nothing; any other error is the store's, and what it wrote is not known.
func (self *SmtpTlsAllowanceStore) allow(domain string, expireTime time.Time, effectKey []byte, approvalId *Id) (*SmtpTlsAllowance, error) {
	if len(effectKey) != 0 && len(effectKey) != sha256.Size {
		return nil, ErrSmtpTlsRequest
	}
	if err := self.load(); err != nil {
		return nil, err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	now := self.clock.Now()
	next := func() map[string]*SmtpTlsAllowance {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return maps.Clone(self.domainAllowances)
	}()
	if existing, ok := next[domain]; ok && len(effectKey) != 0 && bytes.Equal(existing.effectKey, effectKey) {
		return existing.clone(), nil
	}
	if !expireTime.IsZero() && !now.Before(expireTime) {
		return nil, ErrSmtpTlsAllowanceEnded
	}
	for otherDomain, other := range next {
		if !other.heldAt(now) {
			delete(next, otherDomain)
		}
	}
	if _, ok := next[domain]; !ok && self.settings.TlsAllowanceMaxCount <= len(next) {
		return nil, ErrSmtpTlsAllowanceFull
	}
	allowance := &SmtpTlsAllowance{
		RecipientDomain: domain,
		// to the millisecond, as the file keeps it
		AllowTime: time.UnixMilli(now.UnixMilli()),
		effectKey: bytes.Clone(effectKey),
	}
	if !expireTime.IsZero() {
		allowance.ExpireTime = time.UnixMilli(expireTime.UnixMilli())
	}
	if approvalId != nil {
		id := *approvalId
		allowance.ApprovalId = &id
	}
	next[domain] = allowance
	data, err := encodeSmtpTlsAllowanceFile(next)
	if err != nil {
		return nil, fmt.Errorf("%w: smtp tls allowances do not encode", ErrSidecarStoreFailed)
	}
	testHookBarrier("smtp.tls_allowance_write.before", "")
	if err := smtpWriteStoreFile(self.store, smtpTlsAllowanceFileName, data); err != nil {
		return nil, err
	}
	testHookBarrier("smtp.tls_allowance_write.after", "")
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.domainAllowances = next
	return allowance.clone(), nil
}
