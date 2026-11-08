//go:build !sidecar_http

// Each sending sidecar's DKIM keys (§14.6, owner decision 36): an RSA-2048 key per signing domain,
// made on this device and kept in this network's keychain.ur, so URnetwork holds only the public keys
// that POST /smtp/dkim-keys publishes (R-SMTP-10, I-1). A replying or forwarding burner signs under
// its own <blabel>.<net>.<root> key until the PSL listing (owner decision 79); the server's write adds
// D-DNS-11's copies for the label, so this side never writes them. smtp_dkim_rotate.go holds the
// writes: the first publish, rotation and retirement.
//
// Each selector has two records under SmtpDkimSecretsNamespace, the namespace of keychain.ur this
// component reads (§5.9): selector/<selector> holds what is not secret (domain, state, times and the
// public key) and key/<selector> the private key alone, PKCS #8 DER, read only to sign. So deciding
// which selector signs never unwraps a key. A key record with no selector record is one a crash left
// before its first publish, or after its purge, and either way it is deleted.
//
// A selector signs only once the server has answered its publish, and a send pins the one it declared
// at its preamble, so a rotation in between never leaves it signing under a key that has gone: a
// retired key stays in the keychain DkimRetiredKeepTimeout, as long as the server keeps it in DNS, and
// longer while a send still holds it. A Locked keychain answers ErrSidecarStoreLocked, which holds the
// send, and a Failed one ErrSidecarStoreFailed, on which nothing is generated (D-CORE-15).
//
// Keys reach testHookSecret when made and each time one is read to sign. No key, and no signing
// domain, reaches a log or an error: logs name selectors, which are opaque and random (I-7, I-13).
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Format values (§14.6, plan-SMTP-small-readings#5), not settings.
const (
	// §14.6's RSA-2048. A signature is then 256 octets, 344 base64 characters, whatever the message,
	// which is what lets a send declare its byte count before it signs.
	SmtpDkimRsaKeyBitCount = 2048
	// A selector is the lowercase unpadded base32 of this many random octets.
	smtpDkimSelectorRandomByteCount = 16
	// So a selector is this many characters: one DNS label of a fixed length.
	SmtpDkimSelectorLength = 26
	// The keychain.ur namespace holding every selector's records.
	SmtpDkimSecretsNamespace = "smtp-dkim"
	// The selector record's format version.
	smtpDkimRecordVersion = 1
	// The longest signing domain: <selector>._domainkey.<domain> must fit DNS's 253 octets.
	smtpDkimDomainMaxByteCount = 253 - SmtpDkimSelectorLength - len("._domainkey.")
	// Record names under the namespace.
	smtpDkimSelectorRecordPrefix = "selector/"
	smtpDkimKeyRecordPrefix      = "key/"
)

// Lowercase unpadded base32, a selector's alphabet (plan-SMTP-small-readings#5).
var smtpDkimBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var (
	// POST /smtp/dkim-keys refused the selector for good, such as past the cap of 64 device selectors
	// (burners' excluded). errors.As finds the *SidecarApiError and its code, the reason the send's
	// failed outcome gives. Nothing was published and the key is gone.
	ErrSmtpDkimPublishRefused = errors.New("smtp dkim: publish refused")
	// A signing domain no selector may sign under: not RFC 5321's Domain, or too long for its key
	// record's name.
	ErrSmtpDkimDomain = errors.New("smtp dkim: invalid signing domain")
	// The selector's key is no longer in the keychain: retired and purged, or another sidecar's.
	ErrSmtpDkimSelectorGone = errors.New("smtp dkim: selector gone")
)

// Where POST /smtp/dkim-keys goes: SidecarApi, or a test's fake. Safe for concurrent use.
type SmtpDkimPublisher interface {
	SmtpDkimKeys(ctx context.Context, args *SmtpDkimKeysArgs) (*SmtpDkimKeysResult, error)
}

// Where a selector is in its life.
type smtpDkimState string

const (
	// Sent to POST /smtp/dkim-keys and not yet answered. It never signs, and it is sent again, the
	// same selector and key, before anything else is made for its domain.
	smtpDkimStatePending smtpDkimState = "pending"
	// The server answered: it signs until a rotation retires it.
	smtpDkimStatePublished smtpDkimState = "published"
	// A retire sent and not yet answered. It never signs again, and the retire is sent again.
	smtpDkimStateRetiring smtpDkimState = "retiring"
	// The server keeps it in DNS 7 days; here its key stays as long, or while a send holds it.
	smtpDkimStateRetired smtpDkimState = "retired"
)

// selector/<selector>'s value, as JSON. It holds no private key.
type smtpDkimRecord struct {
	Version  uint32        `json:"version"`
	Selector string        `json:"selector"`
	Domain   string        `json:"domain"`
	State    smtpDkimState `json:"state"`
	// While pending: the selectors the same call retires, which a rotation names.
	Replaces      []string `json:"replaces,omitempty"`
	CreateTimeMs  int64    `json:"create_time_ms"`
	PublishTimeMs int64    `json:"publish_time_ms,omitempty"`
	RetireTimeMs  int64    `json:"retire_time_ms,omitempty"`
	// DER SubjectPublicKeyInfo, which is what the server publishes.
	PublicKey []byte `json:"public_key"`
}

func smtpDkimSelectorRecordName(selector string) string {
	return smtpDkimSelectorRecordPrefix + selector
}

func smtpDkimKeyRecordName(selector string) string {
	return smtpDkimKeyRecordPrefix + selector
}

// Whether a selector is the 26 characters of 16 octets in its one spelling: base32's unused low
// bits zero.
func smtpDkimSelectorForm(selector string) bool {
	if len(selector) != SmtpDkimSelectorLength {
		return false
	}
	decoded, err := smtpDkimBase32.DecodeString(selector)
	return err == nil && len(decoded) == smtpDkimSelectorRandomByteCount && smtpDkimBase32.EncodeToString(decoded) == selector
}

// A fresh selector: 16 random octets, 128 bits, so two sidecars never collide on one.
func newSmtpDkimSelector() (string, error) {
	random := make([]byte, smtpDkimSelectorRandomByteCount)
	if _, err := cryptorand.Read(random); err != nil {
		return "", err
	}
	return smtpDkimBase32.EncodeToString(random), nil
}

// Whether a name is RFC 5321's Domain: dot-separated labels of 1 to 63 letters, digits and hyphens,
// a letter or digit at each end of each, 255 octets in all. Nothing in such a name can end a path, a
// tag or a line, which is why every name a preamble or a header carries is held to it (SPEC.md
// section 6).
func smtpDomainForm(name string) bool {
	if name == "" || 255 < len(name) {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || 63 < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Whether a name may be d=: RFC 5321's Domain in lowercase, short enough for its key record's name.
func smtpDkimDomainForm(domain string) bool {
	return smtpDomainForm(domain) && len(domain) <= smtpDkimDomainMaxByteCount && strings.ToLower(domain) == domain
}

// selector/<selector>'s bytes.
func encodeSmtpDkimRecord(record *smtpDkimRecord) ([]byte, error) {
	return json.Marshal(record)
}

// A selector record read back. Anything but this version's well-formed record under its own name is
// ErrSidecarStoreFailed and never absent, so a damaged record generates nothing over it.
func decodeSmtpDkimRecord(name string, value []byte) (*smtpDkimRecord, error) {
	record := &smtpDkimRecord{}
	if err := json.Unmarshal(value, record); err != nil {
		return nil, fmt.Errorf("%w: a dkim selector record does not decode", ErrSidecarStoreFailed)
	}
	switch record.State {
	case smtpDkimStatePending, smtpDkimStatePublished, smtpDkimStateRetiring, smtpDkimStateRetired:
	default:
		return nil, fmt.Errorf("%w: a dkim selector record has an unknown state", ErrSidecarStoreFailed)
	}
	if record.Version != smtpDkimRecordVersion || !smtpDkimSelectorForm(record.Selector) || name != smtpDkimSelectorRecordName(record.Selector) ||
		!smtpDkimDomainForm(record.Domain) || !smtpDkimPublicKeyValid(record.PublicKey) {
		return nil, fmt.Errorf("%w: a dkim selector record is malformed", ErrSidecarStoreFailed)
	}
	for _, replaced := range record.Replaces {
		if !smtpDkimSelectorForm(replaced) {
			return nil, fmt.Errorf("%w: a dkim selector record is malformed", ErrSidecarStoreFailed)
		}
	}
	return record, nil
}

// A network's DKIM keys on this device, from its keychain. Safe for concurrent use.
type SmtpDkimKeys struct {
	secrets   SidecarSecrets
	publisher SmtpDkimPublisher
	settings  *SmtpSenderSettings
	clock     Clock
	log       Logger

	// Orders every read, decision and write of the records, and is held across POST
	// /smtp/dkim-keys, so two sends never make two keys for one domain and a rotation is decided
	// once. It is never stateLock and never taken under it.
	publishLock sync.Mutex

	stateLock sync.Mutex
	// How many sends hold each selector. A purge leaves a held one's key in place.
	pinnedSelectorCounts map[string]int
}

// The keys under secrets, which is this network's keychain.ur namespace SmtpDkimSecretsNamespace,
// published through publisher. settings must have passed validate; nil clock is real time and nil
// log silence.
func NewSmtpDkimKeys(secrets SidecarSecrets, publisher SmtpDkimPublisher, settings *SmtpSenderSettings, clock Clock, log Logger) *SmtpDkimKeys {
	if log == nil {
		log = NewNoopLogger()
	}
	return &SmtpDkimKeys{
		secrets:              secrets,
		publisher:            publisher,
		settings:             settings,
		clock:                clockOrReal(clock),
		log:                  log,
		pinnedSelectorCounts: map[string]int{},
	}
}

// One selector a send pinned at its preamble: what the preamble declares as dkim_selector and what
// signs the message, whatever rotation happens in between. Its key stays in the keychain until
// Release, so a send releases it when it ends. Safe for concurrent use.
type SmtpDkimSelector struct {
	// SmtpDkimSelectorLength characters.
	Selector string
	// d=.
	Domain string
	// DER SubjectPublicKeyInfo, as published.
	PublicKey []byte

	keys        *SmtpDkimKeys
	releaseOnce sync.Once
}

// See SmtpDkimSigner.
func (self *SmtpDkimSelector) DkimSelector() string {
	return self.Selector
}

// See SmtpDkimSigner.
func (self *SmtpDkimSelector) DkimDomain() string {
	return self.Domain
}

// Signs a SHA-256 digest with RSASSA-PKCS1-v1_5, as rsa-sha256 signs (RFC 6376 §3.3.1), under the
// selector's key, read from the keychain for this call alone and dropped after it. A Locked keychain
// answers ErrSidecarStoreLocked, and a key that has gone ErrSmtpDkimSelectorGone.
func (self *SmtpDkimSelector) SignDkim(digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, errors.New("smtp dkim: a digest is not sha-256")
	}
	der, err := self.keys.secrets.Get(smtpDkimKeyRecordName(self.Selector))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, ErrSmtpDkimSelectorGone
	}
	if err != nil {
		return nil, err
	}
	defer clear(der)
	testHookSecret("dkim_private_key", der)
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: a dkim key does not decode", ErrSidecarStoreFailed)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() != SmtpDkimRsaKeyBitCount {
		return nil, fmt.Errorf("%w: a dkim key is not rsa-2048", ErrSidecarStoreFailed)
	}
	// the key must be the one DNS holds, or every signature fails at the receiver
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil || !bytes.Equal(publicKey, self.PublicKey) {
		return nil, fmt.Errorf("%w: a dkim key is not its selector's", ErrSidecarStoreFailed)
	}
	return rsa.SignPKCS1v15(cryptorand.Reader, key, crypto.SHA256, digest)
}

// Ends the send's hold on the selector. Calling it again does nothing.
func (self *SmtpDkimSelector) Release() {
	self.releaseOnce.Do(func() {
		self.keys.stateLock.Lock()
		defer self.keys.stateLock.Unlock()
		self.keys.pinnedSelectorCounts[self.Selector] -= 1
		if self.keys.pinnedSelectorCounts[self.Selector] <= 0 {
			delete(self.keys.pinnedSelectorCounts, self.Selector)
		}
	})
}

// A hold on record's selector, under publishLock.
func (self *SmtpDkimKeys) pinWithPublishLock(record *smtpDkimRecord) *SmtpDkimSelector {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.pinnedSelectorCounts[record.Selector] += 1
	}()
	return &SmtpDkimSelector{
		Selector:  record.Selector,
		Domain:    record.Domain,
		PublicKey: bytes.Clone(record.PublicKey),
		keys:      self,
	}
}

func (self *SmtpDkimKeys) pinned(selector string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return 0 < self.pinnedSelectorCounts[selector]
}

// The selector to sign domain's mail under, pinned until its Release: the newest published one, after
// a rotation once it has signed DkimRotateTimeout. A domain with no selector gets a new key, and the
// call returns only once POST /smtp/dkim-keys has answered, so nothing signs under a selector DNS may
// not hold. One whose publish went unanswered is sent again, the same key, before anything new is
// made. A rotation that fails for any reason but the keychain leaves the old selector signing, since
// the server still holds it, and the next call tries again.
//
// domain is d=, which the From's domain must equal: <net>.<root>, a burner's <blabel>.<net>.<root> or
// a verified Team domain. Errors: ErrSmtpDkimDomain; ErrSidecarStoreLocked, which holds the send;
// ErrSidecarStoreFailed, on which nothing is made; ErrSmtpDkimPublishRefused with the server's reason;
// or the transport's, after which the same key is sent again.
func (self *SmtpDkimKeys) Current(ctx context.Context, domain string) (*SmtpDkimSelector, error) {
	domain = strings.ToLower(domain)
	if !smtpDkimDomainForm(domain) {
		return nil, ErrSmtpDkimDomain
	}
	self.publishLock.Lock()
	defer self.publishLock.Unlock()
	records, err := self.prepareWithPublishLock(ctx)
	if err != nil {
		return nil, err
	}
	now := self.clock.Now()
	current := smtpDkimNewest(records, domain, smtpDkimStatePublished)
	if pending := smtpDkimNewest(records, domain, smtpDkimStatePending); pending != nil {
		published, err := self.sendPendingWithPublishLock(ctx, records, pending, now)
		switch {
		case err == nil:
			current = published
		case current == nil || smtpDkimStoreError(err):
			return nil, err
		default:
			// a rotation left unanswered: the old selector is still in DNS
			self.logRotationFailure(current.Selector, err)
		}
	}
	switch {
	case current == nil:
		if current, err = self.publishNewWithPublishLock(ctx, records, domain, now); err != nil {
			return nil, err
		}
	case self.settings.DkimRotateTimeout <= now.Sub(time.UnixMilli(current.PublishTimeMs)):
		rotated, err := self.publishNewWithPublishLock(ctx, records, domain, now)
		switch {
		case err == nil:
			current = rotated
		case smtpDkimStoreError(err):
			return nil, err
		default:
			self.logRotationFailure(current.Selector, err)
		}
	}
	return self.pinWithPublishLock(current), nil
}

// A rotation that failed, by the old selector's name: opaque and random, unlike the domain (I-13).
func (self *SmtpDkimKeys) logRotationFailure(selector string, err error) {
	self.log.Infof("[smtp]dkim rotation away from selector %s failed, which keeps signing: %v\n", selector, err)
}

// Whether err is the keychain's, which no fallback outlives: a Locked or Failed store.
func smtpDkimStoreError(err error) bool {
	return errors.Is(err, ErrSidecarStoreLocked) || errors.Is(err, ErrSidecarStoreFailed)
}

// domain's newest record in state: by publish time once published, else by creation.
func smtpDkimNewest(records map[string]*smtpDkimRecord, domain string, state smtpDkimState) *smtpDkimRecord {
	var newest *smtpDkimRecord
	for _, record := range records {
		if record.Domain != domain || record.State != state {
			continue
		}
		if newest == nil || newest.PublishTimeMs < record.PublishTimeMs ||
			(newest.PublishTimeMs == record.PublishTimeMs && newest.CreateTimeMs < record.CreateTimeMs) {
			newest = record
		}
	}
	return newest
}

// Every selector record, by selector, under publishLock. A record that does not decode is
// ErrSidecarStoreFailed, as any fault of the store is.
func (self *SmtpDkimKeys) loadWithPublishLock() (map[string]*smtpDkimRecord, error) {
	names, err := self.secrets.List(smtpDkimSelectorRecordPrefix)
	if err != nil {
		return nil, err
	}
	records := map[string]*smtpDkimRecord{}
	for _, name := range names {
		value, err := self.secrets.Get(name)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		record, err := decodeSmtpDkimRecord(name, value)
		if err != nil {
			return nil, err
		}
		records[record.Selector] = record
	}
	return records, nil
}

// Writes record, under publishLock.
func (self *SmtpDkimKeys) putWithPublishLock(record *smtpDkimRecord) error {
	value, err := encodeSmtpDkimRecord(record)
	if err != nil {
		return err
	}
	return self.secrets.Put(smtpDkimSelectorRecordName(record.Selector), value)
}

// Deletes a selector's records, the selector record first, so a crash between leaves only a key
// record, which the next load deletes. Under publishLock.
func (self *SmtpDkimKeys) deleteWithPublishLock(records map[string]*smtpDkimRecord, selector string) error {
	if err := self.secrets.Delete(smtpDkimSelectorRecordName(selector)); err != nil {
		return err
	}
	delete(records, selector)
	return self.secrets.Delete(smtpDkimKeyRecordName(selector))
}

// The records as they stand, tidied under publishLock: key records with no selector record deleted,
// retired selectors past DkimRetiredKeepTimeout that no send holds purged, and retires left
// unanswered sent again. A failed resend is left for the next call: those selectors never sign
// again, whatever the server answers.
func (self *SmtpDkimKeys) prepareWithPublishLock(ctx context.Context) (map[string]*smtpDkimRecord, error) {
	records, err := self.loadWithPublishLock()
	if err != nil {
		return nil, err
	}
	keyNames, err := self.secrets.List(smtpDkimKeyRecordPrefix)
	if err != nil {
		return nil, err
	}
	for _, keyName := range keyNames {
		selector := strings.TrimPrefix(keyName, smtpDkimKeyRecordPrefix)
		if _, ok := records[selector]; !ok {
			if err := self.secrets.Delete(keyName); err != nil {
				return nil, err
			}
		}
	}
	now := self.clock.Now()
	for selector, record := range records {
		if record.State != smtpDkimStateRetired || self.pinned(selector) {
			continue
		}
		if now.Sub(time.UnixMilli(record.RetireTimeMs)) < self.settings.DkimRetiredKeepTimeout {
			continue
		}
		if err := self.deleteWithPublishLock(records, selector); err != nil {
			return nil, err
		}
	}
	var retiring []*smtpDkimRecord
	for _, record := range records {
		if record.State == smtpDkimStateRetiring {
			retiring = append(retiring, record)
		}
	}
	if 0 < len(retiring) {
		if err := self.sendRetireWithPublishLock(ctx, retiring, now); err != nil {
			if smtpDkimStoreError(err) {
				return nil, err
			}
			self.log.Infof("[smtp]dkim retire of %d selectors left for the next call: %v\n", len(retiring), err)
		}
	}
	return records, nil
}
