//go:build !sidecar_http

// §7.8's revocation objects as evs and gkm read them (owner decision 2; §2.8 evs-18): one object per
// revoked subject, rev/<network_id>/<kind>/<subject_id>/_ on the first metadata cluster, whatever cluster
// a repo is on. api writes them on a removal, deactivation, suspension or token revocation: If-None-Match
// to create, If-Match to raise not_before, never lowering it. taskworker deletes one 20 minutes after its
// last write, since a service token lives 15.
//
// The object is a compact JWS (RFC 7515) under api's svc- key set, which evs and gkm already hold to
// verify service tokens: header {alg ES256, kid svc-..., typ ur-rev+jwt}, and as its payload this JSON,
// its keys in this order and nothing else:
//
//	{"subject":"<network_id>/<kind>/<subject_id>","not_before":<unix s>,"reason":"<reason>","time":<unix s>}
//
// subject repeats the key's middle, so an object copied to another key fails to read. not_before is a
// whole second: a token's iat is one, and a token issued before not_before is void. time is when api
// signed this version of the object. The typ keeps the object from ever verifying as a service token,
// and a service token, which has no such payload, from ever reading as one.
//
// RevocationChecker is the read side: the root holds the format, and the host supplies the signature
// check as a function, so the root imports no JWT library and the engines never import server. It
// GETs a token's three subjects, its client, its sidecar and its member, each answer kept at most
// RevocationSettings.CacheTimeout, 5 s (§7.8's check row). Every doubt refuses: a read that fails, or
// an object that does not verify or parse, is an error that is not ErrRevocationVoidsToken, which an
// engine answers 503, never an allow. Nothing here logs or counts by id (I-13).

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Format values of the object, not settings.
const (
	// The object family, on the first metadata cluster only.
	revocationKeyPrefix = "rev/"
	// The last element of every key, so no key prefixes another (§11.8's keys row).
	revocationKeySuffix = "/_"
	// The JWS header's typ. A verifier refuses any other.
	RevocationJwsType = "ur-rev+jwt"
	// The most bytes an object may hold: its header, payload and an ES256 signature fit in under 512, so
	// anything near this is not one of api's.
	RevocationObjectMaxByteCount = 2 * 1024
	// The most bytes a payload may hold.
	revocationPayloadMaxByteCount = 512
	// The longest reason, which is lowercase letters and underscores.
	revocationReasonMaxByteCount = 32
)

// Whose tokens an object voids: one of a token's three subjects (§7.8's key row).
type RevocationKind string

const (
	// ur_client_id: a client removed, deactivated or reaped.
	RevocationKindClient RevocationKind = "client"
	// ur_sidecar_id: a sidecar revoked or suspended.
	RevocationKindSidecar RevocationKind = "sidecar"
	// member_id: a member removed.
	RevocationKindMember RevocationKind = "member"
)

// Whether this build knows the kind.
func (self RevocationKind) known() bool {
	return self == RevocationKindClient || self == RevocationKindSidecar || self == RevocationKindMember
}

// Why api wrote an object. It is for logs and audits alone: whatever the reason, a token issued before
// not_before is void, so a reader takes a reason it does not know.
type RevocationReason string

const (
	// The subject was removed: a client by remove-client, a member by member-remove (§7.10).
	RevocationReasonRemoved RevocationReason = "removed"
	// The subject was deactivated without a removal: a reaped client (§18.8).
	RevocationReasonDeactivated RevocationReason = "deactivated"
	// A sidecar's Suspend (§8.8).
	RevocationReasonSuspended RevocationReason = "suspended"
	// The subject's tokens were revoked and the subject stays: a session's revocation.
	RevocationReasonRevoked RevocationReason = "revoked"
)

// Whether reason is a word a payload may carry: 1 to 32 lowercase letters and underscores.
func (self RevocationReason) wellFormed() bool {
	if len(self) == 0 || revocationReasonMaxByteCount < len(self) {
		return false
	}
	for i := 0; i < len(self); i += 1 {
		if c := self[i]; !('a' <= c && c <= 'z' || c == '_') {
			return false
		}
	}
	return true
}

// A record the encoder refuses, or an object or payload a reader cannot take: the reader answers an
// error that voids nothing and allows nothing. The message names no id (I-13).
var ErrRevocationInvalid = errors.New("revocation object invalid")

// A token one of whose subjects an object voids: issued before that object's not_before. evs and gkm
// answer 401, so the daemon mints no new one for that subject.
var ErrRevocationVoidsToken = errors.New("a revocation voids the token")

// The key of one subject's object: rev/<network_id>/<kind>/<subject_id>/_.
func RevocationKey(networkId Id, kind RevocationKind, subjectId Id) string {
	return revocationKeyPrefix + revocationSubject(networkId, kind, subjectId) + revocationKeySuffix
}

// The key prefix every object starts with, for taskworker's sweep.
func RevocationKeyPrefix() string {
	return revocationKeyPrefix
}

// The payload's subject, and the key's middle: <network_id>/<kind>/<subject_id>.
func revocationSubject(networkId Id, kind RevocationKind, subjectId Id) string {
	return networkId.String() + "/" + string(kind) + "/" + subjectId.String()
}

// What subject names, false for anything that is not a known kind between two canonical ids.
func parseRevocationSubject(subject string) (networkId Id, kind RevocationKind, subjectId Id, ok bool) {
	parts := strings.Split(subject, "/")
	if len(parts) != 3 {
		return
	}
	kind = RevocationKind(parts[1])
	if !kind.known() {
		return
	}
	var err error
	if networkId, err = ParseId(parts[0]); err != nil || networkId.String() != parts[0] || networkId == (Id{}) {
		return
	}
	if subjectId, err = ParseId(parts[2]); err != nil || subjectId.String() != parts[2] || subjectId == (Id{}) {
		return
	}
	ok = true
	return
}

// What key names, false for anything but an object key in the canonical form.
func ParseRevocationKey(key string) (networkId Id, kind RevocationKind, subjectId Id, ok bool) {
	if !strings.HasPrefix(key, revocationKeyPrefix) || !strings.HasSuffix(key, revocationKeySuffix) {
		return
	}
	return parseRevocationSubject(key[len(revocationKeyPrefix) : len(key)-len(revocationKeySuffix)])
}

// One object's terms.
type RevocationRecord struct {
	NetworkId Id
	Kind      RevocationKind
	SubjectId Id
	// A token issued before this is void. A whole second.
	NotBefore time.Time
	Reason    RevocationReason
	// When api signed this version. A whole second.
	Time time.Time
}

// The object's key.
func (self *RevocationRecord) Key() string {
	return RevocationKey(self.NetworkId, self.Kind, self.SubjectId)
}

// Whether a token issued at issuedAt is void under this record: issued before not_before. A zero
// issuedAt is before every not_before, so a token with no iat is void.
func (self *RevocationRecord) Voids(issuedAt time.Time) bool {
	return issuedAt.Before(self.NotBefore)
}

// The whole second at or after at: the not_before that voids every token issued at or before at,
// since a token's iat is a whole second taken by truncation.
func RevocationNotBefore(at time.Time) time.Time {
	notBefore := at.UTC().Truncate(time.Second)
	if notBefore.Before(at) {
		notBefore = notBefore.Add(time.Second)
	}
	return notBefore
}

// The payload's bytes, keys in the order the format fixes and no trailing newline: what api's signer
// signs. Refuses a record a reader could not read back: zero ids, an unknown kind, a reason that is
// not a word, a time before 1970, and a not_before or time that is not a whole second.
func EncodeRevocationPayload(record *RevocationRecord) ([]byte, error) {
	if record.NetworkId == (Id{}) || record.SubjectId == (Id{}) {
		return nil, fmt.Errorf("%w: a zero network or subject id", ErrRevocationInvalid)
	}
	if !record.Kind.known() {
		return nil, fmt.Errorf("%w: an unknown kind", ErrRevocationInvalid)
	}
	if !record.Reason.wellFormed() {
		return nil, fmt.Errorf("%w: a reason that is not a word", ErrRevocationInvalid)
	}
	for _, at := range []time.Time{record.NotBefore, record.Time} {
		if at.IsZero() || at.Unix() < 0 || !at.Equal(at.Truncate(time.Second)) {
			return nil, fmt.Errorf("%w: a time that is not a whole second after 1970", ErrRevocationInvalid)
		}
	}
	b := &bytes.Buffer{}
	b.WriteString(`{"subject":"`)
	b.WriteString(revocationSubject(record.NetworkId, record.Kind, record.SubjectId))
	b.WriteString(`","not_before":`)
	b.WriteString(strconv.FormatInt(record.NotBefore.Unix(), 10))
	b.WriteString(`,"reason":"`)
	b.WriteString(string(record.Reason))
	b.WriteString(`","time":`)
	b.WriteString(strconv.FormatInt(record.Time.Unix(), 10))
	b.WriteByte('}')
	return b.Bytes(), nil
}

// The payload as it arrives. Pointers tell a missing key from a zero one.
type revocationPayloadJson struct {
	Subject   *string `json:"subject"`
	NotBefore *int64  `json:"not_before"`
	Reason    *string `json:"reason"`
	Time      *int64  `json:"time"`
}

// Reads a verified payload as a record, or answers ErrRevocationInvalid: a payload over its bound,
// JSON that does not parse, a key missing or unknown, trailing bytes, a subject that is not
// <network_id>/<kind>/<subject_id> of a known kind, a reason that is not a word, or a time before 1970.
func ParseRevocationPayload(payload []byte) (*RevocationRecord, error) {
	if revocationPayloadMaxByteCount < len(payload) {
		return nil, fmt.Errorf("%w: a %d byte payload", ErrRevocationInvalid, len(payload))
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	y := &revocationPayloadJson{}
	if err := decoder.Decode(y); err != nil {
		return nil, fmt.Errorf("%w: the payload does not parse", ErrRevocationInvalid)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: bytes after the payload", ErrRevocationInvalid)
	}
	if y.Subject == nil || y.NotBefore == nil || y.Reason == nil || y.Time == nil {
		return nil, fmt.Errorf("%w: a key is missing", ErrRevocationInvalid)
	}
	networkId, kind, subjectId, ok := parseRevocationSubject(*y.Subject)
	if !ok {
		return nil, fmt.Errorf("%w: the subject", ErrRevocationInvalid)
	}
	reason := RevocationReason(*y.Reason)
	if !reason.wellFormed() {
		return nil, fmt.Errorf("%w: the reason", ErrRevocationInvalid)
	}
	if *y.NotBefore < 0 || *y.Time < 0 {
		return nil, fmt.Errorf("%w: a time before 1970", ErrRevocationInvalid)
	}
	return &RevocationRecord{
		NetworkId: networkId,
		Kind:      kind,
		SubjectId: subjectId,
		NotBefore: time.Unix(*y.NotBefore, 0).UTC(),
		Reason:    reason,
		Time:      time.Unix(*y.Time, 0).UTC(),
	}, nil
}

// The host's check of an object's signature: the object's bytes, a compact JWS, to its payload, once
// its signature verifies under the svc- key set and its header's typ is RevocationJwsType. Any failure
// is an error, which the checker answers as an unknown, never as a revocation. Safe for concurrent use.
type RevocationVerifyFunction func(object []byte) (payload []byte, err error)

// Reads one object: its record, nil for no object, or an error for a read that failed or an object
// that is not a revocation of this key's subject.
func ReadRevocation(ctx context.Context, cluster BlobCluster, verify RevocationVerifyFunction, networkId Id, kind RevocationKind, subjectId Id) (*RevocationRecord, error) {
	key := RevocationKey(networkId, kind, subjectId)
	testHookBarrier("revocation.read.before", networkId.String())
	object, err := cluster.Get(ctx, key)
	testHookBarrier("revocation.read.after", networkId.String())
	if errors.Is(err, ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	// one byte past the bound tells a longer object
	body, err := io.ReadAll(io.LimitReader(object.Body, RevocationObjectMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	if RevocationObjectMaxByteCount < len(body) {
		return nil, fmt.Errorf("%w: an object over %d bytes", ErrRevocationInvalid, RevocationObjectMaxByteCount)
	}
	payload, err := verify(body)
	if err != nil {
		return nil, fmt.Errorf("%w: the signature: %w", ErrRevocationInvalid, err)
	}
	record, err := ParseRevocationPayload(payload)
	if err != nil {
		return nil, err
	}
	if record.NetworkId != networkId || record.Kind != kind || record.SubjectId != subjectId {
		return nil, fmt.Errorf("%w: a payload of another subject", ErrRevocationInvalid)
	}
	return record, nil
}

type RevocationSettings struct {
	// How long one read answers for its subject: §7.8 caps it at 5 s, so a removal reaches evs and gkm
	// within 5 s of its object. Zero or negative reads on every check.
	CacheTimeout time.Duration
	// The most subjects held at once, past which the entry read longest ago goes. Each is a few hundred
	// bytes. Zero or negative holds none.
	CacheEntryCount int
	// The clock the cache reads. nil is real time.
	Clock Clock
}

func DefaultRevocationSettings() *RevocationSettings {
	return &RevocationSettings{
		CacheTimeout:    5 * time.Second,
		CacheEntryCount: 100000,
	}
}

// One subject's answer: its record, nil for none, or the error its read gave.
type revocationEntry struct {
	record *RevocationRecord
	err    error
	readAt time.Time
}

// A read under way, which other checks of its subject wait on rather than reading again.
type revocationRead struct {
	done  chan struct{}
	entry *revocationEntry
}

// One token subject: its kind and id.
type revocationTokenSubject struct {
	kind RevocationKind
	id   Id
}

// evs's and gkm's reader of rev/ (§7.8's check row). Safe for concurrent use. Check does I/O under ctx
// and holds no lock across it.
type RevocationChecker struct {
	blobs    BlobStore
	verify   RevocationVerifyFunction
	settings *RevocationSettings
	clock    Clock

	stateLock sync.Mutex
	entries   map[string]*revocationEntry
	reads     map[string]*revocationRead
}

// A checker reading blobs' first metadata cluster, its objects' signatures checked by verify. settings
// may be nil for the defaults.
func NewRevocationChecker(blobs BlobStore, verify RevocationVerifyFunction, settings *RevocationSettings) *RevocationChecker {
	if settings == nil {
		settings = DefaultRevocationSettings()
	}
	return &RevocationChecker{
		blobs:    blobs,
		verify:   verify,
		settings: settings,
		clock:    clockOrReal(settings.Clock),
		entries:  map[string]*revocationEntry{},
		reads:    map[string]*revocationRead{},
	}
}

// nil when no object voids the token's client, sidecar or member; ErrRevocationVoidsToken, wrapped,
// when one does; any other error when the checker cannot tell, which an engine answers 503. A
// principal Principal.Validate refuses is that refusal.
func (self *RevocationChecker) Check(ctx context.Context, principal *Principal) error {
	if err := principal.Validate(); err != nil {
		return err
	}
	if self.blobs == nil || self.verify == nil {
		return errors.New("this host reads no revocations")
	}
	networkId := Id(principal.NetworkId)
	subjects := []revocationTokenSubject{{kind: RevocationKindClient, id: Id(principal.ClientId)}}
	if principal.SidecarId != nil {
		subjects = append(subjects, revocationTokenSubject{kind: RevocationKindSidecar, id: Id(*principal.SidecarId)})
	}
	if principal.MemberId != nil {
		subjects = append(subjects, revocationTokenSubject{kind: RevocationKindMember, id: Id(*principal.MemberId)})
	}

	// the subjects read side by side, so a cold check costs one round trip
	entries := make([]*revocationEntry, len(subjects))
	waitGroup := &sync.WaitGroup{}
	for i, subject := range subjects {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			entries[i] = self.entry(ctx, networkId, subject.kind, subject.id)
		}()
	}
	waitGroup.Wait()

	var unknownErr error
	for i, entry := range entries {
		if entry.err != nil {
			unknownErr = errors.Join(unknownErr, entry.err)
			continue
		}
		if entry.record != nil && entry.record.Voids(principal.IssuedAt) {
			return fmt.Errorf("%w: its %s", ErrRevocationVoidsToken, subjects[i].kind)
		}
	}
	if unknownErr != nil {
		return fmt.Errorf("revocation unknown: %w", unknownErr)
	}
	return nil
}

// The record that voids networkId's subject, nil for none: what Check reads, from the same cache.
func (self *RevocationChecker) Revocation(ctx context.Context, networkId Id, kind RevocationKind, subjectId Id) (*RevocationRecord, error) {
	if self.blobs == nil || self.verify == nil {
		return nil, errors.New("this host reads no revocations")
	}
	entry := self.entry(ctx, networkId, kind, subjectId)
	return entry.record, entry.err
}

// The subject's answer: a fresh cached one, a read under way, or a new read.
func (self *RevocationChecker) entry(ctx context.Context, networkId Id, kind RevocationKind, subjectId Id) *revocationEntry {
	key := RevocationKey(networkId, kind, subjectId)
	cached, read, owner := func() (*revocationEntry, *revocationRead, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if entry, ok := self.entries[key]; ok {
			if self.clock.Now().Sub(entry.readAt) < self.settings.CacheTimeout {
				return entry, nil, false
			}
			delete(self.entries, key)
		}
		if read, ok := self.reads[key]; ok {
			return nil, read, false
		}
		read := &revocationRead{done: make(chan struct{})}
		self.reads[key] = read
		return nil, read, true
	}()
	if cached != nil {
		return cached
	}
	if !owner {
		select {
		case <-read.done:
			return read.entry
		case <-ctx.Done():
			return &revocationEntry{err: ctx.Err()}
		}
	}

	// this goroutine reads, and the others of its subject wait on it
	entry := &revocationEntry{}
	cluster, err := self.blobs.FirstCluster()
	if err == nil {
		entry.record, entry.err = ReadRevocation(ctx, cluster, self.verify, networkId, kind, subjectId)
	} else {
		entry.err = err
	}
	entry.readAt = self.clock.Now()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.reads, key)
		// a read the caller's ctx cut short, or that the store failed, says nothing lasting about the
		// object, so only an answer and an object that does not read as one are kept
		keep := entry.err == nil || errors.Is(entry.err, ErrRevocationInvalid)
		if keep && ctx.Err() == nil && 0 < self.settings.CacheEntryCount && 0 < self.settings.CacheTimeout {
			if self.settings.CacheEntryCount <= len(self.entries) {
				self.evictWithLock()
			}
			self.entries[key] = entry
		}
	}()
	read.entry = entry
	close(read.done)
	return entry
}

// Drops every entry past the cache's timeout, then, while still full, the entry read longest ago.
func (self *RevocationChecker) evictWithLock() {
	now := self.clock.Now()
	for key, entry := range self.entries {
		if self.settings.CacheTimeout <= now.Sub(entry.readAt) {
			delete(self.entries, key)
		}
	}
	for self.settings.CacheEntryCount <= len(self.entries) {
		oldestKey := ""
		var oldestAt time.Time
		for key, entry := range self.entries {
			if oldestKey == "" || entry.readAt.Before(oldestAt) {
				oldestKey, oldestAt = key, entry.readAt
			}
		}
		delete(self.entries, oldestKey)
	}
}
