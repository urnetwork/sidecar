//go:build !sidecar_http

// §21.9's preservation holds as every reader sees them: hold/<network_id>/<case_id>/_ on the first
// metadata cluster (§11.8, evs-19), which api writes from abuse_legal_hold and evs, gkm and taskworker
// read before they delete anything a hold may cover (§10.6, §11.13). evs and gkm read holds from M2,
// three milestones before api writes one, so the codec and the reader live here, in the root, where
// both engines and server can import them (EVSB-M2-11's HoldCache, KEYS-M2-16, EVS1-M2-19).
//
// The object, plan-ABUSE-hold-format as decided (QD-026, QD-058): UTF-8 JSON, at most 1 KiB, unsigned,
// its keys in this order:
//
//	{"version":1,"network_id":"<id>","case_id":"<id>","kind":"preserve_2703f"|"report_2258a",
//	 "scope":"network"|["<repo_id>",...],"place_time_ms":<int>,"expire_time_ms":<int>}
//
// scope is the network, or a list of 1 to 16 repo ids, each covering that repo's objects on every
// cluster and its gkm group. A renewal rewrites the object If-Match and keeps place_time_ms, which
// the versionless purge and FS-69 read as what existed at placement; the object's LastModified would
// not do, since a renewal moves it.
//
// Every doubt keeps data. A body that does not parse, an unknown version, kind or scope, a body that
// names another network or case than its key, and a key that is not <case_id>/_ cover the whole
// network with no end and no placement, as does a LIST or GET that fails, which a caller reads as
// covered and so deletes nothing. A record past its own expire_time is no hold, even before api's
// sweep deletes the object, so no reader depends on that sweep. Each object is its own hold and a
// reader takes the union, which is how §21.9's overlap rule falls out: a repo stays until the latest
// expire_time of any hold that covers it.
//
// Forged or unreadable holds fail toward keeping data, which is why the object carries no signature
// (plan-ABUSE-hold-format's option 1). Nothing here logs or counts by network or repo id (I-13).

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Format values of the hold object (plan-ABUSE-hold-format), not settings.
const (
	holdRecordVersion = 1
	// §11.8's bound on the object.
	HoldRecordMaxByteCount = 1024
	// The most repo ids one scope lists.
	HoldScopeMaxRepoCount = 16
	// The object family, on the first metadata cluster only.
	holdKeyPrefix = "hold/"
	// The last element of every hold key, so no key prefixes another (§11.8's keys row).
	holdKeySuffix = "/_"
	// scope's one string value.
	holdScopeNetworkValue = "network"
)

// A hold's statutory kind, which sets its deadline (§21.9).
type HoldKind string

const (
	// 18 U.S.C. §2703(f): 90 days from placement, renewed once for 90 days by a renewed request.
	HoldKindPreserve2703f HoldKind = "preserve_2703f"
	// 18 U.S.C. §2258A(h): a year from the NCMEC report, which may precede placement; not renewable.
	HoldKindReport2258a HoldKind = "report_2258a"
)

// Whether this build knows the kind's deadline.
func (self HoldKind) known() bool {
	return self == HoldKindPreserve2703f || self == HoldKindReport2258a
}

// What a hold covers: the whole network, or the repos it lists. The zero value is the network.
type HoldScope struct {
	// Empty: the network. Otherwise 1 to HoldScopeMaxRepoCount repo ids.
	RepoIds []Id
}

// The scope of a whole network, counsel's default (plan-ABUSE-hold-format).
func HoldScopeNetwork() HoldScope {
	return HoldScope{}
}

// A scope of the listed repos.
func HoldScopeRepos(repoIds ...Id) HoldScope {
	return HoldScope{RepoIds: slices.Clone(repoIds)}
}

// Whether the scope is the whole network.
func (self HoldScope) Network() bool {
	return len(self.RepoIds) == 0
}

// Whether the scope covers repoId. A zero repoId asks for what is the network's and no one repo's,
// such as a server row, which every hold of the network covers (plan-ABUSE-hold-format: server rows
// are always covered by network).
func (self HoldScope) Covers(repoId Id) bool {
	if self.Network() || repoId == (Id{}) {
		return true
	}
	return slices.Contains(self.RepoIds, repoId)
}

// One hold object's terms (evs-19's fields, and the placement time FS-69 needs).
type HoldRecord struct {
	NetworkId Id
	CaseId    Id
	Kind      HoldKind
	Scope     HoldScope
	// When the hold was placed, kept across a renewal: what existed then is what the hold keeps.
	PlaceTime time.Time
	// When the hold ends by its kind's deadline, renewal included. Past it the record is no hold.
	ExpireTime time.Time
}

// Whether the hold stands at now: before its own expire time.
func (self *HoldRecord) Live(now time.Time) bool {
	return now.Before(self.ExpireTime)
}

// A record EncodeHoldRecord refuses, or a body ParseHoldRecord cannot read as a known hold. A reader
// that gets one covers the whole network. The message names no id (I-13).
var ErrHoldRecordInvalid = errors.New("hold record invalid")

// A record whose encoding would pass §11.8's 1 KiB, refused at encode.
var ErrHoldRecordTooLarge = errors.New("hold record too large")

// The key of one hold: hold/<network_id>/<case_id>/_.
func HoldObjectKey(networkId Id, caseId Id) string {
	return holdNetworkKeyPrefix(networkId) + caseId.String() + holdKeySuffix
}

// Every hold key of one network starts with this.
func holdNetworkKeyPrefix(networkId Id) string {
	return holdKeyPrefix + networkId.String() + "/"
}

// The object's bytes, keys in the order the format fixes, with no trailing newline. Refuses a
// record a reader could not read back as the same hold: zero ids, an unknown kind, a scope of more
// than HoldScopeMaxRepoCount repos or a zero repo id, a placement before 1970 or an expiry not after
// it, and anything over HoldRecordMaxByteCount, which is checked before the scope's count.
func EncodeHoldRecord(record *HoldRecord) ([]byte, error) {
	if record.NetworkId == (Id{}) || record.CaseId == (Id{}) {
		return nil, fmt.Errorf("%w: a zero network or case id", ErrHoldRecordInvalid)
	}
	if !record.Kind.known() {
		return nil, fmt.Errorf("%w: an unknown kind", ErrHoldRecordInvalid)
	}
	for _, repoId := range record.Scope.RepoIds {
		if repoId == (Id{}) {
			return nil, fmt.Errorf("%w: a zero repo id in the scope", ErrHoldRecordInvalid)
		}
	}
	placeTimeMs := record.PlaceTime.UnixMilli()
	expireTimeMs := record.ExpireTime.UnixMilli()
	if record.PlaceTime.IsZero() || placeTimeMs < 0 {
		return nil, fmt.Errorf("%w: no placement time", ErrHoldRecordInvalid)
	}
	if expireTimeMs <= placeTimeMs {
		return nil, fmt.Errorf("%w: an expiry not after the placement", ErrHoldRecordInvalid)
	}

	b := &bytes.Buffer{}
	b.WriteString(`{"version":`)
	b.WriteString(strconv.Itoa(holdRecordVersion))
	b.WriteString(`,"network_id":"`)
	b.WriteString(record.NetworkId.String())
	b.WriteString(`","case_id":"`)
	b.WriteString(record.CaseId.String())
	b.WriteString(`","kind":"`)
	b.WriteString(string(record.Kind))
	b.WriteString(`","scope":`)
	if record.Scope.Network() {
		b.WriteString(`"` + holdScopeNetworkValue + `"`)
	} else {
		b.WriteByte('[')
		for i, repoId := range record.Scope.RepoIds {
			if 0 < i {
				b.WriteByte(',')
			}
			b.WriteString(`"` + repoId.String() + `"`)
		}
		b.WriteByte(']')
	}
	b.WriteString(`,"place_time_ms":`)
	b.WriteString(strconv.FormatInt(placeTimeMs, 10))
	b.WriteString(`,"expire_time_ms":`)
	b.WriteString(strconv.FormatInt(expireTimeMs, 10))
	b.WriteByte('}')

	if HoldRecordMaxByteCount < b.Len() {
		return nil, fmt.Errorf("%w: %d bytes", ErrHoldRecordTooLarge, b.Len())
	}
	if HoldScopeMaxRepoCount < len(record.Scope.RepoIds) {
		return nil, fmt.Errorf("%w: a scope of %d repos", ErrHoldRecordInvalid, len(record.Scope.RepoIds))
	}
	return b.Bytes(), nil
}

// The JSON object as it arrives. Pointers tell a missing key from a zero one.
type holdRecordJson struct {
	Version      *int            `json:"version"`
	NetworkId    *Id             `json:"network_id"`
	CaseId       *Id             `json:"case_id"`
	Kind         *string         `json:"kind"`
	Scope        json.RawMessage `json:"scope"`
	PlaceTimeMs  *int64          `json:"place_time_ms"`
	ExpireTimeMs *int64          `json:"expire_time_ms"`
}

// Reads one object's body as a known hold, or answers ErrHoldRecordInvalid: a body over
// HoldRecordMaxByteCount, JSON that does not parse, a key missing or unknown, trailing bytes, an
// unknown version or kind, a scope that is neither "network" nor 1 to HoldScopeMaxRepoCount repo ids,
// zero ids, or an expiry not after the placement. A reader covers the whole network on any of these.
func ParseHoldRecord(body []byte) (*HoldRecord, error) {
	if HoldRecordMaxByteCount < len(body) {
		return nil, fmt.Errorf("%w: %d bytes", ErrHoldRecordInvalid, len(body))
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	y := &holdRecordJson{}
	if err := decoder.Decode(y); err != nil {
		return nil, fmt.Errorf("%w: the body does not parse", ErrHoldRecordInvalid)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: bytes after the object", ErrHoldRecordInvalid)
	}
	if y.Version == nil || y.NetworkId == nil || y.CaseId == nil || y.Kind == nil || y.Scope == nil ||
		y.PlaceTimeMs == nil || y.ExpireTimeMs == nil {
		return nil, fmt.Errorf("%w: a key is missing", ErrHoldRecordInvalid)
	}
	if *y.Version != holdRecordVersion {
		return nil, fmt.Errorf("%w: version %d", ErrHoldRecordInvalid, *y.Version)
	}
	if *y.NetworkId == (Id{}) || *y.CaseId == (Id{}) {
		return nil, fmt.Errorf("%w: a zero network or case id", ErrHoldRecordInvalid)
	}
	kind := HoldKind(*y.Kind)
	if !kind.known() {
		return nil, fmt.Errorf("%w: an unknown kind", ErrHoldRecordInvalid)
	}
	scope, err := parseHoldScope(y.Scope)
	if err != nil {
		return nil, err
	}
	if *y.PlaceTimeMs < 0 || *y.ExpireTimeMs <= *y.PlaceTimeMs {
		return nil, fmt.Errorf("%w: times out of order", ErrHoldRecordInvalid)
	}
	return &HoldRecord{
		NetworkId:  *y.NetworkId,
		CaseId:     *y.CaseId,
		Kind:       kind,
		Scope:      scope,
		PlaceTime:  time.UnixMilli(*y.PlaceTimeMs).UTC(),
		ExpireTime: time.UnixMilli(*y.ExpireTimeMs).UTC(),
	}, nil
}

// "network", or a list of 1 to HoldScopeMaxRepoCount repo ids.
func parseHoldScope(raw json.RawMessage) (HoldScope, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		if value == holdScopeNetworkValue {
			return HoldScopeNetwork(), nil
		}
		return HoldScope{}, fmt.Errorf("%w: an unknown scope", ErrHoldRecordInvalid)
	}
	var repoIds []Id
	if err := json.Unmarshal(raw, &repoIds); err != nil {
		return HoldScope{}, fmt.Errorf("%w: an unknown scope", ErrHoldRecordInvalid)
	}
	if len(repoIds) == 0 || HoldScopeMaxRepoCount < len(repoIds) {
		return HoldScope{}, fmt.Errorf("%w: a scope of %d repos", ErrHoldRecordInvalid, len(repoIds))
	}
	for _, repoId := range repoIds {
		if repoId == (Id{}) {
			return HoldScope{}, fmt.Errorf("%w: a zero repo id in the scope", ErrHoldRecordInvalid)
		}
	}
	return HoldScope{RepoIds: repoIds}, nil
}

// What covers one repo at one read: the live holds whose scope covers it, and whether something whose
// terms are unknown covers it too. An unknown cover keeps everything in scope, with no end and no
// placement, so a caller deletes nothing it covers.
type HoldCover struct {
	// Each live covering hold, its own object. The union governs (§21.9's overlap rule).
	Holds []*HoldRecord
	// A body no reader can read as a known hold, a listing or read that failed, or a repo whose
	// network is not known.
	Unknown bool
}

// Whether anything covers: while true, a server sweep, GC or drop deletes nothing in scope.
func (self *HoldCover) Covered() bool {
	return self.Unknown || 0 < len(self.Holds)
}

// When the cover ends: the latest expire time of any covering hold. bounded is false while nothing
// covers, and while the cover is unknown, which has no end a reader can trust.
func (self *HoldCover) ExpireTime() (expireTime time.Time, bounded bool) {
	if self.Unknown || len(self.Holds) == 0 {
		return time.Time{}, false
	}
	for _, record := range self.Holds {
		if record.ExpireTime.After(expireTime) {
			expireTime = record.ExpireTime
		}
	}
	return expireTime, true
}

// Whether content created at createTime is kept: it existed when some covering hold was placed, so
// the versionless purge keeps it while purging what came since (owner decision 133, FS-69). An
// unknown cover keeps everything.
func (self *HoldCover) Keeps(createTime time.Time) bool {
	if self.Unknown {
		return true
	}
	for _, record := range self.Holds {
		if !createTime.After(record.PlaceTime) {
			return true
		}
	}
	return false
}

// Tunables of a HoldSet.
type HoldSetSettings struct {
	// How long one network's read answers before the next LIST: §11.13's reread rows cache hold/ at
	// most 5 s, so a hold placed now covers within that. Non-positive rereads on every call.
	RereadInterval time.Duration
	// Keys one LIST page asks for. A network's holds are few; a page bounds what one request returns.
	// Must be positive.
	ListPageCount int
	// Networks kept cached past which a new read drops every stale one, so a long-lived process that
	// asks about many networks holds at most this many stale reads. Non-positive drops stale reads on
	// every new one.
	CacheNetworkCount int
}

// §11.13's 5 s reread.
func DefaultHoldSetSettings() *HoldSetSettings {
	return &HoldSetSettings{
		RereadInterval:    5 * time.Second,
		ListPageCount:     1000,
		CacheNetworkCount: 4096,
	}
}

// One hold object as a read found it.
type holdObject struct {
	etag string
	// nil when the object covers the network with unknown terms
	record *HoldRecord
}

// One read of a network's hold/ prefix, shared by the callers that wait on it.
type holdRead struct {
	done chan struct{}
	// set before done closes
	keyObjects map[string]*holdObject
	err        error
}

// One network's cache: its last good read, and the read in flight.
type holdNetworkEntry struct {
	keyObjects map[string]*holdObject
	readTime   time.Time
	reading    *holdRead
}

// The holds of every network, read from the first metadata cluster through one cache per network.
// Concurrent callers for one network share one read, and no lock is held across I/O. Safe for
// concurrent use.
type HoldSet struct {
	blobs    BlobStore
	clock    Clock
	settings *HoldSetSettings

	stateLock        sync.Mutex
	networkIdEntries map[Id]*holdNetworkEntry
}

// clock nil is real time, and settings nil the defaults.
func NewHoldSet(blobs BlobStore, clock Clock, settings *HoldSetSettings) *HoldSet {
	if settings == nil {
		settings = DefaultHoldSetSettings()
	}
	return &HoldSet{
		blobs:            blobs,
		clock:            clockOrReal(clock),
		settings:         settings,
		networkIdEntries: map[Id]*holdNetworkEntry{},
	}
}

// The live holds of networkId whose scope covers repoId, from a read at most RereadInterval old. A
// zero repoId asks for what is the network's and no one repo's, which every hold covers. A zero
// networkId is a repo whose network the caller does not know, which is covered with unknown terms
// (plan-EVSB-repo-network: a reader that finds no network keeps everything).
//
// On a LIST or GET that fails, the answer is an unknown cover together with the error, so a caller
// that reads only the cover still deletes nothing.
func (self *HoldSet) Covering(ctx context.Context, networkId Id, repoId Id) (*HoldCover, error) {
	if networkId == (Id{}) {
		return &HoldCover{Unknown: true}, nil
	}
	keyObjects, err := self.networkObjects(ctx, networkId)
	if err != nil {
		return &HoldCover{Unknown: true}, err
	}
	now := self.clock.Now()
	cover := &HoldCover{}
	for _, object := range keyObjects {
		switch {
		case object.record == nil:
			cover.Unknown = true
		case !object.record.Live(now):
			// past its own expiry, whether or not api has deleted it yet
		case object.record.Scope.Covers(repoId):
			// a copy, so a caller cannot change what the cache holds
			record := *object.record
			record.Scope = HoldScopeRepos(object.record.Scope.RepoIds...)
			cover.Holds = append(cover.Holds, &record)
		}
	}
	// a stable order, since the cache is a map
	slices.SortFunc(cover.Holds, func(a *HoldRecord, b *HoldRecord) int {
		return a.CaseId.Cmp(b.CaseId)
	})
	return cover, nil
}

// The network's hold objects by key: the cached read while it is fresh, the read in flight when one
// is, else a new read, which this caller makes and others share.
func (self *HoldSet) networkObjects(ctx context.Context, networkId Id) (map[string]*holdObject, error) {
	now := self.clock.Now()
	var cached map[string]*holdObject
	var previous map[string]*holdObject
	var read *holdRead
	reader := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry := self.networkIdEntries[networkId]
		if entry == nil {
			self.dropStaleWithLock(now)
			entry = &holdNetworkEntry{}
			self.networkIdEntries[networkId] = entry
		}
		if entry.reading != nil {
			read = entry.reading
			return
		}
		if entry.keyObjects != nil && now.Sub(entry.readTime) < self.settings.RereadInterval {
			cached = entry.keyObjects
			return
		}
		previous = entry.keyObjects
		read = &holdRead{done: make(chan struct{})}
		entry.reading = read
		reader = true
	}()
	if cached != nil {
		return cached, nil
	}
	if !reader {
		select {
		case <-read.done:
			return read.keyObjects, read.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// A read that never finishes, by a panic or a schedule's crash, still releases its waiters, and
	// with an error, since nothing read must never pass for no holds.
	completed := false
	defer func() {
		if !completed {
			read.keyObjects, read.err = nil, errHoldReadAbandoned
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			entry := self.networkIdEntries[networkId]
			entry.reading = nil
			if read.err == nil {
				entry.keyObjects = read.keyObjects
				// the time before the LIST, so a read is never older than it claims
				entry.readTime = now
			}
		}()
		close(read.done)
	}()
	read.keyObjects, read.err = self.readNetwork(ctx, networkId, previous)
	completed = true
	return read.keyObjects, read.err
}

// What waiters get from a read that ended without an answer.
var errHoldReadAbandoned = errors.New("hold read abandoned")

// Drops every cached read that has gone stale and is not being read, once the cache is past
// CacheNetworkCount.
func (self *HoldSet) dropStaleWithLock(now time.Time) {
	if len(self.networkIdEntries) < self.settings.CacheNetworkCount {
		return
	}
	for networkId, entry := range self.networkIdEntries {
		if entry.reading == nil && self.settings.RereadInterval <= now.Sub(entry.readTime) {
			delete(self.networkIdEntries, networkId)
		}
	}
}

// One LIST of the network's prefix, page by page, and a GET of each object new or changed since
// previous, matched by ETag.
func (self *HoldSet) readNetwork(ctx context.Context, networkId Id, previous map[string]*holdObject) (map[string]*holdObject, error) {
	cluster, err := self.blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	keyPrefix := holdNetworkKeyPrefix(networkId)
	infos := []*BlobInfo{}
	testHookBarrier("hold.list.before", networkId.String())
	startAfter := ""
	for {
		page, more, err := cluster.List(ctx, keyPrefix, startAfter, self.settings.ListPageCount)
		if err != nil {
			return nil, err
		}
		infos = append(infos, page...)
		if !more || len(page) == 0 {
			break
		}
		startAfter = page[len(page)-1].Key
	}
	testHookBarrier("hold.list.after", networkId.String())

	keyObjects := map[string]*holdObject{}
	for _, info := range infos {
		if object, ok := previous[info.Key]; ok && object.etag == info.Etag {
			keyObjects[info.Key] = object
			continue
		}
		body, etag, err := self.getBody(ctx, cluster, info.Key)
		if errors.Is(err, ErrBlobNotFound) {
			// api deleted it between the LIST and the GET: that hold has ended
			continue
		}
		if err != nil {
			return nil, err
		}
		keyObjects[info.Key] = &holdObject{
			etag:   etag,
			record: holdRecordOfObject(networkId, strings.TrimPrefix(info.Key, keyPrefix), body),
		}
	}
	return keyObjects, nil
}

// An object's body, read to one byte past the bound so an oversized body shows as one.
func (self *HoldSet) getBody(ctx context.Context, cluster BlobCluster, key string) ([]byte, string, error) {
	object, err := cluster.Get(ctx, key)
	if err != nil {
		return nil, "", err
	}
	defer object.Body.Close()
	body, err := io.ReadAll(io.LimitReader(object.Body, HoldRecordMaxByteCount+1))
	if err != nil {
		return nil, "", err
	}
	return body, object.Etag, nil
}

// What one object under hold/<network_id>/ holds, or nil when its terms are unknown: a key that is
// not <case_id>/_, a body ParseHoldRecord refuses, or one naming another network or case than its
// key.
func holdRecordOfObject(networkId Id, keyRest string, body []byte) *HoldRecord {
	caseIdStr, found := strings.CutSuffix(keyRest, holdKeySuffix)
	if !found {
		return nil
	}
	caseId, err := ParseId(caseIdStr)
	if err != nil {
		return nil
	}
	record, err := ParseHoldRecord(body)
	if err != nil {
		return nil
	}
	if record.NetworkId != networkId || record.CaseId != caseId {
		return nil
	}
	return record
}
