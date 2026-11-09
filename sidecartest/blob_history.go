// A record of what a store's clients saw, and FI-30's check of it. BlobRecorder wraps any BlobStore, a
// fake or a real one, so one check reads T2's and T3's histories. It sees only what a client sees, so
// the check asks the question a client can: is there an order of these requests, each taking effect
// between its call and its answer, in which every answer was right? A write whose outcome is unknown
// may land anywhere up to its deadline, or never (§19.6). That is D-OPS-20 seen from outside: a write
// landing past its deadline, an acknowledged write lost, a stale read and a resurrection each leave a
// history with no such order, and a write the store acknowledged though it was issued past its
// deadline is refused outright. A LIST is a request on every key under its prefix that it covers, and
// reads each as a GET would, so a LIST showing a deleted key or missing an acknowledged one is wrong
// too. The keys it checks a LIST against are the ones the history has other requests on, or a start
// for: a key nothing else in it touched may have any past.
//
// Past a deadline is by the recorder's clock, the sender's, which x-ur-deadline-ms is written in. A
// store's own clock may sit up to §19.6's 50 ms behind it and take a write issued less than that past
// its deadline, so a T3 schedule that sends a late write sends it further past than that.
//
// Safe for concurrent use.

package sidecartest

import (
	"cmp"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

type BlobOutcome string

const (
	BlobOutcomeOk           BlobOutcome = "ok"
	BlobOutcomeNotFound     BlobOutcome = "not-found"
	BlobOutcomePrecondition BlobOutcome = "precondition"
	// The request took no effect: a hold, a bad checksum, bad options or a bad range.
	BlobOutcomeRefused BlobOutcome = "refused"
	// A write that may have landed.
	BlobOutcomeUnknown BlobOutcome = "unknown"
	// A read with no answer.
	BlobOutcomeFailed BlobOutcome = "failed"
)

type BlobHistoryOp string

const (
	BlobHistoryPutIfNoneMatch BlobHistoryOp = "put-if-none-match"
	BlobHistoryPutIfMatch     BlobHistoryOp = "put-if-match"
	BlobHistoryPutStream      BlobHistoryOp = "put-stream"
	BlobHistoryGet            BlobHistoryOp = "get"
	BlobHistoryGetRange       BlobHistoryOp = "get-range"
	BlobHistoryHead           BlobHistoryOp = "head"
	BlobHistoryList           BlobHistoryOp = "list"
	BlobHistoryDelete         BlobHistoryOp = "delete"
)

// One request as a client saw it. Seqs order calls and answers across a recorder.
type BlobHistoryEntry struct {
	ClusterId string
	Actor     string
	Op        BlobHistoryOp
	Key       string
	// PutIfMatch's condition.
	IfEtag string
	// A write: the ETag its bytes have, known before the store answers.
	WriteEtag string
	// A read: what it saw.
	ReadEtag string
	Outcome  BlobOutcome
	// A LIST: Key is its prefix, and it covers the keys after StartAfter, up to the last it returned
	// when ListTruncated says more follow.
	StartAfter     string
	ListedKeyEtags map[string]string
	ListTruncated  bool

	InvokeSeq uint64
	// Zero: no answer yet.
	ReturnSeq uint64
	Invoked   time.Time
	Returned  time.Time
	// When the store stops taking this request. Zero: no deadline.
	Deadline time.Time
}

func (self *BlobHistoryEntry) String() string {
	return fmt.Sprintf(
		"[%d,%d] %s %s %s if=%s write=%s read=%s -> %s",
		self.InvokeSeq, self.ReturnSeq, self.Actor, self.Op, self.Key,
		self.IfEtag, self.WriteEtag, self.ReadEtag, self.Outcome,
	)
}

// Wraps store so every request through it is kept. Hand engines the recorder, and read the history
// from the recorder too. etagOf is what the store's ETag for a body is, so a write whose answer was
// lost can be recognized when a read finds it; nil means an MD5, which MinIO's and the fake's are.
type BlobRecorder struct {
	store  sidecar.BlobStore
	clock  Clock
	etagOf func(body []byte) string

	stateLock sync.Mutex
	seq       uint64
	entries   []*BlobHistoryEntry
}

func NewBlobRecorder(store sidecar.BlobStore, clock Clock, etagOf func(body []byte) string) *BlobRecorder {
	if etagOf == nil {
		etagOf = func(body []byte) string {
			sum := md5.Sum(body)
			return hex.EncodeToString(sum[:])
		}
	}
	return &BlobRecorder{store: store, clock: clock, etagOf: etagOf}
}

func (self *BlobRecorder) wrap(cluster sidecar.BlobCluster, err error) (sidecar.BlobCluster, error) {
	if err != nil {
		return nil, err
	}
	return &recordedBlobCluster{BlobCluster: cluster, recorder: self}, nil
}

func (self *BlobRecorder) Cluster(clusterId string) (sidecar.BlobCluster, error) {
	return self.wrap(self.store.Cluster(clusterId))
}

func (self *BlobRecorder) FirstCluster() (sidecar.BlobCluster, error) {
	return self.wrap(self.store.FirstCluster())
}

func (self *BlobRecorder) SegmentCluster() (sidecar.BlobCluster, error) {
	return self.wrap(self.store.SegmentCluster())
}

func (self *BlobRecorder) MetadataClusterIds() []string {
	return self.store.MetadataClusterIds()
}

func (self *BlobRecorder) NewRepoClusterId() string {
	return self.store.NewRepoClusterId()
}

// Every request so far, in call order, each a copy, so a request still in flight changes nothing here.
func (self *BlobRecorder) History() []*BlobHistoryEntry {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := make([]*BlobHistoryEntry, 0, len(self.entries))
	for _, entry := range self.entries {
		entryCopy := *entry
		entries = append(entries, &entryCopy)
	}
	return entries
}

func (self *BlobRecorder) begin(ctx context.Context, entry *BlobHistoryEntry) {
	entry.Actor = ActorName(ctx)
	entry.Invoked = self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.seq += 1
	entry.InvokeSeq = self.seq
	self.entries = append(self.entries, entry)
}

func (self *BlobRecorder) end(entry *BlobHistoryEntry, outcome BlobOutcome, readEtag string) {
	returned := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.seq += 1
	entry.ReturnSeq = self.seq
	entry.Returned = returned
	entry.Outcome = outcome
	entry.ReadEtag = readEtag
}

func blobOutcomeOf(err error, isWrite bool) BlobOutcome {
	switch {
	case err == nil:
		return BlobOutcomeOk
	case errors.Is(err, sidecar.ErrBlobNotFound):
		return BlobOutcomeNotFound
	case errors.Is(err, sidecar.ErrBlobPrecondition):
		return BlobOutcomePrecondition
	case errors.Is(err, sidecar.ErrBlobHeld), errors.Is(err, sidecar.ErrBlobChecksum),
		errors.Is(err, sidecar.ErrBlobPutOptions), errors.Is(err, sidecar.ErrBlobRange):
		return BlobOutcomeRefused
	case isWrite:
		return BlobOutcomeUnknown
	}
	return BlobOutcomeFailed
}

type recordedBlobCluster struct {
	sidecar.BlobCluster
	recorder *BlobRecorder
}

func (self *recordedBlobCluster) entry(ctx context.Context, op BlobHistoryOp, key string) *BlobHistoryEntry {
	entry := &BlobHistoryEntry{ClusterId: self.ClusterId(), Op: op, Key: key}
	if op != BlobHistoryPutStream {
		entry.Deadline = sidecar.BlobRequestDeadline(ctx, clockOf(ctx, self.recorder.clock).Now(), self.RequestTimeout())
	}
	return entry
}

func (self *recordedBlobCluster) PutIfNoneMatch(ctx context.Context, key string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	entry := self.entry(ctx, BlobHistoryPutIfNoneMatch, key)
	entry.WriteEtag = self.recorder.etagOf(body)
	self.recorder.begin(ctx, entry)
	newEtag, err := self.BlobCluster.PutIfNoneMatch(ctx, key, body, options)
	self.recorder.end(entry, blobOutcomeOf(err, true), "")
	return newEtag, err
}

func (self *recordedBlobCluster) PutIfMatch(ctx context.Context, key string, etag string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	entry := self.entry(ctx, BlobHistoryPutIfMatch, key)
	entry.IfEtag = etag
	entry.WriteEtag = self.recorder.etagOf(body)
	self.recorder.begin(ctx, entry)
	newEtag, err := self.BlobCluster.PutIfMatch(ctx, key, etag, body, options)
	self.recorder.end(entry, blobOutcomeOf(err, true), "")
	return newEtag, err
}

func (self *recordedBlobCluster) PutStream(ctx context.Context, key string, body io.Reader, byteCount int64, checksumSha256 []byte) (string, error) {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return "", &sidecar.BlobUnknownError{Err: err}
	}
	entry := self.entry(ctx, BlobHistoryPutStream, key)
	entry.WriteEtag = self.recorder.etagOf(bodyBytes)
	self.recorder.begin(ctx, entry)
	newEtag, err := self.BlobCluster.PutStream(ctx, key, strings.NewReader(string(bodyBytes)), byteCount, checksumSha256)
	self.recorder.end(entry, blobOutcomeOf(err, true), "")
	return newEtag, err
}

func (self *recordedBlobCluster) Get(ctx context.Context, key string) (*sidecar.BlobObject, error) {
	// an oracle's look under InspectContext is no request a client made, so FI-30 never reads it
	if isInspecting(ctx) {
		return self.BlobCluster.Get(ctx, key)
	}
	entry := self.entry(ctx, BlobHistoryGet, key)
	self.recorder.begin(ctx, entry)
	object, err := self.BlobCluster.Get(ctx, key)
	readEtag := ""
	if err == nil {
		readEtag = object.Etag
	}
	self.recorder.end(entry, blobOutcomeOf(err, false), readEtag)
	return object, err
}

func (self *recordedBlobCluster) GetRange(ctx context.Context, key string, offset int64, byteCount int64) (*sidecar.BlobObject, error) {
	// an oracle's look under InspectContext is no request a client made, so FI-30 never reads it
	if isInspecting(ctx) {
		return self.BlobCluster.GetRange(ctx, key, offset, byteCount)
	}
	entry := self.entry(ctx, BlobHistoryGetRange, key)
	self.recorder.begin(ctx, entry)
	object, err := self.BlobCluster.GetRange(ctx, key, offset, byteCount)
	readEtag := ""
	if err == nil {
		readEtag = object.Etag
	}
	self.recorder.end(entry, blobOutcomeOf(err, false), readEtag)
	return object, err
}

func (self *recordedBlobCluster) Head(ctx context.Context, key string) (*sidecar.BlobInfo, error) {
	// an oracle's look under InspectContext is no request a client made, so FI-30 never reads it
	if isInspecting(ctx) {
		return self.BlobCluster.Head(ctx, key)
	}
	entry := self.entry(ctx, BlobHistoryHead, key)
	self.recorder.begin(ctx, entry)
	info, err := self.BlobCluster.Head(ctx, key)
	readEtag := ""
	if err == nil {
		readEtag = info.Etag
	}
	self.recorder.end(entry, blobOutcomeOf(err, false), readEtag)
	return info, err
}

func (self *recordedBlobCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	// an oracle's look under InspectContext is no request a client made, so FI-30 never reads it
	if isInspecting(ctx) {
		return self.BlobCluster.List(ctx, keyPrefix, startAfter, limit)
	}
	entry := self.entry(ctx, BlobHistoryList, keyPrefix)
	self.recorder.begin(ctx, entry)
	entry.StartAfter = startAfter
	objects, more, err := self.BlobCluster.List(ctx, keyPrefix, startAfter, limit)
	listedKeyEtags := map[string]string{}
	for _, object := range objects {
		listedKeyEtags[object.Key] = object.Etag
	}
	func() {
		self.recorder.stateLock.Lock()
		defer self.recorder.stateLock.Unlock()
		entry.ListedKeyEtags = listedKeyEtags
		entry.ListTruncated = more
	}()
	self.recorder.end(entry, blobOutcomeOf(err, false), "")
	return objects, more, err
}

func (self *recordedBlobCluster) Delete(ctx context.Context, key string) error {
	entry := self.entry(ctx, BlobHistoryDelete, key)
	self.recorder.begin(ctx, entry)
	err := self.BlobCluster.Delete(ctx, key)
	self.recorder.end(entry, blobOutcomeOf(err, true), "")
	return err
}

// One key's state in the check's model.
type blobModelState struct {
	exists bool
	etag   string
}

// Applied or not: every state op can leave, given the state before it and its answer. Empty means the
// answer is impossible from that state. An unknown write has two.
func (self *BlobHistoryEntry) nextStates(state blobModelState) []blobModelState {
	outcome := self.Outcome
	if outcome == "" {
		// still in flight, so as good as unknown
		outcome = BlobOutcomeUnknown
	}
	switch self.Op {
	case BlobHistoryGet, BlobHistoryGetRange, BlobHistoryHead, BlobHistoryList:
		// a LIST here is one key's share of it, as listedEntries makes it
		switch outcome {
		case BlobOutcomeOk:
			if state.exists && state.etag == self.ReadEtag {
				return []blobModelState{state}
			}
			return nil
		case BlobOutcomeNotFound:
			if !state.exists {
				return []blobModelState{state}
			}
			return nil
		}
		return []blobModelState{state}
	case BlobHistoryDelete:
		switch outcome {
		case BlobOutcomeOk:
			return []blobModelState{{}}
		case BlobOutcomeUnknown:
			return []blobModelState{{}, state}
		}
		return []blobModelState{state}
	}
	// a PUT, whose condition says whether it could apply
	conditionHolds := !state.exists
	if self.Op == BlobHistoryPutIfMatch {
		conditionHolds = state.exists && state.etag == self.IfEtag
	}
	written := blobModelState{exists: true, etag: self.WriteEtag}
	switch outcome {
	case BlobOutcomeOk:
		if conditionHolds {
			return []blobModelState{written}
		}
		return nil
	case BlobOutcomePrecondition:
		if !conditionHolds {
			return []blobModelState{state}
		}
		return nil
	case BlobOutcomeUnknown:
		if conditionHolds {
			return []blobModelState{written, state}
		}
	}
	return []blobModelState{state}
}

func (self *BlobHistoryEntry) isWrite() bool {
	switch self.Op {
	case BlobHistoryPutIfNoneMatch, BlobHistoryPutIfMatch, BlobHistoryPutStream, BlobHistoryDelete:
		return true
	}
	return false
}

func (self *BlobHistoryEntry) issuedPastDeadline() bool {
	return !self.Deadline.IsZero() && !self.Invoked.Before(self.Deadline)
}

// Whether this write, with no acknowledgement, could take effect at all: one issued past its deadline
// could not, since the store refuses it (§19.6). A read keeps whatever it saw, deadline or not, and
// an acknowledged write issued past its deadline is a violation of its own (CheckBlobHistory).
func (self *BlobHistoryEntry) deadOnArrival() bool {
	return self.isWrite() && self.Outcome != BlobOutcomeOk && self.issuedPastDeadline()
}

// A LIST's share for each key it covers among keys: a read of that key, finding it with the ETag
// listed or finding it absent. A LIST with no answer says nothing.
func (self *BlobHistoryEntry) listedEntries(keys []string) []*BlobHistoryEntry {
	if self.Outcome != BlobOutcomeOk {
		return nil
	}
	last := ""
	for key := range self.ListedKeyEtags {
		last = max(last, key)
	}
	entries := []*BlobHistoryEntry{}
	for _, key := range keys {
		if !strings.HasPrefix(key, self.Key) || key <= self.StartAfter || (self.ListTruncated && last < key) {
			continue
		}
		entry := *self
		entry.Key = key
		entry.ListedKeyEtags = nil
		if etag, listed := self.ListedKeyEtags[key]; listed {
			entry.ReadEtag = etag
		} else {
			entry.Outcome = BlobOutcomeNotFound
		}
		entries = append(entries, &entry)
	}
	return entries
}

// The last seq at which this request can take effect. An answered one, its answer's. One with no
// definite answer may land after its caller gave up, but before any request issued past its deadline.
func blobLatestSeq(entry *BlobHistoryEntry, keyEntries []*BlobHistoryEntry) uint64 {
	const unbounded = ^uint64(0)
	if entry.Outcome != BlobOutcomeUnknown && entry.ReturnSeq != 0 {
		return entry.ReturnSeq
	}
	if entry.Deadline.IsZero() {
		return unbounded
	}
	latest := unbounded
	for _, other := range keyEntries {
		if !other.Invoked.Before(entry.Deadline) && other.InvokeSeq <= latest {
			latest = other.InvokeSeq - 1
		}
	}
	return latest
}

// The most requests one key's check takes: a search over more says nothing it can finish saying. A
// schedule writes one key far fewer times than this.
const blobHistoryKeyLimit = 256

// Searches for an order of one key's requests with every answer right, from a key that held initial.
func checkBlobKeyHistory(keyEntries []*BlobHistoryEntry, initial blobModelState) error {
	if blobHistoryKeyLimit < len(keyEntries) {
		return fmt.Errorf("%d requests is more than one check takes", len(keyEntries))
	}
	latestSeqs := make([]uint64, len(keyEntries))
	for index, entry := range keyEntries {
		latestSeqs[index] = blobLatestSeq(entry, keyEntries)
	}
	done := make([]bool, len(keyEntries))
	visited := map[string]bool{}
	var search func(state blobModelState, remaining int) bool
	search = func(state blobModelState, remaining int) bool {
		if remaining == 0 {
			return true
		}
		memoKey := make([]byte, 0, len(done)+len(state.etag)+1)
		for _, entryDone := range done {
			if entryDone {
				memoKey = append(memoKey, '1')
			} else {
				memoKey = append(memoKey, '0')
			}
		}
		if state.exists {
			memoKey = append(memoKey, '+')
		}
		memoKey = append(memoKey, state.etag...)
		if visited[string(memoKey)] {
			return false
		}
		visited[string(memoKey)] = true

		// a request may go next only if nothing left had to finish before it began
		firstDeadline := ^uint64(0)
		for index := range keyEntries {
			if !done[index] {
				firstDeadline = min(firstDeadline, latestSeqs[index])
			}
		}
		for index, entry := range keyEntries {
			if done[index] || firstDeadline < entry.InvokeSeq {
				continue
			}
			done[index] = true
			for _, next := range entry.nextStates(state) {
				if search(next, remaining-1) {
					return true
				}
			}
			done[index] = false
		}
		return false
	}
	if !search(initial, len(keyEntries)) {
		return errors.New("no order of these requests gives every answer")
	}
	return nil
}

// FI-30 from outside: each key's requests have an order in which every answer was right and no
// unknown write landed past its deadline. Each key is taken to start absent, or as initialEtags gives,
// for a history that begins after its key was written.
func CheckBlobHistory(entries []*BlobHistoryEntry, initialEtags map[string]string) error {
	keyEntries := map[string][]*BlobHistoryEntry{}
	lists := []*BlobHistoryEntry{}
	for _, entry := range entries {
		if entry.isWrite() && entry.Outcome == BlobOutcomeOk && entry.issuedPastDeadline() {
			return fmt.Errorf("key %q: the store acknowledged a write issued past its deadline (§19.6)\n  %s", entry.Key, entry)
		}
		if entry.Op == BlobHistoryList {
			lists = append(lists, entry)
			continue
		}
		if entry.deadOnArrival() {
			continue
		}
		clusterKey := entry.ClusterId + "\x00" + entry.Key
		keyEntries[clusterKey] = append(keyEntries[clusterKey], entry)
	}
	for _, list := range lists {
		keys := []string{}
		for clusterKey := range keyEntries {
			if clusterId, key, _ := strings.Cut(clusterKey, "\x00"); clusterId == list.ClusterId {
				keys = append(keys, key)
			}
		}
		for key := range initialEtags {
			if _, ok := keyEntries[list.ClusterId+"\x00"+key]; !ok {
				keys = append(keys, key)
			}
		}
		for _, entry := range list.listedEntries(keys) {
			clusterKey := entry.ClusterId + "\x00" + entry.Key
			keyEntries[clusterKey] = append(keyEntries[clusterKey], entry)
		}
	}
	for _, each := range keyEntries {
		// in call order, as the search's seqs expect
		slices.SortStableFunc(each, func(a *BlobHistoryEntry, b *BlobHistoryEntry) int { return cmp.Compare(a.InvokeSeq, b.InvokeSeq) })
	}
	clusterKeys := make([]string, 0, len(keyEntries))
	for clusterKey := range keyEntries {
		clusterKeys = append(clusterKeys, clusterKey)
	}
	slices.Sort(clusterKeys)
	for _, clusterKey := range clusterKeys {
		initial := blobModelState{}
		_, key, _ := strings.Cut(clusterKey, "\x00")
		if etag, ok := initialEtags[key]; ok {
			initial = blobModelState{exists: true, etag: etag}
		}
		if err := checkBlobKeyHistory(keyEntries[clusterKey], initial); err != nil {
			lines := []string{fmt.Sprintf("key %q: %v", key, err)}
			for _, entry := range keyEntries[clusterKey] {
				lines = append(lines, "  "+entry.String())
			}
			return errors.New(strings.Join(lines, "\n"))
		}
	}
	return nil
}
