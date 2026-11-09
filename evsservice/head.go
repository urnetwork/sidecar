// The head (§11.8, D-EVS-29): head/<repo>/<ref>, a ref's one commit point, server-internal and never a client wire
// format. A ref's state changes only by a head If-Match PUT (If-None-Match to create), and its history is the
// sequence of those that succeeded (§11.8's linearizability). HeadStore is the one way evs and taskworker read and
// write it, so every write keeps the head's rules:
//
//   - every write raises the version or, for a write that commits nothing (a refusal record, a fence, a seal lease,
//     a creation block, dropping drained sources, a collection window), the fence, so an ETag never repeats: a
//     stale If-Match can never succeed (D-EVS-13). Commit refuses a next head that does neither;
//   - pins never fall: the authorization pin, the generation, index_epoch and consumed_through (§11.8, I-16);
//   - written_ms is the writer's clock at every write (§11.13's orphan rule);
//   - any write drops the refusal records whose until_s its writer's clock has passed, except on a process whose
//     clock is unsure, which drops none (§11.8's refusal row);
//   - only evacuation and GC fences set fence_ms (RaiseFence), and a refusal fence sets refused_ms (its caller);
//   - at most 255 window entries and 8 refusal records, and §11.8's size: ~8.9 KiB at 127 entries, 17 KiB at 255.
//
// Reads come from the cluster, or from {evsh_<repo_id>} (head_cache.go) where §11.9's cache row allows it: within
// 10 min of its cache time, at least the version asked, and never for a fresh read. Nothing here deletes.
//
// Safe for concurrent use; it holds no lock across I/O.

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §11.8's size row: at most ~0.85 KiB of fields, 255 window entries while folds lag and 8 refusal records.
const EvsHeadMaxByteCount = 17 * 1024

var (
	// A head whose bytes break the head's shape: a fault that alarms, never a state to act on.
	ErrEvsHeadInvalid = errors.New("evs head invalid")
	// A next head that would break one of the head's rules: a caller's bug, and nothing was written.
	ErrEvsHeadRule = errors.New("evs head rule broken")
	// A fence asked of a ref with no head: there is nothing to fence (questions/evs-models-gc-unfenced-new-ref).
	ErrEvsHeadAbsent = errors.New("evs head absent")
	// This process's clock is unsure, so it raises no evacuation or GC fence (§19.6's clocks row).
	ErrEvsClockUnsure = errors.New("evs clock unsure")
	// RaiseFence lost FenceRetryCount races in a row.
	ErrEvsHeadBusy = errors.New("evs head busy")
)

// A head as one read or write left it.
type EvsStoredHead struct {
	// The head, nil when the ref has none.
	Head *protocol.EvsHead
	// Its bytes as stored.
	Bytes []byte
	// What the next write's If-Match names. Empty when the ref has no head.
	Etag string
	// From {evsh_}: when it was cached, and the push sequence its commit raised. A cluster read leaves both zero.
	Cached       bool
	CachedAt     time.Time
	PushSequence uint64
}

// Whether the ref has no head: its first write creates one, If-None-Match.
func (self *EvsStoredHead) Absent() bool {
	return self.Head == nil
}

// The head's version, 0 when absent.
func (self *EvsStoredHead) Version() uint64 {
	return self.Head.GetVersion()
}

// A head's bytes held to its shape: a version past 0 names its push and chain; the window, refusal records and
// their bounds are whole; ids and chains have their widths. A placeholder head, version 0 with no window, kind or
// mode, is a head (§11.8's first row).
func ParseEvsHead(headBytes []byte) (*protocol.EvsHead, error) {
	if EvsHeadMaxByteCount < len(headBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrEvsHeadInvalid, len(headBytes))
	}
	head := &protocol.EvsHead{}
	if err := proto.Unmarshal(headBytes, head); err != nil {
		return nil, fmt.Errorf("%w: does not parse", ErrEvsHeadInvalid)
	}
	if err := checkEvsHeadShape(head); err != nil {
		return nil, err
	}
	return head, nil
}

// The shape ParseEvsHead and Commit both hold a head to.
func checkEvsHeadShape(head *protocol.EvsHead) error {
	if 0 < head.GetVersion() {
		if len(head.GetPushId()) != 16 || len(head.GetChain()) != 32 {
			return fmt.Errorf("%w: version %d with a push id of %d bytes and a chain of %d", ErrEvsHeadInvalid,
				head.GetVersion(), len(head.GetPushId()), len(head.GetChain()))
		}
	}
	window := head.GetWindow()
	if len(window)%sidecar.EvsWindowEntryByteCount != 0 || sidecar.EvsWindowMaxEntryCount < len(window)/sidecar.EvsWindowEntryByteCount {
		return fmt.Errorf("%w: a window of %d bytes", ErrEvsHeadInvalid, len(window))
	}
	if uint64(len(window)/sidecar.EvsWindowEntryByteCount) > head.GetVersion() {
		return fmt.Errorf("%w: %d window entries at version %d", ErrEvsHeadInvalid, len(window)/sidecar.EvsWindowEntryByteCount, head.GetVersion())
	}
	if 0 < len(window) && len(head.GetWindowBaseChain()) != 32 {
		return fmt.Errorf("%w: a window with no base chain", ErrEvsHeadInvalid)
	}
	refused := head.GetRefused()
	if len(refused)%sidecar.EvsRefusalByteCount != 0 || sidecar.EvsHeadMaxRefusalCount < len(refused)/sidecar.EvsRefusalByteCount {
		return fmt.Errorf("%w: %d bytes of refusal records", ErrEvsHeadInvalid, len(refused))
	}
	if head.GetFoldedThrough() > head.GetVersion() {
		return fmt.Errorf("%w: folded through %d past version %d", ErrEvsHeadInvalid, head.GetFoldedThrough(), head.GetVersion())
	}
	return nil
}

// The head's window entries, versions v-w+1 to v, oldest first.
func EvsHeadWindow(head *protocol.EvsHead) ([]*sidecar.EvsWindowEntry, error) {
	return sidecar.DecodeEvsWindow(head.GetWindow())
}

// The version of the head's oldest window entry, or v+1 when its window is empty.
func EvsHeadWindowFirstVersion(head *protocol.EvsHead) uint64 {
	return head.GetVersion() + 1 - uint64(len(head.GetWindow())/sidecar.EvsWindowEntryByteCount)
}

// A copy of a head to build the next write on.
func CloneEvsHead(head *protocol.EvsHead) *protocol.EvsHead {
	if head == nil {
		return &protocol.EvsHead{}
	}
	return proto.Clone(head).(*protocol.EvsHead)
}

// See the file header.
type HeadStore struct {
	clock      sidecar.Clock
	clockCheck sidecar.ClockCheck
	cache      *HeadCache
	settings   *EvsSettings
	log        sidecar.Logger
}

// A store reading and writing through clusters handed to each call. clockCheck nil reads as unsure; redis nil
// serves no cached head.
func NewHeadStore(clock sidecar.Clock, clockCheck sidecar.ClockCheck, redis sidecar.Redis, settings *EvsSettings, log sidecar.Logger) *HeadStore {
	return &HeadStore{
		clock:      clock,
		clockCheck: clockCheck,
		cache:      NewHeadCache(clock, redis, settings, log),
		settings:   settings,
		log:        log,
	}
}

// The head cache behind ReadCached.
func (self *HeadStore) Cache() *HeadCache {
	return self.cache
}

// Whether this process's clock is sure.
func (self *HeadStore) clockSure() bool {
	return self.clockCheck != nil && self.clockCheck.Sure()
}

// The ref's head from the cluster: one GET, which every refusal rests on (§11.8's refuse row). A 404 is an absent
// head, not an error; bytes that break the head's shape are ErrEvsHeadInvalid.
func (self *HeadStore) ReadCluster(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id) (*EvsStoredHead, error) {
	barrierKey := barrierRefKey(repoId, refId)
	testHookBarrier(BarrierHeadReadBefore, barrierKey)
	object, err := cluster.Get(ctx, HeadKey(repoId, refId))
	testHookBarrier(BarrierHeadReadAfter, barrierKey)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return &EvsStoredHead{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	headBytes, err := io.ReadAll(io.LimitReader(object.Body, EvsHeadMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	head, err := ParseEvsHead(headBytes)
	if err != nil {
		return nil, err
	}
	return &EvsStoredHead{Head: head, Bytes: headBytes, Etag: object.Etag}, nil
}

// The ref's head from {evsh_} when §11.9's cache row allows it: the request is not fresh, the entry is within
// HeadCacheServeAge of its cache time, and its version is at least atLeastVersion (a reader's pin, a hinted version,
// a push's base). Else, or when Redis does not answer, the cluster's.
func (self *HeadStore) ReadCached(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, atLeastVersion uint64, fresh bool) (*EvsStoredHead, error) {
	if !fresh {
		if cached, ok := self.cache.Read(ctx, repoId, refId, atLeastVersion); ok {
			return cached, nil
		}
	}
	return self.ReadCluster(ctx, cluster, repoId, refId)
}

// Writes next over prior: If-Match prior's ETag, or If-None-Match when prior is absent. next must raise the version,
// or keep it and raise the fence, and lower no pin; Commit sets written_ms and drops lapsed refusal records itself.
// The answer is the head as written. ErrBlobPrecondition means another write came first, and the caller rereads;
// a *sidecar.BlobUnknownError leaves the write's outcome to a reread (§11.8's unknown row). next is not kept.
func (self *HeadStore) Commit(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, prior *EvsStoredHead, next *protocol.EvsHead) (*EvsStoredHead, error) {
	written := CloneEvsHead(next)
	now := self.clock.Now()
	written.WrittenMs = now.UnixMilli()
	if self.clockSure() {
		refused, err := dropLapsedRefusals(written.GetRefused(), now.UnixMilli())
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEvsHeadRule, err)
		}
		written.Refused = refused
	}
	if err := checkEvsHeadShape(written); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsHeadRule, err)
	}
	if err := checkEvsHeadRises(prior.Head, written); err != nil {
		return nil, err
	}
	headBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(written)
	if err != nil {
		return nil, err
	}
	if EvsHeadMaxByteCount < len(headBytes) {
		return nil, fmt.Errorf("%w: a head of %d bytes", ErrEvsHeadRule, len(headBytes))
	}
	key := HeadKey(repoId, refId)
	barrierKey := barrierRefKey(repoId, refId)
	var etag string
	testHookBarrier(BarrierHeadCasBefore, barrierKey)
	if prior.Absent() {
		etag, err = cluster.PutIfNoneMatch(ctx, key, headBytes, nil)
	} else {
		etag, err = cluster.PutIfMatch(ctx, key, prior.Etag, headBytes, nil)
	}
	testHookBarrier(BarrierHeadCasAfter, barrierKey)
	if err != nil {
		return nil, err
	}
	return &EvsStoredHead{Head: written, Bytes: headBytes, Etag: etag}, nil
}

// The head's rules between two writes: the version rises, or stays with the fence raised; the fence, pins,
// index_epoch and consumed_through never fall, and an equal pin keeps its chain or commitment.
func checkEvsHeadRises(prior *protocol.EvsHead, next *protocol.EvsHead) error {
	if prior == nil {
		return nil
	}
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrEvsHeadRule, fmt.Sprintf(format, args...))
	}
	switch {
	case next.GetVersion() < prior.GetVersion():
		return refuse("version %d below %d", next.GetVersion(), prior.GetVersion())
	case next.GetFence() < prior.GetFence():
		return refuse("fence %d below %d", next.GetFence(), prior.GetFence())
	case next.GetVersion() == prior.GetVersion() && next.GetFence() == prior.GetFence():
		// an ETag would repeat (D-EVS-13)
		return refuse("a write at version %d that raises neither the version nor the fence", next.GetVersion())
	}
	if err := checkAuthPinRises(prior.GetAuth(), next.GetAuth()); err != nil {
		return err
	}
	switch {
	case next.GetGeneration() < prior.GetGeneration():
		return refuse("generation %d below %d", next.GetGeneration(), prior.GetGeneration())
	case next.GetGeneration() == prior.GetGeneration() && 0 < prior.GetGeneration() &&
		(!bytes.Equal(next.GetGroupId(), prior.GetGroupId()) || !bytes.Equal(next.GetGenerationCommitment(), prior.GetGenerationCommitment())):
		return refuse("generation %d with another group or commitment", next.GetGeneration())
	case next.GetIndexEpoch() < prior.GetIndexEpoch():
		return refuse("index epoch %d below %d", next.GetIndexEpoch(), prior.GetIndexEpoch())
	case next.GetConsumedThrough() < prior.GetConsumedThrough():
		return refuse("consumed_through %d below %d", next.GetConsumedThrough(), prior.GetConsumedThrough())
	case next.GetPathEpoch().GetCurrent() < prior.GetPathEpoch().GetCurrent():
		return refuse("path epoch %d below %d", next.GetPathEpoch().GetCurrent(), prior.GetPathEpoch().GetCurrent())
	case next.GetFoldedThrough() < prior.GetFoldedThrough():
		return refuse("folded_through %d below %d", next.GetFoldedThrough(), prior.GetFoldedThrough())
	}
	return nil
}

// The authorization pin (n, A_n) never falls, and an equal n keeps its chain (§11.8's gate row).
func checkAuthPinRises(prior *bridge.AuthPin, next *bridge.AuthPin) error {
	if prior == nil {
		return nil
	}
	switch {
	case next.GetVersion() < prior.GetVersion():
		return fmt.Errorf("%w: auth pin %d below %d", ErrEvsHeadRule, next.GetVersion(), prior.GetVersion())
	case next.GetVersion() == prior.GetVersion() && !bytes.Equal(next.GetChain(), prior.GetChain()):
		return fmt.Errorf("%w: auth pin %d with another chain", ErrEvsHeadRule, next.GetVersion())
	}
	return nil
}

// The refusal records whose until_s nowMs has not passed (§11.8's refusal row). Records that do not decode are an
// invalid head, never dropped quietly.
func dropLapsedRefusals(refused []byte, nowMs int64) ([]byte, error) {
	if len(refused) == 0 {
		return refused, nil
	}
	refusals, err := sidecar.DecodeEvsRefusals(refused)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsHeadInvalid, err)
	}
	live := make([]*sidecar.EvsRefusal, 0, len(refusals))
	for _, refusal := range refusals {
		if !refusal.LapsedAt(nowMs) {
			live = append(live, refusal)
		}
	}
	if len(live) == len(refusals) {
		return refused, nil
	}
	return sidecar.EncodeEvsRefusals(live)
}

// Writes the head a commit left into {evsh_<repo_id>}, after step 8 raised the push sequence (§11.9's cache row):
// only if its version rises above the cached one. A Redis failure is logged and ignored, since a missing entry
// costs only a cluster read.
func (self *HeadStore) CacheCommit(ctx context.Context, repoId sidecar.Id, refId sidecar.Id, committed *EvsStoredHead, pushSequence uint64) {
	self.cache.Write(ctx, repoId, refId, committed, pushSequence)
}

// The fence evacuation and GC raise on a ref (§11.8's fence row, §11.13): one head CAS that raises the fence and sets
// fence_ms to this process's clock, changing no version, so every attempt of a push that arrived before it and may
// still issue step 7 ends 503 unknown. It reads the head from the cluster and writes If-Match its ETag; a 412 rereads
// and tries again, at most FenceRetryCount times; an unknown outcome rereads and finds whether it landed, the settle
// rule ordering that read after it. While this process's clock is unsure it raises nothing (ErrEvsClockUnsure), and a
// ref with no head has nothing to fence (ErrEvsHeadAbsent). The caller's ctx carries its P2 class.
func (self *HeadStore) RaiseFence(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id) (*EvsStoredHead, error) {
	if !self.clockSure() {
		return nil, ErrEvsClockUnsure
	}
	prior, err := self.ReadCluster(ctx, cluster, repoId, refId)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt <= self.settings.FenceRetryCount; attempt += 1 {
		if prior.Absent() {
			return nil, ErrEvsHeadAbsent
		}
		// a turn of the clock between attempts reads as unsure, and stops the fence
		if !self.clockSure() {
			return nil, ErrEvsClockUnsure
		}
		next := CloneEvsHead(prior.Head)
		next.Fence = prior.Head.GetFence() + 1
		fenceMs := self.clock.Now().UnixMilli()
		next.FenceMs = fenceMs
		written, err := self.Commit(ctx, cluster, repoId, refId, prior, next)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			return written, nil
		case errors.Is(err, sidecar.ErrBlobPrecondition):
		case errors.As(err, &unknown):
			reread, readErr := self.ReadCluster(ctx, cluster, repoId, refId)
			if readErr != nil {
				return nil, err
			}
			if !reread.Absent() && reread.Head.GetVersion() == next.GetVersion() &&
				reread.Head.GetFence() == next.GetFence() && reread.Head.GetFenceMs() == fenceMs {
				return reread, nil
			}
			prior = reread
			continue
		default:
			return nil, err
		}
		prior, err = self.ReadCluster(ctx, cluster, repoId, refId)
		if err != nil {
			return nil, err
		}
	}
	return nil, ErrEvsHeadBusy
}
