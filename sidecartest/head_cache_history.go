// A record of evs's head cache, {evsh_<repo_id>} (§11.9's cache row), as the engines that ran it saw it, kept beside
// the blob history (BlobRecorder): what FI-27's cached-head clause reads (QD-1146), since §11.8's step 4 may take a
// reuse source's head from the cache, which no blob request shows. HeadCacheRecorder wraps the Redis an engine runs
// on, a fake or a real one, and keeps the cache's own requests alone:
//
//	get   each HGET of a ref's field of a {evsh_} key, with the entry it answered
//	put   each run of the cache's put script, with the entry it carried and what the script replied
//
// Every other call passes through untouched. It knows the cache's requests by their literal names, the family's hash
// tag and the script's Name, as fake_evs_twins.go does, since sidecartest may not import evsservice: a name that
// drifts leaves the record empty, which an oracle reading it takes as no cached read at all, so it fails closed.
//
// Each request is kept with how many requests the blob history held at its call and at its answer, the order it
// shares with the blob history and with an attempt's StoreArrival, and at its own index, which an attempt's
// CacheArrival counts. An oracle's look under InspectContext is no request a client made and is not kept. As in
// BlobRecorder, a request's entry changes in two steps, each under the lock: begin publishes it holding everything
// its call does, and end writes its whole answer, so History copies each request as called or as answered.
//
// Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// evsservice/head_cache.go's family prefix: a repo's key is {evsh_<repo_id>}.
const evsHeadCacheKeyPrefix = "{evsh_"

// evsservice/head_cache.go's version field prefix: v:<ref> holds a ref's cached version, which the cache's reads
// never ask for.
const evsHeadCacheVersionFieldPrefix = "v:"

type HeadCacheHistoryOp string

const (
	HeadCacheHistoryGet HeadCacheHistoryOp = "get"
	HeadCacheHistoryPut HeadCacheHistoryOp = "put"
)

type HeadCacheOutcome string

const (
	// A get that answered an entry, or a put the script wrote.
	HeadCacheOutcomeOk HeadCacheOutcome = "ok"
	// A get of a field the key did not hold.
	HeadCacheOutcomeAbsent HeadCacheOutcome = "absent"
	// A put the script did not write, the cached version being as new or newer.
	HeadCacheOutcomeKept HeadCacheOutcome = "kept"
	// A get with no answer.
	HeadCacheOutcomeFailed HeadCacheOutcome = "failed"
	// A put with no answer, or one the script answered with no reply it gives, which may have written.
	HeadCacheOutcomeUnknown HeadCacheOutcome = "unknown"
)

// One request of the head cache as its engine saw it. An empty Outcome has no answer yet.
type HeadCacheHistoryEntry struct {
	Actor string
	Op    HeadCacheHistoryOp
	// The repo's key, {evsh_<repo_id>}.
	Key string
	// The ref's field: its id as sidecar.EvsKeyId spells it.
	Field string
	// A put's entry as it carried it, and a get's as it answered it, in evsservice/head_cache.go's layout: version,
	// push sequence and cached_ms as 8 bytes each, the ETag's length as 2, all big-endian, the ETag, and the head's
	// bytes. Nil for a get that answered none.
	Entry   []byte
	Outcome HeadCacheOutcome
	// On the recorder's clock, the Net's. Returned is zero while it has no answer.
	Invoked  time.Time
	Returned time.Time
	// How many requests the blob history held at its call and at its answer: a blob request at an index at or past
	// StoreInvoked was called after this one was, and one at or past StoreReturned after its answer. StoreReturned is
	// 0 while it has no answer.
	StoreInvoked  int
	StoreReturned int
}

// Wraps the Redis engines run their head cache on, so each of the cache's requests is kept. storeCount is how many
// requests the blob history holds now (Net.BlobHistoryCount).
type HeadCacheRecorder struct {
	clock      Clock
	storeCount func() int

	stateLock sync.Mutex
	entries   []*HeadCacheHistoryEntry
}

func NewHeadCacheRecorder(clock Clock, storeCount func() int) *HeadCacheRecorder {
	return &HeadCacheRecorder{clock: clock, storeCount: storeCount}
}

// redis with the head cache's requests through it kept here. nil stays nil, and a Redis this recorder already wraps
// is returned as it is, so a host handed back to AddEngines is not recorded twice.
func (self *HeadCacheRecorder) Wrap(redis sidecar.Redis) sidecar.Redis {
	if redis == nil {
		return nil
	}
	if recorded, ok := redis.(*headCacheRecordedRedis); ok && recorded.recorder == self {
		return redis
	}
	return &headCacheRecordedRedis{Redis: redis, recorder: self}
}

// Every request so far, in call order, each a copy with its own entry bytes: a request still in flight changes nothing
// here, and a caller's change to its copy reaches no one else.
func (self *HeadCacheRecorder) History() []*HeadCacheHistoryEntry {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := make([]*HeadCacheHistoryEntry, 0, len(self.entries))
	for _, entry := range self.entries {
		entryCopy := *entry
		entryCopy.Entry = bytes.Clone(entry.Entry)
		entries = append(entries, &entryCopy)
	}
	return entries
}

// How many requests History holds now: a request at this index or later was called after this call.
func (self *HeadCacheRecorder) Count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.entries)
}

// Publishes entry, which holds everything its call does.
func (self *HeadCacheRecorder) begin(ctx context.Context, entry *HeadCacheHistoryEntry) {
	entry.Actor = ActorName(ctx)
	entry.Invoked = self.clock.Now()
	entry.StoreInvoked = self.storeCount()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.entries = append(self.entries, entry)
}

// Writes the answer into entry in one step: the outcome, and a get's entry, nil for none.
func (self *HeadCacheRecorder) end(entry *HeadCacheHistoryEntry, outcome HeadCacheOutcome, answered []byte) {
	returned := self.clock.Now()
	storeReturned := self.storeCount()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry.Outcome = outcome
	entry.Returned = returned
	entry.StoreReturned = storeReturned
	if entry.Op == HeadCacheHistoryGet {
		entry.Entry = answered
	}
}

type headCacheRecordedRedis struct {
	sidecar.Redis
	recorder *HeadCacheRecorder
}

// An HGET of a ref's entry in a {evsh_} key is the cache's read (HeadCache.Read); every other passes through.
func (self *headCacheRecordedRedis) HashGet(ctx context.Context, key string, field string) ([]byte, bool, error) {
	if isInspecting(ctx) || !strings.HasPrefix(key, evsHeadCacheKeyPrefix) || strings.HasPrefix(field, evsHeadCacheVersionFieldPrefix) {
		return self.Redis.HashGet(ctx, key, field)
	}
	entry := &HeadCacheHistoryEntry{Op: HeadCacheHistoryGet, Key: key, Field: field}
	self.recorder.begin(ctx, entry)
	value, found, err := self.Redis.HashGet(ctx, key, field)
	switch {
	case err != nil:
		self.recorder.end(entry, HeadCacheOutcomeFailed, nil)
	case !found:
		self.recorder.end(entry, HeadCacheOutcomeAbsent, nil)
	default:
		self.recorder.end(entry, HeadCacheOutcomeOk, bytes.Clone(value))
	}
	return value, found, err
}

// A run of the cache's put script (HeadCache.Write), KEYS the repo's key and ARGV the ref's field, its version, the
// entry and the ttl, is the cache's write; every other script passes through.
func (self *headCacheRecordedRedis) RunScript(ctx context.Context, script *sidecar.RedisScript, keys []string, args []string) (*sidecar.RedisReply, error) {
	if isInspecting(ctx) || script == nil || script.Name != evsHeadCachePutScriptName || len(keys) != 1 || len(args) < 3 {
		return self.Redis.RunScript(ctx, script, keys, args)
	}
	entry := &HeadCacheHistoryEntry{Op: HeadCacheHistoryPut, Key: keys[0], Field: args[0], Entry: []byte(args[2])}
	self.recorder.begin(ctx, entry)
	reply, err := self.Redis.RunScript(ctx, script, keys, args)
	switch {
	case err != nil || reply == nil || reply.Kind != sidecar.RedisReplyInteger:
		self.recorder.end(entry, HeadCacheOutcomeUnknown, nil)
	case reply.Integer == 1:
		self.recorder.end(entry, HeadCacheOutcomeOk, nil)
	case reply.Integer == 0:
		self.recorder.end(entry, HeadCacheOutcomeKept, nil)
	default:
		self.recorder.end(entry, HeadCacheOutcomeUnknown, nil)
	}
	return reply, err
}
