// {evsh_<repo_id>} (§11.9's cache row, evs-24): a verified copy of each ref's head beside the time evs cached it and
// the push sequence its commit raised, which GET .../refs?moved_after= reads (§11.9's moved row). Soft state that a
// cluster read rebuilds, outside the rdb bundles (owner decision 136, D-OPS-16).
//
//   - written after each commit, after step 8 raised the push sequence, and only if its version rises above the
//     cached one, by one script on the repo's one hash tag, so a late writer never lowers it;
//   - served within HeadCacheServeAge (10 min) of its own cache time, so a ref another ref's writes kept in the
//     hash is still not served past its own 10 min (FS-62); the key's ttl, which any ref's write extends, only
//     bounds memory;
//   - served only at or above the version asked (a reader's pin, a hinted version, a push's base), and never to a
//     fresh read; a stale ETag costs a push one cluster read and one more PUT (§11.8's cache row).
//
// Fields, per ref: <ref> holds the entry (version u64 | push_sequence u64 | cached_ms i64 | etag length u16 | etag |
// the head's bytes, integers big-endian), and v:<ref> its version in canonical decimal, which the script compares
// by length then by bytes, so no version passes through Lua's doubles (host_redis.go). Ref ids are
// sidecar.EvsKeyId's hex.
//
// Every failure fails open to the cluster: a lost, stale or unreadable entry costs a read, never an answer. Safe for
// concurrent use.

package evsservice

import (
	"bytes"
	"context"
	"encoding/binary"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
)

// The family's hash tag prefix.
const headCacheKeyPrefix = "{evsh_"

// A cached head's version field: v:<ref>.
const headCacheVersionFieldPrefix = "v:"

// The fixed part of an entry: version, push sequence, cache time and the ETag's length.
const headCacheEntryHeaderByteCount = 8 + 8 + 8 + 2

// The repo's one key: {evsh_<repo_id>}.
func HeadCacheKey(repoId sidecar.Id) string {
	return headCacheKeyPrefix + sidecar.EvsKeyId(repoId) + "}"
}

// Writes a ref's entry only if its version rises above the cached one, and extends the key's ttl. KEYS[1] the
// repo's key; ARGV the ref's field, the version in canonical decimal, the entry, the ttl in ms. Replies 1 when it
// wrote, 0 when the cached version was as new or newer.
var HeadCachePutScript = &sidecar.RedisScript{
	Name: "evs_head_cache_put",
	Source: `
local current = redis.call('HGET', KEYS[1], 'v:' .. ARGV[1])
if current then
  if string.len(current) > string.len(ARGV[2]) or (string.len(current) == string.len(ARGV[2]) and current >= ARGV[2]) then
    return 0
  end
end
redis.call('HSET', KEYS[1], 'v:' .. ARGV[1], ARGV[2], ARGV[1], ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return 1
`,
}

// One ref's entry as the hash holds it.
type headCacheEntry struct {
	version      uint64
	pushSequence uint64
	cachedMs     int64
	etag         string
	headBytes    []byte
}

// The entry's bytes.
func (self *headCacheEntry) encode() []byte {
	encoded := make([]byte, 0, headCacheEntryHeaderByteCount+len(self.etag)+len(self.headBytes))
	encoded = binary.BigEndian.AppendUint64(encoded, self.version)
	encoded = binary.BigEndian.AppendUint64(encoded, self.pushSequence)
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(self.cachedMs))
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(self.etag)))
	encoded = append(encoded, self.etag...)
	return append(encoded, self.headBytes...)
}

// An entry from its bytes, false for bytes that are no entry.
func decodeHeadCacheEntry(encoded []byte) (*headCacheEntry, bool) {
	if len(encoded) < headCacheEntryHeaderByteCount {
		return nil, false
	}
	etagLength := int(binary.BigEndian.Uint16(encoded[24:26]))
	if len(encoded) < headCacheEntryHeaderByteCount+etagLength {
		return nil, false
	}
	return &headCacheEntry{
		version:      binary.BigEndian.Uint64(encoded[0:8]),
		pushSequence: binary.BigEndian.Uint64(encoded[8:16]),
		cachedMs:     int64(binary.BigEndian.Uint64(encoded[16:24])),
		etag:         string(encoded[26 : 26+etagLength]),
		headBytes:    encoded[26+etagLength:],
	}, true
}

// See the file header.
type HeadCache struct {
	clock    sidecar.Clock
	redis    sidecar.Redis
	settings *EvsSettings
	log      sidecar.Logger
}

// A cache over redis; nil redis serves nothing and writes nothing.
func NewHeadCache(clock sidecar.Clock, redis sidecar.Redis, settings *EvsSettings, log sidecar.Logger) *HeadCache {
	return &HeadCache{clock: clock, redis: redis, settings: settings, log: log}
}

// The ref's cached head when §11.9 allows serving it: within HeadCacheServeAge of its cache time and at least
// atLeastVersion. false otherwise, and for anything Redis did not answer or that does not parse.
func (self *HeadCache) Read(ctx context.Context, repoId sidecar.Id, refId sidecar.Id, atLeastVersion uint64) (*EvsStoredHead, bool) {
	if self.redis == nil || self.settings.HeadCacheServeAge <= 0 {
		return nil, false
	}
	encoded, found, err := self.redis.HashGet(ctx, HeadCacheKey(repoId), sidecar.EvsKeyId(refId))
	if err != nil || !found {
		return nil, false
	}
	entry, ok := decodeHeadCacheEntry(encoded)
	if !ok {
		return nil, false
	}
	cachedAt := time.UnixMilli(entry.cachedMs)
	if !self.clock.Now().Before(cachedAt.Add(self.settings.HeadCacheServeAge)) {
		return nil, false
	}
	if entry.version < atLeastVersion {
		return nil, false
	}
	head, err := ParseEvsHead(entry.headBytes)
	if err != nil || head.GetVersion() != entry.version {
		return nil, false
	}
	return &EvsStoredHead{
		Head:         head,
		Bytes:        bytes.Clone(entry.headBytes),
		Etag:         entry.etag,
		Cached:       true,
		CachedAt:     cachedAt,
		PushSequence: entry.pushSequence,
	}, true
}

// Writes the committed head as the ref's entry, cached now, if its version rises (the script decides). Failures
// are logged and dropped.
func (self *HeadCache) Write(ctx context.Context, repoId sidecar.Id, refId sidecar.Id, committed *EvsStoredHead, pushSequence uint64) {
	if self.redis == nil || committed.Absent() {
		return
	}
	entry := &headCacheEntry{
		version:      committed.Version(),
		pushSequence: pushSequence,
		cachedMs:     self.clock.Now().UnixMilli(),
		etag:         committed.Etag,
		headBytes:    committed.Bytes,
	}
	barrierKey := barrierRefKey(repoId, refId)
	testHookBarrier(BarrierHeadCacheWriteBefore, barrierKey)
	_, err := self.redis.RunScript(ctx, HeadCachePutScript, []string{HeadCacheKey(repoId)}, []string{
		sidecar.EvsKeyId(refId),
		strconv.FormatUint(entry.version, 10),
		string(entry.encode()),
		strconv.FormatInt(self.settings.HeadCacheTtl.Milliseconds(), 10),
	})
	testHookBarrier(BarrierHeadCacheWriteAfter, barrierKey)
	if err != nil {
		self.log.Warningf("[evs] head cache write for repo %s failed: %v", sidecar.EvsKeyId(repoId), err)
	}
}

// Every ref's cached push sequence, for GET .../refs?moved_after= (§11.9's moved row): ref id to the sequence its
// last cached commit raised. A field that does not parse is left out, which reads as a hash lacking that ref.
func (self *HeadCache) PushSequences(ctx context.Context, repoId sidecar.Id) (map[sidecar.Id]uint64, error) {
	refIdPushSequences := map[sidecar.Id]uint64{}
	if self.redis == nil {
		return refIdPushSequences, nil
	}
	fieldValues, err := self.redis.HashGetAll(ctx, HeadCacheKey(repoId))
	if err != nil {
		return nil, err
	}
	for field, encoded := range fieldValues {
		refId, err := parseEvsHexId(field)
		if err != nil {
			continue
		}
		if entry, ok := decodeHeadCacheEntry(encoded); ok {
			refIdPushSequences[refId] = entry.pushSequence
		}
	}
	return refIdPushSequences, nil
}
