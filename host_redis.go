//go:build !sidecar_http && !ios_extension

// ServiceHost.Redis: the Redis Cluster behind engines, with go-redis kept in server (§4.5). It holds
// soft state only. Every key is rebuildable (D-OPS-7), from Postgres or a cluster, by re-registration,
// or by restarting above its old values, so a lost key costs a resync, never correctness, and evs and
// gkm keep nothing durable here (owner decision 136).
//
// Rules every caller keeps:
//
//   - Keys of one call share one hash tag, since production's cluster answers CROSSSLOT otherwise and
//     a one-node Redis would not (§22.4's lint). RedisKeysShareTag states the rule. No script or MULTI
//     spans two slots (§18.7's WK1).
//   - What has no method here runs as a script: a family's sorted sets and hash arithmetic, and every
//     read-then-write that must be atomic. A hot path stays at one script a call, which §22.5 counts
//     with an op-counting Redis (a Find is one, §9.8).
//   - A large number never passes through Lua, which holds numbers as doubles, exact only below 2^53:
//     versions and sequences travel as canonical decimal strings, compared as §6.8 says, and come back
//     as bulk replies (§6.8, §11.10). A stream id compares as its two integer parts.
//   - Inline packet and frame paths never wait on this interface (I-12), and an unset or unavailable
//     projection refuses (connect/CODESTYLE.md:107).
//
// An absent key or field is an answer, reported by found, never an error. An error means Redis did not
// answer, so the caller does not know what a write did. Each section says what then fails open or
// closed.

package sidecar

import (
	"context"
	"strings"
	"time"
)

// What lies between key's first { and the next }, and whether it has that. An empty {} is no tag.
func redisKeyTag(key string) (string, bool) {
	if start := strings.IndexByte(key, '{'); 0 <= start {
		if length := strings.IndexByte(key[start+1:], '}'); 0 < length {
			return key[start+1 : start+1+length], true
		}
	}
	return "", false
}

// The part of a key Redis Cluster hashes: its tag, else the whole key. {scp_c}ver and {scp_c}n share
// "scp_c".
func RedisHashTag(key string) string {
	if tag, tagged := redisKeyTag(key); tagged {
		return tag
	}
	return key
}

// Whether one call may name these keys, by §22.4's rule: a call of two or more keys shares one hash
// tag, and each key carries it. A key with no tag fails, even one that hashes alike, as scp_c does
// beside {scp_c}n, since that is the luck of a shared slot and not the rule. One key needs no tag.
// What a fake checks to fail as production's cluster does.
func RedisKeysShareTag(keys []string) bool {
	if len(keys) < 2 {
		return true
	}
	firstTag, tagged := redisKeyTag(keys[0])
	if !tagged {
		return false
	}
	for _, key := range keys[1:] {
		if tag, tagged := redisKeyTag(key); !tagged || tag != firstTag {
			return false
		}
	}
	return true
}

// A Lua script. The host runs it by its SHA-1, falling back to the source when the node has not
// loaded it, so a script is a package-level value and never built per call.
type RedisScript struct {
	// Stable and unique: the label a Metrics count takes, and how T2's fake finds the Go twin that
	// stands in for this source.
	Name string
	// Reads every key from KEYS and never builds one, or the slot check proves nothing. Reads TIME
	// inside, as server/model/subscription_redis_admission.go:225 does, when it needs the master's
	// clock.
	Source string
}

// What a RedisReply holds. The zero value is a nil reply.
type RedisReplyKind int

const (
	// A Lua nil or false, or a command's nil.
	RedisReplyNil RedisReplyKind = iota
	// Exact as an int64. A Lua number past 2^53 has already lost its value, so never return one.
	RedisReplyInteger
	// A string, binary safe, and what a version must come back as. A status reply such as OK reads
	// the same.
	RedisReplyBulk
	RedisReplyArray
)

// What a script returned. A script's error_reply is the call's error, never a reply.
type RedisReply struct {
	Kind RedisReplyKind
	// RedisReplyInteger.
	Integer int64
	// RedisReplyBulk.
	Bulk []byte
	// RedisReplyArray, in order.
	Replies []*RedisReply
}

// A stream entry, as XRANGE and XREADGROUP give it.
type RedisStreamEntry struct {
	// <ms>-<seq>, compared as two integers (§6.8).
	Id          string
	FieldValues map[string][]byte
}

// One keyspace event from the process's shared subscriber.
type RedisKeyEvent struct {
	// The key that changed. Empty on Resync.
	Key string
	// The subscription was lost and re-established. Anything published in the gap is gone, so the
	// callback rereads what it watches (server/connect/key_event_subscriber.go:81).
	Resync bool
}

// Runs on the shared subscriber's goroutine, so it never blocks or does I/O: it notes the key and
// returns, and a worker of its own does the rest (connect/CODESTYLE.md:119).
type RedisKeyEventFunction func(event RedisKeyEvent)

// See the rules above. Each method says what a zero means, and none passes one through to Redis, whose
// zero is another operation: EXPIRE 0, EXPIRE NX 0 and HEXPIRE 0 delete what they name, SET PX 0 is an
// error, XADD MAXLEN ~ 0 trims the entry just added and XREADGROUP BLOCK 0 waits forever. A positive ttl
// rounds up to the millisecond Redis keeps, so it never reaches Redis as zero. A negative ttl or length,
// or a count that is not positive, is the caller's bug and an error: COUNT 0 means nothing on XRANGE, no
// limit on XREADGROUP and an error on XAUTOCLAIM, so it has no one meaning to keep.
type Redis interface {
	// A string key.
	Get(ctx context.Context, key string) (value []byte, found bool, err error)
	// MGET, in keys' order, a nil element for an absent key.
	GetMany(ctx context.Context, keys []string) (values [][]byte, err error)
	// A ttl of zero leaves the key with no expiry, clearing one it had.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// SET NX, the once-only write: a DPoP jti's, {dpop_<client_id>}<jti> (§7.4), and a poll's
	// {scp_<C>}hb (§6.16). A ttl of zero sets no expiry.
	SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (set bool, err error)
	// Replaces value only while the key holds expected: a lease renewal's cas. Absent never matches. A
	// ttl of zero leaves the key with no expiry, so a lease never renews with one.
	CompareAndSet(ctx context.Context, key string, expected []byte, value []byte, ttl time.Duration) (set bool, err error)
	// Deletes only while the key holds expected: a lease's release, which another holder's newer
	// lease survives.
	CompareAndDelete(ctx context.Context, key string, expected []byte) (deleted bool, err error)
	// INCR with an EXPIRE NX of ttl in one step, so the first increment sets the key's life and later
	// ones leave it. A ttl of zero sends no EXPIRE at all, since EXPIRE NX 0 would delete the counter
	// it just raised. This is what fires a trigger: an INCR emits a class $ keyspace event, where HSET
	// and XADD emit nothing (D-PROTO-12).
	Increment(ctx context.Context, key string, ttl time.Duration) (value int64, err error)
	// Absent keys are no error.
	Delete(ctx context.Context, keys []string) error
	// Sets the key's ttl, which must be positive here: zero is an error, since a zero EXPIRE would
	// delete the key. found is false when the key is absent.
	Expire(ctx context.Context, key string, ttl time.Duration) (found bool, err error)

	// One field of a hash.
	HashGet(ctx context.Context, key string, field string) (value []byte, found bool, err error)
	// An absent key is an empty map: {scp_<C>}ver for a reset (§6.8), {gka_<group_id>} for gkm's
	// retention (§10.6).
	HashGetAll(ctx context.Context, key string) (fieldValues map[string][]byte, err error)
	// Writes fieldValues into the hash, leaving its other fields and their ttls.
	HashSet(ctx context.Context, key string, fieldValues map[string][]byte) error
	// Absent fields are no error.
	HashDelete(ctx context.Context, key string, fields []string) error
	// HEXPIRE: a ttl per field, the leases of §9.8's groups and {svc_} pairs. A field that is absent
	// is no error. The ttl must be positive here, as Expire's: zero is an error, since HEXPIRE 0 would
	// delete the fields, and a host passing it through would lose the lease.
	HashExpire(ctx context.Context, key string, fields []string, ttl time.Duration) error

	// XADD with MAXLEN ~ maxLength, and returns the entry's id: {wakeq_<shard>} (§18.7). A maxLength of
	// zero sends no MAXLEN.
	StreamAdd(ctx context.Context, key string, maxLength int64, fieldValues map[string][]byte) (entryId string, err error)
	// XRANGE, entries after afterEntryId, from the start when it is empty, at most count: a
	// publisher's hint stream (§6.8).
	StreamRange(ctx context.Context, key string, afterEntryId string, count int64) (entries []*RedisStreamEntry, err error)
	// XGROUP CREATE MKSTREAM, for entries from now on. An existing group is no error.
	StreamGroupCreate(ctx context.Context, key string, group string) error
	// XREADGROUP of entries no consumer has been given, waiting up to block for one: §19.4's push
	// sender. Empty when block passes. A block of zero does not wait and sends no BLOCK.
	StreamGroupRead(ctx context.Context, key string, group string, consumer string, count int64, block time.Duration) (entries []*RedisStreamEntry, err error)
	// XACK.
	StreamGroupAck(ctx context.Context, key string, group string, entryIds []string) error
	// XAUTOCLAIM of entries idle at least minIdle, from cursor, empty at first: the next cursor comes
	// back, and "0-0" means the pending list is done (§19.4: 30 s).
	StreamGroupClaim(ctx context.Context, key string, group string, consumer string, minIdle time.Duration, cursor string, count int64) (entries []*RedisStreamEntry, nextCursor string, err error)

	// One script, atomic on its slot. keys name every key it touches and args are its ARGV.
	RunScript(ctx context.Context, script *RedisScript, keys []string, args []string) (*RedisReply, error)

	// Adds callback to the process's one shared key-event subscriber, for keys matching keyPattern,
	// such as {tes_*}n (§13.9) or {*}c_removed (§9.8): a family, with a * in it. That is the only way
	// to watch keyspace events, and it is never per client, the pattern that melted the cluster on
	// 2026-07-15 (server/model/peer_model.go:32-37), so a pattern without a * is an error. Every
	// process watches few families, and the callback tells one client's key from another's. Returns
	// the call that removes it.
	AddKeyEventCallback(keyPattern string, callback RedisKeyEventFunction) (remove func(), err error)
}
