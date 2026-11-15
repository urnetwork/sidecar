//go:build !sidecar_http && !ios_extension

// ServiceHost.Redis: the Redis Cluster behind engines, with go-redis kept in server (§4.5). The
// interface and its value types are operator-core's (owner decision 251); the key-tag rule's helpers
// stay here. It holds soft state only. Every key is rebuildable (D-OPS-7), from Postgres or a
// cluster, by re-registration, or by restarting above its old values, so a lost key costs a resync,
// never correctness, and evs and gkm keep nothing durable here (owner decision 136).
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
	"strings"

	operator "github.com/urnetwork/operator-core"
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

// A Lua script, a package-level value run by its SHA-1.
type RedisScript = operator.RedisScript

// What a RedisReply holds. The zero value is a nil reply.
type RedisReplyKind = operator.RedisReplyKind

const (
	// A Lua nil or false, or a command's nil.
	RedisReplyNil = operator.RedisReplyNil
	// Exact as an int64.
	RedisReplyInteger = operator.RedisReplyInteger
	// A string, binary safe, and what a version must come back as.
	RedisReplyBulk  = operator.RedisReplyBulk
	RedisReplyArray = operator.RedisReplyArray
)

// What a script returned.
type RedisReply = operator.RedisReply

// A stream entry, as XRANGE and XREADGROUP give it.
type RedisStreamEntry = operator.RedisStreamEntry

// One keyspace event from the process's shared subscriber.
type RedisKeyEvent = operator.RedisKeyEvent

// Runs on the shared subscriber's goroutine, so it never blocks or does I/O.
type RedisKeyEventFunction = operator.RedisKeyEventFunction

// See the rules above.
type Redis = operator.Redis
