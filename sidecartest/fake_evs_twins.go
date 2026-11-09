// The Go twins of evsservice's Redis scripts, which FakeRedis runs in their place (fake_redis_script.go). This file
// names each script by its literal Name, since sidecartest may not import evsservice, whose tests import this
// package: a name that drifts fails the engine's tests with ErrRedisNoTwin, never silently.
//
// A twin is only as true as its author made it, so T3 runs the real Source through the same scenarios (Q-TEST-1).

package sidecartest

import (
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
)

// evsservice.HeadCachePutScript's Name.
const evsHeadCachePutScriptName = "evs_head_cache_put"

// The budget and hdd loops' lease scripts' Names (evsservice/budget_loop.go).
const (
	evsBudgetLeaseTakeScriptName    = "evs_budget_lease_take"
	evsBudgetLeaseReleaseScriptName = "evs_budget_lease_release"
)

// Registers every evs twin on redis. Call it once per fake.
func RegisterEvsTwins(redis *FakeRedis) {
	redis.RegisterScript(evsHeadCachePutScriptName, evsHeadCachePutTwin)
	redis.RegisterScript(evsBudgetLeaseTakeScriptName, evsBudgetLeaseTakeTwin)
	redis.RegisterScript(evsBudgetLeaseReleaseScriptName, evsBudgetLeaseReleaseTwin)
}

// A lease field taken or renewed: set to the holder while absent or already the holder's, with its own ttl.
// KEYS[1] the cluster's {nvb_} key; ARGV the field, the holder, the ttl in ms. 1 when held.
func evsBudgetLeaseTakeTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	field, holder, ttlText := call.Args[0], call.Args[1], call.Args[2]
	current, found, err := call.HashGet(key, field)
	if err != nil {
		return nil, err
	}
	if found && string(current) != holder {
		return RedisIntegerReply(0), nil
	}
	if err := call.HashSet(key, map[string][]byte{field: []byte(holder)}); err != nil {
		return nil, err
	}
	ttlMs, err := strconv.ParseInt(ttlText, 10, 64)
	if err != nil {
		return nil, err
	}
	if err := call.HashExpire(key, []string{field}, time.Duration(ttlMs)*time.Millisecond); err != nil {
		return nil, err
	}
	return RedisIntegerReply(1), nil
}

// A lease field released only while the holder holds it. KEYS[1] the key; ARGV the field, the holder.
func evsBudgetLeaseReleaseTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	field, holder := call.Args[0], call.Args[1]
	current, found, err := call.HashGet(key, field)
	if err != nil {
		return nil, err
	}
	if !found || string(current) != holder {
		return RedisIntegerReply(0), nil
	}
	if err := call.HashDelete(key, []string{field}); err != nil {
		return nil, err
	}
	return RedisIntegerReply(1), nil
}

// Whether canonical decimal a is above b, compared by length then by bytes, as the Lua compares them.
func evsDecimalAbove(a string, b string) bool {
	if len(a) != len(b) {
		return len(b) < len(a)
	}
	return b < a
}

// {evsh_<repo_id>}'s write: the ref's entry and version field set only if the version rises, the key's ttl
// extended. KEYS[1] the key; ARGV the ref, the version, the entry, the ttl in ms.
func evsHeadCachePutTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	ref, version, entry, ttlText := call.Args[0], call.Args[1], call.Args[2], call.Args[3]
	current, found, err := call.HashGet(key, "v:"+ref)
	if err != nil {
		return nil, err
	}
	if found && !evsDecimalAbove(version, string(current)) {
		return &sidecar.RedisReply{Kind: sidecar.RedisReplyInteger, Integer: 0}, nil
	}
	if err := call.HashSet(key, map[string][]byte{"v:" + ref: []byte(version), ref: []byte(entry)}); err != nil {
		return nil, err
	}
	ttlMs, err := strconv.ParseInt(ttlText, 10, 64)
	if err != nil {
		return nil, err
	}
	if _, err := call.Expire(key, time.Duration(ttlMs)*time.Millisecond); err != nil {
		return nil, err
	}
	return &sidecar.RedisReply{Kind: sidecar.RedisReplyInteger, Integer: 1}, nil
}
