// The Go twins of evsservice's Redis scripts, which FakeRedis runs in their place (fake_redis_script.go). This file
// names each script by its literal Name, since sidecartest may not import evsservice, whose tests import this
// package: a name that drifts fails the engine's tests with ErrRedisNoTwin, never silently.
//
// A twin is only as true as its author made it, so T3 runs the real Source through the same scenarios (Q-TEST-1).

package sidecartest

import (
	"fmt"
	"strconv"
	"strings"
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

// The nightly count's scripts' Names (evsservice/nightly_sums.go).
const (
	evsNightlySumsWriteScriptName   = "evs_nightly_sums_write"
	evsNightlySumsMissingScriptName = "evs_nightly_sums_missing"
)

// Registers every evs twin on redis. Call it once per fake.
func RegisterEvsTwins(redis *FakeRedis) {
	redis.RegisterScript(evsHeadCachePutScriptName, evsHeadCachePutTwin)
	redis.RegisterScript(evsBudgetLeaseTakeScriptName, evsBudgetLeaseTakeTwin)
	redis.RegisterScript(evsBudgetLeaseReleaseScriptName, evsBudgetLeaseReleaseTwin)
	redis.RegisterScript(evsPushSequenceRaiseScriptName, evsPushSequenceRaiseTwin)
	redis.RegisterScript(evsLeasePutScriptName, evsLeasePutTwin)
	redis.RegisterScript(evsLeaseDeleteScriptName, evsLeaseDeleteTwin)
	redis.RegisterScript(evsLeaseSweepScriptName, evsLeaseSweepTwin)
	redis.RegisterScript(evsClientRepoPutScriptName, evsClientRepoPutTwin)
	redis.RegisterScript(evsClientRepoRemoveScriptName, evsClientRepoRemoveTwin)
	redis.RegisterScript(evsNightlySumsWriteScriptName, evsNightlySumsWriteTwin)
	redis.RegisterScript(evsNightlySumsMissingScriptName, evsNightlySumsMissingTwin)
}

// One field of a night written whole, and the night's key given its ttl while it has none (PEXPIRE NX). KEYS[1]
// {evsn_<night>}; ARGV the field, its value, the ttl in ms. 1.
func evsNightlySumsWriteTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	field, value, ttlText := call.Args[0], call.Args[1], call.Args[2]
	if err := call.HashSet(key, map[string][]byte{field: []byte(value)}); err != nil {
		return nil, err
	}
	ttlMs, err := strconv.ParseInt(ttlText, 10, 64)
	if err != nil {
		return nil, err
	}
	if _, err := call.ExpireIfNone(key, time.Duration(ttlMs)*time.Millisecond); err != nil {
		return nil, err
	}
	return RedisIntegerReply(1), nil
}

// The fields of ARGV the night's key lacks, in ARGV's order, as HEXISTS finds them. KEYS[1] {evsn_<night>}.
func evsNightlySumsMissingTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	missing := []*sidecar.RedisReply{}
	for _, field := range call.Args {
		_, found, err := call.HashGet(key, field)
		if err != nil {
			return nil, err
		}
		if !found {
			missing = append(missing, RedisBulkReply([]byte(field)))
		}
	}
	return RedisArrayReply(missing...), nil
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

// evsservice's push sequence and lease scripts' Names (sequence.go, subscribe.go).
const (
	evsPushSequenceRaiseScriptName = "evs_push_sequence_raise"
	evsLeasePutScriptName          = "evs_lease_put"
	evsLeaseDeleteScriptName       = "evs_lease_delete"
	evsLeaseSweepScriptName        = "evs_lease_sweep"
	evsClientRepoPutScriptName     = "evs_client_repo_put"
	evsClientRepoRemoveScriptName  = "evs_client_repo_remove"
)

// {evsq_<repo_id>}'s raise: SET to the master's TIME in µs x 1,000 as joined strings when absent, then INCR,
// PEXPIRE, and GET's bulk string. KEYS[1] the key; ARGV[1] the ttl in ms.
func evsPushSequenceRaiseTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	exists, err := call.Exists(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		now := call.Now()
		seed := strconv.FormatInt(now.Unix(), 10) + fmt.Sprintf("%06d", now.Nanosecond()/1000) + "000"
		if err := call.Set(key, []byte(seed), 0); err != nil {
			return nil, err
		}
	}
	value, _, err := call.Get(key)
	if err != nil {
		return nil, err
	}
	// INCR in Redis's own 64-bit integers, as the real command does: never through a double
	current, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return nil, err
	}
	raised := []byte(strconv.FormatInt(current+1, 10))
	if err := call.Set(key, raised, 0); err != nil {
		return nil, err
	}
	ttlMs, err := strconv.ParseInt(call.Args[0], 10, 64)
	if err != nil {
		return nil, err
	}
	if _, err := call.Expire(key, time.Duration(ttlMs)*time.Millisecond); err != nil {
		return nil, err
	}
	return &sidecar.RedisReply{Kind: sidecar.RedisReplyBulk, Bulk: raised}, nil
}

// {evsl_<repo_id>}'s write: refuses a new holder at the cap, else sets each field, extends both keys and raises the
// version. KEYS[1] the leases, KEYS[2] the version; ARGV now ms, holder, cap, ttl ms, then field and expiry pairs.
func evsLeasePutTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	leaseKey, versionKey := call.Keys[0], call.Keys[1]
	now, err := strconv.ParseInt(call.Args[0], 10, 64)
	if err != nil {
		return nil, err
	}
	holder := call.Args[1]
	limit, err := strconv.ParseInt(call.Args[2], 10, 64)
	if err != nil {
		return nil, err
	}
	ttlMs, err := strconv.ParseInt(call.Args[3], 10, 64)
	if err != nil {
		return nil, err
	}
	fields, err := call.HashGetAll(leaseKey)
	if err != nil {
		return nil, err
	}
	holders := map[string]bool{}
	for field, value := range fields {
		fieldHolder, _, found := strings.Cut(field, "|")
		expiry, err := strconv.ParseInt(string(value), 10, 64)
		if !found || err != nil || expiry <= now {
			continue
		}
		holders[fieldHolder] = true
	}
	if !holders[holder] && limit <= int64(len(holders)) {
		return RedisIntegerReply(0), nil
	}
	set := map[string][]byte{}
	for i := 4; i+1 < len(call.Args); i += 2 {
		set[call.Args[i]] = []byte(call.Args[i+1])
	}
	if err := call.HashSet(leaseKey, set); err != nil {
		return nil, err
	}
	if _, err := call.Expire(leaseKey, time.Duration(ttlMs)*time.Millisecond); err != nil {
		return nil, err
	}
	if _, err := call.Increment(versionKey, 0); err != nil {
		return nil, err
	}
	if _, err := call.Expire(versionKey, time.Duration(ttlMs)*time.Millisecond); err != nil {
		return nil, err
	}
	return RedisIntegerReply(1), nil
}

// {evsl_<repo_id>}'s removal: exact fields, or every field under a prefix; the version raised when any went.
func evsLeaseDeleteTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	leaseKey, versionKey := call.Keys[0], call.Keys[1]
	fields, err := call.HashGetAll(leaseKey)
	if err != nil {
		return nil, err
	}
	remove := []string{}
	for _, name := range call.Args[1:] {
		if call.Args[0] == "prefix" {
			for field := range fields {
				if strings.HasPrefix(field, name) {
					remove = append(remove, field)
				}
			}
			continue
		}
		if _, ok := fields[name]; ok {
			remove = append(remove, name)
		}
	}
	if 0 < len(remove) {
		if err := call.HashDelete(leaseKey, remove); err != nil {
			return nil, err
		}
		if _, err := call.Increment(versionKey, 0); err != nil {
			return nil, err
		}
	}
	return RedisIntegerReply(int64(len(remove))), nil
}

// {evsl_<repo_id>}'s sweep: every field whose expiry has passed, the version raised when any went.
func evsLeaseSweepTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	leaseKey, versionKey := call.Keys[0], call.Keys[1]
	now, err := strconv.ParseInt(call.Args[0], 10, 64)
	if err != nil {
		return nil, err
	}
	fields, err := call.HashGetAll(leaseKey)
	if err != nil {
		return nil, err
	}
	remove := []string{}
	for field, value := range fields {
		if expiry, err := strconv.ParseInt(string(value), 10, 64); err == nil && expiry <= now {
			remove = append(remove, field)
		}
	}
	if 0 < len(remove) {
		if err := call.HashDelete(leaseKey, remove); err != nil {
			return nil, err
		}
		if _, err := call.Increment(versionKey, 0); err != nil {
			return nil, err
		}
	}
	return RedisIntegerReply(int64(len(remove))), nil
}

// {evsc_<client_id>}'s count: drops the members whose score has lapsed, refuses a new repo at the cap, else scores
// the repo now and extends the key. KEYS[1] the client's repos; ARGV now ms, the repo, the cap, the newest lapsed
// score in ms, the ttl in ms. 0 refused, 1 added, 2 renewed. FakeRedis has no sorted set, so the twin keeps the set
// as a hash of member to score, which no caller reads but these twins; the real Source's ZADD, ZCARD and
// ZREMRANGEBYSCORE run on the private Redis in server's evshost tests.
func evsClientRepoPutTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	if _, err := strconv.ParseInt(call.Args[0], 10, 64); err != nil {
		return nil, err
	}
	repo := call.Args[1]
	limit, err := strconv.ParseInt(call.Args[2], 10, 64)
	if err != nil {
		return nil, err
	}
	lapsed, err := strconv.ParseInt(call.Args[3], 10, 64)
	if err != nil {
		return nil, err
	}
	ttlMs, err := strconv.ParseInt(call.Args[4], 10, 64)
	if err != nil {
		return nil, err
	}
	members, err := call.HashGetAll(key)
	if err != nil {
		return nil, err
	}
	remove := []string{}
	for member, value := range members {
		if score, err := strconv.ParseInt(string(value), 10, 64); err != nil || score <= lapsed {
			remove = append(remove, member)
			delete(members, member)
		}
	}
	if 0 < len(remove) {
		if err := call.HashDelete(key, remove); err != nil {
			return nil, err
		}
	}
	_, held := members[repo]
	if !held && limit <= int64(len(members)) {
		return RedisIntegerReply(0), nil
	}
	if err := call.HashSet(key, map[string][]byte{repo: []byte(call.Args[0])}); err != nil {
		return nil, err
	}
	if _, err := call.Expire(key, time.Duration(ttlMs)*time.Millisecond); err != nil {
		return nil, err
	}
	if held {
		return RedisIntegerReply(2), nil
	}
	return RedisIntegerReply(1), nil
}

// {evsc_<client_id>}'s removal of one repo: how many went. KEYS[1] the client's repos; ARGV the repo.
func evsClientRepoRemoveTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	key := call.Keys[0]
	if _, held, err := call.HashGet(key, call.Args[0]); err != nil {
		return nil, err
	} else if !held {
		return RedisIntegerReply(0), nil
	}
	if err := call.HashDelete(key, []string{call.Args[0]}); err != nil {
		return nil, err
	}
	return RedisIntegerReply(1), nil
}
