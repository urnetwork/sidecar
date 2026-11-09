// The Go twins of pushservice's scripts for FakeRedis (fake_redis_script.go): each does what its Lua
// does, step for step, holding the fake's lock for the whole run. PushStoreSuite runs both the twin and
// the Lua through the same cases, so a twin that drifts fails there (D-TEST-2).

package sidecartest

import (
	"errors"
	"maps"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
)

// Registers every twin on redis, which then runs pushservice.HintScript, HintAckScript and
// HintTailScript, and the wake token scripts, WakeTokenTimeScript and WakeTokenApplyScript
// (push_token_twins.go).
func RegisterPushScripts(redis *FakeRedis) {
	redis.RegisterScript(pushservice.HintScript.Name, pushHintTwin)
	redis.RegisterScript(pushservice.HintAckScript.Name, pushHintAckTwin)
	redis.RegisterScript(pushservice.HintTailScript.Name, pushHintTailTwin)
	redis.RegisterScript(pushservice.WakeTokenTimeScript.Name, pushTokenTimeTwin)
	redis.RegisterScript(pushservice.WakeTokenApplyScript.Name, pushTokenApplyTwin)
}

// The fields of a hint entry in the order the hint script's XADD writes them, which a real stream keeps
// and XREVRANGE gives back.
var pushTwinEntryFields = []string{"seq", "topic", "version", "kind", "hint"}

// pushservice.HintTailScript: the entry as XREVRANGE gives it, its fields in XADD's order, any others
// after them by name.
func pushHintTailTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 1 || len(call.Args) != 0 {
		return nil, errPushTwinArguments
	}
	entry, found, err := call.StreamLast(call.Keys[0])
	if err != nil {
		return nil, err
	}
	if !found {
		return RedisNilReply(), nil
	}
	fields := make([]*sidecar.RedisReply, 0, 2*len(entry.FieldValues))
	for _, field := range pushTwinEntryFields {
		if value, ok := entry.FieldValues[field]; ok {
			fields = append(fields, RedisBulkReply([]byte(field)), RedisBulkReply(value))
		}
	}
	for _, field := range slices.Sorted(maps.Keys(entry.FieldValues)) {
		if !slices.Contains(pushTwinEntryFields, field) {
			fields = append(fields, RedisBulkReply([]byte(field)), RedisBulkReply(entry.FieldValues[field]))
		}
	}
	return RedisArrayReply(RedisBulkReply([]byte(entry.Id)), RedisArrayReply(fields...)), nil
}

var (
	errPushTwinArguments = errors.New("ERR wrong number of arguments")
	errPushTwinVersion   = errors.New("ERR push hint topic or version not canonical")
	errPushTwinStreamId  = errors.New("ERR push ack stream id malformed")
	// what HINCRBY answers on a field that is no int64, or would pass one
	errPushTwinNotInteger = errors.New("ERR hash value is not an integer")
	errPushTwinOverflow   = errors.New("ERR increment or decrement would overflow")
)

// A ttl in whole seconds, as the script's ARGV gives it.
func pushTwinSeconds(text string) (time.Duration, error) {
	seconds, err := strconv.ParseInt(text, 10, 64)
	if err != nil || seconds <= 0 {
		return 0, errors.New("ERR invalid expire time")
	}
	return time.Duration(seconds) * time.Second, nil
}

// pushservice.HintScript.
func pushHintTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 5 || len(call.Args) != 7 {
		return nil, errPushTwinArguments
	}
	versionsKey, streamKey, seqKey, tokenKey, liveKey := call.Keys[0], call.Keys[1], call.Keys[2], call.Keys[3], call.Keys[4]
	topic, version, kind, hint, raise := call.Args[0], call.Args[1], call.Args[2], call.Args[3], call.Args[4]
	if topic == "" || !pushservice.CanonicalVersion(version) {
		return nil, errPushTwinVersion
	}
	maxLength, err := strconv.ParseInt(call.Args[6], 10, 64)
	if err != nil || maxLength < 0 {
		return nil, errors.New("ERR value is not an integer or out of range")
	}
	ttl, err := pushTwinSeconds(call.Args[5])
	if err != nil {
		return nil, err
	}

	storedValue, found, err := call.HashGet(versionsKey, topic)
	if err != nil {
		return nil, err
	}
	stored := string(storedValue)
	if found && !pushservice.CanonicalVersion(stored) {
		found = false
	}
	higher := !found
	if found {
		comparison, _ := pushservice.CompareVersion(version, stored)
		higher = 0 < comparison
	}
	switch {
	case higher:
		if err := call.HashSet(versionsKey, map[string][]byte{topic: []byte(version)}); err != nil {
			return nil, err
		}
	case raise == "1":
		value, err := strconv.ParseInt(stored, 10, 64)
		if err != nil {
			return nil, errPushTwinNotInteger
		}
		if value == math.MaxInt64 {
			return nil, errPushTwinOverflow
		}
		version = strconv.FormatInt(value+1, 10)
		if err := call.HashSet(versionsKey, map[string][]byte{topic: []byte(version)}); err != nil {
			return nil, err
		}
	default:
		version = stored
	}
	seq, err := call.Increment(seqKey, 0)
	if err != nil {
		return nil, err
	}
	streamId, err := call.StreamAdd(streamKey, maxLength, map[string][]byte{
		"seq":     strconv.AppendInt(nil, seq, 10),
		"topic":   []byte(topic),
		"version": []byte(version),
		"kind":    []byte(kind),
		"hint":    []byte(hint),
	})
	if err != nil {
		return nil, err
	}
	for _, key := range []string{versionsKey, streamKey, seqKey} {
		if _, err := call.ExpireIfNone(key, ttl); err != nil {
			return nil, err
		}
	}
	slotValue := func(key string) (*sidecar.RedisReply, error) {
		value, found, err := call.Get(key)
		if err != nil {
			return nil, err
		}
		if !found {
			return RedisNilReply(), nil
		}
		return RedisBulkReply(value), nil
	}
	tokenReply, err := slotValue(tokenKey)
	if err != nil {
		return nil, err
	}
	liveReply, err := slotValue(liveKey)
	if err != nil {
		return nil, err
	}
	return RedisArrayReply(
		RedisBulkReply([]byte(streamId)),
		RedisBulkReply([]byte(version)),
		RedisIntegerReply(seq),
		tokenReply,
		liveReply,
	), nil
}

// pushservice.HintAckScript.
func pushHintAckTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 2 || len(call.Args) != 2 {
		return nil, errPushTwinArguments
	}
	ackKey, tokenKey := call.Keys[0], call.Keys[1]
	streamId := call.Args[0]
	if _, _, err := pushservice.ParseStreamId(streamId); err != nil {
		return nil, errPushTwinStreamId
	}
	ttl, err := pushTwinSeconds(call.Args[1])
	if err != nil {
		return nil, err
	}
	tokenExists, err := call.Exists(tokenKey)
	if err != nil {
		return nil, err
	}
	if !tokenExists {
		return RedisIntegerReply(0), nil
	}
	stored, found, err := call.Get(ackKey)
	if err != nil {
		return nil, err
	}
	if found {
		if comparison, err := pushservice.CompareStreamId(streamId, string(stored)); err == nil && comparison <= 0 {
			return RedisIntegerReply(0), nil
		}
	}
	if err := call.Set(ackKey, []byte(streamId), ttl); err != nil {
		return nil, err
	}
	return RedisIntegerReply(1), nil
}
