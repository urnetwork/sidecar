// The Go twins of pushservice's wake token scripts (§18.7's step 0) for FakeRedis, step for step as the
// Lua, holding the fake's lock for the whole run. RunPushStoreSuite runs both the twins and the Lua
// through the same cases (push_token_suite.go), so a twin that drifts fails there (D-TEST-2).

package sidecartest

import (
	"errors"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
)

var errPushTokenTwinArguments = errors.New("ERR wake token apply arguments malformed")

// pushservice.WakeTokenTimeScript: the master's TIME, {seconds, microseconds} as bulk strings, from the
// fake's clock. It reads no key.
func pushTokenTimeTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 1 || len(call.Args) != 0 {
		return nil, errPushTwinArguments
	}
	now := call.Now()
	return RedisArrayReply(
		RedisBulkReply([]byte(strconv.FormatInt(now.Unix(), 10))),
		RedisBulkReply([]byte(strconv.FormatInt(int64(now.Nanosecond()/1000), 10))),
	), nil
}

// The script's revision test: 1 to 16 digits, the first not 0, at most 2^53 - 1.
func pushTokenTwinRevision(text string) (int64, bool) {
	if text == "" || 16 < len(text) || text[0] < '1' || '9' < text[0] {
		return 0, false
	}
	if strings.IndexFunc(text, func(r rune) bool { return r < '0' || '9' < r }) >= 0 {
		return 0, false
	}
	if len(text) == 16 && "9007199254740991" < text {
		return 0, false
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// pushservice.WakeTokenApplyScript.
func pushTokenApplyTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 2 || len(call.Args) != 4 {
		return nil, errPushTwinArguments
	}
	tok, tokrev := call.Keys[0], call.Keys[1]
	t0, t0Ok := pushTokenTwinRevision(call.Args[0])
	window, windowOk := pushTokenTwinRevision(call.Args[1])
	rev, revOk := pushTokenTwinRevision(call.Args[2])
	value := call.Args[3]
	if !t0Ok || !windowOk || !revOk {
		return nil, errPushTokenTwinArguments
	}
	now := call.Now()
	nowMs := now.Unix()*1000 + int64(now.Nanosecond()/1000)/1000
	if window < nowMs-t0 {
		return RedisBulkReply([]byte(pushservice.WakeTokenExpired)), nil
	}
	stored, found, err := call.Get(tokrev)
	if err != nil {
		return nil, err
	}
	if found {
		if storedRev, ok := pushTokenTwinRevision(string(stored)); ok {
			if rev < storedRev {
				return RedisBulkReply([]byte(pushservice.WakeTokenStale)), nil
			}
			if rev == storedRev {
				return RedisBulkReply([]byte(pushservice.WakeTokenCurrent)), nil
			}
		}
	}
	if err := call.Set(tokrev, []byte(call.Args[2]), 0); err != nil {
		return nil, err
	}
	if value == "" {
		if err := call.Delete(tok); err != nil {
			return nil, err
		}
	} else if err := call.Set(tok, []byte(value), 0); err != nil {
		return nil, err
	}
	return RedisBulkReply([]byte(pushservice.WakeTokenApplied)), nil
}
