// The Go twin of pushservice's wake rate script (§19.4's rate row; SDK-M8-10) for FakeRedis, step for step as
// the Lua, holding the fake's lock for the whole run. RunPushStoreSuite runs the twin and the Lua through the same
// cases (push_wake_suite.go), so a twin that drifts fails there (D-TEST-2).

package sidecartest

import (
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
)

var errPushWakeRateTwinArguments = errors.New("ERR wake rate arguments malformed")

// The Lua's '^fcm:[a-z]+$'.
var pushWakeRateFcmFieldPattern = regexp.MustCompile(`^fcm:[a-z]+$`)

// The Lua's decimal: 1 to 15 digits, the first not 0.
func pushWakeRateTwinDecimal(text string) (int64, bool) {
	if text == "" || 15 < len(text) || text[0] < '1' || '9' < text[0] {
		return 0, false
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// pushservice.WakeRateScript.
func pushWakeRateTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 1 || len(call.Args) != 4 {
		return nil, errPushTwinArguments
	}
	key := call.Keys[0]
	now, capField := call.Args[0], call.Args[2]
	_, nowOk := pushWakeRateTwinDecimal(now)
	windowMs, windowOk := pushWakeRateTwinDecimal(call.Args[1])
	capWindowMs, capWindowOk := pushWakeRateTwinDecimal(call.Args[3])
	if !nowOk || !windowOk || !capWindowOk || (capField != "apns" && !pushWakeRateFcmFieldPattern.MatchString(capField)) {
		return nil, errPushWakeRateTwinArguments
	}
	start, found, err := call.HashGet(key, "w")
	if err != nil {
		return nil, err
	}
	if found {
		return RedisArrayReply(RedisIntegerReply(0), RedisBulkReply(start)), nil
	}
	if err := call.HashSet(key, map[string][]byte{"w": []byte(now)}); err != nil {
		return nil, err
	}
	if err := call.HashExpire(key, []string{"w"}, time.Duration(windowMs)*time.Millisecond); err != nil {
		return nil, err
	}
	count, err := call.HashIncrement(key, capField)
	if err != nil {
		return nil, err
	}
	if count == 1 {
		if err := call.HashExpire(key, []string{capField}, time.Duration(capWindowMs)*time.Millisecond); err != nil {
			return nil, err
		}
	}
	return RedisArrayReply(RedisIntegerReply(1), RedisIntegerReply(count)), nil
}
