// RunPushStoreSuite's cases for §19.4's rate row (SDK-M8-10): pushservice.WakeRateScript taking a client's
// window and counting its wake against a vendor's cap in one step on {wake_<C>}, on FakeRedis with the twin in
// push_wake_twins.go and on server's real Redis with the Lua, so the twin stays honest (D-TEST-2). Windows and
// caps run on the target's KeyTimeout, so a real store waits seconds, and each case uses a client id no other
// case shares.

package sidecartest

import (
	"fmt"
	"strconv"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
)

func pushWakeSuiteCases() []pushSuiteCase {
	return []pushSuiteCase{
		{name: "the rate script takes the window and counts the wake, then answers the held window's start", run: casePushWakeRateTakesTheWindow},
		{name: "a lapsed window is taken again while the cap counts on", run: casePushWakeRateCapCountsOn},
		{name: "a cap's field lapses on its own", run: casePushWakeRateCapLapses},
		{name: "each fcm topic's cap is a field of its own beside apns's", run: casePushWakeRateFcmTopics},
		{name: "the rate script refuses malformed arguments and writes nothing", run: casePushWakeRateRefuses},
	}
}

// Runs the rate script for clientId at nowMs, the window windowMs, capField's cap window capWindowMs: whether
// it took the window, and the held window's start or the cap's count.
func (self *pushSuiteEnv) wakeRate(clientId connect.Id, nowMs int64, window time.Duration, capField string, capWindow time.Duration) (bool, int64, error) {
	reply, err := self.target.Redis.RunScript(self.ctx, pushservice.WakeRateScript, []string{pushservice.WakeRateKey(clientId)}, []string{
		strconv.FormatInt(nowMs, 10),
		strconv.FormatInt(window.Milliseconds(), 10),
		capField,
		strconv.FormatInt(capWindow.Milliseconds(), 10),
	})
	if err != nil {
		return false, 0, err
	}
	if reply == nil || reply.Kind != sidecar.RedisReplyArray || len(reply.Replies) != 2 || reply.Replies[0].Kind != sidecar.RedisReplyInteger {
		return false, 0, fmt.Errorf("a reply of %+v", reply)
	}
	switch value := reply.Replies[1]; {
	case reply.Replies[0].Integer == 0 && value.Kind == sidecar.RedisReplyBulk:
		start, err := strconv.ParseInt(string(value.Bulk), 10, 64)
		return false, start, err
	case reply.Replies[0].Integer == 1 && value.Kind == sidecar.RedisReplyInteger:
		return true, value.Integer, nil
	}
	return false, 0, fmt.Errorf("a reply of %+v", reply)
}

// Fails unless the rate script answers taken and value.
func (self *pushSuiteEnv) expectWakeRate(clientId connect.Id, nowMs int64, window time.Duration, capField string, capWindow time.Duration, wantTaken bool, wantValue int64) error {
	taken, value, err := self.wakeRate(clientId, nowMs, window, capField, capWindow)
	if err != nil {
		return err
	}
	if taken != wantTaken || value != wantValue {
		return fmt.Errorf("at %d %s answered taken %t value %d, want %t and %d", nowMs, capField, taken, value, wantTaken, wantValue)
	}
	return nil
}

// A time well past any a test clock starts at, and distinct per call, so a held window's start is told apart.
const pushWakeSuiteNowMs = int64(1_800_000_000_000)

func casePushWakeRateTakesTheWindow(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	window := env.target.KeyTimeout
	if err := env.expectWakeRate(clientId, pushWakeSuiteNowMs, window, "apns", 30*window, true, 1); err != nil {
		return err
	}
	if err := env.expectWakeRate(clientId, pushWakeSuiteNowMs+1, window, "apns", 30*window, false, pushWakeSuiteNowMs); err != nil {
		return err
	}
	fieldValues, err := env.target.Redis.HashGetAll(env.ctx, pushservice.WakeRateKey(clientId))
	if err != nil {
		return err
	}
	if len(fieldValues) != 2 || string(fieldValues["w"]) != strconv.FormatInt(pushWakeSuiteNowMs, 10) || string(fieldValues["apns"]) != "1" {
		return fmt.Errorf("the hash holds %q", fieldValues)
	}
	return nil
}

func casePushWakeRateCapCountsOn(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	window := env.target.KeyTimeout
	if err := env.expectWakeRate(clientId, pushWakeSuiteNowMs, window, "apns", 30*window, true, 1); err != nil {
		return err
	}
	env.target.Pass(window + window/2)
	return env.expectWakeRate(clientId, pushWakeSuiteNowMs+2, window, "apns", 30*window, true, 2)
}

func casePushWakeRateCapLapses(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	window := env.target.KeyTimeout
	if err := env.expectWakeRate(clientId, pushWakeSuiteNowMs, window, "apns", window, true, 1); err != nil {
		return err
	}
	env.target.Pass(window + window/2)
	if err := env.expectWakeRate(clientId, pushWakeSuiteNowMs+3, window, "apns", window, true, 1); err != nil {
		return err
	}
	return nil
}

func casePushWakeRateFcmTopics(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	window := env.target.KeyTimeout
	if err := env.expectWakeRate(clientId, pushWakeSuiteNowMs, window, "fcm:mail", 30*window, true, 1); err != nil {
		return err
	}
	env.target.Pass(window + window/2)
	if err := env.expectWakeRate(clientId, pushWakeSuiteNowMs+4, window, "fcm:team", 30*window, true, 1); err != nil {
		return err
	}
	env.target.Pass(window + window/2)
	if err := env.expectWakeRate(clientId, pushWakeSuiteNowMs+5, window, "fcm:mail", 30*window, true, 2); err != nil {
		return err
	}
	fieldValues, err := env.target.Redis.HashGetAll(env.ctx, pushservice.WakeRateKey(clientId))
	if err != nil {
		return err
	}
	if string(fieldValues["fcm:mail"]) != "2" || string(fieldValues["fcm:team"]) != "1" || fieldValues["apns"] != nil {
		return fmt.Errorf("the hash holds %q", fieldValues)
	}
	return nil
}

func casePushWakeRateRefuses(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	key := pushservice.WakeRateKey(clientId)
	for _, args := range [][]string{
		{"0", "10000", "apns", "3600000"},
		{"1800000000000", "-1", "apns", "3600000"},
		{"1800000000000", "10000", "apns", ""},
		{"1800000000000", "10000", "fcm:MAIL", "60000"},
		{"1800000000000", "10000", "w", "60000"},
		{"1800000000000", "10000", "fcm:", "60000"},
		{"18000000000000000", "10000", "apns", "3600000"},
	} {
		if _, err := env.target.Redis.RunScript(env.ctx, pushservice.WakeRateScript, []string{key}, args); err == nil {
			return fmt.Errorf("arguments %q were taken", args)
		}
	}
	fieldValues, err := env.target.Redis.HashGetAll(env.ctx, key)
	if err != nil {
		return err
	}
	if len(fieldValues) != 0 {
		return fmt.Errorf("a refused call wrote %q", fieldValues)
	}
	return nil
}
