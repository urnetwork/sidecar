package pushservice_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// tok's value parses back to what was written, and anything else the sender would act on does not.
func TestWakeTokenValueRoundTrip(t *testing.T) {
	for _, platform := range []string{sidecar.PushTokenPlatformApns, sidecar.PushTokenPlatformFcm} {
		token := "fixture-token_0123:abc"
		gotPlatform, gotToken, ok := pushservice.ParseWakeTokenValue(pushservice.WakeTokenValue(platform, token))
		if !ok || gotPlatform != platform || gotToken != token {
			t.Errorf("%s: parsed %q %q %t", platform, gotPlatform, gotToken, ok)
		}
	}
	for _, value := range []string{
		"",
		"apns",
		"apns\n",
		"\nfixture",
		"gcm\nfixture",
		"apns\nfixture\nsecond",
		"apns\nfix ture",
		"APNS\nfixture",
		"apns\n" + strings.Repeat("a", sidecar.PushTokenMaxByteCount+1),
	} {
		if _, _, ok := pushservice.ParseWakeTokenValue([]byte(value)); ok {
			t.Errorf("%q parsed", value)
		}
	}
}

// A HintRedis that notes each script's keys before passing the call on.
type wakeTokenRecordingRedis struct {
	pushservice.HintRedis
	scriptKeys map[string][][]string
}

func (self *wakeTokenRecordingRedis) RunScript(ctx context.Context, script *sidecar.RedisScript, keys []string, args []string) (*sidecar.RedisReply, error) {
	self.scriptKeys[script.Name] = append(self.scriptKeys[script.Name], slices.Clone(keys))
	return self.HintRedis.RunScript(ctx, script, keys, args)
}

// t0 is the slot master's clock, read inside the script that names the client's tokrev, so on a cluster
// the call routes to that master; on T2's fake it is the fake's clock to the millisecond.
func TestWakeTokenTimeIsTheSlotMastersClock(t *testing.T) {
	fakeRedis, clock := testPushRedis(t)
	redis := &wakeTokenRecordingRedis{HintRedis: fakeRedis, scriptKeys: map[string][][]string{}}
	clientId := connect.NewId()
	clock.Advance(1234567 * time.Microsecond)
	t0, err := pushservice.ReadWakeTokenTime(t.Context(), redis, clientId)
	if err != nil {
		t.Fatal(err)
	}
	if want := clock.Now().UnixMilli(); t0 != want {
		t.Fatalf("t0 = %d, want %d", t0, want)
	}
	calls := redis.scriptKeys[pushservice.WakeTokenTimeScript.Name]
	if len(calls) != 1 || !slices.Equal(calls[0], []string{pushservice.WakeTokenRevisionKey(clientId)}) {
		t.Fatalf("the time script ran on %v, want the client's tokrev alone", calls)
	}
}

// The apply answers on T2's twin: applied, current, stale and expired, each with what it leaves. The same
// cases run on server's real Redis through RunPushStoreSuite (push_token_suite.go).
func TestWakeTokenApplyAnswersOnTheTwin(t *testing.T) {
	redis, clock := testPushRedis(t)
	ctx := t.Context()
	clientId := connect.NewId()
	window := 60 * time.Second
	row := func(revision int64, token string) *pushservice.WakeTokenRow {
		row := &pushservice.WakeTokenRow{ClientId: clientId, Revision: revision, Token: token}
		if token != "" {
			row.Platform = sidecar.PushTokenPlatformFcm
		}
		return row
	}
	t0 := clock.Now().UnixMilli()
	for _, step := range []struct {
		row  *pushservice.WakeTokenRow
		want pushservice.WakeTokenApplyResult
	}{
		{row: row(100, "first"), want: pushservice.WakeTokenApplied},
		{row: row(100, "other"), want: pushservice.WakeTokenCurrent},
		{row: row(99, "older"), want: pushservice.WakeTokenStale},
		{row: row(101, ""), want: pushservice.WakeTokenApplied},
		{row: row(100, "first"), want: pushservice.WakeTokenStale},
	} {
		result, err := pushservice.ApplyWakeToken(ctx, redis, step.row, t0, window)
		if err != nil {
			t.Fatal(err)
		}
		if result != step.want {
			t.Fatalf("revision %d answered %s, want %s", step.row.Revision, result, step.want)
		}
	}
	if _, found, _ := redis.Get(ctx, pushservice.HintTokenKey(clientId)); found {
		t.Fatal("tok outlived its tombstone")
	}
	if tokrev, _, _ := redis.Get(ctx, pushservice.WakeTokenRevisionKey(clientId)); string(tokrev) != "101" {
		t.Fatalf("tokrev = %q", tokrev)
	}

	// exactly the window past t0 still lands; a millisecond more is expired
	clock.Advance(window)
	if result, err := pushservice.ApplyWakeToken(ctx, redis, row(102, "edge"), t0, window); err != nil || result != pushservice.WakeTokenApplied {
		t.Fatalf("at the window: %s %v", result, err)
	}
	clock.Advance(time.Millisecond)
	if result, err := pushservice.ApplyWakeToken(ctx, redis, row(103, "late"), t0, window); err != nil || result != pushservice.WakeTokenExpired {
		t.Fatalf("past the window: %s %v", result, err)
	}
	if tokrev, _, _ := redis.Get(ctx, pushservice.WakeTokenRevisionKey(clientId)); string(tokrev) != "102" {
		t.Fatalf("an expired apply wrote tokrev %q", tokrev)
	}
	if violations := redis.Violations(); len(violations) != 0 {
		t.Fatalf("violations: %v", violations)
	}
}

// What the apply refuses before sending anything.
func TestApplyWakeTokenRefusesWhatItCannotCarry(t *testing.T) {
	redis, clock := testPushRedis(t)
	ctx := t.Context()
	clientId := connect.NewId()
	t0 := clock.Now().UnixMilli()
	good := &pushservice.WakeTokenRow{ClientId: clientId, Revision: 1, Platform: sidecar.PushTokenPlatformApns, Token: "fixture"}
	for _, c := range []struct {
		row    *pushservice.WakeTokenRow
		t0     int64
		window time.Duration
	}{
		{row: nil, t0: t0, window: time.Minute},
		{row: good, t0: 0, window: time.Minute},
		{row: good, t0: t0, window: 0},
		{row: good, t0: t0, window: time.Minute + time.Microsecond},
		{row: &pushservice.WakeTokenRow{ClientId: clientId, Revision: 1, Platform: sidecar.PushTokenPlatformApns}, t0: t0, window: time.Minute},
		{row: &pushservice.WakeTokenRow{ClientId: clientId, Revision: -1, Token: ""}, t0: t0, window: time.Minute},
	} {
		if _, err := pushservice.ApplyWakeToken(ctx, redis, c.row, c.t0, c.window); !errors.Is(err, pushservice.ErrWakeTokenInvalid) {
			t.Errorf("%+v %d %v: %v", c.row, c.t0, c.window, err)
		}
	}
	if count := redis.OpCounts()["script:"+pushservice.WakeTokenApplyScript.Name]; count != 0 {
		t.Fatalf("sent %d applies", count)
	}
}

// The token's keys and the hint keys share the client's tag, so the hint script's read of tok and every
// apply stay on one slot (WK1).
func TestWakeTokenKeysShareTheClientsTag(t *testing.T) {
	clientId := connect.NewId()
	keys := []string{
		pushservice.HintTokenKey(clientId),
		pushservice.WakeTokenRevisionKey(clientId),
		pushservice.HintVersionsKey(clientId),
		pushservice.HintAckKey(clientId),
	}
	if !sidecar.RedisKeysShareTag(keys) {
		t.Fatalf("%v share no tag", keys)
	}
	slot := sidecartest.RedisClusterSlot(keys[0])
	for _, key := range keys[1:] {
		if sidecartest.RedisClusterSlot(key) != slot {
			t.Fatalf("%s is on another slot", key)
		}
	}
	if pushservice.WakeTokenRevisionKey(clientId) != "{scp_"+clientId.String()+"}tokrev" {
		t.Fatalf("tokrev is %s", pushservice.WakeTokenRevisionKey(clientId))
	}
}
