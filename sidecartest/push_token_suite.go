// RunPushStoreSuite's cases for §18.7's step 0 (SDK-M8-09): the wake token apply script's four answers,
// applied, current, stale and expired, and what each leaves in tok and tokrev, on FakeRedis with the twins
// in push_token_twins.go and on server's real Redis with the Lua, so the twin stays honest (D-TEST-2).
// Each case uses a client id no other case shares.

package sidecartest

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
)

// The window every case applies with: §18.7's 60 s.
const pushTokenSuiteWindow = 60 * time.Second

func pushTokenSuiteCases() []pushSuiteCase {
	return []pushSuiteCase{
		{name: "a token apply sets tok and tokrev at the row's revision", run: casePushTokenApplied},
		{name: "a token apply at tokrev's revision writes nothing", run: casePushTokenCurrent},
		{name: "a token apply below tokrev's revision is stale and writes nothing", run: casePushTokenStale},
		{name: "a token apply over the window past t0 is expired and writes nothing", run: casePushTokenExpired},
		{name: "a tombstone deletes tok, keeps its revision, and no older token returns", run: casePushTokenTombstone},
		{name: "token revisions near 2^53 compare exactly", run: casePushTokenLargeRevisions},
		{name: "a stored tokrev that is no revision is overwritten", run: casePushTokenMalformedStored},
		{name: "the token apply script refuses arguments that are no revision and writes nothing", run: casePushTokenArgumentsRefused},
		{name: "a token's keys share the client's tag and have no ttl", run: casePushTokenKeys},
	}
}

// The slot master's TIME now, as a writer reads t0.
func (self *pushSuiteEnv) tokenTime(clientId connect.Id) (int64, error) {
	return pushservice.ReadWakeTokenTime(self.ctx, self.target.Redis, clientId)
}

// Applies row with a t0 read now.
func (self *pushSuiteEnv) applyToken(row *pushservice.WakeTokenRow) (pushservice.WakeTokenApplyResult, error) {
	t0, err := self.tokenTime(row.ClientId)
	if err != nil {
		return "", err
	}
	return pushservice.ApplyWakeToken(self.ctx, self.target.Redis, row, t0, pushTokenSuiteWindow)
}

// What tok and tokrev hold, "" for an absent key.
func (self *pushSuiteEnv) tokenKeys(clientId connect.Id) (tok string, tokrev string, err error) {
	tokValue, tokFound, err := self.target.Redis.Get(self.ctx, pushservice.HintTokenKey(clientId))
	if err != nil {
		return "", "", err
	}
	revValue, revFound, err := self.target.Redis.Get(self.ctx, pushservice.WakeTokenRevisionKey(clientId))
	if err != nil {
		return "", "", err
	}
	if tokFound {
		tok = string(tokValue)
	}
	if revFound {
		tokrev = string(revValue)
	}
	return tok, tokrev, nil
}

// Fails unless tok and tokrev hold wantTok and wantRev, "" meaning absent.
func (self *pushSuiteEnv) expectTokenKeys(clientId connect.Id, wantTok string, wantRev string) error {
	tok, tokrev, err := self.tokenKeys(clientId)
	if err != nil {
		return err
	}
	if tok != wantTok || tokrev != wantRev {
		return fmt.Errorf("tok %q tokrev %q, want %q and %q", tok, tokrev, wantTok, wantRev)
	}
	return nil
}

func pushTokenSuiteRow(clientId connect.Id, revision int64, token string) *pushservice.WakeTokenRow {
	row := &pushservice.WakeTokenRow{ClientId: clientId, Revision: revision, Token: token}
	if token != "" {
		row.Platform = sidecar.PushTokenPlatformApns
	}
	return row
}

func pushTokenSuiteValue(token string) string {
	return string(pushservice.WakeTokenValue(sidecar.PushTokenPlatformApns, token))
}

// Applies each row in turn, failing unless each answers its result.
func (self *pushSuiteEnv) applyTokens(rows []*pushservice.WakeTokenRow, wants []pushservice.WakeTokenApplyResult) error {
	for index, row := range rows {
		result, err := self.applyToken(row)
		if err != nil {
			return err
		}
		if result != wants[index] {
			return fmt.Errorf("apply %d of revision %d answered %s, want %s", index, row.Revision, result, wants[index])
		}
	}
	return nil
}

func casePushTokenApplied(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	if err := env.applyTokens(
		[]*pushservice.WakeTokenRow{pushTokenSuiteRow(clientId, 1_731_000_000_000, "a0"), pushTokenSuiteRow(clientId, 1_731_000_000_001, "a1")},
		[]pushservice.WakeTokenApplyResult{pushservice.WakeTokenApplied, pushservice.WakeTokenApplied},
	); err != nil {
		return err
	}
	value, found, err := env.target.Redis.Get(env.ctx, pushservice.HintTokenKey(clientId))
	if err != nil || !found {
		return fmt.Errorf("tok absent: %v", err)
	}
	platform, token, ok := pushservice.ParseWakeTokenValue(value)
	if !ok || platform != sidecar.PushTokenPlatformApns || token != "a1" {
		return fmt.Errorf("tok parses as %q %q %t", platform, token, ok)
	}
	return env.expectTokenKeys(clientId, pushTokenSuiteValue("a1"), "1731000000001")
}

func casePushTokenCurrent(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	if err := env.applyTokens(
		[]*pushservice.WakeTokenRow{pushTokenSuiteRow(clientId, 5, "c0"), pushTokenSuiteRow(clientId, 5, "c1")},
		[]pushservice.WakeTokenApplyResult{pushservice.WakeTokenApplied, pushservice.WakeTokenCurrent},
	); err != nil {
		return err
	}
	return env.expectTokenKeys(clientId, pushTokenSuiteValue("c0"), "5")
}

func casePushTokenStale(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	if err := env.applyTokens(
		// lengths differ, so a comparison as text would get 10 against 9 wrong
		[]*pushservice.WakeTokenRow{pushTokenSuiteRow(clientId, 10, "s10"), pushTokenSuiteRow(clientId, 9, "s9"), pushTokenSuiteRow(clientId, 2, "")},
		[]pushservice.WakeTokenApplyResult{pushservice.WakeTokenApplied, pushservice.WakeTokenStale, pushservice.WakeTokenStale},
	); err != nil {
		return err
	}
	return env.expectTokenKeys(clientId, pushTokenSuiteValue("s10"), "10")
}

func casePushTokenExpired(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	now, err := env.tokenTime(clientId)
	if err != nil {
		return err
	}
	// a t0 a second past the window ago
	staleT0 := now - pushTokenSuiteWindow.Milliseconds() - 1000
	result, err := pushservice.ApplyWakeToken(env.ctx, env.target.Redis, pushTokenSuiteRow(clientId, 3, "e0"), staleT0, pushTokenSuiteWindow)
	if err != nil {
		return err
	}
	if result != pushservice.WakeTokenExpired {
		return fmt.Errorf("an apply past its window answered %s", result)
	}
	if err := env.expectTokenKeys(clientId, "", ""); err != nil {
		return err
	}
	// its retry rereads t0 and lands
	result, err = env.applyToken(pushTokenSuiteRow(clientId, 3, "e0"))
	if err != nil {
		return err
	}
	if result != pushservice.WakeTokenApplied {
		return fmt.Errorf("the retry answered %s", result)
	}
	return env.expectTokenKeys(clientId, pushTokenSuiteValue("e0"), "3")
}

func casePushTokenTombstone(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	if err := env.applyTokens(
		[]*pushservice.WakeTokenRow{pushTokenSuiteRow(clientId, 20, "t20"), pushTokenSuiteRow(clientId, 21, "")},
		[]pushservice.WakeTokenApplyResult{pushservice.WakeTokenApplied, pushservice.WakeTokenApplied},
	); err != nil {
		return err
	}
	if err := env.expectTokenKeys(clientId, "", "21"); err != nil {
		return err
	}
	// the removed token's apply, landing late, is stale
	if err := env.applyTokens(
		[]*pushservice.WakeTokenRow{pushTokenSuiteRow(clientId, 20, "t20")},
		[]pushservice.WakeTokenApplyResult{pushservice.WakeTokenStale},
	); err != nil {
		return err
	}
	return env.expectTokenKeys(clientId, "", "21")
}

func casePushTokenLargeRevisions(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	top := pushservice.WakeTokenMaxRevision
	if err := env.applyTokens(
		[]*pushservice.WakeTokenRow{pushTokenSuiteRow(clientId, top-1, "l1"), pushTokenSuiteRow(clientId, top, "l2"), pushTokenSuiteRow(clientId, top-1, "l3")},
		[]pushservice.WakeTokenApplyResult{pushservice.WakeTokenApplied, pushservice.WakeTokenApplied, pushservice.WakeTokenStale},
	); err != nil {
		return err
	}
	return env.expectTokenKeys(clientId, pushTokenSuiteValue("l2"), strconv.FormatInt(top, 10))
}

func casePushTokenMalformedStored(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	// written through the store, as nothing but a corruption would
	if err := env.target.Redis.Set(env.ctx, pushservice.WakeTokenRevisionKey(clientId), []byte("not a revision"), 0); err != nil {
		return err
	}
	if err := env.applyTokens(
		[]*pushservice.WakeTokenRow{pushTokenSuiteRow(clientId, 7, "m7")},
		[]pushservice.WakeTokenApplyResult{pushservice.WakeTokenApplied},
	); err != nil {
		return err
	}
	return env.expectTokenKeys(clientId, pushTokenSuiteValue("m7"), "7")
}

func casePushTokenArgumentsRefused(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	t0, err := env.tokenTime(clientId)
	if err != nil {
		return err
	}
	keys := []string{pushservice.HintTokenKey(clientId), pushservice.WakeTokenRevisionKey(clientId)}
	t0Text := strconv.FormatInt(t0, 10)
	for _, args := range [][]string{
		{t0Text, "60000", "0", "x"},
		{t0Text, "60000", "9007199254740992", "x"},
		{t0Text, "60000", "-1", "x"},
		{t0Text, "60000", "01", "x"},
		{t0Text, "0", "1", "x"},
		{"", "60000", "1", "x"},
	} {
		if _, err := env.target.Redis.RunScript(env.ctx, pushservice.WakeTokenApplyScript, keys, args); err == nil {
			return fmt.Errorf("the script took %q", args)
		}
	}
	// and the Go side refuses before sending
	for _, row := range []*pushservice.WakeTokenRow{
		pushTokenSuiteRow(clientId, 0, "x"),
		pushTokenSuiteRow(clientId, pushservice.WakeTokenMaxRevision+1, "x"),
		{ClientId: clientId, Revision: 1, Platform: "gcm", Token: "x"},
		{ClientId: clientId, Revision: 1, Platform: sidecar.PushTokenPlatformFcm, Token: "two\nlines"},
		{ClientId: clientId, Revision: 1, Platform: sidecar.PushTokenPlatformFcm},
	} {
		if _, err := pushservice.ApplyWakeToken(env.ctx, env.target.Redis, row, t0, pushTokenSuiteWindow); !errors.Is(err, pushservice.ErrWakeTokenInvalid) {
			return fmt.Errorf("a row %+v applied: %v", *row, err)
		}
	}
	return env.expectTokenKeys(clientId, "", "")
}

func casePushTokenKeys(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	keys := []string{pushservice.HintTokenKey(clientId), pushservice.WakeTokenRevisionKey(clientId), pushservice.HintSeqKey(clientId)}
	if !sidecar.RedisKeysShareTag(keys) {
		return fmt.Errorf("%v share no tag", keys)
	}
	if err := env.applyTokens(
		[]*pushservice.WakeTokenRow{pushTokenSuiteRow(clientId, 40, "k40")},
		[]pushservice.WakeTokenApplyResult{pushservice.WakeTokenApplied},
	); err != nil {
		return err
	}
	// no ttl: a hint script's EXPIRE NX on n never touches them, and they outlive the hint keys' hour
	env.target.Pass(env.target.KeyTimeout + time.Second)
	return env.expectTokenKeys(clientId, pushTokenSuiteValue("k40"), "40")
}
