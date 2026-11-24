//go:build !sidecar_http

// A token refused for good is no unreachability (gkm_ladder.go's gkmTokenRefused; KF7, §10.5's Rotate inside
// EnsureWritable): a revoked device's write, its own state still behind its revocation, where the generation it holds
// covers every holder that state knows of, ends at the ladder with its token's refusal and seals nothing from the
// keychain, as does a deposit, and a sync's late answers stop at the first such refusal; with gkm truly unreachable,
// its transport failing, the lb answering in its place, gkm's own 503 or a token the keeper cannot have for now, the
// write still goes on from what the keychain holds while every shrink its state shows is covered. On the grant-lag
// world (gkm_grant_lag_test.go): one device on GkmApi itself, over a token exchange answering from api's gate and a
// gkm guarding on the log's tip.

package sidecar_test

import (
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// How many requests the fake gkm took, of every route.
func (self *gkmGrantLagGkm) requestCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.requests)
}

// The exchange's refusal of a client its gate no longer admits, as server/oauth answers it.
func gkmTokenRefusalInvalidGrant() *sidecar.SidecarApiError {
	return &sidecar.SidecarApiError{Route: "POST /oauth/token", Status: http.StatusBadRequest, Code: "invalid_grant"}
}

// Whether err holds the exchange's refusal with code.
func gkmTokenRefusalIsExchangeCode(err error, code string) bool {
	var apiError *sidecar.SidecarApiError
	return errors.As(err, &apiError) && apiError.Code == code
}

// A revoked writer whose own state lags its revocation, generation 1 covering every holder that state knows of: with
// gkm's gate holding the revocation and api's behind it, the exchange grants the token and gkm refuses it 401, and the
// write ends with ErrGkmTokenRefused after that one read of the generations; with api's gate holding it too, the
// exchange refuses invalid_grant, and the write ends with that after one ask, nothing reaching gkm. The clock does not
// move, no key is answered, and no claim reaches gkm. The code before read both refusals as gkm unreachable (KF7) and
// answered generation 1's key from the keychain, the write going on sealed to it until evs's own exchange refused it.
func TestARevokedDevicesWriteEndsAtItsTokensRefusal(t *testing.T) {
	lag := newGkmGrantLagReader(t, true)
	agent := lag.device
	key, err, _ := lag.ensureWritable()
	if err != nil || key.Generation() != 1 {
		t.Fatalf("the writer's write while it stands: %v", err)
	}
	lag.revoke(agent.gkmWorldDevice)
	revoked := lag.stateFor(agent.gkmWorldDevice)

	generationsBefore := len(lag.gkm.taken("Generations"))
	key, err, took := lag.ensureWritable()
	if key != nil || !errors.Is(err, sidecar.ErrGkmTokenRefused) || took != 0 {
		t.Errorf("a revoked writer, api's gate behind: %v after %s, answering a key: %t", err, took, key != nil)
	}
	if generations := lag.gkm.taken("Generations")[generationsBefore:]; len(generations) != 1 || generations[0].status != http.StatusUnauthorized {
		t.Errorf("gkm took %d reads of the generations", len(generations))
	}

	lag.exchange.apply(revoked)
	asksBefore := lag.exchange.count(agent.id)
	requestsBefore := lag.gkm.requestCount()
	key, err, took = lag.ensureWritable()
	if key != nil || !gkmTokenRefusalIsExchangeCode(err, "invalid_grant") || took != 0 {
		t.Errorf("a revoked writer, api's gate holding it: %v after %s, answering a key: %t", err, took, key != nil)
	}
	if asks := lag.exchange.count(agent.id) - asksBefore; asks != 1 {
		t.Errorf("the write asked the exchange %d times", asks)
	}
	if requests := lag.gkm.requestCount() - requestsBefore; requests != 0 {
		t.Errorf("a write with no token reached gkm %d times", requests)
	}
	if lag.store.callCount("ClaimGeneration") != 0 || lag.store.newestGeneration(lag.groupId) != 1 {
		t.Errorf("gkm's store took %d claims and holds generation %d", lag.store.callCount("ClaimGeneration"), lag.store.newestGeneration(lag.groupId))
	}
}

// A writer whose grant ended, its own state still showing it, generation 1 covering every holder that state knows of:
// the exchange leaves the repo out of the batch's token, gkm refuses the read of the generations, and the read's r
// scope alone is refused invalid_scope, asked again through QD-1230's window, 0 to 5 s; then the write ends with that
// refusal and answers no key. The code before took the refusal past the window as gkm unreachable and answered
// generation 1's key from the keychain.
func TestAWriteWhoseGrantEndedEndsAtTheExchangesRefusal(t *testing.T) {
	lag := newGkmGrantLagReader(t, true)
	agent := lag.device
	lag.drop(agent.gkmWorldDevice)
	lag.repo.HoldersShrunkAt = lag.nextPosition()
	lag.exchange.apply(lag.stateFor(agent.gkmWorldDevice))
	start := lag.clock.Now()

	key, err, took := lag.ensureWritable()
	if key != nil || !gkmTokenRefusalIsExchangeCode(err, "invalid_scope") || took != lag.apiSettings.ExchangeScopeWaitTimeout {
		t.Errorf("a writer whose grant ended: %v after %s, answering a key: %t", err, took, key != nil)
	}
	alone := lag.exchange.asked(agent.id, lag.scope(sidecar.GkmScopeRoleRead))
	wantOffsets := []time.Duration{0, time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second, 5 * time.Second}
	if offsets := gkmGrantLagAskOffsets(alone, start); !slices.Equal(offsets, wantOffsets) {
		t.Errorf("the r scope alone was asked at %v, want %v", offsets, wantOffsets)
	}
	if lag.store.callCount("ClaimGeneration") != 0 || lag.store.newestGeneration(lag.groupId) != 1 {
		t.Errorf("gkm's store took %d claims and holds generation %d", lag.store.callCount("ClaimGeneration"), lag.store.newestGeneration(lag.groupId))
	}
}

// A writer with no enrolled client, its keeper refusing every token (ErrSidecarServiceTokenNoClient, which a revoked
// sidecar's lifecycle answers): the write ends with that refusal after one ask and answers no key, nothing reaching
// gkm, where the code before answered generation 1's key from the keychain.
func TestAWriteWithNoEnrolledClientEndsAtTheKeepersRefusal(t *testing.T) {
	lag := newGkmGrantLagReader(t, true)
	agent := lag.device
	lag.exchange.refuse(sidecar.ErrSidecarServiceTokenNoClient)
	asksBefore := lag.exchange.count(agent.id)
	requestsBefore := lag.gkm.requestCount()

	key, err, took := lag.ensureWritable()
	if key != nil || !errors.Is(err, sidecar.ErrSidecarServiceTokenNoClient) || took != 0 {
		t.Errorf("a write with no enrolled client: %v after %s, answering a key: %t", err, took, key != nil)
	}
	if asks := lag.exchange.count(agent.id) - asksBefore; asks != 1 {
		t.Errorf("the write asked the keeper %d times", asks)
	}
	if requests := lag.gkm.requestCount() - requestsBefore; requests != 0 {
		t.Errorf("a write with no token reached gkm %d times", requests)
	}
}

// KF7 on GkmApi itself: the writer's write goes on from the keychain, generation 1's key, with gkm's transport failing
// at once, the lb answering 502 or 504 in gkm's place, gkm's own 503 to the read of the generations and each of its
// ReadRetryCount retries a second apart, and the token keeper unable to have a token for now, api giving no answer or
// its 503, asked again ExchangeRetryCount times a second apart: nothing of those refuses. It still stops at the first
// shrink its state shows that its newest generation does not cover, ErrGkmWait, and nothing claims a generation.
func TestAWriteGoesOnFromTheKeychainOnlyWhileGkmIsUnreachable(t *testing.T) {
	lag := newGkmGrantLagReader(t, true)
	agent := lag.device
	retried := time.Duration(lag.apiSettings.ReadRetryCount) * lag.apiSettings.ReadRetryWait
	exchangeRetried := time.Duration(lag.apiSettings.ExchangeRetryCount) * lag.apiSettings.ReadRetryWait
	for _, case_ := range []struct {
		name   string
		fault  func()
		clear  func()
		took   time.Duration
		gkmAsk bool
	}{
		{
			name:   "gkm's transport failing",
			fault:  func() { lag.store.setDown(true) },
			clear:  func() { lag.store.setDown(false) },
			gkmAsk: true,
		},
		{
			name:   "the lb's 502",
			fault:  func() { lag.store.setLb(http.StatusBadGateway) },
			clear:  func() { lag.store.setLb(0) },
			gkmAsk: true,
		},
		{
			name:   "the lb's 504",
			fault:  func() { lag.store.setLb(http.StatusGatewayTimeout) },
			clear:  func() { lag.store.setLb(0) },
			gkmAsk: true,
		},
		{
			name: "gkm's 503",
			fault: func() {
				lag.store.refuseTimes("Generations", http.StatusServiceUnavailable, lag.apiSettings.ReadRetryCount+1)
			},
			clear:  func() {},
			took:   retried,
			gkmAsk: true,
		},
		{
			name:  "no answer from api",
			fault: func() { lag.exchange.refuse(errors.New("synthetic: api gave no answer")) },
			clear: func() { lag.exchange.refuse(nil) },
			took:  exchangeRetried,
		},
		{
			name: "api's 503",
			fault: func() {
				lag.exchange.refuse(&sidecar.SidecarApiError{Route: "POST /oauth/token", Status: http.StatusServiceUnavailable})
			},
			clear: func() { lag.exchange.refuse(nil) },
			took:  exchangeRetried,
		},
	} {
		requestsBefore := lag.gkm.requestCount()
		case_.fault()
		key, err, took := lag.ensureWritable()
		case_.clear()
		if err != nil || key.Generation() != 1 {
			t.Errorf("%s: the write did not go on from the keychain: %v", case_.name, err)
		}
		if took != case_.took {
			t.Errorf("%s: the write took %s of the clock, want %s", case_.name, took, case_.took)
		}
		if asked := requestsBefore < lag.gkm.requestCount(); asked != case_.gkmAsk {
			t.Errorf("%s: the write asked gkm: %t", case_.name, asked)
		}
	}

	lag.store.setDown(true)
	lag.revoke(lag.x)
	lag.stateFor()
	if key, err, _ := lag.ensureWritable(); key != nil || !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("a write past a removal with gkm unreachable: %v", err)
	}
	lag.store.setDown(false)
	if lag.store.callCount("ClaimGeneration") != 0 || lag.store.newestGeneration(lag.groupId) != 1 {
		t.Errorf("gkm's store took %d claims and holds generation %d", lag.store.callCount("ClaimGeneration"), lag.store.newestGeneration(lag.groupId))
	}
	if len(agent.alarms) != 0 {
		t.Errorf("gkm's absence alarmed: %+v", agent.alarms[0])
	}
}

// KF7's deposits on GkmApi: a depositor that holds generation 2's GenRotate seals to its drop key while the token
// keeper cannot have a token for now, api's 503 asked again ExchangeRetryCount times; once the exchange refuses it for
// good, invalid_grant, the deposit ends with that after one ask and answers no drop key, where the code before
// answered generation 2's from what the depositor held.
func TestADepositEndsAtATokenRefusedForGood(t *testing.T) {
	world, depositor := newGkmDropWorld(t)
	if dropKey, err := depositor.client.DropKey(world.ctx, world.repoId); err != nil || dropKey.Generation != 2 {
		t.Fatalf("the first deposit: %v", err)
	}
	lag := newGkmGrantLagWorld(world, depositor)
	lag.setScopes(sidecar.GkmScopeRoleDeposit)
	dropKey := func() (*sidecar.GkmDropKey, error, time.Duration) {
		var key *sidecar.GkmDropKey
		err, took := lag.drive(func() error {
			var err error
			key, err = depositor.client.DropKey(lag.ctx, lag.repoId)
			return err
		})
		return key, err, took
	}

	lag.exchange.refuse(&sidecar.SidecarApiError{Route: "POST /oauth/token", Status: http.StatusServiceUnavailable})
	key, err, took := dropKey()
	if err != nil || key.Generation != 2 {
		t.Errorf("a deposit while api answers 503: %v", err)
	}
	if want := time.Duration(lag.apiSettings.ExchangeRetryCount) * lag.apiSettings.ReadRetryWait; took != want {
		t.Errorf("the deposit took %s of the clock, want %s", took, want)
	}

	refusal := gkmTokenRefusalInvalidGrant()
	lag.exchange.refuse(refusal)
	asksBefore := lag.exchange.count(depositor.id)
	requestsBefore := lag.gkm.requestCount()
	key, err, took = dropKey()
	if key != nil || !errors.Is(err, refusal) || took != 0 {
		t.Errorf("a deposit the exchange refuses for good: %v after %s, answering a drop key: %t", err, took, key != nil)
	}
	if asks := lag.exchange.count(depositor.id) - asksBefore; asks != 1 {
		t.Errorf("the deposit asked the exchange %d times", asks)
	}
	if requests := lag.gkm.requestCount() - requestsBefore; requests != 0 {
		t.Errorf("a deposit with no token reached gkm %d times", requests)
	}
}

// A sync's late answers stop at the first token refused for good, as they stop at gkm unreachable: a writer owing three
// joiners a LATE delivery of generation 1, whose exchange refuses invalid_grant from the first joiner's ReaderKey read
// on, asks it once and goes on to no other joiner, so the sync ends with the refusal, no delivery stored, where going
// on would ask the exchange again for each joiner, and ride QD-1230's window out for each where the refusal is the
// repo scope's invalid_scope. The code before stopped there too, reading the refusal as gkm unreachable; this holds it
// now that it is not.
func TestASyncsLateAnswersStopAtATokenRefusedForGood(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	writer := world.admitAgent("writer", true)
	for _, label := range []string{"joiner-1", "joiner-2", "joiner-3"} {
		world.admitAgent(label, false)
	}
	world.stateFor()
	world.hold(writer.gkmWorldDevice, world.gen1)
	lag := newGkmGrantLagWorld(world, writer)
	lag.setScopes(sidecar.GkmScopeRoleWrite)
	refusal := gkmTokenRefusalInvalidGrant()
	asksBefore := -1
	lag.groupApi.hook("ReaderKey", func() {
		asksBefore = lag.exchange.count(writer.id)
		lag.exchange.refuse(refusal)
	})

	err, _ := lag.drive(func() error {
		return writer.client.SyncRepo(lag.ctx, lag.repoId)
	})
	if !errors.Is(err, refusal) {
		t.Fatalf("a sync whose late answers met the exchange's refusal ended with %v", err)
	}
	if asksBefore < 0 {
		t.Fatal("the sync read no joiner's ReaderKey")
	}
	if asks := lag.exchange.count(writer.id) - asksBefore; asks != 1 {
		t.Errorf("the sync asked the exchange %d times after its refusal", asks)
	}
	if recipients := lag.deliveryRecipients(1); 0 < len(recipients) {
		t.Errorf("gkm holds deliveries of generation 1: %v", recipients)
	}

	// the three were owed: once the exchange grants again, the next sync answers each
	lag.exchange.refuse(nil)
	if err, _ := lag.drive(func() error { return writer.client.SyncRepo(lag.ctx, lag.repoId) }); err != nil {
		t.Fatalf("the sync once the exchange grants again: %v", err)
	}
	recipients := lag.deliveryRecipients(1)
	for _, label := range []string{"joiner-1", "joiner-2", "joiner-3"} {
		if kind, ok := recipients["s:"+label]; !ok || kind != sidecar.GkmDeliveryLate {
			t.Errorf("gkm holds no LATE delivery of generation 1 to %s: %v", label, recipients)
		}
	}
}
