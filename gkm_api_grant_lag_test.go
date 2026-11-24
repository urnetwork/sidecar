// GkmApi riding out api's gate lag on a new grant (QD-1230), and its reading of the token keeper's other refusals, on
// a fake gkm and a fake token exchange whose grants come from a state of api's gate a test moves on the clock, so these
// run on every leg, the sidecar_http page Worker's included. sidecar_test's gkm_grant_lag_test.go holds the same over
// the group flows, a new writer's rotation inside EnsureWritable among them.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One exchange the fake took: when, the scopes asked, and the scopes it granted or its refusal.
type gkmGrantLagExchangeRecord struct {
	at      time.Time
	scopes  []string
	granted []string
	err     error
}

// A token exchange behind api's gate, as QD-1230's case has it: each repo scope asked is granted where the gate's
// state gives the client that role or a stronger one on the repo, and a request none of whose scopes it grants is
// refused invalid_scope, as server/oauth's exchange answers. The gate's state changes at a time on the clock a test
// sets, as a grant reaching api's gate late does. Each token it mints is kept with the scopes it granted, which the fake
// gkm reads off the bearer. Safe for concurrent use.
type gkmGrantLagExchange struct {
	clock *gkmTestClock

	stateLock sync.Mutex
	// the role api's gate gives the client on each repo, "" for none
	repoIdRoles map[Id]string
	// the roles the gate gives from dueAt on, set where a test has a grant reach it later
	dueRepoIdRoles map[Id]string
	dueAt          time.Time
	// what the exchange answers in place of a token, refusalCount more times, a keeper's refusal or api's
	refusal      error
	refusalCount int
	tokenScopes  map[string][]string
	exchanges    []*gkmGrantLagExchangeRecord
}

func newGkmGrantLagExchange(clock *gkmTestClock) *gkmGrantLagExchange {
	return &gkmGrantLagExchange{
		clock:       clock,
		repoIdRoles: map[Id]string{},
		tokenScopes: map[string][]string{},
	}
}

// api's gate gives the client role on repoId now, "" for none.
func (self *gkmGrantLagExchange) setRole(repoId Id, role string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.repoIdRoles[repoId] = role
}

// api's gate gives the client role on repoId from lag on.
func (self *gkmGrantLagExchange) setRoleAfter(repoId Id, role string, lag time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dueRepoIdRoles = map[Id]string{repoId: role}
	self.dueAt = self.clock.Now().Add(lag)
}

// The exchange answers err in place of a token count times.
func (self *gkmGrantLagExchange) refuse(err error, count int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refusal, self.refusalCount = err, count
}

// Sidecar.GrantedServiceToken's shape over the gate's state at the clock's now.
func (self *gkmGrantLagExchange) grantedServiceToken(ctx context.Context, resource string, scopes []string) (string, []string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	record := &gkmGrantLagExchangeRecord{at: now, scopes: slices.Sorted(slices.Values(scopes))}
	self.exchanges = append(self.exchanges, record)
	if 0 < self.refusalCount {
		self.refusalCount -= 1
		record.err = self.refusal
		return "", nil, self.refusal
	}
	if !self.dueAt.IsZero() && !now.Before(self.dueAt) {
		for repoId, role := range self.dueRepoIdRoles {
			self.repoIdRoles[repoId] = role
		}
		self.dueRepoIdRoles, self.dueAt = nil, time.Time{}
	}
	granted := []string{}
	for _, scope := range record.scopes {
		rest, found := strings.CutPrefix(scope, sidecarExchangeRepoScopePrefix)
		if !found {
			continue
		}
		repoText, role, found := strings.Cut(rest, ":")
		repoId, err := ParseId(repoText)
		if found && err == nil && gkmRoleCovers(self.repoIdRoles[repoId], role) {
			granted = append(granted, scope)
		}
	}
	if len(granted) == 0 {
		record.err = &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusBadRequest, Code: sidecarExchangeCodeInvalidScope}
		return "", nil, record.err
	}
	record.granted = granted
	token := fmt.Sprintf("synthetic-grant-lag-token-%d", len(self.exchanges))
	self.tokenScopes[token] = granted
	return token, slices.Clone(granted), nil
}

// The scopes a token carries, nil for one the exchange never minted.
func (self *gkmGrantLagExchange) scopesOf(token string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.tokenScopes[token]
}

// Every exchange that asked for scopes exactly, in order.
func (self *gkmGrantLagExchange) asked(scopes ...string) []*gkmGrantLagExchangeRecord {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	asked := []*gkmGrantLagExchangeRecord{}
	for _, record := range self.exchanges {
		if slices.Equal(record.scopes, slices.Sorted(slices.Values(scopes))) {
			asked = append(asked, record)
		}
	}
	return asked
}

// How many exchanges the fake took.
func (self *gkmGrantLagExchange) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.exchanges)
}

// gkm's guard over its newest state, as gkmTestGuard's, reading the scopes a bearer carries off the exchange that
// minted it: the strongest right the token holds on the route's repo of those its row takes, with each weaker right
// of its role the row takes, honored only whole, else 403; a token the exchange never minted 401; a route on no repo
// honored under any r, rw or admin scope.
func gkmGrantLagServe(guard *gkmTestGuard, exchange *gkmGrantLagExchange) func(request *gkmTestRequest) (int, http.Header, []byte) {
	return func(request *gkmTestRequest) (int, http.Header, []byte) {
		scopes := exchange.scopesOf(request.token)
		if scopes == nil {
			return http.StatusUnauthorized, nil, nil
		}
		rowRights, repoId, onRepo := guard.routeOf(request)
		if !onRepo {
			if slices.ContainsFunc(scopes, func(scope string) bool { return !strings.HasSuffix(scope, ":"+GkmScopeRoleDeposit) }) {
				return http.StatusOK, nil, nil
			}
			return http.StatusForbidden, nil, nil
		}
		held := AclEvsRights(0)
		for _, scope := range scopes {
			if role, found := strings.CutPrefix(scope, sidecarExchangeRepoScopePrefix+repoId.String()+":"); found {
				held |= gkmTestRoleRights(role)
			}
		}
		right := AclEvsRights(0)
		for _, candidate := range []AclEvsRights{AclEvsAdmin, AclEvsWrite, AclEvsRead, AclEvsDeposit} {
			if (held & rowRights).Has(candidate) {
				right = candidate
				break
			}
		}
		if right == 0 {
			return http.StatusForbidden, nil, nil
		}
		asked := right
		switch right {
		case AclEvsAdmin:
			asked |= (AclEvsWrite | AclEvsRead) & rowRights
		case AclEvsWrite:
			asked |= AclEvsRead & rowRights
		}
		guard.stateLock.Lock()
		stateRights := gkmTestRoleRights(guard.repoIdRoles[repoId])
		guard.stateLock.Unlock()
		if !stateRights.Has(asked) {
			return http.StatusForbidden, nil, nil
		}
		return http.StatusOK, nil, nil
	}
}

// The world of one client: its GkmApi on the fake exchange and the fake gkm guarding gkm's state, its repo repoId and
// a group of it, and another repo its state gives r on, which api's gate gives too, so its batch is two scopes as a
// device's config scope and a repo's make one.
type gkmGrantLagApiWorld struct {
	clock    *gkmTestClock
	exchange *gkmGrantLagExchange
	guard    *gkmTestGuard
	gkm      *gkmTestTransport
	api      *GkmApi
	repoId   Id
	otherId  Id
	groupId  Id
}

// A client whose state gives clientRole on the repo and r on the other, under settings, nil for the defaults, with gkm's
// state giving gkmRole on the repo and api's gate apiRole now.
func newGkmGrantLagApiWorld(t *testing.T, clientRole string, gkmRole string, apiRole string, settings *GkmSettings) *gkmGrantLagApiWorld {
	t.Helper()
	clock := newGkmTestClock()
	world := &gkmGrantLagApiWorld{
		clock:    clock,
		exchange: newGkmGrantLagExchange(clock),
		guard:    newGkmTestGuard(nil),
		gkm:      &gkmTestTransport{},
		repoId:   NewId(),
		otherId:  NewId(),
	}
	world.gkm.serve = gkmGrantLagServe(world.guard, world.exchange)
	world.groupId = world.guard.newGroup(world.repoId)
	world.guard.setRole(world.repoId, gkmRole)
	world.guard.setRole(world.otherId, GkmScopeRoleRead)
	world.exchange.setRole(world.repoId, apiRole)
	world.exchange.setRole(world.otherId, GkmScopeRoleRead)
	api, err := NewGkmApi(&GkmApiArgs{
		GkmUrl:              "https://gkm.example",
		Transport:           world.gkm,
		GrantedServiceToken: world.exchange.grantedServiceToken,
		Settings:            settings,
		Clock:               clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	api.SetRepoScopes([]GkmRepoScope{{RepoId: world.repoId, Role: clientRole}, {RepoId: world.otherId, Role: GkmScopeRoleRead}})
	world.api = api
	return world
}

// The repo's scope at role, as a call asks for it alone.
func (self *gkmGrantLagApiWorld) scope(role string) string {
	return GkmRepoScope{RepoId: self.repoId, Role: role}.scope()
}

// The client's batch: the repo at role, and the other at r.
func (self *gkmGrantLagApiWorld) batch(role string) []string {
	return slices.Sorted(slices.Values([]string{self.scope(role), GkmRepoScope{RepoId: self.otherId, Role: GkmScopeRoleRead}.scope()}))
}

// A claim of generation 2 of the repo's group, as a rotation sends it.
func (self *gkmGrantLagApiWorld) claim(ctx context.Context) error {
	return self.api.ClaimGeneration(ctx, self.repoId, self.groupId, 2, &bridge.Signed{Body: []byte("a rotation's GenRotate"), Signature: []byte("its signature")})
}

// Runs call on its own goroutine, moving the clock past each wait it arms, and answers its error and the waits.
func (self *gkmGrantLagApiWorld) run(call func(ctx context.Context) error) (error, []time.Duration) {
	done := make(chan error, 1)
	go func() {
		done <- call(context.Background())
	}()
	waits := []time.Duration{}
	for {
		select {
		case err := <-done:
			return err, waits
		case wait := <-self.clock.armed:
			waits = append(waits, wait)
			self.clock.Advance(wait)
		}
	}
}

// The times of exchanges after start, as offsets.
func gkmGrantLagOffsets(records []*gkmGrantLagExchangeRecord, start time.Time) []time.Duration {
	offsets := []time.Duration{}
	for _, record := range records {
		offsets = append(offsets, record.at.Sub(start))
	}
	return offsets
}

// Repeated durations, for a want.
func gkmGrantLagRepeat(duration time.Duration, count int) []time.Duration {
	durations := []time.Duration{}
	for range count {
		durations = append(durations, duration)
	}
	return durations
}

// QD-1230's case at the claim of a new writer's rotation: the client's state just gave it rw, gkm's gate holds the grant
// and api's gate takes it 2.5 s late. The batch's token comes back granting the other repo's scope alone, leaving the
// repo's rw out, and gkm refuses the claim 403 under it. The claim goes again under the repo's rw scope alone, whose
// exchange is refused invalid_scope at 0, 1 and 2 s, ReadRetryWait apart, and granted at 3 s, once the gate holds the
// grant; gkm takes the claim under it, with the same bytes, and nothing goes a third time. The code before ended the
// claim at gkm's first 403, since the batch carried the role the claim needs.
func TestGkmApiRidesOutANewWritersGrantApisGateLagsAtItsClaim(t *testing.T) {
	world := newGkmGrantLagApiWorld(t, GkmScopeRoleWrite, GkmScopeRoleWrite, GkmScopeRoleRead, nil)
	start := world.clock.Now()
	world.exchange.setRoleAfter(world.repoId, GkmScopeRoleWrite, 2500*time.Millisecond)

	err, waits := world.run(world.claim)
	if err != nil {
		t.Fatalf("the claim: %v", err)
	}
	batch := world.exchange.asked(world.batch(GkmScopeRoleWrite)...)
	if len(batch) != 1 {
		t.Fatalf("the batch was asked %d times", len(batch))
	}
	if !slices.Equal(batch[0].granted, []string{GkmRepoScope{RepoId: world.otherId, Role: GkmScopeRoleRead}.scope()}) {
		t.Errorf("the batch's token granted %v", batch[0].granted)
	}
	alone := world.exchange.asked(world.scope(GkmScopeRoleWrite))
	if offsets := gkmGrantLagOffsets(alone, start); !slices.Equal(offsets, []time.Duration{0, time.Second, 2 * time.Second, 3 * time.Second}) {
		t.Errorf("the rw scope alone was asked at %v", offsets)
	}
	for index, record := range alone {
		refused := sidecarServiceTokenRefusalOf(record.err).scopeRefused
		if index < len(alone)-1 && !refused || index == len(alone)-1 && record.granted == nil {
			t.Errorf("the ask at +%s answered %v, granting %v", record.at.Sub(start), record.err, record.granted)
		}
	}
	if !slices.Equal(waits, gkmGrantLagRepeat(time.Second, 3)) {
		t.Errorf("the claim waited %v", waits)
	}
	requests := world.gkm.taken()
	if len(requests) != 2 {
		t.Fatalf("gkm took %d requests, want the batch's and the rw scope's", len(requests))
	}
	if !bytes.Equal(requests[0].body, requests[1].body) || len(requests[0].body) == 0 {
		t.Error("the claim did not go again with its same bytes")
	}
	if scopes := world.exchange.scopesOf(requests[1].token); !slices.Equal(scopes, []string{world.scope(GkmScopeRoleWrite)}) {
		t.Errorf("gkm took the claim under %v", scopes)
	}
}

// A grant that never reaches api's gate: the claim's rw scope alone is refused invalid_scope at 0 to 5 s, six asks
// ReadRetryWait apart, the last at the window's end, and the claim then ends with that refusal, which carries
// errGkmNoServiceToken, gkm having taken only the batch's request. A 2.5 s window asks at 0, 1, 2 and 2.5 s, its last
// wait the half second left. A window of none ends at the first refusal of the scope alone.
func TestGkmApiEndsAGrantApisGateNeverHoldsAfterTheWindow(t *testing.T) {
	for _, c := range []struct {
		window  time.Duration
		offsets []time.Duration
		waits   []time.Duration
	}{
		{window: 5 * time.Second, offsets: []time.Duration{0, time.Second, 2 * time.Second, 3 * time.Second, 4 * time.Second, 5 * time.Second}, waits: gkmGrantLagRepeat(time.Second, 5)},
		{window: 2500 * time.Millisecond, offsets: []time.Duration{0, time.Second, 2 * time.Second, 2500 * time.Millisecond}, waits: []time.Duration{time.Second, time.Second, 500 * time.Millisecond}},
		{window: 0, offsets: []time.Duration{0}, waits: []time.Duration{}},
	} {
		settings := DefaultGkmSettings()
		settings.ExchangeScopeWaitTimeout = c.window
		world := newGkmGrantLagApiWorld(t, GkmScopeRoleWrite, GkmScopeRoleWrite, GkmScopeRoleRead, settings)
		start := world.clock.Now()

		err, waits := world.run(world.claim)
		var apiError *SidecarApiError
		if !errors.As(err, &apiError) || apiError.Code != sidecarExchangeCodeInvalidScope || !errors.Is(err, errGkmNoServiceToken) {
			t.Errorf("window %s: the claim ended with %v, not the exchange's invalid_scope", c.window, err)
		}
		alone := world.exchange.asked(world.scope(GkmScopeRoleWrite))
		if offsets := gkmGrantLagOffsets(alone, start); !slices.Equal(offsets, c.offsets) {
			t.Errorf("window %s: the rw scope alone was asked at %v, want %v", c.window, offsets, c.offsets)
		}
		if !slices.Equal(waits, c.waits) {
			t.Errorf("window %s: the claim waited %v, want %v", c.window, waits, c.waits)
		}
		if count := len(world.gkm.taken()); count != 1 {
			t.Errorf("window %s: gkm took %d requests, want the batch's alone", c.window, count)
		}
	}
}

// A read of a reader granted the repo again just now, as a new holder's first deliveries read: its batch carries r,
// the call's own role, api's gate leaves it out for 2.5 s and gkm refuses the batch. The read goes again under the
// repo's r scope alone and rides the exchange's invalid_scope out until the grant reaches the gate. A batch the exchange
// grants nothing of, the other repo's scope refused too, goes to the scope alone the same way, its own invalid_scope
// not ridden out but taken as the batch leaving the call's scope out.
func TestGkmApiRidesOutANewReadersGrantUnderItsScopeAlone(t *testing.T) {
	for _, otherGranted := range []bool{true, false} {
		world := newGkmGrantLagApiWorld(t, GkmScopeRoleRead, GkmScopeRoleRead, "", nil)
		if !otherGranted {
			world.exchange.setRole(world.otherId, "")
		}
		start := world.clock.Now()
		world.exchange.setRoleAfter(world.repoId, GkmScopeRoleRead, 2500*time.Millisecond)

		err, waits := world.run(func(ctx context.Context) error {
			_, err := world.api.Generations(ctx, world.repoId, world.groupId, 1)
			return err
		})
		if err != nil {
			t.Fatalf("other granted %t: the read: %v", otherGranted, err)
		}
		alone := world.exchange.asked(world.scope(GkmScopeRoleRead))
		if offsets := gkmGrantLagOffsets(alone, start); !slices.Equal(offsets, []time.Duration{0, time.Second, 2 * time.Second, 3 * time.Second}) {
			t.Errorf("other granted %t: the r scope alone was asked at %v", otherGranted, offsets)
		}
		if !slices.Equal(waits, gkmGrantLagRepeat(time.Second, 3)) {
			t.Errorf("other granted %t: the read waited %v", otherGranted, waits)
		}
		wantRequests := 2
		if !otherGranted {
			// the batch's token was never minted, so gkm saw only the scope alone's
			wantRequests = 1
		}
		if count := len(world.gkm.taken()); count != wantRequests {
			t.Errorf("other granted %t: gkm took %d requests, want %d", otherGranted, count, wantRequests)
		}
	}
}

// A writer gkm's newest state has revoked while api's gate still grants its scopes, a revoked writer whose own state
// lags: the token carried the repo's rw, so gkm's 403 is gkm's own judgment, and the claim ends at once with it, one
// request and no wait. A read under the batch's rw goes once more at its own role, as QD-1179 has it, and is refused
// twice. With api's gate holding the revocation too, the rw scope alone is refused invalid_scope through the window,
// QD-1230's cost: a revoked writer's refusal comes up to the window later.
func TestGkmApiRefusesARevokedWriter(t *testing.T) {
	world := newGkmGrantLagApiWorld(t, GkmScopeRoleWrite, "", GkmScopeRoleWrite, nil)
	err, waits := world.run(world.claim)
	if !IsGkmStatus(err, http.StatusForbidden) || len(waits) != 0 || len(world.gkm.taken()) != 1 {
		t.Errorf("a claim gkm refuses under a token carrying rw: %v after %d requests and waits %v, want 403 after 1", err, len(world.gkm.taken()), waits)
	}
	err, waits = world.run(func(ctx context.Context) error {
		_, err := world.api.Generations(ctx, world.repoId, world.groupId, 1)
		return err
	})
	if !IsGkmStatus(err, http.StatusForbidden) || len(waits) != 0 || len(world.gkm.taken()) != 3 {
		t.Errorf("a read gkm refuses: %v after %d requests and waits %v, want 403 after 2 more", err, len(world.gkm.taken()), waits)
	}

	revoked := newGkmGrantLagApiWorld(t, GkmScopeRoleWrite, "", "", nil)
	start := revoked.clock.Now()
	err, waits = revoked.run(revoked.claim)
	var apiError *SidecarApiError
	if !errors.As(err, &apiError) || apiError.Code != sidecarExchangeCodeInvalidScope {
		t.Errorf("a claim api's gate refuses too: %v", err)
	}
	if offsets := gkmGrantLagOffsets(revoked.exchange.asked(revoked.scope(GkmScopeRoleWrite)), start); len(offsets) != 6 || offsets[5] != 5*time.Second || len(waits) != 5 {
		t.Errorf("a claim api's gate refuses too asked at %v and waited %v", offsets, waits)
	}
	if count := len(revoked.gkm.taken()); count != 1 {
		t.Errorf("gkm took %d requests of a writer api's gate refuses", count)
	}
}

// A role the client's state does not give is never ridden out: a creation, needing admin of a repo whose state gives rw,
// asks for the admin scope alone, and the exchange's invalid_scope ends it at once. A route on no repo, a ReaderKey's
// upload, whose batch the exchange grants nothing of, ends at once too, having no repo scope of its own.
func TestGkmApiRidesOutNothingTheClientsStateDoesNotGive(t *testing.T) {
	world := newGkmGrantLagApiWorld(t, GkmScopeRoleWrite, GkmScopeRoleWrite, GkmScopeRoleWrite, nil)
	world.guard.createRepoId = world.repoId
	err, waits := world.run(func(ctx context.Context) error {
		return world.api.CreateGroup(ctx, world.repoId, nil)
	})
	if !sidecarServiceTokenRefusalOf(err).scopeRefused || len(waits) != 0 || world.exchange.count() != 1 {
		t.Errorf("a creation the state gives no admin for: %v after %d exchanges and waits %v", err, world.exchange.count(), waits)
	}

	world.exchange.setRole(world.repoId, "")
	world.exchange.setRole(world.otherId, "")
	before := world.exchange.count()
	err, waits = world.run(func(ctx context.Context) error {
		return world.api.UploadReaderKey(ctx, &bridge.Signed{Body: []byte("a ReaderKey")})
	})
	if !sidecarServiceTokenRefusalOf(err).scopeRefused || len(waits) != 0 || world.exchange.count()-before != 1 {
		t.Errorf("a route on no repo the exchange grants nothing for: %v after %d exchanges and waits %v", err, world.exchange.count()-before, waits)
	}
	if count := len(world.gkm.taken()); count != 0 {
		t.Errorf("gkm took %d requests with no token", count)
	}
}

// The token keeper's refusals for good end a call at once, a write's as a read's: the exchange's invalid_grant, and no
// enrolled client to present a token for, each after one ask and no wait, carrying errGkmNoServiceToken, with nothing
// sent to gkm. The code before answered the same, which this holds.
func TestGkmApiEndsAtOnceOnATokenRefusalForGood(t *testing.T) {
	for _, refusal := range []error{
		&SidecarApiError{Route: "POST /oauth/token", Status: http.StatusBadRequest, Code: "invalid_grant"},
		ErrSidecarServiceTokenNoClient,
	} {
		world := newGkmGrantLagApiWorld(t, GkmScopeRoleWrite, GkmScopeRoleWrite, GkmScopeRoleWrite, nil)
		world.exchange.refuse(refusal, 10)
		err, waits := world.run(world.claim)
		if !errors.Is(err, refusal) || !errors.Is(err, errGkmNoServiceToken) || len(waits) != 0 || world.exchange.count() != 1 {
			t.Errorf("%v: the claim ended with %v after %d asks and waits %v, want it after 1", refusal, err, world.exchange.count(), waits)
		}
		if count := len(world.gkm.taken()); count != 0 {
			t.Errorf("%v: gkm took %d requests", refusal, count)
		}
	}
}

// A token keeper's failure that may change goes again within ExchangeRetryCount, a write's as a read's, since nothing
// reached gkm: a keychain still locked twice, then open, lands the claim on its third ask after two waits of
// ReadRetryWait; one that stays locked ends with ErrSidecarServiceTokenLocked after ExchangeRetryCount+1 asks; no api
// yet goes again alike; the exchange's 429 waits its retry_after; one asking past ReadRetryMaxWait ends at once; and
// its 503 naming no wait waits ReadRetryWait. The code before ended the call at the first of each.
func TestGkmApiAsksAgainAfterATokenFailureThatMayChange(t *testing.T) {
	cases := []struct {
		name    string
		refusal error
		count   int
		landed  bool
		waits   []time.Duration
	}{
		{name: "locked twice", refusal: ErrSidecarServiceTokenLocked, count: 2, landed: true, waits: gkmGrantLagRepeat(time.Second, 2)},
		{name: "locked", refusal: ErrSidecarServiceTokenLocked, count: 10, waits: gkmGrantLagRepeat(time.Second, 3)},
		{name: "no api", refusal: ErrSidecarServiceTokenNoApi, count: 1, landed: true, waits: gkmGrantLagRepeat(time.Second, 1)},
		{name: "429", refusal: &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusTooManyRequests, RetryAfterMs: 2000}, count: 1, landed: true, waits: []time.Duration{2 * time.Second}},
		{name: "429 past the bound", refusal: &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusTooManyRequests, RetryAfterMs: 60_000}, count: 1, waits: []time.Duration{}},
		{name: "503", refusal: &SidecarApiError{Route: "POST /oauth/token", Status: http.StatusServiceUnavailable}, count: 1, landed: true, waits: gkmGrantLagRepeat(time.Second, 1)},
	}
	for _, c := range cases {
		world := newGkmGrantLagApiWorld(t, GkmScopeRoleWrite, GkmScopeRoleWrite, GkmScopeRoleWrite, nil)
		world.exchange.refuse(c.refusal, c.count)
		err, waits := world.run(world.claim)
		switch {
		case c.landed && err != nil:
			t.Errorf("%s: the claim: %v", c.name, err)
		case !c.landed && (!errors.Is(err, c.refusal) || !errors.Is(err, errGkmNoServiceToken)):
			t.Errorf("%s: the claim ended with %v", c.name, err)
		}
		if !slices.Equal(waits, c.waits) {
			t.Errorf("%s: the claim waited %v, want %v", c.name, waits, c.waits)
		}
		wantAsks := len(c.waits) + 1
		if world.exchange.count() != wantAsks {
			t.Errorf("%s: %d asks, want %d", c.name, world.exchange.count(), wantAsks)
		}
		wantRequests := 0
		if c.landed {
			wantRequests = 1
		}
		if count := len(world.gkm.taken()); count != wantRequests {
			t.Errorf("%s: gkm took %d requests, want %d", c.name, count, wantRequests)
		}
	}
}

// A client built on ServiceToken alone, which names no grant, reads each token as granting every scope asked, so a 403
// to a batch carrying the call's own role goes once, as before QD-1230: nothing tells it the exchange left a scope out.
func TestGkmApiOnServiceTokenAloneTakesNoGrantLagRetry(t *testing.T) {
	clock := newGkmTestClock()
	exchange := newGkmGrantLagExchange(clock)
	guard := newGkmTestGuard(nil)
	gkm := &gkmTestTransport{serve: gkmGrantLagServe(guard, exchange)}
	repoId, otherId := NewId(), NewId()
	groupId := guard.newGroup(repoId)
	guard.setRole(repoId, GkmScopeRoleWrite)
	exchange.setRole(repoId, GkmScopeRoleRead)
	exchange.setRole(otherId, GkmScopeRoleRead)
	api, err := NewGkmApi(&GkmApiArgs{
		GkmUrl:    "https://gkm.example",
		Transport: gkm,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			token, _, err := exchange.grantedServiceToken(ctx, resource, scopes)
			return token, err
		},
		Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	api.SetRepoScopes([]GkmRepoScope{{RepoId: repoId, Role: GkmScopeRoleWrite}, {RepoId: otherId, Role: GkmScopeRoleRead}})
	err = api.ClaimGeneration(context.Background(), repoId, groupId, 2, &bridge.Signed{Body: []byte("a GenRotate")})
	if !IsGkmStatus(err, http.StatusForbidden) || len(gkm.taken()) != 1 || exchange.count() != 1 {
		t.Errorf("a claim on ServiceToken alone: %v after %d requests and %d asks", err, len(gkm.taken()), exchange.count())
	}
	if _, err := NewGkmApi(&GkmApiArgs{GkmUrl: "https://gkm.example", Transport: gkm}); !errors.Is(err, errInvalidSettings) {
		t.Errorf("a gkm api with no token keeper: %v", err)
	}
}

// Sidecar.GrantedServiceToken answers the scopes the exchange granted beside the token: every scope asked for a full
// grant, kept and answered again with the same scopes and no exchange; the subset a partial grant names, not kept, so
// the next ask exchanges again and, once the gate grants the rest, holds them all; and ServiceToken's refusals alike.
func TestGrantedServiceTokenAnswersTheGrantedScopes(t *testing.T) {
	settings := validSidecarSettings()
	settings.Clock = newTokenTestClock()
	sidecar := newSidecarBase(nil, settings)
	exchangeCount := 0
	partial := true
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			exchangeCount += 1
			granted := "repo:a:rw repo:b:r"
			if partial {
				granted = "repo:b:r"
			}
			return syntheticResponse(request, 200, fmt.Sprintf(`{"access_token":"synthetic-granted-token-%d","expires_in":900,"scope":%q}`, exchangeCount, granted), nil), nil
		},
	}
	api, err := newSidecarApi(settings, transport, testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(testByJwt)
	installTestDpopSigner(t, api)
	sidecar.sidecarApi = api
	ctx := context.Background()
	asked := []string{"repo:b:r", "repo:a:rw"}

	sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled})
	if _, _, err := sidecar.GrantedServiceToken(ctx, "https://gkm.example", asked); !errors.Is(err, ErrSidecarServiceTokenNoClient) {
		t.Errorf("with no enrolled client: %v", err)
	}
	sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 1})
	_, granted, err := sidecar.GrantedServiceToken(ctx, "https://gkm.example", asked)
	if err != nil || !slices.Equal(granted, []string{"repo:b:r"}) {
		t.Fatalf("a partial grant: %v, %v", granted, err)
	}
	partial = false
	token, granted, err := sidecar.GrantedServiceToken(ctx, "https://gkm.example", asked)
	if err != nil || exchangeCount != 2 || !slices.Equal(granted, []string{"repo:a:rw", "repo:b:r"}) {
		t.Fatalf("after a partial grant: %v after %d exchanges, %v", granted, exchangeCount, err)
	}
	again, granted, err := sidecar.GrantedServiceToken(ctx, "https://gkm.example", asked)
	if err != nil || again != token || exchangeCount != 2 || !slices.Equal(granted, []string{"repo:a:rw", "repo:b:r"}) {
		t.Errorf("a kept full grant: %v after %d exchanges, %v", granted, exchangeCount, err)
	}
	if plain, err := sidecar.ServiceToken(ctx, "https://gkm.example", asked); err != nil || plain != token {
		t.Errorf("ServiceToken answers the same token: %v", err)
	}
}
