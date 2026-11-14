package sidecar

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// A Clock a test moves. After arms a wait that fires only once Advance reaches it, and each armed wait is counted and
// its duration kept, so a test waits for the manager to reach its next wait with no sleep.
type tokenTestClock struct {
	stateLock sync.Mutex
	now       time.Time
	waits     []tokenTestWait
	timeouts  []time.Duration
	armed     *MonitorValue[int]
}

type tokenTestWait struct {
	at   time.Time
	fire chan time.Time
}

func newTokenTestClock() *tokenTestClock {
	return &tokenTestClock{now: sdkScheduleNow, armed: NewMonitorValue(0)}
}

func (self *tokenTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *tokenTestClock) After(timeout time.Duration) <-chan time.Time {
	fire := make(chan time.Time, 1)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.timeouts = append(self.timeouts, timeout)
		if timeout <= 0 {
			fire <- self.now
			return
		}
		self.waits = append(self.waits, tokenTestWait{at: self.now.Add(timeout), fire: fire})
	}()
	self.armed.Update(func(count int) int { return count + 1 })
	return fire
}

func (self *tokenTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	fire := self.After(timeout)
	stopped := make(chan struct{})
	go func() {
		select {
		case <-fire:
			function()
		case <-stopped:
		}
	}()
	once := sync.Once{}
	return func() bool {
		result := false
		once.Do(func() { close(stopped); result = true })
		return result
	}
}

// Moves the clock and fires every wait it reaches.
func (self *tokenTestClock) Advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(by)
	kept := self.waits[:0]
	for _, wait := range self.waits {
		if wait.at.After(self.now) {
			kept = append(kept, wait)
			continue
		}
		wait.fire <- self.now
	}
	self.waits = kept
}

// Waits until count waits have been armed, and answers the newest's duration. The real-time bound only stops a
// broken test from hanging.
func (self *tokenTestClock) awaitArmed(t *testing.T, count int) time.Duration {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		armed, changed := self.armed.Get()
		if count <= armed {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.timeouts[count-1]
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%d waits armed, want %d", armed, count)
		}
	}
}

// One manager on a scripted api, and what its callbacks saw.
type tokenTestFixture struct {
	clock     *tokenTestClock
	transport *scriptedApiTransport
	api       *SidecarApi
	manager   *sidecarTokenManager

	stateLock sync.Mutex
	order     []string
	persisted []string
	installed []string
	refused   []SidecarStateReason
	restores  int
	// signaled after each refusal or restore, for a test that waits on one
	events *MonitorValue[int]
}

// A fixture whose api holds byJwt and answers refreshes with answer. The manager is not started.
func newTokenTestFixture(t *testing.T, byJwt string, answer func(request *http.Request, body []byte) (*http.Response, error)) *tokenTestFixture {
	t.Helper()
	self := &tokenTestFixture{clock: newTokenTestClock(), events: NewMonitorValue(0)}
	self.transport = &scriptedApiTransport{answer: answer}
	self.api = newTestSidecarApi(t, self.transport)
	installTestDpopSigner(t, self.api)
	self.api.SetByJwt(byJwt)
	return self
}

func (self *tokenTestFixture) note(update func()) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		update()
	}()
	self.events.Update(func(count int) int { return count + 1 })
}

// Starts the manager for generation with the fixture's callbacks, stopped at the test's end.
func (self *tokenTestFixture) start(t *testing.T, generation int64, edit func(args *sidecarTokenManagerArgs)) {
	t.Helper()
	settings := DefaultSidecarSettings().TokenRefreshSettings
	args := &sidecarTokenManagerArgs{
		Api:        self.api,
		Settings:   settings,
		Clock:      self.clock,
		Generation: generation,
		Persist: func(byJwt string) error {
			self.note(func() {
				self.order = append(self.order, "persist")
				self.persisted = append(self.persisted, byJwt)
			})
			return nil
		},
		Install: func(byJwt string) {
			self.note(func() {
				// SidecarApi holds the token before connect's holders get it
				if self.api.currentByJwt() == byJwt {
					self.order = append(self.order, "install")
				} else {
					self.order = append(self.order, "install before the api")
				}
				self.installed = append(self.installed, byJwt)
			})
		},
		Refused: func(generation int64, reason SidecarStateReason) {
			self.note(func() { self.refused = append(self.refused, reason) })
		},
		Restore: func(ctx context.Context, install func(presentedByJwt string, byJwt string) error) error {
			self.note(func() { self.restores += 1 })
			return nil
		},
		RetryTimeout: func() time.Duration { return time.Minute },
	}
	if edit != nil {
		edit(args)
	}
	self.manager = newSidecarTokenManager(context.Background(), args)
	t.Cleanup(self.manager.closeAndWait)
}

// Waits until the callbacks have noted count events.
func (self *tokenTestFixture) awaitEvents(t *testing.T, count int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		events, changed := self.events.Get()
		if count <= events {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%d events, want %d", events, count)
		}
	}
}

// The refresh requests the api saw.
func (self *tokenTestFixture) refreshCount() int {
	self.transport.stateLock.Lock()
	defer self.transport.stateLock.Unlock()
	count := 0
	for _, request := range self.transport.requests {
		if request.URL.Path == "/auth/refresh" {
			count += 1
		}
	}
	return count
}

// An answer to refresh with a new token issued now on clock, and to nothing else.
func refreshAnswer(clock *tokenTestClock, jtiPrefix string) func(request *http.Request, body []byte) (*http.Response, error) {
	count := 0
	countLock := sync.Mutex{}
	return func(request *http.Request, body []byte) (*http.Response, error) {
		countLock.Lock()
		count += 1
		jti := fmt.Sprintf("%s-%d", jtiPrefix, count)
		countLock.Unlock()
		byJwt := testClientJwtAt(jti, clock.Now(), 7*24*time.Hour)
		return syntheticResponse(request, 200, `{"by_jwt":"`+byJwt+`"}`, nil), nil
	}
}

// A 7-day token issued now on the fixture's default clock.
func testInitialJwt() string {
	return testClientJwtAt("synthetic-initial", sdkScheduleNow, 7*24*time.Hour)
}

// The refresh waits for its token's drawn point, and not a second less, then installs what api answers.
func TestRefreshAtDrawnPoint(t *testing.T) {
	clock := newTokenTestClock()
	fixture := newTokenTestFixture(t, testInitialJwt(), refreshAnswer(clock, "refreshed"))
	fixture.clock = clock
	fixture.start(t, 1, nil)
	byJwt := testInitialJwt()
	settings := DefaultSidecarSettings().TokenRefreshSettings
	want := sidecarJwtRefreshTime(byJwt, sdkScheduleNow, sidecarJwtRefreshDraw(byJwt), settings).Sub(sdkScheduleNow)
	if timeout := clock.awaitArmed(t, 1); timeout != want {
		t.Fatalf("waits %v, want the drawn point at %v", timeout, want)
	}
	clock.Advance(want - time.Second)
	if count := fixture.refreshCount(); count != 0 {
		t.Fatalf("%d refreshes before the point", count)
	}
	clock.Advance(time.Second)
	fixture.awaitEvents(t, 2)
	clock.awaitArmed(t, 2)
	if fixture.refreshCount() != 1 || len(fixture.installed) != 1 || fixture.api.currentByJwt() != fixture.installed[0] {
		t.Fatalf("refreshes %d, installed %d", fixture.refreshCount(), len(fixture.installed))
	}
}

// A refreshed token whose point is already past waits the floor from the attempt, not zero, so no server-set
// lifetime makes a hot loop.
func TestFloorHoldsRetries(t *testing.T) {
	clock := newTokenTestClock()
	// each refresh answers a token issued a week ago, whose point has passed
	answer := func(request *http.Request, body []byte) (*http.Response, error) {
		byJwt := testClientJwtAt(fmt.Sprintf("stale-%d", clock.Now().UnixNano()), clock.Now().Add(-6*24*time.Hour), 7*24*time.Hour)
		return syntheticResponse(request, 200, `{"by_jwt":"`+byJwt+`"}`, nil), nil
	}
	fixture := newTokenTestFixture(t, testInitialJwt(), answer)
	fixture.clock = clock
	fixture.start(t, 1, nil)
	clock.awaitArmed(t, 1)
	fixture.manager.requestRefresh()
	fixture.awaitEvents(t, 2)
	if timeout := clock.awaitArmed(t, 2); timeout != 5*time.Minute {
		t.Fatalf("the next refresh waits %v, want the 5 min floor", timeout)
	}
	if fixture.refreshCount() != 1 {
		t.Fatalf("%d refreshes", fixture.refreshCount())
	}
}

// A request made while a refresh is in flight is honored when it returns, not dropped with an edge nobody waited on.
func TestRequestDuringRefreshNotLost(t *testing.T) {
	clock := newTokenTestClock()
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	refreshed := refreshAnswer(clock, "during")
	first := true
	firstLock := sync.Mutex{}
	answer := func(request *http.Request, body []byte) (*http.Response, error) {
		firstLock.Lock()
		hold := first
		first = false
		firstLock.Unlock()
		entered <- struct{}{}
		if hold {
			<-release
		}
		return refreshed(request, body)
	}
	fixture := newTokenTestFixture(t, testInitialJwt(), answer)
	fixture.clock = clock
	fixture.start(t, 1, nil)
	clock.awaitArmed(t, 1)
	fixture.manager.requestRefresh()
	<-entered
	fixture.manager.requestRefresh()
	close(release)
	<-entered
	fixture.awaitEvents(t, 4)
	if count := fixture.refreshCount(); count != 2 {
		t.Fatalf("%d refreshes, want the second request's too", count)
	}
}

// A refused refresh ends the generation and leaves the sidecar Unenrolled with its identity and keychain kept
// (D-CORE-8): never Revoked.
func TestRefusedRefreshKeepsIdentity(t *testing.T) {
	sidecar, _, _ := newIdentityTestSidecar(t)
	sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 1})
	sidecar.applyTransition(sidecarTransition{to: SidecarStateOnline, generation: 1})
	fixture := newTokenTestFixture(t, testInitialJwt(), func(request *http.Request, body []byte) (*http.Response, error) {
		return syntheticResponse(request, 401, `Not authorized.`, nil), nil
	})
	fixture.start(t, 1, func(args *sidecarTokenManagerArgs) {
		refused := args.Refused
		args.Refused = func(generation int64, reason SidecarStateReason) {
			sidecar.tokenRefused(generation, reason)
			refused(generation, reason)
		}
	})
	fixture.clock.awaitArmed(t, 1)
	fixture.manager.requestRefresh()
	fixture.awaitEvents(t, 1)
	status := testLifecycleOf(sidecar)
	if status.state != SidecarStateUnenrolled || status.reason != SidecarReasonRefused || fixture.refused[0] != SidecarReasonRefused {
		t.Fatalf("status %+v, refused %v", status, fixture.refused)
	}
	if sidecar.currentIdentity() == nil {
		t.Fatal("the identity went with the refusal")
	}
	if _, err := loadSidecarIdentity(sidecar.coreSecrets); err != nil {
		t.Fatalf("the keychain's identity: %v", err)
	}
	<-fixture.manager.done
	if len(fixture.persisted) != 0 {
		t.Fatal("a refused refresh persisted something")
	}
}

// connect's AuthorizationClosed for anything but unavailability asks for one refresh and nothing more: no refusal,
// no move.
func TestAuthorizationCloseOnlyRefreshes(t *testing.T) {
	clock := newTokenTestClock()
	fixture := newTokenTestFixture(t, testInitialJwt(), refreshAnswer(clock, "closed"))
	fixture.clock = clock
	fixture.start(t, 1, nil)
	clock.awaitArmed(t, 1)
	fixture.manager.authorizationClosed(false)
	fixture.awaitEvents(t, 2)
	if fixture.refreshCount() != 1 || len(fixture.refused) != 0 || len(fixture.installed) != 1 {
		t.Fatalf("refreshes %d, refused %v", fixture.refreshCount(), fixture.refused)
	}
}

// A close for unavailability is ignored: it asks for nothing.
func TestUnavailableCloseIgnored(t *testing.T) {
	fixture := newTokenTestFixture(t, testInitialJwt(), refreshAnswer(newTokenTestClock(), "ignored"))
	fixture.start(t, 1, nil)
	fixture.clock.awaitArmed(t, 1)
	fixture.manager.authorizationClosed(true)
	if requests := fixture.manager.requests.Value(); requests != 0 {
		t.Fatalf("%d refresh requests", requests)
	}
	if fixture.refreshCount() != 0 {
		t.Fatal("an unavailable close refreshed")
	}
}

// A token whose exp passed with no refresh ends the generation as expired, sending nothing.
func TestExpiredUnrefreshed(t *testing.T) {
	expired := testClientJwtAt("synthetic-expired", sdkScheduleNow.Add(-8*24*time.Hour), 7*24*time.Hour)
	fixture := newTokenTestFixture(t, expired, refreshAnswer(newTokenTestClock(), "late"))
	fixture.start(t, 1, nil)
	fixture.awaitEvents(t, 1)
	if len(fixture.refused) != 1 || fixture.refused[0] != SidecarReasonExpired || fixture.refreshCount() != 0 {
		t.Fatalf("refused %v, refreshes %d", fixture.refused, fixture.refreshCount())
	}
}

// §18.5: a 401 whose code is session_revoked reads as session_ended, a child's other refusal as parent_lost, and a
// 200 error object as a refusal.
func TestSessionRevokedIsSessionEnded(t *testing.T) {
	cases := []struct {
		status int
		body   string
		child  bool
		want   SidecarStateReason
	}{
		{status: 401, body: `{"error":"Session revoked.","code":"session_revoked"}`, want: SidecarReasonSessionEnded},
		{status: 401, body: `{"error":"Session revoked.","code":"session_revoked"}`, child: true, want: SidecarReasonSessionEnded},
		{status: 401, body: `Not authorized.`, child: true, want: SidecarReasonParentLost},
		{status: 200, body: `{"error":{"message":"Client does not exist"}}`, want: SidecarReasonRefused},
	}
	for _, c := range cases {
		fixture := newTokenTestFixture(t, testInitialJwt(), func(request *http.Request, body []byte) (*http.Response, error) {
			return syntheticResponse(request, c.status, c.body, nil), nil
		})
		fixture.start(t, 1, func(args *sidecarTokenManagerArgs) { args.Child = c.child })
		fixture.clock.awaitArmed(t, 1)
		fixture.manager.requestRefresh()
		fixture.awaitEvents(t, 1)
		if fixture.refused[0] != c.want {
			t.Errorf("%d %s child %t: %s, want %s", c.status, c.body, c.child, fixture.refused[0], c.want)
		}
	}
}

// restore_required is no refusal: the owner re-registers, and the refresh runs again and installs.
func TestRestoreRequiredRebindsNotUnenrolls(t *testing.T) {
	clock := newTokenTestClock()
	refreshed := refreshAnswer(clock, "restored")
	first := true
	answer := func(request *http.Request, body []byte) (*http.Response, error) {
		if first {
			first = false
			return syntheticResponse(request, 200, `{"error":{"message":"Re-register.","code":"restore_required"}}`, nil), nil
		}
		return refreshed(request, body)
	}
	fixture := newTokenTestFixture(t, testInitialJwt(), answer)
	fixture.clock = clock
	fixture.start(t, 1, nil)
	clock.awaitArmed(t, 1)
	fixture.manager.requestRefresh()
	fixture.awaitEvents(t, 3)
	if fixture.restores != 1 || fixture.refreshCount() != 2 || len(fixture.refused) != 0 || len(fixture.installed) != 1 {
		t.Fatalf("restores %d, refreshes %d, refused %v, installed %d", fixture.restores, fixture.refreshCount(), fixture.refused, len(fixture.installed))
	}
}

// An answer to refresh as server's: the presented token's network, client, device and sidecar_id claim, if it had one,
// kept, with a new jti and a 7-day lifetime issued now on clock; refresh never adds the claim (QD-040, QD-797).
func refreshKeepingClaim(clock *tokenTestClock) func(request *http.Request, body []byte) (*http.Response, error) {
	return func(request *http.Request, body []byte) (*http.Response, error) {
		presented := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		now := clock.Now()
		byJwt := testEditedJwt(presented, func(claims map[string]any) {
			claims["jti"] = NewId().String()
			claims["iat"] = now.Unix()
			claims["exp"] = now.Add(7 * 24 * time.Hour).Unix()
		})
		return syntheticResponse(request, 200, `{"by_jwt":"`+byJwt+`"}`, nil), nil
	}
}

// A token that names its sidecar keeps the claim through a refresh: the refreshed token names the same network,
// client and device, so it is installed, and the sidecar_id comes with it (QD-797).
func TestRefreshKeepsTheSidecarClaim(t *testing.T) {
	clock := newTokenTestClock()
	sidecarId := NewId()
	initial := testRemintJwt(testInitialJwt(), sidecarId)
	fixture := newTokenTestFixture(t, initial, refreshKeepingClaim(clock))
	fixture.clock = clock
	fixture.start(t, 1, nil)
	clock.awaitArmed(t, 1)
	fixture.manager.requestRefresh()
	fixture.awaitEvents(t, 2)
	if len(fixture.installed) != 1 || fixture.installed[0] == initial || fixture.api.currentByJwt() != fixture.installed[0] {
		t.Fatalf("installed %d", len(fixture.installed))
	}
	if claimed, ok := sidecarJwtSidecarId(fixture.installed[0]); !ok || claimed != sidecarId {
		t.Errorf("the refreshed token names sidecar %s", claimed)
	}
}

// restore_required's re-mint goes through the manager's install, and the refresh that follows presents it and installs
// against it at once: the token api re-minted with the sidecar_id is the one refreshed, never refused as a token
// changed under the refresh and waited out (QD-797).
func TestRestoreInstallsTheRemintThenRefreshesIt(t *testing.T) {
	clock := newTokenTestClock()
	sidecarId := NewId()
	refreshed := refreshKeepingClaim(clock)
	first := true
	answer := func(request *http.Request, body []byte) (*http.Response, error) {
		if first {
			first = false
			return syntheticResponse(request, 200, `{"error":{"message":"Re-register.","code":"restore_required"}}`, nil), nil
		}
		return refreshed(request, body)
	}
	fixture := newTokenTestFixture(t, testInitialJwt(), answer)
	fixture.clock = clock
	reminted := ""
	fixture.start(t, 1, func(args *sidecarTokenManagerArgs) {
		args.Restore = func(ctx context.Context, install func(presentedByJwt string, byJwt string) error) error {
			presented := fixture.api.currentByJwt()
			reminted = testRemintJwt(presented, sidecarId)
			err := install(presented, reminted)
			fixture.note(func() { fixture.restores += 1 })
			return err
		}
	})
	clock.awaitArmed(t, 1)
	fixture.manager.requestRefresh()
	// the re-mint's persist and install, the restore, the refresh's persist and install
	fixture.awaitEvents(t, 5)
	if fixture.restores != 1 || fixture.refreshCount() != 2 || len(fixture.installed) != 2 || fixture.installed[0] != reminted {
		t.Fatalf("restores %d, refreshes %d, installed %d", fixture.restores, fixture.refreshCount(), len(fixture.installed))
	}
	fixture.transport.stateLock.Lock()
	presented := fixture.transport.requests[1].Header.Get("Authorization")
	fixture.transport.stateLock.Unlock()
	if presented != "Bearer "+reminted {
		t.Error("the refresh after the restore did not present the re-mint")
	}
	if claimed, ok := sidecarJwtSidecarId(fixture.api.currentByJwt()); !ok || claimed != sidecarId {
		t.Errorf("the token held names sidecar %s", claimed)
	}
}

// restore_required's steps on a Sidecar: the newest binding goes to POST /sidecar/bind again, the token bind re-mints
// with the sidecar_id goes through the manager's install against the token the bind presented (QD-797), then each
// component's registrations.
func TestRestoreRegistrationsRepostsTheBinding(t *testing.T) {
	sidecar, _, _ := newIdentityTestSidecar(t)
	fields := testBindingFields()
	transport := bindAnswer(1, fields.SidecarId)
	sidecar.sidecarApi = newTestSidecarApi(t, transport)
	presented := testBindClientJwt(fields.NetworkId, fields.ClientId)
	sidecar.sidecarApi.SetByJwt(presented)
	installed := []string{}
	install := func(presentedByJwt string, byJwt string) error {
		if presentedByJwt != presented {
			return errors.New("installed against another token than the bind presented")
		}
		installed = append(installed, byJwt)
		return nil
	}
	reregistered := false
	restorer := sidecarRestorerFunc(func(ctx context.Context) error {
		if transport.requestCount() != 1 || len(installed) != 1 {
			return errors.New("a registration before the binding and its token")
		}
		reregistered = true
		return nil
	})
	if err := sidecar.restoreRegistrations(context.Background(), []SidecarRestorer{restorer}, install); err != nil {
		t.Fatal(err)
	}
	request, body := transport.onlyRequest(t)
	record, err := loadSidecarIdentity(sidecar.coreSecrets)
	if err != nil {
		t.Fatal(err)
	}
	record.keys.erase()
	want, _ := json.Marshal(map[string]string{"binding": base64.StdEncoding.EncodeToString(record.binding)})
	if request.URL.Path != "/sidecar/bind" || string(body) != string(want) || !reregistered {
		t.Fatalf("%s %s, reregistered %t", request.URL.Path, body, reregistered)
	}
	if claimed, ok := sidecarJwtSidecarId(installed[0]); !ok || claimed != fields.SidecarId {
		t.Errorf("the installed token names sidecar %s", claimed)
	}
}

// A restore whose re-mint names another sidecar than the identity's, whose install refuses, or that has no generation
// to install through installs nothing and re-registers nothing, so the token held stays, and the manager retries the
// whole restore (QD-797).
func TestRestoreRegistrationsInstallsNoOtherSidecarsToken(t *testing.T) {
	fields := testBindingFields()
	for _, c := range []struct {
		name      string
		sidecarId Id
		refuse    bool
		noInstall bool
	}{
		{name: "another sidecar", sidecarId: NewId()},
		{name: "an install refusing", sidecarId: fields.SidecarId, refuse: true},
		{name: "no generation", sidecarId: fields.SidecarId, noInstall: true},
	} {
		sidecar, _, _ := newIdentityTestSidecar(t)
		sidecar.sidecarApi = newTestSidecarApi(t, bindAnswer(1, c.sidecarId))
		presented := testBindClientJwt(fields.NetworkId, fields.ClientId)
		sidecar.sidecarApi.SetByJwt(presented)
		installed := 0
		install := func(presentedByJwt string, byJwt string) error {
			if c.refuse {
				return errors.New("synthetic refusal")
			}
			installed += 1
			return nil
		}
		if c.noInstall {
			install = nil
		}
		reregistered := false
		restorer := sidecarRestorerFunc(func(ctx context.Context) error {
			reregistered = true
			return nil
		})
		if err := sidecar.restoreRegistrations(context.Background(), []SidecarRestorer{restorer}, install); err == nil {
			t.Errorf("%s: restored", c.name)
		}
		if installed != 0 || reregistered || sidecar.sidecarApi.currentByJwt() != presented {
			t.Errorf("%s: installed %d, reregistered %t", c.name, installed, reregistered)
		}
	}
}

// Where a sidecar's machine stands, read under its lock (Status is CORE-M1-08's).
func testLifecycleOf(sidecar *Sidecar) sidecarLifecycle {
	sidecar.stateLock.Lock()
	defer sidecar.stateLock.Unlock()
	return sidecar.lifecycle
}

// A SidecarRestorer from a function.
type sidecarRestorerFunc func(ctx context.Context) error

func (self sidecarRestorerFunc) Reregister(ctx context.Context) error {
	return self(ctx)
}

// A refreshed token goes to the keychain first, then SidecarApi, then connect's holders through the install callback.
func TestRefreshInstallsAllThreeHolders(t *testing.T) {
	clock := newTokenTestClock()
	fixture := newTokenTestFixture(t, testInitialJwt(), refreshAnswer(clock, "holders"))
	fixture.clock = clock
	fixture.start(t, 1, nil)
	clock.awaitArmed(t, 1)
	fixture.manager.requestRefresh()
	fixture.awaitEvents(t, 2)
	if strings.Join(fixture.order, ",") != "persist,install" || fixture.persisted[0] != fixture.installed[0] {
		t.Fatalf("order %v", fixture.order)
	}
}

// A refresh whose token names another client or device is not installed.
func TestRefreshOfAnotherClientIsNotInstalled(t *testing.T) {
	answer := func(request *http.Request, body []byte) (*http.Response, error) {
		byJwt := testClientJwt(`{"jti":"other","client_id":"another-client","device_id":"synthetic-device"}`)
		return syntheticResponse(request, 200, `{"by_jwt":"`+byJwt+`"}`, nil), nil
	}
	fixture := newTokenTestFixture(t, testInitialJwt(), answer)
	fixture.start(t, 1, nil)
	fixture.clock.awaitArmed(t, 1)
	fixture.manager.requestRefresh()
	// the failure arms the retry wait
	if timeout := fixture.clock.awaitArmed(t, 2); timeout != time.Minute {
		t.Fatalf("waits %v, want the retry", timeout)
	}
	if len(fixture.persisted) != 0 || len(fixture.installed) != 0 || fixture.api.currentByJwt() != testInitialJwt() {
		t.Fatal("another client's token was installed")
	}
}

// An older generation's refusal is dropped by the state machine: a newer generation stays Online (D-SDK-14).
func TestOldGenerationRefusalDropped(t *testing.T) {
	sidecar, _, _ := newIdentityTestSidecar(t)
	sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 2})
	sidecar.applyTransition(sidecarTransition{to: SidecarStateOnline, generation: 2})
	sidecar.tokenRefused(1, SidecarReasonRefused)
	if status := testLifecycleOf(sidecar); status.state != SidecarStateOnline || status.generation != 2 {
		t.Fatalf("status %+v", status)
	}
}

// A service token goes only to its in-process caller: it is cached per audience and scope set within a generation,
// a new generation exchanges again, and no log line or error carries it (I-7).
func TestServiceTokenNeverLeavesProcess(t *testing.T) {
	log := &capturingApiLogger{}
	settings := validSidecarSettings()
	settings.Log = log
	clock := newTokenTestClock()
	settings.Clock = clock
	sidecar := newSidecarBase(nil, settings)
	exchangeCount := 0
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			exchangeCount += 1
			token := fmt.Sprintf("synthetic-service-token-%d", exchangeCount)
			return syntheticResponse(request, 200, `{"access_token":"`+token+`","expires_in":900,"scope":"repo:x:r"}`, nil), nil
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

	if _, err := sidecar.ServiceToken(ctx, "https://evs.example", nil); err == nil {
		t.Fatal("a locked sidecar handed out a token")
	}
	sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled})
	sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 1})

	first, err := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:b:r", "repo:a:r"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:a:r", "repo:b:r"})
	if err != nil || again != first || exchangeCount != 1 {
		t.Fatalf("the same audience and scopes exchanged again: %d", exchangeCount)
	}
	clock.Advance(10 * time.Minute)
	if expired, _ := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:a:r", "repo:b:r"}); expired == first || exchangeCount != 2 {
		t.Fatal("a token was kept past its stay")
	}
	sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 2})
	if newer, _ := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:a:r", "repo:b:r"}); exchangeCount != 3 || newer == first {
		t.Fatal("a new generation took the old one's token")
	}
	log.stateLock.Lock()
	defer log.stateLock.Unlock()
	for _, line := range log.lines {
		if strings.Contains(line, "synthetic-service-token") {
			t.Fatalf("a log line holds a service token: %s", line)
		}
	}
}

// The client's token round-trips through the core's keychain namespace, and an empty one is refused.
func TestByJwtPersistsInTheKeychain(t *testing.T) {
	_, secrets := newIdentityTestSecrets(t, testBindingFields().NetworkId)
	if _, err := loadSidecarByJwt(secrets); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Fatalf("before: %v", err)
	}
	if err := persistSidecarByJwt(secrets, ""); err == nil {
		t.Fatal("an empty token was kept")
	}
	if err := persistSidecarByJwt(secrets, testInitialJwt()); err != nil {
		t.Fatal(err)
	}
	if byJwt, err := loadSidecarByJwt(secrets); err != nil || byJwt != testInitialJwt() {
		t.Fatalf("%v", err)
	}
}
