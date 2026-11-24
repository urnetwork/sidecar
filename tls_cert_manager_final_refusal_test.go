//go:build !sidecar_http && !ios_extension && !js

// The certificate manager's background pass holds a name whose certs token was refused for good (tls_cert_manager.go's
// file comment): the exchange's invalid_grant or restore_required, or no enrolled client, met by the pass's own token
// or by the renewal after certs' 401, stops the pass's tries for that name until the device's state or its enrollment
// moves, while what may change, the exchange's 503 past the token's bound or certs' 401 to a renewed token, backs off
// and goes again as before. Each test but the last runs the manager as the Sidecar builds it, over
// tls_certs_401_refresh_test.go's renewal world: the keeper's own certs token, a scripted exchange and api's certs
// routes behind certs' guard.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// The renewal world's Sidecar with a tls component of its own (TlsForegroundComponentArgs) on the cert fixture's keys,
// store and settings, whose names carry the verified state's version the test sets and whose every ask of the
// manager's certs token, the renewal's included, is counted. Safe for concurrent use.
type tlsCertHoldWorld struct {
	t         *testing.T
	renew     *tlsCertsRenewWorld
	fixture   *tlsCertFixture
	component *TlsComponent

	tokenAskCount atomic.Int64
	pinVersion    atomic.Uint64
}

// A world whose certs issue each order at once when issueAtOnce, its component attached to a first generation and its
// loop parked on its resync timer after the attachment's pass, which finds nothing to order.
func newTlsCertHoldWorld(t *testing.T, issueAtOnce bool) *tlsCertHoldWorld {
	t.Helper()
	renew := newTlsCertsRenewWorld(t, issueAtOnce)
	fixture := renew.fixture
	self := &tlsCertHoldWorld{t: t, renew: renew, fixture: fixture}
	args, err := renew.world.sidecar.TlsForegroundComponentArgs()
	if err != nil {
		t.Fatal(err)
	}
	serviceToken := args.Manager.ServiceToken
	args.Manager.ServiceToken = func(ctx context.Context, resource string, scopes []string) (string, error) {
		self.tokenAskCount.Add(1)
		return serviceToken(ctx, resource, scopes)
	}
	args.Manager.NetworkId = fixture.networkId
	args.Manager.SidecarId = fixture.sidecarId
	args.Manager.Settings = fixture.settings
	args.Manager.Keys = fixture.keys
	args.Manager.Sign = testTlsSign(fixture.identity, fixture.sidecarId[:])
	args.Manager.Names = self.names
	args.Manager.Store = fixture.store
	args.Manager.Clock = fixture.clock
	args.Manager.Log = NewNoopLogger()
	component, err := NewTlsComponent(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(component.Close)
	self.component = component
	self.attach()
	return self
}

// The fixture's names, read at the verified state's version the test set.
func (self *tlsCertHoldWorld) names(ctx context.Context) (*TlsCertNames, error) {
	names, err := self.fixture.names(ctx)
	if err != nil {
		return nil, err
	}
	names.PinVersion = self.pinVersion.Load()
	return names, nil
}

// Attaches a client generation on the world's api, as each generation's start does, and waits out the pass the
// attachment asks for, until the loop is parked on its resync timer.
func (self *tlsCertHoldWorld) attach() {
	self.t.Helper()
	env := &SidecarEnv{
		Ctx:        self.t.Context(),
		SidecarApi: self.renew.world.sidecar.sidecarApi,
		Identity:   &SidecarIdentity{NetworkId: self.fixture.networkId, SidecarId: self.fixture.sidecarId},
		Log:        NewNoopLogger(),
	}
	if err := self.component.Attach(env); err != nil {
		self.t.Fatal(err)
	}
	self.fixture.settleLoop()
}

func (self *tlsCertHoldWorld) manager() *TlsCertManager {
	return self.component.CertManager()
}

// One pass, driven by the test while the loop is parked.
func (self *tlsCertHoldWorld) sync() error {
	return self.manager().Sync(self.t.Context())
}

// api answers the next count exchanges with the exchange's refusal code at status, in place of a token.
func (self *tlsCertHoldWorld) refuseExchanges(count int, status int, code string) {
	for range count {
		self.renew.world.refuseExchange(status, fmt.Sprintf(`{"error":%q}`, code))
	}
}

// Moves the Sidecar's lifecycle, as its run loop would.
func (self *tlsCertHoldWorld) move(transition sidecarTransition) {
	self.t.Helper()
	if !self.renew.world.sidecar.applyTransition(transition) {
		self.t.Fatalf("the move to %s was refused", transition.to)
	}
}

// Passes past the longest backoff: one a CertRetryMinInterval on, the loop's own at its resync past a
// CertRetryMaxInterval more, and one after that. Answers their errors.
func (self *tlsCertHoldWorld) passPastTheBackoff() error {
	self.t.Helper()
	clock := self.fixture.clock
	clock.advance(self.fixture.settings.CertRetryMinInterval)
	firstErr := self.sync()
	clock.advance(self.fixture.settings.CertRetryMaxInterval)
	self.fixture.settleLoop()
	return errors.Join(firstErr, self.sync())
}

// What the world has taken: asks of the manager's certs token, exchanges api took, requests certs took behind its
// guard, and orders that reached its rows.
type tlsCertHoldCounts struct {
	tokenAsks     int64
	exchanges     int
	certsRequests int
	orders        int
}

func (self *tlsCertHoldWorld) counts() tlsCertHoldCounts {
	return tlsCertHoldCounts{
		tokenAsks:     self.tokenAskCount.Load(),
		exchanges:     self.renew.world.exchanges(),
		certsRequests: self.renew.world.requestCount(),
		orders:        self.fixture.api.orderCount(),
	}
}

// What was taken since before.
func (self tlsCertHoldCounts) since(before tlsCertHoldCounts) tlsCertHoldCounts {
	return tlsCertHoldCounts{
		tokenAsks:     self.tokenAsks - before.tokenAsks,
		exchanges:     self.exchanges - before.exchanges,
		certsRequests: self.certsRequests - before.certsRequests,
		orders:        self.orders - before.orders,
	}
}

// A name whose order meets a certs token refused for good is held: the exchange's invalid_grant or restore_required,
// no enrolled client, and the invalid_grant the renewal after certs' 401 meets each end the pass's order for a custom
// host with that refusal, nothing reaching certs' rows, and no pass after asks for the name again, neither one a
// minute on nor the loop's own at its resync past the longest backoff nor one after it: the keeper and the exchange
// are asked nothing more. The code before tried the name again at each backoff, from CertRetryMinInterval doubling to
// CertRetryMaxInterval, each try asking the keeper and api's exchange.
func TestTlsCertManagerHoldsANameWhoseTokenIsRefusedForGood(t *testing.T) {
	cases := []struct {
		name string
		// makes the refusal, the keeper holding no certs token before
		refuse func(world *tlsCertHoldWorld)
		// the exchange's code the pass ends with, or the keeper's refusal
		code    string
		refusal error
		// what the refused pass took
		taken tlsCertHoldCounts
	}{
		{
			name: "invalid_grant",
			refuse: func(world *tlsCertHoldWorld) {
				world.refuseExchanges(10, http.StatusBadRequest, "invalid_grant")
			},
			code:  "invalid_grant",
			taken: tlsCertHoldCounts{tokenAsks: 1, exchanges: 1},
		},
		{
			name: "restore_required",
			refuse: func(world *tlsCertHoldWorld) {
				world.refuseExchanges(10, http.StatusBadRequest, "restore_required")
			},
			code:  "restore_required",
			taken: tlsCertHoldCounts{tokenAsks: 1, exchanges: 1},
		},
		{
			name: "no enrolled client",
			refuse: func(world *tlsCertHoldWorld) {
				// the client's credential was refused: generation 1 ended for Unenrolled, its api not yet taken back
				world.move(sidecarTransition{to: SidecarStateUnenrolled, generation: 1})
			},
			refusal: ErrSidecarServiceTokenNoClient,
			taken:   tlsCertHoldCounts{tokenAsks: 1},
		},
		{
			name: "the renewal's invalid_grant",
			refuse: func(world *tlsCertHoldWorld) {
				// the keeper keeps a certs token certs no longer authenticates, and the exchange refuses the next
				if _, err := world.renew.world.sidecar.certsServiceToken(world.t.Context(), world.renew.resource(), nil); err != nil {
					world.t.Fatal(err)
				}
				world.renew.world.expireTokens()
				world.refuseExchanges(10, http.StatusBadRequest, "invalid_grant")
			},
			code:  "invalid_grant",
			taken: tlsCertHoldCounts{tokenAsks: 2, exchanges: 1, certsRequests: 1},
		},
	}
	for _, c := range cases {
		world := newTlsCertHoldWorld(t, true)
		world.fixture.setCustomHosts(tlsCertTestCustom)
		c.refuse(world)

		before := world.counts()
		err := world.sync()
		var apiErr *SidecarApiError
		switch {
		case !tlsCertTokenRefusedForGood(err):
			t.Errorf("%s: the pass ended with %v, no token refused for good", c.name, err)
		case c.code != "" && (!errors.As(err, &apiErr) || apiErr.Code != c.code):
			t.Errorf("%s: the pass ended with %v, want the exchange's %s", c.name, err, c.code)
		case c.refusal != nil && !errors.Is(err, c.refusal):
			t.Errorf("%s: the pass ended with %v, want %v", c.name, err, c.refusal)
		}
		if taken := world.counts().since(before); taken != c.taken {
			t.Errorf("%s: the refused pass took %+v, want %+v", c.name, taken, c.taken)
		}

		before = world.counts()
		if err := world.passPastTheBackoff(); err != nil {
			t.Errorf("%s: a pass with the name held: %v", c.name, err)
		}
		if taken := world.counts().since(before); taken != (tlsCertHoldCounts{}) {
			t.Errorf("%s: passes with the name held took %+v", c.name, taken)
		}
	}
}

// What may change backs off and goes again, as before the hold: the exchange's 503, which the token's own bound asks
// CertsExchangeRetryCount more times a CertsExchangeRetryWait apart before the order ends with it, and certs' 401 to
// the token the renewal minted, a voided subject's, which is certs' answer and no token refusal. A pass inside the
// backoff asks nothing, and the first past it asks again: the 503's order lands once the exchange grants, and the
// voided one meets certs' 401 again.
func TestTlsCertManagerBacksOffWhatMayChange(t *testing.T) {
	cases := []struct {
		name   string
		refuse func(world *tlsCertHoldWorld)
		// the token's waits the refused pass arms, each CertsExchangeRetryWait
		waitCount int
		// the refused pass's answer: its status, and whether a token that could not be had carries it
		status    int
		tokenless bool
		taken     tlsCertHoldCounts
		// what the pass past the backoff takes, and its answer's status, 0 for none
		againStatus int
		againTaken  tlsCertHoldCounts
	}{
		{
			name: "the exchange's 503",
			refuse: func(world *tlsCertHoldWorld) {
				world.refuseExchanges(DefaultSidecarTlsSettings().CertsExchangeRetryCount+1, http.StatusServiceUnavailable, "temporarily_unavailable")
			},
			waitCount:  DefaultSidecarTlsSettings().CertsExchangeRetryCount,
			status:     http.StatusServiceUnavailable,
			tokenless:  true,
			taken:      tlsCertHoldCounts{tokenAsks: 1, exchanges: DefaultSidecarTlsSettings().CertsExchangeRetryCount + 1},
			againTaken: tlsCertHoldCounts{tokenAsks: 1, exchanges: 1, certsRequests: 1, orders: 1},
		},
		{
			name: "certs' 401 to the renewed token",
			refuse: func(world *tlsCertHoldWorld) {
				world.renew.world.void()
			},
			status:      http.StatusUnauthorized,
			taken:       tlsCertHoldCounts{tokenAsks: 2, exchanges: 2, certsRequests: 2},
			againStatus: http.StatusUnauthorized,
			againTaken:  tlsCertHoldCounts{tokenAsks: 2, exchanges: 1, certsRequests: 2},
		},
	}
	for _, c := range cases {
		world := newTlsCertHoldWorld(t, true)
		settings := world.fixture.settings
		clock := world.fixture.clock
		world.fixture.setCustomHosts(tlsCertTestCustom)
		c.refuse(world)

		before := world.counts()
		passDone := make(chan error, 1)
		go func() {
			passDone <- world.sync()
		}()
		for range c.waitCount {
			clock.awaitTimer(t, DefaultSidecarTlsSettings().CertsExchangeRetryWait)
			clock.advance(DefaultSidecarTlsSettings().CertsExchangeRetryWait)
		}
		var err error
		select {
		case err = <-passDone:
		case <-time.After(30 * time.Second):
			// a guard against a broken test, never the proof
			t.Fatalf("%s: the refused pass did not end", c.name)
		}
		var apiErr *SidecarApiError
		if tlsCertTokenRefusedForGood(err) || errors.Is(err, errTlsCertNoServiceToken) != c.tokenless || !errors.As(err, &apiErr) || apiErr.Status != c.status {
			t.Errorf("%s: the pass ended with %v", c.name, err)
		}
		if taken := world.counts().since(before); taken != c.taken {
			t.Errorf("%s: the refused pass took %+v, want %+v", c.name, taken, c.taken)
		}

		// half the first backoff on, the waits included, nothing is asked
		before = world.counts()
		clock.advance(settings.CertRetryMinInterval / 2)
		if err := world.sync(); err != nil {
			t.Errorf("%s: a pass inside the backoff: %v", c.name, err)
		}
		if taken := world.counts().since(before); taken != (tlsCertHoldCounts{}) {
			t.Errorf("%s: a pass inside the backoff took %+v", c.name, taken)
		}

		before = world.counts()
		clock.advance(settings.CertRetryMinInterval / 2)
		err = world.sync()
		switch {
		case c.againStatus == 0 && err != nil:
			t.Errorf("%s: the pass past the backoff: %v", c.name, err)
		case c.againStatus != 0 && (!errors.As(err, &apiErr) || apiErr.Status != c.againStatus):
			t.Errorf("%s: the pass past the backoff ended with %v", c.name, err)
		}
		if taken := world.counts().since(before); taken != c.againTaken {
			t.Errorf("%s: the pass past the backoff took %+v, want %+v", c.name, taken, c.againTaken)
		}
	}
}

// A generation's start lets a held name go: a name held at the exchange's invalid_grant, asked nothing past the
// backoff, is asked again by the pass the next generation's attachment asks for, its order landing once the exchange
// grants; and a name held at no enrolled client, the client's credential refused, is asked again once the device
// enrolls generation 2 and its component attaches it, and lands.
func TestTlsCertManagerTriesAHeldNameAgainAtTheNextGeneration(t *testing.T) {
	cases := []struct {
		name   string
		refuse func(world *tlsCertHoldWorld)
		// what the device does before its next generation attaches, nil for nothing
		enroll func(world *tlsCertHoldWorld)
		// the attachment's pass's asks of the exchange
		exchanges int
	}{
		{
			name: "invalid_grant",
			refuse: func(world *tlsCertHoldWorld) {
				world.refuseExchanges(1, http.StatusBadRequest, "invalid_grant")
			},
			exchanges: 1,
		},
		{
			name: "no enrolled client",
			refuse: func(world *tlsCertHoldWorld) {
				world.move(sidecarTransition{to: SidecarStateUnenrolled, generation: 1})
			},
			enroll: func(world *tlsCertHoldWorld) {
				world.move(sidecarTransition{to: SidecarStateOffline, generation: 2})
			},
			exchanges: 1,
		},
	}
	for _, c := range cases {
		world := newTlsCertHoldWorld(t, true)
		world.fixture.setCustomHosts(tlsCertTestCustom)
		c.refuse(world)
		if err := world.sync(); !tlsCertTokenRefusedForGood(err) {
			t.Errorf("%s: the pass ended with %v, no token refused for good", c.name, err)
			continue
		}
		before := world.counts()
		if err := world.passPastTheBackoff(); err != nil {
			t.Errorf("%s: a pass with the name held: %v", c.name, err)
		}
		if taken := world.counts().since(before); taken != (tlsCertHoldCounts{}) {
			t.Errorf("%s: passes with the name held took %+v", c.name, taken)
		}

		if c.enroll != nil {
			c.enroll(world)
		}
		before = world.counts()
		world.attach()
		want := tlsCertHoldCounts{tokenAsks: 1, exchanges: c.exchanges, certsRequests: 1, orders: 1}
		if taken := world.counts().since(before); taken != want {
			t.Errorf("%s: the next generation's pass took %+v, want %+v", c.name, taken, want)
		}
	}
}

// The device's verified state moving lets a held name go: a name held at the exchange's invalid_grant while the names
// read version 7 is asked nothing by passes reading 7, past the backoff, and is asked again by the first pass whose
// names read 8, its order landing once the exchange grants.
func TestTlsCertManagerTriesAHeldNameAgainOnceTheDevicesStateMoves(t *testing.T) {
	world := newTlsCertHoldWorld(t, true)
	world.pinVersion.Store(7)
	world.fixture.setCustomHosts(tlsCertTestCustom)
	world.refuseExchanges(1, http.StatusBadRequest, "invalid_grant")
	if err := world.sync(); !tlsCertTokenRefusedForGood(err) {
		t.Fatalf("the pass ended with %v, no token refused for good", err)
	}
	before := world.counts()
	if err := world.passPastTheBackoff(); err != nil {
		t.Errorf("a pass with the name held: %v", err)
	}
	if taken := world.counts().since(before); taken != (tlsCertHoldCounts{}) {
		t.Errorf("passes at the refusal's state took %+v", taken)
	}

	world.pinVersion.Store(8)
	before = world.counts()
	if err := world.sync(); err != nil {
		t.Errorf("the pass past the state: %v", err)
	}
	want := tlsCertHoldCounts{tokenAsks: 1, exchanges: 1, certsRequests: 1, orders: 1}
	if taken := world.counts().since(before); taken != want {
		t.Errorf("the pass past the state took %+v, want %+v", taken, want)
	}
}

// A certs call that lands under the manager's token lets every held name go, since no refusal of that token stands:
// a custom host held at the exchange's invalid_grant is asked nothing past the backoff, a person's
// EnsureTlsCertificate then lands the network's order and installs its certificate, and the next pass asks for the
// custom host again, its order landing under the token the person's order minted, no exchange more.
func TestTlsCertManagerLetsHoldsGoOnceACertsCallLands(t *testing.T) {
	world := newTlsCertHoldWorld(t, true)
	world.fixture.setCustomHosts(tlsCertTestCustom)
	world.refuseExchanges(1, http.StatusBadRequest, "invalid_grant")
	if err := world.sync(); !tlsCertTokenRefusedForGood(err) {
		t.Fatalf("the pass ended with %v, no token refused for good", err)
	}
	before := world.counts()
	if err := world.passPastTheBackoff(); err != nil {
		t.Errorf("a pass with the name held: %v", err)
	}
	if taken := world.counts().since(before); taken != (tlsCertHoldCounts{}) {
		t.Errorf("passes with the name held took %+v", taken)
	}

	outcome := tlsCertsRenewAwait(t, tlsCertsRenewEnsure(t.Context(), world.manager()))
	if outcome.err != nil || outcome.certificate == nil {
		t.Fatalf("the person's order: %v", outcome.err)
	}
	before = world.counts()
	if err := world.sync(); err != nil {
		t.Errorf("the pass after the person's order: %v", err)
	}
	want := tlsCertHoldCounts{tokenAsks: 1, certsRequests: 1, orders: 1}
	if taken := world.counts().since(before); taken != want {
		t.Errorf("the pass after the person's order took %+v, want %+v", taken, want)
	}
}

// The network's own order is held as a custom host's is: the successor's order for a person's rotation, placed by the
// pass the rotation asks for, meets the exchange's invalid_grant, no pass after asks again past the backoff, and the
// certificate on the serving key goes on serving meanwhile.
func TestTlsCertManagerHoldsTheNetworksOrderWhoseTokenIsRefusedForGood(t *testing.T) {
	world := newTlsCertHoldWorld(t, true)
	outcome := tlsCertsRenewAwait(t, tlsCertsRenewEnsure(t.Context(), world.manager()))
	if outcome.err != nil || outcome.certificate == nil {
		t.Fatalf("the person's order: %v", outcome.err)
	}
	served := tlsCertLeafOf(t, outcome.certificate)
	// the token the person's order minted is gone, and the exchange refuses the device from here on
	world.renew.world.sidecar.ForgetServiceToken(world.renew.resource(), nil)
	world.refuseExchanges(10, http.StatusBadRequest, "invalid_grant")

	before := world.counts()
	if err := world.manager().RotateTlsKey(t.Context(), TlsKeyRotationRequest); err != nil {
		t.Fatal(err)
	}
	world.fixture.settleLoop()
	if taken, want := world.counts().since(before), (tlsCertHoldCounts{tokenAsks: 1, exchanges: 1}); taken != want {
		t.Errorf("the rotation's pass took %+v, want %+v", taken, want)
	}

	before = world.counts()
	if err := world.passPastTheBackoff(); err != nil {
		t.Errorf("a pass with the network's order held: %v", err)
	}
	if taken := world.counts().since(before); taken != (tlsCertHoldCounts{}) {
		t.Errorf("passes with the network's order held took %+v", taken)
	}
	certificate, err := world.manager().PublishCertificate(world.fixture.networkSet())
	if err != nil || !tlsCertLeafOf(t, certificate).Equal(served) {
		t.Errorf("the serving certificate does not serve: %v", err)
	}
}

// A status read whose renewal after certs' 401 meets a refusal of its token keeps the order: the exchange's 404 to the
// renewal is no answer about the order's row, so EnsureTlsCertificate ends with the token refusal, the order stays
// open, and once the row issues the next EnsureTlsCertificate follows that same order to its certificate, placing no
// second one. The code before read the renewal's 404 as certs' own, dropped the order as gone, ended with
// ErrTlsCertOrderFailed, and the next call ordered again.
func TestTlsCertManagerKeepsAnOrderWhoseStatusReadsRenewalIsRefused(t *testing.T) {
	world := newTlsCertHoldWorld(t, false)
	fixture := world.fixture
	done := tlsCertsRenewEnsure(t.Context(), world.manager())
	// the order is placed and its first status read answers queued: the poll parks on its timer
	fixture.clock.awaitTimer(t, fixture.settings.CertOrderPollInterval)
	world.renew.world.expireTokens()
	world.refuseExchanges(1, http.StatusNotFound, "not_found")
	fixture.clock.advance(fixture.settings.CertOrderPollInterval)
	outcome := tlsCertsRenewAwait(t, done)
	var apiErr *SidecarApiError
	if !errors.Is(outcome.err, errTlsCertNoServiceToken) || errors.Is(outcome.err, ErrTlsCertOrderFailed) || !errors.As(outcome.err, &apiErr) || apiErr.Status != http.StatusNotFound {
		t.Errorf("a status read whose renewal met the exchange's 404 ended with %v", outcome.err)
	}

	fixture.api.issue(fixture.api.lastRow().CertId, tlsCertTestLifetime)
	outcome = tlsCertsRenewAwait(t, tlsCertsRenewEnsure(t.Context(), world.manager()))
	if outcome.err != nil || outcome.certificate == nil {
		t.Fatalf("the next call: %v", outcome.err)
	}
	if count := fixture.api.orderCount(); count != 1 {
		t.Errorf("%d orders reached certs' rows", count)
	}
}

// The hold's reading of an order's error (tlsCertTokenRefusedForGood), on the errors the manager's own certs token
// answers (certsServiceToken): the keeper's refusal for good holds, the exchange's invalid_grant, restore_required,
// invalid_scope and 2xx that carried no token, and no enrolled client; what may change does not, the exchange's 429 and
// 503, a keychain still locked, no api yet; nor does any answer of certs' own, its 401 included, which carries no
// token's marker, nor an exchange refusal that did not come through the manager's token.
func TestTlsCertTokenRefusedForGoodReadsWhy(t *testing.T) {
	tokenErr := func(keeperErr error) error {
		manager := &TlsCertManager{
			settings: DefaultSidecarTlsSettings(),
			serviceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
				return "", keeperErr
			},
		}
		_, err := manager.certsServiceToken(context.Background())
		return err
	}
	cases := []struct {
		name string
		err  error
		held bool
	}{
		{name: "invalid_grant", err: tokenErr(serviceTokenRefusalExchangeError(http.StatusBadRequest, "invalid_grant", 0)), held: true},
		{name: "restore_required", err: tokenErr(serviceTokenRefusalExchangeError(http.StatusBadRequest, "restore_required", 0)), held: true},
		{name: "invalid_scope", err: tokenErr(serviceTokenRefusalExchangeError(http.StatusBadRequest, sidecarExchangeCodeInvalidScope, 0)), held: true},
		{name: "a 2xx with no token", err: tokenErr(fmt.Errorf("sidecar api POST /oauth/token: %w", ErrSidecarApiReply)), held: true},
		{name: "no enrolled client", err: tokenErr(ErrSidecarServiceTokenNoClient), held: true},
		{name: "429", err: tokenErr(serviceTokenRefusalExchangeError(http.StatusTooManyRequests, "slow_down", 2000)), held: false},
		{name: "503", err: tokenErr(serviceTokenRefusalExchangeError(http.StatusServiceUnavailable, "temporarily_unavailable", 0)), held: false},
		{name: "locked", err: tokenErr(ErrSidecarServiceTokenLocked), held: false},
		{name: "no api", err: tokenErr(ErrSidecarServiceTokenNoApi), held: false},
		{name: "certs' 401", err: &SidecarApiError{Route: tlsCertOrderRoute, Status: http.StatusUnauthorized}, held: false},
		{name: "certs' 403", err: &SidecarApiError{Route: tlsCertOrderRoute, Status: http.StatusForbidden}, held: false},
		{name: "certs' 409", err: &SidecarApiError{Route: tlsCertOrderRoute, Status: http.StatusConflict, Code: "no_account"}, held: false},
		{name: "an unmarked invalid_grant", err: serviceTokenRefusalExchangeError(http.StatusBadRequest, "invalid_grant", 0), held: false},
	}
	for _, c := range cases {
		if held := tlsCertTokenRefusedForGood(c.err); held != c.held {
			t.Errorf("%s: held %t, want %t", c.name, held, c.held)
		}
	}
	if err := tokenErr(ErrSidecarServiceTokenNoClient); !errors.Is(err, errTlsCertNoServiceToken) || !errors.Is(err, ErrSidecarServiceTokenNoClient) {
		t.Errorf("a token failure that does not carry its keeper's error: %v", err)
	}
}
