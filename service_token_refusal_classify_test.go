//go:build !sidecar_http && !ios_extension && !js

// What dns's and certs' clients do with a service token they could not have, read as evs's and gkm's retry owners read
// one (sidecarServiceTokenRefusalOf; QD-1226): a refusal for good, the exchange's invalid_grant or no enrolled client,
// ends the call at once with nothing sent, and what may change, a keychain still locked, no api yet, the exchange's 429
// or 5xx, goes again within the call's own bound. dns's client asked nothing again before and certs' manager neither,
// so a keychain locked for a moment ended their calls; the ordering desktop read no enrolled client as no answer and
// tried again under its claim until the attempt's deadline. The owned ref's queue, which holds on no enrolled client
// until a reconnect, is evs_local_receive_offline_hold_test.go's.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"
)

// Runs call on its own goroutine, moving clock past each wait it arms, after onWait, nil for none, has seen the wait's
// index from 1; answers call's error and the waits.
func serviceTokenRefusalRun(clock *gkmTestClock, onWait func(index int), call func(ctx context.Context) error) (error, []time.Duration) {
	done := make(chan error, 1)
	go func() {
		done <- call(context.Background())
	}()
	waits := []time.Duration{}
	for {
		select {
		case err := <-done:
			return err, waits
		case wait := <-clock.armed:
			waits = append(waits, wait)
			if onWait != nil {
				onWait(len(waits))
			}
			clock.Advance(wait)
		}
	}
}

// A token keeper answering refusals in turn, then a token: Sidecar.ServiceToken's shape, counting its asks.
type serviceTokenRefusalKeeper struct {
	stateLock sync.Mutex
	refusals  []error
	askCount  int
}

func (self *serviceTokenRefusalKeeper) serviceToken(ctx context.Context, resource string, scopes []string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.askCount += 1
	if 0 < len(self.refusals) {
		refusal := self.refusals[0]
		self.refusals = self.refusals[1:]
		return "", refusal
	}
	return testDnsClientToken, nil
}

func (self *serviceTokenRefusalKeeper) asks() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.askCount
}

// A dns client on the fake block whose service token comes from keeper, on clock.
func newServiceTokenRefusalDnsClient(t *testing.T, block *testDnsBlock, keeper *serviceTokenRefusalKeeper, clock Clock, networkId Id) *DnsClient {
	t.Helper()
	client, err := NewDnsClient(&DnsClientArgs{
		DnsUrl:       "https://dns.test.example",
		Transport:    block,
		ServiceToken: keeper.serviceToken,
		NetworkId:    networkId,
		Clock:        clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// The exchange's answer of a refusal, as SidecarApi reads it.
func serviceTokenRefusalExchangeError(status int, code string, retryAfterMs uint32) *SidecarApiError {
	return &SidecarApiError{Route: "POST /oauth/token", Status: status, Code: code, RetryAfterMs: retryAfterMs}
}

// A dns call whose service token is refused for good, the exchange's invalid_grant or restore_required or no enrolled
// client, ends at once with that refusal after one ask and no wait, a read as a write, nothing reaching the block.
func TestDnsClientEndsAtOnceOnATokenRefusalForGood(t *testing.T) {
	networkId := NewId()
	for _, refusal := range []error{
		serviceTokenRefusalExchangeError(http.StatusBadRequest, "invalid_grant", 0),
		serviceTokenRefusalExchangeError(http.StatusBadRequest, "restore_required", 0),
		ErrSidecarServiceTokenNoClient,
	} {
		calls := map[string]func(client *DnsClient, ctx context.Context) error{
			"zone": func(client *DnsClient, ctx context.Context) error {
				_, err := client.Zone(ctx)
				return err
			},
			"write": func(client *DnsClient, ctx context.Context) error {
				_, err := client.SetRecord(ctx, &DnsRecordUpsert{Name: "shop.lbl0000001.root.example.", Type: "A", Values: []string{"192.0.2.44"}}, nil)
				return err
			},
		}
		for name, call := range calls {
			clock := newGkmTestClock()
			block := newTestDnsBlock(testDnsClientZone(networkId, 3))
			keeper := &serviceTokenRefusalKeeper{refusals: slices.Repeat([]error{refusal}, 10)}
			client := newServiceTokenRefusalDnsClient(t, block, keeper, clock, networkId)
			err, waits := serviceTokenRefusalRun(clock, nil, func(ctx context.Context) error { return call(client, ctx) })
			if !errors.Is(err, refusal) || len(waits) != 0 || keeper.asks() != 1 {
				t.Errorf("%v, %s: ended with %v after %d asks and waits %v, want it at the first", refusal, name, err, keeper.asks(), waits)
			}
			if zones, writes := block.counts(); zones != 0 || writes != 0 || len(block.bearers) != 0 {
				t.Errorf("%v, %s: the block took %d requests", refusal, name, len(block.bearers))
			}
		}
	}
}

// A dns call whose service token may yet be had asks again within ExchangeRetryCount, a write as a read, since nothing
// reached the block: a keychain still locked twice, then open, lands on the third ask after two waits of
// ExchangeRetryWait; one that stays locked ends with ErrSidecarServiceTokenLocked after ExchangeRetryCount+1 asks; no
// api yet goes again alike; the exchange's 429 waits its retry_after, one asking past ExchangeRetryMaxWait ends at once,
// and its 503 naming no wait waits ExchangeRetryWait. The code before ended the call at the first of each.
func TestDnsClientAsksAgainAfterATokenFailureThatMayChange(t *testing.T) {
	networkId := NewId()
	cases := []struct {
		name     string
		refusals []error
		landed   bool
		waits    []time.Duration
	}{
		{name: "locked twice", refusals: slices.Repeat([]error{ErrSidecarServiceTokenLocked}, 2), landed: true, waits: gkmGrantLagRepeat(time.Second, 2)},
		{name: "locked", refusals: slices.Repeat([]error{ErrSidecarServiceTokenLocked}, 10), waits: gkmGrantLagRepeat(time.Second, 3)},
		{name: "no api", refusals: []error{ErrSidecarServiceTokenNoApi}, landed: true, waits: gkmGrantLagRepeat(time.Second, 1)},
		{name: "429", refusals: []error{serviceTokenRefusalExchangeError(http.StatusTooManyRequests, "slow_down", 2000)}, landed: true,
			waits: []time.Duration{2 * time.Second}},
		{name: "429 past the bound", refusals: []error{serviceTokenRefusalExchangeError(http.StatusTooManyRequests, "slow_down", 60_000)},
			waits: []time.Duration{}},
		{name: "503", refusals: []error{serviceTokenRefusalExchangeError(http.StatusServiceUnavailable, "", 0)}, landed: true,
			waits: gkmGrantLagRepeat(time.Second, 1)},
		{name: "no answer", refusals: []error{errors.New("synthetic: connection reset before api answered")}, landed: true,
			waits: gkmGrantLagRepeat(time.Second, 1)},
	}
	for _, c := range cases {
		for _, write := range []bool{false, true} {
			clock := newGkmTestClock()
			block := newTestDnsBlock(testDnsClientZone(networkId, 3))
			keeper := &serviceTokenRefusalKeeper{refusals: slices.Clone(c.refusals)}
			client := newServiceTokenRefusalDnsClient(t, block, keeper, clock, networkId)
			err, waits := serviceTokenRefusalRun(clock, nil, func(ctx context.Context) error {
				if write {
					_, err := client.SetRecord(ctx, &DnsRecordUpsert{Name: "shop.lbl0000001.root.example.", Type: "A", Values: []string{"192.0.2.44"}}, nil)
					return err
				}
				zone, err := client.Zone(ctx)
				if err == nil && zone.Version != 3 {
					return fmt.Errorf("zone version %d", zone.Version)
				}
				return err
			})
			switch {
			case c.landed && err != nil:
				t.Errorf("%s, write %v: %v", c.name, write, err)
			case !c.landed && !errors.Is(err, c.refusals[0]):
				t.Errorf("%s, write %v: ended with %v", c.name, write, err)
			}
			if !slices.Equal(waits, c.waits) {
				t.Errorf("%s, write %v: waited %v, want %v", c.name, write, waits, c.waits)
			}
			if keeper.asks() != len(c.waits)+1 {
				t.Errorf("%s, write %v: %d asks, want %d", c.name, write, keeper.asks(), len(c.waits)+1)
			}
			wantRequests := 0
			if c.landed {
				wantRequests = 1
			}
			if len(block.bearers) != wantRequests {
				t.Errorf("%s, write %v: the block took %d requests, want %d", c.name, write, len(block.bearers), wantRequests)
			}
		}
	}
}

// A dns call whose caller gives up while it waits for its token ends with the caller's context error, asking nothing
// more and sending nothing.
func TestDnsClientTokenWaitEndsWithItsCaller(t *testing.T) {
	networkId := NewId()
	clock := newGkmTestClock()
	block := newTestDnsBlock(testDnsClientZone(networkId, 3))
	keeper := &serviceTokenRefusalKeeper{refusals: slices.Repeat([]error{ErrSidecarServiceTokenLocked}, 10)}
	client := newServiceTokenRefusalDnsClient(t, block, keeper, clock, networkId)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.Zone(ctx)
		done <- err
	}()
	// the first wait armed: the caller gives up, and the clock never passes it
	select {
	case <-clock.armed:
	case err := <-done:
		cancel()
		t.Fatalf("ended with %v before any wait, after %d asks", err, keeper.asks())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || keeper.asks() != 1 || len(block.bearers) != 0 {
		t.Errorf("ended with %v after %d asks and %d requests", err, keeper.asks(), len(block.bearers))
	}
}

// The scripted exchange behind a test Sidecar's api: each exchange takes the next of its answers, and once they run out
// answers a token for the audience. Safe for concurrent use.
type serviceTokenRefusalExchange struct {
	stateLock     sync.Mutex
	answers       []*evsTestExchangeAnswer
	exchangeCount int
}

func (self *serviceTokenRefusalExchange) answer(request *http.Request, body []byte) (*http.Response, error) {
	answer := func() *evsTestExchangeAnswer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.exchangeCount += 1
		if len(self.answers) == 0 {
			return nil
		}
		answer := self.answers[0]
		self.answers = self.answers[1:]
		return answer
	}()
	if answer == nil {
		return syntheticResponse(request, http.StatusOK, `{"access_token":"synthetic-certs-token","expires_in":900}`, nil), nil
	}
	return syntheticResponse(request, answer.status, answer.body, answer.header), nil
}

func (self *serviceTokenRefusalExchange) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.exchangeCount
}

// certs' token as the tls component's manager takes it from a Sidecar (TlsForegroundComponentArgs, which
// TlsComponentArgs shares): a keychain still locked twice, then open, lands on the third ask after two waits of
// CertsExchangeRetryWait, exchanging once; one that stays locked ends with ErrSidecarServiceTokenLocked after
// CertsExchangeRetryCount+1 asks; no api ends with ErrSidecarServiceTokenNoApi alike; no enrolled client, Unenrolled or
// Revoked, ends at once with ErrSidecarServiceTokenNoClient, asking the exchange nothing; the exchange's invalid_grant
// ends at once after one exchange; its 503 goes again after the wait and its 429 after its retry_after, and a 429 asking
// past CertsExchangeRetryMaxWait ends at once. The manager took Sidecar.ServiceToken itself before, and every one of
// these ended its call, a certificate order or its status read, at the first.
func TestTlsCertsServiceTokenReadsWhyItCouldNotBeHad(t *testing.T) {
	cases := []struct {
		name    string
		state   SidecarState
		noApi   bool
		answers []*evsTestExchangeAnswer
		// the wait at whose arming the Sidecar's generation starts, 0 for none
		openAt    int
		landed    bool
		refusal   error
		code      string
		waits     []time.Duration
		exchanges int
	}{
		{name: "locked twice", state: SidecarStateLocked, openAt: 2, landed: true, waits: gkmGrantLagRepeat(time.Second, 2), exchanges: 1},
		{name: "locked", state: SidecarStateLocked, refusal: ErrSidecarServiceTokenLocked, waits: gkmGrantLagRepeat(time.Second, 3)},
		{name: "no api", state: SidecarStateOffline, noApi: true, refusal: ErrSidecarServiceTokenNoApi, waits: gkmGrantLagRepeat(time.Second, 3)},
		{name: "unenrolled", state: SidecarStateUnenrolled, refusal: ErrSidecarServiceTokenNoClient, waits: []time.Duration{}},
		{name: "revoked", state: SidecarStateRevoked, refusal: ErrSidecarServiceTokenNoClient, waits: []time.Duration{}},
		{name: "invalid_grant", state: SidecarStateOffline, answers: []*evsTestExchangeAnswer{evsTestExchangeRefusal(http.StatusBadRequest, "invalid_grant")},
			code: "invalid_grant", waits: []time.Duration{}, exchanges: 1},
		{name: "503", state: SidecarStateOffline, answers: []*evsTestExchangeAnswer{evsTestExchangeWait(http.StatusServiceUnavailable, "temporarily_unavailable", 0)},
			landed: true, waits: gkmGrantLagRepeat(time.Second, 1), exchanges: 2},
		{name: "429", state: SidecarStateOffline, answers: []*evsTestExchangeAnswer{evsTestExchangeWait(http.StatusTooManyRequests, "slow_down", 2)},
			landed: true, waits: []time.Duration{2 * time.Second}, exchanges: 2},
		{name: "429 past the bound", state: SidecarStateOffline, answers: []*evsTestExchangeAnswer{evsTestExchangeWait(http.StatusTooManyRequests, "slow_down", 60)},
			code: "slow_down", waits: []time.Duration{}, exchanges: 1},
	}
	for _, c := range cases {
		clock := newGkmTestClock()
		sidecar := newTlsListenTestSidecar(t, clock)
		exchange := &serviceTokenRefusalExchange{answers: c.answers}
		if !c.noApi {
			api := newTestSidecarApi(t, &scriptedApiTransport{answer: exchange.answer})
			installTestDpopSigner(t, api)
			sidecar.sidecarApi = api
		}
		evsTestMoveTokenSidecar(t, sidecar, c.state)
		args, err := sidecar.TlsForegroundComponentArgs()
		if err != nil {
			t.Fatal(err)
		}
		var token string
		onWait := func(index int) {
			if index == c.openAt {
				evsTestMoveTokenSidecar(t, sidecar, SidecarStateOffline)
			}
		}
		err, waits := serviceTokenRefusalRun(clock, onWait, func(ctx context.Context) error {
			var err error
			token, err = args.Manager.ServiceToken(ctx, "https://certs.example", nil)
			return err
		})
		var apiErr *SidecarApiError
		switch {
		case c.landed && (err != nil || token != "synthetic-certs-token"):
			t.Errorf("%s: the token: %v", c.name, err)
		case c.refusal != nil && !errors.Is(err, c.refusal):
			t.Errorf("%s: ended with %v, want %v", c.name, err, c.refusal)
		case c.code != "" && (!errors.As(err, &apiErr) || apiErr.Code != c.code):
			t.Errorf("%s: ended with %v, want the exchange's %s", c.name, err, c.code)
		}
		if !slices.Equal(waits, c.waits) {
			t.Errorf("%s: waited %v, want %v", c.name, waits, c.waits)
		}
		if exchange.count() != c.exchanges {
			t.Errorf("%s: %d exchanges, want %d", c.name, exchange.count(), c.exchanges)
		}
	}
}

// A custom route's call whose service token could not be had, through the custom api over keeperErr: the error it
// answers, which carries errTlsCustomNoServiceToken and the keeper's error.
func tlsCustomTokenFailure(t *testing.T, keeperErr error) error {
	t.Helper()
	transport := &scriptedApiTransport{answer: func(request *http.Request, body []byte) (*http.Response, error) {
		t.Errorf("a custom route went with no token")
		return syntheticResponse(request, http.StatusOK, `{}`, nil), nil
	}}
	api := NewTlsCustomApi(newTestSidecarApi(t, transport), func(ctx context.Context) (string, error) { return "", keeperErr })
	_, err := api.Claim(context.Background(), &TlsCustomClaimArgs{Domain: "customer.example", Purpose: TlsCustomPurposeOrder, CertId: NewId(), KeySeq: 1})
	if !errors.Is(err, errTlsCustomNoServiceToken) || !errors.Is(err, keeperErr) {
		t.Fatalf("a token failure that does not carry its keeper's error: %v", err)
	}
	return err
}

// The ordering desktop reads a custom route's call that never went for want of its token by why: a refusal for good,
// no enrolled client, the exchange's invalid_grant or its malformed reply, is an answer, so a hold's renewal loses the
// hold and a register's loop ends; what may change, a keychain still locked, no api yet, the exchange's 503 or 429, is
// no answer, tried again as one is. A route's own answers read as before, its reply that does not parse no answer. The
// desktop read every token failure but the exchange's 4xx as no answer before, no enrolled client among them.
func TestTlsCustomTokenFailuresAreReadByWhy(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		forGood bool
	}{
		{name: "no enrolled client", err: ErrSidecarServiceTokenNoClient, forGood: true},
		{name: "invalid_grant", err: serviceTokenRefusalExchangeError(http.StatusBadRequest, "invalid_grant", 0), forGood: true},
		{name: "malformed exchange reply", err: fmt.Errorf("sidecar api POST /oauth/token: %w", ErrSidecarApiReply), forGood: true},
		{name: "locked", err: ErrSidecarServiceTokenLocked},
		{name: "no api", err: ErrSidecarServiceTokenNoApi},
		{name: "503", err: serviceTokenRefusalExchangeError(http.StatusServiceUnavailable, "", 0)},
		{name: "429", err: serviceTokenRefusalExchangeError(http.StatusTooManyRequests, "slow_down", 1000)},
	}
	for _, c := range cases {
		err := tlsCustomTokenFailure(t, c.err)
		if unanswered := tlsCustomUnanswered(err); unanswered == c.forGood {
			t.Errorf("%s: unanswered %v", c.name, unanswered)
		}
		if forGood := tlsCustomTokenRefusedForGood(err); forGood != c.forGood {
			t.Errorf("%s: refused for good %v", c.name, forGood)
		}
	}
	routeReply := fmt.Errorf("sidecar api POST /tls/custom-claim: %w", ErrSidecarApiReply)
	routeRefusal := &SidecarApiError{Route: "POST /tls/custom-claim", Status: http.StatusBadRequest}
	if !tlsCustomUnanswered(routeReply) || tlsCustomTokenRefusedForGood(routeReply) || tlsCustomUnanswered(routeRefusal) || tlsCustomTokenRefusedForGood(routeRefusal) {
		t.Errorf("a route's own answers read otherwise than before")
	}
}

// A custom api whose first claim answers a hold and every later one, a renewal, answers renewal.
type tlsCustomTokenRenewalApi struct {
	tlsCustomScriptedApi
	renewal    error
	claimCount int
}

func (self *tlsCustomTokenRenewalApi) Claim(ctx context.Context, args *TlsCustomClaimArgs) (*TlsCustomClaimResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.claimCount += 1
	if 1 < self.claimCount {
		return nil, self.renewal
	}
	return &TlsCustomClaimResult{ClaimSeq: 1, LeaseMs: 120_000, Record: &TlsCertRecord{CertId: args.CertId}}, nil
}

// A holder whose renewal falls due while it waits: a renewal refused for good for want of its token loses the hold at
// once, the claim left to lapse; one that may change leaves it standing, the renewal tried again OrderPollInterval on.
// The holder kept its hold on no enrolled client before, renewing every OrderPollInterval until its deadline.
func TestTlsCustomHoldEndsAtATokenRefusalForGood(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		kept bool
	}{
		{name: "no enrolled client", err: ErrSidecarServiceTokenNoClient},
		{name: "invalid_grant", err: serviceTokenRefusalExchangeError(http.StatusBadRequest, "invalid_grant", 0)},
		{name: "locked", err: ErrSidecarServiceTokenLocked, kept: true},
	} {
		api := &tlsCustomTokenRenewalApi{renewal: tlsCustomTokenFailure(t, c.err)}
		start := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
		clock := &tlsCustomJumpClock{now: start}
		orderer := newTlsCustomTestOrderer(t, api, &tlsCustomTestKeys{files: map[Id][]byte{}, locals: map[string][]byte{}}, clock, nil)
		account := &TlsCustomAccount{Domain: "customer.example", AccountUri: "https://ca.example/acct/1", KeySeq: 1}
		hold, err := orderer.claim(context.Background(), account, &TlsCustomClaimArgs{Domain: account.Domain, Purpose: TlsCustomPurposeOrder, CertId: NewId(), KeySeq: 1})
		if err != nil {
			t.Fatal(err)
		}
		// past the renewal a third of the 120 s lease on, inside the local deadline
		func() {
			clock.stateLock.Lock()
			defer clock.stateLock.Unlock()
			clock.now = start.Add(41 * time.Second)
		}()
		kept := hold.keep(context.Background())
		if kept != c.kept || hold.lost == c.kept || api.claimCount != 2 {
			t.Errorf("%s: kept %v, lost %v after %d claims", c.name, kept, hold.lost, api.claimCount)
		}
		if c.kept && !hold.renewTime.Equal(start.Add(41*time.Second+DefaultTlsCustomSettings().OrderPollInterval)) {
			t.Errorf("%s: the renewal is due again at %v", c.name, hold.renewTime)
		}
	}
}

// A challenge write whose POST never went for want of its token: refused for good, no enrolled client or the
// exchange's invalid_grant, it ends after that one try with the hold lost, nothing written, no release sent and the
// CA's challenge never answered; a keychain locked once goes again OrderPollInterval on, under the same claim, and the
// authorization goes on. The write tried again every OrderPollInterval until the attempt's deadline on no enrolled
// client before.
func TestTlsCustomChallengeWriteEndsAtATokenRefusalForGood(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
	}{
		{name: "no enrolled client", err: ErrSidecarServiceTokenNoClient},
		{name: "invalid_grant", err: serviceTokenRefusalExchangeError(http.StatusBadRequest, "invalid_grant", 0)},
	} {
		failure := tlsCustomTokenFailure(t, c.err)
		world := newTlsCustomDnsWorld(t, DefaultTlsCustomSettings(), 120_000, func(index int) error {
			return failure
		})
		if order, done := world.authorize(); !done || order != nil {
			t.Errorf("%s: answered %+v, done %v", c.name, order, done)
			continue
		}
		if len(world.api.postClaimSeqs) != 1 || len(world.api.writes) != 0 || world.ca.challengeCount != 0 || len(world.clock.waits) != 0 {
			t.Errorf("%s: %d POSTs, %d writes, %d challenges, waits %v", c.name, len(world.api.postClaimSeqs), len(world.api.writes), world.ca.challengeCount, world.clock.waits)
		}
		if !world.hold.lost || world.api.eventCount(TlsCustomEventRelease) != 0 {
			t.Errorf("%s: lost %v, %d releases", c.name, world.hold.lost, world.api.eventCount(TlsCustomEventRelease))
		}
	}
	locked := tlsCustomTokenFailure(t, ErrSidecarServiceTokenLocked)
	world := newTlsCustomDnsWorld(t, DefaultTlsCustomSettings(), 120_000, func(index int) error {
		if index == 0 {
			return locked
		}
		return nil
	})
	order, done := world.authorize()
	if done || order == nil || order.Status != TlsAcmeStatusReady {
		t.Fatalf("locked once: answered %+v, done %v", order, done)
	}
	if !slices.Equal(world.api.postClaimSeqs, []uint64{1, 1}) || len(world.api.writes) != 1 || world.clock.waits[0] != DefaultTlsCustomSettings().OrderPollInterval {
		t.Errorf("locked once: POSTs under %v, %d writes, waits %v", world.api.postClaimSeqs, len(world.api.writes), world.clock.waits)
	}
	if world.hold.lost || world.api.eventCount(TlsCustomEventRelease) != 0 {
		t.Errorf("locked once: lost %v, %d releases", world.hold.lost, world.api.eventCount(TlsCustomEventRelease))
	}
}

// The receipt api, its GET answering statusErr, counted.
type tlsCustomTokenStatusApi struct {
	*tlsCustomReceiptApi
	statusErr   error
	statusCount int
}

func (self *tlsCustomTokenStatusApi) ChallengeStatus(ctx context.Context, challengeId uint64) (*TlsCustomChallengeResult, error) {
	self.statusCount += 1
	return nil, self.statusErr
}

// While the edges catch up, a GET that never went because no enrolled client can have its token ends the wait with the
// hold lost, after that one read and with the CA's challenge never answered, where the wait read again every
// OrderPollInterval until the challenge's lifetime before.
func TestTlsCustomChallengeStatusEndsAtATokenRefusalForGood(t *testing.T) {
	world := newTlsCustomDnsWorld(t, DefaultTlsCustomSettings(), 120_000, nil)
	api := &tlsCustomTokenStatusApi{tlsCustomReceiptApi: world.api, statusErr: tlsCustomTokenFailure(t, ErrSidecarServiceTokenNoClient)}
	world.orderer.deps.Api = api
	if order, done := world.authorize(); !done || order != nil {
		t.Fatalf("answered %+v, done %v", order, done)
	}
	if api.statusCount != 1 || len(world.api.writes) != 1 || world.ca.challengeCount != 0 || world.ca.deactivateCount != 0 {
		t.Errorf("%d reads, %d writes, %d challenges, %d deactivations", api.statusCount, len(world.api.writes), world.ca.challengeCount, world.ca.deactivateCount)
	}
	if !world.hold.lost || world.api.eventCount(TlsCustomEventRelease) != 0 {
		t.Errorf("lost %v, %d releases", world.hold.lost, world.api.eventCount(TlsCustomEventRelease))
	}
}
