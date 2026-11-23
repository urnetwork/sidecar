// The follow-ups of evs-exchange-refusal-retry: what evs's retry owners do with a service token they could not have.
//
//	window     a write, a lease and a delivery ride out the token exchange's invalid_scope for ExchangeScopeWaitTimeout
//	           (5 s, §8.9's bound for a grant to reach api's gate) from its first, ending after it, not after
//	           PushRetryCount's 40 s and not at once (question evs-refusal-retry-followups-grant-gate-window)
//	typed      Sidecar.ServiceToken's own refusals are typed: no enrolled client ends a call at once, a keychain still
//	           locked and no api yet go again within the call's bound
//	leases     a lease classifies as retryRefusingNothing does: a refusal for good ends Subscribe at once, the lb's 502
//	           and 504 go again, and a final refusal in the rounds waits SubscribeResyncInterval, which
//	           SubscribeRetryMaxWait no longer caps (§11.10's lease, gap and loss rows)
//	deliveries a delivery's log read refused for good, by the exchange or by evs's 401 twice, raises its gap at once
//	           rather than being owed again every ReadRetryWait, and the lb's lost answer is owed again, not a gap
//
// Over SidecarApi's own exchange against a scripted api (evs_exchange_refusal_retry_test.go's), the write tests'
// stand-in evs (evs_plan_test.go) and the subscription tests' lease stand-in (evs_subscribe_test.go). The owned ref's
// queue is evs_local_receive_exchange_hold_test.go's.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// api's token exchange for one scope whose grant reaches api's gate late, as an appended entry reaches it within §8.9's
// bound: each exchange first moves the test clock on by the waits the client took since the one before, as the time
// they stand for would pass, and the scope is refused invalid_scope until late has passed since its first refusal, for
// good when never is set. Every other scope is granted.
type evsTestLateGrant struct {
	clock *evsTestClock
	scope string
	late  time.Duration
	never bool

	stateLock    sync.Mutex
	waitsPassed  int
	firstRefusal time.Time
	// each exchange of the scope's time on the clock
	askedAt []time.Time
}

// A late grant installed as client's service token, which keeps nothing, so every attempt exchanges.
func newEvsTestLateGrant(t *testing.T, client *EvsClient, clock *evsTestClock, scope string, late time.Duration, never bool) *evsTestLateGrant {
	t.Helper()
	grant := &evsTestLateGrant{clock: clock, scope: scope, late: late, never: never, waitsPassed: len(clock.waited())}
	api := newTestSidecarApi(t, &scriptedApiTransport{answer: grant.answer})
	installTestDpopSigner(t, api)
	client.http.serviceToken = func(ctx context.Context, resource string, scopes []string) (string, error) {
		token, err := api.ExchangeToken(ctx, resource, scopes)
		if err != nil {
			return "", err
		}
		return token.AccessToken, nil
	}
	client.http.forgetServiceToken = nil
	return grant
}

func (self *evsTestLateGrant) answer(request *http.Request, body []byte) (*http.Response, error) {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return syntheticResponse(request, http.StatusBadRequest, `{"error":"invalid_request"}`, nil), nil
	}
	scope := form.Get("scope")
	refused := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		waits := self.clock.waited()
		for _, wait := range waits[self.waitsPassed:] {
			self.clock.advance(wait)
		}
		self.waitsPassed = len(waits)
		if scope != self.scope {
			return false
		}
		now := self.clock.Now()
		self.askedAt = append(self.askedAt, now)
		if self.firstRefusal.IsZero() {
			self.firstRefusal = now
		}
		return self.never || now.Before(self.firstRefusal.Add(self.late))
	}()
	if refused {
		return syntheticResponse(request, http.StatusBadRequest, `{"error":"invalid_scope","error_description":"Synthetic description."}`, nil), nil
	}
	granted := fmt.Sprintf(`{"access_token":%q,"issued_token_type":"urn:ietf:params:oauth:token-type:access_token",`+
		`"token_type":"N_A","expires_in":900,"scope":%q}`, evsTestServiceToken, scope)
	return syntheticResponse(request, http.StatusOK, granted, nil), nil
}

// How long after the first exchange of the scope each one was asked.
func (self *evsTestLateGrant) asked() []time.Duration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	asked := []time.Duration{}
	for _, at := range self.askedAt {
		asked = append(asked, at.Sub(self.askedAt[0]))
	}
	return asked
}

// The waits a test clock recorded from the index from on.
func evsTestWaitsSince(clock *evsTestClock, from int) []time.Duration {
	return clock.waited()[from:]
}

// Whether err is the exchange's invalid_scope, its route the exchange's.
func evsTestIsScopeRefusal(err error) bool {
	var apiErr *SidecarApiError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest && apiErr.Code == "invalid_scope" &&
		apiErr.Route == "POST /oauth/token"
}

// A write whose grant reaches api's gate 2 s after the exchange first refused its scope lands: an upload and a push
// with no segment are refused invalid_scope at 0 s and 1 s, ReadRetryWait apart, granted at 2 s, and commit once. The
// code before ended either at the first refusal.
func TestEvsWriteRidesOutAGrantTheExchangeLoadsLate(t *testing.T) {
	contents := []struct {
		name    string
		content []byte
	}{
		{name: "upload", content: evsTestContent("late grant upload", 64*1024)},
		{name: "push", content: []byte("late grant push")},
	}
	for _, c := range contents {
		writer := newEvsTestWriter(t)
		grant := newEvsTestLateGrant(t, writer.test.client, writer.test.clock, evsTestWriteScope(writer), 2*time.Second, false)
		result, err := writer.write(t, "a.txt", c.content)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		retryWait := writer.test.client.settings.ReadRetryWait
		if waits := writer.test.clock.waited(); !slices.Equal(waits, []time.Duration{retryWait, retryWait}) {
			t.Errorf("%s: waits %v, not ReadRetryWait twice", c.name, waits)
		}
		// refused at 0 and 1 s, granted at 2 s; and the push's own after an upload
		want := []time.Duration{0, time.Second, 2 * time.Second}
		if c.name == "upload" {
			want = append(want, 2*time.Second)
		}
		if asked := grant.asked(); !slices.Equal(asked, want) {
			t.Errorf("%s: the write scope asked at %v", c.name, asked)
		}
		if pushIds := writer.server.postedPushIds(t); len(pushIds) != 1 || pushIds[0] != result.PushId || len(writer.world.commits) != 1 {
			t.Errorf("%s: pushes %v, %d commits", c.name, pushIds, len(writer.world.commits))
		}
		if read, _, err := writer.read(t, "a.txt"); err != nil || string(read) != string(c.content) {
			t.Errorf("%s: read back: %v", c.name, err)
		}
	}
}

// A write whose scope the exchange never grants ends with its invalid_scope once ExchangeScopeWaitTimeout has passed
// since the first refusal, the last try at the window's end: 5 s and six exchanges at the default, where the code
// before this one's predecessor asked 41 times over 40 s, and a 2.5 s window's last wait is its half second left.
// Nothing reaches evs, and the error holds nothing of api's text.
func TestEvsWriteEndsAnExchangeScopeRefusalAfterTheWindow(t *testing.T) {
	second := time.Second
	cases := []struct {
		name   string
		window time.Duration
		waits  []time.Duration
	}{
		{name: "default", window: DefaultEvsSettings().ExchangeScopeWaitTimeout, waits: []time.Duration{second, second, second, second, second}},
		{name: "2.5 s", window: 2500 * time.Millisecond, waits: []time.Duration{second, second, 500 * time.Millisecond}},
	}
	contents := []struct {
		name    string
		content []byte
	}{
		{name: "upload", content: evsTestContent("never granted upload", 64*1024)},
		{name: "push", content: []byte("never granted push")},
	}
	for _, c := range cases {
		for _, content := range contents {
			writer := newEvsTestWriter(t)
			writer.test.client.settings.ExchangeScopeWaitTimeout = c.window
			grant := newEvsTestLateGrant(t, writer.test.client, writer.test.clock, evsTestWriteScope(writer), 0, true)
			_, err := writer.write(t, "a.txt", content.content)
			if !evsTestIsScopeRefusal(err) {
				t.Errorf("%s %s: the write ended %v", c.name, content.name, err)
				continue
			}
			if strings.Contains(err.Error(), "Synthetic description") || strings.Contains(err.Error(), testByJwt) {
				t.Errorf("%s %s: the error repeats api's text or the subject token: %v", c.name, content.name, err)
			}
			if waits := writer.test.clock.waited(); !slices.Equal(waits, c.waits) {
				t.Errorf("%s %s: waits %v, not %v", c.name, content.name, waits, c.waits)
			}
			asked := grant.asked()
			if len(asked) != len(c.waits)+1 || asked[len(asked)-1] != c.window {
				t.Errorf("%s %s: the write scope asked at %v, the last not at the window's end", c.name, content.name, asked)
			}
			if !evsTestWriterSentNothing(t, writer) {
				t.Errorf("%s %s: %d uploads, %d commits", c.name, content.name, len(writer.server.uploads), len(writer.world.commits))
			}
		}
	}
}

// A Sidecar for ServiceToken's states: Locked as built, or moved to state, its api answering every exchange with the
// evs test token.
func newEvsTestTokenSidecar(t *testing.T, state SidecarState) *Sidecar {
	t.Helper()
	settings := validSidecarSettings()
	settings.Clock = newTokenTestClock()
	sidecar := newSidecarBase(nil, settings)
	api := newTestSidecarApi(t, &scriptedApiTransport{answer: func(request *http.Request, body []byte) (*http.Response, error) {
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		granted := fmt.Sprintf(`{"access_token":%q,"expires_in":900,"scope":%q}`, evsTestServiceToken, form.Get("scope"))
		return syntheticResponse(request, http.StatusOK, granted, nil), nil
	}})
	installTestDpopSigner(t, api)
	sidecar.sidecarApi = api
	evsTestMoveTokenSidecar(t, sidecar, state)
	return sidecar
}

// Moves a Locked test Sidecar to state: Unenrolled, Offline at generation 1, or Revoked by a verified revocation. A
// refused move is an error of the test's, reported from whichever goroutine moved it.
func evsTestMoveTokenSidecar(t *testing.T, sidecar *Sidecar, state SidecarState) {
	t.Helper()
	moves := map[SidecarState][]sidecarTransition{
		SidecarStateLocked:     nil,
		SidecarStateUnenrolled: {{to: SidecarStateUnenrolled}},
		SidecarStateOffline:    {{to: SidecarStateUnenrolled}, {to: SidecarStateOffline, generation: 1}},
		SidecarStateRevoked:    {{to: SidecarStateUnenrolled}, {to: SidecarStateRevoked, reason: SidecarReasonSigned, verifiedRevocation: true}},
	}
	for _, move := range moves[state] {
		if !sidecar.applyTransition(move) {
			t.Errorf("the move to %s was refused", move.to)
		}
	}
}

// ServiceToken's own refusals are typed (the brief's third item): Locked answers ErrSidecarServiceTokenLocked, which is
// ErrSidecarStoreLocked too; Unenrolled and Revoked ErrSidecarServiceTokenNoClient; a Sidecar with no api
// ErrSidecarServiceTokenNoApi. A retry owner ends a call on no enrolled client alone, and takes none of them for the
// exchange's own refusal. Before, each was an untyped error every retry owner tried again.
func TestServiceTokenRefusalsAreTyped(t *testing.T) {
	cases := []struct {
		name  string
		state SidecarState
		noApi bool
		want  error
		final bool
	}{
		{name: "locked", state: SidecarStateLocked, want: ErrSidecarServiceTokenLocked},
		{name: "unenrolled", state: SidecarStateUnenrolled, want: ErrSidecarServiceTokenNoClient, final: true},
		{name: "revoked", state: SidecarStateRevoked, want: ErrSidecarServiceTokenNoClient, final: true},
		{name: "no api", state: SidecarStateOffline, noApi: true, want: ErrSidecarServiceTokenNoApi},
	}
	ctx := context.Background()
	for _, c := range cases {
		sidecar := newEvsTestTokenSidecar(t, c.state)
		if c.noApi {
			sidecar.sidecarApi = nil
		}
		_, err := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:a:rw"})
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		wrapped := fmt.Errorf("evs POST /evs/v1/repos/{repo_id}/push: %w: %w", errEvsNoServiceToken, err)
		if refusal := sidecarServiceTokenRefusalOf(wrapped); refusal.final != c.final || refusal.exchange || refusal.scopeRefused {
			t.Errorf("%s: read as %+v", c.name, refusal)
		}
	}
	if !errors.Is(ErrSidecarServiceTokenLocked, ErrSidecarStoreLocked) {
		t.Errorf("a locked keychain's refusal is not the store's")
	}
	// once Offline with its api, the same Sidecar exchanges
	sidecar := newEvsTestTokenSidecar(t, SidecarStateOffline)
	if token, err := sidecar.ServiceToken(ctx, "https://evs.example", []string{"repo:a:rw"}); err != nil || token != evsTestServiceToken {
		t.Errorf("an enrolled sidecar's token: %v", err)
	}
}

// The writer's token function asking sidecar for the write scope alone, each ask counted and passed to onAsk first,
// nil for none; the head reads a write makes before its uploads and push are granted as the test client grants them,
// as for a sidecar whose state moved after those reads.
func evsTestWriteScopeToken(writer *evsTestWriter, sidecar *Sidecar, asks *int, onAsk func(ask int)) EvsServiceTokenFunction {
	writeScope := evsTestWriteScope(writer)
	return func(ctx context.Context, resource string, scopes []string) (string, error) {
		if !slices.Contains(scopes, writeScope) {
			return writer.test.tokens.token(ctx, resource, scopes)
		}
		*asks += 1
		if onAsk != nil {
			onAsk(*asks)
		}
		return sidecar.ServiceToken(ctx, resource, scopes)
	}
}

// An evs write whose Sidecar has no enrolled client by its upload, Unenrolled or Revoked, ends at that first try with
// ErrSidecarServiceTokenNoClient, waiting nothing and sending nothing to evs: the call asked again every
// ReadRetryWait, PushRetryCount times, before.
func TestEvsWriteEndsAtOnceWithNoEnrolledClient(t *testing.T) {
	for _, state := range []SidecarState{SidecarStateUnenrolled, SidecarStateRevoked} {
		writer := newEvsTestWriter(t)
		sidecar := newEvsTestTokenSidecar(t, state)
		asks := 0
		writer.test.client.http.serviceToken = evsTestWriteScopeToken(writer, sidecar, &asks, nil)
		writer.test.client.http.forgetServiceToken = sidecar.ForgetServiceToken
		_, err := writer.write(t, "a.txt", evsTestContent("no client", 64*1024))
		if !errors.Is(err, ErrSidecarServiceTokenNoClient) {
			t.Errorf("%s: the write ended %v", state, err)
			continue
		}
		if waits := writer.test.clock.waited(); len(waits) != 0 || asks != 1 {
			t.Errorf("%s: %d token asks, waits %v", state, asks, waits)
		}
		if !evsTestWriterSentNothing(t, writer) {
			t.Errorf("%s: %d uploads, %d commits", state, len(writer.server.uploads), len(writer.world.commits))
		}
	}
}

// A keychain still locked, and no api yet, can change, so a write asks again ReadRetryWait apart within
// PushRetryCount: a Sidecar unlocked after two tries lands the write on its third, and one locked for good ends after
// PushRetryCount+1 tries with the typed refusal.
func TestEvsWriteAsksAgainWhileTheKeychainIsLocked(t *testing.T) {
	writer := newEvsTestWriter(t)
	sidecar := newEvsTestTokenSidecar(t, SidecarStateLocked)
	asks := 0
	writer.test.client.http.serviceToken = evsTestWriteScopeToken(writer, sidecar, &asks, func(ask int) {
		if ask == 3 {
			// unlocked: the run loop starts the client again
			evsTestMoveTokenSidecar(t, sidecar, SidecarStateOffline)
		}
	})
	if _, err := writer.write(t, "a.txt", []byte("after the unlock")); err != nil {
		t.Fatalf("the write after the unlock: %v", err)
	}
	retryWait := writer.test.client.settings.ReadRetryWait
	if waits := writer.test.clock.waited(); !slices.Equal(waits, []time.Duration{retryWait, retryWait}) || len(writer.world.commits) != 1 {
		t.Errorf("waits %v, %d commits", waits, len(writer.world.commits))
	}
	for _, noApi := range []bool{false, true} {
		writer := newEvsTestWriter(t)
		writer.test.client.settings.PushRetryCount = 3
		state, want := SidecarStateLocked, ErrSidecarServiceTokenLocked
		if noApi {
			state, want = SidecarStateOffline, ErrSidecarServiceTokenNoApi
		}
		sidecar := newEvsTestTokenSidecar(t, state)
		if noApi {
			sidecar.sidecarApi = nil
		}
		asks := 0
		writer.test.client.http.serviceToken = evsTestWriteScopeToken(writer, sidecar, &asks, nil)
		_, err := writer.write(t, "a.txt", []byte("locked for good"))
		if !errors.Is(err, want) || asks != 4 || len(writer.test.clock.waited()) != 3 {
			t.Errorf("no api %t: ended %v after %d asks and %d waits", noApi, err, asks, len(writer.test.clock.waited()))
		}
	}
}

// A subscription test whose first subscription, docs, is leased and pinned the head, so a later Subscribe asks evs for
// its lease alone.
func newEvsTestLeasedSubscriber(t *testing.T) (*evsTestWorld, *evsTestLeases, *evsTestClient) {
	t.Helper()
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	if _, err := test.client.Repo(world.repoId).Subscribe(context.Background(), &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}}); err != nil {
		t.Fatal(err)
	}
	return world, leases, test
}

// The subscriptions the subscriber holds.
func evsTestSubscriptionCount(test *evsTestClient) int {
	test.client.subscriber.stateLock.Lock()
	defer test.client.subscriber.stateLock.Unlock()
	return len(test.client.subscriber.subscriptions)
}

// A lease whose service token is refused for good ends Subscribe at once with that refusal (the brief's second item):
// the exchange's invalid_grant and no enrolled client each end it after one ask, with no wait, nothing posted and the
// subscription dropped. Before, evsLeaseRetries read both as a lost token and asked SubscribeRetryCount more times,
// then answered the subscription with its lease owed.
func TestEvsSubscribeEndsAtOnceAtAServiceTokenRefusedForGood(t *testing.T) {
	cases := []struct {
		name string
		// installs the refusing token on the read scope, answering how many asks it took
		install func(t *testing.T, test *evsTestClient, scope string) func() int
		check   func(err error) bool
	}{
		{name: "invalid_grant", install: func(t *testing.T, test *evsTestClient, scope string) func() int {
			return newEvsTestExchange(t, test.client, scope, evsTestExchangeRefusedForGood(http.StatusBadRequest, "invalid_grant")).count
		}, check: func(err error) bool {
			var apiErr *SidecarApiError
			return errors.As(err, &apiErr) && apiErr.Code == "invalid_grant"
		}},
		{name: "no enrolled client", install: func(t *testing.T, test *evsTestClient, scope string) func() int {
			asks := 0
			test.client.http.serviceToken = func(ctx context.Context, resource string, scopes []string) (string, error) {
				asks += 1
				return "", ErrSidecarServiceTokenNoClient
			}
			return func() int { return asks }
		}, check: func(err error) bool { return errors.Is(err, ErrSidecarServiceTokenNoClient) }},
	}
	for _, c := range cases {
		world, leases, test := newEvsTestLeasedSubscriber(t)
		posts := leases.postCount()
		waits := len(test.clock.waited())
		asks := c.install(t, test, evsRepoScope(world.repoId, evsScopeRead))
		subscription, err := test.client.Repo(world.repoId).Subscribe(context.Background(), &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"src"}})
		if subscription != nil || !c.check(err) {
			t.Errorf("%s: Subscribe answered %v, %v", c.name, subscription, err)
			continue
		}
		if count := asks(); count != 1 {
			t.Errorf("%s: %d asks", c.name, count)
		}
		if got := evsTestWaitsSince(test.clock, waits); len(got) != 0 || leases.postCount() != posts {
			t.Errorf("%s: waits %v, %d posts", c.name, got, leases.postCount()-posts)
		}
		if count := evsTestSubscriptionCount(test); count != 1 {
			t.Errorf("%s: %d subscriptions kept", c.name, count)
		}
	}
}

// A handler in front of next that answers the next lost requests matching the route with the lb's page for status,
// no answer from evs at all (QD-758).
func evsTestLbLosing(next http.Handler, method string, matches func(path string) bool, status int, lost *int) http.Handler {
	pages := map[int]string{http.StatusBadGateway: evsTestLbBadGatewayPage, http.StatusGatewayTimeout: evsTestLbGatewayTimeoutPage}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == method && matches(request.URL.Path) && 0 < *lost {
			*lost -= 1
			writer.Header().Set("Content-Type", "text/html")
			writer.WriteHeader(status)
			writer.Write([]byte(pages[status]))
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// The lb's 502 or 504 to a lease's POST is no answer from evs at all (QD-758), so Subscribe tries again after
// SubscribeRetryMinWait and holds its lease once evs answers 200. Before, the lease read its unknown outcome as a
// refusal for good and Subscribe dropped the subscription with it.
func TestEvsSubscribeTriesAgainAfterTheLbsLostAnswer(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusGatewayTimeout} {
		world, leases, test := newEvsTestLeasedSubscriber(t)
		lost := 1
		front := evsTestLbLosing(leases, http.MethodPost, func(path string) bool { return path == "/evs/v1/subscriptions" }, status, &lost)
		test.client.http.transport = wrapSidecarApiTransport(&evsTestTransport{handler: front})
		waits := len(test.clock.waited())
		if _, err := test.client.Repo(world.repoId).Subscribe(context.Background(), &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"src"}}); err != nil {
			t.Errorf("%d: %v", status, err)
			continue
		}
		if got := evsTestWaitsSince(test.clock, waits); !slices.Equal(got, []time.Duration{test.client.settings.SubscribeRetryMinWait}) {
			t.Errorf("%d: waits %v", status, got)
		}
		if lost != 0 || len(leases.fields()) != 2 || evsTestSubscriptionCount(test) != 2 {
			t.Errorf("%d: leases %q, %d subscriptions", status, leases.fields(), evsTestSubscriptionCount(test))
		}
	}
}

// A lease the rounds owe that is refused for good, evs's 403 SCOPE or the exchange's invalid_grant, is tried again at
// the hourly resync's pace, SubscribeResyncInterval on (§11.10's gap and loss rows), with nothing asked at
// SubscribeRetryMaxWait: before, min(wait, SubscribeRetryMaxWait) brought an hour down to 5 min, and the exchange's
// refusal was not even read as final, its next try 2 s on.
func TestEvsLeaseRefusedForGoodWaitsTheHourlyResync(t *testing.T) {
	cases := []struct {
		name string
		// refuses the owed lease for good from here on, answering a count that moves with each try of it
		refuse func(t *testing.T, test *evsTestClient, world *evsTestWorld, leases *evsTestLeases) func() int
	}{
		{name: "evs SCOPE", refuse: func(t *testing.T, test *evsTestClient, world *evsTestWorld, leases *evsTestLeases) func() int {
			posts := 0
			front := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodPost && request.URL.Path == "/evs/v1/subscriptions" {
					posts += 1
					body, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE})
					writer.WriteHeader(http.StatusForbidden)
					writer.Write(body)
					return
				}
				leases.ServeHTTP(writer, request)
			})
			test.client.http.transport = wrapSidecarApiTransport(&evsTestTransport{handler: front})
			return func() int { return posts }
		}},
		{name: "exchange invalid_grant", refuse: func(t *testing.T, test *evsTestClient, world *evsTestWorld, leases *evsTestLeases) func() int {
			return newEvsTestExchange(t, test.client, evsRepoScope(world.repoId, evsScopeRead),
				evsTestExchangeRefusedForGood(http.StatusBadRequest, "invalid_grant")).count
		}},
	}
	for _, c := range cases {
		world := newEvsTestWorld(t)
		leases := newEvsTestLeases(world)
		test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
		settings := test.client.settings
		world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
		ctx := context.Background()
		// Subscribe tries once, evs answers 503, and the rounds owe the lease
		settings.SubscribeRetryCount = 0
		leases.failPosts = 1
		if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}}); err != nil {
			t.Fatal(err)
		}
		// the first round's resync and reads, before the lease falls due
		test.client.subscriber.runDue(ctx)
		tries := c.refuse(t, test, world, leases)
		test.clock.advance(settings.SubscribeRetryMinWait)
		refusedAt := test.clock.Now()
		test.client.subscriber.runDue(ctx)
		if count := tries(); count != 1 {
			t.Errorf("%s: the owed lease tried %d times", c.name, count)
			continue
		}
		dueAt := func() time.Time {
			test.client.subscriber.stateLock.Lock()
			defer test.client.subscriber.stateLock.Unlock()
			for _, state := range test.client.subscriber.subscriptions {
				return state.leaseDueAt
			}
			return time.Time{}
		}()
		if due := dueAt.Sub(refusedAt); due != settings.SubscribeResyncInterval {
			t.Errorf("%s: the next try %s on, not SubscribeResyncInterval", c.name, due)
		}
		test.clock.advance(settings.SubscribeRetryMaxWait)
		test.client.subscriber.runDue(ctx)
		if count := tries(); count != 1 {
			t.Errorf("%s: tried again %d times at SubscribeRetryMaxWait", c.name, count-1)
		}
		if evsTestSubscriptionCount(test) != 1 {
			t.Errorf("%s: the rounds dropped the subscription", c.name)
		}
	}
}

// A lease whose read scope reaches api's gate 2 s after the exchange first refused it lands: Subscribe asks at 0 s,
// 1 s and 3 s, its doubling wait, and the third is granted. One never granted ends Subscribe with its invalid_scope
// after the window, the last try at its end (0, 1, 3 and 5 s), and drops the subscription. Before, invalid_scope was a
// lost token, asked again SubscribeRetryCount times and answered as a subscription with its lease owed.
func TestEvsLeaseRidesOutAGrantTheExchangeLoadsLate(t *testing.T) {
	second := time.Second
	cases := []struct {
		name  string
		late  time.Duration
		never bool
		asked []time.Duration
	}{
		{name: "2 s late", late: 2 * time.Second, asked: []time.Duration{0, second, 3 * second}},
		{name: "never", never: true, asked: []time.Duration{0, second, 3 * second, 5 * second}},
	}
	for _, c := range cases {
		world, leases, test := newEvsTestLeasedSubscriber(t)
		grant := newEvsTestLateGrant(t, test.client, test.clock, evsRepoScope(world.repoId, evsScopeRead), c.late, c.never)
		subscription, err := test.client.Repo(world.repoId).Subscribe(context.Background(), &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"src"}})
		if asked := grant.asked(); !slices.Equal(asked, c.asked) {
			t.Errorf("%s: the lease asked at %v", c.name, asked)
		}
		if c.never {
			if subscription != nil || !evsTestIsScopeRefusal(err) || evsTestSubscriptionCount(test) != 1 {
				t.Errorf("%s: Subscribe answered %v, %v, %d subscriptions", c.name, subscription, err, evsTestSubscriptionCount(test))
			}
			continue
		}
		if err != nil || len(leases.fields()) != 2 {
			t.Errorf("%s: %v, leases %q", c.name, err, leases.fields())
		}
	}
}

// A followed ref whose pin another call raised past its mark with no statement, so its delivery reads the log: two
// commits past the subscription's mark, the hourly resync and the reread run first.
func newEvsTestOwedDelivery(t *testing.T) (*evsTestWorld, *evsTestLeases, *evsTestClient, *evsTestChanges) {
	t.Helper()
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	ctx := context.Background()
	listened := &evsTestChanges{}
	test.client.AddRepoChangeListener(&world.repoId, listened.add)
	if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}}); err != nil {
		t.Fatal(err)
	}
	test.clock.advance(test.client.settings.SubscribeRereadDelay)
	test.client.subscriber.runDue(ctx)
	world.push(&evsTestChange{path: "docs/b", content: []byte("b")})
	world.push(&evsTestChange{path: "docs/c", content: []byte("c")})
	if err := evsTestWalkRaise(ctx, test.client, world.repoId, world.refId); err != nil {
		t.Fatal(err)
	}
	return world, leases, test, listened
}

// A delivery whose log read the exchange refuses for good, invalid_grant, raises its gap at the pin at once, after one
// ask, and asks nothing more; one refused invalid_scope is owed again ReadRetryWait apart until
// ExchangeScopeWaitTimeout has passed since the first, then raises the gap, six asks in all; and one whose grant
// reaches api's gate 2 s late raises both commits' own changes and no gap. Before, every one of them was owed again
// every ReadRetryWait for as long as the exchange refused, and raised nothing.
func TestEvsDeliveryRaisesAGapAtALogTheExchangeRefusesForGood(t *testing.T) {
	ctx := context.Background()
	// invalid_grant
	world, _, test, listened := newEvsTestOwedDelivery(t)
	exchange := newEvsTestExchange(t, test.client, evsRepoScope(world.repoId, evsScopeRead), evsTestExchangeRefusedForGood(http.StatusBadRequest, "invalid_grant"))
	test.client.subscriber.runDue(ctx)
	if change := listened.last(); len(listened.versions()) != 1 || change == nil || !change.Gap || change.Version != 3 || !slices.Equal(change.Paths, []string{"docs"}) {
		t.Errorf("invalid_grant: changes %v, the last %+v", listened.versions(), change)
	}
	test.clock.advance(test.client.settings.ReadRetryWait)
	test.client.subscriber.runDue(ctx)
	if count := exchange.count(); count != 1 || len(listened.versions()) != 1 {
		t.Errorf("invalid_grant: %d asks, %d changes", count, len(listened.versions()))
	}

	// invalid_scope, never granted
	world, _, test, listened = newEvsTestOwedDelivery(t)
	grant := newEvsTestLateGrant(t, test.client, test.clock, evsRepoScope(world.repoId, evsScopeRead), 0, true)
	for round := range 6 {
		test.client.subscriber.runDue(ctx)
		if round < 5 {
			if count := len(listened.versions()); count != 0 {
				t.Fatalf("invalid_scope: round %d raised %d changes inside the window", round, count)
			}
			test.clock.advance(test.client.settings.ReadRetryWait)
		}
	}
	if change := listened.last(); len(listened.versions()) != 1 || change == nil || !change.Gap || change.Version != 3 {
		t.Errorf("invalid_scope: changes %v, the last %+v", listened.versions(), change)
	}
	second := time.Second
	if asked := grant.asked(); !slices.Equal(asked, []time.Duration{0, second, 2 * second, 3 * second, 4 * second, 5 * second}) {
		t.Errorf("invalid_scope: the log asked at %v", asked)
	}
	test.clock.advance(test.client.settings.ReadRetryWait)
	test.client.subscriber.runDue(ctx)
	if count := len(grant.asked()); count != 6 {
		t.Errorf("invalid_scope: asked %d times after the gap", count-6)
	}

	// invalid_scope, granted 2 s late
	world, _, test, listened = newEvsTestOwedDelivery(t)
	newEvsTestLateGrant(t, test.client, test.clock, evsRepoScope(world.repoId, evsScopeRead), 2*time.Second, false)
	for range 3 {
		test.client.subscriber.runDue(ctx)
		test.clock.advance(test.client.settings.ReadRetryWait)
	}
	if versions := listened.versions(); !slices.Equal(versions, []uint64{2, 3}) || listened.last().Gap {
		t.Errorf("a late grant: changes %v", versions)
	}
}

// The lb's 502 or 504 to a delivery's log read is no answer at all (QD-758): the delivery is owed again and raises
// both commits' own changes once the log answers, where it raised a gap before. evs's 401 twice, a client a rev/
// object voids, refuses for good: the delivery raises its gap at once, where it was owed again every ReadRetryWait,
// two exchanges and two 401s a try.
func TestEvsDeliveryTriesAgainAfterTheLbsLostAnswer(t *testing.T) {
	ctx := context.Background()
	isLog := func(path string) bool { return strings.HasSuffix(path, "/log") }
	for _, status := range []int{http.StatusBadGateway, http.StatusGatewayTimeout} {
		_, leases, test, listened := newEvsTestOwedDelivery(t)
		lost := 1
		test.client.http.transport = wrapSidecarApiTransport(&evsTestTransport{handler: evsTestLbLosing(leases, http.MethodGet, isLog, status, &lost)})
		test.client.subscriber.runDue(ctx)
		if lost != 0 || len(listened.versions()) != 0 {
			t.Errorf("%d: %d lost left, changes %v", status, lost, listened.versions())
		}
		test.clock.advance(test.client.settings.ReadRetryWait)
		test.client.subscriber.runDue(ctx)
		if versions := listened.versions(); !slices.Equal(versions, []uint64{2, 3}) || listened.last().Gap {
			t.Errorf("%d: changes %v", status, versions)
		}
	}
	_, leases, test, listened := newEvsTestOwedDelivery(t)
	unauthenticated := 0
	test.client.http.transport = wrapSidecarApiTransport(&evsTestTransport{handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && isLog(request.URL.Path) {
			unauthenticated += 1
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		leases.ServeHTTP(writer, request)
	})})
	test.client.subscriber.runDue(ctx)
	if change := listened.last(); len(listened.versions()) != 1 || change == nil || !change.Gap || change.Version != 3 {
		t.Errorf("401: changes %v, the last %+v", listened.versions(), change)
	}
	test.clock.advance(test.client.settings.ReadRetryWait)
	test.client.subscriber.runDue(ctx)
	if unauthenticated != 2 || len(listened.versions()) != 1 {
		t.Errorf("401: %d log reads, %d changes", unauthenticated, len(listened.versions()))
	}
}
