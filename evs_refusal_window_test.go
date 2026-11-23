// The follow-ups of evs-exchange-refusal-retry: what evs's retry owners do with a service token they could not have.
//
//	window     a write rides out the token exchange's invalid_scope for ExchangeScopeWaitTimeout (5 s, §8.9's bound
//	           for a grant to reach api's gate) from its first, ending after it, not after PushRetryCount's 40 s and
//	           not at once (question evs-refusal-retry-followups-grant-gate-window)
//	typed      Sidecar.ServiceToken's own refusals are typed: no enrolled client ends a call at once, a keychain still
//	           locked and no api yet go again within the call's bound
//
// Over SidecarApi's own exchange against a scripted api (evs_exchange_refusal_retry_test.go's) and the write tests'
// stand-in evs (evs_plan_test.go).

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
