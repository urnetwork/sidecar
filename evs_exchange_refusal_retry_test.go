// A service token the exchange refused for good ends an evs push or upload at once, with the exchange's answer
// (§7.8's exchange answers; §11.8's retry id row): its 400 invalid_grant and every other answer but a 429, a 5xx or
// invalid_scope are answered after one exchange, with no wait, where evs's client asked again every ReadRetryWait up
// to PushRetryCount times. Its 429 waits its retry-after, its 5xx goes again within PushRetryCount, and no answer from
// api goes again as evs's no answer does. invalid_scope goes again within ExchangeScopeWaitTimeout, a grant's way to
// api's gate, which evs_refusal_window_test.go tests. Over SidecarApi's own exchange against a scripted api, and the
// stand-in evs of the write tests (evs_plan_test.go).

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

	"github.com/urnetwork/sidecar/protocol"
)

// One answer of the scripted exchange: a status, body and headers, or no answer at all.
type evsTestExchangeAnswer struct {
	status int
	body   string
	header http.Header
	// the transport fails, and api answers nothing
	err error
	// answered again to every later exchange of the scope, as a refusal for good is
	repeats bool
}

// api's token exchange behind a SidecarApi, scripted for one scope: each exchange asking for that scope takes the next
// of its answers, and once they run out, as every other exchange does, a token granting what it asked.
type evsTestExchange struct {
	scope string
	api   *SidecarApi

	stateLock  sync.Mutex
	answers    []*evsTestExchangeAnswer
	scopeCount int
}

// An exchange answering scope from answers, installed as client's service token, which keeps nothing, so every attempt
// exchanges as a token keeper with nothing kept for the scope does.
func newEvsTestExchange(t *testing.T, client *EvsClient, scope string, answers ...*evsTestExchangeAnswer) *evsTestExchange {
	t.Helper()
	exchange := &evsTestExchange{scope: scope, answers: answers}
	exchange.api = newTestSidecarApi(t, &scriptedApiTransport{answer: exchange.answer})
	installTestDpopSigner(t, exchange.api)
	client.http.serviceToken = exchange.token
	client.http.forgetServiceToken = nil
	return exchange
}

func (self *evsTestExchange) answer(request *http.Request, body []byte) (*http.Response, error) {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return syntheticResponse(request, http.StatusBadRequest, `{"error":"invalid_request"}`, nil), nil
	}
	scope := form.Get("scope")
	answer := func() *evsTestExchangeAnswer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if scope != self.scope {
			return nil
		}
		self.scopeCount += 1
		if len(self.answers) == 0 {
			return nil
		}
		answer := self.answers[0]
		if !answer.repeats {
			self.answers = self.answers[1:]
		}
		return answer
	}()
	switch {
	case answer == nil:
		granted := fmt.Sprintf(`{"access_token":%q,"issued_token_type":"urn:ietf:params:oauth:token-type:access_token",`+
			`"token_type":"N_A","expires_in":900,"scope":%q}`, evsTestServiceToken, scope)
		return syntheticResponse(request, http.StatusOK, granted, nil), nil
	case answer.err != nil:
		return nil, answer.err
	}
	return syntheticResponse(request, answer.status, answer.body, answer.header), nil
}

func (self *evsTestExchange) token(ctx context.Context, resource string, scopes []string) (string, error) {
	token, err := self.api.ExchangeToken(ctx, resource, scopes)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// How many exchanges asked for the scope.
func (self *evsTestExchange) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.scopeCount
}

// An RFC 6749 refusal of the exchange's, as server/oauth's writeOauthError answers it, once.
func evsTestExchangeRefusal(status int, code string) *evsTestExchangeAnswer {
	return &evsTestExchangeAnswer{status: status, body: fmt.Sprintf(`{"error":%q,"error_description":"Synthetic description."}`, code)}
}

// The same refusal, answered to every exchange of the scope from then on.
func evsTestExchangeRefusedForGood(status int, code string) *evsTestExchangeAnswer {
	answer := evsTestExchangeRefusal(status, code)
	answer.repeats = true
	return answer
}

// The answer of a 429 or 5xx of the exchange's: its status and code, with Retry-After's delay-seconds, none for 0.
func evsTestExchangeWait(status int, code string, retryAfterSeconds int) *evsTestExchangeAnswer {
	answer := evsTestExchangeRefusal(status, code)
	if 0 < retryAfterSeconds {
		answer.header = http.Header{"Retry-After": {fmt.Sprintf("%d", retryAfterSeconds)}}
	}
	return answer
}

// The scope a test writer's uploads and pushes present.
func evsTestWriteScope(writer *evsTestWriter) string {
	return evsRepoScope(writer.world.repoId, evsScopeWrite)
}

// Whether the writer sent nothing to evs that its write scope's token would carry: no upload, no push.
func evsTestWriterSentNothing(t *testing.T, writer *evsTestWriter) bool {
	t.Helper()
	return len(writer.server.uploads) == 0 && len(writer.server.postedPushIds(t)) == 0 && len(writer.world.commits) == 0
}

// The brief's first case: an upload, and a push with no segment, whose write scope the exchange refuses 400
// invalid_grant end at once with that answer, after one exchange of the scope, with nothing waited and nothing sent
// to evs under it. evs's client asked again every ReadRetryWait, PushRetryCount times, before. invalid_scope's window
// is evs_refusal_window_test.go's.
func TestEvsWriteAnswersAnExchangeRefusalAfterOneExchange(t *testing.T) {
	contents := []struct {
		name    string
		content []byte
	}{
		{name: "upload", content: evsTestContent("refused upload", 64*1024)},
		{name: "push", content: []byte("refused push")},
	}
	for _, code := range []string{"invalid_grant"} {
		for _, c := range contents {
			writer := newEvsTestWriter(t)
			exchange := newEvsTestExchange(t, writer.test.client, evsTestWriteScope(writer), evsTestExchangeRefusedForGood(http.StatusBadRequest, code))
			_, err := writer.write(t, "a.txt", c.content)
			var apiErr *SidecarApiError
			if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest || apiErr.Code != code || apiErr.Route != "POST /oauth/token" {
				t.Errorf("%s %s: the write ended %v", c.name, code, err)
				continue
			}
			if _, ok := EvsErrorOf(err); ok || errors.Is(err, ErrEvsUnauthorized) {
				t.Errorf("%s %s: the exchange's refusal read as evs's: %v", c.name, code, err)
			}
			if count := exchange.count(); count != 1 {
				t.Errorf("%s %s: %d exchanges of the write scope", c.name, code, count)
			}
			if waits := writer.test.clock.waited(); len(waits) != 0 {
				t.Errorf("%s %s: waited %v", c.name, code, waits)
			}
			if !evsTestWriterSentNothing(t, writer) {
				t.Errorf("%s %s: %d uploads, %d pushes and %d commits", c.name, code, len(writer.server.uploads),
					len(writer.server.postedPushIds(t)), len(writer.world.commits))
			}
			if strings.Contains(err.Error(), testByJwt) || strings.Contains(err.Error(), "Synthetic description") {
				t.Errorf("%s %s: the error repeats the subject token or api's text: %v", c.name, code, err)
			}
		}
	}
}

// Every answer of the exchange's but a 429, a 5xx or invalid_scope refuses the same request whatever the wait (§7.8),
// and so does a request SidecarApi cannot ask as given or a 2xx that is not the exchange's: each ends a push's post
// after at most one exchange, sending nothing to evs and waiting nothing, with its own reason.
func TestEvsRetryAnswersEveryDefinitiveExchangeRefusalAtOnce(t *testing.T) {
	cases := []struct {
		name   string
		answer *evsTestExchangeAnswer
		// the evs url the client presents as the token's audience, the test's when empty
		evsUrl string
		// the exchanges the scope takes: 0 where nothing is sent
		exchanges int
		check     func(err error) bool
	}{
		{name: "invalid_grant", answer: evsTestExchangeRefusedForGood(400, "invalid_grant"), exchanges: 1},
		{name: "invalid_request", answer: evsTestExchangeRefusedForGood(400, "invalid_request"), exchanges: 1},
		{name: "invalid_target", answer: evsTestExchangeRefusedForGood(400, "invalid_target"), exchanges: 1},
		{name: "restore_required", answer: evsTestExchangeRefusedForGood(400, SidecarApiCodeRestoreRequired), exchanges: 1},
		// api's clock is where the proof was signed, so SidecarApi's own retry on it is not taken
		{name: "invalid_dpop_proof", answer: evsTestExchangeRefusedForGood(400, sidecarApiCodeInvalidDpopProof), exchanges: 1},
		// route_authz's plain-text refusal of a strict_exp bearer, with no code
		{name: "plain 403", answer: &evsTestExchangeAnswer{status: 403, body: "A sidecar token cannot call this route.", repeats: true}, exchanges: 1},
		{name: "401", answer: evsTestExchangeRefusedForGood(401, "invalid_client"), exchanges: 1},
		{name: "not the exchange's 2xx", answer: &evsTestExchangeAnswer{status: 200, body: `{}`, repeats: true}, exchanges: 1,
			check: func(err error) bool { return errors.Is(err, ErrSidecarApiReply) }},
		// the api's own audience, which the exchange never issues: refused before sending
		{name: "api audience", evsUrl: "https://api.example", exchanges: 0,
			check: func(err error) bool { return errors.Is(err, ErrSidecarApiArgs) }},
	}
	repoId := evsTestId("repo")
	scope := evsRepoScope(repoId, evsScopeWrite)
	for _, c := range cases {
		evsCount := 0
		test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			evsCount += 1
			writer.WriteHeader(http.StatusOK)
		}), newEvsTestStore(t))
		if c.evsUrl != "" {
			test.client.http.baseUrl = c.evsUrl
		}
		answers := []*evsTestExchangeAnswer{}
		if c.answer != nil {
			answers = append(answers, c.answer)
		}
		exchange := newEvsTestExchange(t, test.client, scope, answers...)
		call := &evsCall{route: "POST /evs/v1/repos/{repo_id}/push", method: http.MethodPost,
			path: "/evs/v1/repos/" + evsUrlId(repoId) + "/push", repoId: repoId, role: evsScopeWrite,
			body: &protocol.EvsPushRequest{Statement: []byte("statement")}}
		ctx := context.Background()
		err := test.client.retryRefusingNothing(ctx, func() error { return test.client.http.callMessage(ctx, call, nil) })
		if c.check != nil {
			if !c.check(err) {
				t.Errorf("%s: ended %v", c.name, err)
			}
		} else {
			var apiErr *SidecarApiError
			if !errors.As(err, &apiErr) || apiErr.Status != c.answer.status {
				t.Errorf("%s: ended %v", c.name, err)
			}
		}
		if count := exchange.count(); count != c.exchanges || evsCount != 0 {
			t.Errorf("%s: %d exchanges, %d evs requests", c.name, count, evsCount)
		}
		if waits := test.clock.waited(); len(waits) != 0 {
			t.Errorf("%s: waited %v", c.name, waits)
		}
	}
}

// The brief's second case: the exchange's 5xx refuses nothing, its 503 temporarily_unavailable, its 500 server_error
// and the lb's 502 or 504 alike, and so does no answer from api at all: the upload or push goes again after
// ReadRetryWait each time, presenting a token once the exchange grants one, and the write commits once.
func TestEvsWriteRetriesAnExchangeUnavailableThenCommits(t *testing.T) {
	answers := []struct {
		name   string
		answer *evsTestExchangeAnswer
	}{
		{name: "503", answer: evsTestExchangeWait(503, "temporarily_unavailable", 0)},
		{name: "500", answer: evsTestExchangeWait(500, "server_error", 0)},
		{name: "lb 502", answer: &evsTestExchangeAnswer{status: 502, body: evsTestLbBadGatewayPage,
			header: http.Header{"Content-Type": {"text/html"}}}},
		{name: "lb 504", answer: &evsTestExchangeAnswer{status: 504, body: evsTestLbGatewayTimeoutPage,
			header: http.Header{"Content-Type": {"text/html"}}}},
		{name: "no answer", answer: &evsTestExchangeAnswer{err: errors.New("synthetic connection reset")}},
	}
	contents := []struct {
		name    string
		content []byte
	}{
		{name: "upload", content: evsTestContent("unavailable upload", 64*1024)},
		{name: "push", content: []byte("unavailable push")},
	}
	for _, a := range answers {
		for _, c := range contents {
			writer := newEvsTestWriter(t)
			exchange := newEvsTestExchange(t, writer.test.client, evsTestWriteScope(writer), a.answer, a.answer)
			result, err := writer.write(t, "a.txt", c.content)
			if err != nil {
				t.Errorf("%s %s: %v", a.name, c.name, err)
				continue
			}
			// the upload's two refused exchanges and its granted one; the push's own, which no segment precedes
			wantCount := 3
			if c.name == "upload" {
				// and the push's, after the upload's grant
				wantCount = 4
			}
			if count := exchange.count(); count != wantCount {
				t.Errorf("%s %s: %d exchanges of the write scope", a.name, c.name, count)
			}
			retryWait := writer.test.client.settings.ReadRetryWait
			if waits := writer.test.clock.waited(); !slices.Equal(waits, []time.Duration{retryWait, retryWait}) {
				t.Errorf("%s %s: waits %v, not ReadRetryWait twice", a.name, c.name, waits)
			}
			if pushIds := writer.server.postedPushIds(t); len(pushIds) != 1 || pushIds[0] != result.PushId || len(writer.world.commits) != 1 {
				t.Errorf("%s %s: pushes %v, %d commits", a.name, c.name, pushIds, len(writer.world.commits))
			}
			if c.name == "upload" && len(writer.server.uploads) != 1 {
				t.Errorf("%s %s: %d uploads", a.name, c.name, len(writer.server.uploads))
			}
			if read, _, err := writer.read(t, "a.txt"); err != nil || string(read) != string(c.content) {
				t.Errorf("%s %s: read back: %v", a.name, c.name, err)
			}
		}
	}
}

// The brief's second case's bound: an exchange that answers 503 on every try ends the upload after PushRetryCount
// tries again, PushRetryCount+1 exchanges in all with ReadRetryWait between each, answering the 503 itself at once
// after the last: the loop waited once more after it before, for nothing, PushRetryCount+1 waits in all.
func TestEvsWriteRetriesAnExchangeUnavailableWithinTheBound(t *testing.T) {
	writer := newEvsTestWriter(t)
	settings := writer.test.client.settings
	settings.PushRetryCount = 3
	unavailable := []*evsTestExchangeAnswer{}
	for range settings.PushRetryCount + 2 {
		unavailable = append(unavailable, evsTestExchangeWait(503, "temporarily_unavailable", 0))
	}
	exchange := newEvsTestExchange(t, writer.test.client, evsTestWriteScope(writer), unavailable...)
	_, err := writer.write(t, "a.txt", evsTestContent("unavailable upload", 64*1024))
	var apiErr *SidecarApiError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusServiceUnavailable || apiErr.Code != "temporarily_unavailable" {
		t.Fatalf("the write ended %v", err)
	}
	if count := exchange.count(); count != settings.PushRetryCount+1 {
		t.Errorf("%d exchanges of the write scope, not PushRetryCount+1", count)
	}
	waits := writer.test.clock.waited()
	if len(waits) != settings.PushRetryCount || slices.ContainsFunc(waits, func(wait time.Duration) bool { return wait != settings.ReadRetryWait }) {
		t.Errorf("waits %v, not ReadRetryWait PushRetryCount times", waits)
	}
	if !evsTestWriterSentNothing(t, writer) {
		t.Errorf("%d uploads, %d commits", len(writer.server.uploads), len(writer.world.commits))
	}
}

// The brief's third case: the exchange's 429 waits its retry-after, Retry-After's seconds or the body's retry_after_ms,
// and ReadRetryWait where it names none; a 503's Retry-After is waited alike. The write then commits once.
func TestEvsWriteWaitsAnExchangeRetryAfter(t *testing.T) {
	cases := []struct {
		name   string
		answer *evsTestExchangeAnswer
		// the wait, ReadRetryWait for 0
		wait time.Duration
	}{
		{name: "429 Retry-After", answer: evsTestExchangeWait(429, "temporarily_unavailable", 7), wait: 7 * time.Second},
		{name: "429 retry_after_ms", answer: &evsTestExchangeAnswer{status: 429,
			body: `{"error":"temporarily_unavailable","retry_after_ms":2500}`}, wait: 2500 * time.Millisecond},
		{name: "429 naming none", answer: evsTestExchangeWait(429, "temporarily_unavailable", 0)},
		{name: "503 Retry-After", answer: evsTestExchangeWait(503, "temporarily_unavailable", 5), wait: 5 * time.Second},
	}
	contents := []struct {
		name    string
		content []byte
	}{
		{name: "upload", content: evsTestContent("waited upload", 64*1024)},
		{name: "push", content: []byte("waited push")},
	}
	for _, c := range cases {
		for _, content := range contents {
			writer := newEvsTestWriter(t)
			wait := c.wait
			if wait == 0 {
				wait = writer.test.client.settings.ReadRetryWait
			}
			exchange := newEvsTestExchange(t, writer.test.client, evsTestWriteScope(writer), c.answer)
			if _, err := writer.write(t, "a.txt", content.content); err != nil {
				t.Errorf("%s %s: %v", c.name, content.name, err)
				continue
			}
			if waits := writer.test.clock.waited(); !slices.Equal(waits, []time.Duration{wait}) {
				t.Errorf("%s %s: waits %v, not %s", c.name, content.name, waits, wait)
			}
			// the refused exchange and the granted one, and the push's own after an upload
			wantCount := 2
			if content.name == "upload" {
				wantCount = 3
			}
			if count := exchange.count(); count != wantCount || len(writer.world.commits) != 1 {
				t.Errorf("%s %s: %d exchanges, %d commits", c.name, content.name, count, len(writer.world.commits))
			}
		}
	}
}

// A 429 or 5xx asking a longer wait than PushRetryMaxWait ends the write at once with that answer, its wait in it: an
// exchange before api's wait is over meets the same answer, so none is made, and nothing is waited.
func TestEvsWriteAnswersAnExchangeWaitPastPushRetryMaxWait(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		writer := newEvsTestWriter(t)
		retryAfterSeconds := int(writer.test.client.settings.PushRetryMaxWait/time.Second) + 1
		exchange := newEvsTestExchange(t, writer.test.client, evsTestWriteScope(writer),
			evsTestExchangeWait(status, "temporarily_unavailable", retryAfterSeconds))
		_, err := writer.write(t, "a.txt", evsTestContent("long wait", 64*1024))
		var apiErr *SidecarApiError
		if !errors.As(err, &apiErr) || apiErr.Status != status || apiErr.RetryAfterMs != uint32(retryAfterSeconds*1000) {
			t.Errorf("%d: the write ended %v", status, err)
			continue
		}
		if count := exchange.count(); count != 1 {
			t.Errorf("%d: %d exchanges", status, count)
		}
		if waits := writer.test.clock.waited(); len(waits) != 0 {
			t.Errorf("%d: waited %v", status, waits)
		}
		if !evsTestWriterSentNothing(t, writer) {
			t.Errorf("%d: %d uploads, %d commits", status, len(writer.server.uploads), len(writer.world.commits))
		}
	}
}

// An exchange refusal that ends a push's post while evs's own 503 of unknown outcome was being resolved ends it as
// well: the second attempt's token is refused invalid_grant, a client revoked between the attempts, and the post
// answers that refusal after the one wait, with no third attempt.
func TestEvsRetryEndsAtAnExchangeRefusalAfterAnUnknownOutcome(t *testing.T) {
	repoId := evsTestId("repo")
	pushId := evsTestId("push")
	unknown := &protocol.EvsRefusalReply{PushId: pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE,
		Outcome: protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN}
	evs := evsRefusingHandler(t, http.StatusServiceUnavailable, unknown, nil)
	evsCount := 0
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		evsCount += 1
		evs.ServeHTTP(writer, request)
	}), newEvsTestStore(t))
	// the first exchange grants, the second refuses
	exchange := newEvsTestExchange(t, test.client, evsRepoScope(repoId, evsScopeWrite))
	call := &evsCall{route: "POST /evs/v1/repos/{repo_id}/push", method: http.MethodPost,
		path: "/evs/v1/repos/" + evsUrlId(repoId) + "/push", repoId: repoId, role: evsScopeWrite,
		body: &protocol.EvsPushRequest{Statement: []byte("statement")}}
	ctx := context.Background()
	attempts := 0
	err := test.client.retryRefusingNothing(ctx, func() error {
		attempts += 1
		if attempts == 2 {
			func() {
				exchange.stateLock.Lock()
				defer exchange.stateLock.Unlock()
				exchange.answers = append(exchange.answers, evsTestExchangeRefusedForGood(http.StatusBadRequest, "invalid_grant"))
			}()
		}
		return test.client.http.callMessage(ctx, call, nil)
	})
	var apiErr *SidecarApiError
	if !errors.As(err, &apiErr) || apiErr.Code != "invalid_grant" {
		t.Fatalf("the post ended %v", err)
	}
	if attempts != 2 || exchange.count() != 2 || evsCount != 1 {
		t.Errorf("%d attempts, %d exchanges, %d evs requests", attempts, exchange.count(), evsCount)
	}
	if waits := test.clock.waited(); !slices.Equal(waits, []time.Duration{test.client.settings.ReadRetryWait}) {
		t.Errorf("waits %v", waits)
	}
}
