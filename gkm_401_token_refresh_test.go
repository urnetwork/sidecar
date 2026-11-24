// GkmApi's renewal of a token gkm answered 401 (gkm_api.go's file comment): the token keeper's contract has a caller
// drop a token a service refused and ask once more, as evs's client does on its 401 (owner decision 411). Each test
// runs GkmApi as the daemon builds it, from a Sidecar's own GkmApiArgs, so over the keeper itself, whose
// GrantedServiceToken keeps a token for its scope set and whose ForgetServiceToken drops one, with a scripted api
// exchange and a fake gkm behind the one transport SidecarApi carries both on. These run on every leg, the
// sidecar_http page Worker's included.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// What the scripted api answers an exchange in place of a token: a status and a body.
type gkmTokenRenewRefusal struct {
	status int
	body   string
}

// One request gkm took: its method and path, the token it bore, its body and the status gkm answered.
type gkmTokenRenewRequest struct {
	route  string
	token  string
	body   []byte
	status int
}

// A Sidecar's token keeper and a GkmApi from its GkmApiArgs, over a scripted api exchange and a fake gkm behind one
// transport. api grants each exchange every scope asked under a new token, which the keeper keeps for the scope set,
// unless a test queued a refusal for it. gkm answers 401 to a token a test marked as no longer authenticating there,
// past its life by gkm's clock or signed under a key gkm retired, and to every token once rev/ voids the subject;
// where a test has it refuse batches, 403 to a token of more than one scope, as gkm's guard answers a batch's stronger
// role its state does not give (QD-1179); and 200 with no body to every other. Safe for concurrent use.
type gkmTokenRenewWorld struct {
	t       *testing.T
	clock   *gkmTestClock
	sidecar *Sidecar
	api     *GkmApi
	repoId  Id
	groupId Id

	stateLock sync.Mutex
	// api's answers to the next exchanges in place of a token, one each
	refusals []*gkmTokenRenewRefusal
	// how many exchanges api took, refused ones included
	exchangeCount int
	// each token api minted, with the scopes it granted
	tokenScopes map[string][]string
	// the tokens gkm no longer authenticates
	expiredTokens map[string]bool
	// whether rev/ voids the subject, so gkm refuses every token
	voided bool
	// whether gkm refuses a token of more than one scope 403
	refuseBatches bool
	requests      []*gkmTokenRenewRequest
}

// A world whose GkmApi comes from the Sidecar's own GkmApiArgs, as the daemon's and a member replica's do, holding the
// repo's rw scope, with otherScopes beside it, as a verified state gives them.
func newGkmTokenRenewWorld(t *testing.T, otherScopes ...GkmRepoScope) *gkmTokenRenewWorld {
	t.Helper()
	clock := newGkmTestClock()
	settings := validSidecarSettings()
	settings.Clock = clock
	world := &gkmTokenRenewWorld{
		t:             t,
		clock:         clock,
		sidecar:       newSidecarBase(nil, settings),
		repoId:        NewId(),
		groupId:       NewId(),
		tokenScopes:   map[string][]string{},
		expiredTokens: map[string]bool{},
	}
	api, err := newSidecarApi(settings, world, testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(testByJwt)
	installTestDpopSigner(t, api)
	networkId := NewId()
	world.sidecar.sidecarApi = api
	world.sidecar.networkId = &networkId
	world.sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled})
	world.sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 1})
	args, err := world.sidecar.GkmApiArgs()
	if err != nil {
		t.Fatal(err)
	}
	world.api, err = NewGkmApi(args)
	if err != nil {
		t.Fatal(err)
	}
	world.api.SetRepoScopes(append([]GkmRepoScope{{RepoId: world.repoId, Role: GkmScopeRoleWrite}}, otherScopes...))
	return world
}

// api's exchange at auth.example, and gkm's routes at gkm.example.
func (self *gkmTokenRenewWorld) RoundTrip(request *http.Request) (*http.Response, error) {
	body := []byte{}
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	switch request.URL.Host {
	case "auth.example":
		return self.exchange(request, body)
	case "gkm.example":
		return self.serveGkm(request, body), nil
	}
	self.t.Errorf("a request to %s", request.URL.Host)
	return nil, errors.New("synthetic: no such host")
}

// api's token exchange: the next refusal queued, else a new token granting every scope asked.
func (self *gkmTokenRenewWorld) exchange(request *http.Request, body []byte) (*http.Response, error) {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.exchangeCount += 1
	if 0 < len(self.refusals) {
		refusal := self.refusals[0]
		self.refusals = self.refusals[1:]
		return syntheticResponse(request, refusal.status, refusal.body, nil), nil
	}
	token := fmt.Sprintf("synthetic-gkm-renew-token-%d", self.exchangeCount)
	self.tokenScopes[token] = strings.Fields(form.Get("scope"))
	return syntheticResponse(request, http.StatusOK, fmt.Sprintf(`{"access_token":%q,"expires_in":900,"scope":%q}`, token, form.Get("scope")), nil), nil
}

// gkm's guard on the token alone, then a 200 with no body.
func (self *gkmTokenRenewWorld) serveGkm(request *http.Request, body []byte) *http.Response {
	token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	scopes, minted := self.tokenScopes[token]
	status := http.StatusOK
	switch {
	case !minted || self.voided || self.expiredTokens[token]:
		status = http.StatusUnauthorized
	case self.refuseBatches && 1 < len(scopes):
		status = http.StatusForbidden
	}
	self.requests = append(self.requests, &gkmTokenRenewRequest{route: request.Method + " " + request.URL.Path, token: token, body: body, status: status})
	recorder := httptest.NewRecorder()
	recorder.WriteHeader(status)
	return recorder.Result()
}

// Every token api minted so far no longer authenticates at gkm: gkm's clock passed its life, or its key retired.
func (self *gkmTokenRenewWorld) expireTokens() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for token := range self.tokenScopes {
		self.expiredTokens[token] = true
	}
}

// rev/ voids the subject: gkm refuses every token from now on.
func (self *gkmTokenRenewWorld) void() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.voided = true
}

// gkm refuses a token of more than one scope 403 from now on.
func (self *gkmTokenRenewWorld) refuseBatchesFromNow() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refuseBatches = true
}

// api answers the next exchange status with body in place of a token.
func (self *gkmTokenRenewWorld) refuseExchange(status int, body string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refusals = append(self.refusals, &gkmTokenRenewRefusal{status: status, body: body})
}

// How many exchanges api took.
func (self *gkmTokenRenewWorld) exchanges() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.exchangeCount
}

// How many requests gkm took.
func (self *gkmTokenRenewWorld) requestCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.requests)
}

// The requests gkm took after the first start.
func (self *gkmTokenRenewWorld) requestsSince(start int) []*gkmTokenRenewRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*gkmTokenRenewRequest{}, self.requests[start:]...)
}

// A read of the repo's group.
func (self *gkmTokenRenewWorld) read() error {
	_, err := self.api.Group(context.Background(), self.repoId, self.groupId)
	return err
}

// A write: a commit of epoch 3 with a body.
func (self *gkmTokenRenewWorld) write() error {
	return self.api.CommitEpoch(context.Background(), self.repoId, self.groupId, 3, &protocol.GkmEpochRequest{Commit: []byte("synthetic commit")})
}

// Whether a wait was armed on the clock, which no renewal takes.
func (self *gkmTokenRenewWorld) waited() bool {
	return 0 < len(self.clock.armed)
}

// The statuses of requests, in order.
func gkmTokenRenewStatuses(requests []*gkmTokenRenewRequest) []int {
	statuses := []int{}
	for _, request := range requests {
		statuses = append(statuses, request.status)
	}
	return statuses
}

// A token the keeper keeps, which gkm no longer authenticates (past its life by gkm's clock, which runs ahead of this
// device's, or signed under a key gkm retired), is dropped at gkm's 401, and the call goes once more at once under a
// token minted after it: a read lands after one more exchange, and the next call presents the new token, which the
// keeper kept, asking the exchange nothing; a write lands too, sending its same bytes again. No wait is armed. The code
// before ended each call with ErrGkmTokenRefused at the first 401 and dropped nothing, so every call met the kept token
// again until the keeper's cache let it go.
func TestGkmApiRenewsATokenGkmNoLongerAuthenticates(t *testing.T) {
	world := newGkmTokenRenewWorld(t)
	if err := world.read(); err != nil {
		t.Fatalf("the first read: %v", err)
	}
	if count := world.exchanges(); count != 1 {
		t.Fatalf("the first read took %d exchanges", count)
	}
	world.expireTokens()

	start := world.requestCount()
	if err := world.read(); err != nil {
		t.Fatalf("a read under a token gkm no longer authenticates: %v", err)
	}
	requests := world.requestsSince(start)
	if statuses := gkmTokenRenewStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusOK {
		t.Fatalf("gkm answered the read %v", statuses)
	}
	if requests[0].token == requests[1].token {
		t.Errorf("the read went again under the token gkm refused")
	}
	if count := world.exchanges(); count != 2 {
		t.Errorf("the read's renewal took %d exchanges in all", count)
	}
	renewed := requests[1].token

	start = world.requestCount()
	if err := world.read(); err != nil {
		t.Fatalf("the read after the renewal: %v", err)
	}
	if requests := world.requestsSince(start); len(requests) != 1 || requests[0].token != renewed {
		t.Errorf("the read after the renewal went %d times, under the renewed token: %t", len(requests), len(requests) == 1 && requests[0].token == renewed)
	}
	if count := world.exchanges(); count != 2 {
		t.Errorf("the keeper did not keep the renewed token: %d exchanges", count)
	}

	world.expireTokens()
	start = world.requestCount()
	if err := world.write(); err != nil {
		t.Fatalf("a write under a token gkm no longer authenticates: %v", err)
	}
	requests = world.requestsSince(start)
	if statuses := gkmTokenRenewStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusOK {
		t.Fatalf("gkm answered the write %v", statuses)
	}
	if requests[0].token == requests[1].token || len(requests[0].body) == 0 || !bytes.Equal(requests[0].body, requests[1].body) {
		t.Errorf("the write did not go again with its same bytes under a new token")
	}
	if count := world.exchanges(); count != 3 {
		t.Errorf("%d exchanges in all", count)
	}
	if world.waited() {
		t.Error("a renewal waited on the clock")
	}
}

// gkm's 401 to the token the call minted after its first is a refusal for good: rev/ voids the subject. A read, which
// retries gkm's 429 and 503, and a write each end with ErrGkmTokenRefused after exactly two requests, the second under
// a new token, and one more exchange, with no wait, and gkmTokenRefused reads it so, never KF7's unreachability. Each
// call renews once: the write presents the token the read's renewal left kept, and renews it again.
func TestGkmApiEndsACallWhoseRenewedTokenGkmRefuses(t *testing.T) {
	world := newGkmTokenRenewWorld(t)
	if err := world.read(); err != nil {
		t.Fatalf("the first read: %v", err)
	}
	world.void()
	ctx := context.Background()
	for _, call := range []struct {
		name string
		do   func() error
	}{
		{name: "a read", do: world.read},
		{name: "a write", do: world.write},
	} {
		start := world.requestCount()
		exchangesBefore := world.exchanges()
		err := call.do()
		if !errors.Is(err, ErrGkmTokenRefused) || !gkmTokenRefused(err) || gkmUnreachable(ctx, err) {
			t.Errorf("%s ended with %v, a refusal for good: %t, unreachable: %t", call.name, err, gkmTokenRefused(err), gkmUnreachable(ctx, err))
		}
		requests := world.requestsSince(start)
		if statuses := gkmTokenRenewStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusUnauthorized {
			t.Errorf("gkm answered %s %v", call.name, statuses)
			continue
		}
		if requests[0].token == requests[1].token {
			t.Errorf("%s went again under the token gkm refused", call.name)
		}
		if exchanges := world.exchanges() - exchangesBefore; exchanges != 1 {
			t.Errorf("%s asked the exchange %d times", call.name, exchanges)
		}
	}
	if world.waited() {
		t.Error("a renewal waited on the clock")
	}
}

// The token a call asks for after gkm's 401 is read by why it could not be had, as every other is: the exchange's
// invalid_grant, api's gate holding the device's revocation too, ends the call at once with that refusal, a token
// refused for good, nothing more reaching gkm; api's 503 goes again ReadRetryWait later, and the call lands under the
// token minted then; and for a call no verified state backs, the scopes an unconfirmed state's, api's 503 ends it at
// once, a token the keeper cannot have for now, which KF7 reads as gkm unreachable.
func TestGkmApiReadsTheRenewalsTokenFailureByWhy(t *testing.T) {
	ctx := context.Background()
	world := newGkmTokenRenewWorld(t)
	if err := world.read(); err != nil {
		t.Fatalf("the first read: %v", err)
	}
	world.expireTokens()
	world.refuseExchange(http.StatusBadRequest, `{"error":"invalid_grant"}`)
	start := world.requestCount()
	exchangesBefore := world.exchanges()
	err := world.write()
	var apiError *SidecarApiError
	if !errors.As(err, &apiError) || apiError.Code != "invalid_grant" || !errors.Is(err, errGkmNoServiceToken) || errors.Is(err, ErrGkmTokenRefused) {
		t.Errorf("a write whose renewal met invalid_grant ended with %v", err)
	}
	if !gkmTokenRefused(err) || gkmUnreachable(ctx, err) {
		t.Errorf("invalid_grant after gkm's 401: a refusal for good %t, unreachable %t", gkmTokenRefused(err), gkmUnreachable(ctx, err))
	}
	if statuses := gkmTokenRenewStatuses(world.requestsSince(start)); len(statuses) != 1 || statuses[0] != http.StatusUnauthorized {
		t.Errorf("gkm answered the write %v", statuses)
	}
	if exchanges := world.exchanges() - exchangesBefore; exchanges != 1 {
		t.Errorf("the write asked the exchange %d times", exchanges)
	}
	if world.waited() {
		t.Error("invalid_grant waited on the clock")
	}

	// api's 503 refuses nothing: the renewal's exchange goes again a ReadRetryWait later
	if err := world.read(); err != nil {
		t.Fatalf("a read once api grants again: %v", err)
	}
	world.expireTokens()
	world.refuseExchange(http.StatusServiceUnavailable, `{}`)
	start = world.requestCount()
	exchangesBefore = world.exchanges()
	done := make(chan error, 1)
	go func() {
		done <- world.read()
	}()
	select {
	case wait := <-world.clock.armed:
		if wait != DefaultGkmSettings().ReadRetryWait {
			t.Errorf("the renewal's exchange waits %s after api's 503", wait)
		}
		world.clock.Advance(wait)
	case err := <-done:
		t.Fatalf("the read ended before its renewal's exchange went again: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("a read whose renewal met api's 503 once: %v", err)
	}
	requests := world.requestsSince(start)
	if statuses := gkmTokenRenewStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusOK || requests[0].token == requests[1].token {
		t.Errorf("gkm answered the read %v", statuses)
	}
	if exchanges := world.exchanges() - exchangesBefore; exchanges != 2 {
		t.Errorf("the read asked the exchange %d times", exchanges)
	}

	unconfirmed := newGkmTokenRenewWorld(t)
	unconfirmed.api.SetUnconfirmedRepoScopes([]GkmRepoScope{{RepoId: unconfirmed.repoId, Role: GkmScopeRoleWrite}})
	if err := unconfirmed.read(); err != nil {
		t.Fatalf("the first read under an unconfirmed state's scopes: %v", err)
	}
	unconfirmed.expireTokens()
	unconfirmed.refuseExchange(http.StatusServiceUnavailable, `{}`)
	start = unconfirmed.requestCount()
	err = unconfirmed.read()
	if !errors.As(err, &apiError) || apiError.Status != http.StatusServiceUnavailable || gkmTokenRefused(err) || !gkmUnreachable(ctx, err) {
		t.Errorf("an unconfirmed state's read whose renewal met api's 503 ended with %v", err)
	}
	if statuses := gkmTokenRenewStatuses(unconfirmed.requestsSince(start)); len(statuses) != 1 || statuses[0] != http.StatusUnauthorized {
		t.Errorf("gkm answered the unconfirmed state's read %v", statuses)
	}
	if unconfirmed.waited() {
		t.Error("a call no verified state backs waited on the clock")
	}
}

// A call that may narrow after its 401 presents only tokens minted after it (QD-1179's narrowed retry): with gkm
// refusing the batch's stronger role, a read on the repo goes under the batch, rw there, and then under its r scope
// alone, each token kept; once gkm no longer authenticates either, the read's 401 to the batch's token drops both, so
// the batch's new token meets the 403 and the r scope's new token lands. Kept, the r scope's old token would have
// met a second 401 and ended the read as a refusal for good, though gkm refused no token minted after its first.
func TestGkmApiRenewsTheNarrowedRetrysTokenWithTheBatchs(t *testing.T) {
	world := newGkmTokenRenewWorld(t, GkmRepoScope{RepoId: NewId(), Role: GkmScopeRoleRead})
	world.refuseBatchesFromNow()
	if err := world.read(); err != nil {
		t.Fatalf("the first read: %v", err)
	}
	first := world.requestsSince(0)
	if statuses := gkmTokenRenewStatuses(first); len(statuses) != 2 || statuses[0] != http.StatusForbidden || statuses[1] != http.StatusOK {
		t.Fatalf("gkm answered the first read %v", statuses)
	}
	world.expireTokens()

	start := world.requestCount()
	if err := world.read(); err != nil {
		t.Fatalf("a read narrowing after its 401: %v", err)
	}
	requests := world.requestsSince(start)
	statuses := gkmTokenRenewStatuses(requests)
	if len(statuses) != 3 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusForbidden || statuses[2] != http.StatusOK {
		t.Fatalf("gkm answered the read %v", statuses)
	}
	if requests[0].token != first[0].token || requests[1].token == first[0].token || requests[2].token == first[1].token {
		t.Errorf("the read did not present the batch's kept token and then new tokens alone")
	}
	if count := world.exchanges(); count != 4 {
		t.Errorf("%d exchanges in all", count)
	}
}
