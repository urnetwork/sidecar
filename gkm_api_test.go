// GkmApi's transport, scope batching and answers, and the late-delivery ask's pace, on a fake gkm reached through
// a RoundTripper, so these run on every leg, the sidecar_http page Worker's included (KEYS-M2-18).

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A clock a test moves, whose After and AfterFunc fire as it passes their time. Each After it arms is reported on
// armed, so a test can tell a wait has begun.
type gkmTestClock struct {
	stateLock sync.Mutex
	current   time.Time
	timers    []*gkmTestTimer
	armed     chan time.Duration
}

// One armed timer.
type gkmTestTimer struct {
	at       time.Time
	fire     func(at time.Time)
	stopped  bool
	finished bool
}

// A fixed date, so a test repeats.
func newGkmTestClock() *gkmTestClock {
	return &gkmTestClock{current: time.Date(2026, time.November, 9, 10, 0, 0, 0, time.UTC), armed: make(chan time.Duration, 1024)}
}

func (self *gkmTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.current
}

func (self *gkmTestClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	self.arm(timeout, func(at time.Time) { fired <- at })
	select {
	case self.armed <- timeout:
	default:
	}
	return fired
}

func (self *gkmTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	timer := self.arm(timeout, func(at time.Time) { go function() })
	return func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if timer.finished || timer.stopped {
			return false
		}
		timer.stopped = true
		return true
	}
}

// Arms a timer, firing it at once when timeout is not positive.
func (self *gkmTestClock) arm(timeout time.Duration, fire func(at time.Time)) *gkmTestTimer {
	self.stateLock.Lock()
	timer := &gkmTestTimer{at: self.current.Add(timeout), fire: fire}
	if 0 < timeout {
		self.timers = append(self.timers, timer)
		self.stateLock.Unlock()
		return timer
	}
	timer.finished = true
	now := self.current
	self.stateLock.Unlock()
	fire(now)
	return timer
}

// Moves the clock by and fires every timer it passes, in time order.
func (self *gkmTestClock) Advance(by time.Duration) {
	self.stateLock.Lock()
	self.current = self.current.Add(by)
	now := self.current
	due := []*gkmTestTimer{}
	remaining := []*gkmTestTimer{}
	for _, timer := range self.timers {
		switch {
		case timer.stopped:
		case !timer.at.After(now):
			timer.finished = true
			due = append(due, timer)
		default:
			remaining = append(remaining, timer)
		}
	}
	self.timers = remaining
	self.stateLock.Unlock()
	slices.SortStableFunc(due, func(a *gkmTestTimer, b *gkmTestTimer) int { return a.at.Compare(b.at) })
	for _, timer := range due {
		timer.fire(timer.at)
	}
}

// One request a fake gkm took: its route's method and path, and the token it bore.
type gkmTestRequest struct {
	method string
	path   string
	query  string
	token  string
	body   []byte
}

// A fake gkm behind a RoundTripper: answers with serve, records every request. Safe for concurrent use.
type gkmTestTransport struct {
	stateLock sync.Mutex
	requests  []*gkmTestRequest
	serve     func(request *gkmTestRequest) (status int, header http.Header, body []byte)
}

func (self *gkmTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body := []byte{}
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
	}
	recorded := &gkmTestRequest{
		method: request.Method,
		path:   request.URL.Path,
		query:  request.URL.RawQuery,
		token:  strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "),
		body:   body,
	}
	self.stateLock.Lock()
	self.requests = append(self.requests, recorded)
	serve := self.serve
	self.stateLock.Unlock()
	status, header, replyBody := http.StatusOK, http.Header{}, []byte{}
	if serve != nil {
		status, header, replyBody = serve(recorded)
	}
	recorder := httptest.NewRecorder()
	for name, values := range header {
		for _, value := range values {
			recorder.Header().Add(name, value)
		}
	}
	recorder.WriteHeader(status)
	recorder.Write(replyBody)
	return recorder.Result(), nil
}

// What was asked, in order.
func (self *gkmTestTransport) taken() []*gkmTestRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.requests)
}

// A fake token exchange: one token per scope set, cached as Sidecar.ServiceToken caches, each set recorded.
type gkmTestTokens struct {
	stateLock sync.Mutex
	setTokens map[string]string
	exchanges [][]string
}

func newGkmTestTokens() *gkmTestTokens {
	return &gkmTestTokens{setTokens: map[string]string{}}
}

func (self *gkmTestTokens) serviceToken(ctx context.Context, resource string, scopes []string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	key := strings.Join(sorted, " ")
	if token, ok := self.setTokens[key]; ok {
		return token, nil
	}
	if sidecarExchangeMaxRepoScopeCount < len(sorted) {
		return "", errors.New("more than 64 repo scopes in one exchange")
	}
	token := fmt.Sprintf("test-gkm-token-%d", len(self.exchanges))
	self.setTokens[key] = token
	self.exchanges = append(self.exchanges, sorted)
	return token, nil
}

// The scopes a token was issued for.
func (self *gkmTestTokens) scopesOf(token string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for key, issued := range self.setTokens {
		if issued == token {
			return strings.Fields(key)
		}
	}
	return nil
}

// A GkmApi on a fake gkm and token exchange.
func newGkmTestApi(t *testing.T, transport *gkmTestTransport, tokens *gkmTestTokens, clock Clock) *GkmApi {
	t.Helper()
	api, err := NewGkmApi(&GkmApiArgs{
		GkmUrl:       "https://gkm.example",
		Transport:    transport,
		ServiceToken: tokens.serviceToken,
		Clock:        clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return api
}

// n repo scopes of role, each repo a fresh id.
func gkmTestScopes(n int, role string) []GkmRepoScope {
	scopes := []GkmRepoScope{}
	for i := 0; i < n; i += 1 {
		scopes = append(scopes, GkmRepoScope{RepoId: NewId(), Role: role})
	}
	return scopes
}

// §7.8: at most 64 repo scopes an exchange, so 65 repos take 2 tokens and 300 take 5, and every call on a repo
// presents the one token whose batch holds that repo's scope.
func TestGkmApiBatchesRepoScopesSixtyFourAToken(t *testing.T) {
	for _, case_ := range []struct {
		repoCount  int
		tokenCount int
	}{
		{repoCount: 64, tokenCount: 1},
		{repoCount: 65, tokenCount: 2},
		{repoCount: 300, tokenCount: 5},
	} {
		transport := &gkmTestTransport{}
		tokens := newGkmTestTokens()
		api := newGkmTestApi(t, transport, tokens, nil)
		scopes := gkmTestScopes(case_.repoCount, GkmScopeRoleRead)
		api.SetRepoScopes(scopes)
		for _, scope := range scopes {
			if _, err := api.Group(context.Background(), scope.RepoId, NewId()); err != nil {
				t.Fatal(err)
			}
		}
		if len(tokens.exchanges) != case_.tokenCount {
			t.Errorf("%d repos: %d exchanges, want %d", case_.repoCount, len(tokens.exchanges), case_.tokenCount)
		}
		for i, request := range transport.taken() {
			if !slices.Contains(tokens.scopesOf(request.token), scopes[i].scope()) {
				t.Fatalf("%d repos: a call on a repo bore a token without its scope", case_.repoCount)
			}
		}
	}
}

// A call needing a stronger role than its repo's batch carries asks for that one scope alone; a role the batch
// covers rides the batch.
func TestGkmApiAsksAStrongerRoleAlone(t *testing.T) {
	transport := &gkmTestTransport{}
	tokens := newGkmTestTokens()
	api := newGkmTestApi(t, transport, tokens, nil)
	repoId := NewId()
	api.SetRepoScopes(append(gkmTestScopes(3, GkmScopeRoleWrite), GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleRead}))
	if err := api.CreateGroup(context.Background(), repoId, &protocol.GkmGroupCreateRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := tokens.scopesOf(transport.taken()[0].token); !slices.Equal(got, []string{GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleAdmin}.scope()}) {
		t.Errorf("the creation's token holds %v", got)
	}
	if _, err := api.DropKeys(context.Background(), repoId, 0); err != nil {
		t.Fatal(err)
	}
	if got := tokens.scopesOf(transport.taken()[1].token); len(got) != 4 {
		t.Errorf("a deposit route under an r scope took %v, not the batch", got)
	}
}

// A sidecar's own routes need an r, rw or admin scope on some repo (QD-177): a client holding only deposit scopes
// has none to present.
func TestGkmApiOwnRoutesNeedAnAccessScope(t *testing.T) {
	transport := &gkmTestTransport{}
	tokens := newGkmTestTokens()
	api := newGkmTestApi(t, transport, tokens, nil)
	if err := api.UploadReaderKey(context.Background(), &bridge.Signed{}); !errors.Is(err, ErrGkmNoScope) {
		t.Errorf("with no scope: %v", err)
	}
	api.SetRepoScopes(gkmTestScopes(2, GkmScopeRoleDeposit))
	if err := api.UploadReaderKey(context.Background(), &bridge.Signed{}); !errors.Is(err, ErrGkmNoScope) {
		t.Errorf("with deposit scopes alone: %v", err)
	}
	if len(transport.taken()) != 0 {
		t.Error("a call went out with no scope to present")
	}
	api.SetRepoScopes(append(gkmTestScopes(2, GkmScopeRoleDeposit), gkmTestScopes(1, GkmScopeRoleRead)...))
	if err := api.UploadReaderKey(context.Background(), &bridge.Signed{}); err != nil {
		t.Errorf("with an r scope: %v", err)
	}
}

// URLs carry ids as 32 lowercase hex characters and nothing else, and the token rides the Authorization header
// alone (I-7, I-13).
func TestGkmApiRequestsCarryOpaqueIdsAndTheTokenInItsHeader(t *testing.T) {
	transport := &gkmTestTransport{}
	tokens := newGkmTestTokens()
	api := newGkmTestApi(t, transport, tokens, nil)
	scopes := gkmTestScopes(1, GkmScopeRoleAdmin)
	api.SetRepoScopes(scopes)
	repoId := scopes[0].RepoId
	groupId := NewId()
	ctx := context.Background()
	commitment := bytes.Repeat([]byte{0xc8}, 32)
	calls := []func() error{
		func() error { _, err := api.Epochs(ctx, repoId, groupId, 7); return err },
		func() error { return api.CommitEpoch(ctx, repoId, groupId, 8, &protocol.GkmEpochRequest{}) },
		func() error { return api.ClaimGeneration(ctx, repoId, groupId, 2, &bridge.Signed{}) },
		func() error {
			_, err := api.UploadWraps(ctx, repoId, groupId, 2, commitment, &protocol.GkmWrapBatch{})
			return err
		},
		func() error {
			_, err := api.Wraps(ctx, repoId, groupId, 2, &GkmWrapsQuery{Recipient: "s:" + gkmUrlId(repoId), Want: commitment[:8], Since: time.UnixMilli(5)})
			return err
		},
		func() error { _, err := api.ReaderKey(ctx, groupId); return err },
	}
	for _, call := range calls {
		if err := call(); err != nil && !errors.Is(err, ErrGkmReplyInvalid) {
			t.Fatal(err)
		}
	}
	wantPaths := []string{
		"/gkm/groups/" + gkmUrlId(groupId) + "/epochs",
		"/gkm/groups/" + gkmUrlId(groupId) + "/epochs/8",
		"/gkm/groups/" + gkmUrlId(groupId) + "/gen/2",
		"/gkm/groups/" + gkmUrlId(groupId) + "/wraps/2/c8c8c8c8c8c8c8c8",
		"/gkm/groups/" + gkmUrlId(groupId) + "/wraps/2",
		"/gkm/reader-key/" + gkmUrlId(groupId),
	}
	for i, request := range transport.taken() {
		if request.path != wantPaths[i] {
			t.Errorf("path %s, want %s", request.path, wantPaths[i])
		}
		if strings.Contains(request.path+request.query, "test-gkm-token") || request.token == "" {
			t.Error("the token is not in its header alone")
		}
		if strings.Contains(request.path, groupId.String()) || strings.Contains(request.query, repoId.String()) {
			t.Errorf("an id in its dashed form in %s", request.path)
		}
	}
	if query := transport.taken()[4].query; query != "recipient=s%3A"+gkmUrlId(repoId)+"&since=5&want=c8c8c8c8c8c8c8c8" {
		t.Errorf("a late ask's query %s", query)
	}
}

// Answers map to typed errors: a 409's and a 412's winner, 401's refusal, a 404 ReaderKey as none, and a read's 503
// retried after its Retry-After where a write's is not.
func TestGkmApiMapsAnswers(t *testing.T) {
	clock := newGkmTestClock()
	winner := []byte("the winning GenRotate")
	transport := &gkmTestTransport{}
	unavailableCount := 0
	transport.serve = func(request *gkmTestRequest) (int, http.Header, []byte) {
		switch {
		case strings.HasSuffix(request.path, "/gen/2"):
			return http.StatusPreconditionFailed, nil, winner
		case strings.HasSuffix(request.path, "/epochs/3"):
			return http.StatusConflict, nil, []byte("the winning epoch")
		case strings.HasPrefix(request.path, "/gkm/reader-key/"):
			return http.StatusNotFound, nil, nil
		case strings.HasSuffix(request.path, "/ack"):
			return http.StatusUnauthorized, nil, nil
		case unavailableCount < 1:
			unavailableCount += 1
			return http.StatusServiceUnavailable, http.Header{"Retry-After": {"2"}}, nil
		}
		return http.StatusOK, nil, nil
	}
	api := newGkmTestApi(t, transport, newGkmTestTokens(), clock)
	scopes := gkmTestScopes(1, GkmScopeRoleWrite)
	api.SetRepoScopes(scopes)
	repoId, groupId := scopes[0].RepoId, NewId()
	ctx := context.Background()

	err := api.ClaimGeneration(ctx, repoId, groupId, 2, &bridge.Signed{})
	if gkmError, ok := GkmErrorOf(err); !ok || gkmError.Status != http.StatusPreconditionFailed || !bytes.Equal(gkmError.Winner, winner) {
		t.Errorf("a 412: %v", err)
	}
	err = api.CommitEpoch(ctx, repoId, groupId, 3, &protocol.GkmEpochRequest{})
	if gkmError, ok := GkmErrorOf(err); !ok || gkmError.Status != http.StatusConflict || string(gkmError.Winner) != "the winning epoch" {
		t.Errorf("a 409: %v", err)
	}
	if readerKey, err := api.ReaderKey(ctx, NewId()); err != nil || readerKey != nil {
		t.Errorf("a sidecar with no ReaderKey: %v %v", readerKey, err)
	}
	if err := api.Ack(ctx, repoId, groupId, 1); !errors.Is(err, ErrGkmTokenRefused) {
		t.Errorf("a 401: %v", err)
	}
	// a read's 503 waits its Retry-After on the clock, then goes again
	done := make(chan error, 1)
	go func() {
		_, err := api.Group(ctx, repoId, groupId)
		done <- err
	}()
	if wait := <-clock.armed; wait != 2*time.Second {
		t.Errorf("the retry waits %s", wait)
	}
	clock.Advance(2 * time.Second)
	if err := <-done; err != nil {
		t.Errorf("a read after its retry: %v", err)
	}
	// a write's 503 comes back at once
	unavailableCount = 0
	if err := api.UploadGroupInfo(ctx, repoId, groupId, &protocol.GkmGroupInfoObject{}); !IsGkmStatus(err, http.StatusServiceUnavailable) {
		t.Errorf("a write's 503: %v", err)
	}
}

// QD-747: HEAD welcome/<n> goes under rw with no body and opaque ids, and its status is the whole answer: a 200 is a
// Welcome that stands and a 404 one that does not; a refusal, or a success of another status, says nothing of the
// Welcome and is an error.
func TestGkmApiWelcomeStandsReadsTheHeadsStatus(t *testing.T) {
	transport := &gkmTestTransport{}
	status := http.StatusOK
	transport.serve = func(request *gkmTestRequest) (int, http.Header, []byte) {
		return status, nil, nil
	}
	tokens := newGkmTestTokens()
	api := newGkmTestApi(t, transport, tokens, nil)
	repoId, groupId := NewId(), NewId()
	api.SetRepoScopes(append(gkmTestScopes(2, GkmScopeRoleRead), GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleRead}))
	ctx := context.Background()
	if stands, err := api.WelcomeStands(ctx, repoId, groupId, 7); err != nil || !stands {
		t.Fatalf("a 200: %v %v", stands, err)
	}
	asked := transport.taken()[0]
	if asked.method != http.MethodHead || asked.path != "/gkm/groups/"+gkmUrlId(groupId)+"/welcome/7" || asked.query != "" || len(asked.body) != 0 {
		t.Errorf("the ask: %s %s, a body of %d bytes", asked.method, asked.path, len(asked.body))
	}
	// the batch carries r, so the ask takes the repo's rw scope alone
	if got := tokens.scopesOf(asked.token); !slices.Equal(got, []string{GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleWrite}.scope()}) {
		t.Errorf("the ask's token holds %v", got)
	}
	status = http.StatusNotFound
	if stands, err := api.WelcomeStands(ctx, repoId, groupId, 7); err != nil || stands {
		t.Errorf("a 404: %v %v", stands, err)
	}
	status = http.StatusForbidden
	if stands, err := api.WelcomeStands(ctx, repoId, groupId, 7); !IsGkmStatus(err, http.StatusForbidden) || stands {
		t.Errorf("a 403: %v %v", stands, err)
	}
	status = http.StatusCreated
	if stands, err := api.WelcomeStands(ctx, repoId, groupId, 7); !errors.Is(err, ErrGkmReplyInvalid) || stands {
		t.Errorf("a 201: %v %v", stands, err)
	}
}

// GET /gkm/welcomes answers per token, so the client asks with each batch and takes each Welcome once, by its
// pointer's group and epoch.
func TestGkmApiWelcomesAskWithEachToken(t *testing.T) {
	transport := &gkmTestTransport{}
	tokens := newGkmTestTokens()
	scopes := gkmTestScopes(70, GkmScopeRoleRead)
	sharedGroupId := NewId()
	transport.serve = func(request *gkmTestRequest) (int, http.Header, []byte) {
		// each token's answer: its batch's own Welcome, and one both batches reach
		ownGroupId := sha256.Sum256([]byte(request.token))
		reply := &protocol.GkmWelcomesReply{Welcomes: []*protocol.GkmWelcomeEntry{
			{KeyPackageRef: []byte("shared"), Pointer: &protocol.GkmWelcomePointer{GroupId: sharedGroupId.Bytes(), Epoch: 1}, Welcome: []byte("w")},
			{KeyPackageRef: []byte(request.token), Pointer: &protocol.GkmWelcomePointer{GroupId: ownGroupId[:16], Epoch: 1}, Welcome: []byte("w")},
		}}
		body, _ := proto.Marshal(reply)
		return http.StatusOK, nil, body
	}
	api := newGkmTestApi(t, transport, tokens, nil)
	api.SetRepoScopes(scopes)
	welcomes, err := api.Welcomes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(transport.taken()) != 2 || len(welcomes) != 3 {
		t.Errorf("%d calls and %d Welcomes, want 2 and 3", len(transport.taken()), len(welcomes))
	}
}

// DESIGN-DETAILS 6.2.2's pointer row: one last-resort KeyPackage served Adds in two groups, so two Welcomes carry one
// KeyPackageRef, and the client takes both; one group's Welcome a second token also reaches is taken once.
func TestGkmApiWelcomesKeepOneKeyPackagesWelcomesInTwoGroups(t *testing.T) {
	transport := &gkmTestTransport{}
	tokens := newGkmTestTokens()
	scopes := gkmTestScopes(70, GkmScopeRoleRead)
	firstGroupId, secondGroupId := NewId(), NewId()
	transport.serve = func(request *gkmTestRequest) (int, http.Header, []byte) {
		reply := &protocol.GkmWelcomesReply{Welcomes: []*protocol.GkmWelcomeEntry{
			{KeyPackageRef: []byte("last-resort"), Pointer: &protocol.GkmWelcomePointer{GroupId: firstGroupId.Bytes(), Epoch: 1}, Welcome: []byte("w1")},
			{KeyPackageRef: []byte("last-resort"), Pointer: &protocol.GkmWelcomePointer{GroupId: secondGroupId.Bytes(), Epoch: 4}, Welcome: []byte("w2")},
		}}
		body, _ := proto.Marshal(reply)
		return http.StatusOK, nil, body
	}
	api := newGkmTestApi(t, transport, tokens, nil)
	api.SetRepoScopes(scopes)
	welcomes, err := api.Welcomes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(welcomes) != 2 || string(welcomes[0].GetWelcome()) != "w1" || string(welcomes[1].GetWelcome()) != "w2" {
		t.Errorf("the Welcomes of one KeyPackage in two groups: %d", len(welcomes))
	}
}

// §10.6's late wraps: a recipient asks at most once a LateAskInterval for a generation, its since its first ask's,
// and starts afresh once the delivery came.
func TestGkmLateAsksKeepTheirPaceAndSince(t *testing.T) {
	asks := NewGkmLateAsks(nil)
	groupId := NewId()
	start := time.Date(2026, time.November, 9, 0, 0, 0, 0, time.UTC)
	since, ok := asks.Ask(groupId, 4, "s:aa", start)
	if !ok || !since.Equal(start) {
		t.Fatal("the first ask")
	}
	if _, ok := asks.Ask(groupId, 4, "s:aa", start.Add(59*time.Second)); ok {
		t.Error("a second ask within the minute")
	}
	if _, ok := asks.Ask(groupId, 4, "s:bb", start.Add(59*time.Second)); !ok {
		t.Error("another recipient's ask")
	}
	since, ok = asks.Ask(groupId, 4, "s:aa", start.Add(time.Minute))
	if !ok || !since.Equal(start) {
		t.Errorf("the next minute's ask: %v since %s", ok, since)
	}
	asks.Done(groupId, 4, "s:aa")
	if since, ok := asks.Ask(groupId, 4, "s:aa", start.Add(61*time.Second)); !ok || !since.Equal(start.Add(61*time.Second)) {
		t.Error("an ask after its delivery did not start afresh")
	}
}

// nginx's error page for status with its headers, as the lb answers when its tries at gkm's blocks failed or timed
// out.
func gkmTestLbAnswer(status int) (int, http.Header, []byte) {
	text := fmt.Sprintf("%d %s", status, http.StatusText(status))
	page := "<html>\r\n<head><title>" + text + "</title></head>\r\n<body>\r\n<center><h1>" + text + "</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	return status, http.Header{"Content-Type": {"text/html"}, "Server": {"nginx"}}, []byte(page)
}

// QD-876: a 502 or 504 is the lb's answer and no answer from gkm at all, so it is ErrGkmNoAnswer and never a
// *GkmError, on a read, a write and the Welcome's HEAD alike. A read does not go again on it, as it does not on a
// transport error; nothing of nginx's page reaches the error; and a page past the reply bound is still no answer,
// not an invalid reply.
func TestGkmApiReadsTheLbs502And504AsNoAnswer(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusGatewayTimeout} {
		clock := newGkmTestClock()
		transport := &gkmTestTransport{}
		transport.serve = func(request *gkmTestRequest) (int, http.Header, []byte) {
			return gkmTestLbAnswer(status)
		}
		api := newGkmTestApi(t, transport, newGkmTestTokens(), clock)
		scopes := gkmTestScopes(1, GkmScopeRoleWrite)
		api.SetRepoScopes(scopes)
		repoId, groupId := scopes[0].RepoId, NewId()
		ctx := context.Background()

		noAnswer := func(name string, err error) {
			t.Helper()
			if !errors.Is(err, ErrGkmNoAnswer) {
				t.Fatalf("%d: %s: %v", status, name, err)
			}
			if gkmError, refused := GkmErrorOf(err); refused {
				t.Errorf("%d: %s read as gkm's refusal: %+v", status, name, gkmError)
			}
			if errors.Is(err, ErrGkmReplyInvalid) || errors.Is(err, ErrGkmTokenRefused) {
				t.Errorf("%d: %s read as another answer: %v", status, name, err)
			}
			if text := err.Error(); strings.Contains(text, "nginx") || strings.Contains(text, "html") || strings.Contains(text, "gkm.example") || strings.Contains(text, "test-gkm-token") {
				t.Errorf("%d: %s: the error repeats the answer or the request: %s", status, name, text)
			}
		}

		_, err := api.Group(ctx, repoId, groupId)
		noAnswer("a read", err)
		if count := len(transport.taken()); count != 1 {
			t.Errorf("%d: a read was sent %d times", status, count)
		}
		select {
		case wait := <-clock.armed:
			t.Errorf("%d: a read waited %s to go again", status, wait)
		default:
		}
		noAnswer("a commit", api.CommitEpoch(ctx, repoId, groupId, 3, &protocol.GkmEpochRequest{}))
		noAnswer("a claim", api.ClaimGeneration(ctx, repoId, groupId, 2, &bridge.Signed{}))
		noAnswer("a creation", api.CreateGroup(ctx, repoId, &protocol.GkmGroupCreateRequest{}))
		stands, err := api.WelcomeStands(ctx, repoId, groupId, 7)
		noAnswer("the Welcome's ask", err)
		if stands {
			t.Errorf("%d: a Welcome stands by the lb's answer", status)
		}
		// a read whose 404 means none
		readerKey, err := api.ReaderKey(ctx, NewId())
		noAnswer("a ReaderKey's read", err)
		if readerKey != nil {
			t.Errorf("%d: a ReaderKey by the lb's answer", status)
		}

		// a page past the reply bound: its body is never read
		settings := DefaultGkmSettings()
		settings.ReplyMaxByteCount = 16
		bounded, err := NewGkmApi(&GkmApiArgs{GkmUrl: "https://gkm.example", Transport: transport, ServiceToken: newGkmTestTokens().serviceToken, Settings: settings, Clock: clock})
		if err != nil {
			t.Fatal(err)
		}
		bounded.SetRepoScopes(scopes)
		noAnswer("a write whose page is past the bound", bounded.CommitEpoch(ctx, repoId, groupId, 3, &protocol.GkmEpochRequest{}))
	}
}

// QD-876's other half: every answer of gkm's own keeps its meaning with its body. A 409 and a 412 are refusals
// carrying the winner, a 403 and a 404 refusals with none, a 429 and a 503 refusals of nothing with their
// Retry-After, and none of them is no answer.
func TestGkmApiKeepsAGkmRefusalWithItsBody(t *testing.T) {
	winner := []byte("the winner gkm stored")
	cases := []struct {
		status     int
		header     http.Header
		body       []byte
		winner     []byte
		retryAfter time.Duration
		nothing    bool
	}{
		{status: http.StatusConflict, body: winner, winner: winner},
		{status: http.StatusPreconditionFailed, body: winner, winner: winner},
		{status: http.StatusForbidden},
		{status: http.StatusNotFound},
		{status: http.StatusBadRequest},
		{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": {"7"}}, retryAfter: 7 * time.Second, nothing: true},
		{status: http.StatusServiceUnavailable, header: http.Header{"Retry-After": {"2"}}, retryAfter: 2 * time.Second, nothing: true},
		{status: http.StatusNotImplemented},
	}
	for _, c := range cases {
		transport := &gkmTestTransport{}
		transport.serve = func(request *gkmTestRequest) (int, http.Header, []byte) {
			return c.status, c.header, c.body
		}
		api := newGkmTestApi(t, transport, newGkmTestTokens(), newGkmTestClock())
		scopes := gkmTestScopes(1, GkmScopeRoleWrite)
		api.SetRepoScopes(scopes)
		// a write, which never goes again here
		err := api.CommitEpoch(context.Background(), scopes[0].RepoId, NewId(), 3, &protocol.GkmEpochRequest{})
		gkmError, refused := GkmErrorOf(err)
		if !refused || errors.Is(err, ErrGkmNoAnswer) {
			t.Fatalf("%d: not read as gkm's refusal: %v", c.status, err)
		}
		if gkmError.Status != c.status || !bytes.Equal(gkmError.Winner, c.winner) || gkmError.RetryAfter != c.retryAfter || gkmError.RefusesNothing() != c.nothing {
			t.Errorf("%d: the refusal: %+v", c.status, gkmError)
		}
	}
}

// A fake gkm guard over gkm's newest state, as gkmservice's AuthorizeRepo has it (§10.6's checks row; QD-975, owner
// decision 563): a call on a repo asks the state for the strongest right its token holds there of those the route's
// row takes, with each weaker right of its role that the row takes, and is honored only whole, else refused 403. A
// group's repo is the one the test formed it in, and a group of no repo is refused. A route on no repo is answered
// 200. Safe for concurrent use.
type gkmTestGuard struct {
	tokens *gkmTestTokens

	stateLock sync.Mutex
	// the role gkm's newest state gives the client on each repo: none refuses every call there
	repoIdRoles    map[Id]string
	groupIdRepoIds map[Id]Id
	// the repo a group's creation names in its GroupForm, which the fake does not parse
	createRepoId Id
}

func newGkmTestGuard(tokens *gkmTestTokens) *gkmTestGuard {
	return &gkmTestGuard{tokens: tokens, repoIdRoles: map[Id]string{}, groupIdRepoIds: map[Id]Id{}}
}

// gkm's state now gives the client role on repoId, "" for none.
func (self *gkmTestGuard) setRole(repoId Id, role string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.repoIdRoles[repoId] = role
}

// A new group of repoId.
func (self *gkmTestGuard) newGroup(repoId Id) Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	groupId := NewId()
	self.groupIdRepoIds[groupId] = repoId
	return groupId
}

// The rights a scope's role carries, and those gkm's state gives a holder of that role: admin write and read, write
// read, and read or deposit nothing more (gkmservice's gkmScopeRoleRights; AclHonorScope).
func gkmTestRoleRights(role string) AclEvsRights {
	switch role {
	case GkmScopeRoleDeposit:
		return AclEvsDeposit
	case GkmScopeRoleRead:
		return AclEvsRead
	case GkmScopeRoleWrite:
		return AclEvsWrite | AclEvsRead
	case GkmScopeRoleAdmin:
		return AclEvsAdmin | AclEvsWrite | AclEvsRead
	}
	return 0
}

// An id as a path names it, or false.
func gkmTestParseUrlId(text string) (Id, bool) {
	idBytes, err := hex.DecodeString(text)
	if err != nil {
		return Id{}, false
	}
	id, err := IdFromBytes(idBytes)
	return id, err == nil
}

// The rights the request's route row takes, any one of them (gkmservice's gkmScope.rights), and the repo it is on;
// false for a route on no repo.
func (self *gkmTestGuard) routeOf(request *gkmTestRequest) (AclEvsRights, Id, bool) {
	accessRights := AclEvsRead | AclEvsWrite | AclEvsAdmin
	writeRights := AclEvsWrite | AclEvsAdmin
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	groupRepoId := func(text string) Id {
		groupId, _ := gkmTestParseUrlId(text)
		return self.groupIdRepoIds[groupId]
	}
	segments := strings.Split(strings.TrimPrefix(request.path, "/gkm/"), "/")
	switch {
	case len(segments) == 1 && segments[0] == "groups" && request.method == http.MethodPost:
		return AclEvsAdmin, self.createRepoId, true
	case 2 <= len(segments) && segments[0] == "groups":
		repoId := groupRepoId(segments[1])
		rest := segments[2:]
		switch {
		case len(rest) == 1 && rest[0] == "ladder":
			return AclEvsAdmin, repoId, true
		case len(rest) == 2 && (rest[0] == "gen" || rest[0] == "welcome"):
			return writeRights, repoId, true
		}
		return accessRights, repoId, true
	case len(segments) == 3 && segments[0] == "repos":
		repoId, _ := gkmTestParseUrlId(segments[1])
		switch {
		case segments[2] == "forms" && request.method == http.MethodPost:
			return AclEvsAdmin, repoId, true
		case segments[2] == "drop-key":
			return AclEvsDeposit | accessRights, repoId, true
		}
		return accessRights, repoId, true
	case request.path == "/gkm/key-packages/claim":
		claim := &protocol.GkmKeyPackageClaimRequest{}
		if err := proto.Unmarshal(request.body, claim); err != nil {
			return writeRights, Id{}, true
		}
		groupId, _ := IdFromBytes(claim.GetGroupId())
		return writeRights, self.groupIdRepoIds[groupId], true
	}
	return 0, Id{}, false
}

// gkm's answer to request: 200 with no body where its state honors the call whole, else 403.
func (self *gkmTestGuard) serve(request *gkmTestRequest) (int, http.Header, []byte) {
	rowRights, repoId, onRepo := self.routeOf(request)
	if !onRepo {
		return http.StatusOK, nil, nil
	}
	held := AclEvsRights(0)
	for _, scope := range self.tokens.scopesOf(request.token) {
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
	self.stateLock.Lock()
	stateRights := gkmTestRoleRights(self.repoIdRoles[repoId])
	self.stateLock.Unlock()
	if !stateRights.Has(asked) {
		return http.StatusForbidden, nil, nil
	}
	return http.StatusOK, nil, nil
}

// A GkmApi on a fake gkm guarding its state: its scopes those of others at their roles and repoId's at clientRole,
// which gkm's state gives at gkmRole, and every other repo at its own role.
func newGkmTestGuardedApi(t *testing.T, others []GkmRepoScope, repoId Id, clientRole string, gkmRole string, clock Clock) (*GkmApi, *gkmTestTransport, *gkmTestTokens, *gkmTestGuard) {
	t.Helper()
	transport := &gkmTestTransport{}
	tokens := newGkmTestTokens()
	guard := newGkmTestGuard(tokens)
	transport.serve = guard.serve
	api := newGkmTestApi(t, transport, tokens, clock)
	for _, other := range others {
		guard.setRole(other.RepoId, other.Role)
	}
	guard.setRole(repoId, gkmRole)
	api.SetRepoScopes(append(slices.Clone(others), GkmRepoScope{RepoId: repoId, Role: clientRole}))
	return api, transport, tokens, guard
}

// The scopes of the tokens requests bore, in order.
func gkmTestTakenScopes(tokens *gkmTestTokens, requests []*gkmTestRequest) [][]string {
	scopes := [][]string{}
	for _, request := range requests {
		scopes = append(scopes, tokens.scopesOf(request.token))
	}
	return scopes
}

// QD-1179: an ACL save just took the client's role on a repo from admin to rw at gkm, before the client's own state
// applied it, so its batch still carries admin there and gkm refuses the batch whole. A read, as the GET of a group's
// generations a write starts with, and an rw route go once more under the repo's one scope at the role each needs,
// which gkm honors, the write with its same bytes. A call on another repo of the batch goes once, and once the
// client's state takes the save its calls go once.
func TestGkmApiRetriesARoleASaveNarrowedUnderTheCallsRole(t *testing.T) {
	others := gkmTestScopes(3, GkmScopeRoleWrite)
	repoId := NewId()
	api, transport, tokens, guard := newGkmTestGuardedApi(t, others, repoId, GkmScopeRoleAdmin, GkmScopeRoleWrite, nil)
	groupId := guard.newGroup(repoId)
	ctx := context.Background()
	batchAdmin := GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleAdmin}.scope()

	if _, err := api.Generations(ctx, repoId, groupId, 1); err != nil {
		t.Fatalf("a read after the save: %v", err)
	}
	taken := transport.taken()
	scopes := gkmTestTakenScopes(tokens, taken)
	if len(taken) != 2 {
		t.Fatalf("a read after the save went %d times, want 2", len(taken))
	}
	if len(scopes[0]) != 4 || !slices.Contains(scopes[0], batchAdmin) {
		t.Errorf("the read's first token holds %v, not the batch", scopes[0])
	}
	if !slices.Equal(scopes[1], []string{GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleRead}.scope()}) {
		t.Errorf("the read's retry presented %v", scopes[1])
	}
	if taken[1].method != taken[0].method || taken[1].path != taken[0].path || taken[1].query != taken[0].query {
		t.Errorf("the retry asked %s %s?%s, the call %s %s?%s", taken[1].method, taken[1].path, taken[1].query, taken[0].method, taken[0].path, taken[0].query)
	}

	rotate := &bridge.Signed{Body: []byte("the claim's GenRotate"), Signature: []byte("its signature")}
	if err := api.ClaimGeneration(ctx, repoId, groupId, 2, rotate); err != nil {
		t.Fatalf("an rw route after the save: %v", err)
	}
	taken = transport.taken()[2:]
	scopes = gkmTestTakenScopes(tokens, taken)
	if len(taken) != 2 {
		t.Fatalf("an rw route after the save went %d times, want 2", len(taken))
	}
	if !slices.Contains(scopes[0], batchAdmin) || !slices.Equal(scopes[1], []string{GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleWrite}.scope()}) {
		t.Errorf("the claim presented %v, then %v", scopes[0], scopes[1])
	}
	if len(taken[0].body) == 0 || !bytes.Equal(taken[1].body, taken[0].body) {
		t.Error("the claim's retry did not carry its same bytes")
	}

	// another repo of the batch, whose role gkm's state gives, goes once
	before := len(transport.taken())
	if _, err := api.Generations(ctx, others[0].RepoId, guard.newGroup(others[0].RepoId), 1); err != nil {
		t.Fatalf("a read of another repo: %v", err)
	}
	if count := len(transport.taken()) - before; count != 1 {
		t.Errorf("a read of another repo went %d times", count)
	}

	// the client's state takes the save, so its batch carries rw, which gkm honors at once
	api.SetRepoScopes(append(slices.Clone(others), GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleWrite}))
	before = len(transport.taken())
	if _, err := api.Generations(ctx, repoId, groupId, 1); err != nil {
		t.Fatalf("a read once the client took the save: %v", err)
	}
	if err := api.ClaimGeneration(ctx, repoId, groupId, 3, rotate); err != nil {
		t.Fatalf("an rw route once the client took the save: %v", err)
	}
	if count := len(transport.taken()) - before; count != 2 {
		t.Errorf("two calls once the client took the save went %d times, want 2", count)
	}
}

// QD-1179's other direction: the client's state already shows a role a save widened, and gkm's newest state does not
// yet. A call needing less than the widened role is refused under the batch and goes once more at its own role,
// which gkm honors. A call needing the widened role itself presents no stronger one, so it is refused once, as it
// should be until gkm's state catches up, and goes once after.
func TestGkmApiRetriesARoleWidenedAheadOfGkmUnderTheCallsRole(t *testing.T) {
	for _, c := range []struct {
		clientRole string
		gkmRole    string
		// whether an rw route passes after one retry, or is refused under its own role, which the batch carries
		writePasses bool
	}{
		{clientRole: GkmScopeRoleWrite, gkmRole: GkmScopeRoleRead, writePasses: false},
		{clientRole: GkmScopeRoleAdmin, gkmRole: GkmScopeRoleWrite, writePasses: true},
	} {
		repoId := NewId()
		api, transport, tokens, guard := newGkmTestGuardedApi(t, gkmTestScopes(2, GkmScopeRoleRead), repoId, c.clientRole, c.gkmRole, nil)
		groupId := guard.newGroup(repoId)
		ctx := context.Background()

		if _, err := api.Epochs(ctx, repoId, groupId, 4); err != nil {
			t.Fatalf("%s ahead of %s: a read: %v", c.clientRole, c.gkmRole, err)
		}
		scopes := gkmTestTakenScopes(tokens, transport.taken())
		if len(scopes) != 2 || !slices.Equal(scopes[1], []string{GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleRead}.scope()}) {
			t.Errorf("%s ahead of %s: a read presented %v", c.clientRole, c.gkmRole, scopes)
		}

		before := len(transport.taken())
		err := api.ClaimGeneration(ctx, repoId, groupId, 2, &bridge.Signed{Body: []byte("a GenRotate")})
		count := len(transport.taken()) - before
		switch {
		case c.writePasses && (err != nil || count != 2):
			t.Errorf("%s ahead of %s: an rw route: %v after %d requests, want a pass after 2", c.clientRole, c.gkmRole, err, count)
		case !c.writePasses && (!IsGkmStatus(err, http.StatusForbidden) || count != 1):
			t.Errorf("%s ahead of %s: an rw route under its own role: %v after %d requests, want 403 after 1", c.clientRole, c.gkmRole, err, count)
		}

		// gkm's state catches up
		guard.setRole(repoId, c.clientRole)
		before = len(transport.taken())
		if _, err := api.Epochs(ctx, repoId, groupId, 4); err != nil {
			t.Fatalf("%s: a read once gkm caught up: %v", c.clientRole, err)
		}
		if err := api.ClaimGeneration(ctx, repoId, groupId, 3, &bridge.Signed{Body: []byte("a GenRotate")}); err != nil {
			t.Fatalf("%s: an rw route once gkm caught up: %v", c.clientRole, err)
		}
		if count := len(transport.taken()) - before; count != 2 {
			t.Errorf("%s: two calls once gkm caught up went %d times, want 2", c.clientRole, count)
		}
	}
}

// QD-1179: a call refused for a right the client lacks in gkm's state, under the batch's stronger role, is refused
// again after its one retry at its own role, and goes no third time; no wait is armed for it. A call that presented
// its repo's one scope already, needing a stronger role than the batch carries, and one whose batch carries its own
// role, are refused once.
func TestGkmApiRefusesARightTheClientLacksAfterOneRetry(t *testing.T) {
	clock := newGkmTestClock()
	repoId, readOnlyRepoId := NewId(), NewId()
	api, transport, tokens, guard := newGkmTestGuardedApi(t, []GkmRepoScope{{RepoId: readOnlyRepoId, Role: GkmScopeRoleRead}}, repoId, GkmScopeRoleAdmin, "", clock)
	groupId := guard.newGroup(repoId)
	ctx := context.Background()
	refusedOnce := func(name string, wantCount int, call func() error) {
		t.Helper()
		before := len(transport.taken())
		err := call()
		count := len(transport.taken()) - before
		if !IsGkmStatus(err, http.StatusForbidden) || count != wantCount {
			t.Errorf("%s: %v after %d requests, want 403 after %d", name, err, count, wantCount)
		}
	}

	// gkm's state gives the client nothing on the repo, the client's admin
	refusedOnce("a read", 2, func() error { _, err := api.Group(ctx, repoId, groupId); return err })
	refusedOnce("an rw route", 2, func() error { return api.UploadWelcome(ctx, repoId, groupId, 3, &protocol.GkmWelcomeRequest{}) })
	if scopes := gkmTestTakenScopes(tokens, transport.taken()); len(scopes) != 4 || !slices.Equal(scopes[3], []string{GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleWrite}.scope()}) {
		t.Errorf("the read and the rw route presented %v", scopes)
	}
	// gkm's state gives r, so a write needing rw is refused at its own role
	guard.setRole(repoId, GkmScopeRoleRead)
	refusedOnce("an rw route gkm gives r of", 2, func() error {
		return api.ClaimGeneration(ctx, repoId, groupId, 2, &bridge.Signed{Body: []byte("a GenRotate")})
	})
	select {
	case wait := <-clock.armed:
		t.Errorf("a refusal waited %s to go again", wait)
	default:
	}

	// the client reads and gkm's state gives nothing: an rw route presents the repo's one rw scope, a read the batch
	// at its own role, and neither has a narrower one to try
	readOnlyGroupId := guard.newGroup(readOnlyRepoId)
	guard.setRole(readOnlyRepoId, "")
	refusedOnce("an rw route under its one scope", 1, func() error {
		return api.ClaimGeneration(ctx, readOnlyRepoId, readOnlyGroupId, 2, &bridge.Signed{Body: []byte("a GenRotate")})
	})
	refusedOnce("a read under the batch's own role", 1, func() error {
		_, err := api.Generations(ctx, readOnlyRepoId, readOnlyGroupId, 1)
		return err
	})
}

// QD-1179 leaves the admin routes alone: no role outranks admin, so a group's creation, a re-form and a ladder are
// refused once, under the batch where it carries admin and under the repo's one admin scope where it does not.
func TestGkmApiDoesNotRetryAnAdminRoute(t *testing.T) {
	for _, clientRole := range []string{GkmScopeRoleAdmin, GkmScopeRoleWrite} {
		repoId := NewId()
		api, transport, tokens, guard := newGkmTestGuardedApi(t, gkmTestScopes(2, GkmScopeRoleWrite), repoId, clientRole, GkmScopeRoleWrite, nil)
		guard.createRepoId = repoId
		groupId := guard.newGroup(repoId)
		ctx := context.Background()
		calls := []struct {
			name string
			call func() error
		}{
			{name: "a creation", call: func() error { return api.CreateGroup(ctx, repoId, &protocol.GkmGroupCreateRequest{}) }},
			{name: "a re-form", call: func() error { return api.Reform(ctx, repoId, &protocol.GkmGroupReformRequest{}) }},
			{name: "a ladder", call: func() error { return api.UploadLadder(ctx, repoId, groupId, &protocol.GkmLadderRequest{}) }},
		}
		for _, call := range calls {
			before := len(transport.taken())
			err := call.call()
			taken := transport.taken()[before:]
			if !IsGkmStatus(err, http.StatusForbidden) || len(taken) != 1 {
				t.Errorf("%s under %s: %v after %d requests, want 403 after 1", call.name, clientRole, err, len(taken))
				continue
			}
			scopes := tokens.scopesOf(taken[0].token)
			if !slices.Contains(scopes, GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleAdmin}.scope()) {
				t.Errorf("%s under %s presented %v", call.name, clientRole, scopes)
			}
		}
	}
}

// A read's narrowed retry holds for the rest of the call and is none of its ReadRetryCount: refused under the batch,
// answered 503 under the repo's one r scope, it waits the Retry-After and goes again under that scope, though it may
// retry a 503 once.
func TestGkmApiKeepsTheNarrowedScopeThroughAReadsRetries(t *testing.T) {
	clock := newGkmTestClock()
	transport := &gkmTestTransport{}
	tokens := newGkmTestTokens()
	guard := newGkmTestGuard(tokens)
	settings := DefaultGkmSettings()
	settings.ReadRetryCount = 1
	api, err := NewGkmApi(&GkmApiArgs{GkmUrl: "https://gkm.example", Transport: transport, ServiceToken: tokens.serviceToken, Settings: settings, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	repoId := NewId()
	api.SetRepoScopes(append(gkmTestScopes(2, GkmScopeRoleRead), GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleAdmin}))
	guard.setRole(repoId, GkmScopeRoleRead)
	groupId := guard.newGroup(repoId)
	unavailableCount := 0
	transport.serve = func(request *gkmTestRequest) (int, http.Header, []byte) {
		status, header, body := guard.serve(request)
		if status == http.StatusOK && unavailableCount < 1 {
			unavailableCount += 1
			return http.StatusServiceUnavailable, http.Header{"Retry-After": {"2"}}, nil
		}
		return status, header, body
	}

	done := make(chan error, 1)
	go func() {
		_, err := api.Wraps(context.Background(), repoId, groupId, 2, &GkmWrapsQuery{Recipient: "s:" + gkmUrlId(NewId())})
		done <- err
	}()
	// a read that goes no second time ends without arming its wait
	select {
	case wait := <-clock.armed:
		if wait != 2*time.Second {
			t.Errorf("the narrowed read waits %s", wait)
		}
	case err := <-done:
		t.Fatalf("the read ended before waiting out its 503: %v", err)
	}
	clock.Advance(2 * time.Second)
	if err := <-done; err != nil {
		t.Fatalf("the narrowed read after its 503: %v", err)
	}
	scopes := gkmTestTakenScopes(tokens, transport.taken())
	narrowed := []string{GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleRead}.scope()}
	if len(scopes) != 3 || len(scopes[0]) != 3 || !slices.Equal(scopes[1], narrowed) || !slices.Equal(scopes[2], narrowed) {
		t.Errorf("the read presented %v", scopes)
	}
}

// QD-1179 on the drop-key route, which deposit, r, rw and admin reach: a batch carrying r on a repo where gkm's state
// gives the client deposit alone is refused, and the call goes once more under the repo's one deposit scope, its own.
func TestGkmApiNarrowsADropKeyReadToDeposit(t *testing.T) {
	repoId := NewId()
	api, transport, tokens, _ := newGkmTestGuardedApi(t, gkmTestScopes(1, GkmScopeRoleWrite), repoId, GkmScopeRoleRead, GkmScopeRoleDeposit, nil)
	if _, err := api.DropKeys(context.Background(), repoId, 0); err != nil {
		t.Fatalf("a drop-key read: %v", err)
	}
	scopes := gkmTestTakenScopes(tokens, transport.taken())
	if len(scopes) != 2 || len(scopes[0]) != 2 || !slices.Equal(scopes[1], []string{GkmRepoScope{RepoId: repoId, Role: GkmScopeRoleDeposit}.scope()}) {
		t.Errorf("a drop-key read presented %v", scopes)
	}
}
