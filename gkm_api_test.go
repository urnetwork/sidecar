// GkmApi's transport, scope batching and answers, and the late-delivery ask's pace, on a fake gkm reached through
// a RoundTripper, so these run on every leg, the sidecar_http page Worker's included (KEYS-M2-18).

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
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
