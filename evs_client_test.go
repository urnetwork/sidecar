// EVS1-M2-22's tests: the transport against a stub evs for every refusal class §11.20 names, the token's scope and
// header, the pin store across a restart and its refusals, the read records' bound, and the lifecycle's thin calls.

package sidecar

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A transport that serves each request from a handler in this process, so no socket opens.
type evsTestTransport struct {
	handler http.Handler
}

func (self *evsTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	self.handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

// A clock whose waits end at once and whose deadlines never fire, recording each wait, so a retry needs no sleep.
type evsTestClock struct {
	stateLock sync.Mutex
	now       time.Time
	waits     []time.Duration
}

func newEvsTestClock() *evsTestClock {
	return &evsTestClock{now: time.Date(2026, time.November, 8, 9, 10, 11, 0, time.UTC)}
}

func (self *evsTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *evsTestClock) advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(by)
}

func (self *evsTestClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.waits = append(self.waits, timeout)
	fired := make(chan time.Time, 1)
	fired <- self.now
	return fired
}

func (self *evsTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return true }
}

func (self *evsTestClock) waited() []time.Duration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]time.Duration{}, self.waits...)
}

// The token every test call presents, which must never show in an error.
const evsTestServiceToken = "synthetic-evs-token"

// What a test client's token function saw.
type evsTestTokens struct {
	stateLock sync.Mutex
	scopes    [][]string
	resources []string
}

func (self *evsTestTokens) token(ctx context.Context, resource string, scopes []string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.resources = append(self.resources, resource)
	self.scopes = append(self.scopes, append([]string{}, scopes...))
	return evsTestServiceToken, nil
}

// A statement poster that records what it filed.
type evsTestPoster struct {
	stateLock sync.Mutex
	filed     []bridge.SignedType
	bodies    []proto.Message
}

func (self *evsTestPoster) file(ctx context.Context, signedType bridge.SignedType, body proto.Message) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.filed = append(self.filed, signedType)
	self.bodies = append(self.bodies, body)
	return nil
}

// A gkm client that records the groups it was asked for and refuses everything else.
type evsTestGkm struct {
	gkmRefusingClient
	stateLock sync.Mutex
	created   []*GkmCreateGroupArgs
	forgotten []Id
}

func (self *evsTestGkm) CreateGroup(ctx context.Context, args *GkmCreateGroupArgs) (*EvsRepoKey, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.created = append(self.created, args)
	return evsTestRepoKey(args.RepoId, 1), nil
}

func (self *evsTestGkm) ForgetRepo(ctx context.Context, repoId Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.forgotten = append(self.forgotten, repoId)
	return nil
}

// A test client on handler and store.
type evsTestClient struct {
	client *EvsClient
	tokens *evsTestTokens
	poster *evsTestPoster
	gkm    *evsTestGkm
	clock  *evsTestClock
	events *[]SidecarEvent
}

func newEvsTestClient(t *testing.T, handler http.Handler, store SidecarStore) *evsTestClient {
	t.Helper()
	tokens := &evsTestTokens{}
	poster := &evsTestPoster{}
	gkm := &evsTestGkm{}
	clock := newEvsTestClock()
	events := &[]SidecarEvent{}
	eventsLock := &sync.Mutex{}
	identity := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: evsTestId("sidecar"), ClientId: evsTestId("client")}
	client, err := NewEvsClient(&EvsClientArgs{
		NetworkId:    testNetworkId,
		EvsUrl:       "https://evs.example",
		Transport:    &evsTestTransport{handler: handler},
		ServiceToken: tokens.token,
		Sign: func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
			return nil, errors.New("no signer in this test")
		},
		Identity:      func() *SidecarIdentity { return identity },
		Gkm:           gkm,
		Store:         store,
		FileStatement: poster.file,
		Emit: func(event SidecarEvent) {
			eventsLock.Lock()
			defer eventsLock.Unlock()
			*events = append(*events, event)
		},
		Clock:    clock,
		Log:      NewNoopLogger(),
		Settings: DefaultEvsSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &evsTestClient{client: client, tokens: tokens, poster: poster, gkm: gkm, clock: clock, events: events}
}

// A sealed store of an enrolled test network.
func newEvsTestStore(t *testing.T) SidecarStore {
	t.Helper()
	instance, _, _ := enrolledInstance(t)
	return storeOf(t, instance, testNetworkId, evsComponentName)
}

// A handler that answers every request with reply at status, after checking the token's header.
func evsRefusingHandler(t *testing.T, status int, reply *protocol.EvsRefusalReply, header map[string]string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+evsTestServiceToken {
			t.Errorf("Authorization %q", request.Header.Get("Authorization"))
		}
		for name, value := range header {
			writer.Header().Set(name, value)
		}
		body, _ := proto.Marshal(reply)
		writer.WriteHeader(status)
		writer.Write(body)
	})
}

// Every refusal class §11.20 names maps to its typed error, with the fields its reply carries, and never repeats the
// token.
func TestEvsTransportMapsEveryRefusalClass(t *testing.T) {
	pushId := evsTestId("push")
	path := EvsTokenPath{evsTestToken("a"), evsTestToken("b")}
	cases := []struct {
		name   string
		status int
		reply  *protocol.EvsRefusalReply
		check  func(evsError *EvsError) bool
	}{
		{name: "scope", status: 403, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE},
			check: func(e *EvsError) bool { return e.Code == protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE }},
		{name: "quota payment", status: 402, reply: &protocol.EvsRefusalReply{
			Code:  protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT,
			Quota: &protocol.EvsQuotaRefusal{LimitKey: "storage_bytes", Limit: 10, Used: 11, Upgrade: true},
		}, check: func(e *EvsError) bool { return e.Quota.GetLimitKey() == "storage_bytes" && e.Quota.GetUpgrade() }},
		{name: "quota limit", status: 403, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT},
			check: func(e *EvsError) bool { return e.Code == protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT }},
		{name: "path conflict", status: 409, reply: &protocol.EvsRefusalReply{
			PushId: pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT,
			Paths: []*protocol.EvsTokenPath{path.Proto()},
		}, check: func(e *EvsError) bool {
			return len(e.Paths) == 1 && e.Paths[0].Equal(path) && e.PushId != nil && *e.PushId == pushId && !e.Recorded
		}},
		{name: "recorded", status: 409, reply: &protocol.EvsRefusalReply{
			PushId: pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL, Recorded: true,
		}, check: func(e *EvsError) bool {
			return e.Recorded && e.Code == protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL
		}},
		{name: "format", status: 409, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED, NeedsFormat: 2},
			check: func(e *EvsError) bool { return e.NeedsFormat == 2 }},
		{name: "base stale", status: 409, reply: &protocol.EvsRefusalReply{
			Code: protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE, DepositHead: &protocol.EvsDepositHead{Version: 7},
		}, check: func(e *EvsError) bool { return e.DepositHead.GetVersion() == 7 }},
		{name: "gate", status: 412, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED},
			check: func(e *EvsError) bool {
				return e.Code == protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED && !e.RefusesNothing()
			}},
		{name: "path epoch due", status: 412, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE},
			check: func(e *EvsError) bool { return e.Code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE }},
		{name: "busy", status: 429, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_BUSY, RetryAfterMs: 1500},
			check: func(e *EvsError) bool { return e.RetryAfter == 1500*time.Millisecond && e.RefusesNothing() }},
		{name: "unknown", status: 503, reply: &protocol.EvsRefusalReply{
			PushId: pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE,
			Outcome: protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN,
		}, check: func(e *EvsError) bool { return e.OutcomeUnknown && !e.RefusesNothing() }},
		{name: "cluster full", status: 507, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL},
			check: func(e *EvsError) bool { return e.Code == protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL }},
		// a code whose status is not its own is not believed
		{name: "mismatched code", status: 409, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_BUSY},
			check: func(e *EvsError) bool { return e.Code == protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED }},
	}
	for _, c := range cases {
		test := newEvsTestClient(t, evsRefusingHandler(t, c.status, c.reply, nil), newEvsTestStore(t))
		err := test.client.http.callMessage(context.Background(), &evsCall{
			route: "POST /evs/v1/repos/{repo_id}/push", method: http.MethodPost,
			path: "/evs/v1/repos/" + EvsKeyId(evsTestId("repo")) + "/push", repoId: evsTestId("repo"), role: evsScopeWrite,
		}, nil)
		evsError, ok := EvsErrorOf(err)
		if !ok || evsError.Status != c.status || !c.check(evsError) {
			t.Errorf("%s: %#v", c.name, err)
		}
		if err != nil && strings.Contains(err.Error(), evsTestServiceToken) {
			t.Errorf("%s: the error repeats the token", c.name)
		}
	}
}

// A 401 is ErrEvsUnauthorized, and a proxy's page under a 502 reads as no code at all.
func TestEvsTransportUnauthorizedAndForeignBodies(t *testing.T) {
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
	}), newEvsTestStore(t))
	call := &evsCall{route: "GET /evs/v1/repos/{repo_id}/refs", method: http.MethodGet,
		path: "/evs/v1/repos/" + EvsKeyId(evsTestId("repo")) + "/refs", repoId: evsTestId("repo"), role: evsScopeRead}
	if err := test.client.http.callMessage(context.Background(), call, nil); !errors.Is(err, ErrEvsUnauthorized) {
		t.Errorf("401: %v", err)
	}
	test = newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusBadGateway)
		writer.Write([]byte("<html>bad gateway</html>"))
	}), newEvsTestStore(t))
	err := test.client.http.callMessage(context.Background(), call, nil)
	evsError, ok := EvsErrorOf(err)
	if !ok || evsError.Status != http.StatusBadGateway || evsError.Code != protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
		t.Errorf("502: %#v", err)
	}
}

// A read retries a 429 after its retry_after_ms and a 503 after Retry-After, then succeeds; a push call never
// retries, and an unknown outcome is never retried even on a read.
func TestEvsTransportRetriesOnlyWhatRefusesNothing(t *testing.T) {
	answers := []func(writer http.ResponseWriter){
		func(writer http.ResponseWriter) {
			body, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_FOLD_BEHIND, RetryAfterMs: 2000})
			writer.WriteHeader(http.StatusTooManyRequests)
			writer.Write(body)
		},
		func(writer http.ResponseWriter) {
			writer.Header().Set("Retry-After", "3")
			writer.WriteHeader(http.StatusServiceUnavailable)
		},
		func(writer http.ResponseWriter) {
			body, _ := proto.Marshal(&protocol.EvsRefsReply{Format: 1, PushSequence: 42})
			writer.WriteHeader(http.StatusOK)
			writer.Write(body)
		},
	}
	count := 0
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		answers[min(count, len(answers)-1)](writer)
		count += 1
	}), newEvsTestStore(t))
	reply := &protocol.EvsRefsReply{}
	call := &evsCall{route: "GET /evs/v1/repos/{repo_id}/refs", method: http.MethodGet,
		path: "/evs/v1/repos/" + EvsKeyId(evsTestId("repo")) + "/refs", repoId: evsTestId("repo"), role: evsScopeRead, retry: true}
	if err := test.client.http.callMessage(context.Background(), call, reply); err != nil || reply.GetPushSequence() != 42 {
		t.Fatalf("read: %v %v", err, reply)
	}
	if waits := test.clock.waited(); len(waits) != 2 || waits[0] != 2*time.Second || waits[1] != 3*time.Second {
		t.Errorf("waits %v", waits)
	}

	count = 0
	pushCall := *call
	pushCall.retry = false
	if err := test.client.http.callMessage(context.Background(), &pushCall, reply); !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_FOLD_BEHIND) || count != 1 {
		t.Errorf("a push call retried or answered %v after %d", err, count)
	}

	unknownCount := 0
	test = newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		unknownCount += 1
		body, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE, Outcome: protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN})
		writer.WriteHeader(http.StatusServiceUnavailable)
		writer.Write(body)
	}), newEvsTestStore(t))
	if err := test.client.http.callMessage(context.Background(), call, reply); err == nil || unknownCount != 1 {
		t.Errorf("an unknown outcome retried: %v after %d", err, unknownCount)
	}
}

// Each call presents one repo scope for the role its route takes, to the evs url alone, and its url holds only ids.
func TestEvsTransportScopesAndUrls(t *testing.T) {
	repoId := evsTestId("repo")
	var seenPath string
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seenPath = request.URL.String()
		writer.WriteHeader(http.StatusOK)
	}), newEvsTestStore(t))
	call := &evsCall{route: "DELETE /evs/v1/repos/{repo_id}", method: http.MethodDelete,
		path: "/evs/v1/repos/" + EvsKeyId(repoId) + "?now=1", repoId: repoId, role: evsScopeAdmin}
	if err := test.client.http.callMessage(context.Background(), call, nil); err != nil {
		t.Fatal(err)
	}
	if seenPath != "https://evs.example/evs/v1/repos/"+EvsKeyId(repoId)+"?now=1" {
		t.Errorf("url %s", seenPath)
	}
	if len(test.tokens.scopes) != 1 || len(test.tokens.scopes[0]) != 1 ||
		test.tokens.scopes[0][0] != "repo:"+repoId.String()+":admin" || test.tokens.resources[0] != "https://evs.example" {
		t.Errorf("scopes %v resources %v", test.tokens.scopes, test.tokens.resources)
	}
}

// A read reply's frames read one at a time, refusing a frame past its bound and a stream cut before its end.
func TestEvsReadFramesBoundAndEnd(t *testing.T) {
	first, err := EncodeEvsReadFrame(&protocol.EvsReadFrame{Head: &protocol.EvsHeadSummary{Version: 3}})
	if err != nil {
		t.Fatal(err)
	}
	last, err := EncodeEvsReadFrame(&protocol.EvsReadFrame{End: true})
	if err != nil {
		t.Fatal(err)
	}
	frames := NewEvsReadFrames(strings.NewReader(string(first) + string(last)))
	frame, err := frames.Next()
	if err != nil || frame.GetHead().GetVersion() != 3 {
		t.Fatalf("first %v %v", frame, err)
	}
	if frame, err := frames.Next(); err != nil || !frame.GetEnd() {
		t.Fatalf("last %v %v", frame, err)
	}
	if _, err := frames.Next(); err != io.EOF {
		t.Errorf("after the end: %v", err)
	}
	if _, err := NewEvsReadFrames(strings.NewReader(string(first))).Next(); err != nil {
		t.Fatal(err)
	}
	cut := NewEvsReadFrames(strings.NewReader(string(first)))
	cut.Next()
	if _, err := cut.Next(); !errors.Is(err, ErrEvsReplyInvalid) {
		t.Errorf("a cut stream: %v", err)
	}
	huge := []byte{0x7f, 0xff, 0xff, 0xff}
	if _, err := NewEvsReadFrames(strings.NewReader(string(huge))).Next(); !errors.Is(err, ErrEvsReplyInvalid) {
		t.Errorf("a frame past its bound: %v", err)
	}
}

// A pin survives the store's reopening, refuses a lower version and a fork, and falls only under a reseed, which
// it keeps as a loss.
func TestEvsPinStoreSurvivesRestartAndNeverFalls(t *testing.T) {
	instance, backend, keyStore := enrolledInstance(t)
	store := storeOf(t, instance, testNetworkId, evsComponentName)
	pins := NewEvsPinStore(store, DefaultEvsSettings())
	repoId, refId := evsTestId("repo"), evsTestId("ref")
	chain := [32]byte(evsTestBytes("chain 5", 32))
	pinnedAt := time.Date(2026, time.November, 8, 0, 0, 0, 0, time.UTC)
	if err := pins.Raise(&EvsPin{RepoId: repoId, RefId: refId, Version: 5, Chain: chain, PinnedAt: pinnedAt}); err != nil {
		t.Fatal(err)
	}
	instance.Close()

	again := newInstanceOn(t, backend, keyStore)
	if err := again.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	reopened := NewEvsPinStore(storeOf(t, again, testNetworkId, evsComponentName), DefaultEvsSettings())
	pin, ok, err := reopened.Pin(repoId, refId)
	if err != nil || !ok || pin.Version != 5 || pin.Chain != chain || !pin.PinnedAt.Equal(pinnedAt) {
		t.Fatalf("after a restart: %+v %v %v", pin, ok, err)
	}
	if err := reopened.Raise(&EvsPin{RepoId: repoId, RefId: refId, Version: 4, Chain: chain}); !errors.Is(err, ErrEvsPinLower) {
		t.Errorf("a lower version: %v", err)
	}
	if err := reopened.Raise(&EvsPin{RepoId: repoId, RefId: refId, Version: 5, Chain: [32]byte(evsTestBytes("other", 32))}); !errors.Is(err, ErrEvsPinFork) {
		t.Errorf("a fork: %v", err)
	}
	lowChain := [32]byte(evsTestBytes("chain 3", 32))
	if err := reopened.lowerByReseed(&EvsPin{RepoId: repoId, RefId: refId, Version: 3, Chain: lowChain}, []byte("incident"), pinnedAt); err != nil {
		t.Fatal(err)
	}
	pin, _, _ = reopened.Pin(repoId, refId)
	if pin.Version != 3 || pin.Loss == nil || pin.Loss.FromVersion != 5 || string(pin.Loss.IncidentId) != "incident" {
		t.Errorf("after a reseed: %+v", pin)
	}
	if err := reopened.Forget(repoId); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := reopened.Pin(repoId, refId); ok {
		t.Errorf("a forgotten repo's pin")
	}
}

// Read records keep the newest of each path and the network's most recent HeadReadRecordCount.
func TestEvsReadRecordsBoundLeastRecentlyUsed(t *testing.T) {
	settings := DefaultEvsSettings()
	settings.HeadReadRecordCount = 2
	pins := NewEvsPinStore(newEvsTestStore(t), settings)
	repoId, otherRepoId, refId := evsTestId("repo"), evsTestId("other repo"), evsTestId("ref")
	at := time.Date(2026, time.November, 8, 0, 0, 0, 0, time.UTC)
	raise := func(repoId Id, path string, entryVersion uint64, pinVersion uint64, usedAt time.Time) {
		if err := pins.RaiseReadRecords(repoId, []*EvsReadRecord{{RefId: refId, Path: path, EntryVersion: entryVersion, PinVersion: pinVersion, UsedAt: usedAt}}); err != nil {
			t.Fatal(err)
		}
	}
	raise(repoId, "a", 3, 10, at)
	raise(repoId, "a", 2, 9, at.Add(time.Second))
	record, ok, _ := pins.ReadRecord(repoId, refId, "a")
	if !ok || record.EntryVersion != 3 || record.PinVersion != 10 {
		t.Errorf("a record fell: %+v", record)
	}
	raise(otherRepoId, "b", 1, 1, at.Add(2*time.Second))
	raise(repoId, "c", 1, 1, at.Add(3*time.Second))
	if _, ok, _ := pins.ReadRecord(repoId, refId, "a"); ok {
		t.Errorf("the least recently used record stayed")
	}
	for _, kept := range []struct {
		repoId Id
		path   string
	}{{repoId: otherRepoId, path: "b"}, {repoId: repoId, path: "c"}} {
		if _, ok, _ := pins.ReadRecord(kept.repoId, refId, kept.path); !ok {
			t.Errorf("%s was evicted", kept.path)
		}
	}
}

// CreateRepo files RepoCreate, places the repo, runs KF1 and activates it, in that order, waiting out the projection's
// lag; without a statement poster it sends nothing.
func TestEvsCreateRepoFilesThenPlacesThenActivates(t *testing.T) {
	routes := []string{}
	statementMissing := true
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		routes = append(routes, request.Method+" "+request.URL.Path)
		if request.Method == http.MethodPut && statementMissing {
			statementMissing = false
			body, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING})
			writer.WriteHeader(http.StatusConflict)
			writer.Write(body)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	test := newEvsTestClient(t, handler, newEvsTestStore(t))
	repo, err := test.client.CreateRepo(context.Background(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatal(err)
	}
	repoPath := "/evs/v1/repos/" + EvsKeyId(repo.RepoId())
	want := []string{"PUT " + repoPath, "PUT " + repoPath, "POST " + repoPath + "/activate"}
	if strings.Join(routes, ",") != strings.Join(want, ",") {
		t.Errorf("routes %v", routes)
	}
	if len(test.poster.filed) != 1 || test.poster.filed[0] != bridge.SignedType_SIGNED_REPO_CREATE {
		t.Errorf("filed %v", test.poster.filed)
	}
	created := test.poster.bodies[0].(*protocol.RepoCreate)
	if string(created.GetRepoId()) != string(repo.RepoId().Bytes()) || created.GetKind() != protocol.RepoKind_REPO_KIND_GENERAL {
		t.Errorf("RepoCreate %v", created)
	}
	if len(test.gkm.created) != 1 || test.gkm.created[0].RepoId != repo.RepoId() || test.gkm.created[0].NetworkId != testNetworkId {
		t.Errorf("groups %v", test.gkm.created)
	}

	routes = nil
	unwired := newEvsTestClient(t, handler, newEvsTestStore(t))
	unwired.client.args.FileStatement = nil
	if _, err := unwired.client.CreateRepo(context.Background(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_GENERAL}); !errors.Is(err, ErrEvsNoStatementPoster) || len(routes) != 0 {
		t.Errorf("without a poster: %v, %v", err, routes)
	}
	if _, err := test.client.CreateRepo(context.Background(), &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_VAULT}); err == nil {
		t.Errorf("an owner-bound kind with no owner")
	}
}

// Delete files RepoDelete and calls the route, with now for a shred, which then drops the repo's keys and pins; a
// refused route is the caller's error.
func TestEvsDeleteAndShredStayThin(t *testing.T) {
	routes := []string{}
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		routes = append(routes, request.Method+" "+request.URL.String())
		writer.WriteHeader(http.StatusOK)
	}), newEvsTestStore(t))
	repo := test.client.Repo(evsTestId("repo"))
	if err := test.client.pins.Raise(&EvsPin{RepoId: repo.RepoId(), RefId: evsTestId("ref"), Version: 1}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Shred(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0] != "DELETE https://evs.example/evs/v1/repos/"+EvsKeyId(repo.RepoId())+"?now=1" {
		t.Errorf("routes %v", routes)
	}
	deletion := test.poster.bodies[0].(*protocol.RepoDelete)
	if !deletion.GetNow() || len(deletion.GetDeletionId()) != 16 {
		t.Errorf("RepoDelete %v", deletion)
	}
	if len(test.gkm.forgotten) != 1 {
		t.Errorf("keys kept")
	}
	if _, ok, _ := test.client.pins.Pin(repo.RepoId(), evsTestId("ref")); ok {
		t.Errorf("pins kept")
	}

	refusing := newEvsTestClient(t, evsRefusingHandler(t, 409, &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING}, nil), newEvsTestStore(t))
	if err := refusing.client.Repo(evsTestId("repo")).Delete(context.Background(), false); !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING) {
		t.Errorf("a refused delete: %v", err)
	}
}

// A hint raises the version the next read must reach past evs's cache, and a lower or malformed one changes nothing.
func TestEvsHintRaisesOnlyTheHintedVersion(t *testing.T) {
	test := newEvsTestClient(t, http.NotFoundHandler(), newEvsTestStore(t))
	repoId, refId := evsTestId("repo"), evsTestId("ref")
	hint := func(version uint64) []byte {
		delta, _ := proto.Marshal(&protocol.EvsHeadChanged{RefId: refId.Bytes(), Version: version})
		return delta
	}
	test.client.ReceiveHint(repoId, 100, hint(7))
	test.client.ReceiveHint(repoId, 101, hint(5))
	test.client.ReceiveHint(repoId, 102, []byte{0xff})
	if got := test.client.hintedVersion(repoId, refId); got != 7 {
		t.Errorf("hinted %d", got)
	}
}

// Every method this draft does not build answers ErrEvsNotBuilt and sends nothing.
func TestEvsUnbuiltMethodsRefuse(t *testing.T) {
	sent := 0
	test := newEvsTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		sent += 1
	}), newEvsTestStore(t))
	repo := test.client.Repo(evsTestId("repo"))
	ctx := context.Background()
	calls := []error{}
	_, err := repo.Write(ctx, &EvsWriteArgs{})
	calls = append(calls, err)
	_, err = repo.Deposit(ctx, &EvsDepositArgs{})
	calls = append(calls, err)
	_, err = repo.Consume(ctx, &EvsConsumeArgs{})
	calls = append(calls, err)
	_, err = repo.Subscribe(ctx, &EvsSubscribeArgs{})
	calls = append(calls, err)
	_, err = repo.Erasures(ctx)
	calls = append(calls, err)
	_, err = repo.Import(ctx, &EvsImportArgs{})
	calls = append(calls, err)
	for i, err := range calls {
		if !errors.Is(err, ErrEvsNotBuilt) {
			t.Errorf("call %d: %v", i, err)
		}
	}
	if sent != 0 {
		t.Errorf("sent %d", sent)
	}
}
