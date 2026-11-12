//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

package sidecar

// CORE-M10-05: D-CORE-17's budget on a clock the test moves, 4 computing, 16 waiting at most 1 s each, 30 s of CPU a
// minute, the requester's rate, a page's 2 s and 1,000 verifications, 8 MiB a search and 64 cursors; and serving's
// registration, which follows the designation, taints no run, keeps local searches to their own slots, counts with no
// label and persists no query.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A budget under the default settings on a clock the test moves.
func newSearchTestBudget(t *testing.T) (*SidecarRemoteBudget, *SidecarSearchSettings, *searchTestClock) {
	t.Helper()
	settings := DefaultSidecarSettings().Search
	clock := newSearchTestClock()
	budget, err := NewSidecarRemoteBudget(settings, clock)
	if err != nil {
		t.Fatal(err)
	}
	return budget, settings, clock
}

// Admits count requests of fresh requesters at once, failing on a wait or a refusal.
func admitNow(t *testing.T, budget *SidecarRemoteBudget, count int) []*SidecarRemoteAdmission {
	t.Helper()
	admissions := []*SidecarRemoteAdmission{}
	for range count {
		admission, err := budget.Admit(t.Context(), NewId())
		if err != nil {
			t.Fatal(err)
		}
		admissions = append(admissions, admission)
	}
	return admissions
}

// One Admit run in the background, its answer on a channel.
type searchTestAdmit struct {
	admission *SidecarRemoteAdmission
	err       error
}

func admitLater(ctx context.Context, budget *SidecarRemoteBudget, requesterId Id) chan searchTestAdmit {
	answer := make(chan searchTestAdmit, 1)
	go func() {
		admission, err := budget.Admit(ctx, requesterId)
		answer <- searchTestAdmit{admission: admission, err: err}
	}()
	return answer
}

// Waits until the budget has waiting requests waiting: each arms its timeout after it joins the queue, so the clock's
// armed timers say when they all have.
func awaitWaiting(t *testing.T, budget *SidecarRemoteBudget, clock *searchTestClock, waiting int) {
	t.Helper()
	clock.awaitPending(t, waiting)
	if _, queued := budget.Load(); queued != waiting {
		t.Fatalf("%d waiting, not %d", queued, waiting)
	}
}

// The refusal err is, or a failure.
func refusalOf(t *testing.T, err error) *SidecarRemoteRefusal {
	t.Helper()
	var refusal *SidecarRemoteRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("not a refusal: %v", err)
	}
	return refusal
}

// Four compute at once; a fifth waits, and takes the first slot given back, its wait counted.
func TestFifthSearchQueues(t *testing.T) {
	budget, _, clock := newSearchTestBudget(t)
	world := newSearchTestSidecar(t, nil)
	network := budget.For(world.sidecar)
	admissions := admitNow(t, network, 4)
	if computing, waiting := budget.Load(); computing != 4 || waiting != 0 {
		t.Fatalf("%d computing, %d waiting", computing, waiting)
	}
	fifth := admitLater(t.Context(), network, NewId())
	awaitWaiting(t, budget, clock, 1)
	clock.advance(400 * time.Millisecond)
	admissions[0].Release()
	answer := <-fifth
	if answer.err != nil {
		t.Fatal(answer.err)
	}
	if wait := answer.admission.QueueWait(); wait != 400*time.Millisecond {
		t.Errorf("waited %s", wait)
	}
	if computing, waiting := budget.Load(); computing != 4 || waiting != 0 {
		t.Errorf("%d computing, %d waiting", computing, waiting)
	}
	stats := world.sidecar.Stats().RemoteSearch
	if stats.QueueWaitCount != 1 || stats.QueueWait != 400*time.Millisecond {
		t.Errorf("stats %+v", stats)
	}
}

// With four computing and sixteen waiting, the next is refused at once: RESOURCE_EXHAUSTED, with when to come back.
func TestSeventeenthWaitIsExhausted(t *testing.T) {
	budget, settings, clock := newSearchTestBudget(t)
	admitNow(t, budget, settings.RemoteSearchCount)
	answers := []chan searchTestAdmit{}
	for range settings.RemoteQueueCount {
		answers = append(answers, admitLater(t.Context(), budget, NewId()))
	}
	awaitWaiting(t, budget, clock, settings.RemoteQueueCount)
	_, err := budget.Admit(t.Context(), NewId())
	refusal := refusalOf(t, err)
	if refusal.Reason != SidecarRemoteRefusedQueueFull || refusal.RetryAfter <= 0 {
		t.Errorf("refusal %+v", refusal)
	}
	subprotocolError := refusal.SubprotocolError()
	if subprotocolError.Code != protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED || subprotocolError.RetryAfter != refusal.RetryAfter {
		t.Errorf("answered %+v", subprotocolError)
	}
	// the sixteen time out at their second
	clock.advance(settings.RemoteQueueTimeout)
	for _, answer := range answers {
		if result := <-answer; refusalOf(t, result.err).Reason != SidecarRemoteRefusedQueueTimeout {
			t.Errorf("a waiter answered %v", result.err)
		}
	}
}

// A wait lasts RemoteQueueTimeout, 1 s, on the budget's clock: not a moment less, and then it is refused.
func TestQueueTimeoutOneSecond(t *testing.T) {
	budget, settings, clock := newSearchTestBudget(t)
	admissions := admitNow(t, budget, settings.RemoteSearchCount)
	waiting := admitLater(t.Context(), budget, NewId())
	awaitWaiting(t, budget, clock, 1)
	clock.advance(settings.RemoteQueueTimeout - time.Millisecond)
	select {
	case answer := <-waiting:
		t.Fatalf("answered before its second: %+v", answer)
	default:
	}
	clock.advance(time.Millisecond)
	answer := <-waiting
	refusal := refusalOf(t, answer.err)
	if refusal.Reason != SidecarRemoteRefusedQueueTimeout || refusal.RetryAfter != settings.RemoteQueueTimeout {
		t.Errorf("refusal %+v", refusal)
	}
	// it left the queue, so the next slot given back goes to no one who went
	admissions[0].Release()
	if computing, queued := budget.Load(); computing != settings.RemoteSearchCount-1 || queued != 0 {
		t.Errorf("%d computing, %d waiting", computing, queued)
	}
}

// 30 s of compute a minute for all remote work: spent, the next is refused until the oldest charge leaves the window.
func TestCpuPerMinuteCap(t *testing.T) {
	budget, settings, clock := newSearchTestBudget(t)
	world := newSearchTestSidecar(t, nil)
	network := budget.For(world.sidecar)
	// three slots of 10 s each, given back at 10 s, 20 s and 30 s
	first := admitNow(t, network, 1)[0]
	clock.advance(10 * time.Second)
	if held := first.Release(); held != 10*time.Second {
		t.Fatalf("held %s", held)
	}
	for range 2 {
		admission := admitNow(t, network, 1)[0]
		clock.advance(10 * time.Second)
		admission.Release()
	}
	if cpu := world.sidecar.Stats().RemoteSearch.Cpu; cpu != 30*time.Second {
		t.Errorf("stats cpu %s", cpu)
	}
	_, err := budget.Admit(t.Context(), NewId())
	refusal := refusalOf(t, err)
	// the first charge, at 10 s, leaves the minute at 70 s, 40 s from now
	if refusal.Reason != SidecarRemoteRefusedCpu || refusal.RetryAfter != settings.RemoteCpuWindow-20*time.Second {
		t.Errorf("refusal %+v", refusal)
	}
	clock.advance(refusal.RetryAfter)
	if _, err := budget.Admit(t.Context(), NewId()); err != nil {
		t.Errorf("past the window: %v", err)
	}
	// a slot still held counts what it has held
	budget2, _, clock2 := newSearchTestBudget(t)
	held := admitNow(t, budget2, 1)[0]
	clock2.advance(settings.RemoteCpuPerMinute)
	if _, err := budget2.Admit(t.Context(), NewId()); refusalOf(t, err).Reason != SidecarRemoteRefusedCpu {
		t.Errorf("a held slot's time was not counted: %v", err)
	}
	held.Release()
}

// 64 cursors over every requester: the 65th ends the least recently used.
func TestCursorsDropOldest(t *testing.T) {
	budget, settings, _ := newSearchTestBudget(t)
	ended := make([]bool, settings.RemoteCursorCount+2)
	touches, releases := []func(){}, []func(){}
	for index := range settings.RemoteCursorCount {
		touch, release := budget.AddCursor(func() { ended[index] = true })
		touches = append(touches, touch)
		releases = append(releases, release)
	}
	// the first is used again, so the second is the oldest
	touches[0]()
	budget.AddCursor(func() { ended[settings.RemoteCursorCount] = true })
	if ended[0] || !ended[1] || budget.CursorCount() != settings.RemoteCursorCount {
		t.Errorf("ended first %v, second %v, %d open", ended[0], ended[1], budget.CursorCount())
	}
	for index := 2; index <= settings.RemoteCursorCount; index += 1 {
		if ended[index] {
			t.Errorf("cursor %d ended", index)
		}
	}
	// a cursor that ends by itself leaves the count, and the next takes its place with no other ended
	releases[5]()
	if count := budget.CursorCount(); count != settings.RemoteCursorCount-1 {
		t.Errorf("%d open after a release", count)
	}
	budget.AddCursor(func() { ended[settings.RemoteCursorCount+1] = true })
	for index := 2; index <= settings.RemoteCursorCount+1; index += 1 {
		if ended[index] {
			t.Errorf("cursor %d ended after a release made room", index)
		}
	}
}

// A requester's rate: 10 at once, then one each 2 s (30 a minute); another requester is not held by it.
func TestRequesterRateLimits(t *testing.T) {
	budget, settings, clock := newSearchTestBudget(t)
	requester := NewId()
	for range settings.RemoteRequesterRate.Burst {
		admission, err := budget.Admit(t.Context(), requester)
		if err != nil {
			t.Fatal(err)
		}
		admission.Release()
	}
	_, err := budget.Admit(t.Context(), requester)
	refusal := refusalOf(t, err)
	if refusal.Reason != SidecarRemoteRefusedRate || refusal.RetryAfter != 2*time.Second {
		t.Errorf("refusal %+v", refusal)
	}
	if _, err := budget.Admit(t.Context(), NewId()); err != nil {
		t.Errorf("another requester: %v", err)
	}
	clock.advance(2 * time.Second)
	if _, err := budget.Admit(t.Context(), requester); err != nil {
		t.Errorf("after its token came back: %v", err)
	}
}

// A page stops at 1,000 verifications or 2 s of compute, and a search holds at most 8 MiB.
func TestPageAndMemoryBounds(t *testing.T) {
	budget, settings, clock := newSearchTestBudget(t)
	admission := admitNow(t, budget, 1)[0]
	page := admission.Page()
	for range settings.PageCandidateCount {
		if !page.Verify() {
			t.Fatalf("stopped at %d", page.Verified())
		}
	}
	if page.Verify() || !page.Spent() {
		t.Error("a page went past its verifications")
	}
	timed := admission.Page()
	clock.advance(settings.PageCpu - time.Millisecond)
	if !timed.Verify() {
		t.Error("stopped before its CPU")
	}
	clock.advance(time.Millisecond)
	if timed.Verify() {
		t.Error("a page went past its CPU")
	}
	if !admission.Reserve(settings.RemoteSearchMemoryByteCount) || admission.Reserve(1) {
		t.Error("a search went past its memory")
	}
	admission.Free(1024)
	if !admission.Reserve(1024) {
		t.Error("freed memory did not come back")
	}
	admission.Release()
	if admission.Reserve(1) {
		t.Error("a released admission took memory")
	}
}

// A fake generation dispatcher: what is registered for SEARCH, the features set, and a signal at each change.
type searchServeTestDispatcher struct {
	stateLock sync.Mutex
	handler   SubprotocolHandler
	features  uint64
	changes   chan struct{}
}

func newSearchServeTestDispatcher() *searchServeTestDispatcher {
	return &searchServeTestDispatcher{changes: make(chan struct{}, 16)}
}

func (self *searchServeTestDispatcher) Handle(messageType protocol.MessageType, handler SubprotocolHandler, options *HandleOptions) (func(), error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if messageType != protocol.MessageType_SEARCH || self.handler != nil {
		return nil, errHandleType
	}
	self.handler = handler
	self.changes <- struct{}{}
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.handler = nil
		self.changes <- struct{}{}
	}, nil
}

func (self *searchServeTestDispatcher) SetFeatures(features uint64, asksSearch func(clientId Id) bool) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.features = features
	return nil
}

// Whether SEARCH is registered, and the features set.
func (self *searchServeTestDispatcher) state() (bool, uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.handler != nil, self.features
}

// A search-serve component of world's Sidecar on handler, designated as designated says.
func newSearchServeTest(world *searchTestSidecar, handler SubprotocolHandler, designated *bool, designatedLock *sync.Mutex) *searchServeComponent {
	return newSearchServeComponent(world.sidecar, &DaemonSearchServe{
		Handler: handler,
		Designated: func() bool {
			designatedLock.Lock()
			defer designatedLock.Unlock()
			return *designated
		},
	})
}

// A SEARCH request from requester, its body of the request's size holding text.
func searchServeTestRequest(requesterId Id, text string) *SubprotocolRequest {
	body := make([]byte, DefaultSidecarProtocolSettings().Search.RequestByteCount)
	copy(body, text)
	return &SubprotocolRequest{SourceId: requesterId, MessageType: protocol.MessageType_SEARCH, Body: body}
}

// Serving registers while designated, the handler before bit 0, and leaves when the designation does, bit 0 cleared
// first; with Search.RemoteServe off, as on an app host, nothing registers at all.
func TestServingFollowsDesignation(t *testing.T) {
	world := newSearchTestSidecar(t, nil)
	designated := false
	designatedLock := &sync.Mutex{}
	component := newSearchServeTest(world, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		return []byte("reply"), nil
	}, &designated, designatedLock)
	dispatcher := newSearchServeTestDispatcher()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		component.follow(ctx, dispatcher)
	}()
	waitRecheck := func() {
		// the loop armed its recheck: it has applied what it read
		world.clock.awaitPending(t, 1)
	}
	waitRecheck()
	if registered, features := dispatcher.state(); registered || features != 0 {
		t.Fatalf("registered %v, features %#x before a designation", registered, features)
	}
	setDesignated := func(value bool) {
		designatedLock.Lock()
		designated = value
		designatedLock.Unlock()
		world.clock.advance(world.sidecar.settings.Search.ServeRecheckInterval)
		<-dispatcher.changes
		waitRecheck()
	}
	setDesignated(true)
	if registered, features := dispatcher.state(); !registered || features != SubprotocolFeatureServesSearch {
		t.Fatalf("registered %v, features %#x while designated", registered, features)
	}
	setDesignated(false)
	if registered, features := dispatcher.state(); registered || features != 0 {
		t.Fatalf("registered %v, features %#x after the designation went", registered, features)
	}
	cancel()
	<-done

	app := newSearchTestSidecar(t, searchAppHost)
	appDesignated := true
	appComponent := newSearchServeTest(app, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		return nil, nil
	}, &appDesignated, &sync.Mutex{})
	appDispatcher := newSearchServeTestDispatcher()
	if registered := appComponent.apply(appDispatcher, nil); registered != nil {
		t.Error("an app host registered serving")
	}
	daemon := &Daemon{networkIdSidecars: map[Id]*Sidecar{app.networkId: app.sidecar}}
	if _, err := daemon.ServeRemoteSearch(app.networkId, &DaemonSearchServe{Handler: appComponent.serve.Handler}); !errors.Is(err, ErrSidecarSearchRefused) {
		t.Errorf("an app host's ServeRemoteSearch: %v", err)
	}
}

// Serving runs outside every MCP session and run: an open run stays untainted however many searches it answers, and
// the handler's context carries no session or run.
func TestServingTaintsNoRun(t *testing.T) {
	world := newSearchTestSidecar(t, nil)
	runs, err := world.sidecar.Runs()
	if err != nil {
		t.Fatal(err)
	}
	runId := NewId()
	if err := runs.Create(t.Context(), &RunFile{RunId: runId, Harness: "claude"}); err != nil {
		t.Fatal(err)
	}
	designated := true
	contexts := []context.Context{}
	component := newSearchServeTest(world, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		contexts = append(contexts, ctx)
		return []byte("reply"), nil
	}, &designated, &sync.Mutex{})
	for range 3 {
		if _, err := component.handle(context.Background(), searchServeTestRequest(NewId(), "untrusted words from another member")); err != nil {
			t.Fatal(err)
		}
	}
	if runs.Tainted(runId) {
		t.Error("serving tainted a run")
	}
	for _, ctx := range contexts {
		if ctx != context.Background() {
			t.Error("the handler ran under a context the wrapper made")
		}
	}
	if pages := world.sidecar.Stats().RemoteSearch.PageCount; pages != 3 {
		t.Errorf("%d pages", pages)
	}
}

// Remote serving takes no local slot: with every remote slot and queue place taken and the window's CPU spent, a local
// search on the same Sidecar runs at once, through its own engine's limits.
func TestLocalSearchesKeepTargetsUnderRemoteLoad(t *testing.T) {
	budget, settings, clock := newSearchTestBudget(t)
	world := newSearchTestSidecar(t, nil)
	engine := newSearchTestEngine()
	installSearchTestEngine(t, world.sidecar, engine)
	network := budget.For(world.sidecar)
	admitNow(t, network, settings.RemoteSearchCount)
	for range settings.RemoteQueueCount {
		admitLater(t.Context(), network, NewId())
	}
	awaitWaiting(t, budget, clock, settings.RemoteQueueCount)
	if _, err := network.Admit(t.Context(), NewId()); refusalOf(t, err).Reason != SidecarRemoteRefusedQueueFull {
		t.Fatalf("remote not saturated: %v", err)
	}
	for range settings.DaemonSearchCount {
		stream, err := world.sidecar.Search(t.Context(), &SearchRequest{Text: "local agent's query"})
		if err != nil {
			t.Fatalf("a local search under remote load: %v", err)
		}
		defer stream.Close()
	}
	if computing, _ := budget.Load(); computing != settings.RemoteSearchCount {
		t.Errorf("local searches took remote slots: %d computing", computing)
	}
}

// The counters name codes and nothing else: no requester, repo or query reaches SidecarStats.
func TestStatsCarryNoLabels(t *testing.T) {
	budget, _, _ := newSearchTestBudget(t)
	world := newSearchTestSidecar(t, nil)
	network := budget.For(world.sidecar)
	canary := "q-canary-stats-6d2b-ibis"
	requesterId := NewId()
	designated := true
	designatedLock := &sync.Mutex{}
	component := newSearchServeTest(world, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		admission, err := network.Admit(ctx, request.SourceId)
		if err != nil {
			return nil, err
		}
		defer admission.Release()
		return []byte("reply"), nil
	}, &designated, designatedLock)
	for range world.sidecar.settings.Search.RemoteRequesterRate.Burst + 1 {
		component.handle(t.Context(), searchServeTestRequest(requesterId, canary))
	}
	designatedLock.Lock()
	designated = false
	designatedLock.Unlock()
	component.handle(t.Context(), searchServeTestRequest(requesterId, canary))
	stats := world.sidecar.Stats().RemoteSearch
	if stats.PageCount != uint64(world.sidecar.settings.Search.RemoteRequesterRate.Burst) {
		t.Errorf("%d pages", stats.PageCount)
	}
	refusals := map[string]uint64{}
	for _, refusal := range stats.Refusals {
		refusals[refusal.Code] = refusal.Count
	}
	if refusals["ERR_RESOURCE_EXHAUSTED"] != 1 || refusals["ERR_PERMISSION_DENIED"] != 1 || len(refusals) != 2 {
		t.Errorf("refusals %v", refusals)
	}
	// every string in the stats is a code, and no field is an id
	var walk func(value reflect.Value)
	walk = func(value reflect.Value) {
		switch value.Kind() {
		case reflect.Struct:
			if value.Type() == reflect.TypeFor[Id]() {
				t.Errorf("an id in the stats")
			}
			for index := range value.NumField() {
				walk(value.Field(index))
			}
		case reflect.Slice, reflect.Array:
			if value.Type() == reflect.TypeFor[Id]() {
				t.Errorf("an id in the stats")
			}
			for index := range value.Len() {
				walk(value.Index(index))
			}
		case reflect.String:
			text := value.String()
			if strings.Contains(text, canary) || strings.Contains(text, requesterId.String()) || !strings.HasPrefix(text, "ERR_") {
				t.Errorf("a stats string %q", text)
			}
		}
	}
	walk(reflect.ValueOf(stats))
}

// Nothing about a remote search is persisted but the served record: a search under a canary query, which writes its
// served record, leaves no trace of the query in any file of the network's.
func TestNoQueryPersisted(t *testing.T) {
	budget, _, _ := newSearchTestBudget(t)
	world := newSearchTestSidecar(t, nil)
	network := budget.For(world.sidecar)
	canary := "q-canary-persist-91fd-tapir"
	repoId := NewId()
	state, err := world.sidecar.SearchState()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.sidecar.SearchCache(); err != nil {
		t.Fatal(err)
	}
	designated := true
	component := newSearchServeTest(world, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		admission, err := network.Admit(ctx, request.SourceId)
		if err != nil {
			return nil, err
		}
		defer admission.Release()
		// page 0 of an EvsShare reader's search in an owner-bound repo
		if err := state.RecordServed(request.SourceId, repoId); err != nil {
			return nil, err
		}
		return []byte("reply"), nil
	}, &designated, &sync.Mutex{})
	if _, err := component.handle(t.Context(), searchServeTestRequest(NewId(), canary)); err != nil {
		t.Fatal(err)
	}
	if records, err := state.ServedRecords(); err != nil || len(records) != 1 {
		t.Fatalf("records %v %v", records, err)
	}
	store := world.instance.Store(&world.networkId)
	entries, err := world.backend.List("")
	if err != nil {
		t.Fatal(err)
	}
	opened := 0
	for _, class := range []string{SidecarSearchFileClass} {
		classStore, err := store.Directory("", class)
		if err != nil {
			t.Fatal(err)
		}
		names, err := classStore.List("")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range names {
			reader, err := classStore.Open(entry.Name)
			if err != nil {
				continue
			}
			plaintext, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			opened += 1
			if bytes.Contains(plaintext, []byte(canary)) {
				t.Errorf("%s holds the query", entry.Name)
			}
		}
	}
	if opened == 0 {
		t.Fatal("no file opened, so nothing was checked")
	}
	for _, entry := range entries {
		reader, err := world.backend.Open(entry.Name)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(reader)
		reader.Close()
		if bytes.Contains(raw, []byte(canary)) {
			t.Errorf("%s holds the query in the clear", entry.Name)
		}
	}
}
