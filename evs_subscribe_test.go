package sidecar

// EvsRepo.Subscribe and catch-up (§11.10, FS-12, §22.5's prefix subscriptions, FS-4's closing case) on the stand-in
// evs of evs_world_test.go, beside a stand-in of evs's lease routes that keeps leases as {evsl_<repo_id>} does and can
// fail, crash after its write, or lose them all.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The stand-in of POST, GET and DELETE /evs/v1/subscriptions and GET .../refs, in front of a world.
type evsTestLeases struct {
	world *evsTestWorld

	stateLock sync.Mutex
	// ref|epoch|prefix: a lease, as the hash's field names one
	leases  map[string]*protocol.EvsSubscription
	posts   []*protocol.EvsSubscriptionRequest
	deletes []*protocol.EvsSubscriptionRequest
	lists   int
	// answer the next n POSTs 503 and write nothing
	failPosts int
	// write the next n POSTs' leases, then answer 503: a crash after the Redis write and before the 200
	writeThenFailPosts int
	// GET .../refs is served (M6's listing), else 404 as before EVS1-M6-01
	serveRefs  bool
	refsListed int
}

func newEvsTestLeases(world *evsTestWorld) *evsTestLeases {
	return &evsTestLeases{world: world, leases: map[string]*protocol.EvsSubscription{}}
}

// A lease's field.
func evsTestLeaseField(refId []byte, epoch uint64, prefix []byte) string {
	return string(refId) + "|" + string(rune('0'+epoch)) + "|" + string(prefix)
}

func (self *evsTestLeases) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	refuse := func(status int, code protocol.EvsRefusalCode) {
		body, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: code})
		writer.WriteHeader(status)
		writer.Write(body)
	}
	switch {
	case request.URL.Path == "/evs/v1/subscriptions":
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if request.Method == http.MethodGet {
			self.lists += 1
			reply := &protocol.EvsSubscriptionsReply{}
			for _, lease := range self.leases {
				reply.Subscriptions = append(reply.Subscriptions, lease)
			}
			body, _ := proto.Marshal(reply)
			writer.WriteHeader(http.StatusOK)
			writer.Write(body)
			return
		}
		body, _ := io.ReadAll(request.Body)
		lease := &protocol.EvsSubscriptionRequest{}
		if err := proto.Unmarshal(body, lease); err != nil || lease.GetPathEpoch() == 0 || 16 < len(lease.GetPrefixes()) {
			refuse(http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
			return
		}
		prefixes := lease.GetPrefixes()
		if len(prefixes) == 0 {
			prefixes = []*protocol.EvsTokenPath{{}}
		}
		if request.Method == http.MethodDelete {
			self.deletes = append(self.deletes, lease)
			for _, prefix := range prefixes {
				delete(self.leases, evsTestLeaseField(lease.GetRefId(), lease.GetPathEpoch(), bytesOfTokens(prefix)))
			}
			writer.WriteHeader(http.StatusOK)
			return
		}
		self.posts = append(self.posts, lease)
		if 0 < self.failPosts {
			self.failPosts -= 1
			refuse(http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
			return
		}
		for _, prefix := range prefixes {
			self.leases[evsTestLeaseField(lease.GetRefId(), lease.GetPathEpoch(), bytesOfTokens(prefix))] = &protocol.EvsSubscription{
				RefId: lease.GetRefId(), PathEpoch: lease.GetPathEpoch(), Prefix: prefix, ExpiresMs: 1,
			}
		}
		if 0 < self.writeThenFailPosts {
			self.writeThenFailPosts -= 1
			refuse(http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
			return
		}
		writer.WriteHeader(http.StatusOK)
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/refs"):
		self.stateLock.Lock()
		serve := self.serveRefs
		self.refsListed += 1
		self.stateLock.Unlock()
		if !serve {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := proto.Marshal(&protocol.EvsRefsReply{Format: 1, PushSequence: 1, Refs: []*protocol.EvsHeadSummary{{RefId: self.world.refId.Bytes()}}})
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	default:
		self.world.ServeHTTP(writer, request)
	}
}

// A prefix's bytes, its tokens joined.
func bytesOfTokens(prefix *protocol.EvsTokenPath) []byte {
	joined := []byte{}
	for _, token := range prefix.GetToken() {
		joined = append(joined, token...)
	}
	return joined
}

// The lease fields standing.
func (self *evsTestLeases) fields() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fields := []string{}
	for field := range self.leases {
		fields = append(fields, field)
	}
	slices.Sort(fields)
	return fields
}

// Redis lost {evsl_<repo_id>}.
func (self *evsTestLeases) lose() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.leases = map[string]*protocol.EvsSubscription{}
}

func (self *evsTestLeases) postCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.posts)
}

// The reads the world served.
func (self *evsTestWorld) readCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.reads
}

// A path's token path in epoch.
func (self *evsTestWorld) tokensIn(path string, epoch uint64) EvsTokenPath {
	names := [][]byte{}
	for _, name := range strings.Split(path, "/") {
		names = append(names, []byte(name))
	}
	tokenPath, err := EvsPathTokens(evsTestPathKey(self.t, self.repoId, epoch), names)
	if err != nil {
		self.t.Fatal(err)
	}
	return tokenPath
}

// A reader of the world behind the lease stand-in, on store, its random offsets 0.
func newEvsSubscribeTest(t *testing.T, world *evsTestWorld, leases *evsTestLeases, store SidecarStore) *evsTestClient {
	t.Helper()
	test := newEvsTestClient(t, leases, store)
	test.client.args.Gkm = world.gkm
	test.client.args.Config = func() GkmAuthView { return world.config }
	identity := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: evsTestId("subscriber"), ClientId: evsTestId("subscriber client")}
	test.client.args.Identity = func() *SidecarIdentity { return identity }
	test.client.subscriber.random = func(limit time.Duration) time.Duration { return 0 }
	return test
}

// The changes a listener saw.
type evsTestChanges struct {
	stateLock sync.Mutex
	changes   []*EvsRepoChange
}

func (self *evsTestChanges) add(change *EvsRepoChange) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.changes = append(self.changes, change)
}

func (self *evsTestChanges) versions() []uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	versions := []uint64{}
	for _, change := range self.changes {
		versions = append(versions, change.Version)
	}
	return versions
}

func (self *evsTestChanges) last() *EvsRepoChange {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.changes) == 0 {
		return nil
	}
	return self.changes[len(self.changes)-1]
}

// A hint as evs sends one for the world's head: the repo's push sequence and EvsHeadChanged.
func (self *evsTestWorld) hint(test *evsTestClient, sequence uint64) {
	version, chain := self.head()
	delta, _ := proto.Marshal(&protocol.EvsHeadChanged{RefId: self.refId.Bytes(), Version: version, Chain: chain[:]})
	test.client.ReceiveHint(self.repoId, sequence, delta)
}

// FS-12 and §22.5: a subscription tokenizes its paths in the ref's epoch and leases them; 5 s after the 200 it rereads
// the head fresh, which catches a commit made before then that no hint named; a hinted commit after it is read; each
// change names the subscribed path it touched and its signer, and a commit touching none raises nothing.
func TestEvsSubscribeLeasesItsPrefixesAndReadsWhatMoved(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	// the hourly resync half an hour on, out of this test's way
	test.client.subscriber.random = func(limit time.Duration) time.Duration { return limit / 2 }
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	repo := test.client.Repo(world.repoId)
	listened := &evsTestChanges{}
	remove := test.client.AddRepoChangeListener(&world.repoId, listened.add)
	defer remove()
	own := &evsTestChanges{}
	ctx := context.Background()
	if _, err := repo.Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs", "src/main.go"}, Changes: own.add}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		evsTestLeaseField(world.refId.Bytes(), 1, world.tokens("docs").Bytes()),
		evsTestLeaseField(world.refId.Bytes(), 1, world.tokens("src/main.go").Bytes()),
	}
	slices.Sort(want)
	if got := leases.fields(); !slices.Equal(got, want) {
		t.Fatalf("leases %q, want %q", got, want)
	}
	// a commit after the 200 and before the reread, which no hint names
	world.push(&evsTestChange{path: "docs/b", content: []byte("b")})
	test.client.subscriber.runDue(ctx)
	if versions := listened.versions(); len(versions) != 0 {
		t.Fatalf("changes before the reread: %v", versions)
	}
	test.clock.advance(test.client.settings.SubscribeRereadDelay)
	readsBefore := world.readCount()
	test.client.subscriber.runDue(ctx)
	if world.readCount() != readsBefore+1 {
		t.Fatalf("the reread read %d times", world.readCount()-readsBefore)
	}
	change := listened.last()
	if change == nil || change.Version != 2 || !slices.Equal(change.Paths, []string{"docs"}) || change.SignerSidecarId != world.signer.sidecarId || change.WholeRef {
		t.Fatalf("the reread's change %+v", change)
	}
	// a commit touching no subscribed path raises nothing; a hinted one touching a subpath does
	world.push(&evsTestChange{path: "other/x", content: []byte("x")})
	world.hint(test, 100)
	test.client.subscriber.runDue(ctx)
	if versions := listened.versions(); !slices.Equal(versions, []uint64{2}) {
		t.Fatalf("an untouched commit raised %v", versions)
	}
	test.clock.advance(time.Second)
	world.push(&evsTestChange{path: "src/main.go", content: []byte("main")})
	world.hint(test, 101)
	test.client.subscriber.runDue(ctx)
	change = listened.last()
	if change == nil || change.Version != 4 || !slices.Equal(change.Paths, []string{"src/main.go"}) {
		t.Fatalf("the hinted change %+v", change)
	}
	if versions := own.versions(); !slices.Equal(versions, []uint64{2, 4}) {
		t.Errorf("the subscription's own changes %v", versions)
	}
}

// FS-12: a crash after the lease's Redis write and before the 200: the retry writes the same lease and gets its 200.
// And a device that dies with the lease owed: its record is in the sealed store, and its next start leases it.
func TestEvsSubscribeRetriesUntilTheTwoHundredAcrossARestart(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	store := newEvsTestStore(t)
	test := newEvsSubscribeTest(t, world, leases, store)
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	ctx := context.Background()
	leases.writeThenFailPosts = 1
	if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}}); err != nil {
		t.Fatal(err)
	}
	if leases.postCount() != 2 || len(leases.fields()) != 1 {
		t.Fatalf("%d posts, leases %q", leases.postCount(), leases.fields())
	}
	// a second subscription whose lease never answers before the device dies
	leases.failPosts = 100
	if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"src"}}); err != nil {
		t.Fatal(err)
	}
	if len(leases.fields()) != 1 {
		t.Fatalf("leases %q", leases.fields())
	}
	test.client.Close()
	leases.failPosts = 0
	restarted := newEvsSubscribeTest(t, world, leases, store)
	restarted.client.subscriber.runDue(ctx)
	want := []string{
		evsTestLeaseField(world.refId.Bytes(), 1, world.tokens("docs").Bytes()),
		evsTestLeaseField(world.refId.Bytes(), 1, world.tokens("src").Bytes()),
	}
	slices.Sort(want)
	if got := leases.fields(); !slices.Equal(got, want) {
		t.Fatalf("after the restart: leases %q, want %q", got, want)
	}
	if count := len(restarted.client.subscriber.subscriptions); count != 2 {
		t.Errorf("%d subscriptions after the restart", count)
	}
}

// The hint rows: one past the repo's sequence reads only the named ref; a skip, the first hint, or a fall reads every
// subscribed ref of the repo, a fall as a gap that raises no alarm.
func TestEvsHintSequenceChoosesWhatToRead(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	ctx := context.Background()
	if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName}); err != nil {
		t.Fatal(err)
	}
	subscriber := test.client.subscriber
	queued := func() *evsSyncRequest {
		subscriber.stateLock.Lock()
		defer subscriber.stateLock.Unlock()
		request := subscriber.syncs[world.repoId]
		delete(subscriber.syncs, world.repoId)
		return request
	}
	queued()
	cases := []struct {
		sequence uint64
		all      bool
	}{
		{sequence: 50, all: true},
		{sequence: 51, all: false},
		{sequence: 53, all: true},
		{sequence: 20, all: true},
		{sequence: 21, all: false},
	}
	for _, c := range cases {
		world.hint(test, c.sequence)
		request := queued()
		if request == nil || request.all != c.all || (!c.all && !request.refIds[world.refId]) {
			t.Errorf("sequence %d: %+v", c.sequence, request)
		}
	}
	// a hint for a repo nothing subscribes reads nothing
	delta, _ := proto.Marshal(&protocol.EvsHeadChanged{RefId: world.refId.Bytes(), Version: 1})
	test.client.ReceiveHint(evsTestId("other repo"), 1, delta)
	if _, ok := subscriber.syncs[evsTestId("other repo")]; ok {
		t.Error("an unsubscribed repo queued a read")
	}
	// the fall, read through: a gap, never an alarm
	world.push(&evsTestChange{path: "docs/b", content: []byte("b")})
	world.hint(test, 3)
	subscriber.runDue(ctx)
	if alarms := test.eventsOf(SidecarEventHeadAlarm); len(alarms) != 0 {
		t.Errorf("a fall alarmed: %v", alarms)
	}
	// a reset that moved the topic reads at once, fresh
	test.client.ReceiveResync(world.repoId, 7)
	if request := queued(); request == nil || !request.all || !request.fresh {
		t.Errorf("the reset queued %+v", request)
	}
}

// FS-12's loss row: the lease family lost, the hourly resync lists the caller's leases, finds them gone, re-creates
// them and reads every subscribed head fresh.
func TestEvsHourlyResyncReCreatesLostLeases(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	ctx := context.Background()
	if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}}); err != nil {
		t.Fatal(err)
	}
	subscriber := test.client.subscriber
	subscriber.random = func(limit time.Duration) time.Duration { return limit / 2 }
	subscriber.runDue(ctx)
	leased := leases.fields()
	leases.lose()
	test.clock.advance(test.client.settings.SubscribeResyncInterval)
	readsBefore := world.readCount()
	subscriber.runDue(ctx)
	subscriber.runDue(ctx)
	if got := leases.fields(); !slices.Equal(got, leased) {
		t.Fatalf("after the resync: leases %q, want %q", got, leased)
	}
	if leases.lists == 0 || world.readCount() == readsBefore {
		t.Errorf("the resync listed %d times and read %d times", leases.lists, world.readCount()-readsBefore)
	}
}

// §11.10's renew row: a lease over 24 h old is renewed at a random time within the next hour, and a reconnect renews
// nothing.
func TestEvsLeaseRenewsOnceOverADayAtARandomTime(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	ctx := context.Background()
	if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}}); err != nil {
		t.Fatal(err)
	}
	subscriber := test.client.subscriber
	subscriber.random = func(limit time.Duration) time.Duration { return 10 * time.Minute }
	// keep the hourly resync out of the count
	subscriber.nextResyncAt = test.clock.Now().Add(1000 * time.Hour)
	posts := leases.postCount()
	test.clock.advance(test.client.settings.SubscribeRenewAge - time.Minute)
	subscriber.runDue(ctx)
	if leases.postCount() != posts {
		t.Fatal("renewed before a day")
	}
	test.clock.advance(time.Minute)
	subscriber.runDue(ctx)
	if leases.postCount() != posts {
		t.Fatal("renewed at once, not at its random time")
	}
	test.clock.advance(10 * time.Minute)
	subscriber.runDue(ctx)
	if leases.postCount() != posts+1 {
		t.Fatalf("%d renewals", leases.postCount()-posts)
	}
}

// FS-4's closing case: a read finding the ref's current epoch past the lease's re-tokenizes the subscription, leases
// it in the new epoch and deletes the old epoch's lease; a change in either epoch still names its path.
func TestEvsPathEpochReCreatesLeasesInTheNewEpoch(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	ctx := context.Background()
	listened := &evsTestChanges{}
	test.client.AddRepoChangeListener(nil, listened.add)
	if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}}); err != nil {
		t.Fatal(err)
	}
	world.stateLock.Lock()
	world.currentEpoch = 2
	world.stateLock.Unlock()
	world.push(&evsTestChange{path: "docs/b", content: []byte("b")})
	world.hint(test, 40)
	subscriber := test.client.subscriber
	subscriber.runDue(ctx)
	subscriber.runDue(ctx)
	want := []string{evsTestLeaseField(world.refId.Bytes(), 2, world.tokensIn("docs", 2).Bytes())}
	if got := leases.fields(); !slices.Equal(got, want) {
		t.Fatalf("leases %q, want epoch 2's %q", got, want)
	}
	if change := listened.last(); change == nil || change.Version != 2 || !slices.Equal(change.Paths, []string{"docs"}) {
		t.Errorf("the change %+v", change)
	}
	for id := range subscriber.subscriptions {
		if epoch := subscriber.subscriptions[id].pathEpoch; epoch != 2 {
			t.Errorf("the subscription's epoch %d", epoch)
		}
	}
}

// §22.5's prefix subscriptions: more than 16 paths are refused before anything is sent; no paths leases the whole
// ref; no ref leases every ref, in main's epoch; Close drops the record and deletes the leases no other subscription
// holds.
func TestEvsSubscriptionShapes(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	store := newEvsTestStore(t)
	test := newEvsSubscribeTest(t, world, leases, store)
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	ctx := context.Background()
	repo := test.client.Repo(world.repoId)
	paths := []string{}
	for i := range 17 {
		paths = append(paths, "dir"+string(rune('a'+i)))
	}
	if _, err := repo.Subscribe(ctx, &EvsSubscribeArgs{Paths: paths}); !errors.Is(err, ErrEvsSubscriptionInvalid) {
		t.Fatalf("17 paths: %v", err)
	}
	if leases.postCount() != 0 {
		t.Fatal("17 paths sent")
	}
	whole, err := repo.Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName})
	if err != nil {
		t.Fatal(err)
	}
	every, err := repo.Subscribe(ctx, &EvsSubscribeArgs{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{evsTestLeaseField(nil, 1, nil), evsTestLeaseField(world.refId.Bytes(), 1, nil)}
	slices.Sort(want)
	if got := leases.fields(); !slices.Equal(got, want) {
		t.Fatalf("leases %q, want %q", got, want)
	}
	// every ref: a sync lists the refs (404 before M6, so pins and main)
	world.push(&evsTestChange{path: "docs/b", content: []byte("b")})
	listened := &evsTestChanges{}
	test.client.AddRepoChangeListener(&world.repoId, listened.add)
	test.client.ReceiveResync(world.repoId, 9)
	test.client.subscriber.runDue(ctx)
	if change := listened.last(); change == nil || change.Version != 2 || !change.WholeRef {
		t.Fatalf("the whole ref's change %+v", change)
	}
	whole.Close()
	every.Close()
	if count := len(test.client.subscriber.subscriptions); count != 0 {
		t.Errorf("%d subscriptions after Close", count)
	}
	test.client.subscriber.runDue(ctx)
	if got := leases.fields(); len(got) != 0 {
		t.Errorf("leases after Close %q", got)
	}
	entries, err := store.List(evsSubscriptionDirectory)
	if err != nil || len(entries) != 0 {
		t.Errorf("the store keeps %v %v", entries, err)
	}
}

// A clock whose timers fire only when the test fires them, for the rounds' own goroutine.
type evsSubscribeLoopClock struct {
	*evsTestClock
	armed chan time.Duration
	fire  chan time.Time
}

func (self *evsSubscribeLoopClock) After(timeout time.Duration) <-chan time.Time {
	select {
	case self.armed <- timeout:
	default:
	}
	return self.fire
}

// The rounds' goroutine: Start loads and leases what is owed, a hint wakes it to read, and Close ends it.
func TestEvsSubscriberRoundsRunOnTheirOwnGoroutine(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	ctx := context.Background()
	if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}}); err != nil {
		t.Fatal(err)
	}
	loopClock := &evsSubscribeLoopClock{evsTestClock: test.clock, armed: make(chan time.Duration, 64), fire: make(chan time.Time)}
	test.client.clock = loopClock
	listened := &evsTestChanges{}
	test.client.AddRepoChangeListener(&world.repoId, listened.add)
	rounds, changed := test.client.subscriber.roundCount.Get()
	if err := test.client.StartSubscriptions(); err != nil {
		t.Fatal(err)
	}
	waitRounds := func(after int) {
		for {
			count, next := test.client.subscriber.roundCount.Get()
			if after < count {
				return
			}
			<-next
		}
	}
	<-changed
	waitRounds(rounds)
	rounds, _ = test.client.subscriber.roundCount.Get()
	world.push(&evsTestChange{path: "docs/b", content: []byte("b")})
	world.hint(test, 1)
	waitRounds(rounds)
	if change := listened.last(); change == nil || change.Version != 2 {
		t.Errorf("the change %+v", change)
	}
	test.client.Close()
}
