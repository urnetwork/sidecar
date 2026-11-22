package sidecar

// EvsRepo.Subscribe and catch-up (§11.10, FS-12, §22.5's prefix subscriptions, FS-4's closing case) on the stand-in
// evs of evs_world_test.go, beside a stand-in of evs's lease routes that keeps leases as {evsl_<repo_id>} does and can
// fail, crash after its write, or lose them all. The changes rows (the e2e blogger case's findings): every commit that
// passes a client's pin raises its change once to each subscriber, whichever call of the client verified it.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
	// where every other request goes, the world when nil: a push stand-in for a client that writes
	next http.Handler

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
	case self.next != nil:
		self.next.ServeHTTP(writer, request)
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
	// how many came, for await, made on first use
	count *MonitorValue[int]
}

// The count's monitor.
func (self *evsTestChanges) counter() *MonitorValue[int] {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.count == nil {
		self.count = NewMonitorValue(len(self.changes))
	}
	return self.count
}

func (self *evsTestChanges) add(change *EvsRepoChange) {
	counter := self.counter()
	count := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.changes = append(self.changes, change)
		return len(self.changes)
	}()
	counter.Set(count)
}

// Waits until a change at version or past it came, or ctx ends: a bound on a hang, never what a test proves by.
func (self *evsTestChanges) await(ctx context.Context, version uint64) error {
	counter := self.counter()
	for {
		_, changed := counter.Get()
		if versions := self.versions(); 0 < len(versions) && version <= slices.Max(versions) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("no change at version %d came, only at %v: %w", version, self.versions(), ctx.Err())
		case <-changed:
		}
	}
}

// Each change's signer, in order.
func (self *evsTestChanges) signers() []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	signers := []Id{}
	for _, change := range self.changes {
		signers = append(signers, change.SignerSidecarId)
	}
	return signers
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

// A client of the world that subscribes, reads and writes as a writer of its own, through a lease stand-in of its own
// in front of the push stand-in: what the blogger case's writers are. Its listener of the world's repo hears every
// change, and its subscription's callback its own.
type evsTestSubscriber struct {
	test     *evsTestClient
	signer   *evsTestSigner
	server   *evsTestPushServer
	listened *evsTestChanges
	own      *evsTestChanges
}

// A subscriber of the world signing as label, a writer and reader the world's config holds, writing through server.
func newEvsTestSubscriber(t *testing.T, world *evsTestWorld, server *evsTestPushServer, label string) *evsTestSubscriber {
	t.Helper()
	signer := newEvsTestSigner(label)
	func() {
		world.config.stateLock.Lock()
		defer world.config.stateLock.Unlock()
		world.config.identityKeys[signer.sidecarId] = signer.publicKey()
		world.config.writers = append(world.config.writers, signer.sidecarId)
		world.config.readers = append(world.config.readers, signer.sidecarId)
	}()
	leases := newEvsTestLeases(world)
	leases.next = server
	test := newEvsTestClient(t, leases, newEvsTestStore(t))
	test.client.args.Gkm = newEvsTestWriteGkm()
	test.client.args.Config = func() GkmAuthView { return world.config }
	test.client.args.Sign = signer.sign
	identity := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: signer.sidecarId, ClientId: evsTestId(label + " client")}
	test.client.args.Identity = func() *SidecarIdentity { return identity }
	// the hourly resync half an hour on, out of the way of a clock no test advances that far
	test.client.subscriber.random = func(limit time.Duration) time.Duration { return limit / 2 }
	subscriber := &evsTestSubscriber{test: test, signer: signer, server: server, listened: &evsTestChanges{}, own: &evsTestChanges{}}
	test.client.AddRepoChangeListener(&world.repoId, subscriber.listened.add)
	return subscriber
}

// Subscribes to paths of the world's main ref, the subscription's changes its own.
func (self *evsTestSubscriber) subscribe(t *testing.T, world *evsTestWorld, paths ...string) {
	t.Helper()
	args := &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: paths, Changes: self.own.add}
	if _, err := self.test.client.Repo(world.repoId).Subscribe(context.Background(), args); err != nil {
		t.Fatal(err)
	}
}

// Writes content to path, answering the version it committed at.
func (self *evsTestSubscriber) write(world *evsTestWorld, path string, content []byte) (uint64, error) {
	self.server.know(path)
	result, err := self.test.client.Repo(world.repoId).Write(context.Background(), &EvsWriteArgs{
		Path: path, Content: bytes.NewReader(content), Size: int64(len(content)),
	})
	if err != nil {
		return 0, err
	}
	return result.Version, nil
}

// Reads path fresh, as a webserver's cache miss does.
func (self *evsTestSubscriber) read(world *evsTestWorld, path string) error {
	out := &bytes.Buffer{}
	_, err := self.test.client.Repo(world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: path, Fresh: true}, out)
	return err
}

// Raises client's pin of a ref as a reader that walks the ref's statements itself raises one, the sync engine's,
// record streams' and a git-mode export's (evs_pin_walk.go): the head read fresh, held to the pin it asked at, the
// log walked from that pin, and the head raised with the walk's chains alone, carrying no statement.
func evsTestWalkRaise(ctx context.Context, client *EvsClient, repoId Id, refId Id) error {
	done := client.pins.beginRead(repoId, refId)
	defer done()
	head, err := client.Repo(repoId).pinnedHead(ctx, refId)
	if err != nil {
		return err
	}
	version, chain := uint64(0), EvsChainStart(repoId, refId)
	if head.ask.pin != nil {
		version, chain = head.ask.pin.Version, head.ask.pin.Chain
	}
	trail := newEvsWalkTrail(head.ask)
	trail.start(version, chain)
	walked, err := client.verifier.Walk(ctx, repoId, refId, version, chain, head.Version)
	if err != nil {
		return err
	}
	trail.add(walked)
	raised := trail.head(head)
	if len(raised.Statements) != 0 {
		return errors.New("a walk's raise that carries statements")
	}
	return client.verifier.Pin(raised)
}

// The blogger case's finding (e2e-blogger's TestE2eBloggerChangeAfterTheReadersOwnRead): another writer's commits
// that the client's own calls verify first, a fresh read, its write's plan, a reader that walks the ref itself and so
// raises with no statement, and the mapper's tick, each raise exactly one change per commit to each subscription whose
// paths it touched and to the listener, in order, as does the commit the subscriber's own read verifies, and the
// client's own write; a commit touching no subscribed path raises none, and a round with nothing new raises nothing.
// The client's write also changes the root, whose listing the world's own pushes never write, and the root is on
// every branch, so src's subscription hears that one too. Before the fix only what the subscriber's own read brought
// past the pin was raised, so the commits the other calls verified were lost.
func TestEvsSubscriberRaisesEachCommitOnceWhicheverCallOfItsClientVerifiedIt(t *testing.T) {
	world := newEvsTestWorld(t)
	server := newEvsTestPushServer(t, world)
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	subscriber := newEvsTestSubscriber(t, world, server, "subscriber")
	client := subscriber.test.client
	ctx := context.Background()
	subscriber.subscribe(t, world, "docs")
	other := &evsTestChanges{}
	if _, err := client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"src"}, Changes: other.add}); err != nil {
		t.Fatal(err)
	}
	// the leases' rereads raise nothing: the first commit stood at the pin when the subscriptions began
	subscriber.test.clock.advance(client.settings.SubscribeRereadDelay)
	client.subscriber.runDue(ctx)
	if versions := subscriber.listened.versions(); len(versions) != 0 {
		t.Fatalf("changes before any commit past the pin: %v", versions)
	}
	sequence := uint64(100)
	hinted := func() {
		sequence += 1
		world.hint(subscriber.test, sequence)
		client.subscriber.runDue(ctx)
	}
	push := func(path string) uint64 {
		return world.push(&evsTestChange{path: path, content: []byte(path)})
	}
	// verified first by the client's fresh read, as a webserver's miss does
	readFirst := push("docs/b")
	if err := subscriber.read(world, "docs/b"); err != nil {
		t.Fatal(err)
	}
	hinted()
	// crossed by the client's own write's plan, then the write's own commit
	writeCrossed := push("docs/c")
	written, err := subscriber.write(world, "docs/mine", []byte("mine"))
	if err != nil {
		t.Fatal(err)
	}
	hinted()
	// walked by a reader that raises with chains alone: these changes come from the log
	walkedDocs, walkedOther, walkedSrc := push("docs/d"), push("other/x"), push("src/main.go")
	if err := evsTestWalkRaise(ctx, client, world.repoId, world.refId); err != nil {
		t.Fatal(err)
	}
	hinted()
	// verified first by the mapper's tick, which the component asks of a hint
	ticked := push("docs/e")
	client.Repo(world.repoId).TickMapper(ctx, world.refId)
	hinted()
	// the subscriber's own read alone
	subscriberRead := push("docs/f")
	hinted()
	client.subscriber.runDue(ctx)
	docs := []uint64{readFirst, writeCrossed, written, walkedDocs, ticked, subscriberRead}
	if got := subscriber.own.versions(); !slices.Equal(got, docs) {
		t.Errorf("docs' subscription heard %v, want %v (%d is the commit touching no subscribed path)", got, docs, walkedOther)
	}
	if got := other.versions(); !slices.Equal(got, []uint64{written, walkedSrc}) {
		t.Errorf("src's subscription heard %v, want [%d %d]", got, written, walkedSrc)
	}
	all := []uint64{readFirst, writeCrossed, written, walkedDocs, walkedSrc, ticked, subscriberRead}
	if got := subscriber.listened.versions(); !slices.Equal(got, all) {
		t.Fatalf("the listener heard %v, want %v", got, all)
	}
	for i, signer := range subscriber.listened.signers() {
		want := world.signer.sidecarId
		if all[i] == written {
			want = subscriber.signer.sidecarId
		}
		if signer != want {
			t.Errorf("the change at %d names signer %s, want %s", all[i], signer, want)
		}
	}
	for _, change := range subscriber.listened.changes {
		paths := []string{"docs"}
		switch change.Version {
		case written:
			paths = []string{"docs", "src"}
		case walkedSrc:
			paths = []string{"src"}
		}
		if change.Gap || change.WholeRef || !slices.Equal(change.Paths, paths) {
			t.Errorf("the change at %d: %+v, want paths %v", change.Version, change, paths)
		}
	}
	if alarms := subscriber.test.eventsOf(SidecarEventHeadAlarm); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// The root cause of the blogger case's other finding, commits that reached no subscriber though no read or write of
// the client crossed them: the evs component's hint, before its fix, ran the mapper's tick on the generation's queue
// right after noting the hint, and the tick's fresh head read raised the pin before the subscriber's round read, so
// the round's read brought nothing past it. This replays that order, the hint noted, the tick's read, then the round,
// and the round raises the commit's change.
func TestEvsSubscriberHearsACommitTheMappersTickPinnedFirst(t *testing.T) {
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
	commit := world.push(&evsTestChange{path: "docs/b", content: []byte("b")})
	world.hint(test, 1)
	test.client.Repo(world.repoId).TickMapper(ctx, world.refId)
	if pin, _, _ := test.client.pins.Pin(world.repoId, world.refId); pin == nil || pin.Version != commit {
		t.Fatalf("the tick left the pin at %+v, not %d", pin, commit)
	}
	test.client.subscriber.runDue(ctx)
	if versions := listened.versions(); !slices.Equal(versions, []uint64{commit}) {
		t.Fatalf("the round raised %v, want [%d]", versions, commit)
	}
}

// §11.10's changes row under load (-count=20): three writers' commits, the world's and two of the subscribers' own,
// reach every subscriber exactly once each and in order, while each subscriber's rounds run on their own goroutine,
// woken by the hints and the raises, and its own fresh reads, on a goroutine of their own, raise its pin across every
// other commit before any hint names it and race the rounds for the rest; the next write's plan crosses those too.
// Before the fix the commits the reads raised first were lost.
func TestEvsSubscribersHearEveryCommitOfSeveralWritersOnce(t *testing.T) {
	commitCount := 24
	world := newEvsTestWorld(t)
	server := newEvsTestPushServer(t, world)
	world.push(&evsTestChange{path: "docs/seed", content: []byte("seed")})
	subscribers := []*evsTestSubscriber{
		newEvsTestSubscriber(t, world, server, "writer two"),
		newEvsTestSubscriber(t, world, server, "writer three"),
		newEvsTestSubscriber(t, world, server, "reader"),
	}
	for _, subscriber := range subscribers {
		subscriber.subscribe(t, world, "docs")
		// the rounds' timers fire for no one: a round runs at a hint's or a raise's wake
		subscriber.test.client.clock = &evsSubscribeLoopClock{evsTestClock: subscriber.test.clock, armed: make(chan time.Duration, 1024), fire: make(chan time.Time)}
		if err := subscriber.test.client.StartSubscriptions(); err != nil {
			t.Fatal(err)
		}
	}
	// each subscriber's own fresh read of each commit's path, on a goroutine of its own
	type evsTestReadAsk struct {
		path string
		done chan struct{}
	}
	readAsks := []chan *evsTestReadAsk{}
	readErrors := make(chan error, len(subscribers)*commitCount)
	reading := &sync.WaitGroup{}
	for _, subscriber := range subscribers {
		asks := make(chan *evsTestReadAsk, commitCount)
		readAsks = append(readAsks, asks)
		reading.Add(1)
		go func() {
			defer reading.Done()
			for ask := range asks {
				if err := subscriber.read(world, ask.path); err != nil && !errors.Is(err, ErrEvsReadStale) {
					readErrors <- fmt.Errorf("%s's read of %s: %w", subscriber.signer.sidecarId, ask.path, err)
				}
				close(ask.done)
			}
		}()
	}
	versions := []uint64{}
	sequence := uint64(0)
	for i := range commitCount {
		path := fmt.Sprintf("docs/commit-%d", i)
		version := uint64(0)
		if writer := i % 3; writer == 0 {
			version = world.push(&evsTestChange{path: path, content: []byte(path)})
		} else {
			committed, err := subscribers[writer-1].write(world, path, []byte(path))
			if err != nil {
				t.Fatalf("commit %d: %v", i, err)
			}
			version = committed
		}
		versions = append(versions, version)
		dones := []chan struct{}{}
		for _, asks := range readAsks {
			ask := &evsTestReadAsk{path: path, done: make(chan struct{})}
			asks <- ask
			dones = append(dones, ask.done)
		}
		if i%2 == 0 {
			// the reads raise every subscriber's pin across this commit before any hint names it, and the next commit's
			// hint, which covers both, finds nothing past the pin to read
			for _, done := range dones {
				<-done
			}
			continue
		}
		sequence += 1
		for _, subscriber := range subscribers {
			world.hint(subscriber.test, sequence)
		}
	}
	for _, asks := range readAsks {
		close(asks)
	}
	reading.Wait()
	close(readErrors)
	for err := range readErrors {
		t.Error(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, subscriber := range subscribers {
		if err := subscriber.listened.await(ctx, versions[len(versions)-1]); err != nil {
			t.Fatalf("%s: %v", subscriber.signer.sidecarId, err)
		}
	}
	for _, subscriber := range subscribers {
		subscriber.test.client.Close()
	}
	for _, subscriber := range subscribers {
		if got := subscriber.listened.versions(); !slices.Equal(got, versions) {
			t.Errorf("%s's listener heard %v, want %v", subscriber.signer.sidecarId, got, versions)
		}
		if got := subscriber.own.versions(); !slices.Equal(got, versions) {
			t.Errorf("%s's subscription heard %v, want %v", subscriber.signer.sidecarId, got, versions)
		}
	}
}

// Past §11.9's catch-up budget a delivery reads no further: commits another call verified, raising with no statement,
// whose log passes the budget from the mark raise one gap change at the pin naming every subscribed path; and a log
// that fails its checks, a version missing from its pages, raises a gap change too, never a change it could not
// verify. Each moves the mark to the pin, so nothing is raised twice.
func TestEvsSubscriberRaisesAGapForWhatItCannotWalk(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	ctx := context.Background()
	listened := &evsTestChanges{}
	test.client.AddRepoChangeListener(&world.repoId, listened.add)
	if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs", "src"}}); err != nil {
		t.Fatal(err)
	}
	test.clock.advance(test.client.settings.SubscribeRereadDelay)
	test.client.subscriber.runDue(ctx)
	statementByteCount := func(version uint64) int64 {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		return int64(len(world.commits[version-1].statement))
	}
	// four commits, a budget of two statements
	for _, path := range []string{"docs/b", "docs/c", "docs/d", "docs/e"} {
		world.push(&evsTestChange{path: path, content: []byte(path)})
	}
	test.client.settings.CatchUpByteCount = 2 * statementByteCount(2)
	if err := evsTestWalkRaise(ctx, test.client, world.repoId, world.refId); err != nil {
		t.Fatal(err)
	}
	test.client.subscriber.runDue(ctx)
	change := listened.last()
	if count := len(listened.versions()); count != 1 || !change.Gap || change.Version != 5 || !slices.Equal(change.Paths, []string{"docs", "src"}) {
		t.Fatalf("past the budget: %d changes, the last %+v", count, change)
	}
	// a log missing a version of those another call verified
	test.client.settings.CatchUpByteCount = DefaultEvsSettings().CatchUpByteCount
	for _, path := range []string{"docs/f", "docs/g"} {
		world.push(&evsTestChange{path: path, content: []byte(path)})
	}
	if err := evsTestWalkRaise(ctx, test.client, world.repoId, world.refId); err != nil {
		t.Fatal(err)
	}
	world.stateLock.Lock()
	world.omitVersion = 6
	world.stateLock.Unlock()
	test.client.subscriber.runDue(ctx)
	change = listened.last()
	if count := len(listened.versions()); count != 2 || !change.Gap || change.Version != 7 {
		t.Fatalf("a log missing a version: %d changes, the last %+v", count, change)
	}
	test.client.subscriber.runDue(ctx)
	if count := len(listened.versions()); count != 2 {
		t.Errorf("a round after raised %d changes", count-2)
	}
}

// The marks start at the pins after a restart: a restarted client's round raises the commit past its pin once, and
// nothing below it again.
func TestEvsSubscriberMarksStartAtThePinsAfterARestart(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	store := newEvsTestStore(t)
	test := newEvsSubscribeTest(t, world, leases, store)
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	ctx := context.Background()
	if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}}); err != nil {
		t.Fatal(err)
	}
	world.push(&evsTestChange{path: "docs/b", content: []byte("b")})
	world.hint(test, 1)
	test.client.subscriber.runDue(ctx)
	test.client.Close()
	commit := world.push(&evsTestChange{path: "docs/c", content: []byte("c")})
	restarted := newEvsSubscribeTest(t, world, leases, store)
	listened := &evsTestChanges{}
	restarted.client.AddRepoChangeListener(&world.repoId, listened.add)
	world.hint(restarted, 2)
	restarted.client.subscriber.runDue(ctx)
	if versions := listened.versions(); !slices.Equal(versions, []uint64{commit}) {
		t.Fatalf("after the restart: %v, want [%d]", versions, commit)
	}
}

// HeadCheck's catch-up (§6.4, evs_witness.go) raises the pin through the log to a replaying peer's head with no read
// of its own: the commits it passes raise their changes, once, at the next round, with no hint.
func TestEvsSubscriberHearsTheCommitsHeadChecksCatchUpPinned(t *testing.T) {
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
	first := world.push(&evsTestChange{path: "docs/b", content: []byte("b")})
	second := world.push(&evsTestChange{path: "docs/c", content: []byte("c")})
	version, chain := world.head()
	through := &protocol.RefHead{RepoId: world.repoId.Bytes(), RefId: world.refId.Bytes(), Version: version, Chain: chain[:]}
	if result, err := test.client.CatchUpRef(ctx, through); result != HeadCheckCaughtUp || err != nil {
		t.Fatalf("the catch-up: %v %v", result, err)
	}
	test.client.subscriber.runDue(ctx)
	test.client.subscriber.runDue(ctx)
	if versions := listened.versions(); !slices.Equal(versions, []uint64{first, second}) {
		t.Fatalf("after HeadCheck's catch-up: %v, want [%d %d]", versions, first, second)
	}
}
