//go:build !sidecar_http

// The evs component routes a hint on evs:<repo_id> through its generation's queue to the client, refuses a topic
// that names no repo, drops hints between generations, and runs no mapper's tick on the queue.

package sidecar

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A hint reaches the client in the generation's queue, in order, and nothing does without a generation. The mapper's
// tick the hint asks for runs on the mapper's loop, whose read evs answers 404 here.
func TestEvsComponentRoutesHintsThroughItsQueue(t *testing.T) {
	test := newEvsTestClient(t, http.NotFoundHandler(), newEvsTestStore(t))
	component := NewEvsComponent(test.client)
	repoId, refId := evsTestId("repo"), evsTestId("ref")
	delta, _ := proto.Marshal(&protocol.EvsHeadChanged{RefId: refId.Bytes(), Version: 9})
	if component.ReceiveHint(PushTopicEvs(repoId), 1, delta) {
		t.Errorf("a hint with no generation was taken")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := newSidecarComponentQueue(ctx, 4, 1024*1024, &sidecarQueueCounters{}, NewNoopLogger())
	defer queue.closeAndWait()
	env := &SidecarEnv{Ctx: ctx, queue: queue}
	if err := component.Attach(env); err != nil {
		t.Fatal(err)
	}
	if component.ReceiveHint("evs:not-an-id", 1, delta) || component.ReceiveHint(PushTopicCore, 1, delta) {
		t.Errorf("a topic that names no repo was taken")
	}
	if !component.ReceiveHint(PushTopicEvs(repoId), 2, delta) {
		t.Fatalf("the hint was dropped")
	}
	done := make(chan struct{})
	if !env.Enqueue(0, func(ctx context.Context) { close(done) }) {
		t.Fatal("the marker was dropped")
	}
	<-done
	if got := test.client.hintedVersion(repoId, refId); got != 9 {
		t.Errorf("hinted %d", got)
	}
}

// §11.10's renew row: a reconnect, a new generation attaching, starts the subscriptions' rounds once and renews no
// lease that is not due.
func TestEvsComponentReconnectRenewsNothing(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	ctx := context.Background()
	if _, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}}); err != nil {
		t.Fatal(err)
	}
	test.client.subscriber.nextResyncAt = test.clock.Now().Add(1000 * time.Hour)
	posts := leases.postCount()
	test.client.clock = &evsSubscribeLoopClock{evsTestClock: test.clock, armed: make(chan time.Duration, 64), fire: make(chan time.Time)}
	component := NewEvsComponent(test.client)
	for range 2 {
		componentCtx, cancel := context.WithCancel(context.Background())
		queue := newSidecarComponentQueue(componentCtx, 4, 1024*1024, &sidecarQueueCounters{}, NewNoopLogger())
		if err := component.Attach(&SidecarEnv{Ctx: componentCtx, queue: queue}); err != nil {
			t.Fatal(err)
		}
		cancel()
		queue.closeAndWait()
	}
	component.Close()
	test.client.subscriber.runDue(ctx)
	if leases.postCount() != posts {
		t.Errorf("a reconnect renewed: %d", leases.postCount()-posts)
	}
}

// The evs component's hint does no I/O on the generation's queue: the mapper's tick it asks for runs on the mapper's
// loop, so a later hint reaches the client while that tick's head read is still held. Before the fix the tick ran on
// the queue and every later hint waited behind its read, the bounded queue dropping them once full.
func TestEvsComponentHintWaitsForNoMapperTick(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	test := newEvsSubscribeTest(t, world, newEvsTestLeases(world), newEvsTestStore(t))
	test.client.clock = &evsSubscribeLoopClock{evsTestClock: test.clock, armed: make(chan time.Duration, 64), fire: make(chan time.Time)}
	held, release := make(chan struct{}), make(chan struct{})
	var holdOnce sync.Once
	world.stateLock.Lock()
	world.beforeRead = func(read *protocol.EvsReadRequest) {
		holdOnce.Do(func() {
			close(held)
			<-release
		})
	}
	world.stateLock.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	queue := newSidecarComponentQueue(ctx, 4, 1024*1024, &sidecarQueueCounters{}, NewNoopLogger())
	component := NewEvsComponent(test.client)
	defer func() {
		// the held read let go first, so the mapper's loop and the queue end
		close(release)
		cancel()
		queue.closeAndWait()
		component.Close()
	}()
	env := &SidecarEnv{Ctx: ctx, queue: queue}
	if err := component.Attach(env); err != nil {
		t.Fatal(err)
	}
	hint := func(version uint64) []byte {
		delta, _ := proto.Marshal(&protocol.EvsHeadChanged{RefId: world.refId.Bytes(), Version: version})
		return delta
	}
	if !component.ReceiveHint(PushTopicEvs(world.repoId), 1, hint(1)) {
		t.Fatal("the first hint was dropped")
	}
	<-held
	if !component.ReceiveHint(PushTopicEvs(world.repoId), 2, hint(2)) {
		t.Fatal("the second hint was dropped")
	}
	done := make(chan struct{})
	if !env.Enqueue(0, func(ctx context.Context) { close(done) }) {
		t.Fatal("the marker was dropped")
	}
	select {
	case <-done:
	case <-time.After(time.Minute):
		// a bound on a hang, never what this proves by: the queue waited behind the tick's held read
		t.Fatal("a hint waited on the queue behind the mapper's tick")
	}
	if got := test.client.hintedVersion(world.repoId, world.refId); got != 2 {
		t.Errorf("the client was hinted %d, not 2", got)
	}
}
