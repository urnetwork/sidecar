//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// An owned ref's queue that finds no enrolled client holds, offline in DESIGN-DETAILS 8.2.8's queue rows, rather than
// build and seal its push again every QueueInterval to fail at its first token, and the next client generation's start
// releases it, the queue building on that generation (service-token-refusal-classify). With stock git pushing to a
// mount, as evs_local_receive_test.go's tests do, and the queue's rounds run by hand on the evs test clock; and the evs
// component telling the local tier of each generation it follows, which is that start.

package sidecar

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The writer's token keeper as a sidecar runs it with or without a client generation: while offline every token of
// the scopes it refuses answers ErrSidecarServiceTokenNoClient, nil refusing every scope; once a generation runs, the
// test writer's tokens. Counts the asks it refused or would have. Safe for concurrent use.
type evsTestOfflineTokens struct {
	tokens *evsTestTokens
	scopes []string

	stateLock sync.Mutex
	offline   bool
	askCount  int
}

// Installs a keeper over writer, offline, refusing scopes.
func newEvsTestOfflineTokens(writer *evsTestWriter, scopes ...string) *evsTestOfflineTokens {
	self := &evsTestOfflineTokens{tokens: writer.test.tokens, scopes: scopes, offline: true}
	writer.test.client.http.serviceToken = self.token
	return self
}

func (self *evsTestOfflineTokens) token(ctx context.Context, resource string, scopes []string) (string, error) {
	refused := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.scopes != nil && !slices.ContainsFunc(scopes, func(scope string) bool { return slices.Contains(self.scopes, scope) }) {
			return false
		}
		self.askCount += 1
		return self.offline
	}()
	if refused {
		return "", ErrSidecarServiceTokenNoClient
	}
	return self.tokens.token(ctx, resource, scopes)
}

// A client generation began, or ended.
func (self *evsTestOfflineTokens) setOffline(offline bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.offline = offline
}

func (self *evsTestOfflineTokens) asks() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.askCount
}

// Whether the queue has a push of refId due or waiting.
func evsTestQueued(receiver *EvsGitReceiver, refId Id) bool {
	receiver.stateLock.Lock()
	defer receiver.stateLock.Unlock()
	_, queued := receiver.queueDue[refId]
	return queued
}

// An owned ref pushed while this sidecar runs no client generation: the queue's round finds no enrolled client at the
// push's first token and holds, ur evs status's journal showing `no enrolled client`, the commits staying on the local
// ref and nothing posted, and queues nothing more, so a round an interval on asks no token and builds nothing. The next
// client generation's start (EvsMounts.reconnected, which wakes the queue) releases the hold at the next round, which
// pushes on that generation, and the push lands. Before, the queue asked again every QueueInterval, building and sealing
// the push each time, for as long as no client ran.
func TestEvsLocalReceiveQueueHeldOfflineUntilAReconnect(t *testing.T) {
	ctx := context.Background()
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	queue := receiver.mount.receiver
	clock := publisher.writer.test.clock
	settings := publisher.writer.test.client.settings
	sidecarId := publisher.writer.test.client.args.Identity().SidecarId
	owned := string(EvsOwnedRefName(sidecarId, "offline"))
	dir := receiver.clone()
	c1 := receiver.commit(dir, map[string]string{"a.txt": "pushed with no client generation\n"})
	if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/"+owned); !ok {
		t.Fatalf("the push: %s", out)
	}
	refId := publisher.ref(owned).refId
	tokens := newEvsTestOfflineTokens(publisher.writer, evsTestWriteScope(publisher.writer))

	clock.advance(settings.QueueFirstDelay)
	queue.queueRound(ctx)
	statuses, err := queue.JournalStatus()
	if err != nil || len(statuses) != 1 || statuses[0].HoldCode != evsLocalOfflineHoldCode || statuses[0].Pending {
		t.Fatalf("the queue after no enrolled client: %+v %v", statuses, err)
	}
	if local := receiver.local("refs/heads/" + owned); local == nil || *local != c1 {
		t.Fatalf("the held commits left the local ref: %v", local)
	}
	if tokens.asks() != 1 || publisher.posted() != 0 || receiver.headVersion(owned) != 0 {
		t.Fatalf("%d asks and %d posts before the hold", tokens.asks(), publisher.posted())
	}
	if evsTestQueued(queue, refId) {
		t.Fatal("the held ref is queued again")
	}
	clock.advance(settings.QueueInterval)
	queue.queueRound(ctx)
	if tokens.asks() != 1 || publisher.posted() != 0 {
		t.Fatalf("a held queue asked %d more times and posted %d", tokens.asks()-1, publisher.posted())
	}

	tokens.setOffline(false)
	receiver.mounts.reconnected()
	select {
	case <-queue.queueWakeup:
	default:
		t.Fatal("the reconnect woke no round")
	}
	queue.queueRound(ctx)
	if version := receiver.headVersion(owned); version != 1 {
		t.Fatalf("the push after the reconnect: version %d", version)
	}
	record, _ := receiver.mount.sync.GitRef(ctx, refId)
	if !evsOidEqual(record.Tip, &c1) {
		t.Fatalf("evs's tip %v", record.Tip)
	}
	if statuses, _ := queue.JournalStatus(); len(statuses) != 0 {
		t.Fatalf("the journal after the reconnect %+v", statuses)
	}
}

// A reconnect releases only what offline held: of two owned refs, one held by evs's 403 SCOPE and one for want of an
// enrolled client, the round after the reconnect pushes the second and leaves the first held, as `ur evs retry` or its
// local ref's move alone release it. A held queue's local ref moving still releases it as before, and with still no
// client it holds again at the new tip.
func TestEvsLocalReceiveReconnectReleasesOnlyTheOfflineHolds(t *testing.T) {
	ctx := context.Background()
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	queue := receiver.mount.receiver
	clock := publisher.writer.test.clock
	settings := publisher.writer.test.client.settings
	sidecarId := publisher.writer.test.client.args.Identity().SidecarId
	scoped := string(EvsOwnedRefName(sidecarId, "scoped"))
	offline := string(EvsOwnedRefName(sidecarId, "offline"))
	dir := receiver.clone()
	receiver.commit(dir, map[string]string{"a.txt": "refused by evs\n"})
	if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/"+scoped); !ok {
		t.Fatalf("the push: %s", out)
	}
	func() {
		publisher.writer.server.stateLock.Lock()
		defer publisher.writer.server.stateLock.Unlock()
		publisher.writer.server.pushRefusals = []*evsTestRefusal{{status: http.StatusForbidden, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE}}}
	}()
	if err := queue.publishQueued(ctx, publisher.ref(scoped).refId); err != nil {
		t.Fatal(err)
	}
	tokens := newEvsTestOfflineTokens(publisher.writer, evsTestWriteScope(publisher.writer))
	receiver.commit(dir, map[string]string{"a.txt": "held offline\n"})
	if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/"+offline); !ok {
		t.Fatalf("the push: %s", out)
	}
	offlineRefId := publisher.ref(offline).refId
	if err := queue.publishQueued(ctx, offlineRefId); err != nil {
		t.Fatal(err)
	}
	holds := func() map[string]string {
		statuses, err := queue.JournalStatus()
		if err != nil {
			t.Fatal(err)
		}
		holds := map[string]string{}
		for _, status := range statuses {
			holds[string(status.RefName)] = status.HoldCode
		}
		return holds
	}
	if got := holds(); got[scoped] != "SCOPE" || got[offline] != evsLocalOfflineHoldCode {
		t.Fatalf("the holds %v", got)
	}

	// the offline ref's local ref moves with still no client: released by the move, held again at the new tip
	c3 := receiver.commit(dir, map[string]string{"a.txt": "moved while offline\n"})
	if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/"+offline); !ok {
		t.Fatalf("the push: %s", out)
	}
	asks := tokens.asks()
	if err := queue.publishQueued(ctx, offlineRefId); err != nil {
		t.Fatal(err)
	}
	if got := holds(); got[offline] != evsLocalOfflineHoldCode || tokens.asks() != asks+1 {
		t.Fatalf("after the local ref moved: %v, %d more asks", got, tokens.asks()-asks)
	}

	tokens.setOffline(false)
	receiver.mounts.reconnected()
	clock.advance(settings.QueueInterval)
	queue.queueRound(ctx)
	if version := receiver.headVersion(offline); version != 1 {
		t.Fatalf("the offline ref after the reconnect: version %d", version)
	}
	record, _ := receiver.mount.sync.GitRef(ctx, offlineRefId)
	if !evsOidEqual(record.Tip, &c3) {
		t.Fatalf("evs's tip %v", record.Tip)
	}
	if got := holds(); got[scoped] != "SCOPE" || len(got) != 1 {
		t.Fatalf("the holds after the reconnect %v", got)
	}
	if receiver.headVersion(scoped) != 0 {
		t.Fatal("the reconnect pushed the ref evs refused")
	}
}

// What was sent cannot be resolved with no client generation either: a queue whose owned ref has an attempt whose
// outcome is unknown, and whose resolve finds no enrolled client at its replay's first token, holds offline at its local
// ref, its updates waiting as LOCAL, rather than ask again every QueueInterval.
func TestEvsLocalReceiveQueueHeldOfflineAtTheResolve(t *testing.T) {
	ctx := context.Background()
	publisher := newEvsTestPublisher(t)
	receiver := newEvsTestReceiver(t, publisher)
	queue := receiver.mount.receiver
	sidecarId := publisher.writer.test.client.args.Identity().SidecarId
	owned := string(EvsOwnedRefName(sidecarId, "resolve"))
	dir := receiver.clone()
	c1 := receiver.commit(dir, map[string]string{"a.txt": "sent, its answer lost\n"})
	if out, ok := receiver.push(dir, "origin", "HEAD:refs/heads/"+owned); !ok {
		t.Fatalf("the push: %s", out)
	}
	refId := publisher.ref(owned).refId
	// an attempt journaled before its POST, whose answer the daemon never read
	if err := queue.journalAttempt(ctx, refId, &EvsGitPublishAttempt{
		PushId: NewId(), BaseVersion: 0, BaseChain: EvsChainStart(publisher.writer.world.repoId, refId), New: &c1,
		TimeMs: publisher.writer.test.clock.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	if statuses, _ := queue.JournalStatus(); len(statuses) != 1 || !statuses[0].Pending {
		t.Fatalf("the attempt is not pending: %+v", statuses)
	}
	tokens := newEvsTestOfflineTokens(publisher.writer)
	if err := queue.publishQueued(ctx, refId); err != nil {
		t.Fatalf("the queue answered %v, not a hold", err)
	}
	statuses, _ := queue.JournalStatus()
	if len(statuses) != 1 || statuses[0].HoldCode != evsLocalOfflineHoldCode || statuses[0].Pending || statuses[0].Queued != 1 {
		t.Fatalf("the queue after no enrolled client at the resolve: %+v", statuses)
	}
	if tokens.asks() == 0 || publisher.posted() != 0 {
		t.Fatalf("%d asks, %d posts", tokens.asks(), publisher.posted())
	}
	if local := receiver.local("refs/heads/" + owned); local == nil || *local != c1 {
		t.Fatalf("the held commits left the local ref: %v", local)
	}
}

// A local tier that counts the reconnects it was told of.
type evsTestReconnectTier struct {
	stateLock      sync.Mutex
	reconnectCount int
}

func (self *evsTestReconnectTier) reconnected() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reconnectCount += 1
}

// Each client generation the evs component follows tells the client's local tier it began, so an owned ref's queue held
// for want of an enrolled client builds on it (DESIGN-DETAILS 8.2.8's offline row). Nothing told it before.
func TestEvsComponentTellsTheLocalTierOfEachGeneration(t *testing.T) {
	test := newEvsTestClient(t, http.NotFoundHandler(), newEvsTestStore(t))
	tier := &evsTestReconnectTier{}
	func() {
		test.client.stateLock.Lock()
		defer test.client.stateLock.Unlock()
		test.client.localTier = tier
	}()
	component := NewEvsComponent(test.client)
	for range 2 {
		ctx, cancel := context.WithCancel(context.Background())
		queue := newSidecarComponentQueue(ctx, 4, 1024*1024, &sidecarQueueCounters{}, NewNoopLogger())
		if err := component.Attach(&SidecarEnv{Ctx: ctx, queue: queue}); err != nil {
			t.Fatal(err)
		}
		cancel()
		queue.closeAndWait()
	}
	tier.stateLock.Lock()
	defer tier.stateLock.Unlock()
	if tier.reconnectCount != 2 {
		t.Errorf("told of %d generations, want 2", tier.reconnectCount)
	}
}
