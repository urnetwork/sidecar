// The GkmHint intake (KEYS-M2-18): a hint is a wake, coalesced, and a lost one is recovered at the resync, on a
// clock the test moves and handlers it holds, so nothing here sleeps.

package sidecar

import (
	"context"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A GkmHint notice on a topic.
func gkmTestNotice(t *testing.T, topic string, version uint64, hint *protocol.GkmHint) PushNotice {
	t.Helper()
	body, err := proto.Marshal(hint)
	if err != nil {
		t.Fatal(err)
	}
	return PushNotice{Topic: topic, Version: version, Kind: uint32(protocol.MessageType_GKM_HINT), Hint: body}
}

// Waits until the intake has finished more than after passes.
func awaitGkmHintPasses(t *testing.T, hints *GkmHints, after int) {
	t.Helper()
	for {
		count, changed := hints.Passes()
		if after < count {
			return
		}
		<-changed
	}
}

// A handler that records its wakes and, while held, blocks the intake inside the first one.
type gkmTestHandler struct {
	stateLock sync.Mutex
	wakes     []*GkmHintWake
	entered   chan struct{}
	release   chan struct{}
	holdFirst bool
}

func newGkmTestHandler(holdFirst bool) *gkmTestHandler {
	return &gkmTestHandler{entered: make(chan struct{}, 16), release: make(chan struct{}), holdFirst: holdFirst}
}

func (self *gkmTestHandler) handle(ctx context.Context, wake *GkmHintWake) {
	wakeCopy := *wake
	first := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		first = len(self.wakes) == 0
		self.wakes = append(self.wakes, &wakeCopy)
	}()
	self.entered <- struct{}{}
	if first && self.holdFirst {
		<-self.release
	}
}

func (self *gkmTestHandler) taken() []*GkmHintWake {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*GkmHintWake(nil), self.wakes...)
}

// Hints arriving while a handler runs coalesce into one wake, a commit keeping its newest epoch and generation from
// its topic's version (D-KEYS-19); hints of other groups stay apart.
func TestGkmHintsCoalesceABurstIntoOneWake(t *testing.T) {
	clock := newGkmTestClock()
	hints, err := NewGkmHints(context.Background(), &GkmHintsArgs{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer hints.Close()
	handler := newGkmTestHandler(true)
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_COMMIT, handler.handle)
	groupId := NewId()
	otherGroupId := NewId()
	topic := PushTopicGkmGroup(groupId)
	commit := &protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_COMMIT}
	version := func(epoch uint64, generation uint64) uint64 {
		version, err := GkmGroupVersion(epoch, generation)
		if err != nil {
			t.Fatal(err)
		}
		return version
	}
	hints.Receive(gkmTestNotice(t, topic, version(1, 1), commit))
	<-handler.entered
	// the handler holds the first: these three wait, coalesced, with the other group's apart
	hints.Receive(gkmTestNotice(t, topic, version(2, 1), commit))
	hints.Receive(gkmTestNotice(t, topic, version(3, 2), commit))
	hints.Receive(gkmTestNotice(t, topic, version(2, 5), commit))
	hints.Receive(gkmTestNotice(t, PushTopicGkmGroup(otherGroupId), version(1, 1), commit))
	close(handler.release)
	<-handler.entered
	<-handler.entered
	wakes := handler.taken()
	if len(wakes) != 3 {
		t.Fatalf("%d wakes, want 3", len(wakes))
	}
	if *wakes[1].GroupId != groupId || wakes[1].Epoch != 3 || wakes[1].Generation != 2 {
		t.Errorf("the coalesced wake %+v", wakes[1])
	}
	if *wakes[2].GroupId != otherGroupId {
		t.Error("another group's hint coalesced with this one's")
	}
}

// A hint lost on its way is recovered at the next resync, every ResyncInterval; a resync notice, a hint that does not
// decode and a kind no handler takes yet each come to the resync too.
func TestGkmHintsLostHintRecoveredAtResync(t *testing.T) {
	clock := newGkmTestClock()
	settings := DefaultGkmSettings()
	hints, err := NewGkmHints(context.Background(), &GkmHintsArgs{Clock: clock, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	defer hints.Close()
	resyncs := make(chan struct{}, 16)
	hints.AddResync(func(ctx context.Context) { resyncs <- struct{}{} })
	handler := newGkmTestHandler(false)
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_PENDING, handler.handle)

	// the pending hint never arrives: an hour on, the resync refetches what it would have said
	awaitGkmHintPasses(t, hints, 0)
	<-clock.armed
	clock.Advance(settings.ResyncInterval)
	<-resyncs
	if len(handler.taken()) != 0 {
		t.Error("a handler ran for a hint that never came")
	}
	// a reset's resync notice
	hints.Receive(PushNotice{Topic: PushTopicGkm, Resync: true})
	<-resyncs
	// a hint whose bytes do not decode is a lost hint
	hints.Receive(PushNotice{Topic: PushTopicGkm, Kind: uint32(protocol.MessageType_GKM_HINT), Hint: []byte{0xff, 0xff}})
	<-resyncs
	// a commit on the per-client topic is no hint that topic carries
	hints.Receive(gkmTestNotice(t, PushTopicGkm, 1, &protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_COMMIT}))
	<-resyncs
	// and a pending hint that does come wakes its handler
	groupId := NewId()
	hints.Receive(gkmTestNotice(t, PushTopicGkm, 2, &protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_PENDING, GroupId: groupId.Bytes()}))
	<-handler.entered
	if wakes := handler.taken(); len(wakes) != 1 || *wakes[0].GroupId != groupId {
		t.Errorf("the pending wake %+v", wakes)
	}
}

// Past HintPendingCount waiting wakes a new one is dropped and a resync asked for instead, so memory stays bounded
// and nothing is lost.
func TestGkmHintsPastTheBoundDropAndResync(t *testing.T) {
	clock := newGkmTestClock()
	settings := DefaultGkmSettings()
	settings.HintPendingCount = 2
	hints, err := NewGkmHints(context.Background(), &GkmHintsArgs{Clock: clock, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	defer hints.Close()
	resyncs := make(chan struct{}, 16)
	hints.AddResync(func(ctx context.Context) { resyncs <- struct{}{} })
	handler := newGkmTestHandler(true)
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_WELCOME, handler.handle)
	welcome := func(groupId Id) PushNotice {
		return gkmTestNotice(t, PushTopicGkm, 1, &protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_WELCOME, GroupId: groupId.Bytes()})
	}
	hints.Receive(welcome(NewId()))
	<-handler.entered
	for i := 0; i < 3; i += 1 {
		hints.Receive(welcome(NewId()))
	}
	if dropped := hints.DroppedCount(); dropped != 1 {
		t.Errorf("%d dropped, want 1", dropped)
	}
	close(handler.release)
	<-handler.entered
	<-handler.entered
	<-resyncs
}

// The intake subscribes to the gkm topic and the gkm: family through the feed it is given, and the feed's notices
// reach it.
func TestGkmHintsSubscribeToBothTopics(t *testing.T) {
	topicCallbacks := map[string]PushNoticeFunction{}
	subscribe := func(topic string, callback PushNoticeFunction) (func(), error) {
		topicCallbacks[topic] = callback
		return func() { delete(topicCallbacks, topic) }, nil
	}
	hints, err := NewGkmHints(context.Background(), &GkmHintsArgs{Subscribe: subscribe, Clock: newGkmTestClock()})
	if err != nil {
		t.Fatal(err)
	}
	handler := newGkmTestHandler(false)
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW, handler.handle)
	if topicCallbacks[PushTopicGkm] == nil || topicCallbacks[PushTopicGkmGroupPrefix] == nil {
		t.Fatalf("subscribed to %v", topicCallbacks)
	}
	topicCallbacks[PushTopicGkm](gkmTestNotice(t, PushTopicGkm, 3, &protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW}))
	<-handler.entered
	hints.Close()
	if len(topicCallbacks) != 0 {
		t.Error("Close left a subscription")
	}
}
