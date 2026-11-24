//go:build !sidecar_http && !js

// GkmHints taking the batches a resident's publisher sends (§6.8), the composed path of
// gkm_hint_intake_bodyless_test.go's rows: hints written as gkm writes them, on T2's FakeRedis, are read and coalesced
// by pushservice's own publisher, whose frames the test decodes as the client's dispatcher does and hands the intake
// as the client's push machine hands its subscribers the hints above the versions it holds. A group's commit the
// publisher superseded wakes the group with no resync. A per-client work hint it sent without its bytes costs a
// resync whether the hint was past TopicHintBodyCount or a repeat whose copy follows, the two being one notice to the
// client: the second resync is what question gkm-hint-intake-bodyless-superseded-mark asks to spare. Fake clocks
// throughout; a real-time timer here only fails a test that would otherwise hang.

package sidecar_test

import (
	"context"
	"encoding/hex"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How long a test waits for the publisher or the intake before it fails. Real time, only ever a failure's bound.
const testGkmBodylessTimeout = 30 * time.Second

// A resident's publisher for one client on T2's FakeRedis and a fake clock, started and past its first reset, its
// send decoding each frame as the client's dispatcher reads it and taking its pool buffer, as a resident does once
// its client has the frame.
type testGkmBodylessPublisher struct {
	t         *testing.T
	clock     *sidecartest.FakeClock
	settings  *pushservice.SidecarPublisherSettings
	writer    *pushservice.HintWriter
	clientId  connect.Id
	publisher *pushservice.SidecarPublisher
	resets    chan *protocol.PushReset
	hints     chan *protocol.PushHint
}

// settings nil takes the defaults. Returns once the publisher waits out the window before the read that follows its
// reset, so every hint written then goes in that read's batch.
func newTestGkmBodylessPublisher(t *testing.T, settings *pushservice.SidecarPublisherSettings) *testGkmBodylessPublisher {
	t.Helper()
	if settings == nil {
		settings = pushservice.DefaultSidecarPublisherSettings()
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	fakeRedis := sidecartest.NewFakeRedis(t.Context(), clock, sidecartest.NewFaultQueue(), nil, nil)
	t.Cleanup(fakeRedis.Close)
	sidecartest.RegisterPushScripts(fakeRedis)
	writer, err := pushservice.NewHintWriter(fakeRedis, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := pushservice.NewSidecarPublisher(settings, clock)
	if err != nil {
		t.Fatal(err)
	}
	// registered after Redis's, so it runs first
	t.Cleanup(publisher.Close)
	self := &testGkmBodylessPublisher{
		t:         t,
		clock:     clock,
		settings:  settings,
		writer:    writer,
		clientId:  connect.NewId(),
		publisher: publisher,
		resets:    make(chan *protocol.PushReset, 16),
		hints:     make(chan *protocol.PushHint, 1024),
	}
	publisher.Start(t.Context(), &pushservice.PublisherEnv{
		ClientId:  self.clientId,
		NetworkId: connect.NewId(),
		Send:      self.send,
		Redis:     fakeRedis,
	})
	// the reset of an empty ver, then the window
	for complete := false; !complete; {
		select {
		case reset := <-self.resets:
			complete = reset.Complete
		case <-time.After(testGkmBodylessTimeout):
			t.Fatal("the publisher sent no reset")
		}
	}
	at := clock.Now().Add(settings.HintCoalesceTimeout)
	guard := time.After(testGkmBodylessTimeout)
	for {
		pending, added := clock.WatchTimers()
		if slices.ContainsFunc(pending, at.Equal) {
			return self
		}
		select {
		case <-added:
		case <-guard:
			t.Fatalf("no window at %s: %v", at, pending)
		}
	}
}

// The resident's send. Runs on the publisher's goroutine, so a frame no client reads fails the test without stopping
// it there.
func (self *testGkmBodylessPublisher) send(frame *connectprotocol.Frame, ack connect.AckFunction) bool {
	func() {
		wrapper := &connectprotocol.SubprotocolMessage{}
		envelope := &protocol.Envelope{}
		if frame.MessageType != connectprotocol.MessageType_Subprotocol || proto.Unmarshal(frame.MessageBytes, wrapper) != nil ||
			wrapper.SubprotocolId != sidecar.SubprotocolId || proto.Unmarshal(wrapper.MessageBytes, envelope) != nil {
			self.t.Errorf("the resident got a frame no client reads")
			return
		}
		switch protocol.MessageType(envelope.Type) {
		case protocol.MessageType_PUSH_RESET:
			reset := &protocol.PushReset{}
			if err := proto.Unmarshal(envelope.Body, reset); err != nil {
				self.t.Errorf("a reset that does not decode: %v", err)
				return
			}
			self.resets <- reset
		case protocol.MessageType_PUSH_HINT:
			hint := &protocol.PushHint{}
			if err := proto.Unmarshal(envelope.Body, hint); err != nil {
				self.t.Errorf("a hint that does not decode: %v", err)
				return
			}
			self.hints <- hint
		default:
			self.t.Errorf("an envelope of type %#x", envelope.Type)
		}
	}()
	if pooled, _ := connect.MessagePoolCheck(frame.MessageBytes); pooled {
		connect.MessagePoolReturn(frame.MessageBytes)
	}
	return true
}

// Writes hints as their owners do, then ends the window, so the publisher's read takes them as one batch, and
// answers what it sent of them, in seq order.
func (self *testGkmBodylessPublisher) batch(hints ...*sidecar.ClientHint) []*protocol.PushHint {
	self.t.Helper()
	for _, hint := range hints {
		if _, err := self.writer.HintClient(self.t.Context(), self.clientId, hint); err != nil {
			self.t.Fatal(err)
		}
	}
	self.clock.Advance(self.settings.HintCoalesceTimeout)
	sent := []*protocol.PushHint{}
	for range hints {
		select {
		case hint := <-self.hints:
			sent = append(sent, hint)
		case <-time.After(testGkmBodylessTimeout):
			self.t.Fatalf("the publisher sent %d of the batch's %d hints", len(sent), len(hints))
		}
	}
	for index, hint := range sent {
		if hint.Seq != uint64(index+1) {
			self.t.Errorf("hint %d has seq %d", index, hint.Seq)
		}
	}
	return sent
}

// A work hint on the per-client gkm topic as gkm writes one (gkmservice/hints.go): its kind, group and recipient in
// the bytes, versioned by gkm's clock in µs, which the hint script raises past the stored value.
func (self *testGkmBodylessPublisher) workHint(kind protocol.GkmHintKind, groupId sidecar.Id, recipient string) *sidecar.ClientHint {
	self.t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmHint{Kind: kind, GroupId: groupId.Bytes(), Recipient: []byte(recipient)})
	if err != nil {
		self.t.Fatal(err)
	}
	return &sidecar.ClientHint{Topic: sidecar.PushTopicGkm, Version: uint64(self.clock.Now().UnixMicro()), Kind: uint32(protocol.MessageType_GKM_HINT), Body: body}
}

// A late ask's recipient, s:<sidecar_id> in hex, as its wrap path writes it.
func testGkmBodylessRecipient() string {
	return "s:" + hex.EncodeToString(sidecar.NewId().Bytes())
}

// A commit hint on gkm:<group_id> as gkm writes one in v0: the group and the kind in the bytes, the same for every
// commit of the group, and the generation as the version.
func testGkmBodylessCommit(t *testing.T, groupId sidecar.Id, generation uint64) *sidecar.ClientHint {
	t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmHint{GroupId: groupId.Bytes(), Kind: protocol.GkmHintKind_GKM_HINT_COMMIT})
	if err != nil {
		t.Fatal(err)
	}
	return &sidecar.ClientHint{Topic: sidecar.PushTopicGkmGroup(groupId), Version: generation, Kind: uint32(protocol.MessageType_GKM_HINT), Body: body}
}

// What the publisher counted, once it has stopped.
func (self *testGkmBodylessPublisher) closedStats() pushservice.SidecarPublisherStats {
	self.publisher.Close()
	return self.publisher.Stats()
}

// Fails unless hint went without its bytes and kept the rest: a per-client one's notice is then the same whatever
// dropped its bytes.
func expectGkmBodylessHint(t *testing.T, hint *protocol.PushHint, topic string) {
	t.Helper()
	if hint.Topic != topic || hint.Version == 0 || hint.Kind != uint32(protocol.MessageType_GKM_HINT) || len(hint.Hint) != 0 {
		t.Fatalf("the hint %v, want one of %s without its bytes", hint, topic)
	}
}

// A GkmHints intake on a clock that never moves, so no hourly resync runs, whose handlers record the wakes they take
// and whose resyncs it counts.
type testGkmBodylessIntake struct {
	hints *sidecar.GkmHints

	stateLock   sync.Mutex
	wakes       []*sidecar.GkmHintWake
	resyncCount int
}

func newTestGkmBodylessIntake(t *testing.T) *testGkmBodylessIntake {
	t.Helper()
	hints, err := sidecar.NewGkmHints(t.Context(), &sidecar.GkmHintsArgs{Clock: sidecartest.NewFakeClock(sidecartest.DefaultClockStart())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hints.Close)
	self := &testGkmBodylessIntake{hints: hints}
	record := func(ctx context.Context, wake *sidecar.GkmHintWake) {
		wakeCopy := *wake
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.wakes = append(self.wakes, &wakeCopy)
	}
	for _, kind := range []protocol.GkmHintKind{protocol.GkmHintKind_GKM_HINT_COMMIT, protocol.GkmHintKind_GKM_HINT_PENDING, protocol.GkmHintKind_GKM_HINT_WELCOME, protocol.GkmHintKind_GKM_HINT_WRAP_PENDING} {
		hints.SetHandler(kind, record)
	}
	hints.AddResync(func(ctx context.Context) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.resyncCount += 1
	})
	return self
}

// Hands the intake a batch's hints as the client's push machine hands its subscribers a hint above the version it
// holds, as each here is, while the intake is held inside a key-packages-low wake, so it takes the batch in one pass
// as it would one the push delivers at once; then lets it go, waits for that pass and answers what it woke and how
// often it resynced.
func (self *testGkmBodylessIntake) take(t *testing.T, sent []*protocol.PushHint) (wakes []*sidecar.GkmHintWake, resyncCount int) {
	t.Helper()
	entered := make(chan int, 1)
	release := make(chan struct{})
	self.hints.SetHandler(protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW, func(ctx context.Context, wake *sidecar.GkmHintWake) {
		// the pass running this is not counted yet: once it ends, the next takes the batch
		passCount, _ := self.hints.Passes()
		entered <- passCount
		select {
		case <-release:
		case <-ctx.Done():
		}
	})
	body, err := proto.Marshal(&protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW})
	if err != nil {
		t.Fatal(err)
	}
	self.hints.Receive(sidecar.PushNotice{Topic: sidecar.PushTopicGkm, Version: 1, Kind: uint32(protocol.MessageType_GKM_HINT), Hint: body})
	var heldPassCount int
	select {
	case heldPassCount = <-entered:
	case <-time.After(testGkmBodylessTimeout):
		t.Fatal("the intake never took the holding wake")
	}
	for _, hint := range sent {
		self.hints.Receive(sidecar.PushNotice{Topic: hint.Topic, Version: hint.Version, Kind: hint.Kind, Hint: slices.Clone(hint.Hint)})
	}
	close(release)
	guard := time.After(testGkmBodylessTimeout)
	for {
		passCount, changed := self.hints.Passes()
		if heldPassCount+1 < passCount {
			break
		}
		select {
		case <-changed:
		case <-guard:
			t.Fatal("the intake's pass never finished")
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.wakes), self.resyncCount
}

// Fails unless wake is kind's for groupId, a commit's at generation and a work hint's for recipient.
func expectGkmBodylessWake(t *testing.T, wake *sidecar.GkmHintWake, kind protocol.GkmHintKind, groupId sidecar.Id, generation uint64, recipient string) {
	t.Helper()
	if wake.Kind != kind || wake.GroupId == nil || *wake.GroupId != groupId || wake.Epoch != 0 || wake.Generation != generation || wake.Recipient != recipient {
		t.Errorf("the wake %+v, want %s for %s at %d for %q", wake, kind, groupId, generation, recipient)
	}
}

// A group's two commits in one window with another group's between them, each on its gkm:<group_id>: the publisher
// supersedes the first, whose bytes the third repeats, and the intake takes the batch with no resync, waking each
// group's commit handler once, the first group's at its later generation. Before, the superseded notice failed the
// group topic's form and resynced every repo the device holds.
func TestGkmHintsTakeAPublishersGroupRepeatWithNoResync(t *testing.T) {
	publisher := newTestGkmBodylessPublisher(t, nil)
	groupId, otherGroupId := sidecar.NewId(), sidecar.NewId()
	sent := publisher.batch(
		testGkmBodylessCommit(t, groupId, 5),
		testGkmBodylessCommit(t, otherGroupId, 3),
		testGkmBodylessCommit(t, groupId, 6),
	)
	expectGkmBodylessHint(t, sent[0], sidecar.PushTopicGkmGroup(groupId))
	if len(sent[1].Hint) == 0 || len(sent[2].Hint) == 0 {
		t.Fatalf("hints %v and %v went without their bytes", sent[1], sent[2])
	}

	wakes, resyncCount := newTestGkmBodylessIntake(t).take(t, sent)
	if resyncCount != 0 {
		t.Errorf("the batch took %d resyncs, want none", resyncCount)
	}
	if len(wakes) != 2 {
		t.Fatalf("%d wakes, want 2", len(wakes))
	}
	expectGkmBodylessWake(t, wakes[0], protocol.GkmHintKind_GKM_HINT_COMMIT, groupId, 6, "")
	expectGkmBodylessWake(t, wakes[1], protocol.GkmHintKind_GKM_HINT_COMMIT, otherGroupId, 3, "")
	if stats := publisher.closedStats(); stats.HintCount != 3 || stats.CoalescedCount != 1 || stats.BodyBoundCount != 0 {
		t.Errorf("stats %+v", stats)
	}
}

// Three distinct work hints for one client in one window under a TopicHintBodyCount of two: the publisher sends the
// oldest, a late ask's, without its bytes, and the intake resyncs, the one way left to recover that ask's delivery,
// while the two hints with their bytes wake their handlers.
func TestGkmHintsResyncForAPublishersWorkHintPastTheBound(t *testing.T) {
	settings := pushservice.DefaultSidecarPublisherSettings()
	settings.TopicHintBodyCount = 2
	publisher := newTestGkmBodylessPublisher(t, settings)
	groupIds := []sidecar.Id{sidecar.NewId(), sidecar.NewId(), sidecar.NewId()}
	recipient := testGkmBodylessRecipient()
	sent := publisher.batch(
		publisher.workHint(protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, groupIds[0], recipient),
		publisher.workHint(protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, groupIds[1], recipient),
		publisher.workHint(protocol.GkmHintKind_GKM_HINT_PENDING, groupIds[2], ""),
	)
	expectGkmBodylessHint(t, sent[0], sidecar.PushTopicGkm)
	if len(sent[1].Hint) == 0 || len(sent[2].Hint) == 0 {
		t.Fatalf("hints %v and %v went without their bytes", sent[1], sent[2])
	}

	wakes, resyncCount := newTestGkmBodylessIntake(t).take(t, sent)
	if resyncCount != 1 {
		t.Errorf("the batch took %d resyncs, want 1", resyncCount)
	}
	if len(wakes) != 2 {
		t.Fatalf("%d wakes, want 2", len(wakes))
	}
	expectGkmBodylessWake(t, wakes[0], protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, groupIds[1], 0, recipient)
	expectGkmBodylessWake(t, wakes[1], protocol.GkmHintKind_GKM_HINT_PENDING, groupIds[2], 0, "")
	if stats := publisher.closedStats(); stats.HintCount != 3 || stats.CoalescedCount != 1 || stats.BodyBoundCount != 1 {
		t.Errorf("stats %+v", stats)
	}
}

// A late ask's wrap-pending hint repeated in one window, another ask's between them: the publisher sends the first
// copy without its bytes, which the third carries, and the intake resyncs all the same, since that notice is the one
// a hint past the bound sends. The later copy wakes the ask's delivery; the resync is the cost question
// gkm-hint-intake-bodyless-superseded-mark asks to spare, and this test changes with its answer.
func TestGkmHintsResyncForAPublishersWorkHintRepeat(t *testing.T) {
	publisher := newTestGkmBodylessPublisher(t, nil)
	groupId, otherGroupId := sidecar.NewId(), sidecar.NewId()
	recipient := testGkmBodylessRecipient()
	sent := publisher.batch(
		publisher.workHint(protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, groupId, recipient),
		publisher.workHint(protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, otherGroupId, recipient),
		publisher.workHint(protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, groupId, recipient),
	)
	expectGkmBodylessHint(t, sent[0], sidecar.PushTopicGkm)
	if len(sent[1].Hint) == 0 || len(sent[2].Hint) == 0 {
		t.Fatalf("hints %v and %v went without their bytes", sent[1], sent[2])
	}

	wakes, resyncCount := newTestGkmBodylessIntake(t).take(t, sent)
	if resyncCount != 1 {
		t.Errorf("the batch took %d resyncs, want 1", resyncCount)
	}
	if len(wakes) != 2 {
		t.Fatalf("%d wakes, want 2", len(wakes))
	}
	expectGkmBodylessWake(t, wakes[0], protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, otherGroupId, 0, recipient)
	expectGkmBodylessWake(t, wakes[1], protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, groupId, 0, recipient)
	if stats := publisher.closedStats(); stats.HintCount != 3 || stats.CoalescedCount != 1 || stats.BodyBoundCount != 0 {
		t.Errorf("stats %+v", stats)
	}
}
