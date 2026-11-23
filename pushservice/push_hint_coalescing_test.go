package pushservice_test

// §6.8's coalescing of a topic's superseded hints in one publisher batch, on publisher_test.go's FakeRedis,
// fake clock and fake resident send: a hint that a later one of its topic repeats, the same kind and the
// same bytes, keeps its seq and loses its bytes, while distinct hints of a topic each keep theirs, up to
// the topic's newest TopicHintBodyCount. gkm-reader-key-upload-retry found the publisher keeping only a
// topic's last body a batch, so of two late asks reaching a holder at once on its per-client gkm topic,
// one ask's wrap-pending hint arrived without its group and recipient, and only the asker's next ask
// delivered.

import (
	"context"
	"encoding/hex"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A per-client gkm work hint's bytes as gkm writes them (gkmservice/hints.go's gkmHintBody): group, epoch,
// kind and, for a late ask, the asker as its wrap path names it.
func testGkmHintBody(t testing.TB, kind protocol.GkmHintKind, groupId *sidecar.Id, recipient string) []byte {
	t.Helper()
	hint := &protocol.GkmHint{Kind: kind, Recipient: []byte(recipient)}
	if groupId != nil {
		hint.GroupId = groupId.Bytes()
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(hint)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// A late ask's recipient, s:<sidecar_id> in hex, as the wrap path writes it.
func testGkmRecipient(sidecarId sidecar.Id) string {
	return "s:" + hex.EncodeToString(sidecarId.Bytes())
}

// Writes one hint of the per-client gkm topic as gkm does: GKM_HINT, versioned by gkm's clock in µs,
// which the script raises past the stored value.
func (self *testPublisherEnv) gkmHint(body []byte) *pushservice.PushHintResult {
	self.t.Helper()
	return self.hintOfKind(sidecar.PushTopicGkm, uint64(self.clock.Now().UnixMicro()), uint32(protocol.MessageType_GKM_HINT), body)
}

// Writes one hint as an owner would, with its owner's MessageType, and no event.
func (self *testPublisherEnv) hintOfKind(topic string, version uint64, kind uint32, body []byte) *pushservice.PushHintResult {
	self.t.Helper()
	result, err := self.writer.HintClient(self.t.Context(), self.clientId, &sidecar.ClientHint{Topic: topic, Version: version, Kind: kind, Body: body})
	if err != nil {
		self.t.Fatal(err)
	}
	return result
}

// Kicks the publisher, passes its window and takes the batch of count hints its read sends, checking that
// their seqs run on from first with no gap and that only the last carries an ack.
func (self *testPublisherEnv) awaitBatch(first uint64, count int) []*protocol.PushHint {
	self.t.Helper()
	self.publisher.Kick()
	self.passWindow()
	self.awaitCall("xrange")
	hints := []*protocol.PushHint{}
	for index, message := range self.awaitHints(count) {
		if message.hint.Seq != first+uint64(index) {
			self.t.Errorf("hint %d has seq %d, want %d", index, message.hint.Seq, first+uint64(index))
		}
		if (message.ack != nil) != (index == count-1) {
			self.t.Errorf("hint %d's ack is set: %t", index, message.ack != nil)
		}
		hints = append(hints, message.hint)
	}
	self.expectNoMessage()
	return hints
}

// A gkm hint intake on the client's side (gkm_hints.go), its handlers recording the wakes they take and
// its resyncs, on a clock that never moves, so no hourly resync runs.
type testGkmIntake struct {
	hints *sidecar.GkmHints

	stateLock   sync.Mutex
	wakes       []*sidecar.GkmHintWake
	resyncCount int
	// at key-packages-low's wake, the passes the intake had finished before the one running it
	lowPasses chan int
}

func newTestGkmIntake(t *testing.T) *testGkmIntake {
	t.Helper()
	hints, err := sidecar.NewGkmHints(t.Context(), &sidecar.GkmHintsArgs{Clock: sidecartest.NewFakeClock(sidecartest.DefaultClockStart())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hints.Close)
	self := &testGkmIntake{hints: hints, lowPasses: make(chan int, 16)}
	record := func(ctx context.Context, wake *sidecar.GkmHintWake) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.wakes = append(self.wakes, wake)
	}
	for _, kind := range []protocol.GkmHintKind{protocol.GkmHintKind_GKM_HINT_PENDING, protocol.GkmHintKind_GKM_HINT_WELCOME, protocol.GkmHintKind_GKM_HINT_WRAP_PENDING} {
		hints.SetHandler(kind, record)
	}
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW, func(ctx context.Context, wake *sidecar.GkmHintWake) {
		record(ctx, wake)
		passCount, _ := hints.Passes()
		self.lowPasses <- passCount
	})
	hints.AddResync(func(ctx context.Context) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.resyncCount += 1
	})
	return self
}

// Hands the intake each hint as the client's push machine hands a subscriber a hint above the version it
// holds (push_state.go's pushMachine.hint), then waits until the pass that took key-packages-low's wake,
// which a test sends last, has finished, so every wake and any resync the notices asked for has run.
func (self *testGkmIntake) take(t *testing.T, hints []*protocol.PushHint) (wakes []*sidecar.GkmHintWake, resyncCount int) {
	t.Helper()
	for _, hint := range hints {
		self.hints.Receive(sidecar.PushNotice{Topic: hint.Topic, Version: hint.Version, Kind: hint.Kind, Hint: slices.Clone(hint.Hint)})
	}
	var lowPassCount int
	select {
	case lowPassCount = <-self.lowPasses:
	case <-time.After(testPublisherTimeout):
		t.Fatal("the intake never took key-packages-low's wake")
	}
	guard := time.After(testPublisherTimeout)
	for {
		passCount, changed := self.hints.Passes()
		if lowPassCount < passCount {
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

// Two late asks reaching one holder at once, for two groups, with a pending wake for one of them and the
// holder's key-packages-low behind them, all on its per-client gkm topic in one batch: each is distinct,
// so each goes with its bytes and the holder's intake wakes each ask's delivery by its group and
// recipient, asking no resync. Keeping only the topic's last body, the publisher sent the first three
// bare, which the intake took as lost hints, waking neither delivery.
func TestPublisherKeepsDistinctGkmWorkHintsOfOneBatch(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	env.startIdle(nil)
	groupId, otherGroupId := sidecar.NewId(), sidecar.NewId()
	recipient := testGkmRecipient(sidecar.NewId())
	bodies := [][]byte{
		testGkmHintBody(t, protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, &groupId, recipient),
		testGkmHintBody(t, protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, &otherGroupId, recipient),
		testGkmHintBody(t, protocol.GkmHintKind_GKM_HINT_PENDING, &groupId, ""),
		testGkmHintBody(t, protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW, nil, ""),
	}
	results := []*pushservice.PushHintResult{}
	for _, body := range bodies {
		results = append(results, env.gkmHint(body))
	}
	hints := env.awaitBatch(1, len(bodies))
	for index, hint := range hints {
		want := &protocol.PushHint{Seq: results[index].Seq, Topic: sidecar.PushTopicGkm, Version: results[index].Version, Kind: uint32(protocol.MessageType_GKM_HINT), Hint: bodies[index]}
		if !proto.Equal(hint, want) {
			t.Errorf("hint %d is %v, want %v", index, hint, want)
		}
	}
	if stats := env.publisher.Stats(); stats.HintCount != 4 || stats.CoalescedCount != 0 || stats.BodyBoundCount != 0 {
		t.Errorf("stats %+v", stats)
	}

	wakes, resyncCount := newTestGkmIntake(t).take(t, hints)
	if resyncCount != 0 {
		t.Errorf("the intake resynced %d times", resyncCount)
	}
	type wakeKey struct {
		kind      protocol.GkmHintKind
		groupId   sidecar.Id
		recipient string
	}
	got := map[wakeKey]bool{}
	for _, wake := range wakes {
		key := wakeKey{kind: wake.Kind, recipient: wake.Recipient}
		if wake.GroupId != nil {
			key.groupId = *wake.GroupId
		}
		got[key] = true
	}
	for _, want := range []wakeKey{
		{kind: protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, groupId: groupId, recipient: recipient},
		{kind: protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, groupId: otherGroupId, recipient: recipient},
		{kind: protocol.GkmHintKind_GKM_HINT_PENDING, groupId: groupId},
		{kind: protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW},
	} {
		if !got[want] {
			t.Errorf("no wake of %v: %d wakes", want, len(wakes))
		}
	}
	if len(wakes) != 4 {
		t.Errorf("%d wakes, want 4", len(wakes))
	}
}

// One late ask's hint repeated in a batch, as gkm sends it again to a holder its first reached, is one
// hint: the earlier goes with its seq and without its bytes, and the later one carries them; another
// ask's hint between them keeps its own.
func TestPublisherCoalescesRepeatsOfOneGkmHint(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	env.startIdle(nil)
	groupId, otherGroupId := sidecar.NewId(), sidecar.NewId()
	recipient := testGkmRecipient(sidecar.NewId())
	repeated := testGkmHintBody(t, protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, &groupId, recipient)
	other := testGkmHintBody(t, protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, &otherGroupId, recipient)
	env.gkmHint(repeated)
	env.gkmHint(other)
	env.gkmHint(repeated)
	hints := env.awaitBatch(1, 3)
	for index, want := range [][]byte{nil, other, repeated} {
		if hints[index].Topic != sidecar.PushTopicGkm || hints[index].Kind != uint32(protocol.MessageType_GKM_HINT) || !slices.Equal(hints[index].Hint, want) {
			t.Errorf("hint %d is %v, want its bytes %x", index, hints[index], want)
		}
	}
	if !(hints[0].Version < hints[1].Version && hints[1].Version < hints[2].Version) {
		t.Errorf("the versions do not rise: %d, %d, %d", hints[0].Version, hints[1].Version, hints[2].Version)
	}
	if stats := env.publisher.Stats(); stats.HintCount != 3 || stats.CoalescedCount != 1 || stats.BodyBoundCount != 0 {
		t.Errorf("stats %+v", stats)
	}
}

// Hints of one topic with the same bytes and different kinds, the owner's MessageType, are distinct; a
// repeat of one kind supersedes only its own.
func TestPublisherKeepsHintsOfOneBytesAndTwoKinds(t *testing.T) {
	env := newTestPublisherEnv(t, nil)
	env.startIdle(nil)
	body := []byte{0x08, 0x01}
	env.hintOfKind(sidecar.PushTopicMail, 1, uint32(protocol.MessageType_MAIL_HINT), body)
	env.hintOfKind(sidecar.PushTopicMail, 2, uint32(protocol.MessageType_SMTP_STATUS), body)
	env.hintOfKind(sidecar.PushTopicMail, 3, uint32(protocol.MessageType_MAIL_HINT), body)
	hints := env.awaitBatch(1, 3)
	for index, want := range []struct {
		kind protocol.MessageType
		hint []byte
	}{
		{kind: protocol.MessageType_MAIL_HINT},
		{kind: protocol.MessageType_SMTP_STATUS, hint: body},
		{kind: protocol.MessageType_MAIL_HINT, hint: body},
	} {
		if hints[index].Kind != uint32(want.kind) || !slices.Equal(hints[index].Hint, want.hint) {
			t.Errorf("hint %d is %v, want kind %s with bytes %x", index, hints[index], want.kind, want.hint)
		}
	}
	if stats := env.publisher.Stats(); stats.CoalescedCount != 1 || stats.BodyBoundCount != 0 {
		t.Errorf("stats %+v", stats)
	}
}

// TopicHintBodyCount holds: of eight distinct hints of one topic and a repeat of one of them in a batch,
// only the topic's newest three go with their bytes, the repeat's earlier copy taking no place among
// them; another topic keeps its own beside them; every seq still goes.
func TestPublisherHoldsATopicToItsHintBodyCount(t *testing.T) {
	settings := pushservice.DefaultSidecarPublisherSettings()
	settings.TopicHintBodyCount = 3
	env := newTestPublisherEnv(t, settings)
	env.startIdle(nil)
	recipient := testGkmRecipient(sidecar.NewId())
	bodies := [][]byte{}
	for range 8 {
		groupId := sidecar.NewId()
		bodies = append(bodies, testGkmHintBody(t, protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, &groupId, recipient))
	}
	// in seq order: the eight, a team hint, then the sixth again
	for _, body := range bodies {
		env.gkmHint(body)
	}
	env.hint(sidecar.PushTopicTeam, 1, []byte("team"))
	env.gkmHint(bodies[5])
	hints := env.awaitBatch(1, 10)
	// the newest three distinct of gkm, from the end: the sixth's repeat, the eighth and the seventh
	want := [][]byte{nil, nil, nil, nil, nil, nil, bodies[6], bodies[7], []byte("team"), bodies[5]}
	gkmBodyCount := 0
	for index, hint := range hints {
		if !slices.Equal(hint.Hint, want[index]) {
			t.Errorf("hint %d of %s carries %x, want %x", index, hint.Topic, hint.Hint, want[index])
		}
		if hint.Topic == sidecar.PushTopicGkm && 0 < len(hint.Hint) {
			gkmBodyCount += 1
		}
	}
	if gkmBodyCount != settings.TopicHintBodyCount {
		t.Errorf("%d gkm hints carry their bytes, want %d", gkmBodyCount, settings.TopicHintBodyCount)
	}
	// six without their bytes: the sixth's earlier copy superseded, and five past the bound
	if stats := env.publisher.Stats(); stats.HintCount != 10 || stats.CoalescedCount != 6 || stats.BodyBoundCount != 5 {
		t.Errorf("stats %+v", stats)
	}
}

// A hint past the format's bytes goes without them and takes no place under TopicHintBodyCount, so the
// distinct hint before it keeps its own at a bound of one.
func TestPublisherOversizeHintTakesNoPlaceUnderTheBound(t *testing.T) {
	settings := pushservice.DefaultSidecarPublisherSettings()
	settings.TopicHintBodyCount = 1
	settings.Format.MaxHintByteCount = 8
	env := newTestPublisherEnv(t, settings)
	env.startIdle(nil)
	env.hint(sidecar.PushTopicTeam, 1, []byte("small"))
	env.hint(sidecar.PushTopicTeam, 2, []byte("past eight bytes"))
	hints := env.awaitBatch(1, 2)
	if !slices.Equal(hints[0].Hint, []byte("small")) || len(hints[1].Hint) != 0 {
		t.Errorf("hints %v and %v", hints[0], hints[1])
	}
	if stats := env.publisher.Stats(); stats.CoalescedCount != 1 || stats.BodyBoundCount != 0 {
		t.Errorf("stats %+v", stats)
	}
}
