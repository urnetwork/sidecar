// The GkmHint intake's notices without their bytes (§6.8): a resident's publisher sends a hint past its topic's
// TopicHintBodyCount with its seq, topic, version and kind but not its bytes, as a publisher before QD-1397 sent a
// hint that a later one of its batch repeats, which one now sends as its seq alone. A gkm:<group_id> notice without
// them is still its group's commit wake and asks no resync, so a group's commits coalesced in one window cost one
// sync rather than a resync of everything; a per-client gkm one, whose kind, group and recipient went with the
// bytes, still asks for a resync. Each batch is handed to the intake
// while it is held inside another wake, so it takes the batch in one pass, as it would a batch the push delivers at
// once, on a clock the test never moves and handlers it holds, so nothing here sleeps.

package sidecar

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A notice of a hint the publisher sent without its bytes: its topic, version and kind alone.
func gkmTestBodylessNotice(topic string, version uint64) PushNotice {
	return PushNotice{Topic: topic, Version: version, Kind: uint32(protocol.MessageType_GKM_HINT)}
}

// Holds the intake inside a key-packages-low wake, hands it notices, which it takes together in its next pass, then
// lets it go and waits for that pass to finish, by which every wake and resync the notices asked for has run.
func takeGkmTestBatch(t *testing.T, hints *GkmHints, notices ...PushNotice) {
	t.Helper()
	holder := newGkmTestHandler(true)
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW, holder.handle)
	hints.Receive(gkmTestNotice(t, PushTopicGkm, 1, &protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW}))
	<-holder.entered
	// the pass running the holder is not counted yet: once it ends, the next takes the batch
	heldPassCount, _ := hints.Passes()
	for _, notice := range notices {
		hints.Receive(notice)
	}
	close(holder.release)
	awaitGkmHintPasses(t, hints, heldPassCount+1)
}

// A running intake on a clock that never moves, so no hourly resync runs, and the channel its resyncs signal on.
func newGkmTestBodylessHints(t *testing.T) (*GkmHints, chan struct{}) {
	t.Helper()
	hints, err := NewGkmHints(context.Background(), &GkmHintsArgs{Clock: newGkmTestClock()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hints.Close)
	resyncs := make(chan struct{}, 16)
	hints.AddResync(func(ctx context.Context) { resyncs <- struct{}{} })
	return hints, resyncs
}

// A group's two commits in one window, as a publisher before QD-1397 sent them: the earlier goes without its bytes,
// which the later one repeats. The batch takes no resync and wakes the group's commit handler once, at the later
// generation. Before, the earlier notice failed the group topic's form and resynced every repo the device holds.
func TestGkmHintsBodylessGroupRepeatAsksNoResync(t *testing.T) {
	hints, resyncs := newGkmTestBodylessHints(t)
	commits := newGkmTestHandler(false)
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_COMMIT, commits.handle)
	groupId := NewId()
	topic := PushTopicGkmGroup(groupId)
	body := &protocol.GkmHint{GroupId: groupId.Bytes(), Kind: protocol.GkmHintKind_GKM_HINT_COMMIT}

	takeGkmTestBatch(t, hints, gkmTestBodylessNotice(topic, 5), gkmTestNotice(t, topic, 6, body))
	if len(resyncs) != 0 {
		t.Errorf("the batch took %d resyncs, want none", len(resyncs))
	}
	wakes := commits.taken()
	if len(wakes) != 1 {
		t.Fatalf("%d commit wakes, want 1", len(wakes))
	}
	if wakes[0].Kind != protocol.GkmHintKind_GKM_HINT_COMMIT || wakes[0].GroupId == nil || *wakes[0].GroupId != groupId || wakes[0].Epoch != 0 || wakes[0].Generation != 6 {
		t.Errorf("the commit wake %+v", wakes[0])
	}
}

// A group's commit whose copy never comes, as one past TopicHintBodyCount: its topic still names its group and its
// version the generation, past 2^24 too, so it is the group's commit wake and asks no resync. A group topic out of its
// one form, or a notice without bytes of another MessageType, still asks for one.
func TestGkmHintsBodylessGroupHintWakesItsGroup(t *testing.T) {
	hints, resyncs := newGkmTestBodylessHints(t)
	commits := newGkmTestHandler(false)
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_COMMIT, commits.handle)
	groupId := NewId()
	generation := uint64(1<<32 + 7)

	takeGkmTestBatch(t, hints, gkmTestBodylessNotice(PushTopicGkmGroup(groupId), generation))
	if len(resyncs) != 0 {
		t.Errorf("%d resyncs, want none", len(resyncs))
	}
	wakes := commits.taken()
	if len(wakes) != 1 || wakes[0].GroupId == nil || *wakes[0].GroupId != groupId || wakes[0].Epoch != 0 || wakes[0].Generation != generation {
		t.Fatalf("the commit wakes %+v", wakes)
	}

	// the id parses without its dashes, but the topic is not the group's one name
	hints.Receive(gkmTestBodylessNotice(PushTopicGkmGroupPrefix+strings.ReplaceAll(groupId.String(), "-", ""), generation+1))
	<-resyncs
	hints.Receive(PushNotice{Topic: PushTopicGkmGroup(groupId), Version: generation + 2})
	<-resyncs
	if wakes := commits.taken(); len(wakes) != 1 {
		t.Errorf("%d commit wakes, want the first alone", len(wakes))
	}
}

// A per-client work hint without its bytes asks for a resync, whatever dropped them: past TopicHintBodyCount, its
// kind, group and recipient are lost but for the resync, and a publisher before QD-1397 sent a repeat superseded by
// a copy later in its batch as the same notice, which nothing the client receives tells apart. The batch's hints
// with their bytes still wake their handlers, and the batch costs one resync.
func TestGkmHintsBodylessWorkHintResyncs(t *testing.T) {
	hints, resyncs := newGkmTestBodylessHints(t)
	works := newGkmTestHandler(false)
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, works.handle)
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_PENDING, works.handle)
	groupId, otherGroupId := NewId(), NewId()
	// a late ask's, as its wrap path writes it
	recipient := "s:" + hex.EncodeToString(NewId().Bytes())

	takeGkmTestBatch(
		t,
		hints,
		gkmTestBodylessNotice(PushTopicGkm, 10),
		gkmTestNotice(t, PushTopicGkm, 11, &protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, GroupId: groupId.Bytes(), Recipient: []byte(recipient)}),
		gkmTestNotice(t, PushTopicGkm, 12, &protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_PENDING, GroupId: otherGroupId.Bytes()}),
	)
	if len(resyncs) != 1 {
		t.Errorf("the batch took %d resyncs, want 1", len(resyncs))
	}
	wakes := works.taken()
	if len(wakes) != 2 {
		t.Fatalf("%d work wakes, want 2", len(wakes))
	}
	wrapPendingWake, pendingWake := wakes[0], wakes[1]
	if wrapPendingWake.Kind != protocol.GkmHintKind_GKM_HINT_WRAP_PENDING || *wrapPendingWake.GroupId != groupId || wrapPendingWake.Recipient != recipient {
		t.Errorf("the wrap-pending wake %+v", wrapPendingWake)
	}
	if pendingWake.Kind != protocol.GkmHintKind_GKM_HINT_PENDING || *pendingWake.GroupId != otherGroupId {
		t.Errorf("the pending wake %+v", pendingWake)
	}
}
