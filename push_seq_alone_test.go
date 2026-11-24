//go:build !js

// The superseded hint a resident's publisher sends as its seq alone, PushHint{seq} (§6.8, QD-1397), as the
// client's push machine (push_state.go) takes it: counted, so the hints around it run on with no gap and
// ask for no versions, and applying nothing, so it raises no version, changes nothing kept and tells no
// subscriber, while the later copy of its batch, which carries the topic, its version and the bytes,
// raises the topic and tells its subscribers. A seq alone first after a reset sets the seq baseline as any
// hint does, and one that does not follow the last seq is a gap like any other. Every leg but js, whose
// tests cannot open files.

package sidecar

import (
	"bytes"
	"context"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A per-client gkm work hint as the publisher's batch carries it with its bytes.
func testPushGkmWorkHint(seq uint64, version uint64, body string) *protocol.PushHint {
	return &protocol.PushHint{Seq: seq, Topic: PushTopicGkm, Version: version, Kind: uint32(protocol.MessageType_GKM_HINT), Hint: []byte(body)}
}

// The machine counts a seq alone between two hints, and the next hint follows it; after a reset a seq
// alone sets the baseline; one past a gap sends the client to versions and still applies nothing.
func TestPushSeqAloneHintCountsWithNoGap(t *testing.T) {
	machine := testPushMachine()
	if action := machine.hint(testPushGkmWorkHint(7, 100, "before")); action.refetchVersions || len(action.notices) != 1 {
		t.Fatalf("the hint before the batch: %+v", action)
	}
	if action := machine.hint(&protocol.PushHint{Seq: 8}); action.refetchVersions || action.changed || len(action.notices) != 0 || len(action.alarms) != 0 {
		t.Errorf("the seq alone: %+v", action)
	}
	if !machine.hasSeq || machine.lastSeq != 8 || len(machine.topicVersions) != 1 || machine.topicVersions[PushTopicGkm] != 100 {
		t.Errorf("after the seq alone the machine holds seq %d (%t) and %v", machine.lastSeq, machine.hasSeq, machine.topicVersions)
	}
	if action := machine.hint(testPushGkmWorkHint(9, 101, "after")); action.refetchVersions || !action.changed || len(action.notices) != 1 {
		t.Errorf("the hint after the seq alone: %+v", action)
	}

	machine.reset(map[string]uint64{}, machine.inputCount)
	for _, seq := range []uint64{40, 41} {
		if action := machine.hint(&protocol.PushHint{Seq: seq}); action.refetchVersions || len(action.notices) != 0 {
			t.Errorf("the seq alone %d after a reset: %+v", seq, action)
		}
	}
	if action := machine.hint(testPushHint(42, PushTopicTeam, 3)); action.refetchVersions || len(action.notices) != 1 {
		t.Errorf("the hint after them: %+v", action)
	}
	if action := machine.hint(&protocol.PushHint{Seq: 44}); !action.refetchVersions || action.changed || len(action.notices) != 0 {
		t.Errorf("a seq alone past a gap: %+v", action)
	}
}

// The batch a publisher sends for one late ask's work hint repeated around another ask's, through the feed
// a PushClient hands each frame to: the gkm subscriber hears the two hints that carry their topic, each
// with its bytes and none a resync notice, never the seq alone, and no hint asks the feed for versions,
// so the seqs ran on with no gap.
func TestPushFeedTellsNoSubscriberOfASeqAloneHint(t *testing.T) {
	feed, err := newPushFeed(t.Context(), DefaultPushClientSettings(), newTestPushStore(), newTestEnvelopeClock(), NewNoopLogger(), nil, func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		// the start refetch never answers, so no page's notice joins the hints'
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer feed.close()
	// a callback runs on the goroutine that fed the input, this one
	notices := []PushNotice{}
	for _, topic := range []string{PushTopicGkm, PushTopicGkmGroupPrefix, PushTopicCore, PushTopicTeam} {
		remove, err := feed.subscribe(topic, func(notice PushNotice) {
			notices = append(notices, notice)
		})
		if err != nil {
			t.Fatal(err)
		}
		defer remove()
	}
	hints := []*protocol.PushHint{
		{Seq: 1},
		testPushGkmWorkHint(2, 11, "other"),
		testPushGkmWorkHint(3, 12, "repeated"),
	}
	for _, hint := range hints {
		feed.applyHint(hint)
	}
	if asks, _ := feed.asks.Get(); asks.askCount != 0 {
		t.Errorf("the batch asked for versions %d times", asks.askCount)
	}
	if len(notices) != 2 {
		t.Fatalf("%d notices, want 2: %+v", len(notices), notices)
	}
	for index, notice := range notices {
		hint := hints[index+1]
		if notice.Resync || notice.Topic != hint.Topic || notice.Version != hint.Version || notice.Kind != hint.Kind || !bytes.Equal(notice.Hint, hint.Hint) {
			t.Errorf("notice %d is %+v, want hint %v's", index, notice, hint)
		}
	}
	if version := feed.version(PushTopicGkm); version != 12 {
		t.Errorf("the feed holds gkm at %d, want 12", version)
	}
}
