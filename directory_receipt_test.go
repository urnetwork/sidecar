//go:build !sidecar_http && !ios_extension

// RECORD-M6-19's receipt over the fake world: a requester reading one notice and the one entry it names and nothing
// else; a DecisionRef that names another request's entry refused with an alarm; an approval not taken while nothing
// checks its statement; and a notice kept until the vault records the outcome.

package sidecar_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A source that counts its reads over the copy's.
type testReceiptSource struct {
	device *testDirectoryDevice
	reads  []string
}

func (self *testReceiptSource) DecisionEntry(ctx context.Context, deciderSidecarId sidecar.Id, seq uint64) (*sidecar.DirectoryDecisionView, error) {
	self.reads = append(self.reads, deciderSidecarId.String())
	views, err := self.device.client.GetRequests(ctx, &sidecar.DirectoryRequestFilter{Mine: true})
	if err != nil {
		return nil, err
	}
	for _, view := range views {
		for _, decision := range view.Decisions {
			if decision.DeciderSidecarId == deciderSidecarId && decision.Seq == seq {
				return decision, nil
			}
		}
	}
	return nil, nil
}

// A requester's receipt reads the decided notice and, by its one DecisionRef, one entry of its decider's stream, and
// nothing else: no stream is scanned and no index is asked.
func TestDirectoryReceiptReadsOneNoticeAndOneEntry(t *testing.T) {
	env := newTestDecideEnv(t)
	filed := env.mustFile(env.requester, env.ask())
	env.mustDecide(env.approver, filed.RequestId, true)
	view := env.request(env.requester, filed.RequestId)
	source := &testReceiptSource{device: env.requester}
	receipt, err := env.requester.client.Requests().Receive(t.Context(), view, source)
	if err != nil || receipt == nil {
		t.Fatalf("receipt %v, %v", receipt, err)
	}
	if len(source.reads) != 1 || source.reads[0] != env.approver.writer.sidecarId.String() {
		t.Fatalf("the receipt read %v", source.reads)
	}
	if receipt.Outcome != sidecar.SidecarAccessDecidedApproved || len(receipt.Decisions) != 1 || !receipt.Recorded {
		t.Fatalf("receipt %+v", receipt)
	}
	// an entry not there yet waits, with no alarm
	if receipt, err := env.requester.client.Requests().Receive(t.Context(), view, &testEmptyReceiptSource{}); err != nil || receipt != nil {
		t.Fatalf("a receipt with no entry yet answered %v, %v", receipt, err)
	}
	if count := testAlarmCount(env.requester, sidecar.SidecarRecordAlarmBadDecision); count != 0 {
		t.Fatalf("%d bad_decision alarms", count)
	}
}

// A source that holds nothing yet.
type testEmptyReceiptSource struct{}

func (self *testEmptyReceiptSource) DecisionEntry(ctx context.Context, deciderSidecarId sidecar.Id, seq uint64) (*sidecar.DirectoryDecisionView, error) {
	return nil, nil
}

// A decided notice whose DecisionRef names another request's decision entry is not taken: the receipt refuses it with a
// bad_decision alarm, raises nothing and records nothing.
func TestDirectoryReceiptRefusesAnotherRequestsEntry(t *testing.T) {
	env := newTestDecideEnv(t)
	first := env.mustFile(env.requester, env.ask())
	second := env.mustFile(env.requester, env.ask())
	env.mustDecide(env.approver, first.RequestId, true)
	// the approver rewrites the second request's notice to name its decision on the first
	env.approver.mustSync(t)
	decidedNotice := testNoticeAt(t, env.approver, first.NoticePath)
	forged := proto.Clone(decidedNotice).(*protocol.DirectoryNotice)
	forged.RequestId, forged.EntrySeq, forged.NotAfterMillis = second.RequestId.Bytes(), second.EntrySeq, second.NotAfterMillis
	testPutNotice(t, env.testRequestsEnv, env.approver, second.NoticePath, forged)

	view := env.request(env.requester, second.RequestId)
	if view.Notice == nil || view.Notice.GetState() != uint32(sidecar.DirectoryNoticeStateDecided) {
		t.Fatalf("the forged notice is not the one shown: %v", view.Notice)
	}
	if _, err := env.requester.client.Requests().Receive(t.Context(), view, nil); !errors.Is(err, sidecar.ErrDirectoryReceiptRefused) {
		t.Fatalf("a receipt naming another request's entry answered %v", err)
	}
	if count := testAlarmCount(env.requester, sidecar.SidecarRecordAlarmBadDecision); count != 1 {
		t.Fatalf("%d bad_decision alarms", count)
	}
	requesterId := env.requester.writer.sidecarId
	if err := env.requester.client.Requests().Maintain(t.Context()); !errors.Is(err, sidecar.ErrDirectoryReceiptRefused) {
		t.Fatalf("the upkeep over a forged notice answered %v", err)
	}
	for _, event := range env.events[requesterId] {
		if event == "access_decided/approved/"+second.RequestId.String() {
			t.Fatal("a forged approval was raised")
		}
	}
	for _, recorded := range env.receipts[requesterId].recorded {
		if recorded.RequestId == second.RequestId {
			t.Fatal("a forged approval was recorded")
		}
	}
}

// With nothing bound to check an approval's statement the approval is not taken; while the vault does not record, the
// outcome is raised once and the approved notice stays; once it records, the notice is closed.
func TestDirectoryReceiptFailsClosedAndClosesOnceRecorded(t *testing.T) {
	env := newTestDecideEnv(t)
	filed := env.mustFile(env.requester, env.ask())
	env.mustDecide(env.approver, filed.RequestId, true)
	requesterId := env.requester.writer.sidecarId
	unbound := env.binding(env.requester)
	env.requester.client.BindRequests(unbound)
	env.requester.mustSync(t)
	if err := env.requester.client.Requests().Maintain(t.Context()); !errors.Is(err, sidecar.ErrDirectoryReceiptsUnbound) {
		t.Fatalf("an approval with no receipts bound answered %v", err)
	}
	if len(env.events[requesterId]) != 0 {
		t.Fatalf("an unchecked approval raised %v", env.events[requesterId])
	}
	env.bind(env.requester)
	env.receipts[requesterId].recordErr = errors.New("the vault is locked")
	env.upkeep(env.requester)
	env.upkeep(env.requester)
	if events := env.events[requesterId]; len(events) != 1 {
		t.Fatalf("events while the vault does not record: %v", events)
	}
	if notice := testNoticeAt(t, env.requester, filed.NoticePath); notice == nil {
		t.Fatal("an approved notice was closed before the vault recorded it")
	}
	env.receipts[requesterId].recordErr = nil
	env.upkeep(env.requester)
	env.requester.mustSync(t)
	if notice := testNoticeAt(t, env.requester, filed.NoticePath); notice != nil {
		t.Fatal("an approved notice stands after the vault recorded it")
	}
	if events := env.events[requesterId]; len(events) != 1 {
		t.Fatalf("events after the close: %v", events)
	}
}
