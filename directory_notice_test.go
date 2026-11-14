//go:build !sidecar_http && !ios_extension

// RECORD-M6-18's notices over the fake world: a notice whose write did not land repaired from its request entry; the
// path rules ignoring a version its signer may not write, with a path_rule alarm, while the version last accepted
// shows; the requester's repair writing over a breach; and the leases an approver and a requester hold.

package sidecar_test

import (
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Writes notice at path as device, from the version its copy read.
func testPutNotice(t *testing.T, env *testRequestsEnv, device *testDirectoryDevice, path string, notice *protocol.DirectoryNotice) {
	t.Helper()
	device.mustSync(t)
	ifVersion := uint64(0)
	for _, file := range device.client.Cards() {
		if file.Path == path && !file.Removed {
			ifVersion = file.Version
		}
	}
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(notice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := device.client.PutCard(t.Context(), &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: path, IfVersion: ifVersion, Content: content, AuthPin: env.world.directoryAuth.Tip().Pin(),
	}); err != nil {
		t.Fatal(err)
	}
}

// A crash between the request entry and its notice leaves a request with no notice, which no approver sees; the
// requester's next upkeep writes the pending notice from its entry, once.
func TestDirectoryNoticeWriteOrderCrashRepaired(t *testing.T) {
	env := newTestRequestsEnv(t)
	requesterId := env.requester.writer.sidecarId
	// the notice's write is refused: evs lets this sidecar read and no longer write
	if err := env.world.streams.Grant(env.world.directoryId, requesterId, sidecartest.RecordStreamsScope{Read: true}); err != nil {
		t.Fatal(err)
	}
	filed := env.mustFile(env.requester, env.ask())
	if filed.NoticeWritten || filed.EntrySeq == 0 {
		t.Fatalf("filed %+v", filed)
	}
	if err := env.world.streams.Grant(env.world.directoryId, requesterId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	env.requester.flush(t)
	if views := env.requests(env.approver, nil); len(views) != 0 {
		t.Fatalf("a request with no notice shows to %d approvers", len(views))
	}
	if mine := env.request(env.requester, filed.RequestId); mine.State != sidecar.DirectoryRequestPending || mine.Notice != nil {
		t.Fatalf("the requester's view before the repair %+v", mine)
	}
	writes := env.world.cards.Counts().CardWrites
	for range 2 {
		if err := env.requester.client.Requests().Maintain(t.Context()); err != nil {
			t.Fatal(err)
		}
		env.requester.mustSync(t)
	}
	if written := env.world.cards.Counts().CardWrites - writes; written != 1 {
		t.Fatalf("the repair wrote %d notices", written)
	}
	view := env.request(env.approver, filed.RequestId)
	if !view.Decidable || view.Notice == nil || view.Notice.GetEntrySeq() != filed.EntrySeq {
		t.Fatalf("the approver's view after the repair %+v", view)
	}
}

// A notice version its signer may not write is ignored with a path_rule alarm, once: a decided rewrite by a sidecar
// that decides nothing for the target, and a pending one by another than the requester. Readers show the version they
// last accepted meanwhile, and the requester's repair writes the pending notice over the breach.
func TestDirectoryNoticePathRulesIgnoreABreach(t *testing.T) {
	env := newTestRequestsEnv(t)
	intruderWriter := env.world.memberWriter(sidecar.NewId())
	env.world.publish()
	intruder := env.device(intruderWriter)
	filed := env.mustFile(env.requester, env.ask())
	if view := env.request(env.approver, filed.RequestId); view.Notice == nil {
		t.Fatal("no notice accepted")
	}
	forged := &protocol.DirectoryNotice{
		RequestId:          filed.RequestId.Bytes(),
		RequesterSidecarId: env.requester.writer.sidecarId.Bytes(),
		EntrySeq:           filed.EntrySeq,
		NotAfterMillis:     filed.NotAfterMillis,
		State:              uint32(sidecar.DirectoryNoticeStateDecided),
		Outcome:            uint32(sidecar.DirectoryOutcomeApproved),
		Decisions: []*protocol.DecisionRef{{
			DeciderSidecarId: intruderWriter.sidecarId.Bytes(), Seq: 1, HeaderSha256: make([]byte, 32),
		}},
	}
	testPutNotice(t, env, intruder, filed.NoticePath, forged)
	for range 2 {
		view := env.request(env.approver, filed.RequestId)
		if view.State != sidecar.DirectoryRequestPending || view.Notice == nil || len(view.Notice.GetDecisions()) != 0 {
			t.Fatalf("a forged approval reads %s", view.State)
		}
	}
	if count := testAlarmCount(env.approver, sidecar.SidecarRecordAlarmPathRule); count != 1 {
		t.Fatalf("%d path_rule alarms", count)
	}
	// the requester's own view never takes it as an approval either, and its upkeep repairs the path
	if mine := env.request(env.requester, filed.RequestId); mine.State != sidecar.DirectoryRequestPending {
		t.Fatalf("the requester reads a forged approval as %s", mine.State)
	}
	if err := env.requester.client.Requests().Maintain(t.Context()); err != nil {
		t.Fatal(err)
	}
	env.approver.mustSync(t)
	if notice := testNoticeAt(t, env.approver, filed.NoticePath); notice == nil || notice.GetState() != uint32(sidecar.DirectoryNoticeStatePending) {
		t.Fatalf("the path after the repair holds %v", notice)
	}

	// a pending notice for a request, written by another than its requester, is none
	second := env.mustFile(env.requester, env.ask())
	env.requester.mustSync(t)
	if err := env.requester.client.RemoveCard(t.Context(), &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: second.NoticePath, IfVersion: 1, AuthPin: env.world.directoryAuth.Tip().Pin(),
	}); err != nil {
		t.Fatal(err)
	}
	pending := proto.Clone(forged).(*protocol.DirectoryNotice)
	pending.RequestId, pending.EntrySeq, pending.NotAfterMillis = second.RequestId.Bytes(), second.EntrySeq, second.NotAfterMillis
	pending.State, pending.Outcome, pending.Decisions = uint32(sidecar.DirectoryNoticeStatePending), 0, nil
	testPutNotice(t, env, intruder, second.NoticePath, pending)
	if views := env.requests(env.approver, &sidecar.DirectoryRequestFilter{RequestId: &second.RequestId}); len(views) != 0 {
		t.Fatalf("a notice its requester did not write shows the request")
	}
	if count := testAlarmCount(env.approver, sidecar.SidecarRecordAlarmPathRule); count != 2 {
		t.Fatalf("%d path_rule alarms after the second breach", count)
	}
}

// How many alarms of reason a device raised.
func testAlarmCount(device *testDirectoryDevice, reason sidecar.SidecarRecordAlarm) int {
	count := 0
	for _, raised := range device.alarmReasons() {
		if raised == reason {
			count += 1
		}
	}
	return count
}

// An approver's device leases the notice prefix of each target it decides, and a requester's each pending notice's
// own path; neither leases anything else, and a closed part releases them.
func TestDirectoryNoticeLeases(t *testing.T) {
	env := newTestRequestsEnv(t)
	filed := env.mustFile(env.requester, env.ask())
	for _, device := range []*testDirectoryDevice{env.requester, env.approver} {
		device.mustSync(t)
		if err := device.client.Requests().Maintain(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	repoPrefix, err := sidecar.DirectoryNoticePrefix(&protocol.RequestTarget{RepoId: env.repoId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	held := map[sidecar.Id][]string{}
	for _, lease := range env.world.cards.Leases() {
		if !strings.HasPrefix(lease.Prefix, "q/") {
			t.Fatalf("a lease on %q", lease.Prefix)
		}
		held[lease.SidecarId] = append(held[lease.SidecarId], lease.Prefix)
	}
	if !slices.Contains(held[env.approver.writer.sidecarId], repoPrefix) || slices.Contains(held[env.requester.writer.sidecarId], repoPrefix) {
		t.Fatalf("the repo's prefix is leased by %v", held)
	}
	if !slices.Contains(held[env.requester.writer.sidecarId], filed.NoticePath) || slices.Contains(held[env.approver.writer.sidecarId], filed.NoticePath) {
		t.Fatalf("the notice's path is leased by %v", held)
	}
	// a second upkeep takes none again
	taken := env.world.cards.Counts().LeasesTaken
	for _, device := range []*testDirectoryDevice{env.requester, env.approver} {
		if err := device.client.Requests().Maintain(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if counts := env.world.cards.Counts(); counts.LeasesTaken != taken || counts.LeasesRelease != 0 {
		t.Fatalf("a second upkeep took %d leases and released %d", counts.LeasesTaken-taken, counts.LeasesRelease)
	}
	env.requester.client.Requests().Close()
	if released := env.world.cards.Counts().LeasesRelease; released != len(held[env.requester.writer.sidecarId]) {
		t.Fatalf("a closed requester released %d of its %d leases", released, len(held[env.requester.writer.sidecarId]))
	}
}
