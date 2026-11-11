//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// Conflict branches (DESIGN-DETAILS 8.2.7; QD-602): a real divergence makes one branch at the local commit, named
// ur/<sidecar_id>/conflicts/<ref>/<time>, in the git transaction that moves the ref to evs's tip, with evs_conflict and
// a queue update for the branch; at the bound the ref stops settling, its local ref left alone; and a local tag that
// differs is replaced by evs's, its commit saved only when no other ref reaches it.

package sidecar

import (
	"context"
	"strings"
	"testing"
)

// A local ref moved outside the daemon to a commit evs's ref does not hold, then evs's ref moves elsewhere: one
// conflict branch at the local commit, the ref at evs's tip, evs_conflict naming both, and a LOCAL update of kind 4
// queued for the branch, which is an owned ref of this sidecar.
func TestEvsLocalConflictOnARealDivergence(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c0 := publisher.commit(map[string]string{"a.txt": "zero\n"})
	if _, err := publisher.publish("main", &c0); err != nil {
		t.Fatal(err)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.replay("main")
	diverged := publisher.commit(map[string]string{"a.txt": "local\n"}, c0)
	device.hold(diverged)
	device.moveLocal("refs/heads/main", &diverged)
	c1 := publisher.commit(map[string]string{"a.txt": "one\n"}, c0)
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	queued := []Id{}
	device.engine.setQueueWake(func(refId Id) { queued = append(queued, refId) })
	device.replay("main")
	if local := device.local("refs/heads/main"); local == nil || *local != c1 {
		t.Fatalf("main is %v", local)
	}
	branches, err := device.engine.ConflictBranches(context.Background())
	if err != nil || len(branches) != 1 {
		t.Fatalf("conflict branches %q %v", branches, err)
	}
	sidecarId := device.test.client.args.Identity().SidecarId
	prefix := string(EvsOwnedRefName(sidecarId, "conflicts/main/"))
	if !strings.HasPrefix(string(branches[0]), prefix) || len(string(branches[0])) != len(prefix)+len("20060102T150405Z") {
		t.Fatalf("the branch's name %q", branches[0])
	}
	if local := device.local(evsGitBranchPrefix + string(branches[0])); local == nil || *local != diverged {
		t.Fatalf("the branch is at %v", local)
	}
	conflicts := device.test.eventsOf(SidecarEventEvsConflict)
	if len(conflicts) != 1 || *conflicts[0].RefId != publisher.ref("main").refId || conflicts[0].Path != string(branches[0]) {
		t.Fatalf("evs_conflict %v", conflicts)
	}
	branchId, err := device.engine.repo.resolveRefId(context.Background(), branches[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := device.engine.state.journal(branchId)
	if err != nil || len(journal.Updates) != 1 || journal.Updates[0].State != EvsJournalLocal ||
		journal.Updates[0].Kind != EvsJournalKindConflict || journal.Updates[0].New != diverged.String() {
		t.Fatalf("the branch's queue %+v %v", journal, err)
	}
	if len(queued) != 1 || queued[0] != branchId {
		t.Fatalf("the queue woken for %v", queued)
	}
	if fsck := evsTestFsck(t, device.mount.BareDir); strings.Join(fsck, "") != "" {
		t.Fatalf("fsck %v", fsck)
	}
}

// At ConflictBranchCount branches a ref stops settling: a second divergence leaves the local ref where it is and marks
// the record, until a branch is deleted, after which settle makes the second branch.
func TestEvsLocalConflictBound(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c0 := publisher.commit(map[string]string{"a.txt": "zero\n"})
	if _, err := publisher.publish("main", &c0); err != nil {
		t.Fatal(err)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.test.client.settings.ConflictBranchCount = 1
	device.replay("main")
	first := publisher.commit(map[string]string{"a.txt": "first local\n"}, c0)
	device.hold(first)
	device.moveLocal("refs/heads/main", &first)
	c1 := publisher.commit(map[string]string{"a.txt": "one\n"}, c0)
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	device.replay("main")
	second := publisher.commit(map[string]string{"a.txt": "second local\n"}, c1)
	device.hold(second)
	device.moveLocal("refs/heads/main", &second)
	c2 := publisher.commit(map[string]string{"a.txt": "two\n"}, c1)
	if _, err := publisher.publish("main", &c2); err != nil {
		t.Fatal(err)
	}
	device.replay("main")
	if local := device.local("refs/heads/main"); local == nil || *local != second {
		t.Fatalf("main at the bound moved to %v", local)
	}
	if ref := device.ref("main"); !ref.SettleStopped || !evsOidEqual(ref.Tip, &c2) {
		t.Fatalf("the record at the bound %+v", ref)
	}
	branches, _ := device.engine.ConflictBranches(context.Background())
	if len(branches) != 1 {
		t.Fatalf("branches %q", branches)
	}
	device.moveLocal(evsGitBranchPrefix+string(branches[0]), nil)
	if err := device.engine.settle(context.Background(), publisher.ref("main").refId); err != nil {
		t.Fatal(err)
	}
	if local := device.local("refs/heads/main"); local == nil || *local != c2 {
		t.Fatalf("main after a branch went is %v", local)
	}
	if branches, _ := device.engine.ConflictBranches(context.Background()); len(branches) != 1 {
		t.Fatalf("the second branch %q", branches)
	}
	if ref := device.ref("main"); ref.SettleStopped {
		t.Fatalf("still stopped %+v", ref)
	}
}

// A local tag moved to a commit another ref reaches is replaced by evs's with no branch; one at a commit no other ref
// reaches is saved on a conflict branch first.
func TestEvsLocalConflictOfATag(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	c0 := publisher.commit(map[string]string{"a.txt": "zero\n"})
	c1 := publisher.commit(map[string]string{"a.txt": "one\n"}, c0)
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.publish("refs/tags/v1", &c1); err != nil {
		t.Fatal(err)
	}
	device := newEvsTestDevice(t, publisher, "device b")
	device.replay("refs/tags/v1")
	tagId := publisher.ref("refs/tags/v1").refId
	// the tag moved to c0, which main reaches: replaced, no branch
	device.moveLocal("refs/tags/v1", &c0)
	if err := device.engine.settle(context.Background(), tagId); err != nil {
		t.Fatal(err)
	}
	ref := device.ref("refs/tags/v1")
	ref.AppliedTip = nil
	if err := device.engine.writeRef(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if err := device.engine.settle(context.Background(), tagId); err != nil {
		t.Fatal(err)
	}
	if local := device.local("refs/tags/v1"); local == nil || *local != c1 {
		t.Fatalf("the tag is %v", local)
	}
	if branches, _ := device.engine.ConflictBranches(context.Background()); len(branches) != 0 {
		t.Fatalf("a branch for a commit main reaches: %q", branches)
	}
	// the tag moved to a commit nothing else reaches: saved first
	lone := publisher.commit(map[string]string{"a.txt": "lone\n"}, c0)
	device.hold(lone)
	device.moveLocal("refs/tags/v1", &lone)
	ref = device.ref("refs/tags/v1")
	ref.AppliedTip = nil
	if err := device.engine.writeRef(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if err := device.engine.settle(context.Background(), tagId); err != nil {
		t.Fatal(err)
	}
	if local := device.local("refs/tags/v1"); local == nil || *local != c1 {
		t.Fatalf("the tag is %v", local)
	}
	branches, _ := device.engine.ConflictBranches(context.Background())
	if len(branches) != 1 {
		t.Fatalf("the lone commit's branch %q", branches)
	}
	if local := device.local(evsGitBranchPrefix + string(branches[0])); local == nil || *local != lone {
		t.Fatalf("the branch is at %v", local)
	}
}
