package evsservice

import (
	"bytes"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Deletes the entry of labels' path, as a marker's collection does.
func (self *pushFixture) deleteEntry(labels ...string) {
	self.t.Helper()
	if err := self.cluster.Delete(self.paidContext(), IndexEntryKey(self.check.repoId, self.check.refId, 1, checkTestPath(labels...))); err != nil {
		self.t.Fatal(err)
	}
}

// Checks a removal as §11.9's reader does: its statement, among those after the pin or beside the reply, removes the
// path, inline or by its proof, one past the version the removal names.
func requireRemovalProven(t *testing.T, reply *readTestReply, pathReply *protocol.EvsReadPathReply, path sidecar.EvsTokenPath) {
	t.Helper()
	removal := pathReply.GetRemoval()
	if removal == nil || pathReply.GetVersion() != nil {
		t.Fatalf("path %v: no removal alone", pathReply)
	}
	statement := readTestStatement(t, reply, pathReply, removal.GetRemovalVersion())
	push := statement.Push
	if !bytes.Equal(push.GetPushId(), removal.GetPushId()) {
		t.Fatal("a removal naming another push than its statement's")
	}
	var change *protocol.EvsChange
	if len(push.GetChangesRoot()) == 0 {
		if len(pathReply.GetProof()) != 0 {
			t.Fatal("a proof beside an inline list")
		}
		for _, listed := range statement.Changes {
			if listed.TokenPath.Equal(path) {
				change = listed.Change
			}
		}
	} else {
		proven, provenPath, err := sidecar.EvsVerifyChangeInclusion(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), pathReply.GetProof())
		if err != nil || !provenPath.Equal(path) {
			t.Fatalf("proof: %v %v", err, provenPath)
		}
		change = proven
	}
	if change == nil || len(change.GetEntrySha256()) != 0 || change.GetBaseEntryVersion()+1 != removal.GetPathVersion() {
		t.Fatalf("the statement's change %v is not the removal %v", change, removal)
	}
}

// Whether a path reply names a path evs holds nothing of.
func readReplyPlainAbsent(pathReply *protocol.EvsReadPathReply) bool {
	return pathReply.GetRemoval() == nil && pathReply.GetVersion() == nil && pathReply.GetBase() == nil &&
		len(pathReply.GetStatement()) == 0 && len(pathReply.GetProof()) == 0
}

// QD-879 (question test-m2-04-recreate-after-collection): once a removal's marker is collected, a reader pinned below
// the removal, whose walk holds its statement, is served the removal from the window, as its marker served it; a
// reader pinned at or past it reads the path absent; and the path is created again at max(b, m) + 1.
func TestReadServesARemovalFromTheWindowOnceItsMarkerIsCollected(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	path := checkTestPath("a")
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
	write := fixture.plan()
	write.Changes = append(write.Changes, fixture.check.change(write, path, 1, 2))
	fixture.requireCommitted(fixture.push(write), 2)
	fixture.awaitStepEights()
	remove := fixture.plan()
	remove.Changes = append(remove.Changes, fixture.check.change(remove, path, 2, 0))
	fixture.requireCommitted(fixture.push(remove), 3)
	fixture.awaitStepEights()
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "b")
	fixture.foldRef()
	if head := fixture.head(); head.Head.GetFoldedThrough() != 4 {
		t.Fatalf("folded through %d", head.Head.GetFoldedThrough())
	}
	marked := fixture.readPath(token, 0, true, path).paths[0].GetRemoval()
	if marked == nil || marked.GetRemovalVersion() != 3 || marked.GetPathVersion() != 3 || !bytes.Equal(marked.GetPushId(), remove.PushId.Bytes()) {
		t.Fatalf("the marker's removal %v", marked)
	}
	fixture.deleteEntry("a")
	for _, pin := range []uint64{0, 1, 2} {
		reply := fixture.readPath(token, pin, true, path)
		pathReply := reply.paths[0]
		removal := pathReply.GetRemoval()
		if removal == nil || removal.GetRemovalVersion() != 3 || removal.GetPathVersion() != 3 || !bytes.Equal(removal.GetPushId(), remove.PushId.Bytes()) ||
			removal.GetLeafPart() != 0 || removal.GetLeafIndex() != 0 {
			t.Fatalf("pinned at %d: removal %v, the marker's %v", pin, removal, marked)
		}
		// the statement is among those the walk returns, not beside the reply
		if len(pathReply.GetStatement()) != 0 || len(reply.statements) != int(4-pin) {
			t.Fatalf("pinned at %d: %d statements, %d bytes beside the reply", pin, len(reply.statements), len(pathReply.GetStatement()))
		}
		requireRemovalProven(t, reply, pathReply, path)
	}
	for _, pin := range []uint64{3, 4} {
		reply := fixture.readPath(token, pin, true, path)
		if !readReplyPlainAbsent(reply.paths[0]) {
			t.Fatalf("pinned at %d, past the removal: %v", pin, reply.paths[0])
		}
	}
	// a path never written reads absent to a reader of any pin
	if reply := fixture.readPath(token, 0, true, checkTestPath("never")); !readReplyPlainAbsent(reply.paths[0]) {
		t.Fatalf("a path never written: %v", reply.paths[0])
	}
	// created again by the versions rule: b is past the removal, so the marker's going moves nothing
	create := fixture.plan()
	create.Changes = append(create.Changes, fixture.check.change(create, path, 0, max(create.BaseVersion, marked.GetPathVersion())+1))
	fixture.requireCommitted(fixture.push(create), 5)
	fixture.awaitStepEights()
	reply := fixture.readPath(token, 0, true, path)
	if reply.paths[0].GetRemoval() != nil || reply.paths[0].GetVersion().GetCommitVersion() != 5 {
		t.Fatalf("re-created: %v", reply.paths[0])
	}
	requireVersionProven(t, reply, reply.paths[0], path)
}

// The same under changes_root: the removal a collection took the marker of comes with its inclusion proof from the
// window's record, located by the path's current token path, the marker's leaf place being gone with it.
func TestReadProvesACollectedRemovalUnderChangesRoot(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	path := checkTestPath("a")
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
	remove := fixture.plan()
	remove.Changes = append(remove.Changes, fixture.check.change(remove, path, 1, 0))
	for _, label := range readTestLabels("n") {
		fixture.create(remove, label)
	}
	if built := fixture.built(remove); len(built.Statement.Push.GetChangesRoot()) == 0 || len(built.Parts) != 0 {
		t.Fatal("a push whose list is inline or in parts")
	}
	fixture.requireCommitted(fixture.push(remove), 2)
	fixture.awaitStepEights()
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "b")
	fixture.foldRef()
	marked := fixture.readPath(token, 0, true, path)
	requireRemovalProven(t, marked, marked.paths[0], path)
	if marked.paths[0].GetRemoval().GetLeafIndex() == 0 {
		t.Fatalf("the marker's removal %v names no leaf place", marked.paths[0].GetRemoval())
	}
	fixture.deleteEntry("a")
	reply := fixture.readPath(token, 0, true, path)
	removal := reply.paths[0].GetRemoval()
	if removal == nil || removal.GetRemovalVersion() != 2 || removal.GetPathVersion() != 2 || removal.GetLeafIndex() != 0 || len(reply.paths[0].GetProof()) == 0 {
		t.Fatalf("removal %v with %d proofs", removal, len(reply.paths[0].GetProof()))
	}
	requireRemovalProven(t, reply, reply.paths[0], path)
	if reply := fixture.readPath(token, 2, true, path); !readReplyPlainAbsent(reply.paths[0]) {
		t.Fatalf("pinned at the removal: %v", reply.paths[0])
	}
}
