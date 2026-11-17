// A read by number that the path holds no version at answers its newest version or removal below it (QD-888,
// question mail-m7-04-recreated-record-history; owner decision 380), so History walks from a creation into the
// removal before it and the life that removal ended: from the entry while the creation is unfolded, from the window's
// statements once the creation's fold replaced what the entry held, and from the ref's log pages once the removal
// paged out of the window. A path that holds nothing below the number answers with no version, and a scan past
// ReadVersionScanCount versions below the window answers 503, the read unfinished. On T2's fakes, through the engine's
// guard.

package evsservice

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A read of path by number on the main ref, naming its token path in epoch 1: the reply and its one path.
func (self *pushFixture) readNumber(token string, path sidecar.EvsTokenPath, version uint64) (*readTestReply, *protocol.EvsReadPathReply) {
	self.t.Helper()
	reply := self.read(token, &protocol.EvsReadRequest{
		RefId: self.check.refId.Bytes(),
		Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: path.Components()}}, Version: version}},
	})
	return reply, reply.paths[0]
}

// Commits one push of change to path on the head: a write over base, a removal of base when version is 0, or a
// creation over a removal at removedAt, at max(b, removedAt) + 1. Its push id and the ref version it committed at.
func (self *pushFixture) commitChange(path sidecar.EvsTokenPath, base uint64, version uint64, removedAt uint64) (sidecar.Id, uint64) {
	self.t.Helper()
	plan := self.plan()
	if base == 0 && version == 0 {
		version = max(plan.BaseVersion, removedAt) + 1
	}
	plan.Changes = append(plan.Changes, self.check.change(plan, path, base, version))
	committed := self.requireCommitted(self.push(plan), plan.BaseVersion+1).GetVersion()
	self.awaitStepEights()
	return plan.PushId, committed
}

// Commits count pushes each creating a path of its own below "n": versions that change nothing of another path.
func (self *pushFixture) commitOthers(prefix string, count int) {
	self.t.Helper()
	for i := 0; i < count; i += 1 {
		self.commitOne(protocol.EvsRefMode_EVS_REF_FILE, fmt.Sprintf("%s-%03d", prefix, i))
	}
}

// Requires the reply to serve path's version number, committed at commitVersion, proven against its statement.
func requireNumberedVersion(t *testing.T, label string, reply *readTestReply, pathReply *protocol.EvsReadPathReply, path sidecar.EvsTokenPath, number uint64, commitVersion uint64) {
	t.Helper()
	if pathReply.GetRemoval() != nil || pathReply.GetVersion().GetCommitVersion() != commitVersion {
		t.Fatalf("%s: answered %v, want version %d committed at %d", label, pathReply, number, commitVersion)
	}
	requireVersionProven(t, reply, pathReply, path)
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(pathReply.GetVersion().GetEntryVersion(), entry); err != nil || entry.GetVersion() != number {
		t.Fatalf("%s: entry %v %v, want version %d", label, entry, err, number)
	}
}

// Requires the reply to serve the removal pushId committed at removalVersion, of path version pathVersion, proven.
func requireNumberedRemoval(t *testing.T, label string, reply *readTestReply, pathReply *protocol.EvsReadPathReply, path sidecar.EvsTokenPath, pushId sidecar.Id, removalVersion uint64, pathVersion uint64) {
	t.Helper()
	removal := pathReply.GetRemoval()
	if removal == nil || removal.GetRemovalVersion() != removalVersion || removal.GetPathVersion() != pathVersion ||
		!bytes.Equal(removal.GetPushId(), pushId.Bytes()) {
		t.Fatalf("%s: answered %v, want the removal at %d of path version %d", label, pathReply, removalVersion, pathVersion)
	}
	requireRemovalProven(t, reply, pathReply, path)
}

// A path written, removed and created again: by number, the removal's own number and every number up to the
// creation's answer the removal, the earlier life's numbers its versions, the standing life's its own, and a number
// past the newest the newest; unfolded, where the entry still holds the earlier life, and folded, where the creation
// replaced what the entry held and the window's statements hold it. A path never written, and one whose first
// creation took a number past 1 with nothing below it, answer no version below.
func TestReadByNumberWalksAcrossARemovalIntoTheEarlierLife(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	path := checkTestPath("a")
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
	fixture.commitChange(path, 1, 2, 0)
	removalId, removalVersion := fixture.commitChange(path, 2, 0, 0)
	// the creation over the removal takes max(b, m) + 1 = max(3, 3) + 1
	fixture.commitChange(path, 0, 0, 3)
	fixture.commitChange(path, 4, 5, 0)
	// a path created over nothing at max(b, m) + 1 = 6, with no life below it
	late := checkTestPath("late")
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "late")

	check := func(label string) {
		t.Helper()
		reply, pathReply := fixture.readNumber(token, path, 3)
		requireNumberedRemoval(t, label+": 3, the removal's own number", reply, pathReply, path, removalId, removalVersion, 3)
		for _, number := range []uint64{1, 2} {
			reply, pathReply := fixture.readNumber(token, path, number)
			requireNumberedVersion(t, fmt.Sprintf("%s: the earlier life's %d", label, number), reply, pathReply, path, number, number)
		}
		for _, number := range []uint64{4, 5} {
			reply, pathReply := fixture.readNumber(token, path, number)
			requireNumberedVersion(t, fmt.Sprintf("%s: the standing life's %d", label, number), reply, pathReply, path, number, number)
		}
		reply, pathReply = fixture.readNumber(token, path, 9)
		requireNumberedVersion(t, label+": past the newest", reply, pathReply, path, 5, 5)
		if _, pathReply := fixture.readNumber(token, late, 5); !readReplyPlainAbsent(pathReply) {
			t.Fatalf("%s: below a first creation: %v", label, pathReply)
		}
		if _, pathReply := fixture.readNumber(token, checkTestPath("never"), 3); !readReplyPlainAbsent(pathReply) {
			t.Fatalf("%s: a path never written: %v", label, pathReply)
		}
	}
	check("unfolded")
	fixture.foldRef()
	read := fixture.entryAt(1, "a")
	if folded := fixture.head().Head.GetFoldedThrough(); read.Entry.GetMarker() != nil || len(read.Entry.GetVersions()) != 2 || folded != 6 {
		t.Fatalf("the creation's fold kept %v through %d", read.Entry, folded)
	}
	check("folded")
}

// Once the removal and the earlier life page out of the window, below a creation the entry holds alone, a read by
// number finds them through their log pages, each served with its statement beside the reply; a ref whose scan bound
// stops short of them answers 503, the read unfinished, and still serves the path's newest.
func TestReadByNumberFindsAnEarlierLifeInTheLogPages(t *testing.T) {
	build := func(scanCount int) (*pushFixture, string, sidecar.Id, uint64) {
		fixture := newPushFixture(t, func(settings *EvsSettings) { settings.ReadVersionScanCount = scanCount })
		token := fixture.token(fixture.check.signerId)
		path := checkTestPath("a")
		fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
		removalId, removalVersion := fixture.commitChange(path, 1, 0, 0)
		fixture.commitOthers("n", 40)
		// created again at max(b, m) + 1 = 43, the life below it 40 versions down
		fixture.commitChange(path, 0, 0, 2)
		fixture.commitOthers("m", 130)
		fixture.foldRef()
		head := fixture.head().Head
		if first := EvsHeadWindowFirstVersion(head); first <= 43 {
			t.Fatalf("the window starts at %d", first)
		}
		return fixture, token, removalId, removalVersion
	}
	path := checkTestPath("a")

	fixture, token, removalId, removalVersion := build(DefaultEvsSettings().ReadVersionScanCount)
	if read := fixture.entryAt(1, "a"); read.Entry.GetMarker() != nil || len(read.Entry.GetVersions()) != 1 {
		t.Fatalf("the entry %v", read.Entry)
	}
	reply, pathReply := fixture.readNumber(token, path, 42)
	requireNumberedRemoval(t, "below the creation", reply, pathReply, path, removalId, removalVersion, 2)
	if len(pathReply.GetStatement()) == 0 {
		t.Fatal("a removal below the window with no statement beside it")
	}
	reply, pathReply = fixture.readNumber(token, path, 1)
	requireNumberedVersion(t, "the earlier life", reply, pathReply, path, 1, 1)
	reply, pathReply = fixture.readNumber(token, path, 43)
	requireNumberedVersion(t, "the creation", reply, pathReply, path, 43, 43)

	// a bound of 32 versions below the window stops the scan short of the removal
	short, shortToken, _, _ := build(32)
	recorder := short.call(shortToken, http.MethodPost, "/read", &protocol.EvsReadRequest{
		RefId: short.check.refId.Bytes(),
		Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: path.Components()}}, Version: 42}},
	})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("past the scan bound: status %d", recorder.Code)
	}
	reply, pathReply = short.readNumber(shortToken, path, 0)
	requireNumberedVersion(t, "the newest past the bound", reply, pathReply, path, 43, 43)
}
