// QD-1043 (question evs-absent-walked-removal-own-present, option 1) on T2's fakes through the engine: for a path it
// serves plain absent, evs sends in each walked rooted statement's absence the present of the path's own change, a
// write or a removal, and of a strict prefix's removal, so the client's reader verifies a removal made under
// changes_root, collected and paged out, by its own walk (QD-979), as it does an inline one
// (TestReadAbsentPastAPagedOutRemovalVerifiesByTheWalk).

package evsservice

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A push on the head writing path over base, with 30 creations of labels from rooted beside it, which put its list
// under changes_root. The version it committed at.
func (self *pushFixture) presentTestRootedWrite(path sidecar.EvsTokenPath, base uint64, rooted string) uint64 {
	self.t.Helper()
	plan := self.plan()
	plan.Changes = append(plan.Changes, self.check.change(plan, path, base, base+1))
	for _, label := range readTestLabels(rooted) {
		self.create(plan, label)
	}
	if built := self.built(plan); len(built.Statement.Push.GetChangesRoot()) == 0 || len(built.Parts) != 0 {
		self.t.Fatal("a write whose list is inline or in parts")
	}
	version := self.requireCommitted(self.push(plan), plan.BaseVersion+1).GetVersion()
	self.awaitStepEights()
	return version
}

// 70 versions, a fold, the collection of the markers of labels' paths, and 60 more versions: the head at 133 with its
// window from 64, so a removal at 3 or below has left the window and evs holds nothing of those paths (QD-979).
func (self *pushFixture) presentTestPageOut(removed uint64, labels ...[]string) {
	self.t.Helper()
	self.commitOthers("n", 70)
	self.foldRef()
	for _, pathLabels := range labels {
		self.deleteEntry(pathLabels...)
	}
	self.commitOthers("m", 60)
	head := self.head().Head
	if removed != 3 || head.GetVersion() != 133 || head.GetFoldedThrough() != 73 || EvsHeadWindowFirstVersion(head) != 64 {
		self.t.Fatalf("removed at %d, head %d folded through %d, the window from %d", removed, head.GetVersion(), head.GetFoldedThrough(), EvsHeadWindowFirstVersion(head))
	}
}

// The presents of reply's absences, by the version of their statement and their token path.
func presentTestPresents(t *testing.T, pathReply *protocol.EvsReadPathReply) map[uint64]sidecar.EvsTokenPath {
	t.Helper()
	presents := map[uint64]sidecar.EvsTokenPath{}
	for _, absence := range pathReply.GetAbsences() {
		if len(absence.GetPresent()) == 0 {
			continue
		}
		absencePath, err := sidecar.ParseEvsTokenPath(absence.GetTokenPath())
		if err != nil || len(absence.GetBelow()) != 0 || len(absence.GetAbove()) != 0 {
			t.Fatalf("a present %v: %v", absence, err)
		}
		if _, ok := presents[absence.GetVersion()]; ok {
			t.Fatalf("two presents at %d", absence.GetVersion())
		}
		presents[absence.GetVersion()] = absencePath
	}
	return presents
}

// reply with its one path's absences that carry a present left out, those of the statement at version alone or with
// version 0 all of them, as evs sent it before QD-1043.
func presentTestWithout(reply *readTestReply, version uint64) *readTestReply {
	stripped := *reply
	pathReply := proto.Clone(reply.paths[0]).(*protocol.EvsReadPathReply)
	pathReply.Absences = nil
	for _, absence := range reply.paths[0].GetAbsences() {
		if len(absence.GetPresent()) != 0 && (version == 0 || absence.GetVersion() == version) {
			continue
		}
		pathReply.Absences = append(pathReply.Absences, absence)
	}
	stripped.paths = []*protocol.EvsReadPathReply{pathReply}
	return &stripped
}

// x.txt written inline at 1, written again at 2 and removed at 3 by statements whose lists are under changes_root,
// then paged out (presentTestPageOut). evs serves x.txt plain absent with behind to readers pinned at 0 to 3, and in
// the absences of 2 and 3, where the pin is below them, the presents of x.txt's own write and its own removal. The
// client's reader, paging the log, verifies x.txt absent by the walked removal at 3, x.txt's own (E1), with no alarm;
// without the presents, as evs sent before, it refuses the reply with no alarm where its walk holds either statement.
// A reader pinned at the removal walks no change of x.txt. x.txt's creation commits at b + 1, and the absent reply
// in place of the version it reads is refused and alarmed as tampering.
func TestReadAbsentPastAPagedOutRootedRemovalCarriesItsPresents(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	reader := newWalkedTestReader(fixture)
	path := checkTestPath("x.txt")
	chains := [][]byte{nil}
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "x.txt")
	chains = append(chains, fixture.head().Head.GetChain())
	written := fixture.presentTestRootedWrite(path, 1, "w")
	chains = append(chains, fixture.head().Head.GetChain())
	removed := fixture.walkedRemove(path, 2, "r")
	chains = append(chains, fixture.head().Head.GetChain())
	if served := fixture.readPath(token, 0, true, path).paths[0].GetRemoval(); served == nil || served.GetRemovalVersion() != removed {
		t.Fatalf("the window's removal %v", served)
	}
	fixture.presentTestPageOut(removed, []string{"x.txt"})
	for pin := uint64(0); pin <= removed; pin += 1 {
		reply := fixture.readPath(token, pin, true, path)
		if !readReplyPlainAbsent(reply.paths[0]) || reply.behind != pin+1 {
			t.Fatalf("pinned at %d: %v, behind %d", pin, reply.paths[0], reply.behind)
		}
		presents := presentTestPresents(t, reply.paths[0])
		want := map[uint64]bool{}
		for _, version := range []uint64{written, removed} {
			if pin < version {
				want[version] = true
			}
		}
		if len(presents) != len(want) {
			t.Fatalf("pinned at %d: presents at %v, want %v", pin, presents, want)
		}
		for version, presentPath := range presents {
			if !want[version] || !presentPath.Equal(path) {
				t.Fatalf("pinned at %d: a present of %v at %d", pin, presentPath, version)
			}
		}
		verified, err := reader.verify(reply, pin, chains[pin], pin, path)
		if err != nil || !verified.Absent {
			t.Fatalf("pinned at %d: the reader's check: %+v %v", pin, verified, err)
		}
		walked := verified.WalkedRemoval
		if pin == removed {
			if walked != nil || verified.Floor != 0 {
				t.Fatalf("pinned at the removal: a walked removal %+v, floor %d", walked, verified.Floor)
			}
			continue
		}
		if walked == nil || walked.CommitVersion != removed || !walked.ChangePath.Equal(path) || len(walked.Change.GetEntrySha256()) != 0 ||
			walked.Change.GetBaseEntryVersion() != 2 {
			t.Fatalf("pinned at %d: the walked removal %+v, not x.txt's at %d", pin, walked, removed)
		}
		// E1: the removal's statement, verified by its present, names x.txt's token path in epoch 1
		if verified.Floor != 1 {
			t.Fatalf("pinned at %d: floor %d after the walked removal", pin, verified.Floor)
		}
		// as evs sent before: no proof of what the rooted statements did to x.txt, refused with no alarm
		if _, err := reader.verify(presentTestWithout(reply, 0), pin, chains[pin], pin, path); !errors.Is(err, sidecar.ErrEvsEntryRefused) {
			t.Fatalf("pinned at %d: no presents: %v", pin, err)
		}
	}
	if alarms := reader.raised(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	// created again at max(b, m) + 1 with no m: b + 1
	head := fixture.head().Head
	absent := fixture.readPath(token, 2, true, path).paths[0]
	_, created := fixture.commitChange(path, 0, 0, 0)
	reply := fixture.readPath(token, 2, true, path)
	requireVersionProven(t, reply, reply.paths[0], path)
	verified, err := reader.verify(reply, 2, chains[2], 2, path)
	if err != nil || created != head.GetVersion()+1 || verified.CommitVersion != created || verified.Entry.GetVersion() != head.GetVersion()+1 {
		t.Fatalf("the creation at %d: %+v %v", created, verified, err)
	}
	reply.paths[0] = absent
	if _, err := reader.verify(reply, 2, chains[2], 2, path); !errors.Is(err, sidecar.ErrEvsEntryRefused) {
		t.Fatalf("absent served over the creation: %v", err)
	}
	if alarms := reader.raised(); len(alarms) != 1 || alarms[0] != sidecar.SidecarEvsAlarmTamper {
		t.Errorf("alarms %v", alarms)
	}
}

// The same through a prefix: d holding d/a.txt created inline at 1, d/a.txt written again at 2 and d removed at 3 by
// statements whose lists are under changes_root, then paged out with both markers collected. evs serves d/a.txt plain
// absent, with the present of its own write in 2's absences, d/a.txt's adjacent leaves and the present of d's removal
// in 3's, and the client's reader verifies it absent by d's walked removal, with no alarm. Without d's removal's
// present, as evs sent before, a reader whose walk holds a write of d/a.txt can neither count the removal nor rule it
// out, and refuses the reply with no alarm. d and d/a.txt are created again at b + 1, and the absent reply in place of
// d/a.txt's version is refused and alarmed as tampering.
func TestReadAbsentPastAPagedOutRootedPrefixRemovalCarriesItsPresent(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	reader := newWalkedTestReader(fixture)
	directory, file := walkedTestPaths()
	chains := [][]byte{nil}
	fixture.walkedCreate(0, 0, false)
	chains = append(chains, fixture.head().Head.GetChain())
	written := fixture.presentTestRootedWrite(file, 1, "w")
	chains = append(chains, fixture.head().Head.GetChain())
	removed := fixture.walkedRemove(directory, 1, "r")
	chains = append(chains, fixture.head().Head.GetChain())
	fixture.presentTestPageOut(removed, []string{"d"}, []string{"d", "a.txt"})
	for pin := uint64(0); pin <= removed; pin += 1 {
		reply := fixture.readPath(token, pin, true, file)
		if !readReplyPlainAbsent(reply.paths[0]) || reply.behind != pin+1 {
			t.Fatalf("pinned at %d: %v, behind %d", pin, reply.paths[0], reply.behind)
		}
		presents := presentTestPresents(t, reply.paths[0])
		want := map[uint64]sidecar.EvsTokenPath{}
		if pin < written {
			want[written] = file
		}
		if pin < removed {
			want[removed] = directory
		}
		if len(presents) != len(want) {
			t.Fatalf("pinned at %d: presents at %v, want %v", pin, presents, want)
		}
		for version, presentPath := range presents {
			if !presentPath.Equal(want[version]) {
				t.Fatalf("pinned at %d: a present of %v at %d", pin, presentPath, version)
			}
		}
		verified, err := reader.verify(reply, pin, chains[pin], pin, file)
		if err != nil || !verified.Absent {
			t.Fatalf("pinned at %d: the reader's check: %+v %v", pin, verified, err)
		}
		walked := verified.WalkedRemoval
		if pin == removed {
			if walked != nil {
				t.Fatalf("pinned at the removal: a walked removal %+v", walked)
			}
			continue
		}
		if walked == nil || walked.CommitVersion != removed || !walked.ChangePath.Equal(directory) || len(walked.Change.GetEntrySha256()) != 0 {
			t.Fatalf("pinned at %d: the walked removal %+v, not d's at %d", pin, walked, removed)
		}
		if pin < written {
			// the write of d/a.txt walked, and d's removal after it shown by nothing: refused, with no alarm
			if _, err := reader.verify(presentTestWithout(reply, removed), pin, chains[pin], pin, file); !errors.Is(err, sidecar.ErrEvsEntryRefused) {
				t.Fatalf("pinned at %d: no present of d's removal: %v", pin, err)
			}
		}
	}
	if alarms := reader.raised(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	// created again at max(b, m) + 1 with no m: b + 1, d and d/a.txt alike
	head := fixture.head().Head
	absent := fixture.readPath(token, 2, true, file).paths[0]
	created := fixture.walkedCreate(0, 0, false)
	reply := fixture.readPath(token, 2, true, file)
	requireVersionProven(t, reply, reply.paths[0], file)
	verified, err := reader.verify(reply, 2, chains[2], 2, file)
	if err != nil || created != head.GetVersion()+1 || verified.CommitVersion != created || verified.Entry.GetVersion() != head.GetVersion()+1 {
		t.Fatalf("the creation at %d: %+v %v", created, verified, err)
	}
	reply.paths[0] = absent
	if _, err := reader.verify(reply, 2, chains[2], 2, file); !errors.Is(err, sidecar.ErrEvsEntryRefused) {
		t.Fatalf("absent served over the creation: %v", err)
	}
	if alarms := reader.raised(); len(alarms) != 1 || alarms[0] != sidecar.SidecarEvsAlarmTamper {
		t.Errorf("alarms %v", alarms)
	}
}
