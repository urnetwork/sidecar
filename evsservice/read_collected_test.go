// `collected` on the read route (EVS2-M10-08; FS-64's and FS-66's read clauses, plan-EVS2-small-readings#5): the
// minute rule on a fake clock across a minute boundary, a kept version, a removal, observe mode, and an unsure clock.

package evsservice

import (
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Commits path as a versionless file at version on base, its one record a staged segment of the push, which must
// commit at want: the staged segment's bytes and id.
func (self *pushFixture) commitStaged(path sidecar.EvsTokenPath, base uint64, version uint64, label string, want uint64) ([]byte, [32]byte) {
	self.t.Helper()
	token := self.token(self.check.signerId)
	plan := self.plan()
	segment, staged := checkTestStaged(self.t, plan, label)
	plan.NewObjects = append(plan.NewObjects, staged.NewObject())
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: path, BaseEntryVersion: base,
		EntryVersion: self.check.versionedEntry(plan, version, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(staged.Id, true)),
	})
	self.requireCommitted(self.post(token, self.bodyStaged(plan, [][]byte{segment})), want)
	self.awaitStepEights()
	return segment, staged.Id
}

// A read of path at version (0 the newest) pinned at the head, with ranges beside it, under a token minted now, since
// a test's clock moves past a token's life.
func (self *pushFixture) readVersion(path sidecar.EvsTokenPath, version uint64, ranges ...*protocol.EvsReadRange) *readTestReply {
	self.t.Helper()
	return self.read(self.token(self.check.signerId), &protocol.EvsReadRequest{
		RefId: self.check.refId.Bytes(), PinVersion: self.head().Version(),
		Paths:  []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: path.Components()}}, Version: version}},
		Ranges: ranges,
	})
}

// From when a version the push at commitVersion replaced reads `collected`, by that push's window place.
func (self *pushFixture) collectedFrom(commitVersion uint64) time.Time {
	self.t.Helper()
	entry := windowEntryAt(self.head().Head, commitVersion)
	if entry == nil {
		self.t.Fatalf("version %d is not in the window", commitVersion)
	}
	return collectedFrom(entry.Place, self.settings.ReadCollectedAfter)
}

// Moves the fixture's clock to at.
func (self *pushFixture) clockTo(at time.Time) {
	self.t.Helper()
	self.clock.Advance(at.Sub(self.clock.Now()))
}

// FS-64's read clauses on evs: a replaced versionless version reads as any older version until T, the end of the
// replacing record's minute plus 60 s, and `collected` from T on, with its signed entry version, statement and proof;
// the head read is unchanged throughout.
func TestReadAnswersCollectedFromTheMinuteRule(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	path := checkTestPath("big")
	fixture.commitStaged(path, 0, 1, "one", 1)
	// 20 s into a minute, so the replacement's minute ends 40 s later and T is 100 s after the commit
	fixture.clockTo(fixture.clock.Now().Truncate(time.Minute).Add(time.Minute + 20*time.Second))
	committed := fixture.clock.Now()
	fixture.commitStaged(path, 1, 2, "two", 2)
	from := fixture.collectedFrom(2)
	if wait := from.Sub(committed); wait != 100*time.Second {
		t.Fatalf("T is %s after the commit, want the minute's end plus 60 s", wait)
	}

	older := func() *protocol.EvsReadPathReply {
		t.Helper()
		reply := fixture.readVersion(path, 1)
		pathReply := reply.paths[0]
		if pathReply.GetVersion().GetCommitVersion() != 1 {
			t.Fatalf("version 1 answered %v", pathReply.GetVersion())
		}
		// collected or not, the version is proven as any other
		requireVersionProven(t, reply, pathReply, path)
		return pathReply
	}
	if state := older().GetState(); state != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("a version replaced just now reads %s", state)
	}
	// across the minute boundary and up to the last instant before T
	fixture.clockTo(committed.Add(60 * time.Second))
	if state := older().GetState(); state != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("60 s after the commit, inside the allowance, it reads %s", state)
	}
	fixture.clockTo(from.Add(-time.Millisecond))
	if state := older().GetState(); state != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("a millisecond before T it reads %s", state)
	}
	fixture.clockTo(from)
	if state := older().GetState(); state != protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED {
		t.Fatalf("at T it reads %s", state)
	}
	fixture.clockTo(from.Add(48 * time.Hour))
	if state := older().GetState(); state != protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED {
		t.Fatalf("long after T it reads %s", state)
	}

	// the head read is unchanged: the newest version, no state
	newest := fixture.readVersion(path, 0).paths[0]
	if newest.GetVersion().GetCommitVersion() != 2 || newest.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("the newest version: %v state %s", newest.GetVersion(), newest.GetState())
	}
	// and the newest asked for by its own number is the newest still
	byNumber := fixture.readVersion(path, 2).paths[0]
	if byNumber.GetVersion().GetCommitVersion() != 2 || byNumber.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("the newest version by number: %v state %s", byNumber.GetVersion(), byNumber.GetState())
	}
}

// A kept version is never collected, however long ago it was replaced, and a kept version that a versionless one
// replaced is not either: the rule reads the replaced version's own versioning.
func TestReadNeverCollectsAKeptVersion(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	path := checkTestPath("kept")
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "kept")
	write := fixture.plan()
	write.Changes = append(write.Changes, fixture.check.change(write, path, 1, 2))
	fixture.requireCommitted(fixture.push(write), 2)
	fixture.awaitStepEights()
	fixture.commitStaged(path, 2, 3, "now versionless", 3)
	fixture.clockTo(fixture.clock.Now().Add(72 * time.Hour))
	for version := uint64(1); version <= 2; version += 1 {
		pathReply := fixture.readVersion(path, version).paths[0]
		if pathReply.GetVersion().GetCommitVersion() != version || pathReply.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
			t.Fatalf("kept version %d: %v state %s", version, pathReply.GetVersion(), pathReply.GetState())
		}
	}
}

// A versionless path's removal replaces its last version as a write does: that version reads `collected` from the
// removing record's T.
func TestReadAnswersCollectedAfterARemoval(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	token := fixture.token(fixture.check.signerId)
	path := checkTestPath("gone")
	fixture.commitStaged(path, 0, 1, "one", 1)
	remove := fixture.plan()
	remove.Changes = append(remove.Changes, &sidecar.EvsPlannedChange{TokenPath: path, BaseEntryVersion: 1})
	fixture.requireCommitted(fixture.post(token, fixture.bodyFormat2(remove)), 2)
	fixture.awaitStepEights()
	from := fixture.collectedFrom(2)
	fixture.clockTo(from.Add(-time.Second))
	if state := fixture.readVersion(path, 1).paths[0].GetState(); state != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("before the removal's T it reads %s", state)
	}
	fixture.clockTo(from)
	pathReply := fixture.readVersion(path, 1).paths[0]
	if pathReply.GetVersion().GetCommitVersion() != 1 || pathReply.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED {
		t.Fatalf("at the removal's T: %v state %s", pathReply.GetVersion(), pathReply.GetState())
	}
	// the head read answers the removal, with no state
	removed := fixture.readVersion(path, 0).paths[0]
	if removed.GetRemoval() == nil || removed.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("the removed path: %v state %s", removed.GetRemoval(), removed.GetState())
	}
}

// A version replaced several times over reads `collected` from its own replacement's T, not the newest write's: the
// version after it, still inside its allowance, reads as served.
func TestReadCollectsEachVersionByItsOwnReplacement(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	path := checkTestPath("busy")
	fixture.commitStaged(path, 0, 1, "one", 1)
	fixture.commitStaged(path, 1, 2, "two", 2)
	firstFrom := fixture.collectedFrom(2)
	fixture.clockTo(firstFrom.Add(time.Hour))
	fixture.commitStaged(path, 2, 3, "three", 3)
	if state := fixture.readVersion(path, 1).paths[0].GetState(); state != protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED {
		t.Fatalf("version 1, replaced an hour ago, reads %s", state)
	}
	if state := fixture.readVersion(path, 2).paths[0].GetState(); state != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("version 2, replaced just now, reads %s", state)
	}
	fixture.clockTo(fixture.collectedFrom(3))
	if state := fixture.readVersion(path, 2).paths[0].GetState(); state != protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED {
		t.Fatalf("version 2 at its own T reads %s", state)
	}
}

// A process whose clock is unsure cannot place itself against T: the read of a replaced versionless version answers
// 503, and reads the rule does not touch are served as before.
func TestReadCollectedNeedsASureClock(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	token := fixture.token(fixture.check.signerId)
	path := checkTestPath("big")
	fixture.commitStaged(path, 0, 1, "one", 1)
	fixture.commitStaged(path, 1, 2, "two", 2)
	pin := fixture.head().Version()
	fixture.host.ClockCheck.SetUnknown()
	request := &protocol.EvsReadRequest{
		RefId: fixture.check.refId.Bytes(), PinVersion: pin,
		Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: path.Components()}}, Version: 1}},
	}
	if recorder := fixture.call(token, http.MethodPost, "/read", request); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("a collected verdict on an unsure clock answered %d", recorder.Code)
	}
	request.Paths[0].Version = 0
	if recorder := fixture.call(token, http.MethodPost, "/read", request); recorder.Code != http.StatusOK {
		t.Fatalf("a head read on an unsure clock answered %d", recorder.Code)
	}
	fixture.host.ClockCheck.SetOffset(0)
	request.Paths[0].Version = 1
	if recorder := fixture.call(token, http.MethodPost, "/read", request); recorder.Code != http.StatusOK {
		t.Fatalf("with the clock sure again the read answered %d", recorder.Code)
	}
}
