// QD-1055 (question absent-walked-removal-followups-gap-removal-record, option 1) beyond the path's own removal, on the
// stand-in evs (evs_world_test.go): a gap head that passed a record's pin drops it for a path served a prefix's
// removal too, as finishRead's "its own or a prefix's" says; and once the record is gone a later version of the path
// is held to the walk from the ref's pin alone, as a never-read path's is (Q-EVS-6): a removal served over a creation
// the walk holds is still refused and alarmed, and the creation, served honestly, reads with a new record and no
// second gap.

package sidecar

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Has world serve path as removal, with its statement and nothing else, as evs answers a path from the marker its
// fold wrote: for a prefix's removal, on every entry below the prefix (evsservice's fold.go), which the stand-in,
// serving a child its own last version, does not.
func evsGapRemovalTestServeRemoval(world *evsTestWorld, path string, removal *protocol.EvsRemovalMarker, statement []byte) {
	tokenPath := world.tokens(path)
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		replyPath, err := ParseEvsChangedTokenPath(reply.GetTokenPath())
		if err != nil || !replyPath.Equal(tokenPath) {
			return
		}
		// the statement always: the reader takes the walked one where it holds the version
		reply.Version, reply.Removal, reply.Base, reply.Statement, reply.Proof = nil, removal, nil, statement, nil
		reply.Names, reply.NamesThrough, reply.Deltas, reply.DeltaProofs, reply.Absences = nil, 0, nil, nil, nil
	}
}

// The removal world holds standing on path, and the statement of the push that made it.
func evsGapRemovalTestMarker(t *testing.T, world *evsTestWorld, path string) (*protocol.EvsRemovalMarker, []byte) {
	t.Helper()
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	state := world.paths[path]
	if state == nil || state.removal == nil {
		t.Fatalf("%s holds no removal", path)
	}
	return state.removal, world.commits[state.removal.GetRemovalVersion()-1].statement
}

// d holding d/a.txt, written at 1, which a reader reads, holding d/a.txt's record at 1; 40 versions; d removed at 42;
// two versions more, the window holding the last 4, from 41; evs serving d/a.txt d's removal. Past the reader's
// catch-up budget its read of d/a.txt re-pins at the head with the gap marked, and the walk holds d's removal: the
// reader takes it with no alarm and drops the record, whose pin the gap passed, so the next read of d/a.txt starts
// from the head, paging no log and gapping no more.
func TestEvsGapHeadDropsTheRecordOfAPathServedItsPrefixsRemoval(t *testing.T) {
	world := newEvsTestWorld(t)
	world.window = 4
	world.push(&evsTestChange{path: "d", children: []string{"a.txt"}}, &evsTestChange{path: "d/a.txt", content: []byte("a")})
	reader := world.reader(t, evsTestId("reader"))
	if content, _, err := evsTestRead(t, reader, world, "d/a.txt"); err != nil || string(content) != "a" {
		t.Fatalf("d/a.txt at 1: %q %v", content, err)
	}
	if record := evsGapTestRecord(t, reader, world, "d/a.txt"); record == nil || record.EntryVersion != 1 || record.PinVersion != 1 {
		t.Fatalf("d/a.txt's record %+v", record)
	}
	evsTestPushOthers(world, "f", 40)
	removed := world.push(&evsTestChange{path: "d"})
	evsTestPushOthers(world, "g", 2)
	head, _ := world.head()
	removal, statement := evsGapRemovalTestMarker(t, world, "d")
	evsGapRemovalTestServeRemoval(world, "d/a.txt", removal, statement)
	reader.client.settings.CatchUpByteCount = 2 * 1024
	pages := world.logPageCount
	if _, _, err := evsTestRead(t, reader, world, "d/a.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("d's removal at %d past the gap: %v", removed, err)
	}
	if world.logPageCount == pages || len(reader.eventsOf(SidecarEventEvsGap)) != 1 {
		t.Fatalf("%d log pages, gap events %v: no gap", world.logPageCount-pages, reader.eventsOf(SidecarEventEvsGap))
	}
	if pin, ok, _ := reader.client.pins.Pin(world.repoId, world.refId); !ok || pin.Version != head {
		t.Fatalf("pin %+v, not the head %d", pin, head)
	}
	if record := evsGapTestRecord(t, reader, world, "d/a.txt"); record != nil {
		t.Fatalf("d/a.txt's record kept past the gap: %+v", record)
	}
	pages = world.logPageCount
	if _, _, err := evsTestRead(t, reader, world, "d/a.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("d/a.txt read again: %v", err)
	}
	if world.logPageCount != pages || len(reader.eventsOf(SidecarEventEvsGap)) != 1 {
		t.Fatalf("d/a.txt read again: %d log pages, gap events %v", world.logPageCount-pages, reader.eventsOf(SidecarEventEvsGap))
	}
	evsTestRequireNoAlarm(t, "d's removal past the gap", reader)
}

// x.txt written at 1, which a reader reads; 40 versions; x.txt removed at 42; two versions more, the window from 41.
// The reader's read past its budget drops x.txt's record at the gap head, 44, and x.txt is then created again at 45.
// An evs serving the old removal over that creation is refused with the tamper alarm, since the walk from the ref's
// pin holds the creation, and the pin stays; served honestly, x.txt reads at 45 and its record is raised there, with
// no log paged and no second gap.
func TestEvsGapHeadDroppedRecordLeavesALaterVersionToTheWalk(t *testing.T) {
	world := newEvsTestWorld(t)
	world.window = 4
	world.push(&evsTestChange{path: "x.txt", content: []byte("first")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); err != nil {
		t.Fatal(err)
	}
	evsTestPushOthers(world, "f", 40)
	removed := world.push(&evsTestChange{path: "x.txt"})
	evsTestPushOthers(world, "g", 2)
	gapHead, _ := world.head()
	removal, statement := evsGapRemovalTestMarker(t, world, "x.txt")
	reader.client.settings.CatchUpByteCount = 2 * 1024
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("x.txt's removal at %d past the gap: %v", removed, err)
	}
	if record := evsGapTestRecord(t, reader, world, "x.txt"); record != nil || len(reader.eventsOf(SidecarEventEvsGap)) != 1 {
		t.Fatalf("x.txt's record %+v, gap events %v", record, reader.eventsOf(SidecarEventEvsGap))
	}
	created := world.push(&evsTestChange{path: "x.txt", content: []byte("again")})
	pages := world.logPageCount

	evsGapRemovalTestServeRemoval(world, "x.txt", removal, statement)
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("x.txt's removal at %d served over its creation at %d: %v", removed, created, err)
	}
	evsTestRequireTamper(t, "the removal over the creation", reader, 1)
	if pin, ok, _ := reader.client.pins.Pin(world.repoId, world.refId); !ok || pin.Version != gapHead {
		t.Fatalf("pin %+v moved by a refused read, not at %d", pin, gapHead)
	}
	if record := evsGapTestRecord(t, reader, world, "x.txt"); record != nil {
		t.Fatalf("x.txt's record %+v raised by a refused read", record)
	}

	world.stateLock.Lock()
	world.mutatePath = nil
	world.stateLock.Unlock()
	content, info, err := evsTestRead(t, reader, world, "x.txt")
	if err != nil || string(content) != "again" || info.Version != created || info.CommitVersion != created {
		t.Fatalf("x.txt created again at %d: %q %+v %v", created, content, info, err)
	}
	if record := evsGapTestRecord(t, reader, world, "x.txt"); record == nil || record.EntryVersion != created || record.PinVersion != created {
		t.Fatalf("x.txt's record %+v, not at %d", record, created)
	}
	if world.logPageCount != pages || len(reader.eventsOf(SidecarEventEvsGap)) != 1 {
		t.Fatalf("after the gap: %d log pages, gap events %v", world.logPageCount-pages, reader.eventsOf(SidecarEventEvsGap))
	}
	evsTestRequireTamper(t, "the honest read", reader, 1)
}
