// QD-1041 (question evs-absent-walked-removal-past-catch-up, option 1) on the stand-in evs (evs_world_test.go): a
// reader whose read re-pins at the head past EvsSettings.CatchUpByteCount, the gap passing a path's record, takes that
// path served plain absent with no alarm and drops its record, so it reads as a never-read path does (Q-EVS-6); a
// version served below the record is refused and alarmed, gap or not; and a record pinned inside the window the gap
// walks keeps the records' rule (finishRead).

package sidecar

import (
	"context"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Has world serve each of paths plain absent, as evs does once a collection took a removal's marker and the window
// paged the removal out, or as an evs hiding a standing path would. The pushes these tests make list their changes
// inline, so there is no absence to send.
func evsGapTestServeAbsent(world *evsTestWorld, paths ...string) {
	tokenPaths := []EvsTokenPath{}
	for _, path := range paths {
		tokenPaths = append(tokenPaths, world.tokens(path))
	}
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		replyPath, err := ParseEvsChangedTokenPath(reply.GetTokenPath())
		if err != nil || !slices.ContainsFunc(tokenPaths, replyPath.Equal) {
			return
		}
		reply.Version, reply.Removal, reply.Base, reply.Statement, reply.Proof = nil, nil, nil, nil, nil
		reply.Names, reply.NamesThrough, reply.Deltas, reply.DeltaProofs, reply.Absences = nil, 0, nil, nil, nil
	}
}

// The record reader holds of path, nil for none.
func evsGapTestRecord(t *testing.T, reader *evsTestClient, world *evsTestWorld, path string) *EvsReadRecord {
	t.Helper()
	record, ok, err := reader.client.pins.ReadRecord(world.repoId, world.refId, path)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		return nil
	}
	return record
}

// x.txt written at 1, which a reader reads, holding its record at 1; removed at 2; then 40 versions, the window
// holding the last 4. Past the reader's catch-up budget its read of x.txt re-pins at the head with the gap marked, and
// its walk, the window's statements alone, holds no removal of x.txt. evs serves x.txt plain absent, as it does once
// the removal was collected and paged out: the reader takes it absent with no alarm and drops its record, where before
// QD-1041 it refused the read with the tamper alarm on an honest evs. The next read of x.txt, from the head, pages no
// log and gaps no more.
func TestEvsGapHeadTakesARecordedPathServedAbsentAndDropsItsRecord(t *testing.T) {
	world := newEvsTestWorld(t)
	world.window = 4
	world.push(&evsTestChange{path: "x.txt", content: []byte("first")})
	reader := world.reader(t, evsTestId("reader"))
	if content, _, err := evsTestRead(t, reader, world, "x.txt"); err != nil || string(content) != "first" {
		t.Fatalf("x.txt at 1: %q %v", content, err)
	}
	if record := evsGapTestRecord(t, reader, world, "x.txt"); record == nil || record.EntryVersion != 1 || record.PinVersion != 1 {
		t.Fatalf("x.txt's record %+v", record)
	}
	world.push(&evsTestChange{path: "x.txt"})
	evsTestPushOthers(world, "f", 40)
	head, _ := world.head()
	reader.client.settings.CatchUpByteCount = 2 * 1024
	evsTestServeAbsent(world, "x.txt", false)
	pages := world.logPageCount
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("x.txt served absent past the gap: %v", err)
	}
	evsTestRequireNoAlarm(t, "past the gap", reader)
	since := reader.client.Repo(world.repoId).VerifiedSince(world.refId)
	if world.logPageCount == pages || since.IsZero() || len(reader.eventsOf(SidecarEventEvsGap)) != 1 {
		t.Fatalf("%d log pages, verified since %v, gap events %v: no gap", world.logPageCount-pages, since, reader.eventsOf(SidecarEventEvsGap))
	}
	if pin, ok, _ := reader.client.pins.Pin(world.repoId, world.refId); !ok || pin.Version != head {
		t.Fatalf("pin %+v, not the head %d", pin, head)
	}
	if record := evsGapTestRecord(t, reader, world, "x.txt"); record != nil {
		t.Fatalf("x.txt's record kept past the gap: %+v", record)
	}
	pages = world.logPageCount
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("x.txt read again: %v", err)
	}
	if world.logPageCount != pages || len(reader.eventsOf(SidecarEventEvsGap)) != 1 {
		t.Fatalf("x.txt read again from the head: %d log pages, gap events %v", world.logPageCount-pages, reader.eventsOf(SidecarEventEvsGap))
	}
	evsTestRequireNoAlarm(t, "read again", reader)
}

// a.txt written at 1 and 2, which a reader reads at 2; then 40 versions, the window holding the last 4. Past the
// reader's catch-up budget, evs serving a.txt at 1 is refused with the tamper alarm, gap or not, the pin and the record
// left where they were; served honestly, a.txt reads at 2 on the gap head, its record raised to it.
func TestEvsGapHeadStillRefusesAVersionBelowTheRecord(t *testing.T) {
	world := newEvsTestWorld(t)
	world.window = 4
	world.push(&evsTestChange{path: "a.txt", content: []byte("v1")})
	world.push(&evsTestChange{path: "a.txt", content: []byte("v2")})
	reader := world.reader(t, evsTestId("reader"))
	if content, _, err := evsTestRead(t, reader, world, "a.txt"); err != nil || string(content) != "v2" {
		t.Fatalf("a.txt at 2: %q %v", content, err)
	}
	evsTestPushOthers(world, "f", 40)
	head, _ := world.head()
	reader.client.settings.CatchUpByteCount = 2 * 1024
	world.stateLock.Lock()
	world.serveVersion["a.txt"] = 1
	world.stateLock.Unlock()
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("a.txt below its record past the gap: %v", err)
	}
	evsTestRequireTamper(t, "below the record past the gap", reader, 1)
	if pin, ok, _ := reader.client.pins.Pin(world.repoId, world.refId); !ok || pin.Version != 2 {
		t.Fatalf("pin %+v moved by a refused read", pin)
	}
	if record := evsGapTestRecord(t, reader, world, "a.txt"); record == nil || record.EntryVersion != 2 || record.PinVersion != 2 {
		t.Fatalf("a.txt's record %+v after the refusal", record)
	}
	world.stateLock.Lock()
	world.serveVersion = map[string]uint64{}
	world.stateLock.Unlock()
	if content, _, err := evsTestRead(t, reader, world, "a.txt"); err != nil || string(content) != "v2" {
		t.Fatalf("the honest read past the gap: %q %v", content, err)
	}
	if len(reader.eventsOf(SidecarEventEvsGap)) != 1 {
		t.Fatalf("gap events %v", reader.eventsOf(SidecarEventEvsGap))
	}
	if record := evsGapTestRecord(t, reader, world, "a.txt"); record == nil || record.EntryVersion != 2 || record.PinVersion != head {
		t.Fatalf("a.txt's record %+v, not raised to the head %d", record, head)
	}
	evsTestRequireTamper(t, "the honest read", reader, 1)
}

// A record the gap's walk covers keeps the records' rule. x.txt written at 1, read, and removed at 2; 40 versions;
// y.txt written at 43 and read at 43; two versions more, the window holding the last 4, from 42. One read of both
// starts from x.txt's record at 1 and re-pins past the budget, walking the window alone: x.txt, served absent, is
// passed by the gap, but y.txt's record lies inside the walk, which holds every statement after it and no removal of
// y.txt, so y.txt served absent is refused with the tamper alarm and neither record moves. Read alone, x.txt reads
// absent and its record goes.
func TestEvsGapHeadKeepsTheRuleForARecordItsWalkCovers(t *testing.T) {
	world := newEvsTestWorld(t)
	world.window = 4
	world.push(&evsTestChange{path: "x.txt", content: []byte("x")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); err != nil {
		t.Fatal(err)
	}
	world.push(&evsTestChange{path: "x.txt"})
	evsTestPushOthers(world, "f", 40)
	world.push(&evsTestChange{path: "y.txt", content: []byte("y")})
	if content, _, err := evsTestRead(t, reader, world, "y.txt"); err != nil || string(content) != "y" {
		t.Fatalf("y.txt: %q %v", content, err)
	}
	written, _ := world.head()
	if record := evsGapTestRecord(t, reader, world, "y.txt"); record == nil || record.PinVersion != written {
		t.Fatalf("y.txt's record %+v, not at %d", record, written)
	}
	evsTestPushOthers(world, "g", 2)
	reader.client.settings.CatchUpByteCount = 2 * 1024
	evsGapTestServeAbsent(world, "x.txt", "y.txt")
	result, err := reader.client.Repo(world.repoId).read(context.Background(), world.refId, []string{"x.txt", "y.txt"}, 0, false)
	if err == nil {
		result.objects.close()
	}
	if !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("y.txt served absent inside the walk: %v", err)
	}
	evsTestRequireTamper(t, "y.txt inside the walk", reader, 1)
	if record := evsGapTestRecord(t, reader, world, "x.txt"); record == nil || record.PinVersion != 1 {
		t.Fatalf("x.txt's record %+v after the refused read", record)
	}
	if record := evsGapTestRecord(t, reader, world, "y.txt"); record == nil || record.PinVersion != written {
		t.Fatalf("y.txt's record %+v after the refused read", record)
	}
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("x.txt alone past the gap: %v", err)
	}
	if record := evsGapTestRecord(t, reader, world, "x.txt"); record != nil {
		t.Fatalf("x.txt's record kept past the gap: %+v", record)
	}
	evsTestRequireTamper(t, "x.txt alone", reader, 1)
}

// The gap's walk as the reader keeps it: the window's statements, the first after FromVersion, which the records'
// rule compares a record's pin with.
func TestEvsGapHeadWalksTheWindowFromItsFirstStatement(t *testing.T) {
	world := newEvsTestWorld(t)
	world.window = 4
	world.push(&evsTestChange{path: "x.txt", content: []byte("x")})
	reader := world.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, world, "x.txt"); err != nil {
		t.Fatal(err)
	}
	evsTestPushOthers(world, "f", 40)
	head, _ := world.head()
	reader.client.settings.CatchUpByteCount = 2 * 1024
	world.stateLock.Lock()
	statements := []*protocol.EvsReadStatement{}
	for version := head - 3; version <= head; version += 1 {
		statements = append(statements, &protocol.EvsReadStatement{Version: version, Statement: world.commits[version-1].statement})
	}
	summary := proto.Clone(world.headSummaryWithLock()).(*protocol.EvsHeadSummary)
	world.stateLock.Unlock()
	verified, err := reader.client.verifier.VerifyHead(context.Background(), &EvsHeadRead{
		RepoId: world.repoId, RefId: world.refId, Head: summary, FromVersion: 1, FromChain: world.commits[0].chain,
		Statements: statements, Behind: 2,
	})
	if err != nil || !verified.Gap || verified.FromVersion != head-4 || len(verified.Statements) != 4 {
		t.Fatalf("the gap head %+v %v", verified, err)
	}
}
