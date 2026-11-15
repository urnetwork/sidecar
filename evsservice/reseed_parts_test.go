// QD-818's tests of a re-seeded push in parts at POST .../reseed on T2 (reseed.go, push_seal.go): a ref whose history
// holds a push in parts, written through the push route of a site the test then loses, returns whole from a repo
// admin's mirror through sidecar.EvsRepo.Reseed, its push in parts as an EVS_BATCH_SEAL record naming one
// EVS_BATCH_RESEED record per part, and every reader of a sealed push answers there as it did on the lost site: reads
// and their proofs, the newest rule under later pushes, the sweep's recompute and the fold. A call whose parts are
// not the push's, one per part in order, is refused writing nothing; a reseed record holding a part is refused at a
// place no seal names; a slot returns only under a re-seeded seal; and evacuation keeps a re-seeded part its seal
// names and drops one no seal names.

package evsservice

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A shared file-mode ref a writer filled through the push route of a site the test then loses: a at version 1, a push
// in parts creating 1,100 files at 2, and at 3 a write, on its version 2, of the last file of the push's second part.
// What a mirror holds of it, by version: each statement, and its records as a read serves them, part 0 first.
type reseedPartsHistory struct {
	site       *pushFixture
	statements [][]byte
	records    [][][]byte
	chains     [][32]byte
	// the push in parts as built, and the first and last path of each of its parts, in part order
	built *sidecar.EvsBuiltPush
	paths []sidecar.EvsTokenPath
	// the path version 3 wrote again
	written sidecar.EvsTokenPath
}

func newReseedPartsHistory(t *testing.T) *reseedPartsHistory {
	t.Helper()
	site := newPushFixture(t, nil)
	token := site.token(site.check.signerId)
	history := &reseedPartsHistory{site: site}
	first := site.plan()
	site.create(first, "a")
	site.requireCommitted(site.push(first), 1)
	history.built = site.built(site.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	if len(history.built.Parts) != 2 {
		t.Fatalf("the push in parts holds %d parts, want 2", len(history.built.Parts))
	}
	for i, partBytes := range history.built.Parts {
		checked, err := sidecar.EvsCheckPart(history.built.Statement, partBytes)
		if err != nil || !checked.HoldsChanges() {
			t.Fatalf("part %d: %v", i+1, err)
		}
		history.paths = append(history.paths, checked.Changes[0].TokenPath, checked.Changes[len(checked.Changes)-1].TokenPath)
	}
	site.requireCommitted(site.seal(token, history.built, site.postParts(token, history.built)), 2)
	history.written = history.paths[3]
	third := site.plan()
	third.Changes = append(third.Changes, site.check.change(third, history.written, 2, 3))
	site.requireCommitted(site.push(third), 3)
	site.awaitStepEights()

	head := site.head()
	window, err := EvsHeadWindow(head.Head)
	if err != nil || len(window) != 3 || EvsHeadWindowFirstVersion(head.Head) != 1 {
		t.Fatalf("the lost site's window: %d entries, %v", len(window), err)
	}
	chain := sidecar.EvsChainStart(site.check.repoId, site.check.refId)
	readBytes := func(place *protocol.EvsPlace) []byte {
		t.Helper()
		recordBytes, err := site.engine.readRecordBytesAt(site.ctx, site.cluster, site.check.repoId, site.check.refId, place)
		if err != nil {
			t.Fatal(err)
		}
		return recordBytes
	}
	for _, entry := range window {
		recordBytes := readBytes(entry.Place)
		record, err := sidecar.ParseEvsBatchRecord(recordBytes)
		if err != nil {
			t.Fatal(err)
		}
		statementBytes, err := recordStatementBytes(record)
		if err != nil {
			t.Fatal(err)
		}
		records := [][]byte{recordBytes}
		if record.Type == protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
			_, sealParts, err := sidecar.ParseEvsSealRecordBody(record.Body)
			if err != nil {
				t.Fatal(err)
			}
			for _, sealPart := range sealParts {
				records = append(records, readBytes(sealPart.Place))
			}
		}
		statement, err := sidecar.ParseEvsStatement(statementBytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = sidecar.EvsChainNext(chain, entry.PushId, statement.Sha256)
		history.statements = append(history.statements, statementBytes)
		history.records = append(history.records, records)
		history.chains = append(history.chains, chain)
	}
	if len(history.records[1]) != 3 {
		t.Fatalf("version 2 holds %d records, want its seal and 2 parts", len(history.records[1]))
	}
	return history
}

// The mirror holds each version through through of a ref's history, as the devices' syncs kept them: its statement
// and its records, part 0 first.
func (self *reseedDevice) holdsRecords(refId sidecar.Id, statements [][]byte, records [][][]byte, chains [][32]byte, through uint64) {
	t := self.fixture.t
	t.Helper()
	for version := uint64(1); version <= through; version += 1 {
		statement, err := sidecar.ParseEvsStatement(statements[version-1])
		if err != nil {
			t.Fatal(err)
		}
		if err := self.mirror.Put(sidecar.EvsMirrorStatementKey(refId, version), bytes.NewReader(statement.Bytes)); err != nil {
			t.Fatal(err)
		}
		for part, recordBytes := range records[version-1] {
			key := sidecar.EvsMirrorRecordKey(sidecar.Id(statement.Push.GetPushId()), uint32(part))
			if err := self.mirror.Put(key, bytes.NewReader(recordBytes)); err != nil {
				t.Fatal(err)
			}
		}
	}
	ref := &sidecar.EvsMirrorRef{RefId: refId, Version: through, Chain: chains[through-1], MirroredAt: self.fixture.clock.Now()}
	if err := self.mirror.RaiseRef(ref); err != nil {
		t.Fatal(err)
	}
}

// A push in parts as a mirror kept it: count files created on the fixture's ref, signed a month ago. testId keeps 16
// bytes of a label, so every label here keeps its token's within them.
func (self *reseedFixture) keptParts(count int) *sidecar.EvsPushPlan {
	plan := self.kept()
	for i := 0; i < count; i += 1 {
		self.create(plan, fmt.Sprintf("file-%05d", i))
	}
	return plan
}

// built's reseed call: its statement and every part, in part order.
func reseedPartsBody(built *sidecar.EvsBuiltPush) *protocol.EvsReseedRequest {
	return &protocol.EvsReseedRequest{Statement: built.Statement.Bytes, Parts: built.Parts}
}

// Two read replies of one path answer alike: the same statements after the pin, and the same path frames, version,
// proofs and absences included.
func requireSameRead(t *testing.T, label string, want *readTestReply, got *readTestReply) {
	t.Helper()
	if len(got.statements) != len(want.statements) || len(got.paths) != len(want.paths) || len(got.paths) == 0 {
		t.Fatalf("%s: %d statements and %d paths, want %d and %d", label, len(got.statements), len(got.paths), len(want.statements), len(want.paths))
	}
	for i, statement := range want.statements {
		if !proto.Equal(got.statements[i], statement) {
			t.Fatalf("%s: statement %d differs", label, i)
		}
	}
	for i, path := range want.paths {
		if !proto.Equal(got.paths[i], path) {
			t.Fatalf("%s: path frame %d differs:\n%v\nwant\n%v", label, i, got.paths[i], path)
		}
	}
}

// The sweep's recompute of the list of the push committed at version, as a marked list's is: its candidates and how
// many replaced versions it did not find.
func (self *pushFixture) recomputeAt(version uint64, record *sidecar.EvsBatchRecord) (*protocol.EvsPurgeList, int) {
	self.t.Helper()
	sweep, err := NewSweep(self.host.ServiceHost(), &SweepDeps{EvsSettings: self.settings})
	if err != nil {
		self.t.Fatal(err)
	}
	list, unfound, err := sweep.recompute(self.ctx, self.cluster, &SweepTarget{
		RepoId: self.check.repoId, RefId: self.check.refId, PathEpoch: 1, Record: record, CommitVersion: version,
	})
	if err != nil {
		self.t.Fatalf("the recompute at version %d: %v", version, err)
	}
	return list, unfound
}

// A ref whose history holds a push in parts returns whole from a complete mirror: the device's walk sends version 2
// as its statement and both parts, and evs commits it as an EVS_BATCH_SEAL record naming an EVS_BATCH_RESEED record
// per part, each holding the part the mirror held with no receipt. Every reader of the sealed push answers as the lost
// site did: a read of each part's edge paths, the file version 3 wrote again and a, whose read proves the push in
// parts left it alone from that push's parts; the recompute of version 3's list, which walks back into the push in
// parts; the newest rule, under a write of the rewritten file on its stale version, which conflicts, and of another
// on its version, which commits; and the fold of every version, path by path. A second walk changes nothing.
func TestReseedReturnsARefHoldingAPushInPartsWhole(t *testing.T) {
	history := newReseedPartsHistory(t)
	site := history.site
	fixture := newReseedFixture(t)
	check := fixture.check
	device := fixture.device()
	device.holdsRecords(check.refId, history.statements, history.records, history.chains, 3)
	ref := device.reseed()
	if ref.Stopped != nil || ref.MirrorVersion != 3 || ref.Version != 3 || ref.Chain != history.chains[2] || device.reseedCallCount != 3 {
		t.Fatalf("the walk ended at %d of %d after %d calls, stopped by %v", ref.Version, ref.MirrorVersion, device.reseedCallCount, ref.Stopped)
	}
	head := fixture.head()
	if head.Version() != 3 || !bytes.Equal(head.Head.GetChain(), history.chains[2][:]) || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("head at %d, not the lost site's, with %d bytes of refusals", head.Version(), len(head.Head.GetRefused()))
	}
	for _, version := range []uint64{1, 3} {
		record := fixture.recordAt(check.refId, version)
		if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || sidecar.EvsReseedRecordHoldsPart(record) {
			t.Fatalf("version %d's record is type %s, holding a part %t", version, record.Type, sidecar.EvsReseedRecordHoldsPart(record))
		}
	}
	seal := fixture.recordAt(check.refId, 2)
	statementBytes, sealParts, err := sidecar.ParseEvsSealRecordBody(seal.Body)
	if err != nil || seal.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL || !bytes.Equal(statementBytes, history.statements[1]) || len(sealParts) != 2 {
		t.Fatalf("version 2's record is type %s with %d parts: %v", seal.Type, len(sealParts), err)
	}
	for i, sealPart := range sealParts {
		part, err := fixture.engine.readRecordAt(fixture.ctx, fixture.cluster, check.repoId, check.refId, sealPart.Place)
		if err != nil {
			t.Fatal(err)
		}
		partStatement, partBytes, receipts, checkedVersion, err := sidecar.ParseEvsSealPartRecord(part)
		if err != nil || part.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || part.PushId != seal.PushId {
			t.Fatalf("part %d's record is type %s: %v", i+1, part.Type, err)
		}
		if !bytes.Equal(partStatement, history.statements[1]) || !bytes.Equal(partBytes, history.built.Parts[i]) || len(receipts) != 0 || checkedVersion != 1 {
			t.Fatalf("part %d's record holds other bytes than the mirror's part, %d receipts, checked at %d", i+1, len(receipts), checkedVersion)
		}
	}
	// 5a answers each version where it stands, and nothing is written
	if again := device.reseed(); again.Stopped != nil || again.Version != 3 {
		t.Fatalf("a second walk ended at %d, stopped by %v", again.Version, again.Stopped)
	}
	if after := fixture.head(); after.Etag != head.Etag {
		t.Fatal("a second walk wrote the head")
	}

	// reads and their proofs, path by path
	paths := append([]sidecar.EvsTokenPath{checkTestPath("a")}, history.paths...)
	for i, path := range paths {
		label := fmt.Sprintf("path %d", i)
		lost := site.readPath(site.token(site.check.signerId, "r"), 0, true, path)
		returned := fixture.readPath(fixture.token(check.signerId, "r"), 0, true, path)
		requireSameRead(t, label, lost, returned)
		requireVersionProven(t, returned, returned.paths[0], path)
	}
	if aRead := fixture.readPath(fixture.token(check.signerId, "r"), 0, true, checkTestPath("a")); len(aRead.paths[0].GetAbsences()) == 0 {
		t.Fatal("a's read carries no absence from the push in parts")
	}

	// the sweep's recompute of version 3's list finds the version it replaced in the push in parts
	lostList, lostUnfound := site.recomputeAt(3, site.recordOf(3))
	returnedList, returnedUnfound := fixture.recomputeAt(3, fixture.recordAt(check.refId, 3))
	if lostUnfound != 0 || returnedUnfound != 0 || !proto.Equal(lostList, returnedList) {
		t.Fatalf("the recompute: %d and %d unfound, lists %v and %v", lostUnfound, returnedUnfound, lostList, returnedList)
	}

	// the newest rule under later pushes, on each site
	for _, each := range []*pushFixture{site, fixture.pushFixture} {
		stale := each.plan()
		stale.PushId = testId("stale write")
		stale.Changes = append(stale.Changes, each.check.change(stale, history.written, 2, 3))
		requireRefusal(t, each.push(stale), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
		fresh := each.plan()
		fresh.PushId = testId("fresh write")
		fresh.Changes = append(fresh.Changes, each.check.change(fresh, history.paths[0], 2, 3))
		each.requireCommitted(each.push(fresh), 4)
		each.awaitStepEights()
	}

	// the fold of every version, path by path
	for _, each := range []*pushFixture{site, fixture.pushFixture} {
		now := each.clock.Now()
		if _, err := each.engine.folder.FoldAll(each.ctx, each.cluster, each.check.repoId, each.check.refId, each.head(), now, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	for i, path := range paths {
		lost, err := ReadEntry(site.ctx, site.cluster, site.check.repoId, site.check.refId, 1, path, 0)
		if err != nil {
			t.Fatal(err)
		}
		returned, err := ReadEntry(fixture.ctx, fixture.cluster, check.repoId, check.refId, 1, path, 0)
		if err != nil {
			t.Fatal(err)
		}
		if lost.Absent() || returned.Absent() || !proto.Equal(lost.Entry, returned.Entry) {
			t.Fatalf("path %d's folded entry differs: %v, want %v", i, returned.Entry, lost.Entry)
		}
	}
}

// The record of the fixture's ref's version, from the head's window.
func (self *pushFixture) recordOf(version uint64) *sidecar.EvsBatchRecord {
	self.t.Helper()
	window, err := EvsHeadWindow(self.head().Head)
	if err != nil {
		self.t.Fatal(err)
	}
	index := int(version - EvsHeadWindowFirstVersion(self.head().Head))
	if index < 0 || len(window) <= index {
		self.t.Fatalf("version %d is not in the window", version)
	}
	record, err := self.engine.readRecordAt(self.ctx, self.cluster, self.check.repoId, self.check.refId, window[index].Place)
	if err != nil {
		self.t.Fatal(err)
	}
	return record
}

// A call whose parts are not the push's, one per part in order and nothing beside them, is refused before anything is
// written: a part missing, a payload beside the parts, the parts out of order, a part changed. The parts as the
// mirror held them then commit at the next version, and the call again answers that version, writing nothing.
func TestReseedTakesAPushInPartsOnlyAsItsPartsInOrder(t *testing.T) {
	fixture := newReseedFixture(t)
	built := fixture.built(fixture.keptParts(1100))
	if len(built.Parts) != 2 {
		t.Fatalf("%d parts, want 2", len(built.Parts))
	}
	changed := bytes.Clone(built.Parts[0])
	changed[len(changed)-1] ^= 0x01
	for _, call := range []struct {
		label string
		body  *protocol.EvsReseedRequest
	}{
		{"a part missing", &protocol.EvsReseedRequest{Statement: built.Statement.Bytes, Parts: built.Parts[:1]}},
		{"a payload beside the parts", &protocol.EvsReseedRequest{Statement: built.Statement.Bytes, Parts: built.Parts, Payload: []byte("payload")}},
		{"the parts out of order", &protocol.EvsReseedRequest{Statement: built.Statement.Bytes, Parts: [][]byte{built.Parts[1], built.Parts[0]}}},
		{"a part changed", &protocol.EvsReseedRequest{Statement: built.Statement.Bytes, Parts: [][]byte{changed, built.Parts[1]}}},
	} {
		recorder := fixture.reseed(call.body)
		if recorder.Code != http.StatusBadRequest || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_INVALID {
			t.Fatalf("%s: status %d (%s), want 400 INVALID", call.label, recorder.Code, refusalOf(t, recorder).GetCode())
		}
	}
	if records := fixture.batchRecords(); len(records) != 0 || !fixture.head().Absent() {
		t.Fatalf("refused calls wrote %d records or the head", len(records))
	}
	fixture.requireCommitted(fixture.reseed(reseedPartsBody(built)), 1)
	fixture.awaitStepEights()
	written := len(fixture.batchRecords())
	if written != 3 {
		t.Fatalf("the re-seed wrote %d records, want 2 parts and a seal", written)
	}
	fixture.requireCommitted(fixture.reseed(reseedPartsBody(built)), 1)
	if again := len(fixture.batchRecords()); again != written || fixture.head().Version() != 1 {
		t.Fatalf("the call again wrote %d records more, head at %d", again-written, fixture.head().Version())
	}
}

// A reseed record holding a part is refused where no seal names it: with the version's window entry naming the first
// part's record in place of its seal, a version's place, where a reseed record is a one-part push's, the read
// route's, the newest rule's and the slot rule's reads of the version each refuse it rather than take it as the push.
func TestReseedRecordHoldingAPartIsRefusedWhereNoSealNamesIt(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	plan := fixture.keptParts(1100)
	slotId, slotObject, slot := checkTestSlot(t, "up slot")
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: checkTestPath("slotted"), EntryVersion: check.fileEntry(plan, plan.BaseVersion+1, nil, slotId)})
	plan.NewObjects = append(plan.NewObjects, slotObject)
	plan.SlotBodies = append(plan.SlotBodies, slot)
	built := fixture.built(plan)
	fixture.requireCommitted(fixture.reseed(reseedPartsBody(built)), 1)
	fixture.awaitStepEights()
	_, sealParts, err := sidecar.ParseEvsSealRecordBody(fixture.recordAt(check.refId, 1).Body)
	if err != nil {
		t.Fatal(err)
	}
	fixture.rewriteHeadOf(check.refId, func(head *protocol.EvsHead) {
		window, err := EvsHeadWindow(head)
		if err != nil || len(window) != 1 {
			t.Fatalf("window %v %v", window, err)
		}
		window[0].Place = sealParts[0].Place
		head.Window = window[0].Encode()
	})
	head := fixture.head()
	window, err := EvsHeadWindow(head.Head)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newReadPushes(fixture.engine, fixture.ctx, fixture.cluster, check.repoId, check.refId, head.Head).at(1); err == nil {
		t.Fatal("the read route took a part's reseed record as the version's record")
	}
	source := NewRecordPushSource(fixture.engine.records, fixture.engine.locator, fixture.cluster, check.repoId, check.refId)
	if _, err := source.ChangesAt(fixture.ctx, 1, window[0], checkTestPath("slotted")); err == nil {
		t.Fatal("the newest rule took a part's reseed record as the version's record")
	}
	statement, err := sidecar.ParseEvsStatement(built.Statement.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if named, err := fixture.engine.reseededVersionNames(fixture.ctx, fixture.cluster, check.repoId, check.refId, statement, slotId); err == nil || named {
		t.Fatalf("the slot rule took a part's reseed record as a re-seeded version: named %t, %v", named, err)
	}
	if recorder := fixture.reseedSlot(&protocol.EvsReseedRequest{Statement: built.Statement.Bytes}, slotId, slot); recorder.Code == http.StatusOK {
		t.Fatal("a slot was taken under a version whose place holds a part")
	}
	if indexes := fixture.slotIndexes(slotId); indexes != nil {
		t.Fatalf("the slot was stored: keys %v", indexes)
	}
}

// A slot returns only under a re-seeded seal, one whose parts are EVS_BATCH_RESEED records, the mark the slot rule
// reads (QD-818): not before its push in parts commits, and once it has, from its own call alone, step 6 having
// written none; a push in parts the push route sealed names nothing for a re-seed.
func TestReseedSlotReturnsOnlyUnderAReseededSeal(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	slotted := func(plan *sidecar.EvsPushPlan, label string) (sidecar.Id, []byte) {
		slotId, slotObject, slot := checkTestSlot(t, label)
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: checkTestPath(label), EntryVersion: check.fileEntry(plan, plan.BaseVersion+1, nil, slotId)})
		plan.NewObjects = append(plan.NewObjects, slotObject)
		plan.SlotBodies = append(plan.SlotBodies, slot)
		return slotId, slot
	}
	plan := fixture.keptParts(1100)
	slotId, slot := slotted(plan, "rs slot")
	built := fixture.built(plan)
	named := &protocol.EvsReseedRequest{Statement: built.Statement.Bytes}
	requireRefusal(t, fixture.reseedSlot(named, slotId, slot), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN)
	fixture.requireCommitted(fixture.reseed(reseedPartsBody(built)), 1)
	fixture.awaitStepEights()
	if indexes := fixture.slotIndexes(slotId); indexes != nil {
		t.Fatalf("step 6 of a re-seeded push in parts wrote its slot: keys %v", indexes)
	}
	if recorder := fixture.reseedSlot(named, slotId, slot); recorder.Code != http.StatusOK {
		t.Fatalf("status %d (%s) for a slot under a re-seeded seal", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 {
		t.Fatalf("the slot's keys %v", indexes)
	}

	// the push route's own push in parts, sealed on the re-seeded head, which wrote its slot itself
	pushed := fixture.plan()
	for i := 0; i < 1100; i += 1 {
		fixture.create(pushed, fmt.Sprintf("p-%05d", i))
	}
	pushedSlotId, pushedSlot := slotted(pushed, "ps slot")
	token := fixture.token(check.signerId)
	pushedBuilt := fixture.built(pushed)
	fixture.requireCommitted(fixture.seal(token, pushedBuilt, fixture.postParts(token, pushedBuilt)), 2)
	requireRefusal(t, fixture.reseedSlot(&protocol.EvsReseedRequest{Statement: pushedBuilt.Statement.Bytes}, pushedSlotId, pushedSlot),
		http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN)
}

// Evacuation keeps a re-seeded push in parts' records where its seal names them and drops the rest (QD-818): past
// 25 h the seal and its two parts leave their batches, the parts of an attempt whose seal never named them (written
// again by hand, as an attempt that failed after its parts would have left them) drop as duplicates, and the parts
// of a re-seed that never committed drop as dead once the fence passes their statement. The ref then reads, re-seeds
// and proves from where the kept records moved.
func TestReseededPartsEvacuateWithTheirSeal(t *testing.T) {
	nightly := newNightlyFixture(t)
	fixture := reseedFixtureOf(nightly.pushFixture)
	check := fixture.check
	built := fixture.built(fixture.keptParts(1100))
	fixture.requireCommitted(fixture.reseed(reseedPartsBody(built)), 1)
	fixture.awaitStepEights()
	appendParts := func(built *sidecar.EvsBuiltPush) {
		t.Helper()
		push := built.Statement.Push
		for _, part := range built.Parts {
			record := &sidecar.EvsBatchRecord{
				Type: protocol.EvsBatchRecordType_EVS_BATCH_RESEED, RepoId: check.repoId, RefId: check.refId,
				PushId: sidecar.Id(push.GetPushId()), SignerSidecarId: sidecar.Id(push.GetSignerSidecarId()), TimeMs: push.GetTimeMs(),
				Body: sidecar.EvsPartRecordBody(built.Statement.Bytes, part, nil, 1),
			}
			if _, err := fixture.engine.batches.AppendFormat2(fixture.paidContext(), "meta-1", record, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	appendParts(built)
	unsealed := fixture.keptParts(0)
	for i := 0; i < 1100; i += 1 {
		fixture.create(unsealed, fmt.Sprintf("u-%05d", i))
	}
	appendParts(fixture.built(unsealed))

	nightly.age()
	result := nightly.mustRun()
	if result.KeptCount != 3 || result.DuplicateCount != 2 || result.DeadCount != 2 || result.MinuteWaitingCount != 0 || result.HasBatches {
		t.Fatalf("result %+v", result)
	}
	if keys := nightly.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		t.Fatalf("batches left: %v", keys)
	}
	seal := fixture.recordAt(check.refId, 1)
	_, sealParts, err := sidecar.ParseEvsSealRecordBody(seal.Body)
	if err != nil || seal.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
		t.Fatalf("version 1's moved record is type %s: %v", seal.Type, err)
	}
	for i, sealPart := range sealParts {
		part, err := fixture.engine.readRecordAt(fixture.ctx, fixture.cluster, check.repoId, check.refId, sealPart.Place)
		if err != nil || !sidecar.EvsReseedRecordHoldsPart(part) {
			t.Fatalf("part %d after evacuation: %v", i+1, err)
		}
	}
	fixture.requireCommitted(fixture.reseed(reseedPartsBody(built)), 1)
	for _, label := range []string{"file-00000", "file-01099"} {
		path := checkTestPath(label)
		reply := fixture.readPath(fixture.token(check.signerId, "r"), 0, true, path)
		requireVersionProven(t, reply, reply.paths[0], path)
	}
}

// A call that carries no part is held to the route's own bound, and one carrying a push in parts to the parts' bound,
// each refused 400 past it before anything is read of the push.
func TestReseedHoldsEachCallToItsBodyBound(t *testing.T) {
	push := newPushFixture(t, func(settings *EvsSettings) {
		settings.ReseedBodyMaxByteCount = 4 * 1024
		settings.ReseedPartsBodyMaxByteCount = 64 * 1024
	})
	fixture := reseedFixtureOf(push)
	plan := fixture.kept()
	fixture.create(plan, "a")
	body := fixture.reseedBody(plan)
	padded := proto.Clone(body).(*protocol.EvsReseedRequest)
	padded.Payload = append(bytes.Clone(body.GetPayload()), make([]byte, 8*1024)...)
	requireRefusal(t, fixture.reseed(padded), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	built := fixture.built(fixture.keptParts(1100))
	requireRefusal(t, fixture.reseed(reseedPartsBody(built)), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	if !fixture.head().Absent() || len(fixture.batchRecords()) != 0 {
		t.Fatal("a call past its bound wrote something")
	}
	fixture.requireCommitted(fixture.reseed(body), 1)
}

// The newest rule finds the root's own change in a sealed push: a push in parts that changes the root, as one creating
// a top-level directory does, names the root's delta first, in its first part (QD-661), and RecordPushSource.ChangesAt,
// which the read route and step 4 read a sealed push's changes through, finds it for the root, through the push
// route's part records and a re-seed's alike; so a second creation of the root, on the head after it, conflicts.
func TestNewestFindsTheRootsChangeInASealedPush(t *testing.T) {
	for _, reseeded := range []bool{false, true} {
		fixture := newReseedFixture(t)
		check := fixture.check
		root := sidecar.EvsTokenPath{}
		rowsOf := func(labels ...string) []*protocol.EvsName {
			rows := []*protocol.EvsName{}
			for _, label := range labels {
				token := worldToken(label)
				rows = append(rows, &protocol.EvsName{Token: token[:], Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: []byte("sealed " + label)})
			}
			return rows
		}
		plan := fixture.plan()
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: root, EntryVersion: check.directoryEntry(plan, 1, rowsOf("file-00000", "file-00001"), nil)})
		for i := 0; i < 1100; i += 1 {
			fixture.create(plan, fmt.Sprintf("file-%05d", i))
		}
		built := fixture.built(plan)
		if first, err := sidecar.EvsCheckPart(built.Statement, built.Parts[0]); err != nil || len(first.FirstTokenPath()) != 0 {
			t.Fatalf("the first part does not start at the root: %v", err)
		}
		if reseeded {
			fixture.requireCommitted(fixture.reseed(reseedPartsBody(built)), 1)
		} else {
			token := fixture.token(check.signerId)
			fixture.requireCommitted(fixture.seal(token, built, fixture.postParts(token, built)), 1)
		}
		fixture.awaitStepEights()
		window, err := EvsHeadWindow(fixture.head().Head)
		if err != nil || len(window) != 1 {
			t.Fatalf("window %v %v", window, err)
		}
		source := NewRecordPushSource(fixture.engine.records, fixture.engine.locator, fixture.cluster, check.repoId, check.refId)
		changes, err := source.ChangesAt(fixture.ctx, 1, window[0], root)
		if err != nil || len(changes) != 1 || len(changes[0].TokenPath) != 0 {
			t.Fatalf("re-seeded %t: the root's changes in the sealed push: %d, %v", reseeded, len(changes), err)
		}
		again := fixture.plan()
		again.PushId = testId(fmt.Sprintf("root again %t", reseeded))
		again.Changes = []*sidecar.EvsPlannedChange{{TokenPath: root, EntryVersion: check.directoryEntry(again, 2, rowsOf("file-00002"), nil)}}
		requireRefusal(t, fixture.push(again), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	}
}
