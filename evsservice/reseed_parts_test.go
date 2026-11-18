// QD-818's and QD-836's tests of a re-seeded push in parts at POST .../reseed on T2 (reseed.go, push_seal.go): a push in
// parts goes one part a call, each answered with its EVS_BATCH_RESEED record's place, then a seal call naming those
// places. A ref whose history holds a push in parts, written through the push route of a site the test then loses,
// returns whole from a repo admin's mirror through sidecar.EvsRepo.Reseed, its push in parts as an EVS_BATCH_SEAL
// record naming one EVS_BATCH_RESEED record per part, and every reader of a sealed push answers there as it did on the
// lost site: reads and their proofs, the newest rule under later pushes, the sweep's recompute and the fold. A push in
// parts past the lb's 16 MiB returns with no call past the route's bound. Each call out of its form is refused writing
// nothing; a seal naming a place that holds no part of its statement, the other mode's part, or a part its statement
// does not cover is refused committing nothing; a part call retried writes a copy the seal may name or leave, and once
// the push stands committed answers its version writing nothing; the device's walk retries a part whose answer it lost
// and sends the parts again after PARTS_MISSING; a reseed record holding a part is refused at a place no seal names; a
// slot returns only under a re-seeded seal; and evacuation keeps a re-seeded part its seal names and drops the copies
// and the parts of a seal that never came, those only on a fence raised after the run held them (QD-974). A seal
// naming a part place whose minute began more than EvsSettings.ReseedPartMaxAge before it arrived is refused
// PARTS_MISSING, writing nothing, and the parts sent again commit under a new seal (QD-974).

package evsservice

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
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
	history.statements, history.records, history.chains = site.mirroredHistory()
	if len(history.records) != 3 || len(history.records[1]) != 3 {
		t.Fatalf("the lost site's history holds %d versions, version 2 %d records, want its seal and 2 parts", len(history.records), len(history.records[1]))
	}
	return history
}

// What a mirror holds of the fixture's ref, every version of which its head's window names: by version, each statement,
// its records as a read serves them, part 0 first, and the chain through it.
func (self *pushFixture) mirroredHistory() ([][]byte, [][][]byte, [][32]byte) {
	t := self.t
	t.Helper()
	head := self.head()
	window, err := EvsHeadWindow(head.Head)
	if err != nil || len(window) == 0 || EvsHeadWindowFirstVersion(head.Head) != 1 {
		t.Fatalf("the site's window: %d entries, %v", len(window), err)
	}
	readBytes := func(place *protocol.EvsPlace) []byte {
		t.Helper()
		recordBytes, err := self.engine.readRecordBytesAt(self.ctx, self.cluster, self.check.repoId, self.check.refId, place)
		if err != nil {
			t.Fatal(err)
		}
		return recordBytes
	}
	statements := [][]byte{}
	records := [][][]byte{}
	chains := [][32]byte{}
	chain := sidecar.EvsChainStart(self.check.repoId, self.check.refId)
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
		versionRecords := [][]byte{recordBytes}
		if record.Type == protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
			_, sealParts, err := sidecar.ParseEvsSealRecordBody(record.Body)
			if err != nil {
				t.Fatal(err)
			}
			for _, sealPart := range sealParts {
				versionRecords = append(versionRecords, readBytes(sealPart.Place))
			}
		}
		statement, err := sidecar.ParseEvsStatement(statementBytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = sidecar.EvsChainNext(chain, entry.PushId, statement.Sha256)
		statements = append(statements, statementBytes)
		records = append(records, versionRecords)
		chains = append(chains, chain)
	}
	return statements, records, chains
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

// built's part call for part index (QD-836): its statement and that one part, numbered.
func reseedPartBody(built *sidecar.EvsBuiltPush, index int) *protocol.EvsReseedRequest {
	return &protocol.EvsReseedRequest{Statement: built.Statement.Bytes, Parts: [][]byte{built.Parts[index]}, PartNumber: uint32(index + 1)}
}

// built's seal call, naming places.
func reseedSealBody(built *sidecar.EvsBuiltPush, places []*protocol.EvsPlace) *protocol.EvsReseedRequest {
	return &protocol.EvsReseedRequest{Statement: built.Statement.Bytes, PartPlaces: places}
}

// Every part's call of built, in part order, each answering its record's place.
func (self *reseedFixture) reseedParts(built *sidecar.EvsBuiltPush) []*protocol.EvsPlace {
	self.t.Helper()
	places := make([]*protocol.EvsPlace, len(built.Parts))
	for i := range built.Parts {
		places[i] = self.requirePlace(self.reseed(reseedPartBody(built, i)))
	}
	return places
}

// built re-seeded as a device sends it: each part's call in part order, then the seal naming their places. The seal's
// answer.
func (self *reseedFixture) reseedInParts(built *sidecar.EvsBuiltPush) *httptest.ResponseRecorder {
	self.t.Helper()
	return self.reseed(reseedSealBody(built, self.reseedParts(built)))
}

// The reseed record at place: its statement and part, which it must hold with no receipt.
func (self *reseedFixture) reseedPartAt(place *protocol.EvsPlace) ([]byte, []byte) {
	self.t.Helper()
	record, err := self.engine.readRecordAt(self.ctx, self.cluster, self.check.repoId, self.check.refId, place)
	if err != nil {
		self.t.Fatal(err)
	}
	statementBytes, partBytes, receipts, _, err := sidecar.ParseEvsSealPartRecord(record)
	if err != nil || record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || len(receipts) != 0 {
		self.t.Fatalf("the record at %s is type %s with %d receipts: %v", placeKey(place), record.Type, len(receipts), err)
	}
	return statementBytes, partBytes
}

// The places the seal record of the ref's version names, in part order.
func (self *reseedFixture) sealPlacesAt(version uint64) []*protocol.EvsPlace {
	self.t.Helper()
	seal := self.recordAt(self.check.refId, version)
	_, sealParts, err := sidecar.ParseEvsSealRecordBody(seal.Body)
	if err != nil || seal.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
		self.t.Fatalf("version %d's record is type %s: %v", version, seal.Type, err)
	}
	places := []*protocol.EvsPlace{}
	for _, sealPart := range sealParts {
		places = append(places, sealPart.Place)
	}
	return places
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

// A ref whose history holds a push in parts returns whole from a complete mirror: the device's walk sends version 2 as
// a call per part, in part order, and then its seal (QD-836), and evs commits it as an EVS_BATCH_SEAL record naming an
// EVS_BATCH_RESEED record per part, each holding the part the mirror held with no receipt. Every reader of the sealed
// push answers as the lost site did: a read of each part's edge paths, the file version 3 wrote again and a, whose read
// proves the push in parts left it alone from that push's parts; the recompute of version 3's list, which walks back
// into the push in parts; the newest rule, under a write of the rewritten file on its stale version, which conflicts,
// and of another on its version, which commits; and the fold of every version, path by path. A second walk changes
// nothing: its first part call finds the push committed, and nothing is written.
func TestReseedReturnsARefHoldingAPushInPartsWhole(t *testing.T) {
	history := newReseedPartsHistory(t)
	site := history.site
	fixture := newReseedFixture(t)
	check := fixture.check
	device := fixture.device()
	device.holdsRecords(check.refId, history.statements, history.records, history.chains, 3)
	ref := device.reseed()
	// versions 1 and 3 a call each, version 2 a call per part and its seal
	if ref.Stopped != nil || ref.MirrorVersion != 3 || ref.Version != 3 || ref.Chain != history.chains[2] || device.reseedCallCount != 5 {
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
		// each part call read the head at version 1
		if !bytes.Equal(partStatement, history.statements[1]) || !bytes.Equal(partBytes, history.built.Parts[i]) || len(receipts) != 0 || checkedVersion != 1 {
			t.Fatalf("part %d's record holds other bytes than the mirror's part, %d receipts, taken at %d", i+1, len(receipts), checkedVersion)
		}
	}
	// 5a answers each version where it stands, version 2 at its first part call, and nothing is written
	written := len(fixture.batchRecords())
	device.reseedCallCount = 0
	if again := device.reseed(); again.Stopped != nil || again.Version != 3 || device.reseedCallCount != 3 {
		t.Fatalf("a second walk ended at %d after %d calls, stopped by %v", again.Version, device.reseedCallCount, again.Stopped)
	}
	if after := fixture.head(); after.Etag != head.Etag || len(fixture.batchRecords()) != written {
		t.Fatal("a second walk wrote the head or a record")
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

// QD-836's bound: a push in parts of at least 20 parts of about 1 MiB each, past the lb's 16 MiB together, which the
// one call QD-725 had could not carry, returns whole from a mirror of the lost site where the push route took it. The
// device's walk sends it a part a call and then its seal, no call's body past the route's 2 MiB bound and so none past
// RequestBodyMaxByteCount, and the ref reads back as the lost site read: the paths of its first, a middle and its last
// part, each proven to its part's root.
func TestReseedReturnsAPushInPartsPastTheRequestBound(t *testing.T) {
	site := newPushFixture(t, nil)
	token := site.token(site.check.signerId)
	plan := site.plan()
	// a part holds about 63 entries of a 15,872 B inline record each, a Padmé size, so 1,300 files make 21 parts
	inline := bytes.Repeat([]byte{0x5a}, 15872)
	paths := []sidecar.EvsTokenPath{}
	for i := 0; i < 1300; i += 1 {
		path := checkTestPath(fmt.Sprintf("big-%05d", i))
		paths = append(paths, path)
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
			TokenPath:    path,
			EntryVersion: site.check.fileEntry(plan, 1, []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: inline}}),
		})
	}
	built := site.built(plan)
	partByteCount := 0
	for i, part := range built.Parts {
		if i < len(built.Parts)-1 && len(part) < 900*1024 {
			t.Fatalf("part %d holds %d bytes, not about 1 MiB", i+1, len(part))
		}
		partByteCount += len(part)
	}
	requestBound := site.settings.RequestBodyMaxByteCount
	if len(built.Parts) < 20 || int64(partByteCount) <= requestBound {
		t.Fatalf("%d parts of %d bytes in all, want at least 20 past %d", len(built.Parts), partByteCount, requestBound)
	}
	site.requireCommitted(site.seal(token, built, site.postParts(token, built)), 1)
	site.awaitStepEights()
	statements, records, chains := site.mirroredHistory()

	fixture := newReseedFixture(t)
	check := fixture.check
	device := fixture.device()
	device.holdsRecords(check.refId, statements, records, chains, 1)
	ref := device.reseed()
	if ref.Stopped != nil || ref.Version != 1 || ref.Chain != chains[0] || device.reseedCallCount != len(built.Parts)+1 {
		t.Fatalf("the walk ended at %d after %d calls, stopped by %v", ref.Version, device.reseedCallCount, ref.Stopped)
	}
	if int64(device.reseedMaxByteCount) > fixture.settings.ReseedBodyMaxByteCount || fixture.settings.ReseedBodyMaxByteCount > requestBound {
		t.Fatalf("a reseed call of %d bytes, past the route's %d or the request bound's %d", device.reseedMaxByteCount, fixture.settings.ReseedBodyMaxByteCount, requestBound)
	}
	head := fixture.head()
	if head.Version() != 1 || !bytes.Equal(head.Head.GetChain(), chains[0][:]) {
		t.Fatalf("head at %d, not the lost site's", head.Version())
	}
	places := fixture.sealPlacesAt(1)
	if len(places) != len(built.Parts) {
		t.Fatalf("the seal names %d parts, want %d", len(places), len(built.Parts))
	}
	for i, place := range places {
		if statementBytes, partBytes := fixture.reseedPartAt(place); !bytes.Equal(statementBytes, statements[0]) || !bytes.Equal(partBytes, built.Parts[i]) {
			t.Fatalf("part %d's reseed record holds other bytes than the mirror's", i+1)
		}
	}
	for _, index := range []int{0, len(paths) / 2, len(paths) - 1} {
		path := paths[index]
		label := fmt.Sprintf("path %d", index)
		lost := site.readPath(site.token(site.check.signerId, "r"), 0, true, path)
		returned := fixture.readPath(fixture.token(check.signerId, "r"), 0, true, path)
		requireSameRead(t, label, lost, returned)
		requireVersionProven(t, returned, returned.paths[0], path)
	}
}

// part with a sealed-metadata slice of its own in place of the one it held: still a part of its push by every check a
// part call runs, its changes and their root unchanged, but not the part parts_sha256 covers.
func reseedAlteredPart(part []byte) []byte {
	altered := protowire.AppendTag(bytes.Clone(part), 6, protowire.BytesType)
	return protowire.AppendBytes(altered, []byte("another slice of sealed metadata"))
}

// A push in parts is taken one part a call and then its seal, and each call out of that form is refused before
// anything is written: the push whole, a part with no number, numbered unlike its part or past the count, a payload
// beside a part, a part and a seal at once, a seal short of a place, and the statement alone. The parts' calls then
// write their records, and a seal is refused with nothing committed while it names a place no record holds (409
// PARTS_MISSING), the places out of order, or the place of a part that passed its call but is not the one the
// statement covers (400). The seal of the parts' own places commits; after it, a part call and the seal each answer the
// version, writing nothing.
func TestReseedTakesAPushInPartsOnlyAPartACallThenItsSeal(t *testing.T) {
	fixture := newReseedFixture(t)
	built := fixture.built(fixture.keptParts(1100))
	if len(built.Parts) != 2 {
		t.Fatalf("%d parts, want 2", len(built.Parts))
	}
	statement := built.Statement.Bytes
	place := &protocol.EvsPlace{Minute: 1, Seq: 1}
	for _, call := range []struct {
		label string
		body  *protocol.EvsReseedRequest
	}{
		{"the push whole", &protocol.EvsReseedRequest{Statement: statement, Parts: built.Parts}},
		{"the push whole, numbered", &protocol.EvsReseedRequest{Statement: statement, Parts: built.Parts, PartNumber: 1}},
		{"a part with no number", &protocol.EvsReseedRequest{Statement: statement, Parts: built.Parts[:1]}},
		{"a number with no part", &protocol.EvsReseedRequest{Statement: statement, PartNumber: 1}},
		{"a part numbered unlike it", &protocol.EvsReseedRequest{Statement: statement, Parts: built.Parts[1:], PartNumber: 1}},
		{"a part number past the count", &protocol.EvsReseedRequest{Statement: statement, Parts: built.Parts[:1], PartNumber: 3}},
		{"a payload beside a part", &protocol.EvsReseedRequest{Statement: statement, Parts: built.Parts[:1], PartNumber: 1, Payload: []byte("payload")}},
		{"a part and a seal at once", &protocol.EvsReseedRequest{Statement: statement, Parts: built.Parts[:1], PartNumber: 1, PartPlaces: []*protocol.EvsPlace{place, place}}},
		{"a seal short of a place", reseedSealBody(built, []*protocol.EvsPlace{place})},
		{"a payload beside a seal", &protocol.EvsReseedRequest{Statement: statement, PartPlaces: []*protocol.EvsPlace{place, place}, Payload: []byte("payload")}},
		{"the statement alone", &protocol.EvsReseedRequest{Statement: statement}},
	} {
		recorder := fixture.reseed(call.body)
		if recorder.Code != http.StatusBadRequest || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_INVALID {
			t.Fatalf("%s: status %d (%s), want 400 INVALID", call.label, recorder.Code, refusalOf(t, recorder).GetCode())
		}
	}
	if records := fixture.batchRecords(); len(records) != 0 || !fixture.head().Absent() {
		t.Fatalf("refused calls wrote %d records or the head", len(records))
	}

	places := fixture.reseedParts(built)
	altered := &sidecar.EvsBuiltPush{Statement: built.Statement, Parts: [][]byte{reseedAlteredPart(built.Parts[0]), built.Parts[1]}}
	alteredPlace := fixture.requirePlace(fixture.reseed(reseedPartBody(altered, 0)))
	gone := proto.Clone(places[1]).(*protocol.EvsPlace)
	gone.Seq += 100
	for _, seal := range []struct {
		label  string
		places []*protocol.EvsPlace
		status int
		code   protocol.EvsRefusalCode
	}{
		{"a place no record holds", []*protocol.EvsPlace{places[0], gone}, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING},
		{"the places out of order", []*protocol.EvsPlace{places[1], places[0]}, http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID},
		{"an altered part's place", []*protocol.EvsPlace{alteredPlace, places[1]}, http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID},
	} {
		recorder := fixture.reseed(reseedSealBody(built, seal.places))
		if recorder.Code != seal.status || refusalOf(t, recorder).GetCode() != seal.code {
			t.Fatalf("a seal naming %s: status %d (%s), want %d %s", seal.label, recorder.Code, refusalOf(t, recorder).GetCode(), seal.status, seal.code)
		}
		if !fixture.head().Absent() {
			t.Fatalf("a seal naming %s committed", seal.label)
		}
	}
	written := len(fixture.batchRecords())
	if written != 3 {
		t.Fatalf("the part calls wrote %d records, want 3", written)
	}
	fixture.requireCommitted(fixture.reseed(reseedSealBody(built, places)), 1)
	fixture.awaitStepEights()
	if after := len(fixture.batchRecords()); after != written+1 {
		t.Fatalf("the seal wrote %d records, want its own", after-written)
	}
	for i := range built.Parts {
		fixture.requireCommitted(fixture.reseed(reseedPartBody(built, i)), 1)
	}
	fixture.requireCommitted(fixture.reseed(reseedSealBody(built, places)), 1)
	if again := len(fixture.batchRecords()); again != written+1 || fixture.head().Version() != 1 {
		t.Fatalf("the calls again wrote %d records more, head at %d", again-written-1, fixture.head().Version())
	}
}

// Neither mode seals the other's parts (QD-818): a fresh push in parts' records from the push route's part route are
// not a re-seed's, nor are its re-seeded parts the push route's. Each seal naming the other's places is answered 409
// PARTS_MISSING, committing nothing, and the re-seed's seal of its own parts commits.
func TestReseedSealTakesNeitherModesOtherParts(t *testing.T) {
	fixture := newReseedFixture(t)
	token := fixture.token(fixture.check.signerId)
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	reseeded := fixture.reseedParts(built)
	pushed := fixture.postParts(token, built)
	requireRefusal(t, fixture.reseed(reseedSealBody(built, pushed)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING)
	requireRefusal(t, fixture.seal(token, built, reseeded), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING)
	if !fixture.head().Absent() {
		t.Fatal("a seal of the other mode's parts committed")
	}
	fixture.requireCommitted(fixture.reseed(reseedSealBody(built, reseeded)), 1)
	for i, place := range fixture.sealPlacesAt(1) {
		if !sameEvsPlace(place, reseeded[i]) {
			t.Fatalf("the seal names part %d at %s, not its reseed record", i+1, placeKey(place))
		}
	}
}

// A part call retried, as a device retries one whose answer it lost, writes a second record of the same part, and the
// seal names either copy: here the second of part 1. Once the push stands committed a part call answers its version
// and writes nothing, and so does the seal again.
func TestReseedPartCallIsIdempotentOnRetry(t *testing.T) {
	fixture := newReseedFixture(t)
	built := fixture.built(fixture.keptParts(1100))
	first := fixture.requirePlace(fixture.reseed(reseedPartBody(built, 0)))
	retried := fixture.requirePlace(fixture.reseed(reseedPartBody(built, 0)))
	if sameEvsPlace(first, retried) {
		t.Fatal("a retried part call answered the place of the first")
	}
	for _, place := range []*protocol.EvsPlace{first, retried} {
		if statementBytes, partBytes := fixture.reseedPartAt(place); !bytes.Equal(statementBytes, built.Statement.Bytes) || !bytes.Equal(partBytes, built.Parts[0]) {
			t.Fatalf("the record at %s holds another part", placeKey(place))
		}
	}
	second := fixture.requirePlace(fixture.reseed(reseedPartBody(built, 1)))
	fixture.requireCommitted(fixture.reseed(reseedSealBody(built, []*protocol.EvsPlace{retried, second})), 1)
	fixture.awaitStepEights()
	if named := fixture.sealPlacesAt(1); len(named) != 2 || !sameEvsPlace(named[0], retried) || !sameEvsPlace(named[1], second) {
		t.Fatalf("the seal names %v", named)
	}
	written := len(fixture.batchRecords())
	if written != 4 {
		t.Fatalf("%d records, want 3 parts and a seal", written)
	}
	for _, index := range []int{0, 1, 0} {
		reply := fixture.requireCommitted(fixture.reseed(reseedPartBody(built, index)), 1)
		if reply.GetPlace() != nil {
			t.Fatalf("a part call after the commit answered a place")
		}
	}
	fixture.requireCommitted(fixture.reseed(reseedSealBody(built, []*protocol.EvsPlace{first, second})), 1)
	if again := len(fixture.batchRecords()); again != written {
		t.Fatalf("calls after the commit wrote %d records", again-written)
	}
}

// The device's walk retries what refuses nothing (QD-836): part 2's first answer is lost after evs wrote its record,
// and the walk sends that call again with the same bytes; the first seal names a place whose record is gone, as after
// an evacuation, and its 409 PARTS_MISSING sends every part again and the seal again. The ref returns whole, the seal
// naming the last copy of each part, and the copies no seal names are left for evacuation.
func TestReseedWalkRetriesItsPartCallsAndSealsAgain(t *testing.T) {
	history := newReseedPartsHistory(t)
	fixture := newReseedFixture(t)
	check := fixture.check
	device := fixture.device()
	device.holdsRecords(check.refId, history.statements, history.records, history.chains, 3)
	partTries := map[uint32]int{}
	sealTries := 0
	device.onReseed = func(call int, body *protocol.EvsReseedRequest) bool {
		switch {
		case body.GetPartNumber() != 0:
			partTries[body.GetPartNumber()] += 1
			return body.GetPartNumber() == 2 && partTries[2] == 1
		case 0 < len(body.GetPartPlaces()):
			sealTries += 1
			if sealTries == 1 {
				gone := proto.Clone(body.PartPlaces[0]).(*protocol.EvsPlace)
				gone.Seq += 100
				body.PartPlaces[0] = gone
			}
		}
		return false
	}
	ref := device.reseed()
	if ref.Stopped != nil || ref.Version != 3 || ref.Chain != history.chains[2] {
		t.Fatalf("the walk ended at %d, stopped by %v", ref.Version, ref.Stopped)
	}
	// part 1 twice, part 2 three times: its lost answer's retry, and the parts again after PARTS_MISSING
	if partTries[1] != 2 || partTries[2] != 3 || sealTries != 2 {
		t.Fatalf("part calls %v and %d seals", partTries, sealTries)
	}
	partRecords := 0
	for _, recordBytes := range fixture.batchRecords() {
		record, err := sidecar.ParseEvsBatchRecord(recordBytes)
		if err != nil {
			t.Fatal(err)
		}
		if sidecar.EvsReseedRecordHoldsPart(record) {
			partRecords += 1
		}
	}
	if partRecords != 5 {
		t.Fatalf("%d part records, want 5", partRecords)
	}
	for i, place := range fixture.sealPlacesAt(2) {
		if _, partBytes := fixture.reseedPartAt(place); !bytes.Equal(partBytes, history.built.Parts[i]) {
			t.Fatalf("the seal's part %d holds another part", i+1)
		}
	}
}

// A reseed record holding a part is refused where no seal names it: with the version's window entry naming the first
// part's record in place of its seal, a version's place, where a reseed record is a one-part push's, the read route's,
// the newest rule's and the slot rule's reads of the version each refuse it rather than take it as the push.
func TestReseedRecordHoldingAPartIsRefusedWhereNoSealNamesIt(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	plan := fixture.keptParts(1100)
	slotId, slotObject, slot := checkTestSlot(t, "up slot")
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: checkTestPath("slotted"), EntryVersion: check.fileEntry(plan, plan.BaseVersion+1, nil, slotId)})
	plan.NewObjects = append(plan.NewObjects, slotObject)
	plan.SlotBodies = append(plan.SlotBodies, slot)
	built := fixture.built(plan)
	fixture.requireCommitted(fixture.reseedInParts(built), 1)
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
// reads (QD-818): not before its push in parts commits, and once it has, from its own call alone, no call of the push
// having carried it; a push in parts the push route sealed names nothing for a re-seed.
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
	fixture.requireCommitted(fixture.reseedInParts(built), 1)
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

// Evacuation keeps a re-seeded push in parts' records where its seal names them and drops the rest (QD-818, QD-836,
// QD-974): each part's call went twice, as a device retries one whose answer it lost, and the seal named one copy of
// each; then a push in parts' part calls went and its seal never came, and an hour on the ref took a fence, long past
// their month-old statement's time. A seal arriving after that fence could still commit those parts, so Resolve
// holds them pending on it. Past 25 h the seal and the two parts it names leave their batches, the copies it does not
// name drop as duplicates, and the parts of the seal that never came drop as dead only once the run has raised the
// ref's fence again, past the time it held them. The ref then reads, re-seeds and proves from where the kept records
// moved.
func TestReseededPartsEvacuateWithTheirSeal(t *testing.T) {
	nightly := newNightlyFixture(t)
	fixture := reseedFixtureOf(nightly.pushFixture)
	check := fixture.check
	built := fixture.built(fixture.keptParts(1100))
	firsts := fixture.reseedParts(built)
	seconds := fixture.reseedParts(built)
	fixture.requireCommitted(fixture.reseed(reseedSealBody(built, []*protocol.EvsPlace{seconds[0], firsts[1]})), 1)
	fixture.awaitStepEights()
	unsealed := fixture.keptParts(0)
	for i := 0; i < 1100; i += 1 {
		fixture.create(unsealed, fmt.Sprintf("u-%05d", i))
	}
	unsealedPlaces := fixture.reseedParts(fixture.built(unsealed))
	fixture.clock.Advance(time.Hour)
	older, err := fixture.engine.heads.RaiseFence(fixture.paidContext(), fixture.cluster, check.repoId, check.refId)
	if err != nil {
		t.Fatal(err)
	}
	// as a run 25 h on holds them, on that fence
	heldTime := fixture.clock.Now().Add(25 * time.Hour)
	for i, place := range unsealedPlaces {
		record, err := fixture.engine.readRecordAt(fixture.ctx, fixture.cluster, check.repoId, check.refId, place)
		if err != nil {
			t.Fatal(err)
		}
		resolution, err := fixture.engine.ResolvePush(fixture.ctx, fixture.cluster, record, older.Head, heldTime)
		if err != nil || resolution.State != EvsResolvePending {
			t.Fatalf("part %d of the seal that never came resolves %+v on the older fence: %v", i+1, resolution, err)
		}
	}

	nightly.age()
	result := nightly.mustRun()
	if result.KeptCount != 3 || result.DuplicateCount != 2 || result.DeadCount != 2 || result.FenceCount != 1 || result.MinuteWaitingCount != 0 ||
		result.HasBatches {
		t.Fatalf("result %+v", result)
	}
	if head := fixture.head(); head.Version() != 1 || head.Head.GetFence() != older.Head.GetFence()+1 || head.Head.GetFenceMs() != fixture.clock.Now().UnixMilli() {
		t.Fatalf("the run's fence left version %d fence %d fence_ms %d", head.Version(), head.Head.GetFence(), head.Head.GetFenceMs())
	}
	if keys := nightly.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		t.Fatalf("batches left: %v", keys)
	}
	sealPlaces := fixture.sealPlacesAt(1)
	for i, place := range sealPlaces {
		part, err := fixture.engine.readRecordAt(fixture.ctx, fixture.cluster, check.repoId, check.refId, place)
		if err != nil || !sidecar.EvsReseedRecordHoldsPart(part) {
			t.Fatalf("part %d after evacuation: %v", i+1, err)
		}
	}
	// the push's calls again each answer its version where its records moved, writing nothing
	fixture.requireCommitted(fixture.reseed(reseedPartBody(built, 0)), 1)
	fixture.requireCommitted(fixture.reseed(reseedSealBody(built, sealPlaces)), 1)
	if keys := nightly.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		t.Fatalf("the calls again wrote batches: %v", keys)
	}
	for _, label := range []string{"file-00000", "file-01099"} {
		path := checkTestPath(label)
		reply := fixture.readPath(fixture.token(check.signerId, "r"), 0, true, path)
		requireVersionProven(t, reply, reply.paths[0], path)
	}
}

// Every call is held to the route's one bound, a part call carrying one part as a one-part push's call carries its
// payload (QD-836), and one past it is refused 400 before anything is read of the push.
func TestReseedHoldsEveryCallToItsBodyBound(t *testing.T) {
	push := newPushFixture(t, func(settings *EvsSettings) {
		settings.ReseedBodyMaxByteCount = 64 * 1024
	})
	fixture := reseedFixtureOf(push)
	plan := fixture.kept()
	fixture.create(plan, "a")
	body := fixture.reseedBody(plan)
	padded := proto.Clone(body).(*protocol.EvsReseedRequest)
	padded.Payload = append(bytes.Clone(body.GetPayload()), make([]byte, 80*1024)...)
	requireRefusal(t, fixture.reseed(padded), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	built := fixture.built(fixture.keptParts(1100))
	if len(built.Parts[0]) <= 64*1024 {
		t.Fatalf("part 1 holds %d bytes, within the bound", len(built.Parts[0]))
	}
	requireRefusal(t, fixture.reseed(reseedPartBody(built, 0)), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
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
			fixture.requireCommitted(fixture.reseedInParts(built), 1)
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

// QD-974's bound on a re-seed's seal: a seal naming a part place whose batch minute began more than
// EvsSettings.ReseedPartMaxAge before it arrived is refused 409 PARTS_MISSING, refusing and recording nothing, so no
// seal can name a part evacuation may have judged. Both parts sent a day ago, the seal of their places is refused, and
// so is one naming part 1 sent again beside part 2's old place; neither writes a record or the head. Part 2 sent
// again, the seal of the fresh places commits and names them, and the stale seal, sent after, answers the version by
// 5a rather than PARTS_MISSING.
func TestReseedSealRefusesAPartPlacePastItsAgeBound(t *testing.T) {
	fixture := newReseedFixture(t)
	built := fixture.built(fixture.keptParts(1100))
	stale := fixture.reseedParts(built)
	// a minute past the bound, so past it from the start of the parts' minute
	fixture.clock.Advance(fixture.settings.ReseedPartMaxAge + time.Minute)
	written := len(fixture.batchRecords())
	requireRefusal(t, fixture.reseed(reseedSealBody(built, stale)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING)
	fresh := []*protocol.EvsPlace{fixture.requirePlace(fixture.reseed(reseedPartBody(built, 0))), stale[1]}
	requireRefusal(t, fixture.reseed(reseedSealBody(built, fresh)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING)
	if after := len(fixture.batchRecords()); !fixture.head().Absent() || after != written+1 {
		t.Fatalf("the refused seals wrote %d records or the head", after-written-1)
	}
	fresh[1] = fixture.requirePlace(fixture.reseed(reseedPartBody(built, 1)))
	fixture.requireCommitted(fixture.reseed(reseedSealBody(built, fresh)), 1)
	fixture.awaitStepEights()
	if named := fixture.sealPlacesAt(1); len(named) != 2 || !sameEvsPlace(named[0], fresh[0]) || !sameEvsPlace(named[1], fresh[1]) {
		t.Fatalf("the seal names %v", named)
	}
	fixture.requireCommitted(fixture.reseed(reseedSealBody(built, stale)), 1)
}

// The bound is judged at the seal attempt's arrival from the start of each part place's minute: a place whose minute
// began exactly ReseedPartMaxAge before is taken, and one a millisecond more is not, whichever of the seal's places it
// is. Outside the reseed mode, a seal of the push route's, no place is held to it.
func TestReseedPartAgeIsJudgedAtTheSealsArrival(t *testing.T) {
	settings := DefaultEvsSettings()
	minute := BatchMinute(time.Unix(1800000000, 0))
	start := batchMinuteTime(minute)
	places := []*protocol.EvsPlace{{Minute: minute + 1, Seq: 1}, {Minute: minute, Seq: 2}}
	for _, c := range []struct {
		arrival time.Time
		reseed  bool
		stale   bool
	}{
		{arrival: start.Add(settings.ReseedPartMaxAge), reseed: true, stale: false},
		{arrival: start.Add(settings.ReseedPartMaxAge + time.Millisecond), reseed: true, stale: true},
		{arrival: start.Add(-time.Hour), reseed: true, stale: false},
		{arrival: start.Add(settings.ReseedPartMaxAge + time.Hour), reseed: false, stale: false},
	} {
		attempt := &pushAttempt{settings: settings, arrival: c.arrival}
		if c.reseed {
			attempt.reseed = &reseedAttempt{}
		}
		if stale := attempt.reseedPartPlaceStale(places); stale != c.stale {
			t.Errorf("arrival %s after the minute's start, reseed %t: stale %t, want %t", c.arrival.Sub(start), c.reseed, stale, c.stale)
		}
	}
}

// ReseedPartMaxAge is held positive and under evacuation's 25 h floor, which Resolve's fence rule for a re-seeded part
// rests on (QD-974): a seal may not take a part as old as one evacuation can judge.
func TestReseedPartMaxAgeIsHeldUnderEvacuationsFloor(t *testing.T) {
	for _, age := range []time.Duration{0, -time.Hour, evsEvacuateMinMinuteAge, evsEvacuateMinMinuteAge + time.Hour} {
		settings := DefaultEvsSettings()
		settings.ReseedPartMaxAge = age
		if err := settings.Validate(); err == nil {
			t.Errorf("a part age of %s validated", age)
		}
	}
	settings := DefaultEvsSettings()
	settings.ReseedPartMaxAge = evsEvacuateMinMinuteAge - time.Minute
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	if defaults := DefaultEvsSettings(); defaults.ReseedPartMaxAge != 24*time.Hour || defaults.Validate() != nil {
		t.Fatalf("the default part age %s", defaults.ReseedPartMaxAge)
	}
}
