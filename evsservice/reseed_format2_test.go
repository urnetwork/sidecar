// EVS2-M10-13's re-seed of a format-2 repo on T2 (reseed_format2.go, FS-70's re-seed clauses, FS-96's re-seed
// clause to the purge's hand-off): a repo admin's device walks a mirror holding only a versionless path's newest
// content, and the replaced version returns as its statement and entry version, its replacement's record listing the
// replaced content for the purge; a stale mirror's upload of that content is refused at its version's call and handed
// to the purge; a mirror whose copy ends before the replacement re-seeds the replaced version's content as newest;
// staged heads come back as ordinary kind-5 uploads, the re-seeded record carrying no staged tail, and a replaced
// version's staged content is not sent; and a network outside the format2 gate, or a format-1 instance, takes none.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A format-2 history as a lost site committed it: each version's statement and record bytes, its tail included, and
// the ref's chain after it.
type reseedFormat2History struct {
	statements [][]byte
	records    [][]byte
	chains     [][32]byte
	// the kind-5 uploads and staged segments the site's pushes introduced, by id
	segments map[[32]byte][]byte
}

// A lost site in format 2: a push fixture with the format2 gate open and format 2's own rules.
func newReseedFormat2Site(t *testing.T) (*pushFixture, *reseedFormat2History) {
	t.Helper()
	site := newPushFixture(t, nil)
	site.openFormat2Checked()
	return site, &reseedFormat2History{segments: map[[32]byte][]byte{}}
}

// The bytes of a kind-5 segment of plan's push holding label: a kind-5 header of this repo naming the push, padded to a
// Padmé length.
func reseedTestKind5Bytes(plan *sidecar.EvsPushPlan, label string) []byte {
	segment := make([]byte, int(sidecar.EvsPadme(1000)))
	copy(segment, "URvs")
	segment[4] = 2
	copy(segment[8:24], plan.RepoId[:])
	segment[31] = 1
	copy(segment[32:48], plan.PushId[:])
	copy(segment[48:], []byte("kind-5 upload "+label))
	return segment
}

// A versionless version of path at version on base, its one kind-5 locator an upload of plan's push holding label: the
// upload's id, its bytes kept in history, and its receipt marked versionless.
func (self *reseedFormat2History) upload(site *pushFixture, plan *sidecar.EvsPushPlan, path sidecar.EvsTokenPath, base uint64, version uint64, label string) ([32]byte, *protocol.EvsUploadReceipt) {
	t := site.t
	t.Helper()
	segment := reseedTestKind5Bytes(plan, label)
	segmentId := sha256.Sum256(segment)
	uploadTime := site.clock.Now().Add(-time.Minute)
	receipt, err := IssueUploadReceipt(site.check.receiptKeys, site.check.repoId, segmentId, uint64(len(segment)), uploadTime, site.check.signerId, true, site.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	plan.NewObjects = append(plan.NewObjects, &sidecar.EvsNewObject{
		Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: segmentId[:], PaddedSize: uint64(len(segment)),
		UploadDay: uint32(uploadTime.UnixMilli() / evsUploadDayMs),
	})
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: path, BaseEntryVersion: base,
		EntryVersion: site.check.versionedEntry(plan, version, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(segmentId, false)),
	})
	self.segments[segmentId] = segment
	return segmentId, receipt
}

// A versionless version of path at version on base staged in plan's push, holding label: its staged segment's id and
// bytes, which the request carries outside every hash.
func (self *reseedFormat2History) staged(site *pushFixture, plan *sidecar.EvsPushPlan, path sidecar.EvsTokenPath, base uint64, version uint64, label string) ([32]byte, []byte) {
	t := site.t
	t.Helper()
	segment, staged := checkTestStaged(t, plan, label)
	plan.NewObjects = append(plan.NewObjects, staged.NewObject())
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: path, BaseEntryVersion: base,
		EntryVersion: site.check.versionedEntry(plan, version, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(staged.Id, true)),
	})
	self.segments[staged.Id] = segment
	return staged.Id, segment
}

// Commits body at the site as the history's next version and keeps its statement, record and chain.
func (self *reseedFormat2History) commit(site *pushFixture, body *protocol.EvsPushRequest) {
	t := site.t
	t.Helper()
	version := uint64(len(self.statements) + 1)
	site.requireCommitted(site.post(site.token(site.check.signerId), body), version)
	site.awaitStepEights()
	head := site.head()
	entry := windowEntryAt(head.Head, version)
	if entry == nil {
		t.Fatalf("no window entry at %d", version)
	}
	recordBytes, err := site.engine.readRecordBytesAt(site.ctx, site.cluster, site.check.repoId, site.check.refId, entry.Place)
	if err != nil {
		t.Fatal(err)
	}
	self.statements = append(self.statements, body.GetStatement())
	self.records = append(self.records, recordBytes)
	self.chains = append(self.chains, [32]byte(head.Head.GetChain()))
}

// The new site in its recovery with the format2 gate open to its network, or closed, and a recording purge sink.
func (self *reseedFixture) gateFormat2(admitted bool) *recordingPurgeSink {
	self.t.Helper()
	text := "sidecar:\n  evs:\n    enabled: true\n    networks: [\"" + self.check.networkId.String() + "\"]\n  reseed: true\n"
	if admitted {
		text += fmt.Sprintf("  format2: {enabled: true, networks: [%q]}\n", connect.Id(self.check.networkId).String())
	}
	if err := self.host.Gates.Set(text); err != nil {
		self.t.Fatal(err)
	}
	self.engine.deps.Format2Rules = nil
	sink := &recordingPurgeSink{}
	self.engine.deps.Purge = sink
	return sink
}

// A device reading format 2 whose mirror holds history's versions through through, and the segments named.
func (self *reseedFixture) format2Device(history *reseedFormat2History, through uint64, segments ...[32]byte) *reseedDevice {
	t := self.t
	t.Helper()
	device := self.device()
	device.client.EnableFormat2Reader()
	refId := self.check.refId
	for version := uint64(1); version <= through; version += 1 {
		statement, err := sidecar.ParseEvsStatementFormat2(history.statements[version-1])
		if err != nil {
			t.Fatal(err)
		}
		if err := device.mirror.Put(sidecar.EvsMirrorStatementKey(refId, version), bytes.NewReader(statement.Bytes)); err != nil {
			t.Fatal(err)
		}
		recordKey := sidecar.EvsMirrorRecordKey(sidecar.Id(statement.Push.GetPushId()), 0)
		if err := device.mirror.Put(recordKey, bytes.NewReader(history.records[version-1])); err != nil {
			t.Fatal(err)
		}
	}
	for _, segmentId := range segments {
		if err := device.mirror.Put(sidecar.EvsMirrorSegmentKey(segmentId[:]), bytes.NewReader(history.segments[segmentId])); err != nil {
			t.Fatal(err)
		}
	}
	ref := &sidecar.EvsMirrorRef{RefId: refId, Version: through, Chain: history.chains[through-1], MirroredAt: self.clock.Now()}
	if err := device.mirror.RaiseRef(ref); err != nil {
		t.Fatal(err)
	}
	return device
}

// The device's walk and its one ref, once every step 8 of the commits it made has finished.
func (self *reseedDevice) reseedFormat2() (*sidecar.EvsReseedResult, *sidecar.EvsReseedRef) {
	t := self.fixture.t
	t.Helper()
	result, err := self.client.Repo(self.fixture.check.repoId).Reseed(self.fixture.ctx, &sidecar.EvsReseedArgs{})
	if err != nil {
		t.Fatal(err)
	}
	self.fixture.awaitStepEights()
	if len(result.Refs) != 1 || result.Refs[0].RefId != self.fixture.check.refId {
		t.Fatalf("a walk of %d refs", len(result.Refs))
	}
	return result, result.Refs[0]
}

// The record the new site holds at the ref's version, with its format-2 tail.
func (self *reseedFixture) recordFormat2At(version uint64) (*sidecar.EvsBatchRecord, *sidecar.EvsBatchRecordTail) {
	self.t.Helper()
	entry := windowEntryAt(self.head().Head, version)
	if entry == nil {
		self.t.Fatalf("no window entry at %d", version)
	}
	recordBytes, err := self.engine.readRecordBytesAt(self.ctx, self.cluster, self.check.repoId, self.check.refId, entry.Place)
	if err != nil {
		self.t.Fatal(err)
	}
	record, tail, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
	if err != nil {
		self.t.Fatal(err)
	}
	return record, tail
}

// x written versionless at 1 and overwritten at 2, each content one kind-5 upload.
func reseedFormat2Overwrite(t *testing.T) (*reseedFormat2History, [32]byte, [32]byte) {
	t.Helper()
	site, history := newReseedFormat2Site(t)
	x := checkTestPath("x")
	first := site.plan()
	firstId, firstReceipt := history.upload(site, first, x, 0, 1, "v1")
	body := site.bodyFormat2(first)
	body.Receipts = []*protocol.EvsUploadReceipt{firstReceipt}
	history.commit(site, body)
	second := site.plan()
	secondId, secondReceipt := history.upload(site, second, x, 1, 2, "v2")
	body = site.bodyFormat2(second)
	body.Receipts = []*protocol.EvsUploadReceipt{secondReceipt}
	history.commit(site, body)
	return history, firstId, secondId
}

// FS-70: a mirror holding only the newest version's content re-seeds the ref whole. The replaced version goes as its
// statement and entry version with no content, the replacement's content as an upload, and the replacement's
// re-seeded record lists the replaced content, handed to the purge as a commit's.
func TestReseedFormat2FromAMirrorOfNewestVersionsOnly(t *testing.T) {
	history, firstId, secondId := reseedFormat2Overwrite(t)
	fixture := newReseedFixture(t)
	sink := fixture.gateFormat2(true)
	device := fixture.format2Device(history, 2, secondId)
	result, ref := device.reseedFormat2()
	if ref.Stopped != nil || ref.Version != 2 || ref.Chain != history.chains[1] {
		t.Fatalf("the walk ended at %d, stopped by %v", ref.Version, ref.Stopped)
	}
	if result.SegmentCount != 1 || result.CollectedCount != 1 || result.StagedCount != 0 {
		t.Fatalf("%d segments sent, %d collected, %d staged", result.SegmentCount, result.CollectedCount, result.StagedCount)
	}
	if fixture.segmentStored(firstId) || !fixture.segmentStored(secondId) {
		t.Fatalf("seg/ holds the replaced content %v, the newest %v", fixture.segmentStored(firstId), fixture.segmentStored(secondId))
	}
	record, tail := fixture.recordFormat2At(2)
	if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || tail == nil || len(tail.Staged) != 0 {
		t.Fatalf("the replacement's record of type %d with %d staged bytes", record.Type, len(tail.Staged))
	}
	list, err := tail.PurgeListValue()
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetCandidates()) != 1 || len(list.GetCandidates()[0].GetSegmentIds()) != 1 ||
		[32]byte(list.GetCandidates()[0].GetSegmentIds()[0]) != firstId {
		t.Fatalf("the replacement's list: %v", list)
	}
	commits := sink.all()
	if len(commits) != 1 || commits[0].Version != 2 || len(commits[0].Replaced) != 1 || commits[0].Replaced[0].Version.GetVersion() != 1 {
		t.Fatalf("the purge was handed %d lists", len(commits))
	}
}

// FS-70: after a re-seed from a mirror of newest versions, a stale mirror that never applied the replacement uploads
// the replaced content, and its version's call is refused 409 VERSIONING, the content handed to the purge as the
// replacement's list named it: the stale mirror's ref stops there, having nothing past it evs lacks.
func TestReseedFormat2RefusesAStaleMirrorsReplacedContent(t *testing.T) {
	history, firstId, secondId := reseedFormat2Overwrite(t)
	fixture := newReseedFixture(t)
	sink := fixture.gateFormat2(true)
	if _, ref := fixture.format2Device(history, 2, secondId).reseedFormat2(); ref.Stopped != nil || ref.Version != 2 {
		t.Fatalf("the newest mirror's walk ended at %d, stopped by %v", ref.Version, ref.Stopped)
	}
	listed := len(sink.all())

	stale := fixture.format2Device(history, 1, firstId)
	result, ref := stale.reseedFormat2()
	if !sidecar.IsEvsRefusal(ref.Stopped, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING) || ref.Version != 0 {
		t.Fatalf("the stale walk ended at %d, stopped by %v", ref.Version, ref.Stopped)
	}
	if result.SegmentCount != 1 || result.CollectedCount != 0 {
		t.Fatalf("the stale walk sent %d segments, %d collected", result.SegmentCount, result.CollectedCount)
	}
	commits := sink.all()[listed:]
	if len(commits) != 1 || commits[0].Version != 2 || len(commits[0].List.GetCandidates()) != 1 ||
		len(commits[0].List.GetCandidates()[0].GetSegmentIds()) != 1 || [32]byte(commits[0].List.GetCandidates()[0].GetSegmentIds()[0]) != firstId ||
		commits[0].List.GetCandidates()[0].GetReplacedVersion() != 1 || len(commits[0].Replaced) != 1 {
		t.Fatalf("the stale upload handed the purge %d lists", len(commits))
	}
	if head := fixture.head(); head.Version() != 2 || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("head at %d with %d bytes of refusals", head.Version(), len(head.Head.GetRefused()))
	}
}

// FS-70: a mirror whose copy ends before the replacement re-seeds the replaced version's content as newest, which is
// correct for that head.
func TestReseedFormat2MirrorEndingBeforeTheReplacement(t *testing.T) {
	history, firstId, secondId := reseedFormat2Overwrite(t)
	fixture := newReseedFixture(t)
	sink := fixture.gateFormat2(true)
	result, ref := fixture.format2Device(history, 1, firstId).reseedFormat2()
	if ref.Stopped != nil || ref.Version != 1 || ref.Chain != history.chains[0] {
		t.Fatalf("the walk ended at %d, stopped by %v", ref.Version, ref.Stopped)
	}
	if result.SegmentCount != 1 || result.CollectedCount != 0 || !fixture.segmentStored(firstId) || fixture.segmentStored(secondId) {
		t.Fatalf("%d segments sent, %d collected", result.SegmentCount, result.CollectedCount)
	}
	if commits := sink.all(); len(commits) != 0 {
		t.Fatalf("a creation handed the purge %d lists", len(commits))
	}
}

// A versionless version no held version replaces whose kind-5 content the mirror lacks stops the ref, as any missing
// segment does, and nothing of it is sent.
func TestReseedFormat2StopsOnANewestVersionsMissingContent(t *testing.T) {
	history, _, _ := reseedFormat2Overwrite(t)
	fixture := newReseedFixture(t)
	fixture.gateFormat2(true)
	result, ref := fixture.format2Device(history, 2).reseedFormat2()
	if !errors.Is(ref.Stopped, sidecar.ErrEvsReseedMirrorPartial) || ref.Version != 1 {
		t.Fatalf("the walk ended at %d, stopped by %v", ref.Version, ref.Stopped)
	}
	if result.CollectedCount != 1 || result.SegmentCount != 0 {
		t.Fatalf("%d segments sent, %d collected", result.SegmentCount, result.CollectedCount)
	}
}

// FS-70: staged heads re-upload as segments. y staged at 1 and again at 2, z staged at 3: the replaced version's
// staged content is not sent, each newest version's goes through PUT .../segments before its call, and no re-seeded
// record carries a staged tail.
func TestReseedFormat2StagedHeadsReuploadAsSegments(t *testing.T) {
	site, history := newReseedFormat2Site(t)
	y, z := checkTestPath("y"), checkTestPath("z")
	stage := func(path sidecar.EvsTokenPath, base uint64, version uint64, label string) [32]byte {
		t.Helper()
		plan := site.plan()
		segmentId, segment := history.staged(site, plan, path, base, version, label)
		body := site.bodyFormat2(plan)
		body.Staged = sidecar.EvsEncodeStaged([][]byte{segment})
		history.commit(site, body)
		return segmentId
	}
	replaced := stage(y, 0, 1, "y1")
	newest := stage(y, 1, 2, "y2")
	other := stage(z, 0, 3, "z3")
	if _, tail := (&reseedFixture{pushFixture: site}).recordFormat2At(1); tail == nil || len(tail.Staged) == 0 {
		t.Fatal("the lost site's record carries no staged tail")
	}

	fixture := newReseedFixture(t)
	fixture.gateFormat2(true)
	result, ref := fixture.format2Device(history, 3).reseedFormat2()
	if ref.Stopped != nil || ref.Version != 3 {
		t.Fatalf("the walk ended at %d, stopped by %v", ref.Version, ref.Stopped)
	}
	if result.StagedCount != 2 || result.CollectedCount != 1 || result.SegmentCount != 2 {
		t.Fatalf("%d staged sent, %d collected, %d segments", result.StagedCount, result.CollectedCount, result.SegmentCount)
	}
	if fixture.segmentStored(replaced) || !fixture.segmentStored(newest) || !fixture.segmentStored(other) {
		t.Fatal("seg/ does not hold exactly the newest versions' staged content")
	}
	for version := uint64(1); version <= 3; version += 1 {
		if _, tail := fixture.recordFormat2At(version); tail != nil && len(tail.Staged) != 0 {
			t.Fatalf("the re-seeded record at %d carries %d staged bytes", version, len(tail.Staged))
		}
	}
}

// A network outside the format2 gate re-seeds no format-2 push: 409 VERSIONING, refusing and committing nothing.
func TestReseedFormat2OutsideTheGate(t *testing.T) {
	history, firstId, _ := reseedFormat2Overwrite(t)
	fixture := newReseedFixture(t)
	fixture.gateFormat2(false)
	body := &protocol.EvsReseedRequest{Statement: history.statements[0], Payload: reseedFormat2Payload(t, history.records[0])}
	requireRefusal(t, fixture.reseed(body), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)
	if fixture.head().Version() != 0 || fixture.segmentStored(firstId) {
		t.Fatal("a re-seed outside the gate committed")
	}
}

// A format-1 instance answers a format-2 re-seed 409 FORMAT_UNSUPPORTED {needs_format: 2}, recording nothing.
func TestReseedFormat2AtAFormat1Instance(t *testing.T) {
	history, _, _ := reseedFormat2Overwrite(t)
	fixture := reseedFixtureOf(newPushFixture(t, func(settings *EvsSettings) { settings.InstanceFormat = sidecar.EvsRepoFormat1 }))
	body := &protocol.EvsReseedRequest{Statement: history.statements[0], Payload: reseedFormat2Payload(t, history.records[0])}
	recorder := fixture.reseed(body)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED)
	if reply := refusalOf(t, recorder); reply.GetNeedsFormat() != 2 {
		t.Fatalf("needs_format %d", reply.GetNeedsFormat())
	}
	if head := fixture.head(); head.Version() != 0 || len(head.Head.GetRefused()) != 0 {
		t.Fatal("a format-1 instance committed or recorded a format-2 re-seed")
	}
}

// A record's payload as a reseed call carries it: the record body's, with no tail.
func reseedFormat2Payload(t *testing.T, recordBytes []byte) []byte {
	t.Helper()
	record, _, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := sidecar.ParseEvsPushRecordBody(record.Body)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
