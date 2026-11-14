// QD-735 on evs (question evs1-m2-01-inline-record-home): an inline record rides only inside its entry version's
// kind-2 locator. A push or part carrying section 3 or inline_records is refused INVALID, recording nothing; each
// version's record is stored once, in its push's batch record; a fold keeps the newest version whole and elides the
// older ones, cutting their inline bytes and nothing else; a read by number serves each elided version byte for byte
// as its push carried it; 5h adopts nothing for a kind-2 locator and refuses one holding no record; and a dropped
// version's entry version is served only when its chain names no inline record.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A section's items, each u32 length | bytes.
func inlineTestItems(items ...[]byte) []byte {
	encoded := []byte{}
	for _, item := range items {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(item)))
		encoded = append(encoded, item...)
	}
	return encoded
}

// 64 bytes no other test value shares, standing for one sealed inline record.
func inlineTestRecord(label string) []byte {
	first := sha256.Sum256([]byte("inline test record " + label))
	second := sha256.Sum256(first[:])
	return append(first[:], second[:]...)
}

// A one-part push whose payload carries section 3, and parts carrying inline_records or section 3 among their
// sections, answer 400 INVALID, recording nothing and writing no head; the same push with its record in its locator
// alone commits, and the same part answers its place.
func TestPushRefusesInlineRecordsOutsideTheirLocators(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	record := inlineTestRecord("beside its locator")
	plan := fixture.plan()
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("a"),
		EntryVersion: fixture.check.fileEntry(plan, 1, []*protocol.EvsLocator{
			{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: record},
		}),
	})
	body := fixture.body(plan)
	payload, err := sidecar.ParseEvsPayload(body.GetPayload())
	if err != nil {
		t.Fatal(err)
	}
	payload.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_INLINE_RECORDS, inlineTestItems(record))
	recorder := fixture.post(token, &protocol.EvsPushRequest{Statement: body.GetStatement(), Payload: payload.Encode()})
	requireRefusal(t, recorder, http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	if refusalOf(t, recorder).GetRecorded() || !fixture.head().Absent() {
		t.Fatal("section 3's refusal was recorded or wrote a head")
	}
	// the twin: the record in its locator alone
	fixture.requireCommitted(fixture.post(token, body), 1)
	fixture.awaitStepEights()

	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	pushId := sidecar.Id(built.Statement.Push.GetPushId())
	postFirstPart := func(partBytes []byte) *httptest.ResponseRecorder {
		return fixture.call(token, http.MethodPost, "/push/"+sidecar.EvsKeyId(pushId)+"/1",
			&protocol.EvsPartRequest{Statement: built.Statement.Bytes, Part: partBytes})
	}
	withField := &protocol.EvsPushPart{}
	if err := proto.Unmarshal(built.Parts[0], withField); err != nil {
		t.Fatal(err)
	}
	withField.InlineRecords = [][]byte{record}
	withFieldBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(withField)
	if err != nil {
		t.Fatal(err)
	}
	withSection := &protocol.EvsPushPart{}
	if err := proto.Unmarshal(built.Parts[0], withSection); err != nil {
		t.Fatal(err)
	}
	sections, err := sidecar.ParseEvsPayload(withSection.GetSections())
	if err != nil {
		t.Fatal(err)
	}
	sections.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_INLINE_RECORDS, inlineTestItems(record))
	withSection.Sections = sections.Encode()
	withSectionBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(withSection)
	if err != nil {
		t.Fatal(err)
	}
	batches := func() int {
		count := 0
		for key := range fixture.host.Blobs.Dump() {
			if strings.HasPrefix(key, "meta-1/"+batchKeyPrefix) {
				count += 1
			}
		}
		return count
	}
	before := batches()
	for label, partBytes := range map[string][]byte{"inline_records": withFieldBytes, "section 3 among its sections": withSectionBytes} {
		recorder := postFirstPart(partBytes)
		requireRefusal(t, recorder, http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		if refusalOf(t, recorder).GetRecorded() {
			t.Errorf("a part's %s: its refusal answered recorded", label)
		}
	}
	if got := batches(); got != before {
		t.Fatalf("refused parts wrote %d batches", got-before)
	}
	if fixture.head().Version() != 1 {
		t.Fatal("a refused part moved the head")
	}
	// the twin: the part as built
	fixture.requirePlace(fixture.postPart(token, built, 0))
}

// Three versions of a file, each one fresh inline record: each record is stored once in the batch records; the fold
// keeps the newest whole in idx/ and elides the two older ones, their inline bytes cut and nothing else; and a read by
// number serves each older version byte for byte as its push carried it, restored from the push record, as it serves
// the newest from the entry.
func TestFoldElidesOlderInlineRecordsAndReadRestoresThem(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	path := checkTestPath("small")
	records := [][]byte{}
	entries := [][]byte{}
	for version := uint64(1); version <= 3; version += 1 {
		plan := fixture.plan()
		record := inlineTestRecord(fmt.Sprint("version ", version))
		entry := fixture.check.fileEntry(plan, version, []*protocol.EvsLocator{
			{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: record},
		})
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: path, BaseEntryVersion: version - 1, EntryVersion: entry})
		fixture.requireCommitted(fixture.push(plan), version)
		fixture.awaitStepEights()
		records = append(records, record)
		entries = append(entries, entry)
	}
	stored := func(prefix string, record []byte) int {
		count := 0
		for key, object := range fixture.host.Blobs.Dump() {
			if strings.HasPrefix(key, "meta-1/"+prefix) {
				count += bytes.Count(object, record)
			}
		}
		return count
	}
	for i, record := range records {
		if count := stored(batchKeyPrefix, record); count != 1 {
			t.Fatalf("version %d's record is in the batches %d times", i+1, count)
		}
	}

	fixture.foldRef()
	versions := fixture.entryAt(1, "small").Entry.GetVersions()
	if len(versions) != 3 {
		t.Fatalf("the entry holds %d versions", len(versions))
	}
	if versions[0].GetElided() || !bytes.Equal(versions[0].GetEntryVersion(), entries[2]) {
		t.Fatal("the newest version is not held whole")
	}
	for i, version := range versions[1:] {
		original := entries[1-i]
		cut := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(original, cut); err != nil {
			t.Fatal(err)
		}
		for _, locator := range cut.GetChain() {
			locator.Inline = nil
		}
		cutBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(cut)
		if err != nil {
			t.Fatal(err)
		}
		if !version.GetElided() || !bytes.Equal(version.GetEntryVersion(), cutBytes) || bytes.Contains(version.GetEntryVersion(), records[1-i]) {
			t.Fatalf("version %d is not held with its inline record cut and nothing else", 2-i)
		}
	}
	for i, record := range records {
		want := 0
		if i == 2 {
			want = 1
		}
		if count := stored("idx/", record); count != want {
			t.Fatalf("version %d's record is in idx/ %d times, want %d", i+1, count, want)
		}
	}

	for version := uint64(0); version <= 3; version += 1 {
		reply := fixture.read(token, &protocol.EvsReadRequest{
			RefId: fixture.check.refId.Bytes(),
			Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: path.Components()}}, Version: version}},
		})
		pathReply := reply.paths[0]
		want := entries[2]
		if version != 0 {
			want = entries[version-1]
		}
		served := pathReply.GetVersion()
		if served.GetElided() || !bytes.Equal(served.GetEntryVersion(), want) {
			t.Fatalf("version %d is not served as its push carried it", version)
		}
		requireVersionProven(t, reply, pathReply, path)
	}
}

// 5h adopts nothing for a kind-2 locator: a version whose chain is inline records alone passes with no receipt, no new
// object and no version read, as one-part push and as part; one whose kind-2 locator holds no record, the elided form
// only idx/ keeps, is refused INVALID, which the codecs refuse first.
func TestCheckObjectsAdoptsNothingForAnInlineRecord(t *testing.T) {
	fixture := newCheckFixture(t)
	path := checkTestPath("a")
	plan := fixture.plan()
	chain := []*protocol.EvsLocator{
		{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: inlineTestRecord("a checkpoint and its key block")},
		{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: inlineTestRecord("a diff under the chain's key")},
	}
	plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: path, EntryVersion: fixture.fileEntry(plan, 1, chain)}}
	for _, stage := range []PushStage{PushStageOnePart, PushStagePart} {
		view := fixture.view(plan)
		view.Stage = stage
		requireCheckPass(t, fmt.Sprintf("an inline chain at stage %d", stage), CheckObjects(view))
	}

	elided := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(plan.Changes[0].EntryVersion, elided); err != nil {
		t.Fatal(err)
	}
	elided.Chain[1].Inline = nil
	elidedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(elided)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []PushStage{PushStageOnePart, PushStagePart} {
		view := fixture.view(plan)
		view.Stage = stage
		view.Payload.Changes[0].EntryVersion = elidedBytes
		requireCheckRefusal(t, fmt.Sprintf("an inline locator holding no record at stage %d", stage), CheckObjects(view), EvsCheckReasonInvalid)
	}
	cutPlan := fixture.plan()
	cutPlan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: path, EntryVersion: fixture.fileEntry(cutPlan, 1, elided.Chain)}}
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.signingKey, fixture.signerId)).Build(cutPlan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.EvsCheckPayload(built.Statement, built.Payload); sidecar.EvsRefusalCodeOf(err) != protocol.EvsRefusalCode_EVS_REFUSAL_INVALID {
		t.Fatalf("the codec took an inline locator holding no record: %v", err)
	}
}

// §11.9's serve row on QD-735: a dropped version's entry version is served only when its chain names no inline
// record; one naming an inline record, whole or elided, among segment locators or alone, is not, nor are bytes that
// are no entry version.
func TestDroppedVersionNamingAnInlineRecordIsNotServed(t *testing.T) {
	fixture := newCheckFixture(t)
	plan := fixture.plan()
	segment := checkTestSegmentLocator(sha256.Sum256([]byte("dropped segment")))
	inline := &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: inlineTestRecord("dropped")}
	segmentEntry := fixture.fileEntry(plan, 1, []*protocol.EvsLocator{segment})
	if served := droppedEntryVersionServed(segmentEntry); !bytes.Equal(served, segmentEntry) {
		t.Fatal("a dropped version of segments alone is not served")
	}
	directoryEntry := fixture.directoryEntry(plan, 1, []*protocol.EvsName{{Token: bytes.Repeat([]byte{1}, sidecar.EvsTokenByteCount), Kind: 1, SealedName: []byte("name")}}, nil)
	if served := droppedEntryVersionServed(directoryEntry); !bytes.Equal(served, directoryEntry) {
		t.Fatal("a dropped directory delta is not served")
	}
	inlineEntry := fixture.fileEntry(plan, 1, []*protocol.EvsLocator{inline})
	elided := elideEvsIndexVersion(&protocol.EvsIndexVersion{EntryVersion: inlineEntry})
	if !elided.GetElided() {
		t.Fatal("the inline version did not elide")
	}
	withheld := map[string][]byte{
		"an inline record":                inlineEntry,
		"an inline record elided":         elided.GetEntryVersion(),
		"an inline record among segments": fixture.fileEntry(plan, 1, []*protocol.EvsLocator{segment, inline}),
		"bytes that are no entry version": {0xff, 0xff},
		"no bytes":                        nil,
	}
	for label, entryBytes := range withheld {
		if served := droppedEntryVersionServed(entryBytes); served != nil {
			t.Errorf("a dropped version naming %s was served", label)
		}
	}
}
