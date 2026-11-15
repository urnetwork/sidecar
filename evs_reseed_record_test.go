// QD-818's reseed record of a re-seeded push's part (evs_reseed_record.go): its body is a part record's, a reseed
// record is taken at a seal's part place only when its body parses as a part's, and a one-part reseed's body is never
// a part's nor a part's a push's, so each is refused where the other belongs. The mirror's check of a sealed push's
// records takes reseed parts as part records and refuses a reseed record of the other body on either side.

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A record of recordType holding body, for statement's push.
func evsTestReseedRecord(recordType protocol.EvsBatchRecordType, statement *EvsStatement, body []byte) *EvsBatchRecord {
	push := statement.Push
	return &EvsBatchRecord{
		Type: recordType, RepoId: Id(push.GetRepoId()), RefId: Id(push.GetRefId()), PushId: Id(push.GetPushId()),
		SignerSidecarId: Id(push.GetSignerSidecarId()), TimeMs: push.GetTimeMs(), Body: body,
	}
}

// A reseed record holding a part's body, read back from its batch by its place, is a part at a seal's part place and
// is no push; one holding a push's body is no part; a posted part is a part but no reseed record; and a push or seal
// record, or a push record holding a part's body, is no part.
func TestEvsReseedRecordIsAPartOnlyWhereItsBodyIsAPartsAndAtASealsPartPlace(t *testing.T) {
	signer := newEvsTestSigner("reseed parts")
	built, _ := evsTestBuildAndCheck(t, signer, evsTestPlan(t, signer, "reseed parts", 1100))
	statement := built.Statement
	if len(built.Parts) < 2 {
		t.Fatalf("%d parts", len(built.Parts))
	}
	partBody := EvsPartRecordBody(statement.Bytes, built.Parts[0], nil, 9)
	pushBody := EvsPushRecordBody(statement.Bytes, []byte("a one-part push's payload"))

	writer := NewEvsBatchWriter(1, 2, 3, 4)
	place, err := writer.Add(evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_RESEED, statement, partBody))
	if err != nil {
		t.Fatal(err)
	}
	batchBytes, err := writer.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	read, err := NewEvsBatchReader(bytes.NewReader(batchBytes)).Record(place)
	if err != nil {
		t.Fatal(err)
	}
	if !EvsReseedRecordHoldsPart(read) {
		t.Fatal("a reseed record holding a part's body reads as no part")
	}
	partStatement, part, receipts, checkedVersion, err := ParseEvsSealPartRecord(read)
	if err != nil || !bytes.Equal(partStatement, statement.Bytes) || !bytes.Equal(part, built.Parts[0]) || len(receipts) != 0 || checkedVersion != 9 {
		t.Fatalf("the part read back: %d receipts, checked at %d: %v", len(receipts), checkedVersion, err)
	}
	if _, _, err := ParseEvsPushRecordBody(read.Body); !errors.Is(err, ErrEvsPushInvalid) {
		t.Fatalf("a part's body read as a push's: %v", err)
	}

	reseedPush := evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_RESEED, statement, pushBody)
	if EvsReseedRecordHoldsPart(reseedPush) {
		t.Fatal("a one-part reseed record reads as a part")
	}
	if _, _, _, _, err := ParseEvsSealPartRecord(reseedPush); !errors.Is(err, ErrEvsPushInvalid) {
		t.Fatalf("a one-part reseed record at a seal's part place: %v", err)
	}

	posted := evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_PART, statement, EvsPartRecordBody(statement.Bytes, built.Parts[0], [][]byte{[]byte("receipt")}, 3))
	if EvsReseedRecordHoldsPart(posted) {
		t.Fatal("a posted part reads as a reseed record")
	}
	if _, _, receipts, _, err := ParseEvsSealPartRecord(posted); err != nil || len(receipts) != 1 {
		t.Fatalf("a posted part at a seal's part place: %d receipts, %v", len(receipts), err)
	}
	for _, other := range []*EvsBatchRecord{
		evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_PUSH, statement, pushBody),
		evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_PUSH, statement, partBody),
		evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_SEAL, statement, partBody),
	} {
		if _, _, _, _, err := ParseEvsSealPartRecord(other); !errors.Is(err, ErrEvsPushInvalid) {
			t.Fatalf("a record of type %s at a seal's part place: %v", other.Type, err)
		}
		if EvsReseedRecordHoldsPart(other) {
			t.Fatalf("a record of type %s reads as a re-seeded part", other.Type)
		}
	}
}

// A mirror's check of a sealed push's records takes its parts as reseed records holding a part's body, alone or beside
// posted parts, and refuses a reseed record holding a push's body at a part's place; a one-part push's reseed record
// holding a part's body is refused too.
func TestEvsMirrorTakesAReseededPushInPartsAndRefusesABodyOutOfPlace(t *testing.T) {
	signer := newEvsTestSigner("mirror parts")
	built, _ := evsTestBuildAndCheck(t, signer, evsTestPlan(t, signer, "mirror parts", 1100))
	statement := built.Statement
	sealParts := []*EvsSealPart{}
	for i, partBytes := range built.Parts {
		checked, err := EvsCheckPart(statement, partBytes)
		if err != nil {
			t.Fatal(err)
		}
		sealParts = append(sealParts, &EvsSealPart{Place: &protocol.EvsPlace{Minute: uint32(i + 1)}, ChangesRoot: checked.Root, FirstTokenPath: checked.FirstTokenPath()})
	}
	seal := evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_SEAL, statement, EvsSealRecordBody(statement.Bytes, sealParts)).encode()
	partRecord := func(recordType protocol.EvsBatchRecordType, index int) []byte {
		receipts := [][]byte{}
		if recordType == protocol.EvsBatchRecordType_EVS_BATCH_PART {
			receipts = append(receipts, []byte("receipt"))
		}
		return evsTestReseedRecord(recordType, statement, EvsPartRecordBody(statement.Bytes, built.Parts[index], receipts, 7)).encode()
	}
	records := [][]byte{seal}
	for i := range built.Parts {
		records = append(records, partRecord(protocol.EvsBatchRecordType_EVS_BATCH_RESEED, i))
	}
	payload, err := evsMirrorCheckRecords(statement, records)
	if err != nil || len(payload.Changes) != 1100 {
		t.Fatalf("a re-seeded push in parts: %v", err)
	}
	records[1] = partRecord(protocol.EvsBatchRecordType_EVS_BATCH_PART, 0)
	if _, err := evsMirrorCheckRecords(statement, records); err != nil {
		t.Fatalf("a posted part beside a re-seeded one: %v", err)
	}
	records[len(records)-1] = evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_RESEED, statement, EvsPushRecordBody(statement.Bytes, built.Parts[len(built.Parts)-1])).encode()
	if _, err := evsMirrorCheckRecords(statement, records); !errors.Is(err, ErrEvsMirrorRecordInvalid) {
		t.Fatalf("a one-part reseed body at a part's place: %v", err)
	}

	onePart, _ := evsTestBuildAndCheck(t, signer, evsTestPlan(t, signer, "mirror one part", 3))
	reseeded := evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_RESEED, onePart.Statement, EvsPushRecordBody(onePart.Statement.Bytes, onePart.Payload)).encode()
	if _, err := evsMirrorCheckRecords(onePart.Statement, [][]byte{reseeded}); err != nil {
		t.Fatalf("a one-part reseed record: %v", err)
	}
	misplaced := evsTestReseedRecord(protocol.EvsBatchRecordType_EVS_BATCH_RESEED, onePart.Statement, EvsPartRecordBody(onePart.Statement.Bytes, onePart.Payload, nil, 1)).encode()
	if _, err := evsMirrorCheckRecords(onePart.Statement, [][]byte{misplaced}); !errors.Is(err, ErrEvsMirrorRecordInvalid) {
		t.Fatalf("a part's body at a one-part push's place: %v", err)
	}
}
