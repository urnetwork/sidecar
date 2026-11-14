// §22.5's batch and window vectors on every leg, and §22.6's batch-record and window-entry targets: batches tile and
// hash as §11.8 lays them out, records read back by their places, refusal records and the code table hold, and
// tampering is refused before anything is adopted.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

//go:embed testdata/evs/batch_vectors.json
var evsBatchVectorsJson []byte

//go:embed testdata/evs/window_vectors.json
var evsWindowVectorsJson []byte

// A batch holding a push, a part, a seal and a reseed record, each body as §11.8's record row orders it.
func evsTestBatch(t testing.TB) (*EvsBatchWriter, []*EvsBatchRecord) {
	t.Helper()
	writer := NewEvsBatchWriter(0x0a0b0c0d, 29453760, 7, 1767225600123)
	statement := evsTestBody(200)
	place := &protocol.EvsPlace{Minute: 29453760, Instance: 0x0a0b0c0d, Seq: 6, Offset: 32, Length: 500}
	records := []*EvsBatchRecord{
		{Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, Body: EvsPushRecordBody(statement, evsTestBytes("payload", 32))},
		{Type: protocol.EvsBatchRecordType_EVS_BATCH_PART, Body: EvsPartRecordBody(statement, evsTestBytes("part", 32), [][]byte{evsTestBytes("receipt", 32)}, 41)},
		{Type: protocol.EvsBatchRecordType_EVS_BATCH_SEAL, Body: EvsSealRecordBody(statement, []*EvsSealPart{
			{Place: place, ChangesRoot: [32]byte(evsTestBytes("root 1", 32)), FirstTokenPath: EvsTokenPath{evsTestToken("a")}},
			{Place: place, ChangesRoot: [32]byte(evsTestBytes("root 2", 32)), FirstTokenPath: EvsTokenPath{evsTestToken("b"), evsTestToken("c")}},
		})},
		{Type: protocol.EvsBatchRecordType_EVS_BATCH_RESEED, Body: EvsPushRecordBody(statement, evsTestBytes("reseed payload", 16))},
	}
	for i, record := range records {
		record.RepoId = evsTestId("repo")
		record.RefId = evsTestId("ref main")
		record.PushId = evsTestId("push " + string(rune('a'+i)))
		record.SignerSidecarId = evsTestId("sidecar writer")
		record.TimeMs = 1767225600000 + int64(i)
		if _, err := writer.Add(record); err != nil {
			t.Fatal(err)
		}
	}
	return writer, records
}

// What testdata/evs/batch_vectors.json holds.
type evsBatchVectors struct {
	Batch  hexBytes                `json:"batch"`
	Places []*evsRecordPlaceVector `json:"places"`
}

func computeEvsBatchVectors(t *testing.T) *evsBatchVectors {
	writer, _ := evsTestBatch(t)
	batchBytes, err := writer.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ParseEvsBatch(batchBytes)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &evsBatchVectors{Batch: batchBytes}
	for i, place := range batch.Places {
		vectors.Places = append(vectors.Places, &evsRecordPlaceVector{Offset: place.GetOffset(), Length: place.GetLength(), BodyLength: uint64(len(batch.Records[i].Body))})
	}
	return vectors
}

// The stored batch is what this build writes, and §11.8's layout read apart from evs_batch.go: the header's fields,
// the index tiling the records, and the trailer's hash.
func TestEvsBatchVectors(t *testing.T) {
	stored := &evsBatchVectors{}
	if !compareEvsVectors(t, "testdata/evs/batch_vectors.json", evsBatchVectorsJson, computeEvsBatchVectors(t), stored) {
		return
	}
	batchBytes := []byte(stored.Batch)
	if string(batchBytes[0:4]) != "URpb" || batchBytes[4] != 1 || binary.BigEndian.Uint32(batchBytes[8:12]) != 0x0a0b0c0d ||
		binary.BigEndian.Uint32(batchBytes[12:16]) != 29453760 || binary.BigEndian.Uint32(batchBytes[16:20]) != 7 ||
		binary.BigEndian.Uint64(batchBytes[20:28]) != 1767225600123 || binary.BigEndian.Uint32(batchBytes[28:32]) != 4 {
		t.Error("the header is not §11.8's")
	}
	trailerAt := len(batchBytes) - 36
	digest := sha256.Sum256(batchBytes[:trailerAt])
	if !bytes.Equal(digest[:], batchBytes[trailerAt+4:]) {
		t.Error("the trailer's hash is not over the bytes before it")
	}
	indexOffset := int(binary.BigEndian.Uint32(batchBytes[trailerAt : trailerAt+4]))
	for i, place := range stored.Places {
		at := indexOffset + 8*i
		if binary.BigEndian.Uint32(batchBytes[at:at+4]) != place.Offset || binary.BigEndian.Uint32(batchBytes[at+4:at+8]) != place.Length {
			t.Errorf("index entry %d", i)
		}
		record := batchBytes[place.Offset : place.Offset+place.Length]
		if binary.BigEndian.Uint32(record[76:80]) != uint32(place.BodyLength) || record[0] != byte(i+1) {
			t.Errorf("record %d's header", i)
		}
	}
}

// What testdata/evs/window_vectors.json holds.
type evsWindowVectors struct {
	Entries  []*evsWindowEntryVector `json:"entries"`
	Refusals []*evsRefusalVector     `json:"refusals"`
}

type evsWindowEntryVector struct {
	Name    string   `json:"name"`
	Encoded hexBytes `json:"encoded"`
}

type evsRefusalVector struct {
	Code    uint16   `json:"code"`
	UntilMs int64    `json:"until_ms"`
	Encoded hexBytes `json:"encoded"`
}

func computeEvsWindowVectors(t *testing.T) *evsWindowVectors {
	vectors := &evsWindowVectors{}
	statementSha256 := sha256.Sum256([]byte("statement"))
	place := &protocol.EvsPlace{Minute: 29453760, Instance: 0x0a0b0c0d, Seq: 7, Offset: 32, Length: 812}
	tokenPath := EvsTokenPath{evsTestToken("a"), evsTestToken("b")}
	cases := []struct {
		name        string
		push        *protocol.EvsPush
		createsPath bool
	}{
		{name: "a write", push: &protocol.EvsPush{PushId: evsTestId("push 1").Bytes(), Changes: []*protocol.EvsChange{{}, {}}}},
		{name: "a creation under a root", createsPath: true, push: &protocol.EvsPush{
			PushId: evsTestId("push 2").Bytes(), ChangesRoot: evsTestBytes("root", 32), ChangeCount: 70000,
		}},
		{name: "a forced path epoch", push: &protocol.EvsPush{
			PushId: evsTestId("push 3").Bytes(), Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE) | uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH),
		}},
	}
	for _, entryCase := range cases {
		var covering []EvsTokenPath
		if len(entryCase.push.GetChangesRoot()) != 0 {
			covering = []EvsTokenPath{tokenPath[:1]}
		}
		entry := NewEvsWindowEntry(statementSha256, entryCase.push, []EvsTokenPath{tokenPath}, covering, entryCase.createsPath, place)
		vectors.Entries = append(vectors.Entries, &evsWindowEntryVector{Name: entryCase.name, Encoded: entry.Encode()})
	}
	for _, refusalCase := range []struct {
		code    protocol.EvsRefusalCode
		untilMs int64
	}{
		{code: protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED, untilMs: 1767225600001},
		{code: protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED, untilMs: 1767225601000},
	} {
		refusal, err := NewEvsRefusal(evsTestId("push 1"), statementSha256, refusalCase.code, refusalCase.untilMs)
		if err != nil {
			t.Fatal(err)
		}
		vectors.Refusals = append(vectors.Refusals, &evsRefusalVector{Code: uint16(refusalCase.code), UntilMs: refusalCase.untilMs, Encoded: refusal.Encode()})
	}
	return vectors
}

// Each stored entry and refusal is what this build writes and reads back field by field at §11.8's offsets; the
// change count saturates; until_s rounds up.
func TestEvsWindowVectors(t *testing.T) {
	stored := &evsWindowVectors{}
	if !compareEvsVectors(t, "testdata/evs/window_vectors.json", evsWindowVectorsJson, computeEvsWindowVectors(t), stored) {
		return
	}
	statementSha256 := sha256.Sum256([]byte("statement"))
	for _, vector := range stored.Entries {
		encoded := []byte(vector.Encoded)
		if len(encoded) != 64 || !bytes.Equal(encoded[16:32], statementSha256[:16]) ||
			binary.BigEndian.Uint32(encoded[32:36]) != 29453760 || binary.BigEndian.Uint32(encoded[48:52]) != 812 {
			t.Errorf("%s: not at §11.8's offsets", vector.Name)
		}
		entry, err := DecodeEvsWindowEntry(encoded)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		switch vector.Name {
		case "a write":
			if entry.ChangeCount() != 2 || entry.CreatesPath() || entry.ChangesInPayload() {
				t.Errorf("a write: flags %#x", entry.Flags)
			}
		case "a creation under a root":
			if entry.ChangeCount() != 0xffff || !entry.CreatesPath() || !entry.ChangesInPayload() {
				t.Errorf("a creation under a root: flags %#x", entry.Flags)
			}
		case "a forced path epoch":
			if !entry.PathEpoch() || !entry.RewritesHistory() || entry.ChangeCount() != 0 {
				t.Errorf("a forced path epoch: flags %#x", entry.Flags)
			}
		}
	}
	for _, vector := range stored.Refusals {
		encoded := []byte(vector.Encoded)
		if binary.BigEndian.Uint16(encoded[10:12]) != vector.Code || int64(binary.BigEndian.Uint32(encoded[12:16]))*1000 < vector.UntilMs ||
			int64(binary.BigEndian.Uint32(encoded[12:16])-1)*1000 >= vector.UntilMs {
			t.Errorf("refusal %d: code or until_s", vector.Code)
		}
	}
}

// Every record reads back from the batch at its place, and from its place's bytes alone, as a range read gets them.
func TestEvsBatchRecordsReadBackByPlace(t *testing.T) {
	writer, records := evsTestBatch(t)
	batchBytes, err := writer.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if writer.ByteCount() != len(batchBytes) {
		t.Errorf("ByteCount %d for %d bytes", writer.ByteCount(), len(batchBytes))
	}
	batch, err := ParseEvsBatch(batchBytes)
	if err != nil {
		t.Fatal(err)
	}
	for i, place := range batch.Places {
		read, err := ParseEvsBatchRecord(batchBytes[place.GetOffset() : place.GetOffset()+place.GetLength()])
		if err != nil {
			t.Fatal(err)
		}
		want := records[i]
		if read.Type != want.Type || read.PushId != want.PushId || read.TimeMs != want.TimeMs || !bytes.Equal(read.Body, want.Body) {
			t.Errorf("record %d read back otherwise", i)
		}
	}
	reader := NewEvsBatchReader(bytes.NewReader(batchBytes))
	for i, place := range batch.Places {
		read, err := reader.Record(place)
		if err != nil || !bytes.Equal(read.Body, records[i].Body) {
			t.Errorf("record %d through the reader: %v", i, err)
		}
	}
	if _, err := reader.Record(&protocol.EvsPlace{Offset: 0, Length: 100}); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a place inside the header: %v", err)
	}
	statement, payload, err := ParseEvsPushRecordBody(batch.Records[0].Body)
	if err != nil || !bytes.Equal(statement, evsTestBody(200)) || !bytes.Equal(payload, evsTestBytes("payload", 32)) {
		t.Errorf("the push body: %v", err)
	}
	_, part, receipts, version, err := ParseEvsPartRecordBody(batch.Records[1].Body)
	if err != nil || !bytes.Equal(part, evsTestBytes("part", 32)) || len(receipts) != 1 || version != 41 {
		t.Errorf("the part body: %v", err)
	}
	_, sealParts, err := ParseEvsSealRecordBody(batch.Records[2].Body)
	if err != nil || len(sealParts) != 2 || !sealParts[1].FirstTokenPath.Equal(EvsTokenPath{evsTestToken("b"), evsTestToken("c")}) ||
		sealParts[0].Place.GetLength() != 500 {
		t.Errorf("the seal body: %v", err)
	}
}

// A push in parts whose first change is the root's delta (EVS1-M2-46) names the root's empty token path as its first
// part's, so that part's item is exactly 52 bytes, its place and changes_root with no token bytes, and it reads back
// as the root through a batch and by its place, beside a part of a deeper path and a changeless part, and writes the
// same bytes again (QD-661). An item of 51 bytes, one of 52 plus a part of a token, and a part with a change after a
// changeless one are still refused.
func TestEvsSealRecordNamesTheRootAsItsFirstPart(t *testing.T) {
	statement := evsTestBody(200)
	placeOf := func(seq uint32) *protocol.EvsPlace {
		return &protocol.EvsPlace{Minute: 29453760, Instance: 0x0a0b0c0d, Seq: seq, Offset: 32, Length: 400 + seq}
	}
	parts := []*EvsSealPart{
		{Place: placeOf(1), ChangesRoot: [32]byte(evsTestBytes("root's part", 32)), FirstTokenPath: EvsTokenPath{}},
		{Place: placeOf(2), ChangesRoot: [32]byte(evsTestBytes("second part", 32)), FirstTokenPath: EvsTokenPath{evsTestToken("d"), evsTestToken("child")}},
		{Place: placeOf(3), Changeless: true},
	}
	body := EvsSealRecordBody(statement, parts)
	items, err := EvsPayloadItems(body)
	if err != nil || len(items) != 4 {
		t.Fatalf("the seal's items: %d %v", len(items), err)
	}
	if len(items[1]) != EvsPlaceByteCount+sha256.Size {
		t.Errorf("the root's part item is %d bytes", len(items[1]))
	}
	if len(items[2]) != 52+2*EvsTokenByteCount || len(items[3]) != EvsPlaceByteCount {
		t.Errorf("the other parts' items are %d and %d bytes", len(items[2]), len(items[3]))
	}
	check := func(label string, recordBody []byte) {
		readStatement, readParts, err := ParseEvsSealRecordBody(recordBody)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if !bytes.Equal(readStatement, statement) || len(readParts) != len(parts) {
			t.Fatalf("%s: %d parts", label, len(readParts))
		}
		root := readParts[0]
		if len(root.FirstTokenPath) != 0 || root.Changeless || root.ChangesRoot != parts[0].ChangesRoot || !proto.Equal(root.Place, parts[0].Place) {
			t.Errorf("%s: the root's part read back as %+v", label, root)
		}
		if !readParts[1].FirstTokenPath.Equal(parts[1].FirstTokenPath) || readParts[1].ChangesRoot != parts[1].ChangesRoot ||
			!proto.Equal(readParts[1].Place, parts[1].Place) {
			t.Errorf("%s: the second part read back as %+v", label, readParts[1])
		}
		if !readParts[2].Changeless || !proto.Equal(readParts[2].Place, parts[2].Place) {
			t.Errorf("%s: the changeless part read back as %+v", label, readParts[2])
		}
		// the root's empty path sorts first, so the part holding any path below the second part's start is the first
		if 0 < root.FirstTokenPath.Compare(EvsTokenPath{evsTestToken("a")}) {
			t.Errorf("%s: the root's path sorts after a top-level path", label)
		}
		if !bytes.Equal(EvsSealRecordBody(readStatement, readParts), recordBody) {
			t.Errorf("%s: the parts read back write other bytes", label)
		}
	}
	check("the body", body)

	// through a batch, and by the seal record's place alone, as evs and FI-1's walk read it
	writer := NewEvsBatchWriter(0x0a0b0c0d, 29453760, 9, 1767225600123)
	record := &EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_SEAL, RepoId: evsTestId("repo"), RefId: evsTestId("ref main"),
		PushId: evsTestId("push in parts"), SignerSidecarId: evsTestId("sidecar writer"), TimeMs: 1767225600000, Body: body,
	}
	place, err := writer.Add(record)
	if err != nil {
		t.Fatal(err)
	}
	batchBytes, err := writer.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ParseEvsBatch(batchBytes)
	if err != nil {
		t.Fatal(err)
	}
	check("the batch's record", batch.Records[0].Body)
	byPlace, err := NewEvsBatchReader(bytes.NewReader(batchBytes)).Record(place)
	if err != nil {
		t.Fatal(err)
	}
	check("the record at its place", byPlace.Body)

	refused := map[string][][]byte{
		"a part of 51 bytes":                    {statement, items[1][:51], items[2]},
		"a part of 52 bytes and half a token":   {statement, append(bytes.Clone(items[1]), evsTestBytes("half", 8)...), items[2]},
		"a part with a change after changeless": {statement, items[3], items[1]},
	}
	for label, refusedItems := range refused {
		if _, _, err := ParseEvsSealRecordBody(evsJoinItems(refusedItems)); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
}

// §11.8's bounds: 256 KiB for several records, 1 MiB for one alone; and what a reader refuses: format 2 as needing it
// (an evacuator leaves it), and a bad magic, hash, index, type or tiling as INVALID.
func TestEvsBatchBoundsAndRefusals(t *testing.T) {
	writer := NewEvsBatchWriter(1, 2, 3, 4)
	big := &EvsBatchRecord{Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, Body: make([]byte, 600*1024)}
	if _, err := writer.Add(big); err != nil {
		t.Fatalf("a lone record of 600 KiB: %v", err)
	}
	if writer.Fits(1) {
		t.Error("a second record fits beside one past 256 KiB")
	}
	if _, err := NewEvsBatchWriter(1, 2, 3, 4).Add(&EvsBatchRecord{Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, Body: make([]byte, 1024*1024)}); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a lone record past 1 MiB: %v", err)
	}
	several := NewEvsBatchWriter(1, 2, 3, 4)
	for several.Fits(100 * 1024) {
		if _, err := several.Add(&EvsBatchRecord{Type: protocol.EvsBatchRecordType_EVS_BATCH_PART, Body: make([]byte, 100*1024)}); err != nil {
			t.Fatal(err)
		}
	}
	if several.RecordCount() != 2 || EvsBatchMaxByteCount < several.ByteCount() {
		t.Errorf("%d records in %d bytes", several.RecordCount(), several.ByteCount())
	}
	if _, err := NewEvsBatchWriter(1, 2, 3, 4).Bytes(); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a batch of no record: %v", err)
	}
	if _, err := NewEvsBatchWriter(1, 2, 3, 4).Add(&EvsBatchRecord{Type: 5}); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("record type 5: %v", err)
	}

	good, _ := evsTestBatch(t)
	batchBytes, _ := good.Bytes()
	rehash := func(batch []byte) []byte {
		trailerAt := len(batch) - 36
		digest := sha256.Sum256(batch[:trailerAt])
		copy(batch[trailerAt+4:], digest[:])
		return batch
	}
	format2 := bytes.Clone(batchBytes)
	format2[4] = 2
	if _, err := ParseEvsBatch(rehash(format2)); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("a format-2 batch: %v", err)
	}
	refused := map[string][]byte{}
	badMagic := bytes.Clone(batchBytes)
	badMagic[0] = 'u'
	refused["a bad magic"] = rehash(badMagic)
	badHash := bytes.Clone(batchBytes)
	badHash[100] ^= 1
	refused["a byte flipped under the hash"] = badHash
	badCount := bytes.Clone(batchBytes)
	binary.BigEndian.PutUint32(badCount[28:32], 3)
	refused["a record count off its index"] = rehash(badCount)
	badType := bytes.Clone(batchBytes)
	badType[32] = 9
	refused["record type 9"] = rehash(badType)
	badLength := bytes.Clone(batchBytes)
	badLength[32+79] ^= 1
	refused["a record length off its index"] = rehash(badLength)
	for label, batch := range refused {
		if _, err := ParseEvsBatch(batch); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
}

// The window entry's flags come from its push; format 2's bits 4 and 5 are read past, any of 6 to 15 refused.
func TestEvsWindowEntryFlagsAndRefusals(t *testing.T) {
	place := &protocol.EvsPlace{Minute: 1, Instance: 2, Seq: 3, Offset: 4, Length: 5}
	push := &protocol.EvsPush{PushId: evsTestId("push").Bytes(), Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE), Changes: []*protocol.EvsChange{{}}}
	statementSha256 := sha256.Sum256([]byte("statement"))
	entry := NewEvsWindowEntry(statementSha256, push, nil, nil, false, place)
	if !entry.RewritesHistory() || entry.ChangeCount() != 1 || !entry.Names(evsTestId("push"), statementSha256) {
		t.Errorf("flags %#x", entry.Flags)
	}
	encoded := entry.Encode()
	for _, bit := range []uint32{16, 32} {
		withBit := bytes.Clone(encoded)
		binary.BigEndian.PutUint32(withBit[60:64], entry.Flags|bit)
		if _, err := DecodeEvsWindowEntry(withBit); err != nil {
			t.Errorf("format 2's bit %#x: %v", bit, err)
		}
	}
	for _, bit := range []uint32{64, 1 << 15} {
		withBit := bytes.Clone(encoded)
		binary.BigEndian.PutUint32(withBit[60:64], entry.Flags|bit)
		if _, err := DecodeEvsWindowEntry(withBit); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("bit %#x: %v", bit, err)
		}
	}
	window := append(bytes.Clone(encoded), encoded...)
	if entries, err := DecodeEvsWindow(window); err != nil || len(entries) != 2 {
		t.Errorf("a window of two: %v", err)
	}
	if _, err := DecodeEvsWindow(window[:100]); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a window of no whole entries: %v", err)
	}
	if _, err := DecodeEvsWindow(make([]byte, 256*64)); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a window of 256: %v", err)
	}
	packed := EvsPackPlace(place)
	if unpacked, err := EvsUnpackPlace(packed); err != nil || !proto.Equal(unpacked, place) || len(packed) != 20 {
		t.Errorf("a place back: %v", err)
	}
}

// The code table: every code has its status, a record holds only codes below 64, codes from 128 refuse nothing, and
// the codecs' errors map onto INVALID and FORMAT_UNSUPPORTED.
func TestEvsRefusalRecordsAndCodes(t *testing.T) {
	for number, name := range protocol.EvsRefusalCode_name {
		code := protocol.EvsRefusalCode(number)
		if code == protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
			continue
		}
		if _, ok := EvsRefusalStatus(code); !ok {
			t.Errorf("%s has no status", name)
		}
		if EvsRefusalRecordable(code) != (number < 64) || EvsRefusalRefusesNothing(code) != (128 <= number) {
			t.Errorf("%s is in the wrong range", name)
		}
	}
	if status, _ := EvsRefusalStatus(protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT); status != 403 {
		t.Error("QUOTA_LIMIT is not 403")
	}
	statementSha256 := sha256.Sum256([]byte("statement"))
	if _, err := NewEvsRefusal(evsTestId("push"), statementSha256, protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED, 0); !errors.Is(err, ErrEvsRefusalInvalid) {
		t.Errorf("a final code recorded: %v", err)
	}
	refusal, err := NewEvsRefusal(evsTestId("push"), statementSha256, protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE, 1001)
	if err != nil || refusal.UntilS != 2 || !refusal.LapsedAt(2000) || refusal.LapsedAt(1999) {
		t.Errorf("until_s %d: %v", refusal.UntilS, err)
	}
	if !refusal.RecordsPush(evsTestId("push")) || refusal.RecordsPush(evsTestId("other")) || !refusal.RecordsStatement(statementSha256) {
		t.Error("a record's prefixes")
	}
	eight := make([]*EvsRefusal, 8)
	for i := range eight {
		eight[i] = refusal
	}
	refused, err := EncodeEvsRefusals(eight)
	if err != nil || len(refused) != 128 {
		t.Fatalf("eight records: %v", err)
	}
	if back, err := DecodeEvsRefusals(refused); err != nil || len(back) != 8 {
		t.Errorf("eight back: %v", err)
	}
	if _, err := EncodeEvsRefusals(append(eight, refusal)); !errors.Is(err, ErrEvsRefusalInvalid) {
		t.Errorf("nine records: %v", err)
	}
	finalCode := bytes.Clone(refused[:16])
	binary.BigEndian.PutUint16(finalCode[10:12], 64)
	if _, err := DecodeEvsRefusal(finalCode); !errors.Is(err, ErrEvsRefusalInvalid) {
		t.Errorf("a final code read from a record: %v", err)
	}
	if EvsRefusalCodeOf(ErrEvsFormatUnsupported) != protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED ||
		EvsRefusalCodeOf(ErrEvsPushInvalid) != protocol.EvsRefusalCode_EVS_REFUSAL_INVALID {
		t.Error("the codecs' errors map elsewhere")
	}
}

// §22.6's batch-record target: whatever is done to a batch, one that parses is the batch written, or, for bytes made
// whole, one that encodes back to them.
func checkEvsBatchTampering(t *testing.T, original []byte, input []byte) {
	tampered := evsFuzzTamper(original, input, func([]byte) {})
	batch, err := ParseEvsBatch(tampered)
	if err != nil {
		return
	}
	if 0 < len(input) && input[0]%5 == 3 {
		writer := NewEvsBatchWriter(batch.Header.Instance, batch.Header.Minute, batch.Header.Seq, batch.Header.CreatedMs)
		for _, record := range batch.Records {
			if _, err := writer.Add(record); err != nil {
				t.Fatalf("a parsed batch's record does not fit again: %v", err)
			}
		}
		again, err := writer.Bytes()
		if err != nil || !bytes.Equal(again, tampered) {
			t.Fatal("a parsed batch encodes to other bytes")
		}
		return
	}
	if !bytes.Equal(tampered, original) {
		t.Fatal("a tampered batch parsed")
	}
}

func TestEvsBatchFuzzSeeds(t *testing.T) {
	writer, _ := evsTestBatch(t)
	batchBytes, err := writer.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, seed := range evsFuzzSeedFiles(t, "testdata/fuzz/evs_batch") {
		checkEvsBatchTampering(t, batchBytes, seed)
	}
}

// §22.6's window-entry target: an entry decodes or not, and one that decodes encodes back to its bytes.
func checkEvsWindowEntryDecode(t *testing.T, encoded []byte) {
	entry, err := DecodeEvsWindowEntry(encoded)
	if err != nil {
		return
	}
	if !bytes.Equal(entry.Encode(), encoded) {
		t.Fatal("a window entry encodes to other bytes")
	}
}

// §22.6's upload-receipt and path-map targets: decoding is total, and what decodes holds its shape.
func checkEvsReceiptAndMapDecode(t *testing.T, input []byte) {
	if receipt, err := DecodeEvsUploadReceipt(input); err == nil {
		if len(receipt.GetSegmentId()) != 32 || !EvsIsPadme(receipt.GetPaddedSize()) {
			t.Fatal("a receipt out of shape decoded")
		}
	}
	if _, pathMap, err := ParseEvsPathMap(input); err == nil {
		if pathMap.GetPathEpoch() < 2 || pathMap.GetParts() < pathMap.GetPart() {
			t.Fatal("a path map out of shape parsed")
		}
	}
}

func TestEvsWindowReceiptAndMapSeeds(t *testing.T) {
	entry := NewEvsWindowEntry(sha256.Sum256([]byte("s")), &protocol.EvsPush{PushId: evsTestId("push").Bytes()}, nil, nil, true,
		&protocol.EvsPlace{Minute: 1, Instance: 2, Seq: 3, Offset: 4, Length: 5})
	for _, seed := range [][]byte{entry.Encode(), make([]byte, 64), bytes.Repeat([]byte{0xff}, 64), {}} {
		checkEvsWindowEntryDecode(t, seed)
	}
	receipt, _ := proto.Marshal(&protocol.EvsUploadReceipt{RepoId: make([]byte, 16), SegmentId: make([]byte, 32), PaddedSize: 4096, UploadMs: 1, UploaderSidecarId: make([]byte, 16), Mac: make([]byte, 16)})
	for _, seed := range [][]byte{receipt, evsTestPathMap(t), {0x0a, 0x01}, {}} {
		checkEvsReceiptAndMapDecode(t, seed)
	}
}
