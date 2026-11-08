// §22.5's record and segment vectors on every leg, §22.6's segment and name-table targets, where tampering fails
// before plaintext, and the working set over a 2 GiB stream (R-EVS-14). The vectors regenerate with the others under
// -update-evs-vectors (evs_format_test.go); their randomness is cryptotest's, so the same seed gives the same bytes.

package sidecar

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"embed"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
	"testing"
	"testing/cryptotest"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

//go:embed testdata/evs/record_vectors.json
var evsRecordVectorsJson []byte

//go:embed testdata/evs/segment_vectors.json
var evsSegmentVectorsJson []byte

// Each target's seeds are tamperings, as evsFuzzTamper reads them, of its fixture: the segment, name table, push and
// batch the tests build.
//
//go:embed testdata/fuzz/evs_segment testdata/fuzz/evs_name_table testdata/fuzz/evs_push testdata/fuzz/evs_batch
var evsFuzzSeeds embed.FS

// A body no other vector shares: byte i is i mod 251, so another implementation rebuilds it.
func evsTestBody(byteCount int) []byte {
	body := make([]byte, byteCount)
	for i := range body {
		body[i] = byte(i % 251)
	}
	return body
}

// The keys of generation g of the test repo.
type evsTestGenerationKeys struct {
	repoId   Id
	manifest *EvsManifestKey
	fek      *EvsFekKey
	path     *EvsPathKey
}

func evsTestKeys(t testing.TB, repoId Id, generation uint64) *evsTestGenerationKeys {
	t.Helper()
	repoKey := evsTestRepoKey(repoId, generation)
	manifest, err := NewEvsManifestKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	fek, err := NewEvsFekKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	path, err := NewEvsPathKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	return &evsTestGenerationKeys{repoId: repoId, manifest: manifest, fek: fek, path: path}
}

// A checkpoint header of a body's length, under the container's key.
func evsTestHeader(label string, kind protocol.EvsRecordKind, bodyLength int) *EvsRecordHeader {
	header := &EvsRecordHeader{
		RecordId:   evsTestId("record " + label),
		Generation: 1,
		BodyLength: uint64(bodyLength),
		Kind:       kind,
		KeyRefKind: protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER,
		OidKind:    protocol.EvsOidKind_EVS_OID_SHA1,
	}
	copy(header.Oid[:20], evsTestBytes("oid "+label, 20))
	if kind == protocol.EvsRecordKind_EVS_RECORD_DIFF {
		header.BaseRecordId = evsTestId("base " + label)
	}
	return header
}

// A whole record written by a fresh writer.
func evsTestWriteRecord(t testing.TB, manifestKey *EvsManifestKey, objectKey *EvsObjectKey, fileId Id, header *EvsRecordHeader, body []byte) ([]byte, EvsRecordHeader) {
	t.Helper()
	out := &bytes.Buffer{}
	writer := NewEvsRecordWriter()
	if err := writer.Begin(out, manifestKey, objectKey, fileId, header); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), writer.Header()
}

// A record's header and body read back.
func evsTestReadRecord(manifestKey *EvsManifestKey, objectKey *EvsObjectKey, fileId Id, record []byte) (*EvsRecordHeader, []byte, error) {
	if len(record) < EvsRecordHeaderByteCount {
		return nil, nil, ErrEvsSealInvalid
	}
	header, err := EvsOpenRecordHeader(manifestKey, record[:EvsRecordHeaderByteCount])
	if err != nil {
		return nil, nil, err
	}
	reader := NewEvsRecordReader()
	if err := reader.Begin(bytes.NewReader(record[EvsRecordHeaderByteCount:]), header, objectKey, manifestKey.repoId, fileId); err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(reader)
	return header, body, err
}

// What testdata/evs/record_vectors.json holds.
type evsRecordVectors struct {
	RandomSeed  uint64             `json:"random_seed"`
	RepoId      hexBytes           `json:"repo_id"`
	Generation  uint64             `json:"generation"`
	ManifestKey hexBytes           `json:"manifest_key"`
	ObjectKey   hexBytes           `json:"object_key"`
	DepositKey  hexBytes           `json:"deposit_manifest_key"`
	FileId      hexBytes           `json:"file_id"`
	BodyRule    string             `json:"body_rule"`
	Records     []*evsRecordVector `json:"records"`
}

type evsRecordVector struct {
	Name         string   `json:"name"`
	Deposit      bool     `json:"deposit,omitempty"`
	RecordId     hexBytes `json:"record_id"`
	BaseRecordId hexBytes `json:"base_record_id"`
	Oid          hexBytes `json:"oid"`
	SlotId       hexBytes `json:"slot_id"`
	Generation   uint64   `json:"generation"`
	BodyLength   uint64   `json:"body_length"`
	KeyIndex     uint16   `json:"key_index"`
	Kind         uint8    `json:"kind"`
	KeyRefKind   uint8    `json:"key_ref_kind"`
	OidKind      uint8    `json:"oid_kind"`
	NoncePrefix  hexBytes `json:"nonce_prefix"`
	SealedHeader hexBytes `json:"sealed_header"`
	RecordSha256 hexBytes `json:"record_sha256"`
	// the whole record, when it is short
	Record hexBytes `json:"record,omitempty"`
}

func computeEvsRecordVectors(t *testing.T) *evsRecordVectors {
	const seed = 1
	cryptotest.SetGlobalRandom(t, seed)
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 3)
	objectKey := evsObjectKeyOf(evsTestBytes("object key", 32))
	depositKey, err := NewEvsDepositManifestKey(repoId, 3, objectKey)
	if err != nil {
		t.Fatal(err)
	}
	fileId := evsTestId("file")
	vectors := &evsRecordVectors{
		RandomSeed:  seed,
		RepoId:      repoId.Bytes(),
		Generation:  3,
		ManifestKey: keys.manifest.key,
		ObjectKey:   objectKey.key,
		DepositKey:  depositKey.key,
		FileId:      fileId.Bytes(),
		BodyRule:    "byte i is i mod 251",
	}
	slotHeader := evsTestHeader("slot", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 50)
	slotHeader.KeyRefKind = protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT
	slotHeader.SlotId = evsTestId("slot")
	slotHeader.KeyIndex = 5
	slotHeader.Generation = 2
	depositHeader := evsTestHeader("deposit", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 80)
	depositHeader.KeyRefKind = protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT
	depositHeader.SlotId = evsTestId("deposit slot")
	depositHeader.Generation = 3
	cases := []struct {
		name    string
		deposit bool
		header  *EvsRecordHeader
	}{
		{name: "empty checkpoint", header: evsTestHeader("empty", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 0)},
		{name: "checkpoint", header: evsTestHeader("checkpoint", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 100)},
		{name: "diff", header: evsTestHeader("diff", protocol.EvsRecordKind_EVS_RECORD_DIFF, 300)},
		{name: "chunk of two frames", header: evsTestHeader("chunk", protocol.EvsRecordKind_EVS_RECORD_CHUNK, EvsRecordFrameByteCount+1)},
		{name: "slot-keyed", header: slotHeader},
		{name: "deposit", deposit: true, header: depositHeader},
	}
	for _, recordCase := range cases {
		manifestKey := keys.manifest
		if recordCase.deposit {
			manifestKey = depositKey
		}
		record, written := evsTestWriteRecord(t, manifestKey, objectKey, fileId, recordCase.header, evsTestBody(int(recordCase.header.BodyLength)))
		recordSha256 := sha256.Sum256(record)
		vector := &evsRecordVector{
			Name:         recordCase.name,
			Deposit:      recordCase.deposit,
			RecordId:     written.RecordId.Bytes(),
			BaseRecordId: written.BaseRecordId.Bytes(),
			Oid:          bytes.Clone(written.Oid[:]),
			SlotId:       written.SlotId.Bytes(),
			Generation:   written.Generation,
			BodyLength:   written.BodyLength,
			KeyIndex:     written.KeyIndex,
			Kind:         uint8(written.Kind),
			KeyRefKind:   uint8(written.KeyRefKind),
			OidKind:      uint8(written.OidKind),
			NoncePrefix:  bytes.Clone(written.NoncePrefix[:]),
			SealedHeader: record[:EvsRecordHeaderByteCount],
			RecordSha256: recordSha256[:],
		}
		if len(record) <= 2048 {
			vector.Record = record
		}
		vectors.Records = append(vectors.Records, vector)
	}
	return vectors
}

// Opens a stored record's header and frames as EVS-FORMAT.md spells them, written apart from evs_record.go.
func evsVectorOpenRecord(t *testing.T, vectors *evsRecordVectors, vector *evsRecordVector) []byte {
	manifestKey := []byte(vectors.ManifestKey)
	if vector.Deposit {
		manifestKey = vectors.DepositKey
	}
	headerAad := binary.BigEndian.AppendUint64(append([]byte("UR evs 1.0 record"), vectors.RepoId...), vectors.Generation)
	headerAead, _ := chacha20poly1305.NewX(manifestKey)
	sealed := vector.SealedHeader
	fields, err := headerAead.Open(nil, sealed[:24], sealed[24:], headerAad)
	if err != nil || len(fields) != 120 {
		t.Fatalf("%s: the header does not open as EVS-FORMAT.md seals it", vector.Name)
	}
	if !bytes.Equal(fields[0:16], vector.RecordId) || !bytes.Equal(fields[16:32], vector.BaseRecordId) ||
		!bytes.Equal(fields[32:64], vector.Oid) || !bytes.Equal(fields[64:80], vector.SlotId) ||
		binary.BigEndian.Uint64(fields[80:88]) != vector.Generation ||
		binary.BigEndian.Uint64(fields[88:96]) != vector.BodyLength ||
		binary.BigEndian.Uint16(fields[96:98]) != vector.KeyIndex || fields[98] != vector.Kind ||
		fields[99] != vector.KeyRefKind || fields[100] != vector.OidKind || !bytes.Equal(fields[101:120], vector.NoncePrefix) {
		t.Fatalf("%s: the header's fields are not at EVS-FORMAT.md's offsets", vector.Name)
	}
	if vector.Record == nil {
		return nil
	}
	bodyAead, _ := chacha20poly1305.NewX(vectors.ObjectKey)
	frameCount := max(1, (int(vector.BodyLength)+65535)/65536)
	rest := vector.Record[160:]
	body := []byte{}
	for index := range frameCount {
		plaintextLength := min(65536, int(vector.BodyLength)-65536*index)
		nonce := binary.BigEndian.AppendUint32(bytes.Clone(vector.NoncePrefix), uint32(index))
		nonce = append(nonce, 0)
		if index == frameCount-1 {
			nonce[23] = 1
		}
		aad := append(append(append(bytes.Clone(vectors.RepoId), vectors.FileId...), vector.RecordId...), binary.BigEndian.AppendUint64(nil, vector.Generation)...)
		aad = binary.BigEndian.AppendUint32(aad, uint32(index))
		frame, err := bodyAead.Open(nil, nonce, rest[:plaintextLength+16], aad)
		if err != nil {
			t.Fatalf("%s: frame %d does not open as EVS-FORMAT.md seals it", vector.Name, index)
		}
		body = append(body, frame...)
		rest = rest[plaintextLength+16:]
	}
	if len(rest) != 0 {
		t.Fatalf("%s: bytes past the last frame", vector.Name)
	}
	return body
}

func TestEvsRecordVectors(t *testing.T) {
	stored := &evsRecordVectors{}
	if !compareEvsVectors(t, "testdata/evs/record_vectors.json", evsRecordVectorsJson, computeEvsRecordVectors(t), stored) {
		return
	}
	repoId := Id(stored.RepoId)
	manifestKey := &EvsManifestKey{repoId: repoId, generation: stored.Generation, key: stored.ManifestKey}
	depositKey := &EvsManifestKey{repoId: repoId, generation: stored.Generation, deposit: true, key: stored.DepositKey}
	objectKey := evsObjectKeyOf(stored.ObjectKey)
	derived, err := NewEvsDepositManifestKey(repoId, stored.Generation, objectKey)
	if err != nil || !bytes.Equal(derived.key, stored.DepositKey) {
		t.Errorf("K_dep is not the stored one: %v", err)
	}
	for _, vector := range stored.Records {
		body := evsVectorOpenRecord(t, stored, vector)
		if vector.Record != nil && !bytes.Equal(body, evsTestBody(int(vector.BodyLength))) {
			t.Errorf("%s: another body", vector.Name)
		}
		if vector.Record == nil {
			continue
		}
		key := manifestKey
		if vector.Deposit {
			key = depositKey
		}
		_, read, err := evsTestReadRecord(key, objectKey, Id(stored.FileId), vector.Record)
		if err != nil || !bytes.Equal(read, evsTestBody(int(vector.BodyLength))) {
			t.Errorf("%s: this build reads it back as another body: %v", vector.Name, err)
		}
	}
}

// What testdata/evs/segment_vectors.json holds.
type evsSegmentVectors struct {
	RandomSeed uint64              `json:"random_seed"`
	RepoId     hexBytes            `json:"repo_id"`
	Generation uint64              `json:"generation"`
	FekKey     hexBytes            `json:"fek_key"`
	FileId     hexBytes            `json:"file_id"`
	Segments   []*evsSegmentVector `json:"segments"`
}

type evsSegmentVector struct {
	Name       string                  `json:"name"`
	Segment    hexBytes                `json:"segment"`
	Id         hexBytes                `json:"id"`
	PaddedSize uint64                  `json:"padded_size"`
	Length     uint64                  `json:"length"`
	Places     []*evsRecordPlaceVector `json:"places"`
	// a slot-keyed segment's slot object
	SlotId hexBytes `json:"slot_id,omitempty"`
	Slot   hexBytes `json:"slot,omitempty"`
}

type evsRecordPlaceVector struct {
	Offset     uint32 `json:"offset"`
	Length     uint32 `json:"length"`
	BodyLength uint64 `json:"body_length"`
}

func computeEvsSegmentVectors(t *testing.T) *evsSegmentVectors {
	const seed = 2
	cryptotest.SetGlobalRandom(t, seed)
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 3)
	fileId := evsTestId("file")
	vectors := &evsSegmentVectors{RandomSeed: seed, RepoId: repoId.Bytes(), Generation: 3, FekKey: keys.fek.key, FileId: fileId.Bytes()}

	general := &bytes.Buffer{}
	builder, err := NewEvsSegmentBuilder(general, keys.manifest, keys.fek)
	if err != nil {
		t.Fatal(err)
	}
	bodyLengths := []int{100, 1000}
	for i, bodyLength := range bodyLengths {
		kind := protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT
		if i == 1 {
			kind = protocol.EvsRecordKind_EVS_RECORD_DIFF
		}
		record, err := builder.BeginRecord(fileId, evsTestHeader(fmt.Sprint("general ", i), kind, bodyLength))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := record.Write(evsTestBody(bodyLength)); err != nil {
			t.Fatal(err)
		}
		if err := record.Close(); err != nil {
			t.Fatal(err)
		}
	}
	vectors.Segments = append(vectors.Segments, evsSegmentVectorOf(t, "general", general, builder, bodyLengths))

	slotKeyed := &bytes.Buffer{}
	slotBuilder, err := NewEvsSlotKeyedSegmentBuilder(slotKeyed, keys.manifest)
	if err != nil {
		t.Fatal(err)
	}
	slotObjectKey := evsObjectKeyOf(evsTestBytes("slot object key", 32))
	slotId := evsTestId("slot")
	header := evsTestHeader("slot-keyed", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 200)
	header.KeyRefKind = protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT
	header.SlotId = slotId
	header.KeyIndex = 7
	header.Generation = 3
	record, err := slotBuilder.BeginSlotRecord(keys.manifest, slotObjectKey, fileId, header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.Write(evsTestBody(200)); err != nil {
		t.Fatal(err)
	}
	if err := record.Close(); err != nil {
		t.Fatal(err)
	}
	vector := evsSegmentVectorOf(t, "slot-keyed", slotKeyed, slotBuilder, []int{200})
	wrapped, err := EvsWrapObjectKey(keys.fek, slotObjectKey)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := EvsEncodeSlotObject(&protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 7, Generation: 3, Wrapped: wrapped}}})
	if err != nil {
		t.Fatal(err)
	}
	vector.SlotId = slotId.Bytes()
	vector.Slot = slot
	vectors.Segments = append(vectors.Segments, vector)
	return vectors
}

// A segment as a vector, once its builder has finished and padded it into out.
func evsSegmentVectorOf(t *testing.T, name string, out *bytes.Buffer, builder *EvsSegmentBuilder, bodyLengths []int) *evsSegmentVector {
	length := builder.length
	summary, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	vector := &evsSegmentVector{Name: name, Segment: out.Bytes(), Id: summary.Id[:], PaddedSize: summary.PaddedSize, Length: length}
	for i, place := range summary.Places {
		vector.Places = append(vector.Places, &evsRecordPlaceVector{Offset: place.Offset, Length: place.Length, BodyLength: uint64(bodyLengths[i])})
	}
	return vector
}

func TestEvsSegmentVectors(t *testing.T) {
	stored := &evsSegmentVectors{}
	if !compareEvsVectors(t, "testdata/evs/segment_vectors.json", evsSegmentVectorsJson, computeEvsSegmentVectors(t), stored) {
		return
	}
	repoId := Id(stored.RepoId)
	fekKey := &EvsFekKey{repoId: repoId, generation: stored.Generation, key: stored.FekKey}
	manifestKey := evsTestKeys(t, repoId, stored.Generation).manifest
	for _, vector := range stored.Segments {
		segment := []byte(vector.Segment)
		id := sha256.Sum256(segment)
		if !bytes.Equal(id[:], vector.Id) || uint64(len(segment)) != vector.PaddedSize || EvsPadme(vector.Length) != vector.PaddedSize {
			t.Errorf("%s: id, size or padding", vector.Name)
		}
		if !bytes.Equal(segment[0:4], []byte("URvs")) || segment[4] != 1 || segment[5] != 0 || segment[6] != 0 ||
			segment[7] != 0 || !bytes.Equal(segment[8:24], stored.RepoId) || binary.BigEndian.Uint64(segment[24:32]) != stored.Generation {
			t.Errorf("%s: the public header is not EVS-FORMAT.md's", vector.Name)
		}
		var reader *EvsSegmentReader
		var err error
		var slotKey EvsSlotKeyFunction
		if vector.Slot == nil {
			reader, err = NewEvsSegmentReader(bytes.NewReader(segment), uint64(len(segment)), fekKey)
		} else {
			reader, err = NewEvsSlotKeyedSegmentReader(bytes.NewReader(segment), uint64(len(segment)))
			slot, decodeErr := EvsDecodeSlotObject(vector.Slot)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			slotKey = func(slotId Id, keyIndex uint16, generation uint64) (*EvsObjectKey, error) {
				slotEntry, ok := EvsSlotKeyAt(slot, uint32(keyIndex))
				if slotId != Id(vector.SlotId) || !ok || slotEntry.GetGeneration() != generation {
					return nil, ErrEvsKeyMissing
				}
				return EvsOpenSlotKey(fekKey, slotEntry)
			}
		}
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		for _, place := range vector.Places {
			_, body, err := reader.OpenRecord(manifestKey, EvsRecordPlace{Offset: place.Offset, Length: place.Length}, Id(stored.FileId), slotKey)
			if err != nil {
				t.Fatalf("%s: %v", vector.Name, err)
			}
			read, err := io.ReadAll(body)
			if err != nil || !bytes.Equal(read, evsTestBody(int(place.BodyLength))) {
				t.Errorf("%s: a record reads back otherwise: %v", vector.Name, err)
			}
		}
	}
}

// Bodies of every frame shape read back whole: empty, short, one byte short of a frame, a frame, a frame and a byte,
// and three frames and a bit.
func TestEvsRecordRoundTrips(t *testing.T) {
	keys := evsTestKeys(t, evsTestId("repo"), 1)
	objectKey := NewEvsObjectKey()
	fileId := evsTestId("file")
	for _, bodyLength := range []int{0, 1, EvsRecordFrameByteCount - 1, EvsRecordFrameByteCount, EvsRecordFrameByteCount + 1, 3*EvsRecordFrameByteCount + 5} {
		body := evsTestBody(bodyLength)
		record, _ := evsTestWriteRecord(t, keys.manifest, objectKey, fileId, evsTestHeader("round", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, bodyLength), body)
		if uint64(len(record)) != EvsRecordByteCount(uint64(bodyLength)) {
			t.Errorf("a %d-byte body: %d bytes, not %d", bodyLength, len(record), EvsRecordByteCount(uint64(bodyLength)))
		}
		_, read, err := evsTestReadRecord(keys.manifest, objectKey, fileId, record)
		if err != nil || !bytes.Equal(read, body) {
			t.Errorf("a %d-byte body: %v", bodyLength, err)
		}
	}
}

// Reads a record and fails unless what came out before the error is a prefix of body, ends on a frame boundary, and
// an error came.
func evsRequireTamperRefused(t *testing.T, label string, manifestKey *EvsManifestKey, objectKey *EvsObjectKey, repoId Id, fileId Id, record []byte, body []byte) {
	t.Helper()
	header, err := EvsOpenRecordHeader(manifestKey, record[:EvsRecordHeaderByteCount])
	if err != nil {
		if !errors.Is(err, ErrEvsSealInvalid) {
			t.Errorf("%s: %v", label, err)
		}
		return
	}
	reader := NewEvsRecordReader()
	if err := reader.Begin(bytes.NewReader(record[EvsRecordHeaderByteCount:]), header, objectKey, repoId, fileId); err != nil {
		return
	}
	read, err := io.ReadAll(reader)
	if err == nil {
		t.Errorf("%s: the tampered record read whole", label)
	} else if !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("%s: %v", label, err)
	}
	if !bytes.HasPrefix(body, read) || len(read)%EvsRecordFrameByteCount != 0 {
		t.Errorf("%s: %d bytes released that are not whole frames of the body", label, len(read))
	}
}

// §22.6: a swapped frame, a dropped or cut frame, a frame sealed as the last before it is, a byte flipped anywhere,
// and another repo or file in the AAD each fail before the frame's plaintext is released.
func TestEvsRecordTamperingFailsBeforePlaintext(t *testing.T) {
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 1)
	objectKey := NewEvsObjectKey()
	fileId := evsTestId("file")
	body := evsTestBody(3*EvsRecordFrameByteCount + 10)
	record, header := evsTestWriteRecord(t, keys.manifest, objectKey, fileId, evsTestHeader("tamper", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, len(body)), body)
	frameByteCount := EvsRecordFrameByteCount + chacha20poly1305.Overhead
	frameAt := func(index int) int {
		return EvsRecordHeaderByteCount + index*frameByteCount
	}

	swapped := bytes.Clone(record)
	copy(swapped[frameAt(0):frameAt(1)], record[frameAt(1):frameAt(2)])
	copy(swapped[frameAt(1):frameAt(2)], record[frameAt(0):frameAt(1)])
	evsRequireTamperRefused(t, "frames 0 and 1 swapped", keys.manifest, objectKey, repoId, fileId, swapped, body)

	dropped := append(bytes.Clone(record[:frameAt(1)]), record[frameAt(2):]...)
	evsRequireTamperRefused(t, "frame 1 dropped", keys.manifest, objectKey, repoId, fileId, dropped, body)
	evsRequireTamperRefused(t, "the last frame dropped", keys.manifest, objectKey, repoId, fileId, record[:frameAt(3)], body)
	evsRequireTamperRefused(t, "the last frame cut", keys.manifest, objectKey, repoId, fileId, record[:len(record)-1], body)
	evsRequireTamperRefused(t, "cut after the header", keys.manifest, objectKey, repoId, fileId, record[:EvsRecordHeaderByteCount], body)

	// frame 1 sealed with the final flag, as if the body ended there: the reader expects more and refuses it
	early := bytes.Clone(record[:frameAt(2)])
	frames := &evsRecordFrames{}
	if err := frames.begin(objectKey, repoId, fileId, &header); err != nil {
		t.Fatal(err)
	}
	frames.frameIndex = 1
	frames.frameCount = 2
	frames.frame()
	resealed := frames.aead.Seal(nil, frames.nonce[:], body[EvsRecordFrameByteCount:2*EvsRecordFrameByteCount], frames.aad[:])
	copy(early[frameAt(1):], resealed)
	evsRequireTamperRefused(t, "frame 1 sealed as the last", keys.manifest, objectKey, repoId, fileId, early, body)

	evsRequireTamperRefused(t, "another repo in the AAD", keys.manifest, objectKey, evsTestId("other repo"), fileId, record, body)
	evsRequireTamperRefused(t, "another file in the AAD", keys.manifest, objectKey, repoId, evsTestId("other file"), record, body)
	evsRequireTamperRefused(t, "another object key", keys.manifest, NewEvsObjectKey(), repoId, fileId, record, body)
	evsRequireTamperRefused(t, "another generation's manifest", evsTestKeys(t, repoId, 2).manifest, objectKey, repoId, fileId, record, body)
	for _, at := range []int{0, 30, EvsRecordHeaderByteCount - 1, frameAt(0), frameAt(1) + 5, frameAt(3), len(record) - 1} {
		flipped := bytes.Clone(record)
		flipped[at] ^= 0x01
		evsRequireTamperRefused(t, fmt.Sprint("a byte flipped at ", at), keys.manifest, objectKey, repoId, fileId, flipped, body)
	}
}

// A writer refuses a body longer or shorter than its header says, and a header format 1 does not write.
func TestEvsRecordWriterRefusesWhatItCannotWrite(t *testing.T) {
	keys := evsTestKeys(t, evsTestId("repo"), 1)
	objectKey := NewEvsObjectKey()
	writer := NewEvsRecordWriter()
	if err := writer.Begin(io.Discard, keys.manifest, objectKey, Id{}, evsTestHeader("long", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(make([]byte, 11)); !errors.Is(err, ErrEvsRecordInvalid) {
		t.Errorf("a body past its length: %v", err)
	}
	if err := writer.Close(); err == nil {
		t.Error("a refused record closed")
	}
	if err := writer.Begin(io.Discard, keys.manifest, objectKey, Id{}, evsTestHeader("short", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 10)); err != nil {
		t.Fatal(err)
	}
	writer.Write(make([]byte, 9))
	if err := writer.Close(); !errors.Is(err, ErrEvsRecordInvalid) {
		t.Errorf("a body short of its length: %v", err)
	}
	refused := []*EvsRecordHeader{}
	for i := range 8 {
		header := evsTestHeader("refused", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 10)
		switch i {
		case 0:
			header.Kind = 4
		case 1:
			header.BaseRecordId = evsTestId("base")
		case 2:
			header.Kind = protocol.EvsRecordKind_EVS_RECORD_DIFF
		case 3:
			header.SlotId = evsTestId("slot")
		case 4:
			header.KeyRefKind = protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT
		case 5:
			header.OidKind = protocol.EvsOidKind_EVS_OID_SHA256
		case 6:
			header.Oid[31] = 1
		case 7:
			header.BodyLength = EvsRecordMaxBodyLength + 1
		}
		refused = append(refused, header)
	}
	for i, header := range refused {
		if err := NewEvsRecordWriter().Begin(io.Discard, keys.manifest, objectKey, Id{}, header); !errors.Is(err, ErrEvsRecordInvalid) {
			t.Errorf("header %d: %v", i, err)
		}
	}
}

// A general repo's segment, a slot-keyed one and a deposit's each read back by their places, padded to Padmé, with
// the id the SHA-256 of every byte.
func TestEvsSegmentRoundTrips(t *testing.T) {
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 2)
	fileId := evsTestId("file")
	bodies := [][]byte{evsTestBody(100), evsTestBody(EvsRecordFrameByteCount + 500), {}}

	out := &bytes.Buffer{}
	builder, err := NewEvsSegmentBuilder(out, keys.manifest, keys.fek)
	if err != nil {
		t.Fatal(err)
	}
	for i, body := range bodies {
		record, err := builder.BeginRecord(fileId, evsTestHeader(fmt.Sprint(i), protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, len(body)))
		if err != nil {
			t.Fatal(err)
		}
		record.Write(body)
		if err := record.Close(); err != nil {
			t.Fatal(err)
		}
	}
	unpadded := uint64(out.Len())
	summary, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	segment := out.Bytes()
	if summary.PaddedSize != EvsPadme(unpadded) || uint64(len(segment)) != summary.PaddedSize || summary.Id != sha256.Sum256(segment) {
		t.Fatalf("size %d, padded %d, %d bytes", unpadded, summary.PaddedSize, len(segment))
	}
	if _, err := EvsCheckSegmentUpload(segment, uint64(len(segment)), repoId); err != nil {
		t.Errorf("evs's check of an honest upload: %v", err)
	}
	reader, err := NewEvsSegmentReader(bytes.NewReader(segment), uint64(len(segment)), keys.fek)
	if err != nil {
		t.Fatal(err)
	}
	for i, place := range summary.Places {
		_, body, err := reader.OpenRecord(keys.manifest, place, fileId, nil)
		if err != nil {
			t.Fatal(err)
		}
		read, err := io.ReadAll(body)
		if err != nil || !bytes.Equal(read, bodies[i]) {
			t.Errorf("record %d: %v", i, err)
		}
	}
	if _, _, err := reader.OpenRecord(keys.manifest, EvsRecordPlace{Offset: summary.Places[0].Offset, Length: summary.Places[0].Length + 1}, fileId, nil); err == nil {
		t.Error("a place longer than its record opened")
	}
	if _, _, err := reader.OpenRecord(keys.manifest, EvsRecordPlace{Offset: 32, Length: 200}, fileId, nil); err == nil {
		t.Error("a place inside the wrapped-key block opened")
	}

	// a deposit: its key HPKE-XWing to the drop key, its header under K_dep
	dropPrivateKey, err := evsTestRepoKey(repoId, 2).DropKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	depositKey := NewEvsObjectKey()
	wrapped, err := EvsWrapDepositKey(dropPrivateKey.PublicKey(), repoId, 2, depositKey)
	if err != nil {
		t.Fatal(err)
	}
	slotId := NewEvsSlotId()
	slotBytes, err := EvsEncodeSlotObject(&protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 0, Generation: 2, Wrapped: wrapped}}})
	if err != nil {
		t.Fatal(err)
	}
	depositManifest, err := NewEvsDepositManifestKey(repoId, 2, depositKey)
	if err != nil {
		t.Fatal(err)
	}
	depositOut := &bytes.Buffer{}
	depositBuilder, err := NewEvsSlotKeyedSegmentBuilder(depositOut, depositManifest)
	if err != nil {
		t.Fatal(err)
	}
	header := evsTestHeader("deposit", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 300)
	header.KeyRefKind = protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT
	header.SlotId = slotId
	header.Generation = 2
	record, err := depositBuilder.BeginSlotRecord(depositManifest, depositKey, fileId, header)
	if err != nil {
		t.Fatal(err)
	}
	record.Write(evsTestBody(300))
	record.Close()
	depositSummary, err := depositBuilder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	// the reader: slot, drop key, then K_dep, then the record
	slot, err := EvsDecodeSlotObject(slotBytes)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := EvsOpenDepositSlotKey(dropPrivateKey, repoId, slot.GetKeys()[0])
	if err != nil {
		t.Fatal(err)
	}
	readerManifest, err := NewEvsDepositManifestKey(repoId, 2, opened)
	if err != nil {
		t.Fatal(err)
	}
	depositReader, err := NewEvsSlotKeyedSegmentReader(bytes.NewReader(depositOut.Bytes()), depositSummary.PaddedSize)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := depositReader.OpenRecord(readerManifest, depositSummary.Places[0], fileId, func(gotSlotId Id, keyIndex uint16, generation uint64) (*EvsObjectKey, error) {
		if gotSlotId != slotId || keyIndex != 0 || generation != 2 {
			return nil, ErrEvsKeyMissing
		}
		return opened, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if read, err := io.ReadAll(body); err != nil || !bytes.Equal(read, evsTestBody(300)) {
		t.Errorf("the deposit reads back otherwise: %v", err)
	}
	if _, err := EvsOpenDepositSlotKey(dropPrivateKey, evsTestId("other repo"), slot.GetKeys()[0]); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("a deposit key moved to another repo: %v", err)
	}
	otherDrop, _ := evsTestRepoKey(repoId, 3).DropKeyPair()
	if _, err := EvsOpenDepositSlotKey(otherDrop, repoId, slot.GetKeys()[0]); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("another generation's drop key: %v", err)
	}
}

// What evs and readers refuse of a segment: format 2's header as needing it, any other header, another repo, a size
// that is not a Padmé length or passes 8 MiB, a record past 8 MiB, keys of another generation.
func TestEvsSegmentRefusals(t *testing.T) {
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 2)
	header := (&EvsSegmentHeader{RepoId: repoId, Generation: 2}).encode()
	format2 := bytes.Clone(header)
	format2[4] = 2
	if _, err := ParseEvsSegmentHeader(format2); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("format 2: %v", err)
	}
	for at, value := range map[int]byte{0: 'u', 4: 3, 5: 1, 6: 1, 7: 1} {
		bad := bytes.Clone(header)
		bad[at] = value
		if _, err := ParseEvsSegmentHeader(bad); !errors.Is(err, ErrEvsSegmentInvalid) {
			t.Errorf("byte %d as %d: %v", at, value, err)
		}
	}
	noGeneration := bytes.Clone(header)
	binary.BigEndian.PutUint64(noGeneration[24:32], 0)
	if _, err := ParseEvsSegmentHeader(noGeneration); !errors.Is(err, ErrEvsSegmentInvalid) {
		t.Errorf("generation 0: %v", err)
	}
	if _, err := EvsCheckSegmentUpload(header, 1024, evsTestId("other repo")); !errors.Is(err, ErrEvsSegmentInvalid) {
		t.Errorf("another repo: %v", err)
	}
	for _, size := range []uint64{1025, EvsSegmentMaxByteCount + 1, EvsPadme(EvsSegmentMaxByteCount + 1), 16} {
		if _, err := EvsCheckSegmentUpload(header, size, repoId); !errors.Is(err, ErrEvsSegmentInvalid) {
			t.Errorf("size %d: %v", size, err)
		}
	}
	builder, err := NewEvsSegmentBuilder(io.Discard, keys.manifest, keys.fek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.BeginRecord(Id{}, evsTestHeader("big", protocol.EvsRecordKind_EVS_RECORD_CHUNK, EvsRecordMaxBodyLength)); !errors.Is(err, ErrEvsSegmentFull) {
		t.Errorf("a record past 8 MiB: %v", err)
	}
	if _, err := builder.Finish(); !errors.Is(err, ErrEvsSegmentInvalid) {
		t.Errorf("a segment of no record: %v", err)
	}
	if _, err := NewEvsSegmentBuilder(io.Discard, keys.manifest, evsTestKeys(t, repoId, 3).fek); !errors.Is(err, ErrEvsSegmentInvalid) {
		t.Errorf("fek of another generation: %v", err)
	}
}

// A segment of two 4 MiB chunks does not fit; one 4 MiB chunk pads to a size under 8 MiB.
func TestEvsSegmentHoldsOneFourMiBChunk(t *testing.T) {
	keys := evsTestKeys(t, evsTestId("repo"), 1)
	builder, err := NewEvsSegmentBuilder(io.Discard, keys.manifest, keys.fek)
	if err != nil {
		t.Fatal(err)
	}
	chunk := evsTestBody(4 * 1024 * 1024)
	record, err := builder.BeginRecord(Id{}, evsTestHeader("chunk", protocol.EvsRecordKind_EVS_RECORD_CHUNK, len(chunk)))
	if err != nil {
		t.Fatal(err)
	}
	record.Write(chunk)
	record.Close()
	if _, err := builder.BeginRecord(Id{}, evsTestHeader("chunk 2", protocol.EvsRecordKind_EVS_RECORD_CHUNK, len(chunk))); !errors.Is(err, ErrEvsSegmentFull) {
		t.Errorf("a second chunk: %v", err)
	}
	summary, err := builder.Finish()
	if err != nil || EvsSegmentMaxByteCount < summary.PaddedSize {
		t.Errorf("%v, %d bytes", err, summary.PaddedSize)
	}
}

// An inline chain: its first record carries the chain's key block and pads to a Padmé length within 16 KiB, its
// later ones use that key, and each opens only under its own keys.
func TestEvsInlineRecords(t *testing.T) {
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 2)
	fileId := evsTestId("file")
	firstBody := evsTestBody(1000)
	first, chainKey, err := EvsSealInlineRecord(keys.manifest, keys.fek, nil, fileId, evsTestHeader("inline 1", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 0), firstBody)
	if err != nil {
		t.Fatal(err)
	}
	if !EvsIsPadme(uint64(len(first))) || EvsInlineMaxByteCount < len(first) {
		t.Errorf("first inline record of %d bytes", len(first))
	}
	header, body, openedKey, err := EvsOpenInlineRecord(keys.manifest, keys.fek, nil, fileId, first)
	if err != nil || !bytes.Equal(body, firstBody) || header.Generation != 2 {
		t.Fatalf("the first record: %v", err)
	}
	laterHeader := evsTestHeader("inline 2", protocol.EvsRecordKind_EVS_RECORD_DIFF, 0)
	laterHeader.Generation = 2
	laterKeys := evsTestKeys(t, repoId, 3)
	later, _, err := EvsSealInlineRecord(laterKeys.manifest, nil, chainKey, fileId, laterHeader, evsTestBody(40))
	if err != nil {
		t.Fatal(err)
	}
	if _, body, _, err := EvsOpenInlineRecord(laterKeys.manifest, nil, openedKey, fileId, later); err != nil || !bytes.Equal(body, evsTestBody(40)) {
		t.Errorf("the later record: %v", err)
	}
	if _, _, _, err := EvsOpenInlineRecord(keys.manifest, nil, openedKey, fileId, later); err == nil {
		t.Error("a later record opened under another push's manifest")
	}
	if _, _, _, err := EvsOpenInlineRecord(keys.manifest, keys.fek, nil, evsTestId("other file"), first); err == nil {
		t.Error("an inline record opened as another file's")
	}
	if _, _, _, err := EvsOpenInlineRecord(keys.manifest, keys.fek, nil, fileId, first[:len(first)-1]); err == nil {
		t.Error("an inline record of no Padmé length opened")
	}
	if _, _, err := EvsSealInlineRecord(keys.manifest, keys.fek, nil, fileId, evsTestHeader("inline big", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 0), evsTestBody(16*1024)); !errors.Is(err, ErrEvsRecordInvalid) {
		t.Errorf("an inline record past 16 KiB: %v", err)
	}
}

// Names: the 64-byte steps, a round trip under each epoch's keys, NFC and NFD as two rows, and a row moved to
// another child, parent, epoch or repo, or tampered, refused.
func TestEvsNamesSealAndOpen(t *testing.T) {
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 2)
	parent, err := EvsPathToken(keys.path, EvsRootToken, []byte("src"))
	if err != nil {
		t.Fatal(err)
	}
	for _, nameLength := range []int{1, 63, 64, 127, 128, 200} {
		name := bytes.Repeat([]byte{'n'}, nameLength)
		child, err := EvsPathToken(keys.path, parent, name)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := EvsNameSeal(keys.manifest, parent, child, name)
		if err != nil {
			t.Fatal(err)
		}
		wantPadded := (nameLength/64 + 1) * 64
		if len(sealed) != 24+wantPadded+16 {
			t.Errorf("a %d-byte name sealed to %d bytes", nameLength, len(sealed))
		}
		opened, err := EvsNameOpen(keys.manifest, keys.path, parent, child, sealed)
		if err != nil || !bytes.Equal(opened, name) {
			t.Errorf("a %d-byte name: %v", nameLength, err)
		}
	}
	name := []byte("café")
	child, _ := EvsPathToken(keys.path, parent, name)
	sealed, err := EvsNameSeal(keys.manifest, parent, child, name)
	if err != nil {
		t.Fatal(err)
	}
	nfdChild, _ := EvsPathToken(keys.path, parent, []byte("café"))
	if _, err := EvsNameOpen(keys.manifest, keys.path, parent, nfdChild, sealed); err == nil {
		t.Error("an NFC name opened as its NFD twin's row")
	}
	otherParent, _ := EvsPathToken(keys.path, EvsRootToken, []byte("lib"))
	otherKeys := evsTestKeys(t, repoId, 3)
	otherRepo := evsTestKeys(t, evsTestId("other repo"), 2)
	for label, open := range map[string]func() ([]byte, error){
		"another child":  func() ([]byte, error) { return EvsNameOpen(keys.manifest, keys.path, parent, nfdChild, sealed) },
		"another parent": func() ([]byte, error) { return EvsNameOpen(keys.manifest, keys.path, otherParent, child, sealed) },
		"another epoch":  func() ([]byte, error) { return EvsNameOpen(otherKeys.manifest, otherKeys.path, parent, child, sealed) },
		"another repo":   func() ([]byte, error) { return EvsNameOpen(otherRepo.manifest, otherRepo.path, parent, child, sealed) },
		"a flipped byte": func() ([]byte, error) {
			flipped := bytes.Clone(sealed)
			flipped[30] ^= 1
			return EvsNameOpen(keys.manifest, keys.path, parent, child, flipped)
		},
		"keys of two epochs": func() ([]byte, error) { return EvsNameOpen(keys.manifest, otherKeys.path, parent, child, sealed) },
	} {
		if opened, err := open(); err == nil {
			t.Errorf("%s: opened %q", label, opened)
		}
	}
	// a writer whose name does not match the row's token: readers refuse it by the token check
	wrongChild, _ := EvsPathToken(keys.path, parent, []byte("other"))
	mismatched, _ := EvsNameSeal(keys.manifest, parent, wrongChild, name)
	if _, err := EvsNameOpen(keys.manifest, keys.path, parent, wrongChild, mismatched); !errors.Is(err, ErrEvsTokenInvalid) {
		t.Errorf("a name under another's token: %v", err)
	}
	// padding §11.7 does not write: a second step of zeros
	padded := append(append(bytes.Clone(name), 0x80), make([]byte, 128-len(name)-1)...)
	overPadded, _ := evsSeal(keys.manifest.key, padded, evsNameAad(repoId, 2, parent, child))
	if _, err := EvsNameOpen(keys.manifest, keys.path, parent, child, overPadded); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("a name padded a step too far: %v", err)
	}
	for _, refused := range [][]byte{{}, []byte("a/b"), []byte("a\x00")} {
		if _, err := EvsNameSeal(keys.manifest, parent, child, refused); !errors.Is(err, ErrEvsTokenInvalid) {
			t.Errorf("name %q: %v", refused, err)
		}
	}
}

// The name table evsFuzzNameTable builds: two files and a directory in epoch 2 under src, a carried row of epoch 1,
// and a removed token; with the keys and parents each epoch opens under.
type evsTestNameTable struct {
	table     *protocol.EvsNameTable
	names     map[EvsToken][]byte
	epochKeys EvsNameEpochFunction
}

func newEvsTestNameTable(t testing.TB) *evsTestNameTable {
	repoId := evsTestId("repo")
	epochs := map[uint64]*evsTestGenerationKeys{1: evsTestKeys(t, repoId, 1), 2: evsTestKeys(t, repoId, 2)}
	parents := map[uint64]EvsToken{}
	for epoch, keys := range epochs {
		parent, err := EvsPathToken(keys.path, EvsRootToken, []byte("src"))
		if err != nil {
			t.Fatal(err)
		}
		parents[epoch] = parent
	}
	built := &evsTestNameTable{table: &protocol.EvsNameTable{}, names: map[EvsToken][]byte{}}
	add := func(epoch uint64, carried bool, kind protocol.EvsEntryKind, name string) {
		keys := epochs[epoch]
		child, err := EvsPathToken(keys.path, parents[epoch], []byte(name))
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := EvsNameSeal(keys.manifest, parents[epoch], child, []byte(name))
		if err != nil {
			t.Fatal(err)
		}
		row := &protocol.EvsName{Token: child.Bytes(), Kind: uint32(kind), SealedName: sealed}
		if carried {
			row.Epoch = epoch
		}
		built.table.Names = append(built.table.Names, row)
		built.names[child] = []byte(name)
	}
	add(2, false, protocol.EvsEntryKind_EVS_ENTRY_FILE, "main.go")
	add(2, false, protocol.EvsEntryKind_EVS_ENTRY_FILE, "café.go")
	add(2, false, protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY, "evs")
	add(1, true, protocol.EvsEntryKind_EVS_ENTRY_FILE, "old.go")
	built.table.RemovedTokens = [][]byte{evsTestToken("removed").Bytes()}
	built.epochKeys = func(epoch uint64) (*EvsManifestKey, *EvsPathKey, EvsToken, error) {
		keys, ok := epochs[epoch]
		if !ok {
			return nil, nil, EvsToken{}, ErrEvsKeyMissing
		}
		return keys.manifest, keys.path, parents[epoch], nil
	}
	return built
}

// A table opens row by row under each row's own epoch, and a table repeating a token, with a kind no entry has, or
// carrying a row of its own epoch, is refused whole.
func TestEvsNameTableOpens(t *testing.T) {
	built := newEvsTestNameTable(t)
	opened, err := EvsOpenNameTable(built.table, 2, built.epochKeys)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) != 4 {
		t.Fatalf("%d rows", len(opened))
	}
	for _, row := range opened {
		if !bytes.Equal(row.Name, built.names[row.Token]) {
			t.Errorf("row %v: %q", row.Token, row.Name)
		}
	}
	repeated := proto.Clone(built.table).(*protocol.EvsNameTable)
	repeated.Names = append(repeated.Names, repeated.Names[0])
	badKind := proto.Clone(built.table).(*protocol.EvsNameTable)
	badKind.Names[0].Kind = 3
	ownEpoch := proto.Clone(built.table).(*protocol.EvsNameTable)
	ownEpoch.Names[0].Epoch = 2
	shortRemoved := proto.Clone(built.table).(*protocol.EvsNameTable)
	shortRemoved.RemovedTokens = [][]byte{make([]byte, 15)}
	movedCarried := proto.Clone(built.table).(*protocol.EvsNameTable)
	movedCarried.Names[3].Epoch = 0
	for label, table := range map[string]*protocol.EvsNameTable{
		"a repeated token": repeated, "kind 3": badKind, "a carried row of the table's epoch": ownEpoch,
		"a short removed token": shortRemoved, "a carried row read as current": movedCarried,
	} {
		if _, err := EvsOpenNameTable(table, 2, built.epochKeys); err == nil {
			t.Errorf("%s: opened", label)
		}
	}
	untagged := proto.Clone(built.table).(*protocol.EvsNameTable)
	untagged.Names[3].Epoch = 0
	if EvsNameTableBoundByteCount(built.table) != EvsNameTableBoundByteCount(untagged) {
		t.Error("a carried row counts its epoch against the bound")
	}
	if EvsNameTableBoundByteCount(built.table) >= proto.Size(built.table) {
		t.Error("the bound counts more than the rows")
	}
}

// Sealed fields round-trip, and format 1 refuses content_sha256 as format 2's, a directory's mode, a short file_id and
// an oid that is not SHA-1; metadata opens only under its own push's generation.
func TestEvsSealedFields(t *testing.T) {
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 2)
	fields := &protocol.EvsSealedFields{
		FileId: evsTestId("file").Bytes(), Mode: EvsGitModeFile, GitOid: evsTestBytes("oid", 20),
		OidKind: protocol.EvsOidKind_EVS_OID_SHA1, Size: 12345,
	}
	sealed, err := EvsSealFields(keys.manifest, fields)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := EvsOpenFields(keys.manifest, sealed)
	if err != nil || !proto.Equal(opened, fields) {
		t.Fatalf("fields back: %v", err)
	}
	if _, err := EvsOpenFields(evsTestKeys(t, repoId, 3).manifest, sealed); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("another generation: %v", err)
	}
	versionless := proto.Clone(fields).(*protocol.EvsSealedFields)
	versionless.ContentSha256 = evsTestBytes("content", 32)
	if _, err := EvsSealFields(keys.manifest, versionless); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("content_sha256: %v", err)
	}
	plaintext, _ := proto.Marshal(versionless)
	sealedVersionless, _ := evsSeal(keys.manifest.key, plaintext, evsLabeledAad(evsFieldsAadLabel, repoId, 2))
	if _, err := EvsOpenFields(keys.manifest, sealedVersionless); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("a stored content_sha256: %v", err)
	}
	for label, mutate := range map[string]func(*protocol.EvsSealedFields){
		"a directory's mode": func(fields *protocol.EvsSealedFields) { fields.Mode = EvsGitModeDirectory },
		"a short file_id":    func(fields *protocol.EvsSealedFields) { fields.FileId = fields.FileId[:15] },
		"a SHA-256 oid": func(fields *protocol.EvsSealedFields) {
			fields.OidKind = protocol.EvsOidKind_EVS_OID_SHA256
			fields.GitOid = evsTestBytes("oid", 32)
		},
	} {
		bad := proto.Clone(fields).(*protocol.EvsSealedFields)
		mutate(bad)
		if _, err := EvsSealFields(keys.manifest, bad); !errors.Is(err, ErrEvsSealInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
	metadata := &protocol.EvsSealedMetadata{Provenance: &protocol.EvsProvenance{AgentId: evsTestId("agent").Bytes(), Tainted: true}}
	sealedMetadata, err := EvsSealMetadata(keys.manifest, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if openedMetadata, err := EvsOpenMetadata(keys.manifest, sealedMetadata); err != nil || !proto.Equal(openedMetadata, metadata) {
		t.Errorf("metadata back: %v", err)
	}
	if _, err := EvsOpenFields(keys.manifest, sealedMetadata); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("metadata opened as fields: %v", err)
	}
}

// Slot objects: ascending indexes, one way of wrapping, 64 keys and 8 KiB at most; an erasure drops only the keys it
// names and shifts no index.
func TestEvsSlotObjects(t *testing.T) {
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	wrappedOf := func() []byte {
		wrapped, err := EvsWrapObjectKey(keys.fek, NewEvsObjectKey())
		if err != nil {
			t.Fatal(err)
		}
		return wrapped
	}
	slot := &protocol.EvsSlotObject{}
	for _, keyIndex := range []uint32{0, 3, 63} {
		slot.Keys = append(slot.Keys, &protocol.EvsSlotKey{KeyIndex: keyIndex, Generation: 2, Wrapped: wrappedOf()})
	}
	encoded, err := EvsEncodeSlotObject(slot)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := EvsDecodeSlotObject(encoded)
	if err != nil || !proto.Equal(decoded, slot) {
		t.Fatalf("slot back: %v", err)
	}
	if key, ok := EvsSlotKeyAt(decoded, 3); !ok {
		t.Error("key 3 missing")
	} else if _, err := EvsOpenSlotKey(keys.fek, key); err != nil {
		t.Errorf("key 3 does not open: %v", err)
	}
	if _, err := EvsOpenSlotKey(evsTestKeys(t, evsTestId("repo"), 3).fek, slot.Keys[0]); !errors.Is(err, ErrEvsKeyMissing) {
		t.Errorf("fek of another generation: %v", err)
	}
	erased, removedCount, err := EvsSlotWithoutKeys(encoded, []uint32{3, 40})
	if err != nil || removedCount != 1 {
		t.Fatalf("erase: %d, %v", removedCount, err)
	}
	afterErase, _ := EvsDecodeSlotObject(erased)
	if _, ok := EvsSlotKeyAt(afterErase, 3); ok || len(afterErase.GetKeys()) != 2 {
		t.Error("key 3 survives its erasure")
	}
	if key, ok := EvsSlotKeyAt(afterErase, 63); !ok || !bytes.Equal(key.GetWrapped(), slot.Keys[2].GetWrapped()) {
		t.Error("key 63 moved")
	}
	if same, removedCount, err := EvsSlotWithoutKeys(erased, []uint32{3}); err != nil || removedCount != 0 || !bytes.Equal(same, erased) {
		t.Error("erasing an erased key changed the slot")
	}
	emptied, _, err := EvsSlotWithoutKeys(erased, []uint32{0, 63})
	if err != nil {
		t.Fatal(err)
	}
	if empty, err := EvsDecodeSlotObject(emptied); err != nil || len(empty.GetKeys()) != 0 {
		t.Errorf("a slot with every key erased: %v", err)
	}
	refused := map[string]*protocol.EvsSlotObject{
		"no key":        {},
		"index 64":      {Keys: []*protocol.EvsSlotKey{{KeyIndex: 64, Generation: 2, Wrapped: wrappedOf()}}},
		"unsorted":      {Keys: []*protocol.EvsSlotKey{{KeyIndex: 2, Generation: 2, Wrapped: wrappedOf()}, {KeyIndex: 1, Generation: 2, Wrapped: wrappedOf()}}},
		"repeated":      {Keys: []*protocol.EvsSlotKey{{KeyIndex: 1, Generation: 2, Wrapped: wrappedOf()}, {KeyIndex: 1, Generation: 2, Wrapped: wrappedOf()}}},
		"generation 0":  {Keys: []*protocol.EvsSlotKey{{KeyIndex: 0, Generation: 0, Wrapped: wrappedOf()}}},
		"a short wrap":  {Keys: []*protocol.EvsSlotKey{{KeyIndex: 0, Generation: 2, Wrapped: make([]byte, 71)}}},
		"two wrappings": {Keys: []*protocol.EvsSlotKey{{KeyIndex: 0, Generation: 2, Wrapped: wrappedOf()}, {KeyIndex: 1, Generation: 2, Wrapped: make([]byte, EvsDepositWrappedKeyByteCount)}}},
	}
	big := &protocol.EvsSlotObject{}
	for keyIndex := range uint32(64) {
		big.Keys = append(big.Keys, &protocol.EvsSlotKey{KeyIndex: keyIndex, Generation: 2, Wrapped: make([]byte, EvsDepositWrappedKeyByteCount)})
	}
	refused["past 8 KiB"] = big
	for label, bad := range refused {
		if _, err := EvsEncodeSlotObject(bad); !errors.Is(err, ErrEvsSealInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
	if _, err := EvsDecodeSlotObject([]byte{0xff}); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("garbage: %v", err)
	}
}

// R-EVS-14: 2 GiB streamed through the record codec, as 512 chunk records of 4 MiB from writer to reader through a
// pipe, never holds more than 4 MiB of heap beyond where it began. The heap is sampled every 8 frames, and collected
// between records so one record's small garbage does not count against the next.
func TestEvsRecordWorkingSetStaysUnder4MiB(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("the Worker leg runs the codec's other tests; 2 GiB in wasm is a review-phase hand run")
	}
	const chunkByteCount = 4 * 1024 * 1024
	const chunkCount = 512
	keys := evsTestKeys(t, evsTestId("repo"), 1)
	objectKey := NewEvsObjectKey()
	fileId := evsTestId("file")
	writer := NewEvsRecordWriter()
	reader := NewEvsRecordReader()
	source := make([]byte, EvsRecordFrameByteCount)
	sink := make([]byte, 32*1024)
	written := sha256.New()
	read := sha256.New()

	stats := &runtime.MemStats{}
	runtime.GC()
	runtime.ReadMemStats(stats)
	baseline := stats.HeapAlloc
	peak := uint64(0)
	sample := func() {
		runtime.ReadMemStats(stats)
		peak = max(peak, stats.HeapAlloc-min(stats.HeapAlloc, baseline))
	}

	for chunk := range chunkCount {
		header := evsTestHeader("chunk", protocol.EvsRecordKind_EVS_RECORD_CHUNK, chunkByteCount)
		pipeReader, pipeWriter := io.Pipe()
		writeDone := make(chan error, 1)
		go func() {
			err := func() error {
				if err := writer.Begin(pipeWriter, keys.manifest, objectKey, fileId, header); err != nil {
					return err
				}
				for frame := range chunkByteCount / EvsRecordFrameByteCount {
					for i := range source {
						source[i] = byte(chunk + frame + i)
					}
					written.Write(source)
					if _, err := writer.Write(source); err != nil {
						return err
					}
					if frame%8 == 0 {
						sample()
					}
				}
				return writer.Close()
			}()
			pipeWriter.CloseWithError(err)
			writeDone <- err
		}()
		sealedHeader := make([]byte, EvsRecordHeaderByteCount)
		if _, err := io.ReadFull(pipeReader, sealedHeader); err != nil {
			t.Fatal(err)
		}
		opened, err := EvsOpenRecordHeader(keys.manifest, sealedHeader)
		if err != nil {
			t.Fatal(err)
		}
		if err := reader.Begin(pipeReader, opened, objectKey, keys.repoId, fileId); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyBuffer(read, reader, sink); err != nil {
			t.Fatal(err)
		}
		if err := <-writeDone; err != nil {
			t.Fatal(err)
		}
		sample()
		runtime.GC()
	}
	if !bytes.Equal(written.Sum(nil), read.Sum(nil)) {
		t.Fatal("2 GiB read back as other bytes")
	}
	t.Logf("the working set peaked at %d bytes past its start", peak)
	if 4*1024*1024 <= peak {
		t.Errorf("the working set reached %d bytes", peak)
	}
}

// The segment evsFuzzSegment tampers with: a general repo's, holding a 100-byte record, one of 128 KiB and 500
// bytes in three frames, and an empty one, with what each holds.
type evsFuzzSegmentFixture struct {
	keys    *evsTestGenerationKeys
	fileId  Id
	segment []byte
	places  []EvsRecordPlace
	bodies  [][]byte
}

func newEvsFuzzSegmentFixture(t testing.TB) *evsFuzzSegmentFixture {
	fixture := &evsFuzzSegmentFixture{
		keys:   evsTestKeys(t, evsTestId("repo"), 2),
		fileId: evsTestId("file"),
		bodies: [][]byte{evsTestBody(100), evsTestBody(2*EvsRecordFrameByteCount + 500), {}},
	}
	out := &bytes.Buffer{}
	builder, err := NewEvsSegmentBuilder(out, fixture.keys.manifest, fixture.keys.fek)
	if err != nil {
		t.Fatal(err)
	}
	for i, body := range fixture.bodies {
		record, err := builder.BeginRecord(fixture.fileId, evsTestHeader(fmt.Sprint("fuzz ", i), protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, len(body)))
		if err != nil {
			t.Fatal(err)
		}
		record.Write(body)
		if err := record.Close(); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	fixture.segment = out.Bytes()
	fixture.places = summary.Places
	return fixture
}

// A tampering of a fixture's bytes: op 0 flips the bytes after a u32 offset by the rest of the input; op 1 cuts at a
// u32 length; op 2 swaps the second record's first two frames; op 3 takes the rest of the input as the bytes whole; op 4
// appends the rest.
func evsFuzzTamper(original []byte, input []byte, frameSwap func([]byte)) []byte {
	if len(input) == 0 {
		return bytes.Clone(original)
	}
	op, rest := input[0], input[1:]
	tampered := bytes.Clone(original)
	readOffset := func() int {
		if len(rest) < 4 {
			return 0
		}
		offset := int(binary.BigEndian.Uint32(rest))
		rest = rest[4:]
		return offset
	}
	switch op % 5 {
	case 0:
		at := readOffset() % max(1, len(tampered))
		for i, mask := range rest {
			if at+i < len(tampered) {
				tampered[at+i] ^= mask
			}
		}
	case 1:
		tampered = tampered[:readOffset()%(len(tampered)+1)]
	case 2:
		frameSwap(tampered)
	case 3:
		tampered = bytes.Clone(rest)
	case 4:
		tampered = append(tampered, rest...)
	}
	return tampered
}

// §22.6's segment target: whatever is done to the segment's bytes, each record either opens to exactly what was
// written or fails, and before failing releases only whole frames of what was written.
func checkEvsSegmentTampering(t *testing.T, fixture *evsFuzzSegmentFixture, input []byte) {
	frameByteCount := EvsRecordFrameByteCount + chacha20poly1305.Overhead
	second := int(fixture.places[1].Offset) + EvsRecordHeaderByteCount
	tampered := evsFuzzTamper(fixture.segment, input, func(segment []byte) {
		first := bytes.Clone(segment[second : second+frameByteCount])
		copy(segment[second:], segment[second+frameByteCount:second+2*frameByteCount])
		copy(segment[second+frameByteCount:], first)
	})
	reader, err := NewEvsSegmentReader(bytes.NewReader(tampered), uint64(len(tampered)), fixture.keys.fek)
	if err != nil {
		return
	}
	for i, place := range fixture.places {
		_, body, err := reader.OpenRecord(fixture.keys.manifest, place, fixture.fileId, nil)
		if err != nil {
			continue
		}
		read, err := io.ReadAll(body)
		if err == nil && !bytes.Equal(read, fixture.bodies[i]) {
			t.Fatalf("record %d opened to other bytes", i)
		}
		if err != nil && (!bytes.HasPrefix(fixture.bodies[i], read) || len(read)%EvsRecordFrameByteCount != 0) {
			t.Fatalf("record %d released %d bytes before failing", i, len(read))
		}
	}
}

func evsFuzzSeedFiles(t testing.TB, directory string) [][]byte {
	t.Helper()
	entries, err := evsFuzzSeeds.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	seeds := [][]byte{}
	for _, entry := range entries {
		seed, err := evsFuzzSeeds.ReadFile(directory + "/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, seed)
	}
	if len(seeds) == 0 {
		t.Fatalf("no seeds in %s", directory)
	}
	return seeds
}

// Every seed, run as a test, with an untampered pass to show the fixture reads.
func TestEvsSegmentFuzzSeeds(t *testing.T) {
	fixture := newEvsFuzzSegmentFixture(t)
	checkEvsSegmentTampering(t, fixture, nil)
	for _, seed := range evsFuzzSeedFiles(t, "testdata/fuzz/evs_segment") {
		checkEvsSegmentTampering(t, fixture, seed)
	}
}

// §22.6's name-table target: whatever is done to a table's bytes, it decodes or not, and a row that opens names what
// that token's row was sealed with; a table refused is refused before any name.
func checkEvsNameTableTampering(t *testing.T, built *evsTestNameTable, encoded []byte, input []byte) {
	tampered := evsFuzzTamper(encoded, input, func(table []byte) {})
	table := &protocol.EvsNameTable{}
	if err := proto.Unmarshal(tampered, table); err != nil {
		return
	}
	opened, err := EvsOpenNameTable(table, 2, built.epochKeys)
	if err != nil {
		if opened != nil {
			t.Fatal("a refused table returned names")
		}
		return
	}
	for _, row := range opened {
		want, ok := built.names[row.Token]
		if !ok || !bytes.Equal(row.Name, want) {
			t.Fatalf("a row opened to %q", row.Name)
		}
	}
}

func TestEvsNameTableFuzzSeeds(t *testing.T) {
	built := newEvsTestNameTable(t)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(built.table)
	if err != nil {
		t.Fatal(err)
	}
	checkEvsNameTableTampering(t, built, encoded, nil)
	for _, seed := range evsFuzzSeedFiles(t, "testdata/fuzz/evs_name_table") {
		checkEvsNameTableTampering(t, built, encoded, seed)
	}
}

// The drop key's public half as X-Wing, for a depositor holding only GenRotate's bytes.
func TestEvsDepositKeyFromGenRotateBytes(t *testing.T) {
	repoId := evsTestId("repo")
	dropPrivateKey, err := evsTestRepoKey(repoId, 2).DropKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := hpke.MLKEM768X25519().NewPublicKey(dropPrivateKey.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	objectKey := NewEvsObjectKey()
	wrapped, err := EvsWrapDepositKey(publicKey, repoId, 2, objectKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != EvsDepositWrappedKeyByteCount {
		t.Errorf("a deposit key of %d bytes", len(wrapped))
	}
	opened, err := EvsUnwrapDepositKey(dropPrivateKey, repoId, 2, wrapped)
	if err != nil || !bytes.Equal(opened.key, objectKey.key) {
		t.Errorf("back: %v", err)
	}
	if _, err := EvsUnwrapDepositKey(dropPrivateKey, repoId, 3, wrapped); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("another generation in the AAD: %v", err)
	}
	if hex.EncodeToString(wrapped[:4]) == hex.EncodeToString(make([]byte, 4)) {
		t.Error("an encapsulation of zeros")
	}
}
