// Format 2's codecs (EVS2-M10-02): §22.5's kind-5 segment, staged segment, batch record and window entry vectors in
// testdata/evs/format2/, byte-equal on every leg (embedded, so the Worker reads them too, and regenerated with the
// others under -update-evs-vectors); §22.6's targets with kind-5 and staged seeds, where tampering fails before
// plaintext or adoption; a staged segment naming another push refused; a format-1 reader leaving a format-2 batch and
// record; the staged checks of a one-part push and of a push in parts; the layouts schema.yml writes, held to this
// build's constants; and the working set over a 2 GiB stream of kind-5 chunk segments (R-EVS-14).

package sidecar

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"testing"
	"testing/cryptotest"

	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar/protocol"
)

//go:embed testdata/evs/format2/segment_vectors.json
var evsFormat2SegmentVectorsJson []byte

//go:embed testdata/evs/format2/batch_vectors.json
var evsFormat2BatchVectorsJson []byte

//go:embed testdata/evs/format2/schema.yml
var evsFormat2SchemaYaml []byte

// The push every format-2 fixture's kind-5 headers name.
func evsFormat2TestPushId() Id {
	return evsTestId("push format 2")
}

// A kind-5 segment of one checkpoint record of body, general (slotKey nil) or slot-keyed, for pushId.
func evsTestKind5Segment(t testing.TB, keys *evsTestGenerationKeys, pushId Id, fileId Id, label string, body []byte, slotKey *EvsObjectKey, slotId Id) ([]byte, *EvsSegmentSummary, uint64) {
	t.Helper()
	out := &bytes.Buffer{}
	var builder *EvsSegmentBuilder
	var err error
	if slotKey == nil {
		builder, err = NewEvsKind5SegmentBuilder(out, keys.manifest, keys.fek, pushId)
	} else {
		builder, err = NewEvsSlotKeyedKind5SegmentBuilder(out, keys.manifest, pushId)
	}
	if err != nil {
		t.Fatal(err)
	}
	header := evsTestHeader(label, protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, len(body))
	var record io.WriteCloser
	if slotKey == nil {
		record, err = builder.BeginRecord(fileId, header)
	} else {
		header.KeyRefKind = protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT
		header.SlotId = slotId
		header.KeyIndex = 0
		header.Generation = keys.manifest.generation
		record, err = builder.BeginSlotRecord(keys.manifest, slotKey, fileId, header)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := record.Close(); err != nil {
		t.Fatal(err)
	}
	length := builder.length
	summary, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), summary, length
}

// What testdata/evs/format2/segment_vectors.json holds (schema.yml's vectors section).
type evsFormat2SegmentVectors struct {
	RandomSeed  uint64                     `json:"random_seed"`
	RepoId      hexBytes                   `json:"repo_id"`
	Generation  uint64                     `json:"generation"`
	FekKey      hexBytes                   `json:"fek_key"`
	ManifestKey hexBytes                   `json:"manifest_key"`
	FileId      hexBytes                   `json:"file_id"`
	PushId      hexBytes                   `json:"push_id"`
	Segments    []*evsFormat2SegmentVector `json:"segments"`
}

type evsFormat2SegmentVector struct {
	Name          string                `json:"name"`
	Segment       hexBytes              `json:"segment"`
	Id            hexBytes              `json:"id"`
	PaddedSize    uint64                `json:"padded_size"`
	Length        uint64                `json:"length"`
	Staged        bool                  `json:"staged"`
	Place         *evsRecordPlaceVector `json:"place"`
	ContentSha256 hexBytes              `json:"content_sha256"`
	SlotId        hexBytes              `json:"slot_id,omitempty"`
	Slot          hexBytes              `json:"slot,omitempty"`
}

func computeEvsFormat2SegmentVectors(t *testing.T) *evsFormat2SegmentVectors {
	const seed = 5
	cryptotest.SetGlobalRandom(t, seed)
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 3)
	fileId := evsTestId("file")
	pushId := evsFormat2TestPushId()
	vectors := &evsFormat2SegmentVectors{
		RandomSeed: seed, RepoId: repoId.Bytes(), Generation: 3, FekKey: keys.fek.key, ManifestKey: keys.manifest.key,
		FileId: fileId.Bytes(), PushId: pushId.Bytes(),
	}
	add := func(name string, body []byte, staged bool, slotKey *EvsObjectKey, slotId Id) *evsFormat2SegmentVector {
		segment, summary, length := evsTestKind5Segment(t, keys, pushId, fileId, name, body, slotKey, slotId)
		content := sha256.Sum256(body)
		vector := &evsFormat2SegmentVector{
			Name: name, Segment: segment, Id: summary.Id[:], PaddedSize: summary.PaddedSize, Length: length, Staged: staged,
			Place:         &evsRecordPlaceVector{Offset: summary.Places[0].Offset, Length: summary.Places[0].Length, BodyLength: uint64(len(body))},
			ContentSha256: content[:],
		}
		vectors.Segments = append(vectors.Segments, vector)
		return vector
	}
	add("general", evsTestBody(20000), false, nil, Id{})
	add("staged", evsTestBody(300), true, nil, Id{})
	slotKey := evsObjectKeyOf(evsTestBytes("versionless slot key", 32))
	slotId := evsTestId("versionless slot")
	vector := add("slot-keyed", evsTestBody(700), false, slotKey, slotId)
	wrapped, err := EvsWrapObjectKey(keys.fek, slotKey)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := EvsEncodeSlotObject(&protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 0, Generation: 3, Wrapped: wrapped}}})
	if err != nil {
		t.Fatal(err)
	}
	vector.SlotId = slotId.Bytes()
	vector.Slot = slot
	return vectors
}

// Each stored kind-5 segment is what this build writes; its 48 B header is EVS-FORMAT.md's, read apart from
// evs_segment_kind5.go; it opens to its body, whose SHA-256 is its content_sha256; and the staged one is a staged
// segment of its push.
func TestEvsFormat2SegmentVectors(t *testing.T) {
	stored := &evsFormat2SegmentVectors{}
	if !compareEvsVectors(t, "testdata/evs/format2/segment_vectors.json", evsFormat2SegmentVectorsJson, computeEvsFormat2SegmentVectors(t), stored) {
		return
	}
	repoId := Id(stored.RepoId)
	fekKey := &EvsFekKey{repoId: repoId, generation: stored.Generation, key: stored.FekKey}
	manifestKey := &EvsManifestKey{repoId: repoId, generation: stored.Generation, key: stored.ManifestKey}
	for _, vector := range stored.Segments {
		segment := []byte(vector.Segment)
		id := sha256.Sum256(segment)
		if !bytes.Equal(id[:], vector.Id) || uint64(len(segment)) != vector.PaddedSize || EvsPadme(vector.Length) != vector.PaddedSize {
			t.Errorf("%s: id, size or padding", vector.Name)
		}
		if !bytes.Equal(segment[0:4], []byte("URvs")) || segment[4] != 2 || segment[5] != 0 || segment[6] != 0 ||
			segment[7] != 0 || !bytes.Equal(segment[8:24], stored.RepoId) ||
			binary.BigEndian.Uint64(segment[24:32]) != stored.Generation || !bytes.Equal(segment[32:48], stored.PushId) {
			t.Errorf("%s: the 48 B header is not EVS-FORMAT.md's", vector.Name)
		}
		var reader *EvsSegmentReader
		var err error
		var slotKey EvsSlotKeyFunction
		wantOffset := uint32(EvsKind5SegmentHeaderByteCount + EvsWrappedKeyByteCount)
		if vector.Slot == nil {
			reader, err = NewEvsSegmentReaderFormat2(bytes.NewReader(segment), uint64(len(segment)), fekKey)
		} else {
			wantOffset = EvsKind5SegmentHeaderByteCount
			reader, err = NewEvsSlotKeyedSegmentReaderFormat2(bytes.NewReader(segment), uint64(len(segment)))
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
		if pushId, ok := reader.Kind5PushId(); !ok || pushId != Id(stored.PushId) {
			t.Errorf("%s: the reader names push %v", vector.Name, pushId)
		}
		if vector.Place.Offset != wantOffset {
			t.Errorf("%s: its record at %d, not %d", vector.Name, vector.Place.Offset, wantOffset)
		}
		_, body, err := reader.OpenRecord(manifestKey, EvsRecordPlace{Offset: vector.Place.Offset, Length: vector.Place.Length}, Id(stored.FileId), slotKey)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		read, err := io.ReadAll(body)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		content := sha256.Sum256(read)
		if !bytes.Equal(read, evsTestBody(int(vector.Place.BodyLength))) || !bytes.Equal(content[:], vector.ContentSha256) {
			t.Errorf("%s: read back as another body", vector.Name)
		}
		// any kind-5 segment within 16 KiB may ride staged; the staged vector does
		staged, err := EvsStagedSegmentOf(segment, repoId, Id(stored.PushId))
		if (vector.Staged && err != nil) || (EvsStagedSegmentMaxByteCount < vector.PaddedSize && err == nil) {
			t.Errorf("%s: staged %t at %d bytes, and EvsStagedSegmentOf says %v", vector.Name, vector.Staged, vector.PaddedSize, err)
		}
		if err == nil && (staged.Id != id || staged.NewObject().PaddedSize != vector.PaddedSize) {
			t.Errorf("%s: the staged segment's id or item", vector.Name)
		}
	}
}

// A kind-5 segment holds one record; format 1's reader refuses its header as needing format 2, and a format-2 reader
// reads a format-1 segment too, naming no push, since a kind-1 locator may name either.
func TestEvsKind5SegmentHoldsOneRecordAndFormat1RefusesIt(t *testing.T) {
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	out := &bytes.Buffer{}
	builder, err := NewEvsKind5SegmentBuilder(out, keys.manifest, keys.fek, evsFormat2TestPushId())
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.BeginRecord(evsTestId("file"), evsTestHeader("one", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 10))
	if err != nil {
		t.Fatal(err)
	}
	record.Write(evsTestBody(10))
	if err := record.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := builder.BeginRecord(evsTestId("file"), evsTestHeader("two", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 10)); !errors.Is(err, ErrEvsSegmentInvalid) {
		t.Errorf("a second record: %v", err)
	}
	if _, err := NewEvsKind5SegmentBuilder(out, keys.manifest, keys.fek, Id{}); !errors.Is(err, ErrEvsSegmentInvalid) {
		t.Errorf("a kind-5 segment naming no push: %v", err)
	}
	summary, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	segment := out.Bytes()
	if _, err := NewEvsSegmentReader(bytes.NewReader(segment), uint64(len(segment)), keys.fek); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("format 1 read a kind-5 segment: %v", err)
	}
	if EvsRefusalCodeOf(ErrEvsFormatUnsupported) != protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED {
		t.Error("FORMAT_UNSUPPORTED's code")
	}
	if summary.Places[0].Offset != evsKind5KeyedRecordOffset {
		t.Errorf("its record at %d", summary.Places[0].Offset)
	}

	format1 := &bytes.Buffer{}
	plain, err := NewEvsSegmentBuilder(format1, keys.manifest, keys.fek)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := plain.BeginRecord(evsTestId("file"), evsTestHeader("plain", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, 10))
	first.Write(evsTestBody(10))
	first.Close()
	plainSummary, err := plain.Finish()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewEvsSegmentReaderFormat2(bytes.NewReader(format1.Bytes()), uint64(format1.Len()), keys.fek)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reader.Kind5PushId(); ok {
		t.Error("a format-1 segment names a push")
	}
	if _, body, err := reader.OpenRecord(keys.manifest, plainSummary.Places[0], evsTestId("file"), nil); err != nil {
		t.Fatal(err)
	} else if read, _ := io.ReadAll(body); !bytes.Equal(read, evsTestBody(10)) {
		t.Error("a format-1 segment read through format 2 reads otherwise")
	}
}

// §11.13's upload check in format 2: a kind-5 header naming the upload's push is a versionless receipt's, one naming
// another push is 409 VERSIONING, a format-1 header is a plain receipt's, and format 1 refuses the kind-5 header.
func TestEvsKind5UploadNamesItsPush(t *testing.T) {
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	pushId := evsFormat2TestPushId()
	segment, _, _ := evsTestKind5Segment(t, keys, pushId, evsTestId("file"), "upload", evsTestBody(100), nil, Id{})
	size := uint64(len(segment))
	header, versionless, err := EvsCheckSegmentUploadFormat2(segment[:EvsKind5SegmentHeaderByteCount], size, keys.repoId, pushId)
	if err != nil || !versionless || header.Generation != 2 {
		t.Errorf("the upload's own push: %v %t", err, versionless)
	}
	_, _, err = EvsCheckSegmentUploadFormat2(segment[:EvsKind5SegmentHeaderByteCount], size, keys.repoId, evsTestId("another push"))
	if !errors.Is(err, ErrEvsVersioning) || EvsRefusalCodeOf(err) != protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING {
		t.Errorf("another push: %v", err)
	}
	if _, _, err := EvsCheckSegmentUploadFormat2(segment[:EvsKind5SegmentHeaderByteCount], size, evsTestId("another repo"), pushId); !errors.Is(err, ErrEvsSegmentInvalid) {
		t.Errorf("another repo: %v", err)
	}
	if _, err := EvsCheckSegmentUpload(segment[:EvsKind5SegmentHeaderByteCount], size, keys.repoId); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("format 1's upload check: %v", err)
	}
	plain := (&EvsSegmentHeader{RepoId: keys.repoId, Generation: 2}).encode()
	if _, versionless, err := EvsCheckSegmentUploadFormat2(plain, 4096, keys.repoId, pushId); err != nil || versionless {
		t.Errorf("a format-1 header: %v %t", err, versionless)
	}
}

// §11.7's staged row: a staged segment names this push and this repo, pads within 16 KiB, and frames as a count and
// length-prefixed segments, absent when none.
func TestEvsStagedSegmentRules(t *testing.T) {
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	pushId := evsFormat2TestPushId()
	small, _, _ := evsTestKind5Segment(t, keys, pushId, evsTestId("file"), "small", evsTestBody(200), nil, Id{})
	if _, err := EvsStagedSegmentOf(small, keys.repoId, pushId); err != nil {
		t.Fatal(err)
	}
	if _, err := EvsStagedSegmentOf(small, keys.repoId, evsTestId("another push")); !errors.Is(err, ErrEvsVersioning) {
		t.Errorf("a staged segment naming another push: %v", err)
	}
	if _, err := EvsStagedSegmentOf(small, evsTestId("another repo"), pushId); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("another repo's: %v", err)
	}
	large, _, _ := evsTestKind5Segment(t, keys, pushId, evsTestId("file"), "large", evsTestBody(20000), nil, Id{})
	if _, err := EvsStagedSegmentOf(large, keys.repoId, pushId); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a staged segment past 16 KiB: %v", err)
	}
	if EvsEncodeStaged(nil) != nil {
		t.Error("no staged segment framed as bytes")
	}
	framed := EvsEncodeStaged([][]byte{small, small[:100]})
	segments, err := EvsDecodeStaged(framed)
	if err != nil || len(segments) != 2 || !bytes.Equal(segments[0], small) || binary.BigEndian.Uint32(framed[:4]) != 2 {
		t.Errorf("framing: %v", err)
	}
	zeroCount := binary.BigEndian.AppendUint32(nil, 0)
	wrongCount := append(binary.BigEndian.AppendUint32(nil, 3), framed[4:]...)
	for name, bad := range map[string][]byte{"a count of 0": zeroCount, "a count past its items": wrongCount, "cut short": framed[:len(framed)-1], "three bytes": framed[:3]} {
		if _, err := EvsDecodeStaged(bad); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A format-2 test push: a versionless creation staged, a versionless replacement uploaded as kind 5, and a versioned
// file, with their new objects; its staged bytes beside it.
func evsTestFormat2Push(t testing.TB, signer *evsTestSigner, label string) (*EvsPushPlan, []byte) {
	t.Helper()
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 2)
	plan := evsTestPlan(t, signer, label, 0)
	plan.PushId = evsTestId("push " + label)
	plan.NewObjects = nil
	staged, _, _ := evsTestKind5Segment(t, keys, plan.PushId, evsTestId("file staged"), "staged "+label, evsTestBody(300), nil, Id{})
	stagedId := sha256.Sum256(staged)
	upload, uploadSummary, _ := evsTestKind5Segment(t, keys, plan.PushId, evsTestId("file uploaded"), "uploaded "+label, evsTestBody(30000), nil, Id{})
	plan.NewObjects = []*EvsNewObject{
		{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: uploadSummary.Id[:], PaddedSize: uint64(len(upload)), UploadDay: 20454},
		{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT, Id: stagedId[:], PaddedSize: uint64(len(staged))},
	}
	pathKey := evsTestPathKey(t, repoId, 2)
	entry := func(name string, versioning uint32, version uint64, chain []*protocol.EvsLocator) *EvsPlannedChange {
		tokenPath, err := EvsPathTokens(pathKey, [][]byte{[]byte(name)})
		if err != nil {
			t.Fatal(err)
		}
		entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
			Version: version, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
			Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: evsTestBytes("fields "+name, 32),
			Chain: chain, Versioning: versioning,
		})
		if err != nil {
			t.Fatal(err)
		}
		return &EvsPlannedChange{TokenPath: tokenPath, BaseEntryVersion: version - 1, EntryVersion: entryBytes}
	}
	plan.Changes = []*EvsPlannedChange{
		entry("staged.bin", 1, 1, []*protocol.EvsLocator{{
			Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: stagedId[:],
			Offset: evsKind5KeyedRecordOffset, Length: uint32(EvsRecordByteCount(300)), Staged: true,
		}}),
		entry("uploaded.bin", 1, 4, []*protocol.EvsLocator{{
			Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: uploadSummary.Id[:],
			Offset: uploadSummary.Places[0].Offset, Length: uploadSummary.Places[0].Length,
		}}),
		entry("kept.txt", 0, 2, []*protocol.EvsLocator{{
			Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: evsTestBytes("inline", 32),
		}}),
	}
	return plan, EvsEncodeStaged([][]byte{staged})
}

// §11.6's checks row in format 2 over a one-part push: format 1's checks refuse it as needing format 2, format 2's take
// it with its staged segment matched; a staged segment off its item, naming another push, missing, or one too many is
// refused, and so is a staged id the new-objects list does not name.
func TestEvsFormat2PayloadStagedChecks(t *testing.T) {
	signer := newEvsTestSigner("format 2 writer")
	plan, stagedBytes := evsTestFormat2Push(t, signer, "staged checks")
	built, err := NewEvsStatementBuilder(signer.sign).BuildFormat2(plan)
	if err != nil {
		t.Fatal(err)
	}
	if built.Statement.Push.GetPartCount() != 0 {
		t.Fatal("the push went to parts")
	}
	if _, err := EvsCheckPayload(built.Statement, built.Payload); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("format 1's check: %v", err)
	}
	checked, err := EvsCheckPayloadFormat2(built.Statement, built.Payload, stagedBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(checked.Staged) != 1 || checked.Staged[0].Header.PushId != plan.PushId || checked.Drop != nil {
		t.Error("the staged segment was not matched to its item")
	}
	segments, _ := EvsDecodeStaged(stagedBytes)
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	otherPush, _, _ := evsTestKind5Segment(t, keys, evsTestId("another push"), evsTestId("file staged"), "other", evsTestBody(300), nil, Id{})
	tampered := bytes.Clone(segments[0])
	tampered[len(tampered)-1] ^= 1
	cases := []struct {
		name   string
		staged []byte
		want   error
	}{
		{name: "none", staged: nil, want: ErrEvsPushInvalid},
		{name: "one too many", staged: EvsEncodeStaged([][]byte{segments[0], segments[0]}), want: ErrEvsPushInvalid},
		{name: "bytes off its id", staged: EvsEncodeStaged([][]byte{tampered}), want: ErrEvsPushInvalid},
		{name: "naming another push", staged: EvsEncodeStaged([][]byte{otherPush}), want: ErrEvsVersioning},
	}
	for _, c := range cases {
		if _, err := EvsCheckPayloadFormat2(built.Statement, built.Payload, c.staged); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}

	// a staged segment the new-objects list does not name: the plan lists only the upload
	unlisted, unlistedStaged := evsTestFormat2Push(t, signer, "staged unlisted")
	unlisted.NewObjects = unlisted.NewObjects[:1]
	built, err = NewEvsStatementBuilder(signer.sign).BuildFormat2(unlisted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvsCheckPayloadFormat2(built.Statement, built.Payload, unlistedStaged); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a staged id the new objects do not list: %v", err)
	}
}

// Format 2's entry and object shapes: versioning past 2 and versioning on a directory are malformed, a staged mark off
// kind 5 too, and a staged item with an upload day; a versionless receipt decodes only in format 2.
func TestEvsFormat2ShapeRefusals(t *testing.T) {
	push := &protocol.EvsPush{PushId: evsTestId("push").Bytes(), BaseVersion: 7}
	entry := func(mutate func(*protocol.EvsEntryVersion)) []byte {
		version := &protocol.EvsEntryVersion{
			Version: 1, PushId: push.PushId, BaseVersion: 7, Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE),
			SealedFields: evsTestBytes("fields", 32), Versioning: 1,
			Chain: []*protocol.EvsLocator{{
				Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: evsTestBytes("segment", 32),
				Offset: 120, Length: uint32(EvsRecordByteCount(10)),
			}},
		}
		mutate(version)
		encoded, _ := proto.Marshal(version)
		return encoded
	}
	if _, err := checkEvsEntryVersionOf(entry(func(*protocol.EvsEntryVersion) {}), push, true); err != nil {
		t.Errorf("a versionless file: %v", err)
	}
	if _, err := checkEvsEntryVersionOf(entry(func(*protocol.EvsEntryVersion) {}), push, false); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("format 1 took versioning 1: %v", err)
	}
	for name, mutate := range map[string]func(*protocol.EvsEntryVersion){
		"versioning 3": func(entry *protocol.EvsEntryVersion) { entry.Versioning = 3 },
		"a versionless directory": func(entry *protocol.EvsEntryVersion) {
			entry.Kind = uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)
			entry.SealedFields = nil
			entry.Chain = nil
		},
		"staged on kind 1": func(entry *protocol.EvsEntryVersion) {
			entry.Chain[0].Kind = uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT)
			entry.Chain[0].Staged = true
		},
		"a kind-5 record inside its header": func(entry *protocol.EvsEntryVersion) { entry.Chain[0].Offset = 40 },
		"a staged record past 16 KiB": func(entry *protocol.EvsEntryVersion) {
			entry.Chain[0].Staged = true
			entry.Chain[0].Offset = 16300
		},
	} {
		if _, err := checkEvsEntryVersionOf(entry(mutate), push, true); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	stagedItem := (&EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT, Id: evsTestBytes("staged", 32), PaddedSize: 448}).encode()
	if _, err := decodeEvsNewObjectOf(stagedItem, true); err != nil {
		t.Errorf("a staged item: %v", err)
	}
	if _, err := decodeEvsNewObject(stagedItem); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("format 1 took a staged item: %v", err)
	}
	withDay := (&EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT, Id: evsTestBytes("staged", 32), PaddedSize: 448, UploadDay: 3}).encode()
	tooLarge := (&EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT, Id: evsTestBytes("staged", 32), PaddedSize: 20480}).encode()
	for name, item := range map[string][]byte{"an upload day": withDay, "past 16 KiB": tooLarge} {
		if _, err := decodeEvsNewObjectOf(item, true); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("a staged item with %s: %v", name, err)
		}
	}
	receipt, _ := proto.Marshal(&protocol.EvsUploadReceipt{
		RepoId: evsTestId("repo").Bytes(), SegmentId: evsTestBytes("segment", 32), PaddedSize: 4096, UploadMs: 1,
		UploaderSidecarId: evsTestId("uploader").Bytes(), Mac: evsTestBytes("mac", 16), Versionless: true,
	})
	if _, err := DecodeEvsUploadReceipt(receipt); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("format 1 took a versionless receipt: %v", err)
	}
	if decoded, err := DecodeEvsUploadReceiptFormat2(receipt); err != nil || !decoded.GetVersionless() {
		t.Errorf("format 2's receipt: %v", err)
	}
}

// content_sha256 in format 2's sealed fields: required for versioning 1 and 2, refused on 0, a mismatch failing as
// tampering; format 1 still refuses it as needing format 2.
func TestEvsFormat2SealedFieldsCarryContentSha256(t *testing.T) {
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	content := sha256.Sum256(evsTestBody(100))
	fields := &protocol.EvsSealedFields{
		FileId: evsTestId("file").Bytes(), Mode: EvsGitModeFile, GitOid: evsTestBytes("oid", 20),
		OidKind: protocol.EvsOidKind_EVS_OID_SHA1, Size: 100, ContentSha256: content[:],
	}
	sealed, err := EvsSealFieldsFormat2(keys.manifest, fields, 1)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := EvsOpenFieldsFormat2(keys.manifest, sealed, 1)
	if err != nil || !bytes.Equal(opened.GetContentSha256(), content[:]) {
		t.Errorf("versioning 1: %v", err)
	}
	if _, err := EvsOpenFieldsFormat2(keys.manifest, sealed, 0); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("a versioned version's fields with content_sha256: %v", err)
	}
	if _, err := EvsOpenFields(keys.manifest, sealed); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("format 1 opened content_sha256: %v", err)
	}
	if _, err := EvsSealFieldsFormat2(keys.manifest, &protocol.EvsSealedFields{
		FileId: evsTestId("file").Bytes(), Mode: EvsGitModeFile, GitOid: evsTestBytes("oid", 20), OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
	}, 2); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("a versionless version's fields without content_sha256: %v", err)
	}
}

// A push in parts in format 2: each part's staged segments checked alone as it arrives, one naming another push
// refused there; at the seal, joined in part order, they are the kind-2 items in order, and out of order they are not.
func TestEvsFormat2PartsMatchStagedAtTheSeal(t *testing.T) {
	signer := newEvsTestSigner("format 2 parts")
	plan := evsTestPlan(t, signer, "format 2 parts", 1100)
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	stagedSegments := [][]byte{}
	for i := range 2 {
		segment, _, _ := evsTestKind5Segment(t, keys, plan.PushId, evsTestId("file"), fmt.Sprint("part staged ", i), evsTestBody(100+i), nil, Id{})
		id := sha256.Sum256(segment)
		stagedSegments = append(stagedSegments, segment)
		plan.NewObjects = append(plan.NewObjects, &EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT, Id: id[:], PaddedSize: uint64(len(segment))})
	}
	built, err := NewEvsStatementBuilder(signer.sign).BuildFormat2(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Parts) < 2 {
		t.Fatalf("%d parts", len(built.Parts))
	}
	partStaged := make([][]byte, len(built.Parts))
	partStaged[0] = EvsEncodeStaged(stagedSegments[:1])
	partStaged[len(partStaged)-1] = EvsEncodeStaged(stagedSegments[1:])
	checked, _, err := EvsCheckSealFormat2(built.Statement, built.Parts, partStaged)
	if err != nil {
		t.Fatal(err)
	}
	if len(checked.Staged) != 2 {
		t.Errorf("%d staged segments matched", len(checked.Staged))
	}
	swapped := make([][]byte, len(built.Parts))
	swapped[0] = EvsEncodeStaged(stagedSegments[1:])
	swapped[len(swapped)-1] = EvsEncodeStaged(stagedSegments[:1])
	if _, _, err := EvsCheckSealFormat2(built.Statement, built.Parts, swapped); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("staged segments out of their items' order: %v", err)
	}
	other, _, _ := evsTestKind5Segment(t, keys, evsTestId("another push"), evsTestId("file"), "part other", evsTestBody(100), nil, Id{})
	if _, err := EvsCheckPartFormat2(built.Statement, built.Parts[0], EvsEncodeStaged([][]byte{other})); !errors.Is(err, ErrEvsVersioning) {
		t.Errorf("a part staging another push's segment: %v", err)
	}
	if _, _, err := EvsCheckSealFormat2(built.Statement, built.Parts, partStaged[:1]); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("staged bytes for one part of many: %v", err)
	}
}

// What testdata/evs/format2/batch_vectors.json holds (schema.yml's vectors section).
type evsFormat2BatchVectors struct {
	Batches []*evsFormat2BatchVector  `json:"batches"`
	Windows []*evsFormat2WindowVector `json:"windows"`
	Staged  []*evsFormat2StagedVector `json:"staged"`
}

type evsFormat2BatchVector struct {
	Name      string                         `json:"name"`
	Instance  uint32                         `json:"instance"`
	Minute    uint32                         `json:"minute"`
	Seq       uint32                         `json:"seq"`
	CreatedMs int64                          `json:"created_ms"`
	Records   []*evsFormat2BatchRecordVector `json:"records"`
	Bytes     hexBytes                       `json:"bytes"`
}

type evsFormat2BatchRecordVector struct {
	Type            uint8    `json:"type"`
	Format          uint8    `json:"format"`
	RepoId          hexBytes `json:"repo_id"`
	RefId           hexBytes `json:"ref_id"`
	PushId          hexBytes `json:"push_id"`
	SignerSidecarId hexBytes `json:"signer_sidecar_id"`
	TimeMs          int64    `json:"time_ms"`
	Body            hexBytes `json:"body"`
	Staged          hexBytes `json:"staged"`
	PurgeList       hexBytes `json:"purge_list"`
	Offset          uint32   `json:"offset"`
	Length          uint32   `json:"length"`
}

type evsFormat2WindowVector struct {
	Name                string   `json:"name"`
	Encoded             hexBytes `json:"encoded"`
	Flags               uint32   `json:"flags"`
	ReplacesVersionless bool     `json:"replaces_versionless"`
	Drop                bool     `json:"drop"`
}

type evsFormat2StagedVector struct {
	Name     string     `json:"name"`
	Staged   hexBytes   `json:"staged"`
	Segments []hexBytes `json:"segments"`
}

// A purge list of one candidate, the test's.
func evsTestPurgeList(t testing.TB) []byte {
	encoded, err := EncodeEvsPurgeList(&protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{{
		TokenPath:        EvsTokenPath{evsTestToken("versionless")}.Components(),
		ReplacedVersion:  4,
		SegmentIds:       [][]byte{evsTestBytes("candidate 1", 32)},
		StagedSegmentIds: [][]byte{evsTestBytes("candidate staged", 32)},
		SlotIds:          [][]byte{evsTestId("candidate slot").Bytes()},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// A format-2 batch: a push record staging a segment and listing candidates, a part record staging one, a format-1
// form push between them, and a seal listing candidates; its records as added.
func evsTestFormat2Batch(t testing.TB) (*EvsBatchWriter, []*EvsBatchRecord, []*EvsBatchRecordTail) {
	t.Helper()
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	staged, _, _ := evsTestKind5Segment(t, keys, evsTestId("push a"), evsTestId("file"), "batch staged", evsTestBody(120), nil, Id{})
	writer := NewEvsBatchWriter(0x0a0b0c0e, 29453761, 3, 1767225660123)
	statement := evsTestBody(200)
	place := &protocol.EvsPlace{Minute: 29453761, Instance: 0x0a0b0c0e, Seq: 2, Offset: 32, Length: 500}
	records := []*EvsBatchRecord{
		{Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, Body: EvsPushRecordBody(statement, evsTestBytes("payload", 32))},
		{Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, Body: EvsPushRecordBody(statement, evsTestBytes("payload 1", 32))},
		{Type: protocol.EvsBatchRecordType_EVS_BATCH_PART, Body: EvsPartRecordBody(statement, evsTestBytes("part", 32), [][]byte{evsTestBytes("receipt", 32)}, 41)},
		{Type: protocol.EvsBatchRecordType_EVS_BATCH_SEAL, Body: EvsSealRecordBody(statement, []*EvsSealPart{
			{Place: place, ChangesRoot: [32]byte(evsTestBytes("root 1", 32)), FirstTokenPath: EvsTokenPath{evsTestToken("a")}},
			{Place: place, ChangesRoot: [32]byte(evsTestBytes("root 2", 32)), FirstTokenPath: EvsTokenPath{evsTestToken("b")}},
		})},
	}
	tails := []*EvsBatchRecordTail{
		{Staged: EvsEncodeStaged([][]byte{staged}), PurgeList: evsTestPurgeList(t)},
		nil,
		{Staged: EvsEncodeStaged([][]byte{staged})},
		{PurgeList: evsTestPurgeList(t)},
	}
	for i, record := range records {
		record.RepoId = evsTestId("repo")
		record.RefId = evsTestId("ref main")
		record.PushId = evsTestId("push " + string(rune('a'+i)))
		record.SignerSidecarId = evsTestId("sidecar writer")
		record.TimeMs = 1767225660000 + int64(i)
		if _, err := writer.AddFormat2(record, tails[i]); err != nil {
			t.Fatal(err)
		}
	}
	return writer, records, tails
}

func computeEvsFormat2BatchVectors(t *testing.T) *evsFormat2BatchVectors {
	cryptotest.SetGlobalRandom(t, 7)
	writer, records, tails := evsTestFormat2Batch(t)
	batchBytes, err := writer.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ParseEvsBatchFormat2(batchBytes)
	if err != nil {
		t.Fatal(err)
	}
	vector := &evsFormat2BatchVector{
		Name: "a format-2 batch", Instance: 0x0a0b0c0e, Minute: 29453761, Seq: 3, CreatedMs: 1767225660123, Bytes: batchBytes,
	}
	for i, record := range records {
		recordVector := &evsFormat2BatchRecordVector{
			Type: uint8(record.Type), RepoId: record.RepoId.Bytes(), RefId: record.RefId.Bytes(), PushId: record.PushId.Bytes(),
			SignerSidecarId: record.SignerSidecarId.Bytes(), TimeMs: record.TimeMs, Body: record.Body,
			Offset: batch.Places[i].GetOffset(), Length: batch.Places[i].GetLength(),
		}
		if !tails[i].Empty() {
			recordVector.Format = 2
			recordVector.Staged = tails[i].Staged
			recordVector.PurgeList = tails[i].PurgeList
		}
		vector.Records = append(vector.Records, recordVector)
	}
	vectors := &evsFormat2BatchVectors{Batches: []*evsFormat2BatchVector{vector}}

	statementSha256 := sha256.Sum256([]byte("statement"))
	place := &protocol.EvsPlace{Minute: 29453761, Instance: 0x0a0b0c0e, Seq: 3, Offset: 32, Length: 900}
	tokenPath := EvsTokenPath{evsTestToken("versionless")}
	replacing := NewEvsWindowEntry(statementSha256, &protocol.EvsPush{PushId: evsTestId("push replacing").Bytes(), Changes: []*protocol.EvsChange{{}}}, []EvsTokenPath{tokenPath}, nil, false, place)
	replacing.SetReplacesVersionless()
	drop := NewEvsWindowEntry(statementSha256, &protocol.EvsPush{PushId: evsTestId("push drop").Bytes(), Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)}, nil, nil, false, place)
	for _, entry := range []struct {
		name  string
		entry *EvsWindowEntry
	}{{name: "a versionless replacement", entry: replacing}, {name: "a DROP", entry: drop}} {
		vectors.Windows = append(vectors.Windows, &evsFormat2WindowVector{
			Name: entry.name, Encoded: entry.entry.Encode(), Flags: entry.entry.Flags,
			ReplacesVersionless: entry.entry.ReplacesVersionless(), Drop: entry.entry.Drop(),
		})
	}
	segments, err := tails[0].StagedSegments()
	if err != nil {
		t.Fatal(err)
	}
	stagedVector := &evsFormat2StagedVector{Name: "one staged segment", Staged: tails[0].Staged}
	for _, segment := range segments {
		stagedVector.Segments = append(stagedVector.Segments, segment)
	}
	vectors.Staged = append(vectors.Staged, stagedVector)
	return vectors
}

// The stored format-2 batch is what this build writes and reads back, record by record at its place: each format-2
// record's header byte 1 is 2 and its tail EVS-FORMAT.md's two items, a format-1 form record in its batch keeps byte 1
// zero, and format 1's readers refuse the batch and each format-2 record as needing format 2. The window entries'
// bits 4 and 5 sit where EVS-FORMAT.md puts them, and format 1's decode keeps them as read.
func TestEvsFormat2BatchVectors(t *testing.T) {
	stored := &evsFormat2BatchVectors{}
	if !compareEvsVectors(t, "testdata/evs/format2/batch_vectors.json", evsFormat2BatchVectorsJson, computeEvsFormat2BatchVectors(t), stored) {
		return
	}
	for _, vector := range stored.Batches {
		batchBytes := []byte(vector.Bytes)
		if batchBytes[4] != 2 {
			t.Errorf("%s: header format %d", vector.Name, batchBytes[4])
		}
		if _, err := ParseEvsBatch(batchBytes); !errors.Is(err, ErrEvsFormatUnsupported) {
			t.Errorf("%s: format 1 read the batch: %v", vector.Name, err)
		}
		batch, err := ParseEvsBatchFormat2(batchBytes)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		reader := NewEvsBatchReader(bytes.NewReader(batchBytes))
		for i, recordVector := range vector.Records {
			recordBytes := batchBytes[recordVector.Offset : recordVector.Offset+recordVector.Length]
			if recordBytes[0] != recordVector.Type || recordBytes[1] != recordVector.Format {
				t.Errorf("%s record %d: type or format byte", vector.Name, i)
			}
			if !bytes.Equal(batch.Records[i].Body, recordVector.Body) {
				t.Errorf("%s record %d: its body", vector.Name, i)
			}
			record, tail, err := reader.RecordFormat2(&protocol.EvsPlace{Offset: recordVector.Offset, Length: recordVector.Length})
			if err != nil {
				t.Fatalf("%s record %d: %v", vector.Name, i, err)
			}
			if !bytes.Equal(record.Body, recordVector.Body) {
				t.Errorf("%s record %d: read alone, another body", vector.Name, i)
			}
			if recordVector.Format == 0 {
				if tail != nil {
					t.Errorf("%s record %d: a tail on a format-1 form record", vector.Name, i)
				}
				if _, err := ParseEvsBatchRecord(recordBytes); err != nil {
					t.Errorf("%s record %d: format 1 refused its own form: %v", vector.Name, i, err)
				}
				continue
			}
			wantTail := append(binary.BigEndian.AppendUint32(nil, uint32(len(recordVector.Staged))), recordVector.Staged...)
			wantTail = binary.BigEndian.AppendUint32(wantTail, uint32(len(recordVector.PurgeList)))
			wantTail = append(wantTail, recordVector.PurgeList...)
			if !bytes.HasSuffix(recordBytes, wantTail) || !bytes.Equal(tail.Staged, recordVector.Staged) || !bytes.Equal(tail.PurgeList, recordVector.PurgeList) {
				t.Errorf("%s record %d: its tail is not EVS-FORMAT.md's", vector.Name, i)
			}
			if _, err := ParseEvsBatchRecord(recordBytes); !errors.Is(err, ErrEvsFormatUnsupported) {
				t.Errorf("%s record %d: format 1 read a format-2 record: %v", vector.Name, i, err)
			}
		}
	}
	for _, vector := range stored.Windows {
		entry, err := DecodeEvsWindowEntry(vector.Encoded)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		flags := binary.BigEndian.Uint32(vector.Encoded[60:64])
		if entry.Flags != vector.Flags || flags != vector.Flags || entry.ReplacesVersionless() != vector.ReplacesVersionless ||
			entry.Drop() != vector.Drop || (flags&16 != 0) != vector.ReplacesVersionless || (flags&32 != 0) != vector.Drop {
			t.Errorf("%s: bits 4 and 5", vector.Name)
		}
	}
	for _, vector := range stored.Staged {
		segments, err := EvsDecodeStaged(vector.Staged)
		if err != nil || len(segments) != len(vector.Segments) || binary.BigEndian.Uint32(vector.Staged[:4]) != uint32(len(segments)) {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		for i, segment := range segments {
			if !bytes.Equal(segment, vector.Segments[i]) {
				t.Errorf("%s: segment %d", vector.Name, i)
			}
		}
	}
}

// Format 2's batch bounds: a record's 1 MiB counts its tail, a seal staging a segment is refused, a purge list past
// 2,048 ids or a marked one listing candidates is refused, and a batch whose header and records disagree on format 2
// is refused.
func TestEvsFormat2BatchBoundsAndRefusals(t *testing.T) {
	writer := NewEvsBatchWriter(1, 2, 3, 4)
	record := &EvsBatchRecord{Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, Body: EvsPushRecordBody(evsTestBody(100), make([]byte, EvsBatchMaxRecordByteCount-1000))}
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	staged, _, _ := evsTestKind5Segment(t, keys, evsTestId("push"), evsTestId("file"), "bound", evsTestBody(5000), nil, Id{})
	if _, err := writer.AddFormat2(record, &EvsBatchRecordTail{Staged: EvsEncodeStaged([][]byte{staged})}); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a record past 1 MiB by its staged tail: %v", err)
	}
	seal := &EvsBatchRecord{Type: protocol.EvsBatchRecordType_EVS_BATCH_SEAL, Body: EvsPushRecordBody(evsTestBody(10), nil)}
	if _, err := writer.AddFormat2(seal, &EvsBatchRecordTail{Staged: EvsEncodeStaged([][]byte{staged})}); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a seal staging a segment: %v", err)
	}
	manyIds := &protocol.EvsPurgeCandidate{TokenPath: EvsTokenPath{evsTestToken("x")}.Components(), ReplacedVersion: 1}
	for i := range DefaultEvsFormatSettings().PurgeListMaxIdCount + 1 {
		manyIds.SegmentIds = append(manyIds.SegmentIds, evsTestBytes(fmt.Sprint("id ", i), 32))
	}
	for name, list := range map[string]*protocol.EvsPurgeList{
		"past 2,048 ids":    {Candidates: []*protocol.EvsPurgeCandidate{manyIds}},
		"marked and listed": {Marked: true, Candidates: []*protocol.EvsPurgeCandidate{{TokenPath: manyIds.TokenPath, ReplacedVersion: 1, SlotIds: [][]byte{evsTestId("s").Bytes()}}}},
		"empty":             {},
		"a repeated id":     {Candidates: []*protocol.EvsPurgeCandidate{{TokenPath: manyIds.TokenPath, ReplacedVersion: 1, SegmentIds: [][]byte{manyIds.SegmentIds[0], manyIds.SegmentIds[0]}}}},
		"an id of 20 bytes": {Candidates: []*protocol.EvsPurgeCandidate{{TokenPath: manyIds.TokenPath, ReplacedVersion: 1, SlotIds: [][]byte{evsTestBytes("short", 20)}}}},
		"no version":        {Candidates: []*protocol.EvsPurgeCandidate{{TokenPath: manyIds.TokenPath, SlotIds: [][]byte{evsTestId("s").Bytes()}}}},
	} {
		if _, err := EncodeEvsPurgeList(list); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("a purge list %s: %v", name, err)
		}
	}
	if encoded, err := EncodeEvsPurgeList(&protocol.EvsPurgeList{Marked: true}); err != nil || len(encoded) == 0 {
		t.Errorf("a marked list: %v", err)
	}

	format2Writer, _, _ := evsTestFormat2Batch(t)
	batchBytes, err := format2Writer.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	rehash := func(batch []byte) []byte {
		trailerAt := len(batch) - EvsBatchTrailerByteCount
		digest := sha256.Sum256(batch[:trailerAt])
		copy(batch[trailerAt+4:], digest[:])
		return batch
	}
	asFormat1 := bytes.Clone(batchBytes)
	asFormat1[4] = 1
	if _, err := ParseEvsBatchFormat2(rehash(asFormat1)); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a format-1 header over format-2 records: %v", err)
	}
	asFormat3 := bytes.Clone(batchBytes)
	asFormat3[4] = 3
	if _, err := ParseEvsBatchFormat2(rehash(asFormat3)); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("a batch of format 3, which an evacuator leaves: %v", err)
	}
	plainWriter, _ := evsTestBatch(t)
	plainBytes, err := plainWriter.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	plainAsFormat2 := bytes.Clone(plainBytes)
	plainAsFormat2[4] = 2
	if _, err := ParseEvsBatchFormat2(rehash(plainAsFormat2)); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a format-2 header over format-1 records: %v", err)
	}
	if batch, err := ParseEvsBatchFormat2(plainBytes); err != nil || len(batch.Tails) != len(batch.Records) {
		t.Errorf("a format-1 batch through format 2: %v", err)
	}
}

// A window entry's bits 4 and 5: a DROP's statement sets bit 5, evs sets bit 4, and format 1's decode keeps both as
// read without meaning; bit 6 is still refused.
func TestEvsFormat2WindowBits(t *testing.T) {
	place := &protocol.EvsPlace{Minute: 1, Offset: 32, Length: 100}
	statementSha256 := sha256.Sum256([]byte("drop"))
	drop := NewEvsWindowEntry(statementSha256, &protocol.EvsPush{PushId: evsTestId("drop").Bytes(), Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)}, nil, nil, false, place)
	if !drop.Drop() || drop.ReplacesVersionless() {
		t.Errorf("a DROP's flags %#x", drop.Flags)
	}
	plain := NewEvsWindowEntry(statementSha256, &protocol.EvsPush{PushId: evsTestId("plain").Bytes()}, nil, nil, false, place)
	if plain.Drop() || plain.ReplacesVersionless() {
		t.Errorf("a plain push's flags %#x", plain.Flags)
	}
	plain.SetReplacesVersionless()
	decoded, err := DecodeEvsWindowEntry(plain.Encode())
	if err != nil || !decoded.ReplacesVersionless() {
		t.Errorf("bit 4 as read: %v", err)
	}
	encoded := plain.Encode()
	encoded[63] |= 64
	if _, err := DecodeEvsWindowEntry(encoded); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("bit 6: %v", err)
	}
}

// schema.yml's layouts are this build's constants: the kind-5 header, the staged bound, the record's format byte and
// tail, the purge list's cap, the drop's bounds and window, and the window bits.
func TestEvsFormat2LayoutsMatchTheSchema(t *testing.T) {
	schema := &struct {
		Layouts map[string]int64 `yaml:"layouts"`
	}{}
	if err := yaml.Unmarshal(evsFormat2SchemaYaml, schema); err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{
		"repo/ format":                    2,
		"segment header format":           int64(evsSegmentFormat2),
		"kind-5 segment header bytes":     EvsKind5SegmentHeaderByteCount,
		"kind-5 segment push_id offset":   evsKind5PushIdOffset,
		"kind-5 general records offset":   evsKind5KeyedRecordOffset,
		"staged segment max padded bytes": EvsStagedSegmentMaxByteCount,
		"batch header format":             int64(evsBatchFormat2),
		"batch record format":             evsBatchRecordFormat2,
		"batch record format byte":        evsBatchRecordFormatByte,
		"batch record tail items":         evsBatchRecordTailItemCount,
		"purge list max ids":              int64(DefaultEvsFormatSettings().PurgeListMaxIdCount),
		"drop max paths":                  int64(DefaultEvsFormatSettings().DropMaxPathCount),
		"drop max listed versions":        int64(DefaultEvsFormatSettings().DropMaxListedCount),
		"drop max body bytes":             int64(DefaultEvsFormatSettings().DropMaxBodyByteCount),
		"drop list part values":           int64(DefaultEvsFormatSettings().DropListPartValueCount),
		"drop window ms":                  DefaultEvsFormatSettings().DropWindowMs(),
		"window bit versionless replaced": 4,
		"window bit drop":                 5,
	}
	for name, value := range want {
		if schema.Layouts[name] != value {
			t.Errorf("%s: the schema says %d, and this build %d", name, schema.Layouts[name], value)
		}
	}
	if len(schema.Layouts) != len(want) {
		t.Errorf("the schema lists %d layouts, and this test checks %d", len(schema.Layouts), len(want))
	}
	if uint32(protocol.EvsWindowFlag_EVS_WINDOW_VERSIONLESS_REPLACED) != 1<<4 || uint32(protocol.EvsWindowFlag_EVS_WINDOW_DROP) != 1<<5 {
		t.Error("window bits 4 and 5")
	}
}

// §22.6's segment target over a kind-5 segment: whatever is done to its bytes, its one record opens to its body or
// fails, releasing no byte past a frame that failed (evsFuzzTamper's ops; seeds in testdata/fuzz/evs_segment).
func checkEvsKind5SegmentTampering(t *testing.T, fixture *evsFuzzSegmentFixture, input []byte) {
	tampered := evsFuzzTamper(fixture.segment, input, func(segment []byte) {
		at := int(fixture.places[0].Offset) + EvsRecordHeaderByteCount
		frameByteCount := EvsRecordFrameByteCount + 16
		if at+2*frameByteCount <= len(segment) {
			first := bytes.Clone(segment[at : at+frameByteCount])
			copy(segment[at:], segment[at+frameByteCount:at+2*frameByteCount])
			copy(segment[at+frameByteCount:], first)
		}
	})
	reader, err := NewEvsSegmentReaderFormat2(bytes.NewReader(tampered), uint64(len(tampered)), fixture.keys.fek)
	if err != nil {
		return
	}
	if pushId, ok := reader.Kind5PushId(); !ok || pushId != evsFormat2TestPushId() {
		// a header naming another push is no longer this push's segment; its id, which locators name, differs too
		return
	}
	_, body, err := reader.OpenRecord(fixture.keys.manifest, fixture.places[0], fixture.fileId, nil)
	if err != nil {
		return
	}
	read, err := io.ReadAll(body)
	if err == nil && !bytes.Equal(read, fixture.bodies[0]) {
		t.Fatal("a tampered kind-5 segment opened to other bytes")
	}
	if err != nil && (!bytes.HasPrefix(fixture.bodies[0], read) || len(read)%EvsRecordFrameByteCount != 0) {
		t.Fatalf("released %d bytes before failing", len(read))
	}
}

// The kind-5 segment the target tampers with: one record of two frames and more.
func newEvsFuzzKind5SegmentFixture(t testing.TB) *evsFuzzSegmentFixture {
	fixture := &evsFuzzSegmentFixture{
		keys:   evsTestKeys(t, evsTestId("repo"), 2),
		fileId: evsTestId("file"),
		bodies: [][]byte{evsTestBody(2*EvsRecordFrameByteCount + 700)},
	}
	segment, summary, _ := evsTestKind5Segment(t, fixture.keys, evsFormat2TestPushId(), fixture.fileId, "fuzz kind 5", fixture.bodies[0], nil, Id{})
	fixture.segment = segment
	fixture.places = summary.Places
	return fixture
}

func TestEvsKind5SegmentFuzzSeeds(t *testing.T) {
	fixture := newEvsFuzzKind5SegmentFixture(t)
	checkEvsKind5SegmentTampering(t, fixture, nil)
	for _, seed := range evsFuzzSeedFiles(t, "testdata/fuzz/evs_segment") {
		checkEvsKind5SegmentTampering(t, fixture, seed)
	}
}

// §22.6's batch target in format 2: a tampered batch either fails to parse or reads back the original's records and
// tails, every staged segment and purge list as written.
func checkEvsFormat2BatchTampering(t *testing.T, original []byte, input []byte) {
	tampered := evsFuzzTamper(original, input, func([]byte) {})
	batch, err := ParseEvsBatchFormat2(tampered)
	if err != nil {
		return
	}
	want, err := ParseEvsBatchFormat2(original)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Records) != len(want.Records) {
		t.Fatal("a tampered batch read back with other records")
	}
	for i := range batch.Records {
		if !bytes.Equal(batch.Records[i].Body, want.Records[i].Body) || (batch.Tails[i] == nil) != (want.Tails[i] == nil) {
			t.Fatalf("record %d read back otherwise", i)
		}
		if batch.Tails[i] != nil && (!bytes.Equal(batch.Tails[i].Staged, want.Tails[i].Staged) || !bytes.Equal(batch.Tails[i].PurgeList, want.Tails[i].PurgeList)) {
			t.Fatalf("record %d's tail read back otherwise", i)
		}
	}
}

func TestEvsFormat2BatchFuzzSeeds(t *testing.T) {
	writer, _, _ := evsTestFormat2Batch(t)
	original, err := writer.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	checkEvsFormat2BatchTampering(t, original, nil)
	for _, seed := range evsFuzzSeedFiles(t, "testdata/fuzz/evs_batch") {
		checkEvsFormat2BatchTampering(t, original, seed)
	}
}

// R-EVS-14: 2 GiB of versionless content as 512 kind-5 chunk segments of 4 MiB each, streamed through the kind-5
// builder into a hash, holds no segment: the heap past its baseline stays under 4 MiB.
func TestEvsKind5WorkingSetStaysUnder4MiB(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("the Worker leg runs the codec's other tests; 2 GiB in wasm is a review-phase hand run")
	}
	const chunkByteCount = 4 * 1024 * 1024
	const chunkCount = 512
	keys := evsTestKeys(t, evsTestId("repo"), 1)
	fileId := evsTestId("file")
	source := make([]byte, EvsRecordFrameByteCount)
	stats := &runtime.MemStats{}
	runtime.GC()
	runtime.ReadMemStats(stats)
	baseline := stats.HeapAlloc
	peak := uint64(0)
	// What the builder holds, not what it has let go of: each sample collects first. Garbage waits for
	// the collector, whose pace follows the heap the rest of the package left, so counting it failed
	// this test in a full package run now and then, and passed it alone.
	sample := func() {
		runtime.GC()
		runtime.ReadMemStats(stats)
		peak = max(peak, stats.HeapAlloc-min(stats.HeapAlloc, baseline))
	}
	for chunk := range chunkCount {
		segmentHash := sha256.New()
		builder, err := NewEvsKind5SegmentBuilder(segmentHash, keys.manifest, keys.fek, evsFormat2TestPushId())
		if err != nil {
			t.Fatal(err)
		}
		record, err := builder.BeginRecord(fileId, evsTestHeader("chunk", protocol.EvsRecordKind_EVS_RECORD_CHUNK, chunkByteCount))
		if err != nil {
			t.Fatal(err)
		}
		for frame := range chunkByteCount / EvsRecordFrameByteCount {
			for i := range source {
				source[i] = byte(chunk + frame + i)
			}
			if _, err := record.Write(source); err != nil {
				t.Fatal(err)
			}
			// mid-record, and on the record's last frame, where a builder that kept the chunk holds most
			if frame%32 == 31 {
				sample()
			}
		}
		if err := record.Close(); err != nil {
			t.Fatal(err)
		}
		summary, err := builder.Finish()
		if err != nil {
			t.Fatal(err)
		}
		if summary.Id != [sha256.Size]byte(segmentHash.Sum(nil)) {
			t.Fatal("a segment's id is not the hash of the bytes it wrote")
		}
	}
	sample()
	if 4*1024*1024 <= peak {
		t.Errorf("the kind-5 builder held %d bytes past its baseline", peak)
	}
}
