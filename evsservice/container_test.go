package evsservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A batch of minute holding one record per item, each typed and sized as given, and its records as a container
// takes them.
type containerTestBatch struct {
	key     string
	bytes   []byte
	records []*ContainerRecord
}

func newContainerTestBatch(t testing.TB, minute uint32, seq uint32, repoId sidecar.Id, refId sidecar.Id, firstVersion uint64, types []protocol.EvsBatchRecordType) *containerTestBatch {
	t.Helper()
	writer := sidecar.NewEvsBatchWriter(7, minute, seq, int64(minute)*60000)
	places := []*protocol.EvsPlace{}
	for i, recordType := range types {
		body := bytes.Repeat([]byte{byte(i + 1)}, 40+i)
		place, err := writer.Add(&sidecar.EvsBatchRecord{Type: recordType, RepoId: repoId, RefId: refId, PushId: sidecar.Id(sha256Prefix(t, body)), TimeMs: int64(minute) * 60000, Body: body})
		if err != nil {
			t.Fatal(err)
		}
		places = append(places, place)
	}
	batchBytes, err := writer.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	batch := &containerTestBatch{key: BatchKey(minute, 7, seq), bytes: batchBytes}
	for i, place := range places {
		batch.records = append(batch.records, &ContainerRecord{
			RefId:   refId,
			Version: firstVersion + uint64(i),
			Place:   place,
			Bytes:   bytes.Clone(batchBytes[place.GetOffset() : place.GetOffset()+place.GetLength()]),
		})
	}
	return batch
}

func sha256Prefix(t testing.TB, data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:16]
}

func testIdFrom(text string) sidecar.Id {
	sum := sha256.Sum256([]byte(text))
	return sidecar.Id(sum[:16])
}

// A rerun over the same inputs, in any order, builds equal bytes and so the same id.
func TestContainerIsDeterministic(t *testing.T) {
	repoId := testIdFrom("repo")
	refA := testIdFrom("ref a")
	refB := testIdFrom("ref b")
	types := []protocol.EvsBatchRecordType{protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_PART, protocol.EvsBatchRecordType_EVS_BATCH_SEAL}
	records := append(newContainerTestBatch(t, 1000, 1, repoId, refA, 10, types).records, newContainerTestBatch(t, 1001, 2, repoId, refB, 3, types).records...)
	logPages := []*ContainerLogPage{{RefId: refA, Page: 0, Bytes: []byte("page a0")}, {RefId: refB, Page: 0, Bytes: []byte("page b0")}}
	first, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PACK, records, logPages)
	if err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		shuffled := append([]*ContainerRecord{}, records...)
		random.Shuffle(len(shuffled), func(i int, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		pages := []*ContainerLogPage{logPages[1], logPages[0]}
		again, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PACK, shuffled, pages)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again.Bytes, first.Bytes) || again.Id != first.Id {
			t.Fatal("a rerun built other bytes")
		}
	}
	sum := sha256.Sum256(first.Bytes)
	if !bytes.Equal(first.Id[:], sum[:16]) {
		t.Fatal("the id is not the first 16 B of the bytes' SHA-256")
	}
}

// Each ref's entry lists its records with their kinds, versions, places and offsets into the container, where the
// record's bytes are exactly its batch's, so a part is found by the place its seal names.
func TestContainerEntriesNameEachRecordByPlace(t *testing.T) {
	repoId := testIdFrom("repo")
	refId := testIdFrom("ref")
	types := []protocol.EvsBatchRecordType{protocol.EvsBatchRecordType_EVS_BATCH_PART, protocol.EvsBatchRecordType_EVS_BATCH_PART, protocol.EvsBatchRecordType_EVS_BATCH_SEAL}
	batch := newContainerTestBatch(t, 2000, 1, repoId, refId, 40, types)
	// the parts take their seal's version
	batch.records[0].Version = 42
	batch.records[1].Version = 42
	segmentId := sha256.Sum256([]byte("segment"))
	batch.records[2].SegmentIds = [][32]byte{segmentId}
	container, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PARCEL, batch.records, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry := container.RefEntries[refId]
	if entry.GetFirstVersion() != 42 || entry.GetLastVersion() != 42 || len(entry.GetRecords()) != 3 || len(entry.GetSegmentIds()) != 1 {
		t.Fatalf("entry %v", entry)
	}
	for _, record := range batch.records {
		found := false
		for _, listed := range entry.GetRecords() {
			if comparePlaces(listed.GetPlace(), record.Place) != 0 {
				continue
			}
			found = true
			held := container.Bytes[listed.GetOffset() : listed.GetOffset()+uint64(listed.GetLength())]
			if !bytes.Equal(held, record.Bytes) {
				t.Fatal("a record's bytes moved")
			}
			parsed, err := sidecar.ParseEvsBatchRecord(held)
			if err != nil || parsed.Type != listed.GetType() {
				t.Fatalf("parsed %v %v", parsed, err)
			}
		}
		if !found {
			t.Fatal("a record's place is not listed")
		}
	}
	keys, entryBytes, err := container.EntryKeys(repoId)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != PidxKey(repoId, refId, 42, container.Id) {
		t.Fatalf("keys %v", keys)
	}
	decoded, err := DecodeEvsPidxEntry(entryBytes[0])
	if err != nil || decoded.GetFirstVersion() != 42 {
		t.Fatalf("decoded %v %v", decoded, err)
	}
	if first, containerId, ok := parsePidxKey(PidxRefPrefix(repoId, refId), keys[0]); !ok || first != 42 || containerId != container.Id {
		t.Fatalf("key parsed to %d %v %v", first, containerId, ok)
	}
}

// Parcels hold records only, and a container refuses what breaks its rules.
func TestContainerRefusesWhatBreaksItsRules(t *testing.T) {
	repoId := testIdFrom("repo")
	refId := testIdFrom("ref")
	batch := newContainerTestBatch(t, 3000, 1, repoId, refId, 1, []protocol.EvsBatchRecordType{protocol.EvsBatchRecordType_EVS_BATCH_PUSH})
	page := []*ContainerLogPage{{RefId: refId, Page: 0, Bytes: []byte("page")}}
	if _, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PARCEL, batch.records, page); !errors.Is(err, ErrEvsContainerInvalid) {
		t.Errorf("a parcel with a log page: %v", err)
	}
	if _, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PACK, nil, nil); !errors.Is(err, ErrEvsContainerInvalid) {
		t.Errorf("an empty pack: %v", err)
	}
	twice := append(append([]*ContainerRecord{}, batch.records...), batch.records...)
	if _, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PACK, twice, nil); !errors.Is(err, ErrEvsContainerInvalid) {
		t.Errorf("one place twice: %v", err)
	}
	short := *batch.records[0]
	short.Bytes = short.Bytes[:len(short.Bytes)-1]
	if _, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PACK, []*ContainerRecord{&short}, nil); !errors.Is(err, ErrEvsContainerInvalid) {
		t.Errorf("a record shorter than its place: %v", err)
	}
}

// testdata/evs/pidx/'s vector: a pack of two refs, a push and a seal on one and a part with a log page on the other.
// The bytes and ids pin the container layout and EvsPidxEntry's encoding. EVS_PIDX_VECTORS_WRITE=1 rewrites it.
type pidxVector struct {
	ContainerSha256 string            `json:"container_sha256"`
	ContainerId     string            `json:"container_id"`
	EntryKeys       []string          `json:"entry_keys"`
	EntryHex        map[string]string `json:"entry_hex"`
}

func buildPidxVectorContainer(t testing.TB) (*Container, sidecar.Id) {
	repoId := testIdFrom("vector repo")
	refA := testIdFrom("vector ref a")
	refB := testIdFrom("vector ref b")
	records := newContainerTestBatch(t, 29000000, 1, repoId, refA, 128, []protocol.EvsBatchRecordType{protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_SEAL}).records
	records = append(records, newContainerTestBatch(t, 29000001, 4, repoId, refB, 7, []protocol.EvsBatchRecordType{protocol.EvsBatchRecordType_EVS_BATCH_PART}).records...)
	container, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PACK, records, []*ContainerLogPage{{RefId: refB, Page: 0, Bytes: []byte("vector log page")}})
	if err != nil {
		t.Fatal(err)
	}
	return container, repoId
}

func TestPidxVectors(t *testing.T) {
	container, repoId := buildPidxVectorContainer(t)
	keys, entryBytes, err := container.EntryKeys(repoId)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(container.Bytes)
	got := &pidxVector{
		ContainerSha256: hex.EncodeToString(sum[:]),
		ContainerId:     sidecar.EvsKeyId(container.Id),
		EntryKeys:       keys,
		EntryHex:        map[string]string{},
	}
	for i, key := range keys {
		got.EntryHex[key] = hex.EncodeToString(entryBytes[i])
	}
	path := filepath.Join("..", "testdata", "evs", "pidx", "pack_vector.json")
	if os.Getenv("EVS_PIDX_VECTORS_WRITE") == "1" {
		encoded, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := &pidxVector{}
	if err := json.Unmarshal(wantBytes, want); err != nil {
		t.Fatal(err)
	}
	gotJson, _ := json.Marshal(got)
	wantJson, _ := json.Marshal(want)
	if !bytes.Equal(gotJson, wantJson) {
		t.Fatalf("the vector moved:\n got %s\nwant %s", gotJson, wantJson)
	}
	for key, entryHex := range want.EntryHex {
		entryBytes, err := hex.DecodeString(entryHex)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeEvsPidxEntry(entryBytes); err != nil {
			t.Errorf("%s does not decode: %v", key, err)
		}
	}
}

// Decoding is total and bounded: any bytes decode to an entry that keeps every rule, which re-encodes to bytes that
// decode alike, or fail with ErrEvsPidxInvalid.
func FuzzEvsPidxEntry(f *testing.F) {
	container, repoId := buildPidxVectorContainer(f)
	_, entryBytes, err := container.EntryKeys(repoId)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range entryBytes {
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Add([]byte{0x08, 0x03})
	f.Fuzz(func(t *testing.T, data []byte) {
		entry, err := DecodeEvsPidxEntry(data)
		if err != nil {
			if !errors.Is(err, ErrEvsPidxInvalid) {
				t.Fatalf("an error outside the format's: %v", err)
			}
			return
		}
		encoded, err := encodeEvsPidxEntry(entry)
		if err != nil {
			t.Fatalf("a decoded entry does not encode: %v", err)
		}
		again, err := DecodeEvsPidxEntry(encoded)
		if err != nil || len(again.GetRecords()) != len(entry.GetRecords()) {
			t.Fatalf("a re-encoded entry decodes to %v %v", again, err)
		}
	})
}
