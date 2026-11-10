// The sealed store (DESIGN-DETAILS 4.2.2): records round-trip at every chunk edge and hold nothing in the clear; a
// flipped byte, a truncation at a chunk boundary or inside one, swapped chunks, bytes after the final chunk, a record
// moved to another name and another root key each fail as a store fault, never as absent; and a posture on it
// restores, and fails closed on a tampered record.

package device

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A synthetic forwarding root key.
func testSealedRootKey(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, sealedPostureRootKeyByteCount)
}

// A sealed store over a memory store, and the memory store.
func newTestSealedStore(t *testing.T, rootKey []byte) (PostureStore, *memoryPostureStore) {
	t.Helper()
	inner := newMemoryPostureStore()
	store, err := NewSealedPostureStore(inner, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return store, inner
}

// Writes content under name, in pieces of pieceByteCount.
func writeSealedRecord(t *testing.T, store PostureStore, name string, content []byte, pieceByteCount int) {
	t.Helper()
	err := store.Write(name, func(writer io.Writer) error {
		for rest := content; 0 < len(rest); {
			piece := rest[:min(pieceByteCount, len(rest))]
			if _, err := writer.Write(piece); err != nil {
				return err
			}
			rest = rest[len(piece):]
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The record read to its end, or the error that stopped it.
func readSealedRecord(store PostureStore, name string) ([]byte, error) {
	reader, err := store.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Synthetic content of byteCount bytes, a marker repeated, so the clear text is easy to look for.
func testSealedContent(byteCount int) []byte {
	return bytes.Repeat([]byte("plaintext marker "), byteCount/17+1)[:byteCount]
}

func TestSealedPostureStoreRoundTrips(t *testing.T) {
	store, inner := newTestSealedStore(t, testSealedRootKey(0x31))
	sizes := []int{0, 1, sealedPostureChunkByteCount - 1, sealedPostureChunkByteCount, sealedPostureChunkByteCount + 1,
		3*sealedPostureChunkByteCount + 5}
	for _, size := range sizes {
		for _, pieceByteCount := range []int{1000, 3 * sealedPostureChunkByteCount} {
			content := testSealedContent(size)
			writeSealedRecord(t, store, "rows-1", content, pieceByteCount)
			got, err := readSealedRecord(store, "rows-1")
			if err != nil || !bytes.Equal(got, content) {
				t.Errorf("%d bytes in pieces of %d: %v, %d bytes back", size, pieceByteCount, err, len(got))
			}
			sealed := inner.record("rows-1")
			chunkCount := max(1, (size+sealedPostureChunkByteCount-1)/sealedPostureChunkByteCount)
			if want := len(sealedPostureMagic) + sealedPostureFileIdByteCount + size + chunkCount*sealedPostureTagByteCount; len(sealed) != want {
				t.Errorf("%d bytes sealed to %d, want %d", size, len(sealed), want)
			}
			if !bytes.HasPrefix(sealed, []byte(sealedPostureMagic)) || (0 < size && bytes.Contains(sealed, []byte("marker"))) {
				t.Errorf("%d bytes: the sealed record shows its plaintext", size)
			}
		}
	}
	// the same content twice seals under two file ids, so to other bytes
	writeSealedRecord(t, store, "state-1", testSealedContent(100), 100)
	first := bytes.Clone(inner.record("state-1"))
	writeSealedRecord(t, store, "state-1", testSealedContent(100), 100)
	if bytes.Equal(first, inner.record("state-1")) {
		t.Error("two writes of one record sealed to the same bytes")
	}
}

func TestSealedRecordsRefuseEveryTamper(t *testing.T) {
	const name = "rows-7-1"
	header := len(sealedPostureMagic) + sealedPostureFileIdByteCount
	chunk := sealedPostureChunkByteCount + sealedPostureTagByteCount
	content := testSealedContent(2*sealedPostureChunkByteCount + 100)
	sealedOf := func(store PostureStore, inner *memoryPostureStore) []byte {
		writeSealedRecord(t, store, name, content, len(content))
		return bytes.Clone(inner.record(name))
	}
	store, inner := newTestSealedStore(t, testSealedRootKey(0x32))
	sealed := sealedOf(store, inner)
	if len(sealed) != header+2*chunk+100+sealedPostureTagByteCount {
		t.Fatalf("a record of %d bytes", len(sealed))
	}
	flip := func(index int) []byte {
		changed := bytes.Clone(sealed)
		changed[index] ^= 0x01
		return changed
	}
	otherStore, otherInner := newTestSealedStore(t, testSealedRootKey(0x33))
	cases := []struct {
		name   string
		sealed []byte
		// the name the bytes are opened under; name when empty
		openAs string
	}{
		{name: "a flipped byte in the magic", sealed: flip(0)},
		{name: "a flipped byte in the file id", sealed: flip(len(sealedPostureMagic) + 3)},
		{name: "a flipped byte in the first chunk", sealed: flip(header + 10)},
		{name: "a flipped byte in the last chunk's tag", sealed: flip(len(sealed) - 1)},
		{name: "cut at a chunk boundary", sealed: sealed[:header+2*chunk]},
		{name: "cut inside a chunk", sealed: sealed[:header+chunk+500]},
		{name: "cut inside the header", sealed: sealed[:header-1]},
		{name: "the header alone", sealed: sealed[:header]},
		{name: "empty", sealed: []byte{}},
		{name: "the first two chunks swapped", sealed: append(append(append(bytes.Clone(sealed[:header]),
			sealed[header+chunk:header+2*chunk]...), sealed[header:header+chunk]...), sealed[header+2*chunk:]...)},
		{name: "bytes after the final chunk", sealed: append(bytes.Clone(sealed), 0x00)},
		{name: "a final chunk repeated", sealed: append(bytes.Clone(sealed), sealed[header+2*chunk:]...)},
		{name: "moved to another name", sealed: sealed, openAs: "state-7"},
		{name: "sealed under another root key", sealed: sealedOf(otherStore, otherInner)},
	}
	for _, c := range cases {
		openAs := c.openAs
		if openAs == "" {
			openAs = name
		}
		inner.setRecord(openAs, c.sealed)
		got, err := readSealedRecord(store, openAs)
		if !errors.Is(err, ErrPostureStoreFailed) || errors.Is(err, ErrPostureStoreAbsent) {
			t.Errorf("%s: %v, %d bytes read", c.name, err, len(got))
		}
		inner.setRecord(name, sealed)
	}
	// a chunk that does not open gives none of its bytes
	inner.setRecord(name, flip(header+10))
	reader, err := store.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 10)
	if n, err := reader.Read(buffer); n != 0 || !errors.Is(err, ErrPostureStoreFailed) {
		t.Errorf("a tampered first chunk read %d bytes, %v", n, err)
	}
	reader.Close()
}

func TestSealedPostureStorePassesAbsentListAndRemove(t *testing.T) {
	store, inner := newTestSealedStore(t, testSealedRootKey(0x34))
	if _, err := store.Open("posture"); !errors.Is(err, ErrPostureStoreAbsent) {
		t.Errorf("absent: %v", err)
	}
	inner.unreadableNames["posture"] = true
	if _, err := store.Open("posture"); !errors.Is(err, ErrPostureStoreFailed) || errors.Is(err, ErrPostureStoreAbsent) {
		t.Errorf("unreadable: %v", err)
	}
	delete(inner.unreadableNames, "posture")
	writeSealedRecord(t, store, "posture", []byte("manifest"), 8)
	writeSealedRecord(t, store, "state-2", []byte("state"), 5)
	if names, err := store.List(); err != nil || len(names) != 2 || names[0] != "posture" || names[1] != "state-2" {
		t.Errorf("list %v, %v", names, err)
	}
	if err := store.Remove("state-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open("state-2"); !errors.Is(err, ErrPostureStoreAbsent) {
		t.Errorf("removed: %v", err)
	}
	// a write that fails leaves the old record
	failed := errors.New("the writer failed")
	if err := store.Write("posture", func(writer io.Writer) error {
		writer.Write([]byte("half"))
		return failed
	}); !errors.Is(err, failed) {
		t.Fatalf("a failed write: %v", err)
	}
	if got, err := readSealedRecord(store, "posture"); err != nil || string(got) != "manifest" {
		t.Errorf("after a failed write: %q, %v", got, err)
	}
}

func TestSealedPostureStoreRefusesABadRootKey(t *testing.T) {
	for _, byteCount := range []int{0, 16, 31, 33} {
		if _, err := NewSealedPostureStore(newMemoryPostureStore(), bytes.Repeat([]byte{0x35}, byteCount)); !errors.Is(err, ErrPostureStoreFailed) {
			t.Errorf("a root key of %d bytes: %v", byteCount, err)
		}
	}
	if _, err := NewSealedPostureStore(nil, testSealedRootKey(0x35)); !errors.Is(err, ErrPostureStoreFailed) {
		t.Errorf("no inner store: %v", err)
	}
	// the store keeps its own copy, so a caller zeroing its key changes nothing
	rootKey := testSealedRootKey(0x36)
	store, err := NewSealedPostureStore(newMemoryPostureStore(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	writeSealedRecord(t, store, "posture", []byte("manifest"), 8)
	clear(rootKey)
	if got, err := readSealedRecord(store, "posture"); err != nil || string(got) != "manifest" {
		t.Errorf("after the caller zeroed its key: %q, %v", got, err)
	}
}

// A posture on a sealed store over files restores what it committed; on a sealed store over memory, a tampered rows,
// state or manifest record restores pending, never legacy.
func TestPostureOnASealedStore(t *testing.T) {
	fixture := newPostureFixture(t)
	files, err := NewFilePostureStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealedFiles, err := NewSealedPostureStore(files, testSealedRootKey(0x37))
	if err != nil {
		t.Fatal(err)
	}
	posture := fixture.enforcing(sealedFiles, true)
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	if _, err := posture.ApplyDeltas(fixture.log(revoke, revoke)); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSealedPostureStore(files, testSealedRootKey(0x37))
	if err != nil {
		t.Fatal(err)
	}
	if _, restored := fixture.open(reopened); restored.State != PostureEnforcingDocument || restored.Pin.GetVersion() != revoke ||
		len(restored.Overlay) != 1 || len(restored.Alarms) != 0 {
		t.Fatalf("restored %v, %v, %v", restored.State, restored.Pin, restored.Alarms)
	}
	// under another root key nothing reads, so pending, never legacy
	otherKey, err := NewSealedPostureStore(files, testSealedRootKey(0x38))
	if err != nil {
		t.Fatal(err)
	}
	if _, restored := fixture.open(otherKey); restored.State != PosturePending || !postureAlarmed(restored, PostureAlarmStoreUnreadable) {
		t.Errorf("another root key: %v, %v", restored.State, restored.Alarms)
	}

	for _, kind := range []string{"rows", "state", "posture"} {
		fixture := newPostureFixture(t)
		inner := newMemoryPostureStore()
		store, err := NewSealedPostureStore(inner, testSealedRootKey(0x39))
		if err != nil {
			t.Fatal(err)
		}
		fixture.enforcing(store, true)
		survivor := inner.survivor()
		name := kind
		if kind != postureManifestName {
			name = survivor.recordOf(kind)
		}
		postureFlipByte(survivor, name, len(survivor.record(name))-3)
		restoredStore, err := NewSealedPostureStore(survivor, testSealedRootKey(0x39))
		if err != nil {
			t.Fatal(err)
		}
		if _, restored := fixture.open(restoredStore); restored.State != PosturePending || len(restored.Alarms) == 0 {
			t.Errorf("a tampered %s record restored %v, %v", kind, restored.State, restored.Alarms)
		}
	}
}
