//go:build !sidecar_http && !js && !ios_extension

// MAIL-M7-14's spool: a 50 MiB message in 64 KiB segments within one chunk of memory, its hash as received, reads
// at any offset and a replay from the start equal to what was written; chunks that open only under their own
// message's key at their own index; no store file holding a byte of plaintext; and the sweep that drops what a crash
// left.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand/v2"
	"strings"
	"testing"
)

// size bytes of a fixed pseudo-random stream, so a failure repeats.
func testMailSpoolBytes(size int, seed uint64) []byte {
	random := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	data := make([]byte, size)
	for index := range data {
		data[index] = byte(random.Uint32())
	}
	return data
}

// The working set: a 50 MiB message written as a sender's 64 KiB segments, then replayed from the start and read at
// scattered offsets, never holds more than one chunk being filled and one being read, and reads back as written.
func TestMailSpoolHoldsAFiftyMebibyteMessageInOneChunk(t *testing.T) {
	const chunkByteCount = 64 * 1024
	const messageByteCount = 50 * 1024 * 1024
	store := newTestMemoryStore()
	spool, err := newMailSpool(store, chunkByteCount)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.close()
	base := testMailSpoolBytes(chunkByteCount, 7)
	segment := bytes.Clone(base)
	hash := sha256.New()
	for written := 0; written < messageByteCount; written += len(segment) {
		// each segment differs from the one before, so a chunk read at another index cannot pass
		segment[0] = byte(written / len(segment))
		hash.Write(segment)
		if _, err := spool.Write(segment); err != nil {
			t.Fatal(err)
		}
		if peak := spool.peakHeld(); chunkByteCount < peak {
			t.Fatalf("writing held %d bytes", peak)
		}
	}
	if err := spool.finish(); err != nil {
		t.Fatal(err)
	}
	want := [sha256.Size]byte(hash.Sum(nil))
	if spool.Sha256() != want || spool.Size() != messageByteCount {
		t.Fatal("the spool's hash or size is not the message's as received")
	}
	replay := sha256.New()
	if _, err := io.Copy(replay, spool.Reader()); err != nil {
		t.Fatal(err)
	}
	if [sha256.Size]byte(replay.Sum(nil)) != want {
		t.Fatal("the replay differs from the message")
	}
	// what the message holds at offset: each segment's first byte its number, the rest base's
	expectedAt := func(offset int64) byte {
		if offset%chunkByteCount == 0 {
			return byte(offset / chunkByteCount)
		}
		return base[offset%chunkByteCount]
	}
	random := rand.New(rand.NewPCG(11, 13))
	for range 64 {
		offset := random.Int64N(messageByteCount - 2*chunkByteCount)
		read := make([]byte, 1+random.IntN(2*chunkByteCount))
		if _, err := spool.ReadAt(read, offset); err != nil {
			t.Fatal(err)
		}
		for index, got := range read {
			if got != expectedAt(offset+int64(index)) {
				t.Fatalf("a read at %d differs at %d", offset, index)
			}
		}
	}
	if peak := spool.peakHeld(); 2*chunkByteCount < peak {
		t.Fatalf("the spool held %d bytes at once, past two chunks", peak)
	}
}

// A chunk opens only under its own message's key at its own index: two chunks swapped in the store, or a chunk of
// another message put in, fail the read, and no store file holds the plaintext.
func TestMailSpoolChunksOpenOnlyUnderTheirKeyAtTheirIndex(t *testing.T) {
	store := newTestMemoryStore()
	// ten chunks and a part, so the last chunk holds bytes a read opens
	message := []byte(strings.Repeat("a synthetic message line for the spool\r\n", 64) + "end")
	write := func() *mailSpool {
		spool, err := newMailSpool(store, 256)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := spool.Write(message); err != nil {
			t.Fatal(err)
		}
		if err := spool.finish(); err != nil {
			t.Fatal(err)
		}
		return spool
	}
	spool, other := write(), write()
	defer spool.close()
	defer other.close()
	files := func() map[string][]byte {
		store.shared.stateLock.Lock()
		defer store.shared.stateLock.Unlock()
		copied := map[string][]byte{}
		for name, content := range store.shared.files {
			copied[name] = bytes.Clone(content)
		}
		return copied
	}()
	for name, content := range files {
		if bytes.Contains(content, []byte("a synthetic message line")) {
			t.Fatalf("%s holds plaintext", name)
		}
	}
	read := func() error {
		_, err := io.ReadAll(spool.Reader())
		return err
	}
	if err := read(); err != nil {
		t.Fatal(err)
	}
	first, second := spool.chunkName(0), spool.chunkName(1)
	swap := func(a string, b string) {
		store.shared.stateLock.Lock()
		defer store.shared.stateLock.Unlock()
		store.shared.files[a], store.shared.files[b] = store.shared.files[b], store.shared.files[a]
	}
	swap(first, second)
	if err := read(); !errors.Is(err, errMailSpoolChunk) {
		t.Errorf("swapped chunks: %v", err)
	}
	swap(first, second)
	swap(first, other.chunkName(0))
	if err := read(); !errors.Is(err, errMailSpoolChunk) {
		t.Errorf("another message's chunk: %v", err)
	}
	swap(first, other.chunkName(0))
	// the size is the spool's own, so a tail the store lost fails rather than reading short, and an earlier chunk put
	// in the last one's place does not open there
	last := spool.chunkName(spool.chunkCount - 1)
	store.shared.stateLock.Lock()
	lastContent := store.shared.files[last]
	store.shared.files[last] = store.shared.files[spool.chunkName(spool.chunkCount-2)]
	store.shared.stateLock.Unlock()
	if err := read(); !errors.Is(err, errMailSpoolChunk) {
		t.Errorf("an earlier chunk at the end: %v", err)
	}
	store.shared.stateLock.Lock()
	store.shared.files[last] = lastContent
	store.shared.stateLock.Unlock()
	store.Remove(last)
	if err := read(); err == nil {
		t.Error("a lost tail read short and whole")
	}
}

// close removes every chunk; a spool a crash left behind, never closed, is removed by the next start's sweep.
func TestMailSpoolSweepRemovesWhatACrashLeft(t *testing.T) {
	store := newTestMemoryStore()
	writeStoreFile(t, store, mailReceiverTlsaFileName, []byte("{}"))
	spool, err := newMailSpool(store, 128)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Write(testMailSpoolBytes(1000, 3)); err != nil {
		t.Fatal(err)
	}
	if err := spool.finish(); err != nil {
		t.Fatal(err)
	}
	spool.close()
	if entries, _ := store.List(mailSpoolDirectory); len(entries) != 0 {
		t.Fatalf("close left %d chunks", len(entries))
	}
	crashed, err := newMailSpool(store, 128)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crashed.Write(testMailSpoolBytes(1000, 5)); err != nil {
		t.Fatal(err)
	}
	if entries, _ := store.List(mailSpoolDirectory); len(entries) == 0 {
		t.Fatal("no chunk reached the store")
	}
	if err := sweepMailSpools(store); err != nil {
		t.Fatal(err)
	}
	if entries, _ := store.List(mailSpoolDirectory); len(entries) != 0 {
		t.Fatalf("the sweep left %d chunks", len(entries))
	}
	if entries, _ := store.List(""); len(entries) != 1 || entries[0].Name != mailReceiverTlsaFileName {
		t.Fatalf("the sweep took files beside the spool's: %v", entries)
	}
}

// The spool refuses use out of order: a read before finish, a write after it, and anything after close.
func TestMailSpoolRefusesUseOutOfOrder(t *testing.T) {
	spool, err := newMailSpool(newTestMemoryStore(), 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.ReadAt(make([]byte, 1), 0); !errors.Is(err, errMailSpoolState) {
		t.Errorf("a read before finish: %v", err)
	}
	if _, err := spool.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := spool.finish(); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Write([]byte("d")); !errors.Is(err, errMailSpoolState) {
		t.Errorf("a write after finish: %v", err)
	}
	spool.close()
	if _, err := spool.ReadAt(make([]byte, 1), 0); !errors.Is(err, errMailSpoolState) {
		t.Errorf("a read after close: %v", err)
	}
}
