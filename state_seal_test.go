// The sealed file format on its own, under a key from nowhere: what a reader does with every way a
// file can be damaged.

package sidecar

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"golang.org/x/crypto/chacha20poly1305"
)

// The key of these tests. Sealing does not care where a key came from.
var sealTestKey = bytes.Repeat([]byte{0x42}, chacha20poly1305.KeySize)

// What a seal asks for its key through, with key always there.
func sealTestAead(key []byte) func() (cipher.AEAD, error) {
	return func() (cipher.AEAD, error) {
		return chacha20poly1305.NewX(key)
	}
}

// One fixed header, so a test repeats.
func sealTestHeader() *sealHeader {
	header := &sealHeader{generation: 7, class: "evs"}
	copy(header.noncePrefix[:], bytes.Repeat([]byte{0x24}, sealNoncePrefixByteCount))
	return header
}

// plaintext sealed as a whole file.
func sealTestFile(t *testing.T, header *sealHeader, key []byte, path string, plaintext []byte) []byte {
	t.Helper()
	sealed := &bytes.Buffer{}
	writer, err := newSealWriter(sealed, header, path, sealTestAead(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.finish(); err != nil {
		t.Fatal(err)
	}
	return sealed.Bytes()
}

// What a reader makes of sealed at path under key: the plaintext, or the error it stops with.
func openTestFile(sealed []byte, key []byte, path string) ([]byte, error) {
	in := bytes.NewReader(sealed)
	header, err := readSealHeader(in)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(newSealReader(in, header, path, sealTestAead(key)))
}

// Bytes no chunk boundary repeats exactly.
func sealTestPlaintext(byteCount int) []byte {
	plaintext := make([]byte, byteCount)
	for i := range plaintext {
		plaintext[i] = byte(i*131 + i>>8)
	}
	return plaintext
}

// Where each chunk of a sealed file sits, past its header.
func sealChunks(t *testing.T, header *sealHeader, sealed []byte) [][]byte {
	t.Helper()
	body := sealed[len(header.encode()):]
	chunks := [][]byte{}
	for sealChunkByteCount+sealTagByteCount < len(body) {
		chunks = append(chunks, body[:sealChunkByteCount+sealTagByteCount])
		body = body[sealChunkByteCount+sealTagByteCount:]
	}
	return append(chunks, body)
}

// Fails unless err is want.
func requireError(t *testing.T, err error, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("err %v, want %v", err, want)
	}
}

// A damaged file must read as failed, and never as absent.
func requireSealFailed(t *testing.T, name string, plaintext []byte, err error) {
	t.Helper()
	if !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("%s: err %v, read %d bytes", name, err, len(plaintext))
	}
	if errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("%s: a damaged file read as absent", name)
	}
}

// Each size around a chunk's edge, the empty file and a full last chunk above all.
func TestSealRoundTrip(t *testing.T) {
	for _, byteCount := range []int{
		0,
		1,
		sealChunkByteCount - 1,
		sealChunkByteCount,
		sealChunkByteCount + 1,
		2 * sealChunkByteCount,
		3*sealChunkByteCount + 17,
	} {
		plaintext := sealTestPlaintext(byteCount)
		sealed := sealTestFile(t, sealTestHeader(), sealTestKey, "evs/a", plaintext)
		opened, err := openTestFile(sealed, sealTestKey, "evs/a")
		if err != nil {
			t.Errorf("%d: %v", byteCount, err)
			continue
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("%d: the plaintext changed", byteCount)
		}
	}
}

// A file holds a final chunk even when empty, so a header alone is a cut file.
func TestEmptyFileStillHasAFinalChunk(t *testing.T) {
	header := sealTestHeader()
	sealed := sealTestFile(t, header, sealTestKey, "evs/a", nil)
	if want := len(header.encode()) + sealTagByteCount; len(sealed) != want {
		t.Fatalf("%d bytes, want %d", len(sealed), want)
	}
	plaintext, err := openTestFile(sealed[:len(header.encode())], sealTestKey, "evs/a")
	requireSealFailed(t, "header alone", plaintext, err)
}

// A writer that takes its bytes in any pieces seals the same file.
func TestSealWritesInPiecesAsOne(t *testing.T) {
	plaintext := sealTestPlaintext(2*sealChunkByteCount + 100)
	whole := sealTestFile(t, sealTestHeader(), sealTestKey, "evs/a", plaintext)

	pieces := &bytes.Buffer{}
	writer, err := newSealWriter(pieces, sealTestHeader(), "evs/a", sealTestAead(sealTestKey))
	if err != nil {
		t.Fatal(err)
	}
	for start := 0; start < len(plaintext); start += 1021 {
		if _, err := writer.Write(plaintext[start:min(start+1021, len(plaintext))]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.finish(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pieces.Bytes(), whole) {
		t.Error("the same plaintext sealed differently")
	}
}

// A reader handing out one byte at a time, or short reads from the medium, reads the same.
func TestSealReadsInPiecesAsOne(t *testing.T) {
	plaintext := sealTestPlaintext(sealChunkByteCount + 5)
	sealed := sealTestFile(t, sealTestHeader(), sealTestKey, "evs/a", plaintext)
	in := iotest.OneByteReader(bytes.NewReader(sealed))
	header, err := readSealHeader(in)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := io.ReadAll(iotest.HalfReader(newSealReader(in, header, "evs/a", sealTestAead(sealTestKey))))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Error("the plaintext changed")
	}
}

// Every byte of a small file matters, the header's above all, since a header byte that nothing checked
// could say a file is something else.
func TestEveryByteIsAuthenticated(t *testing.T) {
	plaintext := []byte("synthetic file")
	sealed := sealTestFile(t, sealTestHeader(), sealTestKey, "evs/a", plaintext)
	for i := range sealed {
		tampered := bytes.Clone(sealed)
		tampered[i] ^= 0x01
		opened, err := openTestFile(tampered, sealTestKey, "evs/a")
		if !errors.Is(err, ErrSidecarStoreFailed) {
			t.Fatalf("byte %d: err %v, read %d bytes", i, err, len(opened))
		}
	}
}

func TestTamperedChunkStopsTheRead(t *testing.T) {
	header := sealTestHeader()
	plaintext := sealTestPlaintext(2*sealChunkByteCount + 10)
	sealed := sealTestFile(t, header, sealTestKey, "evs/a", plaintext)
	tampered := bytes.Clone(sealed)
	tampered[len(header.encode())+sealChunkByteCount+sealTagByteCount+5] ^= 0x80

	opened, err := openTestFile(tampered, sealTestKey, "evs/a")
	requireSealFailed(t, "second chunk", opened, err)
	// the first chunk authenticated, and nothing of the tampered one came out
	if !bytes.Equal(opened, plaintext[:sealChunkByteCount]) {
		t.Errorf("read %d bytes before the failure", len(opened))
	}
}

// Cut at every chunk boundary, and inside a chunk: never a clean end of file.
func TestTruncationFails(t *testing.T) {
	header := sealTestHeader()
	plaintext := sealTestPlaintext(3*sealChunkByteCount + 10)
	sealed := sealTestFile(t, header, sealTestKey, "evs/a", plaintext)
	headerByteCount := len(header.encode())
	for _, byteCount := range []int{
		0,
		1,
		headerByteCount - 1,
		headerByteCount,
		headerByteCount + 1,
		headerByteCount + sealTagByteCount - 1,
		headerByteCount + sealChunkByteCount + sealTagByteCount,
		headerByteCount + 2*(sealChunkByteCount+sealTagByteCount),
		headerByteCount + 3*(sealChunkByteCount+sealTagByteCount),
		len(sealed) - 1,
	} {
		opened, err := openTestFile(sealed[:byteCount], sealTestKey, "evs/a")
		requireSealFailed(t, "cut", opened, err)
	}
}

// A file cut exactly at a chunk's end, and that ends on a full chunk of its own, are told apart only by
// the final flag.
func TestAFullLastChunkIsNotACutFile(t *testing.T) {
	header := sealTestHeader()
	plaintext := sealTestPlaintext(2 * sealChunkByteCount)
	sealed := sealTestFile(t, header, sealTestKey, "evs/a", plaintext)
	chunks := sealChunks(t, header, sealed)
	if len(chunks) != 2 {
		t.Fatalf("%d chunks", len(chunks))
	}
	opened, err := openTestFile(sealed[:len(sealed)-len(chunks[1])], sealTestKey, "evs/a")
	requireSealFailed(t, "first chunk alone", opened, err)
}

func TestReorderedChunksFail(t *testing.T) {
	header := sealTestHeader()
	plaintext := sealTestPlaintext(2*sealChunkByteCount + 10)
	sealed := sealTestFile(t, header, sealTestKey, "evs/a", plaintext)
	chunks := sealChunks(t, header, sealed)
	reordered := bytes.Join([][]byte{header.encode(), chunks[1], chunks[0], chunks[2]}, nil)
	opened, err := openTestFile(reordered, sealTestKey, "evs/a")
	requireSealFailed(t, "swapped", opened, err)
	if 0 < len(opened) {
		t.Errorf("read %d bytes of a swapped chunk", len(opened))
	}
}

// A chunk replayed in a later place, or the whole file again behind itself.
func TestRepeatedChunksFail(t *testing.T) {
	header := sealTestHeader()
	sealed := sealTestFile(t, header, sealTestKey, "evs/a", sealTestPlaintext(sealChunkByteCount+10))
	chunks := sealChunks(t, header, sealed)
	opened, err := openTestFile(bytes.Join([][]byte{header.encode(), chunks[0], chunks[0], chunks[1]}, nil), sealTestKey, "evs/a")
	requireSealFailed(t, "repeated", opened, err)
	opened, err = openTestFile(append(bytes.Clone(sealed), chunks[1]...), sealTestKey, "evs/a")
	requireSealFailed(t, "extended", opened, err)
}

func TestAppendedBytesFail(t *testing.T) {
	sealed := sealTestFile(t, sealTestHeader(), sealTestKey, "evs/a", []byte("synthetic"))
	opened, err := openTestFile(append(bytes.Clone(sealed), 0), sealTestKey, "evs/a")
	requireSealFailed(t, "one more byte", opened, err)
}

func TestMovedFileFails(t *testing.T) {
	sealed := sealTestFile(t, sealTestHeader(), sealTestKey, "evs/a", []byte("synthetic"))
	opened, err := openTestFile(sealed, sealTestKey, "evs/b")
	requireSealFailed(t, "moved", opened, err)
}

func TestWrongKeyFails(t *testing.T) {
	sealed := sealTestFile(t, sealTestHeader(), sealTestKey, "evs/a", []byte("synthetic"))
	opened, err := openTestFile(sealed, bytes.Repeat([]byte{0x43}, chacha20poly1305.KeySize), "evs/a")
	requireSealFailed(t, "wrong key", opened, err)
}

// Two files under one key never share a nonce: each draws its own prefix, so the same plaintext at the
// same path seals differently.
func TestTwoSealsOfOneFileDiffer(t *testing.T) {
	first := sealTestHeader()
	second := sealTestHeader()
	second.noncePrefix[0] ^= 0xff
	sealedFirst := sealTestFile(t, first, sealTestKey, "evs/a", []byte("synthetic"))
	sealedSecond := sealTestFile(t, second, sealTestKey, "evs/a", []byte("synthetic"))
	firstChunk := sealedFirst[len(first.encode()):]
	secondChunk := sealedSecond[len(second.encode()):]
	if bytes.Equal(firstChunk, secondChunk) {
		t.Error("the same chunk twice")
	}
}

func TestSealHeaderRoundTrip(t *testing.T) {
	header := sealTestHeader()
	read, err := readSealHeader(bytes.NewReader(header.encode()))
	if err != nil {
		t.Fatal(err)
	}
	if read.generation != header.generation || read.class != header.class || read.noncePrefix != header.noncePrefix {
		t.Errorf("header %+v", read)
	}
}

func TestSealHeaderRefusesWhatIsNotOne(t *testing.T) {
	good := sealTestHeader().encode()
	mutate := func(i int, value byte) []byte {
		bad := bytes.Clone(good)
		bad[i] = value
		return bad
	}
	for _, c := range []struct {
		name    string
		encoded []byte
	}{
		{name: "empty", encoded: nil},
		{name: "magic", encoded: mutate(0, 'X')},
		{name: "version", encoded: mutate(4, 2)},
		{name: "no class", encoded: mutate(13, 0)},
		{name: "class too long", encoded: mutate(13, sealClassMaxByteCount+1)},
		{name: "class not a word", encoded: mutate(14, 'E')},
		{name: "short nonce", encoded: good[:len(good)-1]},
	} {
		if _, err := readSealHeader(bytes.NewReader(c.encoded)); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s: err %v", c.name, err)
		}
	}
}

// The reader asks for its key at each chunk, so a keychain that locks stops a read mid-file, with the
// lock's answer, not a failure.
func TestALockStopsAReadAtItsNextChunk(t *testing.T) {
	plaintext := sealTestPlaintext(2*sealChunkByteCount + 1)
	sealed := sealTestFile(t, sealTestHeader(), sealTestKey, "evs/a", plaintext)
	in := bytes.NewReader(sealed)
	header, err := readSealHeader(in)
	if err != nil {
		t.Fatal(err)
	}
	chunksAllowed := 1
	reader := newSealReader(in, header, "evs/a", func() (cipher.AEAD, error) {
		if chunksAllowed == 0 {
			return nil, ErrSidecarStoreLocked
		}
		chunksAllowed -= 1
		return chacha20poly1305.NewX(sealTestKey)
	})
	opened, err := io.ReadAll(reader)
	requireError(t, err, ErrSidecarStoreLocked)
	if len(opened) != sealChunkByteCount {
		t.Errorf("read %d bytes", len(opened))
	}
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("a later read: %v", err)
	}
}

// A medium that fails mid-file is a failure, never a short clean read.
func TestAMediumFaultFailsTheRead(t *testing.T) {
	sealed := sealTestFile(t, sealTestHeader(), sealTestKey, "evs/a", sealTestPlaintext(sealChunkByteCount+10))
	in := io.MultiReader(bytes.NewReader(sealed[:len(sealed)/2]), iotest.ErrReader(errors.New("synthetic fault")))
	header, err := readSealHeader(in)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := io.ReadAll(newSealReader(in, header, "evs/a", sealTestAead(sealTestKey)))
	requireSealFailed(t, "fault", opened, err)
}

func TestSealWriterTakesNothingAfterFinish(t *testing.T) {
	writer, err := newSealWriter(&bytes.Buffer{}, sealTestHeader(), "evs/a", sealTestAead(sealTestKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.finish(); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("late")); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("err %v", err)
	}
	if err := writer.finish(); err != nil {
		t.Errorf("a second finish: %v", err)
	}
}

// A writer whose key went away stops at the chunk it needed it for.
func TestAWriterKeepsItsFirstError(t *testing.T) {
	writer, err := newSealWriter(&bytes.Buffer{}, sealTestHeader(), "evs/a", func() (cipher.AEAD, error) {
		return nil, ErrSidecarStoreLocked
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(make([]byte, sealChunkByteCount+1)); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("err %v", err)
	}
	if err := writer.finish(); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("finish: %v", err)
	}
}

func TestIsSealClass(t *testing.T) {
	for _, class := range []string{"evs", "smtp-dkim", "a", "search", "x0"} {
		if !isSealClass(class) {
			t.Errorf("%q refused", class)
		}
	}
	for _, class := range []string{"", "-evs", "Evs", "e/v", "e v", "é", string(make([]byte, sealClassMaxByteCount+1))} {
		if isSealClass(class) {
			t.Errorf("%q taken", class)
		}
	}
}
