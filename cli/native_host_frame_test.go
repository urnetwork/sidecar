package main

// Native messaging's frames: a round trip in this machine's byte order, a reply past a frame split into chunks that
// join to it, and a length the host refuses ending the session.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// A frame written is the same message read, its length in native order before it.
func TestNativeHostFrameRoundTrip(t *testing.T) {
	stream := &bytes.Buffer{}
	messages := [][]byte{[]byte(`{"jsonrpc":"2.0","id":1,"method":"status"}`), []byte(`{}`), bytes.Repeat([]byte("x"), 70000)}
	for _, message := range messages {
		if err := writeNativeHostFrame(stream, message); err != nil {
			t.Fatal(err)
		}
	}
	if length := binary.NativeEndian.Uint32(stream.Bytes()[:4]); int(length) != len(messages[0]) {
		t.Errorf("the first length field reads %d", length)
	}
	for _, message := range messages {
		read, err := readNativeHostFrame(stream, 1024*1024)
		if err != nil || !bytes.Equal(read, message) {
			t.Fatalf("read %d bytes, %v", len(read), err)
		}
	}
	if _, err := readNativeHostFrame(stream, 1024*1024); !errors.Is(err, io.EOF) {
		t.Errorf("past the last frame: %v", err)
	}
}

// A reply past the chunk size goes as chunks, each a frame under Chrome's limit, which name the request and join, in
// index order, to the reply; one within it goes whole.
func TestNativeHostOversizedReplySplits(t *testing.T) {
	reply := []byte(`{"jsonrpc":"2.0","id":7,"result":"` + strings.Repeat("\"quoted\\", 40000) + `"}`)
	stream := &bytes.Buffer{}
	chunkByteCount := 64 * 1024
	if err := writeNativeHostReply(stream, json.RawMessage("7"), reply, chunkByteCount); err != nil {
		t.Fatal(err)
	}
	joined := []byte{}
	count := -1
	for index := 0; ; index += 1 {
		frame, err := readNativeHostFrame(stream, nativeHostMaxFrameByteCount)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if nativeHostMaxFrameByteCount < len(frame) {
			t.Errorf("chunk %d is %d bytes", index, len(frame))
		}
		chunk := &nativeHostChunk{}
		if err := json.Unmarshal(frame, chunk); err != nil {
			t.Fatal(err)
		}
		if chunk.Chunk.Index != index || string(chunk.Chunk.Id) != "7" {
			t.Errorf("chunk %d reads %+v", index, chunk.Chunk)
		}
		count = chunk.Chunk.Count
		data, err := base64.StdEncoding.DecodeString(chunk.DataBase64)
		if err != nil || chunkByteCount < len(data) {
			t.Fatalf("chunk %d's data: %d bytes, %v", index, len(data), err)
		}
		joined = append(joined, data...)
	}
	if !bytes.Equal(joined, reply) || count != (len(reply)+chunkByteCount-1)/chunkByteCount || count < 2 {
		t.Errorf("%d chunks joined to %d bytes of %d", count, len(joined), len(reply))
	}

	whole := &bytes.Buffer{}
	if err := writeNativeHostReply(whole, json.RawMessage("8"), []byte(`{"jsonrpc":"2.0","id":8,"result":null}`), chunkByteCount); err != nil {
		t.Fatal(err)
	}
	if frame, err := readNativeHostFrame(whole, nativeHostMaxFrameByteCount); err != nil || !bytes.HasPrefix(frame, []byte(`{"jsonrpc"`)) {
		t.Errorf("a short reply went as %q, %v", frame, err)
	}

	// the default chunk size's chunk, base64 and envelope with the longest id, fits a frame
	longest := json.RawMessage(`"` + strings.Repeat("i", nativeHostMaxIdByteCount-2) + `"`)
	if err := writeNativeHostReply(io.Discard, longest, bytes.Repeat([]byte{0xff}, 3*defaultUrSettings().NativeHostChunkByteCount),
		defaultUrSettings().NativeHostChunkByteCount); err != nil {
		t.Errorf("the default chunk size does not fit a frame: %v", err)
	}
}

// A zero length, a length past the bound and a stream that ends inside a frame are each refused, reading nothing
// past the header that could be mistaken for a message.
func TestNativeHostGarbageLengthRefused(t *testing.T) {
	header := func(length uint32) []byte {
		encoded := make([]byte, 4)
		binary.NativeEndian.PutUint32(encoded, length)
		return encoded
	}
	cases := map[string][]byte{
		"zero":           header(0),
		"past the bound": append(header(4096+1), bytes.Repeat([]byte("{"), 4097)...),
		"the top bit":    header(0x80000000),
		"cut short":      append(header(10), []byte(`{"a"`)...),
		"cut header":     []byte{1, 0},
	}
	for name, stream := range cases {
		message, err := readNativeHostFrame(bytes.NewReader(stream), 4096)
		if err == nil || message != nil {
			t.Errorf("%s: read %q", name, message)
		}
		if name == "cut short" && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("a frame cut short reads %v", err)
		}
	}
	if err := writeNativeHostFrame(io.Discard, bytes.Repeat([]byte("x"), nativeHostMaxFrameByteCount+1)); err == nil {
		t.Error("a frame past Chrome's limit was written")
	}
	if err := writeNativeHostFrame(io.Discard, nil); err == nil {
		t.Error("an empty frame was written")
	}
}
