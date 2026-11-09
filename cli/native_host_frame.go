// Native messaging's frames (§18.8's connectNative path): every message, either way, is a 32-bit length in this
// machine's byte order and then that many bytes of UTF-8 JSON, as Chrome and Firefox speak to a native host over its
// stdin and stdout (https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging, MDN's Native
// messaging). The stream has no other framing, so a length past the host's bound, or a stream that ends inside a
// frame, ends the session: what follows cannot be found.
//
// Chrome refuses a message from a host past 1 MiB, so a reply past one chunk goes as chunks, consecutive frames of
// {"ur_chunk":{"id":<the request's id>,"index":i,"count":n},"data_base64":"..."} whose decoded data, joined in index
// order, is the reply's JSON. Base64 keeps a chunk's size exact whatever the reply holds, where JSON's escaping could
// grow it sixfold.

package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// The format's values.
const (
	// A frame's length field.
	nativeHostFrameHeaderByteCount = 4
	// Chrome's limit on one message from a native host: 1 MiB. No frame this host writes passes it.
	nativeHostMaxFrameByteCount = 1024 * 1024
)

// A frame whose length is zero or past the host's bound: the session ends, since the stream cannot be resynced.
var errNativeHostFrameLength = errors.New("native messaging frame length refused")

// One frame's message, at most maxByteCount bytes. io.EOF for a stream that ends between frames; a stream that ends
// inside one is io.ErrUnexpectedEOF.
func readNativeHostFrame(reader io.Reader, maxByteCount int) ([]byte, error) {
	header := make([]byte, nativeHostFrameHeaderByteCount)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := binary.NativeEndian.Uint32(header)
	if length == 0 || uint64(maxByteCount) < uint64(length) {
		return nil, fmt.Errorf("%w: %d bytes", errNativeHostFrameLength, length)
	}
	message := make([]byte, length)
	if _, err := io.ReadFull(reader, message); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return message, nil
}

// Writes message as one frame. A message past Chrome's limit, or an empty one, is refused unwritten.
func writeNativeHostFrame(writer io.Writer, message []byte) error {
	if len(message) == 0 || nativeHostMaxFrameByteCount < len(message) {
		return fmt.Errorf("%w: %d bytes", errNativeHostFrameLength, len(message))
	}
	frame := make([]byte, nativeHostFrameHeaderByteCount+len(message))
	binary.NativeEndian.PutUint32(frame, uint32(len(message)))
	copy(frame[nativeHostFrameHeaderByteCount:], message)
	_, err := writer.Write(frame)
	return err
}

// One chunk of a reply too long for a frame.
type nativeHostChunk struct {
	Chunk struct {
		Id    json.RawMessage `json:"id"`
		Index int             `json:"index"`
		Count int             `json:"count"`
	} `json:"ur_chunk"`
	DataBase64 string `json:"data_base64"`
}

// Writes reply, the answer to the request id names, as one frame, or as chunks of at most chunkByteCount bytes of
// reply each when it is longer than that.
func writeNativeHostReply(writer io.Writer, id json.RawMessage, reply []byte, chunkByteCount int) error {
	if len(reply) <= chunkByteCount {
		return writeNativeHostFrame(writer, reply)
	}
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	count := (len(reply) + chunkByteCount - 1) / chunkByteCount
	for index := 0; index < count; index += 1 {
		end := min((index+1)*chunkByteCount, len(reply))
		chunk := &nativeHostChunk{DataBase64: base64.StdEncoding.EncodeToString(reply[index*chunkByteCount : end])}
		chunk.Chunk.Id = id
		chunk.Chunk.Index = index
		chunk.Chunk.Count = count
		encoded, err := json.Marshal(chunk)
		if err != nil {
			return err
		}
		if err := writeNativeHostFrame(writer, encoded); err != nil {
			return err
		}
	}
	return nil
}
