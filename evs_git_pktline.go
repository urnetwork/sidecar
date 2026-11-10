//go:build !ios_extension

// Git's pkt-line framing (gitprotocol-common), on every leg: the proc-receive hook's conversation with
// receive-pack is pkt-lines, and §5.8's git hello hands a daemon raw ones (§11.11). This is framing
// only: what a payload says, an `ERR` line's meaning included, is for its protocol. mlsinterop's
// git_oracle_test.go holds this equal to go-git.
//
// A line's first four bytes are its length in hex, those four included, and the lengths 0000, 0001
// and 0002 are the special packets stock git's pkt-line.c reads. go-git's v5 scanner knows only the
// first, refuses 0001, 0002 and 0004, and reads four bytes past the format's limit. This follows git
// on the first three and the format on the last.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	// A line's length field: four hex digits.
	evsPktLineHeaderSize = 4
	// The longest line the format allows, its length field included (LARGE_PACKET_MAX).
	evsPktLineMaxSize = 65520
	// The longest payload the format allows.
	EvsPktLineMaxPayloadSize = evsPktLineMaxSize - evsPktLineHeaderSize
)

// A stream or a line that does not hold the format's framing.
var ErrEvsPktLineInvalid = errors.New("pkt-line invalid")

// What a line is: payload bytes, or one of the special packets, which carry none.
type EvsPktLineKind int

const (
	// A payload, length 0004 on up. The format discourages an empty one, so it is read and never
	// written.
	EvsPktLineData EvsPktLineKind = iota
	// 0000: the end of a message.
	EvsPktLineFlush
	// 0001: the end of a section of a message (gitprotocol-v2).
	EvsPktLineDelim
	// 0002: the end of a stateless response (gitprotocol-v2).
	EvsPktLineResponseEnd
)

// One line.
type EvsPktLine struct {
	Kind EvsPktLineKind
	// A data line's bytes. From a reader, borrowed until its next call.
	Payload []byte
}

// The line's bytes on the wire. A payload past the format's limit is refused and never split, since
// a split would change where the receiver's lines fall, and so is an empty one.
func (self EvsPktLine) Encode() ([]byte, error) {
	var specialLength string
	switch self.Kind {
	case EvsPktLineData:
		if len(self.Payload) == 0 || EvsPktLineMaxPayloadSize < len(self.Payload) {
			return nil, fmt.Errorf("%w: a payload is empty or past the format's limit", ErrEvsPktLineInvalid)
		}
		lineSize := len(self.Payload) + evsPktLineHeaderSize
		encoded := make([]byte, 0, lineSize)
		encoded = hex.AppendEncode(encoded, []byte{byte(lineSize / 256), byte(lineSize % 256)})
		return append(encoded, self.Payload...), nil
	case EvsPktLineFlush:
		specialLength = "0000"
	case EvsPktLineDelim:
		specialLength = "0001"
	case EvsPktLineResponseEnd:
		specialLength = "0002"
	default:
		return nil, fmt.Errorf("%w: a line of no known kind", ErrEvsPktLineInvalid)
	}
	if len(self.Payload) != 0 {
		return nil, fmt.Errorf("%w: a special packet with a payload", ErrEvsPktLineInvalid)
	}
	return []byte(specialLength), nil
}

// The payload without the one trailing LF a line of text may carry, as git's reader chomps it. The
// format leaves that LF to the sender, so a text protocol's lines read the same either way.
func (self EvsPktLine) Text() []byte {
	return bytes.TrimSuffix(self.Payload, []byte{'\n'})
}

// Reads lines one at a time from a stream, holding one line at most. Not safe for concurrent use.
type EvsPktLineReader struct {
	reader io.Reader
	// The current line's payload, reused. A line grows it, up to the format's limit.
	payloadBuffer []byte
}

// Reads from reader, and reads no more than the lines it is asked for, so a caller can hand the
// stream on after a flush.
func NewEvsPktLineReader(reader io.Reader) *EvsPktLineReader {
	return &EvsPktLineReader{reader: reader}
}

// The next line. io.EOF means the stream ended between lines. A stream that ends inside one, or a
// length that is not hex, 0003 or past the format's limit, is ErrEvsPktLineInvalid. A reader's own
// error comes back as it is.
func (self *EvsPktLineReader) Next() (EvsPktLine, error) {
	cut := func(err error) error {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return fmt.Errorf("%w: the stream ends inside a line", ErrEvsPktLineInvalid)
		}
		return err
	}
	header := [evsPktLineHeaderSize]byte{}
	if _, err := io.ReadFull(self.reader, header[:]); err != nil {
		if err == io.EOF {
			return EvsPktLine{}, io.EOF
		}
		return EvsPktLine{}, cut(err)
	}
	lengthBytes := [evsPktLineHeaderSize / 2]byte{}
	if _, err := hex.Decode(lengthBytes[:], header[:]); err != nil {
		return EvsPktLine{}, fmt.Errorf("%w: a length is not hex", ErrEvsPktLineInvalid)
	}
	lineSize := int(lengthBytes[0])*256 + int(lengthBytes[1])
	switch {
	case lineSize == 0:
		return EvsPktLine{Kind: EvsPktLineFlush}, nil
	case lineSize == 1:
		return EvsPktLine{Kind: EvsPktLineDelim}, nil
	case lineSize == 2:
		return EvsPktLine{Kind: EvsPktLineResponseEnd}, nil
	case lineSize < evsPktLineHeaderSize || evsPktLineMaxSize < lineSize:
		return EvsPktLine{}, fmt.Errorf("%w: a length is 0003 or past the format's limit", ErrEvsPktLineInvalid)
	}
	payloadSize := lineSize - evsPktLineHeaderSize
	if cap(self.payloadBuffer) < payloadSize {
		self.payloadBuffer = make([]byte, payloadSize)
	}
	payload := self.payloadBuffer[:payloadSize]
	if _, err := io.ReadFull(self.reader, payload); err != nil {
		return EvsPktLine{}, cut(err)
	}
	return EvsPktLine{Kind: EvsPktLineData, Payload: payload}, nil
}
