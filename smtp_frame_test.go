//go:build !sidecar_http

package sidecar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The first octets of a TLS ClientHello record, which follow the frames on the stream.
var testSmtpTlsStart = []byte{0x16, 0x03, 0x01, 0x02, 0x00}

// The frame's body bound, plan-SMTP-wire-gaps#3's, which DefaultSmtpFrameSettings gives.
const testSmtpFrameMaxBodyByteCount = 64 * 1024

func testSmtpPreamble() *protocol.SmtpPreamble {
	return &protocol.SmtpPreamble{
		Version:          1,
		RecipientDomain:  "mail.example",
		RecipientCount:   2,
		MessageId:        "qvsc2zbwd5c3m5rbnvzxjzpnay@n1.root.example",
		HeaderFromDomain: "n1.root.example",
		DkimSelector:     "abcdefghijklmnopqrstuvwxyz",
		MessageByteCount: 4096,
		Flags:            SmtpFlagBulk,
	}
}

func testSmtpPreambleResult() *protocol.SmtpPreambleResult {
	return &protocol.SmtpPreambleResult{
		Code:         uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK),
		SendId:       bytes.Repeat([]byte{7}, 12),
		XUrRef:       "1." + strings.Repeat("a", 34),
		FeedbackId:   "n:c:" + strings.Repeat("b", 26) + ":urnetwork",
		HeloName:     "o1.out.root.example",
		MxHost:       "mx1.mail.example",
		DnssecChain:  []byte{1, 2, 3},
		EhloKeywords: []string{"PIPELINING", "CHUNKING", "STARTTLS"},
	}
}

// A frame's header, for a body of any claimed length.
func testSmtpFrameHeader(bodyByteCount uint32, messageType protocol.MessageType) []byte {
	header := make([]byte, SmtpFrameHeaderByteCount)
	binary.BigEndian.PutUint32(header[0:4], bodyByteCount)
	binary.BigEndian.PutUint16(header[4:6], uint16(messageType))
	return header
}

// Counts what is read from it, and fails any read past a limit, so a test can show a reader took no
// more than a frame.
type testCountingReader struct {
	reader    io.Reader
	readCount int
	limit     int
}

func (self *testCountingReader) Read(buffer []byte) (int, error) {
	if self.limit <= self.readCount {
		return 0, errors.New("read past the frame")
	}
	if remaining := self.limit - self.readCount; remaining < len(buffer) {
		buffer = buffer[:remaining]
	}
	n, err := self.reader.Read(buffer)
	self.readCount += n
	return n, err
}

// Counts writes, so a test can show a frame went out in one.
type testCountingWriter struct {
	bytes.Buffer
	writeCount int
}

func (self *testCountingWriter) Write(data []byte) (int, error) {
	self.writeCount += 1
	return self.Buffer.Write(data)
}

func TestSmtpPreambleRoundTripsAsAFrameAndLeavesTheTlsBytes(t *testing.T) {
	stream := &testCountingWriter{}
	if err := WriteSmtpPreamble(stream, testSmtpPreamble(), nil); err != nil {
		t.Fatal(err)
	}
	if stream.writeCount != 1 {
		t.Errorf("%d writes", stream.writeCount)
	}
	stream.Write(testSmtpTlsStart)
	reader := bytes.NewReader(stream.Bytes())
	preamble, err := ReadSmtpPreamble(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(preamble, testSmtpPreamble()) {
		t.Errorf("read back %v", preamble)
	}
	rest, _ := io.ReadAll(reader)
	if !bytes.Equal(rest, testSmtpTlsStart) {
		t.Errorf("the reader took the stream's TLS octets: %x left", rest)
	}
}

func TestSmtpPreambleResultRoundTripsAsAFrameAndLeavesTheTlsBytes(t *testing.T) {
	stream := &bytes.Buffer{}
	if err := WriteSmtpPreambleResult(stream, testSmtpPreambleResult(), nil); err != nil {
		t.Fatal(err)
	}
	frameByteCount := stream.Len()
	stream.Write(testSmtpTlsStart)
	reader := &testCountingReader{reader: bytes.NewReader(stream.Bytes()), limit: frameByteCount}
	result, err := ReadSmtpPreambleResult(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(result, testSmtpPreambleResult()) {
		t.Errorf("read back %v", result)
	}
	if reader.readCount != frameByteCount {
		t.Errorf("read %d of a %d B frame", reader.readCount, frameByteCount)
	}
}

func TestSmtpFrameTakesABodyAtTheBound(t *testing.T) {
	stream := &bytes.Buffer{}
	body := bytes.Repeat([]byte{0}, testSmtpFrameMaxBodyByteCount)
	if err := WriteSmtpFrame(stream, &SmtpFrame{Type: protocol.MessageType_SMTP_PREAMBLE, Body: body}, nil); err != nil {
		t.Fatal(err)
	}
	frame, err := ReadSmtpFrame(stream, protocol.MessageType_SMTP_PREAMBLE, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame.Body) != testSmtpFrameMaxBodyByteCount {
		t.Errorf("%d B", len(frame.Body))
	}
}

// plan-SMTP-wire-gaps#3: a bad length resets, and nothing is allocated for a length past the bound,
// nor read past its header.
func TestSmtpFrameRefusesALengthPastTheBoundBeforeAllocating(t *testing.T) {
	for _, bodyByteCount := range []uint32{testSmtpFrameMaxBodyByteCount + 1, 1024 * 1024, 0xFFFFFFFF} {
		stream := append(testSmtpFrameHeader(bodyByteCount, protocol.MessageType_SMTP_PREAMBLE), make([]byte, 1024)...)
		reader := &testCountingReader{reader: bytes.NewReader(stream), limit: len(stream)}
		if _, err := ReadSmtpFrame(reader, protocol.MessageType_SMTP_PREAMBLE, nil); !errors.Is(err, ErrSmtpFrameProtocol) {
			t.Errorf("%d B: %v", bodyByteCount, err)
		}
		if reader.readCount != SmtpFrameHeaderByteCount {
			t.Errorf("%d B: read %d octets", bodyByteCount, reader.readCount)
		}
	}

	header := testSmtpFrameHeader(0xFFFFFFFF, protocol.MessageType_SMTP_PREAMBLE)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	const readCount = 1000
	for range readCount {
		ReadSmtpFrame(bytes.NewReader(header), protocol.MessageType_SMTP_PREAMBLE, nil)
	}
	runtime.ReadMemStats(&after)
	// an error and a reader a call, never a body: a 4 GiB claim allocating anything for itself would
	// pass this many times over
	if perRead := (after.TotalAlloc - before.TotalAlloc) / readCount; 1024 < perRead {
		t.Errorf("%d B allocated a refused read", perRead)
	}
}

func TestSmtpFrameRefusesATypeThatIsNotItsOwn(t *testing.T) {
	for _, c := range []struct {
		frameType protocol.MessageType
		want      protocol.MessageType
	}{
		{frameType: protocol.MessageType_SMTP_PREAMBLE_RESULT, want: protocol.MessageType_SMTP_PREAMBLE},
		{frameType: protocol.MessageType_SMTP_PREAMBLE, want: protocol.MessageType_SMTP_PREAMBLE_RESULT},
		{frameType: protocol.MessageType_SMTP_PROOF, want: protocol.MessageType_SMTP_PREAMBLE},
		{frameType: protocol.MessageType_SMTP_OUTCOME, want: protocol.MessageType_SMTP_PREAMBLE},
		{frameType: protocol.MessageType_MESSAGE_TYPE_NONE, want: protocol.MessageType_SMTP_PREAMBLE},
	} {
		stream := testSmtpFrameHeader(0, c.frameType)
		if _, err := ReadSmtpFrame(bytes.NewReader(stream), c.want, nil); !errors.Is(err, ErrSmtpFrameProtocol) {
			t.Errorf("%s for %s: %v", c.frameType, c.want, err)
		}
	}
	// and nothing but the two frames may be written as one
	for _, frameType := range []protocol.MessageType{protocol.MessageType_SMTP_PROOF, protocol.MessageType_SMTP_OUTCOME, protocol.MessageType_MESSAGE_TYPE_NONE} {
		if err := WriteSmtpFrame(io.Discard, &SmtpFrame{Type: frameType}, nil); !errors.Is(err, ErrSmtpFrameProtocol) {
			t.Errorf("wrote %s: %v", frameType, err)
		}
	}
	if err := WriteSmtpFrame(io.Discard, &SmtpFrame{Type: protocol.MessageType_SMTP_PREAMBLE, Body: make([]byte, testSmtpFrameMaxBodyByteCount+1)}, nil); !errors.Is(err, ErrSmtpFrameProtocol) {
		t.Errorf("wrote a body past the bound: %v", err)
	}
}

func TestSmtpFrameEndingEarlyIsAReset(t *testing.T) {
	if _, err := ReadSmtpFrame(bytes.NewReader(nil), protocol.MessageType_SMTP_PREAMBLE, nil); err != io.EOF {
		t.Errorf("an empty stream: %v", err)
	}
	header := testSmtpFrameHeader(10, protocol.MessageType_SMTP_PREAMBLE)
	if _, err := ReadSmtpFrame(bytes.NewReader(header[:3]), protocol.MessageType_SMTP_PREAMBLE, nil); err != io.ErrUnexpectedEOF {
		t.Errorf("half a header: %v", err)
	}
	if _, err := ReadSmtpFrame(bytes.NewReader(header), protocol.MessageType_SMTP_PREAMBLE, nil); err != io.ErrUnexpectedEOF {
		t.Errorf("no body: %v", err)
	}
	if _, err := ReadSmtpFrame(bytes.NewReader(append(header, 1, 2, 3)), protocol.MessageType_SMTP_PREAMBLE, nil); err != io.ErrUnexpectedEOF {
		t.Errorf("part of a body: %v", err)
	}
}

func TestSmtpFrameBodyThatDoesNotDecodeIsAReset(t *testing.T) {
	// a field tag naming wire type 7, which no encoding has
	garbage := []byte{0x0f, 0xff}
	stream := append(testSmtpFrameHeader(uint32(len(garbage)), protocol.MessageType_SMTP_PREAMBLE), garbage...)
	if _, err := ReadSmtpPreamble(bytes.NewReader(stream), nil); !errors.Is(err, ErrSmtpFrameProtocol) {
		t.Errorf("preamble: %v", err)
	}
	stream = append(testSmtpFrameHeader(uint32(len(garbage)), protocol.MessageType_SMTP_PREAMBLE_RESULT), garbage...)
	if _, err := ReadSmtpPreambleResult(bytes.NewReader(stream), nil); !errors.Is(err, ErrSmtpFrameProtocol) {
		t.Errorf("result: %v", err)
	}
}

// DESIGN-DETAILS 3.2.5: the key set a connection is proven under travels in the preamble, and a preamble
// without one reads back without one.
func TestSmtpPreambleRoundTripsWithAndWithoutItsKeySet(t *testing.T) {
	for _, keySet := range [][]byte{nil, bytes.Repeat([]byte{0xa5}, 32)} {
		preamble := testSmtpPreamble()
		preamble.ProofKeySet = keySet
		stream := &bytes.Buffer{}
		if err := WriteSmtpPreamble(stream, preamble, nil); err != nil {
			t.Fatal(err)
		}
		read, err := ReadSmtpPreamble(stream, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(read, preamble) || !bytes.Equal(read.GetProofKeySet(), keySet) {
			t.Errorf("a %d-octet key set read back as %x", len(keySet), read.GetProofKeySet())
		}
	}
	// a preamble from a sender before the field decodes, with no key set
	old := testSmtpPreamble()
	body, err := proto.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	stream := append(testSmtpFrameHeader(uint32(len(body)), protocol.MessageType_SMTP_PREAMBLE), body...)
	read, err := ReadSmtpPreamble(bytes.NewReader(stream), nil)
	if err != nil || len(read.GetProofKeySet()) != 0 {
		t.Errorf("an old preamble: %x, %v", read.GetProofKeySet(), err)
	}
}

// DESIGN-DETAILS 3.2.5: KEYS is a code both ends know, an answer and no protocol error, while 0 stays one.
func TestSmtpPreambleResultKeysIsAKnownCode(t *testing.T) {
	result := &protocol.SmtpPreambleResult{Code: uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS)}
	stream := &bytes.Buffer{}
	if err := WriteSmtpPreambleResult(stream, result, nil); err != nil {
		t.Fatal(err)
	}
	read, err := ReadSmtpPreambleResult(stream, nil)
	if err != nil || read.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS) {
		t.Fatalf("KEYS read back as %d: %v", read.GetCode(), err)
	}
	if protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS != 8 {
		t.Errorf("KEYS is %d", protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS)
	}
	zero := &protocol.SmtpPreambleResult{}
	if err := WriteSmtpPreambleResult(io.Discard, zero, nil); !errors.Is(err, ErrSmtpFrameProtocol) {
		t.Errorf("wrote code 0: %v", err)
	}
}

// The bound is the settings' (QD-702): the defaults hold 64 KiB, and a tighter bound refuses what passes
// it in both directions, before allocating for a read.
func TestSmtpFrameBoundIsItsSettings(t *testing.T) {
	if bound := DefaultSmtpFrameSettings().MaxBodyByteCount; bound != testSmtpFrameMaxBodyByteCount {
		t.Errorf("the default bound is %d", bound)
	}
	tight := DefaultSmtpFrameSettings()
	tight.MaxBodyByteCount = 16
	frame := &SmtpFrame{Type: protocol.MessageType_SMTP_PREAMBLE, Body: make([]byte, 17)}
	if err := WriteSmtpFrame(io.Discard, frame, tight); !errors.Is(err, ErrSmtpFrameProtocol) {
		t.Errorf("wrote past a tight bound: %v", err)
	}
	stream := &bytes.Buffer{}
	if err := WriteSmtpFrame(stream, frame, nil); err != nil {
		t.Fatal(err)
	}
	reader := &testCountingReader{reader: bytes.NewReader(stream.Bytes()), limit: stream.Len()}
	if _, err := ReadSmtpFrame(reader, protocol.MessageType_SMTP_PREAMBLE, tight); !errors.Is(err, ErrSmtpFrameProtocol) {
		t.Errorf("read past a tight bound: %v", err)
	}
	if reader.readCount != SmtpFrameHeaderByteCount {
		t.Errorf("read %d octets of a refused frame", reader.readCount)
	}
	frame.Body = frame.Body[:16]
	stream.Reset()
	if err := WriteSmtpFrame(stream, frame, tight); err != nil {
		t.Fatal(err)
	}
	if read, err := ReadSmtpFrame(stream, protocol.MessageType_SMTP_PREAMBLE, tight); err != nil || len(read.Body) != 16 {
		t.Errorf("a body at a tight bound: %v", err)
	}
}

// §6.11: a result code of 0 is a protocol error, never retry, refusal or success, and so is one this
// version does not know.
func TestSmtpPreambleResultRefusesCodeZeroAndUnknownCodes(t *testing.T) {
	for _, code := range []uint32{0, 9, 0xFFFFFFFF} {
		result := testSmtpPreambleResult()
		result.Code = code
		body, err := proto.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		stream := append(testSmtpFrameHeader(uint32(len(body)), protocol.MessageType_SMTP_PREAMBLE_RESULT), body...)
		if _, err := ReadSmtpPreambleResult(bytes.NewReader(stream), nil); !errors.Is(err, ErrSmtpFrameProtocol) {
			t.Errorf("read code %d: %v", code, err)
		}
		if err := WriteSmtpPreambleResult(io.Discard, result, nil); !errors.Is(err, ErrSmtpFrameProtocol) {
			t.Errorf("wrote code %d: %v", code, err)
		}
	}
	for code := range protocol.SmtpPreambleCode_name {
		if code == 0 {
			continue
		}
		result := testSmtpPreambleResult()
		result.Code = uint32(code)
		stream := &bytes.Buffer{}
		if err := WriteSmtpPreambleResult(stream, result, nil); err != nil {
			t.Errorf("code %d: %v", code, err)
			continue
		}
		if _, err := ReadSmtpPreambleResult(stream, nil); err != nil {
			t.Errorf("code %d: %v", code, err)
		}
	}
}

// plan-SMTP-wire-gaps#3: a chain that would pass the bound goes empty, so the connection has no TL1,
// and everything else arrives as written.
func TestSmtpPreambleResultDropsAChainPastTheBound(t *testing.T) {
	result := testSmtpPreambleResult()
	result.DnssecChain = bytes.Repeat([]byte{9}, testSmtpFrameMaxBodyByteCount)
	stream := &bytes.Buffer{}
	if err := WriteSmtpPreambleResult(stream, result, nil); err != nil {
		t.Fatal(err)
	}
	if len(result.DnssecChain) != testSmtpFrameMaxBodyByteCount {
		t.Error("the writer changed its argument")
	}
	read, err := ReadSmtpPreambleResult(stream, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.DnssecChain) != 0 {
		t.Errorf("a %d B chain arrived", len(read.DnssecChain))
	}
	read.DnssecChain = testSmtpPreambleResult().DnssecChain
	if !proto.Equal(read, testSmtpPreambleResult()) {
		t.Errorf("read back %v", read)
	}

	// a chain that fits goes as it is
	result = testSmtpPreambleResult()
	result.DnssecChain = bytes.Repeat([]byte{9}, testSmtpFrameMaxBodyByteCount/2)
	stream.Reset()
	if err := WriteSmtpPreambleResult(stream, result, nil); err != nil {
		t.Fatal(err)
	}
	if read, err := ReadSmtpPreambleResult(stream, nil); err != nil || len(read.DnssecChain) != testSmtpFrameMaxBodyByteCount/2 {
		t.Errorf("a chain that fits: %v", err)
	}

	// what is past the bound without a chain is refused, not cut
	result = testSmtpPreambleResult()
	result.DnssecChain = nil
	result.EhloKeywords = []string{strings.Repeat("K", testSmtpFrameMaxBodyByteCount)}
	if err := WriteSmtpPreambleResult(io.Discard, result, nil); !errors.Is(err, ErrSmtpFrameProtocol) {
		t.Errorf("keywords past the bound: %v", err)
	}
}

// §22.6's frame target: no input panics, a frame over the size bound is refused with no allocation for
// it, and whatever reads is exactly what a writer writes for it, with nothing read past it.
func FuzzSmtpFrame(f *testing.F) {
	preamble := &bytes.Buffer{}
	WriteSmtpPreamble(preamble, testSmtpPreamble(), nil)
	result := &bytes.Buffer{}
	WriteSmtpPreambleResult(result, testSmtpPreambleResult(), nil)
	keyed := &bytes.Buffer{}
	keyedPreamble := testSmtpPreamble()
	keyedPreamble.ProofKeySet = bytes.Repeat([]byte{0xa5}, 32)
	WriteSmtpPreamble(keyed, keyedPreamble, nil)
	keys := &bytes.Buffer{}
	WriteSmtpPreambleResult(keys, &protocol.SmtpPreambleResult{Code: uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS)}, nil)
	f.Add(preamble.Bytes())
	f.Add(result.Bytes())
	f.Add(keyed.Bytes())
	f.Add(keys.Bytes())
	f.Add(append(slices.Clone(preamble.Bytes()), testSmtpTlsStart...))
	f.Add(testSmtpFrameHeader(0, protocol.MessageType_SMTP_PREAMBLE))
	f.Add(testSmtpFrameHeader(testSmtpFrameMaxBodyByteCount+1, protocol.MessageType_SMTP_PREAMBLE))
	f.Add(testSmtpFrameHeader(0xFFFFFFFF, protocol.MessageType_SMTP_PREAMBLE_RESULT))
	f.Add(testSmtpFrameHeader(4, protocol.MessageType_SMTP_PROOF))
	f.Add(preamble.Bytes()[:preamble.Len()-1])
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, want := range []protocol.MessageType{protocol.MessageType_SMTP_PREAMBLE, protocol.MessageType_SMTP_PREAMBLE_RESULT} {
			reader := bytes.NewReader(data)
			frame, err := ReadSmtpFrame(reader, want, nil)
			if 6 <= len(data) && testSmtpFrameMaxBodyByteCount < binary.BigEndian.Uint32(data[0:4]) {
				if !errors.Is(err, ErrSmtpFrameProtocol) {
					t.Fatalf("a length past the bound: %v", err)
				}
				if consumed := len(data) - reader.Len(); consumed != SmtpFrameHeaderByteCount {
					t.Fatalf("read %d octets of a refused frame", consumed)
				}
			}
			if err != nil {
				continue
			}
			if frame.Type != want || testSmtpFrameMaxBodyByteCount < len(frame.Body) {
				t.Fatalf("read a %s frame of %d B", frame.Type, len(frame.Body))
			}
			written := &bytes.Buffer{}
			if err := WriteSmtpFrame(written, frame, nil); err != nil {
				t.Fatal(err)
			}
			if consumed := len(data) - reader.Len(); !bytes.Equal(written.Bytes(), data[:consumed]) {
				t.Fatalf("read %d octets that write as %d others", consumed, written.Len())
			}
		}
		ReadSmtpPreamble(bytes.NewReader(data), nil)
		if result, err := ReadSmtpPreambleResult(bytes.NewReader(data), nil); err == nil && !smtpPreambleCodeKnown(result.GetCode()) {
			t.Fatalf("read code %d", result.GetCode())
		}
	})
}
