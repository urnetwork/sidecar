// §6's wire as M2 froze it (D-PROTO-20): golden encodings in testdata/wire/ for the envelope, Chunk, Error,
// Hello and HelloResult, HeadCheck and its proof, the push messages and every stream message, streams'
// own included though they run only from M5, so their numbers froze with the rest. Each vector is built
// here, marshalled as the dispatcher marshals, and held byte-equal to its file, decoded back, and read
// from its protojson form, on every leg: the files are embedded, so the sidecar_http leg's Worker, which
// has no file system, runs the same comparison (legs_test.go names these tests). Decoders skip what they
// do not know, and §22.5's enum and zero rows run again over protocol/wire_lock.json's codes.
//
// SIDECAR_REGENERATE_WIRE_GOLDENS=1 writes a vector this file adds to its golden, and refuses to change one
// a golden holds: a frozen encoding changes only by a format change, never by a regeneration.

package sidecar

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/wire/envelope.json
var testWireEnvelopeJson []byte

//go:embed testdata/wire/headcheck.json
var testWireHeadCheckJson []byte

//go:embed testdata/wire/push.json
var testWirePushJson []byte

//go:embed testdata/wire/stream.json
var testWireStreamJson []byte

//go:embed protocol/wire_lock.json
var testWireLockJson []byte

// Set, a vector this file builds that its golden lacks is written to it.
const testWireRegenerateEnvironment = "SIDECAR_REGENERATE_WIRE_GOLDENS"

// One golden encoding: the message's full name, its fields in protojson, and its bytes in hex.
type testWireVector struct {
	Name    string          `json:"name"`
	Message string          `json:"message"`
	Fields  json.RawMessage `json:"fields"`
	Wire    string          `json:"wire"`
}

// One golden file.
type testWireGolden struct {
	Comment []string          `json:"comment"`
	Vectors []*testWireVector `json:"vectors"`
}

// A vector as this file builds it.
type testWireCase struct {
	name    string
	message proto.Message
}

// A byte string of n bytes counting up from first, so a vector's bytes are visibly synthetic.
func testWireBytes(first byte, n int) []byte {
	value := make([]byte, n)
	for i := range value {
		value[i] = first + byte(i)
	}
	return value
}

// A marshalled message, for a vector whose body is another's bytes.
func testWireMarshal(message proto.Message) []byte {
	data, err := proto.Marshal(message)
	if err != nil {
		panic(err)
	}
	return data
}

// A synthetic id in UUID form, as a topic names one (push_topic.go).
func testWireId(first byte) string {
	var id Id
	copy(id[:], testWireBytes(first, len(id)))
	return id.String()
}

const testWireRequestId = 0x0123456789abcdef

// testdata/wire/envelope.json: the envelope's shapes, Chunk, Error, Hello and HelloResult.
func testWireEnvelopeCases() []*testWireCase {
	finalChunkHash := testWireBytes(0xa0, 32)
	return []*testWireCase{
		{name: "a request", message: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_HEAD_CHECK), RequestId: testWireRequestId,
			TimeoutMs: 15000, Body: testWireBytes(0x10, 24),
		}},
		{name: "its response", message: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_HEAD_CHECK_RESULT), RequestId: testWireRequestId,
			Flags: EnvelopeFlagResponse, Body: testWireBytes(0x30, 24),
		}},
		{name: "a refusal", message: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_ERROR), RequestId: testWireRequestId,
			Flags: EnvelopeFlagResponse | EnvelopeFlagError,
			Body:  testWireMarshal(&protocol.Error{Code: uint32(protocol.ErrorCode_ERR_PERMISSION_DENIED)}),
		}},
		{name: "a version refusal with the receiver's range", message: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_ERROR), RequestId: testWireRequestId,
			Flags: EnvelopeFlagResponse | EnvelopeFlagError,
			Body: testWireMarshal(&protocol.Error{
				Code: uint32(protocol.ErrorCode_ERR_VERSION), MinVersion: WireVersionMajor, MaxVersion: WireVersionMajor,
			}),
		}},
		{name: "a ping", message: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_PING), RequestId: testWireRequestId, TimeoutMs: 15000,
		}},
		{name: "a pong", message: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_PONG), RequestId: testWireRequestId,
			Flags: EnvelopeFlagResponse,
		}},
		{name: "a cancel", message: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_CANCEL), RequestId: testWireRequestId,
			Flags: EnvelopeFlagNoReply,
		}},
		{name: "a first chunk", message: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_HEAD_CHECK_PROOF), RequestId: testWireRequestId,
			Flags: EnvelopeFlagResponse | EnvelopeFlagMore,
			Chunk: &protocol.Chunk{Index: 0, Count: 3, TotalByteCount: 9000}, Body: testWireBytes(0x40, 16),
		}},
		{name: "a final chunk", message: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_HEAD_CHECK_PROOF), RequestId: testWireRequestId,
			Flags: EnvelopeFlagResponse,
			Chunk: &protocol.Chunk{Index: 2, Count: 3, TotalByteCount: 9000, Sha256: finalChunkHash}, Body: testWireBytes(0x50, 16),
		}},
		{name: "a stream frame", message: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_STREAM_DATA), Flags: EnvelopeFlagNoReply, StreamId: 2,
			Body: testWireMarshal(&protocol.StreamData{Offset: 2048, Data: testWireBytes(0x60, 8)}),
		}},
		{name: "the widest header", message: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_SEARCH_RESULT), RequestId: math.MaxUint64,
			Flags: EnvelopeFlagResponse | EnvelopeFlagError | EnvelopeFlagMore | EnvelopeFlagNoReply, StreamId: math.MaxUint64,
			TimeoutMs: uint32(MaxCallTimeout.Milliseconds()),
			Chunk:     &protocol.Chunk{Index: math.MaxUint32, Count: math.MaxUint32, TotalByteCount: MaxReassemblyBodyByteCount, Sha256: finalChunkHash},
		}},
		{name: "a final chunk alone", message: &protocol.Chunk{Index: 4, Count: 5, TotalByteCount: 20064, Sha256: finalChunkHash}},
		{name: "an error with every field", message: &protocol.Error{
			Code: uint32(protocol.ErrorCode_ERR_ALREADY_EXISTS), Message: "response too large to keep", RetryAfterMs: 250,
			ResultRef: testWireBytes(0x70, 16),
		}},
		{name: "a version error", message: &protocol.Error{
			Code: uint32(protocol.ErrorCode_ERR_VERSION), MinVersion: WireVersionMajor, MaxVersion: WireVersionMajor,
		}},
		{name: "a hello", message: &protocol.Hello{
			MinVersion: WireVersionMajor, MaxVersion: WireVersionMajor, SecureVersion: 1,
			// §6.11's bits 0, serves remote search, and 1, asks it
			Features: 1<<0 | 1<<1, MaxBodyByteCount: 256 * 1024,
			InitialWindow: 16 * 1024, Binding: testWireBytes(0x80, 48),
		}},
		{name: "a hello result", message: &protocol.HelloResult{
			MinVersion: WireVersionMajor, MaxVersion: WireVersionMajor, SecureVersion: 1,
			MaxBodyByteCount: 256 * 1024, InitialWindow: 16 * 1024, Binding: testWireBytes(0xb0, 48),
		}},
		{name: "an edge's hello fields, none", message: &protocol.Hello{}},
	}
}

// testdata/wire/headcheck.json: HeadCheck at every list, its result, the proof request and the proof.
func testWireHeadCheckCases() []*testWireCase {
	pin := func(version uint64, first byte) *bridge.AuthPin {
		return &bridge.AuthPin{Version: version, Chain: testWireBytes(first, 32)}
	}
	full := func() *protocol.HeadCheck {
		return &protocol.HeadCheck{
			NetworkId: testWireBytes(0x01, 16),
			Auth:      pin(42, 0x11),
			Groups: []*protocol.GroupHead{
				{GroupId: testWireBytes(0x21, 16), Epoch: 7, EpochAuthenticator: testWireBytes(0x31, 32)},
				{GroupId: testWireBytes(0x41, 16), Epoch: 1 << 40, EpochAuthenticator: testWireBytes(0x51, 32)},
			},
			Gens:   []*protocol.GenHead{{GroupId: testWireBytes(0x21, 16), Generation: 3, Commitment: testWireBytes(0x61, 32)}},
			Refs:   []*protocol.RefHead{{RepoId: testWireBytes(0x71, 16), RefId: testWireBytes(0x81, 16), Version: 1786000000000000123, Chain: testWireBytes(0x91, 32)}},
			Vetoes: [][]byte{testWireBytes(0xa1, 40)},
			Proven: pin(50, 0xb1),
			Unverified: []*protocol.UnverifiedPin{
				{Pin: pin(60, 0xc1), Path: [][]byte{testWireBytes(0xd1, 16), testWireBytes(0xe1, 16)}},
			},
		}
	}
	return []*testWireCase{
		{name: "a head check at every list", message: full()},
		{name: "a head check with its auth pin alone", message: &protocol.HeadCheck{NetworkId: testWireBytes(0x01, 16), Auth: pin(42, 0x11)}},
		{name: "its result", message: testWireHeadCheckResult(full())},
		{name: "a proof request", message: &protocol.HeadCheckProofRequest{After: 41}},
		{name: "a proof", message: &protocol.HeadCheckProof{Entries: [][]byte{testWireBytes(0x02, 40), testWireBytes(0x42, 40)}}},
		{name: "an unverified pin and its path", message: &protocol.UnverifiedPin{Pin: pin(60, 0xc1), Path: [][]byte{testWireBytes(0xd1, 16)}}},
		{name: "an auth pin", message: pin(42, 0x11)},
	}
}

// A HeadCheckResult with a HeadCheck's fields, which carry the same numbers (I-16).
func testWireHeadCheckResult(message *protocol.HeadCheck) *protocol.HeadCheckResult {
	return &protocol.HeadCheckResult{
		NetworkId: message.NetworkId, Auth: message.Auth, Groups: message.Groups, Gens: message.Gens, Refs: message.Refs,
		Vetoes: message.Vetoes, Proven: message.Proven, Unverified: message.Unverified,
	}
}

// testdata/wire/push.json: a reset complete and in part, a hint and a coalesced one, and the long-poll's
// body after a hint and after an empty hold.
func testWirePushCases() []*testWireCase {
	evsTopic := PushTopicEvsPrefix + testWireId(0x10)
	reset := &protocol.PushReset{
		Epoch: 1767323045000,
		Versions: []*protocol.TopicVersion{
			{Topic: PushTopicCore, Version: 1767323045123456},
			{Topic: evsTopic, Version: 1786000000000000123},
		},
		Complete: true,
	}
	hint := &protocol.PushHint{Seq: 17, Topic: PushTopicGkm, Version: 1767323045123457, Kind: uint32(protocol.MessageType_GKM_HINT), Hint: testWireBytes(0x20, 24)}
	coalesced := &protocol.PushHint{Seq: 18, Topic: evsTopic, Version: 1786000000000000124, Kind: uint32(protocol.MessageType_EVS_HEAD_CHANGED)}
	return []*testWireCase{
		{name: "a complete reset", message: reset},
		{name: "a reset in part", message: &protocol.PushReset{Epoch: 1767323045000, Versions: []*protocol.TopicVersion{{Topic: PushTopicTeam, Version: 42}}}},
		{name: "a topic version", message: &protocol.TopicVersion{Topic: PushTopicDns, Version: 2026110901}},
		{name: "a hint", message: hint},
		{name: "a coalesced hint, its bytes dropped", message: coalesced},
		{name: "a poll answered with hints", message: &protocol.PollResponse{
			Cursor: []byte("1767323045123-0"), Hints: []*protocol.PushHint{hint, coalesced}, Reset_: reset,
		}},
		{name: "a poll after an empty hold", message: &protocol.PollResponse{Cursor: []byte("1767323045123-0")}},
	}
}

// testdata/wire/stream.json: every stream message, frozen at M2 though streams run from M5.
func testWireStreamCases() []*testWireCase {
	return []*testWireCase{
		{name: "an open with every field", message: &protocol.StreamOpen{
			Target: "examplenet:tls/443/blog", Metadata: testWireBytes(0x10, 32), Ticket: testWireBytes(0x40, 64),
			Window: 256 * 1024, EarlyData: append([]byte{0x16, 0x03, 0x01}, testWireBytes(0x80, 29)...),
		}},
		{name: "an open with a target and a window", message: &protocol.StreamOpen{Target: "examplenet:ur/agent", Window: 64 * 1024}},
		{name: "an accept", message: &protocol.StreamAccept{Window: 256 * 1024}},
		{name: "a reject", message: &protocol.StreamReject{Code: uint32(protocol.StreamRejectCode_SR_BUSY), RetryAfterMs: 5000}},
		{name: "data", message: &protocol.StreamData{Offset: 2048, Data: testWireBytes(0x20, 16)}},
		{name: "data far along", message: &protocol.StreamData{Offset: 1 << 40, Data: testWireBytes(0x30, 4)}},
		{name: "a window", message: &protocol.StreamWindow{ConsumedOffset: 64 * 1024, MaxOffset: 320 * 1024}},
		{name: "a close", message: &protocol.StreamClose{FinalOffset: 70000}},
		{name: "a reset", message: &protocol.StreamReset{Code: uint32(protocol.StreamResetCode_RST_IDENTITY), FinalOffset: 4096}},
		{name: "a reset before any byte", message: &protocol.StreamReset{Code: uint32(protocol.StreamResetCode_RST_PEER_TIMEOUT)}},
	}
}

// The four goldens: each file's path, embedded bytes and cases.
func testWireGoldens() []struct {
	path     string
	embedded []byte
	cases    []*testWireCase
} {
	return []struct {
		path     string
		embedded []byte
		cases    []*testWireCase
	}{
		{path: "testdata/wire/envelope.json", embedded: testWireEnvelopeJson, cases: testWireEnvelopeCases()},
		{path: "testdata/wire/headcheck.json", embedded: testWireHeadCheckJson, cases: testWireHeadCheckCases()},
		{path: "testdata/wire/push.json", embedded: testWirePushJson, cases: testWirePushCases()},
		{path: "testdata/wire/stream.json", embedded: testWireStreamJson, cases: testWireStreamCases()},
	}
}

// What a golden's comment says, the same in each file.
var testWireGoldenComment = []string{
	"§6's wire as M2 froze it (D-PROTO-20): each vector's bytes are proto.Marshal's of its fields, which",
	"envelope_wire_test.go builds and holds byte-equal on every leg. A vector's bytes never change: a new vector",
	"is added with SIDECAR_REGENERATE_WIRE_GOLDENS=1, which refuses to change one already here.",
}

// A golden from its bytes.
func testReadWireGolden(t testing.TB, data []byte) *testWireGolden {
	t.Helper()
	golden := &testWireGolden{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(golden); err != nil {
		t.Fatal(err)
	}
	return golden
}

// A vector from its case: the bytes the dispatcher would send, and the fields as protojson.
func testWireVectorOf(t testing.TB, c *testWireCase) *testWireVector {
	t.Helper()
	fields, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(c.message)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, fields); err != nil {
		t.Fatal(err)
	}
	return &testWireVector{
		Name:    c.name,
		Message: string(c.message.ProtoReflect().Descriptor().FullName()),
		Fields:  compact.Bytes(),
		Wire:    hex.EncodeToString(testWireMarshal(c.message)),
	}
}

// Writes golden to path, one vector a line.
func testWriteWireGolden(t testing.TB, path string, golden *testWireGolden) {
	t.Helper()
	var out bytes.Buffer
	out.WriteString("{\n  \"comment\": [\n")
	for i, line := range golden.Comment {
		data, _ := json.Marshal(line)
		out.WriteString("    ")
		out.Write(data)
		if i < len(golden.Comment)-1 {
			out.WriteString(",")
		}
		out.WriteString("\n")
	}
	out.WriteString("  ],\n  \"vectors\": [\n")
	for i, vector := range golden.Vectors {
		data, err := json.Marshal(vector)
		if err != nil {
			t.Fatal(err)
		}
		out.WriteString("    ")
		out.Write(data)
		if i < len(golden.Vectors)-1 {
			out.WriteString(",")
		}
		out.WriteString("\n")
	}
	out.WriteString("  ]\n}\n")
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A new message of the vector's type, from the registry both protocol packages register into.
func testWireNewMessage(t testing.TB, fullName string) proto.Message {
	t.Helper()
	messageType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(fullName))
	if err != nil {
		t.Fatalf("%s: %v", fullName, err)
	}
	return messageType.New().Interface()
}

// Each vector this file builds, marshalled as the dispatcher marshals, is byte-equal to its golden, decodes
// from the golden's bytes to the same message, and reads the same from the golden's protojson; and every
// vector a golden holds is one this file builds, so none is dropped unseen.
func TestWireGoldensAreByteEqual(t *testing.T) {
	regenerate := os.Getenv(testWireRegenerateEnvironment) != ""
	for _, golden := range testWireGoldens() {
		held := testReadWireGolden(t, golden.embedded)
		heldByName := map[string]*testWireVector{}
		for _, vector := range held.Vectors {
			if heldByName[vector.Name] != nil {
				t.Errorf("%s: %q twice", golden.path, vector.Name)
			}
			heldByName[vector.Name] = vector
		}
		names := []string{}
		for _, c := range golden.cases {
			names = append(names, c.name)
			built := testWireVectorOf(t, c)
			vector := heldByName[c.name]
			if vector == nil {
				if !regenerate {
					t.Errorf("%s: no vector %q", golden.path, c.name)
					continue
				}
				held.Vectors = append(held.Vectors, built)
				vector = built
			}
			if vector.Message != built.Message {
				t.Errorf("%s %q: a %s, built as a %s", golden.path, c.name, vector.Message, built.Message)
				continue
			}
			if vector.Wire != built.Wire {
				t.Errorf("%s %q: the frozen bytes moved:\n held  %s\n built %s", golden.path, c.name, vector.Wire, built.Wire)
			}
			wire, err := hex.DecodeString(vector.Wire)
			if err != nil {
				t.Fatalf("%s %q: %v", golden.path, c.name, err)
			}
			decoded := testWireNewMessage(t, vector.Message)
			if err := proto.Unmarshal(wire, decoded); err != nil {
				t.Errorf("%s %q: %v", golden.path, c.name, err)
			} else if !proto.Equal(decoded, c.message) {
				t.Errorf("%s %q: decodes to %v", golden.path, c.name, decoded)
			}
			fromFields := testWireNewMessage(t, vector.Message)
			if err := protojson.Unmarshal(vector.Fields, fromFields); err != nil {
				t.Errorf("%s %q: fields: %v", golden.path, c.name, err)
			} else if !proto.Equal(fromFields, c.message) {
				t.Errorf("%s %q: fields read as %v", golden.path, c.name, fromFields)
			}
		}
		for _, vector := range held.Vectors {
			if !slices.Contains(names, vector.Name) {
				t.Errorf("%s: %q is held and built by nothing", golden.path, vector.Name)
			}
		}
		if regenerate && !t.Failed() {
			held.Comment = testWireGoldenComment
			testWriteWireGolden(t, golden.path, held)
		}
	}
}

// Every message the goldens hold, the stream messages among them, has a vector, so a golden covers each
// of §6's messages the plan freezes.
func TestWireGoldensCoverEveryFrozenMessage(t *testing.T) {
	covered := map[string]bool{}
	for _, golden := range testWireGoldens() {
		for _, c := range golden.cases {
			covered[string(c.message.ProtoReflect().Descriptor().FullName())] = true
		}
	}
	for _, name := range []string{
		"Envelope", "Chunk", "Error", "Hello", "HelloResult", "HeadCheck", "HeadCheckResult", "HeadCheckProofRequest",
		"HeadCheckProof", "UnverifiedPin", "PushReset", "TopicVersion", "PushHint", "PollResponse", "StreamOpen",
		"StreamAccept", "StreamReject", "StreamData", "StreamWindow", "StreamClose", "StreamReset", "AuthPin",
	} {
		if !covered["urnetwork.sidecar."+name] {
			t.Errorf("no golden holds a %s", name)
		}
	}
}

// Decoders skip what they do not know (§6.4): each vector with a field number no message declares
// appended, as a later version might add one, decodes without error to the same known fields.
func TestWireDecodersSkipUnknownFields(t *testing.T) {
	for _, golden := range testWireGoldens() {
		for _, c := range golden.cases {
			wire := testWireMarshal(c.message)
			// a varint and a length-delimited field past any number §6 uses
			wire = protowire.AppendTag(wire, 1000, protowire.VarintType)
			wire = protowire.AppendVarint(wire, 99)
			wire = protowire.AppendTag(wire, 1001, protowire.BytesType)
			wire = protowire.AppendBytes(wire, []byte("later"))
			decoded := c.message.ProtoReflect().New().Interface()
			if err := proto.Unmarshal(wire, decoded); err != nil {
				t.Errorf("%s %q: %v", golden.path, c.name, err)
				continue
			}
			if len(decoded.ProtoReflect().GetUnknown()) == 0 {
				t.Errorf("%s %q: the unknown fields were not seen", golden.path, c.name)
			}
			decoded.ProtoReflect().SetUnknown(nil)
			if !proto.Equal(decoded, c.message) {
				t.Errorf("%s %q: known fields changed: %v", golden.path, c.name, decoded)
			}
		}
	}
}

// protocol/wire_lock.json's values of one enum, by number.
func testWireLockedValues(t testing.TB, enumName string) map[int32]string {
	t.Helper()
	lock := struct {
		Enums []struct {
			Name   string `json:"name"`
			Values []struct {
				Number int32  `json:"number"`
				Name   string `json:"name"`
			} `json:"values"`
		} `json:"enums"`
	}{}
	if err := json.Unmarshal(testWireLockJson, &lock); err != nil {
		t.Fatal(err)
	}
	for _, enum := range lock.Enums {
		if enum.Name != enumName {
			continue
		}
		values := map[int32]string{}
		for _, value := range enum.Values {
			values[value.Number] = value.Name
		}
		return values
	}
	t.Fatalf("the lock holds no %s", enumName)
	return nil
}

// Numbers no locked code holds, past each end of its range and a wrapped one: each reads as unknown.
func testWireUnknownNumbers(values map[int32]string) []uint32 {
	highest := int32(0)
	for number := range values {
		highest = max(highest, number)
	}
	return []uint32{uint32(highest) + 1, uint32(highest) + 100, math.MaxInt32, math.MaxUint32}
}

// §22.5's enum and zero rows over the lock: every locked ErrorCode but OK is a code a call fails with, and
// OK and any number the lock does not hold fail the call as unknown, never as success (§6.5).
func TestWireLockedErrorCodesRead(t *testing.T) {
	values := testWireLockedValues(t, "urnetwork.sidecar.ErrorCode")
	if values[0] != "ERR_OK" {
		t.Fatalf("ErrorCode's zero is %q", values[0])
	}
	for number, name := range values {
		code, ok := readErrorCode(uint32(number))
		switch {
		case number == 0 && ok:
			t.Errorf("ERR_OK read as a code a sender sets")
		case number != 0 && (!ok || code.String() != name):
			t.Errorf("%s (%d) read as %v %t", name, number, code, ok)
		}
	}
	for _, number := range testWireUnknownNumbers(values) {
		if code, ok := readErrorCode(number); ok {
			t.Errorf("%d read as %v", number, code)
		}
	}
}

// Over the lock: every locked StreamRejectCode but UNSPECIFIED reads as itself, and the zero and any
// number the lock does not hold read as INVALID, never as retry (§6.11).
func TestWireLockedRejectCodesRead(t *testing.T) {
	values := testWireLockedValues(t, "urnetwork.sidecar.StreamRejectCode")
	if values[0] != "SR_UNSPECIFIED" {
		t.Fatalf("StreamRejectCode's zero is %q", values[0])
	}
	for number, name := range values {
		code := readStreamRejectCode(uint32(number))
		want := name
		if number == 0 {
			want = "SR_INVALID"
		}
		if code.String() != want {
			t.Errorf("%s (%d) read as %v", name, number, code)
		}
	}
	for _, number := range testWireUnknownNumbers(values) {
		if code := readStreamRejectCode(number); code != protocol.StreamRejectCode_SR_INVALID {
			t.Errorf("%d read as %v", number, code)
		}
	}
}

// Over the lock: every locked StreamResetCode but UNSPECIFIED reads as itself, and the zero and any number
// the lock does not hold read as PROTOCOL, never as drain (§6.11).
func TestWireLockedResetCodesRead(t *testing.T) {
	values := testWireLockedValues(t, "urnetwork.sidecar.StreamResetCode")
	if values[0] != "RST_UNSPECIFIED" {
		t.Fatalf("StreamResetCode's zero is %q", values[0])
	}
	for number, name := range values {
		code := readStreamResetCode(uint32(number))
		want := name
		if number == 0 {
			want = "RST_PROTOCOL"
		}
		if code.String() != want {
			t.Errorf("%s (%d) read as %v", name, number, code)
		}
	}
	for _, number := range testWireUnknownNumbers(values) {
		if code := readStreamResetCode(number); code != protocol.StreamResetCode_RST_PROTOCOL {
			t.Errorf("%d read as %v", number, code)
		}
	}
}

// Over the lock: MessageType's and SignedType's zeros name nothing a sender sets, and every locked value
// is one the registry still holds by that name, the zero rule's other half.
func TestWireLockedRegistriesHoldTheirZeros(t *testing.T) {
	for _, c := range []struct {
		enum  string
		names map[int32]string
		zero  string
	}{
		{enum: "urnetwork.sidecar.MessageType", names: protocol.MessageType_name, zero: "MESSAGE_TYPE_NONE"},
		{enum: "urnetwork.sidecar.SignedType", names: bridge.SignedType_name, zero: "SIGNED_TYPE_NONE"},
	} {
		values := testWireLockedValues(t, c.enum)
		if values[0] != c.zero {
			t.Errorf("%s's zero is %q", c.enum, values[0])
		}
		for number, name := range values {
			if c.names[number] != name {
				t.Errorf("%s: %d is %q, locked as %q", c.enum, number, c.names[number], name)
			}
		}
	}
	// the version refusal's range rides VERSION alone, as the golden shows
	if refusal := refusalError(protocol.ErrorCode_ERR_UNAUTHENTICATED); refusal.MinVersion != 0 || refusal.MaxVersion != 0 {
		t.Errorf("a refusal other than VERSION carries a range: %v", refusal)
	}
	if refusal := refusalError(protocol.ErrorCode_ERR_VERSION); refusal.MinVersion != WireVersionMajor || refusal.MaxVersion != WireVersionMajor {
		t.Errorf("VERSION's range: %v", refusal)
	}
}
