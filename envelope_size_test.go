//go:build !sidecar_http

// §6.5's budget, one row a line, each through the real codec, and the codec's own limit at its edges:
// "a test asserts that every maximal envelope fits". Numbers are the largest a varint holds and
// identifiers the design's 16 B ids and 32 B hashes, so each row overstates what a real message takes.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const (
	testSizeIdByteCount   = 16
	testSizeHashByteCount = 32
	// §5.5's seven fields at their widest beside two Ed25519 signatures, as plan-CORE-binding-wire.md
	// proposes them. Its bytes are not settled, so this stands in for one.
	testSizeBindingByteCount = 279
	// §6.5's "~250 more a veto": a Signed RecoveryVeto.
	testSizeVetoByteCount = 250
	// an evs: or gkm: topic with the id in its text form
	testSizeTopicByteCount = 4 + 36
)

// Stands for an identifier or hash of this size.
func testSizeBytes(byteCount int) []byte {
	return bytes.Repeat([]byte{0xFF}, byteCount)
}

// What a message's body takes, encoded.
func testSizeBody(t *testing.T, message proto.Message) []byte {
	t.Helper()
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// A call's header at its widest, which no stream frame's fields add to.
func testSizeCallHeader(messageType protocol.MessageType) *protocol.Envelope {
	return &protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(messageType),
		RequestId: math.MaxUint64,
		Flags:     EnvelopeFlagResponse | EnvelopeFlagError | EnvelopeFlagNoReply,
		TimeoutMs: uint32(MaxCallTimeout / time.Millisecond),
	}
}

// A stream frame's header at its widest.
func testSizeStreamHeader(messageType protocol.MessageType) *protocol.Envelope {
	header := testSizeCallHeader(messageType)
	header.StreamId = math.MaxUint64
	return header
}

// What byteCount of payload takes inside connect's wrapper, which connect encodes byte for byte as this
// message (connect/subprotocol.go:138-142).
func testSizeWrapped(byteCount int) int {
	return proto.Size(&connectprotocol.SubprotocolMessage{
		SubprotocolId: SubprotocolId,
		MessageBytes:  make([]byte, byteCount),
	})
}

// Each envelope's length on the wire, through the codec, which is what refuses one past the limit.
func testSizesOf(t *testing.T, envelopes []*protocol.Envelope) []int {
	t.Helper()
	sizes := []int{}
	for _, envelope := range envelopes {
		encoded, err := envelopeCodec{}.MarshalAppend(nil, envelope)
		if err != nil {
			t.Fatalf("%v", err)
		}
		sizes = append(sizes, len(encoded))
	}
	return sizes
}

// A maximal Hello: every number at its widest, and §5.5's binding.
func testMaxHello() *protocol.Hello {
	return &protocol.Hello{
		MinVersion:       math.MaxUint32,
		MaxVersion:       math.MaxUint32,
		SecureVersion:    math.MaxUint32,
		Features:         math.MaxUint64,
		MaxBodyByteCount: math.MaxUint32,
		InitialWindow:    math.MaxUint32,
		Binding:          testSizeBytes(testSizeBindingByteCount),
	}
}

// A pin at its widest.
func testMaxAuthPin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: math.MaxUint64, Chain: testSizeBytes(testSizeHashByteCount)}
}

// A HeadCheck at every list cap §6.4 gives: 16 groups, generations and refs, 4 vetoes, a proven pin, and
// 4 unverified pins with 8-hop paths.
func testMaxHeadCheck() *protocol.HeadCheck {
	headCheck := &protocol.HeadCheck{
		NetworkId: testSizeBytes(testSizeIdByteCount),
		Auth:      testMaxAuthPin(),
		Proven:    testMaxAuthPin(),
	}
	for range 16 {
		headCheck.Groups = append(headCheck.Groups, &protocol.GroupHead{
			GroupId:            testSizeBytes(testSizeIdByteCount),
			Epoch:              math.MaxUint64,
			EpochAuthenticator: testSizeBytes(testSizeHashByteCount),
		})
		headCheck.Gens = append(headCheck.Gens, &protocol.GenHead{
			GroupId:    testSizeBytes(testSizeIdByteCount),
			Generation: math.MaxUint64,
			Commitment: testSizeBytes(testSizeHashByteCount),
		})
		headCheck.Refs = append(headCheck.Refs, &protocol.RefHead{
			RepoId:  testSizeBytes(testSizeIdByteCount),
			RefId:   testSizeBytes(testSizeIdByteCount),
			Version: math.MaxUint64,
			Chain:   testSizeBytes(testSizeHashByteCount),
		})
	}
	for range 4 {
		headCheck.Vetoes = append(headCheck.Vetoes, testSizeBytes(testSizeVetoByteCount))
		pin := &protocol.UnverifiedPin{Pin: testMaxAuthPin()}
		for range 8 {
			pin.Path = append(pin.Path, testSizeBytes(testSizeIdByteCount))
		}
		headCheck.Unverified = append(headCheck.Unverified, pin)
	}
	return headCheck
}

// §6.5: a HeadCheck past 4,016 B is chunked, and two envelopes hold one at every list cap.
func TestHeadCheckAtItsCapsTakesTwoEnvelopes(t *testing.T) {
	body := testSizeBody(t, testMaxHeadCheck())
	if len(body) <= MaxEnvelopeBodyByteCount {
		t.Fatalf("%d B is no maximal HeadCheck", len(body))
	}
	for _, messageType := range []protocol.MessageType{protocol.MessageType_HEAD_CHECK, protocol.MessageType_HEAD_CHECK_RESULT} {
		envelopes, err := chunkBody(testSizeCallHeader(messageType), body)
		if err != nil {
			t.Fatal(err)
		}
		if len(envelopes) != 2 {
			t.Errorf("%d B took %d envelopes", len(body), len(envelopes))
		}
		testSizesOf(t, envelopes)
	}
}

// §6.5: a proof of 64 KiB of entries takes 17 envelopes, its encoding's own bytes included.
func TestHeadCheckProofAtItsCapTakesSeventeenEnvelopes(t *testing.T) {
	proof := &protocol.HeadCheckProof{}
	for range 64 {
		proof.Entries = append(proof.Entries, testSizeBytes(1024))
	}
	envelopes, err := chunkBody(testSizeCallHeader(protocol.MessageType_HEAD_CHECK_PROOF), testSizeBody(t, proof))
	if err != nil {
		t.Fatal(err)
	}
	if len(envelopes) != 17 {
		t.Errorf("took %d envelopes", len(envelopes))
	}
	testSizesOf(t, envelopes)
}

// Every line of §6.5's table that is one envelope, each under its own bound, with connect's wrapper
// where the line counts it.
func TestEveryMaximalMessageFitsOneEnvelope(t *testing.T) {
	versions := make([]*protocol.TopicVersion, 0, 48)
	for range 48 {
		versions = append(versions, &protocol.TopicVersion{
			Topic:   strings.Repeat("t", testSizeTopicByteCount),
			Version: math.MaxUint64,
		})
	}
	cases := []struct {
		name   string
		header *protocol.Envelope
		body   []byte
		// the most its body takes, or 0 where its line bounds the envelope
		bodyByteCount int
		// the most it takes with connect's wrapper, or 0 where its line bounds the body
		wrappedByteCount int
	}{
		{
			name:             "Hello",
			header:           testSizeCallHeader(protocol.MessageType_HELLO),
			body:             testSizeBody(t, testMaxHello()),
			wrappedByteCount: 512,
		},
		{
			name:   "StreamOpen",
			header: testSizeStreamHeader(protocol.MessageType_STREAM_OPEN),
			body: testSizeBody(t, &protocol.StreamOpen{
				Target:    strings.Repeat("t", 128),
				Metadata:  testSizeBytes(1024),
				Ticket:    testSizeBytes(512),
				Window:    math.MaxUint32,
				EarlyData: testSizeBytes(2048),
			}),
			bodyByteCount: 3800,
		},
		{
			name:   "StreamData",
			header: testSizeStreamHeader(protocol.MessageType_STREAM_DATA),
			body: testSizeBody(t, &protocol.StreamData{
				Offset: math.MaxUint64,
				Data:   testSizeBytes(MaxStreamDataByteCount),
			}),
			bodyByteCount: MaxEnvelopeBodyByteCount,
		},
		{
			name:   "PushReset",
			header: testSizeCallHeader(protocol.MessageType_PUSH_RESET),
			body: testSizeBody(t, &protocol.PushReset{
				Epoch:    math.MaxUint64,
				Versions: versions,
				Complete: true,
			}),
			bodyByteCount: MaxEnvelopeBodyByteCount,
		},
		{
			name:   "PushHint",
			header: testSizeCallHeader(protocol.MessageType_PUSH_HINT),
			body: testSizeBody(t, &protocol.PushHint{
				Seq:     math.MaxUint64,
				Topic:   strings.Repeat("t", testSizeTopicByteCount),
				Version: math.MaxUint64,
				Kind:    math.MaxUint32,
				Hint:    testSizeBytes(256),
			}),
			bodyByteCount: 400,
		},
		{
			name:          "StreamAccept",
			header:        testSizeStreamHeader(protocol.MessageType_STREAM_ACCEPT),
			body:          testSizeBody(t, &protocol.StreamAccept{Window: math.MaxUint32}),
			bodyByteCount: 300,
		},
		{
			name:   "StreamReject",
			header: testSizeStreamHeader(protocol.MessageType_STREAM_REJECT),
			body: testSizeBody(t, &protocol.StreamReject{
				Code:         uint32(protocol.StreamRejectCode_SR_QUOTA),
				RetryAfterMs: math.MaxUint32,
			}),
			bodyByteCount: 300,
		},
		{
			name:   "StreamWindow",
			header: testSizeStreamHeader(protocol.MessageType_STREAM_WINDOW),
			body: testSizeBody(t, &protocol.StreamWindow{
				ConsumedOffset: math.MaxUint64,
				MaxOffset:      math.MaxUint64,
			}),
			bodyByteCount: 300,
		},
		{
			name:          "StreamClose",
			header:        testSizeStreamHeader(protocol.MessageType_STREAM_CLOSE),
			body:          testSizeBody(t, &protocol.StreamClose{FinalOffset: math.MaxUint64}),
			bodyByteCount: 300,
		},
		{
			name:   "StreamReset",
			header: testSizeStreamHeader(protocol.MessageType_STREAM_RESET),
			body: testSizeBody(t, &protocol.StreamReset{
				Code:        uint32(protocol.StreamResetCode_RST_IDENTITY),
				FinalOffset: math.MaxUint64,
			}),
			bodyByteCount: 300,
		},
		{
			name:             "Ping",
			header:           testSizeCallHeader(protocol.MessageType_PING),
			wrappedByteCount: 32,
		},
		{
			name:             "Pong",
			header:           testSizeCallHeader(protocol.MessageType_PONG),
			wrappedByteCount: 32,
		},
		{
			name:             "Cancel",
			header:           testSizeCallHeader(protocol.MessageType_CANCEL),
			wrappedByteCount: 32,
		},
	}
	for _, c := range cases {
		if c.bodyByteCount != 0 && c.bodyByteCount < len(c.body) {
			t.Errorf("%s: a body of %d B, over %d", c.name, len(c.body), c.bodyByteCount)
		}
		envelopes, err := chunkBody(c.header, c.body)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if len(envelopes) != 1 {
			t.Errorf("%s: %d envelopes", c.name, len(envelopes))
			continue
		}
		size := testSizesOf(t, envelopes)[0]
		if wrapped := testSizeWrapped(size); c.wrappedByteCount != 0 && c.wrappedByteCount < wrapped {
			t.Errorf("%s: %d B with the wrapper, over %d", c.name, wrapped, c.wrappedByteCount)
		}
	}
}

// §6.5 and §11.14: a search request is one envelope with no chunk header, at a body of exactly 4,016 B,
// timeout_ms 10,000, so it has one length.
func TestSearchRequestRidesOneEnvelopeWithNoChunk(t *testing.T) {
	header := testSizeCallHeader(protocol.MessageType_SEARCH)
	header.Flags = 0
	header.TimeoutMs = 10000
	envelopes, err := chunkBody(header, testSizeBytes(MaxEnvelopeBodyByteCount))
	if err != nil {
		t.Fatal(err)
	}
	if len(envelopes) != 1 || envelopes[0].Chunk != nil {
		t.Fatalf("%d envelopes, chunk %v", len(envelopes), envelopes[0].Chunk)
	}
	testSizesOf(t, envelopes)
}

// §6.5: steps × 16,384 B of reply is 4 × steps envelopes of 4,016 B and a final one of 320 × steps B:
// five at one step.
func TestSearchReplyTakesFourEnvelopesAStepAndAFinal(t *testing.T) {
	for steps := 1; steps <= 4; steps += 1 {
		header := testSizeCallHeader(protocol.MessageType_SEARCH_RESULT)
		header.Flags = EnvelopeFlagResponse
		header.TimeoutMs = 10000
		envelopes, err := chunkBody(header, testSizeBytes(steps*16*1024))
		if err != nil {
			t.Fatal(err)
		}
		if len(envelopes) != 4*steps+1 {
			t.Errorf("%d steps took %d envelopes", steps, len(envelopes))
			continue
		}
		for _, envelope := range envelopes[:4*steps] {
			if len(envelope.Body) != MaxEnvelopeBodyByteCount {
				t.Errorf("%d steps: a chunk of %d B", steps, len(envelope.Body))
			}
		}
		if final := envelopes[4*steps]; len(final.Body) != 320*steps {
			t.Errorf("%d steps: a final chunk of %d B", steps, len(final.Body))
		}
		testSizesOf(t, envelopes)
	}
}

// A stream header is the widest any chunk can have, and the longest body the deepest chunk indexes, so
// this is the worst case chunking can reach: the final chunk's 32 B hash included, each still fits.
func TestWidestChunkFitsAtEveryIndex(t *testing.T) {
	header := testSizeStreamHeader(protocol.MessageType_HEAD_CHECK_PROOF)
	for _, byteCount := range []int{
		MaxReassemblyBodyByteCount,
		MaxReassemblyBodyByteCount - 1,
		MaxEnvelopeBodyByteCount*260 + MaxFinalChunkBodyByteCount,
		MaxEnvelopeBodyByteCount*260 + MaxFinalChunkBodyByteCount + 1,
	} {
		envelopes, err := chunkBody(header, testSizeBytes(byteCount))
		if err != nil {
			t.Fatal(err)
		}
		testSizesOf(t, envelopes)
	}
}

// §6.5: "a body's length fixes its envelope sizes". Two bodies of one length, with different bytes and
// different request ids, must come out as the same sizes in the same order, at every length through
// three cuts, which holds each edge of the layout, and at the lengths the design names past them.
func TestBodyLengthAloneFixesEnvelopeSizes(t *testing.T) {
	byteCounts := []int{16 * 1024, 64 * 1024, 256 * 1024, MaxReassemblyBodyByteCount}
	for byteCount := range 3*MaxEnvelopeBodyByteCount + 1 {
		byteCounts = append(byteCounts, byteCount)
	}
	for _, byteCount := range byteCounts {
		first := testSizeCallHeader(protocol.MessageType_HEAD_CHECK_PROOF)
		first.RequestId = 1
		second := testSizeCallHeader(protocol.MessageType_HEAD_CHECK_PROOF)
		second.RequestId = math.MaxUint64
		firstEnvelopes, err := chunkBody(first, make([]byte, byteCount))
		if err != nil {
			t.Fatal(err)
		}
		secondEnvelopes, err := chunkBody(second, testSizeBytes(byteCount))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(testSizesOf(t, firstEnvelopes), testSizesOf(t, secondEnvelopes)) {
			t.Errorf("%d B has two size sequences", byteCount)
		}
	}
}

// An envelope of exactly byteCount on the wire, whatever its fields: unknown bytes make up the length,
// as a later version's field would. byteCount is past what a bare 4,016 B body takes.
func testEnvelopeOfSize(t *testing.T, byteCount int) *protocol.Envelope {
	t.Helper()
	envelope := &protocol.Envelope{Body: testSizeBytes(MaxEnvelopeBodyByteCount)}
	padding := byteCount - proto.Size(envelope)
	// a field number past any the message declares, holding a length that fits one byte's prefix
	unknown := protowire.AppendTag(nil, 9999, protowire.BytesType)
	unknown = protowire.AppendVarint(unknown, uint64(padding-len(unknown)-1))
	unknown = append(unknown, make([]byte, padding-len(unknown))...)
	envelope.ProtoReflect().SetUnknown(unknown)
	if size := proto.Size(envelope); size != byteCount {
		t.Fatalf("built %d B, want %d", size, byteCount)
	}
	return envelope
}

// §6.5's enforcement at its edge, both ways: exactly 4,080 B passes, one more does not.
func TestCodecHoldsTheEnvelopeLimit(t *testing.T) {
	codec := envelopeCodec{}
	fits := testEnvelopeOfSize(t, MaxEnvelopeByteCount)
	encoded, err := codec.MarshalAppend(nil, fits)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != MaxEnvelopeByteCount {
		t.Fatalf("encoded %d B", len(encoded))
	}
	decoded := &protocol.Envelope{}
	if err := codec.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(decoded, fits) {
		t.Error("the envelope changed")
	}

	over := testEnvelopeOfSize(t, MaxEnvelopeByteCount+1)
	prefix := []byte("prefix")
	refused, err := codec.MarshalAppend(prefix, over)
	if !errors.Is(err, errEnvelopeTooLarge) {
		t.Fatalf("err %v", err)
	}
	if !bytes.Equal(refused, prefix) {
		t.Errorf("a refusal left %d B", len(refused))
	}
	if code, ok := envelopeErrorCode(err); !ok || code != protocol.ErrorCode_ERR_TOO_LARGE {
		t.Errorf("it answers %s", code)
	}
	encodedOver, err := proto.Marshal(over)
	if err != nil {
		t.Fatal(err)
	}
	if err := codec.Unmarshal(encodedOver, &protocol.Envelope{}); !errors.Is(err, errEnvelopeTooLarge) {
		t.Errorf("err %v", err)
	}
}

// §6.5 bounds the body apart from the envelope: one under 4,080 B on the wire with a body past 4,016 B is
// still refused, by both sides, so a sender that skipped chunkBody cannot reach a peer.
func TestCodecHoldsTheBodyLimit(t *testing.T) {
	codec := envelopeCodec{}
	over := &protocol.Envelope{Body: testSizeBytes(MaxEnvelopeBodyByteCount + 1)}
	if _, err := codec.MarshalAppend(nil, over); !errors.Is(err, errEnvelopeTooLarge) {
		t.Fatalf("err %v", err)
	}
	encoded, err := proto.Marshal(over)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaxEnvelopeByteCount {
		t.Fatalf("%d B proves nothing about the body", len(encoded))
	}
	if err := codec.Unmarshal(encoded, &protocol.Envelope{}); !errors.Is(err, errEnvelopeTooLarge) {
		t.Errorf("err %v", err)
	}
	fits := &protocol.Envelope{Body: testSizeBytes(MaxEnvelopeBodyByteCount)}
	if _, err := codec.MarshalAppend(nil, fits); err != nil {
		t.Errorf("err %v", err)
	}
}

// Malformed bytes fail as proto.Unmarshal fails them, which is no size refusal and takes no code.
func TestCodecPassesOnMalformedBytes(t *testing.T) {
	err := envelopeCodec{}.Unmarshal([]byte{0xFF}, &protocol.Envelope{})
	if err == nil || errors.Is(err, errEnvelopeTooLarge) {
		t.Errorf("err %v", err)
	}
}

// §6.5 through connect's own send path, where a sender meets the refusal: it comes back as it left the
// codec, and nothing is sent.
func TestSendRefusesTooLargeThroughConnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := connect.NewClient(ctx, connect.NewId(), connect.NewNoContractClientOob(), connect.DefaultClientSettings())
	defer client.Cancel()
	unregister, err := connect.RegisterSubprotocol(client, SubprotocolId, envelopeCodec{}, func(
		source connect.TransferPath,
		envelope *protocol.Envelope,
		peer connect.Peer,
	) {
	})
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()

	sent, err := connect.SendSubprotocolWithTimeout(
		client,
		SubprotocolId,
		&protocol.Envelope{Body: testSizeBytes(MaxEnvelopeBodyByteCount + 1)},
		connect.NewId(),
		func(err error) {},
		0,
	)
	if sent || !errors.Is(err, errEnvelopeTooLarge) {
		t.Fatalf("sent %v, err %v", sent, err)
	}
	if stats := client.SubprotocolStats(); stats.Sent != 0 {
		t.Errorf("stats %+v", stats)
	}
}
