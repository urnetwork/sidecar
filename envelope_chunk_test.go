// §22.5's chunk limits: where a body is cut, what each chunk repeats, and what only the final one holds.
// Budget rows and the wire's lengths are envelope_size_test.go's.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A request's header, every field set to something a dropped field would change.
func testEnvelopeHeader() *protocol.Envelope {
	return &protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(protocol.MessageType_HEAD_CHECK_PROOF),
		RequestId: 0x0102030405060708,
		Flags:     EnvelopeFlagNoReply,
		StreamId:  9,
		TimeoutMs: 15000,
	}
}

// byteCount bytes in which every 4,016 B cut lands on a different value, so a chunk out of place shows.
func testEnvelopeBody(byteCount int) []byte {
	body := make([]byte, byteCount)
	for i := range body {
		body[i] = byte(i*31 + i/MaxEnvelopeBodyByteCount)
	}
	return body
}

// Cuts body, failing the test if it cannot be.
func testChunks(t testing.TB, header *protocol.Envelope, body []byte) []*protocol.Envelope {
	t.Helper()
	envelopes, err := chunkBody(header, body)
	if err != nil {
		t.Fatalf("%d B: %v", len(body), err)
	}
	return envelopes
}

// §6.4's and §6.5's numbers as written.
func TestEnvelopeConstantsMatchDesign(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{name: "SubprotocolId", got: SubprotocolId, want: 21842},
		{name: "SubprotocolHeldLastId", got: SubprotocolHeldLastId, want: 21851},
		{name: "WireVersionMajor", got: WireVersionMajor, want: 1},
		{name: "MaxEnvelopeByteCount", got: MaxEnvelopeByteCount, want: 4080},
		{name: "MaxEnvelopeBodyByteCount", got: MaxEnvelopeBodyByteCount, want: 4016},
		{name: "MaxFinalChunkBodyByteCount", got: MaxFinalChunkBodyByteCount, want: 3980},
		{name: "MaxStreamDataByteCount", got: MaxStreamDataByteCount, want: 4000},
		{name: "MaxCallTimeout", got: int(MaxCallTimeout.Seconds()), want: 55},
		{name: "MaxReassemblyBodyByteCount", got: MaxReassemblyBodyByteCount, want: 1048576},
		{name: "EnvelopeFlagResponse", got: int(EnvelopeFlagResponse), want: 1},
		{name: "EnvelopeFlagError", got: int(EnvelopeFlagError), want: 2},
		{name: "EnvelopeFlagMore", got: int(EnvelopeFlagMore), want: 4},
		{name: "EnvelopeFlagNoReply", got: int(EnvelopeFlagNoReply), want: 8},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s is %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestBodyUpToTheLimitHasNoChunk(t *testing.T) {
	for _, byteCount := range []int{0, 1, MaxFinalChunkBodyByteCount + 1, MaxEnvelopeBodyByteCount} {
		body := testEnvelopeBody(byteCount)
		envelopes := testChunks(t, testEnvelopeHeader(), body)
		if len(envelopes) != 1 {
			t.Errorf("%d B took %d envelopes", byteCount, len(envelopes))
			continue
		}
		if envelopes[0].Chunk != nil {
			t.Errorf("%d B has a chunk", byteCount)
		}
		if envelopes[0].Flags != EnvelopeFlagNoReply {
			t.Errorf("%d B has flags %d", byteCount, envelopes[0].Flags)
		}
		if !bytes.Equal(envelopes[0].Body, body) {
			t.Errorf("%d B changed", byteCount)
		}
	}
}

// §6.5's cuts at each edge: a rest of 3,980 B sits beside the hash and 3,981 B does not, a body on a
// multiple of 4,016 B ends in the empty final chunk that holds its hash, and one past it does not need one.
func TestBodyLengthFixesItsCuts(t *testing.T) {
	full := MaxEnvelopeBodyByteCount
	cases := []struct {
		byteCount int
		want      []int
	}{
		{byteCount: full + 1, want: []int{full, 1}},
		{byteCount: full + MaxFinalChunkBodyByteCount, want: []int{full, MaxFinalChunkBodyByteCount}},
		{byteCount: full + MaxFinalChunkBodyByteCount + 1, want: []int{full, MaxFinalChunkBodyByteCount + 1, 0}},
		{byteCount: 2*full - 1, want: []int{full, full - 1, 0}},
		{byteCount: 2 * full, want: []int{full, full, 0}},
		{byteCount: 2*full + 1, want: []int{full, full, 1}},
		{byteCount: 16 * 1024, want: []int{full, full, full, full, 320}},
	}
	for _, c := range cases {
		got := []int{}
		for _, envelope := range testChunks(t, testEnvelopeHeader(), testEnvelopeBody(c.byteCount)) {
			got = append(got, len(envelope.Body))
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%d B cut as %v, want %v", c.byteCount, got, c.want)
		}
	}
}

// What every chunk of every layout carries, and that the pieces make up the body in order.
func TestChunksRebuildTheirBodyAndCountThemselves(t *testing.T) {
	for _, byteCount := range []int{
		MaxEnvelopeBodyByteCount + 1,
		MaxEnvelopeBodyByteCount + MaxFinalChunkBodyByteCount + 1,
		2 * MaxEnvelopeBodyByteCount,
		64 * 1024,
		MaxReassemblyBodyByteCount,
	} {
		body := testEnvelopeBody(byteCount)
		envelopes := testChunks(t, testEnvelopeHeader(), body)
		rebuilt := []byte{}
		for i, envelope := range envelopes {
			chunk := envelope.Chunk
			if chunk == nil {
				t.Fatalf("%d B: chunk %d has no header", byteCount, i)
			}
			if int(chunk.Index) != i || int(chunk.Count) != len(envelopes) || int(chunk.TotalByteCount) != byteCount {
				t.Errorf("%d B: chunk %d says %d of %d, %d B", byteCount, i, chunk.Index, chunk.Count, chunk.TotalByteCount)
			}
			rebuilt = append(rebuilt, envelope.Body...)
		}
		if !bytes.Equal(rebuilt, body) {
			t.Errorf("%d B did not come back", byteCount)
		}
	}
}

// Reading 4: MORE on every chunk but the final, so a receiver reads the end from the flags as well as
// the count, and the rest of the header on all of them.
func TestEveryChunkRepeatsItsHeader(t *testing.T) {
	header := testEnvelopeHeader()
	envelopes := testChunks(t, header, testEnvelopeBody(3*MaxEnvelopeBodyByteCount))
	for i, envelope := range envelopes {
		wantFlags := header.Flags | EnvelopeFlagMore
		if i == len(envelopes)-1 {
			wantFlags = header.Flags
		}
		if envelope.Flags != wantFlags {
			t.Errorf("chunk %d has flags %d, want %d", i, envelope.Flags, wantFlags)
		}
		if envelope.Version != header.Version || envelope.Type != header.Type || envelope.RequestId != header.RequestId ||
			envelope.StreamId != header.StreamId || envelope.TimeoutMs != header.TimeoutMs {
			t.Errorf("chunk %d differs from its header: %v", i, envelope)
		}
	}
}

func TestOnlyTheFinalChunkCarriesTheHash(t *testing.T) {
	body := testEnvelopeBody(2*MaxEnvelopeBodyByteCount + 7)
	hash := sha256.Sum256(body)
	envelopes := testChunks(t, testEnvelopeHeader(), body)
	for i, envelope := range envelopes {
		if i == len(envelopes)-1 {
			if !bytes.Equal(envelope.Chunk.Sha256, hash[:]) {
				t.Errorf("the final chunk holds %x", envelope.Chunk.Sha256)
			}
		} else if len(envelope.Chunk.Sha256) != 0 {
			t.Errorf("chunk %d holds a hash", i)
		}
	}
}

// The header gives what repeats and nothing else: not a stale chunk or body, and not a MORE, which is
// this function's to set.
func TestHeaderBringsOnlyWhatRepeats(t *testing.T) {
	header := testEnvelopeHeader()
	header.Flags |= EnvelopeFlagMore
	header.Chunk = &protocol.Chunk{Index: 7, Count: 8}
	header.Body = []byte("stale")
	before := proto.Clone(header)

	plain := testChunks(t, header, []byte("body"))
	if plain[0].Flags != EnvelopeFlagNoReply || plain[0].Chunk != nil || string(plain[0].Body) != "body" {
		t.Errorf("a plain envelope took %v", plain[0])
	}
	chunked := testChunks(t, header, testEnvelopeBody(MaxEnvelopeBodyByteCount+1))
	if final := chunked[len(chunked)-1]; final.Flags != EnvelopeFlagNoReply {
		t.Errorf("the final chunk has flags %d", final.Flags)
	}
	if chunked[0].Chunk.Index != 0 || chunked[0].Chunk.Count != 2 {
		t.Errorf("the first chunk took %v", chunked[0].Chunk)
	}
	if !proto.Equal(header, before) {
		t.Errorf("the header changed: %v", header)
	}
}

func TestBodyPastTheProtocolMaximumIsTooLarge(t *testing.T) {
	testChunks(t, testEnvelopeHeader(), testEnvelopeBody(MaxReassemblyBodyByteCount))
	_, err := chunkBody(testEnvelopeHeader(), testEnvelopeBody(MaxReassemblyBodyByteCount+1))
	if !errors.Is(err, errEnvelopeTooLarge) {
		t.Fatalf("err %v", err)
	}
	if code, ok := envelopeErrorCode(err); !ok || code != protocol.ErrorCode_ERR_TOO_LARGE {
		t.Errorf("it answers %s", code)
	}
}

// A declared length no reassembler takes still has a layout, so a first chunk stating one is a cap's to
// refuse and not a panic's.
func TestLayoutHoldsAtTheLargestDeclaredLength(t *testing.T) {
	fullCount, restByteCount, chunkCount := chunkLayout(math.MaxUint32)
	if fullCount*MaxEnvelopeBodyByteCount+restByteCount != math.MaxUint32 {
		t.Errorf("%d full chunks and %d B", fullCount, restByteCount)
	}
	if math.MaxUint32 < chunkCount {
		t.Errorf("%d chunks pass a uint32", chunkCount)
	}
	if byteCount := chunkByteCount(math.MaxUint32, chunkCount); byteCount != 0 {
		t.Errorf("past the last chunk there are %d B", byteCount)
	}
}
