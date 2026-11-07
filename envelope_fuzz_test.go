//go:build !sidecar_http

// §22.6's targets for what crosses the envelope: the envelope itself, chunks and their reassembly, and
// every sidecar/protocol body as a peer receives it. testdata/fuzz holds the seeds §22.6 names: reordered,
// repeated, unknown, packed and unpacked fields and non-minimal varints.
//
// protocol/body_test.go's FuzzBody takes each body alone. FuzzProtocolBody here takes it through the
// envelope path as well, because signatures verify over the bytes as received (§22.6), so those bytes
// must come out of the path as they went in, however oddly they were encoded.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/urnetwork/sidecar/protocol"
)

// §22.6: what the codec decodes equals proto.Unmarshal's, its encoding equals a deterministic marshal,
// and that encoding decodes back equal, for everything it accepts. What it refuses is only what §6.5
// refuses, or what protobuf does.
func FuzzEnvelope(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		codec := envelopeCodec{}
		decoded := &protocol.Envelope{}
		err := codec.Unmarshal(encoded, decoded)
		reference := &protocol.Envelope{}
		referenceErr := proto.Unmarshal(encoded, reference)
		switch {
		case MaxEnvelopeByteCount < len(encoded), referenceErr == nil && MaxEnvelopeBodyByteCount < len(reference.Body):
			if !errors.Is(err, errEnvelopeTooLarge) {
				t.Fatalf("%d B, body %d B: err %v", len(encoded), len(reference.Body), err)
			}
			return
		case referenceErr != nil:
			if err == nil {
				t.Fatalf("took what protobuf refuses: %v", referenceErr)
			}
			return
		case err != nil:
			t.Fatalf("refused what fits: %v", err)
		}
		if !proto.Equal(decoded, reference) {
			t.Fatal("decoded differently from proto.Unmarshal")
		}

		canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		marshalled, err := codec.MarshalAppend(nil, decoded)
		if MaxEnvelopeByteCount < len(canonical) {
			if !errors.Is(err, errEnvelopeTooLarge) {
				t.Fatalf("%d B: err %v", len(canonical), err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(marshalled, canonical) {
			t.Fatal("encoded differently from a deterministic marshal")
		}
		if size := codec.Size(decoded); size != len(marshalled) {
			t.Fatalf("sized %d B, wrote %d", size, len(marshalled))
		}
		again := &protocol.Envelope{}
		if err := codec.Unmarshal(marshalled, again); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(again, decoded) {
			t.Fatal("did not decode back equal")
		}
	})
}

// What a script's byte does to the chunks of one body, in FuzzChunkReassembly.
const (
	testScriptDeliver = iota
	testScriptChangeType
	testScriptFlipMore
	testScriptChangeTotal
	testScriptChangeCount
	testScriptChangeIndex
	testScriptCorruptBody
	testScriptTruncateBody
	testScriptClearHash
	testScriptCorruptHash
	testScriptRepeat
	testScriptSkip
	testScriptRestart
	testScriptIdle
	testScriptTick
	testScriptSwitchPeer
	testScriptOpCount
)

// Caps small enough for a script to reach each of them, chunked bodies of a few envelopes filling them.
func testFuzzReassemblySettings() *SidecarProtocolSettings {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyMaxBodyByteCount = 64 * 1024
	settings.ReassemblyPeerCount = 2
	settings.ReassemblyPeerByteCount = 96 * 1024
	settings.ReassemblyProcessByteCount = 128 * 1024
	return settings
}

// Fails unless every cap holds at this moment.
func testRequireCapsHold(t *testing.T, settings *SidecarProtocolSettings, reassembly *testReassembly) {
	t.Helper()
	if held := reassembly.heldByteCount(); settings.ReassemblyProcessByteCount < held {
		t.Fatalf("the process holds %d B", held)
	}
	reassembly.reassembler.stateLock.Lock()
	defer reassembly.reassembler.stateLock.Unlock()
	for source, peer := range reassembly.reassembler.peers {
		if settings.ReassemblyPeerCount < len(peer.groups) || settings.ReassemblyPeerByteCount < peer.byteCount {
			t.Fatalf("%s holds %d groups, %d B", source, len(peer.groups), peer.byteCount)
		}
	}
}

// §22.6 for chunks: a script reorders, repeats, loses and tampers with one body's chunks, across two
// peers and the clock. Whatever it does, memory stays inside the caps, only the true body ever completes,
// offer answers only as it says it does, and every reservation comes back. seed fills the body, and the
// script's first two bytes set its length, so a small input still reaches many chunks.
func FuzzChunkReassembly(f *testing.F) {
	f.Add([]byte("body"), []byte{0x20, 0x00, testScriptDeliver, testScriptDeliver, testScriptDeliver})
	f.Fuzz(func(t *testing.T, seed []byte, script []byte) {
		if len(seed) == 0 || len(script) < 2 {
			return
		}
		body := make([]byte, int(binary.BigEndian.Uint16(script))*2)
		for i := range body {
			body[i] = seed[i%len(seed)]
		}
		settings := testFuzzReassemblySettings()
		reassembly := newTestReassembly(t, settings, 128*1024*1024)
		envelopes := testChunks(t, testEnvelopeHeader(), body)

		source := testPeerA
		next := 0
		offer := func(envelope *protocol.Envelope) {
			whole, err := reassembly.reassembler.offer(source, envelope)
			switch {
			case err == nil && whole == nil:
			case err == nil:
				if !bytes.Equal(whole.Body, body) {
					t.Fatalf("a body of %d B completed as %d B of something else", len(body), len(whole.Body))
				}
			case errors.Is(err, errReassemblyDropped), errors.Is(err, errReassemblyExhausted):
			default:
				t.Fatalf("err %v", err)
			}
			testRequireCapsHold(t, settings, reassembly)
		}
		// the next chunk, changed by mutate; past the last it wraps, as a resend would
		deliver := func(mutate func(envelope *protocol.Envelope)) {
			envelope := envelopes[next%len(envelopes)]
			if mutate != nil {
				envelope = proto.Clone(envelope).(*protocol.Envelope)
				if envelope.Chunk == nil {
					envelope.Chunk = &protocol.Chunk{}
				}
				mutate(envelope)
			}
			next += 1
			offer(envelope)
		}
		for _, step := range script[2:] {
			switch step % testScriptOpCount {
			case testScriptDeliver:
				deliver(nil)
			case testScriptChangeType:
				deliver(func(envelope *protocol.Envelope) { envelope.Type += 1 })
			case testScriptFlipMore:
				deliver(func(envelope *protocol.Envelope) { envelope.Flags ^= EnvelopeFlagMore })
			case testScriptChangeTotal:
				deliver(func(envelope *protocol.Envelope) { envelope.Chunk.TotalByteCount += 1 })
			case testScriptChangeCount:
				deliver(func(envelope *protocol.Envelope) { envelope.Chunk.Count += 1 })
			case testScriptChangeIndex:
				deliver(func(envelope *protocol.Envelope) { envelope.Chunk.Index += 1 })
			case testScriptCorruptBody:
				deliver(func(envelope *protocol.Envelope) {
					if len(envelope.Body) != 0 {
						envelope.Body[0] ^= 1
					}
				})
			case testScriptTruncateBody:
				deliver(func(envelope *protocol.Envelope) {
					if len(envelope.Body) != 0 {
						envelope.Body = envelope.Body[:len(envelope.Body)-1]
					}
				})
			case testScriptClearHash:
				deliver(func(envelope *protocol.Envelope) { envelope.Chunk.Sha256 = nil })
			case testScriptCorruptHash:
				deliver(func(envelope *protocol.Envelope) {
					corrupted := make([]byte, sha256.Size)
					copy(corrupted, envelope.Chunk.Sha256)
					corrupted[0] ^= 1
					envelope.Chunk.Sha256 = corrupted
				})
			case testScriptRepeat:
				next = max(next-1, 0)
				deliver(nil)
			case testScriptSkip:
				next += 1
			case testScriptRestart:
				next = 0
			case testScriptIdle:
				reassembly.clock.Advance(settings.ReassemblyIdleTimeout)
				reassembly.reassembler.expire()
			case testScriptTick:
				reassembly.clock.Advance(settings.ReassemblyIdleTimeout / 8)
			case testScriptSwitchPeer:
				if source == testPeerA {
					source = testPeerB
				} else {
					source = testPeerA
				}
				next = 0
			}
		}

		reassembly.clock.Advance(settings.ReassemblyIdleTimeout)
		reassembly.reassembler.expire()
		reassembly.requireEmpty(t)
	})
}

// Every message this binary registers in sidecar's proto package, sorted, so a new one joins by being
// declared.
func testProtocolBodyTypes(t testing.TB) []protoreflect.MessageType {
	types := []protoreflect.MessageType{}
	protoregistry.GlobalTypes.RangeMessages(func(messageType protoreflect.MessageType) bool {
		descriptor := messageType.Descriptor()
		if descriptor.ParentFile().Package() == "urnetwork.sidecar" && !descriptor.IsMapEntry() {
			types = append(types, messageType)
		}
		return true
	})
	slices.SortFunc(types, func(a protoreflect.MessageType, b protoreflect.MessageType) int {
		return cmp.Compare(a.Descriptor().FullName(), b.Descriptor().FullName())
	})
	// the floor keeps a filter that matched nothing from passing every case
	if len(types) < 200 {
		t.Fatalf("found %d message types", len(types))
	}
	return types
}

// §22.6 for every body, as a peer gets one: through chunkBody, the codec and the reassembler. The bytes
// must come out as they went in, since a signature covers them and never a re-marshal. Then what decodes
// equals proto.Unmarshal's of the bytes sent, and its deterministic encoding decodes back equal and
// settles. name picks the message, and a mutated name still lands on one.
func FuzzProtocolBody(f *testing.F) {
	types := testProtocolBodyTypes(f)
	typesByName := map[string]protoreflect.MessageType{}
	for _, messageType := range types {
		name := string(messageType.Descriptor().Name())
		typesByName[name] = messageType
		f.Add(name, []byte{})
	}

	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyMaxBodyByteCount = MaxReassemblyBodyByteCount
	budget := NewSubprotocolBudget(settings, 128*1024*1024)
	reassembler := newReassembler(context.Background(), settings, budget, newTestEnvelopeClock(), nil)
	f.Cleanup(reassembler.close)

	f.Fuzz(func(t *testing.T, name string, body []byte) {
		if MaxReassemblyBodyByteCount < len(body) {
			return
		}
		messageType := typesByName[name]
		if messageType == nil {
			messageType = types[crc32.ChecksumIEEE([]byte(name))%uint32(len(types))]
		}

		codec := envelopeCodec{}
		var received *protocol.Envelope
		for _, envelope := range testChunks(t, testEnvelopeHeader(), body) {
			encoded, err := codec.MarshalAppend(nil, envelope)
			if err != nil {
				t.Fatalf("%d B: %v", len(body), err)
			}
			decoded := &protocol.Envelope{}
			if err := codec.Unmarshal(encoded, decoded); err != nil {
				t.Fatalf("%d B: %v", len(body), err)
			}
			if received, err = reassembler.offer(testPeerA, decoded); err != nil {
				t.Fatalf("%d B: %v", len(body), err)
			}
		}
		if received == nil {
			t.Fatalf("%d B never completed", len(body))
		}
		if !bytes.Equal(received.Body, body) {
			t.Fatalf("%d B changed on the way", len(body))
		}

		decoded := messageType.New().Interface()
		err := proto.Unmarshal(received.Body, decoded)
		reference := messageType.New().Interface()
		referenceErr := proto.Unmarshal(body, reference)
		if (err == nil) != (referenceErr == nil) {
			t.Fatalf("%s: err %v, against %v", messageType.Descriptor().Name(), err, referenceErr)
		}
		if err != nil {
			return
		}
		if !proto.Equal(decoded, reference) {
			t.Fatalf("%s decoded differently from proto.Unmarshal", messageType.Descriptor().Name())
		}
		deterministic := proto.MarshalOptions{Deterministic: true}
		canonical, err := deterministic.Marshal(decoded)
		if err != nil {
			t.Fatalf("%s: %v", messageType.Descriptor().Name(), err)
		}
		again := messageType.New().Interface()
		if err := proto.Unmarshal(canonical, again); err != nil {
			t.Fatalf("%s: its own encoding does not decode: %v", messageType.Descriptor().Name(), err)
		}
		if !proto.Equal(again, decoded) {
			t.Fatalf("%s changed when re-encoded", messageType.Descriptor().Name())
		}
		settled, err := deterministic.Marshal(again)
		if err != nil {
			t.Fatalf("%s: %v", messageType.Descriptor().Name(), err)
		}
		if !bytes.Equal(settled, canonical) {
			t.Fatalf("%s has two canonical forms", messageType.Descriptor().Name())
		}
	})
}
