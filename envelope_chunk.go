// Cutting a body into envelopes (§6.5), on every leg. A body's length fixes its envelopes: where it is
// cut, how many there are and, given one header, how long each is. envelope_reassembly.go holds a peer
// to the same layout, through these same functions.

package sidecar

import (
	"crypto/sha256"

	"github.com/urnetwork/sidecar/protocol"
)

// How a chunked body of this length is cut: fullCount chunks of MaxEnvelopeBodyByteCount, then the
// rest, then an empty final chunk if the rest is too long to sit beside the hash. A rest of zero is
// itself the empty final chunk, since a full chunk has no room for the hash either.
func chunkLayout(totalByteCount int64) (fullCount int64, restByteCount int64, chunkCount int64) {
	fullCount = totalByteCount / MaxEnvelopeBodyByteCount
	restByteCount = totalByteCount % MaxEnvelopeBodyByteCount
	chunkCount = fullCount + 1
	if MaxFinalChunkBodyByteCount < restByteCount {
		chunkCount += 1
	}
	return fullCount, restByteCount, chunkCount
}

// What the chunk at index carries of a chunked body of this length.
func chunkByteCount(totalByteCount int64, index int64) int64 {
	fullCount, restByteCount, _ := chunkLayout(totalByteCount)
	switch {
	case index < fullCount:
		return MaxEnvelopeBodyByteCount
	case index == fullCount:
		return restByteCount
	}
	return 0
}

// The envelopes that carry body, in order. Each repeats header's version, type, request_id, flags,
// stream_id and timeout_ms, whatever header's own chunk and body hold. A body up to
// MaxEnvelopeBodyByteCount has no Chunk. A longer one is cut by chunkLayout: MORE is set on every chunk
// but the final (reading 4), and the final chunk alone carries the whole body's SHA-256.
//
// Refuses a body past MaxReassemblyBodyByteCount with errEnvelopeTooLarge, since no peer would take it.
// A peer's own lower limit is its Hello's, and the caller's to check. The envelopes borrow body, so it
// must not change until they are sent. Safe for concurrent use.
func chunkBody(header *protocol.Envelope, body []byte) ([]*protocol.Envelope, error) {
	if MaxReassemblyBodyByteCount < len(body) {
		return nil, errEnvelopeTooLarge
	}
	envelopeFor := func(flags uint32, chunk *protocol.Chunk, chunkBytes []byte) *protocol.Envelope {
		return &protocol.Envelope{
			Version:   header.Version,
			Type:      header.Type,
			RequestId: header.RequestId,
			Flags:     flags,
			StreamId:  header.StreamId,
			TimeoutMs: header.TimeoutMs,
			Chunk:     chunk,
			Body:      chunkBytes,
		}
	}
	flags := header.Flags &^ EnvelopeFlagMore
	if len(body) <= MaxEnvelopeBodyByteCount {
		return []*protocol.Envelope{envelopeFor(flags, nil, body)}, nil
	}

	totalByteCount := int64(len(body))
	_, _, chunkCount := chunkLayout(totalByteCount)
	hash := sha256.Sum256(body)
	envelopes := make([]*protocol.Envelope, 0, chunkCount)
	offset := int64(0)
	for index := range chunkCount {
		chunk := &protocol.Chunk{
			Index:          uint32(index),
			Count:          uint32(chunkCount),
			TotalByteCount: uint32(totalByteCount),
		}
		chunkFlags := flags | EnvelopeFlagMore
		if index == chunkCount-1 {
			chunk.Sha256 = hash[:]
			chunkFlags = flags
		}
		end := offset + chunkByteCount(totalByteCount, index)
		envelopes = append(envelopes, envelopeFor(chunkFlags, chunk, body[offset:end]))
		offset = end
	}
	return envelopes, nil
}
