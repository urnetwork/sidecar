// Large files (§11.7's large files row): a file past 8 MiB is 4 MiB chunk records at fixed offsets, rewritten only
// where touched. Fixed sizes leak only the file's padded size, where content-defined chunking's sizes would leak
// content and its keyed variants were broken in 2025 (ePrint 2025/558). A version is at most 2 GiB, v0's cap.
//
// A chunk is kept, its previous locator cited, when the previous version was chunks too, its chunk at the same index
// holds equal bytes, and no checkpoint rule asks for the whole file again (a REMOVE generation past the chain's key,
// or a forced rewrite). The comparison reads both versions in pieces, so neither is held whole (R-EVS-14). A kept
// chunk's record keeps the header and file id it was written with; the frames' AAD binds the file id, which a path
// keeps for life (§11.7's sealed fields), so it opens in the new version as in the old.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.7's large files: past 8 MiB a file is 4 MiB chunks, and no file passes 2 GiB.
const (
	EvsChunkThresholdByteCount = 8 * 1024 * 1024
	EvsChunkByteCount          = 4 * 1024 * 1024
)

// The piece a chunk comparison reads of each version at once.
const evsChunkCompareByteCount = 64 * 1024

// Whether a file of size bytes is chunks: past 8 MiB, or too large for its one record to fit a segment beside the
// segment's header and key block, which a file just under 8 MiB is.
func EvsChunked(size uint64) bool {
	return EvsChunkThresholdByteCount < size || EvsSegmentMaxByteCount < evsSegmentKeyedRecordsOffset+EvsRecordByteCount(size)
}

// A file past v0's 2 GiB cap.
var ErrEvsFileTooLarge = errors.New("evs: a file past 2 GiB")

// One chunk of a chunked version.
type EvsChunkPlan struct {
	Index  int
	Offset int64
	Length int64
	// The previous version's locator of the same chunk, cited as it stands; nil for a chunk written anew.
	Kept *protocol.EvsLocator
}

// The chunks of a version of size bytes: 4 MiB each at fixed offsets, the last the remainder.
func evsChunkBounds(size int64) []*EvsChunkPlan {
	chunks := []*EvsChunkPlan{}
	for offset := int64(0); offset < size; offset += EvsChunkByteCount {
		chunks = append(chunks, &EvsChunkPlan{Index: len(chunks), Offset: offset, Length: min(EvsChunkByteCount, size-offset)})
	}
	return chunks
}

// Plans content as chunks. previous and previousChain are the previous version's content and chain when it was
// chunks, else nil; rewriteAll writes every chunk anew.
func EvsPlanChunks(content EvsGitDeltaSource, previous EvsGitDeltaSource, previousChain []*protocol.EvsLocator, rewriteAll bool) ([]*EvsChunkPlan, error) {
	if EvsFileMaxByteCount < content.Size() {
		return nil, fmt.Errorf("%w: %d bytes", ErrEvsFileTooLarge, content.Size())
	}
	chunks := evsChunkBounds(content.Size())
	if previous == nil || rewriteAll {
		return chunks, nil
	}
	previousChunks := evsChunkBounds(previous.Size())
	if len(previousChunks) != len(previousChain) {
		// a chain that is not one locator a chunk was not chunked as this plans: write every chunk
		return chunks, nil
	}
	left := make([]byte, evsChunkCompareByteCount)
	right := make([]byte, evsChunkCompareByteCount)
	for _, chunk := range chunks {
		if len(previousChunks) <= chunk.Index || previousChunks[chunk.Index].Length != chunk.Length {
			continue
		}
		equal, err := evsRangesEqual(content, previous, chunk.Offset, chunk.Length, left, right)
		if err != nil {
			return nil, err
		}
		if equal {
			chunk.Kept = previousChain[chunk.Index]
		}
	}
	return chunks, nil
}

// Whether a and b hold equal bytes over [offset, offset+length), read a piece at a time into the buffers given.
func evsRangesEqual(a io.ReaderAt, b io.ReaderAt, offset int64, length int64, left []byte, right []byte) (bool, error) {
	for at := offset; at < offset+length; {
		n := min(int64(len(left)), offset+length-at)
		if err := evsReadFull(a, left[:n], at); err != nil {
			return false, err
		}
		if err := evsReadFull(b, right[:n], at); err != nil {
			return false, err
		}
		if !bytes.Equal(left[:n], right[:n]) {
			return false, nil
		}
		at += n
	}
	return true, nil
}

// Reads exactly len(buffer) bytes at offset.
func evsReadFull(source io.ReaderAt, buffer []byte, offset int64) error {
	n, err := source.ReadAt(buffer, offset)
	if n == len(buffer) {
		return nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		return fmt.Errorf("evs: a source shorter than it says")
	}
	return err
}
