//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's transcript row: transcript_path, the harness's JSONL, tailed at Stop, SubagentStop, PreCompact and
// SessionEnd and every Ingest.TranscriptTailInterval while the run lives. The tail is line-framed: only whole lines
// are taken, from the byte after the last one read, so a secret never splits across two reads and the redactor sees
// each line whole. A line over PayloadByteCount is cut there, truncated, and the rest of it skipped, a truncation
// gap. A file shorter than the offset was rewritten: the tail starts over and counts a missed_event, since what
// stood before is unknown. Cursor's null path, or a path that cannot be opened, is a gap once per run. The offset
// and next line number persist in the run's ingest state, so a restart resumes where it left.

package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Tails the run's transcript now, appending one transcript entry per read of up to PayloadByteCount of whole lines,
// until no whole line remains. The run's lock is held.
func (self *Ingest) tailTranscriptWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor) {
	state := run.state
	if state.TranscriptPath == "" {
		if !state.TranscriptGapped {
			state.TranscriptGapped = true
			run.dirty = true
			self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		}
		return
	}
	file, err := os.Open(state.TranscriptPath)
	if err != nil {
		if !state.TranscriptGapped {
			state.TranscriptGapped = true
			run.dirty = true
			self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		}
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return
	}
	if info.Size() < state.TranscriptAt {
		// rewritten under us: what stood before the rewrite is gone
		state.TranscriptAt = 0
		state.TranscriptLine = 1
		run.dirty = true
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
	}
	if state.TranscriptLine == 0 {
		state.TranscriptLine = 1
	}
	cap := self.settings.PayloadByteCount
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		chunk, err := ingestReadChunk(file, state.TranscriptAt, cap+1)
		if err != nil {
			return
		}
		lines, consumed, lineCount, truncated := ingestFrameLines(chunk, cap)
		if lineCount == 0 {
			return
		}
		if truncated {
			// the rest of the long line goes unseen: skip to its end
			skipped, err := ingestSkipLine(file, state.TranscriptAt+consumed)
			if err != nil {
				return
			}
			consumed += skipped
			self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapTruncation)
		}
		redacted := self.redact(ctx, run, redactor, lines)
		redacted, cut := ingestCut(redacted, cap)
		if cut && !truncated {
			truncated = true
			self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapTruncation)
		}
		firstLine := state.TranscriptLine
		appended := self.appendWithLock(ctx, run, &ingestEntry{
			kind:   sidecar.RecordKindTranscript,
			source: sidecar.RecordSourceHook,
			body: &protocol.TranscriptBody{
				FirstLine: firstLine,
				LineCount: uint32(lineCount),
				Lines:     redacted,
				Truncated: truncated,
			},
			byteCount:      int64(len(redacted)),
			coverageSource: sidecar.RecordCoverageSourceTranscript,
		})
		// consumed either way: a dropped chunk is the oversize gap appendWithLock counted, and the tail moves on
		_ = appended
		state.TranscriptAt += consumed
		state.TranscriptLine += uint64(lineCount)
		run.dirty = true
		if int64(len(chunk)) <= cap {
			return
		}
	}
}

// Up to byteCount bytes of file from offset.
func ingestReadChunk(file *os.File, offset int64, byteCount int64) ([]byte, error) {
	chunk := make([]byte, byteCount)
	read, err := file.ReadAt(chunk, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return chunk[:read], nil
}

// The whole lines at the start of chunk within cap: the bytes through the last newline inside cap, how many bytes
// they take and how many lines; or, with no newline inside cap and the chunk past it, the first cap bytes as one
// truncated line.
func ingestFrameLines(chunk []byte, cap int64) (lines []byte, consumed int64, lineCount int, truncated bool) {
	window := chunk
	if cap < int64(len(window)) {
		window = window[:cap]
	}
	last := bytes.LastIndexByte(window, '\n')
	if last < 0 {
		if int64(len(chunk)) <= cap {
			// a partial last line waits for its newline
			return nil, 0, 0, false
		}
		cut, _ := ingestCut(window, cap)
		return cut, int64(len(cut)), 1, true
	}
	lines = window[:last+1]
	return lines, int64(len(lines)), bytes.Count(lines, []byte{'\n'}), false
}

// Skips to the byte after the next newline from offset, answering how many bytes that is.
func ingestSkipLine(file *os.File, offset int64) (int64, error) {
	skipped := int64(0)
	buffer := make([]byte, 64*1024)
	for {
		read, err := file.ReadAt(buffer, offset+skipped)
		if read == 0 {
			if err != nil && !errors.Is(err, io.EOF) {
				return skipped, err
			}
			return skipped, nil
		}
		if at := bytes.IndexByte(buffer[:read], '\n'); 0 <= at {
			return skipped + int64(at) + 1, nil
		}
		skipped += int64(read)
		if err != nil {
			return skipped, nil
		}
	}
}

// Arms the periodic tail, every TranscriptTailInterval, while the run lives. The run's lock is held.
func (self *Ingest) armTailWithLock(run *ingestRun) {
	if run.tailStop != nil {
		run.tailStop()
	}
	run.tailStop = self.clock.AfterFunc(self.settings.TranscriptTailInterval, func() {
		self.tailTick(run)
	})
}

// One periodic tail: nothing once the run is covered.
func (self *Ingest) tailTick(run *ingestRun) {
	ctx := context.Background()
	run.runLock.Lock()
	defer run.runLock.Unlock()
	defer self.saveRunWithLock(run)
	if run.state.Covered {
		return
	}
	redactor, err := self.redactor(run.network)
	if err != nil {
		return
	}
	self.tailTranscriptWithLock(ctx, run, redactor)
	self.armTailWithLock(run)
}
