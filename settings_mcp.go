// §16's local settings. Each field is a limit §16 states in prose, under the name this file gives it,
// so the track that builds §16 extends these structs and keeps the names. Every number here must be
// positive, as settings.go's header says.

package sidecar

import (
	"time"
)

// §16.4's bounds on one MCP session.
type SidecarMcpSettings struct {
	// Calls in flight a session: 8.
	SessionCallCount int
	// W calls a session may start: 20 a second, and burst 20, a reading, since §16.4 states none.
	SessionWriteRate SidecarRate
	// A result over this becomes a resource_link from 2025-06-18, else a text naming the ur://
	// resource: 256 KiB (D-MCP-13).
	ResultByteCount int
	// When a call times out: 30 s, under Codex's 60 s tool_timeout_sec default. A call awaiting a
	// person returns pending at once.
	CallTimeout time.Duration
	// How long an approval's ledger file stays past its not_after: 30 days (§16.6's retention row),
	// long after a local use stops completing at not_after + 10 min.
	ApprovalFileRetention time.Duration
	// How long a run's file stays once its Coverage entry is sealed: 30 days (§16.6's retention row),
	// for restore (§16.7). A later Coverage starts it again.
	RunFileRetention time.Duration
}

// §16.7's capture bounds. Every cut, missed event or changed config is a coverage gap.
type SidecarIngestSettings struct {
	// One hook payload or tool body: 1 MiB, past which it is cut.
	PayloadByteCount int64
	// A file over this is recorded by hash and size: 8 MiB.
	FileByteCount int64
	// Captured bytes per run-hour, since vault bytes count toward storage (§20): 256 MiB.
	RunHourByteCount int64
	// The local encrypted spool, which keeps capturing while the daemon is locked: 1 GiB.
	SpoolByteCount int64
	// One spool segment, past which the next record starts another: 16 MiB, a reading, so a drain
	// removes what it has taken in steps and never holds a gigabyte in one file.
	SpoolSegmentByteCount int64
	// Records a drain hands over between writes of its cursor: 64, a reading. After a kill at most
	// this many come again, each with its SpoolRecordId, which the consumer skips.
	SpoolCursorRecordCount int
	// A transcript is tailed this often, and at Stop, SubagentStop, PreCompact and SessionEnd: 30 s.
	TranscriptTailInterval time.Duration
	// `ur hook` passes its stdin to the daemon and exits 0 within this: 300 ms.
	HookExitTimeout time.Duration
	// A run's restore point on disk: 256 MiB.
	RestorePointByteCount int64
	// A path's bytes are held from its PreToolUse to its PostToolUse at most this long: 10 min.
	RestoreHoldTimeout time.Duration
	// How much of a file that hold keeps: 8 MiB.
	RestoreHoldByteCount int64
}

// §16.8's record defaults.
type SidecarRecordSettings struct {
	// Entries one push carries into a stream: 64.
	PushEntryCount int
	// How long a push waits for more entries, whichever comes first: 1 s.
	PushCoalesce time.Duration
	// ReachReceipts coalesce per (grant, peer) over this: 5 min.
	ReachReceiptCoalesce time.Duration
	// A run with no SessionEnd closes its Coverage after this idle: 10 min.
	CoverageIdleTimeout time.Duration
	// The team record's retention until its admin signs a RetentionPolicy: 400 days, in days as
	// RetentionPolicy.keep_days counts them.
	TeamRecordKeepDays int
	// How much of that stays searchable: 90 days.
	TeamRecordSearchableDays int
}

// A fresh value each call, as DefaultSidecarSettings's is.
func defaultSidecarMcpSettings() *SidecarMcpSettings {
	return &SidecarMcpSettings{
		SessionCallCount:      8,
		SessionWriteRate:      SidecarRate{Count: 20, Burst: 20, Interval: 1 * time.Second},
		ResultByteCount:       256 * 1024,
		CallTimeout:           30 * time.Second,
		ApprovalFileRetention: 30 * 24 * time.Hour,
		RunFileRetention:      30 * 24 * time.Hour,
	}
}

// A fresh value each call, as DefaultSidecarSettings's is.
func defaultSidecarIngestSettings() *SidecarIngestSettings {
	return &SidecarIngestSettings{
		PayloadByteCount:       1024 * 1024,
		FileByteCount:          8 * 1024 * 1024,
		RunHourByteCount:       256 * 1024 * 1024,
		SpoolByteCount:         1024 * 1024 * 1024,
		SpoolSegmentByteCount:  16 * 1024 * 1024,
		SpoolCursorRecordCount: 64,
		TranscriptTailInterval: 30 * time.Second,
		HookExitTimeout:        300 * time.Millisecond,
		RestorePointByteCount:  256 * 1024 * 1024,
		RestoreHoldTimeout:     10 * time.Minute,
		RestoreHoldByteCount:   8 * 1024 * 1024,
	}
}

// A fresh value each call, as DefaultSidecarSettings's is.
func defaultSidecarRecordSettings() *SidecarRecordSettings {
	return &SidecarRecordSettings{
		PushEntryCount:           64,
		PushCoalesce:             1 * time.Second,
		ReachReceiptCoalesce:     5 * time.Minute,
		CoverageIdleTimeout:      10 * time.Minute,
		TeamRecordKeepDays:       400,
		TeamRecordSearchableDays: 90,
	}
}
