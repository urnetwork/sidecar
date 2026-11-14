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
	// The most of one file a read through MCP holds in memory, evs_read's and ur://evs's: 16 MiB, a reading, since
	// §16.4 bounds a result, not a resource, and an over-limit result links to its resource. A larger file is refused,
	// naming ur evs for the person's own terminal.
	ResourceByteCount int64
	// How long an approval's ledger file stays past its not_after: 30 days (§16.6's retention row),
	// long after a local use stops completing at not_after + 10 min.
	ApprovalFileRetention time.Duration
	// How long an ApprovalRequest waits for a decision, its not_after_millis from its filing: 24 h, MCP.md's
	// reading 3, since §16.8 states no default. An action's own expiry wins where it is sooner, since a decision
	// past it could activate nothing.
	ApprovalRequestTimeout time.Duration
	// How long past not_after a local use reserved before it may still complete its effect under its effect_key:
	// 10 min (§16.6's expiry row). Past it a retry only reconciles, by the kind's Lookup.
	ApprovalCompleteTimeout time.Duration
	// How often the requester's inbox asks the approval log for the decisions of its pending requests, the poll
	// behind ur://approval/{id} until the record's hints reach the inbox: 30 s, a reading, since §16.8 names
	// hints and no poll.
	ApprovalPollInterval time.Duration
	// How long a presence key ur keys add-presence or ur login registers lasts, its KeyRegister's not_after from now:
	// 365 days, a reading, since §7.9 requires a not_after and states no value. A key past it countersigns nothing and
	// is registered again.
	PresenceKeyLifetime time.Duration
	// How long a run's file stays once its Coverage entry is sealed: 30 days (§16.6's retention row),
	// for restore (§16.7). A later Coverage starts it again.
	RunFileRetention time.Duration
	// What Sidecar.SecretMatcher matches a tool result against (I-7; record_secret_match.go).
	SecretMatch *SecretMatchSettings
}

// A SecretMatcher's bounds (record_secret_match.go).
type SecretMatchSettings struct {
	// A credential shorter than this is not matched: 16 bytes, under every key and token the daemon
	// holds (32-byte seeds, JWTs of hundreds), so a short value can never match ordinary text.
	CredentialMinByteCount int
}

// A fresh value each call.
func DefaultSecretMatchSettings() *SecretMatchSettings {
	return &SecretMatchSettings{
		CredentialMinByteCount: 16,
	}
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
	// How long the daemon's presence prompt may wait for the person, and ur hook on a PermissionRequest it answers by
	// one, past which the hook gives no decision and the call returns pending: 60 s (plan-MCP-presence-hook-timing).
	PresencePromptTimeout time.Duration
	// How long `ur hook` waits on a PreToolUse until the daemon holds the paths it names, past which it exits 0 and
	// those paths' before is unknown (§16.7): 10 s, a reading, far under a harness's own hook timeout.
	HookPathTimeout time.Duration
	// A hook coverage lapse: a tool call of a bound session with no hook event of its run within this either side
	// of it taints the run and counts a missed_event gap (§16.6's taint row): 60 s.
	HookLapseTimeout time.Duration
	// The harness config hashes are checked at each SessionStart and this often while a run lives (§16.6): 5 min.
	ConfigCheckInterval time.Duration
	// Tools whose use taints the run before the hook is acked (§16.6's taint row; MCP.md's reading 12): a tool of
	// one of these names, or a shell call whose pipeline has a stage whose first word is one, by its base name.
	// Matched exactly, so a wrapped call such as `python -c` goes unseen, as harness-native egress does.
	WebToolNames []string
	// Programs a harness may run a hook or an MCP server through, which the ancestry rules step over to find the
	// harness process itself (plan-MCP-taint-new-session): shells, by base name without .exe, lowercase.
	ShellNames []string
	// The most ancestors a pid's ancestry reads before it stops, a bound on the work one lookup does: 64, far past
	// any real process tree.
	AncestorDepthCount int
	// A run's restore point on disk: 256 MiB.
	RestorePointByteCount int64
	// A path's bytes are held from its PreToolUse to its PostToolUse at most this long: 10 min.
	RestoreHoldTimeout time.Duration
	// How much of a file that hold keeps: 8 MiB.
	RestoreHoldByteCount int64
	// The largest per-run ingest state file read whole: 1 MiB, its blob hashes bounded by IngestBlobHashCount.
	IngestStateByteCount int64
	// The blob hashes a run's ingest state remembers, so a blob already captured is not captured again, the oldest
	// forgotten past it: 4,096, a bound on the state file.
	IngestBlobHashCount int
	// The largest file of a restore point read whole, its manifest, ledger, preview list or one preview: 64 MiB, past
	// any real point's, so one that is larger reads as failed rather than being held in memory.
	RestoreManifestByteCount int64
	// The dry runs' previews one restore point keeps, the oldest removed past it: 16, a reading. An apply names one by
	// its preview_id, and a removed one is previewed again (§16.7's apply row).
	RestorePreviewCount int
	// The random bytes in each hidden name an apply stages, moves aside or probes under in a path's directory: 16, so a
	// fresh name never meets one that exists (§16.7's stage and aside rows).
	RestoreHiddenNameByteCount int
	// The names one conflict copy tries, <name>.ur-restored-<h>, then -2 and on (§16.7's copies row), before the bytes
	// stay under their hidden name, which the result names instead: 1,024, a reading. Non-positive tries the first
	// name alone.
	RestoreCopyNameCount int
	// Permission modes under which a run is recorded and gapped bypass_mode, and whose harness evidence never counts
	// (§16.6; D-MCP-9): Claude Code's bypassPermissions and dontAsk, and Codex's auto, as the harness names them.
	BypassPermissionModes []string
	// The instruction files a harness loads from the project, relative to the session's cwd, which the context entry
	// names by hash, never by text (§16.7): a directory among them lists its files. A reading, since §16.7 names no
	// list: Claude Code's, Codex's and Cursor's documented files.
	InstructionProjectFileNames []string
	// The instruction files a harness loads from the person's home, relative to it, scope user.
	InstructionUserFileNames []string
	// The most paths one scan's change entry carries, RECORD.md's ChangedPath cap, past which path_count stands
	// and the run's coverage has truncation: 4,096.
	ChangePathCount int
	// How much of the user prompts a run card keeps: 2 KiB (§16.10).
	RunCardPromptByteCount int
	// The most touched paths a run card keeps: 256 (§16.10).
	RunCardPathCount int
	// The agent-config files of a shared repo, which evs_write and evs_delete reach only as an outward action
	// (§16.5's row; sidecar/design/pitch5.html:737): CLAUDE.md, AGENTS.md, .mcp.json and each harness's hook and
	// settings files. An entry with no / matches a path's last name, at any depth, as harnesses load nested
	// CLAUDE.md and AGENTS.md files; one with a / matches the path itself or its tail after a /. Matched exactly, case
	// and all.
	AgentConfigPaths []string
	// The largest harness config file `ur install-harness` and the config check read whole: 16 MiB, past the
	// counters and per-project state Claude Code keeps in ~/.claude.json. A larger one is refused, and its check reads
	// changed.
	HarnessConfigByteCount int64
	// How deep a harness config's JSON or TOML values may nest before it is refused: 64, far past any real one.
	HarnessConfigDepthCount int
	// The most exact edits one install makes in one file before it stops: 1,024, far past the entries ur writes (an
	// MCP entry, an ask rule per outward tool, a hook per event) and any stale copies of them a file could hold.
	HarnessConfigEditCount int
	// The lines of context `ur install-harness` shows around each change of its diff: 3, unified diff's own.
	HarnessDiffContextLineCount int
	// The timeout `ur install-harness` writes on the hook entries that may wait on the daemon's presence prompt, Claude
	// Code's and Codex's PermissionRequest and Cursor's beforeMCPExecution: 75 s, past Ingest.PresencePromptTimeout's
	// 60 s, since Claude Code and Codex default to 600 s and Cursor states only a platform default
	// (plan-MCP-presence-hook-timing). Written in whole seconds.
	PermissionHookTimeout time.Duration
	// How many times `ur install-harness` plans a file again when the harness rewrote it between the plan and the
	// write: 3. Past that the install stops, naming the file.
	HarnessInstallRetryCount int
	// How old a hook event may be and still count as harness evidence, and how long a harness decision on it lasts:
	// 10 min (§16.6's harness_ok; MCP.md's reading 4).
	HarnessEvidenceTimeout time.Duration
	// The most unused harness evidence events kept in memory per network, the oldest dropped first: 1,024, far past
	// the prompts a person answers in ten minutes. A dropped event is lost evidence, the closed direction.
	HarnessEvidenceEventCount int
	// The permission modes a hook event's session may report for its event to count as harness evidence, as each
	// harness names them: Claude Code's default, acceptEdits and plan. Any other mode, an unknown or missing one
	// included, voids it (§16.6's harness_ok; D-MCP-9), so a harness whose modes this list does not name gives no
	// evidence until hook conformance (MCP-M3-28) names them. Cursor reports none: its beforeMCPExecution counts only
	// where `ur hook cursor` answered ask, which makes Cursor prompt.
	HarnessPromptingModes []string
}

// §16.8's record defaults, with RECORD.md section 18's fields below the first six, whose names stand
// (plan-RECORD-small-readings#1).
type SidecarRecordSettings struct {
	// Entries one push carries into a stream: 64, which is also the most one slot object holds, so a push
	// past it still carries 64.
	PushEntryCount int
	// How long a push waits for more entries, whichever comes first: 1 s. Also the first wait before a push
	// or deposit whose outcome is unknown, or that evs refused, goes again, doubling up to DepositInterval,
	// since §16.8 names no backoff of its own.
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
	// A deposit batch waits this long for more entries, unless an approval-family entry, a run's end, sleep
	// or exit sends it at once: 5 min, the slower pace owner decision 172 sets companion pushes (RECORD.md
	// section 5.3's deposits row).
	DepositInterval time.Duration
	// The most one deposit batch carries, unless one entry alone passes it: 1 MiB (section 5.4).
	DepositByteCount int
	// An entry whose time_millis is past its push's time_ms by more than this reads as skewed: 10 min
	// (section 5.3's time row). An ingester takes the same tolerance for section 5.4's right step, §16.11's
	// 10 min between a log entry ending a depositor's right and the deposit's push.
	TimeSkewTimeout time.Duration
	// A depositing writer's chain gap stays open this long before it alarms, since one ingester's push can
	// land before another's: 1 h (section 5.5's chain step).
	ChainGapTimeout time.Duration
	// A run card is re-projected this often: 5 min (§16.10's re-index).
	CardInterval time.Duration
	// The expiry pass runs this often on a log admin's daemon: 24 h (section 8).
	ExpiryInterval time.Duration
	// Up to this long after first syncing the work, so admins' daemons do not all start at once: 10 min
	// (section 8).
	ExpiryDelay time.Duration
	// An admin BASE re-lists a log's live set this often: 7 d (section 8).
	BaseInterval time.Duration
	// A checkpoint batch is cut this often, interval_seconds' default: 1 h (section 10.1).
	CheckpointInterval time.Duration
	// How long a witness has to cosign: 60 s (section 10.2).
	WitnessTimeout time.Duration
	// A cosignature older than this is not fresh: 24 h (section 10.2).
	WitnessFreshInterval time.Duration
	// Misses before a witness alarms: 3 (section 10.2).
	WitnessMissCount int
	// Leaves one checkpoint batch takes at most: 32,768 (section 10.2).
	LeafBatchCount int
}

// A fresh value each call, as DefaultSidecarSettings's is.
func defaultSidecarMcpSettings() *SidecarMcpSettings {
	return &SidecarMcpSettings{
		SessionCallCount:        8,
		SessionWriteRate:        SidecarRate{Count: 20, Burst: 20, Interval: 1 * time.Second},
		ResultByteCount:         256 * 1024,
		CallTimeout:             30 * time.Second,
		ResourceByteCount:       16 * 1024 * 1024,
		ApprovalFileRetention:   30 * 24 * time.Hour,
		ApprovalRequestTimeout:  24 * time.Hour,
		ApprovalCompleteTimeout: 10 * time.Minute,
		ApprovalPollInterval:    30 * time.Second,
		PresenceKeyLifetime:     365 * 24 * time.Hour,
		RunFileRetention:        30 * 24 * time.Hour,
		SecretMatch:             DefaultSecretMatchSettings(),
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
		PresencePromptTimeout:  60 * time.Second,
		HookPathTimeout:        10 * time.Second,
		HookLapseTimeout:       60 * time.Second,
		ConfigCheckInterval:    5 * time.Minute,
		WebToolNames:           []string{"WebFetch", "WebSearch", "web_search", "web_fetch", "curl", "wget"},
		ShellNames: []string{
			"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "tcsh", "csh", "nu", "cmd", "powershell", "pwsh",
		},
		AncestorDepthCount:    64,
		RestorePointByteCount: 256 * 1024 * 1024,
		RestoreHoldTimeout:    10 * time.Minute,
		RestoreHoldByteCount:  8 * 1024 * 1024,
		IngestStateByteCount:  1024 * 1024,
		IngestBlobHashCount:   4096,
		// a restore point's files and the apply's names and copies (MCP-M3-21)
		RestoreManifestByteCount:   64 * 1024 * 1024,
		RestorePreviewCount:        16,
		RestoreHiddenNameByteCount: 16,
		RestoreCopyNameCount:       1024,
		BypassPermissionModes:      []string{"bypassPermissions", "dontAsk", "auto"},
		InstructionProjectFileNames: []string{
			"CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", "AGENTS.md", ".cursorrules", ".cursor/rules",
		},
		InstructionUserFileNames: []string{".claude/CLAUDE.md", ".codex/AGENTS.md"},
		ChangePathCount:          4096,
		RunCardPromptByteCount:   2 * 1024,
		RunCardPathCount:         256,
		AgentConfigPaths: []string{
			"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".mcp.json", ".cursorrules",
			".claude/settings.json", ".claude/settings.local.json",
			".codex/config.toml", ".codex/hooks.json",
			".cursor/mcp.json", ".cursor/hooks.json",
			".ur",
		},
		HarnessConfigByteCount:      16 * 1024 * 1024,
		HarnessConfigDepthCount:     64,
		HarnessConfigEditCount:      1024,
		HarnessDiffContextLineCount: 3,
		PermissionHookTimeout:       75 * time.Second,
		HarnessInstallRetryCount:    3,
		HarnessEvidenceTimeout:      10 * time.Minute,
		HarnessEvidenceEventCount:   1024,
		HarnessPromptingModes:       []string{"default", "acceptEdits", "plan"},
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
		DepositInterval:          5 * time.Minute,
		DepositByteCount:         1024 * 1024,
		TimeSkewTimeout:          10 * time.Minute,
		ChainGapTimeout:          1 * time.Hour,
		CardInterval:             5 * time.Minute,
		ExpiryInterval:           24 * time.Hour,
		ExpiryDelay:              10 * time.Minute,
		BaseInterval:             7 * 24 * time.Hour,
		CheckpointInterval:       1 * time.Hour,
		WitnessTimeout:           60 * time.Second,
		WitnessFreshInterval:     24 * time.Hour,
		WitnessMissCount:         3,
		LeafBatchCount:           32768,
	}
}
