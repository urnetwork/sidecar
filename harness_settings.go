//go:build !ios_extension && !sidecar_http

// The Harness's settings, DESIGN-COMPUTE §7's, which HARN's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultHarnessSettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the
// compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultHarnessSettings.
//
// HARN-M11-01 fills it whole with every limit §7 names, so later tasks only read it: the loop's (§7.4), the tool
// budget's, the workspace's and Pi's file tools' (§7.5), the events' (§7.6), sub-agents' (§7.9), and the attach link's
// line, replay and reconnect bounds HARN-M14's tasks read (§7.10).
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

import (
	"time"
)

// DESIGN-COMPUTE §7, the Harness: its sessions, events, tools, approvals and agents.
type HarnessSettings struct {
	// §7.4's loop. The most turns one prompt runs before the run ends with stop reason max_turns: 100 (Pi has no cap),
	// settable per agent through its spec. A turn is one assistant response and the tool calls it made. Non-positive
	// sets no cap, as Pi has none.
	MaxTurnCount int
	// The tries a retryable failure (capacity, transport) gets after the first, each on the same model, never another
	// (R-INFER-3): 3. Non-positive retries nothing.
	RetryCount int
	// The first retry's wait, doubling each try after it: 2 seconds, Pi's base. Run on the Harness's clock, never a
	// sleep. Non-positive retries at once.
	RetryBase time.Duration
	// The retries insufficient_quota with reason held takes, each at the time the broker gives (§6.6, §9.7), before the
	// run reports the error: 3. Non-positive reports it at once.
	HeldRetryCount int

	// §7.4's compaction. The context compacts when its tokens pass the model's window less the reserve, the lesser of
	// CompactionReserveTokenCount and CompactionReserveFraction of the window: 16,384 tokens and a quarter, so a
	// 32k-token model compacts at 24,576. A non-positive count or fraction reserves nothing from that side, and a
	// reserve of nothing compacts only when a provider refuses a request as too large.
	CompactionReserveTokenCount int64
	CompactionReserveFraction   float64
	// What a compaction keeps of the newest messages, the lesser of CompactionKeepTokenCount and
	// CompactionKeepFraction of the window: 20,000 tokens and a quarter, so a 32k-token model keeps 8,192. A call is
	// never split from its result, so what is kept may run a little past it. Non-positive keeps nothing but the
	// summary.
	CompactionKeepTokenCount int64
	CompactionKeepFraction   float64

	// §7.4's tool budget: a request's tool schemas and the skill take at most this fraction of the model's window,
	// where the catalog gives no tool budget of its own: a quarter, §6.3's. An agent whose spec names no tools gets
	// its profile's whole set where it fits, else SmallToolNames. Non-positive gives no room, so every agent gets the
	// small set and a spec naming tools is refused.
	ToolBudgetFraction float64
	// The small set §7.4 names, each taken where a tool of the name is registered for the agent's profile.
	SmallToolNames []string
	// Bytes counted as one token where the Harness estimates a text's tokens itself (a schema, the skill, a message
	// before a provider has counted it): 4, Pi's chars/4 estimate. Below 1 counts each byte a token.
	TokenEstimateByteCount int
	// How long a tool call runs before the turn hooks hear it is slow (§20.6's status line): 10 seconds.
	// Non-positive calls them at each call's start.
	ToolCallSlowAfter time.Duration

	// §7.5's workspace: the most an agent's temp directory may hold, its files and git worktrees counted together,
	// checked before a write lands. 1 GiB on desktops, 256 MiB on phones, 64 MiB in the browser (Later, Q-HARN-3).
	// Non-positive refuses every write.
	WorkspaceDesktopByteCount int64
	WorkspacePhoneByteCount   int64
	WorkspaceBrowserByteCount int64

	// Pi's file tools' limits, Pi 1.5.0's defaults (truncate.js, ls.js, grep.js, find.js), which models are trained
	// on. The most lines read returns at once: 2000. Non-positive returns none.
	ReadLineCount int
	// The most bytes read, ls, grep and find return at once: 50 KiB. Non-positive returns none.
	OutputByteCount int
	// The entries ls returns where the call names no limit: 500.
	LsEntryCount int
	// The matches grep returns where the call names no limit: 100.
	GrepMatchCount int
	// The characters a grep line shows before it is cut: 500.
	GrepLineCharCount int
	// The paths find returns where the call names no limit: 1000.
	FindResultCount int
	// The most bytes grep reads of one file: 16 MiB, so one large file cannot hold a call. Larger files are skipped and
	// named. Non-positive skips every file.
	GrepFileByteCount int64

	// §7.5's enclave profile (HARN-M14-05): bash's timeout, 10 minutes, and what it keeps of each of stdout and stderr,
	// 256 KiB. Non-positive ends every command at once and keeps nothing.
	BashTimeout         time.Duration
	BashStreamByteCount int64

	// §7.6's delivery: the most message_update events a second the batcher passes for one agent, text, thinking and
	// tool call deltas folded between them: 30. message_end carries the whole message, so a folded update loses
	// nothing. Non-positive passes every update.
	EventRate int
	// The events a subscriber's queue holds before its oldest delta is folded or, past it, the subscriber is dropped,
	// so a slow view never holds the loop: 1024. Below 1 holds one.
	EventSubscriberBufferCount int

	// §7.9's limits for a local Harness: 8 agents at work at once, a woken one past them waiting its turn (§20.7), and
	// 4 levels counted along the parent chain the Harness holds. Non-positive starts none.
	AgentConcurrentCount int
	AgentDepthCount      int

	// §7.10's attach link (HARN-M14). The longest JSON line either end reads: 16 MiB, room for a prompt's images in
	// base64. A line past it ends the session. A protocol limit both ends read from these settings. Non-positive ends
	// every session at its first line.
	RpcLineByteCount int
	// What the incarnation's journal keeps of each run's events for a reconnecting client's subscribe from_seq: the
	// newest 4096 events and at most 64 MiB of them. A seq older than what is kept replays from the vault. Non-positive
	// keeps none.
	RpcReplayEventCount int
	RpcReplayByteCount  int64
	// A management link's reconnect waits: 1 second at first, doubling to 60 seconds. Non-positive reconnects at once.
	ManageLinkReconnectBase time.Duration
	ManageLinkReconnectMax  time.Duration
}

// The component's defaults, the only place one is set.
func DefaultHarnessSettings() *HarnessSettings {
	return &HarnessSettings{
		MaxTurnCount:   100,
		RetryCount:     3,
		RetryBase:      2 * time.Second,
		HeldRetryCount: 3,

		CompactionReserveTokenCount: 16384,
		CompactionReserveFraction:   0.25,
		CompactionKeepTokenCount:    20000,
		CompactionKeepFraction:      0.25,

		ToolBudgetFraction: 0.25,
		SmallToolNames: []string{
			"read", "write", "edit", "ls", "grep", "git", "evs_read", "evs_list", "web_search", "web_fetch",
			"agent_register", "agent_summary", "agent_send", "agent_inbox",
		},
		TokenEstimateByteCount: 4,
		ToolCallSlowAfter:      10 * time.Second,

		WorkspaceDesktopByteCount: 1024 * 1024 * 1024,
		WorkspacePhoneByteCount:   256 * 1024 * 1024,
		WorkspaceBrowserByteCount: 64 * 1024 * 1024,

		ReadLineCount:     2000,
		OutputByteCount:   50 * 1024,
		LsEntryCount:      500,
		GrepMatchCount:    100,
		GrepLineCharCount: 500,
		FindResultCount:   1000,
		GrepFileByteCount: 16 * 1024 * 1024,

		BashTimeout:         10 * time.Minute,
		BashStreamByteCount: 256 * 1024,

		EventRate:                  30,
		EventSubscriberBufferCount: 1024,

		AgentConcurrentCount: 8,
		AgentDepthCount:      4,

		RpcLineByteCount:        16 * 1024 * 1024,
		RpcReplayEventCount:     4096,
		RpcReplayByteCount:      64 * 1024 * 1024,
		ManageLinkReconnectBase: 1 * time.Second,
		ManageLinkReconnectMax:  60 * time.Second,
	}
}
