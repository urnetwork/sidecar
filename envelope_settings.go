// §6.6's subprotocol bounds, on every leg. Timings and policy sizes are settings; protocol values such
// as the 4,080 B envelope are constants (D-PROTO-16), in envelope_constants.go. Process-wide caps sit
// inside SidecarSettings.MemoryBudgetByteCount and answer RESOURCE_EXHAUSTED (envelope_budget.go). Every
// number here must be positive, as settings.go's header says, which holds for the head checks above
// all: a zero there would read as no witness ever asked for.

package sidecar

import (
	"fmt"
	"time"
)

// §6.6's table. Defaults are the desktop's; a mobile value follows a semicolon.
type SidecarProtocolSettings struct {
	// How long a peer's Hello stands: 10 min. Since connect signals no sequence exit, it ends sooner at
	// any change of the peer's C15 key, checked per frame, or on a send's ack error
	// (plan-PROTO-small-readings.md's reading 1). A pair in a §6.10 window keeps it while the window is
	// open and no 120 s pass without a keepalive.
	HelloCacheTimeout time.Duration
	// How often an app host Pings an indexer whose §6.10 window is open, while in the foreground, on
	// a grid from the window's start: 60 s, under connect's 120 s receive idle.
	MarkedKeepaliveInterval time.Duration
	// A call's timeout when its caller sets none: 15 s. The protocol's maximum is 55 s, before the 60 s
	// sequence exit (§6.6).
	DefaultCallTimeout time.Duration
	// Requests one peer may have queued past the inline handler, which answers RESOURCE_EXHAUSTED
	// past this without waiting: 64.
	PeerQueueMessageCount int
	// The largest body reassembled from chunks: 256 KiB. The protocol's maximum is 1 MiB.
	ReassemblyMaxBodyByteCount int64
	// Bodies reassembling at once from one peer: 8; 4: two search pages (§11.14) and HeadCheck both
	// ways at one peer.
	ReassemblyPeerCount int
	// Bytes reassembling from one peer: 2 MiB; 512 KiB.
	ReassemblyPeerByteCount int64
	// Bytes reassembling in the process: 16 MiB; 2 MiB.
	ReassemblyProcessByteCount int64
	// How long a partial body waits after its last chunk: 30 s.
	ReassemblyIdleTimeout time.Duration
	// How long a mutating call's response stays cached by (source, request_id), so a retry gets it
	// and nothing runs twice: 10 min.
	IdempotencyTimeout time.Duration
	// Cached responses from one peer: 256 KiB; 64 KiB.
	IdempotencyPeerByteCount int64
	// Cached responses in the process: 4 MiB; 512 KiB.
	IdempotencyProcessByteCount int64
	// The largest response cached: 16 KiB. A retry of a larger one gets Error{ALREADY_EXISTS} with a
	// result_ref (§6.6).
	IdempotencyMaxResponseByteCount int64
	// What a stream may send an acceptor before StreamAccept: 16 KiB, advertised in Hello, and the
	// value without a Hello, as from edges (§6.7).
	StreamInitialWindowByteCount int64
	// The credit a receiver commits before it sends a window, else StreamReject{BUSY}: 256 KiB;
	// 64 KiB.
	StreamMinWindowByteCount int64
	// The most a window grows to while the reader keeps up: 1 MiB; 256 KiB.
	StreamMaxWindowByteCount int64
	// Credit across one peer's streams: 8 MiB; 1 MiB. Edge peers: grows with streams, so one slow
	// visitor cannot stall the rest.
	StreamPeerCreditByteCount int64
	// Credit across every stream: 64 MiB; 8 MiB.
	StreamProcessCreditByteCount int64
	// The share of a peer's credit one stream's window may reach: 1/8.
	StreamMaxPeerCreditFraction float64
	// How long open streams go without inbound traffic before a Ping: 15 s.
	PingTimeout time.Duration
	// How long they go before the peer's streams reset with PEER_TIMEOUT: 45 s, before connect's 60 s
	// exit.
	PeerSilenceTimeout time.Duration
	// How often a round of HeadCheck runs: 1 h per peer; overdue after 1 h without a consistent result
	// (§6.4).
	HeadCheckInterval time.Duration
	// Peers a round checks: 4: up to 2 of other members, the rest own devices and agents (§6.4; owner
	// decision 129).
	HeadCheckRoundPeerCount int
	// How long a scheduled HeadCheck call waits: 10 s; silent own app hosts get a wake (M8).
	HeadCheckTimeout time.Duration
	// How long api gets to serve a peer's newer entries, before asking the peer for a HeadCheckProof:
	// 10 min (2 tries).
	HeadCheckFetchTimeout time.Duration
	// How often a round runs while a revocation this device signed is unwitnessed: 10 min.
	HeadCheckUnwitnessedInterval time.Duration
	// The least time between wakes of one device: 1 h, as the api enforces; woken sidecars check
	// first. Neither witness bound is a local setting: the stop at ServiceSettings.witness_bound_hours
	// is per-network config (§7.9), and the 24 h alarm is a protocol constant fixed by owner decision 129
	// (plan-PROTO-small-readings.md's reading 3).
	WakeInterval time.Duration
	// How often a client resyncs its topics, so correctness never rests on a hint's delivery: 1 h
	// (§6.8).
	SyncRefetchInterval time.Duration
}

// The one source of §6.6's defaults, the desktop's. A fresh value each call, as DefaultSidecarSettings's
// is.
func DefaultSidecarProtocolSettings() *SidecarProtocolSettings {
	return &SidecarProtocolSettings{
		HelloCacheTimeout:               10 * time.Minute,
		MarkedKeepaliveInterval:         60 * time.Second,
		DefaultCallTimeout:              15 * time.Second,
		PeerQueueMessageCount:           64,
		ReassemblyMaxBodyByteCount:      256 * 1024,
		ReassemblyPeerCount:             8,
		ReassemblyPeerByteCount:         2 * 1024 * 1024,
		ReassemblyProcessByteCount:      16 * 1024 * 1024,
		ReassemblyIdleTimeout:           30 * time.Second,
		IdempotencyTimeout:              10 * time.Minute,
		IdempotencyPeerByteCount:        256 * 1024,
		IdempotencyProcessByteCount:     4 * 1024 * 1024,
		IdempotencyMaxResponseByteCount: 16 * 1024,
		StreamInitialWindowByteCount:    16 * 1024,
		StreamMinWindowByteCount:        256 * 1024,
		StreamMaxWindowByteCount:        1024 * 1024,
		StreamPeerCreditByteCount:       8 * 1024 * 1024,
		StreamProcessCreditByteCount:    64 * 1024 * 1024,
		StreamMaxPeerCreditFraction:     1.0 / 8,
		PingTimeout:                     15 * time.Second,
		PeerSilenceTimeout:              45 * time.Second,
		HeadCheckInterval:               1 * time.Hour,
		HeadCheckRoundPeerCount:         4,
		HeadCheckTimeout:                10 * time.Second,
		HeadCheckFetchTimeout:           10 * time.Minute,
		HeadCheckUnwitnessedInterval:    10 * time.Minute,
		WakeInterval:                    1 * time.Hour,
		SyncRefetchInterval:             1 * time.Hour,
	}
}

// §6.6's values after each semicolon, for a host that runs on a phone, as sdk's
// applyMobileLowMemoryClientSettings narrows connect's defaults (§18.4). Exported so that host keeps no
// second copy of a number, and it leaves every field §6.6 gives one value alone.
func ApplyMobileSidecarProtocolSettings(settings *SidecarProtocolSettings) {
	settings.ReassemblyPeerCount = 4
	settings.ReassemblyPeerByteCount = 512 * 1024
	settings.ReassemblyProcessByteCount = 2 * 1024 * 1024
	settings.IdempotencyPeerByteCount = 64 * 1024
	settings.IdempotencyProcessByteCount = 512 * 1024
	settings.StreamMinWindowByteCount = 64 * 1024
	settings.StreamMaxWindowByteCount = 256 * 1024
	settings.StreamPeerCreditByteCount = 1024 * 1024
	settings.StreamProcessCreditByteCount = 8 * 1024 * 1024
}

// §6.6's protocol maximums, which no adjustment may pass: a call past MaxCallTimeout outlives its
// sequence, and a body past MaxReassemblyBodyByteCount is no peer's to take.
func (self *SidecarProtocolSettings) validate() error {
	if MaxCallTimeout < self.DefaultCallTimeout {
		return fmt.Errorf("%w: ProtocolSettings.DefaultCallTimeout is past the protocol's maximum", errInvalidSettings)
	}
	if MaxReassemblyBodyByteCount < self.ReassemblyMaxBodyByteCount {
		return fmt.Errorf("%w: ProtocolSettings.ReassemblyMaxBodyByteCount is past the protocol's maximum", errInvalidSettings)
	}
	return nil
}
