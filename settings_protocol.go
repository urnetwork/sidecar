// §6.6's subprotocol bounds. Timings and policy sizes are settings; protocol values such as the
// 4,080 B envelope are constants (D-PROTO-16). Process-wide caps sit inside
// SidecarSettings.MemoryBudgetByteCount and answer RESOURCE_EXHAUSTED.

package sidecar

import (
	"time"
)

// Defaults are the desktop's; a mobile value follows a semicolon.
type SidecarProtocolSettings struct {
	// 10 min, or until the sequence exits; a pair in a §6.10 window keeps it while the window is
	// open and no 120 s pass without a keepalive.
	HelloCacheTimeout time.Duration
	// 60 s: an app host's Ping to an indexer whose §6.10 window is open, while in the foreground,
	// on a grid from the window's start, under connect's 120 s receive idle.
	MarkedKeepaliveInterval time.Duration
	// 15 s. The protocol's maximum is 55 s.
	DefaultCallTimeout time.Duration
	// 64.
	PeerQueueMessageCount int
	// 256 KiB. The protocol's maximum is 1 MiB.
	ReassemblyMaxBodyByteCount int64
	// 8; 4: two search pages (§11.14) and HeadCheck both ways at one peer.
	ReassemblyPeerCount int
	// 2 MiB; 512 KiB.
	ReassemblyPeerByteCount int64
	// 16 MiB; 2 MiB.
	ReassemblyProcessByteCount int64
	// 30 s from the last chunk.
	ReassemblyIdleTimeout time.Duration
	// 10 min.
	IdempotencyTimeout time.Duration
	// 256 KiB; 64 KiB.
	IdempotencyPeerByteCount int64
	// 4 MiB; 512 KiB.
	IdempotencyProcessByteCount int64
	// 16 KiB.
	IdempotencyMaxResponseByteCount int64
	// 16 KiB, advertised in Hello.
	StreamInitialWindowByteCount int64
	// 256 KiB; 64 KiB.
	StreamMinWindowByteCount int64
	// 1 MiB; 256 KiB.
	StreamMaxWindowByteCount int64
	// 8 MiB; 1 MiB. Edge peers: grows with streams.
	StreamPeerCreditByteCount int64
	// 64 MiB; 8 MiB.
	StreamProcessCreditByteCount int64
	// 1/8 per stream.
	StreamMaxPeerCreditFraction float64
	// 15 s without inbound traffic.
	PingTimeout time.Duration
	// 45 s, before connect's 60 s exit.
	PeerSilenceTimeout time.Duration
	// 1 h per peer; overdue after 1 h without a consistent result (§6.4).
	HeadCheckInterval time.Duration
	// 4 per round: up to 2 of other members, the rest own devices and agents (§6.4; owner decision
	// 129).
	HeadCheckRoundPeerCount int
	// 10 s per scheduled call; silent own app hosts get a wake (M8).
	HeadCheckTimeout time.Duration
	// 10 min (2 tries) for api to serve a peer's newer entries, before asking the peer for a
	// HeadCheckProof.
	HeadCheckFetchTimeout time.Duration
	// 10 min while a revocation this device signed is unwitnessed.
	HeadCheckUnwitnessedInterval time.Duration
	// 1 h per woken device, as the api enforces; woken sidecars check first. The 24 h witness alarm
	// and the stop at ServiceSettings.witness_bound_hours are per-network config (§7.9; owner
	// decision 129), never local settings.
	WakeInterval time.Duration
	// 1 h.
	SyncRefetchInterval time.Duration
}

func defaultSidecarProtocolSettings() *SidecarProtocolSettings {
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
