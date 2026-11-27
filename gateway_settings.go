//go:build !ios_extension && !sidecar_http

// The gateway's settings, DESIGN-COMPUTE §8's, which GW's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultGatewaySettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the
// compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultGatewaySettings.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go). The gateway itself runs only in a desktop's daemon and an
// enclave's (Q-GW-5), so its files carry the daemon's build line too; these settings stay on every compute leg, since
// SidecarSettings holds them.

package sidecar

import (
	"time"
)

// DESIGN-COMPUTE §8, the local gateway: its listener, grants and tokens, its API fronts, retries and recording. GW's
// tasks add their fields; HostedSearch is SRCH's.
type GatewaySettings struct {
	// §21.7's refusal of hosted web search, which the fronts call before routing (gateway_search.go).
	HostedSearch *GatewayHostedSearchSettings

	// §8.7's limit on a request's body: 32 MiB, since Codex and Claude Code resend the whole history, its images
	// included, at every turn. A body past it is refused 413 before a front reads it. Non-positive refuses every body.
	RequestByteCount int64
	// §8.7's limit on requests the listener serves at once: 32. One past it is refused 429 at once, never queued, so a
	// harness's own retry paces it. Non-positive refuses every request.
	ConcurrentRequestCount int
	// What a request refused for ConcurrentRequestCount tells its harness to wait in Retry-After, in whole seconds: 1 s,
	// so a burst drains as calls end. Less than a second sends one.
	BusyRetryAfter time.Duration
	// The most bytes of a request's header lines and request line: 64 KiB, past any harness's headers. Go's server
	// answers 431 past it.
	HeaderByteCount int
	// How long a connection may take to send its request's headers: 30 s, so a client that holds a connection open
	// without sending ties nothing up. The body and a stream's answer have no bound here: a front bounds its own.
	ReadHeaderTimeout time.Duration
	// How long an idle keep-alive connection stays open: 2 min.
	IdleTimeout time.Duration
	// How long a close of the listener, at the daemon's end or a reload, waits for requests in flight before it
	// closes their connections: 10 s. A planned restart's longer wait for calls in flight is §8.5's, GW-M12-05's.
	ShutdownTimeout time.Duration

	// The first and last port the install draws the gateway's port from (§8.4: "the port chosen at install"): 21000
	// to 29999, below every desktop system's ephemeral range (macOS's 49152 on, Linux's 32768 on, Windows' 49152 on),
	// so an outgoing connection is never handed the port while the daemon is down.
	PortFirst int
	PortLast  int
	// How many ports a choice tries, each drawn at random from the range and taken only where both loopback
	// addresses bind: 32.
	PortChoiceAttemptCount int
	// How long the daemon looks for who holds an address of the port another process took, where the OS shows it, which
	// `ur status` prints: 2 s, a listing of the system's sockets. Past it nothing is named.
	HolderLookupTimeout time.Duration
	// The most processes a holder lookup reads, where it reads them one by one (Linux's /proc): 8192.
	HolderProcessCount int
	// The most bytes of the instance's gateway state file, <state>/gateway/gateway.json (gateway_state.go): 4 KiB.
	StateFileByteCount int64

	// §8.4's listener proof: the bytes of the key the daemon gives a command for one ask over its control socket: 32,
	// HMAC-SHA256's block-safe key length.
	ListenerProofKeyByteCount int
	// The random bytes of a key's id, which the command names in its ask: 16. Not secret: it only says which key.
	ListenerProofKeyIdByteCount int
	// The bytes of the nonce a command sends to the listener: 32.
	ListenerProofNonceByteCount int
	// How long a key answers proofs after it is given: 1 min, past a command's dial and answer on a slow host. A key
	// lives in the daemon's memory alone and is never written.
	ListenerProofKeyLife time.Duration
	// The most keys outstanding at once: 64. A key asked past it ends the oldest, whose command then fails closed.
	ListenerProofKeyCount int
	// How long a command waits for the listener's answer, its dial included: 5 s.
	ListenerProofTimeout time.Duration
	// The most bytes of the listener's answer a command reads: 4 KiB, far past the answer's JSON.
	ListenerProofAnswerByteCount int64

	// §8.6's token: ur_gw_ and this many random bytes in base64url: 32.
	TokenByteCount int
	// How long a token is valid from its mint: 1 h, so a token on disk lives at most an hour (IC-11).
	TokenLife time.Duration
	// The most grants one network's store holds: 64, past every harness and agent of one person's devices. A grant
	// past it is refused.
	GrantCount int
	// The most live tokens one grant holds: 64, past a harness that mints a token every 5 minutes (Claude Code's
	// helper cache) across a dozen processes in one hour. A mint past it drops the grant's oldest token, which expires
	// first anyway.
	GrantTokenCount int
	// The most model globs a grant names (§16.4's form): 64.
	GrantModelCount int
	// The most bytes of the store's sealed file, every grant and live token hash of one network: 4 MiB.
	GrantFileByteCount int
	// The most bytes of a harness's name in a grant: 64, past every harness §8.3 names.
	HarnessNameByteCount int

	// The process base names that read as each harness (§8.9's run handle): the nearest of a minting command's
	// ancestors that is no shell binds the token only where its name is one of its harness's here, or a run of the
	// network names that process already, so a token minted under a terminal emulator, a multiplexer or a login is
	// unbound. A name matches as itself or followed by "-", as Codex's native binary is named per target. Codex:
	// codex; Claude Code: claude, and node, which runs it from npm.
	HarnessProcessNames map[string][]string
}

// The component's defaults, the only place one is set.
func DefaultGatewaySettings() *GatewaySettings {
	return &GatewaySettings{
		HostedSearch: DefaultGatewayHostedSearchSettings(),

		RequestByteCount:       32 * 1024 * 1024,
		ConcurrentRequestCount: 32,
		BusyRetryAfter:         1 * time.Second,
		HeaderByteCount:        64 * 1024,
		ReadHeaderTimeout:      30 * time.Second,
		IdleTimeout:            2 * time.Minute,
		ShutdownTimeout:        10 * time.Second,

		PortFirst:              21000,
		PortLast:               29999,
		PortChoiceAttemptCount: 32,
		HolderLookupTimeout:    2 * time.Second,
		HolderProcessCount:     8192,
		StateFileByteCount:     4 * 1024,

		ListenerProofKeyByteCount:    32,
		ListenerProofKeyIdByteCount:  16,
		ListenerProofNonceByteCount:  32,
		ListenerProofKeyLife:         1 * time.Minute,
		ListenerProofKeyCount:        64,
		ListenerProofTimeout:         5 * time.Second,
		ListenerProofAnswerByteCount: 4 * 1024,

		TokenByteCount:       32,
		TokenLife:            1 * time.Hour,
		GrantCount:           64,
		GrantTokenCount:      64,
		GrantModelCount:      64,
		GrantFileByteCount:   4 * 1024 * 1024,
		HarnessNameByteCount: 64,

		HarnessProcessNames: map[string][]string{
			"codex":       {"codex"},
			"claude-code": {"claude", "node"},
		},
	}
}
