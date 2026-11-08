// urnetwork_mxedge_*: results only, from the closed sets below, never a network, domain or address
// (§19.8, I-13), so a metric cannot say who mailed whom.

package mxedgeservice

import (
	"github.com/urnetwork/sidecar"
)

// How a session ended.
const (
	// Refused before the banner by a cap, or by a draining engine.
	mxSessionResultOverCap  = "over_cap"
	mxSessionResultDraining = "draining"
	// A conn whose peer address cannot be read, so no cap can count it.
	mxSessionResultNoSender = "no_sender"
	// The sender said QUIT.
	mxSessionResultQuit = "quit"
	// A limit, a broken line.
	mxSessionResultLimit = "limit"
	// A byte came behind STARTTLS.
	mxSessionResultReset = "reset"
	// The peer left, or the dialog's time ran out.
	mxSessionResultEnded = "ended"
	// Reached TLS and closed in the handshake, a temporary failure.
	mxSessionResultClosedHandshake = "closed_handshake"
)

// Which refusal a plaintext transaction's session got.
const (
	mxPlaintextResult451 = "451"
	mxPlaintextResult530 = "530"
)

// How one use of the closed-handshake memory went.
const (
	mxMemoryResultRecent  = "recent"
	mxMemoryResultAbsent  = "absent"
	mxMemoryResultWritten = "written"
	// Redis did not answer, or today's k is not held.
	mxMemoryResultFailed = "failed"
)

// The engine's counters.
type mxMetrics struct {
	// Sessions, by how each ended.
	sessions sidecar.MetricsCounter
	// Sessions refused, by the cap that refused them.
	capRefusals sidecar.MetricsCounter
	// Sessions that tried a plaintext transaction, by the refusal they got.
	plaintextSessions sidecar.MetricsCounter
	// Reads of the closed-handshake memory, by answer.
	memoryReads sidecar.MetricsCounter
	// Writes to the closed-handshake memory, by outcome.
	memoryWrites sidecar.MetricsCounter
	// Reads of the memory's daily k, one each probe, by how each went.
	dailyKeyRefreshes sidecar.MetricsCounter
	// Accepts that failed and were retried.
	acceptFailures sidecar.MetricsCounter
}

// Declares the families. Two engines in one process share them, as Metrics allows.
func newMxMetrics(metrics sidecar.Metrics) *mxMetrics {
	return &mxMetrics{
		sessions:          metrics.Counter("urnetwork_mxedge_sessions_total", "Sessions on TCP 25, by how each ended.", "result"),
		capRefusals:       metrics.Counter("urnetwork_mxedge_cap_refusals_total", "Sessions refused, by the cap that refused them.", "result"),
		plaintextSessions: metrics.Counter("urnetwork_mxedge_plaintext_sessions_total", "Sessions that tried a plaintext transaction, by the refusal.", "result"),
		memoryReads:       metrics.Counter("urnetwork_mxedge_closed_handshake_reads_total", "Reads of the closed-handshake memory, by answer.", "result"),
		memoryWrites:      metrics.Counter("urnetwork_mxedge_closed_handshake_writes_total", "Writes to the closed-handshake memory, by outcome.", "result"),
		dailyKeyRefreshes: metrics.Counter("urnetwork_mxedge_daily_key_refreshes_total", "Reads of the closed-handshake memory's daily key, by outcome.", "result"),
		acceptFailures:    metrics.Counter("urnetwork_mxedge_accept_failures_total", "Accepts that failed and were retried."),
	}
}
