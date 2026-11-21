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
	// The platform role: a TLS handshake that failed, remembered as a closed one.
	mxSessionResultPlatformHandshakeFailed = "platform_handshake_failed"
	// The platform role: a session after TLS that ran to its end.
	mxSessionResultPlatformServed = "platform_served"
	// The router (router.go): closed in the handshake, by why.
	mxSessionResultHelloFailed        = "hello_failed"
	mxSessionResultGateClosed         = "gate_closed"
	mxSessionResultNotReady           = "not_ready"
	mxSessionResultNoSni              = "no_sni"
	mxSessionResultUnknownName        = "unknown_name"
	mxSessionResultRouteUnavailable   = "route_unavailable"
	mxSessionResultNetworkCap         = "network_cap"
	mxSessionResultSpent              = "spent"
	mxSessionResultNoReceiver         = "no_receiver"
	mxSessionResultReceiverBusy       = "receiver_busy"
	mxSessionResultReceiverDenied     = "receiver_denied"
	mxSessionResultSocketsUnavailable = "sockets_unavailable"
	mxSessionResultSetupFailed        = "setup_failed"
	// The router: spliced, then ended by one of splice.go's reasons, which follows this.
	mxSessionResultSplicePrefix = "splice_"
)

// How a PTR lookup went (ptr.go).
const (
	mxPtrResultConfirmed = "confirmed"
	// No name, none confirmed, a failure, or an answer past the bound or the session.
	mxPtrResultNone = "none"
	// Every slot was taken, so none ran.
	mxPtrResultNoSlot = "no_slot"
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
	// Outcomes of the SMTP dialog through the STARTTLS reply, independent of the later TLS session.
	preambles sidecar.MetricsCounter
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
	// Session records, written or dropped for a full queue (records.go).
	records sidecar.MetricsCounter
	// Writes of a batch of session records, by outcome.
	recordFlushes sidecar.MetricsCounter
	// The platform role's recipients, by how each was answered.
	platformRecipients sidecar.MetricsCounter
	// The platform role's messages, by how each was answered.
	platformMessages sidecar.MetricsCounter
	// The router's splices, by how each ended.
	spliceEnds sidecar.MetricsCounter
	// The router's spliced bytes, by direction.
	spliceBytes sidecar.MetricsCounter
	// The router's PTR lookups, by how each went.
	ptrLookups sidecar.MetricsCounter
	// The router's loads of the listing mirror, by how each went.
	listingLoads sidecar.MetricsCounter
	// The router's wake holds, by how each ended (wake_hold.go).
	wakeHolds sidecar.MetricsCounter
	// The router's wake hints, by how each went.
	wakeHints sidecar.MetricsCounter
}

// Declares the families. Two engines in one process share them, as Metrics allows.
func newMxMetrics(metrics sidecar.Metrics) *mxMetrics {
	return &mxMetrics{
		sessions:           metrics.Counter("urnetwork_mxedge_sessions_total", "Sessions on TCP 25, by how each ended.", "result"),
		preambles:          metrics.Counter("urnetwork_mxedge_preambles_total", "Router and platform SMTP dialogs through the STARTTLS reply, by outcome.", "result"),
		capRefusals:        metrics.Counter("urnetwork_mxedge_cap_refusals_total", "Sessions refused, by the cap that refused them.", "result"),
		plaintextSessions:  metrics.Counter("urnetwork_mxedge_plaintext_sessions_total", "Sessions that tried a plaintext transaction, by the refusal.", "result"),
		memoryReads:        metrics.Counter("urnetwork_mxedge_closed_handshake_reads_total", "Reads of the closed-handshake memory, by answer.", "result"),
		memoryWrites:       metrics.Counter("urnetwork_mxedge_closed_handshake_writes_total", "Writes to the closed-handshake memory, by outcome.", "result"),
		dailyKeyRefreshes:  metrics.Counter("urnetwork_mxedge_daily_key_refreshes_total", "Reads of the closed-handshake memory's daily key, by outcome.", "result"),
		acceptFailures:     metrics.Counter("urnetwork_mxedge_accept_failures_total", "Accepts that failed and were retried."),
		records:            metrics.Counter("urnetwork_mxedge_session_records_total", "Session records, written or dropped for a full queue.", "result"),
		recordFlushes:      metrics.Counter("urnetwork_mxedge_session_record_flushes_total", "Writes of a batch of session records, by outcome.", "result"),
		platformRecipients: metrics.Counter("urnetwork_mxedge_platform_recipients_total", "The platform listener's recipients, by how each was answered.", "result"),
		platformMessages:   metrics.Counter("urnetwork_mxedge_platform_messages_total", "The platform listener's messages, by how each was answered.", "result"),
		spliceEnds:         metrics.Counter("urnetwork_mxedge_splice_ends_total", "The router's splices, by how each ended.", "result"),
		spliceBytes:        metrics.Counter("urnetwork_mxedge_splice_bytes_total", "The router's spliced bytes, by direction.", "direction"),
		ptrLookups:         metrics.Counter("urnetwork_mxedge_ptr_lookups_total", "The router's forward-confirmed PTR lookups, by how each went.", "result"),
		listingLoads:       metrics.Counter("urnetwork_mxedge_listing_loads_total", "The router's loads of the IP listing mirror, by how each went.", "result"),
		wakeHolds:          metrics.Counter("urnetwork_mxedge_wake_holds_total", "The router's wake holds, by how each ended.", "result"),
		wakeHints:          metrics.Counter("urnetwork_mxedge_wake_hints_total", "The router's wake hints to a network's receivers, by how each went.", "result"),
	}
}
