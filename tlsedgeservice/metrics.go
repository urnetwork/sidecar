// urnetwork_tlsedge_*: results only, from the closed sets below, never a network, host, name or address
// (§19.8, I-13), so a metric cannot say who published what or who visited it. The connection path's
// families (urnetwork_tlsedge_connections_total and the rest) are here too.

package tlsedgeservice

import (
	"github.com/urnetwork/sidecar"
)

// How a read of the label map went.
const (
	tlsNameLoadResultSnapshot = "snapshot"
	tlsNameLoadResultDelta    = "delta"
	tlsNameLoadResultFailed   = "failed"
)

// How a read of the kill switch went.
const (
	tlsKillLoadResultRows       = "rows"
	tlsKillLoadResultRowsFailed = "rows_failed"
	tlsKillLoadResultKey        = "key"
	tlsKillLoadResultKeyFailed  = "key_failed"
)

// How a connection ended, urnetwork_tlsedge_connections_total's result. Each names an outcome, never whom
// it happened to.
const (
	// the process cap, before a hello was read
	tlsConnectionResultProcessCap = "process_cap"
	// the hello never completed: its timeout, or the visitor left
	tlsConnectionResultHelloIncomplete = "hello_incomplete"
	// a hello that does not parse: decode_error
	tlsConnectionResultHelloRefused = "hello_refused"
	// §13.4's route probe: unrecognized_name at once
	tlsConnectionResultRouteProbe = "route_probe"
	// the gate is off, the network is outside it, or the engine is not ready: internal_error
	tlsConnectionResultGateClosed = "gate_closed"
	tlsConnectionResultNotReady   = "not_ready"
	// no mapping, a kill, or a denied dial: unrecognized_name
	tlsConnectionResultUnmapped = "unmapped"
	tlsConnectionResultKilled   = "killed"
	tlsConnectionResultDenied   = "denied"
	// a visitor's or an endpoint's cap: internal_error
	tlsConnectionResultCap = "cap"
	// the negative cache answered for Find
	tlsConnectionResultNegativeNoListener = "negative_no_listener"
	tlsConnectionResultNegativeDenied     = "negative_denied"
	// Find's and the open's refusals: internal_error
	tlsConnectionResultNoListener  = "no_listener"
	tlsConnectionResultBusy        = "busy"
	tlsConnectionResultQuota       = "quota"
	tlsConnectionResultUnavailable = "unavailable"
	tlsConnectionResultSetupFailed = "setup_failed"
	// the stream opened and bytes were spliced
	tlsConnectionResultSpliced = "spliced"
)

// Why a spliced connection ended, urnetwork_tlsedge_stream_ends_total's reason.
const (
	tlsStreamEndClosed        = "closed"
	tlsStreamEndVisitorReset  = "visitor_reset"
	tlsStreamEndListenerReset = "listener_reset"
	tlsStreamEndIdle          = "idle"
	tlsStreamEndExpired       = "expired"
	tlsStreamEndKilled        = "killed"
	tlsStreamEndQuota         = "quota"
	tlsStreamEndDrain         = "drain"
	tlsStreamEndEngineClosed  = "engine_closed"
)

// A byte's direction, urnetwork_tlsedge_bytes_total's label.
const (
	tlsByteDirectionToListener = "to_listener"
	tlsByteDirectionToVisitor  = "to_visitor"
)

// How a connection record and a flush of them went.
const (
	tlsRecordResultWritten      = "written"
	tlsRecordResultDropped      = "dropped"
	tlsRecordFlushResultWritten = "written"
	tlsRecordFlushResultFailed  = "failed"
)

// The engine's counters.
type tlsEdgeMetrics struct {
	// Connections, by how each ended.
	connections sidecar.MetricsCounter
	// From accept to the listener's stream, for connections that got one.
	setupSeconds sidecar.MetricsHistogram
	// Bytes spliced, by direction.
	bytes sidecar.MetricsCounter
	// Connections a cap refused, by cap.
	capRefusals sidecar.MetricsCounter
	// Spliced connections, by why each ended.
	streamEnds sidecar.MetricsCounter
	// Connection records, by result, and flushes of them, by result.
	records       sidecar.MetricsCounter
	recordFlushes sidecar.MetricsCounter
	// Reads of the label map, by result.
	nameLoads sidecar.MetricsCounter
	// Reads of network_tls_suspension and of {tes_} keys, by result.
	killLoads sidecar.MetricsCounter
	// Negative cache entries the bound evicted before their time.
	negativeEvictions sidecar.MetricsCounter
	// Accepts that failed and were retried.
	acceptFailures sidecar.MetricsCounter
}

// Declares the families. Two engines in one process share them, as Metrics allows.
func newTlsEdgeMetrics(metrics sidecar.Metrics, settings *TlsEdgeSettings) *tlsEdgeMetrics {
	return &tlsEdgeMetrics{
		connections:       metrics.Counter("urnetwork_tlsedge_connections_total", "Connections, by how each ended.", "result"),
		setupSeconds:      metrics.Histogram("urnetwork_tlsedge_setup_seconds", "Seconds from accept to the listener's stream, for connections that got one.", settings.SetupSecondsBuckets),
		bytes:             metrics.Counter("urnetwork_tlsedge_bytes_total", "Bytes spliced, by direction.", "direction"),
		capRefusals:       metrics.Counter("urnetwork_tlsedge_cap_refusals_total", "Connections a cap refused, by cap.", "cap"),
		streamEnds:        metrics.Counter("urnetwork_tlsedge_stream_ends_total", "Spliced connections, by why each ended.", "reason"),
		records:           metrics.Counter("urnetwork_tlsedge_records_total", "Connection records, by result.", "result"),
		recordFlushes:     metrics.Counter("urnetwork_tlsedge_record_flushes_total", "Flushes of connection records, by result.", "result"),
		nameLoads:         metrics.Counter("urnetwork_tlsedge_name_loads_total", "Reads of the label map, by result.", "result"),
		killLoads:         metrics.Counter("urnetwork_tlsedge_kill_loads_total", "Reads of the kill switch's rows and keys, by result.", "result"),
		negativeEvictions: metrics.Counter("urnetwork_tlsedge_negative_cache_evictions_total", "Negative cache entries evicted before their time by the bound."),
		acceptFailures:    metrics.Counter("urnetwork_tlsedge_accept_failures_total", "Accepts that failed and were retried."),
	}
}
