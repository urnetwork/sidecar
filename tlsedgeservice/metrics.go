// urnetwork_tlsedge_*: results only, from the closed sets below, never a network, host, name or address
// (§19.8, I-13), so a metric cannot say who published what or who visited it. The connection path's
// families (TLS-M5-10's urnetwork_tlsedge_connections_total and the rest) join these.

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

// The engine's counters.
type tlsEdgeMetrics struct {
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
func newTlsEdgeMetrics(metrics sidecar.Metrics) *tlsEdgeMetrics {
	return &tlsEdgeMetrics{
		nameLoads:         metrics.Counter("urnetwork_tlsedge_name_loads_total", "Reads of the label map, by result.", "result"),
		killLoads:         metrics.Counter("urnetwork_tlsedge_kill_loads_total", "Reads of the kill switch's rows and keys, by result.", "result"),
		negativeEvictions: metrics.Counter("urnetwork_tlsedge_negative_cache_evictions_total", "Negative cache entries evicted before their time by the bound."),
		acceptFailures:    metrics.Counter("urnetwork_tlsedge_accept_failures_total", "Accepts that failed and were retried."),
	}
}
