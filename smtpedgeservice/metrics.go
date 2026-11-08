// urnetwork_smtpedge_*: results, modes, TLS levels and proof times, from the closed sets below, never a
// network, domain or address (§14.9, §19.8, I-13), so a metric cannot say who mailed whom. The report
// families serve the intake in mxedge's platform block, the rest the edge's connection path, which
// SMTP-M9-13 drives.

package smtpedgeservice

import (
	"github.com/urnetwork/sidecar"
)

// How one readiness probe of the store went.
const (
	smtpProbeResultOk     = "ok"
	smtpProbeResultFailed = "failed"
)

// A preamble's answer, as SmtpPreambleResult's code names it (§14.5).
const (
	smtpPreambleResultOk       = "ok"
	smtpPreambleResultHalted   = "halted"
	smtpPreambleResultQuota    = "quota"
	smtpPreambleResultDenied   = "denied"
	smtpPreambleResultNoMx     = "no_mx"
	smtpPreambleResultNoTls    = "no_tls"
	smtpPreambleResultTryLater = "try_later"
)

// A connection's mode (§14.4), unknown until the proofs fix it.
const (
	smtpModeUnknown = "unknown"
	smtpModeBdat    = "bdat"
	smtpModeData    = "data"
)

// The labels a connection's TLS level takes (§14.4).
var smtpTlsLevelLabels = map[uint8]string{
	0:                         "unknown",
	SmtpTlsLevelDane:          "tl1",
	SmtpTlsLevelMtaSts:        "tl2",
	SmtpTlsLevelIndependentMx: "tl3",
	SmtpTlsLevelNone:          "tl4",
}

// How a connection ended.
const (
	smtpConnectionResultSent = "sent"
	// The MX refused, or closed before the message.
	smtpConnectionResultRefused = "refused"
	// §14.7's cut: a client record a part refused.
	smtpConnectionResultCut = "cut"
	// An idle or lifetime limit.
	smtpConnectionResultTimeout = "timeout"
	// The sidecar left, or a stream broke.
	smtpConnectionResultEnded = "ended"
)

// The engine's and the intake's families.
type smtpMetrics struct {
	// Readiness probes of the store, by how each went.
	storeProbes sidecar.MetricsCounter
	// Reports the intake took, by kind and outcome.
	reports sidecar.MetricsCounter
	// Preambles answered, by code.
	preambles sidecar.MetricsCounter
	// Connections ended, by result, mode and TLS level.
	connections sidecar.MetricsCounter
	// Time to verify one part, by mode.
	proofSeconds sidecar.MetricsHistogram
}

// Declares the families. Two engines in one process share them, as Metrics allows.
func newSmtpMetrics(metrics sidecar.Metrics) *smtpMetrics {
	return &smtpMetrics{
		storeProbes:  metrics.Counter("urnetwork_smtpedge_store_probes_total", "Readiness probes of the store, by result.", "result"),
		reports:      metrics.Counter("urnetwork_smtpedge_reports_total", "Reports taken at the report host, by kind and outcome.", "kind", "result"),
		preambles:    metrics.Counter("urnetwork_smtpedge_preambles_total", "Preambles answered, by code.", "result"),
		connections:  metrics.Counter("urnetwork_smtpedge_connections_total", "Connections ended, by result, mode and TLS level.", "result", "mode", "tls_level"),
		proofSeconds: metrics.Histogram("urnetwork_smtpedge_proof_seconds", "Time to verify one proof part, by mode.", nil, "mode"),
	}
}
