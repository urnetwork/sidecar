// urnetwork_sockets_*, §9.10's families and no others: results, reasons and times from the closed sets
// below, never a network, name, client or address (I-13), so no metric can say who listens or dials
// what. The registration and Find paths (SOCK-M5-05, SOCK-M5-06) count into these; this task declares
// them so that every route shares one set.

package socketsservice

import (
	"github.com/urnetwork/sidecar"
)

// find_total's results: Find's answers in §9.6's step order, then a signed one.
const (
	socketFindResultUnavailable = "unavailable"
	socketFindResultDenied      = "denied"
	socketFindResultQuota       = "quota"
	socketFindResultNoListener  = "no_listener"
	socketFindResultBusy        = "busy"
	socketFindResultOk          = "ok"
)

// registration_calls_total's results: a page's own answer.
const (
	socketRegistrationResultOk          = "ok"
	socketRegistrationResultUnavailable = "unavailable"
	socketRegistrationResultStale       = "stale"
	socketRegistrationResultInvalid     = "invalid"
)

// failure_reports_total's reasons, a dialer's own word for a failed ticket (socket_api.go).
const (
	socketFailureReasonTimeout = string(sidecar.SocketFailedReasonTimeout)
	socketFailureReasonRefused = string(sidecar.SocketFailedReasonRefused)
	// a report the service dropped: a ticket that did not verify, or a stranger's
	socketFailureReasonDropped = "dropped"
)

// The engine's families, declared once per engine. Two engines in one process share them, as Metrics
// allows.
type socketMetrics struct {
	// Finds answered, by result.
	findCount sidecar.MetricsCounter
	// Time to answer a Find, signing included.
	findSeconds sidecar.MetricsHistogram
	// Leases this process last saw written, a level.
	registrations sidecar.MetricsGauge
	// Registration calls answered, by result.
	registrationCallCount sidecar.MetricsCounter
	// Failed tickets reported, by reason.
	failureReportCount sidecar.MetricsCounter
	// Reports that excluded a listener for their dialer.
	exclusionCount sidecar.MetricsCounter
	// Reports that ejected a listener for every dialer.
	ejectionCount sidecar.MetricsCounter
}

// Declares the families on metrics.
func newSocketMetrics(metrics sidecar.Metrics) *socketMetrics {
	return &socketMetrics{
		findCount:             metrics.Counter("urnetwork_sockets_find_total", "Finds answered, by result.", "result"),
		findSeconds:           metrics.Histogram("urnetwork_sockets_find_seconds", "Time to answer a Find.", nil),
		registrations:         metrics.Gauge("urnetwork_sockets_registrations", "Leases written by this process's last pages."),
		registrationCallCount: metrics.Counter("urnetwork_sockets_registration_calls_total", "Registration calls answered, by result.", "result"),
		failureReportCount:    metrics.Counter("urnetwork_sockets_failure_reports_total", "Failed tickets reported, by reason.", "reason"),
		exclusionCount:        metrics.Counter("urnetwork_sockets_exclusions_total", "Reports that excluded a listener for their dialer."),
		ejectionCount:         metrics.Counter("urnetwork_sockets_ejections_total", "Reports that ejected a listener for every dialer."),
	}
}
