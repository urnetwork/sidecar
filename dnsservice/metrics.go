// urnetwork_dnsedge_* (§19.8): what an edge counts, declared once from ServiceHost.Metrics. Labels
// carry only an rcode, a reason, a source or a transport, each from the closed sets here and never
// from a request, so no name, address or network reaches a metric (I-13, dns-2).

package dnsservice

import (
	"errors"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
)

// Why an edge refused what the feed gave it, the values of feedRefusals' reason label.
const (
	dnsFeedRefusedGap       = "gap"
	dnsFeedRefusedLower     = "lower"
	dnsFeedRefusedFormat    = "format"
	dnsFeedRefusedMalformed = "malformed"
	dnsFeedRefusedOther     = "other"
)

// Where a signature on an answer came from, the values of signatures' source label.
const (
	dnsSignatureSourceCache = "cache"
	dnsSignatureSourceFresh = "fresh"
)

// The label for EDNS's BADVERS.
const dnsRcodeBadVersLabel = "BADVERS"

// The label for any other rcode, so the set stays closed.
const dnsRcodeOtherLabel = "OTHER"

// An edge's counters and levels.
type dnsMetrics struct {
	// Answers sent, by rcode.
	answers sidecar.MetricsCounter
	// Rows and snapshots refused, by reason.
	feedRefusals sidecar.MetricsCounter
	// RRsets a view holds and will not answer, which only a write path's fault can leave there.
	withheldRrsets sidecar.MetricsGauge
	// Signatures put on answers, by source: the cache or the ZSK just now.
	signatures sidecar.MetricsCounter
	// Answers refused at signatures_per_second, by transport: TC over UDP, SERVFAIL over TCP.
	signatureCapped sidecar.MetricsCounter
	// Responses RRL held back, by class and action: dropped, or slipped out empty with TC.
	rrlLimited sidecar.MetricsCounter
	// Packets answered with nothing, by reason: one that does not parse, or a root not yet ready.
	dropped sidecar.MetricsCounter
	// TCP connections closed at accept, by reason: a source at its cap, every connection taken, or a
	// draining edge.
	tcpRefused sidecar.MetricsCounter
	// TCP connections held now.
	tcpConnections sidecar.MetricsGauge
	// Whether each lb interface's address of a family is in the healthy set, by inventory name and
	// family, which OPS's page for a failing split probe reads.
	interfaceHealthy sidecar.MetricsGauge
	// Whether each router interface's address of a family answers mx hosts, by inventory name and
	// family: its 25 banner and drains decide it (DNS-M7-01).
	routerHealthy sidecar.MetricsGauge
	// Whether never-all is keeping a family's last set, by set (edge or router) and family.
	healthyHeld sidecar.MetricsGauge
	// Feed polls, by what each came to: rows, a reload, nothing new, or an error.
	feedPolls sidecar.MetricsCounter
	// Self-checks of a view or key set, by result.
	selfChecks sidecar.MetricsCounter
	// Replaced snapshots' diffs, by what became of them: posted, a failed post, or expired unposted.
	reloadDiffs sidecar.MetricsCounter
	// Writes of the local snapshot, by result.
	snapshotWrites sidecar.MetricsCounter
	// Route probes of the custom-host map, by result: pass or fail.
	routeProbes sidecar.MetricsCounter
	// Rounds' route-probe reports, by result: posted, or failed and to be probed again.
	routeReports sidecar.MetricsCounter
}

// Declares the families. Two edges in one process share them, as Metrics allows.
func newDnsMetrics(metrics sidecar.Metrics) *dnsMetrics {
	return &dnsMetrics{
		answers:        metrics.Counter("urnetwork_dnsedge_answers_total", "Answers sent, by rcode.", "rcode"),
		feedRefusals:   metrics.Counter("urnetwork_dnsedge_feed_refused_total", "Rows and snapshots refused, by reason.", "reason"),
		withheldRrsets: metrics.Gauge("urnetwork_dnsedge_withheld_rrsets", "RRsets held in the view and not answered."),
		signatures:     metrics.Counter("urnetwork_dnsedge_signatures_total", "Signatures put on answers, by source.", "source"),
		signatureCapped: metrics.Counter("urnetwork_dnsedge_signature_capped_total",
			"Answers refused at signatures_per_second, by transport.", "transport"),
		rrlLimited: metrics.Counter("urnetwork_dnsedge_rrl_limited_total", "Responses RRL held back, by class and action.",
			"class", "action"),
		dropped:        metrics.Counter("urnetwork_dnsedge_dropped_total", "Packets answered with nothing, by reason.", "reason"),
		tcpRefused:     metrics.Counter("urnetwork_dnsedge_tcp_refused_total", "TCP connections closed at accept, by reason.", "reason"),
		tcpConnections: metrics.Gauge("urnetwork_dnsedge_tcp_connections", "TCP connections held now."),
		interfaceHealthy: metrics.Gauge("urnetwork_dnsedge_interface_healthy",
			"Whether an lb interface's address of a family is answered, by interface and family.", "interface", "family"),
		routerHealthy: metrics.Gauge("urnetwork_dnsedge_router_healthy",
			"Whether a router interface's address of a family is answered at mx hosts, by interface and family.", "interface", "family"),
		healthyHeld: metrics.Gauge("urnetwork_dnsedge_healthy_held",
			"Whether every address of a family failed and the last set is kept, by set and family.", "set", "family"),
		feedPolls:  metrics.Counter("urnetwork_dnsedge_feed_polls_total", "Feed polls, by what each came to.", "result"),
		selfChecks: metrics.Counter("urnetwork_dnsedge_self_checks_total", "Self-checks of a view or key set, by result.", "result"),
		reloadDiffs: metrics.Counter("urnetwork_dnsedge_reload_diffs_total",
			"Replaced snapshots' diffs, by what became of them.", "result"),
		snapshotWrites: metrics.Counter("urnetwork_dnsedge_snapshot_writes_total", "Writes of the local snapshot, by result.", "result"),
		routeProbes:    metrics.Counter("urnetwork_dnsedge_route_probes_total", "Route probes of the custom-host map, by result.", "result"),
		routeReports: metrics.Counter("urnetwork_dnsedge_route_reports_total",
			"Rounds' route-probe reports, by result.", "result"),
	}
}

// The closed label of an rcode.
func dnsRcodeLabel(rcode int) string {
	switch rcode {
	case dns.RcodeSuccess, dns.RcodeFormatError, dns.RcodeServerFailure, dns.RcodeNameError, dns.RcodeNotImplemented,
		dns.RcodeRefused:
		return dns.RcodeToString[rcode]
	case dns.RcodeBadVers:
		// miekg's table reads this value as BADSIG, TSIG's name for it, and this edge has no TSIG
		return dnsRcodeBadVersLabel
	}
	return dnsRcodeOtherLabel
}

// The closed label of why the feed's rows were refused.
func dnsFeedRefusedLabel(err error) string {
	switch {
	case errors.Is(err, ErrDnsSerialGap):
		return dnsFeedRefusedGap
	case errors.Is(err, ErrDnsSerialLower):
		return dnsFeedRefusedLower
	case errors.Is(err, ErrDnsFormatTooNew):
		return dnsFeedRefusedFormat
	case errors.Is(err, ErrDnsRowMalformed):
		return dnsFeedRefusedMalformed
	}
	return dnsFeedRefusedOther
}
