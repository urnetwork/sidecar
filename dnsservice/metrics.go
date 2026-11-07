// urnetwork_dnsedge_* (§19.8): what an edge counts, declared once from ServiceHost.Metrics. Labels
// carry only an rcode and a reason, each from the closed sets here and never from a request, so no
// name, address or network reaches a metric (I-13, dns-2).

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
}

// Declares the families. Two edges in one process share them, as Metrics allows.
func newDnsMetrics(metrics sidecar.Metrics) *dnsMetrics {
	return &dnsMetrics{
		answers:        metrics.Counter("urnetwork_dnsedge_answers_total", "Answers sent, by rcode.", "rcode"),
		feedRefusals:   metrics.Counter("urnetwork_dnsedge_feed_refused_total", "Rows and snapshots refused, by reason.", "reason"),
		withheldRrsets: metrics.Gauge("urnetwork_dnsedge_withheld_rrsets", "RRsets held in the view and not answered."),
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
