package dnsservice

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
)

// Counts declarations. sidecartest's fake holds the naming rules, and a test here cannot import it,
// since it imports this package.
type declaredMetrics struct {
	names []string
}

type noMetric struct{}

func (self noMetric) Add(value float64, labelValues ...string)     {}
func (self noMetric) Set(value float64, labelValues ...string)     {}
func (self noMetric) Observe(value float64, labelValues ...string) {}

func (self *declaredMetrics) Counter(name string, help string, labelNames ...string) sidecar.MetricsCounter {
	self.names = append(self.names, name)
	return noMetric{}
}

func (self *declaredMetrics) Gauge(name string, help string, labelNames ...string) sidecar.MetricsGauge {
	self.names = append(self.names, name)
	return noMetric{}
}

func (self *declaredMetrics) Histogram(name string, help string, bucketUpperBounds []float64, labelNames ...string) sidecar.MetricsHistogram {
	self.names = append(self.names, name)
	return noMetric{}
}

func TestDnsMetricsAreNamedForTheEdge(t *testing.T) {
	metrics := &declaredMetrics{}
	newDnsMetrics(metrics)
	if len(metrics.names) == 0 {
		t.Fatal("no metric declared")
	}
	for _, name := range metrics.names {
		if !strings.HasPrefix(name, "urnetwork_dnsedge_") {
			t.Errorf("metric %s", name)
		}
	}
}

// An rcode off the wire reaches a label only through this closed set.
func TestDnsRcodeLabelsAreClosed(t *testing.T) {
	seen := []string{}
	for rcode := range 4096 {
		if label := dnsRcodeLabel(rcode); !slices.Contains(seen, label) {
			seen = append(seen, label)
		}
	}
	slices.Sort(seen)
	want := []string{"BADVERS", "FORMERR", "NOERROR", "NOTIMP", "NXDOMAIN", dnsRcodeOtherLabel, "REFUSED", "SERVFAIL"}
	slices.Sort(want)
	if !slices.Equal(seen, want) {
		t.Errorf("labels %v", seen)
	}
	if dnsRcodeLabel(dns.RcodeNameError) != "NXDOMAIN" {
		t.Errorf("NXDOMAIN reads %s", dnsRcodeLabel(dns.RcodeNameError))
	}
}

func TestDnsFeedRefusedLabels(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{err: fmt.Errorf("wrapped: %w", ErrDnsSerialGap), want: dnsFeedRefusedGap},
		{err: fmt.Errorf("wrapped: %w", ErrDnsSerialLower), want: dnsFeedRefusedLower},
		{err: fmt.Errorf("wrapped: %w", ErrDnsFormatTooNew), want: dnsFeedRefusedFormat},
		{err: fmt.Errorf("wrapped: %w", ErrDnsRowMalformed), want: dnsFeedRefusedMalformed},
		{err: errors.New("anything else"), want: dnsFeedRefusedOther},
	}
	for _, c := range cases {
		if label := dnsFeedRefusedLabel(c.err); label != c.want {
			t.Errorf("%v: %s", c.err, label)
		}
	}
}
