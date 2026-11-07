// ServiceHost.Metrics in memory, with prometheus's refusals: a name redeclared with another kind or
// label set panics, as MustRegister does, and a wrong number of label values panics, as
// WithLabelValues does. It also holds what prometheus cannot check: a metric is named
// urnetwork_<svc>_*, and a label's value comes from a closed set, never a request (I-13), so a value
// shaped like an id or an address is a violation.

package sidecartest

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

var metricNamePattern = regexp.MustCompile(`^urnetwork_[a-z0-9]+_[a-z0-9_]+$`)

// A ULID, a UUID, an IPv4 address or an IPv6 one: an identity where a fixed vocabulary belongs.
var metricIdentityPattern = regexp.MustCompile(
	`^[0-9A-HJKMNP-TV-Z]{26}$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$|^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]*:[0-9a-fA-F:]*$`,
)

type FakeMetricsSettings struct {
	// Told each rule a caller broke, as it happens. nil: Violations alone holds them.
	Report func(violation string)
}

func DefaultFakeMetricsSettings() *FakeMetricsSettings {
	return &FakeMetricsSettings{}
}

type fakeMetricKind string

const (
	fakeMetricCounter   fakeMetricKind = "counter"
	fakeMetricGauge     fakeMetricKind = "gauge"
	fakeMetricHistogram fakeMetricKind = "histogram"
)

type fakeMetric struct {
	metrics    *FakeMetrics
	name       string
	kind       fakeMetricKind
	labelNames []string
	// by label values joined with a unit separator
	values map[string]float64
	counts map[string]int
}

type FakeMetrics struct {
	settings *FakeMetricsSettings

	stateLock  sync.Mutex
	metrics    map[string]*fakeMetric
	violations []string
}

func NewFakeMetrics(settings *FakeMetricsSettings) *FakeMetrics {
	if settings == nil {
		settings = DefaultFakeMetricsSettings()
	}
	return &FakeMetrics{settings: settings, metrics: map[string]*fakeMetric{}}
}

func (self *FakeMetrics) violateWithLock(violation string) {
	self.violations = append(self.violations, violation)
	if self.settings.Report != nil {
		self.settings.Report(violation)
	}
}

// Every rule a caller broke.
func (self *FakeMetrics) Violations() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.violations)
}

func (self *FakeMetrics) declare(name string, kind fakeMetricKind, labelNames []string) *fakeMetric {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !metricNamePattern.MatchString(name) {
		self.violateWithLock(fmt.Sprintf("metric %q is not urnetwork_<svc>_*", name))
	}
	if metric, ok := self.metrics[name]; ok {
		if metric.kind != kind || !slices.Equal(metric.labelNames, labelNames) {
			panic(fmt.Sprintf("metric %q redeclared: a %s of %v, then a %s of %v", name, metric.kind, metric.labelNames, kind, labelNames))
		}
		return metric
	}
	metric := &fakeMetric{
		metrics:    self,
		name:       name,
		kind:       kind,
		labelNames: slices.Clone(labelNames),
		values:     map[string]float64{},
		counts:     map[string]int{},
	}
	self.metrics[name] = metric
	return metric
}

func (self *FakeMetrics) Counter(name string, help string, labelNames ...string) sidecar.MetricsCounter {
	return &fakeMetricsCounter{metric: self.declare(name, fakeMetricCounter, labelNames)}
}

func (self *FakeMetrics) Gauge(name string, help string, labelNames ...string) sidecar.MetricsGauge {
	return &fakeMetricsGauge{metric: self.declare(name, fakeMetricGauge, labelNames)}
}

func (self *FakeMetrics) Histogram(name string, help string, bucketUpperBounds []float64, labelNames ...string) sidecar.MetricsHistogram {
	return &fakeMetricsHistogram{metric: self.declare(name, fakeMetricHistogram, labelNames)}
}

func metricSeries(labelValues []string) string {
	return strings.Join(labelValues, "\x1f")
}

// Applies change to one series, with the label checks every write goes through.
func (self *fakeMetric) update(labelValues []string, change func(series string)) {
	if len(labelValues) != len(self.labelNames) {
		panic(fmt.Sprintf("metric %q: %d label values for labels %v", self.name, len(labelValues), self.labelNames))
	}
	self.metrics.stateLock.Lock()
	defer self.metrics.stateLock.Unlock()
	for index, value := range labelValues {
		if metricIdentityPattern.MatchString(value) {
			self.metrics.violateWithLock(fmt.Sprintf("metric %q: label %s holds an identity (I-13)", self.name, self.labelNames[index]))
		}
	}
	change(metricSeries(labelValues))
}

type fakeMetricsCounter struct {
	metric *fakeMetric
}

func (self *fakeMetricsCounter) Add(value float64, labelValues ...string) {
	if value < 0 {
		panic(fmt.Sprintf("counter %q: Add of %v", self.metric.name, value))
	}
	self.metric.update(labelValues, func(series string) {
		self.metric.values[series] += value
	})
}

type fakeMetricsGauge struct {
	metric *fakeMetric
}

func (self *fakeMetricsGauge) Set(value float64, labelValues ...string) {
	self.metric.update(labelValues, func(series string) {
		self.metric.values[series] = value
	})
}

type fakeMetricsHistogram struct {
	metric *fakeMetric
}

func (self *fakeMetricsHistogram) Observe(value float64, labelValues ...string) {
	self.metric.update(labelValues, func(series string) {
		self.metric.values[series] += value
		self.metric.counts[series] += 1
	})
}

// A counter's or gauge's value, or a histogram's sum: zero for a series never written.
func (self *FakeMetrics) Value(name string, labelValues ...string) float64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	metric, ok := self.metrics[name]
	if !ok {
		return 0
	}
	return metric.values[metricSeries(labelValues)]
}

// How many times a histogram observed a series.
func (self *FakeMetrics) ObservationCount(name string, labelValues ...string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	metric, ok := self.metrics[name]
	if !ok {
		return 0
	}
	return metric.counts[metricSeries(labelValues)]
}

// Every metric's name and label values, for CC4's scan.
func (self *FakeMetrics) Dump() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lines := []string{}
	for _, name := range slices.Sorted(maps.Keys(self.metrics)) {
		metric := self.metrics[name]
		for _, series := range slices.Sorted(maps.Keys(metric.values)) {
			lines = append(lines, name+" "+strings.ReplaceAll(series, "\x1f", " "))
		}
	}
	return lines
}
