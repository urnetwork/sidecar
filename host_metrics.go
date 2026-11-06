//go:build !sidecar_http

// ServiceHost.Metrics: prometheus in server, kept behind this interface so it stays out of this
// module (§4.5). A metric's name is urnetwork_<svc>_*. Its labels are route template, result, code,
// cluster, tier and fixed vocabularies of that kind (§19.8), never a network, repo, client or
// address, so a label value comes from a closed set, not a request (I-13).

package sidecar

// Declares metrics. Declaring a name again with the same kind and labels returns the same metric, so
// two engines in one process, or a restarted one in a test, can share a name. A second kind or label
// set for a name is the caller's bug, and the host panics, as prometheus's MustRegister does.
type Metrics interface {
	Counter(name string, help string, labelNames ...string) MetricsCounter
	Gauge(name string, help string, labelNames ...string) MetricsGauge
	// bucketUpperBounds in seconds or bytes, as the metric's name says. nil takes the host's default.
	Histogram(name string, help string, bucketUpperBounds []float64, labelNames ...string) MetricsHistogram
}

// labelValues follow labelNames in order, here and in the two below. Add takes a value of zero or
// more.
type MetricsCounter interface {
	Add(value float64, labelValues ...string)
}

type MetricsGauge interface {
	Set(value float64, labelValues ...string)
}

type MetricsHistogram interface {
	Observe(value float64, labelValues ...string)
}
