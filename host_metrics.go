//go:build !sidecar_http && !ios_extension

// ServiceHost.Metrics: prometheus in server, kept behind this interface so it stays out of this
// module (§4.5). A metric's name is urnetwork_<svc>_*. Its labels are route template, result, code,
// cluster, tier and fixed vocabularies of that kind (§19.8), never a network, repo, client or
// address, so a label value comes from a closed set, not a request (I-13).
//
// The interfaces are operator-core's (owner decision 251).

package sidecar

import (
	operator "github.com/urnetwork/operator-core"
)

// Declares metrics. A second kind or label set for a name is the caller's bug, and the host panics.
type Metrics = operator.Metrics

// A declared counter.
type MetricsCounter = operator.MetricsCounter

// A declared gauge.
type MetricsGauge = operator.MetricsGauge

// A declared histogram.
type MetricsHistogram = operator.MetricsHistogram
