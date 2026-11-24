// ComputeServiceLog: §14.2's Logs row. One line a request: the engine's own request id, the route's name, the
// status and code, the latency, and the opaque compute row ids its handler names (ComputeRequest.NoteRowIds). Never a
// body, an envelope byte, a header value, a query, a path value or an address (IC-13, I-13): the line is built from
// those fields alone, so a handler has nothing else to put on it. A route flagged NoLog, POST /v1/search/authorize,
// leaves no line at all, its counts going to the metrics alone (§21.5), so no line ever joins a search to its network.
//
// The metrics are §19.8's for the block, by route name, status and code, each a closed set.

package computeservice

import (
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// One line.
type ComputeServiceLogEntry struct {
	Time time.Time
	// The engine's own id for the request, minted as it arrived; never one a caller sent.
	RequestId sidecar.Id
	// The route's name, its method and pattern, which hold no id; "unrouted" for a path no route takes.
	Route    string
	Status   int
	Code     ComputeRefusalCode
	Duration time.Duration
	// The compute rows the handler named: operation keys, charges, enclaves, by their opaque ids.
	RowIds []sidecar.Id
}

// Where the lines go: the host's log pipeline. Write never blocks a request on I/O of its own. Safe for concurrent
// use.
type ComputeServiceLog interface {
	Write(entry *ComputeServiceLogEntry)
}

// The lines through a Logger, one Info line a request.
type loggerComputeServiceLog struct {
	log sidecar.Logger
}

// The service log through log.
func NewLoggerComputeServiceLog(log sidecar.Logger) ComputeServiceLog {
	return &loggerComputeServiceLog{log: log}
}

// One line: time, request id, route, status and code, duration, row ids.
func (self *loggerComputeServiceLog) Write(entry *ComputeServiceLogEntry) {
	rowIds := make([]string, len(entry.RowIds))
	for i, rowId := range entry.RowIds {
		rowIds[i] = sidecar.EvsKeyId(rowId)
	}
	code := string(entry.Code)
	if code == "" {
		code = "-"
	}
	self.log.Infof("[compute] %d %s %s %d %s ms=%d rows=%s",
		entry.Time.UnixMilli(), sidecar.EvsKeyId(entry.RequestId), entry.Route, entry.Status, code,
		entry.Duration.Milliseconds(), strings.Join(rowIds, ","))
}

// The route name a request no route takes counts and logs under: one closed label, never its path (I-13).
const computeUnroutedRouteName = "unrouted"

// The engine's series. Labels come from closed sets: a route's name, a status, a code, an alarm's kind.
type computeMetrics struct {
	requests   sidecar.MetricsCounter
	refusals   sidecar.MetricsCounter
	gateClosed sidecar.MetricsCounter
	seconds    sidecar.MetricsHistogram
	// streams opened, by route
	streams sidecar.MetricsCounter
	// a handler's refusal with a code the table does not have, a stream that could not clear its deadlines
	alarms sidecar.MetricsCounter
}

// Declares the series.
func newComputeMetrics(metrics sidecar.Metrics) *computeMetrics {
	return &computeMetrics{
		requests:   metrics.Counter("urnetwork_compute_requests_total", "compute requests by route and status", "route", "status"),
		refusals:   metrics.Counter("urnetwork_compute_refusals_total", "compute refusals by route and code", "route", "code"),
		gateClosed: metrics.Counter("urnetwork_compute_gate_closed_total", "compute requests the gate answered 503", "route"),
		seconds:    metrics.Histogram("urnetwork_compute_request_seconds", "compute request time by route", nil, "route"),
		streams:    metrics.Counter("urnetwork_compute_streams_total", "compute streams opened, by route", "route"),
		alarms:     metrics.Counter("urnetwork_compute_alarms_total", "compute faults that alarm, by kind", "kind"),
	}
}

// Counts one finished request.
func (self *computeMetrics) finish(route string, status int, code ComputeRefusalCode, duration time.Duration) {
	self.requests.Add(1, route, strconv.Itoa(status))
	if code != "" {
		self.refusals.Add(1, route, string(code))
	}
	self.seconds.Observe(duration.Seconds(), route)
}
