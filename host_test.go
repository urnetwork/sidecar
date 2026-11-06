//go:build !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"
	"slices"
	"testing"

	"github.com/urnetwork/connect"
)

// A stand-in for each interface, so a ServiceHost assembles and an engine can be declared against it.
// sidecartest owns the fakes engines test on; these only prove the shapes.
type (
	hostAuthenticator struct{}
	hostQuota         struct{}
	hostQuotaLease    struct{}
	hostMetrics       struct{}
	hostMetric        struct{}
	hostTasks         struct{}
	hostRedis         struct{ Redis }
	hostBlobStore     struct{}
	hostPush          struct{}
	hostClientSource  struct{}
)

func (self hostAuthenticator) Authenticate(ctx context.Context, audience string, jwt string) (*Principal, error) {
	if audience == "" {
		return nil, ErrAuthenticationRefused
	}
	principal := &Principal{NetworkId: connect.NewId(), ClientId: connect.NewId(), Audience: audience}
	if err := principal.Validate(); err != nil {
		return nil, err
	}
	return principal, nil
}

func (self hostQuota) Limits(ctx context.Context, networkId connect.Id) (*QuotaLimits, error) {
	return &QuotaLimits{}, nil
}

func (self hostQuota) CountRate(ctx context.Context, networkId connect.Id, keyAmounts map[string]int64, debitId connect.Id) (*QuotaRefusal, error) {
	return nil, nil
}

func (self hostQuota) Lease(ctx context.Context, networkId connect.Id, meter string) (QuotaLease, *QuotaRefusal, error) {
	return hostQuotaLease{}, nil, nil
}

func (self hostQuota) ReportUsage(ctx context.Context, batch *UsageBatch) error {
	return nil
}

func (self hostQuota) OverLimit(ctx context.Context) (*QuotaOverLimit, error) {
	return &QuotaOverLimit{}, nil
}

func (self hostQuotaLease) Spend(byteCount int64) bool {
	return true
}

func (self hostQuotaLease) Close() {
}

func (self hostMetrics) Counter(name string, help string, labelNames ...string) MetricsCounter {
	return hostMetric{}
}

func (self hostMetrics) Gauge(name string, help string, labelNames ...string) MetricsGauge {
	return hostMetric{}
}

func (self hostMetrics) Histogram(name string, help string, bucketUpperBounds []float64, labelNames ...string) MetricsHistogram {
	return hostMetric{}
}

func (self hostMetric) Add(value float64, labelValues ...string) {
}

func (self hostMetric) Set(value float64, labelValues ...string) {
}

func (self hostMetric) Observe(value float64, labelValues ...string) {
}

func (self hostTasks) Register(name string, function TaskFunction) {
}

func (self hostTasks) Schedule(ctx context.Context, request *TaskRequest) error {
	return nil
}

func (self hostBlobStore) Cluster(clusterId string) (BlobCluster, error) {
	return nil, ErrBlobClusterUnknown
}

func (self hostBlobStore) FirstCluster() (BlobCluster, error) {
	return nil, ErrBlobClusterUnknown
}

func (self hostBlobStore) SegmentCluster() (BlobCluster, error) {
	return nil, ErrBlobClusterUnknown
}

func (self hostBlobStore) MetadataClusterIds() []string {
	return []string{"meta-1", "meta-2"}
}

func (self hostBlobStore) NewRepoClusterId() string {
	return "meta-2"
}

func (self hostPush) Hint(ctx context.Context, clientIds []connect.Id, hint *ClientHint) error {
	return nil
}

func (self hostPush) HintSidecars(ctx context.Context, sidecarIds []connect.Id, hint *ClientHint) error {
	return nil
}

func (self hostClientSource) ServiceClient(ctx context.Context, clientIndex int) (*ServiceClientAuth, error) {
	return &ServiceClientAuth{}, nil
}

type hostHttpEngine struct{}

func (self hostHttpEngine) Ready() bool {
	return true
}

func (self hostHttpEngine) Drain() {
}

func (self hostHttpEngine) Close() {
}

func (self hostHttpEngine) Handler() http.Handler {
	return http.NotFoundHandler()
}

type hostStreamEngine struct {
	hostHttpEngine
}

func (self hostStreamEngine) Serve(listener net.Listener) error {
	return nil
}

// No Handler and no Serve: an engine that dials out and listens on nothing, as smtpedge does (§14.9).
type hostDialOutEngine struct{}

func (self hostDialOutEngine) Ready() bool {
	return true
}

func (self hostDialOutEngine) Drain() {
}

func (self hostDialOutEngine) Close() {
}

var (
	_ Authenticator       = hostAuthenticator{}
	_ Quota               = hostQuota{}
	_ QuotaLease          = hostQuotaLease{}
	_ Metrics             = hostMetrics{}
	_ MetricsCounter      = hostMetric{}
	_ MetricsGauge        = hostMetric{}
	_ MetricsHistogram    = hostMetric{}
	_ Tasks               = hostTasks{}
	_ Redis               = hostRedis{}
	_ BlobStore           = hostBlobStore{}
	_ Push                = hostPush{}
	_ ServiceClientSource = hostClientSource{}
	_ HttpEngine          = hostHttpEngine{}
	_ StreamEngine        = hostStreamEngine{}
	// stops the build if Engine gains a member that smtpedge has nothing to give
	_ Engine = hostDialOutEngine{}
)

// §4.5's eight fields, named as engines reach them (§14.9's NewSmtpEdgeService takes *ServiceHost).
func TestServiceHostAssembles(t *testing.T) {
	host := &ServiceHost{
		Authenticator: hostAuthenticator{},
		Quota:         hostQuota{},
		Metrics:       hostMetrics{},
		Tasks:         hostTasks{},
		Redis:         hostRedis{},
		Blobs:         hostBlobStore{},
		Push:          hostPush{},
		ServiceClient: hostClientSource{},
	}

	ctx := context.Background()
	if _, err := host.Authenticate(ctx, "evs", "synthetic-token"); err != nil {
		t.Errorf("a token naming its network and client: %v", err)
	}
	if _, err := host.Blobs.Cluster("no-such-cluster"); !errors.Is(err, ErrBlobClusterUnknown) {
		t.Errorf("an unknown cluster: %v", err)
	}
}

// §20.7's signatures, verbatim. Assigning to these stops the build if one drifts, since §20.7's text,
// not this package, is what server's implementation is written from.
var (
	_ func(Quota, context.Context, connect.Id) (*QuotaLimits, error)                                = Quota.Limits
	_ func(Quota, context.Context, connect.Id, map[string]int64, connect.Id) (*QuotaRefusal, error) = Quota.CountRate
	_ func(Quota, context.Context, connect.Id, string) (QuotaLease, *QuotaRefusal, error)           = Quota.Lease
	_ func(Quota, context.Context, *UsageBatch) error                                               = Quota.ReportUsage
	_ func(Quota, context.Context) (*QuotaOverLimit, error)                                         = Quota.OverLimit
	_ func(QuotaLease, int64) bool                                                                  = QuotaLease.Spend
	_ func(QuotaLease)                                                                              = QuotaLease.Close
)

// Hints fan out with one body, to the clients §11.10's leases name and the sidecars §10.6's rows name.
var (
	_ func(Push, context.Context, []connect.Id, *ClientHint) error = Push.Hint
	_ func(Push, context.Context, []connect.Id, *ClientHint) error = Push.HintSidecars
)

// §9.6 reads only the spent mark and evs reads both, so a network can be at its storage limit and not
// spent: the two stay two maps, and this stops the build if they become one.
var _ = QuotaOverLimit{
	StorageNetworkIdRefusals: map[connect.Id]*QuotaRefusal{},
	SpentNetworkIdRefusals:   map[connect.Id]*QuotaRefusal{},
}

// §20.5 defines a limit of 0 as not included. An absent key reads 0 only while the values are plain
// numbers, so this stops the build if they become anything that could read as unset.
var _ map[string]int64 = QuotaLimits{}.Limits

// The exported fields of a struct, in order.
func structFieldNames(value any) []string {
	names := []string{}
	valueType := reflect.TypeOf(value)
	for i := 0; i < valueType.NumField(); i += 1 {
		names = append(names, valueType.Field(i).Name)
	}
	return names
}

// §2.8's evs-9 lists transfer bytes per caller network and stored-byte deltas per repo network and no
// more, and this crosses to server, so a field added here is a metadata change that needs its row
// first (I-18).
func TestUsageEventCarriesOnlyWhatEvs9Lists(t *testing.T) {
	want := []string{"NetworkId", "Meter", "TransferByteCount", "StoredByteDelta"}
	if names := structFieldNames(UsageEvent{}); !slices.Equal(names, want) {
		t.Errorf("fields %q, want %q", names, want)
	}
	want = []string{"BatchId", "Producer", "WindowStart", "Events"}
	if names := structFieldNames(UsageBatch{}); !slices.Equal(names, want) {
		t.Errorf("fields %q, want %q", names, want)
	}
}

// A host finds what to serve by asking, so an engine with neither is one it starts and serves nothing
// for, and the two kinds stay told apart.
func TestAHostAsksAnEngineWhatItServes(t *testing.T) {
	for _, c := range []struct {
		name       string
		engine     Engine
		wantHttp   bool
		wantStream bool
	}{
		{name: "dial out", engine: hostDialOutEngine{}},
		{name: "http", engine: hostHttpEngine{}, wantHttp: true},
		{name: "http and stream", engine: hostStreamEngine{}, wantHttp: true, wantStream: true},
	} {
		if _, ok := c.engine.(HttpEngine); ok != c.wantHttp {
			t.Errorf("%s: HttpEngine %v", c.name, ok)
		}
		if _, ok := c.engine.(StreamEngine); ok != c.wantStream {
			t.Errorf("%s: StreamEngine %v", c.name, ok)
		}
	}
}
