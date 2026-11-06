//go:build !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

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
	return &Principal{Audience: audience}, nil
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
	// an engine that dials out and listens on nothing, as smtpedge does
	_ Engine = hostHttpEngine{}
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
	if _, err := host.Authenticator.Authenticate(ctx, "", "synthetic-token"); !errors.Is(err, ErrAuthenticationRefused) {
		t.Errorf("an empty audience: %v", err)
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

// §20.7's fields, as a producer fills them.
func TestUsageBatchCarriesWhatEvs9Lists(t *testing.T) {
	networkId := connect.NewId()
	batch := &UsageBatch{
		BatchId:     connect.NewId(),
		Producer:    "evs",
		WindowStart: time.Unix(0, 0),
		Events: []*UsageEvent{
			{NetworkId: networkId, Meter: "evs", TransferByteCount: 1024},
			{NetworkId: networkId, Meter: "evs", StoredByteDelta: -1024},
		},
	}
	if err := (hostQuota{}).ReportUsage(context.Background(), batch); err != nil {
		t.Error(err)
	}
}

// §9.6 reads only the spent mark, and evs both: a network can be at its storage limit and not spent.
func TestQuotaOverLimitKeepsTheTwoReasonsApart(t *testing.T) {
	networkId := connect.NewId()
	overLimit := &QuotaOverLimit{
		StorageNetworkIdRefusals: map[connect.Id]*QuotaRefusal{networkId: {LimitKey: "storage"}},
		SpentNetworkIdRefusals:   map[connect.Id]*QuotaRefusal{},
	}
	if _, spent := overLimit.SpentNetworkIdRefusals[networkId]; spent {
		t.Error("a network over its storage limit reads as spent, which would refuse its sockets")
	}
	if refusal := overLimit.StorageNetworkIdRefusals[networkId]; refusal.LimitKey != "storage" {
		t.Errorf("refusal %+v", refusal)
	}
}

// Hints fan out with one body, to the clients §11.10's leases name and the sidecars §10.6's rows name.
func TestPushHintTakesManyClientsOrSidecars(t *testing.T) {
	ids := []connect.Id{connect.NewId(), connect.NewId()}
	hint := &ClientHint{Topic: "evs:synthetic", Version: 1793836800123457024, Kind: 0x1401, Body: []byte{1}}
	if err := (hostPush{}).Hint(context.Background(), ids, hint); err != nil {
		t.Error(err)
	}
	if err := (hostPush{}).HintSidecars(context.Background(), ids, hint); err != nil {
		t.Error(err)
	}
}

// Engine has no Handler: an engine that serves nothing inbound must still fit, as §14.9's does.
func TestEngineNeedsNoHandlerOrListener(t *testing.T) {
	var engine Engine = hostHttpEngine{}
	if !engine.Ready() {
		t.Error("not ready")
	}
	engine.Drain()
	engine.Close()
	// a host finds what to serve by asking
	if _, ok := engine.(HttpEngine); !ok {
		t.Error("an http engine is no HttpEngine")
	}
	if _, ok := engine.(StreamEngine); ok {
		t.Error("an http engine is a StreamEngine")
	}
}
