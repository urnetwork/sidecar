// §19.9's cohorts row and D-OPS-22 on evs (EVSB-M3-02): until a move tool exists, a metadata cluster at 80% raw or
// 70% inodes takes only what §20.7's storage limit accepts. The cluster's budget loop sets its at_limit flag in
// {nvb_<cluster>} from admin info (plan-EVSB-nvb-fields; budget_loop.go), and each evs process reads it with its
// allowance, keeping the last value while the key is absent (WriteBudgetClient.AtLimit). ClusterLimit answers from
// that flag with no I/O, so it sits on a request's path:
//
//   - a segment upload to a repo placed on a full cluster: 507 CLUSTER_FULL with Retry-After, after §20.7's own
//     QuotaRefusal and before the HDD share (upload_segment.go). A re-seed upload passes, as at the storage limit,
//     and a ?closure=1 upload is held to the closure bounds the storage limit holds it to (QuotaGate), past a
//     closure upload's size 507;
//   - step 5c (check_refs.go): what the storage limit refuses, a push naming a new segment or inline record that is
//     none of the maintenance it accepts, answers 507 CLUSTER_FULL with Retry-After once the head records it
//     (§11.20), after the network's own QuotaRefusal; deletion, erasure, a shred, CONSUME, BASE, a drop that uploads
//     no segment, and config and mailcfg pushes pass, and a CLOSURE's inline records spend its eraser's allowance
//     as at the limit.
//
// The flag is the cluster's, never the estate's: a placed repo never moves (owner decision 145), so free space on
// another cluster lifts nothing, and a network with repos on two clusters is refused only on the full one. A flag
// nobody published reads as not full, since a storage limit is soft (owner decisions 2, 10) and the budget loop
// keeps the last value it knew while admin info cannot be read.
//
// The first cluster's control plane (§19.9's first row: place/, proj/, projrows/, rev/, hold/ and the per-sidecar
// gkm/ objects) is counted apart, by the nightly pass's start, into urnetwork_filecluster_control_plane_bytes, which
// monitor's cohort signal projects beside the cluster's own growth (CountControlPlane).
//
// Safe for concurrent use.

package evsservice

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §19.8's series of the first cluster's control-plane bytes, with no network or repo label (D-OPS-8).
const fileClusterControlPlaneBytesMetricName = "urnetwork_filecluster_control_plane_bytes"

// The control-plane families the first metadata cluster holds for every cluster (§19.9's first row), by the key
// prefix their owners write them under: place/ (evs_repo_place.go), proj/ and projrows/ (config_rows_only.go), rev/
// (config_rev.go), hold/ (host_hold.go), and gkm's per-sidecar KeyPackages, ReaderKeys, Welcomes and delegation keys
// (gkmservice/objects.go). A group's gkm/ objects follow its repo's cluster, so they are its cohort's.
var fileClusterControlPlanePrefixes = []string{
	"place/",
	"proj/",
	"projrows/",
	"rev/",
	"hold/",
	"gkm/kp/",
	"gkm/rk/",
	"gkm/welcome/",
	"gkm/dkey/",
}

// Where a cluster's at_limit flag is read: *WriteBudgetClient meets it. Safe for concurrent use and free of I/O.
type ClusterAtLimitSource interface {
	// §19.9's line from the cluster's last allowance, kept while the key is absent.
	AtLimit(clusterId string) bool
}

// Tunables of the cohort limit.
type ClusterLimitSettings struct {
	// The wait a 507 CLUSTER_FULL carries as retry_after_ms and Retry-After: 10 min. The flag falls only as the
	// cluster's cohort deletes, or a move tool lands, so a sooner ask finds it standing; positive.
	RetryAfter time.Duration
	// Keys one LIST page of CountControlPlane asks for: 1000. Positive.
	ListLimit int
}

func DefaultClusterLimitSettings() *ClusterLimitSettings {
	return &ClusterLimitSettings{
		RetryAfter: 10 * time.Minute,
		ListLimit:  1000,
	}
}

// Settings a limit cannot work with.
var ErrClusterLimitSettings = errors.New("evs cluster limit settings invalid")

// ErrClusterLimitSettings for a value the limit cannot work with.
func (self *ClusterLimitSettings) Validate() error {
	if self.RetryAfter <= 0 || self.ListLimit <= 0 {
		return ErrClusterLimitSettings
	}
	return nil
}

// See the file header.
type ClusterLimit struct {
	source   ClusterAtLimitSource
	settings *ClusterLimitSettings
}

// The limit over source, which nil reads as never full. settings nil takes the defaults.
func NewClusterLimit(source ClusterAtLimitSource, settings *ClusterLimitSettings) (*ClusterLimit, error) {
	if settings == nil {
		settings = DefaultClusterLimitSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return &ClusterLimit{source: source, settings: settings}, nil
}

// The limit over host's write budget, the process's WriteBudgetClient, which reads each cluster's flag with its
// allowance: what an evs host hands EvsUploadDeps.ClusterLimit. A budget that keeps no flag reads never full.
func NewClusterLimitOfHost(host *sidecar.ServiceHost, settings *ClusterLimitSettings) (*ClusterLimit, error) {
	var source ClusterAtLimitSource
	if host != nil {
		source, _ = host.Budget.(ClusterAtLimitSource)
	}
	return NewClusterLimit(source, settings)
}

// Whether the metadata cluster stands at its cohort limit. A nil limit, or one with no source, is never full.
func (self *ClusterLimit) Full(clusterId string) bool {
	if self == nil || self.source == nil {
		return false
	}
	return self.source.AtLimit(clusterId)
}

// The wait a 507 carries.
func (self *ClusterLimit) RetryAfter() time.Duration {
	if self == nil {
		return DefaultClusterLimitSettings().RetryAfter
	}
	return self.settings.RetryAfter
}

// The refusal an upload answers at the cohort limit: 507 CLUSTER_FULL with retry_after_ms.
func (self *ClusterLimit) UploadRefusal() *protocol.EvsRefusalReply {
	return &protocol.EvsRefusalReply{
		Code:         protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL,
		RetryAfterMs: uint32(max(1, min(self.RetryAfter().Milliseconds(), int64(^uint32(0))))),
	}
}

// What one LIST of a cluster's control-plane families gave: their objects and bytes as LIST sized them.
type ControlPlaneCount struct {
	ClusterId   string
	ObjectCount int64
	ByteCount   int64
}

// The control-plane families on cluster (see the file header), from one LIST of each prefix, paged by listLimit.
// The first error stops it, and what it counted before stands beside the error.
func CountControlPlane(ctx context.Context, cluster sidecar.BlobCluster, listLimit int) (*ControlPlaneCount, error) {
	count := &ControlPlaneCount{ClusterId: cluster.ClusterId()}
	if listLimit <= 0 {
		return count, ErrClusterLimitSettings
	}
	for _, prefix := range fileClusterControlPlanePrefixes {
		startAfter := ""
		for {
			objects, more, err := cluster.List(ctx, prefix, startAfter, listLimit)
			if err != nil {
				return count, err
			}
			for _, object := range objects {
				count.ObjectCount += 1
				count.ByteCount += object.ByteCount
				startAfter = object.Key
			}
			if !more || len(objects) == 0 {
				break
			}
		}
	}
	return count, nil
}

// Counts the first metadata cluster's control plane and sets §19.8's gauges through host.Metrics: what the nightly
// pass's start runs once a day. A host with no metrics or clusters publishes nothing. The count, or the first error.
func PublishControlPlane(ctx context.Context, host *sidecar.ServiceHost, settings *ClusterLimitSettings) (*ControlPlaneCount, error) {
	if settings == nil {
		settings = DefaultClusterLimitSettings()
	}
	if host == nil || host.Blobs == nil {
		return nil, errors.New("the control-plane count needs a host with Blobs")
	}
	clusterIds := host.Blobs.MetadataClusterIds()
	if len(clusterIds) == 0 {
		return nil, sidecar.ErrBlobClusterUnknown
	}
	cluster, err := host.Blobs.Cluster(clusterIds[0])
	if err != nil {
		return nil, err
	}
	count, err := CountControlPlane(ctx, cluster, settings.ListLimit)
	if err != nil {
		// a partial count is no level: the gauges keep their last value
		return count, err
	}
	if host.Metrics != nil {
		host.Metrics.Gauge(fileClusterControlPlaneBytesMetricName,
			"The first metadata cluster's control-plane bytes (place/, proj/, projrows/, rev/, hold/, per-sidecar gkm/), as LIST sizes them.",
			"cluster").Set(float64(count.ByteCount), count.ClusterId)
	}
	return count, nil
}
