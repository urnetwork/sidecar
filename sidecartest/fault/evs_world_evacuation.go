// The evs world's evacuation steps beyond Evacuate (evs_world.go), for FS-53's and FS-60's schedules (EVSB-M2-11): a
// run with the evacuator's settings as a schedule adjusts them and its result read, a run a fault the schedule armed
// kills, and what the clusters' containers and batches hold, read under an inspecting context. Each run is one
// evacuator as a taskworker run builds one, on the repo's cluster, and none is run again here: a schedule that kills a
// run names the run that resumes it, as taskworker's next hourly run would.

package fault

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The prefixes a schedule reads the containers and batches under (§11.13's evacuation objects): batches, parcels and
// log pages on the repo's metadata cluster, packs on the segment cluster, and the entries listing what each container
// holds.
const (
	evsWorldBatchPrefix  = "pb/"
	evsWorldParcelPrefix = "hp/"
	evsWorldPackPrefix   = "pack/"
	evsWorldEntryPrefix  = "pidx/"
	evsWorldLogPrefix    = "log/"
)

// One evacuation run on the repo's cluster, adjust changing the evacuator's settings where it is not nil.
func (self *EvsWorld) evacuateOnce(ctx context.Context, net *Net, adjust func(settings *evsservice.EvacuatorSettings)) (*evsservice.EvacuationResult, error) {
	first, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	settings := evsservice.DefaultEvacuatorSettings()
	if adjust != nil {
		adjust(settings)
	}
	evacuator, err := evsservice.NewEvacuator(net.Host(), &evsservice.EvacuatorDeps{Settings: settings})
	if err != nil {
		return nil, err
	}
	return evacuator.Run(ctx, first.ClusterId())
}

// A step action: one evacuation run, adjust changing the evacuator's settings where it is not nil, which must end
// clean; check, where it is not nil, reads its result.
func (self *EvsWorld) EvacuateWith(adjust func(settings *evsservice.EvacuatorSettings), check func(result *evsservice.EvacuationResult) error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		result, err := self.evacuateOnce(ctx, net, adjust)
		if err != nil {
			return fmt.Errorf("an evacuation run: %w (%+v)", err, result)
		}
		if check == nil {
			return nil
		}
		if err := check(result); err != nil {
			return fmt.Errorf("an evacuation run: %w (%+v)", err, result)
		}
		return nil
	}
}

// A step action: one evacuation run that a plan the schedule armed before it kills, which must end in that plan's
// error. adjust changes the evacuator's settings where it is not nil. A plan that never fires fails the schedule at its
// end, as every unfired plan does.
func (self *EvsWorld) EvacuateKilled(adjust func(settings *evsservice.EvacuatorSettings)) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		result, err := self.evacuateOnce(ctx, net, adjust)
		if err == nil {
			return fmt.Errorf("an evacuation run the schedule killed ended clean: %+v", result)
		}
		if errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	}
}

// The keys under prefix on the repo's metadata cluster, or on the segment cluster where segment is true, read under an
// inspecting context, so a read takes no fault and counts toward no plan.
func (self *EvsWorld) StoredKeys(ctx context.Context, net *Net, segment bool, prefix string) ([]string, error) {
	inspect := sidecartest.InspectContext(ctx)
	var cluster sidecar.BlobCluster
	if segment {
		segmentCluster, err := net.Host().Blobs.SegmentCluster()
		if err != nil {
			return nil, err
		}
		cluster = segmentCluster
	} else {
		clusterId, err := NewStoreView(net, nil).RepoClusterId(inspect, self.RepoId)
		if err != nil {
			return nil, err
		}
		metadataCluster, err := net.Host().Blobs.Cluster(clusterId)
		if err != nil {
			return nil, err
		}
		cluster = metadataCluster
	}
	keys := []string{}
	startAfter := ""
	for {
		objects, more, err := cluster.List(inspect, prefix, startAfter, 1000)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			keys = append(keys, object.Key)
			startAfter = object.Key
		}
		if !more || len(objects) == 0 {
			return keys, nil
		}
	}
}

// A step action: the cluster holds count keys under prefix, the segment cluster where segment is true and the repo's
// metadata cluster otherwise.
func (self *EvsWorld) ExpectStoredKeyCount(what string, segment bool, prefix string, count int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		keys, err := self.StoredKeys(ctx, net, segment, prefix)
		if err != nil {
			return err
		}
		if len(keys) != count {
			return fmt.Errorf("%s: %d keys under %s, want %d: %v", what, len(keys), prefix, count, keys)
		}
		return nil
	}
}
