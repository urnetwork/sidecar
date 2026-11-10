// §11.12's reconciler (the log first row; EVS1-M2-19): taskworker's daily job evs.reconcile, a walk of every repo/
// on every metadata cluster, so the state the access log records is the state repo/ shows even when a device was
// killed between filing its statement and calling the route, and every shred a lost queue dropped is queued again.
//
//	apply  the newest projection's RepoDelete a repo/ lacks is applied as DELETE would apply it (decideDelete), and a
//	       projected RepoRestore of the deletion repo/ shows as restore would (decideRestore), each P0 lifecycle
//	queue  each deleted repo's start, 7 d 10 min after its RepoDelete's entry, and each shredding repo's shred, under
//	       the shred's once keys (shred.go)
//
// The walk lists repo/ a page at a time and reads each object from the cluster. A repo/ that names no network is
// held to plan-EVSB-repo-network: nothing is applied to it, though a shred it already shows is queued, which keeps
// its ciphertext under step 4's hold rule. A repo whose projection cannot be read is left as it is, and the walk goes
// on. Not built: a checkpoint between pages (connect/CODESTYLE.md's bounded passes), so a walk killed midway begins
// again at the next run.

package evsservice

import (
	"context"
	"errors"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The job's name in taskworker's registry.
const EvsReconcileTaskName = "evs.reconcile"

// What the reconciler runs on beyond its host.
type EvsReconcileDeps struct {
	// The newest projection's RepoDelete of each repo. nil applies nothing, the walk only queueing shreds.
	Deletions EvsRepoDeletionSource
	// nil: the defaults.
	Settings *EvsSettings
	// nil discards.
	Log sidecar.Logger
}

// What one walk did, for its log line and a test.
type EvsReconcileCounts struct {
	// repo/ objects read.
	Repos int
	// Statements applied: deletions and restores.
	Applied int
	// Shred passes queued.
	Queued int
	// Repos left as they were for an error, which the next walk tries again.
	Failed int
}

// One walk: see the file header. An error only for a cluster that could not be listed; each repo's own failure is
// counted and the walk goes on.
func RunReconcile(ctx context.Context, host *sidecar.ServiceHost, deps *EvsReconcileDeps) (*EvsReconcileCounts, error) {
	if host == nil || host.Blobs == nil || host.Budget == nil || host.Tasks == nil {
		return nil, errors.New("evs's reconciler needs a host with Blobs, a write budget and a task queue")
	}
	if deps == nil {
		deps = &EvsReconcileDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultEvsSettings()
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	priceTable, err := DefaultPriceTable(settings.PriceBlockByteCount)
	if err != nil {
		return nil, err
	}
	clock := host.ClockOrReal()
	blobs := NewBudgetedBlobs(host.Blobs)
	repos := NewRepoCache(clock, settings)
	counts := &EvsReconcileCounts{}
	for _, clusterId := range blobs.MetadataClusterIds() {
		cluster, err := blobs.Cluster(clusterId)
		if err != nil {
			return counts, err
		}
		startAfter := ""
		for {
			infos, more, err := cluster.List(ctx, repoKeyPrefix, startAfter, settings.ShredListPageCount)
			if err != nil {
				return counts, err
			}
			for _, info := range infos {
				repoId, err := parseEvsHexId(strings.TrimPrefix(info.Key, repoKeyPrefix))
				if err != nil {
					continue
				}
				counts.Repos += 1
				if err := reconcileRepo(ctx, host, deps.Deletions, settings, priceTable, repos, cluster, repoId, counts); err != nil {
					counts.Failed += 1
					log.Warningf("[evs] reconcile of repo %s: %v", sidecar.EvsKeyId(repoId), err)
				}
			}
			if !more || len(infos) == 0 {
				break
			}
			startAfter = infos[len(infos)-1].Key
		}
	}
	return counts, nil
}

// One repo: apply what the projection holds that repo/ lacks, then queue what its state leaves due.
func reconcileRepo(ctx context.Context, host *sidecar.ServiceHost, deletions EvsRepoDeletionSource, settings *EvsSettings, priceTable *PriceTable, repos *RepoCache, cluster sidecar.BlobCluster, repoId sidecar.Id, counts *EvsReconcileCounts) error {
	read, err := repos.ReadFresh(ctx, cluster, repoId)
	if err != nil {
		return err
	}
	object := read.Object
	if deletions != nil && len(object.GetNetworkId()) == 16 {
		deletion, err := deletions.RepoDeletion(ctx, sidecar.Id(object.GetNetworkId()), repoId)
		if err != nil {
			return err
		}
		var decide repoDecide
		switch {
		case deletion == nil:
		case deletion.Restored && object.GetState() == protocol.EvsRepoState_EVS_REPO_DELETED && evsRepoNamesDeletion(object, deletion.DeletionId):
			decide = decideRestore(deletion, host.ClockOrReal().Now())
		case !deletion.Restored && !evsRepoNamesDeletion(object, deletion.DeletionId) &&
			(object.GetState() == protocol.EvsRepoState_EVS_REPO_ACTIVE || object.GetState() == protocol.EvsRepoState_EVS_REPO_DELETED && deletion.Now):
			decide = decideDelete(deletion, host.ClockOrReal().Now())
		}
		if decide != nil {
			written, err := transitionRepo(ctx, cluster, repos, repoId, settings.RepoTransitionRetryCount,
				evsP0Class(host.Budget, priceTable, cluster, sidecar.WriteP0KindLifecycle), decide)
			var refusal *EvsRepoRefusal
			switch {
			case errors.As(err, &refusal):
				// the state moved between the read and the decision: the next walk sees it
			case err != nil:
				return err
			default:
				counts.Applied += 1
				object = written.Object
			}
		}
	}
	request, ok := evsShredRequest(repoId, object, host.ClockOrReal().Now())
	if !ok {
		return nil
	}
	if err := host.Tasks.Schedule(ctx, request); err != nil {
		return err
	}
	counts.Queued += 1
	return nil
}
