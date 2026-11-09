// §11.12's shred of a repo's gkm objects (§10.8's erasure; owner decisions 82, 133): ShredGroup, which evs's shred job
// calls at its step 3 and again at step 6, ten minutes later, for stragglers. It deletes every group the repo's
// GroupForms name, each group's objects on the repo's cluster, its recovery wraps on every metadata cluster and its
// {gka_<group_id>} acks; at step 6, final, the forms themselves last, so a repeat still finds every group until then.
// No hold pauses a user's shred (owner decision 133), so none is read here.
//
// Safe to repeat: a key already gone is no error, and a write in flight at step 3, which gkm issued before it reread
// repo/ as shredding, lands within the store's request deadline, which step 6's ten minutes outlast (§10.6's checks
// row).

package gkmservice

import (
	"context"
	"errors"
	"strings"

	"github.com/urnetwork/sidecar"
)

// Deletes repoId's gkm objects on cluster, its repo's metadata cluster; final also deletes its GroupForms.
func ShredGroup(ctx context.Context, host *sidecar.ServiceHost, cluster sidecar.BlobCluster, repoId sidecar.Id, final bool, settings *GkmServiceSettings) error {
	if host == nil || host.Blobs == nil || cluster == nil {
		return errors.New("gkm's shred needs a host with Blobs and the repo's cluster")
	}
	if settings == nil {
		settings = DefaultGkmServiceSettings()
	}
	forms, err := gkmReadForms(ctx, cluster, repoId, settings)
	if err != nil {
		return err
	}
	groupIds := map[sidecar.Id]bool{}
	for _, form := range forms {
		groupIds[form.GroupId] = true
	}
	for groupId := range groupIds {
		if err := deleteGkmPrefix(ctx, cluster, GkmGroupPrefix(groupId), settings.ListPageCount); err != nil {
			return err
		}
		if host.Redis != nil {
			if err := host.Redis.Delete(ctx, []string{GkmAckRedisKey(groupId)}); err != nil {
				return err
			}
		}
	}
	if 0 < len(groupIds) {
		for _, clusterId := range host.Blobs.MetadataClusterIds() {
			recoveryCluster, err := host.Blobs.Cluster(clusterId)
			if err != nil {
				return err
			}
			if err := deleteGkmRecoveryWrapsOfGroups(ctx, recoveryCluster, groupIds, settings.ListPageCount); err != nil {
				return err
			}
		}
	}
	if final {
		return deleteGkmPrefix(ctx, cluster, GkmFormPrefix(repoId), settings.ListPageCount)
	}
	return nil
}

// Deletes every key under prefix, a page at a time.
func deleteGkmPrefix(ctx context.Context, cluster sidecar.BlobCluster, prefix string, pageCount int) error {
	startAfter := ""
	for {
		infos, more, err := cluster.List(ctx, prefix, startAfter, pageCount)
		if err != nil {
			return err
		}
		for _, info := range infos {
			if err := cluster.Delete(ctx, info.Key); err != nil {
				return err
			}
		}
		if !more || len(infos) == 0 {
			return nil
		}
		startAfter = infos[len(infos)-1].Key
	}
}

// Deletes every recovery wrap on cluster whose group is one of groupIds: one walk of gkm/recovery/, since recovery
// wraps are keyed by member first.
func deleteGkmRecoveryWrapsOfGroups(ctx context.Context, cluster sidecar.BlobCluster, groupIds map[sidecar.Id]bool, pageCount int) error {
	startAfter := ""
	for {
		infos, more, err := cluster.List(ctx, gkmRecoveryKeyPrefix, startAfter, pageCount)
		if err != nil {
			return err
		}
		for _, info := range infos {
			rest := strings.TrimPrefix(info.Key, gkmRecoveryKeyPrefix)
			parts := strings.Split(rest, "/")
			if len(parts) != 5 {
				continue
			}
			groupId, err := parseGkmHexId(parts[1])
			if err != nil || !groupIds[groupId] {
				continue
			}
			if err := cluster.Delete(ctx, info.Key); err != nil {
				return err
			}
		}
		if !more || len(infos) == 0 {
			return nil
		}
		startAfter = infos[len(infos)-1].Key
	}
}
