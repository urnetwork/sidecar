// The nightly pass's containers (§11.13's move and resume rows; plan-EVSB-parcel-log-pages; EVSB-M2-12):
//
//	unnamed  a pack or parcel whose id no pidx/ entry key of its repo names, once it is UnnamedContainerAge (25 h)
//	         old by its LastModified and the cluster's horizon has passed every batch it could hold records of,
//	         so that no evacuation can find its records in a batch again and reuse it, and, for a pack, while the
//	         repo has no parcel and no log page at log/ that a move could build the same bytes from again: one
//	         DELETE naming its listed LastModified (sidecar.WithBlobUnmodified), a 412 counted as replaced and
//	         never as deleted, a held key or an unknown outcome left for the next night
//	idle     a repo whose oldest parcel content or unpacked log page would pass PackAge (7 d) before the next
//	         pass is packed by evacuation's move with no kept records (Evacuator.PackIdleRepo), which also deletes
//	         each parcel a pack already holds, its entries first, so a run killed between a pack's entries and its
//	         deletes is finished here on a repo no push brings back to evacuation
//
// The horizon bound on an unnamed container: a run writes a container after it took its minutes, each over
// MinuteAge (25 h) old by the run's clock, so every batch it read records from names a minute that began at least
// MinuteAge before the container's LastModified, less the clocks' 100 ms. Once the horizon passes that minute those
// batches are gone and nothing rebuilds the container from them. A pass with no horizon deletes no container.
//
// Every delete rereads repo/ and hold/ as it issues: nothing a hold covers goes (§21.9), and nothing of a repo whose
// repo/ is not active or deleted. A parcel's delete is unfunded P2 on the metadata cluster (§11.13's wallet row: the
// nightly pass has no payer); a pack's is on the segment cluster, which spends no NVMe budget.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// repo/ or hold/, reread as a container's delete issued, let it go no further.
var errNightlyRepoStops = errors.New("evs nightly pass repo stops")

// The clocks' allowance between a container's LastModified and the minutes its writer took (§19.6's 50 ms each).
const evsNightlyContainerClockSlack = 1 * time.Second

// Whether repo/ shows active or deleted in a format this instance reads and no hold covers the repo: what a delete
// of something the repo no longer needs asks. why is not empty otherwise.
func (self *NightlyPass) repoDeletes(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) (why string, err error) {
	read, err := self.repos.Read(ctx, cluster, repoId)
	if err != nil {
		return "repo/ unread", err
	}
	cover, err := self.holds.CoveringRepo(ctx, repoId, read.Object)
	if err != nil {
		return "hold/ unread", err
	}
	if cover.Covered() {
		return "held", nil
	}
	if !read.FormatWithin(self.evsSettings.InstanceFormat) {
		return "repo/ format", nil
	}
	switch read.Object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_ACTIVE, protocol.EvsRepoState_EVS_REPO_DELETED:
		return "", nil
	}
	return "repo/ state", nil
}

// The container id a pack/<repo>/<id> or hp/<repo>/<id> key names, under prefix.
func nightlyContainerId(prefix string, key string) (sidecar.Id, bool) {
	idText, ok := strings.CutPrefix(key, prefix)
	if !ok {
		return sidecar.Id{}, false
	}
	containerId, err := sidecar.ParseId(idText)
	if err != nil || sidecar.EvsKeyId(containerId) != idText {
		return sidecar.Id{}, false
	}
	return containerId, true
}

// The container ids the repo's pidx/ entry keys name, and whether every key parsed. A key that does not parse could
// name any container, so the run then deletes none.
func nightlyNamedContainerIds(repoId sidecar.Id, entries []*sidecar.BlobInfo) (map[sidecar.Id]bool, bool) {
	repoPrefix := pidxKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
	named := map[sidecar.Id]bool{}
	for _, entry := range entries {
		rest, ok := strings.CutPrefix(entry.Key, repoPrefix)
		if !ok || len(rest) < 33 || rest[32] != '/' {
			return nil, false
		}
		_, containerId, ok := parsePidxKey(repoPrefix+rest[:33], entry.Key)
		if !ok {
			return nil, false
		}
		named[containerId] = true
	}
	return named, true
}

// One repo's containers: see the file header.
func (self *NightlyPass) runContainers(ctx context.Context, cluster sidecar.BlobCluster, segmentCluster sidecar.BlobCluster, listing *nightlyListing, result *NightlyResult) error {
	if !self.clockSure() || !result.HasHorizon {
		return nil
	}
	repoId := listing.repoId
	why, err := self.repoDeletes(ctx, cluster, repoId)
	if err != nil {
		return err
	}
	if why != "" {
		return nil
	}
	if err := self.deleteUnnamed(ctx, cluster, segmentCluster, listing, result); err != nil {
		return err
	}
	if !self.idleDue(listing) {
		return nil
	}
	moved, err := self.evacuator.PackIdleRepo(ctx, cluster.ClusterId(), repoId, self.settings.RunInterval)
	if moved != nil {
		result.IdlePackCount += moved.PackCount
		result.ReplacedParcelCount += moved.ReplacedParcelCount
	}
	if errors.Is(err, errEvacuateRepoWaits) || errors.Is(err, errEvacuateHeld) {
		return nil
	}
	return err
}

// Whether the repo's oldest parcel content or unpacked log page would pass PackAge before the next pass, by what the
// LISTs show, or a pack stands newer than a parcel and may hold it: a parcel's records are from minutes at least
// MinuteAge older than its LastModified, and a log page's age is its LastModified's, as evacuation's move reads them.
func (self *NightlyPass) idleDue(listing *nightlyListing) bool {
	evacuatorSettings := self.evacuator.settings
	nextPass := self.clock.Now().Add(self.settings.RunInterval)
	newestPack := time.Time{}
	for _, pack := range listing.packs {
		if !listing.deletedKeys[pack.Key] && pack.LastModified.After(newestPack) {
			newestPack = pack.LastModified
		}
	}
	for _, parcel := range listing.parcels {
		if listing.deletedKeys[parcel.Key] {
			continue
		}
		oldest := parcel.LastModified.Add(-evacuatorSettings.MinuteAge)
		if !oldest.Add(evacuatorSettings.PackAge).After(nextPass) || parcel.LastModified.Before(newestPack) {
			return true
		}
	}
	for _, page := range listing.logPages {
		if !page.LastModified.Add(evacuatorSettings.PackAge).After(nextPass) {
			return true
		}
	}
	return false
}

// The containers no entry names: deleted once old enough and behind the horizon.
func (self *NightlyPass) deleteUnnamed(ctx context.Context, cluster sidecar.BlobCluster, segmentCluster sidecar.BlobCluster, listing *nightlyListing, result *NightlyResult) error {
	repoId := listing.repoId
	named, ok := nightlyNamedContainerIds(repoId, listing.pidxEntries)
	if !ok {
		self.log.Errorf("[evs] alarm nightly_pidx_key: repo %s: a pidx/ key names no container: no container is deleted", sidecar.EvsKeyId(repoId))
		return nil
	}
	now := self.clock.Now()
	due := func(object *sidecar.BlobInfo) bool {
		if object.LastModified.Add(self.settings.UnnamedContainerAge).After(now) {
			return false
		}
		// every minute it could hold records of began before the horizon
		latestMinute := object.LastModified.Add(-self.evacuator.settings.MinuteAge).Add(evsNightlyContainerClockSlack)
		return latestMinute.Before(result.Horizon)
	}
	type unnamed struct {
		object  *sidecar.BlobInfo
		cluster sidecar.BlobCluster
		parcel  bool
	}
	candidates := []*unnamed{}
	repoHex := sidecar.EvsKeyId(repoId)
	for _, parcel := range listing.parcels {
		if containerId, ok := nightlyContainerId(parcelKeyPrefix+repoHex+"/", parcel.Key); ok && !named[containerId] && due(parcel) {
			candidates = append(candidates, &unnamed{object: parcel, cluster: cluster, parcel: true})
		}
	}
	// a pack a killed move left is built again, byte for byte, by the next move of the same parcels and log pages,
	// which reuses it on its 412 and then names it: while any stand, a run beside this one could be that move
	rebuildable := 0 < len(listing.parcels) || 0 < len(listing.logPages)
	for _, pack := range listing.packs {
		if containerId, ok := nightlyContainerId(packKeyPrefix+repoHex+"/", pack.Key); ok && !named[containerId] && due(pack) && !rebuildable {
			candidates = append(candidates, &unnamed{object: pack, cluster: segmentCluster})
		}
	}
	barrierKey := barrierRepoKey(repoId)
	for _, candidate := range candidates {
		if !self.clockSure() {
			return nil
		}
		if err := self.step(BarrierGcDeleteBefore, barrierKey); err != nil {
			return err
		}
		recheck := func(ctx context.Context) error {
			why, err := self.repoDeletes(ctx, cluster, repoId)
			if err != nil {
				return err
			}
			if why != "" {
				return fmt.Errorf("%w: %s", errNightlyRepoStops, why)
			}
			return nil
		}
		deleteCtx := ctx
		var grant sidecar.WriteGrant
		if candidate.parcel {
			byteCount, err := self.priceTable.Price(WriteOperation{Kind: WriteOperationDelete, Count: 1})
			if err != nil {
				return err
			}
			grant, err = self.host.Budget.AcquireP2(ctx, cluster.ClusterId(), &sidecar.WriteP2Work{
				Rank: sidecar.WriteP2RankGc, Due: now, ByteCount: byteCount, Recheck: recheck,
			})
			if errors.Is(err, errNightlyRepoStops) {
				return nil
			}
			if err != nil {
				return err
			}
			deleteCtx = grant.Context()
		} else if err := recheck(ctx); err != nil {
			if errors.Is(err, errNightlyRepoStops) {
				return nil
			}
			return err
		}
		deleteErr := candidate.cluster.Delete(sidecar.WithBlobUnmodified(deleteCtx, candidate.object.LastModified), candidate.object.Key)
		if grant != nil {
			grant.Close()
		}
		switch {
		case deleteErr == nil:
			result.UnnamedDeletedCount += 1
			listing.deletedKeys[candidate.object.Key] = true
		case errors.Is(deleteErr, sidecar.ErrBlobPrecondition):
			// stored again since the LIST: another object, judged on a later night
			result.UnnamedReplacedCount += 1
		default:
			// held, or unknown: listed again the next night, never counted as deleted
			result.UnnamedLeftCount += 1
		}
		if err := self.step(BarrierGcDeleteAfter, barrierKey); err != nil {
			return err
		}
	}
	return nil
}
