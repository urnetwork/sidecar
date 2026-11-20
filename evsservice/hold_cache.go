// §21.9's preservation holds as evs's taskworker jobs read them (§11.13's gc, skip and who rows; EVSB-M2-11): a thin
// wrapper of the root's HoldSet (CONTRACTS.md C-14, C-20), which lists hold/<network_id>/ on the first metadata
// cluster and parses each object, here held to §11.13's bound, a read at most 5 s old, and asked by repo: a repo's
// network is the network_id its repo/ carries (plan-EVSB-repo-network), and a repo/ without one reads as held with
// unknown terms, so nothing of it is deleted.
//
// The bound holds at the DELETE (owner decision 629): a hold binds every deleter from the bound after api
// acknowledged its placement, so a deleter issues a DELETE only on a cover whose read is younger than the bound as the
// DELETE issues. A cover carries its read's time (sidecar.HoldCover.ReadTime), and each deleter calls
// CoveringAtDelete, or CoveringRepoAtDelete, with the cover it judged on, after every wait and request that comes
// before its DELETE (a HEAD, the budget's turn, a pace) and before the DELETE's barrier: a quick HEAD deletes on the
// cover it had, and a stall past the bound reads hold/ again, through the cache, so the stall costs one read that every
// DELETE after it shares, and the deleter judges again on the new cover. A read that comes back already past the bound
// is unknown with sidecar.ErrHoldReadStale, as a read that failed is.
//
// Every doubt keeps data, as HoldSet's does: a LIST or GET that fails answers an unknown cover with the error, and
// a caller that reads only the cover still deletes nothing. Safe for concurrent use.

package evsservice

import (
	"context"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Tunables of a HoldCache.
type HoldCacheSettings struct {
	// The HoldSet beneath. Its RereadInterval is the bound of owner decision 629: the cache answers no read older,
	// and no DELETE issues on a read that old, so a hold binds evs's deleters from that long after api acknowledged
	// its placement. nil: HoldSet's defaults.
	HoldSet *sidecar.HoldSetSettings
	// §11.13's ceiling on that bound: a longer RereadInterval is held to it, so no HoldSet setting lets evs's deleters
	// act on an older read. 5 s, HoldSet's own default. Non-positive holds the cache to rereading on every call,
	// which leaves the deleters no read young enough to delete on.
	MaxRereadInterval time.Duration
}

// HoldSet's defaults, held to §11.13's 5 s, their own reread interval.
func DefaultHoldCacheSettings() *HoldCacheSettings {
	holdSet := sidecar.DefaultHoldSetSettings()
	return &HoldCacheSettings{
		HoldSet:           holdSet,
		MaxRereadInterval: holdSet.RereadInterval,
	}
}

// See the file header.
type HoldCache struct {
	holds *sidecar.HoldSet
}

// A cache reading hold/ through blobs on clock. settings nil takes the defaults. A reread interval past
// MaxRereadInterval is held to it.
func NewHoldCache(blobs sidecar.BlobStore, clock sidecar.Clock, settings *HoldCacheSettings) *HoldCache {
	if settings == nil {
		settings = DefaultHoldCacheSettings()
	}
	held := *sidecar.DefaultHoldSetSettings()
	if settings.HoldSet != nil {
		held = *settings.HoldSet
	}
	if settings.MaxRereadInterval < held.RereadInterval {
		held.RereadInterval = settings.MaxRereadInterval
	}
	return &HoldCache{holds: sidecar.NewHoldSet(blobs, clock, &held)}
}

// The HoldSet beneath, for a job that shares it with another reader.
func (self *HoldCache) HoldSet() *sidecar.HoldSet {
	return self.holds
}

// The live holds of networkId covering repoId, from a read at most 5 s old. A zero networkId is covered with
// unknown terms.
func (self *HoldCache) Covering(ctx context.Context, networkId sidecar.Id, repoId sidecar.Id) (*sidecar.HoldCover, error) {
	return self.holds.Covering(ctx, networkId, repoId)
}

// The live holds covering the repo whose repo/ object is given, by the network it carries. An object with no
// network, or one that is not 16 bytes, is covered with unknown terms.
func (self *HoldCache) CoveringRepo(ctx context.Context, repoId sidecar.Id, object *protocol.EvsRepoObject) (*sidecar.HoldCover, error) {
	networkId, err := sidecar.IdFromBytes(object.GetNetworkId())
	if err != nil {
		return &sidecar.HoldCover{Unknown: true}, nil
	}
	return self.holds.Covering(ctx, networkId, repoId)
}

// The cover a DELETE about to issue acts on: cover while its read is younger than the bound, else a read of hold/
// again, held to the bound itself (sidecar.HoldSet.CoveringAtDelete; the file header). A nil cover reads now. The
// caller judges again on what comes back and issues its DELETE with nothing between.
func (self *HoldCache) CoveringAtDelete(ctx context.Context, cover *sidecar.HoldCover, networkId sidecar.Id, repoId sidecar.Id) (*sidecar.HoldCover, error) {
	return self.holds.CoveringAtDelete(ctx, cover, networkId, repoId)
}

// CoveringAtDelete by the network the repo's repo/ object carries. An object with no network, or one that is not
// 16 bytes, is covered with unknown terms.
func (self *HoldCache) CoveringRepoAtDelete(ctx context.Context, cover *sidecar.HoldCover, repoId sidecar.Id, object *protocol.EvsRepoObject) (*sidecar.HoldCover, error) {
	networkId, err := sidecar.IdFromBytes(object.GetNetworkId())
	if err != nil {
		return &sidecar.HoldCover{Unknown: true}, nil
	}
	return self.holds.CoveringAtDelete(ctx, cover, networkId, repoId)
}
