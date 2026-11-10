// §21.9's preservation holds as evs's taskworker jobs read them (§11.13's gc, skip and who rows; EVSB-M2-11): a thin
// wrapper of the root's HoldSet (CONTRACTS.md C-14, C-20), which lists hold/<network_id>/ on the first metadata
// cluster and parses each object, here held to §11.13's bound, a read at most 5 s old, and asked by repo: a repo's
// network is the network_id its repo/ carries (plan-EVSB-repo-network), and a repo/ without one reads as held with
// unknown terms, so nothing of it is deleted.
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

// §11.13's bound on a cached hold/ read, which no setting passes.
const evsHoldCacheMaxAge = 5 * time.Second

// See the file header.
type HoldCache struct {
	holds *sidecar.HoldSet
}

// A cache reading hold/ through blobs on clock. settings nil takes HoldSet's defaults; a reread interval past 5 s is
// held to 5 s.
func NewHoldCache(blobs sidecar.BlobStore, clock sidecar.Clock, settings *sidecar.HoldSetSettings) *HoldCache {
	held := *sidecar.DefaultHoldSetSettings()
	if settings != nil {
		held = *settings
	}
	if evsHoldCacheMaxAge < held.RereadInterval {
		held.RereadInterval = evsHoldCacheMaxAge
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
