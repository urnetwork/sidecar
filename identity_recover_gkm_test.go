//go:build !sidecar_http

// CORE-M2-06's row on KEYS-M2-24's real recovery client and the fake gkm: a recovered device ranked past the config
// group's first 1,000 live member devices, so entitled to no leaf there (§7.9's leaves rule, §5.6's reads row), anchors
// on its RecoveryWrap and reads the config by it: it holds the newest generation with no self-join and no commit, and
// serves reads from it.

package sidecar_test

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A state that ranks one device past the first 1,000 leaves of a leaf-ranked group, as §7.9's leaves rule does to the
// 1,001st live member device.
type recoverTestRankedView struct {
	*sidecartest.FakeGkmAuthView
	pastSeats sidecar.Id
}

func (self *recoverTestRankedView) LeafEntitled(sidecarId sidecar.Id) bool {
	return sidecarId != self.pastSeats
}

func TestARecoveredDevicePastTheFirstThousandReadsByItsRecoveryWrap(t *testing.T) {
	world := newGkmRecoveryWorld(t, protocol.RepoKind_REPO_KIND_CONFIG, false)
	r := world.r
	// every other device takes the state as it is; this one takes it ranked past the seats
	view := world.stateFor(r.gkmWorldDevice)
	r.client.AuthAdvanced(&recoverTestRankedView{FakeGkmAuthView: view, pastSeats: r.id})
	if kept, err := r.client.FetchRecoveryWraps(world.ctx, world.binding, false); err != nil || kept != 1 {
		t.Fatalf("the fetch before admission kept %d: %v", kept, err)
	}
	if err := r.client.AnchorRecovery(world.ctx, world.args(false)); err != nil {
		t.Fatalf("the anchor: %v", err)
	}
	progress := world.run(false)
	if progress.SelfJoined || progress.Leaf || progress.Generation != 2 || progress.Waiting != nil {
		t.Fatalf("a device past the first 1,000: %+v", progress)
	}
	if slices.Contains(world.store.callsOf("r"), "CommitEpoch") {
		t.Error("a device entitled to no leaf committed")
	}
	key, err := r.client.CurrentRepoKey(world.ctx, world.repoId)
	if err != nil || key.Generation() != 2 {
		t.Fatalf("the config's key by the RecoveryWrap: %v", err)
	}
	if earlier, err := r.client.RepoKey(world.ctx, world.repoId, 1); err != nil || earlier.Generation() != 1 {
		t.Errorf("the ladder below the RecoveryWrap's generation: %v", err)
	}
}
