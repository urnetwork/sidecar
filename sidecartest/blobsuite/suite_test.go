package blobsuite

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

func newFakeTarget(t *testing.T) (*sidecartest.FakeBlobs, *Target) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	store := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	cluster, err := store.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	return store, &Target{
		Cluster: cluster,
		Now:     clock.Now,
		Settle:  &Settle{Now: clock.Now, Delayed: cluster},
	}
}

func TestFakeBlobsConform(t *testing.T) {
	store, target := newFakeTarget(t)
	Run(t, target)
	if violations := store.Violations(); len(violations) != 0 {
		t.Errorf("the suite's own keys broke a rule: %v", violations)
	}
}

func TestFakeBlobsConformOnEveryCluster(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecartest.DefaultFakeBlobsSettings()
	settings.MetadataClusterIds = []string{"meta-1", "meta-2"}
	store := sidecartest.NewFakeBlobs(clock, nil, nil, settings)
	RunStore(t, store)
	for _, clusterId := range []string{"meta-1", "meta-2", "seg-1"} {
		cluster, err := store.Cluster(clusterId)
		if err != nil {
			t.Fatal(err)
		}
		Run(t, &Target{Cluster: cluster, Now: clock.Now, Settle: &Settle{Now: clock.Now, Delayed: cluster}})
	}
}

// A store that waits for the settle cases says so, by name, and claims nothing.
func TestAStoreWithoutSettleRulesClaimsNoPass(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecartest.DefaultFakeBlobsSettings()
	settings.SettlePassed = false
	store := sidecartest.NewFakeBlobs(clock, nil, nil, settings)
	cluster, err := store.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	Run(t, &Target{Cluster: cluster, Now: clock.Now, ClockTolerance: 1 * time.Second})
}

// The twin: a store answering SettlePassed true with no settle rules fails the identity case.
func TestAStoreClaimingAPassItCannotProveFails(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	store := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	cluster, err := store.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	target := &Target{Cluster: cluster, Now: clock.Now}
	keys := &keySpace{prefix: "blobsuite/identity/"}
	if err := caseIdentity(t.Context(), target, keys); err == nil {
		t.Error("a claimed pass went unchallenged")
	}
}
