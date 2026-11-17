package blobsuite

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// DefaultSettle's tunables on now and delayed, as a caller builds one.
func newTestSettle(now func() time.Time, delayed sidecar.BlobCluster) *Settle {
	settle := DefaultSettle()
	settle.Now = now
	settle.Delayed = delayed
	return settle
}

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
		Settle:  newTestSettle(clock.Now, cluster),
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
		Run(t, &Target{Cluster: cluster, Now: clock.Now, Settle: newTestSettle(clock.Now, cluster)})
	}
}

// FakeBlobs judges a deadline by its own clock, which the suite reads from another (QD-892): with that
// clock 100 ms behind the suite's, the most §19.6's clock rule lets two clocks differ, DefaultSettle's
// late requests are still late to it, and it passes the settle cases.
func TestFakeBlobsPassTheSettleCasesOnAClockBehindTheSuites(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	store := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	cluster, err := store.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	suiteNow := func() time.Time {
		return clock.Now().Add(100 * time.Millisecond)
	}
	target := &Target{Cluster: cluster, Now: clock.Now, Settle: newTestSettle(suiteNow, cluster)}
	for _, c := range settleCases() {
		if err := c.run(t.Context(), target, &keySpace{prefix: "settle/" + c.name + "/"}); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
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
