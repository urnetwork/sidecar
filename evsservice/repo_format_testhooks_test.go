//go:build sidecar_testhooks

package evsservice

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The raise's barriers (§22.8, EVS2-M10-05): evs.migrate.raise.before and .after stand around the whole
// transition, repo/'s If-Match between them, each keyed by the repo. A sibling's raise that lands while this one is
// held at .before is found by its read, so the pair writes repo/ once.
func TestRaiseBarriersStandAroundTheWholeRaise(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.writeRepo(fixture.fullRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE, sidecar.EvsRepoFormat1))
	repos, siblingRepos := NewRepoCache(fixture.clock, fixture.settings), NewRepoCache(fixture.clock, fixture.settings)
	repoKey := barrierRepoKey(fixture.check.repoId)
	names := []string{}
	record := &sidecar.TestHooks{Barrier: func(name string, key string) {
		if key == repoKey && (name == BarrierMigrateRaiseBefore || name == BarrierMigrateRaiseAfter || name == BarrierRepoCasBefore || name == BarrierRepoCasAfter) {
			names = append(names, name)
		}
	}}
	sidecar.SetTestHooks(record)
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	if _, err := RaiseRepoFormat(fixture.ctx, fixture.cluster, repos, fixture.check.repoId, 8, raiseTestClassify); err != nil {
		t.Fatal(err)
	}
	if want := []string{BarrierMigrateRaiseBefore, BarrierRepoCasBefore, BarrierRepoCasAfter, BarrierMigrateRaiseAfter}; !slices.Equal(names, want) {
		t.Fatalf("barriers %v, want %v", names, want)
	}

	// held at .before while a sibling raises: this raise then reads format 2 and issues no If-Match
	fixture.writeRepo(fixture.fullRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE, sidecar.EvsRepoFormat1))
	repos.Forget(fixture.check.repoId)
	names = nil
	var siblingEtag string
	var siblingErr error
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != BarrierMigrateRaiseBefore || key != repoKey {
			return
		}
		sidecar.SetTestHooks(record)
		var sibling *EvsRepoRead
		if sibling, siblingErr = RaiseRepoFormat(fixture.ctx, fixture.cluster, siblingRepos, fixture.check.repoId, 8, raiseTestClassify); siblingErr == nil {
			siblingEtag = sibling.Etag
		}
		names = nil
	}})
	held, err := RaiseRepoFormat(fixture.ctx, fixture.cluster, repos, fixture.check.repoId, 8, raiseTestClassify)
	if err != nil || siblingErr != nil {
		t.Fatalf("the held raise and its sibling: %v, %v", err, siblingErr)
	}
	if held.Etag != siblingEtag || held.Object.GetFormat() != sidecar.EvsRepoFormat2 || !slices.Equal(names, []string{BarrierMigrateRaiseAfter}) {
		t.Fatalf("the held raise wrote past its sibling's: barriers %v", names)
	}
}

// Step 7's 5 s bounds the raise with the rest: a raise that lands only as the window from step 4's reads passes
// sends the attempt back to steps 4 and 5, which find format 2, raise nothing more and commit.
func TestSlowRaiseRerunsStepsFourAndFive(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2()
	plan := fixture.plan()
	fixture.createVersionless(plan, "a")
	body := fixture.bodyFormat2(plan)
	repoKey := barrierRepoKey(fixture.check.repoId)
	refKey := barrierRefKey(fixture.check.repoId, fixture.check.refId)
	raises, stepSixes := 0, 0
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		switch {
		case name == BarrierMigrateRaiseAfter && key == repoKey:
			raises += 1
			if raises == 1 {
				fixture.clock.Advance(fixture.settings.PushStepSevenWindow)
			}
		case name == BarrierPushStep6Before && key == refKey:
			stepSixes += 1
		}
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), body), 1)
	if raises != 1 || stepSixes != 2 {
		t.Fatalf("%d raises and %d step 6s, want one raise and a rerun", raises, stepSixes)
	}
	if object, _ := fixture.repo(); object.GetFormat() != sidecar.EvsRepoFormat2 {
		t.Fatalf("repo/ format %d", object.GetFormat())
	}
}
