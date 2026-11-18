//go:build sidecar_testhooks

package evsservice

import (
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// QD-982's races at their barriers (§11.8's placement row, owner decision 567): two config writers' creates of the
// config repo, one held at a barrier while the other runs whole inside the hook, both answer 200 and leave one place/
// and one repo/, at place/'s If-None-Match and at repo/'s alike. A general repo raced the same way at place/ still
// refuses the held creator 409 REPO_PLACED (FS-63).

// At repo/'s If-None-Match, over a placement standing alone with its creator gone: config writer A is held just before
// its repo/ create while B's create runs whole and writes repo/; A's If-None-Match then meets B's repo/, reads it back
// as this config repo's and answers 200, writing nothing over it, and place/ stays as it stood.
func TestPlaceConfigRepoTwoConfigWritersRacingAtRepoObjectConvergeOnOne(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("config")
	configWriterA := testId("sidecar-a")
	configWriterB := testId("sidecar-b")
	fixture.projectConfigRepo(repoId, configWriterA, configWriterB)
	placeBytes := fixture.standPlacement(repoId, "meta-1", testId("sidecar-gone"))
	racingStatus := 0
	var racingRepoBytes []byte
	reached := atBarrierOnce(t, BarrierRepoPutBefore, barrierRepoKey(repoId), func() {
		racingStatus = fixture.putRepo(repoId, configWriterB)
		racingRepoBytes = fixture.object("meta-1", RepoKey(repoId))
	})
	if status := fixture.putRepo(repoId, configWriterA); status != http.StatusOK {
		t.Fatalf("the held config writer's create: %d", status)
	}
	if *reached != 1 || racingStatus != http.StatusOK || racingRepoBytes == nil {
		t.Fatalf("the race: the barrier reached %d times, the racing create answered %d", *reached, racingStatus)
	}
	if repoBytes := fixture.requireConfigRepoObject("meta-1", repoId); string(repoBytes) != string(racingRepoBytes) {
		t.Error("the held create wrote over the racing create's repo/")
	}
	if keys := fixture.keysUnder("meta-2", "repo/"); len(keys) != 0 {
		t.Errorf("repo/ on a cluster place/ does not name: %v", keys)
	}
	if string(fixture.object("meta-1", sidecar.EvsPlaceKey(repoId))) != string(placeBytes) {
		t.Error("place/ was rewritten")
	}
}

// At place/'s If-None-Match, on a config repo nothing has placed: config writer A is held just before its place/
// create while B's create runs whole, placing the repo as its creator and writing repo/; A's If-None-Match then meets
// B's place/, continues on it as a config writer and answers 200 on B's repo/. One place/, naming B, and one repo/.
func TestPlaceConfigRepoTwoConfigWritersRacingAtPlaceConvergeOnOne(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("config")
	configWriterA := testId("sidecar-a")
	configWriterB := testId("sidecar-b")
	fixture.projectConfigRepo(repoId, configWriterA, configWriterB)
	racingStatus := 0
	var racingPlaceBytes, racingRepoBytes []byte
	reached := atBarrierOnce(t, BarrierPlacePutBefore, barrierRepoKey(repoId), func() {
		racingStatus = fixture.putRepo(repoId, configWriterB)
		racingPlaceBytes = fixture.object("meta-1", sidecar.EvsPlaceKey(repoId))
		racingRepoBytes = fixture.object("meta-1", RepoKey(repoId))
	})
	if status := fixture.putRepo(repoId, configWriterA); status != http.StatusOK {
		t.Fatalf("the held config writer's create: %d", status)
	}
	if *reached != 1 || racingStatus != http.StatusOK || racingPlaceBytes == nil || racingRepoBytes == nil {
		t.Fatalf("the race: the barrier reached %d times, the racing create answered %d", *reached, racingStatus)
	}
	if place := fixture.placement(repoId); place == nil || place.ClusterId != "meta-1" || place.CreatorSidecarId != configWriterB {
		t.Errorf("place/ %+v", place)
	}
	if string(fixture.object("meta-1", sidecar.EvsPlaceKey(repoId))) != string(racingPlaceBytes) {
		t.Error("place/ was rewritten")
	}
	if repoBytes := fixture.requireConfigRepoObject("meta-1", repoId); string(repoBytes) != string(racingRepoBytes) {
		t.Error("the held create wrote over the racing create's repo/")
	}
}

// The same race at place/ on a general repo keeps §11.8's rule for every kind but config: the held creator meets the
// other's placement and is refused 409 REPO_PLACED, writing nothing (QD-927, FS-63).
func TestPlaceGeneralRepoTwoCreatorsRacingAtPlaceRefusesTheHeldOne(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId := testId("repo")
	creatorA := testId("sidecar-a")
	creatorB := testId("sidecar-b")
	fixture.projectRepo(repoId, creatorA, creatorB)
	racingStatus := 0
	var racingRepoBytes []byte
	atBarrierOnce(t, BarrierPlacePutBefore, barrierRepoKey(repoId), func() {
		racingStatus = fixture.putRepo(repoId, creatorB)
		racingRepoBytes = fixture.object("meta-1", RepoKey(repoId))
	})
	requireRefusal(t, fixture.putRepoAnswer(repoId, creatorA), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED)
	if racingStatus != http.StatusOK || racingRepoBytes == nil {
		t.Fatalf("the racing create answered %d", racingStatus)
	}
	if place := fixture.placement(repoId); place == nil || place.CreatorSidecarId != creatorB {
		t.Errorf("place/ %+v", place)
	}
	if string(fixture.object("meta-1", RepoKey(repoId))) != string(racingRepoBytes) {
		t.Error("the refused create wrote over repo/")
	}
}
