//go:build sidecar_testhooks

// QD-1186's schedules at gkm, held on the barriers around a claim's create and a re-form's closing (reform_fence.go):
// a claim checked before a re-form lands and created after its marker; a claim that landed before the marker, which
// the re-form, drafted a generation behind, cannot carry; a claim created before the marker and read after it; and two
// tries of one re-form racing a claim the fence refused. In each the repo never holds two generations of one number as
// gkm answers and serves them: a claim either lands before the marker, and the re-form that stands carries it, or is
// refused 409 naming the new group.

package gkmservice

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A claim that passed its checks while the repo's newest form named its group, held at its create, is created after
// a re-form has landed whole, marker, form and epoch 0: it is refused 409 with the re-form's GroupForm, naming the new
// group, and what it wrote reaches no reader; the new group's ladder and its own generation 2 stand.
func TestGkmClaimCheckedBeforeAReformLandsIsRefusedAfterItsMarker(t *testing.T) {
	world := newGkmGroupWorld(t)
	world.createAndActivate()
	fixture := world.fixture
	oldGroupId := world.groupId
	newGroupId := testId("group-reformed")
	_, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	held, reformCode := 0, 0
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != BarrierGenClaimBefore || key != gkmBarrierNumberKey(oldGroupId, 2) {
			return
		}
		held += 1
		if held == 1 {
			// the claim passed its checks with the old group the repo's newest; the re-form lands whole now
			reformCode = world.postReform(newGroupId, oldGroupId, 1).Code
		}
	}})
	defer sidecar.SetTestHooks(nil)

	recorder := world.postClaim(world.adminToken, 2, claim2)
	if held != 1 || reformCode != http.StatusOK {
		t.Fatalf("the claim was held %d times and the re-form answered %d", held, reformCode)
	}
	if fixture.object("meta-2", GkmGenerationKey(oldGroupId, 2)) == nil {
		t.Fatalf("the claim's create did not land after the marker: the schedule held nothing")
	}
	if recorder.Code != http.StatusConflict || !bytes.Equal(recorder.Body.Bytes(), world.reformBytes(newGroupId, oldGroupId, 1)) {
		t.Fatalf("the claim created after the re-form's marker: %d", recorder.Code)
	}
	if served := world.servedGenerations(oldGroupId, 0, false); !slices.Equal(served, []uint64{1}) {
		t.Errorf("GET gen of the re-formed group serves %v", served)
	}
	world.groupId = newGroupId
	if recorder := world.postLadder(world.adminToken, world.rotate1); recorder.Code != http.StatusOK {
		t.Fatalf("the new group's ladder: %d", recorder.Code)
	}
	_, newClaim2 := world.nextGenerationIn(newGroupId, world.key1)
	if recorder := world.postClaim(world.adminToken, 2, newClaim2); recorder.Code != http.StatusCreated {
		t.Errorf("the new group's generation 2: %d", recorder.Code)
	}
	if served := world.servedGenerations(newGroupId, 0, true); !slices.Equal(served, []uint64{1, 2}) {
		t.Errorf("the drop key serves the new group's %v", served)
	}
}

// A claim that lands, 201, while a re-form drafted at the generation before it is held before its marker: the re-form
// finds the generation its form does not carry, its closing comes to void, which empties the marker, and it is refused
// 409 with that generation; the re-form drafted again at it stands, and its ladder carries the claim byte for byte.
func TestGkmClaimLandedBeforeAReformsMarkerVoidsItsClosingAndTheNextReformCarriesIt(t *testing.T) {
	world := newGkmGroupWorld(t)
	world.createAndActivate()
	fixture := world.fixture
	oldGroupId := world.groupId
	_, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	held, claimCode := 0, 0
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != BarrierGroupCloseBefore || key != gkmBarrierGroupKey(oldGroupId) {
			return
		}
		held += 1
		if held == 1 {
			// the re-form, drafted at generation 1, is about to write its marker; the claim of 2 lands first
			claimCode = world.postClaim(world.adminToken, 2, claim2).Code
		}
	}})
	staleGroupId := testId("group-stale")
	recorder := world.postReform(staleGroupId, oldGroupId, 1)
	sidecar.SetTestHooks(nil)
	if held == 0 || claimCode != http.StatusCreated {
		t.Fatalf("the re-form was held %d times and the claim answered %d", held, claimCode)
	}
	if recorder.Code != http.StatusConflict || !bytes.Equal(recorder.Body.Bytes(), fixture.marshal(claim2)) {
		t.Fatalf("the re-form the group moved past: %d", recorder.Code)
	}
	if marker, found := world.stored(GkmGroupClosedKey(oldGroupId)); !found || len(marker) != 0 {
		t.Errorf("the void closing did not empty the marker")
	}
	if served := world.servedGenerations(oldGroupId, 0, false); !slices.Equal(served, []uint64{1, 2}) {
		t.Errorf("GET gen of the group opened again serves %v", served)
	}

	newGroupId := testId("group-reformed")
	if recorder := world.postReform(newGroupId, oldGroupId, 2); recorder.Code != http.StatusOK {
		t.Fatalf("the re-form drafted again at generation 2: %d", recorder.Code)
	}
	world.groupId = newGroupId
	if recorder := world.postLadder(world.adminToken, world.rotate1, claim2); recorder.Code != http.StatusOK {
		t.Fatalf("the ladder: %d", recorder.Code)
	}
	if !bytes.Equal(fixture.object("meta-2", GkmGenerationKey(newGroupId, 2)), fixture.marshal(claim2)) {
		t.Errorf("the re-form that stands does not carry the claim's generation byte for byte")
	}
}

// A claim whose create lands before a re-form's marker and whose read of the marker comes after it, while the
// re-form is held before its verdict: the claim is refused 409 with the re-form's GroupForm; the re-form then finds
// that generation, its closing comes to void and it is refused 409 with it; the group, open again, serves the
// generation, and its claimer's same bytes sent again answer 201, as its rotation from its draft would take it.
func TestGkmClaimCreatedBeforeAReformsMarkerAndReadAfterIsRefusedAndTheClosingComesToNothing(t *testing.T) {
	world := newGkmGroupWorld(t)
	world.createAndActivate()
	fixture := world.fixture
	oldGroupId := world.groupId
	staleGroupId := testId("group-stale")
	_, claim2 := world.nextGeneration(world.admin, world.key1, nil)
	reformBody := fixture.marshal(&protocol.GkmGroupReformRequest{
		Form:            world.form(world.admin, staleGroupId, &oldGroupId, 1),
		GenWrap:         bytes.Repeat([]byte{5}, gkmSealedKeyByteCount),
		SealedGroupInfo: []byte("sealed group info of the re-formed epoch 0"),
		CipherSuite:     gkmCipherSuiteXWing,
	})
	formsPath := "/gkm/repos/" + sidecar.EvsKeyId(world.repoId) + "/forms"
	markerStands := make(chan struct{})
	releaseClaim := sync.OnceFunc(func() { close(markerStands) })
	claimAnswered := make(chan struct{})
	reformAnswered := make(chan *httptest.ResponseRecorder, 1)
	var claimOnce, closingOnce sync.Once
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		switch {
		case name == BarrierGenClaimAfter && key == gkmBarrierNumberKey(oldGroupId, 2):
			claimOnce.Do(func() {
				// the claim's create landed; the re-form writes its marker before the claim reads it
				go func() {
					defer releaseClaim()
					reformAnswered <- fixture.serve(http.MethodPost, formsPath, world.adminToken, reformBody)
				}()
				<-markerStands
			})
		case name == BarrierGroupClosingBefore && key == gkmBarrierGroupKey(oldGroupId):
			closingOnce.Do(func() {
				// the marker stands and the verdict waits: the claim reads the marker now
				releaseClaim()
				<-claimAnswered
			})
		}
	}})
	defer sidecar.SetTestHooks(nil)

	recorder := world.postClaim(world.adminToken, 2, claim2)
	close(claimAnswered)
	reform := <-reformAnswered
	if recorder.Code != http.StatusConflict || !bytes.Equal(recorder.Body.Bytes(), world.reformBytes(staleGroupId, oldGroupId, 1)) {
		t.Errorf("the claim read after the re-form's marker: %d", recorder.Code)
	}
	if reform.Code != http.StatusConflict || !bytes.Equal(reform.Body.Bytes(), fixture.marshal(claim2)) {
		t.Fatalf("the re-form that found the claim's generation: %d", reform.Code)
	}
	if marker, found := world.stored(GkmGroupClosedKey(oldGroupId)); !found || len(marker) != 0 {
		t.Errorf("the void closing did not empty the marker")
	}
	if fixture.object("meta-2", GkmFormKey(world.repoId, 2)) != nil {
		t.Errorf("the void closing's form was filed")
	}
	sidecar.SetTestHooks(nil)
	if served := world.servedGenerations(oldGroupId, 0, false); !slices.Equal(served, []uint64{1, 2}) {
		t.Errorf("GET gen of the group opened again serves %v", served)
	}
	if recorder := world.postClaim(world.adminToken, 2, claim2); recorder.Code != http.StatusCreated {
		t.Errorf("the refused claim's same bytes once the group is open again: %d", recorder.Code)
	}
}

// Two tries of one re-form request, a resend beside an original whose answer was lost, with a claim the fence refused
// landing past the form's generation between them. Once the first try has sealed its closing, the second follows the
// verdict and files the form, and so does the first: one form, the marker standing, the claim's generation served to
// no one.
func TestGkmTwoTriesOfOneReformFollowTheSealedVerdict(t *testing.T) {
	world := newGkmGroupWorld(t)
	world.createAndActivate()
	fixture := world.fixture
	oldGroupId := world.groupId
	newGroupId := testId("group-reformed")
	_, refused := world.nextGeneration(world.admin, world.key1, nil)
	hits, secondCode := 0, 0
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != BarrierGroupClosingAfter || key != gkmBarrierGroupKey(oldGroupId) {
			return
		}
		hits += 1
		if hits == 1 {
			// the first try sealed its closing; a claim the fence refused leaves generation 2, and the resend comes
			fixture.put("meta-2", GkmGenerationKey(oldGroupId, 2), fixture.marshal(refused))
			secondCode = world.postReform(newGroupId, oldGroupId, 1).Code
		}
	}})
	first := world.postReform(newGroupId, oldGroupId, 1)
	sidecar.SetTestHooks(nil)
	if hits == 0 {
		t.Fatalf("the schedule held nothing")
	}
	if first.Code != http.StatusOK || secondCode != http.StatusOK {
		t.Fatalf("the two tries of the sealed re-form answered %d and %d", first.Code, secondCode)
	}
	form := world.reformBytes(newGroupId, oldGroupId, 1)
	if !bytes.Equal(fixture.object("meta-2", GkmFormKey(world.repoId, 2)), form) || fixture.object("meta-2", GkmFormKey(world.repoId, 3)) != nil {
		t.Errorf("the repo does not hold the one re-form")
	}
	if marker, _ := world.stored(GkmGroupClosedKey(oldGroupId)); !bytes.Equal(marker, form) {
		t.Errorf("the sealed closing's marker moved")
	}
	if served := world.servedGenerations(oldGroupId, 0, false); !slices.Equal(served, []uint64{1}) {
		t.Errorf("GET gen of the re-formed group serves %v", served)
	}
}

// The same two tries, the claim the fence refused landing while the first is about to seal: the second finds it and
// records the closing void first, so the first's seal loses and follows the void verdict. Both are refused 409 with
// the claim's generation, no form is filed, and the group, open again, serves the generation as its own.
func TestGkmTwoTriesOfOneReformFollowTheVoidVerdict(t *testing.T) {
	world := newGkmGroupWorld(t)
	world.createAndActivate()
	fixture := world.fixture
	oldGroupId := world.groupId
	newGroupId := testId("group-reformed")
	_, refused := world.nextGeneration(world.admin, world.key1, nil)
	hits, secondCode := 0, 0
	var secondBody []byte
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != BarrierGroupClosingBefore || key != gkmBarrierGroupKey(oldGroupId) {
			return
		}
		hits += 1
		if hits == 1 {
			// the first try found nothing past its form and is about to seal; the refused claim lands, and the resend
			// comes
			fixture.put("meta-2", GkmGenerationKey(oldGroupId, 2), fixture.marshal(refused))
			second := world.postReform(newGroupId, oldGroupId, 1)
			secondCode, secondBody = second.Code, second.Body.Bytes()
		}
	}})
	first := world.postReform(newGroupId, oldGroupId, 1)
	sidecar.SetTestHooks(nil)
	if hits < 2 {
		t.Fatalf("the schedule held %d verdicts", hits)
	}
	refusedBytes := fixture.marshal(refused)
	if first.Code != http.StatusConflict || !bytes.Equal(first.Body.Bytes(), refusedBytes) || secondCode != http.StatusConflict || !bytes.Equal(secondBody, refusedBytes) {
		t.Fatalf("the two tries of the voided re-form answered %d and %d", first.Code, secondCode)
	}
	form := world.reformBytes(newGroupId, oldGroupId, 1)
	if verdict, found := world.stored(GkmGroupClosingKey(oldGroupId, sha256Of(form))); !found || len(verdict) != 0 {
		t.Errorf("the closing is not void")
	}
	if marker, found := world.stored(GkmGroupClosedKey(oldGroupId)); !found || len(marker) != 0 {
		t.Errorf("the void closing did not empty the marker")
	}
	if fixture.object("meta-2", GkmFormKey(world.repoId, 2)) != nil {
		t.Errorf("the void closing's form was filed")
	}
	if served := world.servedGenerations(oldGroupId, 0, false); !slices.Equal(served, []uint64{1, 2}) {
		t.Errorf("GET gen of the group opened again serves %v", served)
	}
}
