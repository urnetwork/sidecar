//go:build !sidecar_http

// A re-form gkm's fence refuses because the group it re-forms moved past its form (QD-1187's void closing; §10.8's
// re-form rows), on the fake gkm, whose POST forms answers as the fence does (gkm_reform_test.go): a claim of the old
// group that lands before the re-form's POST makes gkm refuse the form 409 with that generation, and the re-former
// takes it and forms again at once, its ladder carrying it, so its re-form stands; a re-form refused because another
// re-form stands still waits, drafting nothing again; and a group that moves past every draft ends the call at
// ReformRedraftCount, its draft dropped.

package sidecar_test

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// b's rotation of the old group lands just before a's POST of its re-form acts, so gkm refuses a's form, at
// generation 1, with gen/2. a takes gen/2 by its delivery and forms again at once at generation 2: the form stands,
// the new group's ladder holds both old statements byte for byte, a's rotation names the new group at generation 3,
// and nothing more stands in the old group.
func TestAReformOutrunByAClaimReformsAtTheNewerGeneration(t *testing.T) {
	world := newGkmFenceWorld(t)
	a, b := world.flows[world.a], world.flows[world.b]
	oldGroupId := world.groupId
	var rotateErr error
	world.store.plantHook(world.a.label, "Reform", func() {
		_, rotateErr = b.client.RotateRepo(world.ctx, world.repoId)
	})
	newGroupId, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	if rotateErr != nil {
		t.Fatalf("b's rotation before a's POST: %v", rotateErr)
	}
	if err != nil {
		t.Fatalf("a's re-form outrun by b's claim: %v", err)
	}
	if calls := world.store.callCount("Reform"); calls != 2 {
		t.Errorf("a's re-form posted %d times, want 2", calls)
	}
	forms := world.store.repoForms[world.repoId]
	form := &protocol.GroupForm{}
	if len(forms) != 2 || proto.Unmarshal(forms[1].GetBody(), form) != nil || sidecar.Id(form.GetGroupId()) != newGroupId ||
		!bytes.Equal(form.GetPreviousGroupId(), oldGroupId.Bytes()) || form.GetGeneration() != 2 {
		t.Fatalf("the repo's forms after the re-form: %d, the newest at generation %d", len(forms), form.GetGeneration())
	}
	oldStatements := world.store.groupGenerations[oldGroupId]
	newStatements := world.store.groupGenerations[newGroupId]
	if len(oldStatements) != 2 || len(newStatements) != 3 {
		t.Fatalf("the old group holds %d generations and the new one %d", len(oldStatements), len(newStatements))
	}
	for index := range oldStatements {
		if !proto.Equal(oldStatements[index], newStatements[index]) {
			t.Errorf("the new group's ladder does not carry gen/%d byte for byte", index+1)
		}
	}
	third := &protocol.GenRotate{}
	if err := proto.Unmarshal(newStatements[2].GetBody(), third); err != nil || sidecar.Id(third.GetGroupId()) != newGroupId {
		t.Errorf("gen/3 does not name the new group: %v", err)
	}
	if groupId, _, generation, err := a.client.TestPins(world.repoId); err != nil || groupId != newGroupId || generation != 3 {
		t.Errorf("a's pins after its re-form: generation %d, %v", generation, err)
	}
	if _, _, _, found, err := a.client.TestReformRecord(world.repoId); found || err != nil {
		t.Errorf("a's re-form record stands after the re-form: %v", err)
	}
	if len(a.alarms) != 0 {
		t.Errorf("a alarmed: %+v", a.alarms[0])
	}
}

// a's whole re-form stands just before b's POST acts, so gkm refuses b's form 409 with a's: b waits and drafts nothing
// again, one POST of its own, its record gone, and the old group moved nowhere.
func TestAReformRefusedForAnotherStandingReformWaitsWithoutDraftingAgain(t *testing.T) {
	world := newGkmFenceWorld(t)
	a, b := world.flows[world.a], world.flows[world.b]
	var reformErr error
	world.store.plantHook(world.b.label, "Reform", func() {
		_, reformErr = a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	})
	if _, err := b.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId}); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("b's re-form beside a's standing one: %v", err)
	}
	if reformErr != nil {
		t.Fatalf("a's re-form: %v", reformErr)
	}
	if calls := world.store.callCount("Reform"); calls != 2 {
		t.Errorf("%d POSTs of a re-form, want a's and b's one each", calls)
	}
	if forms := world.store.repoForms[world.repoId]; len(forms) != 2 {
		t.Errorf("the repo holds %d forms", len(forms))
	}
	if _, _, _, found, err := b.client.TestReformRecord(world.repoId); found || err != nil {
		t.Errorf("b's re-form record stands after its wait: %v", err)
	}
	if generation := world.store.newestGeneration(world.groupId); generation != 1 {
		t.Errorf("the old group holds generation %d", generation)
	}
}

// b rotates the old group before each of a's POSTs, so each of a's forms is outrun: with ReformRedraftCount 1, a
// takes gen/2, forms again at it, is outrun by gen/3, and waits, its draft dropped and no form of its filed.
func TestAReformOutrunAtEveryDraftStopsAtItsBound(t *testing.T) {
	world := newGkmFenceWorld(t)
	settings := sidecar.DefaultGkmSettings()
	settings.ReformRedraftCount = 1
	world.settings = settings
	a, b := world.flows[world.a], world.flows[world.b]
	a.restart()
	var rotateErrs []error
	var rotateBeforePost func()
	rotateBeforePost = func() {
		_, err := b.client.RotateRepo(world.ctx, world.repoId)
		rotateErrs = append(rotateErrs, err)
		world.store.plantHook(world.a.label, "Reform", rotateBeforePost)
	}
	world.store.plantHook(world.a.label, "Reform", rotateBeforePost)
	if _, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId}); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("a's re-form outrun at each draft: %v", err)
	}
	for index, rotateErr := range rotateErrs {
		if rotateErr != nil {
			t.Fatalf("b's rotation %d: %v", index+1, rotateErr)
		}
	}
	if calls := world.store.callCount("Reform"); calls != 2 || len(rotateErrs) != 2 {
		t.Errorf("a posted %d times past %d rotations, want 2 and 2", calls, len(rotateErrs))
	}
	if forms := world.store.repoForms[world.repoId]; len(forms) != 1 {
		t.Errorf("the repo holds %d forms, want only the creation's", len(forms))
	}
	if generation := world.store.newestGeneration(world.groupId); generation != 3 {
		t.Errorf("the old group holds generation %d", generation)
	}
	if _, _, _, found, err := a.client.TestReformRecord(world.repoId); found || err != nil {
		t.Errorf("a's re-form record stands after its bound: %v", err)
	}
	// it took the generation that outran its first draft, and drafted no more past its bound
	if groupId, _, generation, err := a.client.TestPins(world.repoId); err != nil || groupId != world.groupId || generation != 2 {
		t.Errorf("a's pins after its bound: generation %d, %v", generation, err)
	}
}
