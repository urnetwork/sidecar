// PUT /evs/v1/repos/<id> in a recovery (place.go; §19.10's groups row, §11.13's re-seed row; QD-1062): while reseed is
// on, a repo whose projection ends in an unrestored, dated RepoDelete without now, inside the restore window, is
// created with repo/ deleted{deletion_id, its entry's time, signer}, never keying; one past restoring is refused 409
// SHREDDING with nothing written; and with reseed off, or for a live or restored repo, every create is keying as
// before.

package evsservice

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A repo the projection holds as ending in deletion, admin granted to admin.
func (self *evsFixture) projectDeletedRepo(repoId sidecar.Id, admin sidecar.Id, deletion *EvsRepoDeletionFacts) {
	self.auth.setRepo(repoId, &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: sidecar.Id(self.networkId), Deletion: deletion})
	self.auth.grant(admin, repoId, sidecar.AclEvsAdmin)
}

// Fails unless repoId has neither place/ nor repo/ on either cluster.
func (self *evsFixture) requireNothingPlaced(what string, repoId sidecar.Id) {
	self.t.Helper()
	for _, clusterId := range []string{"meta-1", "meta-2"} {
		if self.object(clusterId, sidecar.EvsPlaceKey(repoId)) != nil || self.object(clusterId, RepoKey(repoId)) != nil {
			self.t.Fatalf("%s: a refused create wrote on %s", what, clusterId)
		}
	}
}

// A restorable deleted repo placed afresh is deleted from its first object: repo/ names the RepoDelete, its entry's
// time and its signer, the 7-day start is queued once from the entry's time, a retry writes nothing, activate answers
// 409 REPO_DELETED with the group formed, a reader's GET stays refused, and the RepoRestore brings it to active.
func TestPlaceInARecoveryCreatesARestorableDeletedRepoDeleted(t *testing.T) {
	fixture := newEvsFixture(t)
	fixture.setReseed(true)
	repoId, admin, reader := testId("repo"), testId("sidecar-a"), testId("sidecar-r")
	entryTime := fixture.clock.Now().Add(-3 * 24 * time.Hour)
	deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: entryTime, SignerSidecarId: testId("sidecar-signer")}
	fixture.projectDeletedRepo(repoId, admin, deletion)
	fixture.auth.grant(reader, repoId, sidecar.AclEvsRead)
	if status := fixture.putRepo(repoId, admin); status != http.StatusOK {
		t.Fatalf("create: %d", status)
	}
	if place := fixture.placement(repoId); place == nil || place.ClusterId != "meta-1" || place.CreatorSidecarId != admin {
		t.Fatalf("place/ %+v", place)
	}
	repoBytes := fixture.object("meta-1", RepoKey(repoId))
	object := fixture.repoObject(repoId)
	if object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || sidecar.Id(object.GetDeletionId()) != deletion.DeletionId ||
		object.GetStateMs() != entryTime.UnixMilli() || sidecar.Id(object.GetStateSigner()) != deletion.SignerSidecarId ||
		object.GetFormat() != sidecar.EvsRepoFormat1 || object.GetKind() != protocol.RepoKind_REPO_KIND_GENERAL ||
		sidecar.Id(object.GetNetworkId()) != sidecar.Id(fixture.networkId) {
		t.Fatalf("repo/ %v", object)
	}
	if requests := fixture.shredRequests(repoId); len(requests) != 1 || !requests[0].RunAt.Equal(entryTime.Add(evsShredStartAfter)) {
		t.Fatalf("the start queued %v", requests)
	}
	// a retry, later in the window: the same repo/, nothing rewritten, no second start
	fixture.clock.Advance(time.Hour)
	if status := fixture.putRepo(repoId, admin); status != http.StatusOK {
		t.Fatalf("a retry: %d", status)
	}
	if string(fixture.object("meta-1", RepoKey(repoId))) != string(repoBytes) {
		t.Fatal("a retry rewrote repo/")
	}
	if requests := fixture.shredRequests(repoId); len(requests) != 1 {
		t.Fatalf("a retry queued %d starts", len(requests))
	}
	// nothing activates it, its group re-formed or not
	activate := func() *httptest.ResponseRecorder {
		return fixture.serve(http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/activate", fixture.token(admin, repoScope(repoId, "admin")), nil)
	}
	requireRefusal(t, activate(), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	fixture.formGroup(repoId, testId("group"), true)
	requireRefusal(t, activate(), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	get := fixture.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId), fixture.token(reader, repoScope(repoId, "r")), nil)
	requireRefusal(t, get, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED {
		t.Fatalf("repo/ %v after the refused activations", object)
	}
	// restore resumes: the RepoRestore of its deletion brings it to active
	restored := *deletion
	restored.Restored = true
	fixture.projectDeletion(repoId, &restored)
	if status := fixture.lifecycle(http.MethodPost, repoId, "/restore", admin); status != http.StatusOK {
		t.Fatalf("restore: %d", status)
	}
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE || len(object.GetDeletionId()) != 0 {
		t.Fatalf("restored repo/ %v", object)
	}
}

// A repo past restoring is never placed afresh: its RepoDelete carrying now, undated, at the restore window's end or
// past it answers 409 SHREDDING, and neither place/ nor repo/ is written; the last moment inside the window still
// creates it deleted.
func TestPlaceInARecoveryRefusesARepoPastRestoring(t *testing.T) {
	fixture := newEvsFixture(t)
	fixture.setReseed(true)
	admin := testId("sidecar-a")
	window := fixture.engine.settings.ReseedRestoreWindow
	now := fixture.clock.Now()
	cases := []struct {
		what     string
		deletion *EvsRepoDeletionFacts
	}{
		{what: "a RepoDelete with now", deletion: &EvsRepoDeletionFacts{DeletionId: testId("deletion-now"), Now: true, Time: now.Add(-time.Hour), SignerSidecarId: admin}},
		{what: "an undated RepoDelete", deletion: &EvsRepoDeletionFacts{DeletionId: testId("deletion-undated"), SignerSidecarId: admin}},
		{what: "a RepoDelete at the window's end", deletion: &EvsRepoDeletionFacts{DeletionId: testId("deletion-end"), Time: now.Add(-window), SignerSidecarId: admin}},
		{what: "a RepoDelete past the window", deletion: &EvsRepoDeletionFacts{DeletionId: testId("deletion-past"), Time: now.Add(-window - 24*time.Hour), SignerSidecarId: admin}},
	}
	for index, c := range cases {
		repoId := testId("repo-" + string(rune('a'+index)))
		fixture.projectDeletedRepo(repoId, admin, c.deletion)
		for range 2 {
			recorder := fixture.putRepoAnswer(repoId, admin)
			if recorder.Code != http.StatusConflict || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING {
				t.Fatalf("%s: answered %d %s", c.what, recorder.Code, refusalOf(t, recorder).GetCode())
			}
		}
		fixture.requireNothingPlaced(c.what, repoId)
		if requests := fixture.shredRequests(repoId); len(requests) != 0 {
			t.Errorf("%s: queued %v", c.what, requests)
		}
	}
	// a millisecond inside the window is still restorable
	repoId := testId("repo-inside")
	inside := &EvsRepoDeletionFacts{DeletionId: testId("deletion-inside"), Time: now.Add(-window + time.Millisecond), SignerSidecarId: admin}
	fixture.projectDeletedRepo(repoId, admin, inside)
	if status := fixture.putRepo(repoId, admin); status != http.StatusOK {
		t.Fatalf("the window's last moment: %d", status)
	}
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || object.GetStateMs() != inside.Time.UnixMilli() {
		t.Fatalf("repo/ %v", object)
	}
	// and time passing it afterwards refuses the creator's retry too, repo/ left as the shred's
	fixture.clock.Advance(time.Second)
	requireRefusal(t, fixture.putRepoAnswer(repoId, admin), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)
}

// A RepoDelete whose signer neither the projection's log nor its row names creates nothing: 409 STATEMENT_MISSING, no
// value guessed for repo/'s state_signer, and the create goes through once the projection names it.
func TestPlaceInARecoveryWritesNoDeletedRepoWithoutItsSigner(t *testing.T) {
	fixture := newEvsFixture(t)
	fixture.setReseed(true)
	repoId, admin := testId("repo"), testId("sidecar-a")
	deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: fixture.clock.Now().Add(-time.Hour)}
	fixture.projectDeletedRepo(repoId, admin, deletion)
	requireRefusal(t, fixture.putRepoAnswer(repoId, admin), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING)
	fixture.requireNothingPlaced("no signer", repoId)
	named := *deletion
	named.SignerSidecarId = admin
	fixture.projectDeletion(repoId, &named)
	if status := fixture.putRepo(repoId, admin); status != http.StatusOK {
		t.Fatalf("with its signer: %d", status)
	}
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || sidecar.Id(object.GetStateSigner()) != admin {
		t.Fatalf("repo/ %v", object)
	}
}

// An unsure clock judges no restore window: a dated RepoDelete's create answers 503 with nothing written, a clock
// unknown or past §11.8's 50 ms alike, while a live repo's create, which judges none, goes through; sure again, the
// deleted repo is created deleted.
func TestPlaceInARecoveryJudgesTheWindowOnlyByASureClock(t *testing.T) {
	fixture := newEvsFixture(t)
	fixture.setReseed(true)
	repoId, liveRepoId, admin := testId("repo"), testId("repo-live"), testId("sidecar-a")
	deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: fixture.clock.Now().Add(-time.Hour), SignerSidecarId: admin}
	fixture.projectDeletedRepo(repoId, admin, deletion)
	fixture.projectRepo(liveRepoId, admin)
	fixture.host.ClockCheck.SetUnknown()
	requireRefusal(t, fixture.putRepoAnswer(repoId, admin), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	fixture.host.ClockCheck.SetOffset(60 * time.Millisecond)
	requireRefusal(t, fixture.putRepoAnswer(repoId, admin), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	fixture.requireNothingPlaced("an unsure clock", repoId)
	if status := fixture.putRepo(liveRepoId, admin); status != http.StatusOK {
		t.Fatalf("a live repo on an unsure clock: %d", status)
	}
	fixture.host.ClockCheck.SetOffset(10 * time.Millisecond)
	if status := fixture.putRepo(repoId, admin); status != http.StatusOK {
		t.Fatalf("sure again: %d", status)
	}
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED {
		t.Fatalf("repo/ %v", object)
	}
}

// Only a recovery, and only an unrestored RepoDelete, creates a repo deleted: with reseed off the same projection is
// created keying, as every create was, a repo past restoring included; with reseed on a live repo and one whose
// RepoDelete a RepoRestore answered, however old, are created keying; and a repo/ that stood keying before the
// recovery answers its creator's retry 200 as it stands, never rewritten.
func TestPlaceCreatesKeyingOutsideARecoveryAndForALiveRepo(t *testing.T) {
	fixture := newEvsFixture(t)
	admin := testId("sidecar-a")
	entryTime := fixture.clock.Now().Add(-3 * 24 * time.Hour)
	keying := func(what string, repoId sidecar.Id) []byte {
		t.Helper()
		if status := fixture.putRepo(repoId, admin); status != http.StatusOK {
			t.Fatalf("%s: %d", what, status)
		}
		object := fixture.repoObject(repoId)
		if object.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING || len(object.GetDeletionId()) != 0 || len(object.GetStateSigner()) != 0 {
			t.Fatalf("%s: repo/ %v", what, object)
		}
		if requests := fixture.shredRequests(repoId); len(requests) != 0 {
			t.Fatalf("%s: queued %v", what, requests)
		}
		return fixture.object("meta-1", RepoKey(repoId))
	}
	restorable := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: entryTime, SignerSidecarId: admin}
	fixture.setReseed(false)
	standing := testId("repo-standing")
	fixture.projectDeletedRepo(standing, admin, restorable)
	standingBytes := keying("reseed off", standing)
	past := testId("repo-past")
	fixture.projectDeletedRepo(past, admin, &EvsRepoDeletionFacts{DeletionId: testId("deletion-past"), Now: true, Time: entryTime, SignerSidecarId: admin})
	keying("reseed off, past restoring", past)

	fixture.setReseed(true)
	live := testId("repo-live")
	fixture.projectRepo(live, admin)
	keying("a live repo in a recovery", live)
	restored := testId("repo-restored")
	fixture.projectDeletedRepo(restored, admin, &EvsRepoDeletionFacts{
		DeletionId: testId("deletion-restored"), Time: fixture.clock.Now().Add(-30 * 24 * time.Hour), SignerSidecarId: admin, Restored: true,
	})
	keying("a restored repo in a recovery", restored)
	// the repo/ that stood keying is this create's repo: answered as it stands
	if status := fixture.putRepo(standing, admin); status != http.StatusOK {
		t.Fatalf("a retry over a keying repo/: %d", status)
	}
	if string(fixture.object("meta-1", RepoKey(standing))) != string(standingBytes) {
		t.Fatal("a retry rewrote a keying repo/")
	}
}
