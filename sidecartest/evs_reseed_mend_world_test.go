// A repo re-seeded as deleted whose repo/ the new site created keying, end to end on T2 (QD-1064; §19.10's groups
// row, §11.12's state, activate, delete and refused rows): the epoch world's repo is deleted, its RepoDelete
// unrestored in its devices' state, and its site lost inside the restore window, as in
// evs_reseed_deleted_world_test.go. Here evsservice's PUT /evs/v1/repos/<id> creates repo/ keying, as it does while
// the operator has not yet turned reseed on at the new site, or while its projection does not yet hold the RepoDelete
// the devices' state shows. The admin's groups step (sidecar.EvsRepo.ReseedPlace) activates it, which answers 200, and
// sends DELETE, the route alone, which moves repo/ from active to deleted{deletion_id, its entry's time, signer} under
// the projected RepoDelete, a trailing projection's 409 STATEMENT_MISSING waited out. While repo/ reads active between
// the two, evs's view of the projection, holding the RepoDelete, gives the admin admin alone (QD-880), so even its
// admin token reads nothing. The walk then returns the whole mirror into the deleted repo/, as in the honest order,
// and the step run again costs one refused activate.

package sidecartest

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Sets the RepoDelete evs's view of the projection holds, nil while that view trails the devices' state.
func (self *reseedDeletedAuthState) project(deletion *evsservice.EvsRepoDeletionFacts) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.deletion = deletion
}

// Turns the new site's reseed gate on or off.
func (self *reseedDeletedWorld) setReseed(on bool) {
	self.t.Helper()
	network := connect.Id(self.networkId).String()
	if err := self.host.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  reseed: %t\n", network, on)); err != nil {
		self.t.Fatal(err)
	}
}

// The groups step's re-form, once, as it leaves the new site for activate's check of a keying repo/: the groups'
// objects returned and a Signed GroupForm of the repo naming the fake gkm's group, whose gen/1 they hold. Fails the
// test unless repo/ stands keying when the re-form comes.
func (self *reseedDeletedWorld) reformKeying() func(ctx context.Context, args *sidecar.GkmReformArgs) (sidecar.Id, error) {
	t := self.t
	reformed := false
	return func(ctx context.Context, args *sidecar.GkmReformArgs) (sidecar.Id, error) {
		groupId, generation, ok := self.gkm.Newest(self.repoId)
		if !ok {
			t.Fatal("the fake gkm holds no group of the repo")
		}
		if !args.Reseed || args.RepoId != self.repoId {
			t.Errorf("a re-form of a repo re-seeded as deleted asked %+v", args)
		}
		if reformed {
			return groupId, nil
		}
		reformed = true
		if object, _ := self.repoObject(); object.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING {
			t.Fatalf("repo/ at the re-form: %v", object)
		}
		self.returnGroups(self.lost)
		formBody, err := proto.Marshal(&protocol.GroupForm{RepoId: self.repoId.Bytes(), GroupId: groupId.Bytes(), Generation: generation})
		if err != nil {
			t.Fatal(err)
		}
		form, err := self.signers["w"].Sign("group-form", bridge.SignedType_SIGNED_GROUP_FORM, formBody, nil)
		if err != nil {
			t.Fatal(err)
		}
		formBytes, err := proto.Marshal(form)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := self.cluster.PutIfNoneMatch(self.ctx, gkmservice.GkmFormKey(self.repoId, 1), formBytes, nil); err != nil {
			t.Fatal(err)
		}
		return groupId, nil
	}
}

// Records each request the devices send the new site, its method and path with any query, and calls atDelete before
// each DELETE reaches evs, with the count of DELETEs so far.
func (self *reseedDeletedWorld) beforeDelete(atDelete func(deleteCount int)) {
	deleteCount := 0
	self.setIntercept(func(device *epochDevice, request *http.Request) error {
		self.stateLock.Lock()
		self.requests = append(self.requests, request.Method+" "+request.URL.RequestURI())
		if request.Method == http.MethodDelete {
			deleteCount += 1
		}
		count := deleteCount
		self.stateLock.Unlock()
		if request.Method == http.MethodDelete {
			atDelete(count)
		}
		return nil
	})
}

// The refusal code an answer carries.
func reseedMendRefusalCode(t *testing.T, body []byte) protocol.EvsRefusalCode {
	t.Helper()
	reply := &protocol.EvsRefusalReply{}
	if err := proto.Unmarshal(body, reply); err != nil {
		t.Fatalf("a refusal that does not parse: %v", err)
	}
	return reply.GetCode()
}

// While the new site's reseed gate is still off, its place creates repo/ keying. The groups step's activate answers
// 200 and its DELETE, with no query and no statement filed, takes repo/ to deleted{deletion_id, its entry's time,
// signer}, the admin reading nothing while repo/ reads active between the two. Once the operator turns reseed on, the
// walk returns the whole mirror into the deleted repo/, whose bytes it never rewrites, and the step run again costs one
// refused activate.
func TestEvsReseedPlaceDeletesARepoPlacedKeyingWhileReseedWasOffEndToEnd(t *testing.T) {
	world := newReseedDeletedWorld(t, 3*24*time.Hour)
	repoPath := "/evs/v1/repos/" + sidecar.EvsKeyId(world.repoId)
	world.setReseed(false)
	between := 0
	world.beforeDelete(func(deleteCount int) {
		object, _ := world.repoObject()
		if object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
			t.Errorf("repo/ at DELETE %d: %v", deleteCount, object)
			return
		}
		// the projection holds the RepoDelete: its admin holds admin alone, so neither its admin token nor a reading
		// one reads the active repo/
		for _, role := range []string{"admin", "r"} {
			recorder := world.requestAs(role, http.MethodGet, "")
			if recorder.Code != http.StatusForbidden || reseedMendRefusalCode(t, recorder.Body.Bytes()) != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
				t.Errorf("a GET of the active repo/ under the admin's %s token: %d", role, recorder.Code)
			}
		}
		between += 1
	})

	reform := world.reformKeying()
	placed, err := world.writer.repo.ReseedPlace(world.ctx, &sidecar.EvsReseedPlaceArgs{ReformGroup: reform})
	if err != nil {
		t.Fatalf("the groups step: %v", err)
	}
	if !placed.Deleted || !placed.Mended || placed.PlacedByAnother {
		t.Fatalf("placed %+v", placed)
	}
	if sent, want := world.sent(), []string{"PUT " + repoPath, "POST " + repoPath + "/activate", "DELETE " + repoPath}; !slices.Equal(sent, want) {
		t.Fatalf("the groups step sent %v, want %v", sent, want)
	}
	if between != 1 {
		t.Fatalf("%d DELETEs met an active repo/", between)
	}
	mended := world.requireDeleted("after the groups step")

	// the operator turns reseed on, and the walk, its first request a segment upload, returns the whole mirror
	world.setReseed(true)
	result, err := world.reseed(world.writer, &sidecar.EvsReseedArgs{IncidentId: []byte("incident 64")})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range result.Refs {
		if ref.Stopped != nil || ref.FileError != nil {
			t.Fatalf("ref %s stopped at %d of %d: %v; its EvsReseed: %v", ref.RefId, ref.Version, ref.MirrorVersion, ref.Stopped, ref.FileError)
		}
	}
	if !result.Whole() || result.SegmentCount == 0 || result.SlotCount == 0 {
		t.Fatalf("the walk sent %d segments and %d slots, whole %v", result.SegmentCount, result.SlotCount, result.Whole())
	}
	if returned := world.head(world.refId); returned.GetVersion() != world.mirrored.GetVersion() || !bytes.Equal(returned.GetChain(), world.mirrored.GetChain()) {
		t.Fatalf("the returned head is at %d; the mirror held %d", returned.GetVersion(), world.mirrored.GetVersion())
	}
	if after := world.requireDeleted("after the walk"); !bytes.Equal(after, mended) {
		t.Fatal("the walk rewrote repo/")
	}
	if _, _, err := world.device("r", nil).read("ledger/a"); err == nil {
		t.Fatal("a read of a repo re-seeded as deleted")
	}

	// the step run again: the place answers its retry, and activate refuses the deleted repo/
	world.sent()
	placed, err = world.writer.repo.ReseedPlace(world.ctx, &sidecar.EvsReseedPlaceArgs{ReformGroup: reform})
	if err != nil || !placed.Deleted || placed.Mended {
		t.Fatalf("the step run again: %+v, %v", placed, err)
	}
	if sent, want := world.sent(), []string{"PUT " + repoPath, "POST " + repoPath + "/activate"}; !slices.Equal(sent, want) {
		t.Fatalf("the step run again sent %v, want %v", sent, want)
	}
	if after := world.requireDeleted("after the step run again"); !bytes.Equal(after, mended) {
		t.Fatal("the step run again rewrote repo/")
	}
}

// A RepoDelete filed after the log resumed reaches the devices' state before evs's projection: the place, reseed on,
// creates repo/ keying for a repo evs still lists live, the activate answers 200, and the DELETE's 409
// STATEMENT_MISSING is asked again until the projection holds the RepoDelete, which then takes repo/ to deleted, and
// the walk returns the whole mirror into it.
func TestEvsReseedPlaceWaitsOutATrailingProjectionEndToEnd(t *testing.T) {
	world := newReseedDeletedWorld(t, 3*24*time.Hour)
	repoPath := "/evs/v1/repos/" + sidecar.EvsKeyId(world.repoId)
	world.auth.project(nil)
	world.beforeDelete(func(deleteCount int) {
		if object, _ := world.repoObject(); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
			t.Errorf("repo/ at DELETE %d: %v", deleteCount, object)
		}
		if deleteCount == 2 {
			// the projection catches up while the device waits
			deletion := *world.deletion
			world.auth.project(&deletion)
		}
	})

	placed, err := world.writer.repo.ReseedPlace(world.ctx, &sidecar.EvsReseedPlaceArgs{ReformGroup: world.reformKeying()})
	if err != nil {
		t.Fatalf("the groups step: %v", err)
	}
	if !placed.Deleted || !placed.Mended || placed.PlacedByAnother {
		t.Fatalf("placed %+v", placed)
	}
	want := []string{"PUT " + repoPath, "POST " + repoPath + "/activate", "DELETE " + repoPath, "DELETE " + repoPath}
	if sent := world.sent(); !slices.Equal(sent, want) {
		t.Fatalf("the groups step sent %v, want %v", sent, want)
	}
	mended := world.requireDeleted("after the projection caught up")

	result, err := world.reseed(world.writer, &sidecar.EvsReseedArgs{IncidentId: []byte("incident 64")})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Whole() || result.SegmentCount == 0 || result.SlotCount == 0 {
		t.Fatalf("the walk sent %d segments and %d slots, whole %v", result.SegmentCount, result.SlotCount, result.Whole())
	}
	if after := world.requireDeleted("after the walk"); !bytes.Equal(after, mended) {
		t.Fatal("the walk rewrote repo/")
	}
}
