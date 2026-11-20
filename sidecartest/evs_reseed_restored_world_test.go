// A restored repo's groups step, end to end on T2 (owner decision 618; QD-1077; §19.10's groups row, §11.8's place
// row, §11.12's naming paragraph and its restore and log first rows): the epoch world's repo is deleted and then
// restored, its devices' state holding the RepoDelete with a RepoRestore of it, and its site lost inside the restore
// window, as in evs_reseed_deleted_world_test.go. Where evs's projection at the new site holds the RepoDelete but not
// yet the RepoRestore, as for one filed after the log resumed, evsservice's PUT /evs/v1/repos/<id> creates repo/
// deleted{deletion_id, its entry's time, signer}; the admin's groups step (sidecar.EvsRepo.ReseedPlace) sends
// restore, the route alone, which evsservice answers 409 STATEMENT_MISSING until the projection holds the RepoRestore
// and then takes repo/ to active, before the re-form, so the step need not wait for taskworker's daily reconciler.
// Where the projection holds the RepoRestore at the place, repo/ is created keying and the restore is the one refused
// call the honest order costs. Either way the re-form's two calls come around an activate, and the walk returns the
// whole mirror into the active repo/, which a fresh reader reads.

package sidecartest

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The world of evs_reseed_deleted_world_test.go with the repo restored in its devices' state: its row carries the
// RepoDelete and a RepoRestore of it, while evs's projection holds the RepoDelete alone until the test projects the
// RepoRestore.
func newReseedRestoredWorld(t *testing.T) *reseedDeletedWorld {
	t.Helper()
	world := newReseedDeletedWorld(t, 3*24*time.Hour)
	restoredRow := proto.Clone(world.row).(*protocol.AclRepoDeletionRow)
	restoredRow.RestoredAt = 5
	mirrorWorldAdminWith(world.epochWorld, "w", restoredRow)
	return world
}

// The groups step's re-form of a restored repo, as it leaves the new site: its first call, with Reseed, returns the
// groups' objects and a Signed GroupForm of the repo naming the fake gkm's group, whose gen/1 they hold, which
// activate's check of a keying repo/ reads; its second call, without Reseed, whose rotation and Adds stay with the
// fake gkm, writes nothing here. Each call is noted with the state repo/ read at it.
func (self *reseedDeletedWorld) reformRestored(calls *[]string) func(ctx context.Context, args *sidecar.GkmReformArgs) (sidecar.Id, error) {
	t := self.t
	formed := false
	return func(ctx context.Context, args *sidecar.GkmReformArgs) (sidecar.Id, error) {
		groupId, generation, ok := self.gkm.Newest(self.repoId)
		if !ok {
			t.Fatal("the fake gkm holds no group of the repo")
		}
		if args.RepoId != self.repoId {
			t.Errorf("a re-form of another repo: %+v", args)
		}
		object, _ := self.repoObject()
		*calls = append(*calls, fmt.Sprintf("reseed %t at %s", args.Reseed, object.GetState()))
		if !args.Reseed || formed {
			return groupId, nil
		}
		formed = true
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

// Records each request the devices send the new site, its method and path, and calls atRestore before each restore
// reaches evs, with the count of restores so far and the state repo/ reads then.
func (self *reseedDeletedWorld) beforeRestore(atRestore func(restoreCount int, state protocol.EvsRepoState)) {
	restoreCount := 0
	self.setIntercept(func(device *epochDevice, request *http.Request) error {
		self.stateLock.Lock()
		self.requests = append(self.requests, request.Method+" "+request.URL.Path)
		self.stateLock.Unlock()
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/restore") {
			restoreCount += 1
			object, _ := self.repoObject()
			atRestore(restoreCount, object.GetState())
		}
		return nil
	})
}

// The walk returns the whole mirror into the active repo/, and a device that never read the repo reads its history.
func (self *reseedDeletedWorld) requireReturnedLive() {
	t := self.t
	t.Helper()
	result, err := self.reseed(self.writer, &sidecar.EvsReseedArgs{IncidentId: []byte("incident 77")})
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
	if returned := self.head(self.refId); returned.GetVersion() != self.mirrored.GetVersion() || !bytes.Equal(returned.GetChain(), self.mirrored.GetChain()) {
		t.Fatalf("the returned head is at %d; the mirror held %d", returned.GetVersion(), self.mirrored.GetVersion())
	}
	if object, _ := self.repoObject(); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE || len(object.GetDeletionId()) != 0 {
		t.Fatalf("repo/ after the walk %v", object)
	}
	fresh := self.device("m", nil)
	for path, want := range map[string][]byte{"ledger/a": self.small, "ledger/b": self.large} {
		content, _, err := fresh.read(path)
		if err != nil || !bytes.Equal(content, want) {
			t.Fatalf("a fresh reader's %s: %d bytes, %v", path, len(content), err)
		}
	}
}

// A RepoRestore evs's projection trails at the place: repo/ is created deleted under the RepoDelete the projection
// holds, the groups step's restore is answered 409 STATEMENT_MISSING and asked again until the projection holds the
// RepoRestore, which then takes repo/ to active, and the re-form's two calls both find repo/ active, the activate
// between them answering 200. The walk returns the whole mirror into it, which a fresh reader reads.
func TestEvsReseedPlaceRestoresARestoredRepoPlacedDeletedEndToEnd(t *testing.T) {
	world := newReseedRestoredWorld(t)
	repoPath := "/evs/v1/repos/" + sidecar.EvsKeyId(world.repoId)
	atRestores := []protocol.EvsRepoState{}
	world.beforeRestore(func(restoreCount int, state protocol.EvsRepoState) {
		atRestores = append(atRestores, state)
		if restoreCount == 2 {
			// the projection catches up while the device waits
			world.auth.restore()
		}
	})

	calls := []string{}
	placed, err := world.writer.repo.ReseedPlace(world.ctx, &sidecar.EvsReseedPlaceArgs{ReformGroup: world.reformRestored(&calls)})
	if err != nil {
		t.Fatalf("the groups step: %v", err)
	}
	if placed.Deleted || !placed.Mended || placed.PlacedByAnother {
		t.Fatalf("placed %+v", placed)
	}
	want := []string{"PUT " + repoPath, "POST " + repoPath + "/restore", "POST " + repoPath + "/restore", "POST " + repoPath + "/activate"}
	if sent := world.sent(); !slices.Equal(sent, want) {
		t.Fatalf("the groups step sent %v, want %v", sent, want)
	}
	if want := []protocol.EvsRepoState{protocol.EvsRepoState_EVS_REPO_DELETED, protocol.EvsRepoState_EVS_REPO_DELETED}; !slices.Equal(atRestores, want) {
		t.Fatalf("repo/ at the restores: %v", atRestores)
	}
	if want := []string{"reseed true at EVS_REPO_ACTIVE", "reseed false at EVS_REPO_ACTIVE"}; !slices.Equal(calls, want) {
		t.Fatalf("the re-forms: %v", calls)
	}
	world.requireReturnedLive()
}

// The honest order: evs's projection holds the RepoRestore at the place, so repo/ is created keying, and the groups
// step's restore is answered 409 REPO_KEYING, the one refused call it costs, which mends nothing; the re-form's first
// call finds repo/ keying, activate takes it to active, and the second call finds it active. The walk returns the whole
// mirror into it, which a fresh reader reads.
func TestEvsReseedPlaceCostsARestoredRepoOneRefusedRestoreEndToEnd(t *testing.T) {
	world := newReseedRestoredWorld(t)
	world.auth.restore()
	repoPath := "/evs/v1/repos/" + sidecar.EvsKeyId(world.repoId)
	atRestores := []protocol.EvsRepoState{}
	world.beforeRestore(func(restoreCount int, state protocol.EvsRepoState) {
		atRestores = append(atRestores, state)
	})

	calls := []string{}
	placed, err := world.writer.repo.ReseedPlace(world.ctx, &sidecar.EvsReseedPlaceArgs{ReformGroup: world.reformRestored(&calls)})
	if err != nil {
		t.Fatalf("the groups step: %v", err)
	}
	// the step takes no refusal of its restore but 409 REPO_KEYING, and a 200 would have said it mended repo/
	if placed.Deleted || placed.Mended || placed.PlacedByAnother {
		t.Fatalf("placed %+v", placed)
	}
	want := []string{"PUT " + repoPath, "POST " + repoPath + "/restore", "POST " + repoPath + "/activate"}
	if sent := world.sent(); !slices.Equal(sent, want) {
		t.Fatalf("the groups step sent %v, want %v", sent, want)
	}
	if want := []protocol.EvsRepoState{protocol.EvsRepoState_EVS_REPO_KEYING}; !slices.Equal(atRestores, want) {
		t.Fatalf("repo/ at the restores: %v", atRestores)
	}
	if want := []string{"reseed true at EVS_REPO_KEYING", "reseed false at EVS_REPO_ACTIVE"}; !slices.Equal(calls, want) {
		t.Fatalf("the re-forms: %v", calls)
	}
	world.requireReturnedLive()
}
