// A repo re-seeded as deleted, end to end on T2 (EVSB-M2-20; §19.10's groups and repos rows, §11.12's re-seed
// exception, §11.13's re-seed row; QD-1062, QD-977): the epoch world's repo is deleted, its RepoDelete unrestored, and
// its site is lost inside the restore window. On the new site, evs with reseed on, the repo admin's device runs the
// groups step (sidecar.EvsRepo.ReseedPlace) through evsservice's PUT /evs/v1/repos/<id>, which creates repo/
// deleted{deletion_id, its entry's time, signer} and never keying, re-forms the group and sends an activate, which
// evs refuses 409 REPO_DELETED, activating nothing (a repo/ created keying is evs_reseed_mend_world_test.go's); then its
// walk (sidecar.EvsRepo.Reseed), whose first request is a segment upload, before any reseed call, returns the whole
// mirror while repo/ stays deleted, every read refused. The RepoRestore then brings back a repo a fresh reader reads.
// A repo past its restore window is refused 409 SHREDDING at the place, and nothing of it comes back.
//
// evs's view of the projection here gives a deleted repo's standing admin admin alone, as the real gate state does
// (QD-880), so the walk's uploads pass only by the guard's marked pass (QD-977).

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// evs's view of the projection in a recovery of a deleted repo: the repo's facts with its newest RepoDelete, and, while
// that stands unrestored, admin alone to the repo's standing admin and nothing to anyone else (QD-880); every right of
// its token to every principal once it is restored.
type reseedDeletedAuthState struct {
	networkId sidecar.Id
	kind      protocol.RepoKind
	adminId   sidecar.Id

	stateLock sync.Mutex
	deletion  *evsservice.EvsRepoDeletionFacts
}

func (self *reseedDeletedAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *reseedDeletedAuthState) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *reseedDeletedAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.deletion == nil || self.deletion.Restored {
		return evsservice.EvsAuthAllowed
	}
	if rights == sidecar.AclEvsAdmin && principal.SidecarId != nil && sidecar.Id(*principal.SidecarId) == self.adminId {
		return evsservice.EvsAuthAllowed
	}
	return evsservice.EvsAuthDenied
}

func (self *reseedDeletedAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	facts := &evsservice.EvsRepoFacts{Kind: self.kind, NetworkId: self.networkId}
	if self.deletion != nil {
		deletion := *self.deletion
		facts.Deletion = &deletion
	}
	return facts, evsservice.EvsAuthAllowed
}

// Projects a RepoRestore of the deletion.
func (self *reseedDeletedAuthState) restore() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	restored := *self.deletion
	restored.Restored = true
	self.deletion = &restored
}

// A record repo whose first version carries a segment, mirrored whole by its admin's device, then deleted by a
// RepoDelete entered deletedAgo before now, in the devices' state and in evs's projection, and its site lost with
// nothing of the repo on the new one.
type reseedDeletedWorld struct {
	*epochWorld
	writer    *epochDevice
	auth      *reseedDeletedAuthState
	deletion  *evsservice.EvsRepoDeletionFacts
	row       *protocol.AclRepoDeletionRow
	refId     sidecar.Id
	mirrored  *protocol.EvsHead
	lost      sidecar.BlobCluster
	large     []byte
	small     []byte
	stateLock sync.Mutex
	// each request a device sent the new site, method and path
	requests []string
}

func newReseedDeletedWorld(t *testing.T, deletedAgo time.Duration) *reseedDeletedWorld {
	t.Helper()
	world := &reseedDeletedWorld{
		epochWorld: newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD),
		large:      bytes.Repeat([]byte("a larger entry; "), 20000),
		small:      bytes.Repeat([]byte("an entry of the ledger; "), 300),
	}
	world.writer = world.device("w", nil)
	// the ref's first version introduces segments, so the walk's first request of the ref is an upload
	if _, err := world.writer.write("ledger/b", world.large); err != nil {
		t.Fatalf("the large entry: %v", err)
	}
	if len(world.segmentKeys()) == 0 {
		t.Fatal("the first version wrote no segment")
	}
	if _, err := world.writer.write("ledger/a", world.small); err != nil {
		t.Fatalf("the small entry: %v", err)
	}
	mirrorWorldAdmin(world.epochWorld, "w")
	mirror := newWorldMirror(t, world.epochWorld, world.writer)
	if _, err := mirror.Sync(world.ctx); err != nil {
		t.Fatal(err)
	}
	world.refId = world.mainRefId(world.writer)
	world.mirrored = world.head(world.refId)
	// the RepoDelete, in the devices' state and the projection's rows
	adminId := world.signers["w"].SidecarId
	deletionId := sidecar.NewId()
	entryTime := world.clock.Now().Add(-deletedAgo)
	world.row = &protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), DeletedAt: 3, DeletedTimeMs: entryTime.UnixMilli(), Signer: adminId.Bytes()}
	mirrorWorldAdminWith(world.epochWorld, "w", world.row)
	world.deletion = &evsservice.EvsRepoDeletionFacts{DeletionId: deletionId, Time: time.UnixMilli(entryTime.UnixMilli()), SignerSidecarId: adminId}
	deletion := *world.deletion
	world.auth = &reseedDeletedAuthState{networkId: world.networkId, kind: world.kind, adminId: adminId, deletion: &deletion}
	world.lost = world.loseSiteUnplaced(world.auth)
	world.setIntercept(func(device *epochDevice, request *http.Request) error {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.requests = append(world.requests, request.Method+" "+request.URL.Path)
		return nil
	})
	return world
}

// The requests the devices sent the new site since the last call.
func (self *reseedDeletedWorld) sent() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	requests := self.requests
	self.requests = nil
	return requests
}

// repo/ as the new site's cluster holds it, nil for none, with its bytes.
func (self *reseedDeletedWorld) repoObject() (*protocol.EvsRepoObject, []byte) {
	self.t.Helper()
	object, err := self.cluster.Get(self.ctx, evsservice.RepoKey(self.repoId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		self.t.Fatal(err)
	}
	objectBytes, err := readAllAndClose(object)
	if err != nil {
		self.t.Fatal(err)
	}
	parsed, err := sidecar.ParseEvsRepoObject(self.repoId, objectBytes)
	if err != nil {
		self.t.Fatal(err)
	}
	return parsed, objectBytes
}

// Fails unless repo/ reads deleted under the world's RepoDelete, its entry's time and its signer.
func (self *reseedDeletedWorld) requireDeleted(when string) []byte {
	self.t.Helper()
	object, objectBytes := self.repoObject()
	if object == nil || object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED ||
		!bytes.Equal(object.GetDeletionId(), self.deletion.DeletionId.Bytes()) || object.GetStateMs() != self.deletion.Time.UnixMilli() ||
		!bytes.Equal(object.GetStateSigner(), self.deletion.SignerSidecarId.Bytes()) {
		self.t.Fatalf("%s: repo/ %v", when, object)
	}
	return objectBytes
}

// One lifecycle request of the repo's admin at the new site's engine.
func (self *reseedDeletedWorld) lifecycle(method string, suffix string) *httptest.ResponseRecorder {
	return self.requestAs("admin", method, suffix)
}

// One request of the repo's admin at the new site's engine, past the devices' transport, under a token of role.
func (self *reseedDeletedWorld) requestAs(role string, method string, suffix string) *httptest.ResponseRecorder {
	signer := self.signers["w"]
	connectSidecarId := connect.Id(signer.SidecarId)
	token := self.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(self.networkId), ClientId: connect.Id(self.clientId), SidecarId: &connectSidecarId,
		Audience: evsservice.EvsAudience, Scopes: []string{fmt.Sprintf("repo:%s:%s", self.repoId, role)},
		IssuedAt: self.clock.Now(), ExpiresAt: self.clock.Now().Add(15 * time.Minute),
	})
	request := httptest.NewRequest(method, "https://evs.example/evs/v1/repos/"+sidecar.EvsKeyId(self.repoId)+suffix, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// The walk of a repo re-seeded as deleted whose first walked version carries new segments uploads them and completes,
// with repo/ deleted from creation.
func TestEvsReseedReturnsARepoReseededAsDeletedEndToEnd(t *testing.T) {
	world := newReseedDeletedWorld(t, 3*24*time.Hour)
	repoPath := "/evs/v1/repos/" + sidecar.EvsKeyId(world.repoId)
	if object, _ := world.repoObject(); object != nil {
		t.Fatalf("repo/ on the new site before its place: %v", object)
	}

	// the groups step: the place creates repo/ deleted, the group re-forms as a deleted repo's, and the activate it
	// sends, the one refused call this order costs, is answered 409 REPO_DELETED, its group there, activating nothing
	reforms := []*sidecar.GkmReformArgs{}
	groupId := sidecar.NewId()
	var created []byte
	placed, err := world.writer.repo.ReseedPlace(world.ctx, &sidecar.EvsReseedPlaceArgs{
		ReformGroup: func(ctx context.Context, args *sidecar.GkmReformArgs) (sidecar.Id, error) {
			// the repo stands deleted before its group returns
			created = world.requireDeleted("at the re-form")
			reforms = append(reforms, args)
			world.returnGroups(world.lost)
			return groupId, nil
		},
	})
	if err != nil {
		t.Fatalf("the groups step: %v", err)
	}
	if !placed.Deleted || placed.Mended || placed.PlacedByAnother || placed.GroupId != groupId {
		t.Fatalf("placed %+v", placed)
	}
	if len(reforms) != 1 || reforms[0].RepoId != world.repoId || !reforms[0].Reseed {
		t.Fatalf("re-forms %+v", reforms)
	}
	if sent := world.sent(); len(sent) != 2 || sent[0] != "PUT "+repoPath || sent[1] != "POST "+repoPath+"/activate" {
		t.Fatalf("the groups step sent %v", sent)
	}
	if after := world.requireDeleted("after the groups step"); !bytes.Equal(after, created) {
		t.Fatal("the refused activate rewrote repo/")
	}

	// the walk: its first request is the first version's segment, before any reseed call
	result, err := world.reseed(world.writer, &sidecar.EvsReseedArgs{IncidentId: []byte("incident 62")})
	if err != nil {
		t.Fatal(err)
	}
	sent := world.sent()
	if len(sent) == 0 || !strings.HasPrefix(sent[0], "PUT "+repoPath+"/segments/") {
		t.Fatalf("the walk began with %v", sent)
	}
	for _, ref := range result.Refs {
		if ref.Stopped != nil || ref.FileError != nil {
			t.Fatalf("ref %s stopped at %d of %d: %v; its EvsReseed: %v", ref.RefId, ref.Version, ref.MirrorVersion, ref.Stopped, ref.FileError)
		}
	}
	for _, slot := range result.Slots {
		t.Errorf("slot %s was not taken: %v", slot.SlotId, slot.Refused)
	}
	if !result.Whole() || result.SegmentCount == 0 || result.SlotCount == 0 {
		t.Fatalf("the walk sent %d segments and %d slots, whole %v", result.SegmentCount, result.SlotCount, result.Whole())
	}
	main := reseedRefOf(t, result, world.refId)
	if main.Version != world.mirrored.GetVersion() || !bytes.Equal(main.Chain[:], world.mirrored.GetChain()) {
		t.Fatalf("the main ref returned to %d; the mirror held %d", main.Version, world.mirrored.GetVersion())
	}
	if returned := world.head(world.refId); returned.GetVersion() != world.mirrored.GetVersion() || !bytes.Equal(returned.GetChain(), world.mirrored.GetChain()) ||
		!bytes.Equal(returned.GetPushId(), world.mirrored.GetPushId()) {
		t.Fatalf("the returned head is at %d", returned.GetVersion())
	}
	if len(world.segmentKeys()) == 0 {
		t.Fatal("no segment on the new site")
	}
	// repo/ never left deleted: the bytes its creation wrote
	if after := world.requireDeleted("after the walk"); !bytes.Equal(after, created) {
		t.Fatal("the walk rewrote repo/")
	}
	// access stays refused while the history returns and after it
	reader := world.device("r", nil)
	if _, _, err := reader.read("ledger/a"); err == nil {
		t.Fatal("a read of a repo re-seeded as deleted")
	}
	if _, err := world.device("v", nil).write("ledger/d", []byte("written while deleted")); err == nil {
		t.Fatal("a push into a repo re-seeded as deleted")
	}
	// a second walk finds everything there
	if again, err := world.reseed(world.writer, &sidecar.EvsReseedArgs{IncidentId: []byte("incident 62")}); err != nil || !again.Whole() {
		t.Fatalf("a second walk: %+v, %v", again, err)
	}

	// the RepoRestore: the repo is live again with its history, which a device that never read it reads
	restoredRow := proto.Clone(world.row).(*protocol.AclRepoDeletionRow)
	restoredRow.RestoredAt = 5
	mirrorWorldAdminWith(world.epochWorld, "w", restoredRow)
	world.auth.restore()
	if recorder := world.lifecycle(http.MethodPost, "/restore"); recorder.Code != http.StatusOK {
		t.Fatalf("restore: %d", recorder.Code)
	}
	if object, _ := world.repoObject(); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE || len(object.GetDeletionId()) != 0 {
		t.Fatalf("restored repo/ %v", object)
	}
	fresh := world.device("m", nil)
	for path, want := range map[string][]byte{"ledger/a": world.small, "ledger/b": world.large} {
		content, _, err := fresh.read(path)
		if err != nil || !bytes.Equal(content, want) {
			t.Fatalf("a fresh reader's %s after the restore: %d bytes, %v", path, len(content), err)
		}
	}
}

// A repo past its restore window is refused 409 SHREDDING at the place: neither place/ nor repo/ is written, no group
// is re-formed, and the walk returns nothing of it.
func TestEvsReseedPlaceRefusesARepoPastItsRestoreWindowEndToEnd(t *testing.T) {
	world := newReseedDeletedWorld(t, evsservice.DefaultEvsSettings().ReseedRestoreWindow+time.Hour)
	placed, err := world.writer.repo.ReseedPlace(world.ctx, &sidecar.EvsReseedPlaceArgs{
		ReformGroup: func(ctx context.Context, args *sidecar.GkmReformArgs) (sidecar.Id, error) {
			t.Error("a group re-formed for a repo past restoring")
			return sidecar.Id{}, nil
		},
	})
	if !sidecar.IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING) || placed != nil {
		t.Fatalf("the place of a repo past restoring: %+v, %v", placed, err)
	}
	evsError, _ := sidecar.EvsErrorOf(err)
	if evsError.Status != http.StatusConflict {
		t.Fatalf("answered %d", evsError.Status)
	}
	if sent := world.sent(); len(sent) != 1 || sent[0] != "PUT /evs/v1/repos/"+sidecar.EvsKeyId(world.repoId) {
		t.Fatalf("the groups step sent %v", sent)
	}
	// every object of a repo carries its id in its key, on the metadata cluster and the segment cluster alike
	nothing := func(when string) {
		t.Helper()
		for key := range world.host.Blobs.Dump() {
			if strings.Contains(key, sidecar.EvsKeyId(world.repoId)) {
				t.Fatalf("%s: the new site holds %s", when, key)
			}
		}
	}
	nothing("after the refused place")
	// the walk, run all the same, returns nothing: no ref gets a version in
	result, err := world.reseed(world.writer, &sidecar.EvsReseedArgs{IncidentId: []byte("incident 62")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Whole() || result.SegmentCount != 0 || result.SlotCount != 0 {
		t.Fatalf("a walk into an unplaced repo: %d segments, %d slots, whole %v", result.SegmentCount, result.SlotCount, result.Whole())
	}
	for _, ref := range result.Refs {
		if ref.Stopped == nil || ref.Version != 0 {
			t.Fatalf("ref %s went to %d: %v", ref.RefId, ref.Version, ref.Stopped)
		}
	}
	nothing("after the walk")
}
