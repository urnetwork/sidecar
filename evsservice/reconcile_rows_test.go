// QD-798 through the real gate on T2: taskworker's reconciler applies a RepoDelete the route never got, from the
// AclRepo row's time and signer, over §8.9's real gate cache reading the admission world's log from the Net's Redis and
// first metadata cluster, as evs's lifecycle jobs read it (taskworker's installEvsDeletionSource). The owner creates a
// general repo, evs places and activates it, and the owner files its RepoDelete and is killed before calling DELETE:
//
//	retention   a gate that read every entry, two bases on: its log no longer keeps the RepoDelete's entry
//	later base  a gate that first loads the network after one base folded the RepoDelete: its log never judged it
//
// Either way the walk writes deleted{deletion_id, the entry's time, the statement's signer} and queues the start,
// which at 7 d 10 min past the entry moves repo/ to shredding. No sleeps: each load is awaited by the cache's OnLoad,
// and the clock is the Net's.

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// rev/ holding no object.
type evsDeletionRowRevocations struct{}

func (self evsDeletionRowRevocations) Check(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

// One gate cache over the Net's stores, as an evs or taskworker process holds one, with its loads.
type evsDeletionRowGate struct {
	cache *sidecar.AclGateCache
	loads chan *bridge.AuthPin
}

// The world: the Net, its admission network, the gate evs's engine serves from, and the repo and its deletion.
type evsDeletionRowWorld struct {
	t          *testing.T
	net        *sidecartest.Net
	admission  *sidecartest.AdmissionNet
	gate       *evsDeletionRowGate
	engine     *EvsEngine
	repoId     sidecar.Id
	deletionId sidecar.Id
}

func newEvsDeletionRowWorld(t *testing.T) *evsDeletionRowWorld {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = sidecartest.AclAdmissionCompile
	admission := sidecartest.NewAdmissionNet(t, tier)
	t.Cleanup(admission.Close)
	world := &evsDeletionRowWorld{
		t: t, net: net, admission: admission,
		repoId: admission.Id("deleted repo"), deletionId: admission.Id("deletion"),
	}
	fakes := net.Fakes()
	sidecartest.RegisterEvsTwins(fakes.Redis)
	fakes.Gates.OpenService(sidecar.ServiceGateEvs, connect.Id(admission.NetworkId()))
	fakes.Quota.SetBalance(connect.Id(admission.NetworkId()), 1<<40)
	world.gate = world.newGate()
	settings := DefaultEvsSettings()
	settings.RepoCacheTtl = 0
	world.engine, err = NewEvsEngine(t.Context(), net.Host(), settings, &EvsEngineDeps{
		AuthState: NewAclEvsAuthState(world.gate.cache, evsDeletionRowRevocations{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.engine.Close)
	return world
}

// A gate cache of its own over the Net's Redis and first metadata cluster, holding nothing until its first load.
func (self *evsDeletionRowWorld) newGate() *evsDeletionRowGate {
	gate := &evsDeletionRowGate{loads: make(chan *bridge.AuthPin, 64)}
	gateSettings := sidecar.DefaultAclGateSettings()
	gateSettings.Log = sidecar.NewNoopLogger()
	gateSettings.PollInterval = 0
	gateSettings.FailureBackoff = 0
	gateSettings.OnLoad = func(networkId sidecar.Id, pin *bridge.AuthPin, err error) {
		if err != nil {
			self.t.Errorf("the gate's load: %v", err)
		}
		gate.loads <- pin
	}
	source := sidecar.NewAclGateDirectSource(self.net.Host().Redis, self.net.Host().Blobs, gateSettings)
	gate.cache = sidecar.NewAclGateCache(self.admission.Context(), source, self.net.Clock(), gateSettings)
	self.t.Cleanup(gate.cache.Close)
	return gate
}

// Tells a gate the log moved and waits for its load to reach the tip: its snapshot there.
func (self *evsDeletionRowWorld) load(gate *evsDeletionRowGate) *sidecar.AclGateSnapshot {
	self.t.Helper()
	networkId := self.admission.NetworkId()
	gate.cache.Changed(networkId)
	want := self.admission.Tip()
	for {
		select {
		case <-gate.loads:
		case <-self.admission.Context().Done():
			self.t.Fatalf("no load reached %d: %v", want.GetVersion(), self.admission.Context().Err())
		}
		snapshot, status := gate.cache.State(networkId)
		if status == sidecar.AclGateLoaded && snapshot != nil && proto.Equal(snapshot.Pin, want) {
			return snapshot
		}
		gate.cache.Changed(networkId)
	}
}

// One request of the owner's sidecar to evs's lifecycle routes with an admin token, as the exchange would mint it.
func (self *evsDeletionRowWorld) serve(method string, suffix string) int {
	self.t.Helper()
	owner := self.admission.Owner()
	sidecarId := connect.Id(owner.SidecarId)
	now := self.net.Clock().Now()
	token := self.net.Fakes().Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(self.admission.NetworkId()),
		ClientId:  connect.Id(self.admission.Id("client of " + owner.SidecarId.String())),
		SidecarId: &sidecarId,
		Audience:  EvsAudience,
		Scopes:    []string{repoScope(self.repoId, "admin")},
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	})
	request := httptest.NewRequestWithContext(self.t.Context(), method, "/evs/v1/repos/"+sidecar.EvsKeyId(self.repoId)+suffix, strings.NewReader(""))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder.Code
}

// The repo's cluster, from its place/.
func (self *evsDeletionRowWorld) cluster() sidecar.BlobCluster {
	self.t.Helper()
	first, err := self.net.Host().Blobs.FirstCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	place, err := sidecar.ReadEvsRepoPlace(self.t.Context(), first, self.repoId)
	if err != nil {
		self.t.Fatalf("place/: %v", err)
	}
	cluster, err := self.net.Host().Blobs.Cluster(place.ClusterId)
	if err != nil {
		self.t.Fatal(err)
	}
	return cluster
}

// repo/ as the repo's cluster holds it.
func (self *evsDeletionRowWorld) repoObject() *protocol.EvsRepoObject {
	self.t.Helper()
	object, _, err := sidecar.ReadEvsRepoObject(self.t.Context(), self.cluster(), self.repoId)
	if err != nil {
		self.t.Fatalf("repo/: %v", err)
	}
	return object
}

// The owner's RepoCreate, evs's placement and activation over the world's gate, then the owner's RepoDelete, which no
// DELETE follows: the RepoDelete's position and its entry's time, its row checked to carry the statement's signer.
func (self *evsDeletionRowWorld) deleteWithoutTheRoute() (uint64, time.Time) {
	self.t.Helper()
	admission, owner := self.admission, self.admission.Owner()
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: admission.Header(), RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	}))
	self.load(self.gate)
	if status := self.serve(http.MethodPut, ""); status != http.StatusOK {
		self.t.Fatalf("PUT: %d", status)
	}
	// gkm's objects of a formed group, as KF1 leaves them: the repo's GroupForm 1 and the group's gen/1
	cluster := self.cluster()
	groupId := admission.Id("group")
	formBody, err := proto.Marshal(&protocol.GroupForm{RepoId: self.repoId.Bytes(), GroupId: groupId.Bytes(), Generation: 1})
	if err != nil {
		self.t.Fatal(err)
	}
	form, err := proto.Marshal(&bridge.Signed{Type: uint32(bridge.SignedType_SIGNED_GROUP_FORM), Body: formBody, SignerId: owner.SidecarId.Bytes()})
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(self.t.Context(), gkmservice.GkmFormKey(self.repoId, 1), form, nil); err != nil {
		self.t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(self.t.Context(), sidecar.GkmGenerationPath(groupId, 1), []byte("a signed GenRotate"), nil); err != nil {
		self.t.Fatal(err)
	}
	if status := self.serve(http.MethodPost, "/activate"); status != http.StatusOK {
		self.t.Fatalf("activate: %d", status)
	}

	signedBytes := admission.Sign(owner, bridge.SignedType_SIGNED_REPO_DELETE, &protocol.RepoDelete{
		Header: admission.Header(), RepoId: self.repoId.Bytes(), DeletionId: self.deletionId.Bytes(),
	})
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		self.t.Fatal(err)
	}
	deletedAt := admission.MustLand(signedBytes).Pin.GetVersion()
	acl, err := admission.State().Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	row := acl.Repo(self.repoId).GetDeletion()
	if row.GetDeletedAt() != deletedAt || row.GetDeletedTimeMs() == 0 || !bytes.Equal(row.GetSigner(), signed.GetSignerId()) ||
		!bytes.Equal(row.GetSigner(), owner.SidecarId.Bytes()) {
		self.t.Fatalf("the deletion row %+v for the statement signed by %x", row, signed.GetSignerId())
	}
	if object := self.repoObject(); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		self.t.Fatalf("repo/ before the walk: %v", object)
	}
	return deletedAt, time.UnixMilli(row.GetDeletedTimeMs())
}

// taskworker's walk and then its start over gate, as the lifecycle jobs read it: deleted{deletion_id, the entry's time,
// the owner's sidecar}, the start queued 7 d 10 min after the entry, and shredding once it runs then.
func (self *evsDeletionRowWorld) reconcileAndStart(gate *evsDeletionRowGate, deletedTime time.Time) {
	self.t.Helper()
	host := *self.net.Host()
	host.Tasks = self.net.Fakes().Tasks
	deletions := NewAclEvsAuthState(gate.cache, nil)
	counts, err := RunReconcile(self.t.Context(), &host, &EvsReconcileDeps{Deletions: deletions})
	if err != nil || counts.Applied != 1 || counts.Queued != 1 || counts.Failed != 0 {
		self.t.Fatalf("the walk: %+v %v", counts, err)
	}
	object := self.repoObject()
	if object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || !bytes.Equal(object.GetDeletionId(), self.deletionId.Bytes()) ||
		object.GetStateMs() != deletedTime.UnixMilli() || !bytes.Equal(object.GetStateSigner(), self.admission.Owner().SidecarId.Bytes()) {
		self.t.Fatalf("repo/ after the walk: %v", object)
	}
	starts := 0
	for _, request := range self.net.Fakes().Tasks.Pending() {
		if request.Name == EvsShredTaskName && strings.Contains(request.OnceKey, sidecar.EvsKeyId(self.repoId)) {
			starts += 1
			if !request.RunAt.Equal(deletedTime.Add(evsShredStartAfter)) {
				self.t.Errorf("the start runs at %v, want %v", request.RunAt, deletedTime.Add(evsShredStartAfter))
			}
		}
	}
	if starts != 1 {
		self.t.Fatalf("%d starts queued", starts)
	}

	self.net.Clock().AdvanceTo(deletedTime.Add(evsShredStartAfter))
	outcome, err := RunShred(self.t.Context(), &host, &EvsShredDeps{
		ShredGroup: func(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, final bool) error {
			return errors.New("the start shredded gkm")
		},
		Deletions: deletions,
	}, EvsShredArgs(self.repoId, self.deletionId, false))
	if state := self.repoObject().GetState(); err != nil || outcome != EvsShredWaiting || state != protocol.EvsRepoState_EVS_REPO_SHREDDING {
		self.t.Errorf("the start: %v %v %s", outcome, err, state)
	}
}

// A RepoDelete applied by the walk after its entry left the retention of a gate that read every entry: two bases on,
// the gate's retention point is past the entry, and the row alone names its time and signer.
func TestEvsReconcilerAppliesARepoDeleteFromItsRowPastItsEntrysRetention(t *testing.T) {
	world := newEvsDeletionRowWorld(t)
	deletedAt, deletedTime := world.deleteWithoutTheRoute()
	world.admission.Fold(true)
	world.admission.MustLand(world.admission.Sign(world.admission.Owner(), bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: world.admission.Header(), RepoId: world.admission.Id("a later repo").Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	}))
	world.admission.Fold(true)
	snapshot := world.load(world.gate)
	if point := snapshot.Config.RetentionPoint(); point <= deletedAt {
		t.Fatalf("the gate's retention point %d has not passed the RepoDelete at %d", point, deletedAt)
	}
	world.reconcileAndStart(world.gate, deletedTime)
}

// A RepoDelete applied by the walk over a gate that first loaded the network after one base folded the RepoDelete, as an
// evs or taskworker process restarted then: its cold start began at that base.
func TestEvsReconcilerAppliesARepoDeleteFromItsRowAtAGateLoadedAtALaterBase(t *testing.T) {
	world := newEvsDeletionRowWorld(t)
	deletedAt, deletedTime := world.deleteWithoutTheRoute()
	base := world.admission.Fold(true)
	later := world.newGate()
	snapshot := world.load(later)
	if base.GetVersion() <= deletedAt || snapshot.Config.Base().GetFoldedThrough() < deletedAt {
		t.Fatalf("the later gate's base at %d folds through %d, not the RepoDelete at %d", base.GetVersion(), snapshot.Config.Base().GetFoldedThrough(), deletedAt)
	}
	world.reconcileAndStart(later, deletedTime)
}
