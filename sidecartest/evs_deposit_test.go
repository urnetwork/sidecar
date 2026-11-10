// EVS1-M2-29's deposits end to end on T2 (FS-23's M2 case; §11.12's deposits rows): a deposit-only sidecar deposits
// into a mailbox through sidecar.EvsClient against an evsservice.EvsEngine over FakeHost's stores, with FakeGkm's
// drop keys; the owner's device ingests in version order, each deposit opened by the drop key of its slot, and
// commits a CONSUME, after which the slots are gone; the depositor's token holds deposit alone, so every read route
// refuses it; and a depositor with no state reaches the ref's head through BASE_STALE.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// evs's view of the deposit world: every principal may do what its token says, and the repo is a mailbox.
type depositAuthState struct {
	networkId sidecar.Id
	kind      protocol.RepoKind
}

func (self *depositAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *depositAuthState) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *depositAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *depositAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	return &evsservice.EvsRepoFacts{Kind: self.kind, NetworkId: self.networkId}, evsservice.EvsAuthAllowed
}

// A mailbox, its owner's device and a depositor, on one engine.
type depositWorld struct {
	t         *testing.T
	ctx       context.Context
	clock     *FakeClock
	host      *FakeHost
	cluster   sidecar.BlobCluster
	networkId sidecar.Id
	repoId    sidecar.Id
	clientId  sidecar.Id
	owner     *FakeGkmSigner
	depositor *FakeGkmSigner
	view      *FakeGkmAuthView
	gkm       *FakeGkm
	engine    *evsservice.EvsEngine
}

func newDepositWorld(t *testing.T) *depositWorld {
	t.Helper()
	ctx := t.Context()
	clock := NewFakeClock(DefaultClockStart())
	hostSettings := DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := NewFakeHost(ctx, clock, nil, nil, hostSettings)
	RegisterEvsTwins(host.Redis)
	world := &depositWorld{
		t: t, ctx: ctx, clock: clock, host: host,
		networkId: sidecar.NewId(), repoId: sidecar.NewId(), clientId: sidecar.NewId(),
		owner: NewFakeGkmSigner(), depositor: NewFakeGkmSigner(),
	}
	network := connect.Id(world.networkId).String()
	if err := host.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n", network)); err != nil {
		t.Fatal(err)
	}
	host.Quota.SetBalance(connect.Id(world.networkId), 1<<40)
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	world.cluster = cluster
	memberId := sidecar.NewId()
	rows := FakeGkmAuthRows(&protocol.AclRepo{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX, OwnerMemberId: memberId.Bytes(),
		Admins: []*protocol.AclRepoAdminRow{{SidecarId: world.owner.SidecarId.Bytes()}},
	})
	sidecarRows, member := FakeGkmAuthMemberDevices(memberId, world.owner.SidecarId, world.depositor.SidecarId)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	world.view = NewFakeGkmAuthLog().Append(&FakeGkmAuthFixture{
		Rows: rows,
		IdentityKeys: map[sidecar.Id][]byte{
			world.owner.SidecarId: world.owner.PublicKey(), world.depositor.SidecarId: world.depositor.PublicKey(),
		},
		RepoReaders: map[sidecar.Id][]sidecar.Id{world.repoId: {world.owner.SidecarId}},
		RepoWriters: map[sidecar.Id][]sidecar.Id{world.repoId: {world.owner.SidecarId}},
	})
	world.gkm = NewFakeGkm(clock, host.Blobs, nil)
	ownerGkm := world.gkm.Client(world.owner.SidecarId, world.owner.Sign)
	ownerGkm.AuthAdvanced(world.view)
	if _, err := ownerGkm.CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_MAILBOX, OwnerMemberId: &memberId}); err != nil {
		t.Fatal(err)
	}
	usage, err := evsservice.NewUsageBatcher(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	quota, err := evsservice.NewQuotaGate(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Close)
	receiptKey := sha256.Sum256([]byte("deposit world receipt key"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{{KeyId: 1, Key: receiptKey[:], IssueFrom: clock.Now().Add(-48 * time.Hour)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := evsservice.DefaultEvsSettings()
	settings.BatchFlushDelay = 0
	settings.PushUnknownRereadInterval = 0
	settings.RepoCacheTtl = 0
	world.engine, err = evsservice.NewEvsEngine(ctx, host.ServiceHost(), settings, &evsservice.EvsEngineDeps{
		AuthState: &depositAuthState{networkId: world.networkId, kind: protocol.RepoKind_REPO_KIND_MAILBOX},
		Uploads:   &evsservice.EvsUploadDeps{Keys: receiptKeys, Quota: quota, Usage: usage},
		GateViews: &format2GateViews{networkId: world.networkId, view: world.view},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.engine.Close)
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: world.owner.SidecarId}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(ctx, sidecar.EvsPlaceKey(world.repoId), placeBytes, nil); err != nil {
		t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: world.networkId.Bytes(), OwnerMemberId: memberId.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(ctx, evsservice.RepoKey(world.repoId), repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	return world
}

// The devices' transport: the engine's handler, its step 8s waited out after each push.
func (self *depositWorld) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	if strings.HasSuffix(request.URL.Path, "/push") {
		for {
			started, finished, changed := self.engine.StepEights()
			if started == finished {
				break
			}
			<-changed
		}
	}
	return recorder.Result(), nil
}

// A device of signer whose tokens carry the scopes it asks for, or deposit alone.
func (self *depositWorld) device(signer *FakeGkmSigner, depositOnly bool, store sidecar.SidecarStore) *sidecar.EvsClient {
	self.t.Helper()
	gkmClient := self.gkm.Client(signer.SidecarId, signer.Sign)
	gkmClient.AuthAdvanced(self.view)
	identity := &sidecar.SidecarIdentity{NetworkId: self.networkId, SidecarId: signer.SidecarId, ClientId: self.clientId, Generation: 1, IdentityPublicKey: signer.PublicKey()}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: self.networkId,
		EvsUrl:    "https://evs.example",
		Transport: self,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			if depositOnly {
				// the exchange mints a deposit-only sidecar its deposit scope and nothing else
				scopes = []string{"repo:" + self.repoId.String() + ":deposit"}
			}
			connectSidecarId := connect.Id(signer.SidecarId)
			return self.host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(self.networkId), ClientId: connect.Id(self.clientId), SidecarId: &connectSidecarId,
				Audience: evsservice.EvsAudience, Scopes: scopes, IssuedAt: self.clock.Now(), ExpiresAt: self.clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:     sidecar.EvsSignFunction(signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      gkmClient,
		Store:    store,
		Config:   func() sidecar.GkmAuthView { return self.view },
		Clock:    self.clock,
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	return client
}

// Every slot object the cluster holds for the repo.
func (self *depositWorld) slotCount() int {
	count := 0
	for key := range self.host.Blobs.Dump() {
		if strings.Contains(key, "slot/") {
			count += 1
		}
	}
	return count
}

// A deposit-only sidecar deposits a small entry and a 17 MiB one, which goes in 4 MiB chunks across segments; the
// owner's device ingests both in version order, each body as it went in, and consumes them, and their slots go; the
// depositor reads nothing; and a depositor that lost its state reaches the ref's head through BASE_STALE.
func TestEvsDepositIngestAndConsume(t *testing.T) {
	world := newDepositWorld(t)
	depositorStore := NewFakeStore().Root()
	depositor := world.device(world.depositor, true, depositorStore).Repo(world.repoId)
	owner := world.device(world.owner, false, NewFakeStore().Root()).Repo(world.repoId)
	small := []byte("a small deposit")
	large := bytes.Repeat([]byte("a large deposit, past 8 MiB; "), 17*1024*1024/29)
	first, err := depositor.Deposit(world.ctx, &sidecar.EvsDepositArgs{Body: bytes.NewReader(small), Size: int64(len(small))})
	if err != nil {
		t.Fatalf("the first deposit: %v", err)
	}
	second, err := depositor.Deposit(world.ctx, &sidecar.EvsDepositArgs{Body: bytes.NewReader(large), Size: int64(len(large))})
	if err != nil {
		t.Fatalf("the large deposit: %v", err)
	}
	if first.Version != 1 || second.Version != 2 || world.slotCount() != 2 {
		t.Fatalf("versions %d and %d, %d slots", first.Version, second.Version, world.slotCount())
	}
	// every read route refuses a deposit-only principal (FS-23)
	if _, err := depositor.List(world.ctx, &sidecar.EvsReadArgs{RefId: refIdOf(sidecar.EvsDepositRefId(world.repoId, world.depositor.SidecarId))}); err == nil {
		t.Error("a deposit-only sidecar read its own ref")
	}
	ingested := []sidecar.EvsToken{}
	bodies := [][]byte{}
	err = owner.ReadDeposits(world.ctx, world.depositor.SidecarId, 0, func(deposit *sidecar.EvsDeposit, body io.Reader) error {
		content, err := io.ReadAll(body)
		ingested = append(ingested, deposit.EntryId)
		bodies = append(bodies, content)
		return err
	})
	if err != nil || len(ingested) != 2 || ingested[0] != first.EntryId || !bytes.Equal(bodies[0], small) || !bytes.Equal(bodies[1], large) {
		t.Fatalf("ingest: %d deposits %v", len(ingested), err)
	}
	consumed, err := owner.Consume(world.ctx, &sidecar.EvsConsumeArgs{
		DepositRefId: sidecar.EvsDepositRefId(world.repoId, world.depositor.SidecarId), EntryIds: ingested, ConsumedThrough: second.Version,
	})
	if err != nil || consumed.Version != 3 {
		t.Fatalf("the CONSUME: %v %v", consumed, err)
	}
	if world.slotCount() != 0 {
		t.Errorf("%d slots after the CONSUME", world.slotCount())
	}
	left := 0
	if err := owner.ReadDeposits(world.ctx, world.depositor.SidecarId, 0, func(deposit *sidecar.EvsDeposit, body io.Reader) error {
		left += 1
		return nil
	}); err != nil || left != 0 {
		t.Fatalf("after the CONSUME: %d deposits %v", left, err)
	}
	// a depositor restarted with no state bases on version 0 and reaches the head through BASE_STALE
	restarted := world.device(world.depositor, true, NewFakeStore().Root()).Repo(world.repoId)
	third, err := restarted.Deposit(world.ctx, &sidecar.EvsDepositArgs{Body: bytes.NewReader(small), Size: int64(len(small))})
	if err != nil || third.Version != 4 {
		t.Fatalf("a deposit with no state: %v %v", third, err)
	}
}

// The id of a ref named by id.
func refIdOf(refId sidecar.Id) *sidecar.Id {
	return &refId
}

// An erasure of an unconsumed deposit (§11.12's closure row; FS-47's client rows at M2): the owner's device destroys
// the deposit's slot key by an ERASE on the erasure ref, after which the deposit opens no more; the ERASE reads back
// with its keys and its note; the erasure shows done; and an ERASE of keys already gone is NOTHING_TO_ERASE, done.
func TestEvsEraseADeposit(t *testing.T) {
	world := newDepositWorld(t)
	depositor := world.device(world.depositor, true, NewFakeStore().Root()).Repo(world.repoId)
	owner := world.device(world.owner, false, NewFakeStore().Root()).Repo(world.repoId)
	body := []byte("a message to erase")
	if _, err := depositor.Deposit(world.ctx, &sidecar.EvsDepositArgs{Body: bytes.NewReader(body), Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	var slotId sidecar.Id
	if err := owner.ReadDeposits(world.ctx, world.depositor.SidecarId, 0, func(deposit *sidecar.EvsDeposit, body io.Reader) error {
		slotId = deposit.SlotId
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	erasureId := sidecar.NewId()
	keys := []*sidecar.EvsErasedKey{{SlotId: slotId, KeyIndex: 0}}
	erased, err := owner.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: erasureId, Keys: keys, Complete: true, Note: []byte("the message")})
	if err != nil || erased.Version != 1 {
		t.Fatalf("the ERASE: %v %v", erased, err)
	}
	if err := owner.ReadDeposits(world.ctx, world.depositor.SidecarId, 0, func(deposit *sidecar.EvsDeposit, body io.Reader) error {
		return nil
	}); err == nil {
		t.Error("an erased deposit still opens")
	}
	erasures, err := owner.ReadErasures(world.ctx, 0)
	if err != nil || len(erasures) != 1 || erasures[0].ErasureId != erasureId || len(erasures[0].Keys) != 1 ||
		erasures[0].Keys[0].SlotId != slotId || string(erasures[0].Note) != "the message" || !erasures[0].Complete {
		t.Fatalf("the ERASE read back: %v %v", erasures, err)
	}
	states, err := owner.Erasures(world.ctx)
	if err != nil || len(states) != 1 || states[0].State != "done" {
		t.Fatalf("the erasure's state: %v %v", states, err)
	}
	again, err := owner.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: erasureId, Keys: keys, Complete: true})
	if err != nil || again.Version != 0 {
		t.Fatalf("an ERASE of keys gone: %v %v", again, err)
	}
}
