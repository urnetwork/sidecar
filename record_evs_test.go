//go:build !sidecar_http

// RECORD-M3-12 on T2: sidecar.RecordEvsStreams, EvsRepo.BuildStreamPush and RecordVault.Ensure against an
// evsservice.EvsEngine over sidecartest's FakeHost, FakeGkm and a FakeGkmAuthLog, every device its own EvsClient. The
// world grants scopes as §7.8's tokens would: evs honors a right only where the world's grant gives it, so a refusal
// is evs's own. Its slot rows are RECORD.md's 64 B key || salt, each stored as EVS-FORMAT.md's 104 B record slot row
// block (QD-739).

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A device's clock: the world's time, a wait moving the world's clock on by its timeout, so a retry's backoff
// holds no test and evs sees the time pass, as a fence's or a refusal's retry_after needs.
type recordEvsWorldClock struct {
	clock *sidecartest.FakeClock
}

func (self *recordEvsWorldClock) Now() time.Time {
	return self.clock.Now()
}

func (self *recordEvsWorldClock) After(timeout time.Duration) <-chan time.Time {
	if 0 < timeout {
		self.clock.Advance(timeout)
	}
	fired := make(chan time.Time, 1)
	fired <- self.clock.Now()
	return fired
}

func (self *recordEvsWorldClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return self.clock.AfterFunc(timeout, function)
}

// One repo of the world: its kind and owner, the grants on it, its admins, and its deletion.
type recordEvsWorldRepo struct {
	kind     protocol.RepoKind
	grants   map[sidecar.Id]sidecartest.RecordStreamsScope
	admins   []sidecar.Id
	shrunkAt uint64
	deletion *evsservice.EvsRepoDeletionFacts
}

// The world: one member, its devices, and the repos they share.
type recordEvsWorld struct {
	t         *testing.T
	ctx       context.Context
	clock     *sidecartest.FakeClock
	host      *sidecartest.FakeHost
	cluster   sidecar.BlobCluster
	networkId sidecar.Id
	clientId  sidecar.Id
	memberId  sidecar.Id
	gkm       *sidecartest.FakeGkm
	authLog   *sidecartest.FakeGkmAuthLog
	engine    *evsservice.EvsEngine

	stateLock sync.Mutex
	// the gate's view, and the one devices read: two while a gate is held closed
	evsView    *sidecartest.FakeGkmAuthView
	deviceView *sidecartest.FakeGkmAuthView
	// repos in the order their RepoCreate landed
	repoIds    []sidecar.Id
	repos      map[sidecar.Id]*recordEvsWorldRepo
	signers    map[sidecar.Id]*sidecartest.FakeGkmSigner
	gkmClients map[sidecar.Id]sidecar.GkmClient
	clients    map[sidecar.Id]*sidecar.EvsClient
	streams    map[sidecar.Id]*sidecar.RecordEvsStreams
	// the sidecars filed as not member devices, a tagged sidecar's place
	tagged map[sidecar.Id]bool
	// the device that holds each repo's group from its creation
	ownerId sidecar.Id
	// run before a filed statement lands, nil for none
	beforeLand func(signerId sidecar.Id, signedType bridge.SignedType, body proto.Message)
	// called after a request is served, before its answer goes back: an error loses the answer, as a crash would
	afterServe func(request *http.Request) error
	// every request a device sent, its route alone
	requests []string
}

// evs's view of the world: a token's rights are what its sidecar's grant gives.
type recordEvsWorldAuthState struct {
	world *recordEvsWorld
}

func (self *recordEvsWorldAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *recordEvsWorldAuthState) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *recordEvsWorldAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	world := self.world
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	repo := world.repos[repoId]
	if repo == nil || principal.SidecarId == nil {
		return evsservice.EvsAuthDenied
	}
	scope := repo.grants[sidecar.Id(*principal.SidecarId)]
	granted := sidecar.AclEvsRights(0)
	if scope.Read || scope.Write || scope.Admin || scope.ReceiptOnly {
		granted |= sidecar.AclEvsRead
	}
	if scope.Write || scope.Admin {
		granted |= sidecar.AclEvsWrite
	}
	if scope.Admin {
		granted |= sidecar.AclEvsAdmin
	}
	if scope.Deposit || scope.ReceiptOnly {
		granted |= sidecar.AclEvsDeposit
	}
	if rights&^granted != 0 {
		return evsservice.EvsAuthDenied
	}
	return evsservice.EvsAuthAllowed
}

func (self *recordEvsWorldAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	world := self.world
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	repo := world.repos[repoId]
	if repo == nil {
		return nil, evsservice.EvsAuthDenied
	}
	return &evsservice.EvsRepoFacts{Kind: repo.kind, OwnerMemberId: world.memberId, NetworkId: world.networkId, Deletion: repo.deletion}, evsservice.EvsAuthAllowed
}

// The gate's view.
func (self *recordEvsWorldAuthState) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	world := self.world
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	if networkId != world.networkId || world.evsView == nil {
		return nil, evsservice.EvsAuthUnknown
	}
	return world.evsView, evsservice.EvsAuthAllowed
}

func newRecordEvsWorld(t *testing.T) *recordEvsWorld {
	t.Helper()
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	sidecartest.RegisterEvsTwins(host.Redis)
	world := &recordEvsWorld{
		t: t, ctx: ctx, clock: clock, host: host,
		networkId: sidecar.NewId(), clientId: sidecar.NewId(), memberId: sidecar.NewId(),
		authLog:    sidecartest.NewFakeGkmAuthLog(),
		repos:      map[sidecar.Id]*recordEvsWorldRepo{},
		signers:    map[sidecar.Id]*sidecartest.FakeGkmSigner{},
		gkmClients: map[sidecar.Id]sidecar.GkmClient{},
		clients:    map[sidecar.Id]*sidecar.EvsClient{},
		streams:    map[sidecar.Id]*sidecar.RecordEvsStreams{},
		tagged:     map[sidecar.Id]bool{},
	}
	network := connect.Id(world.networkId).String()
	if err := host.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n", network)); err != nil {
		t.Fatal(err)
	}
	host.Quota.SetBalance(connect.Id(world.networkId), 1024*1024*1024*1024)
	// §11.12's receipt budget, which pro.yml sets per tier
	host.Quota.SetLimits(connect.Id(world.networkId), &sidecar.QuotaLimits{Limits: map[string]int64{"evs_read_receipts_per_repo_day": 256}})
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	world.cluster = cluster
	world.gkm = sidecartest.NewFakeGkm(clock, host.Blobs, nil)
	world.ownerId = sidecar.NewId()
	world.signerWithLock(world.ownerId)
	world.publishWithLock(true)
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
	receiptKey := sha256.Sum256([]byte("record evs world receipt key"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{{KeyId: 1, Key: receiptKey[:], IssueFrom: clock.Now().Add(-48 * time.Hour)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := evsservice.DefaultEvsSettings()
	settings.BatchFlushDelay = 0
	settings.PushUnknownRereadInterval = 0
	settings.RepoCacheTtl = 0
	authState := &recordEvsWorldAuthState{world: world}
	world.engine, err = evsservice.NewEvsEngine(ctx, host.ServiceHost(), settings, &evsservice.EvsEngineDeps{
		AuthState: authState,
		Uploads:   &evsservice.EvsUploadDeps{Keys: receiptKeys, Quota: quota, Usage: usage},
		GateViews: authState,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.engine.Close)
	return world
}

// The signer of sidecarId, its identity key, as signerWithLock makes it.
func (self *recordEvsWorld) signer(sidecarId sidecar.Id) *sidecartest.FakeGkmSigner {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.signerWithLock(sidecarId)
}

// The signer of sidecarId, made a member device of the world's member on first use.
func (self *recordEvsWorld) signerWithLock(sidecarId sidecar.Id) *sidecartest.FakeGkmSigner {
	signer := self.signers[sidecarId]
	if signer == nil {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			self.t.Fatal(err)
		}
		signer = &sidecartest.FakeGkmSigner{SidecarId: sidecarId, PrivateKey: privateKey}
		self.signers[sidecarId] = signer
	}
	return signer
}

// Appends the world's state as the log's next position: every repo's row, readers, writers and admins. devices
// moves the devices' view too, else only the gate's.
func (self *recordEvsWorld) publishWithLock(devices bool) {
	repoRows := []*protocol.AclRepo{}
	readers := map[sidecar.Id][]sidecar.Id{}
	writers := map[sidecar.Id][]sidecar.Id{}
	for _, repoId := range self.repoIds {
		repo := self.repos[repoId]
		row := &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: repo.kind, OwnerMemberId: self.memberId.Bytes(), HoldersShrunkAt: repo.shrunkAt}
		for _, adminId := range repo.admins {
			row.Admins = append(row.Admins, &protocol.AclRepoAdminRow{SidecarId: adminId.Bytes()})
		}
		repoRows = append(repoRows, row)
		for sidecarId, scope := range repo.grants {
			if scope.Read || scope.Write || scope.Admin || scope.ReceiptOnly {
				readers[repoId] = append(readers[repoId], sidecarId)
			}
			if scope.Write || scope.Admin {
				writers[repoId] = append(writers[repoId], sidecarId)
			}
		}
		slices.SortFunc(readers[repoId], sidecar.Id.Cmp)
		slices.SortFunc(writers[repoId], sidecar.Id.Cmp)
	}
	rows := sidecartest.FakeGkmAuthRows(repoRows...)
	memberDevices := []sidecar.Id{}
	identityKeys := map[sidecar.Id][]byte{}
	for sidecarId, signer := range self.signers {
		identityKeys[sidecarId] = signer.PublicKey()
		if !self.tagged[sidecarId] {
			memberDevices = append(memberDevices, sidecarId)
		}
	}
	slices.SortFunc(memberDevices, sidecar.Id.Cmp)
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(self.memberId, memberDevices...)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	view := self.authLog.Append(&sidecartest.FakeGkmAuthFixture{Rows: rows, IdentityKeys: identityKeys, RepoReaders: readers, RepoWriters: writers})
	self.evsView = view
	if devices || self.deviceView == nil {
		self.deviceView = view
		for _, gkmClient := range self.gkmClients {
			gkmClient.AuthAdvanced(view)
		}
	}
}

// The devices' verified state.
func (self *recordEvsWorld) view() sidecar.GkmAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.deviceView
}

// A fresh vault of the world's member, its group held by the world's owner device: what the suite's NewRepo is.
func (self *recordEvsWorld) NewRepo(ctx context.Context) (sidecar.Id, error) {
	repoId := sidecar.NewId()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.repoIds = append(self.repoIds, repoId)
		self.repos[repoId] = &recordEvsWorldRepo{
			kind:   protocol.RepoKind_REPO_KIND_VAULT,
			grants: map[sidecar.Id]sidecartest.RecordStreamsScope{self.ownerId: {Read: true, Write: true, Admin: true}},
			admins: []sidecar.Id{self.ownerId},
		}
		self.publishWithLock(true)
	}()
	memberId := self.memberId
	if _, err := self.gkmClient(self.ownerId).CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: repoId, Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: &memberId}); err != nil {
		return sidecar.Id{}, err
	}
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: self.ownerId}).Marshal()
	if err != nil {
		return sidecar.Id{}, err
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, sidecar.EvsPlaceKey(repoId), placeBytes, nil); err != nil {
		return sidecar.Id{}, err
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: self.networkId.Bytes(), OwnerMemberId: memberId.Bytes(),
	})
	if err != nil {
		return sidecar.Id{}, err
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, evsservice.RepoKey(repoId), repoBytes, nil); err != nil {
		return sidecar.Id{}, err
	}
	return repoId, nil
}

// Gives sidecarId scope on repoId: a reader of the log reads, a writer or admin writes too, and an admin is a repo
// admin; a receipt-only depositor reads and does not write, as an owner-bound repo's other readers do.
func (self *recordEvsWorld) Grant(repoId sidecar.Id, sidecarId sidecar.Id, scope sidecartest.RecordStreamsScope) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repo := self.repos[repoId]
	if repo == nil {
		return fmt.Errorf("no repo %s", repoId)
	}
	self.signerWithLock(sidecarId)
	repo.grants[sidecarId] = scope
	if scope.Admin && !slices.Contains(repo.admins, sidecarId) {
		repo.admins = append(repo.admins, sidecarId)
	}
	self.publishWithLock(true)
	return nil
}

// Closes repoId's gate as a holder's removal does: the repo's holders shrink at a position the gate's view holds and
// the devices' does not, so a push sealed to the generation the devices hold is 412 GATE_CLOSED; opening it moves the
// devices to that position, whose EnsureWritable rotates past the shrink.
func (self *recordEvsWorld) SetGateClosed(repoId sidecar.Id, closed bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !closed {
		self.publishWithLock(true)
		return
	}
	self.repos[repoId].shrunkAt = self.evsView.Pin().GetVersion() + 1
	self.publishWithLock(false)
}

func (self *recordEvsWorld) Advance(duration time.Duration) {
	self.clock.Advance(duration)
}

// The devices' newest pin, which a push of the suite declares.
func (self *recordEvsWorld) Pin() *bridge.AuthPin {
	return self.view().Pin()
}

// A device's gkm client that, beside FakeGkm's group, writes the GroupForm gkm would at gkm/repo/<repo_id>/, which
// FakeGkm does not and evs's activation reads.
type recordEvsWorldGkm struct {
	sidecar.GkmClient
	world *recordEvsWorld
}

func (self *recordEvsWorldGkm) CreateGroup(ctx context.Context, args *sidecar.GkmCreateGroupArgs) (*sidecar.EvsRepoKey, error) {
	key, err := self.GkmClient.CreateGroup(ctx, args)
	if err != nil {
		return nil, err
	}
	form, err := proto.Marshal(&protocol.GroupForm{RepoId: args.RepoId.Bytes(), GroupId: key.GroupId().Bytes(), Generation: 1})
	if err != nil {
		return nil, err
	}
	signed, err := proto.Marshal(&bridge.Signed{Type: uint32(bridge.SignedType_SIGNED_GROUP_FORM), Body: form})
	if err != nil {
		return nil, err
	}
	if _, err := self.world.cluster.PutIfNoneMatch(ctx, "gkm/repo/"+sidecar.EvsKeyId(args.RepoId)+"/00000000000000000001", signed, nil); err != nil {
		return nil, err
	}
	return key, nil
}

// The gkm client of sidecarId, made on first use at the devices' view.
func (self *recordEvsWorld) gkmClient(sidecarId sidecar.Id) sidecar.GkmClient {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.gkmClientWithLock(sidecarId)
}

func (self *recordEvsWorld) gkmClientWithLock(sidecarId sidecar.Id) sidecar.GkmClient {
	gkmClient := self.gkmClients[sidecarId]
	if gkmClient == nil {
		signer := self.signerWithLock(sidecarId)
		gkmClient = &recordEvsWorldGkm{GkmClient: self.gkm.Client(sidecarId, signer.Sign), world: self}
		gkmClient.AuthAdvanced(self.deviceView)
		self.gkmClients[sidecarId] = gkmClient
	}
	return gkmClient
}

// The devices' transport: the engine's handler, its step 8s waited out after each push.
func (self *recordEvsWorld) RoundTrip(request *http.Request) (*http.Response, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, request.Method+" "+request.URL.Path)
	}()
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	if strings.HasSuffix(request.URL.Path, "/push") || strings.HasSuffix(request.URL.Path, "/slots/delete") {
		for {
			started, finished, changed := self.engine.StepEights()
			if started == finished {
				break
			}
			<-changed
		}
	}
	afterServe := func() func(request *http.Request) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.afterServe
	}()
	if afterServe != nil {
		if err := afterServe(request); err != nil {
			return nil, err
		}
	}
	return recorder.Result(), nil
}

// Every request the devices sent, as method and path.
func (self *recordEvsWorld) sent() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.requests)
}

// Files a device's statement as the core's poster lands it: a RepoCreate of a vault the world's next repo, a
// RepoDelete its deletion, each at the log's next position.
func (self *recordEvsWorld) fileStatement(signerId sidecar.Id) sidecar.EvsFileStatementFunction {
	return func(ctx context.Context, signedType bridge.SignedType, body proto.Message) error {
		beforeLand := func() func(signerId sidecar.Id, signedType bridge.SignedType, body proto.Message) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.beforeLand
		}()
		if beforeLand != nil {
			beforeLand(signerId, signedType, body)
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		switch statement := body.(type) {
		case *protocol.RepoCreate:
			repoId, err := sidecar.IdFromBytes(statement.GetRepoId())
			if err != nil || self.repos[repoId] != nil {
				return fmt.Errorf("a RepoCreate the log refuses")
			}
			self.repoIds = append(self.repoIds, repoId)
			self.repos[repoId] = &recordEvsWorldRepo{
				kind:   statement.GetKind(),
				grants: map[sidecar.Id]sidecartest.RecordStreamsScope{signerId: {Read: true, Write: true, Admin: true}},
				admins: []sidecar.Id{signerId},
			}
			for sidecarId := range self.signers {
				if !self.tagged[sidecarId] && sidecarId != signerId && sidecarId != self.ownerId {
					self.repos[repoId].grants[sidecarId] = sidecartest.RecordStreamsScope{Read: true, Write: true}
				}
			}
		case *protocol.RepoDelete:
			repoId, err := sidecar.IdFromBytes(statement.GetRepoId())
			repo := self.repos[repoId]
			if err != nil || repo == nil {
				return fmt.Errorf("a RepoDelete the log refuses")
			}
			deletionId, _ := sidecar.IdFromBytes(statement.GetDeletionId())
			repo.deletion = &evsservice.EvsRepoDeletionFacts{DeletionId: deletionId, Now: statement.GetNow(), Time: self.clock.Now(), SignerSidecarId: signerId}
		default:
			return fmt.Errorf("a statement the world does not file")
		}
		self.publishWithLock(true)
		return nil
	}
}

// What sidecarId reaches: its own evs client over the world, on a store of its own.
func (self *recordEvsWorld) For(sidecarId sidecar.Id) sidecar.RecordStreams {
	self.stateLock.Lock()
	streams := self.streams[sidecarId]
	self.stateLock.Unlock()
	if streams != nil {
		return streams
	}
	return self.streamsOn(sidecarId, self.newClient(sidecarId, sidecartest.NewFakeStore().Root()), sidecartest.NewFakeStore().Root())
}

// A binding of sidecarId on client and store, kept as its For.
func (self *recordEvsWorld) streamsOn(sidecarId sidecar.Id, client *sidecar.EvsClient, store sidecar.SidecarStore) *sidecar.RecordEvsStreams {
	streams, err := sidecar.NewRecordEvsStreams(&sidecar.RecordEvsStreamsArgs{Client: client, Store: store})
	if err != nil {
		self.t.Fatal(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.streams[sidecarId] = streams
	return streams
}

// A device of sidecarId on store, its tokens carrying what it asks for, which evs honors as its grants say.
func (self *recordEvsWorld) newClient(sidecarId sidecar.Id, store sidecar.SidecarStore) *sidecar.EvsClient {
	self.t.Helper()
	signer, gkmClient := func() (*sidecartest.FakeGkmSigner, sidecar.GkmClient) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		signer := self.signerWithLock(sidecarId)
		self.publishWithLock(true)
		return signer, self.gkmClientWithLock(sidecarId)
	}()
	identity := &sidecar.SidecarIdentity{NetworkId: self.networkId, SidecarId: sidecarId, ClientId: self.clientId, Generation: 1, IdentityPublicKey: signer.PublicKey()}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: self.networkId,
		EvsUrl:    "https://evs.example",
		Transport: self,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			connectSidecarId := connect.Id(sidecarId)
			return self.host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(self.networkId), ClientId: connect.Id(self.clientId), SidecarId: &connectSidecarId,
				Audience: evsservice.EvsAudience, Scopes: scopes, IssuedAt: self.clock.Now(), ExpiresAt: self.clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:          sidecar.EvsSignFunction(signer.Sign),
		Identity:      func() *sidecar.SidecarIdentity { return identity },
		Gkm:           gkmClient,
		Store:         store,
		Config:        self.view,
		FileStatement: self.fileStatement(sidecarId),
		Clock:         &recordEvsWorldClock{clock: self.clock},
		Log:           sidecar.NewNoopLogger(),
		Settings:      sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clients[sidecarId] = client
	return client
}

// RECORD-M2-03's conformance suite on T2: the binding over the real engine keeps every rule the fake keeps, on
// RECORD.md's 64 B rows.
func TestRecordEvsStreamsConformance(t *testing.T) {
	sidecartest.RunRecordStreamsSuite(t, newRecordEvsWorld(t), sidecartest.DefaultRecordStreamsSuiteSettings())
}

// One row of RECORD.md section 5.2, a fresh key || a fresh salt, with the key and the salt apart.
func recordEvsWorldRow(world *recordEvsWorld) (row []byte, key []byte, salt []byte) {
	key = make([]byte, sidecar.RecordKeyByteCount)
	salt = make([]byte, sidecar.RecordSaltByteCount)
	if _, err := rand.Read(key); err != nil {
		world.t.Fatal(err)
	}
	if _, err := rand.Read(salt); err != nil {
		world.t.Fatal(err)
	}
	row, err := sidecar.RecordSlotRowJoin(key, salt)
	if err != nil {
		world.t.Fatal(err)
	}
	return row, key, salt
}

// A push of one entry a path, each keyed by a fresh row at its index of the push's slot, at the world's pin.
func recordEvsWorldPush(world *recordEvsWorld, writerId sidecar.Id, paths ...string) *sidecar.RecordStreamPush {
	push := &sidecar.RecordStreamPush{PushId: sidecar.NewEvsPushId(), WriterSidecarId: writerId, SlotId: sidecar.NewEvsSlotId(), AuthPin: world.Pin()}
	for index, path := range paths {
		row, _, _ := recordEvsWorldRow(world)
		push.SlotRows = append(push.SlotRows, &sidecar.RecordSlotRow{KeyIndex: uint32(index), Row: row})
		push.Entries = append(push.Entries, &sidecar.RecordStreamEntry{Path: path, Entry: []byte("entry " + path)})
	}
	return push
}

// The slot/ object evs stores for slotId: its bytes, and those bytes decoded as evs decodes them.
func (self *recordEvsWorld) storedSlot(repoId sidecar.Id, slotId sidecar.Id) ([]byte, *protocol.EvsSlotObject) {
	self.t.Helper()
	object, err := self.cluster.Get(self.ctx, evsservice.SlotKey(repoId, slotId))
	if err != nil {
		self.t.Fatal(err)
	}
	defer object.Body.Close()
	slotBytes, err := io.ReadAll(object.Body)
	if err != nil {
		self.t.Fatal(err)
	}
	slot, err := sidecar.EvsDecodeSlotObject(slotBytes)
	if err != nil {
		self.t.Fatal(err)
	}
	return slotBytes, slot
}

// The cluster and key of every object stored on the world's metadata and segment clusters whose bytes hold one of
// secrets in the clear: slots, heads, logs, indexes, batch records and segments alike.
func (self *recordEvsWorld) storedHolding(secrets ...[]byte) []string {
	self.t.Helper()
	segmentCluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	holding := []string{}
	for _, cluster := range []sidecar.BlobCluster{self.cluster, segmentCluster} {
		for startAfter, more := "", true; more; {
			var infos []*sidecar.BlobInfo
			infos, more, err = cluster.List(self.ctx, "", startAfter, 1000)
			if err != nil {
				self.t.Fatal(err)
			}
			for _, info := range infos {
				startAfter = info.Key
				object, err := cluster.Get(self.ctx, info.Key)
				if err != nil {
					self.t.Fatal(err)
				}
				content, err := io.ReadAll(object.Body)
				object.Body.Close()
				if err != nil {
					self.t.Fatal(err)
				}
				for _, secret := range secrets {
					if bytes.Contains(content, secret) {
						holding = append(holding, cluster.ClusterId()+":"+info.Key)
						break
					}
				}
			}
		}
	}
	return holding
}

// Fails the test unless storedHolding finds repoId, which repo/ on the metadata cluster and every segment's public
// header carry in the clear: a scan that finds nothing it should proves nothing.
func (self *recordEvsWorld) requireScanFinds(repoId sidecar.Id) {
	self.t.Helper()
	segmentCluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	holding := self.storedHolding(repoId.Bytes())
	for _, clusterId := range []string{self.cluster.ClusterId(), segmentCluster.ClusterId()} {
		if !slices.ContainsFunc(holding, func(key string) bool { return strings.HasPrefix(key, clusterId+":") }) {
			self.t.Fatalf("the scan finds no object of cluster %s holding the repo's id", clusterId)
		}
	}
}

// QD-739 through the binding: a push of RECORD.md's 64 B rows commits a slot whose every key is a 104 B record slot
// row block at its row's index, of one generation, holding no key or salt in the clear, and a slot read opens each
// row back. Rows evs's slot cannot hold are refused before anything is journaled or sent.
func TestRecordEvsStreamsStoresRowsAsRecordSlotRowBlocks(t *testing.T) {
	world := newRecordEvsWorld(t)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	writerId, readerId := sidecar.NewId(), sidecar.NewId()
	if err := world.Grant(repoId, writerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	if err := world.Grant(repoId, readerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	push := &sidecar.RecordStreamPush{PushId: sidecar.NewEvsPushId(), WriterSidecarId: writerId, SlotId: sidecar.NewEvsSlotId(), AuthPin: world.Pin()}
	secrets := [][]byte{}
	// indexes with gaps, as a push whose own entries and ingested ones interleave may leave none
	for index, keyIndex := range []uint32{0, 1, 5, 63} {
		row, key, salt := recordEvsWorldRow(world)
		secrets = append(secrets, key, salt)
		push.SlotRows = append(push.SlotRows, &sidecar.RecordSlotRow{KeyIndex: keyIndex, Row: row})
		path, err := sidecar.RecordStreamPath(uint64(index + 1))
		if err != nil {
			t.Fatal(err)
		}
		push.Entries = append(push.Entries, &sidecar.RecordStreamEntry{Path: path, Entry: []byte("entry " + path)})
	}
	if _, err := world.For(writerId).Append(t.Context(), repoId, push); err != nil {
		t.Fatal(err)
	}
	_, slot := world.storedSlot(repoId, push.SlotId)
	if len(slot.GetKeys()) != len(push.SlotRows) {
		t.Fatalf("the stored slot holds %d keys for %d rows", len(slot.GetKeys()), len(push.SlotRows))
	}
	for i, slotKey := range slot.GetKeys() {
		if slotKey.GetKeyIndex() != push.SlotRows[i].KeyIndex || len(slotKey.GetWrapped()) != sidecar.EvsRecordSlotRowWrappedByteCount ||
			slotKey.GetGeneration() == 0 || slotKey.GetGeneration() != slot.GetKeys()[0].GetGeneration() {
			t.Fatalf("stored key %d: index %d, %d B, generation %d", i, slotKey.GetKeyIndex(), len(slotKey.GetWrapped()), slotKey.GetGeneration())
		}
	}
	world.requireScanFinds(repoId)
	if holding := world.storedHolding(secrets...); len(holding) != 0 {
		t.Fatalf("a key or salt in the clear in %v", holding)
	}
	for _, sidecarId := range []sidecar.Id{writerId, readerId} {
		read, err := world.For(sidecarId).ReadSlot(t.Context(), repoId, push.SlotId)
		if err != nil {
			t.Fatal(err)
		}
		if len(read.Rows) != len(push.SlotRows) {
			t.Fatalf("%d rows read back", len(read.Rows))
		}
		for i, row := range read.Rows {
			if row.KeyIndex != push.SlotRows[i].KeyIndex || !bytes.Equal(row.Row, push.SlotRows[i].Row) {
				t.Fatalf("row %d read back as another", i)
			}
		}
	}

	refused := map[string]func(push *sidecar.RecordStreamPush){
		"an object key's width": func(push *sidecar.RecordStreamPush) { push.SlotRows[0].Row = push.SlotRows[0].Row[:32] },
		"a row a byte long":     func(push *sidecar.RecordStreamPush) { push.SlotRows[1].Row = append(push.SlotRows[1].Row, 0) },
		"a block's width": func(push *sidecar.RecordStreamPush) {
			push.SlotRows[0].Row = make([]byte, sidecar.EvsRecordSlotRowWrappedByteCount)
		},
		"indexes descending": func(push *sidecar.RecordStreamPush) { push.SlotRows[0].KeyIndex = 2 },
		"an index past 63":   func(push *sidecar.RecordStreamPush) { push.SlotRows[1].KeyIndex = 64 },
		"no row":             func(push *sidecar.RecordStreamPush) { push.SlotRows = nil },
		"65 rows": func(push *sidecar.RecordStreamPush) {
			push.SlotRows = nil
			for keyIndex := range uint32(65) {
				row, _, _ := recordEvsWorldRow(world)
				push.SlotRows = append(push.SlotRows, &sidecar.RecordSlotRow{KeyIndex: keyIndex, Row: row})
			}
		},
	}
	for label, refuse := range refused {
		bad := recordEvsWorldPush(world, writerId, "e/0/0/10", "e/0/0/11")
		refuse(bad)
		before := len(world.sent())
		if _, err := world.For(writerId).Append(t.Context(), repoId, bad); !errors.Is(err, sidecar.ErrRecordDraftInvalid) {
			t.Errorf("%s: %v", label, err)
		}
		if sent := world.sent()[before:]; len(sent) != 0 {
			t.Errorf("%s: a refused push sent %v", label, sent)
		}
	}
}

// QD-739's erasure through the binding: an ERASE naming one row of a record slot rewrites the slot without that
// row's whole 104 B block, every other block left byte for byte at its index, so the entry's key and salt go
// together and no slot read returns either. Neither was ever stored in the clear, the entry files included, and
// neither is after. What the binding cannot reach, the push's own record holding its slot body as sent, is question
// record-slot-104-push-record-slot-bodies.
func TestRecordEvsStreamsEraseTakesARowsKeyAndSaltTogether(t *testing.T) {
	world := newRecordEvsWorld(t)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	writerId, adminId := sidecar.NewId(), sidecar.NewId()
	if err := world.Grant(repoId, writerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	if err := world.Grant(repoId, adminId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true}); err != nil {
		t.Fatal(err)
	}
	push := &sidecar.RecordStreamPush{PushId: sidecar.NewEvsPushId(), WriterSidecarId: writerId, SlotId: sidecar.NewEvsSlotId(), AuthPin: world.Pin()}
	keys, salts := [][]byte{}, [][]byte{}
	for index := range 3 {
		row, key, salt := recordEvsWorldRow(world)
		keys, salts = append(keys, key), append(salts, salt)
		push.SlotRows = append(push.SlotRows, &sidecar.RecordSlotRow{KeyIndex: uint32(index), Row: row})
		path, err := sidecar.RecordStreamPath(uint64(index + 1))
		if err != nil {
			t.Fatal(err)
		}
		push.Entries = append(push.Entries, &sidecar.RecordStreamEntry{Path: path, Entry: []byte("entry " + path)})
	}
	if _, err := world.For(writerId).Append(t.Context(), repoId, push); err != nil {
		t.Fatal(err)
	}
	_, before := world.storedSlot(repoId, push.SlotId)
	erasedBlock := bytes.Clone(before.GetKeys()[1].GetWrapped())
	world.requireScanFinds(repoId)
	if holding := world.storedHolding(keys[1], salts[1]); len(holding) != 0 {
		t.Fatalf("the key or salt in the clear before the ERASE, in %v", holding)
	}

	erase := &sidecar.RecordStreamErase{
		PushId: sidecar.NewEvsPushId(), ErasureId: sidecar.NewId(), Complete: true,
		Keys: []*sidecar.RecordSlotKey{{SlotId: push.SlotId, KeyIndex: 1}}, SealedNote: []byte("sealed note"),
	}
	if _, err := world.For(adminId).Erase(t.Context(), repoId, erase); err != nil {
		t.Fatal(err)
	}

	afterBytes, after := world.storedSlot(repoId, push.SlotId)
	if len(after.GetKeys()) != 2 || after.GetKeys()[0].GetKeyIndex() != 0 || after.GetKeys()[1].GetKeyIndex() != 2 {
		t.Fatalf("after the ERASE the slot holds %d keys", len(after.GetKeys()))
	}
	for i, kept := range []int{0, 2} {
		if !bytes.Equal(after.GetKeys()[i].GetWrapped(), before.GetKeys()[kept].GetWrapped()) {
			t.Errorf("row %d's block changed with the ERASE", kept)
		}
	}
	if bytes.Contains(afterBytes, erasedBlock) {
		t.Fatal("the erased row's block is still in its slot")
	}
	for _, sidecarId := range []sidecar.Id{writerId, adminId} {
		read, err := world.For(sidecarId).ReadSlot(t.Context(), repoId, push.SlotId)
		if err != nil {
			t.Fatal(err)
		}
		if len(read.Rows) != 2 {
			t.Fatalf("%d rows read back after the ERASE", len(read.Rows))
		}
		for _, row := range read.Rows {
			if bytes.Contains(row.Row, keys[1]) || bytes.Contains(row.Row, salts[1]) {
				t.Fatal("a slot read returns the erased key or salt")
			}
		}
	}
	if holding := world.storedHolding(keys[1], salts[1]); len(holding) != 0 {
		t.Fatalf("the erased key or salt in the clear after the ERASE, in %v", holding)
	}
	// the entry files stay, holding neither: headers and chains still verify after erasure (§16.8)
	versions, err := world.For(adminId).ReadStream(t.Context(), repoId, writerId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || len(versions[0].Entries) != 3 {
		t.Fatal("the ERASE took entry files")
	}
	for _, entry := range versions[0].Entries {
		if bytes.Contains(entry.Entry, keys[1]) || bytes.Contains(entry.Entry, salts[1]) {
			t.Fatalf("the entry file at %s holds the erased key or salt", entry.Path)
		}
	}
}

// QD-739 from RECORD-M3-01's sealing to evs and back: notes RecordSeal sealed go to their writer's stream with their
// slot rows; a reader verifies each header and opens each body from the row its entry's key_slot_id and key_index
// name in the stored slot, the commitment holding; after an ERASE of the first note's row its header still verifies
// and no slot read gives its row, so its body opens nowhere, while the second note's still opens.
func TestRecordEvsStreamsSealedEntriesOpenFromTheirRowsUntilErased(t *testing.T) {
	world := newRecordEvsWorld(t)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	writerId, adminId := sidecar.NewId(), sidecar.NewId()
	if err := world.Grant(repoId, writerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	if err := world.Grant(repoId, adminId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true}); err != nil {
		t.Fatal(err)
	}
	signer := world.signer(writerId)
	env := &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(sidecartest.NewFakeStore().Root(), writerId), Sign: signer.Sign}
	push := &sidecar.RecordStreamPush{PushId: sidecar.NewEvsPushId(), WriterSidecarId: writerId, SlotId: sidecar.NewEvsSlotId(), AuthPin: world.Pin()}
	wantBodies := [][]byte{}
	for index := range 2 {
		text := fmt.Sprint("note ", index)
		sealed, err := sidecar.RecordSeal(env, testChainNote(repoId, text))
		if err != nil {
			t.Fatal(err)
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.CoordinationBody{Text: text})
		if err != nil {
			t.Fatal(err)
		}
		wantBodies = append(wantBodies, body)
		path, err := sidecar.RecordStreamPath(sealed.Seq)
		if err != nil {
			t.Fatal(err)
		}
		push.SlotRows = append(push.SlotRows, sealed.SlotRow(uint32(index)))
		push.Entries = append(push.Entries, &sidecar.RecordStreamEntry{Path: path, Entry: sealed.EntryBytes(&push.SlotId, uint32(index))})
	}
	if _, err := world.For(writerId).Append(t.Context(), repoId, push); err != nil {
		t.Fatal(err)
	}

	// each entry of the writer's stream by seq, its header verified, and its body opened from the row it names: nil
	// where its slot holds no live row at its index
	open := func(readerId sidecar.Id) map[uint64][]byte {
		streams := world.For(readerId)
		versions, err := streams.ReadStream(t.Context(), repoId, writerId, 0)
		if err != nil {
			t.Fatal(err)
		}
		seqBodies := map[uint64][]byte{}
		for _, version := range versions {
			for _, streamEntry := range version.Entries {
				entry := &protocol.RecordEntry{}
				if err := proto.Unmarshal(streamEntry.Entry, entry); err != nil {
					t.Fatal(err)
				}
				if err := bridge.VerifySigned(entry.GetHeader(), sidecar.RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, bridge.SignedKeyAlgEd25519, signer.PublicKey()); err != nil {
					t.Fatalf("the header at %s does not verify: %v", streamEntry.Path, err)
				}
				header, err := sidecar.ParseStoredRecordHeader(entry.GetHeader().GetBody())
				if err != nil {
					t.Fatal(err)
				}
				slotId, err := sidecar.IdFromBytes(entry.GetKeySlotId())
				if err != nil {
					t.Fatal(err)
				}
				slot, err := streams.ReadSlot(t.Context(), repoId, slotId)
				if err != nil {
					t.Fatal(err)
				}
				var body []byte
				for _, row := range slot.Rows {
					if row.KeyIndex != entry.GetKeyIndex() {
						continue
					}
					key, salt, err := sidecar.RecordSlotRowSplit(row.Row)
					if err != nil {
						t.Fatal(err)
					}
					if body, err = sidecar.RecordOpen(header, entry.GetSealedBody(), key, salt); err != nil {
						t.Fatalf("the body at %s does not open from its row: %v", streamEntry.Path, err)
					}
				}
				seqBodies[header.Header.GetSeq()] = body
			}
		}
		return seqBodies
	}
	for _, readerId := range []sidecar.Id{writerId, adminId} {
		seqBodies := open(readerId)
		if len(seqBodies) != 2 || !bytes.Equal(seqBodies[1], wantBodies[0]) || !bytes.Equal(seqBodies[2], wantBodies[1]) {
			t.Fatal("a reader does not open both notes from their rows")
		}
	}

	erase := &sidecar.RecordStreamErase{
		PushId: sidecar.NewEvsPushId(), ErasureId: sidecar.NewId(), Complete: true,
		Keys: []*sidecar.RecordSlotKey{{SlotId: push.SlotId, KeyIndex: 0}}, SealedNote: []byte("sealed note"),
	}
	if _, err := world.For(adminId).Erase(t.Context(), repoId, erase); err != nil {
		t.Fatal(err)
	}
	for _, readerId := range []sidecar.Id{writerId, adminId} {
		seqBodies := open(readerId)
		if len(seqBodies) != 2 || seqBodies[1] != nil || !bytes.Equal(seqBodies[2], wantBodies[1]) {
			t.Fatal("after the ERASE the erased note still opens, or the other does not")
		}
	}
}

// 412 GATE_CLOSED, recorded: the refused push id keeps its refusal, and the writer's rebuilt push, under a new push
// id and new slot ids, commits after the rotation, its slot the new one with the rows it carried.
func TestRecordEvsStreamsGateClosedRebuildsWithNewSlotIds(t *testing.T) {
	world := newRecordEvsWorld(t)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	writerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	streams := world.For(writerId)
	push := recordEvsWorldPush(world, writerId, "e/0/0/1", "e/0/0/2")
	world.SetGateClosed(repoId, true)
	_, err = streams.Append(t.Context(), repoId, push)
	if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED {
		t.Fatalf("a push past the closed gate: %v", err)
	}
	world.SetGateClosed(repoId, false)
	if _, err := streams.Append(t.Context(), repoId, push); err == nil {
		t.Fatal("the refused push id committed after the gate opened")
	}
	rebuilt := *push
	rebuilt.PushId = sidecar.NewEvsPushId()
	rebuilt.SlotId = sidecar.NewEvsSlotId()
	rebuilt.AuthPin = world.Pin()
	commit, err := streams.Append(t.Context(), repoId, &rebuilt)
	if err != nil {
		t.Fatalf("the rebuilt push: %v", err)
	}
	versions, err := streams.ReadStream(t.Context(), repoId, writerId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0].Version != commit.Version || versions[0].PushId != rebuilt.PushId || versions[0].SlotId != rebuilt.SlotId {
		t.Fatalf("the stream reads %+v", versions)
	}
	slot, err := streams.ReadSlot(t.Context(), repoId, rebuilt.SlotId)
	if err != nil {
		t.Fatal(err)
	}
	if len(slot.Rows) != 2 || !bytes.Equal(slot.Rows[1].Row, rebuilt.SlotRows[1].Row) {
		t.Fatal("the rebuilt push's slot does not hold its rows")
	}
}

// A writer that lost its local state reads its stream's counter back from evs: the newest push holds the highest, each
// entry's path found from its tokens, in the push's order.
func TestRecordEvsStreamsRestartResumesTheCounter(t *testing.T) {
	world := newRecordEvsWorld(t)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	writerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := world.For(writerId).Append(t.Context(), repoId, recordEvsWorldPush(world, writerId, "e/0/0/1", "e/0/0/2", "e/0/0/3")); err != nil {
		t.Fatal(err)
	}
	restarted := world.streamsOn(writerId, world.newClient(writerId, sidecartest.NewFakeStore().Root()), sidecartest.NewFakeStore().Root())
	counter, err := sidecar.RecordStreamCounter(t.Context(), restarted, repoId, writerId)
	if err != nil {
		t.Fatal(err)
	}
	if counter != 3 {
		t.Fatalf("the counter read back as %d", counter)
	}
	versions, err := restarted.ReadStream(t.Context(), repoId, writerId, 0)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{}
	for _, entry := range versions[0].Entries {
		paths = append(paths, entry.Path)
	}
	if !slices.Equal(paths, []string{"e/0/0/1", "e/0/0/2", "e/0/0/3"}) {
		t.Fatalf("the stream's paths read back as %v", paths)
	}
}

// A push whose every answer was lost, as a crash loses it: the device restarted on the same store sends the journaled
// statement again, which evs answers as the commit it made, so the stream holds the entries once; the same push id
// with other entries is PUSH_ID_REUSED.
func TestRecordEvsStreamsRetryAfterALostAnswerSendsTheSameStatement(t *testing.T) {
	world := newRecordEvsWorld(t)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	writerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	store := sidecartest.NewFakeStore().Root()
	streams := world.streamsOn(writerId, world.newClient(writerId, sidecartest.NewFakeStore().Root()), store)
	push := recordEvsWorldPush(world, writerId, "e/0/0/1", "e/0/0/2")
	lost := errors.New("the answer was lost")
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.afterServe = func(request *http.Request) error {
			if strings.HasSuffix(request.URL.Path, "/push") {
				return lost
			}
			return nil
		}
	}()
	if _, err := streams.Append(t.Context(), repoId, push); err == nil {
		t.Fatal("a push whose every answer was lost answered")
	}
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.afterServe = nil
	}()
	restarted := world.streamsOn(writerId, world.newClient(writerId, sidecartest.NewFakeStore().Root()), store)
	commit, err := restarted.Append(t.Context(), repoId, push)
	if err != nil {
		t.Fatalf("the retry after the restart: %v", err)
	}
	versions, err := restarted.ReadStream(t.Context(), repoId, writerId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || versions[0].PushId != push.PushId || versions[0].Version != commit.Version || versions[0].TimeMillis != commit.TimeMillis {
		t.Fatalf("the stream after the retry reads %+v", versions)
	}
	other := *push
	other.Entries = []*sidecar.RecordStreamEntry{{Path: "e/0/0/3", Entry: []byte("another entry")}}
	_, err = restarted.Append(t.Context(), repoId, &other)
	if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED {
		t.Fatalf("another statement under the push id: %v", err)
	}
}

// A push of the stream's entries from through to, each at section 5.2's path for its counter, all keyed by one row of
// the push's slot: what a writer that drew those counters appends.
func recordEvsWorldCounterPush(world *recordEvsWorld, writerId sidecar.Id, from uint64, to uint64) *sidecar.RecordStreamPush {
	row, _, _ := recordEvsWorldRow(world)
	push := &sidecar.RecordStreamPush{
		PushId: sidecar.NewEvsPushId(), WriterSidecarId: writerId, SlotId: sidecar.NewEvsSlotId(), AuthPin: world.Pin(),
		SlotRows: []*sidecar.RecordSlotRow{{KeyIndex: 0, Row: row}},
	}
	for n := from; n <= to; n += 1 {
		path, err := sidecar.RecordStreamPath(n)
		if err != nil {
			world.t.Fatal(err)
		}
		push.Entries = append(push.Entries, &sidecar.RecordStreamEntry{Path: path, Entry: []byte(fmt.Sprint("entry ", n))})
	}
	return push
}

// The engine folds every unfolded version of writerId's stream, as its idle fold would: each directory's newest is then
// a table that keeps no version of its own until the next delta.
func (self *recordEvsWorld) foldStream(repoId sidecar.Id, writerId sidecar.Id) {
	self.t.Helper()
	refId := self.streamRefId(repoId, writerId)
	head, err := self.engine.Heads().ReadCluster(self.ctx, self.cluster, repoId, refId)
	if err != nil {
		self.t.Fatal(err)
	}
	now := self.clock.Now()
	if _, err := self.engine.Folder().FoldAll(self.ctx, self.cluster, repoId, refId, head, now, now.Add(15*time.Second)); err != nil {
		self.t.Fatal(err)
	}
}

// writerId's stream's ref id, as Streams lists it.
func (self *recordEvsWorld) streamRefId(repoId sidecar.Id, writerId sidecar.Id) sidecar.Id {
	self.t.Helper()
	heads, err := self.For(writerId).Streams(self.ctx, repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	for _, head := range heads {
		if head.SidecarId == writerId {
			return head.RefId
		}
	}
	self.t.Fatalf("no stream of %s", writerId)
	return sidecar.Id{}
}

// The counters a stream's versions hold, in order, and whether each version's entries are its path's counters in
// order: what reading a stream back must give.
func recordEvsStreamCounters(t *testing.T, versions []*sidecar.RecordStreamVersion) []uint64 {
	t.Helper()
	counters := []uint64{}
	for _, version := range versions {
		for _, entry := range version.Entries {
			n, ok := sidecar.RecordStreamPathCounter(entry.Path)
			if !ok || !bytes.Equal(entry.Entry, []byte(fmt.Sprint("entry ", n))) {
				t.Fatalf("version %d reads back an entry at %s", version.Version, entry.Path)
			}
			counters = append(counters, n)
		}
	}
	return counters
}

// QD-722 on T2: a stream grows past one push per leaf directory and past 2,048 entries, each push into a standing
// directory adding its names by that directory's delta on its newest version, which evs's creates-only rule takes on a
// record-class stream: into e/0/0/ again and again, from e/0/0/ into e/0/1/ by e/0's delta, and after a fold, when the
// leaf's newest is a folded table that keeps no version of its own and evs reads it from the table's delta. The
// stream reads back whole, from its first push and from a later one, by the writer and by another device replaying it.
func TestRecordEvsStreamsGrowPastALeafDirectory(t *testing.T) {
	world := newRecordEvsWorld(t)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// the reader another device of the vault's member, which writes it too and so reads with no receipt to deposit
	writerId, readerId := sidecar.NewId(), sidecar.NewId()
	if err := world.Grant(repoId, writerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	if err := world.Grant(repoId, readerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	streams := world.For(writerId)
	// e/0/0/ holds 1 to 2,047 and e/0/1/ from 2,048: pushes 2 and 3 are deltas of e/0/0, push 4 fills it and starts
	// e/0/1 by e/0's delta, and push 5 adds to e/0/1
	pushes := [][2]uint64{{1, 700}, {701, 1400}, {1401, 2000}, {2001, 2100}, {2101, 2110}}
	for i, bounds := range pushes {
		if i == 2 || i == 4 {
			// folded first: the directory the push adds to is then a table with no version of its own
			world.foldStream(repoId, writerId)
		}
		commit, err := streams.Append(t.Context(), repoId, recordEvsWorldCounterPush(world, writerId, bounds[0], bounds[1]))
		if err != nil {
			t.Fatalf("push %d of %d to %d: %v", i+1, bounds[0], bounds[1], err)
		}
		if commit.Version != uint64(i+1) {
			t.Fatalf("push %d committed at %d", i+1, commit.Version)
		}
	}
	want := []uint64{}
	for n := uint64(1); n <= 2110; n += 1 {
		want = append(want, n)
	}
	versions, err := streams.ReadStream(t.Context(), repoId, writerId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != len(pushes) || !slices.Equal(recordEvsStreamCounters(t, versions), want) {
		t.Fatalf("the stream reads back %d versions", len(versions))
	}
	later, err := streams.ReadStream(t.Context(), repoId, writerId, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(later) != 2 || !slices.Equal(recordEvsStreamCounters(t, later), want[2000:]) {
		t.Fatalf("after version 3 the stream reads back %d versions", len(later))
	}
	// another device, which holds no replay of the stream, replays it from the first push to read from a later one
	replayed, err := world.For(readerId).ReadStream(t.Context(), repoId, writerId, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(replayed) != 1 || !slices.Equal(recordEvsStreamCounters(t, replayed), want[2100:]) {
		t.Fatalf("a replaying reader reads back %d versions after version 4", len(replayed))
	}
	if counter, err := sidecar.RecordStreamCounter(t.Context(), streams, repoId, writerId); err != nil || counter != 2110 {
		t.Fatalf("the counter reads back as %d: %v", counter, err)
	}
}

// QD-722 at evs: two pushes the writer built on one read of a leaf directory, each adding its own entry. The first
// commits; the second's delta, on the version the first replaced, is 409 PATH_CONFLICT naming the leaf, and nothing of
// it commits. The writer's next push, planned on the newest version, commits.
func TestRecordEvsStreamsRefusesADeltaOffTheNewestVersion(t *testing.T) {
	world := newRecordEvsWorld(t)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	writerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	streams := world.For(writerId)
	if _, err := streams.Append(t.Context(), repoId, recordEvsWorldCounterPush(world, writerId, 1, 1)); err != nil {
		t.Fatal(err)
	}
	repo := func() *sidecar.EvsRepo {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		return world.clients[writerId].Repo(repoId)
	}()
	build := func(n uint64) *sidecar.EvsStreamPush {
		push := recordEvsWorldCounterPush(world, writerId, n, n)
		built, err := repo.BuildStreamPush(t.Context(), &sidecar.EvsStreamPushArgs{
			RefName: sidecar.RecordStreamRefName(writerId),
			PushId:  push.PushId,
			SlotId:  push.SlotId,
			SlotKeys: func(fek *sidecar.EvsFekKey) ([]*protocol.EvsSlotKey, error) {
				// the row as the binding wraps it, one 104 B record slot row block
				wrapped, err := sidecar.EvsWrapRecordSlotRow(fek, push.SlotRows[0].Row)
				if err != nil {
					return nil, err
				}
				return []*protocol.EvsSlotKey{{KeyIndex: 0, Generation: fek.Generation(), Wrapped: wrapped}}, nil
			},
			Files:   []*sidecar.EvsStreamFile{{Path: push.Entries[0].Path, Content: push.Entries[0].Entry}},
			AuthPin: push.AuthPin,
		})
		if err != nil {
			t.Fatal(err)
		}
		return built
	}
	first, second := build(2), build(3)
	if commit, err := repo.PostStreamPush(t.Context(), first); err != nil || commit.Version != 2 {
		t.Fatalf("the first push: %+v %v", commit, err)
	}
	_, err = repo.PostStreamPush(t.Context(), second)
	evsError, ok := sidecar.EvsErrorOf(err)
	if !ok || evsError.Status != http.StatusConflict || evsError.Code != protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT || len(evsError.Paths) != 1 {
		t.Fatalf("a delta off the leaf's newest version: %v", err)
	}
	if commit, err := streams.Append(t.Context(), repoId, recordEvsWorldCounterPush(world, writerId, 3, 3)); err != nil || commit.Version != 3 {
		t.Fatalf("the push planned on the newest version: %+v %v", commit, err)
	}
	versions, err := streams.ReadStream(t.Context(), repoId, writerId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(recordEvsStreamCounters(t, versions), []uint64{1, 2, 3}) {
		t.Fatalf("the stream reads back %d versions", len(versions))
	}
}

// The world's verified state as the record reads it, for the vault rule: the world's member, and its vault the live
// vault repo whose RepoCreate landed first.
type recordEvsWorldAuth struct {
	sidecar.RecordAuthUnavailable
	world *recordEvsWorld
}

func (self recordEvsWorldAuth) Member(sidecarId sidecar.Id) (sidecar.Id, bool) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if self.world.tagged[sidecarId] {
		return sidecar.Id{}, false
	}
	return self.world.memberId, true
}

func (self recordEvsWorldAuth) Vault(memberId sidecar.Id) (sidecar.Id, bool) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	for _, repoId := range self.world.repoIds {
		repo := self.world.repos[repoId]
		if repo.kind == protocol.RepoKind_REPO_KIND_VAULT && repo.deletion == nil && memberId == self.world.memberId {
			return repoId, true
		}
	}
	return sidecar.Id{}, false
}

// Every member device of the world is a consented one that is not read_only; a tagged sidecar is none.
type recordEvsWorldVaultAuthority struct {
	world *recordEvsWorld
}

func (self recordEvsWorldVaultAuthority) VaultCreator(sidecarId sidecar.Id, memberId sidecar.Id) bool {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	return !self.world.tagged[sidecarId] && memberId == self.world.memberId
}

// A RecordVault of sidecarId on its own client and store, its waits the world's.
func (self *recordEvsWorld) vault(sidecarId sidecar.Id, store sidecar.SidecarStore) *sidecar.RecordVault {
	client := self.newClient(sidecarId, sidecartest.NewFakeStore().Root())
	vault, err := sidecar.NewRecordVault(&sidecar.RecordVaultArgs{
		SidecarId: sidecarId, Client: client, Auth: func() sidecar.RecordAuthView { return recordEvsWorldAuth{world: self} },
		Authority: recordEvsWorldVaultAuthority{world: self}, Store: store, Clock: &recordEvsWorldClock{clock: self.clock},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return vault
}

// The world's live vault repos, in the order their RepoCreate landed.
func (self *recordEvsWorld) liveVaults() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	live := []sidecar.Id{}
	for _, repoId := range self.repoIds {
		if repo := self.repos[repoId]; repo.kind == protocol.RepoKind_REPO_KIND_VAULT && repo.deletion == nil {
			live = append(live, repoId)
		}
	}
	return live
}

// Two devices of one member race to make its vault: the second files its RepoCreate while the first's is on its way,
// and lands first. Each runs §11.12's creation and then reads the rule: the first to land is the vault, the other
// device files RepoDelete{now} for its own empty repo, and both answer the one vault left.
func TestRecordVaultEnsureLeavesOneVault(t *testing.T) {
	world := newRecordEvsWorld(t)
	firstId := sidecar.NewId()
	secondId := sidecar.NewId()
	first := world.vault(firstId, sidecartest.NewFakeStore().Root())
	second := world.vault(secondId, sidecartest.NewFakeStore().Root())
	var secondVaultId sidecar.Id
	var secondErr error
	raced := false
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.beforeLand = func(signerId sidecar.Id, signedType bridge.SignedType, body proto.Message) {
			if signerId != firstId || signedType != bridge.SignedType_SIGNED_REPO_CREATE || raced {
				return
			}
			raced = true
			// the second device's whole Ensure lands ahead of the first's RepoCreate
			secondVaultId, secondErr = second.Ensure(t.Context())
		}
	}()
	firstVaultId, err := first.Ensure(t.Context())
	if err != nil {
		t.Fatalf("the first device: %v", err)
	}
	if secondErr != nil {
		t.Fatalf("the second device: %v", secondErr)
	}
	live := world.liveVaults()
	if len(live) != 1 || live[0] != secondVaultId || firstVaultId != secondVaultId {
		t.Fatalf("the vaults left %v, the devices answer %s and %s", live, firstVaultId, secondVaultId)
	}
	deleted := func() []*recordEvsWorldRepo {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		deleted := []*recordEvsWorldRepo{}
		for _, repoId := range world.repoIds {
			if repo := world.repos[repoId]; repo.deletion != nil {
				deleted = append(deleted, repo)
			}
		}
		return deleted
	}()
	if len(deleted) != 1 || !deleted[0].deletion.Now || deleted[0].deletion.SignerSidecarId != firstId {
		t.Fatal("the losing vault's RepoDelete{now} is not the first device's")
	}
	// a later Ensure answers the vault and files nothing
	position := world.authLog.Tip().Pin().GetVersion()
	if again, err := first.Ensure(t.Context()); err != nil || again != secondVaultId {
		t.Fatalf("a later Ensure: %s, %v", again, err)
	}
	if position != world.authLog.Tip().Pin().GetVersion() {
		t.Fatal("a later Ensure filed again")
	}
}

// Only a consented, not read_only device of its member files the vault: a tagged sidecar files nothing.
func TestRecordVaultEnsureRefusesANonCreator(t *testing.T) {
	world := newRecordEvsWorld(t)
	taggedId := sidecar.NewId()
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.tagged[taggedId] = true
	}()
	vault := world.vault(taggedId, sidecartest.NewFakeStore().Root())
	if _, err := vault.Ensure(t.Context()); !errors.Is(err, sidecar.ErrRecordVaultNotCreator) {
		t.Fatalf("a tagged sidecar's Ensure: %v", err)
	}
	if live := world.liveVaults(); len(live) != 0 {
		t.Fatalf("a tagged sidecar filed %v", live)
	}
}

// A device killed after its RepoCreate landed and before the creation finished resumes from its journal: it files no
// second RepoCreate, finishes the repo, and answers it as the vault.
func TestRecordVaultEnsureResumesFromItsJournal(t *testing.T) {
	world := newRecordEvsWorld(t)
	deviceId := sidecar.NewId()
	store := sidecartest.NewFakeStore().Root()
	cut := errors.New("killed before the repo was placed")
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.afterServe = func(request *http.Request) error {
			if request.Method == http.MethodPut && strings.HasPrefix(request.URL.Path, "/evs/v1/repos/") && !strings.Contains(request.URL.Path, "/segments/") {
				return cut
			}
			return nil
		}
	}()
	if _, err := world.vault(deviceId, store).Ensure(t.Context()); err == nil {
		t.Fatal("an Ensure whose creation was cut short answered")
	}
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.afterServe = nil
	}()
	filed := world.liveVaults()
	if len(filed) != 1 {
		t.Fatalf("%d vaults filed before the kill", len(filed))
	}
	vaultId, err := world.vault(deviceId, store).Ensure(t.Context())
	if err != nil {
		t.Fatalf("the resumed Ensure: %v", err)
	}
	if live := world.liveVaults(); len(live) != 1 || vaultId != filed[0] {
		t.Fatalf("the resumed Ensure answers %s with %v live", vaultId, live)
	}
}

// evs takes an ERASE under a preservation hold of the repo (owner decision 133): holds pause sweeps and GC, never a
// person's shredding, so the key goes and the ERASE reads back while the hold stands.
func TestRecordEvsStreamsEraseUnderAHold(t *testing.T) {
	world := newRecordEvsWorld(t)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	adminId := sidecar.NewId()
	if err := world.Grant(repoId, adminId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true}); err != nil {
		t.Fatal(err)
	}
	streams := world.For(adminId)
	push := recordEvsWorldPush(world, adminId, "e/0/0/1", "e/0/0/2")
	if _, err := streams.Append(t.Context(), repoId, push); err != nil {
		t.Fatal(err)
	}
	hold, err := sidecar.EncodeHoldRecord(&sidecar.HoldRecord{
		NetworkId: world.networkId, CaseId: sidecar.NewId(), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScope{RepoIds: []sidecar.Id{repoId}}, PlaceTime: world.clock.Now(), ExpireTime: world.clock.Now().Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.cluster.PutIfNoneMatch(t.Context(), sidecar.HoldObjectKey(world.networkId, sidecar.NewId()), hold, nil); err != nil {
		t.Fatal(err)
	}
	erase := &sidecar.RecordStreamErase{
		PushId: sidecar.NewEvsPushId(), ErasureId: sidecar.NewId(), Complete: true,
		Keys: []*sidecar.RecordSlotKey{{SlotId: push.SlotId, KeyIndex: 0}}, SealedNote: []byte("an erasure's note"),
	}
	if _, err := streams.Erase(t.Context(), repoId, erase); err != nil {
		t.Fatalf("an ERASE under a hold: %v", err)
	}
	slot, err := streams.ReadSlot(t.Context(), repoId, push.SlotId)
	if err != nil {
		t.Fatal(err)
	}
	if len(slot.Rows) != 1 || slot.Rows[0].KeyIndex != 1 {
		t.Fatalf("under the hold the slot holds %d rows", len(slot.Rows))
	}
	erasures, err := streams.ReadErasures(t.Context(), repoId, 0)
	if err != nil || len(erasures) != 1 || erasures[0].ErasureId != erase.ErasureId || !bytes.Equal(erasures[0].SealedNote, erase.SealedNote) {
		t.Fatalf("the ERASE reads back as %v: %v", erasures, err)
	}
}
