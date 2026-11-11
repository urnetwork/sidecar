// pagestack's fixture network (SDK-M4-09; §22.9's Browsers row, "a vault record opens with C4 absent"): one network on
// T2's fixture states, whose owner's vault holds one record, served over HTTPS alone by evsservice's and gkmservice's
// engines on the Net's host, so whatever opens the record reaches it with no connect carrier at all.
//
//	state    a FakeGkmAuthLog, T2's chain of fixture states: each position names the owner, every device of it and the
//	         vault. The engines read its tip through the root's own rules (the view's readers and writers, KeyHolders,
//	         GkmRemoveDue), as a gate's EvsAuthState and GkmAuthState over §8.9's cache will once ACL-M2-14 and
//	         KEYS-M2-17 land. A token of another network answers as a network whose state is not loaded (503), and a
//	         sidecar, binding or repo the tip does not hold is denied, so nothing outside the fixture is honored
//	member   one, the network's owner, every device of it an untagged member device it consented to
//	devices  each an identity key, a client bound to it, a ReaderKey at gkm, a GkmGroupClient over gkm's routes and an
//	         EvsClient over evs's. The writer is the fixture's own, reaching the engines' handlers in process; admit
//	         adds another device of the owner, over whatever transport its caller gives it, and the writer then rotates
//	         the vault's key so the new device holds it. Every such device writes the vault, as an owner's consented
//	         devices do, so its reads need no read receipt (evs_receipt_gate.go)
//	vault    a repo of kind vault the owner holds, placed on the first metadata cluster as evs's create leaves it, its
//	         group at generation 1 by the writer, with the writer's own staged ReaderWrap (KF1's deliveries)
//	record   one file the writer commits at start, standing for a record of the vault until RECORD-M3-12 binds record
//	         streams to evs; its path and content are fixed, so a reader checks what it opened
//
// A device's tokens are minted by the Net's authenticator for exactly the scopes it asks, as the exchange would mint
// them for a device its state grants them to. A page Worker's would come from the fake api's exchange, which grants no
// scope until a scope source answers for this fixture, and a page Worker is read_only, so its read of the vault waits
// on the read receipt gate as well: neither is here yet (the harness's fixme specs).
//
// Safe for concurrent use.

package main

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The record the writer commits at start: its path in the vault and its content.
const (
	pagestackRecordPath    = "records/fixture-record.txt"
	pagestackRecordContent = "A record of the pagestack fixture network's vault, opened over HTTPS with no connect carrier.\n"
)

// The fixture network (the file's comment).
type pagestackFixture struct {
	ctx      context.Context
	world    *sidecartest.Net
	settings *pagestackSettings
	log      *sidecartest.FakeGkmAuthLog

	networkId    sidecar.Id
	memberId     sidecar.Id
	vaultRepoId  sidecar.Id
	vaultGroupId sidecar.Id

	evs *pagestackEvsHost
	gkm *gkmservice.GkmEngine

	// the writer, set before the engines take a request
	writer *pagestackDevice

	stateLock sync.Mutex
	// every device the fixture admitted, the writer first
	devices []*pagestackDevice
	// what each device's own clients close
	closers []func()
	closed  bool
}

// One device of the owner: its keys, fixed at its making, and once opened its clients, set under the fixture's
// stateLock.
type pagestackDevice struct {
	name             string
	signer           *sidecartest.FakeGkmSigner
	clientId         sidecar.Id
	readerKey        *bridge.Signed
	readerPrivateKey hpke.PrivateKey
	readerKeySha256  []byte

	gkmApi *sidecar.GkmApi
	gkm    *sidecar.GkmGroupClient
	evs    *sidecar.EvsClient
}

// The network, its vault and the writer, the engines on the Net's host, and the record committed. A failure closes
// what it made.
func newPagestackFixture(ctx context.Context, world *sidecartest.Net, settings *pagestackSettings) (fixture *pagestackFixture, returnErr error) {
	fixture = &pagestackFixture{
		ctx:          ctx,
		world:        world,
		settings:     settings,
		log:          sidecartest.NewFakeGkmAuthLog(),
		networkId:    sidecar.NewId(),
		memberId:     sidecar.NewId(),
		vaultRepoId:  sidecar.NewId(),
		vaultGroupId: sidecar.NewId(),
	}
	defer func() {
		if returnErr != nil {
			fixture.close()
		}
	}()
	fakes := world.Fakes()
	networkId := connect.Id(fixture.networkId)
	fakes.Gates.OpenService(sidecar.ServiceGateEvs, networkId)
	fakes.Gates.OpenService(sidecar.ServiceGateGkm, networkId)
	fakes.Quota.SetBalance(networkId, settings.fixtureBalanceByteCount)
	sidecartest.RegisterEvsTwins(fakes.Redis)

	writer, err := fixture.newDevice("writer")
	if err != nil {
		return nil, err
	}
	fixture.writer = writer
	view := fixture.appendState(writer)

	gkmEngine, err := world.AddEngine("gkm", func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return gkmservice.NewGkmEngine(ctx, host, nil, &gkmservice.GkmEngineDeps{AuthState: &pagestackGkmAuthState{fixture: fixture}})
	})
	if err != nil {
		return nil, fmt.Errorf("gkm: %w", err)
	}
	fixture.gkm = gkmEngine.(*gkmservice.GkmEngine)
	evsEngine, err := world.AddEngine("evs", func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return newPagestackEvsHost(ctx, host, fixture)
	})
	if err != nil {
		return nil, fmt.Errorf("evs: %w", err)
	}
	fixture.evs = evsEngine.(*pagestackEvsHost)

	inProcess := &pagestackHandlerTransport{byHost: map[string]http.Handler{
		"evs.fixture.invalid": fixture.evs.Handler(),
		"gkm.fixture.invalid": fixture.gkm.Handler(),
	}}
	if err := fixture.openDevice(writer, inProcess, "https://evs.fixture.invalid", "https://gkm.fixture.invalid"); err != nil {
		return nil, err
	}
	if err := writer.gkmApi.UploadReaderKey(ctx, writer.readerKey); err != nil {
		return nil, fmt.Errorf("the writer's ReaderKey: %w", err)
	}
	if err := fixture.placeVault(view); err != nil {
		return nil, fmt.Errorf("the vault: %w", err)
	}
	if _, err := writer.evs.Repo(fixture.vaultRepoId).Write(ctx, &sidecar.EvsWriteArgs{
		Path: pagestackRecordPath, Content: strings.NewReader(pagestackRecordContent), Size: int64(len(pagestackRecordContent)),
	}); err != nil {
		return nil, fmt.Errorf("the record: %w", err)
	}
	return fixture, nil
}

// Closes every device's clients. The engines are the Net's, which its Close ends.
func (self *pagestackFixture) close() {
	var closers []func()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		closers = self.closers
		self.closers = nil
	}()
	for i := len(closers) - 1; 0 <= i; i -= 1 {
		closers[i]()
	}
}

// A device's keys: a fresh identity key and client, and a ReaderKey it signs, not yet in any state.
func (self *pagestackFixture) newDevice(name string) (*pagestackDevice, error) {
	signer := sidecartest.NewFakeGkmSigner()
	now := self.world.Clock().Now()
	readerKey, readerPrivateKey, err := sidecar.NewGkmReaderKey(signer.SidecarId, now, now.Add(self.settings.readerKeyLifetime), signer.Sign)
	if err != nil {
		return nil, err
	}
	readerKeySha256 := sha256.Sum256(readerPrivateKey.PublicKey().Bytes())
	return &pagestackDevice{
		name:             name,
		signer:           signer,
		clientId:         sidecar.NewId(),
		readerKey:        readerKey,
		readerPrivateKey: readerPrivateKey,
		readerKeySha256:  readerKeySha256[:],
	}, nil
}

// Appends the next position, naming every device admitted so far and added, and hands it to every device's group
// client. The owner's devices all read and write the vault, each consented.
func (self *pagestackFixture) appendState(added ...*pagestackDevice) *sidecartest.FakeGkmAuthView {
	var view *sidecartest.FakeGkmAuthView
	gkmClients := []*sidecar.GkmGroupClient{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.devices = append(self.devices, added...)
		devices := slices.Clone(self.devices)
		for _, device := range devices {
			if device.gkm != nil {
				gkmClients = append(gkmClients, device.gkm)
			}
		}
		sidecarIds := []sidecar.Id{}
		consentedIds := [][]byte{}
		identityKeys := map[sidecar.Id][]byte{}
		for _, device := range devices {
			sidecarIds = append(sidecarIds, device.signer.SidecarId)
			consentedIds = append(consentedIds, device.signer.SidecarId.Bytes())
			identityKeys[device.signer.SidecarId] = device.signer.PublicKey()
		}
		rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{
			RepoId: self.vaultRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: self.memberId.Bytes(),
			ConsentedSidecarIds: consentedIds,
		})
		sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(self.memberId, sidecarIds...)
		rows.Sidecars = sidecarRows
		rows.Members = []*bridge.MemberRow{memberRow}
		view = self.log.Append(&sidecartest.FakeGkmAuthFixture{
			Rows:         rows,
			IdentityKeys: identityKeys,
			RepoReaders:  map[sidecar.Id][]sidecar.Id{self.vaultRepoId: sidecarIds},
			RepoWriters:  map[sidecar.Id][]sidecar.Id{self.vaultRepoId: sidecarIds},
		})
	}()
	for _, gkm := range gkmClients {
		gkm.AuthAdvanced(view)
	}
	return view
}

// The tip, for a principal of the fixture's network; nil for any other, whose state this stack never loads.
func (self *pagestackFixture) viewOf(principal *sidecar.Principal) *sidecartest.FakeGkmAuthView {
	if principal == nil || sidecar.Id(principal.NetworkId) != self.networkId {
		return nil
	}
	return self.log.Tip()
}

// The device whose identity sidecarId is, or nil.
func (self *pagestackFixture) device(sidecarId sidecar.Id) *pagestackDevice {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, device := range self.devices {
		if device.signer.SidecarId == sidecarId {
			return device
		}
	}
	return nil
}

// A service token for device, as the exchange mints one: its network, client and sidecar, audience and scopes.
func (self *pagestackFixture) token(device *pagestackDevice, audience string, scopes []string) string {
	now := self.world.Clock().Now()
	sidecarId := connect.Id(device.signer.SidecarId)
	return self.world.Fakes().Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(self.networkId),
		ClientId:  connect.Id(device.clientId),
		SidecarId: &sidecarId,
		Audience:  audience,
		Scopes:    slices.Clone(scopes),
		IssuedAt:  now,
		ExpiresAt: now.Add(self.settings.serviceTokenLifetime),
	})
}

// Builds device's GkmApi, group client and EvsClient over transport, at evsUrl and gkmUrl, scoped rw on the vault, and
// hands the group client the tip.
func (self *pagestackFixture) openDevice(device *pagestackDevice, transport http.RoundTripper, evsUrl string, gkmUrl string) error {
	clock := &pagestackDeviceClock{clock: self.world.Clock()}
	gkmApi, err := sidecar.NewGkmApi(&sidecar.GkmApiArgs{
		GkmUrl:    gkmUrl,
		Transport: transport,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return self.token(device, gkmservice.GkmAudience, scopes), nil
		},
		Clock: clock,
	})
	if err != nil {
		return err
	}
	gkmApi.SetRepoScopes([]sidecar.GkmRepoScope{{RepoId: self.vaultRepoId, Role: sidecar.GkmScopeRoleWrite}})
	gkm, err := sidecar.NewGkmGroupClient(&sidecar.GkmGroupClientArgs{
		SidecarId: device.signer.SidecarId,
		NetworkId: self.networkId,
		Api:       gkmApi,
		Sign:      device.signer.Sign,
		Secrets:   &pagestackSecrets{nameValues: map[string][]byte{}},
		ReaderPrivateKey: func(keySha256 []byte) (hpke.PrivateKey, error) {
			if !bytes.Equal(keySha256, device.readerKeySha256) {
				return nil, sidecar.ErrGkmKeyMissing
			}
			return device.readerPrivateKey, nil
		},
		ReaderKeySha256: func() []byte { return bytes.Clone(device.readerKeySha256) },
		ReaderRepoIds:   func() []sidecar.Id { return []sidecar.Id{self.vaultRepoId} },
		Clock:           clock,
	})
	if err != nil {
		return err
	}
	identity := &sidecar.SidecarIdentity{
		NetworkId: self.networkId, SidecarId: device.signer.SidecarId, ClientId: device.clientId, Generation: 1,
		IdentityPublicKey: device.signer.PublicKey(),
	}
	evs, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: self.networkId,
		EvsUrl:    evsUrl,
		Transport: transport,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return self.token(device, evsservice.EvsAudience, scopes), nil
		},
		Sign:     sidecar.EvsSignFunction(device.signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      gkm,
		Store:    sidecartest.NewFakeStore().Root(),
		Config:   func() sidecar.GkmAuthView { return self.log.Tip() },
		Clock:    clock,
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		return err
	}
	opened := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		device.gkmApi, device.gkm, device.evs = gkmApi, gkm, evs
		self.closers = append(self.closers, evs.Close)
		return true
	}()
	if !opened {
		evs.Close()
		return errors.New("the fixture is closed")
	}
	// after the client is set, so a position appended meanwhile reaches it too; a lower one changes nothing (I-16)
	gkm.AuthAdvanced(self.log.Tip())
	return nil
}

// Admits another device of the owner, its clients over transport at evsUrl and gkmUrl: a position names it, it uploads
// its ReaderKey through its own GkmApi, and the writer rotates the vault's key to every holder, so it opens the vault
// from the new generation down the ladder.
func (self *pagestackFixture) admit(ctx context.Context, name string, transport http.RoundTripper, evsUrl string, gkmUrl string) (*pagestackDevice, error) {
	device, err := self.newDevice(name)
	if err != nil {
		return nil, err
	}
	self.appendState(device)
	if err := self.openDevice(device, transport, evsUrl, gkmUrl); err != nil {
		return nil, err
	}
	if err := device.gkmApi.UploadReaderKey(ctx, device.readerKey); err != nil {
		return nil, fmt.Errorf("%s's ReaderKey: %w", name, err)
	}
	if _, err := self.writer.gkm.RotateRepo(ctx, self.vaultRepoId); err != nil {
		return nil, fmt.Errorf("the vault's rotation to %s: %w", name, err)
	}
	return device, nil
}

// Places the vault on the first metadata cluster as evs's create and gkm's KF1 leave it: place/ and repo/, the group's
// form and owner marker, generation 1 by the writer at view over its holders there, and the writer's staged ReaderWrap.
func (self *pagestackFixture) placeVault(view *sidecartest.FakeGkmAuthView) error {
	ctx := self.ctx
	cluster, err := self.world.Host().Blobs.FirstCluster()
	if err != nil {
		return err
	}
	put := func(key string, message proto.Message) error {
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			return err
		}
		if _, err := cluster.PutIfNoneMatch(ctx, key, body, nil); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		return nil
	}
	writer := self.writer
	place, err := (&sidecar.EvsRepoPlace{ClusterId: cluster.ClusterId(), CreatorSidecarId: writer.signer.SidecarId}).Marshal()
	if err != nil {
		return err
	}
	if _, err := cluster.PutIfNoneMatch(ctx, sidecar.EvsPlaceKey(self.vaultRepoId), place, nil); err != nil {
		return err
	}
	if err := put(gkmservice.GkmEvsRepoKey(self.vaultRepoId), &protocol.EvsRepoObject{
		RepoId: self.vaultRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: self.memberId.Bytes(),
		State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Format: sidecar.EvsRepoFormat1, NetworkId: self.networkId.Bytes(),
	}); err != nil {
		return err
	}
	formBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GroupForm{
		RepoId: self.vaultRepoId.Bytes(), GroupId: self.vaultGroupId.Bytes(), Generation: 1,
	})
	if err != nil {
		return err
	}
	form, err := writer.signer.Sign("group-form", bridge.SignedType_SIGNED_GROUP_FORM, formBody, nil)
	if err != nil {
		return err
	}
	if err := put(gkmservice.GkmFormKey(self.vaultRepoId, 1), form); err != nil {
		return err
	}
	if err := put(gkmservice.GkmGroupOwnerKey(self.vaultGroupId), &protocol.GkmGroupOwner{
		RepoId: self.vaultRepoId.Bytes(), NetworkId: self.networkId.Bytes(),
	}); err != nil {
		return err
	}
	at := self.world.Clock().Now()
	holders, err := sidecar.KeyHolders(view, self.vaultRepoId, at)
	if err != nil {
		return err
	}
	key, rotate, err := sidecar.NewGkmFirstGeneration(self.vaultRepoId, self.vaultGroupId, &sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRequest, Auth: view.Pin(), Time: at, HoldersSha256: holders.Sha256(), WrapCount: 1,
	})
	if err != nil {
		return err
	}
	signedRotate, err := sidecar.SignGenRotate(rotate, writer.signer.Sign)
	if err != nil {
		return err
	}
	if err := put(gkmservice.GkmGenerationKey(self.vaultGroupId, 1), signedRotate); err != nil {
		return err
	}
	delivery, err := sidecar.SealGkmDelivery(key, &sidecar.GkmDeliveryArgs{
		GroupId: self.vaultGroupId, Type: sidecar.GkmWrapTypeReader, Recipient: writer.signer.SidecarId.Bytes(),
		RecipientPublicKey: writer.readerPrivateKey.PublicKey().Bytes(), Kind: sidecar.GkmDeliveryStaged,
	})
	if err != nil {
		return err
	}
	signedDelivery, err := sidecar.SignGkmDelivery(delivery, sidecar.GkmWrapTypeReader, writer.signer.Sign)
	if err != nil {
		return err
	}
	parsed, err := sidecar.ParseGkmDelivery(signedDelivery, sidecar.GkmWrapTypeReader, sidecar.GkmIdentityKeys(view))
	if err != nil {
		return err
	}
	path, err := sidecar.GkmDeliveryPath(self.vaultGroupId, parsed)
	if err != nil {
		return err
	}
	return put(path, signedDelivery)
}

// The ids a harness opens the fixture by, as GET /fixture.json on the stack's own address answers them.
type pagestackFixtureView struct {
	NetworkId   string `json:"network_id"`
	MemberId    string `json:"member_id"`
	VaultRepoId string `json:"vault_repo_id"`
	RecordPath  string `json:"record_path"`
}

func (self *pagestackFixture) view() *pagestackFixtureView {
	return &pagestackFixtureView{
		NetworkId:   self.networkId.String(),
		MemberId:    self.memberId.String(),
		VaultRepoId: self.vaultRepoId.String(),
		RecordPath:  pagestackRecordPath,
	}
}

// Whether the tip honors right on repoId for sidecarId at now: read while it reads the repo then, write and admin
// while it writes it, standing and not read_only. Deposit is honored to no one: no fixture device deposits, and a read
// receipt's deposit is RECORD-M3-12's binding. Every right in right must hold.
func pagestackHonors(view *sidecartest.FakeGkmAuthView, repoId sidecar.Id, sidecarId sidecar.Id, right sidecar.AclEvsRights, now time.Time) bool {
	if right == 0 || view.Repo(repoId) == nil {
		return false
	}
	row := view.SidecarRow(sidecarId)
	if row == nil || row.GetRevokedAt() != 0 || row.GetParkedAt() != 0 {
		return false
	}
	readOnly := row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0
	for _, one := range []sidecar.AclEvsRights{sidecar.AclEvsRead, sidecar.AclEvsWrite, sidecar.AclEvsAdmin, sidecar.AclEvsDeposit} {
		if !right.Has(one) {
			continue
		}
		switch one {
		case sidecar.AclEvsRead:
			if !slices.Contains(view.RepoReadersAt(repoId, now), sidecarId) {
				return false
			}
		case sidecar.AclEvsWrite, sidecar.AclEvsAdmin:
			if readOnly || !slices.Contains(view.RepoWriters(repoId), sidecarId) {
				return false
			}
		default:
			return false
		}
	}
	return right&^(sidecar.AclEvsRead|sidecar.AclEvsWrite|sidecar.AclEvsAdmin|sidecar.AclEvsDeposit) == 0
}

// evs's newest verified state of the fixture (evsservice.EvsAuthState): see the file header.
type pagestackEvsAuthState struct {
	fixture *pagestackFixture
}

// No rev/ object is in the fixture.
func (self *pagestackEvsAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

// Allowed only for a device's own client: the binding the fixture made it.
func (self *pagestackEvsAuthState) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	if self.fixture.viewOf(principal) == nil {
		return evsservice.EvsAuthUnknown
	}
	if principal.SidecarId == nil {
		return evsservice.EvsAuthDenied
	}
	device := self.fixture.device(sidecar.Id(*principal.SidecarId))
	if device == nil || device.clientId != sidecar.Id(principal.ClientId) {
		return evsservice.EvsAuthDenied
	}
	return evsservice.EvsAuthAllowed
}

func (self *pagestackEvsAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	view := self.fixture.viewOf(principal)
	if view == nil {
		return evsservice.EvsAuthUnknown
	}
	if principal.SidecarId == nil || !pagestackHonors(view, repoId, sidecar.Id(*principal.SidecarId), rights, now) {
		return evsservice.EvsAuthDenied
	}
	return evsservice.EvsAuthAllowed
}

func (self *pagestackEvsAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	view := self.fixture.viewOf(principal)
	if view == nil {
		return nil, evsservice.EvsAuthUnknown
	}
	repo := view.Repo(repoId)
	if repo == nil {
		return nil, evsservice.EvsAuthDenied
	}
	facts := &evsservice.EvsRepoFacts{Kind: repo.GetKind(), NetworkId: self.fixture.networkId}
	if ownerMemberId, err := sidecar.IdFromBytes(repo.GetOwnerMemberId()); err == nil {
		facts.OwnerMemberId = ownerMemberId
	}
	return facts, evsservice.EvsAuthAllowed
}

// The tip as a push's 5b and 5d read it (evsservice.EvsGateViews), for the fixture's network alone.
type pagestackGateViews struct {
	fixture *pagestackFixture
}

func (self *pagestackGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	if networkId != self.fixture.networkId {
		return nil, evsservice.EvsAuthUnknown
	}
	return self.fixture.log.Tip(), evsservice.EvsAuthAllowed
}

// gkm's newest verified state of the fixture (gkmservice.GkmAuthState): see the file header.
type pagestackGkmAuthState struct {
	fixture *pagestackFixture
}

// The answer of a test the tip decides.
func pagestackGkmAnswer(allowed bool) gkmservice.GkmAuthAnswer {
	if allowed {
		return gkmservice.GkmAuthAllowed
	}
	return gkmservice.GkmAuthDenied
}

// No rev/ object is in the fixture.
func (self *pagestackGkmAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *pagestackGkmAuthState) Sidecar(principal *sidecar.Principal, sidecarId sidecar.Id) (*gkmservice.GkmSidecarFacts, gkmservice.GkmAuthAnswer) {
	view := self.fixture.viewOf(principal)
	if view == nil {
		return nil, gkmservice.GkmAuthUnknown
	}
	row := view.SidecarRow(sidecarId)
	if row == nil {
		return nil, gkmservice.GkmAuthDenied
	}
	facts := &gkmservice.GkmSidecarFacts{
		IdentityPublicKey: view.IdentityKey(sidecarId),
		Revoked:           row.GetRevokedAt() != 0,
		Parked:            row.GetParkedAt() != 0,
		ReadOnly:          row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0,
		MemberDevice:      len(row.GetTagIds()) == 0 && !row.GetEphemeral() && len(row.GetMemberId()) == len(sidecar.Id{}),
	}
	if memberId, err := sidecar.IdFromBytes(row.GetMemberId()); err == nil {
		facts.MemberId = &memberId
	}
	return facts, gkmservice.GkmAuthAllowed
}

func (self *pagestackGkmAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, right sidecar.AclEvsRights, now time.Time) gkmservice.GkmAuthAnswer {
	view := self.fixture.viewOf(principal)
	if view == nil {
		return gkmservice.GkmAuthUnknown
	}
	return pagestackGkmAnswer(principal.SidecarId != nil && pagestackHonors(view, repoId, sidecar.Id(*principal.SidecarId), right, now))
}

func (self *pagestackGkmAuthState) Reads(principal *sidecar.Principal, repoId sidecar.Id, sidecarId sidecar.Id, now time.Time) gkmservice.GkmAuthAnswer {
	view := self.fixture.viewOf(principal)
	if view == nil {
		return gkmservice.GkmAuthUnknown
	}
	return pagestackGkmAnswer(slices.Contains(view.RepoReadersAt(repoId, now), sidecarId))
}

// The vault, when sidecarId reads it, with its writers.
func (self *pagestackGkmAuthState) PendingTargets(principal *sidecar.Principal, sidecarId sidecar.Id, now time.Time) ([]*gkmservice.GkmPendingTarget, gkmservice.GkmAuthAnswer) {
	view := self.fixture.viewOf(principal)
	if view == nil {
		return nil, gkmservice.GkmAuthUnknown
	}
	repoId := self.fixture.vaultRepoId
	if !slices.Contains(view.RepoReadersAt(repoId, now), sidecarId) {
		return nil, gkmservice.GkmAuthAllowed
	}
	return []*gkmservice.GkmPendingTarget{{RepoId: repoId, SidecarIds: view.RepoWriters(repoId)}}, gkmservice.GkmAuthAllowed
}

func (self *pagestackGkmAuthState) RepoReaders(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	view := self.fixture.viewOf(principal)
	if view == nil {
		return nil, gkmservice.GkmAuthUnknown
	}
	return view.RepoReadersAt(repoId, now), gkmservice.GkmAuthAllowed
}

func (self *pagestackGkmAuthState) RepoWriters(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	view := self.fixture.viewOf(principal)
	if view == nil {
		return nil, gkmservice.GkmAuthUnknown
	}
	return view.RepoWriters(repoId), gkmservice.GkmAuthAllowed
}

// A pin past the tip is not reached yet; one on the tip's chain within what it retains agrees.
func (self *pagestackGkmAuthState) CheckPin(principal *sidecar.Principal, pin *bridge.AuthPin) gkmservice.GkmAuthAnswer {
	view := self.fixture.viewOf(principal)
	if view == nil || view.Pin().GetVersion() < pin.GetVersion() {
		return gkmservice.GkmAuthUnknown
	}
	return pagestackGkmAnswer(view.OnChain(pin))
}

// The fixture holds no Delegation, so no DelegationWrap's recipient reads.
func (self *pagestackGkmAuthState) DelegationReads(principal *sidecar.Principal, repoId sidecar.Id, delegationId []byte, now time.Time) gkmservice.GkmAuthAnswer {
	view := self.fixture.viewOf(principal)
	if view == nil {
		return gkmservice.GkmAuthUnknown
	}
	holds, err := sidecar.GkmDelegationHolds(view, repoId, delegationId, now)
	if err != nil {
		return gkmservice.GkmAuthUnknown
	}
	return pagestackGkmAnswer(holds)
}

func (self *pagestackGkmAuthState) DelegationKey(principal *sidecar.Principal, delegationId []byte) (*gkmservice.GkmDelegationKeyFacts, gkmservice.GkmAuthAnswer) {
	if self.fixture.viewOf(principal) == nil {
		return nil, gkmservice.GkmAuthUnknown
	}
	return nil, gkmservice.GkmAuthDenied
}

// The vault's standing writers, which hold its key and may deliver, by identity bytes: the fixture's one member's
// devices.
func (self *pagestackGkmAuthState) LateHolders(principal *sidecar.Principal, repoId sidecar.Id, recipient string, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	view := self.fixture.viewOf(principal)
	if view == nil {
		return nil, gkmservice.GkmAuthUnknown
	}
	holderIds := []sidecar.Id{}
	for _, writerId := range view.RepoWriters(repoId) {
		if pagestackHonors(view, repoId, writerId, sidecar.AclEvsWrite, now) {
			holderIds = append(holderIds, writerId)
		}
	}
	slices.SortFunc(holderIds, func(a sidecar.Id, b sidecar.Id) int {
		return bytes.Compare(view.IdentityKey(a), view.IdentityKey(b))
	})
	return holderIds, gkmservice.GkmAuthAllowed
}

func (self *pagestackGkmAuthState) HoldersDropped(principal *sidecar.Principal, repoId sidecar.Id, pin *bridge.AuthPin, since time.Time, now time.Time) gkmservice.GkmAuthAnswer {
	view := self.fixture.viewOf(principal)
	if view == nil {
		return gkmservice.GkmAuthUnknown
	}
	dropped, err := sidecar.GkmRemoveDue(view, repoId, pin, since, now)
	if err != nil {
		return gkmservice.GkmAuthUnknown
	}
	return pagestackGkmAnswer(dropped)
}

// evs's block as server/cli/evs builds it (evshost.NewHost), on the fixture's state: the engine with the segment
// route's receipt keys, storage gate, HDD share, usage producer and cohort limit. Its receipt key is made at start and
// lives only in this process.
type pagestackEvsHost struct {
	engine  *evsservice.EvsEngine
	closers []func()
}

func newPagestackEvsHost(ctx context.Context, host *sidecar.ServiceHost, fixture *pagestackFixture) (evsHost *pagestackEvsHost, returnErr error) {
	evsHost = &pagestackEvsHost{}
	defer func() {
		if returnErr != nil {
			evsHost.Close()
		}
	}()
	receiptKey := make([]byte, sha256.Size)
	if _, err := rand.Read(receiptKey); err != nil {
		return nil, err
	}
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{{KeyId: 1, Key: receiptKey, IssueFrom: fixture.world.Clock().Now()}}, nil)
	if err != nil {
		return nil, err
	}
	clusterLimit, err := evsservice.NewClusterLimitOfHost(host, nil)
	if err != nil {
		return nil, err
	}
	uploads := &evsservice.EvsUploadDeps{Keys: receiptKeys, ClusterLimit: clusterLimit}
	quota, err := evsservice.NewQuotaGate(ctx, host, nil)
	if err != nil {
		return nil, err
	}
	evsHost.closers = append(evsHost.closers, quota.Close)
	uploads.Quota = quota
	usage, err := evsservice.NewUsageBatcher(ctx, host, nil)
	if err != nil {
		return nil, err
	}
	evsHost.closers = append(evsHost.closers, usage.Close)
	uploads.Usage = usage
	segmentCluster, err := host.Blobs.SegmentCluster()
	if err != nil {
		return nil, err
	}
	hdd, err := evsservice.NewHddAdmission(ctx, host, segmentCluster.ClusterId(), nil)
	if err != nil {
		return nil, err
	}
	evsHost.closers = append(evsHost.closers, hdd.Close)
	uploads.Hdd = hdd
	settings := evsservice.DefaultEvsSettings()
	settings.InstanceFormat = sidecar.EvsRepoFormat1
	// a push's batch flushes at once: a browser's writes arrive one at a time, and nothing here waits on a batch timer
	settings.BatchFlushDelay = 0
	evsHost.engine, err = evsservice.NewEvsEngine(ctx, host, settings, &evsservice.EvsEngineDeps{
		AuthState: &pagestackEvsAuthState{fixture: fixture},
		Uploads:   uploads,
		GateViews: &pagestackGateViews{fixture: fixture},
	})
	if err != nil {
		return nil, err
	}
	return evsHost, nil
}

func (self *pagestackEvsHost) Handler() http.Handler {
	return self.engine.Handler()
}

func (self *pagestackEvsHost) Ready() bool {
	return self.engine != nil && self.engine.Ready()
}

func (self *pagestackEvsHost) Drain() {
	if self.engine != nil {
		self.engine.Drain()
	}
}

func (self *pagestackEvsHost) Close() {
	if self.engine != nil {
		self.engine.Close()
	}
	for i := len(self.closers) - 1; 0 <= i; i -= 1 {
		self.closers[i]()
	}
	self.closers = nil
}

// The fixture's own device's transport: each request to the engine its host names, in process.
type pagestackHandlerTransport struct {
	byHost map[string]http.Handler
}

func (self *pagestackHandlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	handler, ok := self.byHost[request.URL.Host]
	if !ok {
		return nil, fmt.Errorf("no fixture engine at %s", request.URL.Host)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Result(), nil
}

// A device's clock: the Net's time, every wait answered at once, so a client's retry runs on at once and never parks
// on a clock that moves only with real time; AfterFunc on the Net's clock.
type pagestackDeviceClock struct {
	clock *sidecartest.FakeClock
}

func (self *pagestackDeviceClock) Now() time.Time {
	return self.clock.Now()
}

func (self *pagestackDeviceClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.clock.Now()
	return fired
}

func (self *pagestackDeviceClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return self.clock.AfterFunc(timeout, function)
}

// A device's keychain under gkm's namespace, in memory.
type pagestackSecrets struct {
	stateLock  sync.Mutex
	nameValues map[string][]byte
}

func (self *pagestackSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.nameValues[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *pagestackSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameValues[name] = bytes.Clone(value)
	return nil
}

func (self *pagestackSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.nameValues, name)
	return nil
}

func (self *pagestackSecrets) List(prefix string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for name := range self.nameValues {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}
