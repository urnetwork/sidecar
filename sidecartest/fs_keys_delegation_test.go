package sidecartest

// FS-18's forwarding cases (KEYS-M8-01; §22.7; D-KEYS-16, D-KEYS-24; owner decision 197; DESIGN-DETAILS 4.2.2) on T2,
// with fixed keys on a fake clock: gkm's group client rotating the config's group against gkmservice's engine on a
// fake host, both over one log of fixture states (FakeGkmAuthLog), which the engine's state reads at its tip as a
// gate's would. Each forwarding Delegation's row is the one TEAM-M8-01 writes: the sidecar it forwards for, where a
// newer one superseded it or its end, and its reader key's SHA-256, never the key.
//
//   - a rotation wraps to the live forwarding Delegation's key, which it reads from gkm's object, and the key opens
//     the generation; it wraps to no superseded one, and the generation's holders_sha256 is the one before the
//     supersession: the holder is its sidecar's, and the newer key gets the current generation late, from its
//     sidecar, once the object stands;
//   - a DelegationRevoke of the live one makes the next generation REMOVE, wrapped to no forwarding key;
//   - a forwarding key opens the config's generations and is wrapped to by no other repo's rotation;
//   - an object whose bytes do not hash to the row's digest is refused at gkm, and a rotator gkm serves such bytes to
//     seals nothing to them;
//   - a rotation that finds no object skips that wrap and counts it, and the sidecar's late wrap, once it uploads the
//     object, gives the forwarding key the generation.
//
// FS-18's other cases, a covered agent's Suspend and the rest, are KEYS-M2-28's.

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A SidecarSecrets over a map, for a device's keychain.
type fsKeysDelegationSecrets struct {
	stateLock  sync.Mutex
	nameValues map[string][]byte
}

func (self *fsKeysDelegationSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.nameValues[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *fsKeysDelegationSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameValues[name] = bytes.Clone(value)
	return nil
}

func (self *fsKeysDelegationSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.nameValues, name)
	return nil
}

func (self *fsKeysDelegationSecrets) List(prefix string) ([]string, error) {
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

// gkm's newest verified state, the log's tip, read through the root's own rules: what a gate's GkmAuthState over
// §8.9's cache answers.
type fsKeysDelegationState struct {
	log          *FakeGkmAuthLog
	memberId     sidecar.Id
	configRepoId sidecar.Id
}

func (self *fsKeysDelegationState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *fsKeysDelegationState) Sidecar(principal *sidecar.Principal, sidecarId sidecar.Id) (*gkmservice.GkmSidecarFacts, gkmservice.GkmAuthAnswer) {
	view := self.log.Tip()
	row := view.SidecarRow(sidecarId)
	if row == nil {
		return nil, gkmservice.GkmAuthDenied
	}
	memberId := self.memberId
	return &gkmservice.GkmSidecarFacts{
		IdentityPublicKey: view.IdentityKey(sidecarId),
		Revoked:           row.GetRevokedAt() != 0,
		Parked:            row.GetParkedAt() != 0,
		MemberDevice:      true,
		MemberId:          &memberId,
	}, gkmservice.GkmAuthAllowed
}

// The answer of a test of membership.
func fsKeysDelegationAnswer(allowed bool) gkmservice.GkmAuthAnswer {
	if allowed {
		return gkmservice.GkmAuthAllowed
	}
	return gkmservice.GkmAuthDenied
}

func (self *fsKeysDelegationState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, right sidecar.AclEvsRights, now time.Time) gkmservice.GkmAuthAnswer {
	view := self.log.Tip()
	sidecarId := sidecar.Id(*principal.SidecarId)
	switch right {
	case sidecar.AclEvsRead:
		return fsKeysDelegationAnswer(slices.Contains(view.RepoReadersAt(repoId, now), sidecarId))
	case sidecar.AclEvsWrite, sidecar.AclEvsAdmin:
		return fsKeysDelegationAnswer(slices.Contains(view.RepoWriters(repoId), sidecarId))
	}
	return gkmservice.GkmAuthDenied
}

func (self *fsKeysDelegationState) Reads(principal *sidecar.Principal, repoId sidecar.Id, sidecarId sidecar.Id, now time.Time) gkmservice.GkmAuthAnswer {
	return fsKeysDelegationAnswer(slices.Contains(self.log.Tip().RepoReadersAt(repoId, now), sidecarId))
}

func (self *fsKeysDelegationState) PendingTargets(principal *sidecar.Principal, sidecarId sidecar.Id, now time.Time) ([]*gkmservice.GkmPendingTarget, gkmservice.GkmAuthAnswer) {
	return nil, gkmservice.GkmAuthAllowed
}

func (self *fsKeysDelegationState) RepoReaders(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	return self.log.Tip().RepoReadersAt(repoId, now), gkmservice.GkmAuthAllowed
}

func (self *fsKeysDelegationState) RepoWriters(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	return self.log.Tip().RepoWriters(repoId), gkmservice.GkmAuthAllowed
}

func (self *fsKeysDelegationState) CheckPin(principal *sidecar.Principal, pin *bridge.AuthPin) gkmservice.GkmAuthAnswer {
	view := self.log.Tip()
	if view.Pin().GetVersion() < pin.GetVersion() {
		return gkmservice.GkmAuthUnknown
	}
	return fsKeysDelegationAnswer(view.OnChain(pin))
}

func (self *fsKeysDelegationState) DelegationReads(principal *sidecar.Principal, repoId sidecar.Id, delegationId []byte, now time.Time) gkmservice.GkmAuthAnswer {
	holds, err := sidecar.GkmDelegationHolds(self.log.Tip(), repoId, delegationId, now)
	if err != nil {
		return gkmservice.GkmAuthUnknown
	}
	return fsKeysDelegationAnswer(holds)
}

func (self *fsKeysDelegationState) DelegationKey(principal *sidecar.Principal, delegationId []byte) (*gkmservice.GkmDelegationKeyFacts, gkmservice.GkmAuthAnswer) {
	for _, row := range self.log.Tip().Delegations() {
		if !bytes.Equal(row.GetDelegationId(), delegationId) {
			continue
		}
		keySha256, ok := sidecar.GkmDelegationKeySha256(row)
		if !ok {
			return nil, gkmservice.GkmAuthDenied
		}
		facts := &gkmservice.GkmDelegationKeyFacts{ReaderKeySha256: keySha256, ConfigRepoId: self.configRepoId}
		if sidecar.ConfigDelegationRowForwards(row) {
			forwardSidecarId := sidecar.Id(row.GetForwardSidecarId())
			facts.ForwardSidecarId = &forwardSidecarId
		}
		return facts, gkmservice.GkmAuthAllowed
	}
	return nil, gkmservice.GkmAuthDenied
}

func (self *fsKeysDelegationState) LateHolders(principal *sidecar.Principal, repoId sidecar.Id, recipient string, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	return nil, gkmservice.GkmAuthAllowed
}

func (self *fsKeysDelegationState) HoldersDropped(principal *sidecar.Principal, repoId sidecar.Id, pin *bridge.AuthPin, since time.Time, now time.Time) gkmservice.GkmAuthAnswer {
	dropped, err := sidecar.GkmRemoveDue(self.log.Tip(), repoId, pin, since, now)
	if err != nil {
		return gkmservice.GkmAuthUnknown
	}
	return fsKeysDelegationAnswer(dropped)
}

// One member device of the world: its identity key, its ReaderKey, its api and its group client.
type fsKeysDelegationDevice struct {
	signer           *FakeGkmSigner
	readerKey        *bridge.Signed
	readerPrivateKey hpke.PrivateKey
	readerKeySha256  []byte
	api              *sidecar.GkmApi
	client           *sidecar.GkmGroupClient
}

// A forwarding Delegation of the world's app: its id and its reader key, which its VPN component keeps.
type fsKeysDelegationForward struct {
	delegationId []byte
	privateKey   hpke.PrivateKey
	publicKey    []byte
	keySha256    []byte
}

// A repo of the world and its group, generation 1 of which the creator claimed.
type fsKeysDelegationRepo struct {
	repoId  sidecar.Id
	groupId sidecar.Id
	kind    protocol.RepoKind
}

type fsKeysDelegationWorld struct {
	t         *testing.T
	ctx       context.Context
	clock     *FakeClock
	host      *FakeHost
	engine    *gkmservice.GkmEngine
	log       *FakeGkmAuthLog
	networkId connect.Id
	memberId  sidecar.Id
	config    *fsKeysDelegationRepo
	general   *fsKeysDelegationRepo
	// the creator files generation 1 of each group; the rotator, a config writer, rotates; the app's sidecar files
	// its forwarding Delegations, uploads their keys and writes their late wraps
	creator *fsKeysDelegationDevice
	rotator *fsKeysDelegationDevice
	app     *fsKeysDelegationDevice
	// what the next position's rows hold
	delegations    []*bridge.DelegationRow
	configShrunkAt uint64
}

// The world at its first position: the three member devices of one member, reading both repos and the creator and
// rotator writing them, each repo's group at generation 1, the rotator holding it by the creator's staged wrap.
func newFsKeysDelegationWorld(t *testing.T) *fsKeysDelegationWorld {
	ctx := t.Context()
	clock := NewFakeClock(DefaultClockStart())
	host := NewFakeHost(ctx, clock, nil, nil, nil)
	world := &fsKeysDelegationWorld{
		t:         t,
		ctx:       ctx,
		clock:     clock,
		host:      host,
		log:       NewFakeGkmAuthLog(),
		networkId: connect.NewId(),
		memberId:  sidecar.NewId(),
		config:    &fsKeysDelegationRepo{repoId: sidecar.NewId(), groupId: sidecar.NewId(), kind: protocol.RepoKind_REPO_KIND_CONFIG},
		general:   &fsKeysDelegationRepo{repoId: sidecar.NewId(), groupId: sidecar.NewId(), kind: protocol.RepoKind_REPO_KIND_GENERAL},
	}
	host.Gates.OpenService(sidecar.ServiceGateGkm, world.networkId)
	state := &fsKeysDelegationState{log: world.log, memberId: world.memberId, configRepoId: world.config.repoId}
	engine, err := gkmservice.NewGkmEngine(ctx, host.ServiceHost(), nil, &gkmservice.GkmEngineDeps{AuthState: state})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	world.engine = engine
	world.creator = world.newDevice(sidecar.GkmScopeRoleWrite)
	world.rotator = world.newDevice(sidecar.GkmScopeRoleWrite)
	world.app = world.newDevice(sidecar.GkmScopeRoleRead)
	view := world.appendState()
	for _, repo := range []*fsKeysDelegationRepo{world.config, world.general} {
		world.placeGroup(repo, view)
	}
	// the app's ReaderKey stands at gkm, so each rotation wraps to it
	if err := world.app.api.UploadReaderKey(ctx, world.app.readerKey); err != nil {
		t.Fatalf("the app's ReaderKey: %v", err)
	}
	for _, device := range []*fsKeysDelegationDevice{world.rotator, world.app} {
		device.client.AuthAdvanced(view)
	}
	for _, repo := range []*fsKeysDelegationRepo{world.config, world.general} {
		if _, err := world.rotator.client.CurrentRepoKey(ctx, repo.repoId); err != nil {
			t.Fatalf("the rotator's first wrap: %v", err)
		}
	}
	return world
}

// A member device of the world, its api scoped to both repos at role and its group client on the world's clock.
func (self *fsKeysDelegationWorld) newDevice(role string) *fsKeysDelegationDevice {
	self.t.Helper()
	signer := NewFakeGkmSigner()
	readerKey, readerPrivateKey, err := sidecar.NewGkmReaderKey(signer.SidecarId, self.clock.Now(), self.clock.Now().Add(6*24*time.Hour), signer.Sign)
	if err != nil {
		self.t.Fatal(err)
	}
	readerKeySha256 := sha256.Sum256(readerPrivateKey.PublicKey().Bytes())
	device := &fsKeysDelegationDevice{signer: signer, readerKey: readerKey, readerPrivateKey: readerPrivateKey, readerKeySha256: readerKeySha256[:]}
	connectSidecarId := connect.Id(signer.SidecarId)
	device.api, err = sidecar.NewGkmApi(&sidecar.GkmApiArgs{
		GkmUrl:    "https://gkm.example",
		Transport: &gkmHandlerTransport{handler: self.engine.Handler()},
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return self.host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: self.networkId,
				ClientId:  connect.NewId(),
				SidecarId: &connectSidecarId,
				Audience:  gkmservice.GkmAudience,
				Scopes:    scopes,
				IssuedAt:  self.clock.Now(),
				ExpiresAt: self.clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Clock: self.clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	device.api.SetRepoScopes([]sidecar.GkmRepoScope{{RepoId: self.config.repoId, Role: role}, {RepoId: self.general.repoId, Role: role}})
	device.client, err = sidecar.NewGkmGroupClient(&sidecar.GkmGroupClientArgs{
		SidecarId: signer.SidecarId,
		NetworkId: sidecar.Id(self.networkId),
		Api:       device.api,
		Sign:      signer.Sign,
		Secrets:   &fsKeysDelegationSecrets{nameValues: map[string][]byte{}},
		ReaderPrivateKey: func(keySha256 []byte) (hpke.PrivateKey, error) {
			if !bytes.Equal(keySha256, device.readerKeySha256) {
				return nil, sidecar.ErrGkmKeyMissing
			}
			return device.readerPrivateKey, nil
		},
		ReaderKeySha256: func() []byte { return bytes.Clone(device.readerKeySha256) },
		Clock:           self.clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return device
}

// Appends the next position: the three devices reading both repos, the creator and rotator writing them, the
// Delegations the world holds, and the config's holders_shrunk_at. Every device's client takes it.
func (self *fsKeysDelegationWorld) appendState() *FakeGkmAuthView {
	devices := []*fsKeysDelegationDevice{self.creator, self.rotator, self.app}
	sidecarIds := []sidecar.Id{}
	identityKeys := map[sidecar.Id][]byte{}
	for _, device := range devices {
		sidecarIds = append(sidecarIds, device.signer.SidecarId)
		identityKeys[device.signer.SidecarId] = device.signer.PublicKey()
	}
	writerIds := []sidecar.Id{self.creator.signer.SidecarId, self.rotator.signer.SidecarId}
	fixture := &FakeGkmAuthFixture{
		Rows: FakeGkmAuthRows(
			&protocol.AclRepo{RepoId: self.config.repoId.Bytes(), Kind: self.config.kind, HoldersShrunkAt: self.configShrunkAt},
			&protocol.AclRepo{RepoId: self.general.repoId.Bytes(), Kind: self.general.kind},
		),
		IdentityKeys: identityKeys,
		RepoReaders:  map[sidecar.Id][]sidecar.Id{self.config.repoId: sidecarIds, self.general.repoId: sidecarIds},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{self.config.repoId: writerIds, self.general.repoId: writerIds},
	}
	sidecarRows, memberRow := FakeGkmAuthMemberDevices(self.memberId, sidecarIds...)
	fixture.Rows.Sidecars = sidecarRows
	fixture.Rows.Members = []*bridge.MemberRow{memberRow}
	for _, row := range self.delegations {
		fixture.Rows.Delegations = append(fixture.Rows.Delegations, proto.Clone(row).(*bridge.DelegationRow))
	}
	view := self.log.Append(fixture)
	for _, device := range devices {
		if device.client != nil {
			device.client.AuthAdvanced(view)
		}
	}
	return view
}

// The next position's number.
func (self *fsKeysDelegationWorld) nextPosition() uint64 {
	return self.log.Tip().Pin().GetVersion() + 1
}

// Writes a key on the first cluster, as another writer or a lying store would.
func (self *fsKeysDelegationWorld) put(key string, body []byte) {
	self.t.Helper()
	cluster, err := self.host.Blobs.FirstCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(self.ctx, key, body, nil); err != nil {
		self.t.Fatalf("put %s: %v", key, err)
	}
}

// A message's bytes.
func (self *fsKeysDelegationWorld) marshal(message proto.Message) []byte {
	self.t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		self.t.Fatal(err)
	}
	return body
}

// Places a repo on the first cluster, active, with its form and owner marker and generation 1 by the creator at
// view, holders_sha256 over the holders there, and its staged ReaderWrap to the rotator, as KF1 leaves a group.
func (self *fsKeysDelegationWorld) placeGroup(repo *fsKeysDelegationRepo, view *FakeGkmAuthView) {
	self.t.Helper()
	cluster, err := self.host.Blobs.FirstCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	place, err := (&sidecar.EvsRepoPlace{ClusterId: cluster.ClusterId(), CreatorSidecarId: self.creator.signer.SidecarId}).Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	self.put(sidecar.EvsPlaceKey(repo.repoId), place)
	self.put(gkmservice.GkmEvsRepoKey(repo.repoId), self.marshal(&protocol.EvsRepoObject{
		RepoId: repo.repoId.Bytes(), Kind: repo.kind, State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Format: 1, NetworkId: sidecar.Id(self.networkId).Bytes(),
	}))
	formBody := self.marshal(&protocol.GroupForm{RepoId: repo.repoId.Bytes(), GroupId: repo.groupId.Bytes(), Generation: 1})
	form, err := self.creator.signer.Sign("group-form", bridge.SignedType_SIGNED_GROUP_FORM, formBody, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	self.put(gkmservice.GkmFormKey(repo.repoId, 1), self.marshal(form))
	self.put(gkmservice.GkmGroupOwnerKey(repo.groupId), self.marshal(&protocol.GkmGroupOwner{RepoId: repo.repoId.Bytes(), NetworkId: sidecar.Id(self.networkId).Bytes()}))
	at := self.clock.Now()
	holders, err := sidecar.KeyHolders(view, repo.repoId, at)
	if err != nil {
		self.t.Fatal(err)
	}
	key1, rotate1, err := sidecar.NewGkmFirstGeneration(repo.repoId, repo.groupId, &sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRequest, Auth: view.Pin(), Time: at, HoldersSha256: holders.Sha256(), WrapCount: 1,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed1, err := sidecar.SignGenRotate(rotate1, self.creator.signer.Sign)
	if err != nil {
		self.t.Fatal(err)
	}
	self.put(gkmservice.GkmGenerationKey(repo.groupId, 1), self.marshal(signed1))
	body, err := sidecar.SealGkmDelivery(key1, &sidecar.GkmDeliveryArgs{
		GroupId: repo.groupId, Type: sidecar.GkmWrapTypeReader, Recipient: self.rotator.signer.SidecarId.Bytes(),
		RecipientPublicKey: self.rotator.readerPrivateKey.PublicKey().Bytes(), Kind: sidecar.GkmDeliveryStaged,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGkmDelivery(body, sidecar.GkmWrapTypeReader, self.creator.signer.Sign)
	if err != nil {
		self.t.Fatal(err)
	}
	delivery, err := sidecar.ParseGkmDelivery(signed, sidecar.GkmWrapTypeReader, sidecar.GkmIdentityKeys(view))
	if err != nil {
		self.t.Fatal(err)
	}
	path, err := sidecar.GkmDeliveryPath(repo.groupId, delivery)
	if err != nil {
		self.t.Fatal(err)
	}
	self.put(path, self.marshal(signed))
}

// A new forwarding Delegation of the app at the next position, superseding the one live before it: its row as
// TEAM-M8-01 writes it, its reader key a fresh X-Wing key whose SHA-256 alone the row holds.
func (self *fsKeysDelegationWorld) forward(label string) *fsKeysDelegationForward {
	self.t.Helper()
	privateKey, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		self.t.Fatal(err)
	}
	publicKey := privateKey.PublicKey().Bytes()
	keySha256 := sha256.Sum256(publicKey)
	delegationId := sha256.Sum256([]byte("forwarding Delegation " + label))
	at := self.nextPosition()
	for _, row := range self.delegations {
		if row.GetEndedAt() == 0 && row.GetSupersededAt() == 0 {
			row.SupersededAt = at
		}
	}
	appSidecarId := self.app.signer.SidecarId
	self.delegations = append(self.delegations, &bridge.DelegationRow{
		DelegationId:     delegationId[:],
		Signer:           appSidecarId.Bytes(),
		At:               at,
		Pubkey:           bytes.Repeat([]byte{0x5a}, 32),
		ForwardSidecarId: appSidecarId.Bytes(),
		ReaderKeySha256:  keySha256[:],
	})
	return &fsKeysDelegationForward{delegationId: delegationId[:], privateKey: privateKey, publicKey: publicKey, keySha256: keySha256[:]}
}

// Ends a forwarding Delegation at the next position by its DelegationRevoke, a shrink of the config there (§7.9's
// shrink row, which TEAM's verifier computes from KeyHolders).
func (self *fsKeysDelegationWorld) revoke(forward *fsKeysDelegationForward) {
	at := self.nextPosition()
	for _, row := range self.delegations {
		if bytes.Equal(row.GetDelegationId(), forward.delegationId) {
			row.EndedAt = at
			row.KeyDroppedAt = at
		}
	}
	self.configShrunkAt = at
}

// The app's sidecar uploads a forwarding Delegation's key and writes its late wraps, as its setup's S3 and S4 do.
func (self *fsKeysDelegationWorld) upload(forward *fsKeysDelegationForward) {
	self.t.Helper()
	if err := self.app.api.UploadDelegationKey(self.ctx, forward.delegationId, forward.publicKey); err != nil {
		self.t.Fatalf("the upload: %v", err)
	}
}

// The newest generation gkm holds of a repo's group, parsed at the log's tip.
func (self *fsKeysDelegationWorld) newestGeneration(repo *fsKeysDelegationRepo) *sidecar.GkmGeneration {
	self.t.Helper()
	reply, err := self.rotator.api.Generations(self.ctx, repo.repoId, repo.groupId, 0)
	if err != nil {
		self.t.Fatal(err)
	}
	generations := reply.GetGenerations()
	if len(generations) == 0 {
		self.t.Fatal("no generation")
	}
	signedBytes := self.marshal(generations[len(generations)-1])
	generation, err := sidecar.ParseGenRotate(signedBytes, repo.groupId, uint64(len(generations)), sidecar.GkmIdentityKeys(self.log.Tip()))
	if err != nil {
		self.t.Fatal(err)
	}
	return generation
}

// The DelegationWraps of a generation of a repo's group gkm stores, by recipient's delegation_id in hex.
func (self *fsKeysDelegationWorld) delegationWraps(repo *fsKeysDelegationRepo, generation uint64) map[string]*bridge.Signed {
	self.t.Helper()
	cluster, err := self.host.Blobs.FirstCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	prefix := gkmservice.GkmWrapGenerationPrefix(repo.groupId, generation)
	infos, _, err := cluster.List(self.ctx, prefix, "", 1000)
	if err != nil {
		self.t.Fatal(err)
	}
	wraps := map[string]*bridge.Signed{}
	for _, info := range infos {
		parts := strings.Split(strings.TrimPrefix(info.Key, prefix), "/")
		if len(parts) != 3 || !strings.HasPrefix(parts[1], "d:") {
			continue
		}
		object, err := cluster.Get(self.ctx, info.Key)
		if err != nil {
			self.t.Fatal(err)
		}
		body := new(bytes.Buffer)
		if _, err := body.ReadFrom(object.Body); err != nil {
			self.t.Fatal(err)
		}
		object.Body.Close()
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(body.Bytes(), signed); err != nil {
			self.t.Fatal(err)
		}
		wraps[strings.TrimPrefix(parts[1], "d:")] = signed
	}
	return wraps
}

// RK_g of generation from its DelegationWrap to forward, opened with the forwarding key and judged at its state as
// the VPN component's compile would (DESIGN-DETAILS 4.2.5's step 2); nil when gkm holds no such wrap.
func (self *fsKeysDelegationWorld) openForwarding(repo *fsKeysDelegationRepo, generation *sidecar.GkmGeneration, forward *fsKeysDelegationForward) *sidecar.EvsRepoKey {
	self.t.Helper()
	signed, found := self.delegationWraps(repo, generation.Rotate.GetGeneration())[hex.EncodeToString(forward.delegationId)]
	if !found {
		return nil
	}
	delivery, err := sidecar.ParseGkmDelivery(signed, sidecar.GkmWrapTypeDelegation, sidecar.GkmIdentityKeys(self.log.Tip()))
	if err != nil {
		self.t.Fatal(err)
	}
	if !bytes.Equal(delivery.Body.GetRecipientKeySha256(), forward.keySha256) {
		self.t.Fatalf("a DelegationWrap sealed to another key than the row's")
	}
	key, verdict, err := sidecar.GkmUseDelivery(self.log.Tip(), &sidecar.GkmDeliveryCheckArgs{
		RepoId: repo.repoId, Delivery: delivery, Generation: generation, Now: self.clock.Now(),
	}, forward.delegationId, forward.privateKey)
	if err != nil || verdict.Refused {
		self.t.Fatalf("the forwarding key's wrap: %v %v", verdict, err)
	}
	return key
}

// The rotator rotates a repo: the key it claimed.
func (self *fsKeysDelegationWorld) rotate(repo *fsKeysDelegationRepo) *sidecar.EvsRepoKey {
	self.t.Helper()
	key, err := self.rotator.client.RotateRepo(self.ctx, repo.repoId)
	if err != nil {
		self.t.Fatalf("the rotation: %v", err)
	}
	return key
}

// FS-18: a rotation of the config wraps to the live forwarding Delegation's key, read from gkm's object, and the key
// opens the generation; after a supersession it wraps to the newer key and not the superseded one, the generation's
// holders_sha256 unchanged by the supersession, and the newer key gets the generation claimed before it late, from
// its sidecar.
func TestFsKeysDelegationARotationWrapsToTheLiveForwardingKeyAlone(t *testing.T) {
	world := newFsKeysDelegationWorld(t)
	first := world.forward("first")
	world.appendState()
	world.upload(first)
	key2 := world.rotate(world.config)
	generation2 := world.newestGeneration(world.config)
	if opened := world.openForwarding(world.config, generation2, first); opened == nil || !bytes.Equal(opened.Commitment(), key2.Commitment()) {
		t.Fatalf("the live forwarding key does not open the config's generation 2")
	}
	holders2, err := sidecar.KeyHolders(world.log.Tip(), world.config.repoId, time.UnixMilli(generation2.Rotate.GetTimeMs()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(holders2.Sha256(), generation2.Rotate.GetHoldersSha256()) {
		t.Fatal("generation 2's holders_sha256 is not its state's")
	}

	second := world.forward("second")
	world.appendState()
	holdersAfter, err := sidecar.KeyHolders(world.log.Tip(), world.config.repoId, world.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(holdersAfter.Sha256(), holders2.Sha256()) {
		t.Errorf("the supersession changed holders_sha256")
	}
	// the newer key's late wrap of the generation claimed before it: its sidecar's, once the object stands
	world.upload(second)
	if _, err := world.app.client.CurrentRepoKey(world.ctx, world.config.repoId); err != nil {
		t.Fatalf("the app's own key of the config: %v", err)
	}
	if err := world.app.client.DeliverDelegationWraps(world.ctx, second.delegationId); err != nil {
		t.Fatalf("the newer key's late wrap: %v", err)
	}
	if opened := world.openForwarding(world.config, generation2, second); opened == nil || !bytes.Equal(opened.Commitment(), key2.Commitment()) {
		t.Errorf("the newer forwarding key does not open generation 2 by its late wrap")
	}

	key3 := world.rotate(world.config)
	generation3 := world.newestGeneration(world.config)
	if !bytes.Equal(generation3.Rotate.GetHoldersSha256(), holders2.Sha256()) {
		t.Errorf("a rotation after the supersession counts other holders")
	}
	if sidecar.GkmCause(generation3.Rotate.GetCause()) == sidecar.GkmCauseRemove {
		t.Errorf("a supersession made the next generation REMOVE")
	}
	if opened := world.openForwarding(world.config, generation3, second); opened == nil || !bytes.Equal(opened.Commitment(), key3.Commitment()) {
		t.Errorf("the newer forwarding key does not open generation 3")
	}
	if world.openForwarding(world.config, generation3, first) != nil {
		t.Errorf("generation 3 is wrapped to the superseded forwarding key")
	}
}

// FS-18: a DelegationRevoke of the live forwarding Delegation is a shrink of the config, so the next generation is
// REMOVE, wrapped to no forwarding key and excluding the forwarding holder.
func TestFsKeysDelegationARevokeMakesTheNextGenerationRemove(t *testing.T) {
	world := newFsKeysDelegationWorld(t)
	forward := world.forward("revoked")
	world.appendState()
	world.upload(forward)
	world.rotate(world.config)
	if world.openForwarding(world.config, world.newestGeneration(world.config), forward) == nil {
		t.Fatal("no wrap to the forwarding key before its revocation")
	}
	world.revoke(forward)
	world.appendState()
	world.rotate(world.config)
	generation := world.newestGeneration(world.config)
	if sidecar.GkmCause(generation.Rotate.GetCause()) != sidecar.GkmCauseRemove {
		t.Errorf("the generation after the revocation is cause %d", generation.Rotate.GetCause())
	}
	if len(world.delegationWraps(world.config, generation.Rotate.GetGeneration())) != 0 {
		t.Errorf("the REMOVE generation is wrapped to a forwarding key")
	}
	holders, err := sidecar.KeyHolders(world.log.Tip(), world.config.repoId, time.UnixMilli(generation.Rotate.GetTimeMs()))
	if err != nil {
		t.Fatal(err)
	}
	if holders.Contains(sidecar.GkmHolderForwarding, world.app.signer.SidecarId.Bytes()) {
		t.Errorf("the revoked forwarding Delegation's holder stands")
	}
}

// FS-18: a forwarding key opens the config's generations and nothing else: the general repo's rotation wraps to no
// forwarding Delegation, though the app's sidecar reads that repo, and a DelegationWrap of that repo's generation to
// the forwarding Delegation is refused at gkm.
func TestFsKeysDelegationAForwardingKeyOpensTheConfigAlone(t *testing.T) {
	world := newFsKeysDelegationWorld(t)
	forward := world.forward("config alone")
	world.appendState()
	world.upload(forward)
	world.rotate(world.config)
	if world.openForwarding(world.config, world.newestGeneration(world.config), forward) == nil {
		t.Fatal("no wrap to the forwarding key in the config")
	}
	generalKey := world.rotate(world.general)
	generalGeneration := world.newestGeneration(world.general)
	if wraps := world.delegationWraps(world.general, generalGeneration.Rotate.GetGeneration()); len(wraps) != 0 {
		t.Errorf("the general repo's generation is wrapped to %d Delegations", len(wraps))
	}
	// a holder's late wrap of the general repo to the forwarding Delegation: no key holder there, so gkm refuses it
	body, err := sidecar.SealGkmDelivery(generalKey, &sidecar.GkmDeliveryArgs{
		GroupId: world.general.groupId, Type: sidecar.GkmWrapTypeDelegation, Recipient: forward.delegationId,
		RecipientPublicKey: forward.publicKey, Kind: sidecar.GkmDeliveryLate, Auth: world.log.Tip().Pin(), Time: world.clock.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := sidecar.SignGkmDelivery(body, sidecar.GkmWrapTypeDelegation, world.rotator.signer.Sign)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := world.rotator.api.UploadWraps(world.ctx, world.general.repoId, world.general.groupId, generalGeneration.Rotate.GetGeneration(), generalKey.Commitment(),
		&protocol.GkmWrapBatch{Deliveries: [][]byte{world.marshal(signed)}})
	if err != nil {
		t.Fatal(err)
	}
	if status := reply.GetResults()[0].GetStatus(); status != http.StatusForbidden {
		t.Errorf("a late wrap of another repo's generation to a forwarding Delegation: %d", status)
	}
	// and the app's client, holding both repos' keys, delivers none there
	for _, repo := range []*fsKeysDelegationRepo{world.config, world.general} {
		if _, err := world.app.client.CurrentRepoKey(world.ctx, repo.repoId); err != nil {
			t.Fatalf("the app's own key: %v", err)
		}
	}
	if err := world.app.client.DeliverDelegationWraps(world.ctx, forward.delegationId); err != nil {
		t.Fatal(err)
	}
	if wraps := world.delegationWraps(world.general, generalGeneration.Rotate.GetGeneration()); len(wraps) != 0 {
		t.Errorf("the forwarding Delegation's sidecar wrote a wrap of another repo")
	}
}

// An object whose bytes are not the key the row names is refused at gkm, and so is another sidecar's upload; gkm's
// bytes a rotator meets that are not the row's key, as a lying store serves them, it seals nothing to and counts.
func TestFsKeysDelegationAKeyOffItsDigestIsRefusedAtGkmAndAtARotator(t *testing.T) {
	world := newFsKeysDelegationWorld(t)
	forward := world.forward("digest")
	world.appendState()
	stray, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := world.app.api.UploadDelegationKey(world.ctx, forward.delegationId, stray.PublicKey().Bytes()); !sidecar.IsGkmStatus(err, http.StatusForbidden) {
		t.Errorf("an upload of bytes off the row's digest: %v", err)
	}
	if err := world.rotator.api.UploadDelegationKey(world.ctx, forward.delegationId, forward.publicKey); !sidecar.IsGkmStatus(err, http.StatusForbidden) {
		t.Errorf("another sidecar's upload of the key: %v", err)
	}
	if key, err := world.rotator.api.DelegationKey(world.ctx, world.config.repoId, forward.delegationId); err != nil || key != nil {
		t.Fatalf("a refused upload stored a key: %v", err)
	}
	// a store that holds other bytes, past gkm's check
	objectKey, err := gkmservice.GkmDelegationKeyKey(forward.delegationId)
	if err != nil {
		t.Fatal(err)
	}
	world.put(objectKey, stray.PublicKey().Bytes())
	skipped := world.rotator.client.DelegationWrapsSkipped()
	world.rotate(world.config)
	if wraps := world.delegationWraps(world.config, world.newestGeneration(world.config).Rotate.GetGeneration()); len(wraps) != 0 {
		t.Errorf("a rotator sealed to bytes off the row's digest")
	}
	if world.rotator.client.DelegationWrapsSkipped() != skipped+1 {
		t.Errorf("the skipped wrap was not counted")
	}
}

// A rotation that finds no object of a live forwarding Delegation's key skips its wrap and counts it; once the
// Delegation's sidecar uploads the object, its late wrap gives the forwarding key that generation, and the next
// rotation wraps to it at once.
func TestFsKeysDelegationARotationWithNoObjectSkipsAndDeliversLate(t *testing.T) {
	world := newFsKeysDelegationWorld(t)
	forward := world.forward("missing")
	world.appendState()
	skipped := world.rotator.client.DelegationWrapsSkipped()
	key2 := world.rotate(world.config)
	generation2 := world.newestGeneration(world.config)
	if world.rotator.client.DelegationWrapsSkipped() != skipped+1 {
		t.Errorf("the skipped wrap was not counted")
	}
	if world.openForwarding(world.config, generation2, forward) != nil {
		t.Fatalf("a wrap to a key gkm holds no object of")
	}
	if generation2.Rotate.GetWrapCount() != 1 {
		// the app's ReaderWrap alone
		t.Errorf("generation 2 counts %d deliveries", generation2.Rotate.GetWrapCount())
	}
	// the app's late DelegationWrap before the upload writes nothing
	if _, err := world.app.client.CurrentRepoKey(world.ctx, world.config.repoId); err != nil {
		t.Fatalf("the app's own key of the config: %v", err)
	}
	if err := world.app.client.DeliverDelegationWraps(world.ctx, forward.delegationId); err != nil {
		t.Fatal(err)
	}
	if world.openForwarding(world.config, generation2, forward) != nil {
		t.Fatalf("a late wrap before the object stood")
	}
	world.upload(forward)
	if err := world.app.client.DeliverDelegationWraps(world.ctx, forward.delegationId); err != nil {
		t.Fatal(err)
	}
	if opened := world.openForwarding(world.config, generation2, forward); opened == nil || !bytes.Equal(opened.Commitment(), key2.Commitment()) {
		t.Fatalf("the late wrap does not give the forwarding key generation 2")
	}
	skipped = world.rotator.client.DelegationWrapsSkipped()
	key3 := world.rotate(world.config)
	if opened := world.openForwarding(world.config, world.newestGeneration(world.config), forward); opened == nil || !bytes.Equal(opened.Commitment(), key3.Commitment()) {
		t.Errorf("the next rotation does not wrap to the uploaded key")
	}
	if world.rotator.client.DelegationWrapsSkipped() != skipped {
		t.Errorf("a rotation with the object counted a skip")
	}
	// the app's newest generation is no longer gkm's newest: its late wrap is refused as stale, and nothing changes
	if err := world.app.client.DeliverDelegationWraps(world.ctx, forward.delegationId); err != nil {
		t.Errorf("a late wrap of a generation gkm no longer holds newest: %v", err)
	}
}
