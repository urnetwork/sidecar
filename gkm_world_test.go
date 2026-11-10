// The world the member checks', the rotation's and the membership flows' tests share: a log of fixture states
// (sidecartest.FakeGkmAuthLog), one repo with its group on FakeMls, and devices that each hold an identity key, an
// admitted credential and an engine. A test changes the world in place, then appends a position.

package sidecar_test

import (
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The clock every test of the world starts at.
var gkmWorldStart = time.UnixMilli(1_800_000_000_000)

// One sidecar of the world.
type gkmWorldDevice struct {
	label  string
	signer *sidecartest.FakeGkmSigner
	id     sidecar.Id
	row    *bridge.SidecarRow
	// its leaf's credential, signed by its identity key
	credential []byte
	mls        *sidecartest.FakeMls
	// the group as it last adopted it, nil while no leaf
	group sidecar.MlsGroup
}

type gkmWorld struct {
	t        *testing.T
	log      *sidecartest.FakeGkmAuthLog
	mlsWorld *sidecartest.FakeMlsWorld
	now      time.Time

	repoId  sidecar.Id
	groupId sidecar.Id
	repo    *protocol.AclRepo
	// every repo row of the state, the world's own among them
	repos []*protocol.AclRepo

	memberId sidecar.Id
	members  []*bridge.MemberRow
	devices  []*gkmWorldDevice
	// what the next state answers
	readers        []sidecar.Id
	writers        []sidecar.Id
	readerExpiries map[sidecar.Id]time.Time
	delegations    []*bridge.DelegationRow
	atomRepos      map[sidecar.Id][]sidecar.Id
}

// A world with one general repo and one member, at no state yet.
func newGkmWorld(t *testing.T, kind protocol.RepoKind) *gkmWorld {
	world := &gkmWorld{
		t:              t,
		log:            sidecartest.NewFakeGkmAuthLog(),
		mlsWorld:       sidecartest.NewFakeMlsWorld(),
		now:            gkmWorldStart,
		repoId:         sidecar.NewId(),
		groupId:        sidecar.NewId(),
		memberId:       sidecar.NewId(),
		readerExpiries: map[sidecar.Id]time.Time{},
		atomRepos:      map[sidecar.Id][]sidecar.Id{},
	}
	world.repo = &protocol.AclRepo{RepoId: world.repoId.Bytes(), Kind: kind}
	world.repos = []*protocol.AclRepo{world.repo}
	world.members = []*bridge.MemberRow{{MemberId: world.memberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_OWNER}}
	return world
}

// A credential for a device, naming admissionSha256 and lasting until notAfter.
func (self *gkmWorld) credential(device *gkmWorldDevice, admissionSha256 []byte, notAfter time.Time) []byte {
	self.t.Helper()
	credential, err := sidecar.SignUrMlsCredential(&sidecar.UrMlsCredentialArgs{
		SidecarId:             device.id,
		IdentityPublicKey:     device.signer.PublicKey(),
		MlsSignaturePublicKey: device.signer.PublicKey(),
		NotAfter:              notAfter,
		AdmissionSha256:       admissionSha256,
	}, device.signer.Sign)
	if err != nil {
		self.t.Fatal(err)
	}
	return credential
}

// Admits a sidecar: a member device of the world's member unless tagIds names tags, with its row, credential and
// engine. It reads and writes nothing until the test says so.
func (self *gkmWorld) admit(label string, tagIds ...sidecar.Id) *gkmWorldDevice {
	self.t.Helper()
	signer := sidecartest.NewFakeGkmSigner()
	admission := sha256.Sum256([]byte("admission of " + label))
	position := uint64(len(self.devices) + 1)
	row := &bridge.SidecarRow{
		SidecarId:         signer.SidecarId.Bytes(),
		AdmissionSha256:   admission[:],
		AdmittedAt:        position,
		LiveSince:         position,
		IdentityPublicKey: signer.PublicKey(),
		IdentityAlg:       "ed25519",
	}
	if len(tagIds) == 0 {
		row.MemberId = self.memberId.Bytes()
	}
	for _, tagId := range tagIds {
		row.TagIds = append(row.TagIds, tagId.Bytes())
	}
	device := &gkmWorldDevice{label: label, signer: signer, id: signer.SidecarId, row: row}
	device.credential = self.credential(device, admission[:], self.now.Add(90*24*time.Hour))
	device.mls = self.mlsWorld.Engine(device.id, device.credential)
	self.devices = append(self.devices, device)
	return device
}

// Lets devices read the repo, and write it too with write.
func (self *gkmWorld) grant(write bool, devices ...*gkmWorldDevice) {
	for _, device := range devices {
		if !slices.Contains(self.readers, device.id) {
			self.readers = append(self.readers, device.id)
		}
		if write && !slices.Contains(self.writers, device.id) {
			self.writers = append(self.writers, device.id)
		}
	}
}

// Revokes a device at the next position: its row a tombstone, and no reader or writer.
func (self *gkmWorld) revoke(device *gkmWorldDevice) {
	device.row.RevokedAt = self.nextPosition()
	self.drop(device)
	self.repo.HoldersShrunkAt = self.nextPosition()
}

// Ends a device's reading with no change to its row, as a grant's end does. The repo's holders_shrunk_at is the
// caller's to advance.
func (self *gkmWorld) drop(device *gkmWorldDevice) {
	self.readers = slices.DeleteFunc(self.readers, func(id sidecar.Id) bool { return id == device.id })
	self.writers = slices.DeleteFunc(self.writers, func(id sidecar.Id) bool { return id == device.id })
}

// The position the next state takes.
func (self *gkmWorld) nextPosition() uint64 {
	if tip := self.log.Tip(); tip != nil {
		return tip.Pin().GetVersion() + 1
	}
	return 1
}

// Appends the world as it stands as the log's next position.
func (self *gkmWorld) state() *sidecartest.FakeGkmAuthView {
	self.t.Helper()
	acl, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.AclRows{Repos: self.repos})
	if err != nil {
		self.t.Fatal(err)
	}
	rows := &bridge.ProjectionRows{Acl: acl, Members: self.members, Delegations: self.delegations}
	identityKeys := map[sidecar.Id][]byte{}
	for _, device := range self.devices {
		rows.Sidecars = append(rows.Sidecars, device.row)
		identityKeys[device.id] = device.signer.PublicKey()
	}
	fixture := &sidecartest.FakeGkmAuthFixture{
		Rows:               rows,
		IdentityKeys:       identityKeys,
		RepoReaders:        map[sidecar.Id][]sidecar.Id{self.repoId: self.readers},
		RepoWriters:        map[sidecar.Id][]sidecar.Id{self.repoId: self.writers},
		RepoReaderExpiries: map[sidecar.Id]map[sidecar.Id]time.Time{self.repoId: self.readerExpiries},
		AtomRepos:          self.atomRepos,
	}
	return self.log.Append(fixture)
}

// A GkmCommitHeader's encoding.
func gkmWorldHeader(t *testing.T, generation uint64, pin *bridge.AuthPin) []byte {
	t.Helper()
	header, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmCommitHeader{Generation: generation, Auth: pin})
	if err != nil {
		t.Fatal(err)
	}
	return header
}

// The creator's group at epoch 0.
func (self *gkmWorld) createGroup(creator *gkmWorldDevice) {
	self.t.Helper()
	group, err := creator.mls.CreateGroup(self.groupId, &sidecar.MlsUrGroup{RepoId: self.repoId, Kind: self.repo.GetKind()})
	if err != nil {
		self.t.Fatal(err)
	}
	creator.group = group
}

// A one-time KeyPackage of each device, as a claim would return it.
func (self *gkmWorld) keyPackages(devices ...*gkmWorldDevice) [][]byte {
	self.t.Helper()
	keyPackages := [][]byte{}
	for _, device := range devices {
		keyPackage, err := device.mls.CreateKeyPackage(false)
		if err != nil {
			self.t.Fatal(err)
		}
		keyPackages = append(keyPackages, keyPackage.Encoded)
	}
	return keyPackages
}

// The leaf index of a device in a group's roster.
func (self *gkmWorld) leafIndex(group sidecar.MlsGroup, device *gkmWorldDevice) uint32 {
	self.t.Helper()
	for _, member := range group.Roster() {
		if member.SidecarId == device.id {
			return member.LeafIndex
		}
	}
	self.t.Fatalf("%s is no leaf", device.label)
	return 0
}

// Stages committer's commit of adds and removes on its group, with a path whenever it is not Add-only.
func (self *gkmWorld) stage(committer *gkmWorldDevice, generation uint64, pin *bridge.AuthPin, adds []*gkmWorldDevice, removes []*gkmWorldDevice) sidecar.MlsStagedCommit {
	self.t.Helper()
	args := &sidecar.MlsCommitArgs{
		Adds:              self.keyPackages(adds...),
		Path:              len(adds) == 0 || 0 < len(removes),
		AuthenticatedData: gkmWorldHeader(self.t, generation, pin),
	}
	for _, removed := range removes {
		args.Removes = append(args.Removes, self.leafIndex(committer.group, removed))
	}
	staged, err := committer.group.Commit(args)
	if err != nil {
		self.t.Fatal(err)
	}
	return staged
}

// Adopts a staged commit at its committer and at every other leaf that holds the group, and joins its Adds by its
// Welcome, with no check: the tests judge it themselves first.
func (self *gkmWorld) adopt(committer *gkmWorldDevice, staged sidecar.MlsStagedCommit, joiners ...*gkmWorldDevice) {
	self.t.Helper()
	message := staged.Message()
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		self.t.Fatal(err)
	}
	welcome := staged.Welcome()
	removed := staged.Removed()
	for _, device := range self.devices {
		if device == committer || device.group == nil || slices.Contains(joiners, device) {
			continue
		}
		received, err := device.group.Process(message)
		if err != nil {
			self.t.Fatalf("%s processes the commit: %v", device.label, err)
		}
		group, err := received.Adopt()
		if slices.ContainsFunc(removed, func(member sidecar.MlsMember) bool { return member.SidecarId == device.id }) {
			device.group = nil
			continue
		}
		if err != nil {
			self.t.Fatalf("%s adopts the commit: %v", device.label, err)
		}
		device.group = group
	}
	group, err := staged.Adopt()
	if err != nil {
		self.t.Fatal(err)
	}
	committer.group = group
	for _, joiner := range joiners {
		pending, err := joiner.mls.JoinWelcome(welcome)
		if err != nil {
			self.t.Fatalf("%s opens the Welcome: %v", joiner.label, err)
		}
		joined, err := pending.Complete(groupInfo)
		if err != nil {
			self.t.Fatalf("%s completes the join: %v", joiner.label, err)
		}
		joiner.group = joined
	}
}

// A commit as another leaf receives it: staged on receiver's group from the committer's message.
func (self *gkmWorld) receive(receiver *gkmWorldDevice, staged sidecar.MlsStagedCommit) sidecar.MlsStagedCommit {
	self.t.Helper()
	received, err := receiver.group.Process(staged.Message())
	if err != nil {
		self.t.Fatalf("%s processes the commit: %v", receiver.label, err)
	}
	return received
}

// One generation of the world's repo as its rotator made it and a reader parses it.
type gkmWorldGeneration struct {
	key        *sidecar.EvsRepoKey
	generation *sidecar.GkmGeneration
	rotate     *protocol.GenRotate
	signed     *bridge.Signed
}

// The key holders hash of the repo at a state and time.
func (self *gkmWorld) holdersSha256(view sidecar.GkmAuthView, at time.Time) []byte {
	self.t.Helper()
	holders, err := sidecar.KeyHolders(view, self.repoId, at)
	if err != nil {
		self.t.Fatal(err)
	}
	return holders.Sha256()
}

// Signs rotate as rotator and parses it back under the state's identity keys.
func (self *gkmWorld) signGeneration(view sidecar.GkmAuthView, rotator *gkmWorldDevice, key *sidecar.EvsRepoKey, rotate *protocol.GenRotate) *gkmWorldGeneration {
	self.t.Helper()
	signed, err := sidecar.SignGenRotate(rotate, rotator.signer.Sign)
	if err != nil {
		self.t.Fatal(err)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	generation, err := sidecar.ParseGenRotate(encoded, self.groupId, rotate.GetGeneration(), sidecar.GkmIdentityKeys(view))
	if err != nil {
		self.t.Fatal(err)
	}
	return &gkmWorldGeneration{key: key, generation: generation, rotate: rotate, signed: signed}
}

// Generation 1 by rotator at view and the world's clock, or the next after parent, with edit changing the statement
// before it is signed.
func (self *gkmWorld) generation(view sidecar.GkmAuthView, rotator *gkmWorldDevice, parent *gkmWorldGeneration, cause sidecar.GkmCause, edit func(args *sidecar.GkmGenerationArgs)) *gkmWorldGeneration {
	self.t.Helper()
	args := &sidecar.GkmGenerationArgs{
		Cause:         cause,
		Auth:          view.Pin(),
		Time:          self.now,
		HoldersSha256: self.holdersSha256(view, self.now),
	}
	if edit != nil {
		edit(args)
	}
	var key *sidecar.EvsRepoKey
	var rotate *protocol.GenRotate
	var err error
	if parent == nil {
		key, rotate, err = sidecar.NewGkmFirstGeneration(self.repoId, self.groupId, args)
	} else {
		key, rotate, err = parent.key.NextGeneration(args)
	}
	if err != nil {
		self.t.Fatal(err)
	}
	return self.signGeneration(view, rotator, key, rotate)
}

// A GenWrap of a generation's key under a staged commit's epoch.
func (self *gkmWorld) genWrap(staged sidecar.MlsStagedCommit, generation *gkmWorldGeneration) []byte {
	self.t.Helper()
	kek, err := sidecar.MlsKek(staged, self.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	genWrap, err := sidecar.SealGkmGenWrap(generation.key, self.groupId, staged.Epoch(), kek)
	if err != nil {
		self.t.Fatal(err)
	}
	return genWrap
}
