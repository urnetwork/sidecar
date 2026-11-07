// §23.5's fake of gkm and its client: a sidecar.GkmClient for each sidecar of a test, over one FakeGkm that keeps
// every repo's ladder. It holds real RK_g, drawn and linked by KEYS-M2-02's ladder, and writes each generation as gkm
// would, a real Signed GenRotate at gkm/<group_id>/gen/<g> in fake Blobs, since evs reads those objects for its gate.
// Clients read keys back through those objects: every gen/<g> verified under its signer's identity key from the
// reader's own state, the newest key opened from a GenWrap under the group's KEK and checked against its C_g, and the
// rest walked down the ladder. A rewritten object therefore refuses, as it would on gkm.
//
// What it keeps of §10:
//
//   - a client acts only on a verified state, from AuthAdvanced, and refuses with ErrGkmUnavailable before one;
//   - each generation goes to the readers its rotator's state names, as staged deliveries do, and a reader asking
//     later gets the newest, as a late delivery gives it, so a sidecar dropped before a rotation holds nothing of the
//     new generation and keeps what it held;
//   - EnsureWritable refuses a non-writer and rotates when the newest generation does not cover the repo's
//     holders_shrunk_at, or a sidecar holding it reads no more (cause REMOVE), or it is ScheduleInterval old (cause
//     SCHEDULE); RotateRepo rotates now, REMOVE or REQUEST by the same test;
//   - DropKey keeps the depositor rule as far as this fake sees: coverage, the drop key's expiry and a pin that never
//     falls;
//   - generation 1 carries cause REQUEST (keys-ladder-aad-widths.md).
//
// What it does not keep: MLS, whose fake is FakeMls, so no epoch object, Welcome or LeafWrap is written, and the
// GenWrap a client opens is under a KEK of this fake's own; KeyHolders and expiries (KEYS-M2-03), so deliveries
// follow RepoReaders, holders_sha256 comes from FakeGkmSettings.HoldersSha256 and no expiry rotates; staged and late
// wraps as objects; and gkm's route and scope checks. Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What FakeGkm refuses that the seam names no error for.
var errFakeGkmRefused = errors.New("fake gkm: refused")

type FakeGkmSettings struct {
	// The metadata cluster gen/<g> objects go to. Empty: the first.
	ClusterId string
	// The age at which EnsureWritable rotates with cause SCHEDULE: 30 days (§10.5).
	ScheduleInterval time.Duration
	// How long a drop key takes deposits: GkmSettings.DropKeyLifetime's 90 days (QD-031).
	DropKeyLifetime time.Duration
	// The kinds whose GenRotates carry a drop key (D-KEYS-17): §8.5's deposit column, vault, mailbox, secret and the
	// team record.
	DepositKinds []protocol.RepoKind
	// holders_sha256 for a new generation, until KEYS-M2-03's KeyHolders. Nil: SHA-256 of no identity.
	HoldersSha256 func(repoId sidecar.Id, state sidecar.GkmAuthView, at time.Time) []byte
}

func DefaultFakeGkmSettings() *FakeGkmSettings {
	return &FakeGkmSettings{
		ScheduleInterval: 30 * 24 * time.Hour,
		DropKeyLifetime:  90 * 24 * time.Hour,
		DepositKinds: []protocol.RepoKind{
			protocol.RepoKind_REPO_KIND_VAULT,
			protocol.RepoKind_REPO_KIND_MAILBOX,
			protocol.RepoKind_REPO_KIND_SECRET,
			protocol.RepoKind_REPO_KIND_TEAM_RECORD,
		},
	}
}

// Every repo's ladder on the fake.
type FakeGkm struct {
	clock    Clock
	blobs    sidecar.BlobStore
	settings *FakeGkmSettings

	// Held across a rotation's object write, so two rotations of one fake never race on gen/<g+1>.
	rotateLock sync.Mutex

	stateLock   sync.Mutex
	repoIdRepos map[sidecar.Id]*fakeGkmRepo
}

// One repo's group and ladder.
type fakeGkmRepo struct {
	repoId  sidecar.Id
	groupId sidecar.Id
	kind    protocol.RepoKind
	// the group's KEK on this fake, which seals each generation's GenWrap
	kek []byte
	// by generation, from 1
	keys     []*sidecar.EvsRepoKey
	genWraps [][]byte
	// who each generation was delivered to
	generationHolders []map[sidecar.Id]bool
}

// clock and settings may be nil, for a fresh clock and the defaults. blobs holds the gen/<g> objects.
func NewFakeGkm(clock Clock, blobs sidecar.BlobStore, settings *FakeGkmSettings) *FakeGkm {
	if clock == nil {
		clock = NewFakeClock(DefaultClockStart())
	}
	if settings == nil {
		settings = DefaultFakeGkmSettings()
	}
	return &FakeGkm{
		clock:       clock,
		blobs:       blobs,
		settings:    settings,
		repoIdRepos: map[sidecar.Id]*fakeGkmRepo{},
	}
}

// A test sidecar's identity key, signing as Sidecar.Sign does (CORE-M1-05): signer_id its sidecar_id, the
// signature over §6.9's signed bytes. A fixture's IdentityKeys holds its PublicKey.
type FakeGkmSigner struct {
	SidecarId  sidecar.Id
	PrivateKey ed25519.PrivateKey
}

// A fresh sidecar_id and identity key.
func NewFakeGkmSigner() *FakeGkmSigner {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("fake gkm signer: %v", err))
	}
	return &FakeGkmSigner{SidecarId: sidecar.NewId(), PrivateKey: privateKey}
}

func (self *FakeGkmSigner) PublicKey() ed25519.PublicKey {
	return self.PrivateKey.Public().(ed25519.PublicKey)
}

// A sidecar.GkmSignFunction.
func (self *FakeGkmSigner) Sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.SidecarId.Bytes(),
		Signature: ed25519.Sign(self.PrivateKey, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// One sidecar's client, which signs its GenRotates through sign, as Sidecar.Sign would.
func (self *FakeGkm) Client(sidecarId sidecar.Id, sign sidecar.GkmSignFunction) sidecar.GkmClient {
	return &fakeGkmClient{
		gkm:            self,
		sidecarId:      sidecarId,
		sign:           sign,
		repoIdDropPins: map[sidecar.Id]uint64{},
	}
}

// The group of a repo and its newest generation, as gkm serves them.
func (self *FakeGkm) Newest(repoId sidecar.Id) (groupId sidecar.Id, generation uint64, ok bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repo, ok := self.repoIdRepos[repoId]
	if !ok {
		return sidecar.Id{}, 0, false
	}
	return repo.groupId, uint64(len(repo.keys)), true
}

// The cluster gen/<g> objects go to.
func (self *FakeGkm) cluster() (sidecar.BlobCluster, error) {
	if self.settings.ClusterId == "" {
		return self.blobs.FirstCluster()
	}
	return self.blobs.Cluster(self.settings.ClusterId)
}

// Whether the kind's GenRotates carry a drop key.
func (self *FakeGkm) takesDeposits(kind protocol.RepoKind) bool {
	return slices.Contains(self.settings.DepositKinds, kind)
}

// The settings' holders hash, or the hash of no identity.
func (self *FakeGkm) holdersSha256(repoId sidecar.Id, state sidecar.GkmAuthView, at time.Time) []byte {
	if self.settings.HoldersSha256 != nil {
		return self.settings.HoldersSha256(repoId, state, at)
	}
	empty := sha256.Sum256(nil)
	return empty[:]
}

// A copy of the repo's state, or nil.
func (self *FakeGkm) repo(repoId sidecar.Id) *fakeGkmRepo {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repo, ok := self.repoIdRepos[repoId]
	if !ok {
		return nil
	}
	copied := *repo
	copied.keys = slices.Clone(repo.keys)
	copied.genWraps = slices.Clone(repo.genWraps)
	copied.generationHolders = []map[sidecar.Id]bool{}
	for _, holders := range repo.generationHolders {
		copied.generationHolders = append(copied.generationHolders, cloneHolders(holders))
	}
	return &copied
}

// A copy of one generation's holders.
func cloneHolders(holders map[sidecar.Id]bool) map[sidecar.Id]bool {
	cloned := map[sidecar.Id]bool{}
	for sidecarId, held := range holders {
		cloned[sidecarId] = held
	}
	return cloned
}

// Writes gen/<g> signed by sign, then the generation's key, GenWrap and holders, under rotateLock.
func (self *FakeGkm) claim(ctx context.Context, repo *fakeGkmRepo, key *sidecar.EvsRepoKey, rotate *protocol.GenRotate, sign sidecar.GkmSignFunction, holders map[sidecar.Id]bool) error {
	signed, err := sidecar.SignGenRotate(rotate, sign)
	if err != nil {
		return err
	}
	objectBytes, err := proto.Marshal(signed)
	if err != nil {
		return err
	}
	genWrap, err := sidecar.SealGkmGenWrap(key, repo.groupId, 0, repo.kek)
	if err != nil {
		return err
	}
	cluster, err := self.cluster()
	if err != nil {
		return err
	}
	if _, err := cluster.PutIfNoneMatch(ctx, sidecar.GkmGenerationPath(repo.groupId, key.Generation()), objectBytes, nil); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	stored, ok := self.repoIdRepos[repo.repoId]
	if !ok {
		stored = repo
		self.repoIdRepos[repo.repoId] = stored
	}
	stored.keys = append(stored.keys, key)
	stored.genWraps = append(stored.genWraps, genWrap)
	stored.generationHolders = append(stored.generationHolders, holders)
	return nil
}

// Gives a sidecar the newest generation, a late delivery.
func (self *FakeGkm) deliverNewest(repoId sidecar.Id, sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if repo, ok := self.repoIdRepos[repoId]; ok && 0 < len(repo.keys) {
		repo.generationHolders[len(repo.keys)-1][sidecarId] = true
	}
}

// Drops every generation a sidecar was given.
func (self *FakeGkm) forget(repoId sidecar.Id, sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if repo, ok := self.repoIdRepos[repoId]; ok {
		for _, holders := range repo.generationHolders {
			delete(holders, sidecarId)
		}
	}
}

// gen/<g>'s object, read back and verified by state's identity keys.
func (self *FakeGkm) readGeneration(ctx context.Context, groupId sidecar.Id, generation uint64, state sidecar.GkmAuthView) (*sidecar.GkmGeneration, error) {
	cluster, err := self.cluster()
	if err != nil {
		return nil, err
	}
	object, err := cluster.Get(ctx, sidecar.GkmGenerationPath(groupId, generation))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, fmt.Errorf("%w: gen/%d is not there", sidecar.ErrGkmKeyMissing, generation)
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	objectBytes, err := io.ReadAll(object.Body)
	if err != nil {
		return nil, err
	}
	identityKey := func(signerId sidecar.Id) ([]byte, error) {
		publicKey := state.IdentityKey(signerId)
		if publicKey == nil {
			return nil, fmt.Errorf("%w: gen/%d's signer is not admitted", sidecar.ErrGkmAuthentication, generation)
		}
		return publicKey, nil
	}
	return sidecar.ParseGenRotate(objectBytes, groupId, generation, identityKey)
}

// One sidecar's client on the fake.
type fakeGkmClient struct {
	gkm       *FakeGkm
	sidecarId sidecar.Id
	sign      sidecar.GkmSignFunction

	stateLock sync.Mutex
	state     sidecar.GkmAuthView
	// the newest generation each repo's drop key came from (§10.5's depositor pin)
	repoIdDropPins map[sidecar.Id]uint64
}

// The newest state given, or ErrGkmUnavailable before one.
func (self *fakeGkmClient) currentState() (sidecar.GkmAuthView, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state == nil {
		return nil, fmt.Errorf("%w: no verified state yet", sidecar.ErrGkmUnavailable)
	}
	return self.state, nil
}

func (self *fakeGkmClient) AuthAdvanced(state sidecar.GkmAuthView) {
	if state == nil {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state == nil || self.state.Pin().GetVersion() <= state.Pin().GetVersion() {
		self.state = state
	}
}

func (self *fakeGkmClient) CreateGroup(ctx context.Context, args *sidecar.GkmCreateGroupArgs) (*sidecar.EvsRepoKey, error) {
	state, err := self.currentState()
	if err != nil {
		return nil, err
	}
	if args == nil {
		return nil, fmt.Errorf("%w: no repo", errFakeGkmRefused)
	}
	self.gkm.rotateLock.Lock()
	defer self.gkm.rotateLock.Unlock()
	if self.gkm.repo(args.RepoId) != nil {
		return nil, fmt.Errorf("%w: repo %s has a group", errFakeGkmRefused, args.RepoId)
	}
	var groupId sidecar.Id
	rand.Read(groupId[:])
	kek := make([]byte, 32)
	rand.Read(kek)
	repo := &fakeGkmRepo{repoId: args.RepoId, groupId: groupId, kind: args.Kind, kek: kek}
	now := self.gkm.clock.Now()
	generationArgs := &sidecar.GkmGenerationArgs{
		Cause:         sidecar.GkmCauseRequest,
		Auth:          state.Pin(),
		Time:          now,
		HoldersSha256: self.gkm.holdersSha256(args.RepoId, state, now),
	}
	if self.gkm.takesDeposits(args.Kind) {
		generationArgs.DropNotAfter = now.Add(self.gkm.settings.DropKeyLifetime)
	}
	key, rotate, err := sidecar.NewGkmFirstGeneration(args.RepoId, groupId, generationArgs)
	if err != nil {
		return nil, err
	}
	holders := map[sidecar.Id]bool{self.sidecarId: true}
	for _, reader := range state.RepoReaders(args.RepoId) {
		holders[reader] = true
	}
	if err := self.gkm.claim(ctx, repo, key, rotate, self.sign, holders); err != nil {
		return nil, err
	}
	return key, nil
}

// Whether the newest generation leaves out a shrink the state shows: below holders_shrunk_at, or held by a sidecar
// that reads no more.
func (self *fakeGkmClient) needsRemove(repo *fakeGkmRepo, state sidecar.GkmAuthView) bool {
	newest := repo.keys[len(repo.keys)-1]
	if aclRepo := state.Repo(repo.repoId); aclRepo != nil && newest.Auth().GetVersion() < aclRepo.GetHoldersShrunkAt() {
		return true
	}
	readers := state.RepoReaders(repo.repoId)
	for holder := range repo.generationHolders[len(repo.keys)-1] {
		if !slices.Contains(readers, holder) {
			return true
		}
	}
	return false
}

// A new generation now, delivered to the readers state names, signed by this client.
func (self *fakeGkmClient) rotateWithLock(ctx context.Context, repo *fakeGkmRepo, state sidecar.GkmAuthView, cause sidecar.GkmCause) (*sidecar.EvsRepoKey, error) {
	now := self.gkm.clock.Now()
	generationArgs := &sidecar.GkmGenerationArgs{
		Cause:         cause,
		Auth:          state.Pin(),
		Time:          now,
		HoldersSha256: self.gkm.holdersSha256(repo.repoId, state, now),
	}
	if self.gkm.takesDeposits(repo.kind) {
		generationArgs.DropNotAfter = now.Add(self.gkm.settings.DropKeyLifetime)
	}
	key, rotate, err := repo.keys[len(repo.keys)-1].NextGeneration(generationArgs)
	if err != nil {
		return nil, err
	}
	holders := map[sidecar.Id]bool{}
	for _, reader := range state.RepoReaders(repo.repoId) {
		holders[reader] = true
	}
	if err := self.gkm.claim(ctx, repo, key, rotate, self.sign, holders); err != nil {
		return nil, err
	}
	return key, nil
}

// The repo and this client's state, once it writes the repo.
func (self *fakeGkmClient) writable(repoId sidecar.Id) (*fakeGkmRepo, sidecar.GkmAuthView, error) {
	state, err := self.currentState()
	if err != nil {
		return nil, nil, err
	}
	if !slices.Contains(state.RepoWriters(repoId), self.sidecarId) {
		return nil, nil, sidecar.ErrGkmNotWriter
	}
	repo := self.gkm.repo(repoId)
	if repo == nil {
		return nil, nil, fmt.Errorf("%w: repo %s has no group", sidecar.ErrGkmKeyMissing, repoId)
	}
	return repo, state, nil
}

func (self *fakeGkmClient) EnsureWritable(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	key, state, err := func() (*sidecar.EvsRepoKey, sidecar.GkmAuthView, error) {
		self.gkm.rotateLock.Lock()
		defer self.gkm.rotateLock.Unlock()
		repo, state, err := self.writable(repoId)
		if err != nil {
			return nil, nil, err
		}
		newest := repo.keys[len(repo.keys)-1]
		var key *sidecar.EvsRepoKey
		switch {
		case self.needsRemove(repo, state):
			key, err = self.rotateWithLock(ctx, repo, state, sidecar.GkmCauseRemove)
		case self.gkm.settings.ScheduleInterval <= self.gkm.clock.Now().Sub(newest.Time()):
			key, err = self.rotateWithLock(ctx, repo, state, sidecar.GkmCauseSchedule)
		}
		return key, state, err
	}()
	if err != nil || key != nil {
		return key, err
	}
	// covered: the newest, as a writer that reads it holds it
	held, err := self.held(repoId, state)
	if err != nil {
		return nil, err
	}
	return self.repoKey(ctx, repoId, held, held, state)
}

func (self *fakeGkmClient) RotateRepo(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	self.gkm.rotateLock.Lock()
	defer self.gkm.rotateLock.Unlock()
	repo, state, err := self.writable(repoId)
	if err != nil {
		return nil, err
	}
	cause := sidecar.GkmCauseRequest
	if self.needsRemove(repo, state) {
		cause = sidecar.GkmCauseRemove
	}
	return self.rotateWithLock(ctx, repo, state, cause)
}

func (self *fakeGkmClient) CurrentRepoKey(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	state, err := self.currentState()
	if err != nil {
		return nil, err
	}
	held, err := self.held(repoId, state)
	if err != nil {
		return nil, err
	}
	return self.repoKey(ctx, repoId, held, held, state)
}

func (self *fakeGkmClient) RepoKey(ctx context.Context, repoId sidecar.Id, generation uint64) (*sidecar.EvsRepoKey, error) {
	state, err := self.currentState()
	if err != nil {
		return nil, err
	}
	held, err := self.held(repoId, state)
	if err != nil {
		return nil, err
	}
	if generation == 0 || held < generation {
		return nil, fmt.Errorf("%w: generation %d is not held", sidecar.ErrGkmKeyMissing, generation)
	}
	return self.repoKey(ctx, repoId, held, generation, state)
}

// The newest generation this client holds, after the late delivery a current reader gets.
func (self *fakeGkmClient) held(repoId sidecar.Id, state sidecar.GkmAuthView) (uint64, error) {
	if slices.Contains(state.RepoReaders(repoId), self.sidecarId) {
		self.gkm.deliverNewest(repoId, self.sidecarId)
	}
	repo := self.gkm.repo(repoId)
	if repo == nil {
		return 0, fmt.Errorf("%w: repo %s has no group", sidecar.ErrGkmKeyMissing, repoId)
	}
	for index := len(repo.generationHolders) - 1; 0 <= index; index -= 1 {
		if repo.generationHolders[index][self.sidecarId] {
			return uint64(index + 1), nil
		}
	}
	return 0, fmt.Errorf("%w: no generation of repo %s is held", sidecar.ErrGkmKeyMissing, repoId)
}

// Generation g, as a reader holding generation top opens it: every gen/<k> up to top read back and verified, top's
// key opened from its GenWrap against its C_g, and the ladder walked down to RK_1.
func (self *fakeGkmClient) repoKey(ctx context.Context, repoId sidecar.Id, top uint64, generation uint64, state sidecar.GkmAuthView) (*sidecar.EvsRepoKey, error) {
	repo := self.gkm.repo(repoId)
	if repo == nil {
		return nil, fmt.Errorf("%w: repo %s has no group", sidecar.ErrGkmKeyMissing, repoId)
	}
	if generation == 0 || top < generation || uint64(len(repo.keys)) < top {
		return nil, fmt.Errorf("%w: generation %d is not held", sidecar.ErrGkmKeyMissing, generation)
	}
	generations := []*sidecar.GkmGeneration{}
	for k := uint64(1); k <= top; k += 1 {
		parsed, err := self.gkm.readGeneration(ctx, repo.groupId, k, state)
		if err != nil {
			return nil, err
		}
		generations = append(generations, parsed)
	}
	topKey, err := sidecar.OpenGkmGenWrap(generations[top-1], repo.groupId, 0, repo.kek, repo.genWraps[top-1])
	if err != nil {
		return nil, err
	}
	keys, err := sidecar.OpenGkmLadder(topKey, generations[:top-1])
	if err != nil {
		return nil, err
	}
	return keys[generation-1], nil
}

func (self *fakeGkmClient) DropKey(ctx context.Context, repoId sidecar.Id) (*sidecar.GkmDropKey, error) {
	state, err := self.currentState()
	if err != nil {
		return nil, err
	}
	repo := self.gkm.repo(repoId)
	if repo == nil {
		return nil, fmt.Errorf("%w: repo %s has no group", sidecar.ErrGkmKeyMissing, repoId)
	}
	if !self.gkm.takesDeposits(repo.kind) {
		return nil, fmt.Errorf("%w: repo %s takes no deposits", sidecar.ErrGkmKeyMissing, repoId)
	}
	newest := uint64(len(repo.keys))
	generation, err := self.gkm.readGeneration(ctx, repo.groupId, newest, state)
	if err != nil {
		return nil, err
	}
	rotate := generation.Rotate
	if aclRepo := state.Repo(repoId); aclRepo != nil && rotate.GetAuth().GetVersion() < aclRepo.GetHoldersShrunkAt() {
		return nil, fmt.Errorf("%w: gen/%d does not cover a shrink", sidecar.ErrGkmWait, newest)
	}
	notAfter := time.UnixMilli(rotate.GetDropNotAfterMs())
	if !self.gkm.clock.Now().Before(notAfter) {
		return nil, fmt.Errorf("%w: gen/%d's drop key has lapsed", sidecar.ErrGkmWait, newest)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if newest < self.repoIdDropPins[repoId] {
		return nil, fmt.Errorf("%w: gen/%d is below this sidecar's pin", sidecar.ErrGkmWait, newest)
	}
	self.repoIdDropPins[repoId] = newest
	return &sidecar.GkmDropKey{
		RepoId:     repoId,
		GroupId:    repo.groupId,
		Generation: newest,
		Commitment: bytes.Clone(rotate.GetCommitment()),
		PublicKey:  bytes.Clone(rotate.GetDropPublicKey()),
		NotAfter:   notAfter,
	}, nil
}

func (self *fakeGkmClient) ForgetRepo(ctx context.Context, repoId sidecar.Id) error {
	self.gkm.forget(repoId, self.sidecarId)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.repoIdDropPins, repoId)
	return nil
}
