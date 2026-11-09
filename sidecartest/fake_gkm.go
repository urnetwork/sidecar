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
//   - each generation goes to the readers its rotator's state names, as staged deliveries do. A reader its own
//     state names asks for the newest later, and gets it only as §10.9's late row lets a holder deliver it: from a
//     holder of it whose own newest state is at or past the generation's auth pin and names both as readers, at that
//     state. A sidecar dropped before a rotation therefore holds nothing of the new generation, however far behind
//     its own state is, and keeps what it held;
//   - a client uses a delivery only once its state reaches the delivery's pin, gen/<g>'s for a staged one and its
//     deliverer's for a late one (§10.9's judged row), and until then waits with ErrGkmAuthAhead;
//   - EnsureWritable and RotateRepo act only for a writer whose state reaches the newest generation's pin and
//     which holds that generation, never sealing to or rotating from an older one (ErrGkmAuthAhead or
//     ErrGkmKeyMissing until then). EnsureWritable rotates when the newest does not cover the repo's
//     holders_shrunk_at, a key holder of the repo expired after the newest's time (sidecar.GkmRemoveDue), or a
//     sidecar holding it reads no more (cause REMOVE), or when it is ScheduleInterval old (cause SCHEDULE); RotateRepo
//     rotates now, REMOVE or REQUEST by the same test. So a generation EnsureWritable answers without rotating passes
//     sidecar.GkmGatePasses at that state and now, as evs's gate will judge it;
//   - DropKey keeps the depositor rule as far as this fake sees: the gate's coverage of shrinks and expiries, the
//     drop key's expiry and a pin that never falls;
//   - holders_sha256 is sidecar.KeyHolders' at the rotator's state and time, unless the settings give another;
//   - generation 1 carries cause REQUEST (keys-ladder-aad-widths.md).
//
// KeyHolders needs a row for each reader (FakeGkmAuthMemberDevices gives member devices theirs). On a state that
// names a reader with none, EnsureWritable, RotateRepo and DropKey refuse with ErrGkmMalformed, as evs's gate would,
// and holders_sha256 falls back to the hash of no identity.
//
// What it does not keep: MLS, whose fake is FakeMls, so no epoch object, Welcome or LeafWrap is written, and the
// GenWrap a client opens is under a KEK of this fake's own; KeyHolders' wraps, so staged deliveries follow
// RepoReaders, a covered agent getting its own rather than its Delegation's; ReaderKeys,
// hint timing, and gkm's own late check that the recipient reads the repo in gkm's newest state, so any holder that
// may deliver does so at once, and what a removed reader gets here is what the holders' rules alone give it, as the
// revocation suite needs; staged and late wraps as objects; and gkm's route and scope checks.
//
// Safe for concurrent use. Locks nest one way: rotateLock, then the fake's stateLock or one client's stateLock,
// never two stateLocks at once.

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
	"maps"
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
	// holders_sha256 for a new generation. Nil: sidecar.KeyHolders' at the rotator's state and time, or SHA-256 of no
	// identity where the state cannot name the holders.
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

	// Held across a rotation's object write, so two rotations of one fake never race on gen/<g+1>. The functions
	// named WithLock run under it.
	rotateLock sync.Mutex

	stateLock   sync.Mutex
	repoIdRepos map[sidecar.Id]*fakeGkmRepo
	// each sidecar's newest client, which answers for it as a holder that may deliver late
	sidecarIdClients map[sidecar.Id]*fakeGkmClient
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
	// who each generation was delivered to, and the pin each delivery is judged at: gen/<g>'s auth for a staged one,
	// its deliverer's state for a late one. A pin is never changed once stored.
	generationHolderIdPins []map[sidecar.Id]*bridge.AuthPin
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
		clock:            clock,
		blobs:            blobs,
		settings:         settings,
		repoIdRepos:      map[sidecar.Id]*fakeGkmRepo{},
		sidecarIdClients: map[sidecar.Id]*fakeGkmClient{},
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

// One sidecar's client, which signs its GenRotates through sign, as Sidecar.Sign would. A sidecar's newest client
// answers for it as a holder.
func (self *FakeGkm) Client(sidecarId sidecar.Id, sign sidecar.GkmSignFunction) sidecar.GkmClient {
	client := &fakeGkmClient{
		gkm:            self,
		sidecarId:      sidecarId,
		sign:           sign,
		repoIdDropPins: map[sidecar.Id]uint64{},
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sidecarIdClients[sidecarId] = client
	return client
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

// The settings' holders hash, or KeyHolders', or the hash of no identity.
func (self *FakeGkm) holdersSha256(repoId sidecar.Id, state sidecar.GkmAuthView, at time.Time) []byte {
	if self.settings.HoldersSha256 != nil {
		return self.settings.HoldersSha256(repoId, state, at)
	}
	if holders, err := sidecar.KeyHolders(state, repoId, at); err == nil {
		return holders.Sha256()
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
	copied.generationHolderIdPins = []map[sidecar.Id]*bridge.AuthPin{}
	for _, holderIdPins := range repo.generationHolderIdPins {
		// the pins themselves never change, so the copy shares them
		copied.generationHolderIdPins = append(copied.generationHolderIdPins, maps.Clone(holderIdPins))
	}
	return &copied
}

// Writes gen/<g> signed by sign, then the generation's key, GenWrap and staged deliveries, under rotateLock.
func (self *FakeGkm) claimWithLock(ctx context.Context, repo *fakeGkmRepo, key *sidecar.EvsRepoKey, rotate *protocol.GenRotate, sign sidecar.GkmSignFunction, holderIdPins map[sidecar.Id]*bridge.AuthPin) error {
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
	stored.generationHolderIdPins = append(stored.generationHolderIdPins, holderIdPins)
	return nil
}

// A late delivery of the repo's newest generation to recipientId, unless it holds one (§10.6's late wraps). Only a
// holder of that generation delivers, at its own newest state, and only if that state opens its own delivery of it,
// so is at or past gen/<g>'s auth pin, and names both it and the recipient as readers (§10.9's late row). The
// asker's state decides nothing. Of several such holders the delivery takes the lowest position, which a recipient
// behind the others reaches first, so the outcome never rests on which one answers first; with none, nothing is
// delivered.
func (self *FakeGkm) deliverLate(repoId sidecar.Id, recipientId sidecar.Id) {
	var generation int
	holderIdPins := map[sidecar.Id]*bridge.AuthPin{}
	holderIdClients := map[sidecar.Id]*fakeGkmClient{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		repo, ok := self.repoIdRepos[repoId]
		if !ok || len(repo.keys) == 0 {
			return
		}
		generation = len(repo.keys)
		for holderId, pin := range repo.generationHolderIdPins[generation-1] {
			if client, ok := self.sidecarIdClients[holderId]; ok {
				holderIdPins[holderId] = pin
				holderIdClients[holderId] = client
			}
		}
	}()

	// each holder's state read with no other lock held
	var deliveryPin *bridge.AuthPin
	for holderId, holderPin := range holderIdPins {
		state, err := holderIdClients[holderId].currentState()
		if err != nil || judgeFakeGkmPin(state, holderPin) != nil {
			continue
		}
		readers := state.RepoReaders(repoId)
		if !slices.Contains(readers, holderId) || !slices.Contains(readers, recipientId) {
			continue
		}
		if pin := state.Pin(); deliveryPin == nil || pin.GetVersion() < deliveryPin.GetVersion() {
			deliveryPin = pin
		}
	}
	if deliveryPin == nil {
		return
	}

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	deliveries := self.repoIdRepos[repoId].generationHolderIdPins[generation-1]
	// one delivery per recipient, the first stored, as If-None-Match keeps it: a staged one is never replaced
	if _, ok := deliveries[recipientId]; !ok {
		deliveries[recipientId] = deliveryPin
	}
}

// Whether state may act on what was stated or delivered at pin, as §10.9's judged row has it: at or below its tip
// on its chain, or before what it retains, which it does not judge and holds against no one. ErrGkmAuthAhead above
// its tip, which waits until the log reaches it, and ErrGkmAuthOffChain off its chain.
func judgeFakeGkmPin(state sidecar.GkmAuthView, pin *bridge.AuthPin) error {
	if _, err := state.At(pin); err != nil && !errors.Is(err, sidecar.ErrGkmAuthNotRetained) {
		return err
	}
	return nil
}

// Drops every generation a sidecar was given.
func (self *FakeGkm) forget(repoId sidecar.Id, sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if repo, ok := self.repoIdRepos[repoId]; ok {
		for _, holderIdPins := range repo.generationHolderIdPins {
			delete(holderIdPins, sidecarId)
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
	// staged, judged at gen/1's pin
	holderIdPins := map[sidecar.Id]*bridge.AuthPin{self.sidecarId: generationArgs.Auth}
	for _, reader := range state.RepoReaders(args.RepoId) {
		holderIdPins[reader] = generationArgs.Auth
	}
	if err := self.gkm.claimWithLock(ctx, repo, key, rotate, self.sign, holderIdPins); err != nil {
		return nil, err
	}
	return key, nil
}

// Whether the newest generation leaves out a drop the state shows at now: a shrink below holders_shrunk_at or a key
// holder's expiry after its time (sidecar.GkmRemoveDue), or a sidecar holding it that reads no more. An error when the
// state cannot name the repo's holders.
func (self *fakeGkmClient) needsRemove(repo *fakeGkmRepo, state sidecar.GkmAuthView, now time.Time) (bool, error) {
	newest := repo.keys[len(repo.keys)-1]
	due, err := sidecar.GkmRemoveDue(state, repo.repoId, newest.Auth(), newest.Time(), now)
	if err != nil || due {
		return due, err
	}
	readers := state.RepoReaders(repo.repoId)
	for holder := range repo.generationHolderIdPins[len(repo.keys)-1] {
		if !slices.Contains(readers, holder) {
			return true, nil
		}
	}
	return false, nil
}

// A new generation after parent, the newest as this writer holds it, now: delivered to the readers state names,
// signed by this client.
func (self *fakeGkmClient) rotateWithLock(ctx context.Context, repo *fakeGkmRepo, parent *sidecar.EvsRepoKey, state sidecar.GkmAuthView, cause sidecar.GkmCause) (*sidecar.EvsRepoKey, error) {
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
	key, rotate, err := parent.NextGeneration(generationArgs)
	if err != nil {
		return nil, err
	}
	// staged, judged at gen/<g>'s pin
	holderIdPins := map[sidecar.Id]*bridge.AuthPin{}
	for _, reader := range state.RepoReaders(repo.repoId) {
		holderIdPins[reader] = generationArgs.Auth
	}
	if err := self.gkm.claimWithLock(ctx, repo, key, rotate, self.sign, holderIdPins); err != nil {
		return nil, err
	}
	return key, nil
}

// The repo, this client's state and the repo's newest generation as this client holds it, once it writes the repo
// and may act on that generation. A writer whose state is below gen/<g>'s auth pin cannot judge it and waits for the
// log (ErrGkmAuthAhead), since a claim from its older state would be refused below its parent's pin (§10.6's claim
// checks). One the newest was not delivered to has nothing to seal to or rotate from (ErrGkmKeyMissing), and is never
// given an older generation instead. Under rotateLock, so the newest cannot change before the caller acts.
func (self *fakeGkmClient) writableWithLock(ctx context.Context, repoId sidecar.Id) (*fakeGkmRepo, sidecar.GkmAuthView, *sidecar.EvsRepoKey, error) {
	state, err := self.currentState()
	if err != nil {
		return nil, nil, nil, err
	}
	if !slices.Contains(state.RepoWriters(repoId), self.sidecarId) {
		return nil, nil, nil, sidecar.ErrGkmNotWriter
	}
	repo := self.gkm.repo(repoId)
	if repo == nil {
		return nil, nil, nil, fmt.Errorf("%w: repo %s has no group", sidecar.ErrGkmKeyMissing, repoId)
	}
	newest := uint64(len(repo.keys))
	if err := judgeFakeGkmPin(state, repo.keys[newest-1].Auth()); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: gen/%d's auth pin", err, newest)
	}
	held, err := self.held(repoId, state, newest)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := self.repoKey(ctx, repoId, held, held, state)
	if err != nil {
		return nil, nil, nil, err
	}
	return repo, state, key, nil
}

func (self *fakeGkmClient) EnsureWritable(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	self.gkm.rotateLock.Lock()
	defer self.gkm.rotateLock.Unlock()
	repo, state, newest, err := self.writableWithLock(ctx, repoId)
	if err != nil {
		return nil, err
	}
	now := self.gkm.clock.Now()
	needsRemove, err := self.needsRemove(repo, state, now)
	switch {
	case err != nil:
		return nil, err
	case needsRemove:
		return self.rotateWithLock(ctx, repo, newest, state, sidecar.GkmCauseRemove)
	case self.gkm.settings.ScheduleInterval <= now.Sub(newest.Time()):
		return self.rotateWithLock(ctx, repo, newest, state, sidecar.GkmCauseSchedule)
	}
	// covered
	return newest, nil
}

func (self *fakeGkmClient) RotateRepo(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	self.gkm.rotateLock.Lock()
	defer self.gkm.rotateLock.Unlock()
	repo, state, newest, err := self.writableWithLock(ctx, repoId)
	if err != nil {
		return nil, err
	}
	needsRemove, err := self.needsRemove(repo, state, self.gkm.clock.Now())
	if err != nil {
		return nil, err
	}
	cause := sidecar.GkmCauseRequest
	if needsRemove {
		cause = sidecar.GkmCauseRemove
	}
	return self.rotateWithLock(ctx, repo, newest, state, cause)
}

func (self *fakeGkmClient) CurrentRepoKey(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	state, err := self.currentState()
	if err != nil {
		return nil, err
	}
	held, err := self.held(repoId, state, 1)
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
	held, err := self.held(repoId, state, generation)
	if err != nil {
		return nil, err
	}
	return self.repoKey(ctx, repoId, held, generation, state)
}

// The newest generation this client may use, at least atLeast. A reader its own state names first asks for a late
// delivery of the newest, which a holder may then make (deliverLate). Of the generations delivered to it, the newest
// whose delivery its state judges usable answers, every older one being reached down the ladder. When none at or
// above atLeast is usable, it refuses as the newest delivery at or above atLeast does, ErrGkmAuthAhead until the log
// reaches that delivery's pin, or with ErrGkmKeyMissing when there is none.
func (self *fakeGkmClient) held(repoId sidecar.Id, state sidecar.GkmAuthView, atLeast uint64) (uint64, error) {
	if slices.Contains(state.RepoReaders(repoId), self.sidecarId) {
		self.gkm.deliverLate(repoId, self.sidecarId)
	}
	repo := self.gkm.repo(repoId)
	if repo == nil {
		return 0, fmt.Errorf("%w: repo %s has no group", sidecar.ErrGkmKeyMissing, repoId)
	}
	var refusal error
	for index := len(repo.generationHolderIdPins) - 1; 0 <= index; index -= 1 {
		generation := uint64(index + 1)
		pin, ok := repo.generationHolderIdPins[index][self.sidecarId]
		if !ok {
			continue
		}
		err := judgeFakeGkmPin(state, pin)
		if err == nil && atLeast <= generation {
			return generation, nil
		}
		if err == nil {
			break
		}
		if refusal == nil && atLeast <= generation {
			refusal = fmt.Errorf("%w: generation %d's delivery", err, generation)
		}
	}
	if refusal == nil {
		refusal = fmt.Errorf("%w: generation %d of repo %s is not held", sidecar.ErrGkmKeyMissing, atLeast, repoId)
	}
	return 0, refusal
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
	now := self.gkm.clock.Now()
	err = sidecar.GkmGateCheck(state, repoId, rotate.GetAuth(), time.UnixMilli(rotate.GetTimeMs()), now)
	switch {
	case errors.Is(err, sidecar.ErrGkmGateClosed):
		return nil, fmt.Errorf("%w: gen/%d: %w", sidecar.ErrGkmWait, newest, err)
	case err != nil:
		return nil, err
	}
	notAfter := time.UnixMilli(rotate.GetDropNotAfterMs())
	if !now.Before(notAfter) {
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
