package gkmservice

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// T2's GkmReconcilerState: each network's state as a test sets it, announced to the reconciler's watch.
type fakeGkmReconcilerState struct {
	stateLock       sync.Mutex
	networkStates   map[sidecar.Id]*GkmNetworkState
	sidecarNetworks map[sidecar.Id]sidecar.Id
	revokedIds      map[sidecar.Id]bool
	changed         func(change *GkmStateChange)
}

func newFakeGkmReconcilerState() *fakeGkmReconcilerState {
	return &fakeGkmReconcilerState{
		networkStates:   map[sidecar.Id]*GkmNetworkState{},
		sidecarNetworks: map[sidecar.Id]sidecar.Id{},
		revokedIds:      map[sidecar.Id]bool{},
	}
}

func (self *fakeGkmReconcilerState) Watch(changed func(change *GkmStateChange)) (func(), error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.changed = changed
	return func() {}, nil
}

func (self *fakeGkmReconcilerState) Networks() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkIds := []sidecar.Id{}
	for networkId := range self.networkStates {
		networkIds = append(networkIds, networkId)
	}
	return networkIds
}

func (self *fakeGkmReconcilerState) State(ctx context.Context, networkId sidecar.Id) (*GkmNetworkState, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, ok := self.networkStates[networkId]
	if !ok {
		return nil, errors.New("not loaded")
	}
	return state, nil
}

func (self *fakeGkmReconcilerState) SidecarStanding(ctx context.Context, sidecarId sidecar.Id) (sidecar.Id, bool, bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkId, ok := self.sidecarNetworks[sidecarId]
	return networkId, self.revokedIds[sidecarId], ok, nil
}

// Moves a network to view and announces the change, signed by signerId.
func (self *fakeGkmReconcilerState) set(networkId sidecar.Id, view sidecar.GkmAuthView, repoIds []sidecar.Id, signerId *sidecar.Id) {
	changed := func() func(change *GkmStateChange) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.networkStates[networkId] = &GkmNetworkState{View: view, RepoIds: slices.Clone(repoIds)}
		return self.changed
	}()
	if changed != nil {
		changed(&GkmStateChange{NetworkId: networkId, SignerId: signerId})
	}
}

// One network, one repo on the second cluster with its group, and a reconciler on the fixture's host.
type gkmReconcilerWorld struct {
	t          *testing.T
	fixture    *gkmFixture
	state      *fakeGkmReconcilerState
	reconciler *GkmReconciler
	log        *sidecartest.FakeGkmAuthLog
	networkId  sidecar.Id
	repoId     sidecar.Id
	groupId    sidecar.Id
	memberId   sidecar.Id
	signer     *gkmTestSidecar
	key1       *sidecar.EvsRepoKey
}

func newGkmReconcilerWorld(t *testing.T) *gkmReconcilerWorld {
	fixture := newGkmFixture(t)
	world := &gkmReconcilerWorld{
		t:         t,
		fixture:   fixture,
		state:     newFakeGkmReconcilerState(),
		log:       sidecartest.NewFakeGkmAuthLog(),
		networkId: testId("network-a"),
		repoId:    testId("repo-g"),
		groupId:   testId("group-g"),
		memberId:  testId("member-a"),
	}
	fixture.placeRepo(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.fileForm(world.repoId, "meta-2", 1, world.groupId)
	world.signer = fixture.newSidecar("sc-signer", memberDeviceFacts(world.memberId))
	reconciler, err := NewGkmReconciler(fixture.ctx, fixture.host.ServiceHost(), DefaultGkmReconcilerSettings(), &GkmReconcilerDeps{State: world.state})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reconciler.Close)
	world.reconciler = reconciler
	return world
}

// A log position at which readers read the repo, writers write it, holders_shrunk_at is shrunkAt, and each reader in
// expiries stops reading at its time.
func (self *gkmReconcilerWorld) appendState(readers []sidecar.Id, writers []sidecar.Id, shrunkAt uint64, expiries map[sidecar.Id]time.Time) *sidecartest.FakeGkmAuthView {
	fixture := &sidecartest.FakeGkmAuthFixture{
		Rows:               sidecartest.FakeGkmAuthRows(&protocol.AclRepo{RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, HoldersShrunkAt: shrunkAt}),
		IdentityKeys:       map[sidecar.Id][]byte{},
		RepoReaders:        map[sidecar.Id][]sidecar.Id{self.repoId: readers},
		RepoWriters:        map[sidecar.Id][]sidecar.Id{self.repoId: writers},
		RepoReaderExpiries: map[sidecar.Id]map[sidecar.Id]time.Time{self.repoId: expiries},
	}
	allIds := slices.Clone(readers)
	for _, writerId := range writers {
		if !slices.Contains(allIds, writerId) {
			allIds = append(allIds, writerId)
		}
	}
	sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(self.memberId, allIds...)
	fixture.Rows.Sidecars = sidecarRows
	fixture.Rows.Members = []*bridge.MemberRow{memberRow}
	return self.log.Append(fixture)
}

// Writes gen/<g> of the group at pin and now, as a claim would have: the first from a new key, a later one from
// parent.
func (self *gkmReconcilerWorld) putGeneration(parent *sidecar.EvsRepoKey, pin *bridge.AuthPin) *sidecar.EvsRepoKey {
	self.t.Helper()
	args := &sidecar.GkmGenerationArgs{Cause: sidecar.GkmCauseRemove, Auth: pin, Time: self.fixture.clock.Now(), HoldersSha256: gkmTestHoldersSha256()}
	var key *sidecar.EvsRepoKey
	var rotate *protocol.GenRotate
	var err error
	if parent == nil {
		args.Cause = sidecar.GkmCauseRequest
		key, rotate, err = sidecar.NewGkmFirstGeneration(self.repoId, self.groupId, args)
	} else {
		key, rotate, err = parent.NextGeneration(args)
	}
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGenRotate(rotate, self.signer.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	self.fixture.put("meta-2", GkmGenerationKey(self.groupId, key.Generation()), self.fixture.marshal(signed))
	return key
}

// Runs fn, then waits until the reconciler holds view for the network: the pass that read it has finished.
func (self *gkmReconcilerWorld) awaitState(view sidecar.GkmAuthView, fn func()) {
	self.t.Helper()
	_, changed := self.reconciler.Passes()
	fn()
	for {
		held := func() sidecar.GkmAuthView {
			self.reconciler.stateLock.Lock()
			defer self.reconciler.stateLock.Unlock()
			if entry, ok := self.reconciler.networkEntries[self.networkId]; ok && entry.state != nil {
				return entry.state.View
			}
			return nil
		}()
		if held == view {
			return
		}
		select {
		case <-changed:
			_, changed = self.reconciler.Passes()
		case <-self.fixture.ctx.Done():
			self.t.Fatal("the reconciler never read the state")
		}
	}
}

// Waits until the loop waits with its timer set, so a move of the fake clock reaches that timer.
func (self *gkmReconcilerWorld) awaitIdle() {
	self.t.Helper()
	for {
		idle, changed := self.reconciler.idle.Get()
		if idle {
			return
		}
		select {
		case <-changed:
		case <-self.fixture.ctx.Done():
			self.t.Fatal("the reconciler never waited")
		}
	}
}

// Runs fn, which moves the clock, once the loop waits, and waits for the pass that move starts to finish.
func (self *gkmReconcilerWorld) awaitPass(fn func()) {
	self.t.Helper()
	self.awaitIdle()
	count, changed := self.reconciler.Passes()
	fn()
	for {
		select {
		case <-changed:
		case <-self.fixture.ctx.Done():
			self.t.Fatal("no pass")
		}
		var now int
		now, changed = self.reconciler.Passes()
		if count < now {
			return
		}
	}
}

// The pending hints a sidecar's client holds about the group.
func (self *gkmReconcilerWorld) pendingHints(sidecarId sidecar.Id) int {
	self.t.Helper()
	count := 0
	for _, hint := range self.fixture.hints(sidecarId) {
		if hint.GetKind() == protocol.GkmHintKind_GKM_HINT_PENDING && sidecar.Id(hint.GetGroupId()) == self.groupId {
			count += 1
		}
	}
	return count
}

// §10.6's pending changes: a shrink hints the writers, the revoking device first, and again every interval while the
// gate stays closed; a covering generation stops it; an expiry, which no entry announces, closes the gate at its time
// and hints within one interval.
func TestGkmReconcilerHintsAShrinkAndAnExpiryWithinOneInterval(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	writer, readerA, readerB := testId("sc-writer"), testId("sc-reader-a"), testId("sc-reader-b")
	for _, sidecarId := range []sidecar.Id{writer, readerA, readerB} {
		fixture.clientOf(sidecarId)
	}
	view1 := world.appendState([]sidecar.Id{writer, readerA, readerB}, []sidecar.Id{writer}, 0, nil)
	world.key1 = world.putGeneration(nil, view1.Pin())
	world.awaitState(view1, func() { world.state.set(world.networkId, view1, []sidecar.Id{world.repoId}, nil) })
	if count := world.pendingHints(writer); count != 0 {
		t.Fatalf("a first sight with the gate open hinted: %d", count)
	}

	// A is revoked: a shrink at position 2, which gen/1 does not cover
	view2 := world.appendState([]sidecar.Id{writer, readerB}, []sidecar.Id{writer}, 2, nil)
	world.awaitState(view2, func() { world.state.set(world.networkId, view2, []sidecar.Id{world.repoId}, &writer) })
	if count := world.pendingHints(writer); count != 1 {
		t.Fatalf("pending hints after the shrink: %d", count)
	}
	if count := world.pendingHints(readerB); count != 0 {
		t.Errorf("a reader that writes nothing was hinted: %d", count)
	}
	world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.PendingHintInterval) })
	if count := world.pendingHints(writer); count != 2 {
		t.Errorf("pending hints one interval into a closed gate: %d", count)
	}

	// a rotation covering the shrink reopens the gate, and the hints stop
	key2 := world.putGeneration(world.key1, view2.Pin())
	world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.PendingHintInterval) })
	world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.PendingHintInterval) })
	if count := world.pendingHints(writer); count != 2 {
		t.Errorf("pending hints once a generation covers the shrink: %d", count)
	}

	// B's grant expires in an hour, with no entry: the gate closes then
	expiry := fixture.clock.Now().Add(time.Hour)
	view3 := world.appendState([]sidecar.Id{writer, readerB}, []sidecar.Id{writer}, 2, map[sidecar.Id]time.Time{readerB: expiry})
	world.putGeneration(key2, view3.Pin())
	world.awaitState(view3, func() { world.state.set(world.networkId, view3, []sidecar.Id{world.repoId}, nil) })
	if count := world.pendingHints(writer); count != 2 {
		t.Fatalf("a change with no shrink hinted: %d", count)
	}
	for fixture.clock.Now().Before(expiry) {
		world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.PendingHintInterval) })
	}
	if count := world.pendingHints(writer); count != 3 {
		t.Errorf("pending hints within an interval of the expiry: %d", count)
	}
}

// DESIGN-DETAILS 6.2.3's H1: after a rotation that covers a shrink, the gate is open, yet pending still goes to the
// writers every DroppedLeafHintInterval while the newest epoch's pin is below the drop, since the dropped holder's
// leaf may still stand; it stops at the first epoch whose pin passes the drop.
func TestGkmReconcilerHintsWhileADroppedHolderPrecedesTheNewestEpochsPin(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	writer, readerA := testId("sc-writer"), testId("sc-reader-a")
	for _, sidecarId := range []sidecar.Id{writer, readerA} {
		fixture.clientOf(sidecarId)
	}
	putEpoch := func(epoch uint64, pin *bridge.AuthPin) {
		fixture.put("meta-2", GkmEpochKey(world.groupId, epoch), fixture.marshal(&protocol.GkmEpochObject{
			Header: &protocol.GkmCommitHeader{Generation: 1, Auth: pin}, TimeMs: fixture.clock.Now().UnixMilli(),
		}))
	}
	view1 := world.appendState([]sidecar.Id{writer, readerA}, []sidecar.Id{writer}, 0, nil)
	world.key1 = world.putGeneration(nil, view1.Pin())
	putEpoch(0, view1.Pin())
	world.awaitState(view1, func() { world.state.set(world.networkId, view1, []sidecar.Id{world.repoId}, nil) })
	if count := world.pendingHints(writer); count != 0 {
		t.Fatalf("a first sight with nothing dropped hinted: %d", count)
	}
	// A is revoked at position 2, and a wrapped writer's rotation covers it at once: the gate is open
	view2 := world.appendState([]sidecar.Id{writer}, []sidecar.Id{writer}, 2, nil)
	world.putGeneration(world.key1, view2.Pin())
	world.awaitState(view2, func() { world.state.set(world.networkId, view2, []sidecar.Id{world.repoId}, &writer) })
	hinted := world.pendingHints(writer)
	if hinted == 0 {
		t.Fatalf("no pending hint at the shrink")
	}
	// epoch 0's pin is below the drop: the hint repeats though the gate is open
	world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.DroppedLeafHintInterval) })
	if count := world.pendingHints(writer); count != hinted+1 {
		t.Errorf("pending hints one interval into a dropped holder before the newest epoch: %d, was %d", count, hinted)
	}
	// a writer leaf's Remove lands at a pin past the drop: the hints stop
	putEpoch(1, view2.Pin())
	world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.DroppedLeafHintInterval) })
	stopped := world.pendingHints(writer)
	world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.DroppedLeafHintInterval) })
	world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.DroppedLeafHintInterval) })
	if count := world.pendingHints(writer); count != stopped {
		t.Errorf("pending hints after an epoch whose pin passes the drop: %d, was %d", count, stopped)
	}
}

// Places repoId keying on clusterId as evs's PUT by creator does.
func (self *gkmFixture) placeRepoBy(repoId sidecar.Id, clusterId string, creator sidecar.Id) {
	self.t.Helper()
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: clusterId, CreatorSidecarId: creator}).Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	self.put("meta-1", sidecar.EvsPlaceKey(repoId), placeBytes)
	self.put(clusterId, GkmEvsRepoKey(repoId), self.marshal(&protocol.EvsRepoObject{
		RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_KEYING,
		Format: 1, NetworkId: testId("network-a").Bytes(),
	}))
}

// The pending hints a sidecar's client holds that name no group: QD-638's, for a repo with no group yet.
func (self *gkmReconcilerWorld) formlessHints(sidecarId sidecar.Id) int {
	self.t.Helper()
	count := 0
	for _, hint := range self.fixture.hints(sidecarId) {
		if hint.GetKind() == protocol.GkmHintKind_GKM_HINT_PENDING && len(hint.GetGroupId()) == 0 {
			count += 1
		}
	}
	return count
}

// QD-638 (KEYS-M2-32): a repo a tagged sidecar placed, keying with no form, has pending go to the network's config
// writers, naming no group, at the state that first holds it and every PendingHintInterval while it stands so; a
// repo a member device placed takes none, since its creator forms its group; a repo not yet placed is watched and
// hinted once it is; and the agent's repo's first form ends its hints.
func TestGkmReconcilerHintsTheConfigWritersOfAKeyingRepoAnAgentCreated(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	configRepoId, agentRepoId, memberRepoId, laterRepoId := testId("repo-config"), testId("repo-agent"), testId("repo-member"), testId("repo-later")
	configWriter, agent, otherWriter := testId("sc-config-writer"), testId("sc-agent"), testId("sc-other-writer")
	for _, sidecarId := range []sidecar.Id{configWriter, agent, otherWriter} {
		fixture.clientOf(sidecarId)
	}
	fixture.placeRepoBy(agentRepoId, "meta-2", agent)
	fixture.placeRepoBy(memberRepoId, "meta-2", configWriter)
	// the config repo is the Genesis's, whose row the state adds while the rows hold none (QD-719, QD-762)
	rows := sidecartest.FakeGkmAuthRows(
		&protocol.AclRepo{RepoId: agentRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
		&protocol.AclRepo{RepoId: memberRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
		&protocol.AclRepo{RepoId: laterRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
	)
	sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(world.memberId, configWriter, otherWriter)
	rows.Sidecars = append(sidecarRows, &bridge.SidecarRow{SidecarId: agent.Bytes(), TagIds: [][]byte{testId("tag-agent").Bytes()}, AdmittedAt: 1})
	rows.Members = []*bridge.MemberRow{memberRow}
	view := world.log.Append(&sidecartest.FakeGkmAuthFixture{
		Rows:         rows,
		IdentityKeys: map[sidecar.Id][]byte{},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{configRepoId: {configWriter, otherWriter, agent}, agentRepoId: {agent, configWriter}},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{configRepoId: {configWriter}, agentRepoId: {agent}, memberRepoId: {configWriter}},
		ConfigRepoId: configRepoId,
	})
	repoIds := []sidecar.Id{configRepoId, agentRepoId, memberRepoId, laterRepoId}
	world.awaitState(view, func() { world.state.set(world.networkId, view, repoIds, nil) })
	if count := world.formlessHints(configWriter); count != 1 {
		t.Fatalf("the config writer's hints at the agent's repo's first sight: %d", count)
	}
	if count := world.formlessHints(otherWriter); count != 0 {
		t.Errorf("a member device that writes no config was hinted: %d", count)
	}
	if count := world.formlessHints(agent); count != 0 {
		t.Errorf("the agent was hinted: %d", count)
	}
	world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.PendingHintInterval) })
	if count := world.formlessHints(configWriter); count != 2 {
		t.Errorf("the config writer's hints one interval on: %d", count)
	}
	// the later repo is placed by the agent: watched since its row appeared, it is hinted at the next interval
	fixture.placeRepoBy(laterRepoId, "meta-2", agent)
	world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.PendingHintInterval) })
	if count := world.formlessHints(configWriter); count != 4 {
		t.Errorf("the config writer's hints once the later repo is placed: %d", count)
	}
	// a member device forms the agent's repos' groups: the hints stop
	fixture.fileForm(agentRepoId, "meta-2", 1, testId("group-agent"))
	fixture.fileForm(laterRepoId, "meta-2", 1, testId("group-later"))
	world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.PendingHintInterval) })
	world.awaitPass(func() { fixture.clock.Advance(world.reconciler.settings.PendingHintInterval) })
	if count := world.formlessHints(configWriter); count != 4 {
		t.Errorf("the config writer's hints once the groups stand: %d", count)
	}
}
