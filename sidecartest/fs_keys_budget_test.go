package sidecartest

// FS-117's gkm legs on T2 (KEYS-M2-30; §10.6's checks row, §11.13; FI-3, FI-14): gkm's engine on the real process
// budget and governor, evsservice's, over fake drive counters on one fake clock, its bucket empty and P0 taking the
// refill. A storm of REMOVE rotations, each gate's claim and staged deliveries, issues on arrival with the clock
// standing still, so the budget adds nothing to a gate's close-to-reopen time; a rotation whose claim states REMOVE
// while gkm's state shows no drop since gen/<g-1> is charged as P1 and issues nothing while P0 takes the refill; once
// the storm ends the P1 claim goes through within the governor's next intervals.
//
// gkmservice's budget_test.go holds the per-write classes on a fake budget: the commits a state's drop makes Removes
// under a closed budget, LATE deliveries and key upkeep as P1, the shred's P0 and the sweeps' unfunded P2. The rest
// of FS-117, its 24 h of 100 Teams, the governor killed and {nvb_<set>} lost, is the budget's own (EVSB).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// How long a step that waits on another goroutine may take before the test fails: a guard, never the proof.
const fsKeysBudgetStepTimeout = 30 * time.Second

// The busiest drive's written bytes, moved by hand.
type fsKeysBudgetCounters struct {
	stateLock sync.Mutex
	written   uint64
}

func (self *fsKeysBudgetCounters) ReadDriveCounters(ctx context.Context, clusterId string) (*evsservice.DriveCounterReading, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &evsservice.DriveCounterReading{Drives: []*evsservice.DriveCounter{{DriveId: "0-0-0", WrittenByteCount: self.written}}}, nil
}

func (self *fsKeysBudgetCounters) write(byteCount uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.written += byteCount
}

// What gkm's newest verified state holds here: every sidecar a member device writing every repo, the log at
// position 10, and per repo whether a holder dropped since any pin.
type fsKeysBudgetState struct {
	stateLock      sync.Mutex
	identityKeys   map[sidecar.Id][]byte
	droppedRepoIds map[sidecar.Id]bool
}

func (self *fsKeysBudgetState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *fsKeysBudgetState) Sidecar(principal *sidecar.Principal, sidecarId sidecar.Id) (*gkmservice.GkmSidecarFacts, gkmservice.GkmAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	identityKey, ok := self.identityKeys[sidecarId]
	if !ok {
		return nil, gkmservice.GkmAuthDenied
	}
	digest := sha256.Sum256(sidecarId.Bytes())
	var memberId sidecar.Id
	copy(memberId[:], digest[:])
	return &gkmservice.GkmSidecarFacts{IdentityPublicKey: identityKey, MemberDevice: true, MemberId: &memberId}, gkmservice.GkmAuthAllowed
}

func (self *fsKeysBudgetState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, right sidecar.AclEvsRights, now time.Time) gkmservice.GkmAuthAnswer {
	if right == sidecar.AclEvsAdmin {
		return gkmservice.GkmAuthDenied
	}
	return gkmservice.GkmAuthAllowed
}

func (self *fsKeysBudgetState) Reads(principal *sidecar.Principal, repoId sidecar.Id, sidecarId sidecar.Id, now time.Time) gkmservice.GkmAuthAnswer {
	return gkmservice.GkmAuthAllowed
}

func (self *fsKeysBudgetState) PendingTargets(principal *sidecar.Principal, sidecarId sidecar.Id, now time.Time) ([]*gkmservice.GkmPendingTarget, gkmservice.GkmAuthAnswer) {
	return nil, gkmservice.GkmAuthAllowed
}

func (self *fsKeysBudgetState) RepoReaders(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	return nil, gkmservice.GkmAuthAllowed
}

func (self *fsKeysBudgetState) RepoWriters(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	return nil, gkmservice.GkmAuthAllowed
}

func (self *fsKeysBudgetState) CheckPin(principal *sidecar.Principal, pin *bridge.AuthPin) gkmservice.GkmAuthAnswer {
	if 10 < pin.GetVersion() {
		return gkmservice.GkmAuthUnknown
	}
	return gkmservice.GkmAuthAllowed
}

func (self *fsKeysBudgetState) DelegationReads(principal *sidecar.Principal, repoId sidecar.Id, delegationId []byte, now time.Time) gkmservice.GkmAuthAnswer {
	return gkmservice.GkmAuthDenied
}

func (self *fsKeysBudgetState) LateHolders(principal *sidecar.Principal, repoId sidecar.Id, recipient string, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	return nil, gkmservice.GkmAuthAllowed
}

func (self *fsKeysBudgetState) HoldersDropped(principal *sidecar.Principal, repoId sidecar.Id, pin *bridge.AuthPin, since time.Time, now time.Time) gkmservice.GkmAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.droppedRepoIds[repoId] {
		return gkmservice.GkmAuthAllowed
	}
	return gkmservice.GkmAuthDenied
}

// The process budget, telling the test when a P1 admission starts to wait, so the test knows it is queued.
type fsKeysObservedBudget struct {
	sidecar.WriteBudget
	admitting chan struct{}
}

func (self *fsKeysObservedBudget) AdmitP1(ctx context.Context, clusterId string, networkId connect.Id, cost sidecar.WriteCost) (sidecar.WriteGrant, error) {
	self.admitting <- struct{}{}
	return self.WriteBudget.AdmitP1(ctx, clusterId, networkId, cost)
}

// One writer device: its identity key signs its statements.
type fsKeysBudgetDevice struct {
	sidecarId  sidecar.Id
	privateKey ed25519.PrivateKey
}

func (self *fsKeysBudgetDevice) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.privateKey, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// A repo with its group at generation 1, as KF1 left it.
type fsKeysBudgetGroup struct {
	repoId  sidecar.Id
	groupId sidecar.Id
	key1    *sidecar.EvsRepoKey
	token   string
}

type fsKeysBudgetWorld struct {
	t         *testing.T
	ctx       context.Context
	clock     *FakeClock
	host      *FakeHost
	counters  *fsKeysBudgetCounters
	settings  *evsservice.BudgetLoopSettings
	loop      *evsservice.BudgetLoop
	budget    *fsKeysObservedBudget
	state     *fsKeysBudgetState
	engine    *gkmservice.GkmEngine
	networkId connect.Id
	writer    *fsKeysBudgetDevice
	reader    sidecar.Id
	readerKey []byte
}

// The governor over a bucket at zero, one process budget whose first tick has passed, and gkm on it.
func newFsKeysBudgetWorld(t *testing.T) *fsKeysBudgetWorld {
	ctx := t.Context()
	clock := NewFakeClock(DefaultClockStart())
	host := NewFakeHost(ctx, clock, nil, nil, nil)
	RegisterEvsTwins(host.Redis)
	settings := evsservice.DefaultBudgetLoopSettings()
	// weights reread once an hour, so the only timers an interval waits for are the process's ticks
	settings.Budget.WeightRefreshInterval = time.Hour
	saved := &evsservice.GovernorState{
		Seq:             1,
		TimeMs:          clock.Now().Add(-settings.Budget.Interval).UnixMilli(),
		BucketByteCount: 0,
		Calibration:     1,
	}
	if err := evsservice.SaveGovernorState(ctx, host.Redis, settings.Budget, "meta-1", saved); err != nil {
		t.Fatal(err)
	}
	counters := &fsKeysBudgetCounters{}
	loop, err := evsservice.NewBudgetLoop(host.ServiceHost(), "meta-1", counters, nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	world := &fsKeysBudgetWorld{
		t:         t,
		ctx:       ctx,
		clock:     clock,
		host:      host,
		counters:  counters,
		settings:  settings,
		loop:      loop,
		state:     &fsKeysBudgetState{identityKeys: map[sidecar.Id][]byte{}, droppedRepoIds: map[sidecar.Id]bool{}},
		networkId: connect.NewId(),
	}
	loop.Step(ctx)
	next := clock.Now().Add(settings.Budget.Interval)
	before := world.timerCount(next)
	client, err := evsservice.NewWriteBudget(ctx, host.ServiceHost(), []string{"meta-1"}, settings.Budget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	world.awaitTimers(next, before+1)
	world.interval(0)
	world.budget = &fsKeysObservedBudget{WriteBudget: client, admitting: make(chan struct{}, 16)}
	serviceHost := host.ServiceHost()
	serviceHost.Budget = world.budget
	host.Gates.OpenService(sidecar.ServiceGateGkm, world.networkId)
	engine, err := gkmservice.NewGkmEngine(ctx, serviceHost, nil, &gkmservice.GkmEngineDeps{AuthState: world.state})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	world.engine = engine
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	world.writer = &fsKeysBudgetDevice{sidecarId: sidecar.NewId(), privateKey: privateKey}
	world.state.identityKeys[world.writer.sidecarId] = publicKey
	world.reader = sidecar.NewId()
	readerSigned, _, err := sidecar.NewGkmReaderKey(world.reader, clock.Now(), clock.Now().Add(6*24*time.Hour), world.writer.sign)
	if err != nil {
		t.Fatal(err)
	}
	body := &protocol.ReaderKey{}
	if err := proto.Unmarshal(readerSigned.GetBody(), body); err != nil {
		t.Fatal(err)
	}
	world.readerKey = body.GetXwingPublicKey()
	return world
}

// The timers pending at exactly at.
func (self *fsKeysBudgetWorld) timerCount(at time.Time) int {
	pending, _ := self.clock.WatchTimers()
	count := 0
	for _, pendingAt := range pending {
		if pendingAt.Equal(at) {
			count += 1
		}
	}
	return count
}

// Returns once count timers are pending at exactly at: a process re-arms its interval's timer only after its tick.
func (self *fsKeysBudgetWorld) awaitTimers(at time.Time, count int) {
	self.t.Helper()
	for {
		pending, added := self.clock.WatchTimers()
		found := 0
		for _, pendingAt := range pending {
			if pendingAt.Equal(at) {
				found += 1
			}
		}
		if count <= found {
			return
		}
		select {
		case <-added:
		case <-self.ctx.Done():
			self.t.Fatal(self.ctx.Err())
		}
	}
}

// One interval: the drives write byteCount, the process ticks at its end, and the governor steps.
func (self *fsKeysBudgetWorld) interval(byteCount uint64) *evsservice.WriteBudgetAllowance {
	self.t.Helper()
	self.counters.write(byteCount)
	next := self.clock.Now().Add(2 * self.settings.Budget.Interval)
	before := self.timerCount(next)
	self.clock.Advance(self.settings.Budget.Interval)
	self.awaitTimers(next, before+1)
	return self.loop.Step(self.ctx)
}

// The refill r in drive bytes an interval.
func (self *fsKeysBudgetWorld) refill() uint64 {
	budget := self.settings.Budget
	return uint64(budget.RefillDwpd * float64(budget.DriveByteCount) / (24 * time.Hour).Seconds() * budget.Interval.Seconds())
}

// Places a repo on the first cluster, active, with its group's form and generation 1, as evs and KF1 left them; a
// drop since generation 1 shows in gkm's state when dropped.
func (self *fsKeysBudgetWorld) newGroup(dropped bool) *fsKeysBudgetGroup {
	self.t.Helper()
	group := &fsKeysBudgetGroup{repoId: sidecar.NewId(), groupId: sidecar.NewId()}
	cluster, err := self.host.Blobs.FirstCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	place, err := (&sidecar.EvsRepoPlace{ClusterId: cluster.ClusterId(), CreatorSidecarId: self.writer.sidecarId}).Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	repoObject, _ := proto.Marshal(&protocol.EvsRepoObject{RepoId: group.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Format: 1, NetworkId: sidecar.Id(self.networkId).Bytes()})
	formBody, _ := proto.Marshal(&protocol.GroupForm{RepoId: group.repoId.Bytes(), GroupId: group.groupId.Bytes(), Generation: 1})
	form, _ := proto.Marshal(&bridge.Signed{Body: formBody, Type: uint32(bridge.SignedType_SIGNED_GROUP_FORM)})
	groupOwner, _ := proto.Marshal(&protocol.GkmGroupOwner{RepoId: group.repoId.Bytes(), NetworkId: sidecar.Id(self.networkId).Bytes()})
	key1, rotate1, err := sidecar.NewGkmFirstGeneration(group.repoId, group.groupId, &sidecar.GkmGenerationArgs{
		Cause:         sidecar.GkmCauseRequest,
		Auth:          fsKeysBudgetPin(10),
		Time:          self.clock.Now(),
		HoldersSha256: bytes.Repeat([]byte{1}, 32),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed1, err := sidecar.SignGenRotate(rotate1, self.writer.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	generation1, _ := proto.Marshal(signed1)
	for key, body := range map[string][]byte{
		sidecar.EvsPlaceKey(group.repoId):             place,
		gkmservice.GkmEvsRepoKey(group.repoId):        repoObject,
		gkmservice.GkmFormKey(group.repoId, 1):        form,
		gkmservice.GkmGenerationKey(group.groupId, 1): generation1,
		// the group's owner marker, which every group route resolves through (DESIGN-DETAILS 6.2.2)
		gkmservice.GkmGroupOwnerKey(group.groupId): groupOwner,
	} {
		if _, err := cluster.PutIfNoneMatch(self.ctx, key, body, nil); err != nil {
			self.t.Fatal(err)
		}
	}
	group.key1 = key1
	connectSidecarId := connect.Id(self.writer.sidecarId)
	group.token = self.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: self.networkId,
		ClientId:  connect.NewId(),
		SidecarId: &connectSidecarId,
		Audience:  gkmservice.GkmAudience,
		Scopes:    []string{"repo:" + group.repoId.String() + ":rw"},
		IssuedAt:  self.clock.Now(),
		ExpiresAt: self.clock.Now().Add(15 * time.Minute),
	})
	self.state.stateLock.Lock()
	self.state.droppedRepoIds[group.repoId] = dropped
	self.state.stateLock.Unlock()
	return group
}

// A synthetic pin of position version.
func fsKeysBudgetPin(version uint64) *bridge.AuthPin {
	chain := sha256.Sum256([]byte("chain " + strconv.FormatUint(version, 10)))
	return &bridge.AuthPin{Version: version, Chain: chain[:]}
}

// Generation 2 of group, stating cause, and its staged ReaderWrap to the reader.
func (self *fsKeysBudgetWorld) rotation(group *fsKeysBudgetGroup, cause sidecar.GkmCause) (*sidecar.EvsRepoKey, []byte, []byte) {
	self.t.Helper()
	key2, rotate2, err := group.key1.NextGeneration(&sidecar.GkmGenerationArgs{
		Cause:         cause,
		Auth:          fsKeysBudgetPin(10),
		Time:          self.clock.Now(),
		HoldersSha256: bytes.Repeat([]byte{2}, 32),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed2, err := sidecar.SignGenRotate(rotate2, self.writer.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	claim, _ := proto.Marshal(signed2)
	delivery, err := sidecar.SealGkmDelivery(key2, &sidecar.GkmDeliveryArgs{
		GroupId:            group.groupId,
		Type:               sidecar.GkmWrapTypeReader,
		Recipient:          self.reader.Bytes(),
		RecipientPublicKey: self.readerKey,
		Kind:               sidecar.GkmDeliveryStaged,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signedDelivery, err := sidecar.SignGkmDelivery(delivery, sidecar.GkmWrapTypeReader, self.writer.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	staged, _ := proto.Marshal(signedDelivery)
	return key2, claim, staged
}

// One request through the engine under ctx: its status and body.
func (self *fsKeysBudgetWorld) serve(ctx context.Context, path string, token string, body []byte) (int, []byte) {
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder.Code, recorder.Body.Bytes()
}

// Stages group's delivery of generation 2: the batch's one status.
func (self *fsKeysBudgetWorld) stage(ctx context.Context, group *fsKeysBudgetGroup, key2 *sidecar.EvsRepoKey, staged []byte) int {
	self.t.Helper()
	path := "/gkm/groups/" + sidecar.EvsKeyId(group.groupId) + "/wraps/2/" + hex.EncodeToString(key2.Commitment()[:8])
	batch, _ := proto.Marshal(&protocol.GkmWrapBatch{Deliveries: [][]byte{staged}})
	code, body := self.serve(ctx, path, group.token, batch)
	if code != http.StatusOK {
		return code
	}
	reply := &protocol.GkmWrapBatchReply{}
	if err := proto.Unmarshal(body, reply); err != nil {
		self.t.Fatal(err)
	}
	return int(reply.GetResults()[0].GetStatus())
}

// Claims group's generation 2: the status.
func (self *fsKeysBudgetWorld) claim(ctx context.Context, group *fsKeysBudgetGroup, claim []byte) int {
	code, _ := self.serve(ctx, "/gkm/groups/"+sidecar.EvsKeyId(group.groupId)+"/gen/2", group.token, claim)
	return code
}

// Whether group's generation 2 is stored.
func (self *fsKeysBudgetWorld) claimed(group *fsKeysBudgetGroup) bool {
	cluster, _ := self.host.Blobs.FirstCluster()
	_, err := cluster.Head(self.ctx, gkmservice.GkmGenerationKey(group.groupId, 2))
	return err == nil
}

// FS-117's gkm legs: while P0 holds the bucket empty, every REMOVE rotation's claim and staged delivery issues on
// arrival with the clock standing still, its bytes reported by kind; a rotation whose claim says REMOVE with no drop
// in gkm's state waits as P1 and writes nothing; once the storm ends it goes through.
func TestFsKeysBudgetRemoveRotationsIssueOnArrivalAndMislabeledOnesWait(t *testing.T) {
	world := newFsKeysBudgetWorld(t)
	refill := world.refill()
	// the storm's other safety work, revocations at twice the refill, which the drives write: P0 alone, holding the
	// bucket and T at zero
	storm := func() *evsservice.WriteBudgetAllowance {
		world.budget.IssueP0(world.ctx, "meta-1", sidecar.WriteP0KindRevocation, int64(2*refill))
		return world.interval(2 * refill)
	}
	var allowance *evsservice.WriteBudgetAllowance
	for range 4 {
		allowance = storm()
	}
	if allowance.TotalByteCount != 0 || allowance.BucketByteCount != 0 {
		t.Fatalf("T %d and B %d while P0 takes twice the refill", allowance.TotalByteCount, allowance.BucketByteCount)
	}

	stormStart := world.clock.Now()
	prices := gkmservice.DefaultGkmWritePrices()
	removed := []*fsKeysBudgetGroup{}
	for range 3 {
		group := world.newGroup(true)
		key2, claim, staged := world.rotation(group, sidecar.GkmCauseRemove)
		if status := world.stage(world.ctx, group, key2, staged); status != http.StatusCreated {
			t.Fatalf("a REMOVE rotation's staged delivery in the storm: %d", status)
		}
		if status := world.claim(world.ctx, group, claim); status != http.StatusCreated {
			t.Fatalf("a REMOVE rotation's claim in the storm: %d", status)
		}
		removed = append(removed, group)
	}
	if !world.clock.Now().Equal(stormStart) {
		t.Fatal("a P0 write waited on the clock")
	}
	select {
	case <-world.budget.admitting:
		t.Fatal("a REMOVE rotation's write queued as P1")
	default:
	}

	// a claim stating REMOVE where gkm's state shows no drop since gen/1: P1, which waits while P0 takes the refill
	mislabeled := world.newGroup(false)
	_, mislabeledClaim, _ := world.rotation(mislabeled, sidecar.GkmCauseRemove)
	waitCtx, cancelWait := context.WithCancel(world.ctx)
	defer cancelWait()
	statuses := make(chan int, 1)
	go func() {
		statuses <- world.claim(waitCtx, mislabeled, mislabeledClaim)
	}()
	select {
	case <-world.budget.admitting:
	case <-time.After(fsKeysBudgetStepTimeout):
		t.Fatal("the mislabeled claim never reached the budget")
	}
	allowance = storm()
	if allowance.TotalByteCount != 0 {
		t.Fatalf("T %d while the storm lasts", allowance.TotalByteCount)
	}
	// the process reports what it issued at its tick: the storm's rotations as P0 of kind rotation
	wantRotation := float64(3 * (prices.CreateByteCount + prices.CreateByteCount))
	if issued := world.host.Metrics.Value("urnetwork_evs_budget_issued_bytes_total", "meta-1", "p0", string(sidecar.WriteP0KindRotation)); issued != wantRotation {
		t.Errorf("P0 rotation bytes issued %v, want %v", issued, wantRotation)
	}
	select {
	case status := <-statuses:
		t.Fatalf("the mislabeled claim answered %d while P0 took the refill", status)
	default:
	}
	if world.claimed(mislabeled) {
		t.Fatal("the mislabeled claim was written during the storm")
	}

	// the storm ends: the governor's next intervals give P1 a share, and the waiting claim goes through
	var status int
	admitted := false
	for range 4 {
		world.interval(0)
		select {
		case status = <-statuses:
			admitted = true
		default:
		}
		if admitted {
			break
		}
	}
	if !admitted {
		select {
		case status = <-statuses:
		case <-time.After(fsKeysBudgetStepTimeout):
			t.Fatal("the mislabeled claim never went through after the storm")
		}
	}
	if status != http.StatusCreated || !world.claimed(mislabeled) {
		t.Fatalf("the mislabeled claim after the storm: %d", status)
	}
	world.interval(0)
	if issued := world.host.Metrics.Value("urnetwork_evs_budget_issued_bytes_total", "meta-1", "p1", ""); issued != float64(prices.CreateByteCount) {
		t.Errorf("P1 bytes issued %v after the storm, want the claim's %d", issued, prices.CreateByteCount)
	}
	for _, group := range removed {
		if !world.claimed(group) {
			t.Error("a REMOVE rotation's claim is not stored")
		}
	}
}
