//go:build !sidecar_http

// A live repo's groups step with GkmGroupClient's own re-form on the fake gkm (owner decision 618; QD-1076; §19.10's
// groups row, §10.6's checks row, §10.8's after row): after a site loss the vault's owner's device runs
// sidecar.EvsRepo.ReseedPlace, its key client re-forming the group. The test's evs places repo/ keying, as a recovery
// does for a repo its projection lists live, and activates it once gkm holds the repo's newest GroupForm and its
// group's gen/1. gkm refuses the device's writes that gkmservice's route table takes for an active repo/ alone, the
// generation claim, the KeyPackage claims, the commits, the Welcomes, GroupInfo and a member's own RecoveryWrap, while
// repo/ reads anything else, as its checks row does; the form, the ladder and the deliveries' wraps, which it takes
// while keying too, pass. The step activates between the ladder and the rotation, and every member returns by its
// Welcome. The whole re-form the step sent before activate under its old order is refused at its claim, and the step
// run again finishes it from the keychain's record.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A clock over the world's time whose waits end at once, each recorded, so a step that waits shows it rather than
// hanging on the world's fake clock.
type evsReseedReformClock struct {
	*sidecartest.FakeClock
	stateLock sync.Mutex
	waits     []time.Duration
}

func (self *evsReseedReformClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.waits = append(self.waits, timeout)
	fired := make(chan time.Time, 1)
	fired <- self.Now()
	return fired
}

func (self *evsReseedReformClock) waited() []time.Duration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.waits)
}

// The vault's re-form world after its site loss, the test's evs holding the repo's repo/, and the owner's device a's
// evs client, whose key client is a's GkmGroupClient.
type evsReseedReformTest struct {
	t     *testing.T
	world *gkmReformWorld
	// the old group's statements, gen/1 and gen/2, as gkm held them before the site loss
	oldStatements []*bridge.Signed
	client        *sidecar.EvsClient
	evsClock      *evsReseedReformClock

	// how many gkm calls the store had seen at the site loss, the world's own before it
	lostAt int

	stateLock sync.Mutex
	repoState protocol.EvsRepoState
	// how many gkm calls the store had seen when activate took repo/ to active, -1 before
	activatedAt int
	// device a's gkm writes refused while repo/ read anything but active, by route
	refusedRoutes []string
}

func newEvsReseedReformTest(t *testing.T) *evsReseedReformTest {
	t.Helper()
	world := newGkmReformWorld(t)
	test := &evsReseedReformTest{
		t:             t,
		world:         world,
		oldStatements: slices.Clone(world.store.groupGenerations[world.oldGroupId]),
		evsClock:      &evsReseedReformClock{FakeClock: world.clock},
		activatedAt:   -1,
	}
	world.loseSite()
	_, test.lostAt = test.gkmGroup()
	owner := world.a
	identity := &sidecar.SidecarIdentity{SidecarId: owner.id, IdentityPublicKey: owner.signer.PublicKey()}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: sidecar.NewId(),
		EvsUrl:    "https://evs.example",
		Transport: test,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return "synthetic-evs-token", nil
		},
		Sign:     sidecar.EvsSignFunction(owner.signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      world.flows[owner].client,
		Store:    sidecartest.NewFakeStore().Root(),
		Config: func() sidecar.GkmAuthView {
			if tip := world.log.Tip(); tip != nil {
				return tip
			}
			return nil
		},
		Clock:    test.evsClock,
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	test.client = client
	test.gateActiveWrites()
	return test
}

// gkm's checks row (§10.6) over device a's writes: each of gkmservice's routes that take an active repo/ alone is
// answered 403 while repo/, as the test's evs holds it, reads anything else. Each route's calls come one at a time
// in a flow, so a hook planted again as it runs sees every one.
func (self *evsReseedReformTest) gateActiveWrites() {
	store := self.world.store
	label := self.world.a.label
	for _, route := range []string{"ClaimGeneration", "ClaimKeyPackage", "CommitEpoch", "UploadWelcome", "UploadGroupInfo", "UploadRecoveryWrap"} {
		var gate func()
		gate = func() {
			store.plantHook(label, route, gate)
			if self.repoObjectState() == protocol.EvsRepoState_EVS_REPO_ACTIVE {
				return
			}
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.refusedRoutes = append(self.refusedRoutes, route)
			}()
			store.refuseOnce(route, http.StatusForbidden)
		}
		store.plantHook(label, route, gate)
	}
}

// repo/'s state as the test's evs holds it.
func (self *evsReseedReformTest) repoObjectState() protocol.EvsRepoState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.repoState
}

// The gkm writes the gate refused, in order.
func (self *evsReseedReformTest) refused() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.refusedRoutes)
}

// Whether gkm holds the repo's newest GroupForm and its group's gen/1, what activate reads (§11.12's activate row), and
// how many calls the store has seen.
func (self *evsReseedReformTest) gkmGroup() (ready bool, callCount int) {
	store := self.world.store
	store.stateLock.Lock()
	defer store.stateLock.Unlock()
	callCount = len(store.calls)
	forms := store.repoForms[self.world.repoId]
	if len(forms) == 0 {
		return false, callCount
	}
	form := &protocol.GroupForm{}
	if err := proto.Unmarshal(forms[len(forms)-1].GetBody(), form); err != nil {
		return false, callCount
	}
	groupId, err := sidecar.IdFromBytes(form.GetGroupId())
	if err != nil {
		return false, callCount
	}
	return 0 < len(store.groupGenerations[groupId]), callCount
}

// The store's calls since the site loss, "<label>:<route>", before and after activate took repo/ to active.
func (self *evsReseedReformTest) callsAroundActivate() (before []string, after []string) {
	self.t.Helper()
	activatedAt := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.activatedAt
	}()
	if activatedAt < 0 {
		self.t.Fatal("activate never took repo/ to active")
	}
	store := self.world.store
	store.stateLock.Lock()
	defer store.stateLock.Unlock()
	return slices.Clone(store.calls[self.lostAt:activatedAt]), slices.Clone(store.calls[activatedAt:])
}

func (self *evsReseedReformTest) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	self.serve(recorder, request)
	return recorder.Result(), nil
}

// evs's answers, as §11.12's rows give them: the place creates repo/ keying and answers a retry 200; activate takes
// keying to active once gkm holds the newest GroupForm and gen/1, else 409 GROUP_NOT_READY, and answers active 200.
func (self *evsReseedReformTest) serve(writer http.ResponseWriter, request *http.Request) {
	repoPath := "/evs/v1/repos/" + sidecar.EvsKeyId(self.world.repoId)
	code := protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED
	switch {
	case request.Method == http.MethodPut && request.URL.Path == repoPath:
		self.stateLock.Lock()
		if self.repoState == protocol.EvsRepoState_EVS_REPO_STATE_UNSPECIFIED {
			self.repoState = protocol.EvsRepoState_EVS_REPO_KEYING
		}
		self.stateLock.Unlock()
	case request.Method == http.MethodPost && request.URL.Path == repoPath+"/activate":
		ready, callCount := self.gkmGroup()
		self.stateLock.Lock()
		switch {
		case self.repoState == protocol.EvsRepoState_EVS_REPO_KEYING && ready:
			self.repoState = protocol.EvsRepoState_EVS_REPO_ACTIVE
			self.activatedAt = callCount
		case self.repoState == protocol.EvsRepoState_EVS_REPO_KEYING:
			code = protocol.EvsRefusalCode_EVS_REFUSAL_GROUP_NOT_READY
		}
		self.stateLock.Unlock()
	default:
		self.t.Errorf("a request the groups step of a live repo never sends: %s %s", request.Method, request.URL.Path)
		code = protocol.EvsRefusalCode_EVS_REFUSAL_INVALID
	}
	if code != protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
		body, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: code})
		writer.WriteHeader(http.StatusConflict)
		writer.Write(body)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

// Each member device syncs, follows the form to the re-formed group, joins it by its Welcome at epoch 1 and
// generation 3, and reads every generation, raising no alarm.
func (self *evsReseedReformTest) requireMembersBack(newGroupId sidecar.Id, devices ...*gkmWorldDevice) {
	self.t.Helper()
	world := self.world
	for _, device := range devices {
		flow := world.flows[device]
		if err := flow.client.SyncRepo(world.ctx, world.repoId); err != nil {
			self.t.Fatalf("%s syncs after the re-form: %v", device.label, err)
		}
		joined, err := flow.client.JoinWelcomes(world.ctx)
		if err != nil || !slices.Contains(joined, world.repoId) {
			self.t.Fatalf("%s joins the re-formed group: %v %v", device.label, joined, err)
		}
		groupId, epoch, generation, err := flow.client.TestPins(world.repoId)
		if err != nil || groupId != newGroupId || epoch != 1 || generation != 3 {
			self.t.Errorf("%s in the re-formed group: epoch %d, generation %d, %v", device.label, epoch, generation, err)
		}
		for number := uint64(1); number <= 3; number += 1 {
			if key, err := flow.client.RepoKey(world.ctx, world.repoId, number); err != nil || key.Generation() != number {
				self.t.Errorf("%s reads generation %d after the re-form: %v", device.label, number, err)
			}
		}
		if len(flow.alarms) != 0 {
			self.t.Errorf("%s alarmed: %+v", device.label, flow.alarms[0])
		}
	}
}

// The step for a live repo, its re-form GkmGroupClient's (QD-1076): repo/ goes active after the form and the ladder
// land and before any write of the rotation, nothing gkm takes for an active repo/ alone is sent before then, so
// nothing is refused; the new group's ladder is the old one byte for byte, generation 3 names the new group, epoch 1
// adds every reader, a member that reads by its recovery code keeps generation 3's RecoveryWrap, and every member
// returns by its Welcome.
func TestEvsReseedPlaceActivatesALiveRepoBetweenItsLadderAndItsRotation(t *testing.T) {
	test := newEvsReseedReformTest(t)
	world := test.world
	placed, err := test.client.Repo(world.repoId).ReseedPlace(world.ctx, nil)
	if err != nil {
		t.Fatalf("the groups step: %v", err)
	}
	newGroupId := world.formedGroupId()
	if placed.Deleted || placed.Mended || placed.PlacedByAnother || placed.GroupId != newGroupId || newGroupId == world.oldGroupId {
		t.Fatalf("placed %+v, the repo's newest group %s", placed, newGroupId)
	}
	if state := test.repoObjectState(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Fatalf("repo/ %s", state)
	}
	label := world.a.label + ":"
	before, after := test.callsAroundActivate()
	for _, route := range []string{"Reform", "UploadLadder"} {
		if !slices.Contains(before, label+route) || slices.Contains(after, label+route) {
			t.Errorf("%s does not come before activate alone: %v, then %v", route, before, after)
		}
	}
	for _, route := range []string{"UploadRecoveryWraps", "ClaimGeneration", "ClaimKeyPackage", "CommitEpoch", "UploadWelcome"} {
		if slices.Contains(before, label+route) || !slices.Contains(after, label+route) {
			t.Errorf("%s does not come after activate alone: %v, then %v", route, before, after)
		}
	}
	if refused := test.refused(); len(refused) != 0 {
		t.Errorf("gkm refused %v", refused)
	}
	if waited := test.evsClock.waited(); len(waited) != 0 {
		t.Errorf("the step waited %v", waited)
	}

	statements := world.store.groupGenerations[newGroupId]
	if len(statements) != 3 || !proto.Equal(statements[0], test.oldStatements[0]) || !proto.Equal(statements[1], test.oldStatements[1]) {
		t.Fatalf("the new group holds %d generations, or its ladder is not the old one's", len(statements))
	}
	gen3 := &protocol.GenRotate{}
	if err := proto.Unmarshal(statements[2].GetBody(), gen3); err != nil || !bytes.Equal(gen3.GetGroupId(), newGroupId.Bytes()) {
		t.Errorf("generation 3 does not name the new group: %v", err)
	}
	if epochs := world.store.groupEpochs[newGroupId]; len(epochs) != 2 || epochs[1].GetHeader().GetGeneration() != 3 {
		t.Fatalf("the new group's epochs: %d", len(epochs))
	}
	if labels := world.rosterLabels(world.engineGroup2(world.a, newGroupId)); strings.Join(labels, "") != "abcpx" {
		t.Errorf("the new tree: %v", labels)
	}
	reply, err := world.flows[world.a].api.RecoveryWraps(world.ctx, world.sharedId, false)
	if err != nil || len(reply.GetWraps()) != 1 || reply.GetWraps()[0].GetGeneration() != 3 {
		t.Errorf("the recovery wraps of the member who reads by its code: %v %v", reply.GetWraps(), err)
	}
	test.requireMembersBack(newGroupId, world.b, world.c, world.x)
}

// QD-1076's failure as GkmGroupClient met it: the step's old order, the whole re-form before activate, as a re-form
// that drops Reseed sends it, lands the form, the ladder and the rotation's wraps while repo/ reads keying, and gkm
// refuses the rotation's claim, so the step's error is the re-form's and nothing activates. The step run again in its
// own order resumes the re-form from the keychain's record, posting no second form or ladder: its first call answers
// at once, activate takes repo/ to active, and its second call claims generation 3 and adds every reader, who return.
func TestEvsReseedPlaceFinishesTheWholeReFormItsOldOrderLeftKeying(t *testing.T) {
	test := newEvsReseedReformTest(t)
	world := test.world
	owner := world.flows[world.a]
	repo := test.client.Repo(world.repoId)
	whole := func(ctx context.Context, args *sidecar.GkmReformArgs) (sidecar.Id, error) {
		return owner.client.ReformGroup(ctx, &sidecar.GkmReformArgs{RepoId: args.RepoId})
	}
	placed, err := repo.ReseedPlace(world.ctx, &sidecar.EvsReseedPlaceArgs{ReformGroup: whole})
	if !errors.Is(err, sidecar.ErrGkmWait) || placed == nil || placed.GroupId != (sidecar.Id{}) {
		t.Fatalf("the whole re-form before activate: %+v, %v", placed, err)
	}
	if refused := test.refused(); !slices.Equal(refused, []string{"ClaimGeneration"}) {
		t.Errorf("gkm refused %v, want the rotation's claim", refused)
	}
	if state := test.repoObjectState(); state != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Errorf("after the whole re-form before activate repo/ %s", state)
	}
	newGroupId := world.formedGroupId()
	if generations := world.store.newestGeneration(newGroupId); generations != 2 {
		t.Errorf("after the refused claim the new group holds %d generations", generations)
	}

	placed, err = repo.ReseedPlace(world.ctx, nil)
	if err != nil || placed.GroupId != newGroupId {
		t.Fatalf("the step run again: %+v, %v", placed, err)
	}
	if state := test.repoObjectState(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("after the step run again repo/ %s", state)
	}
	if forms, ladders := world.store.callCount("Reform"), world.store.callCount("UploadLadder"); forms != 1 || ladders != 1 {
		t.Errorf("the re-form posted %d forms and %d ladders, want one each", forms, ladders)
	}
	_, after := test.callsAroundActivate()
	if !slices.Contains(after, world.a.label+":ClaimGeneration") {
		t.Errorf("no claim after activate: %v", after)
	}
	if refused := test.refused(); !slices.Equal(refused, []string{"ClaimGeneration"}) {
		t.Errorf("after the step run again gkm had refused %v, the old order's claim alone", refused)
	}
	if generations := world.store.newestGeneration(newGroupId); generations != 3 {
		t.Errorf("the new group holds %d generations", generations)
	}
	test.requireMembersBack(newGroupId, world.b, world.c)
}
