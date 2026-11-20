//go:build !sidecar_http

// A re-form's finishing phase resumed at its re-former's own syncs (QD-1143; §10.8's paragraph on a repo re-seeded as
// deleted, §19.10's groups row; KEYS-M2-25): after a site loss the vault, deleted inside its restore window, is placed
// as deleted by its owner's device a (sidecar.EvsRepo.ReseedPlace, a's GkmGroupClient re-forming), which leaves the
// new group's form, epoch 0 and ladder at gkm and the keychain's re-form record at its finishing phase. While every
// device's state shows the vault deleted, a's syncs send nothing more. Once it is restored, by `ur evs restore` on a
// (EvsRepo.Restore) or by a RepoRestore another admin's device filed and taskworker's reconciler applied with no device
// involved, a's next sync rotates to generation 3 with every delivery, the RecoveryWrap of the member who reads by its
// code among them, and adds every reader, who return by their Welcomes. While gkm refuses the rotation's writes, repo/
// still deleted, a's syncs try at most once a ReformResumeInterval, a restart included, and a rotation draft a refused
// try left is drawn afresh once it is older than ReformDraftMaxAge, as is one a rotation of the old group left. A sync
// drafts no re-form: none where no record stands, none of a record cut short before its ladder stood. And a live repo's
// groups step whose second call comes after a sync finished its re-form drafts no second one, nor does the step run
// again after the group is finished.

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

// Device a's evs client in a re-form world, over transport, its key client a's GkmGroupClient and its state the log's
// tip, filing statements through fileStatement.
func newGkmReformResumeEvsClient(t *testing.T, world *gkmReformWorld, transport http.RoundTripper, fileStatement sidecar.EvsFileStatementFunction, clock sidecar.Clock) *sidecar.EvsClient {
	t.Helper()
	owner := world.a
	identity := &sidecar.SidecarIdentity{SidecarId: owner.id, IdentityPublicKey: owner.signer.PublicKey()}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: sidecar.NewId(),
		EvsUrl:    "https://evs.example",
		Transport: transport,
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
		FileStatement: fileStatement,
		Clock:         clock,
		Log:           sidecar.NewNoopLogger(),
		Settings:      sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// The vault's re-form world after its site loss with the vault deleted in every device's state, the test's evs
// holding repo/ as a recovery with reseed on places it, and device a's evs client.
type gkmReformResumeTest struct {
	t          *testing.T
	world      *gkmReformWorld
	client     *sidecar.EvsClient
	evsClock   *evsReseedReformClock
	deletionId []byte

	stateLock sync.Mutex
	repoState protocol.EvsRepoState
	// evs's projection holds the vault's RepoRestore
	restoreProjected bool
	// each request evs got, its method and path
	requests []string
	// device a's gkm writes refused while repo/ read a state their route does not take, in order
	refusedRoutes []string
}

func newGkmReformResumeTest(t *testing.T) *gkmReformResumeTest {
	t.Helper()
	world := newGkmReformWorld(t)
	test := &gkmReformResumeTest{
		t:          t,
		world:      world,
		evsClock:   &evsReseedReformClock{FakeClock: world.clock},
		deletionId: sidecar.NewId().Bytes(),
	}
	// the owner's RepoDelete, inside its restore window, in every device's state; then the site is lost
	world.repo.Deletion = &protocol.AclRepoDeletionRow{
		DeletionId: test.deletionId, DeletedAt: world.nextPosition(), DeletedTimeMs: world.now.UnixMilli(), Signer: world.a.id.Bytes(),
	}
	world.stateFor()
	world.loseSite()
	test.client = newGkmReformResumeEvsClient(t, world, test, test.fileStatement, test.evsClock)
	test.gateWrites()
	return test
}

// gkm's checks row over device a's writes (§10.6; gkmservice's route table): the generation claim, the KeyPackage
// claims, the commits, the Welcomes, GroupInfo and a member's own RecoveryWrap are taken for an active repo/ alone,
// the staged wraps and RecoveryWraps for an active or keying one, and the form and the ladder, which pass here, for a
// deleted one too while reseed is on. Each other write is answered 403. Each route's calls come one at a time in a
// flow, so a hook planted again as it runs sees every one.
func (self *gkmReformResumeTest) gateWrites() {
	store := self.world.store
	label := self.world.a.label
	keyingRoutes := []string{"UploadWraps", "UploadRecoveryWraps"}
	activeRoutes := []string{"ClaimGeneration", "ClaimKeyPackage", "CommitEpoch", "UploadWelcome", "UploadGroupInfo", "UploadRecoveryWrap"}
	for _, route := range append(slices.Clone(keyingRoutes), activeRoutes...) {
		takesKeying := slices.Contains(keyingRoutes, route)
		var gate func()
		gate = func() {
			store.plantHook(label, route, gate)
			state := self.repoObjectState()
			if state == protocol.EvsRepoState_EVS_REPO_ACTIVE || takesKeying && state == protocol.EvsRepoState_EVS_REPO_KEYING {
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
func (self *gkmReformResumeTest) repoObjectState() protocol.EvsRepoState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.repoState
}

// The gkm writes the gate refused, in order.
func (self *gkmReformResumeTest) refused() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.refusedRoutes)
}

// How many requests evs has had.
func (self *gkmReformResumeTest) requestCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.requests)
}

// The core's statement poster as `ur evs restore` reaches it: a RepoRestore of the vault's deletion, which the log
// takes.
func (self *gkmReformResumeTest) fileStatement(ctx context.Context, signedType bridge.SignedType, body proto.Message) error {
	restore, ok := body.(*protocol.RepoRestore)
	if signedType != bridge.SignedType_SIGNED_REPO_RESTORE || !ok || !bytes.Equal(restore.GetRepoId(), self.world.repoId.Bytes()) ||
		!bytes.Equal(restore.GetDeletionId(), self.deletionId) {
		self.t.Errorf("a statement no restore files: %v %v", signedType, body)
		return errors.New("not the vault's RepoRestore")
	}
	self.restoreInLog()
	return nil
}

// A RepoRestore of the vault's deletion takes the log's next position, which every device's state then shows and
// evs's projection holds.
func (self *gkmReformResumeTest) restoreInLog() {
	world := self.world
	world.repo.Deletion.RestoredAt = world.nextPosition()
	world.stateFor()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.restoreProjected = true
}

// taskworker's reconciler at its daily walk (evsservice's RunReconcile): a projected RepoRestore of the deletion repo/
// shows takes repo/ to active, as restore would, with no device involved.
func (self *gkmReformResumeTest) reconcile() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.restoreProjected && self.repoState == protocol.EvsRepoState_EVS_REPO_DELETED {
		self.repoState = protocol.EvsRepoState_EVS_REPO_ACTIVE
	}
}

func (self *gkmReformResumeTest) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	self.serve(recorder, request)
	return recorder.Result(), nil
}

// evs's answers, as §11.12's rows give them for a repo whose projection ends in an unrestored RepoDelete inside its
// window, reseed on: the place creates repo/ deleted and answers a retry 200; activate answers deleted 409
// REPO_DELETED and active 200; restore takes deleted to active once the projection holds the RepoRestore, else 409
// STATEMENT_MISSING, and answers active 200.
func (self *gkmReformResumeTest) serve(writer http.ResponseWriter, request *http.Request) {
	repoPath := "/evs/v1/repos/" + sidecar.EvsKeyId(self.world.repoId)
	code := protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, request.Method+" "+request.URL.Path)
		switch {
		case request.Method == http.MethodPut && request.URL.Path == repoPath:
			if self.repoState == protocol.EvsRepoState_EVS_REPO_STATE_UNSPECIFIED {
				self.repoState = protocol.EvsRepoState_EVS_REPO_DELETED
			}
		case request.Method == http.MethodPost && request.URL.Path == repoPath+"/activate":
			if self.repoState != protocol.EvsRepoState_EVS_REPO_ACTIVE {
				code = protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED
			}
		case request.Method == http.MethodPost && request.URL.Path == repoPath+"/restore":
			switch {
			case !self.restoreProjected:
				code = protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING
			case self.repoState == protocol.EvsRepoState_EVS_REPO_DELETED:
				self.repoState = protocol.EvsRepoState_EVS_REPO_ACTIVE
			}
		default:
			self.t.Errorf("a request the groups step and the restore never send: %s %s", request.Method, request.URL.Path)
			code = protocol.EvsRefusalCode_EVS_REFUSAL_INVALID
		}
	}()
	if code != protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
		body, _ := proto.Marshal(&protocol.EvsRefusalReply{Code: code})
		writer.WriteHeader(http.StatusConflict)
		writer.Write(body)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

// The groups step on device a, its re-form a's own: the vault placed as deleted, its form, epoch 0 and ladder at gkm,
// a's record at the finishing phase, untried, and none of a's writes refused, since the step sends none that repo/
// deleted refuses. The new group's id.
func (self *gkmReformResumeTest) place() sidecar.Id {
	t := self.t
	t.Helper()
	world := self.world
	placed, err := self.client.Repo(world.repoId).ReseedPlace(world.ctx, nil)
	if err != nil {
		t.Fatalf("the groups step: %v", err)
	}
	newGroupId := world.formedGroupId()
	if !placed.Deleted || placed.Mended || placed.Restored || placed.PlacedByAnother || placed.GroupId != newGroupId || newGroupId == world.oldGroupId {
		t.Fatalf("placed %+v, the repo's newest group %s", placed, newGroupId)
	}
	if state := self.repoObjectState(); state != protocol.EvsRepoState_EVS_REPO_DELETED {
		t.Fatalf("repo/ after the groups step %s", state)
	}
	if generations, epochs := world.store.newestGeneration(newGroupId), len(world.store.groupEpochs[newGroupId]); generations != 2 || epochs != 1 {
		t.Fatalf("the new group holds %d generations and %d epochs", generations, epochs)
	}
	self.requireRecord(newGroupId, time.Time{})
	if refused := self.refused(); len(refused) != 0 {
		t.Errorf("gkm refused %v of the groups step", refused)
	}
	return newGroupId
}

// Device a's keychain holds the re-form's record at its finishing phase for groupId, last tried at resumedAt to the
// millisecond the record keeps, zero for never.
func (self *gkmReformResumeTest) requireRecord(groupId sidecar.Id, resumedAt time.Time) {
	self.t.Helper()
	phase, recordGroupId, recordResumedAt, found, err := self.world.flows[self.world.a].client.TestReformRecord(self.world.repoId)
	tried := recordResumedAt.IsZero() == resumedAt.IsZero() && (resumedAt.IsZero() || recordResumedAt.UnixMilli() == resumedAt.UnixMilli())
	if err != nil || !found || phase != sidecar.TestGkmReformPhaseFinishing || recordGroupId != groupId || !tried {
		self.t.Fatalf("a's re-form record: phase %d, group %s, tried %v, found %t, %v; want tried %v", phase, recordGroupId, recordResumedAt, found, err, resumedAt)
	}
}

// One of device a's syncs, which must end cleanly whatever its re-form's resume met.
func (self *gkmReformResumeTest) sync() {
	self.t.Helper()
	world := self.world
	if err := world.flows[world.a].client.SyncRepo(world.ctx, world.repoId); err != nil {
		self.t.Fatalf("a's sync: %v", err)
	}
}

// How many calls of route device a has made since mark, the store's call count when it was taken.
func (self *gkmReformResumeTest) callsSince(mark int, route string) int {
	store := self.world.store
	store.stateLock.Lock()
	defer store.stateLock.Unlock()
	count := 0
	for _, call := range store.calls[mark:] {
		if call == self.world.a.label+":"+route {
			count += 1
		}
	}
	return count
}

// The store's call count now.
func (self *gkmReformResumeTest) mark() int {
	store := self.world.store
	store.stateLock.Lock()
	defer store.stateLock.Unlock()
	return len(store.calls)
}

// Device a has sent none of the re-form's writes since mark: no form, ladder, staged delivery, claim, commit or
// Welcome.
func (self *gkmReformResumeTest) requireNoTry(mark int) {
	self.t.Helper()
	for _, route := range []string{"Reform", "UploadLadder", "UploadWraps", "UploadRecoveryWraps", "ClaimGeneration", "ClaimKeyPackage", "CommitEpoch", "UploadWelcome"} {
		if calls := self.callsSince(mark, route); calls != 0 {
			self.t.Errorf("a called %s %d times", route, calls)
		}
	}
}

// The group finished from a's record: generation 3 names the new group, with a RecoveryWrap for the member who reads
// by its code, epoch 1 adds every reader, a's pins stand at both, and a's record is gone. The generation's statement.
func (self *gkmReformResumeTest) requireFinished(newGroupId sidecar.Id) *protocol.GenRotate {
	t := self.t
	t.Helper()
	world := self.world
	a := world.flows[world.a]
	statements := world.store.groupGenerations[newGroupId]
	if len(statements) != 3 {
		t.Fatalf("the new group holds %d generations", len(statements))
	}
	gen3 := &protocol.GenRotate{}
	if err := proto.Unmarshal(statements[2].GetBody(), gen3); err != nil || !bytes.Equal(gen3.GetGroupId(), newGroupId.Bytes()) {
		t.Fatalf("generation 3 does not name the new group: %v", err)
	}
	if epochs := world.store.groupEpochs[newGroupId]; len(epochs) != 2 || epochs[1].GetHeader().GetGeneration() != 3 {
		t.Fatalf("the new group's epochs: %d", len(epochs))
	}
	if labels := world.rosterLabels(world.engineGroup2(world.a, newGroupId)); strings.Join(labels, "") != "abcpx" {
		t.Errorf("the new tree: %v", labels)
	}
	reply, err := a.api.RecoveryWraps(world.ctx, world.sharedId, false)
	if err != nil || len(reply.GetWraps()) != 1 || reply.GetWraps()[0].GetGeneration() != 3 {
		t.Errorf("the recovery wraps of the member who reads by its code: %v %v", reply.GetWraps(), err)
	}
	if groupId, epoch, generation, err := a.client.TestPins(world.repoId); err != nil || groupId != newGroupId || epoch != 1 || generation != 3 {
		t.Errorf("a's pins: epoch %d, generation %d, %v", epoch, generation, err)
	}
	if _, _, _, found, err := a.client.TestReformRecord(world.repoId); found || err != nil {
		t.Errorf("a's re-form record outlived its finish: %v", err)
	}
	return gen3
}

// Each member device syncs, joins the re-formed group by its Welcome at epoch 1 and generation 3, and reads every
// generation, raising no alarm.
func (self *gkmReformResumeTest) requireMembersBack(newGroupId sidecar.Id, devices ...*gkmWorldDevice) {
	t := self.t
	t.Helper()
	world := self.world
	for _, device := range devices {
		flow := world.flows[device]
		if err := flow.client.SyncRepo(world.ctx, world.repoId); err != nil {
			t.Fatalf("%s syncs after the re-form: %v", device.label, err)
		}
		joined, err := flow.client.JoinWelcomes(world.ctx)
		if err != nil || !slices.Contains(joined, world.repoId) {
			t.Fatalf("%s joins the re-formed group: %v %v", device.label, joined, err)
		}
		groupId, epoch, generation, err := flow.client.TestPins(world.repoId)
		if err != nil || groupId != newGroupId || epoch != 1 || generation != 3 {
			t.Errorf("%s in the re-formed group: epoch %d, generation %d, %v", device.label, epoch, generation, err)
		}
		for number := uint64(1); number <= 3; number += 1 {
			if key, err := flow.client.RepoKey(world.ctx, world.repoId, number); err != nil || key.Generation() != number {
				t.Errorf("%s reads generation %d after the re-form: %v", device.label, number, err)
			}
		}
		if len(flow.alarms) != 0 {
			t.Errorf("%s alarmed: %+v", device.label, flow.alarms[0])
		}
	}
}

// QD-1143 with `ur evs restore` on the re-former's device: while every device's state shows the vault deleted, a's
// syncs, however far apart, send none of the re-form's writes, and b follows the form and waits at its epoch 0; the
// restore files the RepoRestore and takes repo/ to active, and a's next sync finishes the group, gkm refusing nothing,
// after which every member returns. The groups step run again then re-forms nothing: it restores, the restore taking
// a repo/ already active, and answers the group, with no second form or ladder.
func TestARepoReseededAsDeletedFinishesItsGroupAtTheSyncAfterItsRestore(t *testing.T) {
	test := newGkmReformResumeTest(t)
	world := test.world
	interval := sidecar.DefaultGkmSettings().ReformResumeInterval
	newGroupId := test.place()

	mark := test.mark()
	for range 3 {
		test.sync()
		world.advance(2 * interval)
	}
	test.requireNoTry(mark)
	test.requireRecord(newGroupId, time.Time{})
	b := world.flows[world.b]
	if err := b.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatalf("b's sync while the vault is deleted: %v", err)
	}
	if groupId, epoch, generation, err := b.client.TestPins(world.repoId); err != nil || groupId != newGroupId || epoch != 0 || generation != 2 {
		t.Fatalf("b while the vault is deleted: epoch %d, generation %d, %v", epoch, generation, err)
	}

	if err := test.client.Repo(world.repoId).Restore(world.ctx); err != nil {
		t.Fatalf("ur evs restore: %v", err)
	}
	if state := test.repoObjectState(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Fatalf("repo/ after the restore %s", state)
	}
	test.sync()
	test.requireFinished(newGroupId)
	if refused := test.refused(); len(refused) != 0 {
		t.Errorf("gkm refused %v", refused)
	}
	if waited := test.evsClock.waited(); len(waited) != 0 {
		t.Errorf("evs's client waited %v", waited)
	}
	test.requireMembersBack(newGroupId, world.b, world.c, world.x)

	// the groups step run again: no second form, ladder or rotation
	placed, err := test.client.Repo(world.repoId).ReseedPlace(world.ctx, nil)
	if err != nil || placed.Deleted || !placed.Restored || !placed.Mended || placed.GroupId != newGroupId {
		t.Fatalf("the groups step run again: %+v, %v", placed, err)
	}
	if forms, ladders := world.store.callCount("Reform"), world.store.callCount("UploadLadder"); forms != 1 || ladders != 1 {
		t.Errorf("the re-form posted %d forms and %d ladders, want one each", forms, ladders)
	}
	if generations := world.store.newestGeneration(newGroupId); generations != 3 {
		t.Errorf("the new group holds %d generations", generations)
	}
}

// QD-1143 with taskworker's reconciler: another admin's device files the RepoRestore, and its restore call never
// reaches evs, so repo/ stays deleted until the reconciler's walk applies it with no device involved. a's state shows
// the vault restored, so its next sync tries the rotation, and gkm refuses its first write, the staged RecoveryWrap of
// the member who reads by its code, while repo/ reads deleted (every other reader is a member device, which returns by
// the Adds rather than a wrap); a's syncs try again only a ReformResumeInterval after the last try, a restart over the
// same keychain included, each refused try's draft drawn afresh at the next, past ReformDraftMaxAge. Once the
// reconciler has taken repo/ to active, a's first sync past the interval finishes the group with a generation drawn at
// that try, and every member returns, a having sent evs nothing since its groups step.
func TestARepoTheReconcilerRestoresFinishesItsGroupAtTheReformersSyncsWithinTheirInterval(t *testing.T) {
	test := newGkmReformResumeTest(t)
	world := test.world
	a := world.flows[world.a]
	interval := sidecar.DefaultGkmSettings().ReformResumeInterval
	newGroupId := test.place()
	requestCount := test.requestCount()
	test.restoreInLog()

	mark := test.mark()
	tries := func() int {
		return test.callsSince(mark, "UploadRecoveryWraps")
	}
	test.sync()
	firstTriedAt := world.clock.Now()
	if refused := test.refused(); tries() != 1 || !slices.Equal(refused, []string{"UploadRecoveryWraps"}) {
		t.Fatalf("the first sync after the RepoRestore: %d tries, gkm refused %v", tries(), refused)
	}
	test.requireRecord(newGroupId, firstTriedAt)
	if !a.client.TestHasRotateDraft(world.repoId) {
		t.Fatalf("the refused try left no rotation draft")
	}
	// at once, a moment before the interval, and after a restart: no try
	test.sync()
	world.advance(interval - time.Millisecond)
	test.sync()
	a.restart()
	test.sync()
	if claims := test.callsSince(mark, "ClaimGeneration"); tries() != 1 || claims != 0 {
		t.Fatalf("syncs within the interval tried %d times and claimed %d", tries(), claims)
	}
	test.requireRecord(newGroupId, firstTriedAt)
	// at the interval: a second try, refused again
	world.advance(time.Millisecond)
	test.sync()
	if tries() != 2 || len(test.refused()) != 2 {
		t.Fatalf("the sync at the interval: %d tries, gkm refused %v", tries(), test.refused())
	}
	test.requireRecord(newGroupId, world.clock.Now())

	// the reconciler's walk, no device involved; a's sync within the interval still does not try
	test.reconcile()
	if state := test.repoObjectState(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Fatalf("repo/ after the reconciler's walk %s", state)
	}
	test.sync()
	if tries() != 2 {
		t.Fatalf("a sync within the interval after the reconciler's walk tried")
	}
	world.advance(interval)
	test.sync()
	finishedAt := world.clock.Now()
	gen3 := test.requireFinished(newGroupId)
	if gen3.GetTimeMs() != finishedAt.UnixMilli() {
		t.Errorf("generation 3 was drawn at %d, the finishing try at %d", gen3.GetTimeMs(), finishedAt.UnixMilli())
	}
	if len(test.refused()) != 2 {
		t.Errorf("gkm refused %v", test.refused())
	}
	if test.requestCount() != requestCount {
		t.Errorf("a sent evs %d requests after its groups step", test.requestCount()-requestCount)
	}
	test.requireMembersBack(newGroupId, world.b, world.c, world.x)
}

// A rotation of the old group a kill cut short before the site loss, on a tree that still seats revoked c's leaf, so
// its draft carries no leaf wrap (R5), leaves a draft that names the old group and chains on generation 2; the
// re-form's rotation, at a's sync, claims no such draft in the new group but draws afresh, so generation 3 names the
// new group, and every member still reading takes it. Here the draft's delivery count, made on the old tree, already
// differs from the new tree's; finishReformInFlow drops one naming another group whatever its count.
func TestAReformDrawsItsRotationAfreshOverADraftOfTheOldGroup(t *testing.T) {
	world := newGkmReformWorld(t)
	a := world.flows[world.a]
	world.revoke(world.c)
	world.stateFor()
	world.store.plant("UploadRecoveryWraps", true)
	if _, err := a.client.RotateRepo(world.ctx, world.repoId); !errors.Is(err, errGkmFakeFault) {
		t.Fatalf("the killed rotation of the old group: %v", err)
	}
	if !a.client.TestHasRotateDraft(world.repoId) {
		t.Fatalf("the killed rotation left no draft")
	}
	world.loseSite()
	newGroupId, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId, Reseed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatalf("a's sync: %v", err)
	}
	statements := world.store.groupGenerations[newGroupId]
	gen3 := &protocol.GenRotate{}
	if len(statements) != 3 || proto.Unmarshal(statements[2].GetBody(), gen3) != nil || !bytes.Equal(gen3.GetGroupId(), newGroupId.Bytes()) {
		t.Fatalf("generation 3 at gkm does not name the new group: %d generations", len(statements))
	}
	if _, _, _, found, err := a.client.TestReformRecord(world.repoId); found || err != nil {
		t.Fatalf("a's re-form record outlived its finish: %v", err)
	}
	for _, device := range []*gkmWorldDevice{world.b, world.x} {
		flow := world.flows[device]
		if err := flow.client.SyncRepo(world.ctx, world.repoId); err != nil {
			t.Fatalf("%s syncs after the re-form: %v", device.label, err)
		}
		if joined, err := flow.client.JoinWelcomes(world.ctx); err != nil || !slices.Contains(joined, world.repoId) {
			t.Fatalf("%s joins the re-formed group: %v %v", device.label, joined, err)
		}
		if key, err := flow.client.RepoKey(world.ctx, world.repoId, 3); err != nil || key.Generation() != 3 {
			t.Errorf("%s reads generation 3: %v", device.label, err)
		}
		if len(flow.alarms) != 0 {
			t.Errorf("%s alarmed: %+v", device.label, flow.alarms[0])
		}
	}
}

// A sync never drafts a re-form. A device whose keychain holds no re-form record, its group never re-formed, posts no
// form or ladder and claims nothing at its syncs, however far apart; asked with Resume it drafts nothing and answers
// the group it pins, whose form stands at gkm, and asked so after a site loss took that form it answers
// ErrGkmKeyMissing. A record a kill cut short during its ladder is left to ReformGroup: the syncs send nothing of it,
// and ReformGroup then resumes it with no second form.
func TestASyncDraftsNoReform(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.members[0].Role = bridge.MemberRole_MEMBER_ROLE_MEMBER
	world.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.a.id.Bytes(), Signer: world.a.id.Bytes(), At: 1}}
	world.stateFor()
	for _, device := range []*gkmWorldDevice{world.b, world.c, world.p, world.x} {
		world.store.publishKeyPackages(device, 1, false)
	}
	a := world.flows[world.a]
	interval := sidecar.DefaultGkmSettings().ReformResumeInterval
	syncs := func() {
		for range 3 {
			if err := a.client.SyncRepo(world.ctx, world.repoId); err != nil {
				t.Fatalf("a's sync: %v", err)
			}
			world.advance(2 * interval)
		}
	}
	syncs()
	if forms, ladders, claims := world.store.callCount("Reform"), world.store.callCount("UploadLadder"), world.store.callCount("ClaimGeneration"); forms != 0 || ladders != 0 || claims != 0 {
		t.Fatalf("syncs with no record posted %d forms and %d ladders and claimed %d", forms, ladders, claims)
	}
	groupId, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId, Resume: true})
	if err != nil || groupId != world.groupId || world.store.callCount("Reform") != 0 {
		t.Fatalf("a resume with no record: %s, %v, %d forms", groupId, err, world.store.callCount("Reform"))
	}

	// a record whose ladder a kill cut short
	world.store.plantCount("UploadLadder", true, 3)
	if _, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId}); err == nil {
		t.Fatalf("the killed re-form answered")
	}
	phase, newGroupId, _, found, err := a.client.TestReformRecord(world.repoId)
	if err != nil || !found || phase != sidecar.TestGkmReformPhaseLadder {
		t.Fatalf("the killed re-form's record: phase %d, found %t, %v", phase, found, err)
	}
	a.restart()
	syncs()
	if forms, ladders, claims := world.store.callCount("Reform"), world.store.callCount("UploadLadder"), world.store.callCount("ClaimGeneration"); forms != 1 || ladders != 3 || claims != 0 {
		t.Fatalf("syncs over a record cut short posted %d forms and %d ladders and claimed %d", forms, ladders, claims)
	}
	if phase, _, _, _, _ := a.client.TestReformRecord(world.repoId); phase != sidecar.TestGkmReformPhaseLadder {
		t.Fatalf("the syncs moved the record to phase %d", phase)
	}
	resumedGroupId, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	if err != nil || resumedGroupId != newGroupId || world.store.callCount("Reform") != 1 || world.store.newestGeneration(newGroupId) != 2 {
		t.Fatalf("the re-form resumed by ReformGroup: %s, %v, %d forms", resumedGroupId, err, world.store.callCount("Reform"))
	}

	// a site loss takes every form: a resume with no record answers that none stands, drafting nothing
	world.store.loseSite()
	if _, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId, Resume: true}); !errors.Is(err, sidecar.ErrGkmKeyMissing) || world.store.callCount("Reform") != 1 {
		t.Fatalf("a resume with no record or form: %v, %d forms", err, world.store.callCount("Reform"))
	}
	if _, _, _, found, _ := a.client.TestReformRecord(world.repoId); found {
		t.Fatalf("a resume with no record drafted one")
	}
}

// Runs sync once, right after the first activate evs answers 200, before the step's next call.
type gkmReformSyncAtActivate struct {
	test   *evsReseedReformTest
	sync   func()
	synced bool
}

func (self *gkmReformSyncAtActivate) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := self.test.RoundTrip(request)
	if err == nil && response.StatusCode == http.StatusOK && strings.HasSuffix(request.URL.Path, "/activate") && !self.synced {
		self.synced = true
		self.sync()
	}
	return response, err
}

// A live repo's groups step whose re-form a's sync finishes between the step's activate and its second call: the
// sync, as activate has taken repo/ to active, rotates and adds every reader; the second call, asked with Resume,
// finds no record and answers the group the repo's newest form names, so gkm holds one form, one ladder and one
// generation 3, and every member returns by its Welcome.
func TestAReseedPlaceSecondCallAfterASyncFinishedItsReformDraftsNoOther(t *testing.T) {
	test := newEvsReseedReformTest(t)
	world := test.world
	a := world.flows[world.a]
	transport := &gkmReformSyncAtActivate{test: test}
	transport.sync = func() {
		if err := a.client.SyncRepo(world.ctx, world.repoId); err != nil {
			t.Errorf("a's sync at activate: %v", err)
		}
		if _, _, _, found, err := a.client.TestReformRecord(world.repoId); found || err != nil {
			t.Errorf("a's sync at activate left the re-form's record: %v", err)
		}
	}
	client := newGkmReformResumeEvsClient(t, world, transport, nil, test.evsClock)
	placed, err := client.Repo(world.repoId).ReseedPlace(world.ctx, nil)
	if err != nil {
		t.Fatalf("the groups step: %v", err)
	}
	newGroupId := world.formedGroupId()
	if !transport.synced || placed.Deleted || placed.Mended || placed.PlacedByAnother || placed.GroupId != newGroupId {
		t.Fatalf("placed %+v, the repo's newest group %s, synced at activate %t", placed, newGroupId, transport.synced)
	}
	if forms, ladders := world.store.callCount("Reform"), world.store.callCount("UploadLadder"); forms != 1 || ladders != 1 {
		t.Errorf("the re-form posted %d forms and %d ladders, want one each", forms, ladders)
	}
	if generations, epochs := world.store.newestGeneration(newGroupId), len(world.store.groupEpochs[newGroupId]); generations != 3 || epochs != 2 {
		t.Errorf("the new group holds %d generations and %d epochs", generations, epochs)
	}
	if refused := test.refused(); len(refused) != 0 {
		t.Errorf("gkm refused %v", refused)
	}
	test.requireMembersBack(newGroupId, world.b, world.c, world.x)
}
