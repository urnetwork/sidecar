package gkmschedule

// FS-20's recovery legs and FS-22 on T2 (KEYS-M2-27, KEYS-M2-28; FI-12, I-15, FI-3; §10.8's Recovery, §7.9's anchor,
// compromise clause and rebind row, DESIGN-DETAILS 6.2.4's Recovery and 6.6's self-join row), on the real subset
// against gkmservice's engine, the world holding the member's recovery binding and the network's config group:
//
//   - an epoch commits and its committer crashes as it lands, then every leaf's state is lost: the device the
//     member's recovery code admits fetches only its wraps before admission, anchors on the config group's RK_g,
//     and self-joins both groups from the newest epoch's inline GroupInfo, no group-info object standing at 16
//     leaves or fewer; with the lost devices revoked and their leaves still in the trees, each self-join is
//     generation 0 with no GenWrap, which gkm takes from a recovery-admitted device alone, its next commit removes
//     them, and the rotation after is the first new generation, cause REMOVE, which the lost devices reach nothing
//     of; over a clean tree, the self-join carries the newest generation's GenWrap, and the Remove and rotation
//     follow the revocations;
//   - gkm killed between an epoch's PUT 16 past the group-info pointer and the pointer's rewrite: the pointer lags,
//     a resync's probe from it, paging epochs?after= to the end at a bound of 4, finds the newest epoch, and the
//     resync's external commit, the next epoch, rewrites the pointer;
//   - FS-22: after RecoveryRebind{reason: compromise} the gate closes at the old generation, the member's device
//     re-wraps the newest generation to the new binding, deletes the old binding's wraps and rotates REMOVE, so the
//     old code's derived keys open nothing gkm holds and no generation past the cutover; the twin, a routine rebind,
//     leaves the gate open and rotates REQUEST.
//
// FS-22's --compromise plan and its since_n clamp, and a personal network's last device enrolling its replacement,
// are TEAM's and CORE's; the content keys a generation derives (path tokens, file keys) are evs's, and a key that
// does not open RK_g derives none.

import (
	"bytes"
	"errors"
	"net/http"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
)

// gkm's group-info object of groupId, nil for none: the pointer at 16 leaves or fewer.
func (self *FsKeysWorld) GroupInfoObject(groupId sidecar.Id) *protocol.GkmGroupInfoObject {
	self.t.Helper()
	for key, body := range self.objects(gkmservice.GkmGroupInfoKey(groupId)) {
		if key != gkmservice.GkmGroupInfoKey(groupId) {
			continue
		}
		object := &protocol.GkmGroupInfoObject{}
		if err := proto.Unmarshal(body, object); err != nil {
			self.t.Fatal(err)
		}
		return object
	}
	return nil
}

// The recovery world: the member's devices a, its config writer and the repo's admin, and b, both writer leaves of
// both groups; the agent d reading the repo; the member's binding, current from the start, so generation 1 of each
// group carries its RecoveryWrap.
func newFsKeysRecoveryWorld(t FsKeysT, newWorld FsKeysNewWorld) (*FsKeysWorld, *FsKeysDevice, *FsKeysDevice, *FsKeysDevice, *FsKeysRecoveryBinding) {
	t.Helper()
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	d := world.AddAgent("d")
	world.Grant(true, a, b)
	world.Grant(false, d)
	world.Admin(a)
	world.ConfigWriters(a)
	binding := world.BindRecovery("m", a)
	world.Advance()
	world.Publish()
	world.CreateConfig(a)
	world.AddPendingIn(a, world.ConfigRepoId)
	world.Create(a)
	world.AddPending(a)
	for _, groupId := range []sidecar.Id{world.ConfigGroupId, world.GroupId} {
		if !world.HoldsRecoveryWrap(groupId, 1, binding) {
			t.Fatalf("generation 1 of group %s holds no RecoveryWrap to the member's binding", groupId)
		}
	}
	if labels := world.RosterIn(a, world.ConfigGroupId); labels != "ab" {
		t.Fatalf("the config group's tree: %s", labels)
	}
	return world, a, b, d, binding
}

// The world's two groups, the config group first.
func (self *FsKeysWorld) groupIds() []sidecar.Id {
	return []sidecar.Id{self.ConfigGroupId, self.GroupId}
}

// The world's two repos, the config repo first, in the order groupIds names their groups.
func (self *FsKeysWorld) recoveryRepoIds() []sidecar.Id {
	return []sidecar.Id{self.ConfigRepoId, self.RepoId}
}

// a commits a path-only epoch of each group and crashes as each lands: gkm takes it, the answer is lost, and a never
// returns. The newest epoch of each group is then a's, carrying its inline GroupInfo.
func (self *FsKeysWorld) commitAndCrash(a *FsKeysDevice) {
	self.t.Helper()
	before := map[sidecar.Id]uint64{}
	for _, groupId := range self.groupIds() {
		before[groupId] = self.NewestEpochIn(groupId)
	}
	a.Transport.Before = func(request *http.Request) FsKeysFault {
		if FsKeysEpochCommit(request) {
			return FsKeysFaultDropAnswer
		}
		return FsKeysFaultNone
	}
	for _, repoId := range self.recoveryRepoIds() {
		// the answer never reaches a: whatever its client concludes, a is gone
		a.Client.SelfUpdate(self.Ctx, repoId)
	}
	a.Transport.Before = nil
	for _, groupId := range self.groupIds() {
		newest := self.NewestEpochIn(groupId)
		if newest != before[groupId]+1 {
			self.t.Fatalf("the crashed commit of group %s: epoch %d after %d", groupId, newest, before[groupId])
		}
		if object := self.EpochObjectIn(groupId, newest); len(object.GetSealedGroupInfo()) == 0 {
			self.t.Fatalf("epoch %d of group %s carries no inline GroupInfo", newest, groupId)
		}
		if self.GroupInfoObject(groupId) != nil {
			self.t.Fatalf("a group-info object stands at 16 leaves or fewer below 16 epochs")
		}
	}
}

// The recovered device: admitted by the member's binding, writing the repo, its wraps fetched before admission
// under recovery:<member_id> alone. It stands in the next state.
func (self *FsKeysWorld) recoveredDevice(binding *FsKeysRecoveryBinding) *FsKeysDevice {
	self.t.Helper()
	r := self.AddRecovered("r", binding)
	self.Grant(true, r)
	routes := []string{}
	r.Transport.Before = func(request *http.Request) FsKeysFault {
		routes = append(routes, request.Method+" "+request.URL.Path)
		return FsKeysFaultNone
	}
	kept, err := r.Client.FetchRecoveryWraps(self.Ctx, binding.Binding(self.MemberId), false)
	if err != nil || kept != 2 {
		self.t.Fatalf("the fetch before admission kept %d wraps: %v", kept, err)
	}
	r.Transport.Before = nil
	if len(routes) != 1 || routes[0] != "GET /gkm/recovery/"+sidecar.EvsKeyId(self.MemberId)+"/wraps" {
		self.t.Errorf("an unadmitted device called %v", routes)
	}
	// a generation-0 self-join from anything but a recovery-admitted device is refused: the agent's, say, never
	// reaches the epoch route, which takes member devices alone
	return r
}

// FS-20: a commit and its committer's crash, then every leaf's state lost and the lost devices revoked: the code-only
// device self-joins both groups at generation 0 over their revoked leaves, from the inline GroupInfo, removes them in
// its next commit and rotates REMOVE, the first new generation, which the lost devices reach nothing of and the agent
// reads by its ReaderWrap.
func FsKeysScheduleRecoveryOverLostLeaves(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, b, d, binding := newFsKeysRecoveryWorld(t, newWorld)
	world.commitAndCrash(a)
	// every leaf's state is lost: a and b take nothing more
	a.Offline = true
	b.Offline = true
	r := world.recoveredDevice(binding)
	// §5.6 revokes the lost devices as the recovered device is admitted
	world.Revoke(a)
	world.Revoke(b)
	world.AdmitRecovered(r)
	world.Advance()
	world.Publish()
	joinEpochs := map[sidecar.Id]uint64{}
	for _, groupId := range world.groupIds() {
		joinEpochs[groupId] = world.NewestEpochIn(groupId) + 1
	}
	args := world.RecoverArgs(binding)
	if err := r.Client.AnchorRecovery(world.Ctx, args); err != nil {
		t.Fatalf("the anchor: %v", err)
	}
	progress, err := r.Client.RunRecovery(world.Ctx, args)
	if err != nil {
		t.Fatalf("the recovery pass: %v", err)
	}
	for _, repo := range progress {
		if !repo.SelfJoined || !repo.GenerationZero || !repo.Leaf || repo.Waiting != nil {
			t.Errorf("repo %s after the recovery pass: %+v", repo.RepoId, repo)
		}
	}
	for index, groupId := range world.groupIds() {
		repoId := world.recoveryRepoIds()[index]
		join := world.EpochObjectIn(groupId, joinEpochs[groupId])
		if join == nil {
			t.Fatalf("group %s holds no self-join epoch", groupId)
		}
		header, err := sidecar.ParseMlsHeader(join.GetCommit())
		if err != nil {
			t.Fatal(err)
		}
		joinHeader := &protocol.GkmCommitHeader{}
		if err := proto.Unmarshal(header.AuthenticatedData, joinHeader); err != nil {
			t.Fatal(err)
		}
		if !sidecar.GkmCommitIsExternal(join.GetCommit()) || joinHeader.GetGeneration() != 0 || len(join.GetGenWrap()) != 0 {
			t.Errorf("group %s's self-join: external %v, generation %d, a GenWrap of %d bytes", groupId, sidecar.GkmCommitIsExternal(join.GetCommit()), joinHeader.GetGeneration(), len(join.GetGenWrap()))
		}
		// its next commit removes the lost leaves, and carries gen/'s newest again
		remove := world.EpochObjectIn(groupId, joinEpochs[groupId]+1)
		if remove == nil || remove.GetHeader().GetGeneration() == 0 || len(remove.GetGenWrap()) == 0 {
			t.Errorf("group %s's commit after the self-join: %v", groupId, remove.GetHeader())
		}
		if labels := world.RosterIn(r, groupId); labels != "r" {
			t.Errorf("group %s's tree after the recovered device's next commit: %s", groupId, labels)
		}
		// the first new generation, past the lost devices
		if count := world.GenerationCountIn(groupId); count != 2 {
			t.Fatalf("group %s holds %d generations", groupId, count)
		}
		generation2 := world.GenerationIn(groupId, 2)
		if sidecar.GkmCause(generation2.Rotate.GetCause()) != sidecar.GkmCauseRemove {
			t.Errorf("group %s's rotation past the lost devices: cause %d", groupId, generation2.Rotate.GetCause())
		}
		recipients := world.WrapRecipientsIn(groupId, 2)
		if recipients[a.SidecarId()] || recipients[b.SidecarId()] {
			t.Errorf("group %s's generation 2 delivers to a lost device", groupId)
		}
		if !world.HoldsRecoveryWrap(groupId, 2, binding) {
			t.Errorf("group %s's generation 2 carries no RecoveryWrap to the member's binding", groupId)
		}
		for _, lost := range []*FsKeysDevice{a, b} {
			if reached := world.RemovedReachIn(lost, repoId, groupId); reached != 1 {
				t.Errorf("lost device %s reaches generation %d of group %s", lost.Label, reached, groupId)
			}
		}
	}
	// the agent reads the first new generation by its ReaderWrap
	if err := d.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the agent's sync: %v", err)
	}
	if key, err := d.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 {
		t.Errorf("the agent does not hold generation 2: %v", err)
	}
	if len(r.Alarms) != 0 {
		t.Errorf("the recovered device alarmed: %+v", r.Alarms[0])
	}
}

// FS-20 over a clean tree: the lost devices not yet revoked, the code-only device's self-join carries the newest
// generation's GenWrap, as a resync does; their revocation then has its next commit remove them and rotate REMOVE.
func FsKeysScheduleRecoveryOverACleanTree(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, b, d, binding := newFsKeysRecoveryWorld(t, newWorld)
	world.commitAndCrash(a)
	a.Offline = true
	b.Offline = true
	r := world.recoveredDevice(binding)
	world.AdmitRecovered(r)
	world.Advance()
	world.Publish()
	args := world.RecoverArgs(binding)
	if err := r.Client.AnchorRecovery(world.Ctx, args); err != nil {
		t.Fatalf("the anchor: %v", err)
	}
	joinEpochs := map[sidecar.Id]uint64{}
	for _, groupId := range world.groupIds() {
		joinEpochs[groupId] = world.NewestEpochIn(groupId) + 1
	}
	progress, err := r.Client.RunRecovery(world.Ctx, args)
	if err != nil {
		t.Fatalf("the recovery pass: %v", err)
	}
	for _, repo := range progress {
		if !repo.SelfJoined || repo.GenerationZero || !repo.Leaf || repo.Generation != 1 || repo.Waiting != nil {
			t.Errorf("repo %s after the recovery pass over a clean tree: %+v", repo.RepoId, repo)
		}
	}
	for _, groupId := range world.groupIds() {
		join := world.EpochObjectIn(groupId, joinEpochs[groupId])
		if join == nil || !sidecar.GkmCommitIsExternal(join.GetCommit()) || len(join.GetGenWrap()) == 0 || join.GetGroupInfoGeneration() != 1 {
			t.Errorf("group %s's self-join over a clean tree carries no GenWrap of generation 1", groupId)
		}
		if labels := world.RosterIn(r, groupId); labels != "abr" {
			t.Errorf("group %s's tree after the self-join: %s", groupId, labels)
		}
	}
	// the lost devices are revoked: the recovered device's next pass removes them and rotates past them
	world.Revoke(a)
	world.Revoke(b)
	world.Advance()
	if _, err := r.Client.RunRecovery(world.Ctx, args); err != nil {
		t.Fatalf("the pass after the revocations: %v", err)
	}
	for index, groupId := range world.groupIds() {
		repoId := world.recoveryRepoIds()[index]
		if labels := world.RosterIn(r, groupId); labels != "r" {
			t.Errorf("group %s's tree after the revocations: %s", groupId, labels)
		}
		if count := world.GenerationCountIn(groupId); count != 2 || sidecar.GkmCause(world.GenerationIn(groupId, 2).Rotate.GetCause()) != sidecar.GkmCauseRemove {
			t.Errorf("group %s past the revocations: %d generations", groupId, count)
			continue
		}
		for _, lost := range []*FsKeysDevice{a, b} {
			if reached := world.RemovedReachIn(lost, repoId, groupId); reached != 1 {
				t.Errorf("lost device %s reaches generation %d of group %s", lost.Label, reached, groupId)
			}
		}
	}
	if err := d.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if key, err := d.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 {
		t.Errorf("the agent does not hold generation 2: %v", err)
	}
}

// FS-20's pointer: gkm killed between epoch 32's PUT, 16 past the group-info pointer at 16, and the pointer's rewrite,
// its committer with it. The pointer stands at 16; b, whose MLS state was lost while its keychain pinned epoch 1,
// resyncs: its probe starts at the pointer and pages epochs?after= at gkm's bound of 4 to the end, finding epoch 32,
// and its external commit, epoch 33, rewrites the pointer.
func FsKeysSchedulePointerRewrite(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) { settings.EpochsReplyMaxCount = 4 })
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	world.Grant(true, a, b)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	b.Offline = true
	for world.NewestEpoch() < 31 {
		if err := a.Client.SelfUpdate(world.Ctx, world.RepoId); err != nil {
			t.Fatalf("a's self-update at epoch %d: %v", world.NewestEpoch()+1, err)
		}
	}
	if pointer := world.GroupInfoObject(world.GroupId); pointer.GetEpoch() != 16 {
		t.Fatalf("the pointer names epoch %d before the kill", pointer.GetEpoch())
	}

	// epoch 32 lands, and gkm dies before the pointer's rewrite, taking the committer's answer with it
	pointerKey := gkmservice.GkmGroupInfoKey(world.GroupId)
	world.BlobWrite = func(op string, key string) FsKeysFault {
		if key == pointerKey {
			return FsKeysFaultFailBefore
		}
		return FsKeysFaultNone
	}
	a.Transport.Before = func(request *http.Request) FsKeysFault {
		if FsKeysEpochCommit(request) {
			return FsKeysFaultDropAnswer
		}
		return FsKeysFaultNone
	}
	a.Client.SelfUpdate(world.Ctx, world.RepoId)
	world.BlobWrite = nil
	a.Transport.Before = nil
	a.Offline = true
	world.RestartEngine()
	if world.NewestEpoch() != 32 || world.GroupInfoObject(world.GroupId).GetEpoch() != 16 {
		t.Fatalf("after the kill: newest epoch %d, the pointer at %d", world.NewestEpoch(), world.GroupInfoObject(world.GroupId).GetEpoch())
	}

	// b comes back with its MLS state lost: its probe pages from the pointer to the end
	b.LoseMlsState()
	b.Offline = false
	b.Take(world.Log.Tip())
	pages := []string{}
	b.Transport.Before = func(request *http.Request) FsKeysFault {
		if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/epochs") {
			pages = append(pages, request.URL.Query().Get("after"))
		}
		return FsKeysFaultNone
	}
	if err := b.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("b's resync: %v", err)
	}
	b.Transport.Before = nil
	if world.NewestEpoch() != 33 || !sidecar.GkmCommitIsExternal(world.EpochObject(33).GetCommit()) {
		t.Fatalf("b's resync did not commit epoch 33 by external commit: newest %d", world.NewestEpoch())
	}
	if pointer := world.GroupInfoObject(world.GroupId); pointer.GetEpoch() != 33 {
		t.Errorf("the next epoch did not rewrite the pointer: it names %d", pointer.GetEpoch())
	}
	// from the pointer's 16 to 32 at 4 a page is at least five pages, then the empty one: uncapped
	probed := 0
	for _, after := range pages {
		if after != "" && after != "0" {
			probed += 1
		}
	}
	if probed < 5 {
		t.Errorf("the probe read %d pages past the pointer: %v", probed, pages)
	}
	if labels := world.Roster(b); labels != "ab" {
		t.Errorf("b's tree after its resync: %s", labels)
	}
}

// The FS-22 world: the member's devices a, the config writer and admin, and b, writer leaves of both groups, the
// agent d, and the member's first binding, which generation 2 of the repo, a rotation by a, carries too.
func newFsKeysRebindWorld(t FsKeysT, newWorld FsKeysNewWorld) (*FsKeysWorld, *FsKeysDevice, *FsKeysDevice, *FsKeysDevice, *FsKeysRecoveryBinding) {
	t.Helper()
	world, a, b, d, old := newFsKeysRecoveryWorld(t, newWorld)
	if key, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the rotation that wraps to the old binding: %v", err)
	}
	if !world.HoldsRecoveryWrap(world.GroupId, 2, old) {
		t.Fatalf("generation 2 carries no RecoveryWrap to the old binding")
	}
	return world, a, b, d, old
}

// FS-22: RecoveryRebind{reason: compromise}. The rebind shrinks every repo the member reads, so the gate closes at
// generation 2 (evs's 412 GATE_CLOSED for a write sealed to it); a's rebind re-wraps generation 2 to the new binding,
// deletes every wrap of the old one and rotates REMOVE in each group, so the old code's derived keys open nothing gkm
// holds, in particular no generation past the cutover, while the new code opens the newest of each.
func FsKeysScheduleCompromiseRebind(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, b, d, old := newFsKeysRebindWorld(t, newWorld)
	generation2 := world.Generation(2)
	newer := world.RebindRecovery("m'", a, true)
	view := world.Advance()
	if sidecar.GkmGatePasses(view, world.RepoId, generation2.Rotate.GetAuth(), world.GenerationTime(generation2), world.Clock.Now()) {
		t.Errorf("the gate stays open at generation 2 after a compromise rebind")
	}
	args := &sidecar.GkmRecoveryRebindArgs{MemberId: world.MemberId, New: newer.Key(), RetiredKeySha256: old.KeySha256, Compromise: true}
	if err := a.Client.RebindRecovery(world.Ctx, args); err != nil {
		t.Fatalf("the compromise rebind: %v", err)
	}
	for index, groupId := range world.groupIds() {
		newest := uint64(world.GenerationCountIn(groupId))
		rotate := world.GenerationIn(groupId, newest).Rotate
		if sidecar.GkmCause(rotate.GetCause()) != sidecar.GkmCauseRemove {
			t.Errorf("group %s's rotation after the compromise rebind: cause %d", groupId, rotate.GetCause())
		}
		if rotate.GetAuth().GetVersion() < view.Pin().GetVersion() {
			t.Errorf("group %s's rotation is pinned before the rebind", groupId)
		}
		for generation := uint64(1); generation <= newest; generation += 1 {
			if world.HoldsRecoveryWrap(groupId, generation, old) {
				t.Errorf("group %s keeps a RecoveryWrap of generation %d to the old binding", groupId, generation)
			}
		}
		if reached := world.RecoveryReach(old, groupId); reached != 0 {
			t.Errorf("the old code opens generation %d of group %s", reached, groupId)
		}
		if reached := world.RecoveryReach(newer, groupId); reached != newest {
			t.Errorf("the new code opens generation %d of group %s, not the newest, %d", reached, groupId, newest)
		}
		if index == 1 {
			newestGeneration := world.GenerationIn(groupId, newest)
			if !sidecar.GkmGatePasses(world.Log.Tip(), world.RepoId, newestGeneration.Rotate.GetAuth(), world.GenerationTime(newestGeneration), world.Clock.Now()) {
				t.Errorf("the gate does not reopen at the REMOVE generation")
			}
		}
	}
	// gkm serves the old binding's code nothing: every wrap of its b8 is gone
	wraps, err := a.Api.RecoveryWraps(world.Ctx, world.MemberId, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrap := range wraps.GetWraps() {
		if bytes.Equal(wrap.GetBindingPrefix(), old.KeySha256[:8]) {
			t.Errorf("gkm serves a wrap of the old binding, generation %d", wrap.GetGeneration())
		}
	}
	for _, device := range []*FsKeysDevice{b, d} {
		if err := device.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
			t.Fatalf("%s's sync: %v", device.Label, err)
		}
		if key, err := device.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || key.Generation() != uint64(world.GenerationCount()) {
			t.Errorf("%s does not follow to the REMOVE generation: %v", device.Label, err)
		}
	}
}

// FS-22's twin: a routine rebind shrinks nothing, so the gate stays open at generation 2; the rebind re-wraps to the
// new binding, deletes the old one's wraps and rotates REQUEST.
func FsKeysScheduleRoutineRebind(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, _, _, old := newFsKeysRebindWorld(t, newWorld)
	generation2 := world.Generation(2)
	newer := world.RebindRecovery("m'", a, false)
	view := world.Advance()
	if !sidecar.GkmGatePasses(view, world.RepoId, generation2.Rotate.GetAuth(), world.GenerationTime(generation2), world.Clock.Now()) {
		t.Errorf("a routine rebind closed the gate")
	}
	args := &sidecar.GkmRecoveryRebindArgs{MemberId: world.MemberId, New: newer.Key(), RetiredKeySha256: old.KeySha256}
	if err := a.Client.RebindRecovery(world.Ctx, args); err != nil {
		t.Fatalf("the routine rebind: %v", err)
	}
	for _, groupId := range world.groupIds() {
		newest := uint64(world.GenerationCountIn(groupId))
		if cause := sidecar.GkmCause(world.GenerationIn(groupId, newest).Rotate.GetCause()); cause != sidecar.GkmCauseRequest {
			t.Errorf("group %s's rotation after a routine rebind: cause %d", groupId, cause)
		}
		if reached := world.RecoveryReach(old, groupId); reached != 0 {
			t.Errorf("the old code still opens generation %d of group %s", reached, groupId)
		}
		if reached := world.RecoveryReach(newer, groupId); reached != newest {
			t.Errorf("the new code opens generation %d of group %s", reached, groupId)
		}
	}
}

// An external commit by device past its own R3 wait, as a hostile client would make it: from the newest epoch's
// inline GroupInfo, removing device's own old leaf where the tree holds one, its header naming generation 0 with no
// GenWrap, its GroupInfo sealed under the generation the epoch named. gkm's answer.
func (self *FsKeysWorld) InjectGenerationZeroJoin(device *FsKeysDevice) int {
	self.t.Helper()
	newest := self.NewestEpoch()
	object := self.EpochObject(newest)
	key, err := device.Client.RepoKey(self.Ctx, self.RepoId, object.GetGroupInfoGeneration())
	if err != nil {
		self.t.Fatalf("%s's generation %d: %v", device.Label, object.GetGroupInfoGeneration(), err)
	}
	groupInfo, err := sidecar.OpenGkmGroupInfo(key, self.GroupId, newest, object.GetSealedGroupInfo())
	if err != nil {
		self.t.Fatal(err)
	}
	reader, ok := device.Mls.(sidecar.MlsGroupInfoReader)
	if !ok {
		self.t.Fatal("the engine reads no GroupInfo")
	}
	_, _, roster, err := reader.GroupInfoRoster(groupInfo)
	if err != nil {
		self.t.Fatal(err)
	}
	removes := []uint32{}
	for _, member := range roster {
		if member.SidecarId == device.SidecarId() {
			removes = append(removes, member.LeafIndex)
		}
	}
	header := self.marshal(&protocol.GkmCommitHeader{Auth: device.state.Pin()})
	staged, err := device.Mls.JoinExternal(groupInfo, &sidecar.MlsCommitArgs{Path: true, Removes: removes, AuthenticatedData: header})
	if err != nil {
		self.t.Fatal(err)
	}
	defer staged.Discard()
	stagedGroupInfo, err := staged.GroupInfo()
	if err != nil {
		self.t.Fatal(err)
	}
	sealedGroupInfo, err := sidecar.SealGkmGroupInfo(key, self.GroupId, staged.Epoch(), stagedGroupInfo)
	if err != nil {
		self.t.Fatal(err)
	}
	err = device.Api.CommitEpoch(self.Ctx, self.RepoId, self.GroupId, staged.Epoch(), &protocol.GkmEpochRequest{
		Commit: staged.Message(), SealedGroupInfo: sealedGroupInfo, GroupInfoGeneration: key.Generation(),
	})
	if err == nil {
		return http.StatusOK
	}
	if gkmError, ok := sidecar.GkmErrorOf(err); ok {
		return gkmError.Status
	}
	self.t.Fatalf("the injected external commit: %v", err)
	return 0
}

// FS-15 and FS-20's exception, refused: a member device its member's recovery key did not admit, its MLS state lost
// while a revoked leaf stands, waits under R3 rather than join, and its external commit at generation 0 with no
// GenWrap, made past that wait, is refused by gkm (403) and stands nowhere; once a writer's Remove lands, and with it
// the REMOVE rotation's leaf_wrap c cannot open, c takes a late delivery and its resync carries the newest
// generation and is taken.
func FsKeysScheduleGenerationZeroFromAnOrdinaryDevice(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	c := world.AddMember("c", false)
	world.Grant(true, a, b, c)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	world.Revoke(b)
	b.Offline = true
	world.Advance()
	c.LoseMlsState()
	c.Take(world.Log.Tip())
	if err := c.Client.SyncRepo(world.Ctx, world.RepoId); !errors.Is(err, sidecar.ErrGkmDroppedLeafStands) {
		t.Errorf("the resync while a revoked leaf stands: %v", err)
	}
	epoch := world.NewestEpoch()
	if status := world.InjectGenerationZeroJoin(c); status != http.StatusForbidden {
		t.Errorf("a generation-0 external commit by a device no recovery key admitted: %d", status)
	}
	if world.NewestEpoch() != epoch {
		t.Fatalf("the refused external commit stands")
	}
	// the twin: a's Remove lands with the REMOVE rotation, whose leaf_wrap c, holding no epoch past its loss, cannot
	// open; it asks, a delivers late to its key, and c's resync carries the newest generation
	if err := a.Client.RunPending(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("a's Remove: %v", err)
	}
	if err := c.Client.SyncRepo(world.Ctx, world.RepoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("c's resync before its late delivery: %v", err)
	}
	if err := a.Client.DeliverLate(world.Ctx, world.RepoId, fsKeysRecipient(c.SidecarId())); err != nil {
		t.Fatalf("the late delivery to c: %v", err)
	}
	if err := c.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("c's resync after the Remove: %v", err)
	}
	newest := world.EpochObject(world.NewestEpoch())
	if !sidecar.GkmCommitIsExternal(newest.GetCommit()) || len(newest.GetGenWrap()) == 0 || newest.GetHeader().GetGeneration() == 0 {
		t.Errorf("c's resync is no external commit carrying the newest generation")
	}
	if labels := world.Roster(c); labels != "ac" {
		t.Errorf("the tree after c's resync: %s", labels)
	}
}
