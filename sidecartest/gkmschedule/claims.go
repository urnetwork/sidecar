package gkmschedule

// FS-15 on T2 and T3 (KEYS-M2-27; §22.7's schedule rows, D-TEST-10, FI-4, DESIGN-DETAILS 6.2.3 and 6.6's added rows): gkm's
// group client on the real MLS subset, every device its own engine, identity key, keychain and store, against
// gkmservice's engine on the world's host, the fake one on T2 and the local stack's stores on T3, both over one log of
// fixture states read at its tip as a gate's state reads
// §8.9's cache (FsKeysWorld). Each schedule drives the flows in an order it fixes, its interleavings made at the
// transport, which holds a request while another device runs or loses an answer the engine gave, so nothing here
// sleeps or depends on the scheduler.
//
//   - an agent removed with every leaf offline: a wrapped writer rotates with ReaderWraps to every remaining leaf and
//     the gate reopens; the read_only leaf's due self-update waits while the dropped leaf stands (R3); the returning
//     writer leaf commits the Remove first, its commit carrying the newest GenWrap; the read_only leaf's self-update
//     then lands; and the removed leaf, fetching everything, opens nothing of the generation that excludes it;
//   - a leaf's and a wrapped rotation race for g+1: one gen/<g+1>, every holder converging on it;
//   - a claim's lost answer, retried: one success, the same commitment;
//   - a rotation killed before its claim resumes from its keychain draft with the same bytes after a restart, which
//     reaches another gkm instance over the same stores;
//   - a commit whose header generation is below its predecessor's, made with the real subset past the client's own
//     checks, is refused by gkm;
//   - a delivery to a non-holder: a hostile leaf claims a generation whose leaf_wrap lies under an epoch whose tree
//     still holds a revoked leaf, which gkm, seeing no tree, takes; every member judging it poisons it, alarms
//     naming the hostile leaf, and rotates REMOVE past it, the revoked leaf reaching nothing of that rotation;
//   - kills before and after the wrap, gen/ and epoch/ writes: a wrapped writer's REMOVE rotation and the writer
//     leaf's Remove carrying it, the writer of one of those writes and gkm killed there, each restart resuming from
//     its keychain: one REMOVE generation, the Remove carrying it, every holder converging and the revoked leaf
//     reaching nothing of it;
//   - 6.6's added rows: a rotator at a stale tip refuses to claim past a generation pinned above its state, and gkm
//     refuses a claim whose auth is below gen/<g>'s; one device's last-resort KeyPackage serves two Adds in two
//     groups, and it joins both.

import (
	"bytes"
	"errors"
	"net/http"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// FS-15: an agent's ReaderWraps reopen the gate while every leaf is offline; the read_only leaf's self-update waits
// under R3 until the returning writer leaf's Remove, which carries the newest GenWrap; the removed leaf opens nothing
// of the REMOVE generation.
func FsKeysScheduleWrappedRotation(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	c := world.AddMember("c", true)
	x := world.AddMember("x", false)
	d := world.AddAgent("d")
	world.Grant(true, a, b, x, d)
	world.Grant(false, c)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	if key, err := d.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || key.Generation() != 1 {
		t.Fatalf("the agent's first wrap: %v", err)
	}

	// x is revoked, and every leaf is offline: the agent alone takes the state
	world.Revoke(x)
	for _, device := range []*FsKeysDevice{a, b, c, x} {
		device.Offline = true
	}
	view := world.Advance()
	key2, err := d.Client.EnsureWritable(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatalf("the agent's rotation: %v", err)
	}
	generation2 := world.Generation(2)
	if key2.Generation() != 2 || sidecar.GkmCause(generation2.Rotate.GetCause()) != sidecar.GkmCauseRemove {
		t.Fatalf("the agent's rotation is generation %d, cause %d", key2.Generation(), generation2.Rotate.GetCause())
	}
	if generation2.Rotate.GetLeafWrap() != nil {
		t.Errorf("a rotator that is no leaf wrote a leaf_wrap")
	}
	if !sidecar.GkmGatePasses(view, world.RepoId, generation2.Rotate.GetAuth(), world.GenerationTime(generation2), world.Clock.Now()) {
		t.Errorf("the gate does not reopen at the REMOVE generation")
	}
	recipients := world.WrapRecipients(2)
	for _, device := range []*FsKeysDevice{a, b, c} {
		if !recipients[device.SidecarId()] {
			t.Errorf("no ReaderWrap of generation 2 to %s", device.Label)
		}
	}
	if recipients[x.SidecarId()] {
		t.Fatalf("a ReaderWrap of generation 2 to the removed leaf")
	}
	epochBefore := world.NewestEpoch()

	// c returns first: its due self-update waits while x's leaf stands, and commits nothing
	c.Offline = false
	c.Take(view)
	if err := c.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the read_only leaf's sync: %v", err)
	}
	if err := c.Client.SelfUpdate(world.Ctx, world.RepoId); err == nil {
		t.Fatalf("the read_only leaf committed while the removed leaf stands")
	}
	if world.NewestEpoch() != epochBefore {
		t.Fatalf("a commit landed while the removed leaf stands")
	}

	// a returns and, as its resync runs, takes generation 2 from its ReaderWrap, then commits the Remove first,
	// carrying generation 2's GenWrap
	a.Offline = false
	a.Take(view)
	if err := a.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the returning leaf's sync: %v", err)
	}
	if err := a.Client.RunPending(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the returning leaf's pending run: %v", err)
	}
	removeEpoch := world.NewestEpoch()
	if removeEpoch != epochBefore+1 {
		t.Fatalf("the returning leaf committed %d epochs", removeEpoch-epochBefore)
	}
	if header := world.EpochObject(removeEpoch).GetHeader(); header.GetGeneration() != 2 {
		t.Errorf("the Remove carries generation %d's GenWrap", header.GetGeneration())
	}
	if labels := world.Roster(a); labels != "abc" {
		t.Errorf("the tree after the Remove: %s", labels)
	}

	// c's self-update lands once it has processed the Remove
	if err := c.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the read_only leaf's sync: %v", err)
	}
	if err := c.Client.SelfUpdate(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the read_only leaf's self-update after the Remove: %v", err)
	}
	if world.NewestEpoch() != removeEpoch+1 {
		t.Errorf("the read_only leaf's self-update did not land")
	}
	for _, device := range []*FsKeysDevice{a, b, c} {
		device.Offline = false
		device.Take(world.Log.Tip())
		if err := device.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
			t.Fatalf("%s's sync: %v", device.Label, err)
		}
		if key, err := device.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 {
			t.Errorf("%s does not hold generation 2: %v", device.Label, err)
		}
	}
	world.AgreeOnEpoch(a, b, c)

	// x, fetching every epoch and wrap gkm stores, opens nothing at or above generation 2, and keeps generation 1,
	// which it held
	if reached := world.RemovedReach(x); reached != 1 {
		t.Errorf("the removed leaf reaches generation %d", reached)
	}
}

// FS-15: a leaf's rotation and the agent's race for gen/2, the leaf's claim landing while the agent's is on its way:
// one gen/2, the agent's 412 judged and adopted, since it covers what the agent rotated for, and every holder
// converging on it.
func FsKeysScheduleRotationRace(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	d := world.AddAgent("d")
	world.Grant(true, a, b, d)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	if _, err := d.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	// the agent's claim of gen/2 is held at the transport while a rotates and claims it
	var leafKey *sidecar.EvsRepoKey
	held := false
	d.Transport.Before = func(request *http.Request) FsKeysFault {
		if request.Method != http.MethodPost || !FsKeysGenerationClaim(request.URL.Path, 2) || held {
			return FsKeysFaultNone
		}
		held = true
		key, err := a.Client.RotateRepo(world.Ctx, world.RepoId)
		if err != nil {
			t.Errorf("the leaf's rotation: %v", err)
		}
		leafKey = key
		return FsKeysFaultNone
	}
	agentKey, err := d.Client.RotateRepo(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatalf("the agent's rotation: %v", err)
	}
	if !held || leafKey == nil {
		t.Fatal("the race did not happen")
	}
	if world.GenerationCount() != 2 {
		t.Fatalf("gkm holds %d generations", world.GenerationCount())
	}
	if !bytes.Equal(agentKey.Commitment(), leafKey.Commitment()) || agentKey.Generation() != 2 {
		t.Errorf("the agent did not adopt the winner")
	}
	if !bytes.Equal(world.Generation(2).Rotate.GetCommitment(), leafKey.Commitment()) {
		t.Errorf("gen/2 is not the leaf's")
	}
	if err := b.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	for _, device := range []*FsKeysDevice{a, b, d} {
		key, err := device.Client.CurrentRepoKey(world.Ctx, world.RepoId)
		if err != nil || !bytes.Equal(key.Commitment(), leafKey.Commitment()) {
			t.Errorf("%s does not converge on gen/2: %v", device.Label, err)
		}
	}
}

// FS-15: a claim gkm takes whose answer is lost is sent again, and the retry is one success with the same
// commitment; a rotation killed before its claim leaves its draft in the keychain, and its device's restart, whose
// client reaches another gkm instance over the same stores, claims with the same bytes.
func FsKeysScheduleLostAndKilledClaims(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	world.Grant(true, a, b)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)

	// the lost answer: gkm claims gen/2, the answer never reaches a
	dropped := 0
	a.Transport.Before = func(request *http.Request) FsKeysFault {
		if request.Method == http.MethodPost && FsKeysGenerationClaim(request.URL.Path, 2) && dropped == 0 {
			dropped += 1
			return FsKeysFaultDropAnswer
		}
		return FsKeysFaultNone
	}
	key2, err := a.Client.RotateRepo(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatalf("the rotation whose claim's answer was lost: %v", err)
	}
	if dropped != 1 || world.GenerationCount() != 2 || !bytes.Equal(world.Generation(2).Rotate.GetCommitment(), key2.Commitment()) {
		t.Fatalf("one gen/2, the rotator's: %d dropped, %d generations", dropped, world.GenerationCount())
	}

	// the kill: the claim of gen/3 never leaves a, which keeps its draft
	a.Transport.Before = func(request *http.Request) FsKeysFault {
		if request.Method == http.MethodPost && FsKeysGenerationClaim(request.URL.Path, 3) {
			return FsKeysFaultFailBefore
		}
		return FsKeysFaultNone
	}
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err == nil {
		t.Fatal("a rotation whose claim never left answered")
	}
	if !a.HoldsRotateDraft() {
		t.Fatal("the killed rotation left no draft")
	}
	staged := world.WrapRecipients(3)
	// a restarts, its client on another gkm instance over the same stores
	world.RestartEngine()
	a.Transport.Before = nil
	a.Restart()
	key3, err := a.Client.RotateRepo(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatalf("the restarted rotation: %v", err)
	}
	if key3.Generation() != 3 || world.GenerationCount() != 3 {
		t.Fatalf("the restarted rotation is generation %d of %d", key3.Generation(), world.GenerationCount())
	}
	if !bytes.Equal(world.Generation(3).Rotate.GetCommitment(), key3.Commitment()) {
		t.Errorf("gen/3 is not the draft's")
	}
	if a.HoldsRotateDraft() {
		t.Errorf("the claimed rotation kept its draft")
	}
	// the staged deliveries the killed run wrote are the draft's: the restart wrote them again under the same bytes
	for recipient := range staged {
		if !world.WrapRecipients(3)[recipient] {
			t.Errorf("a delivery the draft staged is gone")
		}
	}
	if err := b.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if key, err := b.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || !bytes.Equal(key.Commitment(), key3.Commitment()) {
		t.Errorf("b does not hold the restarted claim's generation: %v", err)
	}
}

// FS-15: a commit whose header carries a generation below its predecessor's, made on the real subset past every
// client check, is refused by gkm and stands nowhere; the twin at the newest generation is taken.
func FsKeysScheduleCommitBelowItsPredecessor(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	world.Grant(true, a, b)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	// an epoch carrying generation 2, then a's path commit claiming generation 1
	if err := a.Client.SelfUpdate(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("a's self-update at generation 2: %v", err)
	}
	newest := world.NewestEpoch()
	if world.EpochObject(newest).GetHeader().GetGeneration() != 2 {
		t.Fatalf("the newest epoch carries generation %d", world.EpochObject(newest).GetHeader().GetGeneration())
	}
	status := world.InjectPathCommit(a, 1)
	if status != http.StatusForbidden {
		t.Errorf("a commit below its predecessor's generation: %d", status)
	}
	if world.NewestEpoch() != newest {
		t.Fatalf("the refused commit stands")
	}
	if status := world.InjectPathCommit(a, 2); status != http.StatusOK {
		t.Errorf("the twin at the newest generation: %d", status)
	}
}

// Claims the repo's next generation as device, past every check its client makes, as a hostile leaf would: cause
// REMOVE at its own state, its holders counted there, and one leaf_wrap under the KEK of the epoch it holds, whatever
// that epoch's tree holds. gkm's answer.
func (self *FsKeysWorld) InjectLeafWrapRotation(device *FsKeysDevice) int {
	self.t.Helper()
	return self.InjectRotation(device, device.state.Pin(), sidecar.GkmCauseRemove, true)
}

// Claims the repo's next generation as device, past every check its client makes: of cause, at pin, its holders
// counted at the state pin names, with one leaf_wrap under the KEK of the epoch device holds when leafWrap says so.
// gkm's answer.
func (self *FsKeysWorld) InjectRotation(device *FsKeysDevice, pin *bridge.AuthPin, cause sidecar.GkmCause, leafWrap bool) int {
	self.t.Helper()
	newest := uint64(self.GenerationCount())
	key, err := device.Client.RepoKey(self.Ctx, self.RepoId, newest)
	if err != nil {
		self.t.Fatalf("%s's generation %d: %v", device.Label, newest, err)
	}
	now := self.Clock.Now()
	state, err := self.Log.Tip().At(pin)
	if err != nil {
		self.t.Fatal(err)
	}
	holders, err := sidecar.KeyHolders(state, self.RepoId, now)
	if err != nil {
		self.t.Fatal(err)
	}
	args := &sidecar.GkmGenerationArgs{Cause: cause, Auth: pin, Time: now, HoldersSha256: holders.Sha256()}
	if leafWrap {
		group, err := device.Mls.LoadGroup(self.GroupId)
		if err != nil {
			self.t.Fatal(err)
		}
		if args.LeafWrapKek, err = sidecar.MlsKek(group, self.RepoId); err != nil {
			self.t.Fatal(err)
		}
		args.LeafWrapEpoch = group.Epoch()
	}
	_, rotate, err := key.NextGeneration(args)
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGenRotate(rotate, device.signer.Sign)
	if err != nil {
		self.t.Fatal(err)
	}
	err = device.Api.ClaimGeneration(self.Ctx, self.RepoId, self.GroupId, newest+1, signed)
	if err == nil {
		return http.StatusOK
	}
	if gkmError, ok := sidecar.GkmErrorOf(err); ok {
		return gkmError.Status
	}
	self.t.Fatalf("the injected rotation: %v", err)
	return 0
}

// Whether device raised a refusal naming committer.
func (self *FsKeysDevice) RefusedBy(committer *FsKeysDevice) bool {
	for _, alarm := range self.Alarms {
		if alarm.Kind == sidecar.GkmAlarmRefused && alarm.SidecarId == committer.SidecarId() {
			return true
		}
	}
	return false
}

// FS-15: a delivery to a non-holder makes members alarm and rotate. x is revoked and no Remove has landed, so the
// tree still holds x's leaf; the hostile leaf h claims generation 2 with a leaf_wrap under the KEK of that tree's
// epoch, which x holds, and gkm, which reads no tree, takes it. a, judging generation 2, poisons it and alarms
// naming h. A commit must carry gen/'s newest, the poisoned generation, so a's leaf waits and its EnsureWritable
// rotates REMOVE past it by ReaderWraps to the leaves it holds as holders, wrapping nothing into the tree that holds
// x; its pending run then commits the Remove carrying that generation. x reaches the poisoned generation, as h
// meant, and nothing of the one past it.
func FsKeysScheduleDeliveryToANonHolder(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	h := world.AddMember("h", false)
	x := world.AddMember("x", false)
	world.Grant(true, a, h, x)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	world.Revoke(x)
	world.Advance()
	if status := world.InjectLeafWrapRotation(h); status != http.StatusOK {
		t.Fatalf("gkm refused the hostile rotation, which it cannot judge: %d", status)
	}
	// the sync takes the poisoned generation as refused, whatever it answers
	a.Client.SyncRepo(world.Ctx, world.RepoId)
	if !a.RefusedBy(h) {
		t.Errorf("a raised no refusal naming the hostile leaf: %+v", a.Alarms)
	}
	key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatalf("a's EnsureWritable past the poisoned generation: %v", err)
	}
	if key.Generation() != 3 || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("a seals to generation %d, cause %d", key.Generation(), key.Cause())
	}
	if world.Generation(3).Rotate.GetLeafWrap() != nil {
		t.Errorf("generation 3 carries a leaf_wrap while the tree holds the revoked leaf")
	}
	recipients := world.WrapRecipients(3)
	if !recipients[h.SidecarId()] || recipients[x.SidecarId()] {
		t.Errorf("generation 3's ReaderWraps: to h %v, to x %v", recipients[h.SidecarId()], recipients[x.SidecarId()])
	}
	if err := a.Client.RunPending(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("a's Remove: %v", err)
	}
	if labels := world.Roster(a); labels != "ah" {
		t.Errorf("the tree past the Remove: %s", labels)
	}
	if header := world.EpochObject(world.NewestEpoch()).GetHeader(); header.GetGeneration() != 3 {
		t.Errorf("the Remove carries generation %d", header.GetGeneration())
	}
	if reached := world.RemovedReach(x); reached != 2 {
		t.Errorf("the revoked leaf reaches generation %d, not the poisoned 2 alone", reached)
	}
}

// FS-15, 6.6's stale tip: b, its state left behind while a rotates at a newer one, refuses to claim past gen/2, whose
// pin is above its tip (ErrGkmAuthAhead); gkm refuses a claim of gen/3 pinned below gen/2's auth; and once b takes
// the newest state it takes gen/2 and its next rotation lands.
func FsKeysScheduleStaleTipClaimRefused(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	world.Grant(true, a, b)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	stale := world.Log.Tip()
	b.Offline = true
	c := world.AddAgent("c")
	world.Grant(false, c)
	world.Advance()
	world.Publish()
	if key, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 {
		t.Fatalf("a's rotation at the newer state: %v", err)
	}
	b.Offline = false
	if _, err := b.Client.RotateRepo(world.Ctx, world.RepoId); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a rotation at a stale tip: %v", err)
	}
	if world.GenerationCount() != 2 {
		t.Fatalf("a stale rotator claimed: %d generations", world.GenerationCount())
	}
	if status := world.InjectRotation(a, stale.Pin(), sidecar.GkmCauseRequest, false); status != http.StatusForbidden {
		t.Errorf("a claim pinned below gen/2's auth: %d", status)
	}
	if world.GenerationCount() != 2 {
		t.Fatalf("the refused claim stands")
	}
	// at the newest state b takes gen/2, newer and covering, and claims nothing; its next rotation claims gen/3
	b.Take(world.Log.Tip())
	if key, err := b.Client.RotateRepo(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 || world.GenerationCount() != 2 {
		t.Errorf("b's first rotation at the newest state: %v", err)
	}
	if key, err := b.Client.RotateRepo(world.Ctx, world.RepoId); err != nil || key.Generation() != 3 {
		t.Errorf("b's rotation at the newest state: %v", err)
	}
}

// One last-resort KeyPackage and nothing else, uploaded with the device's ReaderKey: a device whose one-time ones
// are spent.
func (self *FsKeysDevice) PublishLastResortOnly() {
	world := self.world
	world.t.Helper()
	self.published = true
	self.PublishReaderKey()
	keyPackage, err := self.Mls.CreateKeyPackage(true)
	if err != nil {
		world.t.Fatal(err)
	}
	world.Again(self.Label+"'s last-resort KeyPackage", func() error { return self.Api.UploadKeyPackages(world.Ctx, [][]byte{keyPackage.Encoded}) })
}

// FS-15, 6.6's last-resort row: c's one KeyPackage is its last-resort one, which serves the Adds of both the config
// group and the repo's; c joins both, each Welcome found by its pointer, keyed by group and epoch, and notes the
// last-resort join it owes a path for.
func FsKeysScheduleLastResortInTwoGroups(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	c := world.AddMember("c", false)
	world.Grant(true, a)
	world.Grant(false, c)
	world.Admin(a)
	world.ConfigWriters(a)
	world.Advance()
	c.PublishLastResortOnly()
	world.Publish()
	world.CreateConfig(a)
	world.Create(a)
	world.Again("a's pending run in the config group", func() error { return a.Client.RunPending(world.Ctx, world.ConfigRepoId) })
	world.Again("a's pending run in the repo's group", func() error { return a.Client.RunPending(world.Ctx, world.RepoId) })
	joined, err := c.Client.JoinWelcomes(world.Ctx)
	if err != nil {
		t.Fatalf("c's joins: %v", err)
	}
	if len(joined) != 2 {
		t.Errorf("c joined %d groups through its last-resort KeyPackage", len(joined))
	}
	for _, groupId := range world.groupIds() {
		if labels := world.RosterIn(c, groupId); labels != "ac" {
			t.Errorf("group %s's tree as c holds it: %s", groupId, labels)
		}
		world.AgreeOnEpochIn(groupId, a, c)
	}
	if c.Client.LastResortJoinedAt().IsZero() {
		t.Errorf("c noted no last-resort join")
	}
}

// FS-15's kills: for each of the wrap, gen/ and epoch/ writes, before it leaves and after gkm took it, the agent w's
// REMOVE rotation past x's revocation and a's Remove carrying it, the writer of that write killed there: from then on
// every request of its process fails, as a dead process's does, and gkm dies with it. Their restarts, gkm's on
// another instance over the same stores, resume from the keychain: one REMOVE generation, the Remove carrying gen/'s
// newest as it lands, b converging, x reaching nothing of either. a learns of w's rotation, which commits nothing, by
// gkm:<group_id>'s hint (FS-24), whose work, SyncRepo, runs before its pending run.
func FsKeysScheduleKillsBetweenWrites(t FsKeysT, newWorld FsKeysNewWorld) {
	for _, kill := range []struct {
		segment string
		after   bool
	}{{"wraps", false}, {"wraps", true}, {"gen", false}, {"gen", true}, {"epochs", false}, {"epochs", true}} {
		name := kill.segment
		if kill.after {
			name += " after"
		}
		world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
		a := world.AddMember("a", false)
		b := world.AddMember("b", false)
		x := world.AddMember("x", false)
		w := world.AddAgent("w")
		world.Grant(true, a, b, x, w)
		world.Admin(a)
		world.Advance()
		world.Publish()
		world.Create(a)
		world.AddPending(a)
		world.Again("w's first wrap", func() error {
			_, err := w.Client.CurrentRepoKey(world.Ctx, world.RepoId)
			return err
		})
		world.Revoke(x)
		x.Offline = true
		world.Advance()
		victim := w
		if kill.segment == "epochs" {
			victim = a
		}
		dead := false
		victim.Transport.Before = func(request *http.Request) FsKeysFault {
			if dead {
				return FsKeysFaultFailBefore
			}
			parts := strings.Split(request.URL.Path, "/")
			if request.Method == http.MethodPost && 5 < len(parts) && parts[2] == "groups" && parts[4] == kill.segment {
				dead = true
				if kill.after {
					return FsKeysFaultDropAnswer
				}
				return FsKeysFaultFailBefore
			}
			return FsKeysFaultNone
		}
		// the flows up to the kill, each failing once its process is dead
		w.Client.EnsureWritable(world.Ctx, world.RepoId)
		a.Client.SyncRepo(world.Ctx, world.RepoId)
		a.Client.RunPending(world.Ctx, world.RepoId)
		if !dead {
			t.Fatalf("%s: the kill never came", name)
		}
		victim.Transport.Before = nil
		world.RestartEngine()
		victim.Restart()
		world.Again(name+": w's rotation after the kill", func() error {
			_, err := w.Client.EnsureWritable(world.Ctx, world.RepoId)
			return err
		})
		world.Again(name+": a's sync after the kill", func() error { return a.Client.SyncRepo(world.Ctx, world.RepoId) })
		world.Again(name+": a's Remove after the kill", func() error { return a.Client.RunPending(world.Ctx, world.RepoId) })
		if count := world.GenerationCount(); count != 2 || sidecar.GkmCause(world.Generation(2).Rotate.GetCause()) != sidecar.GkmCauseRemove {
			t.Errorf("%s: %d generations past the kill", name, count)
			continue
		}
		if labels := world.Roster(a); labels != "ab" {
			t.Errorf("%s: the tree after the Remove: %s", name, labels)
		}
		// the Remove carries gen/'s newest as it lands: generation 1 where w died before its claim, so a's Remove
		// landed first and w's resumed claim followed, else 2
		carried := uint64(2)
		if kill.segment == "wraps" || kill.segment == "gen" && !kill.after {
			carried = 1
		}
		if header := world.EpochObject(world.NewestEpoch()).GetHeader(); header.GetGeneration() != carried {
			t.Errorf("%s: the Remove carries generation %d, not %d", name, header.GetGeneration(), carried)
		}
		world.Again("b's sync", func() error { return b.Client.SyncRepo(world.Ctx, world.RepoId) })
		if key, err := b.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 {
			t.Errorf("%s: b does not hold generation 2: %v", name, err)
		}
		if reached := world.RemovedReach(x); reached != 1 {
			t.Errorf("%s: the revoked leaf reaches generation %d", name, reached)
		}
	}
}
