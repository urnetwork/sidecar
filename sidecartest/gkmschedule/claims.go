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
//     checks, is refused by gkm.

import (
	"bytes"
	"net/http"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
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
