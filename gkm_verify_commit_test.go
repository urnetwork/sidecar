// §10.9's committer and check rows on fixtures (KEYS-M2-19, DESIGN-DETAILS 6.6): one success and one refusal per
// row, the roster rule's refusals with their poison verdict, S3's forged admission and KeyPackage, and the judged
// row's wait, fork and not-judged answers. FakeMls stages the commits, and FS-104's oracle is separate code.

package sidecar_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A world whose group stands at epoch 1 under generation 1: writers a and b, reader c, read_only reader p and
// reader x, every one a leaf, at the log's first position.
type gkmCommitWorld struct {
	*gkmWorld
	a, b, c, p, x *gkmWorldDevice
	first         *sidecartest.FakeGkmAuthView
	gen1          *gkmWorldGeneration
	// epoch 1's header
	header *protocol.GkmCommitHeader
}

func newGkmCommitWorld(t *testing.T, kind protocol.RepoKind) *gkmCommitWorld {
	world := &gkmCommitWorld{gkmWorld: newGkmWorld(t, kind)}
	world.a = world.admit("a")
	world.b = world.admit("b")
	world.c = world.admit("c")
	world.p = world.admit("p")
	world.p.row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	world.x = world.admit("x")
	world.grant(true, world.a, world.b)
	world.grant(false, world.c, world.p, world.x)
	world.first = world.state()
	world.createGroup(world.a)
	world.gen1 = world.generation(world.first, world.a, nil, sidecar.GkmCauseRequest, nil)
	joiners := []*gkmWorldDevice{world.b, world.c, world.p, world.x}
	staged := world.stage(world.a, 1, world.first.Pin(), joiners, nil)
	world.adopt(world.a, staged, joiners...)
	world.header = &protocol.GkmCommitHeader{Generation: 1, Auth: world.first.Pin()}
	return world
}

// CheckCommit of staged as receiver judges it at view, under generation 1 and epoch 1's header.
func (self *gkmCommitWorld) check(view sidecar.GkmAuthView, receiver *gkmWorldDevice, staged sidecar.MlsStagedCommit) (*sidecar.GkmCommitCheck, error) {
	self.t.Helper()
	received := staged
	if receiver.group.Self().SidecarId != staged.Committer().SidecarId {
		received = self.receive(receiver, staged)
	}
	return sidecar.CheckCommit(view, receiver.group, received, &sidecar.GkmCommitCheckArgs{
		RepoId:         self.repoId,
		PreviousHeader: self.header,
		Generation:     self.gen1.generation,
		GenWrap:        self.genWrap(staged, self.gen1),
		Time:           self.now,
		Now:            self.now,
	})
}

// Fails unless the commit passes.
func (self *gkmCommitWorld) expectPass(label string, view sidecar.GkmAuthView, receiver *gkmWorldDevice, staged sidecar.MlsStagedCommit) *sidecar.GkmCommitCheck {
	self.t.Helper()
	check, err := self.check(view, receiver, staged)
	if err != nil {
		self.t.Fatalf("%s: %v", label, err)
	}
	if !check.Verdict.Passed() {
		self.t.Fatalf("%s: refused: %s (%s)", label, check.Verdict.Reason, check.Verdict.Detail)
	}
	return check
}

// Fails unless the commit is refused for reason, poisoning poisoned.
func (self *gkmCommitWorld) expectRefused(label string, view sidecar.GkmAuthView, receiver *gkmWorldDevice, staged sidecar.MlsStagedCommit, reason sidecar.GkmRefusalReason, poisoned uint64) {
	self.t.Helper()
	check, err := self.check(view, receiver, staged)
	if err != nil {
		self.t.Fatalf("%s: %v", label, err)
	}
	if !check.Verdict.Refused || check.Verdict.Reason != reason || check.Verdict.Poisoned != poisoned {
		self.t.Errorf("%s: verdict %+v, want refused for %s poisoning %d", label, check.Verdict, reason, poisoned)
	}
}

// The Add row: a writer leaf adds a member device that reads the repo at the pin, and a member refuses an Add of a
// non-reader, of a revoked device, of an agent, by a leaf that does not write and by a read_only leaf.
func TestCheckCommitAddRow(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	d := world.admit("d")
	nonReader := world.admit("non-reader")
	revoked := world.admit("revoked")
	agent := world.admit("agent", sidecar.NewId())
	world.grant(false, d, revoked, agent)
	world.revoke(revoked)
	world.repo.HoldersShrunkAt = 0
	second := world.state()

	check := world.expectPass("a writer leaf's Add of a reader", second, world.b, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{d}, nil))
	if len(check.Roster) != 6 || check.Key == nil || check.Key.Generation() != 1 {
		t.Errorf("the passed commit's roster of %d and key %v", len(check.Roster), check.Key)
	}
	// the committer runs the same check on its own staged commit before it uploads it
	world.expectPass("the committer's own check", second, world.a, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{d}, nil))

	world.expectRefused("an Add of a non-reader", second, world.b, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{nonReader}, nil), sidecar.GkmRefusalAdd, 0)
	world.expectRefused("an Add of a revoked device", second, world.b, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{revoked}, nil), sidecar.GkmRefusalCredential, 0)
	world.expectRefused("an Add of an agent as a leaf", second, world.b, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{agent}, nil), sidecar.GkmRefusalAdd, 0)
	world.expectRefused("an Add by a leaf that does not write", second, world.b, world.stage(world.c, 1, second.Pin(), []*gkmWorldDevice{d}, nil), sidecar.GkmRefusalCommitter, 0)
	world.expectRefused("an Add by a read_only leaf", second, world.b, world.stage(world.p, 1, second.Pin(), []*gkmWorldDevice{d}, nil), sidecar.GkmRefusalCommitter, 0)
}

// S3: a KeyPackage whose credential names an admission the log does not hold, and one under a second identity key
// for an admitted sidecar, are refused at the Add, and the engine's admission check refuses the same leaves.
func TestCheckCommitRefusesAForgedAdmissionAndASecondIdentityKey(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	d := world.admit("d")
	world.grant(false, d)
	second := world.state()

	// d's own key over another admission
	forgedAdmission := sha256.Sum256([]byte("an admission the log never held"))
	forged := &gkmWorldDevice{label: "forged admission", signer: d.signer, id: d.id, row: d.row}
	forged.credential = world.credential(forged, forgedAdmission[:], world.now.Add(90*24*time.Hour))
	forged.mls = world.mlsWorld.Engine(forged.id, forged.credential)
	world.expectRefused("a forged admission", second, world.b, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{forged}, nil), sidecar.GkmRefusalCredential, 0)

	// another key claiming d's sidecar_id and d's admission
	thief := sidecartest.NewFakeGkmSigner()
	thief.SidecarId = d.id
	second2 := &gkmWorldDevice{label: "second key", signer: thief, id: d.id, row: d.row}
	second2.credential = world.credential(second2, d.row.GetAdmissionSha256(), world.now.Add(90*24*time.Hour))
	second2.mls = world.mlsWorld.Engine(second2.id, second2.credential)
	world.expectRefused("a second identity key", second, world.b, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{second2}, nil), sidecar.GkmRefusalCredential, 0)

	// the engine's check on every leaf it takes in
	admission := sidecar.NewGkmCredentialCheck(func() sidecar.GkmAuthView { return second })
	parse := func(credential []byte) *protocol.UrMlsCredential {
		parsed, err := sidecar.CheckUrMlsCredential(credential)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	if err := admission(parse(d.credential)); err != nil {
		t.Errorf("an admitted credential: %v", err)
	}
	if err := admission(parse(forged.credential)); !errors.Is(err, sidecar.ErrGkmNotAdmitted) {
		t.Errorf("a forged admission at the engine: %v", err)
	}
	if err := admission(parse(second2.credential)); !errors.Is(err, sidecar.ErrGkmNotAdmitted) || !errors.Is(err, sidecar.ErrMlsIdentityPin) {
		t.Errorf("a second identity key at the engine: %v", err)
	}
	if err := sidecar.NewGkmCredentialCheck(func() sidecar.GkmAuthView { return nil })(parse(d.credential)); !errors.Is(err, sidecar.ErrGkmNotAdmitted) {
		t.Errorf("a credential before any state: %v", err)
	}
	// the pin §6's Hello shares
	pinned := sidecar.GkmPinnedIdentityKey(second)
	if err := sidecar.CheckMlsIdentityPin(pinned, &sidecar.MlsIdentityPin{SidecarId: d.id, IdentityPublicKey: thief.PublicKey()}); !errors.Is(err, sidecar.ErrMlsIdentityPin) {
		t.Errorf("a second key against the log's pin: %v", err)
	}
}

// The Remove row: a writer leaf removes a revoked leaf, and a member refuses a Remove with no input and one by a
// leaf that does not write.
func TestCheckCommitRemoveRow(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.revoke(world.x)
	second := world.state()

	world.expectPass("a writer leaf's Remove of a revoked leaf", second, world.b, world.stage(world.a, 1, second.Pin(), nil, []*gkmWorldDevice{world.x}))
	world.expectRefused("a Remove of a reader with no input", second, world.b, world.stage(world.a, 1, second.Pin(), nil, []*gkmWorldDevice{world.x, world.c}), sidecar.GkmRefusalRemove, 0)
	world.expectRefused("a Remove by a leaf that does not write", second, world.b, world.stage(world.c, 1, second.Pin(), nil, []*gkmWorldDevice{world.x}), sidecar.GkmRefusalCommitter, 0)
	world.expectRefused("a Remove by a read_only leaf", second, world.b, world.stage(world.p, 1, second.Pin(), nil, []*gkmWorldDevice{world.x}), sidecar.GkmRefusalCommitter, 0)
}

// R3: a member refuses a commit that adds a reader and omits a needed Remove, and a path-only commit over a tree
// that holds a dropped leaf, naming the generation their GenWrap carried as poisoned; the same commits with the
// Remove pass, and a commit judged at a pin before the drop passes at a later tip.
func TestAMemberRefusesACommitThatOmitsANeededRemove(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	d := world.admit("d")
	world.grant(false, d)
	world.revoke(world.x)
	second := world.state()

	world.expectRefused("an Add that leaves a dropped leaf", second, world.b, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{d}, nil), sidecar.GkmRefusalRoster, 1)
	world.expectRefused("a read_only leaf's self-update over a dropped leaf", second, world.b, world.stage(world.p, 1, second.Pin(), nil, nil), sidecar.GkmRefusalRoster, 1)
	world.expectRefused("the committer's own check of the same self-update", second, world.p, world.stage(world.p, 1, second.Pin(), nil, nil), sidecar.GkmRefusalRoster, 1)
	world.expectPass("one commit carrying the Remove and the Add", second, world.b, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{d}, []*gkmWorldDevice{world.x}))
	// judged at its own pin, never at the tip: a self-update made before the revocation
	world.expectPass("a self-update at the pin before the drop", second, world.b, world.stage(world.p, 1, world.first.Pin(), nil, nil))
}

// R1 and R2: a pin above the tip waits, one off the chain is a fork, one before what is retained is not judged, and
// one below the previous epoch's or the carried generation's is refused.
func TestCheckCommitJudgesAtItsPin(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	second := world.state()
	third := world.state()

	staged := world.stage(world.a, 1, third.Pin(), nil, nil)
	if _, err := world.check(second, world.b, staged); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a pin above the tip: %v", err)
	}
	world.expectPass("the same commit once the log reaches it", third, world.b, staged)

	fork := world.stage(world.a, 1, sidecartest.FakeGkmForkPin(2), nil, nil)
	check, err := world.check(third, world.b, fork)
	if err != nil || !check.Verdict.Refused || !check.Verdict.Fork || check.Verdict.Reason != sidecar.GkmRefusalFork {
		t.Errorf("a pin off the chain: %+v %v", check, err)
	}

	// the previous epoch's pin is the floor
	world.header = &protocol.GkmCommitHeader{Generation: 1, Auth: second.Pin()}
	world.expectRefused("a pin below the previous epoch's", third, world.b, world.stage(world.a, 1, world.first.Pin(), nil, nil), sidecar.GkmRefusalPinFloor, 0)
	world.header = &protocol.GkmCommitHeader{Generation: 2, Auth: world.first.Pin()}
	world.expectRefused("a generation below the previous epoch's", third, world.b, world.stage(world.a, 1, third.Pin(), nil, nil), sidecar.GkmRefusalGenWrap, 0)
	world.header = &protocol.GkmCommitHeader{Generation: 1, Auth: world.first.Pin()}

	// the carried generation's pin is a floor too
	gen2 := world.generation(third, world.a, world.gen1, sidecar.GkmCauseRequest, nil)
	behind := world.stage(world.a, 2, second.Pin(), nil, nil)
	received := world.receive(world.b, behind)
	behindCheck, err := sidecar.CheckCommit(third, world.b.group, received, &sidecar.GkmCommitCheckArgs{
		RepoId: world.repoId, PreviousHeader: world.header, Generation: gen2.generation, GenWrap: world.genWrap(behind, gen2), Time: world.now, Now: world.now,
	})
	if err != nil || behindCheck.Verdict.Reason != sidecar.GkmRefusalPinFloor {
		t.Errorf("a pin below the carried generation's: %+v %v", behindCheck, err)
	}

	// a pin before what this reader retains is not judged, and so not adopted
	world.log.Retain(2)
	old := world.stage(world.a, 1, world.first.Pin(), nil, nil)
	check, err = world.check(third, world.b, old)
	if err != nil || !check.Verdict.NotJudged || check.Verdict.Refused || check.Verdict.Passed() {
		t.Errorf("a pin before what is retained: %+v %v", check, err)
	}
}

// R4: the GenWrap opens under the new epoch's KEK to the key gen/<g> commits to, and nothing else passes.
func TestCheckCommitHoldsTheGenWrapToItsGeneration(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	second := world.state()
	staged := world.stage(world.a, 1, second.Pin(), nil, nil)
	received := world.receive(world.b, staged)
	check := func(genWrap []byte) *sidecar.GkmCommitCheck {
		result, err := sidecar.CheckCommit(second, world.b.group, received, &sidecar.GkmCommitCheckArgs{
			RepoId: world.repoId, PreviousHeader: world.header, Generation: world.gen1.generation, GenWrap: genWrap, Time: world.now, Now: world.now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := check(world.genWrap(staged, world.gen1)); !result.Verdict.Passed() || result.Key == nil {
		t.Errorf("the commit's own GenWrap: %+v", result.Verdict)
	}
	// another key of the same number: a generation a second rotator drafted and never claimed
	other := world.generation(world.first, world.a, nil, sidecar.GkmCauseRequest, nil)
	if result := check(world.genWrap(staged, other)); result.Verdict.Reason != sidecar.GkmRefusalGenWrap || result.Key != nil {
		t.Errorf("a GenWrap of a key gen/1 does not commit to: %+v", result.Verdict)
	}
	// the right key under another epoch's KEK
	otherStaged := world.stage(world.b, 1, second.Pin(), nil, nil)
	if result := check(world.genWrap(otherStaged, world.gen1)); result.Verdict.Reason != sidecar.GkmRefusalGenWrap {
		t.Errorf("a GenWrap under another epoch's KEK: %+v", result.Verdict)
	}
	if result := check(nil); result.Verdict.Reason != sidecar.GkmRefusalGenWrap {
		t.Errorf("no GenWrap: %+v", result.Verdict)
	}
}

// The external rows: a resync removing its own old leaf passes; a recovery-admitted device's generation-0
// self-join passes over a tree that still holds a dropped leaf and carries no GenWrap; a generation-0 commit by
// any other device, a self-join with a GenWrap, and a resync over a dropped leaf are refused.
func TestCheckCommitExternalRows(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	recoveryKey := sha256.Sum256([]byte("the member's recovery key"))
	world.members[0].RecoveryKeySha256 = recoveryKey[:]
	world.members[0].Bindings = []*bridge.RecoveryBindingRow{{KeySha256: recoveryKey[:], Signer: world.a.id.Bytes(), At: 1}}
	recovered := world.admit("recovered")
	recovered.row.AdmissionSigners = [][]byte{recoveryKey[:]}
	plain := world.admit("plain")
	world.grant(true, recovered, plain)
	second := world.state()
	groupInfo, err := world.a.group.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	external := func(device *gkmWorldDevice, generation uint64, pin *bridge.AuthPin, removeOld bool) sidecar.MlsStagedCommit {
		args := &sidecar.MlsCommitArgs{Path: true, AuthenticatedData: gkmWorldHeader(t, generation, pin)}
		if removeOld {
			args.Removes = []uint32{world.leafIndex(world.a.group, device)}
		}
		staged, err := device.mls.JoinExternal(groupInfo, args)
		if err != nil {
			t.Fatal(err)
		}
		return staged
	}
	judge := func(view sidecar.GkmAuthView, staged sidecar.MlsStagedCommit, generation *gkmWorldGeneration, genWrap []byte) *sidecar.GkmCommitCheck {
		received := world.receive(world.b, staged)
		args := &sidecar.GkmCommitCheckArgs{RepoId: world.repoId, PreviousHeader: world.header, GenWrap: genWrap, Time: world.now, Now: world.now}
		if generation != nil {
			args.Generation = generation.generation
		}
		result, err := sidecar.CheckCommit(view, world.b.group, received, args)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	resync := external(world.c, 1, second.Pin(), true)
	if result := judge(second, resync, world.gen1, world.genWrap(resync, world.gen1)); !result.Verdict.Passed() || len(result.Roster) != 5 {
		t.Errorf("a resync removing its own old leaf: %+v", result.Verdict)
	}

	// x is revoked and its leaf stands
	world.revoke(world.x)
	third := world.state()
	selfJoin := external(recovered, 0, third.Pin(), false)
	if result := judge(third, selfJoin, nil, nil); !result.Verdict.Passed() || result.Key != nil {
		t.Errorf("a recovery self-join over a dropped leaf: %+v", result.Verdict)
	}
	if result := judge(third, selfJoin, nil, []byte("a GenWrap")); result.Verdict.Reason != sidecar.GkmRefusalGenWrap {
		t.Errorf("a self-join carrying a GenWrap: %+v", result.Verdict)
	}
	notRecovered := external(plain, 0, third.Pin(), false)
	if result := judge(third, notRecovered, nil, nil); result.Verdict.Reason != sidecar.GkmRefusalCommitter {
		t.Errorf("a generation-0 join by a device no recovery admitted: %+v", result.Verdict)
	}
	dirtyResync := external(world.c, 1, third.Pin(), true)
	if result := judge(third, dirtyResync, world.gen1, world.genWrap(dirtyResync, world.gen1)); result.Verdict.Reason != sidecar.GkmRefusalRoster || result.Verdict.Poisoned != 1 {
		t.Errorf("a resync over a dropped leaf: %+v", result.Verdict)
	}
	joinWithGenWrap := external(plain, 1, third.Pin(), false)
	if result := judge(third, joinWithGenWrap, world.gen1, world.genWrap(joinWithGenWrap, world.gen1)); result.Verdict.Reason != sidecar.GkmRefusalRoster {
		t.Errorf("an external join at a generation over a dropped leaf: %+v", result.Verdict)
	}
}

// A state that answers §7.9's stale_leaf_days, wrapping a fixture's.
type gkmWorldStaleView struct {
	sidecar.GkmAuthView
	days uint32
}

func (self gkmWorldStaleView) StaleLeafDays() (uint32, bool) {
	return self.days, 0 < self.days
}

func (self gkmWorldStaleView) At(pin *bridge.AuthPin) (sidecar.GkmAuthView, error) {
	at, err := self.GkmAuthView.At(pin)
	if err != nil {
		return nil, err
	}
	return gkmWorldStaleView{GkmAuthView: at, days: self.days}, nil
}

// The stale row (plan-KEYS-stale-remove-evidence): a Remove of a reading leaf is valid once its credential's
// not_after - 90 d + stale_leaf_days has passed, read from the prior epoch's tree, and refused inside the window and
// at a state that cannot answer the setting.
func TestCheckCommitStaleRemove(t *testing.T) {
	world := newGkmWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.admit("a")
	b := world.admit("b")
	quiet := world.admit("quiet")
	// its leaf last changed 91 days ago
	quiet.credential = world.credential(quiet, quiet.row.GetAdmissionSha256(), world.now.Add(-24*time.Hour))
	quiet.mls = world.mlsWorld.Engine(quiet.id, quiet.credential)
	fresh := world.admit("fresh")
	world.grant(true, a, b)
	world.grant(false, quiet, fresh)
	first := world.state()
	world.createGroup(a)
	gen1 := world.generation(first, a, nil, sidecar.GkmCauseRequest, nil)
	joiners := []*gkmWorldDevice{b, quiet, fresh}
	world.adopt(a, world.stage(a, 1, first.Pin(), joiners, nil), joiners...)
	header := &protocol.GkmCommitHeader{Generation: 1, Auth: first.Pin()}
	judge := func(view sidecar.GkmAuthView, target *gkmWorldDevice, now time.Time) sidecar.GkmVerdict {
		staged := world.stage(a, 1, first.Pin(), nil, []*gkmWorldDevice{target})
		result, err := sidecar.CheckCommit(view, b.group, world.receive(b, staged), &sidecar.GkmCommitCheckArgs{
			RepoId: world.repoId, PreviousHeader: header, Generation: gen1.generation, GenWrap: world.genWrap(staged, gen1), Time: now, Now: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result.Verdict
	}
	stale := gkmWorldStaleView{GkmAuthView: first, days: 90}
	if verdict := judge(stale, quiet, world.now); !verdict.Passed() {
		t.Errorf("a stale Remove 91 days after the leaf's last change: %+v", verdict)
	}
	if verdict := judge(stale, fresh, world.now); verdict.Reason != sidecar.GkmRefusalRemove {
		t.Errorf("a stale Remove inside the window: %+v", verdict)
	}
	if verdict := judge(gkmWorldStaleView{GkmAuthView: first, days: 120}, quiet, world.now); verdict.Reason != sidecar.GkmRefusalRemove {
		t.Errorf("a stale Remove before a longer stale_leaf_days: %+v", verdict)
	}
	if verdict := judge(first, quiet, world.now); verdict.Reason != sidecar.GkmRefusalRemove {
		t.Errorf("a stale Remove at a state that does not answer stale_leaf_days: %+v", verdict)
	}
	// the boundary, with the 60 s of skew: at 91 days the leaf goes stale a day after its not_after, which is now
	boundary := gkmWorldStaleView{GkmAuthView: first, days: 91}
	staleAt := world.now
	if verdict := judge(boundary, quiet, staleAt.Add(-sidecar.GkmMemberClockSkew-time.Millisecond)); verdict.Reason != sidecar.GkmRefusalRemove {
		t.Errorf("a stale Remove one ms before the bound: %+v", verdict)
	}
	if verdict := judge(boundary, quiet, staleAt.Add(-sidecar.GkmMemberClockSkew)); !verdict.Passed() {
		t.Errorf("a stale Remove at the bound: %+v", verdict)
	}
}

// §8.5 and owner decision 126: an owner-bound repo takes the owner's device as a leaf only once consented.
func TestCheckCommitOwnerBoundConsent(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_VAULT)
	consented := world.admit("consented")
	unconsented := world.admit("unconsented")
	world.grant(false, consented, unconsented)
	world.repo.OwnerMemberId = world.memberId.Bytes()
	for _, device := range []*gkmWorldDevice{world.a, world.b, world.c, world.p, world.x, consented} {
		world.repo.ConsentedSidecarIds = append(world.repo.ConsentedSidecarIds, device.id.Bytes())
	}
	second := world.state()
	world.expectPass("a consented device", second, world.b, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{consented}, nil))
	world.expectRefused("an unconsented device", second, world.b, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{unconsented}, nil), sidecar.GkmRefusalAdd, 0)
}

// A state that answers §7.9's leaves rule, wrapping a fixture's: every device is leaf-entitled but those named.
type gkmWorldRankView struct {
	sidecar.GkmAuthView
	wrapped map[sidecar.Id]bool
}

func (self gkmWorldRankView) LeafEntitled(sidecarId sidecar.Id) bool {
	return !self.wrapped[sidecarId]
}

func (self gkmWorldRankView) At(pin *bridge.AuthPin) (sidecar.GkmAuthView, error) {
	at, err := self.GkmAuthView.At(pin)
	if err != nil {
		return nil, err
	}
	return gkmWorldRankView{GkmAuthView: at, wrapped: self.wrapped}, nil
}

// The config group's rows (owner decisions 128, 182): the admission's signer commits the Add it requires from its
// leaf with no writer online, a leaf that neither writes nor signed the admission does not, a device past the
// leaf-entitled 1,000 takes no leaf, and a leaf that lost entitlement is removed with no other input.
func TestCheckCommitConfigGroupRows(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	signed := world.admit("signed by c")
	signed.row.AdmissionSigners = [][]byte{world.c.id.Bytes()}
	other := world.admit("signed by a")
	other.row.AdmissionSigners = [][]byte{world.a.id.Bytes()}
	world.grant(false, signed, other)
	second := world.state()

	world.expectPass("the admission's signer, no writer", second, world.b, world.stage(world.c, 1, second.Pin(), []*gkmWorldDevice{signed}, nil))
	world.expectRefused("a leaf that neither writes nor signed the admission", second, world.b, world.stage(world.c, 1, second.Pin(), []*gkmWorldDevice{other}, nil), sidecar.GkmRefusalCommitter, 0)

	wrapped := gkmWorldRankView{GkmAuthView: second, wrapped: map[sidecar.Id]bool{signed.id: true}}
	world.expectRefused("a leaf for a device past the leaf-entitled 1,000", wrapped, world.b, world.stage(world.c, 1, second.Pin(), []*gkmWorldDevice{signed}, nil), sidecar.GkmRefusalAdd, 0)
	moved := gkmWorldRankView{GkmAuthView: second, wrapped: map[sidecar.Id]bool{world.x.id: true}}
	world.expectPass("a Remove of a leaf that lost entitlement", moved, world.b, world.stage(world.a, 1, second.Pin(), nil, []*gkmWorldDevice{world.x}))
	world.expectRefused("a commit that leaves a leaf with no entitlement", moved, world.b, world.stage(world.a, 1, second.Pin(), nil, nil), sidecar.GkmRefusalRoster, 0)
}

// D-KEYS-2: an Add past 1,000 leaves is refused, and the 1,000th is taken.
func TestCheckCommitRefusesThe1001stLeaf(t *testing.T) {
	world := newGkmWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.admit("a")
	b := world.admit("b")
	world.grant(true, a, b)
	joiners := []*gkmWorldDevice{b}
	for len(joiners) < sidecar.GkmSeatCount-2 {
		device := world.admit("leaf")
		world.grant(false, device)
		joiners = append(joiners, device)
	}
	last := world.admit("the 1,000th")
	over := world.admit("the 1,001st")
	world.grant(false, last, over)
	first := world.state()
	world.createGroup(a)
	gen1 := world.generation(first, a, nil, sidecar.GkmCauseRequest, nil)
	world.adopt(a, world.stage(a, 1, first.Pin(), joiners, nil), b)
	header := &protocol.GkmCommitHeader{Generation: 1, Auth: first.Pin()}
	judge := func(adds ...*gkmWorldDevice) sidecar.GkmVerdict {
		staged := world.stage(a, 1, first.Pin(), adds, nil)
		result, err := sidecar.CheckCommit(first, b.group, world.receive(b, staged), &sidecar.GkmCommitCheckArgs{
			RepoId: world.repoId, PreviousHeader: header, Generation: gen1.generation, GenWrap: world.genWrap(staged, gen1), Time: world.now, Now: world.now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result.Verdict
	}
	if len(a.group.Roster()) != sidecar.GkmSeatCount-1 {
		t.Fatalf("a tree of %d leaves", len(a.group.Roster()))
	}
	if verdict := judge(last); !verdict.Passed() {
		t.Errorf("the 1,000th leaf: %+v", verdict)
	}
	if verdict := judge(last, over); verdict.Reason != sidecar.GkmRefusalAdd {
		t.Errorf("the 1,001st leaf: %+v", verdict)
	}
}
