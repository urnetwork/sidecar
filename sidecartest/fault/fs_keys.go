// FS-15, FS-18, FS-20, FS-22, FS-23, FS-24 and FS-105 (§22.8; §10; KEYS-M2-27, KEYS-M2-28): gkm's schedules from
// sidecartest/gkmschedule, each run on the Net under every rule §22.8 gives its row. The world is gkm's group client
// on the real MLS subset, every device its own engine, keychain and store, against gkmservice's engine on the Net's
// stores, so every one of gkm's store requests passes the Net's fault queue and blob recorder and every barrier the
// client and the engine name reaches the Net's driver (gkmschedule's net.go). A world's failure inside a step, a
// Fatal, ends the step with its error, and an Errorf fails the step at its end.
//
// The rows' checks are FI-3 and FI-4, which are TEST-M2-05's oracles and not bound yet, so a schedule here names
// FsKeysOneLadder, one ladder in each group, in FI-4's place, as fs_team.go names its agreement check; once FI-4
// binds, each schedule adds FI(4) beside it. FI-12 (FS-20) and FI-29 (FS-105) are TEST-M3-01's and KEYS-M2-28's,
// unbound as well: FS-105's oracle is the copy's reach, which the schedule computes itself.
//
// Registered, each on T2 (a T2+T3 row's T3 runs gkmschedule's builders on server's stores in server/gkm, outside this
// registry, until T3's Nets take the store clock the ReaderKey and retention rules read from LastModified):
//
//   - FS-15: a leaf's and a wrapped rotation race for generation 2 as two actors, so the explorer's seeds choose who
//     runs at each of the client's and the engine's barriers, and the row's unknown rule loses each write's answer
//     in turn: one gen/2 in every order, both rotators and the other leaf converging on it.
//   - FS-18: a covered agent's Suspend and what its keys reach after it.
//   - FS-20: an ordinary device's generation-0 external commit refused by gkm, beside its twin, the code-only
//     device's generation-0 self-join over revoked lost leaves.
//   - FS-22: a compromise rebind closing the gate at the old generation, beside a routine one's.
//   - FS-23: a depositor refusing an older drop key after a removal, beside the depositor's honest follow.
//   - FS-24: an idle writer told pending at an unchanged epoch, after a Redis loss too.
//   - FS-105: an advertisement valid past 7 days refused, beside the copied keychain's 60 days.
//
// Each row's other schedules run as clauses under the same rules (fs_keys_test.go).

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest/gkmschedule"
)

var (
	Fs15  = Register("FS-15", "", []Tier{TierT2}, Fs15RotationRace)
	Fs18  = Register("FS-18", "", []Tier{TierT2}, Fs18CoveredAgentSuspended)
	Fs20  = Register("FS-20", "", []Tier{TierT2}, Twin(Fs20GenerationZeroRefused, Fs20RecoveryOverLostLeaves))
	Fs22  = Register("FS-22", "", []Tier{TierT2}, Twin(Fs22CompromiseRebind, Fs22RoutineRebind))
	Fs23  = Register("FS-23", "", []Tier{TierT2}, Twin(Fs23DepositorReplay, Fs23Depositor))
	Fs24  = Register("FS-24", "", []Tier{TierT2}, Fs24IdleWriterHint)
	Fs105 = Register("FS-105", "", []Tier{TierT2}, Twin(Fs105LongAdvertisement, Fs105CopiedAgentKeychain))
)

// A failure the gkm world raised inside a step.
type fsKeysFailure struct {
	err error
}

// The gkm world's FsKeysT inside a schedule: Fatal panics, and fsKeysCatch recovers it into the step's error;
// Errorf gathers what the step returns at its end; each cleanup runs at the schedule's last step.
type fsKeysFailer struct {
	ctx context.Context

	stateLock sync.Mutex
	errs      []error
	cleanups  []func()
}

var _ gkmschedule.FsKeysT = (*fsKeysFailer)(nil)

func (self *fsKeysFailer) Helper() {}

func (self *fsKeysFailer) Fatal(args ...any) {
	panic(fsKeysFailure{err: errors.New(fmt.Sprint(args...))})
}

func (self *fsKeysFailer) Fatalf(format string, args ...any) {
	panic(fsKeysFailure{err: fmt.Errorf(format, args...)})
}

func (self *fsKeysFailer) Errorf(format string, args ...any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.errs = append(self.errs, fmt.Errorf(format, args...))
}

func (self *fsKeysFailer) Context() context.Context {
	return self.ctx
}

func (self *fsKeysFailer) Cleanup(cleanup func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cleanups = append(self.cleanups, cleanup)
}

// The errors gathered since the last call.
func (self *fsKeysFailer) takeErrs() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	err := errors.Join(self.errs...)
	self.errs = nil
	return err
}

// Runs body, turning a failure the world raises into its error.
func fsKeysCatch(body func()) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			failure, ok := recovered.(fsKeysFailure)
			if !ok {
				panic(recovered)
			}
			err = failure.err
		}
	}()
	body()
	return nil
}

// What one schedule builds and its steps share.
type fsKeysRun struct {
	net    *Net
	failer *fsKeysFailer

	stateLock sync.Mutex
	worlds    []*gkmschedule.FsKeysWorld
}

func newFsKeysRun(net *Net) *fsKeysRun {
	return &fsKeysRun{net: net, failer: &fsKeysFailer{ctx: net.Context()}}
}

// A world of one repo of kind on the run's Net, which the run's invariant checks after every step.
func (self *fsKeysRun) world(kind protocol.RepoKind) *gkmschedule.FsKeysWorld {
	world := gkmschedule.NewFsKeysWorldOnNet(self.failer, kind, self.net)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.worlds = append(self.worlds, world)
	return world
}

// A step by actor running body, the failures the world raised there its error.
func (self *fsKeysRun) step(actor string, body func(ctx context.Context)) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		if err := fsKeysCatch(func() { body(ctx) }); err != nil {
			return err
		}
		return self.failer.takeErrs()
	}}
}

// step, queued: it starts with the next step's actors, which is what the explorer interleaves.
func (self *fsKeysRun) background(actor string, body func(ctx context.Context)) *Step {
	step := self.step(actor, body)
	step.Background = true
	return step
}

// The last step: everything the worlds started closes, the last started first.
func (self *fsKeysRun) cleanup() *Step {
	return &Step{Actor: "cleanup", Action: func(ctx context.Context, net *Net) error {
		self.failer.stateLock.Lock()
		cleanups := self.failer.cleanups
		self.failer.cleanups = nil
		self.failer.stateLock.Unlock()
		for i := len(cleanups) - 1; 0 <= i; i -= 1 {
			cleanups[i]()
		}
		return nil
	}}
}

// The invariants every gkm schedule checks after every step: FsKeysOneLadder in FI-4's place.
func (self *fsKeysRun) checks() []Invariant {
	return []Invariant{NewInvariant("FsKeysOneLadder", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		worlds := append([]*gkmschedule.FsKeysWorld(nil), self.worlds...)
		self.stateLock.Unlock()
		for _, world := range worlds {
			if err := world.CheckLadders(ctx); err != nil {
				return err
			}
		}
		return nil
	})}
}

// One of gkmschedule's schedules, whole, as actor on the run's worlds: a refusal names what it expects refused.
func fsKeysWhole(id string, refuses string, actor string, schedule func(t gkmschedule.FsKeysT, newWorld gkmschedule.FsKeysNewWorld)) Builder {
	return func(net *Net) *Schedule {
		run := newFsKeysRun(net)
		steps := []*Step{
			run.step(actor, func(ctx context.Context) {
				schedule(run.failer, run.world)
			}),
			run.cleanup(),
		}
		return &Schedule{Id: id, Steps: steps, Check: run.checks(), Tiers: []Tier{TierT2}, Refuses: refuses}
	}
}

// FS-15: the leaf a's rotation and the agent d's race for generation 2, each its own actor: one gen/2, both rotators
// holding it and b converging on it, in every order the explorer chooses and with any one write's answer lost.
func Fs15RotationRace(net *Net) *Schedule {
	run := newFsKeysRun(net)
	var world *gkmschedule.FsKeysWorld
	var a, b, d *gkmschedule.FsKeysDevice
	var leafKey, agentKey *sidecar.EvsRepoKey
	steps := []*Step{
		run.step("setup", func(ctx context.Context) {
			world = run.world(protocol.RepoKind_REPO_KIND_GENERAL)
			a = world.AddMember("a", false)
			b = world.AddMember("b", false)
			d = world.AddAgent("d")
			world.Grant(true, a, b, d)
			world.Admin(a)
			world.Advance()
			world.Publish()
			world.Create(a)
			world.AddPending(a)
			world.Again("the agent's first wrap", func() error {
				_, err := d.Client.CurrentRepoKey(ctx, world.RepoId)
				return err
			})
		}),
		run.background("leaf", func(ctx context.Context) {
			world.Again("the leaf's rotation", func() (err error) {
				leafKey, err = a.Client.RotateRepo(ctx, world.RepoId)
				return err
			})
		}),
		run.background("agent", func(ctx context.Context) {
			world.Again("the agent's rotation", func() (err error) {
				agentKey, err = d.Client.RotateRepo(ctx, world.RepoId)
				return err
			})
		}),
		{Actor: "leaf", Join: true},
		{Actor: "agent", Join: true},
		run.step("check", func(ctx context.Context) {
			if count := world.GenerationCount(); count != 2 {
				world.Fail("the race left %d generations", count)
			}
			commitment := world.Generation(2).Rotate.GetCommitment()
			if !bytes.Equal(leafKey.Commitment(), commitment) || !bytes.Equal(agentKey.Commitment(), commitment) {
				world.Fail("the rotators hold generations %d and %d, not gen/2's", leafKey.Generation(), agentKey.Generation())
			}
			world.Again("b's sync", func() error { return b.Client.SyncRepo(ctx, world.RepoId) })
			held, err := b.Client.CurrentRepoKey(ctx, world.RepoId)
			if err != nil || !bytes.Equal(held.Commitment(), commitment) {
				world.Fail("b does not converge on gen/2: %v", err)
			}
		}),
		run.cleanup(),
	}
	return &Schedule{Id: "FS-15 rotation race", Steps: steps, Check: run.checks(), Tiers: []Tier{TierT2}}
}

// FS-18: see gkmschedule's FsKeysScheduleCoveredAgentSuspended.
var Fs18CoveredAgentSuspended = fsKeysWhole("FS-18 covered agent suspended", "", "keys", gkmschedule.FsKeysScheduleCoveredAgentSuspended)

// FS-20: an ordinary device's generation-0 external commit, refused by gkm (FsKeysScheduleGenerationZeroFromAnOrdinaryDevice).
var Fs20GenerationZeroRefused = fsKeysWhole("FS-20 generation zero refused", "an ordinary device's generation-0 external commit, 403", "keys", gkmschedule.FsKeysScheduleGenerationZeroFromAnOrdinaryDevice)

// FS-20's twin: the code-only device's generation-0 self-join over revoked lost leaves (FsKeysScheduleRecoveryOverLostLeaves).
var Fs20RecoveryOverLostLeaves = fsKeysWhole("FS-20 recovery over lost leaves", "", "keys", gkmschedule.FsKeysScheduleRecoveryOverLostLeaves)

// FS-22: the gate closed at the old generation by a compromise rebind (FsKeysScheduleCompromiseRebind).
var Fs22CompromiseRebind = fsKeysWhole("FS-22 compromise rebind", "a write at the old generation, the gate closed", "keys", gkmschedule.FsKeysScheduleCompromiseRebind)

// FS-22's twin: a routine rebind, the gate open (FsKeysScheduleRoutineRebind).
var Fs22RoutineRebind = fsKeysWhole("FS-22 routine rebind", "", "keys", gkmschedule.FsKeysScheduleRoutineRebind)

// FS-23: an older drop key refused after a removal (FsKeysScheduleDepositorReplay).
var Fs23DepositorReplay = fsKeysWhole("FS-23 depositor replay", "an older unexpired GenRotate after a removal", "keys", gkmschedule.FsKeysScheduleDepositorReplay)

// FS-23's twin: the depositor follows the drop key (FsKeysScheduleDepositor).
var Fs23Depositor = fsKeysWhole("FS-23 depositor", "", "keys", gkmschedule.FsKeysScheduleDepositor)

// FS-24: see gkmschedule's FsKeysScheduleIdleWriterHint.
var Fs24IdleWriterHint = fsKeysWhole("FS-24 idle writer hint", "", "keys", gkmschedule.FsKeysScheduleIdleWriterHint)

// FS-105: an advertisement valid past 7 days refused (FsKeysScheduleLongAdvertisement).
var Fs105LongAdvertisement = fsKeysWhole("FS-105 long advertisement", "an advertisement valid past 7 days", "keys", gkmschedule.FsKeysScheduleLongAdvertisement)

// FS-105's twin: the copied keychain's 60 days (FsKeysScheduleCopiedAgentKeychain).
var Fs105CopiedAgentKeychain = fsKeysWhole("FS-105 copied agent keychain", "", "keys", gkmschedule.FsKeysScheduleCopiedAgentKeychain)
