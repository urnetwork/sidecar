// §22.7's revocation suite's device form (TEST-M2-12; R-TEST-4, D-TEST-6, I-15): the checks TEST composes from KEYS's
// and EVS's exported worlds, registered with sidecartest's suite (revocation_suite.go), each a fault schedule whose
// steps run as their actors, so the keys X held are what testHookSecret recorded under X's actor, never a list the
// check wrote. Composition adds no mechanism: a failure goes back to the area named.
//
//   - keys/x-opens-nothing-claimed-after (KEYS): X, a member device or for a grant's expiry and an ephemeral reap an
//     uncovered agent, reads generation g; X loses access by the way; the writer's next write key is generation g+1,
//     wrapped to no device of X's, and with every wrap the store holds delivered to X (a malicious server's), no key
//     X held opens g+1, nor do its ReaderKeys or its MLS state, while one it held opens g, so the check is no
//     vacuous pass. Without the hooks the held-key clause reads open.
//   - evs/new-content-opens-under-no-key-x-held (EVS, the gate off): on the evs world, X reads, a read loss drops it,
//     and with evs's gate off a writer's next change rests on a generation no key X held opens, so what refuses X is
//     the writers' own rotation, not 5d (D-TEST-6). Without the hooks it reads open, having no gate to switch and no
//     key of X's to try.
//
// RevocationKeysCheck's mutant, a writer sealing to the generation it held before X's loss, is the suite's own
// test that a writer sealing to an old generation fails.
//
// Not composed yet, each reading missing in its way's report only where no other check names that way: the gates'
// 412 GATE_CLOSED and deposits until a covering generation is claimed (FS-3's, on the evs world, gate on), receivers'
// 451, members refusing a commit that adds a non-reader or omits a Remove (KEYS-M2-28's revocation_test.go, a _test
// file nothing can register), tokens failing in their windows at api, sockets, edges, evs, gkm and connect, path
// tokens, first-write checkpoints, five ephemeral agents through a reap with a covered agent's reap starting no
// generation, a Delegation's reader key, a reader-only holder with evs's help, a withheld Remove, and SOCK's, TLS's,
// TEAM's SCIM and CORE's FS-98 checks, which their areas register.

package scenarios

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/fault"
	"github.com/urnetwork/sidecar/sidecartest/gkmschedule"
)

var (
	RevocationKeysNextGeneration = sidecartest.RegisterRevocationCheck(RevocationKeysCheck(false))
	RevocationEvsNewContent      = sidecartest.RegisterRevocationCheck(RevocationEvsCheck())
)

// Why a held-key clause cannot run on a leg without the hooks.
const revocationOpenWithoutHooks = "the keys X held reach no record without sidecar_testhooks, so whether they open the new generation is not judged"

// The keys check of the device form; sealsToOld makes the writer seal to the generation it held before X's loss, the
// mutant the suite must fail.
func RevocationKeysCheck(sealsToOld bool) *sidecartest.RevocationCheck {
	id := "keys/x-opens-nothing-claimed-after"
	if sealsToOld {
		id += "/mutant-sealing-to-the-old-generation"
	}
	return &sidecartest.RevocationCheck{
		Id:   id,
		Area: "KEYS",
		Ways: sidecartest.RevocationFormDevice.Ways(),
		Run: func(run *sidecartest.RevocationRun) (string, error) {
			return revocationKeysRun(run, sealsToOld)
		},
	}
}

// A gkm world's FsKeysT inside a fault schedule: Fatal panics, and a step recovers it into its error; Errorf gathers
// what the step returns; cleanups run at the schedule's last step.
type revocationFailer struct {
	ctx context.Context

	stateLock sync.Mutex
	errs      []error
	cleanups  []func()
}

type revocationFailure struct {
	err error
}

var _ gkmschedule.FsKeysT = (*revocationFailer)(nil)

func (self *revocationFailer) Helper() {}

func (self *revocationFailer) Fatal(args ...any) {
	panic(revocationFailure{err: errors.New(fmt.Sprint(args...))})
}

func (self *revocationFailer) Fatalf(format string, args ...any) {
	panic(revocationFailure{err: fmt.Errorf(format, args...)})
}

func (self *revocationFailer) Errorf(format string, args ...any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.errs = append(self.errs, fmt.Errorf(format, args...))
}

func (self *revocationFailer) Context() context.Context {
	return self.ctx
}

func (self *revocationFailer) Cleanup(cleanup func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cleanups = append(self.cleanups, cleanup)
}

// A step by actor running body, what the world raised there its error.
func (self *revocationFailer) step(actor string, body func(ctx context.Context) error) *fault.Step {
	return &fault.Step{Actor: actor, Action: func(ctx context.Context, net *fault.Net) (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				failure, ok := recovered.(revocationFailure)
				if !ok {
					panic(recovered)
				}
				err = failure.err
			}
		}()
		if err := body(ctx); err != nil {
			return err
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		err = errors.Join(self.errs...)
		self.errs = nil
		return err
	}}
}

// The last step: every cleanup the world registered, the last first.
func (self *revocationFailer) cleanup() *fault.Step {
	return &fault.Step{Actor: "cleanup", Action: func(ctx context.Context, net *fault.Net) error {
		self.stateLock.Lock()
		cleanups := self.cleanups
		self.cleanups = nil
		self.stateLock.Unlock()
		for i := len(cleanups) - 1; 0 <= i; i -= 1 {
			cleanups[i]()
		}
		return nil
	}}
}

// See the file header.
func revocationKeysRun(run *sidecartest.RevocationRun, sealsToOld bool) (string, error) {
	failer := &revocationFailer{ctx: run.Ctx}
	agent := run.Way == sidecartest.RevocationGrantExpiry || run.Way == sidecartest.RevocationEphemeralReap
	var world *gkmschedule.FsKeysWorld
	var writer, x *gkmschedule.FsKeysDevice
	var before, after *sidecar.EvsRepoKey
	open := ""
	steps := []*fault.Step{
		failer.step("setup", func(ctx context.Context) error {
			world = gkmschedule.NewFsKeysWorldOnNet(failer, protocol.RepoKind_REPO_KIND_GENERAL, run.Net)
			writer = world.AddMember("writer", false)
			return nil
		}),
		// X's own keys are made as X
		failer.step("x", func(ctx context.Context) error {
			if agent {
				x = world.AddAgent("x")
			} else {
				x = world.AddMember("x", false)
			}
			return nil
		}),
		failer.step("setup", func(ctx context.Context) error {
			world.Grant(true, writer)
			world.Grant(false, x)
			world.Admin(writer)
			world.Advance()
			world.Publish()
			return nil
		}),
		failer.step("writer", func(ctx context.Context) error {
			world.Create(writer)
			world.AddPending(writer)
			var err error
			before, err = writer.Client.CurrentRepoKey(ctx, world.RepoId)
			return err
		}),
		failer.step("x", func(ctx context.Context) error {
			held, err := x.Client.CurrentRepoKey(ctx, world.RepoId)
			if err != nil {
				return fmt.Errorf("X reads nothing before its loss, so the check proves nothing: %w", err)
			}
			if held.Generation() != before.Generation() {
				return fmt.Errorf("X holds generation %d, the writer %d", held.Generation(), before.Generation())
			}
			return nil
		}),
		failer.step("api", func(ctx context.Context) error {
			switch run.Way {
			case sidecartest.RevocationDeviceRevoke:
				world.Revoke(x)
			case sidecartest.RevocationReadLoss:
				world.Drop(x)
			case sidecartest.RevocationGrantExpiry:
				world.ExpireAt(x, world.Clock.Now().Add(time.Minute))
				world.Clock.Advance(2 * time.Minute)
			case sidecartest.RevocationSuspension:
				world.Suspend(x)
			case sidecartest.RevocationEphemeralReap:
				world.Reap(x)
			default:
				return fmt.Errorf("the keys check runs no %s", run.Way)
			}
			world.Advance()
			return nil
		}),
		failer.step("writer", func(ctx context.Context) error {
			var err error
			if sealsToOld {
				after, err = writer.Client.CurrentRepoKey(ctx, world.RepoId)
			} else {
				after, err = writer.Client.EnsureWritable(ctx, world.RepoId)
			}
			return err
		}),
		failer.step("check", func(ctx context.Context) error {
			errs := []error{}
			if after.Generation() <= before.Generation() {
				errs = append(errs, fmt.Errorf("the writer seals to generation %d after X's %s, which X holds", after.Generation(), run.Way))
			}
			if world.WrapRecipients(after.Generation())[x.SidecarId()] {
				errs = append(errs, fmt.Errorf("a wrap of generation %d to X", after.Generation()))
			}
			if world.OpensWrapOf(x, after.Generation(), x.CopyReaderKeys()) {
				errs = append(errs, fmt.Errorf("X's ReaderKeys open generation %d's wraps", after.Generation()))
			}
			if !agent {
				if reach := world.RemovedReach(x); after.Generation() <= reach {
					errs = append(errs, fmt.Errorf("X's MLS state reaches generation %d of %d", reach, after.Generation()))
				}
			}
			ladder := []*sidecar.GkmGeneration{}
			for generation := uint64(1); generation <= uint64(world.GenerationCount()); generation += 1 {
				ladder = append(ladder, world.Generation(generation))
			}
			revoked := run.RevokedActor("x")
			switch {
			case !sidecartest.HooksLinked:
				open = revocationOpenWithoutHooks
			case !revoked.OpensGeneration(ladder, before.Generation()):
				errs = append(errs, fmt.Errorf("no key X held opens generation %d, which it read: the check proves nothing", before.Generation()))
			case revoked.OpensGeneration(ladder, after.Generation()):
				errs = append(errs, fmt.Errorf("a key X held opens generation %d, claimed after its %s", after.Generation(), run.Way))
			}
			return errors.Join(errs...)
		}),
		failer.cleanup(),
	}
	result := fault.Run(run.Ctx, &fault.Schedule{Id: "revocation " + string(run.Way), Steps: steps}, run.Net)
	return open, result.Err
}

// The evs check of the device form: see the file header.
func RevocationEvsCheck() *sidecartest.RevocationCheck {
	return &sidecartest.RevocationCheck{
		Id:      "evs/new-content-opens-under-no-key-x-held",
		Area:    "EVS",
		Ways:    []sidecartest.RevocationWay{sidecartest.RevocationReadLoss},
		GateOff: true,
		Run:     revocationEvsRun,
	}
}

func revocationEvsRun(run *sidecartest.RevocationRun) (string, error) {
	if !sidecartest.HooksLinked {
		return revocationOpenWithoutHooks, nil
	}
	settings := fault.DefaultEvsWorldSettings()
	settings.Devices = append(settings.Devices, &fault.EvsWorldDeviceSettings{Name: "x", Instances: []string{"evsr"}})
	world := fault.NewEvsWorld(run.Net, settings)
	var before uint64
	steps := []*fault.Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", fault.EvsWorldContent("revocation a", 200))},
		{Actor: "x", Action: world.Verify("x", "a.txt")},
		{Actor: "check", Action: func(ctx context.Context, net *fault.Net) error {
			head, err := world.Head(ctx)
			if err != nil || head == nil {
				return fmt.Errorf("main's head: %v", err)
			}
			before = head.GetGeneration()
			return nil
		}},
		{Actor: "api", Action: world.DropReader("x")},
		// a change, since a creation waits out the path epoch's due the shrink leaves (FS-3's, FS-4's)
		{Actor: "writerB", Action: world.Write("writerB", "a.txt", fault.EvsWorldContent("revocation a by B", 200))},
		{Actor: "check", Action: func(ctx context.Context, net *fault.Net) error {
			head, err := world.Head(ctx)
			if err != nil || head == nil {
				return fmt.Errorf("main's head: %v", err)
			}
			groupId, err := sidecar.IdFromBytes(head.GetGroupId())
			if err != nil {
				return err
			}
			ladder, err := fault.NewStoreView(net, nil).Generations(sidecartest.InspectContext(ctx), groupId)
			if err != nil {
				return err
			}
			revoked := sidecartest.NewRevokedActor(net, "x")
			switch {
			case head.GetGeneration() <= before:
				return fmt.Errorf("a commit after X's read loss under generation %d, which X holds, with the gate off", head.GetGeneration())
			case !revoked.OpensGeneration(ladder, before):
				return fmt.Errorf("no key X held opens generation %d, which it read: the check proves nothing", before)
			case revoked.OpensGeneration(ladder, head.GetGeneration()):
				return fmt.Errorf("a key X held opens generation %d, which the commit after its read loss rests on", head.GetGeneration())
			}
			return nil
		}},
	}
	result := fault.Run(run.Ctx, &fault.Schedule{Id: "revocation evs " + string(run.Way), Steps: steps, Check: world.Checks()}, run.Net)
	return "", result.Err
}
