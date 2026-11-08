// The FS schedule runner (§22.8, D-TEST-10): a fault schedule is a deterministic sequence of actor
// steps, barriers, store faults and clock moves, checked against FI invariants after every step and at
// the end. One Schedule per FS row. Owners write their rows as fs<n>_test.go here, against engines this
// package knows nothing about, and their invariants as fi<n>.go.
//
// What a step does, in this order, whichever fields it sets:
//
//  1. Fault arms a plan the next matching operation gets.
//  2. Counters sets fake drive counters.
//  3. Advance moves the clock every actor shares.
//  4. Kill drops Actor's memory, and Restart builds it again on an instance from durable state alone.
//  5. Release lets the named barriers go, in order.
//  6. Action starts on Actor.
//  7. Await, Join or the Action's end is what the step waits for.
//
// Every site a schedule awaits is armed before its first step, so an actor that gets there early stops
// there and cannot slip past it. Actors run one at a time, under the driver's baton, so a schedule
// repeats exactly. A Seed turns each barrier an actor passes into a seeded choice of who runs next,
// which is §22.8's explorer. Waiting over 10 s of real time for a barrier fails with the trace.
//
// A schedule that names a site reached through testHookBarrier needs the sidecar_testhooks tag.

package fault

import (
	"context"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

type (
	Net           = sidecartest.Net
	FaultPlan     = sidecartest.FaultPlan
	FaultResult   = sidecartest.FaultResult
	FaultDelay    = sidecartest.FaultDelay
	DriveCounters = sidecartest.DriveCounters
)

// §22.8's results. QuorumLoss and DriveMiss run on T3's real stores alone, and a fake refuses them.
const (
	ApplyThenDrop    = sidecartest.ApplyThenDrop
	FailBeforeApply  = sidecartest.FailBeforeApply
	Precondition     = sidecartest.Precondition
	Delay            = sidecartest.Delay
	Held             = sidecartest.Held
	CrashBeforeApply = sidecartest.CrashBeforeApply
	CrashAfterApply  = sidecartest.CrashAfterApply
	QuorumLoss       = sidecartest.QuorumLoss
	DriveMiss        = sidecartest.DriveMiss
)

// As an Await, the moment the last plan armed fires, for a result that holds no barrier: a crash point,
// or a Delay parking its caller.
const FaultFired = "fault.fired"

// A tier a row runs on (§22.4): T2's fakes in one process, T3's real stores and server's exchange,
// T4's device and SDK cells.
type Tier string

const (
	TierT2 Tier = "T2"
	TierT3 Tier = "T3"
	TierT4 Tier = "T4"
)

// Makes a fresh Schedule on net each call. Every rule across runs reruns it, the explorer's seeds,
// every write's lost response, a twin and a replay, so a schedule built once and shared would carry
// one run's state into the next. A row registers one (Register), and its T2 and T3 tests run the same
// one.
type Builder func(net *Net) *Schedule

type Schedule struct {
	// "FS-1".
	Id string
	// Non-zero runs the explorer's interleavings under this seed. Zero is the fixed schedule.
	Seed  int64
	Steps []*Step
	// FI-n, after every step and at the end.
	Check []Invariant
	// The tiers its row names, beside the T2 this runs it on (§22.8's cadence rule). A row that adds a
	// connect client runs on sidecartest's fake contract issuer and ControlId sink, so it names T3 too,
	// where a divergence from server's exchange fails (Q-TEST-1), and Run fails one that does not.
	Tiers []Tier
}

type Step struct {
	// Who: "writerA", "evs1", "gc", "shred", "daemonM", "stripe".
	Actor string
	// What Actor does. A non-nil error fails the schedule, so an Action expecting a refusal handles
	// it and returns nil. ctx is Actor's, and ends if Actor is killed.
	Action func(ctx context.Context, net *Net) error
	// Run until Actor reaches this barrier, then hold it there: a name or <name>@<key>
	// (sidecartest.BarrierSite). An actor reaching it early holds there until this step.
	Await string
	// Arrivals at Await to let pass first, for a site a loop reaches more than once.
	AwaitSkip int
	// Barriers to release, in this order. An actor's own hold at a site two actors share is
	// sidecartest.ActorBarrierSite.
	Release []string
	// The result the next matching store, Redis or Postgres operation gets.
	Fault *FaultPlan
	// Fake clock, shared by every actor.
	Advance time.Duration
	// Drop Actor's memory; Restart builds it again from durable state alone.
	Kill bool
	// Instance to restart Actor on ("evs2").
	Restart string
	// Fake metadata drive counters (FS-61).
	Counters *DriveCounters
	// The Action queues and this step ends at once: it starts together with the next step's actors,
	// so a run of these steps is what gives the explorer something to interleave. The fixed schedule
	// runs them in the order written.
	Background bool
	// Waits for every Action of Actor to end.
	Join bool
	// Moves Actor's clock this far from the shared one (FS-1's evs2, 150 ms fast).
	ClockOffset time.Duration
}

func (self *Step) String() string {
	return fmt.Sprintf(
		"actor=%q action=%t await=%q release=%v fault=%v advance=%v kill=%t restart=%q background=%t join=%t",
		self.Actor, self.Action != nil, self.Await, self.Release, self.Fault, self.Advance, self.Kill, self.Restart, self.Background, self.Join,
	)
}
