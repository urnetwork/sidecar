// FS-25 (§22.8; §16.6; D-MCP-11, AU1-AU4, FI-2, FI-7, TS1; MCP-M3-24) on T2: §22.7's uses row as schedules on one
// requesting daemon's real gate (sidecartest.ApprovalWorld), its local state's every write taken at the Net's fault
// queue, the daemon a process a schedule kills and restarts, and each agent's MCP session an actor of its own. FI-7's
// oracle (fi7.go) checks after every step, and so does the outcomes clause of FI-2 the world can show (Fs25Outcomes);
// FI(2) itself is TEST-M2-04's, unbound, so a schedule names the clause instead.
//
// The registered case, beside its twin:
//
//   - Fs25TwoCallersOneUseLeft: a template decision of uses = 2, its first use spent, then two callers, each with its
//     own action inside the template, barriered at record.reserve.before and released together: one effect, the
//     other caller's action spent (a template binds only uses > 1, §16.6's multi-use row);
//   - Fs25TwoCallersTwoUsesLeft, its twin: the same at uses = 3, both callers' actions taking a use.
//
// The row's other clauses run by fs25_test.go under the explorer and the unknown rule, each refusal beside a twin:
//
//   - one action's two callers, the second after the first's outcome: one effect, which both get (AU4), on an exact
//     action's decision of uses = 1 (Fs25RetrySameAction); two callers of one action at once join one flight, which
//     blocks outside any barrier and so stays MCP-M3-06's unit test (TestOneEffectForTwoCallers);
//   - kills after the Reserve's fsync, after the component's effect and before the Outcome, each then a restart, whose
//     reconcile reads the kind's Lookup, and a retry through a new MCP session: one effect, the retry answered the
//     original outcome or completing an uncertain one under the same key (Fs25KillAfter*);
//   - uses = 2 with three actions one after another: two effects, the third taking no use but filing a request of its
//     own, since the spent template is no candidate for it; the twin at uses = 3 (Fs25TwoUsesThreeActions);
//   - a cancel after the first of three uses, a reservation made before it still completing, the next action filing a
//     request of its own; the twin without the cancel (Fs25Cancel);
//   - on the fake clock, a local reservation at not_after - 1 s completing at + 5 min, and a retry at + 11 min only
//     reconciling; the twin's retry at + 9 min completing (Fs25Expiry); the daemon refusing to reserve a server-gated
//     use past not_after - 60 s; the twin at not_after - 90 s (Fs25ServerGatedExpiry);
//   - uses = 3 with the run tainted after the first use: a use reserved before the taint completes, and the next is
//     refused stale and files a tainted request; the twin untainted (Fs25TaintedAfterFirstUse).
//
// The gate's own legs, a response lost after COMMIT and two api instances racing, run on real Postgres through
// model.ConsumeApprovalUseInTx (server/api/approval_schedule_db_test.go), as plan-MCP-fs25-gate-before-dns says, and
// again through POST /dns/records at M5-out (MCP-M5-01); the cancel's server half runs there through POST
// /approval/cancel. Mail's case, counting outbox objects, is MCP-M7-01's once its outbox lands.

package fault

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs25 = Register("FS-25", "", []Tier{TierT2}, Twin(Fs25TwoCallersOneUseLeft, Fs25TwoCallersTwoUsesLeft))

// The daemon's process name in every FS-25 and FS-29 world.
const fs25Daemon = "daemon"

// How long an approval in these schedules lasts: an hour of the fake clock.
const fs25Lifetime = time.Hour

// How many times an agent sends a call whose answer was a lost write's: §22.8's unknown rule loses one response a
// run, so a second send answers.
const fs25RetryCount = 3

// FI-2's outcomes clause as the world shows it: a use's first done or not_done Outcome is the one every later
// Outcome of the use repeats, so a retry of a committed use returns its original result.
var Fs25Outcomes Invariant = NewInvariant("FI-2/approval", func(ctx context.Context, oracle *Oracle) error {
	for _, world := range oracle.Net.ApprovalWorlds() {
		if err := world.CheckOutcomes(); err != nil {
			return err
		}
	}
	return nil
})

// One schedule's state, which its steps share. The callers' answers are under stateLock, since callers are actors of
// their own.
type fs25State struct {
	world *sidecartest.ApprovalWorld
	// the approval the setup filed and decided
	approvalId sidecar.Id
	template   *sidecar.StoredCanonicalAction

	stateLock sync.Mutex
	// each caller's answer, by actor name
	answers map[string]*fs25Answer
}

// One caller's call and what the gate answered.
type fs25Answer struct {
	action *sidecar.SidecarAction
	err    error
}

// Sends call until it answers something other than a lost write's error, at most fs25RetryCount times, as an agent
// resends a call whose response it lost.
func fs25Retry(call func() error) error {
	var err error
	for range fs25RetryCount {
		err = call()
		if !errors.Is(err, sidecartest.ErrFaultStoreTransport) {
			return err
		}
	}
	return err
}

// The recipients of the setup's template, the mail each caller sends among them.
var fs25Recipients = []string{"a@recipient.example", "b@recipient.example", "c@recipient.example", "d@recipient.example"}

// The setup step: the world, then the agent's request filed, decided by the phone for uses, until the clock's now plus
// fs25Lifetime, and the inbox's next poll: at uses = 1 the mail to fs25Recipients[0] itself, else a template every
// mail here falls inside, since a template binds only uses > 1.
func (self *fs25State) setup(uses uint32) *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		world, err := sidecartest.NewApprovalWorld(net, fs25Daemon)
		if err != nil {
			return err
		}
		self.world = world
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.answers = map[string]*fs25Answer{}
		}()
		if uses == 1 {
			self.template, err = world.MailAction(fs25Recipients[0])
		} else {
			self.template, err = world.MailTemplate(fs25Recipients...)
		}
		if err != nil {
			return err
		}
		approvalId, err := self.file(ctx, self.template)
		if err != nil {
			return err
		}
		self.approvalId = approvalId
		notAfter := net.Clock().Now().Add(fs25Lifetime)
		if err := fs25Retry(func() error { return world.Approve(ctx, approvalId, uses, notAfter, nil) }); err != nil {
			return err
		}
		// the inbox's next poll, as its Run makes one, before any use
		return fs25Retry(func() error { return world.PollInbox(ctx) })
	}}
}

// Files stored's request through the gate, as an O tool's first call does, answering its approval.
func (self *fs25State) file(ctx context.Context, stored *sidecar.StoredCanonicalAction) (sidecar.Id, error) {
	var approvalId sidecar.Id
	err := fs25Retry(func() error {
		err := self.world.Authorize(ctx, self.world.Action(stored))
		pending := &sidecar.ApprovalPendingError{}
		if !errors.As(err, &pending) {
			if err == nil {
				return errors.New("the first call of an action passed with no decision")
			}
			return err
		}
		approvalId = pending.ApprovalId
		return nil
	})
	return approvalId, err
}

// The mail to fs25Recipients[index], inside the template.
func (self *fs25State) mail(index int) (*sidecar.StoredCanonicalAction, error) {
	return self.world.MailAction(fs25Recipients[index])
}

// A caller's call of the mail to fs25Recipients[index], its answer kept under the actor's name.
func (self *fs25State) call(actor string, index int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		stored, err := self.mail(index)
		if err != nil {
			return err
		}
		answer := &fs25Answer{}
		answer.err = fs25Retry(func() error {
			answer.action = self.world.Action(stored)
			return self.world.Authorize(ctx, answer.action)
		})
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.answers[actor] = answer
		return nil
	}
}

// The answer an actor got, an error for none.
func (self *fs25State) answer(actor string) (*fs25Answer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	answer, ok := self.answers[actor]
	if !ok {
		return nil, fmt.Errorf("%s has no answer", actor)
	}
	return answer, nil
}

// Whether actor's call ended done.
func (self *fs25State) done(actor string) error {
	answer, err := self.answer(actor)
	if err != nil {
		return err
	}
	if answer.err != nil {
		return fmt.Errorf("%s: %w", actor, answer.err)
	}
	if answer.action.Outcome == nil || answer.action.Outcome.State != sidecar.ApprovalOutcomeDone {
		return fmt.Errorf("%s's outcome %+v", actor, answer.action.Outcome)
	}
	return nil
}

// Whether actor's call was refused with want.
func (self *fs25State) refused(actor string, want error) error {
	answer, err := self.answer(actor)
	if err != nil {
		return err
	}
	if !errors.Is(answer.err, want) {
		return fmt.Errorf("%s answered %v, want %v", actor, answer.err, want)
	}
	return nil
}

// Whether actor's call took no use of the setup's approval and filed a request of its own, pending.
func (self *fs25State) filedAnother(actor string) error {
	answer, err := self.answer(actor)
	if err != nil {
		return err
	}
	pending := &sidecar.ApprovalPendingError{}
	if !errors.As(answer.err, &pending) || pending.ApprovalId == self.approvalId {
		return fmt.Errorf("%s answered %v, want a request of its own", actor, answer.err)
	}
	return nil
}

// The mail sink's effects, which must be want.
func (self *fs25State) effects(want int) error {
	if got := self.world.Sink(sidecar.SidecarActionMail).EffectCount(); got != want {
		return fmt.Errorf("%d effects, want %d", got, want)
	}
	return nil
}

// The last step every schedule takes: the daemon reconciles, as its next start would, so FI-7's final check reads
// every Reserve with its Outcome.
func (self *fs25State) reconcile() *Step {
	return &Step{Actor: "reconcile", Action: func(ctx context.Context, net *Net) error {
		return fs25Retry(func() error { return self.world.Reconcile(ctx) })
	}}
}

// The checks every FS-25 schedule runs.
func fs25Checks() []Invariant {
	return []Invariant{FI(7), Fs25Outcomes}
}

// See the file header.
func Fs25TwoCallersOneUseLeft(net *Net) *Schedule {
	schedule := fs25TwoCallers(2)
	schedule.Refuses = "the second caller's action, spent once the first took the template's last use"
	return schedule
}

// See the file header.
func Fs25TwoCallersTwoUsesLeft(net *Net) *Schedule {
	return fs25TwoCallers(3)
}

// A template of uses, its first use spent, then two callers with an action each held at record.reserve.before and
// released together: with one use left one is spent, with two both take one.
func fs25TwoCallers(uses uint32) *Schedule {
	state := &fs25State{}
	return &Schedule{
		Steps: []*Step{
			state.setup(uses),
			{Actor: "callerP", Action: state.call("callerP", 0)},
			{Actor: "callerA", Action: state.call("callerA", 1), Await: "record.reserve.before"},
			{Actor: "callerB", Action: state.call("callerB", 2), Await: "record.reserve.before"},
			{Release: []string{
				sidecartest.ActorBarrierSite("callerA", "record.reserve.before"),
				sidecartest.ActorBarrierSite("callerB", "record.reserve.before"),
			}},
			{Actor: "callerA", Join: true},
			{Actor: "callerB", Join: true},
			{Actor: "judge", Action: func(ctx context.Context, net *Net) error {
				if err := state.done("callerP"); err != nil {
					return err
				}
				if uses == 3 {
					return errors.Join(state.done("callerA"), state.done("callerB"), state.effects(3))
				}
				doneA, doneB := state.done("callerA"), state.done("callerB")
				switch {
				case doneA == nil && doneB == nil:
					return errors.New("two actions both took the template's last use")
				case doneA == nil:
					return errors.Join(state.refused("callerB", sidecar.ErrApprovalSpent), state.effects(2))
				case doneB == nil:
					return errors.Join(state.refused("callerA", sidecar.ErrApprovalSpent), state.effects(2))
				}
				return fmt.Errorf("neither action ran: %v; %v", doneA, doneB)
			}},
			state.reconcile(),
		},
		Check: fs25Checks(),
		Tiers: []Tier{TierT2},
	}
}

// An exact action's decision of uses = 1, its caller's call done, then a second caller of the same action through
// another session: answered the first's outcome and its effect's reference, no second effect (AU4).
func Fs25RetrySameAction(net *Net) *Schedule {
	state := &fs25State{}
	return &Schedule{
		Id: "FS-25 retry of the same action",
		Steps: []*Step{
			state.setup(1),
			{Actor: "callerA", Action: state.call("callerA", 0)},
			{Actor: "callerB", Action: state.call("callerB", 0)},
			{Actor: "judge", Action: func(ctx context.Context, net *Net) error {
				if err := errors.Join(state.done("callerA"), state.done("callerB")); err != nil {
					return err
				}
				first, _ := state.answer("callerA")
				second, _ := state.answer("callerB")
				if string(first.action.Outcome.EffectRef) != string(second.action.Outcome.EffectRef) {
					return errors.New("one action's two callers got two effects' references")
				}
				if runs := state.world.Sink(sidecar.SidecarActionMail).RunCount(); runs != 1 {
					return fmt.Errorf("the effect ran %d times", runs)
				}
				return state.effects(1)
			}},
			state.reconcile(),
		},
		Check: fs25Checks(),
		Tiers: []Tier{TierT2},
	}
}

// See the file header: killed at site, the daemon restarted, the action retried through a new session at once, or,
// with expired, past not_after plus the completion window, where the retry only reconciles.
func fs25KillAt(site string, expired bool) *Schedule {
	state := &fs25State{}
	steps := []*Step{
		state.setup(1),
		{Actor: "callerA", Action: state.call("callerA", 0), Await: site},
		{Actor: "callerA", Kill: true},
		{Actor: fs25Daemon, Kill: true},
		{Actor: fs25Daemon, Restart: fs25Daemon},
	}
	if expired {
		steps = append(steps, &Step{Advance: fs25Lifetime + 11*time.Minute})
	}
	steps = append(steps,
		&Step{Actor: "callerA2", Action: state.call("callerA2", 0)},
		&Step{Actor: "judge", Action: func(ctx context.Context, net *Net) error {
			sink := state.world.Sink(sidecar.SidecarActionMail)
			if expired {
				answer, err := state.answer("callerA2")
				if err != nil {
					return err
				}
				if answer.err != nil || answer.action.Outcome == nil || !errors.Is(answer.action.Outcome.Err, sidecar.ErrApprovalExpired) {
					return fmt.Errorf("a retry past the window: %v, %+v", answer.err, answer.action.Outcome)
				}
				if site == "record.reserve.after" && sink.EffectCount() != 0 {
					return fmt.Errorf("a retry past the window ran the effect: %d effects", sink.EffectCount())
				}
				return nil
			}
			if err := state.done("callerA2"); err != nil {
				return err
			}
			return state.effects(1)
		}},
		state.reconcile(),
	)
	schedule := &Schedule{Id: "FS-25 kill at " + site, Steps: steps, Check: fs25Checks(), Tiers: []Tier{TierT2}}
	if expired {
		schedule.Id += " and a late retry"
		schedule.Refuses = "a retry past not_after plus the completion window, which only reconciles"
		schedule.Twin = func(net *Net) *Schedule { return fs25KillAt(site, false) }
	}
	return schedule
}

// A kill after the Reserve's fsync, before the effect.
func Fs25KillAfterReserve(net *Net) *Schedule {
	return fs25KillAt("record.reserve.after", false)
}

// A kill after the component's effect, before its Outcome.
func Fs25KillAfterEffect(net *Net) *Schedule {
	return fs25KillAt("record.effect.after", false)
}

// A kill before the Outcome's fsync.
func Fs25KillBeforeOutcome(net *Net) *Schedule {
	return fs25KillAt("record.outcome.before", false)
}

// A kill after the Reserve, and the retry past not_after plus the completion window: it only reconciles; its twin
// retries at once and completes.
func Fs25KillThenLateRetry(net *Net) *Schedule {
	return fs25KillAt("record.reserve.after", true)
}

// Three actions one after another on a template of uses: at uses = 2 two effects, the third taking no use and filing a
// request of its own; the twin at uses = 3, three effects.
func fs25UsesThreeActions(uses uint32) *Schedule {
	state := &fs25State{}
	schedule := &Schedule{
		Id: fmt.Sprintf("FS-25 uses = %d with three actions", uses),
		Steps: []*Step{
			state.setup(uses),
			{Actor: "callerA", Action: state.call("callerA", 0)},
			{Actor: "callerB", Action: state.call("callerB", 1)},
			{Actor: "callerC", Action: state.call("callerC", 2)},
			{Actor: "judge", Action: func(ctx context.Context, net *Net) error {
				if err := errors.Join(state.done("callerA"), state.done("callerB")); err != nil {
					return err
				}
				if uses == 2 {
					return errors.Join(state.filedAnother("callerC"), state.effects(2))
				}
				return errors.Join(state.done("callerC"), state.effects(3))
			}},
			state.reconcile(),
		},
		Check: fs25Checks(),
		Tiers: []Tier{TierT2},
	}
	if uses == 2 {
		schedule.Refuses = "a third action on uses = 2, taking no use and filing a request of its own"
		schedule.Twin = func(net *Net) *Schedule { return fs25UsesThreeActions(3) }
	}
	return schedule
}

// See the file header.
func Fs25TwoUsesThreeActions(net *Net) *Schedule {
	return fs25UsesThreeActions(2)
}

// uses = 3: a first use, a second reserved and held at record.effect.before, the approver's cancel, the second
// released and completing, and a third taking no use of the cancelled approval, filing a request of its own; the twin
// sends no cancel and the third completes.
func fs25Cancel(cancel bool) *Schedule {
	state := &fs25State{}
	steps := []*Step{
		state.setup(3),
		{Actor: "callerA", Action: state.call("callerA", 0)},
		{Actor: "callerB", Action: state.call("callerB", 1), Await: "record.effect.before"},
	}
	if cancel {
		steps = append(steps, &Step{Actor: "approver", Action: func(ctx context.Context, net *Net) error {
			return fs25Retry(func() error { return state.world.Cancel(ctx, state.approvalId) })
		}})
	}
	steps = append(steps,
		&Step{Release: []string{sidecartest.ActorBarrierSite("callerB", "record.effect.before")}},
		&Step{Actor: "callerB", Join: true},
		&Step{Actor: "callerC", Action: state.call("callerC", 2)},
		&Step{Actor: "judge", Action: func(ctx context.Context, net *Net) error {
			if err := errors.Join(state.done("callerA"), state.done("callerB")); err != nil {
				return fmt.Errorf("a use reserved before the cancel: %w", err)
			}
			if cancel {
				return errors.Join(state.filedAnother("callerC"), state.effects(2))
			}
			return errors.Join(state.done("callerC"), state.effects(3))
		}},
		state.reconcile(),
	)
	schedule := &Schedule{Id: "FS-25 cancel", Steps: steps, Check: fs25Checks(), Tiers: []Tier{TierT2}}
	if cancel {
		schedule.Refuses = "a use after the approver's cancel, taking none of the cancelled approval's"
		schedule.Twin = func(net *Net) *Schedule { return fs25Cancel(false) }
	}
	return schedule
}

// See the file header.
func Fs25Cancel(net *Net) *Schedule {
	return fs25Cancel(true)
}

// uses = 2 on the fake clock: two uses reserved at not_after - 1 s and held before their effects; the clock moves 5 min
// and the first completes; the second's caller and the daemon are killed and the daemon restarted, and the clock moves
// to retry, past which a retry of the second only reconciles: + 11 min, refused; the twin's + 9 min, completing.
func fs25Expiry(late bool) *Schedule {
	state := &fs25State{}
	retryAt := 4 * time.Minute
	if late {
		retryAt = 6 * time.Minute
	}
	schedule := &Schedule{
		Id: "FS-25 expiry",
		Steps: []*Step{
			state.setup(2),
			{Advance: fs25Lifetime - time.Second},
			{Actor: "callerA", Action: state.call("callerA", 0), Await: "record.effect.before"},
			{Actor: "callerB", Action: state.call("callerB", 1), Await: "record.effect.before"},
			{Advance: 5 * time.Minute},
			{Release: []string{sidecartest.ActorBarrierSite("callerA", "record.effect.before")}},
			{Actor: "callerA", Join: true},
			{Actor: "callerB", Kill: true},
			{Actor: fs25Daemon, Kill: true},
			{Actor: fs25Daemon, Restart: fs25Daemon},
			{Advance: retryAt},
			{Actor: "callerB2", Action: state.call("callerB2", 1)},
			{Actor: "judge", Action: func(ctx context.Context, net *Net) error {
				if err := state.done("callerA"); err != nil {
					return fmt.Errorf("a reservation at not_after - 1 s completing at + 5 min: %w", err)
				}
				if !late {
					return errors.Join(state.done("callerB2"), state.effects(2))
				}
				answer, err := state.answer("callerB2")
				if err != nil {
					return err
				}
				if answer.action.Outcome == nil || answer.action.Outcome.State == sidecar.ApprovalOutcomeDone ||
					!errors.Is(answer.action.Outcome.Err, sidecar.ErrApprovalExpired) {
					return fmt.Errorf("a retry at + 11 min: %v, %+v", answer.err, answer.action.Outcome)
				}
				return state.effects(1)
			}},
			state.reconcile(),
		},
		Check: fs25Checks(),
		Tiers: []Tier{TierT2},
	}
	if late {
		schedule.Refuses = "a retry at not_after + 11 min, past the completion window, which only reconciles"
		schedule.Twin = func(net *Net) *Schedule { return fs25Expiry(false) }
	}
	return schedule
}

// See the file header.
func Fs25Expiry(net *Net) *Schedule {
	return fs25Expiry(true)
}

// A dns_set approved until not_after: the daemon presents it at not_after - 30 s, past the server-gated bound of
// not_after - 60 s, refused expired before any Reserve; the twin presents it at not_after - 90 s and completes.
func fs25ServerGatedExpiry(late bool) *Schedule {
	state := &fs25State{}
	presentAt := fs25Lifetime - 90*time.Second
	if late {
		presentAt = fs25Lifetime - 30*time.Second
	}
	var dnsAction *sidecar.StoredCanonicalAction
	answer := &fs25Answer{}
	schedule := &Schedule{
		Id: "FS-25 server-gated expiry",
		Steps: []*Step{
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				world, err := sidecartest.NewApprovalWorld(net, fs25Daemon)
				if err != nil {
					return err
				}
				state.world = world
				dnsAction, err = world.DnsAction("192.0.2.110")
				if err != nil {
					return err
				}
				approvalId, err := state.file(ctx, dnsAction)
				if err != nil {
					return err
				}
				state.approvalId = approvalId
				notAfter := net.Clock().Now().Add(fs25Lifetime)
				if err := fs25Retry(func() error { return world.Approve(ctx, approvalId, 1, notAfter, nil) }); err != nil {
					return err
				}
				return fs25Retry(func() error { return world.PollInbox(ctx) })
			}},
			{Advance: presentAt},
			{Actor: "callerA", Action: func(ctx context.Context, net *Net) error {
				answer.err = fs25Retry(func() error {
					answer.action = state.world.Action(dnsAction)
					return state.world.Authorize(ctx, answer.action)
				})
				return nil
			}},
			{Actor: "judge", Action: func(ctx context.Context, net *Net) error {
				sink := state.world.Sink(sidecar.SidecarActionDnsSet)
				if late {
					ledger, err := state.world.LedgerState(state.approvalId)
					if err != nil {
						return err
					}
					if !errors.Is(answer.err, sidecar.ErrApprovalExpired) || sink.EffectCount() != 0 || len(ledger.Reserves) != 0 {
						return fmt.Errorf("a server-gated use at not_after - 30 s: %v, %d effects, %d Reserves", answer.err, sink.EffectCount(), len(ledger.Reserves))
					}
					return nil
				}
				if answer.err != nil || answer.action.Outcome == nil || answer.action.Outcome.State != sidecar.ApprovalOutcomeDone || sink.EffectCount() != 1 {
					return fmt.Errorf("a server-gated use at not_after - 90 s: %v, %+v", answer.err, answer.action.Outcome)
				}
				return nil
			}},
			state.reconcile(),
		},
		Check: fs25Checks(),
		Tiers: []Tier{TierT2},
	}
	if late {
		schedule.Refuses = "a server-gated use presented at not_after - 30 s, past the gate's skew bound"
		schedule.Twin = func(net *Net) *Schedule { return fs25ServerGatedExpiry(false) }
	}
	return schedule
}

// See the file header.
func Fs25ServerGatedExpiry(net *Net) *Schedule {
	return fs25ServerGatedExpiry(true)
}

// uses = 3: a first use; a second reserved and held at record.effect.before; the run tainted; the second released,
// completing (a use reserved before the taint, spend step 2); the third refused stale, which files a tainted request
// and answers pending (TS1). The twin taints nothing and the third completes.
func fs25Tainted(taint bool) *Schedule {
	state := &fs25State{}
	steps := []*Step{
		state.setup(3),
		{Actor: "callerA", Action: state.call("callerA", 0)},
		{Actor: "callerB", Action: state.call("callerB", 1), Await: "record.effect.before"},
	}
	if taint {
		steps = append(steps, &Step{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			return fs25Retry(func() error { return state.world.Taint(ctx) })
		}})
	}
	steps = append(steps,
		&Step{Release: []string{sidecartest.ActorBarrierSite("callerB", "record.effect.before")}},
		&Step{Actor: "callerB", Join: true},
		&Step{Actor: "callerC", Action: state.call("callerC", 2)},
		&Step{Actor: "judge", Action: func(ctx context.Context, net *Net) error {
			if err := errors.Join(state.done("callerA"), state.done("callerB")); err != nil {
				return fmt.Errorf("a use reserved before the taint: %w", err)
			}
			if !taint {
				return errors.Join(state.done("callerC"), state.effects(3))
			}
			answer, err := state.answer("callerC")
			if err != nil {
				return err
			}
			pending := &sidecar.ApprovalPendingError{}
			if !errors.As(answer.err, &pending) || pending.ApprovalId == state.approvalId {
				return fmt.Errorf("a use after the taint: %v", answer.err)
			}
			request := state.world.Log().Request(pending.ApprovalId)
			if request == nil || !request.Request.GetTainted() {
				return errors.New("the use after the taint filed no tainted request")
			}
			return state.effects(2)
		}},
		state.reconcile(),
	)
	schedule := &Schedule{Id: "FS-25 tainted after the first use", Steps: steps, Check: fs25Checks(), Tiers: []Tier{TierT2}}
	if taint {
		schedule.Refuses = "a use in the run tainted after its first, refused stale and filed tainted"
		schedule.Twin = func(net *Net) *Schedule { return fs25Tainted(false) }
	}
	return schedule
}

// See the file header.
func Fs25TaintedAfterFirstUse(net *Net) *Schedule {
	return fs25Tainted(true)
}
