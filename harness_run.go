//go:build !ios_extension && !sidecar_http

// A Harness run (DESIGN-COMPUTE §7.8, R-HARN-8, IC-12, I-8, I-9): one agent's run, kept as a RunStore run of harness
// ur-harness with no harness process, so every gate, the router and record_query read one taint and one set of
// marks for it.
//
// Taint is write-ahead (DESIGN §16.6, D-MCP-16): Taint fsyncs through RunStore.Taint before the data that tainted the
// run reaches the model or a tool's result returns, and a failed taint fails the call. Marks are kept the same way
// (RunStore.Mark, §8.9's rule): limited_use (§25.10) and private (§7.8, CO-43), each fsynced before the data that gave
// it leaves the daemon. Both only accumulate, and a run whose file is missing or unreadable reads tainted and marked,
// so a restart never reopens egress.
//
// Authorize (harness_approval.go) is the outward-action gate a tool's before-hook calls, Untrusted
// (harness_untrusted.go) fences untrusted text, and SendIsOutward (harness_send.go) is kind 24's rule.
//
// Safe for concurrent use: the run's state is the store's, which is.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// The harness name a Harness run's file carries (§16.6's run file), which tells its runs from hook-recorded ones.
const HarnessRunHarnessName = "ur-harness"

// A run's marks, as §24.5's SessionEntryBody.marks writes them: bit 0 limited_use (§25.10), bit 1 private (§7.8).
type HarnessMark uint32

const (
	HarnessMarkLimitedUse HarnessMark = 1 << 0
	HarnessMarkPrivate    HarnessMark = 1 << 1
)

// Each mark's name in the run file, in bit order, as INFER's router and GW's run handle read them.
var harnessMarkNames = []struct {
	mark HarnessMark
	name string
}{
	{mark: HarnessMarkLimitedUse, name: "limited_use"},
	{mark: HarnessMarkPrivate, name: "private"},
}

// Every mark this build knows.
const harnessMarkAll = HarnessMarkLimitedUse | HarnessMarkPrivate

// The run file's names of the marks set, in bit order.
func (self HarnessMark) Names() []string {
	names := []string{}
	for _, entry := range harnessMarkNames {
		if self&entry.mark != 0 {
			names = append(names, entry.name)
		}
	}
	return names
}

// The marks names give. A name this build does not know is kept by the store and read here as every mark, since a
// newer build's mark restricts something this one cannot tell.
func HarnessMarkOf(names []string) HarnessMark {
	marks := HarnessMark(0)
	for _, name := range names {
		index := slices.IndexFunc(harnessMarkNames, func(entry struct {
			mark HarnessMark
			name string
		}) bool {
			return entry.name == name
		})
		if index < 0 {
			return harnessMarkAll
		}
		marks |= harnessMarkNames[index].mark
	}
	return marks
}

var (
	// The run has no id or no store.
	ErrHarnessRunInvalid = errors.New("harness run is malformed")
)

// The run store as a Harness run uses it: Sidecar.Runs, or a test's.
type HarnessRunStore interface {
	Create(ctx context.Context, run *RunFile) error
	Get(runId Id) (*RunFile, error)
	Taint(ctx context.Context, runId Id, reason RunTaintReason) error
	Tainted(runId Id) bool
	TaintReasons(runId Id) []RunTaintReason
	Mark(ctx context.Context, runId Id, mark string) error
	Marks(runId Id) ([]string, error)
}

var _ HarnessRunStore = (*RunStore)(nil)

// What a run is built on.
type HarnessRunArgs struct {
	RunId   Id
	AgentId Id
	// Required: the network's run store.
	Runs HarnessRunStore
	// §5.4's gate: the Sidecar's Authorize. Nil refuses every outward action.
	Gate HarnessGate
	// The requester's approvals, which a waiting action watches. Nil refuses an action that waits for a person.
	Approvals HarnessApprovals
	// SAFE's verdict of an automatic decision (§27.9), for the note a run shows. Nil shows the note without one.
	AutoVerdicts HarnessAutoVerdicts
	// Emits approval_pending and approval_resolved as the run's agent's. Nil emits nothing.
	Emit func(agentId Id, event *HarnessEvent) error
	// A run started tainted (§7.9's child of a tainted run, a continuation of a flagged node), with its reasons.
	TaintReasons []RunTaintReason
	// Marks a run starts with (§7.9, §24.7).
	Marks HarnessMark
}

// One agent's run.
type HarnessRun struct {
	runId        Id
	agentId      Id
	runs         HarnessRunStore
	gate         HarnessGate
	approvals    HarnessApprovals
	autoVerdicts HarnessAutoVerdicts
	emit         func(agentId Id, event *HarnessEvent) error
}

// A run over args, its file created (harness ur-harness, no harness process) unless it exists, as a continued run's
// does; its starting taint and marks written, write-ahead, before it returns.
func NewHarnessRun(ctx context.Context, args *HarnessRunArgs) (*HarnessRun, error) {
	if args == nil || args.Runs == nil || args.RunId == (Id{}) || args.AgentId == (Id{}) {
		return nil, ErrHarnessRunInvalid
	}
	run := &HarnessRun{
		runId:        args.RunId,
		agentId:      args.AgentId,
		runs:         args.Runs,
		gate:         args.Gate,
		approvals:    args.Approvals,
		autoVerdicts: args.AutoVerdicts,
		emit:         args.Emit,
	}
	err := args.Runs.Create(ctx, &RunFile{RunId: args.RunId, Harness: HarnessRunHarnessName})
	if err != nil && !errors.Is(err, ErrRunExists) {
		return nil, err
	}
	for _, reason := range args.TaintReasons {
		if err := run.Taint(ctx, reason); err != nil {
			return nil, err
		}
	}
	if args.Marks != 0 {
		if err := run.Mark(ctx, args.Marks); err != nil {
			return nil, err
		}
	}
	return run, nil
}

// The run's id.
func (self *HarnessRun) Id() Id {
	return self.runId
}

// The agent whose run it is.
func (self *HarnessRun) AgentId() Id {
	return self.agentId
}

// Taints the run for good, write-ahead: fsynced before this returns, so the caller lets the data that tainted it
// reach the model or return only after. An error fails the caller's call; the run reads tainted all the same.
func (self *HarnessRun) Taint(ctx context.Context, reason RunTaintReason) error {
	return self.runs.Taint(ctx, self.runId, reason)
}

// Whether the run is tainted: true too where its file is missing or unreadable.
func (self *HarnessRun) Tainted() bool {
	return self.runs.Tainted(self.runId)
}

// Why the run is tainted, each reason once.
func (self *HarnessRun) TaintReasons() []RunTaintReason {
	return self.runs.TaintReasons(self.runId)
}

// Marks the run for good with each mark set in marks, write-ahead: fsynced before this returns, so the caller lets the
// data that gave them leave only after. An error fails the caller's call.
func (self *HarnessRun) Mark(ctx context.Context, marks HarnessMark) error {
	for _, name := range marks.Names() {
		if err := self.runs.Mark(ctx, self.runId, name); err != nil {
			return fmt.Errorf("the run's %s mark did not persist: %w", name, err)
		}
	}
	return nil
}

// The run's marks. Where they do not read, every mark with the error, so a caller that ignores the error still fails
// closed.
func (self *HarnessRun) Marks() (HarnessMark, error) {
	names, err := self.runs.Marks(self.runId)
	if err != nil {
		return harnessMarkAll, err
	}
	return HarnessMarkOf(names), nil
}
