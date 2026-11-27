// ur harness continue and ur harness export (DESIGN-COMPUTE §24.6, §24.7, §24.9; CTXH-M11-05; D-CTXH-5, D-CTXH-11):
//
//	ur harness continue <run> [--at=<node>] [--model=<name>] [--name=<name>] [--network=<net>]
//	ur harness export <run> [--out=<path>] [--network=<net>]
//
// continue reads the run from the member's vault and starts a new run in the daemon's Harness that hangs from it
// (the root's session_continue.go): from its tip, refused while the run is live, or with --at a fork at that node, any
// node of it this device holds, named by its id or by its first hex characters as `ur harness show` prints them. It
// prints what the new run takes first: the node, the model and the one it replaces, the taint and the private mark it
// carries, and what this device does not hold; then it asks on the terminal, and the daemon takes the continuation as
// the person's act alone. The new agent's name and run follow, and `ur harness --agent=<name>` talks to it. Moving a
// run into an enclave is CTXH-M14-01's.
//
// export writes the run as Pi's v3 JSONL, every node and part, which Pi and PiG open (the root's session_export_pi.go).
// It asks on the terminal before anything is read; the daemon then taints the runs of a harness among this process's
// ancestors, files the export's disclosure entry in the vault and answers the lines once it lands, with email
// addresses and phone numbers hashed under record.redact.pii. The lines go to stdout, or with --out to a new file.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

func init() {
	registerUrHarnessSubcommand(&urHarnessSubcommand{
		name:  "continue",
		usage: "  ur harness continue <run> [--at=<node>] [--model=<name>] [--name=<name>] [--network=<net>]",
		run:   runUrHarnessContinue,
	})
	registerUrHarnessSubcommand(&urHarnessSubcommand{
		name:  "export",
		usage: "  ur harness export <run> [--out=<path>] [--network=<net>]",
		run:   runUrHarnessExport,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urHarnessHistoryMethods)
}

// What the history methods act on: a daemon target that runs a Sidecar's record and Harness. pid is the caller's, as
// the daemon read it.
type urHarnessHistoryTarget interface {
	harnessContinuePlan(ctx context.Context, params *sidecar.HarnessContinueParams) (*sidecar.SessionContinuePlan, error)
	harnessContinue(ctx context.Context, params *sidecar.HarnessContinueParams, pid int, confirmed bool) (*sidecar.SessionContinued, error)
	harnessExport(ctx context.Context, params *sidecar.HarnessExportParams, pid int, confirmed bool) (*sidecar.HarnessExportReply, error)
}

// The network's continuer.
func (self *urDaemonNetwork) sessionContinue() (*sidecar.Sidecar, *sidecar.SessionContinue, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, nil, err
	}
	continues, err := running.SessionContinue()
	if err != nil {
		return nil, nil, err
	}
	return running, continues, nil
}

func (self *urDaemonNetwork) harnessContinuePlan(ctx context.Context, params *sidecar.HarnessContinueParams) (*sidecar.SessionContinuePlan, error) {
	_, continues, err := self.sessionContinue()
	if err != nil {
		return nil, err
	}
	return continues.Plan(ctx, &params.SessionContinueSpec)
}

// The person's act alone: confirmed, with no harness process among the caller's ancestors.
func (self *urDaemonNetwork) harnessContinue(ctx context.Context, params *sidecar.HarnessContinueParams, pid int, confirmed bool) (*sidecar.SessionContinued, error) {
	running, continues, err := self.sessionContinue()
	if err != nil {
		return nil, err
	}
	if !confirmed || pid <= 0 || running.HarnessAncestor(ctx, pid) {
		return nil, sidecar.ErrHarnessPersonOnly
	}
	continued, err := continues.Continue(ctx, &params.SessionContinueSpec)
	if err != nil {
		return nil, err
	}
	if harness, err := running.Harness(); err == nil {
		harness.OpenView(continued.AgentId)
	}
	return continued, nil
}

// A harness ancestor's runs tainted first, then the run exported under the network's capture redactor.
func (self *urDaemonNetwork) harnessExport(ctx context.Context, params *sidecar.HarnessExportParams, pid int, confirmed bool) (*sidecar.HarnessExportReply, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	if err := running.TaintAncestorRuns(ctx, pid); err != nil {
		return nil, fmt.Errorf("the runs of the harness this command runs under could not be tainted: %w", err)
	}
	record, err := running.Record()
	if err != nil {
		return nil, err
	}
	args := &sidecar.SessionPiExportArgs{RunId: params.Run, Confirmed: confirmed}
	if spool, err := running.Spool(); err == nil {
		args.Redactor = spool.Redactor()
	}
	exported, err := record.SessionPiExport().Export(ctx, args)
	if err != nil {
		return nil, err
	}
	return sidecar.HarnessExportReplyOf(exported), nil
}

// The history methods over target, when it runs a Sidecar's record and Harness.
func urHarnessHistoryMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	history, ok := target.(urHarnessHistoryTarget)
	if !ok {
		return nil
	}
	continueParams := func(call *sidecar.DaemonCall) (*sidecar.HarnessContinueParams, error) {
		params := &sidecar.HarnessContinueParams{}
		if err := decodeUrParams(call, params); err != nil || params.RunId == (sidecar.Id{}) {
			return nil, errors.New("a continuation takes a run")
		}
		return params, nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: sidecar.HarnessDaemonMethodContinuePlan,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := continueParams(call)
				if err != nil {
					return nil, err
				}
				return history.harnessContinuePlan(ctx, params)
			},
		},
		{
			Name:    sidecar.HarnessDaemonMethodContinue,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, err := continueParams(call)
				if err != nil {
					return nil, err
				}
				return history.harnessContinue(ctx, params, urCallPid(call), call.Confirmed)
			},
		},
		{
			Name:    sidecar.HarnessDaemonMethodExport,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &sidecar.HarnessExportParams{}
				if err := decodeUrParams(call, params); err != nil || params.Run == (sidecar.Id{}) {
					return nil, errors.New("an export takes a run")
				}
				return history.harnessExport(ctx, params, urCallPid(call), call.Confirmed)
			},
		},
	}
}

// What a continuation takes, as the person reads it before the question.
func printUrHarnessContinuePlan(out interface{ Write([]byte) (int, error) }, plan *sidecar.SessionContinuePlan) {
	fmt.Fprintf(out, "%s run %s from node %s (last on device %s)\n", plan.Act, plan.RunId, plan.NodeId, plan.WriterSidecarId)
	model := plan.Model
	if plan.PreviousModel != "" {
		model += " in place of " + plan.PreviousModel
		if !plan.PreviousModelHere {
			model += ", which this device cannot run"
		}
	}
	fmt.Fprintf(out, "  model: %s\n", model)
	fmt.Fprintf(out, "  context: %d nodes, %d flagged, %d untrusted\n", plan.NodeCount, plan.FlaggedCount, plan.UntrustedCount)
	carries := []string{}
	if plan.Tainted {
		carries = append(carries, "taint: its sends wait for you")
	}
	if plan.Private {
		carries = append(carries, "the private mark")
	}
	if plan.LimitedUse {
		carries = append(carries, "the limited_use mark")
	}
	if 0 < len(carries) {
		fmt.Fprintf(out, "  carries: %s\n", strings.Join(carries, "; "))
	}
	if plan.Cut {
		fmt.Fprintf(out, "  earlier nodes are not held here (erased, withheld or dropped): the context starts after them\n")
	}
	if 0 < plan.PrunedPartCount {
		fmt.Fprintf(out, "  %d parts not held here read as their markers\n", plan.PrunedPartCount)
	}
	fmt.Fprintf(out, "  it gets the context, not the workspace; web search results stay stubs, so it searches again\n")
}

// Prints the plan, asks on the terminal, then has the daemon start the new run.
func runUrHarnessContinue(ctx context.Context, cli *urCli, options docopt.Opts) error {
	runId, err := parseUrRecordId(urOptionString(options, "<run>"))
	if err != nil {
		return err
	}
	params := &sidecar.HarnessContinueParams{Network: urOptionString(options, "--network"), SessionContinueSpec: sidecar.SessionContinueSpec{
		RunId: runId, At: urOptionString(options, "--at"), Model: urOptionString(options, "--model"), Name: urOptionString(options, "--name"),
	}}
	if params.At != "" {
		params.Act = sidecar.SessionContinueActFork
	}
	plan := &sidecar.SessionContinuePlan{}
	if err := cli.callDaemon(ctx, sidecar.HarnessDaemonMethodContinuePlan, params, false, plan); err != nil {
		return err
	}
	switch {
	case plan.Live:
		return fmt.Errorf("run %s is live: its agent is %s; fork it with --at, or continue once it is idle", plan.RunId, plan.LiveState)
	case plan.LiveUnknown != "":
		return fmt.Errorf("whether run %s is live could not be read (%s); fork it with --at instead", plan.RunId, plan.LiveUnknown)
	}
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	printUrHarnessContinuePlan(tty, plan)
	tty.Close()
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("Start a new run here that %ss run %s on %s?", plan.Act, plan.RunId, plan.Model))
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing was started\n")
		return nil
	}
	continued := &sidecar.SessionContinued{}
	if err := cli.callDaemon(ctx, sidecar.HarnessDaemonMethodContinue, params, true, continued); err != nil {
		return err
	}
	cli.printf("agent %s (%s) runs %s, continuing run %s; ur harness --agent=%s talks to it\n", continued.Name, continued.AgentId,
		continued.NewRunId, plan.RunId, continued.Name)
	return nil
}

// Asks on the terminal before anything is read, then writes the lines the daemon answers.
func runUrHarnessExport(ctx context.Context, cli *urCli, options docopt.Opts) error {
	runId, err := parseUrRecordId(urOptionString(options, "<run>"))
	if err != nil {
		return err
	}
	params := &sidecar.HarnessExportParams{Network: urOptionString(options, "--network"), Run: runId}
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("Export run %s as a Pi session: every node and part of its context leaves the vault, "+
		"email addresses and phone numbers hashed, the export recorded in your vault. A copy that leaves is beyond recall. Go on?", runId))
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing was exported\n")
		return nil
	}
	out := urOptionString(options, "--out")
	var file *os.File
	if out != "" {
		if file, err = createUrRecordOut(out); err != nil {
			return err
		}
	}
	reply := &sidecar.HarnessExportReply{}
	if err := cli.callDaemon(ctx, sidecar.HarnessDaemonMethodExport, params, true, reply); err != nil {
		if file != nil {
			file.Close()
			os.Remove(file.Name())
		}
		return err
	}
	text := ""
	if 0 < len(reply.Lines) {
		text = strings.Join(reply.Lines, "\n") + "\n"
	}
	notes := fmt.Sprintf("%d nodes, %d addresses and numbers hashed", reply.NodeCount, reply.PiiCount)
	if 0 < reply.UnheldCount {
		notes += fmt.Sprintf(", %d nodes not held here left out", reply.UnheldCount)
	}
	if 0 < reply.PrunedPartCount {
		notes += fmt.Sprintf(", %d parts as their markers", reply.PrunedPartCount)
	}
	if file == nil {
		cli.printf("%s", text)
		fmt.Fprintf(cli.stderr, "exported run %s: %s\n", runId, notes)
		return nil
	}
	if err := writeUrRecordOut(file, []byte(text)); err != nil {
		return err
	}
	fmt.Fprintf(cli.stderr, "wrote run %s to %s: %s\n", runId, file.Name(), notes)
	return nil
}
