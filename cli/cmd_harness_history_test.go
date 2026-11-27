// ur harness continue and ur harness export (CTXH-M11-05; DESIGN-COMPUTE §24.6, §24.7): export asks on the terminal
// before the daemon reads anything and calls it confirmed, with the caller's pid for the ancestry taint; continue
// prints what the new run takes on the terminal, asks, and calls the person's confirmed act, a live run refused before
// any question and --at asking a fork.

package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target that answers the history methods as a test sets them, recording each call in order.
type testUrHarnessHistoryTarget struct {
	testUrDaemonTarget
	stateLock sync.Mutex
	// "plan <act> <at>", "continue <act> <pid> <confirmed>", "export <pid> <confirmed>", in order
	steps []string
	live  bool
}

func (self *testUrHarnessHistoryTarget) step(text string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.steps = append(self.steps, text)
}

func (self *testUrHarnessHistoryTarget) taken() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.steps...)
}

func (self *testUrHarnessHistoryTarget) harnessContinuePlan(ctx context.Context, params *sidecar.HarnessContinueParams) (*sidecar.SessionContinuePlan, error) {
	self.step("plan " + string(params.Act) + " " + params.At)
	plan := &sidecar.SessionContinuePlan{RunId: params.RunId, Act: sidecar.SessionContinueActContinue, Model: "engy-glm-5.2-high",
		PreviousModel: "local-gemma-4-e4b-high", NodeCount: 4, FlaggedCount: 1, Tainted: true, Private: true}
	if params.Act != "" {
		plan.Act = params.Act
	}
	if self.live {
		plan.Live, plan.LiveState = true, sidecar.AgentStateWorking
	}
	return plan, nil
}

func (self *testUrHarnessHistoryTarget) harnessContinue(ctx context.Context, params *sidecar.HarnessContinueParams, pid int, confirmed bool) (*sidecar.SessionContinued, error) {
	self.step("continue " + string(params.Act) + " " + map[bool]string{true: "own", false: "other"}[pid == os.Getpid()] + " " + map[bool]string{true: "confirmed", false: "unconfirmed"}[confirmed])
	return &sidecar.SessionContinued{AgentId: sidecar.NewId(), Name: "planner", NewRunId: sidecar.NewId()}, nil
}

func (self *testUrHarnessHistoryTarget) harnessExport(ctx context.Context, params *sidecar.HarnessExportParams, pid int, confirmed bool) (*sidecar.HarnessExportReply, error) {
	self.step("export " + map[bool]string{true: "own", false: "other"}[pid == os.Getpid()] + " " + map[bool]string{true: "confirmed", false: "unconfirmed"}[confirmed])
	return &sidecar.HarnessExportReply{Lines: []string{`{"type":"session","version":3}`, `{"type":"message","id":"0000000a"}`}, NodeCount: 1, PiiCount: 2}, nil
}

// export with no terminal, or a no on it, calls nothing; a yes calls the daemon confirmed with this process's pid, and
// the lines go to stdout with the counts on stderr.
func TestUrHarnessExportAsksBeforeTheDaemonReads(t *testing.T) {
	target := &testUrHarnessHistoryTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	runId := sidecar.NewId().String()
	cli, _, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "harness", "export", runId}); code == urExitOk {
		t.Fatal("an export with no terminal ran")
	}
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "harness", "export", runId}); code != urExitOk || !strings.Contains(stdout.String(), "nothing was exported") {
		t.Fatalf("a declined export: exit %d, %q", code, stdout.String())
	}
	if steps := target.taken(); len(steps) != 0 {
		t.Fatalf("the daemon was called before a yes: %v", steps)
	}
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	tty := &testTty{lines: []string{"y"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "harness", "export", runId}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if steps := target.taken(); len(steps) != 1 || steps[0] != "export own confirmed" {
		t.Fatalf("steps %v", steps)
	}
	if !strings.HasPrefix(stdout.String(), `{"type":"session","version":3}`) || !strings.Contains(stderr.String(), "2 addresses and numbers hashed") ||
		!strings.Contains(tty.written.String(), "hashed") {
		t.Fatalf("stdout %q, stderr %q, tty %q", stdout.String(), stderr.String(), tty.written.String())
	}
}

// continue prints the plan on the terminal and asks, then calls the person's confirmed act; --at asks a fork; a live
// run is refused before any question.
func TestUrHarnessContinuePrintsPlanAndAsks(t *testing.T) {
	target := &testUrHarnessHistoryTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	runId := sidecar.NewId().String()
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	tty := &testTty{lines: []string{"y"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "harness", "continue", runId, "--model=engy-glm-5.2-high"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if steps := target.taken(); len(steps) != 2 || steps[0] != "plan  " || steps[1] != "continue  own confirmed" {
		t.Fatalf("steps %v", steps)
	}
	shown := tty.written.String()
	if !strings.Contains(shown, "in place of local-gemma-4-e4b-high") || !strings.Contains(shown, "taint") || !strings.Contains(shown, "private") ||
		!strings.Contains(stdout.String(), "ur harness --agent=planner") {
		t.Fatalf("tty %q, stdout %q", shown, stdout.String())
	}
	cli, _, _ = newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"y"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "harness", "continue", runId, "--at=0123456789ab"}); code != urExitOk {
		t.Fatal("a fork did not run")
	}
	if steps := target.taken(); len(steps) != 4 || steps[2] != "plan fork 0123456789ab" || steps[3] != "continue fork own confirmed" {
		t.Fatalf("steps %v", steps)
	}
	target.live = true
	cli, _, _ = newTestUrCli(daemon.socketPath)
	asked := &testTty{lines: []string{"y"}}
	cli.openTty = func() (urTty, error) { return asked, nil }
	if code := cli.main(context.Background(), []string{"ur", "harness", "continue", runId}); code == urExitOk {
		t.Fatal("a live run was continued")
	}
	if steps := target.taken(); len(steps) != 5 || asked.written.Len() != 0 {
		t.Fatalf("a live run: steps %v, asked %q", steps, asked.written.String())
	}
}
