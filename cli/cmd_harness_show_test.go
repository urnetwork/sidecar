// ur harness show (CTXH-M11-04; DESIGN-COMPUTE §24.6): the daemon taints each run its caller's ancestry binds before it
// reads anything, a refused taint reading nothing; a run's text prints only to a terminal, off one the daemon is asked
// for stubs and the view prints each node's and message's place and size alone; and --call names a call from 1.

package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target that answers a run as a test sets it, recording each taint and show in order.
type testUrHarnessShowTarget struct {
	testUrDaemonTarget
	stateLock sync.Mutex
	// "taint <pid>" and "show <run> <call> <terminal>", in order
	steps []string
	// the taint's answer
	taintErr error
}

func (self *testUrHarnessShowTarget) harnessShowTaint(ctx context.Context, pid int) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.steps = append(self.steps, "taint "+strconv.Itoa(pid))
	return self.taintErr
}

func (self *testUrHarnessShowTarget) harnessShow(ctx context.Context, params *urHarnessShowParams) (*urHarnessShowReply, error) {
	self.stateLock.Lock()
	self.steps = append(self.steps, "show "+params.Run+" "+strconv.Itoa(params.Call)+" "+map[bool]string{true: "terminal", false: "stubs"}[params.Terminal])
	self.stateLock.Unlock()
	reply := &urHarnessShowReply{RunId: params.Run, CallCount: 1, Stubbed: !params.Terminal}
	if params.Call == 0 {
		node := &urHarnessShowNode{NodeId: strings.Repeat("ab", 16), Type: "message", State: "live", ByteCount: 42}
		if params.Terminal {
			node.Item = `{"message":{"content":"a secret plan","role":"user"}}`
		}
		reply.Nodes = []*urHarnessShowNode{node}
		return reply, nil
	}
	message := &urHarnessShowMessage{Role: "user", ByteCount: 13}
	if params.Terminal {
		message.Text = "a secret plan"
	}
	reply.Call = &urHarnessShowCall{N: params.Call, Check: "verified", Renderer: "harness-1", Exact: true, Messages: []*urHarnessShowMessage{message}}
	return reply, nil
}

// The steps so far.
func (self *testUrHarnessShowTarget) taken() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.steps...)
}

// Off a terminal the daemon is asked for stubs, and neither the tree nor a call prints any of the run's text: each
// node and message prints its place and size alone. On one, the text prints.
func TestUrHarnessShowStubsOffTerminal(t *testing.T) {
	target := &testUrHarnessShowTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	runId := sidecar.NewId().String()
	for _, args := range [][]string{{"ur", "harness", "show", runId}, {"ur", "harness", "show", runId, "--call=1"}} {
		cli, stdout, stderr := newTestUrCli(daemon.socketPath)
		if code := cli.main(context.Background(), args); code != urExitOk {
			t.Fatalf("%v: exit %d: %s", args, code, stderr.String())
		}
		if strings.Contains(stdout.String(), "a secret plan") || !strings.Contains(stdout.String(), "only to a terminal") {
			t.Fatalf("off a terminal, %v printed %q", args, stdout.String())
		}
		cli, stdout, stderr = newTestUrCli(daemon.socketPath)
		cli.stdoutIsTerminal = func() bool { return true }
		if code := cli.main(context.Background(), args); code != urExitOk {
			t.Fatalf("%v on a terminal: exit %d: %s", args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "a secret plan") {
			t.Fatalf("on a terminal, %v printed %q", args, stdout.String())
		}
	}
	steps := target.taken()
	if len(steps) != 8 || !strings.HasSuffix(steps[1], " 0 stubs") || !strings.HasSuffix(steps[3], " 0 terminal") || !strings.HasSuffix(steps[5], " 1 stubs") {
		t.Fatalf("steps %v", steps)
	}
	cli, _, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "harness", "show", runId, "--call=0"}); code == urExitOk {
		t.Fatal("--call=0 was taken")
	}
}

// The daemon taints the caller's ancestry's runs, with the caller's pid, before it reads the run; a taint that fails
// reads nothing and fails the call.
func TestUrHarnessShowTaintsAncestorRuns(t *testing.T) {
	target := &testUrHarnessShowTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	runId := sidecar.NewId().String()
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "harness", "show", runId}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	steps := target.taken()
	if len(steps) != 2 || steps[0] != "taint "+strconv.Itoa(os.Getpid()) || !strings.HasPrefix(steps[1], "show "+runId) {
		t.Fatalf("steps %v", steps)
	}
	target.taintErr = errors.New("the run file did not take its taint")
	cli, _, _ = newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "harness", "show", runId}); code == urExitOk {
		t.Fatal("a show ran past a failed taint")
	}
	if steps := target.taken(); len(steps) != 3 || !strings.HasPrefix(steps[2], "taint ") {
		t.Fatalf("after a failed taint: %v", steps)
	}
}
