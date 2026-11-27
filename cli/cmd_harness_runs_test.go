// ur harness runs (CTXH-M11-06; DESIGN-COMPUTE §24.10's see row): the runs with their nodes' and blobs' bytes apart,
// history's totals and the caps' warning with the largest runs; --size asks largest first and --agent one agent; the
// one tap and the switch ask on the terminal and call the daemon confirmed, nothing before a yes.

package main

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target that answers the runs methods as a test sets them.
type testUrHarnessRunsTarget struct {
	testUrDaemonTarget
	stateLock sync.Mutex
	asked     []*sidecar.HarnessRunsParams
	expiries  []bool
	switches  []bool
}

func (self *testUrHarnessRunsTarget) harnessRuns(ctx context.Context, params *sidecar.HarnessRunsParams) (*sidecar.SessionSizes, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asked = append(self.asked, params)
	big := &sidecar.SessionRunSize{RunId: sidecar.NewId(), AgentLabel: "planner", NodeCount: 150, NodeByteCount: 600 * 1024, BlobCount: 4, BlobByteCount: 30 * 1024 * 1024}
	small := &sidecar.SessionRunSize{RunId: sidecar.NewId(), AgentLabel: "planner", NodeCount: 12, NodeByteCount: 40 * 1024, WithheldCount: 3}
	return &sidecar.SessionSizes{Runs: []*sidecar.SessionRunSize{big, small}, NodeByteCount: 640 * 1024, BlobByteCount: 30 * 1024 * 1024,
		VaultByteCount: 40 * 1024 * 1024, Largest: []*sidecar.SessionRunSize{big},
		Caps: &sidecar.SessionCapState{StorageLimit: 48 * 1024 * 1024, NetworkCap: 43 * 1024 * 1024, NetworkUsed: 40 * 1024 * 1024, NetworkUsedEstimated: true,
			MemberShare: 1, MemberCap: 48 * 1024 * 1024, MemberUsed: 31 * 1024 * 1024, Warning: sidecar.SessionCapNetwork, ExpiryNeed: 6 * 1024 * 1024}}, nil
}

func (self *testUrHarnessRunsTarget) harnessRunsExpire(ctx context.Context, params *sidecar.HarnessRunsExpireParams, pid int, confirmed bool) (*sidecar.SessionExpired, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.expiries = append(self.expiries, confirmed)
	return &sidecar.SessionExpired{BlobCount: 2, ByteCount: 7 * 1024 * 1024, NeedCount: 6 * 1024 * 1024}, nil
}

func (self *testUrHarnessRunsTarget) harnessRunsAutoExpire(ctx context.Context, params *sidecar.HarnessRunsAutoExpireParams, pid int, confirmed bool) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.switches = append(self.switches, params.On && confirmed)
	return nil
}

// The runs print their nodes' and blobs' bytes apart, what is held back, the totals and the warning naming the largest
// run; --size and --agent reach the daemon; --expire and --auto-expire call nothing before a yes, then call confirmed.
func TestUrHarnessRunsSizesBlobsApart(t *testing.T) {
	target := &testUrHarnessRunsTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "harness", "runs", "--size", "--agent=planner"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"nodes 150 600.0 KiB, blobs 4 30.0 MiB", "nodes 12 40.0 KiB, blobs 0 0 B, 3 held back", "history: nodes 640.0 KiB, blobs 30.0 MiB",
		"this vault's alone", "warning: history is near the network cap", "frees 6.0 MiB"} {
		if !strings.Contains(out, want) {
			t.Errorf("the view lacks %q:\n%s", want, out)
		}
	}
	if len(target.asked) != 1 || !target.asked[0].BySize || target.asked[0].AgentLabel != "planner" {
		t.Fatalf("asked %+v", target.asked)
	}
	cli, _, _ = newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "harness", "runs", "--expire"}); code != urExitOk || len(target.expiries) != 0 {
		t.Fatalf("a declined tap: exit %d, %v", code, target.expiries)
	}
	cli, stdout, _ = newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"y"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "harness", "runs", "--expire", "--cap=network"}); code != urExitOk || len(target.expiries) != 1 ||
		!target.expiries[0] || !strings.Contains(stdout.String(), "expired 2 blobs") {
		t.Fatalf("the tap: exit %d, %v, %q", code, target.expiries, stdout.String())
	}
	cli, _, _ = newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "harness", "runs", "--auto-expire=on"}); code != urExitOk || len(target.switches) != 1 || !target.switches[0] {
		t.Fatalf("the switch: exit %d, %v", code, target.switches)
	}
	cli, _, _ = newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "harness", "runs", "--expire", "--cap=everything"}); code == urExitOk {
		t.Fatal("a cap that is none was taken")
	}
}
