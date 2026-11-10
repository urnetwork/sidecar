// ur record log: on and off ask on the terminal and reach the daemon only on a yes, as Confirm methods; a witness is
// typed as name,url,vkey; checkpoint and status print what the daemon answers.

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target that runs a record's verifiable log, as a test sets it.
type testUrRecordLogTarget struct {
	testUrDaemonTarget
	ons        []*urRecordLogOnParams
	offs       []string
	checkpoint *urRecordLogCheckpointReply
	logStatus  *urRecordLogStatusReply
}

func (self *testUrRecordLogTarget) recordLogOn(ctx context.Context, params *urRecordLogOnParams, confirmed bool) error {
	if confirmed {
		self.ons = append(self.ons, params)
	}
	return nil
}

func (self *testUrRecordLogTarget) recordLogOff(ctx context.Context, log string, confirmed bool) error {
	if confirmed {
		self.offs = append(self.offs, log)
	}
	return nil
}

func (self *testUrRecordLogTarget) recordLogCheckpoint(ctx context.Context, log string) (*urRecordLogCheckpointReply, error) {
	return self.checkpoint, nil
}

func (self *testUrRecordLogTarget) recordLogStatus(ctx context.Context, log string) (*urRecordLogStatusReply, error) {
	return self.logStatus, nil
}

func TestRecordLogOnAndOffAskOnTheTerminal(t *testing.T) {
	target := &testUrRecordLogTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	witness := "auditor,https://auditor.witness.example/log,auditor+00000000+AAAA"
	args := []string{"ur", "record", "log", "on", "--log=team", "--interval=10m", "--witness=" + witness}
	if code := cli.main(context.Background(), args); code != urExitFailed || len(target.ons) != 0 {
		t.Fatalf("with no terminal: exit %d, %v", code, target.ons)
	}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), args); code != urExitOk || len(target.ons) != 0 {
		t.Fatalf("a no turned the log on: exit %d, %v", code, target.ons)
	}
	if !strings.Contains(tty.written.String(), "auditor at https://auditor.witness.example/log") {
		t.Errorf("the question names no witness: %q", tty.written.String())
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), args); code != urExitOk || len(target.ons) != 1 {
		t.Fatalf("a yes: exit %d, %v: %s", code, target.ons, stderr.String())
	}
	on := target.ons[0]
	if on.Log != "team" || on.IntervalSeconds != 600 || len(on.Witnesses) != 1 || on.Witnesses[0].Name != "auditor" ||
		on.Witnesses[0].Url != "https://auditor.witness.example/log" || on.Witnesses[0].Vkey != "auditor+00000000+AAAA" {
		t.Errorf("the params: %+v %+v", on, on.Witnesses)
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "record", "log", "on", "--log=team", "--witness=auditor"}); code != urExitFailed || len(target.ons) != 1 {
		t.Errorf("a witness with no url or key: exit %d", code)
	}
	if code := cli.main(context.Background(), []string{"ur", "record", "log", "on", "--log=team", "--interval=90"}); code != urExitFailed {
		t.Errorf("an interval with no unit: exit %d", code)
	}

	tty = &testTty{lines: []string{"y"}}
	if code := cli.main(context.Background(), []string{"ur", "record", "log", "off", "--log=team"}); code != urExitOk || len(target.offs) != 1 {
		t.Fatalf("off: exit %d, %v", code, target.offs)
	}
	if !strings.Contains(stdout.String(), "is off") {
		t.Errorf("off printed %q", stdout.String())
	}
}

func TestRecordLogCheckpointAndStatusPrint(t *testing.T) {
	checkpointer := sidecar.NewId()
	target := &testUrRecordLogTarget{
		checkpoint: &urRecordLogCheckpointReply{Batch: 4, Size: 91, Cosigned: []string{"auditor"}},
		logStatus: &urRecordLogStatusReply{
			LogId: sidecar.NewId(), On: true, Origin: "ur.io/recurd/log/00", Checkpointer: &checkpointer, LogKey: "origin+00000000+AAAA",
			IntervalSeconds: 3600, ThisDevice: true, Batch: 4, Size: 91, Root: "ab", WaitingLeafCount: 2,
			Witnesses: []*urRecordLogWitnessStatus{{Name: "auditor", Url: "https://auditor.witness.example/log", MissCount: 2, Refusal: "403: it does not trust this log key", CosignedBatch: 3}},
			Findings:  []string{"batch 5 has a second entry with another note: a fork"},
		},
	}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "record", "log", "checkpoint"}); code != urExitOk {
		t.Fatalf("checkpoint: exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "batch 4 filed at size 91, cosigned by auditor") {
		t.Errorf("checkpoint printed %q", stdout.String())
	}
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "record", "log", "status", "--log=team"}); code != urExitOk {
		t.Fatalf("status: exit %d: %s", code, stderr.String())
	}
	for _, want := range []string{": on", "(this device)", "log key: origin+00000000+AAAA", "batch 4, size 91", "2 leaves wait", "403", "a fork"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("status lacks %q: %s", want, stdout.String())
		}
	}
	target.checkpoint = &urRecordLogCheckpointReply{}
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "record", "log", "checkpoint"}); code != urExitOk || !strings.Contains(stdout.String(), "nothing waits") {
		t.Errorf("a checkpoint with nothing due: exit %d, %q", code, stdout.String())
	}
}

// on and off are Confirm methods; checkpoint and status are not, and a target with no record serves none.
func TestRecordLogMethodsConfirm(t *testing.T) {
	confirm := map[string]bool{}
	for _, method := range urRecordLogMethods(&testUrRecordLogTarget{}) {
		confirm[method.Name] = method.Confirm
	}
	if len(confirm) != 4 || !confirm[urMethodRecordLogOn] || !confirm[urMethodRecordLogOff] || confirm[urMethodRecordLogCheckpoint] || confirm[urMethodRecordLogStatus] {
		t.Errorf("the methods' confirm flags: %v", confirm)
	}
	if methods := urRecordLogMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no record serves the log methods")
	}
}
