// ur record export: a plain export asks nothing and prints its lines; bodies, ocsf, otel and --follow ask on the
// terminal first and go as confirmed calls; lines go to a file that is never replaced, or to stdout; and --follow
// hands the daemon an absolute path.

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target that runs a record's export, as a test sets it.
type testUrRecordExportTarget struct {
	testUrDaemonTarget
	lines     []string
	exports   []*urRecordExportParams
	confirmed []bool
	follows   []*urRecordExportParams
}

func (self *testUrRecordExportTarget) recordExport(ctx context.Context, params *urRecordExportParams, pid int, confirmed bool) (*urRecordExportReply, error) {
	self.exports = append(self.exports, params)
	self.confirmed = append(self.confirmed, confirmed)
	return &urRecordExportReply{Lines: self.lines}, nil
}

func (self *testUrRecordExportTarget) recordExportFollow(ctx context.Context, params *urRecordExportParams, pid int, confirmed bool) (*urRecordExportFollowReply, error) {
	if !confirmed {
		return nil, sidecar.ErrRecordExportUnconfirmed
	}
	self.follows = append(self.follows, params)
	return &urRecordExportFollowReply{JobId: sidecar.NewId()}, nil
}

func TestRecordExportAsksOnlyForBodyData(t *testing.T) {
	target := &testUrRecordExportTarget{lines: []string{`{"entry":"00"}`, `{"entry":"01"}`}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	runId := sidecar.NewId()
	plain := []string{"ur", "record", "export", "--log=team", "--since=2026-11-05", "--until=2026-11-06T00:00:00Z", "--run=" + runId.String(), "--kind=context,change,1024"}
	if code := cli.main(context.Background(), plain); code != urExitOk || len(target.exports) != 1 || target.confirmed[0] {
		t.Fatalf("a plain export: exit %d, %v: %s", code, target.confirmed, stderr.String())
	}
	if stdout.String() != "{\"entry\":\"00\"}\n{\"entry\":\"01\"}\n" {
		t.Errorf("stdout: %q", stdout.String())
	}
	params := target.exports[0]
	if params.SinceMillis != 1793836800000 || params.UntilMillis != 1793923200000 || params.Run == nil || *params.Run != runId ||
		len(params.Kinds) != 3 || params.Kinds[0] != 16 || params.Kinds[1] != 17 || params.Kinds[2] != 1024 {
		t.Errorf("the params: %+v", params)
	}
	for _, flags := range [][]string{{"--bodies"}, {"--format=ocsf"}, {"--format=otel"}} {
		args := append([]string{"ur", "record", "export", "--log=team"}, flags...)
		before := len(target.exports)
		if code := cli.main(context.Background(), args); code != urExitFailed || len(target.exports) != before {
			t.Fatalf("%v with no terminal: exit %d", flags, code)
		}
		tty := &testTty{lines: []string{"n"}}
		cli.openTty = func() (urTty, error) { return tty, nil }
		if code := cli.main(context.Background(), args); code != urExitOk || len(target.exports) != before {
			t.Fatalf("%v after a no: exit %d", flags, code)
		}
		tty = &testTty{lines: []string{"yes"}}
		if code := cli.main(context.Background(), args); code != urExitOk || len(target.exports) != before+1 || !target.confirmed[before] {
			t.Fatalf("%v after a yes: exit %d", flags, code)
		}
		if !strings.Contains(tty.written.String(), "beyond recall") {
			t.Errorf("%v: the question does not say a copy is beyond recall: %q", flags, tty.written.String())
		}
		cli.openTty = func() (urTty, error) { return nil, os.ErrNotExist }
	}
	if code := cli.main(context.Background(), []string{"ur", "record", "export", "--log=team", "--format=csv"}); code != urExitFailed {
		t.Errorf("an unknown format: exit %d", code)
	}
	if code := cli.main(context.Background(), []string{"ur", "record", "export", "--log=team", "--kind=nonsense"}); code != urExitFailed {
		t.Errorf("an unknown kind: exit %d", code)
	}
}

func TestRecordExportWritesAFileAndFollows(t *testing.T) {
	target := &testUrRecordExportTarget{lines: []string{`{"entry":"00"}`}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	directory := t.TempDir()
	out := filepath.Join(directory, "team.jsonl")
	args := []string{"ur", "record", "export", "--log=team", "--out=" + out}
	if code := cli.main(context.Background(), args); code != urExitOk || stdout.Len() != 0 {
		t.Fatalf("to a file: exit %d, stdout %q: %s", code, stdout.String(), stderr.String())
	}
	if written, err := os.ReadFile(out); err != nil || string(written) != "{\"entry\":\"00\"}\n" {
		t.Fatalf("the file: %q, %v", written, err)
	}
	if code := cli.main(context.Background(), args); code != urExitFailed || len(target.exports) != 1 {
		t.Fatalf("over a file that exists: exit %d, %d exports", code, len(target.exports))
	}

	if code := cli.main(context.Background(), []string{"ur", "record", "export", "--log=team", "--follow"}); code != urExitFailed {
		t.Fatalf("--follow with no file: exit %d", code)
	}
	follow := []string{"ur", "record", "export", "--log=team", "--follow", "--out=" + filepath.Join(directory, "follow.jsonl")}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), follow); code != urExitOk || len(target.follows) != 0 {
		t.Fatalf("--follow after a no: exit %d", code)
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), follow); code != urExitOk || len(target.follows) != 1 || !filepath.IsAbs(target.follows[0].Path) {
		t.Fatalf("--follow after a yes: exit %d, %+v", code, target.follows)
	}
}

// The follow job is a Confirm method; a plain export is not, and a target with no record serves neither.
func TestRecordExportMethodsConfirm(t *testing.T) {
	confirm := map[string]bool{}
	for _, method := range urRecordExportMethods(&testUrRecordExportTarget{}) {
		confirm[method.Name] = method.Confirm
	}
	if len(confirm) != 2 || confirm[urMethodRecordExport] || !confirm[urMethodRecordExportFollow] {
		t.Errorf("the methods' confirm flags: %v", confirm)
	}
	if methods := urRecordExportMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no record serves the export methods")
	}
}
