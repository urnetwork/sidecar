// ur record disclose, open and verify: the plan shown on the terminal before a yes, --dry-run printing it and building
// nothing, the packet written only after the daemon answered, a file never replaced, the caller's pid handed to the
// daemon's ancestry check, and verify's three exit codes on the committed packet vector with no daemon at all.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target that runs a record's disclosure, as a test sets it.
type testUrRecordDiscloseTarget struct {
	testUrDaemonTarget
	plan      *urRecordDisclosedReply
	packet    []byte
	plans     []*urRecordDiscloseParams
	disclosed []*urRecordDiscloseParams
	opened    []*urRecordOpenParams
	pids      []int
}

func (self *testUrRecordDiscloseTarget) recordDisclosePlan(ctx context.Context, params *urRecordDiscloseParams, pid int) (*urRecordDisclosedReply, error) {
	self.plans = append(self.plans, params)
	self.pids = append(self.pids, pid)
	return self.plan, nil
}

func (self *testUrRecordDiscloseTarget) recordDisclose(ctx context.Context, params *urRecordDiscloseParams, pid int, confirmed bool) (*urRecordDisclosedReply, error) {
	if !confirmed {
		return nil, sidecar.ErrRecordDisclosureUnconfirmed
	}
	self.disclosed = append(self.disclosed, params)
	self.pids = append(self.pids, pid)
	reply := *self.plan
	reply.Packet, reply.PacketSha256 = self.packet, "00ff"
	return &reply, nil
}

func (self *testUrRecordDiscloseTarget) recordOpen(ctx context.Context, params *urRecordOpenParams, pid int, confirmed bool) (*urRecordDisclosedReply, error) {
	if !confirmed {
		return nil, sidecar.ErrRecordDisclosureUnconfirmed
	}
	self.opened = append(self.opened, params)
	return &urRecordDisclosedReply{Packet: self.packet, PacketSha256: "00ff"}, nil
}

func TestRecordDiscloseShowsThePlanAndWritesOnAYes(t *testing.T) {
	approvalId := sidecar.NewId()
	entryId := sidecar.NewId()
	target := &testUrRecordDiscloseTarget{
		packet: []byte("packet bytes"),
		plan: &urRecordDisclosedReply{LogId: sidecar.NewId(), Profile: "approval", Items: []*urRecordDiscloseItem{
			{EntryId: entryId, Kind: "approval", TimeMillis: 1762387200000, Opened: true, Fields: []string{"canonical_action", "summary"}},
			{EntryId: sidecar.NewId(), Kind: "coverage", TimeMillis: 1762387200000},
		}},
	}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	out := filepath.Join(t.TempDir(), "packet.bin")
	args := []string{"ur", "record", "disclose", "--log=team", "--approval=" + approvalId.String(), "--recipient=client.example", "--out=" + out}

	if code := cli.main(context.Background(), append(args, "--dry-run")); code != urExitOk || len(target.disclosed) != 0 {
		t.Fatalf("a dry run: exit %d: %s", code, stderr.String())
	}
	for _, want := range []string{"profile approval: 2 entries", "opens: canonical_action, summary", "its header alone"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("the dry run lacks %q: %s", want, stdout.String())
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a dry run wrote the file")
	}
	if len(target.pids) != 1 || target.pids[0] != os.Getpid() {
		t.Errorf("the daemon was handed pid %v, and this process is %d", target.pids, os.Getpid())
	}

	if code := cli.main(context.Background(), args); code != urExitFailed || len(target.disclosed) != 0 {
		t.Fatalf("with no terminal: exit %d", code)
	}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), args); code != urExitOk || len(target.disclosed) != 0 {
		t.Fatalf("a no disclosed: exit %d", code)
	}
	if !strings.Contains(tty.written.String(), "opens: canonical_action, summary") {
		t.Errorf("the terminal was not shown what the packet opens: %q", tty.written.String())
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), args); code != urExitOk || len(target.disclosed) != 1 {
		t.Fatalf("a yes: exit %d: %s", code, stderr.String())
	}
	params := target.disclosed[0]
	if params.Log != "team" || params.Approval == nil || *params.Approval != approvalId || params.Recipient != "client.example" || len(params.Expect) != 2 || params.Expect[0] != entryId {
		t.Errorf("the params: %+v", params)
	}
	written, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(written, target.packet) {
		t.Fatalf("the file: %q, %v", written, err)
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the file's mode: %v", info.Mode())
	}
	// a file is never replaced, and nothing is disclosed for one that cannot be written
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), args); code != urExitFailed || len(target.disclosed) != 1 {
		t.Fatalf("over a file that exists: exit %d, %d disclosures", code, len(target.disclosed))
	}
}

func TestRecordOpenAsksAndWrites(t *testing.T) {
	target := &testUrRecordDiscloseTarget{packet: []byte("openings")}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	entryId := sidecar.NewId()
	out := filepath.Join(t.TempDir(), "openings.bin")
	args := []string{"ur", "record", "open", "--entry=" + entryId.String(), "--purpose=for the packet", "--out=" + out}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), args); code != urExitOk || len(target.opened) != 0 {
		t.Fatalf("a no opened: exit %d", code)
	}
	tty = &testTty{lines: []string{"y"}}
	if code := cli.main(context.Background(), args); code != urExitOk || len(target.opened) != 1 || target.opened[0].Entries[0] != entryId {
		t.Fatalf("a yes: exit %d: %s", code, stderr.String())
	}
	if written, err := os.ReadFile(out); err != nil || string(written) != "openings" {
		t.Fatalf("the file: %q, %v", written, err)
	}
}

// plan runs unconfirmed, since it builds nothing; the packet and the opening are Confirm methods.
func TestRecordDiscloseMethodsConfirm(t *testing.T) {
	confirm := map[string]bool{}
	for _, method := range urRecordDiscloseMethods(&testUrRecordDiscloseTarget{}) {
		confirm[method.Name] = method.Confirm
	}
	if len(confirm) != 3 || confirm[urMethodRecordDisclosePlan] || !confirm[urMethodRecordDisclose] || !confirm[urMethodRecordOpen] {
		t.Errorf("the methods' confirm flags: %v", confirm)
	}
	if methods := urRecordDiscloseMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no record serves the disclosure methods")
	}
}

// ur record verify needs no daemon: exit 0 for the committed vector under its log key, 1 under another key or with a
// byte changed, and 2 for a file that cannot be read.
func TestRecordVerifyExitCodes(t *testing.T) {
	content, err := os.ReadFile("../testdata/record/packets/approval.json")
	if err != nil {
		t.Fatal(err)
	}
	vector := struct {
		LogKey string `json:"log_key"`
		Packet string `json:"packet"`
	}{}
	if err := json.Unmarshal(content, &vector); err != nil {
		t.Fatal(err)
	}
	packet, err := base64.StdEncoding.DecodeString(vector.Packet)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	good := filepath.Join(directory, "good.bin")
	garbage := filepath.Join(directory, "garbage.bin")
	if err := os.WriteFile(good, packet, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(garbage, []byte("not a packet"), 0o600); err != nil {
		t.Fatal(err)
	}
	// no daemon answers at this socket, and none may be spawned
	cli, stdout, stderr := newTestUrCli(filepath.Join(directory, "no-daemon.sock"))
	if code := cli.main(context.Background(), []string{"ur", "record", "verify", good, "--log-key=" + vector.LogKey}); code != urExitOk {
		t.Fatalf("a good packet: exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "every check passed") || !strings.Contains(stdout.String(), "the team's statement") {
		t.Errorf("the report: %s", stdout.String())
	}
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "record", "verify", good, "--log-key=" + vector.LogKey, "--format=json"}); code != urExitOk || !strings.Contains(stdout.String(), `"Ok": true`) {
		t.Errorf("the json report: exit %d: %s", code, stdout.String())
	}
	other, err := sidecar.NewRecordLogVerifierKey("ur.io/recurd/log/another", sidecar.RecordLogKeyTypeEd25519, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if code := cli.main(context.Background(), []string{"ur", "record", "verify", good, "--log-key=" + other.String()}); code != urExitFailed {
		t.Errorf("under another log key: exit %d", code)
	}
	if code := cli.main(context.Background(), []string{"ur", "record", "verify", good, "--log-key=" + vector.LogKey, "--ssh-key=allowed_signers"}); code != urExitFailed {
		t.Errorf("an ssh check that is not built: exit %d", code)
	}
	if code := cli.main(context.Background(), []string{"ur", "record", "verify", garbage, "--log-key=" + vector.LogKey}); code != urExitUnreadable {
		t.Errorf("a file that is no packet: exit %d", code)
	}
	if code := cli.main(context.Background(), []string{"ur", "record", "verify", filepath.Join(directory, "absent.bin"), "--log-key=" + vector.LogKey}); code != urExitUnreadable {
		t.Errorf("a file that is not there: exit %d", code)
	}
}
