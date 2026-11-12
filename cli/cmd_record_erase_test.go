// ur record erase: the plan goes to the terminal, a yes there sends the confirmed erasure and a no erases nothing,
// --dry-run asks nothing and erases nothing, a run with no terminal erases nothing, and only the erase method is a
// Confirm one.

package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target that runs a record's erasures, as a test sets it.
type testUrRecordEraseTarget struct {
	testUrDaemonTarget
	plans     []*urRecordEraseParams
	erasures  []*urRecordEraseParams
	confirmed []bool
}

func (self *testUrRecordEraseTarget) recordErasePlan(ctx context.Context, params *urRecordEraseParams, pid int) (*urRecordEraseReply, error) {
	self.plans = append(self.plans, params)
	reply := &urRecordEraseReply{LogId: sidecar.NewId()}
	for _, entryId := range params.Entries {
		reply.Items = append(reply.Items, &urRecordEraseItem{EntryId: entryId, Kind: "note", CopyCount: 1})
	}
	return reply, nil
}

func (self *testUrRecordEraseTarget) recordErase(ctx context.Context, params *urRecordEraseParams, pid int, confirmed bool) (*urRecordEraseReply, error) {
	if !confirmed {
		return nil, sidecar.ErrRecordEraseUnconfirmed
	}
	self.erasures = append(self.erasures, params)
	self.confirmed = append(self.confirmed, confirmed)
	erasureId := sidecar.NewId()
	return &urRecordEraseReply{LogId: sidecar.NewId(), ErasureId: &erasureId, Erased: params.Entries, KeyCount: len(params.Entries)}, nil
}

func TestRecordEraseAsksOnTheTerminal(t *testing.T) {
	target := &testUrRecordEraseTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	entryId := sidecar.NewId()
	args := []string{"ur", "record", "erase", "--log=vault", "--entry=" + entryId.String()}
	if code := cli.main(context.Background(), append(args, "--dry-run")); code != urExitOk || len(target.erasures) != 0 || !strings.Contains(stdout.String(), entryId.String()) {
		t.Fatalf("a dry run: exit %d, %d erasures: %s", code, len(target.erasures), stderr.String())
	}
	if code := cli.main(context.Background(), args); code != urExitFailed || len(target.erasures) != 0 {
		t.Fatalf("with no terminal: exit %d", code)
	}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), args); code != urExitOk || len(target.erasures) != 0 {
		t.Fatalf("after a no: exit %d", code)
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), append(args, "--reason=moderation")); code != urExitOk || len(target.erasures) != 1 || !target.confirmed[0] {
		t.Fatalf("after a yes: exit %d: %s", code, stderr.String())
	}
	if target.erasures[0].Reason != "moderation" || len(target.erasures[0].Entries) != 1 || target.erasures[0].Entries[0] != entryId {
		t.Errorf("the erasure's params: %+v", target.erasures[0])
	}
	if !strings.Contains(tty.written.String(), "Copies in other logs are not reached") {
		t.Errorf("the terminal was not told what the erasure does not reach: %q", tty.written.String())
	}
	cli.openTty = func() (urTty, error) { return nil, os.ErrNotExist }
	if code := cli.main(context.Background(), append(args, "--reason=retention")); code != urExitFailed {
		t.Errorf("a reason a person does not give: exit %d", code)
	}
}

// The erasure is a Confirm method; its plan is not, and a target with no record serves neither.
func TestRecordEraseMethodsConfirm(t *testing.T) {
	confirm := map[string]bool{}
	for _, method := range urRecordEraseMethods(&testUrRecordEraseTarget{}) {
		confirm[method.Name] = method.Confirm
	}
	if len(confirm) != 2 || confirm[urMethodRecordErasePlan] || !confirm[urMethodRecordErase] {
		t.Errorf("the methods' confirm flags: %v", confirm)
	}
	if methods := urRecordEraseMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no record serves the erase methods")
	}
}
