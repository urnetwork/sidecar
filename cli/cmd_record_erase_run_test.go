// ur record erase --run (CTXH-M11-06; DESIGN-COMPUTE §24.10's prune row): the plan asks for the run and its scope and
// lists, beside its entries, the nodes left without their item, the calls whose context it cuts and the runs that
// continue it; the erasure, after a yes on the terminal, takes the entries the plan listed and names no run.

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target whose plans of a run list two blobs and what they cut.
type testUrRecordEraseRunTarget struct {
	testUrRecordEraseTarget
	blobs  []sidecar.Id
	sameAs sidecar.Id
	call   sidecar.Id
	run    sidecar.Id
}

func (self *testUrRecordEraseRunTarget) recordErasePlan(ctx context.Context, params *urRecordEraseParams, pid int) (*urRecordEraseReply, error) {
	self.plans = append(self.plans, params)
	reply := &urRecordEraseReply{LogId: sidecar.NewId(), SameAs: []sidecar.Id{self.sameAs}, Calls: []sidecar.Id{self.call}, Runs: []sidecar.Id{self.run}}
	for _, blobId := range self.blobs {
		reply.Items = append(reply.Items, &urRecordEraseItem{EntryId: blobId, Kind: "session_blob", CopyCount: 1})
	}
	return reply, nil
}

func TestRecordEraseRunListsWhatItCuts(t *testing.T) {
	target := &testUrRecordEraseRunTarget{blobs: []sidecar.Id{sidecar.NewId(), sidecar.NewId()}, sameAs: sidecar.NewId(), call: sidecar.NewId(), run: sidecar.NewId()}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	tty := &testTty{lines: []string{"y"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	runId := sidecar.NewId()
	if code := cli.main(context.Background(), []string{"ur", "record", "erase", "--run=" + runId.String(), "--blobs-only"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if len(target.plans) != 1 || target.plans[0].Run == nil || *target.plans[0].Run != runId || target.plans[0].Scope != string(sidecar.RecordEraseRunBlobs) {
		t.Fatalf("the plan's params: %+v", target.plans)
	}
	shown := tty.written.String()
	for _, want := range []string{target.sameAs.String() + "  a node of the run that stays", target.call.String() + "  a model call whose context this cuts",
		"run " + target.run.String() + " continues or forks"} {
		if !strings.Contains(shown, want) {
			t.Errorf("the terminal was not shown %q:\n%s", want, shown)
		}
	}
	if len(target.erasures) != 1 || target.erasures[0].Run != nil || len(target.erasures[0].Entries) != 2 || target.erasures[0].Entries[0] != target.blobs[0] {
		t.Fatalf("the erasure's params: %+v", target.erasures)
	}
}
