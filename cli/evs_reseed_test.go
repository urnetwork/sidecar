// ur evs reseed (EVSB-M2-20): refused with no terminal, nothing sent on a no; on a yes the daemon is handed the repo,
// the incident and whether to sign, through a Confirm method alone, and what it answers is printed by ref and slot; a
// partial re-seed exits failed, naming what stopped; --sign needs its incident.

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target whose re-seeds a test sets and reads.
type testUrEvsReseedTarget struct {
	testUrDaemonTarget
	repoIds []sidecar.Id
	args    []*sidecar.EvsReseedArgs
	result  *sidecar.EvsReseedResult
	err     error
}

func (self *testUrEvsReseedTarget) reseedRepo(ctx context.Context, repoId sidecar.Id, args *sidecar.EvsReseedArgs) (*sidecar.EvsReseedResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.repoIds = append(self.repoIds, repoId)
	self.args = append(self.args, args)
	return self.result, self.err
}

func TestEvsReseedSendsOnlyOnAYesAndPrintsWhatReturned(t *testing.T) {
	repoId, refId := sidecar.NewId(), sidecar.NewId()
	target := &testUrEvsReseedTarget{result: &sidecar.EvsReseedResult{
		Refs:         []*sidecar.EvsReseedRef{{RefId: refId, MirrorVersion: 7, Version: 7, Filed: true}},
		SegmentCount: 3, SlotCount: 2,
	}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	command := []string{"ur", "evs", "reseed", repoId.String(), "--incident=incident-41", "--sign"}
	if code := cli.main(context.Background(), command); code != urExitFailed || len(target.args) != 0 {
		t.Fatalf("no terminal: exit %d, %d re-seeds", code, len(target.args))
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(context.Background(), command); code != urExitOk || len(target.args) != 0 {
		t.Fatalf("a no: exit %d, %d re-seeds", code, len(target.args))
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), command); code != urExitOk {
		t.Fatalf("a yes: exit %d: %s", code, stderr.String())
	}
	if len(target.args) != 1 || target.repoIds[0] != repoId || !target.args[0].SignReseed || string(target.args[0].IncidentId) != "incident-41" {
		t.Fatalf("the re-seed asked: %v %+v", target.repoIds, target.args)
	}
	shown := stdout.String()
	for _, want := range []string{repoId.String(), "1 refs, 3 segments sent, 2 slots taken", "ref " + refId.String() + ": version 7 of 7, EvsReseed filed"} {
		if !strings.Contains(shown, want) {
			t.Errorf("the re-seed does not show %q:\n%s", want, shown)
		}
	}
	// without --sign nothing is signed, and --sign without its incident is refused before the daemon is asked
	if code := cli.main(context.Background(), []string{"ur", "evs", "reseed", repoId.String()}); code != urExitOk || len(target.args) != 2 || target.args[1].SignReseed {
		t.Fatalf("without --sign: exit %d, %+v", code, target.args)
	}
	if code := cli.main(context.Background(), []string{"ur", "evs", "reseed", repoId.String(), "--sign"}); code != urExitFailed || len(target.args) != 2 {
		t.Fatalf("--sign with no incident: exit %d, %d re-seeds", code, len(target.args))
	}
	methods := urEvsReseedMethods(target)
	if len(methods) != 1 || methods[0].Name != urMethodEvsReseed || !methods[0].Confirm {
		t.Error("evs.reseed runs unconfirmed")
	}
	if urEvsReseedMethods(&testUrDaemonTarget{}) != nil {
		t.Error("evs.reseed is served over a target with no evs client")
	}
}

func TestEvsReseedExitsFailedOnAPartialReseed(t *testing.T) {
	repoId, refId, slotId, unnamedId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	target := &testUrEvsReseedTarget{result: &sidecar.EvsReseedResult{
		Refs:  []*sidecar.EvsReseedRef{{RefId: refId, MirrorVersion: 9, Version: 4, Stopped: sidecar.ErrEvsReseedParts}},
		Slots: []*sidecar.EvsReseedSlot{{SlotId: slotId, Refused: errors.New("evs refused: 409")}, {SlotId: unnamedId}},
	}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "evs", "reseed", repoId.String()}); code != urExitFailed {
		t.Fatalf("a partial re-seed: exit %d", code)
	}
	shown := stdout.String()
	for _, want := range []string{
		"ref " + refId.String() + ": version 4 of 9, stopped: " + sidecar.ErrEvsReseedParts.Error(),
		"slot " + slotId.String() + ": not taken: evs refused: 409",
		"slot " + unnamedId.String() + ": not sent, no returned version names it",
		"the re-seed is partial",
	} {
		if !strings.Contains(shown, want) {
			t.Errorf("a partial re-seed does not show %q:\n%s", want, shown)
		}
	}
	// a walk that ended early still shows what went
	target.err = errors.New("the mirror would not open")
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "evs", "reseed", repoId.String()}); code != urExitFailed || !strings.Contains(stdout.String(), "ended early: the mirror would not open") {
		t.Fatalf("an early end: exit %d:\n%s", code, stdout.String())
	}
}
