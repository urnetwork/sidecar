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

// A daemon target whose re-seeds and groups steps a test sets and reads.
type testUrEvsReseedTarget struct {
	testUrDaemonTarget
	repoIds []sidecar.Id
	args    []*sidecar.EvsReseedArgs
	result  *sidecar.EvsReseedResult
	err     error
	// the groups steps asked, each after how many re-seeds, and what they answer
	placedRepoIds    []sidecar.Id
	placedAfterCount []int
	placed           *sidecar.EvsReseedPlaced
	placeErr         error
}

func (self *testUrEvsReseedTarget) reseedPlaceRepo(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsReseedPlaced, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.placedRepoIds = append(self.placedRepoIds, repoId)
	self.placedAfterCount = append(self.placedAfterCount, len(self.args))
	return self.placed, self.placeErr
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
		Refs:  []*sidecar.EvsReseedRef{{RefId: refId, MirrorVersion: 9, Version: 4, Stopped: sidecar.ErrEvsReseedVersion}},
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
		"ref " + refId.String() + ": version 4 of 9, stopped: " + sidecar.ErrEvsReseedVersion.Error(),
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

// --place runs the repo's groups step before its walk, after the same yes, and shows what it did: a live repo placed
// and active; one re-seeded as deleted left deleted, whose group this device finishes at its next sync once it is
// restored (QD-1143), with the DELETE that mended a place leaving repo/ keying; a restored repo placed and restored,
// with the restore that mended a place leaving repo/ deleted; one another admin's device placed; a groups step that
// fails walks nothing and exits failed; and without --place no groups step runs.
func TestEvsReseedPlaceRunsTheGroupsStepBeforeTheWalk(t *testing.T) {
	repoId, refId := sidecar.NewId(), sidecar.NewId()
	target := &testUrEvsReseedTarget{
		result: &sidecar.EvsReseedResult{Refs: []*sidecar.EvsReseedRef{{RefId: refId, MirrorVersion: 3, Version: 3}}, SegmentCount: 1},
		placed: &sidecar.EvsReseedPlaced{Deleted: true, GroupId: sidecar.NewId()},
	}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	command := []string{"ur", "evs", "reseed", repoId.String(), "--place"}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), command); code != urExitOk || len(target.placedRepoIds) != 0 || len(target.args) != 0 {
		t.Fatalf("a no: exit %d, %d groups steps, %d re-seeds", code, len(target.placedRepoIds), len(target.args))
	}
	yes := func() {
		cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	}
	yes()
	if code := cli.main(context.Background(), command); code != urExitOk {
		t.Fatalf("a repo re-seeded as deleted: exit %d: %s", code, stderr.String())
	}
	if len(target.placedRepoIds) != 1 || target.placedRepoIds[0] != repoId || target.placedAfterCount[0] != 0 || len(target.args) != 1 {
		t.Fatalf("groups steps %v after %v re-seeds, %d re-seeds", target.placedRepoIds, target.placedAfterCount, len(target.args))
	}
	placedLine := "repo " + repoId.String() + ": placed as deleted, its group's form and ladder returned; it stays deleted until its restore, " +
		"after which this device finishes its group at its next sync\n"
	walkedLine := "ref " + refId.String() + ": version 3 of 3"
	shown := stdout.String()
	if !strings.Contains(shown, placedLine) || !strings.Contains(shown, walkedLine) || strings.Index(shown, walkedLine) < strings.Index(shown, placedLine) {
		t.Errorf("a repo re-seeded as deleted shows:\n%s", shown)
	}
	for _, c := range []struct {
		placed *sidecar.EvsReseedPlaced
		want   string
	}{
		{placed: &sidecar.EvsReseedPlaced{GroupId: sidecar.NewId()}, want: ": placed afresh, its group re-formed, active\n"},
		{
			placed: &sidecar.EvsReseedPlaced{Deleted: true, Mended: true, GroupId: sidecar.NewId()},
			want: ": placed as deleted, a DELETE mending a place that left repo/ keying, its group's form and ladder returned; " +
				"it stays deleted until its restore, after which this device finishes its group at its next sync\n",
		},
		{placed: &sidecar.EvsReseedPlaced{Restored: true, GroupId: sidecar.NewId()}, want: ": placed afresh as restored, its group re-formed, active\n"},
		{
			placed: &sidecar.EvsReseedPlaced{Restored: true, Mended: true, GroupId: sidecar.NewId()},
			want:   ": placed and restored, its restore mending a place that left repo/ deleted, its group re-formed, active\n",
		},
		{placed: &sidecar.EvsReseedPlaced{PlacedByAnother: true}, want: ": placed by another admin's device, which re-forms its group\n"},
	} {
		target.placed = c.placed
		stdout.Reset()
		yes()
		if code := cli.main(context.Background(), command); code != urExitOk || !strings.Contains(stdout.String(), "repo "+repoId.String()+c.want) {
			t.Errorf("exit %d, want %q in:\n%s", code, c.want, stdout.String())
		}
	}
	// a groups step that fails walks nothing
	walked := len(target.args)
	target.placed, target.placeErr = nil, errors.New("evs refused: 409 SHREDDING")
	stderr.Reset()
	yes()
	if code := cli.main(context.Background(), command); code != urExitFailed || len(target.args) != walked || !strings.Contains(stderr.String(), "the repo's place: evs refused: 409 SHREDDING") {
		t.Fatalf("a refused place: exit %d, %d re-seeds, %s", code, len(target.args)-walked, stderr.String())
	}
	// and without --place no groups step runs
	steps := len(target.placedRepoIds)
	yes()
	if code := cli.main(context.Background(), []string{"ur", "evs", "reseed", repoId.String()}); code != urExitOk || len(target.placedRepoIds) != steps {
		t.Fatalf("without --place: exit %d, %d groups steps", code, len(target.placedRepoIds)-steps)
	}
}
