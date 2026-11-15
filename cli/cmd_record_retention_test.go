// ur record retention: show prints each class's policy and asks nothing; set says on the terminal what the policy
// does, a shortening named as one, and signs only on a yes there, never with no terminal; a class no policy takes and
// a count that is no number are refused before any call; and only the set method is a Confirm one.

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target that runs a record's retention, as a test sets it.
type testUrRecordRetentionTarget struct {
	testUrDaemonTarget
	logId     sidecar.Id
	shortens  bool
	shows     []*urRecordRetentionParams
	plans     []*urRecordRetentionParams
	sets      []*urRecordRetentionParams
	confirmed []bool
}

func (self *testUrRecordRetentionTarget) recordRetentionShow(ctx context.Context, params *urRecordRetentionParams) (*urRecordRetentionReply, error) {
	self.shows = append(self.shows, params)
	entryId := sidecar.NewId()
	return &urRecordRetentionReply{LogId: self.logId, Policies: []*urRecordRetentionPolicy{
		{Class: "capture", KeepDays: 400, SearchableDays: 90, Default: true},
		{Class: "action", KeepDays: 0, SearchableDays: 0, Archive: true, EntryId: &entryId},
	}}, nil
}

func (self *testUrRecordRetentionTarget) recordRetentionPlan(ctx context.Context, params *urRecordRetentionParams, pid int) (*urRecordRetentionReply, error) {
	self.plans = append(self.plans, params)
	return &urRecordRetentionReply{LogId: self.logId, Shortens: self.shortens, Policies: []*urRecordRetentionPolicy{
		{Class: params.Class, KeepDays: 400, SearchableDays: 90, Default: true},
	}}, nil
}

func (self *testUrRecordRetentionTarget) recordRetentionSet(ctx context.Context, params *urRecordRetentionParams, pid int, confirmed bool) (*urRecordRetentionReply, error) {
	if !confirmed {
		return nil, sidecar.ErrRecordRetentionUnconfirmed
	}
	self.sets = append(self.sets, params)
	self.confirmed = append(self.confirmed, confirmed)
	entryId := sidecar.NewId()
	return &urRecordRetentionReply{LogId: self.logId, EntryId: &entryId}, nil
}

func TestRecordRetentionShowPrintsEachClass(t *testing.T) {
	target := &testUrRecordRetentionTarget{logId: sidecar.NewId()}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "record", "retention", "show", "--log=team"}); code != urExitOk {
		t.Fatalf("show: exit %d: %s", code, stderr.String())
	}
	if len(target.shows) != 1 || target.shows[0].Log != "team" || len(target.plans) != 0 || len(target.sets) != 0 {
		t.Fatalf("show's calls: %d shows, %d plans, %d sets", len(target.shows), len(target.plans), len(target.sets))
	}
	for _, text := range []string{target.logId.String(), "capture", "keep 400 days, then expires; searchable 90 days", "the log's default",
		"keep no limit, then archived; searchable no limit", "class 7"} {
		if !strings.Contains(stdout.String(), text) {
			t.Errorf("show does not print %q: %s", text, stdout.String())
		}
	}
}

func TestRecordRetentionSetAsksOnTheTerminal(t *testing.T) {
	target := &testUrRecordRetentionTarget{logId: sidecar.NewId(), shortens: true}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	args := []string{"ur", "record", "retention", "set", "--log=team", "--class=action", "--keep=365", "--searchable=90"}
	if code := cli.main(context.Background(), args); code != urExitFailed || len(target.sets) != 0 {
		t.Fatalf("with no terminal: exit %d, %d sets", code, len(target.sets))
	}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), args); code != urExitOk || len(target.sets) != 0 {
		t.Fatalf("after a no: exit %d, %d sets", code, len(target.sets))
	}
	if !strings.Contains(tty.written.String(), "shortens the class's life") || !strings.Contains(tty.written.String(), "keep 365 days") {
		t.Errorf("the terminal was not told what the policy does: %q", tty.written.String())
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), append(args, "--archive")); code != urExitOk || len(target.sets) != 1 || !target.confirmed[0] {
		t.Fatalf("after a yes: exit %d: %s", code, stderr.String())
	}
	set := target.sets[0]
	if set.Log != "team" || set.Class != "action" || set.KeepDays != 365 || set.SearchableDays != 90 || !set.Archive {
		t.Errorf("the set's params: %+v", set)
	}
	if !strings.Contains(tty.written.String(), "are archived") {
		t.Errorf("the terminal was not told the policy archives: %q", tty.written.String())
	}
	plans := len(target.plans)
	for _, bad := range [][]string{
		{"ur", "record", "retention", "set", "--log=team", "--class=log", "--keep=400"},
		{"ur", "record", "retention", "set", "--log=team", "--class=action", "--keep=a-year"},
	} {
		if code := cli.main(context.Background(), bad); code == urExitOk || len(target.plans) != plans {
			t.Errorf("%v: exit %d, %d calls", bad, code, len(target.plans)-plans)
		}
	}
}

// The set is a Confirm method; show and the plan are not, and a target with no record serves none.
func TestRecordRetentionMethodsConfirm(t *testing.T) {
	confirm := map[string]bool{}
	for _, method := range urRecordRetentionMethods(&testUrRecordRetentionTarget{}) {
		confirm[method.Name] = method.Confirm
	}
	if len(confirm) != 3 || confirm[urMethodRecordRetentionShow] || confirm[urMethodRecordRetentionPlan] || !confirm[urMethodRecordRetentionSet] {
		t.Errorf("the methods' confirm flags: %v", confirm)
	}
	if methods := urRecordRetentionMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no record serves the retention methods")
	}
}
