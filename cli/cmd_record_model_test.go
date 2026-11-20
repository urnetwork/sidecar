// ur record model and ur record cost: a declaration goes to the terminal and is sent confirmed only on a yes there,
// a run with no terminal declares nothing, show asks nothing, only the set method is a Confirm one, a manifest's
// fields print with how each is known, and a cost report prints the daemon's rows in the order given.

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target that holds manifests and sums costs, as a test sets it.
type testUrRecordModelTarget struct {
	testUrDaemonTarget
	declared  []*urRecordModelParams
	confirmed []bool
	shown     []uint32
	costs     []*urRecordCostParams
}

// A manifest as the daemon would answer it for params.
func testUrRecordModelItem(params *urRecordModelParams) *urRecordModelItem {
	entryId, logId := sidecar.NewId(), sidecar.NewId()
	return &urRecordModelItem{
		Port: params.Port,
		Fields: []*urRecordModelField{
			{Name: "engine", Value: params.Engine, Evidence: "declared"},
			{Name: "served_name", Value: "local-coder", Evidence: "reported"},
			{Name: "weights_digest", Value: strings.Repeat("ab", 32), Evidence: "measured"},
		},
		WeightsBytes: 42,
		EntryId:      &entryId,
		LogId:        &logId,
		Written:      true,
	}
}

func (self *testUrRecordModelTarget) recordModelSet(ctx context.Context, params *urRecordModelParams, pid int, confirmed bool) (*urRecordModelReply, error) {
	if !confirmed {
		return nil, sidecar.ErrRecordModelInvalid
	}
	self.declared = append(self.declared, params)
	self.confirmed = append(self.confirmed, confirmed)
	return &urRecordModelReply{Items: []*urRecordModelItem{testUrRecordModelItem(params)}}, nil
}

func (self *testUrRecordModelTarget) recordModelShow(ctx context.Context, port uint32) (*urRecordModelReply, error) {
	self.shown = append(self.shown, port)
	return &urRecordModelReply{Items: []*urRecordModelItem{}}, nil
}

func (self *testUrRecordModelTarget) recordCost(ctx context.Context, params *urRecordCostParams) (*urRecordCostReply, error) {
	self.costs = append(self.costs, params)
	return &urRecordCostReply{LogId: sidecar.NewId(), Rows: []*sidecar.RecordCostRow{
		{Group: "alpha", Runs: 2, Calls: 3, InputTokens: 1007, OutputTokens: 11, ReportedMicroUsd: 1500000, Complete: true},
		{Group: "other", Runs: 1, Calls: 1, InputTokens: 5, Complete: false},
	}}, nil
}

func TestRecordModelSetAsksOnTheTerminal(t *testing.T) {
	target := &testUrRecordModelTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	args := []string{"ur", "record", "model", "set", "--port=8080", "--engine=llama.cpp", "--quantization=Q4_K_M", "--weights=weights/a.gguf"}
	if code := cli.main(context.Background(), args); code != urExitFailed || len(target.declared) != 0 {
		t.Fatalf("with no terminal: exit %d, %d declarations", code, len(target.declared))
	}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), args); code != urExitOk || len(target.declared) != 0 {
		t.Fatalf("after a no: exit %d, %d declarations", code, len(target.declared))
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), args); code != urExitOk || len(target.declared) != 1 || !target.confirmed[0] {
		t.Fatalf("after a yes: exit %d: %s", code, stderr.String())
	}
	declared := target.declared[0]
	if declared.Port != 8080 || declared.Engine != "llama.cpp" || declared.Quantization != "Q4_K_M" || declared.EngineVersion != "" ||
		len(declared.Weights) != 1 || !filepath.IsAbs(declared.Weights[0]) || filepath.Base(declared.Weights[0]) != "a.gguf" {
		t.Errorf("the declaration's params: %+v", declared)
	}
	if !strings.Contains(tty.written.String(), "port 8080") || !strings.Contains(tty.written.String(), "llama.cpp") {
		t.Errorf("the terminal was not shown the declaration: %q", tty.written.String())
	}
	// each field with how it is known, the join named as an inference, and nothing as attested
	printed := stdout.String()
	for _, want := range []string{"(declared)", "(reported)", "(measured)", "local-coder", sidecar.RecordModelJoinLabel} {
		if !strings.Contains(printed, want) {
			t.Errorf("the manifest printed without %q: %s", want, printed)
		}
	}
	if strings.Contains(printed, "attested") {
		t.Errorf("a manifest printed as attested: %s", printed)
	}
	cli.openTty = func() (urTty, error) { return nil, os.ErrNotExist }
	if code := cli.main(context.Background(), []string{"ur", "record", "model", "set", "--port=0"}); code == urExitOk || len(target.declared) != 1 {
		t.Errorf("port 0: exit %d", code)
	}
	if code := cli.main(context.Background(), []string{"ur", "record", "model", "show", "--port=8080"}); code != urExitOk || len(target.shown) != 1 || target.shown[0] != 8080 {
		t.Errorf("show: exit %d, shown %v: %s", code, target.shown, stderr.String())
	}
	if code := cli.main(context.Background(), []string{"ur", "record", "model", "show"}); code != urExitOk || len(target.shown) != 2 || target.shown[1] != 0 {
		t.Errorf("show with no port: exit %d, shown %v", code, target.shown)
	}
}

// A value claiming attested evidence prints as unverified, never as attested.
func TestRecordModelNeverPrintsAttested(t *testing.T) {
	if shown := urRecordModelEvidence(sidecar.RecordModelEvidenceAttested); shown != "unverified" {
		t.Errorf("attested evidence shows as %q", shown)
	}
	if shown := urRecordModelEvidence(99); shown != "unverified" {
		t.Errorf("unknown evidence shows as %q", shown)
	}
}

// The declaration is a Confirm method; show and cost are not, and a target with no record serves none of them.
func TestRecordModelAndCostMethodsConfirm(t *testing.T) {
	confirm := map[string]bool{}
	for _, method := range urRecordModelMethods(&testUrRecordModelTarget{}) {
		confirm[method.Name] = method.Confirm
	}
	for _, method := range urRecordCostMethods(&testUrRecordModelTarget{}) {
		confirm[method.Name] = method.Confirm
	}
	if len(confirm) != 3 || !confirm[urMethodRecordModelSet] || confirm[urMethodRecordModelShow] || confirm[urMethodRecordCost] {
		t.Errorf("the methods' confirm flags: %v", confirm)
	}
	if len(urRecordModelMethods(&testUrDaemonTarget{})) != 0 || len(urRecordCostMethods(&testUrDaemonTarget{})) != 0 {
		t.Error("a target with no record serves the model or cost methods")
	}
}

func TestRecordCostPrintsTheRowsInTheirOrder(t *testing.T) {
	target := &testUrRecordModelTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	mapPath := filepath.Join(t.TempDir(), "clients.csv")
	if err := os.WriteFile(mapPath, []byte("# project,client\nalpha,acme\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"ur", "record", "cost", "--by=project", "--map=" + mapPath, "--format=csv"}
	if code := cli.main(context.Background(), args); code != urExitOk || len(target.costs) != 1 {
		t.Fatalf("cost: exit %d: %s", code, stderr.String())
	}
	asked := target.costs[0]
	if asked.Log != "" || asked.By != "project" || len(asked.Clients) != 1 || asked.Clients["alpha"] != "acme" {
		t.Errorf("the report's params: %+v", asked)
	}
	printed := stdout.String()
	alpha, other := strings.Index(printed, "alpha"), strings.Index(printed, "other")
	if alpha < 0 || other < alpha {
		t.Errorf("the rows printed out of the order given: %s", printed)
	}
	// no grouping by member, and no format but the three
	if code := cli.main(context.Background(), []string{"ur", "record", "cost", "--by=member"}); code == urExitOk || len(target.costs) != 1 {
		t.Errorf("--by=member: exit %d", code)
	}
	if code := cli.main(context.Background(), []string{"ur", "record", "cost", "--format=xml"}); code == urExitOk || len(target.costs) != 1 {
		t.Errorf("--format=xml: exit %d", code)
	}
}

// --by client needs --map: with none, or one naming no project, it is refused before the daemon is asked; with one
// the daemon is asked by client with the map's clients (§7.9's grouping beside RECORD.md section 13.1's --by project
// --map).
func TestRecordCostByClientNeedsTheMap(t *testing.T) {
	target := &testUrRecordModelTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	directory := t.TempDir()
	emptyPath, mapPath := filepath.Join(directory, "empty.csv"), filepath.Join(directory, "clients.csv")
	if err := os.WriteFile(emptyPath, []byte("# project,client\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mapPath, []byte("alpha,acme\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"ur", "record", "cost", "--by=client"},
		{"ur", "record", "cost", "--by=client", "--map=" + emptyPath},
	} {
		if code := cli.main(context.Background(), args); code == urExitOk || len(target.costs) != 0 {
			t.Fatalf("%v: exit %d, %d reports asked", args, code, len(target.costs))
		}
	}
	if !strings.Contains(stderr.String(), "--by client needs --map") {
		t.Errorf("the refusal: %s", stderr.String())
	}
	if code := cli.main(context.Background(), []string{"ur", "record", "cost", "--by=client", "--map=" + mapPath}); code != urExitOk || len(target.costs) != 1 {
		t.Fatalf("--by client with a map: exit %d: %s", code, stderr.String())
	}
	if asked := target.costs[0]; asked.By != "client" || len(asked.Clients) != 1 || asked.Clients["alpha"] != "acme" {
		t.Errorf("the report's params: %+v", asked)
	}
}
