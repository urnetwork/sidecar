// ur evs rekey (KEYS-M2-26): the command hands the daemon the repo, refs and paths named and prints the job's scope
// and counts as the daemon answers them; --status shows a job, a stopped one with its reason and how to go on, and
// says so when there is none; a skipped ref is named; and the methods are served only over a target with rekey jobs.

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target whose rekey jobs a test sets and reads.
type testUrRekeyTarget struct {
	testUrDaemonTarget
	requests []*sidecar.GkmRekeyRequest
	progress *sidecar.GkmRekeyProgress
	err      error
}

func (self *testUrRekeyTarget) startRekey(request *sidecar.GkmRekeyRequest) (*sidecar.GkmRekeyProgress, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requests = append(self.requests, request)
	return self.progress, self.err
}

func (self *testUrRekeyTarget) rekeyProgress(repoId sidecar.Id) (*sidecar.GkmRekeyProgress, bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.progress, self.progress != nil, self.err
}

// The start carries the refs and paths as named, and what the daemon answers is printed with its scope.
func TestEvsRekeyStartsTheJobOverTheRefsAndPathsNamed(t *testing.T) {
	repoId := sidecar.NewId()
	target := &testUrRekeyTarget{progress: &sidecar.GkmRekeyProgress{
		RepoId: repoId, State: sidecar.GkmRekeyStateRunning, Generation: 5,
		RefNames: [][]byte{[]byte("main"), []byte("notes")}, Paths: []string{"docs", "src/a.txt"},
	}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "evs", "rekey", repoId.String(), "--ref", "main", "--ref=notes", "docs", "src/a.txt"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if len(target.requests) != 1 {
		t.Fatalf("%d starts", len(target.requests))
	}
	request := target.requests[0]
	if request.RepoId != repoId || len(request.RefNames) != 2 || string(request.RefNames[0]) != "main" || string(request.RefNames[1]) != "notes" ||
		len(request.Paths) != 2 || request.Paths[0] != "docs" || request.Paths[1] != "src/a.txt" {
		t.Errorf("the request: %+v", request)
	}
	shown := stdout.String()
	for _, want := range []string{repoId.String(), "generation 5, running", "refs main, notes", "paths docs, src/a.txt", "--status"} {
		if !strings.Contains(shown, want) {
			t.Errorf("the start does not show %q:\n%s", want, shown)
		}
	}

	// the repo alone: no ref and no path, which the daemon reads as its unfinished job or the whole ref
	if code := cli.main(context.Background(), []string{"ur", "evs", "rekey", repoId.String()}); code != urExitOk || len(target.requests) != 2 ||
		target.requests[1].RefNames != nil || target.requests[1].Paths != nil {
		t.Errorf("the repo alone: exit %d, %+v", code, target.requests[len(target.requests)-1])
	}
	// a repo id that does not parse reaches no daemon
	if code := cli.main(context.Background(), []string{"ur", "evs", "rekey", "not-an-id", "docs"}); code != urExitFailed || len(target.requests) != 2 {
		t.Errorf("a malformed repo id: exit %d", code)
	}
	// a refusal is shown and nothing is printed as started
	target.err = sidecar.ErrGkmRekeyRunning
	stdout.Reset()
	stderr.Reset()
	if code := cli.main(context.Background(), []string{"ur", "evs", "rekey", repoId.String(), "docs"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), sidecar.ErrGkmRekeyRunning.Error()) || stdout.Len() != 0 {
		t.Errorf("a refused start: exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
}

// --status: none, a stopped job with why and how to go on, and a finished one with what it skipped and what its scope
// leaves untouched. It starts nothing.
func TestEvsRekeyStatusShowsWhereTheJobStands(t *testing.T) {
	repoId := sidecar.NewId()
	target := &testUrRekeyTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	status := func() string {
		t.Helper()
		stdout.Reset()
		if code := cli.main(context.Background(), []string{"ur", "evs", "rekey", repoId.String(), "--status"}); code != urExitOk {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		return stdout.String()
	}
	if shown := status(); !strings.Contains(shown, "no rekey job") {
		t.Errorf("a repo with no job: %q", shown)
	}

	target.progress = &sidecar.GkmRekeyProgress{
		RepoId: repoId, State: sidecar.GkmRekeyStateStopped, Generation: 3, RefNames: [][]byte{[]byte("main")}, Paths: []string{"docs"},
		RewrittenCount: 2048, CurrentCount: 7, AbsentCount: 1, PushCount: 2, StopReason: "evs refused: 507 EVS_REFUSAL_CLUSTER_FULL",
	}
	shown := status()
	for _, want := range []string{"generation 3, stopped", "2048 file(s) rewritten in 2 push(es)", "7 already of the generation", "1 gone",
		"stopped: evs refused: 507", "again to go on from the last push that committed"} {
		if !strings.Contains(shown, want) {
			t.Errorf("a stopped job does not show %q:\n%s", want, shown)
		}
	}

	target.progress = &sidecar.GkmRekeyProgress{
		RepoId: repoId, State: sidecar.GkmRekeyStateDone, Generation: 3, RefNames: [][]byte{[]byte("main"), []byte("tree")}, Paths: []string{"docs"},
		RewrittenCount: 9, PushCount: 1, SkippedRefs: []*sidecar.GkmRekeySkippedRef{{RefName: []byte("tree"), Reason: "git_mode"}},
	}
	shown = status()
	for _, want := range []string{"generation 3, done", "skipped ref tree: a git-mode ref", "outside this scope"} {
		if !strings.Contains(shown, want) {
			t.Errorf("a finished job does not show %q:\n%s", want, shown)
		}
	}
	if len(target.requests) != 0 {
		t.Error("--status started a job")
	}
}

// The rekey methods are served only over a target with rekey jobs, refuse a call with no repo or an empty ref name,
// and no host builds an evs client yet, so the daemon's own target refuses.
func TestEvsRekeyMethods(t *testing.T) {
	if methods := urEvsRekeyMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no rekey jobs serves the rekey methods")
	}
	target := &testUrRekeyTarget{progress: &sidecar.GkmRekeyProgress{State: sidecar.GkmRekeyStateRunning}}
	methods := map[string]*sidecar.DaemonMethod{}
	for _, method := range urEvsRekeyMethods(target) {
		methods[method.Name] = method
	}
	if len(methods) != 2 || methods[urMethodEvsRekeyStart] == nil || methods[urMethodEvsRekeyStatus] == nil {
		t.Fatalf("the rekey methods: %v", methods)
	}
	for name, method := range methods {
		if _, err := method.Handler(context.Background(), &sidecar.DaemonCall{}); err == nil {
			t.Errorf("%s with no repo ran", name)
		}
	}
	emptyRef := []byte(`{"repo_id":"` + sidecar.NewId().String() + `","refs":[""]}`)
	if _, err := methods[urMethodEvsRekeyStart].Handler(context.Background(), &sidecar.DaemonCall{Params: emptyRef}); err == nil || len(target.requests) != 0 {
		t.Errorf("a start naming an empty ref: %v", err)
	}
	// the daemon's own target: refused while no host builds an evs client, and with no Sidecar either way
	network := &urDaemonNetwork{noSidecar: "not enrolled"}
	if _, err := network.startRekey(&sidecar.GkmRekeyRequest{RepoId: sidecar.NewId()}); err == nil || (urDaemonRekey == nil && !errors.Is(err, errUrNoRekey)) {
		t.Errorf("a daemon with no evs client or no Sidecar started a rekey: %v", err)
	}
	if _, _, err := network.rekeyProgress(sidecar.NewId()); err == nil || (urDaemonRekey == nil && !errors.Is(err, errUrNoRekey)) {
		t.Errorf("a daemon with no evs client or no Sidecar answered a rekey's progress: %v", err)
	}
}
