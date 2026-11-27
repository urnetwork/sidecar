//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
)

// The open-run registry as a test keeps it, in memory: what a daemon's sealed store holds across its restart.
type harnessTestOpenRuns struct {
	stateLock sync.Mutex
	runs      map[Id]*harnessOpenRun
}

func newHarnessTestOpenRuns() *harnessTestOpenRuns {
	return &harnessTestOpenRuns{runs: map[Id]*harnessOpenRun{}}
}

func (self *harnessTestOpenRuns) Put(run *harnessOpenRun) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *run
	self.runs[run.RunId] = &copied
	return nil
}

func (self *harnessTestOpenRuns) Remove(runId Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.runs, runId)
	return nil
}

func (self *harnessTestOpenRuns) List() ([]*harnessOpenRun, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	runs := []*harnessOpenRun{}
	for _, run := range self.runs {
		copied := *run
		runs = append(runs, &copied)
	}
	return runs, nil
}

// The record a reopen reads a run back from: the test journal's nodes of the run, in the order they were journaled.
type harnessTestRunReader struct {
	journal *harnessTestJournal
}

func (self *harnessTestRunReader) Nodes(ctx context.Context, runId Id) ([]*HarnessJournalNode, error) {
	self.journal.stateLock.Lock()
	defer self.journal.stateLock.Unlock()
	nodes := []*HarnessJournalNode{}
	for _, id := range self.journal.order {
		if node, ok := self.journal.runNodes[runId][id]; ok {
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

// A daemon that stops with a run open takes it up at its restart: the same agent and run, its session tree restored,
// its next call carrying the conversation before the restart, the run's downtime counted as its gap; a closed run is
// not reopened.
func TestHarnessRunReopenedAfterDaemonRestart(t *testing.T) {
	openRuns := newHarnessTestOpenRuns()
	router := newHarnessScriptedRouter(t)
	world := newHarnessTestWorld(t, router, nil, &HarnessArgs{OpenRuns: openRuns})
	world.harness.runReader = &harnessTestRunReader{journal: world.journal}
	agent := world.agent(t, &HarnessAgentSpec{Name: "keeper"})
	closed := world.agent(t, &HarnessAgentSpec{Name: "closed"})
	closed.Close()
	router.script(harnessTextCall("the answer before the restart"))
	if err := agent.Prompt(context.Background(), "the question before the restart", nil); err != nil {
		t.Fatal(err)
	}
	<-router.called
	if err := agent.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runs, _ := openRuns.List(); len(runs) != 1 || runs[0].RunId != agent.Run().Id() {
		t.Fatalf("the registry holds %d runs", len(runs))
	}

	// the restart: a new Harness on the same run files, registry and record
	restarted, err := NewHarness(&HarnessArgs{Router: router, Journal: world.journal, Skill: world.skill, Runs: world.runs,
		Clock: world.clock, Tools: map[string]*HarnessToolSpec{}, TurnHooks: map[string]HarnessTurnHook{},
		WorkspaceParent: t.TempDir(), OpenRuns: openRuns, RunReader: &harnessTestRunReader{journal: world.journal}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	reopened, err := restarted.Reopen(context.Background())
	if err != nil || len(reopened) != 1 {
		t.Fatalf("reopened %d: %v", len(reopened), err)
	}
	again := reopened[0]
	if again.Id() != agent.Id() || again.Run().Id() != agent.Run().Id() || again.Name() != "keeper" {
		t.Fatalf("the reopened agent: %s %s %s", again.Id(), again.Run().Id(), again.Name())
	}
	if file, err := world.runs.Get(agent.Run().Id()); err != nil || !slices.Contains(file.Gaps, RecordCoverageGapDowntime) {
		t.Fatalf("the reopened run's gaps: %v, %v", file, err)
	}
	router.script(harnessTextCall("after"))
	if err := again.Prompt(context.Background(), "the question after the restart", nil); err != nil {
		t.Fatal(err)
	}
	request := <-router.called
	texts := []string{}
	for _, message := range request.Messages {
		texts = append(texts, message.Text())
	}
	joined := strings.Join(texts, "\n")
	if !strings.Contains(joined, "the question before the restart") || !strings.Contains(joined, "the answer before the restart") ||
		!strings.HasSuffix(joined, "the question after the restart") {
		t.Fatalf("the reopened run's call: %q", joined)
	}
	if err := again.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	// a second reopen takes nothing it holds open already
	if more, err := restarted.Reopen(context.Background()); err != nil || len(more) != 0 {
		t.Fatalf("a second reopen: %d, %v", len(more), err)
	}
}
