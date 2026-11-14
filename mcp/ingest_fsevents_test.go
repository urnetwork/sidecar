//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.18's filesystem capture (MCP-M6-03) on the composed daemon over a real git worktree, the watch a test's that
// reports what the test says: a file event narrows a run's interval, so a hand's write between a run's hooks reads
// foreign where it would read shell, and a file event never makes a change the run's edit, the scan waiting while the
// run's tool is in flight.

package mcp

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A watch whose changes a test reports, by root.
type testFileWatch struct {
	stateLock sync.Mutex
	rootSinks map[string]*IngestFileWatchSink
	stopped   int
}

func (self *testFileWatch) watch(root string, directoryCount int, sink *IngestFileWatchSink) (func(), error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rootSinks[root] = sink
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.stopped += 1
	}, nil
}

// Reports a change of path under root, as the OS would.
func (self *testFileWatch) change(t *testing.T, root string, path string, op IngestFileOp) {
	t.Helper()
	sink := func() *IngestFileWatchSink {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.rootSinks[root]
	}()
	if sink == nil {
		t.Fatalf("%s is not watched", root)
	}
	sink.Change(&IngestFileChange{Path: path, Op: op})
}

// The composed env, file events on or off, the watch the test's.
func newFileEventEnv(t *testing.T, on bool) (*restoreSuiteEnv, *testFileWatch) {
	t.Helper()
	env := newRestoreSuiteEnv(t, nil)
	env.server.settings.Ingest.FileEvents = on
	watch := &testFileWatch{rootSinks: map[string]*IngestFileWatchSink{}}
	env.ingest.detach()
	env.ingest = NewIngest(&IngestArgs{
		Server:    env.server,
		Writers:   func(network McpNetwork) (sidecar.RecordWriter, error) { return env.writer, nil },
		Redactors: func(network McpNetwork) (*sidecar.Redactor, error) { return env.redactor, nil },
		Restore:   env.restore,
		Record:    sidecar.DefaultSidecarSettings().Record,
		FileWatch: watch.watch,
	})
	return env, watch
}

// A run's shell call, then a hand's write the watch reports, then the run's next unrelated hook: with file events the
// write reads foreign, in an interval of its own with no activity of the run's, and a file_event entry records it;
// without them it shares the next hook's interval, where the run's own tool makes it shell.
func TestFileEventNarrowsInterval(t *testing.T) {
	for _, on := range []bool{true, false} {
		env, watch := newFileEventEnv(t, on)
		claude := sidecartest.FakeHarnessClaudeCode
		a := env.start(claude, "sA")
		env.toolCall(a, "sA", "Bash", map[string]any{"command": "make"}, func() {})
		env.repo.write("committed.txt", "one\ntwo\nthree\nby hand\n")
		if on {
			watch.change(t, env.repo.dir, "committed.txt", IngestFileWrite)
		}
		env.unrelated(a, claude, "sA")
		_, plan := env.plan(claude, "sA", nil)
		want := RestoreReasonShell
		if on {
			want = RestoreReasonForeign
		}
		if reason := restoreSuiteReason(plan, "committed.txt"); reason != want {
			t.Errorf("file events %t: the hand's write reads %q, want %q", on, reason, want)
		}
		events := env.writer.of(sidecar.RecordKindFileEvent)
		if on {
			if len(events) != 1 {
				t.Fatalf("%d file_event entries", len(events))
			}
			body := events[0].Body.(*protocol.FileEventBody)
			if body.Path != "committed.txt" || body.Op != uint32(IngestFileWrite) || !bytes.Equal(body.AfterSha256, sha256Of([]byte("one\ntwo\nthree\nby hand\n"))) ||
				events[0].Source != sidecar.RecordSourceObserved {
				t.Errorf("the file event %+v", body)
			}
		} else if len(events) != 0 {
			t.Errorf("file events off wrote %d entries", len(events))
		}
	}
}

// A file event while the run's tool is in flight scans nothing, so the tool's own PostToolUse attributes its edit; a
// file event after it finds nothing new, and a later hand's write it reports reads foreign, never the run's edit.
func TestFileEventNeverAttributesEdit(t *testing.T) {
	env, watch := newFileEventEnv(t, true)
	claude := sidecartest.FakeHarnessClaudeCode
	a := env.start(claude, "sA")
	env.edit(a, claude, "sA", "dir/nested.txt", "nested", "nested by A")
	env.toolCall(a, "sA", "Edit", map[string]any{
		"file_path": env.repo.dir + "/committed.txt", "old_string": "two", "new_string": "2",
	}, func() {
		env.repo.write("committed.txt", "one\n2\nthree\n")
		// the OS reports the tool's own write while the tool is in flight
		watch.change(t, env.repo.dir, "committed.txt", IngestFileWrite)
	})
	_, plan := env.plan(claude, "sA", nil)
	if len(plan.Paths()) != 2 {
		t.Fatalf("the run's own edits: %v %+v", plan.Paths(), plan.Refusals)
	}
	if events := env.writer.of(sidecar.RecordKindFileEvent); len(events) != 0 {
		t.Errorf("a file event during the run's tool wrote %d entries", len(events))
	}
	// after the tool: nothing new to scan
	watch.change(t, env.repo.dir, "committed.txt", IngestFileWrite)
	if _, again := env.plan(claude, "sA", nil); len(again.Paths()) != 2 {
		t.Errorf("a file event after the tool moved the preview: %v", again.Paths())
	}
	// a hand's write, reported: foreign, though it chains from the run's last after
	env.repo.write("committed.txt", "one\n2\nthree\nby hand\n")
	watch.change(t, env.repo.dir, "committed.txt", IngestFileWrite)
	point, after := env.plan(claude, "sA", nil)
	if reason := restoreSuiteReason(after, "committed.txt"); reason != RestoreReasonForeign {
		t.Errorf("the hand's write reads %q", reason)
	}
	for _, observation := range point.Observations("committed.txt") {
		if observation.Kind == RestoreObservationScan && observation.Attribution == RestoreAttributionEdit && bytes.Equal(observation.After.Sha256, sha256Of([]byte("one\n2\nthree\nby hand\n"))) {
			t.Error("a file event's scan attributed an edit")
		}
	}
	if !slices.Contains(env.writer.kinds(), sidecar.RecordKindFileEvent) {
		t.Error("no file_event entry")
	}
	env.ingest.Close(context.Background())
	if watch.stopped != 1 {
		t.Errorf("the watch stopped %d times at the ingest's close", watch.stopped)
	}
}
