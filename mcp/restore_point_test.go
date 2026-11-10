//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's restore points on a real git worktree under t.TempDir(): the base's exact copies, a file changed during
// the walk, the cap, and the before row's holds and re-applied inputs for each harness's edit tools.

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A git worktree, a fake network and a registry over them.
type restoreTestEnv struct {
	t         *testing.T
	dir       string
	clock     *sidecartest.FakeClock
	points    *RestorePoints
	network   *fakeMcpNetwork
	networkId sidecar.Id
	runId     sidecar.Id
	settings  *sidecar.SidecarIngestSettings
}

// A repository with one commit holding committed.txt and dir/nested.txt, and a .gitignore of *.log.
func newRestoreTestEnv(t *testing.T) *restoreTestEnv {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
	dir := t.TempDir()
	// macOS gives a symlinked temp dir, which git reports resolved
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	networkId, network := daemon.host(t, sidecar.SidecarStateOnline, clock)
	settings := sidecar.DefaultSidecarSettings().Ingest
	env := &restoreTestEnv{
		t:         t,
		dir:       dir,
		clock:     clock,
		network:   network,
		networkId: networkId,
		runId:     sidecar.NewId(),
		settings:  settings,
	}
	env.points = env.newPoints()
	env.git("init", "-q", "-b", "main")
	env.git("config", "user.email", "builder@test.example")
	env.git("config", "user.name", "builder")
	env.git("config", "commit.gpgsign", "false")
	env.write(".gitignore", "*.log\n")
	env.write("committed.txt", "one\ntwo\nthree\n")
	env.write("dir/nested.txt", "nested\n")
	env.git("add", "-A")
	env.git("commit", "-q", "-m", "first")
	return env
}

// A registry on the env's clock and settings, as a restarted daemon makes one.
func (self *restoreTestEnv) newPoints() *RestorePoints {
	return NewRestorePoints(&RestorePointsArgs{Clock: self.clock, Ingest: self.settings})
}

func (self *restoreTestEnv) git(args ...string) string {
	self.t.Helper()
	command := exec.Command("git", append([]string{"-C", self.dir}, args...)...)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	output, err := command.CombinedOutput()
	if err != nil {
		self.t.Fatalf("git %v: %s: %s", args, err, output)
	}
	return string(output)
}

func (self *restoreTestEnv) write(path string, content string) {
	self.t.Helper()
	self.writeBytes(path, []byte(content))
}

func (self *restoreTestEnv) writeBytes(path string, content []byte) {
	self.t.Helper()
	absolute := filepath.Join(self.dir, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		self.t.Fatal(err)
	}
	if err := os.WriteFile(absolute, content, 0o644); err != nil {
		self.t.Fatal(err)
	}
}

func (self *restoreTestEnv) remove(path string) {
	self.t.Helper()
	if err := os.Remove(filepath.Join(self.dir, filepath.FromSlash(path))); err != nil {
		self.t.Fatal(err)
	}
}

func (self *restoreTestEnv) read(path string) []byte {
	self.t.Helper()
	content, err := os.ReadFile(filepath.Join(self.dir, filepath.FromSlash(path)))
	if err != nil {
		self.t.Fatal(err)
	}
	return content
}

// The run's point, opened on the current registry.
func (self *restoreTestEnv) open() *RestorePoint {
	self.t.Helper()
	point, err := self.points.Open(context.Background(), self.network, self.networkId, self.runId, self.dir)
	if err != nil {
		self.t.Fatalf("open: %s", err)
	}
	return point
}

// A Claude Code hook payload for a tool event in the env's worktree.
func (self *restoreTestEnv) claudePayload(event string, toolName string, toolUseId string, toolInput map[string]any) []byte {
	self.t.Helper()
	payload, err := json.Marshal(map[string]any{
		"session_id":      "s1",
		"transcript_path": filepath.Join(self.dir, "transcript.jsonl"),
		"cwd":             self.dir,
		"hook_event_name": event,
		"permission_mode": "default",
		"tool_name":       toolName,
		"tool_input":      toolInput,
		"tool_use_id":     toolUseId,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return payload
}

// A hook event parsed by harness's adapter.
func (self *restoreTestEnv) parse(harness string, payload []byte) *HookEvent {
	self.t.Helper()
	adapter, _ := HookAdapterFor(harness)
	event, err := adapter.Parse(payload, self.settings)
	if err != nil {
		self.t.Fatalf("parse: %s", err)
	}
	return event
}

// A PreToolUse's holds, as the hook path runs them.
func (self *restoreTestEnv) preToolUse(toolName string, toolUseId string, toolInput map[string]any) {
	self.t.Helper()
	event := self.parse("claude-code", self.claudePayload("PreToolUse", toolName, toolUseId, toolInput))
	if err := self.points.HookHolds()(context.Background(), self.network, self.networkId, self.runId, event); err != nil {
		self.t.Fatalf("holds: %s", err)
	}
}

// A PostToolUse noted, and the scan it ran.
func (self *restoreTestEnv) postToolUse(toolName string, toolUseId string, toolInput map[string]any) *RestoreScan {
	self.t.Helper()
	payload := self.claudePayload("PostToolUse", toolName, toolUseId, toolInput)
	event := self.parse("claude-code", payload)
	scan, err := self.points.NoteEvent(context.Background(), self.network, self.networkId, self.runId, event, payload)
	if err != nil {
		self.t.Fatalf("note: %s", err)
	}
	return scan
}

func sha256Of(content []byte) []byte {
	sum := sha256.Sum256(content)
	return sum[:]
}

// The base copies every dirty file byte for byte, a synthetic secret included, honors .gitignore, learns a clean
// file's base from HEAD, and records a deletion as an exact absent base.
func TestBaselineExactCopy(t *testing.T) {
	env := newRestoreTestEnv(t)
	secret := append([]byte("ur_sk_synthetic_0123456789abcdef\n"), bytes.Repeat([]byte{0, 1, 2, 255}, 64)...)
	env.writeBytes("committed.txt", secret)
	env.write("untracked.txt", "new\n")
	env.write("debug.log", "ignored\n")
	env.remove("dir/nested.txt")
	point := env.open()
	ctx := context.Background()
	if point.HeadCommit() == "" || point.Root() != env.dir {
		t.Fatalf("head %q root %q", point.HeadCommit(), point.Root())
	}
	modified, err := point.BaseOf(ctx, "committed.txt")
	if err != nil || !modified.Exact || modified.HashOnly || !bytes.Equal(modified.State.Sha256, sha256Of(secret)) {
		t.Fatalf("the modified file's base: %+v %v", modified, err)
	}
	if copied, err := point.BaseBytes(ctx, "committed.txt"); err != nil || !bytes.Equal(copied, secret) {
		t.Errorf("the copy is not byte-exact: %v", err)
	}
	if untracked, err := point.BaseOf(ctx, "untracked.txt"); err != nil || !untracked.Exact || untracked.Copy == "" {
		t.Errorf("the untracked file's base: %+v %v", untracked, err)
	}
	if deleted, err := point.BaseOf(ctx, "dir/nested.txt"); err != nil || !deleted.Exact || deleted.State.Kind != RestoreKindAbsent {
		t.Errorf("the deleted file's base: %+v %v", deleted, err)
	}
	for _, path := range point.BasePaths() {
		if path == "debug.log" {
			t.Error("an ignored file was walked")
		}
	}
	gitignore, err := point.BaseOf(ctx, ".gitignore")
	if err != nil || !gitignore.Exact || !gitignore.FromHead || gitignore.Blob == "" || !bytes.Equal(gitignore.State.Sha256, sha256Of([]byte("*.log\n"))) {
		t.Errorf("a clean file's base from HEAD: %+v %v", gitignore, err)
	}
	if fromHead, err := point.BaseBytes(ctx, ".gitignore"); err != nil || string(fromHead) != "*.log\n" {
		t.Errorf("HEAD's blob: %q %v", fromHead, err)
	}
	if never, err := point.BaseOf(ctx, "never.txt"); err != nil || never.State.Kind != RestoreKindAbsent || !never.Exact {
		t.Errorf("a path the repository never held: %+v %v", never, err)
	}
	// a second open reads the manifest back
	reopened := env.newPoints()
	again, err := reopened.Open(ctx, env.network, env.networkId, env.runId, env.dir)
	if err != nil {
		t.Fatal(err)
	}
	if copied, err := again.BaseBytes(ctx, "committed.txt"); err != nil || !bytes.Equal(copied, secret) {
		t.Errorf("the copy after a reload: %v", err)
	}
}

// A file written while the walk is under way has a ctime past start_ns, so its base is not exact; the others stay
// exact.
func TestFileChangedDuringWalkNotExact(t *testing.T) {
	env := newRestoreTestEnv(t)
	env.write("a.txt", "a\n")
	env.write("b.txt", "b\n")
	// the OS stamps ctimes on its own clock, so start_ns is taken well before: the walk's write is then later
	env.points = NewRestorePoints(&RestorePointsArgs{Clock: env.clock, Ingest: env.settings, WallClock: func() time.Time {
		return time.Now().Add(-time.Hour)
	}})
	env.points.walkHook = func(path string) {
		if path == "b.txt" {
			env.write("b.txt", "b changed during the walk\n")
		}
	}
	point := env.open()
	ctx := context.Background()
	changed, err := point.BaseOf(ctx, "b.txt")
	if err != nil || changed.Exact {
		t.Errorf("a file changed during the walk reads exact: %+v %v", changed, err)
	}
	if ok, reason, err := point.Restorable(ctx, "b.txt"); ok || reason != RestoreReasonNotExact || err != nil {
		t.Errorf("restorable %t %q %v", ok, reason, err)
	}
}

// A file over Ingest.FileByteCount keeps its hash and size alone, and is never exact.
func TestOverCapHashOnly(t *testing.T) {
	env := newRestoreTestEnv(t)
	env.settings.FileByteCount = 16
	large := bytes.Repeat([]byte("x"), 64)
	env.writeBytes("large.bin", large)
	env.write("small.txt", "small\n")
	point := env.open()
	ctx := context.Background()
	file, err := point.BaseOf(ctx, "large.bin")
	if err != nil || !file.HashOnly || file.Exact || file.Copy != "" || !bytes.Equal(file.State.Sha256, sha256Of(large)) || file.State.Size != 64 {
		t.Fatalf("the large file's base: %+v %v", file, err)
	}
	if _, err := point.BaseBytes(ctx, "large.bin"); err == nil {
		t.Error("a hash-only base gave bytes")
	}
	if small, err := point.BaseOf(ctx, "small.txt"); err != nil || !small.Exact {
		t.Errorf("the small file's base: %+v %v", small, err)
	}
	// the point's own cap: a second registry whose cap is under the small file's size keeps hashes alone
	env.settings.FileByteCount = 8 * 1024 * 1024
	env.settings.RestorePointByteCount = 4
	env.runId = sidecar.NewId()
	capped := env.open()
	if small, err := capped.BaseOf(ctx, "small.txt"); err != nil || !small.HashOnly || small.Exact {
		t.Errorf("past the point's cap: %+v %v", small, err)
	}
}

// Edit, Write, apply_patch and NotebookEdit: the held bytes are the before only when the call's input re-applied to
// them gives the after bytes; bytes the input does not reproduce leave the before unknown.
func TestBeforeFromHeldBytes(t *testing.T) {
	notebook := func(cells ...[2]string) string {
		rows := []map[string]any{}
		for _, cell := range cells {
			rows = append(rows, map[string]any{"id": cell[0], "cell_type": "code", "source": cell[1], "metadata": map[string]any{}, "outputs": []any{}})
		}
		encoded, _ := json.Marshal(map[string]any{"cells": rows, "nbformat": 4, "nbformat_minor": 5})
		return string(encoded)
	}
	cases := []struct {
		name      string
		toolName  string
		path      string
		before    string
		input     map[string]any
		after     string
		knownWant bool
	}{
		{
			name: "Edit once", toolName: "Edit", path: "committed.txt", before: "one\ntwo\nthree\n",
			input: map[string]any{"old_string": "two", "new_string": "2"}, after: "one\n2\nthree\n", knownWant: true,
		},
		{
			name: "Edit replace_all", toolName: "Edit", path: "committed.txt", before: "a a a\n",
			input: map[string]any{"old_string": "a", "new_string": "b", "replace_all": true}, after: "b b b\n", knownWant: true,
		},
		{
			name: "Edit ambiguous without replace_all", toolName: "Edit", path: "committed.txt", before: "a a\n",
			input: map[string]any{"old_string": "a", "new_string": "b"}, after: "b a\n", knownWant: false,
		},
		{
			name: "Edit whose after differs", toolName: "Edit", path: "committed.txt", before: "one\ntwo\n",
			input: map[string]any{"old_string": "two", "new_string": "2"}, after: "one\n2\nextra by hand\n", knownWant: false,
		},
		{
			name: "Write", toolName: "Write", path: "fresh.txt", before: "",
			input: map[string]any{"content": "written\n"}, after: "written\n", knownWant: true,
		},
		{
			name: "Write over an existing file", toolName: "Write", path: "committed.txt", before: "one\n",
			input: map[string]any{"content": "replaced\n"}, after: "replaced\n", knownWant: true,
		},
		{
			name: "apply_patch update", toolName: "apply_patch", path: "committed.txt", before: "one\ntwo\nthree\n",
			input: map[string]any{"command": "*** Begin Patch\n*** Update File: committed.txt\n@@\n one\n-two\n+TWO\n three\n*** End Patch\n"},
			after: "one\nTWO\nthree\n", knownWant: true,
		},
		{
			name: "apply_patch update that does not match", toolName: "apply_patch", path: "committed.txt", before: "one\ntwo\nthree\n",
			input: map[string]any{"command": "*** Begin Patch\n*** Update File: committed.txt\n@@\n one\n-two\n+TWO\n three\n*** End Patch\n"},
			after: "one\nTWO\nthree\nfour\n", knownWant: false,
		},
		{
			name: "NotebookEdit replace", toolName: "NotebookEdit", path: "book.ipynb",
			before: notebook([2]string{"c1", "print(1)"}, [2]string{"c2", "print(2)"}),
			input:  map[string]any{"notebook_path": "book.ipynb", "cell_id": "c2", "new_source": "print(22)", "edit_mode": "replace"},
			after:  notebook([2]string{"c1", "print(1)"}, [2]string{"c2", "print(22)"}), knownWant: true,
		},
		{
			name: "NotebookEdit with another cell changed", toolName: "NotebookEdit", path: "book.ipynb",
			before: notebook([2]string{"c1", "print(1)"}, [2]string{"c2", "print(2)"}),
			input:  map[string]any{"notebook_path": "book.ipynb", "cell_id": "c2", "new_source": "print(22)", "edit_mode": "replace"},
			after:  notebook([2]string{"c1", "print(11)"}, [2]string{"c2", "print(22)"}), knownWant: false,
		},
	}
	for _, c := range cases {
		env := newRestoreTestEnv(t)
		if c.before != "" {
			env.write(c.path, c.before)
		} else if c.path != "fresh.txt" {
			env.remove(c.path)
		}
		env.open()
		input := map[string]any{}
		for name, value := range c.input {
			input[name] = value
		}
		absolute := filepath.Join(env.dir, c.path)
		if c.toolName == "NotebookEdit" {
			input["notebook_path"] = absolute
		} else {
			input["file_path"] = absolute
		}
		env.preToolUse(c.toolName, "toolu_"+c.name, input)
		point, _ := env.points.Point(env.networkId, env.runId)
		if !point.Holds("toolu_"+c.name, absolute) {
			t.Errorf("%s: the path is not held", c.name)
		}
		env.write(c.path, c.after)
		env.postToolUse(c.toolName, "toolu_"+c.name, input)
		observations := point.Observations(c.path)
		if len(observations) == 0 || observations[0].Kind != RestoreObservationEdit {
			t.Errorf("%s: no edit observation: %+v", c.name, observations)
			continue
		}
		edit := observations[0]
		if edit.BeforeKnown != c.knownWant {
			t.Errorf("%s: before known %t", c.name, edit.BeforeKnown)
		}
		if c.knownWant && edit.BeforeKnown {
			wantBefore := sha256Of([]byte(c.before))
			if c.before == "" {
				if edit.Before.Kind != RestoreKindAbsent {
					t.Errorf("%s: an absent before reads %+v", c.name, edit.Before)
				}
			} else if !bytes.Equal(edit.Before.Sha256, wantBefore) {
				t.Errorf("%s: the before is not the held bytes' hash", c.name)
			}
		}
		if !bytes.Equal(edit.After.Sha256, sha256Of([]byte(c.after))) {
			t.Errorf("%s: the after is not the file's hash", c.name)
		}
		if point.Holds("toolu_"+c.name, absolute) {
			t.Errorf("%s: the hold outlived its PostToolUse", c.name)
		}
	}
}

// Cursor's afterFileEdit reverses its edits on the after bytes, last first.
func TestCursorReverseEdits(t *testing.T) {
	env := newRestoreTestEnv(t)
	env.write("committed.txt", "alpha\nbeta\ngamma\n")
	env.open()
	env.write("committed.txt", "ALPHA\nbeta\nGAMMA\n")
	payload, _ := json.Marshal(map[string]any{
		"conversation_id": "c1",
		"generation_id":   "g1",
		"hook_event_name": "afterFileEdit",
		"workspace_roots": []string{env.dir},
		"file_path":       filepath.Join(env.dir, "committed.txt"),
		"edits": []map[string]any{
			{"old_string": "alpha", "new_string": "ALPHA"},
			{"old_string": "gamma", "new_string": "GAMMA"},
		},
	})
	event := env.parse("cursor", payload)
	if _, err := env.points.NoteEvent(context.Background(), env.network, env.networkId, env.runId, event, payload); err != nil {
		t.Fatal(err)
	}
	point, _ := env.points.Point(env.networkId, env.runId)
	observations := point.Observations("committed.txt")
	if len(observations) == 0 || !observations[0].BeforeKnown || !bytes.Equal(observations[0].Before.Sha256, sha256Of([]byte("alpha\nbeta\ngamma\n"))) {
		t.Fatalf("the reversed before: %+v", observations)
	}
	if ok, reason, err := point.Restorable(context.Background(), "committed.txt"); !ok || err != nil {
		t.Errorf("restorable %t %q %v", ok, reason, err)
	}
}

// A new_string found twice, or found nowhere, leaves the before unknown.
func TestAmbiguousReverseIsUnknown(t *testing.T) {
	for _, after := range []string{"X\nX\n", "Y\n"} {
		env := newRestoreTestEnv(t)
		env.write("committed.txt", "a\nb\n")
		env.open()
		env.write("committed.txt", after)
		payload, _ := json.Marshal(map[string]any{
			"conversation_id": "c1",
			"hook_event_name": "afterFileEdit",
			"workspace_roots": []string{env.dir},
			"file_path":       filepath.Join(env.dir, "committed.txt"),
			"edits":           []map[string]any{{"old_string": "a", "new_string": "X"}},
		})
		event := env.parse("cursor", payload)
		if _, err := env.points.NoteEvent(context.Background(), env.network, env.networkId, env.runId, event, payload); err != nil {
			t.Fatal(err)
		}
		point, _ := env.points.Point(env.networkId, env.runId)
		observations := point.Observations("committed.txt")
		if len(observations) == 0 || observations[0].BeforeKnown {
			t.Errorf("after %q: %+v", after, observations)
		}
	}
}

// A hold times out after RestoreHoldTimeout, and a file over RestoreHoldByteCount is not held, so the before is
// unknown either way.
func TestHoldTimesOutAndCaps(t *testing.T) {
	env := newRestoreTestEnv(t)
	env.settings.RestoreHoldByteCount = 4
	env.write("committed.txt", "one\n")
	env.write("big.txt", "far too many bytes\n")
	env.open()
	point, _ := env.points.Point(env.networkId, env.runId)
	input := map[string]any{"file_path": filepath.Join(env.dir, "committed.txt"), "old_string": "one", "new_string": "1"}
	env.preToolUse("Edit", "toolu_1", input)
	env.clock.Advance(env.settings.RestoreHoldTimeout + time.Second)
	if point.Holds("toolu_1", filepath.Join(env.dir, "committed.txt")) {
		t.Fatal("a hold outlived its timeout")
	}
	env.write("committed.txt", "1\n")
	env.postToolUse("Edit", "toolu_1", input)
	if observations := point.Observations("committed.txt"); len(observations) == 0 || observations[0].BeforeKnown {
		t.Errorf("after the timeout: %+v", observations)
	}
	bigInput := map[string]any{"file_path": filepath.Join(env.dir, "big.txt"), "old_string": "far", "new_string": "FAR"}
	env.preToolUse("Edit", "toolu_2", bigInput)
	env.write("big.txt", "FAR too many bytes\n")
	env.postToolUse("Edit", "toolu_2", bigInput)
	if observations := point.Observations("big.txt"); len(observations) == 0 || observations[0].BeforeKnown {
		t.Errorf("an oversize hold: %+v", observations)
	}
}
