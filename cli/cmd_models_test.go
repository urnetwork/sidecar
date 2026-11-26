package main

// ur models (cmd_models.go; INFER-M11-08): the list with its labels, efforts, file states and disclosure lines, its
// filters reaching the daemon, an unsigned name between the markers; a pull followed by chunks done, resumed where a cut
// left it, and stopping with download_corrupt naming its chunk; the models key shown and set, a set printed and taken
// on /dev/tty, refused without one and under a harness; on stand-ins of the daemon's methods.

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Stand-ins of the daemon's model methods: what each was sent, and what each answers in turn.
type testUrModelsStand struct {
	stateLock sync.Mutex
	calls     []string
	confirmed []bool
	params    []json.RawMessage
	// by method, the replies in turn, the last again once they run out
	replies map[string][]any
	// by method, the notifications a call sends before its reply, in turn
	notifications map[string][][]any
}

func (self *testUrModelsStand) methods() []*sidecar.DaemonMethod {
	methods := []*sidecar.DaemonMethod{}
	for _, name := range []string{
		sidecar.DaemonMethodModelsList, sidecar.DaemonMethodModelsPull, sidecar.DaemonMethodModelsRemove,
		sidecar.DaemonMethodModelsSettings, sidecar.DaemonMethodModelsSet, sidecar.DaemonMethodInferRun,
	} {
		methods = append(methods, &sidecar.DaemonMethod{
			Name:    name,
			Confirm: name == sidecar.DaemonMethodModelsSet,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				reply, notifications := func() (any, []any) {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.calls = append(self.calls, name)
					self.confirmed = append(self.confirmed, call.Confirmed)
					self.params = append(self.params, append(json.RawMessage{}, call.Params...))
					var notifications []any
					if queued := self.notifications[name]; 0 < len(queued) {
						notifications = queued[0]
						self.notifications[name] = queued[1:]
					}
					replies := self.replies[name]
					if len(replies) == 0 {
						return map[string]any{}, notifications
					}
					reply := replies[0]
					if 1 < len(replies) {
						self.replies[name] = replies[1:]
					}
					return reply, notifications
				}()
				for _, notification := range notifications {
					method := sidecar.DaemonNotifyModelsPullProgress
					if name == sidecar.DaemonMethodInferRun {
						method = sidecar.DaemonNotifyInferEvent
					}
					if err := call.Notify(method, notification); err != nil {
						return nil, err
					}
				}
				if err, ok := reply.(error); ok {
					return nil, err
				}
				return reply, nil
			},
		})
	}
	return urModelsGuardMethods(methods)
}

func (self *testUrModelsStand) recorded() ([]string, []bool, []json.RawMessage) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.calls), slices.Clone(self.confirmed), slices.Clone(self.params)
}

// A ur over a daemon serving stand's methods, with no terminal unless lines are given, and under no harness.
func testUrModelsCli(t *testing.T, stand *testUrModelsStand, ttyLines ...string) (*urCli, *testUrComputeOutput, *testTty) {
	t.Helper()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range stand.methods() {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	var tty *testTty
	if ttyLines != nil {
		tty = &testTty{lines: ttyLines}
		cli.openTty = func() (urTty, error) { return tty, nil }
	}
	underHarness := urModelsUnderHarness
	urModelsUnderHarness = func(ctx context.Context, call *sidecar.DaemonCall) bool { return false }
	t.Cleanup(func() { urModelsUnderHarness = underHarness })
	return cli, &testUrComputeOutput{stdout: stdout, stderr: stderr}, tty
}

// A listing of a local model pulled and recommended, a TEE model with its disclosure line, a direct model the policy
// does not cover, whose name no signed source vouches for, and why no remote model of a kind is offered.
func testUrModelsListing() *sidecar.InferModelsListing {
	return &sidecar.InferModelsListing{
		Entries: []*sidecar.InferModelsEntry{
			{
				Name: "local-gemma-4-e4b-off", Provider: "local", Kind: sidecar.InferCatalogKindLocal, Label: sidecar.ComputeLabelLocal,
				Efforts: []sidecar.InferEffort{sidecar.InferEffortOff}, Signed: true, DisclosureId: "inference:local",
				DisclosureLine: "Runs on this device: nothing leaves it.",
				Local:          &sidecar.InferModelsLocal{File: "gemma-4-E4B-it.litertlm", ByteCount: 3_660_000_000, State: sidecar.InferPullFileWhole},
			},
			{
				Name: "chutes-qwen3.8-27b-tee-high", Provider: "chutes", Kind: sidecar.InferCatalogKindTee, Label: sidecar.ComputeLabelAp,
				Efforts: []sidecar.InferEffort{sidecar.InferEffortLow, sidecar.InferEffortHigh}, Signed: true,
				DisclosureId: "inference:chutes", DisclosureLine: "Chutes runs it in a TEE; its operator cannot read it.",
			},
			{
				Name: "engy-glm-5.2-high", Provider: "engy", Kind: sidecar.InferCatalogKindDirect, Label: sidecar.ComputeLabelNone,
				Efforts: []sidecar.InferEffort{sidecar.InferEffortHigh}, Signed: false, DisclosureId: "inference:engy",
				Unavailable: "the policy lists no direct provider engy, so the model is unusable",
			},
		},
		Recommended:       "local-gemma-4-e4b-off",
		RemoteUnavailable: "",
	}
}

// The list: each model with its label, efforts, file state and disclosure line, the recommendation, an unsigned name
// between the markers; --local, --tee and --provider reach the daemon as its filter.
func TestUrModelsListsLabelsAndLines(t *testing.T) {
	stand := &testUrModelsStand{replies: map[string][]any{sidecar.DaemonMethodModelsList: {testUrModelsListing()}}}
	cli, output, _ := testUrModelsCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "models"}); code != urExitOk {
		t.Fatalf("ur models: %d %s", code, output.stderr)
	}
	printed := output.stdout.String()
	for _, want := range []string{
		"local-gemma-4-e4b-off  local  off  3.66 GB, pulled  recommended here\n",
		"    Runs on this device: nothing leaves it.\n",
		"chutes-qwen3.8-27b-tee-high  AP  low|high\n",
		"    Chutes runs it in a TEE; its operator cannot read it.\n",
		sidecar.ComputeUntrustedBegin + " engy-glm-5.2-high " + sidecar.ComputeUntrustedEnd,
		"unavailable: the policy lists no direct provider engy",
	} {
		if !strings.Contains(printed, want) {
			t.Errorf("ur models printed no %q:\n%s", want, printed)
		}
	}
	for _, c := range []struct {
		args []string
		want sidecar.InferModelsFilter
	}{
		{args: []string{"--local"}, want: sidecar.InferModelsFilter{Local: true}},
		{args: []string{"--tee"}, want: sidecar.InferModelsFilter{Tee: true}},
		{args: []string{"--provider=chutes"}, want: sidecar.InferModelsFilter{Provider: "chutes"}},
	} {
		if code := cli.main(context.Background(), append([]string{"ur", "models"}, c.args...)); code != urExitOk {
			t.Fatalf("ur models %v: %d", c.args, code)
		}
		_, _, params := stand.recorded()
		read := &sidecar.DaemonModelsListParams{}
		if err := json.Unmarshal(params[len(params)-1], read); err != nil || read.InferModelsFilter != c.want {
			t.Errorf("ur models %v sent %s", c.args, params[len(params)-1])
		}
	}
	// --json writes the listing as the daemon answered it
	if code := cli.main(context.Background(), []string{"ur", "models", "--json"}); code != urExitOk {
		t.Fatal("ur models --json failed")
	}
	lines := strings.Split(strings.TrimSpace(output.stdout.String()), "\n")
	listing := &sidecar.InferModelsListing{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), listing); err != nil || len(listing.Entries) != 3 || listing.Recommended != "local-gemma-4-e4b-off" {
		t.Errorf("--json wrote %s (%v)", lines[len(lines)-1], err)
	}
}

// A pull's progress, chunk by chunk, as the daemon follows it.
func testUrModelsPullProgress(done int, count int) *sidecar.DaemonModelsPullReply {
	return &sidecar.DaemonModelsPullReply{Name: "local-gemma-4-e2b-off", State: sidecar.DaemonModelsPullRunning, Progress: &sidecar.InferPullProgress{
		Name: "local-gemma-4-e2b-off", Phase: sidecar.InferPullPhaseModel, File: "gemma-4-E2B-it.litertlm", ChunkCount: count,
		DoneChunkCount: done, ByteCount: int64(count) * 16 * 1024 * 1024, DoneByteCount: int64(done) * 16 * 1024 * 1024,
		Source: "api", FileIndex: 1, FileCount: 1,
	}}
}

// A pull prints its progress by chunks done and ends saying the model is on this device; it follows the daemon's pull.
func TestUrModelsPullProgress(t *testing.T) {
	stand := &testUrModelsStand{
		replies: map[string][]any{sidecar.DaemonMethodModelsPull: {&sidecar.DaemonModelsPullReply{Name: "local-gemma-4-e2b-off", State: sidecar.DaemonModelsPullDone}}},
		notifications: map[string][][]any{sidecar.DaemonMethodModelsPull: {{
			testUrModelsPullProgress(0, 3), testUrModelsPullProgress(1, 3), testUrModelsPullProgress(2, 3), testUrModelsPullProgress(3, 3),
		}}},
	}
	cli, output, _ := testUrModelsCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "models", "pull", "local-gemma-4-e2b-off"}); code != urExitOk {
		t.Fatalf("ur models pull: %d %s", code, output.stderr)
	}
	printed := output.stdout.String()
	for done := range 4 {
		want := "model gemma-4-E2B-it.litertlm: " + []string{"0", "1", "2", "3"}[done] + " of 3 chunks done"
		if !strings.Contains(printed, want) {
			t.Errorf("no %q in:\n%s", want, printed)
		}
	}
	if !strings.Contains(printed, "local-gemma-4-e2b-off is on this device") {
		t.Errorf("the end is not said:\n%s", printed)
	}
	_, _, params := stand.recorded()
	read := &sidecar.DaemonModelsPullParams{}
	if err := json.Unmarshal(params[0], read); err != nil || !read.Follow || read.Name != "local-gemma-4-e2b-off" {
		t.Errorf("the pull sent %s", params[0])
	}
}

// A pull cut mid-file says how to resume; the next starts where the cut left it, at the first chunk missing.
func TestUrModelsPullResumesAtFirstMissingChunk(t *testing.T) {
	cut := &sidecar.DaemonModelsPullReply{Name: "local-gemma-4-e2b-off", State: sidecar.DaemonModelsPullFailed,
		Progress: testUrModelsPullProgress(2, 5).Progress,
		Error:    &sidecar.DaemonModelsPullError{Code: string(sidecar.InferDownloadErrorUnavailable), Message: "the api stopped answering"}}
	stand := &testUrModelsStand{
		replies: map[string][]any{sidecar.DaemonMethodModelsPull: {cut, &sidecar.DaemonModelsPullReply{Name: "local-gemma-4-e2b-off", State: sidecar.DaemonModelsPullDone}}},
		notifications: map[string][][]any{sidecar.DaemonMethodModelsPull: {
			{testUrModelsPullProgress(0, 5), testUrModelsPullProgress(1, 5), testUrModelsPullProgress(2, 5)},
			{testUrModelsPullProgress(2, 5), testUrModelsPullProgress(3, 5), testUrModelsPullProgress(4, 5), testUrModelsPullProgress(5, 5)},
		}},
	}
	cli, output, _ := testUrModelsCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "models", "pull", "local-gemma-4-e2b-off"}); code == urExitOk {
		t.Fatal("a cut pull succeeded")
	}
	if stderr := output.stderr.String(); !strings.Contains(stderr, "download_unavailable") || !strings.Contains(stderr, "resumes at the first chunk missing") {
		t.Errorf("the cut says %q", stderr)
	}
	before := len(output.stdout.String())
	if code := cli.main(context.Background(), []string{"ur", "models", "pull", "local-gemma-4-e2b-off"}); code != urExitOk {
		t.Fatalf("the resumed pull failed: %s", output.stderr)
	}
	resumed := output.stdout.String()[before:]
	if first := strings.SplitN(resumed, "\n", 2)[0]; !strings.Contains(first, "2 of 5 chunks done") {
		t.Errorf("the resumed pull began %q", first)
	}
}

// A chunk that fails its check every time stops the pull with download_corrupt naming the chunk.
func TestUrModelsPullReportsCorruptChunk(t *testing.T) {
	chunk := 37
	stand := &testUrModelsStand{replies: map[string][]any{sidecar.DaemonMethodModelsPull: {&sidecar.DaemonModelsPullReply{
		Name: "local-gemma-4-e2b-off", State: sidecar.DaemonModelsPullFailed,
		Error: &sidecar.DaemonModelsPullError{Code: string(sidecar.InferDownloadErrorCorrupt), Chunk: &chunk, Message: "it failed its check 3 times"},
	}}}}
	cli, output, _ := testUrModelsCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "models", "pull", "local-gemma-4-e2b-off"}); code == urExitOk {
		t.Fatal("a corrupt pull succeeded")
	}
	if stderr := output.stderr.String(); !strings.Contains(stderr, "download_corrupt at chunk 37") {
		t.Errorf("the corrupt chunk says %q", stderr)
	}
}

// A set prints the change, and needs a yes on /dev/tty: without a terminal nothing is sent, and with one the Confirm
// method is sent confirmed.
func TestUrModelsSetNeedsTty(t *testing.T) {
	stand := &testUrModelsStand{replies: map[string][]any{
		sidecar.DaemonMethodModelsSettings: {&sidecar.DaemonModelsSettingsReply{SignInMail: "withhold"}},
		sidecar.DaemonMethodModelsSet:      {&sidecar.DaemonModelsSettingsReply{TeeOnly: true, SignInMail: "withhold"}},
	}}
	cli, output, _ := testUrModelsCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "models", "set", "--tee-only=on"}); code == urExitOk {
		t.Fatal("a set without a terminal succeeded")
	}
	if !strings.Contains(output.stderr.String(), "terminal") {
		t.Errorf("no terminal says %q", output.stderr)
	}
	if calls, _, _ := stand.recorded(); slices.Contains(calls, sidecar.DaemonMethodModelsSet) {
		t.Error("models.set was sent without a terminal")
	}
	cli, output, tty := testUrModelsCli(t, stand, "yes")
	if code := cli.main(context.Background(), []string{"ur", "models", "set", "--tee-only=on", "--allow=local-*", "--allow=chutes-*"}); code != urExitOk {
		t.Fatalf("a confirmed set: %d %s", code, output.stderr)
	}
	shown := tty.written.String()
	if !strings.Contains(shown, "tee_only: off -> on") || !strings.Contains(shown, "allow: every model -> local-* chutes-*") {
		t.Errorf("the change shown on /dev/tty: %q", shown)
	}
	calls, confirmed, params := stand.recorded()
	last := len(calls) - 1
	set := &sidecar.DaemonModelsSetParams{}
	if calls[last] != sidecar.DaemonMethodModelsSet || !confirmed[last] || json.Unmarshal(params[last], set) != nil ||
		set.TeeOnly == nil || !*set.TeeOnly || set.Allow == nil || !slices.Equal(*set.Allow, []string{"local-*", "chutes-*"}) {
		t.Errorf("sent %s %v %s", calls[last], confirmed[last], params[last])
	}
	// a no at the terminal changes nothing
	cli, output, _ = testUrModelsCli(t, stand, "no")
	count := len(calls)
	if code := cli.main(context.Background(), []string{"ur", "models", "set", "--default=local-gemma-4-e2b-off"}); code != urExitOk ||
		!strings.Contains(output.stdout.String(), "nothing changed") {
		t.Errorf("a declined set: %s", output.stdout)
	}
	if calls, _, _ := stand.recorded(); slices.Contains(calls[count:], sidecar.DaemonMethodModelsSet) {
		t.Error("a declined set was sent")
	}
	// a set that names nothing is refused before anything is asked
	if code := cli.main(context.Background(), []string{"ur", "models", "set"}); code == urExitOk {
		t.Error("an empty set succeeded")
	}
}

// Under a harness the daemon refuses the set, confirmed or not, and the key's writer is never reached.
func TestUrModelsSetRefusedUnderHarness(t *testing.T) {
	stand := &testUrModelsStand{replies: map[string][]any{sidecar.DaemonMethodModelsSettings: {&sidecar.DaemonModelsSettingsReply{}}}}
	cli, output, _ := testUrModelsCli(t, stand, "yes")
	urModelsUnderHarness = func(ctx context.Context, call *sidecar.DaemonCall) bool { return true }
	if code := cli.main(context.Background(), []string{"ur", "models", "set", "--tee-only=on"}); code == urExitOk {
		t.Fatal("a set under a harness succeeded")
	}
	if !strings.Contains(output.stderr.String(), "harness") {
		t.Errorf("under a harness says %q", output.stderr)
	}
	if calls, _, _ := stand.recorded(); slices.Contains(calls, sidecar.DaemonMethodModelsSet) {
		t.Error("the set's handler ran under a harness")
	}
}

// The settings print as the person reads them.
func TestUrModelsSettingsPrints(t *testing.T) {
	stand := &testUrModelsStand{replies: map[string][]any{sidecar.DaemonMethodModelsSettings: {&sidecar.DaemonModelsSettingsReply{
		Default: "local-gemma-4-e4b-off", Allow: []string{}, TeeOnly: true, SignInMail: "withhold",
		Harness: map[string]map[string]string{"codex": {"model": "chutes-qwen3.8-27b-tee-high"}},
	}}}}
	cli, output, _ := testUrModelsCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "models", "settings"}); code != urExitOk {
		t.Fatal("ur models settings failed")
	}
	for _, want := range []string{"default: local-gemma-4-e4b-off\n", "allow: no model\n", "tee_only: on\n", "harness codex model: chutes-qwen3.8-27b-tee-high\n"} {
		if !strings.Contains(output.stdout.String(), want) {
			t.Errorf("no %q in %s", want, output.stdout)
		}
	}
}
