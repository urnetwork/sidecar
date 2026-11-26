package main

// ur infer (cmd_infer.go; INFER-M11-08): the answer streamed as terminal text, a call the daemon did not record said
// so, and a model labeled none whose disclosure waits: its whole text on /dev/tty, the person's answer taken through
// CTRUST's acknowledgment and the prompt asked again, or disclosure_required without a terminal; on stand-ins of the
// daemon's methods.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A stand-in of CTRUST's texts and acknowledgment: one text, and the acknowledgments taken.
type testUrInferDisclosures struct {
	stateLock sync.Mutex
	acked     []string
}

func (self *testUrInferDisclosures) Line(ctx context.Context, id string) (string, error) {
	return "the line of " + id, nil
}

func (self *testUrInferDisclosures) Text(ctx context.Context, id string, version uint32) (string, error) {
	return "What could be exposed: " + id + " reads every request.", nil
}

func (self *testUrInferDisclosures) Ack(ctx context.Context, id string, version uint32) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.acked = append(self.acked, id)
	return nil
}

// The stand-in's disclosure entry in place of CTRUST's until the test ends.
func testUrInferDisclosureEntry(t *testing.T, disclosures *testUrInferDisclosures) {
	t.Helper()
	entry := urHarnessDisclosureEntry
	t.Cleanup(func() { urHarnessDisclosureEntry = entry })
	urHarnessDisclosureEntry = func(cli *urCli, network string) (sidecar.HarnessDisclosureTexts, sidecar.HarnessDisclosureAcker) {
		return disclosures, disclosures
	}
}

// infer.run's text events, as the router streams them.
func testUrInferText(texts ...string) []any {
	events := []any{&sidecar.InferEvent{Kind: sidecar.InferEventStart}}
	for _, text := range texts {
		events = append(events, &sidecar.InferEvent{Kind: sidecar.InferEventText, Text: text})
	}
	return append(events, &sidecar.InferEvent{Kind: sidecar.InferEventUsage, Usage: &sidecar.InferUsage{InputTokens: 4, OutputTokens: 2}})
}

// The answer streams as terminal text, a control character dropped, and the prompt reaches infer.run whole.
func TestUrInferStreams(t *testing.T) {
	stand := &testUrModelsStand{
		replies:       map[string][]any{sidecar.DaemonMethodInferRun: {&sidecar.DaemonInferRunReply{RunId: sidecar.NewId(), Model: "local-gemma-4-e4b-off", Recorded: true}}},
		notifications: map[string][][]any{sidecar.DaemonMethodInferRun: {testUrInferText("Hello", ", \x1b[2Jworld")}},
	}
	cli, output, _ := testUrModelsCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "infer", "--model=local-gemma-4-e4b", "say hello"}); code != urExitOk {
		t.Fatalf("ur infer: %d %s", code, output.stderr)
	}
	if printed := output.stdout.String(); printed != "Hello, [2Jworld\n" {
		t.Errorf("ur infer printed %q", printed)
	}
	_, _, params := stand.recorded()
	run := &sidecar.DaemonInferRunParams{}
	if err := json.Unmarshal(params[0], run); err != nil || run.Model != "local-gemma-4-e4b" || run.Prompt != "say hello" {
		t.Errorf("infer.run had %s", params[0])
	}
}

// A call the daemon ran but did not record says so on stderr; the daemon's record of a call is infer.run's own,
// held in the root's TestDaemonInferRunRecordsModelCall.
func TestUrInferRecordsModelCall(t *testing.T) {
	stand := &testUrModelsStand{
		replies: map[string][]any{sidecar.DaemonMethodInferRun: {
			&sidecar.DaemonInferRunReply{RunId: sidecar.NewId(), Model: "local-gemma-4-e4b-off", Recorded: true},
			&sidecar.DaemonInferRunReply{RunId: sidecar.NewId(), Model: "local-gemma-4-e4b-off", RecordError: "the record is locked"},
		}},
		notifications: map[string][][]any{sidecar.DaemonMethodInferRun: {testUrInferText("one"), testUrInferText("two")}},
	}
	cli, output, _ := testUrModelsCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "infer", "--model=local-gemma-4-e4b-off", "hello"}); code != urExitOk ||
		strings.Contains(output.stderr.String(), "not recorded") {
		t.Fatalf("a recorded call: %d %q", code, output.stderr)
	}
	if code := cli.main(context.Background(), []string{"ur", "infer", "--model=local-gemma-4-e4b-off", "hello"}); code != urExitOk ||
		!strings.Contains(output.stderr.String(), "not recorded: the record is locked") {
		t.Errorf("an unrecorded call: %d %q", code, output.stderr)
	}
}

// disclosure_required for a model labeled none.
func testUrInferDisclosureRequired() *sidecar.DaemonInferRunReply {
	return &sidecar.DaemonInferRunReply{RunId: sidecar.NewId(), Model: "engy-glm-5.2-high", Error: &sidecar.InferError{
		Code: sidecar.InferErrorDisclosureRequired, Model: "engy-glm-5.2-high", Reason: sidecar.InferDisclosureReasonUnacknowledged,
		Message: "engy-glm-5.2-high's provider runs outside any TEE", DisclosureId: "inference:engy", DisclosureVersion: 2,
	}}
}

// Before a first call to a model labeled none, the disclosure's whole text prints on /dev/tty and "I understand" is
// taken through CTRUST's acknowledgment, then the prompt is asked again; without a terminal, or declined, the command
// answers disclosure_required, asking once.
func TestUrInferAsksOnTtyForNone(t *testing.T) {
	disclosures := &testUrInferDisclosures{}
	testUrInferDisclosureEntry(t, disclosures)
	stand := &testUrModelsStand{
		replies: map[string][]any{sidecar.DaemonMethodInferRun: {testUrInferDisclosureRequired(),
			&sidecar.DaemonInferRunReply{RunId: sidecar.NewId(), Model: "engy-glm-5.2-high", Recorded: true}}},
		notifications: map[string][][]any{sidecar.DaemonMethodInferRun: {nil, testUrInferText("an answer")}},
	}
	cli, output, tty := testUrModelsCli(t, stand, "I understand")
	if code := cli.main(context.Background(), []string{"ur", "infer", "--model=engy-glm-5.2-high", "hello"}); code != urExitOk {
		t.Fatalf("an acknowledged call: %d %s", code, output.stderr)
	}
	if !strings.Contains(tty.written.String(), "What could be exposed: inference:engy reads every request.") {
		t.Errorf("the text on /dev/tty: %q", tty.written.String())
	}
	if len(disclosures.acked) != 1 || disclosures.acked[0] != "inference:engy" || output.stdout.String() != "an answer\n" {
		t.Errorf("acked %v, printed %q", disclosures.acked, output.stdout)
	}

	// no terminal: disclosure_required, asked once
	stand = &testUrModelsStand{replies: map[string][]any{sidecar.DaemonMethodInferRun: {testUrInferDisclosureRequired()}}}
	cli, output, _ = testUrModelsCli(t, stand)
	if code := cli.main(context.Background(), []string{"ur", "infer", "--model=engy-glm-5.2-high", "hello"}); code == urExitOk {
		t.Fatal("a call waiting for its disclosure succeeded without a terminal")
	}
	if !strings.Contains(output.stderr.String(), "disclosure_required") {
		t.Errorf("without a terminal: %q", output.stderr)
	}
	if calls, _, _ := stand.recorded(); len(calls) != 1 {
		t.Errorf("asked %d times without a terminal", len(calls))
	}

	// declined at the terminal: disclosure_required, nothing acknowledged
	disclosures.acked = nil
	stand = &testUrModelsStand{replies: map[string][]any{sidecar.DaemonMethodInferRun: {testUrInferDisclosureRequired()}}}
	cli, output, _ = testUrModelsCli(t, stand, "not now")
	if code := cli.main(context.Background(), []string{"ur", "infer", "--model=engy-glm-5.2-high", "hello"}); code == urExitOk ||
		len(disclosures.acked) != 0 || !strings.Contains(output.stderr.String(), "disclosure_required") {
		t.Errorf("a declined disclosure: %d %v %q", code, disclosures.acked, output.stderr)
	}
}

// With no disclosure texts in this build, a terminal says so and the call answers disclosure_required.
func TestUrInferWithoutDisclosureTexts(t *testing.T) {
	entry := urHarnessDisclosureEntry
	t.Cleanup(func() { urHarnessDisclosureEntry = entry })
	urHarnessDisclosureEntry = nil
	stand := &testUrModelsStand{replies: map[string][]any{sidecar.DaemonMethodInferRun: {testUrInferDisclosureRequired()}}}
	cli, output, tty := testUrModelsCli(t, stand, "I understand")
	if code := cli.main(context.Background(), []string{"ur", "infer", "--model=engy-glm-5.2-high", "hello"}); code == urExitOk {
		t.Fatal("a call with no disclosure text succeeded")
	}
	if !strings.Contains(tty.written.String(), "does not hold yet") || !strings.Contains(output.stderr.String(), "disclosure_required") {
		t.Errorf("no texts: %q %q", tty.written.String(), output.stderr)
	}
	var refusal *urInferError
	if !errors.As(&urInferError{refusal: testUrInferDisclosureRequired().Error}, &refusal) {
		t.Error("the refusal is no urInferError")
	}
}
