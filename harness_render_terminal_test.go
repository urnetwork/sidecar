//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The signed policy's texts as a test fixes them: each id's line, and each id and version's whole text.
type testHarnessDisclosures struct {
	lines map[string]string
	texts map[string]string
}

// id's line, or the unavailable error.
func (self *testHarnessDisclosures) Line(ctx context.Context, id string) (string, error) {
	line, ok := self.lines[id]
	if !ok {
		return "", ErrHarnessDisclosureTextUnavailable
	}
	return line, nil
}

// id's text at version, or the unavailable error.
func (self *testHarnessDisclosures) Text(ctx context.Context, id string, version uint32) (string, error) {
	text, ok := self.texts[fmt.Sprintf("%s@%d", id, version)]
	if !ok {
		return "", ErrHarnessDisclosureTextUnavailable
	}
	return text, nil
}

// The acknowledgments a test's acker took.
type testHarnessAcker struct {
	stateLock sync.Mutex
	acks      []string
	err       error
}

// Records id at version, or answers the acker's error.
func (self *testHarnessAcker) Ack(ctx context.Context, id string, version uint32) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return self.err
	}
	self.acks = append(self.acks, fmt.Sprintf("%s@%d", id, version))
	return nil
}

// A renderer writing to a buffer, styled as for a terminal.
func newTestHarnessRenderer(styled bool, disclosures HarnessDisclosureTexts) (*HarnessTerminalRenderer, *bytes.Buffer) {
	out := &bytes.Buffer{}
	renderer := NewHarnessTerminalRenderer(&HarnessTerminalRendererArgs{Out: out, Styled: styled, Disclosures: disclosures})
	return renderer, out
}

// An assistant message of text, as message_end carries it.
func testHarnessAssistantEnd(model string, text string) *HarnessEvent {
	return NewHarnessMessageEndEvent(NewHarnessPiAssistantMessage(&HarnessPiAssistant{
		Content:    []*HarnessPiBlock{NewHarnessPiTextBlock(text)},
		Api:        HarnessPiApi,
		Provider:   "engy",
		Model:      model,
		StopReason: HarnessPiStopStop,
	}))
}

// The URLs of every OSC 8 link the output opens.
func testHarnessLinkTargets(output string) []string {
	targets := []string{}
	for rest := output; ; {
		start := strings.Index(rest, harnessTerminalLinkOpen)
		if start < 0 {
			return targets
		}
		rest = rest[start+len(harnessTerminalLinkOpen):]
		end := strings.Index(rest, harnessTerminalLinkClose)
		if end < 0 {
			targets = append(targets, "(unterminated) "+rest)
			return targets
		}
		if target := rest[:end]; target != "" {
			targets = append(targets, target)
		}
		rest = rest[end+len(harnessTerminalLinkClose):]
	}
}

// Every link the renderer makes carries a URL it checked: a markdown link and an autolink to https hosts are links with
// their hosts beside them; http, credentials, a javascript URL and a link a model wrote as a raw OSC 8 escape are text
// and never links; unstyled, nothing is a link and no escape is written at all.
func TestHarnessRendererLinksOnlyCheckedUrls(t *testing.T) {
	text := "Read [the guide](https://docs.example/guide) and <https://auto.example/x>.\n" +
		"Not [plain](http://plain.example/) nor [creds](https://user:pass@creds.example/) nor [js](javascript:alert).\n" +
		"Nor \x1b]8;;https://evil.example/steal\x1b\\this\x1b]8;;\x1b\\ planted link."
	renderer, out := newTestHarnessRenderer(true, nil)
	renderer.Render(context.Background(), testHarnessAssistantEnd(harnessTestModel, text))
	output := out.String()
	targets := testHarnessLinkTargets(output)
	want := []string{"https://docs.example/guide", "https://auto.example/x"}
	if !slices.Equal(targets, want) {
		t.Fatalf("links %q, want %q:\n%q", targets, want, output)
	}
	for _, target := range targets {
		if _, ok := HarnessCheckedUrl(target, DefaultHarnessSettings().TerminalLinkUrlByteCount); !ok {
			t.Errorf("a link to %q, which the check refuses", target)
		}
	}
	for _, shown := range []string{"(docs.example)", "plain (http://plain.example/)", "creds (https://user:pass@creds.example/)"} {
		if !strings.Contains(output, shown) {
			t.Errorf("the output lacks %q:\n%q", shown, output)
		}
	}
	if strings.Contains(output, "\x1b]8;;https://evil.example") {
		t.Fatalf("the planted link reached the terminal:\n%q", output)
	}

	plainRenderer, plainOut := newTestHarnessRenderer(false, nil)
	plainRenderer.Render(context.Background(), testHarnessAssistantEnd(harnessTestModel, text))
	if strings.ContainsRune(plainOut.String(), 0x1b) {
		t.Fatalf("unstyled output holds an escape:\n%q", plainOut.String())
	}
	if !strings.Contains(plainOut.String(), "the guide (https://docs.example/guide)") {
		t.Fatalf("unstyled output names no target:\n%q", plainOut.String())
	}
}

// An image is a link the person may open, never an inline image: a markdown image, iTerm2's, kitty's and sixel's
// escapes a model wrote, and a tool result's image block all reach the terminal as text.
func TestHarnessRendererNoInlineImages(t *testing.T) {
	renderer, out := newTestHarnessRenderer(true, nil)
	text := "A chart: ![sales](https://img.example/sales.png)\n" +
		"\x1b]1337;File=inline=1:iVBORw0KGgo=\x07 \x1b_Ga=T,f=100;iVBORw0K\x1b\\ \x1bPq#0;2;0;0;0#0!10~\x1b\\"
	renderer.Render(context.Background(), testHarnessAssistantEnd(harnessTestModel, text))
	image := []byte("\x89PNG\r\n\x1a\nfake image bytes")
	result := &HarnessToolResultPayload{Content: []*HarnessPiBlock{NewHarnessPiTextBlock("a picture"), NewHarnessPiImageBlock(image, "image/png")}}
	renderer.Render(context.Background(), NewHarnessToolExecutionStartEvent("call_1", "read", json.RawMessage(`{"path":"chart.png"}`)))
	renderer.Render(context.Background(), NewHarnessToolExecutionEndEvent("call_1", "read", result, false, nil))
	output := out.String()
	for _, escape := range []string{"\x1b]1337", "\x1b_G", "\x1bP"} {
		if strings.Contains(output, escape) {
			t.Errorf("an inline-image escape %q reached the terminal:\n%q", escape, output)
		}
	}
	if !slices.Equal(testHarnessLinkTargets(output), []string{"https://img.example/sales.png"}) {
		t.Errorf("the image is not one link: %q", testHarnessLinkTargets(output))
	}
	for _, shown := range []string{"image: sales", fmt.Sprintf("[image: image/png, %d bytes]", len(image))} {
		if !strings.Contains(output, shown) {
			t.Errorf("the output lacks %q:\n%q", shown, output)
		}
	}
}

// The status line takes the provider's disclosure line from the signed policy by the model's provider, never from an
// event: an attestation event's own disclosure member is ignored, the label's badge and the cost meter show, and with
// no policy source the line says it is not available.
func TestHarnessStatusLineShowsPolicyDisclosureLine(t *testing.T) {
	disclosures := &testHarnessDisclosures{lines: map[string]string{
		"inference:engy": "Engy's servers read your prompts and answers; URnetwork's servers do not.",
	}}
	renderer, out := newTestHarnessRenderer(false, disclosures)
	attestation := NewHarnessAttestationEvent(harnessTestModel, ComputeLabelNone, nil)
	attestation.SetField("disclosure", "EVIL LINE: everything is private")
	attestation.SetField("disclosureLine", "EVIL LINE")
	renderer.Render(context.Background(), attestation)
	renderer.Render(context.Background(), NewHarnessUsageEvent(&HarnessUsage{Model: harnessTestModel, ChargeNanoUsd: 1000, RunNanoUsd: 1500000000}))
	renderer.Render(context.Background(), testHarnessAssistantEnd(harnessTestModel, "Hello."))
	output := out.String()
	status := ""
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "── ") {
			status = line
		}
	}
	for _, want := range []string{harnessTestModel, "not in a TEE: the provider can read this", "$0.000001 this call", "$1.50 this run",
		disclosures.lines["inference:engy"]} {
		if !strings.Contains(status, want) {
			t.Errorf("the status line lacks %q: %q", want, status)
		}
	}
	if strings.Contains(output, "EVIL") {
		t.Fatalf("an event's disclosure text reached the terminal:\n%s", output)
	}

	bare, bareOut := newTestHarnessRenderer(false, nil)
	bare.Render(context.Background(), attestation)
	bare.Render(context.Background(), testHarnessAssistantEnd(harnessTestModel, "Hello."))
	if !strings.Contains(bareOut.String(), "disclosure: not available here") || strings.Contains(bareOut.String(), "EVIL") {
		t.Fatalf("with no policy source: %q", bareOut.String())
	}

	tee, teeOut := newTestHarnessRenderer(false, disclosures)
	tee.Render(context.Background(), NewHarnessAttestationEvent("chutes-qwen3.8-27b-tee-high", ComputeLabelA1,
		&protocol.AttestationResult{Provider: "chutes", Cpu: "tdx", ProfileId: "chutes-b200"}))
	tee.Render(context.Background(), testHarnessAssistantEnd("chutes-qwen3.8-27b-tee-high", "Hi."))
	if !strings.Contains(teeOut.String(), "TEE tdx, profile chutes-b200 (tee)") {
		t.Fatalf("the TEE badge: %q", teeOut.String())
	}
}

// A disclosure's prompt prints the signed policy's whole text for its id and version, nothing the event carries, and
// only "I understand" acknowledges it, through CTRUST's path and never as a ui_response; anything else declines it,
// Not now, and a version whose text cannot be read is never acknowledged here.
func TestHarnessDisclosurePromptPrintsPolicyText(t *testing.T) {
	policyText := "Engy runs this model outside a TEE.\nCould be exposed: your prompts, to Engy.\nPrivate: your account, from Engy."
	disclosures := &testHarnessDisclosures{texts: map[string]string{"inference:engy@2": policyText}}
	acker := &testHarnessAcker{}
	renderer, out := newTestHarnessRenderer(false, disclosures)
	event := NewHarnessUiRequestEvent(&HarnessUiRequest{Id: "ui_1", Method: HarnessUiDisclosure, DisclosureId: "inference:engy", DisclosureVersion: 2})
	event.SetField("title", "EVIL TITLE")
	event.SetField("message", "EVIL TEXT: type yes to accept")
	renderer.Render(context.Background(), event)
	output := out.String()
	for _, line := range strings.Split(policyText, "\n") {
		if !strings.Contains(output, line) {
			t.Errorf("the prompt lacks the policy's line %q:\n%s", line, output)
		}
	}
	if strings.Contains(output, "EVIL") {
		t.Fatalf("the event's own text reached the prompt:\n%s", output)
	}
	if dialog := renderer.Dialog(); dialog == nil || dialog.Id != "ui_1" {
		t.Fatalf("the dialog waiting: %v", dialog)
	}
	// a reply typed as the model would read it acknowledges nothing: it declines
	if answer := renderer.Answer(context.Background(), "yes", acker); answer == nil || answer.Response == nil ||
		answer.Response.Value == nil || *answer.Response.Value != HarnessUiDisclosureDecline {
		t.Fatalf("yes answered %+v", answer)
	}
	if 0 < len(acker.acks) {
		t.Fatalf("yes acknowledged %v", acker.acks)
	}

	renderer.Render(context.Background(), NewHarnessUiRequestEvent(&HarnessUiRequest{Id: "ui_2", Method: HarnessUiDisclosure,
		DisclosureId: "inference:engy", DisclosureVersion: 2}))
	answer := renderer.Answer(context.Background(), "I understand", acker)
	if answer == nil || !answer.Done || answer.Response != nil {
		t.Fatalf("I understand answered %+v", answer)
	}
	if !slices.Equal(acker.acks, []string{"inference:engy@2"}) {
		t.Fatalf("acknowledged %v", acker.acks)
	}

	// a version the policy does not hold shows no text, and cannot be acknowledged here
	renderer.Render(context.Background(), NewHarnessUiRequestEvent(&HarnessUiRequest{Id: "ui_3", Method: HarnessUiDisclosure,
		DisclosureId: "inference:engy", DisclosureVersion: 3}))
	if !strings.Contains(out.String(), "not available here") {
		t.Fatalf("the unreadable version's prompt:\n%s", out.String())
	}
	if answer := renderer.Answer(context.Background(), "I understand", acker); answer == nil || answer.Done || answer.Response != nil {
		t.Fatalf("an unshown version answered %+v", answer)
	}
	if len(acker.acks) != 1 {
		t.Fatalf("an unshown version was acknowledged: %v", acker.acks)
	}
	if answer := renderer.Answer(context.Background(), "", acker); answer == nil || answer.Response == nil || !answer.Done {
		t.Fatalf("an empty line answered %+v", answer)
	}
	if renderer.Dialog() != nil {
		t.Fatal("a dialog still waits")
	}

	// a failed acknowledgment leaves the dialog waiting
	renderer.Render(context.Background(), NewHarnessUiRequestEvent(&HarnessUiRequest{Id: "ui_4", Method: HarnessUiDisclosure,
		DisclosureId: "inference:engy", DisclosureVersion: 2}))
	failing := &testHarnessAcker{err: errors.New("disclosure_changed")}
	if answer := renderer.Answer(context.Background(), "I understand", failing); answer == nil || answer.Done {
		t.Fatalf("a failed acknowledgment answered %+v", answer)
	}
	if renderer.Dialog() == nil {
		t.Fatal("the dialog closed on a failed acknowledgment")
	}
}

// A select, confirm and input are answered by the person's line: an option by number or text, y or n, any text; a line
// that fits no option answers nothing, and a ui_response another view sent closes the dialog here.
func TestHarnessRendererDialogsAnswerFromTheLine(t *testing.T) {
	renderer, out := newTestHarnessRenderer(false, nil)
	renderer.Render(context.Background(), NewHarnessUiRequestEvent(&HarnessUiRequest{Id: "s", Method: HarnessUiSelect,
		Title: "The model failed", Options: []string{"retry", "another model", "local"}}))
	if answer := renderer.Answer(context.Background(), "9", nil); answer == nil || answer.Done {
		t.Fatalf("9 answered %+v", answer)
	}
	if answer := renderer.Answer(context.Background(), "2", nil); answer == nil || answer.Response == nil ||
		*answer.Response.Value != "another model" {
		t.Fatalf("2 answered %+v", answer)
	}
	renderer.Render(context.Background(), NewHarnessUiRequestEvent(&HarnessUiRequest{Id: "c", Method: HarnessUiConfirm, Title: "Go on?"}))
	if answer := renderer.Answer(context.Background(), "y", nil); answer == nil || answer.Response == nil || !*answer.Response.Confirmed {
		t.Fatalf("y answered %+v", answer)
	}
	renderer.Render(context.Background(), NewHarnessUiRequestEvent(&HarnessUiRequest{Id: "i", Method: HarnessUiInput, Title: "Name"}))
	renderer.Render(context.Background(), NewHarnessUiResponseEvent(&HarnessUiResponse{Id: "i", Cancelled: true}))
	if renderer.Dialog() != nil {
		t.Fatal("a dialog another view closed still waits")
	}
	if !strings.Contains(out.String(), "1. retry") || !strings.Contains(out.String(), "Go on? [y/N]") {
		t.Fatalf("the dialogs:\n%s", out.String())
	}
}

// Markdown streams a line at a time with its styles, thinking shows its first lines dimmed and folds the rest, and
// message_end completes what a dropped update left out.
func TestHarnessRendererStreamsMarkdownAndFoldsThinking(t *testing.T) {
	renderer, out := newTestHarnessRenderer(true, nil)
	ctx := context.Background()
	start := NewHarnessPiAssistantMessage(&HarnessPiAssistant{Model: harnessTestModel})
	renderer.Render(ctx, NewHarnessMessageStartEvent(start))
	update := func(nested *HarnessAssistantMessageEvent) {
		renderer.Render(ctx, NewHarnessMessageUpdateEvent(nil, nested))
	}
	thinking := "one\ntwo\nthree\nfour\nfive"
	update(&HarnessAssistantMessageEvent{Type: HarnessAssistantEventThinkingStart, ContentIndex: 0})
	update(&HarnessAssistantMessageEvent{Type: HarnessAssistantEventThinkingDelta, ContentIndex: 0, Delta: thinking})
	update(&HarnessAssistantMessageEvent{Type: HarnessAssistantEventThinkingEnd, ContentIndex: 0, Content: thinking})
	update(&HarnessAssistantMessageEvent{Type: HarnessAssistantEventTextStart, ContentIndex: 1})
	update(&HarnessAssistantMessageEvent{Type: HarnessAssistantEventTextDelta, ContentIndex: 1, Delta: "# Result\nIt is **4"})
	// the update carrying "2** and `x`" is dropped, and message_end completes it
	final := NewHarnessPiAssistantMessage(&HarnessPiAssistant{
		Content:    []*HarnessPiBlock{NewHarnessPiThinkingBlock(thinking), NewHarnessPiTextBlock("# Result\nIt is **42** and `x`.")},
		Model:      harnessTestModel,
		StopReason: HarnessPiStopStop,
	})
	renderer.Render(ctx, NewHarnessMessageEndEvent(final))
	output := out.String()
	for _, want := range []string{
		harnessTerminalBold + "Result", harnessTerminalBold + "42" + harnessTerminalReset, harnessTerminalCyan + "x",
		"  │ three", "2 more lines of thinking, folded",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("the output lacks %q:\n%q", want, output)
		}
	}
	if strings.Contains(output, "four") || strings.Contains(output, "five") {
		t.Errorf("folded thinking printed:\n%q", output)
	}
	if strings.Count(output, "Result") != 1 {
		t.Errorf("a line printed twice:\n%q", output)
	}
}

// A tool card summarizes its call on one line and shows the result's last lines, or its diff colored, and an argument
// carrying escapes reaches the terminal sanitized.
func TestHarnessRendererToolCardShowsLastLinesAndDiff(t *testing.T) {
	renderer, out := newTestHarnessRenderer(true, nil)
	ctx := context.Background()
	renderer.Render(ctx, NewHarnessToolExecutionStartEvent("call_1", "grep", json.RawMessage(`{"pattern":"TODO\u001b[2J","path":"."}`)))
	lines := []string{}
	for i := 1; i <= 10; i += 1 {
		lines = append(lines, fmt.Sprintf("match %d", i))
	}
	duration := int64(12)
	renderer.Render(ctx, NewHarnessToolExecutionEndEvent("call_1", "grep",
		&HarnessToolResultPayload{Content: []*HarnessPiBlock{NewHarnessPiTextBlock(strings.Join(lines, "\n"))}}, false, &duration))
	diff, _ := json.Marshal(map[string]any{"diff": "-3 old line\n+3 new line", "firstChangedLine": 3})
	renderer.Render(ctx, NewHarnessToolExecutionStartEvent("call_2", "edit", json.RawMessage(`{"path":"main.go"}`)))
	renderer.Render(ctx, NewHarnessToolExecutionEndEvent("call_2", "edit",
		&HarnessToolResultPayload{Content: []*HarnessPiBlock{NewHarnessPiTextBlock("edited")}, Details: diff}, false, nil))
	output := out.String()
	for _, want := range []string{"grep", "match 10", "4 lines before", "12 ms", harnessTerminalRed + "-3 old line",
		harnessTerminalGreen + "+3 new line", "main.go"} {
		if !strings.Contains(output, want) {
			t.Errorf("the output lacks %q:\n%q", want, output)
		}
	}
	if strings.Count(output, "match ") != 6 || strings.Contains(output, "\x1b[2J") {
		t.Errorf("an early line or a planted escape printed:\n%q", output)
	}
}
