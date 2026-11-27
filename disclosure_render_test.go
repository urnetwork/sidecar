//go:build !ios_extension && !sidecar_http

// A disclosure as a person reads it (CTRUST-M11-01): the header, the summary, "Could be exposed" and "Private" in that
// order, every string from the policy printable, and the Harness's prompt text only at the current version.

package sidecar

import (
	"errors"
	"strings"
	"testing"
)

// The terminal text is the header, the summary, then the two lists in order, each item a line; a control or bidi
// character a policy carries is dropped from every string, the header's id included.
func TestComputeDisclosureRenderOrder(t *testing.T) {
	policy := testDisclosurePolicy(t)
	engy := policy.Disclosure("inference:engy").English()
	registry := newTestDisclosureRegistry(t, &testDisclosureSource{policy: policy})
	view, err := registry.View("inference:engy", "")
	if err != nil {
		t.Fatal(err)
	}
	want := "inference:engy · version 1 · none: not in a TEE · asks before the first call\n" +
		"Summary: " + engy.Summary + "\n" +
		"\nCould be exposed\n- " + strings.Join(engy.Exposed, "\n- ") + "\n" +
		"\nPrivate\n- " + strings.Join(engy.Private, "\n- ") + "\n"
	if got := view.TerminalText(); got != want {
		t.Fatalf("the text\n%s\nwant\n%s", got, want)
	}
	if !view.Asks || view.Label != ComputeLabelNone || view.Version != 1 || view.Locale != "en" || view.GraceDays != 14 {
		t.Errorf("the view %+v", view)
	}

	// the header names an AP provider as trusted, and no label for local
	for id, header := range map[string]string{
		"inference:chutes":  "inference:chutes · version 1 · AP: in a TEE, chutes trusted · asks nothing",
		"inference:local":   "inference:local · version 1 · asks nothing",
		"enclave:hippius":   "enclave:hippius · version 1 · AP: in a TEE, hippius trusted · asks before creating one there",
		"search:parallel":   "search:parallel · version 1 · asks before the first search",
		"support:urnetwork": "support:urnetwork · version 1 · asks before the first message you or your agents send to support",
	} {
		view, err := registry.View(id, "")
		if err != nil {
			t.Fatal(err)
		}
		if view.HeaderLine() != header {
			t.Errorf("%s's header %q, want %q", id, view.HeaderLine(), header)
		}
	}

	// controls and bidi characters a policy carries never reach a terminal
	planted := testDisclosurePolicy(t)
	text := planted.Disclosure("inference:engy").English()
	text.Summary = "Not in a TEE:\x1b[2J engy reads ‮everything‬."
	text.Exposed[0] = "Everything\x07 in the\u0085 conversation⁦."
	text.Private[0] = "\x00Beside‏ what it says."
	view, err = newTestDisclosureRegistry(t, &testDisclosureSource{policy: planted}).View("inference:engy", "")
	if err != nil {
		t.Fatal(err)
	}
	if view.Summary != "Not in a TEE:[2J engy reads everything." || view.Exposed[0] != "Everything in the conversation." ||
		view.Private[0] != "Beside what it says." {
		t.Errorf("a planted control reached the view: %q %q %q", view.Summary, view.Exposed[0], view.Private[0])
	}
	for _, r := range view.TerminalText() {
		if r != '\n' && approvalRenderDropped(r) {
			t.Fatalf("the terminal text holds %U", r)
		}
	}
	if line, err := newTestDisclosureRegistry(t, &testDisclosureSource{policy: planted}).Line("inference:engy", ""); err != nil || line != view.Summary {
		t.Errorf("the line %q, %v", line, err)
	}
}

// The Harness's renderer reads a line and the whole text at the current version; another version is refused
// disclosure_changed, so no version the person was not shown is acknowledged.
func TestComputeDisclosureHarnessTexts(t *testing.T) {
	policy := testDisclosurePolicy(t)
	texts := newTestDisclosureRegistry(t, &testDisclosureSource{policy: policy}).HarnessTexts("de")
	line, err := texts.Line(t.Context(), "inference:local")
	if err != nil || line != policy.Disclosure("inference:local").Text("de").Summary {
		t.Errorf("the line %q, %v", line, err)
	}
	text, err := texts.Text(t.Context(), "inference:engy", 1)
	if err != nil || !strings.HasPrefix(text, "inference:engy · version 1 · ") || !strings.Contains(text, "\nPrivate\n") {
		t.Errorf("the text %q, %v", text, err)
	}
	if _, err := texts.Text(t.Context(), "inference:engy", 2); !errors.Is(err, ErrDisclosureChanged) {
		t.Errorf("another version: %v", err)
	}
	if !strings.HasPrefix(ErrDisclosureChanged.Error(), ComputeDisclosureCodeChanged) {
		t.Errorf("the error does not lead with its code: %v", ErrDisclosureChanged)
	}
	if _, err := texts.Text(t.Context(), "inference:nobody", 1); !errors.Is(err, ErrComputeDisclosureNotCarried) {
		t.Errorf("an id the policy does not carry: %v", err)
	}
	if _, err := texts.Line(t.Context(), "Inference:engy"); !errors.Is(err, ErrComputeDisclosureIdInvalid) {
		t.Errorf("an id outside §2.8's: %v", err)
	}
}
