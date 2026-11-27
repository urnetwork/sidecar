//go:build !ios_extension && !sidecar_http

// A disclosure as a person reads it (DESIGN-COMPUTE §2.8's text and always-shown rows; CTRUST-M11-01): the view every
// surface binds, the settings list, a card's line, `ur disclosures` and the sdk's Disclosures(), and its terminal text,
// which `ur disclosures ack` and the Harness's prompt print whole:
//
//	header    the id, the version, the provider's label in words where it has one, and what it asks before:
//	          "inference:engy · version 1 · none: not in a TEE · asks before the first call"
//	summary   "Summary: " and the one-line summary every card shows
//	lists     "Could be exposed" and "Private", each item a line, in that order, as §21.6's are
//
// Every string from the policy passes ApprovalPrintable, so a C0, C1 or bidi control planted in a policy never reaches a
// terminal or a screen; the words of the header and the lists' headings are this build's. The policy's own locale is
// shown whole (disclosure_registry.go's locale row); the headings stay English, which the apps replace with their own
// (owner rule 6). Lines are not wrapped: a terminal wraps them.

package sidecar

import (
	"context"
	"fmt"
	"strings"
)

// What a header line says each label is.
var computeDisclosureLabelWords = map[ComputeLabel]string{
	ComputeLabelNone: "none: not in a TEE",
	ComputeLabelA1:   "A1: in a TEE that measures all it runs",
	ComputeLabelA2:   "A2: in a TEE that measures all it runs, its machines in a custody registry",
}

// What a header line says each family asks before, where it asks (the design's header lines, §2.8 and §21.6 to §28.13).
var computeDisclosureAsksWords = map[ComputeDisclosureFamily]string{
	ComputeDisclosureFamilySearch:    "asks before the first search",
	ComputeDisclosureFamilyInference: "asks before the first call",
	ComputeDisclosureFamilyEnclave:   "asks before creating one there",
	ComputeDisclosureFamilyConnect:   "asks before the first connection to that service",
	ComputeDisclosureFamilyListeners: "asks before this person's devices publish their listeners",
	ComputeDisclosureFamilyApprovals: "asks before the first automatic approval",
	ComputeDisclosureFamilySupport:   "asks before the first message you or your agents send to support",
}

// A header line's words for a disclosure that asks nothing.
const computeDisclosureAsksNothing = "asks nothing"

// The lists' headings, in the order they render.
const (
	computeDisclosureSummaryHeading = "Summary: "
	computeDisclosureExposedHeading = "Could be exposed"
	computeDisclosurePrivateHeading = "Private"
)

// One disclosure as a surface shows it, every string printable. JSON in the sdk and the daemon's answers.
type ComputeDisclosureView struct {
	// family:slug.
	Id string `json:"id"`
	// The current version, raised only when a fact changes.
	Version uint32 `json:"version"`
	// The current version's revision, raised at any other change of its words.
	Revision uint32 `json:"revision"`
	// How long, in days, the previous version's acknowledgment counts on from SinceMs.
	GraceDays uint32 `json:"grace_days"`
	// When the current version took effect, unix milliseconds.
	SinceMs int64 `json:"since_ms"`
	// The locale of the text shown: the person's where the policy has it, else English.
	Locale string `json:"locale"`
	// An inference: or enclave: id's provider's label; empty for the rest.
	Label ComputeLabel `json:"label,omitempty"`
	// The label in words, as the header line says it; empty where the header names no label.
	LabelText string `json:"label_text,omitempty"`
	// Whether it waits for an acknowledgment before use.
	Asks bool `json:"asks"`
	// What it asks before, in words, or "asks nothing".
	AsksText string `json:"asks_text"`
	// The one line every card of the service shows.
	Summary string `json:"summary"`
	// "Could be exposed", in order.
	Exposed []string `json:"exposed"`
	// "Private", in order.
	Private []string `json:"private"`
}

// disclosure in the person's locale, every string from the policy made printable.
func NewComputeDisclosureView(disclosure *ComputeDisclosure, locale string) *ComputeDisclosureView {
	text := disclosure.Text(locale)
	printable := func(items []string) []string {
		out := make([]string, 0, len(items))
		for _, item := range items {
			out = append(out, ApprovalPrintable(item))
		}
		return out
	}
	view := &ComputeDisclosureView{
		Id:        disclosure.Id.String(),
		Version:   disclosure.Entry.Version,
		Revision:  disclosure.Entry.Revision,
		GraceDays: disclosure.Entry.GraceDays,
		SinceMs:   disclosure.Entry.SinceMs,
		Locale:    ApprovalPrintable(text.Locale),
		Label:     disclosure.Label,
		LabelText: computeDisclosureLabelText(disclosure),
		Asks:      disclosure.Asks,
		AsksText:  computeDisclosureAsksNothing,
		Summary:   ApprovalPrintable(text.Summary),
		Exposed:   printable(text.Exposed),
		Private:   printable(text.Private),
	}
	if disclosure.Asks {
		view.AsksText = computeDisclosureAsksWords[disclosure.Id.Family]
	}
	return view
}

// The header's words for disclosure's label: an AP provider named as trusted, none and the TEE labels in words, and
// nothing for local, which its summary says, or for an id with no provider.
func computeDisclosureLabelText(disclosure *ComputeDisclosure) string {
	switch disclosure.Label {
	case "", ComputeLabelLocal:
		return ""
	case ComputeLabelAp:
		return fmt.Sprintf("AP: in a TEE, %s trusted", disclosure.Id.Slug)
	}
	if words, found := computeDisclosureLabelWords[disclosure.Label]; found {
		return words
	}
	return string(disclosure.Label)
}

// The header line: the id, the version, the label in words where there is one, and what it asks before.
func (self *ComputeDisclosureView) HeaderLine() string {
	parts := []string{self.Id, fmt.Sprintf("version %d", self.Version)}
	if self.LabelText != "" {
		parts = append(parts, self.LabelText)
	}
	parts = append(parts, self.AsksText)
	return strings.Join(parts, " · ")
}

// The whole text as a terminal prints it: the header, the summary, then "Could be exposed" and "Private" with their
// items, each a line.
func (self *ComputeDisclosureView) TerminalText() string {
	builder := strings.Builder{}
	builder.WriteString(self.HeaderLine())
	builder.WriteString("\n")
	builder.WriteString(computeDisclosureSummaryHeading + self.Summary + "\n")
	list := func(heading string, items []string) {
		if len(items) == 0 {
			return
		}
		builder.WriteString("\n" + heading + "\n")
		for _, item := range items {
			builder.WriteString("- " + item + "\n")
		}
	}
	list(computeDisclosureExposedHeading, self.Exposed)
	list(computeDisclosurePrivateHeading, self.Private)
	return builder.String()
}

// The registry as the Harness's terminal renderer reads it (HarnessDisclosureTexts), in the person's locale.
func (self *ComputeDisclosureRegistry) HarnessTexts(locale string) HarnessDisclosureTexts {
	return &computeDisclosureHarnessTexts{registry: self, locale: locale}
}

// HarnessDisclosureTexts over a registry and one locale.
type computeDisclosureHarnessTexts struct {
	registry *ComputeDisclosureRegistry
	locale   string
}

// See HarnessDisclosureTexts.
func (self *computeDisclosureHarnessTexts) Line(ctx context.Context, id string) (string, error) {
	return self.registry.Line(id, self.locale)
}

// See HarnessDisclosureTexts: the whole text, only at the current version, so no version the person was not shown is
// acknowledged (ErrDisclosureChanged).
func (self *computeDisclosureHarnessTexts) Text(ctx context.Context, id string, version uint32) (string, error) {
	view, err := self.registry.View(id, self.locale)
	if err != nil {
		return "", err
	}
	if view.Version != version {
		return "", ErrDisclosureChanged
	}
	return view.TerminalText(), nil
}
