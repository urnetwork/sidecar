//go:build !ios_extension && !sidecar_http

// The terminal renderer (DESIGN-COMPUTE §7.11, §7.6, R-HARN-2, D-HARN-10): `ur harness`'s view of §7.6's events as
// terminal text, with no terminal-UI framework, so it adds little to ur. From the events a view takes, it writes:
//
//   - an assistant's markdown as it streams, a line at a time, with ANSI styles: headings, emphasis, code spans and
//     blocks, quotes and lists; thinking dimmed, its first TerminalThinkingLineCount lines shown and the rest folded;
//     and message_end, which is authoritative, completing whatever a dropped update left out
//   - tool cards: a one-line summary at the call's start, and at its end the result's last lines, or its diff colored
//   - after each answer the status line: the model, its TEE badge, the cost meter (the call's charge and the run's),
//     and the provider's disclosure line, taken from the signed policy by id (HarnessDisclosureTexts) and never from an
//     event, so no model, tool, remote Harness or server changes what the person reads (§7.6's disclosure lines)
//   - notes for the person's prompts, queues, compaction, retries, approvals, sub-agents, the attach link and how a run
//     ended; each registered card through its type's terminal rendering
//   - dialogs: a select, confirm or input's question, and for a disclosure the signed policy's whole text for its id
//     and version, which only the person's acknowledgment answers, never a typed reply to the model (Answer)
//
// Every string an event carries is untrusted, a model's own text and its markdown's links among them, and passes
// HarnessSanitize before the renderer adds its own escapes; a link is an OSC 8 link only where HarnessCheckedUrl passes
// its URL, with the URL's host beside its text, and prints as text otherwise. Nothing is fetched or loaded: an image
// shows as a link or a note, never an inline-image escape (§7.6's no remote loads). Unstyled, for output that is no
// terminal, it writes no escape at all.
//
// Safe for concurrent use: one event, notice or answer at a time (renderLock). A view's answer and its events may come
// from two goroutines.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// The renderer's own escapes: ANSI's select graphic rendition codes, and OSC 8's link brackets with ST.
const (
	harnessTerminalReset     = "\x1b[0m"
	harnessTerminalBold      = "\x1b[1m"
	harnessTerminalDim       = "\x1b[2m"
	harnessTerminalItalic    = "\x1b[3m"
	harnessTerminalUnderline = "\x1b[4m"
	harnessTerminalRed       = "\x1b[31m"
	harnessTerminalGreen     = "\x1b[32m"
	harnessTerminalYellow    = "\x1b[33m"
	harnessTerminalCyan      = "\x1b[36m"
	harnessTerminalLinkOpen  = "\x1b]8;;"
	harnessTerminalLinkClose = "\x1b\\"
)

// What a person types to acknowledge a disclosure on a terminal, as `ur disclosures ack` takes it (§2.8).
const HarnessDisclosureAcknowledgment = "I understand"

var (
	// No source of the signed policy's disclosure texts is wired, so a disclosure is neither shown nor acknowledged.
	ErrHarnessDisclosureTextUnavailable = errors.New("the signed policy's disclosure text is not available here")
)

// The signed policy's disclosure texts as a renderer shows them (§2.8, CTRUST's registry), never an event's.
type HarnessDisclosureTexts interface {
	// id's summary line, which a badge and the status line show.
	Line(ctx context.Context, id string) (string, error)
	// id's whole text at version, as the person reads it before acknowledging: an error where the policy holds no such
	// version, so no version the person was not shown is acknowledged.
	Text(ctx context.Context, id string, version uint32) (string, error)
}

// The person's acknowledgment of a disclosure (§2.8, CTRUST's path, `ur disclosures ack`'s): it records the version the
// person was shown, in the store a disclosure request waits on.
type HarnessDisclosureAcker interface {
	Ack(ctx context.Context, id string, version uint32) error
}

// What a renderer is built on.
type HarnessTerminalRendererArgs struct {
	// Nil takes DefaultHarnessSettings.
	Settings *HarnessSettings
	// For reading a model's provider from its name; nil takes DefaultInferSettings.
	InferSettings *InferSettings
	// Required: where the text goes.
	Out io.Writer
	// Styles with ANSI escapes and links with OSC 8, for a terminal; false writes plain text alone, as to a pipe.
	Styled bool
	// CTRUST's registry; nil shows no disclosure line and no disclosure's text, saying so.
	Disclosures HarnessDisclosureTexts
}

// One content block of the assistant message streaming now.
type harnessTerminalBlock struct {
	kind string
	// what streamed so far, and how much of it printed as whole lines
	text    strings.Builder
	printed int
	// a thinking block's lines shown and folded
	thinkingLines int
	foldedLines   int
	ended         bool
}

// What the status line shows.
type harnessTerminalStatus struct {
	model         string
	label         ComputeLabel
	cpu           string
	profile       string
	chargeNanoUsd uint64
	runNanoUsd    uint64
}

// What answering a dialog on a terminal came to.
type HarnessTerminalAnswer struct {
	// The ui_response to send (harness.respond_ui); nil where none goes: an acknowledged disclosure, which CTRUST's
	// store answers, and a line that answered nothing.
	Response *HarnessUiResponse
	// What the renderer told the person.
	Notice string
	// The dialog is settled here: answered, acknowledged or declined.
	Done bool
}

// The terminal renderer.
type HarnessTerminalRenderer struct {
	settings      *HarnessSettings
	inferSettings *InferSettings
	out           io.Writer
	styled        bool
	disclosures   HarnessDisclosureTexts

	// held across one render, notice or answer, so output never interleaves; the renderer's state below is only read
	// and written under it
	renderLock sync.Mutex
	blocks     map[int]*harnessTerminalBlock
	// the open code fence's marker, empty outside one
	fence  string
	status harnessTerminalStatus
	// the ui requests shown and not yet answered, oldest first
	dialogs []*HarnessUiRequest
	// the disclosure requests whose policy text was shown whole, by request id
	shownDisclosureIds map[string]bool
}

// A renderer over args.
func NewHarnessTerminalRenderer(args *HarnessTerminalRendererArgs) *HarnessTerminalRenderer {
	settings := args.Settings
	if settings == nil {
		settings = DefaultHarnessSettings()
	}
	inferSettings := args.InferSettings
	if inferSettings == nil {
		inferSettings = DefaultInferSettings()
	}
	return &HarnessTerminalRenderer{
		settings:           settings,
		inferSettings:      inferSettings,
		out:                args.Out,
		styled:             args.Styled,
		disclosures:        args.Disclosures,
		blocks:             map[int]*harnessTerminalBlock{},
		shownDisclosureIds: map[string]bool{},
	}
}

// text in style, reset after; text alone when unstyled.
func (self *HarnessTerminalRenderer) style(style string, text string) string {
	if !self.styled || text == "" {
		return text
	}
	return style + text + harnessTerminalReset
}

// Writes one line. A view whose terminal is gone loses the line.
func (self *HarnessTerminalRenderer) writeLine(line string) {
	io.WriteString(self.out, line+"\n")
}

// Writes a note of the view's own: dimmed, sanitized.
func (self *HarnessTerminalRenderer) noteWithLock(prefix string, text string) {
	self.writeLine(prefix + self.style(harnessTerminalDim, HarnessSanitizeLine(text)))
}

// Writes a line of the view's own, as `ur harness` tells the person something: sanitized and dimmed.
func (self *HarnessTerminalRenderer) Notice(text string) {
	self.renderLock.Lock()
	defer self.renderLock.Unlock()
	for _, line := range strings.Split(HarnessSanitize(text), "\n") {
		self.writeLine(self.style(harnessTerminalDim, line))
	}
}

// The ui request shown longest ago and not yet answered, a copy, or nil: the one the person's next line answers.
func (self *HarnessTerminalRenderer) Dialog() *HarnessUiRequest {
	self.renderLock.Lock()
	defer self.renderLock.Unlock()
	if len(self.dialogs) == 0 {
		return nil
	}
	request := *self.dialogs[0]
	return &request
}

// A string member of event, or empty.
func harnessTerminalString(event *HarnessEvent, name string) string {
	value := ""
	event.Decode(name, &value)
	return value
}

// Writes event as terminal text.
func (self *HarnessTerminalRenderer) Render(ctx context.Context, event *HarnessEvent) {
	if event == nil {
		return
	}
	self.renderLock.Lock()
	defer self.renderLock.Unlock()
	prefix := ""
	if event.Enclave != "" {
		// a remote Harness's event, nested under its enclave (§7.10)
		prefix = self.style(harnessTerminalDim, "["+HarnessSanitizeLine(event.Enclave)+"] ")
	}
	omitted := 0
	if event.Decode("omitted", &omitted) {
		self.noteWithLock(prefix, fmt.Sprintf("(a %s event too large to show here: %d bytes)", event.Type, omitted))
		return
	}
	switch event.Type {
	case HarnessEventAgentStart, HarnessEventTurnStart, HarnessEventTurnEnd, HarnessEventAgentEnd:
	case HarnessEventMessageStart:
		if message := event.Message(); message != nil && message.Role() == HarnessPiRoleAssistant {
			self.blocks = map[int]*harnessTerminalBlock{}
			self.fence = ""
		}
	case HarnessEventMessageUpdate:
		if nested := event.AssistantMessageEvent(); nested != nil {
			self.updateWithLock(prefix, nested)
		}
	case HarnessEventMessageEnd:
		self.messageEndWithLock(ctx, prefix, event.Message())
	case HarnessEventToolExecutionStart:
		name := harnessTerminalString(event, "toolName")
		self.writeLine(prefix + self.style(harnessTerminalCyan, "● ") + self.style(harnessTerminalBold, HarnessSanitizeLine(name)) +
			" " + self.argsSummary(event.Field("args")))
	case HarnessEventToolExecutionUpdate:
		// the card's output shows at its end, so a terminal is not flooded by a long call's updates
	case HarnessEventToolExecutionEnd:
		self.toolEndWithLock(prefix, event)
	case HarnessEventQueueUpdate:
		steering, followUp := []string{}, []string{}
		event.Decode("steering", &steering)
		event.Decode("followUp", &followUp)
		if 0 < len(steering)+len(followUp) {
			self.noteWithLock(prefix, fmt.Sprintf("⋯ queued: %d to steer, %d to follow up", len(steering), len(followUp)))
		}
	case HarnessEventCompactionStart:
		self.noteWithLock(prefix, "compacting the context ("+harnessTerminalString(event, "reason")+")")
	case HarnessEventCompactionEnd:
		self.compactionEndWithLock(prefix, event)
	case HarnessEventAutoRetryStart:
		attempt, maxAttempts, delayMs := 0, 0, int64(0)
		event.Decode("attempt", &attempt)
		event.Decode("maxAttempts", &maxAttempts)
		event.Decode("delayMs", &delayMs)
		self.noteWithLock(prefix, fmt.Sprintf("retrying, attempt %d of %d, in %d ms: %s", attempt, maxAttempts, delayMs,
			harnessTerminalString(event, "errorMessage")))
	case HarnessEventAutoRetryEnd:
		success := false
		event.Decode("success", &success)
		if !success {
			self.noteWithLock(prefix, "the retries failed: "+harnessTerminalString(event, "finalError"))
		}
	case HarnessEventAgentSettled:
		reason := harnessTerminalString(event, "stopReason")
		if reason != "" && reason != HarnessStopEnded {
			text := "the run stopped: " + reason
			if message := harnessTerminalString(event, "errorMessage"); message != "" {
				text += ": " + message
			}
			self.noteWithLock(prefix, text)
		}
	case HarnessEventApprovalPending:
		self.approvalPendingWithLock(prefix, event)
	case HarnessEventApprovalResolved:
		self.approvalResolvedWithLock(prefix, event)
	case HarnessEventAttestation:
		self.attestationWithLock(event)
	case HarnessEventUsage:
		event.Decode("chargeNanoUsd", &self.status.chargeNanoUsd)
		event.Decode("runNanoUsd", &self.status.runNanoUsd)
		if model := harnessTerminalString(event, "model"); model != "" {
			self.status.model = model
		}
	case HarnessEventAgentSpawned:
		self.noteWithLock(prefix, fmt.Sprintf("↳ %s started (%s, %s)", harnessTerminalString(event, "name"),
			harnessTerminalString(event, "model"), harnessTerminalString(event, "where")))
	case HarnessEventAgentExited:
		self.noteWithLock(prefix, fmt.Sprintf("↳ %s exited: %s", harnessTerminalString(event, "name"),
			harnessTerminalString(event, "stopReason")))
	case HarnessEventAttachStatus:
		self.noteWithLock(prefix, fmt.Sprintf("⇄ %s: %s (%s)", harnessTerminalString(event, "state"),
			harnessTerminalString(event, "harness"), harnessTerminalString(event, "mode")))
	case HarnessEventUiRequest:
		self.uiRequestWithLock(ctx, prefix, event)
	case HarnessEventUiResponse:
		self.uiResponseWithLock(prefix, event)
	default:
		self.cardWithLock(prefix, event)
	}
}

// A registered card through its type's terminal rendering, each line sanitized and printed in the renderer's style; a
// type this build does not know prints a note.
func (self *HarnessTerminalRenderer) cardWithLock(prefix string, event *HarnessEvent) {
	render := HarnessEventTerminalRendering(event.Type)
	if render == nil {
		self.noteWithLock(prefix, fmt.Sprintf("(a %s event this build does not show)", event.Type))
		return
	}
	lines, err := render(event)
	if err != nil {
		self.noteWithLock(prefix, fmt.Sprintf("(a %s card that could not be shown)", event.Type))
		return
	}
	for _, line := range lines {
		self.writeLine(prefix + HarnessSanitizeLine(line))
	}
}

// One message_update's nested event: a text or thinking block's start, delta or end. Tool call deltas print nothing:
// the call's card shows at its start.
func (self *HarnessTerminalRenderer) updateWithLock(prefix string, nested *HarnessAssistantMessageEvent) {
	kind := ""
	switch nested.Type {
	case HarnessAssistantEventTextStart, HarnessAssistantEventTextDelta, HarnessAssistantEventTextEnd:
		kind = HarnessPiBlockText
	case HarnessAssistantEventThinkingStart, HarnessAssistantEventThinkingDelta, HarnessAssistantEventThinkingEnd:
		kind = HarnessPiBlockThinking
	default:
		return
	}
	block := self.blockWithLock(prefix, nested.ContentIndex, kind)
	if block.ended {
		return
	}
	switch nested.Type {
	case HarnessAssistantEventTextDelta, HarnessAssistantEventThinkingDelta:
		block.text.WriteString(nested.Delta)
		self.flushWithLock(prefix, block, false)
	case HarnessAssistantEventTextEnd, HarnessAssistantEventThinkingEnd:
		self.endBlockWithLock(prefix, block, nested.Content)
	}
}

// The block at index, made where it is new: a thinking block starts with its header.
func (self *HarnessTerminalRenderer) blockWithLock(prefix string, index int, kind string) *harnessTerminalBlock {
	block, ok := self.blocks[index]
	if !ok {
		block = &harnessTerminalBlock{kind: kind}
		self.blocks[index] = block
		if kind == HarnessPiBlockThinking {
			self.writeLine(prefix + self.style(harnessTerminalDim, "thinking"))
		}
	}
	return block
}

// Prints the block's whole lines not yet printed, and with final its last partial line too.
func (self *HarnessTerminalRenderer) flushWithLock(prefix string, block *harnessTerminalBlock, final bool) {
	text := block.text.String()
	for {
		rest := text[block.printed:]
		newline := strings.IndexByte(rest, '\n')
		if newline < 0 {
			if final && rest != "" {
				self.blockLineWithLock(prefix, block, rest)
				block.printed = len(text)
			}
			return
		}
		self.blockLineWithLock(prefix, block, rest[:newline])
		block.printed += newline + 1
	}
}

// One whole line of a block: markdown for text, dimmed or folded for thinking.
func (self *HarnessTerminalRenderer) blockLineWithLock(prefix string, block *harnessTerminalBlock, line string) {
	if block.kind == HarnessPiBlockThinking {
		if block.thinkingLines < self.settings.TerminalThinkingLineCount {
			block.thinkingLines += 1
			self.writeLine(prefix + self.style(harnessTerminalDim, "  │ "+HarnessSanitizeLine(line)))
		} else {
			block.foldedLines += 1
		}
		return
	}
	self.writeLine(prefix + self.markdownLineWithLock(line))
}

// Ends a block on its whole text, final: what streamed completed with what a dropped update left out, or, where the
// streamed text is no prefix of it, the whole text again after a note; a thinking block's fold noted.
func (self *HarnessTerminalRenderer) endBlockWithLock(prefix string, block *harnessTerminalBlock, final string) {
	streamed := block.text.String()
	switch {
	case strings.HasPrefix(final, streamed):
		block.text.WriteString(final[len(streamed):])
	case final != "":
		// an update was lost in the middle, and what printed cannot be mended
		self.noteWithLock(prefix, "(the whole of it, since an update was lost:)")
		block.text.Reset()
		block.text.WriteString(final)
		block.printed = 0
		block.thinkingLines, block.foldedLines = 0, 0
	}
	self.flushWithLock(prefix, block, true)
	block.ended = true
	if block.kind == HarnessPiBlockThinking && 0 < block.foldedLines {
		self.noteWithLock(prefix, fmt.Sprintf("  … %d more lines of thinking, folded", block.foldedLines))
	}
}

// message_end: an assistant's blocks completed from the authoritative message, then its status line; the person's or
// another view's prompt; a custom message the run displays; a summary's note. A tool result's message prints nothing,
// its card having shown it.
func (self *HarnessTerminalRenderer) messageEndWithLock(ctx context.Context, prefix string, message *HarnessPiMessage) {
	if message == nil {
		return
	}
	switch message.Role() {
	case HarnessPiRoleAssistant:
		for index, piBlock := range message.Blocks() {
			kind := piBlock.Type()
			if kind != HarnessPiBlockText && kind != HarnessPiBlockThinking {
				continue
			}
			block := self.blockWithLock(prefix, index, kind)
			if !block.ended {
				self.endBlockWithLock(prefix, block, piBlock.Text())
			}
		}
		self.blocks = map[int]*harnessTerminalBlock{}
		self.fence = ""
		if stopReason := message.StopReason(); stopReason == HarnessPiStopError || stopReason == HarnessPiStopAborted {
			errorMessage := ""
			json.Unmarshal(message.Field("errorMessage"), &errorMessage)
			self.noteWithLock(prefix, strings.TrimSuffix("the answer ended: "+stopReason+": "+errorMessage, ": "))
		}
		if model := message.Model(); model != "" && self.status.model == "" {
			self.status.model = model
		}
		self.writeLine(prefix + self.statusLineWithLock(ctx))
	case HarnessPiRoleUser:
		lines := strings.Split(HarnessSanitize(message.Text()), "\n")
		for i, line := range lines {
			lead := "  "
			if i == 0 {
				lead = self.style(harnessTerminalGreen, "› ")
			}
			self.writeLine(prefix + lead + self.style(harnessTerminalBold, line))
		}
		for _, piBlock := range message.Blocks() {
			if data, mimeType := piBlock.Image(); piBlock.Type() == HarnessPiBlockImage {
				self.noteWithLock(prefix, fmt.Sprintf("  [image: %s, %d bytes]", mimeType, len(data)))
			}
		}
	case HarnessPiRoleCustom:
		display := false
		json.Unmarshal(message.Field("display"), &display)
		if display {
			for _, line := range strings.Split(HarnessSanitize(message.Text()), "\n") {
				self.writeLine(prefix + self.style(harnessTerminalDim, line))
			}
		}
	case HarnessPiRoleCompactionSummary, HarnessPiRoleBranchSummary:
		self.noteWithLock(prefix, "(a summary of the context so far stands in for what came before)")
	}
}

// The status line: the model, its badge, the cost meter and the provider's disclosure line from the signed policy.
func (self *HarnessTerminalRenderer) statusLineWithLock(ctx context.Context) string {
	model := self.status.model
	parts := []string{}
	if model != "" {
		parts = append(parts, HarnessSanitizeLine(model))
	}
	parts = append(parts, self.badgeWithLock(),
		harnessTerminalUsd(self.status.chargeNanoUsd)+" this call", harnessTerminalUsd(self.status.runNanoUsd)+" this run",
		self.disclosureLineWithLock(ctx, model))
	return self.style(harnessTerminalDim, "── "+strings.Join(parts, " · "))
}

// The badge for the label the last attestation event named (§7.6): local, none, AP, or a TEE label with its profile.
func (self *HarnessTerminalRenderer) badgeWithLock() string {
	switch self.status.label {
	case ComputeLabelLocal:
		return "on this device"
	case ComputeLabelNone:
		return "not in a TEE: the provider can read this"
	case ComputeLabelAp:
		return "provider trusted"
	case ComputeLabelA1, ComputeLabelA2:
		badge := "TEE"
		if self.status.cpu != "" {
			badge += " " + HarnessSanitizeLine(self.status.cpu)
		}
		if self.status.profile != "" {
			badge += ", profile " + HarnessSanitizeLine(self.status.profile)
		}
		return badge + " (" + self.status.label.Words() + ")"
	case "":
		return "label not shown yet"
	}
	return "label unknown"
}

// The disclosure line of model's provider, inference:<provider>, from the signed policy alone.
func (self *HarnessTerminalRenderer) disclosureLineWithLock(ctx context.Context, model string) string {
	if model == "" {
		return "disclosure: no model yet"
	}
	name, err := InferParseModelName(model, self.inferSettings)
	if err != nil {
		return "disclosure: the model's provider is unknown"
	}
	if self.disclosures == nil {
		return "disclosure: not available here"
	}
	line, err := self.disclosures.Line(ctx, inferDisclosurePrefix+name.Provider)
	if err != nil || line == "" {
		return "disclosure: not available here"
	}
	return HarnessSanitizeLine(line)
}

// An attestation's label, TEE and profile, kept for the next status line (the event's own words for none of it).
func (self *HarnessTerminalRenderer) attestationWithLock(event *HarnessEvent) {
	self.status.label = ComputeLabel(harnessTerminalString(event, "label"))
	if model := harnessTerminalString(event, "model"); model != "" {
		self.status.model = model
	}
	self.status.cpu, self.status.profile = "", ""
	result := struct {
		Cpu       string `json:"cpu"`
		ProfileId string `json:"profileId"`
	}{}
	if event.Decode("result", &result) {
		self.status.cpu, self.status.profile = result.Cpu, result.ProfileId
	}
}

// nano-USD as dollars: to the micro-dollar, at least two decimals.
func harnessTerminalUsd(nanoUsd uint64) string {
	micro := (nanoUsd + 500) / 1000
	text := fmt.Sprintf("%d.%06d", micro/1000000, micro%1000000)
	for strings.HasSuffix(text, "0") && strings.Index(text, ".")+3 < len(text) {
		text = strings.TrimSuffix(text, "0")
	}
	return "$" + text
}

// A one-line summary of a tool call's arguments: the path, pattern, command, URL, query, agent or name it names, else
// its compact JSON, cut at TerminalSummaryCharCount.
func (self *HarnessTerminalRenderer) argsSummary(args json.RawMessage) string {
	if self.settings.TerminalSummaryCharCount <= 0 || len(args) == 0 {
		return ""
	}
	object := map[string]json.RawMessage{}
	summary := ""
	if json.Unmarshal(args, &object) == nil {
		for _, name := range []string{"path", "pattern", "command", "url", "query", "agent", "name"} {
			value := ""
			if json.Unmarshal(object[name], &value) == nil && value != "" {
				summary = value
				break
			}
		}
	}
	if summary == "" {
		compacted, err := harnessPiCompact(args)
		if err != nil {
			return ""
		}
		summary = string(compacted)
		if summary == "{}" {
			return ""
		}
	}
	return self.style(harnessTerminalDim, harnessTerminalCut(HarnessSanitizeLine(summary), self.settings.TerminalSummaryCharCount))
}

// text cut to at most count characters, an ellipsis ending one that was cut.
func harnessTerminalCut(text string, count int) string {
	if utf8.RuneCountInString(text) <= count {
		return text
	}
	runes := []rune(text)
	return string(runes[:max(0, count-1)]) + "…"
}

// tool_execution_end: the card's end, with the result's diff colored where its details carry one, else its last lines.
func (self *HarnessTerminalRenderer) toolEndWithLock(prefix string, event *HarnessEvent) {
	name := HarnessSanitizeLine(harnessTerminalString(event, "toolName"))
	isError := false
	event.Decode("isError", &isError)
	durationMs := int64(-1)
	event.Decode("durationMs", &durationMs)
	header := self.style(harnessTerminalGreen, "✓ ") + name
	if isError {
		header = self.style(harnessTerminalRed, "✗ ") + name
	}
	if 0 <= durationMs {
		header += self.style(harnessTerminalDim, fmt.Sprintf(" · %d ms", durationMs))
	}
	self.writeLine(prefix + header)
	result := struct {
		Content []*HarnessPiBlock `json:"content"`
		Details json.RawMessage   `json:"details"`
	}{}
	event.Decode("result", &result)
	details := struct {
		Diff string `json:"diff"`
	}{}
	if json.Unmarshal(result.Details, &details) == nil && details.Diff != "" {
		self.diffWithLock(prefix, details.Diff)
		return
	}
	texts := []string{}
	for _, block := range result.Content {
		switch block.Type() {
		case HarnessPiBlockText:
			texts = append(texts, block.Text())
		case HarnessPiBlockImage:
			// an image is a note, never an inline-image escape
			data, mimeType := block.Image()
			texts = append(texts, fmt.Sprintf("[image: %s, %d bytes]", mimeType, len(data)))
		}
	}
	lines := strings.Split(strings.TrimRight(HarnessSanitize(strings.Join(texts, "\n")), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return
	}
	shown := lines
	if count := self.settings.TerminalToolOutputLineCount; count < len(lines) {
		shown = lines[len(lines)-max(0, count):]
		if 0 < count {
			self.noteWithLock(prefix, fmt.Sprintf("  │ … %d lines before", len(lines)-len(shown)))
		}
	}
	for _, line := range shown {
		self.writeLine(prefix + self.style(harnessTerminalDim, "  │ "+line))
	}
}

// A diff's lines, - red and + green, at most TerminalDiffLineCount of them.
func (self *HarnessTerminalRenderer) diffWithLock(prefix string, diff string) {
	lines := strings.Split(HarnessSanitize(diff), "\n")
	for i, line := range lines {
		if self.settings.TerminalDiffLineCount <= i {
			self.noteWithLock(prefix, fmt.Sprintf("  … %d more lines of the diff", len(lines)-i))
			return
		}
		switch {
		case strings.HasPrefix(line, "+"):
			self.writeLine(prefix + "  " + self.style(harnessTerminalGreen, line))
		case strings.HasPrefix(line, "-"):
			self.writeLine(prefix + "  " + self.style(harnessTerminalRed, line))
		case strings.HasPrefix(line, "@@"):
			self.writeLine(prefix + "  " + self.style(harnessTerminalCyan, line))
		default:
			self.writeLine(prefix + "  " + self.style(harnessTerminalDim, line))
		}
	}
}

// compaction_end's note: the tokens before and after, or why it failed.
func (self *HarnessTerminalRenderer) compactionEndWithLock(prefix string, event *HarnessEvent) {
	result := struct {
		TokensBefore         int64 `json:"tokensBefore"`
		EstimatedTokensAfter int64 `json:"estimatedTokensAfter"`
	}{}
	if event.Decode("result", &result) {
		self.noteWithLock(prefix, fmt.Sprintf("compacted: %d tokens to about %d", result.TokensBefore, result.EstimatedTokensAfter))
		return
	}
	self.noteWithLock(prefix, "compaction did not finish: "+harnessTerminalString(event, "errorMessage"))
}

// approval_pending's card: the action's canonical text as this device's daemon built it, and where the person decides.
// It never offers an answer here: a decision comes from another approval-capable device, a presence key or ur
// approve's own confirmation (DESIGN §16.6), never from a line typed to the run.
func (self *HarnessTerminalRenderer) approvalPendingWithLock(prefix string, event *HarnessEvent) {
	kind, text, approvalId := harnessTerminalString(event, "kind"), harnessTerminalString(event, "text"),
		harnessTerminalString(event, "approvalId")
	self.writeLine(prefix + self.style(harnessTerminalYellow, "⏸ approval needed") + " (" + HarnessSanitizeLine(kind) + ")")
	for _, line := range strings.Split(HarnessSanitize(text), "\n") {
		self.writeLine(prefix + "  " + line)
	}
	evidence := []string{}
	event.Decode("evidence", &evidence)
	self.noteWithLock(prefix, fmt.Sprintf("  decide on another of your devices, with a presence key, or with ur approve %s (by %s)",
		approvalId, strings.Join(evidence, ", ")))
}

// approval_resolved's note; an automatic decision as the device's check's, never the person's (§27.9).
func (self *HarnessTerminalRenderer) approvalResolvedWithLock(prefix string, event *HarnessEvent) {
	state := harnessTerminalString(event, "state")
	if event.Field("auto") != nil {
		self.noteWithLock(prefix, "✓ "+HarnessAutomaticDecisionNote)
		return
	}
	self.noteWithLock(prefix, "approval "+state)
}

// A ui_request's question, kept until its answer: a select's numbered options, a confirm's y or n, an input's text, a
// connect told to the app, and a disclosure's whole text from the signed policy for its id and version.
func (self *HarnessTerminalRenderer) uiRequestWithLock(ctx context.Context, prefix string, event *HarnessEvent) {
	request := event.UiRequest()
	if request == nil || request.Id == "" {
		return
	}
	if slices.ContainsFunc(self.dialogs, func(dialog *HarnessUiRequest) bool { return dialog.Id == request.Id }) {
		return
	}
	if request.Method == HarnessUiDisclosure {
		// a disclosure's request carries its id and version and nothing the renderer shows (D-HARN-10)
		request = &HarnessUiRequest{Id: request.Id, Method: HarnessUiDisclosure, DisclosureId: request.DisclosureId,
			DisclosureVersion: request.DisclosureVersion}
	}
	question := self.style(harnessTerminalYellow, "? ")
	switch request.Method {
	case HarnessUiSelect:
		self.writeLine(prefix + question + HarnessSanitizeLine(request.Title))
		for i, option := range request.Options {
			self.writeLine(prefix + fmt.Sprintf("  %d. %s", i+1, HarnessSanitizeLine(option)))
		}
		self.noteWithLock(prefix, "  answer with an option's number, or an empty line to cancel")
	case HarnessUiConfirm:
		text := HarnessSanitizeLine(request.Title)
		if request.Message != "" {
			text += ": " + HarnessSanitizeLine(request.Message)
		}
		self.writeLine(prefix + question + text + " [y/N]")
	case HarnessUiInput:
		text := HarnessSanitizeLine(request.Title)
		if request.Placeholder != "" {
			text += " (" + HarnessSanitizeLine(request.Placeholder) + ")"
		}
		self.writeLine(prefix + question + text)
	case HarnessUiConnect:
		self.writeLine(prefix + question + "an agent asks to connect a service or use a connection on this device: answer in the app")
	case HarnessUiDisclosure:
		self.disclosurePromptWithLock(ctx, prefix, request)
	default:
		return
	}
	self.dialogs = append(self.dialogs, request)
}

// A disclosure's prompt: the signed policy's whole text for the request's id and version, then how the person
// acknowledges it. Where the text cannot be read, it says so, and the request can only be declined here.
func (self *HarnessTerminalRenderer) disclosurePromptWithLock(ctx context.Context, prefix string, request *HarnessUiRequest) {
	id := HarnessSanitizeLine(request.DisclosureId)
	heading := self.style(harnessTerminalYellow, "? ") + self.style(harnessTerminalBold,
		fmt.Sprintf("before this goes ahead, read disclosure %s, version %d", id, request.DisclosureVersion))
	self.writeLine(prefix + heading)
	text, err := "", ErrHarnessDisclosureTextUnavailable
	if self.disclosures != nil {
		text, err = self.disclosures.Text(ctx, request.DisclosureId, request.DisclosureVersion)
	}
	if err != nil || text == "" {
		self.noteWithLock(prefix, "  its text from the signed policy is not available here, so it cannot be acknowledged "+
			"here: acknowledge it in the app, or answer with an empty line for Not now")
		return
	}
	for _, line := range strings.Split(HarnessSanitize(text), "\n") {
		self.writeLine(prefix + "  " + line)
	}
	self.shownDisclosureIds[request.Id] = true
	self.noteWithLock(prefix, fmt.Sprintf("  type %q to acknowledge it, or anything else for Not now", HarnessDisclosureAcknowledgment))
}

// A ui_response closes its dialog in every view: the one shown here is no longer waiting.
func (self *HarnessTerminalRenderer) uiResponseWithLock(prefix string, event *HarnessEvent) {
	id := harnessTerminalString(event, "id")
	index := slices.IndexFunc(self.dialogs, func(dialog *HarnessUiRequest) bool { return dialog.Id == id })
	if index < 0 {
		return
	}
	self.dialogs = slices.Delete(self.dialogs, index, index+1)
	delete(self.shownDisclosureIds, id)
	acknowledged, cancelled := false, false
	event.Decode("acknowledged", &acknowledged)
	event.Decode("cancelled", &cancelled)
	switch {
	case acknowledged:
		self.noteWithLock(prefix, "  (acknowledged)")
	case cancelled:
		self.noteWithLock(prefix, "  (the dialog closed)")
	default:
		self.noteWithLock(prefix, "  (answered)")
	}
}

// Answers the dialog shown longest ago with line, the person's input read from /dev/tty: a select's option by number
// or by its text, a confirm's y or n, an input's text; for a disclosure, "I understand" acknowledges the version whose
// text was shown, through acker, CTRUST's path, and anything else declines it, Not now. A connect takes no line: the
// person answers in the app. Nil where no dialog waits.
func (self *HarnessTerminalRenderer) Answer(ctx context.Context, line string, acker HarnessDisclosureAcker) *HarnessTerminalAnswer {
	self.renderLock.Lock()
	defer self.renderLock.Unlock()
	if len(self.dialogs) == 0 {
		return nil
	}
	request := self.dialogs[0]
	trimmed := strings.TrimSpace(line)
	answer := &HarnessTerminalAnswer{}
	settle := func(response *HarnessUiResponse) *HarnessTerminalAnswer {
		answer.Response, answer.Done = response, true
		self.dialogs = self.dialogs[1:]
		delete(self.shownDisclosureIds, request.Id)
		return answer
	}
	notice := func(text string) *HarnessTerminalAnswer {
		answer.Notice = text
		self.noteWithLock("", text)
		return answer
	}
	switch request.Method {
	case HarnessUiSelect:
		if trimmed == "" {
			return settle(&HarnessUiResponse{Id: request.Id, Cancelled: true})
		}
		value := ""
		if n, err := strconv.Atoi(trimmed); err == nil && 1 <= n && n <= len(request.Options) {
			value = request.Options[n-1]
		} else if slices.Contains(request.Options, trimmed) {
			value = trimmed
		} else {
			return notice("  answer with one of the option numbers")
		}
		return settle(&HarnessUiResponse{Id: request.Id, Value: &value})
	case HarnessUiConfirm:
		confirmed := strings.EqualFold(trimmed, "y") || strings.EqualFold(trimmed, "yes")
		return settle(&HarnessUiResponse{Id: request.Id, Confirmed: &confirmed})
	case HarnessUiInput:
		value := line
		return settle(&HarnessUiResponse{Id: request.Id, Value: &value})
	case HarnessUiConnect:
		return notice("  a connection is answered in the app, on this device")
	case HarnessUiDisclosure:
		if !strings.EqualFold(trimmed, HarnessDisclosureAcknowledgment) {
			decline := HarnessUiDisclosureDecline
			return settle(&HarnessUiResponse{Id: request.Id, Value: &decline})
		}
		if !self.shownDisclosureIds[request.Id] {
			return notice("  its text was not shown here, so it cannot be acknowledged here: acknowledge it in the app, " +
				"or answer with an empty line for Not now")
		}
		if acker == nil {
			return notice("  this build records no acknowledgment here: acknowledge it in the app, or answer with an " +
				"empty line for Not now")
		}
		if err := acker.Ack(ctx, request.DisclosureId, request.DisclosureVersion); err != nil {
			return notice("  the acknowledgment was not recorded: " + err.Error())
		}
		// the store the request waits on answers it, never a ui_response
		answer.Notice = "  acknowledged"
		self.noteWithLock("", answer.Notice)
		return settle(nil)
	}
	return nil
}

// One line of an assistant's markdown in the renderer's styles, the code fence's state carried across lines.
func (self *HarnessTerminalRenderer) markdownLineWithLock(line string) string {
	line = HarnessSanitizeLine(line)
	trimmed := strings.TrimLeft(line, " ")
	if self.fence != "" {
		if strings.HasPrefix(trimmed, self.fence) {
			self.fence = ""
			return self.style(harnessTerminalDim, "  ──")
		}
		return self.style(harnessTerminalCyan, "    "+line)
	}
	if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
		self.fence = trimmed[:3]
		return self.style(harnessTerminalDim, "  ── "+strings.TrimSpace(trimmed[3:]))
	}
	level := 0
	for level < len(trimmed) && trimmed[level] == '#' {
		level += 1
	}
	switch {
	case 1 <= level && level <= 6 && level < len(trimmed) && trimmed[level] == ' ':
		return self.style(harnessTerminalBold, self.inline(strings.TrimSpace(trimmed[level:])))
	case trimmed == "---" || trimmed == "***" || trimmed == "___":
		return self.style(harnessTerminalDim, "────────")
	case strings.HasPrefix(trimmed, "> ") || trimmed == ">":
		return self.style(harnessTerminalDim, "│ ") + self.inline(strings.TrimPrefix(strings.TrimPrefix(trimmed, ">"), " "))
	case strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") || strings.HasPrefix(trimmed, "+ "):
		indent := line[:len(line)-len(trimmed)]
		return indent + "• " + self.inline(trimmed[2:])
	}
	return self.inline(line)
}

// A markdown link at the start of text, [label](target) or [label](target "title"): its label, its target and the
// bytes it takes, or false.
func harnessMarkdownLink(text string) (string, string, int, bool) {
	if !strings.HasPrefix(text, "[") {
		return "", "", 0, false
	}
	labelEnd := strings.Index(text, "](")
	if labelEnd < 0 || strings.ContainsAny(text[1:labelEnd], "[]") {
		return "", "", 0, false
	}
	rest := text[labelEnd+2:]
	targetEnd := strings.IndexAny(rest, " )")
	if targetEnd < 0 {
		return "", "", 0, false
	}
	target := rest[:targetEnd]
	closeAt := targetEnd
	if rest[targetEnd] == ' ' {
		closeAt = strings.IndexByte(rest[targetEnd:], ')')
		if closeAt < 0 {
			return "", "", 0, false
		}
		closeAt += targetEnd
	}
	return text[1:labelEnd], target, labelEnd + 2 + closeAt + 1, true
}

// The styles in force after a span that reset them.
func (self *HarnessTerminalRenderer) resume(bold bool, italic bool) string {
	if !self.styled {
		return ""
	}
	resumed := harnessTerminalReset
	if bold {
		resumed += harnessTerminalBold
	}
	if italic {
		resumed += harnessTerminalItalic
	}
	return resumed
}

// One line's inline markdown, sanitized already: code spans, links and images, autolinks, and * and ** emphasis.
func (self *HarnessTerminalRenderer) inline(text string) string {
	out := strings.Builder{}
	bold, italic := false, false
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == '`':
			if end := strings.IndexByte(text[i+1:], '`'); 0 <= end {
				out.WriteString(self.style(harnessTerminalCyan, text[i+1:i+1+end]))
				out.WriteString(self.resume(bold, italic))
				i += end + 2
				continue
			}
		case c == '!' && strings.HasPrefix(text[i:], "!["):
			// an image is a link the person may open, never fetched or shown inline
			if label, target, size, ok := harnessMarkdownLink(text[i+1:]); ok {
				out.WriteString(self.link("image: "+label, target))
				out.WriteString(self.resume(bold, italic))
				i += 1 + size
				continue
			}
		case c == '[':
			if label, target, size, ok := harnessMarkdownLink(text[i:]); ok {
				out.WriteString(self.link(label, target))
				out.WriteString(self.resume(bold, italic))
				i += size
				continue
			}
		case c == '<':
			if end := strings.IndexByte(text[i+1:], '>'); 0 < end {
				target := text[i+1 : i+1+end]
				if strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "http://") {
					out.WriteString(self.link(target, target))
					out.WriteString(self.resume(bold, italic))
					i += end + 2
					continue
				}
			}
		case c == '*' && strings.HasPrefix(text[i:], "**"):
			bold = !bold
			out.WriteString(self.resume(bold, italic))
			i += 2
			continue
		case c == '*':
			opens := !italic && i+1 < len(text) && text[i+1] != ' '
			closes := italic && 0 < i && text[i-1] != ' '
			if opens || closes {
				italic = !italic
				out.WriteString(self.resume(bold, italic))
				i += 1
				continue
			}
		}
		out.WriteByte(c)
		i += 1
	}
	if (bold || italic) && self.styled {
		out.WriteString(harnessTerminalReset)
	}
	return out.String()
}

// A link to target with label: an OSC 8 link only where HarnessCheckedUrl passes target and the output is a terminal,
// the URL's host beside the label so the person sees where it goes; else the label and the URL as text, never a link.
func (self *HarnessTerminalRenderer) link(label string, target string) string {
	checked, ok := HarnessCheckedUrl(target, self.settings.TerminalLinkUrlByteCount)
	if !ok || !self.styled {
		if label == target {
			return target
		}
		return label + " (" + target + ")"
	}
	parsed, err := url.Parse(checked)
	if err != nil {
		return label + " (" + target + ")"
	}
	return harnessTerminalLinkOpen + checked + harnessTerminalLinkClose + self.style(harnessTerminalUnderline, label) +
		harnessTerminalLinkOpen + harnessTerminalLinkClose + self.style(harnessTerminalDim, " ("+parsed.Hostname()+")")
}
