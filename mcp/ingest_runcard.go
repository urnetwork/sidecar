//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.10's run-card inputs and cadence as ingest gives them (MCP-M10-02; R-MCP-13, D-MCP-24; RECORD.md 7.4;
// DESIGN-DETAILS 15.2.8 and 15.2.9; QD-900):
//
//	inputs    a run card is the fold of its stream's source entries (search_run_card.go), so ingest hands a card its
//	          inputs through the record: the title in the run's context entries, its first line, at most
//	          ContextTitleByteCount (120 B) after redaction; the agent label, harness, model and its version,
//	          project and branch there too; each tool's name in its tool_call entry; every touched path in its
//	          tool_call or change entry; the user prompts in stage 2 context entries, the first
//	          RunCardPromptByteCount (2 KiB) of them; and the times those entries carry. RunCapture mirrors the same
//	          values, at most RunCardPathCount (256) paths, so a live view of a run shows what its card will fold
//	redacted  each is redacted before it is sealed or kept, the identifier fields as the prose (RECORD.md 6.4: the
//	          daemon redacts prose and identifier fields before it signs, by §16.11's classes), each match a
//	          redaction gap on the run: the title and prompts in place, with §16.7's marker; a model, version,
//	          project, branch, tool name or path whole, as §16.11's redaction row does it, a matching field becoming
//	          [REDACTED:<rule>], then cut on a code point to its field's cap; an agent label the redactor matches, or
//	          the record's grammar refuses, is written as none, so the context entry still seals and the card groups
//	          the run by its agent id (§16.10's group row)
//	cadence   the record log's companion push builds a card at once at a run's first source entry and at the
//	          coverage entry that ends it, and at most every Record.CardInterval while the run gains source entries
//	          (RECORD.md 7.4): RunCardSchedule hears those dues, each with the run's capture as of it, and the build
//	          folds the card from the stream, never from the capture, so the cadence is no input to a card's bytes
//	          (15.2.9). A source is a kind a vault's card folds (IndexRunCardSources)
//
// A due is heard once the run's lock is released, so a schedule may call back into ingest; two events of one run that
// race may hand their dues over out of order, each still a due with its own capture. Time is the Ingest's clock.

package mcp

import (
	"context"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Why a run's card is due (RECORD.md 7.4's cadence).
type RunCardDueReason string

const (
	// The run's first source entry: a build at once.
	RunCardDueStart RunCardDueReason = "start"
	// The run gained source entries since its last due: at most every Record.CardInterval.
	RunCardDueMoved RunCardDueReason = "moved"
	// The coverage entry that ends the run: a build at once.
	RunCardDueEnd RunCardDueReason = "end"
)

// What hears a run's card dues: the record log's companion schedule, which builds the run's card from its stream at
// once on start and end and within its interval on moved (SEARCH-M10-14's record-log card markers). capture is the
// run's inputs as of the due, redacted, a copy the schedule keeps. Called with no lock of ingest's held.
type RunCardSchedule interface {
	RunCardDue(ctx context.Context, networkId sidecar.Id, reason RunCardDueReason, capture *RunCapture)
}

// One due waiting for its run's lock to be released.
type ingestCardDue struct {
	reason  RunCardDueReason
	capture *RunCapture
}

// The kinds a vault's run card folds (RECORD.md 7.4's sources row; sidecar.IndexRunCardSources): what moves a run's card
// here, since ingest writes a run's entries to its vault.
func ingestCardSources() []sidecar.RecordKind {
	return sidecar.IndexRunCardSources(protocol.RepoKind_REPO_KIND_VAULT)
}

// The run card's inputs for a run this process ingests, as of now. The run's lock is held.
func (self *Ingest) captureWithLock(run *ingestRun) *RunCapture {
	state := run.state
	counts := map[string]int{}
	for name, count := range state.ToolCounts {
		counts[name] = count
	}
	return &RunCapture{
		RunId:              run.runId,
		Harness:            state.Harness,
		AgentLabel:         state.AgentLabel,
		Model:              state.Model,
		Project:            state.Project,
		Branch:             state.Branch,
		Title:              state.Title,
		ToolCounts:         counts,
		TouchedPaths:       slices.Clone(state.TouchedPaths),
		Prompts:            state.Prompts,
		StartedMillis:      state.StartedMillis,
		LastActivityMillis: state.LastActivityMillis,
		EndedMillis:        state.EndedMillis,
	}
}

// An identifier field a card reads (a model and its version, a project, a branch, a tool name, a path) as it is sealed
// and kept: whole, as §16.11's redaction row does it, the field becoming its first match's [REDACTED:<rule>] where the
// redactor matches anything in it, each match a redaction gap on the run, then cut on a code point to byteCount; a
// non-positive byteCount cuts nothing, for a path, which has no byte cap of its own (RECORD.md 6.4). The shared form,
// with no HMAC, since these fields project to the team record (RecordProjectForTeam). The run's lock is held.
func (self *Ingest) redactFieldWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, text string, byteCount int64) string {
	if text == "" {
		return ""
	}
	redacted, matches := redactor.RedactField([]byte(text))
	for range matches {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapRedaction)
	}
	if byteCount <= 0 {
		return string(redacted)
	}
	cut, _ := ingestCut(redacted, byteCount)
	return string(cut)
}

// A path a card reads, relative to the run's worktree and redacted as an identifier field is.
func (self *Ingest) cardPathWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, path string) string {
	return self.redactFieldWithLock(ctx, run, redactor, self.relativeToCwd(run.state.Cwd, path), 0)
}

// The agent label a context entry carries: `.ur`'s, but none where the redactor matches it, counting the redaction,
// or where the record's grammar refuses it, which would refuse the whole entry. The run's lock is held.
func (self *Ingest) cardLabelWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, label string) string {
	if label == "" {
		return ""
	}
	if self.redactFieldWithLock(ctx, run, redactor, label, 0) != label {
		return ""
	}
	if sidecar.RecordBodyValidate(sidecar.RecordKindContext, &protocol.ContextBody{Stage: 1, AgentLabel: label}) != nil {
		return ""
	}
	return label
}

// Notes an entry of kind appended for the run: its first source entry is a start due at once; a later one moves the
// run, due at most every CardInterval after its last due. A coverage entry is noteCardEndWithLock's. The run's lock is
// held.
func (self *Ingest) noteCardSourceWithLock(run *ingestRun, kind sidecar.RecordKind) {
	if self.runCards == nil || kind == sidecar.RecordKindCoverage || !slices.Contains(self.cardSources, kind) {
		return
	}
	now := self.clock.Now()
	if !run.state.CardStarted {
		run.state.CardStarted = true
		run.dirty = true
		self.dueCardWithLock(run, RunCardDueStart, now)
		return
	}
	run.cardMoved = true
	if run.cardStop != nil {
		// a moved due is armed, or its tick waits for this lock
		return
	}
	delay := time.UnixMilli(run.cardDueMillis).Add(self.record.CardInterval).Sub(now)
	if delay <= 0 {
		self.dueCardWithLock(run, RunCardDueMoved, now)
		return
	}
	run.cardStop = self.clock.AfterFunc(delay, func() {
		self.cardTick(run)
	})
}

// The coverage entry that ended the run: an end due at once, its moved timer stopped. The run's lock is held.
func (self *Ingest) noteCardEndWithLock(run *ingestRun) {
	self.stopCardWithLock(run)
	if self.runCards == nil {
		return
	}
	if !run.state.CardStarted {
		run.state.CardStarted = true
		run.dirty = true
	}
	self.dueCardWithLock(run, RunCardDueEnd, self.clock.Now())
}

// Stops the run's moved timer. The run's lock is held.
func (self *Ingest) stopCardWithLock(run *ingestRun) {
	if run.cardStop != nil {
		run.cardStop()
		run.cardStop = nil
	}
}

// A due of the run at now, with its capture as of it, handed over once the run's lock is released. The run's lock is
// held.
func (self *Ingest) dueCardWithLock(run *ingestRun, reason RunCardDueReason, now time.Time) {
	run.cardDueMillis = now.UnixMilli()
	run.cardMoved = false
	run.cardDues = append(run.cardDues, &ingestCardDue{reason: reason, capture: self.captureWithLock(run)})
}

// The moved timer: a moved due where the run gained source entries since its last due and has not ended.
func (self *Ingest) cardTick(run *ingestRun) {
	ctx := context.Background()
	defer self.deliverCardDues(ctx, run)
	run.runLock.Lock()
	defer run.runLock.Unlock()
	run.cardStop = nil
	if run.cardMoved && !run.state.Covered {
		self.dueCardWithLock(run, RunCardDueMoved, self.clock.Now())
	}
}

// Hands the run's waiting dues to the schedule, with no lock of ingest's held: what each entry point that appends a
// run's entries defers before it takes the run's lock, so it runs once the lock is released.
func (self *Ingest) deliverCardDues(ctx context.Context, run *ingestRun) {
	if self.runCards == nil || run == nil {
		return
	}
	dues := func() []*ingestCardDue {
		run.runLock.Lock()
		defer run.runLock.Unlock()
		dues := run.cardDues
		run.cardDues = nil
		return dues
	}()
	for _, due := range dues {
		self.runCards.RunCardDue(ctx, run.networkId, due.reason, due.capture)
	}
}
