//go:build !ios_extension && !sidecar_http

// An agent's summaries (DESIGN-COMPUTE §20.6, R-SKILL-3, D-SKILL-2; SKILL-M11-03): summary/<name>.md in its member's
// agents repo, versioned, so its history is the summaries, each the agent's own words through agent_summary, in
// markdown under the sections Completed, In progress, Blocked and Next, at most SkillSettings.SummaryByteCount:
//
//	---
//	source: agent | harness
//	---
//	## Completed
//	...
//
//	source    front matter the writer puts first: agent for the agent's own words, harness for a mechanical one the
//	          Harness wrote after SummaryReminderCount reminders went unanswered (§20.6's "source": "harness"), which a
//	          reader shows as such; the source is the writer's word, its trust the push's (agentsTextTrusted)
//	clock     AgentSummaryClock counts an agent's active work, the time its turns run, and makes a summary due every
//	          skill.summary_minutes of it (SkillSettings.SummaryMinutes, 15, within 5 to 60; Q-SKILL-3, QD-1353), at a
//	          task's end, at session end and on request; at a turn's end a due summary puts a reminder in the agent's
//	          next turn (the Harness's steer), and the next due turn's end past SummaryReminderCount reminders writes a
//	          mechanical summary from AgentSummaryFacts (files touched, commands run, the last user request)
//	facts     HARN's run state fills AgentSummaryFacts (RegisterAgentSummaryFacts); until it does a mechanical summary
//	          says the Harness kept no facts, rather than inventing any
//	read      held to the card's own sidecar as cards are: the newest version that sidecar pushed, every other passed
//	          over and alarmed once a push
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Who wrote a summary's words (§20.6).
type AgentSummarySource string

const (
	// The agent's own words, through agent_summary.
	AgentSummarySourceAgent AgentSummarySource = "agent"
	// A mechanical summary the Harness wrote for an agent that left its reminders unanswered.
	AgentSummarySourceHarness AgentSummarySource = "harness"
)

// The summary directory of an agents repo, a summary's suffix, and its front matter's fence and source key.
const (
	agentSummaryDirectory  = "summary"
	agentSummaryFileSuffix = ".md"
	agentSummaryFence      = "---"
	agentSummarySourceKey  = "source: "
)

// The sections of a summary, in their order (§20.6).
const (
	AgentSummarySectionCompleted  = "Completed"
	AgentSummarySectionInProgress = "In progress"
	AgentSummarySectionBlocked    = "Blocked"
	AgentSummarySectionNext       = "Next"
)

// What a due summary puts in the agent's next turn: fixed by the build, the Harness's own text.
const AgentSummaryReminderText = "A summary of your work is due: call agent_summary with what you completed, what is in progress, " +
	"what is blocked and what is next, under those four headings."

// A summary that does not read: no front matter, a source of neither kind, not UTF-8, or past its bound.
var ErrAgentSummaryInvalid = errors.New("agent summary invalid")

// summary/<name>.md, the summary's path in the agents repo.
func AgentSummaryPath(name AgentName) string {
	return agentSummaryDirectory + "/" + string(name) + agentSummaryFileSuffix
}

// One summary.
type AgentSummary struct {
	Source AgentSummarySource
	// The markdown below the front matter.
	Text string
}

// The summary's bytes: its front matter, then its text, refusing one that would not read back.
func EncodeAgentSummary(summary *AgentSummary, settings *SkillSettings) ([]byte, error) {
	encoded := agentSummaryFence + "\n" + agentSummarySourceKey + string(summary.Source) + "\n" + agentSummaryFence + "\n" +
		strings.TrimRight(summary.Text, "\n") + "\n"
	data := []byte(encoded)
	if _, err := ParseAgentSummary(data, settings); err != nil {
		return nil, err
	}
	return data, nil
}

// One summary's bytes as a reader takes them: see the file header.
func ParseAgentSummary(data []byte, settings *SkillSettings) (*AgentSummary, error) {
	if settings.SummaryByteCount < len(data) {
		return nil, fmt.Errorf("%w: past %d bytes", ErrAgentSummaryInvalid, settings.SummaryByteCount)
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, fmt.Errorf("%w: not UTF-8 text", ErrAgentSummaryInvalid)
	}
	lines := strings.SplitN(string(data), "\n", 4)
	if len(lines) < 4 || lines[0] != agentSummaryFence || lines[2] != agentSummaryFence {
		return nil, fmt.Errorf("%w: no front matter", ErrAgentSummaryInvalid)
	}
	source, found := strings.CutPrefix(lines[1], agentSummarySourceKey)
	summary := &AgentSummary{Source: AgentSummarySource(source), Text: strings.TrimRight(lines[3], "\n")}
	if !found || (summary.Source != AgentSummarySourceAgent && summary.Source != AgentSummarySourceHarness) {
		return nil, fmt.Errorf("%w: source", ErrAgentSummaryInvalid)
	}
	return summary, nil
}

// A summary's markdown from its four sections, each a list of lines, a section with none saying so.
func AgentSummaryMarkdown(completed []string, inProgress []string, blocked []string, next []string) string {
	builder := strings.Builder{}
	for i, section := range []struct {
		heading string
		lines   []string
	}{
		{heading: AgentSummarySectionCompleted, lines: completed},
		{heading: AgentSummarySectionInProgress, lines: inProgress},
		{heading: AgentSummarySectionBlocked, lines: blocked},
		{heading: AgentSummarySectionNext, lines: next},
	} {
		if 0 < i {
			builder.WriteString("\n")
		}
		builder.WriteString("## " + section.heading + "\n")
		if len(section.lines) == 0 {
			builder.WriteString("- none\n")
			continue
		}
		for _, line := range section.lines {
			builder.WriteString("- " + strings.ReplaceAll(line, "\n", " ") + "\n")
		}
	}
	return builder.String()
}

// What one summary write asks.
type AgentSummaryWrite struct {
	Name    AgentName
	Summary *AgentSummary
	// The run's tainted bit, which the push's sealed provenance carries.
	Tainted bool
}

// Writes summary/<name>.md as a new version (see the file header): ErrAgentCardAbsent where no unretired card stands at
// the name, ErrAgentsNotWriter where it is another sidecar's agent. An agent's own summary resets its summary clock.
func (self *AgentsClient) WriteSummary(ctx context.Context, write *AgentSummaryWrite) error {
	if write == nil || write.Summary == nil {
		return fmt.Errorf("%w: a summary write", errInvalidSettings)
	}
	place, err := self.placeWithRepo()
	if err != nil {
		return err
	}
	read, err := self.ownCard(ctx, place, write.Name)
	if err != nil {
		return err
	}
	data, err := EncodeAgentSummary(write.Summary, self.settings)
	if err != nil {
		return err
	}
	agentId := read.Card.AgentId
	_, err = place.agentsRepo.WritePaths(ctx, &EvsWritePathsArgs{
		Writes:  []*EvsPathWrite{{Path: AgentSummaryPath(write.Name), Content: bytes.NewReader(data)}},
		AgentId: &agentId,
		Tainted: write.Tainted,
	})
	if err != nil {
		return err
	}
	agentsHarnessTurnHook.summaryWritten(agentId)
	return nil
}

// One summary path as a reader judged it.
type AgentSummaryRead struct {
	// The newest summary its writer pushed, nil for none.
	Summary *AgentSummary
	Version uint64
	Time    time.Time
	// The signer, its provenance and whether the text is trusted on IC-12's terms.
	WriterSidecarId Id
	Provenance      *EvsPushProvenance
	Trusted         bool
	// The versions passed over, newest first.
	PassedOver []uint64
}

// The newest summary of card's agent its writer pushed, each version passed over before it alarmed through alarm.
func agentsReadSummary(ctx context.Context, repo AgentsRepoAccess, authority AgentsAuthority, memberId Id, card *AgentCard,
	settings *SkillSettings, alarm func(version *EvsHistoryVersion)) (*AgentSummaryRead, error) {
	read := &AgentSummaryRead{}
	if card == nil || card.Person() {
		return read, nil
	}
	path := AgentSummaryPath(card.Name)
	history, err := repo.History(ctx, &EvsReadArgs{Path: path})
	if errors.Is(err, ErrEvsPathAbsent) {
		return read, nil
	}
	if err != nil {
		return nil, err
	}
	passOver := func(version *EvsHistoryVersion) {
		read.PassedOver = append(read.PassedOver, version.Version)
		if alarm != nil {
			alarm(version)
		}
	}
	for i, version := range history.Versions {
		if settings.SummaryHistoryMaxCount <= i {
			break
		}
		if version.Removed || version.Ignored || !agentCardWriter(authority, memberId, card, version.SignerSidecarId) {
			passOver(version)
			continue
		}
		buffer := &agentCardBuffer{maxByteCount: settings.SummaryByteCount}
		info, err := repo.ReadHead(ctx, &EvsReadArgs{Path: path, Version: version.Version, Provenance: true}, buffer)
		if errors.Is(err, errAgentCardOversize) {
			passOver(version)
			continue
		}
		if err != nil {
			return nil, err
		}
		summary, err := ParseAgentSummary(buffer.data, settings)
		if err != nil {
			passOver(version)
			continue
		}
		read.Summary, read.Version, read.Time, read.WriterSidecarId = summary, version.Version, version.Time, version.SignerSidecarId
		if info != nil {
			read.Provenance = info.Provenance
		}
		read.Trusted = agentsTextTrusted(authority, memberId, version.SignerSidecarId, read.Provenance)
		return read, nil
	}
	return read, nil
}

// The newest summary of the agent at name, held to its writer.
func (self *AgentsClient) Summary(ctx context.Context, name AgentName) (*AgentSummaryRead, error) {
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	card, err := self.readCard(ctx, place, name)
	if err != nil {
		return nil, err
	}
	if card.Card == nil {
		return nil, fmt.Errorf("%w: %s", ErrAgentCardAbsent, name)
	}
	return agentsReadSummary(ctx, place.agentsRepo, place.authority, place.memberId, card.Card, self.settings,
		func(version *EvsHistoryVersion) { self.alarm(place.agentsRepoId, version) })
}

// What a mechanical summary is made from (§20.6): HARN's run state of the agent's run.
type AgentSummaryFacts interface {
	SummaryFacts(agentId Id, runId Id) (*AgentSummaryFactSet, error)
}

// One run's facts, newest last.
type AgentSummaryFactSet struct {
	FilesTouched    []string
	CommandsRun     []string
	LastUserRequest string
}

// The facts source HARN registers, nil until it does.
var agentsSummaryFacts = struct {
	stateLock sync.Mutex
	facts     AgentSummaryFacts
}{}

// Sets where mechanical summaries read their facts: HARN's run state. Nil removes it.
func RegisterAgentSummaryFacts(facts AgentSummaryFacts) {
	agentsSummaryFacts.stateLock.Lock()
	defer agentsSummaryFacts.stateLock.Unlock()
	agentsSummaryFacts.facts = facts
}

// The registered facts of a run, nil where none is registered or it answers none.
func agentsRunSummaryFacts(agentId Id, runId Id) *AgentSummaryFactSet {
	facts := func() AgentSummaryFacts {
		agentsSummaryFacts.stateLock.Lock()
		defer agentsSummaryFacts.stateLock.Unlock()
		return agentsSummaryFacts.facts
	}()
	if facts == nil {
		return nil
	}
	set, err := facts.SummaryFacts(agentId, runId)
	if err != nil {
		return nil
	}
	return set
}

// What a turn's end asks of the agent's summary.
type AgentSummaryOutcome struct {
	// A summary is due: put a reminder in the agent's next turn.
	Remind bool
	// SummaryReminderCount reminders went unanswered: write a mechanical summary now.
	Mechanical bool
}

// skill.summary_minutes as a cadence: minutes within SummaryMinutesMin to SummaryMinutesMax, a value outside them held
// to the nearer bound, and 0 the default.
func AgentSummaryInterval(minutes int, settings *SkillSettings) time.Duration {
	if minutes == 0 {
		minutes = settings.SummaryMinutes
	}
	minutes = min(max(minutes, settings.SummaryMinutesMin), settings.SummaryMinutesMax)
	return time.Duration(minutes) * time.Minute
}

// One agent's summary cadence: see the file header.
type AgentSummaryClock struct {
	settings *SkillSettings
	interval time.Duration

	stateLock sync.Mutex
	// when the running turn started, zero between turns
	turnStart time.Time
	// active work since the last summary
	active time.Duration
	due    bool
	// reminders put in since the last summary
	reminders int
}

// A clock for skill.summary_minutes minutes (AgentSummaryInterval), no work counted yet.
func NewAgentSummaryClock(settings *SkillSettings, minutes int) *AgentSummaryClock {
	return &AgentSummaryClock{settings: settings, interval: AgentSummaryInterval(minutes, settings)}
}

// The cadence in force.
func (self *AgentSummaryClock) Interval() time.Duration {
	return self.interval
}

// A turn starts at now: its time counts as active work.
func (self *AgentSummaryClock) TurnStart(now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.turnStart = now
}

// A turn ends at now: its time is counted, and a summary due asks for a reminder, or past SummaryReminderCount
// reminders for a mechanical summary, which starts the cadence again.
func (self *AgentSummaryClock) TurnEnd(now time.Time) AgentSummaryOutcome {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.turnStart.IsZero() && now.After(self.turnStart) {
		self.active += now.Sub(self.turnStart)
	}
	self.turnStart = time.Time{}
	if self.interval <= self.active {
		self.due = true
	}
	if !self.due {
		return AgentSummaryOutcome{}
	}
	if self.reminders < self.settings.SummaryReminderCount {
		self.reminders += 1
		return AgentSummaryOutcome{Remind: true}
	}
	self.resetWithLock()
	return AgentSummaryOutcome{Mechanical: true}
}

// A summary is due at the next turn's end: a task ended, the session ends, or the person asked for one.
func (self *AgentSummaryClock) Due() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.due = true
}

// The agent wrote its summary: the cadence starts again.
func (self *AgentSummaryClock) Written() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.resetWithLock()
}

// Starts the cadence again.
func (self *AgentSummaryClock) resetWithLock() {
	self.active, self.due, self.reminders = 0, false, 0
}

// The active work counted and the reminders put in since the last summary.
func (self *AgentSummaryClock) State() (time.Duration, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.active, self.reminders
}

// A mechanical summary from facts, marked source harness: the files touched and commands run, the newest
// SummaryFactCount of each, and the last user request; nil facts say the Harness kept none.
func (self *AgentSummaryClock) MechanicalSummary(facts *AgentSummaryFactSet) *AgentSummary {
	newest := func(values []string) []string {
		if self.settings.SummaryFactCount < len(values) {
			values = values[len(values)-self.settings.SummaryFactCount:]
		}
		lines := []string{}
		for _, value := range values {
			lines = append(lines, AgentStatusText(value, self.settings.CardFieldMaxByteCount))
		}
		return lines
	}
	completed, inProgress := []string{}, []string{}
	if facts == nil {
		completed = append(completed, "the Harness kept no facts of this run")
	} else {
		for _, file := range newest(facts.FilesTouched) {
			completed = append(completed, "touched "+file)
		}
		for _, command := range newest(facts.CommandsRun) {
			completed = append(completed, "ran "+command)
		}
		if facts.LastUserRequest != "" {
			inProgress = append(inProgress, "the last request: "+AgentStatusText(facts.LastUserRequest, self.settings.StatusTaskCharCount))
		}
	}
	summary := &AgentSummary{Source: AgentSummarySourceHarness, Text: AgentSummaryMarkdown(completed, inProgress, nil, nil)}
	// held to the bound: the newest facts kept, the list cut from the front until it fits
	for len(summary.Text)+len(agentSummaryFence)*2+len(agentSummarySourceKey)+16 > self.settings.SummaryByteCount && 1 < len(completed) {
		completed = completed[1:]
		summary.Text = AgentSummaryMarkdown(completed, inProgress, nil, nil)
	}
	return summary
}

// The agent's own summary reset its clock, where the turn hook holds one.
func (self *agentsTurnHook) summaryWritten(agentId Id) {
	self.stateLock.Lock()
	entry := self.agentIdClocks[agentId]
	self.stateLock.Unlock()
	if entry != nil {
		entry.clock.Written()
	}
}
