//go:build !ios_extension && !sidecar_http

// An agent's live status (DESIGN-COMPUTE §20.6, R-SKILL-6, D-SKILL-2; SKILL-M11-03): status/<name>.json in its
// member's agents repo, versionless (DESIGN §11.7), so only the newest stands, written mechanically with no model call:
//
//	{"state": "working|waiting|idle|blocked|offline", "activity": "<= 200 chars", "task": "<= 120 chars",
//	 "updated": "<RFC 3339, UTC>", "run_id": "<32 hex>" | ""}
//
//	write     AgentsClient.WriteStatus, by the card's own sidecar alone (agentsReaderCheck's writer), its push sealing
//	          the agent's id and the run's tainted bit; EvsWriteOptions{Versioning: off}, which format 2's gate makes
//	          versionless and which outside the gate keeps every version. A write that loses a versionless race
//	          (ErrEvsVersionlessConflict) is never written again over the winner: the next note writes anew
//	when      AgentStatusWriter, one a network, whose goroutine writes a noted status at most once a
//	          SkillSettings.StatusMinInterval, the newest note winning, and while a run stays open writes its last
//	          status again every StatusRefreshInterval, so a reader tells an idle agent from a gone one. Notes come
//	          from the Harness's turn hooks (a turn's start and end, a tool call past HarnessSettings.ToolCallSlowAfter)
//	          and from ur hook (mcp/hook.go: SessionStart, PreToolUse, Stop), and return at once: no hook waits on a
//	          write
//	read      held to the card's own sidecar as cards are (agentsReaderCheck): the newest version that sidecar
//	          pushed, every other passed over and alarmed once a push; a status older than SkillSettings.OfflineAfter
//	          reads offline, the clearly intended reading of "whose sidecar holds no live client", since no reader sees
//	          another sidecar's clients; its age is the push's time, never the writer's updated
//	trust     the text is trusted only on IC-12's terms (agentsTextTrusted, agents_stub.go); any other writer's reaches
//	          a model only as an AgentStub
//
// The Harness reaches a writer through its turn hook, registered here: every live writer of the process is noted, and
// only the one whose network holds the agent's card writes, the others' writes refused and the agent left alone there.
// The person's me card carries no status: it is the member's, and no run writes it.
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// What a status says an agent is doing (§20.6).
type AgentState string

const (
	AgentStateWorking AgentState = "working"
	AgentStateWaiting AgentState = "waiting"
	AgentStateIdle    AgentState = "idle"
	AgentStateBlocked AgentState = "blocked"
	AgentStateOffline AgentState = "offline"
)

// The status directory of an agents repo (§20.4's layout).
const agentStatusDirectory = "status"

// A status that does not read: a field out of its grammar or bound, or bytes that are no object. It names the field,
// never its value.
var ErrAgentStatusInvalid = errors.New("agent status invalid")

// The turn hook's name (RegisterHarnessTurnHook).
const agentsTurnHookName = "agents"

// The barriers around a status write, keyed by the agents repo's id.
const (
	agentsStatusWriteBefore = "agents_status.write.before"
	agentsStatusWriteAfter  = "agents_status.write.after"
)

// Whether state is one of §20.6's.
func (self AgentState) valid() bool {
	switch self {
	case AgentStateWorking, AgentStateWaiting, AgentStateIdle, AgentStateBlocked, AgentStateOffline:
		return true
	}
	return false
}

// One status, as §20.6 writes it.
type AgentStatus struct {
	State    AgentState
	Activity string
	Task     string
	// The writer's word for when: a reader ages a status by its push's time.
	Updated time.Time
	// The run the status is of, zero for none.
	RunId Id
}

// The status as its file's bytes, in §20.6's field order.
type agentStatusWire struct {
	State    string `json:"state"`
	Activity string `json:"activity"`
	Task     string `json:"task"`
	Updated  string `json:"updated"`
	RunId    string `json:"run_id"`
}

// A status's free text: UTF-8 within maxCharCount characters, no control character.
func checkAgentStatusText(text string, field string, maxCharCount int) error {
	if !utf8.ValidString(text) {
		return fmt.Errorf("%w: %s is not UTF-8", ErrAgentStatusInvalid, field)
	}
	if maxCharCount < utf8.RuneCountInString(text) {
		return fmt.Errorf("%w: %s is past %d characters", ErrAgentStatusInvalid, field, maxCharCount)
	}
	for _, r := range text {
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 {
			return fmt.Errorf("%w: %s holds a control character", ErrAgentStatusInvalid, field)
		}
	}
	return nil
}

// text cut to maxCharCount characters at a character's edge, its control characters made spaces: what a writer puts
// in a status from words it did not choose, such as a task or a tool's name.
func AgentStatusText(text string, maxCharCount int) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, text)
	cleaned = strings.TrimSpace(cleaned)
	if utf8.RuneCountInString(cleaned) <= maxCharCount {
		return cleaned
	}
	runes := []rune(cleaned)
	return strings.TrimSpace(string(runes[:max(maxCharCount, 0)]))
}

// text as a card's free field from words its writer did not choose, such as a harness's or model's name: each byte
// outside printable ASCII dropped, cut to SkillSettings.CardFieldMaxByteCount.
func AgentCardFieldText(text string, settings *SkillSettings) string {
	kept := make([]byte, 0, min(len(text), settings.CardFieldMaxByteCount))
	for i := 0; i < len(text) && len(kept) < settings.CardFieldMaxByteCount; i += 1 {
		if 0x20 <= text[i] && text[i] <= 0x7e {
			kept = append(kept, text[i])
		}
	}
	return strings.TrimSpace(string(kept))
}

// The status's bytes, refusing one that would not read back.
func EncodeAgentStatus(status *AgentStatus, settings *SkillSettings) ([]byte, error) {
	wire := &agentStatusWire{
		State:    string(status.State),
		Activity: status.Activity,
		Task:     status.Task,
		Updated:  agentCardTimeText(status.Updated),
		RunId:    agentCardIdText(status.RunId),
	}
	encoded := bytes.Buffer{}
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(wire); err != nil {
		return nil, err
	}
	data := encoded.Bytes()
	if _, err := ParseAgentStatus(data, settings); err != nil {
		return nil, err
	}
	return data, nil
}

// One status's bytes as a reader takes them: the state one of §20.6's, each text within its bound, the run 32 hex
// digits or none. Fields a later release adds are passed over.
func ParseAgentStatus(data []byte, settings *SkillSettings) (*AgentStatus, error) {
	if settings.StatusMaxByteCount < len(data) {
		return nil, fmt.Errorf("%w: past %d bytes", ErrAgentStatusInvalid, settings.StatusMaxByteCount)
	}
	wire := &agentStatusWire{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(wire); err != nil {
		return nil, fmt.Errorf("%w: not one JSON object", ErrAgentStatusInvalid)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: bytes past the object", ErrAgentStatusInvalid)
	}
	status := &AgentStatus{State: AgentState(wire.State), Activity: wire.Activity, Task: wire.Task}
	if !status.State.valid() {
		return nil, fmt.Errorf("%w: state", ErrAgentStatusInvalid)
	}
	if err := checkAgentStatusText(status.Activity, "activity", settings.StatusActivityCharCount); err != nil {
		return nil, err
	}
	if err := checkAgentStatusText(status.Task, "task", settings.StatusTaskCharCount); err != nil {
		return nil, err
	}
	var err error
	if status.Updated, err = parseAgentCardTime(wire.Updated, "updated", false); err != nil {
		return nil, fmt.Errorf("%w: updated", ErrAgentStatusInvalid)
	}
	if status.RunId, err = parseAgentCardId(wire.RunId, "run_id", true); err != nil {
		return nil, fmt.Errorf("%w: run_id", ErrAgentStatusInvalid)
	}
	return status, nil
}

// What one status write asks.
type AgentStatusWrite struct {
	Name   AgentName
	Status *AgentStatus
	// The run's tainted bit, which the push's sealed provenance carries (EvsWritePathsArgs.Tainted).
	Tainted bool
}

// The card a status or summary write is made for: standing, unretired and this sidecar's own agent's, never the
// person's me.
func (self *AgentsClient) ownCard(ctx context.Context, place *agentsPlace, name AgentName) (*AgentCardRead, error) {
	read, err := self.readCard(ctx, place, name)
	if err != nil {
		return nil, err
	}
	if read.Card == nil || read.Card.IsRetired() {
		return nil, fmt.Errorf("%w: %s", ErrAgentCardAbsent, name)
	}
	if read.Card.Person() || read.Card.SidecarId != place.sidecarId {
		return nil, fmt.Errorf("%w: %s is another sidecar's agent", ErrAgentsNotWriter, name)
	}
	return read, nil
}

// Writes status/<name>.json once (see the file header): ErrAgentCardAbsent where no unretired card stands at the name,
// ErrAgentsNotWriter where it is another sidecar's agent, and an error wrapping ErrEvsVersionlessConflict where another
// write landed first, which the caller never writes again over.
func (self *AgentsClient) WriteStatus(ctx context.Context, write *AgentStatusWrite) error {
	if write == nil || write.Status == nil {
		return fmt.Errorf("%w: a status write", errInvalidSettings)
	}
	place, err := self.placeWithRepo()
	if err != nil {
		return err
	}
	read, err := self.ownCard(ctx, place, write.Name)
	if err != nil {
		return err
	}
	data, err := EncodeAgentStatus(write.Status, self.settings)
	if err != nil {
		return err
	}
	agentId := read.Card.AgentId
	key := place.agentsRepoId.String()
	testHookBarrier(agentsStatusWriteBefore, key)
	_, err = place.agentsRepo.WritePaths(ctx, &EvsWritePathsArgs{
		Writes: []*EvsPathWrite{{
			Path:    agentStatusPath(write.Name),
			Content: bytes.NewReader(data),
			Options: &EvsWriteOptions{Versioning: EvsVersioningOff},
		}},
		AgentId: &agentId,
		Tainted: write.Tainted,
	})
	testHookBarrier(agentsStatusWriteAfter, key)
	if agentsWriteConflict(err) && !errors.Is(err, ErrEvsVersionlessConflict) {
		// another write of the path landed between the plan's read and the push: lost, as a versionless race is
		return fmt.Errorf("%w: %w", ErrEvsVersionlessConflict, err)
	}
	return err
}

// One status path as a reader judged it.
type AgentStatusRead struct {
	// The status as written, nil where no version its writer pushed stands.
	Status *AgentStatus
	// What a reader shows: the written state, or offline once the push is older than SkillSettings.OfflineAfter.
	State AgentState
	// The push's time and how long ago it was.
	Time time.Time
	Age  time.Duration
	// The path version taken, its signer and its push's provenance (nil where evs gave none).
	Version         uint64
	WriterSidecarId Id
	Provenance      *EvsPushProvenance
	// Whether the text is trusted on IC-12's terms (agentsTextTrusted).
	Trusted bool
	// The versions passed over, each alarmed once a push, newest first.
	PassedOver []uint64
}

// The status of card's agent in memberId's agents repo: its newest version its writer pushed (see the file header),
// each other version passed over through alarm. A path evs shows nothing of, or whose newest kept version's content evs
// no longer serves, reads as no status.
func agentsReadStatus(ctx context.Context, repo AgentsRepoAccess, authority AgentsAuthority, memberId Id, card *AgentCard,
	settings *SkillSettings, now time.Time, alarm func(version *EvsHistoryVersion)) (*AgentStatusRead, error) {
	read := &AgentStatusRead{}
	if card == nil || card.Person() {
		return read, nil
	}
	path := agentStatusPath(card.Name)
	history, err := repo.History(ctx, &EvsReadArgs{Path: path})
	if errors.Is(err, ErrEvsPathAbsent) {
		return read, nil
	}
	if err != nil {
		return nil, err
	}
	for i, version := range history.Versions {
		if settings.SummaryHistoryMaxCount <= i {
			break
		}
		if version.Removed || version.Ignored || !agentCardWriter(authority, memberId, card, version.SignerSidecarId) {
			read.PassedOver = append(read.PassedOver, version.Version)
			if alarm != nil {
				alarm(version)
			}
			continue
		}
		buffer := &agentCardBuffer{maxByteCount: settings.StatusMaxByteCount}
		info, err := repo.ReadHead(ctx, &EvsReadArgs{Path: path, Version: version.Version, Provenance: true}, buffer)
		if errors.Is(err, ErrEvsPathAbsent) || errors.Is(err, ErrEvsCollected) {
			// a versionless version replaced and collected: its successor was passed over, so none stands
			return read, nil
		}
		if errors.Is(err, errAgentCardOversize) {
			read.PassedOver = append(read.PassedOver, version.Version)
			if alarm != nil {
				alarm(version)
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		status, err := ParseAgentStatus(buffer.data, settings)
		if err != nil {
			read.PassedOver = append(read.PassedOver, version.Version)
			if alarm != nil {
				alarm(version)
			}
			continue
		}
		read.Status, read.State, read.Version, read.WriterSidecarId, read.Time = status, status.State, version.Version, version.SignerSidecarId, version.Time
		if info != nil {
			read.Provenance = info.Provenance
		}
		read.Age = max(now.Sub(version.Time), 0)
		if settings.OfflineAfter <= read.Age {
			read.State = AgentStateOffline
		}
		read.Trusted = agentsTextTrusted(authority, memberId, version.SignerSidecarId, read.Provenance)
		return read, nil
	}
	return read, nil
}

// The status of the agent at name, held to its writer: no status where none stands.
func (self *AgentsClient) Status(ctx context.Context, name AgentName) (*AgentStatusRead, error) {
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
	return agentsReadStatus(ctx, place.agentsRepo, place.authority, place.memberId, card.Card, self.settings, self.clock.Now(),
		func(version *EvsHistoryVersion) { self.alarm(place.agentsRepoId, version) })
}

// What a note of a status says.
type AgentStatusNote struct {
	Name    AgentName
	Status  *AgentStatus
	Tainted bool
	// Where the run's end is heard: the status is written again every StatusRefreshInterval until it closes. Nil
	// refreshes until Release.
	Done <-chan struct{}
	// The registration to make first where the agent has no card, as an external harness's first hook does; nil
	// registers nothing.
	Register *AgentRegisterArgs
	// A mechanical summary to write once the status is (AgentSummaryClock's), nil for none.
	Summary *AgentSummary
}

// One agent's status line as a writer holds it.
type agentStatusLine struct {
	name AgentName
	// the newest note not yet written, and its summary
	pending        *AgentStatus
	pendingTainted bool
	pendingSummary *AgentSummary
	register       *AgentRegisterArgs
	// the last status written, when and with what bit
	last        *AgentStatus
	lastTainted bool
	lastAt      time.Time
	written     bool
	// refreshed while open, until done closes
	open bool
	done <-chan struct{}
	// another network's agent, or one that is not this sidecar's: left alone
	foreign bool
}

// When the line is due a write: a pending note StatusMinInterval after the last write (at once before the first), or an
// open line's refresh StatusRefreshInterval after it. False for none.
func (self *agentStatusLine) dueWithLock(settings *SkillSettings) (time.Time, bool) {
	if self.foreign {
		return time.Time{}, false
	}
	if self.pending != nil || self.pendingSummary != nil {
		if !self.written {
			return time.Time{}, true
		}
		return self.lastAt.Add(settings.StatusMinInterval), true
	}
	if self.open && self.last != nil {
		if self.done != nil {
			select {
			case <-self.done:
				self.open = false
				return time.Time{}, false
			default:
			}
		}
		return self.lastAt.Add(settings.StatusRefreshInterval), true
	}
	return time.Time{}, false
}

// What a writer is made with.
type AgentStatusWriterArgs struct {
	Client *AgentsClient
	// Nil logs nothing.
	Log Logger
	// Called after each write the writer makes, its error nil for one that landed: a test's or a view's. Nil for none.
	Written func(name AgentName, err error)
}

// One network's status writer: see the file header.
type AgentStatusWriter struct {
	client   *AgentsClient
	settings *SkillSettings
	clock    Clock
	log      Logger
	written  func(name AgentName, err error)
	ctx      context.Context
	cancel   context.CancelFunc
	wake     chan struct{}
	done     chan struct{}

	stateLock sync.Mutex
	lines     map[AgentName]*agentStatusLine
}

// The status writer's compute component's name.
const agentsStatusComponentName = "agents-status"

// Registers the writer on every Sidecar of a compute leg, after the agents client it writes through.
func init() {
	registerComputeComponent(agentsStatusComponentName, newSidecarAgentStatus, func(writer *AgentStatusWriter) {
		writer.Close()
	})
}

// The writer of sidecar's agents client.
func newSidecarAgentStatus(sidecar *Sidecar) (*AgentStatusWriter, error) {
	client, err := sidecar.AgentsClient()
	if err != nil {
		return nil, err
	}
	return NewAgentStatusWriter(&AgentStatusWriterArgs{Client: client, Log: sidecar.log})
}

// This Sidecar's status writer, or why it has none: what ur hook notes an external harness's status into.
func (self *Sidecar) AgentStatus() (*AgentStatusWriter, error) {
	return sidecarComputeComponent[AgentStatusWriter](self, agentsStatusComponentName)
}

// The process's live writers, which the Harness's turn hook notes: written as writers start and close.
var agentsStatusWriters = struct {
	stateLock sync.Mutex
	writers   map[*AgentStatusWriter]bool
}{writers: map[*AgentStatusWriter]bool{}}

// A writer over args.Client, its goroutine running until Close.
func NewAgentStatusWriter(args *AgentStatusWriterArgs) (*AgentStatusWriter, error) {
	if args == nil || args.Client == nil {
		return nil, fmt.Errorf("%w: a status writer's client", errInvalidSettings)
	}
	ctx, cancel := context.WithCancel(context.Background())
	writer := &AgentStatusWriter{
		client:   args.Client,
		settings: args.Client.settings,
		clock:    args.Client.clock,
		log:      loggerOrDefault(args.Log),
		written:  args.Written,
		ctx:      ctx,
		cancel:   cancel,
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
		lines:    map[AgentName]*agentStatusLine{},
	}
	func() {
		agentsStatusWriters.stateLock.Lock()
		defer agentsStatusWriters.stateLock.Unlock()
		agentsStatusWriters.writers[writer] = true
	}()
	go writer.run()
	return writer, nil
}

// Ends the writer's goroutine, waiting for it, and takes it out of the turn hook's reach.
func (self *AgentStatusWriter) Close() {
	func() {
		agentsStatusWriters.stateLock.Lock()
		defer agentsStatusWriters.stateLock.Unlock()
		delete(agentsStatusWriters.writers, self)
	}()
	self.cancel()
	<-self.done
}

// The settings the writer's client reads.
func (self *AgentStatusWriter) Settings() *SkillSettings {
	return self.settings
}

// Wakes the goroutine without waiting.
func (self *AgentStatusWriter) signal() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Notes a status, returning at once: the newest note is written once the line is due (see the file header).
func (self *AgentStatusWriter) Note(note *AgentStatusNote) {
	if note == nil || note.Status == nil {
		return
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		line := self.lines[note.Name]
		if line == nil {
			line = &agentStatusLine{name: note.Name}
			self.lines[note.Name] = line
		}
		if line.foreign {
			return
		}
		status := *note.Status
		line.pending, line.pendingTainted = &status, note.Tainted
		if note.Summary != nil {
			line.pendingSummary = note.Summary
		}
		if note.Register != nil && !line.written {
			line.register = note.Register
		}
		line.open, line.done = note.Status.State != AgentStateOffline, note.Done
	}()
	self.signal()
}

// Stops refreshing name's status: its run closed.
func (self *AgentStatusWriter) Release(name AgentName) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if line := self.lines[name]; line != nil {
		line.open = false
	}
}

// One write the goroutine makes, taken from a line under the lock.
type agentStatusJob struct {
	name     AgentName
	status   *AgentStatus
	tainted  bool
	summary  *AgentSummary
	register *AgentRegisterArgs
	refresh  bool
}

// The jobs due at now, and how long until the next one; 0 waits for a note.
func (self *AgentStatusWriter) takeDue(now time.Time) ([]*agentStatusJob, time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	jobs := []*agentStatusJob{}
	next := time.Time{}
	for _, line := range self.lines {
		at, due := line.dueWithLock(self.settings)
		if !due {
			continue
		}
		if now.Before(at) {
			if next.IsZero() || at.Before(next) {
				next = at
			}
			continue
		}
		job := &agentStatusJob{name: line.name, register: line.register}
		switch {
		case line.pending != nil:
			job.status, job.tainted = line.pending, line.pendingTainted
		case line.pendingSummary != nil && line.last != nil:
			job.status, job.tainted = line.last, line.lastTainted
		case line.pendingSummary == nil:
			refreshed := *line.last
			refreshed.Updated = now
			job.status, job.tainted, job.refresh = &refreshed, line.lastTainted, true
		default:
			// a summary with no status written yet: noted with its status, so wait for one
			continue
		}
		job.summary = line.pendingSummary
		line.pending, line.pendingSummary, line.register = nil, nil, nil
		// the line counts as written from the try on, so a failing write waits StatusMinInterval too
		line.lastAt, line.written = now, true
		jobs = append(jobs, job)
	}
	if next.IsZero() {
		return jobs, 0
	}
	return jobs, next.Sub(now)
}

// Records a job's outcome on its line: written, lost to another write, or another network's agent, left alone.
func (self *AgentStatusWriter) settle(job *agentStatusJob, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	line := self.lines[job.name]
	if line == nil {
		return
	}
	switch {
	case err == nil:
		line.last, line.lastTainted = job.status, job.tainted
	case errors.Is(err, ErrAgentCardAbsent), errors.Is(err, ErrAgentsNotWriter), errors.Is(err, ErrAgentsRepoAbsent),
		errors.Is(err, ErrAgentReposOff):
		line.foreign = true
		line.pending, line.pendingSummary = nil, nil
	}
}

// One job: the registration first where the agent has no card, then the status, then a mechanical summary.
func (self *AgentStatusWriter) write(job *agentStatusJob) error {
	ctx := self.ctx
	err := self.client.WriteStatus(ctx, &AgentStatusWrite{Name: job.name, Status: job.status, Tainted: job.tainted})
	if errors.Is(err, ErrAgentCardAbsent) && job.register != nil {
		if _, registerErr := self.client.Register(ctx, job.register); registerErr != nil {
			return registerErr
		}
		err = self.client.WriteStatus(ctx, &AgentStatusWrite{Name: job.name, Status: job.status, Tainted: job.tainted})
	}
	if err != nil {
		return err
	}
	if job.summary != nil {
		return self.client.WriteSummary(ctx, &AgentSummaryWrite{Name: job.name, Summary: job.summary, Tainted: job.tainted})
	}
	return nil
}

// The writer's rounds: each due job written, then a wait for the next due time, a note or Close.
func (self *AgentStatusWriter) run() {
	defer close(self.done)
	for {
		jobs, wait := self.takeDue(self.clock.Now())
		for _, job := range jobs {
			err := self.write(job)
			if err != nil && !errors.Is(err, ErrEvsVersionlessConflict) && self.log.V(1).Enabled() {
				self.log.Infof("[agents]a status was not written: %v", err)
			}
			self.settle(job, err)
			if self.written != nil {
				self.written(job.name, err)
			}
		}
		if self.ctx.Err() != nil {
			return
		}
		if 0 < len(jobs) {
			continue
		}
		stop := func() bool { return false }
		if 0 < wait {
			stop = self.clock.AfterFunc(wait, self.signal)
		}
		select {
		case <-self.ctx.Done():
			stop()
			return
		case <-self.wake:
		}
		stop()
	}
}

// The writer's line of name as it stands: whether it is open and when it last wrote. For tests and views.
func (self *AgentStatusWriter) line(name AgentName) (open bool, lastAt time.Time, found bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	line := self.lines[name]
	if line == nil {
		return false, time.Time{}, false
	}
	return line.open, line.lastAt, true
}

// The Harness's turn hook (§20.6): each event noted into every live writer and the agent's summary clock consulted at
// a turn's end, every call returning at once.
type agentsTurnHook struct {
	stateLock sync.Mutex
	// each agent's summary clock, by agent id, made at its first turn and dropped once its run ends
	agentIdClocks map[Id]*agentsTurnClock
}

// One agent's summary clock and where its end is heard.
type agentsTurnClock struct {
	clock *AgentSummaryClock
	done  <-chan struct{}
}

// The process's turn hook.
var agentsHarnessTurnHook = &agentsTurnHook{agentIdClocks: map[Id]*agentsTurnClock{}}

// Registers the turn hook with the Harness.
func init() {
	RegisterHarnessTurnHook(agentsTurnHookName, agentsHarnessTurnHook)
}

// Where an agent's end is heard: the Harness's agent's life, nil for another implementation.
func harnessAgentDone(agent HarnessAgent) <-chan struct{} {
	if concrete, ok := agent.(*harnessAgent); ok && concrete.lifeCtx != nil {
		return concrete.lifeCtx.Done()
	}
	return nil
}

// The live writers.
func agentsLiveStatusWriters() []*AgentStatusWriter {
	agentsStatusWriters.stateLock.Lock()
	defer agentsStatusWriters.stateLock.Unlock()
	writers := make([]*AgentStatusWriter, 0, len(agentsStatusWriters.writers))
	for writer := range agentsStatusWriters.writers {
		writers = append(writers, writer)
	}
	return writers
}

// Notes agent's status into every live writer: only the one whose network holds its card writes it.
func (self *agentsTurnHook) note(agent HarnessAgent, state AgentState, activity string, summary *AgentSummary) {
	run := agent.Run()
	runId, tainted := Id{}, true
	if run != nil {
		runId, tainted = run.Id(), run.Tainted()
	}
	for _, writer := range agentsLiveStatusWriters() {
		name, err := ParseAgentName(agent.Name(), writer.settings)
		if err != nil {
			continue
		}
		writer.Note(&AgentStatusNote{
			Name: name,
			Status: &AgentStatus{
				State:    state,
				Activity: AgentStatusText(activity, writer.settings.StatusActivityCharCount),
				Updated:  writer.clock.Now(),
				RunId:    runId,
			},
			Tainted: tainted,
			Done:    harnessAgentDone(agent),
			Summary: summary,
		})
	}
}

// The agent's summary clock, made at its first turn with the first live writer's settings; clocks of agents whose
// runs ended go as one is made.
func (self *agentsTurnHook) summaryClock(agent HarnessAgent) *AgentSummaryClock {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if entry := self.agentIdClocks[agent.Id()]; entry != nil {
		return entry.clock
	}
	for agentId, entry := range self.agentIdClocks {
		if entry.done == nil {
			continue
		}
		select {
		case <-entry.done:
			delete(self.agentIdClocks, agentId)
		default:
		}
	}
	settings := DefaultSkillSettings()
	if writers := agentsLiveStatusWriters(); 0 < len(writers) {
		settings = writers[0].settings
	}
	entry := &agentsTurnClock{clock: NewAgentSummaryClock(settings, settings.SummaryMinutes), done: harnessAgentDone(agent)}
	self.agentIdClocks[agent.Id()] = entry
	return entry.clock
}

// The clock writers read, the first live writer's, or real time.
func agentsTurnHookNow() time.Time {
	writers := agentsLiveStatusWriters()
	if 0 < len(writers) {
		return writers[0].clock.Now()
	}
	return time.Now()
}

// A turn starts: working.
func (self *agentsTurnHook) TurnStart(agent HarnessAgent) {
	self.summaryClock(agent).TurnStart(agentsTurnHookNow())
	self.note(agent, AgentStateWorking, "working on a turn", nil)
}

// A turn ends: working while the run goes on, else idle; a summary due puts a reminder in the agent's next turn, and
// after SummaryReminderCount unanswered a mechanical one is written for it.
func (self *agentsTurnHook) TurnEnd(agent HarnessAgent) {
	clock := self.summaryClock(agent)
	outcome := clock.TurnEnd(agentsTurnHookNow())
	var summary *AgentSummary
	switch {
	case outcome.Mechanical:
		runId := Id{}
		if run := agent.Run(); run != nil {
			runId = run.Id()
		}
		summary = clock.MechanicalSummary(agentsRunSummaryFacts(agent.Id(), runId))
	case outcome.Remind:
		agent.Steer(AgentSummaryReminderText)
	}
	if agent.Running() {
		self.note(agent, AgentStateWorking, "between turns", summary)
		return
	}
	self.note(agent, AgentStateIdle, "idle", summary)
}

// A tool call runs past HarnessSettings.ToolCallSlowAfter: working, naming the tool.
func (self *agentsTurnHook) ToolCallSlow(agent HarnessAgent, toolCallId string, toolName string) {
	self.note(agent, AgentStateWorking, "running "+toolName, nil)
}
