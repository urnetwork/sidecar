//go:build !ios_extension

// RECORD-M6-16's run announcements (§16.11's start, renew, expire, claims, end, withdraw and offline rows and its runs
// paragraph; R-MCP-13, R-MCP-15, D-MCP-26, D-MCP-27, D-MCP-28, D-CORE-18, I-20; FS-88): DirectoryRuns announces this
// sidecar's runs in the team directory. Before format 2 each item rides announce entries in this sidecar's own stream,
// written through the record writer, which routes the kind to the directory (§16.11's M6 carrier row), and each run's
// claims and handoff are state of its item (directory_claim.go).
//
//	start      claims auto: Started schedules the item's first entry StartDelay on (10 s), coalescing whatever else
//	           changes before it goes; prompt: the run is held, and its first claim or handoff announces it; off:
//	           nothing is announced, and a claim or handoff is refused naming the setting (ErrDirectoryRunsClaimsOff)
//	renew      every RenewInterval (1 h) at a random offset of ±SidecarDirectorySettings.RenewJitter (§5.4's
//	           Directory.RenewJitter), each announced run that moved within MovedWindow (Moved: a hook event or a tool
//	           call) renews: a new entry at the same version, renewed and expires raised; an idle run renews nothing,
//	           so its item expires 90 min after its last renewal
//	end        Ended: state ended, or handed_off where the run's handoff names a member or an agent, the version
//	           raised; no renewal after
//	withdraw   Withdraw: a newer entry at version + 1 holding only a withdrawal's fields (plan-RECORD-m6-carrier#1),
//	           terminal, after which the run's claims read off; SetRuns' off withdraws every running item of its
//	           project at once (§16.10's claims row: off still withdraws a running announcement)
//	where      a run in an evs repo names the repo's id, and the project label and branch only while the repo holds a
//	           live item that is no private marker (RepoItem); else private true with project and branch empty, and a
//	           live item is rewritten so once a write, a renewal or Reconcile finds the repo's marker; a run in no evs
//	           repo names the label its caller resolved (.ur's project, else the remote's host and path, else the top
//	           level's base name; CORE-M6-02's ProjectLabel) and its branch
//	who        the member, or a tagged sidecar's sponsor, by the state now (DirectoryWhoMember), this sidecar, the
//	           agent's id and label, the harness and the model; tainted is the writing run's taint at each version
//	only       who, what and where leave the vault (I-20): the title, cut to 120 B after redaction, the claims' text
//	           and targets and the handoff's note are the only text, each normalized and redacted whole by §16.11's
//	           redaction row (DirectoryRedact) before the writer seals; no prompt past the title, tool call, touched
//	           path or diff reaches this file
//	source     hook, the daemon's own; agent for a version record_append raised
//	persist    each run's item is kept in the directory's store, runs/<announcement_id>, before its entry is
//	           appended, so a restart never writes a version again; Resume, at a start, ends the runs that ended
//	           meanwhile (§16.11's offline row) and keeps the rest, which renew once they move
//	offline    an entry written offline journals in the record writer and pushes once the sidecar is back, a
//	           renewal carrying its old renewed time, so readers let the item expire while it was away
//	close      Close stops the renewal timer and every write after it: the process's stop, after which an open
//	           run's item expires unless the next process's Resume or a move renews it
//
// Barriers: directory.run.before and .after around each append, keyed by the announcement's id. Safe for concurrent
// use. Locks: writeLock, then stateLock. writeLock is held across a write's whole build, its RepoItem call to the
// directory client included, which calls nothing of these runs back; stateLock is never held across a call out, an
// append or a store write.

package sidecar

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The store's names for a run's item, a format value of this device's own state.
const (
	directoryRunsStorePrefix  = "runs/"
	directoryRunsStoreVersion = 1
)

var (
	// The run's claims setting is off: no claim or handoff is filed, and nothing is announced (§16.11's claims row).
	ErrDirectoryRunsClaimsOff = errors.New("directory claims are off for this run's project")
	// No run of this sidecar's is open under that id: a session no run binds, or a run that ended or was withdrawn.
	ErrDirectoryRunUnknown = errors.New("directory run not open")
	// The harness config, where SetRuns keeps a member's value (QD-577), cannot be written yet: the value is not kept.
	ErrDirectoryRunsConfigUnavailable = errors.New("directory runs value cannot be kept")
	// The runs closed: nothing more is written in this process.
	ErrDirectoryRunsClosed = errors.New("directory runs closed")
)

// §16.10's claims values as a run's item reads them. The numbers are SidecarClaims', so the daemon passes a session's
// value by conversion, DirectoryRunClaims(resolution.Claims); zero, and any value off < prompt < auto does not name,
// reads off.
type DirectoryRunClaims int

const (
	DirectoryRunClaimsOff    DirectoryRunClaims = 1
	DirectoryRunClaimsPrompt DirectoryRunClaims = 2
	DirectoryRunClaimsAuto   DirectoryRunClaims = 3
)

// The value as a run's item acts on it: anything but prompt or auto is off.
func (self DirectoryRunClaims) effective() DirectoryRunClaims {
	if self == DirectoryRunClaimsPrompt || self == DirectoryRunClaimsAuto {
		return self
	}
	return DirectoryRunClaimsOff
}

// The value text names, auto, prompt or off, as §18.5's SetRuns and `ur directory runs` take it; any other text is
// refused with ErrDirectoryFormatInvalid.
func ParseDirectoryRunClaims(text string) (DirectoryRunClaims, error) {
	switch text {
	case "auto":
		return DirectoryRunClaimsAuto, nil
	case "prompt":
		return DirectoryRunClaimsPrompt, nil
	case "off":
		return DirectoryRunClaimsOff, nil
	}
	return 0, fmt.Errorf("%w: claims is auto, prompt or off", ErrDirectoryFormatInvalid)
}

// off, prompt or auto.
func (self DirectoryRunClaims) String() string {
	switch self.effective() {
	case DirectoryRunClaimsAuto:
		return "auto"
	case DirectoryRunClaimsPrompt:
		return "prompt"
	}
	return "off"
}

// The runs' own timing. RenewJitter is SidecarDirectorySettings', which §5.4 names.
type DirectoryRunsSettings struct {
	// A run under claims auto is announced this long after Started, whatever else changes first going in the same
	// entry: 10 s (§16.11's start row). Non-positive announces at once.
	StartDelay time.Duration
	// Moving runs renew this often: 1 h (§16.11's renew row). Non-positive renews nothing.
	RenewInterval time.Duration
	// A run renews only when it moved within this: the past hour (§16.11's renew row).
	MovedWindow time.Duration
}

// The defaults, a fresh value each call.
func DefaultDirectoryRunsSettings() *DirectoryRunsSettings {
	return &DirectoryRunsSettings{
		StartDelay:    10 * time.Second,
		RenewInterval: 1 * time.Hour,
		MovedWindow:   1 * time.Hour,
	}
}

// Where SetRuns keeps a member's claims value: the harness config in the author's vault, per project, "" its
// default (plan-RECORD-small-readings #11; plan-MCP-harness-config-schema #1). Nil until its writer is built.
type DirectoryRunsConfig interface {
	SetMemberClaims(ctx context.Context, projectKey string, claims DirectoryRunClaims) error
}

// What DirectoryRuns writes through.
type DirectoryRunsArgs struct {
	SidecarId Id
	// The record's writer: announce entries go to this sidecar's own stream in the directory.
	Writer RecordWriter
	// Each run's taint, read at each version; nil reads every run tainted.
	Runs RecordRunView
	// §7.9's and §8's state now as the directory asks it; nil reads DirectoryAuthUnavailable.
	Auth func() DirectoryAuthView
	// The repo's item that stands now, its private marker included: what a run in an evs repo names (the directory
	// client's RepoItem). Nil reads every repo as holding none, so every such run is private.
	RepoItem func(repoId Id) (*DirectoryItem, bool)
	// §16.7's redactor; nil makes one of the runs' own.
	Redactor *Redactor
	// Where each run's item is kept: the directory's store; nil keeps nothing, so a restart starts afresh.
	Store SidecarStore
	// Where SetRuns keeps a member's value; nil refuses to keep one, with ErrDirectoryRunsConfigUnavailable.
	Config   DirectoryRunsConfig
	Clock    Clock
	Settings *DirectoryRunsSettings
	// RenewJitter's.
	DirectorySettings *SidecarDirectorySettings
	// crypto/rand's reader when nil: announcement and claim ids, and the renewal's offset.
	Random io.Reader
	Log    Logger
}

// One run as Started names it: its who, what and where, and its session's claims value.
type DirectoryRunStart struct {
	RunId Id
	// The session's value, fixed for the session (D-CORE-18).
	Claims DirectoryRunClaims
	// The harness config's project key (SidecarProjectKey), which SetRuns names a project by.
	ProjectKey string
	AgentId    *Id
	// The daemon's normalization of §5.5's label, [a-z0-9-]{1,64}, or "".
	AgentLabel string
	// claude-code, codex or cursor.
	Harness string
	// An identifier, or "".
	Model string
	// SessionStart's title: cut to 120 B after redaction.
	Title string
	// The run's evs repo, nil when it is in none.
	RepoId *Id
	// The project label its caller resolved, and the branch.
	Project string
	Branch  string
}

// One run's item as kept, before its next entry.
type directoryRun struct {
	RunId          Id                 `json:"run_id"`
	AnnouncementId Id                 `json:"announcement_id"`
	Claims         DirectoryRunClaims `json:"claims"`
	ProjectKey     string             `json:"project_key"`
	AgentId        *Id                `json:"agent_id,omitempty"`
	AgentLabel     string             `json:"agent_label"`
	Harness        string             `json:"harness"`
	Model          string             `json:"model"`
	Title          string             `json:"title"`
	RepoId         *Id                `json:"repo_id,omitempty"`
	Project        string             `json:"project"`
	Branch         string             `json:"branch"`
	// The version last written, 0 before the first.
	Version       uint64 `json:"version"`
	StartedMillis int64  `json:"started_millis"`
	RenewedMillis int64  `json:"renewed_millis"`
	State         uint32 `json:"state"`
	// The claims and handoff, marshaled as their messages.
	ClaimBodies [][]byte `json:"claims_items,omitempty"`
	HandoffBody []byte   `json:"handoff,omitempty"`
	// The where last written was private.
	Private bool `json:"private"`
	// Kept in memory only: when it last moved, and whether an entry waits for its start delay.
	movedMillis int64
	startDue    bool
}

// The store's document of a run.
type directoryRunDocument struct {
	Version int           `json:"version"`
	Run     *directoryRun `json:"run"`
}

// This sidecar's run announcements in one network's team directory.
type DirectoryRuns struct {
	sidecarId         Id
	writer            RecordWriter
	runView           RecordRunView
	auth              func() DirectoryAuthView
	repoItem          func(repoId Id) (*DirectoryItem, bool)
	redactor          *Redactor
	store             SidecarStore
	config            DirectoryRunsConfig
	clock             Clock
	settings          *DirectoryRunsSettings
	directorySettings *SidecarDirectorySettings
	random            io.Reader
	log               Logger

	// one item write at a time: its build, its document and its append, in that order
	writeLock sync.Mutex

	stateLock sync.Mutex
	loaded    bool
	runIdRuns map[Id]*directoryRun
	// the renewal's timer, set once a run is announced
	renewStop func() bool
	closed    bool
}

// Runs over args. Nothing is read until the first call.
func NewDirectoryRuns(args *DirectoryRunsArgs) (*DirectoryRuns, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no runs args", ErrDirectoryFormatInvalid)
	}
	random := args.Random
	if random == nil {
		random = cryptorand.Reader
	}
	redactor := args.Redactor
	if redactor == nil {
		var err error
		if redactor, err = NewRedactor(random); err != nil {
			return nil, err
		}
	}
	runView := args.Runs
	if runView == nil {
		runView = RecordRunViewMissing{}
	}
	auth := args.Auth
	if auth == nil {
		auth = func() DirectoryAuthView { return DirectoryAuthUnavailable{} }
	}
	repoItem := args.RepoItem
	if repoItem == nil {
		repoItem = func(repoId Id) (*DirectoryItem, bool) { return nil, false }
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultDirectoryRunsSettings()
	}
	directorySettings := args.DirectorySettings
	if directorySettings == nil {
		directorySettings = DefaultSidecarSettings().Directory
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &DirectoryRuns{
		sidecarId:         args.SidecarId,
		writer:            args.Writer,
		runView:           runView,
		auth:              auth,
		repoItem:          repoItem,
		redactor:          redactor,
		store:             args.Store,
		config:            args.Config,
		clock:             clockOrReal(args.Clock),
		settings:          settings,
		directorySettings: directorySettings,
		random:            random,
		log:               log,
		runIdRuns:         map[Id]*directoryRun{},
	}, nil
}

// This client's runs, made at the first call over the client's writer, run view, state, store and redactor.
func (self *DirectoryClient) Runs() *DirectoryRuns {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	runs, _ := self.runs.(*DirectoryRuns)
	if runs != nil {
		return runs
	}
	var store SidecarStore
	if self.store != nil {
		store = self.store.store
	}
	runs, err := NewDirectoryRuns(&DirectoryRunsArgs{
		SidecarId:         self.sidecarId,
		Writer:            self.writer,
		Runs:              self.runView,
		Auth:              self.auth,
		RepoItem:          self.RepoItem,
		Redactor:          self.redactor,
		Store:             store,
		Clock:             self.clock,
		DirectorySettings: self.settings,
		Log:               self.log,
	})
	if err != nil {
		// a redactor is passed, so nothing above can fail; a nil answer refuses every run below
		return nil
	}
	self.runs = runs
	return runs
}

// The store name of an announcement's item.
func directoryRunStoreName(announcementId Id) string {
	return directoryRunsStorePrefix + recordChainIdText(announcementId)
}

// Reads the kept items once, keeping each open run.
func (self *DirectoryRuns) load() error {
	self.stateLock.Lock()
	loaded := self.loaded
	self.stateLock.Unlock()
	if loaded || self.store == nil {
		self.stateLock.Lock()
		self.loaded = true
		self.stateLock.Unlock()
		return nil
	}
	entries, err := self.store.List(directoryRunsStorePrefix)
	if err != nil {
		return err
	}
	runs := []*directoryRun{}
	for _, entry := range entries {
		reader, err := self.store.Open(entry.Name)
		if err != nil {
			return err
		}
		content, readErr := io.ReadAll(reader)
		reader.Close()
		if readErr != nil {
			return readErr
		}
		document := &directoryRunDocument{}
		if err := json.Unmarshal(content, document); err != nil || document.Version != directoryRunsStoreVersion || document.Run == nil {
			// a kept item that does not read is never taken as no item: its run stays unannounced here, and a reader
			// lets its last entry expire
			self.log.Warningf("[directory]a kept run item does not read: %s", entry.Name)
			continue
		}
		runs = append(runs, document.Run)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.loaded {
		return nil
	}
	for _, run := range runs {
		if _, held := self.runIdRuns[run.RunId]; !held {
			self.runIdRuns[run.RunId] = run
		}
	}
	self.loaded = true
	return nil
}

// A run's item as last kept, a copy, false for none.
func (self *DirectoryRuns) runOf(runId Id) (*directoryRun, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run, ok := self.runIdRuns[runId]
	if !ok {
		return nil, false
	}
	copied := *run
	copied.ClaimBodies = slices.Clone(run.ClaimBodies)
	return &copied, true
}

// Whether a run's item is open: announced, not ended or withdrawn.
func (self *directoryRun) open() bool {
	state := DirectoryAnnouncementState(self.State)
	return 0 < self.Version && state != DirectoryAnnouncementStateEnded && state != DirectoryAnnouncementStateHandedOff &&
		state != DirectoryAnnouncementStateWithdrawn
}

// A run's claims, parsed.
func (self *directoryRun) claims() []*protocol.Claim {
	claims := []*protocol.Claim{}
	for _, body := range self.ClaimBodies {
		claim := &protocol.Claim{}
		if proto.Unmarshal(body, claim) == nil {
			claims = append(claims, claim)
		}
	}
	return claims
}

// Sets a run's claims.
func (self *directoryRun) setClaims(claims []*protocol.Claim) error {
	bodies := [][]byte{}
	for _, claim := range claims {
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(claim)
		if err != nil {
			return err
		}
		bodies = append(bodies, body)
	}
	self.ClaimBodies = bodies
	return nil
}

// A run's handoff, nil for none.
func (self *directoryRun) handoff() *protocol.Handoff {
	if self.HandoffBody == nil {
		return nil
	}
	handoff := &protocol.Handoff{}
	if proto.Unmarshal(self.HandoffBody, handoff) != nil {
		return nil
	}
	return handoff
}

// 16 random bytes as an id.
func (self *DirectoryRuns) newId() (Id, error) {
	var id Id
	if _, err := io.ReadFull(self.random, id[:]); err != nil {
		return Id{}, fmt.Errorf("directory runs: an id: %w", err)
	}
	return id, nil
}

// A run starts (§16.11's start row): auto schedules its item StartDelay on; prompt holds it for its first claim; off
// keeps it so a claim is refused naming the setting. A run already held, a restart's or a resumed session's, keeps
// its item and takes the session's value.
func (self *DirectoryRuns) Started(start *DirectoryRunStart) error {
	if start == nil {
		return fmt.Errorf("%w: no run", ErrDirectoryFormatInvalid)
	}
	if err := self.load(); err != nil {
		return err
	}
	announcementId, err := self.newId()
	if err != nil {
		return err
	}
	nowMillis := self.clock.Now().UnixMilli()
	// the title's first line alone: a prompt past it stays in the vault (I-20)
	title, _, _ := strings.Cut(strings.ReplaceAll(start.Title, "\r", "\n"), "\n")
	due, changed := func() (bool, bool) {
		// with update's lock, which rewrites a run whole from a copy
		self.writeLock.Lock()
		defer self.writeLock.Unlock()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		run, held := self.runIdRuns[start.RunId]
		if !held {
			run = &directoryRun{RunId: start.RunId, AnnouncementId: announcementId, StartedMillis: nowMillis, State: uint32(DirectoryAnnouncementStateActive)}
			self.runIdRuns[start.RunId] = run
		}
		before := *run
		run.Claims = start.Claims.effective()
		run.ProjectKey = start.ProjectKey
		run.AgentId = start.AgentId
		run.AgentLabel = start.AgentLabel
		run.Harness = start.Harness
		run.Model = start.Model
		run.Title = title
		run.RepoId = start.RepoId
		run.Project = start.Project
		run.Branch = start.Branch
		run.movedMillis = nowMillis
		if !directoryRunIdEqual(before.RepoId, run.RepoId) {
			// another repo: its where is judged afresh
			run.Private = false
		}
		if run.Claims == DirectoryRunClaimsAuto && run.Version == 0 {
			run.startDue = true
			return true, false
		}
		// a session resuming an announced run with other who, what or where: a content change
		changed := run.open() && (!directoryRunIdEqual(before.AgentId, run.AgentId) || before.AgentLabel != run.AgentLabel ||
			before.Harness != run.Harness || before.Model != run.Model || before.Title != run.Title ||
			!directoryRunIdEqual(before.RepoId, run.RepoId) || before.Project != run.Project || before.Branch != run.Branch)
		return false, changed
	}()
	if changed {
		return self.updateOnly(start.RunId, RecordSourceHook, func(run *directoryRun) (bool, error) {
			if !run.open() {
				return false, nil
			}
			run.Version += 1
			return true, nil
		})
	}
	if !due {
		return nil
	}
	if self.settings.StartDelay <= 0 {
		return self.announceDue(start.RunId)
	}
	self.clock.AfterFunc(self.settings.StartDelay, func() {
		if err := self.announceDue(start.RunId); err != nil && !errors.Is(err, ErrDirectoryRunsClosed) {
			self.log.Warningf("[directory]a run's announcement was not written: %s", err)
		}
	})
	return nil
}

// Whether two optional ids are both nil or the same id.
func directoryRunIdEqual(a *Id, b *Id) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// The start's entry, unless another write took the run first.
func (self *DirectoryRuns) announceDue(runId Id) error {
	return self.updateOnly(runId, RecordSourceHook, func(run *directoryRun) (bool, error) {
		if !run.startDue || 0 < run.Version {
			run.startDue = false
			return false, nil
		}
		run.startDue = false
		return true, nil
	})
}

// A run moved: a hook event or a tool call, which keeps it renewing (§16.11's renew row), and a where a repo's
// marker changed since is rewritten.
func (self *DirectoryRuns) Moved(runId Id) {
	if self.load() != nil {
		return
	}
	nowMillis := self.clock.Now().UnixMilli()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if run, ok := self.runIdRuns[runId]; ok {
			run.movedMillis = nowMillis
		}
	}()
	if err := self.reconcileRun(runId); err != nil {
		self.log.Warningf("[directory]a run's where was not rewritten: %s", err)
	}
}

// The run ended, at SessionEnd or its Coverage entry (§16.11's end row): its item ended, or handed_off where its
// handoff names a member or an agent, at a raised version; a run never announced is forgotten.
func (self *DirectoryRuns) Ended(runId Id) error {
	if err := self.load(); err != nil {
		return err
	}
	_, err := self.update(runId, RecordSourceHook, func(run *directoryRun) (bool, error) {
		if !run.open() {
			return false, nil
		}
		run.State = uint32(DirectoryAnnouncementStateEnded)
		if handoff := run.handoff(); handoff != nil && (len(handoff.GetToMemberId()) != 0 || handoff.GetToAgentLabel() != "") {
			run.State = uint32(DirectoryAnnouncementStateHandedOff)
		}
		run.Version += 1
		return true, nil
	})
	if err != nil && !errors.Is(err, ErrDirectoryRunUnknown) {
		return err
	}
	self.forget(runId)
	return nil
}

// Withdraws the run's item (§16.11's withdraw row; plan-RECORD-m6-carrier#1): a withdrawal at version + 1, terminal,
// after which the run's claims read off. A run never announced only turns off.
func (self *DirectoryRuns) Withdraw(runId Id) error {
	if err := self.load(); err != nil {
		return err
	}
	_, err := self.update(runId, RecordSourceHook, func(run *directoryRun) (bool, error) {
		run.Claims = DirectoryRunClaimsOff
		if !run.open() {
			return false, nil
		}
		run.State = uint32(DirectoryAnnouncementStateWithdrawn)
		run.Version += 1
		return true, nil
	})
	if err != nil {
		return err
	}
	return nil
}

// Each announced run whose where its repo's item no longer allows is rewritten, once: what a sync calls, and Moved
// for its run.
func (self *DirectoryRuns) Reconcile() error {
	if err := self.load(); err != nil {
		return err
	}
	runIds := func() []Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		runIds := []Id{}
		for runId, run := range self.runIdRuns {
			if run.open() && run.RepoId != nil {
				runIds = append(runIds, runId)
			}
		}
		return runIds
	}()
	errs := []error{}
	for _, runId := range runIds {
		errs = append(errs, self.reconcileRun(runId))
	}
	return errors.Join(errs...)
}

// One run's where rewritten when it turned private since its last entry (§16.11's runs row).
func (self *DirectoryRuns) reconcileRun(runId Id) error {
	run, ok := self.runOf(runId)
	if !ok || !run.open() || run.RepoId == nil || run.Private || !self.repoPrivate(*run.RepoId) {
		return nil
	}
	_, err := self.update(runId, RecordSourceHook, func(run *directoryRun) (bool, error) {
		if !run.open() || run.Private {
			return false, nil
		}
		run.Version += 1
		return true, nil
	})
	if errors.Is(err, ErrDirectoryRunUnknown) {
		return nil
	}
	return err
}

// Whether a run in repoId announces it private: it holds no live item, or its item is a private marker.
func (self *DirectoryRuns) repoPrivate(repoId Id) bool {
	item, ok := self.repoItem(repoId)
	return !ok || item == nil || item.Display != DirectoryItemActive || item.Announcement.GetWhere().GetPrivate()
}

// At a start, ends each kept open run that ended meanwhile (§16.11's offline row), by ended's word; the rest wait to
// renew until they move.
func (self *DirectoryRuns) Resume(ended func(runId Id) bool) error {
	if err := self.load(); err != nil {
		return err
	}
	runIds := func() []Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		runIds := []Id{}
		for runId, run := range self.runIdRuns {
			if run.open() {
				runIds = append(runIds, runId)
			}
		}
		slices.SortFunc(runIds, func(a Id, b Id) int { return a.Cmp(b) })
		return runIds
	}()
	errs := []error{}
	for _, runId := range runIds {
		if ended != nil && ended(runId) {
			errs = append(errs, self.Ended(runId))
		}
	}
	self.scheduleRenew()
	return errors.Join(errs...)
}

// SetRuns' off for projectKey ("" for every project): each open run of it withdrawn at once (§16.10's claims row).
func (self *DirectoryRuns) withdrawProject(projectKey string) error {
	if err := self.load(); err != nil {
		return err
	}
	runIds := func() []Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		runIds := []Id{}
		for runId, run := range self.runIdRuns {
			if projectKey == "" || run.ProjectKey == projectKey {
				runIds = append(runIds, runId)
			}
		}
		slices.SortFunc(runIds, func(a Id, b Id) int { return a.Cmp(b) })
		return runIds
	}()
	errs := []error{}
	for _, runId := range runIds {
		errs = append(errs, self.Withdraw(runId))
	}
	return errors.Join(errs...)
}

// The member's claims value for a project, "" its default (§16.10's claims row; `ur directory runs`, the SDK's
// SetRuns), the person's act on /dev/tty or in an app and never through MCP: off withdraws every running item of the
// project at once, a narrower value applies from each run's next session, and the value is kept in the harness config
// (QD-577), whose writer is not bound yet, so keeping it answers ErrDirectoryRunsConfigUnavailable after any
// withdrawal.
func (self *DirectoryClient) SetRuns(ctx context.Context, projectKey string, claims DirectoryRunClaims) error {
	if self.readOnly {
		return ErrDirectoryReadOnly
	}
	runs := self.Runs()
	if runs == nil {
		return ErrDirectoryNoWriter
	}
	if claims.effective() == DirectoryRunClaimsOff {
		if err := runs.withdrawProject(projectKey); err != nil {
			return err
		}
	}
	if runs.config == nil {
		return ErrDirectoryRunsConfigUnavailable
	}
	return runs.config.SetMemberClaims(ctx, projectKey, claims.effective())
}

// `ur directory withdraw <id>` and the app's toggle: withdraws this sidecar's run item of announcementId.
// ErrDirectoryItemNone when no open run of this sidecar's has it.
func (self *DirectoryClient) Withdraw(announcementId Id) error {
	if self.readOnly {
		return ErrDirectoryReadOnly
	}
	runs := self.Runs()
	if runs == nil {
		return ErrDirectoryNoWriter
	}
	if err := runs.load(); err != nil {
		return err
	}
	runId, ok := func() (Id, bool) {
		runs.stateLock.Lock()
		defer runs.stateLock.Unlock()
		for runId, run := range runs.runIdRuns {
			if run.AnnouncementId == announcementId && run.open() {
				return runId, true
			}
		}
		return Id{}, false
	}()
	if !ok {
		return ErrDirectoryItemNone
	}
	return runs.Withdraw(runId)
}

// Drops a run from memory and its kept item: it ended, and its last entry stands.
func (self *DirectoryRuns) forget(runId Id) {
	run, ok := func() (*directoryRun, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		run, ok := self.runIdRuns[runId]
		delete(self.runIdRuns, runId)
		return run, ok
	}()
	if ok && self.store != nil {
		if err := self.store.Remove(directoryRunStoreName(run.AnnouncementId)); err != nil {
			self.log.Warningf("[directory]an ended run's kept item was not removed: %s", err)
		}
	}
}

// Changes a run's item under writeLock and, when change answers true, writes its next entry: the item built, checked
// and kept, then appended, its ref answered. A change that answers false writes nothing and answers nil. Refused with
// ErrDirectoryRunUnknown for a run not held, and with ErrDirectoryRunsClosed after Close.
func (self *DirectoryRuns) update(runId Id, source RecordSource, change func(run *directoryRun) (bool, error)) (*RecordEntryRef, error) {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if self.isClosed() {
		return nil, ErrDirectoryRunsClosed
	}
	run, ok := self.runOf(runId)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrDirectoryRunUnknown, runId)
	}
	write, err := change(run)
	if err != nil {
		return nil, err
	}
	if !write {
		self.keep(run)
		return nil, nil
	}
	if run.Version == 0 {
		run.Version = 1
	}
	item, err := self.itemOf(run)
	if err != nil {
		return nil, err
	}
	if err := self.persist(run); err != nil {
		return nil, err
	}
	self.keep(run)
	ref, err := self.append(run, item, source)
	if err != nil {
		return nil, err
	}
	// the renewal timer runs while a run is open; setting it waits on nothing (scheduleRenew's timeout is positive)
	self.scheduleRenew()
	return ref, nil
}

// update with its ref dropped.
func (self *DirectoryRuns) updateOnly(runId Id, source RecordSource, change func(run *directoryRun) (bool, error)) error {
	_, err := self.update(runId, source, change)
	return err
}

// Whether Close has run.
func (self *DirectoryRuns) isClosed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

// Stops the renewal timer, and every write after: the component's close. Each open run's item expires unless a later
// process renews it, and its kept item lets Resume end it.
func (self *DirectoryRuns) Close() {
	stop := func() func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		stop := self.renewStop
		self.renewStop = nil
		return stop
	}()
	if stop != nil {
		stop()
	}
}

// Puts a changed run back in memory, its moved time the later of its own and what is held.
func (self *DirectoryRuns) keep(run *directoryRun) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if held, ok := self.runIdRuns[run.RunId]; ok {
		run.movedMillis = max(run.movedMillis, held.movedMillis)
	}
	self.runIdRuns[run.RunId] = run
}

// Writes a run's kept item, before its entry is appended, so a restart never writes its version again.
func (self *DirectoryRuns) persist(run *directoryRun) error {
	if self.store == nil {
		return nil
	}
	content, err := json.Marshal(&directoryRunDocument{Version: directoryRunsStoreVersion, Run: run})
	if err != nil {
		return err
	}
	writer, err := self.store.Create(directoryRunStoreName(run.AnnouncementId))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// The run's item now: its kept state, who by the state now, where by its repo's item now, renewed now, tainted by the
// run now; normalized, redacted, cut and held to §16.11's checks, the run's private bit noted.
func (self *DirectoryRuns) itemOf(run *directoryRun) (*protocol.Announcement, error) {
	nowMillis := self.clock.Now().UnixMilli()
	run.RenewedMillis = nowMillis
	expiresMillis, _ := DirectoryAnnouncementExpiresMillis(DirectoryAnnouncementKindRun, nowMillis)
	who := &protocol.AnnounceWho{SidecarId: self.sidecarId.Bytes()}
	if memberId, ok := DirectoryWhoMember(self.auth(), self.sidecarId); ok {
		who.MemberId = memberId.Bytes()
	}
	if DirectoryAnnouncementState(run.State) == DirectoryAnnouncementStateWithdrawn {
		// a withdrawal's own fields alone (plan-RECORD-m6-carrier#1)
		item := &protocol.Announcement{
			AnnouncementId: run.AnnouncementId.Bytes(),
			Kind:           uint32(DirectoryAnnouncementKindRun),
			Version:        run.Version,
			RenewedMillis:  nowMillis,
			ExpiresMillis:  expiresMillis,
			State:          run.State,
			Who:            who,
		}
		return item, DirectoryCheckItem(item)
	}
	if run.AgentId != nil {
		who.AgentId = run.AgentId.Bytes()
	}
	who.AgentLabel = run.AgentLabel
	who.Harness = run.Harness
	who.Model = run.Model
	where := &protocol.AnnounceWhere{}
	if run.RepoId != nil {
		where.RepoId = run.RepoId.Bytes()
		// private is kept for the run's life once written: a renewal never changes content at its version
		if run.Private || self.repoPrivate(*run.RepoId) {
			where.Private = true
			run.Private = true
		} else {
			where.Project = run.Project
			where.Branch = run.Branch
		}
	} else {
		where.Project = run.Project
		where.Branch = run.Branch
	}
	item := &protocol.Announcement{
		AnnouncementId: run.AnnouncementId.Bytes(),
		Kind:           uint32(DirectoryAnnouncementKindRun),
		Version:        run.Version,
		StartedMillis:  min(run.StartedMillis, nowMillis),
		RenewedMillis:  nowMillis,
		ExpiresMillis:  expiresMillis,
		State:          run.State,
		Tainted:        self.runView.RunTainted(run.RunId),
		Who:            who,
		What:           &protocol.AnnounceWhat{Title: run.Title, RunId: run.RunId.Bytes()},
		Where:          where,
		Claims:         run.claims(),
		Handoff:        run.handoff(),
	}
	if _, err := DirectoryRedact(self.redactor, item); err != nil {
		return nil, err
	}
	item.What.Title = directoryCutText(item.GetWhat().GetTitle(), DirectoryRunTitleByteCount)
	for _, claim := range item.GetClaims() {
		// a claim's expiry is capped by the run's (§16.11's claims row); 0 lasts while the run renews
		if expiresMillis < claim.GetExpiresMillis() {
			claim.ExpiresMillis = expiresMillis
		}
	}
	if err := DirectoryCheckItem(item); err != nil {
		return nil, err
	}
	return item, nil
}

// text cut to at most byteCount bytes at a character's boundary.
func directoryCutText(text string, byteCount int) string {
	if len(text) <= byteCount {
		return text
	}
	cut := text[:byteCount]
	for 0 < len(cut) && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return strings.TrimRight(cut, " ")
}

// Appends a run's item as an announce entry in this sidecar's stream, source hook, or agent for a version
// record_append raised, and answers the entry's ref, which a spooled draft's leaves unset.
func (self *DirectoryRuns) append(run *directoryRun, item *protocol.Announcement, source RecordSource) (*RecordEntryRef, error) {
	if self.writer == nil {
		return nil, ErrDirectoryNoWriter
	}
	runId := run.RunId
	hookKey := recordChainIdText(run.AnnouncementId)
	testHookBarrier("directory.run.before", hookKey)
	refs, err := self.writer.Append(&RecordDraft{Kind: RecordKindAnnounce, Source: source, RunId: &runId, AgentId: run.AgentId, Body: item})
	testHookBarrier("directory.run.after", hookKey)
	if err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return &RecordEntryRef{Spooled: true}, nil
	}
	return refs[0], nil
}

// Sets the renewal timer, when none is set and a run is open: RenewInterval on at a random offset of ±RenewJitter,
// always a positive timeout, so a fake clock never fires it inline.
func (self *DirectoryRuns) scheduleRenew() {
	if self.settings.RenewInterval <= 0 {
		return
	}
	set := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.renewStop != nil || self.closed {
			return false
		}
		for _, run := range self.runIdRuns {
			if run.open() {
				return true
			}
		}
		return false
	}()
	if !set {
		return
	}
	timeout := self.settings.RenewInterval + self.jitter()
	if timeout <= 0 {
		// a jitter past the interval: never a timer that fires inline, under a caller's writeLock
		timeout = self.settings.RenewInterval
	}
	stop := self.clock.AfterFunc(timeout, self.renew)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.renewStop == nil && !self.closed {
		self.renewStop = stop
	} else {
		stop()
	}
}

// A random offset in [-RenewJitter, +RenewJitter].
func (self *DirectoryRuns) jitter() time.Duration {
	jitter := self.directorySettings.RenewJitter
	if jitter <= 0 {
		return 0
	}
	var value [8]byte
	if _, err := io.ReadFull(self.random, value[:]); err != nil {
		return 0
	}
	span := uint64(2*jitter) + 1
	return time.Duration(binary.BigEndian.Uint64(value[:])%span) - jitter
}

// The renewal: each open run that moved within MovedWindow renews at its version, and a where its repo's marker
// changed is rewritten; then the next renewal is set.
func (self *DirectoryRuns) renew() {
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.renewStop = nil
		return self.closed
	}()
	if closed {
		return
	}
	nowMillis := self.clock.Now().UnixMilli()
	runIds := func() []Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		runIds := []Id{}
		for runId, run := range self.runIdRuns {
			if run.open() && nowMillis-run.movedMillis <= self.settings.MovedWindow.Milliseconds() {
				runIds = append(runIds, runId)
			}
		}
		slices.SortFunc(runIds, func(a Id, b Id) int { return a.Cmp(b) })
		return runIds
	}()
	for _, runId := range runIds {
		_, err := self.update(runId, RecordSourceHook, func(run *directoryRun) (bool, error) {
			if !run.open() {
				return false, nil
			}
			if run.RepoId != nil && !run.Private && self.repoPrivate(*run.RepoId) {
				// the repo turned private since: a content change, at a raised version
				run.Version += 1
			}
			return true, nil
		})
		if err != nil && !errors.Is(err, ErrDirectoryRunUnknown) {
			self.log.Warningf("[directory]a run's renewal was not written: %s", err)
		}
	}
	self.scheduleRenew()
}
