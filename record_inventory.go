//go:build !ios_extension

// The agent inventory (RECORD-M6-08; RECORD.md section 6.4's InventoryBody; R-MCP-7): one `inventory` entry a sidecar
// a UTC day it ran anything, naming each agent it ran, its harnesses, models, repos and projects, its runs and when
// it was first and last seen. In a personal network the entry is the vault's; in team mode it is T's (record_team.go).
//
//	day       days since 1970-01-01 UTC on this sidecar's clock. Runs are noted into the component's file
//	          inventory/day as they start; the first note or Tend of a later day writes the earlier day's entry and
//	          starts the file again, so a day with no run writes nothing
//	once      the entry is written, then the file replaced: a crash between leaves the day in the file, and the next
//	          pass writes it again. A reader takes the newest inventory of a (sidecar, day)
//	caps      InventoryBody's: agents, and each agent's harnesses, models, repos and projects. What does not fit is
//	          left out and counted in Stats, never cut to fit under another name
//	never     a credential's value: credential_ref is a delegation id or an auth key id (I-7). A private repo is named
//	          by id, with no project
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

const (
	recordInventoryStateName    = "inventory/day"
	recordInventoryStateVersion = 1
)

// The inventory body's caps.
type RecordInventorySettings struct {
	// InventoryBody's caps (RECORD.md section 6.4): 64 agents; 8 harnesses, 16 models and 64 repos and projects each.
	AgentCount   int
	HarnessCount int
	ModelCount   int
	RepoCount    int
	ProjectCount int
	// The run ids kept for an agent a day, to count a run once however often it is noted. Past it a new run still
	// counts, and one noted again may count again.
	RunCount int
	// A harness's, model's and project's bytes; a longer one is left out.
	NameByteCount int
}

// RECORD.md section 6.4's caps.
func DefaultRecordInventorySettings() *RecordInventorySettings {
	return &RecordInventorySettings{
		AgentCount:    64,
		HarnessCount:  8,
		ModelCount:    16,
		RepoCount:     64,
		ProjectCount:  64,
		RunCount:      1024,
		NameByteCount: 128,
	}
}

// One run as it starts or resumes.
type RecordInventoryRun struct {
	RunId Id
	// The agent, nil for a run under no agent identity.
	AgentId     *Id
	AgentLabel  string
	AgentSource RecordAgentSource
	// name/version
	Harness string
	Model   string
	// The run's evs repo, which names it with no project; else its project.
	RepoId  *Id
	Project string
}

// What the inventory left out since it was made.
type RecordInventoryStats struct {
	// Agents past AgentCount, and names past an agent's caps or NameByteCount.
	DroppedAgentCount int
	DroppedNameCount  int
	WrittenCount      int
}

// One agent of the day's file.
type recordInventoryAgentDocument struct {
	AgentId         *Id      `json:"agent_id,omitempty"`
	AgentLabel      string   `json:"agent_label,omitempty"`
	AgentSource     uint32   `json:"agent_source,omitempty"`
	Harnesses       []string `json:"harnesses,omitempty"`
	Models          []string `json:"models,omitempty"`
	RepoIds         []Id     `json:"repo_ids,omitempty"`
	Projects        []string `json:"projects,omitempty"`
	RunIds          []Id     `json:"run_ids,omitempty"`
	Runs            uint32   `json:"runs"`
	FirstSeenMillis int64    `json:"first_seen_millis"`
	LastSeenMillis  int64    `json:"last_seen_millis"`
}

// The day's file.
type recordInventoryDocument struct {
	Version int                             `json:"version"`
	Day     uint32                          `json:"day"`
	Agents  []*recordInventoryAgentDocument `json:"agents,omitempty"`
}

// A sidecar's daily inventory.
type RecordInventory struct {
	writer   *recordWriter
	settings *RecordInventorySettings

	// one note or roll at a time, across the file and the entry
	dayLock sync.Mutex

	stateLock     sync.Mutex
	credentialRef func() []byte
	stats         RecordInventoryStats
}

// An inventory writing through writer, with the default settings when nil.
func newRecordInventory(writer *recordWriter, settings *RecordInventorySettings) *RecordInventory {
	if settings == nil {
		settings = DefaultRecordInventorySettings()
	}
	return &RecordInventory{writer: writer, settings: settings}
}

// The record's inventory, made at the first call, from when the loop rolls its day.
func (self *SidecarRecord) Inventory() *RecordInventory {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	inventory, _ := self.inventory.(*RecordInventory)
	if inventory == nil {
		inventory = newRecordInventory(self.writer, nil)
		self.inventory = inventory
		self.tendHooks = append(self.tendHooks, func(ctx context.Context) {
			if err := inventory.Tend(ctx); err != nil && self.writer.log.V(1).Enabled() {
				self.writer.log.Infof("[record]%s", err)
			}
		})
	}
	return inventory
}

// Sets what names the credential this sidecar runs agents under: a delegation id or an auth key id, never a value.
func (self *RecordInventory) SetCredentialRef(credentialRef func() []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.credentialRef = credentialRef
}

// What was left out and written so far.
func (self *RecordInventory) Stats() RecordInventoryStats {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.stats
}

// Days since 1970-01-01 UTC.
func recordInventoryDay(now time.Time) uint32 {
	return uint32(max(now.Unix(), 0) / 86400)
}

// The day's file, empty with day 0 when there is none.
func (self *RecordInventory) load() (*recordInventoryDocument, error) {
	content, err := self.writer.chain.readFile(recordInventoryStateName)
	if err != nil {
		return nil, err
	}
	document := &recordInventoryDocument{Version: recordInventoryStateVersion}
	if content != nil {
		if err := recordChainDecode(content, document); err != nil || document.Version != recordInventoryStateVersion {
			return nil, fmt.Errorf("%w: inventory state", ErrRecordChainCorrupt)
		}
	}
	return document, nil
}

// Writes the day's file durably.
func (self *RecordInventory) store(document *recordInventoryDocument) error {
	content, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if err := self.writer.chain.writeFile(recordInventoryStateName, content); err != nil {
		return fmt.Errorf("record: inventory state: %w", err)
	}
	return nil
}

// The entry body of a day's file.
func (self *RecordInventory) body(document *recordInventoryDocument) *protocol.InventoryBody {
	body := &protocol.InventoryBody{Day: document.Day}
	auth := self.writer.auth()
	if memberId, ok := auth.Member(self.writer.sidecarId); ok {
		body.SponsorMemberId = memberId.Bytes()
	} else if sponsorId, ok := auth.Sponsor(self.writer.sidecarId); ok {
		body.SponsorMemberId = sponsorId.Bytes()
	}
	credentialRef := func() func() []byte {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.credentialRef
	}()
	if credentialRef != nil {
		body.CredentialRef = credentialRef()
	}
	for _, agent := range document.Agents {
		entry := &protocol.InventoryAgent{
			AgentLabel:      agent.AgentLabel,
			AgentSource:     agent.AgentSource,
			Harnesses:       slices.Clone(agent.Harnesses),
			Models:          slices.Clone(agent.Models),
			Projects:        slices.Clone(agent.Projects),
			Runs:            agent.Runs,
			FirstSeenMillis: agent.FirstSeenMillis,
			LastSeenMillis:  agent.LastSeenMillis,
		}
		if agent.AgentId != nil {
			entry.AgentId = agent.AgentId.Bytes()
		}
		for _, repoId := range agent.RepoIds {
			entry.RepoIds = append(entry.RepoIds, repoId.Bytes())
		}
		body.Agents = append(body.Agents, entry)
	}
	return body
}

// Writes the file's day as an entry when it is an earlier day than now's and ran anything, then starts today's file.
// dayLock is held.
func (self *RecordInventory) roll(document *recordInventoryDocument, today uint32) (*recordInventoryDocument, error) {
	if document.Day == today {
		return document, nil
	}
	if document.Day != 0 && document.Day < today && 0 < len(document.Agents) {
		testHookBarrier("record.inventory.roll.before", "")
		if _, err := self.writer.Append(&RecordDraft{
			Kind:      RecordKindInventory,
			Source:    RecordSourceObserved,
			NoSession: true,
			Body:      self.body(document),
		}); err != nil {
			return nil, err
		}
		testHookBarrier("record.inventory.roll.after", "")
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.stats.WrittenCount += 1
		}()
	}
	// a file of a later day than the clock's is a clock set back: its runs count toward today
	fresh := &recordInventoryDocument{Version: recordInventoryStateVersion, Day: today}
	if today < document.Day {
		fresh.Agents = document.Agents
	}
	if err := self.store(fresh); err != nil {
		return nil, err
	}
	return fresh, nil
}

// Rolls the day: called by the record's loop, so a day's entry is written though no run starts the next day.
func (self *RecordInventory) Tend(ctx context.Context) error {
	self.dayLock.Lock()
	defer self.dayLock.Unlock()
	document, err := self.load()
	if err != nil {
		return err
	}
	if document.Day == 0 {
		// nothing ran yet: no file to start
		return nil
	}
	_, err = self.roll(document, recordInventoryDay(self.writer.clock.Now()))
	return err
}

// Adds value to values within count, counting one that does not fit.
func (self *RecordInventory) addName(values []string, value string, count int) []string {
	if value == "" || slices.Contains(values, value) {
		return values
	}
	if count <= len(values) || self.settings.NameByteCount < len(value) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.stats.DroppedNameCount += 1
		return values
	}
	return append(values, value)
}

// Notes a run this sidecar started or resumed, into today's file.
func (self *RecordInventory) NoteRun(run *RecordInventoryRun) error {
	if run == nil {
		return fmt.Errorf("%w: no run", ErrRecordDraftInvalid)
	}
	self.dayLock.Lock()
	defer self.dayLock.Unlock()
	document, err := self.load()
	if err != nil {
		return err
	}
	now := self.writer.clock.Now()
	document, err = self.roll(document, recordInventoryDay(now))
	if err != nil {
		return err
	}
	index := slices.IndexFunc(document.Agents, func(agent *recordInventoryAgentDocument) bool {
		if (agent.AgentId == nil) != (run.AgentId == nil) {
			return false
		}
		if agent.AgentId != nil {
			return *agent.AgentId == *run.AgentId
		}
		return agent.AgentLabel == run.AgentLabel
	})
	if index < 0 {
		if self.settings.AgentCount <= len(document.Agents) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.stats.DroppedAgentCount += 1
			return nil
		}
		agent := &recordInventoryAgentDocument{AgentLabel: run.AgentLabel, AgentSource: uint32(run.AgentSource), FirstSeenMillis: now.UnixMilli()}
		if run.AgentId != nil {
			agentId := *run.AgentId
			agent.AgentId = &agentId
		}
		document.Agents = append(document.Agents, agent)
		index = len(document.Agents) - 1
	}
	agent := document.Agents[index]
	agent.LastSeenMillis = now.UnixMilli()
	if !slices.Contains(agent.RunIds, run.RunId) {
		agent.Runs += 1
		if len(agent.RunIds) < self.settings.RunCount {
			agent.RunIds = append(agent.RunIds, run.RunId)
		}
	}
	agent.Harnesses = self.addName(agent.Harnesses, run.Harness, self.settings.HarnessCount)
	agent.Models = self.addName(agent.Models, run.Model, self.settings.ModelCount)
	if run.RepoId != nil {
		if !slices.Contains(agent.RepoIds, *run.RepoId) {
			if len(agent.RepoIds) < self.settings.RepoCount {
				agent.RepoIds = append(agent.RepoIds, *run.RepoId)
			} else {
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.stats.DroppedNameCount += 1
				}()
			}
		}
	} else {
		agent.Projects = self.addName(agent.Projects, run.Project, self.settings.ProjectCount)
	}
	return self.store(document)
}
