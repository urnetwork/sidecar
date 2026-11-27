//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.10's storage view (CTXH-M11-06; R-CTXH-8, D-CTXH-8): what context history holds in the member's
// vault, by run, agent and device, blobs apart, read from the headers a sync brings and the padded sizes the stream
// listing states (RecordEntryCopy.BodyByteCount), so a phone sizes every run without fetching a body.
//
//	sizes     a session entry counts its signed header and its body file's padded size; a blob the same, apart; a body
//	          no listing holds yet, withheld by its writer past a cap or dropped, counts nothing in the vault; an erased
//	          or expired one counts its header alone (sessionEntryByteCount)
//	runs      each run of the vault holding a session entry, newest first or largest first, with its agent, the device
//	          that wrote it (an agents' enclave being one of the member's devices), its model and label from its
//	          context entries and the run it continues, so a run and its continuations show as one conversation;
//	          filtered by agent or run; with the totals by agent and by device
//	tree      a run asked with tree opens it (SessionReader.Open, its bodies fetched only now) and lists its nodes, their
//	          parents, types, states, sizes and parts not held, as `ur harness show` lists them
//	caps      the caps' state (session_cap.go): at WarningFraction of a cap, the largest runs and the one tap offered
//	expire    ExpireOldestBlobs, the warning's one tap: the person's act, confirmed in the app or on /dev/tty, never
//	          through MCP or under a harness; the vault's oldest session_blob entries by push time erased, reason
//	          person, until history is under ExpiryTargetFraction of the cap warned at; every node kept, so runs stay
//	          readable and continuable, their oldest large parts reading [pruned: <size>, sha256 <8 hex>]
//	switch    SetAutoExpire, the person's switch that expires so again at each cap, confirmed as the tap is, kept in
//	          the session component's sealed store
//	hold      LiveHold, what retention's expiry leaves: every node of a run open in this Harness, or live by its agent's
//	          status, and of the runs its path crosses into (§24.10's retain row: expiry keeps a node while a live
//	          run's path needs it); blobs are not held
//
// Safe for concurrent use.

package sidecar

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The switch's file in the session component's store.
const sessionStorageAutoExpireName = "caps-auto-expire"

var (
	// An expiry or a switch that is not the person's confirmed act: nothing was erased or set.
	ErrSessionStorageUnconfirmed = errors.New("session storage: the person's confirmed act alone expires history")
)

// One run's history in the vault.
type SessionRunSize struct {
	RunId      Id     `json:"run"`
	AgentId    *Id    `json:"agent,omitempty"`
	AgentLabel string `json:"agent_label,omitempty"`
	Model      string `json:"model,omitempty"`
	// The device that wrote it: an agents' enclave is one of the member's devices.
	WriterSidecarId Id `json:"device"`
	// The run it continues, from its stage-2 context entry: a run and its continuations are one conversation.
	ContinuesRunId *Id   `json:"continues,omitempty"`
	FirstMillis    int64 `json:"first_millis"`
	LastMillis     int64 `json:"last_millis"`
	// Its session entries and blobs, and their bytes in the vault, blobs apart.
	NodeCount     int   `json:"node_count"`
	BlobCount     int   `json:"blob_count"`
	NodeByteCount int64 `json:"node_byte_count"`
	BlobByteCount int64 `json:"blob_byte_count"`
	// Bodies not in the vault: held by their writer past a cap, or dropped; and entries erased or expired.
	WithheldCount int `json:"withheld_count,omitempty"`
	DroppedCount  int `json:"dropped_count,omitempty"`
	ErasedCount   int `json:"erased_count,omitempty"`
	// Open in this device's Harness now.
	Open bool `json:"open,omitempty"`
}

// The bytes a run's history holds in all.
func (self *SessionRunSize) ByteCount() int64 {
	return self.NodeByteCount + self.BlobByteCount
}

// History by one agent or one device.
type SessionSizeGroup struct {
	Id            Id    `json:"id"`
	RunCount      int   `json:"run_count"`
	NodeByteCount int64 `json:"node_byte_count"`
	BlobByteCount int64 `json:"blob_byte_count"`
}

// One node of a run's tree, as the run view lists it.
type SessionTreeNode struct {
	NodeId       *Id              `json:"node,omitempty"`
	ParentNodeId *Id              `json:"parent,omitempty"`
	ParentRunId  *Id              `json:"parent_run,omitempty"`
	Type         SessionNodeType  `json:"type"`
	State        RecordEntryState `json:"state"`
	ByteCount    int              `json:"byte_count"`
	Untrusted    bool             `json:"untrusted,omitempty"`
	PartCount    int              `json:"part_count,omitempty"`
	// Parts this device does not hold, each reading as its marker.
	PrunedPartCount int    `json:"pruned_part_count,omitempty"`
	Invalid         string `json:"invalid,omitempty"`
}

// What the storage view lists (§24.10's see row; the sdk's Runs).
type SessionSizesFilter struct {
	// One agent's runs, by id or by its label.
	AgentId    *Id    `json:"agent,omitempty"`
	AgentLabel string `json:"agent_label,omitempty"`
	// One run, its tree with it where Tree is set.
	RunId *Id  `json:"run,omitempty"`
	Tree  bool `json:"tree,omitempty"`
	// Largest first, rather than newest.
	BySize bool `json:"by_size,omitempty"`
}

// The storage view.
type SessionSizes struct {
	LogId Id                `json:"log"`
	Runs  []*SessionRunSize `json:"runs"`
	// History's totals by agent and by device, and in all; the vault's every entry.
	ByAgent        []*SessionSizeGroup `json:"by_agent"`
	ByDevice       []*SessionSizeGroup `json:"by_device"`
	NodeByteCount  int64               `json:"node_byte_count"`
	BlobByteCount  int64               `json:"blob_byte_count"`
	VaultByteCount int64               `json:"vault_byte_count"`
	// The caps' state, and the largest runs where it warns; nil where no caps are read here.
	Caps    *SessionCapState  `json:"caps,omitempty"`
	Largest []*SessionRunSize `json:"largest,omitempty"`
	// A run's tree, where one was asked.
	Tree []*SessionTreeNode `json:"tree,omitempty"`
}

// What the warning's one tap asks (§24.10's see row).
type SessionExpireArgs struct {
	// The cap warned at: SessionCapNetwork or SessionCapMember; empty takes the caps' warning.
	Cap string
	// The person confirmed it on /dev/tty or in the app's UI.
	Confirmed bool
	// The caller has a harness process among its ancestors: refused.
	HarnessAncestor bool
}

// What an expiry erased.
type SessionExpired struct {
	// The blobs erased, their bytes, and the bytes the tap was to free.
	BlobCount  int   `json:"blob_count"`
	ByteCount  int64 `json:"byte_count"`
	NeedCount  int64 `json:"need_count"`
	ErasureIds []Id  `json:"erasures,omitempty"`
}

// What a SessionStorage runs on.
type SessionStorageArgs struct {
	Record *SidecarRecord
	// The Harness whose open runs the view marks and retention's hold keeps, read at use; nil, or nil answered, for
	// none. A Sidecar's is read at use since its Harness reaches the session component in turn.
	Harness func() *Harness
	// The caps; nil reads no caps here.
	Caps *SessionCaps
	// SKILL's agent status, for the hold; nil holds only this Harness's open runs.
	Live SessionRunLiveness
	// The session component's sealed store, where the switch is kept; nil keeps it in memory.
	Store    SidecarStore
	Settings *SessionSettings
}

// The storage view of one network's history. See the file header.
type SessionStorage struct {
	record   *SidecarRecord
	harness  func() *Harness
	caps     *SessionCaps
	live     SessionRunLiveness
	store    SidecarStore
	settings *SessionSettings

	expireLock sync.Mutex
}

// A storage view over args, its switch read back from the store.
func NewSessionStorage(args *SessionStorageArgs) (*SessionStorage, error) {
	if args == nil || args.Record == nil {
		return nil, errors.New("session storage needs the record")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSessionSettings()
	}
	storage := &SessionStorage{record: args.Record, harness: args.Harness, caps: args.Caps, live: args.Live, store: args.Store, settings: settings}
	if storage.caps != nil {
		on, err := storage.readAutoExpire()
		if err != nil {
			return nil, err
		}
		storage.caps.setAutoExpire(on)
	}
	return storage, nil
}

// The runs open in this device's Harness.
func (self *SessionStorage) openRuns() map[Id]bool {
	open := map[Id]bool{}
	if self.harness == nil {
		return open
	}
	harness := self.harness()
	if harness == nil {
		return open
	}
	for _, agent := range harness.Agents() {
		open[agent.Run().Id()] = true
	}
	return open
}

// The view (see the file header's sizes, runs, tree and caps rows). The caps are checked first where the view has them.
func (self *SessionStorage) Sizes(ctx context.Context, filter *SessionSizesFilter) (*SessionSizes, error) {
	if filter == nil {
		filter = &SessionSizesFilter{}
	}
	reader := self.record.SessionReader()
	vaultId, err := reader.VaultId()
	if err != nil {
		return nil, err
	}
	sizes := &SessionSizes{LogId: vaultId, Runs: []*SessionRunSize{}, ByAgent: []*SessionSizeGroup{}, ByDevice: []*SessionSizeGroup{}}
	if self.caps != nil {
		if sizes.Caps, err = self.caps.Check(ctx); err != nil && sizes.Caps == nil {
			return nil, err
		}
	} else if err := self.record.reader.Sync(ctx, vaultId); err != nil {
		return nil, err
	}
	open := self.openRuns()
	runs := map[Id]*SessionRunSize{}
	contexts := map[Id][]*RecordReadEntry{}
	for _, entry := range self.record.reader.Entries(vaultId) {
		header := entry.Header.Header
		size := sessionEntryByteCount(entry)
		sizes.VaultByteCount += size
		if len(header.GetRunId()) != len(Id{}) {
			continue
		}
		runId := recordIdOf(header.GetRunId())
		kind := entry.Kind()
		if kind == RecordKindContext {
			contexts[runId] = append(contexts[runId], entry)
		}
		if kind != RecordKindSessionEntry && kind != RecordKindSessionBlob {
			continue
		}
		run, ok := runs[runId]
		if !ok {
			run = &SessionRunSize{RunId: runId, WriterSidecarId: recordIdOf(header.GetWriterSidecarId()), FirstMillis: header.GetTimeMillis(), Open: open[runId]}
			runs[runId] = run
		}
		if agentId := header.GetAgentId(); len(agentId) == len(Id{}) && run.AgentId == nil {
			id := recordIdOf(agentId)
			run.AgentId = &id
		}
		run.FirstMillis = min(run.FirstMillis, header.GetTimeMillis())
		run.LastMillis = max(run.LastMillis, header.GetTimeMillis())
		switch {
		case entry.State.KeyGone():
			run.ErasedCount += 1
		case entry.State == RecordEntryWithheld:
			run.WithheldCount += 1
		case entry.State == RecordEntryDropped:
			run.DroppedCount += 1
		}
		if kind == RecordKindSessionEntry {
			run.NodeCount += 1
			run.NodeByteCount += size
			sizes.NodeByteCount += size
		} else {
			run.BlobCount += 1
			run.BlobByteCount += size
			sizes.BlobByteCount += size
		}
	}
	for runId, run := range runs {
		for _, entry := range contexts[runId] {
			body := &protocol.ContextBody{}
			if entry.Body == nil || proto.Unmarshal(entry.Body, body) != nil {
				continue
			}
			if body.GetAgentLabel() != "" {
				run.AgentLabel = body.GetAgentLabel()
			}
			if body.GetModel() != "" {
				run.Model = body.GetModel()
			}
			if continues := body.GetContinuesRunId(); len(continues) == len(Id{}) {
				id := recordIdOf(continues)
				run.ContinuesRunId = &id
			}
		}
	}
	byAgent := map[Id]*SessionSizeGroup{}
	byDevice := map[Id]*SessionSizeGroup{}
	for _, run := range runs {
		if run.AgentId != nil {
			sessionSizeGroupAdd(byAgent, *run.AgentId, run)
		}
		sessionSizeGroupAdd(byDevice, run.WriterSidecarId, run)
	}
	sizes.ByAgent = sessionSizeGroups(byAgent)
	sizes.ByDevice = sessionSizeGroups(byDevice)
	all := slices.Collect(maps.Values(runs))
	slices.SortFunc(all, func(a *SessionRunSize, b *SessionRunSize) int {
		if order := cmp.Compare(b.ByteCount(), a.ByteCount()); order != 0 {
			return order
		}
		return a.RunId.Cmp(b.RunId)
	})
	if sizes.Caps != nil && sizes.Caps.Warning != "" {
		sizes.Largest = all[:min(len(all), self.settings.WarningRunCount)]
	}
	if !filter.BySize {
		slices.SortStableFunc(all, func(a *SessionRunSize, b *SessionRunSize) int {
			if order := cmp.Compare(b.LastMillis, a.LastMillis); order != 0 {
				return order
			}
			return a.RunId.Cmp(b.RunId)
		})
	}
	for _, run := range all {
		switch {
		case filter.RunId != nil && run.RunId != *filter.RunId:
		case filter.AgentId != nil && (run.AgentId == nil || *run.AgentId != *filter.AgentId):
		case filter.AgentLabel != "" && run.AgentLabel != filter.AgentLabel:
		default:
			sizes.Runs = append(sizes.Runs, run)
		}
	}
	if filter.Tree && filter.RunId != nil {
		if sizes.Tree, err = self.tree(ctx, vaultId, *filter.RunId); err != nil {
			return nil, err
		}
	}
	return sizes, nil
}

// Adds run to its group.
func sessionSizeGroupAdd(groups map[Id]*SessionSizeGroup, id Id, run *SessionRunSize) {
	group, ok := groups[id]
	if !ok {
		group = &SessionSizeGroup{Id: id}
		groups[id] = group
	}
	group.RunCount += 1
	group.NodeByteCount += run.NodeByteCount
	group.BlobByteCount += run.BlobByteCount
}

// The groups, largest first.
func sessionSizeGroups(groups map[Id]*SessionSizeGroup) []*SessionSizeGroup {
	sorted := slices.Collect(maps.Values(groups))
	slices.SortFunc(sorted, func(a *SessionSizeGroup, b *SessionSizeGroup) int {
		if order := cmp.Compare(b.NodeByteCount+b.BlobByteCount, a.NodeByteCount+a.BlobByteCount); order != 0 {
			return order
		}
		return a.Id.Cmp(b.Id)
	})
	return sorted
}

// A run's tree, its bodies fetched only now.
func (self *SessionStorage) tree(ctx context.Context, vaultId Id, runId Id) ([]*SessionTreeNode, error) {
	view, err := self.record.SessionReader().Open(ctx, vaultId, runId)
	if err != nil {
		return nil, err
	}
	tree := []*SessionTreeNode{}
	for _, node := range view.Nodes {
		row := &SessionTreeNode{State: node.State, Untrusted: node.Untrusted}
		if node.Invalid != nil {
			row.Invalid = node.Invalid.Error()
		}
		if body := node.Body; body != nil {
			nodeId := recordIdOf(body.GetNodeId())
			row.NodeId = &nodeId
			if parent := body.GetParentNodeId(); len(parent) == len(Id{}) {
				parentId := recordIdOf(parent)
				row.ParentNodeId = &parentId
			}
			if parentRun := body.GetParentRunId(); len(parentRun) == len(Id{}) {
				parentRunId := recordIdOf(parentRun)
				row.ParentRunId = &parentRunId
			}
			row.Type = SessionNodeType(body.GetType())
			row.ByteCount = len(body.GetItem())
			if itemNode, ok := view.itemOf(node); ok {
				row.PartCount = len(itemNode.Body.GetParts())
				for _, part := range itemNode.Body.GetParts() {
					if _, held := itemNode.PartBytes[part.GetPointer()]; !held && !part.GetOmitted() {
						row.PrunedPartCount += 1
					}
				}
			}
		}
		tree = append(tree, row)
	}
	return tree, nil
}

// The warning's one tap (see the file header's expire row): the oldest blobs erased until history is under
// ExpiryTargetFraction of the cap warned at, every node kept.
func (self *SessionStorage) ExpireOldestBlobs(ctx context.Context, args *SessionExpireArgs) (*SessionExpired, error) {
	if args == nil || !args.Confirmed || args.HarnessAncestor {
		return nil, ErrSessionStorageUnconfirmed
	}
	return self.expireOldestBlobs(ctx, args.Cap)
}

// The tap's work, confirmed already: by the person, or by the person's switch at a cap.
func (self *SessionStorage) expireOldestBlobs(ctx context.Context, capName string) (*SessionExpired, error) {
	self.expireLock.Lock()
	defer self.expireLock.Unlock()
	if self.caps == nil {
		return nil, errors.New("session storage: no caps are read here")
	}
	state, err := self.caps.Check(ctx)
	if err != nil {
		return nil, err
	}
	need := state.ExpiryNeed
	if capName != "" && capName != state.Warning {
		// a cap the person named: what brings history under ExpiryTargetFraction of it
		used, base := state.MemberUsed, state.MemberCap
		if capName == SessionCapNetwork {
			used, base = state.NetworkUsed, state.StorageLimit
		}
		need = 0
		if 0 <= base {
			need = max(used-int64(self.settings.ExpiryTargetFraction*float64(base)), 0)
		}
	}
	expired := &SessionExpired{NeedCount: need}
	if need <= 0 {
		return expired, nil
	}
	vaultId := self.caps.vaultIdNow()
	blobs := []*RecordReadEntry{}
	for _, entry := range self.record.reader.Entries(vaultId) {
		if entry.Kind() == RecordKindSessionBlob && !entry.State.KeyGone() {
			blobs = append(blobs, entry)
		}
	}
	// the oldest first, by push time, which evs bounds
	slices.SortStableFunc(blobs, func(a *RecordReadEntry, b *RecordReadEntry) int {
		switch {
		case a.PushTimeMillis < b.PushTimeMillis:
			return -1
		case b.PushTimeMillis < a.PushTimeMillis:
			return 1
		}
		return a.EntryId.Cmp(b.EntryId)
	})
	chosen := []Id{}
	for _, blob := range blobs {
		if need <= expired.ByteCount {
			break
		}
		chosen = append(chosen, blob.EntryId)
		expired.ByteCount += sessionEntryByteCount(blob) - int64(len(blob.SignedBytes))
		expired.BlobCount += 1
	}
	eraser := self.record.Eraser()
	batch := max(eraser.settings.EntryCount, 1)
	for start := 0; start < len(chosen); start += batch {
		result, err := eraser.Erase(ctx, &RecordEraseArgs{LogId: vaultId, EntryIds: chosen[start:min(start+batch, len(chosen))],
			Reason: RecordErasureReasonPerson, Confirmed: true})
		if err != nil {
			return expired, err
		}
		expired.ErasureIds = append(expired.ErasureIds, result.ErasureId)
	}
	if _, err := self.caps.Check(ctx); err != nil {
		return expired, err
	}
	return expired, nil
}

// The vault the caps last checked.
func (self *SessionCaps) vaultIdNow() Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.vaultId
}

// The person's switch, as the store keeps it.
type sessionAutoExpireDocument struct {
	Version int  `json:"version"`
	On      bool `json:"on"`
}

// The switch's state in the store; off where none was written.
func (self *SessionStorage) readAutoExpire() (bool, error) {
	if self.store == nil {
		return false, nil
	}
	reader, err := self.store.Open(sessionStorageAutoExpireName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		return false, err
	}
	document := &sessionAutoExpireDocument{}
	if err := json.Unmarshal(content, document); err != nil || document.Version != 1 {
		return false, fmt.Errorf("%w: the history switch's state", ErrRecordChainCorrupt)
	}
	return document.On, nil
}

// Sets the person's switch that expires the oldest blobs again at each cap, their confirmed act; kept in the store.
func (self *SessionStorage) SetAutoExpire(on bool, confirmed bool, harnessAncestor bool) error {
	if !confirmed || harnessAncestor {
		return ErrSessionStorageUnconfirmed
	}
	if self.caps == nil {
		return errors.New("session storage: no caps are read here")
	}
	if self.store != nil {
		content, err := json.Marshal(&sessionAutoExpireDocument{Version: 1, On: on})
		if err != nil {
			return err
		}
		writer, err := self.store.Create(sessionStorageAutoExpireName)
		if err != nil {
			return err
		}
		defer writer.Close()
		if _, err := writer.Write(content); err != nil {
			return err
		}
		if err := writer.Commit(); err != nil {
			return err
		}
	}
	self.caps.setAutoExpire(on)
	return nil
}

// A check of the caps, and where the person's switch is on and history is at a cap, the tap's expiry: the session
// component's tick.
func (self *SessionStorage) Tick(ctx context.Context) (*SessionCapState, error) {
	if self.caps == nil {
		return nil, nil
	}
	state, err := self.caps.check(ctx, false)
	if err != nil {
		return state, err
	}
	if state.AutoExpire && state.Capped() {
		if _, err := self.expireOldestBlobs(ctx, ""); err != nil {
			return state, err
		}
		return self.caps.State(), nil
	}
	return state, nil
}

// What retention's expiry leaves of the vault (the file header's hold row): each session_entry of a run live now, open
// in this Harness or live by its agent's status, and of the runs those runs continue. Blobs are not held.
func (self *SessionStorage) LiveHold(ctx context.Context) (func(entry *RecordReadEntry) bool, error) {
	vaultId, err := self.record.SessionReader().VaultId()
	if err != nil {
		return nil, err
	}
	live := self.openRuns()
	runAgents := map[Id]Id{}
	continues := map[Id][]Id{}
	for _, entry := range self.record.reader.Entries(vaultId) {
		header := entry.Header.Header
		if len(header.GetRunId()) != len(Id{}) {
			continue
		}
		runId := recordIdOf(header.GetRunId())
		switch entry.Kind() {
		case RecordKindSessionEntry:
			if agentId := header.GetAgentId(); len(agentId) == len(Id{}) {
				runAgents[runId] = recordIdOf(agentId)
			}
		case RecordKindContext:
			body := &protocol.ContextBody{}
			if entry.Body != nil && proto.Unmarshal(entry.Body, body) == nil && len(body.GetContinuesRunId()) == len(Id{}) {
				continues[runId] = append(continues[runId], recordIdOf(body.GetContinuesRunId()))
			}
		}
	}
	if self.live != nil {
		for runId, agentId := range runAgents {
			if live[runId] {
				continue
			}
			state, err := self.live.RunState(ctx, agentId, runId)
			if err != nil {
				// a status that does not read holds the run, failing toward keeping
				live[runId] = true
				continue
			}
			if SessionAgentStateLive(state) || state == AgentStateIdle {
				live[runId] = true
			}
		}
	}
	// the runs a live run's path crosses into
	for changed := true; changed; {
		changed = false
		for runId := range live {
			for _, continued := range continues[runId] {
				if !live[continued] {
					live[continued] = true
					changed = true
				}
			}
		}
	}
	return func(entry *RecordReadEntry) bool {
		if entry.Kind() != RecordKindSessionEntry {
			return false
		}
		return live[recordIdOf(entry.Header.Header.GetRunId())]
	}, nil
}
