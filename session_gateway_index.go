//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.8's index (CTXH-M12-01; R-CTXH-6, D-CTXH-2, D-CTXH-6): what the gateway's recorder keeps of each run
// it recorded a call in, so a later request of the run finds the longest prefix the run holds. It holds hashes and ids,
// never an item.
//
//	runs      one per run with a call in the last SessionSettings.GatewayIndexWindow: its grant, its last call, the
//	          runs it continues (a resumed session's earlier run, §24.8's resume row), the nodes the recorder journaled
//	          or met in it by chain hash, each with its id, its session_entry where known and whether a part of it was
//	          kept by hash alone, and the SHA-256 of each request id its calls answered
//	lookups   which node a chain hash names is the session journal's to say: it keeps every node under its key,
//	          c<chain hex> for a node of a request's or a response's chain and s<chain hex> for a system node, past the
//	          window too, so a node the index does not know, from before the window or from a call a crash cut before
//	          its end, is still found; its exactness is unknown, and a call that takes it reads inexact
//	segments  each call's end writes one segment, <run hex>/<millis>-<count>, into the daemon's sealed state; every
//	          run's segments are read at the index's first use, and a run past the window is dropped, segments and all
//	rebuild   a run continued after the window is indexed again from its nodes as the journal holds them, their ids
//	          and chain hashes; what the vault's bodies would add, each node's exactness, is not read back (CTXH-M12-01's
//	          report), so such a call reads inexact
//	forms     the recorded forms of a run's items, by the item's own hash, kept in memory alone, up to
//	          SessionSettings.GatewayFormByteCount a run, so a request that repeats the session's history is redacted
//	          and hashed only for its new items
//
// Safe for concurrent use: stateLock guards the maps, loadLock the first read, and neither is held across a store's
// write or removal.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// The index's format value.
const sessionGatewayIndexVersion = 1

// A segment that does not read: the index refuses to answer from a state it cannot trust.
var ErrSessionGatewayIndexCorrupt = errors.New("session gateway index corrupt")

// One node as the index knows it.
type sessionGatewayIndexNode struct {
	NodeId Id `json:"node_id"`
	// Its session_entry, nil where the journal spooled it or the index met it without one.
	EntryId *Id `json:"entry_id,omitempty"`
	// A part of it was kept by hash and size alone, past the part cap, the run-hour budget or a storage cap.
	Omitted bool `json:"omitted,omitempty"`
}

// One run as the index holds it.
type sessionGatewayIndexRun struct {
	runId          Id
	grantId        Id
	lastCallMillis int64
	// the runs this one took a parent from, in the order taken
	continues []Id
	// by chain hash: request and response nodes under chainNodes, system nodes under systemNodes
	chainNodes  map[[sha256.Size]byte]*sessionGatewayIndexNode
	systemNodes map[[sha256.Size]byte]*sessionGatewayIndexNode
	// whether a part of a node, by its id, was kept by hash alone
	nodeIdOmitted map[Id]bool
	// memory alone: the recorded forms of its items by their own hash, and their bytes
	forms         map[[sha256.Size]byte]*sessionGatewayForm
	formByteCount int
}

// One segment as stored: what one call added to its run.
type sessionGatewayIndexSegment struct {
	Version   int                               `json:"version"`
	RunId     Id                                `json:"run_id"`
	GrantId   Id                                `json:"grant_id"`
	Millis    int64                             `json:"millis"`
	Continues []Id                              `json:"continues,omitempty"`
	Nodes     []*sessionGatewayIndexSegmentNode `json:"nodes,omitempty"`
	// lowercase hex SHA-256 of each request id the call answered
	RequestIdSha256s []string `json:"request_id_sha256s,omitempty"`
}

// One node of a segment.
type sessionGatewayIndexSegmentNode struct {
	// lowercase hex
	ChainSha256 string `json:"chain_sha256"`
	System      bool   `json:"system,omitempty"`
	sessionGatewayIndexNode
}

// What one call adds to its run's index at its end.
type sessionGatewayIndexAdd struct {
	runId     Id
	grantId   Id
	continues []Id
	chain     map[[sha256.Size]byte]*sessionGatewayIndexNode
	system    map[[sha256.Size]byte]*sessionGatewayIndexNode
	requestId string
}

// The gateway recorder's index. See the file header.
type SessionGatewayIndex struct {
	store    SidecarStore
	settings *SessionSettings
	clock    Clock

	loadLock sync.Mutex
	loaded   bool
	loadErr  error

	stateLock sync.Mutex
	runs      map[Id]*sessionGatewayIndexRun
	// each request id's SHA-256, with the millis of the call that answered it
	requestIdSha256Millis map[[sha256.Size]byte]int64
	// each run's segment names, for the sweep
	runSegmentNames map[Id][]string
	// the segments this process wrote
	segmentCount uint64
}

// An index over store, whose segments it reads at its first use.
func NewSessionGatewayIndex(store SidecarStore, settings *SessionSettings, clock Clock) (*SessionGatewayIndex, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: an index needs its store", ErrSessionGatewayRefused)
	}
	if settings == nil {
		settings = DefaultSessionSettings()
	}
	return &SessionGatewayIndex{
		store:                 store,
		settings:              settings,
		clock:                 clockOrReal(clock),
		runs:                  map[Id]*sessionGatewayIndexRun{},
		requestIdSha256Millis: map[[sha256.Size]byte]int64{},
		runSegmentNames:       map[Id][]string{},
	}, nil
}

// A run's directory in the store.
func sessionGatewayIndexRunDirectory(runId Id) string {
	return hex.EncodeToString(runId[:]) + "/"
}

// A fresh run.
func newSessionGatewayIndexRun(runId Id, grantId Id) *sessionGatewayIndexRun {
	return &sessionGatewayIndexRun{
		runId:         runId,
		grantId:       grantId,
		chainNodes:    map[[sha256.Size]byte]*sessionGatewayIndexNode{},
		systemNodes:   map[[sha256.Size]byte]*sessionGatewayIndexNode{},
		nodeIdOmitted: map[Id]bool{},
		forms:         map[[sha256.Size]byte]*sessionGatewayForm{},
	}
}

// Reads every segment once, dropping the runs past the window. A segment that does not read fails the index for good,
// so it never answers from a state it cannot trust.
func (self *SessionGatewayIndex) load() error {
	self.loadLock.Lock()
	defer self.loadLock.Unlock()
	if self.loaded {
		return self.loadErr
	}
	self.loaded = true
	entries, err := self.store.List("")
	if err != nil {
		self.loadErr = err
		return err
	}
	segments := []*sessionGatewayIndexSegment{}
	names := []string{}
	for _, entry := range entries {
		content, err := self.read(entry.Name)
		if err != nil {
			self.loadErr = err
			return err
		}
		segment := &sessionGatewayIndexSegment{}
		if err := recordChainDecode(content, segment); err != nil || segment.Version != sessionGatewayIndexVersion ||
			!strings.HasPrefix(entry.Name, sessionGatewayIndexRunDirectory(segment.RunId)) {
			self.loadErr = fmt.Errorf("%w: segment %s", ErrSessionGatewayIndexCorrupt, entry.Name)
			return self.loadErr
		}
		segments = append(segments, segment)
		names = append(names, entry.Name)
	}
	for i, segment := range segments {
		if err := self.apply(segment, names[i]); err != nil {
			self.loadErr = err
			return err
		}
	}
	return nil
}

// A store file's bytes.
func (self *SessionGatewayIndex) read(name string) ([]byte, error) {
	reader, err := self.store.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Adds a segment read or written to the maps.
func (self *SessionGatewayIndex) apply(segment *sessionGatewayIndexSegment, name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run, ok := self.runs[segment.RunId]
	if !ok {
		run = newSessionGatewayIndexRun(segment.RunId, segment.GrantId)
		self.runs[segment.RunId] = run
	}
	if run.grantId != segment.GrantId {
		return fmt.Errorf("%w: run %s under two grants", ErrSessionGatewayIndexCorrupt, segment.RunId)
	}
	run.lastCallMillis = max(run.lastCallMillis, segment.Millis)
	for _, continued := range segment.Continues {
		if !idsContain(run.continues, continued) {
			run.continues = append(run.continues, continued)
		}
	}
	for _, node := range segment.Nodes {
		chain, err := hex.DecodeString(node.ChainSha256)
		if err != nil || len(chain) != sha256.Size {
			return fmt.Errorf("%w: a node's chain hash", ErrSessionGatewayIndexCorrupt)
		}
		indexed := node.sessionGatewayIndexNode
		if node.System {
			run.systemNodes[[sha256.Size]byte(chain)] = &indexed
		} else {
			run.chainNodes[[sha256.Size]byte(chain)] = &indexed
		}
		run.nodeIdOmitted[indexed.NodeId] = indexed.Omitted
	}
	for _, digest := range segment.RequestIdSha256s {
		requestIdSha256, err := hex.DecodeString(digest)
		if err != nil || len(requestIdSha256) != sha256.Size {
			return fmt.Errorf("%w: a request id's hash", ErrSessionGatewayIndexCorrupt)
		}
		self.requestIdSha256Millis[[sha256.Size]byte(requestIdSha256)] = max(self.requestIdSha256Millis[[sha256.Size]byte(requestIdSha256)], segment.Millis)
	}
	self.runSegmentNames[segment.RunId] = append(self.runSegmentNames[segment.RunId], name)
	return nil
}

// Whether ids holds id.
func idsContain(ids []Id, id Id) bool {
	for _, held := range ids {
		if held == id {
			return true
		}
	}
	return false
}

// Drops every run whose last call is older than the window, segments and all, and the request ids answered before it.
func (self *SessionGatewayIndex) Sweep() error {
	if err := self.load(); err != nil {
		return err
	}
	cutoffMillis := self.clock.Now().Add(-self.settings.GatewayIndexWindow).UnixMilli()
	names := func() []string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		names := []string{}
		for runId, run := range self.runs {
			if run.lastCallMillis < cutoffMillis {
				names = append(names, self.runSegmentNames[runId]...)
				delete(self.runs, runId)
				delete(self.runSegmentNames, runId)
			}
		}
		for requestIdSha256, millis := range self.requestIdSha256Millis {
			if millis < cutoffMillis {
				delete(self.requestIdSha256Millis, requestIdSha256)
			}
		}
		return names
	}()
	for _, name := range names {
		if err := self.store.Remove(name); err != nil {
			return err
		}
	}
	return nil
}

// The run's grant and whether the index holds the run.
func (self *SessionGatewayIndex) grantOf(runId Id) (Id, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run, ok := self.runs[runId]
	if !ok {
		return Id{}, false
	}
	return run.grantId, true
}

// The runs a request of runId looks for its prefix in, its own first: the runs it continues, transitively, then
// resumed, each once, at most GatewayResumeRunCount.
func (self *SessionGatewayIndex) candidates(runId Id, resumed []Id) []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := max(self.settings.GatewayResumeRunCount, 1)
	runIds := []Id{runId}
	for at := 0; at < len(runIds) && len(runIds) < count; at += 1 {
		if run, ok := self.runs[runIds[at]]; ok {
			for _, continued := range run.continues {
				if !idsContain(runIds, continued) && len(runIds) < count {
					runIds = append(runIds, continued)
				}
			}
		}
	}
	for _, resumedRunId := range resumed {
		if !idsContain(runIds, resumedRunId) && len(runIds) < count {
			runIds = append(runIds, resumedRunId)
		}
	}
	return runIds
}

// What the index knows of a node of runId by its chain hash: nil where it does not know it.
func (self *SessionGatewayIndex) node(runId Id, chainSha256 [sha256.Size]byte, system bool) *sessionGatewayIndexNode {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run, ok := self.runs[runId]
	if !ok {
		return nil
	}
	nodes := run.chainNodes
	if system {
		nodes = run.systemNodes
	}
	node, ok := nodes[chainSha256]
	if !ok {
		return nil
	}
	copied := *node
	return &copied
}

// Whether a part of the node nodeId of runId was kept by hash alone, and whether the index knows the node.
func (self *SessionGatewayIndex) omitted(runId Id, nodeId Id) (bool, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run, ok := self.runs[runId]
	if !ok {
		return false, false
	}
	omitted, known := run.nodeIdOmitted[nodeId]
	return omitted, known
}

// The recorded form of an item of runId by the item's own hash, nil where none is kept.
func (self *SessionGatewayIndex) form(runId Id, rawSha256 [sha256.Size]byte) *sessionGatewayForm {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run, ok := self.runs[runId]
	if !ok {
		return nil
	}
	return run.forms[rawSha256]
}

// Keeps form for runId while the run's forms stay within GatewayFormByteCount, dropping them all once they would not.
func (self *SessionGatewayIndex) keepForm(runId Id, grantId Id, form *sessionGatewayForm) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run, ok := self.runs[runId]
	if !ok {
		// a run with no call yet: indexed now, its forms kept from its first request
		run = newSessionGatewayIndexRun(runId, grantId)
		run.lastCallMillis = self.clock.Now().UnixMilli()
		self.runs[runId] = run
	}
	byteCount := len(form.raw) + len(form.item)
	if self.settings.GatewayFormByteCount < run.formByteCount+byteCount {
		clear(run.forms)
		run.formByteCount = 0
		if self.settings.GatewayFormByteCount < byteCount {
			return
		}
	}
	if _, held := run.forms[form.rawSha256]; held {
		return
	}
	run.forms[form.rawSha256] = form
	run.formByteCount += byteCount
}

// Holds a node a call journaled in memory, before the call's end writes it: a concurrent call of the run, and the
// call's own same_as nodes, read it known.
func (self *SessionGatewayIndex) note(runId Id, grantId Id, chainSha256 [sha256.Size]byte, system bool, node *sessionGatewayIndexNode) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run, ok := self.runs[runId]
	if !ok {
		run = newSessionGatewayIndexRun(runId, grantId)
		run.lastCallMillis = self.clock.Now().UnixMilli()
		self.runs[runId] = run
	}
	copied := *node
	if system {
		run.systemNodes[chainSha256] = &copied
	} else {
		run.chainNodes[chainSha256] = &copied
	}
	run.nodeIdOmitted[node.NodeId] = node.Omitted
}

// Whether a call of the gateway's answered requestId within the window.
func (self *SessionGatewayIndex) RequestSeen(requestId string) (bool, error) {
	if err := self.load(); err != nil {
		return false, err
	}
	requestIdSha256 := sha256.Sum256([]byte(requestId))
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	_, seen := self.requestIdSha256Millis[requestIdSha256]
	return seen, nil
}

// Whether the index holds a call of the run: the gateway recorded in it within the window.
func (self *SessionGatewayIndex) Recorded(runId Id) (bool, error) {
	if err := self.load(); err != nil {
		return false, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run, ok := self.runs[runId]
	return ok && 0 < len(self.runSegmentNames[runId]) && run.lastCallMillis != 0, nil
}

// Writes what a call added as one segment, durably, then holds it.
func (self *SessionGatewayIndex) add(add *sessionGatewayIndexAdd) error {
	if err := self.load(); err != nil {
		return err
	}
	nowMillis := self.clock.Now().UnixMilli()
	segment := &sessionGatewayIndexSegment{
		Version:   sessionGatewayIndexVersion,
		RunId:     add.runId,
		GrantId:   add.grantId,
		Millis:    nowMillis,
		Continues: add.continues,
	}
	appendNodes := func(nodes map[[sha256.Size]byte]*sessionGatewayIndexNode, system bool) {
		for chainSha256, node := range nodes {
			segment.Nodes = append(segment.Nodes, &sessionGatewayIndexSegmentNode{
				ChainSha256: hex.EncodeToString(chainSha256[:]), System: system, sessionGatewayIndexNode: *node,
			})
		}
	}
	appendNodes(add.chain, false)
	appendNodes(add.system, true)
	if add.requestId != "" {
		requestIdSha256 := sha256.Sum256([]byte(add.requestId))
		segment.RequestIdSha256s = []string{hex.EncodeToString(requestIdSha256[:])}
	}
	content, err := json.Marshal(segment)
	if err != nil {
		return err
	}
	// the millis order a run's segments; the process's count keeps two of one milli apart
	segmentCount := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.segmentCount += 1
		return self.segmentCount
	}()
	name := sessionGatewayIndexRunDirectory(add.runId) + fmt.Sprintf("%016x-%016x", nowMillis, segmentCount)
	writer, err := self.store.Create(name)
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
	return self.apply(segment, name)
}

// A part list's omitted flag: whether any part was kept by hash alone.
func sessionPartsOmitted(parts []*protocol.SessionPart) bool {
	for _, part := range parts {
		if part.GetOmitted() {
			return true
		}
	}
	return false
}
