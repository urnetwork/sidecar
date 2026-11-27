//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.4 and §24.5's session journal (CTXH-M11-03; R-CTXH-1, R-CTXH-6, D-CTXH-1, D-CTXH-2, D-CTXH-3,
// D-CTXH-7, D-CTXH-11, D-CTXH-12, IC-19): the journal every model call writes its context through, the Harness's and
// the gateway's. Each node is one session_entry of its run, each large part session_blob entries of it, written
// through the record's writer, whose Append returns once each entry is durable in its fsynced journal or the spool.
//
//	node       one session_entry: a random 16-byte node id, its parent's within the run (or another run's at a
//	           continuation's root), its type, its item after §24.9's exceptions (session_exceptions.go), RFC 8785,
//	           its parts (session_parts.go), item_sha256 and chain_sha256 (session_format.go), the run's marks at
//	           capture, and the header's tainted bit the run's taint at capture; source observed, or hook for an item
//	           the gateway takes from a harness's request, which is that harness's word
//	dedup      the tree is the deduplication: a message is written once, and later calls name it by their input node
//	           and its path; an item the run already holds is a same_as node, a header and no bytes; a part the run
//	           already holds names its blobs again; bytes never cross runs, only a parent link does (Q-CTXH-5)
//	budget     the run stays under SidecarIngestSettings.RunHourByteCount a run-hour, past which parts go by hash and
//	           size, omitted, with the gap oversize, as a part past SessionPartWholeByteCount does
//	first      Journal returns only once every node it was handed is durable: a context that cannot be journaled is
//	           not sent, so the Harness journals each node before the call that carries it and each response item
//	           before the event that completes it; TurnEnd lets the turn's session entries leave (D-CTXH-12)
//
// Session entries ride (RecordDraft.Rides): they leave in their call's model_call's push, at the turn's end or the
// ride interval after the oldest, which the journal sets from SessionSettings.PushInterval. A node with parts is not
// journaled while the record spools, since its blobs' entry ids are drawn only at sealing; one without is, its draft
// durable in the spool.
//
// The run's journal state, its nodes' keys with their ids and chain hashes and its parts' blobs, is kept in the
// journal's sealed store, one file a node or part under runs/<run_id>/, so a resumed run names its earlier nodes; it
// holds hashes and ids, never an item.
//
// Safe for concurrent use: one Journal call at a time.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The journal state's format values.
const (
	sessionJournalRunsDirectory = "runs"
	sessionJournalNodePrefix    = "node-"
	sessionJournalPartPrefix    = "part-"
	sessionJournalStateVersion  = 1
)

// A node with parts while the record spools: its blobs' entry ids are drawn only when they seal, so it waits.
var ErrSessionJournalSpooled = errors.New("session journal cannot name a spooled part's blobs")

// What the journal writes through: the network's record, its writer and its riding pushes.
type SessionRecord interface {
	Writer() RecordWriter
	ReleaseRides()
	SetRideInterval(interval time.Duration)
}

// What a SessionJournal runs on.
type SessionJournalArgs struct {
	Record SessionRecord
	// The journal's sealed directory for its runs' state.
	Store SidecarStore
	// §16.7's redactor of the network's capture.
	Redactor *Redactor
	Settings *SessionSettings
	// The run-hour budget's settings, DESIGN §16.7's; nil takes the defaults.
	Ingest *SidecarIngestSettings
	Clock  Clock
	// crypto/rand's reader when nil: node ids draw from it.
	Random io.Reader
	// Counts a coverage gap against a run (RunStore.AddGap): oversize and redaction; nil drops it.
	Gap func(runId Id, code string)
}

// One node as journaled: its id, its hashes and its entry.
type SessionJournaled struct {
	Key         string
	NodeId      Id
	ItemSha256  [sha256.Size]byte
	ChainSha256 [sha256.Size]byte
	// The node is a same_as node of the earlier node SameAs names.
	SameAs *Id
	// Its session_entry, nil while it waits unsealed in the spool.
	Entry *RecordEntryRef
	// What §24.9's exceptions came to: markers in the item, and the form its tool result is kept in.
	Redactions int
	Stubs      int
	Form       SessionItemForm
	// The node's parts, omitted ones among them.
	Parts []*protocol.SessionPart
	// The item as recorded, RFC 8785 after the exceptions, each part at its pointer by its reference: a same_as node's
	// too, though its entry holds none. What a call's request_sha256 renders from (session_render.go).
	Item []byte
}

// The journal of one network's record. See the file header.
type SessionJournal struct {
	record   SessionRecord
	store    SidecarStore
	redactor *Redactor
	settings *SessionSettings
	ingest   *SidecarIngestSettings
	clock    Clock
	random   io.Reader
	gap      func(runId Id, code string)
	// whether history stops leaving the device now (§24.10's caps, session_cap.go): a part that would need a blob is
	// kept by hash and size; nil for never
	capped atomic.Pointer[func() bool]

	journalLock sync.Mutex
	stateLock   sync.Mutex
	runs        map[Id]*sessionJournalRun
}

// One run's state: its nodes by key, its items by hash, its parts' blobs by hash, and its run-hour's bytes.
type sessionJournalRun struct {
	keyNodes        map[string]*sessionJournalNodeState
	itemNodeIds     map[[sha256.Size]byte]Id
	partBlobs       map[[sha256.Size]byte][][]byte
	hourStartMillis int64
	hourByteCount   int64
}

// One node's state, as the store keeps it.
type sessionJournalNodeState struct {
	Version     int    `json:"version"`
	Key         string `json:"key"`
	NodeId      Id     `json:"node_id"`
	ItemSha256  []byte `json:"item_sha256"`
	ChainSha256 []byte `json:"chain_sha256"`
	SameAs      bool   `json:"same_as,omitempty"`
}

// One part's blobs, as the store keeps them.
type sessionJournalPartState struct {
	Version      int      `json:"version"`
	Sha256       []byte   `json:"sha256"`
	BlobEntryIds [][]byte `json:"blob_entry_ids"`
}

// A journal over args, which sets the record's ride interval from SessionSettings.PushInterval.
func NewSessionJournal(args *SessionJournalArgs) (*SessionJournal, error) {
	if args == nil || args.Record == nil || args.Store == nil || args.Redactor == nil {
		return nil, fmt.Errorf("%w: a session journal needs its record, store and redactor", ErrSessionNodeRefused)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSessionSettings()
	}
	ingest := args.Ingest
	if ingest == nil {
		ingest = defaultSidecarIngestSettings()
	}
	random := args.Random
	if random == nil {
		random = cryptorand.Reader
	}
	journal := &SessionJournal{
		record:   args.Record,
		store:    args.Store,
		redactor: args.Redactor,
		settings: settings,
		ingest:   ingest,
		clock:    clockOrReal(args.Clock),
		random:   random,
		gap:      args.Gap,
		runs:     map[Id]*sessionJournalRun{},
	}
	args.Record.SetRideInterval(settings.PushInterval)
	return journal, nil
}

// Sets the push interval from the harness config's record.session_push_secs, within its bounds.
func (self *SessionJournal) SetPushSecs(pushSecs int) {
	self.record.SetRideInterval(self.settings.PushIntervalFor(pushSecs))
}

// Sets what says history stops leaving the device (§24.10's caps): while it answers true a part that would need a blob
// is kept by hash and size, omitted, with the run's gap oversize. Nil, the default, never caps.
func (self *SessionJournal) SetCapped(capped func() bool) {
	if capped == nil {
		self.capped.Store(nil)
		return
	}
	self.capped.Store(&capped)
}

// Whether history is at a cap now.
func (self *SessionJournal) isCapped() bool {
	capped := self.capped.Load()
	return capped != nil && (*capped)()
}

// Lets the turn's session entries leave, in the run's next push (D-CTXH-12).
func (self *SessionJournal) TurnEnd(ctx context.Context, runId Id) error {
	self.record.ReleaseRides()
	return nil
}

// Counts a gap against the run.
func (self *SessionJournal) countGap(runId Id, code string) {
	if self.gap != nil {
		self.gap(runId, code)
	}
}

// The run's state directory.
func sessionJournalRunDirectory(runId Id) string {
	return sessionJournalRunsDirectory + "/" + hex.EncodeToString(runId[:]) + "/"
}

// The run's state, read from the store at its first use.
func (self *SessionJournal) runState(runId Id) (*sessionJournalRun, error) {
	held := func() *sessionJournalRun {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.runs[runId]
	}()
	if held != nil {
		return held, nil
	}
	run := &sessionJournalRun{
		keyNodes:    map[string]*sessionJournalNodeState{},
		itemNodeIds: map[[sha256.Size]byte]Id{},
		partBlobs:   map[[sha256.Size]byte][][]byte{},
	}
	directory := sessionJournalRunDirectory(runId)
	entries, err := self.store.List(directory)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		content, err := self.readState(entry.Name)
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(entry.Name, directory)
		switch {
		case strings.HasPrefix(name, sessionJournalNodePrefix):
			node := &sessionJournalNodeState{}
			if err := recordChainDecode(content, node); err != nil || node.Version != sessionJournalStateVersion ||
				len(node.ItemSha256) != sha256.Size || len(node.ChainSha256) != sha256.Size {
				return nil, fmt.Errorf("%w: a journaled node's state %s", ErrRecordChainCorrupt, entry.Name)
			}
			run.keyNodes[node.Key] = node
			if !node.SameAs {
				run.itemNodeIds[[sha256.Size]byte(node.ItemSha256)] = node.NodeId
			}
		case strings.HasPrefix(name, sessionJournalPartPrefix):
			part := &sessionJournalPartState{}
			if err := recordChainDecode(content, part); err != nil || part.Version != sessionJournalStateVersion || len(part.Sha256) != sha256.Size {
				return nil, fmt.Errorf("%w: a journaled part's state %s", ErrRecordChainCorrupt, entry.Name)
			}
			run.partBlobs[[sha256.Size]byte(part.Sha256)] = part.BlobEntryIds
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if held := self.runs[runId]; held != nil {
		return held, nil
	}
	self.runs[runId] = run
	return run, nil
}

// A state file's bytes.
func (self *SessionJournal) readState(name string) ([]byte, error) {
	reader, err := self.store.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Writes a state file durably.
func (self *SessionJournal) writeState(name string, document any) error {
	content, err := json.Marshal(document)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// Whether the run's hour may take size more bytes, counting them when it may: a run-hour from the first byte charged
// to it, RunHourByteCount within it.
func (self *SessionJournal) chargeRunHour(run *sessionJournalRun, size int64) bool {
	nowMillis := self.clock.Now().UnixMilli()
	if run.hourStartMillis == 0 || self.ingest.RunHourInterval.Milliseconds() <= nowMillis-run.hourStartMillis {
		run.hourStartMillis = nowMillis
		run.hourByteCount = 0
	}
	if self.ingest.RunHourByteCount < run.hourByteCount+size {
		return false
	}
	run.hourByteCount += size
	return true
}

// Journals nodes of run, in order, each durable when this returns: see the file header. The first refusal stops it,
// the nodes before it journaled and named in what it answers.
func (self *SessionJournal) Journal(ctx context.Context, run *SessionRun, nodes ...*SessionNode) ([]*SessionJournaled, error) {
	if run == nil || run.RunId == (Id{}) {
		return nil, fmt.Errorf("%w: no run", ErrSessionNodeRefused)
	}
	self.journalLock.Lock()
	defer self.journalLock.Unlock()
	state, err := self.runState(run.RunId)
	if err != nil {
		return nil, err
	}
	journaled := []*SessionJournaled{}
	for _, node := range nodes {
		if err := ctx.Err(); err != nil {
			return journaled, err
		}
		written, err := self.journalNode(state, run, node)
		if err != nil {
			return journaled, err
		}
		journaled = append(journaled, written)
	}
	return journaled, nil
}

// One node: its parent, its exceptions and parts, its blobs, then its entry, then its state.
func (self *SessionJournal) journalNode(state *sessionJournalRun, run *SessionRun, node *SessionNode) (*SessionJournaled, error) {
	if node == nil {
		return nil, fmt.Errorf("%w: no node", ErrSessionNodeRefused)
	}
	if err := node.check(); err != nil {
		return nil, err
	}
	if _, held := state.keyNodes[node.Key]; held {
		return nil, fmt.Errorf("%w: key %q journaled already", ErrSessionNodeRefused, node.Key)
	}
	body := &protocol.SessionEntryBody{Type: uint32(node.Type), Marks: run.Marks & recordSessionMarkBits}
	var parentChain []byte
	switch {
	case node.ParentKey != "":
		parent, ok := state.keyNodes[node.ParentKey]
		if !ok {
			return nil, fmt.Errorf("%w: a parent the run has not journaled", ErrSessionNodeRefused)
		}
		body.ParentNodeId = parent.NodeId.Bytes()
		parentChain = parent.ChainSha256
	case node.ParentNodeId != nil:
		// a continuation's root: another run's node, a parent link and no bytes (§24.7)
		body.ParentNodeId = node.ParentNodeId.Bytes()
		body.ParentRunId = node.ParentRunId.Bytes()
		parentChain = node.ParentChainSha256
	}
	value, err := sessionDecodeJson(node.Item)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionNodeRefused, err)
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, fmt.Errorf("%w: an item that is no JSON object", ErrSessionNodeRefused)
	}
	value, counts, err := sessionApplyExceptions(value, node.Tool, self.redactor)
	if err != nil {
		return nil, err
	}
	recordBody := self.settings.body()
	oversize := 0
	item, cuts, err := sessionCutParts(value, recordBody, func(size uint64) bool {
		// at a cap a part that would need a blob is kept by hash and size, the run's gap oversize (§24.10)
		return !self.isCapped() && self.chargeRunHour(state, int64(size))
	})
	if err != nil {
		return nil, err
	}
	itemSha256 := sessionItemSha256(item)
	chainSha256 := sessionChainSha256(parentChain, itemSha256[:])
	nodeId, err := self.drawNodeId()
	if err != nil {
		return nil, err
	}
	body.NodeId = nodeId.Bytes()
	body.ItemSha256 = itemSha256[:]
	body.ChainSha256 = chainSha256[:]
	body.Redactions = uint32(counts.redactions)
	body.Stubs = uint32(counts.stubs)
	written := &SessionJournaled{
		Key: node.Key, NodeId: nodeId, ItemSha256: itemSha256, ChainSha256: chainSha256,
		Redactions: counts.redactions, Stubs: counts.stubs, Form: counts.form, Item: item,
	}
	if earlier, ok := state.itemNodeIds[itemSha256]; ok {
		// an item the run holds already: a header, not its bytes
		body.SameAs = earlier.Bytes()
		written.SameAs = &earlier
	} else {
		// the item's own bytes count against the run-hour
		self.chargeRunHour(state, int64(len(item)))
		body.Item = item
		for _, cut := range cuts {
			if cut.part.GetOmitted() {
				oversize += 1
				body.Parts = append(body.Parts, cut.part)
				continue
			}
			blobIds, err := self.writeBlobs(state, run, node, cut)
			if err != nil {
				return nil, err
			}
			cut.part.BlobEntryIds = blobIds
			body.Parts = append(body.Parts, cut.part)
		}
	}
	written.Parts = body.Parts
	source := RecordSourceObserved
	if node.FromHarness {
		source = RecordSourceHook
	}
	refs, err := self.record.Writer().Append(&RecordDraft{
		Kind: RecordKindSessionEntry, Source: source, RunId: &run.RunId, AgentId: run.AgentId, Body: body, Rides: true,
	})
	if err != nil {
		return nil, err
	}
	if len(refs) == 1 && !refs[0].Spooled {
		written.Entry = refs[0]
	}
	nodeState := &sessionJournalNodeState{
		Version: sessionJournalStateVersion, Key: node.Key, NodeId: nodeId,
		ItemSha256: bytes.Clone(itemSha256[:]), ChainSha256: bytes.Clone(chainSha256[:]), SameAs: written.SameAs != nil,
	}
	if err := self.writeState(sessionJournalRunDirectory(run.RunId)+sessionJournalNodePrefix+hex.EncodeToString([]byte(node.Key)), nodeState); err != nil {
		return nil, err
	}
	state.keyNodes[node.Key] = nodeState
	if written.SameAs == nil {
		state.itemNodeIds[itemSha256] = nodeId
	}
	for range oversize {
		self.countGap(run.RunId, RecordCoverageGapOversize)
	}
	if 0 < counts.redactions {
		self.countGap(run.RunId, RecordCoverageGapRedaction)
	}
	return written, nil
}

// A part's blobs: the run's own where it holds the part already, else its pieces written as session_blob entries,
// each riding, their entry ids in order. A blob that spools cannot be named, and the node waits.
func (self *SessionJournal) writeBlobs(state *sessionJournalRun, run *SessionRun, node *SessionNode, cut *sessionPartCut) ([][]byte, error) {
	partSha256 := [sha256.Size]byte(cut.part.GetSha256())
	if held, ok := state.partBlobs[partSha256]; ok {
		// the run holds this part already: its blobs again, no bytes
		return held, nil
	}
	settings := self.settings.body()
	pieces := sessionPartPieces(cut.content, settings.BlobByteCount)
	if settings.SessionBlobPieceCount < len(pieces) {
		return nil, fmt.Errorf("%w: a part in %d pieces", ErrSessionNodeRefused, len(pieces))
	}
	source := RecordSourceObserved
	if node.FromHarness {
		source = RecordSourceHook
	}
	blobIds := [][]byte{}
	for index, piece := range pieces {
		refs, err := self.record.Writer().Append(&RecordDraft{
			Kind: RecordKindSessionBlob, Source: source, RunId: &run.RunId, AgentId: run.AgentId, Rides: true,
			Body: &protocol.SessionBlobBody{PartSha256: partSha256[:], Index: uint32(index), Count: uint32(len(pieces)), Content: piece},
		})
		if err != nil {
			return nil, err
		}
		if len(refs) != 1 || refs[0].Spooled {
			return nil, fmt.Errorf("%w: %s", ErrSessionJournalSpooled, cut.part.GetPointer())
		}
		blobIds = append(blobIds, refs[0].EntryId.Bytes())
	}
	if err := self.writeState(sessionJournalRunDirectory(run.RunId)+sessionJournalPartPrefix+hex.EncodeToString(partSha256[:]),
		&sessionJournalPartState{Version: sessionJournalStateVersion, Sha256: partSha256[:], BlobEntryIds: blobIds}); err != nil {
		return nil, err
	}
	state.partBlobs[partSha256] = blobIds
	return blobIds, nil
}

// Counts a response lost before it was journaled, a kill between the response and its journal: the run's coverage
// names the gap downtime, since the call's context stands and its answer does not (§24.16's completeness row). The
// Harness calls it as it resumes a run whose last call has no response node.
func (self *SessionJournal) MarkLostResponse(runId Id) {
	self.countGap(runId, RecordCoverageGapDowntime)
}

// 16 random bytes: a node id, never derived from content.
func (self *SessionJournal) drawNodeId() (Id, error) {
	var nodeId Id
	if _, err := io.ReadFull(self.random, nodeId[:]); err != nil {
		return Id{}, fmt.Errorf("session journal: draw: %w", err)
	}
	return nodeId, nil
}

// The node a key of a run names, false for one the run has not journaled: what a caller builds a call's context from.
func (self *SessionJournal) Node(runId Id, key string) (Id, [sha256.Size]byte, bool) {
	state, err := self.runState(runId)
	if err != nil {
		return Id{}, [sha256.Size]byte{}, false
	}
	self.journalLock.Lock()
	defer self.journalLock.Unlock()
	node, ok := state.keyNodes[key]
	if !ok {
		return Id{}, [sha256.Size]byte{}, false
	}
	return node.NodeId, [sha256.Size]byte(node.ChainSha256), true
}
