//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.6's and §24.7's reader of a run's session (CTXH-M11-04; R-CTXH-2, CF-18's first steps, D-CTXH-9,
// D-CTXH-10): a run's nodes as this device's record reads them from the vault.
//
//	headers   Headers reads the run's session entries from the log's sync alone, every header verified by the
//	          record's reader and no body fetched, as a phone holds a run it has not opened
//	open      Open fetches the run's bodies, its nodes' and its blobs', only now, as a run is opened, continued,
//	          forked or exported (RecordReader.FetchBodies), each held to its header's commitment as it comes; a log's
//	          mirror fetches every body at its syncs
//	writers   a run's nodes are its runner's, the writer of its model calls, or of most of its nodes where it holds
//	          none: a node another writer filed in the run is shown invalid and alarmed
//	chains    each node held to its item_sha256, or its same_as node's, its parts' references in its item, and its
//	          chain_sha256 to its parent's (SessionNodeCheck); a node whose parent's body this device does not hold, or
//	          another run's, is checked without its chain, the parent unread; a parent the run does not hold when every
//	          body is held is invalid
//	blobs     each part kept whole is assembled from its session_blob pieces and held to its sha256
//	          (SessionPartAssemble); a piece that fails it shows the node invalid and alarms, a piece not held, pruned,
//	          expired or not fetched, leaves the part not held, which a rebuild reads unverifiable, never a fault
//	trust     a node is untrusted when its header is flagged, or a tagged sidecar other than the member's own enclave
//	          wrote it (D-CTXH-9), its taint bit then its own word; untrusted nodes taint what continues or forks from
//	          them and return from record_query as stubs
//
// Bodies are held in memory for the view's life, as the record's reader holds them; a phone's offload of large runs to
// storage is the review phase's (QD-641). Safe for concurrent use: a view is the caller's.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The run holds no session entry this device reads in the log.
	ErrSessionRunUnknown = errors.New("session run unknown")
)

// One node of a run as the reader holds it.
type SessionReadNode struct {
	EntryId         Id
	WriterSidecarId Id
	Seq             uint64
	TimeMillis      int64
	State           RecordEntryState
	Flagged         bool
	Source          RecordSource
	// The node's body as recorded, nil while it is away (deferred, withheld, dropped), erased or invalid.
	Body *protocol.SessionEntryBody
	// What the reader's checks found against the node: a body that did not open or commit, its hashes, its same_as,
	// its parts or its parent chain, or a writer not the run's. Nil while it passes or its body is not held.
	Invalid error
	// Flagged, or written by a tagged sidecar other than the member's own enclave (the file header's trust row).
	Untrusted bool
	// Each part's bytes assembled from its pieces and checked, by pointer; a part omitted or not held is absent.
	PartBytes map[string][]byte
}

// The node's id, false while its body is not held.
func (self *SessionReadNode) NodeId() (Id, bool) {
	if self.Body == nil {
		return Id{}, false
	}
	return recordIdOf(self.Body.GetNodeId()), true
}

// One piece of a part, as the reader holds it.
type SessionReadBlob struct {
	EntryId Id
	State   RecordEntryState
	// Nil while its body is away, erased or invalid.
	Body *protocol.SessionBlobBody
}

// One model call of the run.
type SessionReadCall struct {
	EntryId         Id
	WriterSidecarId Id
	Seq             uint64
	TimeMillis      int64
	// Nil while its body is not held.
	Body *protocol.ModelCallBody
}

// A run's session as one read found it.
type SessionRunView struct {
	LogId Id
	RunId Id
	// Every session_entry of the run, in the log's read order, held or not.
	Nodes []*SessionReadNode
	// Every session_blob of the run, by entry id.
	Blobs map[Id]*SessionReadBlob
	// The run's model calls, in the log's read order.
	Calls []*SessionReadCall
	// Bodies this read fetched.
	Fetched int
	// the nodes whose bodies are held, by node id
	nodeIds map[Id]*SessionReadNode
	// some node of the run is not held, so an unknown node id may be its
	unheld bool
}

// The node of nodeId, false while no held node of the run has it.
func (self *SessionRunView) Node(nodeId Id) (*SessionReadNode, bool) {
	node, ok := self.nodeIds[nodeId]
	return node, ok
}

// The node's item and parts as a render reads them: its own, or the node its same_as names.
func (self *SessionRunView) itemOf(node *SessionReadNode) (*SessionReadNode, bool) {
	if node.Body == nil {
		return nil, false
	}
	sameAs := node.Body.GetSameAs()
	if len(sameAs) == 0 {
		return node, true
	}
	named, ok := self.nodeIds[recordIdOf(sameAs)]
	if !ok || named.Body == nil {
		return nil, false
	}
	return named, true
}

// The run's model call at the 1-based index n of its calls, in read order.
func (self *SessionRunView) Call(n int) (*SessionReadCall, bool) {
	if n < 1 || len(self.Calls) < n {
		return nil, false
	}
	return self.Calls[n-1], true
}

// The reader of a record's sessions.
type SessionReader struct {
	record *SidecarRecord
}

// The record's session reader.
func (self *SidecarRecord) SessionReader() *SessionReader {
	return &SessionReader{record: self}
}

// The vault this device reads its runs in: its author's, the member's or its sponsor's, which it must read.
func (self *SessionReader) VaultId() (Id, error) {
	auth := self.record.writer.auth()
	route, err := recordVaultRoute(auth, self.record.writer.sidecarId)
	if err != nil {
		return Id{}, err
	}
	if !auth.Reads(route.logId, self.record.writer.sidecarId) {
		return Id{}, fmt.Errorf("%w: %s", ErrRecordNotReader, route.logId)
	}
	return route.logId, nil
}

// Whether an entry is the run's.
func sessionEntryOfRun(entry *RecordReadEntry, runId Id) bool {
	return bytes.Equal(entry.Header.Header.GetRunId(), runId[:])
}

// The run's session headers, from the log's sync alone (the file header's headers row): no body is fetched.
func (self *SessionReader) Headers(ctx context.Context, logId Id, runId Id) (*SessionRunView, error) {
	if err := self.record.reader.Sync(ctx, logId); err != nil {
		return nil, err
	}
	return self.view(logId, runId, 0)
}

// The run opened (the file header's open row): its bodies fetched, then its nodes and parts checked.
func (self *SessionReader) Open(ctx context.Context, logId Id, runId Id) (*SessionRunView, error) {
	reader := self.record.reader
	if err := reader.Sync(ctx, logId); err != nil {
		return nil, err
	}
	fetched, err := reader.FetchBodies(ctx, logId, func(entry *RecordReadEntry) bool {
		kind := entry.Kind()
		return (kind == RecordKindSessionEntry || kind == RecordKindSessionBlob) && sessionEntryOfRun(entry, runId)
	})
	if err != nil {
		return nil, err
	}
	return self.view(logId, runId, fetched)
}

// The run's view over what the reader holds now, checked.
func (self *SessionReader) view(logId Id, runId Id, fetched int) (*SessionRunView, error) {
	view := &SessionRunView{LogId: logId, RunId: runId, Blobs: map[Id]*SessionReadBlob{}, Fetched: fetched, nodeIds: map[Id]*SessionReadNode{}}
	auth := self.record.writer.auth()
	sidecarId := self.record.writer.sidecarId
	for _, entry := range self.record.reader.Entries(logId) {
		if !sessionEntryOfRun(entry, runId) {
			continue
		}
		header := entry.Header.Header
		switch entry.Kind() {
		case RecordKindSessionEntry:
			node := &SessionReadNode{
				EntryId: entry.EntryId, WriterSidecarId: recordIdOf(header.GetWriterSidecarId()), Seq: header.GetSeq(),
				TimeMillis: header.GetTimeMillis(), State: entry.State, Flagged: entry.Flagged, Source: RecordSource(header.GetSource()),
			}
			node.Untrusted = sessionNodeUntrusted(auth, sidecarId, node)
			switch {
			case entry.BodyInvalid:
				node.Invalid = fmt.Errorf("%w: a body that does not open or commit", ErrSessionNodeInvalid)
			case entry.Body != nil:
				body := &protocol.SessionEntryBody{}
				if err := proto.Unmarshal(entry.Body, body); err != nil {
					node.Invalid = fmt.Errorf("%w: a body that does not parse", ErrSessionNodeInvalid)
				} else {
					node.Body = body
				}
			}
			if node.Body == nil {
				view.unheld = true
			}
			view.Nodes = append(view.Nodes, node)
		case RecordKindSessionBlob:
			blob := &SessionReadBlob{EntryId: entry.EntryId, State: entry.State}
			if entry.Body != nil && !entry.BodyInvalid {
				body := &protocol.SessionBlobBody{}
				if proto.Unmarshal(entry.Body, body) == nil {
					blob.Body = body
				}
			}
			view.Blobs[entry.EntryId] = blob
		case RecordKindModelCall:
			call := &SessionReadCall{EntryId: entry.EntryId, WriterSidecarId: recordIdOf(header.GetWriterSidecarId()), Seq: header.GetSeq(), TimeMillis: header.GetTimeMillis()}
			if entry.Body != nil && !entry.BodyInvalid {
				body := &protocol.ModelCallBody{}
				if proto.Unmarshal(entry.Body, body) == nil {
					call.Body = body
				}
			}
			view.Calls = append(view.Calls, call)
		}
	}
	if len(view.Nodes) == 0 && len(view.Calls) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrSessionRunUnknown, runId)
	}
	self.check(view)
	return view, nil
}

// Whether a node is untrusted to this device (the file header's trust row).
func sessionNodeUntrusted(auth RecordAuthView, sidecarId Id, node *SessionReadNode) bool {
	if node.Flagged {
		return true
	}
	return recordWriterTaggedOther(auth, sidecarId, node.WriterSidecarId)
}

// The run's writer (the file header's writers row): the writer of its model calls, else of its most nodes, a tie to
// the lower id.
func sessionRunWriter(view *SessionRunView) Id {
	counts := map[Id]int{}
	for _, call := range view.Calls {
		counts[call.WriterSidecarId] += 1
	}
	if len(counts) == 0 {
		for _, node := range view.Nodes {
			counts[node.WriterSidecarId] += 1
		}
	}
	var writer Id
	best := -1
	for _, candidate := range slices.SortedFunc(maps.Keys(counts), Id.Cmp) {
		if best < counts[candidate] {
			writer, best = candidate, counts[candidate]
		}
	}
	return writer
}

// Checks view's nodes and parts (the file header's writers, chains and blobs rows), raising bad_entry for each node a
// check finds invalid.
func (self *SessionReader) check(view *SessionRunView) {
	// the run's writer: its model calls' writer, the runner, where it holds a call; else the writer of the most nodes,
	// a tie to the lower id. A body that did not open or commit the record's reader alarmed already.
	runWriter := sessionRunWriter(view)
	held := []*SessionReadNode{}
	checked := []*SessionReadNode{}
	for _, node := range view.Nodes {
		if node.Body == nil || node.Invalid != nil {
			continue
		}
		checked = append(checked, node)
		if node.WriterSidecarId != runWriter {
			node.Invalid = fmt.Errorf("%w: a node another writer filed in the run", ErrSessionNodeInvalid)
			continue
		}
		nodeId := recordIdOf(node.Body.GetNodeId())
		if _, twice := view.nodeIds[nodeId]; twice {
			node.Invalid = fmt.Errorf("%w: a node id the run holds twice", ErrSessionNodeInvalid)
			continue
		}
		view.nodeIds[nodeId] = node
		held = append(held, node)
	}
	// parents before children: a writer journals a parent first, so seq order holds them so
	slices.SortStableFunc(held, func(a *SessionReadNode, b *SessionReadNode) int {
		switch {
		case a.Seq < b.Seq:
			return -1
		case b.Seq < a.Seq:
			return 1
		}
		return 0
	})
	for _, node := range held {
		args := &SessionNodeCheckArgs{}
		body := node.Body
		if parentId := body.GetParentNodeId(); len(parentId) != 0 {
			parent, ok := view.nodeIds[recordIdOf(parentId)]
			switch {
			case len(body.GetParentRunId()) != 0:
				// another run's node: its chain is that run's, read when it is opened
				args.ParentUnread = true
			case ok && parent.Invalid == nil:
				args.ParentChainSha256 = parent.Body.GetChainSha256()
			case ok:
				// an invalid parent's chain is not taken
				args.ParentUnread = true
			case view.unheld:
				args.ParentUnread = true
			default:
				node.Invalid = fmt.Errorf("%w: a parent the run does not hold", ErrSessionNodeInvalid)
				continue
			}
		}
		if sameAs := body.GetSameAs(); len(sameAs) != 0 {
			named, ok := view.nodeIds[recordIdOf(sameAs)]
			if !ok {
				if !view.unheld {
					node.Invalid = fmt.Errorf("%w: a same_as node the run does not hold", ErrSessionNodeInvalid)
				}
				continue
			}
			args.SameAs = named.Body
		}
		if err := SessionNodeCheck(body, args); err != nil {
			node.Invalid = err
			continue
		}
		node.PartBytes = map[string][]byte{}
		for _, part := range body.GetParts() {
			if part.GetOmitted() {
				continue
			}
			pieces := []*protocol.SessionBlobBody{}
			for _, blobEntryId := range part.GetBlobEntryIds() {
				blob := view.Blobs[recordIdOf(blobEntryId)]
				if blob == nil || blob.Body == nil {
					pieces = nil
					break
				}
				pieces = append(pieces, blob.Body)
			}
			if pieces == nil {
				// a piece not held: pruned, expired or not fetched
				continue
			}
			content, err := SessionPartAssemble(part, pieces)
			if err != nil {
				node.Invalid = err
				node.PartBytes = nil
				break
			}
			node.PartBytes[part.GetPointer()] = content
		}
	}
	for _, node := range checked {
		if node.Invalid != nil {
			writerId := node.WriterSidecarId
			self.record.writer.raise(SidecarRecordAlarmBadEntry, view.LogId, &writerId)
		}
	}
}
