//go:build !ios_extension && !sidecar_http

// Erasing context history (DESIGN-COMPUTE §24.10's prune row; CTXH-M11-06; RECORD.md section 8): `ur record erase --run
// <id> [--context | --blobs-only]` and a session entry erased by id, on the eraser's steps (record_erase.go), each
// listed first and confirmed on /dev/tty or in an app, never through MCP or under a harness.
//
//	run       every entry of the run in the log, its transcript, context, tool call, model call and coverage entries
//	          among them; with context its session entries and blobs; with blobs its blobs alone. A class 7 entry
//	          lasts as long as the log and is never among them
//	node      erasing a session_entry by id erases its parts' blobs too, its body fetched where it is deferred
//	listed    beside the entries, what the erasure cuts: the run's nodes left without their item, a same_as node whose
//	          named node goes or a node sharing a part's blobs that go; the run's model calls whose context it cuts,
//	          whose rebuilds then read unverifiable there; and the continued and forked runs whose paths cross into it,
//	          by their stage-2 context entries' continues_run_id
//	batches   an erasure names at most RecordEraseSettings.EntryCount entries, so a run's goes in as many erasures as it
//	          takes, each its own erasure entry
//
// Nothing erased takes another run's bytes, since none are shared (Q-CTXH-5); a continuation keeps its own nodes and
// reads the erased ones as erased in its rebuilds (session_rebuild.go).
//
// Safe for concurrent use: as the eraser.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// What `ur record erase --run` takes of the run.
type RecordEraseRunScope string

const (
	// Every entry of the run.
	RecordEraseRunAll RecordEraseRunScope = "all"
	// Its session entries and blobs: --context.
	RecordEraseRunContext RecordEraseRunScope = "context"
	// Its blobs alone: --blobs-only.
	RecordEraseRunBlobs RecordEraseRunScope = "blobs"
)

// What an erasure of session history cuts beside the entries it takes (the file header's listed row).
type RecordEraseSessionImpact struct {
	// Nodes that stay but lose their item: a same_as node whose named node goes, or one sharing a part's blobs that go.
	SameAs []Id `json:"same_as,omitempty"`
	// Model calls that stay whose context the erasure cuts.
	Calls []Id `json:"calls,omitempty"`
	// Continued and forked runs whose paths cross into a run the erasure takes from.
	Runs []Id `json:"runs,omitempty"`
}

// Whether scope is one the command takes.
func (self RecordEraseRunScope) known() bool {
	return self == RecordEraseRunAll || self == RecordEraseRunContext || self == RecordEraseRunBlobs
}

// The entries of runId in logId that scope takes, as this device reads the log now, entries erased already left out.
func (self *RecordEraser) RunEntries(ctx context.Context, logId Id, runId Id, scope RecordEraseRunScope) ([]Id, error) {
	if !scope.known() {
		return nil, fmt.Errorf("%w: scope %q", ErrRecordEraseInvalid, scope)
	}
	reader := self.record.reader
	if err := reader.Sync(ctx, logId); err != nil {
		return nil, err
	}
	entryIds := []Id{}
	for _, entry := range reader.Entries(logId) {
		if !bytes.Equal(entry.Header.Header.GetRunId(), runId[:]) || entry.State.KeyGone() || entry.Kind().Class() == RecordClassLog {
			continue
		}
		kind := entry.Kind()
		switch scope {
		case RecordEraseRunContext:
			if kind != RecordKindSessionEntry && kind != RecordKindSessionBlob {
				continue
			}
		case RecordEraseRunBlobs:
			if kind != RecordKindSessionBlob {
				continue
			}
		}
		entryIds = append(entryIds, entry.EntryId)
	}
	return entryIds, nil
}

// entryIds with each session_entry's parts' blobs added after it (the file header's node row), each once.
func (self *RecordEraser) WithSessionBlobs(ctx context.Context, logId Id, entryIds []Id) ([]Id, error) {
	reader := self.record.reader
	if err := reader.Sync(ctx, logId); err != nil {
		return nil, err
	}
	nodes := map[Id]bool{}
	for _, entryId := range entryIds {
		if entry, ok := reader.Entry(logId, entryId); ok && entry.Kind() == RecordKindSessionEntry {
			nodes[entryId] = true
		}
	}
	if len(nodes) == 0 {
		return entryIds, nil
	}
	if _, err := reader.FetchBodies(ctx, logId, func(entry *RecordReadEntry) bool { return nodes[entry.EntryId] }); err != nil {
		return nil, err
	}
	all := slices.Clone(entryIds)
	for _, entryId := range entryIds {
		if !nodes[entryId] {
			continue
		}
		entry, ok := reader.Entry(logId, entryId)
		if !ok || entry.Body == nil {
			continue
		}
		body := &protocol.SessionEntryBody{}
		if proto.Unmarshal(entry.Body, body) != nil {
			continue
		}
		for _, part := range body.GetParts() {
			for _, blobEntryId := range part.GetBlobEntryIds() {
				if blobId := recordIdOf(blobEntryId); !slices.Contains(all, blobId) {
					all = append(all, blobId)
				}
			}
		}
	}
	return all, nil
}

// What erasing entryIds cuts of session history (the file header's listed row), each run it takes from opened.
func (self *RecordEraser) SessionImpact(ctx context.Context, logId Id, entryIds []Id) (*RecordEraseSessionImpact, error) {
	reader := self.record.reader
	if err := reader.Sync(ctx, logId); err != nil {
		return nil, err
	}
	erasing := map[Id]bool{}
	runIds := []Id{}
	for _, entryId := range entryIds {
		erasing[entryId] = true
		entry, ok := reader.Entry(logId, entryId)
		if !ok {
			continue
		}
		kind := entry.Kind()
		if kind != RecordKindSessionEntry && kind != RecordKindSessionBlob {
			continue
		}
		if runId := entry.Header.Header.GetRunId(); len(runId) == len(Id{}) && !slices.Contains(runIds, recordIdOf(runId)) {
			runIds = append(runIds, recordIdOf(runId))
		}
	}
	impact := &RecordEraseSessionImpact{}
	sessions := self.record.SessionReader()
	for _, runId := range runIds {
		view, err := sessions.Open(ctx, logId, runId)
		if err != nil {
			return nil, err
		}
		// the run's nodes that go, by node id, and those whose item goes with them
		gone := map[Id]bool{}
		for _, node := range view.Nodes {
			if nodeId, ok := node.NodeId(); ok && erasing[node.EntryId] {
				gone[nodeId] = true
			}
		}
		for _, node := range view.Nodes {
			nodeId, held := node.NodeId()
			if !held || erasing[node.EntryId] {
				continue
			}
			cut := false
			if sameAs := node.Body.GetSameAs(); len(sameAs) != 0 && gone[recordIdOf(sameAs)] {
				cut = true
			}
			if itemNode, ok := view.itemOf(node); ok {
				for _, part := range itemNode.Body.GetParts() {
					for _, blobEntryId := range part.GetBlobEntryIds() {
						if erasing[recordIdOf(blobEntryId)] {
							cut = true
						}
					}
				}
			}
			if cut {
				gone[nodeId] = true
				impact.SameAs = append(impact.SameAs, node.EntryId)
			}
		}
		for _, call := range view.Calls {
			if erasing[call.EntryId] || call.Body == nil || call.Body.GetContext() == nil {
				continue
			}
			if sessionPathCrosses(view, recordIdOf(call.Body.GetContext().GetInputNodeId()), gone) {
				impact.Calls = append(impact.Calls, call.EntryId)
			}
		}
	}
	// the runs that continue a run the erasure takes from, by their stage-2 context entries
	contexts, _ := reader.EntriesOfKinds(logId, 0, RecordKindContext)
	for _, entry := range contexts {
		body := &protocol.ContextBody{}
		if entry.Body == nil || proto.Unmarshal(entry.Body, body) != nil || len(body.GetContinuesRunId()) != len(Id{}) {
			continue
		}
		continuer := recordIdOf(entry.Header.Header.GetRunId())
		if slices.Contains(runIds, recordIdOf(body.GetContinuesRunId())) && !slices.Contains(impact.Runs, continuer) && !slices.Contains(runIds, continuer) {
			impact.Runs = append(impact.Runs, continuer)
		}
	}
	return impact, nil
}

// Whether the path from nodeId to its root, within view's run, holds a node of gone.
func sessionPathCrosses(view *SessionRunView, nodeId Id, gone map[Id]bool) bool {
	seen := map[Id]bool{}
	for !seen[nodeId] {
		seen[nodeId] = true
		if gone[nodeId] {
			return true
		}
		node, ok := view.Node(nodeId)
		if !ok {
			return false
		}
		parent := node.Body.GetParentNodeId()
		if len(parent) == 0 || len(node.Body.GetParentRunId()) != 0 {
			return false
		}
		nodeId = recordIdOf(parent)
	}
	return false
}

// Plans args' entries in as many batches as EntryCount takes, as one plan: what `ur record erase` lists before it asks.
func (self *RecordEraser) PlanAll(ctx context.Context, args *RecordEraseArgs) (*RecordErasePlan, error) {
	if args == nil || len(args.EntryIds) == 0 {
		return nil, fmt.Errorf("%w: an erasure names its entries", ErrRecordEraseInvalid)
	}
	batch := max(self.settings.EntryCount, 1)
	plan := &RecordErasePlan{LogId: args.LogId}
	for start := 0; start < len(args.EntryIds); start += batch {
		part := *args
		part.EntryIds = args.EntryIds[start:min(start+batch, len(args.EntryIds))]
		planned, err := self.Plan(ctx, &part)
		if err != nil {
			return nil, err
		}
		plan.Items = append(plan.Items, planned.Items...)
		plan.Missing = append(plan.Missing, planned.Missing...)
	}
	return plan, nil
}

// Erases args' entries in as many erasures as EntryCount takes, stopping at the first that fails: the results of
// those that ran.
func (self *RecordEraser) EraseAll(ctx context.Context, args *RecordEraseArgs) ([]*RecordEraseResult, error) {
	if args == nil || len(args.EntryIds) == 0 {
		return nil, fmt.Errorf("%w: an erasure names its entries", ErrRecordEraseInvalid)
	}
	batch := max(self.settings.EntryCount, 1)
	results := []*RecordEraseResult{}
	for start := 0; start < len(args.EntryIds); start += batch {
		part := *args
		part.EntryIds = args.EntryIds[start:min(start+batch, len(args.EntryIds))]
		result, err := self.Erase(ctx, &part)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

// What a prune of context history asks (`ur record erase --run`, the sdk's Prune): a run's entries by scope, or entries
// by id, each session entry's blobs with it.
type SessionPruneSpec struct {
	RunId *Id                 `json:"run,omitempty"`
	Scope RecordEraseRunScope `json:"scope,omitempty"`
	// Entries by id; a session entry among them takes its parts' blobs.
	EntryIds []Id `json:"entries,omitempty"`
	// The log; nil takes the author's vault.
	LogId *Id `json:"log,omitempty"`
}

// One entry a prune takes, as listed before the person confirms.
type SessionPruneItem struct {
	EntryId          Id     `json:"entry"`
	Kind             string `json:"kind"`
	TimeMillis       int64  `json:"time_millis"`
	CopyCount        int    `json:"copy_count"`
	Erased           bool   `json:"erased,omitempty"`
	KeptContextCount int    `json:"kept_context_count,omitempty"`
}

// What a prune would take and cut: its entries, those the log does not hold, and the session history it cuts.
type SessionPrunePlan struct {
	LogId   Id                        `json:"log"`
	Items   []*SessionPruneItem       `json:"items"`
	Missing []Id                      `json:"missing,omitempty"`
	Impact  *RecordEraseSessionImpact `json:"impact"`
}

// What a prune erased.
type SessionPruned struct {
	LogId      Id   `json:"log"`
	ErasureIds []Id `json:"erasures"`
	Erased     []Id `json:"erased"`
	Missing    []Id `json:"missing,omitempty"`
	KeyCount   int  `json:"key_count"`
}

// spec's log and entries: a run's by scope, all where none is named, or the entries named, each session entry's blobs
// added.
func (self *SidecarRecord) SessionPruneEntries(ctx context.Context, spec *SessionPruneSpec) (Id, []Id, error) {
	if spec == nil || (spec.RunId == nil && len(spec.EntryIds) == 0) {
		return Id{}, nil, fmt.Errorf("%w: a prune names a run or entries", ErrRecordEraseInvalid)
	}
	var logId Id
	if spec.LogId != nil {
		logId = *spec.LogId
	} else {
		vaultId, err := self.SessionReader().VaultId()
		if err != nil {
			return Id{}, nil, err
		}
		logId = vaultId
	}
	eraser := self.Eraser()
	entryIds := slices.Clone(spec.EntryIds)
	if spec.RunId != nil {
		scope := spec.Scope
		if scope == "" {
			scope = RecordEraseRunAll
		}
		runEntryIds, err := eraser.RunEntries(ctx, logId, *spec.RunId, scope)
		if err != nil {
			return Id{}, nil, err
		}
		for _, entryId := range runEntryIds {
			if !slices.Contains(entryIds, entryId) {
				entryIds = append(entryIds, entryId)
			}
		}
	}
	if len(entryIds) == 0 {
		return logId, entryIds, nil
	}
	entryIds, err := eraser.WithSessionBlobs(ctx, logId, entryIds)
	if err != nil {
		return Id{}, nil, err
	}
	return logId, entryIds, nil
}

// What pruning spec would erase and cut, listed before the person confirms: nothing is erased. Refused under a harness
// process, as a person's erasure is.
func (self *SidecarRecord) SessionPrunePlan(ctx context.Context, spec *SessionPruneSpec, harnessAncestor bool) (*SessionPrunePlan, error) {
	logId, entryIds, err := self.SessionPruneEntries(ctx, spec)
	if err != nil {
		return nil, err
	}
	plan := &SessionPrunePlan{LogId: logId, Items: []*SessionPruneItem{}, Impact: &RecordEraseSessionImpact{}}
	if len(entryIds) == 0 {
		return plan, nil
	}
	eraser := self.Eraser()
	planned, err := eraser.PlanAll(ctx, &RecordEraseArgs{LogId: logId, EntryIds: entryIds, Reason: RecordErasureReasonPerson, HarnessAncestor: harnessAncestor})
	if err != nil {
		return nil, err
	}
	for _, item := range planned.Items {
		plan.Items = append(plan.Items, &SessionPruneItem{EntryId: item.EntryId, Kind: item.Kind.String(), TimeMillis: item.TimeMillis,
			CopyCount: item.CopyCount, Erased: item.Erased, KeptContextCount: item.KeptContextCount})
	}
	plan.Missing = planned.Missing
	if plan.Impact, err = eraser.SessionImpact(ctx, logId, entryIds); err != nil {
		return nil, err
	}
	return plan, nil
}

// Erases what spec names, the person's act confirmed on /dev/tty or in an app (RECORD.md section 8): every entry in as
// many erasures as it takes.
func (self *SidecarRecord) SessionPrune(ctx context.Context, spec *SessionPruneSpec, confirmed bool, harnessAncestor bool) (*SessionPruned, error) {
	logId, entryIds, err := self.SessionPruneEntries(ctx, spec)
	if err != nil {
		return nil, err
	}
	pruned := &SessionPruned{LogId: logId, ErasureIds: []Id{}, Erased: []Id{}}
	if len(entryIds) == 0 {
		return pruned, nil
	}
	results, err := self.Eraser().EraseAll(ctx, &RecordEraseArgs{LogId: logId, EntryIds: entryIds, Reason: RecordErasureReasonPerson,
		Confirmed: confirmed, HarnessAncestor: harnessAncestor})
	for _, result := range results {
		pruned.ErasureIds = append(pruned.ErasureIds, result.ErasureId)
		pruned.Erased = append(pruned.Erased, result.Erased...)
		pruned.Missing = append(pruned.Missing, result.Missing...)
		pruned.KeyCount += len(result.Keys)
	}
	return pruned, err
}
