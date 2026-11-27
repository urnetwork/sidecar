//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.6's rebuild and check (CTXH-M11-04; R-CTXH-2, D-CTXH-4): a call's context rebuilt from the record by
// the renderer its CallContext names, and checked against its request_sha256.
//
//	path       from the call's input node to its root, into another run where a parent link crosses (§24.7), that run
//	           read through OtherRun
//	mail       a mail tool's result kept by reference (§24.9) re-renders from its mailbox through MAILCAL's restorer
//	           and is held to the hash of the text the model read; after DESIGN §15.7's erasure its node reads erased
//	           and the call inexact; with no restorer it reads unverifiable
//	check      the rebuilt request's hash against request_sha256, each part held to its own sha256 by the reader:
//	           verified where equal with every node and part held and the call exact; unverifiable where a node is
//	           erased or its body withheld, dropped or not fetched, a part pruned, or the renderer is one this build
//	           does not hold, each shown at its node and none alarmed; an alarm where a part or node fails its checks
//	           (integrity) or the hash differs with every node present (renderer); inexact where it matches and the call
//	           was not exact, or a mail reference's message is erased: the rebuild is the recorded form, each marker,
//	           stub or omission where the original was, counted
//
// The rebuilt request is the display form: each part held put back, a part not held as its pruned or omitted marker.
// Nothing here reads a clock or a setting, and nothing fetches a pruned part from anywhere else.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// What a rebuild found (§24.6's check row).
type SessionCheck string

const (
	SessionCheckVerified     SessionCheck = "verified"
	SessionCheckUnverifiable SessionCheck = "unverifiable"
	SessionCheckAlarm        SessionCheck = "alarm"
	SessionCheckInexact      SessionCheck = "inexact"
)

// What an alarm is.
const (
	SessionFaultIntegrity = "integrity"
	SessionFaultRenderer  = "renderer"
)

var (
	// The call names no context: a model_call from before CTXH, or a harness's own.
	ErrSessionRebuildNoContext = errors.New("session rebuild: the call names no context")
	// A mail reference's message is gone: DESIGN §15.7's erasure took it.
	ErrSessionMailErased = errors.New("session mail reference erased")
)

// MAILCAL's re-render of a mail tool's result from its mailbox (§23.11): the text the call read, or
// ErrSessionMailErased once a message is erased. Safe for concurrent use.
type SessionMailRestorer interface {
	Restore(ctx context.Context, reference *SessionMailReference) (string, error)
}

// What a rebuild reads.
type SessionRebuildArgs struct {
	// The call's run, opened (SessionReader.Open).
	Run  *SessionRunView
	Call *SessionReadCall
	// Another run opened, where a parent link crosses into it (§24.7); nil reads none, and the path stops there
	// unverifiable.
	OtherRun func(ctx context.Context, runId Id) (*SessionRunView, error)
	// MAILCAL's restorer; nil reads every mail reference unverifiable.
	Mail SessionMailRestorer
}

// One node of a rebuilt call's path, root first.
type SessionRebuiltNode struct {
	RunId   Id
	EntryId Id
	// zero where the node's body is not held
	NodeId Id
	State  RecordEntryState
	Check  SessionCheck
	// Why the node is not verified, empty where it is.
	Why       string
	Untrusted bool
}

// A rebuilt call.
type SessionRebuilt struct {
	Check    SessionCheck
	Renderer string
	Exact    bool
	// alarm's kind: integrity or renderer
	Fault string
	// The path, root first.
	Path []*SessionRebuiltNode
	// The request in its display form, nil where a node of the context is not held or the renderer is unknown.
	Request *InferRequest
	// The rebuilt hash, zero where it could not be computed, and the call's.
	RequestSha256 [sha256.Size]byte
	CallSha256    []byte
	// The markers and stubs in the context's nodes, and its parts kept by hash and size alone.
	Redactions int
	Stubs      int
	Omitted    int
}

// What a rebuild's walk learned of one node.
type sessionRebuildStep struct {
	view *SessionRunView
	node *SessionReadNode
	// the item the render reads, after a mail reference's restore
	item []byte
}

// Rebuilds args.Call's context and checks it (see the file header).
func SessionRebuild(ctx context.Context, args *SessionRebuildArgs) (*SessionRebuilt, error) {
	if args == nil || args.Run == nil || args.Call == nil || args.Call.Body == nil || args.Call.Body.GetContext() == nil {
		return nil, ErrSessionRebuildNoContext
	}
	call := args.Call.Body.GetContext()
	rebuilt := &SessionRebuilt{Renderer: call.GetRenderer(), Exact: call.GetExact(), CallSha256: bytes.Clone(call.GetRequestSha256())}
	// a node the render needs is not held, a part is not held, a node or part failed its checks, a mail message erased
	missingNode, partUnheld, alarm, erasedMail := false, false, false, false
	fault := func(kind string) {
		alarm = true
		if rebuilt.Fault == "" {
			rebuilt.Fault = kind
		}
	}

	// the path, input first, walked to its root and across runs
	type visit struct {
		runId  Id
		nodeId Id
	}
	visited := map[visit]bool{}
	steps := []*sessionRebuildStep{}
	tail := []*SessionRebuiltNode{}
	view := args.Run
	nodeId := recordIdOf(call.GetInputNodeId())
	for {
		if visited[visit{runId: view.RunId, nodeId: nodeId}] {
			// a path that comes back on itself, which no chain of hashes allows
			fault(SessionFaultIntegrity)
			break
		}
		visited[visit{runId: view.RunId, nodeId: nodeId}] = true
		node, ok := view.Node(nodeId)
		if !ok {
			// a node this device does not hold: erased, away, or none
			tail = append(tail, sessionRebuildMissing(view, nodeId))
			missingNode = true
			break
		}
		steps = append(steps, &sessionRebuildStep{view: view, node: node})
		body := node.Body
		parentId := body.GetParentNodeId()
		if len(parentId) == 0 {
			break
		}
		nodeId = recordIdOf(parentId)
		if parentRunId := body.GetParentRunId(); len(parentRunId) != 0 {
			otherRunId := recordIdOf(parentRunId)
			if args.OtherRun == nil {
				tail = append(tail, &SessionRebuiltNode{RunId: otherRunId, NodeId: nodeId, Check: SessionCheckUnverifiable, Why: "another run this rebuild does not read"})
				missingNode = true
				break
			}
			other, err := args.OtherRun(ctx, otherRunId)
			if err != nil {
				tail = append(tail, &SessionRebuiltNode{RunId: otherRunId, NodeId: nodeId, Check: SessionCheckUnverifiable, Why: "another run that does not read: " + err.Error()})
				missingNode = true
				break
			}
			view = other
		}
	}
	// root first
	for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 {
		steps[i], steps[j] = steps[j], steps[i]
	}
	for i, j := 0, len(tail)-1; i < j; i, j = i+1, j-1 {
		tail[i], tail[j] = tail[j], tail[i]
	}
	marks := []*SessionRebuiltNode{}
	for _, step := range steps {
		node := step.node
		mark := &SessionRebuiltNode{RunId: step.view.RunId, EntryId: node.EntryId, State: node.State, Check: SessionCheckVerified, Untrusted: node.Untrusted}
		mark.NodeId, _ = node.NodeId()
		marks = append(marks, mark)
		if node.Invalid != nil {
			mark.Check, mark.Why = SessionCheckAlarm, node.Invalid.Error()
			fault(SessionFaultIntegrity)
			continue
		}
		itemNode, ok := step.view.itemOf(node)
		if !ok {
			mark.Check, mark.Why = SessionCheckUnverifiable, "a same_as node whose item is not held"
			missingNode = true
			continue
		}
		rebuilt.Redactions += int(node.Body.GetRedactions())
		rebuilt.Stubs += int(node.Body.GetStubs())
		for _, part := range itemNode.Body.GetParts() {
			if part.GetOmitted() {
				rebuilt.Omitted += 1
				continue
			}
			if _, held := itemNode.PartBytes[part.GetPointer()]; !held {
				mark.Check, mark.Why = SessionCheckUnverifiable, "a part not held: "+SessionPartMarker(part)
				partUnheld = true
			}
		}
		step.item = itemNode.Body.GetItem()
		restored, check, why, err := sessionRestoreMail(ctx, args.Mail, step.item)
		switch {
		case err != nil:
			mark.Check, mark.Why = SessionCheckAlarm, err.Error()
			fault(SessionFaultIntegrity)
		case check == SessionCheckUnverifiable:
			mark.Check, mark.Why = check, why
			missingNode = true
		case check == SessionCheckInexact:
			mark.Check, mark.Why, mark.State = check, why, RecordEntryErased
			erasedMail = true
		default:
			step.item = restored
		}
	}
	rebuilt.Path = append(marks, tail...)

	renderer, err := SessionRendererOf(call.GetRenderer())
	if err != nil {
		missingNode = true
	}
	if !missingNode && !alarm && !erasedMail && 0 < len(steps) {
		renderNodes := []*SessionRenderNode{}
		byId := map[Id]*SessionRenderNode{}
		for _, step := range steps {
			itemNode, _ := step.view.itemOf(step.node)
			stepNodeId, _ := step.node.NodeId()
			renderNode := &SessionRenderNode{
				NodeId: stepNodeId, Type: SessionNodeType(step.node.Body.GetType()), Item: step.item, Parts: itemNode.Body.GetParts(),
				PartBytes: itemNode.PartBytes,
			}
			renderNodes = append(renderNodes, renderNode)
			byId[stepNodeId] = renderNode
		}
		var systemNodeId *Id
		if system := call.GetSystemNodeId(); len(system) != 0 {
			id := recordIdOf(system)
			systemNodeId = &id
		}
		nodeOf := func(nodeId Id) (*SessionRenderNode, bool) {
			if node, ok := byId[nodeId]; ok {
				return node, true
			}
			node, ok := args.Run.Node(nodeId)
			if !ok {
				return nil, false
			}
			itemNode, ok := args.Run.itemOf(node)
			if !ok {
				return nil, false
			}
			return &SessionRenderNode{NodeId: nodeId, Type: SessionNodeType(node.Body.GetType()), Item: itemNode.Body.GetItem(),
				Parts: itemNode.Body.GetParts(), PartBytes: itemNode.PartBytes}, true
		}
		input, err := renderer.Context(renderNodes, systemNodeId, nodeOf)
		if err == nil {
			input.Params = call.GetParams()
			input.SignInWithheld = call.GetSignInWithheld()
			rebuilt.RequestSha256, err = SessionRequestSha256(renderer, input)
			if err == nil {
				rebuilt.Request, err = SessionRenderDisplay(renderer, input)
			}
		}
		if err != nil || !bytes.Equal(rebuilt.RequestSha256[:], call.GetRequestSha256()) {
			// with every node held, a context the renderer cannot take, or a hash that differs, is a fault
			fault(SessionFaultRenderer)
		}
	}
	switch {
	case alarm:
		rebuilt.Check = SessionCheckAlarm
	case missingNode || len(steps) == 0:
		rebuilt.Check = SessionCheckUnverifiable
	case erasedMail:
		rebuilt.Check = SessionCheckInexact
	case partUnheld:
		rebuilt.Check = SessionCheckUnverifiable
	case !call.GetExact():
		rebuilt.Check = SessionCheckInexact
	default:
		rebuilt.Check = SessionCheckVerified
	}
	return rebuilt, nil
}

// A node a rebuild's path names that its run's view does not hold (CTXH-M11-05; §24.10's after row): erased where every
// node of the run this device does not hold is erased, so the node can be none other, as a fork's path reads once its
// source run is erased; else unverifiable, its body away (withheld, dropped, not fetched). Never an alarm.
func sessionRebuildMissing(view *SessionRunView, nodeId Id) *SessionRebuiltNode {
	missing := &SessionRebuiltNode{RunId: view.RunId, NodeId: nodeId, Check: SessionCheckUnverifiable, Why: "a node whose body is not held"}
	erased := 0
	for _, read := range view.Nodes {
		switch {
		case read.Body != nil:
		case read.State.KeyGone():
			erased += 1
		default:
			return missing
		}
	}
	if 0 < erased {
		missing.State = RecordEntryErased
		missing.Why = "erased"
	}
	return missing
}

// A mail tool's result kept by reference (§24.9), re-rendered from its mailbox: the item with the text put back as the
// result's content, held to the hash of the text read. An item with no reference is the item as it is.
func sessionRestoreMail(ctx context.Context, restorer SessionMailRestorer, item []byte) ([]byte, SessionCheck, string, error) {
	value, err := sessionItemDecode(item)
	if err != nil {
		return item, SessionCheckVerified, "", nil
	}
	result := sessionToolResultObject(value)
	if result == nil {
		return item, SessionCheckVerified, "", nil
	}
	details, _ := result["details"].(map[string]any)
	rawReference, ok := details["mail_reference"]
	if !ok {
		return item, SessionCheckVerified, "", nil
	}
	encoded, err := json.Marshal(rawReference)
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: a mail reference: %v", ErrSessionNodeInvalid, err)
	}
	record := &sessionMailReferenceRecord{}
	if err := json.Unmarshal(encoded, record); err != nil {
		return nil, "", "", fmt.Errorf("%w: a mail reference: %v", ErrSessionNodeInvalid, err)
	}
	if restorer == nil {
		return item, SessionCheckUnverifiable, "a mail reference this build cannot re-render", nil
	}
	repoBytes, err := hex.DecodeString(record.RepoId)
	if err != nil || len(repoBytes) != len(Id{}) {
		return nil, "", "", fmt.Errorf("%w: a mail reference's mailbox", ErrSessionNodeInvalid)
	}
	reference := &SessionMailReference{RepoId: Id(repoBytes), MessageIds: record.MessageIds, Start: record.Start, MaxChars: record.MaxChars, SignInWithheld: record.SignInWithheld}
	text, err := restorer.Restore(ctx, reference)
	if errors.Is(err, ErrSessionMailErased) {
		return item, SessionCheckInexact, "a mail message erased since the call", nil
	}
	if err != nil {
		return item, SessionCheckUnverifiable, "a mail reference that did not re-render: " + err.Error(), nil
	}
	digest := sha256.Sum256([]byte(text))
	if hex.EncodeToString(digest[:]) != record.TextSha256 {
		return nil, "", "", fmt.Errorf("%w: a mail reference whose re-rendered text is not the text read", ErrSessionNodeInvalid)
	}
	result["content"] = []any{map[string]any{"type": "text", "text": text}}
	restored, err := sessionCanonical(value)
	if err != nil {
		return nil, "", "", err
	}
	return restored, SessionCheckVerified, "", nil
}
