//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.6's renderers and request hashes (CTXH-M11-04; R-CTXH-2, D-CTXH-4): a call's request is a pure
// function, by the renderer its CallContext names, of the nodes of its context, each node's trust, the call's params
// and whether it withheld sign-in mail, so the Harness's loop builds each request from its journaled nodes and a
// rebuild from the record equals what was sent by construction.
//
//	renderers  ur keeps every renderer it shipped, by id, as the record keeps its extractors (RECORD.md section 7.1):
//	           harness-<version> (session_render_harness.go), and the gateway's gateway-<api>-<version>, which GW
//	           registers from its own files with RegisterSessionRenderer; a call whose renderer this build does not hold
//	           reads unverifiable, never verified. A renderer reads no clock, catalog or settings that could change after
//	           the call, and a field INFER adds to InferRequest later is a new renderer, never a change to one shipped
//	forms      a node's item is its recorded item, RFC 8785 with each part at its pointer by its reference; a render
//	           puts each part back: its bytes for the request sent (SessionRenderRequest), or for request_sha256 the
//	           reference's own RFC 8785 text in place of its bytes (SessionRequestSha256), so pruning a blob leaves a
//	           call checkable; and for a person's view (SessionRenderDisplay) a marker for a part not held,
//	           [pruned: <size>, sha256 <8 hex>] (§24.10's after row)
//	hash       request_sha256 = SHA-256 of the rendered InferRequest's RFC 8785 form, its JSON names INFER's declared
//	           tags, which are part of the renderer's id (session_render_harness.go pins harness-1's)
//
// Package-level functions are safe for concurrent use; renderers register at init.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A renderer this build does not hold, or none named: the call reads unverifiable.
	ErrSessionRendererUnknown = errors.New("session renderer unknown")
	// A context a renderer cannot render: an item it cannot read, params with a field it does not take, or a part
	// the request sent needs and the device does not hold.
	ErrSessionRenderRefused = errors.New("session render refused")
)

// A renderer's id: harness-<version> or gateway-<api>-<version> (§24.5's CallContext.renderer).
var sessionRendererIdPattern = regexp.MustCompile(`^(harness-[1-9][0-9]*|gateway-[a-z][a-z0-9_]*-[1-9][0-9]*)$`)

// One node of a call's context as a renderer reads it.
type SessionRenderItem struct {
	NodeId Id
	Type   SessionNodeType
	// RFC 8785, each part put back in the render's form (see the file header's forms row).
	Item []byte
	// Written by an untrusted writer: its text goes between the untrusted-data markers naming Sender (§7.8, D-CTXH-9).
	Untrusted bool
	Sender    string
}

// What a call's request is rendered from (§24.6's block).
type SessionRenderContext struct {
	// The context's nodes in order, from its root, or from its newest compaction's first kept node, to its input node,
	// the compaction among them (SessionContextOf).
	Nodes []*SessionRenderItem
	// The system message in force: the first system message on the path and each later one's patch up to the call's
	// system node, in order.
	System []*SessionRenderItem
	// The request's fields beside its system text, tools and messages, RFC 8785 (CallContext.params).
	Params []byte
	// Sign-in mail was withheld from the call's rendering (§23.4).
	SignInWithheld bool
}

// A renderer: a pure function of a context to the request it sends (see the file header). Safe for concurrent use.
type SessionRenderer interface {
	// harness-<version> or gateway-<api>-<version>.
	Id() string
	// The nodes a call renders from (§24.6's path, compaction and system rows): path holds the call's input node's
	// path, its root first, and systemNodeId the system message in force, nil for none named; nodeOf finds any node of
	// the run by its id, for a system node that sits off the path, as the gateway's does.
	Context(path []*SessionRenderNode, systemNodeId *Id, nodeOf func(nodeId Id) (*SessionRenderNode, bool)) (*SessionRenderInput, error)
	Render(context *SessionRenderContext) (*InferRequest, error)
}

// The renderers this build holds, by id: written at init by RegisterSessionRenderer, read under the lock.
var (
	sessionRenderersLock sync.RWMutex
	sessionRenderers     = map[string]SessionRenderer{}
)

// Registers a renderer from an init function in its owner's file (GW's gateway-<api>-<version>). An id that is not a
// renderer's, one registered twice or a nil renderer is a build error, which panics: a shipped renderer is never
// replaced.
func RegisterSessionRenderer(renderer SessionRenderer) {
	if renderer == nil || !sessionRendererIdPattern.MatchString(renderer.Id()) {
		panic(fmt.Sprintf("session renderer %v has no renderer's id", renderer))
	}
	sessionRenderersLock.Lock()
	defer sessionRenderersLock.Unlock()
	if _, registered := sessionRenderers[renderer.Id()]; registered {
		panic(fmt.Sprintf("session renderer %q registered twice", renderer.Id()))
	}
	sessionRenderers[renderer.Id()] = renderer
}

// The renderer of id, ErrSessionRendererUnknown for none.
func SessionRendererOf(id string) (SessionRenderer, error) {
	sessionRenderersLock.RLock()
	defer sessionRenderersLock.RUnlock()
	renderer, ok := sessionRenderers[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrSessionRendererUnknown, id)
	}
	return renderer, nil
}

// The ids of every renderer this build holds, sorted.
func SessionRendererIds() []string {
	sessionRenderersLock.RLock()
	defer sessionRenderersLock.RUnlock()
	return slices.Sorted(maps.Keys(sessionRenderers))
}

// One node as a render takes it: its body as recorded and the bytes of each part the device holds.
type SessionRenderNode struct {
	// As recorded; a same_as node is given as the node it names holds its item (SessionReadNode.Item).
	NodeId Id
	Type   SessionNodeType
	Item   []byte
	Parts  []*protocol.SessionPart
	// Each part's bytes this device holds and checked, by pointer: a pruned, omitted or unfetched part is absent.
	PartBytes map[string][]byte
	Untrusted bool
	Sender    string
}

// The nodes of a render, as SessionContextOf finds them.
type SessionRenderInput struct {
	Nodes          []*SessionRenderNode
	System         []*SessionRenderNode
	Params         []byte
	SignInWithheld bool
}

// What a render puts at a part's pointer.
type sessionRenderForm int

const (
	// each part's bytes; one not held refuses
	sessionRenderSend sessionRenderForm = iota
	// each part's reference text
	sessionRenderHash
	// each part's bytes, a marker for one not held
	sessionRenderDisplay
)

// A part's reference as its RFC 8785 text: what request_sha256 holds in place of its bytes.
func sessionPartRefText(part *protocol.SessionPart) ([]byte, error) {
	encoded, err := json.Marshal(SessionPartRefOf(part))
	if err != nil {
		return nil, err
	}
	return CanonicalJson(encoded)
}

// The marker a person reads where a part this device does not hold stood (§24.10's after row): pruned for a part kept
// whole and gone since, omitted for one kept by hash and size from the start.
func SessionPartMarker(part *protocol.SessionPart) string {
	digest := hex.EncodeToString(part.GetSha256())
	if len(digest) > 8 {
		digest = digest[:8]
	}
	if part.GetOmitted() {
		return fmt.Sprintf("[omitted: %d, sha256 %s]", part.GetSize(), digest)
	}
	return fmt.Sprintf("[pruned: %d, sha256 %s]", part.GetSize(), digest)
}

// A node's item with each part put back in form.
func sessionRenderItemOf(node *SessionRenderNode, form sessionRenderForm) (*SessionRenderItem, error) {
	partBytes := map[string][]byte{}
	for _, part := range node.Parts {
		pointer := part.GetPointer()
		held, ok := node.PartBytes[pointer]
		switch form {
		case sessionRenderHash:
			text, err := sessionPartRefText(part)
			if err != nil {
				return nil, err
			}
			partBytes[pointer] = text
		case sessionRenderSend:
			if !ok {
				return nil, fmt.Errorf("%w: a part at %s this device does not hold", ErrSessionRenderRefused, pointer)
			}
			partBytes[pointer] = held
		case sessionRenderDisplay:
			if ok {
				partBytes[pointer] = held
			} else {
				partBytes[pointer] = []byte(SessionPartMarker(part))
			}
		}
	}
	item, err := SessionItemRestore(node.Item, node.Parts, partBytes)
	if err != nil {
		return nil, err
	}
	return &SessionRenderItem{NodeId: node.NodeId, Type: node.Type, Item: item, Untrusted: node.Untrusted, Sender: node.Sender}, nil
}

// The context of input in form.
func sessionRenderContextOf(input *SessionRenderInput, form sessionRenderForm) (*SessionRenderContext, error) {
	context := &SessionRenderContext{Params: input.Params, SignInWithheld: input.SignInWithheld}
	for _, node := range input.Nodes {
		item, err := sessionRenderItemOf(node, form)
		if err != nil {
			return nil, err
		}
		context.Nodes = append(context.Nodes, item)
	}
	for _, node := range input.System {
		item, err := sessionRenderItemOf(node, form)
		if err != nil {
			return nil, err
		}
		context.System = append(context.System, item)
	}
	return context, nil
}

// The request input renders to as sent: each part's bytes put back, ErrSessionRenderRefused where a part is not held.
func SessionRenderRequest(renderer SessionRenderer, input *SessionRenderInput) (*InferRequest, error) {
	context, err := sessionRenderContextOf(input, sessionRenderSend)
	if err != nil {
		return nil, err
	}
	return renderer.Render(context)
}

// The request input renders to for a person to read: each part held put back, and a marker where one is not.
func SessionRenderDisplay(renderer SessionRenderer, input *SessionRenderInput) (*InferRequest, error) {
	context, err := sessionRenderContextOf(input, sessionRenderDisplay)
	if err != nil {
		return nil, err
	}
	return renderer.Render(context)
}

// request_sha256 (see the file header's hash row): the request input renders to with each part's reference text in
// place of its bytes, as RFC 8785, hashed. It needs no part's bytes, so a pruned blob leaves the call checkable.
func SessionRequestSha256(renderer SessionRenderer, input *SessionRenderInput) ([sha256.Size]byte, error) {
	context, err := sessionRenderContextOf(input, sessionRenderHash)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	request, err := renderer.Render(context)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return SessionRequestSha256Of(request)
}

// SHA-256 of request's RFC 8785 form.
func SessionRequestSha256Of(request *InferRequest) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	canonical, err := CanonicalJson(encoded)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}
