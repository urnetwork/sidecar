//go:build !js && !ios && !android && !sdk_mobile_bind

// What every tool result carries (D-MCP-13, §16.6's prompt injection, I-9): its data inside one envelope whose
// fields tag it,
//
//	{"trust": "own" | "member" | "untrusted", "source": "...", "metered_bytes": n, "marker_broken": true?,
//	 "data": {...}}
//
// in structuredContent, and, with Content left empty, one TextContent of the same JSON, the typed handler's form
// (go-sdk mcp/server.go:398-442), so a client of any version reads the same tagged data. trust is the lowest the
// handler reports: its own sidecar's data, a member's, or untrusted; source names where it came from, ids only
// (I-13). Untrusted strings sit between the fixed markers, inside the strings:
//
//	BEGIN UNTRUSTED DATA
//	...
//	END UNTRUSTED DATA
//
// A literal marker inside the data would close the fence early, so Fence breaks every run of either marker's words,
// in any case, by joining them with underscores, and the result says marker_broken (MCP.md's reading 7).
//
// Taint comes before data (D-MCP-16): Untrusted taints the call's run, write-ahead and fsynced, before it lowers the
// result's trust, and fails when the taint fails; the framework refuses a result holding fenced text whose trust is
// not untrusted, or whose run does not read tainted.
//
// metered_bytes is what the call's evs and mail calls reported through McpMeter: the debit itself is theirs (§20), so
// a result only reports it.
//
// A result past SidecarMcpSettings.ResultByteCount keeps its tags and drops its data for the ur:// resource that holds
// it: a resource_link from 2025-06-18 on, else a text naming the resource, by the session's negotiated version, since
// go-sdk rewrites nothing for an older session (D-MCP-13). The declared outputSchema allows both forms.

package mcp

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"sync/atomic"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
)

// How far a result's data is trusted, lowest first.
type McpTrust string

const (
	// This sidecar's own data.
	McpTrustOwn McpTrust = "own"
	// What a member wrote.
	McpTrustMember McpTrust = "member"
	// Outside mail, outside files, a tainted run's writes, flagged entries, untrusted hits, directory prose (§16.6).
	McpTrustUntrusted McpTrust = "untrusted"
)

// The fixed markers around untrusted text (§16.6).
const (
	McpUntrustedBegin = "BEGIN UNTRUSTED DATA"
	McpUntrustedEnd   = "END UNTRUSTED DATA"
)

// The first protocol version with resource_link content (D-MCP-13). Versions are dates, so they order as strings.
const mcpResourceLinkVersion = "2025-06-18"

// A marker's words with any whitespace between them, in any case, which Fence breaks inside data, and the whitespace
// it replaces.
var (
	mcpMarkerPattern      = regexp.MustCompile(`(?i)(BEGIN|END)\s+UNTRUSTED\s+DATA`)
	mcpMarkerSpacePattern = regexp.MustCompile(`\s+`)
)

// One call's result: what the handler reports of its data. Safe for concurrent use, since a handler may fill parts
// of a result on goroutines of its own.
type McpResult struct {
	call *McpCall

	stateLock    sync.Mutex
	trust        McpTrust
	source       string
	resource     string
	fenced       bool
	markerBroken bool
	tainted      bool
}

// A fresh result of call, its trust own.
func newMcpResult(call *McpCall) *McpResult {
	return &McpResult{call: call, trust: McpTrustOwn}
}

// Names where the data came from, ids only (I-13).
func (self *McpResult) SetSource(source string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.source = source
}

// Names the ur:// resource that holds the whole result, which an over-limit result links to instead.
func (self *McpResult) SetResource(uri string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.resource = uri
}

// Lowers the trust to member, for data another member wrote.
func (self *McpResult) Member() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.trust == McpTrustOwn {
		self.trust = McpTrustMember
	}
}

// Taints the call's run, write-ahead (D-MCP-16), then lowers the trust to untrusted. A handler calls it before it
// reads any untrusted data into the result, and fails when it fails: nothing untrusted returns from an untainted run.
func (self *McpResult) Untrusted(ctx context.Context) error {
	if self.call == nil {
		return errMcpNoCall
	}
	if err := self.call.Taint(ctx, sidecar.RunTaintUntrustedData); err != nil {
		return errMcpTaintFailed
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.trust = McpTrustUntrusted
	self.tainted = true
	return nil
}

// text between the fixed markers, each run of a marker's words inside it broken, for an untrusted string field.
func (self *McpResult) Fence(text string) string {
	broken := mcpMarkerPattern.ReplaceAllStringFunc(text, func(run string) string {
		return mcpMarkerSpacePattern.ReplaceAllString(run, "_")
	})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.fenced = true
	if broken != text {
		self.markerBroken = true
	}
	return McpUntrustedBegin + "\n" + broken + "\n" + McpUntrustedEnd
}

// The envelope a result goes out in.
type mcpResultEnvelope struct {
	Trust        McpTrust        `json:"trust"`
	Source       string          `json:"source"`
	MeteredBytes int64           `json:"metered_bytes"`
	MarkerBroken bool            `json:"marker_broken,omitempty"`
	Data         json.RawMessage `json:"data,omitempty"`
	// An over-limit result's: no data, and the resource that holds it.
	Truncated bool   `json:"truncated,omitempty"`
	Resource  string `json:"resource,omitempty"`
}

// The envelope of data under the result's tags, refusing fenced text that is not untrusted from a tainted run.
func (self *McpResult) envelope(data json.RawMessage, meteredBytes int64) (*mcpResultEnvelope, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.fenced && (self.trust != McpTrustUntrusted || !self.tainted) {
		return nil, errMcpUntaintedUntrust
	}
	if self.trust == McpTrustUntrusted && (self.call == nil || !self.call.Tainted()) {
		return nil, errMcpUntaintedUntrust
	}
	return &mcpResultEnvelope{
		Trust:        self.trust,
		Source:       self.source,
		MeteredBytes: meteredBytes,
		MarkerBroken: self.markerBroken,
		Data:         data,
	}, nil
}

// The resource an over-limit result names.
func (self *McpResult) resourceUri() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.resource
}

// A call's metered-bytes counter, which its context carries.
type mcpMeter struct {
	byteCount atomic.Int64
}

// The context key of a call's meter.
type mcpMeterContextKey struct{}

// Adds byteCount to the bytes the call in ctx reports as metered_bytes: what an evs or mail call debited (§20), which
// it reports here once its own debit is done. Nothing outside a tool call.
func McpMeter(ctx context.Context, byteCount int64) {
	if meter, ok := ctx.Value(mcpMeterContextKey{}).(*mcpMeter); ok && 0 < byteCount {
		meter.byteCount.Add(byteCount)
	}
}

// A context whose calls to McpMeter count into meter.
func withMcpMeter(ctx context.Context, meter *mcpMeter) context.Context {
	return context.WithValue(ctx, mcpMeterContextKey{}, meter)
}

// The protocol version a request's session negotiated: the request's _meta at 2026-07-28, which has no initialize,
// else the session's initialize. Empty when neither says, which shapes as the oldest version.
func mcpProtocolVersion(request *gomcp.CallToolRequest) string {
	if request == nil {
		return ""
	}
	if request.Params != nil {
		if version, ok := request.Params.GetMeta()[gomcp.MetaKeyProtocolVersion].(string); ok && version != "" {
			return version
		}
	}
	if request.Session != nil {
		if params := request.Session.InitializeParams(); params != nil {
			return params.ProtocolVersion
		}
	}
	return ""
}

// The CallToolResult for an envelope: its JSON as structuredContent and as the one TextContent, or past byteLimit the
// tags alone with a link to resource, as the version takes it. errMcpTooLarge for an over-limit result with no
// resource.
func mcpShapeResult(envelope *mcpResultEnvelope, version string, byteLimit int, resource string) (*gomcp.CallToolResult, []byte, error) {
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, nil, errMcpFailed
	}
	if len(encoded) <= byteLimit {
		return &gomcp.CallToolResult{
			StructuredContent: json.RawMessage(encoded),
			Content:           []gomcp.Content{&gomcp.TextContent{Text: string(encoded)}},
		}, encoded, nil
	}
	if resource == "" {
		return nil, nil, errMcpTooLarge
	}
	truncated := *envelope
	truncated.Data = nil
	truncated.Truncated = true
	truncated.Resource = resource
	truncatedEncoded, err := json.Marshal(&truncated)
	if err != nil {
		return nil, nil, errMcpFailed
	}
	result := &gomcp.CallToolResult{StructuredContent: json.RawMessage(truncatedEncoded)}
	if mcpResourceLinkVersion <= version {
		result.Content = []gomcp.Content{&gomcp.ResourceLink{
			URI:         resource,
			Name:        "result",
			Description: "the whole result, too large to return in the call",
			MIMEType:    "application/json",
		}}
	} else {
		result.Content = []gomcp.Content{&gomcp.TextContent{
			Text: "the result is too large to return in the call; read the resource " + resource + ": " + string(truncatedEncoded),
		}}
	}
	return result, truncatedEncoded, nil
}
