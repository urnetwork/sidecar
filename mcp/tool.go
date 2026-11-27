//go:build !js && !ios && !android && !sdk_mobile_bind

// The tool framework (D-MCP-3, D-MCP-4, D-MCP-13, D-MCP-17, R-MCP-9, I-7, I-8, I-9, I-13, X1): AddTool registers one
// tool on an McpCatalog under a constant spec, and the wrapper does everything a tool must not forget. Per call, in
// order:
//
//	network  the call's network resolved by §5.8's rules and ready (server.go's middleware), read as an
//	         McpToolNetwork with a policy installed, else refused
//	input    the arguments against the tool's input schema, network among them, and uses for a tool that takes it,
//	         and no key it does not name; a refusal's text is constant, never the schema validator's, which can quote
//	         a value
//	guard    McpGuard on what the call would touch (spec.Targets)
//	allow    §8's local allow for the session's subject, the sidecar every in-daemon agent shares (owner decision 6;
//	         §5.5), on each McpAccess the call needs (spec.Access)
//	cover    an O tool's covering grant, allowed by §8's local evaluation, runs the call as W (spec.Covering)
//	rate     a W tool's call, or a covered O tool's, takes one of the session's W tokens (§16.4)
//	handler  under a metered-bytes counter (McpMeter); any error it returns becomes an McpError, since go-sdk embeds a
//	         returned error's text in the result
//	tags     the result's trust and source, fenced text only from a tainted run (result.go)
//	secret   a result holding a credential or a token form is refused, and so is an error whose text holds one (I-7)
//	shape    past ResultByteCount, a link to the result's resource, by the session's version (D-MCP-13)
//	sink     a W call's arguments, result and outcome to McpCallSink, a tool_call entry, source observed (MCP-M3-19),
//	         a covered O call's among them
//
// Tier hints: R sets readOnlyHint; O, and a W tool that may run an outward action (spec.MayAct), set openWorldHint;
// every other tool sets openWorldHint false, since the protocol's default is true. A description is the spec's
// constant, so no tool list holds a variable (D-MCP-3), and the tool list is the catalog, fixed before any session
// starts (catalog.go). Nothing here logs a call's arguments or result (I-13).
//
// uses: a tool whose spec takes it (spec.MultiUse) gets an optional uses, an integer of at least 1, which the wrapper
// adds to its input schema as it adds network and hands its handler apart from In (McpUses): how many distinct actions
// the agent asks one approval to cover, 2 or more asking for a template (§16.6's multi-use row). Only mail_send takes
// it (owner decision 613; catalog.go holds every other tool to none), so every other O tool files one use.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
)

// §16.6's tiers.
type McpTier int

const (
	// R: reads, readOnlyHint.
	McpTierRead McpTier = iota + 1
	// W: an in-network write, recorded and rate-limited.
	McpTierWrite
	// O: an outward action through §5.4's gate (Sidecar.Authorize), openWorldHint.
	McpTierOutward
)

// The tier's letter, as §16.5 writes it.
func (self McpTier) String() string {
	switch self {
	case McpTierRead:
		return "R"
	case McpTierWrite:
		return "W"
	case McpTierOutward:
		return "O"
	}
	return "?"
}

// The argument every tool takes (16.4): which network the call acts on, resolved before the tool runs.
const mcpNetworkArgumentName = "network"

// The argument a tool whose spec is MultiUse takes: the uses its agent asks one approval to cover (owner decision 613).
const mcpUsesArgumentName = "uses"

// One tool's constant spec. Every function is called per call, before the handler, with the decoded input.
type McpToolSpec[In any] struct {
	Name string
	Tier McpTier
	// Constant text: no variable ever reaches a tool list (D-MCP-3).
	Description string
	// A W tool that may also run an outward action through Authorize, as evs_write does for agent-config files and
	// mail_send for outside recipients (§16.5): it sets openWorldHint.
	MayAct bool
	// The tool takes an optional uses, the count of distinct actions its agent asks one approval to cover, 2 or more
	// asking for a template, which the handler reads with McpUses and In never names (§16.5's mail_send; owner
	// decision 613). Only a tool that files an outward action, O or MayAct, takes it, and §16.5 gives it to mail_send
	// alone, which the catalog holds (checkMcpCatalog).
	MultiUse bool
	// What the call would touch, for McpGuard. Nil touches nothing the guard names.
	Targets func(call *McpCall, in *In) ([]McpTarget, error)
	// The grants the call needs from §8's local evaluation, every one allowed or the call is refused. Required: a tool
	// that needs none returns none.
	Access func(call *McpCall, in *In) ([]McpAccess, error)
	// An O tool's covering grant (§16.5's "O, or W under a covering grant", socket_listen's): the grant that, allowed
	// by §8's local evaluation for this sidecar, runs the call as W, its W token taken and the call recorded as a W
	// call is, with no approval; the handler reads McpCoveringGrant to know. Nil, or a nil grant, leaves the call O.
	// Only an O tool takes one.
	Covering func(call *McpCall, in *In) (*McpAccess, error)
}

// A tool's handler: the decoded input, the call, and the result it tags; its output is the result's data.
type McpToolHandler[In, Out any] func(ctx context.Context, call *McpCall, in *In, result *McpResult) (*Out, error)

// Registers a tool on catalog. Panics, as go-sdk's AddTool does, on a spec that cannot serve: no name or description,
// an unknown tier, no Access, a name taken, input or output types with no JSON schema, an input that names network or
// uses itself, or uses taken by a tool that files no outward action.
func AddTool[In, Out any](catalog *McpCatalog, spec *McpToolSpec[In], handler McpToolHandler[In, Out]) {
	if spec == nil || spec.Name == "" || spec.Description == "" || handler == nil || spec.Access == nil {
		panic("mcp.AddTool: a spec needs a name, a description, an Access function and a handler")
	}
	if spec.Tier < McpTierRead || McpTierOutward < spec.Tier {
		panic(fmt.Sprintf("mcp.AddTool %q: tier %d", spec.Name, spec.Tier))
	}
	if spec.Covering != nil && spec.Tier != McpTierOutward {
		panic(fmt.Sprintf("mcp.AddTool %q: only an O tool takes a covering grant", spec.Name))
	}
	if spec.MultiUse && spec.Tier != McpTierOutward && !spec.MayAct {
		panic(fmt.Sprintf("mcp.AddTool %q: only a tool that files an outward action takes uses", spec.Name))
	}
	inSchema, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("mcp.AddTool %q: input schema: %v", spec.Name, err))
	}
	if inSchema.Type != "object" {
		panic(fmt.Sprintf("mcp.AddTool %q: input is no object", spec.Name))
	}
	if _, named := inSchema.Properties[mcpNetworkArgumentName]; named {
		panic(fmt.Sprintf("mcp.AddTool %q: the input names network itself", spec.Name))
	}
	if _, named := inSchema.Properties[mcpUsesArgumentName]; named {
		// uses is the wrapper's to add, so a schema names it exactly where the spec takes it (McpToolSpec.MultiUse)
		panic(fmt.Sprintf("mcp.AddTool %q: the input names uses itself", spec.Name))
	}
	if inSchema.Properties == nil {
		inSchema.Properties = map[string]*jsonschema.Schema{}
	}
	inSchema.Properties[mcpNetworkArgumentName] = &jsonschema.Schema{
		Type:        "string",
		Description: "the network to act on, by id or name; omitted, the project's or the only one",
	}
	if spec.MultiUse {
		inSchema.Properties[mcpUsesArgumentName] = &jsonschema.Schema{
			Type:    "integer",
			Minimum: jsonschema.Ptr(1.0),
			Description: "how many calls one approval may cover: 2 or more asks a person to approve a template of this " +
				"call, each later call inside it spending one use, and answers approval_pending with the template's id " +
				"until it is approved; omitted or 1, this call alone",
		}
	}
	inResolved, err := inSchema.Resolve(nil)
	if err != nil {
		panic(fmt.Sprintf("mcp.AddTool %q: input schema: %v", spec.Name, err))
	}
	outSchema, err := jsonschema.For[Out](nil)
	if err != nil {
		panic(fmt.Sprintf("mcp.AddTool %q: output schema: %v", spec.Name, err))
	}

	openWorld := spec.Tier == McpTierOutward || spec.MayAct
	tool := &gomcp.Tool{
		Name:         spec.Name,
		Description:  spec.Description,
		InputSchema:  inSchema,
		OutputSchema: mcpEnvelopeSchema(outSchema),
		Annotations: &gomcp.ToolAnnotations{
			ReadOnlyHint:  spec.Tier == McpTierRead,
			OpenWorldHint: &openWorld,
		},
	}
	wrapped := func(ctx context.Context, request *gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		call := McpCallOf(ctx)
		started := catalog.clock.Now()
		arguments := mcpArgumentsOf(request)
		// the gate's harness evidence matches the call by its tool and its arguments' hash (harness_evidence.go)
		ctx = withMcpToolArguments(ctx, spec.Name, arguments)
		// progress the handler reports goes out while it runs, never after its answer (progress.go)
		progress := newMcpProgress(request)
		ctx = withMcpProgress(ctx, progress)
		recorded := newMcpResult(call)
		result, resultBytes, covered, err := mcpRunTool(ctx, catalog, spec, handler, inResolved, call, request, arguments, recorded)
		progress.close()
		// a result whose data the record must not keep is recorded as its stub, whatever its tier (§24.9, C-31)
		stub, stubbed := recorded.recordStubBytes()
		if stubbed {
			resultBytes = stub
		}
		if (spec.Tier == McpTierWrite || covered || stubbed) && call != nil && catalog.sink != nil {
			catalog.sink.RecordMcpCall(ctx, call, spec.Name, arguments, resultBytes, started.UnixMilli(), catalog.clock.Now().UnixMilli(), err)
		}
		if err != nil {
			return nil, mcpWireError(mcpCheckedError(call, err))
		}
		return result, nil
	}
	catalog.add(&mcpCatalogTool{
		tool: tool, tier: spec.Tier, mayAct: spec.MayAct, multiUse: spec.MultiUse, targeted: spec.Targets != nil, handler: wrapped,
	})
}

// The outputSchema every tool declares: the envelope, its data the handler's output, either form validating
// (result.go).
func mcpEnvelopeSchema(data *jsonschema.Schema) *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"trust":         {Type: "string", Enum: []any{string(McpTrustOwn), string(McpTrustMember), string(McpTrustUntrusted)}},
			"source":        {Type: "string"},
			"metered_bytes": {Type: "integer", Minimum: jsonschema.Ptr(0.0)},
			"marker_broken": {Type: "boolean"},
			"data":          data,
			"truncated":     {Type: "boolean"},
			"resource":      {Type: "string"},
		},
		Required: []string{"trust", "source", "metered_bytes"},
	}
}

// A request's arguments as sent, {} for none.
func mcpArgumentsOf(request *gomcp.CallToolRequest) []byte {
	if request == nil || request.Params == nil || len(request.Params.Arguments) == 0 {
		return []byte("{}")
	}
	return request.Params.Arguments
}

// One call through every step but the sink, its handler filling result: the result to send and its structured bytes,
// or the refusal, and whether a covering grant ran an O call as W.
func mcpRunTool[In, Out any](
	ctx context.Context,
	catalog *McpCatalog,
	spec *McpToolSpec[In],
	handler McpToolHandler[In, Out],
	inResolved *jsonschema.Resolved,
	call *McpCall,
	request *gomcp.CallToolRequest,
	arguments []byte,
	result *McpResult,
) (*gomcp.CallToolResult, []byte, bool, error) {
	if call == nil {
		return nil, nil, false, errMcpNoCall
	}
	network, ok := mcpToolNetworkOf(call)
	if !ok {
		return nil, nil, false, errMcpNoToolNetwork
	}
	now := catalog.clock.Now()
	// a call whose network has no policy installed is refused, whatever it would touch
	if network.Identity() == nil || !network.PolicyInstalled() {
		return nil, nil, false, errMcpNoPolicy
	}

	in, uses, err := mcpDecodeInput[In](inResolved, arguments, spec.MultiUse)
	if err != nil {
		return nil, nil, false, err
	}
	if spec.Targets != nil {
		targets, err := spec.Targets(call, in)
		if err != nil {
			return nil, nil, false, err
		}
		if refusal := McpGuard(targets); refusal != nil {
			return nil, nil, false, refusal
		}
	}
	accesses, err := spec.Access(call, in)
	if err != nil {
		return nil, nil, false, err
	}
	for _, access := range accesses {
		check, installed := network.Allow(access.Action, access.Resource, now)
		if !installed {
			return nil, nil, false, errMcpNoPolicy
		}
		if !check.Allowed {
			return nil, nil, false, errMcpNotAllowed
		}
	}
	covering := &mcpCovering{}
	if spec.Covering != nil {
		access, err := spec.Covering(call, in)
		if err != nil {
			return nil, nil, false, err
		}
		if access != nil {
			check, installed := network.Allow(access.Action, access.Resource, now)
			if !installed {
				return nil, nil, false, errMcpNoPolicy
			}
			covering.covered = check.Allowed
			covering.grantId = check.GrantId
		}
	}
	if spec.Tier == McpTierWrite || covering.covered {
		if err := call.Session.AdmitWrite(); err != nil {
			return nil, nil, covering.covered, err
		}
	}

	meter := &mcpMeter{}
	out, err := handler(withMcpUses(withMcpCovering(withMcpMeter(ctx, meter), covering), uses), call, in, result)
	if err != nil {
		return nil, nil, covering.covered, err
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, nil, covering.covered, errMcpFailed
	}
	envelope, err := result.envelope(json.RawMessage(data), meter.byteCount.Load())
	if err != nil {
		return nil, nil, covering.covered, err
	}
	matcher, err := network.SecretMatcher()
	if err != nil {
		return nil, nil, covering.covered, errMcpMatcher
	}
	if matcher.Matches(data) || matcher.Matches([]byte(envelope.Source)) {
		return nil, nil, covering.covered, errMcpResultSecret
	}
	resource := result.resourceUri()
	if matcher.Matches([]byte(resource)) {
		return nil, nil, covering.covered, errMcpResultSecret
	}
	shaped, shapedBytes, err := mcpShapeResult(envelope, mcpProtocolVersion(request), catalog.settings.ResultByteCount, resource)
	if err != nil {
		return nil, nil, covering.covered, err
	}
	return shaped, shapedBytes, covering.covered, nil
}

// Whether a covering grant ran an O call as W, and that grant's id.
type mcpCovering struct {
	covered bool
	grantId []byte
}

// The context key of a call's covering grant.
type mcpCoveringContextKey struct{}

// ctx carrying covering.
func withMcpCovering(ctx context.Context, covering *mcpCovering) context.Context {
	return context.WithValue(ctx, mcpCoveringContextKey{}, covering)
}

// Whether the O call ctx runs runs as W under a covering grant (McpToolSpec.Covering), and the grant's id, which a
// handler names in its result. False outside a covered call.
func McpCoveringGrant(ctx context.Context) ([]byte, bool) {
	covering, _ := ctx.Value(mcpCoveringContextKey{}).(*mcpCovering)
	if covering == nil || !covering.covered {
		return nil, false
	}
	return covering.grantId, true
}

// The context key of a call's uses.
type mcpUsesContextKey struct{}

// ctx carrying uses.
func withMcpUses(ctx context.Context, uses uint32) context.Context {
	return context.WithValue(ctx, mcpUsesContextKey{}, uses)
}

// The uses the call ctx runs names (McpToolSpec.MultiUse): 2 or more asks for a template, 1 for this action alone. 0
// where the call names none, or its tool takes none, which is this action alone too.
func McpUses(ctx context.Context) uint32 {
	uses, _ := ctx.Value(mcpUsesContextKey{}).(uint32)
	return uses
}

// arguments decoded into In, and the uses a multiUse tool's call names, 0 for none: valid against the input schema,
// which refuses a key it does not name, then decoded without network, which the middleware resolved, and without uses,
// which the handler reads apart (McpUses). Every refusal is errMcpInvalidArguments, whose text is constant.
func mcpDecodeInput[In any](inResolved *jsonschema.Resolved, arguments []byte, multiUse bool) (*In, uint32, error) {
	var instance any
	if err := json.Unmarshal(arguments, &instance); err != nil {
		return nil, 0, errMcpInvalidArguments
	}
	object, ok := instance.(map[string]any)
	if !ok {
		return nil, 0, errMcpInvalidArguments
	}
	if err := inResolved.Validate(instance); err != nil {
		return nil, 0, errMcpInvalidArguments
	}
	delete(object, mcpNetworkArgumentName)
	uses := uint32(0)
	if value, named := object[mcpUsesArgumentName]; named && multiUse {
		// the schema held it to an integer of at least 1; past uint32's range it is no count a request names
		count, ok := value.(float64)
		if !ok || count < 1 || math.MaxUint32 < count || count != math.Trunc(count) {
			return nil, 0, errMcpInvalidArguments
		}
		uses = uint32(count)
		delete(object, mcpUsesArgumentName)
	}
	stripped, err := json.Marshal(object)
	if err != nil {
		return nil, 0, errMcpInvalidArguments
	}
	decoder := json.NewDecoder(bytes.NewReader(stripped))
	decoder.DisallowUnknownFields()
	in := new(In)
	if err := decoder.Decode(in); err != nil {
		return nil, 0, errMcpInvalidArguments
	}
	return in, uses, nil
}

// err as it may reach the caller: an error whose text holds a credential or a token form becomes "the tool failed",
// so no error echoes a secret, whoever wrote it (I-7). While the daemon's credentials cannot be read, only the
// framework's and the server's own errors pass, whose texts are constant.
func mcpCheckedError(call *McpCall, err error) error {
	// nil matches the redactor's token forms alone
	var matcher *sidecar.SecretMatcher
	if network, ok := mcpToolNetworkOf(call); ok {
		built, buildErr := network.SecretMatcher()
		if buildErr != nil {
			var mcpError *McpError
			var wire *jsonrpc.Error
			if !errors.As(err, &mcpError) && !errors.As(err, &wire) {
				return errMcpFailed
			}
		} else {
			matcher = built
		}
	}
	if matcher.Matches([]byte(err.Error())) {
		return errMcpFailed
	}
	return err
}
