//go:build !js && !ios && !android && !sdk_mobile_bind

// The tool framework (D-MCP-3, D-MCP-4, D-MCP-13, D-MCP-17, R-MCP-9, I-7, I-8, I-9, I-13, X1): AddTool registers one
// tool on an McpCatalog under a constant spec, and the wrapper does everything a tool must not forget. Per call, in
// order:
//
//	network  the call's network resolved by §5.8's rules and ready (server.go's middleware), read as an
//	         McpToolNetwork with a policy installed, else refused
//	input    the arguments against the tool's input schema, network among them and no key it does not name; a
//	         refusal's text is constant, never the schema validator's, which can quote a value
//	guard    McpGuard on what the call would touch (spec.Targets)
//	allow    §8's local allow for the session's subject, the sidecar every in-daemon agent shares (owner decision 6;
//	         §5.5), on each McpAccess the call needs (spec.Access)
//	rate     a W tool's call takes one of the session's W tokens (§16.4)
//	handler  under a metered-bytes counter (McpMeter); any error it returns becomes an McpError, since go-sdk embeds a
//	         returned error's text in the result
//	tags     the result's trust and source, fenced text only from a tainted run (result.go)
//	secret   a result holding a credential or a token form is refused, and so is an error whose text holds one (I-7)
//	shape    past ResultByteCount, a link to the result's resource, by the session's version (D-MCP-13)
//	sink     a W call's arguments, result and outcome to McpCallSink, a tool_call entry, source observed (MCP-M3-19)
//
// Tier hints: R sets readOnlyHint; O, and a W tool that may run an outward action (spec.MayAct), set openWorldHint;
// every other tool sets openWorldHint false, since the protocol's default is true. A description is the spec's
// constant, so no tool list holds a variable (D-MCP-3), and the tool list is the catalog, fixed before any session
// starts (catalog.go). Nothing here logs a call's arguments or result (I-13).

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

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

// One tool's constant spec. Every function is called per call, before the handler, with the decoded input.
type McpToolSpec[In any] struct {
	Name string
	Tier McpTier
	// Constant text: no variable ever reaches a tool list (D-MCP-3).
	Description string
	// A W tool that may also run an outward action through Authorize, as evs_write does for agent-config files and
	// mail_send for outside recipients (§16.5): it sets openWorldHint.
	MayAct bool
	// What the call would touch, for McpGuard. Nil touches nothing the guard names.
	Targets func(call *McpCall, in *In) ([]McpTarget, error)
	// The grants the call needs from §8's local evaluation, every one allowed or the call is refused. Required: a tool
	// that needs none returns none.
	Access func(call *McpCall, in *In) ([]McpAccess, error)
}

// A tool's handler: the decoded input, the call, and the result it tags; its output is the result's data.
type McpToolHandler[In, Out any] func(ctx context.Context, call *McpCall, in *In, result *McpResult) (*Out, error)

// Registers a tool on catalog. Panics, as go-sdk's AddTool does, on a spec that cannot serve: no name or description,
// an unknown tier, no Access, a name taken, input or output types with no JSON schema, or an input that names
// network itself.
func AddTool[In, Out any](catalog *McpCatalog, spec *McpToolSpec[In], handler McpToolHandler[In, Out]) {
	if spec == nil || spec.Name == "" || spec.Description == "" || handler == nil || spec.Access == nil {
		panic("mcp.AddTool: a spec needs a name, a description, an Access function and a handler")
	}
	if spec.Tier < McpTierRead || McpTierOutward < spec.Tier {
		panic(fmt.Sprintf("mcp.AddTool %q: tier %d", spec.Name, spec.Tier))
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
	if inSchema.Properties == nil {
		inSchema.Properties = map[string]*jsonschema.Schema{}
	}
	inSchema.Properties[mcpNetworkArgumentName] = &jsonschema.Schema{
		Type:        "string",
		Description: "the network to act on, by id or name; omitted, the project's or the only one",
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
		result, resultBytes, err := mcpRunTool(ctx, catalog, spec, handler, inResolved, call, request, arguments)
		if spec.Tier == McpTierWrite && call != nil && catalog.sink != nil {
			catalog.sink.RecordMcpCall(ctx, call, spec.Name, arguments, resultBytes, started.UnixMilli(), catalog.clock.Now().UnixMilli(), err)
		}
		if err != nil {
			return nil, mcpWireError(mcpCheckedError(call, err))
		}
		return result, nil
	}
	catalog.add(&mcpCatalogTool{tool: tool, tier: spec.Tier, mayAct: spec.MayAct, handler: wrapped})
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

// One call through every step but the sink: the result to send and its structured bytes, or the refusal.
func mcpRunTool[In, Out any](
	ctx context.Context,
	catalog *McpCatalog,
	spec *McpToolSpec[In],
	handler McpToolHandler[In, Out],
	inResolved *jsonschema.Resolved,
	call *McpCall,
	request *gomcp.CallToolRequest,
	arguments []byte,
) (*gomcp.CallToolResult, []byte, error) {
	if call == nil {
		return nil, nil, errMcpNoCall
	}
	network, ok := mcpToolNetworkOf(call)
	if !ok {
		return nil, nil, errMcpNoToolNetwork
	}
	now := catalog.clock.Now()
	// a call whose network has no policy installed is refused, whatever it would touch
	if network.Identity() == nil || !network.PolicyInstalled() {
		return nil, nil, errMcpNoPolicy
	}

	in, err := mcpDecodeInput[In](inResolved, arguments)
	if err != nil {
		return nil, nil, err
	}
	if spec.Targets != nil {
		targets, err := spec.Targets(call, in)
		if err != nil {
			return nil, nil, err
		}
		if refusal := McpGuard(targets); refusal != nil {
			return nil, nil, refusal
		}
	}
	accesses, err := spec.Access(call, in)
	if err != nil {
		return nil, nil, err
	}
	for _, access := range accesses {
		check, installed := network.Allow(access.Action, access.Resource, now)
		if !installed {
			return nil, nil, errMcpNoPolicy
		}
		if !check.Allowed {
			return nil, nil, errMcpNotAllowed
		}
	}
	if spec.Tier == McpTierWrite {
		if err := call.Session.AdmitWrite(); err != nil {
			return nil, nil, err
		}
	}

	meter := &mcpMeter{}
	result := newMcpResult(call)
	out, err := handler(withMcpMeter(ctx, meter), call, in, result)
	if err != nil {
		return nil, nil, err
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, nil, errMcpFailed
	}
	envelope, err := result.envelope(json.RawMessage(data), meter.byteCount.Load())
	if err != nil {
		return nil, nil, err
	}
	matcher, err := network.SecretMatcher()
	if err != nil {
		return nil, nil, errMcpMatcher
	}
	if matcher.Matches(data) || matcher.Matches([]byte(envelope.Source)) {
		return nil, nil, errMcpResultSecret
	}
	resource := result.resourceUri()
	if matcher.Matches([]byte(resource)) {
		return nil, nil, errMcpResultSecret
	}
	shaped, shapedBytes, err := mcpShapeResult(envelope, mcpProtocolVersion(request), catalog.settings.ResultByteCount, resource)
	if err != nil {
		return nil, nil, err
	}
	return shaped, shapedBytes, nil
}

// arguments decoded into In: valid against the input schema, which refuses a key it does not name, then decoded
// without network, which the middleware resolved. Every refusal is errMcpInvalidArguments, whose text is constant.
func mcpDecodeInput[In any](inResolved *jsonschema.Resolved, arguments []byte) (*In, error) {
	var instance any
	if err := json.Unmarshal(arguments, &instance); err != nil {
		return nil, errMcpInvalidArguments
	}
	object, ok := instance.(map[string]any)
	if !ok {
		return nil, errMcpInvalidArguments
	}
	if err := inResolved.Validate(instance); err != nil {
		return nil, errMcpInvalidArguments
	}
	delete(object, mcpNetworkArgumentName)
	stripped, err := json.Marshal(object)
	if err != nil {
		return nil, errMcpInvalidArguments
	}
	decoder := json.NewDecoder(bytes.NewReader(stripped))
	decoder.DisallowUnknownFields()
	in := new(In)
	if err := decoder.Decode(in); err != nil {
		return nil, errMcpInvalidArguments
	}
	return in, nil
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
