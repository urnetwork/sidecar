//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The gateway's recording seam (DESIGN-COMPUTE §8.9, §24.8, IC-19; R-GW-6, D-GW-2): what the fronts call at IC-19's two
// points, and GW-M12-06 implements over CTXH's session recorder (SessionGatewayRecorder) and INFER's model_call writer
// (GatewayCallRecorder). The fronts hold the order:
//
//	begin     a call's request items are recorded before it goes upstream: Begin answers once they are journaled, and
//	          a call whose Begin fails is refused, never sent (IC-19); Begin is called after the router's check, so a
//	          refused call records nothing
//	items     each response item is recorded as the front completes it, before the event that completes it reaches
//	          the caller (response.output_item.done, the chunk carrying finish_reason), so a tool the harness starts on
//	          it finds it journaled; ResponseItem answers the item's node, which the reasoning blob names (§8.5, §24.8).
//	          A failed ResponseItem ends the call before the item is sent
//	end       End once the terminal is decided, with what the call used, for its model_call; a join of a call in
//	          flight, or an answer from a kept response, records nothing (§24.8's order row)
//	cut       after a crash the daemon reads what it kept (GW-M12-05): Cut writes the model_call of a call the crash cut,
//	          its output as far as it was journaled, the rest a gap
//
// Nothing recorded is read back to answer a call (D-GW-2), and the recorder sees no token. With no recorder set every
// call is refused 503, since none could be journaled (IC-19).

package sidecar

import (
	"context"

	"github.com/urnetwork/sidecar/protocol"
)

// The session renderers the fronts register (session_render.go): a recorded call's request is the front's
// translation of its recorded items, so request_sha256 is what was sent by construction.
const (
	GatewayRendererResponses       = "gateway-responses-1"
	GatewayRendererChatCompletions = "gateway-chat_completions-1"
)

// The recorder the fronts call (see the file header). Safe for concurrent use.
type GatewayRecorder interface {
	// Records a call's request before it goes upstream: answers once its new items are journaled, or why they could
	// not be, which refuses the call.
	Begin(ctx context.Context, begin *GatewayRecordBegin) (GatewayRecordCall, error)
	// Writes the model_call of a call a crash cut, from what the gateway kept of it (GW-M12-05): its output as far as
	// it was journaled, the rest a gap in its run's coverage. A nil error once written; the daemon tries again at its
	// next start otherwise.
	Cut(ctx context.Context, cut *GatewayRecordCut) error
}

// One call being recorded, as Begin answers it. Its methods are called in order from one goroutine.
type GatewayRecordCall interface {
	// Records one response item as the front completes it, the item in its API's form (a Responses output item, a
	// Chat Completions assistant message), before the event that completes it is sent: answers its node, or why it
	// could not be journaled, which ends the call.
	ResponseItem(ctx context.Context, item []byte) (Id, error)
	// Ends the call: what it used, for its model_call.
	End(ctx context.Context, end *GatewayRecordEnd) error
}

// What Begin records.
type GatewayRecordBegin struct {
	NetworkId Id
	// The network the call's grant is on (*Sidecar in the daemon).
	Network GatewayNetwork
	Harness string
	// The call's binding (§8.9): its run, agent, grant, handle, and the union the router checked.
	Binding *GatewayBinding
	Api     SessionGatewayApi
	// The renderer the front registered, GatewayRendererResponses or GatewayRendererChatCompletions.
	Renderer string
	// The body as the front routes it, its API's JSON: the request as the model receives it, hosted search dropped
	// (§21.7), its images re-encoded (§8.5) and each reasoning item's text the gateway's own (gateway_reasoning.go).
	Body []byte
	// The response's id the front gave the call (resp_…, chatcmpl-…).
	ResponseId string
	// The model the request names, a canonical name or an alias (§6.3).
	Model string
}

// How a call ended.
type GatewayRecordOutcome string

const (
	// The model's answer came whole.
	GatewayRecordCompleted GatewayRecordOutcome = "completed"
	// The call failed: Error says how.
	GatewayRecordFailed GatewayRecordOutcome = "failed"
)

// What End records of a call.
type GatewayRecordEnd struct {
	Outcome GatewayRecordOutcome
	// What it used and, for a remote call, its charge; nil where the router gave no usage.
	Usage *InferUsage
	// A remote call's verified attestations (§6.8), in order.
	Attestations []*protocol.AttestationResult
	// The failure, for a failed call.
	Error *InferError
	// The provider's request id the call's model_call names, empty where the router gave none.
	RequestId string
}

// What Cut records of a call a crash cut.
type GatewayRecordCut struct {
	NetworkId  Id
	Harness    string
	Binding    *GatewayBinding
	Api        SessionGatewayApi
	ResponseId string
	Model      string
	// The response items journaled before the crash, each its node, in order.
	NodeIds []Id
	// When the call began, in Unix milliseconds by the daemon's clock.
	BeganMillis int64
}
