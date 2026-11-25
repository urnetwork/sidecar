//go:build !ios_extension && !sidecar_http

// sidecar's events, after Pi's (DESIGN-COMPUTE §7.6): approvals, attestation badges, usage and the cost meter,
// sub-agents, the attach link's status, and ui requests, which carry Pi's extension_ui_request members under
// sidecar's ui_request and ui_response types. Their members are named as Pi names its own, camelCase, since every
// view of the stream reads one convention.
//
// Nothing here carries a disclosure's text: a disclosure request names its id and version alone, and a view renders
// the signed policy's text for them (D-HARN-10, §2.8). An approval relayed from a remote Harness renders from the
// approval log's entry alone, never from the event (HARN-M14-03), and an automatic decision is a note in the run,
// never the person's approval (§27.9).

package sidecar

import (
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/urnetwork/sidecar/protocol"
)

// sidecar's event types (§7.6).
const (
	HarnessEventApprovalPending  HarnessEventType = "approval_pending"
	HarnessEventApprovalResolved HarnessEventType = "approval_resolved"
	HarnessEventAttestation      HarnessEventType = "attestation"
	HarnessEventUsage            HarnessEventType = "usage"
	HarnessEventAgentSpawned     HarnessEventType = "agent_spawned"
	HarnessEventAgentExited      HarnessEventType = "agent_exited"
	HarnessEventAttachStatus     HarnessEventType = "attach_status"
	HarnessEventUiRequest        HarnessEventType = "ui_request"
	HarnessEventUiResponse       HarnessEventType = "ui_response"
)

// The note an automatic decision shows in its run, never as the person's approval (§27.9).
const HarnessAutomaticDecisionNote = "approved automatically by this device's check"

// What approval_pending shows of a request (DESIGN §16.6): its id, kind, the action's canonical text as the daemon
// built it, and the evidence a decision may carry.
type HarnessApprovalPending struct {
	ApprovalId Id
	// record.proto's name for the kind, lowercased past its prefix.
	Kind string
	// The canonical action's text, as an approver's device renders it (ApprovalRender.Text).
	Text string
	// The channels a decision may come by: device, presence, and harness where the run may take it.
	Evidence []string
	// Filed in a tainted run (TS1).
	Tainted bool
}

// approval_pending.
func NewHarnessApprovalPendingEvent(pending *HarnessApprovalPending) *HarnessEvent {
	evidence := pending.Evidence
	if evidence == nil {
		evidence = []string{}
	}
	return newHarnessEventOf(HarnessEventApprovalPending, "approvalId", pending.ApprovalId.String(),
		"kind", pending.Kind, "text", pending.Text, "evidence", evidence, "tainted", pending.Tainted)
}

// An automatic decision's verdict (§27.9): why the device's check let the action go ahead, and its score.
type HarnessAutoVerdict struct {
	Reason string  `json:"reason"`
	Score  float64 `json:"score"`
}

// What approval_resolved shows: how the approval stands, the channels its kept decisions came by, and for an
// automatic decision its verdict and the note the run shows.
type HarnessApprovalResolved struct {
	ApprovalId Id
	// ApprovalStatusState's word: approved, denied, cancelled, expired, spent or uncertain.
	State    string
	Channels []string
	// Set where the decision was the device's automatic one alone.
	Auto *HarnessAutoVerdict
}

// approval_resolved. An automatic decision carries auto and the note, never the person's approval.
func NewHarnessApprovalResolvedEvent(resolved *HarnessApprovalResolved) *HarnessEvent {
	channels := resolved.Channels
	if channels == nil {
		channels = []string{}
	}
	event := newHarnessEventOf(HarnessEventApprovalResolved, "approvalId", resolved.ApprovalId.String(),
		"state", resolved.State, "channels", channels)
	if resolved.Auto != nil {
		event.fields.set("auto", resolved.Auto)
		event.fields.set("note", HarnessAutomaticDecisionNote)
	}
	return event
}

// attestation: a remote call's verified result (§5.8), or for a model without a TEE its label alone. The badge's
// disclosure line comes from the signed policy by the provider, never from this event (§7.6).
func NewHarnessAttestationEvent(model string, label ComputeLabel, result *protocol.AttestationResult) *HarnessEvent {
	event := newHarnessEventOf(HarnessEventAttestation, "model", model, "label", string(label))
	if result != nil {
		encoded, err := protojson.Marshal(result)
		if err == nil {
			if compacted, err := harnessPiCompact(encoded); err == nil {
				event.fields.setRaw("result", compacted)
			}
		}
	}
	return event
}

// What usage shows (§7.6's cost meter): the call's tokens and charge, and the run's total charge, in nano-USD.
type HarnessUsage struct {
	Model           string
	InputTokens     uint64
	OutputTokens    uint64
	CachedTokens    uint64
	ReasoningTokens uint64
	ChargeNanoUsd   uint64
	RunNanoUsd      uint64
}

// usage.
func NewHarnessUsageEvent(usage *HarnessUsage) *HarnessEvent {
	return newHarnessEventOf(HarnessEventUsage, "model", usage.Model, "inputTokens", usage.InputTokens,
		"outputTokens", usage.OutputTokens, "cachedTokens", usage.CachedTokens, "reasoningTokens", usage.ReasoningTokens,
		"chargeNanoUsd", usage.ChargeNanoUsd, "runNanoUsd", usage.RunNanoUsd)
}

// A child agent as agent_spawned and agent_exited name it (§7.9).
type HarnessAgentLink struct {
	ChildId Id
	Name    string
	Model   string
	// local, or enclave:<name>
	Where string
	RunId Id
}

// agent_spawned, which an app's agent tree nests the child's events under.
func NewHarnessAgentSpawnedEvent(link *HarnessAgentLink) *HarnessEvent {
	return newHarnessEventOf(HarnessEventAgentSpawned, "child", link.ChildId.String(), "name", link.Name,
		"model", link.Model, "where", link.Where, "run", link.RunId.String())
}

// agent_exited, with the child's stop reason.
func NewHarnessAgentExitedEvent(link *HarnessAgentLink, stopReason string) *HarnessEvent {
	return newHarnessEventOf(HarnessEventAgentExited, "child", link.ChildId.String(), "name", link.Name,
		"model", link.Model, "where", link.Where, "run", link.RunId.String(), "stopReason", stopReason)
}

// attach_status's states and modes (§7.10).
const (
	HarnessAttachAttached     = "attached"
	HarnessAttachDetached     = "detached"
	HarnessAttachReconnecting = "reconnecting"

	// One session of the remote Harness.
	HarnessAttachModeSession = "session"
	// The whole remote Harness, its management mode.
	HarnessAttachModeManage = "manage"
)

// attach_status: the link's state, the remote Harness's name and the link's mode.
func NewHarnessAttachStatusEvent(state string, harness string, mode string) *HarnessEvent {
	return newHarnessEventOf(HarnessEventAttachStatus, "state", state, "harness", harness, "mode", mode)
}

// ui_request: Pi's extension_ui_request members under sidecar's type. A disclosure's request carries its id, method,
// disclosure id and version and nothing else (D-HARN-10).
func NewHarnessUiRequestEvent(request *HarnessUiRequest) *HarnessEvent {
	event := NewHarnessEvent(HarnessEventUiRequest)
	event.fields = request.object()
	return event
}

// ui_response: how a request ended, which closes its dialog in every view.
func NewHarnessUiResponseEvent(response *HarnessUiResponse) *HarnessEvent {
	event := NewHarnessEvent(HarnessEventUiResponse)
	event.fields = response.object()
	return event
}

// The request a ui_request event carries, or nil.
func (self *HarnessEvent) UiRequest() *HarnessUiRequest {
	if self.Type != HarnessEventUiRequest {
		return nil
	}
	encoded, err := self.fields.MarshalJSON()
	if err != nil {
		return nil
	}
	request := &HarnessUiRequest{}
	if json.Unmarshal(encoded, request) != nil {
		return nil
	}
	return request
}
