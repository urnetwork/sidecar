//go:build !js && !ios && !android && !sdk_mobile_bind

// A remote-mode desktop app's request methods (MCP-M8-01; §16.6's host table, D-SDK-9, D-CORE-13, D-MCP-14, I-8): the
// app's SidecarApprovals lists and decides §16.8's requests on its daemon through these, never through ur approve's
// methods, so the daemon decides as the table's remote-mode row (record_approval_app.go): other sidecars' requests
// by device, after the app's confirmation, and never this sidecar's own, which the list shows with no decision for ur
// approve or the daemon's prompt to answer.
//
//	approvals.app.requests   the requests waiting for this device, each rendered with what the app may answer, or
//	                         shown refused; nothing on a device that is no approval-capable device of its member
//	approvals.app.request    Confirm: one decision, approve or deny, signed by the identity key and filed in the
//	                         request's log
//
// Each takes the network the app's pairing bound, else §5.8's rule picks it. ur native-host relays neither: its
// allow-list holds no request method. Replies carry ids, the render's printable text and answers, never a key or a
// token (I-7).

package sidecar

import (
	"context"
	"errors"
)

// The methods.
const (
	// The requests a remote-mode app lists.
	DaemonMethodApprovalsAppRequests = "approvals.app.requests"
	// A remote-mode app's decision on one of them.
	DaemonMethodApprovalsAppRequest = "approvals.app.request"
)

// A decision's params that name no approval or no decision.
var errDaemonApprovalsAppParams = errors.New("a decision takes an approval id and approve or deny")

// approvals.app.requests' params.
type DaemonApprovalsAppParams struct {
	Network string `json:"network,omitempty"`
}

// One request as approvals.app.requests lists it.
type DaemonApprovalsAppItem struct {
	// Nil for a request shown refused, which takes no decision.
	ApprovalId *Id `json:"approval_id,omitempty"`
	EntryId    Id  `json:"entry_id"`
	// The requesting sidecar; nil for a request shown refused.
	SidecarId *Id `json:"sidecar_id,omitempty"`
	// The action's kind as record.proto names it.
	Kind string `json:"kind,omitempty"`
	// A multi-use template.
	Template bool `json:"template,omitempty"`
	// The render's printable text: the daemon-built fields, the agent's words under their untrusted heading.
	Text string `json:"text,omitempty"`
	// Why this device shows it refused; empty for none.
	Refused string `json:"refused,omitempty"`
	// device where the app may sign it; empty where it signs none, as for this sidecar's own request.
	Channel string `json:"channel,omitempty"`
	// What the app may answer: approve and deny, deny alone, or none.
	Decisions []string `json:"decisions"`
}

// approvals.app.requests' reply.
type DaemonApprovalsAppReply struct {
	Items []*DaemonApprovalsAppItem `json:"items"`
}

// approvals.app.request's params.
type DaemonApprovalsAppDecideParams struct {
	Network    string `json:"network,omitempty"`
	ApprovalId Id     `json:"approval_id"`
	// approve or deny.
	Decision string `json:"decision"`
}

// The channel's name as the app shows it, empty where the app signs none.
func daemonApprovalsAppChannel(item *SidecarRequestItem) string {
	if item.Render == nil || len(item.Decisions) == 0 {
		return ""
	}
	return approvalChannelName(item.Channel)
}

// The request methods a remote-mode app calls, each on its call's network's Sidecar as the remote-mode row decides. The
// daemon's composition registers them with RegisterMethod.
func DaemonApprovalsAppMethods() []*DaemonMethod {
	return []*DaemonMethod{
		{
			Name:    DaemonMethodApprovalsAppRequests,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonApprovalsAppParams{}
				if err := decodeDaemonDevicesParams(call, params); err != nil {
					return nil, err
				}
				approver, err := call.Sidecar.ApprovalApprover()
				if err != nil {
					return nil, err
				}
				items, err := approver.ForHost(ApprovalHostAppRemote).Pending(ctx)
				if err != nil {
					return nil, err
				}
				reply := &DaemonApprovalsAppReply{Items: []*DaemonApprovalsAppItem{}}
				for _, item := range items {
					replyItem := &DaemonApprovalsAppItem{
						EntryId:   item.EntryId,
						Refused:   item.Refused,
						Channel:   daemonApprovalsAppChannel(item),
						Decisions: item.Decisions,
					}
					if item.Render != nil {
						approvalId := item.ApprovalId
						requesterId := item.Render.RequesterSidecarId
						replyItem.ApprovalId = &approvalId
						replyItem.SidecarId = &requesterId
						replyItem.Kind = item.Render.KindName
						replyItem.Template = item.Render.Template
						replyItem.Text = item.Render.Text()
					}
					reply.Items = append(reply.Items, replyItem)
				}
				return reply, nil
			},
		},
		{
			Name:    DaemonMethodApprovalsAppRequest,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonApprovalsAppDecideParams{}
				if err := decodeDaemonDevicesParams(call, params); err != nil {
					return nil, err
				}
				if params.ApprovalId == (Id{}) || (params.Decision != SidecarDecisionApprove && params.Decision != SidecarDecisionDeny) {
					return nil, errDaemonApprovalsAppParams
				}
				approver, err := call.Sidecar.ApprovalApprover()
				if err != nil {
					return nil, err
				}
				// Confirm let only a confirmed control call here; no presence check: the remote-mode row signs no
				// request on presence
				err = approver.ForHost(ApprovalHostAppRemote).Decide(ctx, params.ApprovalId, &SidecarRequestDecision{Decision: params.Decision},
					SidecarActConfirmed, nil)
				if err != nil {
					return nil, err
				}
				return map[string]any{}, nil
			},
		},
	}
}
