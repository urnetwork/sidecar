// ur approve for §16's requests (MCP-M3-07; §16.6, D-CORE-13, D-MCP-14, D-MCP-17): beside CORE-M2-04's authority kinds,
// whose path ur approve keeps for them, dispatching by kind, ur approve lists the requests waiting for this device;
// ur approve <id> prints one request's render, the daemon-built action apart from the agent's untrusted text, and signs
// a decision only after the person's yes on /dev/tty, through a Confirm method that no mcp or hook session reaches; and
// ur approve cancel <id> signs an approval's cancel the same way. Every line the daemon sends is printed through
// ApprovalPrintable once more here, so no control character reaches the terminal whatever a daemon answers.
//
//	approvals.requests   the requests and what this device may answer each
//	approvals.request    Confirm: a decision, approve or deny, with uses for a template
//	approvals.cancel     Confirm: a cancel
//
// A request this sidecar made itself signs on channel presence, through the daemon's presence prompt, never device
// (§16.6's host table); a daemon with no presence prompt refuses it.

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The control methods ur approve calls for requests.
const (
	urMethodApprovalsRequests = "approvals.requests"
	urMethodApprovalsRequest  = "approvals.request"
	urMethodApprovalsCancel   = "approvals.cancel"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urApproveRequestMethods)
}

// What the request methods act on: a daemon target that runs a Sidecar.
type urRequestsTarget interface {
	pendingRequests(ctx context.Context) ([]*sidecar.SidecarRequestItem, error)
	decideRequest(ctx context.Context, approvalId sidecar.Id, decision *sidecar.SidecarRequestDecision) error
	cancelApproval(ctx context.Context, approvalId sidecar.Id) error
}

func (self *urDaemonNetwork) pendingRequests(ctx context.Context) ([]*sidecar.SidecarRequestItem, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	approver, err := running.ApprovalApprover()
	if err != nil {
		return nil, err
	}
	return approver.Pending(ctx)
}

// A confirmed control call, the person having answered on /dev/tty; an own request takes the daemon's presence prompt.
func (self *urDaemonNetwork) decideRequest(ctx context.Context, approvalId sidecar.Id, decision *sidecar.SidecarRequestDecision) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	approver, err := running.ApprovalApprover()
	if err != nil {
		return err
	}
	return approver.Decide(ctx, approvalId, decision, sidecar.SidecarActConfirmed, self.presenceCheck(running))
}

// The presence check this host's own requests take: the daemon's presence prompt over its authenticator, nil where none
// is set, which refuses an own request.
func (self *urDaemonNetwork) presenceCheck(running *sidecar.Sidecar) sidecar.SidecarPresenceCheck {
	if self.daemon == nil {
		return nil
	}
	return self.daemon.PresencePrompt(running)
}

// A confirmed control call.
func (self *urDaemonNetwork) cancelApproval(ctx context.Context, approvalId sidecar.Id) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	approver, err := running.ApprovalApprover()
	if err != nil {
		return err
	}
	return approver.Cancel(ctx, approvalId, sidecar.SidecarActConfirmed)
}

// One request as approvals.requests answers it: ids, the render's printable text and what this device may answer.
type urRequestItem struct {
	// nil for a request shown refused
	ApprovalId *sidecar.Id `json:"approval_id,omitempty"`
	EntryId    sidecar.Id  `json:"entry_id"`
	Kind       string      `json:"kind,omitempty"`
	Template   bool        `json:"template,omitempty"`
	Text       string      `json:"text,omitempty"`
	Refused    string      `json:"refused,omitempty"`
	// device or presence, empty where this device signs none
	Channel   string   `json:"channel,omitempty"`
	Decisions []string `json:"decisions"`
}

// approvals.requests' reply.
type urRequestsReply struct {
	Items []*urRequestItem `json:"items"`
}

// approvals.request's params.
type urRequestDecideParams struct {
	ApprovalId sidecar.Id `json:"approval_id"`
	Decision   string     `json:"decision"`
	Uses       uint32     `json:"uses,omitempty"`
}

// approvals.cancel's params.
type urApprovalCancelParams struct {
	ApprovalId sidecar.Id `json:"approval_id"`
}

// A channel's name as ur prints it.
func urApprovalChannelName(channel protocol.ApprovalChannel) string {
	switch channel {
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE:
		return "device"
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE:
		return "presence"
	}
	return ""
}

// The request methods over target, when it runs a Sidecar.
func urApproveRequestMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	requests, ok := target.(urRequestsTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodApprovalsRequests,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				items, err := requests.pendingRequests(ctx)
				if err != nil {
					return nil, err
				}
				reply := &urRequestsReply{Items: []*urRequestItem{}}
				for _, item := range items {
					replyItem := &urRequestItem{
						EntryId:   item.EntryId,
						Refused:   item.Refused,
						Channel:   urApprovalChannelName(item.Channel),
						Decisions: item.Decisions,
					}
					if item.Render != nil {
						approvalId := item.ApprovalId
						replyItem.ApprovalId = &approvalId
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
			Name:    urMethodApprovalsRequest,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urRequestDecideParams{}
				if err := decodeUrParams(call, params); err != nil || params.Decision == "" {
					return nil, errors.New("a decision takes an approval id and a decision")
				}
				return nil, requests.decideRequest(ctx, params.ApprovalId, &sidecar.SidecarRequestDecision{Decision: params.Decision, Uses: params.Uses})
			},
		},
		{
			Name:    urMethodApprovalsCancel,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urApprovalCancelParams{}
				if err := decodeUrParams(call, params); err != nil || params.ApprovalId == (sidecar.Id{}) {
					return nil, errors.New("a cancel takes an approval id")
				}
				return nil, requests.cancelApproval(ctx, params.ApprovalId)
			},
		},
	}
}

// The requests waiting for this device, or an error a daemon without the methods answers.
func urPendingRequests(ctx context.Context, cli *urCli) ([]*urRequestItem, error) {
	reply := &urRequestsReply{}
	if err := cli.callDaemon(ctx, urMethodApprovalsRequests, nil, false, reply); err != nil {
		return nil, err
	}
	return reply.Items, nil
}

// Prints one line per request to stdout for ur approve's list: printable, what this device may answer last.
func urPrintRequests(cli *urCli, items []*urRequestItem) {
	for _, item := range items {
		if item.ApprovalId == nil {
			cli.printf("refused  entry %s: %s\n", item.EntryId, sidecar.ApprovalPrintable(item.Refused))
			continue
		}
		kind := sidecar.ApprovalPrintable(item.Kind)
		if item.Template {
			kind += ", template"
		}
		answers := strings.Join(item.Decisions, "|")
		if answers == "" {
			answers = "not this device's to decide"
		}
		cli.printf("%s  request %s  %s\n", item.ApprovalId, kind, answers)
	}
}

// ur approve <id> on a request: its render on /dev/tty, then the person's yes, then the decision, signed by the
// daemon. Without a terminal it refuses, never reading stdin.
func runUrApproveRequest(ctx context.Context, cli *urCli, approvalId sidecar.Id, options docopt.Opts) error {
	items, err := urPendingRequests(ctx, cli)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(items, func(item *urRequestItem) bool { return item.ApprovalId != nil && *item.ApprovalId == approvalId })
	if index < 0 {
		return errors.New("no such approval waits for this device")
	}
	item := items[index]
	decision := sidecar.SidecarDecisionApprove
	if urOptionBool(options, "--deny") {
		decision = sidecar.SidecarDecisionDeny
	}
	if urOptionBool(options, "--revoke") {
		return errors.New("a request takes approve or deny")
	}
	uses := uint32(0)
	if usesText, _ := options.String("--uses"); usesText != "" {
		parsed, err := strconv.ParseUint(usesText, 10, 32)
		if err != nil || parsed == 0 {
			return fmt.Errorf("%q is not a count of uses", usesText)
		}
		uses = uint32(parsed)
	}
	if !slices.Contains(item.Decisions, decision) {
		if len(item.Decisions) == 0 {
			return errors.New("this request is not this device's to decide")
		}
		return fmt.Errorf("this device may answer the request only with %s", strings.Join(item.Decisions, " or "))
	}

	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	for _, line := range strings.Split(item.Text, "\n") {
		fmt.Fprintln(tty, sidecar.ApprovalPrintable(line))
	}
	if item.Channel == "presence" {
		fmt.Fprintln(tty, "This is this sidecar's own request: your presence key signs it, never this device alone.")
	}
	if 1 < uses {
		fmt.Fprintf(tty, "The approval covers up to %d actions, each matching the template.\n", uses)
	}
	tty.Close()
	confirmed, err := confirmOnTty(cli, decision+" it?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	params := &urRequestDecideParams{ApprovalId: approvalId, Decision: decision, Uses: uses}
	if err := cli.callDaemon(ctx, urMethodApprovalsRequest, params, true, nil); err != nil {
		return err
	}
	cli.printf("%s: %s\n", approvalId, decision)
	return nil
}

// ur approve cancel <id>: after the person's yes on /dev/tty, the approval's cancel. A use already reserved still
// completes.
func runUrApproveCancel(ctx context.Context, cli *urCli, options docopt.Opts) error {
	approvalIdText, _ := options.String("<approval_id>")
	approvalId, err := sidecar.ParseId(approvalIdText)
	if err != nil {
		return fmt.Errorf("%q is not an approval id", approvalIdText)
	}
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	fmt.Fprintf(tty, "Cancel approval %s? A use already reserved still completes, and no new use is taken.\n", approvalId)
	tty.Close()
	confirmed, err := confirmOnTty(cli, "cancel it?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	if err := cli.callDaemon(ctx, urMethodApprovalsCancel, &urApprovalCancelParams{ApprovalId: approvalId}, true, nil); err != nil {
		return err
	}
	cli.printf("%s: cancelled\n", approvalId)
	return nil
}
