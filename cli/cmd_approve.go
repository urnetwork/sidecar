// ur approve (§16.16, D-CORE-13, CORE-M2-04): lists what waits for this device's decision, or decides one after the
// person confirms on /dev/tty, never through MCP. An admission or an admission alarm prints its safety number first,
// for the person to compare with the one the other device shows (§5.6's genesis row). The daemon serves two control
// methods: approvals.list, and approvals.decide, a Confirm method, so it runs only from a confirmed control call.
// §16's request kind (MCP-M3-07, cmd_approve_request.go) rides the same command, dispatched by kind: an id that is no
// authority item is a request's, and ur approve cancel <id> cancels an approval.

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur approve calls.
const (
	urMethodApprovalsList   = "approvals.list"
	urMethodApprovalsDecide = "approvals.decide"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "approve",
		usage:   "  ur approve [<approval_id>] [--deny | --revoke] [--uses=<n>]\n  ur approve cancel <approval_id>",
		summary: "list what waits for this device's decision, or decide one on the terminal",
		run:     runUrApprove,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urApproveMethods)
}

// What the approve methods act on: a daemon target that runs a Sidecar.
type urApprovalsTarget interface {
	pendingApprovals() ([]*sidecar.SidecarApprovalItem, error)
	decideApproval(ctx context.Context, approvalId sidecar.Id, decision string) error
}

func (self *urDaemonNetwork) pendingApprovals() ([]*sidecar.SidecarApprovalItem, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.PendingApprovals()
}

// A confirmed control call, the person having answered on /dev/tty. The daemon's presence prompt is §16's, so a
// statement the log covers is refused until it lands, never signed without the check.
func (self *urDaemonNetwork) decideApproval(ctx context.Context, approvalId sidecar.Id, decision string) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	return running.DecideApproval(ctx, approvalId, decision, sidecar.SidecarActConfirmed, nil)
}

// One item as approvals.list answers it: ids and kinds, never a secret.
type urApprovalItem struct {
	ApprovalId   sidecar.Id  `json:"approval_id"`
	Kind         string      `json:"kind"`
	SidecarId    *sidecar.Id `json:"sidecar_id,omitempty"`
	MemberId     *sidecar.Id `json:"member_id,omitempty"`
	Position     uint64      `json:"position,omitempty"`
	SafetyNumber string      `json:"safety_number,omitempty"`
	Decisions    []string    `json:"decisions"`
}

// approvals.list's reply.
type urApprovalsReply struct {
	Items []*urApprovalItem `json:"items"`
}

// approvals.decide's params.
type urDecideParams struct {
	ApprovalId sidecar.Id `json:"approval_id"`
	Decision   string     `json:"decision"`
}

// The approve methods over target, when it runs a Sidecar.
func urApproveMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	approvals, ok := target.(urApprovalsTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodApprovalsList,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				items, err := approvals.pendingApprovals()
				if err != nil {
					return nil, err
				}
				reply := &urApprovalsReply{Items: []*urApprovalItem{}}
				for _, item := range items {
					reply.Items = append(reply.Items, &urApprovalItem{
						ApprovalId:   item.ApprovalId,
						Kind:         item.Kind,
						SidecarId:    item.SidecarId,
						MemberId:     item.MemberId,
						Position:     item.Position,
						SafetyNumber: item.SafetyNumber,
						Decisions:    item.Decisions,
					})
				}
				return reply, nil
			},
		},
		{
			Name:    urMethodApprovalsDecide,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urDecideParams{}
				if err := decodeUrParams(call, params); err != nil || params.Decision == "" {
					return nil, errors.New("a decision takes an approval id and a decision")
				}
				return nil, approvals.decideApproval(ctx, params.ApprovalId, params.Decision)
			},
		},
	}
}

// Lists the items, or decides the one named.
func runUrApprove(ctx context.Context, cli *urCli, options docopt.Opts) error {
	if urOptionBool(options, "cancel") {
		return runUrApproveCancel(ctx, cli, options)
	}
	reply := &urApprovalsReply{}
	if err := cli.callDaemon(ctx, urMethodApprovalsList, nil, false, reply); err != nil {
		return err
	}
	approvalIdText, _ := options.String("<approval_id>")
	if approvalIdText == "" {
		requests, requestsErr := urPendingRequests(ctx, cli)
		if len(reply.Items) == 0 && len(requests) == 0 {
			cli.printf("nothing waits for this device's decision\n")
		}
		for _, item := range reply.Items {
			cli.printf("%s  %s%s  %s\n", item.ApprovalId, item.Kind, urApprovalSubject(item), strings.Join(item.Decisions, "|"))
		}
		urPrintRequests(cli, requests)
		if requestsErr != nil {
			fmt.Fprintf(cli.stderr, "ur approve: the requests did not list: %s\n", requestsErr)
		}
		return nil
	}
	approvalId, err := sidecar.ParseId(approvalIdText)
	if err != nil {
		return fmt.Errorf("%q is not an approval id", approvalIdText)
	}
	index := slices.IndexFunc(reply.Items, func(item *urApprovalItem) bool { return item.ApprovalId == approvalId })
	if index < 0 {
		// no authority item: a request's, dispatched by kind
		return runUrApproveRequest(ctx, cli, approvalId, options)
	}
	item := reply.Items[index]
	decision := sidecar.SidecarDecisionApprove
	if deny, _ := options.Bool("--deny"); deny {
		decision = sidecar.SidecarDecisionDeny
	}
	if revoke, _ := options.Bool("--revoke"); revoke {
		decision = sidecar.SidecarDecisionRevoke
	}
	if !slices.Contains(item.Decisions, decision) {
		return fmt.Errorf("this device may answer %s only with %s", item.Kind, strings.Join(item.Decisions, " or "))
	}

	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	fmt.Fprintf(tty, "%s%s\n", item.Kind, urApprovalSubject(item))
	if item.SafetyNumber != "" && decision == sidecar.SidecarDecisionApprove {
		fmt.Fprintf(tty, "Compare this safety number with the one the device shows. Approve only if every digit matches:\n%s\n", sidecar.FormatSafetyNumber(item.SafetyNumber))
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
	if err := cli.callDaemon(ctx, urMethodApprovalsDecide, &urDecideParams{ApprovalId: approvalId, Decision: decision}, true, nil); err != nil {
		return err
	}
	cli.printf("%s: %s\n", item.ApprovalId, decision)
	return nil
}

// The device an item is about, for a line ur prints.
func urApprovalSubject(item *urApprovalItem) string {
	if item.SidecarId == nil {
		return ""
	}
	return " of sidecar " + item.SidecarId.String()
}
