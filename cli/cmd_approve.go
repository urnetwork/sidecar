// ur approve (§16.16, D-CORE-13, CORE-M2-04): lists what waits for this device's decision, or decides one after the
// person confirms on /dev/tty, never through MCP. An admission or an admission alarm prints its safety number first,
// for the person to compare with the one the other device shows (§5.6's genesis row). The daemon serves three control
// methods: approvals.list, approvals.revoke_plan, and approvals.decide, a Confirm method, so it runs only from a
// confirmed control call. §16's request kind (MCP-M3-07, cmd_approve_request.go) rides the same command, dispatched
// by kind: an id that is no authority item is a request's, and ur approve cancel <id> cancels an approval.
//
// CORE-M3-04 (D-CORE-20; FS-98, FS-124's CLI cases) adds:
//
//	ur approve <proposal_id>   a revocation proposal's 64 hex digits, as `ur devices revoke` printed them on the
//	                           proposing device: prints the proposal's plan on the terminal, and after the person's yes
//	                           signs this device's AuthorityCosign (the root's devices.proposal and devices.cosign).
//	                           A proposal is approved or left to expire, so --deny and --revoke take none
//	--revoke                   an alarm's revoke answer prints the plan it signs first (PreviewApprovalRevoke): a
//	                           compromise revocation of the alarm's device from the alarm's entry
//
// CORE-M6-04 (§7.10's cleanup row) adds the cleanup kind's revoke: the list it signs printed first, each page Worker
// with its admission time from the rows and its leaf's last change where this device shows one (the root's
// PreviewCleanup, behind approvals.cleanup_list), the daemon keeping that list as the one the revoke may sign.
//
// Every decision here runs under the daemon's presence prompt where the log covers what it signs (§5.6's presence
// countersignature): a host with no authenticator, or a refused check, signs nothing.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur approve calls.
const (
	urMethodApprovalsList          = "approvals.list"
	urMethodApprovalsDecide        = "approvals.decide"
	urMethodApprovalsRevokePlan    = "approvals.revoke_plan"
	urMethodApprovalsCleanupList   = "approvals.cleanup_list"
	urMethodApprovalsCleanupRevoke = "approvals.cleanup_revoke"
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
	// The plan an item's revoke answer signs.
	approvalRevokePlan(approvalId sidecar.Id) (*sidecar.DeviceRevokePlan, error)
}

func (self *urDaemonNetwork) pendingApprovals() ([]*sidecar.SidecarApprovalItem, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.PendingApprovals()
}

// A confirmed control call, the person having answered on /dev/tty. Where the log covers what the decision signs, an
// admission, an OwnerConfirm, a veto or a revocation, the act runs the daemon's presence prompt (presenceCheck): with
// no authenticator on this host it signs nothing.
func (self *urDaemonNetwork) decideApproval(ctx context.Context, approvalId sidecar.Id, decision string) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	return running.DecideApproval(ctx, approvalId, decision, sidecar.SidecarActConfirmed, self.presenceCheck(running))
}

func (self *urDaemonNetwork) approvalRevokePlan(approvalId sidecar.Id) (*sidecar.DeviceRevokePlan, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.PreviewApprovalRevoke(approvalId)
}

// What a target answers of §7.10's cleanup, beside the approvals: the list a cleanup item's revoke signs, which the
// Sidecar keeps as the one shown. Optional: a target without it serves no approvals.cleanup_list.
type urCleanupTarget interface {
	approvalCleanupList(ctx context.Context, approvalId sidecar.Id) (*sidecar.SidecarCleanupList, error)
	// A confirmed control call: the revoke of the list shown, with what it signed.
	approvalCleanupRevoke(ctx context.Context, approvalId sidecar.Id) (*sidecar.SidecarCleanupRevocation, error)
}

func (self *urDaemonNetwork) approvalCleanupList(ctx context.Context, approvalId sidecar.Id) (*sidecar.SidecarCleanupList, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.PreviewCleanup(ctx, approvalId)
}

// A confirmed control call, the person having answered on /dev/tty: the revoke runs the daemon's presence prompt where
// the log covers it, as decideApproval does.
func (self *urDaemonNetwork) approvalCleanupRevoke(ctx context.Context, approvalId sidecar.Id) (*sidecar.SidecarCleanupRevocation, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.RevokeCleanup(ctx, approvalId, sidecar.SidecarActConfirmed, self.presenceCheck(running))
}

// approvals.cleanup_revoke's reply: the Workers whose revocation the act signed, and the proposal_id, in hex, of each
// that awaits other AdminSet devices' cosigns.
type urCleanupRevokeReply struct {
	Revoked   []sidecar.Id `json:"revoked"`
	Proposals []string     `json:"proposals,omitempty"`
	Pending   bool         `json:"pending,omitempty"`
}

// One page Worker as approvals.cleanup_list answers it: ids, positions and times, never a secret.
type urCleanupWorker struct {
	SidecarId  sidecar.Id `json:"sidecar_id"`
	AdmittedAt uint64     `json:"admitted_at"`
	// ms since the epoch; 0 for none
	AdmittedTimeMs int64 `json:"admitted_time_ms,omitempty"`
	LastChangeMs   int64 `json:"last_change_ms,omitempty"`
	Signatures     int   `json:"signatures"`
}

// One member's part.
type urCleanupMember struct {
	MemberId sidecar.Id         `json:"member_id"`
	Workers  []*urCleanupWorker `json:"workers"`
}

// approvals.cleanup_list's reply.
type urCleanupListReply struct {
	AdmissionCount int                `json:"admission_count"`
	AdmissionCap   int                `json:"admission_cap"`
	Members        []*urCleanupMember `json:"members"`
	Presence       bool               `json:"presence,omitempty"`
}

// A list as the reply carries it.
func newUrCleanupListReply(list *sidecar.SidecarCleanupList) *urCleanupListReply {
	reply := &urCleanupListReply{AdmissionCount: list.AdmissionCount, AdmissionCap: list.AdmissionCap, Members: []*urCleanupMember{}, Presence: list.Presence}
	milliseconds := func(at time.Time) int64 {
		if at.IsZero() {
			return 0
		}
		return at.UnixMilli()
	}
	for _, member := range list.Members {
		listed := &urCleanupMember{MemberId: member.MemberId, Workers: []*urCleanupWorker{}}
		for _, worker := range member.Workers {
			listed.Workers = append(listed.Workers, &urCleanupWorker{
				SidecarId:      worker.SidecarId,
				AdmittedAt:     worker.AdmittedAt,
				AdmittedTimeMs: milliseconds(worker.AdmittedTime),
				LastChangeMs:   milliseconds(worker.LastChange),
				Signatures:     worker.Signatures,
			})
		}
		reply.Members = append(reply.Members, listed)
	}
	return reply
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

// approvals.revoke_plan's params.
type urApprovalRevokePlanParams struct {
	ApprovalId sidecar.Id `json:"approval_id"`
}

// approvals.revoke_plan's reply: the plan, or §5.6's refusal.
type urApprovalRevokePlanReply struct {
	Plan    *sidecar.DaemonDeviceRevokePlan `json:"plan,omitempty"`
	Refusal *sidecar.DaemonDeviceRefusal    `json:"refusal,omitempty"`
}

// The approve methods over target, when it runs a Sidecar.
func urApproveMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	approvals, ok := target.(urApprovalsTarget)
	if !ok {
		return nil
	}
	methods := []*sidecar.DaemonMethod{
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
			Name: urMethodApprovalsRevokePlan,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urApprovalRevokePlanParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, errors.New("a revoke plan takes an approval id")
				}
				plan, err := approvals.approvalRevokePlan(params.ApprovalId)
				var revokeError *sidecar.DeviceRevokeError
				if errors.As(err, &revokeError) {
					return &urApprovalRevokePlanReply{Refusal: &sidecar.DaemonDeviceRefusal{Code: revokeError.Code, Position: revokeError.Position}}, nil
				}
				if err != nil {
					return nil, err
				}
				return &urApprovalRevokePlanReply{Plan: sidecar.NewDaemonDeviceRevokePlan(plan)}, nil
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
	if cleanups, ok := target.(urCleanupTarget); ok {
		methods = append(methods, &sidecar.DaemonMethod{
			Name: urMethodApprovalsCleanupList,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urApprovalRevokePlanParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, errors.New("a cleanup list takes an approval id")
				}
				list, err := cleanups.approvalCleanupList(ctx, params.ApprovalId)
				if err != nil {
					return nil, err
				}
				return newUrCleanupListReply(list), nil
			},
		}, &sidecar.DaemonMethod{
			Name:    urMethodApprovalsCleanupRevoke,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urApprovalRevokePlanParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, errors.New("a cleanup revoke takes an approval id")
				}
				revocation, err := cleanups.approvalCleanupRevoke(ctx, params.ApprovalId)
				if revocation == nil {
					return nil, err
				}
				reply := &urCleanupRevokeReply{Revoked: revocation.Revoked, Pending: revocation.Pending}
				for _, workerId := range revocation.Revoked {
					if proposalId, ok := revocation.Proposals[workerId]; ok {
						reply.Proposals = append(reply.Proposals, hex.EncodeToString(proposalId))
					}
				}
				return reply, err
			},
		})
	}
	return methods
}

// Lists the items, or decides the one named.
func runUrApprove(ctx context.Context, cli *urCli, options docopt.Opts) error {
	if urOptionBool(options, "cancel") {
		return runUrApproveCancel(ctx, cli, options)
	}
	approvalIdText, _ := options.String("<approval_id>")
	if proposalId, err := hex.DecodeString(approvalIdText); err == nil && len(proposalId) == sha256.Size {
		// §7.9's proposal_id, never an approval id's form
		return runUrApproveProposal(ctx, cli, approvalIdText, options)
	}
	reply := &urApprovalsReply{}
	if err := cli.callDaemon(ctx, urMethodApprovalsList, nil, false, reply); err != nil {
		return err
	}
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

	// a cleanup's revoke signs the list shown: it is read before the person confirms, and the daemon keeps it
	var cleanupList *urCleanupListReply
	if decision == sidecar.SidecarDecisionRevoke && item.Kind == sidecar.SidecarApprovalCleanup {
		cleanupList = &urCleanupListReply{}
		if err := cli.callDaemon(ctx, urMethodApprovalsCleanupList, &urApprovalRevokePlanParams{ApprovalId: approvalId}, false, cleanupList); err != nil {
			return err
		}
	}
	// a revoke answer signs a compromise revocation: its plan is read before the person confirms
	var revokePlan *sidecar.DaemonDeviceRevokePlan
	if decision == sidecar.SidecarDecisionRevoke && cleanupList == nil {
		planReply := &urApprovalRevokePlanReply{}
		if err := cli.callDaemon(ctx, urMethodApprovalsRevokePlan, &urApprovalRevokePlanParams{ApprovalId: approvalId}, false, planReply); err != nil {
			return err
		}
		if planReply.Refusal != nil {
			return urDeviceRefusalError(planReply.Refusal)
		}
		revokePlan = planReply.Plan
	}

	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	fmt.Fprintf(tty, "%s%s\n", item.Kind, urApprovalSubject(item))
	if cleanupList != nil {
		urPrintCleanupList(tty, cleanupList)
	}
	if revokePlan != nil {
		fmt.Fprintf(tty, "Revoking it signs a compromise revocation of device %s from entry %d:\n", revokePlan.SidecarId, revokePlan.SinceN)
		for _, planItem := range revokePlan.Items {
			fmt.Fprintln(tty, urDeviceRevokeItemLine(planItem))
		}
		urPrintVoidedBindingNote(tty, revokePlan.Items)
		if 1 < revokePlan.Signatures {
			fmt.Fprintf(tty, "  it takes %d admins: this signs the proposal and suspends the device at once\n", revokePlan.Signatures)
		}
	}
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
	if cleanupList != nil {
		reply := &urCleanupRevokeReply{}
		if err := cli.callDaemon(ctx, urMethodApprovalsCleanupRevoke, &urApprovalRevokePlanParams{ApprovalId: approvalId}, true, reply); err != nil {
			return err
		}
		cli.printf("%s: revoked %d page Workers\n", item.ApprovalId, len(reply.Revoked))
		for _, proposalId := range reply.Proposals {
			cli.printf("authority_pending: revoked once another admin's device runs\n  ur approve %s\n", proposalId)
		}
		if reply.Pending {
			cli.printf("signed: the network's answer was lost, so the same statements are sent again until they land\n")
		}
		return nil
	}
	if err := cli.callDaemon(ctx, urMethodApprovalsDecide, &urDecideParams{ApprovalId: approvalId, Decision: decision}, true, nil); err != nil {
		return err
	}
	cli.printf("%s: %s\n", item.ApprovalId, decision)
	return nil
}

// ur approve <proposal_id>: an open revocation proposal's plan on the terminal, the person's yes, then this device's
// cosign under the daemon's presence prompt.
func runUrApproveProposal(ctx context.Context, cli *urCli, proposalIdText string, options docopt.Opts) error {
	if urOptionBool(options, "--deny") || urOptionBool(options, "--revoke") {
		return errors.New("a revocation proposal is approved or left to expire: it takes no --deny or --revoke")
	}
	proposalIdText = strings.ToLower(proposalIdText)
	params := &sidecar.DaemonDevicesProposalParams{ProposalId: proposalIdText}
	shown := &sidecar.DaemonDevicesProposalReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodDevicesProposal, params, false, shown); err != nil {
		return err
	}
	if shown.Unknown || shown.Proposal == nil {
		return errors.New("no open revocation proposal has that id: it was approved, it expired, or this device has not read it yet")
	}
	proposal := shown.Proposal
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	fmt.Fprintf(tty, "A proposal to revoke device %s %s of member %s as %s", urDeviceName(proposal.Name), proposal.SidecarId, proposal.MemberId, proposal.Reason)
	if proposal.SinceN != 0 {
		fmt.Fprintf(tty, ", from entry %d", proposal.SinceN)
		if proposal.SinceTimeMs != 0 {
			fmt.Fprintf(tty, " (%s)", time.UnixMilli(proposal.SinceTimeMs).UTC().Format(time.RFC3339))
		}
	}
	fmt.Fprintln(tty)
	for _, item := range proposal.Items {
		fmt.Fprintln(tty, urDeviceRevokeItemLine(item))
	}
	urPrintVoidedBindingNote(tty, proposal.Items)
	fmt.Fprintf(tty, "  proposed at entry %d, signed so far by %s\n", proposal.ProposedAt, strings.Join(proposal.Signers, ", "))
	if proposal.Suspended {
		fmt.Fprintln(tty, "  the device is suspended while the proposal waits")
	}
	fmt.Fprintf(tty, "  it expires unsigned at %s, the device staying suspended\n", time.UnixMilli(proposal.NotAfterMs).UTC().Format(time.RFC3339))
	if proposal.Presence {
		fmt.Fprintln(tty, "  the authenticator then asks for biometry, a passcode or a touch")
	}
	tty.Close()
	confirmed, err := confirmOnTty(cli, "Approve the revocation?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	reply := &sidecar.DaemonDevicesCosignReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodDevicesCosign, params, true, reply); err != nil {
		return err
	}
	switch {
	case reply.Refusal != nil:
		return urDeviceRefusalError(reply.Refusal)
	case reply.Unknown:
		return errors.New("the proposal closed or expired before this device signed")
	case reply.Pending:
		cli.printf("signed: the network's answer was lost, so the same statement is sent again until it lands\n")
	default:
		cli.printf("proposal %s: approved at entry %d\n", proposalIdText, reply.Position)
	}
	return nil
}

// A cleanup list on the terminal, as the revoke signs it: per member, each page Worker but its newest, oldest first,
// with its admission time from the rows and its leaf's last change where this device shows one.
func urPrintCleanupList(tty urTty, list *urCleanupListReply) {
	fmt.Fprintf(tty, "%d of the network's %d admissions stand. Revoking signs SidecarRevoke{removed} of each page Worker listed:\n", list.AdmissionCount, list.AdmissionCap)
	if len(list.Members) == 0 {
		fmt.Fprintln(tty, "  none: the count is below 90% of the cap")
	}
	for _, member := range list.Members {
		fmt.Fprintf(tty, "  member %s\n", member.MemberId)
		for _, worker := range member.Workers {
			admitted := fmt.Sprintf("admitted at entry %d", worker.AdmittedAt)
			if worker.AdmittedTimeMs != 0 {
				admitted += " (" + time.UnixMilli(worker.AdmittedTimeMs).UTC().Format(time.RFC3339) + ")"
			}
			lastChange := ""
			if worker.LastChangeMs != 0 {
				lastChange = ", its leaf last changed " + time.UnixMilli(worker.LastChangeMs).UTC().Format(time.RFC3339)
			}
			proposal := ""
			if 1 < worker.Signatures {
				proposal = fmt.Sprintf(", a proposal %d admins sign", worker.Signatures)
			}
			fmt.Fprintf(tty, "    page Worker %s, %s%s%s\n", worker.SidecarId, admitted, lastChange, proposal)
		}
	}
	fmt.Fprintln(tty, "  a Worker still in use signs out and is enrolled again")
	if list.Presence {
		fmt.Fprintln(tty, "  the authenticator then asks for biometry, a passcode or a touch")
	}
}

// The device an item is about, for a line ur prints.
func urApprovalSubject(item *urApprovalItem) string {
	if item.SidecarId == nil {
		return ""
	}
	return " of sidecar " + item.SidecarId.String()
}
