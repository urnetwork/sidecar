//go:build !js && !ios && !android && !sdk_mobile_bind

// The daemon's control methods for §5.6's revocation of a member's own devices (CORE-M3-04; D-CORE-20, D-CORE-13,
// I-4, FS-98, FS-124): what `ur devices`, `ur devices revoke` and `ur approve <proposal_id>` send, and what a
// remote-mode app's control calls reach (CORE-M8-03).
//
//	devices.list      Devices(): this member's admitted sidecars, this one first
//	devices.preview   PreviewDeviceRevoke: the plan a person reads, of a device named by its sidecar_id or its config
//	                  device name; signs nothing
//	devices.revoke    RevokeDevice of a previewed plan: a Confirm method, so it runs only from a control call whose
//	                  sender confirmed on /dev/tty or in an app's UI, never from mcp or hook mode (D-CORE-13). Under
//	                  Presence it runs the daemon's presence prompt (daemon_presence.go) over the act's countersigned
//	                  bytes; a host with no authenticator, or one holding no live key of this sidecar's, signs nothing
//	                  (REVOKE_CANCELLED). At k > 1 it answers the proposal's id, the target suspended in the same act
//	devices.proposal  PreviewRevokeProposal: an open revocation proposal's plan, for a cosigner to read
//	devices.cosign    CosignRevokeProposal: a Confirm method, under the same approval and prompt
//
// §5.6's refusals are answers, not rpc errors: a reply carries {code, position} in refusal and nothing else, so a
// caller shows REVOKE_PARKS_SELF's entry and never parses a message. Everything else, a locked or unenrolled sidecar
// among them, is the rpc's error. A reply holds ids, names, positions and times, and never a key, a token or a
// statement's bytes (I-7).

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// The methods.
const (
	// ur devices.
	DaemonMethodDevicesList = "devices.list"
	// ur devices revoke, before the person confirms.
	DaemonMethodDevicesPreview = "devices.preview"
	// ur devices revoke, confirmed.
	DaemonMethodDevicesRevoke = "devices.revoke"
	// ur approve <proposal_id>, before the person confirms.
	DaemonMethodDevicesProposal = "devices.proposal"
	// ur approve <proposal_id>, confirmed.
	DaemonMethodDevicesCosign = "devices.cosign"
)

// One of §5.6's refusals as a reply carries it.
type DaemonDeviceRefusal struct {
	// A REVOKE_ code.
	Code string `json:"code"`
	// REVOKE_PARKS_SELF: the entry that puts this sidecar in P.
	Position uint64 `json:"position,omitempty"`
}

// One device as devices.list answers it.
type DaemonDevice struct {
	SidecarId Id     `json:"sidecar_id"`
	Name      string `json:"name,omitempty"`
	This      bool   `json:"this,omitempty"`
	ReadOnly  bool   `json:"read_only,omitempty"`
	Ephemeral bool   `json:"ephemeral,omitempty"`
	State     string `json:"state"`
	// In milliseconds since the epoch; 0 for none seen.
	AdmittedAtMs int64 `json:"admitted_at_ms,omitempty"`
	LastChangeMs int64 `json:"last_change_ms,omitempty"`
}

// devices.list's params.
type DaemonDevicesListParams struct {
	Network string `json:"network,omitempty"`
}

// devices.list's reply.
type DaemonDevicesListReply struct {
	Devices []*DaemonDevice `json:"devices"`
}

// One row of a plan.
type DaemonDeviceRevokeItem struct {
	Effect string `json:"effect"`
	Kind   string `json:"kind"`
	// In hex.
	Id       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Position uint64 `json:"position,omitempty"`
}

// devices.preview's params.
type DaemonDevicesPreviewParams struct {
	Network string `json:"network,omitempty"`
	// The target: a sidecar_id, or a config device name one of the member's devices carries.
	Device string `json:"device"`
	// "lost" or "compromise".
	Reason string `json:"reason"`
	// compromise: the loss time the person gave, in milliseconds since the epoch; 0 for none.
	LostAtMs int64 `json:"lost_at_ms,omitempty"`
	// compromise: a position the person moved since_n to; 0 for the proposed one.
	SinceN uint64 `json:"since_n,omitempty"`
}

// A plan as devices.preview answers it.
type DaemonDeviceRevokePlan struct {
	PlanId    Id     `json:"plan_id"`
	SidecarId Id     `json:"sidecar_id"`
	Name      string `json:"name,omitempty"`
	Reason    string `json:"reason"`
	SinceN    uint64 `json:"since_n,omitempty"`
	// In milliseconds since the epoch; 0 for none.
	SinceTimeMs int64                     `json:"since_time_ms,omitempty"`
	Items       []*DaemonDeviceRevokeItem `json:"items"`
	Signatures  int                       `json:"signatures"`
	Presence    bool                      `json:"presence,omitempty"`
}

// devices.preview's reply: the plan, or §5.6's refusal.
type DaemonDevicesPreviewReply struct {
	Plan    *DaemonDeviceRevokePlan `json:"plan,omitempty"`
	Refusal *DaemonDeviceRefusal    `json:"refusal,omitempty"`
}

// devices.revoke's params.
type DaemonDevicesRevokeParams struct {
	Network string `json:"network,omitempty"`
	PlanId  Id     `json:"plan_id"`
	// The plan's key items the person left selected, each in hex.
	RevokeKeyIds []string `json:"revoke_key_ids,omitempty"`
}

// devices.revoke's reply.
type DaemonDevicesRevokeReply struct {
	// The SidecarRevoke's entry; 0 while a proposal pends or a post's answer is lost.
	Position uint64 `json:"position,omitempty"`
	// §7.9's proposal_id in hex while k > 1 pends: authority_pending, the target suspended at once.
	ProposalId string `json:"proposal_id,omitempty"`
	// The park and void items that entered after the preview and joined unasked.
	Joined []*DaemonDeviceRevokeItem `json:"joined,omitempty"`
	// The keys whose KeyRevoke the act signed, each in hex.
	RevokedKeyIds []string `json:"revoked_key_ids,omitempty"`
	// The statements are signed and kept, and a post's answer was lost: they go again with the same bytes.
	Pending bool                 `json:"pending,omitempty"`
	Refusal *DaemonDeviceRefusal `json:"refusal,omitempty"`
}

// devices.proposal's and devices.cosign's params.
type DaemonDevicesProposalParams struct {
	Network string `json:"network,omitempty"`
	// §7.9's proposal_id in hex.
	ProposalId string `json:"proposal_id"`
}

// An open revocation proposal as devices.proposal answers it.
type DaemonDeviceRevokeProposal struct {
	ProposalId string `json:"proposal_id"`
	SidecarId  Id     `json:"sidecar_id"`
	Name       string `json:"name,omitempty"`
	MemberId   Id     `json:"member_id"`
	Reason     string `json:"reason"`
	SinceN     uint64 `json:"since_n,omitempty"`
	// In milliseconds since the epoch; 0 for none.
	SinceTimeMs int64                     `json:"since_time_ms,omitempty"`
	Items       []*DaemonDeviceRevokeItem `json:"items"`
	ProposedAt  uint64                    `json:"proposed_at"`
	NotAfterMs  int64                     `json:"not_after_ms"`
	// Each in hex.
	Signers   []string `json:"signers"`
	Suspended bool     `json:"suspended,omitempty"`
	Presence  bool     `json:"presence,omitempty"`
}

// devices.proposal's reply. Unknown is an id no open revocation proposal has.
type DaemonDevicesProposalReply struct {
	Proposal *DaemonDeviceRevokeProposal `json:"proposal,omitempty"`
	Unknown  bool                        `json:"unknown,omitempty"`
}

// devices.cosign's reply.
type DaemonDevicesCosignReply struct {
	// The cosign's entry; 0 while its post's answer is lost.
	Position uint64               `json:"position,omitempty"`
	Pending  bool                 `json:"pending,omitempty"`
	Unknown  bool                 `json:"unknown,omitempty"`
	Refusal  *DaemonDeviceRefusal `json:"refusal,omitempty"`
}

// A param that names no device, plan, key or proposal. The text names nothing it held.
var errDaemonDevicesParams = errors.New("the params name no device, plan, key or proposal")

// A call's params into params, refusing a field it does not know; none is an empty object.
func decodeDaemonDevicesParams(call *DaemonCall, params any) error {
	if len(call.Params) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(call.Params))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(params); err != nil {
		return errDaemonDevicesParams
	}
	return nil
}

// A time as a reply carries it, 0 for none.
func daemonDevicesMs(at time.Time) int64 {
	if at.IsZero() {
		return 0
	}
	return at.UnixMilli()
}

// Plan rows as a reply carries them.
func daemonDeviceRevokeItems(items []DeviceRevokeItem) []*DaemonDeviceRevokeItem {
	replyItems := make([]*DaemonDeviceRevokeItem, 0, len(items))
	for _, item := range items {
		replyItems = append(replyItems, &DaemonDeviceRevokeItem{
			Effect:   item.Effect,
			Kind:     item.Kind,
			Id:       hex.EncodeToString(item.Id),
			Name:     item.Name,
			Position: item.Position,
		})
	}
	return replyItems
}

// A plan as a reply carries it: what devices.preview answers, and what `ur approve <id> --revoke` shows of an alarm's
// revoke answer (PreviewApprovalRevoke).
func NewDaemonDeviceRevokePlan(plan *DeviceRevokePlan) *DaemonDeviceRevokePlan {
	return &DaemonDeviceRevokePlan{
		PlanId:      plan.PlanId,
		SidecarId:   plan.SidecarId,
		Name:        plan.Name,
		Reason:      plan.Reason,
		SinceN:      plan.SinceN,
		SinceTimeMs: daemonDevicesMs(plan.SinceTime),
		Items:       daemonDeviceRevokeItems(plan.Items),
		Signatures:  plan.Signatures,
		Presence:    plan.Presence,
	}
}

// §5.6's refusal in err, nil for any other error.
func daemonDeviceRefusal(err error) *DaemonDeviceRefusal {
	var revokeError *DeviceRevokeError
	if errors.As(err, &revokeError) {
		return &DaemonDeviceRefusal{Code: revokeError.Code, Position: revokeError.Position}
	}
	return nil
}

// The device a call names: a sidecar_id as it is, whoever's it is, since the plan's derivation answers REVOKE_NOT_OWN
// for one that is no device of the member's; else the one device of the member's whose config device name it is. A
// name none or several carry is REVOKE_NOT_OWN.
func daemonDevicesTarget(running *Sidecar, device string) (Id, error) {
	if device == "" {
		return Id{}, errDaemonDevicesParams
	}
	if sidecarId, err := ParseId(device); err == nil {
		return sidecarId, nil
	}
	devices, err := running.Devices()
	if err != nil {
		return Id{}, err
	}
	var named []Id
	for _, each := range devices {
		if each.Name == device {
			named = append(named, each.SidecarId)
		}
	}
	if len(named) != 1 {
		return Id{}, &DeviceRevokeError{Code: DeviceRevokeCodeNotOwn}
	}
	return named[0], nil
}

// §7.9's proposal_id a call names in hex.
func daemonDevicesProposalId(call *DaemonCall) ([]byte, error) {
	params := &DaemonDevicesProposalParams{}
	if err := decodeDaemonDevicesParams(call, params); err != nil {
		return nil, err
	}
	proposalId, err := hex.DecodeString(params.ProposalId)
	if err != nil || len(proposalId) == 0 {
		return nil, errDaemonDevicesParams
	}
	return proposalId, nil
}

// The daemon's devices methods over daemon, whose presence prompt the signing ones run; the daemon's composition
// registers them with RegisterMethod.
func DaemonDevicesMethods(daemon *Daemon) []*DaemonMethod {
	return []*DaemonMethod{
		{
			Name:    DaemonMethodDevicesList,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonDevicesListParams{}
				if err := decodeDaemonDevicesParams(call, params); err != nil {
					return nil, err
				}
				devices, err := call.Sidecar.Devices()
				if err != nil {
					return nil, err
				}
				reply := &DaemonDevicesListReply{Devices: []*DaemonDevice{}}
				for _, device := range devices {
					reply.Devices = append(reply.Devices, &DaemonDevice{
						SidecarId:    device.SidecarId,
						Name:         device.Name,
						This:         device.This,
						ReadOnly:     device.ReadOnly,
						Ephemeral:    device.Ephemeral,
						State:        device.State,
						AdmittedAtMs: daemonDevicesMs(device.AdmittedAt),
						LastChangeMs: daemonDevicesMs(device.LastChange),
					})
				}
				return reply, nil
			},
		},
		{
			Name:    DaemonMethodDevicesPreview,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonDevicesPreviewParams{}
				if err := decodeDaemonDevicesParams(call, params); err != nil {
					return nil, err
				}
				sidecarId, err := daemonDevicesTarget(call.Sidecar, params.Device)
				if refusal := daemonDeviceRefusal(err); refusal != nil {
					return &DaemonDevicesPreviewReply{Refusal: refusal}, nil
				}
				if err != nil {
					return nil, err
				}
				lostAt := time.Time{}
				if params.LostAtMs != 0 {
					lostAt = time.UnixMilli(params.LostAtMs)
				}
				plan, err := call.Sidecar.PreviewDeviceRevoke(ctx, sidecarId, params.Reason, lostAt, params.SinceN)
				if refusal := daemonDeviceRefusal(err); refusal != nil {
					return &DaemonDevicesPreviewReply{Refusal: refusal}, nil
				}
				if err != nil {
					return nil, err
				}
				return &DaemonDevicesPreviewReply{Plan: NewDaemonDeviceRevokePlan(plan)}, nil
			},
		},
		{
			Name:    DaemonMethodDevicesRevoke,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonDevicesRevokeParams{}
				if err := decodeDaemonDevicesParams(call, params); err != nil {
					return nil, err
				}
				if params.PlanId == (Id{}) {
					return nil, errDaemonDevicesParams
				}
				revokeKeyIds := make([][]byte, 0, len(params.RevokeKeyIds))
				for _, keyIdText := range params.RevokeKeyIds {
					keyId, err := hex.DecodeString(keyIdText)
					if err != nil || len(keyId) == 0 {
						return nil, errDaemonDevicesParams
					}
					revokeKeyIds = append(revokeKeyIds, keyId)
				}
				// Confirm let only a confirmed control call here; the origin says so to the act, which checks it again
				revocation, err := call.Sidecar.RevokeDevicePlan(ctx, params.PlanId, revokeKeyIds, SidecarActConfirmed, daemon.PresencePrompt(call.Sidecar))
				reply := &DaemonDevicesRevokeReply{}
				if revocation != nil {
					reply.Position = revocation.Entry.GetVersion()
					reply.ProposalId = hex.EncodeToString(revocation.ProposalId)
					reply.Joined = daemonDeviceRevokeItems(revocation.Joined)
					for _, keyId := range revocation.RevokedKeyIds {
						reply.RevokedKeyIds = append(reply.RevokedKeyIds, hex.EncodeToString(keyId))
					}
					reply.Pending = revocation.Pending
				}
				switch refusal := daemonDeviceRefusal(err); {
				case refusal != nil:
					reply.Refusal = refusal
				case errors.Is(err, ErrSidecarActPending):
					reply.Pending = true
				case err != nil:
					return nil, err
				}
				return reply, nil
			},
		},
		{
			Name:    DaemonMethodDevicesProposal,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				proposalId, err := daemonDevicesProposalId(call)
				if err != nil {
					return nil, err
				}
				proposal, err := call.Sidecar.PreviewRevokeProposal(proposalId)
				if errors.Is(err, ErrSidecarRevokeProposalUnknown) {
					return &DaemonDevicesProposalReply{Unknown: true}, nil
				}
				if err != nil {
					return nil, err
				}
				signers := make([]string, 0, len(proposal.Signers))
				for _, signer := range proposal.Signers {
					signers = append(signers, hex.EncodeToString(signer))
				}
				return &DaemonDevicesProposalReply{Proposal: &DaemonDeviceRevokeProposal{
					ProposalId:  hex.EncodeToString(proposal.ProposalId),
					SidecarId:   proposal.SidecarId,
					Name:        proposal.Name,
					MemberId:    proposal.MemberId,
					Reason:      proposal.Reason,
					SinceN:      proposal.SinceN,
					SinceTimeMs: daemonDevicesMs(proposal.SinceTime),
					Items:       daemonDeviceRevokeItems(proposal.Items),
					ProposedAt:  proposal.ProposedAt,
					NotAfterMs:  daemonDevicesMs(proposal.NotAfter),
					Signers:     signers,
					Suspended:   proposal.Suspended,
					Presence:    proposal.Presence,
				}}, nil
			},
		},
		{
			Name:    DaemonMethodDevicesCosign,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				proposalId, err := daemonDevicesProposalId(call)
				if err != nil {
					return nil, err
				}
				entry, err := call.Sidecar.CosignRevokeProposal(ctx, proposalId, SidecarActConfirmed, daemon.PresencePrompt(call.Sidecar))
				reply := &DaemonDevicesCosignReply{Position: entry.GetVersion()}
				switch refusal := daemonDeviceRefusal(err); {
				case refusal != nil:
					reply.Refusal = refusal
				case errors.Is(err, ErrSidecarRevokeProposalUnknown):
					reply.Unknown = true
				case errors.Is(err, ErrSidecarActPending):
					reply.Pending = true
				case err != nil:
					return nil, err
				}
				return reply, nil
			},
		},
	}
}
