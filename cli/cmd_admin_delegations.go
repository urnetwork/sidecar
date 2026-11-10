// ur admin delegations (TEAM-M2-18; D-TEAM-31): each Delegation's keys and admission state, from the verified log,
// and `ur admin delegations revoke <delegation_id> [--leaked --since <since>]`, a DelegationRevoke confirmed on
// /dev/tty, never through MCP. --leaked is for a bundle that leaked: what the Delegation's key admitted from --since on,
// a log position or an RFC 3339 time the log has an entry at or after, parks (§7.9's cascade). Revoking the auth key at
// api stops only that key's bearer, and every copy of a bundle admits until this lands (D-TEAM-22).
//
// A forwarding Delegation (TEAM-M8-01; D-TEAM-33; owner decision 197) is listed by the sidecar it forwards for and
// where a newer one superseded it, never by admissions or agents, since it admits nothing. Its revocation takes no
// --leaked: it admitted nothing to park, and the log refuses one that carries a since_n.

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur admin delegations calls.
const (
	urMethodAdminDelegations      = "admin.delegations.list"
	urMethodAdminDelegationRevoke = "admin.delegations.revoke"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urAdminDelegationMethods)
}

// What the delegations methods act on.
type urAdminDelegationsTarget interface {
	delegationStates() ([]*sidecar.DelegationState, error)
	revokeDelegation(ctx context.Context, delegationId []byte, leaked bool, sinceN uint64, since time.Time) error
}

func (self *urDaemonNetwork) delegationStates() ([]*sidecar.DelegationState, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.DelegationStates()
}

// A confirmed control call, the person having answered on /dev/tty.
func (self *urDaemonNetwork) revokeDelegation(ctx context.Context, delegationId []byte, leaked bool, sinceN uint64, since time.Time) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	_, err = running.SignDelegationRevoke(ctx, delegationId, leaked, sinceN, since, sidecar.SidecarActConfirmed, nil)
	return err
}

// One Delegation as admin.delegations.list answers it: ids, positions and counts.
type urDelegationItem struct {
	DelegationId   string       `json:"delegation_id"`
	TagIds         []sidecar.Id `json:"tag_ids"`
	At             uint64       `json:"at"`
	KeyDroppedAt   uint64       `json:"key_dropped_at,omitempty"`
	EndedAt        uint64       `json:"ended_at,omitempty"`
	NotAfter       int64        `json:"not_after_ms,omitempty"`
	AdmissionsLeft uint32       `json:"admissions_left"`
	AgentIds       []sidecar.Id `json:"agent_ids"`
	// For a forwarding Delegation, the sidecar it forwards for; absent for any other.
	ForwardSidecarId *sidecar.Id `json:"forward_sidecar_id,omitempty"`
	// The position of that sidecar's newer forwarding Delegation, which superseded this one; absent for none.
	SupersededAt uint64 `json:"superseded_at,omitempty"`
}

type urDelegationsReply struct {
	Items []*urDelegationItem `json:"items"`
}

// admin.delegations.revoke's params.
type urDelegationRevokeParams struct {
	DelegationId string `json:"delegation_id"`
	Leaked       bool   `json:"leaked,omitempty"`
	SinceN       uint64 `json:"since_n,omitempty"`
	SinceMs      int64  `json:"since_ms,omitempty"`
}

// The delegations methods over target, when it hosts a Sidecar.
func urAdminDelegationMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	delegations, ok := target.(urAdminDelegationsTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodAdminDelegations,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				states, err := delegations.delegationStates()
				if err != nil {
					return nil, err
				}
				reply := &urDelegationsReply{Items: []*urDelegationItem{}}
				for _, state := range states {
					item := &urDelegationItem{
						DelegationId:   hex.EncodeToString(state.DelegationId),
						TagIds:         state.TagIds,
						At:             state.At,
						KeyDroppedAt:   state.KeyDroppedAt,
						EndedAt:        state.EndedAt,
						AdmissionsLeft: state.AdmissionsLeft,
						AgentIds:       state.AgentIds,
					}
					if !state.NotAfter.IsZero() {
						item.NotAfter = state.NotAfter.UnixMilli()
					}
					if len(state.ForwardSidecarId) != 0 {
						forwardSidecarId, err := sidecar.IdFromBytes(state.ForwardSidecarId)
						if err != nil {
							return nil, fmt.Errorf("Delegation %x names a malformed forwarding sidecar: %w", state.DelegationId, err)
						}
						item.ForwardSidecarId = &forwardSidecarId
						item.SupersededAt = state.SupersededAt
					}
					reply.Items = append(reply.Items, item)
				}
				return reply, nil
			},
		},
		{
			Name:    urMethodAdminDelegationRevoke,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urDelegationRevokeParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				delegationId, err := hex.DecodeString(params.DelegationId)
				if err != nil {
					return nil, errors.New("a delegation_id is hex")
				}
				since := time.Time{}
				if params.SinceMs != 0 {
					since = time.UnixMilli(params.SinceMs)
				}
				return nil, delegations.revokeDelegation(ctx, delegationId, params.Leaked, params.SinceN, since)
			},
		},
	}
}

// One Delegation's line. A forwarding Delegation's names its sidecar in place of admissions and agents.
func urDelegationLine(item *urDelegationItem) string {
	key := "key live"
	if item.KeyDroppedAt != 0 {
		key = fmt.Sprintf("key dropped at %d", item.KeyDroppedAt)
	}
	if item.ForwardSidecarId != nil {
		standing := "live"
		switch {
		case item.EndedAt != 0:
			standing = fmt.Sprintf("ended at %d", item.EndedAt)
		case item.SupersededAt != 0:
			standing = fmt.Sprintf("superseded at %d", item.SupersededAt)
		}
		return fmt.Sprintf("%s  from %d  %s  forwards for sidecar %s  %s", item.DelegationId, item.At, key, item.ForwardSidecarId, standing)
	}
	authority := fmt.Sprintf("admits %d more", item.AdmissionsLeft)
	if item.NotAfter != 0 {
		authority += " until " + time.UnixMilli(item.NotAfter).UTC().Format(time.RFC3339)
	}
	if item.EndedAt != 0 {
		authority = fmt.Sprintf("ended at %d", item.EndedAt)
	}
	return fmt.Sprintf("%s  from %d  %s  %s  %d agent(s)", item.DelegationId, item.At, key, authority, len(item.AgentIds))
}

// ur admin delegations: the list, or a revoke confirmed on the terminal.
func runUrAdminDelegations(ctx context.Context, cli *urCli, options docopt.Opts) error {
	reply := &urDelegationsReply{}
	if err := cli.callDaemon(ctx, urMethodAdminDelegations, nil, false, reply); err != nil {
		return err
	}
	if !urOptionBool(options, "revoke") {
		if len(reply.Items) == 0 {
			cli.printf("no Delegation\n")
		}
		for _, item := range reply.Items {
			cli.printf("%s\n", urDelegationLine(item))
		}
		return nil
	}
	delegationId, _ := options.String("<delegation_id>")
	params := &urDelegationRevokeParams{DelegationId: strings.ToLower(delegationId), Leaked: urOptionBool(options, "--leaked")}
	since, _ := options.String("--since")
	var item *urDelegationItem
	for _, candidate := range reply.Items {
		if candidate.DelegationId == params.DelegationId {
			item = candidate
		}
	}
	switch {
	case item == nil:
		return errors.New("no such Delegation")
	case item.ForwardSidecarId != nil && params.Leaked:
		return errors.New("a forwarding Delegation admitted nothing, so its revocation takes no --leaked")
	case since != "" && !params.Leaked:
		return errors.New("--since goes with --leaked")
	case params.Leaked && since == "":
		return errors.New("--leaked takes --since <time|position>: what the bundle admitted from then on parks")
	case since != "":
		if position, err := strconv.ParseUint(since, 10, 64); err == nil {
			params.SinceN = position
		} else if at, err := time.Parse(time.RFC3339, since); err == nil {
			params.SinceMs = at.UnixMilli()
		} else {
			return fmt.Errorf("--since takes a log position or an RFC 3339 time: %q", since)
		}
	}
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	fmt.Fprintln(tty, "revoke Delegation: "+urDelegationLine(item))
	switch {
	case item.ForwardSidecarId != nil && (item.EndedAt != 0 || item.SupersededAt != 0):
		fmt.Fprintln(tty, "  a forwarding Delegation no longer live: revoking it changes nothing live")
	case item.ForwardSidecarId != nil:
		fmt.Fprintln(tty, "  a forwarding Delegation: hosts deny its key from this entry on, and that device's VPN component")
		fmt.Fprintln(tty, "  forwards again only after a new setup the person confirms in the app")
	default:
		fmt.Fprintln(tty, "  it admits nothing more, and its shared reader key retires; its agents read on by their own ReaderWraps")
	}
	if params.Leaked {
		fmt.Fprintln(tty, "  for a leaked bundle: what it admitted from "+since+" on parks")
	}
	tty.Close()
	confirmed, err := confirmOnTty(cli, "revoke it?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	if err := cli.callDaemon(ctx, urMethodAdminDelegationRevoke, params, true, nil); err != nil {
		return err
	}
	cli.printf("Delegation %s: revoked\n", params.DelegationId)
	return nil
}
