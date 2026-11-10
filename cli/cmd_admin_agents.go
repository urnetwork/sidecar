// ur admin (TEAM-M2-18, TEAM-M10-01): a network admin's acts on its config, each read from the verified log, printed
// as a plan, confirmed on /dev/tty and signed through the daemon's sidecarAct, never through MCP or a hook (D-CORE-13,
// R-CTX-33). This file registers the command and its agents part:
//
//	ur admin agents revoke <agent> [--compromise [--since=<since>]]
//	ur admin agents suspend <agent>
//	ur admin agents unsuspend <agent>
//
// For an agent a Delegation admitted, the plan names three things apart: the agent; the Delegation's shared reader
// key, the agents that then read by their own ReaderWraps and the repos that rotate; and the Delegation's admission
// authority, its not_after and the admissions left, which only --compromise ends. Any other act offers
// `ur admin delegations revoke`, since revoking an auth key at api stops only its bearer (D-TEAM-31). A revocation or
// Suspend the log covers needs the presence countersignature, which the daemon's prompt gives once §16's lands; until
// then the act refuses rather than sign without it.
//
// cmd_admin_delegations.go adds `ur admin delegations`, and cmd_admin_versioning.go `ur admin versioning`.

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

// The control methods ur admin agents calls.
const (
	urMethodAdminAgentPlan = "admin.agents.plan"
	urMethodAdminAgentAct  = "admin.agents.act"
)

func init() {
	registerUrCommand(&urCommand{
		name: "admin",
		usage: strings.Join([]string{
			"  ur admin agents (revoke|suspend|unsuspend) <agent> [--compromise] [--since=<since>]",
			"  ur admin delegations [revoke <delegation_id>] [--leaked] [--since=<since>]",
			"  ur admin versioning [--rules=<rules_json>]",
		}, "\n"),
		summary: "a network admin's acts on its config: agents, Delegations and versioning, confirmed on the terminal",
		run:     runUrAdmin,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urAdminAgentMethods)
}

// Runs the part of ur admin its first word names.
func runUrAdmin(ctx context.Context, cli *urCli, options docopt.Opts) error {
	switch {
	case urOptionBool(options, "agents"):
		return runUrAdminAgents(ctx, cli, options)
	case urOptionBool(options, "delegations"):
		return runUrAdminDelegations(ctx, cli, options)
	case urOptionBool(options, "versioning"):
		return runUrAdminVersioning(ctx, cli, options)
	}
	return errors.New("ur admin takes agents, delegations or versioning")
}

// A docopt flag or command word, false when absent.
func urOptionBool(options docopt.Opts, key string) bool {
	value, _ := options.Bool(key)
	return value
}

// What the agents methods act on: a target hosting a Sidecar.
type urAdminAgentsTarget interface {
	planAgentAct(agentId sidecar.Id, act sidecar.AgentAct, compromise bool, sinceN uint64) (*sidecar.AgentRevokePlan, error)
	signAgentAct(ctx context.Context, agentId sidecar.Id, act sidecar.AgentAct, compromise bool, sinceN uint64) error
	resolveAgent(nameOrId string) (sidecar.Id, error)
}

func (self *urDaemonNetwork) planAgentAct(agentId sidecar.Id, act sidecar.AgentAct, compromise bool, sinceN uint64) (*sidecar.AgentRevokePlan, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	return running.PlanAgentAct(agentId, act, compromise, sinceN)
}

// A confirmed control call, the person having answered on /dev/tty. The daemon's presence prompt is §16's, so an act
// the log covers is refused until it lands, never signed without the check.
func (self *urDaemonNetwork) signAgentAct(ctx context.Context, agentId sidecar.Id, act sidecar.AgentAct, compromise bool, sinceN uint64) error {
	running, err := self.onlySidecar()
	if err != nil {
		return err
	}
	_, _, err = running.SignAgentAct(ctx, agentId, act, compromise, sinceN, sidecar.SidecarActConfirmed, nil)
	return err
}

func (self *urDaemonNetwork) resolveAgent(nameOrId string) (sidecar.Id, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return sidecar.Id{}, err
	}
	return running.ResolveAgent(nameOrId)
}

// admin.agents.plan's and admin.agents.act's params.
type urAgentActParams struct {
	Agent      string `json:"agent"`
	Act        string `json:"act"`
	Compromise bool   `json:"compromise,omitempty"`
	SinceN     uint64 `json:"since_n,omitempty"`
}

// A plan as the methods answer it: ids, positions and counts, never a secret.
type urAgentPlanReply struct {
	Act       string       `json:"act"`
	AgentId   sidecar.Id   `json:"agent_id"`
	TagIds    []sidecar.Id `json:"tag_ids"`
	Ephemeral bool         `json:"ephemeral,omitempty"`
	NotAfter  int64        `json:"not_after_ms,omitempty"`
	Revoked   bool         `json:"revoked,omitempty"`
	Parked    bool         `json:"parked,omitempty"`
	Suspended bool         `json:"suspended,omitempty"`
	SinceN    uint64       `json:"since_n,omitempty"`

	DelegationId     string       `json:"delegation_id,omitempty"`
	KeyRetires       bool         `json:"key_retires,omitempty"`
	AgentsOnOwnWraps []sidecar.Id `json:"agents_on_own_wraps,omitempty"`
	ReposRotating    []sidecar.Id `json:"repos_rotating,omitempty"`
	AuthorityEnds    bool         `json:"authority_ends,omitempty"`
	AuthorityUntil   int64        `json:"authority_until_ms,omitempty"`
	AdmissionsLeft   uint32       `json:"admissions_left,omitempty"`
	ParkedAgents     []sidecar.Id `json:"parked_agents,omitempty"`
	Lifts            []string     `json:"lifts,omitempty"`
	Offer            string       `json:"offer,omitempty"`
}

// The reply of a plan.
func urAgentPlanReplyOf(plan *sidecar.AgentRevokePlan) *urAgentPlanReply {
	reply := &urAgentPlanReply{
		Act:       string(plan.Act),
		AgentId:   plan.AgentId,
		TagIds:    plan.TagIds,
		Ephemeral: plan.Ephemeral,
		Revoked:   plan.Revoked,
		Parked:    plan.Parked,
		Suspended: plan.Suspended,
		SinceN:    plan.SinceN,
		Offer:     plan.Offer,
	}
	if !plan.NotAfter.IsZero() {
		reply.NotAfter = plan.NotAfter.UnixMilli()
	}
	if delegation := plan.Delegation; delegation != nil {
		reply.DelegationId = hex.EncodeToString(delegation.DelegationId)
		reply.KeyRetires = delegation.KeyRetires
		reply.AgentsOnOwnWraps = delegation.AgentsOnOwnWraps
		reply.ReposRotating = delegation.ReposRotating
		reply.AuthorityEnds = delegation.AuthorityEnds
		reply.AdmissionsLeft = delegation.AdmissionsLeft
		reply.ParkedAgents = delegation.ParkedAgents
		if !delegation.NotAfter.IsZero() {
			reply.AuthorityUntil = delegation.NotAfter.UnixMilli()
		}
		for _, lift := range delegation.Lifts {
			reply.Lifts = append(reply.Lifts, fmt.Sprintf("%s by %s at %d", lift.AgentId, hex.EncodeToString(lift.Signer), lift.Position))
		}
	}
	return reply
}

// The agents methods over target, when it hosts a Sidecar.
func urAdminAgentMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	agents, ok := target.(urAdminAgentsTarget)
	if !ok {
		return nil
	}
	parse := func(call *sidecar.DaemonCall) (*urAgentActParams, sidecar.Id, sidecar.AgentAct, error) {
		params := &urAgentActParams{}
		if err := decodeUrParams(call, params); err != nil {
			return nil, sidecar.Id{}, "", err
		}
		agentId, err := agents.resolveAgent(params.Agent)
		if err != nil {
			return nil, sidecar.Id{}, "", err
		}
		return params, agentId, sidecar.AgentAct(params.Act), nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodAdminAgentPlan,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, agentId, act, err := parse(call)
				if err != nil {
					return nil, err
				}
				plan, err := agents.planAgentAct(agentId, act, params.Compromise, params.SinceN)
				if err != nil {
					return nil, err
				}
				return urAgentPlanReplyOf(plan), nil
			},
		},
		{
			Name:    urMethodAdminAgentAct,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, agentId, act, err := parse(call)
				if err != nil {
					return nil, err
				}
				return nil, agents.signAgentAct(ctx, agentId, act, params.Compromise, params.SinceN)
			},
		},
	}
}

// The plan's lines, as the terminal shows them before the person answers: the agent, then for a Delegation's agent its
// shared key and its admission authority apart, then what is offered.
func urAgentPlanLines(plan *urAgentPlanReply) []string {
	lines := []string{fmt.Sprintf("%s agent %s", plan.Act, plan.AgentId)}
	tagIds := []string{}
	for _, tagId := range plan.TagIds {
		tagIds = append(tagIds, tagId.String())
	}
	agentLine := "  the agent: tags " + strings.Join(tagIds, ",")
	if plan.Ephemeral {
		agentLine += ", ephemeral"
	}
	if plan.NotAfter != 0 {
		agentLine += ", until " + time.UnixMilli(plan.NotAfter).UTC().Format(time.RFC3339)
	}
	if plan.Parked {
		agentLine += ", parked"
	}
	if plan.Suspended {
		agentLine += ", suspended"
	}
	lines = append(lines, agentLine)
	if 0 < plan.SinceN {
		lines = append(lines, fmt.Sprintf("  for compromise: what it signed from position %d is void until signed again outside it", plan.SinceN))
	}
	if plan.DelegationId != "" {
		if plan.KeyRetires {
			wraps := []string{}
			for _, agentId := range plan.AgentsOnOwnWraps {
				wraps = append(wraps, agentId.String())
			}
			repos := []string{}
			for _, repoId := range plan.ReposRotating {
				repos = append(repos, repoId.String())
			}
			lines = append(lines, fmt.Sprintf("  Delegation %s's shared reader key retires: %d agent(s) then read by their own ReaderWraps (%s); %d repo(s) rotate (%s)",
				plan.DelegationId, len(wraps), strings.Join(wraps, ","), len(repos), strings.Join(repos, ",")))
		} else {
			lines = append(lines, fmt.Sprintf("  Delegation %s's shared reader key: unchanged by this act", plan.DelegationId))
		}
		authority := fmt.Sprintf("  Delegation %s's admission authority: ", plan.DelegationId)
		if plan.AuthorityEnds {
			authority += "ends with this act"
		} else {
			authority += fmt.Sprintf("still admits, %d admission(s) left", plan.AdmissionsLeft)
			if plan.AuthorityUntil != 0 {
				authority += " until " + time.UnixMilli(plan.AuthorityUntil).UTC().Format(time.RFC3339)
			}
		}
		lines = append(lines, authority)
		if 0 < len(plan.ParkedAgents) {
			parked := []string{}
			for _, agentId := range plan.ParkedAgents {
				parked = append(parked, agentId.String())
			}
			lines = append(lines, "  its agents parked now: "+strings.Join(parked, ","))
		}
		for _, lift := range plan.Lifts {
			lines = append(lines, "  park lifted: "+lift)
		}
	}
	if plan.Offer != "" {
		lines = append(lines, "  to end the Delegation as well: "+plan.Offer)
		lines = append(lines, "  revoking its auth key at api stops only that key's bearer")
	}
	return lines
}

// ur admin agents: the plan, printed to the terminal, then the act on a yes.
func runUrAdminAgents(ctx context.Context, cli *urCli, options docopt.Opts) error {
	act := sidecar.AgentActRevoke
	switch {
	case urOptionBool(options, "suspend"):
		act = sidecar.AgentActSuspend
	case urOptionBool(options, "unsuspend"):
		act = sidecar.AgentActUnsuspend
	}
	agent, _ := options.String("<agent>")
	compromise := urOptionBool(options, "--compromise")
	since, _ := options.String("--since")
	if since != "" && !compromise {
		return errors.New("--since goes with --compromise")
	}
	params := &urAgentActParams{Agent: agent, Act: string(act), Compromise: compromise}
	if since != "" {
		position, err := strconv.ParseUint(since, 10, 64)
		if err != nil {
			return fmt.Errorf("--since takes a log position for an agent: %q", since)
		}
		params.SinceN = position
	}
	plan := &urAgentPlanReply{}
	if err := cli.callDaemon(ctx, urMethodAdminAgentPlan, params, false, plan); err != nil {
		return err
	}
	tty, err := cli.openTty()
	if err != nil {
		return fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	for _, line := range urAgentPlanLines(plan) {
		fmt.Fprintln(tty, line)
	}
	tty.Close()
	confirmed, err := confirmOnTty(cli, string(act)+" it?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	if err := cli.callDaemon(ctx, urMethodAdminAgentAct, params, true, nil); err != nil {
		return err
	}
	cli.printf("%s %s: done\n", act, plan.AgentId)
	return nil
}
