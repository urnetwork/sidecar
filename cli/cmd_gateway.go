// ur gateway (DESIGN-COMPUTE §8.4, §8.6, §8.9; R-GW-1, D-GW-3, D-GW-7, IC-11; GW-M12-02): the local gateway's tokens and
// grants from the terminal, and from a harness's credential command.
//
//	ur gateway token --harness=<h> [--agent=<label>] [--network=<net>]
//	                                  asks the daemon for a proof key over its control socket, proves on the port's
//	                                  loopback addresses that the daemon holds the listener (gateway_proof.go), and only
//	                                  then asks for a token, which it prints alone on stdout: what Codex's
//	                                  [model_providers.ur.auth] command and Claude Code's apiKeyHelper read. Anything
//	                                  short of the proof prints nothing on stdout and exits non-zero, so a process that
//	                                  took the port gets no token. Run by a harness, the token is that harness process's
//	                                  run handle; at a terminal, whose stdout is one, it is unbound
//	ur gateway grants [--json] [--network=<net>]
//	                                  every network's grants: harness, agent, models, budget, expiry, live tokens, bound
//	                                  and unbound, and raises waiting on their approval; a grant with unbound tokens names
//	                                  the command that binds them
//	ur gateway grants revoke <grant>  revokes a grant and its tokens at once
//	ur gateway status [--json]        the port, who holds it, and the grants
//
// One command, gateway, whose usage is its subcommands', each registered through registerUrGatewaySubcommand from its
// own file at init, so GW's later tasks add config and run in files of their own. Nothing here prints a token but
// gateway token's one line, and no grant is made here: ur install-harness <h> --gateway makes one (GW-M12-07).

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// One `ur gateway` subcommand.
type urGatewaySubcommand struct {
	// The words after gateway that select it, which docopt reads as commands: grants revoke.
	words []string
	// Its docopt usage lines, each starting "ur gateway <words>", without the "Usage:" heading.
	usage string
	run   func(ctx context.Context, cli *urCli, options docopt.Opts) error
}

// The subcommands, the longest words first, so grants revoke is tried before grants. Written only at init.
var urGatewaySubcommands = []*urGatewaySubcommand{}

// ur gateway itself: its usage is its subcommands', rebuilt as each registers.
var urGatewayCommand = &urCommand{
	name:    "gateway",
	summary: "the local gateway: tokens for harnesses, grants and the port",
	run:     runUrGateway,
}

// Adds a subcommand at init. One whose words another holds, or with no words, usage or run, is a programming error,
// found at start.
func registerUrGatewaySubcommand(subcommand *urGatewaySubcommand) {
	if subcommand == nil || len(subcommand.words) == 0 || subcommand.usage == "" || subcommand.run == nil {
		panic("a ur gateway subcommand registered without its words, usage or run")
	}
	for _, other := range urGatewaySubcommands {
		if slices.Equal(other.words, subcommand.words) {
			panic(fmt.Sprintf("ur gateway %s registered twice", strings.Join(subcommand.words, " ")))
		}
	}
	urGatewaySubcommands = append(urGatewaySubcommands, subcommand)
	slices.SortStableFunc(urGatewaySubcommands, func(a *urGatewaySubcommand, b *urGatewaySubcommand) int {
		return len(b.words) - len(a.words)
	})
	usages := []string{}
	for _, registered := range urGatewaySubcommands {
		usages = append(usages, registered.usage)
	}
	urGatewayCommand.usage = strings.Join(usages, "\n")
}

// Registers ur gateway and this file's subcommands.
func init() {
	registerUrCommand(urGatewayCommand)
	for _, subcommand := range []*urGatewaySubcommand{
		{words: []string{"token"}, usage: "  ur gateway token --harness=<h> [--agent=<label>] [--network=<net>]", run: runUrGatewayToken},
		{words: []string{"grants"}, usage: "  ur gateway grants [--json] [--network=<net>]", run: runUrGatewayGrants},
		{words: []string{"grants", "revoke"}, usage: "  ur gateway grants revoke <grant>", run: runUrGatewayGrantsRevoke},
		{words: []string{"status"}, usage: "  ur gateway status [--json]", run: runUrGatewayStatus},
	} {
		registerUrGatewaySubcommand(subcommand)
	}
}

// Runs the subcommand whose words docopt matched.
func runUrGateway(ctx context.Context, cli *urCli, options docopt.Opts) error {
	for _, subcommand := range urGatewaySubcommands {
		matched := true
		for _, word := range subcommand.words {
			if on, _ := options[word].(bool); !on {
				matched = false
				break
			}
		}
		if matched {
			return subcommand.run(ctx, cli, options)
		}
	}
	return errors.New("no gateway subcommand matched")
}

// The proof the token command runs, which a test may stand in for.
var urGatewayProve = func(ctx context.Context, key *sidecar.GatewayListenerKey, address string) error {
	return sidecar.ProveGatewayListener(ctx, sidecar.DefaultGatewaySettings(), key, address, nil)
}

// A token for one harness install, printed alone, only once the listener proved it is the daemon's: see the file header.
func runUrGatewayToken(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &sidecar.GatewayTokenParams{
		Harness:     urOptionString(options, "--harness"),
		Agent:       urOptionString(options, "--agent"),
		Network:     urOptionString(options, "--network"),
		Interactive: cli.stdoutIsTerminal(),
	}
	key := &sidecar.GatewayListenerKey{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodGatewayKey, struct{}{}, false, key); err != nil {
		return fmt.Errorf("no token: the daemon gave no listener key: %w", err)
	}
	addresses, err := sidecar.GatewayListenerAddressesToProve(key)
	if err != nil {
		return fmt.Errorf("no token: %w", err)
	}
	for _, address := range addresses {
		if err := urGatewayProve(ctx, key, address); err != nil {
			return fmt.Errorf("no token: %w", err)
		}
	}
	reply := &sidecar.GatewayTokenReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodGatewayToken, params, false, reply); err != nil {
		return fmt.Errorf("no token: %w", err)
	}
	if !strings.HasPrefix(reply.Token, sidecar.GatewayTokenPrefix) {
		return errors.New("no token: the daemon answered no gateway token")
	}
	fmt.Fprintln(cli.stdout, reply.Token)
	return nil
}

// Every network's grants.
func runUrGatewayGrants(ctx context.Context, cli *urCli, options docopt.Opts) error {
	reply := &sidecar.GatewayGrantsReply{}
	params := &sidecar.GatewayGrantsParams{Action: sidecar.GatewayGrantsActionList, Network: urOptionString(options, "--network")}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodGatewayGrants, params, false, reply); err != nil {
		return err
	}
	if on, _ := options["--json"].(bool); on {
		encoded, err := json.MarshalIndent(reply, "", "  ")
		if err != nil {
			return err
		}
		cli.printf("%s\n", encoded)
		return nil
	}
	for _, line := range urGatewayGrantLines(reply) {
		cli.printf("%s\n", line)
	}
	if len(reply.Grants) == 0 && len(reply.Unread) == 0 {
		cli.printf("no gateway grants: ur install-harness <harness> --gateway makes one\n")
	}
	return nil
}

// Revokes one grant.
func runUrGatewayGrantsRevoke(ctx context.Context, cli *urCli, options docopt.Opts) error {
	grantId, err := sidecar.ParseId(urOptionString(options, "<grant>"))
	if err != nil {
		return errors.New("<grant> is a grant's id, as ur gateway grants lists it")
	}
	reply := &sidecar.GatewayGrantsReply{}
	params := &sidecar.GatewayGrantsParams{Action: sidecar.GatewayGrantsActionRevoke, GrantId: &grantId}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodGatewayGrants, params, false, reply); err != nil {
		return err
	}
	if !reply.Revoked {
		return fmt.Errorf("no grant %s stood", grantId)
	}
	cli.printf("revoked    grant %s and its tokens\n", grantId)
	return nil
}

// The port and the grants.
func runUrGatewayStatus(ctx context.Context, cli *urCli, options docopt.Opts) error {
	status := &sidecar.GatewayServerStatus{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodGatewayStatus, struct{}{}, false, status); err != nil {
		return err
	}
	grants := &sidecar.GatewayGrantsReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodGatewayGrants, &sidecar.GatewayGrantsParams{Action: sidecar.GatewayGrantsActionList}, false, grants); err != nil {
		return err
	}
	if on, _ := options["--json"].(bool); on {
		encoded, err := json.MarshalIndent(map[string]any{"listener": status, "grants": grants}, "", "  ")
		if err != nil {
			return err
		}
		cli.printf("%s\n", encoded)
		return nil
	}
	lines := urGatewayStatusLines(status)
	if len(lines) == 0 {
		lines = append(lines, "gateway:    no port: ur install-harness <harness> --gateway chooses one")
	}
	for _, line := range append(lines, urGatewayGrantLines(grants)...) {
		cli.printf("%s\n", line)
	}
	return nil
}

// A grant's budget as a person reads it: the agent's default where the grant names none.
func urGatewayBudgetText(amount *int64, period string) string {
	if amount == nil {
		return "the agent's default a " + period
	}
	return sidecar.ComputeMoneyText(*amount) + " a " + period
}

// The grants' lines: each grant, its pending raises, and its unbound tokens with the command that binds them.
func urGatewayGrantLines(reply *sidecar.GatewayGrantsReply) []string {
	lines := []string{}
	for _, view := range reply.Grants {
		grant := view.Grant
		models := "every model the models key allows"
		if 0 < len(grant.Models) {
			models = strings.Join(grant.Models, ", ")
		}
		expires := "never"
		if grant.ExpiresMillis != 0 {
			expires = time.UnixMilli(grant.ExpiresMillis).UTC().Format(time.RFC3339)
		}
		lines = append(lines, fmt.Sprintf("grant:      %s  %s, agent %s (%s), network %s", grant.GrantId, grant.Harness, grant.AgentLabel,
			grant.AgentId, view.NetworkId))
		lines = append(lines, fmt.Sprintf("  models:   %s", models))
		lines = append(lines, fmt.Sprintf("  budget:   %s, %s; expires %s", urGatewayBudgetText(grant.DayNanoUsd, "day"),
			urGatewayBudgetText(grant.MonthNanoUsd, "month"), expires))
		for _, raise := range grant.PendingRaises {
			lines = append(lines, fmt.Sprintf("  raise:    to %s a %s waits on approval %s: run ur approve %s on an approval-capable device",
				sidecar.ComputeMoneyText(raise.AmountNanoUsd), raise.Period, raise.ApprovalId, raise.ApprovalId))
		}
		lines = append(lines, fmt.Sprintf("  tokens:   %d live, %d bound to a harness process", view.LiveTokenCount, view.BoundTokenCount))
		if unbound := view.LiveTokenCount - view.BoundTokenCount; 0 < unbound {
			lines = append(lines, fmt.Sprintf("  unbound:  %d token(s) bind no harness process, so their calls are checked against every live run of the grant's harnesses and recorded as untrusted: a token binds its harness when the harness's credential command runs `%s`",
				unbound, view.BindCommand))
		}
	}
	for _, unread := range reply.Unread {
		lines = append(lines, "  warning:  grants do not read: "+unread)
	}
	return lines
}
