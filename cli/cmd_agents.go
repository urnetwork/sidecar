// ur agents (§16.10's CLI block and agents row; owner decision 166; D-MCP-22, D-MCP-23, I-9, FS-80; SEARCH-M10-30;
// DESIGN-COMPUTE §15.1's ur agents rows, §20.8; SKILL-M11-08): the person's agents, and search_agents.
//
//	ur agents [ls]                    the member's agents (agent_list for the person, the daemon's agents.list): each
//	                                  one's state, activity, task, status age and newest summary, printed as prose as
//	                                  ur agents prints search_agents', untrusted writers' text withheld off a terminal
//	                                  unless --untrusted include, which taints first each run whose harness process is
//	                                  an ancestor of this ur process; bare ur agents lists (compute-plan-ur-agents-ls,
//	                                  QD-1380), a change of today's no-task search, which a search flag still asks for
//	ur agents send|broadcast|inbox|reply
//	                                  cmd_agents_send.go
//	ur agents <task>                  search_agents through the daemon's control method search.agents, its groups by
//	                                  (network, sidecar, agent label) with their runs and claims, active groups first,
//	                                  in ur search's formats (search_format.go); ls, send, broadcast, inbox and reply are
//	                                  subcommands, never a task
//
// The search: --since and --until take what ur search's do; the daemon's search_agents looks back 30 d where no
// --since is given. Untrusted text is withheld off a terminal unless --untrusted include is given, and asking for it
// taints first each run whose harness process is an ancestor of this ur process, as ur search's does. The exit codes
// are ur search's. --scope takes network or repo, which names its --repo; --scope all, --network's fan-out and --more
// are refused as not built yet, since the daemon's search_agents takes neither.

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

func init() {
	registerUrCommand(&urCommand{
		name: "agents",
		usage: strings.Join([]string{
			// the subcommands first: docopt takes the first usage a line matches, so ls is ls, never a task
			"  ur agents ls [--retired] [--untrusted=<untrusted>] [--json] [--network=<network>]",
			"  ur agents send <name> <text> [--subject=<subject>] [--json] [--network=<network>]",
			"  ur agents broadcast <text> [--subject=<subject>] [--json] [--network=<network>]",
			"  ur agents inbox [--thread=<thread>] [--untrusted=<untrusted>] [--json] [--network=<network>]",
			"  ur agents reply <thread> <text> [--to=<name>] [--json] [--network=<network>]",
			"  ur agents [<task>] [--scope=<scope>] [--repo=<repo>]... [--network=<network>] [--since=<time>] [--until=<time>] [--more] [--untrusted=<untrusted>] [--limit=<n>] [--wait=<duration>] [--format=<format>]",
		}, "\n"),
		summary: "your agents: what they are doing, messages to them and their replies, or which agents work on a task",
		run:     runUrAgents,
	})
}

// The subcommands, by their word; a task argument never takes one (QD-1380).
var urAgentsSubcommands = map[string]func(ctx context.Context, cli *urCli, options docopt.Opts) error{
	"ls":        runUrAgentsLs,
	"send":      runUrAgentsSend,
	"broadcast": runUrAgentsBroadcast,
	"inbox":     runUrAgentsInbox,
	"reply":     runUrAgentsReply,
}

// The flags only the search takes: given with no task, they ask for a no-task search, as ur agents did before ls.
var urAgentsSearchFlags = []string{"--scope", "--repo", "--since", "--until", "--more", "--limit", "--wait", "--format"}

// Runs ur agents: a subcommand where its word was given, the list where nothing was, else the search.
func runUrAgents(ctx context.Context, cli *urCli, options docopt.Opts) error {
	for word, run := range urAgentsSubcommands {
		if on, _ := options.Bool(word); on {
			return run(ctx, cli, options)
		}
	}
	task := urOptionString(options, "<task>")
	if run, reserved := urAgentsSubcommands[task]; reserved {
		// a subcommand's word reached the task's line: only one that takes no argument runs from there
		if task != "ls" && task != "inbox" {
			return &urExitError{code: urExitUsage, err: fmt.Errorf("ur agents %s takes its arguments: ur agents --help", task)}
		}
		return run(ctx, cli, options)
	}
	if task == "" && !slices.ContainsFunc(urAgentsSearchFlags, func(flag string) bool {
		value, found := options[flag]
		switch value := value.(type) {
		case nil:
			return false
		case bool:
			return value
		case string:
			return value != ""
		case []string:
			return 0 < len(value)
		}
		return found
	}) {
		return runUrAgentsLs(ctx, cli, options)
	}
	return runUrAgentsSearch(ctx, cli, options)
}

var errUrAgentsMore = errors.New("ur agents --more is not built yet: the daemon's search_agents takes no all set")

// search.agents' control params.
type urAgentsParams struct {
	sidecar.SearchAgentsToolArgs
	Network string `json:"network,omitempty"`
}

// Runs ur agents <task>: search_agents.
func runUrAgentsSearch(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params, format, err := urAgentsParamsOf(cli, options)
	if err != nil {
		return &urExitError{code: urSearchExitError, err: err}
	}
	reply := &sidecar.SearchAgentsToolResult{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodSearchAgents, params, false, reply); err != nil {
		return urSearchError(err)
	}
	// written as a search result of groups, so every format reads one way
	result := &sidecar.SearchToolResult{
		Hits: []*sidecar.SearchToolHit{}, Groups: reply.Groups, Coverage: []*sidecar.SearchToolCoverage{}, Counts: reply.Counts,
		Status: sidecar.SearchToolStatus{Complete: reply.Complete, Tainted: reply.Tainted, Trust: reply.Trust},
	}
	switch format {
	case urSearchFormatJson:
		encoded, err := urSearchJson(reply)
		if err != nil {
			return urSearchError(err)
		}
		if _, err := cli.stdout.Write(encoded); err != nil {
			return urSearchError(err)
		}
	case urSearchFormatJsonl:
		for _, group := range reply.Groups {
			encoded, err := urSearchJson(group)
			if err != nil {
				return urSearchError(err)
			}
			if _, err := cli.stdout.Write(encoded); err != nil {
				return urSearchError(err)
			}
		}
		if err := urSearchWriteSummary(cli.stdout, result); err != nil {
			return urSearchError(err)
		}
	case urSearchFormatIds:
		for _, group := range reply.Groups {
			for _, run := range group.Runs {
				if run.RunId != "" {
					cli.printf("%s\n", urSearchSafe(group.Key+" run "+run.RunId))
				}
			}
		}
	default:
		for _, group := range reply.Groups {
			cli.printf("%s\n", urSearchGroupLine(group))
			for _, run := range group.Runs {
				line := "  run " + run.RunId
				if run.Title != "" {
					line += "  " + run.Title
				}
				if run.LastActivity != "" {
					line += "  last " + run.LastActivity
				}
				cli.printf("%s\n", urSearchSafe(line))
			}
			for _, claim := range group.Claims {
				line := "  claim " + claim.ClaimId
				if claim.State != "" {
					line += "  " + claim.State
				}
				if claim.Text != "" {
					line += "  " + claim.Text
				}
				cli.printf("%s\n", urSearchSafe(line))
			}
		}
		state := "complete"
		if !reply.Complete {
			state = "partial: the wait elapsed"
		}
		cli.printf("%s\n", urSearchSafe(fmt.Sprintf("-- %d groups; %d untrusted withheld; %s", len(reply.Groups), reply.Counts.UntrustedWithheld, state)))
	}
	return urSearchExit(result, len(reply.Groups))
}

// ur agents' params from its flags.
func urAgentsParamsOf(cli *urCli, options docopt.Opts) (*urAgentsParams, string, error) {
	now := time.Now()
	params := &urAgentsParams{Network: urOptionString(options, "--network")}
	args := &params.SearchAgentsToolArgs
	args.Task = urOptionString(options, "<task>")
	scope, err := urSearchChoice("--scope", urOptionString(options, "--scope"), "network", "repo", "all")
	if err != nil {
		return nil, "", err
	}
	args.Repos = urOptionStrings(options, "--repo")
	switch {
	case scope == "all":
		return nil, "", sidecar.ErrSearchToolUnbuilt
	case scope == "repo" && len(args.Repos) == 0:
		return nil, "", errors.New("--scope repo names a --repo")
	}
	if urOptionBool(options, "--more") {
		return nil, "", errUrAgentsMore
	}
	if args.Since, err = urSearchTime("--since", urOptionString(options, "--since"), now); err != nil {
		return nil, "", err
	}
	if args.Until, err = urSearchTime("--until", urOptionString(options, "--until"), now); err != nil {
		return nil, "", err
	}
	if args.Untrusted, err = urSearchUntrusted(cli, urOptionString(options, "--untrusted")); err != nil {
		return nil, "", err
	}
	if limit := urOptionString(options, "--limit"); limit != "" {
		if args.Limit, err = strconv.Atoi(limit); err != nil || args.Limit <= 0 {
			return nil, "", errors.New("--limit takes a positive count")
		}
	}
	if args.WaitMs, err = urSearchWaitMs(cli, urOptionString(options, "--wait")); err != nil {
		return nil, "", err
	}
	format, err := urSearchChoice("--format", urOptionString(options, "--format"), urSearchFormatText, urSearchFormatJson, urSearchFormatJsonl, urSearchFormatIds)
	if err != nil {
		return nil, "", err
	}
	return params, format, nil
}

// Runs ur agents ls: the member's agents through the daemon's agents.list, untrusted text withheld off a terminal unless
// --untrusted include.
func runUrAgentsLs(ctx context.Context, cli *urCli, options docopt.Opts) error {
	untrusted, err := urSearchUntrusted(cli, urOptionString(options, "--untrusted"))
	if err != nil {
		return err
	}
	params := &sidecar.DaemonAgentsListParams{Network: urOptionString(options, "--network"), Retired: urOptionBool(options, "--retired"),
		Untrusted: untrusted}
	list := &sidecar.AgentList{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodAgentsList, params, false, list); err != nil {
		return err
	}
	if urOptionBool(options, "--json") {
		encoded, err := urSearchJson(list)
		if err != nil {
			return err
		}
		_, err = cli.stdout.Write(encoded)
		return err
	}
	if len(list.Agents) == 0 {
		cli.printf("no agents are registered in your member's agents repo\n")
		return nil
	}
	for _, agent := range list.Agents {
		for _, line := range urAgentsLsLines(agent) {
			cli.printf("%s\n", urSearchSafe(line))
		}
	}
	if 0 < list.UntrustedWithheld {
		cli.printf("%s\n", urSearchSafe(fmt.Sprintf("-- %d agents' text withheld: untrusted writers wrote it; --untrusted include shows it", list.UntrustedWithheld)))
	}
	return nil
}

// One agent's lines, as ur agents prints prose: a head line, then its activity, task and summary, indented.
func urAgentsLsLines(agent *sidecar.AgentListEntry) []string {
	if agent.Stub != nil {
		stub := agent.Stub
		return []string{fmt.Sprintf("%s  %s %s  on %s  model %s  [untrusted: withheld; written by %s]", stub.Name, stub.State,
			time.Duration(stub.Age)*time.Second, stub.Host, stub.Model, stub.Writer)}
	}
	head := agent.Name
	if agent.Person {
		head += "  (you)"
	}
	if agent.State != "" {
		head += fmt.Sprintf("  %s %s", agent.State, time.Duration(agent.StatusAge)*time.Second)
	} else if !agent.Person {
		head += "  no status yet"
	}
	if agent.Host != "" {
		head += "  on " + agent.Host
	}
	if agent.Model != "" {
		head += "  model " + agent.Model
	}
	if agent.Parent != "" {
		head += "  launched by " + agent.Parent
	}
	if agent.Retired != "" {
		head += "  retired " + agent.Retired
	}
	if !agent.Trusted {
		head += "  [untrusted]"
	}
	lines := []string{head}
	if agent.Activity != "" {
		lines = append(lines, "  doing: "+agent.Activity)
	}
	if agent.Task != "" {
		lines = append(lines, "  task: "+agent.Task)
	}
	if agent.Summary != "" {
		lines = append(lines, fmt.Sprintf("  summary, %s old:", time.Duration(agent.SummaryAge)*time.Second))
		for _, line := range strings.Split(agent.Summary, "\n") {
			lines = append(lines, "    "+line)
		}
	}
	return lines
}
