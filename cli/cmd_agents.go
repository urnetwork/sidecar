// ur agents (§16.10's CLI block and agents row; owner decision 166; D-MCP-22, D-MCP-23, I-9, FS-80; SEARCH-M10-30):
// search_agents through the daemon's control method search.agents, its groups by (network, sidecar, agent label) with
// their runs and claims, active groups first, in ur search's formats (search_format.go).
//
// --since and --until take what ur search's do; the daemon's search_agents looks back 30 d where no --since is given.
// Untrusted text is withheld off a terminal unless --untrusted include is given, and asking for it taints first each
// run whose harness process is an ancestor of this ur process, as ur search's does. The exit codes are ur search's.
// --scope takes network or repo, which names its --repo; --scope all, --network's fan-out and --more are refused as
// not built yet, since the daemon's search_agents takes neither.

package main

import (
	"context"
	"errors"
	"fmt"
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
			"  ur agents [<task>] [--scope=<scope>] [--repo=<repo>]... [--network=<network>] [--since=<time>] [--until=<time>] [--more] [--untrusted=<untrusted>] [--limit=<n>] [--wait=<duration>] [--format=<format>]",
		}, "\n"),
		summary: "find which agents work on a task: search_agents, grouped by agent",
		run:     runUrAgents,
	})
}

var errUrAgentsMore = errors.New("ur agents --more is not built yet: the daemon's search_agents takes no all set")

// search.agents' control params.
type urAgentsParams struct {
	sidecar.SearchAgentsToolArgs
	Network string `json:"network,omitempty"`
}

// Runs ur agents.
func runUrAgents(ctx context.Context, cli *urCli, options docopt.Opts) error {
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
