// ur search, ur search status and ur search sync (§16.10's CLI block, every flag as it prints them; owner decision 166;
// R-MCP-12, D-MCP-22, D-MCP-23, I-9, FS-80; SEARCH-M10-30): one network's encrypted indexes searched on this device by
// the daemon's control-mode search methods, with the MCP tools' arguments (daemon_search.go), so `ur search` and an
// agent read the same results.
//
//	trust     untrusted text is withheld unless stdout is a terminal or --untrusted include is given; whenever ur asks
//	          for it, a terminal included, the daemon first taints, fsynced, each run whose harness process is an
//	          ancestor of this ur process, by the peer pid the system reports for its socket (§16.7's pid ancestry), so
//	          a harness's shell tool or an editor's terminal cannot read around I-9; a terminal outside every harness
//	          taints nothing
//	wait      --wait defaults to SearchTerminalWait (10 s) on a terminal, else to the MCP tool's default
//	pages     jsonl pages on, on one control session, whose search session its cursor is bound to, printing each page's
//	          hits as it lands, at most SearchPageCount pages, then its summary
//	explain   --explain prints each term as normalizer 1 reads it with the field it is confined to and the trigrams it
//	          looks up, then the resolved scope, each repo or ref left out with its reason, never a hit of one, and each
//	          page's time; on stdout for text, on stderr for the machine formats
//	since     --since and --until take RFC 3339, or a span back from now: 30m, 24h, 7d
//	status    per repo the index state, the format, the all policy, what latest and all cover, cache bytes and what is
//	          not yet searchable
//	sync      a round now on every followed index ref of the repo, or of every repo, all's too with --more; --evict drops
//	          the cache first, keeping §5.9's search state; --policy sets this device's all policy (§18.4's modes), or
//	          "default"
//
// Not built yet, each refused rather than narrowed in silence: --include spam,trash, which the daemon's search does not
// take yet; --verify fetch, which opens candidates as reads through a control method that is not built; --scope all and
// --ref, which the daemon refuses as not built; and a --cursor from another ur process, whose search session ended with
// its control session. A query starting with "-" is taken as a flag: quote it with another term. A query is never
// logged (I-13).

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

func init() {
	registerUrCommand(&urCommand{
		name: "search",
		usage: strings.Join([]string{
			"  ur search status [--scope=<scope>] [--repo=<repo>]... [--network=<network>]",
			"  ur search sync [--repo=<repo>] [--more] [--evict] [--policy=<policy>] [--network=<network>]",
			"  ur search <query> [--scope=<scope>] [--repo=<repo>]... [--network=<network>] [--ref=<ref>] [--agent=<agent>] [--sidecar=<sidecar>] [--member=<member>] [--run=<run>] [--session=<session>] [--kind=<kinds>] [--since=<time>] [--until=<time>] [--path=<prefix>] [--field=<field>]... [--latest | --more] [--group=<group>] [--sort=<sort>] [--limit=<n>] [--cursor=<cursor>] [--untrusted=<untrusted>] [--verify=<verify>] [--fuzzy] [--wait=<duration>] [--include=<include>] [--explain] [--format=<format>]",
		}, "\n"),
		summary: "search the encrypted indexes of the repos this device reads",
		run:     runUrSearch,
	})
}

var (
	errUrSearchInclude = errors.New("--include spam,trash is not built yet: the daemon's search leaves out the mail its join marks spam or trash")
	errUrSearchFetch   = errors.New("--verify fetch is not built yet: verify local or none")
)

// search's control params: the tool's arguments, the network, and whether to stream progress.
type urSearchParams struct {
	sidecar.SearchToolArgs
	Network  string `json:"network,omitempty"`
	Progress bool   `json:"progress,omitempty"`
}

// search.status's control params.
type urSearchStatusParams struct {
	sidecar.SearchStatusToolArgs
	Network string `json:"network,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

// Runs ur search, ur search status or ur search sync.
func runUrSearch(ctx context.Context, cli *urCli, options docopt.Opts) error {
	switch {
	case urOptionBool(options, "status"):
		return urSearchError(runUrSearchStatus(ctx, cli, options))
	case urOptionBool(options, "sync"):
		return urSearchError(runUrSearchSync(ctx, cli, options))
	}
	return runUrSearchQuery(ctx, cli, options)
}

// One of choices, or the first where text is empty; an error naming the flag otherwise.
func urSearchChoice(flag string, text string, choices ...string) (string, error) {
	if text == "" {
		return choices[0], nil
	}
	if !slices.Contains(choices, text) {
		return "", fmt.Errorf("%s takes %s", flag, strings.Join(choices, ", "))
	}
	return text, nil
}

// --since or --until as RFC 3339: an RFC 3339 time as it is, or a span back from now (30m, 24h, 7d). Empty is empty.
func urSearchTime(flag string, text string, now time.Time) (string, error) {
	if text == "" {
		return "", nil
	}
	if _, err := time.Parse(time.RFC3339, text); err == nil {
		return text, nil
	}
	span := time.Duration(0)
	if days, ok := strings.CutSuffix(text, "d"); ok {
		count, err := strconv.Atoi(days)
		if err != nil || count < 0 {
			return "", fmt.Errorf("%s takes an RFC 3339 time or a span such as 30m, 24h or 7d", flag)
		}
		span = time.Duration(count) * 24 * time.Hour
	} else {
		parsed, err := time.ParseDuration(text)
		if err != nil || parsed < 0 {
			return "", fmt.Errorf("%s takes an RFC 3339 time or a span such as 30m, 24h or 7d", flag)
		}
		span = parsed
	}
	return now.Add(-span).UTC().Format(time.RFC3339), nil
}

// --wait as wait_ms: the flag's duration, else SearchTerminalWait on a terminal, else none, the daemon's default.
func urSearchWaitMs(cli *urCli, text string) (*int, error) {
	if text == "" {
		if !cli.stdoutIsTerminal() {
			return nil, nil
		}
		waitMs := int(cli.settings.SearchTerminalWait / time.Millisecond)
		return &waitMs, nil
	}
	wait, err := time.ParseDuration(text)
	if err != nil || wait < 0 {
		return nil, errors.New("--wait takes a duration such as 2s")
	}
	waitMs := int(wait / time.Millisecond)
	return &waitMs, nil
}

// --untrusted: the flag's, else include on a terminal and withhold off one (§16.10's cli row).
func urSearchUntrusted(cli *urCli, text string) (string, error) {
	if text == "" {
		if cli.stdoutIsTerminal() {
			return "include", nil
		}
		return "withhold", nil
	}
	return urSearchChoice("--untrusted", text, "withhold", "include")
}

// The search's params from its flags.
func urSearchParamsOf(cli *urCli, options docopt.Opts) (*urSearchParams, string, error) {
	now := time.Now()
	params := &urSearchParams{Network: urOptionString(options, "--network")}
	args := &params.SearchToolArgs
	args.Query = urOptionString(options, "<query>")
	var err error
	if args.Scope, err = urSearchChoice("--scope", urOptionString(options, "--scope"), "network", "repo", "all"); err != nil {
		return nil, "", err
	}
	args.Repos = urOptionStrings(options, "--repo")
	args.Ref = urOptionString(options, "--ref")
	filters := &sidecar.SearchToolFilters{
		Agent: urOptionString(options, "--agent"), Sidecar: urOptionString(options, "--sidecar"),
		Member: urOptionString(options, "--member"), Run: urOptionString(options, "--run"),
		Session: urOptionString(options, "--session"), PathPrefix: urOptionString(options, "--path"),
	}
	if kinds := urOptionString(options, "--kind"); kinds != "" {
		filters.Kind = strings.Split(kinds, ",")
	}
	if filters.Since, err = urSearchTime("--since", urOptionString(options, "--since"), now); err != nil {
		return nil, "", err
	}
	if filters.Until, err = urSearchTime("--until", urOptionString(options, "--until"), now); err != nil {
		return nil, "", err
	}
	for _, field := range urOptionStrings(options, "--field") {
		name, text, ok := strings.Cut(field, "=")
		if !ok || name == "" {
			return nil, "", errors.New("--field takes name=text")
		}
		if filters.Fields == nil {
			filters.Fields = map[string]string{}
		}
		filters.Fields[name] = text
	}
	if filters.Agent != "" || filters.Sidecar != "" || filters.Member != "" || filters.Run != "" || filters.Session != "" ||
		filters.PathPrefix != "" || filters.Since != "" || filters.Until != "" || 0 < len(filters.Kind) || 0 < len(filters.Fields) {
		args.Filters = filters
	}
	args.Latest, args.More, args.Fuzzy = urOptionBool(options, "--latest"), urOptionBool(options, "--more"), urOptionBool(options, "--fuzzy")
	if group := urOptionString(options, "--group"); group != "" {
		if args.GroupBy, err = urSearchChoice("--group", group, "agent", "run", "repo"); err != nil {
			return nil, "", err
		}
	}
	if sort := urOptionString(options, "--sort"); sort != "" {
		if args.Sort, err = urSearchChoice("--sort", sort, "time", "path"); err != nil {
			return nil, "", err
		}
	}
	if limit := urOptionString(options, "--limit"); limit != "" {
		if args.Limit, err = strconv.Atoi(limit); err != nil || args.Limit <= 0 {
			return nil, "", errors.New("--limit takes a positive count")
		}
	}
	args.Cursor = urOptionString(options, "--cursor")
	if args.Untrusted, err = urSearchUntrusted(cli, urOptionString(options, "--untrusted")); err != nil {
		return nil, "", err
	}
	verify, err := urSearchChoice("--verify", urOptionString(options, "--verify"), "local", "none", "fetch")
	if err != nil {
		return nil, "", err
	}
	if verify == "fetch" {
		return nil, "", errUrSearchFetch
	}
	if urOptionString(options, "--verify") != "" {
		args.Verify = verify
	}
	if urOptionString(options, "--include") != "" {
		return nil, "", errUrSearchInclude
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

// Runs one search: its pages on one control session, printed in format, exiting as §16.10's exit row says.
func runUrSearchQuery(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params, format, err := urSearchParamsOf(cli, options)
	if err != nil {
		return &urExitError{code: urSearchExitError, err: err}
	}
	explain := urOptionBool(options, "--explain")
	var explainOut io.Writer = cli.stdout
	if format != urSearchFormatText {
		explainOut = cli.stderr
	}
	if explain && params.Query != "" {
		terms, err := sidecar.ExplainSearchQuery(params.Query)
		if err != nil {
			return urSearchError(err)
		}
		urSearchExplainTerms(explainOut, terms)
	}
	client, err := cli.connectDaemon(ctx, cli.hello(sidecar.DaemonModeControl), nil)
	if err != nil {
		return urSearchError(err)
	}
	defer client.Close()
	call := func(params *urSearchParams) (*sidecar.SearchToolResult, time.Duration, error) {
		callCtx, cancel := context.WithTimeout(ctx, cli.settings.CallTimeout)
		defer cancel()
		result := &sidecar.SearchToolResult{}
		start := time.Now()
		err := client.Call(callCtx, sidecar.DaemonMethodSearch, params, false, result)
		return result, time.Since(start), err
	}
	pages := 1
	if format == urSearchFormatJsonl {
		pages = cli.settings.SearchPageCount
	}
	var last *sidecar.SearchToolResult
	hitCount, groupCount := 0, 0
	for page := 1; page <= pages; page += 1 {
		result, elapsed, err := call(params)
		if err != nil {
			return urSearchError(err)
		}
		if explain {
			fmt.Fprintf(explainOut, "page %d: %d hits in %d ms\n", page, len(result.Hits), elapsed.Milliseconds())
		}
		if err := urSearchWrite(cli.stdout, format, result); err != nil {
			return urSearchError(err)
		}
		hitCount, groupCount = hitCount+len(result.Hits), groupCount+len(result.Groups)
		last = result
		if result.Status.Complete || result.Status.NextCursor == "" {
			break
		}
		params.Cursor = result.Status.NextCursor
	}
	if explain {
		urSearchExplainScope(explainOut, last)
	}
	if format == urSearchFormatJsonl {
		if err := urSearchWriteSummary(cli.stdout, last); err != nil {
			return urSearchError(err)
		}
	}
	return urSearchExit(last, hitCount+groupCount)
}

// --explain's terms: each as normalizer 1 reads it, its field and its trigrams.
func urSearchExplainTerms(out io.Writer, terms []*sidecar.SearchTermExplain) {
	for _, term := range terms {
		role := fmt.Sprintf("group %d", term.Group)
		if term.Excluded {
			role = "excluded"
		}
		field := term.Field
		if field == "" {
			field = "every field"
		}
		quoted := make([]string, 0, len(term.Trigrams))
		for _, trigram := range term.Trigrams {
			quoted = append(quoted, strconv.Quote(trigram))
		}
		shape := "substring"
		switch {
		case term.Phrase:
			shape = "phrase"
		case term.WholeWord:
			shape = "whole word"
		}
		fmt.Fprintln(out, urSearchSafe(fmt.Sprintf("term %q (%s, %s, %s) as %q: trigrams %s", term.Text, role, field, shape, term.Normalized, strings.Join(quoted, " "))))
	}
}

// --explain's scope: each repo or ref searched or left out, with its reason, and no hit of one.
func urSearchExplainScope(out io.Writer, result *sidecar.SearchToolResult) {
	if result == nil {
		return
	}
	for _, coverage := range result.Coverage {
		line := "scope " + coverage.RepoId
		if coverage.Network != "" {
			line = "scope " + coverage.Network + " repo " + coverage.RepoId
		}
		if coverage.RefId != "" {
			line += " ref " + coverage.RefId
		}
		line += ": " + coverage.State
		if coverage.State == "searched" {
			line += fmt.Sprintf(", indexed through %d", coverage.IndexedThrough)
			if coverage.LatestFrom != "" {
				line += ", latest from " + coverage.LatestFrom
			}
			if coverage.All != "" {
				line += ", all " + coverage.All
			}
		}
		fmt.Fprintln(out, urSearchSafe(line))
	}
}

// ur search status.
func runUrSearchStatus(ctx context.Context, cli *urCli, options docopt.Opts) error {
	scope, err := urSearchChoice("--scope", urOptionString(options, "--scope"), "network", "repo", "all")
	if err != nil {
		return err
	}
	params := &urSearchStatusParams{Network: urOptionString(options, "--network")}
	params.Repos = urOptionStrings(options, "--repo")
	switch {
	case scope == "all":
		params.Scope = scope
	case scope == "repo" && len(params.Repos) == 0:
		return errors.New("--scope repo names a --repo")
	}
	reply := &sidecar.SearchStatusToolResult{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodSearchStatus, params, false, reply); err != nil {
		return err
	}
	for _, repo := range reply.Repos {
		index := "index off"
		if repo.IndexOn {
			index = "index on"
		}
		format := "format read"
		if !repo.FormatSupported {
			format = "format newer than this build: update"
		}
		line := fmt.Sprintf("%s  %s  %s", repo.RepoId, index, format)
		if repo.Network != "" {
			line = repo.Network + "  " + line
		}
		if repo.Policy != "" {
			line += "  all policy " + repo.Policy
		}
		if repo.LatestFrom != "" {
			line += "  latest from " + repo.LatestFrom
		}
		if repo.AllCachedThrough != "" {
			line += "  all cached through " + repo.AllCachedThrough
		}
		line += fmt.Sprintf("  all %d B cached, %d B missing  %d not yet searchable", repo.AllCachedByteCount, repo.AllMissingByteCount, repo.Uncovered)
		cli.printf("%s\n", urSearchSafe(line))
	}
	if len(reply.Repos) == 0 {
		cli.printf("no repo in scope\n")
	}
	return nil
}

// ur search sync.
func runUrSearchSync(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &sidecar.DaemonSearchSyncParams{
		Network: urOptionString(options, "--network"),
		More:    urOptionBool(options, "--more"), Evict: urOptionBool(options, "--evict"), Policy: urOptionString(options, "--policy"),
	}
	// --repo repeats in ur search's other forms, so docopt gives it as a list here too
	switch repos := urOptionStrings(options, "--repo"); len(repos) {
	case 0:
	case 1:
		params.Repo = repos[0]
	default:
		return errors.New("ur search sync takes one --repo, or none for every repo")
	}
	if params.Policy != "" {
		if _, err := urSearchChoice("--policy", params.Policy, "background", "wifi_charging", "on_demand", "never", "default"); err != nil {
			return err
		}
	}
	reply := &sidecar.DaemonSearchSyncReply{}
	if err := cli.callDaemon(ctx, sidecar.DaemonMethodSearchSync, params, false, reply); err != nil {
		return err
	}
	if reply.Evicted {
		cli.printf("the search cache is dropped; this device's search state stays\n")
	}
	if reply.Policy != "" {
		cli.printf("the all policy is %s\n", reply.Policy)
	}
	cli.printf("synced %d index refs\n", reply.Synced)
	for _, failure := range reply.Failed {
		cli.printf("%s\n", urSearchSafe(fmt.Sprintf("not synced: %s ref %s: %s", failure.RepoId, failure.RefId, failure.Error)))
	}
	if 0 < len(reply.Failed) {
		return fmt.Errorf("%d index refs did not sync", len(reply.Failed))
	}
	return nil
}
