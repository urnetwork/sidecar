// ur evs index (§11.14's settings, off, status and rebuild rows; R-EVS-21, D-EVS-43, D-QUOTA-10, D-MCP-17;
// SEARCH-M10-15), through the daemon's evs client as ur evs's other parts go (cmd_evs_repo.go):
//
//	ur evs index <repo_id> (on|off) [--ref=<ref>]...          an admin's next settings version on every index root of
//	ur evs index <repo_id> window <days> [--ref=<ref>]...     the repo, main's or each named ref's and ur/index's where
//	                                                          the repo holds it (EvsRepo.IndexSettings); off removes
//	                                                          each root's other files in the same push, or in steps at
//	                                                          the storage limit; window_days 0 means 30, else 7-365
//	ur evs index <repo_id> status [--ref=<ref>]...            each root's state, window, files and bytes apart from
//	                                                          content (EvsRepo.IndexStatus)
//	ur evs index <repo_id> rebuild [--ref=<ref>] [--companion] the root rebuilt whole from the text under the lock
//	                                                          (EvsRepo.IndexRebuild)
//
// on, off, window and rebuild are Confirm methods: the person answers yes on /dev/tty first, and no MCP or hook
// session runs them, so MCP never writes settings or turns the index off (D-MCP-17). A person who is no admin of the
// repo writes nothing, since a version only an admin signed counts. status reads only. Ref names are the person's own
// and go only between ur and its daemon on this device.

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur evs index calls.
const (
	urMethodEvsIndexSettings = "evs.index.settings"
	urMethodEvsIndexStatus   = "evs.index.status"
	urMethodEvsIndexRebuild  = "evs.index.rebuild"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urEvsIndexMethods)
}

// What ur evs index asks: the repo, the refs, and for settings the action and the window.
type urEvsIndexParams struct {
	RepoId     string   `json:"repo_id"`
	Action     string   `json:"action,omitempty"`
	WindowDays uint32   `json:"window_days,omitempty"`
	Refs       []string `json:"refs,omitempty"`
	Companion  bool     `json:"companion,omitempty"`
}

// The refs named, as EvsRepo takes them: nil names main.
func (self *urEvsIndexParams) refNames() [][]byte {
	names := [][]byte{}
	for _, ref := range self.Refs {
		names = append(names, []byte(ref))
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

// A root's name as ur prints it: ur/index, or the ref by its id.
func urEvsIndexRootName(refId sidecar.Id, companion bool, rootNumber uint32) string {
	if companion {
		return fmt.Sprintf("ur/index i%d", rootNumber)
	}
	return fmt.Sprintf("ref %s .ur-index/i%d", refId, rootNumber)
}

// A window as ur prints it.
func urEvsIndexWindow(windowDays uint32) string {
	if windowDays == 0 {
		return "30-day windows"
	}
	return fmt.Sprintf("%d-day windows", windowDays)
}

// What a settings write did, a line a root.
func urEvsIndexSettingsLines(result *sidecar.EvsIndexSettingsResult) []string {
	lines := []string{}
	for _, root := range result.Roots {
		name := urEvsIndexRootName(root.RefId, root.Companion, root.RootNumber)
		state := "on, " + urEvsIndexWindow(root.WindowDays)
		if root.Off {
			state = "off"
		}
		switch {
		case root.Waiting:
			lines = append(lines, fmt.Sprintf("%s: %d file(s) removed; the off version waits until the repo is under its storage limit and its storage cluster has room, run the command again then", name, root.RemovedCount))
		case root.Version == 0 && root.RemovedCount == 0:
			lines = append(lines, fmt.Sprintf("%s: already %s", name, state))
		case root.Off:
			lines = append(lines, fmt.Sprintf("%s: off at settings version %d, %d file(s) removed", name, root.Version, root.RemovedCount))
		default:
			lines = append(lines, fmt.Sprintf("%s: %s at settings version %d", name, state, root.Version))
		}
	}
	if len(lines) == 0 {
		return []string{"the repo holds no index ref to set"}
	}
	return lines
}

// A repo's index status, a line a root and one a content ref's coverage.
func urEvsIndexStatusLines(status *sidecar.EvsIndexStatus) []string {
	lines := []string{}
	for _, root := range status.Roots {
		name := urEvsIndexRootName(root.RefId, root.Companion, root.RootNumber)
		switch root.State {
		case sidecar.EvsIndexStateUpdate:
			lines = append(lines, fmt.Sprintf("%s: in a newer format than this ur reads; update ur to search it", name))
			continue
		case sidecar.EvsIndexStateNone:
			lines = append(lines, fmt.Sprintf("%s: on, %s, not built", name, urEvsIndexWindow(root.WindowDays)))
			continue
		case sidecar.EvsIndexStateOff:
			lines = append(lines, fmt.Sprintf("%s: off, %d file(s), %d B", name, root.FileCount, root.ByteCount))
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: on, %s, %d file(s), %d B of index apart from content, %d bucket(s), %d all shard(s)",
			name, urEvsIndexWindow(root.WindowDays), root.FileCount, root.ByteCount, root.BucketCount, root.AllShardCount))
		if 0 < root.AlarmCount {
			lines = append(lines, fmt.Sprintf("  %d file(s) broke the format and were passed over", root.AlarmCount))
		}
		for _, coverage := range root.Coverage {
			lines = append(lines, fmt.Sprintf("  ref %s: searchable through version %d of %d, %d change(s) not yet searchable",
				coverage.RefId, coverage.IndexedThrough, coverage.Through, coverage.UnindexedCount))
		}
	}
	if len(lines) == 0 {
		return []string{"the repo holds no index ref"}
	}
	return lines
}

// The methods over target, when it hosts a Sidecar: settings and rebuild are Confirm ones.
func urEvsIndexMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	evs, ok := target.(urEvsTarget)
	if !ok {
		return nil
	}
	repoOf := func(call *sidecar.DaemonCall) (*urEvsIndexParams, *sidecar.EvsRepo, error) {
		params := &urEvsIndexParams{}
		if err := decodeUrParams(call, params); err != nil {
			return nil, nil, err
		}
		_, repo, _, err := urEvsRepoOf(evs, &urEvsRepoParams{RepoId: params.RepoId})
		if err != nil {
			return nil, nil, err
		}
		return params, repo, nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name:    urMethodEvsIndexSettings,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, repo, err := repoOf(call)
				if err != nil {
					return nil, err
				}
				result, err := repo.IndexSettings(ctx, &sidecar.EvsIndexSettingsArgs{
					Action: params.Action, WindowDays: params.WindowDays, RefNames: params.refNames(),
				})
				switch {
				case errors.Is(err, sidecar.ErrEvsIndexWaits):
					return &urEvsRepoReply{Lines: urEvsIndexSettingsLines(result)}, nil
				case err != nil:
					return nil, err
				}
				return &urEvsRepoReply{Lines: urEvsIndexSettingsLines(result)}, nil
			},
		},
		{
			Name: urMethodEvsIndexStatus,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, repo, err := repoOf(call)
				if err != nil {
					return nil, err
				}
				status, err := repo.IndexStatus(ctx, &sidecar.EvsIndexStatusArgs{RefNames: params.refNames()})
				if err != nil {
					return nil, err
				}
				return &urEvsRepoReply{Lines: urEvsIndexStatusLines(status)}, nil
			},
		},
		{
			Name:    urMethodEvsIndexRebuild,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params, repo, err := repoOf(call)
				if err != nil {
					return nil, err
				}
				args := &sidecar.EvsIndexRebuildArgs{Companion: params.Companion}
				if names := params.refNames(); 0 < len(names) {
					args.RefName = names[0]
				}
				result, err := repo.IndexRebuild(ctx, args)
				if err != nil {
					return nil, err
				}
				if result.Skipped != "" {
					return &urEvsRepoReply{Lines: []string{fmt.Sprintf("the index is %s: nothing was built", result.Skipped)}}, nil
				}
				return &urEvsRepoReply{Lines: []string{fmt.Sprintf("rebuilt with %d document(s) at ref version %d", result.EntryCount, result.Version)}}, nil
			},
		},
	}
}

// Runs ur evs index: its params from the options; settings and rebuild confirmed on the terminal first.
func runUrEvsIndex(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urEvsIndexParams{RepoId: urOptionString(options, "<repo_id>")}
	if _, err := sidecar.EvsGitRepoOf("id:" + params.RepoId); err != nil {
		return fmt.Errorf("%q is no repo id", params.RepoId)
	}
	// docopt gives an option a list wherever one of the command's patterns repeats it
	switch value := options["--ref"].(type) {
	case string:
		params.Refs = []string{value}
	case []string:
		params.Refs = value
	}
	params.Companion = urOptionBool(options, "--companion")
	method := urMethodEvsIndexSettings
	question := ""
	switch {
	case urOptionBool(options, "status"):
		method = urMethodEvsIndexStatus
	case urOptionBool(options, "rebuild"):
		method = urMethodEvsIndexRebuild
		question = fmt.Sprintf("rebuild %s's index whole from its text, replacing every writer's index files there?", params.RepoId)
	case urOptionBool(options, "on"):
		params.Action = sidecar.EvsIndexOn
		question = fmt.Sprintf("turn %s's search index on, every root of it?", params.RepoId)
	case urOptionBool(options, "off"):
		params.Action = sidecar.EvsIndexOff
		question = fmt.Sprintf("turn %s's search index off, removing its index files (search then scans or matches names only)?", params.RepoId)
	case urOptionBool(options, "window"):
		days, err := strconv.ParseUint(urOptionString(options, "<days>"), 10, 32)
		if err != nil {
			return errors.New("ur evs index window takes a whole number of days: 0 for 30, else 7 to 365")
		}
		params.Action = sidecar.EvsIndexWindow
		params.WindowDays = uint32(days)
		question = fmt.Sprintf("set %s's index windows to %d days, from its next bucket on?", params.RepoId, days)
	default:
		return errors.New("ur evs index takes on, off, window, status or rebuild")
	}
	confirmed := false
	if question != "" {
		answer, err := confirmOnTty(cli, question)
		if err != nil {
			return err
		}
		if !answer {
			cli.printf("nothing changed\n")
			return nil
		}
		confirmed = true
	}
	reply := &urEvsRepoReply{}
	if err := cli.callDaemon(ctx, method, params, confirmed, reply); err != nil {
		return err
	}
	for _, line := range reply.Lines {
		cli.printf("%s\n", line)
	}
	return nil
}
