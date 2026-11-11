// ur evs's §11 parts (§11.12, §18.5; EVS1-M2-38): a repo's files and life through the daemon's evs client, each a
// control method over the only hosted network's client (urEvsTarget):
//
//	ur evs ls <repo_id> [--ref=<ref>] [<path>]                a directory's children, verified
//	ur evs log <repo_id> [--ref=<ref>] <path>                 a path's versions, newest first
//	ur evs delete <repo_id>                                   §8.8's RepoDelete filed, then DELETE, after a yes on the
//	                                                          terminal (§5.8)
//	ur evs restore <repo_id>                                  RepoRestore filed, then POST .../restore, after a yes
//	ur evs import <repo_id> <dir> [<ref>] [--target=<ref>] [--cut=<oid>]... [--force] [--abandon]
//	                                                          history by others into a ref (DESIGN-DETAILS 8.2.6):
//	                                                          --cut ends a push at a commit, --force lets the first
//	                                                          push leave an owned target's line, --abandon ends an
//	                                                          unfinished import, deleting its helper refs
//	ur evs export <repo_id> <dir> [--ref=<ref>]...            plain git rebuilt, with git's own oids
//	ur evs retry <repo_id> [--ref=<ref>]                      an owned ref's held queue released (DESIGN-DETAILS 8.2.8)
//	ur evs status <repo_id>                                   the mount's open work: unfinished imports and leftover
//	                                                          helper refs, conflict branches, refs stopped at a refused
//	                                                          version or waiting on a source, pending outcomes, holds
//
// Delete and restore are Confirm methods, so nothing but a control call a person confirmed reaches them. Paths and ref
// names are the person's own and go only between ur and its daemon on this device.

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The control methods these parts call.
const (
	urMethodEvsLs      = "evs.ls"
	urMethodEvsLog     = "evs.log"
	urMethodEvsDelete  = "evs.delete"
	urMethodEvsRestore = "evs.restore"
	urMethodEvsImport  = "evs.import"
	urMethodEvsExport  = "evs.export"
	urMethodEvsRetry   = "evs.retry"
	urMethodEvsStatus  = "evs.status"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urEvsRepoMethods)
}

// The params every part takes: the repo, a ref's name, and the part's own.
type urEvsRepoParams struct {
	RepoId  string   `json:"repo_id"`
	Ref     string   `json:"ref,omitempty"`
	Path    string   `json:"path,omitempty"`
	Dir     string   `json:"dir,omitempty"`
	Refs    []string `json:"refs,omitempty"`
	Target  string   `json:"target,omitempty"`
	Cuts    []string `json:"cuts,omitempty"`
	Force   bool     `json:"force,omitempty"`
	Abandon bool     `json:"abandon,omitempty"`
}

// One row of a part's answer: what ur prints, a line each.
type urEvsRepoReply struct {
	Lines []string `json:"lines"`
}

// The repo the params name, on the only hosted network's client.
func urEvsRepoOf(evs urEvsTarget, params *urEvsRepoParams) (*sidecar.EvsClient, *sidecar.EvsRepo, sidecar.Id, error) {
	repoId, err := sidecar.EvsGitRepoOf("id:" + params.RepoId)
	if err != nil {
		return nil, nil, sidecar.Id{}, errors.New("no repo id")
	}
	client, err := evs.evsClient()
	if err != nil {
		return nil, nil, sidecar.Id{}, err
	}
	return client, client.Repo(repoId), repoId, nil
}

// The ref name a part names, nil for main.
func urEvsRefName(ref string) []byte {
	if ref == "" {
		return nil
	}
	return []byte(ref)
}

// The parts' methods over target, when it hosts a Sidecar.
func urEvsRepoMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	evs, ok := target.(urEvsTarget)
	if !ok {
		return nil
	}
	method := func(name string, confirm bool, run func(ctx context.Context, params *urEvsRepoParams) ([]string, error)) *sidecar.DaemonMethod {
		return &sidecar.DaemonMethod{
			Name:    name,
			Confirm: confirm,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urEvsRepoParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				lines, err := run(ctx, params)
				if err != nil {
					return nil, err
				}
				return &urEvsRepoReply{Lines: lines}, nil
			},
		}
	}
	return []*sidecar.DaemonMethod{
		method(urMethodEvsLs, false, func(ctx context.Context, params *urEvsRepoParams) ([]string, error) {
			_, repo, _, err := urEvsRepoOf(evs, params)
			if err != nil {
				return nil, err
			}
			listing, err := repo.List(ctx, &sidecar.EvsReadArgs{RefName: urEvsRefName(params.Ref), Path: params.Path})
			if err != nil {
				return nil, err
			}
			lines := []string{fmt.Sprintf("%s at version %d", listingPath(listing.Path), listing.HeadVersion)}
			for _, entry := range listing.Entries {
				suffix := ""
				if entry.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
					suffix = "/"
				}
				lines = append(lines, "  "+string(entry.Name)+suffix)
			}
			return lines, nil
		}),
		method(urMethodEvsLog, false, func(ctx context.Context, params *urEvsRepoParams) ([]string, error) {
			_, repo, _, err := urEvsRepoOf(evs, params)
			if err != nil {
				return nil, err
			}
			history, err := repo.History(ctx, &sidecar.EvsReadArgs{RefName: urEvsRefName(params.Ref), Path: params.Path})
			if err != nil {
				return nil, err
			}
			lines := []string{}
			for _, version := range history.Versions {
				what := version.State
				if version.Removed {
					what = "removed"
				}
				lines = append(lines, fmt.Sprintf("version %d at ref version %d by sidecar %s, %s, %s", version.Version,
					version.CommitVersion, version.SignerSidecarId, version.Time.UTC().Format("2006-01-02 15:04:05Z"), what))
			}
			return lines, nil
		}),
		method(urMethodEvsDelete, true, func(ctx context.Context, params *urEvsRepoParams) ([]string, error) {
			_, repo, repoId, err := urEvsRepoOf(evs, params)
			if err != nil {
				return nil, err
			}
			if err := repo.Delete(ctx, false); err != nil {
				return nil, err
			}
			return []string{fmt.Sprintf("repo %s is deleted; ur evs restore %s brings it back while evs keeps it", repoId, repoId)}, nil
		}),
		method(urMethodEvsRestore, true, func(ctx context.Context, params *urEvsRepoParams) ([]string, error) {
			_, repo, repoId, err := urEvsRepoOf(evs, params)
			if err != nil {
				return nil, err
			}
			if err := repo.Restore(ctx); err != nil {
				return nil, err
			}
			return []string{fmt.Sprintf("repo %s is restored", repoId)}, nil
		}),
		method(urMethodEvsImport, false, func(ctx context.Context, params *urEvsRepoParams) ([]string, error) {
			_, repo, _, err := urEvsRepoOf(evs, params)
			if err != nil {
				return nil, err
			}
			args := &sidecar.EvsImportArgs{Dir: params.Dir, Ref: params.Ref, Target: urEvsRefName(params.Target), Force: params.Force, Abandon: params.Abandon}
			for _, cut := range params.Cuts {
				decoded, err := hex.DecodeString(cut)
				if err != nil || len(decoded) != len(sidecar.EvsGitOid{}) {
					return nil, fmt.Errorf("a cut is a commit's 40 hex digits")
				}
				args.Cuts = append(args.Cuts, sidecar.EvsGitOid(decoded))
			}
			result, err := repo.Import(ctx, args)
			if err != nil {
				return nil, err
			}
			if params.Abandon {
				return []string{fmt.Sprintf("import %s abandoned: its helper refs are deleted and its target stays where it is", result.ImportId)}, nil
			}
			lines := []string{fmt.Sprintf("import %s: %d push(es), the target at %s", result.ImportId, len(result.PushIds), result.Tip)}
			for _, helper := range result.Helpers {
				lines = append(lines, "  went through helper ref "+string(helper)+", deleted at its end")
			}
			return lines, nil
		}),
		method(urMethodEvsExport, false, func(ctx context.Context, params *urEvsRepoParams) ([]string, error) {
			_, repo, _, err := urEvsRepoOf(evs, params)
			if err != nil {
				return nil, err
			}
			args := &sidecar.EvsExportArgs{Dir: params.Dir}
			for _, ref := range params.Refs {
				args.RefNames = append(args.RefNames, []byte(ref))
			}
			result, err := repo.Export(ctx, args)
			if err != nil {
				return nil, err
			}
			lines := []string{}
			for _, ref := range result.Refs {
				lines = append(lines, fmt.Sprintf("%s at %s, %d version(s)", ref.GitRef, ref.Tip, ref.Versions))
				for _, refusal := range ref.Refused {
					lines = append(lines, fmt.Sprintf("  version %d refused: %s", refusal.Version, refusal.Reason))
				}
			}
			return lines, nil
		}),
		method(urMethodEvsRetry, false, func(ctx context.Context, params *urEvsRepoParams) ([]string, error) {
			mount, err := urEvsMountOf(evs, params)
			if err != nil {
				return nil, err
			}
			released, err := mount.Receiver().Retry(ctx, urEvsRefName(params.Ref))
			if err != nil {
				return nil, err
			}
			lines := []string{}
			for _, name := range released {
				lines = append(lines, "released "+string(name)+": its queue pushes again")
			}
			if len(lines) == 0 {
				lines = append(lines, "no queue is held")
			}
			return lines, nil
		}),
		method(urMethodEvsStatus, false, func(ctx context.Context, params *urEvsRepoParams) ([]string, error) {
			mount, err := urEvsMountOf(evs, params)
			if err != nil {
				return nil, err
			}
			return urEvsMountStatus(ctx, evs, mount)
		}),
	}
}

// The mounted repo the params name.
func urEvsMountOf(evs urEvsTarget, params *urEvsRepoParams) (*sidecar.EvsLocalRepo, error) {
	client, _, repoId, err := urEvsRepoOf(evs, params)
	if err != nil {
		return nil, err
	}
	mounts, err := client.Mounts()
	if err != nil {
		return nil, err
	}
	mount, ok := mounts.Get(repoId)
	if !ok {
		return nil, fmt.Errorf("repo %s is not mounted here", repoId)
	}
	return mount, nil
}

// The mount's open work, a line each (DESIGN-DETAILS 8.2.6, 8.2.7, 8.2.8, 8.5).
func urEvsMountStatus(ctx context.Context, evs urEvsTarget, mount *sidecar.EvsLocalRepo) ([]string, error) {
	client, err := evs.evsClient()
	if err != nil {
		return nil, err
	}
	mounts, err := client.Mounts()
	if err != nil {
		return nil, err
	}
	lines := []string{}
	imports, err := mounts.ImportStatus(ctx, mount.RepoId)
	if err != nil {
		return nil, err
	}
	for _, unfinished := range imports.Unfinished {
		reached := "nothing yet"
		if unfinished.Reached != nil {
			reached = unfinished.Reached.String()
		}
		lines = append(lines, fmt.Sprintf("unfinished import %s into %s, at %s", unfinished.ImportId, unfinished.Target, reached))
		for _, helper := range unfinished.Helpers {
			lines = append(lines, "  helper ref "+string(helper))
		}
	}
	for _, leftover := range imports.Leftover {
		lines = append(lines, "leftover helper ref "+string(leftover)+": no import names it, git push --delete removes it")
	}
	branches, err := mount.Sync().ConflictBranches(ctx)
	if err != nil {
		return nil, err
	}
	for _, branch := range branches {
		lines = append(lines, "conflict branch "+string(branch))
	}
	refs, err := mount.Sync().GitRefs()
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		name := string(ref.Name)
		if name == "" {
			name = ref.RefId.String()
		}
		switch {
		case ref.StuckAt != 0:
			lines = append(lines, fmt.Sprintf("ref %s refused at version %d: it takes only a deletion", name, ref.StuckAt))
		case ref.WaitingSource != nil:
			lines = append(lines, fmt.Sprintf("ref %s waiting_source %s at version %d", name, ref.WaitingSource, ref.WaitingVersion))
		case ref.SettleStopped:
			lines = append(lines, fmt.Sprintf("ref %s stops settling: its conflict branches are at the bound", name))
		}
	}
	journals, err := mount.Receiver().JournalStatus()
	if err != nil {
		return nil, err
	}
	for _, journal := range journals {
		switch {
		case journal.HoldCode != "":
			lines = append(lines, fmt.Sprintf("ref %s held: %s; ur evs retry releases it", journal.RefName, journal.HoldCode))
		case journal.Pending:
			lines = append(lines, fmt.Sprintf("ref %s: remote outcome pending", journal.RefName))
		case 0 < journal.Queued:
			lines = append(lines, fmt.Sprintf("ref %s: %d update(s) queued", journal.RefName, journal.Queued))
		}
	}
	if len(lines) == 0 {
		lines = append(lines, "nothing open")
	}
	return lines, nil
}

// A listing's path as ur prints it.
func listingPath(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

// Runs one of the parts: its params from the options, a yes on the terminal for delete and restore, and each line of
// its answer printed.
func runUrEvsRepo(ctx context.Context, cli *urCli, options docopt.Opts, part string) error {
	params := &urEvsRepoParams{RepoId: urOptionString(options, "<repo_id>")}
	if _, err := sidecar.EvsGitRepoOf("id:" + params.RepoId); err != nil {
		return fmt.Errorf("%q is no repo id", params.RepoId)
	}
	// docopt gives an option a list wherever one of the command's patterns repeats it
	strings := func(key string) []string {
		switch value := options[key].(type) {
		case string:
			return []string{value}
		case []string:
			return value
		}
		return nil
	}
	first := func(key string) string {
		if values := strings(key); 0 < len(values) {
			return values[0]
		}
		return ""
	}
	params.Refs = strings("--ref")
	params.Ref = first("--ref")
	params.Path = first("<path>")
	params.Dir = first("<dir>")
	params.Target = first("--target")
	params.Cuts = strings("--cut")
	params.Force = urOptionBool(options, "--force")
	params.Abandon = urOptionBool(options, "--abandon")
	if part == urMethodEvsImport {
		params.Ref = first("<ref>")
	}
	confirmed := false
	switch part {
	case urMethodEvsDelete, urMethodEvsRestore:
		question := fmt.Sprintf("delete repo %s for every member?", params.RepoId)
		if part == urMethodEvsRestore {
			question = fmt.Sprintf("restore repo %s?", params.RepoId)
		}
		yes, err := confirmOnTty(cli, question)
		if err != nil {
			return err
		}
		if !yes {
			cli.printf("nothing changed\n")
			return nil
		}
		confirmed = true
	}
	reply := &urEvsRepoReply{}
	if err := cli.callDaemon(ctx, part, params, confirmed, reply); err != nil {
		return err
	}
	for _, line := range reply.Lines {
		cli.printf("%s\n", line)
	}
	return nil
}
