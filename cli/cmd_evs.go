// ur evs (§11.12, §18.5): the command word several areas build. This file registers it and dispatches by its first
// word; each part lives in its own cmd_evs_<part>.go and adds its usage line and its case here. rekey is KEYS-M2-26's
// (cmd_evs_rekey.go), lock and unlock ACL-M10-01's (cmd_evs_lock.go); §11's own parts, ls, log, delete, restore,
// import, export, retry and status, are EVS1-M2-38's (cmd_evs_repo.go), and EVS2's add the rest.

package main

import (
	"context"
	"errors"
	"strings"

	"github.com/docopt/docopt-go"
)

func init() {
	registerUrCommand(&urCommand{
		name: "evs",
		usage: strings.Join([]string{
			"  ur evs rekey <repo_id> [--ref=<ref>]... [<path>...]",
			"  ur evs rekey <repo_id> --status",
			"  ur evs lock <repo_id>",
			"  ur evs unlock <repo_id>",
			"  ur evs ls <repo_id> [--ref=<ref>]... [<path>...]",
			"  ur evs log <repo_id> [--ref=<ref>]... <path>...",
			"  ur evs delete <repo_id>",
			"  ur evs restore <repo_id>",
			"  ur evs import <repo_id> <dir> [<ref>] [--target=<ref>] [--cut=<oid>]... [--force]",
			"  ur evs import <repo_id> <dir> [<ref>] [--target=<ref>] --abandon",
			"  ur evs export <repo_id> <dir> [--ref=<ref>]...",
			"  ur evs retry <repo_id> [--ref=<ref>]...",
			"  ur evs status <repo_id>",
		}, "\n"),
		summary: "a repo in evs: its files, history, life, imports and exports; rekey; lock and unlock its versioning; a mount's open work",
		run:     runUrEvs,
	})
}

// Runs the part of ur evs its first word names.
func runUrEvs(ctx context.Context, cli *urCli, options docopt.Opts) error {
	switch {
	case urOptionBool(options, "rekey"):
		return runUrEvsRekey(ctx, cli, options)
	case urOptionBool(options, "lock"):
		return runUrEvsLock(ctx, cli, options, true)
	case urOptionBool(options, "unlock"):
		return runUrEvsLock(ctx, cli, options, false)
	case urOptionBool(options, "ls"):
		return runUrEvsRepo(ctx, cli, options, urMethodEvsLs)
	case urOptionBool(options, "log"):
		return runUrEvsRepo(ctx, cli, options, urMethodEvsLog)
	case urOptionBool(options, "delete"):
		return runUrEvsRepo(ctx, cli, options, urMethodEvsDelete)
	case urOptionBool(options, "restore"):
		return runUrEvsRepo(ctx, cli, options, urMethodEvsRestore)
	case urOptionBool(options, "import"):
		return runUrEvsRepo(ctx, cli, options, urMethodEvsImport)
	case urOptionBool(options, "export"):
		return runUrEvsRepo(ctx, cli, options, urMethodEvsExport)
	case urOptionBool(options, "retry"):
		return runUrEvsRepo(ctx, cli, options, urMethodEvsRetry)
	case urOptionBool(options, "status"):
		return runUrEvsRepo(ctx, cli, options, urMethodEvsStatus)
	}
	return errors.New("ur evs takes rekey, lock, unlock, ls, log, delete, restore, import, export, retry or status")
}
