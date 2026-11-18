// ur evs (§11.12, §18.5): the command word several areas build. This file registers it and dispatches by its first
// word; each part lives in its own cmd_evs_<part>.go and adds its usage line and its case here. rekey is KEYS-M2-26's
// (cmd_evs_rekey.go), lock and unlock ACL-M10-01's (cmd_evs_lock.go); §11's own parts, ls, log, delete, restore,
// import, export, retry and status, are EVS1-M2-38's (cmd_evs_repo.go), reseed EVSB-M2-20's (evs_reseed.go, the name
// its plan entry gives it), versioning and ls -l EVS2-M10-16's (cmd_evs_versioning.go), rules and repair EVS1-M6-05's
// (cmd_evs_rules.go, cmd_evs_repair.go), lfs window EVS2-M10-28's (cmd_evs_lfs.go), index SEARCH-M10-15's
// (cmd_evs_index.go), and EVS2's add the rest.

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
			"  ur evs ls <repo_id> [-l] [--ref=<ref>]... [<path>...]",
			"  ur evs versioning <repo_id> (on|off) [--ref=<ref>]... <path>...",
			"  ur evs log <repo_id> [--ref=<ref>]... <path>...",
			"  ur evs delete <repo_id>",
			"  ur evs restore <repo_id>",
			"  ur evs import <repo_id> <dir> [<ref>] [--target=<ref>] [--cut=<oid>]... [--force]",
			"  ur evs import <repo_id> <dir> [<ref>] [--target=<ref>] --abandon",
			"  ur evs export <repo_id> <dir> [--ref=<ref>]...",
			"  ur evs retry <repo_id> [--ref=<ref>]...",
			"  ur evs status <repo_id>",
			"  ur evs reseed <repo_id> [--place] [--incident=<id>] [--sign]",
			"  ur evs rules <repo_id> show [--history]",
			"  ur evs rules <repo_id> allow <subject> <path>...",
			"  ur evs rules <repo_id> deny <subject>",
			"  ur evs rules <repo_id> set <file> [--as-written]",
			"  ur evs rules <repo_id> lift",
			"  ur evs repair <repo_id> [<path>]",
			"  ur evs lfs <repo_id> window <days>",
			"  ur evs index <repo_id> (on|off) [--ref=<ref>]...",
			"  ur evs index <repo_id> window <days> [--ref=<ref>]...",
			"  ur evs index <repo_id> (status|rebuild) [--ref=<ref>]... [--companion]",
		}, "\n"),
		summary: "a repo in evs: its files, history, life, imports and exports; rekey; each file's versioning, and its lock; a mount's open work; its re-seed after a site loss; its prefix write rules and their repairs; its git-lfs prune window; its search index's settings, status and rebuild",
		run:     runUrEvs,
	})
}

// Runs the part of ur evs its first word names.
func runUrEvs(ctx context.Context, cli *urCli, options docopt.Opts) error {
	switch {
	// first, since index's patterns share on, off, window and status with other parts
	case urOptionBool(options, "index"):
		return runUrEvsIndex(ctx, cli, options)
	case urOptionBool(options, "rekey"):
		return runUrEvsRekey(ctx, cli, options)
	case urOptionBool(options, "lock"):
		return runUrEvsLock(ctx, cli, options, true)
	case urOptionBool(options, "unlock"):
		return runUrEvsLock(ctx, cli, options, false)
	case urOptionBool(options, "versioning"):
		return runUrEvsVersioning(ctx, cli, options)
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
	case urOptionBool(options, "reseed"):
		return runUrEvsReseed(ctx, cli, options)
	case urOptionBool(options, "rules"):
		return runUrEvsRules(ctx, cli, options)
	case urOptionBool(options, "repair"):
		return runUrEvsRepair(ctx, cli, options)
	case urOptionBool(options, "lfs"):
		return runUrEvsLfs(ctx, cli, options)
	}
	return errors.New("ur evs takes rekey, lock, unlock, ls, versioning, log, delete, restore, import, export, retry, status, reseed, rules, repair, lfs or index")
}
