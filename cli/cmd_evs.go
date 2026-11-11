// ur evs (§11.12, §18.5): the command word several areas build. This file registers it and dispatches by its first
// word; each part lives in its own cmd_evs_<part>.go and adds its usage line and its case here. rekey is KEYS-M2-26's
// (cmd_evs_rekey.go), lock and unlock ACL-M10-01's (cmd_evs_lock.go); §11's own parts (ls, log, export, import, delete,
// restore and the rest) are EVS1's and EVS2's.

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
		}, "\n"),
		summary: "a repo's files in evs: rekey rewrites them under the current key generation; lock and unlock its versioning",
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
	}
	return errors.New("ur evs takes rekey, lock or unlock")
}
