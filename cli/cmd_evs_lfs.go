// ur evs lfs window (§11.11's prune row; plan-EVS2-lfs-settings, QD-258; EVS2-M10-28), through the daemon's evs client
// as ur evs's other parts go (cmd_evs_repo.go):
//
//	ur evs lfs <repo_id> window <days>   the git-lfs store's settings file at ur/lfs's root takes window_days, 7 to
//	                                     365 (EvsLfsStore.SetWindow): the daily prune then removes an object no tip and
//	                                     no commit of the last <days> days requires, once its newest version is older
//
// Devices count a version of the file only when a repo admin signed it, so a person who is no admin of the repo writes
// a version every device reads as the default, 30 days, alarming. A window under 7 days is refused before anything is
// sent, since the tip check's 5-day freshness rests on it.

package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control method ur evs lfs window calls.
const urMethodEvsLfsWindow = "evs.lfs.window"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urEvsLfsMethods)
}

// What ur evs lfs window asks: the repo and the days.
type urEvsLfsWindowParams struct {
	RepoId string `json:"repo_id"`
	Days   uint32 `json:"days"`
}

// The method over target, when it hosts a Sidecar.
func urEvsLfsMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	evs, ok := target.(urEvsTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name: urMethodEvsLfsWindow,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &urEvsLfsWindowParams{}
			if err := decodeUrParams(call, params); err != nil {
				return nil, err
			}
			_, repo, _, err := urEvsRepoOf(evs, &urEvsRepoParams{RepoId: params.RepoId})
			if err != nil {
				return nil, err
			}
			written, err := sidecar.NewEvsLfsStore(repo).SetWindow(ctx, params.Days)
			if err != nil {
				return nil, err
			}
			return &urEvsRepoReply{Lines: []string{
				fmt.Sprintf("git-lfs prune window %d days, at ref version %d", params.Days, written.Version),
			}}, nil
		},
	}}
}

// Runs ur evs lfs: its window from the options, held to 7 to 365 here too, and the daemon's line printed.
func runUrEvsLfs(ctx context.Context, cli *urCli, options docopt.Opts) error {
	if !urOptionBool(options, "window") {
		return errors.New("ur evs lfs takes window")
	}
	params := &urEvsLfsWindowParams{RepoId: urOptionString(options, "<repo_id>")}
	if _, err := sidecar.EvsGitRepoOf("id:" + params.RepoId); err != nil {
		return fmt.Errorf("%q is no repo id", params.RepoId)
	}
	days, err := strconv.ParseUint(urOptionString(options, "<days>"), 10, 32)
	settings := sidecar.DefaultEvsSettings()
	if err != nil || days < 7 || uint64(settings.LfsWindowMaxDays) < days {
		return fmt.Errorf("a window of 7 to %d days, not %q", settings.LfsWindowMaxDays, urOptionString(options, "<days>"))
	}
	params.Days = uint32(days)
	reply := &urEvsRepoReply{}
	if err := cli.callDaemon(ctx, urMethodEvsLfsWindow, params, false, reply); err != nil {
		return err
	}
	for _, line := range reply.Lines {
		cli.printf("%s\n", line)
	}
	return nil
}
