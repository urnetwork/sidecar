// ur evs repair (EVS1-M6-05; DESIGN-DETAILS 16.2.8's by-hand row): the repairs this device's mirrors journalled for a
// repo, or one path's, sent at once, without the delay, RepairDepth and the hourly and daily bounds, on a device that
// repairs and is allowed the paths (EvsClient.RepairPrefix, ByHand). A path its rules do not give this device stays in
// the journal, as does one another write moved, and `ur status` keeps listing it. Each repair is an ordinary push of
// the effective state, signed by this device, so the command is not confirmed, as no other write of a file is.
//
//	ur evs repair <repo_id> [<path>]
//
// The path is the person's own and goes only between ur and its daemon on this device (I-13).

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control method ur evs repair calls.
const urMethodEvsRepair = "evs.repair"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urEvsRepairMethods)
}

type urEvsRepairParams struct {
	RepoId string `json:"repo_id"`
	Path   string `json:"path,omitempty"`
}

// What a pass did, a line.
func urEvsRepairLines(result *sidecar.EvsPrefixRepairResult) []string {
	lines := []string{fmt.Sprintf("%d repair push(es), %d bytes; %d journal unit(s) settled", result.PushCount, result.ByteCount, result.SettledCount)}
	if 0 < result.WaitingCount {
		lines = append(lines, fmt.Sprintf("%d unit(s) still wait: refused to this device, moved by another write, or of a kind no repair writes yet; ur status lists them", result.WaitingCount))
	}
	return lines
}

// The repair method over target, when it hosts a Sidecar.
func urEvsRepairMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	evs, ok := target.(urEvsTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name: urMethodEvsRepair,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &urEvsRepairParams{}
			if err := decodeUrParams(call, params); err != nil {
				return nil, err
			}
			client, _, repoId, err := urEvsRepoOf(evs, &urEvsRepoParams{RepoId: params.RepoId})
			if err != nil {
				return nil, err
			}
			result, err := client.RepairPrefix(ctx, &sidecar.EvsPrefixRepairArgs{RepoId: repoId, Path: params.Path, ByHand: true})
			if errors.Is(err, sidecar.ErrEvsPrefixRepairOff) {
				return nil, errors.New("this device runs no prefix repair: only a desktop or the daemon that mirrors the repo repairs")
			}
			if err != nil {
				return nil, err
			}
			return &urEvsRepoReply{Lines: urEvsRepairLines(result)}, nil
		},
	}}
}

// Runs ur evs repair: its params from the options, and each line of the daemon's answer printed.
func runUrEvsRepair(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urEvsRepairParams{RepoId: urOptionString(options, "<repo_id>")}
	if _, err := sidecar.ParseId(params.RepoId); err != nil {
		return fmt.Errorf("%q is no repo id", params.RepoId)
	}
	switch paths := urOptionStrings(options, "<path>"); {
	case 1 < len(paths):
		return errors.New("ur evs repair takes one path at most")
	case len(paths) == 1:
		params.Path = paths[0]
	}
	reply := &urEvsRepoReply{}
	if err := cli.callDaemon(ctx, urMethodEvsRepair, params, false, reply); err != nil {
		return err
	}
	for _, line := range reply.Lines {
		cli.printf("%s\n", line)
	}
	return nil
}
