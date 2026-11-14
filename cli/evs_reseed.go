// ur evs reseed (EVSB-M2-20; §11.13's re-seed row, §19.10's repos step; QD-725): after a site loss, while the operator
// runs evs with reseed on, a repo admin sends this device's mirror of a repo back to evs, as its devices signed it and
// never re-signed (sidecar.EvsRepo.Reseed): the ERASEs first, each ref's history in version order, the slots last.
//
//	ur evs reseed <repo_id> [--incident=<id>] [--sign]
//
// --sign also signs and files an EvsReseed over each ref's returned head, naming the recovery by --incident: the
// admin's statement that the history evs now serves is all that survived, under which a device pinned above it accepts
// the shorter history as a loss. It is a statement in the admin's name, so the command asks on the terminal first and
// its method is a Confirm one, never run through MCP.
//
// What it prints is counts and opaque ids: each ref's version returned of the versions mirrored, why a ref stopped,
// the segments sent and the slots taken, and each slot evs did not take.

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control method ur evs reseed calls.
const urMethodEvsReseed = "evs.reseed"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urEvsReseedMethods)
}

// What the reseed method acts on: a target hosting a Sidecar with an evs client and its mirrors.
type urEvsReseedTarget interface {
	reseedRepo(ctx context.Context, repoId sidecar.Id, args *sidecar.EvsReseedArgs) (*sidecar.EvsReseedResult, error)
}

// The only hosted network's re-seed of the repo from this device's mirror.
func (self *urDaemonNetwork) reseedRepo(ctx context.Context, repoId sidecar.Id, args *sidecar.EvsReseedArgs) (*sidecar.EvsReseedResult, error) {
	client, err := self.evsClient()
	if err != nil {
		return nil, err
	}
	return client.Repo(repoId).Reseed(ctx, args)
}

// evs.reseed's params.
type urEvsReseedParams struct {
	RepoId   string `json:"repo_id"`
	Incident string `json:"incident,omitempty"`
	Sign     bool   `json:"sign,omitempty"`
}

// evs.reseed's answer: what ur prints, a line each, and whether everything the mirror holds went.
type urEvsReseedReply struct {
	Lines []string `json:"lines"`
	Whole bool     `json:"whole"`
}

// A re-seed's result as lines.
func urEvsReseedLines(repoId sidecar.Id, result *sidecar.EvsReseedResult) []string {
	lines := []string{fmt.Sprintf("repo %s: %d refs, %d segments sent, %d slots taken", repoId, len(result.Refs), result.SegmentCount, result.SlotCount)}
	for _, ref := range result.Refs {
		line := fmt.Sprintf("  ref %s: version %d of %d", ref.RefId, ref.Version, ref.MirrorVersion)
		if ref.Stopped != nil {
			line += fmt.Sprintf(", stopped: %v", ref.Stopped)
		}
		switch {
		case ref.Filed:
			line += ", EvsReseed filed"
		case ref.FileError != nil:
			line += fmt.Sprintf(", EvsReseed not filed: %v", ref.FileError)
		}
		lines = append(lines, line)
	}
	for _, slot := range result.Slots {
		if slot.Refused == nil {
			lines = append(lines, fmt.Sprintf("  slot %s: not sent, no returned version names it", slot.SlotId))
			continue
		}
		lines = append(lines, fmt.Sprintf("  slot %s: not taken: %v", slot.SlotId, slot.Refused))
	}
	if !result.Whole() {
		lines = append(lines, "the re-seed is partial; run it again once what stopped it is mended")
	}
	return lines
}

// The reseed method over target, when it hosts a Sidecar: a Confirm one, since it writes to evs in the admin's name.
func urEvsReseedMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	reseeds, ok := target.(urEvsReseedTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name:    urMethodEvsReseed,
		Confirm: true,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &urEvsReseedParams{}
			if err := decodeUrParams(call, params); err != nil {
				return nil, err
			}
			repoId, err := sidecar.ParseId(params.RepoId)
			if err != nil {
				return nil, errors.New("no repo id")
			}
			if params.Sign && params.Incident == "" {
				return nil, errors.New("an EvsReseed names its recovery: no incident")
			}
			result, err := reseeds.reseedRepo(ctx, repoId, &sidecar.EvsReseedArgs{IncidentId: []byte(params.Incident), SignReseed: params.Sign})
			if result == nil {
				return nil, err
			}
			reply := &urEvsReseedReply{Lines: urEvsReseedLines(repoId, result), Whole: err == nil && result.Whole()}
			if err != nil {
				// what went before the walk ended is still what evs now holds
				reply.Lines = append(reply.Lines, fmt.Sprintf("the re-seed ended early: %v", err))
			}
			return reply, nil
		},
	}}
}

// ur evs reseed: the repo, a yes on the terminal, then the walk.
func runUrEvsReseed(ctx context.Context, cli *urCli, options docopt.Opts) error {
	repoId, err := sidecar.ParseId(urOptionString(options, "<repo_id>"))
	if err != nil {
		return fmt.Errorf("not a repo id: %w", err)
	}
	params := &urEvsReseedParams{RepoId: repoId.String(), Incident: urOptionString(options, "--incident"), Sign: urOptionBool(options, "--sign")}
	if params.Sign && params.Incident == "" {
		return errors.New("--sign needs --incident, the recovery the EvsReseed names")
	}
	question := fmt.Sprintf("send this device's mirror of %s back to evs?", repoId)
	if params.Sign {
		question = fmt.Sprintf("send this device's mirror of %s back to evs, and sign that what returns is all that survived incident %s?", repoId, params.Incident)
	}
	confirmed, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing sent\n")
		return nil
	}
	reply := &urEvsReseedReply{}
	if err := cli.callDaemon(ctx, urMethodEvsReseed, params, true, reply); err != nil {
		return err
	}
	for _, line := range reply.Lines {
		cli.printf("%s\n", line)
	}
	if !reply.Whole {
		return errors.New("the re-seed is partial")
	}
	return nil
}
