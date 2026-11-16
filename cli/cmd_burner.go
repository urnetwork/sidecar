// ur burner (§15.9, R-MAIL-6, R-MAIL-7; MAIL-M8-01): the network's burners, thin over the daemon's MailClient.
//
//	ur burner create <site> [--network=<net>]    a burner for site, <name>@<blabel>.<net>.<root>, with a vault entry
//	ur burner ls [--network=<net>]               this member's burners, burned and paused ones included
//	ur burner burn <burner> [--network=<net>]    burns a burner, by its address or label, confirmed on the terminal:
//	                                             receivers refuse its mail from then on and the label is never reused
//	ur burner pause <burner> [--network=<net>]   receivers refuse its mail until resume
//	ur burner resume <burner> [--network=<net>]
//
// Creating a burner is an outward action (I-8): it goes through §5.4's gate, and while a person's decision is awaited
// the command prints ur approve <id> for another approval-capable device and exits 1, as ur id does. Before this
// member's first burner it prints §15.9's foreground-only copy while coverage is foreground-only or none, and never
// refuses for coverage (owner decision 12). Burn and pause are local and need no approval (owner decision 32); burn is
// for good, so it asks first. These spellings are proposals until cli/UI.md exists (plan-CORE-cli-ui-missing). An
// address is printed to the person's own terminal and logged nowhere (I-13).

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The control methods ur burner calls.
const (
	urMethodBurnerCreate = "burner.create"
	urMethodBurnerList   = "burner.ls"
	urMethodBurnerBurn   = "burner.burn"
	urMethodBurnerPause  = "burner.pause"
)

func init() {
	registerUrCommand(&urCommand{
		name: "burner",
		usage: "  ur burner create <site> [--network=<net>]\n" +
			"  ur burner ls [--network=<net>]\n" +
			"  ur burner burn <burner> [--network=<net>]\n" +
			"  ur burner pause <burner> [--network=<net>]\n" +
			"  ur burner resume <burner> [--network=<net>]",
		summary: "create, list, burn and pause the network's burner addresses",
		run:     runUrBurner,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urBurnerMethods)
}

// The daemon's MailClient as the burner methods use it: *sidecar.MailClient is one.
type urBurnerClient interface {
	CreateBurner(ctx context.Context, args *sidecar.MailBurnerCreateArgs) (*sidecar.MailBurnerCreated, error)
	Burn(ctx context.Context, addressOrLabel string) error
	PauseBurner(ctx context.Context, addressOrLabel string, paused bool) error
	Burners(ctx context.Context) ([]*sidecar.MailBurnerInfo, error)
}

// A burner method's params.
type urBurnerParams struct {
	Network string `json:"network,omitempty"`
	// create's site, or the burner's address or label.
	Site   string `json:"site,omitempty"`
	Burner string `json:"burner,omitempty"`
	Paused bool   `json:"paused,omitempty"`
}

// burner.create's, burn's and pause's reply: the burner, or the approval its creation waits on.
type urBurnerReply struct {
	Address      string      `json:"address,omitempty"`
	CoverageCopy string      `json:"coverage_copy,omitempty"`
	ApprovalId   *sidecar.Id `json:"approval_id,omitempty"`
	// The burner was made but its vault entry was not: running create again for the same site completes it.
	NoVaultEntry bool `json:"no_vault_entry,omitempty"`
}

// One burner as burner.ls lists it.
type urBurnerItem struct {
	Label     string `json:"label"`
	State     string `json:"state"`
	Replying  bool   `json:"replying,omitempty"`
	CreatedMs int64  `json:"created_ms"`
}

// burner.ls's reply.
type urBurnerListReply struct {
	Burners []*urBurnerItem `json:"burners"`
}

// The state's word.
func urBurnerState(state protocol.MailBurnerState) string {
	switch state {
	case protocol.MailBurnerState_MAIL_BURNER_LIVE:
		return "live"
	case protocol.MailBurnerState_MAIL_BURNER_PAUSED:
		return "paused"
	case protocol.MailBurnerState_MAIL_BURNER_BURNED:
		return "burned"
	}
	return "unknown"
}

// The burner methods over target, when it hosts Sidecars that run mail. burn is a Confirm method: only a control call
// a person confirmed on the terminal runs it.
func urBurnerMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	mail, ok := target.(urMailTarget)
	if !ok {
		return nil
	}
	client := func(call *sidecar.DaemonCall) (urBurnerClient, *urBurnerParams, error) {
		params := &urBurnerParams{}
		if err := decodeUrParams(call, params); err != nil {
			return nil, nil, err
		}
		mailClient, err := mail.mailClient(params.Network)
		if err != nil {
			return nil, nil, err
		}
		burners, ok := mailClient.(urBurnerClient)
		if !ok {
			return nil, nil, errors.New("this daemon's mail makes no burners")
		}
		return burners, params, nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodBurnerCreate,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				burners, params, err := client(call)
				if err != nil {
					return nil, err
				}
				created, err := burners.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: params.Site})
				var pending *sidecar.ApprovalPendingError
				switch {
				case errors.As(err, &pending):
					approvalId := pending.ApprovalId
					return &urBurnerReply{ApprovalId: &approvalId}, nil
				case errors.Is(err, sidecar.ErrMailBurnerNoVaultEntry) && created != nil:
					return &urBurnerReply{Address: created.Address, CoverageCopy: created.CoverageCopy, NoVaultEntry: true}, nil
				case err != nil:
					return nil, err
				}
				return &urBurnerReply{Address: created.Address, CoverageCopy: created.CoverageCopy}, nil
			},
		},
		{
			Name: urMethodBurnerList,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				burners, _, err := client(call)
				if err != nil {
					return nil, err
				}
				infos, err := burners.Burners(ctx)
				if err != nil {
					return nil, err
				}
				reply := &urBurnerListReply{Burners: []*urBurnerItem{}}
				for _, info := range infos {
					reply.Burners = append(reply.Burners, &urBurnerItem{
						Label: info.Label, State: urBurnerState(info.State), Replying: info.Replying, CreatedMs: int64(info.CreatedMillis),
					})
				}
				return reply, nil
			},
		},
		{
			Name:    urMethodBurnerBurn,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				burners, params, err := client(call)
				if err != nil {
					return nil, err
				}
				if err := burners.Burn(ctx, params.Burner); err != nil {
					return nil, err
				}
				return &urBurnerReply{}, nil
			},
		},
		{
			Name: urMethodBurnerPause,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				burners, params, err := client(call)
				if err != nil {
					return nil, err
				}
				if err := burners.PauseBurner(ctx, params.Burner, params.Paused); err != nil {
					return nil, err
				}
				return &urBurnerReply{}, nil
			},
		},
	}
}

func runUrBurner(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urBurnerParams{Network: urOptionString(options, "--network")}
	switch {
	case options["create"] == true:
		params.Site = urOptionString(options, "<site>")
		reply := &urBurnerReply{}
		if err := cli.callDaemon(ctx, urMethodBurnerCreate, params, false, reply); err != nil {
			return err
		}
		if reply.ApprovalId != nil {
			cli.printf("approval pending: run ur approve %s on another approval-capable device, then run this command again\n", reply.ApprovalId)
			return &urExitError{code: urExitFailed, err: errors.New("the burner waits on that approval")}
		}
		cli.printf("%s\n", reply.Address)
		if reply.CoverageCopy != "" {
			cli.printf("note: %s\n", reply.CoverageCopy)
		}
		if reply.NoVaultEntry {
			cli.printf("the burner's vault entry was not written: run this command again to write it\n")
			return &urExitError{code: urExitFailed, err: errors.New("no vault entry")}
		}
		return nil
	case options["ls"] == true:
		reply := &urBurnerListReply{}
		if err := cli.callDaemon(ctx, urMethodBurnerList, params, false, reply); err != nil {
			return err
		}
		for _, burner := range reply.Burners {
			replying := ""
			if burner.Replying {
				replying = "  replying"
			}
			cli.printf("%-7s %s  %s%s\n", burner.State, burner.Label, time.UnixMilli(burner.CreatedMs).UTC().Format(time.DateOnly), replying)
		}
		return nil
	case options["burn"] == true:
		params.Burner = urOptionString(options, "<burner>")
		confirmed, err := confirmOnTty(cli, fmt.Sprintf("burn %s for good? its mail is refused from now on and its label is never reused", params.Burner))
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing changed\n")
			return nil
		}
		if err := cli.callDaemon(ctx, urMethodBurnerBurn, params, true, &urBurnerReply{}); err != nil {
			return err
		}
		cli.printf("burned: its mail is refused from now on\n")
		return nil
	case options["pause"] == true, options["resume"] == true:
		params.Burner = urOptionString(options, "<burner>")
		params.Paused = options["pause"] == true
		if err := cli.callDaemon(ctx, urMethodBurnerPause, params, false, &urBurnerReply{}); err != nil {
			return err
		}
		if params.Paused {
			cli.printf("paused: its mail is refused until ur burner resume\n")
		} else {
			cli.printf("resumed\n")
		}
		return nil
	}
	return errors.New("ur burner takes create, ls, burn, pause or resume")
}
