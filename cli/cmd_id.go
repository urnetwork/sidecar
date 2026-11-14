// ur id (§15.8, R-MAIL-3; MAIL-M7-17): a network's mail addresses, thin over the daemon's MailClient.
//
//	ur id create <name> [--network=<net>]                <name>@<net>.<root>, delivering to this member's mailbox
//	ur id group-create <name> [--private] [--network=<net>]
//	                                                     a group address and its repo, confirmed on the terminal
//	ur id group-add <group> <member_id> [--network=<net>]
//	                                                     a member joined to a group: the only way in (§16.11)
//	ur id ls [--network=<net>]                           every address mailcfg holds
//	ur id rm <name> [--network=<net>]                    an address's record removed
//
// Creating and removing an address are outward actions (I-8): each goes through §5.4's gate, and while a person's
// decision is awaited the command prints ur approve <id> for another approval-capable device and exits 1, the action
// running once it is run again after the approval. §15.8 gives create, group-create with --private and group-add;
// the rest of these spellings and flags are proposals until cli/UI.md exists (plan-CORE-cli-ui-missing), as
// cli/UI.md records. Addresses are printed to the person's own terminal and logged nowhere (I-13).

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The control methods ur id calls.
const (
	urMethodIdCreate      = "id.create"
	urMethodIdGroupCreate = "id.group_create"
	urMethodIdGroupAdd    = "id.group_add"
	urMethodIdList        = "id.ls"
	urMethodIdRemove      = "id.rm"
)

func init() {
	registerUrCommand(&urCommand{
		name: "id",
		usage: "  ur id create <name> [--network=<net>]\n" +
			"  ur id group-create <name> [--private] [--network=<net>]\n" +
			"  ur id group-add <group> <member_id> [--network=<net>]\n" +
			"  ur id ls [--network=<net>]\n" +
			"  ur id rm <name> [--network=<net>]",
		summary: "create, list and remove the network's mail addresses",
		run:     runUrId,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urIdMethods)
}

// An id method's params.
type urIdParams struct {
	Network  string      `json:"network,omitempty"`
	Name     string      `json:"name,omitempty"`
	Private  bool        `json:"private,omitempty"`
	MemberId *sidecar.Id `json:"member_id,omitempty"`
}

// An address as id.ls lists it, and as id.create answers it.
type urIdAddress struct {
	Address string `json:"address"`
	Kind    string `json:"kind"`
	// Whether a receiver takes its mail: policy still grants its creator the listen.
	Known bool `json:"known"`
}

// id.create's and id.rm's reply: the address, or the approval the action waits on.
type urIdReply struct {
	Address    *urIdAddress `json:"address,omitempty"`
	ApprovalId *sidecar.Id  `json:"approval_id,omitempty"`
}

// id.ls's reply.
type urIdListReply struct {
	Addresses []*urIdAddress `json:"addresses"`
}

// The address kind's word.
func urIdKind(lookup *sidecar.MailAddressLookup) string {
	switch lookup.Kind {
	case protocol.MailAddressKind_MAIL_ADDRESS_ADMIN:
		return "admin"
	case protocol.MailAddressKind_MAIL_ADDRESS_ID:
		return "id"
	case protocol.MailAddressKind_MAIL_ADDRESS_GROUP:
		return "group"
	case protocol.MailAddressKind_MAIL_ADDRESS_AGENT:
		return "agent"
	case protocol.MailAddressKind_MAIL_ADDRESS_BURNER:
		return "burner"
	case protocol.MailAddressKind_MAIL_ADDRESS_BOUNCE:
		return "bounce"
	}
	return "unknown"
}

// A reply for err: the approval it waits on, or err itself.
func urIdPending(err error) (*urIdReply, error) {
	var pending *sidecar.ApprovalPendingError
	if errors.As(err, &pending) {
		approvalId := pending.ApprovalId
		return &urIdReply{ApprovalId: &approvalId}, nil
	}
	return nil, err
}

// The id methods over target, when it hosts Sidecars. group-create is a Confirm method: only a control call a person
// confirmed on the terminal runs it, since MailRepos takes a group's creation only so (§5.8).
func urIdMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	mail, ok := target.(urMailTarget)
	if !ok {
		return nil
	}
	client := func(call *sidecar.DaemonCall) (urMailClient, *urIdParams, error) {
		params := &urIdParams{}
		if err := decodeUrParams(call, params); err != nil {
			return nil, nil, err
		}
		client, err := mail.mailClient(params.Network)
		return client, params, err
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodIdCreate,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				client, params, err := client(call)
				if err != nil {
					return nil, err
				}
				lookup, err := client.CreateAlias(ctx, &sidecar.MailAliasCreateArgs{LocalPart: params.Name})
				if err != nil {
					return urIdPending(err)
				}
				return &urIdReply{Address: &urIdAddress{Address: lookup.Address, Kind: urIdKind(lookup), Known: lookup.Known}}, nil
			},
		},
		{
			Name:    urMethodIdGroupCreate,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				client, params, err := client(call)
				if err != nil {
					return nil, err
				}
				_, err = client.CreateGroup(ctx, &sidecar.MailCreateGroupArgs{
					LocalPart: params.Name, DisplayName: params.Name, Private: params.Private, Confirmed: true,
				})
				if err != nil {
					return urIdPending(err)
				}
				return &urIdReply{}, nil
			},
		},
		{
			Name:    urMethodIdGroupAdd,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				client, params, err := client(call)
				if err != nil {
					return nil, err
				}
				if params.MemberId == nil {
					return nil, errors.New("no member id")
				}
				if err := client.AddGroupMember(ctx, params.Name, *params.MemberId); err != nil {
					return urIdPending(err)
				}
				return &urIdReply{}, nil
			},
		},
		{
			Name: urMethodIdList,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				client, _, err := client(call)
				if err != nil {
					return nil, err
				}
				lookups, err := client.Aliases(ctx)
				if err != nil {
					return nil, err
				}
				reply := &urIdListReply{Addresses: []*urIdAddress{}}
				for _, lookup := range lookups {
					reply.Addresses = append(reply.Addresses, &urIdAddress{Address: lookup.Address, Kind: urIdKind(lookup), Known: lookup.Known})
				}
				return reply, nil
			},
		},
		{
			Name: urMethodIdRemove,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				client, params, err := client(call)
				if err != nil {
					return nil, err
				}
				if err := client.DeleteAlias(ctx, params.Name, sidecar.MailConfigActionArgs{}); err != nil {
					return urIdPending(err)
				}
				return &urIdReply{}, nil
			},
		},
	}
}

// Prints the approval the action waits on and exits 1, or nothing for a reply that waits on none.
func urIdWaiting(cli *urCli, reply *urIdReply) error {
	if reply.ApprovalId == nil {
		return nil
	}
	cli.printf("approval pending: run ur approve %s on another approval-capable device, then run this command again\n", reply.ApprovalId)
	return &urExitError{code: urExitFailed, err: errors.New("the action waits on that approval")}
}

func runUrId(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urIdParams{Network: urOptionString(options, "--network")}
	switch {
	case options["create"] == true:
		params.Name = urOptionString(options, "<name>")
		reply := &urIdReply{}
		if err := cli.callDaemon(ctx, urMethodIdCreate, params, false, reply); err != nil {
			return err
		}
		if err := urIdWaiting(cli, reply); err != nil {
			return err
		}
		if reply.Address != nil {
			cli.printf("%s\n", reply.Address.Address)
		}
		return nil
	case options["group-create"] == true:
		params.Name = urOptionString(options, "<name>")
		params.Private, _ = options.Bool("--private")
		question := fmt.Sprintf("create the group %s, whose repo stores its mail once for every member?", params.Name)
		if params.Private {
			question = fmt.Sprintf("create the private group %s, whose repo stores its mail once for every member?", params.Name)
		}
		confirmed, err := confirmOnTty(cli, question)
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing changed\n")
			return nil
		}
		reply := &urIdReply{}
		if err := cli.callDaemon(ctx, urMethodIdGroupCreate, params, true, reply); err != nil {
			return err
		}
		if err := urIdWaiting(cli, reply); err != nil {
			return err
		}
		cli.printf("the group %s is created; ur id group-add adds its members\n", params.Name)
		return nil
	case options["group-add"] == true:
		params.Name = urOptionString(options, "<group>")
		memberId, err := sidecar.ParseId(urOptionString(options, "<member_id>"))
		if err != nil {
			return fmt.Errorf("not a member id: %w", err)
		}
		params.MemberId = &memberId
		confirmed, err := confirmOnTty(cli, fmt.Sprintf("add member %s to the group %s, which reads all of its mail?", memberId, params.Name))
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing changed\n")
			return nil
		}
		reply := &urIdReply{}
		if err := cli.callDaemon(ctx, urMethodIdGroupAdd, params, true, reply); err != nil {
			return err
		}
		if err := urIdWaiting(cli, reply); err != nil {
			return err
		}
		cli.printf("member %s is in the group %s\n", memberId, params.Name)
		return nil
	case options["ls"] == true:
		reply := &urIdListReply{}
		if err := cli.callDaemon(ctx, urMethodIdList, params, false, reply); err != nil {
			return err
		}
		for _, address := range reply.Addresses {
			note := ""
			if !address.Known {
				note = "  (no receiver takes its mail: its creator's grant is gone)"
			}
			cli.printf("%-6s  %s%s\n", address.Kind, address.Address, note)
		}
		return nil
	case options["rm"] == true:
		params.Name = urOptionString(options, "<name>")
		reply := &urIdReply{}
		if err := cli.callDaemon(ctx, urMethodIdRemove, params, false, reply); err != nil {
			return err
		}
		if err := urIdWaiting(cli, reply); err != nil {
			return err
		}
		cli.printf("%s is removed\n", params.Name)
		return nil
	}
	return errors.New("ur id takes create, group-create, group-add, ls or rm")
}
