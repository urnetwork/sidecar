// ur mail recipients rm (§15.10's approved recipients, owner decision 280; MAIL-M9-01): removes the record that
// approves a recipient for a sending alias, so the next mail_send to it waits on a person again.
//
//	ur mail recipients rm <alias> <recipient> [--network=<net>]
//
// A record is made by a send a person approved on a device or by presence, and lasts until a person removes it here
// or in an app: ur asks on /dev/tty first, and mail.recipients.rm is a Confirm method, so neither an MCP nor a hook
// session removes one (D-CORE-13). <alias> is the sending address, one of this network's, and <recipient> the address
// approved for it; a pair with no record changes nothing. The design names this command and no arguments: the pair
// and --network are this file's, as cli/UI.md records (plan-CORE-cli-ui-missing). The addresses go to the person's
// own terminal alone, and nothing logs one (I-13).

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
)

// The control method ur mail recipients rm calls.
const urMethodMailRecipientsRemove = "mail.recipients.rm"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urMailRecipientsMethods)
}

// What mail.recipients.rm acts on: a target that keeps each hosted network's approved recipients.
type urMailRecipientsTarget interface {
	// Removes the record approving recipient for alias in network, a hosted one by name, or, empty, §5.8's pick, and
	// says whether one stood.
	removeMailRecipient(ctx context.Context, network string, alias string, recipient string) (bool, error)
}

// mail.recipients.rm's params.
type urMailRecipientsRemoveParams struct {
	Network   string `json:"network,omitempty"`
	Alias     string `json:"alias"`
	Recipient string `json:"recipient"`
}

// mail.recipients.rm's reply.
type urMailRecipientsRemoveReply struct {
	Removed bool `json:"removed"`
}

// The hosted network's approved recipient, removed.
func (self *urDaemonNetwork) removeMailRecipient(ctx context.Context, network string, alias string, recipient string) (bool, error) {
	if self.daemon == nil {
		return false, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	networkId, err := self.daemon.ResolveNetwork(&sidecar.DaemonHello{Mode: sidecar.DaemonModeControl}, network)
	if err != nil {
		return false, err
	}
	running, ok := self.daemon.SidecarForNetwork(networkId)
	if !ok {
		return false, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	client, err := running.Mail()
	if err != nil {
		return false, err
	}
	removed, err := client.ApprovedRecipients().Remove(ctx, alias, recipient)
	if errors.Is(err, sidecar.ErrMailRecipientApproval) {
		return false, errors.New("not a sending address of this network with a mailbox, or not a recipient's address")
	}
	return removed, err
}

// mail.recipients.rm over target, when it keeps approved recipients.
func urMailRecipientsMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	recipients, ok := target.(urMailRecipientsTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodMailRecipientsRemove,
			// a record is a person's to remove, never an agent's (owner decision 280, D-CORE-13)
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urMailRecipientsRemoveParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				if params.Alias == "" || params.Recipient == "" {
					return nil, errors.New("mail.recipients.rm takes an alias and a recipient")
				}
				removed, err := recipients.removeMailRecipient(ctx, params.Network, params.Alias, params.Recipient)
				if err != nil {
					return nil, err
				}
				return &urMailRecipientsRemoveReply{Removed: removed}, nil
			},
		},
	}
}

// Asks on the terminal, then has the daemon remove the record.
func runUrMailRecipientsRemove(ctx context.Context, cli *urCli, network string, alias string, recipient string) error {
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("stop sending from %s to %s without an approval?", alias, recipient))
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	reply := &urMailRecipientsRemoveReply{}
	params := &urMailRecipientsRemoveParams{Network: network, Alias: alias, Recipient: recipient}
	if err := cli.callDaemon(ctx, urMethodMailRecipientsRemove, params, true, reply); err != nil {
		return err
	}
	if !reply.Removed {
		cli.printf("no approval stood for that alias and recipient; nothing changed\n")
		return nil
	}
	cli.printf("removed: mail from that alias to that recipient waits on a person again\n")
	return nil
}
