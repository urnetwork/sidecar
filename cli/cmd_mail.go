// ur mail (§15.6, §15.15; MAIL-M7-17): a network's mail, which the daemon's mail component runs and keeps the daemon up
// while it is on (§5.8).
//
//	ur mail enable [--network=<net>]   turns mail on: mailcfg, this device's member's mailbox and its RepoAdmin, then
//	                                   POST /mail/enable, which turns on the network's mail records (§12)
//	ur mail status [--network=<net>]   the network's mail status, this device's receiver, and §15.6's prompt for a
//	                                   desktop, NAS or VPS indexer while none stands
//
// `ur status` prints a mail line from the same method for each hosted network, and the prompt while it holds. The
// design names the commands' flags nowhere: --network is this file's, as cli/UI.md records (plan-CORE-cli-ui-missing).
// Nothing here prints an address or an alias but to the person's own terminal, and nothing logs one (I-13).

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur mail and ur status call.
const (
	urMethodMailEnable = "mail.enable"
	urMethodMailStatus = "mail.status"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "mail",
		usage:   "  ur mail enable [--network=<net>]\n  ur mail status [--network=<net>]",
		summary: "turn mail on for the network, or show its status",
		run:     runUrMail,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urMailMethods)
	urStatusSections = append(urStatusSections, printUrStatusMail)
}

// The daemon's MailClient as the mail and id methods use it: *sidecar.MailClient is one, and a test stands a fake in.
type urMailClient interface {
	Enable(ctx context.Context) (*sidecar.MailEnabled, error)
	Status(ctx context.Context) (*sidecar.MailClientStatus, error)
	Aliases(ctx context.Context) ([]*sidecar.MailAddressLookup, error)
	CreateAlias(ctx context.Context, args *sidecar.MailAliasCreateArgs) (*sidecar.MailAddressLookup, error)
	DeleteAlias(ctx context.Context, localPart string, action sidecar.MailConfigActionArgs) error
	CreateGroup(ctx context.Context, args *sidecar.MailCreateGroupArgs) (*sidecar.EvsRepo, error)
	AddGroupMember(ctx context.Context, group string, memberId sidecar.Id) error
}

// What the mail and id methods act on: a target hosting Sidecars, each with its MailClient.
type urMailTarget interface {
	// The MailClient of network, a hosted one by name, or, empty, §5.8's pick.
	mailClient(network string) (urMailClient, error)
}

// The hosted network's MailClient.
func (self *urDaemonNetwork) mailClient(network string) (urMailClient, error) {
	if self.daemon == nil {
		return nil, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	networkId, err := self.daemon.ResolveNetwork(&sidecar.DaemonHello{Mode: sidecar.DaemonModeControl}, network)
	if err != nil {
		return nil, err
	}
	running, ok := self.daemon.SidecarForNetwork(networkId)
	if !ok {
		return nil, fmt.Errorf("no sidecar runs: %s", self.noSidecar)
	}
	return running.Mail()
}

// mail.enable's reply.
type urMailEnableReply struct {
	EnabledTimeMillis int64 `json:"enabled_time_ms"`
}

// mail.status's reply: the status, ids and flags only.
type urMailStatusReply struct {
	Enabled          bool        `json:"enabled"`
	NetworkKnown     bool        `json:"network_known"`
	StorageFull      bool        `json:"storage_full,omitempty"`
	Spent            bool        `json:"spent,omitempty"`
	DirectMx         bool        `json:"direct_mx,omitempty"`
	Receiving        bool        `json:"receiving"`
	Listening        bool        `json:"listening"`
	Serving          bool        `json:"serving"`
	ApprovalId       *sidecar.Id `json:"approval_id,omitempty"`
	Problem          string      `json:"problem,omitempty"`
	MailIndexer      bool        `json:"mail_indexer"`
	MailIndexerKnown bool        `json:"mail_indexer_known"`
	Prompt           string      `json:"prompt,omitempty"`
}

// The reply of status.
func urMailStatusReplyOf(status *sidecar.MailClientStatus) *urMailStatusReply {
	reply := &urMailStatusReply{
		Enabled:          status.Enabled,
		Receiving:        status.Receiver.Running,
		Listening:        status.Receiver.Listening,
		Serving:          status.Receiver.Serving,
		ApprovalId:       status.Receiver.ApprovalId,
		Problem:          status.Receiver.Problem,
		MailIndexer:      status.MailIndexer,
		MailIndexerKnown: status.MailIndexerKnown,
		Prompt:           status.Prompt,
	}
	if status.Network != nil {
		reply.NetworkKnown = true
		reply.StorageFull = status.Network.StorageFull
		reply.Spent = status.Network.Spent
		reply.DirectMx = status.Network.DirectMx
	}
	return reply
}

// Starts each hosted network's mail component, so a network with mail on keeps the daemon up from its start (§5.8).
// A network enrolled after the daemon started takes its component at the daemon's next start.
func (self *urDaemonNetwork) startMail() {
	for _, hosted := range self.hosted() {
		if _, err := hosted.Sidecar.StartMail(); err != nil {
			fmt.Fprintf(os.Stderr, "ur: a network's mail did not start: %v\n", err)
		}
	}
}

// The mail methods over target, when it hosts Sidecars: registered once the daemon hosts its networks, which is when
// their mail components start.
func urMailMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if network, ok := target.(*urDaemonNetwork); ok {
		network.startMail()
	}
	mail, ok := target.(urMailTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodMailEnable,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urNetworkParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				client, err := mail.mailClient(params.Network)
				if err != nil {
					return nil, err
				}
				enabled, err := client.Enable(ctx)
				if err != nil {
					return nil, err
				}
				return &urMailEnableReply{EnabledTimeMillis: enabled.EnabledTime.UnixMilli()}, nil
			},
		},
		{
			Name: urMethodMailStatus,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urNetworkParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				client, err := mail.mailClient(params.Network)
				if err != nil {
					return nil, err
				}
				status, err := client.Status(ctx)
				if err != nil {
					return nil, err
				}
				return urMailStatusReplyOf(status), nil
			},
		},
	}
}

func runUrMail(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network := urOptionString(options, "--network")
	switch {
	case options["enable"] == true:
		reply := &urMailEnableReply{}
		if err := cli.callDaemon(ctx, urMethodMailEnable, &urNetworkParams{Network: network}, false, reply); err != nil {
			return err
		}
		cli.printf("mail is on for the network; the daemon stays up while it is\n")
		return nil
	case options["status"] == true:
		reply := &urMailStatusReply{}
		if err := cli.callDaemon(ctx, urMethodMailStatus, &urNetworkParams{Network: network}, false, reply); err != nil {
			return err
		}
		for _, line := range formatUrMailStatus(reply) {
			cli.printf("%s\n", line)
		}
		return nil
	}
	return errors.New("ur mail takes enable or status")
}

// The status as a person reads it.
func formatUrMailStatus(reply *urMailStatusReply) []string {
	lines := []string{}
	state := "off"
	if reply.Enabled {
		state = "on"
	}
	notes := []string{}
	if reply.StorageFull {
		notes = append(notes, "storage full: receivers defer mail")
	}
	if reply.Spent {
		notes = append(notes, "spent")
	}
	if reply.DirectMx {
		notes = append(notes, "direct MX")
	}
	if !reply.NetworkKnown {
		notes = append(notes, "the network's status could not be read")
	}
	line := "mail:       " + state
	if 0 < len(notes) {
		line += " (" + strings.Join(notes, ", ") + ")"
	}
	lines = append(lines, line)
	receiver := "not receiving"
	switch {
	case reply.ApprovalId != nil:
		receiver = fmt.Sprintf("waiting for approval: run ur approve %s on another approval-capable device", reply.ApprovalId)
	case reply.Serving:
		receiver = "receiving"
	case reply.Receiving:
		receiver = "starting"
	}
	if reply.Problem != "" && reply.ApprovalId == nil && !reply.Serving {
		receiver += ": " + reply.Problem
	}
	lines = append(lines, "receiver:   "+receiver)
	if reply.Prompt != "" {
		lines = append(lines, "note:       "+reply.Prompt)
	}
	return lines
}

// ur status's mail lines: the only or picked network's, once mail is on; nothing from a daemon that runs no mail.
func printUrStatusMail(ctx context.Context, cli *urCli) {
	reply := &urMailStatusReply{}
	if err := cli.callDaemon(ctx, urMethodMailStatus, &urNetworkParams{}, false, reply); err != nil || !reply.Enabled {
		return
	}
	for _, line := range formatUrMailStatus(reply) {
		cli.printf("%s\n", line)
	}
}
