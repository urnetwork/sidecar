// ur admin settings (§7.9's Settings fields; owner decisions 302, 305; QD-204; question
// service-settings-7-9-admin-settings-command, built on its recommendation):
//
//	ur admin settings [--mail-strict=<mail_strict>] [--record-cost=<record_cost>] [--record-required=<record_required>]
//
// Each value is on or off. With no option it prints the three as this device honors them: mail_strict, §15.4's
// mail.strict, off unless set; record_cost, whether per-run cost totals go to the team record as well as each
// member's vault, on unless the Team turns it off; record_required, whether each member's ur install-harness writes
// fail-closed hooks, off unless set. Otherwise it signs, only after a yes on /dev/tty, through a Confirm method: the
// daemon files every option given in one ServiceSettings into the config head, the head's other settings kept, from an
// Owner's or Admin's device that runs the network's config writer (sidecar.SaveServiceSettings), and refuses any other
// device before it signs anything. A value other than on or off refuses as the options parse. The daemon refuses a
// caller with a harness process among its ancestors, by the pid it read off the socket, and no MCP tool reaches any
// of it, so record_required is never set through MCP.

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur admin settings calls.
const (
	urMethodAdminSettingsShow = "admin.settings.show"
	urMethodAdminSettings     = "admin.settings"
)

var _ = registerUrAdminPart(&urAdminPart{
	word:  "settings",
	usage: []string{"  ur admin settings [--mail-strict=<mail_strict>] [--record-cost=<record_cost>] [--record-required=<record_required>] [--network=<network>]"},
	run:   runUrAdminSettings,
})

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urAdminSettingsMethods)
}

// What the methods take: a field left out changes nothing.
type urAdminSettingsParams struct {
	Network string `json:"network,omitempty"`
	// on or off.
	MailStrict     string `json:"mail_strict,omitempty"`
	RecordCost     string `json:"record_cost,omitempty"`
	RecordRequired string `json:"record_required,omitempty"`
}

// The three as this device honors them, or as a change filed them, each on or off.
type urAdminSettingsReply struct {
	// The network is a Team's: its config names a team record or a directory.
	Team bool `json:"team,omitempty"`
	// The head could not be opened here, so the settings are not known.
	Unknown        bool   `json:"unknown,omitempty"`
	MailStrict     string `json:"mail_strict,omitempty"`
	RecordCost     string `json:"record_cost,omitempty"`
	RecordRequired string `json:"record_required,omitempty"`
}

// A setting's value as ur prints it.
func urAdminSettingsWord(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

// A setting's value from its option: true for on, false for off, nil for absent.
func urAdminSettingsValue(option string, text string) (*bool, error) {
	switch text {
	case "":
		return nil, nil
	case "on":
		value := true
		return &value, nil
	case "off":
		value := false
		return &value, nil
	}
	return nil, fmt.Errorf("%s is on or off, not %q", option, text)
}

// The reply of honored settings.
func urAdminSettingsReplyOf(honored *sidecar.ConfigTeamSettings) *urAdminSettingsReply {
	if !honored.Known {
		return &urAdminSettingsReply{Team: honored.Team, Unknown: true}
	}
	return &urAdminSettingsReply{
		Team:           honored.Team,
		MailStrict:     urAdminSettingsWord(honored.MailStrict),
		RecordCost:     urAdminSettingsWord(honored.RecordCost),
		RecordRequired: urAdminSettingsWord(honored.RecordRequired),
	}
}

// The change the params ask for.
func urAdminSettingsChangeOf(params *urAdminSettingsParams) (*sidecar.ServiceSettingsChange, error) {
	change := &sidecar.ServiceSettingsChange{}
	var err error
	if change.MailStrict, err = urAdminSettingsValue("--mail-strict", params.MailStrict); err != nil {
		return nil, err
	}
	if change.RecordCost, err = urAdminSettingsValue("--record-cost", params.RecordCost); err != nil {
		return nil, err
	}
	if change.RecordRequired, err = urAdminSettingsValue("--record-required", params.RecordRequired); err != nil {
		return nil, err
	}
	return change, nil
}

// The admin settings methods over target's networks, when it hosts them.
func urAdminSettingsMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if network, ok := target.(*urDaemonNetwork); !ok || network.daemon == nil {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name:    urMethodAdminSettingsShow,
			Network: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				honored, err := call.Sidecar.TeamSettings()
				if err != nil {
					return nil, err
				}
				return urAdminSettingsReplyOf(honored), nil
			},
		},
		{
			Name:    urMethodAdminSettings,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urAdminSettingsParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				if call.Sidecar.HarnessAncestor(ctx, urCallPid(call)) {
					return nil, errors.New("ur admin settings is refused under a harness process")
				}
				change, err := urAdminSettingsChangeOf(params)
				if err != nil {
					return nil, err
				}
				// a person confirmed it on /dev/tty, which the Confirm method holds the call to
				filed, err := call.Sidecar.SaveServiceSettings(ctx, change, sidecar.SidecarActConfirmed)
				if err != nil {
					return nil, err
				}
				return urAdminSettingsReplyOf(filed), nil
			},
		},
	}
}

// The params the options ask for: a value other than on or off refuses here, before anything is asked or signed.
func urAdminSettingsParamsOf(options docopt.Opts) (*urAdminSettingsParams, error) {
	params := &urAdminSettingsParams{
		Network:        urOptionString(options, "--network"),
		MailStrict:     urOptionString(options, "--mail-strict"),
		RecordCost:     urOptionString(options, "--record-cost"),
		RecordRequired: urOptionString(options, "--record-required"),
	}
	if _, err := urAdminSettingsChangeOf(params); err != nil {
		return nil, err
	}
	return params, nil
}

// The settings' lines as ur prints them.
func printUrAdminSettings(cli *urCli, reply *urAdminSettingsReply) {
	if reply.Unknown {
		cli.printf("settings: not known here, since this device opens no config head\n")
		return
	}
	cli.printf("mail_strict:     %s\n", reply.MailStrict)
	where := "each member's vault and the team record"
	if reply.RecordCost == "off" {
		where = "each member's vault alone"
	}
	cli.printf("record_cost:     %s: per-run cost totals go to %s\n", reply.RecordCost, where)
	cli.printf("record_required: %s\n", reply.RecordRequired)
	if !reply.Team {
		cli.printf("this network names no team record or directory: record_cost changes nothing until it does\n")
	}
}

// Prints the settings, or signs the change after a yes on /dev/tty.
func runUrAdminSettings(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params, err := urAdminSettingsParamsOf(options)
	if err != nil {
		return err
	}
	if params.MailStrict == "" && params.RecordCost == "" && params.RecordRequired == "" {
		reply := &urAdminSettingsReply{}
		if err := cli.callDaemon(ctx, urMethodAdminSettingsShow, params, false, reply); err != nil {
			return err
		}
		printUrAdminSettings(cli, reply)
		return nil
	}
	changes := []string{}
	if params.MailStrict != "" {
		changes = append(changes, "mail_strict "+params.MailStrict)
	}
	if params.RecordCost != "" {
		changes = append(changes, "record_cost "+params.RecordCost)
	}
	if params.RecordRequired != "" {
		changes = append(changes, "record_required "+params.RecordRequired)
	}
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("Sign the network's ServiceSettings with %s?", strings.Join(changes, ", ")))
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("not confirmed: nothing was signed")
	}
	reply := &urAdminSettingsReply{}
	if err := cli.callDaemon(ctx, urMethodAdminSettings, params, true, reply); err != nil {
		return err
	}
	cli.printf("ServiceSettings filed, honored from the base that names the head:\n")
	printUrAdminSettings(cli, reply)
	return nil
}
