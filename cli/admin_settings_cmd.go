// ur admin settings (§7.9's Settings fields; owner decisions 302, 305; QD-204; question
// service-settings-7-9-admin-settings-command, built on its recommendation):
//
//	ur admin settings [--mail-strict=<mail_strict>] [--record-cost=<record_cost>] [--record-required=<record_required>]
//	ur admin settings --feature=<feature>
//
// Each value is on or off. With no option it prints the three as this device honors them: mail_strict, §15.4's
// mail.strict, off unless set; record_cost, whether per-run cost totals go to the team record as well as each
// member's vault, on unless the Team turns it off; record_required, whether each member's ur install-harness writes
// fail-closed hooks, off unless set; and DESIGN-COMPUTE §16.6's authorization features, each on or off with whether this
// device may turn it on. Otherwise it signs, only after a yes on /dev/tty, through a Confirm method: the daemon files
// every option given in one ServiceSettings into the config head, the head's other settings kept, from an Owner's or
// Admin's device that runs the network's config writer (sidecar.SaveServiceSettings), and refuses any other device
// before it signs anything. A value other than on or off refuses as the options parse. The daemon refuses a caller
// with a harness process among its ancestors, by the pid it read off the socket, and no MCP tool reaches any of it, so
// record_required is never set through MCP.
//
// --feature turns one authorization feature on (CACL-M11-03): agent_repos, compute_policy, listeners or enclaves, a
// name that is none refused before anything is asked. It reads the feature's state first and refuses, asking nothing,
// one this device may not turn on, saying why: this release does not implement it, the services serving the network do
// not yet, or only the network's Owners and Admins can, whom it names. Otherwise the question says the feature stays
// on, since no command turns one off, and which of the network's sidecars would pause until they update; on a yes the
// Confirm method admin.settings.feature files it (sidecar.TurnOnAuthFeature), which the daemon refuses as the root does.
//
// The show, and a change once filed, also list the config head's carried records (D-TEAM-26; owner decision 699;
// QD-1207): its ServiceSettings and VersioningRules whose signer no longer stands as one who may sign them, each with
// the signer, its member, why it no longer stands and who files another (sidecar.CarriedConfigRecords). Each stands
// under that signer, as every reader holds it, until an Owner or Admin, or for VersioningRules a Network admin, files a
// fresh one; a device that could not read the head's records now says so.

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control methods ur admin settings calls.
const (
	urMethodAdminSettingsShow = "admin.settings.show"
	urMethodAdminSettings     = "admin.settings"
	// Turning an authorization feature on: a Confirm method, as the apps' prompt calls it in remote mode.
	urMethodAdminSettingsFeature = "admin.settings.feature"
)

var _ = registerUrAdminPart(&urAdminPart{
	word: "settings",
	usage: []string{
		"  ur admin settings [--mail-strict=<mail_strict>] [--record-cost=<record_cost>] [--record-required=<record_required>] [--network=<network>]",
		"  ur admin settings --feature=<feature> [--network=<network>]",
	},
	run: runUrAdminSettings,
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
	// admin.settings.feature's alone: the feature's name.
	Feature string `json:"feature,omitempty"`
}

// The three as this device honors them, or as a change filed them, each on or off, and the authorization features.
type urAdminSettingsReply struct {
	// The network is a Team's: its config names a team record or a directory.
	Team bool `json:"team,omitempty"`
	// The head could not be opened here, so the settings are not known.
	Unknown        bool   `json:"unknown,omitempty"`
	MailStrict     string `json:"mail_strict,omitempty"`
	RecordCost     string `json:"record_cost,omitempty"`
	RecordRequired string `json:"record_required,omitempty"`
	// Each authorization feature as this device sees it, in bit order; absent where the daemon could not say.
	Features []*sidecar.AuthFeatureStatus `json:"features,omitempty"`
	// The head's records whose signer no longer stands, for an Owner or Admin to file anew (QD-1207); empty while every
	// record's signer stands.
	Carried []*sidecar.ConfigCarriedRecord `json:"carried,omitempty"`
	// The daemon could not read the head's records now, so Carried says nothing.
	CarriedUnknown bool `json:"carried_unknown,omitempty"`
}

// What lists the head's carried records: a Sidecar is one.
type urAdminCarriedLister interface {
	CarriedConfigRecords(ctx context.Context) ([]*sidecar.ConfigCarriedRecord, error)
}

var _ urAdminCarriedLister = (*sidecar.Sidecar)(nil)

// Lists into reply the head's records whose signer no longer stands, or that the daemon could not say; nothing where
// the settings themselves are unknown, since a device that opens no head holds no record.
func urAdminSettingsListCarried(ctx context.Context, lister urAdminCarriedLister, reply *urAdminSettingsReply) {
	if reply.Unknown {
		return
	}
	carried, err := lister.CarriedConfigRecords(ctx)
	if err != nil {
		reply.CarriedUnknown = true
		return
	}
	reply.Carried = carried
}

// The feature named name among the reply's, nil if absent.
func (self *urAdminSettingsReply) feature(name string) *sidecar.AuthFeatureStatus {
	for _, status := range self.Features {
		if status != nil && status.Name == name {
			return status
		}
	}
	return nil
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

// The feature --feature names, one of the four.
func urAdminSettingsFeatureOf(name string) (sidecar.AuthFeature, error) {
	feature, err := sidecar.ParseAuthFeature(name)
	if err != nil {
		return 0, fmt.Errorf("--feature is agent_repos, compute_policy, listeners or enclaves, not %q", name)
	}
	return feature, nil
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
				reply := urAdminSettingsReplyOf(honored)
				// the features read the same verified state; a failure leaves them out rather than failing the settings
				if statuses, err := call.Sidecar.AuthFeatureStatuses(); err == nil {
					reply.Features = statuses
				}
				urAdminSettingsListCarried(ctx, call.Sidecar, reply)
				return reply, nil
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
				// the save returns once this device took the base naming the head, so the listing is that head's
				reply := urAdminSettingsReplyOf(filed)
				urAdminSettingsListCarried(ctx, call.Sidecar, reply)
				return reply, nil
			},
		},
		{
			Name:    urMethodAdminSettingsFeature,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &urAdminSettingsParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, err
				}
				feature, err := urAdminSettingsFeatureOf(params.Feature)
				if err != nil {
					return nil, err
				}
				// a person confirmed it on /dev/tty or in an app's UI, which the Confirm method holds the call to; the
				// root refuses a caller under a harness process
				return call.Sidecar.TurnOnAuthFeature(ctx, &sidecar.AuthFeatureTurnOnArgs{
					Feature:         feature,
					Confirmed:       true,
					HarnessAncestor: call.Sidecar.HarnessAncestor(ctx, urCallPid(call)),
				})
			},
		},
	}
}

// The params the options ask for: a value other than on or off, or a feature that is none of the four, refuses here,
// before anything is asked or signed.
func urAdminSettingsParamsOf(options docopt.Opts) (*urAdminSettingsParams, error) {
	params := &urAdminSettingsParams{
		Network:        urOptionString(options, "--network"),
		MailStrict:     urOptionString(options, "--mail-strict"),
		RecordCost:     urOptionString(options, "--record-cost"),
		RecordRequired: urOptionString(options, "--record-required"),
		Feature:        urOptionString(options, "--feature"),
	}
	if _, err := urAdminSettingsChangeOf(params); err != nil {
		return nil, err
	}
	if params.Feature != "" {
		if _, err := urAdminSettingsFeatureOf(params.Feature); err != nil {
			return nil, err
		}
	}
	return params, nil
}

// What a feature's line says after its state: whether, and why not, this device may turn it on.
func urAdminSettingsFeatureNote(status *sidecar.AuthFeatureStatus) string {
	switch {
	case status.On:
		return ""
	case !status.Implemented:
		return "not offered: this release does not implement it"
	case !status.SupportKnown:
		return "not offered now: the services' features are not known here, since this device has no current answer from api"
	case !status.Supported:
		return "not offered: the services serving this network do not implement it yet"
	case !status.MayTurnOn:
		memberIds := []string{}
		for _, memberId := range status.AdminMemberIds {
			memberIds = append(memberIds, memberId.String())
		}
		return "only the network's Owners and Admins can turn it on: " + strings.Join(memberIds, ", ")
	}
	note := fmt.Sprintf("ur admin settings --feature %s turns it on", status.Name)
	if pausing := urAdminSettingsPausing(status); pausing != "" {
		note += "; " + pausing
	}
	return note
}

// Which sidecars would pause until they update at the feature's turning-on, as api listed them to this device; empty
// where it listed none.
func urAdminSettingsPausing(status *sidecar.AuthFeatureStatus) string {
	if !status.PausingKnown || (len(status.PausingSidecarIds) == 0 && !status.PausingMore) {
		return ""
	}
	sidecarIds := []string{}
	for _, sidecarId := range status.PausingSidecarIds {
		sidecarIds = append(sidecarIds, sidecarId.String())
	}
	if status.PausingMore {
		sidecarIds = append(sidecarIds, "and more")
	}
	return fmt.Sprintf("these sidecars would pause until they update: %s", strings.Join(sidecarIds, ", "))
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
	if 0 < len(reply.Features) {
		cli.printf("authorization features, each turned on by ur admin settings --feature <name> and never off:\n")
		for _, status := range reply.Features {
			if status == nil {
				continue
			}
			printUrAdminSettingsFeature(cli, status)
		}
	}
	switch {
	case reply.CarriedUnknown:
		cli.printf("carried records: not known here, since this device could not read the config head's records now\n")
	case 0 < len(reply.Carried):
		cli.printf("carried records, each standing under a signer who no longer stands until another is filed:\n")
		for _, carried := range reply.Carried {
			if carried != nil {
				cli.printf("  %s\n", urAdminCarriedLine(carried))
			}
		}
	}
}

// One carried record as ur lists it: the record, its signer and the signer's member, why the signer no longer stands,
// and who files another with which command (§7.9's records table).
func urAdminCarriedLine(carried *sidecar.ConfigCarriedRecord) string {
	signer := carried.SignerId.String()
	if carried.MemberId != nil {
		signer += " of member " + carried.MemberId.String()
	}
	why := func() string {
		switch carried.Why {
		case sidecar.ConfigCarriedRevoked:
			if carried.MemberRemoved {
				return fmt.Sprintf("revoked at position %d, its member no longer the network's", carried.At)
			}
			return fmt.Sprintf("revoked at position %d", carried.At)
		case sidecar.ConfigCarriedParked:
			return fmt.Sprintf("parked at position %d", carried.At)
		case sidecar.ConfigCarriedExpired:
			return fmt.Sprintf("its admission ended at %s", time.UnixMilli(carried.NotAfterMs).UTC().Format(time.RFC3339))
		case sidecar.ConfigCarriedRemoved:
			return "its member is no longer the network's"
		case sidecar.ConfigCarriedTagged:
			return "a tagged sidecar, which signs no such record"
		case sidecar.ConfigCarriedRole:
			return fmt.Sprintf("its member's role is now %s, which does not sign it", carried.Role)
		case sidecar.ConfigCarriedUnlisted:
			return "the network's rows no longer hold it"
		case sidecar.ConfigCarriedSignature:
			return "its signature does not verify under the key its row admits"
		}
		return carried.Why
	}
	filer, command := "an Owner or Admin", "ur admin settings with any option"
	if carried.Record == sidecar.ConfigHeadVersioningRulesPath {
		filer, command = "an Owner, Admin or Network admin", "ur admin versioning --rules"
	}
	return fmt.Sprintf("%s: signed by %s, %s; %s files another: %s", carried.Record, signer, why(), filer, command)
}

// One feature's line.
func printUrAdminSettingsFeature(cli *urCli, status *sidecar.AuthFeatureStatus) {
	line := fmt.Sprintf("  %-15s %s", status.Name+":", urAdminSettingsWord(status.On))
	if note := urAdminSettingsFeatureNote(status); note != "" {
		line += ": " + note
	}
	cli.printf("%s\n", line)
}

// Prints the settings, or signs the change after a yes on /dev/tty.
func runUrAdminSettings(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params, err := urAdminSettingsParamsOf(options)
	if err != nil {
		return err
	}
	if params.Feature != "" {
		return runUrAdminSettingsFeature(ctx, cli, params)
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

// Turns params' feature on after a yes on /dev/tty, having read its state first: see the file header.
func runUrAdminSettingsFeature(ctx context.Context, cli *urCli, params *urAdminSettingsParams) error {
	shown := &urAdminSettingsReply{}
	if err := cli.callDaemon(ctx, urMethodAdminSettingsShow, &urAdminSettingsParams{Network: params.Network}, false, shown); err != nil {
		return err
	}
	status := shown.feature(params.Feature)
	if status == nil {
		return fmt.Errorf("the daemon could not say whether %s may be turned on here: nothing was signed", params.Feature)
	}
	if status.On {
		cli.printf("%s is on for this network already\n", status.Name)
		return nil
	}
	if !status.MayTurnOn {
		return fmt.Errorf("%s stays off: %s; nothing was signed", status.Name, urAdminSettingsFeatureNote(status))
	}
	question := fmt.Sprintf("Turn on %s for this network? It stays on: no command turns it off.", status.Name)
	if pausing := urAdminSettingsPausing(status); pausing != "" {
		question += " Of its sidecars, " + pausing + "."
	}
	confirmed, err := confirmOnTty(cli, question)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("not confirmed: nothing was signed")
	}
	reply := &sidecar.AuthFeatureStatus{}
	if err := cli.callDaemon(ctx, urMethodAdminSettingsFeature, &urAdminSettingsParams{Network: params.Network, Feature: params.Feature}, true, reply); err != nil {
		return err
	}
	cli.printf("%s filed into the network's ServiceSettings, on from the base that names the head:\n", reply.Name)
	printUrAdminSettingsFeature(cli, reply)
	return nil
}
