// `ur status`'s settings lines (§7.9's Settings fields; owner decisions 302, 305; RECORD.md sections 6.3 and 13.1): for
// each hosted Team network, every member's ur status names record_cost, whether per-run cost totals go to the team
// record as well as the member's vault, and says when record_required asks each member for fail-closed hooks, as this
// device honors them, or that it opens no config head to know them; and while a hosted network requires fail-closed
// hooks, each harness installed fail-open is named, since the daemon's config check reads it as changed and taints its
// runs until ur install-harness runs again (harness_hash.go). A personal network prints nothing here. ur
// install-harness reads the same method from a running daemon, and the daemon's config check the same settings
// (urDaemonRecordRequired). The lines carry network ids, harness names and the person's own directories, nothing
// else (I-13).

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

// The control method `ur status` and `ur install-harness` read the settings by.
const urMethodStatusSettings = "status.settings"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urStatusSettingsMethods)
	urStatusSections = append(urStatusSections, printUrStatusSettings)
}

// One hosted network's Settings fields as its Sidecar honors them.
type urNetworkSettings struct {
	NetworkId sidecar.Id `json:"network_id"`
	// Its config names a team record or a directory.
	Team bool `json:"team,omitempty"`
	// No verified state yet, or a head this device cannot open: the fields below are not known.
	Unknown        bool `json:"unknown,omitempty"`
	RecordCost     bool `json:"record_cost,omitempty"`
	RecordRequired bool `json:"record_required,omitempty"`
}

// status.settings' reply: each hosted network.
type urStatusSettingsReply struct {
	Networks []*urNetworkSettings `json:"networks,omitempty"`
}

// The networks whose head sets record_required, and those whose settings are not known here.
func (self *urStatusSettingsReply) required() (required []sidecar.Id, unknown []sidecar.Id) {
	for _, network := range self.Networks {
		switch {
		case network.Unknown:
			unknown = append(unknown, network.NetworkId)
		case network.RecordRequired:
			required = append(required, network.NetworkId)
		}
	}
	return required, unknown
}

// Each hosted network's settings through honor, a Sidecar with none known marked unknown.
func urStatusSettingsOf(hosted []sidecar.DaemonNetwork, honor func(running *sidecar.Sidecar) (*sidecar.ConfigTeamSettings, error)) *urStatusSettingsReply {
	reply := &urStatusSettingsReply{}
	for _, network := range hosted {
		settings := &urNetworkSettings{NetworkId: network.NetworkId, Unknown: true}
		if network.Sidecar != nil {
			if honored, err := honor(network.Sidecar); err == nil {
				settings.Team = honored.Team
				settings.Unknown = !honored.Known
				settings.RecordCost = honored.RecordCost
				settings.RecordRequired = honored.RecordRequired
			}
		}
		reply.Networks = append(reply.Networks, settings)
	}
	return reply
}

// A hosted Sidecar's Settings fields as it honors them now.
func urSidecarTeamSettings(running *sidecar.Sidecar) (*sidecar.ConfigTeamSettings, error) {
	return running.TeamSettings()
}

// Whether a network the daemon hosts requires fail-closed hooks now: the daemon's config check reads a fail-open
// install as changed while one does (§16.7; owner decision 305). A network whose head this device cannot open
// requires nothing here, since nothing says it does; ur status and ur install-harness say it is not known.
func urDaemonRecordRequired(hosted []sidecar.DaemonNetwork) bool {
	required, _ := urStatusSettingsOf(hosted, urSidecarTeamSettings).required()
	return 0 < len(required)
}

// The settings method over target, when it hosts Sidecars.
func urStatusSettingsMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	hosting, ok := target.(urStatusCoverageTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name: urMethodStatusSettings,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			return urStatusSettingsOf(hosting.hosted(), urSidecarTeamSettings), nil
		},
	}}
}

// The settings of each network a running daemon hosts, asked without starting one: an error where none answers.
func urRunningDaemonSettings(ctx context.Context, cli *urCli) (*urStatusSettingsReply, error) {
	callCtx, cancel := context.WithTimeout(ctx, cli.settings.CallTimeout)
	defer cancel()
	socketPath, err := cli.socketPath(cli.instance)
	if err != nil {
		return nil, err
	}
	client, err := cli.dialDaemon(callCtx, socketPath, cli.hello(sidecar.DaemonModeControl))
	if err != nil {
		return nil, err
	}
	defer client.Close()
	reply := &urStatusSettingsReply{}
	if err := client.Call(callCtx, urMethodStatusSettings, struct{}{}, false, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// The network lines: each Team network's record_cost, and its record_required when set.
func printUrSettingsReply(cli *urCli, reply *urStatusSettingsReply) {
	for _, network := range reply.Networks {
		if !network.Team {
			continue
		}
		switch {
		case network.Unknown:
			fmt.Fprintf(cli.stdout, "team:       network %s: record_cost and record_required are not known here, since this device opens no config head: cost stays in your vault\n", network.NetworkId)
			continue
		case network.RecordCost:
			fmt.Fprintf(cli.stdout, "team:       network %s: record_cost on, the Team's default: per-run cost totals go to the team record as well as your vault\n", network.NetworkId)
		default:
			fmt.Fprintf(cli.stdout, "team:       network %s: record_cost off: per-run cost totals stay in your vault\n", network.NetworkId)
		}
		if network.RecordRequired {
			fmt.Fprintf(cli.stdout, "team:       network %s: record_required on: ur install-harness writes fail-closed hooks\n", network.NetworkId)
		}
	}
}

// Each harness installed fail-open while a hosted network requires fail-closed hooks, read from the instance's seals.
func printUrRequiredHarnesses(cli *urCli, reply *urStatusSettingsReply) {
	required, _ := reply.required()
	if len(required) == 0 {
		return
	}
	stateDirectory, err := cli.stateDirectory(cli.instance)
	if err != nil {
		return
	}
	seals, _, err := mcp.ReadHarnessSeals(stateDirectory, cli.ingest.HarnessConfigByteCount)
	if err != nil {
		return
	}
	ids := []string{}
	for _, networkId := range required {
		ids = append(ids, networkId.String())
	}
	for _, seal := range seals {
		if seal.RecordRequired {
			continue
		}
		where := "your own files"
		if seal.ProjectDirectory != "" {
			where = seal.ProjectDirectory
		}
		fmt.Fprintf(cli.stdout, "harness:    %s in %s: fail-open while network %s requires fail-closed hooks, so its runs are tainted until ur install-harness %s runs again\n",
			seal.Harness, where, strings.Join(ids, ", "), seal.Harness)
	}
}

// The settings lines, after status's own: a daemon that does not answer the method says so in one line.
func printUrStatusSettings(ctx context.Context, cli *urCli) {
	reply := &urStatusSettingsReply{}
	if err := cli.callDaemon(ctx, urMethodStatusSettings, struct{}{}, false, reply); err != nil {
		fmt.Fprintf(cli.stdout, "settings:   not read: %s\n", err)
		return
	}
	printUrSettingsReply(cli, reply)
	printUrRequiredHarnesses(cli, reply)
}
