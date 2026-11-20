// ur record cost (RECORD.md section 13.1; RECORD-M6-08).
//
//	ur record cost [--log=<log>] [--since=<time>] [--until=<time>] [--by=<by>] [--map=<file>] [--format=<format>]
//
// Sums one log's cost entries, the vault by default: per run only the newest, tokens and the amounts harnesses
// reported. No price is computed, so a self-hosted model shows tokens and no amount, and this is no bill. --by is
// project, client, model or month (§7.9's project, client or month beside RECORD.md section 13.1's project, model or
// month). --map is a local file of project,client lines, which groups projects by client with nothing new in any log:
// under --by project a mapped project shows as its client, and --by client needs it, refused before the daemon is
// asked without one, a project it names no client for showing as (no client). There is no grouping by member and no
// order by amount: the report ranks no one. On a team log a group fewer than five members wrote shows as other.

package main

import (
	"context"
	"errors"
	"os"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// The control method ur record cost calls.
const urMethodRecordCost = "record.cost"

func init() {
	registerUrRecordPart(&urRecordPart{
		word:  "cost",
		usage: []string{"  ur record cost [--log=<log>] [--since=<time>] [--until=<time>] [--by=<by>] [--map=<file>] [--format=<format>]"},
		run:   runUrRecordCost,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urRecordCostMethods)
}

// What a report asks, as the method takes it.
type urRecordCostParams struct {
	// a log's name or id; empty is the vault
	Log         string `json:"log,omitempty"`
	SinceMillis int64  `json:"since_millis,omitempty"`
	UntilMillis int64  `json:"until_millis,omitempty"`
	By          string `json:"by,omitempty"`
	// --map's project to client
	Clients map[string]string `json:"clients,omitempty"`
}

// A report's rows.
type urRecordCostReply struct {
	LogId sidecar.Id               `json:"log_id"`
	Rows  []*sidecar.RecordCostRow `json:"rows"`
}

// What the cost method acts on: a daemon target that runs a Sidecar's record.
type urRecordCostTarget interface {
	recordCost(ctx context.Context, params *urRecordCostParams) (*urRecordCostReply, error)
}

func (self *urDaemonNetwork) recordCost(ctx context.Context, params *urRecordCostParams) (*urRecordCostReply, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, err
	}
	record, err := running.Record()
	if err != nil {
		return nil, err
	}
	name := params.Log
	if name == "" {
		name = sidecar.RecordLogNameVault
	}
	logId, err := record.ResolveLog(name)
	if err != nil {
		return nil, err
	}
	by, err := sidecar.ParseRecordCostBy(params.By)
	if err != nil {
		return nil, err
	}
	if err := sidecar.CheckRecordCostQuery(by, params.Clients); err != nil {
		return nil, err
	}
	rows, err := record.CostReport(ctx, logId, &sidecar.RecordCostQuery{
		SinceMillis: params.SinceMillis, UntilMillis: params.UntilMillis, By: by, Clients: params.Clients,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &urRecordCostReply{LogId: logId, Rows: rows}, nil
}

// The cost method over target, when it runs a Sidecar's record.
func urRecordCostMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	costs, ok := target.(urRecordCostTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name: urMethodRecordCost,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &urRecordCostParams{}
			if err := decodeUrParams(call, params); err != nil {
				return nil, errors.New("a cost report takes a log, times, a grouping and a map")
			}
			return costs.recordCost(ctx, params)
		},
	}}
}

// Reads the options, has the daemon sum the log, and prints the rows.
func runUrRecordCost(ctx context.Context, cli *urCli, options docopt.Opts) error {
	params := &urRecordCostParams{Log: urOptionString(options, "--log"), By: urOptionString(options, "--by")}
	if _, err := sidecar.ParseRecordCostBy(params.By); err != nil {
		return err
	}
	format, err := sidecar.ParseRecordCostFormat(urOptionString(options, "--format"))
	if err != nil {
		return err
	}
	if params.SinceMillis, err = parseUrRecordTime(urOptionString(options, "--since")); err != nil {
		return err
	}
	if params.UntilMillis, err = parseUrRecordTime(urOptionString(options, "--until")); err != nil {
		return err
	}
	if path := urOptionString(options, "--map"); path != "" {
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if params.Clients, err = sidecar.ParseRecordCostMap(content, nil); err != nil {
			return err
		}
	}
	// a report by client with no map is refused here, before the daemon is asked
	if err := sidecar.CheckRecordCostQuery(sidecar.RecordCostBy(params.By), params.Clients); err != nil {
		return err
	}
	reply := &urRecordCostReply{}
	if err := cli.callDaemon(ctx, urMethodRecordCost, params, false, reply); err != nil {
		return err
	}
	formatted, err := sidecar.FormatRecordCost(reply.Rows, format)
	if err != nil {
		return err
	}
	_, err = cli.stdout.Write(formatted)
	return err
}
