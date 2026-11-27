// ur harness runs (DESIGN-COMPUTE §24.10's see row; CTXH-M11-06; R-CTXH-8, D-CTXH-8):
//
//	ur harness runs [--agent=<a>] [--size] [--network=<net>]
//	ur harness runs --expire [--cap=<cap>] [--network=<net>]
//	ur harness runs --auto-expire=<on> [--network=<net>]
//
// The member's runs with the context history each holds in the vault (the root's session_storage.go): newest first, or
// with --size largest first, each with its agent, the device that wrote it, its nodes' and its blobs' bytes apart, and
// what is held back or dropped; then history's totals by agent and by device, and the caps: at 80% of the network's
// storage or of the member's share a warning names the largest runs and the bytes the one tap frees. --agent names one
// agent, by its label or its id. Nothing here prints a run's text.
//
// --expire is the warning's one tap: the oldest blobs, class bulk, erased until history is under 70% of the cap warned
// at (--cap names network or member), every node kept, so runs stay readable and continuable, their oldest large parts
// reading as pruned. --auto-expire on or off is the switch that does so again at each cap. Each is the person's act,
// asked on the terminal and refused under a harness process, as an erasure is.

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

func init() {
	registerUrHarnessSubcommand(&urHarnessSubcommand{
		name: "runs",
		usage: "  ur harness runs [--agent=<a>] [--size] [--network=<net>]\n" +
			"  ur harness runs --expire [--cap=<cap>] [--network=<net>]\n" +
			"  ur harness runs --auto-expire=<on> [--network=<net>]",
		run: runUrHarnessRuns,
	})
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urHarnessRunsMethods)
}

// What the runs methods act on: a daemon target that runs a Sidecar's record. pid is the caller's, as the daemon read
// it.
type urHarnessRunsTarget interface {
	harnessRuns(ctx context.Context, params *sidecar.HarnessRunsParams) (*sidecar.SessionSizes, error)
	harnessRunsExpire(ctx context.Context, params *sidecar.HarnessRunsExpireParams, pid int, confirmed bool) (*sidecar.SessionExpired, error)
	harnessRunsAutoExpire(ctx context.Context, params *sidecar.HarnessRunsAutoExpireParams, pid int, confirmed bool) error
}

// The network's storage view.
func (self *urDaemonNetwork) sessionStorage() (*sidecar.Sidecar, *sidecar.SessionStorage, error) {
	running, err := self.onlySidecar()
	if err != nil {
		return nil, nil, err
	}
	storage, err := running.SessionStorage()
	if err != nil {
		return nil, nil, err
	}
	return running, storage, nil
}

func (self *urDaemonNetwork) harnessRuns(ctx context.Context, params *sidecar.HarnessRunsParams) (*sidecar.SessionSizes, error) {
	_, storage, err := self.sessionStorage()
	if err != nil {
		return nil, err
	}
	return storage.Sizes(ctx, &params.SessionSizesFilter)
}

func (self *urDaemonNetwork) harnessRunsExpire(ctx context.Context, params *sidecar.HarnessRunsExpireParams, pid int, confirmed bool) (*sidecar.SessionExpired, error) {
	running, storage, err := self.sessionStorage()
	if err != nil {
		return nil, err
	}
	return storage.ExpireOldestBlobs(ctx, &sidecar.SessionExpireArgs{Cap: params.Cap, Confirmed: confirmed, HarnessAncestor: running.HarnessAncestor(ctx, pid)})
}

func (self *urDaemonNetwork) harnessRunsAutoExpire(ctx context.Context, params *sidecar.HarnessRunsAutoExpireParams, pid int, confirmed bool) error {
	running, storage, err := self.sessionStorage()
	if err != nil {
		return err
	}
	return storage.SetAutoExpire(params.On, confirmed, running.HarnessAncestor(ctx, pid))
}

// The runs methods over target, when it runs a Sidecar's record.
func urHarnessRunsMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	runs, ok := target.(urHarnessRunsTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: sidecar.HarnessDaemonMethodRuns,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &sidecar.HarnessRunsParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, errors.New("the runs view's params do not decode")
				}
				return runs.harnessRuns(ctx, params)
			},
		},
		{
			Name:    sidecar.HarnessDaemonMethodRunsExpire,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &sidecar.HarnessRunsExpireParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, errors.New("an expiry's params do not decode")
				}
				return runs.harnessRunsExpire(ctx, params, urCallPid(call), call.Confirmed)
			},
		},
		{
			Name:    sidecar.HarnessDaemonMethodRunsAutoExpire,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				params := &sidecar.HarnessRunsAutoExpireParams{}
				if err := decodeUrParams(call, params); err != nil {
					return nil, errors.New("the switch's params do not decode")
				}
				return struct{}{}, runs.harnessRunsAutoExpire(ctx, params, urCallPid(call), call.Confirmed)
			},
		},
	}
}

// A byte count as a person reads it.
func urHarnessRunsBytes(byteCount int64) string {
	switch {
	case byteCount < 1024:
		return fmt.Sprintf("%d B", byteCount)
	case byteCount < 1024*1024:
		return fmt.Sprintf("%.1f KiB", float64(byteCount)/1024)
	case byteCount < 1024*1024*1024:
		return fmt.Sprintf("%.1f MiB", float64(byteCount)/(1024*1024))
	}
	return fmt.Sprintf("%.2f GiB", float64(byteCount)/(1024*1024*1024))
}

// The view as a person reads it.
func printUrHarnessRuns(cli *urCli, sizes *sidecar.SessionSizes) {
	for _, run := range sizes.Runs {
		agent := run.AgentLabel
		if agent == "" && run.AgentId != nil {
			agent = run.AgentId.String()
		}
		line := fmt.Sprintf("%s  %s  %s  nodes %d %s, blobs %d %s", run.RunId, time.UnixMilli(run.LastMillis).UTC().Format(time.RFC3339), agent,
			run.NodeCount, urHarnessRunsBytes(run.NodeByteCount), run.BlobCount, urHarnessRunsBytes(run.BlobByteCount))
		if run.ContinuesRunId != nil {
			line += ", continues " + run.ContinuesRunId.String()
		}
		if 0 < run.WithheldCount {
			line += fmt.Sprintf(", %d held back", run.WithheldCount)
		}
		if 0 < run.DroppedCount {
			line += fmt.Sprintf(", %d dropped", run.DroppedCount)
		}
		if 0 < run.ErasedCount {
			line += fmt.Sprintf(", %d erased", run.ErasedCount)
		}
		if run.Open {
			line += ", open here"
		}
		cli.printf("%s\n", line)
	}
	cli.printf("history: nodes %s, blobs %s, of the vault's %s\n", urHarnessRunsBytes(sizes.NodeByteCount), urHarnessRunsBytes(sizes.BlobByteCount),
		urHarnessRunsBytes(sizes.VaultByteCount))
	for _, group := range sizes.ByAgent {
		cli.printf("  agent %s: %d runs, nodes %s, blobs %s\n", group.Id, group.RunCount, urHarnessRunsBytes(group.NodeByteCount), urHarnessRunsBytes(group.BlobByteCount))
	}
	for _, group := range sizes.ByDevice {
		cli.printf("  device %s: %d runs, nodes %s, blobs %s\n", group.Id, group.RunCount, urHarnessRunsBytes(group.NodeByteCount), urHarnessRunsBytes(group.BlobByteCount))
	}
	caps := sizes.Caps
	if caps == nil {
		return
	}
	if caps.StorageLimit < 0 {
		cli.printf("no storage limit holds history now\n")
		return
	}
	estimated := ""
	if caps.NetworkUsedEstimated {
		estimated = " (this vault's alone: no route reports the network's)"
	}
	cli.printf("network: %s of %s stored%s, history stops at %s; your share: %s of %s\n", urHarnessRunsBytes(caps.NetworkUsed),
		urHarnessRunsBytes(caps.StorageLimit), estimated, urHarnessRunsBytes(caps.NetworkCap), urHarnessRunsBytes(caps.MemberUsed), urHarnessRunsBytes(caps.MemberCap))
	if caps.Capped() {
		cli.printf("history is at its cap: calls are still recorded, and their bodies wait on this device (%d held, %s) until there is room\n",
			caps.HeldBodyCount, urHarnessRunsBytes(caps.HeldByteCount))
	}
	if caps.Warning != "" {
		cli.printf("warning: history is near the %s cap; the largest runs:\n", caps.Warning)
		for _, run := range sizes.Largest {
			cli.printf("  %s  %s\n", run.RunId, urHarnessRunsBytes(run.ByteCount()))
		}
		cli.printf("ur harness runs --expire frees %s by expiring the oldest blobs; every node stays\n", urHarnessRunsBytes(caps.ExpiryNeed))
	}
}

// Lists the runs, or with --expire or --auto-expire asks on the terminal and has the daemon act.
func runUrHarnessRuns(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network := urOptionString(options, "--network")
	if urOptionBool(options, "--expire") {
		params := &sidecar.HarnessRunsExpireParams{Network: network, Cap: urOptionString(options, "--cap")}
		if params.Cap != "" && params.Cap != sidecar.SessionCapNetwork && params.Cap != sidecar.SessionCapMember {
			return fmt.Errorf("--cap is network or member, not %q", params.Cap)
		}
		confirmed, err := confirmOnTty(cli, "Expire the oldest blobs of your context history until it is under 70% of its cap? Every node stays; the "+
			"oldest large parts read as pruned.")
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing was expired\n")
			return nil
		}
		expired := &sidecar.SessionExpired{}
		if err := cli.callDaemon(ctx, sidecar.HarnessDaemonMethodRunsExpire, params, true, expired); err != nil {
			return err
		}
		cli.printf("expired %d blobs, %s of %s to free\n", expired.BlobCount, urHarnessRunsBytes(expired.ByteCount), urHarnessRunsBytes(expired.NeedCount))
		return nil
	}
	if text := urOptionString(options, "--auto-expire"); text != "" {
		if text != "on" && text != "off" {
			return fmt.Errorf("--auto-expire is on or off, not %q", text)
		}
		params := &sidecar.HarnessRunsAutoExpireParams{Network: network, On: text == "on"}
		question := "Expire the oldest blobs of your context history again whenever it reaches a cap?"
		if !params.On {
			question = "Stop expiring the oldest blobs at each cap?"
		}
		confirmed, err := confirmOnTty(cli, question)
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing was changed\n")
			return nil
		}
		if err := cli.callDaemon(ctx, sidecar.HarnessDaemonMethodRunsAutoExpire, params, true, &struct{}{}); err != nil {
			return err
		}
		cli.printf("expiry at each cap is %s\n", text)
		return nil
	}
	params := &sidecar.HarnessRunsParams{Network: network, SessionSizesFilter: sidecar.SessionSizesFilter{BySize: urOptionBool(options, "--size")}}
	if agent := urOptionString(options, "--agent"); agent != "" {
		if agentId, err := sidecar.ParseId(agent); err == nil {
			params.AgentId = &agentId
		} else {
			params.AgentLabel = agent
		}
	}
	sizes := &sidecar.SessionSizes{}
	if err := cli.callDaemon(ctx, sidecar.HarnessDaemonMethodRuns, params, false, sizes); err != nil {
		return err
	}
	printUrHarnessRuns(cli, sizes)
	return nil
}
