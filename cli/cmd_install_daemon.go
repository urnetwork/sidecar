// ur install-daemon and ur uninstall-daemon (§5.8, R-CORE-6): the instance's daemon as a unit of the OS's service
// manager, as the user, never idling out (unit.go), and for the default instance the native host's manifests, which
// let URnetwork's extension reach it (native_host_manifest.go). `ur indexer add` installs the unit if absent through
// installDaemonUnitIfAbsent (CORE-M2-09; the command is TEAM-M2-18's).
//
// uninstall-daemon first retires the device's indexer designations, IndexerSet{retire} in each network that stands it,
// confirmed on /dev/tty, and stops, saying why, when a retire cannot land or a network's designations cannot be read,
// since a designation left standing lists a dead indexer (CORE-M2-09). --purge then logs every network out, each
// signing its SidecarRevoke{removed} first (CORE-M2-07), and stops with everything kept if one cannot; then the unit
// goes and, with --purge, <state>.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "install-daemon",
		usage:   "  ur install-daemon",
		summary: "run the instance's daemon from the OS at login",
		run:     runUrInstallDaemon,
	})
	registerUrCommand(&urCommand{
		name:    "uninstall-daemon",
		usage:   "  ur uninstall-daemon [--purge]",
		summary: "stop and remove the daemon's unit; --purge also logs out and deletes state",
		run:     runUrUninstallDaemon,
	})
}

func runUrInstallDaemon(ctx context.Context, cli *urCli, options docopt.Opts) error {
	env, err := cli.unitEnv()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err := installDaemonUnit(ctx, env, cli.unitRunner(cli), cli.instance, executable); err != nil {
		return err
	}
	cli.printf("the daemon of instance %s runs from its unit\n", cli.instance)
	plan, err := cli.nativeHostPlan(env, executable)
	if err != nil {
		return err
	}
	if err := installNativeHostPlan(ctx, cli.unitRunner(cli), plan); err != nil {
		return err
	}
	if plan != nil {
		cli.printf("URnetwork's extension reaches it through ur native-host\n")
	}
	return nil
}

// The native host's manifests for this instance, nil when it is not the default instance or no extension id is
// configured (native_host_manifest.go).
func (self *urCli) nativeHostPlan(env *unitEnv, executable string) (*nativeHostPlan, error) {
	if self.instance != nativeHostInstance {
		return nil, nil
	}
	ids, err := self.nativeHostIds()
	if err != nil {
		return nil, err
	}
	stateDirectory, err := self.stateDirectory(self.instance)
	if err != nil {
		return nil, err
	}
	return nativeHostPlanFor(env, stateDirectory, self.instance, executable, ids)
}

func runUrUninstallDaemon(ctx context.Context, cli *urCli, options docopt.Opts) error {
	purge, _ := options.Bool("--purge")
	env, err := cli.unitEnv()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err := retireDaemonIndexer(ctx, cli); err != nil {
		return err
	}
	if purge {
		confirmed, err := confirmOnTty(cli, fmt.Sprintf("sign instance %s out of every network, remove its clients and delete all of its state?", cli.instance))
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing changed\n")
			return nil
		}
		// every network signs out and its client goes first, while the daemon still runs; a failure keeps everything
		status := &urStatusReply{}
		if err := cli.callDaemon(ctx, urMethodStatus, &urStatusParams{}, false, status); err != nil {
			return fmt.Errorf("uninstall stopped: %w", err)
		}
		for _, network := range status.Networks {
			params := &urNetworkParams{Network: network.NetworkId.String()}
			if err := cli.callDaemon(ctx, urMethodLogout, params, true, nil); err != nil && !isNothingEnrolled(err) {
				return fmt.Errorf("uninstall stopped: network %s did not sign out: %w", network.NetworkId, err)
			}
		}
	}
	if err := uninstallDaemonUnit(ctx, env, cli.unitRunner(cli), cli.instance, executable); err != nil {
		return err
	}
	plan, err := cli.nativeHostPlan(env, executable)
	if err != nil {
		return err
	}
	if err := uninstallNativeHostPlan(ctx, cli.unitRunner(cli), plan); err != nil {
		return err
	}
	if purge {
		stateDirectory, err := cli.stateDirectory(cli.instance)
		if err != nil {
			return err
		}
		if err := os.RemoveAll(stateDirectory); err != nil {
			return err
		}
	}
	cli.printf("the daemon unit of instance %s is removed\n", cli.instance)
	return nil
}

// Whether a logout found nothing to remove, which a purge goes on from.
func isNothingEnrolled(err error) bool {
	rpcErr, ok := err.(*sidecar.DaemonRpcError)
	return ok && rpcErr.Code == sidecar.DaemonRpcFailed && rpcErr.Message == sidecar.ErrSidecarNoIdentity.Error()
}

// The control methods uninstall-daemon reads and runs: the designations standing for this device, and their retirement,
// a Confirm method, since IndexerSet is signed only for a ur command confirmed on /dev/tty (§5.8, D-CORE-13).
const (
	urMethodIndexerDesignations = "indexer.designations"
	urMethodIndexerRetire       = "indexer.retire"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urIndexerMethods)
}

// What the indexer methods act on: a target hosting Sidecars.
type urIndexerTarget interface {
	// How many designations stand for this device across its networks, and why a network's cannot be read, if one's
	// cannot.
	indexerDesignations() (int, string)
	// Retires every designation standing for this device, as the person confirmed it.
	retireIndexers(ctx context.Context) (int, error)
}

// indexer.designations' reply.
type urIndexerDesignationsReply struct {
	Count int `json:"count"`
	// Why a network's designations cannot be read: none of them may be taken as none.
	Unknown string `json:"unknown,omitempty"`
}

// indexer.retire's reply.
type urIndexerRetireReply struct {
	Retired int `json:"retired"`
}

func (self *urDaemonNetwork) indexerDesignations() (int, string) {
	count := 0
	for _, network := range self.hosted() {
		designations, err := network.Sidecar.IndexerDesignations()
		if err != nil {
			return count, fmt.Sprintf("network %s: %s", network.NetworkId, err)
		}
		count += len(designations)
	}
	return count, ""
}

func (self *urDaemonNetwork) retireIndexers(ctx context.Context) (int, error) {
	retired := 0
	for _, network := range self.hosted() {
		count, err := network.Sidecar.RetireIndexer(ctx)
		retired += count
		if err != nil {
			return retired, fmt.Errorf("network %s: %w", network.NetworkId, err)
		}
	}
	return retired, nil
}

// The indexer methods over target, when it hosts Sidecars.
func urIndexerMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	indexers, ok := target.(urIndexerTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodIndexerDesignations,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				count, unknown := indexers.indexerDesignations()
				return &urIndexerDesignationsReply{Count: count, Unknown: unknown}, nil
			},
		},
		{
			Name:    urMethodIndexerRetire,
			Confirm: true,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				retired, err := indexers.retireIndexers(ctx)
				if err != nil {
					return nil, err
				}
				return &urIndexerRetireReply{Retired: retired}, nil
			},
		},
	}
}

// Retires the device's indexer designations before its daemon's unit goes (CORE-M2-09), asking the person on
// /dev/tty when any stand. Stops, saying why, when they cannot be read or a retire does not land.
func retireDaemonIndexer(ctx context.Context, cli *urCli) error {
	designations := &urIndexerDesignationsReply{}
	if err := cli.callDaemon(ctx, urMethodIndexerDesignations, nil, false, designations); err != nil {
		return fmt.Errorf("uninstall stopped: this device's indexer designations could not be read: %w", err)
	}
	if designations.Unknown != "" {
		return fmt.Errorf("uninstall stopped: this device's indexer designations could not be read, and a designation left standing lists a dead indexer: %s", designations.Unknown)
	}
	if designations.Count == 0 {
		return nil
	}
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("this device is an indexer under %d designation(s): retire them before its daemon goes?", designations.Count))
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("uninstall stopped: the indexer designations stand, and a designation left standing lists a dead indexer")
	}
	retired := &urIndexerRetireReply{}
	if err := cli.callDaemon(ctx, urMethodIndexerRetire, nil, true, retired); err != nil {
		return fmt.Errorf("uninstall stopped: the indexer designations did not retire: %w", err)
	}
	cli.printf("retired %d indexer designation(s)\n", retired.Retired)
	return nil
}

// Installs the instance's daemon unit when it is not installed, as `ur indexer add` asks (CORE-M2-09), so an indexer
// restarts at the user's login, or at boot under linger (owner decision 150). Reports whether it installed one. A
// unit that is there already is left as it is; Windows' task, which has no file to look for, installs again, which
// changes nothing.
func installDaemonUnitIfAbsent(ctx context.Context, cli *urCli) (bool, error) {
	env, err := cli.unitEnv()
	if err != nil {
		return false, err
	}
	executable, err := os.Executable()
	if err != nil {
		return false, err
	}
	plan, err := unitPlanFor(env, cli.instance, executable)
	if err != nil {
		return false, err
	}
	if plan.path != "" {
		if _, err := os.Stat(plan.path); err == nil {
			return false, nil
		}
	}
	if err := installDaemonUnit(ctx, env, cli.unitRunner(cli), cli.instance, executable); err != nil {
		return false, err
	}
	return true, nil
}
