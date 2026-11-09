// ur install-daemon and ur uninstall-daemon (§5.8, R-CORE-6): the instance's daemon as a unit of the OS's service
// manager, as the user, never idling out (unit.go), and for the default instance the native host's manifests, which
// let URnetwork's extension reach it (native_host_manifest.go). At M1, uninstall-daemon --purge has the daemon remove its client
// and wipe its network's state (ur logout's M1 half) before the unit goes, then deletes <state>; the SidecarRevoke
// --purge signs is CORE-M2-07's, and retiring indexer designations CORE-M2-09's.

package main

import (
	"context"
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
	if purge {
		confirmed, err := confirmOnTty(cli, fmt.Sprintf("remove instance %s's client and delete all of its state?", cli.instance))
		if err != nil {
			return err
		}
		if !confirmed {
			cli.printf("nothing changed\n")
			return nil
		}
		// the client goes first, while the daemon still runs; a failure here keeps everything
		if err := cli.callDaemon(ctx, urMethodLogout, nil, true, nil); err != nil && !isNothingEnrolled(err) {
			return err
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
