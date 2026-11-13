// The daemon's config followers (QD-796): each hosted network's Sidecar runs one, the device's one judge of the
// network's §7.9 log (sidecar.SidecarConfigFollower). The daemon starts it with the Sidecar (startUrConfigFollower), so
// every network sidecar.json records at a start and the Sidecar a further enrollment takes have one, and builds the
// network's bridge over it when ur tun or ur tun ip first asks (newUrBridgeBuild over bridge_wire.go's
// newUrBridgeWire): the bridge follows no log of its own.
//
// A follower takes what the daemon gives it: the config repo's head reader over evs (urDaemonConfigHeads, nil until an
// EvsClient reads a file-mode ref at a config version, so every base stays withheld and nothing past the genesis
// installs) and the network's key client (cmd_keys.go's urDaemonGkmClient, nil until one is wired). A ur device whose
// enrollment recorded no anchor trusts the first genesis api serves (§5.6's genesis row), and keeps the log's full tail
// in authlog/, as §7.9's retain row has a CLI host's member device do. A network whose follower does not start runs on
// unjudged, nothing admitted on it, and the daemon's other networks follow on (CORE-M6-01).

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
)

// The config repo's head reader over evs for a hosted network's Sidecar, nil for none: no host has one until an
// EvsClient reads a file-mode ref at a config version (TEAM-M2-10's report), and every base is withheld until then.
var urDaemonConfigHeads func(running *sidecar.Sidecar) sidecar.ConfigHeadReader

// ur tun's answer for a network whose follower does not stand: it names what the follower waits for, or why it refused.
var errUrBridgeNotFollowing = errors.New("no bridge runs for this network yet: its config follower does not stand")

// The settings ur's daemon follows each network with: first use trusted, the full tail kept.
func urConfigFollowerSettings() *sidecar.SidecarConfigFollowerSettings {
	settings := sidecar.DefaultSidecarConfigFollowerSettings()
	settings.TrustFirstUse = true
	settings.ConfigClient = sidecar.DefaultConfigClientSettings()
	settings.ConfigClient.RetainFullTail = true
	return settings
}

// Starts running's config follower, as the daemon does with every Sidecar it starts, and logs why where it cannot: the
// Sidecar then runs unjudged, and the daemon's other networks are untouched. Nil when none started.
func startUrConfigFollower(running *sidecar.Sidecar, log sidecar.Logger) *sidecar.SidecarConfigFollower {
	args := &sidecar.SidecarConfigFollowerArgs{Settings: urConfigFollowerSettings()}
	if urDaemonConfigHeads != nil {
		args.Heads = urDaemonConfigHeads(running)
	}
	if urDaemonGkmClient != nil {
		gkm, err := urDaemonGkmClient(running)
		switch {
		case err == nil:
			args.Gkm = gkm
		case log.V(1).Enabled():
			log.Infof("[ur]a network's follower runs with no key client: %s", err)
		}
	}
	follower, err := running.FollowConfig(args)
	if err != nil {
		log.Warningf("[ur]a network follows no config, and nothing is admitted on it: %s", err)
		return nil
	}
	return follower
}

// What the daemon builds a network's bridge over beside the network's follower.
type urBridgeBuildArgs struct {
	// The instance's state directory, which keeps each network's posture.
	StateDirectory string
	// The daemon's local listeners, whose binds are rule 0's input. Nil for none.
	Listeners func() []sidecar.DaemonLocalListenerStatus
	// The settings the daemon's Sidecars run on, whose connect settings a link's generator dials with.
	Settings *sidecar.SidecarSettings
	Log      sidecar.Logger
}

// A builder of a network's bridge over the daemon's config follower for it (urBridgeDaemonArgs.Build): the follower's
// client, head reader, kept rows, the config repo's keys and its acl follower's local policy. Refuses a network that
// runs no follower (errUrBridgeUnwired) and one whose follower does not stand, naming why (errUrBridgeNotFollowing).
func newUrBridgeBuild(args *urBridgeBuildArgs) urBridgeBuildFunction {
	return func(ctx context.Context, networkId sidecar.Id, running *sidecar.Sidecar) (*urBridgeNetwork, error) {
		follower := running.ConfigFollower()
		if follower == nil {
			return nil, errUrBridgeUnwired
		}
		client := follower.Client()
		if client == nil {
			status := follower.Status()
			reason := string(status.State)
			if status.Reason != "" {
				reason += ": " + status.Reason
			}
			return nil, fmt.Errorf("%w (%s)", errUrBridgeNotFollowing, reason)
		}
		if client.NetworkId() != networkId {
			return nil, fmt.Errorf("%w: the sidecar's follower follows another network", errUrBridgeUnwired)
		}
		wire, err := newUrBridgeWire(ctx, &urBridgeWireArgs{
			NetworkId:       networkId,
			Sidecar:         running,
			Config:          client,
			Heads:           follower.Heads(),
			Rows:            follower.Rows(),
			RepoKeyAt:       follower.RepoKeyAt,
			AclLocal:        follower.AclLocal,
			StateDirectory:  args.StateDirectory,
			DaemonListeners: args.daemonListeners,
			SidecarSettings: args.Settings,
			Log:             args.Log,
		})
		if err != nil {
			return nil, err
		}
		return wire.network(), nil
	}
}

// Rule 0's input: each bind of the daemon's local listeners, host:port.
func (self *urBridgeBuildArgs) daemonListeners() []string {
	addresses := []string{}
	if self.Listeners == nil {
		return addresses
	}
	for _, listener := range self.Listeners() {
		addresses = append(addresses, listener.Addresses...)
	}
	return addresses
}
