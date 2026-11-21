// The daemon's config followers (QD-796): each hosted network's Sidecar runs one, the device's one judge of the
// network's §7.9 log (sidecar.SidecarConfigFollower). The daemon starts it with the Sidecar (startUrConfigFollower), so
// every network sidecar.json records at a start and the Sidecar a further enrollment takes have one, and builds the
// network's bridge over it when ur tun or ur tun ip first asks (newUrBridgeBuild over bridge_wire.go's
// newUrBridgeWire): the bridge follows no log of its own.
//
// A follower takes what the daemon's composition gives it (daemon_clients.go): the config repo's head reader over evs
// (urDaemonConfigHeads), on the network's EvsClient over its key client (cmd_keys.go's urDaemonGkmClient); with either
// unset every base stays withheld and nothing past the genesis installs. A ur device whose
// enrollment recorded no anchor trusts the first genesis api serves (§5.6's genesis row), and keeps the log's full tail
// in authlog/, as §7.9's retain row has a CLI host's member device do. A network whose follower does not start runs on
// unjudged, nothing admitted on it, and the daemon's other networks follow on (CORE-M6-01).
//
// Beside each follower the daemon runs the network's scim_signer (QD-829; sidecar.SidecarScimSigner, startUrScimSigner):
// it reads the state the follower installs, and only while this network's Sidecar is the one ServiceSettings.scim_signer
// names does it install SCIM's queue source over the Sidecar's api, GET /sidecar/scim-changes (urDaemonScimSource), which
// its ConfigScimSigner signs the queued removals of members outside the AdminSet from (§7.6, D-TEAM-25).

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
)

// The config repo's head reader over evs for a hosted network's Sidecar: the daemon's composition's
// (daemon_clients.go), sidecar.EvsConfigHeadReader over the network's EvsClient. Nil for none, which withholds every
// base.
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

// SCIM's queue source over a network Sidecar's api, which that network's scim_signer makes only while the Sidecar is the
// one ServiceSettings.scim_signer names (QD-829). Nil is GET /sidecar/scim-changes; a test replaces it.
var urDaemonScimSource func(api *sidecar.SidecarApi) sidecar.ScimChangeSource

// The settings each network's scim_signer runs on: the defaults, a pass every minute while designated.
func urScimSignerSettings() *sidecar.ConfigScimSignerSettings {
	return sidecar.DefaultConfigScimSignerSettings()
}

// Starts running's scim_signer, which installs SCIM's queue source only while running is the sidecar
// ServiceSettings.scim_signer names, and logs why where it cannot start: running then signs no SCIM removal, and
// nothing else changes. Nil when none started.
func startUrScimSigner(running *sidecar.Sidecar, log sidecar.Logger) *sidecar.SidecarScimSigner {
	scimSigner, err := running.RunScimSigner(&sidecar.SidecarScimSignerArgs{
		Settings:  urScimSignerSettings(),
		NewSource: urDaemonScimSource,
	})
	if err != nil {
		log.Warningf("[ur]a network runs no scim_signer, so it signs no SCIM removal: %s", err)
		return nil
	}
	return scimSigner
}

// Starts running's config follower, as the daemon does with every Sidecar it starts, and logs why where it cannot: the
// Sidecar then runs unjudged, and the daemon's other networks are untouched. Nil when none started. A follower that
// starts has the network's scim_signer started beside it (startUrScimSigner), which reads the state it installs.
func startUrConfigFollower(running *sidecar.Sidecar, log sidecar.Logger) *sidecar.SidecarConfigFollower {
	args := &sidecar.SidecarConfigFollowerArgs{Settings: urConfigFollowerSettings(), BootstrapFirstOwner: true}
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
	installSockets := func() {
		// The Sidecar owns the component and closes it at removal or daemon shutdown.
		component, err := running.NewSocketComponent(context.Background())
		if err == nil {
			_, err = running.AddComponent(component)
			if err != nil {
				component.Close()
			}
		}
		if err != nil && !errors.Is(err, sidecar.ErrSidecarClosed) {
			log.Warningf("[ur]a network could not start its sockets: %s", err)
		}
	}
	if running.NetworkId() != nil {
		installSockets()
	} else {
		// Platform sockets only need enrollment. Application sockets additionally wait for verified config.
		go installSockets()
	}
	startUrScimSigner(running, log)
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
		// the engine ur bridge's previews ask holds the routes in force the device role's state was compiled from
		installRoutes := func(servedRoutes *sidecar.AclServedRoutes) {
			if engine := follower.AclEngine(); engine != nil {
				engine.InstallRoutes(servedRoutes)
			}
		}
		wire, err := newUrBridgeWire(ctx, &urBridgeWireArgs{
			NetworkId:       networkId,
			Sidecar:         running,
			Config:          client,
			Heads:           follower.Heads(),
			Rows:            follower.Rows(),
			RepoKeyAt:       follower.RepoKeyAt,
			AclLocal:        follower.AclLocal,
			ServedRoutes:    installRoutes,
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
