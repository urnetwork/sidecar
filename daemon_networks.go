//go:build !js && !ios && !android && !sdk_mobile_bind

// Several networks per daemon (§5.8, CORE-M6-01; Q-CORE-6, owner decision 23): ur daemon hosts one Sidecar per network,
// every one on the instance's SidecarInstance, so one U opens every network's keychain at once, and none shares a
// client, a root key R_n or an identity key with another: each has its own sidecar_id, R_n, InstanceId, recovery code
// and generation (§5.9, D-CORE-14), and a team network's sidecar is a top-level one (§20.8). A network whose keychain
// fails goes Locked alone, and its neighbors run on; a network's logout closes its Sidecar and leaves the others
// running. Nothing here keeps a cache keyed only by member: a person is unlinkable across networks by any key
// (R-CORE-15), so each Sidecar's state is its own.
//
// A call picks its network by §5.8's rule (daemon_project.go's ResolveNetwork), and a git session by its <net>, both
// among the networks this registry holds. The registry is safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"slices"
)

var (
	// A Sidecar is already hosted for the network.
	ErrDaemonNetworkHosted = errors.New("a sidecar of this network is hosted already")
)

// One network a daemon hosts.
type DaemonNetwork struct {
	NetworkId Id
	Sidecar   *Sidecar
}

// Hosts sidecar as networkId's, refusing a second Sidecar for a network and a nil one.
func (self *Daemon) AddSidecar(networkId Id, sidecar *Sidecar) error {
	if sidecar == nil || networkId == (Id{}) {
		return fmt.Errorf("%w: a hosted network needs its id and sidecar", ErrDaemonRegistration)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.networkIdSidecars == nil {
		self.networkIdSidecars = map[Id]*Sidecar{}
	}
	if _, ok := self.networkIdSidecars[networkId]; ok {
		return ErrDaemonNetworkHosted
	}
	self.networkIdSidecars[networkId] = sidecar
	return nil
}

// Stops hosting networkId, answering the Sidecar it hosted, which the caller closes. A network not hosted answers nil.
func (self *Daemon) RemoveSidecar(networkId Id) *Sidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sidecar := self.networkIdSidecars[networkId]
	delete(self.networkIdSidecars, networkId)
	return sidecar
}

// Every hosted network, in network id order.
func (self *Daemon) Sidecars() []DaemonNetwork {
	networks := func() []DaemonNetwork {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		networks := make([]DaemonNetwork, 0, len(self.networkIdSidecars))
		for networkId, sidecar := range self.networkIdSidecars {
			networks = append(networks, DaemonNetwork{NetworkId: networkId, Sidecar: sidecar})
		}
		return networks
	}()
	slices.SortFunc(networks, func(a DaemonNetwork, b DaemonNetwork) int {
		return a.NetworkId.Cmp(b.NetworkId)
	})
	return networks
}

// The Sidecar hosting networkId.
func (self *Daemon) SidecarForNetwork(networkId Id) (*Sidecar, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sidecar, ok := self.networkIdSidecars[networkId]
	return sidecar, ok
}
