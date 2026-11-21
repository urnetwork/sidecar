//go:build !sidecar_http && !ios_extension

package sidecar

import "github.com/urnetwork/sidecar/protocol"

// The config and locally held keys of one enrolled network, used by both remote search hosts.
type searchRemoteHostAuthority struct {
	running   *Sidecar
	networkId Id
	services  func(ConfigIndexer) ([]protocol.IndexerService, bool)
}

func newSearchRemoteHostAuthority(running *Sidecar, networkId Id) *searchRemoteHostAuthority {
	source := &searchRemoteHostAuthority{running: running, networkId: networkId}
	source.services = ConfigIndexerServicesOpener(source.configKeyAt)
	return source
}

// Only a standing follower's published state authorizes a remote search.
func (self *searchRemoteHostAuthority) config() (*ConfigState, error) {
	follower := self.running.ConfigFollower()
	if follower == nil {
		return nil, ErrSidecarSearchUnavailable
	}
	client := follower.Client()
	if client == nil || client.NetworkId() != self.networkId || client.Fork() != nil {
		return nil, ErrSidecarSearchUnavailable
	}
	state := client.State()
	if state == nil || state.NetworkId() != self.networkId {
		return nil, ErrSidecarSearchUnavailable
	}
	return state, nil
}

// Reading a signed designation never opens a network connection.
func (self *searchRemoteHostAuthority) configKeyAt(generation uint64) *EvsRepoKey {
	state, err := self.config()
	if err != nil {
		return nil
	}
	repoId, err := IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		return nil
	}
	key := self.running.GkmHeldKey(repoId, generation)
	if key == nil || key.RepoId() != repoId || key.Generation() != generation {
		return nil
	}
	return key
}

func (self *searchRemoteHostAuthority) selfId() (Id, bool) {
	identity := self.running.currentIdentity()
	if identity == nil || identity.NetworkId != self.networkId {
		return Id{}, false
	}
	return identity.SidecarId, true
}
