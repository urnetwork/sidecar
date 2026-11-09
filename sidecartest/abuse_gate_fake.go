// ServiceHost.Abuse in memory (host_abuse.go): a network's §21.7 standing and its network_verified as a
// test loads them, where ABUSE-M5-07's gate loads them from api. It starts with no network loaded, as a
// host's gate does, so every gate that reads it refuses until a test loads the network: an unloaded
// network answers ok false, never a pass (I-12). A standing and a verification load apart, as a real
// gate may load one before the other, and Unload forgets both, as an eviction does. A test may load a
// standing this build does not know, to hold a gate to refusing it. Nothing here does I/O, so it is as
// fit for an inline path as the real gate.

package sidecartest

import (
	"sync"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// Safe for concurrent use.
type FakeAbuseGate struct {
	stateLock          sync.Mutex
	networkIdStandings map[connect.Id]sidecar.AbuseStanding
	networkIdVerifieds map[connect.Id]bool
}

// No network loaded.
func NewFakeAbuseGate() *FakeAbuseGate {
	return &FakeAbuseGate{
		networkIdStandings: map[connect.Id]sidecar.AbuseStanding{},
		networkIdVerifieds: map[connect.Id]bool{},
	}
}

// Loads the network with both facts.
func (self *FakeAbuseGate) Set(networkId connect.Id, standing sidecar.AbuseStanding, verified bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkIdStandings[networkId] = standing
	self.networkIdVerifieds[networkId] = verified
}

// Loads the network's standing, leaving its verification as it was.
func (self *FakeAbuseGate) SetStanding(networkId connect.Id, standing sidecar.AbuseStanding) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkIdStandings[networkId] = standing
}

// Loads the network's verification, leaving its standing as it was.
func (self *FakeAbuseGate) SetVerified(networkId connect.Id, verified bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkIdVerifieds[networkId] = verified
}

// Forgets both facts, so the network reads unloaded again.
func (self *FakeAbuseGate) Unload(networkId connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.networkIdStandings, networkId)
	delete(self.networkIdVerifieds, networkId)
}

func (self *FakeAbuseGate) Standing(networkId connect.Id) (sidecar.AbuseStanding, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	standing, ok := self.networkIdStandings[networkId]
	return standing, ok
}

func (self *FakeAbuseGate) Verified(networkId connect.Id) (bool, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	verified, ok := self.networkIdVerifieds[networkId]
	return verified, ok
}
