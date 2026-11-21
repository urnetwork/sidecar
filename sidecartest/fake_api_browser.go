package sidecartest

import "github.com/urnetwork/sidecar"

// NewPageClient mints a top-level, limited browser client for a personal-network
// fixture. Only the nominated owner's current, bound native client may subsequently
// request the candidate's browser-admission view. The browser must bind its own keys.
func (self *FakeApi) NewPageClient(networkId, memberId, signerClientId sidecar.Id) (sidecar.Id, string, bool) {
	clientId := sidecar.NewId()
	allowed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if memberId == (sidecar.Id{}) || self.core.ownerUserIds[networkId] != memberId || !self.currentBrowserFixtureBinding(networkId, signerClientId) {
			return false
		}
		self.core.pageSigners[clientId] = signerClientId
		return true
	}()
	if !allowed {
		return sidecar.Id{}, "", false
	}
	return clientId, self.mintClientToken(&fakeApiClient{
		networkId: networkId, clientId: clientId, deviceId: sidecar.NewId(), sessionId: sidecar.NewId(),
		strictExp: true, adminRefused: true, pageReader: true, createTime: self.clock.Now(),
	}), true
}

func (self *FakeApi) ownPageCandidate(caller *fakeApiClient, candidate *fakeApiIdentityResult) bool {
	binding, err := sidecar.VerifySidecarIdentityBinding(candidate.Binding)
	if err != nil || candidate.Status != fakeApiIdentityActive || binding.NetworkId != caller.networkId || caller.clientId == binding.ClientId {
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.core.pageSigners[binding.ClientId] == caller.clientId &&
		self.currentBrowserFixtureBinding(caller.networkId, caller.clientId) && self.currentBrowserFixtureBinding(caller.networkId, binding.ClientId)
}

// The caller holds stateLock.
func (self *FakeApi) currentBrowserFixtureBinding(networkId, clientId sidecar.Id) bool {
	binding := self.core.clientBindings[clientId]
	if binding == nil || self.removedClientIds[clientId] || self.core.endedSessionClientIds[clientId] {
		return false
	}
	identity := self.core.identities[binding.sidecarId]
	return identity != nil && identity.networkId == networkId && identity.status == fakeApiIdentityActive && identity.newest == binding.generation
}
