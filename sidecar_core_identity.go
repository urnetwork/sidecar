//go:build !ios_extension

// The app and daemon restore their enrolled sidecar identity before starting a client generation.

package sidecar

import (
	"bytes"
	"errors"
)

// The open instance's half: read this network's identity and token, and run its generation.
func (self *Sidecar) reconcileOpen() {
	var networkId *Id
	var revoked bool
	var endedGeneration int64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.networkId != nil {
			id := *self.networkId
			networkId = &id
		}
		revoked = self.lifecycle.state == SidecarStateRevoked
		endedGeneration = self.endedGeneration
	}()
	if revoked {
		self.stopGeneration()
		return
	}
	if networkId == nil {
		// not enrolled in any network yet
		self.stopGeneration()
		self.leaveForUnenrolled("")
		return
	}
	secrets := self.instance.secrets(*networkId, sidecarCoreSecretsNamespace)
	restored := self.instance.networkRestored(networkId)
	if self.runningGeneration() == nil && self.enrollLock.TryLock() {
		bound, err := self.resumeBinding(self.ctx, networkId, false, bindingRecovery, nil)
		self.enrollLock.Unlock()
		if bound != nil {
			// finishBinding woke the loop after installing every local record.
			return
		}
		if err != nil && !errors.Is(err, ErrSidecarKeystoreLost) && !errors.Is(err, ErrSidecarStoreLocked) && !restored {
			self.log.Warningf("[identity]the pending binding did not finish: %s", err)
			self.setIdentity(nil, nil)
			self.leaveForUnenrolled("")
			return
		}
	}
	if restored {
		self.stopGeneration()
		self.setIdentity(nil, nil)
		self.leaveForUnenrolled("")
		return
	}
	record, err := loadSidecarIdentity(secrets)
	switch {
	case err == nil:
	case errors.Is(err, ErrSidecarNoIdentity):
		self.setIdentity(secrets, nil)
		self.stopGeneration()
		self.leaveForUnenrolled("")
		return
	case errors.Is(err, ErrSidecarKeystoreLost):
		self.stopGeneration()
		self.leaveForUnenrolled(SidecarReasonKeystoreLost)
		return
	case errors.Is(err, ErrSidecarStoreLocked):
		// the instance locked under us, which wakes the loop again
		self.stopGeneration()
		self.enterLocked()
		return
	default:
		// a keychain that fails decoding or AEAD: as Locked, and alarms, creating nothing (D-CORE-15)
		self.log.Warningf("[sidecar]the network's keychain failed: %s", err)
		self.stopGeneration()
		self.enterLocked()
		self.emitEvent(SidecarEvent{Kind: SidecarEventRefused})
		return
	}
	defer record.keys.erase()
	self.setIdentity(secrets, record.identity)
	if self.lifecycleState() == SidecarStateLocked {
		self.leaveForUnenrolled("")
	}

	identity := record.identity
	if identity.Generation <= endedGeneration {
		// refused: only a re-enrollment, which binds the next generation, goes on (D-CORE-8)
		self.stopGeneration()
		return
	}
	if running := self.runningGeneration(); running != nil && running.generation == identity.Generation {
		if running.leg != nil {
			running.leg.reconcileComponents()
		}
		return
	}
	byJwt, err := loadSidecarByJwt(secrets)
	if err != nil {
		if !errors.Is(err, ErrSidecarStoreAbsent) {
			self.log.Warningf("[sidecar]the client token did not load: %s", err)
		}
		self.stopGeneration()
		self.leaveForUnenrolled("")
		return
	}
	if _, tokenClientId, ok := sidecarJwtClient(byJwt); !ok || tokenClientId != identity.ClientId {
		// the identity and its token are written one after the other, so an enrollment a kill cut short can leave
		// one generation's token beside another's binding: that runs no client
		self.log.Warningf("[sidecar]the client token is not generation %d's", identity.Generation)
		self.stopGeneration()
		self.leaveForUnenrolled("")
		return
	}
	networkRecord, ok := self.networkRecordOf(*networkId)
	if !ok || networkRecord.ClientId != identity.ClientId || networkRecord.SidecarId != identity.SidecarId {
		// The keychain and the network record must name the same committed client.
		self.log.Warningf("[sidecar]an identity with no matching network record does not start")
		self.stopGeneration()
		self.leaveForUnenrolled("")
		return
	}
	self.stopGeneration()
	self.startGeneration(&sidecarGenerationArgs{
		identity:          identity.clone(),
		networkId:         *networkId,
		connectInstanceId: networkRecord.ConnectInstanceId,
		byJwt:             byJwt,
		clientKeySeed:     record.keys.clientKeySeedCopy(),
		binding:           bytes.Clone(record.binding),
		secrets:           secrets,
		child:             networkRecord.Child,
	})
}
