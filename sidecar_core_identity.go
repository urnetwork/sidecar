//go:build !ios_extension

// The app and daemon restore their enrolled sidecar identity before starting a client generation. On a leg whose
// generations run a connect client, the generation's connect identity comes with it (identity_connect.go): read with
// the identity at every pass, so a record that fails is Failed as the identity's would be, and drawn and kept at the
// generation's first start, before its client opens.

package sidecar

import (
	"bytes"
	"crypto/rand"
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
		if errors.Is(err, ErrSidecarStoreFailed) {
			self.lockFailedKeychain(err)
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
		self.lockFailedKeychain(err)
		return
	}
	defer record.keys.erase()
	keepsConnectIdentity := self.leg != nil && self.leg.keepsConnectIdentity()
	var connectIdentitySeed []byte
	if keepsConnectIdentity {
		connectIdentitySeed, err = loadSidecarConnectIdentitySeed(secrets, record.identity)
		if err != nil {
			self.connectIdentityFailed(err)
			return
		}
		defer clear(connectIdentitySeed)
	}
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
	if keepsConnectIdentity && connectIdentitySeed == nil {
		// the generation's first start, the keychain holding no record or a predecessor's: a connect identity of its own,
		// kept before its client opens, so a peer never holds a contract to material the keychain lacks
		connectIdentitySeed, err = newSidecarConnectIdentitySeed(rand.Reader)
		if err != nil {
			self.log.Errorf("[sidecar]generation %d has no connect identity: %s", identity.Generation, err)
			self.stopGeneration()
			return
		}
		defer clear(connectIdentitySeed)
		if err := persistSidecarConnectIdentitySeed(secrets, identity, connectIdentitySeed); err != nil {
			if errors.Is(err, ErrSidecarStoreLocked) || errors.Is(err, ErrSidecarStoreFailed) || errors.Is(err, ErrSidecarKeystoreLost) {
				self.connectIdentityFailed(err)
				return
			}
			// the keychain is open and the write did not finish: the client runs on the seed all the same, and a later
			// start that finds no record of it draws another, a restart costing its peers' contracts as without one
			self.log.Warningf("[sidecar]generation %d's connect identity was not kept: %s", identity.Generation, err)
		}
	}
	self.stopGeneration()
	self.startGeneration(&sidecarGenerationArgs{
		identity:            identity.clone(),
		networkId:           *networkId,
		connectInstanceId:   networkRecord.ConnectInstanceId,
		byJwt:               byJwt,
		clientKeySeed:       record.keys.clientKeySeedCopy(),
		connectIdentitySeed: bytes.Clone(connectIdentitySeed),
		binding:             bytes.Clone(record.binding),
		secrets:             secrets,
		child:               networkRecord.Child,
	})
}

// The keychain answered err for the generation's connect identity, as it may for the identity record (D-CORE-15):
// Locked while it is locked, Unenrolled with keystore_lost for a lost one, and for a record that fails decoding or a
// keychain that fails, Locked with the alarm, the record left as it is.
func (self *Sidecar) connectIdentityFailed(err error) {
	switch {
	case errors.Is(err, ErrSidecarStoreLocked):
		self.stopGeneration()
		self.enterLocked()
	case errors.Is(err, ErrSidecarKeystoreLost):
		self.stopGeneration()
		self.leaveForUnenrolled(SidecarReasonKeystoreLost)
	default:
		self.lockFailedKeychain(err)
	}
}

// A failed keychain read during binding recovery or identity loading locks this network and raises its alarm (D-CORE-15).
func (self *Sidecar) lockFailedKeychain(err error) {
	self.log.Warningf("[sidecar]the network's keychain failed: %s", err)
	self.stopGeneration()
	self.enterLocked()
	self.emitEvent(SidecarEvent{Kind: SidecarEventRefused})
}
