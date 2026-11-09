// Sidecar.Logout, `ur logout` (§5.6, CORE-M2-07): the sidecar signs SidecarRevoke{removed} for its own sidecar_id and
// posts it (identity_revoke_self.go), removes its client (POST /network/remove-client), and wipes this network's state,
// its keychain and directory and its sidecar.json record, in that order, so the instance holds nothing of the network
// and a later enrollment is a first one.
//
// Each step waits for the one before. A sign-out api does not answer stays pending in keychain.ur and nothing is
// removed or wiped, since a wipe first would strand the statement there: the person runs ur logout again, which posts
// the same bytes. A failed removal wipes nothing, so a person can try again: wiping first would leave a live client
// nobody holds the keys of. A generation a confirmed rejection already ended has no client to remove, and no token to
// post with, so its state is wiped at once, and its devices see it revoked only when another device revokes it as lost.
// Nothing here names a connect type, so it builds on every leg.

package sidecar

import (
	"context"
	"errors"
	"slices"
)

// Signs this sidecar out of its network, removes its client and wipes this network's state. ErrSidecarNoIdentity when
// nothing is enrolled; the instance's own errors while it is locked, failed or lost; ErrSidecarLogoutPending and
// ErrSidecarLogoutUnverified while the sign-out cannot land; api's refusal of the sign-out or the removal. Each refusal
// wipes nothing.
func (self *Sidecar) Logout(ctx context.Context) error {
	if self.instance == nil || self.sidecarApi == nil {
		return ErrSidecarClosed
	}
	self.enrollLock.Lock()
	defer self.enrollLock.Unlock()
	networkId := self.enrolledNetworkId()
	if networkId == nil {
		return ErrSidecarNoIdentity
	}
	if err := self.instance.stateError(); err != nil {
		return err
	}
	secrets := self.instance.secrets(*networkId, sidecarCoreSecretsNamespace)
	record, err := loadSidecarIdentity(secrets)
	switch {
	case err == nil:
		defer record.keys.erase()
	case errors.Is(err, ErrSidecarNoIdentity):
	default:
		return err
	}
	if record != nil && self.clientLive() {
		// the sign-out lands before the client goes, and it needs that client's token to post
		if err := self.signOut(ctx, record.identity); err != nil {
			return err
		}
		byJwt, err := loadSidecarByJwt(secrets)
		if err != nil && !errors.Is(err, ErrSidecarStoreAbsent) {
			return err
		}
		if byJwt != "" {
			testHookBarrier("identity.logout.remove.before", record.identity.SidecarId.String())
			err := self.sidecarApi.withByJwt(byJwt).RemoveClient(ctx, record.identity.ClientId)
			testHookBarrier("identity.logout.remove.after", record.identity.SidecarId.String())
			if err != nil {
				return err
			}
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.networkId = nil
		self.identity = nil
		self.coreSecrets = nil
		self.endedGeneration = 0
	}()
	// the run loop ends the generation, and the wipe waits for it, so nothing of it writes under the keychain again
	self.wake()
	for {
		running, changed := self.runningGenerationNumber.Get()
		if running == 0 {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := self.instance.forgetNetwork(*networkId); err != nil {
		return err
	}
	self.log.Infof("[identity]logged out")
	return nil
}

// Whether this sidecar's client may still be live at api: anything but a generation a confirmed rejection ended.
func (self *Sidecar) clientLive() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.lifecycle.state != SidecarStateUnenrolled {
		return true
	}
	switch self.lifecycle.reason {
	case SidecarReasonRefused, SidecarReasonExpired, SidecarReasonSessionEnded, SidecarReasonParentLost:
		return false
	}
	return true
}

// Wipes network networkId from this instance: its open keychain closed, every file under net/<network_id>/ removed,
// and its sidecar.json record dropped, so a later enrollment there is a first one (§5.9). Only Logout calls this, after
// api has removed the client.
func (self *SidecarInstance) forgetNetwork(networkId Id) error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	if err := self.stateError(); err != nil {
		return err
	}
	var opened *keychain
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		opened = self.networkIdKeychains[networkId]
		delete(self.networkIdKeychains, networkId)
	}()
	if opened != nil {
		opened.close()
	}
	if err := self.removeTreeWithLock(networkDirectoryPath(networkId) + "/"); err != nil {
		return err
	}
	return self.editDocumentWithLock(func(document *sidecarStateDocument) error {
		document.NetworkRecords = slices.DeleteFunc(document.NetworkRecords, func(record SidecarNetworkRecord) bool {
			return record.NetworkId == networkId
		})
		return nil
	})
}
