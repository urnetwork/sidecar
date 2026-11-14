// Child enrollment for an sdk host (§5.6's sdk host row, §18.5's EnrollWithDevice, §18.7; CORE-M8-01): the device's
// token mints this sidecar's client as a child of the device client, admin_refused and strict_exp (§7.4), and the
// host's TokenSource refreshes it with the core's DPoP signer (api_token_source.go). The sidecar role never holds the
// device's token: the host mints through MintChild, naming the ClientKey this generation made, and hands back only
// the child's answer, of which only the child's token enters the keychain.
//
// The order is Enroll's, failing closed (D-CORE-7): keys in memory, the mint, the binding, and only once the mint
// confirmed admin_refused and strict_exp and the binding is recorded, the keychain and then sidecar.json, marked a child
// so a confirmed rejection reads as parent_lost (plan-CORE-parent-lost-signal). Without the marks nothing is kept and
// the child is removed, best effort, with its own token. A re-pair keeps the sidecar_id and identity key and binds
// generation n+1 on a new ClientKey, removing the old child (§5.8). A child token minted elsewhere carries no answer
// this sidecar saw, so Enroll refuses ChildJwt alone (ErrSidecarEnrollChild).
//
// The token kept is the one bind answers, the child's re-minted with the bound sidecar_id (QD-040, QD-797), and the
// host's source, which holds the mint's, takes it too where it can (SidecarTokenSourceRemint), so its refreshes keep
// the claim sockets reads.
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
)

// Enrolls this sidecar as a child of its host's device client, credential.MintChild minting it. Called by Enroll.
func (self *Sidecar) enrollChild(ctx context.Context, credential *SidecarEnrollCredential) error {
	if self.instance == nil || self.sidecarApi == nil {
		return ErrSidecarClosed
	}
	self.enrollLock.Lock()
	defer self.enrollLock.Unlock()
	if err := self.checkEnrollable(credential); err != nil {
		return err
	}
	var previous *sidecarIdentityRecord
	previousByJwt := ""
	knownNetworkId := self.enrolledNetworkId()
	if knownNetworkId != nil {
		secrets := self.instance.secrets(*knownNetworkId, sidecarCoreSecretsNamespace)
		record, err := loadSidecarIdentity(secrets)
		switch {
		case err == nil:
			previous = record
			defer previous.keys.erase()
			previousByJwt, _ = loadSidecarByJwt(secrets)
		case !errors.Is(err, ErrSidecarNoIdentity):
			// locked, failed or lost: create nothing (D-CORE-15)
			return err
		}
	}
	var keys *sidecarIdentityKeys
	var sidecarId Id
	generation := int64(1)
	var err error
	if previous != nil {
		keys, err = previous.keys.withNewClientKey(rand.Reader)
		sidecarId = previous.identity.SidecarId
		generation = previous.identity.Generation + 1
	} else {
		keys, err = newSidecarIdentityKeys(rand.Reader)
		sidecarId = NewId()
	}
	if err != nil {
		return err
	}
	defer keys.erase()
	var readerKeySeed []byte
	if previous == nil {
		readerKeySeed, err = newSidecarReaderKeySeed(rand.Reader)
		if err != nil {
			return err
		}
		defer clear(readerKeySeed)
	}

	testHookBarrier("identity.enroll_child.mint.before", sidecarId.String())
	result, err := credential.MintChild(ctx, keys.clientPublicKey())
	testHookBarrier("identity.enroll_child.mint.after", sidecarId.String())
	if err != nil {
		return err
	}
	if result == nil || result.ByClientJwt == "" {
		return fmt.Errorf("%w: the mint answered no child", ErrSidecarApiReply)
	}
	childApi := self.sidecarApi.withByJwt(result.ByClientJwt)
	abandon := func(cause error) error {
		if result.ClientId != (Id{}) {
			if err := childApi.RemoveClient(ctx, result.ClientId); err != nil {
				self.log.Warningf("[identity]an abandoned child's client was not removed: %s", err)
			}
		}
		return cause
	}
	if !result.AdminRefused || !result.StrictExp {
		// the child could administer the network or outlive its 7 days: nothing of it is kept (D-CORE-7, §7.4)
		return abandon(ErrSidecarEnrollNotAdminRefused)
	}
	networkId, clientId, ok := sidecarJwtClient(result.ByClientJwt)
	if !ok || (result.ClientId != (Id{}) && clientId != result.ClientId) {
		return abandon(fmt.Errorf("%w: the child's token does not name the minted client", ErrSidecarApiReply))
	}
	result.ClientId = clientId
	if knownNetworkId != nil && *knownNetworkId != networkId {
		return abandon(fmt.Errorf("%w: the device is another network's than this sidecar's", ErrSidecarEnrolled))
	}
	if knownNetworkId == nil {
		if _, recorded := self.connectInstanceIdOf(networkId); recorded {
			return abandon(fmt.Errorf("%w: this instance is enrolled in that network already", ErrSidecarEnrolled))
		}
	}

	signedBinding, err := NewSidecarIdentityBinding(&SidecarIdentityBinding{
		NetworkId:  networkId,
		SidecarId:  sidecarId,
		ClientId:   clientId,
		Generation: generation,
		IssuedAt:   self.clock.Now(),
	}, keys.identitySeed, keys.clientKeySeed)
	if err != nil {
		return abandon(err)
	}
	testHookBarrier("identity.bind.before", sidecarId.String())
	bound, err := childApi.Bind(ctx, signedBinding)
	testHookBarrier("identity.bind.after", sidecarId.String())
	if err != nil {
		if previous != nil && isSidecarRevokedRefusal(err) {
			if revoked, verifyErr := self.VerifyRevocationClaim(ctx); verifyErr == nil && revoked {
				return abandon(ErrSidecarRevoked)
			}
		}
		return abandon(err)
	}
	if err := checkSidecarBound(bound, generation, sidecarId); err != nil {
		return abandon(err)
	}

	// both marks confirmed and the binding recorded: the keychain first, sidecar.json last of all; the token kept is
	// api's re-mint of the child's, which names the sidecar (QD-797)
	if previous == nil {
		if _, err := self.instance.createKeychain(networkId); err != nil {
			return abandon(err)
		}
	}
	secrets := self.instance.secrets(networkId, sidecarCoreSecretsNamespace)
	if _, err := persistSidecarIdentity(secrets, keys, signedBinding); err != nil {
		return abandon(err)
	}
	if err := persistSidecarByJwt(secrets, bound.ByClientJwt); err != nil {
		return abandon(err)
	}
	if readerKeySeed != nil {
		if err := secrets.Put(sidecarReaderKeyRecordName, readerKeySeed); err != nil {
			return abandon(err)
		}
	}
	connectInstanceId, ok := self.connectInstanceIdOf(networkId)
	if !ok {
		connectInstanceId = NewId()
	}
	err = self.instance.RecordNetwork(SidecarNetworkRecord{
		NetworkId:         networkId,
		ClientId:          clientId,
		SidecarId:         sidecarId,
		ConnectInstanceId: connectInstanceId,
		Child:             true,
	})
	if err != nil {
		return abandon(err)
	}
	// the host's source holds the child's pre-bind token from its mint and refreshes whatever it holds, so it takes the
	// re-mint too before the generation starts, else its first token would replace the keychain's (followTokenSource)
	self.handOffRemintedToken(bound.ByClientJwt)
	if previous != nil && previousByJwt != "" {
		// the old child goes with its own token (§5.8's re-pair)
		if err := self.sidecarApi.withByJwt(previousByJwt).RemoveClient(ctx, previous.identity.ClientId); err != nil {
			self.log.Infof("[identity]generation %d's child was not removed, and the reaper will: %s", previous.identity.Generation, err)
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		id := networkId
		self.networkId = &id
	}()
	self.log.Infof("[identity]enrolled child generation %d", generation)
	self.wake()
	return nil
}
