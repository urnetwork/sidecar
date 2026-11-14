//go:build !ios_extension

// Pairing (§5.8's pair, lost and unpair rows; D-CORE-4, D-CORE-5, D-SDK-14, I-6, I-7; owner decisions 4, 87;
// CORE-M8-02). A desktop app in remote mode, or a sandboxed one through its app-group socket, mints a child C of its
// device client D, POST /network/auth-client {source_client_id: D, admin_refused: true}, and hands the daemon C's jwt
// alone, so the daemon never holds the device's token:
//
//	pair     C's token must name this sidecar's network, or, unenrolled, the one it then enrolls in, and carry
//	         strict_exp, which confines it to §7.4's allowlist with no admin route; its admin_refused is the app's mint's
//	         to confirm (question core-m6-02-pair-admin-refused). Then, in Enroll's order and failing closed
//	         (D-CORE-7): a new ClientKey, the identity key and sidecar_id kept or, unenrolled, new; POST /sidecar/bind
//	         at generation n+1 on C; the keychain, holding bind's re-mint of C's token with the sidecar_id in place of
//	         the one handed over (QD-797), and last sidecar.json's record marked a child; then the previous client
//	         goes with its own token, a top-level one or an earlier child alike. The SidecarAdmit stands, since it
//	         names the sidecar_id, and so does every grant (D-CORE-5)
//	lost     D removed or reaped ends C: a confirmed rejection of the paired generation reads parent_lost by the child
//	         mark (plan-CORE-parent-lost-signal; sidecarTokenManager.refusedReason), and Unenrolled keeps identity and
//	         admission until ur login or a re-pair binds the next generation
//	unpair   ur login on a paired sidecar enrolls a top-level client as the next generation, clearing the child mark,
//	         and removes C with its own token (Enroll, which takes a paired sidecar while it runs)
//
// A pairing takes the running sidecar as it is, Online or Offline: the run loop moves to the new generation once the
// keychain names it. Nothing is kept before the binding lands, and a failure after it removes C, best effort, with its
// own token; the bound generation is then spent, as an abandoned enrollment's is. Nothing returns a token (I-7).
//
// On every leg but the forwarding one: root Id, no connect type.

package sidecar

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
)

var (
	// The child's token names no client, another network than this sidecar's, or no strict_exp: nothing was sent.
	ErrSidecarPairToken = errors.New("the pairing token is not a strict_exp child of this network")
	// The child is the client this sidecar runs already.
	ErrSidecarPairSame = errors.New("this sidecar runs on that client already")
)

// Whether byJwt's claims mark it strict_exp (§7.4), read without verifying it: api verifies it at the binding.
func sidecarJwtStrictExp(byJwt string) bool {
	parse := parseSidecarJwt(byJwt)
	if !parse.ok {
		return false
	}
	strictExp, _ := parse.claims["strict_exp"].(bool)
	return strictExp
}

// Why this sidecar cannot pair now, or nil: closed, revoked, locked, its key store lost, or its instance failed. A
// running sidecar pairs, unlike Enroll's re-enrollment. Runs under enrollLock.
func (self *Sidecar) checkPairable() error {
	if self.isClosed() {
		return ErrSidecarClosed
	}
	if err := self.instance.stateError(); err != nil {
		return err
	}
	var lifecycle sidecarLifecycle
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		lifecycle = self.lifecycle
	}()
	switch lifecycle.state {
	case SidecarStateRevoked:
		return ErrSidecarRevoked
	case SidecarStateLocked:
		return ErrSidecarStoreLocked
	}
	if lifecycle.reason == SidecarReasonKeystoreLost {
		return ErrSidecarKeystoreLost
	}
	if self.instance.Restored() {
		// a restored or copied state takes --replace's path, which a pairing has no flag for
		return ErrSidecarRestored
	}
	return nil
}

// §5.8's Pair: binds generation n+1 of this sidecar, its sidecar_id and identity key kept, on the child client whose
// token the app minted under its device client, marks the record a child, and removes the client this sidecar ran
// before; unenrolled, it enrolls in the child's network as generation 1. The token stays in the keychain and the
// generation's holders; nothing returns it.
func (self *Sidecar) Pair(ctx context.Context, childJwt string) error {
	_, err := self.pair(ctx, childJwt)
	return err
}

// The generation the keychain's identity record names now, which a pairing or an enrollment just bound and the run
// loop moves to; 0 before an identity or while the keychain cannot be read.
func (self *Sidecar) BoundGeneration() int64 {
	networkId := self.enrolledNetworkId()
	if self.instance == nil || networkId == nil {
		return 0
	}
	record, err := loadSidecarIdentity(self.instance.secrets(*networkId, sidecarCoreSecretsNamespace))
	if err != nil {
		return 0
	}
	defer record.keys.erase()
	return record.identity.Generation
}

// Pair's work, answering the generation bound.
func (self *Sidecar) pair(ctx context.Context, childJwt string) (int64, error) {
	if childJwt == "" {
		return 0, fmt.Errorf("%w: no token", ErrSidecarPairToken)
	}
	testHookSecret("by_client_jwt", []byte(childJwt))
	if self.instance == nil || self.sidecarApi == nil {
		return 0, ErrSidecarClosed
	}
	self.enrollLock.Lock()
	defer self.enrollLock.Unlock()
	if err := self.checkPairable(); err != nil {
		return 0, err
	}
	networkId, clientId, ok := sidecarJwtClient(childJwt)
	if !ok || !sidecarJwtStrictExp(childJwt) {
		return 0, ErrSidecarPairToken
	}
	knownNetworkId := self.enrolledNetworkId()
	if knownNetworkId != nil && *knownNetworkId != networkId {
		return 0, fmt.Errorf("%w: the device is another network's than this sidecar's", ErrSidecarPairToken)
	}
	if knownNetworkId == nil {
		if _, recorded := self.connectInstanceIdOf(networkId); recorded {
			// that network is another Sidecar's of this instance, which takes the pairing (CORE-M6-01)
			return 0, fmt.Errorf("%w: this instance is enrolled in that network already", ErrSidecarEnrolled)
		}
	}

	var previous *sidecarIdentityRecord
	previousByJwt := ""
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
			return 0, err
		}
	}
	if previous != nil && previous.identity.ClientId == clientId {
		return 0, ErrSidecarPairSame
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
		return 0, err
	}
	defer keys.erase()
	var readerKeySeed []byte
	if previous == nil {
		readerKeySeed, err = newSidecarReaderKeySeed(rand.Reader)
		if err != nil {
			return 0, err
		}
		defer clear(readerKeySeed)
	}

	childApi := self.sidecarApi.withByJwt(childJwt)
	// keeps nothing, removes the child best effort with its own token, and answers cause
	abandon := func(cause error) (int64, error) {
		if err := childApi.RemoveClient(ctx, clientId); err != nil {
			self.log.Warningf("[identity]an abandoned pairing's child was not removed: %s", err)
		}
		return 0, cause
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
	testHookBarrier("identity.pair.bind.before", sidecarId.String())
	bound, err := childApi.Bind(ctx, signedBinding)
	testHookBarrier("identity.pair.bind.after", sidecarId.String())
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

	// the binding recorded: the keychain first, sidecar.json last of all; the token kept is api's re-mint of C's,
	// which names the sidecar, in place of the one the app handed over (QD-797)
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
	testHookBarrier("identity.pair.record.before", sidecarId.String())
	err = self.instance.RecordNetwork(SidecarNetworkRecord{
		NetworkId:         networkId,
		ClientId:          clientId,
		SidecarId:         sidecarId,
		ConnectInstanceId: connectInstanceId,
		Child:             true,
	})
	testHookBarrier("identity.pair.record.after", sidecarId.String())
	if err != nil {
		return abandon(err)
	}
	if previous != nil && previousByJwt != "" {
		// the top-level client, or an earlier child, goes with its own token (§5.8's remove any top-level client)
		if err := self.sidecarApi.withByJwt(previousByJwt).RemoveClient(ctx, previous.identity.ClientId); err != nil {
			self.log.Infof("[identity]generation %d's client was not removed, and the reaper will: %s", previous.identity.Generation, err)
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		id := networkId
		self.networkId = &id
	}()
	self.log.Infof("[identity]paired generation %d", generation)
	self.wake()
	return generation, nil
}
