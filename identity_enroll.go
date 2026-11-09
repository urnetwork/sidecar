// Sidecar.Enroll (§5.6, D-CORE-7, R-CORE-9, R-CORE-11): a top-level client from a §7 auth key, in the order that
// fails closed. The key's client-only #<bundle> is split off before anything else reads it (TEAM-M1-05's
// ParseAuthKey), and a urn_ API key or any other network credential is refused. The identity key, ClientKey seed,
// ReaderKey and sidecar_id are made in memory; POST /network/enroll sends only the bearer, with admin_refused and
// strict_exp always (§7.4), declares_no_egress unless `ur proxy` or a public exit is set (§20.8), and a body
// CheckAuthKeyBody passed (api_routes_core.go); POST /sidecar/bind posts the dual-signed binding; and only once the
// reply confirms admin_refused and the binding is recorded does anything persist, the keychain first and sidecar.json
// last of all. Without the mark nothing is kept, the new client is removed best effort, and the error stops the
// daemon from starting on it (D-CORE-7).
//
// A re-enrollment after Unenrolled keeps the sidecar_id and identity key: a new ClientKey binds generation n+1, and
// the old client is removed, best effort, with its own token (§5.5). A refused, expired or ended generation is the
// one case: a lost keychain (keystore_lost) enrolls only after the person confirms a new device (D-CORE-15), and a
// revoked sidecar never again. Nothing here names a connect type, so it builds on every leg.

package sidecar

import (
	"context"
	"crypto/hpke"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// The keychain record of the core's namespace holding this sidecar's first ReaderKey, an X-Wing seed (§10.5): the
// slot KEYS-M2-18's upkeep takes over, replacing the pair once it is 6 days old.
const sidecarReaderKeyRecordName = "reader_key"

// The device description an enrollment sends when the credential names none.
const sidecarDefaultDeviceSpec = "ur"

// A sidecar that a verified SidecarRevoke ended enrolls only as a new sidecar_id, from new state (§5.5).
var ErrSidecarRevoked = errors.New("this sidecar is revoked")

// A client token's network and client, read unverified as the refresh schedule reads its claims: only for checks
// that a verified answer already stands behind, never as authority.
func sidecarJwtClient(byJwt string) (networkId Id, clientId Id, ok bool) {
	parse := parseSidecarJwt(byJwt)
	if !parse.ok {
		return Id{}, Id{}, false
	}
	networkId, networkErr := ParseId(parse.stringClaim("network_id"))
	clientId, clientErr := ParseId(parse.stringClaim("client_id"))
	if networkErr != nil || clientErr != nil || networkId == (Id{}) || clientId == (Id{}) {
		return Id{}, Id{}, false
	}
	return networkId, clientId, true
}

// A first ReaderKey: a fresh X-Wing seed, which the KEM must take as a private key.
func newSidecarReaderKeySeed(random io.Reader) ([]byte, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, fmt.Errorf("no randomness for a key: %w", err)
	}
	if _, err := hpke.MLKEM768X25519().NewPrivateKey(seed); err != nil {
		clear(seed)
		return nil, fmt.Errorf("reader key: %w", err)
	}
	testHookSecret("ReaderKey", seed)
	return seed, nil
}

// A client of api on the same settings and transport presenting byJwt, with no proof signer: an enrollment's calls
// for a client this sidecar does not keep yet, or one it is leaving.
func (self *SidecarApi) withByJwt(byJwt string) *SidecarApi {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &SidecarApi{
		settings:  self.settings,
		log:       self.log,
		now:       self.now,
		byJwt:     byJwt,
		transport: self.transport,
	}
}

// Enrolls this sidecar from credential, in D-CORE-7's order, erasing the credential whatever the outcome. On success
// the keychain holds the identity, the new generation's binding and token, and sidecar.json records the network; the
// run loop then starts the generation, which Status shows Offline and then Online. Refusals: a urn_ key
// (ErrAuthKeyIsApiKey), a bundle (ErrSidecarEnrollBundle), a child token (ErrSidecarEnrollChild), a readable
// network credential on this host (ErrSidecarHostCredentialStore), a working enrollment (ErrSidecarEnrolled), api's
// refusal (*SidecarEnrollError, preview and no_genesis among them), and a reply without admin_refused
// (ErrSidecarEnrollNotAdminRefused). Every refusal leaves nothing on disk.
func (self *Sidecar) Enroll(ctx context.Context, credential *SidecarEnrollCredential) error {
	if credential == nil {
		return fmt.Errorf("%w: no credential", ErrSidecarApiArgs)
	}
	defer credential.Erase()
	if credential.ChildJwt != "" {
		return ErrSidecarEnrollChild
	}
	if credential.Bundle != nil {
		return ErrSidecarEnrollBundle
	}
	// the bundle comes off before anything else reads the key
	authKey, err := ParseAuthKey(credential.AuthKey)
	if err != nil {
		return err
	}
	defer authKey.Erase()
	if authKey.Bundle() != nil {
		return ErrSidecarEnrollBundle
	}
	if self.instance == nil || self.sidecarApi == nil {
		return ErrSidecarClosed
	}
	// the network the credential vouches for, checked whole before anything is sent (§5.6's genesis row)
	anchor, err := sidecarAnchorOfCredential(credential, nil)
	if err != nil {
		return err
	}

	self.enrollLock.Lock()
	defer self.enrollLock.Unlock()
	if err := self.checkEnrollable(credential); err != nil {
		return err
	}

	// a re-enrollment keeps the identity and binds the next generation
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

	deviceSpec := credential.DeviceSpec
	if deviceSpec == "" {
		deviceSpec = sidecarDefaultDeviceSpec
	}
	testHookBarrier("identity.enroll.before", sidecarId.String())
	result, err := self.sidecarApi.Enroll(ctx, &SidecarEnrollArgs{
		AuthKey:          authKey.Bearer(),
		ClientPublicKey:  keys.clientPublicKey(),
		DeviceSpec:       deviceSpec,
		DeclaresNoEgress: !credential.DeclaresEgress,
	})
	testHookBarrier("identity.enroll.after", sidecarId.String())
	if err != nil {
		var apiErr *SidecarApiError
		if errors.As(err, &apiErr) {
			return newSidecarEnrollError(apiErr)
		}
		return err
	}
	enrollApi := self.sidecarApi.withByJwt(result.ByClientJwt)
	// keeps nothing, removes the new client best effort, and answers cause
	abandon := func(cause error) error {
		if err := enrollApi.RemoveClient(ctx, result.ClientId); err != nil {
			self.log.Warningf("[identity]an abandoned enrollment's client was not removed: %s", err)
		}
		return cause
	}
	if !result.AdminRefused {
		return abandon(ErrSidecarEnrollNotAdminRefused)
	}
	networkId, tokenClientId, ok := sidecarJwtClient(result.ByClientJwt)
	if !ok || tokenClientId != result.ClientId {
		return abandon(fmt.Errorf("%w: the token does not name the enrolled client", ErrSidecarApiReply))
	}
	if knownNetworkId != nil && *knownNetworkId != networkId {
		return abandon(fmt.Errorf("%w: the key is another network's than this sidecar's", ErrSidecarEnrolled))
	}

	signedBinding, err := NewSidecarIdentityBinding(&SidecarIdentityBinding{
		NetworkId:  networkId,
		SidecarId:  sidecarId,
		ClientId:   result.ClientId,
		Generation: generation,
		IssuedAt:   self.clock.Now(),
	}, keys.identitySeed, keys.clientKeySeed)
	if err != nil {
		return abandon(err)
	}
	testHookBarrier("identity.bind.before", sidecarId.String())
	boundGeneration, err := enrollApi.Bind(ctx, signedBinding)
	testHookBarrier("identity.bind.after", sidecarId.String())
	if err != nil {
		if previous != nil && isSidecarRevokedRefusal(err) {
			// api holds this identity revoked: a claim the config must verify before it means Revoked (CORE-M2-07)
			if revoked, verifyErr := self.VerifyRevocationClaim(ctx); verifyErr == nil && revoked {
				return abandon(ErrSidecarRevoked)
			}
		}
		return abandon(err)
	}
	if boundGeneration != generation {
		return abandon(fmt.Errorf("%w: api bound generation %d, not %d", ErrSidecarApiReply, boundGeneration, generation))
	}

	// admin_refused confirmed and the binding recorded: the keychain first, sidecar.json last of all
	if previous == nil {
		if _, err := self.instance.createKeychain(networkId); err != nil {
			return abandon(err)
		}
	}
	secrets := self.instance.secrets(networkId, sidecarCoreSecretsNamespace)
	if _, err := persistSidecarIdentity(secrets, keys, signedBinding); err != nil {
		return abandon(err)
	}
	if err := persistSidecarByJwt(secrets, result.ByClientJwt); err != nil {
		return abandon(err)
	}
	if readerKeySeed != nil {
		if err := secrets.Put(sidecarReaderKeyRecordName, readerKeySeed); err != nil {
			return abandon(err)
		}
	}
	if anchor != nil {
		// the log this sidecar follows must chain to it (CORE-M2-01): a re-enrollment's anchor must be the one kept
		if err := persistSidecarAnchor(secrets, anchor); err != nil {
			return abandon(err)
		}
	}
	connectInstanceId, ok := self.connectInstanceIdOf(networkId)
	if !ok {
		connectInstanceId = NewId()
	}
	err = self.instance.RecordNetwork(SidecarNetworkRecord{
		NetworkId:         networkId,
		ClientId:          result.ClientId,
		SidecarId:         sidecarId,
		ConnectInstanceId: connectInstanceId,
	})
	if err != nil {
		return abandon(err)
	}
	if credential.Replace && self.instance.Restored() {
		if err := self.instance.AcceptRestored(); err != nil {
			self.log.Warningf("[identity]the restored state was not taken as this machine's: %s", err)
		}
	}
	if previous != nil && previousByJwt != "" {
		// the old client goes with its own token, which the refusal that ended it may have ended too
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
	self.log.Infof("[identity]enrolled generation %d", generation)
	self.wake()
	return nil
}

// Why this sidecar cannot enroll now, or nil. Runs under enrollLock.
func (self *Sidecar) checkEnrollable(credential *SidecarEnrollCredential) error {
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
	case SidecarStateOnline, SidecarStateOffline:
		return ErrSidecarEnrolled
	case SidecarStateLocked:
		return ErrSidecarStoreLocked
	}
	if lifecycle.reason == SidecarReasonKeystoreLost {
		// only the person's confirmation of a new device goes on from here (D-CORE-15)
		return ErrSidecarKeystoreLost
	}
	if credential.Ephemeral && !self.instance.memoryOnly() {
		return ErrSidecarEnrollEphemeral
	}
	if self.instance.Restored() && !credential.Replace {
		return ErrSidecarRestored
	}
	if stores := self.hostCredentialStores(); 0 < len(stores) {
		// D-TRUST-3: ur refuses to enroll beside a readable network credential
		return ErrSidecarHostCredentialStore
	}
	return nil
}

// The network this sidecar is enrolled in, a copy, or nil.
func (self *Sidecar) enrolledNetworkId() *Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.networkId == nil {
		return nil
	}
	id := *self.networkId
	return &id
}

// Whether every file of this instance lives in memory, as an ephemeral sidecar's must (§5.6).
func (self *SidecarInstance) memoryOnly() bool {
	_, ok := self.backend.(*memoryStoreBackend)
	return ok
}
