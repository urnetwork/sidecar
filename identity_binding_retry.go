// An existing identity advances one generation at a time. Keep its exact next binding in its sealed
// keychain until the server and the local network record both acknowledge the change (§5.6, §7.7).

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
)

// An outstanding operation owns its client until replay determines the outcome.
var ErrSidecarBindingPending = errors.New("the sidecar binding is pending")

const sidecarPendingBindingName = "pending_binding"

// The host action that produced a sealed candidate. A restart may finish any of them.
type sidecarBindingOperation string

const (
	bindingRecovery sidecarBindingOperation = ""
	bindingAuthKey  sidecarBindingOperation = "auth_key"
	bindingChild    sidecarBindingOperation = "child"
	bindingPair     sidecarBindingOperation = "pair"
	bindingPage     sidecarBindingOperation = "page"
	bindingBurner   sidecarBindingOperation = "burner"
)

// An immutable candidate for the next generation, stored only inside the existing network's keychain.
type sidecarPendingBinding struct {
	Operation     sidecarBindingOperation `json:",omitempty"`
	Signed        []byte
	ClientKeySeed []byte
	ByJwt         string
	PreviousByJwt string
	Child         bool
	Replace       bool
	MachineIdHash string
	Anchor        []byte
}

// Journals a re-enrollment or re-pair after the mint's marks have been checked and before the first POST.
func (self *Sidecar) changeBinding(ctx context.Context, previous *sidecarIdentityRecord, keys *sidecarIdentityKeys, signed []byte,
	byJwt string, previousByJwt string, operation sidecarBindingOperation, replace bool, anchor *SidecarAnchor) error {
	networkId := previous.identity.NetworkId
	secrets := self.instance.secrets(networkId, sidecarCoreSecretsNamespace)
	pending := &sidecarPendingBinding{
		Signed: signed, ClientKeySeed: keys.clientKeySeed, ByJwt: byJwt, PreviousByJwt: previousByJwt,
		Operation: operation, Child: operation == bindingChild || operation == bindingPair,
		Replace: replace, MachineIdHash: stateMachineIdHash(self.instance.currentDocument().InstanceId, self.instance.machineId),
	}
	abandonBeforeWrite := func(cause error) error {
		if _, clientId, ok := sidecarJwtClient(byJwt); ok {
			if err := self.sidecarApi.withByJwt(byJwt).RemoveClient(ctx, clientId); err != nil {
				self.log.Infof("[identity]the unused client was not removed: %s", err)
			}
		}
		return cause
	}
	if anchor != nil {
		var err error
		if pending.Anchor, err = anchor.encode(); err != nil {
			return abandonBeforeWrite(err)
		}
		existing, err := secrets.Get(sidecarAnchorRecordName)
		if err == nil && !bytes.Equal(existing, pending.Anchor) {
			return abandonBeforeWrite(ErrSidecarAnchorMismatch)
		}
		if err != nil && !errors.Is(err, ErrSidecarStoreAbsent) {
			return abandonBeforeWrite(err)
		}
	}
	encoded, err := json.Marshal(pending)
	if err != nil {
		return abandonBeforeWrite(err)
	}
	defer clear(encoded)
	if err := secrets.Put(sidecarPendingBindingName, encoded); err != nil {
		return fmt.Errorf("%w: %w", ErrSidecarBindingPending, err)
	}
	return self.finishBinding(ctx, networkId, secrets, pending, previous, false)
}

// Continues the exact candidate a previous process may have posted. Called with enrollLock held.
func (self *Sidecar) resumeBinding(ctx context.Context, networkId *Id, replace bool, operation sidecarBindingOperation, clientId *Id) (*SidecarIdentityBinding, error) {
	if networkId == nil {
		return nil, nil
	}
	secrets := self.instance.secrets(*networkId, sidecarCoreSecretsNamespace)
	encoded, err := secrets.Get(sidecarPendingBindingName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	pending := &sidecarPendingBinding{}
	if err := json.Unmarshal(encoded, pending); err != nil {
		return nil, ErrSidecarStoreFailed
	}
	defer clear(pending.ClientKeySeed)
	testHookSecret("ClientKey", pending.ClientKeySeed)
	restored := self.instance.networkRestored(networkId)
	fromOtherMachine := pending.MachineIdHash != stateMachineIdHash(self.instance.currentDocument().InstanceId, self.instance.machineId)
	hold := restored && (!pending.Replace || fromOtherMachine)
	if hold && !replace || fromOtherMachine && !restored {
		return nil, ErrSidecarRestored
	}
	if operation != bindingRecovery && !hold && !pending.matches(operation, clientId) {
		// The lifecycle will finish its original candidate. This caller may retry its
		// own action after that commit, without assuming the other action succeeded.
		self.wake()
		return nil, ErrSidecarBindingPending
	}
	previous, err := loadSidecarIdentity(secrets)
	if err != nil {
		return nil, err
	}
	defer previous.keys.erase()
	if err := self.finishBinding(ctx, *networkId, secrets, pending, previous, hold); err != nil {
		return nil, err
	}
	if hold {
		// Explicit replacement can confirm the original machine's last bind, but only a newly minted client can run here.
		return nil, nil
	}
	return VerifySidecarIdentityBinding(pending.Signed)
}

// Checks whether this caller can resume the journaled operation, using the client id to distinguish legacy pairs.
func (self *sidecarPendingBinding) matches(operation sidecarBindingOperation, expected *Id) bool {
	if self.Operation == bindingRecovery {
		// Earlier journals were either an auth-key top-level mint or a child mint/pair.
		// A pair supplies its exact client. Recovery can disambiguate any other old child.
		if !self.Child {
			return operation == bindingAuthKey
		}
		if operation != bindingPair || expected == nil {
			return false
		}
	} else if self.Operation != operation {
		return false
	}
	if expected != nil {
		_, id, ok := sidecarJwtClient(self.ByJwt)
		return ok && id == *expected
	}
	return true
}

// Replays the exact signed bytes and publishes the new token, keys and network record before removing the old client.
// A transport interruption or a local write failure keeps the candidate for the next retry.
func (self *Sidecar) finishBinding(ctx context.Context, networkId Id, secrets SidecarSecrets, pending *sidecarPendingBinding, previous *sidecarIdentityRecord, hold bool) error {
	binding, err := VerifySidecarIdentityBinding(pending.Signed)
	if err != nil || binding.NetworkId != networkId || binding.SidecarId != previous.identity.SidecarId ||
		len(pending.ClientKeySeed) != ed25519.SeedSize || (binding.Generation != previous.identity.Generation+1 &&
		(binding.Generation != previous.identity.Generation || binding.ClientId != previous.identity.ClientId)) {
		return ErrSidecarStoreFailed
	}
	childNetworkId, childClientId, ok := sidecarJwtClient(pending.ByJwt)
	if !ok || childNetworkId != networkId || childClientId != binding.ClientId {
		return ErrSidecarStoreFailed
	}
	keys := &sidecarIdentityKeys{identitySeed: previous.keys.identitySeed, clientKeySeed: pending.ClientKeySeed}
	if !bytes.Equal(binding.IdentityPublicKey, keys.identityPublicKey()) || !bytes.Equal(binding.ClientPublicKey, keys.clientPublicKey()) {
		return ErrSidecarStoreFailed
	}
	api := self.sidecarApi.withByJwt(pending.ByJwt)
	generation := binding.Generation
	if !bytes.Equal(previous.binding, pending.Signed) {
		testHookBarrier("identity.change.bind.before", binding.SidecarId.String())
		generation, err = api.Bind(ctx, pending.Signed)
		testHookBarrier("identity.change.bind.after", binding.SidecarId.String())
	}
	if err != nil {
		var refusal *SidecarApiError
		if errors.As(err, &refusal) && (refusal.Code == SidecarApiCodeBindingInvalid || refusal.Code == SidecarApiCodeClientBound ||
			refusal.Code == SidecarApiCodeGenerationConflict || refusal.Code == SidecarApiCodeSidecarRevoked) {
			if err := secrets.Delete(sidecarPendingBindingName); err != nil {
				return fmt.Errorf("%w: %w", ErrSidecarBindingPending, err)
			}
			if isSidecarRevokedRefusal(err) {
				if revoked, verifyErr := self.VerifyRevocationClaim(ctx); verifyErr == nil && revoked {
					err = ErrSidecarRevoked
				}
			}
			api.RemoveClient(ctx, binding.ClientId)
			return err
		}
		return fmt.Errorf("%w: %w", ErrSidecarBindingPending, err)
	}
	if generation != binding.Generation {
		return fmt.Errorf("%w: %w", ErrSidecarBindingPending, ErrSidecarApiReply)
	}
	if _, err := persistSidecarIdentity(secrets, keys, pending.Signed); err != nil {
		return fmt.Errorf("%w: %w", ErrSidecarBindingPending, err)
	}
	if err := persistSidecarByJwt(secrets, pending.ByJwt); err != nil {
		return fmt.Errorf("%w: %w", ErrSidecarBindingPending, err)
	}
	if len(pending.Anchor) > 0 {
		anchor, err := decodeSidecarAnchor(pending.Anchor)
		if err != nil {
			return err
		}
		if err := persistSidecarAnchor(secrets, anchor); err != nil {
			return fmt.Errorf("%w: %w", ErrSidecarBindingPending, err)
		}
	}
	if !hold {
		connectId, ok := self.connectInstanceIdOf(networkId)
		if !ok {
			return ErrSidecarStoreFailed
		}
		if err := self.instance.recordNetwork(SidecarNetworkRecord{NetworkId: networkId, ClientId: binding.ClientId,
			SidecarId: binding.SidecarId, ConnectInstanceId: connectId, Child: pending.Child}, pending.Replace); err != nil {
			return fmt.Errorf("%w: %w", ErrSidecarBindingPending, err)
		}
	}
	if _, oldClientId, ok := sidecarJwtClient(pending.PreviousByJwt); ok && oldClientId != binding.ClientId {
		if err := self.sidecarApi.withByJwt(pending.PreviousByJwt).RemoveClient(ctx, oldClientId); err != nil {
			self.log.Infof("[identity]the previous client was not removed, and the reaper will: %s", err)
		}
	}
	if err := secrets.Delete(sidecarPendingBindingName); err != nil {
		return fmt.Errorf("%w: %w", ErrSidecarBindingPending, err)
	}
	self.wake()
	return nil
}
