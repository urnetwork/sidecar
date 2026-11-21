//go:build !ios_extension

// What a host's composition of a network's key client takes from the Sidecar (QD-804): the args of KEYS-M2-22's
// GkmGroupClient and of the network's MLS engine, beside GkmApiArgs, GkmUpkeepArgs and EvsClientArgs. They hold what only
// the Sidecar has: its sidecar_id, identity key and signer, the network's keychain under gkm's namespace and its store,
// its gkm settings, clock, log and events. What only the verified state knows, the admission an engine's credentials
// name and the repos a device reads, is the composition's, from the network's config follower (ur daemon's is
// cli/daemon_clients.go).
//
// Every leg but the iOS extension's, which holds no MLS state and no repo key (owner decision 197).

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
)

// The args a GkmGroupClient takes from this Sidecar for the network it is enrolled in: its sidecar_id and network, api,
// Sign, the network's keychain under gkm's namespace (§5.9), which upkeep's records share, mls, its alarms raised as
// events, settings.Gkm, the clock and the log. What only the verified state and the upkeep know, the reader keys, the
// repos it reads, recovery keys, anchoring and the witness stop, the caller sets. mls is nil for a sidecar that holds
// no leaf.
func (self *Sidecar) GkmGroupClientArgs(api GkmGroupApi, mls MlsEngine) (*GkmGroupClientArgs, error) {
	networkId := self.enrolledNetworkId()
	identity := self.currentIdentity()
	if networkId == nil || identity == nil || self.instance == nil {
		return nil, fmt.Errorf("%w: gkm needs an enrolled network", errInvalidSettings)
	}
	return &GkmGroupClientArgs{
		SidecarId:              identity.SidecarId,
		NetworkId:              *networkId,
		Api:                    api,
		Sign:                   self.Sign,
		Secrets:                self.instance.secrets(*networkId, gkmUpkeepSecretsNamespace),
		Mls:                    mls,
		RecoveryKeyAt:          self.gkmRecoveryKeyAt,
		OwnRecoveryKey:         self.sealOwnRecoveryBinding,
		AwaitingRecoveryAnchor: self.RecoveryAwaitingAnchor,
		Alarm:                  self.raiseGkmAlarm,
		Settings:               self.settings.Gkm,
		Clock:                  self.clock,
		Log:                    self.log,
	}, nil
}

// Reads an already-held generation directly from the encrypted keychain. Config callbacks can run inside a
// group flow, so opening a sealed statement must not re-enter a group manager or perform an unauthenticated fetch.
func (self *Sidecar) GkmHeldKey(repoId Id, generation uint64) *EvsRepoKey {
	networkId := self.enrolledNetworkId()
	if networkId == nil || self.instance == nil {
		return nil
	}
	encoded, err := self.instance.secrets(*networkId, gkmUpkeepSecretsNamespace).Get(gkmGenerationRecordName(repoId, generation))
	if err != nil {
		return nil
	}
	defer clear(encoded)
	held, err := decodeGkmHeldGeneration(encoded)
	if err != nil || held.poisoned {
		return nil
	}
	return held.key
}

func (self *Sidecar) gkmRecoveryKeyAt(view GkmAuthView, memberId Id) (*GkmRecoveryKey, error) {
	state, ok := view.(*ConfigState)
	if !ok {
		return nil, ErrGkmKeyMissing
	}
	repoId, err := IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		return nil, err
	}
	return state.recoveryKey(memberId, func(generation uint64) *EvsRepoKey { return self.GkmHeldKey(repoId, generation) })
}

// A cold follower can start on a folded head instead of observing the original RecoveryBind entry.
func (self *Sidecar) sealOwnRecoveryBinding(key *GkmRecoveryKey) error {
	authority := self.authority()
	if authority == nil {
		return ErrSidecarActNoAuthority
	}
	if err := self.keepRecoveryPublicKey(key.BindingKeySha256, key.XwingPublicKey); err != nil {
		return err
	}
	return self.syncRecoverySeal(authority, authority.Pin())
}

// Whether the network's keychain under gkm's namespace holds RK_g of some generation of the repo, read with no state
// and no key client (QD-817): what a host's key client answers a config follower before its group client is built, so a
// restart that holds the config key keeps the full check from base 1. False before enrollment, and where the keychain
// does not read.
func (self *Sidecar) GkmRepoKeyHeld(repoId Id) bool {
	networkId := self.enrolledNetworkId()
	if networkId == nil || self.instance == nil {
		return false
	}
	held, err := gkmKeychainHoldsRepoKey(self.instance.secrets(*networkId, gkmUpkeepSecretsNamespace), repoId)
	return err == nil && held
}

// The args this sidecar's MLS engine takes (§10.4) for the network it is enrolled in: its sidecar_id and identity key,
// admissionSha256, the hash of the admission the verified state gives it (SidecarRow.admission_sha256, the Genesis's
// for a network's first device), which every credential it signs names, Sign, the network's store, under which the
// engine keeps gkm/, check, which judges each leaf another sidecar brings, and the clock. Refuses before enrollment and
// a hash of another length.
func (self *Sidecar) MlsEngineArgs(admissionSha256 []byte, check MlsCredentialCheck) (*MlsEngineArgs, error) {
	networkId := self.enrolledNetworkId()
	identity := self.currentIdentity()
	if networkId == nil || identity == nil || self.instance == nil {
		return nil, fmt.Errorf("%w: mls needs an enrolled network", errInvalidSettings)
	}
	if len(admissionSha256) != sha256.Size || len(identity.IdentityPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: mls needs the admission's hash and the identity key", errInvalidSettings)
	}
	return &MlsEngineArgs{
		SidecarId:         identity.SidecarId,
		IdentityPublicKey: ed25519.PublicKey(bytes.Clone(identity.IdentityPublicKey)),
		AdmissionSha256:   bytes.Clone(admissionSha256),
		Sign:              self.Sign,
		Store:             self.instance.Store(networkId),
		CheckCredential:   check,
		Clock:             self.clock,
	}, nil
}

// A flow's alarm (§10.9) as this Sidecar's event: a refused commit, rotation, delivery or wrap is refused, a pin off
// this device's chain or one that would fall is head_alarm (fork). An owner-bound repo's device waiting for consent
// names no approval this Sidecar holds, so it is logged, as every alarm is, by ids and positions alone (I-13).
func (self *Sidecar) raiseGkmAlarm(alarm *GkmAlarm) {
	if alarm == nil {
		return
	}
	self.log.Warningf("[gkm]alarm %s on group %s epoch %d generation %d: %s", alarm.Kind, alarm.GroupId, alarm.Epoch, alarm.Generation, alarm.Reason)
	repoId, groupId, sidecarId := alarm.RepoId, alarm.GroupId, alarm.SidecarId
	switch alarm.Kind {
	case GkmAlarmRefused, GkmAlarmWrapConflict:
		event := SidecarEvent{Kind: SidecarEventRefused, RepoId: &repoId, GroupId: &groupId}
		if sidecarId != (Id{}) {
			event.SidecarId = &sidecarId
		}
		self.emitEvent(event)
	case GkmAlarmHead:
		self.emitEvent(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork, RepoId: &repoId, GroupId: &groupId})
	}
}
