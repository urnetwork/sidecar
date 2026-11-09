// Sidecar.Sign (§5.4, §6.9, D-CORE-6): the identity key signs every statement the server stores or verifies, and
// approvals unless a presence key does (§16.6). Sign builds §6.9's typed Signed with signer_id the sidecar_id, and
// takes only a (purpose, type) pair the identity key signs, so no caller can sign one type's body under another's
// purpose or a body the identity key is not the signer of.
//
// The ClientKey signs only the binding and §7.4's DPoP proofs (D-CORE-6), so nothing here reaches it: Sign reads
// the identity seed alone, and the binding's purposes are refused, since NewSidecarIdentityBinding signs those with
// both keys at once. Agent subkeys sign only sealed provenance, and until CORE-M6-03 an agent id selects no key.
//
// Nothing here names a connect type, so it builds on every leg.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Sign refused the purpose or the type before reading any key: the identity key signs no such statement. The
// error names the type's number and the purpose it expects, never the body.
var ErrSidecarSignRefused = errors.New("sign refused")

// The purpose the identity key signs signedType under, from signed.proto's registry (§6.11), and false for a type
// the identity key never signs: SIGNED_TYPE_NONE and unknown values, a socket ticket (a sockets service key's), a
// ShareCert (its ShareKey's) and the binding (NewSidecarIdentityBinding's, with the ClientKey). A type an area adds
// to signed.proto joins here with the purpose its format names.
func sidecarIdentitySignedPurpose(signedType bridge.SignedType) (string, bool) {
	switch signedType {
	case bridge.SignedType_SIGNED_SOCKET_REGISTRATION:
		return "socket-registration", true

	case bridge.SignedType_SIGNED_GRANT_ACTIVATE, bridge.SignedType_SIGNED_GRANT_REVOKE, bridge.SignedType_SIGNED_SUSPEND,
		bridge.SignedType_SIGNED_UNSUSPEND, bridge.SignedType_SIGNED_EVS_SHARE, bridge.SignedType_SIGNED_OWNER_CONFIRM,
		bridge.SignedType_SIGNED_REPO_CREATE, bridge.SignedType_SIGNED_REPO_ADMIN, bridge.SignedType_SIGNED_REPO_GRANT,
		bridge.SignedType_SIGNED_REPO_REVOKE, bridge.SignedType_SIGNED_REPO_DELETE, bridge.SignedType_SIGNED_REPO_RESTORE,
		bridge.SignedType_SIGNED_REPO_VERSIONING:
		return bridge.SignedPurposeAcl, true
	case bridge.SignedType_SIGNED_AUDIT_OPT_IN, bridge.SignedType_SIGNED_AUDIT_OPT_OUT:
		return bridge.SignedPurposeAuthority, true

	case bridge.SignedType_SIGNED_GENESIS, bridge.SignedType_SIGNED_ADMIN_SET, bridge.SignedType_SIGNED_MEMBER_ADMIT,
		bridge.SignedType_SIGNED_MEMBER_REVOKE, bridge.SignedType_SIGNED_SIDECAR_ADMIT, bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		bridge.SignedType_SIGNED_ADMISSION_CONFIRM, bridge.SignedType_SIGNED_SPONSOR_SET, bridge.SignedType_SIGNED_INDEXER_SET,
		bridge.SignedType_SIGNED_RECOVERY_BIND, bridge.SignedType_SIGNED_RECOVERY_REBIND, bridge.SignedType_SIGNED_KEY_REGISTER,
		bridge.SignedType_SIGNED_KEY_REVOKE, bridge.SignedType_SIGNED_DELEGATION, bridge.SignedType_SIGNED_DELEGATION_REVOKE,
		bridge.SignedType_SIGNED_SERVICE_SETTINGS, bridge.SignedType_SIGNED_VERSIONING_RULES,
		bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, bridge.SignedType_SIGNED_AUTHORITY_COSIGN,
		bridge.SignedType_SIGNED_RECOVERY_VETO, bridge.SignedType_SIGNED_PROJECTION_HEADER:
		return bridge.SignedPurposeAuthority, true

	case bridge.SignedType_SIGNED_GEN_ROTATE:
		return "gen-rotate", true
	case bridge.SignedType_SIGNED_READER_KEY:
		return "reader-key", true
	case bridge.SignedType_SIGNED_READER_WRAP, bridge.SignedType_SIGNED_DELEGATION_WRAP:
		return "reader-wrap", true
	case bridge.SignedType_SIGNED_GROUP_FORM:
		return "group-form", true
	case bridge.SignedType_SIGNED_UR_MLS_CREDENTIAL:
		return "mls-credential", true

	case bridge.SignedType_SIGNED_EVS_PUSH:
		return "evs-push", true
	case bridge.SignedType_SIGNED_EVS_RESEED:
		return "evs-reseed", true
	case bridge.SignedType_SIGNED_EVS_PATH_MAP:
		return "evs-path-epoch", true
	case bridge.SignedType_SIGNED_EVS_IMPORT:
		return "evs-import", true

	case bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION:
		return TlsKeyAttestationPurpose, true

	case bridge.SignedType_SIGNED_RECORD_HEADER, bridge.SignedType_SIGNED_RETENTION_POLICY:
		return "record-entry", true
	case bridge.SignedType_SIGNED_APPROVAL_DECISION, bridge.SignedType_SIGNED_APPROVAL_CANCEL:
		return "approval", true
	case bridge.SignedType_SIGNED_DIRECTORY_CARD, bridge.SignedType_SIGNED_DIRECTORY_REPO:
		return "directory", true

	case bridge.SignedType_SIGNED_BRIDGE_BLOCK, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, bridge.SignedType_SIGNED_BRIDGE_ROUTE,
		bridge.SignedType_SIGNED_BRIDGE_MAP, bridge.SignedType_SIGNED_BRIDGE_EGRESS, bridge.SignedType_SIGNED_BRIDGE_ALIAS,
		bridge.SignedType_SIGNED_BRIDGE_WITHDRAW:
		return bridge.SignedPurposeBridge, true
	case bridge.SignedType_SIGNED_WINDOW_DELEGATION:
		return "window-delegation", true
	}
	return "", false
}

// §6.9's Signed over body, as signedType under purpose, by this sidecar's identity key, signer_id its sidecar_id.
// Refuses, before reading any key, a pair the identity key does not sign (ErrSidecarSignRefused); answers a clean
// error wrapping ErrSidecarStoreLocked while Locked, and ErrSidecarNoIdentity before enrollment. agentId is the
// caller's provenance label (source = agent_asserted, §5.5): until CORE-M6-03's subkeys it selects no key, so the
// identity key signs whatever it names. body is copied.
func (self *Sidecar) Sign(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
	expectedPurpose, ok := sidecarIdentitySignedPurpose(signedType)
	if !ok {
		return nil, fmt.Errorf("%w: the identity key signs no type %#x", ErrSidecarSignRefused, int32(signedType))
	}
	if purpose != expectedPurpose {
		return nil, fmt.Errorf("%w: type %#x is signed under purpose %s", ErrSidecarSignRefused, int32(signedType), expectedPurpose)
	}
	var state SidecarState
	var secrets SidecarSecrets
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state = self.lifecycle.state
		secrets = self.coreSecrets
	}()
	switch state {
	case SidecarStateLocked:
		return nil, fmt.Errorf("sign: %w", ErrSidecarStoreLocked)
	case SidecarStateRevoked:
		return nil, fmt.Errorf("%w: this sidecar is revoked", ErrSidecarSignRefused)
	}
	if secrets == nil {
		return nil, fmt.Errorf("sign: %w", ErrSidecarNoIdentity)
	}
	record, err := loadSidecarIdentity(secrets)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	defer record.keys.erase()
	identityKey := ed25519.NewKeyFromSeed(record.keys.identitySeed)
	defer clear(identityKey)
	signature := ed25519.Sign(identityKey, bridge.SignedBytes(purpose, signedType, body))
	if agentId != nil && self.log.V(2).Enabled() {
		self.log.Infof("[identity]signed type %#x for agent %s", int32(signedType), agentId.String())
	}
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  record.identity.SidecarId.Bytes(),
		Signature: signature,
		Type:      uint32(signedType),
	}, nil
}

// This sidecar's identity, a copy, or nil before the keychain holds one.
func (self *Sidecar) currentIdentity() *SidecarIdentity {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.identity == nil {
		return nil
	}
	return self.identity.clone()
}

// This sidecar's ids, generation and public keys, a copy holding no private key, for a host such as §18.5's
// GetSidecarId: nil before the keychain holds an identity, so while Locked before its first unlock and before
// enrollment.
func (self *Sidecar) Identity() *SidecarIdentity {
	return self.currentIdentity()
}

// Points the sidecar at secrets, the core's namespace of its network's keychain, and reads the identity it holds:
// what NewSidecar and an unlock do (CORE-M1-08), and enrollment once it has persisted one (CORE-M1-09).
// ErrSidecarNoIdentity leaves the sidecar pointed at secrets with no identity, as before enrollment.
func (self *Sidecar) adoptIdentity(secrets SidecarSecrets) error {
	record, err := loadSidecarIdentity(secrets)
	if err != nil && !errors.Is(err, ErrSidecarNoIdentity) {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.coreSecrets = secrets
	self.identity = nil
	if record != nil {
		record.keys.erase()
		self.identity = record.identity
	}
	return nil
}
