//go:build !js && !ios && !android && !sdk_mobile_bind

// The daemon's presence prompt and its keys (MCP-M3-09; D-MCP-19, I-8, FS-124, FS-28), over the host's platform
// authenticator, which cli/ sets (PresenceProvider: the ur bundle's Secure Enclave key through purego and
// LocalAuthentication on macOS, Windows Hello through webauthn.dll, a FIDO key over CTAP2 on Linux):
//
//	prompt    PresencePrompt(running): the one function value an act's presence check, a device revocation and a
//	          presence decision take on this host (SidecarPresenceCheck). It asserts over the bytes given with a key
//	          this sidecar registered for its member, live at its state, that the authenticator holds, asking the
//	          person afresh at each call: a Secure Enclave key through a fresh LAContext with no reuse duration
//	          (§16.6's countersign row), a FIDO key with a touch and UV. Each prompt ends by
//	          Ingest.PresencePromptTimeout. What it answers is verified by its caller before anything is signed or
//	          filed: the act's Countersign, the approver's per-use check.
//	register  RegisterPresenceKey: §16.6's register row, on a person's confirmation alone (ur keys add-presence on
//	          /dev/tty, ur login's offer), never a harness's word: a consented, approval-capable device signs the
//	          new key's KeyRegister, carrying the key's own signature over the body before field 9 (QD-086), and the
//	          act's countersignature where this device registered a live key, which the act takes from the log's
//	          presence row, never from a caller. What the authenticator's client answered as the key's attestation
//	          (QD-730's map) is checked by VerifyPresenceAttestation first: one that fails registers nothing
//	remove    RevokePresenceKey: KeyRevoke of one of the member's keys, on a confirmation alone, a presence key only
//	          from a device that registered a live one of its own, the act countersigned
//	list      PresenceKeys: the member's live presence keys, each with its registering device and position
//
// A failed or refused check signs nothing. A key the authenticator made for a registration that then signed nothing
// is taken off it again. Real authenticators are external, so everything above the provider runs on a fake with
// fixture keys in tests. Nothing here holds a private key: the authenticator keeps it, so nothing calls
// testHookSecret. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A presence key the authenticator made, as its KeyRegister names it.
type PresenceKeyHandle struct {
	// The authenticator's name for it, at most 64 bytes: a credential id, or a hash of the key.
	KeyId []byte
	// webauthn-es256 or ecdsa-p256-sha256.
	Alg bridge.KeyAlg
	// A SEC 1 uncompressed point, 65 bytes (QD-445).
	PublicKey []byte
	// KeyRegister.attestation's bytes for a webauthn-es256 key: EncodePresenceAttestation's map of the create ceremony's
	// attestation object and its client data, the clientDataJSON a platform API returned or the JSON a CTAP2 client
	// hashed (QD-730). Clients ask for none conveyance until release roots ship (QD-137), so the object is fmt none.
	// Empty for an ecdsa-p256-sha256 key, which carries none, and for a client that kept none.
	Attestation []byte
}

// A platform authenticator holding presence keys (§16.6's profiles). Safe for concurrent use.
type PresenceProvider interface {
	// Makes a new key under its profile, asking the person as its creation does.
	Register(ctx context.Context) (*PresenceKeyHandle, error)
	// Whether it holds the key of keyId.
	Holds(keyId []byte) bool
	// One assertion of keyId over message, asking the person afresh, never a reused authentication: for
	// webauthn-es256 the authenticator_data and client_data_json of a webauthn.get whose challenge is
	// base64url(SHA-256(message)), and the DER signature over authenticator_data || SHA-256(client_data_json); for
	// ecdsa-p256-sha256 the DER signature over SHA-256(message). key_id and signature are set in the evidence. An
	// error when the person refused, the bound passed or the key failed.
	Assert(ctx context.Context, keyId []byte, message []byte) (*bridge.WebAuthnEvidence, error)
	// Takes the key off the authenticator where it can; a key it does not hold is no error.
	Remove(keyId []byte) error
}

var (
	// No presence authenticator is set on this host.
	ErrPresenceUnavailable = errors.New("no presence authenticator on this host")
	// The authenticator holds no live presence key this sidecar registered for its member.
	ErrPresenceNoKey = errors.New("this host holds no live presence key of this sidecar's member")
	// What a registration's authenticator answered is no §16.6 presence key.
	ErrPresenceKeyInvalid = errors.New("the authenticator's key is no presence key")
)

// Sets the host's platform authenticator, nil for none, which every prompt then refuses: what cli/ sets at start.
func (self *Daemon) SetPresenceProvider(provider PresenceProvider) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.presenceProvider = provider
}

// The host's platform authenticator, nil for none.
func (self *Daemon) PresenceProvider() PresenceProvider {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.presenceProvider
}

// The daemon's presence prompt for running (the file header's prompt row), nil where no authenticator is set or no
// Sidecar is given.
func (self *Daemon) PresencePrompt(running *Sidecar) SidecarPresenceCheck {
	provider := self.PresenceProvider()
	if provider == nil || running == nil {
		return nil
	}
	return NewPresencePrompt(running, provider)
}

// The presence prompt of running over provider: the first of the keys running registered for its member, live at its
// state, that provider holds, asserted over each message within Ingest.PresencePromptTimeout.
func NewPresencePrompt(running *Sidecar, provider PresenceProvider) SidecarPresenceCheck {
	return func(message []byte) (*bridge.WebAuthnEvidence, error) {
		key, err := running.heldPresenceKey(provider)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), running.settings.Ingest.PresencePromptTimeout)
		defer cancel()
		evidence, err := provider.Assert(ctx, bytes.Clone(key.GetKeyId()), bytes.Clone(message))
		if err != nil {
			return nil, err
		}
		if evidence == nil || len(evidence.GetSignature()) == 0 {
			return nil, fmt.Errorf("%w: the authenticator answered no signature", ErrSidecarActPresence)
		}
		answered := proto.Clone(evidence).(*bridge.WebAuthnEvidence)
		answered.KeyId = bytes.Clone(key.GetKeyId())
		return answered, nil
	}
}

// This sidecar's member and standing to register or revoke a key: a consented, approval-capable device (§16.6's
// register row). ErrSidecarApprovalNotEligible where it is not.
func (self *Sidecar) presenceStanding() (SidecarAuthority, *SidecarIdentity, *AclSidecar, error) {
	authority := self.authority()
	if authority == nil {
		return nil, nil, nil, ErrSidecarActNoAuthority
	}
	identity := self.currentIdentity()
	if identity == nil {
		return nil, nil, nil, ErrSidecarNoIdentity
	}
	own, ok := self.approvalCapableAdmission(authority)
	if !ok || !authority.Consented(identity.SidecarId, own.MemberId) {
		return authority, identity, nil, fmt.Errorf("%w: only a consented, approval-capable device registers or removes a key", ErrSidecarApprovalNotEligible)
	}
	return authority, identity, own, nil
}

// The first live key, by key_id, this sidecar registered for its member that provider holds.
func (self *Sidecar) heldPresenceKey(provider PresenceProvider) (*bridge.KeyRow, error) {
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	identity := self.currentIdentity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	keys := slices.Clone(authority.LiveKeys(identity.SidecarId))
	slices.SortFunc(keys, func(a *bridge.KeyRow, b *bridge.KeyRow) int { return bytes.Compare(a.GetKeyId(), b.GetKeyId()) })
	for _, key := range keys {
		if key.GetPurpose() == bridge.KeyPurpose_KEY_PURPOSE_PRESENCE && provider.Holds(key.GetKeyId()) {
			return key, nil
		}
	}
	return nil, ErrPresenceNoKey
}

// One of the member's live presence keys, as ur keys ls lists it.
type SidecarPresenceKey struct {
	KeyId []byte
	Alg   bridge.KeyAlg
	// The device that registered it, and the log position its KeyRegister landed at; 0 while it waits to land.
	RegisteringSidecarId Id
	Position             uint64
	NotAfter             time.Time
	// Whether this host's authenticator holds it.
	Held bool
}

// The member's live presence keys, by registering device then key_id, each marked held where provider, nil for none,
// holds it.
func (self *Sidecar) PresenceKeys(provider PresenceProvider) ([]*SidecarPresenceKey, error) {
	authority, _, own, err := self.presenceStanding()
	if err != nil {
		return nil, err
	}
	devices := authority.MemberDevices(own.MemberId)
	slices.SortFunc(devices, func(a *AclSidecar, b *AclSidecar) int {
		return bytes.Compare(a.Row.GetSidecarId(), b.Row.GetSidecarId())
	})
	keys := []*SidecarPresenceKey{}
	for _, device := range devices {
		deviceId, err := IdFromBytes(device.Row.GetSidecarId())
		if err != nil {
			continue
		}
		rows := slices.Clone(authority.LiveKeys(deviceId))
		slices.SortFunc(rows, func(a *bridge.KeyRow, b *bridge.KeyRow) int { return bytes.Compare(a.GetKeyId(), b.GetKeyId()) })
		for _, row := range rows {
			if !bytes.Equal(row.GetMemberId(), own.MemberId.Bytes()) {
				continue
			}
			keys = append(keys, &SidecarPresenceKey{
				KeyId:                bytes.Clone(row.GetKeyId()),
				Alg:                  row.GetAlg(),
				RegisteringSidecarId: deviceId,
				Position:             row.GetAt(),
				NotAfter:             time.UnixMilli(row.GetNotAfter()),
				Held:                 provider != nil && provider.Holds(row.GetKeyId()),
			})
		}
	}
	return keys, nil
}

// §16.6's register row for a new key of provider's: on the person's confirmation alone, a KeyRegister of this sidecar's
// member carrying the key's own proof, signed as an act, countersigned by check where the log covers it (a live key
// this device registered). A first presence key needs no check. The new key is taken off the authenticator again when
// nothing was signed. Answers the key as ur keys ls lists it, its position 0 until it lands.
func (self *Sidecar) RegisterPresenceKey(ctx context.Context, provider PresenceProvider, origin SidecarActOrigin, check SidecarPresenceCheck) (*SidecarPresenceKey, error) {
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	if provider == nil {
		return nil, ErrPresenceUnavailable
	}
	_, identity, own, err := self.presenceStanding()
	if err != nil {
		return nil, err
	}
	act, err := self.newAct(origin)
	if err != nil {
		return nil, err
	}
	handle, err := provider.Register(ctx)
	if err != nil {
		return nil, err
	}
	signed := false
	defer func() {
		if !signed {
			if err := provider.Remove(handle.KeyId); err != nil {
				self.log.Warningf("[presence]a key registered for nothing was not removed from the authenticator: %s", err)
			}
		}
	}()
	if _, err := presenceSignedKeyAlg(handle.Alg); err != nil || len(handle.PublicKey) != 65 ||
		len(handle.KeyId) == 0 || configKeyIdMaxByteCount < len(handle.KeyId) {
		return nil, fmt.Errorf("%w: alg %s, key_id %d bytes, public key %d bytes", ErrPresenceKeyInvalid, handle.Alg, len(handle.KeyId), len(handle.PublicKey))
	}
	notAfter := self.clock.Now().Add(self.settings.Mcp.PresenceKeyLifetime)
	register := &protocol.KeyRegister{
		MemberId:    own.MemberId.Bytes(),
		KeyId:       bytes.Clone(handle.KeyId),
		Alg:         handle.Alg,
		PublicKey:   bytes.Clone(handle.PublicKey),
		Attestation: bytes.Clone(handle.Attestation),
		Purpose:     bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
		NotAfter:    notAfter.UnixMilli(),
	}
	// the device about to sign refuses an attestation that fails, never signing it as asserted (§16.6's labels)
	if _, err := VerifyPresenceAttestation(register, self.clock.Now().UnixMilli()); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPresenceKeyInvalid, err)
	}
	// QD-086: the new key signs the body before field 9, header included, which AddSealed has set by now
	err = act.AddSealed(bridge.SignedType_SIGNED_KEY_REGISTER, register, func(header *bridge.StatementHeader, statement proto.Message) error {
		keyRegister := statement.(*protocol.KeyRegister)
		keyRegister.KeySignature = nil
		keyRegister.KeyWebauthn = nil
		prefix, err := proto.MarshalOptions{Deterministic: true}.Marshal(keyRegister)
		if err != nil {
			return err
		}
		evidence, err := provider.Assert(ctx, bytes.Clone(handle.KeyId), bridge.SignedBytes(PresenceKeyProofPurpose, bridge.SignedType_SIGNED_KEY_REGISTER, prefix))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSidecarActPresence, err)
		}
		keyRegister.KeySignature = bytes.Clone(evidence.GetSignature())
		if len(evidence.GetAuthenticatorData()) != 0 || len(evidence.GetClientDataJson()) != 0 {
			keyRegister.KeyWebauthn = &bridge.WebAuthnEvidence{
				AuthenticatorData: bytes.Clone(evidence.GetAuthenticatorData()),
				ClientDataJson:    bytes.Clone(evidence.GetClientDataJson()),
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// the proof covers the bytes the act signs, which every verifier slices at field 9
	body := act.statements[len(act.statements)-1].body
	parsed := &protocol.KeyRegister{}
	if err := proto.Unmarshal(body, parsed); err != nil {
		return nil, err
	}
	if err := VerifyPresenceRegistration(parsed, &bridge.Signed{Body: body, Type: uint32(bridge.SignedType_SIGNED_KEY_REGISTER)}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarActPresence, err)
	}
	pins, err := act.Run(ctx, check)
	if err != nil && !errors.Is(err, ErrSidecarActPending) {
		return nil, err
	}
	signed = true
	key := &SidecarPresenceKey{
		KeyId:                bytes.Clone(handle.KeyId),
		Alg:                  handle.Alg,
		RegisteringSidecarId: identity.SidecarId,
		NotAfter:             time.UnixMilli(notAfter.UnixMilli()),
		Held:                 true,
	}
	if 0 < len(pins) && pins[0] != nil {
		key.Position = pins[0].GetVersion()
	}
	return key, err
}

// §16.6's remove row: on the person's confirmation alone, KeyRevoke of one of the member's live keys, a presence key
// only from a device that registered a live presence key of its own, the act countersigned by check where the log
// covers it. provider, nil for none, takes the key off this host's authenticator once the revocation is signed.
func (self *Sidecar) RevokePresenceKey(ctx context.Context, keyId []byte, provider PresenceProvider, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if origin != SidecarActConfirmed {
		return ErrSidecarActMode
	}
	authority, identity, own, err := self.presenceStanding()
	if err != nil {
		return err
	}
	keys, err := self.PresenceKeys(nil)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(keys, func(key *SidecarPresenceKey) bool { return bytes.Equal(key.KeyId, keyId) }) {
		return fmt.Errorf("%w: no live key of member %s has that key_id", ErrSidecarApprovalUnknown, own.MemberId)
	}
	ownKeys := authority.LiveKeys(identity.SidecarId)
	if !slices.ContainsFunc(ownKeys, func(key *bridge.KeyRow) bool { return key.GetPurpose() == bridge.KeyPurpose_KEY_PURPOSE_PRESENCE }) {
		return fmt.Errorf("%w: a presence key is removed only from a device that registered a live one of its own", ErrSidecarApprovalNotEligible)
	}
	act, err := self.newAct(origin)
	if err != nil {
		return err
	}
	if err := act.Add(bridge.SignedType_SIGNED_KEY_REVOKE, &protocol.KeyRevoke{KeyId: bytes.Clone(keyId)}); err != nil {
		return err
	}
	_, err = act.Run(ctx, check)
	if err != nil && !errors.Is(err, ErrSidecarActPending) {
		return err
	}
	if provider != nil && provider.Holds(keyId) {
		if removeErr := provider.Remove(keyId); removeErr != nil {
			self.log.Warningf("[presence]a revoked key stays on the authenticator: %s", removeErr)
		}
	}
	return err
}
