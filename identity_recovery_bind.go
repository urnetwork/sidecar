// Signing a member's recovery binding (§5.9's Recovery code, §7.9's RecoveryBind and RecoveryRebind, D-CORE-10,
// D-CORE-14; owner decisions 62, 127, 149, 189): what `ur keychain recovery-rotate [--compromise]` runs.
//
// RotateRecovery draws a fresh code, derives its keys, and hands their public half to BindRecovery, which signs the
// binding of both public keys to this device's member as one sidecarAct of the person's confirmation: a RecoveryBind where the member has no binding in effect,
// else a RecoveryRebind naming the one it replaces, reason routine or, with compromise, compromise, which makes each
// repo's next rotation a remove rotation with a path epoch (§10.8, KEYS-M2-24). The signer is the member's consented
// device (§8.5); for an AdminSet member the statement is an authority one, which goes as an AuthorityProposal where
// the log asks for more than one counted signer. The log's presence row decides the presence check, never the caller.
// The binding's body, both public keys and genesis_sig, rides sealed under the config repo's key
// (plan-TEAM-sealed-field-format), and genesis_sig is the new Ed25519 key's signature over this network's anchored
// genesis (§7.9's recovery anchor).
//
// The code is returned once, as its 12 words, for the caller to show, and nothing here keeps it: the private keys are
// erased before the act runs, and this device keeps only the binding's X-Wing public key, which the sealer seals
// keychain.wrap to once the binding is current (keys_recovery_seal.go). A host apart from the Sidecar's process, `ur`
// beside its daemon, draws the code itself: RecoveryAnchor gives what the genesis_sig signs, and BindRecovery takes
// only the public keys and that signature, so no code, word or private key crosses the control socket or enters the
// daemon. Afterwards the old code admits nothing and
// gets no new wrap, and opens only what was wrapped to it before; a backup sealed before the rebind still opens under
// the old code, which §5.9 discloses and the result repeats.
//
// Gated: SidecarSettings.RecoveryBindings is off until §5.9 states QD-010's derivation, and while it is off nothing
// is drawn or signed.
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// SidecarSettings.RecoveryBindings is off: no binding is signed until §5.9 states the derivation (QD-010).
	ErrRecoveryBindingGated = errors.New("recovery bindings are not signed yet: the design does not state the code's key derivation")
	// This device is not its member's consented, approval-capable device, which alone signs its member's binding.
	ErrRecoveryBindingNotEligible = errors.New("only the member's consented device signs its recovery binding")
	// No anchored genesis or no config key, so no genesis_sig can be made or no body sealed.
	ErrRecoveryBindingNotReady = errors.New("this device holds no anchored genesis or no config key yet")
)

// §5.9's backup rule, which a rotation's result and `ur keychain recovery-rotate` repeat.
const RecoveryBackupRule = "A backup of this device's state made before this rotation still opens under the old recovery code. " +
	"Destroy such backups, or keep the old code as safe as the new one until they are gone."

// A new binding's public half: what a code's holder hands the device that signs its binding.
type RecoveryBinding struct {
	// RecoveryKeys.Ed25519PublicKey, 32 bytes.
	Ed25519PublicKey []byte
	// RecoveryKeys.XwingPublicKey, 1,216 bytes.
	XwingPublicKey []byte
	// RecoveryKeys.SignGenesis over RecoveryAnchor's network and genesis.
	GenesisSig []byte
}

// What a rotation did.
type RecoveryRotation struct {
	// RotateRecovery only: the new code's 12 words, to show once. Nothing keeps them; the caller drops them once
	// shown.
	Words []string
	// The new binding's name: SHA-256 of its Ed25519 public key.
	KeySha256 []byte
	// The binding it replaced, its key hash; nil for a first binding.
	PreviousKeySha256 []byte
	// Whether the rebind's reason is compromise.
	Compromise bool
	// The entry the statement landed at. Nil while its post is pending (Pending) or it went as a proposal.
	Entry *bridge.AuthPin
	// §7.9's 32-byte proposal_id where the statement went as an AuthorityProposal, awaiting cosigns.
	ProposalId []byte
	// The statement is signed and kept, and its post goes again with the same bytes: the code is the member's new
	// code once it lands.
	Pending bool
	// The member's devices at the rotation, this one first: with compromise, the ones a person reviews and revokes
	// (g0-recheck-2-compromise-rebind-backups #1), the rebind's signer, this device, last of all.
	Devices []MemberDevice
}

// What a genesis_sig for this sidecar's network signs: the network and its anchored A_0 (§7.9's recovery anchor).
// ErrRecoveryBindingNotReady while no genesis is anchored.
func (self *Sidecar) RecoveryAnchor() (Id, []byte, error) {
	identity := self.currentIdentity()
	if identity == nil {
		return Id{}, nil, ErrSidecarNoIdentity
	}
	anchor, err := self.Anchor()
	if err != nil || anchor == nil {
		return Id{}, nil, fmt.Errorf("%w: no anchored genesis", ErrRecoveryBindingNotReady)
	}
	return identity.NetworkId, bytes.Clone(anchor.GenesisSha256), nil
}

// Draws a fresh code, signs its binding for this device's member (BindRecovery) and answers the code, shown once. On
// ErrSidecarActPending the result still carries the code, since the statement may land; on any other error no code
// is answered, as it binds nothing.
func (self *Sidecar) RotateRecovery(ctx context.Context, compromise bool, origin SidecarActOrigin, check SidecarPresenceCheck) (*RecoveryRotation, error) {
	if !self.settings.RecoveryBindings {
		return nil, ErrRecoveryBindingGated
	}
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	networkId, genesisSha256, err := self.RecoveryAnchor()
	if err != nil {
		return nil, err
	}
	code, err := NewRecoveryCode(rand.Reader)
	if err != nil {
		return nil, err
	}
	words, err := code.Words()
	if err != nil {
		code.Erase()
		return nil, err
	}
	keys, err := code.Keys()
	if err != nil {
		return nil, err
	}
	genesisSig, err := keys.SignGenesis(networkId, genesisSha256)
	binding := &RecoveryBinding{
		Ed25519PublicKey: keys.Ed25519PublicKey(),
		XwingPublicKey:   keys.XwingPublicKey(),
		GenesisSig:       genesisSig,
	}
	// the private keys have done all this device needs of them
	keys.Erase()
	if err != nil {
		return nil, err
	}
	rotation, bindErr := self.BindRecovery(ctx, binding, compromise, origin, check)
	if rotation != nil {
		rotation.Words = words
	}
	return rotation, bindErr
}

// Signs binding as this device's member's recovery binding: a RecoveryBind where the member has none in effect, else
// a RecoveryRebind naming the one it replaces. origin must be a person's confirmation, on /dev/tty or in an app's UI;
// check is the presence check a covered act runs. The genesis_sig must verify for this network's anchored genesis
// before anything is signed. ErrRecoveryBindingGated while the setting is off; ErrRecoveryBindingNotEligible on any
// device but the member's consented one; ErrRecoveryBindingNotReady with no anchor or config key; the act's errors
// otherwise, a failed presence check signing nothing. ErrSidecarActPending comes with the result: the statement is
// signed and may land.
func (self *Sidecar) BindRecovery(ctx context.Context, binding *RecoveryBinding, compromise bool, origin SidecarActOrigin, check SidecarPresenceCheck) (*RecoveryRotation, error) {
	if !self.settings.RecoveryBindings {
		return nil, ErrRecoveryBindingGated
	}
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	identity := self.currentIdentity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	own, ok := self.approvalCapableAdmission(authority)
	if !ok || !authority.Consented(identity.SidecarId, own.MemberId) {
		return nil, ErrRecoveryBindingNotEligible
	}
	memberId := own.MemberId
	networkId, genesisSha256, err := self.RecoveryAnchor()
	if err != nil {
		return nil, err
	}
	if binding == nil || len(binding.XwingPublicKey) != recoveryXwingPublicKeyByteCount {
		return nil, ErrRecoveryKeys
	}
	if err := VerifyRecoveryGenesisSig(binding.Ed25519PublicKey, networkId, genesisSha256, binding.GenesisSig); err != nil {
		return nil, err
	}
	configKeys := self.configKeys()
	if configKeys == nil {
		return nil, fmt.Errorf("%w: no config key", ErrRecoveryBindingNotReady)
	}
	configKey, err := configKeys.CurrentConfigKey(ctx)
	if err != nil || configKey == nil {
		return nil, fmt.Errorf("%w: no config key", ErrRecoveryBindingNotReady)
	}
	body := &protocol.RecoveryBindBody{
		XwingPublicKey:   bytes.Clone(binding.XwingPublicKey),
		Ed25519PublicKey: bytes.Clone(binding.Ed25519PublicKey),
		GenesisSig:       bytes.Clone(binding.GenesisSig),
	}
	keySha256 := RecoveryKeySha256(binding.Ed25519PublicKey)

	rotation := &RecoveryRotation{KeySha256: keySha256, Compromise: compromise}
	var signedType bridge.SignedType
	var statement proto.Message
	if current := authority.CurrentBinding(memberId); current == nil {
		signedType = bridge.SignedType_SIGNED_RECOVERY_BIND
		statement = &protocol.RecoveryBind{MemberId: memberId.Bytes(), Ed25519PublicKeySha256: keySha256}
		rotation.Compromise = false
	} else {
		if bytes.Equal(current.GetKeySha256(), keySha256) {
			return nil, fmt.Errorf("%w: that binding is the one in effect", ErrRecoveryKeys)
		}
		rotation.PreviousKeySha256 = bytes.Clone(current.GetKeySha256())
		reason := bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_ROUTINE
		if compromise {
			reason = bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_COMPROMISE
		}
		signedType = bridge.SignedType_SIGNED_RECOVERY_REBIND
		statement = &protocol.RecoveryRebind{
			MemberId:               memberId.Bytes(),
			PrevSha256:             bytes.Clone(current.GetKeySha256()),
			Ed25519PublicKeySha256: keySha256,
			Reason:                 reason,
		}
	}
	// the seal binds the statement's own header, so it runs once the header is set
	seal := func(header *bridge.StatementHeader, withHeader proto.Message) error {
		sealedBody, err := SealConfigBody(configKey, NewConfigSealContext(signedType, header), body, rand.Reader)
		if err != nil {
			return err
		}
		switch message := withHeader.(type) {
		case *protocol.RecoveryBind:
			message.SealedBody = sealedBody
		case *protocol.RecoveryRebind:
			message.SealedBody = sealedBody
		}
		return nil
	}

	act, err := self.newAct(origin)
	if err != nil {
		return nil, err
	}
	proposal, err := act.addCounted(signedType, statement, seal)
	if err != nil {
		return nil, err
	}
	// the sealer needs the new binding's X-Wing key once the binding is current, whoever applies its entry first
	if err := self.keepRecoveryPublicKey(keySha256, body.GetXwingPublicKey()); err != nil {
		return nil, err
	}
	testHookBarrier("identity.recovery_bind.before", identity.SidecarId.String())
	pins, runErr := act.Run(ctx, check)
	testHookBarrier("identity.recovery_bind.after", identity.SidecarId.String())
	if runErr != nil && !errors.Is(runErr, ErrSidecarActPending) {
		// nothing was signed, or api refused it: the keys bind nothing
		return nil, runErr
	}
	rotation.Pending = runErr != nil
	if proposal {
		rotation.ProposalId = act.proposalId(0)
	} else if len(pins) == 1 {
		rotation.Entry = pins[0]
	}
	if devices, err := self.Devices(); err == nil {
		rotation.Devices = devices
	}
	return rotation, runErr
}
