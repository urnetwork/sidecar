// §7.9's RecoveryVeto and the precedence of a veto a device holds off the log (D-TEAM-21):
//
//	valid veto  a RecoveryVeto whose entry lies between the proposal's entry o and its activation a, or one a device
//	              holds (signed, or verified in HeadCheck) whose at.version is >= o and < a, either signed by an
//	              AdminSet member's admitted device, never the proposed device or a read_only one, and countersigned
//	              as the presence row asks
//	precedence  a device that held a valid veto before it applied a refuses the activation: its log forks at a; one
//	              that first verifies the veto after a only alarms
//
// A veto on the log closes the proposal at its position, at every reader alike. HoldVeto is the device's side:
// CORE-M2-04 signs vetoes and PROTO's HeadCheck gossips them, and both hand each verified one here, so the log that
// applies the activation is the one that forks.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. On every leg.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A veto a device holds names a proposal the log already activated: it only alarms (§7.9's precedence row).
var ErrConfigVetoLate = errors.New("config veto after its proposal's activation")

// Registers RecoveryVeto's rule.
func init() {
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_RECOVERY_VETO,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckRecoveryVeto,
		apply:      configApplyRecoveryVeto,
	})
}

// The open proposal a veto names, held by Recovery's window, and the device it would admit, if it admits one.
func (self *ConfigState) vetoedProposal(veto *protocol.RecoveryVeto, timeMs int64) (*configProposal, *Id, error) {
	if len(veto.GetProposalId()) != sha256.Size {
		return nil, nil, fmt.Errorf("%w: a proposal_id of %d bytes", ErrConfigRule, len(veto.GetProposalId()))
	}
	proposal := self.proposals[[sha256.Size]byte(veto.GetProposalId())]
	if proposal == nil || !proposal.open(timeMs) || !proposal.windowed() {
		return nil, nil, fmt.Errorf("%w: a veto of no proposal a window holds open", ErrConfigRule)
	}
	if admit, ok := proposal.statement.body.(*protocol.SidecarAdmit); ok {
		if admission, err := configSidecarAdmission(admit); err == nil {
			return proposal, &admission.sidecarId, nil
		}
	}
	return proposal, nil, nil
}

// A RecoveryVeto: of an open proposal Recovery's window holds, by one standing member device of an AdminSet member,
// not read_only, the subject's other devices included, never the device the proposal admits.
func configCheckRecoveryVeto(state *ConfigState, statement *configStatement) error {
	veto := statement.body.(*protocol.RecoveryVeto)
	_, proposedId, err := state.vetoedProposal(veto, statement.timeMs)
	if err != nil {
		return err
	}
	if len(statement.signers) != 1 {
		return fmt.Errorf("%w: a veto takes one device's signature", ErrConfigSigner)
	}
	if _, ok := state.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		return configRoleInAdminSet(role) && (proposedId == nil || signerId != *proposedId)
	}); !ok {
		return fmt.Errorf("%w: a veto needs an AdminSet member's admitted device", ErrConfigAuthority)
	}
	return nil
}

// A RecoveryVeto's effect: the proposal closes, vetoed, here.
func configApplyRecoveryVeto(next *configStateBuilder, statement *configStatement) error {
	proposalId := statement.body.(*protocol.RecoveryVeto).GetProposalId()
	if len(proposalId) != sha256.Size || next.proposal([sha256.Size]byte(proposalId)) == nil {
		return fmt.Errorf("%w: no such proposal", ErrConfigRule)
	}
	next.closeProposal([sha256.Size]byte(proposalId), statement.n, ConfigProposalVetoed)
	return nil
}

// Holds a veto this device signed or verified in HeadCheck, its Signed as received, so this log forks at an activation
// of its proposal rather than apply it (§7.9's precedence row). The veto must be valid at the current state: a
// RecoveryVeto of an open proposal a window holds, signed by whom its rule allows, with any countersignature the
// presence row asks, and its at at or after the proposal's entry. ErrConfigVetoLate when the proposal already
// activated, which the caller alarms on; any other error leaves nothing held. For the goroutine that applies, as Apply
// is.
func (self *ConfigLog) HoldVeto(signedVeto []byte) error {
	state := self.state.Load()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedVeto, signed); err != nil {
		return fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_RECOVERY_VETO {
		return fmt.Errorf("%w: a held veto of type %d", ErrConfigRule, signed.GetType())
	}
	message, err := ParseConfigStatement(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_RECOVERY_VETO, signed.GetBody())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	veto := message.(*protocol.RecoveryVeto)
	if len(veto.GetProposalId()) == sha256.Size {
		if proposal := state.proposals[[sha256.Size]byte(veto.GetProposalId())]; proposal != nil && proposal.closed == ConfigProposalActivated {
			return fmt.Errorf("%w at %d", ErrConfigVetoLate, proposal.closedAt)
		}
	}
	statement := &configStatement{
		signedType: bridge.SignedType_SIGNED_RECOVERY_VETO,
		purpose:    bridge.SignedPurposeAuthority,
		body:       veto,
		bodyBytes:  signed.GetBody(),
		header:     veto.GetHeader(),
		id:         bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_RECOVERY_VETO, signed.GetBody()),
		n:          state.n + 1,
		timeMs:     state.timeMs,
		signed:     signed,
	}
	signer, err := state.verifySigner(signed, statement.purpose, statement.signedType, state.timeMs)
	if err != nil {
		return err
	}
	statement.signers = []ConfigSigner{signer}
	if err := configCheckRecoveryVeto(state, statement); err != nil {
		return err
	}
	if err := configPresenceCheck(state, statement); err != nil {
		return err
	}
	proposal := state.proposals[[sha256.Size]byte(veto.GetProposalId())]
	if at := veto.GetHeader().GetAt(); at == nil || at.GetVersion() < proposal.row.GetProposedAt() || !state.OnChain(at) {
		return fmt.Errorf("%w: a held veto's at before its proposal or off this chain", ErrConfigReplay)
	}
	if self.heldVetoes == nil {
		self.heldVetoes = map[[sha256.Size]byte]uint64{}
	}
	self.heldVetoes[proposal.id] = veto.GetHeader().GetAt().GetVersion()
	return nil
}

// The fork an activation at n makes when this log holds a valid veto of its proposal, nil when it holds none.
func (self *ConfigLog) heldVetoFork(kept *configKeptEntry, tick *bridge.ApiTick) error {
	for _, proposalId := range tick.GetActivatedProposalIds() {
		if len(proposalId) != sha256.Size {
			continue
		}
		if at, held := self.heldVetoes[[sha256.Size]byte(proposalId)]; held && at < kept.n {
			return self.stopAtFork(&ConfigForkError{
				N: kept.n, RemoteChain: kept.chain, Entry: kept.entryBytes,
				Reason: "an activation of a proposal this reader holds a valid veto of",
			})
		}
	}
	return nil
}
