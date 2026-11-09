// Revocation of this sidecar itself (§5.6, §18.5's State, D-CORE-8, D-SDK-14, I-4, I-15, CORE-M2-07).
//
// Outbound: ur logout signs SidecarRevoke{removed} for its own sidecar_id and posts it before anything else, then
// removes its client and wipes its state (identity_logout.go). The statement is kept in keychain.ur's pending records
// until it lands, so an offline logout keeps state and reports: a wipe first would strand the statement. A read_only
// device may sign it, since it is signing out (§7.9). A sidecar the verified log never admitted, or holds revoked
// already, has nothing to revoke there, and signs nothing.
//
// Inbound: a core hint of kind REVOCATION naming this sidecar, or a bind refused with sidecar_revoked, is a claim, and
// a server originates only denials (I-4). So the claim is never trusted: it fetches the config, and only a
// SidecarRevoke of this sidecar_id that verifies against it, a revoked row of the verified state, moves the sidecar to
// Revoked(signed). Anything else is Unenrolled(refused) with the refused alarm, identity, keys and admission kept, so a
// forged claim costs a client and never the identity. A revoked sidecar keeps its local keys (owner decision 64): only
// its own ur logout wipes.
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What bind's refusal answers for a revoked identity (plan-CORE-binding-wire #6).
const sidecarApiCodeSidecarRevoked = "sidecar_revoked"

var (
	// ur logout signed its SidecarRevoke and api did not answer it: the statement waits in keychain.ur and goes again
	// with the same bytes; nothing was removed or wiped.
	ErrSidecarLogoutPending = errors.New("the sign-out is signed and waits to post: run ur logout again once api answers; nothing was removed or wiped")
	// ur logout cannot sign the sign-out: no verified config state is installed for the network yet.
	ErrSidecarLogoutUnverified = errors.New("the network's config is not verified yet, so the sign-out cannot be signed: try again once the daemon follows it")
)

// An authority that can fetch the newest config before it answers: TEAM-M2-10's adapter, whose ConfigClient follows the
// log. Optional: an authority without it answers on what it holds.
type SidecarAuthorityRefresher interface {
	// Fetches and applies the log to its tip.
	Refresh(ctx context.Context) error
}

// Signs and posts this sidecar's SidecarRevoke{removed}, or posts again one an earlier logout kept: what ur logout runs
// before it removes the client (§5.6). nil once it has landed, or when the verified log holds nothing to revoke;
// ErrSidecarLogoutPending while api does not answer; ErrSidecarLogoutUnverified with no verified state; api's or the
// act's refusal otherwise.
func (self *Sidecar) signOut(ctx context.Context, identity *SidecarIdentity) error {
	// a sign-out an earlier try kept goes again with its same bytes, never signed anew
	pendings, err := self.pendingSignOuts(identity.SidecarId)
	if err != nil {
		return err
	}
	for _, pending := range pendings {
		if _, err := self.postPendingStatement(ctx, pending); err != nil {
			if errors.Is(err, ErrSidecarActRefused) {
				// refused or past its not_after: dropped, and the log decides below
				continue
			}
			return fmt.Errorf("%w: %w", ErrSidecarLogoutPending, err)
		}
		return nil
	}
	authority := self.authority()
	if authority == nil || authority.Pin() == nil {
		return ErrSidecarLogoutUnverified
	}
	if refresher, ok := authority.(SidecarAuthorityRefresher); ok {
		// a sign-out the generation's own repost landed shows here as revoked, and is not signed again
		if err := refresher.Refresh(ctx); err != nil {
			self.log.Infof("[identity]the config did not refresh before a sign-out: %s", err)
		}
	}
	admission := authority.Admission(identity.SidecarId)
	if admission == nil || admission.Row.GetRevokedAt() != 0 {
		// never admitted, or revoked already: the log holds nothing to revoke
		return nil
	}
	act, err := self.newAct(SidecarActConfirmed)
	if err != nil {
		return err
	}
	err = act.Add(bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		SidecarId: identity.SidecarId.Bytes(),
		Reason:    bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED,
	})
	if err != nil {
		return err
	}
	testHookBarrier("identity.logout.sign_out.before", identity.SidecarId.String())
	_, err = act.Run(ctx, nil)
	testHookBarrier("identity.logout.sign_out.after", identity.SidecarId.String())
	if errors.Is(err, ErrSidecarActPending) {
		return fmt.Errorf("%w: %w", ErrSidecarLogoutPending, err)
	}
	return err
}

// The pending statements that are this sidecar's own sign-out.
func (self *Sidecar) pendingSignOuts(sidecarId Id) ([]*sidecarPendingStatement, error) {
	pendings, err := self.pendingStatements()
	if err != nil {
		return nil, err
	}
	signOuts := []*sidecarPendingStatement{}
	for _, pending := range pendings {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(pending.signed, signed); err != nil {
			return nil, fmt.Errorf("%w: a pending statement", ErrSidecarStoreFailed)
		}
		if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE {
			continue
		}
		revoke := &bridge.SidecarRevoke{}
		if err := proto.Unmarshal(signed.GetBody(), revoke); err != nil {
			return nil, fmt.Errorf("%w: a pending statement", ErrSidecarStoreFailed)
		}
		if revokedId, err := IdFromBytes(revoke.GetSidecarId()); err == nil && revokedId == sidecarId {
			signOuts = append(signOuts, pending)
		}
	}
	return signOuts, nil
}

// Verifies a claim that this sidecar is revoked, a REVOCATION core hint or a bind refused with sidecar_revoked,
// against the config and never the claim (§5.6, §18.5, D-CORE-8, D-SDK-14): it fetches the config where the authority
// can, and answers true, moving to Revoked(signed), only when the verified state holds this sidecar revoked by a
// SidecarRevoke. Otherwise the claim does not verify: the current generation ends Unenrolled(refused) and raises the
// refused alarm, keeping identity, keys and admission. ErrSidecarNoIdentity before enrollment.
func (self *Sidecar) VerifyRevocationClaim(ctx context.Context) (bool, error) {
	identity := self.currentIdentity()
	if identity == nil {
		return false, ErrSidecarNoIdentity
	}
	switch self.lifecycleState() {
	case SidecarStateRevoked:
		return true, nil
	case SidecarStateLocked:
		// a lock is no client's to end: the claim waits for the unlock and the claim's next arrival
		return false, ErrSidecarStoreLocked
	}
	generation := self.lifecycleGeneration()
	authority := self.authority()
	if refresher, ok := authority.(SidecarAuthorityRefresher); ok {
		if err := refresher.Refresh(ctx); err != nil {
			// the claim is judged on what the verified state holds
			self.log.Infof("[identity]the config did not refresh for a revocation claim: %s", err)
		}
	}
	if authority != nil {
		if admission := authority.Admission(identity.SidecarId); admission != nil && admission.Row.GetRevokedAt() != 0 {
			self.enterRevoked(generation)
			return true, nil
		}
	}
	self.log.Warningf("[identity]a revocation claim did not verify against the config: generation %d ends refused", generation)
	self.tokenRefused(generation, SidecarReasonRefused)
	self.generationRefused(generation)
	self.emitEvent(SidecarEvent{Kind: SidecarEventRefused, Generation: generation})
	return false, nil
}

// Revoked(signed), from a SidecarRevoke the verified state holds. The run loop then ends the generation; the keychain
// and the identity stay this sidecar's own (owner decision 64).
func (self *Sidecar) enterRevoked(generation int64) {
	self.applyTransition(sidecarTransition{to: SidecarStateRevoked, reason: SidecarReasonSigned, generation: generation, verifiedRevocation: true})
	self.log.Warningf("[identity]revoked: a SidecarRevoke of this sidecar verified against the config")
	self.wake()
}

// Whether err is a bind api refused because the identity is revoked: a claim to verify, never a verdict.
func isSidecarRevokedRefusal(err error) bool {
	apiErr := &SidecarApiError{}
	return errors.As(err, &apiErr) && apiErr.Code == sidecarApiCodeSidecarRevoked
}

// A core hint's revocation claims, one verification at a time: a hint arrives on the push client's goroutine, which
// must not block, so the check runs on its own, and hints meanwhile join it.
type sidecarRevocationClaims struct {
	running atomic.Bool
}

// A core push (§6.8's core topic) of generation's client: hint is PushHint.hint, CoreHint's bytes
// (plan-CORE-core-hint-body #1), which carry no authority (§5.6). A REVOCATION naming this sidecar is a claim, verified
// against the config off this goroutine (VerifyRevocationClaim). Every other kind, an unknown one and a body that does
// not decode are a bare resync, which changes nothing here: no floor is applied from a hint (PROTO-M1-04, QD-032) and
// no gate reads one (OPS-M1-03).
func (self *Sidecar) receiveCoreHint(generation int64, hint []byte) {
	if generation < self.lifecycleGeneration() {
		return
	}
	self.stats.coreHintCount.Add(1)
	coreHint := &protocol.CoreHint{}
	if err := proto.Unmarshal(hint, coreHint); err != nil || coreHint.GetKind() != protocol.CoreHintKind_CORE_HINT_KIND_REVOCATION {
		if self.log.V(1).Enabled() {
			self.log.Infof("[sidecar]core hint of %d bytes, a bare resync", len(hint))
		}
		return
	}
	identity := self.currentIdentity()
	if identity == nil {
		return
	}
	if hintedId, err := IdFromBytes(coreHint.GetSidecarId()); err != nil || hintedId != identity.SidecarId {
		// a revocation hint names this client's own sidecar or nothing (plan-CORE-core-hint-body #1)
		return
	}
	if !self.revocationClaims.running.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer self.revocationClaims.running.Store(false)
		if _, err := self.VerifyRevocationClaim(self.ctx); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[identity]a revocation hint was not checked: %s", err)
		}
	}()
}
