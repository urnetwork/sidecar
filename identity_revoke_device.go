// RevokeDevice (CORE-M3-03, D-CORE-20, I-4, I-15, FI-2, FS-98, FS-124; DESIGN-DETAILS 5.7): §5.6's sign and effects
// rows for a member's revocation of another of its own devices.
//
//	derive    the plan again at the tip it signs at: REVOKE_STALE only if its PlanId changed or it was never previewed
//	          here, REVOKE_PARKS_SELF if P now holds this sidecar; park and void items that entered after the preview,
//	          each resting on a signature in P, join unasked and are listed in the result
//	approve   the call is a person's confirmation, of a ur command on /dev/tty or in an app's UI, which only a
//	          confirmed control call or an app reaches; any other origin, MCP's, a hook's or an unconfirmed control
//	          call's, is refused with nothing signed; where the log covers the act, one presence
//	          check over the act's countersigned bytes (identity_act.go), and a failed or refused check, or evidence
//	          that does not verify, answers REVOKE_CANCELLED with nothing signed
//	sign      the SidecarRevoke, or where the plan needs k > 1 counted signatures its AuthorityProposal with, in the
//	          same act, Suspend{target} signed as its owner, so the target loses scope within 5 s while cosigns are due;
//	          under Presence also a KeyRevoke of each listed key the person left selected, else none. Everything goes
//	          through sidecarAct, so each statement is kept before any is posted and a kill or a lost answer retries
//	          the same bytes until its not_after (identity_pending.go)
//	answer    REVOKE_REFUSED when api or a verifier refuses a statement at the tip; ErrSidecarActPending when the
//	          statements are signed and a post's answer was lost, the decision made and the post going again; anything
//	          before a signature as it is
//	effects   from the revocation's entry, at k > 1 its completing cosign's, which this device sees applied with the
//	          proposal's row gone from PendingProposal: this device commits its Removes first (KEYS-M2-21's commit,
//	          SidecarRevokeEffects.CommitRevocation), then shows the revocation unwitnessed until a HeadCheck peer holds
//	          its position (§6.4's revoker row, TrackRevocation)
//
// A target already revoked signs no second SidecarRevoke where the standing one covers the plan; the call then
// revokes its selected keys alone, under Presence, or answers the standing entry.
//
// testHookBarrier brackets the signing point and the effects; each post has identity.post's.
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A key id RevokeDevice was asked to revoke that the plan does not list.
var ErrSidecarRevokeKey = errors.New("the key is no key item of the plan")

// What a landed revocation hands on. KEYS installs the commit (KEYS-M2-21) and §6's HeadStopState the tracking; with
// none installed the revocation still lands, and any writer leaf commits the Removes (§7.10's commit).
type SidecarRevokeEffects interface {
	// Commits this device's Removes of the revoked sidecar's leaves, in the config and directory groups by rotation
	// alone where this device is wrapped, from the revocation's entry.
	CommitRevocation(ctx context.Context, sidecarId Id, entry *bridge.AuthPin) error
	// Shows the revocation at position unwitnessed until a HeadCheck peer holds it (HeadStopState.TrackRevocation).
	TrackRevocation(position uint64)
}

// What RevokeDevicePlan did.
type DeviceRevocation struct {
	PlanId    Id
	SidecarId Id
	// The SidecarRevoke's entry (n, A_n); for a target a standing revocation covers, that revocation's position
	// alone. Nil while a proposal pends or a post's answer is lost.
	Entry *bridge.AuthPin
	// §7.9's 32-byte proposal_id while k > 1 pends.
	ProposalId []byte
	// The park and void items that entered after the preview and joined unasked.
	Joined []DeviceRevokeItem
	// The keys whose KeyRevoke the act signed.
	RevokedKeyIds [][]byte
	// The statements are signed and kept, and a post's answer was lost: they go again with the same bytes.
	Pending bool
}

// A revocation this device signed whose entry it has not seen yet, watched until it applies: a k > 1 proposal until
// its completing cosign, or a revocation whose post's answer was lost until its retry lands.
type sidecarRevokeWatch struct {
	// the proposal's id; nil for a revocation posted on its own
	proposalId []byte
	sidecarId  Id
}

// The watches a Sidecar holds, in memory, under the revoke plans' lock.
type sidecarRevokeWatches struct {
	watches []*sidecarRevokeWatch
}

// Installs effects as what a landed revocation hands on, replacing any before; the answer removes them, if they are
// still the installed ones.
func (self *Sidecar) InstallRevokeEffects(effects SidecarRevokeEffects) func() {
	func() {
		self.revokePlans.stateLock.Lock()
		defer self.revokePlans.stateLock.Unlock()
		self.revokePlans.effects = effects
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			self.revokePlans.stateLock.Lock()
			defer self.revokePlans.stateLock.Unlock()
			if self.revokePlans.effects == effects {
				self.revokePlans.effects = nil
			}
		})
	}
}

// §5.6's effects row for a revocation of sidecarId that landed at entry: this device's Removes first, then the
// revoker's tracking.
func (self *Sidecar) runRevokeEffects(ctx context.Context, sidecarId Id, entry *bridge.AuthPin) {
	effects := func() SidecarRevokeEffects {
		self.revokePlans.stateLock.Lock()
		defer self.revokePlans.stateLock.Unlock()
		return self.revokePlans.effects
	}()
	testHookBarrier("identity.revoke.effects.before", sidecarId.String())
	if effects == nil {
		self.log.Infof("[identity]the revocation at %d landed with no committer installed: a writer leaf commits its Removes", entry.GetVersion())
	} else {
		if err := effects.CommitRevocation(ctx, sidecarId, entry); err != nil {
			self.log.Warningf("[identity]this device's Removes for the revocation at %d were not committed: %s", entry.GetVersion(), err)
		}
		effects.TrackRevocation(entry.GetVersion())
	}
	testHookBarrier("identity.revoke.effects.after", sidecarId.String())
}

// The watcher's step for one applied entry: a SidecarRevoke of a watched target that took effect, its proposal's row
// gone, runs the effects at this entry, the completing cosign's or the retried post's.
func (self *Sidecar) applyRevokeEntry(authority SidecarAuthority, entry *SidecarAuthorityEntry) {
	if entry == nil || entry.Pin == nil || len(entry.Effects) == 0 {
		return
	}
	proposals, _ := authority.(SidecarAuthorityProposals)
	completed := []*sidecarRevokeWatch{}
	func() {
		self.revokePlans.stateLock.Lock()
		defer self.revokePlans.stateLock.Unlock()
		if len(self.revokeWatches.watches) == 0 {
			return
		}
		for _, effect := range entry.Effects {
			if effect.Type != bridge.SignedType_SIGNED_SIDECAR_REVOKE {
				continue
			}
			revoke := &bridge.SidecarRevoke{}
			if err := proto.Unmarshal(effect.Body, revoke); err != nil {
				continue
			}
			self.revokeWatches.watches = slices.DeleteFunc(self.revokeWatches.watches, func(watch *sidecarRevokeWatch) bool {
				if !bytes.Equal(revoke.GetSidecarId(), watch.sidecarId.Bytes()) {
					return false
				}
				if watch.proposalId != nil && proposals != nil && proposals.PendingProposal(watch.proposalId) != nil {
					// another revocation of the target landed; this proposal still pends
					return false
				}
				completed = append(completed, watch)
				return true
			})
		}
	}()
	pin := proto.Clone(entry.Pin).(*bridge.AuthPin)
	for _, watch := range completed {
		// the follower's goroutine must not block on a commit, which ends with the Sidecar's context
		go self.runRevokeEffects(self.ctx, watch.sidecarId, pin)
	}
}

// §5.4's RevokeDevice: signs the plan planId names, which PreviewDeviceRevoke answered on this Sidecar, re-derived at
// the tip. revokeKeyIds are the plan's key items the person left selected. presence is the host's check over the
// act's countersigned bytes, returning §6.9's WebAuthnEvidence encoded, nil only while the plan's Presence is unset.
// Answers the SidecarRevoke's entry, or at k > 1 the proposal's 32-byte id while it pends. Every refusal is a
// *DeviceRevokeError with §5.6's code; ErrSidecarActPending means the statements are signed and their post goes
// again. The caller is a person's confirmation: a ur command confirmed on /dev/tty, an app's UI or a remote-mode
// app's confirmed control calls, never MCP.
func (self *Sidecar) RevokeDevice(ctx context.Context, planId Id, revokeKeyIds [][]byte, presence func(challenge []byte) ([]byte, error)) (*bridge.AuthPin, []byte, error) {
	var check SidecarPresenceCheck
	if presence != nil {
		check = func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
			encoded, err := presence(countersignedBytes)
			if err != nil {
				return nil, err
			}
			evidence := &bridge.WebAuthnEvidence{}
			if err := proto.Unmarshal(encoded, evidence); err != nil {
				return nil, err
			}
			return evidence, nil
		}
	}
	revocation, err := self.RevokeDevicePlan(ctx, planId, revokeKeyIds, SidecarActConfirmed, check)
	if revocation == nil {
		return nil, nil, err
	}
	return revocation.Entry, revocation.ProposalId, err
}

// RevokeDevice with its whole result: the items that joined since the preview and the keys revoked beside the entry
// and the proposal. origin says who asked: anything but a person's confirmation, MCP's, a hook's or an unconfirmed
// control call's, is ErrSidecarActMode with nothing signed (D-CORE-13). check is the presence check as an act takes
// it. On REVOKE_REFUSED and ErrSidecarActPending the result says what landed before.
func (self *Sidecar) RevokeDevicePlan(ctx context.Context, planId Id, revokeKeyIds [][]byte, origin SidecarActOrigin, check SidecarPresenceCheck) (*DeviceRevocation, error) {
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	identity, err := self.devicesReady()
	if err != nil {
		return nil, err
	}
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	preview := self.revokePreview(planId)
	if preview == nil {
		return nil, &DeviceRevokeError{Code: DeviceRevokeCodeStale}
	}
	derivation, err := self.deriveDeviceRevoke(authority, identity, preview.plan.SidecarId, preview.plan.Reason, time.Time{}, preview.plan.SinceN, true)
	if err != nil {
		return nil, err
	}
	plan := derivation.plan
	if plan.PlanId != planId {
		return nil, &DeviceRevokeError{Code: DeviceRevokeCodeStale}
	}
	revocation := &DeviceRevocation{PlanId: planId, SidecarId: plan.SidecarId}
	// park and void items that entered after the preview join unasked
	for _, item := range plan.Items {
		if item.Effect != DeviceRevokeEffectPark && item.Effect != DeviceRevokeEffectVoid {
			continue
		}
		previewed := slices.ContainsFunc(preview.plan.Items, func(seen DeviceRevokeItem) bool {
			return seen.Effect == item.Effect && seen.Kind == item.Kind && bytes.Equal(seen.Id, item.Id) && seen.Position == item.Position
		})
		if !previewed {
			revocation.Joined = append(revocation.Joined, item)
		}
	}
	planKeyIds := derivation.keyIds()
	for _, keyId := range revokeKeyIds {
		if !slices.ContainsFunc(planKeyIds, func(planKeyId []byte) bool { return bytes.Equal(planKeyId, keyId) }) {
			return nil, fmt.Errorf("%w: %s", ErrSidecarRevokeKey, hex.EncodeToString(keyId))
		}
	}
	if plan.Presence && check == nil {
		return nil, &DeviceRevokeError{Code: DeviceRevokeCodeCancelled}
	}

	act, err := self.newAct(origin)
	if err != nil {
		return nil, err
	}
	proposal := false
	if derivation.signsRevoke {
		revoke := &bridge.SidecarRevoke{SidecarId: plan.SidecarId.Bytes(), Reason: derivation.reason, SinceN: plan.SinceN}
		if 1 < plan.Signatures {
			proposal = true
			proposedBytes, err := act.proposedStatementBytes(revoke)
			if err != nil {
				return nil, err
			}
			if err := act.Add(bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, &protocol.AuthorityProposal{
				StatementType: uint32(bridge.SignedType_SIGNED_SIDECAR_REVOKE),
				Statement:     proposedBytes,
			}); err != nil {
				return nil, err
			}
			// the target loses scope at once, while cosigns are due
			suspendId := make([]byte, len(Id{}))
			if _, err := io.ReadFull(rand.Reader, suspendId); err != nil {
				return nil, fmt.Errorf("no randomness for a suspend id: %w", err)
			}
			if err := act.Add(bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Subject: plan.SidecarId.Bytes(), SuspendId: suspendId}); err != nil {
				return nil, err
			}
		} else if err := act.Add(bridge.SignedType_SIGNED_SIDECAR_REVOKE, revoke); err != nil {
			return nil, err
		}
	}
	// a KeyRevoke of each selected key only with presence evidence, else none
	if plan.Presence {
		for _, keyId := range revokeKeyIds {
			if err := act.Add(bridge.SignedType_SIGNED_KEY_REVOKE, &protocol.KeyRevoke{KeyId: bytes.Clone(keyId)}); err != nil {
				return nil, err
			}
			revocation.RevokedKeyIds = append(revocation.RevokedKeyIds, bytes.Clone(keyId))
		}
	}
	if len(act.statements) == 0 {
		// the standing revocation covers the plan and no key is to be revoked: nothing to sign
		revocation.Entry = &bridge.AuthPin{Version: derivation.revokedAt}
		self.dropRevokePreview(planId)
		return revocation, nil
	}
	// the act's own reading of the log decides the check, whatever the plan said
	if _, covered, err := act.CountersignedBytes(); err != nil {
		return nil, err
	} else if covered && check == nil {
		return nil, &DeviceRevokeError{Code: DeviceRevokeCodeCancelled}
	}
	if proposal {
		revocation.ProposalId = act.proposalId(0)
	}

	testHookBarrier("identity.revoke.sign.before", plan.SidecarId.String())
	pins, runErr := act.Run(ctx, check)
	testHookBarrier("identity.revoke.sign.after", plan.SidecarId.String())
	switch {
	case errors.Is(runErr, ErrSidecarActPresence):
		// nothing was signed
		return nil, &DeviceRevokeError{Code: DeviceRevokeCodeCancelled}
	case errors.Is(runErr, ErrSidecarActRefused):
		runErr = fmt.Errorf("%w: %w", &DeviceRevokeError{Code: DeviceRevokeCodeRefused}, runErr)
	case errors.Is(runErr, ErrSidecarActPending):
		revocation.Pending = true
	case runErr != nil:
		return nil, runErr
	}
	// signed: the plan is spent, whatever its posts' answers
	self.dropRevokePreview(planId)
	if derivation.signsRevoke {
		landed := 0 < len(pins) && pins[0] != nil
		switch {
		case !proposal && landed:
			revocation.Entry = pins[0]
			self.runRevokeEffects(ctx, plan.SidecarId, pins[0])
		case proposal && (landed || revocation.Pending), !proposal && revocation.Pending:
			// the effects wait for the entry this device sees applied: the completing cosign's, or the retried post's
			func() {
				self.revokePlans.stateLock.Lock()
				defer self.revokePlans.stateLock.Unlock()
				self.revokeWatches.watches = append(self.revokeWatches.watches, &sidecarRevokeWatch{proposalId: revocation.ProposalId, sidecarId: plan.SidecarId})
			}()
		}
	} else if derivation.revokedAt != 0 {
		revocation.Entry = &bridge.AuthPin{Version: derivation.revokedAt}
	}
	return revocation, runErr
}

// The plan an alarm's revoke answer signs, for a UI to show before the person decides (§5.6's revocation: §18.5's
// alarm answers that revoke a named device run as PreviewDeviceRevoke and RevokeDevice with the since_n the alarm
// fixes): a compromise revocation of the item's device from the entry that opened the item.
func (self *Sidecar) PreviewApprovalRevoke(approvalId Id) (*DeviceRevokePlan, error) {
	identity, err := self.devicesReady()
	if err != nil {
		return nil, err
	}
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	item, err := func() (*sidecarApprovalRecord, error) {
		self.alarms.stateLock.Lock()
		defer self.alarms.stateLock.Unlock()
		record, err := self.loadAlarmRecord()
		if err != nil {
			return nil, err
		}
		for _, item := range record.Items {
			if item.ItemId == approvalId && !item.Decided {
				copied := *item
				return &copied, nil
			}
		}
		return nil, ErrSidecarApprovalUnknown
	}()
	if err != nil {
		return nil, err
	}
	derivation, err := self.deriveApprovalRevoke(authority, identity, item)
	if err != nil {
		return nil, err
	}
	self.keepRevokePreview(derivation)
	plan := *derivation.plan
	plan.Items = slices.Clone(derivation.plan.Items)
	return &plan, nil
}

// The plan of an alarm item's revoke answer: compromise, from the position the alarm fixed.
func (self *Sidecar) deriveApprovalRevoke(authority SidecarAuthority, identity *SidecarIdentity, item *sidecarApprovalRecord) (*deviceRevokeDerivation, error) {
	if item.SidecarId == nil || item.Position == 0 {
		return nil, ErrSidecarApprovalUnknown
	}
	return self.deriveDeviceRevoke(authority, identity, *item.SidecarId, DeviceRevokeCompromise, time.Time{}, item.Position, true)
}

// An alarm item's revoke answer: the compromise revocation of its device from the alarm's position, through
// RevokeDevicePlan. No key is revoked from here; `ur devices revoke` offers them.
func (self *Sidecar) decideApprovalRevoke(ctx context.Context, authority SidecarAuthority, item *sidecarApprovalRecord, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	identity, err := self.devicesReady()
	if err != nil {
		return err
	}
	derivation, err := self.deriveApprovalRevoke(authority, identity, item)
	if err != nil {
		return err
	}
	self.keepRevokePreview(derivation)
	_, err = self.RevokeDevicePlan(ctx, derivation.plan.PlanId, nil, origin, check)
	return err
}
