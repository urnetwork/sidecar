//go:build !ios_extension

// §7.10's cleanup row on admin devices (CORE-M6-04, D-TEAM-29, D-CORE-13, I-4, I-15; QD-250, QD-646): from 90% of the
// network's config_admissions until the count falls below it, every admin device raises admissions_near_cap and lists,
// per member, its admitted page Workers but its newest, oldest first, for an admin to revoke, so Workers no member
// device answers for are freed before api refuses an admission at the cap (§20.7). A Worker still in use signs out and
// is enrolled again.
//
//	cap      config_admissions from GET /sidecar/limits (QD-250), which no reader derives from the log: read at an
//	         entry the log applies once the last read is SidecarAlarmSettings.AdmissionCapTimeout old, off the
//	         follower's goroutine, and afresh by every preview and revoke. The watcher compares the count with it
//	         (identity_alarms.go); a key the answer lacks (0, not included) and none (-1) put nothing near a cap
//	raise    on an admin device, admissions_near_cap from 90% of the cap, once each time the count rises past the count
//	         it was raised at, opening one cleanup item while none is open; the item closes when the count falls
//	         below 90%, since the list is then gone
//	list     PreviewCleanup: TEAM-M4-01's CleanupList at the newest verified state, the same on every admin device at
//	         one pin, each Worker with its admission position and time from its row (QD-646), never a clock of this
//	         device's, its leaf's last change where a group this device is a leaf of shows one (KEYS-M4-01's group
//	         view, identity_act_stale.go), and the counted signatures its revocation needs; a ListId over what a
//	         revoke signs
//	revoke   a person's confirmation alone, on /dev/tty or in an app (D-CORE-13), on an admin's approval-capable device:
//	         the list derived again at the tip and refused with nothing signed unless its ListId is the one this
//	         device last showed for the item, then one act: SidecarRevoke{removed} of each listed Worker, an AdminSet
//	         member's at k > 1 as an AuthorityProposal of its own (§7.9's several row), which other AdminSet devices
//	         cosign as `ur approve <proposal_id>` does (identity_revoke_cosign.go), all under one presence check where
//	         §7.9's presence row covers the act
//	deny     dismisses the item, until the count rises past it again
//
// Whether this device's member may revoke each Worker is the verifier's rule (§7.9's signers row: an Owner's, Admin's
// or IT admin's device, authority for an AdminSet member's), which api and every reader apply. This device offers the
// revoke on an approval-capable device of an AdminSet member and does not judge it a second way, so a statement no
// signer row admits answers ErrSidecarActRefused at the tip, nothing taking effect.
//
// Nothing here creates, derives or unwraps a key. testHookBarrier brackets the signing point; each post has
// identity.post's. On every leg but the iOS extension, which admits no Worker and raises no alarm: root Id, no connect
// type.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// config_admissions' key in GET /sidecar/limits (§20.4).
const sidecarAdmissionsLimitKey = "config_admissions"

// The ListId's domain: a local digest no peer or server reads, so no format freezes it.
const sidecarCleanupListDomain = "urnetwork-sidecar-v1/local/cleanup-list"

var (
	// The cleanup list at the tip is not the one this device last showed for the item, or it showed none: show it
	// again (PreviewCleanup) and decide on what it lists then. Nothing was signed.
	ErrSidecarCleanupStale = errors.New("the cleanup list changed since it was shown, or was not shown here: show it again")
	// No api client to read GET /sidecar/limits through.
	errSidecarCleanupNoApi = errors.New("no api client to read the network's limits through")
)

// One page Worker on §7.10's cleanup list, as an admin's device shows it.
type SidecarCleanupWorker struct {
	SidecarId Id
	// The position its admission took effect at, and that entry's time, api's, both from its row (QD-646): never a
	// clock of this device's. AdmittedTime is zero for a row that carries none.
	AdmittedAt   uint64
	AdmittedTime time.Time
	// Its leaf's last change, the newest a group this device is a leaf of shows; zero where none does or no group view
	// is installed.
	LastChange time.Time
	// The counted signatures its revocation needs: 1, or k for an AdminSet member's Worker, whose revocation then goes
	// as a proposal other AdminSet devices cosign (§7.9's several row).
	Signatures int
}

// One member's part of the list.
type SidecarCleanupMember struct {
	MemberId Id
	// Its page Workers but its newest, oldest admission first.
	Workers []SidecarCleanupWorker
}

// §7.10's cleanup list as a revoke answer signs it.
type SidecarCleanupList struct {
	// A digest of what a revoke signs: each listed Worker, by member, with its admission position and the signatures
	// it needs. A revoke signs only while the list at the tip has the id this device last showed.
	ListId Id
	// What config_admissions counts at the newest verified state, and the cap GET /sidecar/limits answered: 0 for a
	// tier that does not include admissions, -1 for none.
	AdmissionCount int
	AdmissionCap   int
	// Members in id order; empty below 90% of the cap.
	Members []SidecarCleanupMember
	// Set from the log, never by the caller: the revoke's act runs one presence check.
	Presence bool
}

// The Workers a list names, in its order.
func (self *SidecarCleanupList) workerIds() []Id {
	workerIds := []Id{}
	for _, member := range self.Members {
		for _, worker := range member.Workers {
			workerIds = append(workerIds, worker.SidecarId)
		}
	}
	return workerIds
}

// What a cleanup revoke signed.
type SidecarCleanupRevocation struct {
	ListId Id
	// Each Worker whose SidecarRevoke{removed} the act signed, in the list's order, a proposal's included.
	Revoked []Id
	// §7.9's 32-byte proposal_id of each revocation that went as a proposal, by Worker, while cosigns are due.
	Proposals map[Id][]byte
	// The statements are signed and kept, and a post's answer was lost: they go again with the same bytes.
	Pending bool
}

// The cleanup kind (identity_approvals.go's table).
func init() {
	registerSidecarApprovalKind(SidecarApprovalCleanup, &sidecarApprovalKind{
		decisions:    []string{SidecarDecisionRevoke, SidecarDecisionDeny},
		eligible:     sidecarCleanupEligible,
		decide:       sidecarDecideCleanup,
		entryApplied: sidecarCleanupEntryApplied,
	})
}

// A cleanup item: an approval-capable device of an AdminSet member revokes, where the authority answers the page
// Workers and a revocation's signatures; anyone may dismiss.
func sidecarCleanupEligible(self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord) []string {
	if !self.cleanupCapable(authority) {
		return []string{SidecarDecisionDeny}
	}
	return []string{SidecarDecisionRevoke, SidecarDecisionDeny}
}

// Whether this device may sign a cleanup's revocations: an approval-capable device, not suspended (§16.6), of a member
// the AdminSet names as the newest entry the watcher applied left it, on an authority that answers both the page
// Workers and the signatures a revocation needs. Whether the member's role revokes is the verifier's (§7.9).
func (self *Sidecar) cleanupCapable(authority SidecarAuthority) bool {
	identity := self.currentIdentity()
	if identity == nil {
		return false
	}
	own, ok := self.approvalCapableAdmission(authority)
	revokes, revokesOk := authority.(SidecarRevokeAuthority)
	_, workersOk := authority.(SidecarPageWorkerAuthority)
	if !ok || !revokesOk || !workersOk || !revokes.ApprovalCapable(identity.SidecarId) {
		return false
	}
	record, err := func() (*sidecarAlarmRecord, error) {
		self.alarms.stateLock.Lock()
		defer self.alarms.stateLock.Unlock()
		return self.loadAlarmRecord()
	}()
	return err == nil && slices.Contains(record.AdminMemberIds, own.MemberId)
}

// revoke: the list this device showed, signed at the tip (RevokeCleanup's act); deny dismisses.
func sidecarDecideCleanup(ctx context.Context, self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord, decision string, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if decision != SidecarDecisionRevoke {
		return nil
	}
	_, err := self.revokeCleanupItem(ctx, authority, item, origin, check)
	return err
}

// The cleanup's step at each applied entry: on an admin member device, a read of the cap once the last one is
// AdmissionCapTimeout old, started off the follower's goroutine, which it never blocks. The read records its time
// whether or not it answered, so a failing api is asked at most once a timeout.
func sidecarCleanupEntryApplied(self *Sidecar, authority SidecarAuthority, entry *SidecarAuthorityEntry) {
	timeout := self.settings.alarmSettings().AdmissionCapTimeout
	identity := self.currentIdentity()
	if timeout <= 0 || entry == nil || self.ctx == nil || self.sidecarApi == nil || identity == nil {
		return
	}
	own := authority.Admission(identity.SidecarId)
	if own == nil || own.Row == nil || own.Row.GetRevokedAt() != 0 || 0 < len(own.TagIds) || !slices.Contains(entry.AdminMemberIds, own.MemberId) {
		return
	}
	start := func() bool {
		self.cleanups.stateLock.Lock()
		defer self.cleanups.stateLock.Unlock()
		if self.cleanups.capReading || (!self.cleanups.capReadAt.IsZero() && self.clock.Now().Sub(self.cleanups.capReadAt) < timeout) {
			return false
		}
		self.cleanups.capReading = true
		return true
	}()
	if !start {
		return
	}
	go func() {
		defer func() {
			self.cleanups.stateLock.Lock()
			defer self.cleanups.stateLock.Unlock()
			self.cleanups.capReading = false
		}()
		if _, err := self.RefreshAdmissionCap(self.ctx); err != nil {
			self.log.Infof("[identity]config_admissions was not read: %s", err)
		}
	}()
}

// The cap the watcher compares with now: the last answer GET /sidecar/limits gave, 0 before any.
func (self *Sidecar) knownAdmissionCap() int {
	self.alarms.stateLock.Lock()
	defer self.alarms.stateLock.Unlock()
	return self.alarms.admissionCap
}

// Reads config_admissions from GET /sidecar/limits now, keeps it as the cap admissions_near_cap compares with, and
// judges admissions_near_cap at once at the newest verified state, so a cap read after the entries that reached it
// still raises (identity_alarms.go). Answers the cap: 0 for a tier that does not include admissions, -1 for none. On an
// error it answers the cap read before, 0 if none, beside the error. A host may call it at start; previews and revokes
// do, and the watcher does when its read is due.
func (self *Sidecar) RefreshAdmissionCap(ctx context.Context) (int, error) {
	if self.sidecarApi == nil {
		return self.knownAdmissionCap(), errSidecarCleanupNoApi
	}
	limits, err := self.sidecarApi.Limits(ctx)
	func() {
		self.cleanups.stateLock.Lock()
		defer self.cleanups.stateLock.Unlock()
		self.cleanups.capReadAt = self.clock.Now()
	}()
	if err != nil {
		return self.knownAdmissionCap(), err
	}
	// a key the answer lacks reads 0, not included (§20.5), so nothing is near a cap this build cannot read
	limit := min(max(limits.Limits[sidecarAdmissionsLimitKey], -1), math.MaxInt32)
	admissionCap := int(limit)

	count, position, judged, memberId := 0, uint64(0), false, Id{}
	if authority := self.authority(); authority != nil {
		identity := self.currentIdentity()
		workers, ok := authority.(SidecarPageWorkerAuthority)
		if identity != nil && ok {
			if own := authority.Admission(identity.SidecarId); own != nil && own.Row != nil && own.Row.GetRevokedAt() == 0 &&
				len(own.TagIds) == 0 && !own.Ephemeral {
				count, position, judged, memberId = workers.AdmissionCount(), authority.Pin().GetVersion(), true, own.MemberId
			}
		}
	}
	self.admissionCapRead(admissionCap, count, position, judged, memberId)
	return admissionCap, nil
}

// A list's ListId: the first 16 bytes of SHA-256 over the domain, then each member's id and Worker count, and each
// Worker's id, admission position and signatures, in the list's order.
func sidecarCleanupListId(members []SidecarCleanupMember) Id {
	hash := sha256.New()
	hash.Write([]byte(sidecarCleanupListDomain))
	hash.Write([]byte{0x00})
	for _, member := range members {
		hash.Write(member.MemberId.Bytes())
		hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(member.Workers))))
		for _, worker := range member.Workers {
			hash.Write(worker.SidecarId.Bytes())
			hash.Write(binary.BigEndian.AppendUint64(nil, worker.AdmittedAt))
			hash.Write(binary.BigEndian.AppendUint32(nil, uint32(worker.Signatures)))
		}
	}
	var listId Id
	copy(listId[:], hash.Sum(nil))
	return listId
}

// The list at the authority's newest verified state for admissionCap, as identity's device shows it: CleanupList's
// members and Workers, each Worker's leaf's last change from the group view where it answers, its signatures from the
// log, and Presence from the log's rule over the statements a revoke signs.
func (self *Sidecar) deriveCleanup(ctx context.Context, authority SidecarAuthority, identity *SidecarIdentity, admissionCap int) *SidecarCleanupList {
	list := &SidecarCleanupList{AdmissionCap: admissionCap, Members: []SidecarCleanupMember{}}
	workers, ok := authority.(SidecarPageWorkerAuthority)
	if !ok {
		list.ListId = sidecarCleanupListId(list.Members)
		return list
	}
	list.AdmissionCount = workers.AdmissionCount()
	revokes, _ := authority.(SidecarRevokeAuthority)
	for _, member := range workers.CleanupList(admissionCap) {
		listed := SidecarCleanupMember{MemberId: member.MemberId, Workers: []SidecarCleanupWorker{}}
		for _, worker := range member.Workers {
			signatures := 1
			if revokes != nil {
				signatures = max(revokes.RevokeSignatures(worker.SidecarId), 1)
			}
			listed.Workers = append(listed.Workers, SidecarCleanupWorker{
				SidecarId:    worker.SidecarId,
				AdmittedAt:   worker.AdmittedAt,
				AdmittedTime: worker.AdmittedTime,
				Signatures:   signatures,
			})
		}
		list.Members = append(list.Members, listed)
	}

	// each Worker's leaf's last change, where a group this device is a leaf of shows one; what the view cannot answer
	// shows none, since the list and what a revoke signs rest on the log alone
	if workerIds := list.workerIds(); 0 < len(workerIds) {
		if view := self.staleGroupView(); view != nil {
			leaves, err := view.StaleLeaves(ctx, workerIds)
			var byWorker map[Id][]*SidecarStaleLeaf
			if err == nil {
				byWorker, err = sidecarStaleLeavesByWorker(leaves, workerIds)
			}
			if err != nil {
				self.log.Infof("[identity]the cleanup list shows no leaf's last change: %s", err)
			}
			for i := range list.Members {
				for j := range list.Members[i].Workers {
					worker := &list.Members[i].Workers[j]
					for _, leaf := range byWorker[worker.SidecarId] {
						if worker.LastChange.Before(leaf.LastChange) {
							worker.LastChange = leaf.LastChange
						}
					}
				}
			}
		}
	}

	// the log's rule over what the act would sign, never the caller's
	for _, member := range list.Members {
		for _, worker := range member.Workers {
			revoke := &bridge.SidecarRevoke{SidecarId: worker.SidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED}
			signedType := bridge.SignedType_SIGNED_SIDECAR_REVOKE
			if 1 < worker.Signatures {
				signedType = bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL
			}
			if authority.PresenceRequired(deviceRevokeStatement(identity.SidecarId, bridge.SignedType_SIGNED_SIDECAR_REVOKE, revoke)) ||
				authority.PresenceRequired(deviceRevokeStatement(identity.SidecarId, signedType, revoke)) {
				list.Presence = true
			}
		}
	}
	list.ListId = sidecarCleanupListId(list.Members)
	return list
}

// The cleanup item approvalId names, open: a copy of its record. ErrSidecarApprovalUnknown for any other id.
func (self *Sidecar) openCleanupItem(approvalId Id) (*sidecarApprovalRecord, error) {
	self.alarms.stateLock.Lock()
	defer self.alarms.stateLock.Unlock()
	record, err := self.loadAlarmRecord()
	if err != nil {
		return nil, err
	}
	for _, item := range record.Items {
		if item.ItemId == approvalId && item.Kind == SidecarApprovalCleanup && !item.Decided {
			copied := *item
			return &copied, nil
		}
	}
	return nil, ErrSidecarApprovalUnknown
}

// The list a cleanup item's revoke answer signs, for a UI to show before the person decides (`ur approve <id>
// --revoke`, §18.5's admissions_near_cap): read at the newest verified state against a fresh read of the cap, which
// falls back to the cap read before when api does not answer. This device keeps its ListId for the item, the one the
// revoke then signs. ErrSidecarApprovalUnknown for an id that is no open cleanup item; ErrSidecarDevicesPrecondition
// while Locked or Unenrolled; ErrSidecarActNoAuthority with no verified state. Signs nothing.
func (self *Sidecar) PreviewCleanup(ctx context.Context, approvalId Id) (*SidecarCleanupList, error) {
	identity, err := self.devicesReady()
	if err != nil {
		return nil, err
	}
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	if _, err := self.openCleanupItem(approvalId); err != nil {
		return nil, err
	}
	admissionCap, err := self.RefreshAdmissionCap(ctx)
	if err != nil {
		self.log.Infof("[identity]the cleanup list reads the cap read before: %s", err)
	}
	list := self.deriveCleanup(ctx, authority, identity, admissionCap)
	func() {
		self.cleanups.stateLock.Lock()
		defer self.cleanups.stateLock.Unlock()
		if self.cleanups.previews == nil {
			self.cleanups.previews = map[Id]Id{}
		}
		self.cleanups.previews[approvalId] = list.ListId
	}()
	return list, nil
}

// The ListId this device last showed for the item, false for none.
func (self *Sidecar) cleanupPreview(approvalId Id) (Id, bool) {
	self.cleanups.stateLock.Lock()
	defer self.cleanups.stateLock.Unlock()
	listId, ok := self.cleanups.previews[approvalId]
	return listId, ok
}

// Forgets the list shown for the item, once its revoke signed.
func (self *Sidecar) dropCleanupPreview(approvalId Id) {
	self.cleanups.stateLock.Lock()
	defer self.cleanups.stateLock.Unlock()
	delete(self.cleanups.previews, approvalId)
}

// A cleanup item's revoke answer with its whole result, what DecideApproval's revoke does: origin a person's
// confirmation, never MCP, a hook or an unconfirmed control call (ErrSidecarActMode), on a device the item lets revoke
// (ErrSidecarApprovalNotEligible), signing the list the device last showed for it (ErrSidecarCleanupStale otherwise).
// check is the presence check a covered act runs, its failure, refusal or absence ErrSidecarActPresence with nothing
// signed. The item closes once the act signed, a lost answer's ErrSidecarActPending included, as DecideApproval
// closes it.
func (self *Sidecar) RevokeCleanup(ctx context.Context, approvalId Id, origin SidecarActOrigin, check SidecarPresenceCheck) (*SidecarCleanupRevocation, error) {
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	item, err := self.openCleanupItem(approvalId)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(sidecarCleanupEligible(self, authority, item), SidecarDecisionRevoke) {
		return nil, ErrSidecarApprovalNotEligible
	}
	revocation, revokeErr := self.revokeCleanupItem(ctx, authority, item, origin, check)
	if revokeErr != nil && !errors.Is(revokeErr, ErrSidecarActPending) {
		return revocation, revokeErr
	}
	if err := self.closeApprovalItem(approvalId, SidecarDecisionRevoke); err != nil {
		return revocation, err
	}
	return revocation, revokeErr
}

// Marks an item decided, as DecideApproval does once its decision's statement is signed.
func (self *Sidecar) closeApprovalItem(approvalId Id, decision string) error {
	self.alarms.stateLock.Lock()
	defer self.alarms.stateLock.Unlock()
	record, err := self.loadAlarmRecord()
	if err != nil {
		return err
	}
	for _, held := range record.Items {
		if held.ItemId == approvalId {
			held.Decided = true
			held.Decision = decision
		}
	}
	return self.persistAlarmRecord(record)
}

// Signs item's revoke: the list at the tip, the shown one's ListId or ErrSidecarCleanupStale, then one act of
// SidecarRevoke{removed} for each listed Worker, an AdminSet member's at k > 1 as its own AuthorityProposal, under one
// presence check where the log covers the act. A list with no Worker signs nothing. Answers what the act signed, which
// on ErrSidecarActRefused and ErrSidecarActPending says what landed before.
func (self *Sidecar) revokeCleanupItem(ctx context.Context, authority SidecarAuthority, item *sidecarApprovalRecord, origin SidecarActOrigin, check SidecarPresenceCheck) (*SidecarCleanupRevocation, error) {
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	identity, err := self.devicesReady()
	if err != nil {
		return nil, err
	}
	shown, ok := self.cleanupPreview(item.ItemId)
	if !ok {
		return nil, ErrSidecarCleanupStale
	}
	admissionCap, err := self.RefreshAdmissionCap(ctx)
	if err != nil {
		self.log.Infof("[identity]the cleanup revoke reads the cap read before: %s", err)
	}
	list := self.deriveCleanup(ctx, authority, identity, admissionCap)
	if list.ListId != shown {
		return nil, ErrSidecarCleanupStale
	}
	revocation := &SidecarCleanupRevocation{ListId: list.ListId, Revoked: []Id{}, Proposals: map[Id][]byte{}}
	if len(list.workerIds()) == 0 {
		self.dropCleanupPreview(item.ItemId)
		return revocation, nil
	}

	act, err := self.newAct(origin)
	if err != nil {
		return nil, err
	}
	proposals := map[int]Id{}
	for _, member := range list.Members {
		for _, worker := range member.Workers {
			revoke := &bridge.SidecarRevoke{SidecarId: worker.SidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED}
			if 1 < worker.Signatures {
				proposedBytes, err := act.proposedStatementBytes(revoke)
				if err != nil {
					return nil, err
				}
				proposals[len(act.statements)] = worker.SidecarId
				if err := act.Add(bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, &protocol.AuthorityProposal{
					StatementType: uint32(bridge.SignedType_SIGNED_SIDECAR_REVOKE),
					Statement:     proposedBytes,
				}); err != nil {
					return nil, err
				}
			} else if err := act.Add(bridge.SignedType_SIGNED_SIDECAR_REVOKE, revoke); err != nil {
				return nil, err
			}
			revocation.Revoked = append(revocation.Revoked, worker.SidecarId)
		}
	}
	// the act's own reading of the log decides the check, whatever the list said
	if _, covered, err := act.CountersignedBytes(); err != nil {
		return nil, err
	} else if covered && check == nil {
		return nil, fmt.Errorf("%w: the log requires a presence check and none was given", ErrSidecarActPresence)
	}
	for index, workerId := range proposals {
		revocation.Proposals[workerId] = act.proposalId(index)
	}

	testHookBarrier("identity.cleanup.sign.before", item.ItemId.String())
	_, runErr := act.Run(ctx, check)
	testHookBarrier("identity.cleanup.sign.after", item.ItemId.String())
	switch {
	case errors.Is(runErr, ErrSidecarActPresence):
		// nothing was signed
		return nil, runErr
	case errors.Is(runErr, ErrSidecarActPending):
		revocation.Pending = true
	case runErr != nil && !errors.Is(runErr, ErrSidecarActRefused):
		return nil, runErr
	}
	// signed: the shown list is spent, whatever its posts' answers
	self.dropCleanupPreview(item.ItemId)
	return revocation, runErr
}
