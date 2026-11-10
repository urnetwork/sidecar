// §16.11's card rules as the M6 carrier applies them to run and worker items (RECORD-M6-14): an announce entry's push
// stands for the card, its auth pin for at, and a reader accepts a version only where every rule holds.
//
//	signed      the item's who.sidecar_id is the entry's signer, whose identity key signed its header; another's is
//	            void and alarms bad_entry
//	pushed      a copy sits in the signer's own stream: one only another sidecar pushed alarms path_rule
//	seq         the record reader keeps each writer's chain, so a version whose seq is not above the last is a fork,
//	            shown forked and alarmed chain_fork there, and never folded here
//	at          the push's pin lies within 4,096 positions of the reader's state; a pin out of range on a version its
//	            times still call live alarms bad_entry unless an accepted version of its item stands above it, and one
//	            whose times have run out counts for nothing quietly
//	renewed     no further past its push's time_ms than §8.6's 60 s of skew, so no writer's clock keeps an item active
//	            past what evs's time bounds (FI-25); bad_entry
//	signer      admitted, not revoked, reaped, expired, suspended, parked or read_only at its pin, and for a member
//	            device consented: a device parked for consent writes nothing that counts and alarms parked_writer
//	            (owner decision 126, D-MCP-29), any other standing bad_entry; and standing in the reader's state too
//	            (FI-25), a revocation since masking the item with no alarm (§16.11's member and device rows)
//	who         member_id is the signer's member, or a tagged or ephemeral signer's sponsor, at its pin, and empty for
//	            a tagged one whose sponsor is gone; a mismatch voids the item, bad_entry
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
)

// The card rules that rest on fixed history: who signed and pushed version, its renewal's bound by evs's time, its
// signer's standing at its pin, and who at its pin. Never changes once it is not pending.
func directoryJudgeCardFixed(auth DirectoryAuthView, version *directoryVersion) directoryJudgement {
	item := version.item
	switch {
	case !bytes.Equal(item.GetWho().GetSidecarId(), version.writerId[:]):
		return directoryRefused(SidecarRecordAlarmBadEntry)
	case version.pushPin == nil:
		return directoryRefused(SidecarRecordAlarmPathRule)
	case version.pushTimeMillis+DirectoryClockSkew.Milliseconds() < item.GetRenewedMillis():
		return directoryRefused(SidecarRecordAlarmBadEntry)
	}
	standing, err := auth.SignerStanding(version.writerId, version.pushPin)
	switch {
	case errors.Is(err, ErrDirectoryAuthAhead), errors.Is(err, ErrDirectoryAuthUnavailable):
		return directoryPending
	case errors.Is(err, ErrDirectoryAuthNotRetained):
		// a pin before what the state retains lies past the card rule's 4,096 positions too: the version counts for
		// nothing, though nothing shows that it broke a rule
		return directoryRefused("")
	case err != nil:
		// a pin off the reader's chain: a fork's evidence
		return directoryRefused(SidecarRecordAlarmBadEntry)
	case standing == DirectoryStandingUnconsented:
		return directoryRefused(SidecarRecordAlarmParkedWriter)
	case standing != DirectoryStandingStanding:
		return directoryRefused(SidecarRecordAlarmBadEntry)
	}
	atPin, err := auth.At(version.pushPin)
	if err != nil {
		return directoryPending
	}
	if !directoryWhoMatches(atPin, version.writerId, item.GetWho().GetMemberId()) {
		return directoryRefused(SidecarRecordAlarmBadEntry)
	}
	return directoryAccepted
}

// Whether memberId is the member §16.11's who row names for sidecarId in view: its member, or a tagged or ephemeral
// sidecar's sponsor, or none for one whose sponsor is gone.
func directoryWhoMatches(view DirectoryAuthView, sidecarId Id, memberId []byte) bool {
	expected, ok := DirectoryWhoMember(view, sidecarId)
	if !ok {
		return len(memberId) == 0
	}
	return bytes.Equal(memberId, expected[:])
}

// The card rules that change with the reader's state: the pin within 4,096 positions of it, and the signer standing
// in it (FI-25), a revocation since masking the version with no alarm.
func (self *directoryJudge) cardNow(version *directoryVersion) directoryJudgement {
	if self.readerPin == nil || self.readerPin.GetVersion() < version.pushPin.GetVersion() {
		return directoryPending
	}
	if DirectoryPinPositionCount < self.readerPin.GetVersion()-version.pushPin.GetVersion() {
		if self.nowMillis < version.item.GetExpiresMillis() {
			// a version its own times call live, at a pin the card rule refuses
			return directoryJudgement{verdict: directoryVerdictRefused, alarm: SidecarRecordAlarmBadEntry, aged: true}
		}
		return directoryRefused("")
	}
	switch self.standing(version.writerId) {
	case DirectoryStandingStanding:
		return directoryAccepted
	case DirectoryStandingUnjudged:
		return directoryPending
	}
	return directoryRefused("")
}

// A run or worker version by the card rules.
func (self *directoryJudge) card(version *directoryVersion) directoryJudgement {
	judgement, ok := self.fixed(version)
	if !ok {
		judgement = directoryJudgeCardFixed(self.auth, version)
		self.keepFixed(version, judgement)
	}
	if judgement.verdict != directoryVerdictAccepted {
		return judgement
	}
	return self.cardNow(version)
}

// One run or worker item from its versions, highest first: the highest accepted, unless an accepted withdrawal hides
// it. Each refused version alarms, but one aged past the pin bound below what stands, which an honest renewal leaves
// behind. True when any version was accepted, which id_reuse counts.
func (self *directoryJudge) cardItem(versions []*directoryVersion) (*DirectoryItem, bool) {
	judgements := make([]directoryJudgement, len(versions))
	winnerIndex := -1
	withdrawn := false
	for index, version := range versions {
		judgements[index] = self.card(version)
		if judgements[index].verdict != directoryVerdictAccepted {
			continue
		}
		if DirectoryAnnouncementState(version.item.GetState()) == DirectoryAnnouncementStateWithdrawn {
			withdrawn = true
		}
		if winnerIndex < 0 {
			winnerIndex = index
		}
	}
	for index, version := range versions {
		if judgements[index].aged && 0 <= winnerIndex && winnerIndex < index {
			continue
		}
		self.alarm(version, judgements[index])
	}
	if winnerIndex < 0 {
		return nil, false
	}
	winner := versions[winnerIndex]
	if withdrawn {
		return nil, true
	}
	display, shown := directoryCardDisplay(winner, self.nowMillis)
	if !shown {
		return nil, true
	}
	return self.itemOf(winner, display), true
}

// How a run or worker version that stands shows at nowMillis (§16.11's expire and end rows): active until its
// expires_millis and never after, then stale for 24 h; ended or handed off for 24 h from its renewal. False once it
// shows no more.
func directoryCardDisplay(version *directoryVersion, nowMillis int64) (DirectoryItemDisplay, bool) {
	item := version.item
	switch DirectoryAnnouncementState(item.GetState()) {
	case DirectoryAnnouncementStateActive:
		if nowMillis < item.GetExpiresMillis() {
			return DirectoryItemActive, true
		}
		if nowMillis < item.GetExpiresMillis()+DirectoryStaleShowTime.Milliseconds() {
			return DirectoryItemStale, true
		}
	case DirectoryAnnouncementStateEnded:
		if nowMillis < item.GetRenewedMillis()+DirectoryEndedKeepTime.Milliseconds() {
			return DirectoryItemEnded, true
		}
	case DirectoryAnnouncementStateHandedOff:
		if nowMillis < item.GetRenewedMillis()+DirectoryEndedKeepTime.Milliseconds() {
			return DirectoryItemHandedOff, true
		}
	}
	return "", false
}
