// The audit reader's deliveries (KEYS-M6-02; R-KEYS-9, D-KEYS-9, I-4; §10.8's Escrow paragraph, owner decisions 63
// and 126): Team's opt-in tag:audit reader, on a customer device, gets a repo's key only where every member's config
// holds its block and the repo's reader list shows it. None by default, and never silent.
//
//	reader      once its block counts the audit reader is an ordinary reader: ACL lists it in RepoReaders from the
//	            base that compiled the block under a standing AuditOptIn, so it never gets ahead of what every
//	            member's config holds (acl_audit.go), KeyHolders counts it as an agent, and a rotation or a late
//	            delivery at such a state wraps to it as to any agent. Nothing here adds a holder
//	visible     a delivery is judged at its own state (FI-28), so a ReaderWrap to the audit reader signed at a state
//	            whose reader list does not show it is refused by every member. Where the judge's own state, or the
//	            delivery's, knows the recipient as the repo's audit reader, the refusal is named for what it is,
//	            GkmRefusalAudit: the generation is poisoned, members alarm naming the signer with that reason and
//	            rotate REMOVE (§10.9's poisoned row), and admins revoke the signer
//	signer      GkmAuditWrapAllowed, which a rotation's delivery set and a late delivery hold each ReaderWrap to: no
//	            wrap to a sidecar the signer's newest state knows as the repo's audit reader unless the state it
//	            signs at lists it, whatever the holders it computed say; a refusal there is the signer's own check
//	            before anything is sealed
//	opt out     AuditOptOut, or the opt-in's not_after, drops the reader from KeyHolders: a shrink at the entry, an
//	            expiry at the time (config_coverage.go), so EnsureWritable rotates with cause REMOVE and the next
//	            generation wraps to no audit reader
//	owner-bound in an owner-bound repo admins add only this reader (owner decision 126): ACL's RepoReaders gives it
//	            the read where the block names the kind or the repo and gives an admin's other additions none
//	            (acl_evs.go); GkmAuditHolders shows which holders read as the audit reader
//
// A state that does not answer GkmAuditView names no audit reader: no wrap is named an audit refusal there, and the
// ordinary holder checks decide alone, which refuse a wrap to any reader the list does not show.
//
// Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// A delivery to the audit reader at a state whose reader list does not show it (§10.8).
const GkmRefusalAudit GkmRefusalReason = "audit_unlisted"

// A signer's own refusal to wrap to an audit reader the reader list at its signing state does not show.
var ErrGkmAuditUnlisted = errors.New("gkm: the audit reader is not in the reader list")

// What a state shows of the audit reader, beside GkmAuthView.
type GkmAuditView interface {
	// The sidecars the audit block makes readers of the repo at the time given, sorted: none before its AuditOptIn
	// has reached a base, after an AuditOptOut or past the opt-in's not_after (AclState.AuditReaders).
	AuditReaders(repoId Id, at time.Time) []Id
}

// The audit readers of a repo a state shows at a time; none for a state that does not answer GkmAuditView.
func GkmAuditReaders(view GkmAuthView, repoId Id, at time.Time) []Id {
	auditView, ok := view.(GkmAuditView)
	if !ok || auditView == nil {
		return nil
	}
	return auditView.AuditReaders(repoId, at)
}

// Whether a state's reader list shows a sidecar as the repo's audit reader at a time: it is among the state's audit
// readers and among its readers.
func GkmAuditListed(view GkmAuthView, repoId Id, sidecarId Id, at time.Time) bool {
	if view == nil {
		return false
	}
	return slices.Contains(GkmAuditReaders(view, repoId, at), sidecarId) && slices.Contains(view.RepoReadersAt(repoId, at), sidecarId)
}

// The holders among holders that read the repo as its audit reader at a state and time, in holders' order: what a
// reader list marks, and all an admin's own signature adds to an owner-bound repo.
func GkmAuditHolders(view GkmAuthView, repoId Id, holders GkmHolders, at time.Time) GkmHolders {
	auditReaders := GkmAuditReaders(view, repoId, at)
	audit := GkmHolders{}
	for _, holder := range holders {
		if holder.Kind != GkmHolderAgent && holder.Kind != GkmHolderLeaf {
			continue
		}
		sidecarId, err := IdFromBytes(holder.Id)
		if err != nil {
			continue
		}
		if slices.Contains(auditReaders, sidecarId) {
			audit = append(audit, holder)
		}
	}
	return audit
}

// The signer's own check before it seals a ReaderWrap to recipient at state and time: see the file header. newest is
// the signer's newest state and now its clock, state and at what the wrap is signed at.
func GkmAuditWrapAllowed(newest GkmAuthView, state GkmAuthView, repoId Id, recipient Id, at time.Time, now time.Time) error {
	known := slices.Contains(GkmAuditReaders(newest, repoId, now), recipient) || slices.Contains(GkmAuditReaders(state, repoId, at), recipient)
	if known && !GkmAuditListed(state, repoId, recipient, at) {
		return fmt.Errorf("%w: %s, at the state the wrap is signed at", ErrGkmAuditUnlisted, recipient)
	}
	return nil
}

// GkmAuditWrapAllowed for this device's repo: its newest state and clock against the state and time it signs at. A
// device with no newest state checks the signing state alone.
func (self *gkmGroupManager) auditWrapAllowed(state GkmAuthView, recipient Id, at time.Time) error {
	newest, err := self.client.currentState()
	if err != nil {
		newest = state
	}
	return GkmAuditWrapAllowed(newest, state, self.repoId, recipient, at, self.client.clock.Now())
}

// The refusal of a ReaderWrap whose recipient is no key holder at the delivery's state, when the judge's own state
// at now, or the delivery's at its time, knows the recipient as the repo's audit reader; false for any other
// recipient, whose refusal the caller names.
func gkmAuditRefusal(view GkmAuthView, stateAt GkmAuthView, repoId Id, recipient []byte, at time.Time, now time.Time) (GkmVerdict, bool) {
	recipientId, err := IdFromBytes(recipient)
	if err != nil {
		return GkmVerdict{}, false
	}
	known := slices.Contains(GkmAuditReaders(view, repoId, now), recipientId) || slices.Contains(GkmAuditReaders(stateAt, repoId, at), recipientId)
	if !known || GkmAuditListed(stateAt, repoId, recipientId, at) {
		return GkmVerdict{}, false
	}
	return gkmRefuse(GkmRefusalAudit, "a ReaderWrap to the audit reader %s, which the reader list at its state does not show", recipientId), true
}

// GkmAuditView for the config's state: ACL's audit readers of the repo at the time given, none where the rows do not
// compile.
func (self *ConfigState) AuditReaders(repoId Id, at time.Time) []Id {
	acl, err := self.Acl()
	if err != nil {
		return nil
	}
	return acl.AuditReaders(repoId, at)
}
