// §10.5's key holders of a repo R at a state S and a time t (D-KEYS-16), the identities gen/<g>'s holders_sha256
// covers, and the three predicates they rest on, live(d), reach(d) and covered(s, R):
//
//	leaf(s)        a member device (untagged, not ephemeral) reading R (§8.12): an MLS leaf of R's group, or in the
//	               config and directory groups one wrapped past the first 1,000, which keeps this identity
//	agent(s)       any other sidecar reading R, unless covered there
//	delegation(d)  a live Delegation whose reach holds R
//	recovery(m)    a member with a member device reading R, while its RecoveryBind is current
//	covered(s, R)  s was admitted under a Delegation d with delegation(d) in KeyHolders(R, S, t)
//	reach(d)       the config, in a team network the directory, and each repo a read or write grant naming one of
//	               d's tags reads (ACL's ReposGrantedToAtoms)
//	live(d)        d has not ended, its key has not dropped (key_dropped_at, which TEAM writes at the first Suspend
//	               or revocation but a reap of one of its agents, and no Unsuspend clears), no compromise cascade
//	               voids it, and t < its not_after
//	identity       kind byte (1 leaf, 2 agent, 3 delegation, 4 recovery) || sidecar_id | delegation_id | member_id
//	holders_sha256 SHA-256 of the identities sorted by bytes.Compare and joined with no separator (QD-465)
//
// The set is a function of the log and t alone, so every member recomputes holders_sha256: leaf(s) is every member
// device reading R, seated or not, since seats live in the tree (plan reading 1). A binding a void restored is in
// effect but not current, and takes no recovery identity (§7.9's cascade), so recovery(m) needs the member's newest
// binding to be the one in effect and outside every cascade.
//
// Holders leave in two ways. An entry n shrinks R when KeyHolders(R, n-1, t_n) loses a holder at n (§7.9's shrink);
// a holder expires at T_e when it leaves as t passes T_e with no entry (§7.9's expiry). Dropped decides both, and an
// agent its Delegation covers in the later set is no loss: it reads on through the Delegation's key, so no grant,
// admission or Unsuspend drops anyone (§10.6's never list, §10.5's covered row).
//
// Within one state a holder only leaves as t grows: RepoReadersAt only shrinks, live(d) and reach(d) only end, and an
// agent appears only when its covering Delegation leaves. So an expiry in (t1, t2] is a holder of KeyHolders(R, S, t1)
// that KeyHolders(R, S, t2) drops, and the first one is found by bisection.
//
// Pure, on every leg, the sidecar_http page Worker's included. Nothing here creates, derives or unwraps a key, so
// nothing calls testHookSecret.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a key holder is: the first byte of its identity (§10.5).
type GkmHolderKind byte

const (
	// a member device reading R: a leaf of R's group, or in the config and directory groups a wrapped one
	GkmHolderLeaf GkmHolderKind = 1
	// another sidecar reading R that no live Delegation among the holders covers
	GkmHolderAgent GkmHolderKind = 2
	// a live Delegation whose reach holds R
	GkmHolderDelegation GkmHolderKind = 3
	// a member reading R, by its current RecoveryBind
	GkmHolderRecovery GkmHolderKind = 4
)

// One key holder. Two holders are the same holder when their identities are equal.
type GkmHolder struct {
	Kind GkmHolderKind
	// A sidecar_id or member_id, 16 bytes; a delegation_id, 32.
	Id []byte
	// An agent admitted under a Delegation: its delegation_id, which covers it wherever that Delegation is a holder.
	// Not part of the identity.
	AdmittingDelegationId []byte
}

// kind byte || id, 17 bytes, or 33 for a Delegation (§10.5's identity bytes).
func (self GkmHolder) Identity() []byte {
	identity := make([]byte, 0, 1+len(self.Id))
	identity = append(identity, byte(self.Kind))
	return append(identity, self.Id...)
}

// Compares two holders by identity bytes, the order holders_sha256 sorts in.
func gkmHolderCmp(a GkmHolder, b GkmHolder) int {
	if a.Kind != b.Kind {
		if a.Kind < b.Kind {
			return -1
		}
		return 1
	}
	return bytes.Compare(a.Id, b.Id)
}

// KeyHolders(R, S, t) as a set: sorted by identity bytes, each holder once.
type GkmHolders []GkmHolder

// holders_sha256 (QD-465): SHA-256 of the identities in order, joined with no separator or count; the kind byte fixes
// each length.
func (self GkmHolders) Sha256() []byte {
	hasher := sha256.New()
	for _, holder := range self {
		hasher.Write([]byte{byte(holder.Kind)})
		hasher.Write(holder.Id)
	}
	return hasher.Sum(nil)
}

// Whether the set holds a holder of this identity.
func (self GkmHolders) Contains(kind GkmHolderKind, id []byte) bool {
	_, found := slices.BinarySearchFunc(self, GkmHolder{Kind: kind, Id: id}, gkmHolderCmp)
	return found
}

// The holders of this set that later loses: each missing from later, except an agent whose admitting Delegation is in
// later and so covers it there. Empty when later shrinks nothing (§7.9's shrink and expiry tests).
func (self GkmHolders) Dropped(later GkmHolders) GkmHolders {
	dropped := GkmHolders{}
	for _, holder := range self {
		if later.Contains(holder.Kind, holder.Id) {
			continue
		}
		if holder.Kind == GkmHolderAgent && 0 < len(holder.AdmittingDelegationId) &&
			later.Contains(GkmHolderDelegation, holder.AdmittingDelegationId) {
			continue
		}
		dropped = append(dropped, holder)
	}
	return dropped
}

// Whether later drops none of this set's holders.
func (self GkmHolders) KeptBy(later GkmHolders) bool {
	return len(self.Dropped(later)) == 0
}

// live(d) (§10.5): not ended, its key not dropped, no cascade voiding it, and at before its not_after. A row with
// no not_after, which §7.9 requires, is not live.
func GkmDelegationLive(view GkmAuthView, delegation *bridge.DelegationRow, at time.Time) bool {
	if delegation == nil || len(delegation.GetDelegationId()) != gkmDelegationIdByteCount {
		return false
	}
	if delegation.GetEndedAt() != 0 || delegation.GetKeyDroppedAt() != 0 {
		return false
	}
	if delegation.GetNotAfter() == 0 || delegation.GetNotAfter() <= at.UnixMilli() {
		return false
	}
	return !view.CascadeVoids(delegation.GetSigner(), delegation.GetAt())
}

// Whether reach(d) holds the repo at the time given (§10.5): the config and a team network's directory always, and
// any other repo a read or write grant naming one of d's tags reads then. A tag atom of the wrong size names nothing.
func GkmDelegationReaches(view GkmAuthView, delegation *bridge.DelegationRow, repoId Id, at time.Time) bool {
	repo := view.Repo(repoId)
	if repo == nil {
		return false
	}
	switch repo.GetKind() {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_DIRECTORY:
		return true
	}
	atoms := make([]Id, 0, len(delegation.GetTagAtoms()))
	for _, atomBytes := range delegation.GetTagAtoms() {
		if atom, err := IdFromBytes(atomBytes); err == nil {
			atoms = append(atoms, atom)
		}
	}
	if len(atoms) == 0 {
		return false
	}
	_, found := slices.BinarySearchFunc(view.ReposGrantedToAtoms(atoms, at), repoId, Id.Cmp)
	return found
}

// covered(s, R) (§10.5): the sidecar was admitted under a Delegation that is live and whose reach holds the repo.
func GkmCovered(view GkmAuthView, sidecarId Id, repoId Id, at time.Time) bool {
	row := view.SidecarRow(sidecarId)
	if row == nil || len(row.GetDelegationId()) == 0 {
		return false
	}
	for _, delegation := range view.Delegations() {
		if bytes.Equal(delegation.GetDelegationId(), row.GetDelegationId()) {
			return GkmDelegationLive(view, delegation, at) && GkmDelegationReaches(view, delegation, repoId, at)
		}
	}
	return false
}

// §10.5's set for the repo at the view's state and the time given, sorted by identity bytes. Refuses a repo the state
// does not hold, and a reader the state holds no row for, which a verified state never has.
func KeyHolders(view GkmAuthView, repoId Id, at time.Time) (GkmHolders, error) {
	if view.Repo(repoId) == nil {
		return nil, fmt.Errorf("%w: repo %s", ErrGkmNoRepo, repoId)
	}
	// §7.9's leaves row: untagged, naming a member, and not ephemeral
	memberDevice := func(row *bridge.SidecarRow) bool {
		return len(row.GetTagIds()) == 0 && len(row.GetMemberId()) == len(Id{}) && !row.GetEphemeral()
	}
	// the binding in effect is the newest and no cascade voids it: a void restores an older binding, which takes no
	// wrap until a signer outside P signs it again (§7.9's cascade)
	recoveryCurrent := func(member *bridge.MemberRow) bool {
		inEffect := member.GetRecoveryKeySha256()
		bindings := member.GetBindings()
		if len(inEffect) == 0 || len(bindings) == 0 {
			return false
		}
		newest := bindings[0]
		return bytes.Equal(newest.GetKeySha256(), inEffect) && !view.CascadeVoids(newest.GetSigner(), newest.GetAt())
	}
	holders := GkmHolders{}

	coveringDelegationIds := map[string]bool{}
	for _, delegation := range view.Delegations() {
		if GkmDelegationLive(view, delegation, at) && GkmDelegationReaches(view, delegation, repoId, at) {
			delegationId := delegation.GetDelegationId()
			coveringDelegationIds[string(delegationId)] = true
			holders = append(holders, GkmHolder{Kind: GkmHolderDelegation, Id: bytes.Clone(delegationId)})
		}
	}

	readingMemberIds := map[Id]bool{}
	for _, readerId := range view.RepoReadersAt(repoId, at) {
		row := view.SidecarRow(readerId)
		if row == nil {
			return nil, fmt.Errorf("%w: reader %s has no row", ErrGkmMalformed, readerId)
		}
		if memberDevice(row) {
			memberId, err := IdFromBytes(row.GetMemberId())
			if err != nil {
				return nil, fmt.Errorf("%w: reader %s names no member", ErrGkmMalformed, readerId)
			}
			holders = append(holders, GkmHolder{Kind: GkmHolderLeaf, Id: readerId.Bytes()})
			readingMemberIds[memberId] = true
			continue
		}
		admittingDelegationId := row.GetDelegationId()
		if 0 < len(admittingDelegationId) && coveringDelegationIds[string(admittingDelegationId)] {
			continue
		}
		holders = append(holders, GkmHolder{
			Kind:                  GkmHolderAgent,
			Id:                    readerId.Bytes(),
			AdmittingDelegationId: bytes.Clone(admittingDelegationId),
		})
	}

	for memberId := range readingMemberIds {
		if member := view.Member(memberId); member != nil && recoveryCurrent(member) {
			holders = append(holders, GkmHolder{Kind: GkmHolderRecovery, Id: memberId.Bytes()})
		}
	}

	slices.SortFunc(holders, gkmHolderCmp)
	return slices.CompactFunc(holders, func(a GkmHolder, b GkmHolder) bool {
		return gkmHolderCmp(a, b) == 0
	}), nil
}

// The holders an entry drops, before being KeyHolders(R, n-1, t_n) and after KeyHolders(R, n, t_n): §7.9's shrink
// test, which TEAM runs at each entry to advance holders_shrunk_at. A compromise retirement shrinks though no
// identity leaves, and is TEAM's to add (§7.9).
func GkmHoldersDropped(before GkmAuthView, after GkmAuthView, repoId Id, at time.Time) (GkmHolders, error) {
	beforeHolders, err := KeyHolders(before, repoId, at)
	if err != nil {
		return nil, err
	}
	afterHolders, err := KeyHolders(after, repoId, at)
	if err != nil {
		return nil, err
	}
	return beforeHolders.Dropped(afterHolders), nil
}

// Whether a key holder of the repo expired in (after, through] at the view's state: §7.9's authorization expiry, a
// holder leaving as time passes with no entry. Times count in whole ms, as every expiry and not_after does.
func GkmHolderExpired(view GkmAuthView, repoId Id, after time.Time, through time.Time) (bool, error) {
	afterMs, throughMs := after.UnixMilli(), through.UnixMilli()
	if throughMs <= afterMs {
		return false, nil
	}
	first, err := KeyHolders(view, repoId, time.UnixMilli(afterMs))
	if err != nil {
		return false, err
	}
	last, err := KeyHolders(view, repoId, time.UnixMilli(throughMs))
	if err != nil {
		return false, err
	}
	return !first.KeptBy(last), nil
}

// The first expiry of a key holder of the repo in (after, through] at the view's state, §7.9's identity (R, T_e), and
// false for none. Bisects whole ms: once a holder of KeyHolders(R, S, after) is dropped it stays dropped as t grows.
func GkmHolderExpiry(view GkmAuthView, repoId Id, after time.Time, through time.Time) (time.Time, bool, error) {
	expired, err := GkmHolderExpired(view, repoId, after, through)
	if err != nil || !expired {
		return time.Time{}, false, err
	}
	lowMs, highMs := after.UnixMilli(), through.UnixMilli()
	first, err := KeyHolders(view, repoId, time.UnixMilli(lowMs))
	if err != nil {
		return time.Time{}, false, err
	}
	// invariant: nothing is dropped at lowMs, and something is at highMs
	for 1 < highMs-lowMs {
		middleMs := lowMs + (highMs-lowMs)/2
		middle, err := KeyHolders(view, repoId, time.UnixMilli(middleMs))
		if err != nil {
			return time.Time{}, false, err
		}
		if first.KeptBy(middle) {
			lowMs = middleMs
		} else {
			highMs = middleMs
		}
	}
	return time.UnixMilli(highMs), true, nil
}
