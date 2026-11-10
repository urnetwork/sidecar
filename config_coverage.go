// §7.9's causal identities (TEAM-M2-17): the shrinks and authorization expiries a generation must cover, which KEYS's
// GkmGenerationCovers and GkmGatePasses and EVS's EvsAuthState judge a write by (§10.6).
//
//	shrink   entry n shrinks repo R when KeyHolders(R, n-1, t_n) is not a subset of KeyHolders(R, n, t_n) (§10.5),
//	         t_n its time, or when it retires a holder of R's key for compromise, a SidecarRevoke or RecoveryRebind with
//	         reason compromise or a DelegationRevoke with since_n > 0, though the holder's identity may stay; identity
//	         (R, n, A_n). Every verifier advances AclRepo.holders_shrunk_at to n at each such entry, in Apply and in a
//	         base's re-application alike, on the state being built (DESIGN-DETAILS 5.7), so a new device and a gate
//	         that started at a base reach a long-running reader's value, and writers compile it into bases
//	base     a base whose config head is newer than the previous base's may drop readers by policy, which a verifier
//	         that started at that base cannot compare with the state before it; until question
//	         team-m2-09-base-shrinks is answered, every verifier advances every repo's holders_shrunk_at to such a
//	         base's position, the fail-closed rule
//	expiry   a holder whose RepoGrant or requested grant expires, or whose SidecarAdmit (an uncovered agent's) or
//	         Delegation not_after passes, at T_e, leaves at T_e with no entry: KEYS's GkmHolderExpiry, identity
//	         (R, T_e). A covered agent's own not_after drops no holder where it is covered, and a ReaderKey's lapse is
//	         no expiry: KeyHolders holds neither
//
// Only an entry that wrote a sidecar, member or Delegation row, or the acl rows, can shrink, so every other entry costs
// nothing here; one that did is judged over every repo the rows hold. Bounding that by the repos the entry's subject
// can reach is the review phase's.
//
// Nothing here creates, derives or unwraps a key. On every leg.

package sidecar

import (
	"bytes"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The newest log position that shrank the repo's key holders (§7.9's shrink row), 0 for none or a repo this state does
// not hold: a generation covers it iff its auth pin is at or past it.
func (self *ConfigState) ShrunkAt(repoId Id) uint64 {
	return self.Repo(repoId).GetHoldersShrunkAt()
}

// The first authorization expiry of the repo's key holders in (after, through] at this state (§7.9's expiry row), false
// for none: a generation whose time is before it covers it not, and the covering generation is cause REMOVE.
func (self *ConfigState) ExpiriesFor(repoId Id, after time.Time, through time.Time) (time.Time, bool, error) {
	return GkmHolderExpiry(self, repoId, after, through)
}

// The holders an entry retires for compromise, whose identity may stay: SidecarRevoke and RecoveryRebind with reason
// compromise, and a DelegationRevoke for a leaked bundle (since_n > 0).
type configCompromiseRetirements struct {
	sidecarIds    []Id
	memberIds     []Id
	delegationIds [][]byte
}

// What the statements that took effect at an entry retire for compromise.
func configCompromisesOf(effects []*configStatement) configCompromiseRetirements {
	retirements := configCompromiseRetirements{}
	for _, statement := range effects {
		switch body := statement.body.(type) {
		case *bridge.SidecarRevoke:
			if body.GetReason() == bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE {
				if sidecarId, err := IdFromBytes(body.GetSidecarId()); err == nil {
					retirements.sidecarIds = append(retirements.sidecarIds, sidecarId)
				}
			}
		case *protocol.RecoveryRebind:
			if body.GetReason() == bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_COMPROMISE {
				if memberId, err := IdFromBytes(body.GetMemberId()); err == nil {
					retirements.memberIds = append(retirements.memberIds, memberId)
				}
			}
		case *protocol.DelegationRevoke:
			if 0 < body.GetSinceN() {
				retirements.delegationIds = append(retirements.delegationIds, bytes.Clone(body.GetDelegationId()))
			}
		}
	}
	return retirements
}

// Whether holders hold one of the retired holders.
func (self configCompromiseRetirements) heldBy(holders GkmHolders) bool {
	for _, sidecarId := range self.sidecarIds {
		if holders.Contains(GkmHolderLeaf, sidecarId.Bytes()) || holders.Contains(GkmHolderAgent, sidecarId.Bytes()) {
			return true
		}
	}
	for _, memberId := range self.memberIds {
		if holders.Contains(GkmHolderRecovery, memberId.Bytes()) {
			return true
		}
	}
	for _, delegationId := range self.delegationIds {
		if holders.Contains(GkmHolderDelegation, delegationId) {
			return true
		}
	}
	return false
}

// The statements that took effect at an entry, as the shrink row reads them: a statement's own, a completed proposal's
// statement, or a tick's activations; an AuthorityProposal or AuthorityCosign that left its proposal open took none.
func configEntryEffects(statement *configStatement, activations []configActivation) []*configStatement {
	effects := []*configStatement{}
	if statement != nil {
		switch {
		case statement.completes != nil:
			effects = append(effects, statement.completes)
		case statement.proposed == nil:
			if _, proposes := statement.body.(*protocol.AuthorityProposal); !proposes {
				if _, cosigns := statement.body.(*protocol.AuthorityCosign); !cosigns {
					effects = append(effects, statement)
				}
			}
		}
	}
	for _, activation := range activations {
		effects = append(effects, activation.statement)
	}
	return effects
}

// Advances holders_shrunk_at on next, the state at entry n being built from before, S(n-1), for each repo the entry
// shrinks at its time (§7.9's shrink row). Called once an entry's effects are written, in Apply, in a base's
// re-application and in StateAt's rebuild alike, so every verifier holds one value.
func configAdvanceShrinks(before *ConfigState, next *configStateBuilder, effects []*configStatement) {
	touched := 0 < len(next.sidecarsCopied) || 0 < len(next.membersCopied) || 0 < len(next.delegationsCopied) ||
		next.state.aclRows != before.aclRows
	retirements := configCompromisesOf(effects)
	if !touched {
		return
	}
	// the state the entry made, an immutable view with an acl part of its own
	after := configCopyState(next.state)
	at := time.UnixMilli(next.state.timeMs)
	shrunk := map[Id]bool{}
	for _, repo := range after.aclRows.GetRepos() {
		repoId, err := IdFromBytes(repo.GetRepoId())
		if err != nil || before.Repo(repoId) == nil {
			// a repo the entry made has no holder to lose
			continue
		}
		beforeHolders, err := KeyHolders(before, repoId, at)
		if err != nil {
			continue
		}
		afterHolders, err := KeyHolders(after, repoId, at)
		if err != nil || 0 < len(beforeHolders.Dropped(afterHolders)) || retirements.heldBy(beforeHolders) {
			// holders the state cannot compute fail closed, as a shrink
			shrunk[repoId] = true
		}
	}
	configSetShrunkAt(next, func(repoId Id) bool { return shrunk[repoId] })
}

// Sets holders_shrunk_at to the builder's position for each repo shrink names, on a copy of its acl rows.
func configSetShrunkAt(next *configStateBuilder, shrink func(repoId Id) bool) {
	if next.state.aclRows == nil {
		return
	}
	n := next.state.n
	var rows *protocol.AclRows
	for i, repo := range next.state.aclRows.GetRepos() {
		repoId, err := IdFromBytes(repo.GetRepoId())
		if err != nil || !shrink(repoId) || n <= repo.GetHoldersShrunkAt() {
			continue
		}
		if rows == nil {
			rows = proto.Clone(next.state.aclRows).(*protocol.AclRows)
		}
		rows.Repos[i].HoldersShrunkAt = n
	}
	if rows != nil {
		next.setAclRows(rows)
	}
}

// The fail-closed rule for a base whose config head is newer than the previous base's (question
// team-m2-09-base-shrinks): every repo's holders_shrunk_at advances to the base's position, at every verifier alike,
// since each holds the previous base.
func configAdvanceBaseShrinks(next *configStateBuilder, previous *configBase, header *bridge.ProjectionHeader) {
	if previous == nil || header.GetConfigVersion() <= previous.header.GetConfigVersion() {
		return
	}
	configSetShrunkAt(next, func(repoId Id) bool { return true })
}
