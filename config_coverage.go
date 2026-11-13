// §7.9's causal identities (TEAM-M2-17): the shrinks and authorization expiries a generation must cover, which KEYS's
// GkmGenerationCovers and GkmGatePasses and EVS's EvsAuthState judge a write by (§10.6).
//
//	shrink   entry n shrinks repo R when KeyHolders(R, n-1, t_n) is not a subset of KeyHolders(R, n, t_n) (§10.5),
//	         t_n its time, or when it retires a holder of R's key for compromise, a SidecarRevoke or RecoveryRebind with
//	         reason compromise or a DelegationRevoke with since_n > 0, though the holder's identity may stay; identity
//	         (R, n, A_n). Every verifier advances AclRepo.holders_shrunk_at to n at each such entry, in Apply and in a
//	         base's re-application alike, on the state being built (DESIGN-DETAILS 5.7), so a new device and a gate
//	         that started at a base reach a long-running reader's value, and writers compile it into bases
//	base     a base b is an entry too: its own config head change can drop readers by policy, so it shrinks R when
//	         KeyHolders(R, b-1, t_b) is not a subset of KeyHolders(R, b, t_b), S(b) being b's rows with its tail
//	         re-applied. A verifier that starts at b holds no S(b-1), so b's header carries those repos,
//	         shrunk_repo_ids (QD-746): its writer computes them from its tip and the state its base gives, at its own
//	         clock, since only api knows t_b; api computes them again at the time it stamps the entry and answers 409
//	         to a list that differs, so the writer signs again; a verifier present at b-1 computes them again at t_b
//	         and forks on any difference, as with tail_verdicts; one that starts at b takes them. Every verifier then
//	         advances holders_shrunk_at to b for exactly those repos
//	expiry   a holder whose RepoGrant or requested grant expires, or whose SidecarAdmit (an uncovered agent's) or
//	         Delegation not_after passes, at T_e, leaves at T_e with no entry: KEYS's GkmHolderExpiry, identity
//	         (R, T_e). A covered agent's own not_after drops no holder where it is covered, and a ReaderKey's lapse is
//	         no expiry: KeyHolders holds neither
//
// Only an entry that wrote a sidecar, member or Delegation row, or the acl rows, can shrink, so every other entry costs
// nothing here; one that did is judged over every repo the rows hold, and so is every base. Bounding that by the repos
// the entry's subject can reach is the review phase's.
//
// Nothing here creates, derives or unwraps a key. On every leg.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A base's shrunk_repo_ids, well formed, are not the repos its own change shrinks at its time as this verifier's
// states give them: a fork at a reader present at b-1; at api, whose time is the entry's own, the writer's 409 to sign
// again at its clock (QD-746).
var errConfigBaseShrinksDiffer = errors.New("shrunk_repo_ids differ")

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

// The repos whose key holders a base's own change shrinks (QD-746), as its shrunk_repo_ids carries them: each repo of
// after's rows, after being the base's state with its tail re-applied, that before, S(b-1), holds, and whose
// KeyHolders at the time given lose a holder from before to after by Dropped, so an agent its Delegation covers in
// after is no loss. Holders after's state cannot compute fail closed, as a shrink, as configAdvanceShrinks reads them.
// Sorted by id bytes, each once.
func configBaseShrunkRepoIds(before *ConfigState, after *ConfigState, at time.Time) [][]byte {
	repoIds := []Id{}
	for _, repo := range after.aclRows.GetRepos() {
		repoId, err := IdFromBytes(repo.GetRepoId())
		if err != nil || before.Repo(repoId) == nil {
			// a repo the base's state made has no holder to lose
			continue
		}
		beforeHolders, err := KeyHolders(before, repoId, at)
		if err != nil {
			continue
		}
		afterHolders, err := KeyHolders(after, repoId, at)
		if err != nil || 0 < len(beforeHolders.Dropped(afterHolders)) {
			repoIds = append(repoIds, repoId)
		}
	}
	slices.SortFunc(repoIds, Id.Cmp)
	repoIds = slices.Compact(repoIds)
	repoIdBytes := make([][]byte, 0, len(repoIds))
	for _, repoId := range repoIds {
		repoIdBytes = append(repoIdBytes, repoId.Bytes())
	}
	return repoIdBytes
}

// The repos a base's shrunk_repo_ids name, as a verifier takes them: each a 16-byte repo_id of after's rows, in
// strictly ascending byte order. Else an error, which no honest writer's base gives.
func configBaseShrunkRepoIdsOf(header *bridge.ProjectionHeader, after *ConfigState) (map[Id]bool, error) {
	rowsRepoIds := map[Id]bool{}
	for _, repo := range after.aclRows.GetRepos() {
		if repoId, err := IdFromBytes(repo.GetRepoId()); err == nil {
			rowsRepoIds[repoId] = true
		}
	}
	shrunk := map[Id]bool{}
	for i, repoIdBytes := range header.GetShrunkRepoIds() {
		repoId, err := IdFromBytes(repoIdBytes)
		if err != nil {
			return nil, fmt.Errorf("shrunk_repo_ids[%d] of %d bytes", i, len(repoIdBytes))
		}
		if 0 < i && 0 <= bytes.Compare(header.GetShrunkRepoIds()[i-1], repoIdBytes) {
			return nil, fmt.Errorf("shrunk_repo_ids[%d] out of ascending order", i)
		}
		if !rowsRepoIds[repoId] {
			return nil, fmt.Errorf("shrunk_repo_ids[%d] names a repo the rows do not hold", i)
		}
		shrunk[repoId] = true
	}
	return shrunk, nil
}

// A base in a later base's tail, re-applied on next at its own position: its rows are superseded and it judges
// nothing, but holders_shrunk_at advances again to its position for each repo of the rebuilt rows its shrunk_repo_ids
// name, which every verifier at the later base holds alike, since it keeps the tail's entries. Its list was held to
// what its change shrank where it landed (configApplyBaseShrinks); an id that does not parse names no repo here. An
// entry that does not parse as a base is an error, a fork.
func configReapplyBaseShrinks(next *configStateBuilder, kept *configKeptEntry) error {
	_, header, err := configParseBase(kept.entry)
	if err != nil {
		return fmt.Errorf("the tail's base %d does not parse: %w", kept.n, err)
	}
	shrunk := map[Id]bool{}
	for _, repoIdBytes := range header.GetShrunkRepoIds() {
		if repoId, err := IdFromBytes(repoIdBytes); err == nil {
			shrunk[repoId] = true
		}
	}
	if 0 < len(shrunk) {
		configSetShrunkAt(next, func(repoId Id) bool { return shrunk[repoId] })
	}
	return nil
}

// The shrunk_repo_ids an honest writer signs for a base at this log's next position (QD-746): the state header's fold,
// tail_verdicts and rows give over the tip, built as applying the base builds it, against the tip's state, at timeMs,
// the time the writer expects the entry to carry; api judges the list again at the time it stamps. header's other
// fields must be the base's own, shrunk_repo_ids aside; a header whose tail the log cannot re-apply, or rows that do
// not build, are an error. Nothing is kept and no published state changes. For the goroutine that applies, as Apply
// is, or under the lock that serializes it (ConfigClient's followLock).
func (self *ConfigLog) BaseShrunkRepoIds(header *bridge.ProjectionHeader, rows []byte, timeMs int64) ([][]byte, error) {
	tip := self.state.Load()
	n := tip.n + 1
	verdicts, err := self.checkBaseTail(tip.base, header, n)
	if err != nil {
		return nil, err
	}
	// a copy whose arrays end where its own do, so the dry run appends to arrays of its own and never writes into the
	// ones the log's states share
	before := configCopyState(tip)
	before.chains = before.chains[:len(before.chains):len(before.chains)]
	before.ring = before.ring[:len(before.ring):len(before.ring)]
	// the entry's digest is no input to the holders, so the dry run's is zero
	scratch := &configKeptEntry{
		n:     n,
		entry: &bridge.AuthEntry{NetworkId: self.networkId.Bytes(), N: n, PrevChain: bytes.Clone(tip.chain[:]), Kind: bridge.AuthEntryKindBase, TimeMs: timeMs},
	}
	next, _, err := self.stateFromBase(before, scratch, header, rows)
	if err != nil {
		return nil, err
	}
	if err := self.reapplyTail(next, header.GetFoldedThrough(), n, verdicts, false); err != nil {
		return nil, err
	}
	return configBaseShrunkRepoIds(tip, configCopyState(next.state), time.UnixMilli(timeMs)), nil
}

// A base's own shrinks on next, the state its rows give with its tail re-applied (QD-746; §7.9's shrink row): a
// verifier standing at before, S(b-1), computes the repos at the base's time and requires the header's shrunk_repo_ids
// to be exactly those (errConfigBaseShrinksDiffer otherwise), and one that starts at the base, before nil, takes them;
// either way the list must be well formed. Then holders_shrunk_at advances to the base's position for exactly those
// repos, so a long-running reader, a new device and a cold gate hold one value (D-TEAM-19). An error changes nothing:
// a fork at a reader, a refusal at api.
func configApplyBaseShrinks(before *ConfigState, next *configStateBuilder, header *bridge.ProjectionHeader) error {
	// the state the base made, an immutable view with an acl part of its own
	after := configCopyState(next.state)
	shrunk, err := configBaseShrunkRepoIdsOf(header, after)
	if err != nil {
		return err
	}
	if before != nil {
		computed := configBaseShrunkRepoIds(before, after, time.UnixMilli(next.state.timeMs))
		carried := header.GetShrunkRepoIds()
		if !slices.EqualFunc(computed, carried, bytes.Equal) {
			return fmt.Errorf("%w: the base names %d repos its own change shrinks where this verifier's states give %d, or others",
				errConfigBaseShrinksDiffer, len(carried), len(computed))
		}
	}
	configSetShrunkAt(next, func(repoId Id) bool { return shrunk[repoId] })
	return nil
}
