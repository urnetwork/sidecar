// §7.9's BASE row: a config writer's signed ProjectionHeader that replaces the rows. A base chains on, names rows by
// hash and a config head no older than the previous base's, folds no less, and is signed by a config writer at
// S(my.n); its rows replace the state's, then the STATEMENT and TICK entries among folded_through+1..n-1 re-apply in
// order on them, a BASE there skipped, each keeping the verdict it got at its own position, so a later authority
// change never undoes an earlier revocation, while effects that depend on rows follow the new rows.
//
// A base that fails any of this is a FORK, never a refusal: the rows it names would be every later entry's state.
//
// The config head is the one part this file cannot read: a full reader opens it through ConfigRowsSource.CheckHead,
// which TEAM-M2-08's ConfigHead and CompileProjectionRows fill, given the records this log says the head must hold.
//
// Single-writer, as ConfigLog's Apply is. Nothing here creates, derives or unwraps a key, so nothing calls
// testHookSecret.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One STATEMENT or TICK a config head holds as a record (plan-TEAM-config-head-format #1's ConfigRecord): the log's
// entries in (the previous base's folded_through, folded_through], in position order, BASE entries excluded.
type ConfigFoldRecord struct {
	// A statement's id (its signed bytes' hash); empty for a tick.
	Id []byte
	// The carrying entry's position and time.
	N      uint64
	TimeMs int64
	// AuthEntry.kind, 2 or 3.
	Kind uint32
	// AuthEntry.body, verbatim.
	Body []byte
}

// What a full reader's check of one base's config head is given (§7.9's BASE row).
type ConfigHeadCheck struct {
	// The state the base lands on, S(n-1): its config writers judge the head's chain, and its base is the one the
	// head must descend from.
	Previous *ConfigState
	// The base's header, verified.
	Header *bridge.ProjectionHeader
	// The records the head must hold, exactly. FoldedKnown is false when the reader starts at this base and keeps
	// none of them (§7.9's retention row), and then only the chain to genesis is checked.
	Folded      []ConfigFoldRecord
	FoldedKnown bool
	// The rows, verbatim, whose hash the header names: SHA-256(compile(head)) must equal it.
	Rows []byte
}

// What the head check found.
type ConfigHeadFacts struct {
	// The ServiceSettings record the head holds, nil for none, so the defaults hold (§7.9's ServiceSettings).
	Settings *protocol.ServiceSettings
}

// Where a ConfigLog takes a base's rows and its config head's check from. A full reader's source opens the config
// head (TEAM-M2-08, TEAM-M2-10); api and the gates hold no config key and verify rows only (TEAM-M2-11).
type ConfigRowsSource interface {
	// The ProjectionRows bytes a base names, verbatim (projrows/<network_id>/<rows_sha256>/_). ConfigLog checks
	// their hash and size itself.
	Rows(networkId Id, rowsSha256 []byte) ([]byte, error)
	// Checks the base's config head: it is the previous base's head or a descendant, it chains to genesis through
	// config writers, it holds exactly check.Folded, each by id with its carrying position, and it compiles to
	// check.Rows. Any error makes the base a FORK.
	CheckHead(check *ConfigHeadCheck) (*ConfigHeadFacts, error)
}

// Refuses every base for want of a config head reader: a source to pass where none exists yet, so a log fails closed.
type ConfigNoRowsSource struct{}

// None.
func (self ConfigNoRowsSource) Rows(networkId Id, rowsSha256 []byte) ([]byte, error) {
	return nil, errors.New("no rows source")
}

// None.
func (self ConfigNoRowsSource) CheckHead(check *ConfigHeadCheck) (*ConfigHeadFacts, error) {
	return nil, errors.New("no config head reader")
}

// A base's fork, with its digest as the remote side.
func (self *ConfigLog) baseFork(kept *configKeptEntry, format string, a ...any) error {
	return self.stopAtFork(&ConfigForkError{
		N: kept.n, RemoteChain: kept.chain, Entry: bytes.Clone(kept.entryBytes), Reason: "base: " + fmt.Sprintf(format, a...),
	})
}

// A BASE entry at state, as §7.9's BASE row says. Returns the next state, or a fork.
func (self *ConfigLog) applyBase(state *ConfigState, kept *configKeptEntry, rowsSource ConfigRowsSource) (*ConfigState, error) {
	if rowsSource == nil {
		rowsSource = ConfigNoRowsSource{}
	}
	signed, header, err := configParseBase(kept.entry)
	if err != nil {
		return nil, self.baseFork(kept, "%v", err)
	}
	kept.verdict.SignedType = bridge.SignedType_SIGNED_PROJECTION_HEADER
	kept.verdict.StatementId = bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, signed.GetBody())

	signerId, err := configBaseSigner(signed)
	if err != nil {
		return nil, self.baseFork(kept, "%v", err)
	}
	if !state.IsConfigWriter(signerId) {
		return nil, self.baseFork(kept, "the signer is no config writer at %d", state.n)
	}
	rows, err := rowsSource.Rows(self.networkId, header.GetRowsSha256())
	if err != nil {
		return nil, self.baseFork(kept, "rows: %v", err)
	}
	var previousHeader *bridge.ProjectionHeader
	if state.base != nil {
		previousHeader = state.base.header
	}
	if _, err := bridge.VerifyBaseKeyless(kept.entry, state.IdentityKey(signerId), rows, previousHeader); err != nil {
		return nil, self.baseFork(kept, "%v", err)
	}

	facts := &ConfigHeadFacts{}
	if !self.rowsOnly {
		folded, foldedKnown := self.foldedRecords(state, header)
		if !foldedKnown {
			return nil, self.baseFork(kept, "the records it folds are not all kept")
		}
		facts, err = rowsSource.CheckHead(&ConfigHeadCheck{
			Previous: state, Header: header, Folded: folded, FoldedKnown: true, Rows: rows,
		})
		if err != nil {
			return nil, self.baseFork(kept, "config head: %v", err)
		}
		if facts == nil {
			facts = &ConfigHeadFacts{}
		}
	}

	next, err := self.stateFromBase(state, kept, header, rows, facts)
	if err != nil {
		return nil, self.baseFork(kept, "%v", err)
	}
	self.reapplyTail(next, header.GetFoldedThrough(), kept.n)
	result := next.finish()
	self.retainBase(result, rows)
	return result, nil
}

// A BASE entry's Signed and its header, of the one type a base carries.
func configParseBase(entry *bridge.AuthEntry) (*bridge.Signed, *bridge.ProjectionHeader, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		return nil, nil, err
	}
	if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_PROJECTION_HEADER {
		return nil, nil, fmt.Errorf("a base of type %d", signed.GetType())
	}
	message, err := ParseConfigStatement(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, signed.GetBody())
	if err != nil {
		return nil, nil, err
	}
	return signed, message.(*bridge.ProjectionHeader), nil
}

// The sidecar a base's Signed names: an identity key's form of signer_id, never a recovery key or a Delegation.
func configBaseSigner(signed *bridge.Signed) (Id, error) {
	if len(signed.GetKeyId()) != 0 {
		return Id{}, errors.New("a base signed by other than an identity key")
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return Id{}, fmt.Errorf("signer_id of %d bytes", len(signed.GetSignerId()))
	}
	return signerId, nil
}

// The records a new base's head must hold: every STATEMENT and TICK in (the previous base's folded_through,
// folded_through], false when this log does not keep them all.
func (self *ConfigLog) foldedRecords(state *ConfigState, header *bridge.ProjectionHeader) ([]ConfigFoldRecord, bool) {
	from := uint64(1)
	if state.base != nil {
		from = state.base.header.GetFoldedThrough() + 1
	}
	folded := []ConfigFoldRecord{}
	for n := from; n <= header.GetFoldedThrough(); n += 1 {
		kept := self.keptEntry(n)
		if kept == nil {
			return nil, false
		}
		kind := kept.entry.GetKind()
		if kind == bridge.AuthEntryKindBase {
			continue
		}
		record := ConfigFoldRecord{N: n, TimeMs: kept.entry.GetTimeMs(), Kind: kind, Body: kept.entry.GetBody()}
		if kind == bridge.AuthEntryKindStatement {
			record.Id = bytes.Clone(kept.verdict.StatementId[:])
		}
		folded = append(folded, record)
	}
	return folded, true
}

// The state a base's rows give, before the tail re-applies: its rows replace previous's, its pins move on, and the
// proposals the base folded close, since rows carry no open proposal (question
// team-m2-02-open-proposals-across-bases), while the tail's re-open as it re-applies.
func (self *ConfigLog) stateFromBase(previous *ConfigState, kept *configKeptEntry, header *bridge.ProjectionHeader, rowsBytes []byte, facts *ConfigHeadFacts) (*configStateBuilder, error) {
	rows := &bridge.ProjectionRows{}
	if err := proto.Unmarshal(rowsBytes, rows); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	next := newConfigStateBuilder(previous, kept.n, kept.chain, kept.entry.GetTimeMs())
	state := next.state
	if err := configLoadRows(state, rows); err != nil {
		return nil, err
	}
	state.previousBase = previous.base
	state.base = &configBase{n: kept.n, chain: kept.chain, timeMs: kept.entry.GetTimeMs(), header: header}
	state.threshold = header.GetThreshold()
	state.settings = facts.Settings
	state.settingsKnown = !self.rowsOnly
	state.proposals = map[[sha256.Size]byte]*configProposal{}
	next.membersOwned, next.sidecarsOwned, next.delegationsOwned, next.keysOwned, next.proposalsOwned = true, true, true, true, true
	// every row came from these rows, so the builder owns them all
	for memberId := range state.members {
		next.membersCopied[memberId] = true
	}
	for sidecarId := range state.sidecars {
		next.sidecarsCopied[sidecarId] = true
	}
	for delegationId := range state.delegations {
		next.delegationsCopied[delegationId] = true
	}
	// rows whose acl part does not build are no state; the state's own acl part builds later, on first use, once the
	// tail has re-applied
	if _, err := NewAclState(state.aclRows, state); err != nil {
		return nil, err
	}
	return next, nil
}

// Indexes a base's rows into state, refusing rows a reader cannot hold: a malformed or repeated id, an admission
// naming neither a member nor tags or both, a bad identity key, or acl bytes that do not build.
func configLoadRows(state *ConfigState, rows *bridge.ProjectionRows) error {
	state.members = make(map[Id]*bridge.MemberRow, len(rows.GetMembers()))
	for i, member := range rows.GetMembers() {
		memberId, err := IdFromBytes(member.GetMemberId())
		if err != nil {
			return fmt.Errorf("rows: members[%d].member_id", i)
		}
		if state.members[memberId] != nil {
			return fmt.Errorf("rows: members[%d] repeats a member", i)
		}
		state.members[memberId] = member
	}
	state.sidecars = make(map[Id]*bridge.SidecarRow, len(rows.GetSidecars()))
	for i, sidecar := range rows.GetSidecars() {
		sidecarId, err := IdFromBytes(sidecar.GetSidecarId())
		if err != nil {
			return fmt.Errorf("rows: sidecars[%d].sidecar_id", i)
		}
		if state.sidecars[sidecarId] != nil {
			return fmt.Errorf("rows: sidecars[%d] repeats a sidecar", i)
		}
		_, untagged := configRowMember(sidecar)
		if untagged == (0 < len(sidecar.GetTagIds())) {
			return fmt.Errorf("rows: sidecars[%d] names neither a member nor tags, or both", i)
		}
		for _, tagId := range sidecar.GetTagIds() {
			if len(tagId) != len(Id{}) {
				return fmt.Errorf("rows: sidecars[%d].tag_ids", i)
			}
		}
		identityKey := sidecar.GetIdentityPublicKey()
		genesisDevice := bytes.Equal(sidecar.GetSidecarId(), state.genesis.GetOwnerSidecarId())
		if !(len(identityKey) == 0 && genesisDevice) && !configIdentityKeyValid(identityKey, sidecar.GetIdentityAlg()) {
			return fmt.Errorf("rows: sidecars[%d].identity_public_key", i)
		}
		state.sidecars[sidecarId] = sidecar
	}
	state.delegations = make(map[string]*bridge.DelegationRow, len(rows.GetDelegations()))
	for i, delegation := range rows.GetDelegations() {
		if len(delegation.GetDelegationId()) != configDelegationIdByteCount {
			return fmt.Errorf("rows: delegations[%d].delegation_id", i)
		}
		if state.delegations[string(delegation.GetDelegationId())] != nil {
			return fmt.Errorf("rows: delegations[%d] repeats a Delegation", i)
		}
		state.delegations[string(delegation.GetDelegationId())] = delegation
	}
	state.keys = make(map[string]*bridge.KeyRow, len(rows.GetRegisteredKeys()))
	for i, key := range rows.GetRegisteredKeys() {
		if len(key.GetKeyId()) == 0 {
			return fmt.Errorf("rows: registered_keys[%d].key_id", i)
		}
		if state.keys[string(key.GetKeyId())] != nil {
			return fmt.Errorf("rows: registered_keys[%d] repeats a key", i)
		}
		state.keys[string(key.GetKeyId())] = key
	}
	state.aclRows = &protocol.AclRows{}
	if err := proto.Unmarshal(rows.GetAcl(), state.aclRows); err != nil {
		return fmt.Errorf("rows: acl: %w", err)
	}
	return nil
}

// Re-applies the STATEMENT and TICK entries among foldedThrough+1..n-1 on next, in order, a BASE among them skipped,
// each keeping the verdict it got at its own position: a refused one stays refused and an applied one applies its
// effect again on the new rows, an effect the new rows no longer allow dropping (§7.9's BASE row).
func (self *ConfigLog) reapplyTail(next *configStateBuilder, foldedThrough uint64, n uint64) {
	for k := foldedThrough + 1; k < n; k += 1 {
		kept := self.keptEntry(k)
		if kept == nil || !kept.verdict.Accepted() {
			continue
		}
		switch kept.entry.GetKind() {
		case bridge.AuthEntryKindStatement:
			if kept.statement == nil {
				continue
			}
			if err := configApplyStatement(next, kept.statement, true); err != nil {
				self.log.Infof("[config]%s entry %d's effect ends at base %d: %v", self.networkId, k, n, err)
			}
		case bridge.AuthEntryKindTick:
			if kept.tick != nil {
				configApplyTick(next, kept.tick)
			}
		}
	}
}
