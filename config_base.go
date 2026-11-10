// §7.9's base row as DESIGN-DETAILS 5.2 settles it: a config writer's signed ProjectionHeader that replaces the rows.
// A base chains on, names rows by hash and a config head no older than the previous base's, folds no less, and is
// signed by a config writer at S(my.n). Its folded_through is the previous base's or at least that base's position,
// it leaves at most 4,096 entries unfolded, and its tail_verdicts carries the verdict of every entry among
// folded_through+1..n-1, which must equal this reader's wherever it holds one. Its rows replace the state's, then the
// tail re-applies by those verdicts, judging nothing (Reapply), so a later authority change never undoes an earlier
// revocation while effects that depend on rows follow the new rows, and a reader that started later reaches the same
// state as one that judged each entry at its own position.
//
// A base that fails any of this is a fork, never a refusal: the rows it names would be every later entry's state.
//
// The config head is the one part this file cannot read: a full reader opens it through ConfigRowsSource.CheckHead,
// given the records this log says the head must hold, BASE entries included (question
// details-5-base-records-in-folds, built on its recommendation), and the log-derived rows it compiles with.
//
// Single-writer, as ConfigLog's Apply is. Nothing here creates, derives or unwraps a key, so nothing calls
// testHookSecret.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// DESIGN-DETAILS 5.2.3's tail cap, a protocol constant beside the replay row's 4,096: a base leaves at most this many
// entries unfolded, so every verifier's re-application, the header's bitmap and {acl_}e's needs stay bounded.
const configTailMax = 4096

// One tail entry's verdict as a base's tail_verdicts carries it, two bits (DESIGN-DETAILS 5.2.2).
const (
	// refused at its position, or a BASE
	configTailRefused = uint8(0)
	// took effect
	configTailEffect = uint8(1)
	// took effect and completed a proposal: an AuthorityProposal at k = 1 or the k-th AuthorityCosign only
	configTailCompleted = uint8(2)
	// never valid
	configTailNever = uint8(3)
)

// The rows source cannot read the base's config head now (evs unavailable, the head not fetched): withheld, never a
// fork, so the log stays where it is and its caller reads again later (§7.9's retain row).
var ErrConfigHeadUnavailable = errors.New("config head unavailable")

// One entry a config head holds as a record (plan-TEAM-config-head-format #1's ConfigRecord): the log's entries in
// (the previous base's folded_through, folded_through], in position order, BASE entries included as kind 1 with the
// Signed ProjectionHeader as body (DESIGN-DETAILS 5.2.3; question details-5-base-records-in-folds), so a head holds every
// entry's body and a reader recomputes A_1..A_ft from the genesis through the head alone.
type ConfigFoldRecord struct {
	// A statement's or a base's id (its signed bytes' hash); empty for a tick.
	Id []byte
	// The carrying entry's position and time.
	N      uint64
	TimeMs int64
	// AuthEntry.kind, 1, 2 or 3.
	Kind uint32
	// AuthEntry.body, verbatim.
	Body []byte
}

// What a full reader's check of one base's config head is given (§7.9's base row; DESIGN-DETAILS 5.2.4's ApplyBase and
// StartAtBase).
type ConfigHeadCheck struct {
	// The state the base lands on, S(n-1), for a reader standing there: its config writers judge the head's
	// ServiceSettings, and its base is the one the head must descend from. Nil for a reader starting at this base, a
	// new device or one restarting after it fell behind, which checks the anchor instead (GenesisChain, FoldedFrom,
	// FirstPrevChain, Floor).
	Previous *ConfigState
	// The base's header, verified.
	Header *bridge.ProjectionHeader
	// With Previous, exactly the records in (the previous base's folded_through, folded_through]; without, the
	// entries this reader holds in [FoldedFrom, folded_through]. FoldedKnown false checks only the chain.
	Folded      []ConfigFoldRecord
	FoldedKnown bool
	// The rows, verbatim, whose hash the header names: SHA-256(compile(head, CompileRows)) must equal it.
	Rows []byte
	// L(folded_through), the log-derived rows the head compiles with (DESIGN-DETAILS 5.2.2's compile): base 1's from
	// the Genesis, the previous base's rows when the fold did not move, else this reader's state at folded_through.
	// Nil without Previous, which checks no compile.
	CompileRows *ConfigCompileRows
	// A_0, which the head's genesis must hash to.
	GenesisChain [sha256.Size]byte
	// Without Previous: the first position this reader holds, and that entry's prev_chain, A_{FoldedFrom-1}, which the
	// chain recomputed from the genesis through the head's records must reach; and a pin this reader held before,
	// below FoldedFrom, nil for none, which that chain must pass through (DESIGN-DETAILS 5.5's far-behind reader).
	FoldedFrom     uint64
	FirstPrevChain [sha256.Size]byte
	Floor          *bridge.AuthPin
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
	// check.Rows (CheckConfigBase). ErrConfigHeadUnavailable when the head cannot be read now, which withholds the
	// base; any other error makes the base a fork.
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

// A base entry at state, as §7.9's base row and DESIGN-DETAILS 5.2.4's ApplyBase say. Returns the next state, a fork,
// or ErrConfigHeadUnavailable with nothing changed.
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
	bits, err := self.checkBaseTail(state.base, header, kept.n)
	if err != nil {
		return nil, self.baseFork(kept, "%v", err)
	}

	facts := &ConfigHeadFacts{}
	if !self.rowsOnly {
		from := uint64(1)
		if state.base != nil {
			from = state.base.header.GetFoldedThrough() + 1
		}
		folded, foldedKnown := self.foldedRecords(from, header.GetFoldedThrough())
		if !foldedKnown {
			return nil, self.baseFork(kept, "the records it folds are not all kept")
		}
		compileRows, err := self.foldRows(state, header)
		if err != nil {
			return nil, self.baseFork(kept, "the rows at folded_through %d: %v", header.GetFoldedThrough(), err)
		}
		facts, err = rowsSource.CheckHead(&ConfigHeadCheck{
			Previous:     state,
			Header:       header,
			Folded:       folded,
			FoldedKnown:  true,
			Rows:         rows,
			CompileRows:  compileRows,
			GenesisChain: state.genesisChain,
		})
		if errors.Is(err, ErrConfigHeadUnavailable) {
			return nil, err
		}
		if err != nil {
			return nil, self.baseFork(kept, "config head: %v", err)
		}
		if facts == nil {
			facts = &ConfigHeadFacts{}
		}
		if err := CheckServiceSettings(facts.Settings); err != nil {
			return nil, self.baseFork(kept, "config head: service_settings: %v", err)
		}
	}

	next, rowsMessage, err := self.stateFromBase(state, kept, header, rows)
	if err != nil {
		return nil, self.baseFork(kept, "%v", err)
	}
	if err := self.holdHeadFacts(next.state, rowsMessage, facts); err != nil {
		return nil, self.baseFork(kept, "%v", err)
	}
	if err := self.reapplyTail(next, header.GetFoldedThrough(), kept.n, bits, true); err != nil {
		return nil, self.baseFork(kept, "%v", err)
	}
	result := next.finish()
	self.retainBase(result, rows)
	return result, nil
}

// A base entry's Signed and its header, of the one type a base carries.
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

// The records a head holds for this log's entries in [from, through], in position order, BASE entries included; false
// when this log does not keep them all.
func (self *ConfigLog) foldedRecords(from uint64, through uint64) ([]ConfigFoldRecord, bool) {
	folded := []ConfigFoldRecord{}
	for n := from; n <= through; n += 1 {
		kept := self.keptEntry(n)
		if kept == nil {
			return nil, false
		}
		folded = append(folded, configFoldRecordOf(kept))
	}
	return folded, true
}

// The record a head holds for a kept entry.
func configFoldRecordOf(kept *configKeptEntry) ConfigFoldRecord {
	kind := kept.entry.GetKind()
	record := ConfigFoldRecord{N: kept.n, TimeMs: kept.entry.GetTimeMs(), Kind: kind, Body: bytes.Clone(kept.entry.GetBody())}
	if kind == bridge.AuthEntryKindStatement || kind == bridge.AuthEntryKindBase {
		record.Id = bytes.Clone(kept.verdict.StatementId[:])
	}
	return record
}

// L(folded_through), the log-derived rows a new base's head compiles with (DESIGN-DETAILS 5.2.2): base 1's from the
// Genesis, which the log before it holds nothing of; the previous base's rows when the fold did not move; else this
// reader's state at folded_through, which StateAt serves from the previous base on (the ft rule keeps it there).
func (self *ConfigLog) foldRows(state *ConfigState, header *bridge.ProjectionHeader) (*ConfigCompileRows, error) {
	foldedThrough := header.GetFoldedThrough()
	if state.base == nil {
		return configGenesisCompileRows(state.genesis), nil
	}
	if foldedThrough == state.base.header.GetFoldedThrough() {
		rowsBytes, found := self.baseRows[[sha256.Size]byte(state.base.header.GetRowsSha256())]
		if !found {
			return nil, errors.New("the previous base's rows are not kept")
		}
		rows := &bridge.ProjectionRows{}
		if err := proto.Unmarshal(rowsBytes, rows); err != nil {
			return nil, err
		}
		return configCompileRowsFromRows(rows)
	}
	chain, ok := state.chainAt(foldedThrough)
	if !ok {
		return nil, fmt.Errorf("A_%d is not kept", foldedThrough)
	}
	folded, err := state.StateAt(&bridge.AuthPin{Version: foldedThrough, Chain: chain[:]})
	if err != nil {
		return nil, err
	}
	return ConfigCompileRowsOf(folded), nil
}

// The state a base's rows give, before the tail re-applies and before the head's facts are held: its rows replace
// previous's, its pins move on, and its proposals and replay ring are the rows', which the tail advances
// (DESIGN-DETAILS 5.2.3). Returns the builder and the rows as parsed.
func (self *ConfigLog) stateFromBase(previous *ConfigState, kept *configKeptEntry, header *bridge.ProjectionHeader, rowsBytes []byte) (*configStateBuilder, *bridge.ProjectionRows, error) {
	rows := &bridge.ProjectionRows{}
	if err := proto.Unmarshal(rowsBytes, rows); err != nil {
		return nil, nil, fmt.Errorf("rows: %w", err)
	}
	next := newConfigStateBuilder(previous, kept.n, kept.chain, kept.entry.GetTimeMs())
	state := next.state
	if err := configLoadRows(state, rows); err != nil {
		return nil, nil, err
	}
	foldedThrough := header.GetFoldedThrough()
	for i, ringEntry := range state.ring {
		if foldedThrough < ringEntry.n || configStatementWindow <= foldedThrough-ringEntry.n {
			return nil, nil, fmt.Errorf("rows: ring[%d] at %d is outside the 4,096 entries through %d", i, ringEntry.n, foldedThrough)
		}
	}
	state.previousBase = previous.base
	state.base = &configBase{n: kept.n, chain: kept.chain, timeMs: kept.entry.GetTimeMs(), header: header}
	state.threshold = header.GetThreshold()
	state.settings = configRowsSettingsOrDefault(rows.GetSettings())
	state.headSettings, state.headSettingsKnown = nil, false
	next.membersOwned, next.sidecarsOwned, next.delegationsOwned, next.keysOwned, next.proposalsOwned = true, true, true, true, true
	next.indexersOwned = true
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
	for keyId := range state.keys {
		next.keysCopied[keyId] = true
	}
	// rows whose acl part does not build are no state; the state's own acl part builds later, on first use, once the
	// tail has re-applied
	if _, err := NewAclState(state.aclRows, state); err != nil {
		return nil, nil, err
	}
	return next, rows, nil
}

// Holds what a full reader's head check found on the state a base's rows give: the head's ServiceSettings, to which
// the rows' settings must compile (DESIGN-DETAILS 5.2.3). A rows-only reader opens no head, so its head-only settings
// are unknown.
func (self *ConfigLog) holdHeadFacts(state *ConfigState, rows *bridge.ProjectionRows, facts *ConfigHeadFacts) error {
	if self.rowsOnly {
		state.headSettings, state.headSettingsKnown = nil, false
		return nil
	}
	if facts == nil {
		facts = &ConfigHeadFacts{}
	}
	if !configRowsSettingsMatch(rows.GetSettings(), facts.Settings) {
		return errors.New("rows: settings are not the config head's")
	}
	state.headSettings, state.headSettingsKnown = facts.Settings, true
	return nil
}

// Indexes a base's rows into state, refusing rows a reader cannot hold: a malformed or repeated id, an admission
// naming neither a member nor tags or both, a bad identity key, acl bytes that do not build, or a ring out of order.
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
	if err := configCheckRowsSettings(rows.GetSettings()); err != nil {
		return err
	}
	state.proposals = make(map[[sha256.Size]byte]*configProposal, len(rows.GetProposals()))
	for i, row := range rows.GetProposals() {
		if len(row.GetProposalId()) != sha256.Size {
			return fmt.Errorf("rows: proposals[%d].proposal_id", i)
		}
		proposalId := [sha256.Size]byte(row.GetProposalId())
		if state.proposals[proposalId] != nil {
			return fmt.Errorf("rows: proposals[%d] repeats a proposal", i)
		}
		statement, err := state.proposalRowStatement(row)
		if err != nil {
			return fmt.Errorf("rows: proposals[%d]: %w", i, err)
		}
		state.proposals[proposalId] = &configProposal{id: proposalId, row: row, statement: statement}
	}
	state.ring = make([]configRingEntry, 0, len(rows.GetRing()))
	for i, row := range rows.GetRing() {
		if len(row.GetStatementId()) != configRetainedIdSize {
			return fmt.Errorf("rows: ring[%d].statement_id of %d bytes", i, len(row.GetStatementId()))
		}
		if 0 < i && row.GetN() <= rows.GetRing()[i-1].GetN() {
			return fmt.Errorf("rows: ring[%d] out of position order", i)
		}
		state.ring = append(state.ring, configRingEntry{n: row.GetN(), id: [configRetainedIdSize]byte(row.GetStatementId())})
	}
	state.indexers = make(map[configIndexerKey]*bridge.IndexerRow, len(rows.GetIndexers()))
	for i, row := range rows.GetIndexers() {
		sidecarId, err := IdFromBytes(row.GetSidecarId())
		if err != nil {
			return fmt.Errorf("rows: indexers[%d].sidecar_id", i)
		}
		scope := protocol.IndexerScope(row.GetScope())
		if scope != protocol.IndexerScope_INDEXER_SCOPE_NETWORK && scope != protocol.IndexerScope_INDEXER_SCOPE_MEMBER {
			return fmt.Errorf("rows: indexers[%d].scope %d", i, row.GetScope())
		}
		key := configIndexerKey{sidecarId: sidecarId, scope: scope}
		if state.indexers[key] != nil {
			return fmt.Errorf("rows: indexers[%d] repeats a designation", i)
		}
		state.indexers[key] = row
	}
	return nil
}

// tail_verdicts' bytes for the verdicts of the entries folded_through+1.. in order: entry folded_through+1+j at bits 2j
// and 2j+1 of byte j/4, bit 0 the byte's least significant, padding bits 0, empty for no entry (DESIGN-DETAILS 5.2.2).
func configEncodeTailVerdicts(verdicts []uint8) []byte {
	if len(verdicts) == 0 {
		return nil
	}
	data := make([]byte, (2*len(verdicts)+7)/8)
	for j, verdict := range verdicts {
		data[j/4] |= (verdict & 3) << (2 * (j % 4))
	}
	return data
}

// The count verdicts tail_verdicts carries, refusing a length other than ceil(2*count/8) bytes, a padding bit set, or
// a 3 (DESIGN-DETAILS 5.2.2).
func configDecodeTailVerdicts(data []byte, count uint64) ([]uint8, error) {
	if uint64(len(data)) != (2*count+7)/8 {
		return nil, fmt.Errorf("tail_verdicts of %d bytes for %d entries", len(data), count)
	}
	verdicts := make([]uint8, count)
	for j := uint64(0); j < count; j += 1 {
		verdict := (data[j/4] >> (2 * (j % 4))) & 3
		if verdict == configTailNever {
			return nil, fmt.Errorf("tail_verdicts carries a 3 for its entry %d", j)
		}
		verdicts[j] = verdict
	}
	if used := count % 4; used != 0 && data[len(data)-1]&(byte(0xff)<<(2*used)) != 0 {
		return nil, errors.New("tail_verdicts sets a padding bit")
	}
	return verdicts, nil
}

// Whether a statement entry is an AuthorityProposal or an AuthorityCosign, the only entries a 2 may name.
func configEntryProposes(entry *bridge.AuthEntry) bool {
	if entry.GetKind() != bridge.AuthEntryKindStatement {
		return false
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		return false
	}
	switch bridge.SignedType(signed.GetType()) {
	case bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, bridge.SignedType_SIGNED_AUTHORITY_COSIGN:
		return true
	}
	return false
}

// DESIGN-DETAILS 5.2.3's rules for a base at n after previous, nil for none: folded_through is the previous base's or
// at least that base's position; at most 4,096 entries stay unfolded; and tail_verdicts covers exactly the tail, a 0
// at each BASE, a 2 only on an AuthorityProposal or AuthorityCosign, and this reader's own verdict wherever it holds
// one. Returns the tail's verdicts, entry folded_through+1+j at j.
func (self *ConfigLog) checkBaseTail(previous *configBase, header *bridge.ProjectionHeader, n uint64) ([]uint8, error) {
	foldedThrough := header.GetFoldedThrough()
	if n <= foldedThrough {
		return nil, fmt.Errorf("folded_through %d at position %d", foldedThrough, n)
	}
	if previous != nil {
		previousFoldedThrough := previous.header.GetFoldedThrough()
		if foldedThrough != previousFoldedThrough && foldedThrough < previous.n {
			return nil, fmt.Errorf("folded_through %d is neither the previous base's %d nor at or past that base at %d",
				foldedThrough, previousFoldedThrough, previous.n)
		}
	}
	tailCount := n - 1 - foldedThrough
	if configTailMax < tailCount {
		return nil, fmt.Errorf("%d entries unfolded, past %d", tailCount, configTailMax)
	}
	verdicts, err := configDecodeTailVerdicts(header.GetTailVerdicts(), tailCount)
	if err != nil {
		return nil, err
	}
	for k := foldedThrough + 1; k < n; k += 1 {
		verdict := verdicts[k-foldedThrough-1]
		kept := self.keptEntry(k)
		switch {
		case kept == nil:
			return nil, fmt.Errorf("the tail's entry %d is not kept", k)
		case kept.entry.GetKind() == bridge.AuthEntryKindBase && verdict != configTailRefused:
			return nil, fmt.Errorf("tail_verdicts carries %d for the base at %d", verdict, k)
		case verdict == configTailCompleted && !configEntryProposes(kept.entry):
			return nil, fmt.Errorf("tail_verdicts carries a completion at %d, which is no proposal or cosign", k)
		case kept.verdictHeld && verdict != kept.verdict.tailBits():
			return nil, fmt.Errorf("tail_verdicts carries %d at %d, where this reader's verdict is %d", verdict, k, kept.verdict.tailBits())
		}
	}
	return verdicts, nil
}

// DESIGN-DETAILS 5.2.4's Reapply over the tail folded_through+1..n-1 on next, by verdicts: each entry with a 1 or a 2
// applies its effect again on the state being built, a 0 and a BASE nothing, and nothing is judged, no signature, no
// header, no signer's standing, no type rule. What an effect derives from state, a row's signer, an acl statement's
// fold inputs, a proposal's kind, is recomputed on the state being rebuilt, which every verifier holds alike; the verdict
// and the completion come from verdicts alone. Each entry's effect lands at its own position. take records the
// verdicts on entries this reader held none for, as a new device takes its first base's; a dry run, api's CheckBase,
// records nothing. An error is a tail entry carried as taking effect that is no statement or tick this log reads: the
// base lied, a fork.
func (self *ConfigLog) reapplyTail(next *configStateBuilder, foldedThrough uint64, n uint64, verdicts []uint8, take bool) error {
	state := next.state
	baseN, baseChain, baseTimeMs := state.n, state.chain, state.timeMs
	defer func() {
		state.n, state.chain, state.timeMs = baseN, baseChain, baseTimeMs
	}()
	for k := foldedThrough + 1; k < n; k += 1 {
		kept := self.keptEntry(k)
		if kept == nil {
			return fmt.Errorf("the tail's entry %d is not kept", k)
		}
		verdict := verdicts[k-foldedThrough-1]
		taken := take && !kept.verdictHeld
		if taken {
			kept.verdictHeld = true
			if verdict == configTailRefused && kept.entry.GetKind() != bridge.AuthEntryKindBase {
				kept.verdict.Refusal = fmt.Errorf("%w: at its own position, as base %d's tail_verdicts carry", ErrConfigRefused, n)
			}
		}
		if verdict == configTailRefused || kept.entry.GetKind() == bridge.AuthEntryKindBase {
			continue
		}
		if len(kept.entry.GetPrevChain()) != sha256.Size {
			return fmt.Errorf("the tail's entry %d has no prev_chain", k)
		}
		// what the effect derives is judged on the state rebuilt through k-1, and the effect lands at k
		state.n, state.chain, state.timeMs = k-1, [sha256.Size]byte(kept.entry.GetPrevChain()), kept.entry.GetTimeMs()
		view := next.snapshot()
		state.n, state.chain = k, kept.chain
		switch kept.entry.GetKind() {
		case bridge.AuthEntryKindStatement:
			statement, err := self.reapplyStatement(next, view, kept, verdict)
			if err != nil {
				return err
			}
			if taken {
				kept.verdict.SignedType, kept.verdict.StatementId = statement.signedType, statement.id
				if verdict == configTailCompleted {
					kept.verdict.CompletedProposalId = configCompletedProposalId(statement)
				}
			}
		case bridge.AuthEntryKindTick:
			tick, activations, err := self.reapplyTick(next, view, kept)
			if err != nil {
				return err
			}
			if taken {
				kept.tick, kept.activations = tick, activations
			}
		default:
			return fmt.Errorf("the tail's entry %d of kind %d took effect", k, kept.entry.GetKind())
		}
	}
	return nil
}

// One tail statement's re-application by its verdict (DESIGN-DETAILS 5.2.4's Reapply): an AuthorityProposal at 2
// applies its statement with the proposer as signer, at 1 opens its row with the kind it takes on the rebuilt state;
// an AuthorityCosign at 2 applies its proposal's statement with the row's signers and the cosigner and closes the row,
// at 1 adds the cosigner; anything else applies as its type's apply says. An effect the rebuilt rows no longer allow
// ends at this base, logged, and the statement still joins the replay ring.
func (self *ConfigLog) reapplyStatement(next *configStateBuilder, view *ConfigState, kept *configKeptEntry, verdict uint8) (*configStatement, error) {
	statement, err := configParseStatementUnverified(kept.entry)
	if err != nil {
		return nil, fmt.Errorf("the tail's entry %d took effect and is no statement this log reads: %w", kept.n, err)
	}
	var effectErr error
	switch body := statement.body.(type) {
	case *protocol.AuthorityProposal:
		proposed, err := configProposedStatement(body, statement.signers, statement.n, statement.timeMs)
		if err != nil {
			effectErr = err
			break
		}
		if verdict == configTailCompleted {
			configDeriveStatement(view, proposed)
			statement.completes = proposed
		} else {
			statement.proposed = proposed
			statement.proposalKind = configReapplyProposalKind(view, statement.signers[0], proposed)
		}
		effectErr = configApplyProposal(next, statement)
	case *protocol.AuthorityCosign:
		if len(body.GetProposalId()) != sha256.Size {
			effectErr = fmt.Errorf("%w: a proposal_id of %d bytes", ErrConfigRule, len(body.GetProposalId()))
			break
		}
		proposal := next.proposal([sha256.Size]byte(body.GetProposalId()))
		if proposal == nil || proposal.closedAt != 0 {
			effectErr = fmt.Errorf("%w: the proposal is not open on the rebuilt rows", ErrConfigRule)
			break
		}
		proposed := *proposal.statement
		proposed.signers = append(slices.Clone(proposal.statement.signers), statement.signers[0])
		proposed.n, proposed.timeMs = statement.n, statement.timeMs
		if verdict == configTailCompleted {
			configDeriveStatement(view, &proposed)
			statement.completes = &proposed
		} else {
			statement.proposed = &proposed
		}
		effectErr = configApplyCosign(next, statement)
	default:
		configDeriveStatement(view, statement)
		effectErr = configApplyStatement(next, statement, true)
	}
	if effectErr != nil {
		self.log.Infof("[config]%s entry %d's effect ends at the base: %v", self.networkId, kept.n, effectErr)
	}
	next.addRing(statement.n, statement.id)
	return statement, nil
}

// One tail tick's re-application (DESIGN-DETAILS 5.2.4's Reapply): each reaped admission revoked at the tick, then
// each activated proposal open on the rebuilt state closed and its statement applied there with the row's signers,
// the window not judged again. An activation of a proposal the rebuilt rows do not hold open ends at this base.
func (self *ConfigLog) reapplyTick(next *configStateBuilder, view *ConfigState, kept *configKeptEntry) (*bridge.ApiTick, []configActivation, error) {
	tick := &bridge.ApiTick{}
	if err := proto.Unmarshal(kept.entry.GetBody(), tick); err != nil {
		return nil, nil, fmt.Errorf("the tail's tick %d took effect and does not parse: %w", kept.n, err)
	}
	activations := []configActivation{}
	for _, proposalId := range tick.GetActivatedProposalIds() {
		if len(proposalId) != sha256.Size {
			continue
		}
		proposal := next.proposal([sha256.Size]byte(proposalId))
		if proposal == nil || proposal.closedAt != 0 {
			self.log.Infof("[config]%s tick %d's activation ends at the base: no open proposal", self.networkId, kept.n)
			continue
		}
		statement := *proposal.statement
		statement.n, statement.timeMs, statement.activated = kept.n, kept.entry.GetTimeMs(), true
		configDeriveStatement(view, &statement)
		activations = append(activations, configActivation{proposalId: [sha256.Size]byte(proposalId), statement: &statement})
	}
	if err := configApplyTick(next, tick, activations); err != nil {
		self.log.Infof("[config]%s tick %d's effect ends at the base: %v", self.networkId, kept.n, err)
	}
	return tick, activations, nil
}

// A statement entry as its body says, its signers read from Signed's signer_id and key_id with no signature checked
// (§6.9's Signers): what Reapply applies, since the verdict that it took effect is the base's.
func configParseStatementUnverified(entry *bridge.AuthEntry) (*configStatement, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		return nil, err
	}
	signedType := bridge.SignedType(signed.GetType())
	purpose, ok := ConfigStatementPurpose(signedType)
	if !ok {
		return nil, fmt.Errorf("type %d", signed.GetType())
	}
	message, err := ParseConfigStatement(purpose, signedType, signed.GetBody())
	if err != nil {
		return nil, err
	}
	headerMessage, ok := message.(configHeaderMessage)
	if !ok || headerMessage.GetHeader() == nil {
		return nil, fmt.Errorf("%s carries no StatementHeader", signedType)
	}
	signer, err := configSignerOf(signed)
	if err != nil {
		return nil, err
	}
	return &configStatement{
		signedType: signedType,
		purpose:    purpose,
		body:       message,
		bodyBytes:  signed.GetBody(),
		header:     headerMessage.GetHeader(),
		id:         bridge.SignedBytesSha256(purpose, signedType, signed.GetBody()),
		signers:    []ConfigSigner{signer},
		n:          entry.GetN(),
		timeMs:     entry.GetTimeMs(),
		signed:     signed,
	}, nil
}

// The signer Signed names by its ids' lengths alone, no key looked up and no signature checked (§6.9's Signers): a
// sidecar's identity key, a member's recovery key by the hash of the key key_id carries, or a Delegation's key.
func configSignerOf(signed *bridge.Signed) (ConfigSigner, error) {
	signerIdSize, keyIdSize := len(signed.GetSignerId()), len(signed.GetKeyId())
	switch {
	case signerIdSize == len(Id{}) && keyIdSize == 0:
		return ConfigSigner{Kind: ConfigSignerSidecar, SidecarId: Id(signed.GetSignerId())}, nil
	case signerIdSize == len(Id{}) && keyIdSize == sha256.Size:
		keySha256 := sha256.Sum256(signed.GetKeyId())
		return ConfigSigner{Kind: ConfigSignerRecovery, MemberId: Id(signed.GetSignerId()), RecoveryKeySha256: keySha256[:]}, nil
	case signerIdSize == configDelegationIdByteCount && keyIdSize == sha256.Size:
		return ConfigSigner{Kind: ConfigSignerDelegation, DelegationId: bytes.Clone(signed.GetSignerId())}, nil
	}
	return ConfigSigner{}, fmt.Errorf("signer_id of %d bytes and key_id of %d", signerIdSize, keyIdSize)
}

// Recomputes on view, the state rebuilt through the entry before, what a statement's apply reads that its check
// derives: a row's signer, an acl statement's fold inputs. The check's own verdict counts for nothing here, the base's
// does: where it refuses on the rebuilt state, a row's signer falls back to the statement's first signer and an acl
// statement's inputs to what its body names (configAclBodyVerdict).
func configDeriveStatement(view *ConfigState, statement *configStatement) {
	statement.rowSigner, statement.aclVerdict = ConfigSigner{}, nil
	_ = configCheckStatement(view, statement)
	if statement.rowSigner.Kind == 0 && 0 < len(statement.signers) {
		statement.rowSigner = statement.signers[0]
	}
	if statement.signedType>>8 == 0x11 && statement.aclVerdict == nil {
		statement.aclVerdict = configAclBodyVerdict(statement)
	}
}

// An acl statement's fold inputs as its body and signers give them, for a re-application whose check refuses on the
// rebuilt rows: the signer, its first sidecar signer; an OwnerConfirm's target. What ACL's check derives from state
// beyond these is left zero, which ACL's ReapplyStatement must not need (DESIGN-DETAILS 5.7's acl_statement.go line).
func configAclBodyVerdict(statement *configStatement) *AclStatementVerdict {
	verdict := &AclStatementVerdict{}
	for _, signer := range statement.signers {
		if signer.Kind == ConfigSignerSidecar {
			verdict.Signer = signer.SidecarId
			break
		}
	}
	if confirm, ok := statement.body.(*protocol.OwnerConfirm); ok {
		if sidecarId, err := IdFromBytes(confirm.GetSidecarId()); err == nil {
			verdict.TargetId = sidecarId
		}
	}
	return verdict
}

// The kind an AuthorityProposal that took effect and stayed open takes on the rebuilt state (DESIGN-DETAILS 5.2.3: fixed
// when it takes effect, from the signer's kind, the member's AdminSet standing and whether its binding is one a void
// restored): a device's is k of n; a recovery key's is k of n for an AdminSet member, restored under a restored
// binding, and otherwise recovery-scoped, since it took effect only with self_admit off.
func configReapplyProposalKind(view *ConfigState, proposer ConfigSigner, proposed *configStatement) bridge.ProposalKind {
	if proposer.Kind != ConfigSignerRecovery {
		return bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY
	}
	if kind, err := view.recoveryProposalKind(proposer, proposed); err == nil {
		return kind
	}
	member := view.members[proposer.MemberId]
	switch {
	case member != nil && configRoleInAdminSet(member.GetRole()):
		return bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY
	case view.BindingRestored(proposer.MemberId):
		return bridge.ProposalKind_PROPOSAL_KIND_RESTORED
	}
	return bridge.ProposalKind_PROPOSAL_KIND_RECOVERY_SCOPED
}
