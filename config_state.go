// §7.9's state S(n): the newest base's rows, the statements and ticks re-applied on them, and every entry since, as
// one immutable value per position. ConfigLog (config_apply.go) builds each state from the one before it and swaps it
// in atomically, so a reader holds a state with no lock and every answer it gives stays the same.
//
// A state is what ACL's AclState reads through AclAuthView and gkm's client through GkmAuthView, and what every rule
// of config_apply.go's table judges a statement against. Its rows are ProjectionRows' (§7.9), indexed by id; its acl
// part is ACL's AclState, built on first use from the rows' AclRows with this state as its view, so the acl part of
// S(n) is a function of the log alone.
//
// Safe for concurrent use. Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §7.9's protocol constants, which every reader holds alike.
const (
	// A statement's at lies within this many positions of the entry that carries it, and its id is refused while
	// a statement applied among the last this many entries has it (§7.9's replay and retain rows).
	configStatementWindow = 4096
	// A StatementHeader's not_after_ms is at most this long after signing (§7.9).
	configStatementMaxLifetimeMs = int64(7 * 24 * 60 * 60 * 1000)
	// A base's rows are at most this many bytes (§8.8).
	configRowsMaxByteCount = 4 * 1024 * 1024
	// A StatementHeader's nonce (§7.9).
	configNonceByteCount = 16
	// A delegation_id, a SHA-256 (§10.5's d).
	configDelegationIdByteCount = sha256.Size
	// SidecarAdmit.identity_alg in v0 (§7.9).
	configIdentityAlgEd25519 = "ed25519"
)

// Tunables of a ConfigLog. §7.9's 4,096, 1,024, 4 MiB and 7 days are protocol constants, not these.
type ConfigLogSettings struct {
	// How long, by entries' times, each base's (n, A_n) stays retained after its own entry: 30 days (§7.9's retain
	// row), so a pin a gate or a peer names at a recent base still checks. The current and previous bases stay
	// whatever this says. Non-positive keeps only those two.
	BasePinRetention time.Duration
	// Where refusals and forks are logged, ids only (I-13). Nil is the leg's default: glog, or nowhere on the
	// sidecar_http leg.
	Log Logger
	// How many positions apart StateAt keeps a state between bases (config_state_at.go): S(k) at each base and at
	// every multiple of this, the rest rebuilt on demand from the nearest kept one below, at most this many minus
	// one entries a call. 64 keeps a window of two fold spans (§7.9's fold, about 2,048 entries) to some 32 states,
	// each holding its own copy of every map an entry wrote, while a rebuild stays short. One or less keeps every
	// state.
	StateAtCheckpointInterval int
	// How many rebuilt states StateAt keeps for the next call at the same position, since checks at one pin come in
	// runs, a push's or a delivery's. 8. Non-positive keeps none.
	StateAtCacheCount int
	// §16.6's spend check, which each decision a GrantActivate carries must pass at every reader and at api (ACL-M2-07).
	// Nil refuses every decision, so no GrantActivate takes effect until MCP-M3-03's check is installed here.
	AclSpendCheck AclSpendCheck
}

// §7.9's values.
func DefaultConfigLogSettings() *ConfigLogSettings {
	return &ConfigLogSettings{
		BasePinRetention:          30 * 24 * time.Hour,
		StateAtCheckpointInterval: 64,
		StateAtCacheCount:         8,
	}
}

// Who signed one statement, as §6.9's Signers and protos-bridge-recovery-key-carrier fix it from Signed's signer_id
// and key_id lengths: 16 and 0 a sidecar's identity key, 16 and 32 a member's recovery key, 32 and 32 a Delegation's.
type ConfigSignerKind int

const (
	// a sidecar's identity key: signer_id is its sidecar_id
	ConfigSignerSidecar ConfigSignerKind = iota + 1
	// a member's recovery key: signer_id is the member_id, key_id the raw Ed25519 key
	ConfigSignerRecovery
	// a Delegation's key: signer_id is the delegation_id, key_id the SHA-256 of Delegation.pubkey
	ConfigSignerDelegation
)

// One signer of a statement.
type ConfigSigner struct {
	Kind ConfigSignerKind
	// ConfigSignerSidecar's sidecar.
	SidecarId Id
	// ConfigSignerRecovery's member.
	MemberId Id
	// ConfigSignerRecovery's key hash, MemberRow.recovery_key_sha256's form.
	RecoveryKeySha256 []byte
	// ConfigSignerDelegation's delegation_id.
	DelegationId []byte
}

// The signer as rows name it in a *_signer field: a sidecar_id, a recovery key's hash or a delegation_id (§7.9's
// ProjectionRows comment).
func (self ConfigSigner) RowsSigner() []byte {
	switch self.Kind {
	case ConfigSignerSidecar:
		return self.SidecarId.Bytes()
	case ConfigSignerRecovery:
		return bytes.Clone(self.RecoveryKeySha256)
	case ConfigSignerDelegation:
		return bytes.Clone(self.DelegationId)
	}
	return nil
}

// A base a state stands on.
type configBase struct {
	n      uint64
	chain  [sha256.Size]byte
	timeMs int64
	header *bridge.ProjectionHeader
}

// One base's (n, A_n) kept for ConfigLogSettings.BasePinRetention.
type configBasePin struct {
	n      uint64
	chain  [sha256.Size]byte
	timeMs int64
}

// One AuthorityProposal as a state holds it (§7.9's proposal row, DESIGN-DETAILS 5.2.2's ProposalRow): its row, the
// statement it proposes, and once it closed, where and why. Never changed once a state holds it: a cosign or a close
// makes a new one.
type configProposal struct {
	id [sha256.Size]byte
	// what rows carry while it is open: its entry, not_after, signers with their entries, window and kind
	row *bridge.ProposalRow
	// the proposed statement, its signers the proposal's and each cosign's so far, in log order
	statement *configStatement
	// the position it closed at, 0 while open, and why
	closedAt uint64
	closed   ConfigProposalClose
}

// Whether the proposal is open at timeMs: not closed, and not past its own header's not_after, which bounds every
// cosign and activation.
func (self *configProposal) open(timeMs int64) bool {
	return self.closedAt == 0 && timeMs <= self.row.GetNotAfterMs()
}

// Whether Recovery's window holds it: a recovery key signed it, or it is a restored binding's admission.
func (self *configProposal) windowed() bool {
	return self.row.GetWindowEntry() != 0 || self.row.GetKind() == uint32(bridge.ProposalKind_PROPOSAL_KIND_RESTORED)
}

// §7.9's S(n).
type ConfigState struct {
	networkId    Id
	genesis      *bridge.Genesis
	genesisChain [sha256.Size]byte

	n      uint64
	chain  [sha256.Size]byte
	timeMs int64

	// the newest base at or below n; nil before base 1
	base *configBase
	// the base before it; nil until a second base
	previousBase *configBase

	members     map[Id]*bridge.MemberRow
	sidecars    map[Id]*bridge.SidecarRow
	delegations map[string]*bridge.DelegationRow
	keys        map[string]*bridge.KeyRow
	aclRows     *protocol.AclRows
	// the newest AdminSet's threshold as signed, 0 for the default (§7.9's authority row)
	threshold uint32
	// the ServiceSettings values every verifier judges by, from the newest base's rows; nil before base 1
	settings *bridge.ProjectionSettings
	// the ServiceSettings the base's config head holds, nil for none, and whether the head was opened to see them
	headSettings      *protocol.ServiceSettings
	headSettingsKnown bool
	proposals         map[[sha256.Size]byte]*configProposal
	// the IndexerSet designations that hold, by subject and scope
	indexers map[configIndexerKey]*bridge.IndexerRow
	// §7.9's replay row as a function of the log (DESIGN-DETAILS 5.2.3's ring): the statements that took effect
	// among the 4,096 entries through n, in position order, the oldest trimmed as n moves. Later states append to
	// the same array past this slice's end and never write inside it, so states share it, as chains.
	ring []configRingEntry

	// A_k for k from chainsFrom to n. Later states append to the same array past this slice's end and never write
	// inside it, so states share it.
	chains     [][sha256.Size]byte
	chainsFrom uint64
	basePins   []configBasePin

	// the log's kept states, which StateAt reads; nil for a state no log made
	history *configStateHistory

	aclOnce  sync.Once
	acl      *AclState
	aclError error

	// §7.9's leaves rank, built on first use
	leavesOnce  sync.Once
	leavesCache *configLeaves
}

// The network the log is of.
func (self *ConfigState) NetworkId() Id {
	return self.networkId
}

// The network's Genesis, whose owner_sidecar_id signed it (§8.5's genesis clause). The caller must not change it.
func (self *ConfigState) Genesis() *bridge.Genesis {
	return self.genesis
}

// (n, A_n).
func (self *ConfigState) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: self.n, Chain: bytes.Clone(self.chain[:])}
}

// The time api sequenced entry n at, ms since the epoch (§7.9's AuthEntry.time_ms); 0 at S(0).
func (self *ConfigState) TimeMs() int64 {
	return self.timeMs
}

// The newest base's header, or nil before base 1. The caller must not change it.
func (self *ConfigState) Base() *bridge.ProjectionHeader {
	if self.base == nil {
		return nil
	}
	return self.base.header
}

// §7.9's retention point: min(the previous base, the newest base's folded_through + 1), 0 before base 1. A statement
// whose at is before it is refused, and every reader holds A_k from it on, so equal pins give equal verdicts.
func (self *ConfigState) RetentionPoint() uint64 {
	if self.base == nil {
		return 0
	}
	point := self.base.header.GetFoldedThrough() + 1
	if self.previousBase != nil && self.previousBase.n < point {
		point = self.previousBase.n
	}
	return point
}

// A_k, false when k is above this state or before what it retains.
func (self *ConfigState) chainAt(k uint64) ([sha256.Size]byte, bool) {
	if k < self.chainsFrom || self.n < k {
		return [sha256.Size]byte{}, false
	}
	return self.chains[k-self.chainsFrom], true
}

// Whether pin lies on this state's chain, at or below its position: an A_k it retains, or a kept base's (n, A_n).
func (self *ConfigState) OnChain(pin *bridge.AuthPin) bool {
	if pin == nil || len(pin.GetChain()) != sha256.Size {
		return false
	}
	chain, ok := self.chainAt(pin.GetVersion())
	if ok {
		return bytes.Equal(chain[:], pin.GetChain())
	}
	for _, basePin := range self.basePins {
		if basePin.n == pin.GetVersion() && basePin.n <= self.n {
			return bytes.Equal(basePin.chain[:], pin.GetChain())
		}
	}
	return pin.GetVersion() == 0 && bytes.Equal(self.genesisChain[:], pin.GetChain())
}

// GkmAuthView's state at pin: StateAt's, any pin from the previous base to this state's position
// (config_state_at.go). Its errors wrap ErrGkmAuthAhead, ErrGkmAuthNotRetained and ErrGkmAuthOffChain.
func (self *ConfigState) At(pin *bridge.AuthPin) (GkmAuthView, error) {
	state, err := self.StateAt(pin)
	if err != nil {
		return nil, err
	}
	return state, nil
}

// A member's row, or nil when the id names no member of this state. The caller must not change it.
func (self *ConfigState) Member(memberId Id) *bridge.MemberRow {
	return self.members[memberId]
}

// Every member, in id order.
func (self *ConfigState) MemberIds() []Id {
	memberIds := make([]Id, 0, len(self.members))
	for memberId := range self.members {
		memberIds = append(memberIds, memberId)
	}
	slices.SortFunc(memberIds, Id.Cmp)
	return memberIds
}

// A sidecar's row, revoked tombstones included, or nil when the state never admitted it. The caller must not
// change it.
func (self *ConfigState) SidecarRow(sidecarId Id) *bridge.SidecarRow {
	return self.sidecars[sidecarId]
}

// AclAuthView's admission of a sidecar: its row and what the row says it names. Nil when the state never admitted
// it, or holds a row whose member or tag ids are malformed, which a base refuses to carry.
func (self *ConfigState) Sidecar(sidecarId Id) *AclSidecar {
	row := self.sidecars[sidecarId]
	if row == nil {
		return nil
	}
	sidecar := &AclSidecar{Row: row, Ephemeral: row.GetEphemeral()}
	if len(row.GetMemberId()) != 0 {
		memberId, err := IdFromBytes(row.GetMemberId())
		if err != nil {
			return nil
		}
		sidecar.MemberId = memberId
	}
	for _, tagBytes := range row.GetTagIds() {
		tagId, err := IdFromBytes(tagBytes)
		if err != nil {
			return nil
		}
		sidecar.TagIds = append(sidecar.TagIds, tagId)
	}
	return sidecar
}

// Every sidecar the state holds a row for, revoked tombstones included, in id order.
func (self *ConfigState) SidecarIds() []Id {
	sidecarIds := make([]Id, 0, len(self.sidecars))
	for sidecarId := range self.sidecars {
		sidecarIds = append(sidecarIds, sidecarId)
	}
	slices.SortFunc(sidecarIds, Id.Cmp)
	return sidecarIds
}

// A Delegation's row by its 32-byte delegation_id, or nil. The caller must not change it.
func (self *ConfigState) Delegation(delegationId []byte) *bridge.DelegationRow {
	return self.delegations[string(delegationId)]
}

// Every Delegation's row, ended ones included, in delegation_id order. The caller must not change them.
func (self *ConfigState) Delegations() []*bridge.DelegationRow {
	delegationIds := make([]string, 0, len(self.delegations))
	for delegationId := range self.delegations {
		delegationIds = append(delegationIds, delegationId)
	}
	slices.Sort(delegationIds)
	delegations := make([]*bridge.DelegationRow, 0, len(delegationIds))
	for _, delegationId := range delegationIds {
		delegations = append(delegations, self.delegations[delegationId])
	}
	return delegations
}

// A KeyRegister's row by its key_id, or nil. The caller must not change it.
func (self *ConfigState) RegisteredKey(keyId []byte) *bridge.KeyRow {
	return self.keys[string(keyId)]
}

// The identity key the log admits for a sidecar, by its SidecarAdmit or, for a network's first device, the
// Genesis; nil for none. A revoked sidecar keeps it, for what it signed before (§10.9's history row).
func (self *ConfigState) IdentityKey(sidecarId Id) []byte {
	if row := self.sidecars[sidecarId]; row != nil && len(row.GetIdentityPublicKey()) != 0 {
		return row.GetIdentityPublicKey()
	}
	if self.genesis != nil && bytes.Equal(self.genesis.GetOwnerSidecarId(), sidecarId.Bytes()) {
		return self.genesis.GetOwnerIdentityPublicKey()
	}
	return nil
}

// The member an untagged row names, false for a tagged row or a malformed id.
func configRowMember(row *bridge.SidecarRow) (Id, bool) {
	if row == nil || len(row.GetTagIds()) != 0 || len(row.GetMemberId()) == 0 {
		return Id{}, false
	}
	memberId, err := IdFromBytes(row.GetMemberId())
	return memberId, err == nil
}

// Whether the row is a member device: untagged and not ephemeral (§7.9's leaves row).
func configRowMemberDevice(row *bridge.SidecarRow) bool {
	_, untagged := configRowMember(row)
	return untagged && !row.GetEphemeral()
}

// Whether the row carries the read_only capability (D-TEAM-24).
func configRowReadOnly(row *bridge.SidecarRow) bool {
	return row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0
}

// Whether a member's role is one of the AdminSet's four, which sign config records (§7.5).
func configRoleInAdminSet(role bridge.MemberRole) bool {
	switch role {
	case bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN,
		bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN, bridge.MemberRole_MEMBER_ROLE_IT_ADMIN:
		return true
	}
	return false
}

// The row of a sidecar that may sign at timeMs: admitted, not revoked or parked, its not_after unpassed, and an
// untagged one's member still a member.
func (self *ConfigState) standingSidecar(sidecarId Id, timeMs int64) (*bridge.SidecarRow, bool) {
	row := self.sidecars[sidecarId]
	if row == nil || row.GetRevokedAt() != 0 || row.GetParkedAt() != 0 {
		return nil, false
	}
	if row.GetNotAfter() != 0 && row.GetNotAfter() <= timeMs {
		return nil, false
	}
	if memberId, untagged := configRowMember(row); untagged {
		if self.members[memberId] == nil {
			return nil, false
		}
	} else if len(row.GetTagIds()) == 0 {
		return nil, false
	}
	return row, true
}

// Whether the sidecar writes config heads: an AdminSet member's member device that is not read_only, standing
// (§7.9's Repo paragraph, §8.8). Before base 1 the genesis owner's device alone, which signs base 1 (§7.9's
// bootstrap).
func (self *ConfigState) IsConfigWriter(sidecarId Id) bool {
	if self.base == nil {
		return self.genesis != nil && bytes.Equal(self.genesis.GetOwnerSidecarId(), sidecarId.Bytes())
	}
	row, standing := self.standingSidecar(sidecarId, self.timeMs)
	if !standing || !configRowMemberDevice(row) || configRowReadOnly(row) {
		return false
	}
	memberId, _ := configRowMember(row)
	return configRoleInAdminSet(self.members[memberId].GetRole())
}

// Whether §7.9's compromise cascade, or a leaked bundle's DelegationRevoke, parks the sidecar now, as its row's
// parked_at says (config_cascade.go): parked until a confirmation from outside P lifts it.
func (self *ConfigState) Parked(sidecarId Id) bool {
	row := self.sidecars[sidecarId]
	return row != nil && row.GetParkedAt() != 0
}

// A tagged sidecar's sponsor, its admitting member or the one an admin's SponsorSet names (owner decision 83), and
// false once that member is removed, when autogroup:admin stands in, or for an untagged sidecar.
func (self *ConfigState) Sponsor(sidecarId Id) (Id, bool) {
	row := self.sidecars[sidecarId]
	if row == nil || len(row.GetTagIds()) == 0 || len(row.GetSponsor()) == 0 {
		return Id{}, false
	}
	sponsorId, err := IdFromBytes(row.GetSponsor())
	if err != nil || self.members[sponsorId] == nil {
		return Id{}, false
	}
	return sponsorId, true
}

// The acl part of this state: ACL's AclState over the rows' AclRows with this state as its view, built once on first
// use. An error when the rows do not build, which a base refuses before any state holds them.
func (self *ConfigState) Acl() (*AclState, error) {
	self.aclOnce.Do(func() {
		rows := self.aclRows
		if rows == nil {
			rows = &protocol.AclRows{}
		}
		self.acl, self.aclError = NewAclState(rows, self)
	})
	return self.acl, self.aclError
}

// §8.8's row of a repo, holders_shrunk_at among its fields; nil for a repo this state does not hold.
func (self *ConfigState) Repo(repoId Id) *protocol.AclRepo {
	acl, err := self.Acl()
	if err != nil {
		return nil
	}
	return acl.Repo(repoId)
}

// §8.12's RepoReaders at this state's time: every sidecar §8.6 lets read the repo.
func (self *ConfigState) RepoReaders(repoId Id) []Id {
	acl, err := self.Acl()
	if err != nil {
		return nil
	}
	return acl.RepoReaders(repoId, time.UnixMilli(self.timeMs))
}

// Every sidecar §8.6 lets write the repo at this state's time.
func (self *ConfigState) RepoWriters(repoId Id) []Id {
	acl, err := self.Acl()
	if err != nil {
		return nil
	}
	return acl.RepoWriters(repoId, time.UnixMilli(self.timeMs))
}

// §8.12's RepoReaders at this state and the time given, which §10.5's KeyHolders(R, S, t) reads.
func (self *ConfigState) RepoReadersAt(repoId Id, at time.Time) []Id {
	acl, err := self.Acl()
	if err != nil {
		return nil
	}
	return acl.RepoReaders(repoId, at)
}

// The repos a read, write or admin grant naming one of the atoms reads at the time given: ACL's part of §10.5's
// reach(d).
func (self *ConfigState) ReposGrantedToAtoms(atoms []Id, at time.Time) []Id {
	acl, err := self.Acl()
	if err != nil {
		return nil
	}
	return acl.ReposGrantedToAtoms(atoms, at)
}

// Whether an active Suspend names the subject (§8.8), as the acl part folds them.
func (self *ConfigState) Suspended(subjectId Id) bool {
	acl, err := self.Acl()
	return err == nil && acl.Suspended(subjectId)
}

// The state's rows in ProjectionRows' form, each list in id order and acl deterministically encoded, so two states
// that hold the same rows give the same bytes. Rows that compile a config head are TEAM-M2-08's
// CompileProjectionRows; these are what this state holds.
func (self *ConfigState) Rows() *bridge.ProjectionRows {
	rows := &bridge.ProjectionRows{}
	for _, memberId := range self.MemberIds() {
		rows.Members = append(rows.Members, proto.Clone(self.members[memberId]).(*bridge.MemberRow))
	}
	for _, sidecarId := range self.SidecarIds() {
		rows.Sidecars = append(rows.Sidecars, proto.Clone(self.sidecars[sidecarId]).(*bridge.SidecarRow))
	}
	delegationIds := make([]string, 0, len(self.delegations))
	for delegationId := range self.delegations {
		delegationIds = append(delegationIds, delegationId)
	}
	slices.Sort(delegationIds)
	for _, delegationId := range delegationIds {
		rows.Delegations = append(rows.Delegations, proto.Clone(self.delegations[delegationId]).(*bridge.DelegationRow))
	}
	keyIds := make([]string, 0, len(self.keys))
	for keyId := range self.keys {
		keyIds = append(keyIds, keyId)
	}
	slices.Sort(keyIds)
	for _, keyId := range keyIds {
		rows.RegisteredKeys = append(rows.RegisteredKeys, proto.Clone(self.keys[keyId]).(*bridge.KeyRow))
	}
	if self.aclRows != nil {
		aclBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(self.aclRows)
		if err == nil {
			rows.Acl = aclBytes
		}
	}
	rows.Settings = proto.Clone(self.Settings()).(*bridge.ProjectionSettings)
	rows.Proposals = self.openProposalRows()
	rows.Ring = self.ringRows()
	for _, key := range self.indexerKeys() {
		rows.Indexers = append(rows.Indexers, proto.Clone(self.indexers[key]).(*bridge.IndexerRow))
	}
	return rows
}

// The replay ring as rows carry it at this state's position: each statement that took effect among the 4,096 entries
// through n, in position order (DESIGN-DETAILS 5.2.2's RingRow).
func (self *ConfigState) ringRows() []*bridge.RingRow {
	rows := []*bridge.RingRow{}
	for _, ringEntry := range self.ring {
		if ringEntry.n <= self.n && self.n-ringEntry.n < configStatementWindow {
			rows = append(rows, &bridge.RingRow{StatementId: bytes.Clone(ringEntry.id[:]), N: ringEntry.n})
		}
	}
	return rows
}

// Whether a statement with this id took effect among the 4,096 entries before position n (§7.9's replay row): the
// ring holds only what took effect, so a refused statement resubmitted is judged anew.
func (self *ConfigState) ringHolds(n uint64, statementId [sha256.Size]byte) bool {
	_, found := self.ringFind(n, statementId)
	return found
}

// The position of the newest statement with this id that took effect among the 4,096 entries before position n.
func (self *ConfigState) ringFind(n uint64, statementId [sha256.Size]byte) (uint64, bool) {
	id := RetainedStatementId(statementId)
	for i := len(self.ring) - 1; 0 <= i; i -= 1 {
		ringEntry := self.ring[i]
		if n <= ringEntry.n {
			continue
		}
		if configStatementWindow < n-ringEntry.n {
			break
		}
		if ringEntry.id == id {
			return ringEntry.n, true
		}
	}
	return 0, false
}

// Every proposal this state holds, closed ones included, in id order.
func (self *ConfigState) proposalIds() [][sha256.Size]byte {
	proposalIds := make([][sha256.Size]byte, 0, len(self.proposals))
	for proposalId := range self.proposals {
		proposalIds = append(proposalIds, proposalId)
	}
	slices.SortFunc(proposalIds, func(a [sha256.Size]byte, b [sha256.Size]byte) int {
		return bytes.Compare(a[:], b[:])
	})
	return proposalIds
}

// The open proposals' ids at this state's time, in id order (§7.9's proposal row).
func (self *ConfigState) OpenProposalIds() [][]byte {
	proposalIds := [][]byte{}
	for _, proposalId := range self.proposalIds() {
		if self.proposals[proposalId].open(self.timeMs) {
			proposalIds = append(proposalIds, bytes.Clone(proposalId[:]))
		}
	}
	return proposalIds
}

// The rows of the proposals open at this state's time, in id order, cloned: what rows at this position carry.
func (self *ConfigState) openProposalRows() []*bridge.ProposalRow {
	rows := []*bridge.ProposalRow{}
	for _, proposalId := range self.proposalIds() {
		if proposal := self.proposals[proposalId]; proposal.open(self.timeMs) {
			rows = append(rows, proto.Clone(proposal.row).(*bridge.ProposalRow))
		}
	}
	return rows
}

// Checks an Ed25519 identity key's form, as a SidecarAdmit or a Genesis carries it.
func configIdentityKeyValid(identityKey []byte, identityAlg string) bool {
	return len(identityKey) == ed25519.PublicKeySize && (identityAlg == "" || identityAlg == configIdentityAlgEd25519)
}

// A state being built from the one before it: each map is copied on its first write and each row on its own, so the
// earlier state, which readers may hold, never changes. finish publishes nothing; ConfigLog swaps the result in.
type configStateBuilder struct {
	state *ConfigState

	membersOwned     bool
	sidecarsOwned    bool
	delegationsOwned bool
	keysOwned        bool
	proposalsOwned   bool
	indexersOwned    bool
	// rows this builder already copied, so a second write changes the copy
	membersCopied     map[Id]bool
	sidecarsCopied    map[Id]bool
	delegationsCopied map[string]bool
	keysCopied        map[string]bool
}

// A new state sharing every field of state but its acl part, which builds again on first use.
func configCopyState(state *ConfigState) *ConfigState {
	return &ConfigState{
		networkId:         state.networkId,
		genesis:           state.genesis,
		genesisChain:      state.genesisChain,
		n:                 state.n,
		chain:             state.chain,
		timeMs:            state.timeMs,
		base:              state.base,
		previousBase:      state.previousBase,
		members:           state.members,
		sidecars:          state.sidecars,
		delegations:       state.delegations,
		keys:              state.keys,
		aclRows:           state.aclRows,
		threshold:         state.threshold,
		settings:          state.settings,
		headSettings:      state.headSettings,
		headSettingsKnown: state.headSettingsKnown,
		proposals:         state.proposals,
		indexers:          state.indexers,
		ring:              state.ring,
		chains:            state.chains,
		chainsFrom:        state.chainsFrom,
		basePins:          state.basePins,
		history:           state.history,
	}
}

// The state at entry n, starting as previous's rows with n's pin, its chain appended.
func newConfigStateBuilder(previous *ConfigState, n uint64, chain [sha256.Size]byte, timeMs int64) *configStateBuilder {
	state := configCopyState(previous)
	state.n, state.chain, state.timeMs = n, chain, timeMs
	state.chains = append(previous.chains, chain)
	return &configStateBuilder{
		state:             state,
		membersCopied:     map[Id]bool{},
		sidecarsCopied:    map[Id]bool{},
		delegationsCopied: map[string]bool{},
		keysCopied:        map[string]bool{},
	}
}

// An immutable state holding the builder's rows so far, to judge the next entry by. The builder then copies each map
// and row again on its next write, so the snapshot never changes.
func (self *configStateBuilder) snapshot() *ConfigState {
	snapshot := configCopyState(self.state)
	self.membersOwned, self.sidecarsOwned, self.delegationsOwned, self.keysOwned, self.proposalsOwned = false, false, false, false, false
	self.indexersOwned = false
	clear(self.membersCopied)
	clear(self.sidecarsCopied)
	clear(self.delegationsCopied)
	clear(self.keysCopied)
	return snapshot
}

// A member's row as the state being built holds it. The caller must not change it.
func (self *configStateBuilder) member(memberId Id) *bridge.MemberRow {
	return self.state.members[memberId]
}

// A member's row to change, nil when there is none.
func (self *configStateBuilder) memberForWrite(memberId Id) *bridge.MemberRow {
	row := self.state.members[memberId]
	if row == nil {
		return nil
	}
	if !self.membersCopied[memberId] {
		row = proto.Clone(row).(*bridge.MemberRow)
		self.putMember(memberId, row)
	}
	return row
}

// Sets a member's row, which the builder then owns.
func (self *configStateBuilder) putMember(memberId Id, row *bridge.MemberRow) {
	if !self.membersOwned {
		self.state.members = configCloneMap(self.state.members)
		self.membersOwned = true
	}
	self.state.members[memberId] = row
	self.membersCopied[memberId] = true
}

// Removes a member's row.
func (self *configStateBuilder) deleteMember(memberId Id) {
	if !self.membersOwned {
		self.state.members = configCloneMap(self.state.members)
		self.membersOwned = true
	}
	delete(self.state.members, memberId)
}

// A sidecar's row as the state being built holds it. The caller must not change it.
func (self *configStateBuilder) sidecar(sidecarId Id) *bridge.SidecarRow {
	return self.state.sidecars[sidecarId]
}

// A sidecar's row to change, nil when there is none.
func (self *configStateBuilder) sidecarForWrite(sidecarId Id) *bridge.SidecarRow {
	row := self.state.sidecars[sidecarId]
	if row == nil {
		return nil
	}
	if !self.sidecarsCopied[sidecarId] {
		row = proto.Clone(row).(*bridge.SidecarRow)
		self.putSidecar(sidecarId, row)
	}
	return row
}

// Sets a sidecar's row, which the builder then owns.
func (self *configStateBuilder) putSidecar(sidecarId Id, row *bridge.SidecarRow) {
	if !self.sidecarsOwned {
		self.state.sidecars = configCloneMap(self.state.sidecars)
		self.sidecarsOwned = true
	}
	self.state.sidecars[sidecarId] = row
	self.sidecarsCopied[sidecarId] = true
}

// Sets a new Delegation's row, which the builder then owns.
func (self *configStateBuilder) putDelegation(row *bridge.DelegationRow) {
	if !self.delegationsOwned {
		self.state.delegations = configCloneMap(self.state.delegations)
		self.delegationsOwned = true
	}
	key := string(row.GetDelegationId())
	self.state.delegations[key] = row
	self.delegationsCopied[key] = true
}

// A Delegation's row to change, nil when there is none.
func (self *configStateBuilder) delegationForWrite(delegationId []byte) *bridge.DelegationRow {
	key := string(delegationId)
	row := self.state.delegations[key]
	if row == nil {
		return nil
	}
	if !self.delegationsCopied[key] {
		if !self.delegationsOwned {
			self.state.delegations = configCloneMap(self.state.delegations)
			self.delegationsOwned = true
		}
		row = proto.Clone(row).(*bridge.DelegationRow)
		self.state.delegations[key] = row
		self.delegationsCopied[key] = true
	}
	return row
}

// Sets a new key's row, which the builder then owns.
func (self *configStateBuilder) putKey(row *bridge.KeyRow) {
	if !self.keysOwned {
		self.state.keys = configCloneMap(self.state.keys)
		self.keysOwned = true
	}
	key := string(row.GetKeyId())
	self.state.keys[key] = row
	self.keysCopied[key] = true
}

// A key's row to change, nil when there is none.
func (self *configStateBuilder) keyForWrite(keyId []byte) *bridge.KeyRow {
	key := string(keyId)
	row := self.state.keys[key]
	if row == nil {
		return nil
	}
	if !self.keysCopied[key] {
		row = proto.Clone(row).(*bridge.KeyRow)
		self.putKey(row)
	}
	return row
}

// Sets the designation of a subject at a scope, or removes it for nil.
func (self *configStateBuilder) putIndexer(key configIndexerKey, row *bridge.IndexerRow) {
	if !self.indexersOwned {
		self.state.indexers = configCloneMap(self.state.indexers)
		self.indexersOwned = true
	}
	if row == nil {
		delete(self.state.indexers, key)
		return
	}
	self.state.indexers[key] = row
}

// A proposal, open or closed, or nil.
func (self *configStateBuilder) proposal(proposalId [sha256.Size]byte) *configProposal {
	return self.state.proposals[proposalId]
}

// Sets a proposal.
func (self *configStateBuilder) putProposal(proposal *configProposal) {
	if !self.proposalsOwned {
		self.state.proposals = configCloneMap(self.state.proposals)
		self.proposalsOwned = true
	}
	self.state.proposals[proposal.id] = proposal
}

// Closes an open proposal at n: it stays held, with where and why, and leaves rows (DESIGN-DETAILS 5.2.3).
func (self *configStateBuilder) closeProposal(proposalId [sha256.Size]byte, n uint64, reason ConfigProposalClose) {
	proposal := self.state.proposals[proposalId]
	if proposal == nil || proposal.closedAt != 0 {
		return
	}
	closed := *proposal
	closed.closedAt, closed.closed = n, reason
	self.putProposal(&closed)
}

// Sets the AclRows, which ACL's statement rules write (configAclRules).
func (self *configStateBuilder) setAclRows(rows *protocol.AclRows) {
	self.state.aclRows = rows
}

// Adds a statement that took effect at n to the replay ring, dropping the ids that fall out of the 4,096 entries
// before position n + 1. Appends past the shared array's end, as chains do: a state is built from the one before it
// by one builder at a time, and a rebuild starts from a slice whose capacity ends where it does.
func (self *configStateBuilder) addRing(n uint64, statementId [sha256.Size]byte) {
	ring := append(self.state.ring, configRingEntry{n: n, id: RetainedStatementId(statementId)})
	dropCount := 0
	for dropCount < len(ring) && configStatementWindow < n+1-ring[dropCount].n {
		dropCount += 1
	}
	self.state.ring = ring[dropCount:]
}

// The built state, which the builder must not change afterward.
func (self *configStateBuilder) finish() *ConfigState {
	state := self.state
	self.state = nil
	return state
}

// A shallow copy of a map, the rows shared until each is copied on write.
func configCloneMap[K comparable, V any](values map[K]V) map[K]V {
	cloned := make(map[K]V, len(values)+1)
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
