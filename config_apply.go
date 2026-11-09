// §7.9's apply(e): one reader's walk of the authorization log, entry by entry, from its genesis. An entry chains
// onto the reader's own pin or is a fork; a base replaces the rows (config_base.go); a statement passes its header,
// its presence row and its type's rule at S(my.n) or is refused at its position; a tick passes its content checks.
// Each entry yields the next immutable ConfigState, published with one atomic swap.
//
// The rule table holds one rule per statement type, so api's verifier and every reader reach one verdict for one
// entry: §7's 0x12xx and §17.8's 0x19xx register here from their own files, and §8.8's 0x11xx go to ACL's rules
// through configAclRules. A type with no rule is refused, so nothing passes unchecked while a rule is unbuilt, and a
// rule hook that is not wired yet refuses too.
//
// A refused statement keeps its position, its verdict and its place in the chain, and the log goes on, so every
// reader refuses it alike (FS-102). A fork stops the log: Apply refuses every later entry and keeps the evidence.
// Nothing here reads a clock: every time is an entry's own, so a verdict depends on the log alone.
//
// Apply, Retained and Fork are for one goroutine, the log's follower; State and Pin are safe for concurrent use and
// take no lock. Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The log does not continue this reader's chain: an entry at the next position that does not chain onto its pin,
	// a second A_n at a position it holds, or a base off the chain or missing a folded statement (§7.9's apply row).
	// ConfigForkError carries the evidence.
	ErrConfigFork = errors.New("config log fork")
	// The entry is further on than the next position: the entries between are missing, which is no fork.
	ErrConfigEntryAhead = errors.New("config log entry ahead of the reader")
	// The bytes are no entry of this network's log.
	ErrConfigEntryMalformed = errors.New("config log entry malformed")
	// A statement or tick refused at its position. Each refusal below wraps it.
	ErrConfigRefused = errors.New("config statement refused")
	// The header is off the chain, too old, before the retention point, expired, from another network or
	// malformed, or the id was applied among the last 4,096 entries (§7.9's replay row).
	ErrConfigReplay = fmt.Errorf("%w: replay", ErrConfigRefused)
	// The signer is no one this state knows, or the signature does not verify.
	ErrConfigSigner = fmt.Errorf("%w: signer", ErrConfigRefused)
	// The signer lacks the role the type's rule asks, or the signers lack authority (§7.9's authority row).
	ErrConfigAuthority = fmt.Errorf("%w: authority", ErrConfigRefused)
	// The body breaks its type's rule.
	ErrConfigRule = fmt.Errorf("%w: rule", ErrConfigRefused)
	// The type's rule, or a hook it needs, is not built yet: refused until it is.
	ErrConfigRuleMissing = fmt.Errorf("%w: rule not built", ErrConfigRefused)
	// A read_only device signed what D-TEAM-24 refuses from one.
	ErrConfigReadOnly = fmt.Errorf("%w: read_only", ErrConfigRefused)
	// §7.9's presence row asks for a countersignature this build cannot check yet (TEAM-M2-06).
	ErrConfigPresence = fmt.Errorf("%w: presence", ErrConfigRefused)
	// A rule reads a ServiceSettings value this reader could not open.
	ErrConfigSettingsUnknown = fmt.Errorf("%w: settings unknown", ErrConfigRefused)
)

// Evidence of a fork (§7.9's apply row): the position, what this reader holds there and what the entry presented.
type ConfigForkError struct {
	// The position.
	N uint64
	// A_N as this reader holds it, when it holds one.
	LocalChain    [sha256.Size]byte
	HasLocalChain bool
	// A_N of the entry presented, or for a base off the chain the digest it would have had.
	RemoteChain [sha256.Size]byte
	// The entry as received.
	Entry []byte
	// What did not hold, ids and positions only (I-13).
	Reason string
}

// The position and both digests, which HeadCheck's alarm carries.
func (self *ConfigForkError) Error() string {
	return fmt.Sprintf("%s at %d: %s (local %x, remote %x)", ErrConfigFork, self.N, self.Reason, self.LocalChain[:8], self.RemoteChain[:8])
}

// ErrConfigFork.
func (self *ConfigForkError) Unwrap() error {
	return ErrConfigFork
}

// What one entry came to at its position.
type ConfigVerdict struct {
	// The entry's (n, A_n).
	Pin *bridge.AuthPin
	// AuthEntry.kind.
	Kind uint32
	// A statement's type and id (its signed bytes' hash, protos-bridge-statement-id-wrapper).
	SignedType  bridge.SignedType
	StatementId [sha256.Size]byte
	// Nil when the entry took effect; else why not, wrapping ErrConfigRefused.
	Refusal error
	// The proposal this entry completed, an AuthorityProposal at k = 1 or the cosign holding the k-th counted
	// signature, whose statement takes effect here (§7.9's completion row).
	CompletedProposalId []byte
}

// Whether the entry took effect.
func (self ConfigVerdict) Accepted() bool {
	return self.Refusal == nil
}

// One statement as a rule judges it: the body as signed, its header, its signers, and the entry it takes effect at.
// For a proposal's statement the body is AuthorityProposal.statement, the signers are the proposal's and its cosigns',
// and the entry is the completing one.
type configStatement struct {
	signedType bridge.SignedType
	purpose    string
	body       proto.Message
	bodyBytes  []byte
	header     *bridge.StatementHeader
	// bridge.SignedBytesSha256 of purpose, type and bodyBytes
	id      [sha256.Size]byte
	signers []ConfigSigner
	// the entry it takes effect at
	n      uint64
	timeMs int64
	// the Signed as received; nil for a proposal's statement
	signed *bridge.Signed
	// a proposal or cosign that completed its proposal here: the proposed statement as it took effect, which a base's
	// re-application applies again rather than counting anew (§7.9's base row keeps each verdict)
	completes *configStatement
	// a proposal or cosign that left its proposal open: the proposed statement with its signers so far
	proposed *configStatement
	// the signer a row keeps as the one that did it, as the check found it: an admission's sponsor, a confirmation's
	// confirm_signer
	rowSigner ConfigSigner
	// an acl statement's check, which its apply folds and a base's re-application keeps (configAclRules)
	aclVerdict *AclStatementVerdict
}

// What every statement that enters the log begins with (§7.9's StatementHeader).
type configHeaderMessage interface {
	GetHeader() *bridge.StatementHeader
}

// One statement type's rule (§7.9): how its body parses, what it needs to take effect at a state, and what it writes.
type configStatementRule struct {
	signedType bridge.SignedType
	purpose    string
	// the body as its type; nil parses with ParseConfigStatement
	decode func(body []byte) (proto.Message, error)
	// the verdict at the state the entry lands on: nil to take effect
	check func(state *ConfigState, statement *configStatement) error
	// writes the effect on the next state; on a base's re-application an error drops the effect and keeps the verdict
	apply func(next *configStateBuilder, statement *configStatement) error
	// what the statement acts on, which never counts toward its own authority (§7.9's counted row); nil for a type
	// no AuthorityProposal may carry
	targets func(state *ConfigState, statement *configStatement) ConfigTargets
}

// The rules by type: §7's 0x12xx and §17.8's 0x19xx. Written only by init.
var configStatementRules = map[bridge.SignedType]*configStatementRule{}

// Adds a type's rule from its file's init. A second rule for a type, a type the log does not carry or a purpose
// other than the one it registers is a programming error, so it panics at init.
func registerConfigStatementRule(rule configStatementRule) {
	purpose, ok := ConfigStatementPurpose(rule.signedType)
	if !ok || purpose != rule.purpose || rule.check == nil || rule.apply == nil {
		panic(fmt.Sprintf("config statement rule for %s does not match its registration", rule.signedType))
	}
	if rule.signedType>>8 == 0x11 {
		panic(fmt.Sprintf("%s is an acl statement, which configAclRules takes", rule.signedType))
	}
	if _, found := configStatementRules[rule.signedType]; found {
		panic(fmt.Sprintf("a second config statement rule for %s", rule.signedType))
	}
	if rule.decode == nil {
		signedType := rule.signedType
		rule.decode = func(body []byte) (proto.Message, error) {
			return ParseConfigStatement(purpose, signedType, body)
		}
	}
	configStatementRules[rule.signedType] = &rule
}

// §8.8's statements, 0x11xx, which ACL's rules judge (ACL-M2-06): CheckStatement at the state the entry lands on,
// ApplyStatement's new AclRows and its effect on §7's rows, and ReapplyStatement over a new base, keeping the
// verdict while effects that depend on rows follow the new rows; and what a k-of-n proposal of one acts on, false for
// a type no proposal carries. TEAM declares this and ACL implements it (C-05), so neither waits on the other.
type configAclRules interface {
	check(state *ConfigState, statement *configStatement) error
	apply(next *configStateBuilder, statement *configStatement) error
	reapply(next *configStateBuilder, statement *configStatement) error
	targets(state *ConfigState, statement *configStatement) (ConfigTargets, bool)
}

// What judges 0x11xx statements. ACL-M2-06 replaces it from its own init.
var configAcl configAclRules = configAclRulesUnwired{}

// Refuses every acl statement until ACL's rules are wired in, so none passes unchecked.
type configAclRulesUnwired struct{}

// Refused.
func (self configAclRulesUnwired) check(state *ConfigState, statement *configStatement) error {
	return fmt.Errorf("%w: %s waits on ACL's statement rules", ErrConfigRuleMissing, statement.signedType)
}

// Refused.
func (self configAclRulesUnwired) apply(next *configStateBuilder, statement *configStatement) error {
	return fmt.Errorf("%w: %s", ErrConfigRuleMissing, statement.signedType)
}

// Refused.
func (self configAclRulesUnwired) reapply(next *configStateBuilder, statement *configStatement) error {
	return fmt.Errorf("%w: %s", ErrConfigRuleMissing, statement.signedType)
}

// None: no proposal carries an acl statement.
func (self configAclRulesUnwired) targets(state *ConfigState, statement *configStatement) (ConfigTargets, bool) {
	return ConfigTargets{}, false
}

// One authorization log as one reader walks it.
type ConfigLog struct {
	settings *ConfigLogSettings
	log      Logger

	networkId     Id
	signedGenesis []byte

	state atomic.Pointer[ConfigState]

	// entries from the retention point on, kept[i] at position keptFrom + i
	kept     []*configKeptEntry
	keptFrom uint64
	// the first 16 B of each statement id applied among the last 4,096 entries, with its entry's pin
	ringIds   map[[configRetainedIdSize]byte]configRingEntry
	ringOrder []configRingEntry
	// the rows of the current and previous bases, by rows_sha256
	baseRows map[[sha256.Size]byte][]byte
	// once set, every Apply returns it
	fork *ConfigForkError
	// a rows-only reader opens no config head (config_rows_only.go): its bases skip the head check and its settings
	// are unknown
	rowsOnly bool
	// the states StateAt serves, shared with every state this log makes (config_state_at.go)
	history *configStateHistory
}

// One retained entry and what it came to.
type configKeptEntry struct {
	n          uint64
	chain      [sha256.Size]byte
	entry      *bridge.AuthEntry
	entryBytes []byte
	verdict    ConfigVerdict
	// a statement that took effect, as a base re-applies it
	statement *configStatement
	// a tick that took effect
	tick *bridge.ApiTick
}

// One id in the ring, in position order, with the entry that carried it.
type configRingEntry struct {
	n     uint64
	chain [sha256.Size]byte
	id    [configRetainedIdSize]byte
}

// A log at S(0), from its Signed Genesis as received: A_0 = SHA-256 of those bytes, and before base 1 the genesis
// owner's device is the one config writer. The Genesis's own signature must verify under the key it names (TOFU,
// §7.9's Anchor); which genesis to trust is the caller's, from an invite's or a bundle's hash (CORE-M2-06).
func NewConfigLog(settings *ConfigLogSettings, signedGenesis []byte) (*ConfigLog, error) {
	if settings == nil {
		settings = DefaultConfigLogSettings()
	}
	genesis, err := configParseGenesis(signedGenesis)
	if err != nil {
		return nil, err
	}
	networkId, _ := IdFromBytes(genesis.GetNetworkId())
	genesisChain := bridge.GenesisChain(signedGenesis)
	self := &ConfigLog{
		settings:      settings,
		log:           loggerOrDefault(settings.Log),
		networkId:     networkId,
		signedGenesis: bytes.Clone(signedGenesis),
		keptFrom:      1,
		ringIds:       map[[configRetainedIdSize]byte]configRingEntry{},
		baseRows:      map[[sha256.Size]byte][]byte{},
	}
	self.history = newConfigStateHistory(settings, networkId, self.log)
	state := &ConfigState{
		networkId:    networkId,
		genesis:      genesis,
		genesisChain: genesisChain,
		chain:        genesisChain,
		members:      map[Id]*bridge.MemberRow{},
		sidecars:     map[Id]*bridge.SidecarRow{},
		delegations:  map[string]*bridge.DelegationRow{},
		keys:         map[string]*bridge.KeyRow{},
		proposals:    map[[sha256.Size]byte]*configProposal{},
		chains:       [][sha256.Size]byte{genesisChain},
		chainsFrom:   0,
		history:      self.history,
	}
	self.history.reset(state, nil)
	self.state.Store(state)
	return self, nil
}

// Parses and checks a Signed Genesis: its type, its ids' sizes and its signature under the key it names.
func configParseGenesis(signedGenesis []byte) (*bridge.Genesis, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedGenesis, signed); err != nil {
		return nil, fmt.Errorf("%w: genesis: %w", ErrConfigEntryMalformed, err)
	}
	message, err := ParseConfigStatement(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_GENESIS, signed.GetBody())
	if err != nil {
		return nil, fmt.Errorf("%w: genesis: %w", ErrConfigEntryMalformed, err)
	}
	genesis := message.(*bridge.Genesis)
	if len(genesis.GetNetworkId()) != len(Id{}) || len(genesis.GetConfigRepoId()) != len(Id{}) ||
		len(genesis.GetOwnerMemberId()) != len(Id{}) || len(genesis.GetOwnerSidecarId()) != len(Id{}) ||
		!configIdentityKeyValid(genesis.GetOwnerIdentityPublicKey(), "") {
		return nil, fmt.Errorf("%w: genesis fields", ErrConfigEntryMalformed)
	}
	if err := bridge.VerifySigned(signed, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_GENESIS,
		bridge.SignedKeyAlgEd25519, genesis.GetOwnerIdentityPublicKey()); err != nil {
		return nil, fmt.Errorf("%w: genesis: %w", ErrConfigEntryMalformed, err)
	}
	return genesis, nil
}

// The current S(n). Safe for concurrent use, with no lock.
func (self *ConfigLog) State() *ConfigState {
	return self.state.Load()
}

// The current (n, A_n). Safe for concurrent use, with no lock.
func (self *ConfigLog) Pin() *bridge.AuthPin {
	return self.state.Load().Pin()
}

// The fork that stopped this log, or nil.
func (self *ConfigLog) Fork() *ConfigForkError {
	return self.fork
}

// The verdict a statement would get at the next position, sequenced at timeMs, judged on the current state as §7.9's
// statement row has api verify a statement before it appends one (else 403 with the tip): Apply's judgment, with
// nothing kept and no state changed. A statement applied among the last 4,096 entries is refused here as a repeat,
// which api answers with FindStatement's entry instead. For the goroutine that applies, as Apply is.
func (self *ConfigLog) Check(signedBytes []byte, timeMs int64) ConfigVerdict {
	state := self.state.Load()
	entry := &bridge.AuthEntry{
		NetworkId: self.networkId.Bytes(),
		N:         state.n + 1,
		PrevChain: bytes.Clone(state.chain[:]),
		Kind:      bridge.AuthEntryKindStatement,
		TimeMs:    timeMs,
		Body:      signedBytes,
	}
	verdict := ConfigVerdict{Kind: bridge.AuthEntryKindStatement}
	if chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), timeMs, signedBytes); err == nil {
		verdict.Pin = &bridge.AuthPin{Version: entry.GetN(), Chain: bytes.Clone(chain[:])}
	}
	if self.fork != nil {
		verdict.Refusal = fmt.Errorf("%w: the log stopped at a fork", ErrConfigRefused)
		return verdict
	}
	statement, err := self.judgeStatement(state, entry, state.RetentionPoint())
	if statement != nil {
		verdict.SignedType, verdict.StatementId = statement.signedType, statement.id
		if err == nil && statement.completes != nil {
			verdict.CompletedProposalId = configCompletedProposalId(statement)
		}
	}
	verdict.Refusal = err
	return verdict
}

// Where a retry of the same statement landed: the position of an applied statement with this id among the last
// 4,096 entries, which api answers a retry with (§7.9's statement row). False when none.
func (self *ConfigLog) FindStatement(statementId [sha256.Size]byte) (*bridge.AuthPin, bool) {
	ringEntry, found := self.ringIds[RetainedStatementId(statementId)]
	if !found {
		return nil, false
	}
	if kept := self.keptEntry(ringEntry.n); kept != nil && kept.verdict.StatementId != statementId {
		return nil, false
	}
	return &bridge.AuthPin{Version: ringEntry.n, Chain: bytes.Clone(ringEntry.chain[:])}, true
}

// The kept entry at n, or nil.
func (self *ConfigLog) keptEntry(n uint64) *configKeptEntry {
	if n < self.keptFrom || self.keptFrom+uint64(len(self.kept)) <= n {
		return nil
	}
	return self.kept[n-self.keptFrom]
}

// Stops the log at a fork, logs it and returns its evidence.
func (self *ConfigLog) stopAtFork(fork *ConfigForkError) error {
	self.fork = fork
	self.log.Errorf("[config]%s fork at %d: %s", self.networkId, fork.N, fork.Reason)
	return fork
}

// Applies the entry at the next position, as §7.9's apply(e) says, fetching a base's rows from rowsSource, and
// returns its verdict. An entry already applied returns its kept verdict when it carries the same A_n, and is a fork
// when it does not. An error is ErrConfigFork, ErrConfigEntryAhead or ErrConfigEntryMalformed, and leaves the state
// as it was.
func (self *ConfigLog) Apply(entryBytes []byte, rowsSource ConfigRowsSource) (ConfigVerdict, error) {
	barrierKey := self.networkId.String()
	testHookBarrier("config.apply.before", barrierKey)
	defer testHookBarrier("config.apply.after", barrierKey)

	if self.fork != nil {
		return ConfigVerdict{}, self.fork
	}
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		return ConfigVerdict{}, fmt.Errorf("%w: %w", ErrConfigEntryMalformed, err)
	}
	if !bytes.Equal(entry.GetNetworkId(), self.networkId.Bytes()) {
		return ConfigVerdict{}, fmt.Errorf("%w: another network's entry", ErrConfigEntryMalformed)
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		return ConfigVerdict{}, fmt.Errorf("%w: %w", ErrConfigEntryMalformed, err)
	}

	state := self.state.Load()
	switch {
	case entry.GetN() <= state.n:
		return self.applied(state, entry, entryBytes, chain)
	case state.n+1 < entry.GetN():
		return ConfigVerdict{}, fmt.Errorf("%w: %d after %d", ErrConfigEntryAhead, entry.GetN(), state.n)
	case !bytes.Equal(entry.GetPrevChain(), state.chain[:]):
		return ConfigVerdict{}, self.stopAtFork(&ConfigForkError{
			N: entry.GetN(), RemoteChain: chain, Entry: bytes.Clone(entryBytes), Reason: "prev_chain is not this reader's A_{n-1}",
		})
	}

	var next *ConfigState
	kept := &configKeptEntry{n: entry.GetN(), chain: chain, entry: entry, entryBytes: bytes.Clone(entryBytes)}
	kept.verdict = ConfigVerdict{Pin: &bridge.AuthPin{Version: entry.GetN(), Chain: bytes.Clone(chain[:])}, Kind: entry.GetKind()}
	switch entry.GetKind() {
	case bridge.AuthEntryKindBase:
		next, err = self.applyBase(state, kept, rowsSource)
		if err != nil {
			return ConfigVerdict{}, err
		}
	case bridge.AuthEntryKindStatement:
		next = self.applyStatement(state, kept)
	case bridge.AuthEntryKindTick:
		next = self.applyTick(state, kept)
	default:
		return ConfigVerdict{}, self.stopAtFork(&ConfigForkError{
			N: entry.GetN(), RemoteChain: chain, Entry: bytes.Clone(entryBytes), Reason: fmt.Sprintf("kind %d", entry.GetKind()),
		})
	}

	if !kept.verdict.Accepted() {
		self.log.Infof("[config]%s refused entry %d (%s): %v", self.networkId, entry.GetN(), kept.verdict.SignedType, kept.verdict.Refusal)
	}
	self.keep(kept)
	testHookBarrier("config.apply", barrierKey)
	self.history.push(next, kept)
	self.state.Store(next)
	return kept.verdict, nil
}

// An entry at a position this reader passed: its kept verdict when it chains as the one applied there, a fork when it
// does not, and ErrConfigEntryMalformed when the position is before what this reader keeps.
func (self *ConfigLog) applied(state *ConfigState, entry *bridge.AuthEntry, entryBytes []byte, chain [sha256.Size]byte) (ConfigVerdict, error) {
	local, ok := state.chainAt(entry.GetN())
	if !ok {
		return ConfigVerdict{}, fmt.Errorf("%w: %d is before what this reader keeps", ErrConfigEntryMalformed, entry.GetN())
	}
	if local != chain {
		return ConfigVerdict{}, self.stopAtFork(&ConfigForkError{
			N: entry.GetN(), LocalChain: local, HasLocalChain: true, RemoteChain: chain, Entry: bytes.Clone(entryBytes),
			Reason: "a second entry at a position this reader holds",
		})
	}
	if kept := self.keptEntry(entry.GetN()); kept != nil {
		return kept.verdict, nil
	}
	return ConfigVerdict{Pin: &bridge.AuthPin{Version: entry.GetN(), Chain: bytes.Clone(chain[:])}, Kind: entry.GetKind()}, nil
}

// Keeps an applied entry and its verdict, and its id in the ring when it took effect.
func (self *ConfigLog) keep(kept *configKeptEntry) {
	if len(self.kept) == 0 {
		self.keptFrom = kept.n
	}
	self.kept = append(self.kept, kept)
	if kept.entry.GetKind() == bridge.AuthEntryKindStatement && kept.verdict.Accepted() {
		self.addRingId(kept.n, kept.chain, kept.verdict.StatementId)
	}
	self.trimRing(kept.n)
}

// Adds an applied statement's id at the entry (n, chain).
func (self *ConfigLog) addRingId(n uint64, chain [sha256.Size]byte, statementId [sha256.Size]byte) {
	ringEntry := configRingEntry{n: n, chain: chain, id: RetainedStatementId(statementId)}
	self.ringIds[ringEntry.id] = ringEntry
	self.ringOrder = append(self.ringOrder, ringEntry)
}

// Drops ids that fall out of the 4,096 entries before position n + 1.
func (self *ConfigLog) trimRing(n uint64) {
	dropCount := 0
	for dropCount < len(self.ringOrder) && configStatementWindow < n+1-self.ringOrder[dropCount].n {
		ringEntry := self.ringOrder[dropCount]
		if self.ringIds[ringEntry.id].n == ringEntry.n {
			delete(self.ringIds, ringEntry.id)
		}
		dropCount += 1
	}
	if 0 < dropCount {
		self.ringOrder = append([]configRingEntry(nil), self.ringOrder[dropCount:]...)
	}
}

// Whether a statement with this id took effect among the 4,096 entries before position n.
func (self *ConfigLog) ringHolds(n uint64, statementId [sha256.Size]byte) bool {
	ringEntry, found := self.ringIds[RetainedStatementId(statementId)]
	return found && n-ringEntry.n <= configStatementWindow
}

// A statement entry: judged at state, then applied, or refused at its position.
func (self *ConfigLog) applyStatement(state *ConfigState, kept *configKeptEntry) *ConfigState {
	statement, err := self.judgeStatement(state, kept.entry, state.RetentionPoint())
	if statement != nil {
		kept.verdict.SignedType = statement.signedType
		kept.verdict.StatementId = statement.id
	}
	if err == nil {
		next := newConfigStateBuilder(state, kept.n, kept.chain, kept.entry.GetTimeMs())
		if err = configApplyStatement(next, statement, false); err == nil {
			kept.statement = statement
			if statement.completes != nil {
				kept.verdict.CompletedProposalId = configCompletedProposalId(statement)
			}
			return next.finish()
		}
	}
	kept.verdict.Refusal = err
	return newConfigStateBuilder(state, kept.n, kept.chain, kept.entry.GetTimeMs()).finish()
}

// The id of the proposal a statement completed: its own for an AuthorityProposal, its proposal_id for a cosign.
func configCompletedProposalId(statement *configStatement) []byte {
	if cosign, ok := statement.body.(*protocol.AuthorityCosign); ok {
		return bytes.Clone(cosign.GetProposalId())
	}
	return bytes.Clone(statement.id[:])
}

// §7.9's statement row at state: the Signed parses as a type the log carries and verifies under its signer's key,
// then the header's replay rules, at no older than retentionPoint, then read_only, the presence row and the type's
// rule. Returns the statement, as far as it parsed, and nil or the refusal.
func (self *ConfigLog) judgeStatement(state *ConfigState, entry *bridge.AuthEntry, retentionPoint uint64) (*configStatement, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	signedType := bridge.SignedType(signed.GetType())
	purpose, ok := ConfigStatementPurpose(signedType)
	if !ok {
		return nil, fmt.Errorf("%w: type %d", ErrConfigRule, signed.GetType())
	}
	statement := &configStatement{
		signedType: signedType,
		purpose:    purpose,
		bodyBytes:  signed.GetBody(),
		id:         bridge.SignedBytesSha256(purpose, signedType, signed.GetBody()),
		n:          entry.GetN(),
		timeMs:     entry.GetTimeMs(),
		signed:     signed,
	}
	message, err := ParseConfigStatement(purpose, signedType, signed.GetBody())
	if err != nil {
		return statement, fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	statement.body = message
	headerMessage, ok := message.(configHeaderMessage)
	if !ok || headerMessage.GetHeader() == nil {
		return statement, fmt.Errorf("%w: %s carries no StatementHeader and rides config heads only", ErrConfigRule, signedType)
	}
	statement.header = headerMessage.GetHeader()

	signer, err := state.verifySigner(signed, purpose, signedType, entry.GetTimeMs())
	if err != nil {
		return statement, err
	}
	statement.signers = []ConfigSigner{signer}
	if err := self.checkHeader(state, statement, retentionPoint); err != nil {
		return statement, err
	}
	if err := configReadOnlyCheck(state, statement); err != nil {
		return statement, err
	}
	if err := configPresenceCheck(state, statement); err != nil {
		return statement, err
	}
	return statement, configCheckStatement(state, statement)
}

// §7.9's replay row for a statement carried at statement.n, landing on state: its network; a 16-byte nonce; at on
// this chain, within 4,096 positions of the entry and not before the retention point of the state it lands on;
// unexpired at the entry's time and expiring at most 7 days after it; and an id no statement applied among the last
// 4,096 entries had.
func (self *ConfigLog) checkHeader(state *ConfigState, statement *configStatement, retentionPoint uint64) error {
	header := statement.header
	at := header.GetAt()
	switch {
	case !bytes.Equal(header.GetNetworkId(), state.networkId.Bytes()):
		return fmt.Errorf("%w: another network's statement", ErrConfigReplay)
	case len(header.GetNonce()) != configNonceByteCount:
		return fmt.Errorf("%w: a nonce of %d bytes", ErrConfigReplay, len(header.GetNonce()))
	case at == nil || state.n < at.GetVersion():
		return fmt.Errorf("%w: at is ahead of the entry", ErrConfigReplay)
	case configStatementWindow < statement.n-at.GetVersion():
		return fmt.Errorf("%w: at is %d positions old", ErrConfigReplay, statement.n-at.GetVersion())
	case at.GetVersion() < retentionPoint:
		return fmt.Errorf("%w: at is before the retention point %d", ErrConfigReplay, retentionPoint)
	}
	chain, ok := state.chainAt(at.GetVersion())
	if !ok || !bytes.Equal(chain[:], at.GetChain()) {
		return fmt.Errorf("%w: at is off this chain", ErrConfigReplay)
	}
	switch {
	case header.GetNotAfterMs() < statement.timeMs:
		return fmt.Errorf("%w: expired", ErrConfigReplay)
	case statement.timeMs+configStatementMaxLifetimeMs < header.GetNotAfterMs():
		return fmt.Errorf("%w: not_after more than 7 days on", ErrConfigReplay)
	case self.ringHolds(statement.n, statement.id):
		return fmt.Errorf("%w: a repeat of a statement applied among the last %d entries", ErrConfigReplay, configStatementWindow)
	}
	return nil
}

// Resolves and verifies a statement's signer from Signed's signer_id and key_id (§6.9's Signers). A sidecar's
// identity key must be one this state admits or the Genesis names; a recovery key's statements are TEAM-M2-05's and
// a Delegation's TEAM-M2-04's, each refused until its rule lands.
func (self *ConfigState) verifySigner(signed *bridge.Signed, purpose string, signedType bridge.SignedType, timeMs int64) (ConfigSigner, error) {
	signerIdSize, keyIdSize := len(signed.GetSignerId()), len(signed.GetKeyId())
	switch {
	case signerIdSize == len(Id{}) && keyIdSize == 0:
		sidecarId, _ := IdFromBytes(signed.GetSignerId())
		identityKey := self.IdentityKey(sidecarId)
		if identityKey == nil {
			return ConfigSigner{}, fmt.Errorf("%w: no sidecar admitted with this id", ErrConfigSigner)
		}
		if row := self.sidecars[sidecarId]; row != nil && !configIdentityKeyValid(identityKey, row.GetIdentityAlg()) {
			return ConfigSigner{}, fmt.Errorf("%w: identity algorithm %q", ErrConfigSigner, row.GetIdentityAlg())
		}
		if err := bridge.VerifySigned(signed, purpose, signedType, bridge.SignedKeyAlgEd25519, identityKey); err != nil {
			return ConfigSigner{}, fmt.Errorf("%w: %w", ErrConfigSigner, err)
		}
		return ConfigSigner{Kind: ConfigSignerSidecar, SidecarId: sidecarId}, nil
	case signerIdSize == len(Id{}) && keyIdSize == sha256.Size:
		return ConfigSigner{}, fmt.Errorf("%w: a recovery key's statement waits on TEAM-M2-05's recovery rules", ErrConfigRuleMissing)
	case signerIdSize == configDelegationIdByteCount && keyIdSize == sha256.Size:
		return ConfigSigner{}, fmt.Errorf("%w: a Delegation's statement waits on TEAM-M2-04's delegation rule", ErrConfigRuleMissing)
	}
	return ConfigSigner{}, fmt.Errorf("%w: signer_id of %d bytes and key_id of %d", ErrConfigSigner, signerIdSize, keyIdSize)
}

// The type's rule at state: 0x11xx by ACL's rules, the rest by the table, a type with no rule refused.
func configCheckStatement(state *ConfigState, statement *configStatement) error {
	if statement.signedType>>8 == 0x11 {
		return configAcl.check(state, statement)
	}
	rule := configStatementRules[statement.signedType]
	if rule == nil {
		return fmt.Errorf("%w: no rule for %s yet", ErrConfigRuleMissing, statement.signedType)
	}
	return rule.check(state, statement)
}

// The type's effect on next. reapply is a base's re-application of a statement that took effect at its own position.
func configApplyStatement(next *configStateBuilder, statement *configStatement, reapply bool) error {
	if statement.signedType>>8 == 0x11 {
		if reapply {
			return configAcl.reapply(next, statement)
		}
		return configAcl.apply(next, statement)
	}
	rule := configStatementRules[statement.signedType]
	if rule == nil {
		return fmt.Errorf("%w: no rule for %s yet", ErrConfigRuleMissing, statement.signedType)
	}
	return rule.apply(next, statement)
}

// A tick entry (§7.9's tick row): every reaped id an ephemeral admission, each revoked at the tick; every activated
// proposal meeting Recovery's window, which TEAM-M2-05 judges, so a tick naming one is refused until it lands. A
// refused tick changes nothing.
func (self *ConfigLog) applyTick(state *ConfigState, kept *configKeptEntry) *ConfigState {
	next := newConfigStateBuilder(state, kept.n, kept.chain, kept.entry.GetTimeMs())
	tick := &bridge.ApiTick{}
	if err := proto.Unmarshal(kept.entry.GetBody(), tick); err != nil {
		kept.verdict.Refusal = fmt.Errorf("%w: tick: %w", ErrConfigRule, err)
		return next.finish()
	}
	if err := configCheckTick(state, tick); err != nil {
		kept.verdict.Refusal = err
		return next.finish()
	}
	configApplyTick(next, tick)
	kept.tick = tick
	return next.finish()
}

// The checks a tick's content passes at state.
func configCheckTick(state *ConfigState, tick *bridge.ApiTick) error {
	for _, reapedBytes := range tick.GetReapedSidecarIds() {
		sidecarId, err := IdFromBytes(reapedBytes)
		if err != nil {
			return fmt.Errorf("%w: a reaped id of %d bytes", ErrConfigRule, len(reapedBytes))
		}
		row := state.sidecars[sidecarId]
		if row == nil || !row.GetEphemeral() {
			return fmt.Errorf("%w: a reaped id names no ephemeral admission", ErrConfigRule)
		}
	}
	if 0 < len(tick.GetActivatedProposalIds()) {
		return fmt.Errorf("%w: a tick's activations wait on TEAM-M2-05's recovery window", ErrConfigRuleMissing)
	}
	return nil
}

// A tick's effect: each reaped ephemeral admission revoked at the tick's position, an already revoked one left.
func configApplyTick(next *configStateBuilder, tick *bridge.ApiTick) {
	for _, reapedBytes := range tick.GetReapedSidecarIds() {
		sidecarId, err := IdFromBytes(reapedBytes)
		if err != nil {
			continue
		}
		if row := next.sidecar(sidecarId); row != nil && row.GetRevokedAt() == 0 {
			next.sidecarForWrite(sidecarId).RevokedAt = next.state.n
		}
	}
}

// §7.9's presence row as a hook until TEAM-M2-06 checks countersignatures: a statement the row covers, signed by a
// sidecar that registered a live presence key, is refused, since nothing here can verify the countersignature it
// must carry. A statement the row does not cover, or one whose signer has no live key, passes, as the row says, and a
// recovery key's statements need none. A key counts as live unless revoked or past its not_after, so a void one
// still refuses until TEAM-M2-04 says which are void.
func configPresenceCheck(state *ConfigState, statement *configStatement) error {
	for _, signer := range statement.signers {
		if signer.Kind != ConfigSignerSidecar || !state.hasLivePresenceKey(signer.SidecarId, statement.timeMs) {
			continue
		}
		if configPresenceCovers(state, statement.signedType, statement.body, signer.SidecarId) {
			return fmt.Errorf("%w: %s needs its signer's presence countersignature, which TEAM-M2-06 checks", ErrConfigPresence, statement.signedType)
		}
	}
	return nil
}

// Whether the sidecar registered a presence key that is not revoked and whose not_after, when it has one, comes after
// timeMs (§7.9's presence row).
func (self *ConfigState) hasLivePresenceKey(sidecarId Id, timeMs int64) bool {
	for _, key := range self.keys {
		if key.GetPurpose() == bridge.KeyPurpose_KEY_PURPOSE_PRESENCE && bytes.Equal(key.GetSigner(), sidecarId.Bytes()) &&
			key.GetRevokedAt() == 0 && (key.GetNotAfter() == 0 || timeMs < key.GetNotAfter()) {
			return true
		}
	}
	return false
}

// Whether §7.9's presence row covers a statement by signer (D-TEAM-32's list): a compromise revocation and any other
// SidecarRevoke of another sidecar; a presence key's KeyRegister or KeyRevoke; a Suspend of another sidecar; every
// RecoveryVeto; a DelegationRevoke with since_n; a SidecarAdmit, AdmissionConfirm or OwnerConfirm of an untagged
// sidecar; an AdminSet change, a MemberRevoke, a RecoveryBind or RecoveryRebind; and a proposal carrying one of these
// or a cosign of such a proposal. What cannot be told apart counts as covered.
func configPresenceCovers(state *ConfigState, signedType bridge.SignedType, body proto.Message, signerId Id) bool {
	untaggedRow := func(sidecarBytes []byte) bool {
		sidecarId, err := IdFromBytes(sidecarBytes)
		if err != nil {
			return true
		}
		row := state.sidecars[sidecarId]
		return row == nil || len(row.GetTagIds()) == 0
	}
	switch message := body.(type) {
	case *bridge.SidecarRevoke:
		return message.GetReason() == bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE ||
			!bytes.Equal(message.GetSidecarId(), signerId.Bytes())
	case *protocol.KeyRegister:
		return message.GetPurpose() == bridge.KeyPurpose_KEY_PURPOSE_PRESENCE
	case *protocol.KeyRevoke:
		key := state.keys[string(message.GetKeyId())]
		return key == nil || key.GetPurpose() == bridge.KeyPurpose_KEY_PURPOSE_PRESENCE
	case *bridge.Suspend:
		return !bytes.Equal(message.GetSubject(), signerId.Bytes())
	case *protocol.RecoveryVeto, *protocol.AdminSet, *bridge.MemberRevoke, *protocol.RecoveryBind, *protocol.RecoveryRebind:
		return true
	case *protocol.DelegationRevoke:
		return message.GetSinceN() != 0
	case *protocol.SidecarAdmit:
		return len(message.GetTagIds()) == 0
	case *protocol.AdmissionConfirm:
		return untaggedRow(message.GetSidecarId())
	case *protocol.OwnerConfirm:
		return untaggedRow(message.GetSidecarId())
	case *protocol.AuthorityProposal:
		proposed, err := configProposedStatement(message, nil, 0, 0)
		return err != nil || configPresenceCovers(state, proposed.signedType, proposed.body, signerId)
	case *protocol.AuthorityCosign:
		if len(message.GetProposalId()) != sha256.Size {
			return true
		}
		proposal := state.proposals[[sha256.Size]byte(message.GetProposalId())]
		return proposal == nil || configPresenceCovers(state, proposal.statement.signedType, proposal.statement.body, signerId)
	}
	return false
}
