// The bridge compiler (§17.8, DESIGN-DETAILS 12.2.4; BRIDGE-M4-16): a pure function from the state at a pin, the head
// that pin's base names, the unfolded bridge statements with their verdicts, the generation keys and the host's local
// facts to the BridgeState the host's device role enforces. It reads no clock, no network and no random source, ranges
// over no Go map, and marshals deterministically, so two compilers given the same inputs return the same bytes, on a
// daemon and in a VPN component alike (CompileEqual).
//
//	1 block    ReadBridgeBlock: a refused block keeps the previous and alarms block_refused; none yet compiles no
//	           address and no entry
//	2 reach    one pass over the rows' sidecars in sidecar_id order, each standing X other than S: what reaches S
//	           (in), what S reaches (out) and what S routes or exits through (via), with ACL-M2-17's enumerators
//	3-6 ledger OpenBridgeLedger over the head's ledger files, read once each through the view, and the unfolded
//	           statements with the keys held; past UnfoldedBodyMaxByteCount it refuses with ledger_over_budget
//	7 build    S's addresses; the sender's entries, links and egress; S's maps and served routes in force; the
//	           subjects with their rows
//	8 state    BridgeState at the pin, its names, identities and listeners
//	9 digest   SHA-256 of the state's deterministic marshal
//
// What the compile needs from a server, a target's binding and a subject's client ids, it reads from
// BridgeCompileLocal.Bindings and names in Waits when absent; a body whose generation is not held is pending and named
// too. A link, a subject's clients or an exit with no binding is left out and fails closed: an entry whose links all
// wait still owns its range and rejects, never falling to the default route. Every row the compile writes is one the
// device role's ParseBridgeRules takes, since a row it refuses refuses the whole state: a map or route that would
// not parse is voided here with an alarm instead.
//
// Deferred to the review phase, as BRIDGE-M4-23's ledger was drafted: the ledger is opened from rows decoded into
// memory, so a compile holds the ledger rather than only 12.2.4's wanted rows (CompileBounded); shares and their signers
// are BRIDGE-M6-03's and -04's.
//
// testHookSecret runs where a body's key derives, inside OpenConfigBody. On every leg, the ios_extension legs'
// included (DESIGN-DETAILS 4.7), with no connect import.

package sidecar

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The compile could not build a state: the view holds no state, the ledger's files do not verify, or the unfolded
// bodies pass their budget. The state in force stands.
var ErrBridgeCompileRefused = errors.New("bridge compile refused")

// What the compile reads of the config (DESIGN-DETAILS 12.2.4). A daemon backs it with its ConfigClient's state and the
// head its base names; a VPN component with the Forwarder's rows-only log, its opened head and its sealed store.
type BridgeConfigView interface {
	// S(n): the pin, the log's time, the rows' sidecars, members and Delegations.
	State() *ConfigState
	// NewAclState(rows.acl, State()), built once by the caller.
	Acl() *AclState
	// The sealed policy's CIDRs and ports (§8.6); nil with no document, or before the head's policy is compiled.
	AclLocal() *AclLocalPolicy
	// The head S(n)'s base names, without its folds: the block, the names and the ledger's manifest. Nil before base 1.
	Head() *ConfigHead
	// A ledger file the head's manifest names, streamed: rows in file order, its bytes hashed to the manifest's. Nil and
	// no error for a path the head holds no file at. The only way the compile reads the ledger's rows.
	LedgerFile(path string) (BridgeLedgerFileReader, error)
	// The config repo's key of a generation, nil for one not held.
	RepoKeyAt(generation uint64) *EvsRepoKey
}

// What a compile waits for.
type BridgeCompileWaitKind string

const (
	// A body sealed to a generation not held: Generation.
	BridgeCompileWaitGeneration BridgeCompileWaitKind = "generation"
	// A sidecar's verified binding: SidecarId.
	BridgeCompileWaitBinding BridgeCompileWaitKind = "binding"
)

// One thing the compile lacked, which the component fetches before it compiles again.
type BridgeCompileWait struct {
	Kind       BridgeCompileWaitKind
	Generation uint64
	SidecarId  Id
}

// One bridge_alarm the compile or the component raises.
type BridgeAlarm struct {
	Reason SidecarBridgeAlarm
	// The log position it concerns, 0 for none.
	N uint64
	// The sidecar it concerns, zero for none.
	SidecarId Id
	// What failed, in words that carry no prefix, address, name or key (I-13).
	Detail string
}

// One compile's output.
type BridgeCompiled struct {
	// Nil when the compile refused, beside its error.
	State *bridge.BridgeState
	// SHA-256 of State's deterministic marshal (BridgeStateDigest).
	Digest [sha256.Size]byte
	// What it lacked, in kind, generation and sidecar order.
	Waits []BridgeCompileWait
	// What it alarms on, in the order found.
	Alarms []BridgeAlarm
	// The block in force, the next compile's PreviousBlock; the previous one when this one was refused.
	Block *bridge.BridgeBlock
	// Every sidecar the state names in a link, an entry's or an exit's, ascending: the targets
	// Sidecar.SignWindowDelegation signs for.
	LinkTargets []Id
}

// SHA-256 of a state's deterministic marshal, which `ur bridge` shows and two compiles of one input share.
func BridgeStateDigest(state *bridge.BridgeState) ([sha256.Size]byte, error) {
	stateBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(state)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(stateBytes), nil
}

// The Pending that anchors a device role to the network the state is of (legacy -> pending, §18.6): the network, A_0,
// and the sidecar's id and identity key. Nil for a nil state or identity.
func CompileBridgePending(state *ConfigState, identity *SidecarIdentity) *bridge.Pending {
	if state == nil || identity == nil {
		return nil
	}
	return &bridge.Pending{
		NetworkId:         state.NetworkId().Bytes(),
		GenesisSha256:     bytes.Clone(state.genesisChain[:]),
		SidecarId:         identity.SidecarId.Bytes(),
		IdentityPublicKey: bytes.Clone(identity.IdentityPublicKey),
	}
}

// A view over a state and the head its base names, both held whole: a daemon's ConfigClient backs it so, and tests do.
// Its ledger files stream from the head's bytes, each hashed against the head's manifest.
func NewBridgeConfigView(state *ConfigState, head *ConfigHead, aclLocal *AclLocalPolicy, repoKeyAt func(generation uint64) *EvsRepoKey, settings *BridgeLedgerSettings) (BridgeConfigView, error) {
	if state == nil {
		return nil, fmt.Errorf("%w: no state", ErrBridgeCompileRefused)
	}
	acl, err := state.Acl()
	if err != nil {
		return nil, err
	}
	view := &bridgeHeldConfigView{state: state, acl: acl, aclLocal: aclLocal, head: head, repoKeyAt: repoKeyAt}
	if head != nil {
		rows, err := NewBridgeLedgerHeadRows(head, settings)
		if err != nil {
			return nil, err
		}
		view.rows = rows
	}
	return view, nil
}

// NewBridgeConfigView's view.
type bridgeHeldConfigView struct {
	state     *ConfigState
	acl       *AclState
	aclLocal  *AclLocalPolicy
	head      *ConfigHead
	rows      BridgeLedgerRows
	repoKeyAt func(generation uint64) *EvsRepoKey
}

func (self *bridgeHeldConfigView) State() *ConfigState       { return self.state }
func (self *bridgeHeldConfigView) Acl() *AclState            { return self.acl }
func (self *bridgeHeldConfigView) AclLocal() *AclLocalPolicy { return self.aclLocal }
func (self *bridgeHeldConfigView) Head() *ConfigHead         { return self.head }
func (self *bridgeHeldConfigView) RepoKeyAt(generation uint64) *EvsRepoKey {
	if self.repoKeyAt == nil {
		return nil
	}
	return self.repoKeyAt(generation)
}

func (self *bridgeHeldConfigView) LedgerFile(path string) (BridgeLedgerFileReader, error) {
	if self.rows == nil {
		return nil, nil
	}
	return self.rows.LedgerFile(path)
}

// The head's ledger as the compile reads it: the manifest from the head, held to the checks a reader holds it to, and
// each file through the view.
type bridgeCompileLedgerRows struct {
	view          BridgeConfigView
	manifest      *protocol.BridgeLedgerManifest
	foldedThrough uint64
	named         []string
}

// The head's ledger rows, or none before base 1. A manifest that does not parse, names another format, fold or shard
// width, or names a file out of order or of no ledger path, is no ledger.
func newBridgeCompileLedgerRows(view BridgeConfigView, head *ConfigHead) (*bridgeCompileLedgerRows, error) {
	rows := &bridgeCompileLedgerRows{view: view}
	if head == nil {
		return rows, nil
	}
	rows.foldedThrough = head.FoldedThrough()
	manifestBytes := head.File(ConfigHeadBridgeLedgerManifestPath)
	if manifestBytes == nil {
		return rows, nil
	}
	manifest := &protocol.BridgeLedgerManifest{}
	if err := proto.Unmarshal(manifestBytes, manifest); err != nil {
		return nil, fmt.Errorf("%w: manifest: %w", ErrBridgeLedgerMalformed, err)
	}
	switch {
	case bridgeLedgerUnknownFields(manifest):
		return nil, fmt.Errorf("%w: a manifest with a field this build cannot name", ErrBridgeLedgerMalformed)
	case manifest.GetFormat() != bridgeLedgerFormat:
		return nil, fmt.Errorf("%w: format %d", ErrBridgeLedgerMalformed, manifest.GetFormat())
	case manifest.GetFoldedThrough() != head.FoldedThrough():
		return nil, fmt.Errorf("%w: a manifest through %d in a head folded through %d", ErrBridgeLedgerMalformed, manifest.GetFoldedThrough(), head.FoldedThrough())
	case manifest.GetRuleShardBits() != bridgeLedgerShardBitsNarrow && manifest.GetRuleShardBits() != bridgeLedgerShardBitsWide:
		return nil, fmt.Errorf("%w: rule shards of %d bits", ErrBridgeLedgerMalformed, manifest.GetRuleShardBits())
	}
	for i, file := range manifest.GetFiles() {
		path := file.GetPath()
		if 0 < i && path <= manifest.GetFiles()[i-1].GetPath() {
			return nil, fmt.Errorf("%w: files out of path order", ErrBridgeLedgerMalformed)
		}
		if bridgeLedgerRowOf(path) == nil || !configHeadPathKnown(path) || len(file.GetSha256()) != sha256.Size || file.GetRowCount() == 0 {
			return nil, fmt.Errorf("%w: a file the manifest cannot name", ErrBridgeLedgerMalformed)
		}
		if shard, ok := strings.CutPrefix(path, ConfigHeadBridgeLedgerRulesPrefix); ok && strings.Contains(shard, "/") != (manifest.GetRuleShardBits() == bridgeLedgerShardBitsWide) {
			return nil, fmt.Errorf("%w: a rule shard of another width", ErrBridgeLedgerMalformed)
		}
		rows.named = append(rows.named, path)
	}
	rows.manifest = manifest
	return rows, nil
}

func (self *bridgeCompileLedgerRows) Manifest() *protocol.BridgeLedgerManifest { return self.manifest }
func (self *bridgeCompileLedgerRows) FoldedThrough() uint64                    { return self.foldedThrough }

// A file the manifest names, through the view: one it names and the view does not hold is no ledger.
func (self *bridgeCompileLedgerRows) LedgerFile(path string) (BridgeLedgerFileReader, error) {
	if !slices.Contains(self.named, path) {
		return nil, nil
	}
	reader, err := self.view.LedgerFile(path)
	if err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, fmt.Errorf("%w: a file the manifest names and the head does not hold", ErrBridgeLedgerMalformed)
	}
	return reader, nil
}

// One compile's working state.
type bridgeCompiler struct {
	view     BridgeConfigView
	local    *BridgeCompileLocal
	settings *BridgeCompileSettings
	state    *ConfigState
	acl      *AclState
	aclLocal *AclLocalPolicy
	// t, S(n)'s time, as ms and as a time
	t   int64
	now time.Time
	// S, and what the state says of it
	self        Id
	selfSubject AclSubject
	selfTagged  bool
	selfDenied  bool
	hasDocument bool

	block *bridge.BridgeBlock
	// the block and, while it drains at t, the previous one; none until a head carries a block
	blocks []bridgePrefix
	ledger *BridgeLedger
	// the bindings, never nil
	bindings BridgeBindingView

	reach    []*bridgeCompileReach
	untagged *bridge.BridgeRuleSubject
	// S's routes in force, in rule id order
	served []*bridgeCompileServed

	compiled *BridgeCompiled
}

// Compiles the BridgeState the host local.SidecarId enforces at the view's pin (the file's comment). An error leaves the
// state in force: the BridgeCompiled beside it carries the alarms that say why, and no state. settings nil is the
// ledger's defaults.
func CompileBridgeState(view BridgeConfigView, local *BridgeCompileLocal, settings *BridgeLedgerSettings) (*BridgeCompiled, error) {
	if view == nil || view.State() == nil || view.Acl() == nil || local == nil {
		return nil, fmt.Errorf("%w: no state to compile", ErrBridgeCompileRefused)
	}
	settings = bridgeLedgerSettingsOrDefault(settings)
	compileSettings := local.Settings
	if compileSettings == nil {
		compileSettings = DefaultBridgeCompileSettings()
	}
	state := view.State()
	compiler := &bridgeCompiler{
		view:        view,
		local:       local,
		settings:    compileSettings,
		state:       state,
		acl:         view.Acl(),
		aclLocal:    view.AclLocal(),
		t:           state.TimeMs(),
		now:         time.UnixMilli(state.TimeMs()),
		self:        local.SidecarId,
		selfSubject: AclSidecarSubject(local.SidecarId),
		bindings:    local.Bindings,
		compiled:    &BridgeCompiled{},
	}
	if compiler.bindings == nil {
		compiler.bindings = &bridgeBindingSnapshot{}
	}
	compiler.hasDocument = compiler.acl.HasDocument()
	if row := state.SidecarRow(compiler.self); row != nil {
		compiler.selfTagged = 0 < len(row.GetTagIds())
	}
	selfState := compiler.acl.sidecarState(compiler.self)
	compiler.selfDenied = selfState == nil || selfState.hardDeny(compiler.t) != 0

	// a refused compile changes nothing: the next one reads at the block held before it
	refused := func(err error) (*BridgeCompiled, error) {
		compiler.compiled.Block = local.PreviousBlock
		return compiler.compiled, err
	}
	compiler.readBlock()
	if err := compiler.openLedger(settings); err != nil {
		return refused(err)
	}
	// what S serves first: route rows read it
	compiler.servedRoutes()
	compiler.reachPass()
	rules := compiler.build()
	if err := compiler.finish(rules); err != nil {
		return refused(err)
	}
	return compiler.compiled, nil
}

// Raises an alarm.
func (self *bridgeCompiler) alarm(reason SidecarBridgeAlarm, n uint64, sidecarId Id, detail string) {
	self.compiled.Alarms = append(self.compiled.Alarms, BridgeAlarm{Reason: reason, N: n, SidecarId: sidecarId, Detail: detail})
}

// Names a wait.
func (self *bridgeCompiler) wait(wait BridgeCompileWait) {
	if !slices.Contains(self.compiled.Waits, wait) {
		self.compiled.Waits = append(self.compiled.Waits, wait)
	}
}

// Step 1: the block, judged at the state the head's base lands on, with the previous block kept on a refusal; the
// previous prefix compiles while t is before its drain_until.
func (self *bridgeCompiler) readBlock() {
	block, err := self.local.PreviousBlock, error(nil)
	if head := self.view.Head(); head != nil {
		block, err = ReadBridgeBlock(head, self.baseState(), self.local.PreviousBlock)
	}
	if err != nil {
		self.alarm(SidecarBridgeAlarmBlockRefused, 0, Id{}, "the head's block is refused; the previous one stands")
	}
	self.block = block
	self.compiled.Block = block
	if block == nil {
		return
	}
	if prefix, err := bridgeCheckBlockPrefix(block.GetIpv4Prefix()); err == nil {
		self.blocks = append(self.blocks, prefix)
	}
	if block.GetPreviousPrefix() != nil && self.t < block.GetDrainUntil() {
		if previous, err := bridgeCheckBlockPrefix(block.GetPreviousPrefix()); err == nil && 0 < len(self.blocks) && previous != self.blocks[0] {
			self.blocks = append(self.blocks, previous)
		}
	}
}

// The state the head's base lands on, for its records' signers, or S(n) where the log no longer serves it, which judges
// a signer revoked since then as revoked: the previous block stands.
func (self *bridgeCompiler) baseState() *ConfigState {
	base := self.state.Base()
	if base == nil || base.GetVersion() == self.state.n {
		return self.state
	}
	chain, ok := self.state.chainAt(base.GetVersion())
	if !ok {
		return self.state
	}
	baseState, err := self.state.StateAt(&bridge.AuthPin{Version: base.GetVersion(), Chain: chain[:]})
	if err != nil {
		return self.state
	}
	return baseState
}

// Steps 3 to 6: the ledger over the head's files, each read once through the view, and the unfolded statements with
// the keys held. A file that does not verify, or bodies past their budget, refuse the compile.
func (self *bridgeCompiler) openLedger(settings *BridgeLedgerSettings) error {
	rows, err := newBridgeCompileLedgerRows(self.view, self.view.Head())
	if err == nil {
		self.ledger, err = OpenBridgeLedger(rows, &BridgeLedgerReader{State: self.state, RepoKeyAt: self.view.RepoKeyAt, Settings: settings})
	}
	if err != nil {
		if errors.Is(err, ErrBridgeLedgerOverBudget) {
			self.alarm(SidecarBridgeAlarmLedgerOverBudget, 0, Id{}, "the unfolded bodies pass their budget; the state in force stands")
		} else {
			self.alarm(SidecarBridgeAlarmStateUnverified, 0, Id{}, "the head's bridge ledger does not verify; the state in force stands")
		}
		return fmt.Errorf("%w: %w", ErrBridgeCompileRefused, err)
	}
	for _, entry := range self.ledger.Alarms() {
		self.alarm(SidecarBridgeAlarmStateUnverified, entry.Statement.N, entry.Statement.Signer, "a sealed body does not open")
	}
	for _, entry := range self.ledger.Pending() {
		if 0 < entry.Generation {
			self.wait(BridgeCompileWait{Kind: BridgeCompileWaitGeneration, Generation: entry.Generation})
		}
	}
	return nil
}

// Whether a rule the ledger holds is in force at t, and its drain when a drain withdrawal keeps it compiled (§17.8's
// disposition): active, or withdrawn to drain until max(drain_seconds, DrainMinimum) from its withdrawal; and filed
// under a decision, or covered by a standing grant of the policy at this state (12.2.4's "in force").
func (self *bridgeCompiler) ruleInForce(rule *BridgeLedgerRule) (bool, int64, int64) {
	if rule.Pending || rule.Void || (rule.Route == nil && rule.Map == nil) {
		return false, 0, 0
	}
	if rule.Standing && !self.aclLocal.StandingCovers(self.acl, rule, self.now) {
		return false, 0, 0
	}
	if !rule.Standing && rule.ApprovalId == (Id{}) {
		return false, 0, 0
	}
	if rule.Withdrawn == nil {
		return true, 0, 0
	}
	if rule.Withdrawn.Mode != bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN {
		return false, 0, 0
	}
	drainMs := int64(rule.Route.GetDrainSeconds()) * 1000
	if rule.Map != nil {
		drainMs = int64(rule.Map.GetDrainSeconds()) * 1000
	}
	since := rule.Withdrawn.TimeMs
	if since <= 0 || since+max(drainMs, self.settings.DrainMinimum.Milliseconds()) <= self.t {
		return false, 0, 0
	}
	return true, since, since + drainMs
}

// A prefix as the rules hold it.
func bridgeCompileWire(prefix bridgePrefix) *bridge.BridgeIpv4Prefix {
	return &bridge.BridgeIpv4Prefix{Address: prefix.address, Length: prefix.length}
}

// The host bits of an address or prefix, read into a block: §17.4 keeps them across block changes.
func bridgeCompileInBlock(block bridgePrefix, address uint32) uint32 {
	return block.address | address&0xffff
}

// Whether an address lies in the block or, while it drains, the previous one.
func (self *bridgeCompiler) inBlocks(address uint32) bool {
	return slices.ContainsFunc(self.blocks, func(block bridgePrefix) bool { return block.containsAddress(address) })
}

// The live address of a sidecar in each block, the current block's first, none without a block or an address.
func (self *bridgeCompiler) addressesOf(sidecarId Id) []uint32 {
	address := self.ledger.Address(sidecarId)
	if address == nil {
		return nil
	}
	addresses := []uint32{}
	for _, block := range self.blocks {
		addresses = append(addresses, bridgeCompileInBlock(block, address.HostBits))
	}
	return addresses
}

// Steps 8 and 9: the state, its rules marshalled, and its digest.
func (self *bridgeCompiler) finish(rules *bridge.BridgeRules) error {
	rulesBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(rules)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBridgeCompileRefused, err)
	}
	state := &bridge.BridgeState{
		Auth:            self.state.Pin(),
		GenesisSha256:   bytes.Clone(self.state.genesisChain[:]),
		HasDocument:     self.hasDocument,
		Rules:           rulesBytes,
		Names:           self.names(),
		NameZones:       self.nameZones(),
		Identities:      self.identities(rules),
		DaemonListeners: slices.Clone(self.local.DaemonListeners),
	}
	digest, err := BridgeStateDigest(state)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBridgeCompileRefused, err)
	}
	slices.SortFunc(self.compiled.Waits, func(a BridgeCompileWait, b BridgeCompileWait) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Generation, b.Generation), a.SidecarId.Cmp(b.SidecarId))
	})
	self.compiled.State = state
	self.compiled.Digest = digest
	self.compiled.LinkTargets = bridgeCompileLinkTargets(rules)
	return nil
}

// The zones, lowercase with no trailing dot, each once, in order.
func (self *bridgeCompiler) nameZones() []string {
	zones := []string{}
	for _, zone := range self.local.NameZones {
		zone = strings.ToLower(strings.TrimSuffix(zone, "."))
		if zone != "" && !slices.Contains(zones, zone) {
			zones = append(zones, zone)
		}
	}
	slices.Sort(zones)
	return zones
}

// §12.9's names: ConfigNames' label of S and of each sidecar S may dial that holds a live address (12.2.4's "each
// addressed sidecar among S and out"), to its address in the current block, so names hold only what the table's /32
// entries hold, and no label the zone publishes. A names file that does not read names nothing and alarms.
func (self *bridgeCompiler) names() map[string]uint32 {
	names := map[string]uint32{}
	head := self.view.Head()
	if head == nil || len(self.blocks) == 0 {
		return names
	}
	table, err := head.Names()
	if err != nil {
		self.alarm(SidecarBridgeAlarmStateUnverified, 0, Id{}, "the head's names do not read")
		return names
	}
	sidecarRows := []*bridge.SidecarRow{}
	for _, sidecarId := range self.state.SidecarIds() {
		sidecarRows = append(sidecarRows, self.state.SidecarRow(sidecarId))
	}
	labels, err := ConfigNames(table, sidecarRows, nil)
	if err != nil {
		self.alarm(SidecarBridgeAlarmStateUnverified, 0, Id{}, "the head's names are refused")
		return names
	}
	named := func(sidecarId Id, address uint32) {
		label, ok := labels[sidecarId]
		if !ok || slices.ContainsFunc(self.local.PublishedNames, func(published string) bool {
			return strings.EqualFold(strings.TrimSuffix(published, "."), label)
		}) {
			return
		}
		names[label] = address
	}
	if addresses := self.addressesOf(self.self); 0 < len(addresses) {
		named(self.self, addresses[0])
	}
	for _, reach := range self.reach {
		if !reach.out {
			continue
		}
		if addresses := self.addressesOf(reach.sidecarId); 0 < len(addresses) {
			named(reach.sidecarId, addresses[0])
		}
	}
	return names
}

// Each subject's identity: its SidecarRow's key, admission, revocation and suspension, and its live forwarding
// Delegation's id and key (owner decision 197; DESIGN-DETAILS 4.7).
func (self *bridgeCompiler) identities(rules *bridge.BridgeRules) []*bridge.BridgeIdentity {
	identities := []*bridge.BridgeIdentity{}
	for _, subject := range rules.GetSubjects() {
		sidecarId := Id(subject.GetSidecarId())
		row := self.state.SidecarRow(sidecarId)
		identity := &bridge.BridgeIdentity{
			SidecarId:         sidecarId.Bytes(),
			IdentityPublicKey: bytes.Clone(self.state.IdentityKey(sidecarId)),
			AdmittedAt:        row.GetAdmittedAt(),
			Revoked:           row.GetRevokedAt() != 0,
			Suspended:         self.state.Suspended(sidecarId),
		}
		if delegationId, publicKey, ok := self.state.ForwardingKey(sidecarId); ok {
			identity.ForwardDelegationId, identity.ForwardPublicKey = delegationId, publicKey
		}
		identities = append(identities, identity)
	}
	return identities
}

// Every sidecar the rules link to, ascending, each once.
func bridgeCompileLinkTargets(rules *bridge.BridgeRules) []Id {
	targets := []Id{}
	add := func(link *bridge.BridgeRuleLink) {
		target := Id(link.GetTargetSidecarId())
		if !slices.Contains(targets, target) {
			targets = append(targets, target)
		}
	}
	for _, entry := range rules.GetEntries() {
		for _, link := range entry.GetLinks() {
			add(link)
		}
	}
	for _, link := range rules.GetEgress().GetExits() {
		add(link)
	}
	slices.SortFunc(targets, Id.Cmp)
	return targets
}
