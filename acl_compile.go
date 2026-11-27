// CompileAcl (§8.8, D-ACL-1, D-ACL-15): the AclRows a config head gives, §8's part of §7.9's ProjectionRows, which the
// writer compiles at each base and every reader recompiles, alarming on a mismatch. The BASE row hashes what it
// gives on every reader, so the bytes are the contract: compile is a pure function of the head and the log's rows at
// its folded_through, with no clock, no network and no map iteration, every list sorted and the whole encoded
// deterministically by its caller (config_compile.go).
//
// What it reads, all from AclCompileInput:
//
//	policy.hujson     the document, or with none the implicit one through the same path (D-ACL-20)
//	tags, groups      each name's opaque atom id (plan-ACL-atom-and-rule-ids #1); a name with no row refuses
//	rules             each document rule's id by the SHA-256 of its canonical form (#3); a rule with no row refuses
//	labels            evs: labels to repo ids; a label with no row refuses
//	resolve           user:, network: and client: selectors (plan-ACL-selector-resolution); one with no row refuses
//	socket/key        K_sock, whose token paths application sockets compile to (§9.4), with a second target under
//	                  the previous key while a rotation holds one (plan-SOCK-ksock-rotation)
//	the log's rows    members and sidecars the atoms expand over, and the acl statements' rows: activated grants,
//	                  the folded access logs, suspensions, spent grant ids and BridgeRows' egress modes
//	bridge/ledger/    the routes the head's bridge ledger holds active at its fold, read only by CompileAcl
//	service_settings  auth_features, the authorization features the head turns on, whose implicit fragments a network
//	                  with no document compiles after the frozen implicit document (DESIGN-COMPUTE §16.6;
//	                  aclImplicitFeatureRules), and nothing else of the record
//	compute.hujson    a network with no document's compute block alone (DESIGN-COMPUTE §16.4; ConfigHeadComputePath),
//	                  which compiles as a document's block does and sets no reach (acl_compute_block_compile.go)
//
// What it writes: has_document; evidence_default, the document's effective evidenceDefault as channel values, all
// three where it names none, the implicit document's included, which every verifier reads for an action no requests
// rule names (QD-727); an AclAtom for every tag tagOwners declares and every group the groups block defines, whether
// or not a rule names it (owner decision 353), and for every derived atom the policy names, autogroups being
// fixed constants with no row; the policy's grants, each grant's via subjects in AclRule.via apart from its
// destinations (QD-764), and requests, then §8.5's kind-default rules that need the head
// (acl_kind.go), then the log's activated grants whose requests rule this head still holds (FS-14); the log's repos,
// suspensions and spent grant ids, a spent id dropped once its retention is below the head's newest record time;
// BridgeRows from BRIDGE's CompileBridgeRows, the log's egress modes with a row for each route the head's ledger holds in
// force, a standing one judged against this compile's own rows and policy (QD-764); and the audit block, which counts
// only under the k-of-n AuditOptIn record
// the log's rows hold (acl_audit.go), so a block with none names no reader. Kind defaults themselves are the binary's (acl_kind.go):
// documents add to them and never narrow them, and nothing here can.
//
// What rows drop on purpose stays on the device as AclLocalPolicy, which CompileAclLocal gives from the same input and
// nothing serializes off the device: ports and prefixes (plan-BRIDGE-gate-row-prefixes #1), exact socket globs,
// aliases (D-ACL-12), whether a requests rule names harness itself (owner decision 142), and names for previews.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type. Atom ids are random and
// table-held, so nothing here derives a key; K_sock's derivations call testHookSecret in NewSocketKeys.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Why a head's acl part does not compile: a policy that does not parse, or names what the head's tables do not hold.
var ErrAclCompile = errors.New("acl compile")

// What one compile reads: a config head's files, decoded, and the log's rows at the head's folded_through.
type AclCompileInput struct {
	// The network, the Genesis's: K_sock's token paths hang off its id (§9.4).
	NetworkId Id
	// The document's source, nil when the head holds none.
	Policy []byte
	// The head's tables, nil where the head holds no such file.
	Tags    *protocol.ConfigAtomTable
	Groups  *protocol.ConfigAtomTable
	Rules   *protocol.ConfigRuleTable
	Labels  *protocol.ConfigLabelTable
	Resolve *protocol.ConfigResolution
	// K_sock's file, nil when the head holds none.
	SocketKey *protocol.SocketKeyFile
	// The newest record time in the head's folds, ms since the epoch: the compile's one notion of time, never a clock.
	HeadTimeMs int64
	// L(folded_through): the members and sidecars the atoms expand over, and what the log's acl statements give.
	Members    []*bridge.MemberRow
	Sidecars   []*bridge.SidecarRow
	Statements *protocol.AclRows
	// L(folded_through)'s BridgeRows bytes, whose egress modes the rows carry (C-15).
	Bridge []byte
	// The routes the head's bridge ledger may hold in force (BridgeHeadRoutes): BRIDGE's CompileBridgeRows writes the
	// rows' routes from them, a standing one only where this compile's own policy covers it (QD-764). Nil reads them
	// from the head NewAclCompileInput was given, when CompileAcl first needs them; with no head, none.
	BridgeRoutes []*BridgeLedgerRule
	// The authorization features the head's ServiceSettings turns on (DESIGN-COMPUTE §16.6), whose implicit rules a
	// network with no document compiles after the frozen implicit document (aclImplicitFeatureRules): a part of the
	// head, so the compile stays a function of it.
	AuthFeatures AuthFeature
	// The head's block-alone compute record (ConfigHeadComputePath), nil when the head holds none: a network with no
	// document keeps its compute block there (DESIGN-COMPUTE §16.4).
	ComputeRecord []byte

	// the head the input came from, nil for an input built by hand
	head *ConfigHead
}

// The input a head and the log's rows at its folded_through give.
func NewAclCompileInput(head *ConfigHead, rows *ConfigCompileRows) (*AclCompileInput, error) {
	if head == nil || rows == nil {
		return nil, fmt.Errorf("%w: no head or rows", ErrAclCompile)
	}
	genesis, _ := head.Genesis()
	networkId, err := IdFromBytes(genesis.GetNetworkId())
	if err != nil {
		return nil, fmt.Errorf("%w: the genesis names no network", ErrAclCompile)
	}
	input := &AclCompileInput{
		NetworkId:     networkId,
		Policy:        head.File(ConfigHeadPolicyPath),
		ComputeRecord: head.File(ConfigHeadComputePath),
		HeadTimeMs:    aclHeadTimeMs(head),
		Members:       rows.Members,
		Sidecars:      rows.Sidecars,
		Statements:    rows.AclStatements,
	}
	if input.Statements == nil {
		input.Statements = &protocol.AclRows{}
	}
	decode := func(path string, message proto.Message) (bool, error) {
		data := head.File(path)
		if data == nil {
			return false, nil
		}
		if err := proto.Unmarshal(data, message); err != nil {
			return false, fmt.Errorf("%w: the head's %s file", ErrAclCompile, path)
		}
		return true, nil
	}
	tables := []struct {
		path   string
		target func() proto.Message
	}{
		{path: ConfigHeadTagsPath, target: func() proto.Message { input.Tags = &protocol.ConfigAtomTable{}; return input.Tags }},
		{path: ConfigHeadGroupsPath, target: func() proto.Message { input.Groups = &protocol.ConfigAtomTable{}; return input.Groups }},
		{path: ConfigHeadRulesPath, target: func() proto.Message { input.Rules = &protocol.ConfigRuleTable{}; return input.Rules }},
		{path: ConfigHeadLabelsPath, target: func() proto.Message { input.Labels = &protocol.ConfigLabelTable{}; return input.Labels }},
		{path: ConfigHeadResolvePath, target: func() proto.Message { input.Resolve = &protocol.ConfigResolution{}; return input.Resolve }},
		{path: ConfigHeadSocketKeyPath, target: func() proto.Message { input.SocketKey = &protocol.SocketKeyFile{}; return input.SocketKey }},
	}
	for _, table := range tables {
		if head.File(table.path) == nil {
			continue
		}
		if _, err := decode(table.path, table.target()); err != nil {
			return nil, err
		}
	}
	if _, err := ParseBridgeRows(input.Statements.GetBridge()); err != nil {
		return nil, fmt.Errorf("%w: bridge: %w", ErrAclCompile, err)
	}
	input.Bridge = input.Statements.GetBridge()
	settings, _, err := head.ServiceSettings()
	if err != nil {
		return nil, fmt.Errorf("%w: service_settings: %w", ErrAclCompile, err)
	}
	input.AuthFeatures = AuthFeature(settings.GetAuthFeatures())
	input.head = head
	return input, nil
}

// The newest ConfigRecord time in a head's folds, 0 for a head with none.
func aclHeadTimeMs(head *ConfigHead) int64 {
	for i := len(head.folds) - 1; 0 <= i; i -= 1 {
		if records := head.folds[i].GetRecords(); 0 < len(records) {
			return records[len(records)-1].GetTimeMs()
		}
	}
	return 0
}

// Registers CompileAcl as the config compile's acl part (C-05), so a base compiles only with real rows.
func init() {
	RegisterConfigAclCompiler(func(head *ConfigHead, rows *ConfigCompileRows) (*protocol.AclRows, error) {
		input, err := NewAclCompileInput(head, rows)
		if err != nil {
			return nil, err
		}
		return CompileAcl(input)
	})
}

// The AclRows the input gives. The input is not changed.
func CompileAcl(input *AclCompileInput) (*protocol.AclRows, error) {
	compiler, err := newAclCompiler(input)
	if err != nil {
		return nil, err
	}
	if err := compiler.compileBridge(); err != nil {
		return nil, err
	}
	return compiler.rows, nil
}

// AclRows.bridge at the fold (QD-764): the log's egress modes at folded_through, and a row for each route the head's
// ledger holds in force, BRIDGE's CompileBridgeRows judging a standing one by StandingCovers on these rows, at the head's
// newest record time, with the policy this compile gave. The rows' state for that judgment reads the log's members and
// sidecars at folded_through (aclCompileView); it needs no route row, since a rule that names no via is held by every
// advertiser whose route names it.
func (self *aclCompiler) compileBridge() error {
	routes := self.input.BridgeRoutes
	if routes == nil && self.input.head != nil {
		var err error
		if routes, err = BridgeHeadRoutes(self.input.head); err != nil {
			return fmt.Errorf("%w: bridge: %w", ErrAclCompile, err)
		}
	}
	var state *AclState
	var stateErr error
	now := time.UnixMilli(self.input.HeadTimeMs)
	covers := func(rule *BridgeLedgerRule) bool {
		if state == nil && stateErr == nil {
			state, stateErr = NewAclState(self.rows, newAclCompileView(self.input))
		}
		return stateErr == nil && self.local.StandingCovers(state, rule, now)
	}
	bridgeRows, err := CompileBridgeRows(self.input.Bridge, routes, covers)
	if err != nil {
		return fmt.Errorf("%w: bridge: %w", ErrAclCompile, err)
	}
	if stateErr != nil {
		return fmt.Errorf("%w: the rows' state for a standing route: %w", ErrAclCompile, stateErr)
	}
	self.rows.Bridge = bridgeRows
	return nil
}

// The log's rows at a compile's folded_through as an AclAuthView, for the standing grants a fold judges routes by: each
// sidecar's admission, revocation, park and sponsor as its row holds them, and each member. It holds no Genesis, pin,
// config writer or cascade, none of which a standing grant's cover reads.
type aclCompileView struct {
	members  map[Id]*bridge.MemberRow
	sidecars map[Id]*bridge.SidecarRow
}

// The view of the input's members and sidecars; a row with a malformed id holds no place in it.
func newAclCompileView(input *AclCompileInput) *aclCompileView {
	view := &aclCompileView{members: map[Id]*bridge.MemberRow{}, sidecars: map[Id]*bridge.SidecarRow{}}
	for _, member := range input.Members {
		if memberId, err := IdFromBytes(member.GetMemberId()); err == nil {
			view.members[memberId] = member
		}
	}
	for _, sidecar := range input.Sidecars {
		if sidecarId, err := IdFromBytes(sidecar.GetSidecarId()); err == nil {
			view.sidecars[sidecarId] = sidecar
		}
	}
	return view
}

// Version 0 over a zero chain: the view stands at no position.
func (self *aclCompileView) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: 0, Chain: make([]byte, sha256.Size)}
}

// None: no route's cover reads the config repo or the genesis clause.
func (self *aclCompileView) Genesis() *bridge.Genesis {
	return nil
}

// Every sidecar the rows hold, in id order.
func (self *aclCompileView) SidecarIds() []Id {
	return slices.SortedFunc(maps.Keys(self.sidecars), Id.Cmp)
}

// A sidecar's admission as its row holds it, as ConfigState gives it; nil for a row the rows lack or whose member or tag
// ids are malformed.
func (self *aclCompileView) Sidecar(sidecarId Id) *AclSidecar {
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

// A member's row, nil for none.
func (self *aclCompileView) Member(memberId Id) *bridge.MemberRow {
	return self.members[memberId]
}

// None: no route's cover reads who writes config heads.
func (self *aclCompileView) IsConfigWriter(sidecarId Id) bool {
	return false
}

// As the sidecar's row says, parked_at, which a cascade or a leaked bundle's DelegationRevoke sets (config_cascade.go).
func (self *aclCompileView) Parked(sidecarId Id) bool {
	row := self.sidecars[sidecarId]
	return row != nil && row.GetParkedAt() != 0
}

// A tagged sidecar's sponsor, as its row names one the rows still hold a member of, as ConfigState answers.
func (self *aclCompileView) Sponsor(sidecarId Id) (Id, bool) {
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

// None: no route's cover reads a consent.
func (self *aclCompileView) CascadeVoids(signer []byte, at uint64) bool {
	return false
}

// What rows drop on purpose, from the same input as CompileAcl (plan-ACL-small-readings #12). It never leaves the
// device.
func CompileAclLocal(input *AclCompileInput) (*AclLocalPolicy, error) {
	compiler, err := newAclCompiler(input)
	if err != nil {
		return nil, err
	}
	if input.SocketKey != nil {
		// Old heads still recompile to their original projection rows. Only a complete,
		// valid rotation can supply live blinded socket registrations.
		ring, err := NewSocketKeyRing(input.NetworkId, input.SocketKey, DefaultSocketKeyRingSettings())
		if err == nil {
			compiler.local.socketKeyRing = ring
		}
	}
	return compiler.local, nil
}

// A device's view of its policy beyond rows: what a client checks that a gate cannot (§8.10). Immutable once
// compiled; lists are in rule_id order.
type AclLocalPolicy struct {
	// The same head's validated K_sock, kept only on the device.
	socketKeyRing *SocketKeyRing
	HasDocument   bool
	// Every rule CompileAcl wrote from the head: the document's or the implicit one's grants and the kind defaults'.
	// An activated grant is the log's, and its own fields are the device's from its GrantActivate.
	Rules []AclLocalRule
	// Every requests rule.
	Requests []AclLocalRequest
	// The names behind the atoms and repos the rows name, for previews (§8.8's Saving).
	Names []AclLocalName
	// The document's discovery block, nil with none or no document: what §17.7.1's effective list of service types
	// reads (owner decision 778). It enters no row.
	Discovery *AclDiscoveryBlock
	// DESIGN-COMPUTE §16.4's compute block, the document's or a network with no document's record, as compiled under
	// the compute_policy feature; nil with none. What ComputePolicyView reads; the caller must not change it.
	Compute *AclComputeBlock
}

// One rule's detail.
type AclLocalRule struct {
	RuleId Id
	// The member-chosen id and note, empty for the implicit document's and the kind defaults'.
	DocumentId string
	Note       string
	// The ip field's ports, nil for every port.
	Ports []AclPortRange
	// The ip: destinations' prefixes, which route to them.
	Cidrs []netip.Prefix
	// The sock: destinations as written, globs kept, which rows carry coarsened (§8.4).
	Sockets []string
	// A publish's bound socket, empty for none.
	BoundSocket string
	// The mail: aliases, which rows carry only as mail_send (D-ACL-12).
	Aliases []string
	// An ssh grant's users and check period, nil for any other rule (DESIGN-COMPUTE §16.2).
	Ssh *AclLocalSsh
	// A compute:enclave rule's shapes, nil for every shape (§16.2).
	Shapes []string
}

// One requests rule's detail.
type AclLocalRequest struct {
	RuleId     Id
	DocumentId string
	Note       string
	// Whether the rule's own evidence names harness, which harness_ok reads in a tainted run (owner decision 142).
	NamesHarness bool
	Sockets      []string
	Aliases      []string
	Cidrs        []netip.Prefix
}

// One name a preview shows beside an id: a tag, group, user or other selector for an atom, or a repo's label.
type AclLocalName struct {
	Id   Id
	Text string
}

// The rule's detail, nil for a rule the head did not give, such as an activated grant.
func (self *AclLocalPolicy) Rule(ruleId []byte) *AclLocalRule {
	if self == nil || len(ruleId) != aclAtomByteCount {
		return nil
	}
	index, found := slices.BinarySearchFunc(self.Rules, Id(ruleId), func(rule AclLocalRule, target Id) int {
		return rule.RuleId.Cmp(target)
	})
	if !found {
		return nil
	}
	return &self.Rules[index]
}

// The requests rule's detail, nil for none.
func (self *AclLocalPolicy) Request(ruleId []byte) *AclLocalRequest {
	if self == nil || len(ruleId) != aclAtomByteCount {
		return nil
	}
	index, found := slices.BinarySearchFunc(self.Requests, Id(ruleId), func(request AclLocalRequest, target Id) int {
		return request.RuleId.Cmp(target)
	})
	if !found {
		return nil
	}
	return &self.Requests[index]
}

// One compile's working state, from which both outputs come.
type aclCompiler struct {
	input       *AclCompileInput
	policy      *AclPolicy
	hasDocument bool
	// the head's tables, indexed
	tagIds       map[string]Id
	groupIds     map[string]Id
	ruleIds      map[[32]byte]Id
	labelRepoIds map[string]Id
	labels       []string
	memberIds    map[string]Id
	networkIds   map[string]Id
	clientIds    map[Id]Id
	// the log's rows, indexed
	members map[Id]*bridge.MemberRow
	// K_sock's keys: the current one, then the previous one during a rotation's overlap
	socketKeys []*SocketKeys
	// the atoms compiled so far, by id
	atoms map[Id]*protocol.AclAtom
	// a network with no document's block-alone compute record, nil for none (acl_compute_block_compile.go)
	computeRecord *AclComputeBlock
	// the outputs
	rows  *protocol.AclRows
	local *AclLocalPolicy
}

// A compile refusal, naming no value (I-13).
func aclCompileRefusal(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrAclCompile, fmt.Sprintf(format, a...))
}

// Compiles both outputs.
func newAclCompiler(input *AclCompileInput) (*aclCompiler, error) {
	self, err := newAclCompilerTables(input)
	if err != nil {
		return nil, err
	}
	if err := self.compile(); err != nil {
		return nil, err
	}
	return self, nil
}

// The document, or the implicit one, parsed, and the head's tables and the log's members indexed: what compile and
// ValidateAclPolicy both start from.
func newAclCompilerTables(input *AclCompileInput) (*aclCompiler, error) {
	if input == nil {
		return nil, aclCompileRefusal("no input")
	}
	self := &aclCompiler{
		input:   input,
		atoms:   map[Id]*protocol.AclAtom{},
		members: map[Id]*bridge.MemberRow{},
		local:   &AclLocalPolicy{},
	}
	var err error
	if input.Policy != nil {
		self.hasDocument = true
		self.policy, err = ParseAclPolicy(input.Policy)
	} else {
		self.policy, err = aclImplicitPolicy()
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAclCompile, err)
	}
	if self.hasDocument {
		self.local.Discovery = self.policy.Discovery
	}
	if err := self.readComputeRecord(); err != nil {
		return nil, err
	}
	if err := self.indexTables(); err != nil {
		return nil, err
	}
	return self, nil
}

// Indexes the head's tables and the log's members, refusing a table that repeats a key or holds a malformed id.
func (self *aclCompiler) indexTables() error {
	atomTable := func(table *protocol.ConfigAtomTable, name string) (map[string]Id, error) {
		ids := map[string]Id{}
		for i, row := range table.GetAtoms() {
			id, err := IdFromBytes(row.GetAtomId())
			if err != nil || aclAtomHasAutogroupForm(id) {
				return nil, aclCompileRefusal("%s[%d] holds no atom id", name, i)
			}
			if _, found := ids[row.GetName()]; found {
				return nil, aclCompileRefusal("%s[%d] repeats a name", name, i)
			}
			ids[row.GetName()] = id
		}
		return ids, nil
	}
	var err error
	if self.tagIds, err = atomTable(self.input.Tags, "tags"); err != nil {
		return err
	}
	if self.groupIds, err = atomTable(self.input.Groups, "groups"); err != nil {
		return err
	}
	self.ruleIds = map[[32]byte]Id{}
	for i, row := range self.input.Rules.GetRules() {
		ruleId, err := IdFromBytes(row.GetRuleId())
		if err != nil || len(row.GetCanonicalSha256()) != 32 {
			return aclCompileRefusal("rules[%d] is malformed", i)
		}
		key := [32]byte(row.GetCanonicalSha256())
		if _, found := self.ruleIds[key]; found {
			return aclCompileRefusal("rules[%d] repeats a rule", i)
		}
		self.ruleIds[key] = ruleId
	}
	self.labelRepoIds = map[string]Id{}
	for i, row := range self.input.Labels.GetLabels() {
		repoId, err := IdFromBytes(row.GetRepoId())
		if err != nil || repoId == (Id{}) {
			return aclCompileRefusal("labels[%d] names no repo", i)
		}
		if _, found := self.labelRepoIds[row.GetLabel()]; found {
			return aclCompileRefusal("labels[%d] repeats a label", i)
		}
		self.labelRepoIds[row.GetLabel()] = repoId
		self.labels = append(self.labels, row.GetLabel())
	}
	slices.Sort(self.labels)
	resolve := self.input.Resolve
	self.memberIds = map[string]Id{}
	for i, row := range resolve.GetMembers() {
		memberId, err := IdFromBytes(row.GetMemberId())
		if err != nil {
			return aclCompileRefusal("resolve.members[%d] names no member", i)
		}
		if _, found := self.memberIds[row.GetEmail()]; found {
			return aclCompileRefusal("resolve.members[%d] repeats an email", i)
		}
		self.memberIds[row.GetEmail()] = memberId
	}
	self.networkIds = map[string]Id{}
	for i, row := range resolve.GetNetworks() {
		networkId, err := IdFromBytes(row.GetNetworkId())
		if err != nil {
			return aclCompileRefusal("resolve.networks[%d] names no network", i)
		}
		if _, found := self.networkIds[row.GetText()]; found {
			return aclCompileRefusal("resolve.networks[%d] repeats a name", i)
		}
		self.networkIds[row.GetText()] = networkId
	}
	self.clientIds = map[Id]Id{}
	for i, row := range resolve.GetClients() {
		clientId, err := IdFromBytes(row.GetClientId())
		if err != nil {
			return aclCompileRefusal("resolve.clients[%d] names no client", i)
		}
		sidecarId := Id{}
		if len(row.GetSidecarId()) != 0 {
			if sidecarId, err = IdFromBytes(row.GetSidecarId()); err != nil {
				return aclCompileRefusal("resolve.clients[%d] names no sidecar", i)
			}
		}
		if _, found := self.clientIds[clientId]; found {
			return aclCompileRefusal("resolve.clients[%d] repeats a client", i)
		}
		self.clientIds[clientId] = sidecarId
	}
	for i, member := range self.input.Members {
		memberId, err := IdFromBytes(member.GetMemberId())
		if err != nil {
			return aclCompileRefusal("members[%d] names no member", i)
		}
		self.members[memberId] = member
	}
	if keyFile := self.input.SocketKey; keyFile != nil {
		current, err := NewSocketKeys(self.input.NetworkId, keyFile.GetCurrentKey())
		if err != nil {
			return aclCompileRefusal("socket/key holds no K_sock")
		}
		self.socketKeys = []*SocketKeys{current}
		if 0 < len(keyFile.GetPreviousKey()) {
			previous, err := NewSocketKeys(self.input.NetworkId, keyFile.GetPreviousKey())
			if err != nil {
				return aclCompileRefusal("socket/key's previous key is no K_sock")
			}
			self.socketKeys = append(self.socketKeys, previous)
		}
	}
	return nil
}

// One rule's id: the document's from the rules table, the implicit document's or a kind default's fixed.
func (self *aclCompiler) ruleId(key AclRuleKey, implicitIndex uint32) (Id, error) {
	if !self.hasDocument {
		return aclImplicitRuleId(implicitIndex), nil
	}
	ruleId, found := self.ruleIds[key.CanonicalSha256]
	if !found {
		return Id{}, aclCompileRefusal("%s %d has no rules row", key.Kind, key.Index)
	}
	return ruleId, nil
}

// The ApprovalDecision.channel values of evidence names, sorted.
func aclEvidenceChannels(evidence []AclEvidence) []uint32 {
	channels := []uint32{}
	for _, name := range evidence {
		switch name {
		case AclEvidenceDevice:
			channels = append(channels, uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE))
		case AclEvidencePresence:
			channels = append(channels, uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE))
		case AclEvidenceHarness:
			channels = append(channels, uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS))
		}
	}
	slices.Sort(channels)
	return slices.Compact(channels)
}

// Actions as rows carry them, sorted.
func aclActionValues(actions []protocol.AclAction) []uint32 {
	values := make([]uint32, 0, len(actions))
	for _, action := range actions {
		values = append(values, uint32(action))
	}
	slices.Sort(values)
	return slices.Compact(values)
}

// Builds both outputs.
func (self *aclCompiler) compile() error {
	rows := &protocol.AclRows{
		HasDocument: self.hasDocument,
		// the effective default, as each requests rule's row carries its effective list (QD-396, QD-727)
		EvidenceDefault: aclEvidenceChannels(self.policy.EvidenceDefault),
	}
	self.local.HasDocument = self.hasDocument
	keys, err := AclPolicyRuleKeys(self.policy)
	if err != nil {
		return err
	}

	// every tag tagOwners declares and every group the groups block defines, named by a rule or not (§8.8's Atoms,
	// owner decision 353): CanApplyTag reads a tag's owners from its row alone, so a tag with no rule of its own still
	// needs one for a Delegation or a tagged SidecarAdmit to apply it. A rule naming one finds its row built, the same
	// row, and the rows list atoms in id order, so where a document names them changes no byte.
	for i := range self.policy.TagOwners {
		if _, err := self.atom(self.policy.TagOwners[i].Tag); err != nil {
			return fmt.Errorf("tagOwners[%d]: %w", i, err)
		}
	}
	for i := range self.policy.Groups {
		if _, err := self.atom(self.policy.Groups[i].Group); err != nil {
			return fmt.Errorf("groups[%d]: %w", i, err)
		}
	}

	ruleIds := map[Id]bool{}
	for i := range self.policy.Grants {
		grant := &self.policy.Grants[i]
		ruleId, err := self.ruleId(keys[i], uint32(i))
		if err != nil {
			return err
		}
		if ruleIds[ruleId] {
			// identical rules compile to one (plan-ACL-atom-and-rule-ids #3)
			continue
		}
		ruleIds[ruleId] = true
		rule, local, err := self.compileGrant(ruleId, grant)
		if err != nil {
			return fmt.Errorf("grants[%d]: %w", i, err)
		}
		rows.Rules = append(rows.Rules, rule)
		self.local.Rules = append(self.local.Rules, local)
	}

	requestIds := map[Id]bool{}
	for j := range self.policy.Requests {
		request := &self.policy.Requests[j]
		index := len(self.policy.Grants) + j
		ruleId, err := self.ruleId(keys[index], uint32(index))
		if err != nil {
			return err
		}
		if requestIds[ruleId] {
			continue
		}
		requestIds[ruleId] = true
		requestRow, local, err := self.compileRequest(ruleId, request)
		if err != nil {
			return fmt.Errorf("requests[%d]: %w", j, err)
		}
		rows.Requests = append(rows.Requests, requestRow)
		self.local.Requests = append(self.local.Requests, local)
	}

	// the implicit rules each feature the head turns on adds, after the frozen implicit document (§16.6's implicit row)
	if err := self.aclImplicitFeatureRules(rows, ruleIds, requestIds); err != nil {
		return err
	}

	kindRules, err := self.compileKindRules()
	if err != nil {
		return err
	}
	for _, rule := range kindRules {
		rows.Rules = append(rows.Rules, rule)
		self.local.Rules = append(self.local.Rules, AclLocalRule{RuleId: Id(rule.GetRuleId())})
	}

	// the log's activated grants, each ending at the first base whose head holds its requests rule no more (FS-14), and
	// at its expiry, which the head's newest record time already passed; their subjects' atoms with them
	statements := self.input.Statements
	for _, rule := range statements.GetRules() {
		if len(rule.GetSourceRuleId()) == 0 {
			// a previous base's own compile, which this one replaces
			continue
		}
		sourceRuleId, err := IdFromBytes(rule.GetSourceRuleId())
		if err != nil || !requestIds[sourceRuleId] {
			continue
		}
		if rule.GetExpires() != 0 && rule.GetExpires() <= self.input.HeadTimeMs {
			continue
		}
		kept := proto.Clone(rule).(*protocol.AclRule)
		aclSortRule(kept)
		rows.Rules = append(rows.Rules, kept)
		for _, atomBytes := range kept.GetSrcAtoms() {
			for _, atom := range statements.GetAtoms() {
				if bytes.Equal(atom.GetAtom(), atomBytes) {
					self.mergeAtom(proto.Clone(atom).(*protocol.AclAtom))
				}
			}
		}
	}

	for _, repo := range statements.GetRepos() {
		rows.Repos = append(rows.Repos, proto.Clone(repo).(*protocol.AclRepo))
	}
	for _, suspension := range statements.GetSuspensions() {
		rows.Suspensions = append(rows.Suspensions, proto.Clone(suspension).(*protocol.AclSuspension))
	}
	for _, spent := range statements.GetSpentGrants() {
		if spent.GetRetainUntilMs() != 0 && spent.GetRetainUntilMs() < self.input.HeadTimeMs {
			continue
		}
		rows.SpentGrants = append(rows.SpentGrants, proto.Clone(spent).(*protocol.AclSpentGrant))
	}
	rows.Bridge = bytes.Clone(self.input.Bridge)
	// owner decision 63's reader, under the opt-in record the log's rows hold (acl_audit.go)
	if rows.Audit, err = self.compileAudit(); err != nil {
		return err
	}
	// DESIGN-COMPUTE §16.4's compute block, under its feature, its budget subjects' atoms among the rows' atoms
	if err := self.compileComputeBlock(rows); err != nil {
		return err
	}

	for _, atom := range self.atoms {
		aclSortAtom(atom)
		rows.Atoms = append(rows.Atoms, atom)
	}
	if aclRowsMaxAtomCount < len(rows.Atoms) {
		return fmt.Errorf("%w: %d atoms, over %d", ErrAclRowsTooLarge, len(rows.Atoms), aclRowsMaxAtomCount)
	}
	aclSortRows(rows)
	slices.SortFunc(self.local.Rules, func(a AclLocalRule, b AclLocalRule) int { return a.RuleId.Cmp(b.RuleId) })
	slices.SortFunc(self.local.Requests, func(a AclLocalRequest, b AclLocalRequest) int { return a.RuleId.Cmp(b.RuleId) })
	self.local.Names = self.names()
	self.rows = rows
	return nil
}

// One grant's row and detail.
func (self *aclCompiler) compileGrant(ruleId Id, grant *AclGrant) (*protocol.AclRule, AclLocalRule, error) {
	rule := &protocol.AclRule{
		RuleId:         ruleId.Bytes(),
		Actions:        aclActionValues(grant.Allow),
		PortsLimited:   0 < len(grant.Ip),
		Audience:       grant.Audience,
		AppMode:        grant.AppMode,
		LinkSpkiSha256: bytes.Clone(grant.LinkSpkiSha256),
	}
	if !grant.Expires.IsZero() {
		rule.Expires = grant.Expires.UnixMilli()
	}
	local := AclLocalRule{RuleId: ruleId, DocumentId: grant.Id, Note: grant.Note, Ports: slices.Clone(grant.Ip),
		Ssh: grant.Ssh, Shapes: slices.Clone(grant.Shapes)}
	if grant.Sock != nil {
		local.BoundSocket = grant.Sock.Name
	}
	if err := self.checkComputeActions(grant.Allow); err != nil {
		return nil, local, err
	}
	var err error
	if rule.SrcAtoms, err = self.atomList(grant.Src); err != nil {
		return nil, local, err
	}
	for _, resource := range grant.Dst {
		targets, err := self.targets(resource)
		if err != nil {
			return nil, local, err
		}
		rule.Targets = append(rule.Targets, targets...)
		self.addLocalResource(resource, &local.Sockets, &local.Aliases, &local.Cidrs)
	}
	if slices.Contains(grant.Allow, protocol.AclAction_ACL_ACTION_ROUTE) {
		// a route rule's via subjects, apart from its destinations (QD-764, replacing acl-m2-04-compile-readings #6): with
		// none, the advertisers whose routes name the rule stand in at id level (QD-004)
		for _, via := range grant.Via {
			target, err := self.subjectTarget(via)
			if err != nil {
				return nil, local, err
			}
			rule.Via = append(rule.Via, target)
		}
	}
	aclSortRule(rule)
	return rule, local, nil
}

// One requests rule's row and detail.
func (self *aclCompiler) compileRequest(ruleId Id, request *AclRequest) (*protocol.AclRequestRule, AclLocalRequest, error) {
	evidence := request.Evidence
	if evidence == nil {
		evidence = self.policy.EvidenceDefault
	}
	row := &protocol.AclRequestRule{
		RuleId:               ruleId.Bytes(),
		Actions:              aclActionValues(request.Allow),
		Approvers:            request.Approvers,
		DefaultExpirySeconds: int64(self.policy.ExpiresDefault / time.Second),
		MaxExpirySeconds:     int64(request.MaxExpiry / time.Second),
		Evidence:             aclEvidenceChannels(evidence),
	}
	local := AclLocalRequest{
		RuleId:       ruleId,
		DocumentId:   request.Id,
		Note:         request.Note,
		NamesHarness: slices.Contains(request.Evidence, AclEvidenceHarness),
	}
	if err := self.checkComputeActions(request.Allow); err != nil {
		return nil, local, err
	}
	var err error
	if row.SrcAtoms, err = self.atomList(request.Src); err != nil {
		return nil, local, err
	}
	if row.ApproverAtoms, err = self.atomList(request.Approver); err != nil {
		return nil, local, err
	}
	for _, resource := range request.Dst {
		targets, err := self.targets(resource)
		if err != nil {
			return nil, local, err
		}
		row.Targets = append(row.Targets, targets...)
		self.addLocalResource(resource, &local.Sockets, &local.Aliases, &local.Cidrs)
	}
	row.Targets = aclSortTargets(row.Targets)
	return row, local, nil
}

// The kind defaults the head's tags give: tag:mail's read of every mailcfg repo and deposit to every vault and mailbox
// the log's rows hold (owner decision 150), none when the tags file holds no mail. A mailcfg whose row names an owner,
// a Team scope's own, is no target: the tag:mail kind default reads no scope's mailcfg, whose receivers are its
// member's own consented devices (owner decision 58), and a network mail indexer never resolves a scope's addresses
// (QD-1107), so the read names the network's mailcfg alone.
func (self *aclCompiler) compileKindRules() ([]*protocol.AclRule, error) {
	if _, found := self.tagIds[aclMailIndexerTag]; !found {
		return nil, nil
	}
	mailAtom, err := self.atom(AclSelector{Kind: AclSelectorTag, Name: aclMailIndexerTag})
	if err != nil {
		return nil, err
	}
	rules := []*protocol.AclRule{}
	for index, action := range []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ, protocol.AclAction_ACL_ACTION_DEPOSIT} {
		rule := &protocol.AclRule{
			RuleId:   aclKindRuleId(uint32(index)).Bytes(),
			SrcAtoms: [][]byte{mailAtom.Bytes()},
			Actions:  []uint32{uint32(action)},
		}
		want := AclEvsRead
		if action == protocol.AclAction_ACL_ACTION_DEPOSIT {
			want = AclEvsDeposit
		}
		for _, repo := range self.input.Statements.GetRepos() {
			kindDefault, known := aclKindDefault(repo.GetKind())
			if !known || kindDefault.MailIndexers != want {
				continue
			}
			if aclRepoRowScopeMailcfg(repo) {
				continue
			}
			rule.Targets = append(rule.Targets, &protocol.AclTarget{RepoId: bytes.Clone(repo.GetRepoId())})
		}
		if len(rule.Targets) == 0 {
			continue
		}
		aclSortRule(rule)
		rules = append(rules, rule)
	}
	return rules, nil
}

// The names a preview shows: every atom a table names and every label, by id.
func (self *aclCompiler) names() []AclLocalName {
	names := []AclLocalName{}
	for name, atomId := range self.tagIds {
		names = append(names, AclLocalName{Id: atomId, Text: "tag:" + name})
	}
	for name, atomId := range self.groupIds {
		names = append(names, AclLocalName{Id: atomId, Text: "group:" + name})
	}
	for email, memberId := range self.memberIds {
		names = append(names, AclLocalName{Id: AclDerivedAtom(AclDerivedAtomMember, memberId.Bytes()), Text: "user:" + email})
	}
	for text, networkId := range self.networkIds {
		names = append(names, AclLocalName{Id: AclDerivedAtom(AclDerivedAtomNetwork, networkId.Bytes()), Text: "network:" + text})
	}
	for _, label := range self.labels {
		names = append(names, AclLocalName{Id: self.labelRepoIds[label], Text: "evs:" + label})
	}
	slices.SortFunc(names, func(a AclLocalName, b AclLocalName) int {
		if c := a.Id.Cmp(b.Id); c != 0 {
			return c
		}
		return cmpString(a.Text, b.Text)
	})
	return names
}

// Strings in byte order.
func cmpString(a string, b string) int {
	switch {
	case a < b:
		return -1
	case b < a:
		return 1
	}
	return 0
}

// Every list of the rows in id order, each rule's and request's own lists sorted, so equal input gives equal bytes.
func aclSortRows(rows *protocol.AclRows) {
	slices.SortFunc(rows.Atoms, func(a *protocol.AclAtom, b *protocol.AclAtom) int { return bytes.Compare(a.GetAtom(), b.GetAtom()) })
	slices.SortFunc(rows.Rules, func(a *protocol.AclRule, b *protocol.AclRule) int { return bytes.Compare(a.GetRuleId(), b.GetRuleId()) })
	slices.SortFunc(rows.Requests, func(a *protocol.AclRequestRule, b *protocol.AclRequestRule) int {
		return bytes.Compare(a.GetRuleId(), b.GetRuleId())
	})
	slices.SortFunc(rows.Repos, func(a *protocol.AclRepo, b *protocol.AclRepo) int { return bytes.Compare(a.GetRepoId(), b.GetRepoId()) })
	slices.SortFunc(rows.Suspensions, func(a *protocol.AclSuspension, b *protocol.AclSuspension) int {
		if c := bytes.Compare(a.GetSubject(), b.GetSubject()); c != 0 {
			return c
		}
		return bytes.Compare(a.GetSuspendId(), b.GetSuspendId())
	})
	slices.SortFunc(rows.SpentGrants, func(a *protocol.AclSpentGrant, b *protocol.AclSpentGrant) int {
		return bytes.Compare(a.GetGrantId(), b.GetGrantId())
	})
}

// A rule's own lists sorted and without repeats.
func aclSortRule(rule *protocol.AclRule) {
	rule.SrcAtoms = aclSortBytesList(rule.SrcAtoms)
	rule.Targets = aclSortTargets(rule.Targets)
	if 0 < len(rule.Via) {
		rule.Via = aclSortTargets(rule.Via)
	}
	slices.Sort(rule.Actions)
	rule.Actions = slices.Compact(rule.Actions)
}

// Byte strings sorted and without repeats.
func aclSortBytesList(list [][]byte) [][]byte {
	sorted := slices.Clone(list)
	slices.SortFunc(sorted, bytes.Compare)
	return slices.CompactFunc(sorted, bytes.Equal)
}

// An atom's lists sorted and without repeats.
func aclSortAtom(atom *protocol.AclAtom) {
	atom.MemberIds = aclSortBytesList(atom.MemberIds)
	atom.SidecarIds = aclSortBytesList(atom.SidecarIds)
	atom.TagOwnerMemberIds = aclSortBytesList(atom.TagOwnerMemberIds)
	atom.ClientIds = aclSortBytesList(atom.ClientIds)
	atom.NetworkIds = aclSortBytesList(atom.NetworkIds)
}
