//go:build !ios_extension

// §17.9's filings on a sidecar role (BRIDGE-M4-19; R-BRIDGE-6, R-BRIDGE-7, R-BRIDGE-12, D-BRIDGE-6, D-BRIDGE-13,
// D-BRIDGE-16, I-4, I-8, I-9): one path that MCP's bridge tools (MCP-M4-01) and `ur bridge` (BRIDGE-M4-20) both take,
// so a filing is built, approved, signed and recorded alike whoever asks.
//
//	Expose        a BridgeRoute of this host's subnets or its exit, an outward act under §5.4's gate (kind expose)
//	ExposeMap     a BridgeMap of a port of this host's overlay address, under the gate; its effect files the host's
//	              own BridgeAddress first where the ledger holds none for it (§17.4), then the map
//	Forward       a requested dial grant to a target's port, its GrantActivate through ACL-M4-02's grant component,
//	              the requests rule's lifetime unless asked otherwise, 1 h by default (owner decision 74)
//	Close         bridge_close: a GrantRevoke of a dial or route grant whose subject this sidecar is, or a
//	              BridgeWithdraw of a rule the ledger holds as its own; it narrows reach, so it takes no approval
//	ClaimAddress  this host's BridgeAddress at an address a person chose (ur tun ip <ip>) or the allocator's, for a
//	              person's command alone: with no document a hosted address opens the device's loopback (rule 3), so
//	              an agent gets one only with an approved map
//	SetEgress     a subject's BridgeEgress, an outward act (§17.9) for a person's confirmation alone, under the gate;
//	              kind egress_change has no CanonicalAction row yet, so it is refused there, failing closed (question
//	              bridge-m4-19-egress-change-action)
//	SetBlock      the network's BridgeBlock in a config head, an admin's, for a person's confirmation alone, through
//	              this device's config writer: a /16 CheckBridgeBlock takes, or ChooseBridgeBlock's for cycle, the
//	              block it replaces draining (D-BRIDGE-16)
//	FindRule      a rule id as the authorization log holds it for this host, read through the ledger: what the
//	              bridge component's Lookup answers by (§16.6's step 5)
//
// An exposure's rule id is §17.8's: under a decision SHA-256("urnetwork-sidecar-v1/bridge-rule" || effect_key) of the
// use the gate reserved, its body carrying that spend's BridgeApproval, so a retry or a restart files one id; under a
// standing grant 32 random bytes and no approval. The effect is idempotent per key: it files nothing when the ledger
// holds its rule id, and a re-signed retry of a filing whose answer was lost files the same id, which every reader holds
// once (a filing of a held id activates nothing). A route names the §8 route rules of the head that hold it for this
// advertiser (AclLocalPolicy's own predicate, StandingCovers), which QD-764's rows carry at id level.
//
// Every statement goes through sidecarAct (C-02), which signs only §5.8's own-resource filings for MCP, a hook or an
// unconfirmed call. The filer refuses before that what is not this sidecar's own, as every verifier does after (§7.9,
// §8.8, §17.8): a BridgeAddress for another sidecar_id or a second one for an addressed host, and a GrantRevoke or
// BridgeWithdraw of another's grant or rule. A tainted run's binding reaches the gate unchanged, which takes only I-9's
// evidence for it (owner decision 142).
//
// Once a rule or a grant lands, or is withdrawn or revoked, the filer appends RECORD.md's route entry (RouteBody) through
// the sidecar's RecordWriter, opened or closed, written by the sidecar that files it. Errors and logs name opaque ids
// alone, never a prefix, an address or a port (I-13).
//
// Safe for concurrent use: a filer keeps no state of its own but its arguments.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The filer refuses before any act: not this sidecar's own resource, a filing its origin may not ask for, or one
	// that would change nothing.
	ErrBridgeFileRefused = errors.New("bridge filing refused")
	// No verified config state, no block, no config key, or a head the ledger's rows need that this device cannot
	// read: nothing can be judged, so nothing is filed.
	ErrBridgeFileNoState = errors.New("bridge filing has no verified state to file against")
	// The filing may have landed: a post's answer was lost, so a retry or a restart finds it by its id.
	ErrBridgeFileUncertain = errors.New("bridge filing uncertain")
)

// RouteBody's kinds (RECORD.md's route row).
const (
	bridgeRouteRecordForward uint32 = 1
	bridgeRouteRecordRoute   uint32 = 3
	bridgeRouteRecordMap     uint32 = 4
)

// RouteBody's events and closing reasons.
const (
	bridgeRouteRecordOpened    uint32 = 1
	bridgeRouteRecordClosed    uint32 = 2
	bridgeRouteRecordRevoked   uint32 = 2
	bridgeRouteRecordWithdrawn uint32 = 3
)

// The IP protocol numbers a map or a forward names.
const (
	bridgeProtocolIcmp uint32 = 1
	bridgeProtocolTcp  uint32 = 6
	bridgeProtocolUdp  uint32 = 17
)

// Tunables of a filer.
type BridgeFilerSettings struct {
	// How long a first map waits for its BridgeAddress's entry to apply before it reads the ledger again: 30 s.
	AddressLandTimeout time.Duration
	// How many addresses a first map proposes, drawing again after a claim another won in log order: 3.
	AddressClaimAttemptCount int
	// How long the block SetBlock replaces drains, its drain_until from now: 600 s, §17.8's shortest drain of an old
	// address.
	BlockDrainTimeout time.Duration
	// How many blocks cycle draws before it gives up finding one other than the block in force: 16.
	BlockDrawAttemptCount int
	// The ledger the filer opens, nil its defaults.
	Ledger *BridgeLedgerSettings
}

// The values above.
func DefaultBridgeFilerSettings() *BridgeFilerSettings {
	return &BridgeFilerSettings{
		AddressLandTimeout:       30 * time.Second,
		AddressClaimAttemptCount: 3,
		BlockDrainTimeout:        600 * time.Second,
		BlockDrawAttemptCount:    16,
	}
}

// What a filer reads of the network's config: TEAM-M2-10's ConfigClient is one.
type BridgeFilerConfig interface {
	// The newest verified state, nil before one.
	State() *ConfigState
	// The state at or past n, once the follow reaches it.
	WaitFor(ctx context.Context, n uint64) (*ConfigState, error)
}

// This device's config writer as SetBlock saves through it: ConfigWriter is one.
type BridgeHeadWriter interface {
	SaveHead(ctx context.Context, edit func(head *ConfigHead) (*ConfigHead, error)) (*bridge.AuthPin, error)
}

// What a filer is built over.
type BridgeFilerArgs struct {
	// The sidecar that files: its identity, its acts, its gate, its config keys and its record.
	Sidecar *Sidecar
	// The network's verified config.
	Config BridgeFilerConfig
	// Reads the head a base names: the block, and the ledger's folded rows. Nil reads none, so a state whose base folded
	// any entry refuses, and no block is known.
	Heads ConfigHeadReader
	// ACL-M4-02's grant filer over this sidecar's engine: Forward's grant and Close's GrantRevoke. Nil refuses both.
	Grants *AclGrantFiler
	// The head's compiled policy, whose route rules a route names (AclFollower's); nil, or a nil answer, names none.
	AclLocal func() *AclLocalPolicy
	// This device's config writer, nil, or a nil answer, where none runs: SetBlock refuses.
	HeadWriter func() BridgeHeadWriter
	// Where route entries go; nil is the sidecar's record.
	Records func() (RecordWriter, error)
	// crypto/rand's reader when nil: a standing rule's id, an address's or a block's draw, a seal's nonce.
	Random   io.Reader
	Clock    Clock
	Log      Logger
	Settings *BridgeFilerSettings
}

// Who asks for a filing and under what: what its act signs as and what §5.4's gate binds (§5.8, I-8, I-9).
type BridgeFileOrigin struct {
	// A person's confirmation, MCP, a hook, or an unconfirmed control call.
	Act SidecarActOrigin
	// The run binding a decision binds, passed to the gate unchanged; nil for none.
	RunId   *Id
	AgentId *Id
	// A decision the caller holds, which the gate takes first; nil for none.
	Decision *bridge.Signed
	// The agent's own words about the action, which an approver sees as untrusted text; empty for none.
	Summary string
	// The risk the agent asked, which can only raise the policy's.
	AgentRisk SidecarRisk
	// The presence check an act runs where the log covers a statement; nil for none.
	Check SidecarPresenceCheck
}

// What a filing filed, or found filed.
type BridgeFiling struct {
	// A forward's grant_id; nil for any other filing, and under a standing grant, which files none.
	GrantId []byte
	// An exposure's or a closed rule's id.
	RuleId []byte
	// The decision the filing spent under: zero under a standing grant, for a filing that takes none, and on a retry the
	// gate answered from its record without running the effect.
	ApprovalId Id
	// This host's overlay address a map answers on or a claim filed; invalid for none.
	Address netip.Addr
	// Whether this call filed the address: a host's first map, or a claim.
	AddressFiled bool
}

// The filer (the file's comment).
type BridgeFiler struct {
	args     *BridgeFilerArgs
	settings *BridgeFilerSettings
	clock    Clock
	log      Logger
	random   io.Reader
}

// A filer over args, whose Sidecar and Config are required.
func NewBridgeFiler(args *BridgeFilerArgs) (*BridgeFiler, error) {
	if args == nil || args.Sidecar == nil || args.Config == nil {
		return nil, fmt.Errorf("%w: a filer needs its sidecar and its config", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultBridgeFilerSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = args.Sidecar.clock
	}
	if clock == nil {
		clock = RealClock{}
	}
	random := args.Random
	if random == nil {
		random = rand.Reader
	}
	return &BridgeFiler{args: args, settings: settings, clock: clock, log: loggerOrDefault(args.Log), random: random}, nil
}

// What one filing reads of the network at the newest verified state: the state, the head its base names, the ledger
// over both, and the block in force.
type bridgeFileView struct {
	state  *ConfigState
	head   *ConfigHead
	ledger *BridgeLedger
	// nil before a head carries one, or while the head's is refused
	block *bridge.BridgeBlock
	self  Id
}

// The view at the newest verified state. ErrBridgeFileNoState before a state, for another network's, or for a base that
// folded entries whose head this filer cannot read.
func (self *BridgeFiler) view(ctx context.Context) (*bridgeFileView, error) {
	identity := self.args.Sidecar.currentIdentity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	state := self.args.Config.State()
	if state == nil {
		return nil, fmt.Errorf("%w: no state", ErrBridgeFileNoState)
	}
	if state.NetworkId() != identity.NetworkId {
		return nil, fmt.Errorf("%w: the config is another network's", ErrBridgeFileNoState)
	}
	view := &bridgeFileView{state: state, self: identity.SidecarId}
	if base := state.Base(); base != nil {
		if self.args.Heads != nil {
			head, err := self.args.Heads.ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
			if err != nil {
				return nil, fmt.Errorf("%w: the head: %w", ErrBridgeFileNoState, err)
			}
			view.head = head
		}
		if view.head == nil && 0 < base.GetFoldedThrough() {
			return nil, fmt.Errorf("%w: the base folded entries whose rows this device reads no head for", ErrBridgeFileNoState)
		}
	}
	rows, err := NewBridgeLedgerHeadRows(view.head, self.settings.Ledger)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileNoState, err)
	}
	ledger, err := OpenBridgeLedger(rows, &BridgeLedgerReader{State: state, RepoKeyAt: self.repoKeyAt(), Settings: self.settings.Ledger})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileNoState, err)
	}
	view.ledger = ledger
	if view.head != nil {
		// a refused block leaves none, so nothing that needs one is filed (D-BRIDGE-16)
		if block, err := ReadBridgeBlock(view.head, state, nil); err == nil {
			view.block = block
		}
	}
	return view, nil
}

// The config keys this device holds, as the ledger opens bodies: none where KEYS installed none.
func (self *BridgeFiler) repoKeyAt() func(generation uint64) *EvsRepoKey {
	keys := self.args.Sidecar.configKeys()
	return func(generation uint64) *EvsRepoKey {
		if keys == nil {
			return nil
		}
		return keys.ConfigKeyAt(generation)
	}
}

// The key a new body seals to: the config's current generation's. ErrBridgeFileNoState where none is held.
func (self *BridgeFiler) sealKey(ctx context.Context) (*EvsRepoKey, error) {
	keys := self.args.Sidecar.configKeys()
	if keys == nil {
		return nil, fmt.Errorf("%w: no config key: %w", ErrBridgeFileNoState, ErrConfigSealGenerationMissing)
	}
	repoKey, err := keys.CurrentConfigKey(ctx)
	if err != nil || repoKey == nil {
		return nil, fmt.Errorf("%w: no current config key: %w", ErrBridgeFileNoState, errors.Join(err, ErrConfigSealGenerationMissing))
	}
	return repoKey, nil
}

// The rule the ledger holds under ruleId as this host's, nil for none; refused for one another sidecar holds.
func (self *bridgeFileView) ownRule(ruleId []byte) (*BridgeLedgerRule, error) {
	rule := self.ledger.Rule(ruleId)
	if rule == nil {
		return nil, nil
	}
	if rule.Owner != self.self {
		return nil, fmt.Errorf("%w: another sidecar's rule holds the id", ErrBridgeFileRefused)
	}
	return rule, nil
}

// This host's overlay address in the block in force, invalid where it holds none or no block is known.
func (self *bridgeFileView) address() netip.Addr {
	held := self.ledger.Address(self.self)
	if held == nil || self.block == nil {
		return netip.Addr{}
	}
	return bridgeAddressOf(self.block.GetIpv4Prefix().GetAddress() | held.HostBits)
}

// An IPv4 address as bridge.proto's fixed32 holds one.
func bridgeAddressOf(ipv4 uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(ipv4 >> 24), byte(ipv4 >> 16), byte(ipv4 >> 8), byte(ipv4)})
}

// address as bridge.proto's fixed32, false for one that is no IPv4.
func bridgeIpv4Of(address netip.Addr) (uint32, bool) {
	address = address.Unmap()
	if !address.Is4() {
		return 0, false
	}
	octets := address.As4()
	return uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3]), true
}

// A masked IPv4 prefix as the wire carries it.
func bridgePrefixWire(prefix netip.Prefix) (*bridge.BridgeIpv4Prefix, error) {
	ipv4, ok := bridgeIpv4Of(prefix.Addr())
	if !ok || !prefix.IsValid() || prefix.Masked() != prefix {
		return nil, fmt.Errorf("%w: a prefix that is no masked IPv4 prefix", ErrBridgeFileRefused)
	}
	return &bridge.BridgeIpv4Prefix{Address: ipv4, Length: uint32(prefix.Bits())}, nil
}

// Runs action through §5.4's gate with its effect, and reads what the gate answered: done with the effect's reference,
// or why not.
func (self *BridgeFiler) authorize(ctx context.Context, origin *BridgeFileOrigin, action *SidecarAction) ([]byte, error) {
	if err := self.args.Sidecar.Authorize(ctx, action, origin.Decision); err != nil {
		return nil, err
	}
	outcome := action.Outcome
	switch {
	case outcome == nil:
		return nil, fmt.Errorf("%w: the gate answered no outcome", ErrBridgeFileUncertain)
	case outcome.State == ApprovalOutcomeDone:
		return bytes.Clone(outcome.EffectRef), nil
	case outcome.State == ApprovalOutcomeNotDone:
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, errors.Join(outcome.Err, ErrSidecarEffectNotDone))
	}
	return nil, fmt.Errorf("%w: %w", ErrBridgeFileUncertain, outcome.Err)
}

// The checks every filing's origin takes.
func bridgeFileCheckOrigin(origin *BridgeFileOrigin) error {
	if origin == nil {
		return fmt.Errorf("%w: no origin", ErrBridgeFileRefused)
	}
	switch origin.Act {
	case SidecarActConfirmed, SidecarActMcp, SidecarActHook, SidecarActUnconfirmed:
		return nil
	}
	return fmt.Errorf("%w: an origin %d", ErrBridgeFileRefused, origin.Act)
}

// An outward action of the kind for this filing, built as the daemon builds every action and bound to the origin's run.
func (self *BridgeFiler) newAction(origin *BridgeFileOrigin, stored *StoredCanonicalAction, effect SidecarEffect, detail *SidecarActionDetail) (*SidecarAction, error) {
	action, err := NewSidecarAction(stored, SidecarRiskNormal, origin.AgentRisk, origin.RunId, origin.AgentId)
	if err != nil {
		return nil, err
	}
	action.Effect = effect
	action.Summary = origin.Summary
	action.Detail = detail
	return action, nil
}

// One BridgeRoute this host advertises (§17.7, §17.8): its subnets, or its exit.
type BridgeRouteRequest struct {
	// The subnets, masked IPv4 prefixes, none past /32 and none 0.0.0.0/0; empty for an exit.
	Prefixes []netip.Prefix
	// An exit route, 0.0.0.0/0 through this host, in place of subnets.
	Exit bool
	// A remap of the one prefix: senders reach it as a block of the upper /17 of the same length, keeping host bits
	// (§17.7; plan-BRIDGE-small-readings #14), drawn first fit (AllocateBridgeUpperBlock).
	Remap bool
	// An HA replica's site, at most 32 bytes (D-BRIDGE-8); empty for none.
	SiteId []byte
	// The route's rendezvous weight (D-BRIDGE-9): 0 takes 1.
	Weight uint32
	// How long a withdrawn or edited route drains, at most 3,600 s; 0 takes §17.8's floor.
	DrainSeconds uint32
}

// The CanonicalAction a route asks for: this host as the target, and its prefixes, 0.0.0.0/0 for an exit, which the
// readers hold the body to (CheckBridgeApproval).
func bridgeRouteAction(target Id, route *bridge.BridgeRouteBody) (*StoredCanonicalAction, error) {
	action := &protocol.CanonicalAction{Kind: uint32(SidecarActionExpose), TargetSidecarId: target.Bytes()}
	if route.GetKind() == bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT {
		action.Cidrs = []string{"0.0.0.0/0"}
	}
	for _, wirePrefix := range route.GetPrefixes() {
		action.Cidrs = append(action.Cidrs, bridgePrefix{address: wirePrefix.GetAddress(), length: wirePrefix.GetLength()}.String())
	}
	return NewCanonicalAction(action)
}

// Files a BridgeRoute of this host's (the file's Expose row): its id under the gate's spend, or a standing grant's.
func (self *BridgeFiler) Expose(ctx context.Context, origin *BridgeFileOrigin, request *BridgeRouteRequest) (*BridgeFiling, error) {
	if err := bridgeFileCheckOrigin(origin); err != nil {
		return nil, err
	}
	if request == nil {
		return nil, fmt.Errorf("%w: no route", ErrBridgeFileRefused)
	}
	view, err := self.view(ctx)
	if err != nil {
		return nil, err
	}
	route := &bridge.BridgeRouteBody{
		SiteId: bytes.Clone(request.SiteId), Weight: max(1, request.Weight), DrainSeconds: request.DrainSeconds,
		Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET,
	}
	if request.Exit {
		if len(request.Prefixes) != 0 || request.Remap {
			return nil, fmt.Errorf("%w: an exit with prefixes", ErrBridgeFileRefused)
		}
		route.Kind = bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT
	}
	for _, prefix := range request.Prefixes {
		wirePrefix, err := bridgePrefixWire(prefix)
		if err != nil {
			return nil, err
		}
		route.Prefixes = append(route.Prefixes, wirePrefix)
	}
	if request.Remap {
		if len(route.GetPrefixes()) != 1 || view.block == nil {
			return nil, fmt.Errorf("%w: a remap maps one prefix into a block the head carries", ErrBridgeFileRefused)
		}
		plan, err := NewBridgeAddressPlan(view.block, view.ledger)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBridgeFileNoState, err)
		}
		exposed, err := AllocateBridgeUpperBlock(plan, route.GetPrefixes()[0].GetLength())
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
		}
		route.ExposedPrefix = exposed
	}
	// the shape every reader holds a body to, so no approval is asked for a body they would void
	if err := bridgeCheckRouteBody(route); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
	}
	stored, err := bridgeRouteAction(view.self, route)
	if err != nil {
		return nil, err
	}
	effect := &bridgeRuleEffect{
		filer: self, action: stored, origin: origin, signedType: bridge.SignedType_SIGNED_BRIDGE_ROUTE, route: route,
		routeRuleIds: self.routeRuleIds(view, route),
	}
	action, err := self.newAction(origin, stored, effect, nil)
	if err != nil {
		return nil, err
	}
	ruleId, err := self.authorize(ctx, origin, action)
	if err != nil {
		return nil, err
	}
	filing := effect.result(ruleId)
	return filing, nil
}

// The §8 route rules of the head that hold route for this advertiser, each one alone by the predicate every reader
// judges a standing route by (AclLocalPolicy.StandingCovers), at most a statement's 64, in rule order. None without a
// compiled policy where a document stands.
func (self *BridgeFiler) routeRuleIds(view *bridgeFileView, route *bridge.BridgeRouteBody) [][]byte {
	acl, err := view.state.Acl()
	if err != nil {
		return nil
	}
	var local *AclLocalPolicy
	if self.args.AclLocal != nil {
		local = self.args.AclLocal()
	}
	if local == nil {
		if acl.HasDocument() {
			return nil
		}
		local = aclImplicitLocalPolicy()
	}
	advertiser := acl.sidecarState(view.self)
	if advertiser == nil {
		return nil
	}
	nowMs := view.state.TimeMs()
	ruleIds := [][]byte{}
	for i := range acl.rules {
		ruleId := acl.rules[i].row.GetRuleId()
		if len(ruleIds) == bridgeRouteRuleIdMaxCount {
			break
		}
		if len(ruleId) != len(Id{}) && len(ruleId) != sha256.Size {
			continue
		}
		if local.routeCovered(acl, advertiser, [][]byte{ruleId}, route, nowMs) {
			ruleIds = append(ruleIds, bytes.Clone(ruleId))
		}
	}
	return ruleIds
}

// One BridgeMap of a port of this host's overlay address (§17.6's rule 1; §17.11's expose :<port>[=<ip>:<port>]).
type BridgeMapRequest struct {
	// 6 TCP or 17 UDP, 0 taking TCP; 1 ICMP maps every echo and takes no port.
	Protocol uint32
	// The ports of this host's address the map answers, first to last; LastPort 0 is FirstPort.
	FirstPort uint32
	LastPort  uint32
	// Where the map dials, never an address of the block: 127.0.0.1 when invalid (§17.6's ':5432' -> 127.0.0.1:5432).
	Target netip.Addr
	// The port it dials, 0 for the port matched; with a range, the range maps by offset onto it.
	TargetPort uint32
	// When the map ends; zero for none.
	Expires time.Time
	// How long an edited map drains, at most 3,600 s.
	DrainSeconds uint32
}

// A map's body but for its match prefix, which is the host's address once the ledger shows it.
type bridgeMapPlan struct {
	protocol   uint32
	ports      []*bridge.BridgePortRange
	target     []byte
	targetPort uint32
	expiresMs  int64
	drain      uint32
}

// The body over the address it matches.
func (self *bridgeMapPlan) body(address uint32) *bridge.BridgeMapBody {
	body := &bridge.BridgeMapBody{
		MatchPrefix:  &bridge.BridgeIpv4Prefix{Address: address, Length: 32},
		Protocol:     self.protocol,
		Target:       bytes.Clone(self.target),
		TargetPort:   self.targetPort,
		DrainSeconds: self.drain,
	}
	for _, ports := range self.ports {
		body.Ports = append(body.Ports, proto.Clone(ports).(*bridge.BridgePortRange))
	}
	return body
}

// A map's plan from its request, held to the shape every reader holds a map's body to and to §17.6's rule that a map
// never targets an address of the network's block.
func (self *BridgeFiler) mapPlan(view *bridgeFileView, request *BridgeMapRequest) (*bridgeMapPlan, error) {
	plan := &bridgeMapPlan{protocol: request.Protocol, targetPort: request.TargetPort, drain: request.DrainSeconds}
	if plan.protocol == 0 {
		plan.protocol = bridgeProtocolTcp
	}
	if !request.Expires.IsZero() {
		plan.expiresMs = request.Expires.UnixMilli()
		if plan.expiresMs <= self.clock.Now().UnixMilli() {
			return nil, fmt.Errorf("%w: a map that has expired", ErrBridgeFileRefused)
		}
	}
	switch plan.protocol {
	case bridgeProtocolTcp, bridgeProtocolUdp:
		lastPort := request.LastPort
		if lastPort == 0 {
			lastPort = request.FirstPort
		}
		plan.ports = []*bridge.BridgePortRange{{First: request.FirstPort, Last: lastPort}}
		// one port's target is written out, so the approval binds the port the map dials
		if plan.targetPort == 0 && request.FirstPort == lastPort {
			plan.targetPort = request.FirstPort
		}
	case bridgeProtocolIcmp:
		if request.FirstPort != 0 || request.LastPort != 0 || request.TargetPort != 0 {
			return nil, fmt.Errorf("%w: an ICMP map with ports", ErrBridgeFileRefused)
		}
	default:
		return nil, fmt.Errorf("%w: protocol %d", ErrBridgeFileRefused, plan.protocol)
	}
	target := request.Target.Unmap()
	if !target.IsValid() {
		target = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	plan.target = target.AsSlice()
	if view.block != nil {
		blocks := []*bridge.BridgeIpv4Prefix{view.block.GetIpv4Prefix()}
		if previous := view.block.GetPreviousPrefix(); previous != nil {
			blocks = append(blocks, previous)
		}
		if ipv4, ok := bridgeIpv4Of(target); ok {
			for _, block := range blocks {
				if (bridgePrefix{address: block.GetAddress(), length: block.GetLength()}).containsAddress(ipv4) {
					return nil, fmt.Errorf("%w: a map onto an address of the network's block", ErrBridgeFileRefused)
				}
			}
		}
	}
	// the shape, over any address of the block's lower half: the real one is the host's once the ledger shows it
	if err := bridgeCheckMapBody(plan.body(0x7f000001)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
	}
	return plan, nil
}

// The CanonicalAction a map asks for: this host as the target, the port it dials and its expiry, which the readers hold
// the body to (CheckBridgeApproval).
func bridgeMapAction(target Id, plan *bridgeMapPlan) (*StoredCanonicalAction, error) {
	return NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionExpose), TargetSidecarId: target.Bytes(), TargetPort: plan.targetPort, ExpiresMillis: plan.expiresMs,
	})
}

// Files a BridgeMap of a port of this host's address (the file's ExposeMap row), its address filed first where the
// ledger holds none for it.
func (self *BridgeFiler) ExposeMap(ctx context.Context, origin *BridgeFileOrigin, request *BridgeMapRequest) (*BridgeFiling, error) {
	if err := bridgeFileCheckOrigin(origin); err != nil {
		return nil, err
	}
	if request == nil {
		return nil, fmt.Errorf("%w: no map", ErrBridgeFileRefused)
	}
	view, err := self.view(ctx)
	if err != nil {
		return nil, err
	}
	if view.block == nil {
		return nil, fmt.Errorf("%w: the network has no block yet", ErrBridgeFileNoState)
	}
	plan, err := self.mapPlan(view, request)
	if err != nil {
		return nil, err
	}
	stored, err := bridgeMapAction(view.self, plan)
	if err != nil {
		return nil, err
	}
	effect := &bridgeRuleEffect{filer: self, action: stored, origin: origin, signedType: bridge.SignedType_SIGNED_BRIDGE_MAP, mapPlan: plan}
	// the request binds the port the map exposes on this host, as an approver sees it beside the action's target port
	var detail *SidecarActionDetail
	if 0 < request.FirstPort {
		detail = &SidecarActionDetail{LocalPort: request.FirstPort}
	}
	action, err := self.newAction(origin, stored, effect, detail)
	if err != nil {
		return nil, err
	}
	ruleId, err := self.authorize(ctx, origin, action)
	if err != nil {
		return nil, err
	}
	return effect.result(ruleId), nil
}

// The bridge component's effect for one exposure (§16.6's bridge row): a route or a map under the rule id the spend
// fixes. Run once per call by the gate; what it filed is kept for the caller.
type bridgeRuleEffect struct {
	filer      *BridgeFiler
	action     *StoredCanonicalAction
	origin     *BridgeFileOrigin
	signedType bridge.SignedType
	// a route's body without its approval, and the route rules it names
	route        *bridge.BridgeRouteBody
	routeRuleIds [][]byte
	// a map's plan
	mapPlan *bridgeMapPlan

	// what the run filed or found
	approvalId   Id
	address      netip.Addr
	addressFiled bool
}

// What the call filed, with the rule id the gate answered.
func (self *bridgeRuleEffect) result(ruleId []byte) *BridgeFiling {
	return &BridgeFiling{RuleId: ruleId, ApprovalId: self.approvalId, Address: self.address, AddressFiled: self.addressFiled}
}

// What an exposure files under: the rule id and the BridgeApproval the spend in ctx fixes for effectKey, or under a
// standing grant, an empty key, nil for both. ErrSidecarEffectNotDone where the spend is missing or fixes another key.
func (self *BridgeFiler) ruleApproval(ctx context.Context, action *StoredCanonicalAction, effectKey []byte) ([]byte, *bridge.BridgeApproval, Id, error) {
	if len(effectKey) == 0 {
		return nil, nil, Id{}, nil
	}
	if len(effectKey) != sha256.Size {
		return nil, nil, Id{}, fmt.Errorf("%w: an effect key of %d bytes", ErrSidecarEffectNotDone, len(effectKey))
	}
	spend, ok := ApprovalSpendFromContext(ctx)
	if !ok {
		return nil, nil, Id{}, fmt.Errorf("%w: no spend to file a rule under", ErrSidecarEffectNotDone)
	}
	fixed := ApprovalEffectKey(spend.ApprovalId, action.ActionId(spend.ApprovalId))
	if !bytes.Equal(fixed[:], effectKey) {
		return nil, nil, Id{}, fmt.Errorf("%w: an effect key the spend does not fix", ErrSidecarEffectNotDone)
	}
	approval := &bridge.BridgeApproval{CanonicalAction: bytes.Clone(action.Bytes)}
	if !bytes.Equal(spend.Action, action.Bytes) {
		// a multi-use decision's template, which this use falls inside (owner decision 218)
		approval.TemplateAction = bytes.Clone(spend.Action)
	}
	for _, decisionBytes := range spend.Decisions {
		decision := &bridge.Signed{}
		if err := proto.Unmarshal(decisionBytes, decision); err != nil {
			return nil, nil, Id{}, fmt.Errorf("%w: a decision that is no Signed", ErrSidecarEffectNotDone)
		}
		approval.Decisions = append(approval.Decisions, decision)
	}
	ruleId := BridgeRuleId([sha256.Size]byte(effectKey))
	return ruleId[:], approval, spend.ApprovalId, nil
}

// Files the exposure (§16.6's step 5): nothing when the ledger holds its rule id already, which answers the id again.
// An error wrapping ErrSidecarEffectNotDone proves nothing was filed; any other leaves the use uncertain.
func (self *bridgeRuleEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	filer := self.filer
	ruleId, approval, approvalId, err := filer.ruleApproval(ctx, self.action, effectKey)
	if err != nil {
		return nil, err
	}
	self.approvalId = approvalId
	view, err := filer.view(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	if ruleId != nil {
		held, err := view.ownRule(ruleId)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
		}
		if held != nil {
			// the filing landed before: a retry or a restart files no second one
			self.address = view.address()
			return ruleId, nil
		}
	} else {
		if held := self.standingRule(view); held != nil {
			self.address = view.address()
			return bytes.Clone(held.RuleId), nil
		}
		ruleId = make([]byte, bridgeRuleIdByteCount)
		if _, err := io.ReadFull(filer.random, ruleId); err != nil {
			return nil, fmt.Errorf("%w: no randomness for a rule id: %w", ErrSidecarEffectNotDone, err)
		}
	}

	var statement proto.Message
	var body proto.Message
	record := &RecordRouteArgs{Event: bridgeRouteRecordOpened, RuleId: ruleId, TargetSidecarId: &view.self}
	switch self.signedType {
	case bridge.SignedType_SIGNED_BRIDGE_ROUTE:
		routeBody := proto.Clone(self.route).(*bridge.BridgeRouteBody)
		routeBody.Approval = approval
		statement = &bridge.BridgeRoute{RouteId: ruleId, Advertiser: view.self.Bytes(), RouteRuleIds: self.routeRuleIds}
		body = routeBody
		record.Kind = bridgeRouteRecordRoute
		for _, wirePrefix := range routeBody.GetPrefixes() {
			record.Cidrs = append(record.Cidrs, bridgePrefix{address: wirePrefix.GetAddress(), length: wirePrefix.GetLength()}.String())
		}
	case bridge.SignedType_SIGNED_BRIDGE_MAP:
		address, err := self.hostAddress(ctx, view)
		if err != nil {
			return nil, err
		}
		ipv4, _ := bridgeIpv4Of(address)
		mapBody := self.mapPlan.body(ipv4)
		mapBody.Approval = approval
		statement = &bridge.BridgeMap{MapId: ruleId, Host: view.self.Bytes(), Expires: self.mapPlan.expiresMs}
		body = mapBody
		record.Kind = bridgeRouteRecordMap
		record.TargetPort = mapBody.GetTargetPort()
		record.ExpiresMillis = self.mapPlan.expiresMs
	default:
		return nil, fmt.Errorf("%w: %s is no exposure", ErrSidecarEffectNotDone, self.signedType)
	}
	barrierKey := hex.EncodeToString(ruleId)
	testHookBarrier("bridge_file.rule.before", barrierKey)
	_, err = filer.fileSealed(ctx, self.origin, self.signedType, statement, body)
	testHookBarrier("bridge_file.rule.after", barrierKey)
	if err != nil {
		return nil, err
	}
	if approval != nil {
		approvalIdCopy := approvalId
		record.ApprovalId = &approvalIdCopy
	}
	var actionId []byte
	if approval != nil {
		id := self.action.ActionId(approvalId)
		actionId = id[:]
	}
	filer.recordRoute(self.origin, actionId, nil, record)
	return ruleId, nil
}

// Under a standing grant: a route or map of this host's the ledger holds with this body, filed with no approval and not
// withdrawn, so asking again files nothing. Nil for none.
func (self *bridgeRuleEffect) standingRule(view *bridgeFileView) *BridgeLedgerRule {
	for _, rule := range view.ledger.Rules(self.signedType) {
		if rule.Owner != view.self || !rule.Standing || rule.Withdrawn != nil {
			continue
		}
		switch {
		case rule.Route != nil && self.route != nil:
			if proto.Equal(rule.Route, self.route) && bridgeIdsEqual(rule.RouteRuleIds, self.routeRuleIds) {
				return rule
			}
		case rule.Map != nil && self.mapPlan != nil:
			held := view.ledger.Address(view.self)
			if held != nil && rule.Expires == self.mapPlan.expiresMs &&
				proto.Equal(rule.Map, self.mapPlan.body(view.block.GetIpv4Prefix().GetAddress()|held.HostBits)) {
				return rule
			}
		}
	}
	return nil
}

// Whether two id lists are equal, in order.
func bridgeIdsEqual(a [][]byte, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// This host's overlay address for its map: the ledger's, or one this run claims (§17.4's "the host's first map"),
// waiting for each claim to apply and reading the ledger again, since the first claim in log order wins.
func (self *bridgeRuleEffect) hostAddress(ctx context.Context, view *bridgeFileView) (netip.Addr, error) {
	if address := view.address(); address.IsValid() {
		self.address = address
		return address, nil
	}
	filer := self.filer
	for range max(1, filer.settings.AddressClaimAttemptCount) {
		plan, err := NewBridgeAddressPlan(view.block, view.ledger)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
		}
		proposed, err := AllocateBridgeAddress(plan, filer.random)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
		}
		next, err := filer.claimAddress(ctx, self.origin, view, view.self, proposed)
		if err != nil {
			return netip.Addr{}, err
		}
		self.addressFiled = true
		view = next
		if address := view.address(); address.IsValid() {
			self.address = address
			return address, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: every address this host proposed was another's first", ErrSidecarEffectNotDone)
}

// Files sidecarId's BridgeAddress at ipv4 and answers the view once its entry applied. Only this host's own address is
// filed here: one for another sidecar_id, or a second for a host the ledger addresses, is refused before any act, as
// every verifier refuses it. ErrSidecarEffectNotDone wraps a refusal that proves nothing was filed.
func (self *BridgeFiler) claimAddress(ctx context.Context, origin *BridgeFileOrigin, view *bridgeFileView, sidecarId Id, ipv4 uint32) (*bridgeFileView, error) {
	switch {
	case sidecarId != view.self:
		return nil, fmt.Errorf("%w: %w: a BridgeAddress for another sidecar_id", ErrSidecarEffectNotDone, ErrBridgeFileRefused)
	case view.ledger.Address(sidecarId) != nil:
		return nil, fmt.Errorf("%w: %w: a second BridgeAddress for an addressed host", ErrSidecarEffectNotDone, ErrBridgeFileRefused)
	}
	barrierKey := sidecarId.String()
	testHookBarrier("bridge_file.address.before", barrierKey)
	pins, err := self.fileSealed(ctx, origin, bridge.SignedType_SIGNED_BRIDGE_ADDRESS,
		&bridge.BridgeAddress{SidecarId: sidecarId.Bytes()}, &bridge.BridgeAddressBody{Ipv4: ipv4})
	testHookBarrier("bridge_file.address.after", barrierKey)
	if err != nil {
		return nil, err
	}
	if len(pins) == 0 || pins[0] == nil {
		return nil, fmt.Errorf("%w: the address's entry is not known", ErrBridgeFileUncertain)
	}
	waitCtx, cancel := context.WithTimeout(ctx, self.settings.AddressLandTimeout)
	defer cancel()
	if _, err := self.args.Config.WaitFor(waitCtx, pins[0].GetVersion()); err != nil {
		return nil, fmt.Errorf("%w: the address's entry did not apply: %w", ErrBridgeFileUncertain, err)
	}
	return self.view(ctx)
}

// Signs and posts one statement whose body seals to the config's current generation, as origin's act. Answers the
// entries. A refusal before or at the post wraps ErrSidecarEffectNotDone, since nothing was sequenced; a lost answer
// leaves the statement pending, the same bytes posting again.
func (self *BridgeFiler) fileSealed(ctx context.Context, origin *BridgeFileOrigin, signedType bridge.SignedType, statement proto.Message, body proto.Message) ([]*bridge.AuthPin, error) {
	repoKey, err := self.sealKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	act, err := self.args.Sidecar.newAct(origin.Act)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	err = act.AddSealed(signedType, statement, func(header *bridge.StatementHeader, withHeader proto.Message) error {
		sealed, err := SealConfigBody(repoKey, NewConfigSealContext(signedType, header), body, self.random)
		if err != nil {
			return err
		}
		field := withHeader.ProtoReflect().Descriptor().Fields().ByName("sealed_body")
		if field == nil {
			return fmt.Errorf("%s carries no sealed body", signedType)
		}
		withHeader.ProtoReflect().Set(field, protoreflect.ValueOfBytes(sealed))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	return self.runAct(ctx, act, origin)
}

// Runs an act and maps its answer: a refusal proves nothing was sequenced; a pending statement may still land.
func (self *BridgeFiler) runAct(ctx context.Context, act *sidecarAct, origin *BridgeFileOrigin) ([]*bridge.AuthPin, error) {
	pins, err := act.Run(ctx, origin.Check)
	switch {
	case err == nil:
		return pins, nil
	case errors.Is(err, ErrSidecarActPending):
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileUncertain, err)
	}
	return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
}

// Appends RECORD.md's route entry for a filing that landed, as the sidecar that filed it saw it. A record that does not
// take it is logged: the filing stands.
func (self *BridgeFiler) recordRoute(origin *BridgeFileOrigin, actionId []byte, grantId []byte, args *RecordRouteArgs) {
	body, err := NewRecordRouteBody(args)
	if err != nil {
		self.log.Warningf("[bridge]a route entry was not built: %v", err)
		return
	}
	writer, err := self.records()
	if err != nil {
		self.log.Warningf("[bridge]no record takes the route entry: %v", err)
		return
	}
	draft := &RecordDraft{
		Kind:     RecordKindRoute,
		Source:   RecordSourceObserved,
		RunId:    origin.RunId,
		AgentId:  origin.AgentId,
		ActionId: bytes.Clone(actionId),
		GrantId:  bytes.Clone(grantId),
		Body:     body,
	}
	draft.NoSession = origin.RunId == nil
	if _, err := writer.Append(draft); err != nil {
		self.log.Warningf("[bridge]the route entry was not appended: %v", err)
	}
}

// The record route entries go to.
func (self *BridgeFiler) records() (RecordWriter, error) {
	if self.args.Records != nil {
		return self.args.Records()
	}
	record, err := self.args.Sidecar.Record()
	if err != nil {
		return nil, err
	}
	return record.Writer(), nil
}

// One forward (§17.9, R-BRIDGE-6): a requested dial grant to one target sidecar's port, for one agent, which
// `ur bridge forward` and bridge_forward listen for locally and dial over the userspace stack.
type BridgeForwardRequest struct {
	Target Id
	// 6 TCP or 17 UDP, 0 taking TCP.
	Protocol uint32
	Port     uint32
	// The local port the forward listens on, which the request binds (QD-740); 0 for none.
	LocalPort uint32
	// How long the grant lives; 0 takes the requests rule's lifetime, 1 h by default (owner decision 74).
	Lifetime time.Duration
}

// Files a forward's GrantActivate under the gate (the file's Forward row): its grant_id, or none under a standing grant
// that already covers it.
func (self *BridgeFiler) Forward(ctx context.Context, origin *BridgeFileOrigin, request *BridgeForwardRequest) (*BridgeFiling, error) {
	if err := bridgeFileCheckOrigin(origin); err != nil {
		return nil, err
	}
	grants := self.args.Grants
	if grants == nil {
		return nil, fmt.Errorf("%w: no grant filer", ErrBridgeFileRefused)
	}
	identity := self.args.Sidecar.currentIdentity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	if request == nil || request.Target == (Id{}) || request.Target == identity.SidecarId {
		return nil, fmt.Errorf("%w: a forward names another sidecar", ErrBridgeFileRefused)
	}
	protocolName := map[uint32]string{0: "tcp", bridgeProtocolTcp: "tcp", bridgeProtocolUdp: "udp"}[request.Protocol]
	if protocolName == "" || request.Port == 0 || 65535 < request.Port || 65535 < request.LocalPort {
		return nil, fmt.Errorf("%w: a forward's protocol or port", ErrBridgeFileRefused)
	}
	now := self.clock.Now()
	expiresMs := int64(0)
	if 0 < request.Lifetime {
		expiresMs = now.Add(request.Lifetime).UnixMilli()
	}
	destination := "sidecar:" + hex.EncodeToString(request.Target.Bytes())
	stored, err := grants.Action(ctx, &protocol.CanonicalAction{Kind: uint32(SidecarActionForward)}, &AclGrantRequest{
		Subject:    identity.SidecarId,
		GrantDst:   []string{destination},
		GrantAllow: []string{"dial"},
		ExpiresMs:  expiresMs,
		Detail: &protocol.CanonicalActionDetail{
			TargetPort: request.Port,
			GrantDst:   []string{destination + ":" + protocolName + ":" + strconv.FormatUint(uint64(request.Port), 10)},
		},
	}, now)
	if err != nil {
		return nil, err
	}
	effect := &bridgeForwardEffect{filer: self, inner: grants.Effect(stored), origin: origin, request: request, action: stored}
	var detail *SidecarActionDetail
	if 0 < request.LocalPort {
		detail = &SidecarActionDetail{LocalPort: request.LocalPort}
	}
	action, err := self.newAction(origin, stored, effect, detail)
	if err != nil {
		return nil, err
	}
	grantId, err := self.authorize(ctx, origin, action)
	if err != nil {
		return nil, err
	}
	filing := &BridgeFiling{ApprovalId: effect.approvalId}
	if len(grantId) != 0 {
		filing.GrantId = grantId
	}
	return filing, nil
}

// The grant component's effect for a forward, with the route entry beside it once a grant this run filed lands.
type bridgeForwardEffect struct {
	filer   *BridgeFiler
	inner   SidecarEffect
	origin  *BridgeFileOrigin
	request *BridgeForwardRequest
	action  *StoredCanonicalAction

	approvalId Id
}

// The grant component's Run, then the route entry for a grant it filed and the log did not hold before.
func (self *bridgeForwardEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	spend, ok := ApprovalSpendFromContext(ctx)
	if len(effectKey) == 0 || !ok {
		return self.inner.Run(ctx, effectKey)
	}
	self.approvalId = spend.ApprovalId
	grantId := AclGrantId(spend.ApprovalId, sha256.Sum256(spend.Action))
	heldBefore := self.filer.args.Grants.held(grantId[:])
	grantRef, err := self.inner.Run(ctx, effectKey)
	if err != nil || heldBefore {
		return grantRef, err
	}
	approvalId := spend.ApprovalId
	actionId := self.action.ActionId(approvalId)
	target := self.request.Target
	self.filer.recordRoute(self.origin, actionId[:], grantRef, &RecordRouteArgs{
		Event: bridgeRouteRecordOpened, Kind: bridgeRouteRecordForward, TargetSidecarId: &target, TargetPort: self.request.Port,
		ExpiresMillis: self.action.Action.GetExpiresMillis(), ApprovalId: &approvalId,
	})
	return grantRef, nil
}

// Closes a forward's grant or one of this host's rules by its id (the file's Close row): a BridgeWithdraw that drains,
// or resets with reset, or a GrantRevoke. Neither widens reach, so neither takes an approval, from any mode (§5.8).
func (self *BridgeFiler) Close(ctx context.Context, origin *BridgeFileOrigin, id []byte, reset bool) (*BridgeFiling, error) {
	if err := bridgeFileCheckOrigin(origin); err != nil {
		return nil, err
	}
	if len(id) != sha256.Size {
		return nil, fmt.Errorf("%w: an id of %d bytes", ErrBridgeFileRefused, len(id))
	}
	view, err := self.view(ctx)
	if err != nil {
		return nil, err
	}
	rule, err := view.ownRule(id)
	if err != nil {
		return nil, fmt.Errorf("%w: a BridgeWithdraw of another sidecar's rule", ErrBridgeFileRefused)
	}
	if rule != nil {
		if rule.Withdrawn != nil {
			return nil, fmt.Errorf("%w: the rule is withdrawn already", ErrBridgeFileRefused)
		}
		mode := bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN
		if reset {
			mode = bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET
		}
		act, err := self.args.Sidecar.newAct(origin.Act)
		if err != nil {
			return nil, err
		}
		// bodiless, so it never waits on a seal (§17.8)
		if err := act.Add(bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, &bridge.BridgeWithdraw{RuleId: bytes.Clone(id), Mode: mode}); err != nil {
			return nil, err
		}
		if _, err := self.runAct(ctx, act, origin); err != nil {
			return nil, err
		}
		kind := bridgeRouteRecordRoute
		if rule.SignedType == bridge.SignedType_SIGNED_BRIDGE_MAP {
			kind = bridgeRouteRecordMap
		}
		self.recordRoute(origin, nil, nil, &RecordRouteArgs{
			Event: bridgeRouteRecordClosed, Kind: kind, RuleId: bytes.Clone(id), TargetSidecarId: &view.self, Reason: bridgeRouteRecordWithdrawn,
		})
		return &BridgeFiling{RuleId: bytes.Clone(id)}, nil
	}

	acl, err := view.state.Acl()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileNoState, err)
	}
	grant := acl.grantRule(id)
	if grant == nil || !acl.grantSubjectIs(grant, view.self) ||
		!(grant.allows(protocol.AclAction_ACL_ACTION_DIAL) || grant.allows(protocol.AclAction_ACL_ACTION_ROUTE)) {
		return nil, fmt.Errorf("%w: no rule of this host's and no forward's grant of its own under the id", ErrBridgeFileRefused)
	}
	if self.args.Grants == nil {
		return nil, fmt.Errorf("%w: no grant filer", ErrBridgeFileRefused)
	}
	if err := self.args.Grants.Revoke(ctx, id, origin.Act, origin.Check); err != nil {
		return nil, err
	}
	self.recordRoute(origin, nil, id, &RecordRouteArgs{Event: bridgeRouteRecordClosed, Kind: bridgeRouteRecordForward, Reason: bridgeRouteRecordRevoked})
	return &BridgeFiling{GrantId: bytes.Clone(id)}, nil
}

// Files this host's BridgeAddress (the file's ClaimAddress row): at address, which must lie in the block's lower /17 and
// be free (ValidateBridgeAddress), or, invalid, at the allocator's draw. A person's command alone, never an agent's or a
// hook's: an agent's host is addressed only by its approved first map.
func (self *BridgeFiler) ClaimAddress(ctx context.Context, origin *BridgeFileOrigin, address netip.Addr) (*BridgeFiling, error) {
	if err := bridgeFileCheckOrigin(origin); err != nil {
		return nil, err
	}
	if origin.Act == SidecarActMcp || origin.Act == SidecarActHook {
		return nil, fmt.Errorf("%w: %w: an address is claimed by a person's command", ErrBridgeFileRefused, ErrSidecarActMode)
	}
	view, err := self.view(ctx)
	if err != nil {
		return nil, err
	}
	if view.block == nil {
		return nil, fmt.Errorf("%w: the network has no block yet", ErrBridgeFileNoState)
	}
	plan, err := NewBridgeAddressPlan(view.block, view.ledger)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileNoState, err)
	}
	if view.ledger.Address(view.self) != nil {
		return nil, fmt.Errorf("%w: this host holds an address already", ErrBridgeFileRefused)
	}
	var ipv4 uint32
	if address.IsValid() {
		var ok bool
		if ipv4, ok = bridgeIpv4Of(address); !ok {
			return nil, fmt.Errorf("%w: %w: an address that is no IPv4", ErrBridgeFileRefused, ErrBridgeAddressInvalid)
		}
		if err := ValidateBridgeAddress(plan, ipv4); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
		}
	} else if ipv4, err = AllocateBridgeAddress(plan, self.random); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
	}
	next, err := self.claimAddress(ctx, origin, view, view.self, ipv4)
	if err != nil {
		return nil, err
	}
	held := next.address()
	if held != bridgeAddressOf(ipv4) {
		// another host's claim came first in log order (§17.4)
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, ErrBridgeAddressTaken)
	}
	return &BridgeFiling{Address: held, AddressFiled: true}, nil
}

// One subject's egress spec (§17.9): auto, exits through the sidecars named or tagged, or none.
type BridgeEgressRequest struct {
	Subject Id
	Mode    bridge.BridgeEgressMode
	// Under exits, the exits by id or their tag, not both.
	ExitSidecarIds []Id
	ExitTagId      Id
}

// The statement and the body an egress spec files: the mode in the clear, and under exits only a sealed body.
func bridgeEgressStatement(request *BridgeEgressRequest) (*bridge.BridgeEgress, *bridge.BridgeEgressBody, error) {
	if request == nil || request.Subject == (Id{}) {
		return nil, nil, fmt.Errorf("%w: an egress spec names its subject", ErrBridgeFileRefused)
	}
	statement := &bridge.BridgeEgress{Subject: request.Subject.Bytes(), Mode: request.Mode}
	switch request.Mode {
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE:
		if len(request.ExitSidecarIds) != 0 || request.ExitTagId != (Id{}) {
			return nil, nil, fmt.Errorf("%w: exits under mode %s", ErrBridgeFileRefused, request.Mode)
		}
		return statement, nil, nil
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS:
		if (len(request.ExitSidecarIds) == 0) == (request.ExitTagId == (Id{})) {
			return nil, nil, fmt.Errorf("%w: exits names its sidecars or one tag, not both", ErrBridgeFileRefused)
		}
		if bridgeBodyListMaxCount < len(request.ExitSidecarIds) {
			return nil, nil, fmt.Errorf("%w: %d exits", ErrBridgeFileRefused, len(request.ExitSidecarIds))
		}
		body := &bridge.BridgeEgressBody{}
		for _, exitId := range request.ExitSidecarIds {
			body.ExitSidecarIds = append(body.ExitSidecarIds, exitId.Bytes())
		}
		if request.ExitTagId != (Id{}) {
			body.ExitTagId = request.ExitTagId.Bytes()
		}
		return statement, body, nil
	}
	return nil, nil, fmt.Errorf("%w: egress mode %d", ErrBridgeFileRefused, request.Mode)
}

// The CanonicalAction an egress change asks for. Kind egress_change has no row in the kind table (QD-429), so
// NewCanonicalAction refuses it until its fields are named (question bridge-m4-19-egress-change-action): every
// SetEgress is refused at the gate meanwhile, the closed direction.
func bridgeEgressAction(request *BridgeEgressRequest) (*StoredCanonicalAction, error) {
	return NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionEgressChange), Subject: request.Subject.Bytes()})
}

// Files a subject's egress spec (the file's SetEgress row): a person's confirmation and the gate's pass, which kind
// egress_change cannot get yet, so it is refused there. The verifiers hold its signer to an admin, the subject's owner
// or its sponsor.
func (self *BridgeFiler) SetEgress(ctx context.Context, origin *BridgeFileOrigin, request *BridgeEgressRequest) (*BridgeFiling, error) {
	if err := bridgeFileCheckOrigin(origin); err != nil {
		return nil, err
	}
	if origin.Act != SidecarActConfirmed {
		return nil, fmt.Errorf("%w: %w: egress is set by a person's confirmed command", ErrBridgeFileRefused, ErrSidecarActMode)
	}
	if _, _, err := bridgeEgressStatement(request); err != nil {
		return nil, err
	}
	stored, err := bridgeEgressAction(request)
	if err != nil {
		return nil, fmt.Errorf("%w: no approval can be asked for an egress change yet: %w", ErrBridgeFileRefused, err)
	}
	action, err := self.newAction(origin, stored, &bridgeEgressEffect{filer: self, origin: origin, request: request}, nil)
	if err != nil {
		return nil, err
	}
	if _, err := self.authorize(ctx, origin, action); err != nil {
		return nil, err
	}
	return &BridgeFiling{}, nil
}

// An egress change's effect: the BridgeEgress, as a person's confirmed act.
type bridgeEgressEffect struct {
	filer   *BridgeFiler
	origin  *BridgeFileOrigin
	request *BridgeEgressRequest
}

// Files the BridgeEgress; auto and none carry no body, so they never wait on a seal.
func (self *bridgeEgressEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	if self.origin.Act != SidecarActConfirmed {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, ErrSidecarActMode)
	}
	statement, body, err := bridgeEgressStatement(self.request)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	if body != nil {
		_, err = self.filer.fileSealed(ctx, self.origin, bridge.SignedType_SIGNED_BRIDGE_EGRESS, statement, body)
		return nil, err
	}
	act, err := self.filer.args.Sidecar.newAct(self.origin.Act)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	if err := act.Add(bridge.SignedType_SIGNED_BRIDGE_EGRESS, statement); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	_, err = self.filer.runAct(ctx, act, self.origin)
	return nil, err
}

// What SetBlock writes: a block drawn at random (cycle), or an admin's /16 of 100.64.0.0/10 or RFC 1918.
type BridgeBlockRequest struct {
	Cycle  bool
	Prefix netip.Prefix
}

// Writes the network's BridgeBlock into a config head (the file's SetBlock row) and answers it. The block in force, if
// any, becomes its previous_prefix, draining for BlockDrainTimeout. Refused what CheckBridgeBlock refuses, and before any
// head is written where this device's own signature would not pass a reader's admin check.
func (self *BridgeFiler) SetBlock(ctx context.Context, origin *BridgeFileOrigin, request *BridgeBlockRequest) (*bridge.BridgeBlock, error) {
	if err := bridgeFileCheckOrigin(origin); err != nil {
		return nil, err
	}
	if origin.Act != SidecarActConfirmed {
		return nil, fmt.Errorf("%w: %w: the block is set by a person's confirmed command", ErrBridgeFileRefused, ErrSidecarActMode)
	}
	if request == nil || request.Cycle == request.Prefix.IsValid() {
		return nil, fmt.Errorf("%w: cycle, or a block, not both", ErrBridgeFileRefused)
	}
	var writer BridgeHeadWriter
	if self.args.HeadWriter != nil {
		writer = self.args.HeadWriter()
	}
	if writer == nil {
		return nil, fmt.Errorf("%w: no config writer runs for this network on this device", ErrBridgeFileRefused)
	}
	view, err := self.view(ctx)
	if err != nil {
		return nil, err
	}
	current := view.block.GetIpv4Prefix()
	var prefix *bridge.BridgeIpv4Prefix
	if request.Cycle {
		for range max(1, self.settings.BlockDrawAttemptCount) {
			drawn, err := ChooseBridgeBlock(self.random)
			if err != nil {
				return nil, err
			}
			if !proto.Equal(drawn, current) {
				prefix = drawn
				break
			}
		}
		if prefix == nil {
			return nil, fmt.Errorf("%w: every draw gave the block in force", ErrBridgeFileRefused)
		}
	} else {
		ipv4, ok := bridgeIpv4Of(request.Prefix.Addr())
		if !ok || request.Prefix.Masked() != request.Prefix {
			return nil, fmt.Errorf("%w: %w: a block is a masked IPv4 /16", ErrBridgeFileRefused, ErrBridgeBlockRefused)
		}
		prefix = &bridge.BridgeIpv4Prefix{Address: ipv4, Length: uint32(request.Prefix.Bits())}
	}
	block := &bridge.BridgeBlock{Ipv4Prefix: prefix}
	if current != nil {
		block.PreviousPrefix = proto.Clone(current).(*bridge.BridgeIpv4Prefix)
		block.DrainUntil = self.clock.Now().Add(self.settings.BlockDrainTimeout).UnixMilli()
	}
	if err := CheckBridgeBlock(block); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeFileRefused, err)
	}
	signedBytes, err := configSignRecord(func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return self.args.Sidecar.Sign(purpose, signedType, body, nil)
	}, bridge.SignedType_SIGNED_BRIDGE_BLOCK, block)
	if err != nil {
		return nil, err
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil, err
	}
	// every reader keeps the previous block where the record's signer is no admin's device: write no head they refuse
	if err := configHeadRecordSignedByAdmin(view.state, signed, bridge.SignedType_SIGNED_BRIDGE_BLOCK); err != nil {
		return nil, fmt.Errorf("%w: %w: %w", ErrBridgeFileRefused, ErrBridgeBlockRefused, err)
	}
	if _, err := writer.SaveHead(ctx, func(head *ConfigHead) (*ConfigHead, error) {
		return head.WithFile(ConfigHeadBridgeBlockPath, signedBytes)
	}); err != nil {
		return nil, err
	}
	return block, nil
}

// The rule the authorization log holds under ruleId as this host's (the file's FindRule row), in force, held, pending,
// void or withdrawn alike, as the ledger reads it at the newest verified state; nil for none. Refused for an id another
// sidecar's rule holds.
func (self *BridgeFiler) FindRule(ctx context.Context, ruleId []byte) (*BridgeLedgerRule, error) {
	if len(ruleId) != bridgeRuleIdByteCount {
		return nil, fmt.Errorf("%w: a rule id of %d bytes", ErrBridgeFileRefused, len(ruleId))
	}
	view, err := self.view(ctx)
	if err != nil {
		return nil, err
	}
	return view.ownRule(ruleId)
}

// The bridge component's Lookup (§16.6's step 5), from the stored action and its effect key: done with the rule id once
// the log holds the rule the key fixes, uncertain while it does not, since a pending post may still land.
func (self *BridgeFiler) Lookup(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
	if len(effectKey) != sha256.Size {
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	}
	ruleId := BridgeRuleId([sha256.Size]byte(effectKey))
	rule, err := self.FindRule(ctx, ruleId[:])
	if err != nil || rule == nil {
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	}
	return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: ruleId[:]}, nil
}

// Registers Lookup for bridge_expose on the sidecar's gate, so the gate reserves an exposure's use; the answer removes
// it. MCP-M4-01's bridge component may register its own in its place.
func (self *BridgeFiler) Register() func() {
	return self.args.Sidecar.RegisterEffectLookup(SidecarActionExpose, self.Lookup)
}
