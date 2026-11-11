// §17's device role on fakes (BRIDGE-M4-06): BridgeRulesFixture writes a device's BridgeRules from a compact literal,
// so the tasks that build on rules need no compiler, and FakeBridgeHost stands in for the sdk's and the CLI's
// device.BridgeHost, so links need no client generator.
//
// A literal names prefixes and addresses as strings netip parses, and every id by a seed: one byte standing for a
// synthetic client, sidecar, member, identity key, route, map or grant, each of its own form, so two kinds of id from
// one seed never meet. Times are ms since the epoch, 0 for none. Nothing here is a real identity or address (CODESTYLE's
// test data rule).

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What each kind of fixture id begins with, so one seed gives distinct ids.
const (
	bridgeFixtureClientMark    = 0xC1
	bridgeFixtureSidecarMark   = 0x5C
	bridgeFixtureMemberMark    = 0x3E
	bridgeFixtureKeyMark       = 0xE0
	bridgeFixtureRouteMark     = 0x40
	bridgeFixtureMapMark       = 0x3A
	bridgeFixtureGrantMark     = 0x6A
	bridgeFixtureWindowMark    = 0xF0
	bridgeFixtureWindowKeyMark = 0xF1
)

// byteCount bytes alternating mark and seed.
func bridgeFixtureBytes(mark byte, seed byte, byteCount int) []byte {
	return bytes.Repeat([]byte{mark, seed}, byteCount/2)
}

// The synthetic client a seed stands for: a link's target, or a subject's bound client.
func BridgeFixtureClientId(seed byte) connect.Id {
	return connect.Id(bridgeFixtureBytes(bridgeFixtureClientMark, seed, 16))
}

// The synthetic sidecar_id a seed stands for.
func BridgeFixtureSidecarId(seed byte) []byte {
	return bridgeFixtureBytes(bridgeFixtureSidecarMark, seed, 16)
}

// The synthetic member_id a seed stands for: the member an untagged sidecar of that seed belongs to.
func BridgeFixtureMemberId(seed byte) []byte {
	return bridgeFixtureBytes(bridgeFixtureMemberMark, seed, 16)
}

// The synthetic identity key a seed stands for.
func BridgeFixtureIdentityKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bridgeFixtureBytes(bridgeFixtureKeyMark, seed, ed25519.SeedSize))
}

// The synthetic route_id, map_id and grant_id a seed stands for, 32 bytes each.
func BridgeFixtureRouteId(seed byte) []byte {
	return bridgeFixtureBytes(bridgeFixtureRouteMark, seed, 32)
}

func BridgeFixtureMapId(seed byte) []byte {
	return bridgeFixtureBytes(bridgeFixtureMapMark, seed, 32)
}

func BridgeFixtureGrantId(seed byte) []byte {
	return bridgeFixtureBytes(bridgeFixtureGrantMark, seed, 32)
}

// A device's rules as a literal. See the file's comment.
type BridgeRulesFixture struct {
	// A /16, "" for none.
	Block                   string
	PreviousBlock           string
	PreviousBlockDrainUntil int64
	// This host's addresses.
	Addresses []string
	Entries   []BridgeRulesFixtureEntry
	Maps      []BridgeRulesFixtureMap
	Served    []BridgeRulesFixtureServed
	Subjects  []BridgeRulesFixtureSubject
	// Nil leaves the egress unset.
	Egress *BridgeRulesFixtureEgress
	// The rows autogroup:untagged holds at this host (BridgeRules.untagged), which an sdk provider gives another
	// client. Nil leaves the field unset, so another client holds no rows.
	Untagged *BridgeRulesFixtureUntagged
}

// autogroup:untagged's rows: a subject's, with no ids, since they name no one.
type BridgeRulesFixtureUntagged struct {
	Dial  []BridgeRulesFixtureReach
	Route []BridgeRulesFixtureReach
	Exit  []BridgeRulesFixtureReach
}

// A sender entry: a prefix, its kind, zero for a link entry, and its links.
type BridgeRulesFixtureEntry struct {
	Prefix string
	Kind   bridge.BridgeRuleEntryKind
	Links  []BridgeRulesFixtureLink
}

// A link to a target.
type BridgeRulesFixtureLink struct {
	// The target's seed: its client, sidecar, member and key.
	Target byte
	// A tagged target has no member.
	Tagged bool
	// The advertising route's seed; 0 for an overlay address, which has no rule id.
	Route byte
	// 0 is 1.
	Weight        uint32
	Site          string
	DrainingSince int64
	DrainUntil    int64
}

// A map this host holds.
type BridgeRulesFixtureMap struct {
	Map byte
	// A prefix, or an address standing for its /32.
	Match string
	// A protocol and its ports, as BridgeRulesFixtureReach writes them.
	Ports string
	// An address and port; port 0 keeps the port.
	Target        string
	Expires       int64
	DrainingSince int64
	DrainUntil    int64
}

// A prefix this host serves, or the exit it is.
type BridgeRulesFixtureServed struct {
	Route byte
	Exit  bool
	// Unread for an exit, which serves 0.0.0.0/0.
	Prefix string
	// "" for no remap.
	Exposed       string
	DrainingSince int64
	DrainUntil    int64
}

// A subject that may reach this host.
type BridgeRulesFixtureSubject struct {
	Sidecar byte
	Tagged  bool
	// Its clients' seeds; nil binds one, of the sidecar's own seed.
	Clients []byte
	Dial    []BridgeRulesFixtureReach
	Route   []BridgeRulesFixtureReach
	Exit    []BridgeRulesFixtureReach
}

// A row of reach.
type BridgeRulesFixtureReach struct {
	// Route rows only.
	Prefix string
	// "*" for every protocol and port, "icmp", "tcp" or "udp" for every port of one, or with ports:
	// "tcp:443", "udp:53,123", "tcp:8000-8010".
	Ports string
	// 0 for a policy rule.
	Grant   byte
	Expires int64
}

// The device's own default route.
type BridgeRulesFixtureEgress struct {
	Mode  bridge.BridgeEgressMode
	Exits []BridgeRulesFixtureLink
}

// The literal as rules. Panics on what it cannot read.
func (self *BridgeRulesFixture) Rules() *bridge.BridgeRules {
	rules := &bridge.BridgeRules{
		Block:                   bridgeFixturePrefix(self.Block),
		PreviousBlock:           bridgeFixturePrefix(self.PreviousBlock),
		PreviousBlockDrainUntil: self.PreviousBlockDrainUntil,
	}
	for _, address := range self.Addresses {
		rules.Addresses = append(rules.Addresses, bridgeFixtureAddress(netip.MustParseAddr(address)))
	}
	for _, entry := range self.Entries {
		kind := entry.Kind
		if kind == bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_UNSPECIFIED {
			kind = bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK
		}
		ruleEntry := &bridge.BridgeRuleEntry{Prefix: bridgeFixturePrefix(entry.Prefix), Kind: kind}
		for _, link := range entry.Links {
			ruleEntry.Links = append(ruleEntry.Links, link.rule())
		}
		rules.Entries = append(rules.Entries, ruleEntry)
	}
	for _, fixtureMap := range self.Maps {
		protocolNumber, ports := bridgeFixturePorts(fixtureMap.Ports)
		target := netip.MustParseAddrPort(fixtureMap.Target)
		rules.Maps = append(rules.Maps, &bridge.BridgeRuleMap{
			MapId:         BridgeFixtureMapId(fixtureMap.Map),
			MatchPrefix:   bridgeFixturePrefix(fixtureMap.Match),
			Protocol:      protocolNumber,
			Ports:         ports,
			Target:        target.Addr().AsSlice(),
			TargetPort:    uint32(target.Port()),
			Expires:       fixtureMap.Expires,
			DrainingSince: fixtureMap.DrainingSince,
			DrainUntil:    fixtureMap.DrainUntil,
		})
	}
	for _, served := range self.Served {
		ruleServed := &bridge.BridgeRuleServed{
			RouteId:       BridgeFixtureRouteId(served.Route),
			Kind:          bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET,
			Prefix:        bridgeFixturePrefix(served.Prefix),
			ExposedPrefix: bridgeFixturePrefix(served.Exposed),
			DrainingSince: served.DrainingSince,
			DrainUntil:    served.DrainUntil,
		}
		if served.Exit {
			ruleServed.Kind = bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT
			ruleServed.Prefix = &bridge.BridgeIpv4Prefix{}
			ruleServed.ExposedPrefix = nil
		}
		rules.Served = append(rules.Served, ruleServed)
	}
	for _, subject := range self.Subjects {
		ruleSubject := &bridge.BridgeRuleSubject{
			SidecarId: BridgeFixtureSidecarId(subject.Sidecar),
			Tagged:    subject.Tagged,
		}
		if !subject.Tagged {
			ruleSubject.MemberId = BridgeFixtureMemberId(subject.Sidecar)
		}
		clients := subject.Clients
		if clients == nil {
			clients = []byte{subject.Sidecar}
		}
		for _, client := range clients {
			clientId := BridgeFixtureClientId(client)
			ruleSubject.ClientIds = append(ruleSubject.ClientIds, clientId[:])
		}
		ruleSubject.Dial = bridgeFixtureReach(subject.Dial)
		ruleSubject.Route = bridgeFixtureReach(subject.Route)
		ruleSubject.Exit = bridgeFixtureReach(subject.Exit)
		rules.Subjects = append(rules.Subjects, ruleSubject)
	}
	if self.Egress != nil {
		rules.Egress = &bridge.BridgeRuleEgress{Mode: self.Egress.Mode}
		for _, link := range self.Egress.Exits {
			rules.Egress.Exits = append(rules.Egress.Exits, link.rule())
		}
	}
	if self.Untagged != nil {
		rules.Untagged = &bridge.BridgeRuleSubject{
			Dial:  bridgeFixtureReach(self.Untagged.Dial),
			Route: bridgeFixtureReach(self.Untagged.Route),
			Exit:  bridgeFixtureReach(self.Untagged.Exit),
		}
	}
	return rules
}

// The rules' deterministic bytes, as a compiler writes BridgeState.rules.
func (self *BridgeRulesFixture) Bytes() []byte {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(self.Rules())
	if err != nil {
		panic(err)
	}
	return encoded
}

// The link as a row.
func (self BridgeRulesFixtureLink) rule() *bridge.BridgeRuleLink {
	clientId := BridgeFixtureClientId(self.Target)
	link := &bridge.BridgeRuleLink{
		TargetClientId:          clientId[:],
		TargetSidecarId:         BridgeFixtureSidecarId(self.Target),
		TargetIdentityPublicKey: BridgeFixtureIdentityKey(self.Target).Public().(ed25519.PublicKey),
		Weight:                  max(self.Weight, 1),
		DrainingSince:           self.DrainingSince,
		DrainUntil:              self.DrainUntil,
	}
	if !self.Tagged {
		link.TargetMemberId = BridgeFixtureMemberId(self.Target)
	}
	if self.Route != 0 {
		link.RuleId = BridgeFixtureRouteId(self.Route)
	}
	if self.Site != "" {
		link.SiteId = []byte(self.Site)
	}
	return link
}

// Rows of reach from their literals.
func bridgeFixtureReach(rows []BridgeRulesFixtureReach) []*bridge.BridgeRuleReach {
	reachRows := []*bridge.BridgeRuleReach{}
	for _, row := range rows {
		protocolNumber, ports := bridgeFixturePorts(row.Ports)
		reach := &bridge.BridgeRuleReach{
			Prefix:   bridgeFixturePrefix(row.Prefix),
			Protocol: protocolNumber,
			Ports:    ports,
			Expires:  row.Expires,
		}
		if row.Grant != 0 {
			reach.GrantId = BridgeFixtureGrantId(row.Grant)
		}
		reachRows = append(reachRows, reach)
	}
	return reachRows
}

// An IPv4 address as the rules hold it.
func bridgeFixtureAddress(address netip.Addr) uint32 {
	if !address.Is4() {
		panic(fmt.Sprintf("bridge fixture: %s is not IPv4", address))
	}
	octets := address.As4()
	return uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])
}

// A prefix, or an address as its /32, as the rules hold it; nil for "".
func bridgeFixturePrefix(literal string) *bridge.BridgeIpv4Prefix {
	if literal == "" {
		return nil
	}
	var prefix netip.Prefix
	if strings.Contains(literal, "/") {
		prefix = netip.MustParsePrefix(literal)
	} else {
		prefix = netip.PrefixFrom(netip.MustParseAddr(literal), 32)
	}
	return &bridge.BridgeIpv4Prefix{Address: bridgeFixtureAddress(prefix.Addr()), Length: uint32(prefix.Bits())}
}

// A protocol and its ports from "*", "icmp", "tcp", "udp" or "tcp:443,8000-8010".
func bridgeFixturePorts(literal string) (uint32, []*bridge.BridgePortRange) {
	name, list, _ := strings.Cut(literal, ":")
	protocolNumbers := map[string]uint32{"*": 0, "": 0, "icmp": 1, "tcp": 6, "udp": 17}
	protocolNumber, ok := protocolNumbers[name]
	if !ok {
		panic(fmt.Sprintf("bridge fixture: protocol %q", name))
	}
	ports := []*bridge.BridgePortRange{}
	if list == "" {
		return protocolNumber, ports
	}
	for _, item := range strings.Split(list, ",") {
		firstText, lastText, isRange := strings.Cut(item, "-")
		if !isRange {
			lastText = firstText
		}
		first, err := strconv.ParseUint(firstText, 10, 32)
		if err != nil {
			panic(fmt.Sprintf("bridge fixture: port %q", item))
		}
		last, err := strconv.ParseUint(lastText, 10, 32)
		if err != nil {
			panic(fmt.Sprintf("bridge fixture: port %q", item))
		}
		ports = append(ports, &bridge.BridgePortRange{First: uint32(first), Last: uint32(last)})
	}
	return protocolNumber, ports
}

// What a FakeBridgeHost built: the call's arguments, the window client it signed for and what sign returned.
type FakeBridgeBuild struct {
	Target         connect.Id
	Subject        connect.Id
	ShareAliases   []netip.Prefix
	WindowClientId connect.Id
	Delegation     []byte
	// Nil when sign or the host failed, and no link exists.
	Link *FakeBridgeLink
	Err  error
}

// A device.BridgeHost in memory. Each NewBridgeLink signs for one synthetic window client first, as a real host does
// before any contract, and builds a link only when sign returns a delegation, so a test sees every build, with no link
// ever lacking its delegation. Safe for concurrent use.
type FakeBridgeHost struct {
	stateLock sync.Mutex
	// the strict_exp each window client is given
	notAfter          time.Time
	buildErr          error
	builds            []FakeBridgeBuild
	windowClientCount byte
}

var _ device.BridgeHost = (*FakeBridgeHost)(nil)

// A host whose window clients expire at notAfter.
func NewFakeBridgeHost(notAfter time.Time) *FakeBridgeHost {
	return &FakeBridgeHost{notAfter: notAfter}
}

// The host's own failure, nil for none: every later build fails with it before signing anything.
func (self *FakeBridgeHost) SetBuildError(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.buildErr = err
}

// device.BridgeHost.
func (self *FakeBridgeHost) NewBridgeLink(ctx context.Context, target connect.Id, subject connect.Id,
	shareAliases []netip.Prefix,
	sign func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error),
) (connect.UserNatClient, error) {
	build, buildErr, notAfter := func() (FakeBridgeBuild, error, time.Time) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.windowClientCount += 1
		build := FakeBridgeBuild{
			Target:         target,
			Subject:        subject,
			ShareAliases:   append([]netip.Prefix(nil), shareAliases...),
			WindowClientId: connect.Id(bridgeFixtureBytes(bridgeFixtureWindowMark, self.windowClientCount, 16)),
		}
		return build, self.buildErr, self.notAfter
	}()
	record := func(build FakeBridgeBuild) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.builds = append(self.builds, build)
	}
	if buildErr != nil {
		build.Err = buildErr
		record(build)
		return nil, buildErr
	}
	if err := ctx.Err(); err != nil {
		build.Err = err
		record(build)
		return nil, err
	}
	windowKey := ed25519.NewKeyFromSeed(bridgeFixtureBytes(bridgeFixtureWindowKeyMark, build.WindowClientId[1], ed25519.SeedSize))
	delegation, err := sign(build.WindowClientId, windowKey.Public().(ed25519.PublicKey), notAfter)
	if err == nil && len(delegation) == 0 {
		err = errors.New("sign returned no delegation")
	}
	if err != nil {
		build.Err = err
		record(build)
		return nil, err
	}
	build.Delegation = delegation
	// the bypass starts on, so a test sees the bridge turn it off
	build.Link = &FakeBridgeLink{Target: target, localSecurityBypass: true}
	record(build)
	return build.Link, nil
}

// Every build so far, failures included, oldest first.
func (self *FakeBridgeHost) Builds() []FakeBridgeBuild {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]FakeBridgeBuild(nil), self.builds...)
}

// The links built to target, failures not counted.
func (self *FakeBridgeHost) BuildCount(target connect.Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, build := range self.builds {
		if build.Target == target && build.Link != nil {
			count += 1
		}
	}
	return count
}

// A link a FakeBridgeHost built: a connect.UserNatClient that keeps a copy of each packet it takes. Safe for
// concurrent use.
type FakeBridgeLink struct {
	Target connect.Id

	stateLock           sync.Mutex
	packets             [][]byte
	closed              bool
	localSecurityBypass bool
}

// connect.UserNatClient. Takes the packet on success, as a link does, keeping a copy and returning the buffer to the
// pool; a closed link takes nothing.
func (self *FakeBridgeLink) SendPacket(source connect.TransferPath, provideMode protocol.ProvideMode, packet []byte, timeout time.Duration) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return false
	}
	self.packets = append(self.packets, bytes.Clone(packet))
	connect.MessagePoolReturn(packet)
	return true
}

func (self *FakeBridgeLink) Close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
}

func (self *FakeBridgeLink) Shuffle() {}

func (self *FakeBridgeLink) SecurityPolicyStats(reset bool) connect.SecurityPolicyStats {
	return connect.SecurityPolicyStats{}
}

func (self *FakeBridgeLink) SetLocalSecurityBypass(localSecurityBypass bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.localSecurityBypass = localSecurityBypass
}

// Copies of the packets the link took, oldest first.
func (self *FakeBridgeLink) Packets() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([][]byte(nil), self.packets...)
}

// Whether Close ran.
func (self *FakeBridgeLink) Closed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

// What SetLocalSecurityBypass last set, on from the build: a bridge sets it off on every link (BRIDGE-M4-12).
func (self *FakeBridgeLink) LocalSecurityBypass() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.localSecurityBypass
}
