// §22.5's "hook = reference" for §17.6: a second, separately written walk of the provider hook's table, sharing no code
// with BridgeEgressPolicy, and the differential test that holds the two equal over generated states and flows. The
// reference reads the BridgeRules message and the input as they are, row by row, in the table's order, with its own
// address ranges, time checks and tag hash; FuzzBridgeEgressPolicy (bridge_egress_fuzz_test.go) drives the same
// comparison from fuzz bytes. The generator writes rules ParseBridgeRules takes, nearly always, from a byte stream, so a
// fuzzer steers it and a seeded source fills it.

package device_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What the reference decides; a Deny carries nothing else.
type egressReferenceDecision struct {
	verdict connect.EgressVerdict
	target  netip.AddrPort
	ruleTag uint64
	idle    time.Duration
	// the table's row that decided, for the generator's coverage
	row string
}

// The reference's ranges, written out.
var (
	egressReferenceNonPublicV4 = []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
	}
	egressReferenceNonPublicV6 = []string{"::/128", "::1/128", "fe80::/10", "fc00::/7", "ff00::/8"}
	egressReferenceRuleFive    = []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "0.0.0.0/32", "::1/128", "fe80::/10", "ff00::/8", "::/128"}
)

// Whether any of the written prefixes holds the address.
func egressReferenceIn(prefixes []string, addr netip.Addr) bool {
	for _, text := range prefixes {
		if netip.MustParsePrefix(text).Contains(addr) {
			return true
		}
	}
	return false
}

// A rules prefix, by its own reading of the fields.
func egressReferencePrefix(prefix *bridge.BridgeIpv4Prefix) (netip.Prefix, bool) {
	if prefix == nil {
		return netip.Prefix{}, false
	}
	value := prefix.GetAddress()
	addr := netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
	return netip.PrefixFrom(addr, int(prefix.GetLength())), true
}

// The tag, hashed here on its own.
func egressReferenceTag(subjectId connect.Id, ruleId []byte) uint64 {
	hash := sha256.New()
	hash.Write(subjectId[:])
	hash.Write(ruleId)
	return binary.BigEndian.Uint64(hash.Sum(nil)[:8])
}

// addr + (from - base), as big numbers; false past the space.
func egressReferenceOffset(addr netip.Addr, from netip.Addr, base netip.Addr) (netip.Addr, bool) {
	value := new(big.Int).SetBytes(addr.AsSlice())
	value.Add(value, new(big.Int).SetBytes(from.AsSlice()))
	value.Sub(value, new(big.Int).SetBytes(base.AsSlice()))
	size := len(addr.AsSlice())
	if value.Sign() < 0 || size*8 < value.BitLen() {
		return netip.Addr{}, false
	}
	result, ok := netip.AddrFromSlice(value.FillBytes(make([]byte, size)))
	return result, ok
}

// The reference walk of §17.6's table. See the file's comment.
func egressReferenceResolve(
	profile device.BridgePolicyProfile,
	input *device.BridgePolicyInput,
	flow *connect.EgressFlow,
	now time.Time,
	tcpIdle time.Duration,
	otherIdle time.Duration,
) egressReferenceDecision {
	deny := func(row string) egressReferenceDecision {
		return egressReferenceDecision{verdict: connect.EgressVerdictDeny, row: row}
	}
	sdk := profile == device.BridgePolicyProfileSdkProvider
	mode := flow.ProvideMode
	rules := input.Rules

	// before the numbered rules
	if sdk && input.State == device.PostureLegacy {
		return egressReferenceDecision{verdict: connect.EgressVerdictPass, row: "legacy"}
	}
	if sdk && mode != protocol.ProvideMode_Network && mode != protocol.ProvideMode_Service {
		return egressReferenceDecision{verdict: connect.EgressVerdictPass, row: "mode"}
	}
	if !sdk && mode != protocol.ProvideMode_Network && mode != protocol.ProvideMode_FriendsAndFamily {
		return deny("mode")
	}
	if flow.ContractClass == connect.ContractClassControl || flow.ContractClass == connect.ContractClassUnset {
		return deny("class")
	}
	if flow.ContractClass != connect.ContractClassData || mode == protocol.ProvideMode_Service {
		return deny("class")
	}
	protocolNumbers := map[connect.IpProtocol]uint32{connect.IpProtocolTcp: 6, connect.IpProtocolUdp: 17, connect.IpProtocolIcmp: 1}
	protocolNumber, known := protocolNumbers[flow.Protocol]
	if !known {
		return deny("protocol")
	}

	// the overlay's narrowing
	narrowedSubject := func(subject *bridge.BridgeRuleSubject) bool {
		for _, entry := range input.Overlay {
			switch entry.Kind {
			case device.PostureOverlaySidecarRevoke:
				if string(entry.Id) == string(subject.GetSidecarId()) {
					return true
				}
			case device.PostureOverlayMemberRevoke:
				if 0 < len(subject.GetMemberId()) && string(entry.Id) == string(subject.GetMemberId()) {
					return true
				}
			case device.PostureOverlaySuspend:
				if string(entry.Id) == string(subject.GetSidecarId()) ||
					(0 < len(subject.GetMemberId()) && string(entry.Id) == string(subject.GetMemberId())) {
					return true
				}
			}
		}
		return false
	}
	ruleReset := func(ruleId []byte) bool {
		for _, entry := range input.Overlay {
			if entry.Kind == device.PostureOverlayBridgeWithdraw && string(entry.Id) == string(ruleId) &&
				entry.WithdrawMode != bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN {
				return true
			}
		}
		return false
	}
	ruleDrained := func(ruleId []byte) bool {
		for _, entry := range input.Overlay {
			if entry.Kind == device.PostureOverlayBridgeWithdraw && string(entry.Id) == string(ruleId) &&
				entry.WithdrawMode == bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN {
				return true
			}
		}
		return false
	}
	grantRevoked := func(grantId []byte) bool {
		for _, entry := range input.Overlay {
			if entry.Kind == device.PostureOverlayGrantRevoke && 0 < len(grantId) && string(entry.Id) == string(grantId) {
				return true
			}
		}
		return false
	}

	// the subject
	var subject *bridge.BridgeRuleSubject
	var subjectId connect.Id
	if sdk {
		for _, candidate := range rules.GetSubjects() {
			for _, clientId := range candidate.GetClientIds() {
				if string(clientId) == string(flow.SourceSubject[:]) {
					subject = candidate
				}
			}
		}
		if subject != nil {
			for _, identity := range input.BridgeState.GetIdentities() {
				if string(identity.GetSidecarId()) == string(subject.GetSidecarId()) && (identity.GetRevoked() || identity.GetSuspended()) {
					return deny("subject")
				}
			}
			if narrowedSubject(subject) {
				return deny("subject")
			}
			subjectId = connect.Id(subject.GetSidecarId())
		}
	} else {
		principal := flow.Principal
		if principal == nil {
			return deny("principal")
		}
		for _, candidate := range rules.GetSubjects() {
			if string(candidate.GetSidecarId()) == string(principal.Subject[:]) {
				subject = candidate
			}
		}
		if subject == nil {
			return deny("principal")
		}
		var identity *bridge.BridgeIdentity
		for _, candidate := range input.BridgeState.GetIdentities() {
			if string(candidate.GetSidecarId()) == string(principal.Subject[:]) {
				identity = candidate
			}
		}
		if identity == nil || identity.GetRevoked() || identity.GetSuspended() || narrowedSubject(subject) {
			return deny("principal")
		}
		if len(input.NetworkId) != 16 || connect.Id(input.NetworkId) == (connect.Id{}) || principal.Network != connect.Id(input.NetworkId) {
			return deny("principal")
		}
		if principal.ShareId != (connect.Id{}) || !principal.NotAfter.After(now) || !flow.Sealed {
			return deny("principal")
		}
		if mode == protocol.ProvideMode_FriendsAndFamily {
			return deny("principal")
		}
		subjectId = principal.Subject
	}
	if input.State != device.PostureEnforcingDocument && input.State != device.PostureEnforcingNoDocument {
		return deny("state")
	}
	if rules == nil || input.BridgeState == nil {
		return deny("state")
	}

	addr := flow.To.Addr().Unmap()
	port := flow.To.Port()
	if protocolNumber == 1 {
		port = 0
	}
	idle := time.Duration(0)
	if !sdk {
		idle = otherIdle
		if protocolNumber == 6 {
			idle = tcpIdle
		}
	}
	tagged := subject != nil && subject.GetTagged()
	noDocumentUntagged := input.State == device.PostureEnforcingNoDocument && !tagged
	admitted := func(row string, verdict connect.EgressVerdict, target netip.AddrPort, ruleId []byte) egressReferenceDecision {
		return egressReferenceDecision{verdict: verdict, target: target, ruleTag: egressReferenceTag(subjectId, ruleId), idle: idle, row: row}
	}

	// times
	drainEnd := func(since int64, until int64) time.Time {
		end := time.UnixMilli(since).Add(max(tcpIdle, otherIdle))
		if time.UnixMilli(until).After(end) {
			return time.UnixMilli(until)
		}
		return end
	}
	block, hasBlock := egressReferencePrefix(rules.GetBlock())
	previousBlock, hasPrevious := egressReferencePrefix(rules.GetPreviousBlock())
	inBlocks := func(candidate netip.Addr) bool {
		return (hasBlock && block.Contains(candidate)) || (hasPrevious && previousBlock.Contains(candidate))
	}
	previousLapsed := func(candidate netip.Addr) bool {
		return hasPrevious && previousBlock.Contains(candidate) && !now.Before(time.UnixMilli(rules.GetPreviousBlockDrainUntil()))
	}

	// rows
	rowAdmits := func(row *bridge.BridgeRuleReach) bool {
		if grantRevoked(row.GetGrantId()) || (row.GetExpires() != 0 && !now.Before(time.UnixMilli(row.GetExpires()))) {
			return false
		}
		switch row.GetProtocol() {
		case 0:
			return true
		case protocolNumber:
		default:
			return false
		}
		if len(row.GetPorts()) == 0 {
			return true
		}
		if protocolNumber == 1 {
			return false
		}
		for _, portRange := range row.GetPorts() {
			if uint32(port) >= portRange.GetFirst() && uint32(port) <= portRange.GetLast() {
				return true
			}
		}
		return false
	}
	anyRow := func(rows []*bridge.BridgeRuleReach, routeAddr *netip.Addr) bool {
		for _, row := range rows {
			if routeAddr != nil {
				rowPrefix, _ := egressReferencePrefix(row.GetPrefix())
				if !rowPrefix.Contains(*routeAddr) {
					continue
				}
			}
			if rowAdmits(row) {
				return true
			}
		}
		return false
	}
	dial := func() bool { return subject != nil && anyRow(subject.GetDial(), nil) }
	route := func(destination netip.Addr) bool { return subject != nil && anyRow(subject.GetRoute(), &destination) }
	exit := func() bool { return subject != nil && anyRow(subject.GetExit(), nil) }

	// rule 0
	daemon := func(candidate netip.Addr, candidatePort uint16) bool {
		if candidatePort == 0 {
			return false
		}
		local := candidate.IsLoopback() || candidate.IsUnspecified() || input.LocalAddresses == nil
		for _, localAddr := range input.LocalAddresses {
			if localAddr.Unmap() == candidate {
				local = true
			}
		}
		unknown := false
		ports := []uint16{}
		for _, listener := range input.BridgeState.GetDaemonListeners() {
			host, portText, err := net.SplitHostPort(listener)
			listenerPort, portErr := strconv.ParseUint(portText, 10, 16)
			if err != nil || portErr != nil || listenerPort == 0 {
				unknown = true
				continue
			}
			ports = append(ports, uint16(listenerPort))
			if hostAddr, err := netip.ParseAddr(host); err == nil && !hostAddr.IsUnspecified() && hostAddr.Unmap() == candidate {
				local = true
			}
		}
		if !local {
			return false
		}
		if unknown {
			return true
		}
		for _, listenerPort := range ports {
			if listenerPort == candidatePort {
				return true
			}
		}
		return false
	}
	if daemon(addr, port) {
		return deny("0")
	}

	if !sdk {
		// rule 1
		for _, ruleMap := range rules.GetMaps() {
			match, _ := egressReferencePrefix(ruleMap.GetMatchPrefix())
			if ruleMap.GetProtocol() != protocolNumber || !match.Contains(addr) || previousLapsed(addr) {
				continue
			}
			if ruleReset(ruleMap.GetMapId()) || ruleDrained(ruleMap.GetMapId()) || ruleMap.GetDrainingSince() != 0 {
				continue
			}
			if ruleMap.GetExpires() != 0 && !now.Before(time.UnixMilli(ruleMap.GetExpires())) {
				continue
			}
			if 0 < len(ruleMap.GetPorts()) {
				inRange := false
				for _, portRange := range ruleMap.GetPorts() {
					inRange = inRange || (uint32(port) >= portRange.GetFirst() && uint32(port) <= portRange.GetLast())
				}
				if !inRange {
					continue
				}
			}
			if !dial() {
				return deny("1")
			}
			target, _ := netip.AddrFromSlice(ruleMap.GetTarget())
			target = target.Unmap()
			if match.Bits() < 32 {
				var ok bool
				if target, ok = egressReferenceOffset(target, addr, match.Addr()); !ok {
					return deny("1")
				}
			}
			targetPort := port
			if ruleMap.GetTargetPort() != 0 {
				targetPort = uint16(ruleMap.GetTargetPort() + uint32(port) - ruleMap.GetPorts()[0].GetFirst())
			}
			if inBlocks(target) || daemon(target, targetPort) {
				return deny("1")
			}
			return admitted("1", connect.EgressVerdictMap, netip.AddrPortFrom(target, targetPort), ruleMap.GetMapId())
		}
		// rule 6's remaps
		for _, served := range rules.GetServed() {
			exposed, hasExposed := egressReferencePrefix(served.GetExposedPrefix())
			if served.GetKind() != bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET || !hasExposed || !exposed.Contains(addr) {
				continue
			}
			if previousLapsed(addr) || ruleReset(served.GetRouteId()) ||
				(served.GetDrainingSince() != 0 && !now.Before(drainEnd(served.GetDrainingSince(), served.GetDrainUntil()))) {
				continue
			}
			if !noDocumentUntagged && !route(addr) {
				return deny("1_remap")
			}
			prefix, _ := egressReferencePrefix(served.GetPrefix())
			remapped, _ := egressReferenceOffset(prefix.Addr(), addr, exposed.Addr())
			if daemon(remapped, port) {
				return deny("1_remap")
			}
			return admitted("1_remap", connect.EgressVerdictMap, netip.AddrPortFrom(remapped, port), served.GetRouteId())
		}
		hosted := false
		for _, address := range rules.GetAddresses() {
			if egressReferenceAddr(address) == addr && !previousLapsed(addr) {
				hosted = true
			}
		}
		// rule 2
		if inBlocks(addr) && !hosted {
			return deny("2")
		}
		// rule 3
		if hosted {
			if !noDocumentUntagged && !dial() {
				return deny("3")
			}
			loopback := netip.MustParseAddr("127.0.0.1")
			if daemon(loopback, port) {
				return deny("3")
			}
			return admitted("3", connect.EgressVerdictMap, netip.AddrPortFrom(loopback, port), []byte{3})
		}
	} else if inBlocks(addr) {
		return deny("block")
	}
	// rule 4
	if noDocumentUntagged {
		return admitted("4", connect.EgressVerdictPass, netip.AddrPort{}, []byte{4})
	}
	// rule 5
	if egressReferenceIn(egressReferenceRuleFive, addr) {
		return deny("5")
	}
	// rule 6
	if !sdk {
		for _, served := range rules.GetServed() {
			prefix, _ := egressReferencePrefix(served.GetPrefix())
			if served.GetKind() != bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET || !prefix.Contains(addr) {
				continue
			}
			if ruleReset(served.GetRouteId()) ||
				(served.GetDrainingSince() != 0 && !now.Before(drainEnd(served.GetDrainingSince(), served.GetDrainUntil()))) {
				continue
			}
			if route(addr) {
				return admitted("6", connect.EgressVerdictPass, netip.AddrPort{}, served.GetRouteId())
			}
			return deny("6")
		}
	}
	// rule 7
	public := false
	if addr.Is4() {
		public = !egressReferenceIn(egressReferenceNonPublicV4, addr)
	} else {
		public = !egressReferenceIn(egressReferenceNonPublicV6, addr)
	}
	if public {
		if !sdk {
			servesExit := false
			for _, served := range rules.GetServed() {
				if served.GetKind() != bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT || ruleReset(served.GetRouteId()) {
					continue
				}
				if served.GetDrainingSince() == 0 || now.Before(drainEnd(served.GetDrainingSince(), served.GetDrainUntil())) {
					servesExit = true
				}
			}
			if !servesExit {
				return deny("7")
			}
		}
		if exit() {
			return admitted("7", connect.EgressVerdictPass, netip.AddrPort{}, []byte{7})
		}
		return deny("7")
	}
	// rule 8
	return deny("8")
}

// A rules address, read on its own.
func egressReferenceAddr(address uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(address >> 24), byte(address >> 16), byte(address >> 8), byte(address)})
}

// A clock a test sets.
type egressTestClock struct {
	now time.Time
}

func (self *egressTestClock) Now() time.Time {
	return self.now
}

func (self *egressTestClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *egressTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return false }
}

// The base time of generated states, and an hour.
const (
	egressGenTimeMs = 1_800_000_000_000
	egressGenHourMs = 3_600_000
)

// Choices from a byte stream: the fuzzer's bytes, then a seeded source's. See the file's comment.
type egressGen struct {
	data   []byte
	random *rand.Rand
}

// The next byte.
func (self *egressGen) next() byte {
	if 0 < len(self.data) {
		b := self.data[0]
		self.data = self.data[1:]
		return b
	}
	if self.random == nil {
		return 0
	}
	return byte(self.random.Uint32())
}

// A number below n, n at most 256.
func (self *egressGen) below(n int) int {
	return int(self.next()) % n
}

// One of the values.
func egressGenPick[T any](gen *egressGen, values ...T) T {
	return values[gen.below(len(values))]
}

// true about once in n.
func (self *egressGen) oneIn(n int) bool {
	return self.below(n) == 0
}

// A time near the base: before, at or after it by up to two hours, in steps that land on the rows' times.
func (self *egressGen) timeMs() int64 {
	return egressGenTimeMs + int64(self.below(9)-4)*egressGenHourMs/2
}

// A port range literal of protocol name, as the fixture writes one.
func (self *egressGen) ports(name string) string {
	if name == "*" || name == "icmp" || self.oneIn(3) {
		return name
	}
	ranges := egressGenPick(self, "22", "443", "5432", "8000-8010", "53,123", "993,8443", "1-1024")
	return name + ":" + ranges
}

// A generated state: its profile, input, the posture's state, and a fixture the rules came from.
type egressGenState struct {
	profile device.BridgePolicyProfile
	input   *device.BridgePolicyInput
	// what the flows draw on
	subjects     []sidecartest.BridgeRulesFixtureSubject
	destinations []netip.Addr
}

// The network every generated state is of, and this host.
var (
	egressGenNetworkId = sidecartest.BridgeFixtureSidecarId(0xA1)
	egressGenHostId    = sidecartest.BridgeFixtureSidecarId(0xA2)
)

// A state from the stream.
func (self *egressGen) state() *egressGenState {
	generated := &egressGenState{
		profile: egressGenPick(self, device.BridgePolicyProfileHost, device.BridgePolicyProfileHost, device.BridgePolicyProfileSdkProvider),
	}
	fixture := &sidecartest.BridgeRulesFixture{}
	blockBase := egressGenPick(self, "100.80", "10.20", "172.20", "192.168")
	fixture.Block = blockBase + ".0.0/16"
	if self.oneIn(3) {
		fixture.PreviousBlock = "100.81.0.0/16"
		fixture.PreviousBlockDrainUntil = self.timeMs()
	}
	hosts := []string{blockBase + ".1.2", blockBase + ".1.3", "100.81.1.2"}
	for _, host := range hosts {
		if (host == "100.81.1.2" && fixture.PreviousBlock == "") || self.oneIn(3) {
			continue
		}
		fixture.Addresses = append(fixture.Addresses, host)
	}
	mapCount := 1 + self.below(4)
	for i := range mapCount {
		name := egressGenPick(self, "tcp", "udp", "icmp")
		fixtureMap := sidecartest.BridgeRulesFixtureMap{
			Map:   byte(i + 1),
			Match: egressGenPick(self, blockBase+".1.2", blockBase+".1.3", blockBase+".2.4/30", "100.81.1.2"),
			Ports: self.ports(name),
		}
		if fixtureMap.Match == "100.81.1.2" && fixture.PreviousBlock == "" {
			fixtureMap.Match = blockBase + ".1.2"
		}
		target := egressGenPick(self, "127.0.0.1", "192.168.77.20", "198.51.100.20", blockBase+".1.9", "2001:db8::20")
		targetPort := "0"
		if name != "icmp" && len(fixtureMap.Ports) > len(name) && !self.oneIn(2) {
			// one range, which maps by offset
			fixtureMap.Ports = name + ":" + egressGenPick(self, "8000-8010", "5432", "22")
			targetPort = egressGenPick(self, "9000", "15432")
		}
		fixtureMap.Target = net.JoinHostPort(target, targetPort)
		if self.oneIn(3) {
			fixtureMap.Expires = self.timeMs()
		}
		if self.oneIn(4) {
			fixtureMap.DrainingSince = egressGenTimeMs - egressGenHourMs
			fixtureMap.DrainUntil = fixtureMap.DrainingSince + int64(self.below(3))*egressGenHourMs
		}
		fixture.Maps = append(fixture.Maps, fixtureMap)
	}
	servedCount := 1 + self.below(3)
	for i := range servedCount {
		served := sidecartest.BridgeRulesFixtureServed{
			Route:  byte(0x10 + i),
			Prefix: egressGenPick(self, "192.168.50.0/24", "10.30.0.0/16", "198.51.100.0/24", "203.0.113.0/24"),
		}
		if self.oneIn(4) {
			served.Exit = true
		} else if served.Prefix != "10.30.0.0/16" && self.oneIn(2) {
			served.Exposed = egressGenPick(self, blockBase+".200.0/24", blockBase+".201.0/24")
		}
		if self.oneIn(3) {
			served.DrainingSince = egressGenTimeMs - egressGenHourMs
			served.DrainUntil = served.DrainingSince + int64(self.below(4))*egressGenHourMs/2
		}
		fixture.Served = append(fixture.Served, served)
	}
	subjectCount := 1 + self.below(3)
	for i := range subjectCount {
		seed := byte(0x20 + i)
		subject := sidecartest.BridgeRulesFixtureSubject{Sidecar: seed, Tagged: self.oneIn(3), Clients: []byte{seed}}
		if self.oneIn(3) {
			subject.Clients = append(subject.Clients, seed+0x40)
		}
		rows := func(routeRows bool) []sidecartest.BridgeRulesFixtureReach {
			reach := []sidecartest.BridgeRulesFixtureReach{}
			for range self.below(3) {
				row := sidecartest.BridgeRulesFixtureReach{Ports: self.ports(egressGenPick(self, "*", "tcp", "udp", "icmp"))}
				if routeRows {
					row.Prefix = egressGenPick(self, "192.168.50.0/24", "192.168.50.0/25", "10.30.0.0/16", "198.51.100.0/24",
						blockBase+".200.0/24", "0.0.0.0/0")
				}
				if self.oneIn(2) {
					row.Grant = byte(self.below(4) + 1)
				}
				if self.oneIn(3) {
					row.Expires = self.timeMs()
				}
				reach = append(reach, row)
			}
			return reach
		}
		subject.Dial = rows(false)
		subject.Route = rows(true)
		subject.Exit = rows(false)
		fixture.Subjects = append(fixture.Subjects, subject)
		generated.subjects = append(generated.subjects, subject)
	}

	state := &bridge.BridgeState{}
	for _, subject := range fixture.Subjects {
		if self.oneIn(10) {
			continue
		}
		state.Identities = append(state.Identities, &bridge.BridgeIdentity{
			SidecarId:         sidecartest.BridgeFixtureSidecarId(subject.Sidecar),
			IdentityPublicKey: sidecartest.BridgeFixtureIdentityKey(subject.Sidecar).Public().(ed25519.PublicKey),
			Revoked:           self.oneIn(12),
			Suspended:         self.oneIn(12),
		})
	}
	for range self.below(4) {
		state.DaemonListeners = append(state.DaemonListeners,
			egressGenPick(self, "0.0.0.0:8443", "127.0.0.1:5432", "[::]:993", ":22", "192.168.77.10:9000", "not a listener"))
	}

	input := &device.BridgePolicyInput{
		State:       egressGenPick(self, device.PostureEnforcingDocument, device.PostureEnforcingNoDocument, device.PostureEnforcingDocument, device.PostureEnforcingNoDocument, device.PosturePending, device.PostureLegacy),
		BridgeState: state,
		NetworkId:   egressGenNetworkId,
		SidecarId:   egressGenHostId,
	}
	rulesBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(fixture.Rules())
	if err == nil && !self.oneIn(20) {
		// rules ParseBridgeRules refuses stay nil, as the bridge holds them
		input.Rules, _ = device.ParseBridgeRules(rulesBytes, nil)
	}
	for range max(0, self.below(5)-2) {
		subject := fixture.Subjects[self.below(len(fixture.Subjects))]
		entry := device.PostureOverlayEntry{}
		switch self.below(5) {
		case 0:
			entry.Kind, entry.Id = device.PostureOverlaySidecarRevoke, sidecartest.BridgeFixtureSidecarId(subject.Sidecar)
		case 1:
			entry.Kind, entry.Id = device.PostureOverlayMemberRevoke, sidecartest.BridgeFixtureMemberId(subject.Sidecar)
		case 2:
			entry.Kind, entry.Id = device.PostureOverlaySuspend, egressGenPick(self,
				sidecartest.BridgeFixtureSidecarId(subject.Sidecar), sidecartest.BridgeFixtureMemberId(subject.Sidecar))
		case 3:
			entry.Kind, entry.Id = device.PostureOverlayGrantRevoke, sidecartest.BridgeFixtureGrantId(byte(self.below(4)+1))
		default:
			entry.Kind = device.PostureOverlayBridgeWithdraw
			entry.Id = egressGenPick(self, sidecartest.BridgeFixtureMapId(byte(self.below(3)+1)), sidecartest.BridgeFixtureRouteId(byte(0x10+self.below(3))))
			entry.WithdrawMode = egressGenPick(self, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET,
				bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_UNSPECIFIED)
		}
		input.Overlay = append(input.Overlay, entry)
	}
	if !self.oneIn(3) {
		input.LocalAddresses = []netip.Addr{netip.MustParseAddr("192.168.77.10"), netip.MustParseAddr("203.0.113.10")}
	}
	generated.input = input

	// the first ten are what hosted addresses, maps, remaps and served prefixes hold
	for _, text := range []string{
		blockBase + ".1.2", blockBase + ".1.3", blockBase + ".2.5", blockBase + ".2.6", blockBase + ".200.7",
		blockBase + ".201.9", "192.168.50.9", "192.168.50.200", "10.30.4.4", "198.51.100.7",
		blockBase + ".1.9", "100.81.1.2", "100.81.3.3", "127.0.0.1", "127.0.0.9", "169.254.1.1", "224.0.0.5",
		"0.0.0.0", "192.168.77.10", "100.99.1.1", "203.0.113.9", "203.0.113.10", "192.0.2.33", "255.255.255.255",
		"240.0.0.1", "2001:db8::5", "fd00::5", "::1", "fe80::1", "ff02::1", "::",
	} {
		generated.destinations = append(generated.destinations, netip.MustParseAddr(text))
	}
	return generated
}

// A flow against a generated state, and the time it opens at.
func (self *egressGen) flow(state *egressGenState) (*connect.EgressFlow, time.Time) {
	subject := state.subjects[self.below(len(state.subjects))]
	flow := &connect.EgressFlow{
		ProvideMode:   protocol.ProvideMode_Network,
		ContractClass: connect.ContractClassData,
		Sealed:        !self.oneIn(8),
		Protocol: egressGenPick(self, connect.IpProtocolTcp, connect.IpProtocolTcp, connect.IpProtocolTcp, connect.IpProtocolTcp,
			connect.IpProtocolUdp, connect.IpProtocolUdp, connect.IpProtocolIcmp, connect.IpProtocolIcmp, connect.IpProtocolUnknown),
	}
	// most flows are well formed, so they reach the numbered rules; the rest try each row before them
	if self.oneIn(3) {
		flow.ProvideMode = egressGenPick(self, protocol.ProvideMode_FriendsAndFamily, protocol.ProvideMode_Public,
			protocol.ProvideMode_Service, protocol.ProvideMode_None, protocol.ProvideMode_Stream, protocol.ProvideMode_Network,
			protocol.ProvideMode(9))
		flow.ContractClass = egressGenPick(self, connect.ContractClassData, connect.ContractClassControl, connect.ContractClassUnset)
	}
	clientSeed := egressGenPick(self, subject.Sidecar, subject.Sidecar+0x40, byte(0x7F))
	flow.SourceSubject = sidecartest.BridgeFixtureClientId(clientSeed)
	if self.oneIn(10) {
		flow.SourceSubject = connect.Id{}
	}
	now := time.UnixMilli(self.timeMs())
	if !self.oneIn(8) {
		principal := &connect.BridgePrincipal{
			Subject:  connect.Id(sidecartest.BridgeFixtureSidecarId(subject.Sidecar)),
			Network:  connect.Id(egressGenNetworkId),
			NotAfter: now.Add(time.Hour),
		}
		switch self.below(16) {
		case 0:
			principal.Subject = connect.Id(sidecartest.BridgeFixtureSidecarId(0x7F))
		case 1:
			principal.Network = connect.Id(sidecartest.BridgeFixtureSidecarId(0xA3))
		case 2:
			principal.ShareId = connect.Id(sidecartest.BridgeFixtureSidecarId(0xA4))
		case 3:
			principal.NotAfter = now
		}
		flow.Principal = principal
	}
	// half the time a destination a hosted address, map or remap holds
	destination := state.destinations[self.below(len(state.destinations))]
	if self.oneIn(2) {
		destination = state.destinations[self.below(10)]
	}
	port := egressGenPick(self, uint16(22), uint16(53), uint16(443), uint16(5432), uint16(8000), uint16(8005), uint16(8443),
		uint16(993), uint16(9000), uint16(15432), uint16(1+self.below(250)))
	if flow.Protocol == connect.IpProtocolIcmp {
		port = 0
	}
	flow.To = netip.AddrPortFrom(destination, port)
	flow.From = netip.AddrPortFrom(netip.MustParseAddr("10.9.8.7"), 40000)
	return flow, now
}

// Compares the policy with the reference over one state and its flows; a description of the first difference, or "".
func egressCompare(state *egressGenState, flows []*connect.EgressFlow, nows []time.Time) string {
	clock := &egressTestClock{}
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	policy := device.NewBridgeEgressPolicy(state.profile, settings)
	generation := policy.Publish(state.input)
	for i, flow := range flows {
		clock.now = nows[i]
		got := policy.ResolveEgress(flow)
		want := egressReferenceResolve(state.profile, state.input, flow, nows[i], settings.PinTcpIdleTimeout, settings.PinIdleTimeout)
		differs := got.Verdict != want.verdict || got.PolicyGeneration != generation
		if want.verdict != connect.EgressVerdictDeny {
			differs = differs || got.RuleTag != want.ruleTag || got.IdleTimeout != want.idle
		}
		if want.verdict == connect.EgressVerdictMap {
			differs = differs || got.Target != want.target
		}
		if differs {
			return fmt.Sprintf("profile %v, state %v, flow %+v at %v: policy %+v, reference %+v",
				state.profile, state.input.State, *flow, nows[i].UnixMilli(), got, want)
		}
	}
	return ""
}

// §22.5's "hook = reference": the policy and the reference agree on every flow of thousands of generated states.
func TestBridgeEgressPolicyEqualsTheReference(t *testing.T) {
	random := rand.New(rand.NewPCG(0x5eed, 0xb41d6e))
	rows := map[string]int{}
	for range 3000 {
		gen := &egressGen{random: random}
		state := gen.state()
		flows := []*connect.EgressFlow{}
		nows := []time.Time{}
		for range 60 {
			flow, now := gen.flow(state)
			flows = append(flows, flow)
			nows = append(nows, now)
			decision := egressReferenceResolve(state.profile, state.input, flow, now, 600*time.Second, 5*time.Minute)
			rows[decision.row+" "+decision.verdict.String()] += 1
		}
		if difference := egressCompare(state, flows, nows); difference != "" {
			t.Fatal(difference)
		}
	}
	// the generator reaches every row of the table both ways it can go, so agreement is not agreement on denying
	for _, row := range []string{
		"legacy pass", "mode pass", "mode deny", "class deny", "protocol deny", "subject deny", "principal deny",
		"state deny", "0 deny", "1 map", "1 deny", "1_remap map", "1_remap deny", "2 deny", "3 map", "3 deny",
		"block deny", "4 pass", "5 deny", "6 pass", "6 deny", "7 pass", "7 deny", "8 deny",
	} {
		if rows[row] < 50 {
			t.Errorf("%s reached %d times", row, rows[row])
		}
	}
	if t.Failed() {
		t.Logf("rows: %v", rows)
	}
}
