//go:build !ios_extension

// AclEngine over activated route grants (acl_engine.go's InstallWithGrants; owner decisions 220 and 679, QD-003,
// QD-1164), on the compile's grant net, where a route grant of the laptop's through the desktop activates through the
// log with its prefixes and ports sealed: ur bridge's preview (AllowRoute) and acl_check's Check accept what the grant
// serves and refuse it past its expiry, after its revoke, without the key of its generation, with no opener and where
// its action seals no detail; the engine and the desktop's compile agree flow by flow; the save's run, the compile and
// the engine read each grant to one detail; a grant read once is kept for the next install; the preview allocates
// nothing; and the acl follower installs the grants' details under the keys this device holds. Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The laptop's engine at a reader's tip, its grants opened through opener: nil for the state's own opener under
// generation 3's key where withKey.
func (self *testBridgeGrantNet) grantEngine(log *ConfigLog, withKey bool, opener AclGrantDetails) *AclEngine {
	self.t.Helper()
	view := self.grantViewOf(log, withKey)
	if opener == nil {
		opener = newAclStateGrantDetails(view.state, view.head, view.RepoKeyAt)
	}
	engine := NewAclEngine(self.host.sidecarId, nil, nil, nil)
	if err := engine.InstallWithGrants(view.acl, view.aclLocal, opener); err != nil {
		self.t.Fatal(err)
	}
	return engine
}

// Activates the grant the engine's tests read: 192.168.7.0/25 by cidr and 192.168.7.128/26 by ip: destination, at the
// desktop's tcp 22 and udp 53, ending at expiresMs. Answers its grant id.
func (self *testBridgeGrantNet) portedGrant(label string, expiresMs int64) []byte {
	desktopDst := aclTestDst(self.peer.sidecarId)
	return self.activate(label, self.routeGrantAction(&protocol.CanonicalActionDetail{
		Cidrs: []string{"192.168.7.0/25"}, GrantDst: []string{"ip:192.168.7.128/26", desktopDst + ":tcp:22", desktopDst + ":udp:53"},
	}, expiresMs, nil))
}

// An opener that counts what it is asked, over another. Safe for concurrent use.
type testAclGrantDetailsCount struct {
	opener    AclGrantDetails
	stateLock sync.Mutex
	asked     []string
}

func (self *testAclGrantDetailsCount) GrantDetail(grantId []byte) (*protocol.CanonicalActionDetail, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.asked = append(self.asked, string(grantId))
	}()
	return self.opener.GrantDetail(grantId)
}

// How many times the opener was asked.
func (self *testAclGrantDetailsCount) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.asked)
}

// One route check of the laptop's.
type testAclEngineRoute struct {
	address    string
	ipProtocol uint32
	port       uint32
	allowed    bool
}

// The preview takes the grant's prefixes, its cidr's and its ip: destination's, at its ports and through the desktop
// alone, and refuses another port, another protocol, the served route's part the grant does not name, the desktop's
// other route and another via; Check takes a range its prefixes hold whole, naming the grant, and refuses a wider one
// and one they miss. Both honor the grant until the engine's clock skew past its expiry and refuse it from then on.
func TestAclEngineAnswersAnActivatedRouteGrantByItsDetail(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	expiresMs := net.timeMs + 60*60*1000
	grantId := net.portedGrant("engine", expiresMs)
	engine := net.grantEngine(net.log, true, nil)
	laptop, desktop := AclSidecarSubject(net.host.sidecarId), AclSidecarSubject(net.peer.sidecarId)
	now := time.UnixMilli(net.log.State().TimeMs())
	route := func(address string, ipProtocol uint32, port uint32, via AclSubject, at time.Time) AclDecision {
		return engine.AllowRoute(laptop, netip.MustParseAddr(address), ipProtocol, port, via, at)
	}
	for i, c := range []testAclEngineRoute{
		{address: "192.168.7.10", ipProtocol: aclIpProtocolTcp, port: 22, allowed: true},
		{address: "192.168.7.127", ipProtocol: aclIpProtocolUdp, port: 53, allowed: true},
		{address: "192.168.7.130", ipProtocol: aclIpProtocolTcp, port: 22, allowed: true},
		{address: "192.168.7.10", ipProtocol: aclIpProtocolTcp, port: 23},
		{address: "192.168.7.10", ipProtocol: aclIpProtocolUdp, port: 22},
		{address: "192.168.7.200", ipProtocol: aclIpProtocolTcp, port: 22},
		{address: "192.168.9.10", ipProtocol: aclIpProtocolTcp, port: 22},
	} {
		decision := route(c.address, c.ipProtocol, c.port, desktop, now)
		if decision.Allowed != c.allowed || (c.allowed && !bytes.Equal(decision.Rule.GetRuleId(), grantId)) {
			t.Errorf("route %d: allowed %t (%s)", i, decision.Allowed, decision.Reason)
		}
	}
	if decision := route("192.168.7.10", aclIpProtocolTcp, 22, AclSidecarSubject(net.other.sidecarId), now); decision.Allowed {
		t.Error("the grant routes through a via its grant_dst does not name")
	}
	check := func(cidr string, at time.Time) AclCheck {
		return engine.Check(laptop, protocol.AclAction_ACL_ACTION_ROUTE, AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix(cidr)}, at)
	}
	for _, c := range []struct {
		cidr    string
		allowed bool
	}{
		{cidr: "192.168.7.0/26", allowed: true},
		{cidr: "192.168.7.0/25", allowed: true},
		{cidr: "192.168.7.128/26", allowed: true},
		{cidr: "192.168.7.0/24"},
		{cidr: "192.168.7.192/26"},
		{cidr: "192.168.9.0/24"},
	} {
		result := check(c.cidr, now)
		if result.Allowed != c.allowed || (c.allowed && !bytes.Equal(result.GrantId, grantId)) || (!c.allowed && result.Reason != AclReasonNoGrant) {
			t.Errorf("check of %s: %+v", c.cidr, result)
		}
	}

	// the engine honors a rule until its clock skew past its expiry (§8.6)
	skew := DefaultAclEngineSettings().ClockSkew
	last, ended := time.UnixMilli(expiresMs).Add(skew-time.Millisecond), time.UnixMilli(expiresMs).Add(skew)
	if !route("192.168.7.10", aclIpProtocolTcp, 22, desktop, last).Allowed || !check("192.168.7.0/26", last).Allowed {
		t.Error("the grant ended before its expiry and the skew")
	}
	if route("192.168.7.10", aclIpProtocolTcp, 22, desktop, ended).Allowed || check("192.168.7.0/26", ended).Allowed {
		t.Error("the grant stands past its expiry")
	}
}

// A grant the engine cannot read reaches nothing, the closed direction: installed with no opener, opened without the
// key of its generation, after its GrantRevoke, and where its action seals no detail, which the opener is never asked
// for; a document-free reading of the rows alone would have routed it through the desktop.
func TestAclEngineReachesNothingByAnActivatedRouteGrantItCannotRead(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	grantId := net.portedGrant("unread", net.timeMs+60*60*1000)
	laptop, desktop := AclSidecarSubject(net.host.sidecarId), AclSidecarSubject(net.peer.sidecarId)
	now := time.UnixMilli(net.log.State().TimeMs())
	refuses := func(engine *AclEngine) bool {
		t.Helper()
		routed := engine.AllowRoute(laptop, netip.MustParseAddr("192.168.7.10"), aclIpProtocolTcp, 22, desktop, now).Allowed
		checked := engine.Check(laptop, protocol.AclAction_ACL_ACTION_ROUTE, AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix("192.168.7.0/26")}, now).Allowed
		return !routed && !checked
	}
	if refuses(net.grantEngine(net.log, true, nil)) {
		t.Fatal("the grant does not stand with its key: the refusals below would prove nothing")
	}
	if acl := net.grantViewOf(net.log, true).acl; !acl.MayRoute(laptop, netip.Addr{}, desktop, now).Allowed {
		t.Fatal("the rows do not route the laptop through the desktop")
	}

	bare := NewAclEngine(net.host.sidecarId, nil, nil, nil)
	if err := bare.Install(net.grantViewOf(net.log, true).acl, nil); err != nil {
		t.Fatal(err)
	}
	if !refuses(bare) {
		t.Error("an engine installed with no opener routes by the grant")
	}
	if !refuses(net.grantEngine(net.log, false, nil)) {
		t.Error("an engine without the key of the grant's generation routes by it")
	}

	// the same grant's rule, its action sealing no detail, as rows a base carries name it
	view := net.grantViewOf(net.log, true)
	rows := proto.Clone(view.state.aclRows).(*protocol.AclRows)
	unsealedId := bytes.Repeat([]byte{0x5c}, len(grantId))
	for _, rule := range rows.GetRules() {
		if bytes.Equal(rule.GetRuleId(), grantId) {
			unsealed := proto.Clone(rule).(*protocol.AclRule)
			unsealed.RuleId, unsealed.PortsLimited = unsealedId, false
			rows.Rules = slices.DeleteFunc(rows.Rules, func(held *protocol.AclRule) bool { return bytes.Equal(held.GetRuleId(), grantId) })
			rows.Rules = append(rows.Rules, unsealed)
			break
		}
	}
	acl, err := NewAclState(rows, view.state)
	if err != nil {
		t.Fatal(err)
	}
	if !acl.MayRoute(laptop, netip.Addr{}, desktop, now).Allowed {
		t.Fatal("the unsealed grant does not stand at the rows")
	}
	opener := &testAclGrantDetailsCount{opener: newAclStateGrantDetails(view.state, view.head, view.RepoKeyAt)}
	unsealedEngine := NewAclEngine(net.host.sidecarId, nil, nil, nil)
	if err := unsealedEngine.InstallWithGrants(acl, nil, opener); err != nil {
		t.Fatal(err)
	}
	if !refuses(unsealedEngine) || opener.count() != 0 {
		t.Errorf("a grant sealing no detail: routes %t, its detail asked %d times", !refuses(unsealedEngine), opener.count())
	}

	net.mustPost(net.host, bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{Header: net.header(), GrantId: grantId})
	if !refuses(net.grantEngine(net.log, true, nil)) {
		t.Error("the grant routes after its GrantRevoke")
	}
}

// Flow by flow, the laptop's engine allows exactly what the desktop's compile gives the laptop route rows for, under a
// ported grant and a grant naming no port: every address of both served routes at the boundaries of the grants'
// parts, at tcp and udp, at the grants' ports and another.
func TestAclEngineAgreesFlowByFlowWithTheCompileOnActivatedRouteGrants(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	inPrefix, _ := testBridgeGrantPrefixes()
	expiresMs := net.timeMs + 60*60*1000
	net.portedGrant("agree ported", expiresMs)
	net.activate("agree every port", net.routeGrantAction(&protocol.CanonicalActionDetail{GrantDst: []string{"ip:192.168.9.0/25"}}, expiresMs, nil))
	_, _, _, subject := net.compileGrant(net.log, true, inPrefix)
	if subject == nil || len(subject.GetRoute()) == 0 {
		t.Fatalf("the desktop gives the laptop no route rows: %v", subject)
	}
	admits := func(address uint32, ipProtocol uint32, port uint32) bool {
		for _, row := range subject.GetRoute() {
			prefix, err := bridgePrefixOf(row.GetPrefix())
			if err != nil || !prefix.containsAddress(address) || (row.GetProtocol() != 0 && row.GetProtocol() != ipProtocol) {
				continue
			}
			if len(row.GetPorts()) == 0 {
				return true
			}
			for _, ports := range row.GetPorts() {
				if ports.GetFirst() <= port && port <= ports.GetLast() {
					return true
				}
			}
		}
		return false
	}
	engine := net.grantEngine(net.log, true, nil)
	laptop, desktop := AclSidecarSubject(net.host.sidecarId), AclSidecarSubject(net.peer.sidecarId)
	now := time.UnixMilli(net.log.State().TimeMs())
	admitted, refused := 0, 0
	for _, third := range []byte{7, 9} {
		for _, last := range []byte{0, 10, 127, 128, 150, 191, 192, 255} {
			for _, ipProtocol := range []uint32{aclIpProtocolTcp, aclIpProtocolUdp} {
				for _, port := range []uint32{22, 53, 80} {
					address := netip.AddrFrom4([4]byte{192, 168, third, last})
					compiled := admits(testBridgeIpv4(192, 168, third, last), ipProtocol, port)
					allowed := engine.AllowRoute(laptop, address, ipProtocol, port, desktop, now).Allowed
					if compiled != allowed {
						t.Errorf("%s protocol %d port %d: the compile admits %t, the engine allows %t", address, ipProtocol, port, compiled, allowed)
					}
					if compiled {
						admitted += 1
					} else {
						refused += 1
					}
				}
			}
		}
	}
	if admitted == 0 || refused == 0 {
		t.Errorf("the probes admitted %d and refused %d: they tell nothing apart", admitted, refused)
	}
}

// One opener over the net's state, each grant read by the save's run, the desktop's compile and the laptop's engine
// gives the same prefixes and ports, each once and masked, a prefix the detail names twice read once; a keyless opener
// gives none at all three.
func TestAnActivatedRouteGrantReadsAlikeAtTheSaveTheCompileAndTheEngine(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	expiresMs := net.timeMs + 60*60*1000
	desktopDst := aclTestDst(net.peer.sidecarId)
	grantIds := [][]byte{
		net.portedGrant("alike ported", expiresMs),
		net.activate("alike twice", net.routeGrantAction(&protocol.CanonicalActionDetail{
			Cidrs: []string{"192.168.9.0/25"}, GrantDst: []string{"ip:192.168.9.0/25", desktopDst + ":tcp:22", desktopDst + ":tcp:22"},
		}, expiresMs, nil)),
		net.activate("alike exit", net.routeGrantAction(&protocol.CanonicalActionDetail{Cidrs: []string{"0.0.0.0/0"}}, expiresMs, nil)),
	}
	want := map[string]*AclLocalRule{
		string(grantIds[0]): {
			Cidrs: []netip.Prefix{netip.MustParsePrefix("192.168.7.0/25"), netip.MustParsePrefix("192.168.7.128/26")},
			Ports: []AclPortRange{{Protocol: aclIpProtocolTcp, First: 22, Last: 22}, {Protocol: aclIpProtocolUdp, First: 53, Last: 53}},
		},
		string(grantIds[1]): {
			Cidrs: []netip.Prefix{netip.MustParsePrefix("192.168.9.0/25")},
			Ports: []AclPortRange{{Protocol: aclIpProtocolTcp, First: 22, Last: 22}},
		},
		string(grantIds[2]): {Cidrs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
	}
	same := func(a *AclLocalRule, b *AclLocalRule) bool {
		if a == nil || b == nil {
			return a == b
		}
		return slices.Equal(a.Cidrs, b.Cidrs) && slices.Equal(a.Ports, b.Ports)
	}
	for _, withKey := range []bool{true, false} {
		view := net.grantViewOf(net.log, withKey)
		opener := &aclStateGrantDetails{actions: view.state.grantActionsAtHead(view.head), networkId: view.state.NetworkId(), repoKeyAt: view.RepoKeyAt}
		run := &aclTestRun{grantDetails: opener, grantRoutes: map[string]aclGrantRoute{}}
		compiler := &bridgeCompiler{grantDetails: opener, grantRoutes: map[string]*AclLocalRule{}, compiled: &BridgeCompiled{}}
		engine := net.grantEngine(net.log, withKey, opener)
		installed := engine.installed.Load()
		for _, grantId := range grantIds {
			index := slices.IndexFunc(view.acl.rules, func(rule aclRule) bool { return bytes.Equal(rule.row.GetRuleId(), grantId) })
			if index < 0 {
				t.Fatalf("the grant %x is no rule of the state", grantId)
			}
			rule := &view.acl.rules[index]
			saved := run.grantRoute(rule).local
			compiled := compiler.grantRoute(aclReachRuleOf(rule))
			answered, _, _ := installed.routeLocal(rule)
			expected := want[string(grantId)]
			if !withKey {
				expected = nil
			}
			if !same(saved, expected) || !same(compiled, expected) || !same(answered, expected) {
				t.Errorf("with the key %t, grant %x: the save reads %+v, the compile %+v, the engine %+v", withKey, grantId, saved, compiled, answered)
			}
		}
	}
}

// A grant whose detail read is kept for the next install of a state holding it, so its detail is not opened again; one
// read without its generation's key is read again, and stands once the key is there.
func TestAclEngineKeepsAnActivatedRouteGrantsReadingAcrossInstalls(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	net.portedGrant("kept", net.timeMs+60*60*1000)
	laptop, desktop := AclSidecarSubject(net.host.sidecarId), AclSidecarSubject(net.peer.sidecarId)
	now := time.UnixMilli(net.log.State().TimeMs())
	allows := func(engine *AclEngine) bool {
		return engine.AllowRoute(laptop, netip.MustParseAddr("192.168.7.10"), aclIpProtocolTcp, 22, desktop, now).Allowed
	}
	install := func(engine *AclEngine, withKey bool) *testAclGrantDetailsCount {
		t.Helper()
		view := net.grantViewOf(net.log, withKey)
		opener := &testAclGrantDetailsCount{opener: newAclStateGrantDetails(view.state, view.head, view.RepoKeyAt)}
		if err := engine.InstallWithGrants(view.acl, view.aclLocal, opener); err != nil {
			t.Fatal(err)
		}
		return opener
	}

	keyed := NewAclEngine(net.host.sidecarId, nil, nil, nil)
	if first := install(keyed, true); first.count() != 1 || !allows(keyed) {
		t.Fatalf("the first install asked %d details and allows %t", first.count(), allows(keyed))
	}
	if again := install(keyed, true); again.count() != 0 || !allows(keyed) {
		t.Errorf("the next install asked %d details and allows %t", again.count(), allows(keyed))
	}

	unkeyed := NewAclEngine(net.host.sidecarId, nil, nil, nil)
	if first := install(unkeyed, false); first.count() != 1 || allows(unkeyed) {
		t.Fatalf("without the key the install asked %d details and allows %t", first.count(), allows(unkeyed))
	}
	if keyedAfter := install(unkeyed, true); keyedAfter.count() != 1 || !allows(unkeyed) {
		t.Errorf("with the key the next install asked %d details and allows %t", keyedAfter.count(), allows(unkeyed))
	}
}

// The preview through an activated route grant allocates nothing: the detail was read at the install.
func TestAclEngineChecksAnActivatedRouteGrantWithoutAllocating(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	net.portedGrant("allocations", net.timeMs+60*60*1000)
	engine := net.grantEngine(net.log, true, nil)
	laptop, desktop := AclSidecarSubject(net.host.sidecarId), AclSidecarSubject(net.peer.sidecarId)
	address := netip.MustParseAddr("192.168.7.10")
	now := time.UnixMilli(net.log.State().TimeMs())
	if !engine.AllowRoute(laptop, address, aclIpProtocolTcp, 22, desktop, now).Allowed {
		t.Fatal("the grant does not stand")
	}
	if allocs := testing.AllocsPerRun(100, func() { engine.AllowRoute(laptop, address, aclIpProtocolTcp, 22, desktop, now) }); allocs != 0 {
		t.Errorf("%v allocations", allocs)
	}
}

// The acl follower installs each state with the opener of its activated grants' details under the keys this device
// holds, asked for the network's config repo alone: Check then takes the grant's range. With no key source the same
// state installs with no opener and the grant reaches nothing.
func TestAclFollowerInstallsActivatedRouteGrantsUnderHeldKeys(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	grantId := net.portedGrant("follower", net.timeMs+60*60*1000)
	state := net.log.State()
	configRepoId, err := IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		t.Fatal(err)
	}
	key := testConfigSealKey(testActionDetailGeneration)
	var askedLock sync.Mutex
	askedRepoIds := []Id{}
	held := func(repoId Id, generation uint64) *EvsRepoKey {
		askedLock.Lock()
		defer askedLock.Unlock()
		askedRepoIds = append(askedRepoIds, repoId)
		return testConfigSealKeyAt(key)(generation)
	}
	laptop := AclSidecarSubject(net.host.sidecarId)
	now := time.UnixMilli(state.TimeMs())
	for _, c := range []struct {
		name    string
		held    func(repoId Id, generation uint64) *EvsRepoKey
		allowed bool
	}{
		{name: "held keys", held: held, allowed: true},
		{name: "no key source", held: nil, allowed: false},
	} {
		settings := DefaultAclSettings()
		settings.Clock = newTestConfigClock()
		settings.Log = NewNoopLogger()
		engine := NewAclEngine(net.host.sidecarId, nil, nil, nil)
		follower, err := NewAclFollower(context.Background(), &AclFollowerArgs{
			Source: &aclTestFollowSource{state: state}, Engine: engine, HeldRepoKey: c.held, Settings: settings,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(follower.Close)
		result := engine.Check(laptop, protocol.AclAction_ACL_ACTION_ROUTE, AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix("192.168.7.0/26")}, now)
		if result.Allowed != c.allowed || (c.allowed && !bytes.Equal(result.GrantId, grantId)) {
			t.Errorf("%s: %+v", c.name, result)
		}
	}
	askedLock.Lock()
	defer askedLock.Unlock()
	if len(askedRepoIds) == 0 || slices.ContainsFunc(askedRepoIds, func(repoId Id) bool { return repoId != configRepoId }) {
		t.Errorf("the follower asked for keys of %v, want the config repo %s alone", askedRepoIds, configRepoId)
	}
}
