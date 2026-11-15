// §17.9's shares at a host and a sender (BRIDGE-M6-04, BRIDGE-M6-05; DESIGN-DETAILS 12.6's shares and signers rows,
// §22.5's "C18's aliases within §17.9's isolation"): the FriendsAndFamily row maps an alias to its target keeping host
// bits, across a block change of the accepting network, and reaches only where its share's targets lead, never a daemon
// listener, unmapped loopback, an exit, another host's address or another share's target; FriendsAndFamilyEgress is on
// only at a host holding a share; a share principal is admitted only on its ShareCert under the pinned ShareKey, each
// refusal alone beside its twin, with the ratchet committed before the principal is answered and kept across a restart;
// a removed sidecar's older generation is refused once a later one reached the host; and a share link is built
// FriendsAndFamily with its aliases, its binding of the sharing network, and its window clients signed again when the
// share's signer changes.

package device_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The shares of the tests: share A of network Y, and share B of network Z, each with its own ShareKey.
const (
	shareTestShareA   byte = 0x31
	shareTestShareB   byte = 0x32
	shareTestNetworkY byte = 0xC1
	shareTestNetworkZ byte = 0xC2
)

// A sidecar of Y, its window client and the window client's key, and the ShareSigners of Y's generations.
var (
	shareTestSubjectId = sidecartest.BridgeFixtureSidecarId(0x61)
	shareTestWindowId  = sidecartest.BridgeFixtureClientId(0x91)
	shareTestWindowKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x79}, ed25519.SeedSize))
)

// The seed of Y's ShareSigner of a generation.
func shareTestSignerSeed(generation uint64) []byte {
	return bytes.Repeat([]byte{0x5A, byte(generation)}, ed25519.SeedSize/2)
}

// The host's rules (egressTestFixture's) with share A's targets: a served subnet over TCP/443, this host's address on
// every protocol, a remapped route's exposed prefix over TCP, and four targets the row must refuse wherever they
// lead: a public prefix, another host's address, loopback and a LAN with no route. Share B, of Z, has one target, the
// same served subnet as share A's first.
func shareTestFixture() *sidecartest.BridgeRulesFixture {
	fixture := egressTestFixture()
	fixture.Shares = []sidecartest.BridgeRulesFixtureShare{
		{Share: shareTestShareA, Network: shareTestNetworkY, Grant: 9, Targets: []sidecartest.BridgeRulesFixtureShareTarget{
			{Index: 0, AliasHostBits: 0x8100, Target: "192.168.50.0/24", Ports: "tcp:443"},
			{Index: 1, AliasHostBits: 0x8001, Target: "100.80.1.2/32", Ports: "*"},
			{Index: 2, AliasHostBits: 0x8200, Target: "100.80.200.0/24", Ports: "tcp"},
			{Index: 3, AliasHostBits: 0x8300, Target: "203.0.113.0/24", Ports: "*"},
			{Index: 4, AliasHostBits: 0x8002, Target: "100.80.1.3/32", Ports: "*"},
			{Index: 5, AliasHostBits: 0x8400, Target: "127.0.0.0/24", Ports: "*"},
			{Index: 6, AliasHostBits: 0x8500, Target: "192.168.99.0/24", Ports: "*"},
		}},
		{Share: shareTestShareB, Network: shareTestNetworkZ, Grant: 10, Targets: []sidecartest.BridgeRulesFixtureShareTarget{
			{Index: 0, AliasHostBits: 0x8600, Target: "192.168.50.0/24", Ports: "tcp:443"},
		}},
	}
	return fixture
}

// A share flow: FriendsAndFamily, the data class, sealed, from Y's sidecar with share's principal of network, to to.
func shareTestFlow(share byte, network byte, ipProtocol connect.IpProtocol, to string) *connect.EgressFlow {
	return &connect.EgressFlow{
		ProvideMode:   protocol.ProvideMode_FriendsAndFamily,
		ContractClass: connect.ContractClassData,
		SourceSubject: sidecartest.BridgeFixtureClientId(0x61),
		SourceNetwork: connect.Id(sidecartest.BridgeFixtureNetworkId(network)),
		Principal: &connect.BridgePrincipal{
			Subject:  connect.Id(shareTestSubjectId),
			Network:  connect.Id(sidecartest.BridgeFixtureNetworkId(network)),
			ShareId:  connect.Id(sidecartest.BridgeFixtureShareId(share)),
			NotAfter: time.UnixMilli(egressTestTimeMs + egressTestHourMs),
		},
		Sealed:   true,
		Protocol: ipProtocol,
		From:     netip.MustParseAddrPort("100.90.1.7:40000"),
		To:       netip.MustParseAddrPort(to),
	}
}

// The tag of a share target's flows.
func shareTestTag(share byte, index uint32) uint64 {
	return device.BridgeShareRuleTag(connect.Id(sidecartest.BridgeFixtureShareId(share)), index)
}

// §17.9's row: an alias's destination maps to its target with the bits past the alias's length kept, through rules 1,
// 3 and 6 and rule 6's remap under the share's grant, each tagged by the share and the target, and the same host bits in
// another block of the accepting network map alike, since the host pins host bits, never the block.
func TestAShareFlowMapsItsAliasToItsTargetKeepingHostBits(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, shareTestFixture())
	cases := []struct {
		name   string
		to     string
		target string
		index  uint32
	}{
		{name: "a served subnet, rule 6", to: "100.90.129.20:443", target: "192.168.50.20:443", index: 0},
		{name: "the same host bits after the accepting network cycled its block", to: "100.91.129.20:443", target: "192.168.50.20:443", index: 0},
		{name: "this host's address, rule 3", to: "100.90.128.1:22", target: "127.0.0.1:22", index: 1},
		{name: "this host's address, rule 1's map", to: "100.90.128.1:5432", target: "127.0.0.1:5432", index: 1},
		{name: "a remapped route's exposed prefix", to: "100.90.130.9:443", target: "192.168.60.9:443", index: 2},
	}
	for _, testCase := range cases {
		test.expectMap(testCase.name, shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, testCase.to),
			testCase.target, shareTestTag(shareTestShareA, testCase.index))
	}
	// an ICMP echo to this host's address follows rule 3, which takes every protocol under the target's "*"
	test.expectMap("an echo to this host's address", shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolIcmp, "100.90.128.1:0"),
		"127.0.0.1:0", shareTestTag(shareTestShareA, 1))
	// a share flow holds the link's idles, as every flow with a principal does
	decision := test.policy.ResolveEgress(shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.129.20:443"))
	if decision.IdleTimeout != 600*time.Second {
		t.Errorf("a share flow's idle is %v", decision.IdleTimeout)
	}
	// share B's alias of the same subnet is its own, under its own tag
	test.expectMap("share B's alias", shareTestFlow(shareTestShareB, shareTestNetworkZ, connect.IpProtocolTcp, "100.92.134.20:443"),
		"192.168.50.20:443", shareTestTag(shareTestShareB, 0))
}

// §22.5's isolation for C18's aliases: an alias resolves only to its share's targets, through maps, dialable hosted
// addresses and served prefixes, never to a daemon listener, unmapped loopback, an exit, another host's address, a LAN
// with no route or another share's target; and the principal's verified share and network select the aliases, never
// an address.
func TestAShareFlowReachesOnlyItsSharesTargets(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, shareTestFixture())
	refused := []struct {
		name string
		flow *connect.EgressFlow
	}{
		{name: "another protocol than the target's", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolUdp, "100.90.129.20:443")},
		{name: "another port than the target's", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.129.20:22")},
		{name: "a daemon listener through rule 3", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.128.1:8443")},
		{name: "a map onto a daemon listener", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.128.1:7000")},
		{name: "a map onto another host", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.128.1:7001")},
		{name: "a public prefix, never an exit", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.131.9:443")},
		{name: "another host's address, rule 2", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.128.2:22")},
		{name: "unmapped loopback, rule 5", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.132.1:80")},
		{name: "a daemon listener on loopback, rule 0", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.132.1:8443")},
		{name: "a LAN with no route", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.133.1:80")},
		{name: "host bits in no alias", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.7.20:443")},
		{name: "another share's alias", flow: shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.134.20:443")},
		{name: "a share's principal of another network", flow: shareTestFlow(shareTestShareB, shareTestNetworkY, connect.IpProtocolTcp, "100.92.134.20:443")},
		{name: "a share this host does not serve", flow: shareTestFlow(0x39, shareTestNetworkY, connect.IpProtocolTcp, "100.90.129.20:443")},
	}
	for _, testCase := range refused {
		test.expectDeny(testCase.name, testCase.flow)
	}
	// the twin of each principal row passes, beside it
	twin := shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.129.20:443")
	test.expectMap("the twin", twin, "192.168.50.20:443", shareTestTag(shareTestShareA, 0))
	principalRows := map[string]func(flow *connect.EgressFlow){
		"no principal":                func(flow *connect.EgressFlow) { flow.Principal = nil },
		"a principal of this network": func(flow *connect.EgressFlow) { flow.Principal.ShareId = connect.Id{} },
		"a share principal of this network": func(flow *connect.EgressFlow) {
			flow.Principal.Network = connect.Id(egressTestNetworkId)
		},
		"a lapsed principal":           func(flow *connect.EgressFlow) { flow.Principal.NotAfter = time.UnixMilli(egressTestTimeMs) },
		"an unsealed source":           func(flow *connect.EgressFlow) { flow.Sealed = false },
		"a control contract":           func(flow *connect.EgressFlow) { flow.ContractClass = connect.ContractClassControl },
		"a share principal on Network": func(flow *connect.EgressFlow) { flow.ProvideMode = protocol.ProvideMode_Network },
	}
	for name, edit := range principalRows {
		flow := shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.129.20:443")
		edit(flow)
		test.expectDeny(name, flow)
	}
	// a GrantRevoke of share A's grant between states ends share A alone
	test.input.Overlay = append(test.input.Overlay, device.PostureOverlayEntry{Kind: device.PostureOverlayGrantRevoke, Id: sidecartest.BridgeFixtureGrantId(9)})
	test.republish()
	test.expectDeny("share A after its grant's revocation", shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.129.20:443"))
	test.expectMap("share B beside it", shareTestFlow(shareTestShareB, shareTestNetworkZ, connect.IpProtocolTcp, "100.92.134.20:443"),
		"192.168.50.20:443", shareTestTag(shareTestShareB, 0))
	// a share whose grant expired admits nothing
	expired := shareTestFixture()
	expired.Shares[1].Expires = egressTestTimeMs
	expiredTest := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, expired)
	expiredTest.expectDeny("share B past its grant's expiry", shareTestFlow(shareTestShareB, shareTestNetworkZ, connect.IpProtocolTcp, "100.92.134.20:443"))
	// pending denies every share flow
	pendingTest := newEgressTest(t, device.BridgePolicyProfileHost, device.PosturePending, shareTestFixture())
	pendingTest.expectDeny("pending", shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.129.20:443"))
}

// §17.9's isolation row: C18 is on only at a host enforcing a state with a share; an sdk provider never turns it on.
func TestFriendsAndFamilyEgressIsOnOnlyAtAShareHost(t *testing.T) {
	cases := []struct {
		name    string
		profile device.BridgePolicyProfile
		state   device.PostureState
		fixture *sidecartest.BridgeRulesFixture
		want    bool
	}{
		{name: "a host with a share", profile: device.BridgePolicyProfileHost, state: device.PostureEnforcingDocument, fixture: shareTestFixture(), want: true},
		{name: "a host with none", profile: device.BridgePolicyProfileHost, state: device.PostureEnforcingDocument, fixture: egressTestFixture()},
		{name: "an sdk provider with a share", profile: device.BridgePolicyProfileSdkProvider, state: device.PostureEnforcingDocument, fixture: shareTestFixture()},
		{name: "a pending host", profile: device.BridgePolicyProfileHost, state: device.PosturePending, fixture: shareTestFixture()},
	}
	for _, testCase := range cases {
		test := newEgressTest(t, testCase.profile, testCase.state, testCase.fixture)
		if got := test.policy.FriendsAndFamilyEgress(); got != testCase.want {
			t.Errorf("%s: %v", testCase.name, got)
		}
	}
	if device.NewBridgeEgressPolicy(device.BridgePolicyProfileHost, nil).FriendsAndFamilyEgress() {
		t.Error("a policy before its first publish")
	}
}

// The rules' check refuses a share out of form, each fault alone beside a twin that parses.
func TestParseBridgeRulesHoldsSharesToTheirForm(t *testing.T) {
	if _, err := device.ParseBridgeRules(shareTestFixture().Bytes(), nil); err != nil {
		t.Fatalf("the twin: %v", err)
	}
	faults := map[string]func(rules *bridge.BridgeRules){
		"an alias below the upper /17": func(rules *bridge.BridgeRules) { rules.Shares[0].Targets[0].AliasHostBits = 0x7f00 },
		"a misaligned alias":           func(rules *bridge.BridgeRules) { rules.Shares[0].Targets[0].AliasHostBits = 0x8180 },
		"a /32 alias at a .0":          func(rules *bridge.BridgeRules) { rules.Shares[0].Targets[1].AliasHostBits = 0x8100 },
		"a target of another length":   func(rules *bridge.BridgeRules) { rules.Shares[0].Targets[0].Length = 25 },
		"an alias wider than /17":      func(rules *bridge.BridgeRules) { rules.Shares[0].Targets[0].Length = 16 },
		"two aliases overlapping": func(rules *bridge.BridgeRules) {
			rules.Shares[0].Targets[1].AliasHostBits = 0x8105
		},
		"a target index twice":   func(rules *bridge.BridgeRules) { rules.Shares[0].Targets[1].Index = 0 },
		"a share twice":          func(rules *bridge.BridgeRules) { rules.Shares[1].ShareId = rules.Shares[0].ShareId },
		"a share with no target": func(rules *bridge.BridgeRules) { rules.Shares[1].Targets = nil },
		"a short ShareKey":       func(rules *bridge.BridgeRules) { rules.Shares[0].SharePublicKey = rules.Shares[0].SharePublicKey[:16] },
		"a zero network":         func(rules *bridge.BridgeRules) { rules.Shares[0].AcceptingNetworkId = make([]byte, 16) },
		"ports with no protocol": func(rules *bridge.BridgeRules) {
			rules.Shares[0].Targets[1].Ports = []*bridge.BridgePortRange{{First: 1, Last: 2}}
		},
		"an ICMP target": func(rules *bridge.BridgeRules) { rules.Shares[0].Targets[1].Protocol = 1 },
		"a share link with no network": func(rules *bridge.BridgeRules) {
			rules.Entries = []*bridge.BridgeRuleEntry{{
				Prefix: &bridge.BridgeIpv4Prefix{Address: 0x6450_8100, Length: 24}, Kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK,
				Links: []*bridge.BridgeRuleLink{shareTestRuleLink(8, sidecartest.BridgeFixtureShareId(shareTestShareA), nil)},
			}}
		},
		"an exit over a share link": func(rules *bridge.BridgeRules) {
			rules.Egress = &bridge.BridgeRuleEgress{Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, Exits: []*bridge.BridgeRuleLink{
				shareTestRuleLink(8, sidecartest.BridgeFixtureShareId(shareTestShareA), sidecartest.BridgeFixtureNetworkId(shareTestNetworkY)),
			}}
		},
	}
	for name, edit := range faults {
		rules := shareTestFixture().Rules()
		edit(rules)
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(rules)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := device.ParseBridgeRules(encoded, nil); !errors.Is(err, device.ErrBridgeRulesMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A share link's row to target seed, naming shareId and networkId.
func shareTestRuleLink(seed byte, shareId []byte, networkId []byte) *bridge.BridgeRuleLink {
	clientId := sidecartest.BridgeFixtureClientId(seed)
	return &bridge.BridgeRuleLink{
		TargetClientId:          clientId[:],
		TargetSidecarId:         sidecartest.BridgeFixtureSidecarId(seed),
		TargetIdentityPublicKey: sidecartest.BridgeFixtureIdentityKey(seed).Public().(ed25519.PublicKey),
		Weight:                  1,
		ShareId:                 shareId,
		TargetNetworkId:         networkId,
	}
}

// A ratchet in memory, as the posture keeps one, whose raise a test can fail.
type shareTestRatchet struct {
	stateLock   sync.Mutex
	generations map[string]uint64
	raises      []uint64
	raiseErr    error
}

func newShareTestRatchet() *shareTestRatchet {
	return &shareTestRatchet{generations: map[string]uint64{}}
}

func (self *shareTestRatchet) ShareCertGeneration(shareId []byte) (uint64, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	generation, ok := self.generations[string(shareId)]
	return generation, ok
}

func (self *shareTestRatchet) RaiseShareCert(shareId []byte, generation uint64, signedCert []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.raiseErr != nil {
		return self.raiseErr
	}
	held := self.generations[string(shareId)]
	if generation < held {
		return errors.New("below the ratchet")
	}
	if held < generation {
		self.generations[string(shareId)] = generation
		self.raises = append(self.raises, generation)
	}
	return nil
}

// The ratchet's generation of a share.
func (self *shareTestRatchet) generation(share byte) uint64 {
	generation, _ := self.ShareCertGeneration(sidecartest.BridgeFixtureShareId(share))
	return generation
}

// A ShareCert of share at generation, certifying generation's signer until notAfterMs, signed by the ShareKey seed key.
func shareTestCert(t testing.TB, share byte, generation uint64, notAfterMs int64, key byte) []byte {
	t.Helper()
	cert, err := bridge.ShareCertSigned(&bridge.ShareCert{
		ShareId:          sidecartest.BridgeFixtureShareId(share),
		ConfigGeneration: generation,
		SignerPublicKey:  ed25519.NewKeyFromSeed(shareTestSignerSeed(generation)).Public().(ed25519.PublicKey),
		NotAfterMs:       notAfterMs,
	}, sidecartest.BridgeFixtureShareKey(key).Seed(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// Y's sidecar's delegation for its window client to this host on share, carrying cert, signed by signerGeneration's
// signer, edit applied first.
func shareTestDelegation(t testing.TB, share byte, cert []byte, signerGeneration uint64, edit func(delegation *bridge.WindowDelegation)) []byte {
	t.Helper()
	shareId := sidecartest.BridgeFixtureShareId(share)
	delegation := &bridge.WindowDelegation{
		NetworkId:             sidecartest.BridgeFixtureNetworkId(shareTestNetworkY),
		SubjectSidecarId:      shareTestSubjectId,
		WindowClientId:        shareTestWindowId[:],
		WindowClientPublicKey: shareTestWindowKey.Public().(ed25519.PublicKey),
		TargetSidecarId:       egressTestHostId,
		NotAfterMs:            egressTestTimeMs + egressTestHourMs,
		ShareId:               shareId,
		ShareCert:             cert,
	}
	if edit != nil {
		edit(delegation)
	}
	signed, err := bridge.WindowDelegationSigned(delegation, func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return bridge.ShareSignerSign(delegation.GetShareId(), shareTestSignerSeed(signerGeneration), body)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// A delegation of share A on a cert of generation lapsing in three hours, signed by its signer.
func shareTestValidDelegation(t testing.TB, generation uint64) []byte {
	t.Helper()
	cert := shareTestCert(t, shareTestShareA, generation, egressTestTimeMs+3*egressTestHourMs, shareTestShareA)
	return shareTestDelegation(t, shareTestShareA, cert, generation, nil)
}

// The contract a share link's window client presents: its source, its sealed session key and C13's sealed network.
func shareTestVerify(policy *device.BridgeEgressPolicy, sealedNetwork byte, delegation []byte) *connect.BridgePrincipal {
	return policy.VerifySharePrincipalForTest(shareTestWindowId, shareTestWindowKey.Public().(ed25519.PublicKey),
		connect.Id(sidecartest.BridgeFixtureNetworkId(sealedNetwork)), delegation)
}

// §17.9's admit row, the positive twin: a ShareSigner's delegation under a cert the pinned ShareKey signed is a
// principal of the share and the accepting network, lapsing at the earlier of the two not_afters, and the ratchet holds
// the cert's generation once it is answered; its flows open.
func TestASharePrincipalIsAShareSignersDelegation(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, shareTestFixture())
	ratchet := newShareTestRatchet()
	test.policy.SetShareRatchet(ratchet)
	principal := shareTestVerify(test.policy, shareTestNetworkY, shareTestValidDelegation(t, 7))
	if principal == nil {
		t.Fatal("no principal")
	}
	if principal.Subject != connect.Id(shareTestSubjectId) || principal.Network != connect.Id(sidecartest.BridgeFixtureNetworkId(shareTestNetworkY)) ||
		principal.ShareId != connect.Id(sidecartest.BridgeFixtureShareId(shareTestShareA)) ||
		!principal.NotAfter.Equal(time.UnixMilli(egressTestTimeMs+egressTestHourMs)) {
		t.Fatalf("%+v", principal)
	}
	if ratchet.generation(shareTestShareA) != 7 {
		t.Fatalf("the ratchet is at %d", ratchet.generation(shareTestShareA))
	}
	// a cert that lapses first bounds the principal
	shortCert := shareTestCert(t, shareTestShareA, 7, egressTestTimeMs+egressTestHourMs/2, shareTestShareA)
	short := shareTestVerify(test.policy, shareTestNetworkY, shareTestDelegation(t, shareTestShareA, shortCert, 7, nil))
	if short == nil || !short.NotAfter.Equal(time.UnixMilli(egressTestTimeMs+egressTestHourMs/2)) {
		t.Fatalf("the principal of a shorter cert: %+v", short)
	}
	flow := shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, "100.90.129.20:443")
	flow.Principal = principal
	test.expectMap("its flow", flow, "192.168.50.20:443", shareTestTag(shareTestShareA, 0))
}

// Each refusal of §17.9's admit row alone, beside the twin: a cert below the ratchet, expired, over 7 days and the skew
// out, signed by another key than the pinned ShareKey, or for another share; a delegation its cert's signer did not
// sign, of another network than C13's seal, to another host or window client, lapsed, or signed by an identity key; a
// sealed network that is this one or not the share's; a share the host does not serve; no ratchet. None raises the
// ratchet.
func TestEachShareCertRefusalAdmitsNothing(t *testing.T) {
	now := int64(egressTestTimeMs)
	refusals := []struct {
		name          string
		sealedNetwork byte
		delegation    func(t *testing.T) []byte
	}{
		{name: "a cert below the ratchet", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte { return shareTestValidDelegation(t, 4) }},
		{name: "an expired cert", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte {
			return shareTestDelegation(t, shareTestShareA, shareTestCert(t, shareTestShareA, 7, now, shareTestShareA), 7, nil)
		}},
		{name: "a cert over 7 days out", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte {
			notAfter := now + (7*24*time.Hour + 61*time.Second).Milliseconds()
			return shareTestDelegation(t, shareTestShareA, shareTestCert(t, shareTestShareA, 7, notAfter, shareTestShareA), 7, nil)
		}},
		{name: "a cert not by the pinned ShareKey", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte {
			return shareTestDelegation(t, shareTestShareA, shareTestCert(t, shareTestShareA, 7, now+egressTestHourMs, 0x39), 7, nil)
		}},
		{name: "another share's cert", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte {
			return shareTestDelegation(t, shareTestShareA, shareTestCert(t, shareTestShareB, 7, now+egressTestHourMs, shareTestShareB), 7, nil)
		}},
		{name: "a delegation its cert's signer did not sign", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte {
			return shareTestDelegation(t, shareTestShareA, shareTestCert(t, shareTestShareA, 7, now+egressTestHourMs, shareTestShareA), 8, nil)
		}},
		{name: "a delegation of another network than the seal", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte {
			cert := shareTestCert(t, shareTestShareA, 7, now+egressTestHourMs, shareTestShareA)
			return shareTestDelegation(t, shareTestShareA, cert, 7, func(delegation *bridge.WindowDelegation) {
				delegation.NetworkId = sidecartest.BridgeFixtureNetworkId(shareTestNetworkZ)
			})
		}},
		{name: "a delegation to another host", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte {
			cert := shareTestCert(t, shareTestShareA, 7, now+egressTestHourMs, shareTestShareA)
			return shareTestDelegation(t, shareTestShareA, cert, 7, func(delegation *bridge.WindowDelegation) {
				delegation.TargetSidecarId = sidecartest.BridgeFixtureSidecarId(0x7F)
			})
		}},
		{name: "a delegation of another window client", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte {
			cert := shareTestCert(t, shareTestShareA, 7, now+egressTestHourMs, shareTestShareA)
			return shareTestDelegation(t, shareTestShareA, cert, 7, func(delegation *bridge.WindowDelegation) {
				delegation.WindowClientId = sidecartest.BridgeFixtureSidecarId(0x92)
			})
		}},
		{name: "a lapsed delegation", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte {
			cert := shareTestCert(t, shareTestShareA, 7, now+egressTestHourMs, shareTestShareA)
			return shareTestDelegation(t, shareTestShareA, cert, 7, func(delegation *bridge.WindowDelegation) { delegation.NotAfterMs = now })
		}},
		{name: "a delegation an identity key signed", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte {
			delegation := principalTestDelegation()
			delegation.NetworkId = sidecartest.BridgeFixtureNetworkId(shareTestNetworkY)
			delegation.WindowClientId = shareTestWindowId[:]
			delegation.WindowClientPublicKey = shareTestWindowKey.Public().(ed25519.PublicKey)
			return principalTestSign(t, delegation, sidecartest.BridgeFixtureIdentityKey(egressTestUntagged), bridge.SignedType_SIGNED_WINDOW_DELEGATION)
		}},
		{name: "a sealed network not the share's", sealedNetwork: shareTestNetworkZ, delegation: func(t *testing.T) []byte { return shareTestValidDelegation(t, 7) }},
		{name: "a share this host does not serve", sealedNetwork: shareTestNetworkY, delegation: func(t *testing.T) []byte {
			cert := shareTestCert(t, 0x39, 7, now+egressTestHourMs, 0x39)
			return shareTestDelegation(t, 0x39, cert, 7, nil)
		}},
	}
	for _, refusal := range refusals {
		test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, shareTestFixture())
		ratchet := newShareTestRatchet()
		ratchet.generations[string(sidecartest.BridgeFixtureShareId(shareTestShareA))] = 5
		test.policy.SetShareRatchet(ratchet)
		if principal := shareTestVerify(test.policy, refusal.sealedNetwork, refusal.delegation(t)); principal != nil {
			t.Errorf("%s: admitted %+v", refusal.name, principal)
		}
		if 0 < len(ratchet.raises) {
			t.Errorf("%s: raised the ratchet to %v", refusal.name, ratchet.raises)
		}
		// the twin on the same policy
		if shareTestVerify(test.policy, shareTestNetworkY, shareTestValidDelegation(t, 7)) == nil {
			t.Errorf("%s: the twin was refused", refusal.name)
		}
	}
	// this host's own network, sealed, is no share's
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, shareTestFixture())
	test.policy.SetShareRatchet(newShareTestRatchet())
	if principal := test.policy.VerifySharePrincipalForTest(shareTestWindowId, shareTestWindowKey.Public().(ed25519.PublicKey),
		connect.Id(egressTestNetworkId), shareTestValidDelegation(t, 7)); principal != nil {
		t.Error("a share link sealed to this network was admitted")
	}
	// a policy with no ratchet admits no share principal
	unratcheted := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, shareTestFixture())
	if shareTestVerify(unratcheted.policy, shareTestNetworkY, shareTestValidDelegation(t, 7)) != nil {
		t.Error("a policy with no ratchet admitted a share principal")
	}
	// a share's grant revoked between states admits no new contract
	revoked := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, shareTestFixture())
	revoked.policy.SetShareRatchet(newShareTestRatchet())
	revoked.input.Overlay = []device.PostureOverlayEntry{{Kind: device.PostureOverlayGrantRevoke, Id: sidecartest.BridgeFixtureGrantId(9)}}
	revoked.republish()
	if shareTestVerify(revoked.policy, shareTestNetworkY, shareTestValidDelegation(t, 7)) != nil {
		t.Error("a share whose grant was revoked admitted a contract")
	}
}

// §17.9's bound row: a sidecar Y removed keeps generation 7's signer until a later generation's cert reaches the host,
// in any Y delegation; from then a contract on its generation 7 cert is refused, and Y's current readers go on.
func TestARemovedSidecarIsRefusedAfterALaterCert(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, shareTestFixture())
	ratchet := newShareTestRatchet()
	test.policy.SetShareRatchet(ratchet)
	removed := shareTestValidDelegation(t, 7)
	if shareTestVerify(test.policy, shareTestNetworkY, removed) == nil {
		t.Fatal("generation 7 before a later cert reached the host")
	}
	if shareTestVerify(test.policy, shareTestNetworkY, shareTestValidDelegation(t, 8)) == nil {
		t.Fatal("generation 8")
	}
	if ratchet.generation(shareTestShareA) != 8 {
		t.Fatalf("the ratchet is at %d", ratchet.generation(shareTestShareA))
	}
	if shareTestVerify(test.policy, shareTestNetworkY, removed) != nil {
		t.Fatal("the removed sidecar's generation 7 after generation 8 reached the host")
	}
	if shareTestVerify(test.policy, shareTestNetworkY, shareTestValidDelegation(t, 8)) == nil {
		t.Fatal("a current reader's generation 8")
	}
}

// QD-671: the ratchet's raise is committed before the principal is answered, so a raise that does not commit refuses
// the contract and admits nothing; a kill of the posture's store at the raise leaves the ratchet where it was and the
// contract refused, never admitted on a generation the store does not hold.
func TestTheRatchetIsCommittedBeforeItAdmits(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, shareTestFixture())
	ratchet := newShareTestRatchet()
	ratchet.raiseErr = errors.New("the store's commit failed")
	test.policy.SetShareRatchet(ratchet)
	if principal := shareTestVerify(test.policy, shareTestNetworkY, shareTestValidDelegation(t, 7)); principal != nil {
		t.Fatalf("admitted on a raise that did not commit: %+v", principal)
	}
	if ratchet.generation(shareTestShareA) != 0 {
		t.Fatal("the ratchet moved")
	}

	// the posture's own store, killed at the raise's write
	store := device.NewMemoryPostureStoreForTest()
	share := newShareStateTest(t, store)
	if share.verify(share.delegation(7)) == nil {
		t.Fatal("generation 7 on a live store")
	}
	store.KillAtNextWrite()
	if principal := share.verify(share.delegation(9)); principal != nil {
		t.Fatalf("admitted generation 9 while its raise's write died: %+v", principal)
	}
	share.close()
	restarted := share.restart(store.Survivor())
	// the raise to 9 never landed: 7 is what the store holds, so 8 is admitted and 6 is not
	if restarted.verify(restarted.delegation(6)) != nil {
		t.Fatal("generation 6 below the ratchet the store kept")
	}
	if restarted.verify(restarted.delegation(8)) == nil {
		t.Fatal("generation 8 above the ratchet the store kept")
	}
}

// §17.9's admit row after a restart: the ratchet lives in the posture's store, so a bridge restored from it refuses a
// cert below the generation it committed before it stopped.
func TestTheRatchetSurvivesARestart(t *testing.T) {
	store := device.NewMemoryPostureStoreForTest()
	share := newShareStateTest(t, store)
	if share.verify(share.delegation(7)) == nil {
		t.Fatal("generation 7")
	}
	share.close()
	restarted := share.restart(store)
	if restarted.verify(restarted.delegation(6)) != nil {
		t.Fatal("generation 6 after a restart from a store holding 7")
	}
	if restarted.verify(restarted.delegation(7)) == nil {
		t.Fatal("generation 7 after the restart")
	}
}

// A bridge enforcing shareTestFixture's rules on a store a test holds, its policy's ratchet the bridge's own posture.
type shareStateTest struct {
	t        *testing.T
	log      *device.BridgeLogFixtureForTest
	settings *device.BridgeSettings
	bridge   *device.Bridge
	closed   sync.Once
}

// A bridge on store, through Pending and a state of shareTestFixture's rules, its sidecar_id the log's own.
func newShareStateTest(t *testing.T, store device.PostureStore) *shareStateTest {
	t.Helper()
	clock := sidecartest.NewFakeClock(time.UnixMilli(egressTestTimeMs))
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	log := device.NewBridgeLogFixtureForTest(t)
	log.Base(true)
	log.Tick()
	self := &shareStateTest{t: t, log: log, settings: settings}
	self.open(store)
	if err := self.bridge.SetPending(log.Pending()); err != nil {
		t.Fatal(err)
	}
	fixture := shareTestFixture()
	state, stateLog := log.State(fixture.Bytes(), true)
	state.Identities = stateTestIdentities(fixture)
	state.DaemonListeners = egressTestListeners
	if err := self.bridge.SetState(state, stateLog); err != nil {
		t.Fatal(err)
	}
	return self
}

// Builds the bridge on store, closed with the test unless the test closed it first.
func (self *shareStateTest) open(store device.PostureStore) {
	self.t.Helper()
	bridgeBridge, err := device.NewBridge(context.Background(), store, nil, self.settings)
	if err != nil {
		self.t.Fatal(err)
	}
	self.bridge = bridgeBridge
	self.t.Cleanup(self.close)
}

// Closes the bridge once.
func (self *shareStateTest) close() {
	self.closed.Do(self.bridge.Close)
}

// The same host restored from store, as a restart finds it: enforcing what the store holds.
func (self *shareStateTest) restart(store device.PostureStore) *shareStateTest {
	self.t.Helper()
	restarted := &shareStateTest{t: self.t, log: self.log, settings: self.settings}
	restarted.open(store)
	if !restarted.bridge.Decision().State.Enforcing() {
		self.t.Fatalf("the restored bridge is %v", restarted.bridge.Decision().State)
	}
	return restarted
}

// A delegation of share A on generation's cert, to this bridge's host, the log's sidecar.
func (self *shareStateTest) delegation(generation uint64) []byte {
	self.t.Helper()
	cert := shareTestCert(self.t, shareTestShareA, generation, egressTestTimeMs+3*egressTestHourMs, shareTestShareA)
	return shareTestDelegation(self.t, shareTestShareA, cert, generation, func(delegation *bridge.WindowDelegation) {
		delegation.TargetSidecarId = self.log.Pending().GetSidecarId()
	})
}

// A share link's contract to this bridge's host, from Y's window client, carrying delegation.
func (self *shareStateTest) verify(delegation []byte) *connect.BridgePrincipal {
	return self.bridge.VerifySharePrincipalForTest(shareTestWindowId, shareTestWindowKey.Public().(ed25519.PublicKey),
		connect.Id(sidecartest.BridgeFixtureNetworkId(shareTestNetworkY)), delegation)
}

// §17.9's sender row on a bridge: an entry of an alias whose link is a share link reaches its host over a link the host
// builds FriendsAndFamily with the link's aliases, its target's binding naming the sharing network, and every window
// client's delegation naming the share.
func TestABridgeRoutesAnAliasOverItsShareLink(t *testing.T) {
	fixture := routeTestFixture()
	fixture.Entries = append(fixture.Entries,
		sidecartest.BridgeRulesFixtureEntry{Prefix: "100.80.129.0/24", Links: []sidecartest.BridgeRulesFixtureLink{{Target: 8, Share: shareTestShareA, Network: shareTestNetworkY}}},
		sidecartest.BridgeRulesFixtureEntry{Prefix: "100.80.128.1", Links: []sidecartest.BridgeRulesFixtureLink{{Target: 8, Share: shareTestShareA, Network: shareTestNetworkY}}},
	)
	var signedLock sync.Mutex
	signed := []*bridge.WindowDelegation{}
	test := newRouteTest(t, fixture, func(settings *device.BridgeSettings) {
		settings.LinkSign = func(ctx context.Context, delegation *bridge.WindowDelegation) ([]byte, error) {
			signedLock.Lock()
			defer signedLock.Unlock()
			signed = append(signed, delegation)
			return []byte("signed"), nil
		}
		settings.LinkTargetKey = func(ctx context.Context, targetSidecarId connect.Id, targetClientId connect.Id) ([]byte, error) {
			seed := targetClientId[1]
			network := routeTestNetworkId
			if seed == 8 {
				// the share's host is the sharing network's sidecar
				network = sidecartest.BridgeFixtureNetworkId(shareTestNetworkY)
			}
			return linkTestSignedBinding(t, network, seed, sidecartest.BridgeFixtureIdentityKey(seed), nil), nil
		}
	})
	packet := routeTestTcp(routeTestSource, "100.80.129.20", 443)
	test.bridge.Route(packet)
	link := test.awaitLink(packet)
	if link.Target != sidecartest.BridgeFixtureClientId(8) {
		t.Fatalf("carried to %v", link.Target)
	}
	builds := test.host.Builds()
	build := builds[len(builds)-1]
	want := []netip.Prefix{netip.MustParsePrefix("100.80.128.1/32"), netip.MustParsePrefix("100.80.129.0/24")}
	if len(build.ShareAliases) != len(want) || build.ShareAliases[0] != want[0] || build.ShareAliases[1] != want[1] {
		t.Fatalf("the share link's aliases: %v", build.ShareAliases)
	}
	signedNow := func() []*bridge.WindowDelegation {
		signedLock.Lock()
		defer signedLock.Unlock()
		return append([]*bridge.WindowDelegation(nil), signed...)
	}
	if delegations := signedNow(); len(delegations) == 0 ||
		!bytes.Equal(delegations[len(delegations)-1].GetShareId(), sidecartest.BridgeFixtureShareId(shareTestShareA)) {
		t.Fatalf("the share link's delegation: %v", delegations)
	}
	// a link of this network carries no aliases and names no share
	sameNetwork := routeTestUdp(routeTestSource, "100.80.1.4", 9)
	test.bridge.Route(sameNetwork)
	test.awaitLink(sameNetwork)
	for _, build := range test.host.Builds() {
		if build.Target == sidecartest.BridgeFixtureClientId(4) && build.ShareAliases != nil {
			t.Fatalf("a link of this network carried aliases %v", build.ShareAliases)
		}
	}
	for _, delegation := range signedNow() {
		if bytes.Equal(delegation.GetTargetSidecarId(), sidecartest.BridgeFixtureSidecarId(4)) && 0 < len(delegation.GetShareId()) {
			t.Fatal("a link of this network named a share")
		}
	}
}

// §17.9's target row on a share link: the host's binding must name the sharing network, under the key the alias
// pinned; a binding of this network, or one of another key, builds nothing.
func TestAShareLinksBindingNamesTheSharingNetwork(t *testing.T) {
	networkY := sidecartest.BridgeFixtureNetworkId(shareTestNetworkY)
	target := linkTestTarget(5)
	target.ShareId = connect.Id(sidecartest.BridgeFixtureShareId(shareTestShareA))
	target.TargetNetworkId = connect.Id(networkY)
	aliases := []netip.Prefix{netip.MustParsePrefix("100.80.129.0/24")}
	target.ShareAliasesDigest = device.BridgeShareAliasesDigestForTest(aliases)
	for name, binding := range map[string][]byte{
		"a binding of this network":     linkTestBinding(t, 5),
		"a binding of another identity": linkTestSignedBinding(t, networkY, 5, sidecartest.BridgeFixtureIdentityKey(6), nil),
	} {
		test := newLinkTest(t, nil)
		test.setBinding(5, binding)
		link := test.manager.RetainShares([]device.BridgeLinkTarget{target}, map[device.BridgeLinkTarget][]netip.Prefix{target: aliases})[target][0].Link
		test.manager.RouteForTest(link)
		if down := test.awaitDown(); down != link {
			t.Fatalf("%s: link %d down, want %d", name, down, link)
		}
		if 0 < test.host.BuildCount(target.ClientId) {
			t.Fatalf("%s: built", name)
		}
	}
	test := newLinkTest(t, nil)
	test.setBinding(5, linkTestSignedBinding(t, networkY, 5, sidecartest.BridgeFixtureIdentityKey(5), nil))
	link := test.manager.RetainShares([]device.BridgeLinkTarget{target}, map[device.BridgeLinkTarget][]netip.Prefix{target: aliases})[target][0].Link
	test.open(link)
	builds := test.host.Builds()
	if len(builds) != 1 || len(builds[0].ShareAliases) != 1 || builds[0].ShareAliases[0] != aliases[0] {
		t.Fatalf("the twin's build: %+v", builds)
	}
	if signed := test.signedDelegations(); len(signed) != 1 || !bytes.Equal(signed[0].GetShareId(), target.ShareId[:]) {
		t.Fatalf("the twin's delegation: %v", signed)
	}
}

// §17.9's sign row: when the share's signer changes, each live window client of that share's links is signed again,
// and its next contract carries the new delegation; a link of another share, or of this network, is not.
func TestResignSharesSignsTheShareLinksWindowClientsAgain(t *testing.T) {
	expireTime := time.UnixMilli(linkTestTimeMs).Add(7 * 24 * time.Hour)
	test, host := newGeneratorTest(t, expireTime)
	networkY := sidecartest.BridgeFixtureNetworkId(shareTestNetworkY)
	target := linkTestTarget(4)
	target.ShareId = connect.Id(sidecartest.BridgeFixtureShareId(shareTestShareA))
	target.TargetNetworkId = connect.Id(networkY)
	aliases := []netip.Prefix{netip.MustParsePrefix("100.80.129.0/24")}
	target.ShareAliasesDigest = device.BridgeShareAliasesDigestForTest(aliases)
	test.setBinding(4, linkTestSignedBinding(t, networkY, 4, sidecartest.BridgeFixtureIdentityKey(4), nil))
	link := test.manager.RetainShares([]device.BridgeLinkTarget{target}, map[device.BridgeLinkTarget][]netip.Prefix{target: aliases})[target][0].Link
	test.manager.RouteForTest(link)
	test.await("the build", func() bool { return test.manager.LinkBuiltForTest(link) })
	window, err := host.built()
	if err != nil || window == nil {
		t.Fatalf("no window client: %v", err)
	}
	if count, err := test.manager.ResignSharesForTest([]connect.Id{connect.Id(sidecartest.BridgeFixtureShareId(shareTestShareB))}); count != 0 || err != nil {
		t.Fatalf("another share's signer re-signed %d: %v", count, err)
	}
	test.setSignSuffix([]byte(" by the next signer"))
	count, err := test.manager.ResignSharesForTest([]connect.Id{target.ShareId})
	if count != 1 || err != nil {
		t.Fatalf("re-signed %d: %v", count, err)
	}
	signed := test.signedDelegations()
	if len(signed) != 2 || !bytes.Equal(signed[1].GetShareId(), target.ShareId[:]) ||
		!bytes.Equal(signed[1].GetWindowClientId(), window.ClientId().Bytes()) || signed[1].GetNotAfterMs() != expireTime.UnixMilli() {
		t.Fatalf("the delegations signed: %v", signed)
	}
	window.ContractManager().CreateContract(connect.ContractKey{Destination: connect.DestinationId(target.ClientId)}, 0, 0)
	requests := host.inner.control.taken()
	want := append(append([]byte("signed delegation of "), window.ClientId().Bytes()...), []byte(" by the next signer")...)
	if len(requests) != 1 || !bytes.Equal(requests[0].WindowDelegation, want) {
		t.Fatalf("the next contract carried %q", requests[0].WindowDelegation)
	}
}
