// VerifyPrincipal (§17.9's verify row, D-BRIDGE-17): a delegation the subject signed admits its window client's
// contract, each mismatch alone refuses it beside its twin, C13's sealed subject must be a client the delegation's
// subject binds, and the answer costs one signature check per contract however many flows ride it. FS-38's M4 rows at
// unit level run through principalTestNat, a fake NAT that asks the hook as connect's does, once per contract and then
// per flow, and counts the upstream sockets it would open: an operator-minted contract opens none over TCP, UDP or ICMP,
// and a valid delegation is the positive twin.

package device_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A window client of the untagged subject's: its own id and key, a child of the subject's client.
var (
	principalTestWindowId  = sidecartest.BridgeFixtureClientId(0x90)
	principalTestWindowKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	principalTestOtherKey  = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x78}, ed25519.SeedSize))
)

// The delegation the untagged subject signs for its window client to this host, lapsing in an hour.
func principalTestDelegation() *bridge.WindowDelegation {
	return &bridge.WindowDelegation{
		NetworkId:             egressTestNetworkId,
		SubjectSidecarId:      sidecartest.BridgeFixtureSidecarId(egressTestUntagged),
		WindowClientId:        principalTestWindowId[:],
		WindowClientPublicKey: principalTestWindowKey.Public().(ed25519.PublicKey),
		TargetSidecarId:       egressTestHostId,
		NotAfterMs:            egressTestTimeMs + egressTestHourMs,
	}
}

// delegation signed by key as its subject's id signs, of signedType.
func principalTestSign(t *testing.T, delegation *bridge.WindowDelegation, key ed25519.PrivateKey, signedType bridge.SignedType) []byte {
	t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(delegation)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.Signed{
		Body:      body,
		SignerId:  delegation.GetSubjectSidecarId(),
		Signature: ed25519.Sign(key, bridge.SignedBytes(bridge.SignedPurposeWindowDelegation, signedType, body)),
		Type:      uint32(signedType),
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// delegation signed by its subject, as bridge.WindowDelegationSigned writes it.
func principalTestSigned(t *testing.T, delegation *bridge.WindowDelegation) []byte {
	t.Helper()
	key := sidecartest.BridgeFixtureIdentityKey(egressTestUntagged)
	signed, err := bridge.WindowDelegationSigned(delegation, func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      body,
			SignerId:  delegation.GetSubjectSidecarId(),
			Signature: ed25519.Sign(key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// What one contract shows a host: its source, the session's key, C13's seals and the delegation.
type principalTestContract struct {
	contractId    connect.Id
	sourceId      connect.Id
	sessionKey    []byte
	sealedNetwork connect.Id
	sealedSubject connect.Id
	delegation    []byte
}

// The untagged subject's window client's contract, sealed honestly, carrying delegation.
func principalTestContractOf(contractSeed byte, delegation []byte) principalTestContract {
	return principalTestContract{
		contractId:    sidecartest.BridgeFixtureClientId(contractSeed),
		sourceId:      principalTestWindowId,
		sessionKey:    principalTestWindowKey.Public().(ed25519.PublicKey),
		sealedNetwork: connect.Id(egressTestNetworkId),
		sealedSubject: sidecartest.BridgeFixtureClientId(egressTestUntagged),
		delegation:    delegation,
	}
}

// A fake provider NAT: it asks the hook for a contract's principal once, at its first flow, keeps the answer as
// connect's NAT does, and opens an upstream socket only for a flow the hook passes or maps.
type principalTestNat struct {
	hook        *device.BridgeEgressPolicy
	principals  map[connect.Id]*connect.BridgePrincipal
	socketCount int
}

func newPrincipalTestNat(hook *device.BridgeEgressPolicy) *principalTestNat {
	return &principalTestNat{hook: hook, principals: map[connect.Id]*connect.BridgePrincipal{}}
}

// Opens a flow of contract to to, and whether an upstream socket opened.
func (self *principalTestNat) open(contract principalTestContract, ipProtocol connect.IpProtocol, to string) bool {
	principal, asked := self.principals[contract.contractId]
	if !asked {
		principal = self.hook.VerifyPrincipalForTest(contract.sourceId, contract.sessionKey, contract.sealedNetwork,
			contract.sealedSubject, contract.delegation)
		self.principals[contract.contractId] = principal
	}
	flow := egressTestFlow(egressTestUntagged, ipProtocol, to)
	flow.Source = connect.TransferPath{SourceId: contract.sourceId}
	flow.SourceSubject = contract.sealedSubject
	flow.SourceNetwork = contract.sealedNetwork
	flow.Principal = principal
	decision := self.hook.ResolveEgress(flow)
	if decision.Verdict == connect.EgressVerdictPass || decision.Verdict == connect.EgressVerdictMap {
		self.socketCount += 1
		return true
	}
	return false
}

// The flows FS-38 opens on each contract: TCP, UDP and ICMP, to a LAN host, an exit and this host.
var principalTestFlows = []struct {
	ipProtocol connect.IpProtocol
	to         string
}{
	{ipProtocol: connect.IpProtocolTcp, to: "100.80.1.2:22"},
	{ipProtocol: connect.IpProtocolUdp, to: "100.80.1.2:6000"},
	{ipProtocol: connect.IpProtocolIcmp, to: "100.80.1.2:0"},
	{ipProtocol: connect.IpProtocolTcp, to: "203.0.113.9:443"},
	{ipProtocol: connect.IpProtocolUdp, to: "203.0.113.9:53"},
}

// The positive twin: the subject's delegation verifies, names the subject, this network and its not_after, and its
// flows open sockets.
func TestVerifyPrincipalAdmitsTheSubjectsDelegation(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	contract := principalTestContractOf(1, principalTestSigned(t, principalTestDelegation()))
	principal := test.policy.VerifyPrincipalForTest(contract.sourceId, contract.sessionKey, contract.sealedNetwork,
		contract.sealedSubject, contract.delegation)
	if principal == nil {
		t.Fatal("no principal")
	}
	if principal.Subject != connect.Id(sidecartest.BridgeFixtureSidecarId(egressTestUntagged)) ||
		principal.Network != connect.Id(egressTestNetworkId) || principal.ShareId != (connect.Id{}) ||
		!principal.NotAfter.Equal(time.UnixMilli(egressTestTimeMs+egressTestHourMs)) {
		t.Fatalf("%+v", principal)
	}
	nat := newPrincipalTestNat(test.policy)
	for _, flow := range principalTestFlows {
		if !nat.open(contract, flow.ipProtocol, flow.to) {
			t.Errorf("%v to %s opened nothing", flow.ipProtocol, flow.to)
		}
	}
}

// Each mismatch alone refuses the contract, and every one of its flows opens no socket, beside the twin that passes.
func TestVerifyPrincipalRefusesEachMismatchAlone(t *testing.T) {
	signed := func(mutate func(delegation *bridge.WindowDelegation)) []byte {
		delegation := principalTestDelegation()
		mutate(delegation)
		return principalTestSigned(t, delegation)
	}
	badSignature := &bridge.Signed{}
	if err := proto.Unmarshal(principalTestSigned(t, principalTestDelegation()), badSignature); err != nil {
		t.Fatal(err)
	}
	badSignature.Signature[5] ^= 0x10
	badSignatureBytes, err := proto.Marshal(badSignature)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(contract *principalTestContract, test *egressTest)
	}{
		{name: "key", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.sessionKey = principalTestOtherKey.Public().(ed25519.PublicKey)
		}},
		{name: "expired", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = signed(func(delegation *bridge.WindowDelegation) { delegation.NotAfterMs = egressTestTimeMs })
		}},
		{name: "wrong target", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = signed(func(delegation *bridge.WindowDelegation) {
				delegation.TargetSidecarId = sidecartest.BridgeFixtureSidecarId(0xB5)
			})
		}},
		{name: "wrong network in the delegation", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = signed(func(delegation *bridge.WindowDelegation) {
				delegation.NetworkId = sidecartest.BridgeFixtureSidecarId(0xB6)
			})
		}},
		{name: "another sealed network", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.sealedNetwork = connect.Id(sidecartest.BridgeFixtureSidecarId(0xB6))
		}},
		{name: "unsealed", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.sealedNetwork = connect.Id{}
			contract.sealedSubject = connect.Id{}
		}},
		{name: "wrong source", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.sourceId = sidecartest.BridgeFixtureClientId(0x91)
		}},
		{name: "wrong type", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = principalTestSign(t, principalTestDelegation(), sidecartest.BridgeFixtureIdentityKey(egressTestUntagged),
				bridge.SignedType_SIGNED_SHARE_CERT)
		}},
		{name: "subject not bound", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.sealedSubject = sidecartest.BridgeFixtureClientId(egressTestTagged)
		}},
		{name: "sealed subject unknown", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.sealedSubject = sidecartest.BridgeFixtureClientId(0x7F)
		}},
		{name: "revoked", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.BridgeState.Identities[0].Revoked = true
			test.republish()
		}},
		{name: "suspended", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.BridgeState.Identities[0].Suspended = true
			test.republish()
		}},
		{name: "revoked between states", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.Overlay = []device.PostureOverlayEntry{
				{Kind: device.PostureOverlaySidecarRevoke, Id: sidecartest.BridgeFixtureSidecarId(egressTestUntagged)},
			}
			test.republish()
		}},
		{name: "bad signature", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = badSignatureBytes
		}},
		{name: "signed by another key", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = principalTestSign(t, principalTestDelegation(), principalTestOtherKey, bridge.SignedType_SIGNED_WINDOW_DELEGATION)
		}},
		{name: "no delegation", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = nil
		}},
		{name: "pending", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.State = device.PosturePending
			test.republish()
		}},
	}
	for i, testCase := range cases {
		test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
		contract := principalTestContractOf(byte(i+1), principalTestSigned(t, principalTestDelegation()))
		testCase.mutate(&contract, test)
		if principal := test.policy.VerifyPrincipalForTest(contract.sourceId, contract.sessionKey, contract.sealedNetwork,
			contract.sealedSubject, contract.delegation); principal != nil {
			t.Errorf("%s: a principal %+v", testCase.name, principal)
		}
		nat := newPrincipalTestNat(test.policy)
		for _, flow := range principalTestFlows {
			nat.open(contract, flow.ipProtocol, flow.to)
		}
		if nat.socketCount != 0 {
			t.Errorf("%s: %d sockets", testCase.name, nat.socketCount)
		}
		// the twin, on a fresh host
		twin := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
		twinContract := principalTestContractOf(byte(i+1), principalTestSigned(t, principalTestDelegation()))
		if principal := twin.policy.VerifyPrincipalForTest(twinContract.sourceId, twinContract.sessionKey, twinContract.sealedNetwork,
			twinContract.sealedSubject, twinContract.delegation); principal == nil {
			t.Errorf("%s's twin: no principal", testCase.name)
		}
	}
}

// §17.9's "else deny and alarm": only a sealed subject the delegation's subject does not bind is counted as a mismatch;
// a delegation that fails on its own is refused with no alarm.
func TestVerifyPrincipalAlarmsOnASealedSubjectItsDelegationDoesNotBind(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	contract := principalTestContractOf(1, principalTestSigned(t, principalTestDelegation()))
	contract.sealedSubject = sidecartest.BridgeFixtureClientId(egressTestTagged)
	test.policy.VerifyPrincipalForTest(contract.sourceId, contract.sessionKey, contract.sealedNetwork, contract.sealedSubject, contract.delegation)
	if _, mismatchCount := test.policy.PrincipalCountsForTest(); mismatchCount != 1 {
		t.Fatalf("%d mismatches", mismatchCount)
	}
	contract = principalTestContractOf(2, principalTestSigned(t, principalTestDelegation()))
	contract.sessionKey = principalTestOtherKey.Public().(ed25519.PublicKey)
	test.policy.VerifyPrincipalForTest(contract.sourceId, contract.sessionKey, contract.sealedNetwork, contract.sealedSubject, contract.delegation)
	if _, mismatchCount := test.policy.PrincipalCountsForTest(); mismatchCount != 1 {
		t.Fatalf("%d mismatches after a key mismatch", mismatchCount)
	}
}

// A peer with no verified session key is no session, as on a client without ExposeVerifiedPeerClientKey: refused, as is
// any mode but Network and any principal at an sdk provider.
func TestVerifyPrincipalRefusesWithoutASession(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	peer := connect.Peer{
		ProvideMode:      protocol.ProvideMode_Network,
		ContractClass:    connect.ContractClassData,
		SourceSubject:    sidecartest.BridgeFixtureClientId(egressTestUntagged),
		SourceNetwork:    connect.Id(egressTestNetworkId),
		WindowDelegation: principalTestSigned(t, principalTestDelegation()),
	}
	source := connect.TransferPath{SourceId: principalTestWindowId}
	if principal := test.policy.VerifyPrincipal(source, peer); principal != nil {
		t.Fatal("a principal with no session key")
	}
	peer.ProvideMode = protocol.ProvideMode_FriendsAndFamily
	if principal := test.policy.VerifyPrincipal(source, peer); principal != nil {
		t.Fatal("a principal on a share link")
	}
	if verifiedCount, _ := test.policy.PrincipalCountsForTest(); verifiedCount != 0 {
		t.Fatalf("%d signatures checked with no session", verifiedCount)
	}
}

// FS-38 at unit level: an operator-minted window client, its contract correctly sealed to claim the subject, opens zero
// upstream sockets over TCP, UDP and ICMP whether it carries no delegation, one its operator signed, or another
// subject's; the subject's own delegation is the positive twin.
func TestFs38OperatorMintedWindowClientOpensNoSockets(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	nat := newPrincipalTestNat(test.policy)
	minted := []principalTestContract{
		principalTestContractOf(1, nil),
		principalTestContractOf(2, principalTestSign(t, principalTestDelegation(), principalTestOtherKey, bridge.SignedType_SIGNED_WINDOW_DELEGATION)),
	}
	otherSubject := principalTestDelegation()
	otherSubject.SubjectSidecarId = sidecartest.BridgeFixtureSidecarId(egressTestTagged)
	minted = append(minted, principalTestContractOf(3, principalTestSign(t, otherSubject, sidecartest.BridgeFixtureIdentityKey(egressTestTagged),
		bridge.SignedType_SIGNED_WINDOW_DELEGATION)))
	for _, contract := range minted {
		for _, flow := range principalTestFlows {
			nat.open(contract, flow.ipProtocol, flow.to)
		}
	}
	if nat.socketCount != 0 {
		t.Fatalf("operator-minted contracts opened %d sockets", nat.socketCount)
	}
	valid := principalTestContractOf(4, principalTestSigned(t, principalTestDelegation()))
	for _, flow := range principalTestFlows {
		nat.open(valid, flow.ipProtocol, flow.to)
	}
	if nat.socketCount != len(principalTestFlows) {
		t.Fatalf("the valid delegation opened %d of %d", nat.socketCount, len(principalTestFlows))
	}
}

// A verify costs one signature check per contract across many flows: connect keeps the answer, and ResolveEgress only
// looks the subject up.
func TestVerifyPrincipalChecksOneSignaturePerContract(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	nat := newPrincipalTestNat(test.policy)
	for contractSeed := byte(1); contractSeed <= 3; contractSeed += 1 {
		contract := principalTestContractOf(contractSeed, principalTestSigned(t, principalTestDelegation()))
		for range 100 {
			nat.open(contract, connect.IpProtocolTcp, "203.0.113.9:443")
		}
	}
	if verifiedCount, _ := test.policy.PrincipalCountsForTest(); verifiedCount != 3 {
		t.Fatalf("%d signature checks for 3 contracts of 300 flows", verifiedCount)
	}
	if nat.socketCount != 300 {
		t.Fatalf("%d sockets", nat.socketCount)
	}
}

// The principal rides every flow of its contract, and ResolveEgress rechecks its subject per flow: a revocation after
// the verify denies the next flow, and the principal lapses at its not_after.
func TestResolveEgressRechecksThePrincipalPerFlow(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	nat := newPrincipalTestNat(test.policy)
	contract := principalTestContractOf(1, principalTestSigned(t, principalTestDelegation()))
	if !nat.open(contract, connect.IpProtocolTcp, "203.0.113.9:443") {
		t.Fatal("the first flow")
	}
	test.input.Overlay = []device.PostureOverlayEntry{{Kind: device.PostureOverlaySuspend, Id: sidecartest.BridgeFixtureSidecarId(egressTestUntagged)}}
	test.republish()
	if nat.open(contract, connect.IpProtocolTcp, "203.0.113.9:443") {
		t.Fatal("a flow after the subject's suspension")
	}
	test.input.Overlay = nil
	test.republish()
	if !nat.open(contract, connect.IpProtocolTcp, "203.0.113.9:443") {
		t.Fatal("a flow after the next state reversed it")
	}
	test.clock.now = time.UnixMilli(egressTestTimeMs + egressTestHourMs)
	if nat.open(contract, connect.IpProtocolTcp, "203.0.113.9:443") {
		t.Fatal("a flow at the delegation's not_after")
	}
}
