// Forwarding-key principals at a host (§17.9's verify row, D-BRIDGE-17, owner decision 197; DESIGN-DETAILS 4.2.5): a
// delegation signed by the key of its subject's live forwarding Delegation admits its window client's contract, each
// mismatch alone refuses it beside its twin, the per-flow recheck denies it while the overlay revokes or supersedes
// that Delegation or once the state lists another, a principal the same subject's identity key admitted is untouched,
// and the bridge ends exactly the flows the forwarding key admitted. FS-38's forwarding rows at unit level run through
// principalTestNat: an operator-minted contract carrying a forged forwarding delegation opens no socket.

package device_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A subject's forwarding Delegation, by its seed: a synthetic delegation_id and the forwarding key it names.
func forwardTestDelegationId(seed byte) []byte {
	return bytes.Repeat([]byte{0xFD, seed}, sha256.Size/2)
}

func forwardTestKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xFE, seed}, ed25519.SeedSize/2))
}

// Lists each of the state's identities' forwarding Delegation live, as the compiler fills them.
func forwardTestIdentities(identities []*bridge.BridgeIdentity, fixture *sidecartest.BridgeRulesFixture) {
	for i, subject := range fixture.Subjects {
		identities[i].ForwardDelegationId = forwardTestDelegationId(subject.Sidecar)
		identities[i].ForwardPublicKey = forwardTestKey(subject.Sidecar).Public().(ed25519.PublicKey)
	}
}

// A host enforcing egress_test's rules whose state lists every subject's forwarding Delegation.
func newForwardEgressTest(t *testing.T) *egressTest {
	t.Helper()
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	forwardTestIdentities(test.input.BridgeState.Identities, egressTestFixture())
	test.republish()
	return test
}

// delegation as a forwarding signer writes it: by key, under delegationId, with key_id the SHA-256 of keyIdOf.
func forwardTestSign(
	t *testing.T,
	delegation *bridge.WindowDelegation,
	key ed25519.PrivateKey,
	delegationId []byte,
	keyIdOf ed25519.PublicKey,
	signedType bridge.SignedType,
) []byte {
	t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(delegation)
	if err != nil {
		t.Fatal(err)
	}
	keyId := sha256.Sum256(keyIdOf)
	signed, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.Signed{
		Body:      body,
		SignerId:  delegationId,
		KeyId:     keyId[:],
		Signature: ed25519.Sign(key, bridge.SignedBytes(bridge.SignedPurposeWindowDelegation, signedType, body)),
		Type:      uint32(signedType),
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// The untagged subject's delegation signed by its own live forwarding key.
func forwardTestSigned(t *testing.T, delegation *bridge.WindowDelegation) []byte {
	t.Helper()
	key := forwardTestKey(egressTestUntagged)
	return forwardTestSign(t, delegation, key, forwardTestDelegationId(egressTestUntagged), key.Public().(ed25519.PublicKey),
		bridge.SignedType_SIGNED_WINDOW_DELEGATION)
}

// The tag of the subject's flows under a rule where its forwarding key admitted them.
func forwardTestTag(subjectSeed byte, ruleId []byte) uint64 {
	return device.BridgeForwardRuleTag(connect.Id(sidecartest.BridgeFixtureSidecarId(subjectSeed)),
		[sha256.Size]byte(forwardTestDelegationId(subjectSeed)), ruleId)
}

// The contract's principal as the host's hook answers it.
func forwardTestPrincipal(policy *device.BridgeEgressPolicy, contract principalTestContract) *connect.BridgePrincipal {
	return policy.VerifyPrincipalForTest(contract.sourceId, contract.sessionKey, contract.sealedNetwork, contract.sealedSubject,
		contract.delegation)
}

// The positive twin: the subject's forwarding key admits its window client, the principal is the subject's, and its
// flows open sockets under the forwarding key's own tags.
func TestVerifyPrincipalAdmitsAForwardingKeyDelegation(t *testing.T) {
	test := newForwardEgressTest(t)
	contract := principalTestContractOf(1, forwardTestSigned(t, principalTestDelegation()))
	principal := forwardTestPrincipal(test.policy, contract)
	if principal == nil {
		t.Fatal("no principal")
	}
	if principal.Subject != connect.Id(sidecartest.BridgeFixtureSidecarId(egressTestUntagged)) ||
		principal.Network != connect.Id(egressTestNetworkId) || principal.ShareId != (connect.Id{}) {
		t.Fatalf("%+v", principal)
	}
	nat := newPrincipalTestNat(test.policy)
	for _, flow := range principalTestFlows {
		if !nat.open(contract, flow.ipProtocol, flow.to) {
			t.Errorf("%v to %s opened nothing", flow.ipProtocol, flow.to)
		}
	}
	flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432")
	flow.Principal = principal
	if decision := test.policy.ResolveEgress(flow); decision.Verdict != connect.EgressVerdictMap ||
		decision.RuleTag != forwardTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(1)) {
		t.Fatalf("a forwarding-key flow resolved %+v", decision)
	}
	// the same subject under its identity key keeps the pair's own tag
	identityFlow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432")
	if decision := test.policy.ResolveEgress(identityFlow); decision.RuleTag != egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(1)) {
		t.Fatalf("an identity-key flow took tag %d", decision.RuleTag)
	}
}

// Each mismatch of the forwarding path alone refuses the contract, and every one of its flows opens no socket, beside
// the twin that passes.
func TestVerifyPrincipalRefusesEachForwardingMismatchAlone(t *testing.T) {
	subjectKey := forwardTestKey(egressTestUntagged)
	subjectPublicKey := subjectKey.Public().(ed25519.PublicKey)
	subjectDelegationId := forwardTestDelegationId(egressTestUntagged)
	otherKey := forwardTestKey(egressTestTagged)
	otherDelegationId := forwardTestDelegationId(egressTestTagged)
	newerDelegationId := bytes.Repeat([]byte{0xFC}, sha256.Size)
	shortKeyId := &bridge.Signed{}
	if err := proto.Unmarshal(forwardTestSigned(t, principalTestDelegation()), shortKeyId); err != nil {
		t.Fatal(err)
	}
	shortKeyId.KeyId = shortKeyId.KeyId[:16]
	shortKeyIdBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(shortKeyId)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(contract *principalTestContract, test *egressTest)
	}{
		{name: "another sidecar's forwarding key", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = forwardTestSign(t, principalTestDelegation(), otherKey, otherDelegationId,
				otherKey.Public().(ed25519.PublicKey), bridge.SignedType_SIGNED_WINDOW_DELEGATION)
		}},
		{name: "another sidecar's forwarding key under the subject's Delegation", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = forwardTestSign(t, principalTestDelegation(), otherKey, subjectDelegationId, subjectPublicKey,
				bridge.SignedType_SIGNED_WINDOW_DELEGATION)
		}},
		{name: "a superseded one: the state lists a newer Delegation", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.BridgeState.Identities[0].ForwardDelegationId = newerDelegationId
			test.input.BridgeState.Identities[0].ForwardPublicKey = forwardTestKey(0x55).Public().(ed25519.PublicKey)
			test.republish()
		}},
		{name: "a superseded one: the overlay holds the supersession", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.Overlay = []device.PostureOverlayEntry{{
				Kind: device.PostureOverlayForwardSupersede, N: 9, Id: sidecartest.BridgeFixtureSidecarId(egressTestUntagged),
				DelegationId: newerDelegationId,
			}}
			test.republish()
		}},
		{name: "a revoked one: the overlay holds its DelegationRevoke", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.Overlay = []device.PostureOverlayEntry{
				{Kind: device.PostureOverlayDelegationRevoke, N: 9, Id: subjectDelegationId},
			}
			test.republish()
		}},
		{name: "a revoked one: the state lists none", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.BridgeState.Identities[0].ForwardDelegationId = nil
			test.input.BridgeState.Identities[0].ForwardPublicKey = nil
			test.republish()
		}},
		{name: "a ShareCert type", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = forwardTestSign(t, principalTestDelegation(), subjectKey, subjectDelegationId, subjectPublicKey,
				bridge.SignedType_SIGNED_SHARE_CERT)
		}},
		{name: "a 32-byte signer with a 16-byte key id", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = shortKeyIdBytes
		}},
		{name: "a key id of another key", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.delegation = forwardTestSign(t, principalTestDelegation(), subjectKey, subjectDelegationId,
				otherKey.Public().(ed25519.PublicKey), bridge.SignedType_SIGNED_WINDOW_DELEGATION)
		}},
		{name: "a forwarding key of the wrong length in the state", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.BridgeState.Identities[0].ForwardPublicKey = subjectPublicKey[:16]
			test.republish()
		}},
		{name: "a Delegation two identities list", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.BridgeState.Identities[1].ForwardDelegationId = subjectDelegationId
			test.republish()
		}},
		{name: "the subject revoked", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.BridgeState.Identities[0].Revoked = true
			test.republish()
		}},
		{name: "the subject suspended between states", mutate: func(contract *principalTestContract, test *egressTest) {
			test.input.Overlay = []device.PostureOverlayEntry{
				{Kind: device.PostureOverlaySuspend, N: 9, Id: sidecartest.BridgeFixtureSidecarId(egressTestUntagged)},
			}
			test.republish()
		}},
		{name: "another session key", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.sessionKey = principalTestOtherKey.Public().(ed25519.PublicKey)
		}},
		{name: "a sealed subject the delegation's subject does not bind", mutate: func(contract *principalTestContract, test *egressTest) {
			contract.sealedSubject = sidecartest.BridgeFixtureClientId(egressTestTagged)
		}},
	}
	for i, testCase := range cases {
		test := newForwardEgressTest(t)
		contract := principalTestContractOf(byte(i+1), forwardTestSigned(t, principalTestDelegation()))
		testCase.mutate(&contract, test)
		if principal := forwardTestPrincipal(test.policy, contract); principal != nil {
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
		twin := newForwardEgressTest(t)
		if principal := forwardTestPrincipal(twin.policy, principalTestContractOf(byte(i+1), forwardTestSigned(t, principalTestDelegation()))); principal == nil {
			t.Errorf("%s's twin: no principal", testCase.name)
		}
	}
}

// The per-flow recheck: a principal a forwarding key admitted is denied while the overlay revokes that Delegation or
// supersedes its sidecar by another, and once the state lists another Delegation or none; a principal the same
// subject's identity key admitted passes through all four, and a supersession naming the admitting Delegation itself as
// the newer one denies nothing.
func TestForwardingPrincipalIsRecheckedPerFlow(t *testing.T) {
	subjectId := sidecartest.BridgeFixtureSidecarId(egressTestUntagged)
	subjectDelegationId := forwardTestDelegationId(egressTestUntagged)
	newerDelegationId := bytes.Repeat([]byte{0xFC}, sha256.Size)
	cases := []struct {
		name   string
		mutate func(test *egressTest)
		denied bool
	}{
		{name: "a DelegationRevoke of its id", mutate: func(test *egressTest) {
			test.input.Overlay = []device.PostureOverlayEntry{{Kind: device.PostureOverlayDelegationRevoke, N: 9, Id: subjectDelegationId}}
		}, denied: true},
		{name: "a supersession of its sidecar", mutate: func(test *egressTest) {
			test.input.Overlay = []device.PostureOverlayEntry{
				{Kind: device.PostureOverlayForwardSupersede, N: 9, Id: subjectId, DelegationId: newerDelegationId},
			}
		}, denied: true},
		{name: "the state lists a newer Delegation", mutate: func(test *egressTest) {
			test.input.BridgeState.Identities[0].ForwardDelegationId = newerDelegationId
		}, denied: true},
		{name: "the state lists none", mutate: func(test *egressTest) {
			test.input.BridgeState.Identities[0].ForwardDelegationId = nil
			test.input.BridgeState.Identities[0].ForwardPublicKey = nil
		}, denied: true},
		{name: "a supersession by the admitting Delegation itself", mutate: func(test *egressTest) {
			test.input.Overlay = []device.PostureOverlayEntry{
				{Kind: device.PostureOverlayForwardSupersede, N: 9, Id: subjectId, DelegationId: subjectDelegationId},
			}
		}},
		{name: "a DelegationRevoke of another sidecar's", mutate: func(test *egressTest) {
			test.input.Overlay = []device.PostureOverlayEntry{
				{Kind: device.PostureOverlayDelegationRevoke, N: 9, Id: forwardTestDelegationId(egressTestTagged)},
			}
		}},
		{name: "a supersession of another sidecar", mutate: func(test *egressTest) {
			test.input.Overlay = []device.PostureOverlayEntry{{
				Kind: device.PostureOverlayForwardSupersede, N: 9, Id: sidecartest.BridgeFixtureSidecarId(egressTestTagged),
				DelegationId: newerDelegationId,
			}}
		}},
	}
	for _, testCase := range cases {
		test := newForwardEgressTest(t)
		forwardPrincipal := forwardTestPrincipal(test.policy, principalTestContractOf(1, forwardTestSigned(t, principalTestDelegation())))
		identityPrincipal := forwardTestPrincipal(test.policy, principalTestContractOf(2, principalTestSigned(t, principalTestDelegation())))
		if forwardPrincipal == nil || identityPrincipal == nil {
			t.Fatalf("%s: principals %v and %v", testCase.name, forwardPrincipal, identityPrincipal)
		}
		verdict := func(principal *connect.BridgePrincipal) connect.EgressVerdict {
			flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432")
			flow.Principal = principal
			return test.policy.ResolveEgress(flow).Verdict
		}
		if verdict(forwardPrincipal) != connect.EgressVerdictMap || verdict(identityPrincipal) != connect.EgressVerdictMap {
			t.Fatalf("%s: a flow denied before the change", testCase.name)
		}
		testCase.mutate(test)
		test.republish()
		want := connect.EgressVerdictMap
		if testCase.denied {
			want = connect.EgressVerdictDeny
		}
		if got := verdict(forwardPrincipal); got != want {
			t.Errorf("%s: the forwarding-key principal's flow resolved %v, want %v", testCase.name, got, want)
		}
		if got := verdict(identityPrincipal); got != connect.EgressVerdictMap {
			t.Errorf("%s: the identity-key principal's flow resolved %v", testCase.name, got)
		}
	}
}

// A bridge enforcing the disposition fixture whose state lists every subject's forwarding Delegation.
func newForwardStateTest(t *testing.T) *stateTest {
	t.Helper()
	test := newStateTest(t, dispositionTestFixture(), true)
	state, stateLog := test.log.State(dispositionTestFixture().Bytes(), true)
	state.Identities = stateTestIdentities(dispositionTestFixture())
	forwardTestIdentities(state.Identities, dispositionTestFixture())
	state.DaemonListeners = egressTestListeners
	if err := test.bridge.SetState(state, stateLog); err != nil {
		t.Fatal(err)
	}
	test.closer.take()
	test.drainChanges()
	return test
}

// The forwarding-key tags of a subject in the disposition fixture: dispositionTestTags' pairs under its forwarding
// Delegation.
func forwardTestDispositionTags(subjectSeed byte) []uint64 {
	fixture := dispositionTestFixture()
	octets := [4]byte{100, 80, 1, 2}
	tags := []uint64{forwardTestTag(subjectSeed, append([]byte{device.BridgeRuleHosted}, octets[:]...))}
	for _, fixtureMap := range fixture.Maps {
		tags = append(tags, forwardTestTag(subjectSeed, sidecartest.BridgeFixtureMapId(fixtureMap.Map)))
	}
	if subjectSeed == egressTestUntagged {
		tags = append(tags,
			forwardTestTag(subjectSeed, sidecartest.BridgeFixtureRouteId(1)),
			forwardTestTag(subjectSeed, sidecartest.BridgeFixtureRouteId(2)),
			forwardTestTag(subjectSeed, []byte{device.BridgeRuleExit}))
	}
	slices.Sort(tags)
	return tags
}

// A DelegationRevoke the sidecar role applies between states closes exactly the flows that Delegation's key admitted,
// after the policy swap (D-BRIDGE-21): the subject's identity-key flows, and the sibling subject's flows under either
// key, survive. A SidecarRevoke of the subject then ends both of its keys' flows.
func TestDelegationRevokeClosesExactlyTheFlowsItsKeyAdmitted(t *testing.T) {
	test := newForwardStateTest(t)
	networkId := connect.Id(test.log.NetworkId())
	hostId := test.bridge.Decision().SidecarId
	delegation := principalTestDelegation()
	delegation.NetworkId = networkId[:]
	delegation.TargetSidecarId = hostId
	delegation.NotAfterMs = egressTestTimeMs + 24*egressTestHourMs
	contract := principalTestContractOf(1, forwardTestSigned(t, delegation))
	contract.sealedNetwork = networkId
	forwardPrincipal := test.bridge.VerifyPrincipalForTest(contract.sourceId, contract.sessionKey, contract.sealedNetwork,
		contract.sealedSubject, contract.delegation)
	if forwardPrincipal == nil {
		t.Fatal("the forwarding key admitted nothing")
	}
	forwardFlow := test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432")
	forwardFlow.Principal = forwardPrincipal
	identityFlow := test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432")
	sibling := test.flow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.2:443")
	if test.verdict(forwardFlow) != connect.EgressVerdictMap || test.verdict(identityFlow) != connect.EgressVerdictMap {
		t.Fatal("a flow denied before the revocation")
	}

	n := test.log.Tip() + 1
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_DELEGATION_REVOKE, forwardTestDelegationId(egressTestUntagged), n); err != nil {
		t.Fatal(err)
	}
	tags, generations := test.closer.take()
	if want := forwardTestDispositionTags(egressTestUntagged); !slices.Equal(tags, want) {
		t.Fatalf("closed %v, want the forwarding key's %v", tags, want)
	}
	// the swap came first: every close read the generation that denies the key
	published := test.bridge.EgressHook().PolicyGeneration()
	for _, generation := range generations {
		if generation != published {
			t.Fatalf("a close at generation %d, before the swap to %d", generation, published)
		}
	}
	if test.verdict(forwardFlow) != connect.EgressVerdictDeny {
		t.Fatal("the revoked forwarding key's principal still admits a flow")
	}
	if test.verdict(identityFlow) != connect.EgressVerdictMap {
		t.Fatal("the identity key's principal lost its flow to a forwarding Delegation's revocation")
	}
	if test.verdict(sibling) != connect.EgressVerdictMap {
		t.Fatal("the sibling's flow")
	}
	// the revoked key admits no new contract either
	if principal := test.bridge.VerifyPrincipalForTest(contract.sourceId, contract.sessionKey, contract.sealedNetwork,
		contract.sealedSubject, contract.delegation); principal != nil {
		t.Fatal("a revoked forwarding key admitted a new contract")
	}

	// the sibling's Delegation revoked: its forwarding tags alone
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_DELEGATION_REVOKE, forwardTestDelegationId(egressTestTagged), n+1); err != nil {
		t.Fatal(err)
	}
	if tags, _ := test.closer.take(); !slices.Equal(tags, forwardTestDispositionTags(egressTestTagged)) {
		t.Fatalf("the sibling's revocation closed %v", tags)
	}
	// and the subject itself: what is left of it, its identity key's tags
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_SIDECAR_REVOKE, sidecartest.BridgeFixtureSidecarId(egressTestUntagged), n+2); err != nil {
		t.Fatal(err)
	}
	if tags, _ := test.closer.take(); !slices.Equal(tags, dispositionTestTags(egressTestUntagged)) {
		t.Fatalf("the subject's revocation closed %v", tags)
	}
}

// A subject's revocation ends the flows of both of its keys at once.
func TestSubjectRevocationClosesBothKeysFlows(t *testing.T) {
	test := newForwardStateTest(t)
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_SIDECAR_REVOKE, sidecartest.BridgeFixtureSidecarId(egressTestUntagged), test.log.Tip()+1); err != nil {
		t.Fatal(err)
	}
	want := slices.Concat(dispositionTestTags(egressTestUntagged), forwardTestDispositionTags(egressTestUntagged))
	slices.Sort(want)
	if tags, _ := test.closer.take(); !slices.Equal(tags, want) {
		t.Fatalf("closed %v, want %v", tags, want)
	}
}

// FS-38's forwarding rows at unit level: an operator-minted window client, its contract correctly sealed to claim the
// subject, opens zero upstream sockets over TCP, UDP and ICMP whatever forged forwarding delegation it carries: signed
// by the operator's key under the subject's live Delegation, under a Delegation the operator made up, with the
// operator's key as key_id, or by the subject's superseded key. The subject's own forwarding key is the positive twin.
func TestFs38ForgedForwardingDelegationOpensNoSockets(t *testing.T) {
	test := newForwardEgressTest(t)
	nat := newPrincipalTestNat(test.policy)
	operatorKey := principalTestOtherKey
	operatorPublicKey := operatorKey.Public().(ed25519.PublicKey)
	subjectPublicKey := forwardTestKey(egressTestUntagged).Public().(ed25519.PublicKey)
	subjectDelegationId := forwardTestDelegationId(egressTestUntagged)
	madeUpDelegationId := bytes.Repeat([]byte{0xAB}, sha256.Size)
	supersededKey := forwardTestKey(0x66)
	minted := []principalTestContract{
		principalTestContractOf(1, forwardTestSign(t, principalTestDelegation(), operatorKey, subjectDelegationId, subjectPublicKey,
			bridge.SignedType_SIGNED_WINDOW_DELEGATION)),
		principalTestContractOf(2, forwardTestSign(t, principalTestDelegation(), operatorKey, subjectDelegationId, operatorPublicKey,
			bridge.SignedType_SIGNED_WINDOW_DELEGATION)),
		principalTestContractOf(3, forwardTestSign(t, principalTestDelegation(), operatorKey, madeUpDelegationId, operatorPublicKey,
			bridge.SignedType_SIGNED_WINDOW_DELEGATION)),
		principalTestContractOf(4, forwardTestSign(t, principalTestDelegation(), supersededKey, madeUpDelegationId,
			supersededKey.Public().(ed25519.PublicKey), bridge.SignedType_SIGNED_WINDOW_DELEGATION)),
		// the operator's key under the subject's sidecar_id, as an identity key would sign
		principalTestContractOf(5, principalTestSign(t, principalTestDelegation(), operatorKey, bridge.SignedType_SIGNED_WINDOW_DELEGATION)),
	}
	for i, contract := range minted {
		for _, flow := range principalTestFlows {
			if nat.open(contract, flow.ipProtocol, flow.to) {
				t.Errorf("minted contract %d: %v to %s opened a socket", i+1, flow.ipProtocol, flow.to)
			}
		}
	}
	if nat.socketCount != 0 {
		t.Fatalf("%d upstream sockets on operator-minted contracts", nat.socketCount)
	}
	twin := principalTestContractOf(9, forwardTestSigned(t, principalTestDelegation()))
	for _, flow := range principalTestFlows {
		if !nat.open(twin, flow.ipProtocol, flow.to) {
			t.Errorf("the twin: %v to %s opened nothing", flow.ipProtocol, flow.to)
		}
	}
	if nat.socketCount != len(principalTestFlows) {
		t.Fatalf("the twin opened %d sockets, want %d", nat.socketCount, len(principalTestFlows))
	}
}

// A forwarding-key flow's resolve allocates nothing, as an identity-key flow's does not.
func TestForwardingPrincipalResolveAllocatesNothing(t *testing.T) {
	test := newForwardEgressTest(t)
	principal := forwardTestPrincipal(test.policy, principalTestContractOf(1, forwardTestSigned(t, principalTestDelegation())))
	if principal == nil {
		t.Fatal("no principal")
	}
	flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432")
	flow.Principal = principal
	if allocs := testing.AllocsPerRun(200, func() {
		test.policy.ResolveEgress(flow)
	}); allocs != 0 {
		t.Fatalf("%v allocations a resolve", allocs)
	}
}
