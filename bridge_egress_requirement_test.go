// QD-1053's requirement of default egress, which an admin, owner or sponsor seals in a BridgeEgress's exits body: the
// statement a filing builds carries it under exits alone and shows nothing of it in the clear; the ledger reads it, a
// fold keeps it in the head's bridge/ledger/egress row, and a reader starting at that base holds it again; a row that
// requires it under none is refused; and the compile hands it to the device role in BridgeRuleEgress before and after
// the fold, while a later spec without it lifts it.

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Under exits the body seals the requirement, and the clear statement is the same with it or without it; auto and none,
// which carry no body, refuse it.
func TestAnEgressStatementSealsTheRequirementUnderExitsAlone(t *testing.T) {
	subject, exit := testConfigId("egress subject"), testConfigId("egress exit")
	exits := bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
	required, body, err := bridgeEgressStatement(&BridgeEgressRequest{Subject: subject, Mode: exits, ExitSidecarIds: []Id{exit},
		RequireDefaultEgress: true}, nil)
	if err != nil || body == nil || !body.GetRequireDefaultEgress() || len(body.GetExitSidecarIds()) != 1 {
		t.Fatalf("required: %v %v", body, err)
	}
	plain, plainBody, err := bridgeEgressStatement(&BridgeEgressRequest{Subject: subject, Mode: exits, ExitSidecarIds: []Id{exit}}, nil)
	if err != nil || plainBody.GetRequireDefaultEgress() {
		t.Fatalf("plain: %v %v", plainBody, err)
	}
	requiredBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(required)
	plainBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(plain)
	if !bytes.Equal(requiredBytes, plainBytes) {
		t.Fatal("the clear statement shows the requirement")
	}
	for _, mode := range []bridge.BridgeEgressMode{bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE} {
		if _, _, err := bridgeEgressStatement(&BridgeEgressRequest{Subject: subject, Mode: mode, RequireDefaultEgress: true}, nil); !errors.Is(err, ErrBridgeFileRefused) {
			t.Errorf("%v: %v", mode, err)
		}
	}
}

// Whether the ledger's spec for subject requires default egress.
func testBridgeEgressRequired(ledger *BridgeLedger, subject Id) bool {
	for _, egress := range ledger.Egress() {
		if egress.Subject == subject {
			return egress.RequireDefaultEgress
		}
	}
	return false
}

// The lock survives a fold: the ledger, the head's row, a reader at the base, and the compile before and after it all
// hold the requirement for the subject whose spec sets it, and none for the one whose spec does not; a later spec
// without it lifts it.
func TestTheDefaultEgressRequirementSurvivesAFold(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	exits := bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
	egressType := bridge.SignedType_SIGNED_BRIDGE_EGRESS
	net.mustPost(net.owner, egressType, net.bridgeEgress(net.host.sidecarId, exits, &bridge.BridgeEgressBody{
		ExitSidecarIds: [][]byte{net.peer.sidecarId.Bytes()}, RequireDefaultEgress: true,
	}))
	net.mustPost(net.owner, egressType, net.bridgeEgress(net.peer.sidecarId, exits, &bridge.BridgeEgressBody{
		ExitSidecarIds: [][]byte{net.host.sidecarId.Bytes()},
	}))
	ledger := net.ledgerOf(net.log)
	if !testBridgeEgressRequired(ledger, net.host.sidecarId) || testBridgeEgressRequired(ledger, net.peer.sidecarId) {
		t.Fatalf("the ledger: %+v", ledger.Egress())
	}
	_, rules := testBridgeCompile(t, net.view(), net.local())
	if egress := rules.GetEgress(); egress.GetMode() != exits || !egress.GetRequireDefaultEgress() || len(egress.GetExits()) != 1 {
		t.Fatalf("compiled before the fold: %v", egress)
	}

	net.foldLedger(net.n, nil)
	head := net.heads[net.log.State().Base().GetConfigVersion()]
	specs := &protocol.BridgeLedgerEgressSpecs{}
	if err := proto.Unmarshal(head.File(ConfigHeadBridgeLedgerEgressPath), specs); err != nil || len(specs.GetRows()) != 2 {
		t.Fatalf("the head's egress rows: %v %v", specs, err)
	}
	for _, row := range specs.GetRows() {
		if Id(row.GetSubject()) == net.host.sidecarId != row.GetRequireDefaultEgress() {
			t.Errorf("the head's row %v", row)
		}
	}
	ledger = net.ledgerOf(net.log)
	if len(ledger.Entries()) != 0 || !testBridgeEgressRequired(ledger, net.host.sidecarId) ||
		testBridgeEgressRequired(ledger, net.peer.sidecarId) {
		t.Fatalf("after the fold: %d unfolded, %+v", len(ledger.Entries()), ledger.Egress())
	}
	testBridgeLedgersEqual(t, net.testBridgeLedgerNet, net.presentReader(), net.restoredReader())
	_, rules = testBridgeCompile(t, net.view(), net.local())
	if egress := rules.GetEgress(); egress.GetMode() != exits || !egress.GetRequireDefaultEgress() {
		t.Fatalf("compiled after the fold: %v", egress)
	}

	// the same exits with no requirement lift it
	net.mustPost(net.owner, egressType, net.bridgeEgress(net.host.sidecarId, exits, &bridge.BridgeEgressBody{
		ExitSidecarIds: [][]byte{net.peer.sidecarId.Bytes()},
	}))
	_, rules = testBridgeCompile(t, net.view(), net.local())
	if egress := rules.GetEgress(); egress.GetMode() != exits || egress.GetRequireDefaultEgress() {
		t.Fatalf("lifted: %v", egress)
	}
}

// A head's egress row that requires default egress under none is no row a fold writes, and the ledger refuses it.
func TestALedgerRowRequiresDefaultEgressUnderExitsAlone(t *testing.T) {
	ledger := newBridgeLedger(&BridgeLedgerReader{}, 0, 0, false, 0)
	subject := testConfigId("egress subject")
	none := &protocol.BridgeLedgerEgressRow{Subject: subject.Bytes(), Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE, At: 3,
		RequireDefaultEgress: true}
	if err := ledger.loadEgressRow(none); err == nil {
		t.Fatal("a requirement under none loaded")
	}
	exits := &protocol.BridgeLedgerEgressRow{Subject: subject.Bytes(), Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, At: 3,
		ExitSidecarIds: [][]byte{testConfigId("egress exit").Bytes()}, RequireDefaultEgress: true}
	if err := ledger.loadEgressRow(exits); err != nil || !testBridgeEgressRequired(ledger, subject) {
		t.Fatalf("under exits: %v", err)
	}
}
