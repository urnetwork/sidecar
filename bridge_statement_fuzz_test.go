//go:build !js

// §22.6's typed-statement target for §17.8's statements as a native fuzz target, whose seeds in
// testdata/fuzz/FuzzBridgeStatement run as ordinary tests under go test. Not on js: testing.F reads its corpus
// directory before it runs a seed, and js has none.
//
// The input picks one of the six log statements, bytes merged over a well-formed statement of that type, bytes merged
// over a well-formed sealed body of it, and a position. Both depths are total. At id level, whatever the bytes, the
// log takes the statement or refuses it with a refusal of its own classes, a statement it takes joins the fold, and
// every reader, the keyless gate included, reaches the same verdict. At body level a reader with the key makes each
// entry active, held, pending or void, a void one saying why, and a reader with no key leaves every sealed entry
// pending; raw bytes in place of a seal never open. Tampering is refused: a statement the log takes stops verifying
// once the position's byte of its signed body changes.

package sidecar

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The most bytes one input's statement or body takes.
const bridgeFuzzMaxByteCount = 16 * 1024

// The log's bridge statements, in SignedType order.
var bridgeFuzzStatementTypes = []bridge.SignedType{
	bridge.SignedType_SIGNED_BRIDGE_ADDRESS,
	bridge.SignedType_SIGNED_BRIDGE_ROUTE,
	bridge.SignedType_SIGNED_BRIDGE_MAP,
	bridge.SignedType_SIGNED_BRIDGE_EGRESS,
	bridge.SignedType_SIGNED_BRIDGE_ALIAS,
	bridge.SignedType_SIGNED_BRIDGE_WITHDRAW,
}

// A well-formed sealed body of a type about the fuzz cast, which the fuzz bytes are merged over; nil for a withdrawal,
// which seals none.
func bridgeFuzzBody(signedType bridge.SignedType) proto.Message {
	switch signedType {
	case bridge.SignedType_SIGNED_BRIDGE_ADDRESS:
		return &bridge.BridgeAddressBody{Ipv4: testBridgeIpv4(100, 80, 3, 7)}
	case bridge.SignedType_SIGNED_BRIDGE_ROUTE:
		return testBridgeSubnet(testBridgePrefix(192, 168, 7, 0, 24), "site")
	case bridge.SignedType_SIGNED_BRIDGE_MAP:
		return testBridgeMapBody(testBridgeIpv4(100, 80, 3, 7), 8443, 443)
	case bridge.SignedType_SIGNED_BRIDGE_EGRESS:
		return &bridge.BridgeEgressBody{ExitSidecarIds: [][]byte{testConfigId("exit").Bytes()}}
	case bridge.SignedType_SIGNED_BRIDGE_ALIAS:
		return &bridge.BridgeAliasBody{ShareId: testConfigId("share").Bytes(), AliasPrefix: testBridgePrefix(100, 80, 128, 0, 24), Host: testConfigId("far host").Bytes()}
	}
	return nil
}

// A well-formed statement of a type by signer at the net's tip, its body sealed to generation 1.
func bridgeFuzzStatement(net *testConfigNet, signedType bridge.SignedType, signer testConfigDevice, body proto.Message) proto.Message {
	header := net.header()
	var sealedBody []byte
	if body != nil {
		sealedBody = net.bridgeSeal(signedType, header, body, 1)
	}
	ruleId := testBridgeRuleId("fuzz")
	switch signedType {
	case bridge.SignedType_SIGNED_BRIDGE_ADDRESS:
		return &bridge.BridgeAddress{Header: header, SidecarId: signer.sidecarId.Bytes(), SealedBody: sealedBody}
	case bridge.SignedType_SIGNED_BRIDGE_ROUTE:
		return &bridge.BridgeRoute{Header: header, RouteId: ruleId, Advertiser: signer.sidecarId.Bytes(), SealedBody: sealedBody}
	case bridge.SignedType_SIGNED_BRIDGE_MAP:
		return &bridge.BridgeMap{Header: header, MapId: ruleId, Host: signer.sidecarId.Bytes(), SealedBody: sealedBody}
	case bridge.SignedType_SIGNED_BRIDGE_EGRESS:
		return &bridge.BridgeEgress{Header: header, Subject: signer.sidecarId.Bytes(), SealedBody: sealedBody}
	case bridge.SignedType_SIGNED_BRIDGE_ALIAS:
		return &bridge.BridgeAlias{Header: header, SealedBody: sealedBody}
	}
	return &bridge.BridgeWithdraw{Header: header, RuleId: ruleId, Mode: bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET}
}

// Every entry of a ledger is one of the four dispositions, and a void one says why.
func bridgeFuzzCheckLedger(t *testing.T, ledger *BridgeLedger, wantCount int) {
	t.Helper()
	if len(ledger.Entries()) != wantCount {
		t.Fatalf("the ledger holds %d entries of the log's %d", len(ledger.Entries()), wantCount)
	}
	for _, entry := range ledger.Entries() {
		switch entry.Disposition {
		case BridgeDispositionActive, BridgeDispositionHeld, BridgeDispositionPending:
			if entry.Reason != nil {
				t.Fatalf("the statement at %d: disposition %d with reason %v", entry.Statement.N, entry.Disposition, entry.Reason)
			}
		case BridgeDispositionVoid:
			if !errors.Is(entry.Reason, ErrBridgeVoid) {
				t.Fatalf("the statement at %d: void for %v", entry.Statement.N, entry.Reason)
			}
		default:
			t.Fatalf("the statement at %d: disposition %d", entry.Statement.N, entry.Disposition)
		}
	}
	// what the ledger answers is read without a fault whatever it holds
	ledger.Addresses()
	ledger.Tombstones()
	ledger.Egress()
	ledger.Aliases()
	ledger.UpperRanges()
	ledger.Pending()
	ledger.Alarms()
	for _, signedType := range []bridge.SignedType{bridge.SignedType_SIGNED_BRIDGE_ROUTE, bridge.SignedType_SIGNED_BRIDGE_MAP} {
		for _, rule := range ledger.Rules(signedType) {
			if rule.Active() && rule.Route == nil && rule.Map == nil {
				t.Fatalf("a rule in force with no body: %x", rule.RuleId)
			}
		}
	}
}

func FuzzBridgeStatement(f *testing.F) {
	for i := range bridgeFuzzStatementTypes {
		f.Add(uint8(i), []byte{}, []byte{}, uint16(i))
	}
	f.Fuzz(func(t *testing.T, typeIndex uint8, statementBytes []byte, bodyBytes []byte, flip uint16) {
		if bridgeFuzzMaxByteCount < len(statementBytes) || bridgeFuzzMaxByteCount < len(bodyBytes) {
			return
		}
		signedType := bridgeFuzzStatementTypes[int(typeIndex)%len(bridgeFuzzStatementTypes)]
		net := newTestConfigNet(t)
		_, laptop, desktop := testBridgeCast(net)

		// a held rule, an address and a withdrawn id for the fuzzed statement to meet
		net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(desktop, testBridgeIpv4(100, 80, 3, 9)))
		net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, net.bridgeRoute(desktop, testBridgeRuleId("held"), testBridgeSubnet(testBridgePrefix(192, 168, 7, 0, 24), "site")))
		net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(testBridgeRuleId("withdrawn"), bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))

		body := bridgeFuzzBody(signedType)
		if body != nil {
			if err := (proto.UnmarshalOptions{Merge: true}).Unmarshal(bodyBytes, body); err != nil {
				body = bridgeFuzzBody(signedType)
			}
		}
		statement := bridgeFuzzStatement(net, signedType, laptop, body)
		if err := (proto.UnmarshalOptions{Merge: true}).Unmarshal(statementBytes, statement); err != nil {
			statement = bridgeFuzzStatement(net, signedType, laptop, body)
		}
		before := net.log.State().Bridge().Len()
		verdict := net.post(laptop, signedType, statement)
		after := net.log.State().Bridge().Len()
		switch {
		case verdict.Accepted() && after != before+1:
			t.Fatalf("%s took effect and the fold holds %d statements after %d", signedType, after, before)
		case !verdict.Accepted() && after != before:
			t.Fatalf("%s was refused and the fold moved from %d to %d", signedType, before, after)
		case !verdict.Accepted() && !errors.Is(verdict.Refusal, ErrConfigRefused):
			t.Fatalf("%s: a refusal outside the log's classes: %v", signedType, verdict.Refusal)
		case verdict.Accepted() && signedType == bridge.SignedType_SIGNED_BRIDGE_EGRESS:
			t.Fatal("a BridgeEgress took effect while it shows no mode at id level")
		}
		net.everyReaderAgrees()

		state := net.log.State()
		keyed := state.Bridge().Open(&BridgeLedgerReader{State: state, RepoKeyAt: testConfigSealKeyAt(testConfigSealKey(1)), Approvals: testBridgeApprovalCheck})
		bridgeFuzzCheckLedger(t, keyed, after)
		if len(keyed.Pending()) != 0 && verdict.Accepted() && len(statementBytes) == 0 {
			t.Fatal("a reader holding the generation left an untouched statement pending")
		}
		keyless := state.Bridge().Open(nil)
		bridgeFuzzCheckLedger(t, keyless, after)
		for _, entry := range keyless.Entries() {
			if len(entry.Statement.SealedBody) != 0 && entry.Disposition != BridgeDispositionPending && entry.Disposition != BridgeDispositionVoid {
				t.Fatalf("a keyless reader opened the statement at %d", entry.Statement.N)
			}
		}

		// raw bytes in place of a seal never open, under any key the reader holds
		if logStatements := state.Bridge().Statements(); 0 < len(logStatements) && 0 < len(bodyBytes) {
			raw := *logStatements[0]
			raw.SealedBody = bodyBytes
			for _, entry := range NewBridgeLog([]*BridgeLogStatement{&raw}).Open(&BridgeLedgerReader{RepoKeyAt: func(generation uint64) *EvsRepoKey { return testConfigSealKey(generation) }}).Entries() {
				if entry.Disposition == BridgeDispositionActive || entry.Disposition == BridgeDispositionHeld {
					t.Fatal("raw bytes opened as a sealed body")
				}
			}
		}

		// a statement the log takes stops verifying once its signed body changes
		valid := net.sign(laptop, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(testBridgeRuleId("tampered"), bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN))
		if verdict := net.log.Check(valid, net.timeMs+1000); !verdict.Accepted() {
			t.Fatalf("the untouched statement: %v", verdict.Refusal)
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(valid, signed); err != nil {
			t.Fatal(err)
		}
		signed.Body[int(flip)%len(signed.Body)] ^= byte(flip>>8) | 1
		if verdict := net.log.Check(testConfigMarshal(t, signed), net.timeMs+1000); verdict.Accepted() {
			t.Fatal("a tampered statement took effect")
		}
	})
}
