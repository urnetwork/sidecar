// BridgeRows (bridge_rows.go): the section's one encoding, each BridgeEgress entry's fold over it, and what a parser
// refuses. Ids and modes only.

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The section's bytes with one more entry applied.
func testBridgeRowsWith(t *testing.T, data []byte, subject Id, mode bridge.BridgeEgressMode) []byte {
	t.Helper()
	next, err := bridgeRowsWithEgress(data, subject, mode)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

// Entries fold in log order to one encoding whatever order the subjects came in: exits and none write a subject's
// row, auto removes it, and the newest entry for a subject is the one rows carry. CompileBridgeRows gives the same
// bytes back.
func TestBridgeRowsFoldEachEgressEntryToOneEncoding(t *testing.T) {
	exits, none, auto := bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO
	a, b, c := Id{0x01}, Id{0x02}, Id{0x03}
	forward := testBridgeRowsWith(t, nil, a, exits)
	forward = testBridgeRowsWith(t, forward, b, none)
	forward = testBridgeRowsWith(t, forward, c, exits)
	backward := testBridgeRowsWith(t, nil, c, exits)
	backward = testBridgeRowsWith(t, backward, b, exits)
	backward = testBridgeRowsWith(t, backward, a, exits)
	backward = testBridgeRowsWith(t, backward, b, none)
	if !bytes.Equal(forward, backward) {
		t.Fatalf("two orders of the same entries encode apart: %x and %x", forward, backward)
	}
	rows, err := ParseBridgeRows(forward)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.GetEgress()) != 3 || BridgeRowsEgressMode(rows, a) != exits || BridgeRowsEgressMode(rows, b) != none || BridgeRowsEgressMode(rows, c) != exits {
		t.Fatalf("the rows: %v", rows)
	}
	if BridgeRowsEgressMode(rows, Id{0x09}) != auto {
		t.Error("a subject with no row is in auto")
	}

	back := testBridgeRowsWith(t, forward, b, auto)
	rows, err = ParseBridgeRows(back)
	if err != nil || len(rows.GetEgress()) != 2 || BridgeRowsEgressMode(rows, b) != auto {
		t.Fatalf("auto removes the row: %v, %v", rows, err)
	}
	empty := testBridgeRowsWith(t, testBridgeRowsWith(t, back, a, auto), c, auto)
	if len(empty) != 0 {
		t.Errorf("the empty section is %x, want no bytes", empty)
	}

	net := newTestConfigNet(t)
	compiled, err := CompileBridgeRows(testConfigHead(t, net), forward)
	if err != nil || !bytes.Equal(compiled, forward) {
		t.Fatalf("compile: %x, %v", compiled, err)
	}
	if compiled, err := CompileBridgeRows(testConfigHead(t, net), nil); err != nil || len(compiled) != 0 {
		t.Errorf("compile of the empty section: %x, %v", compiled, err)
	}
	if _, err := CompileBridgeRows(nil, forward); !errors.Is(err, ErrBridgeRowsMalformed) {
		t.Errorf("compile with no head: %v", err)
	}
	if _, err := bridgeRowsWithEgress(forward, a, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_UNSPECIFIED); !errors.Is(err, ErrBridgeRowsMalformed) {
		t.Errorf("an entry of no mode: %v", err)
	}
	// a state with no BridgeEgress in its log holds the empty section
	if rows, err := net.log.State().BridgeRows(); err != nil || len(rows.GetEgress()) != 0 {
		t.Errorf("a new network's rows: %v, %v", rows, err)
	}
}

// A parser refuses what no verifier folds, each beside rows that parse: a short subject, auto or an unknown mode in a
// row, rows out of subject order or naming a subject twice, a field it cannot name, and bytes that are no message.
func TestParseBridgeRowsRefusesWhatNoVerifierFolds(t *testing.T) {
	exits := bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
	a, b := Id{0x01}, Id{0x02}
	marshal := func(rows *bridge.BridgeRows) []byte {
		return testConfigMarshal(t, rows)
	}
	good := marshal(&bridge.BridgeRows{Egress: []*bridge.BridgeEgressRow{{Subject: a.Bytes(), Mode: exits}, {Subject: b.Bytes(), Mode: exits}}})
	if _, err := ParseBridgeRows(good); err != nil {
		t.Fatal(err)
	}
	stray := protowire.AppendVarint(protowire.AppendTag(bytes.Clone(good), 7, protowire.VarintType), 1)
	strayRow := &bridge.BridgeEgressRow{Subject: a.Bytes(), Mode: exits}
	strayRow.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 9, protowire.VarintType), 1))
	for name, data := range map[string][]byte{
		"a short subject": marshal(&bridge.BridgeRows{Egress: []*bridge.BridgeEgressRow{{Subject: a.Bytes()[:8], Mode: exits}}}),
		"auto in a row":   marshal(&bridge.BridgeRows{Egress: []*bridge.BridgeEgressRow{{Subject: a.Bytes(), Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO}}}),
		"no mode":         marshal(&bridge.BridgeRows{Egress: []*bridge.BridgeEgressRow{{Subject: a.Bytes()}}}),
		"an unknown mode": marshal(&bridge.BridgeRows{Egress: []*bridge.BridgeEgressRow{{Subject: a.Bytes(), Mode: 9}}}),
		"out of order":    marshal(&bridge.BridgeRows{Egress: []*bridge.BridgeEgressRow{{Subject: b.Bytes(), Mode: exits}, {Subject: a.Bytes(), Mode: exits}}}),
		"a subject twice": marshal(&bridge.BridgeRows{Egress: []*bridge.BridgeEgressRow{{Subject: a.Bytes(), Mode: exits}, {Subject: a.Bytes(), Mode: exits}}}),
		"a stray field":   stray,
		"a stray row field": func() []byte {
			encoded, err := proto.Marshal(&bridge.BridgeRows{Egress: []*bridge.BridgeEgressRow{strayRow}})
			if err != nil {
				t.Fatal(err)
			}
			return encoded
		}(),
		"no message": {0xff, 0xff, 0xff},
	} {
		if _, err := ParseBridgeRows(data); !errors.Is(err, ErrBridgeRowsMalformed) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := bridgeRowsWithEgress(data, b, exits); !errors.Is(err, ErrBridgeRowsMalformed) {
			t.Errorf("%s, folded onto: %v", name, err)
		}
	}
}
