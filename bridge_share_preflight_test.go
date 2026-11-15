//go:build !ios_extension

package sidecar

import (
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The alias one share's target holds, as the net's owner, an admin's device, files it.
func testBridgeShareAliasBody(share string, target uint32, prefix *bridge.BridgeIpv4Prefix) *bridge.BridgeAliasBody {
	return &bridge.BridgeAliasBody{
		ShareId: testConfigId(share).Bytes(), TargetIndex: target, AliasPrefix: prefix, Host: testConfigId("far host").Bytes(),
		SharingNetworkId: testConfigId("sharing network").Bytes(),
	}
}

// What the preflight planned, as (host bits, length) pairs by index.
func testBridgeSharePlan(t *testing.T, ledger *BridgeLedger, lengths ...uint32) [][2]uint32 {
	t.Helper()
	aliases, err := BridgeSharePreflight(ledger, testBridgeShareTargets(lengths...))
	if err != nil {
		t.Fatalf("the preflight of %v: %v", lengths, err)
	}
	plan := [][2]uint32{}
	for i, alias := range aliases {
		if alias.GetIndex() != uint32(i) {
			t.Fatalf("alias %d carries index %d", i, alias.GetIndex())
		}
		plan = append(plan, [2]uint32{alias.GetAliasHostBits(), alias.GetLength()})
	}
	return plan
}

// DESIGN-DETAILS 12.2.7's preflight: each target takes the first aligned free block of its length from the bottom of
// the upper /17, in index order; two targets never share a block, even two of one prefix; a /32 avoids .0 and .255;
// and what the ledger holds, an alias and an exposed prefix, is planned around.
func TestPreflightIsFirstFitAndAligned(t *testing.T) {
	net := newTestConfigNet(t)
	empty := (*BridgeLog)(nil).Open(nil)
	if plan := testBridgeSharePlan(t, empty, 24, 24, 32, 23, 32); !slices.Equal(plan, [][2]uint32{
		{0x8000, 24}, {0x8100, 24}, {0x8201, 32}, {0x8400, 23}, {0x8202, 32},
	}) {
		t.Errorf("on an empty upper /17: %x", plan)
	}
	if plan := testBridgeSharePlan(t, empty, 17); !slices.Equal(plan, [][2]uint32{{0x8000, 17}}) {
		t.Errorf("the whole upper /17: %x", plan)
	}

	// an alias holds 128.0/24 and another 130.0/24: a /23 goes past both at the next aligned /23, a /24 between them
	ledger, _ := testBridgeLedgerOf(t, nil, nil,
		testBridgeAliasStatement(net, 1, testBridgePrefix(100, 80, 128, 0, 24)),
		testBridgeAliasStatement(net, 2, testBridgePrefix(100, 80, 130, 0, 24)))
	if plan := testBridgeSharePlan(t, ledger, 23, 24, 32); !slices.Equal(plan, [][2]uint32{{0x8400, 23}, {0x8100, 24}, {0x8301, 32}}) {
		t.Errorf("around two aliases: %x", plan)
	}
	// the plan is a function of the ledger and the table: a second run plans the same
	if again := testBridgeSharePlan(t, ledger, 23, 24, 32); !slices.Equal(again, [][2]uint32{{0x8400, 23}, {0x8100, 24}, {0x8301, 32}}) {
		t.Errorf("a second run planned otherwise: %x", again)
	}
	// every planned alias passes the alias table's own check and the ledger's
	aliases, _ := BridgeSharePreflight(ledger, testBridgeShareTargets(23, 24, 32))
	if err := CheckBridgeShareAliases(&bridge.BridgeShareAliases{Aliases: aliases}, testBridgeShareTargets(23, 24, 32)); err != nil {
		t.Errorf("the planned table: %v", err)
	}
}

// A target wider than /17 is refused as too large whatever room there is, and before any space is judged (§17.9's
// size row); a table out of form is refused as invalid.
func TestPreflightRefusesAWideTarget(t *testing.T) {
	empty := (*BridgeLog)(nil).Open(nil)
	for _, lengths := range [][]uint32{{16}, {24, 12}, {17, 17, 8}} {
		if _, err := BridgeSharePreflight(empty, testBridgeShareTargets(lengths...)); !errors.Is(err, ErrBridgeShareTooLarge) {
			t.Errorf("%v: %v", lengths, err)
		}
	}
	sparse := testBridgeShareTargets(24, 24)
	sparse.Targets[1].Index = 5
	noKey := testBridgeShareTargets(24)
	noKey.Targets[0].HostIdentityPublicKey = nil
	unmasked := testBridgeShareTargets(24)
	unmasked.Targets[0].Prefix.Address |= 1
	ports := testBridgeShareTargets(24)
	ports.Targets[0].Ports = []*bridge.BridgePortRange{{First: 80, Last: 80}}
	for name, targets := range map[string]*bridge.BridgeShareTargets{
		"no target": {}, "a sparse index": sparse, "no host key": noKey, "an unmasked prefix": unmasked, "ports of no protocol": ports,
	} {
		if _, err := BridgeSharePreflight(empty, targets); !errors.Is(err, ErrBridgeShareTableInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := BridgeSharePreflight(nil, testBridgeShareTargets(24)); !errors.Is(err, ErrBridgeShareTableInvalid) {
		t.Errorf("no ledger: %v", err)
	}
}

// With no aligned free block for a target the preflight refuses with the shortfall: the first target that found no
// room, its length, the free addresses and the shortest prefix length that still has a block (§17.9's space row).
func TestPreflightReportsItsShortfall(t *testing.T) {
	net := newTestConfigNet(t)
	// aliases hold all of the upper /17 but 255.0/24
	held := []*BridgeLogStatement{
		testBridgeAliasStatement(net, 1, testBridgePrefix(100, 80, 128, 0, 18)),
		testBridgeAliasStatement(net, 2, testBridgePrefix(100, 80, 192, 0, 19)),
		testBridgeAliasStatement(net, 3, testBridgePrefix(100, 80, 224, 0, 20)),
		testBridgeAliasStatement(net, 4, testBridgePrefix(100, 80, 240, 0, 21)),
		testBridgeAliasStatement(net, 5, testBridgePrefix(100, 80, 248, 0, 22)),
		testBridgeAliasStatement(net, 6, testBridgePrefix(100, 80, 252, 0, 23)),
		testBridgeAliasStatement(net, 7, testBridgePrefix(100, 80, 254, 0, 24)),
	}
	ledger, _ := testBridgeLedgerOf(t, nil, nil, held...)
	if plan := testBridgeSharePlan(t, ledger, 24); !slices.Equal(plan, [][2]uint32{{0xff00, 24}}) {
		t.Fatalf("the last /24: %x", plan)
	}
	_, err := BridgeSharePreflight(ledger, testBridgeShareTargets(25, 23))
	noSpace := &BridgeShareRefusal{}
	if !errors.Is(err, ErrBridgeShareNoSpace) || !errors.As(err, &noSpace) {
		t.Fatalf("a /23 with a /24 left: %v", err)
	}
	// the /25 took the bottom half of the last /24, so 128 addresses and a /25 are what is left
	if shortfall := noSpace.Shortfall; shortfall.GetIndex() != 1 || shortfall.GetLength() != 23 || shortfall.GetFreeAddressCount() != 128 || shortfall.GetLargestFreeLength() != 25 {
		t.Errorf("the shortfall: %v", shortfall)
	}
	full, _ := testBridgeLedgerOf(t, nil, nil, testBridgeAliasStatement(net, 1, testBridgePrefix(100, 80, 128, 0, 17)))
	_, err = BridgeSharePreflight(full, testBridgeShareTargets(32))
	if !errors.As(err, &noSpace) || noSpace.Shortfall.GetFreeAddressCount() != 0 || noSpace.Shortfall.GetLargestFreeLength() != bridgeShareNoFreeLength {
		t.Errorf("a full upper /17: %v", err)
	}
}

// An alias ends by a release from its signer or an admin's device (DESIGN-DETAILS 12.2.7): the alias routes nothing
// new at once, keeps its block until its drain's end, 300 s when the release names none, and the block is free after
// it; a release by another member's device, of another prefix, of no alias, or with a drain past the maximum is void.
func TestAnAliasReleaseFreesItsBlockAfterItsDrain(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, _ := testBridgeCast(net.testConfigNet)
	aliasType := bridge.SignedType_SIGNED_BRIDGE_ALIAS
	first := testBridgeShareAliasBody("share", 0, testBridgePrefix(100, 80, 128, 0, 24))
	net.mustPost(net.owner, aliasType, net.bridgeAlias(first))
	release := func(edit func(body *bridge.BridgeAliasBody)) *bridge.BridgeAlias {
		body := testBridgeShareAliasBody("share", 0, testBridgePrefix(100, 80, 128, 0, 24))
		body.Release = true
		if edit != nil {
			edit(body)
		}
		return net.bridgeAlias(body)
	}
	byAnother := net.mustPost(laptop, aliasType, release(nil)).Pin.GetVersion()
	otherPrefix := net.mustPost(net.owner, aliasType, release(func(body *bridge.BridgeAliasBody) {
		body.AliasPrefix = testBridgePrefix(100, 80, 129, 0, 24)
	})).Pin.GetVersion()
	noAlias := net.mustPost(net.owner, aliasType, release(func(body *bridge.BridgeAliasBody) { body.TargetIndex = 4 })).Pin.GetVersion()
	longDrain := net.mustPost(net.owner, aliasType, release(func(body *bridge.BridgeAliasBody) { body.DrainSeconds = 3601 })).Pin.GetVersion()
	ledger := net.ledgerOf(net.log)
	for _, n := range []uint64{byAnother, otherPrefix, noAlias, longDrain} {
		testBridgeDisposition(t, ledger, n, BridgeDispositionVoid)
	}
	if len(ledger.Aliases()) != 1 || len(ledger.DrainingAliases()) != 0 {
		t.Fatalf("after void releases: %d in force, %d draining", len(ledger.Aliases()), len(ledger.DrainingAliases()))
	}

	released := net.mustPost(net.owner, aliasType, release(nil)).Pin.GetVersion()
	ledger = net.ledgerOf(net.log)
	testBridgeDisposition(t, ledger, released, BridgeDispositionActive)
	draining := ledger.DrainingAliases()
	if len(ledger.Aliases()) != 0 || len(draining) != 1 || draining[0].ReleasedAt != released || draining[0].DrainUntilMs() != draining[0].ReleasedMs+300_000 {
		t.Fatalf("after the release: %d in force, draining %+v", len(ledger.Aliases()), draining)
	}
	// the draining alias keeps its block: the preflight plans beside it, and the same target may be aliased again
	if plan := testBridgeSharePlan(t, ledger, 24); !slices.Equal(plan, [][2]uint32{{0x8100, 24}}) {
		t.Errorf("while the alias drains: %x", plan)
	}
	over := net.mustPost(net.owner, aliasType, net.bridgeAlias(testBridgeShareAliasBody("share", 0, testBridgePrefix(100, 80, 128, 0, 24)))).Pin.GetVersion()
	again := net.mustPost(net.owner, aliasType, net.bridgeAlias(testBridgeShareAliasBody("share", 0, testBridgePrefix(100, 80, 129, 0, 24)))).Pin.GetVersion()
	ledger = net.ledgerOf(net.log)
	testBridgeDisposition(t, ledger, over, BridgeDispositionVoid)
	testBridgeDisposition(t, ledger, again, BridgeDispositionActive)

	// past the drain the block is free: an alias over it lands, and the preflight plans it first
	net.timeMs += 300_000
	after := net.mustPost(net.owner, aliasType, net.bridgeAlias(testBridgeShareAliasBody("other share", 0, testBridgePrefix(100, 80, 128, 0, 24)))).Pin.GetVersion()
	ledger = net.ledgerOf(net.log)
	testBridgeDisposition(t, ledger, after, BridgeDispositionActive)
	if len(ledger.Aliases()) != 2 || len(ledger.DrainingAliases()) != 0 {
		t.Errorf("past the drain: %d in force, %d draining", len(ledger.Aliases()), len(ledger.DrainingAliases()))
	}
}

// A release reads alike whether a fold came between or not: the fold writes the released alias as a row with its
// release's entry and time while it drains, a reader that starts at that base holds the block as one present since the
// filing does, and a fold whose time passes the drain drops the row.
func TestAnAliasReleaseReadsAlikeAcrossAFold(t *testing.T) {
	for _, foldBetween := range []bool{true, false} {
		net := newTestBridgeLedgerNet(t)
		aliasType := bridge.SignedType_SIGNED_BRIDGE_ALIAS
		net.mustPost(net.owner, aliasType, net.bridgeAlias(testBridgeShareAliasBody("share", 0, testBridgePrefix(100, 80, 128, 0, 24))))
		body := testBridgeShareAliasBody("share", 0, testBridgePrefix(100, 80, 128, 0, 24))
		body.Release, body.DrainSeconds = true, 600
		released := net.mustPost(net.owner, aliasType, net.bridgeAlias(body)).Pin.GetVersion()
		net.mustPost(net.owner, aliasType, net.bridgeAlias(testBridgeShareAliasBody("share", 0, testBridgePrefix(100, 80, 129, 0, 24))))
		if foldBetween {
			net.foldLedger(net.n, nil)
			_, _, _, rows := net.ledgerOf(net.log).foldRows()
			if len(rows) != 2 || rows[0].GetReleasedAt() != released || rows[0].GetBody().GetDrainSeconds() != 600 || rows[1].GetReleasedAt() != 0 || rows[1].GetAt() <= rows[0].GetAt() {
				t.Fatalf("the folded rows: %v", rows)
			}
		}
		// inside the drain the block is held; an alias over it is void
		// each entry moves the log's time a second on
		net.timeMs += 590_000
		inside := net.mustPost(net.owner, aliasType, net.bridgeAlias(testBridgeShareAliasBody("late share", 0, testBridgePrefix(100, 80, 128, 0, 24)))).Pin.GetVersion()
		// past it the block is free
		net.timeMs += 10_000
		past := net.mustPost(net.owner, aliasType, net.bridgeAlias(testBridgeShareAliasBody("later share", 0, testBridgePrefix(100, 80, 128, 0, 24)))).Pin.GetVersion()
		ledger := net.ledgerOf(net.log)
		testBridgeDisposition(t, ledger, inside, BridgeDispositionVoid)
		testBridgeDisposition(t, ledger, past, BridgeDispositionActive)
		if foldBetween {
			net.foldLedger(net.n, nil)
			_, _, _, rows := net.ledgerOf(net.log).foldRows()
			released := slices.ContainsFunc(rows, func(row *protocol.BridgeLedgerAliasRow) bool { return row.GetReleasedAt() != 0 })
			if len(rows) != 2 || released {
				t.Fatalf("fold between %v: the rows past the drain: %v", foldBetween, rows)
			}
		}
	}
}
