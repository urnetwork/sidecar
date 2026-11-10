//go:build !js

// X18's address plan on a full block (bridge_address.go): the lower /17's exhaustion and the spill to the upper /17's
// top, the 64,770 bound, and the upper /17's first fit against hosts that sit in it. Each case folds a ledger of tens
// of thousands of sealed claims, some 160,000 in all. They stay off the page Worker's run, whose wasm memory they grew
// by some 30 MB that it never gives back (legs_test.go holds that leg's suite to what it needs); the code is the same
// on every leg, and the cases with a handful of hosts in bridge_address_test.go run there too.

package sidecar

import (
	"errors"
	"testing"
)

// Once the lower /17 is full an allocation is the highest free /32 of the upper /17, never .0 or .255, and the log
// takes it there and nowhere else: an upper claim while the lower has room is void. A full block holds 64,770 and
// gives no more.
func TestBridgeAddressesSpillToTheUpperHalfsTopOnceTheLowerIsFull(t *testing.T) {
	lower := testBridgeLowerHosts()
	if len(lower) != bridgeLowerHostCount {
		t.Fatalf("the lower /17 holds %d hosts", len(lower))
	}
	// one short of full: the one free lower host is the only allocation, and the upper /17 takes no host
	short := append([]uint32{}, lower[:len(lower)-1]...)
	ledger, _ := testBridgeLedgerOf(t, nil, append(short, 255<<8|254))
	testBridgeDisposition(t, ledger, uint64(len(short))+1, BridgeDispositionVoid)
	plan, err := NewBridgeAddressPlan(testBridgeBlock(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	if address, err := AllocateBridgeAddress(plan, &testBridgeRandom{seed: "last"}); err != nil || address&0xffff != lower[len(lower)-1] {
		t.Fatalf("the last lower host: %d, %v", address&0xffff, err)
	}

	// full: spill to the top, skipping x.y.255.255, then downward past each .0 and .255
	spilled := []uint32{255<<8 | 254, 255<<8 | 253}
	ledger, _ = testBridgeLedgerOf(t, nil, append(append([]uint32{}, lower...), spilled...))
	for i := range spilled {
		testBridgeDisposition(t, ledger, uint64(len(lower)+i)+1, BridgeDispositionActive)
	}
	plan, err = NewBridgeAddressPlan(testBridgeBlock(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	if plan.FreeCount() != BridgeAddressMaxCount-len(lower)-len(spilled) {
		t.Errorf("%d free", plan.FreeCount())
	}
	if address, err := AllocateBridgeAddress(plan, &testBridgeRandom{seed: "spill"}); err != nil || address != testBridgeIpv4(100, 80, 255, 252) {
		t.Fatalf("the spill: %d.%d, %v", address>>8&0xff, address&0xff, err)
	}
	if err := ValidateBridgeAddress(plan, testBridgeIpv4(100, 80, 255, 252)); !errors.Is(err, ErrBridgeAddressInvalid) {
		t.Errorf("a person may not choose the upper /17: %v", err)
	}

	// the whole block: 64,770 hosts, each claim holding, and then none
	all := append([]uint32{}, lower...)
	for bits := uint32(0xffff); bridgeUpperHostBits <= bits; bits -= 1 {
		if bridgeHostBitsValid(bits) {
			all = append(all, bits)
		}
	}
	ledger, _ = testBridgeLedgerOf(t, nil, all)
	if len(all) != BridgeAddressMaxCount || len(ledger.Addresses()) != BridgeAddressMaxCount {
		t.Fatalf("%d claims, %d held, want 64,770", len(all), len(ledger.Addresses()))
	}
	plan, err = NewBridgeAddressPlan(testBridgeBlock(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	if plan.FreeCount() != 0 {
		t.Errorf("a full block has %d free", plan.FreeCount())
	}
	if _, err := AllocateBridgeAddress(plan, &testBridgeRandom{seed: "full"}); !errors.Is(err, ErrBridgeAddressesExhausted) {
		t.Errorf("a full block allocates: %v", err)
	}
}

// Once the lower /17 is full the upper takes hosts: a /24 skips the aligned block a host sits inside and the one an
// alias holds, wider blocks find the first aligned room past both, and the log voids a host claimed inside an alias
// and an alias laid over a host, so the two never overlap from either side.
func TestAllocateBridgeUpperBlockSkipsABlockAHostSitsInside(t *testing.T) {
	net := newTestConfigNet(t)
	planOf := func(ledger *BridgeLedger) *BridgeAddressPlan {
		plan, err := NewBridgeAddressPlan(testBridgeBlock(), ledger)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	allocate := func(plan *BridgeAddressPlan, length uint32) uint32 {
		prefix, err := AllocateBridgeUpperBlock(plan, length)
		if err != nil {
			t.Fatalf("a /%d: %v", length, err)
		}
		return prefix.GetAddress()
	}
	// once the lower /17 is full the upper takes hosts: a /24 skips the aligned block a host sits inside and the one an
	// alias holds, wider blocks find the first aligned room past both, and the log voids a host claimed inside an alias
	lower := testBridgeLowerHosts()
	claims := append(append([]uint32{}, lower...), 255<<8|254, 128<<8|5)
	aliasN := uint64(len(claims)) + 1
	inside := testBridgeAddressStatement(net, aliasN+1, Id{0x52}, testBridgeIpv4(100, 80, 129, 9))
	ledger, _ := testBridgeLedgerOf(t, nil, claims, testBridgeAliasStatement(net, aliasN, testBridgePrefix(100, 80, 129, 0, 24)), inside)
	testBridgeDisposition(t, ledger, aliasN-1, BridgeDispositionActive)
	testBridgeDisposition(t, ledger, aliasN, BridgeDispositionActive)
	testBridgeDisposition(t, ledger, aliasN+1, BridgeDispositionVoid)
	spilled := planOf(ledger)
	if got := allocate(spilled, 24); got != testBridgeIpv4(100, 80, 130, 0) {
		t.Errorf("a /24 past a host's block and an alias: %v", got)
	}
	if got := allocate(spilled, 19); got != testBridgeIpv4(100, 80, 160, 0) {
		t.Errorf("a /19 past both: %v", got)
	}
	for _, length := range []uint32{17, 18} {
		if _, err := AllocateBridgeUpperBlock(spilled, length); !errors.Is(err, ErrBridgeUpperBlockNoSpace) {
			t.Errorf("a /%d with a host or an alias in every aligned block: %v", length, err)
		}
	}
	// an alias over a host is void in the log too, so the two never overlap from either side
	over := testBridgeAliasStatement(net, aliasN+2, testBridgePrefix(100, 80, 255, 0, 24))
	ledger, _ = testBridgeLedgerOf(t, nil, claims, over)
	testBridgeDisposition(t, ledger, aliasN+2, BridgeDispositionVoid)
}
