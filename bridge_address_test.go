// X18's address plan (bridge_address.go): the block's draw and its exclusions, each out-of-range choice refused, a
// chosen address held to the lower /17, tombstones by the log's time, host bits kept across a renumber, and the upper
// /17's first fit. The cases that need a block full of hosts are bridge_address_full_test.go's.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A random source that repeats on every run: SHA-256 over a seed and a counter.
type testBridgeRandom struct {
	seed    string
	counter uint64
	buffer  []byte
}

func (self *testBridgeRandom) Read(data []byte) (int, error) {
	for i := range data {
		if len(self.buffer) == 0 {
			block := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("bridge test random "+self.seed), self.counter))
			self.counter += 1
			self.buffer = block[:]
		}
		data[i], self.buffer = self.buffer[0], self.buffer[1:]
	}
	return len(data), nil
}

// The test network's block.
func testBridgeBlock() *bridge.BridgeBlock {
	return &bridge.BridgeBlock{Ipv4Prefix: testBridgePrefix(100, 80, 0, 0, 16)}
}

// A ledger over address claims handed in directly, one a sidecar, in order, and whatever statements follow: a block
// full of hosts without a log of 64,770 signed entries.
func testBridgeLedgerOf(t *testing.T, state *ConfigState, hostBits []uint32, more ...*BridgeLogStatement) (*BridgeLedger, []Id) {
	t.Helper()
	net := &testConfigNet{t: t, networkId: testConfigId("network")}
	holders := make([]Id, 0, len(hostBits))
	statements := make([]*BridgeLogStatement, 0, len(hostBits)+len(more))
	for i, bits := range hostBits {
		var holder Id
		binary.BigEndian.PutUint64(holder[8:], uint64(i)+1)
		holder[0] = 0xa0
		holders = append(holders, holder)
		statements = append(statements, testBridgeAddressStatement(net, uint64(i)+1, holder, testBridgeIpv4(100, 80, 0, 0)|bits))
	}
	statements = append(statements, more...)
	ledger := NewBridgeLog(statements).Open(&BridgeLedgerReader{State: state, RepoKeyAt: testConfigSealKeyAt(testConfigSealKey(1)), TimeMs: testConfigStartMs})
	return ledger, holders
}

// A BridgeAddress as the fold holds one, sealed to generation 1.
func testBridgeAddressStatement(net *testConfigNet, n uint64, holder Id, ipv4 uint32) *BridgeLogStatement {
	header := net.header()
	statement := &BridgeLogStatement{
		SignedType: bridge.SignedType_SIGNED_BRIDGE_ADDRESS, N: n, TimeMs: testConfigStartMs, Signer: holder, Subject: holder,
		Seal:       NewConfigSealContext(bridge.SignedType_SIGNED_BRIDGE_ADDRESS, header),
		SealedBody: net.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_ADDRESS, header, &bridge.BridgeAddressBody{Ipv4: ipv4}, 1),
	}
	binary.BigEndian.PutUint64(statement.StatementId[:], n)
	statement.StatementId[31] = 0xad
	return statement
}

// A BridgeAlias as the fold holds one, sealed to generation 1, each a target of one share.
func testBridgeAliasStatement(net *testConfigNet, n uint64, prefix *bridge.BridgeIpv4Prefix) *BridgeLogStatement {
	header := net.header()
	body := &bridge.BridgeAliasBody{ShareId: testConfigId("share").Bytes(), TargetIndex: uint32(n), AliasPrefix: prefix, Host: testConfigId("far host").Bytes()}
	statement := &BridgeLogStatement{
		SignedType: bridge.SignedType_SIGNED_BRIDGE_ALIAS, N: n, TimeMs: testConfigStartMs, Signer: Id{0x51},
		Seal:       NewConfigSealContext(bridge.SignedType_SIGNED_BRIDGE_ALIAS, header),
		SealedBody: net.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_ALIAS, header, body, 1),
	}
	binary.BigEndian.PutUint64(statement.StatementId[:], n)
	return statement
}

// Every host address of a block's lower /17, in order.
func testBridgeLowerHosts() []uint32 {
	hosts := make([]uint32, 0, bridgeLowerHostCount)
	for bits := uint32(0x100); bits < bridgeUpperHostBits; bits += 1 {
		if bridgeHostBitsValid(bits) {
			hosts = append(hosts, bits)
		}
	}
	return hosts
}

// Owner decision 28's draw, over many draws with a seeded source: always a /16 of 100.64.0.0/10 that a reader takes,
// never 100.64.0.0/16 or 100.100.0.0/16, and every one of the other 62 reached.
func TestChooseBridgeBlockDrawsEvenlyAndNeverAnExcludedBlock(t *testing.T) {
	random := &testBridgeRandom{seed: "blocks"}
	drawn := map[uint32]int{}
	for range 20000 {
		prefix, err := ChooseBridgeBlock(random)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckBridgeBlock(&bridge.BridgeBlock{Ipv4Prefix: prefix}); err != nil {
			t.Fatalf("a drawn block a reader refuses: %v", err)
		}
		if prefix.GetLength() != 16 || prefix.GetAddress()>>24 != 100 || prefix.GetAddress()>>22 != (100<<24|64<<16)>>22 {
			t.Fatalf("a block outside 100.64.0.0/10: %v", prefix)
		}
		drawn[prefix.GetAddress()] += 1
	}
	if drawn[testBridgeIpv4(100, 64, 0, 0)] != 0 || drawn[testBridgeIpv4(100, 100, 0, 0)] != 0 {
		t.Error("an excluded block was drawn")
	}
	if len(drawn) != 62 {
		t.Fatalf("%d blocks drawn, want all 62", len(drawn))
	}
	for address, count := range drawn {
		// 20,000 draws over 62 blocks is 322 each; a block drawn under half or over twice that is no even draw
		if count < 161 || 645 < count {
			t.Errorf("block %d.%d.0.0/16 drawn %d times", address>>24, address>>16&0xff, count)
		}
	}
	if prefix, err := ChooseBridgeBlock(nil); err != nil || prefix.GetLength() != 16 {
		t.Errorf("with crypto/rand: %v, %v", prefix, err)
	}
}

// A plan takes only a block a reader takes: each out-of-range choice and a /15 are refused, as CheckBridgeBlock's own
// test covers range by range.
func TestABridgeAddressPlanRefusesABlockNoNetworkMayHold(t *testing.T) {
	for name, prefix := range map[string]*bridge.BridgeIpv4Prefix{
		"public": testBridgePrefix(8, 8, 0, 0, 16), "a /15": testBridgePrefix(100, 64, 0, 0, 15), "link-local": testBridgePrefix(169, 254, 0, 0, 16),
		"below 100.64/10": testBridgePrefix(100, 63, 0, 0, 16), "above 172.16/12": testBridgePrefix(172, 32, 0, 0, 16),
	} {
		if _, err := NewBridgeAddressPlan(&bridge.BridgeBlock{Ipv4Prefix: prefix}, nil); !errors.Is(err, ErrBridgeBlockRefused) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := RenumberBridgeAddress(testBridgeIpv4(100, 80, 3, 7), prefix); !errors.Is(err, ErrBridgeBlockRefused) {
			t.Errorf("%s, as a renumber's block: %v", name, err)
		}
	}
	plan, err := NewBridgeAddressPlan(testBridgeBlock(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.FreeCount() != BridgeAddressMaxCount || BridgeAddressMaxCount != 64770 {
		t.Errorf("an empty block has %d free addresses, want 64,770", plan.FreeCount())
	}
	if plan.Block().GetAddress() != testBridgeIpv4(100, 80, 0, 0) || plan.PreviousBlock() != nil {
		t.Errorf("the plan's block: %v, previous %v", plan.Block(), plan.PreviousBlock())
	}
}

// A chosen address lies in the block's lower /17, outside its services, never ending in 0 or 255, and free.
func TestValidateBridgeAddressHoldsAChosenAddressToTheLowerHalf(t *testing.T) {
	ledger, holders := testBridgeLedgerOf(t, nil, []uint32{3<<8 | 7})
	plan, err := NewBridgeAddressPlan(testBridgeBlock(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	if address, ok := plan.Address(holders[0]); !ok || address != testBridgeIpv4(100, 80, 3, 7) {
		t.Fatalf("the holder's address: %d, %v", address, ok)
	}
	if _, ok := plan.Address(Id{0x77}); ok {
		t.Error("a sidecar with no claim has an address")
	}
	for name, c := range map[string]struct {
		address uint32
		want    error
	}{
		"free":                {address: testBridgeIpv4(100, 80, 3, 8), want: nil},
		"the lower /17's top": {address: testBridgeIpv4(100, 80, 127, 254), want: nil},
		"held":                {address: testBridgeIpv4(100, 80, 3, 7), want: ErrBridgeAddressTaken},
		"another block":       {address: testBridgeIpv4(100, 81, 3, 8), want: ErrBridgeAddressInvalid},
		"the upper /17":       {address: testBridgeIpv4(100, 80, 128, 9), want: ErrBridgeAddressInvalid},
		"the services":        {address: testBridgeIpv4(100, 80, 0, 53), want: ErrBridgeAddressInvalid},
		"ends in 0":           {address: testBridgeIpv4(100, 80, 9, 0), want: ErrBridgeAddressInvalid},
		"ends in 255":         {address: testBridgeIpv4(100, 80, 9, 255), want: ErrBridgeAddressInvalid},
	} {
		if err := ValidateBridgeAddress(plan, c.address); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

// An allocation is a free host of the lower /17, never the services, x.y.z.0 or x.y.z.255, never one held, and over
// many draws with a seeded source reaches the whole lower /17 and none of the upper.
func TestAllocateBridgeAddressDrawsAFreeHostOfTheLowerHalf(t *testing.T) {
	held := []uint32{3<<8 | 7, 3<<8 | 8, 127<<8 | 254}
	ledger, _ := testBridgeLedgerOf(t, nil, held)
	plan, err := NewBridgeAddressPlan(testBridgeBlock(), ledger)
	if err != nil {
		t.Fatal(err)
	}
	random := &testBridgeRandom{seed: "hosts"}
	thirdOctets := map[uint32]bool{}
	for range 5000 {
		address, err := AllocateBridgeAddress(plan, random)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateBridgeAddress(plan, address); err != nil {
			t.Fatalf("an allocation a chosen address could not be: %d.%d: %v", address>>8&0xff, address&0xff, err)
		}
		thirdOctets[address>>8&0xff] = true
	}
	if len(thirdOctets) != 127 || thirdOctets[0] {
		t.Errorf("allocations reached %d of the lower /17's 127 host /24s", len(thirdOctets))
	}
	if address, err := AllocateBridgeAddress(plan, nil); err != nil || ValidateBridgeAddress(plan, address) != nil {
		t.Errorf("with crypto/rand: %d, %v", address, err)
	}
}

// An allocation skips a tombstone by the log's time, not a local clock: a released address is never drawn while its
// 30 days run, whatever time the machine reads, and is drawn again once the ledger is read past them.
func TestAnAllocationSkipsATombstoneByTheLogsTime(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, desktop := testBridgeCast(net)
	// every lower host but two is held by sidecars the rows never knew, which holds nothing against the two below
	lower := testBridgeLowerHosts()
	tombstoned, free := lower[10], lower[20]
	net.mustPost(desktop, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, net.bridgeAddress(desktop, testBridgeIpv4(100, 80, 0, 0)|tombstoned))
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(desktop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	releasedMs := net.timeMs
	state := net.log.State()
	read := func(timeMs int64) *BridgeAddressPlan {
		ledger := state.Bridge().Open(&BridgeLedgerReader{State: state, RepoKeyAt: testConfigSealKeyAt(testConfigSealKey(1)), TimeMs: timeMs})
		plan, err := NewBridgeAddressPlan(testBridgeBlock(), ledger)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	during := read(releasedMs + BridgeAddressTombstoneMs - 1)
	if during.FreeCount() != BridgeAddressMaxCount-1 {
		t.Fatalf("%d free while the tombstone holds", during.FreeCount())
	}
	random := &testBridgeRandom{seed: "tombstone"}
	for range 3000 {
		address, err := AllocateBridgeAddress(during, random)
		if err != nil {
			t.Fatal(err)
		}
		if address&0xffff == tombstoned {
			t.Fatal("a tombstone was allocated")
		}
	}
	if err := ValidateBridgeAddress(during, testBridgeIpv4(100, 80, 0, 0)|tombstoned); !errors.Is(err, ErrBridgeAddressTaken) {
		t.Errorf("a tombstone chosen: %v", err)
	}
	if err := ValidateBridgeAddress(during, testBridgeIpv4(100, 80, 0, 0)|free); err != nil {
		t.Errorf("a free address beside it: %v", err)
	}
	after := read(releasedMs + BridgeAddressTombstoneMs)
	if after.FreeCount() != BridgeAddressMaxCount {
		t.Errorf("%d free once the 30 days ran", after.FreeCount())
	}
	if err := ValidateBridgeAddress(after, testBridgeIpv4(100, 80, 0, 0)|tombstoned); err != nil {
		t.Errorf("the address once its tombstone ran out: %v", err)
	}
}

// A renumber keeps a host's bits across a block change, an address in the upper /17 included, and a plan over a block
// that replaced another names the block still draining.
func TestRenumberBridgeAddressKeepsHostBits(t *testing.T) {
	next := testBridgePrefix(10, 44, 0, 0, 16)
	for _, c := range []struct{ from, want uint32 }{
		{from: testBridgeIpv4(100, 80, 3, 7), want: testBridgeIpv4(10, 44, 3, 7)},
		{from: testBridgeIpv4(100, 80, 255, 254), want: testBridgeIpv4(10, 44, 255, 254)},
		{from: testBridgeIpv4(100, 80, 127, 1), want: testBridgeIpv4(10, 44, 127, 1)},
	} {
		got, err := RenumberBridgeAddress(c.from, next)
		if err != nil || got != c.want {
			t.Errorf("%d: %d, %v, want %d", c.from, got, err, c.want)
		}
		if back, err := RenumberBridgeAddress(got, testBridgePrefix(100, 80, 0, 0, 16)); err != nil || back != c.from {
			t.Errorf("back again: %d, %v", back, err)
		}
	}
	// the ledger binds host bits, so a claim made under the old block is the same host under the new one
	ledger, holders := testBridgeLedgerOf(t, nil, []uint32{3<<8 | 7})
	changed := &bridge.BridgeBlock{Ipv4Prefix: next, PreviousPrefix: testBridgePrefix(100, 80, 0, 0, 16), DrainUntil: testConfigStartMs + testBridgeDayMs}
	plan, err := NewBridgeAddressPlan(changed, ledger)
	if err != nil {
		t.Fatal(err)
	}
	address, ok := plan.Address(holders[0])
	if !ok || address != testBridgeIpv4(10, 44, 3, 7) {
		t.Fatalf("the host under the new block: %d, %v", address, ok)
	}
	if old, err := RenumberBridgeAddress(address, plan.PreviousBlock()); err != nil || old != testBridgeIpv4(100, 80, 3, 7) {
		t.Errorf("where it is still reached while the old block drains: %d, %v", old, err)
	}
	if err := ValidateBridgeAddress(plan, testBridgeIpv4(10, 44, 3, 7)); !errors.Is(err, ErrBridgeAddressTaken) {
		t.Errorf("the host's bits under the new block: %v", err)
	}
}

// The upper /17 fills first-fit from its bottom, aligned, past an alias in force and never over it, and a length the
// upper /17 cannot hold is refused. bridge_address_full_test.go holds the same against hosts in the upper /17.
func TestAllocateBridgeUpperBlockFitsFirstFromTheBottom(t *testing.T) {
	net := newTestConfigNet(t)
	aliasStatement := func(n uint64, prefix *bridge.BridgeIpv4Prefix) *BridgeLogStatement {
		return testBridgeAliasStatement(net, n, prefix)
	}
	planOf := func(ledger *BridgeLedger) *BridgeAddressPlan {
		plan, err := NewBridgeAddressPlan(testBridgeBlock(), ledger)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	allocate := func(plan *BridgeAddressPlan, length uint32) *bridge.BridgeIpv4Prefix {
		prefix, err := AllocateBridgeUpperBlock(plan, length)
		if err != nil {
			t.Fatalf("a /%d: %v", length, err)
		}
		return prefix
	}

	empty := planOf(nil)
	if got := allocate(empty, 24); got.GetAddress() != testBridgeIpv4(100, 80, 128, 0) || got.GetLength() != 24 {
		t.Errorf("the first /24: %v", got)
	}
	if got := allocate(empty, 17); got.GetAddress() != testBridgeIpv4(100, 80, 128, 0) {
		t.Errorf("the whole upper /17: %v", got)
	}
	for _, length := range []uint32{0, 16, 33} {
		if _, err := AllocateBridgeUpperBlock(empty, length); !errors.Is(err, ErrBridgeAddressInvalid) {
			t.Errorf("a /%d: %v", length, err)
		}
	}

	// an alias holds 128.0/24: a /24 goes beside it, a /23 past it at the next aligned /23, and a /32 after it
	ledger, _ := testBridgeLedgerOf(t, nil, nil, aliasStatement(1, testBridgePrefix(100, 80, 128, 0, 24)))
	held := planOf(ledger)
	if got := allocate(held, 24); got.GetAddress() != testBridgeIpv4(100, 80, 129, 0) {
		t.Errorf("a /24 beside an alias: %v", got)
	}
	if got := allocate(held, 23); got.GetAddress() != testBridgeIpv4(100, 80, 130, 0) {
		t.Errorf("a /23 past an alias: %v", got)
	}
	if got := allocate(held, 32); got.GetAddress() != testBridgeIpv4(100, 80, 129, 0) {
		t.Errorf("a /32 past an alias: %v", got)
	}
}
