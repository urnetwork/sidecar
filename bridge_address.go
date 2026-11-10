// X18, §17.4's address plan, as pure functions over a network's block and the ledger a reader opens from its BridgeLog
// (bridge_statement_rules.go):
//
//	block    one IPv4 /16 per network, at random from 100.64.0.0/10 except 100.64.0.0/16, the likeliest in use, and
//	         100.100.0.0/16, which holds another overlay's 100.100.100.100 (ChooseBridgeBlock; owner decision 28). An
//	         admin's own choice is a /16 in 100.64.0.0/10 or RFC 1918 and nothing else (CheckBridgeBlock;
//	         D-BRIDGE-16)
//	host     a random free /32 of the lower /17 outside <block>.0.0/24, which holds services; once that is full, the
//	         highest free /32 of the upper /17; never x.y.z.0 or x.y.z.255 (AllocateBridgeAddress). An address a
//	         person chooses lies in the lower /17 (ValidateBridgeAddress). The block holds 64,770
//	upper    aliases and exposed prefixes fill the upper /17 first-fit from its bottom, aligned, while spilled hosts
//	         take its top, and the two never overlap (AllocateBridgeUpperBlock; D-BRIDGE-20)
//	renumber a host keeps its host bits across a block change while the old block drains (RenumberBridgeAddress)
//
// A client proposes and the log decides: the first claim in log order wins, so an address this allocates is a proposal
// until its BridgeAddress takes effect and the ledger shows it. An address is bound to its sidecar_id, which survives
// re-enrollment and the reaper; it is released on revocation or removal and is then a tombstone for 30 days by the
// log's time, never a local clock, which the ledger holds and an allocation skips (I-14). Nothing here files a
// statement, and nothing claims an address at an app's setup: assignment stays on demand (Q-BRIDGE-8).
//
// A block in 10.0.0.0/8 can collide with connect's tun ranges, 10.a.b.0/24, which the sdk's avoid list handles
// (BRIDGE-M4-21); 169.254.0.0/16 is outside every block a network may hold.
//
// Pure but for the random source a caller passes. On every leg, with no connect import. Nothing here creates, derives
// or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The address is not one a host may hold or choose: outside the block or its lower /17, in the block's services,
	// or ending in 0 or 255.
	ErrBridgeAddressInvalid = errors.New("bridge address invalid")
	// The address is held, or a tombstone of one released within 30 days.
	ErrBridgeAddressTaken = errors.New("bridge address taken")
	// Every host address of the block is held or a tombstone.
	ErrBridgeAddressesExhausted = errors.New("bridge addresses exhausted")
	// The upper /17 has no aligned room for a block of the length asked (§17.9's space row).
	ErrBridgeUpperBlockNoSpace = errors.New("bridge upper /17 has no room")
)

// The /16s ChooseBridgeBlock never draws.
var bridgeBlockExclusions = []uint32{100<<24 | 64<<16, 100<<24 | 100<<16}

// A draw from random below limit, uniform: rejection over 32 bits, so no value is favored.
func bridgeRandomBelow(random io.Reader, limit uint32) (uint32, error) {
	if limit == 0 {
		return 0, errors.New("no value to draw")
	}
	// the largest multiple of limit that fits, below which a draw maps evenly
	bound := (uint64(1) << 32) / uint64(limit) * uint64(limit)
	var draw [4]byte
	for {
		if _, err := io.ReadFull(random, draw[:]); err != nil {
			return 0, fmt.Errorf("bridge address: random: %w", err)
		}
		if value := uint64(binary.BigEndian.Uint32(draw[:])); value < bound {
			return uint32(value % uint64(limit)), nil
		}
	}
}

// A network's block: a /16 drawn evenly from the 62 of 100.64.0.0/10 that are neither 100.64.0.0/16 nor
// 100.100.0.0/16, with random, or crypto/rand's reader when nil. BootstrapNetwork writes it into the first head, and
// any config writer into its next head where a network holds none (plan-BRIDGE-small-readings #13).
func ChooseBridgeBlock(random io.Reader) (*bridge.BridgeIpv4Prefix, error) {
	if random == nil {
		random = rand.Reader
	}
	candidates := []uint32{}
	for secondOctet := uint32(64); secondOctet < 128; secondOctet += 1 {
		address := 100<<24 | secondOctet<<16
		excluded := false
		for _, exclusion := range bridgeBlockExclusions {
			excluded = excluded || exclusion == address
		}
		if !excluded {
			candidates = append(candidates, address)
		}
	}
	index, err := bridgeRandomBelow(random, uint32(len(candidates)))
	if err != nil {
		return nil, err
	}
	return &bridge.BridgeIpv4Prefix{Address: candidates[index], Length: bridgeBlockPrefixLength}, nil
}

// One network's addresses as a reader sees them at the log's time its ledger was read at: the block its verified head
// carries, and the ledger's live addresses, tombstones, aliases and exposed prefixes.
type BridgeAddressPlan struct {
	block    bridgePrefix
	previous *bridgePrefix
	ledger   *BridgeLedger
}

// The plan of a block over a ledger. block is the one a reader holds from ReadBridgeBlock, so it has passed
// CheckBridgeBlock; one that does not is refused here too. A nil ledger holds no address.
func NewBridgeAddressPlan(block *bridge.BridgeBlock, ledger *BridgeLedger) (*BridgeAddressPlan, error) {
	if err := CheckBridgeBlock(block); err != nil {
		return nil, err
	}
	if ledger == nil {
		ledger = (*BridgeLog)(nil).Open(nil)
	}
	prefix, _ := bridgePrefixOf(block.GetIpv4Prefix())
	plan := &BridgeAddressPlan{block: prefix, ledger: ledger}
	if block.GetPreviousPrefix() != nil {
		previous, _ := bridgePrefixOf(block.GetPreviousPrefix())
		plan.previous = &previous
	}
	return plan, nil
}

// The block.
func (self *BridgeAddressPlan) Block() *bridge.BridgeIpv4Prefix {
	return self.block.wire()
}

// The block this one replaced, nil for none or once a head no longer names it: hosts are still reached there, at their
// host bits, until its drain ends.
func (self *BridgeAddressPlan) PreviousBlock() *bridge.BridgeIpv4Prefix {
	if self.previous == nil {
		return nil
	}
	return self.previous.wire()
}

// A sidecar's address in the block, false when it holds none. While a replaced block drains it is also reached at
// RenumberBridgeAddress of this into the previous block.
func (self *BridgeAddressPlan) Address(sidecarId Id) (uint32, bool) {
	address := self.ledger.Address(sidecarId)
	if address == nil {
		return 0, false
	}
	return self.block.address | address.HostBits, true
}

// How many host addresses the block has left: of its 64,770, those neither held nor tombstones, nor inside an alias or
// an exposed prefix.
func (self *BridgeAddressPlan) FreeCount() int {
	free := bridgeLowerHostCount - self.ledger.LowerTakenCount()
	for hostBits := bridgeUpperHostBits; hostBits <= 0xffff; hostBits += 1 {
		if self.upperHostFree(hostBits) {
			free += 1
		}
	}
	return free
}

// Whether an upper /17 host address is free for a spilled host.
func (self *BridgeAddressPlan) upperHostFree(hostBits uint32) bool {
	return bridgeHostBitsValid(hostBits) && !self.ledger.HostBitsTaken(hostBits) && self.ledger.upperRangeHolding(hostBits, hostBits) == nil
}

// Whether a lower /17 host address is free.
func (self *BridgeAddressPlan) lowerHostFree(hostBits uint32) bool {
	return bridgeHostBitsValid(hostBits) && hostBits < bridgeUpperHostBits && !self.ledger.HostBitsTaken(hostBits)
}

// An address to propose for a host that holds none: a free /32 of the lower /17, drawn evenly with random
// (crypto/rand's reader when nil); once the lower /17 is full, the highest free /32 of the upper /17 that no alias or
// exposed prefix holds. ErrBridgeAddressesExhausted when the block has none. The log decides: the caller files it
// and reads the ledger again.
func AllocateBridgeAddress(plan *BridgeAddressPlan, random io.Reader) (uint32, error) {
	if random == nil {
		random = rand.Reader
	}
	freeCount := bridgeLowerHostCount - plan.ledger.LowerTakenCount()
	if 0 < freeCount {
		// an even draw over the free hosts: the index-th free one in address order
		index, err := bridgeRandomBelow(random, uint32(freeCount))
		if err != nil {
			return 0, err
		}
		for hostBits := uint32(0x100); hostBits < bridgeUpperHostBits; hostBits += 1 {
			if !plan.lowerHostFree(hostBits) {
				continue
			}
			if index == 0 {
				return plan.block.address | hostBits, nil
			}
			index -= 1
		}
	}
	for hostBits := uint32(0xffff); bridgeUpperHostBits <= hostBits; hostBits -= 1 {
		if plan.upperHostFree(hostBits) {
			return plan.block.address | hostBits, nil
		}
	}
	return 0, ErrBridgeAddressesExhausted
}

// Whether a person may choose address for a host (`ur tun ip <ip>`): in the block, in its lower /17, outside its
// services, not ending in 0 or 255 (ErrBridgeAddressInvalid), and neither held nor a tombstone at the ledger's time
// (ErrBridgeAddressTaken).
func ValidateBridgeAddress(plan *BridgeAddressPlan, address uint32) error {
	if !plan.block.containsAddress(address) {
		return fmt.Errorf("%w: outside the block %s", ErrBridgeAddressInvalid, plan.block)
	}
	hostBits := address & 0xffff
	switch {
	case bridgeUpperHostBits <= hostBits:
		return fmt.Errorf("%w: a chosen address lies in the lower /17", ErrBridgeAddressInvalid)
	case !bridgeHostBitsValid(hostBits):
		return fmt.Errorf("%w: in the block's services, or ending in 0 or 255", ErrBridgeAddressInvalid)
	case plan.ledger.HostBitsTaken(hostBits):
		return ErrBridgeAddressTaken
	}
	return nil
}

// address moved into block, keeping its host bits: where a host sits after a block change, and, with the previous
// block, where it is still reached while that block drains. ErrBridgeBlockRefused for a block no network may hold.
func RenumberBridgeAddress(address uint32, block *bridge.BridgeIpv4Prefix) (uint32, error) {
	prefix, err := bridgeCheckBlockPrefix(block)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrBridgeBlockRefused, err)
	}
	return prefix.address | address&0xffff, nil
}

// A prefix of the block's upper /17 for an alias (BRIDGE-M6-03) or an exposed_prefix (plan-BRIDGE-small-readings #14),
// of the length asked, /17 to /32: first fit from the upper /17's bottom, aligned to its own size, skipping any
// candidate that overlaps an alias or exposed prefix in force or that a host, live or a tombstone, sits inside.
// ErrBridgeUpperBlockNoSpace when none fits, and ErrBridgeAddressInvalid for a length the upper /17 cannot hold.
func AllocateBridgeUpperBlock(plan *BridgeAddressPlan, length uint32) (*bridge.BridgeIpv4Prefix, error) {
	if length < 17 || 32 < length {
		return nil, fmt.Errorf("%w: a /%d does not fit the upper /17", ErrBridgeAddressInvalid, length)
	}
	size := uint32(1) << (32 - length)
	for first := bridgeUpperHostBits; first <= 0xffff; first += size {
		last := first + size - 1
		if plan.ledger.upperRangeHolding(first, last) == nil && !plan.ledger.hostIn(first, last) {
			return &bridge.BridgeIpv4Prefix{Address: plan.block.address | first, Length: length}, nil
		}
	}
	return nil, ErrBridgeUpperBlockNoSpace
}
