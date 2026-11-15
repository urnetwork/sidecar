// §17.9's preflight (BRIDGE-M6-03; D-BRIDGE-20; DESIGN-DETAILS 12.2.7): what a share's accepting device runs on its
// own ledger before it files any BridgeAlias, since the server sees no prefix and could not refuse an alias that has
// no room.
//
//	held   the upper /17's host bits that are taken: aliases, a released one until its drain's end; exposed prefixes
//	       of routes in force or draining; host addresses spilled there, live or tombstones
//	size   a target wider than /17 is refused_too_large: aliases live in the upper /17 (§17.4)
//	space  for each target in index order, the first aligned block of its prefix length from the bottom of the upper
//	       /17 that holds no taken bit, a /32 avoiding x.y.z.0 and x.y.z.255; none: refused_no_space with the shortfall
//
// Two targets never share a block, whatever their prefixes in the sharing network: two shares of one 192.168.1.0/24
// get two /24s. The answer is a function of the ledger and the table, so two devices at one pin plan the same
// aliases. What makes two concurrent accepts safe is not the plan but the ledger, which gives a block to the first
// alias in log order (holdAlias), and the accepter's check of its own ledger before it reports active.
//
// An alias is host bits and a length: the accepting network's block is not in it, and a block change keeps it (§17.4).
//
// Pure, and safe for concurrent use: a ledger is immutable once built.

package sidecar

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// A target is wider than the upper /17 (§17.9's size row): accept_status refused_too_large. The preflight's error
	// is a *BridgeShareRefusal, which carries the figures.
	ErrBridgeShareTooLarge = errors.New("bridge share target is wider than the upper /17")
	// The upper /17 has no aligned free block for a target (§17.9's space row): accept_status refused_no_space, a
	// *BridgeShareRefusal too.
	ErrBridgeShareNoSpace = errors.New("bridge share has no room in the upper /17")
	// A target table no accept takes: indexes that are not dense from 0, an id, a key, a prefix or ports out of form.
	ErrBridgeShareTableInvalid = errors.New("bridge share table refused")
)

// A refusal of the preflight, with §17.9's figures, which the accept seals under K for the sharing network: the first
// target that found no room, or was too wide, its prefix length, and the room the upper /17 had. It unwraps to
// ErrBridgeShareTooLarge or ErrBridgeShareNoSpace.
type BridgeShareRefusal struct {
	// ErrBridgeShareTooLarge or ErrBridgeShareNoSpace.
	Reason    error
	Shortfall *bridge.BridgeShareShortfall
}

// The reason alone: the figures are for the sharing network, sealed.
func (self *BridgeShareRefusal) Error() string {
	return fmt.Sprintf("%s: target %d, a /%d", self.Reason.Error(), self.Shortfall.GetIndex(), self.Shortfall.GetLength())
}

// The reason, so errors.Is finds ErrBridgeShareTooLarge or ErrBridgeShareNoSpace.
func (self *BridgeShareRefusal) Unwrap() error {
	return self.Reason
}

// The largest shortfall figure for "no aligned free block of any length" (BridgeShareShortfall.largest_free_length).
const bridgeShareNoFreeLength = 33

// The target table an invite seals and an accept opens, held to its form: indexes dense from 0, each host a
// sidecar_id with its Ed25519 identity key (QD-077), a masked IPv4 prefix, a protocol of 0, 6 or 17, and ports only
// under 6 or 17, each range in order. A length is not judged here: the preflight refuses a wide one as too large. At
// most listMaxCount port ranges a target, the ledger's BodyListMaxCount.
func CheckBridgeShareTargets(targets *bridge.BridgeShareTargets, settings *BridgeLedgerSettings) error {
	read := bridgeLedgerSettingsOrDefault(settings)
	if targets == nil || len(targets.GetTargets()) == 0 {
		return fmt.Errorf("%w: no target", ErrBridgeShareTableInvalid)
	}
	for i, target := range targets.GetTargets() {
		switch {
		case target == nil || target.GetIndex() != uint32(i):
			return fmt.Errorf("%w: target %d is out of its index", ErrBridgeShareTableInvalid, i)
		case len(target.GetHostSidecarId()) != len(Id{}):
			return fmt.Errorf("%w: target %d names no host", ErrBridgeShareTableInvalid, i)
		case len(target.GetHostIdentityPublicKey()) != ed25519.PublicKeySize:
			return fmt.Errorf("%w: target %d carries no host identity key", ErrBridgeShareTableInvalid, i)
		}
		prefix, err := bridgePrefixOf(target.GetPrefix())
		if err != nil {
			return fmt.Errorf("%w: target %d: %w", ErrBridgeShareTableInvalid, i, err)
		}
		if prefix.length == 0 {
			return fmt.Errorf("%w: target %d is every address", ErrBridgeShareTableInvalid, i)
		}
		switch target.GetProtocol() {
		case 0:
			if len(target.GetPorts()) != 0 {
				return fmt.Errorf("%w: target %d names ports of no protocol", ErrBridgeShareTableInvalid, i)
			}
		case bridgeProtocolTcp, bridgeProtocolUdp:
		default:
			return fmt.Errorf("%w: target %d names a protocol with no ports", ErrBridgeShareTableInvalid, i)
		}
		if read.BodyListMaxCount < len(target.GetPorts()) {
			return fmt.Errorf("%w: target %d names %d port ranges", ErrBridgeShareTableInvalid, i, len(target.GetPorts()))
		}
		for _, ports := range target.GetPorts() {
			if ports == nil || ports.GetFirst() == 0 || ports.GetLast() < ports.GetFirst() || 65535 < ports.GetLast() {
				return fmt.Errorf("%w: target %d names a port range out of form", ErrBridgeShareTableInvalid, i)
			}
		}
	}
	return nil
}

// The upper /17's host bits a ledger holds at its time, one flag a host address, from bridgeUpperHostBits.
type bridgeUpperMap struct {
	held []bool
}

// The file's held row over ledger.
func newBridgeUpperMap(ledger *BridgeLedger) *bridgeUpperMap {
	upper := &bridgeUpperMap{held: make([]bool, 0x10000-int(bridgeUpperHostBits))}
	// aliases in force, released ones until their drain's end, and the exposed prefixes of routes in force
	for _, held := range ledger.UpperRanges() {
		upper.hold(held[0], held[1])
	}
	// a route withdrawn to drain keeps its exposed prefix until the drain's end: the ledger frees the block for a
	// new filing at once, and a plan that waits is the narrower of the two
	for _, rule := range ledger.Rules(bridge.SignedType_SIGNED_BRIDGE_ROUTE) {
		if rule.Withdrawn == nil || rule.Route == nil || rule.Route.GetExposedPrefix() == nil {
			continue
		}
		if rule.Withdrawn.Mode != bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN {
			continue
		}
		if rule.Withdrawn.TimeMs+int64(rule.Route.GetDrainSeconds())*1000 <= ledger.TimeMs() {
			continue
		}
		if first, last, err := bridgeUpperRangeOf(rule.Route.GetExposedPrefix()); err == nil {
			upper.hold(first, last)
		}
	}
	// hosts spilled into the upper /17, live or tombstones
	for hostBits := bridgeUpperHostBits; hostBits <= 0xffff; hostBits += 1 {
		if ledger.HostBitsTaken(hostBits) {
			upper.hold(hostBits, hostBits)
		}
	}
	return upper
}

// Marks [first, last], host bits of the upper half, as held.
func (self *bridgeUpperMap) hold(first uint32, last uint32) {
	for hostBits := max(first, bridgeUpperHostBits); hostBits <= min(last, 0xffff); hostBits += 1 {
		self.held[hostBits-bridgeUpperHostBits] = true
	}
}

// Whether [first, last] holds no taken bit.
func (self *bridgeUpperMap) free(first uint32, last uint32) bool {
	for hostBits := first; hostBits <= last; hostBits += 1 {
		if self.held[hostBits-bridgeUpperHostBits] {
			return false
		}
	}
	return true
}

// The first aligned free block of a prefix length, /17 to /32, from the bottom of the upper /17: its first host bits
// and true, or false for none. A /32 is never x.y.z.0 or x.y.z.255.
func (self *bridgeUpperMap) firstFit(length uint32) (uint32, bool) {
	size := uint32(1) << (32 - length)
	for first := bridgeUpperHostBits; first <= 0xffff; first += size {
		if length == 32 && (first&0xff == 0x00 || first&0xff == 0xff) {
			continue
		}
		if self.free(first, first+size-1) {
			return first, true
		}
	}
	return 0, false
}

// How many host addresses of the upper /17 are free.
func (self *bridgeUpperMap) freeCount() uint32 {
	count := uint32(0)
	for _, held := range self.held {
		if !held {
			count += 1
		}
	}
	return count
}

// The shortest prefix length with an aligned free block, bridgeShareNoFreeLength for none.
func (self *bridgeUpperMap) largestFreeLength() uint32 {
	for length := uint32(17); length <= 32; length += 1 {
		if _, ok := self.firstFit(length); ok {
			return length
		}
	}
	return bridgeShareNoFreeLength
}

// Plans a share's aliases on ledger, the accepting network's at this device's tip (the file's comment): one alias a
// target, by index, as the alias table carries them. ErrBridgeShareTableInvalid for a table out of form,
// a *BridgeShareRefusal of ErrBridgeShareTooLarge for a target wider than /17, and one of ErrBridgeShareNoSpace where a
// target finds no block, its figures read with the plan's earlier blocks held, since those are part of what leaves it
// no room.
func BridgeSharePreflight(ledger *BridgeLedger, targets *bridge.BridgeShareTargets) ([]*bridge.BridgeShareAlias, error) {
	if ledger == nil {
		return nil, fmt.Errorf("%w: no ledger to plan on", ErrBridgeShareTableInvalid)
	}
	if err := CheckBridgeShareTargets(targets, ledger.settings); err != nil {
		return nil, err
	}
	upper := newBridgeUpperMap(ledger)
	// size first, so a table that can never fit is refused as too large whatever room there is
	for _, target := range targets.GetTargets() {
		if length := target.GetPrefix().GetLength(); length < 17 {
			return nil, &BridgeShareRefusal{Reason: ErrBridgeShareTooLarge, Shortfall: &bridge.BridgeShareShortfall{
				Index: target.GetIndex(), Length: length, FreeAddressCount: upper.freeCount(), LargestFreeLength: upper.largestFreeLength(),
			}}
		}
	}
	aliases := make([]*bridge.BridgeShareAlias, 0, len(targets.GetTargets()))
	for _, target := range targets.GetTargets() {
		length := target.GetPrefix().GetLength()
		first, ok := upper.firstFit(length)
		if !ok {
			return nil, &BridgeShareRefusal{Reason: ErrBridgeShareNoSpace, Shortfall: &bridge.BridgeShareShortfall{
				Index: target.GetIndex(), Length: length, FreeAddressCount: upper.freeCount(), LargestFreeLength: upper.largestFreeLength(),
			}}
		}
		upper.hold(first, first+(uint32(1)<<(32-length))-1)
		aliases = append(aliases, &bridge.BridgeShareAlias{Index: target.GetIndex(), AliasHostBits: first, Length: length})
	}
	return aliases, nil
}

// The alias table an accept seals, held to its target table: one alias a target, by index, each of its target's
// length, aligned, inside the upper /17, a /32 at neither a .0 nor a .255, and no two overlapping.
func CheckBridgeShareAliases(aliases *bridge.BridgeShareAliases, targets *bridge.BridgeShareTargets) error {
	if aliases == nil || targets == nil || len(aliases.GetAliases()) != len(targets.GetTargets()) {
		return fmt.Errorf("%w: an alias table that is not one alias a target", ErrBridgeShareTableInvalid)
	}
	upper := &bridgeUpperMap{held: make([]bool, 0x10000-int(bridgeUpperHostBits))}
	for i, alias := range aliases.GetAliases() {
		target := targets.GetTargets()[i]
		length := alias.GetLength()
		if alias == nil || alias.GetIndex() != uint32(i) || length != target.GetPrefix().GetLength() || length < 17 || 32 < length {
			return fmt.Errorf("%w: alias %d does not match its target", ErrBridgeShareTableInvalid, i)
		}
		first, size := alias.GetAliasHostBits(), uint32(1)<<(32-length)
		switch {
		case first < bridgeUpperHostBits || 0xffff < first || first%size != 0:
			return fmt.Errorf("%w: alias %d is no aligned block of the upper /17", ErrBridgeShareTableInvalid, i)
		case length == 32 && (first&0xff == 0x00 || first&0xff == 0xff):
			return fmt.Errorf("%w: alias %d is a /32 at a .0 or a .255", ErrBridgeShareTableInvalid, i)
		case !upper.free(first, first+size-1):
			return fmt.Errorf("%w: alias %d overlaps another", ErrBridgeShareTableInvalid, i)
		}
		upper.hold(first, first+size-1)
	}
	return nil
}
