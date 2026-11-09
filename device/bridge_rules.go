// BridgeState.rules as the device role reads it (§17.8, plan-BRIDGE-small-readings #2): ParseBridgeRules decodes and
// validates a marshalled bridge.BridgeRules once, off the packet path, and everything that builds a table, a pin set
// or a policy from the result reads it without checking again. A malformed row refuses the whole of it rather than
// being skipped, since skipping a row can open what the row narrowed, and so does a field this role does not know.
//
// What a parse holds is bounded before anything is decoded: the bytes by RulesMaxByteCount, and the fields at every
// depth by RulesMaxFieldCount, counted on the wire, since decoding allocates per field.
//
// Errors name the row and the check, never a value (I-13).

package device

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The rules do not parse, or a row breaks one of the checks below.
var ErrBridgeRulesMalformed = errors.New("bridge rules malformed")

// The lengths ids, rule ids and keys take in the rules (§5, §17.8, §8.8).
const (
	bridgeRuleIdByteCount       = 16
	bridgeRuleRuleIdByteCount   = 32
	bridgeRuleGrantIdByteCount  = 32
	bridgeRuleIdentityByteCount = 32
	// §17.4: one IPv4 /16 per network
	bridgeBlockLength = 16
	// §17.4: a block's <block>.0.0/24 holds its services
	bridgeServiceLength = 24
	// the IP protocol numbers a flow through connect's NAT can have
	bridgeProtocolIcmp = 1
	bridgeProtocolTcp  = 6
	bridgeProtocolUdp  = 17
)

// Where a block may lie: 100.64.0.0/10 and RFC 1918 (owner decision 132, D-BRIDGE-16).
var bridgeBlockRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// Decodes and validates a marshalled BridgeRules, BridgeState.rules. Nil settings are the defaults. Empty bytes are
// valid rules with nothing in them: no block, no entries, no reach.
func ParseBridgeRules(encoded []byte, settings *BridgeSettings) (*bridge.BridgeRules, error) {
	if settings == nil {
		settings = DefaultBridgeSettings()
	}
	if settings.RulesMaxByteCount < len(encoded) {
		return nil, fmt.Errorf("%w: %d bytes, past the bound", ErrBridgeRulesMalformed, len(encoded))
	}
	rules := &bridge.BridgeRules{}
	fieldCount := 0
	err := countBridgeRulesFields(encoded, rules.ProtoReflect().Descriptor(), &fieldCount, settings.RulesMaxFieldCount)
	if err != nil {
		return nil, err
	}
	err = proto.Unmarshal(encoded, rules)
	if err != nil {
		return nil, fmt.Errorf("%w: does not decode", ErrBridgeRulesMalformed)
	}
	if bridgeRulesHoldUnknown(rules.ProtoReflect()) {
		return nil, fmt.Errorf("%w: a field this role does not know", ErrBridgeRulesMalformed)
	}
	err = checkBridgeRules(rules)
	if err != nil {
		return nil, err
	}
	return rules, nil
}

// Counts every field record of encoded as message, and of each message it holds, and fails once the count passes
// maxCount or a record does not parse. A record of a message field is read as that message.
func countBridgeRulesFields(encoded []byte, message protoreflect.MessageDescriptor, count *int, maxCount int) error {
	for rest := encoded; 0 < len(rest); {
		number, wireType, tagLength := protowire.ConsumeTag(rest)
		if tagLength < 0 {
			return fmt.Errorf("%w: a field's tag does not parse", ErrBridgeRulesMalformed)
		}
		valueLength := protowire.ConsumeFieldValue(number, wireType, rest[tagLength:])
		if valueLength < 0 {
			return fmt.Errorf("%w: a field's value does not parse", ErrBridgeRulesMalformed)
		}
		*count += 1
		if maxCount < *count {
			return fmt.Errorf("%w: more fields than the bound", ErrBridgeRulesMalformed)
		}
		field := message.Fields().ByNumber(number)
		if field != nil && field.Message() != nil && wireType == protowire.BytesType {
			inner, _ := protowire.ConsumeBytes(rest[tagLength:])
			err := countBridgeRulesFields(inner, field.Message(), count, maxCount)
			if err != nil {
				return err
			}
		}
		rest = rest[tagLength+valueLength:]
	}
	return nil
}

// Whether a message or any message it holds kept bytes it did not know: an unknown field, or a known one on another
// wire type, which protobuf keeps as unknown.
func bridgeRulesHoldUnknown(message protoreflect.Message) bool {
	if 0 < len(message.GetUnknown()) {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Message() == nil {
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := range list.Len() {
				if bridgeRulesHoldUnknown(list.Get(i).Message()) {
					unknown = true
					return false
				}
			}
			return true
		}
		unknown = bridgeRulesHoldUnknown(value.Message())
		return !unknown
	})
	return unknown
}

// An IPv4 address as the rules hold it: its four bytes, most significant first, as BridgeState.names does.
func bridgeRuleAddr(address uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(address >> 24), byte(address >> 16), byte(address >> 8), byte(address)})
}

// A prefix as the rules hold it, and false for none, a length past 32 or host bits set.
func bridgeRulePrefix(prefix *bridge.BridgeIpv4Prefix) (netip.Prefix, bool) {
	if prefix == nil || 32 < prefix.GetLength() {
		return netip.Prefix{}, false
	}
	parsed := netip.PrefixFrom(bridgeRuleAddr(prefix.GetAddress()), int(prefix.GetLength()))
	if parsed.Masked() != parsed {
		return netip.Prefix{}, false
	}
	return parsed, true
}

// Whether outer holds all of inner.
func bridgePrefixCovers(outer netip.Prefix, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// A block's services, <block>.0.0/24 (§17.4).
func bridgeServicePrefix(block netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(block.Addr(), bridgeServiceLength)
}

// The blocks the rules hold, the current one first, and what each check reads of them.
type bridgeRulesBlocks struct {
	blocks []netip.Prefix
}

// The block holding prefix whole, and false for none.
func (self *bridgeRulesBlocks) blockOf(prefix netip.Prefix) (netip.Prefix, bool) {
	for _, block := range self.blocks {
		if bridgePrefixCovers(block, prefix) {
			return block, true
		}
	}
	return netip.Prefix{}, false
}

// Every check, in the order the fields are numbered, so the first fault named is the first a reader meets.
func checkBridgeRules(rules *bridge.BridgeRules) error {
	blocks, err := checkBridgeRulesBlocks(rules)
	if err != nil {
		return err
	}
	err = checkBridgeRulesAddresses(rules, blocks)
	if err != nil {
		return err
	}
	err = checkBridgeRulesEntries(rules, blocks)
	if err != nil {
		return err
	}
	err = checkBridgeRulesMaps(rules, blocks)
	if err != nil {
		return err
	}
	err = checkBridgeRulesServed(rules, blocks)
	if err != nil {
		return err
	}
	err = checkBridgeRulesSubjects(rules)
	if err != nil {
		return err
	}
	return checkBridgeRulesEgress(rules)
}

// A malformed-rules error at a row.
func bridgeRulesFault(row string, format string, arguments ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrBridgeRulesMalformed, row, fmt.Sprintf(format, arguments...))
}

// The block and the previous block: each a /16 of 100.64.0.0/10 or RFC 1918, a previous block only beside a block,
// differing from it and draining until a time.
func checkBridgeRulesBlocks(rules *bridge.BridgeRules) (*bridgeRulesBlocks, error) {
	blocks := &bridgeRulesBlocks{}
	checkBlock := func(row string, prefix *bridge.BridgeIpv4Prefix) (netip.Prefix, error) {
		block, ok := bridgeRulePrefix(prefix)
		if !ok || block.Bits() != bridgeBlockLength {
			return netip.Prefix{}, bridgeRulesFault(row, "not a /16 with no host bits")
		}
		if !slices.ContainsFunc(bridgeBlockRanges, func(allowed netip.Prefix) bool {
			return bridgePrefixCovers(allowed, block)
		}) {
			return netip.Prefix{}, bridgeRulesFault(row, "outside 100.64.0.0/10 and RFC 1918")
		}
		return block, nil
	}
	if rules.GetBlock() != nil {
		block, err := checkBlock("block", rules.GetBlock())
		if err != nil {
			return nil, err
		}
		blocks.blocks = append(blocks.blocks, block)
	}
	if rules.GetPreviousBlock() == nil {
		if rules.GetPreviousBlockDrainUntil() != 0 {
			return nil, bridgeRulesFault("previous_block_drain_until", "set with no previous block")
		}
		return blocks, nil
	}
	if rules.GetBlock() == nil {
		return nil, bridgeRulesFault("previous_block", "set with no block")
	}
	previousBlock, err := checkBlock("previous_block", rules.GetPreviousBlock())
	if err != nil {
		return nil, err
	}
	if previousBlock == blocks.blocks[0] {
		return nil, bridgeRulesFault("previous_block", "the block itself")
	}
	if rules.GetPreviousBlockDrainUntil() <= 0 {
		return nil, bridgeRulesFault("previous_block_drain_until", "not a time")
	}
	blocks.blocks = append(blocks.blocks, previousBlock)
	return blocks, nil
}

// This host's addresses: each a host of a block, outside its services, never x.y.z.0 or x.y.z.255 (§17.4), once.
func checkBridgeRulesAddresses(rules *bridge.BridgeRules, blocks *bridgeRulesBlocks) error {
	seen := map[uint32]bool{}
	for i, address := range rules.GetAddresses() {
		row := fmt.Sprintf("addresses[%d]", i)
		parsed := bridgeRuleAddr(address)
		block, ok := blocks.blockOf(netip.PrefixFrom(parsed, 32))
		if !ok {
			return bridgeRulesFault(row, "in no block")
		}
		if bridgeServicePrefix(block).Contains(parsed) {
			return bridgeRulesFault(row, "in the block's services")
		}
		lastOctet := byte(address)
		if lastOctet == 0 || lastOctet == 255 {
			return bridgeRulesFault(row, "ends in 0 or 255")
		}
		if seen[address] {
			return bridgeRulesFault(row, "repeated")
		}
		seen[address] = true
	}
	return nil
}

// A drain: none at all, or a start and an end no earlier.
func checkBridgeRuleDrain(row string, drainingSince int64, drainUntil int64) error {
	if drainingSince == 0 && drainUntil == 0 {
		return nil
	}
	if drainingSince <= 0 || drainUntil < drainingSince {
		return bridgeRulesFault(row, "a drain that does not run forward")
	}
	return nil
}

// An id field: exactly byteCount bytes, or with optional, none.
func checkBridgeRuleId(row string, name string, id []byte, byteCount int, optional bool) error {
	if optional && len(id) == 0 {
		return nil
	}
	if len(id) != byteCount {
		return bridgeRulesFault(row, "%s is %d bytes", name, len(id))
	}
	return nil
}

// A link: the target's ids and key, a weight of at least 1, and a drain.
func checkBridgeRuleLink(row string, link *bridge.BridgeRuleLink) error {
	checks := []error{
		checkBridgeRuleId(row, "target_client_id", link.GetTargetClientId(), bridgeRuleIdByteCount, false),
		checkBridgeRuleId(row, "target_sidecar_id", link.GetTargetSidecarId(), bridgeRuleIdByteCount, false),
		checkBridgeRuleId(row, "target_identity_public_key", link.GetTargetIdentityPublicKey(), bridgeRuleIdentityByteCount, false),
		checkBridgeRuleId(row, "target_member_id", link.GetTargetMemberId(), bridgeRuleIdByteCount, true),
		checkBridgeRuleId(row, "rule_id", link.GetRuleId(), bridgeRuleRuleIdByteCount, true),
	}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	if link.GetWeight() == 0 {
		return bridgeRulesFault(row, "a weight of 0")
	}
	return checkBridgeRuleDrain(row, link.GetDrainingSince(), link.GetDrainUntil())
}

// Links of one entry or of the egress: each well formed, each target once.
func checkBridgeRuleLinks(row string, links []*bridge.BridgeRuleLink) error {
	targets := map[string]bool{}
	for j, link := range links {
		linkRow := fmt.Sprintf("%s.links[%d]", row, j)
		err := checkBridgeRuleLink(linkRow, link)
		if err != nil {
			return err
		}
		if targets[string(link.GetTargetClientId())] {
			return bridgeRulesFault(linkRow, "a target the entry already has")
		}
		targets[string(link.GetTargetClientId())] = true
	}
	return nil
}

// The sender's entries: one per prefix, each of a known kind, with links only where its kind takes them.
func checkBridgeRulesEntries(rules *bridge.BridgeRules, blocks *bridgeRulesBlocks) error {
	seen := map[netip.Prefix]bool{}
	for i, entry := range rules.GetEntries() {
		row := fmt.Sprintf("entries[%d]", i)
		prefix, ok := bridgeRulePrefix(entry.GetPrefix())
		if !ok {
			return bridgeRulesFault(row, "a prefix that is none, past /32 or with host bits")
		}
		if seen[prefix] {
			return bridgeRulesFault(row, "a prefix another entry has")
		}
		seen[prefix] = true
		switch entry.GetKind() {
		case bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK:
			// in a block, a link entry is a host's /32 or a remapped range, and §17.4 keeps both off its services
			if block, ok := blocks.blockOf(prefix); ok {
				if bridgeServicePrefix(block).Overlaps(prefix) {
					return bridgeRulesFault(row, "a link entry over the block's services")
				}
				if lastOctet := prefix.Addr().As4()[3]; prefix.IsSingleIP() && (lastOctet == 0 || lastOctet == 255) {
					return bridgeRulesFault(row, "a host ending in 0 or 255")
				}
			}
			err := checkBridgeRuleLinks(row, entry.GetLinks())
			if err != nil {
				return err
			}
			continue
		case bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_UNASSIGNED:
			if _, ok := blocks.blockOf(prefix); !ok {
				return bridgeRulesFault(row, "unassigned addresses outside every block")
			}
		case bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_CARVED:
			if !prefix.IsSingleIP() {
				return bridgeRulesFault(row, "a carved prefix wider than /32")
			}
		case bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_SERVICE:
			if !slices.ContainsFunc(blocks.blocks, func(block netip.Prefix) bool {
				return bridgeServicePrefix(block) == prefix
			}) {
				return bridgeRulesFault(row, "services other than a block's first /24")
			}
		default:
			return bridgeRulesFault(row, "kind %d", entry.GetKind())
		}
		if 0 < len(entry.GetLinks()) {
			return bridgeRulesFault(row, "links on an entry whose kind takes none")
		}
	}
	return nil
}

// Port ranges: each 1 to 65535 and running forward.
func checkBridgeRulePorts(row string, ports []*bridge.BridgePortRange) error {
	for j, port := range ports {
		if port.GetFirst() == 0 || port.GetLast() < port.GetFirst() || 65535 < port.GetLast() {
			return bridgeRulesFault(fmt.Sprintf("%s.ports[%d]", row, j), "not a range of ports")
		}
	}
	return nil
}

// This host's maps: a rule id, a match in a block, TCP, UDP or ICMP, ports where the protocol has them, a target
// address, a target port the ports can map by offset, and a drain.
func checkBridgeRulesMaps(rules *bridge.BridgeRules, blocks *bridgeRulesBlocks) error {
	mapIds := map[string]bool{}
	for i, ruleMap := range rules.GetMaps() {
		row := fmt.Sprintf("maps[%d]", i)
		err := checkBridgeRuleId(row, "map_id", ruleMap.GetMapId(), bridgeRuleRuleIdByteCount, false)
		if err != nil {
			return err
		}
		if mapIds[string(ruleMap.GetMapId())] {
			return bridgeRulesFault(row, "a map_id another map has")
		}
		mapIds[string(ruleMap.GetMapId())] = true
		match, ok := bridgeRulePrefix(ruleMap.GetMatchPrefix())
		if !ok {
			return bridgeRulesFault(row, "a match that is none, past /32 or with host bits")
		}
		if _, ok := blocks.blockOf(match); !ok {
			return bridgeRulesFault(row, "a match outside every block")
		}
		switch ruleMap.GetProtocol() {
		case bridgeProtocolTcp, bridgeProtocolUdp:
		case bridgeProtocolIcmp:
			if 0 < len(ruleMap.GetPorts()) || ruleMap.GetTargetPort() != 0 {
				return bridgeRulesFault(row, "ports on an ICMP map")
			}
		default:
			return bridgeRulesFault(row, "protocol %d", ruleMap.GetProtocol())
		}
		err = checkBridgeRulePorts(row, ruleMap.GetPorts())
		if err != nil {
			return err
		}
		target, ok := netip.AddrFromSlice(ruleMap.GetTarget())
		if !ok || !target.IsValid() || target.IsUnspecified() {
			return bridgeRulesFault(row, "a target that is no address")
		}
		if 65535 < ruleMap.GetTargetPort() {
			return bridgeRulesFault(row, "a target port past 65535")
		}
		if ruleMap.GetTargetPort() != 0 {
			// a range maps by offset from its first port, so one range, and room for its last
			if len(ruleMap.GetPorts()) != 1 {
				return bridgeRulesFault(row, "a target port with other than one range")
			}
			port := ruleMap.GetPorts()[0]
			if 65535 < ruleMap.GetTargetPort()+(port.GetLast()-port.GetFirst()) {
				return bridgeRulesFault(row, "a range that maps past 65535")
			}
		}
		if ruleMap.GetExpires() < 0 {
			return bridgeRulesFault(row, "expires before the epoch")
		}
		err = checkBridgeRuleDrain(row, ruleMap.GetDrainingSince(), ruleMap.GetDrainUntil())
		if err != nil {
			return err
		}
	}
	return nil
}

// What this host serves: a subnet, remapped from a range of a block of its own length or not, or an exit's
// 0.0.0.0/0; each route's prefix once.
func checkBridgeRulesServed(rules *bridge.BridgeRules, blocks *bridgeRulesBlocks) error {
	type servedKey struct {
		routeId string
		prefix  netip.Prefix
	}
	seen := map[servedKey]bool{}
	for i, served := range rules.GetServed() {
		row := fmt.Sprintf("served[%d]", i)
		err := checkBridgeRuleId(row, "route_id", served.GetRouteId(), bridgeRuleRuleIdByteCount, false)
		if err != nil {
			return err
		}
		prefix, ok := bridgeRulePrefix(served.GetPrefix())
		if !ok {
			return bridgeRulesFault(row, "a prefix that is none, past /32 or with host bits")
		}
		switch served.GetKind() {
		case bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET:
			if served.GetExposedPrefix() != nil {
				exposed, ok := bridgeRulePrefix(served.GetExposedPrefix())
				if !ok || exposed.Bits() != prefix.Bits() {
					return bridgeRulesFault(row, "an exposed prefix not of the prefix's length")
				}
				if _, ok := blocks.blockOf(exposed); !ok {
					return bridgeRulesFault(row, "an exposed prefix outside every block")
				}
			}
		case bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT:
			if prefix.Bits() != 0 || served.GetExposedPrefix() != nil {
				return bridgeRulesFault(row, "an exit that is not 0.0.0.0/0 as is")
			}
		default:
			return bridgeRulesFault(row, "kind %d", served.GetKind())
		}
		key := servedKey{routeId: string(served.GetRouteId()), prefix: prefix}
		if seen[key] {
			return bridgeRulesFault(row, "a route's prefix twice")
		}
		seen[key] = true
		err = checkBridgeRuleDrain(row, served.GetDrainingSince(), served.GetDrainUntil())
		if err != nil {
			return err
		}
	}
	return nil
}

// One row of reach: a grant id or none, a prefix on route rows alone, a protocol with ports only where it has them,
// and an expiry.
func checkBridgeRuleReach(row string, reach *bridge.BridgeRuleReach, routeRow bool) error {
	err := checkBridgeRuleId(row, "grant_id", reach.GetGrantId(), bridgeRuleGrantIdByteCount, true)
	if err != nil {
		return err
	}
	if routeRow {
		if _, ok := bridgeRulePrefix(reach.GetPrefix()); !ok {
			return bridgeRulesFault(row, "a route row's prefix that is none, past /32 or with host bits")
		}
	} else if reach.GetPrefix() != nil {
		return bridgeRulesFault(row, "a prefix on a row that takes none")
	}
	switch reach.GetProtocol() {
	case bridgeProtocolTcp, bridgeProtocolUdp:
	case 0, bridgeProtocolIcmp:
		if 0 < len(reach.GetPorts()) {
			return bridgeRulesFault(row, "ports on a row of protocol %d", reach.GetProtocol())
		}
	default:
		return bridgeRulesFault(row, "protocol %d", reach.GetProtocol())
	}
	err = checkBridgeRulePorts(row, reach.GetPorts())
	if err != nil {
		return err
	}
	if reach.GetExpires() < 0 {
		return bridgeRulesFault(row, "expires before the epoch")
	}
	return nil
}

// The subjects: each sidecar once, its member id and clients well formed, no client bound to two subjects, since a
// sealed subject resolves through them (plan-BRIDGE-subject-resolution), and each row of reach.
func checkBridgeRulesSubjects(rules *bridge.BridgeRules) error {
	sidecarIds := map[string]bool{}
	clientIds := map[string]bool{}
	for i, subject := range rules.GetSubjects() {
		row := fmt.Sprintf("subjects[%d]", i)
		err := checkBridgeRuleId(row, "sidecar_id", subject.GetSidecarId(), bridgeRuleIdByteCount, false)
		if err != nil {
			return err
		}
		if sidecarIds[string(subject.GetSidecarId())] {
			return bridgeRulesFault(row, "a sidecar_id another subject has")
		}
		sidecarIds[string(subject.GetSidecarId())] = true
		err = checkBridgeRuleId(row, "member_id", subject.GetMemberId(), bridgeRuleIdByteCount, true)
		if err != nil {
			return err
		}
		if subject.GetTagged() && 0 < len(subject.GetMemberId()) {
			return bridgeRulesFault(row, "a member_id on a tagged subject")
		}
		for j, clientId := range subject.GetClientIds() {
			clientRow := fmt.Sprintf("%s.client_ids[%d]", row, j)
			err := checkBridgeRuleId(clientRow, "client_id", clientId, bridgeRuleIdByteCount, false)
			if err != nil {
				return err
			}
			if clientIds[string(clientId)] {
				return bridgeRulesFault(clientRow, "a client bound to another subject or twice")
			}
			clientIds[string(clientId)] = true
		}
		reachRows := []struct {
			name     string
			rows     []*bridge.BridgeRuleReach
			routeRow bool
		}{
			{name: "dial", rows: subject.GetDial()},
			{name: "route", rows: subject.GetRoute(), routeRow: true},
			{name: "exit", rows: subject.GetExit()},
		}
		for _, reachRow := range reachRows {
			for j, reach := range reachRow.rows {
				err := checkBridgeRuleReach(fmt.Sprintf("%s.%s[%d]", row, reachRow.name, j), reach, reachRow.routeRow)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// The egress: a mode, and exits under exits alone.
func checkBridgeRulesEgress(rules *bridge.BridgeRules) error {
	egress := rules.GetEgress()
	if egress == nil {
		return nil
	}
	switch egress.GetMode() {
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS:
		return checkBridgeRuleLinks("egress", egress.GetExits())
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE:
		if 0 < len(egress.GetExits()) {
			return bridgeRulesFault("egress", "exits under a mode that uses none")
		}
		return nil
	default:
		return bridgeRulesFault("egress", "mode %d", egress.GetMode())
	}
}
