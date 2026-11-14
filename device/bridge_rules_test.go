// ParseBridgeRules against sidecartest's fixture: a full set of rows parses and round-trips, encodes one way, and each
// malformed row, alone, refuses the whole of the rules beside a twin that passes.

package device_test

import (
	"bytes"
	"cmp"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Times in the fixture: a base, and drains after it.
const (
	bridgeRulesTestTimeMs = 1_800_000_000_000
	bridgeRulesTestHourMs = 3_600_000
)

// Every kind of row, once or more: a block draining its predecessor, this host's addresses in both, the sender's
// entries of each kind with HA links, one draining, maps of TCP and ICMP, a remapped subnet and an exit, an untagged
// subject with dial, route and exit rows and a tagged one with two clients, exits, and autogroup:untagged's rows.
func bridgeRulesTestFixture() *sidecartest.BridgeRulesFixture {
	return &sidecartest.BridgeRulesFixture{
		Block:                   "100.80.0.0/16",
		PreviousBlock:           "100.81.0.0/16",
		PreviousBlockDrainUntil: bridgeRulesTestTimeMs + bridgeRulesTestHourMs,
		Addresses:               []string{"100.80.1.2", "100.81.1.2"},
		Entries: []sidecartest.BridgeRulesFixtureEntry{
			{Prefix: "100.80.0.0/16", Kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_UNASSIGNED},
			{Prefix: "100.80.0.0/24", Kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_SERVICE},
			{Prefix: "100.80.7.7/32", Kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_CARVED},
			{Prefix: "100.80.1.3/32", Links: []sidecartest.BridgeRulesFixtureLink{{Target: 3}}},
			{Prefix: "192.0.2.0/24", Links: []sidecartest.BridgeRulesFixtureLink{
				{Target: 4, Route: 1, Weight: 2, Site: "site-a"},
				{Target: 5, Route: 2, Tagged: true, DrainingSince: bridgeRulesTestTimeMs, DrainUntil: bridgeRulesTestTimeMs + 300_000},
			}},
			{Prefix: "100.80.9.0/24", Links: []sidecartest.BridgeRulesFixtureLink{}},
		},
		Maps: []sidecartest.BridgeRulesFixtureMap{
			{Map: 1, Match: "100.80.1.2", Ports: "tcp:5432", Target: "127.0.0.1:5432"},
			{Map: 2, Match: "100.80.1.2", Ports: "tcp:8000-8010", Target: "198.51.100.20:9000", Expires: bridgeRulesTestTimeMs + bridgeRulesTestHourMs},
			{Map: 3, Match: "100.80.1.2", Ports: "icmp", Target: "198.51.100.20:0"},
		},
		Served: []sidecartest.BridgeRulesFixtureServed{
			{Route: 3, Prefix: "198.51.100.0/24", Exposed: "100.80.200.0/24"},
			{Route: 5, Prefix: "203.0.113.0/24", DrainingSince: bridgeRulesTestTimeMs, DrainUntil: bridgeRulesTestTimeMs + 600_000},
			{Route: 4, Exit: true},
		},
		Subjects: []sidecartest.BridgeRulesFixtureSubject{
			{
				Sidecar: 6,
				Dial:    []sidecartest.BridgeRulesFixtureReach{{Ports: "tcp:443"}, {Ports: "icmp"}},
				Route:   []sidecartest.BridgeRulesFixtureReach{{Prefix: "198.51.100.0/24", Ports: "*", Grant: 1, Expires: bridgeRulesTestTimeMs + bridgeRulesTestHourMs}},
				Exit:    []sidecartest.BridgeRulesFixtureReach{{Ports: "*"}},
			},
			{Sidecar: 7, Tagged: true, Clients: []byte{7, 8}, Dial: []sidecartest.BridgeRulesFixtureReach{{Ports: "udp:53,123"}}},
		},
		Egress: &sidecartest.BridgeRulesFixtureEgress{
			Mode:  bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS,
			Exits: []sidecartest.BridgeRulesFixtureLink{{Target: 9, Route: 4}},
		},
		Untagged: &sidecartest.BridgeRulesFixtureUntagged{
			Dial:  []sidecartest.BridgeRulesFixtureReach{{Ports: "tcp:22"}},
			Route: []sidecartest.BridgeRulesFixtureReach{{Prefix: "198.51.100.0/25", Ports: "tcp:443", Grant: 2}},
			Exit:  []sidecartest.BridgeRulesFixtureReach{{Ports: "*", Expires: bridgeRulesTestTimeMs + bridgeRulesTestHourMs}},
		},
	}
}

// A marshal any test here can call without checking an error.
func bridgeRulesTestBytes(t testing.TB, rules *bridge.BridgeRules) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestParseBridgeRulesTakesEveryKindOfRow(t *testing.T) {
	fixture := bridgeRulesTestFixture()
	rules, err := device.ParseBridgeRules(fixture.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.GetEntries()) != 6 || len(rules.GetMaps()) != 3 || len(rules.GetServed()) != 3 ||
		len(rules.GetSubjects()) != 2 || len(rules.GetEgress().GetExits()) != 1 {
		t.Fatalf("parsed %d entries, %d maps, %d served, %d subjects", len(rules.GetEntries()), len(rules.GetMaps()),
			len(rules.GetServed()), len(rules.GetSubjects()))
	}
	untagged := rules.GetUntagged()
	if len(untagged.GetDial()) != 1 || len(untagged.GetRoute()) != 1 || len(untagged.GetExit()) != 1 {
		t.Fatalf("parsed untagged rows %v", untagged)
	}
	// without the field, rules hold no untagged rows
	fixture.Untagged = nil
	rules, err = device.ParseBridgeRules(fixture.Bytes(), nil)
	if err != nil || rules.GetUntagged() != nil {
		t.Fatalf("no field: %v, %v", rules.GetUntagged(), err)
	}
	// and with the field and no rows, an empty set
	fixture.Untagged = &sidecartest.BridgeRulesFixtureUntagged{}
	rules, err = device.ParseBridgeRules(fixture.Bytes(), nil)
	if err != nil || rules.GetUntagged() == nil {
		t.Fatalf("an empty field: %v, %v", rules.GetUntagged(), err)
	}
}

func TestParseBridgeRulesTakesNothing(t *testing.T) {
	rules, err := device.ParseBridgeRules(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rules.GetBlock() != nil || 0 < len(rules.GetEntries()) {
		t.Fatal("empty bytes held rows")
	}
}

func TestBridgeRulesFixtureRoundTrips(t *testing.T) {
	fixture := bridgeRulesTestFixture()
	rules, err := device.ParseBridgeRules(fixture.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(rules, fixture.Rules()) {
		t.Fatal("the parsed rules differ from the literal's")
	}
	if !bytes.Equal(bridgeRulesTestBytes(t, rules), fixture.Bytes()) {
		t.Fatal("the parsed rules re-encode differently")
	}
}

// One literal, one encoding, however many times and in whatever order it is built: a sidecar role's compile is
// byte-equal across runs, so a state's rules change only when the rules do.
func TestBridgeRulesEncodeDeterministically(t *testing.T) {
	first := bridgeRulesTestFixture().Bytes()
	for range 16 {
		if !bytes.Equal(bridgeRulesTestFixture().Bytes(), first) {
			t.Fatal("one literal encoded two ways")
		}
	}
	rules := bridgeRulesTestFixture().Rules()
	// the same rows decoded from an encoding with its fields highest number first, each list in its order, come back
	// to the same bytes
	records := [][]byte{}
	for rest := first; 0 < len(rest); {
		_, _, length := protowire.ConsumeField(rest)
		records = append(records, rest[:length])
		rest = rest[length:]
	}
	slices.SortStableFunc(records, func(a []byte, b []byte) int {
		numberA, _, _ := protowire.ConsumeTag(a)
		numberB, _, _ := protowire.ConsumeTag(b)
		return cmp.Compare(numberB, numberA)
	})
	reordered := bytes.Join(records, nil)
	if bytes.Equal(reordered, first) {
		t.Fatal("the reordering changed nothing, so this proves nothing")
	}
	parsed, err := device.ParseBridgeRules(reordered, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(parsed, rules) || !bytes.Equal(bridgeRulesTestBytes(t, parsed), first) {
		t.Fatal("a reordered encoding decoded to other rules")
	}
}

// Each change below breaks one check, and the fixture it changes passes, so each refusal is that check's alone.
func TestParseBridgeRulesRefusesEachMalformedRow(t *testing.T) {
	if _, err := device.ParseBridgeRules(bridgeRulesTestFixture().Bytes(), nil); err != nil {
		t.Fatalf("the twin itself: %v", err)
	}
	prefix := func(address uint32, length uint32) *bridge.BridgeIpv4Prefix {
		return &bridge.BridgeIpv4Prefix{Address: address, Length: length}
	}
	const (
		block    = 0x64500000 // 100.80.0.0
		previous = 0x64510000 // 100.81.0.0
	)
	link := func(rules *bridge.BridgeRules) *bridge.BridgeRuleLink {
		return rules.Entries[4].Links[0]
	}
	cases := []struct {
		name   string
		mutate func(rules *bridge.BridgeRules)
	}{
		{"block wider than /16", func(rules *bridge.BridgeRules) { rules.Block = prefix(0x64400000, 15) }},
		{"block narrower than /16", func(rules *bridge.BridgeRules) { rules.Block = prefix(block, 17) }},
		{"block with host bits", func(rules *bridge.BridgeRules) { rules.Block = prefix(block|1, 16) }},
		{"block outside the ranges", func(rules *bridge.BridgeRules) { rules.Block = prefix(0xC6330000, 16) }},
		{"block length past 32", func(rules *bridge.BridgeRules) { rules.Block = prefix(block, 33) }},
		{"previous block without a block", func(rules *bridge.BridgeRules) {
			rules.Block = nil
			rules.Addresses = nil
			rules.Entries = nil
			rules.Maps = nil
			rules.Served = rules.Served[2:]
		}},
		{"previous block equal to the block", func(rules *bridge.BridgeRules) { rules.PreviousBlock = prefix(block, 16) }},
		{"previous block outside the ranges", func(rules *bridge.BridgeRules) { rules.PreviousBlock = prefix(0xC6330000, 16) }},
		{"previous block draining to no time", func(rules *bridge.BridgeRules) { rules.PreviousBlockDrainUntil = 0 }},
		{"a drain with no previous block", func(rules *bridge.BridgeRules) {
			rules.PreviousBlock = nil
			rules.Addresses = rules.Addresses[:1]
		}},
		{"address outside every block", func(rules *bridge.BridgeRules) { rules.Addresses[0] = 0xC6336402 }},
		{"address in the services", func(rules *bridge.BridgeRules) { rules.Addresses[0] = block | 0x35 }},
		{"address ending in 0", func(rules *bridge.BridgeRules) { rules.Addresses[0] = block | 0x0100 }},
		{"address ending in 255", func(rules *bridge.BridgeRules) { rules.Addresses[0] = block | 0x01FF }},
		{"address twice", func(rules *bridge.BridgeRules) { rules.Addresses[1] = rules.Addresses[0] }},
		{"entry with no prefix", func(rules *bridge.BridgeRules) { rules.Entries[3].Prefix = nil }},
		{"entry with host bits", func(rules *bridge.BridgeRules) { rules.Entries[4].Prefix = prefix(0xC0000201, 24) }},
		{"entry's prefix twice", func(rules *bridge.BridgeRules) { rules.Entries[5].Prefix = rules.Entries[4].Prefix }},
		{"a host entry in the services", func(rules *bridge.BridgeRules) { rules.Entries[3].Prefix = prefix(block|0x35, 32) }},
		{"a host entry ending in 255", func(rules *bridge.BridgeRules) { rules.Entries[3].Prefix = prefix(block|0x01FF, 32) }},
		{"entry of no kind", func(rules *bridge.BridgeRules) { rules.Entries[3].Kind = 0 }},
		{"entry of an unknown kind", func(rules *bridge.BridgeRules) { rules.Entries[3].Kind = 9 }},
		{"unassigned outside every block", func(rules *bridge.BridgeRules) { rules.Entries[0].Prefix = prefix(0xC0000200, 24) }},
		{"links on an unassigned entry", func(rules *bridge.BridgeRules) {
			rules.Entries[0].Links = []*bridge.BridgeRuleLink{proto.Clone(link(rules)).(*bridge.BridgeRuleLink)}
		}},
		{"carved wider than /32", func(rules *bridge.BridgeRules) { rules.Entries[2].Prefix = prefix(block|0x0700, 24) }},
		{"links on a carved entry", func(rules *bridge.BridgeRules) {
			rules.Entries[2].Links = []*bridge.BridgeRuleLink{proto.Clone(link(rules)).(*bridge.BridgeRuleLink)}
		}},
		{"services other than the block's first /24", func(rules *bridge.BridgeRules) { rules.Entries[1].Prefix = prefix(block|0x0100, 24) }},
		{"link's client id short", func(rules *bridge.BridgeRules) { link(rules).TargetClientId = link(rules).TargetClientId[:15] }},
		{"link's sidecar id missing", func(rules *bridge.BridgeRules) { link(rules).TargetSidecarId = nil }},
		{"link's key short", func(rules *bridge.BridgeRules) {
			link(rules).TargetIdentityPublicKey = link(rules).TargetIdentityPublicKey[:31]
		}},
		{"link's member id short", func(rules *bridge.BridgeRules) { link(rules).TargetMemberId = []byte{1} }},
		{"link's rule id short", func(rules *bridge.BridgeRules) { link(rules).RuleId = link(rules).RuleId[:16] }},
		{"link of weight 0", func(rules *bridge.BridgeRules) { link(rules).Weight = 0 }},
		{"link's pinned client key short", func(rules *bridge.BridgeRules) {
			link(rules).TargetClientPublicKey = bytes.Repeat([]byte{0xC7}, 31)
		}},
		{"link's pinned client key all zero", func(rules *bridge.BridgeRules) {
			link(rules).TargetClientPublicKey = make([]byte, 32)
		}},
		{"link's pinned client key the identity key", func(rules *bridge.BridgeRules) {
			link(rules).TargetClientPublicKey = bytes.Clone(link(rules).TargetIdentityPublicKey)
		}},
		{"link draining backwards", func(rules *bridge.BridgeRules) {
			link(rules).DrainingSince = bridgeRulesTestTimeMs
			link(rules).DrainUntil = bridgeRulesTestTimeMs - 1
		}},
		{"link draining from no time", func(rules *bridge.BridgeRules) { link(rules).DrainUntil = bridgeRulesTestTimeMs }},
		{"link's target twice in an entry", func(rules *bridge.BridgeRules) {
			rules.Entries[4].Links[1].TargetClientId = link(rules).TargetClientId
		}},
		{"map id short", func(rules *bridge.BridgeRules) { rules.Maps[0].MapId = rules.Maps[0].MapId[:16] }},
		{"map id twice", func(rules *bridge.BridgeRules) { rules.Maps[1].MapId = rules.Maps[0].MapId }},
		{"map match outside every block", func(rules *bridge.BridgeRules) { rules.Maps[0].MatchPrefix = prefix(0xC0000202, 32) }},
		{"map match missing", func(rules *bridge.BridgeRules) { rules.Maps[0].MatchPrefix = nil }},
		{"map of no protocol", func(rules *bridge.BridgeRules) { rules.Maps[0].Protocol = 0 }},
		{"map of another protocol", func(rules *bridge.BridgeRules) { rules.Maps[0].Protocol = 47 }},
		{"ports on an ICMP map", func(rules *bridge.BridgeRules) { rules.Maps[2].Ports = rules.Maps[0].Ports }},
		{"map port 0", func(rules *bridge.BridgeRules) { rules.Maps[0].Ports[0].First = 0 }},
		{"map ports backwards", func(rules *bridge.BridgeRules) { rules.Maps[1].Ports[0].Last = 7999 }},
		{"map port past 65535", func(rules *bridge.BridgeRules) { rules.Maps[0].Ports[0].Last = 65536 }},
		{"map target of 5 bytes", func(rules *bridge.BridgeRules) { rules.Maps[0].Target = []byte{127, 0, 0, 1, 0} }},
		{"map target unspecified", func(rules *bridge.BridgeRules) { rules.Maps[0].Target = []byte{0, 0, 0, 0} }},
		{"map target port past 65535", func(rules *bridge.BridgeRules) { rules.Maps[0].TargetPort = 65536 }},
		{"map target port over two ranges", func(rules *bridge.BridgeRules) {
			rules.Maps[1].Ports = append(rules.Maps[1].Ports, &bridge.BridgePortRange{First: 9100, Last: 9100})
		}},
		{"map range mapping past 65535", func(rules *bridge.BridgeRules) { rules.Maps[1].TargetPort = 65530 }},
		{"map expiring before the epoch", func(rules *bridge.BridgeRules) { rules.Maps[0].Expires = -1 }},
		{"map draining backwards", func(rules *bridge.BridgeRules) {
			rules.Maps[0].DrainingSince = bridgeRulesTestTimeMs
			rules.Maps[0].DrainUntil = 1
		}},
		{"served route id short", func(rules *bridge.BridgeRules) { rules.Served[0].RouteId = []byte{1} }},
		{"served with no prefix", func(rules *bridge.BridgeRules) { rules.Served[0].Prefix = nil }},
		{"served of no kind", func(rules *bridge.BridgeRules) { rules.Served[0].Kind = 0 }},
		{"exit other than 0.0.0.0/0", func(rules *bridge.BridgeRules) { rules.Served[2].Prefix = prefix(0xC6336400, 24) }},
		{"exit with a remap", func(rules *bridge.BridgeRules) { rules.Served[2].ExposedPrefix = prefix(block|0xC800, 24) }},
		{"remap of another length", func(rules *bridge.BridgeRules) { rules.Served[0].ExposedPrefix = prefix(block|0xC800, 23) }},
		{"remap outside every block", func(rules *bridge.BridgeRules) { rules.Served[0].ExposedPrefix = prefix(0xCB007100, 24) }},
		{"served route's prefix twice", func(rules *bridge.BridgeRules) {
			rules.Served[1].RouteId = rules.Served[0].RouteId
			rules.Served[1].Prefix = rules.Served[0].Prefix
		}},
		{"served draining backwards", func(rules *bridge.BridgeRules) { rules.Served[1].DrainUntil = 1 }},
		{"subject's sidecar id missing", func(rules *bridge.BridgeRules) { rules.Subjects[0].SidecarId = nil }},
		{"subject twice", func(rules *bridge.BridgeRules) { rules.Subjects[1].SidecarId = rules.Subjects[0].SidecarId }},
		{"subject's member id short", func(rules *bridge.BridgeRules) { rules.Subjects[0].MemberId = []byte{1} }},
		{"tagged subject with a member", func(rules *bridge.BridgeRules) { rules.Subjects[0].Tagged = true }},
		{"subject's client id short", func(rules *bridge.BridgeRules) { rules.Subjects[1].ClientIds[1] = []byte{1} }},
		{"a client bound to two subjects", func(rules *bridge.BridgeRules) {
			rules.Subjects[1].ClientIds[1] = rules.Subjects[0].ClientIds[0]
		}},
		{"a client twice in a subject", func(rules *bridge.BridgeRules) {
			rules.Subjects[1].ClientIds[1] = rules.Subjects[1].ClientIds[0]
		}},
		{"a route row with no prefix", func(rules *bridge.BridgeRules) { rules.Subjects[0].Route[0].Prefix = nil }},
		{"a dial row with a prefix", func(rules *bridge.BridgeRules) { rules.Subjects[0].Dial[0].Prefix = prefix(0xC6336400, 24) }},
		{"an exit row with a prefix", func(rules *bridge.BridgeRules) { rules.Subjects[0].Exit[0].Prefix = prefix(0, 0) }},
		{"ports on every protocol", func(rules *bridge.BridgeRules) { rules.Subjects[0].Exit[0].Ports = rules.Subjects[0].Dial[0].Ports }},
		{"ports on ICMP reach", func(rules *bridge.BridgeRules) { rules.Subjects[0].Dial[1].Ports = rules.Subjects[0].Dial[0].Ports }},
		{"reach of another protocol", func(rules *bridge.BridgeRules) { rules.Subjects[0].Dial[0].Protocol = 132 }},
		{"reach ports backwards", func(rules *bridge.BridgeRules) { rules.Subjects[0].Dial[0].Ports[0].First = 444 }},
		{"reach's grant id short", func(rules *bridge.BridgeRules) { rules.Subjects[0].Route[0].GrantId = []byte{1} }},
		{"reach expiring before the epoch", func(rules *bridge.BridgeRules) { rules.Subjects[0].Dial[0].Expires = -5 }},
		{"egress of no mode", func(rules *bridge.BridgeRules) { rules.Egress.Mode = 0 }},
		{"egress of an unknown mode", func(rules *bridge.BridgeRules) { rules.Egress.Mode = 7 }},
		{"exits under auto", func(rules *bridge.BridgeRules) { rules.Egress.Mode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO }},
		{"exits under none", func(rules *bridge.BridgeRules) { rules.Egress.Mode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE }},
		{"an exit of weight 0", func(rules *bridge.BridgeRules) { rules.Egress.Exits[0].Weight = 0 }},
		{"an exit twice", func(rules *bridge.BridgeRules) {
			rules.Egress.Exits = append(rules.Egress.Exits, proto.Clone(rules.Egress.Exits[0]).(*bridge.BridgeRuleLink))
		}},
		{"untagged rows naming a sidecar", func(rules *bridge.BridgeRules) { rules.Untagged.SidecarId = sidecartest.BridgeFixtureSidecarId(9) }},
		{"untagged rows naming a member", func(rules *bridge.BridgeRules) { rules.Untagged.MemberId = sidecartest.BridgeFixtureMemberId(9) }},
		{"untagged rows naming a client", func(rules *bridge.BridgeRules) {
			clientId := sidecartest.BridgeFixtureClientId(9)
			rules.Untagged.ClientIds = [][]byte{clientId[:]}
		}},
		{"untagged rows tagged", func(rules *bridge.BridgeRules) { rules.Untagged.Tagged = true }},
		{"an untagged route row with no prefix", func(rules *bridge.BridgeRules) { rules.Untagged.Route[0].Prefix = nil }},
		{"an untagged dial row with a prefix", func(rules *bridge.BridgeRules) { rules.Untagged.Dial[0].Prefix = prefix(0xC6336400, 24) }},
		{"ports on an untagged row of every protocol", func(rules *bridge.BridgeRules) {
			rules.Untagged.Exit[0].Ports = rules.Untagged.Dial[0].Ports
		}},
		{"an untagged row's grant id short", func(rules *bridge.BridgeRules) { rules.Untagged.Route[0].GrantId = []byte{2} }},
		{"an untagged row expiring before the epoch", func(rules *bridge.BridgeRules) { rules.Untagged.Exit[0].Expires = -1 }},
	}
	for _, c := range cases {
		rules := bridgeRulesTestFixture().Rules()
		c.mutate(rules)
		_, err := device.ParseBridgeRules(bridgeRulesTestBytes(t, rules), nil)
		if !errors.Is(err, device.ErrBridgeRulesMalformed) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// What the parse refuses before it reads a row: bytes that do not decode, fields it does not know, a known field on
// another wire type, and either bound.
func TestParseBridgeRulesRefusesWhatDoesNotDecode(t *testing.T) {
	encoded := bridgeRulesTestFixture().Bytes()
	unknown := protowire.AppendVarint(protowire.AppendTag(append([]byte{}, encoded...), 99, protowire.VarintType), 1)
	// an unknown field inside a row, which a top-level check would miss
	nestedUnknown := bridgeRulesTestFixture().Rules()
	nestedUnknown.Subjects[0].Dial[0].ProtoReflect().SetUnknown(protoreflect.RawFields(protowire.AppendVarint(protowire.AppendTag(nil, 42, protowire.VarintType), 1)))
	wrongWireType := protowire.AppendVarint(protowire.AppendTag(append([]byte{}, encoded...), 1, protowire.VarintType), 3)
	cases := []struct {
		name     string
		encoded  []byte
		settings *device.BridgeSettings
	}{
		{name: "truncated", encoded: encoded[:len(encoded)-1]},
		{name: "a field it does not know", encoded: unknown},
		{name: "a field it does not know, in a row", encoded: bridgeRulesTestBytes(t, nestedUnknown)},
		{name: "a known field on another wire type", encoded: wrongWireType},
		{name: "past the byte bound", encoded: encoded, settings: func() *device.BridgeSettings {
			settings := device.DefaultBridgeSettings()
			settings.RulesMaxByteCount = len(encoded) - 1
			return settings
		}()},
		{name: "past the field bound", encoded: encoded, settings: func() *device.BridgeSettings {
			settings := device.DefaultBridgeSettings()
			settings.RulesMaxFieldCount = 10
			return settings
		}()},
	}
	for _, c := range cases {
		_, err := device.ParseBridgeRules(c.encoded, c.settings)
		if !errors.Is(err, device.ErrBridgeRulesMalformed) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// Many tiny fields are counted on the wire and refused before any is decoded: address records written one at a
// time, as no compiler writes them, past the field bound.
func TestParseBridgeRulesCountsFieldsBeforeDecoding(t *testing.T) {
	settings := device.DefaultBridgeSettings()
	settings.RulesMaxFieldCount = 1000
	encoded := []byte{}
	for range 1001 {
		encoded = protowire.AppendFixed32(protowire.AppendTag(encoded, 4, protowire.Fixed32Type), 0x64500102)
	}
	_, err := device.ParseBridgeRules(encoded, settings)
	if !errors.Is(err, device.ErrBridgeRulesMalformed) {
		t.Fatalf("1,001 fields under a bound of 1,000: %v", err)
	}
}

// Total and bounded: no input panics, and whatever parses holds no more fields than the bound and comes back to
// itself through an encoding.
func FuzzParseBridgeRules(f *testing.F) {
	fixture := bridgeRulesTestFixture()
	f.Add(fixture.Bytes())
	f.Add([]byte{})
	f.Add(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	small := &sidecartest.BridgeRulesFixture{Block: "10.20.0.0/16", Addresses: []string{"10.20.1.1"}}
	f.Add(small.Bytes())
	// autogroup:untagged's rows alone, and rows that name a sidecar, which are refused
	untagged := &sidecartest.BridgeRulesFixture{Untagged: &sidecartest.BridgeRulesFixtureUntagged{
		Exit: []sidecartest.BridgeRulesFixtureReach{{Ports: "tcp:443", Grant: 1}},
	}}
	f.Add(untagged.Bytes())
	named := untagged.Rules()
	named.Untagged.SidecarId = sidecartest.BridgeFixtureSidecarId(1)
	f.Add(bridgeRulesTestBytes(f, named))
	settings := device.DefaultBridgeSettings()
	settings.RulesMaxByteCount = 64 * 1024
	settings.RulesMaxFieldCount = 4 * 1024
	f.Fuzz(func(t *testing.T, encoded []byte) {
		rules, err := device.ParseBridgeRules(encoded, settings)
		if err != nil {
			if !errors.Is(err, device.ErrBridgeRulesMalformed) {
				t.Fatalf("an error that is no refusal: %v", err)
			}
			return
		}
		if settings.RulesMaxByteCount < len(encoded) {
			t.Fatal("parsed past the byte bound")
		}
		if fieldCount := bridgeRulesTestFieldCount(rules.ProtoReflect()); settings.RulesMaxFieldCount < fieldCount {
			t.Fatalf("parsed %d fields past the bound", fieldCount)
		}
		again, err := device.ParseBridgeRules(bridgeRulesTestBytes(t, rules), settings)
		if err != nil || !proto.Equal(again, rules) {
			t.Fatalf("what parsed did not parse again the same: %v", err)
		}
	})
}

// The fields a message holds at every depth, each element of a list one.
func bridgeRulesTestFieldCount(message protoreflect.Message) int {
	count := 0
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsList():
			list := value.List()
			for i := range list.Len() {
				count += 1
				if field.Message() != nil {
					count += bridgeRulesTestFieldCount(list.Get(i).Message())
				}
			}
		case field.Message() != nil:
			count += 1 + bridgeRulesTestFieldCount(value.Message())
		default:
			count += 1
		}
		return true
	})
	return count
}
