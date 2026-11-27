//go:build !ios_extension && !sidecar_http

// The hook's seams (DESIGN-COMPUTE §26.7, §26.8, D-LSTN-6, D-LSTN-10; LSTN-M13-04): what the list hands the device role
// and what a viewer's badges ask of it, since the root may not import device/ (D-SDK-20,
// compute-plan-lstn-reach-in-device, QD-1250).
//
//	ListenersListedSet      the (protocol, port) of every socket and map entry a file lists, neither shared nor
//	                        hidden: the hook's input (§26.7), each with its description and Bonjour type for DESIGN
//	                        §17.7.1's discovery (D-LSTN-11). A host builds its own from the file it writes, a viewer a
//	                        host's from the file it reads, one function for both (ListenersListedSetOf)
//	ListenersHookSink       the device role's listed set in BridgeEgressPolicy: SetListed swaps a whole set in, Remove
//	                        takes ports out at once, closing their listener flows. The publisher (LSTN-M13-10) drives it,
//	                        a removal at once and an addition only once the write that lists it has landed; the daemon
//	                        (LSTN-M13-13) and the apps (LSTN-M13-14) adapt it to device's Bridge.SetListedPorts. With none
//	                        installed the hook lists nothing, and the listeners rule admits no flow
//	ListenersReachFunction  a badge's evaluation of a host's rules for a viewer as the source over the host's listed set:
//	                        device's BridgeListenerReach (LSTN-M13-07), the hook's own code, which cli and the sdk install.
//	                        With none installed no entry reads reachable
//
// Safe for concurrent use: a set is not changed once built.

package sidecar

import (
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A port of the listed set.
type ListenersListedPort struct {
	Protocol protocol.ListenersProtocol
	Port     uint16
}

// One entry of the listed set: its port, and what discovery names it by.
type ListenersListedEntry struct {
	ListenersListedPort
	// the entry's description, the listing device's word
	Description string
	// the Bonjour type its person's label gives, BridgeDiscoveryListedTypeNone, or empty for the port's
	ServiceType string
}

// The listed set (the file's comment), one entry a port, by protocol then port.
type ListenersListedSet struct {
	Entries []*ListenersListedEntry
}

// Two ports' order: protocol, then port.
func listenersListedPortCompare(a ListenersListedPort, b ListenersListedPort) int {
	if a.Protocol != b.Protocol {
		return int(a.Protocol) - int(b.Protocol)
	}
	return int(a.Port) - int(b.Port)
}

// The listed set a file gives: each socket and map entry neither shared nor hidden, one a port, a map's description
// before a socket's on the port it shadows. A withheld file gives none. Labels' types come from types, by port, where
// the host knows them; a viewer's set has none.
func ListenersListedSetOf(file *protocol.ListenersFile, types map[ListenersListedPort]string) *ListenersListedSet {
	set := &ListenersListedSet{Entries: []*ListenersListedEntry{}}
	if file == nil || file.GetWithheld() != protocol.ListenersWithheld_LISTENERS_WITHHELD_UNSPECIFIED {
		return set
	}
	byPort := map[ListenersListedPort]*ListenersListedEntry{}
	for _, entry := range file.GetEntries() {
		kind := entry.GetKind()
		if kind != protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET && kind != protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP {
			continue
		}
		if entry.GetShared() || entry.GetOwnView() != protocol.ListenersOwnView_LISTENERS_OWN_VIEW_UNSPECIFIED {
			continue
		}
		port := ListenersListedPort{Protocol: entry.GetProto(), Port: uint16(entry.GetPort())}
		if held, ok := byPort[port]; ok {
			// a map takes its port's flows before the socket it shadows (rule 1 before rule 3)
			if kind == protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP {
				held.Description = entry.GetDesc()
			}
			continue
		}
		listed := &ListenersListedEntry{ListenersListedPort: port, Description: entry.GetDesc(), ServiceType: types[port]}
		byPort[port] = listed
		set.Entries = append(set.Entries, listed)
	}
	slices.SortFunc(set.Entries, func(a *ListenersListedEntry, b *ListenersListedEntry) int {
		return listenersListedPortCompare(a.ListenersListedPort, b.ListenersListedPort)
	})
	return set
}

// The set's ports, in its order.
func (self *ListenersListedSet) Ports() []ListenersListedPort {
	ports := make([]ListenersListedPort, 0, len(self.Entries))
	for _, entry := range self.Entries {
		ports = append(ports, entry.ListenersListedPort)
	}
	return ports
}

// Whether the set holds a port.
func (self *ListenersListedSet) Holds(proto protocol.ListenersProtocol, port uint16) bool {
	_, found := slices.BinarySearchFunc(self.Entries, ListenersListedPort{Protocol: proto, Port: port},
		func(entry *ListenersListedEntry, target ListenersListedPort) int {
			return listenersListedPortCompare(entry.ListenersListedPort, target)
		})
	return found
}

// The ports this set holds and next does not: what the publisher hands the sink's Remove at once (§26.6's When).
func (self *ListenersListedSet) Removed(next *ListenersListedSet) []ListenersListedPort {
	removed := []ListenersListedPort{}
	for _, entry := range self.Entries {
		if next == nil || !next.Holds(entry.Protocol, entry.Port) {
			removed = append(removed, entry.ListenersListedPort)
		}
	}
	return removed
}

// Whether next adds a port this set does not hold: what waits for the write that lists it.
func (self *ListenersListedSet) Adds(next *ListenersListedSet) bool {
	for _, entry := range next.Entries {
		if !self.Holds(entry.Protocol, entry.Port) {
			return true
		}
	}
	return false
}

// The device role's listed set (the file's comment). Implementations are safe for concurrent use.
type ListenersHookSink interface {
	// Swaps set into the hook whole, under generation, which orders sets: one older than the set in force is dropped.
	SetListed(set *ListenersListedSet, generation uint64) error
	// Takes ports out of the set in force at once, then closes the flows the listeners rule admitted to them, those
	// alone (§17.8's order: the policy swapped, then the flows closed).
	Remove(ports []ListenersListedPort) error
}

// What a badge's evaluation decided: a flow from the viewer to the entry's port, as the host's hook would decide it.
type ListenersReachVerdict int

const (
	// no rule admits the viewer: the network's document has no listeners rule, or an admin narrowed it past this
	// viewer or entry
	ListenersReachBlocked ListenersReachVerdict = iota
	// DESIGN's allow-all, in a network with no document: "no policy"
	ListenersReachAllowAll
	// the listeners rule
	ListenersReachListenersRule
	// a rule of the document naming the host and port: Reach.RuleId names it
	ListenersReachRule
	// a narrower socket shares the port, so the listeners rule admits no flow to it
	ListenersReachShared
)

// A badge's evaluation (D-LSTN-6).
type ListenersReach struct {
	Verdict ListenersReachVerdict
	// the rule a ListenersReachRule names, as the state holds its id
	RuleId []byte
}

// What a badge asks of a host's rules.
type ListenersReachQuery struct {
	// the host's state as this viewer compiled it for the host, its rules naming this viewer's subject alone
	State *bridge.BridgeState
	// the host's listed set, from the host's file
	Listed *ListenersListedSet
	// the viewer, a sidecar of the host's network
	Viewer Id
	// the entry's protocol and port at the host's overlay address
	Protocol protocol.ListenersProtocol
	Port     uint16
	Now      time.Time
}

// The hook's own evaluation (the file's comment). With none installed no entry reads reachable.
type ListenersReachFunction func(query *ListenersReachQuery) ListenersReach
