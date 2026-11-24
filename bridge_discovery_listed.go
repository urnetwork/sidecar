//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// Listed entries' Bonjour names (§17.7.1's listed row, D-BRIDGE-27; DESIGN-COMPUTE.md §26.8, D-LSTN-11, Q-LSTN-12;
// owner decisions 770 and 778), the ground DESIGN-COMPUTE.md's listeners build on at M13a: each socket and map entry
// of a ur daemon host's listed set whose type is known and in the effective list becomes an own instance named
// "<description> :<port>", cut to fit NameByteCount, with an empty TXT (RFC 6763 §6.1), at the host's overlay address
// and the entry's port; none where the host's own mDNS already announces that protocol and port; only the host's watch
// answers it, to each viewer by its hook, and the listeners repo never carries it. The type is the one its person set
// (`ur listeners label <port>[/udp] --type <service>|none`, none withholding the entry), else its port's from the
// curated table, TCP alone. Forwards, sock, tls and ssh entries, hidden and shared ones and own-view entries take none:
// the listeners hand in only the listed set's socket and map entries.
//
// The listeners (LSTN) feed BridgeDiscoveryArgs.Listed; until they land nothing is listed and no name is made.

package sidecar

import (
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

// A Bonjour type a label withholds an entry with.
const BridgeDiscoveryListedTypeNone = "none"

// One entry of the host's listed set as discovery reads it: a socket or a map, TCP or UDP.
type BridgeDiscoveryListedEntry struct {
	// "tcp" or "udp"
	Protocol string
	Port     uint16
	// the entry's description: its person's label or its program's name, the host's word
	Description string
	// the Bonjour type its person set: a service type, BridgeDiscoveryListedTypeNone, or empty for the port's
	Type string
}

// The instances entries give (the file's comment), sorted by type then port: each typed entry in types, sorted,
// whose protocol and port ownPorts, the own instances' keys, does not hold. Each has no host label or address yet:
// the host sets them.
func bridgeDiscoveryListedInstances(entries []*BridgeDiscoveryListedEntry, types []string, ownPorts map[string]bool, wire *protocol.DnsSdWireSettings) []*protocol.DnsSdInstance {
	instances := []*protocol.DnsSdInstance{}
	held := map[string]bool{}
	for _, entry := range entries {
		if entry == nil || entry.Port == 0 || (entry.Protocol != "tcp" && entry.Protocol != "udp") {
			continue
		}
		serviceType := entry.Type
		switch serviceType {
		case BridgeDiscoveryListedTypeNone:
			continue
		case "":
			serviceType = bridgeDiscoveryPortType(entry.Protocol, entry.Port)
		}
		serviceType = strings.ToLower(serviceType)
		name, transport, ok := protocol.ParseDnsSdServiceType(serviceType)
		if !ok || name == "" || transport != "_"+entry.Protocol {
			continue
		}
		if _, found := slices.BinarySearch(types, serviceType); !found {
			continue
		}
		portKey := bridgeDiscoveryPortKey(transport, entry.Port)
		if ownPorts[portKey] || held[portKey] {
			continue
		}
		held[portKey] = true
		instances = append(instances, &protocol.DnsSdInstance{
			Name:    bridgeDiscoveryListedName(entry.Description, entry.Port, wire.NameByteCount),
			Service: serviceType,
			Port:    uint32(entry.Port),
			Own:     true,
		})
	}
	slices.SortFunc(instances, func(a *protocol.DnsSdInstance, b *protocol.DnsSdInstance) int {
		if order := strings.Compare(a.GetService(), b.GetService()); order != 0 {
			return order
		}
		return int(a.GetPort()) - int(b.GetPort())
	})
	return instances
}

// "<description> :<port>", the description cut at a character so the whole fits byteCount octets, its control
// characters and marks dropped; ":<port>" alone where nothing of it is left.
func bridgeDiscoveryListedName(description string, port uint16, byteCount int) string {
	suffix := ":" + strconv.Itoa(int(port))
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.TrimSpace(description))
	room := byteCount - len(suffix) - 1
	for room < len(clean) {
		_, size := utf8.DecodeLastRuneInString(clean)
		clean = clean[:len(clean)-size]
	}
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return suffix
	}
	return clean + " " + suffix
}
