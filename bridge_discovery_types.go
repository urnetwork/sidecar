//go:build !ios_extension && !sidecar_http

// §17.7.1's types (Q-BRIDGE-10; owner decision 778): a host gathers and publishes only the types of the effective list,
// the curated default list with the ACL document's discovery block's allow added and its deny taken away (§8.5), so the
// network is not shown every device's every service; and the port table a listed entry's type comes from where its
// person set none (§17.7.1's listed row). Both are data in the sidecar repo, embedded, so a binary carries the lists it
// was built with, as §12.5's reserved list is.

package sidecar

import (
	_ "embed"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

//go:embed bridge_discovery_types.txt
var bridgeDiscoveryTypesText string

//go:embed bridge_discovery_ports.txt
var bridgeDiscoveryPortsText string

// The default list, sorted, and the port table's TCP ports to their types.
var (
	bridgeDiscoveryDefaultTypes = mustParseBridgeDiscoveryTypes(bridgeDiscoveryTypesText)
	bridgeDiscoveryPortTypes    = mustParseBridgeDiscoveryPorts(bridgeDiscoveryPortsText)
)

// The lines of text that say something: neither blank nor a comment.
func bridgeDiscoveryLines(text string) []string {
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

// The types file as a sorted list, refusing a line that is no type or repeats one.
func parseBridgeDiscoveryTypes(text string) ([]string, error) {
	types := []string{}
	for _, line := range bridgeDiscoveryLines(text) {
		if !protocol.ValidDnsSdServiceType(line) || line != strings.ToLower(line) {
			return nil, fmt.Errorf("bridge_discovery_types.txt: %q is not a lowercase service type", line)
		}
		if slices.Contains(types, line) {
			return nil, fmt.Errorf("bridge_discovery_types.txt: %q repeats", line)
		}
		types = append(types, line)
	}
	slices.Sort(types)
	return types, nil
}

// The types file, which the build carries, so a fault is the build's.
func mustParseBridgeDiscoveryTypes(text string) []string {
	types, err := parseBridgeDiscoveryTypes(text)
	if err != nil {
		panic(err)
	}
	return types
}

// The ports file as TCP ports to types, refusing a line that is no <port>/tcp <type> or repeats a port.
func parseBridgeDiscoveryPorts(text string) (map[uint16]string, error) {
	ports := map[uint16]string{}
	for _, line := range bridgeDiscoveryLines(text) {
		portText, serviceType, found := strings.Cut(line, " ")
		portText, isTcp := strings.CutSuffix(portText, "/tcp")
		port, err := strconv.ParseUint(portText, 10, 16)
		if !found || !isTcp || err != nil || port == 0 || !protocol.ValidDnsSdServiceType(serviceType) ||
			!strings.HasSuffix(serviceType, "."+protocol.DnsSdTransportTcp) {
			return nil, fmt.Errorf("bridge_discovery_ports.txt: %q is not <port>/tcp <type>", line)
		}
		if _, held := ports[uint16(port)]; held {
			return nil, fmt.Errorf("bridge_discovery_ports.txt: port %d repeats", port)
		}
		ports[uint16(port)] = serviceType
	}
	return ports, nil
}

// The ports file, which the build carries, so a fault is the build's.
func mustParseBridgeDiscoveryPorts(text string) map[uint16]string {
	ports, err := parseBridgeDiscoveryPorts(text)
	if err != nil {
		panic(err)
	}
	return ports
}

// The default list, sorted: a copy the caller owns.
func BridgeDiscoveryDefaultTypes() []string {
	return slices.Clone(bridgeDiscoveryDefaultTypes)
}

// The effective list, sorted (§17.7.1's types): the default list with block's allow added and its deny taken away; with
// no block, the default list.
func BridgeDiscoveryEffectiveTypes(block *AclDiscoveryBlock) []string {
	types := slices.Clone(bridgeDiscoveryDefaultTypes)
	if block == nil {
		return types
	}
	for _, allowed := range block.Allow {
		if !slices.Contains(types, allowed) {
			types = append(types, allowed)
		}
	}
	types = slices.DeleteFunc(types, func(serviceType string) bool {
		return slices.Contains(block.Deny, serviceType)
	})
	slices.Sort(types)
	return types
}

// The type a listed entry takes from the port table, TCP alone, empty for a port the table does not name.
func bridgeDiscoveryPortType(ipProtocol string, port uint16) string {
	if ipProtocol != "tcp" {
		return ""
	}
	return bridgeDiscoveryPortTypes[port]
}
