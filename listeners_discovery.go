//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The listed set as DESIGN §17.7.1's discovery reads it (DESIGN-COMPUTE §26.8, D-LSTN-11; LSTN-M13-04): each socket and
// map entry of the set, by protocol and port, with its description and its label's Bonjour type, what
// BridgeDiscoveryArgs.Listed hands the host's DNS-SD view (bridge_discovery_listed.go). Only the legs discovery runs on
// build this, as they build discovery's files: a ur daemon's. The listeners component's wiring (LSTN-M13-10, M13-13)
// installs it, so a host's Bonjour names follow its listed set: an addition as it is written and a removal at once.

package sidecar

// The set as discovery's listed entries: "tcp" or "udp", the port, the description and the Bonjour type.
func (self *ListenersListedSet) DiscoveryEntries() []*BridgeDiscoveryListedEntry {
	entries := make([]*BridgeDiscoveryListedEntry, 0, len(self.Entries))
	for _, entry := range self.Entries {
		word, ok := listenersProtocolWords[entry.Protocol]
		if !ok {
			continue
		}
		entries = append(entries, &BridgeDiscoveryListedEntry{
			Protocol:    word,
			Port:        entry.Port,
			Description: entry.Description,
			Type:        entry.ServiceType,
		})
	}
	return entries
}
