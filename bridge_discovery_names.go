//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The advertising proxy's names (§17.7.1's names row, Q-BRIDGE-11; owner decision 778), which each platform's proxy in
// cli/ registers: a remote instance keeps its own name unless one of that name and type is in view on this machine,
// from its LAN, its own services or another host's answer; then it, and each same-named remote one, takes
// "<name> (<client-name>)", cut to fit NameByteCount; a local instance that appears later takes its name back at the
// next computation, which the proxy runs at each change; and one whose name, type and host label match a local
// instance's is the same device seen on this LAN, and is not registered. A remote instance never passes for a local
// one, and a client that keys on an instance's name finds it unchanged where nothing clashes.

package sidecar

import (
	"slices"
	"strings"
	"unicode/utf8"
)

// One registration the advertising proxy makes for an instance the viewer keeps.
type BridgeDiscoveryRegistration struct {
	Instance *BridgeDiscoveryViewInstance
	// The name it registers under.
	Name string
	// Its target under local.: "<label>.<client-name>", the device's own label under its host's name, which no LAN
	// host holds (§17.7.1's target row).
	Target string
}

// The registrations for view against local, what the gatherer finds on this machine's own links and services, its
// LocalOnly answers left out, since those are the proxy's own. Sorted by type, then name.
func BridgeDiscoveryRegistrations(view []*BridgeDiscoveryViewInstance, local []*BridgeDiscoveryGathered, nameByteCount int) []*BridgeDiscoveryRegistration {
	type key struct {
		name    string
		service string
	}
	localLabels := map[key][]string{}
	for _, gathered := range local {
		if gathered == nil || gathered.LocalOnly {
			continue
		}
		held := key{name: strings.ToLower(gathered.Name), service: strings.ToLower(gathered.Service)}
		localLabels[held] = append(localLabels[held], BridgeDiscoveryHostLabel(gathered.HostName))
	}
	remoteCounts := map[key]int{}
	for _, instance := range view {
		remoteCounts[key{name: strings.ToLower(instance.Name), service: instance.Service}] += 1
	}
	registrations := []*BridgeDiscoveryRegistration{}
	registered := map[key]bool{}
	for _, instance := range view {
		held := key{name: strings.ToLower(instance.Name), service: instance.Service}
		labels, clashesLocal := localLabels[held]
		if clashesLocal && slices.Contains(labels, strings.ToLower(instance.HostLabel)) {
			// the same device, seen on this LAN too
			continue
		}
		name := instance.Name
		if clashesLocal || 1 < remoteCounts[held] {
			name = bridgeDiscoverySuffixedName(instance.Name, instance.HostName, nameByteCount)
		}
		final := key{name: strings.ToLower(name), service: instance.Service}
		if registered[final] {
			continue
		}
		registered[final] = true
		registrations = append(registrations, &BridgeDiscoveryRegistration{
			Instance: instance,
			Name:     name,
			Target:   instance.HostLabel + "." + instance.HostName,
		})
	}
	slices.SortFunc(registrations, func(a *BridgeDiscoveryRegistration, b *BridgeDiscoveryRegistration) int {
		return strings.Compare(a.Instance.Service+"\x00"+a.Name, b.Instance.Service+"\x00"+b.Name)
	})
	return registrations
}

// "<name> (<client-name>)", the name cut at a character so the whole fits byteCount octets.
func bridgeDiscoverySuffixedName(name string, clientName string, byteCount int) string {
	suffix := " (" + clientName + ")"
	for byteCount < len(name)+len(suffix) && name != "" {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	return strings.TrimRight(name, " ") + suffix
}
