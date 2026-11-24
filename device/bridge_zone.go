// §12.9's private names (owner decision 85, Q-BRIDGE-4, C14): <client-name>.<net>.<root> answers a client's overlay
// address from the state's names, on the device, so no query for one leaves it. BridgeZone is a connect.LocalZone: a
// name in the table is owned and answers its address, which the asker turns into an A record and every other query
// type into NODATA, since the overlay has no IPv6 and browsers ask HTTPS as well; §12.9.1's DNS-SD names are owned too
// and answer NODATA on app paths, whose LocalZone carries no record (owner decision 778), while `ur tun`'s resolver
// answers them from the discovery view (bridge_discovery.go); every other name passes through. The
// compiler drops a client name equal to a live published host or record owner (BRIDGE-M4-16), so the zone checks
// nothing more. A zone is immutable, built when the bridge adopts a state, versioned with its rules; Bridge.LocalZone
// hands out a view that reads the newest, so a new state's names take effect at once. Names never reach a log (I-13).
//
// A BridgeZone and the view are safe for concurrent use, and Answer is inline-safe: no lock, and no allocation for a
// host given in lower case without a trailing dot, as connect's mux gives one.

package device

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/connect"
)

// The longest name DNS carries, in the presentation form without its trailing dot.
const bridgeZoneNameMaxByteCount = 253

// A state's private names. See the file's comment.
type BridgeZone struct {
	// each name under a zone, lowercase, to its address
	addrs map[string][]netip.Addr
	// each zone, <net>.<root> and the alias zone where one is chosen, lowercase with a leading dot
	suffixes []string
	ttl      uint32
	// §12.9.1's DNS-SD names (bridge_discovery.go): each zone's labels, in the suffixes' order; the state's blocks,
	// whose reverse zones `ur tun`'s resolver answers; each assigned address's name, the first in byte order; and the
	// TTL of a DNS-SD denial
	zoneLabels   [][]string
	blocks       []netip.Prefix
	reverseNames map[netip.Addr]string
	discoveryTtl uint32
}

var _ connect.LocalZone = (*BridgeZone)(nil)

// A zone of names, BridgeState.names, under nameZones, BridgeState.name_zones. Names and zones match whatever their
// case and a trailing dot; an empty or overlong one is left out. Where two names differ only in case, the first in
// byte order keeps the name. Nil settings are DefaultBridgeSettings.
func NewBridgeZone(names map[string]uint32, nameZones []string, settings *BridgeSettings) *BridgeZone {
	if settings == nil {
		settings = DefaultBridgeSettings()
	}
	self := &BridgeZone{
		addrs:        map[string][]netip.Addr{},
		ttl:          uint32(settings.NameTtl / time.Second),
		reverseNames: map[netip.Addr]string{},
		discoveryTtl: bridgeDiscoveryTtl(settings),
	}
	for _, zone := range nameZones {
		zone = bridgeZoneNormal(zone)
		if zone == "" || bridgeZoneNameMaxByteCount < len(zone) || slices.Contains(self.suffixes, "."+zone) {
			continue
		}
		self.suffixes = append(self.suffixes, "."+zone)
		self.zoneLabels = append(self.zoneLabels, strings.Split(zone, "."))
	}
	nameKeys := make([]string, 0, len(names))
	for name := range names {
		nameKeys = append(nameKeys, name)
	}
	slices.Sort(nameKeys)
	for _, name := range nameKeys {
		normal := bridgeZoneNormal(name)
		if normal == "" || bridgeZoneNameMaxByteCount < len(normal) {
			continue
		}
		if _, held := self.addrs[normal]; held {
			continue
		}
		addr := bridgeRuleAddr(names[name])
		self.addrs[normal] = []netip.Addr{addr}
		if _, held := self.reverseNames[addr]; !held && !strings.Contains(normal, ".") {
			self.reverseNames[addr] = normal
		}
	}
	return self
}

// The zone with blocks, the state's block and the one draining, whose reverse zones `ur tun`'s resolver answers
// (§12.9.1). Called once, before the zone is published.
func (self *BridgeZone) withBlocks(blocks []netip.Prefix) *BridgeZone {
	self.blocks = slices.Clone(blocks)
	return self
}

// Whether name, lowercase with no dot, is a client name the table holds: what a DNS-SD target sits below.
func (self *BridgeZone) clientName(name string) bool {
	_, found := self.addrs[name]
	return found && !strings.Contains(name, ".")
}

// Whether relative, a name below a zone, lowercase with no trailing dot, is of §12.9.1's forms
// (bridge_discovery.go's bridgeDnsSdForm), read from its last two labels without allocating.
func (self *BridgeZone) discoveryForm(relative string) bool {
	lastDot := strings.LastIndexByte(relative, '.')
	if lastDot < 0 {
		return false
	}
	transport := relative[lastDot+1:]
	before := relative[:lastDot]
	last := before[strings.LastIndexByte(before, '.')+1:]
	if last == bridgeDnsSdLabel && transport == bridgeDnsSdUdpLabel {
		return true
	}
	if (transport == bridgeDnsSdTcpLabel || transport == bridgeDnsSdUdpLabel) && strings.HasPrefix(last, "_") &&
		bridgeDnsLdhLabel(last[1:]) {
		return true
	}
	return self.clientName(transport)
}

// A name as the zone keys it: lowercase, with no trailing dot. Allocates only for a name that needs either.
func bridgeZoneNormal(name string) string {
	name = strings.TrimSuffix(name, ".")
	for i := 0; i < len(name); i += 1 {
		if 'A' <= name[i] && name[i] <= 'Z' {
			return strings.ToLower(name)
		}
	}
	return name
}

// connect.LocalZone: a name of the table is owned and answers its address, whatever qtype asks, which the asker turns
// into A or NODATA; a DNS-SD name of §12.9.1's forms is owned with no address, so it answers NODATA, since this
// interface carries addresses alone (owner decision 778); any other name is not owned. Callers must not change what it
// returns.
func (self *BridgeZone) Answer(host string, qtype uint16) (addrs []netip.Addr, ttl uint32, owned bool) {
	host = bridgeZoneNormal(host)
	for _, suffix := range self.suffixes {
		if len(host) <= len(suffix) || !strings.HasSuffix(host, suffix) {
			continue
		}
		relative := host[:len(host)-len(suffix)]
		if addrs, found := self.addrs[relative]; found {
			return addrs, self.ttl, true
		}
		if self.discoveryForm(relative) {
			return nil, self.discoveryTtl, true
		}
	}
	return nil, 0, false
}

// How many names the zone owns.
func (self *BridgeZone) NameCount() int {
	return len(self.addrs)
}

// The bridge's LocalZone: reads the zone of the state in force at each query.
type bridgeZoneView struct {
	bridge *Bridge
}

// connect.LocalZone: the newest state's answer, or not owned with no state.
func (self *bridgeZoneView) Answer(host string, qtype uint16) (addrs []netip.Addr, ttl uint32, owned bool) {
	zone := self.bridge.zone.Load()
	if zone == nil {
		return nil, 0, false
	}
	return zone.Answer(host, qtype)
}

// §18.6's deviceBridge.LocalZone: §12.9's private names from the state in force, for C14's UpgradeMux.SetLocalZone,
// which the sdk passes it to on each change; nil before a state. What it returns reads the newest state's names at each
// query, so a new state's take effect at once, and one that leaves enforcing owns nothing.
func (self *Bridge) LocalZone() connect.LocalZone {
	if self.zone.Load() == nil {
		return nil
	}
	return self.zoneView
}
