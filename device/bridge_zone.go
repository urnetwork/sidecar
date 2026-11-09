// §12.9's private names (owner decision 85, Q-BRIDGE-4, C14): <client-name>.<net>.<root> answers a client's overlay
// address from the state's names, on the device, so no query for one leaves it. BridgeZone is a connect.LocalZone: a
// name in the table is owned and answers its address, which the asker turns into an A record and every other query
// type into NODATA, since the overlay has no IPv6 and browsers ask HTTPS as well; every other name passes through. The
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
		addrs: map[string][]netip.Addr{},
		ttl:   uint32(settings.NameTtl / time.Second),
	}
	for _, zone := range nameZones {
		zone = bridgeZoneNormal(zone)
		if zone == "" || bridgeZoneNameMaxByteCount < len(zone) || slices.Contains(self.suffixes, "."+zone) {
			continue
		}
		self.suffixes = append(self.suffixes, "."+zone)
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
		self.addrs[normal] = []netip.Addr{bridgeRuleAddr(names[name])}
	}
	return self
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
// into A or NODATA; any other name is not owned. Callers must not change what it returns.
func (self *BridgeZone) Answer(host string, qtype uint16) (addrs []netip.Addr, ttl uint32, owned bool) {
	host = bridgeZoneNormal(host)
	for _, suffix := range self.suffixes {
		if len(host) <= len(suffix) || !strings.HasSuffix(host, suffix) {
			continue
		}
		if addrs, found := self.addrs[host[:len(host)-len(suffix)]]; found {
			return addrs, self.ttl, true
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
