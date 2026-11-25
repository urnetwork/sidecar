//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// A ur daemon host as §17.7.1's Discovery Proxy (RFC 8766; owner decision 778): what it publishes from what its
// gatherer found on its links, its listed entries and the LAN devices its person shared, and its answer to each
// viewer's watch, with only the instances its own hook would let that viewer reach.
//
//	own       an instance whose target is this host, its own mDNS announcing it or one of its listed entries: at the
//	          host's overlay address, port unchanged, only while the host holds an address, which discovery never
//	          claims; withheld by `ur bridge discovery off`, a hidden device, or a hide of its protocol and port
//	listed    with DESIGN-COMPUTE.md's listeners (M13a): each socket and map entry the listeners hand in whose type,
//	          its person's or the port table's, is in the effective list, as "<description> :<port>" with an empty TXT
//	          and ListedTtl, none where the host's own mDNS holds that protocol and port (bridge_discovery_listed.go)
//	shared    an instance whose target is a LAN device its person shared: at the address the device's route serves, an
//	          exposed prefix's with the host bits kept, else the device's own; where no route serves it and one of
//	          this host's maps targets it, at the host's overlay address and the map's port (rule 1)
//	never     a device not shared; an address no served prefix or map of this host reaches; a link-local address; IPv6;
//	          an instance found on a point-to-point link, at an overlay, exposed or alias address, or registered
//	          LocalOnly, the advertising proxy's own among them; an instance or entry the hide set holds
//	answer    the published instances whose address, protocol and port the hook passes with the viewer as the source
//	          (BridgeDiscoveryReachFunction, the device role's own code), at most InstanceCount and AnswerByteCount,
//	          truncated past them; at once when the view differs from the viewer's since, else when it changes or at
//	          the hold, at most WatchHoldTimeout
//
// What a watch brought is never here: the host publishes only what its gatherer found on its LAN, its own services and
// its listed entries, so nothing learned from the network goes back into it (§17.7.1's loops row). Names and TXT are
// their host's words and reach no log (I-13).

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// One instance a host's gatherer found on its links (cli's, per platform): its records as the link holds them.
type BridgeDiscoveryGathered struct {
	Name     string
	Service  string
	Subtypes []string
	Port     uint16
	// The TXT record's rdata, whole character-strings.
	Txt []byte
	// The target's mDNS host name, such as "Synthetic-Phone.local.".
	HostName string
	// The target's addresses as the link resolves them.
	Addresses []netip.Addr
	// The target is this host.
	Own bool
	// Found on a point-to-point link, or answered LocalOnly: this machine's own registration, the advertising proxy's
	// among them. Neither is ever published (§17.7.1's loops row).
	PointToPoint bool
	LocalOnly    bool
	// When its records' TTLs end.
	Expires time.Time
}

// Gathers DNS-SD on a host's links (§17.7.1's gather, links and how rows): cli's, mDNSResponder's API on macOS and its
// own querier on Linux and Windows.
type BridgeDiscoveryGatherer interface {
	// Gathers types on each up, multicast-capable link that is not point-to-point, loopback, ur tun's or another tun,
	// until ctx ends, handing report the whole of what it holds at each change. report must not block.
	Gather(ctx context.Context, types []string, report func(gathered []*BridgeDiscoveryGathered))
}

// A subnet this host serves, and where senders reach it.
type BridgeDiscoveryServed struct {
	Prefix netip.Prefix
	// invalid for none
	Exposed netip.Prefix
}

// A map this host holds: Address's ports FirstPort to LastPort reach Target from TargetPort on, by offset, or at the
// same ports where TargetPort is 0. Transport is DnsSdTransportTcp or DnsSdTransportUdp.
type BridgeDiscoveryMap struct {
	Address    netip.Addr
	Transport  string
	FirstPort  uint16
	LastPort   uint16
	Target     netip.Addr
	TargetPort uint16
}

// A host a viewer's links reach (§17.7.1's viewer row), and what it advertises there.
type BridgeDiscoveryHost struct {
	SidecarId Id
	ClientId  Id
	// zero for a tagged host
	MemberId Id
	Prefixes []netip.Prefix
	// its private name, the client name its instances' targets sit below
	Name string
}

// What discovery reads of the device role's state in force (device.BridgeDiscoveryRoutes, which cli converts).
type BridgeDiscoveryRoutes struct {
	// the state's block and the one draining
	Blocks []netip.Prefix
	// this host's overlay addresses, the first its own
	Addresses []netip.Addr
	Served    []BridgeDiscoveryServed
	Maps      []BridgeDiscoveryMap
	Hosts     []BridgeDiscoveryHost
}

// Whether the device role's hook would pass a flow of transport from viewer to address (device.Bridge.DiscoveryReach,
// which cli installs; the root cannot import device/). transport is DnsSdTransportTcp or DnsSdTransportUdp.
type BridgeDiscoveryReachFunction func(viewer Id, address netip.AddrPort, transport string) bool

// One instance a host publishes, with where it stands and what hides it.
type bridgeDiscoveryPublished struct {
	instance *protocol.DnsSdInstance
	address  netip.Addr
	expires  time.Time
}

// What a host publishes now: its instances, sorted by type then name, and its version, which moves with them and with
// the hook's generation, so a viewer holding since hears every change that could change its answer.
type bridgeDiscoveryHostView struct {
	version   uint64
	serving   bool
	published []*bridgeDiscoveryPublished
	// the hook's generation it was taken at, and the digest of what it publishes
	generation uint64
	digest     [sha256.Size]byte
}

// What a host's publishing reads, each taken whole when it changes.
type bridgeDiscoveryHostInput struct {
	routes   *BridgeDiscoveryRoutes
	gathered []*BridgeDiscoveryGathered
	listed   []*BridgeDiscoveryListedEntry
	types    []string
	state    *bridgeDiscoveryState
	// the host's own label, the target its own instances sit below
	hostLabel string
}

// The host's own overlay address, invalid while it holds none: the first of its addresses inside a block.
func (self *BridgeDiscoveryRoutes) hostAddress() netip.Addr {
	if self == nil {
		return netip.Addr{}
	}
	for _, address := range self.Addresses {
		if self.inBlocks(address) {
			return address
		}
	}
	return netip.Addr{}
}

// Whether address lies in one of the state's blocks: an overlay, exposed or alias address.
func (self *BridgeDiscoveryRoutes) inBlocks(address netip.Addr) bool {
	return slices.ContainsFunc(self.Blocks, func(block netip.Prefix) bool { return block.Contains(address) })
}

// The address a LAN device at device is published at, port port of transport (the file's shared row): a served
// prefix's, its exposed prefix's with the host bits kept, else a map's at the host's own address; invalid where none
// reaches it. The port is the one viewers connect to.
func (self *BridgeDiscoveryRoutes) sharedAddress(device netip.Addr, transport string, port uint16) (netip.Addr, uint16) {
	if served := self.servedAddress(device); served.IsValid() {
		return served, port
	}
	for _, rule := range self.Maps {
		if rule.Transport != transport || rule.Target != device || !self.inBlocks(rule.Address) {
			continue
		}
		if rule.TargetPort == 0 {
			if rule.FirstPort <= port && port <= rule.LastPort {
				return rule.Address, port
			}
			continue
		}
		if rule.TargetPort <= port && uint32(port)-uint32(rule.TargetPort) <= uint32(rule.LastPort)-uint32(rule.FirstPort) {
			return rule.Address, rule.FirstPort + (port - rule.TargetPort)
		}
	}
	return netip.Addr{}, 0
}

// The address a served prefix of this host reaches a LAN device at: an exposed prefix's with the host bits kept, else
// the device's own; invalid where no served prefix holds it.
func (self *BridgeDiscoveryRoutes) servedAddress(device netip.Addr) netip.Addr {
	if self == nil {
		return netip.Addr{}
	}
	for _, served := range self.Served {
		if !served.Prefix.Contains(device) {
			continue
		}
		if !served.Exposed.IsValid() {
			return device
		}
		offset := bridgeDiscoveryAddrValue(device) - bridgeDiscoveryAddrValue(served.Prefix.Masked().Addr())
		return bridgeDiscoveryAddrOf(bridgeDiscoveryAddrValue(served.Exposed.Masked().Addr()) + offset)
	}
	return netip.Addr{}
}

// An IPv4 address's value, most significant octet first.
func bridgeDiscoveryAddrValue(address netip.Addr) uint32 {
	return binary.BigEndian.Uint32(address.Unmap().AsSlice())
}

// The IPv4 address of a value.
func bridgeDiscoveryAddrOf(value uint32) netip.Addr {
	var octets [4]byte
	binary.BigEndian.PutUint32(octets[:], value)
	return netip.AddrFrom4(octets)
}

// Whether address may be published for a LAN device: IPv4, never link-local, loopback, multicast or unspecified.
func bridgeDiscoveryLanAddress(address netip.Addr) bool {
	address = address.Unmap()
	return address.Is4() && !address.IsLinkLocalUnicast() && !address.IsLoopback() && !address.IsMulticast() &&
		!address.IsUnspecified()
}

// A host label from an mDNS host name (§17.7.1's target row): its first label, lowercased, as an LDH label, any other
// character a hyphen; empty where nothing of it is left.
func BridgeDiscoveryHostLabel(hostName string) string {
	label, _, _ := strings.Cut(strings.TrimSuffix(hostName, "."), ".")
	out := make([]byte, 0, len(label))
	for _, c := range []byte(strings.ToLower(label)) {
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9':
			out = append(out, c)
		case 0 < len(out) && out[len(out)-1] != '-':
			out = append(out, '-')
		}
	}
	text := strings.Trim(string(out), "-")
	if 63 < len(text) {
		text = strings.TrimRight(text[:63], "-")
	}
	return text
}

// The first address of a gathered instance a LAN device may be published at, invalid for none.
func bridgeDiscoveryDeviceAddress(gathered *BridgeDiscoveryGathered) netip.Addr {
	for _, address := range gathered.Addresses {
		if bridgeDiscoveryLanAddress(address) {
			return address.Unmap()
		}
	}
	return netip.Addr{}
}

// What the host publishes from input at now (the file's rows), sorted by type then name, at most one of a name and type.
func bridgeDiscoveryPublish(input *bridgeDiscoveryHostInput, now time.Time, settings *BridgeDiscoverySettings) []*bridgeDiscoveryPublished {
	routes := input.routes
	state := input.state
	if routes == nil || state == nil {
		return nil
	}
	wire := settings.wire()
	published := []*bridgeDiscoveryPublished{}
	held := map[[2]string]bool{}
	add := func(instance *protocol.DnsSdInstance, address netip.Addr, expires time.Time) {
		key := [2]string{strings.ToLower(instance.GetName()), instance.GetService()}
		if held[key] || !expires.After(now) {
			return
		}
		instance.Ipv4 = bridgeDiscoveryAddrValue(address)
		if protocol.CheckDnsSdInstance(instance, wire) != nil {
			return
		}
		held[key] = true
		published = append(published, &bridgeDiscoveryPublished{instance: instance, address: address, expires: expires})
	}
	inTypes := func(service string) bool {
		_, found := slices.BinarySearch(input.types, service)
		return found
	}
	// a gathered instance at an overlay, exposed or alias address, on a point-to-point link or LocalOnly, is never
	// published, whatever its target
	gatheredFrom := func(gathered *BridgeDiscoveryGathered) bool {
		if gathered.PointToPoint || gathered.LocalOnly || !inTypes(strings.ToLower(gathered.Service)) {
			return false
		}
		return !slices.ContainsFunc(gathered.Addresses, func(address netip.Addr) bool {
			return routes.inBlocks(address.Unmap())
		})
	}
	hostAddress := routes.hostAddress()
	ownOpen := hostAddress.IsValid() && !state.OwnOff && !state.HiddenDevice
	hostLabel := input.hostLabel
	// own instances, their protocols and ports
	ownPorts := map[string]bool{}
	for _, gathered := range input.gathered {
		if !gathered.Own || !gatheredFrom(gathered) {
			continue
		}
		service := strings.ToLower(gathered.Service)
		transport := service[strings.LastIndexByte(service, '.')+1:]
		ownPorts[bridgeDiscoveryPortKey(transport, gathered.Port)] = true
		if !ownOpen || state.hidesPort(transport, gathered.Port) || state.hidesInstance(gathered.Name, service) {
			continue
		}
		label := hostLabel
		if label == "" {
			label = BridgeDiscoveryHostLabel(gathered.HostName)
		}
		add(&protocol.DnsSdInstance{
			Name:      gathered.Name,
			Service:   service,
			Subtypes:  slices.Clone(gathered.Subtypes),
			Port:      uint32(gathered.Port),
			Txt:       slices.Clone(gathered.Txt),
			HostLabel: label,
			Own:       true,
		}, hostAddress, gathered.Expires)
	}
	// listed entries, none where an own instance holds the protocol and port
	if ownOpen && hostLabel != "" {
		for _, instance := range bridgeDiscoveryListedInstances(input.listed, input.types, ownPorts, wire) {
			transport := instance.GetService()[strings.LastIndexByte(instance.GetService(), '.')+1:]
			if state.hidesPort(transport, uint16(instance.GetPort())) || state.hidesInstance(instance.GetName(), instance.GetService()) {
				continue
			}
			instance.HostLabel = hostLabel
			add(instance, hostAddress, now.Add(settings.ListedTtl))
		}
	}
	// shared LAN devices, each at the address its route or a map serves
	for _, gathered := range input.gathered {
		if gathered.Own || !gatheredFrom(gathered) {
			continue
		}
		share := state.share(BridgeDiscoveryHostLabel(gathered.HostName))
		if share == nil || share.State != bridgeDiscoveryShareActive {
			continue
		}
		service := strings.ToLower(gathered.Service)
		if state.hidesInstance(gathered.Name, service) {
			continue
		}
		device := bridgeDiscoveryDeviceAddress(gathered)
		if !device.IsValid() {
			continue
		}
		transport := service[strings.LastIndexByte(service, '.')+1:]
		address, port := routes.sharedAddress(device, transport, gathered.Port)
		if !address.IsValid() {
			continue
		}
		add(&protocol.DnsSdInstance{
			Name:      gathered.Name,
			Service:   service,
			Subtypes:  slices.Clone(gathered.Subtypes),
			Port:      uint32(port),
			Txt:       slices.Clone(gathered.Txt),
			HostLabel: BridgeDiscoveryHostLabel(gathered.HostName),
		}, address, gathered.Expires)
	}
	slices.SortFunc(published, func(a *bridgeDiscoveryPublished, b *bridgeDiscoveryPublished) int {
		return strings.Compare(a.instance.GetService()+"\x00"+a.instance.GetName(), b.instance.GetService()+"\x00"+b.instance.GetName())
	})
	return published
}

// The digest of what a host publishes, for its version: each instance's bytes, its address and its expiry.
func bridgeDiscoveryPublishedDigest(published []*bridgeDiscoveryPublished) [sha256.Size]byte {
	hash := sha256.New()
	for _, item := range published {
		bytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(item.instance)
		var fixed [16]byte
		binary.BigEndian.PutUint64(fixed[0:8], uint64(len(bytes)))
		binary.BigEndian.PutUint64(fixed[8:16], uint64(item.expires.UnixMilli()))
		hash.Write(fixed[:])
		hash.Write(bytes)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

// The host's answer to viewer's watch from view at now (the file's answer row): the instances the hook passes, each
// with its seconds left, at most InstanceCount and AnswerByteCount, truncated past them.
func bridgeDiscoveryAnswer(view *bridgeDiscoveryHostView, viewer Id, reach BridgeDiscoveryReachFunction, now time.Time, wire *protocol.DnsSdWireSettings) *protocol.DnsSdWatchResult {
	result := &protocol.DnsSdWatchResult{}
	if view == nil {
		return result
	}
	result.Version = view.version
	result.Serving = view.serving
	if !view.serving || reach == nil {
		return result
	}
	byteCount := 0
	for _, item := range view.published {
		remaining := item.expires.Sub(now)
		if remaining <= 0 {
			continue
		}
		transport := item.instance.GetService()[strings.LastIndexByte(item.instance.GetService(), '.')+1:]
		if !reach(viewer, netip.AddrPortFrom(item.address, uint16(item.instance.GetPort())), transport) {
			continue
		}
		instance := proto.Clone(item.instance).(*protocol.DnsSdInstance)
		instance.Ttl = uint32(max(1, (remaining+time.Second-1)/time.Second))
		size := proto.Size(instance)
		if wire.InstanceCount <= len(result.Instances) || wire.AnswerByteCount < byteCount+size {
			result.Truncated = true
			break
		}
		byteCount += size
		result.Instances = append(result.Instances, instance)
	}
	return result
}

// A hide's key for a protocol and port at the host's overlay address.
func bridgeDiscoveryPortKey(transport string, port uint16) string {
	return strings.TrimPrefix(transport, "_") + "/" + strconv.Itoa(int(port))
}

// The serving flag a host's view carries: whether it publishes anything at all.
func bridgeDiscoveryServing(published []*bridgeDiscoveryPublished) bool {
	return 0 < len(published)
}

// connect's monitor of the host's view, which the watch handler waits on.
type bridgeDiscoveryHostMonitor = connect.MonitorValue[*bridgeDiscoveryHostView]
