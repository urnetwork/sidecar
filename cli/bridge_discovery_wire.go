// The daemon's wiring of §17.7.1's discovery (owner decision 778): the root's bridge-discovery component beside each
// network's bridge, over the device role's seams the root cannot import (D-SDK-20):
//
//	routes    device.Bridge.DiscoveryRoutes, at each of the bridge's changes
//	reach     device.Bridge.DiscoveryReach, the hook's own verdict, which the host's answers follow per viewer
//	targets   device.Bridge.RouteTargets, which a viewer's checks read
//	view      each change of what the viewer keeps goes to ur tun's resolver (device.Bridge.SetDiscoveryView, §12.9.1)
//	          and, where the platform has one and the person left it on, the advertising proxy, under the names rule
//	          (sidecar.BridgeDiscoveryRegistrations)
//	viewing   while ur tun carries the network, the device can send into the overlay, so it watches (§17.7.1's viewer
//	          row); the tun is also the link a Linux advertising proxy answers on (discovery_proxy_mdns.go); on macOS a
//	          paired network's app VPN component routing its block is a way in too (bridge_discovery_app.go)
//	gather    the platform's gatherer (discovery_gather_*.go), none where it is not built, which gathers nothing
//	filer     the network's BridgeFiler, whose Expose and Close a share files through
//
// Safe for concurrent use.

package main

import (
	"context"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
)

// The platform's gatherer (discovery_gather_*.go), nil where none is built: discovery then gathers nothing, and the
// host publishes nothing but listed entries.
var urDiscoveryGathererOf func(log sidecar.Logger, settings *sidecar.BridgeDiscoverySettings) sidecar.BridgeDiscoveryGatherer

// The platform's advertising proxy (discovery_proxy_*.go) on the tun that carries the network, nil where none runs
// (§17.7.1's advertising proxy rows; Windows' is Later): macOS's registers with mDNSResponder and reads nothing of the
// tun, and Linux's answers on the tun's own link, so it takes none without one.
var urDiscoveryProxyOf func(ctx context.Context, log sidecar.Logger, link urDiscoveryProxyLink) urDiscoveryProxy

// An advertising proxy: registers each instance the viewer keeps on this machine alone.
type urDiscoveryProxy interface {
	// Registers exactly registrations, withdrawing at once what is no longer among them; translated gives an IPv4
	// address's IPv6 one through ur tun's translator, invalid for none (D-BRIDGE-26). Never waits on the platform.
	Set(registrations []*sidecar.BridgeDiscoveryRegistration, translated func(address netip.Addr) netip.Addr)
	// What it holds now, and why it registers nothing where it does not.
	Status() urDiscoveryProxyStatus
	// Withdraws everything and stops.
	Close()
}

// What an advertising proxy holds, as ur bridge devices shows it.
type urDiscoveryProxyStatus = sidecar.BridgeDiscoveryProxyStatus

// One network's discovery.
type urBridgeDiscovery struct {
	ctx       context.Context
	cancel    context.CancelFunc
	bridge    *device.Bridge
	component *sidecar.BridgeDiscoveryComponent
	remove    func()
	log       sidecar.Logger
	// whether ur tun carries the network now
	viewing atomic.Bool

	stateLock sync.Mutex
	// the tun that carries the network, nil while none does, and the proxy on it
	link      urDiscoveryProxyLink
	proxy     urDiscoveryProxy
	proxyLink urDiscoveryProxyLink
}

// A network's discovery over its bridge, its Sidecar, its local policy and its filer, added to the Sidecar.
func newUrBridgeDiscovery(wire *urBridgeWire, running *sidecar.Sidecar, aclLocal func() *sidecar.AclLocalPolicy, filer sidecar.BridgeDiscoveryFiler) (*urBridgeDiscovery, error) {
	ctx, cancel := context.WithCancel(wire.host.ctx)
	self := &urBridgeDiscovery{ctx: ctx, cancel: cancel, bridge: wire.bridge, log: wire.args.Log}
	settings := sidecar.DefaultBridgeDiscoverySettings()
	var gatherer sidecar.BridgeDiscoveryGatherer
	if urDiscoveryGathererOf != nil {
		gatherer = urDiscoveryGathererOf(wire.args.Log, settings)
	}
	identity := running.Identity()
	if identity == nil {
		cancel()
		return nil, errUrBridgeUnwired
	}
	hostLabel := ""
	if hostname, err := os.Hostname(); err == nil {
		hostLabel = sidecar.BridgeDiscoveryHostLabel(hostname)
	}
	component, err := sidecar.NewBridgeDiscoveryComponent(&sidecar.BridgeDiscoveryArgs{
		NetworkId: wire.args.NetworkId,
		SidecarId: identity.SidecarId,
		Routes: func() *sidecar.BridgeDiscoveryRoutes {
			return urDiscoveryRoutesOf(self.bridge.DiscoveryRoutes())
		},
		AddRoutesCallback: self.bridge.AddChangeCallback,
		Reach: func(viewer sidecar.Id, address netip.AddrPort, transport string) bool {
			ipProtocol := connect.IpProtocolTcp
			if transport == "_udp" {
				ipProtocol = connect.IpProtocolUdp
			}
			return self.bridge.DiscoveryReach(connect.Id(viewer), address, ipProtocol)
		},
		ReachGeneration: func() uint64 {
			return self.bridge.EgressHook().PolicyGeneration()
		},
		RouteTargets: func(address netip.Addr) []sidecar.Id {
			targets := []sidecar.Id{}
			for _, target := range self.bridge.RouteTargets(address) {
				targets = append(targets, sidecar.Id(target))
			}
			return targets
		},
		DiscoveryBlock: func() *sidecar.AclDiscoveryBlock {
			if aclLocal == nil {
				return nil
			}
			if local := aclLocal(); local != nil {
				return local.Discovery
			}
			return nil
		},
		HostLabel:   func() string { return hostLabel },
		Gatherer:    gatherer,
		Viewing:     self.viewing.Load,
		OnView:      self.onView,
		Filer:       filer,
		ProxyStatus: self.proxyStatus,
		RoutePorts:  self.bridge.DiscoveryRoutePorts,
		Log:         wire.args.Log,
		Settings:    settings,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	self.component = component
	self.remove, err = running.AddComponent(component)
	if err != nil {
		component.Close()
		cancel()
		return nil, err
	}
	return self, nil
}

// The root's routes from the device role's, nil for none.
func urDiscoveryRoutesOf(routes *device.BridgeDiscoveryRoutes) *sidecar.BridgeDiscoveryRoutes {
	if routes == nil {
		return nil
	}
	converted := &sidecar.BridgeDiscoveryRoutes{
		Blocks:    slices.Clone(routes.Blocks),
		Addresses: slices.Clone(routes.Addresses),
	}
	for _, served := range routes.Served {
		converted.Served = append(converted.Served, sidecar.BridgeDiscoveryServed{Prefix: served.Prefix, Exposed: served.Exposed})
	}
	for _, rule := range routes.Maps {
		transport := "_tcp"
		if rule.Protocol == connect.IpProtocolUdp {
			transport = "_udp"
		}
		converted.Maps = append(converted.Maps, sidecar.BridgeDiscoveryMap{
			Address:    rule.Address,
			Transport:  transport,
			FirstPort:  rule.FirstPort,
			LastPort:   rule.LastPort,
			Target:     rule.Target,
			TargetPort: rule.TargetPort,
		})
	}
	for _, host := range routes.Hosts {
		converted.Hosts = append(converted.Hosts, sidecar.BridgeDiscoveryHost{
			SidecarId: sidecar.Id(host.SidecarId),
			ClientId:  sidecar.Id(host.ClientId),
			MemberId:  sidecar.Id(host.MemberId),
			Prefixes:  slices.Clone(host.Prefixes),
			Name:      host.Name,
		})
	}
	return converted
}

// The viewer's view to ur tun's resolver and the advertising proxy: on the component's goroutine, so neither blocks.
func (self *urBridgeDiscovery) onView(view []*sidecar.BridgeDiscoveryViewInstance) {
	instances := make([]*device.BridgeDiscoveryInstance, 0, len(view))
	for _, instance := range view {
		instances = append(instances, &device.BridgeDiscoveryInstance{
			Name:       instance.Name,
			Service:    instance.Service,
			Subtypes:   instance.Subtypes,
			Port:       instance.Port,
			Txt:        instance.Txt,
			HostLabel:  instance.HostLabel,
			ClientName: instance.HostName,
			Ipv4:       instance.Address,
		})
	}
	if droppedCount := self.bridge.SetDiscoveryView(instances); 0 < droppedCount && self.log != nil {
		self.log.Warningf("[discovery]the resolver left out %d instances", droppedCount)
	}
	self.refreshProxy(view)
}

// Brings the advertising proxy to view: started while the person leaves it on and the device views, its registrations
// under the names rule against what the gatherer finds on this machine; stopped otherwise.
func (self *urBridgeDiscovery) refreshProxy(view []*sidecar.BridgeDiscoveryViewInstance) {
	wanted := urDiscoveryProxyOf != nil && self.viewing.Load() && self.component.ProxyOn()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	// a proxy on a tun that has since gone goes with it
	if self.proxy != nil && (!wanted || self.proxyLink != self.link) {
		self.proxy.Close()
		self.proxy, self.proxyLink = nil, nil
	}
	if !wanted {
		return
	}
	if self.proxy == nil {
		self.proxy = urDiscoveryProxyOf(self.ctx, self.log, self.link)
		if self.proxy == nil {
			return
		}
		self.proxyLink = self.link
	}
	registrations := sidecar.BridgeDiscoveryRegistrations(view, self.component.Gathered(), sidecar.DefaultBridgeDiscoverySettings().Wire.NameByteCount)
	self.proxy.Set(registrations, self.bridge.TranslatedAddress)
}

// What the advertising proxy holds, or why none runs: for ur bridge devices.
func (self *urBridgeDiscovery) proxyStatus() *sidecar.BridgeDiscoveryProxyStatus {
	proxy := func() urDiscoveryProxy {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.proxy
	}()
	switch {
	case proxy != nil:
		status := proxy.Status()
		return &status
	case urDiscoveryProxyOf == nil:
		return &sidecar.BridgeDiscoveryProxyStatus{Note: "no advertising proxy runs on this platform"}
	case !self.component.ProxyOn():
		return &sidecar.BridgeDiscoveryProxyStatus{Note: "off"}
	case !self.viewing.Load():
		return &sidecar.BridgeDiscoveryProxyStatus{Note: "ur tun does not carry this network, so this device watches no host"}
	}
	return &sidecar.BridgeDiscoveryProxyStatus{}
}

// The app's VPN component started or stopped carrying the network (bridge_discovery_app.go): a view through it while
// ur tun does not carry the network, whose own link wins.
func (self *urBridgeDiscovery) setAppViewing(viaApp bool) {
	current := func() urDiscoveryProxyLink {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.link
	}()
	_, throughApp := current.(urAppDiscoveryLink)
	switch {
	case viaApp && current == nil:
		self.setViewing(urAppDiscoveryLink{})
	case !viaApp && throughApp:
		self.setViewing(nil)
	}
}

// ur tun started carrying the network on link, or stopped where link is nil.
func (self *urBridgeDiscovery) setViewing(link urDiscoveryProxyLink) {
	viewing := link != nil
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.link = link
	}()
	if self.viewing.Swap(viewing) != viewing {
		self.component.ViewingChanged()
	}
	// the proxy follows the tun: on a new one with the view as it stands, and off with none
	if viewing {
		self.refreshProxy(self.component.View())
	} else {
		self.refreshProxy(nil)
	}
}

// Takes discovery out of the Sidecar and stops the proxy.
func (self *urBridgeDiscovery) close() {
	if self.remove != nil {
		self.remove()
	}
	self.cancel()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.proxy != nil {
		self.proxy.Close()
		self.proxy = nil
	}
}
