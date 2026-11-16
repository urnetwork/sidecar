//go:build windows

// ur tun's device on Windows (§17.10, §17.11; BRIDGE-M6-06): the tun is wireguard's (golang.zx2c4.com/wireguard/tun)
// over Wintun, whose driver comes in wintun.dll, and everything set on it goes through IP Helper from the daemon
// itself, never a spawned netsh or route:
//
//	driver     neither bundled nor fetched (owner decision 222): ur tun looks for wintun.dll beside ur.exe, then in
//	           the installed app's folder, and loads one only once its SHA-256 and its Authenticode signer match the
//	           pins of windows/app/tools/fetch-deps.ps1's Wintun 0.14.1 (urWintunPins, tun_wintun.go), holding the
//	           file against writes from the check through the load, since ur tun runs elevated and an unchecked DLL
//	           there is a way into the system; else it says where to get one. fetch-deps.ps1 pins the release zip's
//	           hash, which a host cannot check, so each architecture's pin is the hash of its DLL in that zip, amd64's
//	           and arm64's (QD-823); an architecture with none loads no DLL, the closed direction
//	device     the adapter ur-<instance>, its MTU the settings'; creating one takes an elevated daemon, refused clearly
//	           otherwise
//	addresses  this host's overlay /32s on the adapter (CreateUnicastIpAddressEntry)
//	routes     each of Bridge.Routes() on the adapter, on link (CreateIpForwardEntry2); a prefix another interface's
//	           route holds keeps it, counted, since Windows would otherwise choose between them by metric
//	resolver   bridge_dns_windows.go's
//	local      bridge_local_windows.go's
//	exits      under the egress mode exits, IPv4's two halves on the adapter (urTunExitsHalves), each more specific
//	           than the host's own default route, which stays. connect's sockets are bound to that route's interface
//	           first (IP_UNICAST_IF, connect.SetEgressInterfaceIndex, connect/egress_windows.go), as
//	           egress_dial_sites_test.go pins at every dial site connect makes, so the daemon's own transport keeps the
//	           host's route; its transports dial again, and each sync binds them to the default route's interface
//	           again where it moved. The halves come off first and the binding last
//	carved     under exits, a host route for each IPv4 address the bridge carves that the host's own table reaches
//	           only by its default route, an off-link resolver above all, by that route's next hop on its adapter
//	           (tun_host_routes.go; QD-869; CreateIpForwardEntry2), as WireGuard for Windows routes an endpoint's /32.
//	           They go on before the halves, follow each SetCarved and the default route where it moves, and come off
//	           once no half is left
//
// Only what this interface added is removed. Close takes the exits and the carved addresses' host routes off, reverts
// the resolver, removes the routes and addresses and closes the adapter, which Wintun deletes with whatever was left
// on it. A host route sits on another adapter, so one a daemon that died left stays until the host restarts or a
// person removes it: it reads as another program's route, which ur tun leaves alone.

package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"github.com/urnetwork/connect"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/urnetwork/sidecar"
)

func init() {
	urTunPlatform = newUrTunWindowsSystem
}

// What a daemon that is not elevated reads: the right it lacks and the way to it.
const urTunWindowsPrivilegeText = "ur tun on Windows needs an elevated daemon, since only an administrator may create " +
	"its adapter: stop this daemon and run ur daemon from a terminal opened as administrator. ur bridge works " +
	"without a tun over the userspace stack"

// The installed app's folder under Program Files, which carries wintun.dll beside its service.
const urWintunAppFolderName = "URnetwork"

// The driver's file name, as wireguard's tun loads it.
const urWintunDllName = "wintun.dll"

// Why ur tun on Windows refuses or holds.
var (
	// No wintun.dll is where ur tun looks.
	errUrWintunMissing = errors.New("ur tun on Windows needs Wintun 0.14.1's wintun.dll, signed by WireGuard LLC, " +
		"which ur neither bundles nor fetches: install the URnetwork app, which carries it, or put the one from " +
		"https://www.wintun.net/builds/wintun-0.14.1.zip for this machine's architecture beside ur.exe")
	// No default route leaves by another interface, so the daemon's own transport would have no way out.
	errUrTunWindowsExitsNoDefault = errors.New("no default route leaves this host by another interface for the " +
		"daemon's own transport to keep")
	// Another program's route holds one of IPv4's halves, as another VPN's does.
	errUrTunWindowsExitsHalfInUse = errors.New("another program's route holds half of IPv4's space, as another VPN's does")
	// A call of IP Helper's that this Windows does not have.
	errUrTunWindowsCallMissing = errors.New("an IP Helper call is missing from this Windows")
)

// What ur tun asks of IP Helper and the adapters, a test's recorder standing in for it.
type urTunWindowsIpHelper interface {
	// Adds or removes an IPv4 /32 on the adapter luid. Adding one already there answers ERROR_OBJECT_ALREADY_EXISTS,
	// removing one that is not ERROR_NOT_FOUND.
	AddAddress(luid uint64, address netip.Addr) error
	DeleteAddress(luid uint64, address netip.Addr) error
	// Adds or removes an IPv4 route on link through the adapter luid, at metric.
	AddRoute(luid uint64, prefix netip.Prefix, metric uint32) error
	DeleteRoute(luid uint64, prefix netip.Prefix) error
	// Adds or removes the IPv4 host route of address by nextHop through the adapter luid, at metric, or on link
	// through that adapter where nextHop is not valid. Adding one already there answers
	// ERROR_OBJECT_ALREADY_EXISTS, removing one that is not ERROR_NOT_FOUND.
	AddHostRoute(luid uint64, address netip.Addr, nextHop netip.Addr, metric uint32) error
	DeleteHostRoute(luid uint64, address netip.Addr, nextHop netip.Addr) error
	// Every route of both families.
	Routes() ([]urTunWindowsRoute, error)
	// Every adapter, with its addresses, gateways and resolvers.
	Adapters() ([]urTunWindowsAdapter, error)
	// Sets the IPv4 MTU of the adapter luid, which TCP takes its segment size from.
	SetMtu(luid uint64, mtu int) error
}

// One route of the table.
type urTunWindowsRoute struct {
	dst      netip.Prefix
	luid     uint64
	index    uint32
	nextHop  netip.Addr
	metric   uint32
	protocol uint32
	loopback bool
}

// One adapter.
type urTunWindowsAdapter struct {
	luid   uint64
	name   string
	index4 uint32
	index6 uint32
	// the interface metrics, which a route's own adds to
	metric4   uint32
	metric6   uint32
	addresses []netip.Addr
	gateways  []netip.Addr
	resolvers []netip.Addr
}

// What ur tun asks of the resolver's policy table, a test's recorder standing in for it (bridge_dns_windows.go).
type urTunWindowsResolver interface {
	// Points zones at resolver under the rule named rule, replacing what the rule held. "" when the resolver took it,
	// else the step a person takes.
	Set(rule string, resolver netip.Addr, zones []string) (string, error)
	// Removes the rule.
	Remove(rule string) error
}

// The platform's half of ur tun on Windows. Safe for concurrent use.
type urTunWindowsSystem struct {
	settings *urTunSettings
	log      sidecar.Logger
	pins     *urWintunPins

	// What ur tun reaches of the host, Windows' and connect's own outside a test: IP Helper and the adapters, the
	// resolver's policy table, the driver's load and an adapter's creation, connect's egress binding, and connect's
	// network-change kick, which has the daemon's transports dial again on bound sockets.
	ipHelper           urTunWindowsIpHelper
	resolver           urTunWindowsResolver
	loadDriver         func() error
	create             func(name string, mtu int) (tun.Device, error)
	setEgressInterface func(index4 uint32, index6 uint32)
	networkChanged     func()
}

var _ urTunSystem = (*urTunWindowsSystem)(nil)

func newUrTunWindowsSystem(settings *urTunSettings, log sidecar.Logger) urTunSystem {
	if settings == nil {
		settings = defaultUrTunSettings()
	}
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	pins := defaultUrWintunPins()
	return &urTunWindowsSystem{
		settings: settings,
		log:      log,
		pins:     pins,
		ipHelper: &urTunWindowsIphlpapi{settings: settings},
		resolver: &urTunWindowsNrpt{settings: settings},
		loadDriver: func() error {
			return urWintunLoad(pins, urWintunCandidates())
		},
		create:             urTunWindowsCreate,
		setEgressInterface: connect.SetEgressInterfaceIndex,
		networkChanged:     connect.NetworkChanged,
	}
}

// The tunnel type Wintun records for the adapter, which Windows shows as its description.
const urWintunTunnelType = "URnetwork"

// The domain of an adapter's GUID hash.
const urTunWindowsGuidDomain = "urnetwork-sidecar-v1/wintun-adapter/"

// The adapter name with mtu, under a GUID derived from its name, so Windows keeps one network profile for it from one
// start to the next. The daemon opens one at a time.
func urTunWindowsCreate(name string, mtu int) (tun.Device, error) {
	tun.WintunTunnelType = urWintunTunnelType
	digest := sha256.Sum256([]byte(urTunWindowsGuidDomain + name))
	guid := &windows.GUID{
		Data1: binary.LittleEndian.Uint32(digest[0:4]),
		Data2: binary.LittleEndian.Uint16(digest[4:6]),
		Data3: binary.LittleEndian.Uint16(digest[6:8]),
		Data4: [8]byte(digest[8:16]),
	}
	return tun.CreateTUNWithRequestedGUID(name, guid, mtu)
}

// What a host answers that refuses the daemon the adapter, as the person reads it.
func urTunWindowsError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windows.ERROR_ACCESS_DENIED), errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD):
		return &urTunPrivilegeError{text: urTunWindowsPrivilegeText, err: err}
	}
	return err
}

// Loads the driver, then opens the adapter name with mtu.
func (self *urTunWindowsSystem) Open(name string, mtu int) (urTunInterface, error) {
	if err := self.loadDriver(); err != nil {
		return nil, err
	}
	device, err := self.create(name, mtu)
	if err != nil {
		return nil, urTunWindowsError(err)
	}
	identified, ok := device.(interface{ LUID() uint64 })
	if !ok || identified.LUID() == 0 {
		device.Close()
		return nil, errors.New("the adapter has no interface luid")
	}
	iface := &urTunWindowsInterface{
		system:     self,
		name:       name,
		luid:       identified.LUID(),
		device:     device,
		eventsDone: make(chan struct{}),
	}
	// wireguard's adapter queues its events for a reader that never comes otherwise
	go func() {
		defer close(iface.eventsDone)
		for range device.Events() {
		}
	}()
	if err := self.ipHelper.SetMtu(iface.luid, mtu); err != nil {
		iface.Close()
		return nil, fmt.Errorf("the adapter's MTU did not set (%w)", urTunWindowsError(err))
	}
	return iface, nil
}

// The adapter named name, nil for none.
func (self *urTunWindowsSystem) adapterNamed(adapters []urTunWindowsAdapter, name string) *urTunWindowsAdapter {
	for i := range adapters {
		if adapters[i].name == name {
			return &adapters[i]
		}
	}
	return nil
}

// The interface other than name with a route inside prefix, "" for none: an app's bridge holding the block. A route
// that covers the whole prefix from outside it, as a carrier's 100.64/10 does, is no bridge's and does not count, nor
// does a local address's own host route, a broadcast's or loopback's.
func (self *urTunWindowsSystem) RoutedElsewhere(name string, prefix netip.Prefix) (string, error) {
	adapters, err := self.ipHelper.Adapters()
	if err != nil {
		return "", err
	}
	var ownLuid uint64
	if own := self.adapterNamed(adapters, name); own != nil {
		ownLuid = own.luid
	}
	routes, err := self.ipHelper.Routes()
	if err != nil {
		return "", err
	}
	for _, held := range routes {
		if !held.dst.IsValid() || !held.dst.Addr().Is4() || held.dst.Bits() < prefix.Bits() ||
			!prefix.Contains(held.dst.Addr()) || held.luid == ownLuid || held.loopback ||
			(held.protocol == windows.MIB_IPPROTO_LOCAL && held.dst.IsSingleIP()) {
			continue
		}
		for _, adapter := range adapters {
			if adapter.luid == held.luid {
				return adapter.name, nil
			}
		}
		return fmt.Sprintf("luid %#x", held.luid), nil
	}
	return "", nil
}

// The host's own default route of a family in table, IPv4's or IPv6's, other than ownLuid's, and its adapter's
// interface index for that family: the one whose route and interface metrics add up least, as Windows chooses; index 0
// for a family with none.
func urTunWindowsDefaultRoute(table []urTunWindowsRoute, adapters []urTunWindowsAdapter, ownLuid uint64,
	ipv4 bool) (urTunWindowsRoute, uint32) {
	var best urTunWindowsRoute
	var bestIndex uint32
	bestMetric := uint64(0)
	for _, held := range table {
		if !held.dst.IsValid() || held.dst.Bits() != 0 || held.dst.Addr().Is4() != ipv4 || held.luid == ownLuid ||
			held.loopback {
			continue
		}
		for _, adapter := range adapters {
			if adapter.luid != held.luid {
				continue
			}
			index, interfaceMetric := adapter.index4, adapter.metric4
			if !ipv4 {
				index, interfaceMetric = adapter.index6, adapter.metric6
			}
			metric := uint64(held.metric) + uint64(interfaceMetric)
			if index != 0 && (bestIndex == 0 || metric < bestMetric) {
				best, bestIndex, bestMetric = held, index, metric
			}
		}
	}
	return best, bestIndex
}

// The host routes the carved addresses take over table, the host's routes (urTunHostRoutes): by the next hop and
// adapter of the IPv4 default route Windows chooses other than ownLuid's, on link through that adapter where the route
// names no next hop, none where there is no such route. An address is reached where a route other than a default one
// holds it, but a route on ownLuid, which is the tun's, a half among them, and, for an address of onRoutes, its own
// host route, which this interface put on.
func urTunWindowsHostRoutes(carvedAddrs []netip.Addr, table []urTunWindowsRoute, adapters []urTunWindowsAdapter,
	ownLuid uint64, ownRoutes []netip.Prefix, onRoutes []urTunHostRoute) []urTunHostRoute {
	defaultRoute, index := urTunWindowsDefaultRoute(table, adapters, ownLuid, true)
	if index == 0 {
		return []urTunHostRoute{}
	}
	gateway := defaultRoute.nextHop
	if !gateway.Is4() || gateway.IsUnspecified() {
		gateway = netip.Addr{}
	}
	reached := func(address netip.Addr) bool {
		ownHostRoute := slices.ContainsFunc(onRoutes, func(on urTunHostRoute) bool { return on.address == address })
		return slices.ContainsFunc(table, func(held urTunWindowsRoute) bool {
			if !held.dst.IsValid() || held.dst.Bits() == 0 || !held.dst.Contains(address) || held.luid == ownLuid {
				return false
			}
			return !(ownHostRoute && held.dst.IsSingleIP())
		})
	}
	return urTunHostRoutes(carvedAddrs, gateway, defaultRoute.luid, ownRoutes, reached)
}

// IP Helper's calls.
type urTunWindowsIphlpapi struct {
	settings *urTunSettings
}

var _ urTunWindowsIpHelper = (*urTunWindowsIphlpapi)(nil)

// The calls x/sys/windows does not wrap, from iphlpapi.dll in System32.
var (
	urTunWindowsIphlpapiDll              = windows.NewLazySystemDLL("iphlpapi.dll")
	urTunWindowsInitializeUnicastAddress = urTunWindowsIphlpapiDll.NewProc("InitializeUnicastIpAddressEntry")
	urTunWindowsCreateUnicastAddress     = urTunWindowsIphlpapiDll.NewProc("CreateUnicastIpAddressEntry")
	urTunWindowsDeleteUnicastAddress     = urTunWindowsIphlpapiDll.NewProc("DeleteUnicastIpAddressEntry")
	urTunWindowsInitializeForwardEntry   = urTunWindowsIphlpapiDll.NewProc("InitializeIpForwardEntry")
	urTunWindowsCreateForwardEntry       = urTunWindowsIphlpapiDll.NewProc("CreateIpForwardEntry2")
	urTunWindowsDeleteForwardEntry       = urTunWindowsIphlpapiDll.NewProc("DeleteIpForwardEntry2")
	urTunWindowsSetIpInterfaceEntry      = urTunWindowsIphlpapiDll.NewProc("SetIpInterfaceEntry")
)

// Calls proc with row, answering its NETIO_STATUS as an error. A proc this Windows lacks is an error, not a panic.
func urTunWindowsNetio(proc *windows.LazyProc, row unsafe.Pointer) error {
	if err := proc.Find(); err != nil {
		return fmt.Errorf("%w: %v", errUrTunWindowsCallMissing, err)
	}
	status, _, _ := proc.Call(uintptr(row))
	if status != 0 {
		return windows.Errno(status)
	}
	return nil
}

// address into a SOCKADDR_INET.
func urTunWindowsSetSockaddr(raw *windows.RawSockaddrInet, address netip.Addr) {
	*raw = windows.RawSockaddrInet{}
	if address.Is4() {
		raw4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(raw))
		raw4.Family = windows.AF_INET
		raw4.Addr = address.As4()
		return
	}
	raw6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(raw))
	raw6.Family = windows.AF_INET6
	raw6.Addr = address.As16()
}

// A SOCKADDR_INET's address, invalid for another family.
func urTunWindowsSockaddrAddr(raw *windows.RawSockaddrInet) netip.Addr {
	switch raw.Family {
	case windows.AF_INET:
		return netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(raw)).Addr)
	case windows.AF_INET6:
		return netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(raw)).Addr)
	}
	return netip.Addr{}
}

// The unicast address row of an IPv4 /32 on luid, initialized as IP Helper's defaults have it.
func urTunWindowsAddressRow(luid uint64, address netip.Addr) (*windows.MibUnicastIpAddressRow, error) {
	row := &windows.MibUnicastIpAddressRow{}
	if err := urTunWindowsInitializeUnicastAddress.Find(); err != nil {
		return nil, fmt.Errorf("%w: %v", errUrTunWindowsCallMissing, err)
	}
	urTunWindowsInitializeUnicastAddress.Call(uintptr(unsafe.Pointer(row)))
	row.InterfaceLuid = luid
	urTunWindowsSetSockaddr((*windows.RawSockaddrInet)(unsafe.Pointer(&row.Address)), address)
	row.OnLinkPrefixLength = 32
	row.DadState = windows.IpDadStatePreferred
	return row, nil
}

func (self *urTunWindowsIphlpapi) AddAddress(luid uint64, address netip.Addr) error {
	row, err := urTunWindowsAddressRow(luid, address)
	if err != nil {
		return err
	}
	return urTunWindowsNetio(urTunWindowsCreateUnicastAddress, unsafe.Pointer(row))
}

func (self *urTunWindowsIphlpapi) DeleteAddress(luid uint64, address netip.Addr) error {
	row, err := urTunWindowsAddressRow(luid, address)
	if err != nil {
		return err
	}
	return urTunWindowsNetio(urTunWindowsDeleteUnicastAddress, unsafe.Pointer(row))
}

// The route row of an IPv4 prefix through luid, at metric, initialized as IP Helper's defaults have it: by nextHop, or
// on link where nextHop is not valid.
func urTunWindowsRouteRow(luid uint64, prefix netip.Prefix, nextHop netip.Addr, metric uint32) (*windows.MibIpForwardRow2, error) {
	row := &windows.MibIpForwardRow2{}
	if err := urTunWindowsInitializeForwardEntry.Find(); err != nil {
		return nil, fmt.Errorf("%w: %v", errUrTunWindowsCallMissing, err)
	}
	urTunWindowsInitializeForwardEntry.Call(uintptr(unsafe.Pointer(row)))
	row.InterfaceLuid = luid
	prefix = prefix.Masked()
	urTunWindowsSetSockaddr(&row.DestinationPrefix.Prefix, prefix.Addr())
	row.DestinationPrefix.PrefixLength = uint8(prefix.Bits())
	if !nextHop.Is4() {
		// on link: the unspecified next hop of the prefix's family
		nextHop = netip.IPv4Unspecified()
	}
	urTunWindowsSetSockaddr(&row.NextHop, nextHop)
	row.Metric = metric
	row.Protocol = windows.MIB_IPPROTO_NETMGMT
	return row, nil
}

func (self *urTunWindowsIphlpapi) AddRoute(luid uint64, prefix netip.Prefix, metric uint32) error {
	row, err := urTunWindowsRouteRow(luid, prefix, netip.Addr{}, metric)
	if err != nil {
		return err
	}
	return urTunWindowsNetio(urTunWindowsCreateForwardEntry, unsafe.Pointer(row))
}

func (self *urTunWindowsIphlpapi) DeleteRoute(luid uint64, prefix netip.Prefix) error {
	row, err := urTunWindowsRouteRow(luid, prefix, netip.Addr{}, 0)
	if err != nil {
		return err
	}
	return urTunWindowsNetio(urTunWindowsDeleteForwardEntry, unsafe.Pointer(row))
}

func (self *urTunWindowsIphlpapi) AddHostRoute(luid uint64, address netip.Addr, nextHop netip.Addr, metric uint32) error {
	row, err := urTunWindowsRouteRow(luid, netip.PrefixFrom(address, address.BitLen()), nextHop, metric)
	if err != nil {
		return err
	}
	return urTunWindowsNetio(urTunWindowsCreateForwardEntry, unsafe.Pointer(row))
}

// DeleteIpForwardEntry2 finds the row by its prefix, next hop and adapter.
func (self *urTunWindowsIphlpapi) DeleteHostRoute(luid uint64, address netip.Addr, nextHop netip.Addr) error {
	row, err := urTunWindowsRouteRow(luid, netip.PrefixFrom(address, address.BitLen()), nextHop, 0)
	if err != nil {
		return err
	}
	return urTunWindowsNetio(urTunWindowsDeleteForwardEntry, unsafe.Pointer(row))
}

func (self *urTunWindowsIphlpapi) Routes() ([]urTunWindowsRoute, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	routes := []urTunWindowsRoute{}
	for _, row := range table.Rows() {
		dst := urTunWindowsSockaddrAddr(&row.DestinationPrefix.Prefix)
		if !dst.IsValid() {
			continue
		}
		prefix, err := dst.Prefix(int(row.DestinationPrefix.PrefixLength))
		if err != nil {
			continue
		}
		routes = append(routes, urTunWindowsRoute{
			dst:      prefix,
			luid:     row.InterfaceLuid,
			index:    row.InterfaceIndex,
			nextHop:  urTunWindowsSockaddrAddr(&row.NextHop),
			metric:   row.Metric,
			protocol: row.Protocol,
			loopback: row.Loopback != 0,
		})
	}
	return routes, nil
}

func (self *urTunWindowsIphlpapi) Adapters() ([]urTunWindowsAdapter, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST
	// GetAdaptersAddresses answers the size it needs when the buffer is short, and another pass covers an adapter that
	// came between two
	size := uint32(self.settings.AdapterBufferByteCount)
	var buffer []byte
	for attempt := 1; ; attempt += 1 {
		buffer = make([]byte, max(1, size))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || self.settings.AdapterReadAttemptCount <= attempt {
			return nil, err
		}
	}
	adapters := []urTunWindowsAdapter{}
	for entry := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0])); entry != nil; entry = entry.Next {
		adapter := urTunWindowsAdapter{
			luid:    entry.Luid,
			name:    windows.UTF16PtrToString(entry.FriendlyName),
			index4:  entry.IfIndex,
			index6:  entry.Ipv6IfIndex,
			metric4: entry.Ipv4Metric,
			metric6: entry.Ipv6Metric,
		}
		for unicast := entry.FirstUnicastAddress; unicast != nil; unicast = unicast.Next {
			if address, ok := urTunWindowsSocketAddress(unicast.Address); ok {
				adapter.addresses = append(adapter.addresses, address)
			}
		}
		for gateway := entry.FirstGatewayAddress; gateway != nil; gateway = gateway.Next {
			if address, ok := urTunWindowsSocketAddress(gateway.Address); ok {
				adapter.gateways = append(adapter.gateways, address)
			}
		}
		for resolver := entry.FirstDnsServerAddress; resolver != nil; resolver = resolver.Next {
			if address, ok := urTunWindowsSocketAddress(resolver.Address); ok {
				adapter.resolvers = append(adapter.resolvers, address)
			}
		}
		adapters = append(adapters, adapter)
	}
	return adapters, nil
}

func (self *urTunWindowsIphlpapi) SetMtu(luid uint64, mtu int) error {
	row := &windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceLuid: luid}
	if err := windows.GetIpInterfaceEntry(row); err != nil {
		return err
	}
	row.NlMtu = uint32(mtu)
	// SetIpInterfaceEntry refuses an IPv4 row whose SitePrefixLength is set
	row.SitePrefixLength = 0
	return urTunWindowsNetio(urTunWindowsSetIpInterfaceEntry, unsafe.Pointer(row))
}

// A SOCKET_ADDRESS's address.
func urTunWindowsSocketAddress(socketAddress windows.SocketAddress) (netip.Addr, bool) {
	if socketAddress.Sockaddr == nil {
		return netip.Addr{}, false
	}
	address := urTunWindowsSockaddrAddr((*windows.RawSockaddrInet)(unsafe.Pointer(socketAddress.Sockaddr)))
	return address, address.IsValid()
}

// Where ur tun looks for wintun.dll, in its order: beside ur.exe, then in the installed app's folder.
func urWintunCandidates() []string {
	candidates := []string{}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), urWintunDllName))
	}
	if programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil {
		candidates = append(candidates, filepath.Join(programFiles, urWintunAppFolderName, urWintunDllName))
	}
	return candidates
}

// The driver's load, once it has succeeded: the module stays loaded for the process, so wireguard's tun, which loads
// wintun.dll by its name, takes it.
var urWintunLoaded struct {
	stateLock sync.Mutex
	path      string
}

// Loads the first of candidates that is there, once it matches pins: its SHA-256, read through a handle that refuses
// every writer and deleter from the check through the load, and its Authenticode signature, valid and by the pinned
// signer. A candidate that is not there is passed over; one that is there and fails is refused, never passed over for
// the next, so a planted copy cannot be outranked quietly.
func urWintunLoad(pins *urWintunPins, candidates []string) error {
	urWintunLoaded.stateLock.Lock()
	defer urWintunLoaded.stateLock.Unlock()
	if urWintunLoaded.path != "" {
		return nil
	}
	for _, candidate := range candidates {
		file, err := urWintunOpen(candidate)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: %s did not open (%v)", errUrWintunRefused, candidate, err)
		}
		err = func() error {
			defer file.Close()
			if err := urWintunCheck(file, candidate, pins); err != nil {
				return err
			}
			// loaded by its full path while the handle holds it, so the file loaded is the file checked
			if _, err := windows.LoadLibraryEx(candidate, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32); err != nil {
				return fmt.Errorf("%w: %s did not load (%v)", errUrWintunRefused, candidate, err)
			}
			return nil
		}()
		if err != nil {
			return err
		}
		urWintunLoaded.path = candidate
		return nil
	}
	return errUrWintunMissing
}

// Opens path for reading, sharing it with readers alone, so no one writes, renames or deletes it while it is open.
func urWintunOpen(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// Holds file, path's, to pins: its SHA-256 first, to this architecture's DLL pin (urWintunCheckDigest), then its
// signature.
func urWintunCheck(file *os.File, path string, pins *urWintunPins) error {
	if err := urWintunCheckDigest(file, path, pins, runtime.GOARCH); err != nil {
		return err
	}
	thumbprint, err := urWintunSigner(windows.Handle(file.Fd()), path)
	if err != nil {
		return fmt.Errorf("%w: %s's signature does not verify (%v)", errUrWintunRefused, path, err)
	}
	if !strings.EqualFold(thumbprint, pins.SignerThumbprint) {
		return fmt.Errorf("%w: %s is signed by another certificate", errUrWintunRefused, path)
	}
	return nil
}

// The calls x/sys/windows does not wrap, from crypt32.dll in System32.
var (
	urWintunCrypt32Dll       = windows.NewLazySystemDLL("crypt32.dll")
	urWintunCryptMsgGetParam = urWintunCrypt32Dll.NewProc("CryptMsgGetParam")
	urWintunCryptMsgClose    = urWintunCrypt32Dll.NewProc("CryptMsgClose")
)

// CryptMsgGetParam's CMSG_SIGNER_CERT_INFO_PARAM (wincrypt.h): a signer's issuer and serial, as a CERT_INFO.
const urWintunSignerCertInfoParam = 7

// Verifies the Authenticode signature of the file at handle, path's, to a trusted root (WinVerifyTrust over the handle,
// no revocation fetched, no UI), and answers its signer certificate's SHA-1 thumbprint, hex.
func urWintunSigner(handle windows.Handle, path string) (string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	fileInfo := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: name,
		File:     handle,
	}
	trustData := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, trustData)
	trustData.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, trustData)
	if verifyErr != nil {
		return "", verifyErr
	}
	return urWintunSignerThumbprint(name)
}

// The SHA-1 thumbprint, hex, of the certificate that signed the file name's embedded signature: CryptQueryObject's
// message, its signer's issuer and serial, and that certificate in the message's store.
func urWintunSignerThumbprint(name *uint16) (string, error) {
	var encoding, contentType, formatType uint32
	var store windows.Handle
	var message windows.Handle
	err := windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(name),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, windows.CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding,
		&contentType, &formatType, &store, &message, nil)
	if err != nil {
		return "", err
	}
	defer windows.CertCloseStore(store, 0)
	defer urWintunCryptMsgClose.Call(uintptr(message))
	if err := urWintunCryptMsgGetParam.Find(); err != nil {
		return "", err
	}
	var size uint32
	if ok, _, err := urWintunCryptMsgGetParam.Call(uintptr(message), urWintunSignerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); ok == 0 {
		return "", err
	}
	if size == 0 {
		return "", errors.New("the signature names no signer")
	}
	// CERT_INFO and what its blobs point into, which holds pointers, so it is allocated as pointer words
	words := make([]uintptr, (uintptr(size)+unsafe.Sizeof(uintptr(0))-1)/unsafe.Sizeof(uintptr(0)))
	if ok, _, err := urWintunCryptMsgGetParam.Call(uintptr(message), urWintunSignerCertInfoParam, 0,
		uintptr(unsafe.Pointer(&words[0])), uintptr(unsafe.Pointer(&size))); ok == 0 {
		return "", err
	}
	certificate, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
		windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&words[0]), nil)
	runtime.KeepAlive(words)
	if err != nil {
		return "", err
	}
	defer windows.CertFreeCertificateContext(certificate)
	digest := sha1.Sum(unsafe.Slice(certificate.EncodedCert, certificate.Length))
	return hex.EncodeToString(digest[:]), nil
}

// One open adapter and what this interface set on it. Its configuration calls are serialized.
type urTunWindowsInterface struct {
	system     *urTunWindowsSystem
	name       string
	luid       uint64
	device     tun.Device
	eventsDone chan struct{}

	stateLock sync.Mutex
	// what it added, which Close and the next sets remove
	addresses   []netip.Addr
	routes      []netip.Prefix
	resolverSet bool
	// what the exits put on, which SetExits(false) and Close take off: IPv4's halves, and connect's binding to the
	// interfaces of the host's default routes
	exitsHalves []netip.Prefix
	exitsBound  bool
	boundIndex4 uint32
	boundIndex6 uint32
	// the IPv4 addresses the bridge carves, sorted (SetCarved), and the host routes this interface put on for those
	// of them the host reaches only by its default route, which go with the halves
	carvedAddrs []netip.Addr
	hostRoutes  []urTunHostRoute
	closed      bool
}

var _ urTunInterface = (*urTunWindowsInterface)(nil)
var _ urTunCarvedInterface = (*urTunWindowsInterface)(nil)

func (self *urTunWindowsInterface) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return self.device.Read(bufs, sizes, offset)
}

func (self *urTunWindowsInterface) Write(bufs [][]byte, offset int) (int, error) {
	return self.device.Write(bufs, offset)
}

func (self *urTunWindowsInterface) BatchSize() int {
	return self.device.BatchSize()
}

// Adds each IPv4 address not on the adapter yet and removes each it added that addresses no longer holds.
func (self *urTunWindowsInterface) SetAddresses(addresses []netip.Addr) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return errUrTunClosed
	}
	ipHelper := self.system.ipHelper
	var setErr error
	kept := []netip.Addr{}
	for _, held := range self.addresses {
		if slices.Contains(addresses, held) {
			kept = append(kept, held)
			continue
		}
		if err := ipHelper.DeleteAddress(self.luid, held); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			setErr = errors.Join(setErr, urTunWindowsError(err))
			kept = append(kept, held)
		}
	}
	for _, address := range addresses {
		if !address.Is4() || slices.Contains(kept, address) {
			continue
		}
		err := ipHelper.AddAddress(self.luid, address)
		if err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			setErr = errors.Join(setErr, urTunWindowsError(err))
			continue
		}
		kept = append(kept, address)
	}
	self.addresses = kept
	return setErr
}

// Adds each IPv4 route not on the adapter yet and removes each it added that routes no longer holds. A prefix another
// interface's route holds is counted and left to it, and tried again at the next set.
func (self *urTunWindowsInterface) SetRoutes(routes []netip.Prefix) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return 0, errUrTunClosed
	}
	ipHelper := self.system.ipHelper
	var setErr error
	kept := []netip.Prefix{}
	for _, held := range self.routes {
		if slices.Contains(routes, held) {
			kept = append(kept, held)
			continue
		}
		if err := ipHelper.DeleteRoute(self.luid, held); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			setErr = errors.Join(setErr, urTunWindowsError(err))
			kept = append(kept, held)
		}
	}
	var table []urTunWindowsRoute
	conflictCount := 0
	for _, wanted := range routes {
		if !wanted.Addr().Is4() || slices.Contains(kept, wanted.Masked()) {
			continue
		}
		wanted = wanted.Masked()
		if table == nil {
			var err error
			if table, err = ipHelper.Routes(); err != nil {
				setErr = errors.Join(setErr, err)
				break
			}
		}
		if slices.ContainsFunc(table, func(held urTunWindowsRoute) bool {
			return held.dst == wanted && held.luid != self.luid
		}) {
			conflictCount += 1
			continue
		}
		err := ipHelper.AddRoute(self.luid, wanted, self.system.settings.RouteMetric)
		if err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			setErr = errors.Join(setErr, urTunWindowsError(err))
			continue
		}
		kept = append(kept, wanted)
	}
	self.routes = kept
	return conflictCount, setErr
}

// bridge_dns_windows.go's rule for the zones.
func (self *urTunWindowsInterface) SetResolver(resolver netip.Addr, zones []string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return "", errUrTunClosed
	}
	rule := urTunWindowsRuleName(self.name)
	if len(zones) == 0 || !resolver.IsValid() {
		if self.resolverSet {
			self.system.resolver.Remove(rule)
			self.resolverSet = false
		}
		return "", nil
	}
	names := []string{}
	for _, zone := range zones {
		if name, ok := urTunZoneName(zone, self.system.settings); ok && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return "", nil
	}
	step, err := self.system.resolver.Set(rule, resolver, names)
	if err != nil {
		if self.system.log.V(1).Enabled() {
			self.system.log.Infof("[tun]the resolver's rule did not set: %v", err)
		}
		return urTunWindowsResolverStep(resolver, names), nil
	}
	self.resolverSet = true
	return step, nil
}

// Under exits, binds connect's sockets to the interfaces of the host's own default routes, puts on the host routes of
// the carved addresses SetCarved last gave, by the default route as it is now, so one that moved takes them with it,
// then puts IPv4's halves on the adapter, and has connect's transports dial again where the binding is new or moved,
// so no socket made before it stays in the tun's way. It refuses, and leaves nothing on, where no default route leaves
// by another interface or another program's route holds a half; a host route that will not go on refuses nothing, and
// is SetCarved's to try again. Off exits, takes them off. Answers whether the default route rides the adapter.
func (self *urTunWindowsInterface) SetExits(exits bool) (bool, error) {
	rebound, defaultRoute, err := func() (bool, bool, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false, false, errUrTunClosed
		}
		if !exits {
			err := self.clearExitsWithLock()
			return false, 0 < len(self.exitsHalves), err
		}
		table, err := self.system.ipHelper.Routes()
		if err != nil {
			return false, false, errors.Join(fmt.Errorf("the routes did not read (%v)", err), self.clearExitsWithLock())
		}
		adapters, err := self.system.ipHelper.Adapters()
		if err != nil {
			return false, false, errors.Join(fmt.Errorf("the routes did not read (%v)", err), self.clearExitsWithLock())
		}
		_, index4 := urTunWindowsDefaultRoute(table, adapters, self.luid, true)
		_, index6 := urTunWindowsDefaultRoute(table, adapters, self.luid, false)
		if index4 == 0 {
			return false, false, errors.Join(errUrTunWindowsExitsNoDefault, self.clearExitsWithLock())
		}
		for _, half := range urTunExitsHalves() {
			if slices.ContainsFunc(table, func(held urTunWindowsRoute) bool { return held.dst == half && held.luid != self.luid }) {
				return false, false, errors.Join(errUrTunWindowsExitsHalfInUse, self.clearExitsWithLock())
			}
		}
		rebound := !self.exitsBound || self.boundIndex4 != index4 || self.boundIndex6 != index6
		if rebound {
			// a family with no default route of its own is pinned to the other's (connect/egress_windows.go)
			self.system.setEgressInterface(index4, index6)
			self.exitsBound, self.boundIndex4, self.boundIndex6 = true, index4, index6
		}
		// before the halves, so no lookup of a carved address meets one
		_ = self.setHostRoutesWithLock(self.carvedAddrs, table, adapters)
		for _, half := range urTunExitsHalves() {
			if slices.Contains(self.exitsHalves, half) {
				continue
			}
			err := self.system.ipHelper.AddRoute(self.luid, half, self.system.settings.RouteMetric)
			if err != nil && !errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
				// nothing of a partial set stays on behind a refusal
				return false, false, errors.Join(fmt.Errorf("the default route did not go on (%v)", err), self.clearExitsWithLock())
			}
			self.exitsHalves = append(self.exitsHalves, half)
			rebound = true
		}
		return rebound, true, nil
	}()
	if rebound {
		// a socket made before the binding takes the tun's way from here: connect's transports dial again, bound
		self.system.networkChanged()
	}
	return defaultRoute, err
}

// Sets the addresses the bridge carves (§17.4), the IPv4 ones counting, since the halves are IPv4's (QD-869). While a
// half is on, the host routes follow at once, over the table as it reads now: one for each address the host reaches
// only by its default route that holds none, those of addresses no longer carved, or that a route of the host's own
// has come to reach, off, and those the default route moved from under replaced by its next hop now. Otherwise the
// list waits for SetExits(true), and a host route a clear left on is tried off again. Answers what would not go on or
// come off, which the next call tries again.
func (self *urTunWindowsInterface) SetCarved(addresses []netip.Addr) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return errUrTunClosed
	}
	carvedAddrs := urTunCarvedIpv4Addrs(addresses)
	self.carvedAddrs = carvedAddrs
	if len(self.exitsHalves) == 0 {
		return self.setHostRoutesWithLock(nil, nil, nil)
	}
	if len(carvedAddrs) == 0 && len(self.hostRoutes) == 0 {
		return nil
	}
	// what is on stays as it is for the next call where the host does not read
	table, err := self.system.ipHelper.Routes()
	if err != nil {
		return fmt.Errorf("the routes did not read (%v)", err)
	}
	adapters, err := self.system.ipHelper.Adapters()
	if err != nil {
		return fmt.Errorf("the routes did not read (%v)", err)
	}
	return self.setHostRoutesWithLock(carvedAddrs, table, adapters)
}

// Sets the host routes to those carvedAddrs take over table and adapters, the host's (urTunWindowsHostRoutes,
// urTunSetHostRoutes): none for no addresses. Answers what would not go on or come off, kept as it is for the next
// call.
func (self *urTunWindowsInterface) setHostRoutesWithLock(carvedAddrs []netip.Addr, table []urTunWindowsRoute,
	adapters []urTunWindowsAdapter) error {
	ipHelper := self.system.ipHelper
	wanted := []urTunHostRoute{}
	if 0 < len(carvedAddrs) {
		wanted = urTunWindowsHostRoutes(carvedAddrs, table, adapters, self.luid, self.routes, self.hostRoutes)
	}
	var err error
	self.hostRoutes, err = urTunSetHostRoutes(self.hostRoutes, wanted, &urTunHostRouteCalls{
		add: func(hostRoute urTunHostRoute) error {
			return ipHelper.AddHostRoute(hostRoute.link, hostRoute.address, hostRoute.gateway, self.system.settings.RouteMetric)
		},
		remove: func(hostRoute urTunHostRoute) error {
			return ipHelper.DeleteHostRoute(hostRoute.link, hostRoute.address, hostRoute.gateway)
		},
		held: func(err error) bool {
			return errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS)
		},
		gone: func(err error) bool {
			return errors.Is(err, windows.ERROR_NOT_FOUND)
		},
	})
	return err
}

// Takes off what the exits put on, the halves first, keeping account of what would not come off, so a later call tries
// it again; the carved addresses' host routes go once no half is left, since until then a lookup of one still needs
// its own, and the binding goes then too, since a half without it would take the daemon's own transport.
func (self *urTunWindowsInterface) clearExitsWithLock() error {
	var clearErr error
	kept := []netip.Prefix{}
	for _, half := range self.exitsHalves {
		if err := self.system.ipHelper.DeleteRoute(self.luid, half); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			clearErr = errors.Join(clearErr, fmt.Errorf("the default route did not come off (%v)", err))
			kept = append(kept, half)
		}
	}
	self.exitsHalves = kept
	if len(self.exitsHalves) == 0 {
		clearErr = errors.Join(clearErr, self.setHostRoutesWithLock(nil, nil, nil))
	}
	if self.exitsBound && len(self.exitsHalves) == 0 {
		self.system.setEgressInterface(0, 0)
		self.exitsBound, self.boundIndex4, self.boundIndex6 = false, 0, 0
	}
	return clearErr
}

// Takes the exits off, the carved addresses' host routes with them, removes the resolver's rule, the routes and the
// addresses it added, and closes the adapter, which Wintun deletes with whatever is left on it. Waits for the adapter's
// event listener to end.
func (self *urTunWindowsInterface) Close() error {
	var closeErr error
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return
		}
		self.closed = true
		closeErr = errors.Join(closeErr, self.clearExitsWithLock())
		if self.resolverSet {
			closeErr = errors.Join(closeErr, self.system.resolver.Remove(urTunWindowsRuleName(self.name)))
			self.resolverSet = false
		}
		ipHelper := self.system.ipHelper
		for _, held := range self.routes {
			if err := ipHelper.DeleteRoute(self.luid, held); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
				closeErr = errors.Join(closeErr, err)
			}
		}
		self.routes = nil
		for _, held := range self.addresses {
			if err := ipHelper.DeleteAddress(self.luid, held); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
				closeErr = errors.Join(closeErr, err)
			}
		}
		self.addresses = nil
		closeErr = errors.Join(closeErr, self.device.Close())
	}()
	<-self.eventsDone
	return closeErr
}
