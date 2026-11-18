//go:build darwin

// ur tun's device on macOS (§17.10, §17.11; BRIDGE-M6-06): the tun is wireguard's (golang.zx2c4.com/wireguard/tun), a
// utun whose number the kernel picks, and everything set on it goes through the kernel from the daemon itself, never a
// spawned ifconfig or route:
//
//	device     utun<n>, up, its MTU the settings'; the tun shows that name, since macOS names a utun itself. Only root
//	           may create one, and a daemon that runs as the person is refused in words that send them to no sudo:
//	           a daemon run that way is root's own instance, with none of theirs enrolled
//	addresses  this host's overlay /32s on the device, point to point (SIOCAIFADDR), so the kernel picks one as the
//	           source of what the tun carries
//	routes     each of Bridge.Routes() through the device, written to the routing socket with the device's link address
//	           as the gateway; a route another interface holds at the same prefix answers EEXIST and keeps it, counted
//	resolver   bridge_dns_darwin.go's
//	local      bridge_local_darwin.go's
//	exits      where the tun's plan takes the host's default route (tun_default.go; QD-1052), "under exits"
//	           here, IPv4's two halves through the device (urTunExitsHalves), each more specific
//	           than the host's own default route, which stays. connect's sockets are bound to that default route's
//	           interface first (IP_BOUND_IF, connect.SetEgressInterfaceIndex) and its transports dial again, so the
//	           daemon's own transport, and every link the bridge sends on, keeps the host's route; each sync binds them
//	           to the default route's interface again where it moved. The halves come off first and the binding last
//	ipv6       under exits, IPv6's two halves through the device after IPv4's (urTunExitsIpv6Halves; QD-881), so the
//	           host's IPv6 reaches the tun, where the bridge drops it and counts it, since no exit carries IPv6, while
//	           connect's IPv6 sockets, bound to the IPv6 default route's interface (IPV6_BOUND_IF), keep the host's
//	           route. Where the host has an IPv6 default route, a refusal of IPv6's halves holds the exits as one of
//	           IPv4's does; where it has none, IPv4's halves stand alone, since no IPv6 leaves the host to begin with,
//	           and the next SetExits tries IPv6's again. A half another program holds holds the exits in either family
//	carved     under exits, a host route for each address the bridge carves that the host's own table reaches only by
//	           its default route of that family, an off-link resolver above all, by that route's gateway and interface
//	           (tun_host_routes.go; QD-869), IPv6's by the IPv6 default route's (QD-971), written to the routing socket
//	           with the gateway as its next hop, a link-local IPv6 one carrying its interface as its scope, and the
//	           interface named (RTA_IFP). They go on before the halves, follow each SetCarved and the default routes
//	           where they move, and a family's come off once no half of that family is left
//
// Only what this interface added is removed. Close takes the exits and the carved addresses' host routes off, reverts
// the resolver, removes the routes and addresses and closes the device, which the kernel destroys with whatever was
// left on it, its own routes included. A host route leaves by another interface, so one a daemon that died left stays
// until the host restarts or a person removes it: it reads as another program's route, which ur tun leaves alone.

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/urnetwork/connect"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/urnetwork/sidecar"
)

func init() {
	urTunPlatform = newUrTunDarwinSystem
}

// The name wireguard's tun takes for a utun whose number the kernel picks.
const urTunDarwinDeviceName = "utun"

// What a daemon that runs as the person reads: the right it lacks and the ways it has.
const urTunDarwinPrivilegeText = "ur tun on macOS needs a daemon that runs as root, since only root may create a " +
	"utun, and this one runs as you: this release installs no helper to lend it that right. ur bridge works without " +
	"a tun over the userspace stack, and an instance of root's own, enrolled from root's account, carries one"

// Why the default route stays off the tun under exits on macOS, besides a refusal of the kernel's.
var (
	// No default route leaves by another interface, so the daemon's own transport would have no way out.
	errUrTunExitsNoDefault = errors.New("no default route leaves this host by another interface for the daemon's own " +
		"transport to keep")
	// Another program's route holds one of IPv4's or IPv6's halves, as another VPN's does.
	errUrTunExitsHalfInUse = errors.New("another program's route holds half of IPv4's or IPv6's space, as another " +
		"VPN's does")
)

// What ur tun asks of the kernel, a test's recorder standing in for it.
type urTunDarwinKernel interface {
	// Sets the interface up.
	SetUp(name string) error
	// Adds or removes an IPv4 /32 of the point-to-point interface name (SIOCAIFADDR, SIOCDIFADDR).
	AddAddress(name string, address netip.Addr) error
	DeleteAddress(name string, address netip.Addr) error
	// Adds or removes a route of either family through the interface at index by the routing socket: EEXIST where a
	// route holds the prefix already, ESRCH where none is there to remove.
	AddRoute(index int, prefix netip.Prefix) error
	DeleteRoute(index int, prefix netip.Prefix) error
	// Adds or removes the host route of address, of either family, by the next hop gateway of its family through the
	// interface at index, or through that interface alone where gateway is not valid, by the routing socket, answering
	// as AddRoute and DeleteRoute do.
	AddHostRoute(index int, address netip.Addr, gateway netip.Addr) error
	DeleteHostRoute(index int, address netip.Addr, gateway netip.Addr) error
	// Every route of both families.
	Routes() ([]urTunDarwinRoute, error)
}

// One route of the table.
type urTunDarwinRoute struct {
	dst   netip.Prefix
	index int
	// the next hop's address, invalid for a route to an interface
	gateway netip.Addr
	flags   int
}

// The platform's half of ur tun on macOS. Safe for concurrent use.
type urTunDarwinSystem struct {
	settings *urTunSettings
	log      sidecar.Logger

	// What ur tun reaches of the host, the kernel's and connect's own outside a test: the kernel's calls, wireguard's
	// utun, an interface's index, the resolver files' directory and the system's resolver file, connect's egress
	// binding, and connect's network-change kick, which has the daemon's transports dial again on bound sockets.
	kernel             urTunDarwinKernel
	create             func(mtu int) (tun.Device, error)
	interfaceIndex     func(name string) (int, error)
	resolverDirectory  string
	resolvConfPath     string
	setEgressInterface func(index4 uint32, index6 uint32)
	networkChanged     func()
}

var _ urTunSystem = (*urTunDarwinSystem)(nil)

func newUrTunDarwinSystem(settings *urTunSettings, log sidecar.Logger) urTunSystem {
	if settings == nil {
		settings = defaultUrTunSettings()
	}
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	return &urTunDarwinSystem{
		settings:           settings,
		log:                log,
		kernel:             &urTunDarwinSockets{},
		create:             urTunDarwinCreate,
		interfaceIndex:     urTunDarwinIndex,
		resolverDirectory:  urTunDarwinResolverDirectory,
		resolvConfPath:     urResolvConfPath,
		setEgressInterface: connect.SetEgressInterfaceIndex,
		networkChanged:     connect.NetworkChanged,
	}
}

// A utun the kernel numbers, with mtu.
func urTunDarwinCreate(mtu int) (tun.Device, error) {
	return tun.CreateTUN(urTunDarwinDeviceName, mtu)
}

// The index of name.
func urTunDarwinIndex(name string) (int, error) {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return link.Index, nil
}

// What a host that lacks the privilege answers, as the person reads it.
func urTunDarwinError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return &urTunPrivilegeError{text: urTunDarwinPrivilegeText, err: err}
	}
	return err
}

// Opens a utun with mtu and sets it up. name is the instance's device name, ur-<instance>, which names the resolver
// files this tun writes; the device takes the kernel's utun<n>.
func (self *urTunDarwinSystem) Open(name string, mtu int) (urTunInterface, error) {
	device, err := self.create(mtu)
	if err != nil {
		return nil, urTunDarwinError(err)
	}
	deviceName, err := device.Name()
	if err != nil {
		device.Close()
		return nil, err
	}
	iface := &urTunDarwinInterface{
		system:     self,
		owner:      name,
		name:       deviceName,
		device:     device,
		eventsDone: make(chan struct{}),
	}
	// wireguard's listener blocks once ten events wait unread, which would hold its close
	go func() {
		defer close(iface.eventsDone)
		for range device.Events() {
		}
	}()
	iface.index, err = self.interfaceIndex(deviceName)
	if err != nil {
		iface.Close()
		return nil, err
	}
	if err := self.kernel.SetUp(deviceName); err != nil {
		iface.Close()
		return nil, urTunDarwinError(err)
	}
	return iface, nil
}

// The interface other than name with a unicast route inside prefix, "" for none: an app's bridge holding the block. A
// route that covers the whole prefix from outside it, as a carrier's 100.64/10 does, is no bridge's and does not
// count, nor does a local address's own, a neighbor's cached link address or a broadcast's.
func (self *urTunDarwinSystem) RoutedElsewhere(name string, prefix netip.Prefix) (string, error) {
	ownIndex, _ := self.interfaceIndex(name)
	routes, err := self.kernel.Routes()
	if err != nil {
		return "", err
	}
	for _, held := range routes {
		if held.flags&urTunDarwinNotARouteFlags != 0 || !held.dst.IsValid() || !held.dst.Addr().Is4() ||
			held.dst.Bits() < prefix.Bits() || !prefix.Contains(held.dst.Addr()) || held.index == 0 || held.index == ownIndex {
			continue
		}
		if link, err := net.InterfaceByIndex(held.index); err == nil {
			return link.Name, nil
		}
		return fmt.Sprintf("index %d", held.index), nil
	}
	return "", nil
}

// The flags of an entry the table holds that routes nothing to a network: a local address's, a broadcast's or a
// multicast's, and a neighbor's cached link address.
const urTunDarwinNotARouteFlags = unix.RTF_LOCAL | unix.RTF_BROADCAST | unix.RTF_MULTICAST | unix.RTF_LLINFO | unix.RTF_WASCLONED

// The host's own default routes in table, IPv4's and IPv6's, other than ownIndex's: the unscoped one where there is
// one, else the first scoped one; a route of index 0 for a family with none.
func urTunDarwinDefaultRoutes(table []urTunDarwinRoute, ownIndex int) (urTunDarwinRoute, urTunDarwinRoute) {
	pick := func(ipv4 bool) urTunDarwinRoute {
		scoped := urTunDarwinRoute{}
		for _, held := range table {
			if !held.dst.IsValid() || held.dst.Bits() != 0 || held.dst.Addr().Is4() != ipv4 || held.index == 0 ||
				held.index == ownIndex || held.flags&unix.RTF_UP == 0 {
				continue
			}
			if held.flags&unix.RTF_IFSCOPE == 0 {
				return held
			}
			if scoped.index == 0 {
				scoped = held
			}
		}
		return scoped
	}
	return pick(true), pick(false)
}

// The flags of an entry the table holds under a route that made it, which reaches nothing in its own right: a
// neighbor's cached link address or a route's clone.
const urTunDarwinCachedRouteFlags = unix.RTF_LLINFO | unix.RTF_WASCLONED

// The host routes the carved addresses take over table, the host's routes (urTunHostRoutes), IPv4's then IPv6's
// (QD-971): each family's by the gateway and interface of its default route that leaves by an interface other than
// ownIndex, none for a family with none, and by that interface alone where the route names no gateway of the family.
// An address is reached where a route other than a default one holds it, but a route through ownIndex, which is the
// tun's, a half among them; a scoped route, which only a socket bound to its interface takes, a link-local IPv6
// prefix's among them; a cached entry; and, for an address of onRoutes, its own host route, which this interface put
// on.
func urTunDarwinHostRoutes(carvedAddrs []netip.Addr, table []urTunDarwinRoute, ownIndex int, ownRoutes []netip.Prefix,
	onRoutes []urTunHostRoute) []urTunHostRoute {
	reached := func(address netip.Addr) bool {
		ownHostRoute := slices.ContainsFunc(onRoutes, func(on urTunHostRoute) bool { return on.address == address })
		return slices.ContainsFunc(table, func(held urTunDarwinRoute) bool {
			if !held.dst.IsValid() || held.dst.Bits() == 0 || !held.dst.Contains(address) || held.index == ownIndex ||
				held.flags&unix.RTF_UP == 0 || held.flags&(unix.RTF_IFSCOPE|urTunDarwinCachedRouteFlags) != 0 {
				return false
			}
			return !(ownHostRoute && held.dst.IsSingleIP())
		})
	}
	default4, default6 := urTunDarwinDefaultRoutes(table, ownIndex)
	hostRoutes := []urTunHostRoute{}
	for _, defaultRoute := range []urTunDarwinRoute{default4, default6} {
		if defaultRoute.index == 0 {
			continue
		}
		ipv4 := defaultRoute.dst.Addr().Is4()
		gateway := defaultRoute.gateway
		if gateway.IsValid() && gateway.Is4() != ipv4 {
			gateway = netip.Addr{}
		}
		hostRoutes = append(hostRoutes, urTunHostRoutes(carvedAddrs, ipv4, gateway, uint64(defaultRoute.index), ownRoutes,
			reached)...)
	}
	return hostRoutes
}

// The kernel's calls, each on a socket of its own.
type urTunDarwinSockets struct {
	// numbers each routing message
	sequence atomic.Int32
}

var _ urTunDarwinKernel = (*urTunDarwinSockets)(nil)

// struct ifreq with ifr_flags (<net/if.h>): the name, then the union's first short.
type urTunDarwinIfreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [14]byte
}

// struct ifaliasreq (<net/if.h>): the name and three sockaddrs, here sockaddr_ins.
type urTunDarwinIfaliasreq struct {
	Name      [unix.IFNAMSIZ]byte
	Addr      unix.RawSockaddrInet4
	Broadaddr unix.RawSockaddrInet4
	Mask      unix.RawSockaddrInet4
}

// struct ifreq with ifr_addr.
type urTunDarwinIfreqAddr struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
}

// A socket of family, closed on exec, made under the fork lock as the runtime makes its own.
func urTunDarwinSocket(family int, socketType int, protocol int) (int, error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fd, err := unix.Socket(family, socketType, protocol)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(fd)
	return fd, nil
}

// One ioctl of request on an IPv4 datagram socket, its argument at argument.
func urTunDarwinIoctl[T any](request uint, argument *T) error {
	fd, err := urTunDarwinSocket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(unsafe.Pointer(argument))); errno != 0 {
		return errno
	}
	return nil
}

// A sockaddr_in of address.
func urTunDarwinSockaddr(address netip.Addr) unix.RawSockaddrInet4 {
	return unix.RawSockaddrInet4{Len: unix.SizeofSockaddrInet4, Family: unix.AF_INET, Addr: address.As4()}
}

// The interface's name in an ifreq's array, refused past IFNAMSIZ less its NUL.
func urTunDarwinIfname(name string) ([unix.IFNAMSIZ]byte, error) {
	var ifname [unix.IFNAMSIZ]byte
	if len(name) == 0 || unix.IFNAMSIZ <= len(name) {
		return ifname, fmt.Errorf("no interface may be named %q", name)
	}
	copy(ifname[:], name)
	return ifname, nil
}

// The flags of name.
func urTunDarwinFlags(name string) (int16, error) {
	ifname, err := urTunDarwinIfname(name)
	if err != nil {
		return 0, err
	}
	request := &urTunDarwinIfreqFlags{Name: ifname}
	if err := urTunDarwinIoctl(unix.SIOCGIFFLAGS, request); err != nil {
		return 0, err
	}
	return request.Flags, nil
}

func (self *urTunDarwinSockets) SetUp(name string) error {
	flags, err := urTunDarwinFlags(name)
	if err != nil {
		return err
	}
	if flags&unix.IFF_UP != 0 {
		return nil
	}
	ifname, err := urTunDarwinIfname(name)
	if err != nil {
		return err
	}
	return urTunDarwinIoctl(unix.SIOCSIFFLAGS, &urTunDarwinIfreqFlags{Name: ifname, Flags: flags | unix.IFF_UP})
}

func (self *urTunDarwinSockets) AddAddress(name string, address netip.Addr) error {
	ifname, err := urTunDarwinIfname(name)
	if err != nil {
		return err
	}
	// a point-to-point /32: its own address the destination too, as wg-quick sets a utun's
	return urTunDarwinIoctl(unix.SIOCAIFADDR, &urTunDarwinIfaliasreq{
		Name:      ifname,
		Addr:      urTunDarwinSockaddr(address),
		Broadaddr: urTunDarwinSockaddr(address),
		Mask:      urTunDarwinSockaddr(netip.AddrFrom4([4]byte{255, 255, 255, 255})),
	})
}

func (self *urTunDarwinSockets) DeleteAddress(name string, address netip.Addr) error {
	ifname, err := urTunDarwinIfname(name)
	if err != nil {
		return err
	}
	return urTunDarwinIoctl(unix.SIOCDIFADDR, &urTunDarwinIfreqAddr{Name: ifname, Addr: urTunDarwinSockaddr(address)})
}

func (self *urTunDarwinSockets) AddRoute(index int, prefix netip.Prefix) error {
	return self.route(unix.RTM_ADD, index, prefix)
}

func (self *urTunDarwinSockets) DeleteRoute(index int, prefix netip.Prefix) error {
	return self.route(unix.RTM_DELETE, index, prefix)
}

func (self *urTunDarwinSockets) AddHostRoute(index int, address netip.Addr, gateway netip.Addr) error {
	return self.write(urTunDarwinHostRouteMessage(unix.RTM_ADD, index, address, gateway, os.Getpid(), int(self.sequence.Add(1))))
}

func (self *urTunDarwinSockets) DeleteHostRoute(index int, address netip.Addr, gateway netip.Addr) error {
	return self.write(urTunDarwinHostRouteMessage(unix.RTM_DELETE, index, address, gateway, os.Getpid(), int(self.sequence.Add(1))))
}

// Writes one routing message of messageType for prefix through index.
func (self *urTunDarwinSockets) route(messageType int, index int, prefix netip.Prefix) error {
	return self.write(urTunDarwinRouteMessage(messageType, index, prefix, os.Getpid(), int(self.sequence.Add(1))))
}

// Writes message to a routing socket of its own. The kernel answers a refusal as the write's errno.
func (self *urTunDarwinSockets) write(message *route.RouteMessage) error {
	wire, err := message.Marshal()
	if err != nil {
		return err
	}
	fd, err := urTunDarwinSocket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	// a routing socket hears every route change while it is open; this one only writes
	unix.Shutdown(fd, unix.SHUT_RD)
	_, err = unix.Write(fd, wire)
	return err
}

// The routing message of a prefix of either family through the interface at index: a host route for a whole address, a
// network route with its mask otherwise, the interface's link address as the gateway, so it names no next hop.
func urTunDarwinRouteMessage(messageType int, index int, prefix netip.Prefix, id int, sequence int) *route.RouteMessage {
	prefix = prefix.Masked()
	flags := unix.RTF_UP | unix.RTF_STATIC
	var dst, mask route.Addr
	if prefix.Addr().Is4() {
		dst = &route.Inet4Addr{IP: prefix.Addr().As4()}
		mask = &route.Inet4Addr{IP: [4]byte(net.CIDRMask(prefix.Bits(), 32))}
	} else {
		dst = &route.Inet6Addr{IP: prefix.Addr().As16()}
		mask = &route.Inet6Addr{IP: [16]byte(net.CIDRMask(prefix.Bits(), 128))}
	}
	addrs := []route.Addr{
		unix.RTAX_DST:     dst,
		unix.RTAX_GATEWAY: &route.LinkAddr{Index: index},
	}
	if prefix.IsSingleIP() {
		flags |= unix.RTF_HOST
	} else {
		addrs = append(addrs, mask)
	}
	return &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    messageType,
		Flags:   flags,
		Index:   index,
		ID:      uintptr(id),
		Seq:     sequence,
		Addrs:   addrs,
	}
}

// The routing message of the host route of address, of either family, by the next hop gateway, with the interface at
// index named as the one it leaves by (RTA_IFP), so a gateway two interfaces reach takes the default route's. A
// link-local IPv6 gateway, as IPv6's default routes name, carries index as its scope, embedded in the address's second
// 16 bits as the kernel keeps it and macOS's route(8) writes it, with no sin6_scope_id beside it. Where gateway is not
// valid, or not of address's family, the interface's link address is the gateway, as a route through the tun's is.
func urTunDarwinHostRouteMessage(messageType int, index int, address netip.Addr, gateway netip.Addr, id int,
	sequence int) *route.RouteMessage {
	if !gateway.IsValid() || gateway.Is4() != address.Is4() {
		return urTunDarwinRouteMessage(messageType, index, netip.PrefixFrom(address, address.BitLen()), id, sequence)
	}
	var dst, next route.Addr
	if address.Is4() {
		dst = &route.Inet4Addr{IP: address.As4()}
		next = &route.Inet4Addr{IP: gateway.As4()}
	} else {
		dst = &route.Inet6Addr{IP: address.As16()}
		hop := gateway.As16()
		if gateway.IsLinkLocalUnicast() {
			binary.BigEndian.PutUint16(hop[2:4], uint16(index))
		}
		next = &route.Inet6Addr{IP: hop}
	}
	return &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    messageType,
		Flags:   unix.RTF_UP | unix.RTF_STATIC | unix.RTF_HOST | unix.RTF_GATEWAY,
		Index:   index,
		ID:      uintptr(id),
		Seq:     sequence,
		Addrs: []route.Addr{
			unix.RTAX_DST:     dst,
			unix.RTAX_GATEWAY: next,
			unix.RTAX_IFP:     &route.LinkAddr{Index: index},
		},
	}
}

func (self *urTunDarwinSockets) Routes() ([]urTunDarwinRoute, error) {
	routes := []urTunDarwinRoute{}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rib, err := route.FetchRIB(family, route.RIBTypeRoute, 0)
		if err != nil {
			return nil, err
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if routeMessage, ok := message.(*route.RouteMessage); ok {
				if held, ok := urTunDarwinParseRoute(routeMessage); ok {
					routes = append(routes, held)
				}
			}
		}
	}
	return routes, nil
}

// A dumped route as ur tun reads it: its destination with the mask's length, a host route's the address's whole, a
// route with no mask the default's where its destination is unspecified; its interface; and its gateway's address.
func urTunDarwinParseRoute(message *route.RouteMessage) (urTunDarwinRoute, bool) {
	held := urTunDarwinRoute{index: message.Index, flags: message.Flags}
	addr := func(i int) route.Addr {
		if i < len(message.Addrs) {
			return message.Addrs[i]
		}
		return nil
	}
	var dst netip.Addr
	switch value := addr(unix.RTAX_DST).(type) {
	case *route.Inet4Addr:
		dst = netip.AddrFrom4(value.IP)
	case *route.Inet6Addr:
		dst = netip.AddrFrom16(value.IP)
	default:
		return held, false
	}
	bits := dst.BitLen()
	if message.Flags&unix.RTF_HOST == 0 {
		var mask []byte
		switch value := addr(unix.RTAX_NETMASK).(type) {
		case *route.Inet4Addr:
			mask = value.IP[:]
		case *route.Inet6Addr:
			mask = value.IP[:]
		}
		switch {
		case mask != nil:
			bits, _ = net.IPMask(mask).Size()
		case dst.IsUnspecified():
			bits = 0
		}
	}
	prefix, err := dst.Prefix(bits)
	if err != nil {
		return held, false
	}
	held.dst = prefix
	if message.Flags&unix.RTF_GATEWAY != 0 {
		switch value := addr(unix.RTAX_GATEWAY).(type) {
		case *route.Inet4Addr:
			held.gateway = netip.AddrFrom4(value.IP)
		case *route.Inet6Addr:
			held.gateway = netip.AddrFrom16(value.IP)
		}
	}
	return held, true
}

// One open utun and what this interface set on it. Its configuration calls are serialized.
type urTunDarwinInterface struct {
	system *urTunDarwinSystem
	// the instance's device name, which names the resolver files this tun writes
	owner      string
	name       string
	index      int
	device     tun.Device
	eventsDone chan struct{}

	stateLock sync.Mutex
	// what it added, which Close and the next sets remove
	addresses   []netip.Addr
	routes      []netip.Prefix
	resolverSet bool
	// what the exits put on, which SetExits(false) and Close take off: IPv4's halves and IPv6's (QD-881), and connect's
	// binding to the interfaces of the host's default routes
	exitsHalves []netip.Prefix
	exitsBound  bool
	boundIndex4 int
	boundIndex6 int
	// the addresses the bridge carves, IPv4's then IPv6's, each sorted (SetCarved), and the host routes this interface
	// put on for those of them the host reaches only by its default route of their family, which go with that family's
	// halves
	carvedAddrs []netip.Addr
	hostRoutes  []urTunHostRoute
	closed      bool
}

var _ urTunNamedInterface = (*urTunDarwinInterface)(nil)
var _ urTunCarvedInterface = (*urTunDarwinInterface)(nil)

// The kernel's utun<n>.
func (self *urTunDarwinInterface) Name() string {
	return self.name
}

// wireguard's read, which puts each packet after a utun's 4-byte family header: the tun's read headroom leaves it room.
func (self *urTunDarwinInterface) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset < urTunDarwinFamilyByteCount {
		return 0, fmt.Errorf("a utun read needs %d bytes in front of each packet", urTunDarwinFamilyByteCount)
	}
	return self.device.Read(bufs, sizes, offset)
}

// The family header a utun puts in front of each packet.
const urTunDarwinFamilyByteCount = 4

func (self *urTunDarwinInterface) Write(bufs [][]byte, offset int) (int, error) {
	return self.device.Write(bufs, offset)
}

func (self *urTunDarwinInterface) BatchSize() int {
	return self.device.BatchSize()
}

// Adds each IPv4 address not on the device yet and removes each it added that addresses no longer holds.
func (self *urTunDarwinInterface) SetAddresses(addresses []netip.Addr) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return errUrTunClosed
	}
	kernel := self.system.kernel
	var setErr error
	kept := []netip.Addr{}
	for _, held := range self.addresses {
		if slices.Contains(addresses, held) {
			kept = append(kept, held)
			continue
		}
		if err := kernel.DeleteAddress(self.name, held); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			setErr = errors.Join(setErr, urTunDarwinError(err))
			kept = append(kept, held)
		}
	}
	for _, address := range addresses {
		if !address.Is4() || slices.Contains(kept, address) {
			continue
		}
		if err := kernel.AddAddress(self.name, address); err != nil {
			setErr = errors.Join(setErr, urTunDarwinError(err))
			continue
		}
		kept = append(kept, address)
	}
	self.addresses = kept
	return setErr
}

// Adds each IPv4 route not through the device yet and removes each it added that routes no longer holds. A route
// another holds at the same prefix is counted and left to it, and tried again at the next set.
func (self *urTunDarwinInterface) SetRoutes(routes []netip.Prefix) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return 0, errUrTunClosed
	}
	kernel := self.system.kernel
	var setErr error
	kept := []netip.Prefix{}
	for _, held := range self.routes {
		if slices.Contains(routes, held) {
			kept = append(kept, held)
			continue
		}
		if err := kernel.DeleteRoute(self.index, held); err != nil && !errors.Is(err, unix.ESRCH) {
			setErr = errors.Join(setErr, urTunDarwinError(err))
			kept = append(kept, held)
		}
	}
	conflictCount := 0
	for _, wanted := range routes {
		if !wanted.Addr().Is4() || slices.Contains(kept, wanted.Masked()) {
			continue
		}
		wanted = wanted.Masked()
		err := kernel.AddRoute(self.index, wanted)
		switch {
		case errors.Is(err, unix.EEXIST):
			conflictCount += 1
		case err != nil:
			setErr = errors.Join(setErr, urTunDarwinError(err))
		default:
			kept = append(kept, wanted)
		}
	}
	self.routes = kept
	return conflictCount, setErr
}

// bridge_dns_darwin.go's resolver files for the zones.
func (self *urTunDarwinInterface) SetResolver(resolver netip.Addr, zones []string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return "", errUrTunClosed
	}
	if len(zones) == 0 || !resolver.IsValid() {
		if self.resolverSet {
			urTunDarwinRevertResolver(self.system.resolverDirectory, self.owner)
			self.resolverSet = false
		}
		return "", nil
	}
	step, set := urTunDarwinSetResolver(self.system.resolverDirectory, self.owner, resolver, zones, self.system.settings,
		self.system.log)
	self.resolverSet = self.resolverSet || set
	return step, nil
}

// Under exits, binds connect's sockets to the interfaces of the host's own default routes, puts on the host routes of
// the carved addresses SetCarved last gave, of both families, by the default routes as they are now, so one that moved
// takes them with it, then puts IPv4's halves on the device and IPv6's after them (QD-881), and has connect's
// transports dial again where the binding is new or moved or a half went on, so no socket made before it stays in the
// tun's way. It refuses, and leaves nothing on, where no default route leaves by another interface, another program
// holds a half of either family, or the host has an IPv6 default route and IPv6's halves will not go on; where it has
// none, IPv4's halves stand alone, and no IPv6 address takes a host route. A host route that will not go on refuses
// nothing, and is SetCarved's to try again. Off exits, takes them off. Answers whether the default route rides the
// device.
func (self *urTunDarwinInterface) SetExits(exits bool) (bool, error) {
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
		table, err := self.system.kernel.Routes()
		if err != nil {
			return false, false, errors.Join(fmt.Errorf("the routes did not read (%v)", err), self.clearExitsWithLock())
		}
		default4, default6 := urTunDarwinDefaultRoutes(table, self.index)
		index4, index6 := default4.index, default6.index
		if index4 == 0 {
			return false, false, errors.Join(errUrTunExitsNoDefault, self.clearExitsWithLock())
		}
		// whether IPv6 leaves the host by a route of its own, which IPv6's halves must then take
		ipv6Routed := index6 != 0
		if index6 == 0 {
			index6 = index4
		}
		rebound := !self.exitsBound || self.boundIndex4 != index4 || self.boundIndex6 != index6
		if rebound {
			self.system.setEgressInterface(uint32(index4), uint32(index6))
			self.exitsBound, self.boundIndex4, self.boundIndex6 = true, index4, index6
		}
		// before the halves, so no lookup of a carved address meets one: IPv6's go by the IPv6 default route, so a host
		// with none, whose IPv6 halves may stay off, takes none
		_ = self.setHostRoutesWithLock(urTunDarwinHostRoutes(self.carvedAddrs, table, self.index, self.routes, self.hostRoutes))
		for _, half := range urTunExitsHalves() {
			if slices.Contains(self.exitsHalves, half) {
				continue
			}
			err := self.system.kernel.AddRoute(self.index, half)
			if errors.Is(err, unix.EEXIST) {
				err = errUrTunExitsHalfInUse
			}
			if err != nil {
				// nothing of a partial set stays on behind a refusal
				return false, false, errors.Join(err, self.clearExitsWithLock())
			}
			self.exitsHalves = append(self.exitsHalves, half)
			rebound = true
		}
		ipv6Added := false
		for _, half := range urTunExitsIpv6Halves() {
			if slices.Contains(self.exitsHalves, half) {
				continue
			}
			err := self.system.kernel.AddRoute(self.index, half)
			if err == nil {
				self.exitsHalves = append(self.exitsHalves, half)
				ipv6Added = true
				continue
			}
			if errors.Is(err, unix.EEXIST) {
				return false, false, errors.Join(errUrTunExitsHalfInUse, self.clearExitsWithLock())
			}
			if ipv6Routed {
				return false, false, errors.Join(fmt.Errorf("IPv6's default route did not go on, and the host's IPv6 "+
					"would leave outside the exits (%v)", err), self.clearExitsWithLock())
			}
			// no IPv6 leaves the host by a route of its own: IPv4's halves stand alone and the next call tries IPv6's
			// again, and what of them would not come off is the next clear's
			_ = self.clearHalvesWithLock(urTunExitsIpv6Halves())
			ipv6Added = false
			break
		}
		return rebound || ipv6Added, true, nil
	}()
	if rebound {
		// a socket made before the binding takes the tun's way from here: connect's transports dial again, bound
		self.system.networkChanged()
	}
	return defaultRoute, err
}

// Sets the addresses the bridge carves (§17.4), of both families (QD-869, QD-971): while a half of a family is on, that
// family's host routes follow at once, over the table as it reads now: one for each address the host reaches only by
// its default route of that family that holds none, those of addresses no longer carved, or that a route of the host's
// own has come to reach, off, and those the default route moved from under replaced by its gateway now. A family with
// no half on keeps none, and its list waits for SetExits(true), a host route a clear left on tried off again. Answers
// what would not go on or come off, which the next call tries again.
func (self *urTunDarwinInterface) SetCarved(addresses []netip.Addr) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return errUrTunClosed
	}
	carvedAddrs := urTunCarvedHostAddrs(addresses)
	self.carvedAddrs = carvedAddrs
	ipv4, ipv6 := self.halvesWithLock(true), self.halvesWithLock(false)
	if !ipv4 && !ipv6 {
		return self.setHostRoutesWithLock(nil)
	}
	if len(carvedAddrs) == 0 && len(self.hostRoutes) == 0 {
		return nil
	}
	table, err := self.system.kernel.Routes()
	if err != nil {
		// what is on stays as it is for the next call
		return fmt.Errorf("the routes did not read (%v)", err)
	}
	return self.setHostRoutesWithLock(urTunStandingHostRoutes(
		urTunDarwinHostRoutes(carvedAddrs, table, self.index, self.routes, self.hostRoutes), ipv4, ipv6))
}

// Sets the host routes to wanted (urTunSetHostRoutes): none for nil. Answers what would not go on or come off, kept as
// it is for the next call.
func (self *urTunDarwinInterface) setHostRoutesWithLock(wanted []urTunHostRoute) error {
	kernel := self.system.kernel
	var err error
	self.hostRoutes, err = urTunSetHostRoutes(self.hostRoutes, wanted, &urTunHostRouteCalls{
		add: func(hostRoute urTunHostRoute) error {
			return kernel.AddHostRoute(int(hostRoute.link), hostRoute.address, hostRoute.gateway)
		},
		remove: func(hostRoute urTunHostRoute) error {
			return kernel.DeleteHostRoute(int(hostRoute.link), hostRoute.address, hostRoute.gateway)
		},
		held: func(err error) bool {
			return errors.Is(err, unix.EEXIST)
		},
		gone: func(err error) bool {
			return errors.Is(err, unix.ESRCH)
		},
	})
	return err
}

// Takes off what the exits put on, the halves first, IPv4's then IPv6's, keeping account of what would not come off,
// so a later call tries it again; a family's carved addresses' host routes go once no half of that family is left,
// since until then a lookup of one still needs its own, and the binding goes once no half of either family is, since a
// half without it would take the daemon's own transport.
func (self *urTunDarwinInterface) clearExitsWithLock() error {
	clearErr := self.clearHalvesWithLock(self.exitsHalves)
	clearErr = errors.Join(clearErr, self.setHostRoutesWithLock(urTunStandingHostRoutes(self.hostRoutes,
		self.halvesWithLock(true), self.halvesWithLock(false))))
	if self.exitsBound && len(self.exitsHalves) == 0 {
		self.system.setEgressInterface(0, 0)
		self.exitsBound, self.boundIndex4, self.boundIndex6 = false, 0, 0
	}
	return clearErr
}

// Takes off those of halves the exits put on, in their order, keeping those that would not come off, which a later
// call tries again.
func (self *urTunDarwinInterface) clearHalvesWithLock(halves []netip.Prefix) error {
	var clearErr error
	kept := []netip.Prefix{}
	for _, half := range slices.Clone(self.exitsHalves) {
		if !slices.Contains(halves, half) {
			kept = append(kept, half)
			continue
		}
		if err := self.system.kernel.DeleteRoute(self.index, half); err != nil && !errors.Is(err, unix.ESRCH) {
			clearErr = errors.Join(clearErr, fmt.Errorf("the default route did not come off (%v)", err))
			kept = append(kept, half)
		}
	}
	self.exitsHalves = kept
	return clearErr
}

// Whether a half of a family is on, IPv4's where ipv4 and IPv6's otherwise, which that family's carved addresses' host
// routes stand by.
func (self *urTunDarwinInterface) halvesWithLock(ipv4 bool) bool {
	return slices.ContainsFunc(self.exitsHalves, func(half netip.Prefix) bool { return half.Addr().Is4() == ipv4 })
}

// Takes the exits off, the carved addresses' host routes with them, reverts the resolver, removes the routes and
// addresses it added, and closes the device, which the kernel destroys with whatever is left on it, a half that would
// not come off among them; a host route that waited on such a half leaves by another interface, which the kernel
// keeps, so it is taken off once the device is closed. Waits for the device's event listener to end.
func (self *urTunDarwinInterface) Close() error {
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
			urTunDarwinRevertResolver(self.system.resolverDirectory, self.owner)
			self.resolverSet = false
		}
		kernel := self.system.kernel
		for _, held := range self.routes {
			if err := kernel.DeleteRoute(self.index, held); err != nil && !errors.Is(err, unix.ESRCH) {
				closeErr = errors.Join(closeErr, err)
			}
		}
		self.routes = nil
		for _, held := range self.addresses {
			if err := kernel.DeleteAddress(self.name, held); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
				closeErr = errors.Join(closeErr, err)
			}
		}
		self.addresses = nil
		closeErr = errors.Join(closeErr, self.device.Close())
		// no half outlives the device, so none of these is needed after it
		self.exitsHalves = nil
		closeErr = errors.Join(closeErr, self.setHostRoutesWithLock(nil))
	}()
	<-self.eventsDone
	return closeErr
}
