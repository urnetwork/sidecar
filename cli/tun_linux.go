//go:build linux

// ur tun's device on Linux and WSL2 (§17.11; BRIDGE-M4-18): the tun is wireguard's (golang.zx2c4.com/wireguard/tun),
// cloned from /dev/net/tun with virtio offloads where the kernel has them, and everything set on it goes through
// rtnetlink from the daemon itself, never a spawned ip, which would not inherit a CAP_NET_ADMIN granted to ur by file:
//
//	device     ur-<instance>, up, its MTU the settings'; creating it takes CAP_NET_ADMIN or root, refused clearly
//	           otherwise (errUrTunPrivilege), and a host with no /dev/net/tun is named as such
//	addresses  this host's overlay /32s on the device, so the kernel picks one as the source of what the tun carries
//	routes     each of Bridge.Routes() through the device in the main table, ur's protocol and the settings' metric,
//	           created exclusively: a route another interface holds at the same prefix and metric keeps it, counted
//	resolver   bridge_dns_linux.go's
//	local      bridge_local_linux.go's
//
// Only what this interface added is removed: routes by ur's protocol and the device, addresses by the device. Close
// removes them, reverts the resolver and closes the device, which the kernel deletes with whatever was left on it.

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
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/urnetwork/sidecar"
)

func init() {
	urTunPlatform = newUrTunLinuxSystem
}

// rtnetlink's protocol byte on the tun's routes: an otherwise unused value, 'u', so ur's routes read as such and a
// delete matches only them.
const urTunRouteProtocol = 0x75

// rtattr's and nlmsghdr's alignment (RTA_ALIGNTO, NLMSG_ALIGNTO).
const urNetlinkAlignment = 4

// The cloning device.
const urTunCloneDevicePath = "/dev/net/tun"

// The platform's half of ur tun on Linux. Safe for concurrent use.
type urTunLinuxSystem struct {
	settings *urTunSettings
	log      sidecar.Logger
	// numbers each netlink request
	sequenceLock sync.Mutex
	sequence     uint32
}

var _ urTunSystem = (*urTunLinuxSystem)(nil)

func newUrTunLinuxSystem(settings *urTunSettings, log sidecar.Logger) urTunSystem {
	if settings == nil {
		settings = defaultUrTunSettings()
	}
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	return &urTunLinuxSystem{settings: settings, log: log}
}

// What a host that lacks a privilege or the device answers, as the person reads it.
func urTunLinuxError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return fmt.Errorf("%w (%v)", errUrTunPrivilege, err)
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENODEV), errors.Is(err, unix.ENXIO):
		return fmt.Errorf("%w (%v)", errUrTunNoDevice, err)
	}
	return err
}

// Opens the device, with virtio offloads where the kernel takes them and without where it does not, then sets it up.
func (self *urTunLinuxSystem) Open(name string, mtu int) (urTunInterface, error) {
	device, err := urTunLinuxCreate(name, mtu, true)
	if err != nil && !errors.Is(err, errUrTunPrivilege) && !errors.Is(err, errUrTunNoDevice) {
		// a kernel without TUNSETOFFLOAD's flags, or a sandbox's tun: the plain device carries the same packets
		device, err = urTunLinuxCreate(name, mtu, false)
	}
	if err != nil {
		return nil, err
	}
	iface := &urTunLinuxInterface{
		system:     self,
		name:       name,
		device:     device,
		eventsDone: make(chan struct{}),
	}
	// wireguard's listener blocks once five events wait unread, which would hold its close
	go func() {
		defer close(iface.eventsDone)
		for range device.Events() {
		}
	}()
	link, err := net.InterfaceByName(name)
	if err != nil {
		iface.Close()
		return nil, err
	}
	iface.index = link.Index
	if err := self.ifaceUp(link.Index); err != nil {
		iface.Close()
		return nil, urTunLinuxError(err)
	}
	return iface, nil
}

// Clones name from /dev/net/tun as wireguard's device, closing what it opened on any failure (wireguard's own
// CreateTUN keeps the descriptor of a refused clone).
func urTunLinuxCreate(name string, mtu int, offload bool) (tun.Device, error) {
	fd, err := unix.Open(urTunCloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, urTunLinuxError(err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if offload {
		flags |= unix.IFF_VNET_HDR
	}
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EBUSY) {
			return nil, fmt.Errorf("the device %s is held by another program", name)
		}
		return nil, urTunLinuxError(err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), urTunCloneDevicePath)
	device, err := tun.CreateTUNFromFile(file, mtu)
	if err != nil {
		file.Close()
		return nil, urTunLinuxError(err)
	}
	return device, nil
}

// Sets the link up.
func (self *urTunLinuxSystem) ifaceUp(index int) error {
	body := make([]byte, unix.SizeofIfInfomsg)
	body[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(body[4:8], uint32(index))
	binary.NativeEndian.PutUint32(body[8:12], unix.IFF_UP)
	binary.NativeEndian.PutUint32(body[12:16], unix.IFF_UP)
	return self.request(unix.RTM_NEWLINK, 0, body)
}

// The interface other than name with a unicast route inside prefix, in any table but local's; "" for none. A route
// that covers the whole prefix from outside it, as a carrier's 100.64/10 does, is no bridge's and does not count, nor
// does a local address's own route.
func (self *urTunLinuxSystem) RoutedElsewhere(name string, prefix netip.Prefix) (string, error) {
	ownIndex := urTunLinuxIndex(name)
	routes, err := urTunLinuxRoutes(unix.AF_INET)
	if err != nil {
		return "", err
	}
	for _, route := range routes {
		if route.routeType != unix.RTN_UNICAST || route.table == unix.RT_TABLE_LOCAL || !route.dst.IsValid() ||
			route.dst.Bits() < prefix.Bits() || !prefix.Contains(route.dst.Addr()) {
			continue
		}
		for _, index := range route.oifs {
			if index == ownIndex || index == 0 {
				continue
			}
			if link, err := net.InterfaceByIndex(index); err == nil {
				return link.Name, nil
			}
			return fmt.Sprintf("index %d", index), nil
		}
	}
	return "", nil
}

// The index of name, 0 for none.
func urTunLinuxIndex(name string) int {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return 0
	}
	return link.Index
}

// One route of a dump.
type urTunLinuxRoute struct {
	family    uint8
	table     uint32
	routeType uint8
	// the destination, the default 0/0 or ::/0 when the route names none
	dst netip.Prefix
	// each next hop's interface and gateway, a gateway invalid where it has none
	oifs     []int
	gateways []netip.Addr
}

// Every route of family in every table, AF_UNSPEC for both.
func urTunLinuxRoutes(family int) ([]urTunLinuxRoute, error) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETROUTE, family)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	routes := []urTunLinuxRoute{}
	for i := range messages {
		message := &messages[i]
		if message.Header.Type != unix.RTM_NEWROUTE || len(message.Data) < unix.SizeofRtMsg {
			continue
		}
		route := urTunLinuxRoute{
			family:    message.Data[0],
			table:     uint32(message.Data[4]),
			routeType: message.Data[7],
		}
		dstBits := int(message.Data[1])
		attributes, err := syscall.ParseNetlinkRouteAttr(message)
		if err != nil {
			continue
		}
		var dst netip.Addr
		for _, attribute := range attributes {
			switch attribute.Attr.Type {
			case unix.RTA_DST:
				dst, _ = netip.AddrFromSlice(attribute.Value)
			case unix.RTA_TABLE:
				if len(attribute.Value) == 4 {
					route.table = binary.NativeEndian.Uint32(attribute.Value)
				}
			case unix.RTA_OIF:
				if len(attribute.Value) == 4 {
					route.oifs = append(route.oifs, int(int32(binary.NativeEndian.Uint32(attribute.Value))))
				}
			case unix.RTA_GATEWAY:
				if gateway, ok := netip.AddrFromSlice(attribute.Value); ok {
					route.gateways = append(route.gateways, gateway)
				}
			case unix.RTA_MULTIPATH:
				oifs, gateways := urTunLinuxNextHops(attribute.Value)
				route.oifs = append(route.oifs, oifs...)
				route.gateways = append(route.gateways, gateways...)
			}
		}
		if !dst.IsValid() {
			switch route.family {
			case unix.AF_INET:
				dst = netip.IPv4Unspecified()
			case unix.AF_INET6:
				dst = netip.IPv6Unspecified()
			default:
				continue
			}
		}
		if prefix, err := dst.Prefix(dstBits); err == nil {
			route.dst = prefix
		}
		routes = append(routes, route)
	}
	return routes, nil
}

// A multipath route's next hops (struct rtnexthop, each followed by its attributes): their interfaces and gateways.
func urTunLinuxNextHops(value []byte) ([]int, []netip.Addr) {
	const nextHopByteCount = 8
	oifs := []int{}
	gateways := []netip.Addr{}
	for rest := value; nextHopByteCount <= len(rest); {
		length := int(binary.NativeEndian.Uint16(rest[0:2]))
		if length < nextHopByteCount || len(rest) < length {
			break
		}
		oifs = append(oifs, int(int32(binary.NativeEndian.Uint32(rest[4:8]))))
		for attributes := rest[nextHopByteCount:length]; unix.SizeofRtAttr <= len(attributes); {
			attributeLength := int(binary.NativeEndian.Uint16(attributes[0:2]))
			attributeType := binary.NativeEndian.Uint16(attributes[2:4])
			if attributeLength < unix.SizeofRtAttr || len(attributes) < attributeLength {
				break
			}
			if attributeType == unix.RTA_GATEWAY {
				if gateway, ok := netip.AddrFromSlice(attributes[unix.SizeofRtAttr:attributeLength]); ok {
					gateways = append(gateways, gateway)
				}
			}
			attributes = attributes[min(len(attributes), urNetlinkAlign(attributeLength)):]
		}
		rest = rest[min(len(rest), urNetlinkAlign(length)):]
	}
	return oifs, gateways
}

// One address of a dump.
type urTunLinuxAddress struct {
	index   int
	address netip.Addr
}

// Every address of every interface.
func urTunLinuxAddresses() ([]urTunLinuxAddress, error) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETADDR, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	addresses := []urTunLinuxAddress{}
	for i := range messages {
		message := &messages[i]
		if message.Header.Type != unix.RTM_NEWADDR || len(message.Data) < unix.SizeofIfAddrmsg {
			continue
		}
		index := int(binary.NativeEndian.Uint32(message.Data[4:8]))
		attributes, err := syscall.ParseNetlinkRouteAttr(message)
		if err != nil {
			continue
		}
		var local, peer []byte
		for _, attribute := range attributes {
			switch attribute.Attr.Type {
			case unix.IFA_LOCAL:
				local = attribute.Value
			case unix.IFA_ADDRESS:
				peer = attribute.Value
			}
		}
		// IFA_LOCAL is the interface's own where a point-to-point link sets IFA_ADDRESS to its peer
		value := local
		if value == nil {
			value = peer
		}
		if address, ok := netip.AddrFromSlice(value); ok {
			addresses = append(addresses, urTunLinuxAddress{index: index, address: address.Unmap()})
		}
	}
	return addresses, nil
}

// x rounded up to the netlink alignment.
func urNetlinkAlign(x int) int {
	return (x + urNetlinkAlignment - 1) &^ (urNetlinkAlignment - 1)
}

// One rtattr of attributeType carrying value, padded.
func urNetlinkAttribute(attributeType uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	attribute := make([]byte, urNetlinkAlign(length))
	binary.NativeEndian.PutUint16(attribute[0:2], uint16(length))
	binary.NativeEndian.PutUint16(attribute[2:4], attributeType)
	copy(attribute[unix.SizeofRtAttr:], value)
	return attribute
}

// A uint32 attribute's value in host order.
func urNetlinkUint32(value uint32) []byte {
	encoded := make([]byte, 4)
	binary.NativeEndian.PutUint32(encoded, value)
	return encoded
}

// The next request's number.
func (self *urTunLinuxSystem) nextSequence() uint32 {
	self.sequenceLock.Lock()
	defer self.sequenceLock.Unlock()
	self.sequence += 1
	return self.sequence
}

// One rtnetlink request of messageType with flags and body, waiting PlatformTimeout at most for its acknowledgement.
// An error the kernel answers is its errno.
func (self *urTunLinuxSystem) request(messageType uint16, flags uint16, body []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	timeout := unix.NsecToTimeval(max(self.settings.PlatformTimeout, time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	sequence := self.nextSequence()
	length := unix.SizeofNlMsghdr + len(body)
	message := make([]byte, length)
	binary.NativeEndian.PutUint32(message[0:4], uint32(length))
	binary.NativeEndian.PutUint16(message[4:6], messageType)
	binary.NativeEndian.PutUint16(message[6:8], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(message[8:12], sequence)
	copy(message[unix.SizeofNlMsghdr:], body)
	if err := unix.Sendto(fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	// an acknowledgement of a refusal carries the request after its errno
	answer := make([]byte, max(os.Getpagesize(), unix.SizeofNlMsghdr+4+length))
	for {
		n, _, err := unix.Recvfrom(fd, answer, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("no answer to a netlink request: %w", err)
		}
		replies, err := syscall.ParseNetlinkMessage(answer[:n])
		if err != nil {
			return err
		}
		for _, reply := range replies {
			if reply.Header.Seq != sequence || reply.Header.Type != unix.NLMSG_ERROR || len(reply.Data) < 4 {
				continue
			}
			if code := int32(binary.NativeEndian.Uint32(reply.Data[0:4])); code != 0 {
				return unix.Errno(-code)
			}
			return nil
		}
	}
}

// The address message of an IPv4 /32 on index.
func urTunLinuxAddressBody(index int, address netip.Addr) []byte {
	octets := address.As4()
	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0] = unix.AF_INET
	body[1] = 32
	body[3] = unix.RT_SCOPE_UNIVERSE
	binary.NativeEndian.PutUint32(body[4:8], uint32(index))
	body = append(body, urNetlinkAttribute(unix.IFA_LOCAL, octets[:])...)
	body = append(body, urNetlinkAttribute(unix.IFA_ADDRESS, octets[:])...)
	return body
}

// The route message of an IPv4 prefix through index, ur's, at metric: for an add, unicast in the link's scope; for a
// delete, any type and scope of ur's protocol through index.
func urTunLinuxRouteBody(index int, prefix netip.Prefix, metric uint32, add bool) []byte {
	octets := prefix.Masked().Addr().As4()
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_INET
	body[1] = uint8(prefix.Bits())
	body[4] = unix.RT_TABLE_MAIN
	body[5] = urTunRouteProtocol
	if add {
		body[6] = unix.RT_SCOPE_LINK
		body[7] = unix.RTN_UNICAST
	} else {
		body[6] = unix.RT_SCOPE_NOWHERE
	}
	body = append(body, urNetlinkAttribute(unix.RTA_DST, octets[:])...)
	body = append(body, urNetlinkAttribute(unix.RTA_OIF, urNetlinkUint32(uint32(index)))...)
	body = append(body, urNetlinkAttribute(unix.RTA_PRIORITY, urNetlinkUint32(metric))...)
	return body
}

// One open device and what this interface set on it. Its configuration calls are serialized.
type urTunLinuxInterface struct {
	system     *urTunLinuxSystem
	name       string
	index      int
	device     tun.Device
	eventsDone chan struct{}

	stateLock sync.Mutex
	// what it added, which Close and the next sets remove
	addresses   []netip.Addr
	routes      []netip.Prefix
	resolverSet bool
	closed      bool
}

var _ urTunInterface = (*urTunLinuxInterface)(nil)

// wireguard's read: a batch dropped past the slots given is errUrTunSegmentsDropped, which goes on.
func (self *urTunLinuxInterface) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := self.device.Read(bufs, sizes, offset)
	if errors.Is(err, tun.ErrTooManySegments) {
		return n, fmt.Errorf("%w: %w", errUrTunSegmentsDropped, err)
	}
	return n, err
}

func (self *urTunLinuxInterface) Write(bufs [][]byte, offset int) (int, error) {
	return self.device.Write(bufs, offset)
}

func (self *urTunLinuxInterface) BatchSize() int {
	return self.device.BatchSize()
}

// Adds each IPv4 address not on the device yet and removes each it added that addresses no longer holds.
func (self *urTunLinuxInterface) SetAddresses(addresses []netip.Addr) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return errUrTunClosed
	}
	var setErr error
	kept := []netip.Addr{}
	for _, held := range self.addresses {
		if slices.Contains(addresses, held) {
			kept = append(kept, held)
			continue
		}
		err := self.system.request(unix.RTM_DELADDR, 0, urTunLinuxAddressBody(self.index, held))
		if err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
			setErr = errors.Join(setErr, urTunLinuxError(err))
			kept = append(kept, held)
		}
	}
	for _, address := range addresses {
		if !address.Is4() || slices.Contains(kept, address) {
			continue
		}
		err := self.system.request(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, urTunLinuxAddressBody(self.index, address))
		if err != nil {
			setErr = errors.Join(setErr, urTunLinuxError(err))
			continue
		}
		kept = append(kept, address)
	}
	self.addresses = kept
	return setErr
}

// Adds each IPv4 route not through the device yet, exclusively, and removes each it added that routes no longer holds.
// A route another holds at the same prefix and metric is counted and left to it, and tried again at the next set.
func (self *urTunLinuxInterface) SetRoutes(routes []netip.Prefix) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return 0, errUrTunClosed
	}
	metric := self.system.settings.RouteMetric
	var setErr error
	kept := []netip.Prefix{}
	for _, held := range self.routes {
		if slices.Contains(routes, held) {
			kept = append(kept, held)
			continue
		}
		err := self.system.request(unix.RTM_DELROUTE, 0, urTunLinuxRouteBody(self.index, held, metric, false))
		if err != nil && !errors.Is(err, unix.ESRCH) {
			setErr = errors.Join(setErr, urTunLinuxError(err))
			kept = append(kept, held)
		}
	}
	conflictCount := 0
	for _, route := range routes {
		if !route.Addr().Is4() || slices.Contains(kept, route) {
			continue
		}
		route = route.Masked()
		err := self.system.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, urTunLinuxRouteBody(self.index, route, metric, true))
		switch {
		case errors.Is(err, unix.EEXIST):
			conflictCount += 1
		case err != nil:
			setErr = errors.Join(setErr, urTunLinuxError(err))
		default:
			kept = append(kept, route)
		}
	}
	self.routes = kept
	return conflictCount, setErr
}

// bridge_dns_linux.go's resolver for this device's link.
func (self *urTunLinuxInterface) SetResolver(resolver netip.Addr, zones []string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return "", errUrTunClosed
	}
	if len(zones) == 0 || !resolver.IsValid() {
		if self.resolverSet {
			urTunLinuxRevertResolver(self.index, self.system.settings.PlatformTimeout)
			self.resolverSet = false
		}
		return "", nil
	}
	step, set := urTunLinuxSetResolver(self.index, self.name, resolver, zones, self.system.settings.PlatformTimeout, self.system.log)
	self.resolverSet = self.resolverSet || set
	return step, nil
}

// Reverts the resolver, removes the routes and addresses it added, and closes the device, which the kernel deletes
// with whatever is left on it. Waits for the device's event listener to end.
func (self *urTunLinuxInterface) Close() error {
	var closeErr error
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return
		}
		self.closed = true
		if self.resolverSet {
			urTunLinuxRevertResolver(self.index, self.system.settings.PlatformTimeout)
			self.resolverSet = false
		}
		metric := self.system.settings.RouteMetric
		for _, held := range self.routes {
			if err := self.system.request(unix.RTM_DELROUTE, 0, urTunLinuxRouteBody(self.index, held, metric, false)); err != nil &&
				!errors.Is(err, unix.ESRCH) {
				closeErr = errors.Join(closeErr, err)
			}
		}
		self.routes = nil
		for _, held := range self.addresses {
			if err := self.system.request(unix.RTM_DELADDR, 0, urTunLinuxAddressBody(self.index, held)); err != nil &&
				!errors.Is(err, unix.EADDRNOTAVAIL) {
				closeErr = errors.Join(closeErr, err)
			}
		}
		self.addresses = nil
		closeErr = errors.Join(closeErr, self.device.Close())
	}()
	<-self.eventsDone
	return closeErr
}
