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
//	exits      under the egress mode exits, the default route through the device in a table of its own, ExitsTable,
//	           and wg-quick's two rules ahead of the main table's: `lookup main suppress_prefixlength 0`, so every route
//	           of the main table but its default keeps its way, then `not fwmark <ExitsMark> lookup <ExitsTable>`, so
//	           the rest takes the tun but for the daemon's own connect sockets, which carry connect's egress mark
//	           (QD-800); the mark goes on first and comes off last, connect's transports dial again once the rules are
//	           on, so no socket made before the mark stays in the tun's way, and nothing is carved by address
//
// Only what this interface added is removed: routes and rules by ur's protocol, routes by the device too, addresses by
// the device. Close takes the exits off, removes the routes and addresses, reverts the resolver and closes the device,
// which the kernel deletes with whatever was left on it.

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/urnetwork/connect"
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

// The kernel's IPv4 settings of each interface, and of all of them, rp_filter among them.
const urTunLinuxIpv4ConfPath = "/proc/sys/net/ipv4/conf"

// struct fib_rule_hdr's size: a policy rule message's body before its attributes.
const urTunLinuxRuleHeaderByteCount = 12

// Why the default route stays off the tun under exits, besides a refusal of the kernel's.
var (
	// Another program's route is in the exits table, which ur tun's default route would join.
	errUrTunExitsTableInUse = errors.New("another program's routes are in the routing table the exits use")
	// Another program's policy rule matches the exits mark or reads the exits table, which the daemon's own sockets or
	// the tun's route would then answer to.
	errUrTunExitsMarkInUse = errors.New("another program's policy rule uses the mark or the table the exits use")
	// A reply to the daemon's own socket arrives unmarked, so a strict reverse path filter's lookup of its way back
	// finds the tun and drops it.
	errUrTunExitsStrictReversePath = errors.New("the reverse path filter is strict (rp_filter 1), which would drop " +
		"the daemon's own replies under the default route")
)

// The platform's half of ur tun on Linux. Safe for concurrent use.
type urTunLinuxSystem struct {
	settings *urTunSettings
	log      sidecar.Logger
	// numbers each netlink request
	sequenceLock sync.Mutex
	sequence     uint32

	// What the exits reach of the host, the kernel's and connect's own outside a test: rtnetlink in place of the
	// kernel's where set, IPv4's per-interface settings, an interface's name, connect's egress mark, and connect's
	// network-change kick, which has the daemon's transports dial again on sockets the mark is on.
	netlink        urTunNetlink
	ipv4ConfPath   string
	linkName       func(index int) (string, error)
	setEgressMark  func(mark uint32)
	networkChanged func()
}

var _ urTunSystem = (*urTunLinuxSystem)(nil)

// What ur tun asks of rtnetlink, a test's recorder standing in for the kernel.
type urTunNetlink interface {
	// One request of messageType with flags and body, acknowledged: an error the kernel answers is its errno.
	Request(messageType uint16, flags uint16, body []byte) error
	// Every route of family in every table.
	Routes(family int) ([]urTunLinuxRoute, error)
	// Every policy rule of family.
	Rules(family int) ([]urTunLinuxRule, error)
}

func newUrTunLinuxSystem(settings *urTunSettings, log sidecar.Logger) urTunSystem {
	if settings == nil {
		settings = defaultUrTunSettings()
	}
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	return &urTunLinuxSystem{
		settings:       settings,
		log:            log,
		ipv4ConfPath:   urTunLinuxIpv4ConfPath,
		linkName:       urTunLinuxLinkName,
		setEgressMark:  connect.SetEgressMark,
		networkChanged: connect.NetworkChanged,
	}
}

// The name of the interface at index.
func urTunLinuxLinkName(index int) (string, error) {
	link, err := net.InterfaceByIndex(index)
	if err != nil {
		return "", err
	}
	return link.Name, nil
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
	protocol  uint8
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
			protocol:  message.Data[5],
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

// One policy rule of a dump.
type urTunLinuxRule struct {
	family   uint8
	table    uint32
	action   uint8
	flags    uint32
	priority uint32
	// the fwmark it matches, when markSet
	mark    uint32
	markSet bool
	// suppress_prefixlength, -1 for none
	suppressPrefixLength int
	protocol             uint8
}

// Every policy rule of family.
func urTunLinuxRules(family int) ([]urTunLinuxRule, error) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETRULE, family)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	rules := []urTunLinuxRule{}
	for i := range messages {
		message := &messages[i]
		if message.Header.Type != unix.RTM_NEWRULE || len(message.Data) < urTunLinuxRuleHeaderByteCount {
			continue
		}
		rules = append(rules, urTunLinuxParseRule(message.Data))
	}
	return rules, nil
}

// A rule message's body as a rule: struct fib_rule_hdr, then its attributes, FRA_TABLE naming the table over the
// header's one byte.
func urTunLinuxParseRule(data []byte) urTunLinuxRule {
	rule := urTunLinuxRule{
		family:               data[0],
		table:                uint32(data[4]),
		action:               data[7],
		flags:                binary.NativeEndian.Uint32(data[8:12]),
		suppressPrefixLength: -1,
	}
	for _, attribute := range urNetlinkAttributes(data[urTunLinuxRuleHeaderByteCount:]) {
		switch attribute.attributeType {
		case unix.FRA_TABLE:
			if len(attribute.value) == 4 {
				rule.table = binary.NativeEndian.Uint32(attribute.value)
			}
		case unix.FRA_PRIORITY:
			if len(attribute.value) == 4 {
				rule.priority = binary.NativeEndian.Uint32(attribute.value)
			}
		case unix.FRA_FWMARK:
			if len(attribute.value) == 4 {
				rule.mark = binary.NativeEndian.Uint32(attribute.value)
				rule.markSet = true
			}
		case unix.FRA_SUPPRESS_PREFIXLEN:
			if len(attribute.value) == 4 {
				rule.suppressPrefixLength = int(int32(binary.NativeEndian.Uint32(attribute.value)))
			}
		case unix.FRA_PROTOCOL:
			if 1 <= len(attribute.value) {
				rule.protocol = attribute.value[0]
			}
		}
	}
	return rule
}

// The rule message of one of the exits' two rules, at priority and of ur's protocol, so a delete matches only ur's
// (wg-quick's rules): with suppress, `lookup main suppress_prefixlength 0`, which keeps every route of the main table
// but its default ahead of the tun; without, `not fwmark <mark> lookup <table>`, which sends everything but the
// daemon's own marked sockets to the exits table, whose default route is the tun.
func urTunLinuxRuleBody(priority uint32, suppress bool, table uint32, mark uint32) []byte {
	body := make([]byte, urTunLinuxRuleHeaderByteCount)
	body[0] = unix.AF_INET
	body[7] = unix.FR_ACT_TO_TBL
	lookup := table
	if suppress {
		lookup = unix.RT_TABLE_MAIN
	} else {
		binary.NativeEndian.PutUint32(body[8:12], unix.FIB_RULE_INVERT)
	}
	// the header's one byte names a table under 256; FRA_TABLE names any, and wins
	if lookup < 256 {
		body[4] = uint8(lookup)
	}
	body = append(body, urNetlinkAttribute(unix.FRA_PRIORITY, urNetlinkUint32(priority))...)
	body = append(body, urNetlinkAttribute(unix.FRA_TABLE, urNetlinkUint32(lookup))...)
	if suppress {
		body = append(body, urNetlinkAttribute(unix.FRA_SUPPRESS_PREFIXLEN, urNetlinkUint32(0))...)
	} else {
		body = append(body, urNetlinkAttribute(unix.FRA_FWMARK, urNetlinkUint32(mark))...)
		body = append(body, urNetlinkAttribute(unix.FRA_FWMASK, urNetlinkUint32(math.MaxUint32))...)
	}
	body = append(body, urNetlinkAttribute(unix.FRA_PROTOCOL, []byte{urTunRouteProtocol})...)
	return body
}

// One rtattr of a message.
type urNetlinkAttr struct {
	attributeType uint16
	value         []byte
}

// data's rtattrs, as far as they parse, each type without its nested and byte order flags.
func urNetlinkAttributes(data []byte) []urNetlinkAttr {
	attributes := []urNetlinkAttr{}
	for rest := data; unix.SizeofRtAttr <= len(rest); {
		length := int(binary.NativeEndian.Uint16(rest[0:2]))
		if length < unix.SizeofRtAttr || len(rest) < length {
			break
		}
		attributes = append(attributes, urNetlinkAttr{
			attributeType: binary.NativeEndian.Uint16(rest[2:4]) &^ (unix.NLA_F_NESTED | unix.NLA_F_NET_BYTEORDER),
			value:         rest[unix.SizeofRtAttr:length],
		})
		rest = rest[min(len(rest), urNetlinkAlign(length)):]
	}
	return attributes
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

// One rtnetlink request of messageType with flags and body, waiting PlatformTimeout at most for its acknowledgement,
// or the stand-in's. An error the kernel answers is its errno.
func (self *urTunLinuxSystem) request(messageType uint16, flags uint16, body []byte) error {
	if self.netlink != nil {
		return self.netlink.Request(messageType, flags, body)
	}
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

// Every route of family, the kernel's or the stand-in's.
func (self *urTunLinuxSystem) routes(family int) ([]urTunLinuxRoute, error) {
	if self.netlink != nil {
		return self.netlink.Routes(family)
	}
	return urTunLinuxRoutes(family)
}

// Every policy rule of family, the kernel's or the stand-in's.
func (self *urTunLinuxSystem) rules(family int) ([]urTunLinuxRule, error) {
	if self.netlink != nil {
		return self.netlink.Rules(family)
	}
	return urTunLinuxRules(family)
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

// The route message of an IPv4 prefix through index in table, ur's, at metric: for an add, unicast in the link's scope;
// for a delete, any type and scope of ur's protocol through index. The default route names no destination.
func urTunLinuxRouteBody(index int, prefix netip.Prefix, table uint32, metric uint32, add bool) []byte {
	octets := prefix.Masked().Addr().As4()
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_INET
	body[1] = uint8(prefix.Bits())
	// the header's one byte names a table under 256; RTA_TABLE names any, and wins
	if table < 256 {
		body[4] = uint8(table)
	}
	body[5] = urTunRouteProtocol
	if add {
		body[6] = unix.RT_SCOPE_LINK
		body[7] = unix.RTN_UNICAST
	} else {
		body[6] = unix.RT_SCOPE_NOWHERE
	}
	if 0 < prefix.Bits() {
		body = append(body, urNetlinkAttribute(unix.RTA_DST, octets[:])...)
	}
	body = append(body, urNetlinkAttribute(unix.RTA_OIF, urNetlinkUint32(uint32(index)))...)
	body = append(body, urNetlinkAttribute(unix.RTA_PRIORITY, urNetlinkUint32(metric))...)
	body = append(body, urNetlinkAttribute(unix.RTA_TABLE, urNetlinkUint32(table))...)
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
	// what the exits put on, which SetExits(false) and Close take off: connect's egress mark, the default route in the
	// exits table, and its two rules
	exitsMark         bool
	exitsRoute        bool
	exitsSuppressRule bool
	exitsMarkRule     bool
	closed            bool
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
		err := self.system.request(unix.RTM_DELROUTE, 0, urTunLinuxRouteBody(self.index, held, unix.RT_TABLE_MAIN, metric, false))
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
		err := self.system.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, urTunLinuxRouteBody(self.index, route, unix.RT_TABLE_MAIN, metric, true))
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

// Under exits, marks the daemon's own connect sockets, then puts the default route through the device in the exits table
// and wg-quick's two rules ahead of the main table's (the file's comment), and has connect's transports dial again, so
// no socket made before the mark stays in the tun's way. It refuses, and leaves nothing on, where another program holds
// the table or the mark, or a strict reverse path filter would drop the daemon's replies. Off exits, takes them off.
// Answers whether the default route rides the device.
func (self *urTunLinuxInterface) SetExits(exits bool) (bool, error) {
	installed, defaultRoute, err := func() (bool, bool, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false, false, errUrTunClosed
		}
		if !exits {
			err := self.clearExitsWithLock()
			return false, self.exitsMarkRule && self.exitsRoute, err
		}
		if self.exitsMark && self.exitsRoute && self.exitsSuppressRule && self.exitsMarkRule {
			return false, true, nil
		}
		if err := self.system.exitsRefusal(self.index); err != nil {
			return false, false, errors.Join(err, self.clearExitsWithLock())
		}
		if err := self.setExitsWithLock(); err != nil {
			// nothing of a partial set stays on behind a refusal
			return false, false, errors.Join(err, self.clearExitsWithLock())
		}
		return true, true, nil
	}()
	if installed {
		// a socket made before the mark takes the tun's way from here: connect's transports dial again, marked
		self.system.networkChanged()
	}
	return defaultRoute, err
}

// Puts on what the exits need that is not on yet: the mark first, so every socket connect makes from here keeps
// today's route, then the default route in the exits table, the rule that keeps the main table's other routes ahead of
// it, and last the rule that sends the rest to it.
func (self *urTunLinuxInterface) setExitsWithLock() error {
	settings := self.system.settings
	if !self.exitsMark {
		self.system.setEgressMark(settings.ExitsMark)
		self.exitsMark = true
	}
	if !self.exitsRoute {
		body := urTunLinuxRouteBody(self.index, netip.PrefixFrom(netip.IPv4Unspecified(), 0), settings.ExitsTable,
			settings.RouteMetric, true)
		if err := self.system.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
			return fmt.Errorf("the default route did not go on (%v)", err)
		}
		self.exitsRoute = true
	}
	// a rule already there at the same priority, ur's protocol on it, is this daemon's from an end it did not see
	if !self.exitsSuppressRule {
		body := urTunLinuxRuleBody(settings.ExitsRulePriority, true, settings.ExitsTable, settings.ExitsMark)
		if err := self.system.request(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil &&
			!errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("the rule that keeps the main table's routes ahead did not go on (%v)", err)
		}
		self.exitsSuppressRule = true
	}
	if !self.exitsMarkRule {
		body := urTunLinuxRuleBody(settings.ExitsRulePriority+1, false, settings.ExitsTable, settings.ExitsMark)
		if err := self.system.request(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil &&
			!errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("the rule that sends unmarked traffic to the tun did not go on (%v)", err)
		}
		self.exitsMarkRule = true
	}
	return nil
}

// Takes off what the exits put on, the rule that sends traffic to the tun first, keeping account of what would not come
// off, so a later call tries it again. While that rule stays, the main table's rule ahead of it and the mark stay too,
// and the default route goes anyway, so a stuck rule finds an empty table and leaves the rest to the main table.
func (self *urTunLinuxInterface) clearExitsWithLock() error {
	settings := self.system.settings
	var clearErr error
	if self.exitsMarkRule {
		body := urTunLinuxRuleBody(settings.ExitsRulePriority+1, false, settings.ExitsTable, settings.ExitsMark)
		if err := self.system.request(unix.RTM_DELRULE, 0, body); err != nil && !errors.Is(err, unix.ENOENT) {
			clearErr = errors.Join(clearErr, fmt.Errorf("the rule that sends unmarked traffic to the tun did not come off (%v)", err))
		} else {
			self.exitsMarkRule = false
		}
	}
	if self.exitsRoute {
		body := urTunLinuxRouteBody(self.index, netip.PrefixFrom(netip.IPv4Unspecified(), 0), settings.ExitsTable,
			settings.RouteMetric, false)
		if err := self.system.request(unix.RTM_DELROUTE, 0, body); err != nil && !errors.Is(err, unix.ESRCH) {
			clearErr = errors.Join(clearErr, fmt.Errorf("the default route did not come off (%v)", err))
		} else {
			self.exitsRoute = false
		}
	}
	if self.exitsSuppressRule && !self.exitsMarkRule {
		body := urTunLinuxRuleBody(settings.ExitsRulePriority, true, settings.ExitsTable, settings.ExitsMark)
		if err := self.system.request(unix.RTM_DELRULE, 0, body); err != nil && !errors.Is(err, unix.ENOENT) {
			clearErr = errors.Join(clearErr, fmt.Errorf("the rule that keeps the main table's routes ahead did not come off (%v)", err))
		} else {
			self.exitsSuppressRule = false
		}
	}
	if self.exitsMark && !self.exitsMarkRule {
		self.system.setEgressMark(0)
		self.exitsMark = false
	}
	return clearErr
}

// Why the exits' default route may not go on now, nil when it may: another program's route in the exits table, or rule
// on the exits mark or table, which ur tun's would mix with; or a strict reverse path filter on an interface the main
// table's default route leaves by, which would drop the daemon's own replies there, since a reply arrives unmarked and
// the filter's lookup of its way back finds the tun. A setting that does not read refuses too.
func (self *urTunLinuxSystem) exitsRefusal(index int) error {
	settings := self.settings
	routes, err := self.routes(unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("the routes did not read (%v)", err)
	}
	defaultIndexes := []int{}
	for _, route := range routes {
		if route.table == settings.ExitsTable && (route.protocol != urTunRouteProtocol || !slices.Contains(route.oifs, index)) {
			return fmt.Errorf("%w, table %d", errUrTunExitsTableInUse, settings.ExitsTable)
		}
		if route.family != unix.AF_INET || route.table != unix.RT_TABLE_MAIN || route.routeType != unix.RTN_UNICAST ||
			route.dst.Bits() != 0 {
			continue
		}
		for _, oif := range route.oifs {
			if oif != 0 && oif != index && !slices.Contains(defaultIndexes, oif) {
				defaultIndexes = append(defaultIndexes, oif)
			}
		}
	}
	rules, err := self.rules(unix.AF_INET)
	if err != nil {
		return fmt.Errorf("the policy rules did not read (%v)", err)
	}
	for _, rule := range rules {
		if rule.protocol != urTunRouteProtocol && ((rule.markSet && rule.mark == settings.ExitsMark) || rule.table == settings.ExitsTable) {
			return fmt.Errorf("%w, mark %#x and table %d", errUrTunExitsMarkInUse, settings.ExitsMark, settings.ExitsTable)
		}
	}
	if len(defaultIndexes) == 0 {
		return nil
	}
	all, err := self.reversePathFilter("all")
	if err != nil {
		return fmt.Errorf("the reverse path filter did not read (%v)", err)
	}
	for _, oif := range defaultIndexes {
		name, err := self.linkName(oif)
		if err != nil {
			return fmt.Errorf("the default route's interface did not read (%v)", err)
		}
		value, err := self.reversePathFilter(name)
		if err != nil {
			return fmt.Errorf("the reverse path filter did not read (%v)", err)
		}
		// the kernel filters by the stricter of all's and the interface's, 1 being strict and 2 loose
		if all == 1 || value == 1 {
			return fmt.Errorf("%w on %s: set its rp_filter and all's to 2, loose", errUrTunExitsStrictReversePath, name)
		}
	}
	return nil
}

// The rp_filter of an interface, or of all: 0 off, 1 strict, 2 loose.
func (self *urTunLinuxSystem) reversePathFilter(name string) (int, error) {
	content, err := os.ReadFile(filepath.Join(self.ipv4ConfPath, name, "rp_filter"))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(content)))
}

// Takes the exits off, reverts the resolver, removes the routes and addresses it added, and closes the device, which
// the kernel deletes with whatever is left on it. Waits for the device's event listener to end.
func (self *urTunLinuxInterface) Close() error {
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
			urTunLinuxRevertResolver(self.index, self.system.settings.PlatformTimeout)
			self.resolverSet = false
		}
		metric := self.system.settings.RouteMetric
		for _, held := range self.routes {
			if err := self.system.request(unix.RTM_DELROUTE, 0, urTunLinuxRouteBody(self.index, held, unix.RT_TABLE_MAIN, metric, false)); err != nil &&
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
