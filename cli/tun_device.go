// ur tun's device and its loops (§17.10, §17.11; BRIDGE-M4-18): the OS tun ur-<instance> carries one network's block,
// its granted prefixes and its resolver into that network's device.Bridge, in the daemon, which holds the tun until ur
// tun down or its own end, as it holds a socket (§5.8).
//
//	read     the device's packets, a batch at a time, copied into the message pool and split by Bridge.RouteBurst: a
//	         link, an exit, the reject client, the resolver or, for IPv6 under exits, the bridge's IPv6 reject takes
//	         each run, and a building link refuses its run, which is counted and dropped for TCP to retransmit; a nil
//	         route, today's route, is dropped and counted, since the tun cannot hand a packet back to the host's own
//	         route
//	write    each packet the bridge answers, a link's reply, a reject or the resolver's answer, written into the device
//	         at once on the caller's goroutine, the packet the caller's again after the call
//	sync     on each change the bridge reports, coalesced: the device's addresses are this host's overlay addresses,
//	         its routes Bridge.Routes(), the default route too where the plan for default traffic takes it
//	         (tun_default.go; QD-1052), beside the bridge's carve passed back to the host's own route where the
//	         platform can, and the state's name zones resolve through <block>.0.53; a change of the network's choices
//	         or of the destination syncs again too
//	local    this host's interface, gateway and resolver addresses, which the platform watches and the tun reads again
//	         every LocalPollInterval, into Bridge.SetLocalAddresses whenever they change, the bridge's own resolvers left
//	         out so their routes are never carved
//
// The default route rides the tun where the plan for default traffic takes it (tun_default.go; QD-1052, amending the
// unconditional capture under exits of §17.11 and QD-1048): default egress in force and a destination, the network's
// exits under exits; or no destination with route local traffic off, which the tun refuses. Below, and in each
// platform's file, "under exits" and "the exits" name that capture, whatever the egress mode that asked for it, and
// SetExits is how the sync asks for it. On Linux it goes in a routing table of the platform's own with wg-quick's
// rules, `not fwmark <mark> lookup <table>` and `lookup main suppress_prefixlength 0` (tun_linux.go;
// QD-800): the daemon's own connect sockets carry connect's egress mark, which the first rule passes by, so its
// transport, and with it every link the bridge sends on, keeps today's route; nothing is carved by the platform's
// addresses. The bridge's own carve, this host's interface, gateway and resolver addresses (§17.4), takes a throw route
// each in that table, which each sync keeps in step through urTunCarvedInterface, so the host reaches them by today's
// route too, an off-link resolver among them, rather than through a tun that could only drop them (QD-808). On macOS
// and Windows it goes on as IPv4's two halves (urTunExitsHalves), and connect's sockets are bound to the interface of
// the host's own default route instead (tun_darwin.go, tun_windows.go); there each carved address the host reaches
// only by its default route, which a half would take into the tun, gets a host route by that route's gateway, kept
// in step through urTunCarvedInterface as well (tun_host_routes.go; QD-869). Where the platform cannot put it on, or
// the host refuses it, the exits are held: the status says why, the host's other traffic keeps today's route, and the
// sync tries again. Off exits, or once the tun ends, the route, the rules, the throws, the host routes and the binding
// go.
//
// IPv6's default route rides the tun beside IPv4's under exits (QD-881): on Linux ::/0 in the same table with IPv6's
// copies of the two rules, on macOS and Windows IPv6's two halves (urTunExitsIpv6Halves). Under auto it goes to the
// destination as IPv4's does, and under none the bridge rejects it with the rest. No exit carries IPv6 (§17.4), so
// under the egress mode exits the bridge answers what reaches it through its rejects, a TCP reset or an ICMPv6
// administratively prohibited written back into the device within the source's bucket, past which a packet is
// dropped, and counts it (owner decision 482, QD-970): a dual-stack host's IPv6 goes nowhere rather than past the
// exits, and its connections hear at once and fall back to IPv4 rather than waiting out a connect timeout; the
// daemon's own IPv6 sockets keep today's route by their mark or binding, as its IPv4 ones do. Where the host routes no
// IPv6 off itself and the platform will not take IPv6's half,
// IPv4's stands alone, since no IPv6 leaves to begin with; where the host does route IPv6, a refusal of IPv6's half
// holds the exits as any other does. The carve's IPv6 addresses go back to the host's own route as IPv4's do (owner
// decision 480, QD-971): each one the host reaches only by its IPv6 default route, an off-link IPv6 resolver above all,
// takes an IPv6 throw in the exits table on Linux and an IPv6 host route by the IPv6 default route's gateway on macOS
// and Windows, kept in step through urTunCarvedInterface beside IPv4's (tun_carve.go), while a link-local one and one
// the host's own routes reach take none; the tun hands the platform the carve of both families as it reads it.
//
// A block of the network's that this device routes to another network, one it joined first holding the same block
// (§17.4; bridge_shared_block.go), is withheld: each sync leaves the addresses, routes and names inside it off the
// device, and the read loop drops anything bound into it, so a packet sent there under the exits' default route or a
// wider route reaches none of this network's hosts. Its routes outside the block, its exits and the flows it hosts stay
// its own.
//
// Close, from ur tun down, the daemon's end, the network's bridge closing or a device that failed, stops the loops,
// takes the default route, its rules and the mark off, reverts the resolver, removes the routes and addresses it
// added, and closes the device, whose deletion the kernel follows by dropping anything left, so routes are restored on
// any path. No address, name or prefix reaches a log
// (I-13); ur tun's own replies show them to the person on the terminal.
//
// A urTun is safe for concurrent use.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What ur tun refuses or stops on.
var (
	// The platform has no ur tun (§17.18): Linux and WSL2 from M4, macOS and Windows from M6.
	errUrTunPlatform = errors.New("ur tun has no OS tun on this system: it runs on Linux, WSL2, macOS and Windows; " +
		"ur bridge works without it over the userspace stack")
	// The daemon may not create or configure the device. Linux's words; macOS and Windows say theirs through
	// urTunPrivilegeError, which is this error too.
	errUrTunPrivilege = errors.New("ur tun needs CAP_NET_ADMIN or root in the daemon: grant ur the capability " +
		"(sudo setcap cap_net_admin=ep \"$(command -v ur)\") and run ur again, or run the daemon as root; " +
		"ur bridge works without it over the userspace stack")
	// The host has no tun device to clone.
	errUrTunNoDevice = errors.New("this host has no /dev/net/tun: load the tun module, or pass --device /dev/net/tun " +
		"to a container")
	// An app's bridge holds the block on this host (§17.11's yield).
	errUrTunYield = errors.New("ur tun yields to the app's bridge")
	// The tun is closed.
	errUrTunClosed = errors.New("ur tun is down")
	// A read dropped segments its batch had no room for; the read goes on.
	errUrTunSegmentsDropped = errors.New("segments dropped")
	// The default route stays off the tun where the plan takes it, for the reason it wraps; the sync tries again.
	errUrTunExitsHeld = errors.New("the default route is held off ur tun")
)

// A privilege the daemon lacks, in its platform's words: errors.Is finds errUrTunPrivilege, so the start ends as it
// does on Linux, while the person reads the step their system takes.
type urTunPrivilegeError struct {
	// What the person reads: what the daemon lacks and the step that grants it.
	text string
	// The platform's refusal.
	err error
}

func (self *urTunPrivilegeError) Error() string {
	if self.err == nil {
		return self.text
	}
	return fmt.Sprintf("%s (%v)", self.text, self.err)
}

func (self *urTunPrivilegeError) Is(target error) bool {
	return target == errUrTunPrivilege
}

func (self *urTunPrivilegeError) Unwrap() error {
	return self.err
}

// The two halves of IPv4's space, which macOS and Windows put the default route on as under exits (tun_darwin.go,
// tun_windows.go): each more specific than the host's own default route, which stays, so the transport's interface
// keeps a way out and the halves come off without touching it.
func urTunExitsHalves() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
}

// The two halves of IPv6's space, which macOS and Windows put IPv6's default route on as under exits, after IPv4's
// halves (QD-881): each more specific than the host's own IPv6 default route, which stays, as urTunExitsHalves IPv4's.
// The bridge rejects what they carry, since no exit carries IPv6 (QD-970).
func urTunExitsIpv6Halves() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
}

// Tunables of ur tun.
type urTunSettings struct {
	// The device's MTU: connect's tunnel MTU, 1280, the most a link's NAT packetizes to.
	Mtu int
	// The most packets one read takes: 64, a TSO burst's segments at that MTU. The device's own batch bounds it too.
	ReadBatchCount int
	// Each read slot's bytes: 65535, an IPv4 packet's most, so no packet the device hands over overflows its slot.
	ReadPacketByteCount int
	// The bytes a write leaves in front of each packet: 16, past virtio_net_hdr's 10, which an offloading device writes
	// there. Fewer than 10 fails every write on such a device.
	WriteHeadroomByteCount int
	// How long one send waits for a link's window: 5 s, the sdk's SendTimeout. A send past it is dropped.
	SendTimeout time.Duration
	// How long a sync waits for more changes to coalesce with: 100 ms.
	SyncDelay time.Duration
	// How long after a sync that failed the tun syncs again: 5 s.
	SyncRetryInterval time.Duration
	// How often the local addresses are read again whatever the platform reports: 30 s, for a resolver file that
	// changed with no address or route.
	LocalPollInterval time.Duration
	// How long a read of the local addresses waits for more changes to coalesce with: 250 ms.
	LocalDelay time.Duration
	// The route metric the tun's routes take: 0, so a route another interface holds at the same prefix refuses the
	// tun's, which is reported, rather than either one hiding the other.
	RouteMetric uint32
	// How long one platform call, a netlink request or a resolver's bus call, may take: 5 s.
	PlatformTimeout time.Duration
	// How long close waits for the loops to stop: 10 s, past a send's SendTimeout.
	CloseTimeout time.Duration
	// The longest device name the platform takes: 15, Linux's IFNAMSIZ less its NUL. A longer ur-<instance> is hashed
	// to fit (urTunDeviceName).
	DeviceNameByteCount int
	// The routing table the default route goes in under exits, and the fwmark the daemon's own connect sockets carry
	// so the rule that sends the rest there passes them by: 0x7572, "ur", for both, as wg-quick gives its table and its
	// mark one number. A table another program's routes hold, or a mark another program's rule matches, holds the
	// exits rather than mixing with it.
	ExitsTable uint32
	ExitsMark  uint32
	// The priority of the first of the exits' two rules, `lookup main suppress_prefixlength 0`; the second, `not fwmark
	// <mark> lookup <table>`, takes the one after: 32760, so both run before the main table's rule at 32766 and the
	// first before the second, which is what keeps the host's own non-default routes ahead of the tun.
	ExitsRulePriority uint32
	// How often the daemon judges its networks' shared blocks again with no change reported (bridge_shared_block.go):
	// 1 min, for a drain that ends with no change of state.
	SharedBlockInterval time.Duration
	// The bytes a read leaves in front of each packet: 4, the family header a utun puts there on macOS, which
	// wireguard's read wants room for. Linux and Windows read past it unused.
	ReadHeadroomByteCount int
	// The longest zone name a platform's resolver files or rules take, and its longest label: DNS's 253, a name's 255
	// less its length and root bytes, and 63 (RFC 1035 2.3.4).
	ZoneNameMaxByteCount  int
	ZoneLabelMaxByteCount int
	// Windows' adapter list (tun_windows.go): the buffer GetAdaptersAddresses is first given, 15 KiB as IP Helper
	// advises, and how many times it is asked again with the size it answers, for adapters that come between asks: 3.
	AdapterBufferByteCount  int
	AdapterReadAttemptCount int
	// A network's choices for the host's default traffic until the person makes one (tun_default.go; QD-1052): default
	// egress on, so a host with a destination keeps sending its default traffic there, and route local traffic on, as
	// the sdk's DefaultRouteLocal is, so a host with none keeps its own default routes.
	DefaultEgress     bool
	DefaultRouteLocal bool
}

// The defaults, a fresh value each call.
func defaultUrTunSettings() *urTunSettings {
	return &urTunSettings{
		Mtu:                     connect.DefaultTunnelMtu,
		ReadBatchCount:          64,
		ReadPacketByteCount:     65535,
		WriteHeadroomByteCount:  16,
		SendTimeout:             5 * time.Second,
		SyncDelay:               100 * time.Millisecond,
		SyncRetryInterval:       5 * time.Second,
		LocalPollInterval:       30 * time.Second,
		LocalDelay:              250 * time.Millisecond,
		RouteMetric:             0,
		PlatformTimeout:         5 * time.Second,
		CloseTimeout:            10 * time.Second,
		DeviceNameByteCount:     15,
		ExitsTable:              0x7572,
		ExitsMark:               0x7572,
		ExitsRulePriority:       32760,
		SharedBlockInterval:     time.Minute,
		ReadHeadroomByteCount:   4,
		ZoneNameMaxByteCount:    253,
		ZoneLabelMaxByteCount:   63,
		AdapterBufferByteCount:  15 * 1024,
		AdapterReadAttemptCount: 3,
		DefaultEgress:           true,
		DefaultRouteLocal:       true,
	}
}

// The OS tun as the read and write loops use it: wireguard's tun.Device, less its file and events.
type urTunDevice interface {
	// Reads up to len(bufs) packets, each into bufs[i][offset:], its length in sizes[i]. An error wrapping
	// errUrTunSegmentsDropped comes with the packets it did read and does not end the device.
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	// Writes each of bufs from offset, which leaves the device its headroom in front.
	Write(bufs [][]byte, offset int) (int, error)
	// The most packets one Read hands over.
	BatchSize() int
}

// One open tun: the device and what the platform set on it. Its configuration calls come from the tun's sync, one at a
// time; Read and Write from the loops.
type urTunInterface interface {
	urTunDevice
	// Sets the device's addresses to exactly these, IPv4 /32s: adds what is missing, removes what it added before.
	SetAddresses(addresses []netip.Addr) error
	// Sets the routes through the device to exactly these, as SetAddresses does, and answers how many another route
	// holds at the same prefix and metric, which are left to it.
	SetRoutes(routes []netip.Prefix) (int, error)
	// Points the zones' names at resolver for this device's link: "" when the host's resolver took it, else the step a
	// person takes. No zones reverts what it set.
	SetResolver(resolver netip.Addr, zones []string) (string, error)
	// Puts the host's default routes on the device, where the tun's plan takes them (tun_default.go; QD-1052), with what
	// keeps this daemon's own sockets off them, those sockets marked or bound first, IPv6's beside IPv4's (QD-881); or,
	// where it does not, takes the routes, the rules and the mark off. Answers whether the default route rides the
	// device after the call, and why it does not where the plan asked for it.
	SetExits(exits bool) (bool, error)
	// Takes the default route off, reverts the resolver, removes the routes and addresses it added and closes the
	// device, which ends a Read.
	Close() error
}

// An open tun whose platform names the device itself, as macOS names a utun: the tun takes that name for its status
// and for what it asks the platform about its own interface.
type urTunNamedInterface interface {
	urTunInterface
	Name() string
}

// An open tun whose platform passes the bridge's carved addresses back to the host's own route under exits, as Linux's
// exits table does by a throw route each (tun_linux.go; QD-808) and macOS's and Windows' main table by a host route
// for each one a half would take (tun_host_routes.go; QD-869), IPv6's carve beside IPv4's (QD-971), so the host's own
// traffic to one never meets the tun, which could only drop or reject it. Each sync hands it the carve after SetExits.
type urTunCarvedInterface interface {
	urTunInterface
	// Sets the addresses the bridge carves, of both families, those the local read last handed
	// Bridge.SetLocalAddresses: under exits, each that needs it is passed back to the host's own route, those no longer
	// carved are not, and off exits the list waits for the next SetExits(true). Answers what would not go on or come
	// off, which the next call tries again.
	SetCarved(addresses []netip.Addr) error
}

// The platform's half of ur tun.
type urTunSystem interface {
	// Opens the device name with mtu, up. Refuses with errUrTunPrivilege or errUrTunNoDevice where the host lacks one.
	Open(name string, mtu int) (urTunInterface, error)
	// The interface other than name holding a route inside prefix, "" for none: an app's bridge holding the block.
	RoutedElsewhere(name string, prefix netip.Prefix) (string, error)
	// This host's own addresses, those of every interface but name's, its gateways' and its resolvers', but exclude.
	LocalAddresses(name string, exclude []netip.Addr) ([]netip.Addr, error)
	// Calls changed on each change of addresses or routes the platform reports, until ctx ends. changed never blocks.
	WatchLocal(ctx context.Context, changed func()) error
}

// The platform's half where ur tun runs: tun_linux.go sets it at M4, tun_darwin.go and tun_windows.go at M6. Nil
// elsewhere, where ur tun refuses.
var urTunPlatform func(settings *urTunSettings, log sidecar.Logger) urTunSystem

// What the tun reads and feeds of one network's device.Bridge, which satisfies it; a test stands a fake in.
type urTunBridge interface {
	RouteBurst(packets [][]byte, send func(client connect.UserNatClient, packets [][]byte))
	Routes() []netip.Prefix
	SetLocalAddresses(addresses []netip.Addr)
	SetReceivePacket(receive connect.ReceivePacketFunction)
	AddChangeCallback(callback func()) func()
	Status() device.BridgeStatus
	Decision() device.PostureDecision
}

var _ urTunBridge = (*device.Bridge)(nil)

// What the tun reads and feeds of the bridge's host: where the links' replies go, and the source a send names.
type urTunLinks interface {
	setReceive(receive func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte))
	sourcePath() connect.TransferPath
}

var _ urTunLinks = (*urBridgeHost)(nil)

// What a tun is started over.
type urTunArgs struct {
	// The device's name, ur-<instance> (urTunDeviceName).
	Name      string
	NetworkId sidecar.Id
	System    urTunSystem
	Bridge    urTunBridge
	Links     urTunLinks
	Settings  *urTunSettings
	Log       sidecar.Logger
	// The network's blocks this device routes to another network, one it joined first that holds the same block
	// (bridge_shared_block.go), read at each sync: the tun carries nothing inside them. Nil for none.
	Withheld func() []urSharedBlock
	// The network's choices for the host's default traffic (tun_default.go), nil for the settings' defaults.
	Choices *urTunChoices
	// The connect client's destination under auto, nil for none, which is the daemon's today.
	Destination urTunDestination
	// Called once the tun has closed, on whichever path, with why; nil for none.
	OnClose func(tun *urTun, reason error)
	// Called after each sync has applied, with its error; nil for none. A test's barrier.
	OnSync func(err error)
}

// What ur tun shows: the device and what it carries, for the person's terminal. Nothing secret.
type urTunStatus struct {
	Device    string     `json:"device"`
	NetworkId sidecar.Id `json:"network_id"`
	// The bridge's state in force, as device.PostureState names it.
	State         string `json:"state"`
	Block         string `json:"block,omitempty"`
	PreviousBlock string `json:"previous_block,omitempty"`
	// This host's overlay addresses, on the device.
	Addresses []string `json:"addresses,omitempty"`
	// The routes through the device, and those another route held.
	Routes             []string `json:"routes,omitempty"`
	RouteConflictCount int      `json:"route_conflict_count,omitempty"`
	// Where the zones' names resolve, and the step a person takes where the host's resolver did not take it.
	Resolver     string   `json:"resolver,omitempty"`
	Zones        []string `json:"zones,omitempty"`
	ResolverStep string   `json:"resolver_step,omitempty"`
	// The state's egress mode; whether the default route rides the tun, as the plan for default traffic takes it; and
	// whether the platform holds it off, with why (the file's comment).
	EgressMode      string `json:"egress_mode"`
	DefaultRoute    bool   `json:"default_route,omitempty"`
	ExitsHeld       bool   `json:"exits_held,omitempty"`
	ExitsHeldReason string `json:"exits_held_reason,omitempty"`
	// The plan for default traffic (tun_default.go; QD-1052): default egress in force, and as the person chose it;
	// route local traffic; whether the client has an egress destination; and what the tun does with default traffic,
	// egress, local, refused or off.
	DefaultEgress       bool   `json:"default_egress"`
	DefaultEgressChosen bool   `json:"default_egress_chosen"`
	RouteLocal          bool   `json:"route_local"`
	Destination         bool   `json:"destination,omitempty"`
	DefaultTraffic      string `json:"default_traffic,omitempty"`
	// Whether the network requires default egress on, under exits (QD-1053): it holds DefaultEgress on whatever the
	// person chose, and ur tun refuses to turn it off.
	DefaultEgressRequired bool `json:"default_egress_required,omitempty"`
	// What the bridge waits on, by kind.
	Waits []string `json:"waits,omitempty"`
	// The network's blocks this device routes to a network it joined first (§17.4), which the tun leaves off, and the
	// packets it dropped for being bound into one.
	Withheld      []urTunWithheld `json:"withheld,omitempty"`
	WithheldCount uint64          `json:"withheld_count,omitempty"`
	// How many local addresses the bridge carves; -1 while unknown.
	LocalAddressCount int `json:"local_address_count"`
	// Packets since the tun came up: read, taken by a route, dropped for the default route, IPv6 the bridge rejected
	// under exits, which no exit carries (owner decision 482, QD-970; taken by the bridge's IPv6 reject, so among those
	// taken too, and each reject its source's bucket let go among those written back), refused by a building link or a
	// full window, written back, and writes that failed.
	ReadCount         uint64 `json:"read_count"`
	SentCount         uint64 `json:"sent_count"`
	DefaultCount      uint64 `json:"default_count"`
	Ipv6RejectedCount uint64 `json:"ipv6_rejected_count"`
	RefusedCount      uint64 `json:"refused_count"`
	WrittenCount      uint64 `json:"written_count"`
	WriteErrorCount   uint64 `json:"write_error_count,omitempty"`
	// Why the last sync failed, when it did; it is tried again.
	SyncError string `json:"sync_error,omitempty"`
}

// A block the tun leaves off, as its status shows it: the block, and the network that routes it on this device.
type urTunWithheld struct {
	Block          string     `json:"block"`
	OwnerNetworkId sidecar.Id `json:"owner_network_id"`
}

// One network's OS tun. See the file's comment.
type urTun struct {
	name      string
	networkId sidecar.Id
	settings  *urTunSettings
	system    urTunSystem
	iface     urTunInterface
	bridge    urTunBridge
	links     urTunLinks
	log       sidecar.Logger
	onClose   func(tun *urTun, reason error)
	onSync    func(err error)
	// the network's withheld blocks, nil for none
	withheldOf func() []urSharedBlock
	// their prefixes as the last sync applied them, which the read loop drops packets bound into; nil for none
	withheldPrefixes atomic.Pointer[[]netip.Prefix]

	ctx    context.Context
	cancel context.CancelFunc
	// closed when each loop has returned
	readDone  chan struct{}
	syncDone  chan struct{}
	localDone chan struct{}
	closeOnce sync.Once
	// wakes sync, and the local read; one pending wake each
	syncWake  chan struct{}
	localWake chan struct{}
	// removes the bridge's change callback, and the destination's
	removeChange            func()
	removeDestinationChange func()
	// sendRun as a value, made once so a burst allocates no closure
	send func(client connect.UserNatClient, packets [][]byte)
	// the connect client's destination under auto, nil for none, and the client a nil route's run goes to while the
	// plan sends default traffic there, nil while it does not
	destination       urTunDestination
	destinationClient atomic.Pointer[urTunDestinationClient]
	// serializes the syncs, the sync loop's and a change of the choices', so the last to run applies the newest plan
	syncLock sync.Mutex

	// serializes writes into the device, and owns the buffer each is copied into
	writeLock   sync.Mutex
	writeClosed bool
	writeBuffer []byte
	writeBufs   [][]byte

	readCount       atomic.Uint64
	sentCount       atomic.Uint64
	defaultCount    atomic.Uint64
	refusedCount    atomic.Uint64
	writtenCount    atomic.Uint64
	writeErrorCount atomic.Uint64
	withheldCount   atomic.Uint64
	// the IPv6 the bridge had rejected under exits when the tun came up, which the status counts from
	ipv6RejectedBase uint64

	stateLock sync.Mutex
	// what the last sync applied
	withheld           []urSharedBlock
	addresses          []netip.Addr
	routes             []netip.Prefix
	routeConflictCount int
	resolver           netip.Addr
	zones              []string
	resolverStep       string
	defaultRoute       bool
	exitsHeld          bool
	exitsHeldReason    string
	syncErr            error
	// the network's choices, and the plan the last sync applied
	choices urTunChoices
	plan    urTunDefaultPlan
	// the bridge's own resolver addresses, which the local addresses leave out
	ownResolvers []netip.Addr
	// what the local read last handed the bridge; nil before the first
	localAddrs []netip.Addr
	localKnown bool
}

// The device name of an instance: ur-<instance> where it fits maxByteCount, else ur- and as many hex digits of SHA-256
// over a domain and the instance's name as fit, as the app group's socket names a long instance (daemon_pair.go).
func urTunDeviceName(instance string, maxByteCount int) string {
	const prefix = "ur-"
	if name := prefix + instance; len(name) <= maxByteCount {
		return name
	}
	digest := sha256.Sum256([]byte(urTunDeviceNameDomain + instance))
	digits := hex.EncodeToString(digest[:])
	return prefix + digits[:max(0, min(len(digits), maxByteCount-len(prefix)))]
}

// The domain of a long instance's device name hash.
const urTunDeviceNameDomain = "urnetwork-sidecar-v1/tun-device/"

// Opens the device and starts the tun: the first sync and local read run before it returns, so the reply shows what
// the device carries, and then its loops. A failure closes what it opened.
func startUrTun(ctx context.Context, args *urTunArgs) (*urTun, error) {
	if args == nil || args.System == nil || args.Bridge == nil || args.Links == nil {
		return nil, errUrTunPlatform
	}
	settings := args.Settings
	if settings == nil {
		settings = defaultUrTunSettings()
	}
	iface, err := args.System.Open(args.Name, settings.Mtu)
	if err != nil {
		return nil, err
	}
	name := args.Name
	if named, ok := iface.(urTunNamedInterface); ok {
		name = named.Name()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &urTun{
		name:       name,
		networkId:  args.NetworkId,
		settings:   settings,
		system:     args.System,
		iface:      iface,
		bridge:     args.Bridge,
		links:      args.Links,
		log:        args.Log,
		onClose:    args.OnClose,
		onSync:     args.OnSync,
		withheldOf: args.Withheld,
		ctx:        cancelCtx,
		cancel:     cancel,
		readDone:   make(chan struct{}),
		syncDone:   make(chan struct{}),
		localDone:  make(chan struct{}),
		syncWake:   make(chan struct{}, 1),
		localWake:  make(chan struct{}, 1),
		writeBufs:  make([][]byte, 1),
		// before the read loop hands the bridge a packet
		ipv6RejectedBase: args.Bridge.Status().Ipv6RejectedCount,
		destination:      args.Destination,
		choices:          urTunDefaultChoices(settings),
	}
	if args.Choices != nil {
		self.choices = *args.Choices
	}
	if self.log == nil {
		self.log = sidecar.NewNoopLogger()
	}
	self.send = self.sendRun
	// the first sync names the bridge's own resolvers, which the first local read leaves out. A privilege it lacks
	// ends the start; anything else the sync loop tries again, and the reply names it
	if err := self.sync(); errors.Is(err, errUrTunPrivilege) {
		self.closeAt(err, false)
		return nil, err
	}
	self.readLocal()
	self.bridge.SetReceivePacket(self.write)
	self.links.setReceive(self.write)
	self.removeChange = self.bridge.AddChangeCallback(self.wantSync)
	// a destination that appears or goes plans default traffic again
	if self.destination != nil {
		self.removeDestinationChange = self.destination.AddChangeCallback(self.wantSync)
	}
	go self.runRead()
	go self.runSync()
	go self.runLocal()
	// a change between the first sync and the callback's install is carried by one more
	self.wantSync()
	return self, nil
}

// Wakes sync, coalescing with a wake already pending. Never blocks: the bridge's change callback.
func (self *urTun) wantSync() {
	select {
	case self.syncWake <- struct{}{}:
	default:
	}
}

// Wakes the local read, as wantSync does: the platform's watch.
func (self *urTun) wantLocal() {
	select {
	case self.localWake <- struct{}{}:
	default:
	}
}

// Reads the device until it closes, routing each batch through the bridge. A read that fails ends the tun.
func (self *urTun) runRead() {
	defer close(self.readDone)
	batchCount := max(1, min(self.iface.BatchSize(), self.settings.ReadBatchCount))
	headroom := self.settings.ReadHeadroomByteCount
	bufs := make([][]byte, batchCount)
	for i := range bufs {
		bufs[i] = make([]byte, headroom+self.settings.ReadPacketByteCount)
	}
	sizes := make([]int, batchCount)
	packets := make([][]byte, 0, batchCount)
	for {
		n, err := self.iface.Read(bufs, sizes, headroom)
		if 0 < n {
			packets = packets[:0]
			for i := range n {
				packets = append(packets, connect.MessagePoolCopy(bufs[i][headroom:headroom+sizes[i]]))
			}
			self.readCount.Add(uint64(n))
			if withheld := self.withheldPrefixes.Load(); withheld != nil {
				packets = self.dropWithheld(packets, *withheld)
			}
			// takes every packet: each run's send owns its packets as the route it reaches says
			if 0 < len(packets) {
				self.bridge.RouteBurst(packets, self.send)
			}
			clear(packets[:cap(packets)])
		}
		if err == nil || errors.Is(err, errUrTunSegmentsDropped) {
			continue
		}
		if self.ctx.Err() == nil {
			// the device failed under the tun: end it on another goroutine, since close waits for this one
			go self.closeAt(fmt.Errorf("the device stopped: %w", err), true)
		}
		return
	}
}

// Drops each packet bound into a withheld block, returning it to the pool and counting it, and answers the rest in
// their order, in packets' own array. Only the network that joined first routes a shared block here (§17.4), so a
// packet the host sends there, under the default route of exits or a wider route of the network's, reaches none of
// this network's hosts.
func (self *urTun) dropWithheld(packets [][]byte, withheld []netip.Prefix) [][]byte {
	kept := packets[:0]
	for _, packet := range packets {
		if urTunPacketWithheld(packet, withheld) {
			connect.MessagePoolReturn(packet)
			self.withheldCount.Add(1)
			continue
		}
		kept = append(kept, packet)
	}
	return kept
}

// Whether packet is an IPv4 packet bound into one of withheld. The overlay is IPv4 alone (§17.4), so no IPv6 packet
// is.
func urTunPacketWithheld(packet []byte, withheld []netip.Prefix) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return false
	}
	return urTunInsideAny(withheld, netip.AddrFrom4([4]byte(packet[16:20])))
}

// Whether address lies in one of prefixes.
func urTunInsideAny(prefixes []netip.Prefix, address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// Sends one run of a burst on the route the bridge gave it. Takes every packet: a route takes those it accepts, and a
// packet it refuses, as a building link does, is returned to the pool and counted. A nil route is today's: under auto,
// while the plan sends default traffic to the connect client's destination, the destination takes the run as a route
// does; else the tun cannot hand a packet back to the host's own route, and each is dropped and counted, which is how
// the tun refuses default traffic under auto with no destination and route local traffic off.
func (self *urTun) sendRun(client connect.UserNatClient, packets [][]byte) {
	if client == nil {
		destination := self.destinationClient.Load()
		if destination == nil {
			for _, packet := range packets {
				connect.MessagePoolReturn(packet)
			}
			self.defaultCount.Add(uint64(len(packets)))
			return
		}
		client = destination.client
	}
	source := self.links.sourcePath()
	if batchClient, ok := client.(connect.UserNatBatchClient); ok {
		sentCount := batchClient.SendPacketBatch(source, protocol.ProvideMode_Network, packets, self.settings.SendTimeout)
		self.sentCount.Add(uint64(sentCount))
		self.refusedCount.Add(uint64(len(packets) - sentCount))
		return
	}
	for _, packet := range packets {
		if client.SendPacket(source, protocol.ProvideMode_Network, packet, self.settings.SendTimeout) {
			self.sentCount.Add(1)
		} else {
			connect.MessagePoolReturn(packet)
			self.refusedCount.Add(1)
		}
	}
}

// connect.ReceivePacketFunction for the links, the rejects and the resolver: borrows packet, copies it behind the
// device's headroom and writes it at once. The device-side tun write is CODESTYLE's deliberate callback exception: a
// link's reply reaches here on that link's own receive goroutine, the write's synchronous handoff is the flow control
// back to it, and the device takes a write without waiting on any peer, so no unrelated flow waits behind it.
func (self *urTun) write(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
	if len(packet) == 0 {
		return
	}
	headroom := self.settings.WriteHeadroomByteCount
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if self.writeClosed {
		return
	}
	byteCount := headroom + len(packet)
	if cap(self.writeBuffer) < byteCount {
		self.writeBuffer = make([]byte, byteCount)
	}
	buffer := self.writeBuffer[:byteCount]
	copy(buffer[headroom:], packet)
	self.writeBufs[0] = buffer
	if _, err := self.iface.Write(self.writeBufs, headroom); err != nil {
		self.writeErrorCount.Add(1)
		return
	}
	self.writtenCount.Add(1)
}

// Syncs on each wake, after SyncDelay's coalescing, and again SyncRetryInterval after one that failed, until the tun
// ends.
func (self *urTun) runSync() {
	defer close(self.syncDone)
	var retry <-chan time.Time
	for {
		select {
		case <-self.ctx.Done():
			return
		case <-self.syncWake:
		case <-retry:
		}
		select {
		case <-self.ctx.Done():
			return
		case <-time.After(self.settings.SyncDelay):
		}
		// the delay's changes are in this sync
		select {
		case <-self.syncWake:
		default:
		}
		retry = nil
		if err := self.sync(); err != nil {
			if self.log.V(1).Enabled() {
				self.log.Infof("[tun]%s a sync failed, retried: %v", self.networkId, err)
			}
			retry = time.After(self.settings.SyncRetryInterval)
		}
	}
}

// Sets the device to what the bridge has in force now: its addresses, its routes, the default route where the plan for
// default traffic takes it (tun_default.go) and the zones' resolver, less everything inside a block another network
// routes on this device (§17.4). Every step runs even when one fails. The first error is the sync's, joined by why the
// default route is held, which the sync tries again too and the status names apart. One sync runs at a time.
func (self *urTun) sync() error {
	self.syncLock.Lock()
	defer self.syncLock.Unlock()
	// a close takes this lock to close the device, so no sync puts anything on after it
	if self.ctx.Err() != nil {
		return errUrTunClosed
	}
	var withheld []urSharedBlock
	if self.withheldOf != nil {
		withheld = self.withheldOf()
	}
	withheldPrefixes := []netip.Prefix{}
	for _, shared := range withheld {
		withheldPrefixes = append(withheldPrefixes, shared.Block.Masked())
	}
	// the read loop drops what is bound there before the routes that lead there come off
	if 0 < len(withheldPrefixes) {
		self.withheldPrefixes.Store(&withheldPrefixes)
	} else {
		self.withheldPrefixes.Store(nil)
	}
	status := self.bridge.Status()
	addresses := []netip.Addr{}
	for _, address := range status.Addresses {
		if address = address.Unmap(); address.Is4() && !slices.Contains(addresses, address) &&
			!urTunInsideAny(withheldPrefixes, address) {
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	routes := []netip.Prefix{}
	for _, route := range self.bridge.Routes() {
		// a wider route that holds a withheld block stays for the rest of what it holds, and the read loop drops what
		// is bound into the block
		if !slices.ContainsFunc(withheldPrefixes, func(prefix netip.Prefix) bool {
			return prefix.Bits() <= route.Bits() && prefix.Contains(route.Addr())
		}) {
			routes = append(routes, route)
		}
	}
	ownResolvers := []netip.Addr{}
	for _, block := range []netip.Prefix{status.Block, status.PreviousBlock} {
		if block.IsValid() && block.Addr().Is4() {
			ownResolvers = append(ownResolvers, urTunResolverAddr(block))
		}
	}
	zones := []string{}
	if decision := self.bridge.Decision(); decision.BridgeState != nil {
		for _, zone := range decision.BridgeState.GetNameZones() {
			if zone != "" && !slices.Contains(zones, zone) {
				zones = append(zones, zone)
			}
		}
	}
	slices.Sort(zones)
	var resolver netip.Addr
	// the resolver sits in the block, so a withheld block takes the names with it: they would name hosts this device
	// does not reach
	if status.Block.IsValid() && status.Block.Addr().Is4() && !urTunInsideAny(withheldPrefixes, urTunResolverAddr(status.Block)) {
		resolver = urTunResolverAddr(status.Block)
	}
	if !resolver.IsValid() {
		zones = nil
	}

	var syncErr error
	keep := func(err error) {
		if err != nil && syncErr == nil {
			syncErr = err
		}
	}
	keep(self.iface.SetAddresses(addresses))
	conflictCount, err := self.iface.SetRoutes(routes)
	keep(err)
	// the plan for default traffic, from the network's choices and the destination as they are now
	choices := func() urTunChoices {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.choices
	}()
	var destination connect.UserNatClient
	if self.destination != nil {
		destination = self.destination.Client()
	}
	plan := urTunPlanDefault(status, destination != nil, choices)
	// under auto the destination takes what the bridge leaves to today's route, set before the default route goes on
	// and cleared before it comes off, so no packet the plan does not send there reaches it
	toDestination := plan.Traffic == urTunDefaultTrafficEgress &&
		status.EgressMode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS && destination != nil
	if toDestination {
		self.destinationClient.Store(&urTunDestinationClient{client: destination})
	} else {
		self.destinationClient.Store(nil)
	}
	defaultRoute, exitsErr := self.iface.SetExits(plan.Take)
	if !plan.Take {
		// a default route that did not come off is the sync's to retry, not a hold
		keep(exitsErr)
		exitsErr = nil
	}
	// the bridge's carve, after SetExits, so a carve that changed since the exits went on follows them; what would not
	// go on is the sync's to retry, not a hold, since the exits stand and only the host's traffic to that address drops
	if carvedIface, ok := self.iface.(urTunCarvedInterface); ok {
		var carvedAddrs []netip.Addr
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			carvedAddrs = slices.Clone(self.localAddrs)
		}()
		keep(carvedIface.SetCarved(carvedAddrs))
	}
	exitsHeldReason := ""
	if exitsErr != nil {
		exitsHeldReason = exitsErr.Error()
		// held exits leave the tun up whatever the platform answered, so no hold reads as the start's privilege refusal
		exitsErr = fmt.Errorf("%w: %v", errUrTunExitsHeld, exitsErr)
	}
	var previousResolver netip.Addr
	var previousZones []string
	var previousStep string
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		previousResolver, previousZones, previousStep = self.resolver, self.zones, self.resolverStep
	}()
	step := previousStep
	resolverChanged := resolver != previousResolver || !slices.Equal(zones, previousZones)
	if resolverChanged {
		step, err = self.iface.SetResolver(resolver, zones)
		keep(err)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.withheld = withheld
		self.addresses = addresses
		self.routes = routes
		self.routeConflictCount = conflictCount
		if !resolverChanged || err == nil {
			self.resolver, self.zones, self.resolverStep = resolver, zones, step
		}
		self.defaultRoute = defaultRoute
		self.exitsHeld = plan.Take && !defaultRoute
		self.exitsHeldReason = exitsHeldReason
		self.plan = plan
		self.ownResolvers = ownResolvers
		self.syncErr = syncErr
	}()
	if 0 < conflictCount && self.log.V(1).Enabled() {
		self.log.Infof("[tun]%s %d routes left to another interface's", self.networkId, conflictCount)
	}
	// a change of the bridge's own resolvers changes what the local addresses leave out
	self.wantLocal()
	if self.onSync != nil {
		self.onSync(errors.Join(syncErr, exitsErr))
	}
	return errors.Join(syncErr, exitsErr)
}

// <block>.0.53, the block's resolver (§17.4).
func urTunResolverAddr(block netip.Prefix) netip.Addr {
	octets := block.Masked().Addr().As4()
	octets[3] = 53
	return netip.AddrFrom4(octets)
}

// Reads the local addresses now and on each change the platform reports, every LocalPollInterval regardless, after
// LocalDelay's coalescing, until the tun ends.
func (self *urTun) runLocal() {
	defer close(self.localDone)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		if err := self.system.WatchLocal(self.ctx, self.wantLocal); err != nil && self.ctx.Err() == nil &&
			self.log.V(1).Enabled() {
			self.log.Infof("[tun]%s no watch of the local addresses, read every %s: %v", self.networkId,
				self.settings.LocalPollInterval, err)
		}
	}()
	defer func() {
		<-watchDone
	}()
	for {
		select {
		case <-self.ctx.Done():
			return
		case <-self.localWake:
		case <-time.After(self.settings.LocalPollInterval):
		}
		select {
		case <-self.ctx.Done():
			return
		case <-time.After(self.settings.LocalDelay):
		}
		select {
		case <-self.localWake:
		default:
		}
		self.readLocal()
	}
}

// Reads this host's addresses, leaving out the device's own and the bridge's resolvers, and hands them to the bridge
// when they changed. A read that fails hands over nothing, so the bridge keeps the last ones.
func (self *urTun) readLocal() {
	var exclude []netip.Addr
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		exclude = slices.Clone(self.ownResolvers)
	}()
	addresses, err := self.system.LocalAddresses(self.name, exclude)
	if err != nil {
		if self.log.V(1).Enabled() {
			self.log.Infof("[tun]%s the local addresses did not read: %v", self.networkId, err)
		}
		return
	}
	normal := []netip.Addr{}
	for _, address := range addresses {
		if address.IsValid() && !slices.Contains(normal, address.Unmap()) && !slices.Contains(exclude, address.Unmap()) {
			normal = append(normal, address.Unmap())
		}
	}
	slices.SortFunc(normal, netip.Addr.Compare)
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.localKnown && slices.Equal(self.localAddrs, normal) {
			return false
		}
		self.localAddrs = normal
		self.localKnown = true
		return true
	}()
	if changed {
		// publishes and calls the change callbacks, whose sync then follows any route the carve moved
		self.bridge.SetLocalAddresses(normal)
	}
}

// What the tun carries now.
func (self *urTun) status() *urTunStatus {
	bridgeStatus := self.bridge.Status()
	status := &urTunStatus{
		Device:          self.name,
		NetworkId:       self.networkId,
		State:           bridgeStatus.State.String(),
		EgressMode:      urTunEgressModeName(bridgeStatus.EgressMode),
		ReadCount:       self.readCount.Load(),
		SentCount:       self.sentCount.Load(),
		DefaultCount:    self.defaultCount.Load(),
		RefusedCount:    self.refusedCount.Load(),
		WrittenCount:    self.writtenCount.Load(),
		WriteErrorCount: self.writeErrorCount.Load(),
		WithheldCount:   self.withheldCount.Load(),
	}
	if self.ipv6RejectedBase < bridgeStatus.Ipv6RejectedCount {
		status.Ipv6RejectedCount = bridgeStatus.Ipv6RejectedCount - self.ipv6RejectedBase
	}
	if bridgeStatus.Block.IsValid() {
		status.Block = bridgeStatus.Block.String()
	}
	if bridgeStatus.PreviousBlock.IsValid() {
		status.PreviousBlock = bridgeStatus.PreviousBlock.String()
	}
	for _, wait := range bridgeStatus.Waits {
		status.Waits = append(status.Waits, string(wait.Kind))
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, shared := range self.withheld {
		status.Withheld = append(status.Withheld, urTunWithheld{Block: shared.Block.String(), OwnerNetworkId: shared.OwnerNetworkId})
	}
	for _, address := range self.addresses {
		status.Addresses = append(status.Addresses, address.String())
	}
	for _, route := range self.routes {
		status.Routes = append(status.Routes, route.String())
	}
	status.RouteConflictCount = self.routeConflictCount
	if self.resolver.IsValid() && 0 < len(self.zones) {
		status.Resolver = self.resolver.String()
		status.Zones = slices.Clone(self.zones)
		status.ResolverStep = self.resolverStep
	}
	status.DefaultRoute = self.defaultRoute
	status.ExitsHeld = self.exitsHeld
	status.ExitsHeldReason = self.exitsHeldReason
	status.DefaultEgress = self.plan.DefaultEgress
	status.DefaultEgressRequired = self.plan.Required
	status.DefaultEgressChosen = self.choices.DefaultEgress
	status.RouteLocal = self.choices.RouteLocal
	status.Destination = self.plan.Destination
	status.DefaultTraffic = self.plan.Traffic
	status.LocalAddressCount = -1
	if self.localKnown {
		status.LocalAddressCount = len(self.localAddrs)
	}
	if self.syncErr != nil {
		status.SyncError = self.syncErr.Error()
	}
	return status
}

// Takes the network's choices for the host's default traffic, as ur tun set them, and syncs at once, so the default
// route goes on or comes off before the answer, with no restart of the tun (QD-1052). Answers what the tun carries
// after that sync, whose failure the status names, as the sync loop's own would, and which the loop tries again.
func (self *urTun) setChoices(choices urTunChoices) *urTunStatus {
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.choices == choices {
			return false
		}
		self.choices = choices
		return true
	}()
	if changed && self.ctx.Err() == nil {
		if err := self.sync(); err != nil {
			// the loop tries it again, as it does a sync of its own that failed
			self.wantSync()
		}
	}
	return self.status()
}

// The egress mode as ur tun prints it.
func urTunEgressModeName(mode bridge.BridgeEgressMode) string {
	switch mode {
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS:
		return "exits"
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE:
		return "none"
	default:
		return "auto"
	}
}

// Ends the tun: ur tun down's and the daemon's path.
func (self *urTun) close() {
	self.closeAt(errUrTunClosed, true)
}

// Ends the tun with reason, once: the loops stop, the bridge's and the links' replies stop reaching the device, the
// interface takes its default route, rules and mark off, reverts its resolver, removes its routes and addresses and
// closes the device, and the bridge's local addresses go back to unknown. started is false for a start that failed
// before its loops ran.
func (self *urTun) closeAt(reason error, started bool) {
	self.closeOnce.Do(func() {
		self.cancel()
		if self.removeChange != nil {
			self.removeChange()
		}
		if self.removeDestinationChange != nil {
			self.removeDestinationChange()
		}
		if started {
			self.bridge.SetReceivePacket(nil)
			self.links.setReceive(nil)
		}
		deadline := time.After(self.settings.CloseTimeout)
		wait := func(done chan struct{}) bool {
			select {
			case <-done:
				return true
			case <-deadline:
				return false
			}
		}
		// the sync and local loops end with the context; the read loop with the device
		if started && (!wait(self.syncDone) || !wait(self.localDone)) {
			self.log.Warningf("[tun]%s a loop did not stop within %s", self.networkId, self.settings.CloseTimeout)
		}
		func() {
			self.writeLock.Lock()
			defer self.writeLock.Unlock()
			self.writeClosed = true
		}()
		// after a sync a change of the choices runs, which then finds the context ended and puts nothing on
		func() {
			self.syncLock.Lock()
			defer self.syncLock.Unlock()
			if err := self.iface.Close(); err != nil {
				self.log.Warningf("[tun]%s the device did not close cleanly: %v", self.networkId, err)
			}
		}()
		self.destinationClient.Store(nil)
		if started && !wait(self.readDone) {
			self.log.Warningf("[tun]%s the read did not stop within %s", self.networkId, self.settings.CloseTimeout)
		}
		if started {
			self.bridge.SetLocalAddresses(nil)
		}
		if !errors.Is(reason, errUrTunClosed) {
			self.log.Warningf("[tun]%s down: %v", self.networkId, reason)
		}
		if self.onClose != nil {
			self.onClose(self, reason)
		}
	})
}
