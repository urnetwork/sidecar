//go:build darwin && !ios && !sdk_mobile_bind

// §17.7.1's gatherer on macOS (owner decision 778): mDNSResponder's DNS-SD API through purego (dnssd_darwin.go), on each
// link that is up, multicast-capable and not point-to-point (discovery_links.go): DNSServiceBrowse for each type of the
// effective list on the link's index, DNSServiceResolve for each instance found there, and DNSServiceGetAddrInfo for
// each target's IPv4 addresses, all on one connection. mDNSResponder paces its own queries (RFC 6762 §5.2), so
// QueryRate is the Linux and Windows querier's alone, and keeps their answers fresh. The state between them is
// discovery_dnssd_gather.go's.
//
//	replies   each operation's callback queues what it heard for the gatherer's goroutine, which owns the state and
//	          makes every call, so no callback calls the connection; a queue past QueueCount drops the connection,
//	          which is built again at once with everything browsed anew, so nothing it dropped is lost for good
//	links     read again every LinkInterval: a new link's browses start, a gone one's operations end
//	report    at each change, after ReportDelay's coalescing, and every half of ReportTtl while the gatherer holds an
//	          instance
//	failure   a connection that ends, mDNSResponder's restart among them, is built again after RetryInterval, doubling
//	          to RetryMaxInterval, and the browses start anew; the last report stands until its instances expire
//
// Names and TXT are the LAN's words, kept as they came and logged nowhere (I-13).

package main

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

func init() {
	urDiscoveryGathererOf = func(log sidecar.Logger, settings *sidecar.BridgeDiscoverySettings) sidecar.BridgeDiscoveryGatherer {
		return &urDarwinGatherer{
			log:      log,
			settings: defaultUrDnsSdGatherSettings(),
			links:    urDarwinGatherLinks,
			connect: func() (urDarwinGatherConnection, error) {
				return newDarwinDnsSdConnection()
			},
			localAddresses: urMdnsLocalAddresses,
		}
	}
}

// What the gatherer needs of a connection to mDNSResponder: dnssd_darwin.go's.
type urDarwinGatherConnection interface {
	Browse(index uint32, service string, domain string, handle func(reply *darwinDnsSdBrowseReply)) (*darwinDnsSdOperation, error)
	Resolve(index uint32, name string, service string, domain string, handle func(reply *darwinDnsSdResolveReply)) (*darwinDnsSdOperation, error)
	GetAddrInfo(index uint32, protocol uint32, host string, handle func(reply *darwinDnsSdAddressReply)) (*darwinDnsSdOperation, error)
	Cancel(operation *darwinDnsSdOperation)
	Done() <-chan struct{}
	Close()
}

// The macOS gatherer. See the file's comment.
type urDarwinGatherer struct {
	log      sidecar.Logger
	settings *urDnsSdGatherSettings
	// the links to browse now, by index: discovery_links.go's, or a test's
	links          func() []uint32
	connect        func() (urDarwinGatherConnection, error)
	localAddresses func() []netip.Addr
}

var _ sidecar.BridgeDiscoveryGatherer = (*urDarwinGatherer)(nil)

// The indexes of the links the gatherer browses (discovery_links.go).
func urDarwinGatherLinks() []uint32 {
	indexes := []uint32{}
	interfaces, err := net.Interfaces()
	if err != nil {
		return indexes
	}
	for _, iface := range interfaces {
		if urMdnsEligible(iface) && 0 < iface.Index {
			indexes = append(indexes, uint32(iface.Index))
		}
	}
	return indexes
}

// The queue the callbacks fill and the gatherer's goroutine drains (the file's replies row).
type urDarwinGatherQueue struct {
	count int

	stateLock  sync.Mutex
	events     []func()
	overflowed bool
	// wakes the goroutine; buffered one
	wake chan struct{}
}

// Queues event, or marks the queue overflowed past its count. Never blocks: the connection's reader calls it.
func (self *urDarwinGatherQueue) push(event func()) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.count <= len(self.events) {
			self.overflowed = true
			return
		}
		self.events = append(self.events, event)
	}()
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// What the queue holds, taken whole, and whether it overflowed.
func (self *urDarwinGatherQueue) take() ([]func(), bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	events := self.events
	self.events = nil
	return events, self.overflowed
}

// sidecar.BridgeDiscoveryGatherer: gathers on one connection after another until ctx ends.
func (self *urDarwinGatherer) Gather(ctx context.Context, types []string, report func(gathered []*sidecar.BridgeDiscoveryGathered)) {
	retry := self.settings.RetryInterval
	for ctx.Err() == nil {
		connection, err := self.connect()
		if err != nil {
			if self.log != nil && self.log.V(1).Enabled() {
				self.log.Infof("[discovery]the gatherer reaches no mDNSResponder, tried again in %s: %v", retry, err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry):
			}
			retry = min(2*retry, self.settings.RetryMaxInterval)
			continue
		}
		overflowed := self.gatherOn(ctx, connection, types, report)
		connection.Close()
		if overflowed || ctx.Err() != nil {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
		retry = min(2*retry, self.settings.RetryMaxInterval)
	}
}

// Gathers on connection until ctx ends, the connection does or its queue overflows, which it answers.
func (self *urDarwinGatherer) gatherOn(ctx context.Context, connection urDarwinGatherConnection, types []string,
	report func(gathered []*sidecar.BridgeDiscoveryGathered)) bool {
	queue := &urDarwinGatherQueue{count: self.settings.QueueCount, wake: make(chan struct{}, 1)}
	var state *urDnsSdGatherState
	resolve := func(key urDnsSdInstanceKey, instance *urDnsSdInstance) func() {
		operation, err := connection.Resolve(key.index, instance.name, instance.service, instance.domain, func(reply *darwinDnsSdResolveReply) {
			if reply.Err != nil {
				return
			}
			queue.push(func() { state.resolved(key, reply.Host, reply.Port, reply.Txt) })
		})
		if err != nil {
			return nil
		}
		return func() { connection.Cancel(operation) }
	}
	lookup := func(key urDnsSdHostKey) func() {
		operation, err := connection.GetAddrInfo(key.index, darwinDnsSdProtocolIpv4, key.host, func(reply *darwinDnsSdAddressReply) {
			if reply.Err != nil {
				return
			}
			add := reply.Flags&darwinDnsSdFlagsAdd != 0
			queue.push(func() { state.addressed(key, add, reply.Address) })
		})
		if err != nil {
			return nil
		}
		return func() { connection.Cancel(operation) }
	}
	state = newUrDnsSdGatherState(self.settings, types, resolve, lookup)
	browses := map[uint32][]*darwinDnsSdOperation{}
	scanLinks := func() {
		current := map[uint32]bool{}
		for _, index := range self.links() {
			current[index] = true
			if browses[index] != nil {
				continue
			}
			operations := []*darwinDnsSdOperation{}
			for _, serviceType := range types {
				operation, err := connection.Browse(index, serviceType, "local.", func(reply *darwinDnsSdBrowseReply) {
					if reply.Err != nil {
						return
					}
					add := reply.Flags&darwinDnsSdFlagsAdd != 0
					queue.push(func() { state.browsed(index, reply.InterfaceIndex, add, reply.Name, reply.Service, reply.Domain) })
				})
				if err == nil {
					operations = append(operations, operation)
				}
			}
			browses[index] = operations
		}
		for index, operations := range browses {
			if current[index] {
				continue
			}
			for _, operation := range operations {
				connection.Cancel(operation)
			}
			delete(browses, index)
			state.dropLink(index)
		}
	}
	send := func() {
		report(state.gathered(time.Now(), self.localAddresses()))
	}
	scanLinks()
	send()
	linkTicker := time.NewTicker(self.settings.LinkInterval)
	defer linkTicker.Stop()
	renewTicker := time.NewTicker(max(self.settings.ReportTtl/2, time.Millisecond))
	defer renewTicker.Stop()
	var reportTimer <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return false
		case <-connection.Done():
			return false
		case <-queue.wake:
			events, overflowed := queue.take()
			if overflowed {
				return true
			}
			for _, event := range events {
				event()
			}
			if state.changed && reportTimer == nil {
				reportTimer = time.After(self.settings.ReportDelay)
			}
		case <-reportTimer:
			reportTimer = nil
			send()
		case <-renewTicker.C:
			if 0 < len(state.instances) {
				send()
			}
		case <-linkTicker.C:
			scanLinks()
			if state.changed && reportTimer == nil {
				reportTimer = time.After(self.settings.ReportDelay)
			}
		}
	}
}
