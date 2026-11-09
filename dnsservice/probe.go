// Interface probes and the healthy set (§12.6; owner decision 34; D-DNS-6). Every probe.interval_s
// each edge probes each lb interface the feed names, on each of tlsedge's ports, and answers *, @, each
// copy of *'s records and, from M7, each mx from what passes, with no journal write: a health drop
// reaches every name answered from the set at once.
//
// An address leaves the set after probe.failures consecutive failures on any one port, since a visitor
// cannot pick a port (reading 7), while the feed names its interface map-stale (M6), or while
// sidecar.yml's drained lists it (W1), which the host rereads every 60 s; one probe that passes on
// every port brings it back. The two families are judged apart, as A and AAAA are answered apart, so a
// broken IPv6 path drops only the AAAA. Never all: a round that would leave a family with no address
// keeps that family's last set and says so (§12.6).
//
// Router interfaces serve mx hosts. Their own probe is the 25 banner, which lands in DNS-M7-01 on this
// loop, as probe_route.go's route probes run on it; until then a router interface leaves the mx set
// only while drained. A route probe's result goes to the block and never moves the healthy set.
//
// The set swaps through the edge's atomic pointer, so the answer path takes no lock. The prober logs no
// address, and its per-interface gauge is labeled by inventory name and family only (I-13).

package dnsservice

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
)

// The family label of the interface gauge.
const (
	dnsFamilyIpv4 = "ipv4"
	dnsFamilyIpv6 = "ipv6"
)

// One probed address and port of one interface: what consecutive failures are counted against.
type dnsProbeKey struct {
	name   string
	family string
	port   int
}

// What a prober takes beyond its host and settings.
type ProberDeps struct {
	// How probes reach the lb. Required.
	Dialer DnsProbeDialer
	// Where each round's route probes go: NewDnsRouteProbeSinkHttp on a host, or a fake. nil sends no
	// route probe (probe_route.go).
	RouteProbes DnsRouteProbeSink
	// Lifecycle only: nothing here logs an address. nil discards.
	Log sidecar.Logger
}

// The prober. Safe for concurrent use.
type Prober struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *DnsSettings
	clock    sidecar.Clock
	gates    sidecar.ServiceGates
	log      sidecar.Logger
	metrics  *dnsMetrics
	dialer   DnsProbeDialer
	publish  func(healthy *HealthySet)
	// The hello each root's probes send, made once.
	hellos [][]byte
	// The custom-host map's route probes, which run in each round's pool.
	routes *dnsRouteProbes
	// Rounds finished, each counted once the wait for the next is armed, so a test sees one land and
	// can then move a fake clock past the next.
	roundCount *sidecar.MonitorValue[int]

	stateLock  sync.Mutex
	interfaces []DnsLbInterface
	failures   map[dnsProbeKey]int
	// What was last published, which never-all keeps a family of.
	lastEdge   []DnsLbInterface
	lastRouter []DnsLbInterface
}

// A prober for settings' roots, publishing each healthy set through publish, the edge's SetHealthySet.
// host needs Metrics; its Gates give drained (nil reads none drained) and its Clock every wait. It
// probes nothing until SetInterfaces names an interface, and runs until ctx ends or Close.
func NewProber(ctx context.Context, host *sidecar.ServiceHost, settings *DnsSettings, deps *ProberDeps, publish func(healthy *HealthySet)) (*Prober, error) {
	if host == nil || host.Metrics == nil {
		return nil, errors.New("prober needs a host with Metrics")
	}
	if deps == nil || deps.Dialer == nil {
		return nil, errors.New("prober needs a dialer")
	}
	if publish == nil {
		return nil, errors.New("prober needs somewhere to publish")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	hellos := [][]byte{}
	for _, root := range settings.Roots {
		hello, err := dnsProbeClientHello(dnsProbeServerName(root), nil)
		if err != nil {
			return nil, fmt.Errorf("the probe hello: %w", err)
		}
		hellos = append(hellos, hello)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &Prober{
		ctx:        cancelCtx,
		cancel:     cancel,
		settings:   settings,
		clock:      host.ClockOrReal(),
		gates:      host.GatesOrClosed(),
		log:        log,
		metrics:    newDnsMetrics(host.Metrics),
		dialer:     deps.Dialer,
		publish:    publish,
		hellos:     hellos,
		roundCount: sidecar.NewMonitorValue(0),
		failures:   map[dnsProbeKey]int{},
	}
	self.routes = newDnsRouteProbes(settings, self.clock, self.metrics, deps.RouteProbes)
	go self.run()
	return self, nil
}

// Rounds finished, and a channel that closes at the next.
func (self *Prober) Rounds() (count int, changed chan struct{}) {
	return self.roundCount.Get()
}

// The interfaces to probe from now on, as the feed's last answer names them, with their map state. An
// interface new to the list joins healthy, and one gone from it is forgotten. Publishes at once, so a
// new interface or a drain the feed reports needs no round.
func (self *Prober) SetInterfaces(interfaces []DnsLbInterface) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.interfaces = slices.Clone(interfaces)
		names := map[string]bool{}
		for index := range interfaces {
			names[interfaces[index].Name] = true
		}
		for key := range self.failures {
			if !names[key.name] {
				delete(self.failures, key)
			}
		}
	}()
	self.publishHealthy()
}

// Probes every round until the prober ends.
func (self *Prober) run() {
	for {
		self.round()
		next := self.clock.After(dnsSeconds(self.settings.Probe.IntervalSeconds))
		self.roundCount.Update(func(count int) int { return count + 1 })
		select {
		case <-self.ctx.Done():
			return
		case <-next:
		}
	}
}

// One round: every interface's every address on every port, for every root, and the route probes the
// feed's map fields ask for, at most probe.concurrency at once; then the counts move, the set is
// published and the route probes' results go to the block.
func (self *Prober) round() {
	type probeTask struct {
		key     dnsProbeKey
		address netip.AddrPort
	}
	tasks := []probeTask{}
	var interfaces []DnsLbInterface
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		interfaces = slices.Clone(self.interfaces)
		for index := range self.interfaces {
			lbInterface := &self.interfaces[index]
			for _, port := range self.settings.Probe.Ports {
				for _, family := range []string{dnsFamilyIpv4, dnsFamilyIpv6} {
					address := dnsInterfaceAddress(lbInterface, family)
					if !address.IsValid() {
						continue
					}
					tasks = append(tasks, probeTask{
						key:     dnsProbeKey{name: lbInterface.Name, family: family, port: port},
						address: netip.AddrPortFrom(address, uint16(port)),
					})
				}
			}
		}
	}()
	routeProbes := self.routes.probes(interfaces)
	if len(tasks) == 0 && len(routeProbes) == 0 {
		return
	}
	passed := make([]bool, len(tasks))
	slots := make(chan struct{}, self.settings.Probe.ConcurrencyCount)
	var group sync.WaitGroup
	timeout := dnsSeconds(self.settings.Probe.TimeoutSeconds)
	start := func(probe func()) {
		group.Add(1)
		slots <- struct{}{}
		go func() {
			defer group.Done()
			defer func() { <-slots }()
			probe()
		}()
	}
	for index := range tasks {
		start(func() {
			pass := true
			for _, hello := range self.hellos {
				if !dnsProbeOnce(self.ctx, self.clock, timeout, self.dialer, tasks[index].address, hello) {
					pass = false
					break
				}
			}
			passed[index] = pass
		})
	}
	for _, routeProbe := range routeProbes {
		start(func() {
			routeProbe.passed = routeProbe.hello != nil &&
				dnsProbeOnce(self.ctx, self.clock, timeout, self.dialer, routeProbe.address, routeProbe.hello)
		})
	}
	group.Wait()
	if self.ctx.Err() != nil {
		return
	}
	defer self.routes.report(self.ctx, routeProbes)
	if len(tasks) == 0 {
		return
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for index, task := range tasks {
			if passed[index] {
				delete(self.failures, task.key)
			} else {
				self.failures[task.key] += 1
			}
		}
	}()
	self.publishHealthy()
}

// An interface's address of a family, unmapped, or the zero value.
func dnsInterfaceAddress(lbInterface *DnsLbInterface, family string) netip.Addr {
	if family == dnsFamilyIpv4 {
		if address := lbInterface.Ipv4.Unmap(); address.Is4() {
			return address
		}
		return netip.Addr{}
	}
	if address := lbInterface.Ipv6; address.Is6() && !address.Is4In6() {
		return address
	}
	return netip.Addr{}
}

// The healthy set from the counts, drains and map state now, with never-all applied, published and
// gauged.
func (self *Prober) publishHealthy() {
	drained := self.gates.Drained()
	var edge []DnsLbInterface
	var router []DnsLbInterface
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		failureCount := self.settings.Probe.FailureCount
		healthy := func(lbInterface *DnsLbInterface, family string) bool {
			if !dnsInterfaceAddress(lbInterface, family).IsValid() || slices.Contains(drained, lbInterface.Name) {
				return false
			}
			for _, port := range self.settings.Probe.Ports {
				if failureCount <= self.failures[dnsProbeKey{name: lbInterface.Name, family: family, port: port}] {
					return false
				}
			}
			return true
		}
		for index := range self.interfaces {
			lbInterface := self.interfaces[index]
			kept := DnsLbInterface{Name: lbInterface.Name, Router: lbInterface.Router}
			if !lbInterface.MapStale && healthy(&lbInterface, dnsFamilyIpv4) {
				kept.Ipv4 = lbInterface.Ipv4
			}
			if !lbInterface.MapStale && healthy(&lbInterface, dnsFamilyIpv6) {
				kept.Ipv6 = lbInterface.Ipv6
			}
			for _, family := range []string{dnsFamilyIpv4, dnsFamilyIpv6} {
				if dnsInterfaceAddress(&lbInterface, family).IsValid() {
					value := 0.0
					if dnsInterfaceAddress(&kept, family).IsValid() {
						value = 1
					}
					self.metrics.interfaceHealthy.Set(value, lbInterface.Name, family)
				}
			}
			edge = append(edge, kept)
			if lbInterface.Router {
				// the 25 banner is DNS-M7-01's: until then only a drain takes a router out
				routed := DnsLbInterface{Name: lbInterface.Name, Router: true}
				if !slices.Contains(drained, lbInterface.Name) {
					routed.Ipv4, routed.Ipv6 = lbInterface.Ipv4, lbInterface.Ipv6
				}
				router = append(router, routed)
			}
		}
		edge = self.neverAll(edge, self.lastEdge, "edge")
		router = self.neverAll(router, self.lastRouter, "router")
		self.lastEdge = edge
		self.lastRouter = router
	}()
	self.publish(NewHealthySet(edge, router))
}

// next, or where it leaves a family with no address that last had some, next with last's addresses of
// that family: §12.6's never all. Gauged by set and family.
func (self *Prober) neverAll(next []DnsLbInterface, last []DnsLbInterface, set string) []DnsLbInterface {
	for _, family := range []string{dnsFamilyIpv4, dnsFamilyIpv6} {
		has := func(interfaces []DnsLbInterface) bool {
			return slices.ContainsFunc(interfaces, func(lbInterface DnsLbInterface) bool {
				return dnsInterfaceAddress(&lbInterface, family).IsValid()
			})
		}
		held := 0.0
		if !has(next) && has(last) {
			held = 1
			if self.log.V(1).Enabled() {
				self.log.Infof("[dnsedge] every %s %s address failed; keeping the last", set, family)
			}
			for _, kept := range last {
				if address := dnsInterfaceAddress(&kept, family); address.IsValid() {
					next = append(next, dnsInterfaceWith(DnsLbInterface{Name: kept.Name, Router: kept.Router}, family, address))
				}
			}
		}
		self.metrics.healthyHeld.Set(held, set, family)
	}
	return next
}

// lbInterface with address as its family's.
func dnsInterfaceWith(lbInterface DnsLbInterface, family string, address netip.Addr) DnsLbInterface {
	if family == dnsFamilyIpv4 {
		lbInterface.Ipv4 = address
	} else {
		lbInterface.Ipv6 = address
	}
	return lbInterface
}

// Stops probing. Safe more than once.
func (self *Prober) Close() {
	self.cancel()
}
