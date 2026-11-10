// Interface probes and the healthy set (§12.6; owner decision 34; D-DNS-6). Every probe.interval_s
// each edge probes each lb interface the feed names, on each of tlsedge's ports, and each router
// interface on probe.smtp_port too, and answers *, @, each copy of *'s records and each mx from what
// passes, with no journal write: a health drop reaches every name answered from the set at once.
//
// The set holds two lists, as HealthySet answers edge and router rows apart:
//
//   - Edge, for user names: an address leaves after probe.failures consecutive failures of tlsedge's
//     alert on any one port, since a visitor cannot pick a port (reading 7), while the feed names its
//     interface map-stale (M6), or while sidecar.yml's drained lists it (W1), which the host rereads
//     every 60 s; one probe that passes on every port brings it back.
//   - Router, for mx hosts (DNS-M7-01): a router interface's address leaves after probe.failures
//     consecutive failures of its 25 banner (probe_smtp.go), or while drained; one banner that passes
//     brings it back. Neither tlsedge's alert nor the custom-host map moves it, since mail meets
//     neither, and the banner moves nothing but it: a failure drops an interface from mx only.
//
// The two families are judged apart, as A and AAAA are answered apart, so a broken IPv6 path drops only
// the AAAA. Never all: a round that would leave a list with no address of a family keeps that list's
// last addresses of the family and says so (§12.6). A route probe's result goes to the block and never
// moves the healthy set.
//
// The set swaps through the edge's atomic pointer, so the answer path takes no lock. The prober logs no
// address, and its per-interface gauges are labeled by inventory name and family only (I-13).

package dnsservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// The family label of the interface gauge.
const (
	dnsFamilyIpv4 = "ipv4"
	dnsFamilyIpv6 = "ipv6"
)

// One probed address and port of one interface: what consecutive failures are counted against. A
// router's banner keys on probe.smtp_port, which no tlsedge port may be, so the two never share a
// count.
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

// The interfaces to probe from now on, as the feed's last answer names them, with their router flags
// and map state. An interface new to the list joins healthy, and one gone from it is forgotten, as is
// the banner count of one no longer a router, so a router again starts afresh. Publishes at once, so
// a new interface or a drain the feed reports needs no round.
func (self *Prober) SetInterfaces(interfaces []DnsLbInterface) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.interfaces = slices.Clone(interfaces)
		names := map[string]bool{}
		routers := map[string]bool{}
		for index := range interfaces {
			names[interfaces[index].Name] = true
			routers[interfaces[index].Name] = interfaces[index].Router
		}
		for key := range self.failures {
			if !names[key.name] || (key.port == self.settings.Probe.SmtpPort && !routers[key.name]) {
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

// One round: every interface's every address on every tlsedge port, for every root, each router
// interface's every address's 25 banner, and the route probes the feed's map fields ask for, at most
// probe.concurrency at once; then the counts move, the set is published and the route probes' results
// go to the block.
func (self *Prober) round() {
	type probeTask struct {
		key     dnsProbeKey
		address netip.AddrPort
		// Reads the 25 banner, where any other task sends tlsedge each root's hello.
		banner bool
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
			if !lbInterface.Router {
				continue
			}
			smtpPort := self.settings.Probe.SmtpPort
			for _, family := range []string{dnsFamilyIpv4, dnsFamilyIpv6} {
				address := dnsInterfaceAddress(lbInterface, family)
				if !address.IsValid() {
					continue
				}
				tasks = append(tasks, probeTask{
					key:     dnsProbeKey{name: lbInterface.Name, family: family, port: smtpPort},
					address: netip.AddrPortFrom(address, uint16(smtpPort)),
					banner:  true,
				})
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
			task := &tasks[index]
			if task.banner {
				passed[index] = dnsSmtpProbeOnce(self.ctx, self.clock, timeout, self.dialer, task.address,
					self.settings.Probe.SmtpBannerMaxByteCount)
				return
			}
			pass := true
			for _, hello := range self.hellos {
				if !dnsProbeOnce(self.ctx, self.clock, timeout, self.dialer, task.address, hello) {
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
		answerable := func(lbInterface *DnsLbInterface, family string) bool {
			return dnsInterfaceAddress(lbInterface, family).IsValid() && !slices.Contains(drained, lbInterface.Name)
		}
		// tlsedge's alert on every port, for user names
		healthy := func(lbInterface *DnsLbInterface, family string) bool {
			if lbInterface.MapStale || !answerable(lbInterface, family) {
				return false
			}
			for _, port := range self.settings.Probe.Ports {
				if failureCount <= self.failures[dnsProbeKey{name: lbInterface.Name, family: family, port: port}] {
					return false
				}
			}
			return true
		}
		// the 25 banner alone, for mx hosts
		routing := func(lbInterface *DnsLbInterface, family string) bool {
			key := dnsProbeKey{name: lbInterface.Name, family: family, port: self.settings.Probe.SmtpPort}
			return answerable(lbInterface, family) && self.failures[key] < failureCount
		}
		// metric's value for each family the interface has an address of: whether kept answers it
		gauge := func(metric sidecar.MetricsGauge, lbInterface *DnsLbInterface, kept *DnsLbInterface) {
			for _, family := range []string{dnsFamilyIpv4, dnsFamilyIpv6} {
				if dnsInterfaceAddress(lbInterface, family).IsValid() {
					value := 0.0
					if dnsInterfaceAddress(kept, family).IsValid() {
						value = 1
					}
					metric.Set(value, lbInterface.Name, family)
				}
			}
		}
		for index := range self.interfaces {
			lbInterface := self.interfaces[index]
			kept := DnsLbInterface{Name: lbInterface.Name, Router: lbInterface.Router}
			if healthy(&lbInterface, dnsFamilyIpv4) {
				kept.Ipv4 = lbInterface.Ipv4
			}
			if healthy(&lbInterface, dnsFamilyIpv6) {
				kept.Ipv6 = lbInterface.Ipv6
			}
			gauge(self.metrics.interfaceHealthy, &lbInterface, &kept)
			edge = append(edge, kept)
			if lbInterface.Router {
				routed := DnsLbInterface{Name: lbInterface.Name, Router: true}
				if routing(&lbInterface, dnsFamilyIpv4) {
					routed.Ipv4 = lbInterface.Ipv4
				}
				if routing(&lbInterface, dnsFamilyIpv6) {
					routed.Ipv6 = lbInterface.Ipv6
				}
				gauge(self.metrics.routerHealthy, &lbInterface, &routed)
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

// One probe of address: a connection from dialer, which exchange works and judges, all within timeout
// on clock. Every fault is a failure, and none is logged, since a connection's error names its
// addresses. The timeout and ctx's end each cut the connection short, so a silent far side holds a
// probe no longer, and the connection closes when exchange returns.
func dnsProbeExchange(
	ctx context.Context,
	clock sidecar.Clock,
	timeout time.Duration,
	dialer DnsProbeDialer,
	address netip.AddrPort,
	exchange func(conn net.Conn) bool,
) bool {
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var connLock sync.Mutex
	var conn net.Conn
	cut := false
	context.AfterFunc(probeCtx, func() {
		connLock.Lock()
		defer connLock.Unlock()
		cut = true
		if conn != nil {
			conn.SetDeadline(dnsPastDeadline)
		}
	})
	stop := clock.AfterFunc(timeout, cancel)
	defer stop()
	dialed, err := dialer.DialProbe(probeCtx, address)
	if err != nil {
		return false
	}
	defer dialed.Close()
	if func() bool {
		connLock.Lock()
		defer connLock.Unlock()
		conn = dialed
		return cut
	}() {
		return false
	}
	return exchange(dialed)
}

// Stops probing. Safe more than once.
func (self *Prober) Close() {
	self.cancel()
}
