//go:build darwin && !ios && !sdk_mobile_bind

// §17.7.1's advertising proxy on macOS (owner decision 778; draft-ietf-dnssd-advertising-proxy's role, on the viewer's
// own machine alone): for each instance the viewer keeps, on one DNSServiceCreateConnection (dnssd_darwin.go), a
// LocalOnly A record for its target, an AAAA record at its translated address while ur tun's translator runs (§17.5),
// and a LocalOnly registration of the instance: its type and subtypes, its port, host = that target, and its TXT
// unchanged, so a client's own check of it, CoreDevice's of its authTag among them, still holds; the instance with
// kDNSServiceFlagsNoAutoRename. mDNSResponder never probes a LocalOnly record or sends one on any interface, and only
// this machine's browsers find it (dns_sd.h), so Xcode and every app browsing local. see the instance, and the host's
// LAN sees nothing.
//
//	target    <label>.<client-name>.local. (sidecar.BridgeDiscoveryRegistrations): the device's own label under its
//	          host's client name, which no LAN host holds, since a unique LocalOnly address record hides that name's
//	          other answers on the machine
//	apply     Set hands over the whole set and returns; the proxy's own goroutine brings the registrations to it, so
//	          the discovery component's goroutine never waits on mDNSResponder: a target's records before the instances
//	          that point at it, a withdrawal at once (DNSServiceRefDeallocate, which sends nothing on the wire for a
//	          LocalOnly record), and a record whose address moved replaced by one at the new address, which
//	          mDNSResponder's lookups hear as a removal and an addition
//	failure   a connection that ends, mDNSResponder's restart among them, is built again after RetryInterval, doubling
//	          to RetryMaxInterval, and the set registered whole on it
//	refused   an instance mDNSResponder refuses, a name another LocalOnly registration on this machine holds, is left
//	          out and counted until the set's next change, which tries it again
//	moves     a target whose address moves takes a record at the new address in place of the old, and the instances
//	          that point at it stay registered, so a browser sees no instance go
//
// Names, types, TXT and addresses reach no log (I-13).

package main

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar"
)

func init() {
	urDiscoveryProxyOf = func(ctx context.Context, log sidecar.Logger, link urDiscoveryProxyLink) urDiscoveryProxy {
		return newUrDarwinDiscoveryProxy(ctx, log, defaultUrDiscoveryProxySettings(), func() (urDarwinDnsSdConnection, error) {
			return newDarwinDnsSdConnection()
		}, nil)
	}
}

// The proxy's tunables.
type urDiscoveryProxySettings struct {
	// How long the proxy waits before it builds a connection that failed again: 1 s, doubling at each further failure to
	// RetryMaxInterval, 1 min. Both positive.
	RetryInterval    time.Duration
	RetryMaxInterval time.Duration
	// The TTL of a target's address records: 120 s, RFC 6762 §10's for a host name's records. A LocalOnly lookup hears
	// a withdrawal at once whatever it is.
	AddressTtl time.Duration
}

// The values above.
func defaultUrDiscoveryProxySettings() *urDiscoveryProxySettings {
	return &urDiscoveryProxySettings{
		RetryInterval:    1 * time.Second,
		RetryMaxInterval: 1 * time.Minute,
		AddressTtl:       120 * time.Second,
	}
}

// What the proxy needs of a connection to mDNSResponder: dnssd_darwin.go's, which a test may fake.
type urDarwinDnsSdConnection interface {
	Register(flags uint32, index uint32, name string, service string, domain string, host string, port uint16, txt []byte,
		handle func(reply *darwinDnsSdRegisterReply)) (*darwinDnsSdOperation, error)
	RegisterRecord(flags uint32, index uint32, fullName string, rrtype uint16, rdata []byte, ttl uint32,
		handle func(err error)) (*darwinDnsSdRecord, error)
	RemoveRecord(record *darwinDnsSdRecord)
	Cancel(operation *darwinDnsSdOperation)
	Done() <-chan struct{}
	Close()
}

// One target's address records as the proxy wants them.
type urDarwinProxyTargetWant struct {
	ipv4 netip.Addr
	// invalid while the translator is off
	ipv6 netip.Addr
}

// One instance's registration as the proxy wants it.
type urDarwinProxyServiceWant struct {
	name string
	// the type, then each subtype, as DNSServiceRegister's regtype takes them: "_type._tcp,_sub1,_sub2"
	regtype string
	host    string
	port    uint16
	txt     string
}

// What Set last handed over.
type urDarwinProxyWant struct {
	targets  map[string]urDarwinProxyTargetWant
	services []urDarwinProxyServiceWant
}

// One target's records as registered.
type urDarwinProxyTargetHeld struct {
	want urDarwinProxyTargetWant
	a    *darwinDnsSdRecord
	aaaa *darwinDnsSdRecord
}

// One instance's registration as registered, and whether mDNSResponder refused it.
type urDarwinProxyServiceHeld struct {
	want      urDarwinProxyServiceWant
	operation *darwinDnsSdOperation
	refused   *atomic.Bool
}

// The macOS advertising proxy. See the file's comment.
type urDarwinDiscoveryProxy struct {
	ctx      context.Context
	cancel   context.CancelFunc
	log      sidecar.Logger
	settings *urDiscoveryProxySettings
	connect  func() (urDarwinDnsSdConnection, error)
	// closed when run has returned
	done chan struct{}
	// wakes apply; buffered one
	wake chan struct{}

	stateLock sync.Mutex
	want      *urDarwinProxyWant
	// what apply last published
	status urDiscoveryProxyStatus

	// what apply holds, its own alone: the connection, the targets' records, the instances' registrations, the set it
	// last brought them to and the instances mDNSResponder refused under that set
	connection  urDarwinDnsSdConnection
	targets     map[string]*urDarwinProxyTargetHeld
	services    map[urDarwinProxyServiceWant]*urDarwinProxyServiceHeld
	appliedWant *urDarwinProxyWant
	refused     map[urDarwinProxyServiceWant]bool
	// called after each apply with the status it published; nil for none. A test's barrier.
	onApply func(status urDiscoveryProxyStatus)
}

// The proxy over connect, its goroutine running until ctx ends or Close; onApply, nil outside a test, hears each apply.
func newUrDarwinDiscoveryProxy(ctx context.Context, log sidecar.Logger, settings *urDiscoveryProxySettings,
	connect func() (urDarwinDnsSdConnection, error), onApply func(status urDiscoveryProxyStatus)) *urDarwinDiscoveryProxy {
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &urDarwinDiscoveryProxy{
		ctx:      cancelCtx,
		cancel:   cancel,
		log:      log,
		settings: settings,
		connect:  connect,
		done:     make(chan struct{}),
		wake:     make(chan struct{}, 1),
		want:     &urDarwinProxyWant{targets: map[string]urDarwinProxyTargetWant{}},
		targets:  map[string]*urDarwinProxyTargetHeld{},
		services: map[urDarwinProxyServiceWant]*urDarwinProxyServiceHeld{},
		refused:  map[urDarwinProxyServiceWant]bool{},
		onApply:  onApply,
	}
	go self.run()
	return self
}

// urDiscoveryProxy: hands over the registrations, each target's AAAA at translated's answer, and wakes apply.
func (self *urDarwinDiscoveryProxy) Set(registrations []*sidecar.BridgeDiscoveryRegistration, translated func(address netip.Addr) netip.Addr) {
	want := urDarwinProxyWantOf(registrations, translated)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.want = want
	}()
	self.poke()
}

// Wakes apply.
func (self *urDarwinDiscoveryProxy) poke() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// urDiscoveryProxy: withdraws everything and stops.
func (self *urDarwinDiscoveryProxy) Close() {
	self.cancel()
	<-self.done
}

// urDiscoveryProxy: what the proxy holds, as apply last left it.
func (self *urDarwinDiscoveryProxy) Status() urDiscoveryProxyStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.status
}

// What the registrations ask for: each target once, at its instance's address, and each instance whose target and
// type mDNSResponder can take. A registration whose target is no host name is left out.
func urDarwinProxyWantOf(registrations []*sidecar.BridgeDiscoveryRegistration, translated func(address netip.Addr) netip.Addr) *urDarwinProxyWant {
	want := &urDarwinProxyWant{targets: map[string]urDarwinProxyTargetWant{}}
	for _, registration := range registrations {
		instance := registration.Instance
		if instance == nil || !instance.Address.Is4() {
			continue
		}
		host, ok := urDiscoveryProxyTarget(registration.Target)
		if !ok {
			continue
		}
		target := urDarwinProxyTargetWant{ipv4: instance.Address}
		if translated != nil {
			target.ipv6 = translated(instance.Address)
		}
		if held, taken := want.targets[host]; taken && held != target {
			// one target at two addresses: the device's label under one host names one device, so the first stands
			continue
		}
		want.targets[host] = target
		regtype := instance.Service
		for _, subtype := range instance.Subtypes {
			// a comma would split the subtype in two in DNSServiceRegister's regtype
			if !strings.Contains(subtype, ",") {
				regtype += "," + subtype
			}
		}
		want.services = append(want.services, urDarwinProxyServiceWant{
			name:    registration.Name,
			regtype: regtype,
			host:    host,
			port:    instance.Port,
			txt:     string(instance.Txt),
		})
	}
	return want
}

// Brings the registrations to each set handed over until the proxy closes, building the connection again after a
// failure, then withdraws everything.
func (self *urDarwinDiscoveryProxy) run() {
	defer close(self.done)
	defer self.withdrawAll()
	retry := self.settings.RetryInterval
	for {
		var connectionDone <-chan struct{}
		if self.connection == nil {
			if err := self.open(); err != nil {
				if self.log.V(1).Enabled() {
					self.log.Infof("[discovery]the advertising proxy reaches no mDNSResponder, tried again in %s: %v", retry, err)
				}
				select {
				case <-self.ctx.Done():
					return
				case <-time.After(retry):
				}
				retry = min(2*retry, self.settings.RetryMaxInterval)
				continue
			}
		}
		connectionDone = self.connection.Done()
		select {
		case <-connectionDone:
			// mDNSResponder's end of it is gone, and with it everything registered on it
			self.forget()
			continue
		default:
		}
		retry = self.settings.RetryInterval
		self.apply()
		select {
		case <-self.ctx.Done():
			return
		case <-self.wake:
		case <-connectionDone:
			self.forget()
		}
	}
}

// Opens a connection.
func (self *urDarwinDiscoveryProxy) open() error {
	connection, err := self.connect()
	if err != nil {
		return err
	}
	self.connection = connection
	return nil
}

// Forgets a connection that ended and what was registered on it.
func (self *urDarwinDiscoveryProxy) forget() {
	if self.connection != nil {
		self.connection.Close()
	}
	self.connection = nil
	clear(self.targets)
	clear(self.services)
	self.publish(0)
}

// Withdraws everything and closes the connection.
func (self *urDarwinDiscoveryProxy) withdrawAll() {
	if self.connection == nil {
		return
	}
	for key, held := range self.services {
		self.connection.Cancel(held.operation)
		delete(self.services, key)
	}
	for host, held := range self.targets {
		self.connection.RemoveRecord(held.a)
		self.connection.RemoveRecord(held.aaaa)
		delete(self.targets, host)
	}
	self.connection.Close()
	self.connection = nil
	self.publish(0)
}

// Publishes what is registered now, with refusedCount beside what mDNSResponder refused under the set.
func (self *urDarwinDiscoveryProxy) publish(refusedCount int) {
	registeredCount := 0
	for _, held := range self.services {
		if held.refused.Load() {
			refusedCount += 1
		} else {
			registeredCount += 1
		}
	}
	status := urDiscoveryProxyStatus{RegisteredCount: registeredCount, RefusedCount: refusedCount + len(self.refused)}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.status = status
	}()
	if self.onApply != nil {
		self.onApply(status)
	}
}

// Brings what is registered to the set handed over: instances no longer wanted withdrawn, and those mDNSResponder
// refused, which wait for the set's next change; each target's records, a moved one's replaced; then the instances
// wanted, a target's records going once no instance points at them.
func (self *urDarwinDiscoveryProxy) apply() {
	want := func() *urDarwinProxyWant {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.want
	}()
	if want != self.appliedWant {
		self.appliedWant = want
		clear(self.refused)
	}
	connection := self.connection
	wantedServices := map[urDarwinProxyServiceWant]bool{}
	for _, service := range want.services {
		wantedServices[service] = true
	}
	for key, held := range self.services {
		if held.refused.Load() {
			self.refused[key] = true
		}
		if !wantedServices[key] || held.refused.Load() {
			connection.Cancel(held.operation)
			delete(self.services, key)
		}
	}
	refusedCount := 0
	for host, held := range self.targets {
		if target, wanted := want.targets[host]; wanted && held.want == target {
			continue
		}
		connection.RemoveRecord(held.a)
		connection.RemoveRecord(held.aaaa)
		delete(self.targets, host)
	}
	for host, target := range want.targets {
		if self.targets[host] != nil {
			continue
		}
		held, err := self.registerTarget(host, target)
		if err != nil {
			refusedCount += 1
			continue
		}
		self.targets[host] = held
	}
	for _, service := range want.services {
		if self.services[service] != nil || self.refused[service] || self.targets[service.host] == nil {
			continue
		}
		refused := &atomic.Bool{}
		operation, err := connection.Register(darwinDnsSdFlagsNoAutoRename, darwinDnsSdInterfaceIndexLocalOnly, service.name,
			service.regtype, "local.", service.host, service.port, []byte(service.txt), func(reply *darwinDnsSdRegisterReply) {
				// on the connection's reader, which apply's calls wait on: mark it, and apply withdraws it
				if reply.Err != nil && !refused.Swap(true) {
					self.poke()
				}
			})
		if err != nil {
			self.refused[service] = true
			continue
		}
		self.services[service] = &urDarwinProxyServiceHeld{want: service, operation: operation, refused: refused}
	}
	self.publish(refusedCount)
}

// Registers a target's A record, and its AAAA where it has an IPv6 address.
func (self *urDarwinDiscoveryProxy) registerTarget(host string, target urDarwinProxyTargetWant) (*urDarwinProxyTargetHeld, error) {
	ttl := uint32(self.settings.AddressTtl / time.Second)
	ipv4 := target.ipv4.As4()
	a, err := self.connection.RegisterRecord(darwinDnsSdFlagsUnique, darwinDnsSdInterfaceIndexLocalOnly, host, darwinDnsSdTypeA,
		ipv4[:], ttl, nil)
	if err != nil {
		return nil, err
	}
	held := &urDarwinProxyTargetHeld{want: target, a: a}
	if target.ipv6.Is6() {
		ipv6 := target.ipv6.As16()
		aaaa, err := self.connection.RegisterRecord(darwinDnsSdFlagsUnique, darwinDnsSdInterfaceIndexLocalOnly, host,
			darwinDnsSdTypeAaaa, ipv6[:], ttl, nil)
		if err != nil {
			self.connection.RemoveRecord(a)
			return nil, err
		}
		held.aaaa = aaaa
	}
	return held, nil
}
