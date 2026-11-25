// The macOS gatherer's state (discovery_gather_darwin.go; §17.7.1's gather and how rows, owner decision 778), apart
// from mDNSResponder so it runs and is tested on every platform: per link, the instances its browses found, what each
// one's resolve answered, and each target's IPv4 addresses, starting and ending the resolves and lookups they need.
//
//	browse   an instance found on a link starts its resolve there; one gone ends it, and its target's lookup once no
//	         instance on that link points at the target
//	resolve  each answer sets the instance's target, port and TXT; a new target starts its lookup on the link
//	lookup   each answer adds or removes one of the target's IPv4 addresses; IPv6 is never asked, since the overlay
//	         carries none
//	report   each instance of a listed type whose target has an address, as BridgeDiscoveryGathered, expiring ReportTtl
//	         after the report: mDNSResponder keeps an instance's records fresh while its operations stand and says when
//	         one goes, so the gatherer reports again within each ReportTtl while it holds the instance
//	bounds   at most InstanceCount instances and as many targets over all links, the rest not resolved
//	never    a reply from another link than the one asked, and a LocalOnly instance: this machine's own registration,
//	         the advertising proxy's among them, which is marked so and never published (§17.7.1's loops row)
//
// No subtype is gathered: DNS-SD browses a subtype only by its name, and no list names them. Not safe for concurrent
// use: the gatherer's one goroutine owns it.

package main

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The gatherer's tunables.
type urDnsSdGatherSettings struct {
	// How long a reported instance stands unless reported again: 120 s, RFC 6762 §10's TTL for a host name's records.
	// The gatherer reports again every half of it while it holds the instance. Positive.
	ReportTtl time.Duration
	// How long changes coalesce before a report: 100 ms, so a browse's burst is one report.
	ReportDelay time.Duration
	// How often the links are read again: 30 s, for a link that came or went.
	LinkInterval time.Duration
	// How long the gatherer waits before it builds a connection that failed again: 1 s, doubling at each further
	// failure to RetryMaxInterval, 1 min.
	RetryInterval    time.Duration
	RetryMaxInterval time.Duration
	// The most instances, and targets, the gatherer holds over all links: 1,024 each, the rest left unresolved.
	InstanceCount int
	// The most replies waiting for the gatherer's goroutine before it drops the connection and builds it again: 8,192,
	// eight for each instance, past any burst one browse's answers make.
	QueueCount int
}

// The values above.
func defaultUrDnsSdGatherSettings() *urDnsSdGatherSettings {
	return &urDnsSdGatherSettings{
		ReportTtl:        120 * time.Second,
		ReportDelay:      100 * time.Millisecond,
		LinkInterval:     30 * time.Second,
		RetryInterval:    1 * time.Second,
		RetryMaxInterval: 1 * time.Minute,
		InstanceCount:    1024,
		QueueCount:       8192,
	}
}

// The interface index mDNSResponder gives a LocalOnly registration's replies (dns_sd.h's
// kDNSServiceInterfaceIndexLocalOnly): an identifier, so a constant on every platform.
const urDnsSdLocalOnlyIndex = 0xFFFFFFFF

// An instance on one link.
type urDnsSdInstanceKey struct {
	index uint32
	// the name lowercased, and its type lowercased without its trailing dot
	name    string
	service string
}

// A target on one link.
type urDnsSdHostKey struct {
	index uint32
	// lowercased, with its trailing dot
	host string
}

// One instance a browse found, and what its resolve answered.
type urDnsSdInstance struct {
	// as the browse gave them, which the resolve and the report take
	name    string
	service string
	domain  string
	// ends its resolve
	stopResolve func()
	// its target once resolved, empty before
	host string
	port uint16
	txt  []byte
}

// One target's lookup and the addresses it holds.
type urDnsSdHost struct {
	stopLookup func()
	addresses  map[netip.Addr]bool
	// the instances on its link that point at it
	referenceCount int
}

// What the gatherer knows. See the file's comment.
type urDnsSdGatherState struct {
	settings *urDnsSdGatherSettings
	// the list's types, lowercased
	types     map[string]bool
	instances map[urDnsSdInstanceKey]*urDnsSdInstance
	hosts     map[urDnsSdHostKey]*urDnsSdHost
	// start a resolve or a lookup, answering what ends it, nil where it did not start
	resolve func(key urDnsSdInstanceKey, instance *urDnsSdInstance) func()
	lookup  func(key urDnsSdHostKey) func()
	// whether anything a report shows changed since the last report
	changed bool
}

// The state over types, its resolves and lookups started by resolve and lookup.
func newUrDnsSdGatherState(settings *urDnsSdGatherSettings, types []string, resolve func(key urDnsSdInstanceKey, instance *urDnsSdInstance) func(),
	lookup func(key urDnsSdHostKey) func()) *urDnsSdGatherState {
	held := map[string]bool{}
	for _, serviceType := range types {
		held[strings.ToLower(serviceType)] = true
	}
	return &urDnsSdGatherState{
		settings:  settings,
		types:     held,
		instances: map[urDnsSdInstanceKey]*urDnsSdInstance{},
		hosts:     map[urDnsSdHostKey]*urDnsSdHost{},
		resolve:   resolve,
		lookup:    lookup,
	}
}

// A type as a browse's reply names it, "_smb._tcp.", as the list holds it.
func urDnsSdServiceOf(regtype string) string {
	return strings.ToLower(strings.TrimSuffix(regtype, "."))
}

// A browse on link index found an instance (add) or lost it.
func (self *urDnsSdGatherState) browsed(index uint32, replyIndex uint32, add bool, name string, regtype string, domain string) {
	service := urDnsSdServiceOf(regtype)
	if replyIndex != index || !self.types[service] || name == "" {
		return
	}
	key := urDnsSdInstanceKey{index: index, name: strings.ToLower(name), service: service}
	instance := self.instances[key]
	if !add {
		if instance != nil {
			self.dropInstance(key, instance)
		}
		return
	}
	if instance != nil || self.settings.InstanceCount <= len(self.instances) {
		return
	}
	instance = &urDnsSdInstance{name: name, service: service, domain: domain}
	self.instances[key] = instance
	instance.stopResolve = self.resolve(key, instance)
}

// Ends an instance: its resolve, and its target's lookup where no other instance on its link points at it.
func (self *urDnsSdGatherState) dropInstance(key urDnsSdInstanceKey, instance *urDnsSdInstance) {
	if instance.stopResolve != nil {
		instance.stopResolve()
	}
	if instance.host != "" {
		self.releaseHost(urDnsSdHostKey{index: key.index, host: instance.host})
		self.changed = true
	}
	delete(self.instances, key)
}

// Takes one reference to a target, starting its lookup at the first. False where the targets are at their bound.
func (self *urDnsSdGatherState) holdHost(key urDnsSdHostKey) bool {
	host := self.hosts[key]
	if host == nil {
		if self.settings.InstanceCount <= len(self.hosts) {
			return false
		}
		host = &urDnsSdHost{addresses: map[netip.Addr]bool{}}
		self.hosts[key] = host
		host.stopLookup = self.lookup(key)
	}
	host.referenceCount += 1
	return true
}

// Drops one reference to a target, ending its lookup at the last.
func (self *urDnsSdGatherState) releaseHost(key urDnsSdHostKey) {
	host := self.hosts[key]
	if host == nil {
		return
	}
	host.referenceCount -= 1
	if 0 < host.referenceCount {
		return
	}
	if host.stopLookup != nil {
		host.stopLookup()
	}
	delete(self.hosts, key)
}

// An instance's resolve answered its target, port and TXT.
func (self *urDnsSdGatherState) resolved(key urDnsSdInstanceKey, host string, port uint16, txt []byte) {
	instance := self.instances[key]
	if instance == nil || host == "" {
		return
	}
	host = strings.ToLower(host)
	if !strings.HasSuffix(host, ".") {
		host += "."
	}
	if instance.host != host {
		if instance.host != "" {
			self.releaseHost(urDnsSdHostKey{index: key.index, host: instance.host})
			instance.host = ""
		}
		if !self.holdHost(urDnsSdHostKey{index: key.index, host: host}) {
			self.changed = true
			return
		}
		instance.host = host
		self.changed = true
	}
	if instance.port != port || string(instance.txt) != string(txt) {
		instance.port = port
		instance.txt = slices.Clone(txt)
		self.changed = true
	}
}

// A target's lookup found an address (add) or lost it.
func (self *urDnsSdGatherState) addressed(key urDnsSdHostKey, add bool, address netip.Addr) {
	host := self.hosts[key]
	address = address.Unmap()
	if host == nil || !address.Is4() || host.addresses[address] == add {
		return
	}
	if add {
		host.addresses[address] = true
	} else {
		delete(host.addresses, address)
	}
	self.changed = true
}

// Ends everything on link index: its instances' resolves and its targets' lookups.
func (self *urDnsSdGatherState) dropLink(index uint32) {
	for key, instance := range self.instances {
		if key.index == index {
			self.dropInstance(key, instance)
		}
	}
}

// Ends everything, as a connection that failed did.
func (self *urDnsSdGatherState) clear() {
	for key, instance := range self.instances {
		self.dropInstance(key, instance)
	}
}

// What a report shows at now: every resolved instance whose target has an address, own where one of them is
// localAddresses', LocalOnly where its link is, sorted by type then name, each expiring ReportTtl from now.
func (self *urDnsSdGatherState) gathered(now time.Time, localAddresses []netip.Addr) []*sidecar.BridgeDiscoveryGathered {
	out := []*sidecar.BridgeDiscoveryGathered{}
	for key, instance := range self.instances {
		if instance.host == "" || instance.port == 0 {
			continue
		}
		host := self.hosts[urDnsSdHostKey{index: key.index, host: instance.host}]
		if host == nil || len(host.addresses) == 0 {
			continue
		}
		addresses := []netip.Addr{}
		for address := range host.addresses {
			addresses = append(addresses, address)
		}
		slices.SortFunc(addresses, netip.Addr.Compare)
		out = append(out, &sidecar.BridgeDiscoveryGathered{
			Name:      instance.name,
			Service:   instance.service,
			Port:      instance.port,
			Txt:       slices.Clone(instance.txt),
			HostName:  instance.host,
			Addresses: addresses,
			Own: slices.ContainsFunc(addresses, func(address netip.Addr) bool {
				return slices.Contains(localAddresses, address)
			}),
			LocalOnly: key.index == urDnsSdLocalOnlyIndex,
			Expires:   now.Add(self.settings.ReportTtl),
		})
	}
	slices.SortFunc(out, func(a *sidecar.BridgeDiscoveryGathered, b *sidecar.BridgeDiscoveryGathered) int {
		return strings.Compare(a.Service+"\x00"+a.Name+"\x00"+a.HostName, b.Service+"\x00"+b.Name+"\x00"+b.HostName)
	})
	self.changed = false
	return out
}
