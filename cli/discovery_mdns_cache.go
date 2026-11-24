// The mDNS querier's cache (discovery_gather_mdns.go; §17.7.1, owner decision 778), apart from its sockets so it runs
// and is tested on every platform: PTRs by type, each instance's SRV and TXT, and each target's IPv4 addresses, every
// record with its own TTL, a goodbye (TTL 0) withdrawing it at once (RFC 6762 §10.1), at most RecordCount records.

package main

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
)

// The querier's tunables beside BridgeDiscoverySettings' QueryRate.
type urMdnsSettings struct {
	// The first interval between a type's continuous queries, doubling to QueryMaxInterval (RFC 6762 §5.2): 1 s and 60
	// min.
	QueryInterval    time.Duration
	QueryMaxInterval time.Duration
	// The largest datagram read or sent: 9,000 B, RFC 6762 §17's bound on a multicast DNS message.
	MessageByteCount int
	// How long a record of an instance the cache holds may go unrefreshed past its own TTL: none; a TTL is the
	// record's own. The most records the cache keeps: 4,096, the rest dropped.
	RecordCount int
}

// The values above.
func defaultUrMdnsSettings() *urMdnsSettings {
	return &urMdnsSettings{
		QueryInterval:    1 * time.Second,
		QueryMaxInterval: 60 * time.Minute,
		MessageByteCount: 9000,
		RecordCount:      4096,
	}
}

// mDNS's group and port (RFC 6762 §3): protocol identifiers.
var urMdnsGroup = netip.AddrPortFrom(netip.AddrFrom4([4]byte{224, 0, 0, 251}), 5353)

// One instance's records as the cache holds them, each with its end.
type urMdnsInstance struct {
	// the instance's full name, "<name>.<type>.local.", in the case its PTR gave it
	fullName string
	service  string
	subtypes []string
	target   string
	port     uint16
	txt      []byte
	ends     time.Time
}

// What one interface's querier knows: PTRs by type, instances by full name, addresses by target. Safe for concurrent
// use.
type urMdnsCache struct {
	stateLock sync.Mutex
	settings  *urMdnsSettings
	// type to instance full names, each with its end
	pointers map[string]map[string]time.Time
	// instance full name to its SRV and TXT
	instances map[string]*urMdnsInstance
	// target to its IPv4 addresses, each with its end
	addresses map[string]map[netip.Addr]time.Time
	count     int
}

func newUrMdnsCache(settings *urMdnsSettings) *urMdnsCache {
	return &urMdnsCache{
		settings:  settings,
		pointers:  map[string]map[string]time.Time{},
		instances: map[string]*urMdnsInstance{},
		addresses: map[string]map[netip.Addr]time.Time{},
	}
}

// A name as the cache keys it: lowercased in ASCII, with its trailing dot.
func urMdnsKey(name string) string {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return strings.ToLower(name)
}

// Takes one response's records at now, answering whether anything changed. A record of a type no one asked about is
// kept only as part of an instance a PTR named.
func (self *urMdnsCache) take(message []byte, now time.Time) bool {
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil || !header.Response {
		return false
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	changed := false
	// the answers, then past the authority section, the additionals, which RFC 6763 §12 fills with what a browse needs
	sections := []struct {
		header func() (dnsmessage.ResourceHeader, error)
		skip   func() error
	}{
		{header: parser.AnswerHeader, skip: parser.SkipAnswer},
		{header: parser.AdditionalHeader, skip: parser.SkipAdditional},
	}
	for i, section := range sections {
		if i == 1 {
			if err := parser.SkipAllAuthorities(); err != nil {
				return changed
			}
		}
		for {
			recordHeader, err := section.header()
			if err != nil {
				break
			}
			taken, ok := self.takeRecordWithLock(&parser, recordHeader, now)
			if !ok {
				if err := section.skip(); err != nil {
					return changed
				}
				continue
			}
			changed = taken || changed
		}
	}
	return changed
}

// Takes one record the parser stands at: whether it changed the cache, and false for a type it does not read, which
// the caller skips. Called with stateLock held.
func (self *urMdnsCache) takeRecordWithLock(parser *dnsmessage.Parser, recordHeader dnsmessage.ResourceHeader, now time.Time) (bool, bool) {
	ends := now.Add(time.Duration(recordHeader.TTL) * time.Second)
	name := urMdnsKey(recordHeader.Name.String())
	switch recordHeader.Type {
	case dnsmessage.TypePTR:
		body, err := parser.PTRResource()
		if err != nil {
			return false, true
		}
		instanceName := body.PTR.String()
		if recordHeader.TTL != 0 {
			self.instanceWithLock(urMdnsKey(instanceName)).fullName = instanceName
		}
		return self.setPointerWithLock(name, urMdnsKey(instanceName), ends, recordHeader.TTL == 0), true
	case dnsmessage.TypeSRV:
		body, err := parser.SRVResource()
		if err != nil {
			return false, true
		}
		if recordHeader.TTL == 0 {
			delete(self.instances, name)
			return true, true
		}
		instance := self.instanceWithLock(name)
		instance.target, instance.port, instance.ends = urMdnsKey(body.Target.String()), body.Port, ends
		return true, true
	case dnsmessage.TypeTXT:
		body, err := parser.TXTResource()
		if err != nil {
			return false, true
		}
		txt := []byte{}
		for _, text := range body.TXT {
			txt = append(txt, byte(len(text)))
			txt = append(txt, text...)
		}
		self.instanceWithLock(name).txt = txt
		return true, true
	case dnsmessage.TypeA:
		body, err := parser.AResource()
		if err != nil {
			return false, true
		}
		address := netip.AddrFrom4(body.A)
		held := self.addresses[name]
		if held == nil {
			held = map[netip.Addr]time.Time{}
			self.addresses[name] = held
		}
		if recordHeader.TTL == 0 {
			delete(held, address)
		} else if self.count < self.settings.RecordCount {
			held[address] = ends
			self.count += 1
		}
		return true, true
	}
	return false, false
}

// The instance of a full name, made where the cache holds none. Called with stateLock held.
func (self *urMdnsCache) instanceWithLock(fullName string) *urMdnsInstance {
	instance := self.instances[fullName]
	if instance == nil {
		instance = &urMdnsInstance{fullName: fullName}
		// past RecordCount a new instance is written to and kept nowhere
		if self.count < self.settings.RecordCount {
			self.instances[fullName] = instance
			self.count += 1
		}
	}
	return instance
}

// A PTR from a type, or a subtype, to an instance, or its goodbye. Called with stateLock held.
func (self *urMdnsCache) setPointerWithLock(owner string, instance string, ends time.Time, goodbye bool) bool {
	held := self.pointers[owner]
	if held == nil {
		held = map[string]time.Time{}
		self.pointers[owner] = held
	}
	if goodbye {
		delete(held, instance)
		return true
	}
	if self.settings.RecordCount <= self.count {
		return false
	}
	held[instance] = ends
	self.count += 1
	return true
}

// The instances of types whose records all stand at now, each with its target's addresses.
func (self *urMdnsCache) gathered(types []string, now time.Time, localAddresses []netip.Addr) []*sidecar.BridgeDiscoveryGathered {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	out := []*sidecar.BridgeDiscoveryGathered{}
	for _, serviceType := range types {
		owner := urMdnsKey(serviceType + ".local")
		for fullName, pointerEnds := range self.pointers[owner] {
			instance := self.instances[fullName]
			if !pointerEnds.After(now) || instance == nil || instance.target == "" || !instance.ends.After(now) {
				continue
			}
			addresses := []netip.Addr{}
			ends := pointerEnds
			if instance.ends.Before(ends) {
				ends = instance.ends
			}
			for address, addressEnds := range self.addresses[instance.target] {
				if addressEnds.After(now) {
					addresses = append(addresses, address)
					if addressEnds.Before(ends) {
						ends = addressEnds
					}
				}
			}
			if len(addresses) == 0 {
				continue
			}
			slices.SortFunc(addresses, netip.Addr.Compare)
			// the label as its PTR gave it: the full name less the type and local.
			display := instance.fullName
			if !strings.HasSuffix(strings.ToLower(display), "."+owner) {
				display = fullName
			}
			name := display[:len(display)-len(owner)-1]
			out = append(out, &sidecar.BridgeDiscoveryGathered{
				Name:      urMdnsUnescape(name),
				Service:   serviceType,
				Port:      instance.port,
				Txt:       slices.Clone(instance.txt),
				HostName:  instance.target,
				Addresses: addresses,
				Own:       slices.ContainsFunc(addresses, func(address netip.Addr) bool { return slices.Contains(localAddresses, address) }),
				Expires:   ends,
			})
		}
	}
	return out
}

// An instance label in its presentation form, its escapes undone (RFC 1035 §5.1): \. and \\ and \DDD.
func urMdnsUnescape(label string) string {
	if !strings.Contains(label, "\\") {
		return label
	}
	out := []byte{}
	for i := 0; i < len(label); i += 1 {
		if label[i] != '\\' || i+1 == len(label) {
			out = append(out, label[i])
			continue
		}
		if i+3 < len(label) && '0' <= label[i+1] && label[i+1] <= '9' {
			value := int(label[i+1]-'0')*100 + int(label[i+2]-'0')*10 + int(label[i+3]-'0')
			out = append(out, byte(value))
			i += 3
			continue
		}
		out = append(out, label[i+1])
		i += 1
	}
	return string(out)
}
