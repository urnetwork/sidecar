// §17.7.1's advertising proxy on ur tun's own link, as Linux runs it (discovery_proxy_linux.go; owner decision 778),
// apart from Linux so it runs and is tested on every platform: an mDNS responder for the instances the viewer keeps,
// answering the queries the host's own mDNS stack sends on ur tun's link over IPv4 and IPv6 alike, to 224.0.0.251 and
// ff02::fb (RFC 6762 §3; Apple's stack and many Linux hosts ask over both), systemd-resolved once ur tun sets the
// link's MulticastDNS, or Avahi from 0.9, which uses any multicast interface. The tun hands it the mDNS packets that
// reach the tun from the host's own address, and it answers into the tun alone, from <block>.0.53, or over IPv6 from
// that address's twin in the translator's /96 (the ipv6 row), with RFC 6762 §10's TTLs, so nothing it sends reaches a
// LAN interface.
//
//	records   per instance under its registration's name (sidecar.BridgeDiscoveryRegistrations): PTR from its type and
//	          from each subtype, and PTR from _services._dns-sd._udp.local. to its type, PointerTtl; SRV to its target
//	          and its TXT, unchanged, HostTtl and PointerTtl with cache-flush; and per target its A, and its AAAA at
//	          the translated address while ur tun's translator runs, HostTtl with cache-flush (the same records
//	          macOS's registrations make), the same records over either family
//	answer    a query from the host's own address on port 5353 gets each record that answers a question, those its
//	          known-answer list holds with half their TTL or more left out (RFC 6762 §7.1), SRV, TXT and the target's
//	          addresses as additionals (RFC 6763 §12), multicast to its own family's group, 224.0.0.251:5353 or
//	          [ff02::fb]:5353; a type a name the proxy owns does not hold, an AAAA while the translator is off among
//	          them, is denied by an NSEC (§6.1); a query from another port is a legacy one, answered to it alone with its
//	          id and questions and TTLs of at most LegacyTtl (§6.7)
//	ipv6      answered from <block>.0.53's address in the translator's /96 (ur tun's ResolverIpv6Address), which the
//	          host routes into the tun as it routes <block>.0.53, never from the host's own address: a host's mDNS
//	          stack takes a packet from an address of its own for its own echo and drops it, as systemd-resolved does,
//	          and Linux's IPv4 stack refuses one as a martian, which is why IPv4's answers come from <block>.0.53 too;
//	          while the translator is off the proxy holds no IPv6 address, and an IPv6 query goes unanswered while its
//	          IPv4 twin is answered
//	announce  a record that appears is announced twice, AnnounceInterval apart (RFC 6762 §8.3); one that goes or changes
//	          is withdrawn by a goodbye, its TTL 0 (§10.1), at once, and a closing proxy says goodbye to all; each on
//	          both families where the proxy holds an address of each, since the host's stack caches each apart
//	off       where Avahi's reflector is on, which would repeat what it sends onto the LAN, the proxy sends nothing at all
//	          on either family, and ur bridge devices says why (reflectorOn, Linux's check)
//
// The tun's read loop hands a packet over without waiting: the queue takes it or drops it, counted (CODESTYLE's
// receive callbacks). Names, TXT and addresses reach no log (I-13).

package main

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar"
)

// What an advertising proxy that answers on ur tun's link reaches of the tun (urTun's).
type urDiscoveryProxyLink interface {
	// Hands each mDNS packet the tun reads from the host's own address to receive, a whole IPv4 or IPv6 packet the
	// caller owns again once receive returns; nil hands none. receive must not block.
	SetMdnsReceiver(receive func(packet []byte))
	// Writes one IPv4 or IPv6 packet into the tun.
	WritePacket(packet []byte)
	// The block's resolver, <block>.0.53, which the proxy answers IPv4 from; invalid before a block.
	ResolverAddress() netip.Addr
	// The resolver's address in the translator's /96, which the proxy answers IPv6 from (the file's ipv6 row); invalid
	// while the translator is off or before a block.
	ResolverIpv6Address() netip.Addr
	// Turns the host's mDNS on the link on or off: systemd-resolved's MulticastDNS for the link on Linux.
	SetLinkMulticastDns(on bool) error
}

// The responder's tunables.
type urMdnsProxySettings struct {
	// How long after its first announcement a record is announced again: 1 s (RFC 6762 §8.3). Positive.
	AnnounceInterval time.Duration
	// RFC 6762 §10's TTLs: 4,500 s for PTR and TXT, 120 s for SRV and the address records, which name a host; and the
	// most a legacy unicast answer carries, 10 s (§6.7). Positive.
	PointerTtl time.Duration
	HostTtl    time.Duration
	LegacyTtl  time.Duration
	// The packets the queue holds for the responder's goroutine: 64, the rest dropped and counted. Positive.
	QueueCount int
	// The largest message the responder writes over IPv4, 1,252 B, and over IPv6, 1,232 B: the tun's 1,280 B MTU less
	// each family's IP header and UDP's, so no answer fragments; a larger answer is split over several messages.
	// Positive.
	MessageByteCount     int
	Ipv6MessageByteCount int
	// How often Avahi's reflector setting is read again: 1 min. Positive.
	ReflectorInterval time.Duration
}

// The values above.
func defaultUrMdnsProxySettings() *urMdnsProxySettings {
	return &urMdnsProxySettings{
		AnnounceInterval:     1 * time.Second,
		PointerTtl:           4500 * time.Second,
		HostTtl:              120 * time.Second,
		LegacyTtl:            10 * time.Second,
		QueueCount:           64,
		MessageByteCount:     1252,
		Ipv6MessageByteCount: 1232,
		ReflectorInterval:    1 * time.Minute,
	}
}

// mDNS's groups and port (RFC 6762 §3), 224.0.0.251 and ff02::fb, and the names DNS-SD fixes: identifiers.
var (
	urMdnsProxyGroup     = urMdnsGroup.Addr()
	urMdnsProxyIpv6Group = netip.AddrFrom16([16]byte{0: 0xFF, 1: 0x02, 15: 0xFB})
	urMdnsLocalName      = urMdnsNameParse("local")
	urMdnsServicesName   = urMdnsNameParse("_services._dns-sd._udp.local")
	urMdnsSubtypeLabel   = "_sub"
	urMdnsProxyPort      = urMdnsGroup.Port()
	urMdnsProxyUdpProto  = byte(17)
)

// IPv4's, IPv6's and UDP's numbers the responder reads and writes (RFC 791, RFC 8200, RFC 768): the headers' fixed
// sizes, and the TTL and hop limit every mDNS packet carries, by which a receiver knows it came from its own link
// (RFC 6762 §11), a value the protocol fixes and no bound.
const (
	urMdnsProxyHopLimit            = 255
	urMdnsProxyIpv4HeaderByteCount = 20
	urMdnsProxyIpv6HeaderByteCount = 40
	urMdnsProxyUdpHeaderByteCount  = 8
)

// One record the responder answers with, and the records it brings as additionals.
type urMdnsProxyRecord struct {
	record urMdnsRecord
	// the names whose SRV, TXT and address records an answer of it adds (RFC 6763 §12)
	additionalNames []urMdnsName
}

// The records the registrations make (the file's records row), each once.
func urMdnsProxyRecordsOf(registrations []*sidecar.BridgeDiscoveryRegistration, translated func(address netip.Addr) netip.Addr,
	settings *urMdnsProxySettings) []*urMdnsProxyRecord {
	pointerTtl := uint32(settings.PointerTtl / time.Second)
	hostTtl := uint32(settings.HostTtl / time.Second)
	records := []*urMdnsProxyRecord{}
	held := map[string]bool{}
	add := func(record urMdnsRecord, additionalNames ...urMdnsName) {
		if _, ok := record.wire(); !ok {
			return
		}
		key := urMdnsProxyRecordKey(&record)
		if held[key] {
			return
		}
		held[key] = true
		records = append(records, &urMdnsProxyRecord{record: record, additionalNames: additionalNames})
	}
	targets := map[string]bool{}
	for _, registration := range registrations {
		instance := registration.Instance
		if instance == nil || !instance.Address.Is4() {
			continue
		}
		host, ok := urDiscoveryProxyTarget(registration.Target)
		if !ok {
			continue
		}
		target := urMdnsNameParse(host)
		serviceName := urMdnsNameParse(instance.Service).append(urMdnsLocalName...)
		instanceName := urMdnsNameOf(registration.Name).append(serviceName...)
		add(urMdnsRecord{name: urMdnsServicesName, rrtype: urMdnsTypePtr, ttl: pointerTtl, target: serviceName})
		add(urMdnsRecord{name: serviceName, rrtype: urMdnsTypePtr, ttl: pointerTtl, target: instanceName}, instanceName, target)
		for _, subtype := range instance.Subtypes {
			subtypeName := urMdnsNameOf(subtype, urMdnsSubtypeLabel).append(serviceName...)
			add(urMdnsRecord{name: subtypeName, rrtype: urMdnsTypePtr, ttl: pointerTtl, target: instanceName}, instanceName, target)
		}
		add(urMdnsRecord{name: instanceName, rrtype: urMdnsTypeSrv, cacheFlush: true, ttl: hostTtl, target: target, port: instance.Port}, target)
		add(urMdnsRecord{name: instanceName, rrtype: urMdnsTypeTxt, cacheFlush: true, ttl: pointerTtl, txt: instance.Txt})
		if targets[target.key()] {
			continue
		}
		targets[target.key()] = true
		add(urMdnsRecord{name: target, rrtype: urMdnsTypeA, cacheFlush: true, ttl: hostTtl, address: instance.Address})
		if translated != nil {
			if ipv6 := translated(instance.Address); ipv6.Is6() {
				add(urMdnsRecord{name: target, rrtype: urMdnsTypeAaaa, cacheFlush: true, ttl: hostTtl, address: ipv6})
			}
		}
	}
	return records
}

// A record's identity for announcements and goodbyes: its name, type and rdata.
func urMdnsProxyRecordKey(record *urMdnsRecord) string {
	rdata, _ := record.rdata()
	var rrtype [2]byte
	binary.BigEndian.PutUint16(rrtype[:], record.rrtype)
	return record.name.key() + "\x00" + string(rrtype[:]) + "\x00" + string(rdata)
}

// The responder. See the file's comment.
type urMdnsDiscoveryProxy struct {
	ctx      context.Context
	cancel   context.CancelFunc
	link     urDiscoveryProxyLink
	settings *urMdnsProxySettings
	log      sidecar.Logger
	// whether Avahi's reflector is on, with where it is set; nil reads never
	reflectorOn func() (bool, string)
	// closed once run has returned
	done chan struct{}
	// the packets the tun hands over
	queue chan []byte
	// wakes run for a new set; buffered one
	wake         chan struct{}
	droppedCount atomic.Uint64

	stateLock sync.Mutex
	want      []*urMdnsProxyRecord
	status    urDiscoveryProxyStatus

	// run's own: the records answered with, by key, and those owing their second announcement
	records   map[string]*urMdnsProxyRecord
	announced []string
	reflector string
	// called after each change run applies, with the status it published; nil for none. A test's barrier.
	onApply func(status urDiscoveryProxyStatus)
}

// The responder on link, running until ctx ends or Close; reflectorOn, nil for never, says where Avahi's reflector
// is on, and onApply, nil outside a test, hears each change applied.
func newUrMdnsDiscoveryProxy(ctx context.Context, log sidecar.Logger, link urDiscoveryProxyLink, settings *urMdnsProxySettings,
	reflectorOn func() (bool, string), onApply func(status urDiscoveryProxyStatus)) *urMdnsDiscoveryProxy {
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &urMdnsDiscoveryProxy{
		ctx:         cancelCtx,
		cancel:      cancel,
		link:        link,
		settings:    settings,
		log:         log,
		reflectorOn: reflectorOn,
		done:        make(chan struct{}),
		queue:       make(chan []byte, max(1, settings.QueueCount)),
		wake:        make(chan struct{}, 1),
		records:     map[string]*urMdnsProxyRecord{},
		onApply:     onApply,
	}
	link.SetMdnsReceiver(self.receive)
	go self.run()
	return self
}

// The tun's hand-off: a copy queued for run, or dropped and counted where the queue is full.
func (self *urMdnsDiscoveryProxy) receive(packet []byte) {
	select {
	case self.queue <- slices.Clone(packet):
	default:
		self.droppedCount.Add(1)
	}
}

// urDiscoveryProxy: takes the registrations' records and wakes run.
func (self *urMdnsDiscoveryProxy) Set(registrations []*sidecar.BridgeDiscoveryRegistration, translated func(address netip.Addr) netip.Addr) {
	records := urMdnsProxyRecordsOf(registrations, translated, self.settings)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.want = records
	}()
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// urDiscoveryProxy: as run last left it.
func (self *urMdnsDiscoveryProxy) Status() urDiscoveryProxyStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.status
}

// urDiscoveryProxy: says goodbye to every record, stops answering and turns the link's mDNS back off.
func (self *urMdnsDiscoveryProxy) Close() {
	self.cancel()
	<-self.done
}

// Answers, announces and withdraws until the proxy closes.
func (self *urMdnsDiscoveryProxy) run() {
	defer close(self.done)
	defer self.link.SetMdnsReceiver(nil)
	reflectorTicker := time.NewTicker(self.settings.ReflectorInterval)
	defer reflectorTicker.Stop()
	var announceTimer <-chan time.Time
	linkOn := false
	setLink := func(on bool) {
		if linkOn == on {
			return
		}
		if err := self.link.SetLinkMulticastDns(on); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[discovery]the link's mDNS did not turn %v: %v", on, err)
		}
		linkOn = on
	}
	defer func() {
		if self.reflector == "" {
			self.goodbye(self.allKeys())
		}
		setLink(false)
	}()
	self.checkReflector()
	self.apply()
	setLink(self.reflector == "")
	for {
		if 0 < len(self.announced) && announceTimer == nil {
			announceTimer = time.After(self.settings.AnnounceInterval)
		}
		select {
		case <-self.ctx.Done():
			return
		case packet := <-self.queue:
			if self.reflector == "" {
				self.answer(packet)
			}
		case <-self.wake:
			self.apply()
		case <-announceTimer:
			announceTimer = nil
			if self.reflector == "" {
				self.announce(self.announced)
			}
			self.announced = nil
		case <-reflectorTicker.C:
			was := self.reflector
			self.checkReflector()
			if was != self.reflector {
				if self.reflector == "" {
					// the reflector went off: nothing held was announced while it was on
					all := self.allKeys()
					self.announce(all)
					self.announced = append(self.announced, all...)
				}
				self.apply()
				setLink(self.reflector == "")
			}
		}
	}
}

// Reads Avahi's reflector setting into reflector: where it is on, else empty.
func (self *urMdnsDiscoveryProxy) checkReflector() {
	self.reflector = ""
	if self.reflectorOn != nil {
		if on, where := self.reflectorOn(); on {
			self.reflector = where
		}
	}
}

// The keys of every record held.
func (self *urMdnsDiscoveryProxy) allKeys() []string {
	keys := []string{}
	for key := range self.records {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// Brings the records answered with to the set handed over: a goodbye for each that went, an announcement for each that
// came, then publishes what it holds.
func (self *urMdnsDiscoveryProxy) apply() {
	want := func() []*urMdnsProxyRecord {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.want
	}()
	wanted := map[string]*urMdnsProxyRecord{}
	for _, record := range want {
		wanted[urMdnsProxyRecordKey(&record.record)] = record
	}
	gone := []string{}
	for key := range self.records {
		if wanted[key] == nil {
			gone = append(gone, key)
		}
	}
	slices.Sort(gone)
	if self.reflector == "" {
		self.goodbye(gone)
	}
	for _, key := range gone {
		delete(self.records, key)
	}
	came := []string{}
	for key, record := range wanted {
		if self.records[key] == nil {
			self.records[key] = record
			came = append(came, key)
		}
	}
	slices.Sort(came)
	if self.reflector == "" {
		self.announce(came)
	}
	self.announced = append(self.announced, came...)
	instanceCount := 0
	for _, record := range self.records {
		if record.record.rrtype == urMdnsTypeSrv {
			instanceCount += 1
		}
	}
	status := urDiscoveryProxyStatus{RegisteredCount: instanceCount}
	if self.reflector != "" {
		status = urDiscoveryProxyStatus{Note: "Avahi's reflector is on (" + self.reflector + "), which would repeat the proxy's answers onto the LAN, so the proxy stays off"}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.status = status
	}()
	if self.onApply != nil {
		self.onApply(status)
	}
}

// Sends the records of keys still held as an unsolicited response (RFC 6762 §8.3).
func (self *urMdnsDiscoveryProxy) announce(keys []string) {
	answers := []urMdnsRecord{}
	for _, key := range keys {
		if record := self.records[key]; record != nil {
			answers = append(answers, record.record)
		}
	}
	self.multicast(answers)
}

// Sends a goodbye, TTL 0, for each record of keys (RFC 6762 §10.1).
func (self *urMdnsDiscoveryProxy) goodbye(keys []string) {
	answers := []urMdnsRecord{}
	for _, key := range keys {
		if record := self.records[key]; record != nil {
			goodbye := record.record
			goodbye.ttl = 0
			answers = append(answers, goodbye)
		}
	}
	self.multicast(answers)
}

// Sends answers unsolicited to IPv4's group, then to IPv6's, each where the link holds the proxy an address of its
// family (send), so neither family's caches miss an announcement or keep a record past its goodbye.
func (self *urMdnsDiscoveryProxy) multicast(answers []urMdnsRecord) {
	for _, group := range []netip.Addr{urMdnsProxyGroup, urMdnsProxyIpv6Group} {
		self.send(answers, nil, nil, netip.AddrPortFrom(group, urMdnsProxyPort), 0)
	}
}

// Answers one query the tun handed over (the file's answer row), on the family it came over.
func (self *urMdnsDiscoveryProxy) answer(packet []byte) {
	source, payload, ok := urMdnsProxyUdpPayload(packet)
	if !ok || source.Addr().Is4In6() {
		return
	}
	group := urMdnsProxyGroup
	if source.Addr().Is6() {
		group = urMdnsProxyIpv6Group
	}
	// a family the link holds the proxy no address of goes unanswered: IPv6 while the translator is off
	if from, _ := self.sourceFor(group); !from.IsValid() {
		return
	}
	query, err := parseUrMdnsMessage(payload)
	if err != nil || query.response || len(query.questions) == 0 {
		return
	}
	legacy := source.Port() != urMdnsProxyPort
	answers := []urMdnsRecord{}
	answered := map[string]bool{}
	negated := map[string]bool{}
	additionalNames := []urMdnsName{}
	for _, question := range query.questions {
		// whether the name holds a record of the type asked, and whether it is a name this responder owns, one of its
		// unique records', and the types it holds
		matched, owned := false, false
		types := []uint16{}
		for key, held := range self.records {
			record := &held.record
			if !record.name.equal(question.name) {
				continue
			}
			owned = owned || record.cacheFlush
			types = append(types, record.rrtype)
			if question.qtype != urMdnsTypeAny && question.qtype != record.rrtype {
				continue
			}
			matched = true
			// what the asker already holds with half its TTL or more left (RFC 6762 §7.1)
			if knownRecord, isKnown := urMdnsProxyKnown(query.answers, record); answered[key] || isKnown && record.ttl/2 <= knownRecord.ttl {
				continue
			}
			answered[key] = true
			answers = append(answers, *record)
			additionalNames = append(additionalNames, held.additionalNames...)
		}
		// a name this responder owns, asked for a type it holds none of, an AAAA while the translator is off among
		// them: an NSEC says so, so the asker need not wait (RFC 6762 §6.1)
		if owned && !matched && question.qtype != urMdnsTypeAny && !negated[question.name.key()] {
			negated[question.name.key()] = true
			answers = append(answers, urMdnsProxyNsec(question.name, types, uint32(self.settings.HostTtl/time.Second)))
		}
	}
	if len(answers) == 0 {
		return
	}
	additionals := []urMdnsRecord{}
	for _, name := range additionalNames {
		for key, held := range self.records {
			record := &held.record
			if answered[key] || !record.name.equal(name) || record.rrtype == urMdnsTypePtr {
				continue
			}
			answered[key] = true
			additionals = append(additionals, *record)
		}
	}
	slices.SortFunc(answers, urMdnsProxyRecordOrder)
	slices.SortFunc(additionals, urMdnsProxyRecordOrder)
	if legacy {
		// a legacy query is answered to its asker alone, with its id and questions, its TTLs capped (§6.7)
		legacyTtl := uint32(self.settings.LegacyTtl / time.Second)
		for _, list := range [][]urMdnsRecord{answers, additionals} {
			for i := range list {
				list[i].ttl = min(list[i].ttl, legacyTtl)
				list[i].cacheFlush = false
			}
		}
		self.send(answers, additionals, query.questions, source, query.id)
		return
	}
	self.send(answers, additionals, nil, netip.AddrPortFrom(group, urMdnsProxyPort), 0)
}

// An NSEC record of name asserting that it holds types and no other (RFC 6762 §6.1): its next domain name its own,
// its bitmap window 0's alone, which holds every type the proxy writes.
func urMdnsProxyNsec(name urMdnsName, types []uint16, ttl uint32) urMdnsRecord {
	next, _ := name.wire()
	bitmap := []byte{}
	for _, rrtype := range types {
		if 0xFF < rrtype {
			continue
		}
		at := int(rrtype / 8)
		for len(bitmap) <= at {
			bitmap = append(bitmap, 0)
		}
		bitmap[at] |= 0x80 >> (rrtype % 8)
	}
	data := append(next, 0, byte(len(bitmap)))
	return urMdnsRecord{name: name, rrtype: urMdnsTypeNsec, cacheFlush: true, ttl: ttl, data: append(data, bitmap...)}
}

// The known answer the asker holds of record, by name, type and rdata.
func urMdnsProxyKnown(knownAnswers []urMdnsRecord, record *urMdnsRecord) (*urMdnsRecord, bool) {
	key := urMdnsProxyRecordKey(record)
	for i := range knownAnswers {
		if urMdnsProxyRecordKey(&knownAnswers[i]) == key {
			return &knownAnswers[i], true
		}
	}
	return nil, false
}

// A stable order for what one answer carries: by name, then type.
func urMdnsProxyRecordOrder(a urMdnsRecord, b urMdnsRecord) int {
	if order := strings.Compare(a.name.key(), b.name.key()); order != 0 {
		return order
	}
	return int(a.rrtype) - int(b.rrtype)
}

// Writes a response of answers and additionals, with questions and id for a legacy asker, to destination from the
// proxy's address in its family on port 5353, split over as many messages as that family's bound needs. Sends nothing
// where the link holds the proxy no address of that family: before a block, and over IPv6 while the translator is off.
func (self *urMdnsDiscoveryProxy) send(answers []urMdnsRecord, additionals []urMdnsRecord, questions []urMdnsQuestion,
	destination netip.AddrPort, id uint16) {
	if len(answers) == 0 {
		return
	}
	source, byteCount := self.sourceFor(destination.Addr())
	if !source.IsValid() {
		return
	}
	message := &urMdnsMessage{id: id, response: true, authoritative: true, questions: questions, answers: answers, additionals: additionals}
	for _, payload := range message.pack(byteCount) {
		self.link.WritePacket(urMdnsProxyUdpPacket(netip.AddrPortFrom(source, urMdnsProxyPort), destination, payload))
	}
}

// The address the proxy sends to destination from, <block>.0.53 for IPv4 and its address in the translator's /96 for
// IPv6 (the file's ipv6 row), and the largest message it writes there; invalid where the link holds none of
// destination's family.
func (self *urMdnsDiscoveryProxy) sourceFor(destination netip.Addr) (netip.Addr, int) {
	switch {
	case destination.Is4():
		if source := self.link.ResolverAddress(); source.Is4() {
			return source, self.settings.MessageByteCount
		}
	case destination.Is6() && !destination.Is4In6():
		if source := self.link.ResolverIpv6Address(); source.Is6() && !source.Is4In6() {
			return source, self.settings.Ipv6MessageByteCount
		}
	}
	return netip.Addr{}, 0
}

// A UDP packet from source to destination carrying payload, IPv4 where both are IPv4 addresses and IPv6 where both are
// IPv6 ones, its TTL or hop limit 255 as mDNS asks (RFC 6762 §11), with its checksums; nil for two families.
func urMdnsProxyUdpPacket(source netip.AddrPort, destination netip.AddrPort, payload []byte) []byte {
	udpByteCount := urMdnsProxyUdpHeaderByteCount + len(payload)
	var packet []byte
	var pseudoSum uint32
	switch {
	case source.Addr().Is4() && destination.Addr().Is4():
		packet = make([]byte, urMdnsProxyIpv4HeaderByteCount+udpByteCount)
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[8] = urMdnsProxyHopLimit
		packet[9] = urMdnsProxyUdpProto
		sourceOctets, destinationOctets := source.Addr().As4(), destination.Addr().As4()
		copy(packet[12:16], sourceOctets[:])
		copy(packet[16:20], destinationOctets[:])
		binary.BigEndian.PutUint16(packet[10:12], urMdnsProxyChecksum(0, packet[:urMdnsProxyIpv4HeaderByteCount]))
		// IPv4's pseudo-header (RFC 768): the addresses, a zero octet, the protocol and UDP's length
		var pseudo [12]byte
		copy(pseudo[0:4], sourceOctets[:])
		copy(pseudo[4:8], destinationOctets[:])
		pseudo[9] = urMdnsProxyUdpProto
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpByteCount))
		pseudoSum = urMdnsProxySum(0, pseudo[:])
	case source.Addr().Is6() && destination.Addr().Is6():
		packet = make([]byte, urMdnsProxyIpv6HeaderByteCount+udpByteCount)
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(udpByteCount))
		packet[6] = urMdnsProxyUdpProto
		packet[7] = urMdnsProxyHopLimit
		sourceOctets, destinationOctets := source.Addr().As16(), destination.Addr().As16()
		copy(packet[8:24], sourceOctets[:])
		copy(packet[24:40], destinationOctets[:])
		// IPv6's pseudo-header (RFC 8200 §8.1): the addresses, UDP's length in 32 bits, three zero octets and the next
		// header
		var pseudo [40]byte
		copy(pseudo[0:16], sourceOctets[:])
		copy(pseudo[16:32], destinationOctets[:])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(udpByteCount))
		pseudo[39] = urMdnsProxyUdpProto
		pseudoSum = urMdnsProxySum(0, pseudo[:])
	default:
		return nil
	}
	udp := packet[len(packet)-udpByteCount:]
	binary.BigEndian.PutUint16(udp[0:2], source.Port())
	binary.BigEndian.PutUint16(udp[2:4], destination.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpByteCount))
	copy(udp[urMdnsProxyUdpHeaderByteCount:], payload)
	// a sum of zero goes as all ones, since zero says none was taken, which IPv6 forbids (RFC 768, RFC 8200 §8.1)
	checksum := urMdnsProxyChecksum(pseudoSum, udp)
	if checksum == 0 {
		checksum = 0xFFFF
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return packet
}

// The one's-complement sum of data added to sum, unfolded.
func urMdnsProxySum(sum uint32, data []byte) uint32 {
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

// The Internet checksum of data over sum.
func urMdnsProxyChecksum(sum uint32, data []byte) uint16 {
	sum = urMdnsProxySum(sum, data)
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}

// The source and payload of a UDP packet to mDNS's group and port, IPv4's 224.0.0.251 or IPv6's ff02::fb, false for
// anything else: a fragment, an IPv6 packet whose UDP follows an extension header, or lengths that do not hold.
func urMdnsProxyUdpPayload(packet []byte) (netip.AddrPort, []byte, bool) {
	if len(packet) == 0 {
		return netip.AddrPort{}, nil, false
	}
	var source netip.Addr
	var udp []byte
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < urMdnsProxyIpv4HeaderByteCount+urMdnsProxyUdpHeaderByteCount || packet[9] != urMdnsProxyUdpProto {
			return netip.AddrPort{}, nil, false
		}
		headerByteCount := int(packet[0]&0x0F) * 4
		totalByteCount := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerByteCount < urMdnsProxyIpv4HeaderByteCount || totalByteCount < headerByteCount+urMdnsProxyUdpHeaderByteCount ||
			len(packet) < totalByteCount || binary.BigEndian.Uint16(packet[6:8])&0x3FFF != 0 {
			return netip.AddrPort{}, nil, false
		}
		if netip.AddrFrom4([4]byte(packet[16:20])) != urMdnsProxyGroup {
			return netip.AddrPort{}, nil, false
		}
		source, udp = netip.AddrFrom4([4]byte(packet[12:16])), packet[headerByteCount:totalByteCount]
	case 6:
		// UDP straight after the fixed header: a host's stack puts no extension header on an mDNS query, and a fragment
		// header says the rest is elsewhere
		if len(packet) < urMdnsProxyIpv6HeaderByteCount+urMdnsProxyUdpHeaderByteCount || packet[6] != urMdnsProxyUdpProto {
			return netip.AddrPort{}, nil, false
		}
		totalByteCount := urMdnsProxyIpv6HeaderByteCount + int(binary.BigEndian.Uint16(packet[4:6]))
		if totalByteCount < urMdnsProxyIpv6HeaderByteCount+urMdnsProxyUdpHeaderByteCount || len(packet) < totalByteCount {
			return netip.AddrPort{}, nil, false
		}
		if netip.AddrFrom16([16]byte(packet[24:40])) != urMdnsProxyIpv6Group {
			return netip.AddrPort{}, nil, false
		}
		source, udp = netip.AddrFrom16([16]byte(packet[8:24])), packet[urMdnsProxyIpv6HeaderByteCount:totalByteCount]
	default:
		return netip.AddrPort{}, nil, false
	}
	if binary.BigEndian.Uint16(udp[2:4]) != urMdnsProxyPort || int(binary.BigEndian.Uint16(udp[4:6])) != len(udp) {
		return netip.AddrPort{}, nil, false
	}
	return netip.AddrPortFrom(source, binary.BigEndian.Uint16(udp[0:2])), udp[urMdnsProxyUdpHeaderByteCount:], true
}

// Whether packet is a UDP packet to mDNS's group and port from one of addresses, or over IPv6 from a link-local
// address: what the tun hands the proxy. The tun names its IPv4 addresses and its own IPv6 one, the translator's; a
// link-local source is the host's own too, whichever its kernel drew for the tun, since no router forwards a packet
// from one (RFC 4291 §2.5.6), and a legacy answer to one stays on the host or comes back into the tun, so it never
// reaches a LAN.
func urMdnsProxyQueryFrom(packet []byte, addresses []netip.Addr) bool {
	source, _, ok := urMdnsProxyUdpPayload(packet)
	if !ok {
		return false
	}
	address := source.Addr()
	return slices.Contains(addresses, address) || address.Is6() && !address.Is4In6() && address.IsLinkLocalUnicast()
}

// A registration's target as a full name in local., "<label>.<client-name>.local.": false where it is not a host name
// of LDH labels within DNS's lengths. Both platforms' proxies hold their targets to it.
func urDiscoveryProxyTarget(target string) (string, bool) {
	target = strings.TrimSuffix(strings.ToLower(target), ".")
	if target == "" {
		return "", false
	}
	for _, label := range strings.Split(target, ".") {
		if !urDiscoveryProxyHostLabel(label) {
			return "", false
		}
	}
	full := target + ".local."
	// a name's 255 octets less its length and root bytes (RFC 1035 §2.3.4)
	if 253 < len(full)-1 {
		return "", false
	}
	return full, true
}

// Whether label is an LDH label of one to 63 octets with no hyphen at either end.
func urDiscoveryProxyHostLabel(label string) bool {
	if label == "" || urMdnsLabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i += 1 {
		c := label[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Whether the Avahi configuration at path turns its reflector on, `enable-reflector` under `[reflector]` read as Avahi
// reads a yes (a value starting y, t or 1), and path where it does. A file that does not read turns nothing on.
func urAvahiReflectorOn(path string) (bool, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, ""
	}
	return urAvahiReflectorOnIn(string(data)), path
}

// Whether a configuration's text turns Avahi's reflector on.
func urAvahiReflectorOnIn(text string) bool {
	section := ""
	on := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || section != "reflector" || strings.ToLower(strings.TrimSpace(key)) != "enable-reflector" {
			continue
		}
		value = strings.TrimSpace(value)
		on = value != "" && strings.ContainsRune("yYtT1", rune(value[0]))
	}
	return on
}
