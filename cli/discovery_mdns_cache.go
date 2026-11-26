// The mDNS querier's cache (discovery_gather_mdns.go; §17.7.1, owner decision 778), apart from its sockets so it runs
// and is tested on every platform: what one link's responses say, read with discovery_mdns_wire.go so a label holding
// a dot stays one label.
//
//	records   PTRs by their owner, a type or a subtype's <sub>._sub.<type>.local., each instance's SRV and TXT, and each
//	          target's IPv4 addresses, every record with its own TTL; a goodbye (TTL 0) withdraws a record at once
//	          (RFC 6762 §10.1), and a record past its TTL leaves at the next read
//	bounds    at most RecordCount records over all of them, a new one past it refused until others leave
//	known     the PTRs a type's next query lists as known answers, those with more than half their TTL left (§7.1)
//	missing   the follow-up questions an instance needs where its responder left records out of a browse's answer:
//	          SRV or TXT for its name, A for its target (RFC 6763 §12 lets a responder omit additionals)
//	report    every instance of a listed type whose PTR, SRV, TXT and target's address all stand, with the subtypes its
//	          subtype PTRs name, expiring with the first of its records
//
// Safe for concurrent use. Names and TXT are the LAN's words, kept as they came and logged nowhere (I-13).

package main

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// The querier's tunables beside BridgeDiscoverySettings' QueryRate.
type urMdnsSettings struct {
	// The first interval between a type's continuous queries, doubling to QueryMaxInterval (RFC 6762 §5.2): 1 s and 60
	// min.
	QueryInterval    time.Duration
	QueryMaxInterval time.Duration
	// The largest datagram read: 9,000 B, RFC 6762 §17's bound on a multicast DNS message.
	MessageByteCount int
	// The largest query sent: 1,472 B, an Ethernet frame's 1,500 less IPv4's and UDP's headers, so no query fragments;
	// known answers past it are left out, which costs a redundant answer at most (RFC 6762 §7.2).
	QueryByteCount int
	// The most records the cache keeps over a link: 4,096, a new one past it refused.
	RecordCount int
}

// The values above.
func defaultUrMdnsSettings() *urMdnsSettings {
	return &urMdnsSettings{
		QueryInterval:    1 * time.Second,
		QueryMaxInterval: 60 * time.Minute,
		MessageByteCount: 9000,
		QueryByteCount:   1472,
		RecordCount:      4096,
	}
}

// One record's end, and the TTL it came with.
type urMdnsHeld struct {
	ends time.Time
	ttl  uint32
}

// What the cache holds of one instance: its full name, its SRV and its TXT.
type urMdnsCachedInstance struct {
	name   urMdnsName
	target urMdnsName
	port   uint16
	srv    *urMdnsHeld
	txt    []byte
	txtSet *urMdnsHeld
}

// A PTR the cache holds: the instance it names, and its end.
type urMdnsCachedPointer struct {
	instance urMdnsName
	held     urMdnsHeld
}

// The PTRs of one owner, a type or a subtype, by instance key, with the owner's name.
type urMdnsCachedOwner struct {
	name     urMdnsName
	pointers map[string]*urMdnsCachedPointer
}

// One link's cache. See the file's comment.
type urMdnsCache struct {
	settings *urMdnsSettings

	stateLock sync.Mutex
	// owner key to its PTRs
	owners map[string]*urMdnsCachedOwner
	// instance key to its SRV and TXT
	instances map[string]*urMdnsCachedInstance
	// target key to its addresses, with the target's name
	addresses   map[string]map[netip.Addr]*urMdnsHeld
	targetNames map[string]urMdnsName
}

func newUrMdnsCache(settings *urMdnsSettings) *urMdnsCache {
	return &urMdnsCache{
		settings:    settings,
		owners:      map[string]*urMdnsCachedOwner{},
		instances:   map[string]*urMdnsCachedInstance{},
		addresses:   map[string]map[netip.Addr]*urMdnsHeld{},
		targetNames: map[string]urMdnsName{},
	}
}

// A type's name in local.: "_ipp._tcp" to _ipp._tcp.local.
func urMdnsTypeName(serviceType string) urMdnsName {
	return urMdnsNameParse(serviceType).append(urMdnsLocalName...)
}

// The records held now, past ends pruned first. Called with stateLock held.
func (self *urMdnsCache) countWithLock(now time.Time) int {
	count := 0
	for ownerKey, owner := range self.owners {
		for key, pointer := range owner.pointers {
			if !pointer.held.ends.After(now) {
				delete(owner.pointers, key)
				continue
			}
			count += 1
		}
		if len(owner.pointers) == 0 {
			delete(self.owners, ownerKey)
		}
	}
	for key, instance := range self.instances {
		if instance.srv != nil && !instance.srv.ends.After(now) {
			instance.srv, instance.target, instance.port = nil, nil, 0
		}
		if instance.txtSet != nil && !instance.txtSet.ends.After(now) {
			instance.txtSet, instance.txt = nil, nil
		}
		if instance.srv == nil && instance.txtSet == nil {
			delete(self.instances, key)
			continue
		}
		if instance.srv != nil {
			count += 1
		}
		if instance.txtSet != nil {
			count += 1
		}
	}
	for target, held := range self.addresses {
		for address, record := range held {
			if !record.ends.After(now) {
				delete(held, address)
				continue
			}
			count += 1
		}
		if len(held) == 0 {
			delete(self.addresses, target)
			delete(self.targetNames, target)
		}
	}
	return count
}

// Takes one response's records at now, answering whether anything changed. A malformed message changes nothing.
func (self *urMdnsCache) take(message []byte, now time.Time) bool {
	parsed, err := parseUrMdnsMessage(message)
	if err != nil || !parsed.response {
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := self.countWithLock(now)
	changed := false
	for _, section := range [][]urMdnsRecord{parsed.answers, parsed.additionals} {
		for i := range section {
			taken, added := self.takeRecordWithLock(&section[i], now, count < self.settings.RecordCount)
			changed = changed || taken
			if added {
				count += 1
			}
		}
	}
	return changed
}

// Takes one record: whether it changed the cache, and whether it added a record the count did not hold. A new record
// is kept only where room is.
func (self *urMdnsCache) takeRecordWithLock(record *urMdnsRecord, now time.Time, room bool) (bool, bool) {
	held := &urMdnsHeld{ends: now.Add(time.Duration(record.ttl) * time.Second), ttl: record.ttl}
	goodbye := record.ttl == 0
	name := record.name.key()
	switch record.rrtype {
	case urMdnsTypePtr:
		owner := self.owners[name]
		key := record.target.key()
		if goodbye {
			if owner != nil && owner.pointers[key] != nil {
				delete(owner.pointers, key)
				return true, false
			}
			return false, false
		}
		if owner != nil && owner.pointers[key] != nil {
			owner.pointers[key].held = *held
			return false, false
		}
		if !room {
			return false, false
		}
		if owner == nil {
			owner = &urMdnsCachedOwner{name: record.name, pointers: map[string]*urMdnsCachedPointer{}}
			self.owners[name] = owner
		}
		owner.pointers[key] = &urMdnsCachedPointer{instance: record.target, held: *held}
		return true, true
	case urMdnsTypeSrv:
		instance := self.instances[name]
		if goodbye {
			if instance != nil && instance.srv != nil {
				instance.srv, instance.target, instance.port = nil, nil, 0
				return true, false
			}
			return false, false
		}
		added := instance == nil || instance.srv == nil
		if added && !room {
			return false, false
		}
		if instance == nil {
			instance = &urMdnsCachedInstance{name: record.name}
			self.instances[name] = instance
		}
		changed := added || !instance.target.equal(record.target) || instance.port != record.port
		instance.srv, instance.target, instance.port = held, record.target, record.port
		return changed, added
	case urMdnsTypeTxt:
		instance := self.instances[name]
		if goodbye {
			if instance != nil && instance.txtSet != nil {
				instance.txtSet, instance.txt = nil, nil
				return true, false
			}
			return false, false
		}
		added := instance == nil || instance.txtSet == nil
		if added && !room {
			return false, false
		}
		if instance == nil {
			instance = &urMdnsCachedInstance{name: record.name}
			self.instances[name] = instance
		}
		changed := added || string(instance.txt) != string(record.txt)
		instance.txtSet, instance.txt = held, slices.Clone(record.txt)
		return changed, added
	case urMdnsTypeA:
		addresses := self.addresses[name]
		if goodbye {
			if addresses != nil && addresses[record.address] != nil {
				delete(addresses, record.address)
				return true, false
			}
			return false, false
		}
		if addresses != nil && addresses[record.address] != nil {
			addresses[record.address] = held
			return false, false
		}
		if !room {
			return false, false
		}
		if addresses == nil {
			addresses = map[netip.Addr]*urMdnsHeld{}
			self.addresses[name] = addresses
			self.targetNames[name] = record.name
		}
		addresses[record.address] = held
		return true, true
	}
	return false, false
}

// The PTRs a type's next query lists as known answers: those of its name with more than half their TTL left at now
// (RFC 6762 §7.1).
func (self *urMdnsCache) knownAnswers(serviceType string, now time.Time) []urMdnsRecord {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	typeName := urMdnsTypeName(serviceType)
	known := []urMdnsRecord{}
	owner := self.owners[typeName.key()]
	if owner == nil {
		return known
	}
	for _, pointer := range owner.pointers {
		remaining := pointer.held.ends.Sub(now)
		if time.Duration(pointer.held.ttl)*time.Second < 2*remaining {
			known = append(known, urMdnsRecord{
				name: typeName, rrtype: urMdnsTypePtr, ttl: uint32(remaining / time.Second), target: pointer.instance,
			})
		}
	}
	slices.SortFunc(known, func(a urMdnsRecord, b urMdnsRecord) int { return strings.Compare(a.target.key(), b.target.key()) })
	return known
}

// The follow-up questions the types' instances need at now: SRV and TXT for an instance whose PTR stands without them,
// A for a target an SRV names with no address (RFC 6763 §12 lets a responder leave them out of a browse's answer).
func (self *urMdnsCache) missing(types []string, now time.Time) []urMdnsQuestion {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.countWithLock(now)
	questions := []urMdnsQuestion{}
	asked := map[string]bool{}
	ask := func(name urMdnsName, qtype uint16) {
		key := fmt.Sprintf("%s\x00%d", name.key(), qtype)
		if !asked[key] {
			asked[key] = true
			questions = append(questions, urMdnsQuestion{name: name, qtype: qtype})
		}
	}
	for _, serviceType := range types {
		owner := self.owners[urMdnsTypeName(serviceType).key()]
		if owner == nil {
			continue
		}
		for _, pointer := range owner.pointers {
			instance := self.instances[pointer.instance.key()]
			if instance == nil || instance.srv == nil {
				ask(pointer.instance, urMdnsTypeSrv)
			}
			if instance == nil || instance.txtSet == nil {
				ask(pointer.instance, urMdnsTypeTxt)
			}
			if instance != nil && instance.srv != nil && len(self.addresses[instance.target.key()]) == 0 {
				ask(instance.target, urMdnsTypeA)
			}
		}
	}
	slices.SortFunc(questions, func(a urMdnsQuestion, b urMdnsQuestion) int {
		if order := strings.Compare(a.name.key(), b.name.key()); order != 0 {
			return order
		}
		return int(a.qtype) - int(b.qtype)
	})
	return questions
}

// The instances of types whose records all stand at now, each with its subtypes and its target's addresses, own where
// one of them is localAddresses'.
func (self *urMdnsCache) gathered(types []string, now time.Time, localAddresses []netip.Addr) []*sidecar.BridgeDiscoveryGathered {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.countWithLock(now)
	out := []*sidecar.BridgeDiscoveryGathered{}
	for _, serviceType := range types {
		typeName := urMdnsTypeName(serviceType)
		owner := self.owners[typeName.key()]
		if owner == nil {
			continue
		}
		for instanceKey, pointer := range owner.pointers {
			instance := self.instances[instanceKey]
			// the instance is its type's: its name one label before the type's
			if instance == nil || instance.srv == nil || instance.txtSet == nil || len(pointer.instance) != len(typeName)+1 ||
				!pointer.instance.hasSuffix(typeName) {
				continue
			}
			ends := pointer.held.ends
			for _, record := range []*urMdnsHeld{instance.srv, instance.txtSet} {
				if record.ends.Before(ends) {
					ends = record.ends
				}
			}
			addresses := []netip.Addr{}
			for address, record := range self.addresses[instance.target.key()] {
				addresses = append(addresses, address)
				if record.ends.Before(ends) {
					ends = record.ends
				}
			}
			if len(addresses) == 0 {
				continue
			}
			slices.SortFunc(addresses, netip.Addr.Compare)
			out = append(out, &sidecar.BridgeDiscoveryGathered{
				Name:      pointer.instance[0],
				Service:   serviceType,
				Subtypes:  self.subtypesWithLock(typeName, instanceKey),
				Port:      instance.port,
				Txt:       slices.Clone(instance.txt),
				HostName:  strings.ToLower(strings.Join(instance.target, ".")) + ".",
				Addresses: addresses,
				Own:       slices.ContainsFunc(addresses, func(address netip.Addr) bool { return slices.Contains(localAddresses, address) }),
				Expires:   ends,
			})
		}
	}
	slices.SortFunc(out, func(a *sidecar.BridgeDiscoveryGathered, b *sidecar.BridgeDiscoveryGathered) int {
		return strings.Compare(a.Service+"\x00"+a.Name, b.Service+"\x00"+b.Name)
	})
	return out
}

// The subtypes whose PTRs, <sub>._sub.<type>.local., name the instance, as its responder announced them. Called with
// stateLock held.
func (self *urMdnsCache) subtypesWithLock(typeName urMdnsName, instanceKey string) []string {
	subtypeSuffix := urMdnsNameOf(urMdnsSubtypeLabel).append(typeName...)
	subtypes := []string{}
	for _, owner := range self.owners {
		if owner.pointers[instanceKey] != nil && len(owner.name) == len(subtypeSuffix)+1 && owner.name.hasSuffix(subtypeSuffix) {
			subtypes = append(subtypes, owner.name[0])
		}
	}
	slices.Sort(subtypes)
	return subtypes
}

// A type's PTR query in local., with known answers as many as fit byteCount (RFC 6762 §7.1, §7.2): one message.
func urMdnsBrowseQuery(serviceType string, known []urMdnsRecord, byteCount int) [][]byte {
	message := &urMdnsMessage{
		questions: []urMdnsQuestion{{name: urMdnsTypeName(serviceType), qtype: urMdnsTypePtr}},
		answers:   known,
	}
	packed := message.pack(byteCount)
	if len(packed) == 0 {
		return nil
	}
	return packed[:1]
}

// The follow-up questions as queries, as many questions to a message as fit byteCount.
func urMdnsFollowUps(questions []urMdnsQuestion, byteCount int) [][]byte {
	messages := [][]byte{}
	for at := 0; at < len(questions); {
		message := &urMdnsMessage{}
		for at < len(questions) {
			message.questions = append(message.questions, questions[at])
			if len(message.pack(byteCount)) == 0 {
				message.questions = message.questions[:len(message.questions)-1]
				break
			}
			at += 1
		}
		if len(message.questions) == 0 {
			// a question past byteCount alone is left out
			at += 1
			continue
		}
		messages = append(messages, message.pack(byteCount)...)
	}
	return messages
}
