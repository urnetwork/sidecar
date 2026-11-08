// Response-rate limiting (§12.6's rrl block). An edge answers UDP with no proxy in front, so it sees
// resolvers' own addresses, and the edge holds one token bucket for each resolver prefix, a /24 or a
// /56 by default, and response class: answers, denials and errors are counted apart, so a flood of
// random names spends the denial bucket and leaves a resolver's real answers alone. A bucket earns
// responses_per_second, holds at most a second's worth, and owes at most window_s seconds' worth, so a
// prefix that floods stays limited that long after it stops. Past its balance a response is dropped,
// except every slip-th, which goes out empty with TC set so a real resolver retries over TCP, where
// spoofing cannot reach.
//
// Only UDP is limited: TCP's handshake proves the source, and connections_per_source bounds it. The
// table holds no address, only masked prefixes in memory (§2.8 dns-2), never logged or counted by
// value, and drops the least recently used bucket past rrl.buckets, so a spoofed spread of prefixes
// costs bounded memory. Safe for concurrent use.

package dnsservice

import (
	"container/list"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// What RRL does with one response.
type dnsRrlAction int

const (
	dnsRrlSend dnsRrlAction = iota
	// over the balance: send nothing
	dnsRrlDrop
	// over the balance, and the slip-th such: send it empty with TC
	dnsRrlSlip
)

// The metric label of a limited action.
func (self dnsRrlAction) label() string {
	switch self {
	case dnsRrlDrop:
		return "drop"
	case dnsRrlSlip:
		return "slip"
	}
	return "send"
}

// One bucket's key: a masked prefix and a class. Comparable.
type dnsRrlKey struct {
	prefix netip.Prefix
	class  string
}

// One bucket. balance is in responses: at most the rate, at least minus window_s times the rate.
type dnsRrlBucket struct {
	key       dnsRrlKey
	balance   float64
	last      time.Time
	dropCount int
}

type dnsRrl struct {
	ratePerSecond float64
	debtMax       float64
	// how long a bucket idles before it holds nothing a fresh one would not: its window and the second
	// it takes to earn back a full balance
	expiry      time.Duration
	ipv4Bits    int
	ipv6Bits    int
	slip        int
	bucketCount int
	classes     []string

	stateLock sync.Mutex
	buckets   map[dnsRrlKey]*list.Element
	recency   *list.List
}

func newDnsRrl(settings *DnsSettings) *dnsRrl {
	rrl := &settings.Rrl
	rate := float64(rrl.ResponsesPerSecond)
	return &dnsRrl{
		ratePerSecond: rate,
		debtMax:       rate * float64(rrl.WindowSeconds),
		expiry:        dnsSeconds(rrl.WindowSeconds + 1),
		ipv4Bits:      rrl.Ipv4Prefix,
		ipv6Bits:      rrl.Ipv6Prefix,
		slip:          rrl.Slip,
		bucketCount:   rrl.BucketCount,
		classes:       slices.Clone(rrl.Classes),
		buckets:       map[dnsRrlKey]*list.Element{},
		recency:       list.New(),
	}
}

// source's prefix as RRL buckets it: an IPv4 address, mapped or not, masked to ipv4_prefix, an IPv6 one
// to ipv6_prefix.
func (self *dnsRrl) prefix(source netip.Addr) (netip.Prefix, bool) {
	source = source.Unmap()
	bits := self.ipv6Bits
	if source.Is4() {
		bits = self.ipv4Bits
	}
	prefix, err := source.Prefix(bits)
	return prefix, err == nil
}

// What to do with one response of class to source at now. A class rrl.classes does not list, and a
// source with no address, is never limited.
func (self *dnsRrl) decide(source netip.Addr, class string, now time.Time) dnsRrlAction {
	if !slices.Contains(self.classes, class) {
		return dnsRrlSend
	}
	prefix, ok := self.prefix(source)
	if !ok {
		return dnsRrlSend
	}
	key := dnsRrlKey{prefix: prefix, class: class}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var bucket *dnsRrlBucket
	if element, ok := self.buckets[key]; ok {
		bucket = element.Value.(*dnsRrlBucket)
		self.recency.MoveToFront(element)
		if elapsed := now.Sub(bucket.last); 0 < elapsed {
			bucket.balance = min(self.ratePerSecond, bucket.balance+elapsed.Seconds()*self.ratePerSecond)
			bucket.last = now
		}
	} else {
		bucket = &dnsRrlBucket{key: key, balance: self.ratePerSecond, last: now}
		self.buckets[key] = self.recency.PushFront(bucket)
		for self.bucketCount < self.recency.Len() {
			oldest := self.recency.Back()
			self.recency.Remove(oldest)
			delete(self.buckets, oldest.Value.(*dnsRrlBucket).key)
		}
	}
	bucket.balance -= 1
	limited := bucket.balance < 0
	bucket.balance = max(-self.debtMax, bucket.balance)
	// a bucket idle past its window has earned back all it could owe, so it is a fresh one: drop it
	for oldest := self.recency.Back(); oldest != nil && oldest != self.buckets[key]; oldest = self.recency.Back() {
		if now.Sub(oldest.Value.(*dnsRrlBucket).last) <= self.expiry {
			break
		}
		self.recency.Remove(oldest)
		delete(self.buckets, oldest.Value.(*dnsRrlBucket).key)
	}
	if !limited {
		return dnsRrlSend
	}
	bucket.dropCount += 1
	if 0 < self.slip && bucket.dropCount%self.slip == 0 {
		return dnsRrlSlip
	}
	return dnsRrlDrop
}

// Buckets held now, for a test.
func (self *dnsRrl) bucketsHeld() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.recency.Len()
}
