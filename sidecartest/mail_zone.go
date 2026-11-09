// A fake of the DoH forwarding a receiver's lookups take (connect's DohCache.Forward, §2.8 ext-3;
// MAIL-M7-03): Forward answers TXT, A, AAAA, MX, PTR and TLSA from a table as RFC 8484 wire, each after
// its name's delay on the zone's clock, and fails as a test scripts, so FS-121's 4.9 s selectors cost no
// real time. Its signature is Forward's, so MAIL-M7-07's resolver takes either.
//
// Names compare lowercase with no trailing dot. An answer's owner is the name as asked, absolute, and
// each record keeps the table's TTL. Every query is logged with its start and end on the clock, and the
// queries waiting at once are counted, so a test can show a budget's 64 queries and 8 in flight. Safe for
// concurrent use.

package sidecartest

import (
	"context"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
)

// TLSA's record type (RFC 6698), which dnsmessage has no constant for.
const MailZoneTypeTlsa dnsmessage.Type = 52

// How a scripted lookup fails.
type FakeMailZoneFailure string

const (
	// RCODE 2.
	FakeMailZoneServFail FakeMailZoneFailure = "servfail"
	// RCODE 3, though the table may hold the name.
	FakeMailZoneNxDomain FakeMailZoneFailure = "nxdomain"
	// No usable response, as when every resolver path failed.
	FakeMailZoneUnusable FakeMailZoneFailure = "unusable"
	// The TC bit and no answer.
	FakeMailZoneTruncated FakeMailZoneFailure = "truncated"
	// Bytes that are no DNS message.
	FakeMailZoneMalformed FakeMailZoneFailure = "malformed"
	// No answer until the caller's context ends.
	FakeMailZoneHang FakeMailZoneFailure = "hang"
)

// One query the zone was asked.
type FakeMailZoneQuery struct {
	Name  string
	Type  dnsmessage.Type
	Start time.Time
	// Zero while it waits.
	End time.Time
}

type fakeMailZoneKey struct {
	name  string
	qType dnsmessage.Type
}

// A table of records on a clock.
type FakeMailZone struct {
	clock Clock
	// The TTL every record answers with, in seconds.
	ttl uint32
	// Queries waiting at once, so a test can wait for a count with no sleep.
	inFlight *sidecar.MonitorValue[int]

	stateLock sync.Mutex
	records   map[fakeMailZoneKey][]dnsmessage.ResourceBody
	delays    map[string]time.Duration
	failures  map[fakeMailZoneKey]FakeMailZoneFailure
	queries   []*FakeMailZoneQuery
	// queries waiting now, mirrored to inFlight in the same locked scope
	inFlightCount int
	maxInFlight   int
}

// An empty zone on clock, every record answering with a TTL of 300 s.
func NewFakeMailZone(clock Clock) *FakeMailZone {
	return &FakeMailZone{
		clock:    clock,
		ttl:      300,
		inFlight: sidecar.NewMonitorValue(0),
		records:  map[fakeMailZoneKey][]dnsmessage.ResourceBody{},
		delays:   map[string]time.Duration{},
		failures: map[fakeMailZoneKey]FakeMailZoneFailure{},
	}
}

// A name as the table keys it.
func mailZoneName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Adds a record to its RRset, once: an RRset holds no record twice (RFC 2181 §5).
func (self *FakeMailZone) add(name string, qType dnsmessage.Type, body dnsmessage.ResourceBody) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := fakeMailZoneKey{name: mailZoneName(name), qType: qType}
	if slices.ContainsFunc(self.records[key], func(existing dnsmessage.ResourceBody) bool { return reflect.DeepEqual(existing, body) }) {
		return
	}
	self.records[key] = append(self.records[key], body)
}

// A TXT record of one or more strings, each at most 255 bytes; a longer text is split, as a zone file
// would.
func (self *FakeMailZone) AddTxt(name string, text string) {
	pieces := []string{}
	for 255 < len(text) {
		pieces = append(pieces, text[:255])
		text = text[255:]
	}
	pieces = append(pieces, text)
	self.add(name, dnsmessage.TypeTXT, &dnsmessage.TXTResource{TXT: pieces})
}

// An A or AAAA record, by the address's family.
func (self *FakeMailZone) AddAddress(name string, address netip.Addr) {
	address = address.Unmap()
	if address.Is4() {
		self.add(name, dnsmessage.TypeA, &dnsmessage.AResource{A: address.As4()})
		return
	}
	self.add(name, dnsmessage.TypeAAAA, &dnsmessage.AAAAResource{AAAA: address.As16()})
}

func (self *FakeMailZone) AddMx(name string, preference uint16, host string) {
	self.add(name, dnsmessage.TypeMX, &dnsmessage.MXResource{Pref: preference, MX: dnsmessage.MustNewName(mailZoneName(host) + ".")})
}

// A PTR record at an address's reverse name.
func (self *FakeMailZone) AddPtr(address netip.Addr, host string) {
	self.add(MailZoneReverseName(address), dnsmessage.TypePTR, &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(mailZoneName(host) + ".")})
}

// A TLSA record (RFC 6698 §2.1).
func (self *FakeMailZone) AddTlsa(name string, usage uint8, selector uint8, matchingType uint8, data []byte) {
	rdata := append([]byte{usage, selector, matchingType}, data...)
	self.add(name, MailZoneTypeTlsa, &dnsmessage.UnknownResource{Type: MailZoneTypeTlsa, Data: rdata})
}

// An address's reverse name, in in-addr.arpa or ip6.arpa.
func MailZoneReverseName(address netip.Addr) string {
	address = address.Unmap()
	const hexDigits = "0123456789abcdef"
	if address.Is4() {
		octets := address.As4()
		return strings.Join([]string{
			itoa(int(octets[3])), itoa(int(octets[2])), itoa(int(octets[1])), itoa(int(octets[0])), "in-addr", "arpa",
		}, ".")
	}
	octets := address.As16()
	labels := make([]string, 0, 34)
	for index := len(octets) - 1; 0 <= index; index -= 1 {
		labels = append(labels, string(hexDigits[octets[index]&0x0f]), string(hexDigits[octets[index]>>4]))
	}
	return strings.Join(append(labels, "ip6", "arpa"), ".")
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := []byte{}
	for 0 < value {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// Every query of name answers delay later on the zone's clock.
func (self *FakeMailZone) SetDelay(name string, delay time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.delays[mailZoneName(name)] = delay
}

// Queries of name and qType fail as failure, after the name's delay.
func (self *FakeMailZone) Fail(name string, qType dnsmessage.Type, failure FakeMailZoneFailure) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failures[fakeMailZoneKey{name: mailZoneName(name), qType: qType}] = failure
}

// DohCache.Forward's shape: the raw response to qType for domain, after domain's delay, and whether it is
// usable. A context that ends first answers nothing usable.
func (self *FakeMailZone) Forward(ctx context.Context, qType dnsmessage.Type, domain string) (response []byte, usable bool) {
	name := mailZoneName(domain)
	query := &FakeMailZoneQuery{Name: name, Type: qType, Start: self.clock.Now()}
	key := fakeMailZoneKey{name: name, qType: qType}
	var delay time.Duration
	var failure FakeMailZoneFailure
	var bodies []dnsmessage.ResourceBody
	nameKnown := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.queries = append(self.queries, query)
		delay = self.delays[name]
		failure = self.failures[key]
		bodies = self.records[key]
		for recordKey := range self.records {
			if recordKey.name == name {
				nameKnown = true
				break
			}
		}
	}()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.inFlightCount += 1
		self.maxInFlight = max(self.maxInFlight, self.inFlightCount)
		self.inFlight.Set(self.inFlightCount)
	}()
	defer func() {
		end := self.clock.Now()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		query.End = end
		self.inFlightCount -= 1
		self.inFlight.Set(self.inFlightCount)
	}()

	if failure == FakeMailZoneHang {
		<-ctx.Done()
		return nil, false
	}
	if 0 < delay {
		select {
		case <-self.clock.After(delay):
		case <-ctx.Done():
			return nil, false
		}
	}
	switch failure {
	case FakeMailZoneUnusable:
		return nil, false
	case FakeMailZoneMalformed:
		return []byte{0x00, 0x01, 0xff}, true
	}
	header := dnsmessage.Header{Response: true, Authoritative: true}
	switch {
	case failure == FakeMailZoneServFail:
		header.RCode = dnsmessage.RCodeServerFailure
		bodies = nil
	case failure == FakeMailZoneNxDomain:
		header.RCode = dnsmessage.RCodeNameError
		bodies = nil
	case failure == FakeMailZoneTruncated:
		header.Truncated = true
		bodies = nil
	case !nameKnown:
		header.RCode = dnsmessage.RCodeNameError
	}
	response, err := mailZoneMessage(header, domain, qType, bodies, self.ttl)
	if err != nil {
		return nil, false
	}
	return response, true
}

// The wire form of one answer.
func mailZoneMessage(header dnsmessage.Header, domain string, qType dnsmessage.Type, bodies []dnsmessage.ResourceBody, ttl uint32) ([]byte, error) {
	owner, err := dnsmessage.NewName(mailZoneName(domain) + ".")
	if err != nil {
		return nil, err
	}
	builder := dnsmessage.NewBuilder(nil, header)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{Name: owner, Type: qType, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	for _, body := range bodies {
		resourceHeader := dnsmessage.ResourceHeader{Name: owner, Type: qType, Class: dnsmessage.ClassINET, TTL: ttl}
		var err error
		switch typed := body.(type) {
		case *dnsmessage.TXTResource:
			err = builder.TXTResource(resourceHeader, *typed)
		case *dnsmessage.AResource:
			err = builder.AResource(resourceHeader, *typed)
		case *dnsmessage.AAAAResource:
			err = builder.AAAAResource(resourceHeader, *typed)
		case *dnsmessage.MXResource:
			err = builder.MXResource(resourceHeader, *typed)
		case *dnsmessage.PTRResource:
			err = builder.PTRResource(resourceHeader, *typed)
		case *dnsmessage.UnknownResource:
			err = builder.UnknownResource(resourceHeader, *typed)
		}
		if err != nil {
			return nil, err
		}
	}
	return builder.Finish()
}

// Every query so far, oldest first, as copies.
func (self *FakeMailZone) Queries() []FakeMailZoneQuery {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	queries := make([]FakeMailZoneQuery, 0, len(self.queries))
	for _, query := range self.queries {
		queries = append(queries, *query)
	}
	return queries
}

// The most queries that waited at once.
func (self *FakeMailZone) MaxInFlight() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.maxInFlight
}

// Returns once count queries are waiting, or ctx ends: how a test knows its lookups reached the zone
// before it moves the clock.
func (self *FakeMailZone) AwaitInFlight(ctx context.Context, count int) error {
	for {
		waiting, update := self.inFlight.Get()
		if count <= waiting {
			return nil
		}
		select {
		case <-update:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
