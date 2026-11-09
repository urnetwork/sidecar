//go:build !sidecar_http

// MxWorld: the outside world the edge resolves and dials, in one process. A fixture DNS under a test
// root key signs its zones with miekg/dns (ECDSA P-256, algorithm 13, one key a zone), so a
// dnssec_chain built here validates against TrustAnchorDs and nothing else, and it serves MX, null MX,
// implicit MX, wildcard MX, TLSA, addresses, NSEC3 denials, unsigned zones, broken chains (an expired
// signature, an unpublished key, a DS that matches no key) and MTA-STS policies. It implements
// sidecar.SmtpMxResolver as a validating resolver would answer, and sidecar.SmtpMxDialer over MxPipes
// to the MxServers placed at addresses, so nothing touches port 25 and nothing sleeps.
//
// A chain follows plan-SMTP-small-readings#2's reading of RFC 9102's order: the answer RRsets with
// their RRSIGs, or their NSEC3 denial, then for every zone from the deepest to the root its DNSKEY
// RRset and RRSIG and, below the root, its DS RRset and the parent's RRSIG, all uncompressed wire RRs.
// Names are .example and addresses RFC 5737's. Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
)

var (
	errMxWorldNoZone    = errors.New("mx world: no zone holds that name")
	errMxWorldConnRefus = errors.New("mx world: connection refused")
)

// RRset TTLs here, a format value of the fixture's.
const mxWorldTtl = 300

// How an MxWorld signs.
type MxWorldSettings struct {
	// What RRSIG validity and expiry read. Nil is real time.
	Clock Clock
	// How long a signature stays valid from now: 30 days.
	SignatureValidity time.Duration
	// How far back its inception reaches, so a clock moved a little back still validates: 1 h.
	SignatureBacking time.Duration
}

func DefaultMxWorldSettings() *MxWorldSettings {
	return &MxWorldSettings{SignatureValidity: 30 * 24 * time.Hour, SignatureBacking: time.Hour}
}

// What makes a zone insecure or bogus.
type MxWorldZoneOptions struct {
	// No keys and no DS at the parent: an insecure delegation, answered with Secure false.
	Unsigned bool
	// Every RRSIG the zone makes expired an hour before now.
	ExpiredSignatures bool
	// Every RRset signed by a key the zone's DNSKEY RRset does not hold.
	WrongKey bool
	// The parent's DS for the zone matches no key.
	BrokenDs bool
}

type mxWorldZone struct {
	name    string
	options MxWorldZoneOptions
	key     *dns.DNSKEY
	signer  crypto.Signer
	// what signs every RRset under WrongKey, published nowhere
	wrongKey    *dns.DNSKEY
	wrongSigner crypto.Signer
	// by owner, then type
	records map[string]map[uint16][]dns.RR
}

type MxWorld struct {
	settings *MxWorldSettings
	clock    Clock

	stateLock sync.Mutex
	// by name, fully qualified and lowercase
	zones map[string]*mxWorldZone
	// what each address serves
	servers map[netip.Addr]MxServer
	// MTA-STS policy bodies by domain
	policies map[string]string
	dials    []netip.Addr
	// every connection a server is serving
	serving sync.WaitGroup
}

var _ sidecar.SmtpMxResolver = (*MxWorld)(nil)
var _ sidecar.SmtpMxDialer = (*MxWorld)(nil)
var _ MxChainSource = (*MxWorld)(nil)

// A world with a signed root and a signed example. under it. A nil settings is
// DefaultMxWorldSettings'.
func NewMxWorld(settings *MxWorldSettings) (*MxWorld, error) {
	if settings == nil {
		settings = DefaultMxWorldSettings()
	}
	clock := settings.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	world := &MxWorld{
		settings: settings,
		clock:    clock,
		zones:    map[string]*mxWorldZone{},
		servers:  map[netip.Addr]MxServer{},
		policies: map[string]string{},
	}
	if err := world.addZone(".", &MxWorldZoneOptions{}); err != nil {
		return nil, err
	}
	if err := world.addZone("example.", &MxWorldZoneOptions{}); err != nil {
		return nil, err
	}
	return world, nil
}

func mxWorldName(name string) string {
	return dns.CanonicalName(dns.Fqdn(name))
}

// A new signing key for zone. miekg/dns will not sign under a key whose tag is 0, and about one
// random key in 65536 has that tag, so such a key is drawn again.
func newMxWorldKey(zone string) (*dns.DNSKEY, crypto.Signer, error) {
	for {
		key := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: mxWorldTtl},
			Flags:     dns.ZONE | dns.SEP,
			Protocol:  3,
			Algorithm: dns.ECDSAP256SHA256,
		}
		private, err := key.Generate(256)
		if err != nil {
			return nil, nil, err
		}
		if key.KeyTag() != 0 {
			return key, private.(crypto.Signer), nil
		}
	}
}

// The deepest zone holding name, under the lock.
func (self *MxWorld) zoneOfWithLock(name string) *mxWorldZone {
	for candidate := name; ; {
		if zone, ok := self.zones[candidate]; ok {
			return zone
		}
		if candidate == "." {
			return nil
		}
		labels := dns.SplitDomainName(candidate)
		if len(labels) <= 1 {
			candidate = "."
		} else {
			candidate = dns.Fqdn(strings.Join(labels[1:], "."))
		}
	}
}

// The zone directly above zone, under the lock.
func (self *MxWorld) parentOfWithLock(zone *mxWorldZone) *mxWorldZone {
	if zone.name == "." {
		return nil
	}
	labels := dns.SplitDomainName(zone.name)
	if len(labels) <= 1 {
		return self.zones["."]
	}
	return self.zoneOfWithLock(dns.Fqdn(strings.Join(labels[1:], ".")))
}

func (self *MxWorld) addZone(name string, options *MxWorldZoneOptions) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name = mxWorldName(name)
	if _, ok := self.zones[name]; ok {
		return fmt.Errorf("mx world: zone %s exists", name)
	}
	zone := &mxWorldZone{name: name, options: *options, records: map[string]map[uint16][]dns.RR{}}
	if !options.Unsigned {
		var err error
		if zone.key, zone.signer, err = newMxWorldKey(name); err != nil {
			return err
		}
		if zone.wrongKey, zone.wrongSigner, err = newMxWorldKey(name); err != nil {
			return err
		}
	}
	if name != "." {
		parent := self.zoneOfWithLock(name)
		if parent == nil {
			return errMxWorldNoZone
		}
		parent.add(&dns.NS{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: mxWorldTtl}, Ns: "ns." + name})
		if !options.Unsigned {
			ds := zone.key.ToDS(dns.SHA256)
			ds.Hdr.Ttl = mxWorldTtl
			if options.BrokenDs {
				digest := []byte(ds.Digest)
				digest[0] = "0123456789ABCDEF"[(strings.IndexByte("0123456789ABCDEF", digest[0])+1)%16]
				ds.Digest = string(digest)
			}
			parent.add(ds)
		}
	}
	self.zones[name] = zone
	return nil
}

func (self *mxWorldZone) add(rr dns.RR) {
	header := rr.Header()
	header.Name = mxWorldName(header.Name)
	types, ok := self.records[header.Name]
	if !ok {
		types = map[uint16][]dns.RR{}
		self.records[header.Name] = types
	}
	types[header.Rrtype] = append(types[header.Rrtype], rr)
}

// A zone under the deepest zone holding name, signed unless options say otherwise. A nil options
// signs it whole.
func (self *MxWorld) AddZone(name string, options *MxWorldZoneOptions) error {
	if options == nil {
		options = &MxWorldZoneOptions{}
	}
	return self.addZone(name, options)
}

// domain's MX RRset, replacing none: domain may be a wildcard, *.<name>.
func (self *MxWorld) SetMx(domain string, hosts ...*sidecar.SmtpMxHost) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name := mxWorldName(domain)
	zone := self.zoneOfWithLock(name)
	if zone == nil {
		return errMxWorldNoZone
	}
	for _, host := range hosts {
		zone.add(&dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: mxWorldTtl}, Preference: host.Preference, Mx: mxWorldName(host.Host)})
	}
	return nil
}

// RFC 7505's null MX at domain.
func (self *MxWorld) SetNullMx(domain string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name := mxWorldName(domain)
	zone := self.zoneOfWithLock(name)
	if zone == nil {
		return errMxWorldNoZone
	}
	zone.add(&dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: mxWorldTtl}, Preference: 0, Mx: "."})
	return nil
}

// An MX host: its address, the server there, and any TLSA records at _25._tcp.<host>.
func (self *MxWorld) AddMx(host string, address netip.Addr, server MxServer, tlsa ...*sidecar.SmtpTlsaRecord) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name := mxWorldName(host)
	zone := self.zoneOfWithLock(name)
	if zone == nil {
		return errMxWorldNoZone
	}
	header := dns.RR_Header{Name: name, Class: dns.ClassINET, Ttl: mxWorldTtl}
	if address.Is4() {
		header.Rrtype = dns.TypeA
		zone.add(&dns.A{Hdr: header, A: net.IP(address.AsSlice())})
	} else {
		header.Rrtype = dns.TypeAAAA
		zone.add(&dns.AAAA{Hdr: header, AAAA: net.IP(address.AsSlice())})
	}
	for _, record := range tlsa {
		zone.add(&dns.TLSA{
			Hdr:          dns.RR_Header{Name: "_25._tcp." + name, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: mxWorldTtl},
			Usage:        record.Usage,
			Selector:     record.Selector,
			MatchingType: record.MatchingType,
			Certificate:  fmt.Sprintf("%X", record.Data),
		})
	}
	if server != nil {
		self.servers[address] = server
	}
	return nil
}

// An MTA-STS policy for domain (RFC 8461): its TXT record and the body served at
// https://mta-sts.<domain>/.well-known/mta-sts.txt.
func (self *MxWorld) SetMtaStsPolicy(domain string, id string, policy string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name := mxWorldName(domain)
	zone := self.zoneOfWithLock(name)
	if zone == nil {
		return errMxWorldNoZone
	}
	zone.add(&dns.TXT{Hdr: dns.RR_Header{Name: "_mta-sts." + name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: mxWorldTtl}, Txt: []string{"v=STSv1; id=" + id}})
	self.policies[strings.TrimSuffix(name, ".")] = policy
	return nil
}

// The root's DS, the only trust anchor a chain from here validates under, as an uncompressed wire RR.
func (self *MxWorld) TrustAnchorDs() []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ds := self.zones["."].key.ToDS(dns.SHA256)
	ds.Hdr.Ttl = mxWorldTtl
	return mxWorldPack(ds)
}

// The root's DNSKEY, as an uncompressed wire RR.
func (self *MxWorld) TrustAnchorDnskey() []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return mxWorldPack(self.zones["."].key)
}

// Every address dialed, in order.
func (self *MxWorld) Dials() []netip.Addr {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]netip.Addr(nil), self.dials...)
}

func mxWorldPack(rr dns.RR) []byte {
	wire := make([]byte, dns.Len(rr)+64)
	n, err := dns.PackRR(rr, wire, 0, nil, false)
	if err != nil {
		panic(err)
	}
	return wire[:n]
}

// An RRSIG over rrset by zone, as its options would sign it.
func (self *MxWorld) signWithLock(zone *mxWorldZone, rrset []dns.RR) *dns.RRSIG {
	now := self.clock.Now()
	key, signer := zone.key, zone.signer
	if zone.options.WrongKey {
		key, signer = zone.wrongKey, zone.wrongSigner
	}
	signature := &dns.RRSIG{
		Hdr:        dns.RR_Header{Ttl: mxWorldTtl},
		Algorithm:  dns.ECDSAP256SHA256,
		KeyTag:     key.KeyTag(),
		SignerName: zone.name,
		Inception:  uint32(now.Add(-self.settings.SignatureBacking).Unix()),
		Expiration: uint32(now.Add(self.settings.SignatureValidity).Unix()),
	}
	if zone.options.ExpiredSignatures {
		signature.Inception = uint32(now.Add(-2 * self.settings.SignatureValidity).Unix())
		signature.Expiration = uint32(now.Add(-time.Hour).Unix())
	}
	if err := signature.Sign(signer, rrset); err != nil {
		panic(err)
	}
	return signature
}

// An RRset and, in a signed zone, its RRSIG, as wire.
func (self *MxWorld) signedWithLock(zone *mxWorldZone, rrset []dns.RR) []byte {
	var wire []byte
	for _, rr := range rrset {
		wire = append(wire, mxWorldPack(rr)...)
	}
	if zone.key != nil {
		wire = append(wire, mxWorldPack(self.signWithLock(zone, rrset))...)
	}
	return wire
}

// What NSEC3 here hashes with: SHA-1, no iterations, no salt (RFC 9276).
func mxWorldHash(name string) string {
	return dns.HashName(name, dns.SHA1, 0, "")
}

// The zone's NSEC3 chain, every name and the names between them, sorted by hash.
func (self *mxWorldZone) nsec3Chain() []*dns.NSEC3 {
	nameTypes := map[string][]uint16{self.name: {dns.TypeDNSKEY}}
	for owner, types := range self.records {
		for rrtype := range types {
			nameTypes[owner] = append(nameTypes[owner], rrtype)
		}
		// the names between an owner and the apex exist as empty non-terminals
		for ancestor := owner; ancestor != self.name; {
			labels := dns.SplitDomainName(ancestor)
			if len(labels) <= 1 {
				break
			}
			ancestor = dns.Fqdn(strings.Join(labels[1:], "."))
			if _, ok := nameTypes[ancestor]; !ok && ancestor != self.name && dns.IsSubDomain(self.name, ancestor) {
				nameTypes[ancestor] = []uint16{}
			}
		}
	}
	type hashed struct {
		hash  string
		types []uint16
	}
	var chain []hashed
	for name, types := range nameTypes {
		// a delegation's NS is the child's and unsigned here, so only its DS brings an RRSIG
		delegation := slices.Contains(types, dns.TypeNS) && name != self.name
		if (!delegation && len(types) != 0) || slices.Contains(types, dns.TypeDS) {
			types = append(types, dns.TypeRRSIG)
		}
		slices.Sort(types)
		chain = append(chain, hashed{hash: mxWorldHash(name), types: slices.Compact(types)})
	}
	slices.SortFunc(chain, func(a, b hashed) int { return strings.Compare(a.hash, b.hash) })
	records := make([]*dns.NSEC3, 0, len(chain))
	for i, entry := range chain {
		next := chain[(i+1)%len(chain)].hash
		records = append(records, &dns.NSEC3{
			Hdr:        dns.RR_Header{Name: strings.ToLower(entry.hash) + "." + self.name, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: mxWorldTtl},
			Hash:       dns.SHA1,
			Iterations: 0,
			SaltLength: 0,
			Salt:       "",
			HashLength: sha1.Size,
			NextDomain: next,
			TypeBitMap: entry.types,
		})
	}
	return records
}

// The NSEC3 RRs that deny name of rrtype in zone (RFC 5155 §7.2): the one matching name when it exists
// without that type, else the closest encloser proof and the wildcard's denial. Signed, as wire.
func (self *MxWorld) denialWithLock(zone *mxWorldZone, name string) []byte {
	chain := zone.nsec3Chain()
	matching := func(target string) *dns.NSEC3 {
		for _, record := range chain {
			if record.Match(target) {
				return record
			}
		}
		return nil
	}
	covering := func(target string) *dns.NSEC3 {
		for _, record := range chain {
			if record.Cover(target) {
				return record
			}
		}
		return nil
	}
	var proof []*dns.NSEC3
	if record := matching(name); record != nil {
		proof = append(proof, record)
	} else {
		closest, nextCloser := name, name
		for matching(closest) == nil {
			nextCloser = closest
			labels := dns.SplitDomainName(closest)
			closest = dns.Fqdn(strings.Join(labels[1:], "."))
		}
		for _, record := range []*dns.NSEC3{matching(closest), covering(nextCloser), covering("*." + closest)} {
			if record != nil && !slices.Contains(proof, record) {
				proof = append(proof, record)
			}
		}
	}
	var wire []byte
	for _, record := range proof {
		wire = append(wire, self.signedWithLock(zone, []dns.RR{record})...)
	}
	return wire
}

// Every zone from zone up to the root, deepest first.
func (self *MxWorld) pathWithLock(zone *mxWorldZone) []*mxWorldZone {
	var path []*mxWorldZone
	for ; zone != nil; zone = self.parentOfWithLock(zone) {
		path = append(path, zone)
	}
	return path
}

// Whether every zone on the path is signed and none is broken: Secure and not bogus.
func mxWorldPathState(path []*mxWorldZone) (secure bool, bogus bool) {
	secure = true
	for _, zone := range path {
		if zone.options.Unsigned {
			secure = false
		}
		if zone.options.ExpiredSignatures || zone.options.WrongKey || zone.options.BrokenDs {
			bogus = true
		}
	}
	return secure, bogus && secure
}

// Each zone's DNSKEY and DS material, deepest first, every zone once.
func (self *MxWorld) zoneMaterialWithLock(zones ...*mxWorldZone) []byte {
	var path []*mxWorldZone
	for _, zone := range zones {
		for _, onPath := range self.pathWithLock(zone) {
			if !slices.Contains(path, onPath) {
				path = append(path, onPath)
			}
		}
	}
	slices.SortStableFunc(path, func(a, b *mxWorldZone) int {
		return dns.CountLabel(b.name) - dns.CountLabel(a.name)
	})
	var wire []byte
	for _, zone := range path {
		parent := self.parentOfWithLock(zone)
		if zone.key != nil {
			wire = append(wire, self.signedWithLock(zone, []dns.RR{zone.key})...)
		}
		if parent == nil {
			continue
		}
		if ds := parent.records[zone.name][dns.TypeDS]; 0 < len(ds) {
			wire = append(wire, self.signedWithLock(parent, ds)...)
		} else if parent.key != nil {
			// an insecure delegation: the parent proves the DS absent
			wire = append(wire, self.denialWithLock(parent, zone.name)...)
		}
	}
	return wire
}

// domain's MX answer, as wire with its RRSIG or denial, and what it found. The bool is whether the
// domain exists.
func (self *MxWorld) mxAnswerWithLock(zone *mxWorldZone, name string) (wire []byte, hosts []*sidecar.SmtpMxHost, nullMx bool, exists bool) {
	rrset := zone.records[name][dns.TypeMX]
	wildcard := ""
	if rrset == nil && zone.records[name] == nil {
		labels := dns.SplitDomainName(name)
		for i := 1; i < len(labels) && wildcard == ""; i += 1 {
			candidate := "*." + dns.Fqdn(strings.Join(labels[i:], "."))
			if zone.records[candidate][dns.TypeMX] != nil {
				wildcard = candidate
			}
		}
	}
	switch {
	case rrset != nil:
		wire = self.signedWithLock(zone, rrset)
	case wildcard != "":
		signed := zone.records[wildcard][dns.TypeMX]
		var signature *dns.RRSIG
		if zone.key != nil {
			signature = self.signWithLock(zone, signed)
		}
		for _, rr := range signed {
			expanded := dns.Copy(rr)
			expanded.Header().Name = name
			rrset = append(rrset, expanded)
			wire = append(wire, mxWorldPack(expanded)...)
		}
		if signature != nil {
			signature.Hdr.Name = name
			wire = append(wire, mxWorldPack(signature)...)
			// the proof that no closer name exists (RFC 4035 §5.3.4)
			wire = append(wire, self.denialWithLock(zone, name)...)
		}
	case zone.records[name] != nil:
		// the name exists without MX: RFC 5321 §5.1's implicit MX
		if zone.key != nil {
			wire = self.denialWithLock(zone, name)
		}
		return wire, nil, false, true
	default:
		return nil, nil, false, false
	}
	for _, rr := range rrset {
		mx := rr.(*dns.MX)
		if mx.Mx == "." && mx.Preference == 0 && len(rrset) == 1 {
			return wire, nil, true, true
		}
		hosts = append(hosts, &sidecar.SmtpMxHost{Preference: mx.Preference, Host: strings.TrimSuffix(mx.Mx, ".")})
	}
	slices.SortStableFunc(hosts, func(a, b *sidecar.SmtpMxHost) int { return int(a.Preference) - int(b.Preference) })
	return wire, hosts, false, true
}

// host's TLSA answer at port 25, as wire with its RRSIG or denial.
func (self *MxWorld) tlsaAnswerWithLock(zone *mxWorldZone, host string) ([]byte, []*sidecar.SmtpTlsaRecord) {
	name := "_25._tcp." + host
	rrset := zone.records[name][dns.TypeTLSA]
	if rrset == nil {
		if zone.key == nil {
			return nil, nil
		}
		return self.denialWithLock(zone, name), nil
	}
	var records []*sidecar.SmtpTlsaRecord
	for _, rr := range rrset {
		tlsa := rr.(*dns.TLSA)
		// written by AddMx from octets, so it always decodes
		data, _ := hex.DecodeString(tlsa.Certificate)
		records = append(records, &sidecar.SmtpTlsaRecord{Usage: tlsa.Usage, Selector: tlsa.Selector, MatchingType: tlsa.MatchingType, Data: data})
	}
	return self.signedWithLock(zone, rrset), records
}

// See sidecar.SmtpMxResolver: a validating resolver's view, bogus for a broken path.
func (self *MxWorld) LookupMx(ctx context.Context, domain string) (*sidecar.SmtpMxAnswer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name := mxWorldName(domain)
	zone := self.zoneOfWithLock(name)
	if zone == nil {
		return nil, sidecar.ErrSmtpMxNoSuchDomain
	}
	secure, bogus := mxWorldPathState(self.pathWithLock(zone))
	if bogus {
		return nil, sidecar.ErrSmtpMxBogus
	}
	wire, hosts, nullMx, exists := self.mxAnswerWithLock(zone, name)
	if !exists {
		return nil, sidecar.ErrSmtpMxNoSuchDomain
	}
	answer := &sidecar.SmtpMxAnswer{Hosts: hosts, NullMx: nullMx, Secure: secure}
	if secure {
		answer.Chain = append(wire, self.zoneMaterialWithLock(zone)...)
	}
	return answer, nil
}

func (self *MxWorld) LookupTlsa(ctx context.Context, host string) (*sidecar.SmtpTlsaAnswer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name := mxWorldName(host)
	zone := self.zoneOfWithLock(name)
	if zone == nil {
		return nil, sidecar.ErrSmtpMxNoSuchDomain
	}
	secure, bogus := mxWorldPathState(self.pathWithLock(zone))
	if bogus {
		return nil, sidecar.ErrSmtpMxBogus
	}
	wire, records := self.tlsaAnswerWithLock(zone, name)
	answer := &sidecar.SmtpTlsaAnswer{Records: records, Secure: secure}
	if secure {
		answer.Chain = append(wire, self.zoneMaterialWithLock(zone)...)
	}
	return answer, nil
}

func (self *MxWorld) LookupAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name := mxWorldName(host)
	zone := self.zoneOfWithLock(name)
	if zone == nil {
		return nil, sidecar.ErrSmtpMxNoSuchDomain
	}
	if _, bogus := mxWorldPathState(self.pathWithLock(zone)); bogus {
		return nil, sidecar.ErrSmtpMxBogus
	}
	var addresses []netip.Addr
	for _, rr := range zone.records[name][dns.TypeA] {
		address, _ := netip.AddrFromSlice(rr.(*dns.A).A.To4())
		addresses = append(addresses, address)
	}
	for _, rr := range zone.records[name][dns.TypeAAAA] {
		address, _ := netip.AddrFromSlice(rr.(*dns.AAAA).AAAA)
		addresses = append(addresses, address)
	}
	if addresses == nil {
		return nil, sidecar.ErrSmtpMxNoSuchDomain
	}
	return addresses, nil
}

// Every TXT string at name, as the sidecar's own DoH lookup of _mta-sts would find it.
func (self *MxWorld) LookupTxt(ctx context.Context, name string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fqdn := mxWorldName(name)
	zone := self.zoneOfWithLock(fqdn)
	if zone == nil {
		return nil, sidecar.ErrSmtpMxNoSuchDomain
	}
	var texts []string
	for _, rr := range zone.records[fqdn][dns.TypeTXT] {
		texts = append(texts, strings.Join(rr.(*dns.TXT).Txt, ""))
	}
	return texts, nil
}

// The edge's dnssec_chain for domain and the MX it chose: the MX answer, the TLSA answer or its
// denial, then every zone on both paths. A broken or unsigned zone still gives its chain, which then
// fails to validate, as a forged or stripped one would.
func (self *MxWorld) Chain(domain string, mxHost string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name, host := mxWorldName(domain), mxWorldName(mxHost)
	zone, hostZone := self.zoneOfWithLock(name), self.zoneOfWithLock(host)
	if zone == nil || hostZone == nil {
		return nil, errMxWorldNoZone
	}
	mxWire, _, _, exists := self.mxAnswerWithLock(zone, name)
	if !exists {
		return nil, sidecar.ErrSmtpMxNoSuchDomain
	}
	tlsaWire, _ := self.tlsaAnswerWithLock(hostZone, host)
	chain := append(append(mxWire, tlsaWire...), self.zoneMaterialWithLock(zone, hostZone)...)
	return chain, nil
}

// See sidecar.SmtpMxDialer: a pipe to the server placed at mxAddress, which serves it until it ends.
func (self *MxWorld) DialMx(ctx context.Context, sendingAddress netip.Addr, mxAddress netip.Addr) (net.Conn, error) {
	server, err := func() (MxServer, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.dials = append(self.dials, mxAddress)
		server, ok := self.servers[mxAddress]
		if !ok {
			return nil, errMxWorldConnRefus
		}
		return server, nil
	}()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, serverEnd := NewMxPipe(
		net.TCPAddrFromAddrPort(netip.AddrPortFrom(sendingAddress, 40000)),
		net.TCPAddrFromAddrPort(netip.AddrPortFrom(mxAddress, 25)),
	)
	self.serving.Add(1)
	go func() {
		defer self.serving.Done()
		server.ServeMx(serverEnd)
	}()
	return client, nil
}

// Waits until every connection dialed has been served to its end, so a test reads an MX's record
// only once the MX is done with it.
func (self *MxWorld) Wait() {
	self.serving.Wait()
}

// Serves https://mta-sts.<domain>/.well-known/mta-sts.txt for each policy set, and 404 otherwise, in
// place of the sidecar's own fetch (§14.4's TL2).
func (self *MxWorld) MtaStsTransport() http.RoundTripper {
	return mxWorldMtaSts{world: self}
}

type mxWorldMtaSts struct {
	world *MxWorld
}

func (self mxWorldMtaSts) RoundTrip(request *http.Request) (*http.Response, error) {
	policy, ok := func() (string, bool) {
		self.world.stateLock.Lock()
		defer self.world.stateLock.Unlock()
		domain, found := strings.CutPrefix(request.URL.Hostname(), "mta-sts.")
		if !found || request.URL.Scheme != "https" || request.URL.Path != "/.well-known/mta-sts.txt" {
			return "", false
		}
		policy, ok := self.world.policies[domain]
		return policy, ok
	}()
	response := &http.Response{Request: request, Header: http.Header{"Content-Type": {"text/plain"}}, StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil))}
	if ok {
		response.StatusCode = http.StatusOK
		response.Body = io.NopCloser(strings.NewReader(policy))
		response.ContentLength = int64(len(policy))
	}
	return response, nil
}
