//go:build !sidecar_http && !ios_extension

// The zone watch's mail half (DNS-M7-04; D-TRUST-9, owner decision 98, §2.8 EX2, §15.5, QD-145): the mail hosts a
// receiver serves and the DKIM selectors a sender signs with, which every pass watches beside the published hosts, and
// StrictChain, §15.5's strict_chain.
//
// A mail host (WatchMailHost, named as POST /dns/key-record names it: mx, or mx.<scope> for a Team scope's) adds to
// every pass, under the zone's apex:
//
//   - the MX at its mail domain and at the wildcard under it, which must name the host (§12.7: @ and * MX 10
//     mx.<net>.<root>, a scope's under <scope>), since a forged MX redirects the domain's mail (EX2);
//   - the host's A and AAAA, which the healthy router interfaces or a direct MX's addresses answer, so addresses and
//     never a CNAME, as at an edge host, and CAA there only as the device asked;
//   - _25._tcp.<host>'s TLSA, which must hold this receiver's own 3 1 1 record beside any other receiver's, the rest
//     held to GET /dns/zone's RRset where the device may see it. Where it may not, another receiver's record cannot
//     be told from a forged one here: each receiver's own watch holds its own record.
//
// A DKIM selector (WatchDkimSelector) must hold exactly the sender's own TXT, and a retired one nothing.
//
// StrictChain answers whether a receiver may seal strict_chain for a message: under mail.strict, the SNI host is a
// custom MX host, and every recipient domain's MX RRset and every MX host's TLSA RRset validate to the release's root
// anchors (DefaultSmtpDnssecAnchors), none of their names in a URnetwork zone (DnsWatchSettings.UrnetworkZones and
// the zone's root), with the SNI host among each domain's MX hosts and its TLSA holding this receiver's key (§12.8
// step 4: every MX host the domain lists, and its TLSA, customer-signed). The validator fetches the MX, TLSA, DNSKEY
// and DS RRsets with their RRSIGs and denials over C20's DohCache.ForwardDnssec (DnsWatchDnssecForwarder), assembles
// each domain and host into dnssec_chain's form, uncompressed and canonical, and validates it with SMTP's validator
// (smtp_dnssec_chain.go), which trusts nothing but the chain, the anchors and the clock. Anything it cannot fetch,
// parse, validate or bound answers false, the closed direction: a message without the claim is ordinary mail. Until
// C20 lands in connect nothing implements the forwarder, so the daemon attaches no validator and StrictChain answers
// false.
//
// Off sidecar_http, with SMTP's validator: a page Worker receives no mail. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// C20's DohCache.ForwardDnssec (QD-145): Forward's raw RFC 8484 answer to qType for domain, with EDNS0's DO bit set
// so the answer carries RRSIGs and denials. The domain comes without its final dot, and the root as ".". usable is
// false for no answer. Safe for concurrent use.
type DnsWatchDnssecForwarder interface {
	ForwardDnssec(ctx context.Context, qType dnsmessage.Type, domain string) (response []byte, usable bool)
}

// How much one StrictChain check may cost. Every number must be positive.
type DnsWatchStrictSettings struct {
	// The recipient domains one message's check takes; past it the check claims nothing. A strict Team's own domains
	// are few.
	RecipientDomainMaxCount int
	// The MX hosts one recipient domain may list.
	MxHostMaxCount int
	// The queries one check may send: §15.5's dns row's 64 a message.
	QueryMaxCount int
	// The zone cuts from a name up to the root.
	ZoneMaxDepth int
	// One query's deadline: §15.5's 5 s.
	LookupTimeout time.Duration
	// The bounds each assembled chain is held to: SMTP's dnssec_chain bounds, the CNAME hops at a TLSA name among
	// them.
	Dane *SmtpDaneSettings
}

// A fresh value each call.
func DefaultDnsWatchStrictSettings() *DnsWatchStrictSettings {
	return &DnsWatchStrictSettings{
		RecipientDomainMaxCount: 16,
		MxHostMaxCount:          8,
		QueryMaxCount:           64,
		ZoneMaxDepth:            16,
		LookupTimeout:           5 * time.Second,
		Dane:                    DefaultSmtpDaneSettings(),
	}
}

// Whether every bound is in range.
func (self *DnsWatchStrictSettings) valid() bool {
	return self != nil && 0 < self.RecipientDomainMaxCount && 0 < self.MxHostMaxCount && 0 < self.QueryMaxCount &&
		0 < self.ZoneMaxDepth && 0 < self.LookupTimeout && self.Dane.valid()
}

// TLSA's fields for the record §12 publishes per receiver key (RFC 6698, RFC 7218): DANE-EE, SPKI, SHA-256.
func dnsWatchTlsaValue(spkiSha256 []byte) string {
	return canonicalDnsWatchValue(DnsWatchTypeTlsa, fmt.Sprintf("%d %d %d %s",
		smtpTlsaUsageDaneEe, smtpTlsaSelectorSpki, smtpTlsaMatchingSha256, hex.EncodeToString(spkiSha256)))
}

// Whether host is a mail host as POST /dns/key-record names one: mx, or mx.<scope> with scope one host label.
func isDnsWatchMailHost(host string) bool {
	if host == "mx" {
		return true
	}
	scope, ok := strings.CutPrefix(host, "mx.")
	return ok && isDnsWatchLabel(scope)
}

// Whether label is one lowercase host label.
func isDnsWatchLabel(label string) bool {
	if label == "" || smtpDnsLabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for index := range len(label) {
		c := label[index]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// A mail host's watch refused: a host that is not mx or mx.<scope>, or a key that is no SPKI SHA-256.
var ErrDnsWatchMailHost = errors.New("dns watch: a mail host is mx or mx.<scope>, with its key's SPKI SHA-256")

// Watches host, mx or mx.<scope>, as a mail host this receiver serves with the key whose SubjectPublicKeyInfo hashes to
// spkiSha256 (see the file header): what the receiver calls once POST /dns/key-record took its TLSA. A second call
// for host replaces the key.
func (self *DnsWatch) WatchMailHost(host string, spkiSha256 []byte) error {
	host = strings.ToLower(strings.TrimSpace(host))
	if !isDnsWatchMailHost(host) || len(spkiSha256) != sha256.Size {
		return ErrDnsWatchMailHost
	}
	tlsa := dnsWatchTlsaValue(spkiSha256)
	return self.updateFile(func(file *dnsWatchFile) {
		file.MailHosts = slices.DeleteFunc(file.MailHosts, func(mailHost *dnsWatchMailHost) bool {
			return mailHost.Host == host
		})
		file.MailHosts = append(file.MailHosts, &dnsWatchMailHost{Host: host, Tlsa: tlsa})
	})
}

// Stops watching host as a mail host: the receiver stopped serving it, so its TLSA goes (I-15).
func (self *DnsWatch) UnwatchMailHost(host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	return self.updateFile(func(file *dnsWatchFile) {
		file.MailHosts = slices.DeleteFunc(file.MailHosts, func(mailHost *dnsWatchMailHost) bool {
			return mailHost.Host == host
		})
	})
}

// Watches name, <sel>._domainkey under the zone, as a DKIM selector this sidecar signs with: its TXT must be value,
// the record as published, exactly (§14.6; one selector a sending sidecar). What the sender calls once POST
// /smtp/dkim-keys took it.
func (self *DnsWatch) WatchDkimSelector(name string, value string) error {
	return self.Expect(name, DnsWatchTypeTxt, []string{value})
}

// Watches name as a retired selector, whose TXT the rotation or the removal deleted: any record there is
// unrequested. Forget drops it once the watch no longer needs to hold it.
func (self *DnsWatch) RetireDkimSelector(name string) error {
	return self.Expect(name, DnsWatchTypeTxt, nil)
}

// StrictChain's validation over a DNSSEC forwarder. Immutable, and so safe for concurrent use.
type dnsWatchStrictValidator struct {
	forwarder DnsWatchDnssecForwarder
	anchors   *SmtpDnssecAnchors
	settings  *DnsWatchStrictSettings
}

// A validator over forwarder for DnsWatchArgs.Strict. nil anchors take DefaultSmtpDnssecAnchors, and nil settings the
// defaults. A nil forwarder, or settings out of range, gives a validator that answers false.
func NewDnsWatchStrictValidator(forwarder DnsWatchDnssecForwarder, anchors *SmtpDnssecAnchors, settings *DnsWatchStrictSettings) DnsWatchStrictValidator {
	if anchors == nil {
		anchors = DefaultSmtpDnssecAnchors()
	}
	if settings == nil {
		settings = DefaultDnsWatchStrictSettings()
	}
	return &dnsWatchStrictValidator{forwarder: forwarder, anchors: anchors, settings: settings}
}

func (self *dnsWatchStrictValidator) strictChainHolds(ctx context.Context, request *dnsWatchStrictRequest) bool {
	if self.forwarder == nil || !self.settings.valid() || len(request.spkiSha256) != sha256.Size {
		return false
	}
	sniHost, ok := smtpDnsNameFromText(request.sniHost)
	if !ok || sniHost == smtpDnsRoot {
		return false
	}
	urnetworkZones := []smtpDnsName{}
	for _, text := range request.urnetworkZones {
		zone, ok := smtpDnsNameFromText(text)
		if !ok || zone == smtpDnsRoot {
			// a list that does not read holds nothing apart
			return false
		}
		urnetworkZones = append(urnetworkZones, zone)
	}
	if len(urnetworkZones) == 0 {
		return false
	}
	inUrnetworkZone := func(name smtpDnsName) bool {
		return slices.ContainsFunc(urnetworkZones, name.under)
	}
	if inUrnetworkZone(sniHost) {
		return false
	}
	domains := []smtpDnsName{}
	for _, text := range request.recipientDomains {
		domain, ok := smtpDnsNameFromText(text)
		if !ok || domain == smtpDnsRoot || inUrnetworkZone(domain) {
			return false
		}
		if !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	if len(domains) == 0 || self.settings.RecipientDomainMaxCount < len(domains) {
		return false
	}
	session := &dnsWatchChainSession{
		ctx:        ctx,
		forwarder:  self.forwarder,
		anchors:    self.anchors,
		settings:   self.settings,
		clock:      clockOrReal(request.clock),
		zoneWire:   map[smtpDnsName][]byte{},
		zoneParent: map[smtpDnsName]smtpDnsName{},
	}
	for _, domain := range domains {
		mx, hosts, ok := session.mxHosts(domain)
		if !ok || !slices.Contains(hosts, sniHost) {
			return false
		}
		for _, host := range hosts {
			if inUrnetworkZone(host) {
				return false
			}
			tlsa, owners, ok := session.tlsa(host)
			if !ok || slices.ContainsFunc(owners, inUrnetworkZone) {
				return false
			}
			result, ok := session.validate(mx, tlsa, domain, host, request.now)
			if !ok || result.Status != SmtpDnssecStatusTlsa {
				return false
			}
			if host == sniHost && !dnsWatchTlsaHoldsKey(result.TlsaRecords, request.spkiSha256) {
				return false
			}
		}
	}
	return true
}

// Whether records hold §12's 3 1 1 record of spkiSha256.
func dnsWatchTlsaHoldsKey(records []*SmtpTlsaRecord, spkiSha256 []byte) bool {
	for _, record := range records {
		if record.Usage == smtpTlsaUsageDaneEe && record.Selector == smtpTlsaSelectorSpki &&
			record.MatchingType == smtpTlsaMatchingSha256 && bytes.Equal(record.Data, spkiSha256) {
			return true
		}
	}
	return false
}

// One check's fetches: the queries spent, and each zone's keys and DS, fetched once.
type dnsWatchChainSession struct {
	ctx        context.Context
	forwarder  DnsWatchDnssecForwarder
	anchors    *SmtpDnssecAnchors
	settings   *DnsWatchStrictSettings
	clock      Clock
	queryCount int
	// each zone's DNSKEY RRset and its DS RRset, or its parent's proof of none, as chain wire
	zoneWire map[smtpDnsName][]byte
	// the zone above each, by the signer of its DS answer; the root has none
	zoneParent map[smtpDnsName]smtpDnsName
}

// One answer as a chain carries it.
type dnsWatchChainAnswer struct {
	// NXDOMAIN
	nameError bool
	// the answer and authority sections' records of the chain's types, uncompressed and canonical
	wire []byte
	rrs  []*smtpDnsRr
	// the zones whose RRSIGs are among them
	signers []smtpDnsName
}

// Whether answer holds a record of rrtype at owner.
func (self *dnsWatchChainAnswer) holds(owner smtpDnsName, rrtype uint16) bool {
	return slices.ContainsFunc(self.rrs, func(rr *smtpDnsRr) bool {
		return rr.owner == owner && rr.rrtype == rrtype
	})
}

// The target of a CNAME at owner the answer holds.
func (self *dnsWatchChainAnswer) cname(owner smtpDnsName) (smtpDnsName, bool) {
	for _, rr := range self.rrs {
		if rr.owner == owner && rr.rrtype == smtpDnsTypeCname {
			target, err := parseSmtpDnsCname(rr.rdata)
			return target, err == nil
		}
	}
	return "", false
}

// One query, within the session's budget and LookupTimeout on its clock, held to its question.
func (self *dnsWatchChainSession) fetch(rrtype uint16, name smtpDnsName) (*dnsWatchChainAnswer, bool) {
	if self.settings.QueryMaxCount <= self.queryCount {
		return nil, false
	}
	self.queryCount += 1
	response, usable := func() ([]byte, bool) {
		lookupCtx, cancel := context.WithCancel(self.ctx)
		defer cancel()
		stop := self.clock.AfterFunc(self.settings.LookupTimeout, cancel)
		defer stop()
		response, usable := self.forwarder.ForwardDnssec(lookupCtx, dnsmessage.Type(rrtype), dnsWatchDomainText(name))
		return response, usable && lookupCtx.Err() == nil
	}()
	if !usable {
		return nil, false
	}
	return parseDnsWatchChainAnswer(response, rrtype, name, self.settings.Dane)
}

// domain's MX hosts, as its MX answer lists them, and that answer. A domain with no MX RRset is its own host (RFC
// 5321 §5.1's implicit MX). false for a domain that does not exist, an alias, a null MX (RFC 7505), an unsigned
// answer or one past the bounds.
func (self *dnsWatchChainSession) mxHosts(domain smtpDnsName) (*dnsWatchChainAnswer, []smtpDnsName, bool) {
	answer, ok := self.fetch(smtpDnsTypeMx, domain)
	if !ok || answer.nameError || len(answer.signers) == 0 {
		return nil, nil, false
	}
	hosts := []smtpDnsName{}
	for _, rr := range answer.rrs {
		if rr.owner != domain {
			continue
		}
		switch rr.rrtype {
		case smtpDnsTypeCname:
			return nil, nil, false
		case smtpDnsTypeMx:
			exchange, err := parseSmtpDnsMx(rr.rdata)
			if err != nil || exchange == smtpDnsRoot {
				return nil, nil, false
			}
			if !slices.Contains(hosts, exchange) {
				hosts = append(hosts, exchange)
			}
		}
	}
	if len(hosts) == 0 {
		hosts = []smtpDnsName{domain}
	}
	if self.settings.MxHostMaxCount < len(hosts) {
		return nil, nil, false
	}
	return answer, hosts, true
}

// host's TLSA answers at port 25, following CNAMEs within the chain's bound, and every owner on the way. false where
// the names lead to no TLSA RRset, which leaves DANE out, or an answer is unsigned or past the bounds.
func (self *dnsWatchChainSession) tlsa(host smtpDnsName) ([]*dnsWatchChainAnswer, []smtpDnsName, bool) {
	name := host.child("_tcp").child("_25")
	owners := []smtpDnsName{name}
	answers := []*dnsWatchChainAnswer{}
	var answer *dnsWatchChainAnswer
	for {
		if answer == nil {
			fetched, ok := self.fetch(smtpDnsTypeTlsa, name)
			if !ok || fetched.nameError || len(fetched.signers) == 0 {
				return nil, nil, false
			}
			answer = fetched
			answers = append(answers, answer)
		}
		if answer.holds(name, smtpDnsTypeTlsa) {
			return answers, owners, true
		}
		target, ok := answer.cname(name)
		if !ok || self.settings.Dane.MaxCnameDepth < len(owners) {
			return nil, nil, false
		}
		name = target
		owners = append(owners, name)
		if !answer.holds(name, smtpDnsTypeTlsa) && !answer.holds(name, smtpDnsTypeCname) {
			// a resolver that did not chase the CNAME: ask for its target
			answer = nil
		}
	}
}

// Fetches zone's DNSKEY RRset and its DS RRset, or its parent's proof of none, and so on up to the root's DNSKEY
// RRset, each zone once. false where one cannot be fetched, a DS answer is signed by no zone above, or the path runs
// past ZoneMaxDepth.
func (self *dnsWatchChainSession) material(zone smtpDnsName) bool {
	for depth := 0; ; depth += 1 {
		if _, ok := self.zoneWire[zone]; ok {
			return true
		}
		if self.settings.ZoneMaxDepth < depth {
			return false
		}
		keys, ok := self.fetch(smtpDnsTypeDnskey, zone)
		if !ok || keys.nameError {
			return false
		}
		if zone == smtpDnsRoot {
			self.zoneWire[zone] = keys.wire
			return true
		}
		ds, ok := self.fetch(smtpDnsTypeDs, zone)
		if !ok {
			return false
		}
		// the zone that holds zone's DS, or proves it has none, signs that answer: the nearest strictly above
		parent := smtpDnsName("")
		for _, signer := range ds.signers {
			if signer != zone && zone.under(signer) && (parent == "" || signer.under(parent)) {
				parent = signer
			}
		}
		if parent == "" {
			return false
		}
		self.zoneWire[zone] = append(slices.Clone(keys.wire), ds.wire...)
		self.zoneParent[zone] = parent
		zone = parent
	}
}

// domain's MX answer and host's TLSA answers with every zone's material on their signers' paths, as one dnssec_chain,
// validated for domain and host at now.
func (self *dnsWatchChainSession) validate(mx *dnsWatchChainAnswer, tlsa []*dnsWatchChainAnswer, domain smtpDnsName, host smtpDnsName, now time.Time) (*SmtpDnssecResult, bool) {
	chain := slices.Clone(mx.wire)
	signers := slices.Clone(mx.signers)
	for _, answer := range tlsa {
		chain = append(chain, answer.wire...)
		signers = append(signers, answer.signers...)
	}
	added := map[smtpDnsName]bool{}
	for _, signer := range signers {
		if !self.material(signer) {
			return nil, false
		}
		zone := signer
		for !added[zone] {
			added[zone] = true
			chain = append(chain, self.zoneWire[zone]...)
			parent, ok := self.zoneParent[zone]
			if !ok {
				break
			}
			zone = parent
		}
	}
	parsed, err := ParseSmtpDnssecChain(chain, self.settings.Dane)
	if err != nil {
		return nil, false
	}
	result, err := parsed.Validate(self.anchors, now, dnsWatchDomainText(domain), dnsWatchDomainText(host))
	if err != nil {
		return nil, false
	}
	return result, true
}

// response held to its question, NOERROR or NXDOMAIN, its answer and authority records of the chain's types in
// dnssec_chain's form. Anything else, or a record of those types that does not encode, is no answer.
func parseDnsWatchChainAnswer(response []byte, rrtype uint16, name smtpDnsName, dane *SmtpDaneSettings) (*dnsWatchChainAnswer, bool) {
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil || !header.Response || header.Truncated {
		return nil, false
	}
	switch header.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	default:
		return nil, false
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || uint16(questions[0].Type) != rrtype || questions[0].Class != dnsmessage.ClassINET {
		return nil, false
	}
	if asked, ok := dnsWatchWireName(questions[0].Name); !ok || asked != name {
		return nil, false
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return nil, false
	}
	authorities, err := parser.AllAuthorities()
	if err != nil {
		return nil, false
	}
	answer := &dnsWatchChainAnswer{nameError: header.RCode == dnsmessage.RCodeNameError}
	for _, resource := range append(answers, authorities...) {
		wire, ok := dnsWatchChainRr(resource)
		if !ok {
			return nil, false
		}
		answer.wire = append(answer.wire, wire...)
	}
	answer.rrs, err = parseSmtpDnsRrs(answer.wire, dane.MaxRrCount)
	if err != nil {
		return nil, false
	}
	for _, rr := range answer.rrs {
		if rr.rrtype != smtpDnsTypeRrsig {
			continue
		}
		if signature, err := parseSmtpDnsRrsig(rr.rdata); err == nil && !slices.Contains(answer.signers, signature.signer) {
			answer.signers = append(answer.signers, signature.signer)
		}
	}
	return answer, true
}

// Whether dnssec_chain carries rrtype: the eight types smtp_dnssec_wire.go reads.
func dnsWatchChainType(rrtype uint16) bool {
	switch rrtype {
	case smtpDnsTypeMx, smtpDnsTypeCname, smtpDnsTypeTlsa, smtpDnsTypeDnskey, smtpDnsTypeDs, smtpDnsTypeNsec,
		smtpDnsTypeNsec3, smtpDnsTypeRrsig:
		return true
	}
	return false
}

// resource as one uncompressed wire record, its owner and the names in an MX's or CNAME's RDATA lowercase (RFC 4034
// §6.2): empty for a record dnssec_chain leaves out, an RRSIG over another type among them; false for one of its
// types that does not encode.
func dnsWatchChainRr(resource dnsmessage.Resource) ([]byte, bool) {
	rrtype := uint16(resource.Header.Type)
	if resource.Header.Class != dnsmessage.ClassINET || !dnsWatchChainType(rrtype) {
		return nil, true
	}
	var rdata []byte
	switch body := resource.Body.(type) {
	case *dnsmessage.MXResource:
		exchange, ok := dnsWatchWireName(body.MX)
		if !ok {
			return nil, false
		}
		rdata = append(binary.BigEndian.AppendUint16(nil, body.Pref), exchange...)
	case *dnsmessage.CNAMEResource:
		target, ok := dnsWatchWireName(body.CNAME)
		if !ok {
			return nil, false
		}
		rdata = []byte(target)
	case *dnsmessage.UnknownResource:
		if rrtype == smtpDnsTypeRrsig && (len(body.Data) < 2 || !dnsWatchChainType(binary.BigEndian.Uint16(body.Data[:2]))) {
			return nil, true
		}
		// TLSA, DNSKEY, DS, NSEC, NSEC3 and RRSIG carry no compressible name (RFC 3597 §4, RFC 4034)
		rdata = body.Data
	default:
		return nil, false
	}
	owner, ok := dnsWatchWireName(resource.Header.Name)
	if !ok || 0xffff < len(rdata) {
		return nil, false
	}
	wire := []byte(owner)
	wire = binary.BigEndian.AppendUint16(wire, rrtype)
	wire = binary.BigEndian.AppendUint16(wire, smtpDnsClassIn)
	wire = binary.BigEndian.AppendUint32(wire, resource.Header.TTL)
	wire = binary.BigEndian.AppendUint16(wire, uint16(len(rdata)))
	return append(wire, rdata...), true
}

// name as canonical uncompressed wire: ASCII lowercase, at most 255 octets in labels of at most 63, the root one zero
// octet.
func dnsWatchWireName(name dnsmessage.Name) (smtpDnsName, bool) {
	text := name.String()
	if text == "." {
		return smtpDnsRoot, true
	}
	text = strings.TrimSuffix(text, ".")
	if text == "" {
		return "", false
	}
	wire := []byte{}
	for label := range strings.SplitSeq(text, ".") {
		if label == "" || smtpDnsLabelMaxByteCount < len(label) {
			return "", false
		}
		wire = append(wire, byte(len(label)))
		for index := range len(label) {
			c := label[index]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			wire = append(wire, c)
		}
	}
	wire = append(wire, 0)
	if smtpDnsNameMaxByteCount < len(wire) {
		return "", false
	}
	return smtpDnsName(wire), true
}

// name as text without its final dot, the root as ".".
func dnsWatchDomainText(name smtpDnsName) string {
	if name == smtpDnsRoot {
		return "."
	}
	return strings.Join(name.labels(), ".")
}
