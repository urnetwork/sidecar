//go:build !sidecar_http && !ios_extension && !js

// smtpedge's DNSSEC resolver. Each lookup verifies its own answer or a parent's proof of an unsigned
// delegation. MX and TLSA return the same evidence that was checked, for the sending device to verify.
package sidecar

import (
	"cmp"
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
)

// A process-owned resolver using the DNSSEC-OK transport. Safe for concurrent use.
type SmtpMxDnsResolver struct {
	forwarder DnsWatchDnssecForwarder
	anchors   *SmtpDnssecAnchors
	settings  *DnsWatchStrictSettings
	clock     Clock
}

// Uses the release's root anchors and lookup bounds unless supplied by the host.
func NewSmtpMxDnsResolver(forwarder DnsWatchDnssecForwarder, anchors *SmtpDnssecAnchors, settings *DnsWatchStrictSettings, clock Clock) *SmtpMxDnsResolver {
	if anchors == nil {
		anchors = DefaultSmtpDnssecAnchors()
	}
	if settings == nil {
		settings = DefaultDnsWatchStrictSettings()
	}
	return &SmtpMxDnsResolver{forwarder: forwarder, anchors: anchors, settings: settings, clock: clockOrReal(clock)}
}

// A terminal answer and its canonical owner after any authenticated aliases.
type smtpMxDnsLookup struct {
	owner     smtpDnsName
	records   []*smtpDnsRr
	secure    bool
	nameError bool
	chain     []byte
}

// Checks one answer using the signers' material. For an unsigned answer the parent must prove an insecure
// delegation on the path. An omitted signature in a signed zone can never select the unsigned path.
func (self *dnsWatchChainSession) verifyMxAnswer(name smtpDnsName, rrtype uint16, answer *dnsWatchChainAnswer) (*smtpDnssecAnswer, []byte, error) {
	prove := func(wire []byte, signers []smtpDnsName) (*smtpDnssecAnswer, []byte, error) {
		chain, ok := self.withZoneMaterial(slices.Clone(wire), signers)
		if !ok {
			return nil, nil, ErrSmtpMxTemporary
		}
		parsed, err := parseSmtpLookupChain(chain, self.settings.Dane, self.extraType)
		if err != nil {
			return nil, nil, ErrSmtpMxBogus
		}
		validator := parsed.validator(self.anchors, self.clock.Now())
		verified, err := validator.lookup(name, rrtype)
		if err != nil {
			return nil, nil, ErrSmtpMxBogus
		}
		if answer.nameError && !verified.insecure && verified.cname == "" &&
			(!verified.absent || !validator.provenNameAbsent(validator.zoneOf(name), name)) {
			return nil, nil, ErrSmtpMxBogus
		}
		return verified, chain, nil
	}
	if len(answer.signers) > 0 {
		if result, chain, err := prove(answer.wire, answer.signers); err == nil || err == ErrSmtpMxTemporary {
			return result, chain, err
		}
	}
	// The DS question at the unsigned zone cut is answered by the secure parent. Walk down from the
	// root until such a denial validates. Unrelated denials or DS records cannot prove this cut.
	for depth := 1; depth <= name.labelCount() && depth <= self.settings.ZoneMaxDepth; depth++ {
		ds, ok := self.fetch(smtpDnsTypeDs, name.suffix(depth))
		if !ok {
			return nil, nil, ErrSmtpMxTemporary
		}
		if len(ds.signers) == 0 {
			continue
		}
		result, _, err := prove(ds.wire, ds.signers)
		if err == nil && result.insecure {
			return result, nil, nil
		}
		if err == ErrSmtpMxTemporary {
			return nil, nil, err
		}
	}
	return nil, nil, ErrSmtpMxBogus
}

// Follows only aliases from the requested owner, validating each hop independently within the same budget.
func (self *SmtpMxDnsResolver) lookup(ctx context.Context, text string, rrtype uint16) (*smtpMxDnsLookup, error) {
	name, ok := smtpDnsNameFromText(text)
	if !ok || name == smtpDnsRoot || self.forwarder == nil || !self.settings.valid() {
		return nil, ErrSmtpMxTemporary
	}
	session := &dnsWatchChainSession{ctx: ctx, forwarder: self.forwarder, anchors: self.anchors,
		settings: self.settings, clock: self.clock, zoneWire: map[smtpDnsName][]byte{}, zoneParent: map[smtpDnsName]smtpDnsName{}}
	if !dnsWatchChainType(rrtype) {
		session.extraType = rrtype
	}
	result := &smtpMxDnsLookup{secure: true}
	for range self.settings.Dane.MaxCnameDepth + 1 {
		answer, ok := session.fetch(rrtype, name)
		if !ok {
			return nil, ErrSmtpMxTemporary
		}
		verified, chain, err := session.verifyMxAnswer(name, rrtype, answer)
		if err != nil {
			return nil, err
		}
		result.secure = result.secure && !verified.insecure
		if result.secure {
			if self.settings.Dane.MaxChainByteCount-len(result.chain) < len(chain) {
				return nil, ErrSmtpMxTemporary
			}
			result.chain = append(result.chain, chain...)
		} else {
			result.chain = nil
		}
		target := verified.cname
		for _, rr := range answer.rrs[:answer.answerCount] {
			if rr.owner != name {
				continue
			}
			switch rr.rrtype {
			case rrtype:
				result.records = append(result.records, rr)
			case smtpDnsTypeCname:
				alias, _ := parseSmtpDnsCname(rr.rdata)
				if !verified.insecure && verified.cname != alias || target != "" && target != alias {
					return nil, ErrSmtpMxBogus
				}
				target = alias
			}
		}
		if target != "" {
			if len(result.records) != 0 {
				return nil, ErrSmtpMxBogus
			}
			name = target
			continue
		}
		result.nameError = answer.nameError
		if !verified.insecure {
			if (verified.rrset != nil) != (len(result.records) != 0) {
				return nil, ErrSmtpMxBogus
			}
			if verified.rrset != nil {
				result.records = verified.rrset.rrs
			}
		}
		result.owner = name
		return result, nil
	}
	return nil, ErrSmtpMxBogus
}

// Recipient domain's explicit MX, null MX or address fallback.
func (self *SmtpMxDnsResolver) LookupMx(ctx context.Context, domain string) (*SmtpMxAnswer, error) {
	lookup, err := self.lookup(ctx, domain, smtpDnsTypeMx)
	if err != nil {
		return nil, err
	}
	if lookup.nameError {
		return nil, ErrSmtpMxNoSuchDomain
	}
	answer := &SmtpMxAnswer{Secure: lookup.secure, Chain: lookup.chain}
	for _, rr := range lookup.records {
		exchange, _ := parseSmtpDnsMx(rr.rdata)
		pref := binary.BigEndian.Uint16(rr.rdata)
		if exchange == smtpDnsRoot {
			if pref != 0 || len(lookup.records) != 1 {
				return nil, ErrSmtpMxBogus
			}
			answer.NullMx = true
		} else {
			answer.Hosts = append(answer.Hosts, &SmtpMxHost{Preference: pref, Host: dnsWatchDomainText(exchange)})
		}
	}
	original, _ := smtpDnsNameFromText(domain)
	if len(lookup.records) == 0 && lookup.owner != original {
		answer.Hosts = []*SmtpMxHost{{Host: dnsWatchDomainText(lookup.owner)}}
	}
	slices.SortStableFunc(answer.Hosts, func(a, b *SmtpMxHost) int { return cmp.Compare(a.Preference, b.Preference) })
	return answer, nil
}

// Port 25's TLSA RRset or denial and its evidence.
func (self *SmtpMxDnsResolver) LookupTlsa(ctx context.Context, host string) (*SmtpTlsaAnswer, error) {
	lookup, err := self.lookup(ctx, "_25._tcp."+host, smtpDnsTypeTlsa)
	if err != nil {
		return nil, err
	}
	answer := &SmtpTlsaAnswer{Secure: lookup.secure, Chain: lookup.chain}
	for _, rr := range lookup.records {
		record, _ := parseSmtpDnsTlsa(rr.rdata)
		answer.Records = append(answer.Records, record)
	}
	return answer, nil
}

// A and AAAA of the canonical host. The edge applies its destination address policy separately.
func (self *SmtpMxDnsResolver) LookupAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	var addresses []netip.Addr
	for _, rrtype := range []uint16{smtpDnsTypeA, smtpDnsTypeAaaa} {
		lookup, err := self.lookup(ctx, host, rrtype)
		if err != nil {
			return nil, err
		}
		if lookup.nameError {
			return nil, ErrSmtpMxNoSuchDomain
		}
		for _, rr := range lookup.records {
			ip, _ := netip.AddrFromSlice(rr.rdata)
			addresses = append(addresses, ip)
		}
	}
	return addresses, nil
}

// The sending address's reverse names for the edge's forward-confirmation check.
func (self *SmtpMxDnsResolver) LookupPtr(ctx context.Context, address netip.Addr) ([]string, error) {
	if !address.IsValid() {
		return nil, ErrSmtpMxTemporary
	}
	lookup, err := self.lookup(ctx, mailReverseName(address), smtpDnsTypePtr)
	if err != nil {
		return nil, err
	}
	if lookup.nameError {
		return nil, ErrSmtpMxNoSuchDomain
	}
	var names []string
	for _, rr := range lookup.records {
		target, _ := parseSmtpDnsCname(rr.rdata)
		names = append(names, dnsWatchDomainText(target))
	}
	return names, nil
}
