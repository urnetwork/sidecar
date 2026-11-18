// Team customers' delegated _domainkey.<domain> zones (§14.6, D-SMTP-15; plan reading 17; DNS-M9-02). A
// Team network whose verified domain (§7.6) delegates _domainkey.<domain> to the NS here has each of its
// sending sidecars' selectors answered there: <sel>._domainkey.<domain> TXT answers from the same row as
// <sel>._domainkey.<label>.<root>, which /smtp/dkim-keys writes, so §14.6's two modes publish one key once.
// A per-selector CNAME needs nothing here, since it points at that ordinary row.
//
// The delegation is one row of kind delegated at the network's label apex, <label>.<root>, of type
// DnsDelegatedType, whose rdata is each delegated apex, _domainkey.<domain>. It rides the root's journal
// and snapshots as any row does, so both NS answer a delegation from one serial, and an edge keeps
// answering it through a core outage. Who writes it, and for which domains, is SMTP-M9-34's: a verified
// domain of a Team network, through model's writer (dns_system_records_model.go).
//
// The zones are not roots. They are answered unsigned, since the customer's parent zone holds no DS for
// them, and hold nothing but their apex's SOA and NS and the selectors directly below it: no record
// outside _domainkey, no wildcard, no type but a selector's TXT. A selector answers only from a key row,
// never from <label>.<root>'s wildcard. An apex two networks' rows name answers for neither, so both NS
// agree whatever order they read the rows in; api's one-verified-domain index keeps that from happening.
// dns.yml's delegated.enabled keeps every delegated zone unanswered until it is set (v1).

package dnsservice

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// The label every delegated apex opens with: RFC 6376 §3.6.2.1's _domainkey.
const dnsDomainKeyLabel = "_domainkey"

// A delegated apex, or a delegation's row, that cannot be served.
var ErrDnsDelegatedRefused = errors.New("dns delegated zone refused")

// dns.yml's delegated: whether the edges answer the delegated zones the rows name.
type DnsDelegatedSettings struct {
	// Off, the default: a delegated row is kept, and its zones answer REFUSED as any name outside
	// the roots does, until v1's Team custom domains turn this on.
	Enabled bool `yaml:"enabled"`
}

// The delegated zones one view's rows name: each delegated apex and the label apexes whose rows name
// it. Immutable once its view is built: a build changes only an index of its own generation.
type DelegatedZones struct {
	// The build that may change this one in place.
	generation uint64
	// By delegated apex, the label apexes naming it, sorted.
	apexLabels map[string][]string
}

// The index change makes of this one: before's apexes no longer named by owner, after's named by it.
// before or after may be nil, for a row added or removed. A change at another build's generation
// copies the index first, since an older view still reads it.
func (self *DelegatedZones) change(generation uint64, owner string, before *zoneRrset, after *zoneRrset) *DelegatedZones {
	next := self
	if next == nil || next.generation != generation {
		next = &DelegatedZones{generation: generation, apexLabels: map[string][]string{}}
		if self != nil {
			for apex, labels := range self.apexLabels {
				next.apexLabels[apex] = slices.Clone(labels)
			}
		}
	}
	if before != nil {
		for _, apex := range before.set.Rdata {
			labels := slices.DeleteFunc(next.apexLabels[apex], func(label string) bool { return label == owner })
			if len(labels) == 0 {
				delete(next.apexLabels, apex)
			} else {
				next.apexLabels[apex] = labels
			}
		}
	}
	if after != nil {
		for _, apex := range after.set.Rdata {
			labels := next.apexLabels[apex]
			if index, found := slices.BinarySearch(labels, owner); !found {
				next.apexLabels[apex] = slices.Insert(labels, index, owner)
			}
		}
	}
	return next
}

// The delegated zone name is in, nearest first: its apex and the label apex whose _domainkey answers
// it. False for a name in no delegated zone here, or in one two networks' rows name. name is canonical.
func (self *DelegatedZones) Lookup(name string) (apex string, labelApex string, ok bool) {
	if self == nil || len(self.apexLabels) == 0 {
		return "", "", false
	}
	for offset, end := 0, false; !end; offset, end = dns.NextLabel(name, offset) {
		suffix := name[offset:]
		if !strings.HasPrefix(suffix, dnsDomainKeyLabel+".") {
			continue
		}
		labels, held := self.apexLabels[suffix]
		if !held {
			continue
		}
		if len(labels) != 1 {
			return "", "", false
		}
		return suffix, labels[0], true
	}
	return "", "", false
}

// Every delegated apex named, sorted, those two networks name included.
func (self *DelegatedZones) Apexes() []string {
	if self == nil {
		return []string{}
	}
	apexes := make([]string, 0, len(self.apexLabels))
	for apex := range self.apexLabels {
		apexes = append(apexes, apex)
	}
	slices.Sort(apexes)
	return apexes
}

// The delegated zones this view's rows name. Never nil.
func (self *ZoneView) Delegated() *DelegatedZones {
	if self.delegated == nil {
		return &DelegatedZones{apexLabels: map[string][]string{}}
	}
	return self.delegated
}

// Whether each of a delegated row's rdata is a delegated apex outside root, once each.
func validateDnsDelegatedApexes(root string, apexes []string) error {
	if len(apexes) == 0 {
		return errors.New("it names no apex")
	}
	for index, apex := range apexes {
		if err := validateDnsDelegatedApex(apex); err != nil {
			return err
		}
		if dns.IsSubDomain(root, apex) || dns.IsSubDomain(apex, root) {
			return fmt.Errorf("apex %q is at or below %s, which is a root", apex, root)
		}
		if slices.Contains(apexes[:index], apex) {
			return fmt.Errorf("apex %q twice", apex)
		}
	}
	return nil
}

// Whether apex is _domainkey.<domain>. canonical, domain a dotted name of host labels.
func validateDnsDelegatedApex(apex string) error {
	domain, ok := strings.CutPrefix(apex, dnsDomainKeyLabel+".")
	if !ok || !isCanonicalDnsName(apex) {
		return fmt.Errorf("apex %q is not a canonical _domainkey.<domain>", apex)
	}
	if err := validateDnsRoot(domain); err != nil {
		return fmt.Errorf("apex %q: %v", apex, err)
	}
	return nil
}

// The apex of domain's delegated zone, _domainkey.<domain>., canonical: domain a dotted name of host
// labels of a customer's own, so at or below none of settings' roots and no reverse zone, and not one
// above them either.
func DnsDelegatedApex(settings *DnsSettings, domain string) (string, error) {
	apex := dns.CanonicalName(dnsDomainKeyLabel + "." + strings.TrimSuffix(domain, "."))
	if err := validateDnsDelegatedApex(apex); err != nil {
		return "", fmt.Errorf("%w: %w", ErrDnsDelegatedRefused, err)
	}
	for _, root := range settings.Roots {
		if dns.IsSubDomain(root, apex) || dns.IsSubDomain(apex, root) {
			return "", fmt.Errorf("%w: %s overlaps the root %s", ErrDnsDelegatedRefused, apex, root)
		}
	}
	for _, zone := range settings.Reverse.Zones {
		if dns.IsSubDomain(zone.Zone, apex) || dns.IsSubDomain(apex, zone.Zone) {
			return "", fmt.Errorf("%w: %s overlaps the reverse zone %s", ErrDnsDelegatedRefused, apex, zone.Zone)
		}
	}
	return apex, nil
}

// The row that delegates each domain's _domainkey zone to the network zone at labelApex, <label>.<root>:
// kind delegated, its rdata the apexes sorted, each once. Refuses a labelApex not directly below root, a
// domain at or above root, and a domain DnsDelegatedApex refuses by settings' roots and reverse zones. Its
// TTL means nothing, since the row answers nothing itself.
func NewDnsDelegatedRow(settings *DnsSettings, root string, labelApex string, domains []string) (*DnsRecordSet, error) {
	if _, ok := dnsLabelBelowRoot(root, labelApex); !ok {
		return nil, fmt.Errorf("%w: %s is not a label apex of %s", ErrDnsDelegatedRefused, labelApex, root)
	}
	apexes := []string{}
	for _, domain := range domains {
		apex, err := DnsDelegatedApex(settings, domain)
		if err != nil {
			return nil, err
		}
		apexes = append(apexes, apex)
	}
	slices.Sort(apexes)
	apexes = slices.Compact(apexes)
	set := &DnsRecordSet{Owner: labelApex, Type: DnsDelegatedType, Ttl: settings.Ttl.Ns, Kind: DnsRecordKindDelegated, Rdata: apexes}
	if err := set.Validate(root); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsDelegatedRefused, err)
	}
	return set, nil
}

// The answer to query in the delegated zone at apex, whose selectors view's labelApex answers, unsigned
// (see the file header): SOA and NS at the apex; at <sel>.<apex>, the TXT of <sel>._domainkey.<labelApex>'s
// key row, NODATA for any other type, NXDOMAIN with no key row; NXDOMAIN for every other name. nil for a
// response, as Answer gives.
func AnswerDelegated(query *DnsQuery, view *ZoneView, apex string, labelApex string) *dns.Msg {
	settings := view.settings
	soa := dnsUnsignedSoa(settings, apex, uint32(view.serial))
	zone := &dnsUnsignedZone{
		apex: apex,
		soa:  soa,
		ns:   dnsUnsignedNs(settings, apex),
		lookup: func(name string) (map[uint16][]dns.RR, bool) {
			selector, rest, ok := strings.Cut(name, ".")
			if !ok || rest != apex || selector == "" {
				return nil, false
			}
			node := view.names.get(selector + "." + dnsDomainKeyLabel + "." + labelApex)
			if node == nil || node.withheldOwner() {
				return nil, false
			}
			rrset := node.rrset(dns.TypeTXT)
			if rrset == nil || rrset.set.Kind != DnsRecordKindKey {
				return nil, false
			}
			return map[uint16][]dns.RR{dns.TypeTXT: rrset.records}, true
		},
	}
	return answerUnsignedZone(query, settings, zone)
}
