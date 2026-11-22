// Copy rows (DNS-M5-02; D-DNS-6, D-DNS-11, §12.7; QD-1190): any owner that exists blocks the wildcard
// above it (RFC 4592 §2.2), so a name stops answering from * the moment it holds a record of its own or
// a child. blog stops when _sip._tcp.blog is written, and so does web, a published host whose addresses
// come only from *, when a site-verification TXT is written at web itself, which would leave its
// visitors and a weak-mode custom host's CNAME to it (§12.8) with no address. So each such owner whose
// own rows hold no A, AAAA or CNAME holds one copy row, which a ZoneView answers with the wildcard's
// current records and TTLs for every type the owner holds none of (answer.go), so a write to * or a
// health drop reaches it with no further write. An owner with addresses of its own keeps only those, and
// one with a CNAME takes no copy, since nothing stands beside a CNAME (RFC 2181 §10.1; LintZoneWrite).
//
// The copy is added in the write that makes the owner need it and dropped in the write that ends the
// need: the owner's last row and last child gone, or an address or CNAME of its own written. Empty
// non-terminals, a replying burner's <blabel> and _domainkey.<blabel> (D-DNS-11), a strong-mode probe's
// CAA canary at its host (§12.8), and a user's TXT, MX or SRV at a host are all such owners, and M9's
// writers plan through this same function.
//
// Two kinds of owner keep what they hold:
//   - A Team scope's apex, one label below the zone's apex (owner decisions 40, 58), is a zone apex of its
//     own, whose set writes *.<scope>. Like the zone's apex it takes no copy, so its addresses are its
//     own @'s, there while the scope's apex is published (owner decision 335), and its existing stops the
//     network's wildcard there as zone_scope.go says.
//   - A suspension's withheld owner, and every name at or below it, keeps the copy rows it holds, neither
//     added nor removed, so no write lands under a suspension and Restore puts back exactly what stood
//     (§12.9).

package dnsservice

import (
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// The parent of a canonical name, or "" for the root.
func dnsParentName(name string) string {
	if name == "." {
		return ""
	}
	_, parent, _ := strings.Cut(name, ".")
	if parent == "" {
		return "."
	}
	return parent
}

// Whether a row of rrType keeps its owner from taking a copy: an address of its own, which it answers
// alone, or a CNAME, beside which nothing stands.
func dnsCopyBlockingType(rrType uint16) bool {
	return rrType == dns.TypeA || rrType == dns.TypeAAAA || rrType == dns.TypeCNAME
}

// The copy rows a write must add and delete so that, once it commits, every owner strictly below apex
// that exists, whose own rows hold no A, AAAA or CNAME, and that a wildcard would answer were it absent,
// holds one copy row, and no other owner below apex holds one (see the file header): an owner exists
// while it holds a row other than a copy or has such an owner below it, as an empty non-terminal does.
// A Team scope's apex holds none, and at and below a withheld owner nothing is planned. rows is what the
// write leaves as edges will serve it: the zone's rows with the write's own upserts and deletes applied,
// copy rows included, and rows a suspension or a downgrade withholds left out. Rows outside apex are
// neither read nor planned.
//
// Which wildcard would answer is answer.go's copySource, applied here to the rows: up from the owner,
// past names that exist only for their children, to the first *.<ancestor> that holds rows, stopping
// at an ancestor with rows of its own or at apex. Copy rows hold no addresses, so they are planned
// alike whatever * holds. Both lists are in owner order.
func PlanCopyRows(apex string, rows []DnsRecordSet) (upserts []DnsRecordSet, deletes []DnsRecordKey) {
	apex = dns.CanonicalName(apex)
	// below apex: every owner that holds a row other than a copy, and whether one of its rows keeps it
	// from a copy; at or below apex, every withheld owner; and the scope sets' wildcards
	ownBlocked := map[string]bool{}
	copyOwners := map[string]bool{}
	withheldOwners := map[string]bool{}
	systemWildcards := map[string]bool{}
	for _, row := range rows {
		owner := dns.CanonicalName(row.Owner)
		if !dns.IsSubDomain(apex, owner) {
			continue
		}
		if row.Kind == DnsRecordKindWithheld {
			withheldOwners[owner] = true
		}
		if owner == apex {
			continue
		}
		if row.Kind == DnsRecordKindCopy {
			copyOwners[owner] = true
			continue
		}
		ownBlocked[owner] = ownBlocked[owner] || dnsCopyBlockingType(row.Type)
		if row.Kind == DnsRecordKindSystem && strings.HasPrefix(owner, "*.") {
			systemWildcards[owner] = true
		}
	}
	holdsOwnRows := func(name string) bool {
		_, held := ownBlocked[name]
		return held
	}
	// every name that exists: the owners with rows of their own and each name strictly between apex
	// and one of them, an empty non-terminal unless it holds rows itself
	names := map[string]bool{}
	for owner := range ownBlocked {
		names[owner] = true
		for name := dnsParentName(owner); name != apex && name != ""; name = dnsParentName(name) {
			names[name] = true
		}
	}
	covered := func(name string) bool {
		for ancestor := dnsParentName(name); ancestor != ""; ancestor = dnsParentName(ancestor) {
			if wildcard := "*." + ancestor; wildcard != name && holdsOwnRows(wildcard) {
				return true
			}
			if ancestor == apex || holdsOwnRows(ancestor) {
				return false
			}
		}
		return false
	}
	// a Team scope's apex: directly below apex, with its set's system rows at its own wildcard
	scopeApex := func(name string) bool {
		return dnsParentName(name) == apex && systemWildcards["*."+name]
	}
	// at or below a withheld owner, apex's included: what a suspension holds
	suspended := func(name string) bool {
		for ancestor := name; ancestor != ""; ancestor = dnsParentName(ancestor) {
			if withheldOwners[ancestor] {
				return true
			}
			if ancestor == apex {
				return false
			}
		}
		return false
	}
	wantCopies := map[string]bool{}
	for name := range names {
		if !ownBlocked[name] && !scopeApex(name) && covered(name) {
			wantCopies[name] = true
		}
	}
	for owner := range wantCopies {
		if !copyOwners[owner] && !suspended(owner) {
			upserts = append(upserts, DnsRecordSet{Owner: owner, Type: DnsCopyType, Kind: DnsRecordKindCopy})
		}
	}
	for owner := range copyOwners {
		if !wantCopies[owner] && !suspended(owner) {
			deletes = append(deletes, DnsRecordKey{Owner: owner, Type: DnsCopyType})
		}
	}
	slices.SortFunc(upserts, func(first DnsRecordSet, second DnsRecordSet) int { return strings.Compare(first.Owner, second.Owner) })
	slices.SortFunc(deletes, func(first DnsRecordKey, second DnsRecordKey) int { return strings.Compare(first.Owner, second.Owner) })
	return upserts, deletes
}

// rows with upserts and deletes applied, as a write leaves them: an upsert replaces the RRset at its
// key, and a delete removes it. A new slice, in rows' order with new keys after. For PlanCopyRows and
// LintZoneWrite, which read what a write leaves.
func DnsRowsAfter(rows []DnsRecordSet, upserts []DnsRecordSet, deletes []DnsRecordKey) []DnsRecordSet {
	changed := map[DnsRecordKey]bool{}
	for _, key := range deletes {
		changed[key] = true
	}
	for _, row := range upserts {
		changed[row.Key()] = true
	}
	after := []DnsRecordSet{}
	for _, row := range rows {
		if !changed[row.Key()] {
			after = append(after, row.Clone())
		}
	}
	for _, row := range upserts {
		after = append(after, row.Clone())
	}
	return after
}
