// Copy rows (DNS-M5-02; D-DNS-6, D-DNS-11, §12.7): an owner that exists only because a write gave it a
// child is an empty non-terminal, and an empty non-terminal blocks the wildcard above it (RFC 4592
// §2.2), so blog stops answering from * the moment _sip._tcp.blog is written. Each such owner holds one
// copy row, which a ZoneView answers with the wildcard's current records and TTLs (answer.go), so a
// write to * or a health drop reaches it with no further write. The copy is added in the write that
// makes the empty non-terminal and dropped in the write that ends it, by a child's removal or by the
// owner gaining records of its own. A replying burner's <blabel>, given a child by its first DKIM
// selector, is one such owner (D-DNS-11), and M9's writers plan through this same function.
//
// A copy also stands at an owner whose only rows are canaries: a strong-mode probe's CAA (§12.8) makes
// its host exist, and the copy keeps the host's addresses answering from * while the probe runs.

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

// The copy rows a write must add and delete so that, once it commits, every owner strictly below apex
// that is an empty non-terminal, or holds nothing but canaries, and that a wildcard would answer were
// it absent, holds one copy row, and no other owner below apex holds one. rows is what the write
// leaves: the zone's rows with the write's own upserts and deletes applied, copy rows included. Rows
// outside apex are neither read nor planned.
//
// Which wildcard would answer is answer.go's copySource, applied here to the rows: up from the owner,
// past names that exist only for their children, to the first *.<ancestor> that holds rows, stopping
// at an ancestor with rows of its own or at apex. Copy rows hold no addresses, so they are planned
// alike whatever * holds. Both lists are in owner order.
func PlanCopyRows(apex string, rows []DnsRecordSet) (upserts []DnsRecordSet, deletes []DnsRecordKey) {
	apex = dns.CanonicalName(apex)
	// below apex: every owner that holds a row other than a copy, and whether all its rows are canaries
	ownCanaryOnly := map[string]bool{}
	copyOwners := map[string]bool{}
	for _, row := range rows {
		owner := dns.CanonicalName(row.Owner)
		if owner == apex || !dns.IsSubDomain(apex, owner) {
			continue
		}
		if row.Kind == DnsRecordKindCopy {
			copyOwners[owner] = true
			continue
		}
		canaryOnly, held := ownCanaryOnly[owner]
		ownCanaryOnly[owner] = (!held || canaryOnly) && row.Kind == DnsRecordKindCanary
	}
	// every name strictly between apex and an owner with rows of its own: the empty non-terminals
	// unless they hold rows themselves
	parentNames := map[string]bool{}
	for owner := range ownCanaryOnly {
		for name := dnsParentName(owner); name != apex && name != ""; name = dnsParentName(name) {
			parentNames[name] = true
		}
	}
	holdsOwnRows := func(name string) bool {
		_, held := ownCanaryOnly[name]
		return held
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
	wantCopies := map[string]bool{}
	for name := range parentNames {
		if !holdsOwnRows(name) && covered(name) {
			wantCopies[name] = true
		}
	}
	for owner, canaryOnly := range ownCanaryOnly {
		if canaryOnly && covered(owner) {
			wantCopies[owner] = true
		}
	}
	for owner := range wantCopies {
		if !copyOwners[owner] {
			upserts = append(upserts, DnsRecordSet{Owner: owner, Type: DnsCopyType, Kind: DnsRecordKindCopy})
		}
	}
	for owner := range copyOwners {
		if !wantCopies[owner] {
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
