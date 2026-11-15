// Alias zones (§12.5, §12.7, D-DNS-2, D-DNS-10; DNS-M6-01). A network's opt-in alias, <alias>.<root>,
// is a copy of its label's records except challenges, with its own mx host and TLSA. One row at the
// alias's apex, kind alias, says so, and a view answers every name below the alias from the label's
// rows with the apex rewritten, in owners and in the names MX, CNAME and SRV point at: so a write to
// the label reaches the alias with no second write, mx.<alias>.<root> answers the router interfaces, and
// _25._tcp.mx.<alias>.<root> answers the label's TLSA, which names the same receiver keys.
//
// Plan reading 11. A claim writes the alias row with no rdata, which holds the apex for the alias's own
// rows alone, its challenges, so certs can prove the alias before anything else answers there. Once a
// certificate names it, DnsAliasCertifiedInTx gives the row its label's apex, and from then on the label's
// records answer. A retiring alias keeps answering until its tombstone takes the row, <root>'s CAA
// issue ";" at its apex refusing every new certificate meanwhile (D-DNS-10).
//
// The alias's own rows answer before the label's: a challenge at _acme-challenge.<alias>.<root>, the
// retiring CAA at its apex, a suspension's withheld owner. The label's challenges never answer under
// the alias, since each name proves only its own certificates; the label's names keep existing, so an
// alias name answers NODATA where the label's challenge-only name would. A name the alias holds rows at
// stops the label's wildcard, as any existing name stops a wildcard (RFC 4592 §2.2), so the alias
// answers as one zone would that held both sets.

package dnsservice

import (
	"slices"

	"github.com/miekg/dns"
)

// An alias in effect: its apex and its label's, both canonical and directly below the root.
type zoneAlias struct {
	apex   string
	target string
}

// name, at or below the alias's apex and canonical, as the label's zone holds it.
func (self *zoneAlias) toTarget(name string) string {
	return name[:len(name)-len(self.apex)] + self.target
}

// name as the alias answers it: a name at or below the label's apex moved under the alias's, anything
// else as it is.
func (self *zoneAlias) fromTarget(name string) string {
	canonical := dns.CanonicalName(name)
	if !dns.IsSubDomain(self.target, canonical) {
		return name
	}
	return canonical[:len(canonical)-len(self.target)] + self.apex
}

// The alias name is under, when one is in effect there: the name directly below the root that name
// is at or below holds an alias row naming its label's apex, and no suspension withholds it. name is
// canonical and at or below the root.
func (self *ZoneView) aliasFor(name string) *zoneAlias {
	if name == self.root {
		return nil
	}
	indexes := dns.Split(name)
	rootLabelCount := dns.CountLabel(self.root)
	if len(indexes) <= rootLabelCount {
		return nil
	}
	apex := name[indexes[len(indexes)-rootLabelCount-1]:]
	node := self.names.get(apex)
	if node == nil || node.aliasRow == nil || len(node.aliasRow.set.Rdata) == 0 || node.withheldOwner() {
		return nil
	}
	return &zoneAlias{apex: apex, target: node.aliasRow.set.Rdata[0]}
}

// What one name answers from: the search's match, in the label's zone under an alias, and under an alias
// the alias's own node at the name too.
type zoneLookup struct {
	// the node the search found; node nil when none
	match zoneMatch
	// under an alias: its own node at the name, nil when it holds none there
	own *zoneNode
	// nil when the name is under no alias in effect
	alias *zoneAlias
}

// The search for name (RFC 4592's, answer.go's match), or under an alias in effect the alias's own node
// and the label's name it maps to: that name exactly where the alias holds a node at name, else the
// label's search with its wildcard. name is canonical and at or below the root.
func (self *ZoneView) lookup(name string) zoneLookup {
	alias := self.aliasFor(name)
	if alias == nil {
		return zoneLookup{match: self.match(name)}
	}
	lookup := zoneLookup{own: self.names.get(name), alias: alias}
	target := alias.toTarget(name)
	if lookup.own != nil {
		if node := self.names.get(target); node != nil {
			lookup.match = zoneMatch{node: node, name: target}
		}
		return lookup
	}
	lookup.match = self.match(target)
	if lookup.match.node == nil || lookup.match.name == target {
		return lookup
	}
	// a wildcard answered: a name of the alias's own between it and the wildcard's parent is the closer
	// encloser, and stops it, as in one zone holding both
	wildcardParent := lookup.match.name[len("*."):]
	for ancestor := zoneParent(name); ancestor != alias.apex; ancestor = zoneParent(ancestor) {
		if self.names.get(ancestor) == nil {
			continue
		}
		if mapped := alias.toTarget(ancestor); mapped != wildcardParent && dns.IsSubDomain(wildcardParent, mapped) {
			lookup.match = zoneMatch{}
		}
		break
	}
	return lookup
}

// Whether the name exists, in the alias's own rows or the label's.
func (self *zoneLookup) exists() bool {
	return self.match.node != nil || self.own != nil
}

// Whether a suspension withholds the name: it answers no data of any type (§12.9).
func (self *zoneLookup) withheld() bool {
	return (self.own != nil && self.own.withheldOwner()) || (self.match.node != nil && self.match.node.withheldOwner())
}

// The RRset of rrType the matched node answers, leaving out a label's challenge under an alias.
func (self *zoneLookup) matchRrset(node *zoneNode, rrType uint16) *zoneRrset {
	rrset := node.rrset(rrType)
	if rrset != nil && self.alias != nil && rrset.set.Kind == DnsRecordKindChallenge {
		return nil
	}
	return rrset
}

// Whether the alias's own node holds an RRset it answers.
func (self *zoneLookup) ownAnswers() bool {
	if self.own == nil {
		return false
	}
	return slices.ContainsFunc(self.own.rrsets, func(rrset *zoneRrset) bool {
		return self.own.rrset(rrset.set.Type) != nil
	})
}

// records, the label's as answered under an alias, with every name they point at in the label's zone
// moved under the alias, so its MX names its own mx host and a CNAME or SRV stays in the alias. records
// are the answer's own copies, changed in place.
func (self *zoneLookup) aliasRecords(records []dns.RR) []dns.RR {
	if self.alias == nil {
		return records
	}
	for _, record := range records {
		switch typed := record.(type) {
		case *dns.MX:
			typed.Mx = self.alias.fromTarget(typed.Mx)
		case *dns.CNAME:
			typed.Target = self.alias.fromTarget(typed.Target)
		case *dns.SRV:
			typed.Target = self.alias.fromTarget(typed.Target)
		}
	}
	return records
}
