//go:build !sidecar_http && !ios_extension

// The network's own row as its mail and its sockets read it from the zone (§12.5's alias and retirement rows,
// D-DNS-10): the zone's label and alias, live, and each alias in its 90 days of retiring, which names the network and
// nothing else until it tombstones (I-14), with its tombstone time, so a reader that holds the row leaves the alias out
// from that time on (networkLabelRowAt). The retiring aliases are the ones the zone names, with api's times, and the
// ones the network's label table keeps for it (dns_resolve.go), the alias the table saw leave among them, as the ACL
// writer's network: label read takes them (acl_writer_subjects.go). mail_component.go binds mail's network row from
// it, which a receiver's mailcfg resolves an RCPT's zone by (MailZone.OfNetwork), and socket_host.go the resolver a
// §9.4 address's <net> goes through.

package sidecar

import (
	"context"
	"slices"
	"time"
)

// The zone the network's DnsClient answers now (DnsClient.Zone), and the network's row from it and from the network's
// label table (the file's comment). An alias both name takes the zone's tombstone time, as the table takes an
// answer's over its own (networkLabelAnsweredRow), and else the time either gives; one the zone gives live again, as
// its label or its alias, retires no more. The table opens before the zone is read, so a fetch the read makes feeds it
// first (Sidecar.NetworkLabels); a table that does not open, before enrollment or while the keychain is locked, leaves
// the zone's own retiring aliases. Errors: the zone's, with no zone, or why the zone makes no row
// (canonicalNetworkLabelRow), with the zone.
func (self *Sidecar) networkLabelZoneRow(ctx context.Context) (*DnsZone, NetworkLabelRow, error) {
	dns, err := self.Dns()
	if err != nil {
		return nil, NetworkLabelRow{}, err
	}
	labels, labelsErr := self.NetworkLabels()
	zone, err := dns.Zone(ctx)
	if err != nil {
		return nil, NetworkLabelRow{}, err
	}
	row, err := networkLabelAnswerRow(NetworkLabelRow{Root: zone.Root, NetworkId: zone.NetworkId, Label: zone.Label, Alias: zone.Alias}, zone.RetiringAliases)
	if err != nil {
		return zone, NetworkLabelRow{}, err
	}
	// a table that did not open adds nothing to the zone's own
	if labelsErr == nil {
		// the table's rows as a read now sees them, each alias past its time left out already
		for _, held := range labels.Networks() {
			if held.Root != row.Root || held.NetworkId != row.NetworkId {
				continue
			}
			for _, alias := range held.RetiringAliases {
				if !slices.Contains(row.RetiringAliases, alias) {
					row.RetiringAliases = append(row.RetiringAliases, alias)
				}
				tombstoneTime, timed := held.RetiringAliasTombstoneTimes[alias]
				if _, answered := row.RetiringAliasTombstoneTimes[alias]; !timed || answered {
					continue
				}
				if row.RetiringAliasTombstoneTimes == nil {
					row.RetiringAliasTombstoneTimes = map[string]time.Time{}
				}
				row.RetiringAliasTombstoneTimes[alias] = tombstoneTime
			}
		}
	}
	row.RetiringAliases = slices.DeleteFunc(row.RetiringAliases, func(alias string) bool {
		return alias == row.Label || alias == row.Alias
	})
	// sorted again, and a time kept only for an alias still retiring
	row, err = canonicalNetworkLabelRow(row)
	if err != nil {
		return zone, NetworkLabelRow{}, err
	}
	return zone, row, nil
}
