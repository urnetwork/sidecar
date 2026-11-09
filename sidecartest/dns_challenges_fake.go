// T2's dnsservice.DnsChallengeWriter: certs' challenge TXT written straight through a DnsStore, one write a
// call, so a test drives POST acme-challenge to edges with no Postgres. It holds a write to the shape
// of a challenge and no more: server's model.DnsPutChallenge keeps the hourly cap, the live-label rule
// and the lint, which run on .stack/server-test.sh. Safe for concurrent use.

package sidecartest

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar/dnsservice"
)

// The fake writer over store.
type FakeDnsChallenges struct {
	store dnsservice.DnsStore
}

func NewFakeDnsChallenges(store dnsservice.DnsStore) *FakeDnsChallenges {
	return &FakeDnsChallenges{store: store}
}

// Writes the values at _acme-challenge.<name>, or takes them out with none: a name outside root or more
// than two values is refused, as the model refuses them.
func (self *FakeDnsChallenges) PutChallenge(ctx context.Context, root string, name string, values []string, ttl uint32) (uint64, error) {
	name = strings.TrimPrefix(dns.CanonicalName(name), "*.")
	if name == root || !dns.IsSubDomain(root, name) || 2 < len(values) {
		return 0, fmt.Errorf("%w: %s", dnsservice.ErrDnsChallengeRefused, name)
	}
	owner := "_acme-challenge." + name
	write := &dnsservice.DnsZoneWrite{Root: root}
	if len(values) == 0 {
		write.Deletes = []dnsservice.DnsRecordKey{{Owner: owner, Type: dns.TypeTXT}}
	} else {
		rdata := make([]string, 0, len(values))
		for _, value := range values {
			rdata = append(rdata, `"`+value+`"`)
		}
		write.Upserts = []dnsservice.DnsRecordSet{{Owner: owner, Type: dns.TypeTXT, Ttl: ttl, Kind: dnsservice.DnsRecordKindChallenge, Rdata: rdata}}
	}
	return self.store.Write(ctx, write)
}
