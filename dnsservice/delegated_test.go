package dnsservice_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar/dnsservice"
)

// A DKIM key's TXT, as /smtp/dkim-keys writes one.
const delegatedTestKey = `"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAdelegatedtest"`

// The edge test zone, with net1 delegating corp.example's _domainkey to its own: one selector's key row,
// a system TXT at another selector's name that is no key, and net1's wildcard, which no delegated name may
// answer from.
func delegatedTestRows(t testing.TB, settings *dnsservice.DnsSettings, domains ...string) []dnsservice.DnsRecordSet {
	t.Helper()
	rows := append(edgeTestRows(),
		dnsservice.DnsRecordSet{Owner: "*.net1." + edgeTestRoot, Type: dns.TypeTXT, Ttl: 300, Kind: dnsservice.DnsRecordKindSystem, Rdata: []string{`"wild"`}},
		dnsservice.DnsRecordSet{Owner: "s1._domainkey.net1." + edgeTestRoot, Type: dns.TypeTXT, Ttl: 300, Kind: dnsservice.DnsRecordKindKey, Rdata: []string{delegatedTestKey}},
		dnsservice.DnsRecordSet{Owner: "s3._domainkey.net1." + edgeTestRoot, Type: dns.TypeTXT, Ttl: 300, Kind: dnsservice.DnsRecordKindSystem, Rdata: []string{`"not a key"`}},
	)
	if len(domains) != 0 {
		row, err := dnsservice.NewDnsDelegatedRow(settings, edgeTestRoot, "net1."+edgeTestRoot, domains)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, *row)
	}
	return rows
}

// What the delegated zone at apex answers for name, as the edge finds it in view.
func delegatedTestAnswer(t testing.TB, view *dnsservice.ZoneView, name string, rrType uint16, signed bool) *dns.Msg {
	t.Helper()
	apex, labelApex, ok := view.Delegated().Lookup(dns.CanonicalName(name))
	if !ok {
		t.Fatalf("%s is in no delegated zone", name)
	}
	reply := dnsservice.AnswerDelegated(&dnsservice.DnsQuery{Message: edgeTestQuery(name, rrType, signed)}, view, apex, labelApex)
	if reply == nil {
		t.Fatalf("%s: no reply", name)
	}
	return reply
}

// A delegated zone answers its network's selectors from their key rows, its apex's SOA and NS, and
// nothing else: another type at a selector has no data, and a selector with no key row does not exist.
func TestDelegatedZoneAnswersTheNetworksSelectors(t *testing.T) {
	settings := edgeTestSettings(t)
	view := edgeTestView(t, settings, 9, delegatedTestRows(t, settings, "corp.example", "Shop.Example."))
	if got := view.Delegated().Apexes(); !slices.Equal(got, []string{"_domainkey.corp.example.", "_domainkey.shop.example."}) {
		t.Fatalf("apexes %v", got)
	}
	apex, labelApex, ok := view.Delegated().Lookup("s1._domainkey.corp.example.")
	if !ok || apex != "_domainkey.corp.example." || labelApex != "net1."+edgeTestRoot {
		t.Fatalf("lookup %s %s %t", apex, labelApex, ok)
	}

	for _, domain := range []string{"corp.example.", "shop.example."} {
		reply := delegatedTestAnswer(t, view, "s1._domainkey."+domain, dns.TypeTXT, false)
		if reply.Rcode != dns.RcodeSuccess || !reply.Authoritative || len(reply.Answer) != 1 {
			t.Fatalf("%s's selector %v", domain, reply)
		}
		txt := reply.Answer[0].(*dns.TXT)
		if txt.Hdr.Name != "s1._domainkey."+domain || txt.Hdr.Ttl != 300 || len(txt.Txt) != 1 || txt.Txt[0][:7] != "v=DKIM1" {
			t.Errorf("%s's key %v", domain, txt)
		}
	}
	// another type at the selector: no data, the delegated zone's SOA in authority
	reply := delegatedTestAnswer(t, view, "s1._domainkey.corp.example.", dns.TypeA, false)
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 || len(reply.Ns) != 1 || reply.Ns[0].Header().Name != "_domainkey.corp.example." {
		t.Errorf("A at a selector %v", reply)
	}
	// a selector the network does not hold
	reply = delegatedTestAnswer(t, view, "s2._domainkey.corp.example.", dns.TypeTXT, false)
	if reply.Rcode != dns.RcodeNameError || len(reply.Ns) != 1 {
		t.Errorf("an unknown selector %v", reply)
	}
	// the apex
	reply = delegatedTestAnswer(t, view, "_domainkey.corp.example.", dns.TypeSOA, false)
	if len(reply.Answer) != 1 || reply.Answer[0].(*dns.SOA).Serial != 9 || reply.Answer[0].(*dns.SOA).Ns != "ns1."+edgeTestRoot {
		t.Errorf("apex SOA %v", reply)
	}
	reply = delegatedTestAnswer(t, view, "_domainkey.corp.example.", dns.TypeNS, false)
	if len(reply.Answer) != 2 {
		t.Errorf("apex NS %v", reply)
	}
}

// A delegated zone holds nothing outside its selectors: a name below a selector, a selector whose row is
// no key, and a name net1's wildcard would cover all answer NXDOMAIN, never the wildcard's records; the
// customer's own domain is no delegated zone; and what a delegation's row may name is refused at its build.
func TestDelegatedZoneRefusesAnythingElse(t *testing.T) {
	settings := edgeTestSettings(t)
	view := edgeTestView(t, settings, 9, delegatedTestRows(t, settings, "corp.example"))
	for _, name := range []string{"x.s1._domainkey.corp.example.", "s3._domainkey.corp.example.", "s9._domainkey.corp.example."} {
		for _, rrType := range []uint16{dns.TypeTXT, dns.TypeA, dns.TypeANY} {
			reply := delegatedTestAnswer(t, view, name, rrType, false)
			if reply.Rcode != dns.RcodeNameError || len(reply.Answer) != 0 {
				t.Errorf("%s %s: %v", name, dns.TypeToString[rrType], reply)
			}
		}
	}
	for _, name := range []string{"corp.example.", "www.corp.example.", "_domainkey.other.example.", "s1._domainkey.net1." + edgeTestRoot} {
		if _, _, ok := view.Delegated().Lookup(name); ok {
			t.Errorf("%s is in a delegated zone", name)
		}
	}

	for _, domains := range [][]string{
		{"www." + edgeTestRoot},
		{"zone.example"},
		{"example"},
		{"bad_label.example"},
	} {
		if _, err := dnsservice.NewDnsDelegatedRow(settings, edgeTestRoot, "net1."+edgeTestRoot, domains); !errors.Is(err, dnsservice.ErrDnsDelegatedRefused) {
			t.Errorf("domains %v: %v", domains, err)
		}
	}
	// a reverse zone's names are no customer's
	reverseSettings := edgeTestSettings(t)
	reverseSettings.Reverse.Zones = []dnsservice.DnsReverseZoneSettings{{Zone: "2.0.192.in-addr.arpa.", Prefix: "192.0.2.0/24"}}
	if _, err := dnsservice.NewDnsDelegatedRow(reverseSettings, edgeTestRoot, "net1."+edgeTestRoot, []string{"2.0.192.in-addr.arpa"}); !errors.Is(err, dnsservice.ErrDnsDelegatedRefused) {
		t.Errorf("a reverse zone's name: %v", err)
	}
	if _, err := dnsservice.NewDnsDelegatedRow(settings, edgeTestRoot, "a.net1."+edgeTestRoot, []string{"corp.example"}); !errors.Is(err, dnsservice.ErrDnsDelegatedRefused) {
		t.Errorf("an owner below a label apex: %v", err)
	}
	// the row's wire rules, which a reader holds every row to
	for _, set := range []dnsservice.DnsRecordSet{
		{Owner: "net1." + edgeTestRoot, Type: dnsservice.DnsDelegatedType, Kind: dnsservice.DnsRecordKindDelegated},
		{Owner: "net1." + edgeTestRoot, Type: dnsservice.DnsDelegatedType, Kind: dnsservice.DnsRecordKindDelegated, Rdata: []string{"corp.example."}},
		{Owner: "net1." + edgeTestRoot, Type: dnsservice.DnsDelegatedType, Kind: dnsservice.DnsRecordKindDelegated, Rdata: []string{"_domainkey.x.net1." + edgeTestRoot}},
		{Owner: "net1." + edgeTestRoot, Type: dnsservice.DnsDelegatedType, Kind: dnsservice.DnsRecordKindDelegated, Rdata: []string{"_domainkey.corp.example.", "_domainkey.corp.example."}},
		{Owner: "net1." + edgeTestRoot, Type: dns.TypeTXT, Kind: dnsservice.DnsRecordKindDelegated, Rdata: []string{"_domainkey.corp.example."}},
		{Owner: "net1." + edgeTestRoot, Type: dnsservice.DnsDelegatedType, Kind: dnsservice.DnsRecordKindSystem, Rdata: []string{"_domainkey.corp.example."}},
		{Owner: edgeTestRoot, Type: dnsservice.DnsDelegatedType, Kind: dnsservice.DnsRecordKindDelegated, Rdata: []string{"_domainkey.corp.example."}},
	} {
		if err := set.Validate(edgeTestRoot); !errors.Is(err, dnsservice.ErrDnsRowMalformed) {
			t.Errorf("%+v: %v", set, err)
		}
	}
}

// A delegation follows the journal as any row does: added, changed and deleted at its serial, each view
// keeping the delegations it was built with; and a snapshot of a view carries the row.
func TestDelegatedZonesFollowTheJournal(t *testing.T) {
	settings := edgeTestSettings(t)
	first := edgeTestView(t, settings, 9, delegatedTestRows(t, settings))
	if apexes := first.Delegated().Apexes(); len(apexes) != 0 {
		t.Fatalf("delegations before any row %v", apexes)
	}
	row, err := dnsservice.NewDnsDelegatedRow(settings, edgeTestRoot, "net1."+edgeTestRoot, []string{"corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.Apply([]dnsservice.DnsJournalRow{{Format: dnsservice.DnsFormat, Root: edgeTestRoot, Serial: 10, Upserts: []dnsservice.DnsRecordSet{*row}}})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := dnsservice.NewDnsDelegatedRow(settings, edgeTestRoot, "net1."+edgeTestRoot, []string{"shop.example"})
	if err != nil {
		t.Fatal(err)
	}
	third, err := second.Apply([]dnsservice.DnsJournalRow{{Format: dnsservice.DnsFormat, Root: edgeTestRoot, Serial: 11, Upserts: []dnsservice.DnsRecordSet{*changed}}})
	if err != nil {
		t.Fatal(err)
	}
	fourth, err := third.Apply([]dnsservice.DnsJournalRow{{Format: dnsservice.DnsFormat, Root: edgeTestRoot, Serial: 12, Deletes: []dnsservice.DnsRecordKey{row.Key()}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		view *dnsservice.ZoneView
		want []string
	}{
		{view: first, want: []string{}},
		{view: second, want: []string{"_domainkey.corp.example."}},
		{view: third, want: []string{"_domainkey.shop.example."}},
		{view: fourth, want: []string{}},
	} {
		if got := c.view.Delegated().Apexes(); !slices.Equal(got, c.want) {
			t.Errorf("serial %d: %v, want %v", c.view.Serial(), got, c.want)
		}
	}
	held := false
	for set := range third.Rows() {
		held = held || (set.Kind == dnsservice.DnsRecordKindDelegated && slices.Equal(set.Rdata, []string{"_domainkey.shop.example."}))
	}
	if !held {
		t.Error("the view's rows do not carry the delegation")
	}
}

// An apex two networks' rows name answers for neither, whichever order the rows came in, and for the
// other once one goes: so both NS agree, one built from a snapshot and one from the journal.
func TestDelegatedApexTwoNetworksNameAnswersForNeither(t *testing.T) {
	settings := edgeTestSettings(t)
	net1, err := dnsservice.NewDnsDelegatedRow(settings, edgeTestRoot, "net1."+edgeTestRoot, []string{"corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	net2, err := dnsservice.NewDnsDelegatedRow(settings, edgeTestRoot, "net2."+edgeTestRoot, []string{"corp.example", "other.example"})
	if err != nil {
		t.Fatal(err)
	}
	for _, rows := range [][]dnsservice.DnsRecordSet{{*net1, *net2}, {*net2, *net1}} {
		view := edgeTestView(t, settings, 9, append(edgeTestRows(), rows...))
		if _, _, ok := view.Delegated().Lookup("s1._domainkey.corp.example."); ok {
			t.Errorf("a contested apex answers: %v", view.Delegated().Apexes())
		}
		if _, labelApex, ok := view.Delegated().Lookup("s1._domainkey.other.example."); !ok || labelApex != "net2."+edgeTestRoot {
			t.Errorf("an uncontested apex %s %t", labelApex, ok)
		}
		next, err := view.Apply([]dnsservice.DnsJournalRow{{Format: dnsservice.DnsFormat, Root: edgeTestRoot, Serial: 10, Deletes: []dnsservice.DnsRecordKey{net2.Key()}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, labelApex, ok := next.Delegated().Lookup("s1._domainkey.corp.example."); !ok || labelApex != "net1."+edgeTestRoot {
			t.Errorf("once net2's row goes: %s %t", labelApex, ok)
		}
	}
}

// The edge answers delegated zones only once dns.yml turns them on, and then unsigned under DO, while a
// name in no root or zone is refused as before.
func TestEdgeAnswersDelegatedZonesUnsignedOnlyWhenEnabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		settings := edgeTestSettings(t)
		settings.Rrl.ResponsesPerSecond = 1000 * 1000
		settings.Delegated.Enabled = enabled
		edge := newTestEdge(t, settings)
		edge.publish(t, edgeTestView(t, settings, 7, delegatedTestRows(t, settings, "corp.example")))
		conn := edge.serveUdp(t)
		conn.send(t, edgeTestQuery("s1._domainkey.corp.example.", dns.TypeTXT, true), "198.51.100.7")
		reply, _ := conn.receive(t)
		if !enabled {
			if reply.Rcode != dns.RcodeRefused || len(reply.Answer) != 0 {
				t.Errorf("off: %v", reply)
			}
			continue
		}
		if reply.Rcode != dns.RcodeSuccess || !reply.Authoritative || len(reply.Answer) != 1 || reply.Answer[0].Header().Rrtype != dns.TypeTXT {
			t.Fatalf("on: %v", reply)
		}
		conn.send(t, edgeTestQuery("s2._domainkey.corp.example.", dns.TypeTXT, true), "198.51.100.7")
		denial, _ := conn.receive(t)
		if denial.Rcode != dns.RcodeNameError {
			t.Errorf("an unknown selector under DO %v", denial)
		}
		for _, record := range append(append([]dns.RR{}, reply.Answer...), denial.Ns...) {
			if rrType := record.Header().Rrtype; rrType == dns.TypeRRSIG || rrType == dns.TypeNSEC {
				t.Errorf("a delegated zone answered %v", record)
			}
		}
		conn.send(t, edgeTestQuery("www.corp.example.", dns.TypeA, true), "198.51.100.7")
		if refused, _ := conn.receive(t); refused.Rcode != dns.RcodeRefused {
			t.Errorf("the customer's own name %v", refused)
		}
	}
}
