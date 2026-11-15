package dnsservice

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
)

// Team scopes (zone_scope.go; DNS-M6-06): a scope label refused in each listed case; a scope's set
// answering under its own apex as a network's does, its wildcard stopping the network's below it; its
// hosts one label below it taking user records, its apex and a deeper name not; a user owner equal to a
// scope label refused in the network's zone; and §8.4's dns:<host>.<scope> named for the gate.

const testScopeLabel = "eng"

// The scope's apex under testAliasLabel.
func testScopeApex() string {
	return DnsScopeApex(testAliasLabel, testScopeLabel)
}

// A scope's §12.7 set with mail off, the shape the model's one function writes for a network (and its
// edge rows when edge is set): null MX at the apex and wildcard, SPF, strict DMARC.
func testScopeRows(edge bool) []DnsRecordSet {
	apex := testScopeApex()
	rows := []DnsRecordSet{
		{Owner: apex, Type: dns.TypeMX, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: []string{"0 ."}},
		{Owner: apex, Type: dns.TypeTXT, Ttl: 3600, Kind: DnsRecordKindSystem, Rdata: []string{`"v=spf1 -all"`}},
		{Owner: "*." + apex, Type: dns.TypeMX, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: []string{"0 ."}},
		{Owner: "_dmarc." + apex, Type: dns.TypeTXT, Ttl: 3600, Kind: DnsRecordKindSystem, Rdata: []string{`"v=DMARC1; p=reject; sp=reject; np=reject; adkim=s; aspf=s"`}},
		{Owner: "web." + apex, Type: dns.TypeA, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"11.22.33.55"}},
	}
	if edge {
		rows = append(rows, DnsRecordSet{Owner: "*." + apex, Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindEdge})
	}
	return rows
}

// Refused: not one lowercase LDH label, one of §12.7's system hosts, a word-number label, §12.5's reserved
// list, a host the zone holds, a client name, and a brand the network has not verified; a plain label passes,
// and a brand passes for the network verifying the brand's own domain.
func TestValidateDnsScopeLabel(t *testing.T) {
	context := &DnsScopeLabelContext{Hosts: []string{"shop", "www"}, ClientNames: []string{"laptop"}}
	refused := []string{"", "Eng", "e_ng", "-eng", "b", "mx", "maple-1234", "www", "api", "main-x", "shop", "laptop", "paypal"}
	for _, label := range refused {
		if err := ValidateDnsScopeLabel(label, context); !errors.Is(err, ErrDnsScopeLabelRefused) {
			t.Errorf("%q: %v", label, err)
		}
	}
	for _, label := range []string{"eng", "design", "team-2"} {
		if err := ValidateDnsScopeLabel(label, context); err != nil {
			t.Errorf("%q: %v", label, err)
		}
	}
	verified := &DnsScopeLabelContext{Facts: &sidecar.ScreenFacts{VerifiedDomains: []string{"paypal.com"}}}
	if err := ValidateDnsScopeLabel("paypal", verified); err != nil {
		t.Errorf("a verified brand: %v", err)
	}
	if err := ValidateDnsScopeLabel("eng", nil); err != nil {
		t.Errorf("no context: %v", err)
	}
}

// A scope's set answers under its apex: its MX and SPF there and at its wildcard, a host under it, and no
// address where it has no edge row, though the network's wildcard answers the network's names; with edge
// rows its wildcard answers the healthy set. The scope's apex stops the network's wildcard below it.
func TestZoneScopeAnswersItsOwnSet(t *testing.T) {
	healthy := testAliasHealthy()
	scope := testScopeApex()
	view := newTestView(t, 1, append(append(testApexRows(), testAliasLabelRows()...), testScopeRows(false)...)...)
	requireAliasAnswer(t, view, healthy, scope, dns.TypeMX, dns.RcodeSuccess, "MX 0 .")
	requireAliasAnswer(t, view, healthy, scope, dns.TypeTXT, dns.RcodeSuccess, `TXT "v=spf1 -all"`)
	requireAliasAnswer(t, view, healthy, "maple-1234."+scope, dns.TypeMX, dns.RcodeSuccess, "MX 0 .")
	requireAliasAnswer(t, view, healthy, "web."+scope, dns.TypeA, dns.RcodeSuccess, "A 11.22.33.55")
	// no edge row in the scope: its wildcard holds MX alone, so an address query is NODATA, not the network's
	requireAliasAnswer(t, view, healthy, "app."+scope, dns.TypeA, dns.RcodeSuccess)
	requireAliasAnswer(t, view, healthy, "app."+testAliasLabel, dns.TypeA, dns.RcodeSuccess, "A 192.0.2.1", "A 192.0.2.2")
	requireAliasAnswer(t, view, healthy, "_dmarc."+scope, dns.TypeTXT, dns.RcodeSuccess, `TXT "v=DMARC1; p=reject; sp=reject; np=reject; adkim=s; aspf=s"`)
	withEdge := newTestView(t, 1, append(append(testApexRows(), testAliasLabelRows()...), testScopeRows(true)...)...)
	requireAliasAnswer(t, withEdge, healthy, "app."+scope, dns.TypeA, dns.RcodeSuccess, "A 192.0.2.1", "A 192.0.2.2")
	dropped := NewHealthySet([]DnsLbInterface{{Name: "lb-1", Ipv4: netip.MustParseAddr("192.0.2.1")}}, nil)
	requireAliasAnswer(t, withEdge, dropped, "app."+scope, dns.TypeA, dns.RcodeSuccess, "A 192.0.2.1")
}

// An alias of the network answers the scope's rows under the alias, as it answers every name of its label.
func TestZoneScopeAnswersUnderAnAlias(t *testing.T) {
	healthy := testAliasHealthy()
	view := newTestView(t, 1, append(append(append(testApexRows(), testAliasLabelRows()...), testScopeRows(true)...), testAliasRow(true))...)
	aliasScope := testScopeLabel + "." + testAliasApex
	requireAliasAnswer(t, view, healthy, aliasScope, dns.TypeMX, dns.RcodeSuccess, "MX 0 .")
	requireAliasAnswer(t, view, healthy, "web."+aliasScope, dns.TypeA, dns.RcodeSuccess, "A 11.22.33.55")
	requireAliasAnswer(t, view, healthy, "app."+aliasScope, dns.TypeA, dns.RcodeSuccess, "A 192.0.2.1", "A 192.0.2.2")
}

// In a scope's zone only hosts one label below its apex take user records: the apex and an underscore owner
// at it are refused, as is a host two labels deep; a host, its wildcard and its underscore and SRV owners pass.
// In the network's zone a scope label is refused as a user owner, and so is any name below it.
func TestValidateUserRecordSetInAScope(t *testing.T) {
	scope := testScopeApex()
	inScope := &DnsUserRecordContext{Root: testRoot, Apex: scope, TtlRange: [2]uint32{60, 3600}, Scope: testScopeLabel}
	a := func(owner string) *DnsRecordSet {
		return &DnsRecordSet{Owner: owner, Type: dns.TypeA, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"11.22.33.44"}}
	}
	txt := func(owner string) *DnsRecordSet {
		return &DnsRecordSet{Owner: owner, Type: dns.TypeTXT, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{`"hello"`}}
	}
	srv := &DnsRecordSet{Owner: "_sip._tcp.web." + scope, Type: dns.TypeSRV, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"10 5 5060 web." + scope}}
	for _, set := range []*DnsRecordSet{a("web." + scope), a("*.web." + scope), txt("_verify.web." + scope), srv} {
		if err := ValidateUserRecordSet(inScope, set); err != nil {
			t.Errorf("%s %s: %v", set.Owner, dns.TypeToString[set.Type], err)
		}
	}
	for _, set := range []*DnsRecordSet{a(scope), txt(scope), txt("_verify." + scope), a("a.web." + scope), a("mx." + scope), a("maple-1234." + scope)} {
		if err := ValidateUserRecordSet(inScope, set); !errors.Is(err, ErrDnsUserRecordRefused) {
			t.Errorf("%s %s: %v", set.Owner, dns.TypeToString[set.Type], err)
		}
	}
	inNetwork := &DnsUserRecordContext{Root: testRoot, Apex: testAliasLabel, TtlRange: [2]uint32{60, 3600}, ScopeLabels: []string{testScopeLabel}}
	for _, set := range []*DnsRecordSet{a(scope), a("web." + scope), txt("_verify." + scope)} {
		if err := ValidateUserRecordSet(inNetwork, set); !errors.Is(err, ErrDnsUserRecordRefused) {
			t.Errorf("in the network's zone %s: %v", set.Owner, err)
		}
	}
	if err := ValidateUserRecordSet(inNetwork, a("shop."+testAliasLabel)); err != nil {
		t.Errorf("a network host: %v", err)
	}
}

// §8.4's dns:<host> for a scope's names: <host>.<scope> for the host and every form below it, and the
// network's own forms as they were.
func TestDnsOwnerHostNamesScopeHosts(t *testing.T) {
	root := testRoot
	apex := testAliasLabel
	scope := testScopeApex()
	cases := []struct {
		owner string
		host  string
	}{
		{owner: apex, host: "@"},
		{owner: "_dmarc." + apex, host: "@"},
		{owner: "www." + apex, host: "www"},
		{owner: "*.www." + apex, host: "www"},
		{owner: "_x.www." + apex, host: "www"},
		{owner: "_sip._tcp.www." + apex, host: "www"},
		{owner: scope, host: testScopeLabel},
		{owner: "web." + scope, host: "web." + testScopeLabel},
		{owner: "*.web." + scope, host: "web." + testScopeLabel},
		{owner: "_x.web." + scope, host: "web." + testScopeLabel},
		{owner: "_sip._tcp.web." + scope, host: "web." + testScopeLabel},
	}
	for _, c := range cases {
		host, ok := DnsOwnerHost(root, c.owner)
		if !ok || host != c.host {
			t.Errorf("%s: %q %t, want %q", c.owner, host, ok, c.host)
		}
	}
}

// The scope an owner sits under, from the network's scopes, and the hosts a zone holds for §12.5's check.
func TestDnsOwnerScopeAndZoneHosts(t *testing.T) {
	apex := testAliasLabel
	scopes := []string{testScopeLabel}
	if scope := DnsOwnerScope(apex, "web."+testScopeApex(), scopes); scope != testScopeLabel {
		t.Errorf("a scope host: %q", scope)
	}
	if scope := DnsOwnerScope(apex, testScopeApex(), scopes); scope != testScopeLabel {
		t.Errorf("a scope apex: %q", scope)
	}
	for _, owner := range []string{apex, "web.other." + apex, "shop." + apex, "www.other.example."} {
		if scope := DnsOwnerScope(apex, owner, scopes); scope != "" {
			t.Errorf("%s: %q", owner, scope)
		}
	}
	hosts := DnsZoneHostLabels(apex, []string{apex, "*." + apex, "_dmarc." + apex, "shop." + apex, "a.shop." + apex, "mx." + apex, "www.other.example."})
	if len(hosts) != 2 || hosts[0] != "mx" || hosts[1] != "shop" {
		t.Errorf("hosts %v", hosts)
	}
}
