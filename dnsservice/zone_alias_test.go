package dnsservice

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Alias zones (zone_alias.go; DNS-M6-01, reading 11): an alias in effect answers its label's records
// with the apex rewritten, its own mx host and TLSA included; a write to the label reaches it with no
// second write, and a health drop too; an alias with no rdata answers only its own challenge; the
// label's challenges never answer under it; a retiring CAA answers beside the label's records; the
// row's removal ends it; suspensions hold; compact denial reads the alias's types; and the wire refuses
// an alias row of any other shape.

const (
	testAliasLabel = "lbl1234567.zone.example."
	testAliasApex  = "shopname.zone.example."
)

// A label zone as §12.7 writes it with mail on, a user host, a CNAME to it, a TLSA, the label's own
// challenge and the edge's wildcard.
func testAliasLabelRows() []DnsRecordSet {
	label := testAliasLabel
	return []DnsRecordSet{
		{Owner: label, Type: dns.TypeMX, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: []string{"10 mx." + label}},
		{Owner: label, Type: dns.TypeTXT, Ttl: 3600, Kind: DnsRecordKindSystem, Rdata: []string{`"v=spf1 -all"`}},
		{Owner: "*." + label, Type: dns.TypeMX, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: []string{"10 mx." + label}},
		{Owner: "*." + label, Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindEdge},
		{Owner: "mx." + label, Type: dns.TypeA, Ttl: 300, Kind: DnsRecordKindRouter},
		{Owner: "_25._tcp.mx." + label, Type: dns.TypeTLSA, Ttl: 300, Kind: DnsRecordKindKey, Rdata: []string{"3 1 1 " + strings.Repeat("ab", 32)}},
		{Owner: "shop." + label, Type: dns.TypeA, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"11.22.33.44"}},
		{Owner: "www." + label, Type: dns.TypeCNAME, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"shop." + label}},
		{Owner: "_acme-challenge." + label, Type: dns.TypeTXT, Ttl: 60, Kind: DnsRecordKindChallenge, Rdata: []string{`"label-challenge"`}},
	}
}

// The alias row: with the label's apex when certified, with none when only claimed.
func testAliasRow(certified bool) DnsRecordSet {
	row := DnsRecordSet{Owner: testAliasApex, Type: DnsAliasType, Kind: DnsRecordKindAlias}
	if certified {
		row.Rdata = []string{testAliasLabel}
	}
	return row
}

// One edge interface and one router interface, both healthy.
func testAliasHealthy() *HealthySet {
	edge := DnsLbInterface{Name: "lb-1", Ipv4: netip.MustParseAddr("192.0.2.1")}
	router := DnsLbInterface{Name: "lb-2", Ipv4: netip.MustParseAddr("192.0.2.2"), Router: true}
	return NewHealthySet([]DnsLbInterface{edge, router}, []DnsLbInterface{router})
}

// The rcode and each answer record's RDATA of a query of rrType at name, sorted, owners checked to be
// name or a CNAME chain's.
func testAliasAnswer(t testing.TB, view *ZoneView, healthy *HealthySet, name string, rrType uint16) (int, []string) {
	t.Helper()
	reply := testAnswer(t, view, healthy, name, rrType)
	rdatas := []string{}
	for _, record := range reply.Answer {
		rdatas = append(rdatas, dns.TypeToString[record.Header().Rrtype]+" "+strings.TrimPrefix(record.String(), record.Header().String()))
	}
	slices.Sort(rdatas)
	return reply.Rcode, rdatas
}

func requireAliasAnswer(t testing.TB, view *ZoneView, healthy *HealthySet, name string, rrType uint16, wantRcode int, want ...string) {
	t.Helper()
	rcode, got := testAliasAnswer(t, view, healthy, name, rrType)
	slices.Sort(want)
	if rcode != wantRcode || !slices.Equal(got, want) {
		t.Errorf("%s %s: %s %v, want %s %v", name, dns.TypeToString[rrType], dns.RcodeToString[rcode], got, dns.RcodeToString[wantRcode], want)
	}
}

// A certified alias answers the label's records under its own apex: its MX names its own mx host,
// which answers the router interfaces with the label's TLSA beside it; a user host, a CNAME moved
// into the alias and followed, the wildcard's addresses and MX; and no record anywhere names the
// label.
func TestZoneAliasAnswersTheLabelsRecordsWithItsApex(t *testing.T) {
	view := newTestView(t, 1, append(append(testApexRows(), testAliasLabelRows()...), testAliasRow(true))...)
	healthy := testAliasHealthy()
	alias := testAliasApex
	requireAliasAnswer(t, view, healthy, alias, dns.TypeMX, dns.RcodeSuccess, "MX 10 mx."+alias)
	requireAliasAnswer(t, view, healthy, alias, dns.TypeTXT, dns.RcodeSuccess, `TXT "v=spf1 -all"`)
	requireAliasAnswer(t, view, healthy, "mx."+alias, dns.TypeA, dns.RcodeSuccess, "A 192.0.2.2")
	requireAliasAnswer(t, view, healthy, "_25._tcp.mx."+alias, dns.TypeTLSA, dns.RcodeSuccess, "TLSA 3 1 1 "+strings.Repeat("ab", 32))
	requireAliasAnswer(t, view, healthy, "shop."+alias, dns.TypeA, dns.RcodeSuccess, "A 11.22.33.44")
	requireAliasAnswer(t, view, healthy, "www."+alias, dns.TypeA, dns.RcodeSuccess, "CNAME shop."+alias, "A 11.22.33.44")
	requireAliasAnswer(t, view, healthy, "burner-1234."+alias, dns.TypeMX, dns.RcodeSuccess, "MX 10 mx."+alias)
	requireAliasAnswer(t, view, healthy, "any.deeper."+alias, dns.TypeA, dns.RcodeSuccess, "A 192.0.2.1", "A 192.0.2.2")
	reply := testAnswer(t, view, healthy, "www."+alias, dns.TypeA)
	for _, record := range reply.Answer {
		if strings.Contains(record.String(), testAliasLabel) {
			t.Errorf("the alias answered %s", record)
		}
	}
	// the label answers as it did
	requireAliasAnswer(t, view, healthy, testAliasLabel, dns.TypeMX, dns.RcodeSuccess, "MX 10 mx."+testAliasLabel)
	// a name the label lacks below a host the label holds is no name under the alias either
	requireAliasAnswer(t, view, healthy, "x.shop."+alias, dns.TypeA, dns.RcodeNameError)
}

// A write to the label's rows, and a health drop, reach the alias with no write of its own.
func TestZoneAliasFollowsTheLabelWithNoSecondWrite(t *testing.T) {
	view := newTestView(t, 1, append(append(testApexRows(), testAliasLabelRows()...), testAliasRow(true))...)
	next, err := view.Apply([]DnsJournalRow{{
		Format:  DnsFormat,
		Root:    testRoot,
		Serial:  2,
		Upserts: []DnsRecordSet{{Owner: "shop." + testAliasLabel, Type: dns.TypeA, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"11.22.33.55"}}},
		Deletes: []DnsRecordKey{{Owner: "www." + testAliasLabel, Type: dns.TypeCNAME}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	healthy := testAliasHealthy()
	requireAliasAnswer(t, next, healthy, "shop."+testAliasApex, dns.TypeA, dns.RcodeSuccess, "A 11.22.33.55")
	// www left the label, so the alias's www falls to the wildcard
	requireAliasAnswer(t, next, healthy, "www."+testAliasApex, dns.TypeA, dns.RcodeSuccess, "A 192.0.2.1", "A 192.0.2.2")
	dropped := NewHealthySet([]DnsLbInterface{{Name: "lb-1", Ipv4: netip.MustParseAddr("192.0.2.1")}}, nil)
	requireAliasAnswer(t, next, dropped, "any."+testAliasApex, dns.TypeA, dns.RcodeSuccess, "A 192.0.2.1")
	requireAliasAnswer(t, next, dropped, "mx."+testAliasApex, dns.TypeA, dns.RcodeSuccess)
}

// Claimed and not yet certified, the alias answers only its own challenge, and nothing of the label's.
func TestZoneAliasBeforeItsCertificateAnswersOnlyItsChallenge(t *testing.T) {
	challenge := DnsRecordSet{Owner: "_acme-challenge." + testAliasApex, Type: dns.TypeTXT, Ttl: 60, Kind: DnsRecordKindChallenge, Rdata: []string{`"alias-challenge"`}}
	view := newTestView(t, 1, append(append(testApexRows(), testAliasLabelRows()...), testAliasRow(false), challenge)...)
	healthy := testAliasHealthy()
	requireAliasAnswer(t, view, healthy, "_acme-challenge."+testAliasApex, dns.TypeTXT, dns.RcodeSuccess, `TXT "alias-challenge"`)
	requireAliasAnswer(t, view, healthy, testAliasApex, dns.TypeMX, dns.RcodeSuccess)
	requireAliasAnswer(t, view, healthy, "shop."+testAliasApex, dns.TypeA, dns.RcodeNameError)
	// certified, the same challenge still answers, and the label's records join it
	certified, err := view.Apply([]DnsJournalRow{{Format: DnsFormat, Root: testRoot, Serial: 2, Upserts: []DnsRecordSet{testAliasRow(true)}}})
	if err != nil {
		t.Fatal(err)
	}
	requireAliasAnswer(t, certified, healthy, "_acme-challenge."+testAliasApex, dns.TypeTXT, dns.RcodeSuccess, `TXT "alias-challenge"`)
	requireAliasAnswer(t, certified, healthy, "shop."+testAliasApex, dns.TypeA, dns.RcodeSuccess, "A 11.22.33.44")
	// the alias's challenge name stops the label's wildcard, as one zone holding both would
	requireAliasAnswer(t, certified, healthy, "_acme-challenge."+testAliasApex, dns.TypeA, dns.RcodeSuccess)
	requireAliasAnswer(t, certified, healthy, "x._acme-challenge."+testAliasApex, dns.TypeA, dns.RcodeNameError)
}

// The label's challenge never answers under the alias: each name proves only its own certificates.
func TestZoneAliasLeavesTheLabelsChallengeOut(t *testing.T) {
	view := newTestView(t, 1, append(append(testApexRows(), testAliasLabelRows()...), testAliasRow(true))...)
	healthy := testAliasHealthy()
	requireAliasAnswer(t, view, healthy, "_acme-challenge."+testAliasLabel, dns.TypeTXT, dns.RcodeSuccess, `TXT "label-challenge"`)
	requireAliasAnswer(t, view, healthy, "_acme-challenge."+testAliasApex, dns.TypeTXT, dns.RcodeSuccess)
	requireAliasAnswer(t, view, healthy, "_acme-challenge."+testAliasApex, dns.TypeANY, dns.RcodeSuccess, "HINFO \"RFC8482\" \"\"")
	if types := view.dataTypes("_acme-challenge."+testAliasApex, healthy); len(types) != 0 {
		t.Errorf("the alias's challenge name has types %v", types)
	}
}

// A retiring alias's CAA, <root>'s row at its apex, answers beside the label's records, and its types
// join theirs in a denial; deleting the alias row ends every answer but the CAA.
func TestZoneAliasRetiringCaaAndItsEnd(t *testing.T) {
	caa := DnsRecordSet{Owner: testAliasApex, Type: dns.TypeCAA, Ttl: 3600, Kind: DnsRecordKindSystem, Rdata: []string{`0 issue ";"`}}
	view := newTestView(t, 1, append(append(testApexRows(), testAliasLabelRows()...), testAliasRow(true), caa)...)
	healthy := testAliasHealthy()
	requireAliasAnswer(t, view, healthy, testAliasApex, dns.TypeCAA, dns.RcodeSuccess, `CAA 0 issue ";"`)
	requireAliasAnswer(t, view, healthy, testAliasApex, dns.TypeMX, dns.RcodeSuccess, "MX 10 mx."+testAliasApex)
	if types, want := view.dataTypes(testAliasApex, healthy), []uint16{dns.TypeTXT, dns.TypeMX, dns.TypeCAA}; !slices.Equal(types, slices.Sorted(slices.Values(want))) {
		t.Errorf("the alias's apex has types %v, want %v", types, want)
	}
	ended, err := view.Apply([]DnsJournalRow{{Format: DnsFormat, Root: testRoot, Serial: 2, Deletes: []DnsRecordKey{{Owner: testAliasApex, Type: DnsAliasType}}}})
	if err != nil {
		t.Fatal(err)
	}
	requireAliasAnswer(t, ended, healthy, testAliasApex, dns.TypeCAA, dns.RcodeSuccess, `CAA 0 issue ";"`)
	requireAliasAnswer(t, ended, healthy, testAliasApex, dns.TypeMX, dns.RcodeSuccess)
	requireAliasAnswer(t, ended, healthy, "shop."+testAliasApex, dns.TypeA, dns.RcodeNameError)
	gone, err := ended.Apply([]DnsJournalRow{{Format: DnsFormat, Root: testRoot, Serial: 3, Deletes: []DnsRecordKey{{Owner: testAliasApex, Type: dns.TypeCAA}}}})
	if err != nil {
		t.Fatal(err)
	}
	requireAliasAnswer(t, gone, healthy, testAliasApex, dns.TypeMX, dns.RcodeNameError)
}

// A suspended host of the label answers NODATA under the alias too, and a suspended zone, whose rows the
// feed withheld with the alias row, answers nothing below the alias.
func TestZoneAliasHoldsSuspensions(t *testing.T) {
	withheld := DnsRecordSet{Owner: "shop." + testAliasLabel, Type: DnsWithheldType, Kind: DnsRecordKindWithheld}
	rows := slices.DeleteFunc(testAliasLabelRows(), func(row DnsRecordSet) bool { return row.Owner == "shop."+testAliasLabel })
	view := newTestView(t, 1, append(append(append(testApexRows(), rows...), testAliasRow(true)), withheld)...)
	healthy := testAliasHealthy()
	requireAliasAnswer(t, view, healthy, "shop."+testAliasApex, dns.TypeA, dns.RcodeSuccess)
	requireAliasAnswer(t, view, healthy, "shop."+testAliasApex, dns.TypeANY, dns.RcodeSuccess)
	requireAliasAnswer(t, view, healthy, "a.shop."+testAliasApex, dns.TypeA, dns.RcodeNameError)

	apexWithheld := DnsRecordSet{Owner: testAliasApex, Type: DnsWithheldType, Kind: DnsRecordKindWithheld}
	suspended := newTestView(t, 1, append(testApexRows(), apexWithheld, DnsRecordSet{Owner: testAliasLabel, Type: DnsWithheldType, Kind: DnsRecordKindWithheld})...)
	requireAliasAnswer(t, suspended, healthy, testAliasApex, dns.TypeMX, dns.RcodeSuccess)
	requireAliasAnswer(t, suspended, healthy, "shop."+testAliasApex, dns.TypeA, dns.RcodeNameError)
}

// Signed, a denial at an alias name carries the alias's own types and the label's, and never the
// label's challenge.
func TestZoneAliasCompactDenialReadsItsTypes(t *testing.T) {
	view := newTestView(t, 1, append(append(testApexRows(), testAliasLabelRows()...), testAliasRow(true))...)
	healthy := testAliasHealthy()
	if types := view.dataTypes("mx."+testAliasApex, healthy); !slices.Equal(types, []uint16{dns.TypeA}) {
		t.Errorf("mx under the alias has types %v", types)
	}
	if types := view.dataTypes("nosuch.shop."+testAliasApex, healthy); types != nil {
		t.Errorf("a name the alias lacks has types %v", types)
	}
	if types := view.dataTypes("burner-1234."+testAliasApex, healthy); !slices.Equal(types, []uint16{dns.TypeA, dns.TypeMX}) {
		t.Errorf("a wildcard name under the alias has types %v", types)
	}
}

// The wire takes an alias row only at a name directly below the root, holding at most a label apex
// directly below the root other than itself, and of its own type; nothing else may hold that type.
func TestZoneAliasRowShape(t *testing.T) {
	good := []DnsRecordSet{testAliasRow(true), testAliasRow(false)}
	for _, row := range good {
		if err := row.Validate(testRoot); err != nil {
			t.Errorf("%+v: %v", row, err)
		}
	}
	bad := []DnsRecordSet{
		{Owner: "deep." + testAliasApex, Type: DnsAliasType, Kind: DnsRecordKindAlias, Rdata: []string{testAliasLabel}},
		{Owner: testAliasApex, Type: DnsAliasType, Kind: DnsRecordKindAlias, Rdata: []string{"x." + testAliasLabel}},
		{Owner: testAliasApex, Type: DnsAliasType, Kind: DnsRecordKindAlias, Rdata: []string{testAliasApex}},
		{Owner: testAliasApex, Type: DnsAliasType, Kind: DnsRecordKindAlias, Rdata: []string{testAliasLabel, testAliasLabel}},
		{Owner: testAliasApex, Type: DnsAliasType, Kind: DnsRecordKindAlias, Rdata: []string{"LBL1234567.zone.example."}},
		{Owner: testAliasApex, Type: dns.TypeCNAME, Kind: DnsRecordKindAlias, Rdata: []string{testAliasLabel}},
		{Owner: testAliasApex, Type: DnsAliasType, Kind: DnsRecordKindSystem, Rdata: []string{testAliasLabel}},
		{Owner: testRoot, Type: DnsAliasType, Kind: DnsRecordKindAlias, Rdata: []string{testAliasLabel}},
	}
	for _, row := range bad {
		if err := row.Validate(testRoot); !errors.Is(err, ErrDnsRowMalformed) {
			t.Errorf("%+v: %v", row, err)
		}
	}
	key := DnsRecordKey{Owner: testAliasApex, Type: DnsAliasType}
	if err := key.Validate(testRoot); err != nil {
		t.Errorf("the alias row's key: %v", err)
	}
}

// A direct MX's addresses answer at the mail host, and one that is not public is held and never
// answered, as a user's would be.
func TestZoneDirectRowsAnswerOnlyPublicAddresses(t *testing.T) {
	direct := DnsRecordSet{Owner: "mx." + testAliasLabel, Type: dns.TypeA, Ttl: 300, Kind: DnsRecordKindDirect, Rdata: []string{"11.22.33.66"}}
	view := newTestView(t, 1, append(testApexRows(), direct)...)
	requireAliasAnswer(t, view, nil, "mx."+testAliasLabel, dns.TypeA, dns.RcodeSuccess, "A 11.22.33.66")
	private := direct
	private.Rdata = []string{"10.1.2.3"}
	held := newTestView(t, 1, append(testApexRows(), private)...)
	requireAliasAnswer(t, held, nil, "mx."+testAliasLabel, dns.TypeA, dns.RcodeSuccess)
	if held.WithheldCount() != 1 {
		t.Errorf("%d rows held", held.WithheldCount())
	}
	noAddress := DnsRecordSet{Owner: "mx." + testAliasLabel, Type: dns.TypeA, Ttl: 300, Kind: DnsRecordKindDirect}
	if err := noAddress.Validate(testRoot); !errors.Is(err, ErrDnsRowMalformed) {
		t.Errorf("a direct row with no address: %v", err)
	}
	txt := DnsRecordSet{Owner: "mx." + testAliasLabel, Type: dns.TypeTXT, Ttl: 300, Kind: DnsRecordKindDirect, Rdata: []string{`"x"`}}
	if err := txt.Validate(testRoot); !errors.Is(err, ErrDnsRowMalformed) {
		t.Errorf("a direct row of TXT: %v", err)
	}
}

// §12.7's A rules over a direct MX's addresses (DNS-M7-03): public unicast of either family passes; none, a
// private, documentation, loopback or ULA address, one given twice (its mapped form included) and more than
// the RRset cap of a family refuse.
func TestValidateDirectMxAddresses(t *testing.T) {
	public := []netip.Addr{netip.MustParseAddr("11.22.33.4"), netip.MustParseAddr("2a0b:1111:2222::5")}
	if err := ValidateDirectMxAddresses(public); err != nil {
		t.Errorf("%v: %v", public, err)
	}
	refused := [][]netip.Addr{
		{},
		{netip.MustParseAddr("10.0.0.1")},
		{netip.MustParseAddr("192.0.2.1")},
		{netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("fd00::1")},
		{netip.MustParseAddr("2001:db8::1")},
		{netip.MustParseAddr("11.22.33.4"), netip.MustParseAddr("::ffff:11.22.33.4")},
	}
	many := []netip.Addr{}
	for index := range 9 {
		many = append(many, netip.AddrFrom4([4]byte{11, 22, 33, byte(10 + index)}))
	}
	refused = append(refused, many)
	for _, addresses := range refused {
		if err := ValidateDirectMxAddresses(addresses); !errors.Is(err, ErrDnsDirectMxRefused) {
			t.Errorf("%v: %v", addresses, err)
		}
	}
}
