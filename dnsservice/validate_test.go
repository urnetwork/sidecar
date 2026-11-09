package dnsservice

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/urnetwork/connect"
)

// §12.7's user table and the zone lint (DNS-M5-02), T1: §22.5's §12 row (validator, CNAME lint), every
// row of testdata/dns/records.json accepted or refused, the DNS stand-ins, the TXT bound, and the lint's
// refusals of a CNAME beside a system record, a wildcard CNAME, ruf, fo and report mail into the root.

// testdata/dns/records.json.
type testUserRecordVectors struct {
	Root        string    `json:"root"`
	Apex        string    `json:"apex"`
	TtlRange    [2]uint32 `json:"ttl_range"`
	ScopeLabels []string  `json:"scope_labels"`
	Tombstoned  []string  `json:"tombstoned"`
	Cases       []struct {
		Owner string   `json:"owner"`
		Type  string   `json:"type"`
		Ttl   uint32   `json:"ttl"`
		Kind  string   `json:"kind"`
		Rdata []string `json:"rdata"`
		Ok    bool     `json:"ok"`
		Why   string   `json:"why"`
	} `json:"cases"`
}

func readTestUserRecordVectors(t testing.TB) *testUserRecordVectors {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "dns", "records.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testUserRecordVectors{}
	if err := json.Unmarshal(data, vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

// The vectors' zone as a context.
func (self *testUserRecordVectors) context() *DnsUserRecordContext {
	return &DnsUserRecordContext{
		Root:        self.Root,
		Apex:        self.Apex,
		TtlRange:    self.TtlRange,
		ScopeLabels: self.ScopeLabels,
		Tombstoned: func(label string) bool {
			return slices.Contains(self.Tombstoned, label)
		},
	}
}

// A user RRset at owner, relative to the zone unless it ends with a dot.
func testUserRecordSet(apex string, owner string, rrType uint16, ttl uint32, rdata ...string) *DnsRecordSet {
	switch {
	case owner == "@":
		owner = apex
	case !strings.HasSuffix(owner, "."):
		owner = owner + "." + apex
	}
	return &DnsRecordSet{Owner: owner, Type: rrType, Ttl: ttl, Kind: DnsRecordKindUser, Rdata: rdata}
}

// Every row of the table, accepted or refused as it says, and every refusal wrapping
// ErrDnsUserRecordRefused.
func TestValidateUserRecordSetVectors(t *testing.T) {
	vectors := readTestUserRecordVectors(t)
	if len(vectors.Cases) < 80 {
		t.Fatalf("%d vectors", len(vectors.Cases))
	}
	context := vectors.context()
	for _, c := range vectors.Cases {
		rrType, ok := dns.StringToType[c.Type]
		if !ok {
			t.Fatalf("%s: type %q", c.Owner, c.Type)
		}
		set := testUserRecordSet(vectors.Apex, c.Owner, rrType, c.Ttl, c.Rdata...)
		if c.Kind != "" {
			set.Kind = DnsRecordKind(c.Kind)
		}
		err := ValidateUserRecordSet(context, set)
		if c.Ok && err != nil {
			t.Errorf("%s %s %v refused (%s): %v", c.Owner, c.Type, c.Rdata, c.Why, err)
		}
		if !c.Ok && !errors.Is(err, ErrDnsUserRecordRefused) {
			t.Errorf("%s %s %v answered %v, want a refusal (%s)", c.Owner, c.Type, c.Rdata, err, c.Why)
		}
	}
}

// connect's DNS stand-ins reach no host, so no user record names them, by the constants and never a
// copy of their values.
func TestValidateUserRecordSetRefusesTheStandIns(t *testing.T) {
	vectors := readTestUserRecordVectors(t)
	context := vectors.context()
	for _, set := range []*DnsRecordSet{
		testUserRecordSet(vectors.Apex, "www", dns.TypeA, 300, connect.DefaultDnsUpgradeMaskAddress),
		testUserRecordSet(vectors.Apex, "www", dns.TypeAAAA, 300, connect.DefaultDnsUpgradeMaskAddressIpv6),
	} {
		if err := ValidateUserRecordSet(context, set); !errors.Is(err, ErrDnsUserRecordRefused) {
			t.Errorf("%v answered %v", set.Rdata, err)
		}
	}
}

// 1024 bytes of TXT across the RRset pass and 1025 do not, however the strings are split.
func TestValidateUserRecordSetTxtBound(t *testing.T) {
	vectors := readTestUserRecordVectors(t)
	context := vectors.context()
	quoted := func(count int) string {
		return `"` + strings.Repeat("a", count) + `"`
	}
	accepted := testUserRecordSet(vectors.Apex, "www", dns.TypeTXT, 300, quoted(255)+" "+quoted(255), quoted(255)+" "+quoted(259))
	if err := ValidateUserRecordSet(context, accepted); err != nil {
		t.Fatalf("1024 bytes refused: %v", err)
	}
	refused := testUserRecordSet(vectors.Apex, "www", dns.TypeTXT, 300, quoted(255)+" "+quoted(255), quoted(255)+" "+quoted(255), quoted(5))
	if err := ValidateUserRecordSet(context, refused); !errors.Is(err, ErrDnsUserRecordRefused) {
		t.Fatalf("1025 bytes answered %v", err)
	}
}

// With no tombstone lookup a CNAME into the root is refused, the closed direction, and one out of it is
// not; a context that names no zone or range refuses everything.
func TestValidateUserRecordSetFailsClosed(t *testing.T) {
	vectors := readTestUserRecordVectors(t)
	context := vectors.context()
	context.Tombstoned = nil
	into := testUserRecordSet(vectors.Apex, "www", dns.TypeCNAME, 300, "livelabel1.zone.example.")
	if err := ValidateUserRecordSet(context, into); !errors.Is(err, ErrDnsUserRecordRefused) {
		t.Fatalf("a CNAME into the root with no lookup answered %v", err)
	}
	out := testUserRecordSet(vectors.Apex, "www", dns.TypeCNAME, 300, "host.other.example.")
	if err := ValidateUserRecordSet(context, out); err != nil {
		t.Fatal(err)
	}
	for _, broken := range []*DnsUserRecordContext{
		nil,
		{Root: vectors.Root, Apex: vectors.Root, TtlRange: vectors.TtlRange},
		{Root: vectors.Root, Apex: "net1.other.example.", TtlRange: vectors.TtlRange},
		{Root: vectors.Root, Apex: vectors.Apex},
		{Root: vectors.Root, Apex: vectors.Apex, TtlRange: [2]uint32{3600, 60}},
	} {
		if err := ValidateUserRecordSet(broken, out); !errors.Is(err, ErrDnsUserRecordRefused) {
			t.Errorf("%+v answered %v", broken, err)
		}
	}
}

// §12.7's _dmarc: the policy every zone publishes passes; ruf, fo, a report address in the root, a
// tag twice, a record that is not DMARC1 first, and a rua that is not mailto: are refused.
func TestValidateDmarcRecord(t *testing.T) {
	root := "zone.example."
	accepted := []string{
		"v=DMARC1; p=reject; sp=reject; np=reject; adkim=s; aspf=s; rua=mailto:abcdefghijklmnopqrstuvwxyz@rpt.other.example",
		"v=DMARC1; p=reject; adkim=s; aspf=s; psd=y",
		"v=DMARC1;p=reject;rua=mailto:a@rpt.other.example!10m,mailto:b@rpt.other.example",
		"v=DMARC1; p=reject; rua=mailto:root@notzone.example",
	}
	for _, record := range accepted {
		if err := ValidateDmarcRecord(root, record); err != nil {
			t.Errorf("%q refused: %v", record, err)
		}
	}
	refused := []string{
		"v=DMARC1; p=reject; ruf=mailto:a@rpt.other.example",
		"v=DMARC1; p=reject; RUF=mailto:a@rpt.other.example",
		"v=DMARC1; p=reject; fo=1",
		"v=DMARC1; p=reject; rua=mailto:a@zone.example",
		"v=DMARC1; p=reject; rua=mailto:a@net1.zone.example",
		"v=DMARC1; p=reject; rua=mailto:a@NET1.ZONE.EXAMPLE.",
		"v=DMARC1; p=reject; rua=mailto:a@rpt.other.example,mailto:b@zone.example",
		"v=DMARC1; p=reject; rua=mailto:a%40b@net1.zone.example",
		"v=DMARC1; p=reject; rua=https://report.other.example",
		"v=DMARC1; p=reject; rua=mailto:nobody",
		"v=DMARC1; p=reject; p=none",
		"v=DMARC1",
		"p=reject; v=DMARC1",
		"v=spf1 -all",
		"; v=DMARC1; p=reject; ruf=mailto:a@rpt.other.example",
	}
	for _, record := range refused {
		if err := ValidateDmarcRecord(root, record); !errors.Is(err, ErrDnsDmarcRefused) {
			t.Errorf("%q answered %v", record, err)
		}
	}
}

// A system row of the test zone.
func testSystemRow(owner string, rrType uint16, rdata ...string) DnsRecordSet {
	return DnsRecordSet{Owner: owner, Type: rrType, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: rdata}
}

// The lint over each writer's result: a CNAME beside a system record, beside a copy row, at a
// wildcard, and a DMARC record with ruf, fo or report mail into the root, each refuse the write; an
// owner the write did not change is not judged.
func TestLintZoneWrite(t *testing.T) {
	apex := "net1.zone.example."
	before := []DnsRecordSet{
		testSystemRow(apex, dns.TypeMX, "10 mx.net1.zone.example."),
		testSystemRow("*."+apex, dns.TypeMX, "10 mx.net1.zone.example."),
		testSystemRow("_dmarc."+apex, dns.TypeTXT, `"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:token@rpt.other.example"`),
		testSystemRow("www."+apex, dns.TypeTXT, `"system text"`),
		// an older release's row, which a write elsewhere does not answer for
		{Owner: "old." + apex, Type: dns.TypeCNAME, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"host.other.example."}},
		testSystemRow("old."+apex, dns.TypeTXT, `"beside"`),
	}
	cname := func(owner string) DnsRecordSet {
		return DnsRecordSet{Owner: owner, Type: dns.TypeCNAME, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"host.other.example."}}
	}
	if err := LintZoneWrite(testRoot, before, DnsRowsAfter(before, []DnsRecordSet{cname("blog." + apex)}, nil)); err != nil {
		t.Fatalf("a CNAME alone, with an older owner unchanged: %v", err)
	}
	refusedWrites := []struct {
		why     string
		upserts []DnsRecordSet
	}{
		{why: "a CNAME beside a system record", upserts: []DnsRecordSet{cname("www." + apex)}},
		{why: "a CNAME beside a copy row", upserts: []DnsRecordSet{cname("shop." + apex), {Owner: "shop." + apex, Type: DnsCopyType, Kind: DnsRecordKindCopy}}},
		{why: "a wildcard CNAME", upserts: []DnsRecordSet{cname("*.blog." + apex)}},
		{why: "a system CNAME at *", upserts: []DnsRecordSet{{Owner: "*." + apex, Type: dns.TypeCNAME, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: []string{"edge.other.example."}}}},
		{why: "ruf", upserts: []DnsRecordSet{testSystemRow("_dmarc."+apex, dns.TypeTXT, `"v=DMARC1; p=reject; ruf=mailto:token@rpt.other.example"`)}},
		{why: "fo", upserts: []DnsRecordSet{testSystemRow("_dmarc."+apex, dns.TypeTXT, `"v=DMARC1; p=reject; fo=1"`)}},
		{why: "report mail into the root", upserts: []DnsRecordSet{testSystemRow("_dmarc."+apex, dns.TypeTXT, `"v=DMARC1; p=reject; rua=mailto:token@net1.zone.example"`)}},
		{why: "a scope's report mail into the root", upserts: []DnsRecordSet{testSystemRow("_dmarc.team."+apex, dns.TypeTXT, `"v=DMARC1; p=reject; rua=mailto:token@zone.example"`)}},
		{why: "the old owner touched", upserts: []DnsRecordSet{testSystemRow("old."+apex, dns.TypeTXT, `"changed"`)}},
	}
	for _, refused := range refusedWrites {
		if err := LintZoneWrite(testRoot, before, DnsRowsAfter(before, refused.upserts, nil)); !errors.Is(err, ErrDnsZoneLint) {
			t.Errorf("%s answered %v", refused.why, err)
		}
	}
	// deleting what sat beside a CNAME clears the owner
	if err := LintZoneWrite(testRoot, before, DnsRowsAfter(before, nil, []DnsRecordKey{{Owner: "old." + apex, Type: dns.TypeTXT}})); err != nil {
		t.Fatalf("a delete that leaves the CNAME alone: %v", err)
	}
}

// DnsRowsAfter replaces at a key, deletes, and leaves the rows it was given alone.
func TestDnsRowsAfter(t *testing.T) {
	rows := []DnsRecordSet{
		testSystemRow("a.zone.example.", dns.TypeTXT, `"one"`),
		testSystemRow("b.zone.example.", dns.TypeTXT, `"two"`),
	}
	after := DnsRowsAfter(rows,
		[]DnsRecordSet{testSystemRow("a.zone.example.", dns.TypeTXT, `"three"`), testSystemRow("c.zone.example.", dns.TypeTXT, `"four"`)},
		[]DnsRecordKey{{Owner: "b.zone.example.", Type: dns.TypeTXT}},
	)
	got := []string{}
	for _, row := range after {
		got = append(got, row.Owner+" "+row.Rdata[0])
	}
	if !slices.Equal(got, []string{`a.zone.example. "three"`, `c.zone.example. "four"`}) {
		t.Fatalf("after %v", got)
	}
	after[0].Rdata[0] = "changed"
	if rows[0].Rdata[0] != `"one"` {
		t.Fatal("the result shares rdata with its input")
	}
}
