package dnsservice

import (
	"slices"
	"testing"

	"github.com/miekg/dns"
)

// Copy planning (DNS-M5-02, D-DNS-11): a first child adds a copy at each empty non-terminal it makes,
// a last child removes them, an owner gaining its own record drops its copy, deep names, a wildcard's
// own child, a canary-only host, a zone with no wildcard, and rows outside the zone left alone; and a
// planned copy answers *'s records through a ZoneView.

const testCopyApex = "net1." + testRoot

// A network zone's system rows: its MX at @ and *, and the edge's addresses at *.
func testCopyZoneRows() []DnsRecordSet {
	return []DnsRecordSet{
		testSystemRow(testCopyApex, dns.TypeMX, "10 mx.net1.zone.example."),
		testSystemRow("*."+testCopyApex, dns.TypeMX, "10 mx.net1.zone.example."),
		{Owner: "*." + testCopyApex, Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindEdge},
	}
}

// A user row at owner, relative to the test zone.
func testCopyUserRow(owner string, rrType uint16, rdata ...string) DnsRecordSet {
	return *testUserRecordSet(testCopyApex, owner, rrType, 300, rdata...)
}

// The owners a plan upserts and deletes, relative to the test zone.
func testCopyPlan(t *testing.T, rows []DnsRecordSet) (added []string, removed []string) {
	t.Helper()
	upserts, deletes := PlanCopyRows(testCopyApex, rows)
	relative := func(owner string) string {
		return owner[:len(owner)-len("."+testCopyApex)]
	}
	for _, row := range upserts {
		if row.Kind != DnsRecordKindCopy || row.Type != DnsCopyType || len(row.Rdata) != 0 || row.Validate(testRoot) != nil {
			t.Fatalf("planned %+v, which is not a copy row", row)
		}
		added = append(added, relative(row.Owner))
	}
	for _, key := range deletes {
		if key.Type != DnsCopyType {
			t.Fatalf("planned deleting %+v", key)
		}
		removed = append(removed, relative(key.Owner))
	}
	// a plan applied leaves nothing to plan
	if again, againDeletes := PlanCopyRows(testCopyApex, DnsRowsAfter(rows, upserts, deletes)); len(again) != 0 || len(againDeletes) != 0 {
		t.Fatalf("planning again gave %v and %v", again, againDeletes)
	}
	return added, removed
}

func requireCopyPlan(t *testing.T, rows []DnsRecordSet, wantAdded []string, wantRemoved []string) []DnsRecordSet {
	t.Helper()
	added, removed := testCopyPlan(t, rows)
	if !slices.Equal(added, wantAdded) || !slices.Equal(removed, wantRemoved) {
		t.Fatalf("planned adding %v and removing %v, want %v and %v", added, removed, wantAdded, wantRemoved)
	}
	upserts, deletes := PlanCopyRows(testCopyApex, rows)
	return DnsRowsAfter(rows, upserts, deletes)
}

// _sip._tcp.blog's first write makes blog and _tcp.blog empty non-terminals, each given a copy; its
// removal, the last child, takes both away.
func TestPlanCopyRowsFirstAndLastChild(t *testing.T) {
	rows := testCopyZoneRows()
	requireCopyPlan(t, rows, nil, nil)
	srv := testCopyUserRow("_sip._tcp.blog", dns.TypeSRV, "10 5 5060 sip.other.example.")
	rows = requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{srv}, nil), []string{"_tcp.blog", "blog"}, nil)
	second := testCopyUserRow("_xmpp._tcp.blog", dns.TypeSRV, "10 5 5222 xmpp.other.example.")
	rows = requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{second}, nil), nil, nil)
	rows = requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{srv.Key()}), nil, nil)
	requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{second.Key()}), nil, []string{"_tcp.blog", "blog"})
}

// An owner that gains a record of its own drops its copy, and so does a non-terminal below it that it
// now blocks the wildcard from; losing the record brings both back.
func TestPlanCopyRowsOwnerGainingItsOwnRecord(t *testing.T) {
	rows := requireCopyPlan(t, append(testCopyZoneRows(), testCopyUserRow("_sip._tcp.blog", dns.TypeSRV, "10 5 5060 sip.other.example.")), []string{"_tcp.blog", "blog"}, nil)
	address := testCopyUserRow("blog", dns.TypeA, "11.22.33.44")
	rows = requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{address}, nil), nil, []string{"_tcp.blog", "blog"})
	requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{address.Key()}), []string{"_tcp.blog", "blog"}, nil)
}

// Every empty non-terminal of a deep name gets a copy, and a wildcard host below one of them answers
// for the names under it instead of *.
func TestPlanCopyRowsDeepNames(t *testing.T) {
	rows := requireCopyPlan(t, append(testCopyZoneRows(), testCopyUserRow("_sel._d.c.b", dns.TypeTXT, `"text"`)), []string{"_d.c.b", "b", "c.b"}, nil)
	// b gains a wildcard of its own: c.b now falls to *.b, still covered, so nothing moves
	requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{testCopyUserRow("*.b", dns.TypeA, "11.22.33.44")}, nil), nil, nil)
}

// A wildcard host is its parent's child: *.blog makes blog an empty non-terminal, which keeps *'s
// records through a copy.
func TestPlanCopyRowsWildcardsOwnChild(t *testing.T) {
	requireCopyPlan(t, append(testCopyZoneRows(), testCopyUserRow("*.blog", dns.TypeA, "11.22.33.44")), []string{"blog"}, nil)
}

// A strong-mode probe's CAA canary makes its host exist, and a copy keeps the host's addresses from *
// while it stands; the canary's deletion drops the copy. A host with records of its own gets none.
func TestPlanCopyRowsCanaryOnlyHost(t *testing.T) {
	canary := DnsRecordSet{Owner: "shop." + testCopyApex, Type: dns.TypeCAA, Ttl: 60, Kind: DnsRecordKindCanary, Rdata: []string{`0 issue "ca.example"`}}
	rows := requireCopyPlan(t, append(testCopyZoneRows(), canary), []string{"shop"}, nil)
	requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{canary.Key()}), nil, []string{"shop"})
	withAddress := append(testCopyZoneRows(), testCopyUserRow("shop", dns.TypeA, "11.22.33.44"), canary)
	requireCopyPlan(t, withAddress, nil, nil)
}

// With no wildcard above them, empty non-terminals keep no copy: <root>'s acme.<root> for its
// challenge targets is one. Rows outside the zone are neither read nor planned, a stray copy row
// outside included, and a copy row with nothing below it is removed.
func TestPlanCopyRowsNoWildcardAndOutsideTheZone(t *testing.T) {
	rootRows := []DnsRecordSet{
		testSystemRow(testRoot, dns.TypeTXT, `"v=spf1 -all"`),
		{Owner: "tokenvalue.acme." + testRoot, Type: dns.TypeTXT, Ttl: 60, Kind: DnsRecordKindChallenge, Rdata: []string{`"challenge"`}},
	}
	if upserts, deletes := PlanCopyRows(testRoot, rootRows); len(upserts) != 0 || len(deletes) != 0 {
		t.Fatalf("planned %v and %v in a zone with no wildcard", upserts, deletes)
	}
	rows := append(testCopyZoneRows(),
		DnsRecordSet{Owner: "blog.net2." + testRoot, Type: DnsCopyType, Kind: DnsRecordKindCopy},
		testSystemRow("x.y.net2."+testRoot, dns.TypeTXT, `"other zone"`),
		DnsRecordSet{Owner: "stale." + testCopyApex, Type: DnsCopyType, Kind: DnsRecordKindCopy},
	)
	requireCopyPlan(t, rows, nil, []string{"stale"})
}

// What a plan writes, a ZoneView answers: blog, given a copy by _sip._tcp.blog, answers *'s MX, and
// _sip._tcp.blog still answers its own SRV.
func TestPlannedCopyRowsAnswerFromTheWildcard(t *testing.T) {
	rows := append(testApexRows(), testCopyZoneRows()...)
	rows = append(rows, testCopyUserRow("_sip._tcp.blog", dns.TypeSRV, "10 5 5060 sip.other.example."))
	upserts, deletes := PlanCopyRows(testCopyApex, rows)
	view := newTestView(t, 100, DnsRowsAfter(rows, upserts, deletes)...)
	reply := testAnswer(t, view, nil, "blog."+testCopyApex, dns.TypeMX)
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 || reply.Answer[0].Header().Name != "blog."+testCopyApex {
		t.Fatalf("blog answered %v", reply)
	}
	if mx, ok := reply.Answer[0].(*dns.MX); !ok || mx.Mx != "mx."+testCopyApex {
		t.Fatalf("blog answered %v", reply.Answer)
	}
	reply = testAnswer(t, view, nil, "_sip._tcp.blog."+testCopyApex, dns.TypeSRV)
	if len(reply.Answer) != 1 {
		t.Fatalf("the SRV answered %v", reply)
	}

	// without the plan, blog is an empty non-terminal and answers nothing
	unplanned := newTestView(t, 101, rows...)
	if reply := testAnswer(t, unplanned, nil, "blog."+testCopyApex, dns.TypeMX); len(reply.Answer) != 0 {
		t.Fatalf("an unplanned empty non-terminal answered %v", reply.Answer)
	}
}
