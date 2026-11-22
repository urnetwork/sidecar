package dnsservice

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Copy planning (DNS-M5-02, D-DNS-11, QD-1190): every owner below the zone's apex that exists with no address or
// CNAME of its own and a wildcard above it holds one copy. A first child adds one at each empty non-terminal it makes
// and at itself, and a last child removes them; a user record at a published host adds one there, and its removal
// takes it away; a host with an address of its own keeps only that, and one with a CNAME takes none; deep names, a
// wildcard's own child, a canary-only host, the system set's owners, a Team scope's apex, a suspension's owners, a
// zone with no wildcard, and rows outside the zone. What a plan writes, a ZoneView answers from the wildcard, signed,
// and through a weak-mode custom host's CNAME too.

const testCopyApex = "net1." + testRoot

// A network zone's system rows: its MX at @ and *, and the edge's addresses at *.
func testCopyZoneRows() []DnsRecordSet {
	return []DnsRecordSet{
		testSystemRow(testCopyApex, dns.TypeMX, "10 mx.net1.zone.example."),
		testSystemRow("*."+testCopyApex, dns.TypeMX, "10 mx.net1.zone.example."),
		{Owner: "*." + testCopyApex, Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindEdge},
		{Owner: "*." + testCopyApex, Type: dns.TypeAAAA, Ttl: 60, Kind: DnsRecordKindEdge},
	}
}

// A user row at owner, relative to the test zone.
func testCopyUserRow(owner string, rrType uint16, rdata ...string) DnsRecordSet {
	return *testUserRecordSet(testCopyApex, owner, rrType, 300, rdata...)
}

// A copy row at owner, relative to the test zone.
func testCopyRow(owner string) DnsRecordSet {
	return DnsRecordSet{Owner: owner + "." + testCopyApex, Type: DnsCopyType, Kind: DnsRecordKindCopy}
}

// A suspension's withheld owner at owner, relative to the test zone, "@" for the apex.
func testCopyWithheldRow(owner string) DnsRecordSet {
	if owner == "@" {
		return DnsRecordSet{Owner: testCopyApex, Type: DnsWithheldType, Kind: DnsRecordKindWithheld}
	}
	return DnsRecordSet{Owner: owner + "." + testCopyApex, Type: DnsWithheldType, Kind: DnsRecordKindWithheld}
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

// _sip._tcp.blog's first write makes blog and _tcp.blog empty non-terminals, and is itself an owner with no
// address, each given a copy; a second SRV beside it adds its own; the first's removal takes its copy, and the last
// child's takes the rest.
func TestPlanCopyRowsFirstAndLastChild(t *testing.T) {
	rows := testCopyZoneRows()
	requireCopyPlan(t, rows, nil, nil)
	srv := testCopyUserRow("_sip._tcp.blog", dns.TypeSRV, "10 5 5060 sip.other.example.")
	rows = requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{srv}, nil), []string{"_sip._tcp.blog", "_tcp.blog", "blog"}, nil)
	second := testCopyUserRow("_xmpp._tcp.blog", dns.TypeSRV, "10 5 5222 xmpp.other.example.")
	rows = requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{second}, nil), []string{"_xmpp._tcp.blog"}, nil)
	rows = requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{srv.Key()}), nil, []string{"_sip._tcp.blog"})
	requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{second.Key()}), nil, []string{"_tcp.blog", "_xmpp._tcp.blog", "blog"})
}

// An owner that gains an address of its own drops its copy, and so do the names below it that it now blocks the
// wildcard from; losing the address brings them all back. One that gains a TXT keeps its copy, while the names
// below it lose theirs.
func TestPlanCopyRowsOwnerGainingItsOwnRecord(t *testing.T) {
	everyCopy := []string{"_sip._tcp.blog", "_tcp.blog", "blog"}
	rows := requireCopyPlan(t, append(testCopyZoneRows(), testCopyUserRow("_sip._tcp.blog", dns.TypeSRV, "10 5 5060 sip.other.example.")), everyCopy, nil)
	address := testCopyUserRow("blog", dns.TypeA, "11.22.33.44")
	withAddress := requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{address}, nil), nil, everyCopy)
	requireCopyPlan(t, DnsRowsAfter(withAddress, nil, []DnsRecordKey{address.Key()}), everyCopy, nil)
	txt := testCopyUserRow("blog", dns.TypeTXT, `"text"`)
	withTxt := requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{txt}, nil), nil, []string{"_sip._tcp.blog", "_tcp.blog"})
	requireCopyPlan(t, DnsRowsAfter(withTxt, nil, []DnsRecordKey{txt.Key()}), []string{"_sip._tcp.blog", "_tcp.blog"}, nil)
}

// Every empty non-terminal of a deep name gets a copy, as does the name, and a wildcard host below one of them
// answers for the names under it instead of *.
func TestPlanCopyRowsDeepNames(t *testing.T) {
	rows := requireCopyPlan(t, append(testCopyZoneRows(), testCopyUserRow("_sel._d.c.b", dns.TypeTXT, `"text"`)), []string{"_d.c.b", "_sel._d.c.b", "b", "c.b"}, nil)
	// b gains a wildcard of its own: c.b and what is below it now fall to *.b, still covered, so nothing moves
	requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{testCopyUserRow("*.b", dns.TypeA, "11.22.33.44")}, nil), nil, nil)
}

// A wildcard host is its parent's child: *.blog makes blog an empty non-terminal, which keeps *'s records through a
// copy, and so does a TXT at blog beside it, since a user's wildcard makes no scope.
func TestPlanCopyRowsWildcardsOwnChild(t *testing.T) {
	wildcard := testCopyUserRow("*.blog", dns.TypeA, "11.22.33.44")
	requireCopyPlan(t, append(testCopyZoneRows(), wildcard), []string{"blog"}, nil)
	requireCopyPlan(t, append(testCopyZoneRows(), wildcard, testCopyUserRow("blog", dns.TypeTXT, `"text"`)), []string{"blog"}, nil)
}

// A strong-mode probe's CAA canary makes its host exist, and a copy keeps the host's addresses from * while it
// stands; the canary's deletion drops the copy. A host with an address of its own gets none, and one with a TXT
// beside the canary keeps its copy.
func TestPlanCopyRowsCanaryOnlyHost(t *testing.T) {
	canary := DnsRecordSet{Owner: "shop." + testCopyApex, Type: dns.TypeCAA, Ttl: 60, Kind: DnsRecordKindCanary, Rdata: []string{`0 issue "ca.example"`}}
	rows := requireCopyPlan(t, append(testCopyZoneRows(), canary), []string{"shop"}, nil)
	requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{canary.Key()}), nil, []string{"shop"})
	withAddress := append(testCopyZoneRows(), testCopyUserRow("shop", dns.TypeA, "11.22.33.44"), canary)
	requireCopyPlan(t, withAddress, nil, nil)
	withTxt := requireCopyPlan(t, append(testCopyZoneRows(), testCopyUserRow("shop", dns.TypeTXT, `"text"`), canary), []string{"shop"}, nil)
	requireCopyPlan(t, DnsRowsAfter(withTxt, nil, []DnsRecordKey{canary.Key()}), nil, nil)
}

// QD-1190: a TXT at a published host, which answers its addresses from * alone, gives the host a copy, so it keeps
// answering them; an MX beside it adds nothing; the TXT's removal while the MX stays keeps the copy, and the host's
// last record's removal takes it, nothing left at the host, which answers from * as any name does. A TXT written
// and removed alone takes its copy in and out with it.
func TestPlanCopyRowsUserRecordAtAPublishedHost(t *testing.T) {
	rows := testCopyZoneRows()
	txt := testCopyUserRow("web", dns.TypeTXT, `"site-verification=token"`)
	rows = requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{txt}, nil), []string{"web"}, nil)
	mx := testCopyUserRow("web", dns.TypeMX, "10 mail.other.example.")
	rows = requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{mx}, nil), nil, nil)
	rows = requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{txt.Key()}), nil, nil)
	rows = requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{mx.Key()}), nil, []string{"web"})
	for _, row := range rows {
		if row.Owner == "web."+testCopyApex {
			t.Errorf("the host's last record's removal left %+v", row)
		}
	}
	rows = requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{txt}, nil), []string{"web"}, nil)
	requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{txt.Key()}), nil, []string{"web"})
}

// A host with an address of its own keeps only its own: a TXT beside an A takes no copy, an A or an AAAA written at
// a host holding a copy drops it, and the address's removal brings the copy back.
func TestPlanCopyRowsHostWithAnAddressKeepsOnlyIt(t *testing.T) {
	txt := testCopyUserRow("web", dns.TypeTXT, `"site-verification=token"`)
	address := testCopyUserRow("web", dns.TypeA, "11.22.33.44")
	requireCopyPlan(t, append(testCopyZoneRows(), txt, address), nil, nil)
	rows := requireCopyPlan(t, append(testCopyZoneRows(), txt), []string{"web"}, nil)
	for _, own := range []DnsRecordSet{address, testCopyUserRow("web", dns.TypeAAAA, "2001:db8::7")} {
		withOwn := requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{own}, nil), nil, []string{"web"})
		requireCopyPlan(t, DnsRowsAfter(withOwn, nil, []DnsRecordKey{own.Key()}), []string{"web"}, nil)
	}
}

// A host with a CNAME takes no copy, since nothing stands beside a CNAME: a CNAME alone gets none; a CNAME replacing
// a host's TXT drops its copy in the same write, which the lint refuses without the plan's delete; and an empty
// non-terminal given a CNAME drops its copy and those of the names below it, which it now blocks.
func TestPlanCopyRowsHostWithACnameTakesNoCopy(t *testing.T) {
	cname := testCopyUserRow("web", dns.TypeCNAME, "web.other.example.")
	requireCopyPlan(t, append(testCopyZoneRows(), cname), nil, nil)

	txt := testCopyUserRow("web", dns.TypeTXT, `"site-verification=token"`)
	before := requireCopyPlan(t, append(testCopyZoneRows(), txt), []string{"web"}, nil)
	written := DnsRowsAfter(before, []DnsRecordSet{cname}, []DnsRecordKey{txt.Key()})
	if err := LintZoneWrite(testRoot, before, written); !errors.Is(err, ErrDnsZoneLint) {
		t.Fatalf("a CNAME beside the host's copy linted %v", err)
	}
	after := requireCopyPlan(t, written, nil, []string{"web"})
	if err := LintZoneWrite(testRoot, before, after); err != nil {
		t.Fatal(err)
	}

	everyCopy := []string{"_sip._tcp.blog", "_tcp.blog", "blog"}
	before = requireCopyPlan(t, append(testCopyZoneRows(), testCopyUserRow("_sip._tcp.blog", dns.TypeSRV, "10 5 5060 sip.other.example.")), everyCopy, nil)
	after = requireCopyPlan(t, DnsRowsAfter(before, []DnsRecordSet{testCopyUserRow("blog", dns.TypeCNAME, "blog.other.example.")}, nil), nil, everyCopy)
	if err := LintZoneWrite(testRoot, before, after); err != nil {
		t.Fatal(err)
	}
}

// §12.7's system set: each owner of it with no address of its own, under * with nothing of its own above it, keeps
// *'s records by a copy, as a user's owner does: _dmarc, mail's b, _mta-sts and _smtp._tls with _tls above it. mx's
// router addresses are its own, and what stands below mx, _25._tcp.mx's TLSA and _tcp.mx, lies past mx's rows and
// takes none.
func TestPlanCopyRowsSystemOwners(t *testing.T) {
	rows := append(testCopyZoneRows(),
		testSystemRow(testCopyApex, dns.TypeTXT, `"v=spf1 -all"`),
		testSystemRow("_dmarc."+testCopyApex, dns.TypeTXT, `"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"`),
		DnsRecordSet{Owner: "mx." + testCopyApex, Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindRouter},
		DnsRecordSet{Owner: "mx." + testCopyApex, Type: dns.TypeAAAA, Ttl: 60, Kind: DnsRecordKindRouter},
		DnsRecordSet{Owner: "_25._tcp.mx." + testCopyApex, Type: dns.TypeTLSA, Ttl: 300, Kind: DnsRecordKindKey, Rdata: []string{"3 1 1 " + strings.Repeat("ab", 32)}},
		testSystemRow("b."+testCopyApex, dns.TypeMX, "10 mx.net1.zone.example."),
		testSystemRow("b."+testCopyApex, dns.TypeTXT, `"v=spf1 include:_spf.zone.example -all"`),
		testSystemRow("_mta-sts."+testCopyApex, dns.TypeTXT, `"v=STSv1; id=1"`),
		testSystemRow("_smtp._tls."+testCopyApex, dns.TypeTXT, `"v=TLSRPTv1; rua=mailto:token@rpt.other.example"`),
	)
	requireCopyPlan(t, rows, []string{"_dmarc", "_mta-sts", "_smtp._tls", "_tls", "b"}, nil)
}

// A Team scope's apex is a zone apex of its own (owner decisions 40, 58): with its set's system MX at *.<scope>, the
// scope's apex takes no copy, its addresses staying its own @'s (owner decision 335), while the scope's owners below
// it, system and user, copy *.<scope>'s records as the network's copy *'s.
func TestPlanCopyRowsScopeApexTakesNoCopy(t *testing.T) {
	scopeApex := "team." + testCopyApex
	rows := append(testCopyZoneRows(),
		testSystemRow(scopeApex, dns.TypeMX, "10 mx.team.net1.zone.example."),
		testSystemRow(scopeApex, dns.TypeTXT, `"v=spf1 -all"`),
		testSystemRow("*."+scopeApex, dns.TypeMX, "10 mx.team.net1.zone.example."),
		testSystemRow("_dmarc."+scopeApex, dns.TypeTXT, `"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"`),
	)
	rows = requireCopyPlan(t, rows, []string{"_dmarc.team"}, nil)
	requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{testCopyUserRow("web.team", dns.TypeTXT, `"text"`)}, nil), []string{"web.team"}, nil)
}

// A suspension's withheld owner and every name below it keep what they hold (§12.9): a suspended host's copy stays
// for Restore, a host suspended with nothing of its own takes no copy while withheld, and copies below a suspended
// host stay though it blocks the wildcard from them now, whether the rows read are the zone's stored ones or what
// edges serve; a write beside them plans its own owner, and once Restore has put every row back the plan finds each
// copy as it stood. A zone suspension holds every name below its apex.
func TestPlanCopyRowsLeavesASuspensionsOwnersAlone(t *testing.T) {
	withheldRows := []DnsRecordSet{
		// web held a TXT and its copy when it was suspended
		testCopyUserRow("web", dns.TypeTXT, `"site-verification=token"`),
		testCopyRow("web"),
		// blog was an empty non-terminal over an SRV
		testCopyUserRow("_sip._tcp.blog", dns.TypeSRV, "10 5 5060 sip.other.example."),
		testCopyRow("_sip._tcp.blog"),
		testCopyRow("_tcp.blog"),
		testCopyRow("blog"),
	}
	// shop answered from * alone
	markers := []DnsRecordSet{testCopyWithheldRow("web"), testCopyWithheldRow("shop"), testCopyWithheldRow("blog")}
	stored := slices.Concat(testCopyZoneRows(), withheldRows, markers)
	served := slices.Concat(testCopyZoneRows(), markers)
	for _, rows := range [][]DnsRecordSet{stored, served} {
		rows = requireCopyPlan(t, rows, nil, nil)
		requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{testCopyUserRow("news", dns.TypeTXT, `"text"`)}, nil), []string{"news"}, nil)
	}
	markerKeys := []DnsRecordKey{}
	for _, marker := range markers {
		markerKeys = append(markerKeys, marker.Key())
	}
	requireCopyPlan(t, DnsRowsAfter(stored, nil, markerKeys), nil, nil)

	zone := append(testCopyZoneRows(), testCopyWithheldRow("@"), testCopyUserRow("web", dns.TypeTXT, `"text"`), testCopyRow("stale"))
	requireCopyPlan(t, zone, nil, nil)
}

// With no wildcard above them, empty non-terminals keep no copy: <root>'s acme.<root> for its challenge targets is
// one. Rows outside the zone are neither read nor planned, a stray copy row outside included, and a copy row with
// nothing below it is removed.
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
		testCopyRow("stale"),
	)
	requireCopyPlan(t, rows, nil, []string{"stale"})
}

// What a plan writes, a ZoneView answers: blog, given a copy by _sip._tcp.blog, answers *'s MX, and _sip._tcp.blog
// still answers its own SRV, and for MX *'s.
func TestPlannedCopyRowsAnswerFromTheWildcard(t *testing.T) {
	rows := append(testApexRows(), testCopyZoneRows()...)
	rows = append(rows, testCopyUserRow("_sip._tcp.blog", dns.TypeSRV, "10 5 5060 sip.other.example."))
	upserts, deletes := PlanCopyRows(testCopyApex, rows)
	view := newTestView(t, 100, DnsRowsAfter(rows, upserts, deletes)...)
	for _, name := range []string{"blog." + testCopyApex, "_sip._tcp.blog." + testCopyApex} {
		reply := testAnswer(t, view, nil, name, dns.TypeMX)
		if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 || reply.Answer[0].Header().Name != name {
			t.Fatalf("%s answered %v", name, reply)
		}
		if mx, ok := reply.Answer[0].(*dns.MX); !ok || mx.Mx != "mx."+testCopyApex {
			t.Fatalf("%s answered %v", name, reply.Answer)
		}
	}
	reply := testAnswer(t, view, nil, "_sip._tcp.blog."+testCopyApex, dns.TypeSRV)
	if len(reply.Answer) != 1 {
		t.Fatalf("the SRV answered %v", reply)
	}

	// without the plan, blog is an empty non-terminal and answers nothing
	unplanned := newTestView(t, 101, rows...)
	if reply := testAnswer(t, unplanned, nil, "blog."+testCopyApex, dns.TypeMX); len(reply.Answer) != 0 {
		t.Fatalf("an unplanned empty non-terminal answered %v", reply.Answer)
	}
}

// Two healthy lb interfaces, and the same with lb-1 dropped, on documentation addresses.
func testCopyHealthySets() (both *HealthySet, dropped *HealthySet) {
	lb1 := DnsLbInterface{Name: "lb-1", Ipv4: netip.MustParseAddr("192.0.2.1"), Ipv6: netip.MustParseAddr("2001:db8::1")}
	lb2 := DnsLbInterface{Name: "lb-2", Ipv4: netip.MustParseAddr("192.0.2.2"), Ipv6: netip.MustParseAddr("2001:db8::2")}
	return NewHealthySet([]DnsLbInterface{lb1, lb2}, nil), NewHealthySet([]DnsLbInterface{lb2}, nil)
}

// A reply's answer records but signatures, each its rdata as one line, sorted.
func testCopyDataLines(reply *dns.Msg) []string {
	lines := []string{}
	for _, record := range reply.Answer {
		if record.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		lines = append(lines, strings.TrimPrefix(record.String(), record.Header().String()))
	}
	slices.Sort(lines)
	return lines
}

// The types the denial's NSEC names, nil when it carries none.
func testCopyDenialTypes(reply *dns.Msg) []uint16 {
	for _, record := range reply.Ns {
		if nsec, ok := record.(*dns.NSEC); ok {
			return nsec.TypeBitMap
		}
	}
	return nil
}

// A published host's zone signed under the test keys: the root's apex, the network's system rows, and a
// site-verification TXT at web, with and without the copy the write plans.
type testCopySignedZone struct {
	signing *testSigning
	signer  *Signer
	planned *ZoneView
	// what the zone would serve had the write planned no copy
	unplanned     *ZoneView
	plannedKeys   *DnsSigningKeys
	unplannedKeys *DnsSigningKeys
}

func newTestCopySignedZone(t *testing.T) *testCopySignedZone {
	t.Helper()
	rows := append([]DnsRecordSet{
		{Owner: testRoot, Type: dns.TypeSOA, Ttl: 3600, Kind: DnsRecordKindSystem, Rdata: []string{"ns1.zone.example. hostmaster.zone.example. 1 7200 3600 1209600 60"}},
		{Owner: testRoot, Type: dns.TypeNS, Ttl: 86400, Kind: DnsRecordKindSystem, Rdata: []string{"ns1.zone.example."}},
	}, testCopyZoneRows()...)
	rows = DnsRowsAfter(rows, []DnsRecordSet{testCopyUserRow("web", dns.TypeTXT, `"site-verification=token"`)}, nil)
	upserts, deletes := PlanCopyRows(testCopyApex, rows)
	if len(upserts) != 1 || upserts[0].Owner != "web."+testCopyApex || len(deletes) != 0 {
		t.Fatalf("the TXT's write planned %v and %v", upserts, deletes)
	}
	self := &testCopySignedZone{
		signing:   newTestSigning(t, testRoot),
		signer:    NewSigner(signingTestSettings(t, 1000), newTestClock(testSigningNow), nil),
		planned:   newTestView(t, 300, DnsRowsAfter(rows, upserts, deletes)...),
		unplanned: newTestView(t, 301, rows...),
	}
	self.plannedKeys = self.signing.checked(t, self.planned)
	self.unplannedKeys = self.signing.checked(t, self.unplanned)
	return self
}

// What the view answers name with under DO, its every RRset and denial verified against the test KSK.
func (self *testCopySignedZone) answer(t *testing.T, planned bool, healthy *HealthySet, name string, rrType uint16) *dns.Msg {
	t.Helper()
	view, keys := self.planned, self.plannedKeys
	if !planned {
		view, keys = self.unplanned, self.unplannedKeys
	}
	query := signedQuery(name, rrType, false)
	reply := self.signer.Answer(query, view, keys, healthy)
	if err := verifyDnsSignedReply(reply, query.Message.Question[0], true, false, keys, self.signing.anchors, testSigningNow); err != nil {
		t.Fatalf("%s %s: %v\n%v", name, dnsTypeText(rrType), err, reply)
	}
	return reply
}

// QD-1190 at the edge: web, a published host with a site-verification TXT of its own and the copy its write planned,
// answers its own TXT, the healthy addresses for A and AAAA and *'s MX, each signed and verifying under the root's
// keys, a health drop reaching them with no write; a type neither holds is denied by an NSEC at web naming what it
// answers. Without the copy, web answers its A and AAAA with no data.
func TestCopyRowKeepsAPublishedHostsAddressesSigned(t *testing.T) {
	zone := newTestCopySignedZone(t)
	both, dropped := testCopyHealthySets()
	web := "web." + testCopyApex
	for _, c := range []struct {
		healthy *HealthySet
		rrType  uint16
		want    []string
	}{
		{healthy: both, rrType: dns.TypeA, want: []string{"192.0.2.1", "192.0.2.2"}},
		{healthy: both, rrType: dns.TypeAAAA, want: []string{"2001:db8::1", "2001:db8::2"}},
		{healthy: dropped, rrType: dns.TypeA, want: []string{"192.0.2.2"}},
		{healthy: dropped, rrType: dns.TypeAAAA, want: []string{"2001:db8::2"}},
		{healthy: both, rrType: dns.TypeTXT, want: []string{`"site-verification=token"`}},
		{healthy: both, rrType: dns.TypeMX, want: []string{"10 mx.net1.zone.example."}},
	} {
		reply := zone.answer(t, true, c.healthy, web, c.rrType)
		if got := testCopyDataLines(reply); reply.Rcode != dns.RcodeSuccess || !slices.Equal(got, c.want) {
			t.Errorf("web %s answered %s %v, want %v", dnsTypeText(c.rrType), dns.RcodeToString[reply.Rcode], got, c.want)
		}
	}
	reply := zone.answer(t, true, both, web, dns.TypeSRV)
	wantTypes := []uint16{dns.TypeA, dns.TypeMX, dns.TypeTXT, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC}
	if len(reply.Answer) != 0 || !slices.Equal(testCopyDenialTypes(reply), wantTypes) {
		t.Errorf("web SRV answered %v, its NSEC naming %v", reply.Answer, testCopyDenialTypes(reply))
	}

	for _, rrType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		reply := zone.answer(t, false, both, web, rrType)
		if len(reply.Answer) != 0 || slices.Contains(testCopyDenialTypes(reply), rrType) {
			t.Errorf("web %s answered %v with no copy", dnsTypeText(rrType), reply.Answer)
		}
	}
}

// A weak-mode custom host is the customer's CNAME to its owner (§12.8 step 2): a resolver following
// www.customer.example's CNAME to web, which holds a TXT and its copy, reaches the healthy addresses, signed under
// the root's keys, where without the copy it reaches none.
func TestCopyRowKeepsAWeakModeCustomHostResolving(t *testing.T) {
	zone := newTestCopySignedZone(t)
	both, _ := testCopyHealthySets()
	customerRoot := "customer.example."
	customerSettings := answerTestSettings(t)
	customerSettings.Roots = []string{customerRoot}
	if err := customerSettings.Validate(); err != nil {
		t.Fatal(err)
	}
	customerRows := []DnsRecordSet{
		{Owner: customerRoot, Type: dns.TypeSOA, Ttl: 3600, Kind: DnsRecordKindSystem, Rdata: []string{"ns1.customer.example. hostmaster.customer.example. 1 7200 3600 1209600 60"}},
		{Owner: "www." + customerRoot, Type: dns.TypeCNAME, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"web." + testCopyApex}},
	}
	customer, err := NewZoneView(customerSettings, NewDnsSnapshotRows(DnsSnapshot{Format: DnsFormat, Root: customerRoot, Serial: 1}, customerRows))
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(planned bool, rrType uint16) []string {
		// the customer's zone answers its CNAME and stops there, the target outside its root
		reply := testAnswer(t, customer, nil, "www."+customerRoot, rrType)
		if len(reply.Answer) != 1 {
			t.Fatalf("the customer's zone answered %v", reply)
		}
		cname, ok := reply.Answer[0].(*dns.CNAME)
		if !ok || cname.Target != "web."+testCopyApex {
			t.Fatalf("the customer's zone answered %v", reply.Answer)
		}
		return testCopyDataLines(zone.answer(t, planned, both, cname.Target, rrType))
	}
	if got := resolve(true, dns.TypeA); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Errorf("the custom host's A resolved to %v", got)
	}
	if got := resolve(true, dns.TypeAAAA); !slices.Equal(got, []string{"2001:db8::1", "2001:db8::2"}) {
		t.Errorf("the custom host's AAAA resolved to %v", got)
	}
	if got := resolve(false, dns.TypeA); len(got) != 0 {
		t.Errorf("the custom host's A resolved to %v with no copy", got)
	}
}

// A replying burner's selector, as DNS-M9-01's writers plan it (S10; D-DNS-11): one DKIM key at
// <sel>._domainkey.<blabel>.
func testCopyBurnerSelector(selector string, blabel string) DnsRecordSet {
	return DnsRecordSet{
		Owner: selector + "._domainkey." + blabel + "." + testCopyApex,
		Type:  dns.TypeTXT,
		Ttl:   300,
		Kind:  DnsRecordKindKey,
		Rdata: []string{`"v=DKIM1; k=rsa; p=MIIBCgKCAQEA"`},
	}
}

// S10's plan: a replying burner's first selector gives <blabel>, _domainkey.<blabel> below it, and itself, an owner
// with no address, a copy in the same write; a second selector adds its own alone; the first one's removal takes its
// copy, and the last one's takes the rest, back to the wildcard alone; and a receive-only burner, which has no
// selector, has no row at all.
func TestPlanCopyRowsBurnerSelectors(t *testing.T) {
	rows := testCopyZoneRows()
	first := testCopyBurnerSelector("s1", "maple-1234")
	rows = requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{first}, nil), []string{"_domainkey.maple-1234", "maple-1234", "s1._domainkey.maple-1234"}, nil)
	second := testCopyBurnerSelector("s2", "maple-1234")
	rows = requireCopyPlan(t, DnsRowsAfter(rows, []DnsRecordSet{second}, nil), []string{"s2._domainkey.maple-1234"}, nil)
	rows = requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{first.Key()}), nil, []string{"s1._domainkey.maple-1234"})
	rows = requireCopyPlan(t, DnsRowsAfter(rows, nil, []DnsRecordKey{second.Key()}), nil, []string{"_domainkey.maple-1234", "maple-1234", "s2._domainkey.maple-1234"})
	for _, row := range rows {
		if strings.Contains(row.Owner, "maple-1234") {
			t.Errorf("the last selector's removal left %+v", row)
		}
	}
	// another burner's selector plans only its own label
	requireCopyPlan(t, append(testCopyZoneRows(), testCopyBurnerSelector("s1", "cedar-0042")), []string{"_domainkey.cedar-0042", "cedar-0042", "s1._domainkey.cedar-0042"}, nil)
}

// What S10 serves: a replying burner's label answers *'s MX and the healthy addresses through its copy, as one with
// no selector does through *, a health drop reaching both with no write; and the selector answers its key.
func TestBurnerSelectorCopyAnswersTheWildcardsCurrentRecords(t *testing.T) {
	rows := append(testApexRows(), testCopyZoneRows()...)
	selector := testCopyBurnerSelector("s1", "maple-1234")
	rows = DnsRowsAfter(rows, []DnsRecordSet{selector}, nil)
	upserts, deletes := PlanCopyRows(testCopyApex, rows)
	view := newTestView(t, 200, DnsRowsAfter(rows, upserts, deletes)...)
	both, dropped := testCopyHealthySets()
	answerLines := func(healthy *HealthySet, name string, rrType uint16) []string {
		reply := testAnswer(t, view, healthy, name, rrType)
		if reply.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s %s: %s", name, dns.TypeToString[rrType], dns.RcodeToString[reply.Rcode])
		}
		return testCopyDataLines(reply)
	}
	blabel := "maple-1234." + testCopyApex
	other := "birch-0001." + testCopyApex
	for _, name := range []string{blabel, other} {
		if got := answerLines(both, name, dns.TypeMX); !slices.Equal(got, []string{"10 mx.net1.zone.example."}) {
			t.Errorf("%s MX %v", name, got)
		}
		if got := answerLines(both, name, dns.TypeA); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
			t.Errorf("%s A %v", name, got)
		}
		if got := answerLines(dropped, name, dns.TypeA); !slices.Equal(got, []string{"192.0.2.2"}) {
			t.Errorf("%s A after a drop %v", name, got)
		}
		if got := answerLines(dropped, name, dns.TypeAAAA); !slices.Equal(got, []string{"2001:db8::2"}) {
			t.Errorf("%s AAAA after a drop %v", name, got)
		}
	}
	if got := answerLines(both, selector.Owner, dns.TypeTXT); len(got) != 1 {
		t.Errorf("the selector answered %v", got)
	}
}
