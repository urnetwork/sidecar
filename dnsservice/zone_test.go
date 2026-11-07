package dnsservice

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/urnetwork/connect"
)

// A TXT row of the user's.
func testTxt(owner string, text string) DnsRecordSet {
	return DnsRecordSet{Owner: owner, Type: dns.TypeTXT, Ttl: 60, Kind: DnsRecordKindUser, Rdata: []string{`"` + text + `"`}}
}

// The next row of view with these upserts.
func testRow(view *ZoneView, upserts ...DnsRecordSet) DnsJournalRow {
	return DnsJournalRow{Format: DnsFormat, Root: testRoot, Serial: view.Serial() + 1, Upserts: upserts}
}

// The text at owner, or empty.
func testText(t testing.TB, view *ZoneView, owner string) string {
	t.Helper()
	reply := testAnswer(t, view, nil, owner, dns.TypeTXT)
	if len(reply.Answer) == 0 {
		return ""
	}
	return reply.Answer[0].(*dns.TXT).Txt[0]
}

// Rows as a comparable map, each row's rdata in its own order.
func rowsOf(view *ZoneView) map[string]string {
	rows := map[string]string{}
	for set := range view.Rows() {
		rows[fmt.Sprintf("%s/%d", set.Owner, set.Type)] = fmt.Sprintf("%d %s %q", set.Ttl, set.Kind, set.Rdata)
	}
	return rows
}

func TestZoneApplyTakesRowsInOrder(t *testing.T) {
	view := newTestView(t, 10, testApexRows()...)
	next, err := view.Apply([]DnsJournalRow{
		{Format: DnsFormat, Root: testRoot, Serial: 11, Upserts: []DnsRecordSet{testTxt("a.zone.example.", "eleven")}},
		{Format: DnsFormat, Root: testRoot, Serial: 12, Upserts: []DnsRecordSet{testTxt("a.zone.example.", "twelve"), testTxt("b.zone.example.", "twelve")}},
		{Format: DnsFormat, Root: testRoot, Serial: 13, Deletes: []DnsRecordKey{{Owner: "b.zone.example.", Type: dns.TypeTXT}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if next.Serial() != 13 {
		t.Errorf("serial %d", next.Serial())
	}
	if text := testText(t, next, "a.zone.example."); text != "twelve" {
		t.Errorf("a holds %q", text)
	}
	if reply := testAnswer(t, next, nil, "b.zone.example.", dns.TypeTXT); reply.Rcode != dns.RcodeNameError {
		t.Errorf("b reads %+v", reply)
	}
	if view.Serial() != 10 {
		t.Errorf("the earlier view moved to %d", view.Serial())
	}
}

func TestZoneApplyOfNothingIsTheSameView(t *testing.T) {
	view := newTestView(t, 10, testApexRows()...)
	next, err := view.Apply(nil)
	if err != nil {
		t.Fatal(err)
	}
	if next != view {
		t.Error("a new view for no rows")
	}
}

func TestZoneApplyRefusesAGap(t *testing.T) {
	view := newTestView(t, 10, testApexRows()...)
	row := testRow(view, testTxt("a.zone.example.", "one"))
	row.Serial += 1
	next, err := view.Apply([]DnsJournalRow{row})
	if next != nil || !errors.Is(err, ErrDnsSerialGap) {
		t.Errorf("view %v, err %v", next, err)
	}
	// a gap inside a batch refuses the batch
	first := testRow(view, testTxt("a.zone.example.", "one"))
	second := testRow(view, testTxt("b.zone.example.", "two"))
	second.Serial += 2
	next, err = view.Apply([]DnsJournalRow{first, second})
	if next != nil || !errors.Is(err, ErrDnsSerialGap) {
		t.Errorf("view %v, err %v", next, err)
	}
}

func TestZoneApplyNeverLowers(t *testing.T) {
	view := newTestView(t, 10, testApexRows()...)
	for _, serial := range []uint64{10, 9, 1} {
		row := testRow(view, testTxt("a.zone.example.", "one"))
		row.Serial = serial
		next, err := view.Apply([]DnsJournalRow{row})
		if next != nil || !errors.Is(err, ErrDnsSerialLower) {
			t.Errorf("serial %d: view %v, err %v", serial, next, err)
		}
	}
}

// Whatever a refused row held, the view it was offered to answers as before, and the caller gets none.
func TestZoneApplyRefusesWhole(t *testing.T) {
	view := newTestView(t, 10, append(testApexRows(), testTxt("a.zone.example.", "before"))...)
	good := testTxt("a.zone.example.", "after")
	cases := []struct {
		name string
		rows []DnsJournalRow
		want error
	}{
		{
			name: "a format too new",
			rows: []DnsJournalRow{{Format: DnsFormat + 1, Root: testRoot, Serial: 11, Upserts: []DnsRecordSet{good}}},
			want: ErrDnsFormatTooNew,
		},
		{
			name: "another root",
			rows: []DnsJournalRow{{
				Format: DnsFormat, Root: "other.example.", Serial: 11,
				Upserts: []DnsRecordSet{testTxt("a.other.example.", "after")},
			}},
			want: ErrDnsRowMalformed,
		},
		{
			// deletes name no owner this view could hold, so only the row's own root gives it away
			name: "another root's deletes",
			rows: []DnsJournalRow{{
				Format: DnsFormat, Root: "other.example.", Serial: 11,
				Deletes: []DnsRecordKey{{Owner: "a.other.example.", Type: dns.TypeTXT}},
			}},
			want: ErrDnsRowMalformed,
		},
		{
			name: "rdata that does not parse beside a good row",
			rows: []DnsJournalRow{{
				Format: DnsFormat, Root: testRoot, Serial: 11,
				Upserts: []DnsRecordSet{good, {Owner: "b.zone.example.", Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindUser, Rdata: []string{"nope"}}},
			}},
			want: ErrDnsRowMalformed,
		},
		{
			name: "an unknown kind",
			rows: []DnsJournalRow{{
				Format: DnsFormat, Root: testRoot, Serial: 11,
				Upserts: []DnsRecordSet{{Owner: "b.zone.example.", Type: dns.TypeTXT, Ttl: 60, Kind: "later", Rdata: []string{`"x"`}}},
			}},
			want: ErrDnsRowMalformed,
		},
		{
			name: "a good row, then a bad one",
			rows: []DnsJournalRow{
				{Format: DnsFormat, Root: testRoot, Serial: 11, Upserts: []DnsRecordSet{good}},
				{Format: DnsFormat, Root: testRoot, Serial: 12},
			},
			want: ErrDnsRowMalformed,
		},
	}
	for _, c := range cases {
		next, err := view.Apply(c.rows)
		if next != nil || !errors.Is(err, c.want) {
			t.Errorf("%s: view %v, err %v", c.name, next, err)
		}
		if text := testText(t, view, "a.zone.example."); text != "before" {
			t.Errorf("%s: the view reads %q", c.name, text)
		}
		if view.Serial() != 10 {
			t.Errorf("%s: the view moved to %d", c.name, view.Serial())
		}
	}
}

// A view stays whole for as long as anyone holds it: every serial here answers its own text.
func TestZoneApplyLeavesEveryEarlierViewWhole(t *testing.T) {
	view := newTestView(t, 0, testApexRows()...)
	views := []*ZoneView{view}
	for serial := 1; serial <= 200; serial += 1 {
		text := strconv.Itoa(serial)
		next, err := view.Apply([]DnsJournalRow{testRow(view, testTxt("a.zone.example.", text), testTxt("n"+text+".zone.example.", text))})
		if err != nil {
			t.Fatal(err)
		}
		view = next
		views = append(views, view)
	}
	for serial, held := range views {
		text := strconv.Itoa(serial)
		if serial == 0 {
			text = ""
		}
		if got := testText(t, held, "a.zone.example."); got != text {
			t.Errorf("serial %d reads %q", serial, got)
		}
		if serial != 0 {
			if got := testText(t, held, "n"+text+".zone.example."); got != text {
				t.Errorf("serial %d: its own name reads %q", serial, got)
			}
		}
		if reply := testAnswer(t, held, nil, "n"+strconv.Itoa(serial+1)+".zone.example.", dns.TypeTXT); reply.Rcode != dns.RcodeNameError {
			t.Errorf("serial %d sees the next serial's name", serial)
		}
	}
}

// Two builds from one view change apart, as a retry after a refused self-check makes them.
func TestZoneApplyFromOneViewTwiceKeepsBothApart(t *testing.T) {
	view := newTestView(t, 10, append(testApexRows(), testTxt("a.zone.example.", "before"))...)
	first, err := view.Apply([]DnsJournalRow{testRow(view, testTxt("a.zone.example.", "first"))})
	if err != nil {
		t.Fatal(err)
	}
	second, err := view.Apply([]DnsJournalRow{testRow(view, testTxt("a.zone.example.", "second"))})
	if err != nil {
		t.Fatal(err)
	}
	third, err := first.Apply([]DnsJournalRow{testRow(first, testTxt("a.zone.example.", "third"))})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		view *ZoneView
		want string
	}{
		{view: view, want: "before"},
		{view: first, want: "first"},
		{view: second, want: "second"},
		{view: third, want: "third"},
	} {
		if got := testText(t, c.view, "a.zone.example."); got != c.want {
			t.Errorf("reads %q, want %q", got, c.want)
		}
	}
}

// An SOA row's change reaches every answer in the serial that made it: the apex's, and a denial's.
func TestZoneApplyTakesANewSoa(t *testing.T) {
	view := newTestView(t, 1, testApexRows()...)
	next, err := view.Apply([]DnsJournalRow{testRow(view, DnsRecordSet{
		Owner: testRoot, Type: dns.TypeSOA, Ttl: 30, Kind: DnsRecordKindSystem,
		Rdata: []string{"ns2.zone.example. hostmaster.zone.example. 1 7200 3600 1209600 60"},
	})})
	if err != nil {
		t.Fatal(err)
	}
	reply := testAnswer(t, next, nil, "nosuch.zone.example.", dns.TypeA)
	if soa := reply.Ns[0].(*dns.SOA); soa.Ns != "ns2.zone.example." || soa.Hdr.Ttl != 30 || soa.Serial != 2 {
		t.Errorf("soa %v", soa)
	}
	reply = testAnswer(t, next, nil, testRoot, dns.TypeSOA)
	if soa := reply.Answer[0].(*dns.SOA); soa.Ns != "ns2.zone.example." || soa.Hdr.Ttl != 30 {
		t.Errorf("soa %v", soa)
	}
	if soa := testAnswer(t, view, nil, testRoot, dns.TypeSOA).Answer[0].(*dns.SOA); soa.Ns != "ns1.zone.example." {
		t.Errorf("the earlier view reads %v", soa)
	}
}

// An apex that loses its SOA can deny nothing, so it stops answering rather than go on with the old one.
func TestZoneApplyWithoutAnSoaStopsAnswering(t *testing.T) {
	view := newTestView(t, 1, append(testApexRows(), testTxt("a.zone.example.", "one"))...)
	next, err := view.Apply([]DnsJournalRow{{
		Format: DnsFormat, Root: testRoot, Serial: 2, Deletes: []DnsRecordKey{{Owner: testRoot, Type: dns.TypeSOA}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if reply := testAnswer(t, next, nil, "a.zone.example.", dns.TypeTXT); reply.Rcode != dns.RcodeServerFailure {
		t.Errorf("reply %+v", reply)
	}
}

// Random writes reach the same rows by journal and by snapshot, which is what lets an edge come back
// from a reload holding what its peer holds.
func TestZoneJournalAndSnapshotAgree(t *testing.T) {
	random := rand.New(rand.NewPCG(3, 4))
	view := newTestView(t, 0, testApexRows()...)
	owners := []string{}
	for index := range 40 {
		owners = append(owners, fmt.Sprintf("a%d.b%d.zone.example.", index, index%5), fmt.Sprintf("b%d.zone.example.", index%5))
	}
	for range 2000 {
		row := testRow(view)
		owner := owners[random.IntN(len(owners))]
		switch random.IntN(4) {
		case 0:
			row.Deletes = []DnsRecordKey{{Owner: owner, Type: dns.TypeTXT}}
		case 1:
			row.Deletes = []DnsRecordKey{{Owner: owner, Type: DnsCopyType}}
		case 2:
			row.Upserts = []DnsRecordSet{{Owner: owner, Kind: DnsRecordKindCopy}}
		default:
			row.Upserts = []DnsRecordSet{testTxt(owner, strconv.Itoa(random.IntN(100)))}
		}
		next, err := view.Apply([]DnsJournalRow{row})
		if err != nil {
			t.Fatal(err)
		}
		view = next
	}
	sets := []DnsRecordSet{}
	for set := range view.Rows() {
		sets = append(sets, set.Clone())
	}
	random.Shuffle(len(sets), func(a int, b int) { sets[a], sets[b] = sets[b], sets[a] })
	rebuilt := newTestView(t, view.Serial(), sets...)
	if !maps.Equal(rowsOf(view), rowsOf(rebuilt)) {
		t.Fatal("the two hold other rows")
	}
	// every name, and the ones between them, exists on both or neither
	names := []string{}
	for name := range view.names.all() {
		names = append(names, name)
	}
	for name := range rebuilt.names.all() {
		names = append(names, name)
	}
	for _, name := range names {
		got := view.names.get(name)
		want := rebuilt.names.get(name)
		if got == nil || want == nil || got.childCount != want.childCount {
			t.Errorf("%s holds %+v and %+v", name, got, want)
		}
	}
}

// Empty non-terminals exist while a child does: a name's first child brings its parents into being
// and the last takes them away, or * would stay blocked for ever.
func TestZoneEmptyNonTerminalsComeAndGo(t *testing.T) {
	star := DnsRecordSet{Owner: "*.net1.zone.example.", Type: dns.TypeTXT, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: []string{`"star"`}}
	view := newTestView(t, 1, append(testApexRows(), star)...)
	if text := testText(t, view, "a.net1.zone.example."); text != "star" {
		t.Fatalf("before the child, a reads %q", text)
	}
	child := "c.b.a.net1.zone.example."
	withChild, err := view.Apply([]DnsJournalRow{testRow(view, testTxt(child, "child"))})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.net1.zone.example.", "b.a.net1.zone.example."} {
		reply := testAnswer(t, withChild, nil, name, dns.TypeTXT)
		if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 {
			t.Errorf("%s under a child: %+v", name, reply)
		}
	}
	if reply := testAnswer(t, withChild, nil, "x.b.a.net1.zone.example.", dns.TypeTXT); reply.Rcode != dns.RcodeNameError {
		t.Errorf("a name beside the child: %+v", reply)
	}
	withoutChild, err := withChild.Apply([]DnsJournalRow{{
		Format: DnsFormat, Root: testRoot, Serial: withChild.Serial() + 1,
		Deletes: []DnsRecordKey{{Owner: child, Type: dns.TypeTXT}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.net1.zone.example.", "b.a.net1.zone.example.", "c.b.a.net1.zone.example."} {
		if text := testText(t, withoutChild, name); text != "star" {
			t.Errorf("with the child gone, %s reads %q", name, text)
		}
		if withoutChild.names.get(name) != nil {
			t.Errorf("%s left a name behind", name)
		}
	}
	if got := withoutChild.names.get("net1.zone.example."); got == nil || got.childCount != 1 {
		t.Errorf("net1 holds %+v", got)
	}
}

// Two children hold their parent until the last goes.
func TestZoneNonTerminalOutlivesItsFirstChild(t *testing.T) {
	view := newTestView(t, 1, append(testApexRows(), testTxt("a.b.zone.example.", "a"), testTxt("c.b.zone.example.", "c"))...)
	next, err := view.Apply([]DnsJournalRow{{
		Format: DnsFormat, Root: testRoot, Serial: 2, Deletes: []DnsRecordKey{{Owner: "a.b.zone.example.", Type: dns.TypeTXT}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if reply := testAnswer(t, next, nil, "b.zone.example.", dns.TypeTXT); reply.Rcode != dns.RcodeSuccess {
		t.Errorf("b reads %+v", reply)
	}
	next, err = next.Apply([]DnsJournalRow{{
		Format: DnsFormat, Root: testRoot, Serial: 3, Deletes: []DnsRecordKey{{Owner: "c.b.zone.example.", Type: dns.TypeTXT}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if reply := testAnswer(t, next, nil, "b.zone.example.", dns.TypeTXT); reply.Rcode != dns.RcodeNameError {
		t.Errorf("b reads %+v", reply)
	}
}

// A delete of what is not there changes nothing but the serial, so a retried withdrawal is harmless.
func TestZoneDeleteOfNothingIsNoFault(t *testing.T) {
	view := newTestView(t, 1, append(testApexRows(), DnsRecordSet{Owner: "copy.zone.example.", Kind: DnsRecordKindCopy})...)
	next, err := view.Apply([]DnsJournalRow{{
		Format: DnsFormat, Root: testRoot, Serial: 2,
		Deletes: []DnsRecordKey{
			{Owner: "nosuch.zone.example.", Type: dns.TypeTXT},
			{Owner: "nosuch.zone.example.", Type: DnsCopyType},
			{Owner: "copy.zone.example.", Type: dns.TypeTXT},
			{Owner: testRoot, Type: DnsCopyType},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if next.Serial() != 2 || !maps.Equal(rowsOf(view), rowsOf(next)) {
		t.Errorf("rows %v", rowsOf(next))
	}
}

func TestNewZoneViewRefuses(t *testing.T) {
	settings := answerTestSettings(t)
	row := testTxt("a.zone.example.", "one")
	cases := []struct {
		name     string
		snapshot DnsSnapshot
		rows     []DnsRecordSet
		want     error
	}{
		{name: "a format too new", snapshot: DnsSnapshot{Format: DnsFormat + 1, Root: testRoot, Serial: 1}, want: ErrDnsFormatTooNew},
		{name: "no format", snapshot: DnsSnapshot{Root: testRoot, Serial: 1}, want: ErrDnsRowMalformed},
		{name: "no root", snapshot: DnsSnapshot{Format: DnsFormat, Serial: 1}, want: ErrDnsRowMalformed},
		{name: "a key twice", snapshot: DnsSnapshot{Format: DnsFormat, Root: testRoot, Serial: 1}, rows: []DnsRecordSet{row, row}, want: ErrDnsRowMalformed},
		{
			name:     "a copy row twice",
			snapshot: DnsSnapshot{Format: DnsFormat, Root: testRoot, Serial: 1},
			rows:     []DnsRecordSet{{Owner: "a.zone.example.", Kind: DnsRecordKindCopy}, {Owner: "a.zone.example.", Kind: DnsRecordKindCopy}},
			want:     ErrDnsRowMalformed,
		},
		{
			name:     "a row outside the root",
			snapshot: DnsSnapshot{Format: DnsFormat, Root: testRoot, Serial: 1},
			rows:     []DnsRecordSet{testTxt("a.other.example.", "one")},
			want:     ErrDnsRowMalformed,
		},
	}
	for _, c := range cases {
		view, err := NewZoneView(settings, NewDnsSnapshotRows(c.snapshot, c.rows))
		if view != nil || !errors.Is(err, c.want) {
			t.Errorf("%s: view %v, err %v", c.name, view, err)
		}
	}
}

// A snapshot cut short builds no view, or an edge would deny what it had not read yet.
func TestNewZoneViewRefusesAStreamCutShort(t *testing.T) {
	stream := strings.NewReader(`{"format":1,"root":"zone.example.","serial":44,"restore_serial":0}` + "\n" +
		`{"owner":"a.zone.example.","type":16,"ttl":60,"kind":"user","rdata":["\"one\""]}` + "\n")
	rows, err := NewDnsSnapshotReader(stream)
	if err != nil {
		t.Fatal(err)
	}
	view, err := NewZoneView(answerTestSettings(t), rows)
	if view != nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("view %v, err %v", view, err)
	}
}

// What §12.7 refuses of a user is held and not answered, and costs its own name and nothing else:
// the rows behind it in the journal still apply.
func TestZoneWithholdsWhatAUserMayNotPublish(t *testing.T) {
	user := func(owner string, rrType uint16, rdata ...string) DnsRecordSet {
		return DnsRecordSet{Owner: owner, Type: rrType, Ttl: 60, Kind: DnsRecordKindUser, Rdata: rdata}
	}
	cases := []struct {
		name string
		set  DnsRecordSet
	}{
		{name: "rfc 1918", set: user("a.zone.example.", dns.TypeA, "10.1.2.3")},
		{name: "the overlay's", set: user("a.zone.example.", dns.TypeA, "100.64.0.1")},
		{name: "loopback", set: user("a.zone.example.", dns.TypeA, "127.0.0.1")},
		{name: "documentation", set: user("a.zone.example.", dns.TypeA, "192.0.2.1")},
		{name: "one bad address in a good set", set: user("a.zone.example.", dns.TypeA, "11.22.33.44", "10.1.2.3")},
		{name: "ula", set: user("a.zone.example.", dns.TypeAAAA, "fd00::1")},
		{name: "ipv4-mapped private", set: user("a.zone.example.", dns.TypeAAAA, "::ffff:10.1.2.3")},
		{name: "a dns stand-in", set: user("a.zone.example.", dns.TypeA, connect.DefaultDnsUpgradeMaskAddress)},
		{name: "NS", set: user("a.zone.example.", dns.TypeNS, "ns.other.example.")},
		{name: "DS", set: user("a.zone.example.", dns.TypeDS, "12345 13 2 "+strings.Repeat("ab", 32))},
		{name: "DNAME", set: user("a.zone.example.", dns.TypeDNAME, "other.example.")},
		{name: "PTR", set: user("a.zone.example.", dns.TypePTR, "other.example.")},
		{name: "CAA", set: user("a.zone.example.", dns.TypeCAA, `0 issue "ca.example"`)},
		{name: "HTTPS", set: user("a.zone.example.", dns.TypeHTTPS, "1 . alpn=h3")},
		{name: "SVCB", set: user("a.zone.example.", dns.TypeSVCB, "1 . alpn=h3")},
		{name: "SOA", set: user("a.zone.example.", dns.TypeSOA, "ns.other.example. a.other.example. 1 2 3 4 5")},
	}
	for _, c := range cases {
		view := newTestView(t, 1, append(testApexRows(), testTxt("b.zone.example.", "before"))...)
		next, err := view.Apply([]DnsJournalRow{testRow(view, c.set)})
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		reply := testAnswer(t, next, nil, "a.zone.example.", c.set.Type)
		if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 0 {
			t.Errorf("%s: answered %+v", c.name, reply)
		}
		if any := testAnswer(t, next, nil, "a.zone.example.", dns.TypeANY); len(any.Answer) != 1 || any.Answer[0].Header().Rrtype != dns.TypeHINFO {
			t.Errorf("%s: ANY answered %v", c.name, any.Answer)
		}
		if next.WithheldCount() != 1 {
			t.Errorf("%s: withheld count %d", c.name, next.WithheldCount())
		}
		if _, ok := rowsOf(next)[fmt.Sprintf("a.zone.example./%d", c.set.Type)]; !ok {
			t.Errorf("%s: gone from the rows, so a snapshot would disagree with the server's", c.name)
		}
		// the journal goes on behind it
		after, err := next.Apply([]DnsJournalRow{testRow(next, testTxt("b.zone.example.", "after"))})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if text := testText(t, after, "b.zone.example."); text != "after" {
			t.Errorf("%s: b reads %q", c.name, text)
		}
	}
}

// The system writers hold what no user may, on the owners §12.7 gives them.
func TestZoneAnswersSystemRowsAUserCouldNotHold(t *testing.T) {
	system := func(owner string, rrType uint16, rdata ...string) DnsRecordSet {
		return DnsRecordSet{Owner: owner, Type: rrType, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: rdata}
	}
	view := newTestView(t, 1, append(testApexRows(),
		system("ns1.zone.example.", dns.TypeA, "192.0.2.1"),
		system(testRoot, dns.TypeNS, "ns1.zone.example."),
		system(testRoot, dns.TypeCAA, `0 issue "ca.example"`),
		DnsRecordSet{Owner: "h.zone.example.", Type: dns.TypeCAA, Ttl: 60, Kind: DnsRecordKindCanary, Rdata: []string{`0 urcanary "nonce"`}},
	)...)
	if view.WithheldCount() != 0 {
		t.Errorf("withheld count %d", view.WithheldCount())
	}
	for _, c := range []struct {
		owner  string
		rrType uint16
	}{{"ns1.zone.example.", dns.TypeA}, {testRoot, dns.TypeNS}, {testRoot, dns.TypeCAA}, {"h.zone.example.", dns.TypeCAA}} {
		if reply := testAnswer(t, view, nil, c.owner, c.rrType); len(reply.Answer) != 1 {
			t.Errorf("%s %d: %+v", c.owner, c.rrType, reply)
		}
	}
}

// §12.7's rules on what any writer's row may be, since these hold whoever wrote it (D-DNS-6, plan
// reading 2).
func TestZoneWithholdsWhatNoWriterMayHold(t *testing.T) {
	cases := []struct {
		name string
		set  DnsRecordSet
		// a name the set would answer
		query string
	}{
		{
			name:  "a wildcard CNAME",
			set:   DnsRecordSet{Owner: "*.net1.zone.example.", Type: dns.TypeCNAME, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: []string{"target.other.example."}},
			query: "x.net1.zone.example.",
		},
		{
			name:  "an SOA below the apex",
			set:   DnsRecordSet{Owner: "net1.zone.example.", Type: dns.TypeSOA, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: []string{"ns1.zone.example. a.zone.example. 1 2 3 4 5"}},
			query: "net1.zone.example.",
		},
		{
			name:  "an NS below the apex",
			set:   DnsRecordSet{Owner: "net1.zone.example.", Type: dns.TypeNS, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: []string{"ns.other.example."}},
			query: "net1.zone.example.",
		},
	}
	for _, c := range cases {
		view := newTestView(t, 1, append(testApexRows(), c.set)...)
		reply := testAnswer(t, view, nil, c.query, c.set.Type)
		if len(reply.Answer) != 0 {
			t.Errorf("%s: answered %v", c.name, reply.Answer)
		}
		if address := testAnswer(t, view, nil, c.query, dns.TypeA); len(address.Answer) != 0 {
			t.Errorf("%s: followed to %v", c.name, address.Answer)
		}
		if view.WithheldCount() != 1 {
			t.Errorf("%s: withheld count %d", c.name, view.WithheldCount())
		}
	}
}

// A copy row at a wildcard with rows of its own answers the rest from the wildcard above it, never from
// itself. A strong-mode probe's copy at such an owner would read this way.
func TestZoneCopyAtAWildcardLooksAboveItself(t *testing.T) {
	view := newTestView(t, 1, append(testApexRows(),
		DnsRecordSet{Owner: "*.net1.zone.example.", Type: dns.TypeMX, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: []string{"10 mx.net1.zone.example."}},
		DnsRecordSet{Owner: "*.host.net1.zone.example.", Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindUser, Rdata: []string{"11.22.33.44"}},
		DnsRecordSet{Owner: "*.host.net1.zone.example.", Kind: DnsRecordKindCopy},
	)...)
	reply := testAnswer(t, view, nil, "x.host.net1.zone.example.", dns.TypeMX)
	if lines := recordLines(reply.Answer); !slices.Equal(lines, []string{"x.host.net1.zone.example. 300 IN MX 10 mx.net1.zone.example."}) {
		t.Errorf("answer %q", lines)
	}
	reply = testAnswer(t, view, nil, "x.host.net1.zone.example.", dns.TypeA)
	if lines := recordLines(reply.Answer); !slices.Equal(lines, []string{"x.host.net1.zone.example. 60 IN A 11.22.33.44"}) {
		t.Errorf("answer %q", lines)
	}
}

// A withheld row that goes or is replaced stops counting.
func TestZoneWithheldCountFollowsTheRows(t *testing.T) {
	bad := DnsRecordSet{Owner: "a.zone.example.", Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindUser, Rdata: []string{"10.1.2.3"}}
	good := DnsRecordSet{Owner: "a.zone.example.", Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindUser, Rdata: []string{"11.22.33.44"}}
	view := newTestView(t, 1, append(testApexRows(), bad)...)
	if view.WithheldCount() != 1 {
		t.Fatalf("withheld count %d", view.WithheldCount())
	}
	replaced, err := view.Apply([]DnsJournalRow{testRow(view, good)})
	if err != nil {
		t.Fatal(err)
	}
	if replaced.WithheldCount() != 0 || view.WithheldCount() != 1 {
		t.Errorf("withheld counts %d and %d", replaced.WithheldCount(), view.WithheldCount())
	}
	if reply := testAnswer(t, replaced, nil, "a.zone.example.", dns.TypeA); len(reply.Answer) != 1 {
		t.Errorf("the good row: %+v", reply)
	}
	badAgain, err := replaced.Apply([]DnsJournalRow{testRow(replaced, bad)})
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := badAgain.Apply([]DnsJournalRow{{
		Format: DnsFormat, Root: testRoot, Serial: badAgain.Serial() + 1, Deletes: []DnsRecordKey{bad.Key()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if badAgain.WithheldCount() != 1 || deleted.WithheldCount() != 0 {
		t.Errorf("withheld counts %d and %d", badAgain.WithheldCount(), deleted.WithheldCount())
	}
}

// RFC 2181 §10.1. The lint refuses this at the write, so this is the read side's answer should one
// arrive: the other data stands and the CNAME is not followed.
func TestZoneCnameBesideDataIsNotAnswered(t *testing.T) {
	cname := DnsRecordSet{Owner: "a.zone.example.", Type: dns.TypeCNAME, Ttl: 60, Kind: DnsRecordKindUser, Rdata: []string{"b.zone.example."}}
	target := testTxt("b.zone.example.", "target")
	for _, beside := range []DnsRecordSet{testTxt("a.zone.example.", "own"), {Owner: "a.zone.example.", Kind: DnsRecordKindCopy}} {
		view := newTestView(t, 1, append(testApexRows(), cname, target, beside)...)
		if reply := testAnswer(t, view, nil, "a.zone.example.", dns.TypeCNAME); len(reply.Answer) != 0 {
			t.Errorf("answered %v", reply.Answer)
		}
		if reply := testAnswer(t, view, nil, "a.zone.example.", dns.TypeA); len(reply.Answer) != 0 {
			t.Errorf("followed to %v", reply.Answer)
		}
	}
}

func TestIsPublicDnsAddress(t *testing.T) {
	public := []string{"11.22.33.44", "1.1.1.1", "2a0f:ffff::7", "2600::1", "::ffff:11.22.33.44"}
	for _, text := range public {
		if !isPublicDnsAddress(netip.MustParseAddr(text)) {
			t.Errorf("%s reads as not public", text)
		}
	}
	nonPublic := []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.1.1", "172.16.0.1", "172.31.255.255",
		"192.0.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1",
		"239.255.255.255", "240.0.0.1", "255.255.255.255",
		"::", "::1", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1", "2001:db8::1", "3fff::1", "64:ff9b::1", "::ffff:10.0.0.1",
		"::ffff:127.0.0.1", connect.DefaultDnsUpgradeMaskAddress, connect.DefaultDnsUpgradeMaskAddressIpv6,
	}
	for _, text := range nonPublic {
		if isPublicDnsAddress(netip.MustParseAddr(text)) {
			t.Errorf("%s reads as public", text)
		}
	}
	if isPublicDnsAddress(netip.Addr{}) {
		t.Error("the zero address reads as public")
	}
}

func TestHealthySetAnswersByKindAndFamily(t *testing.T) {
	edge := []DnsLbInterface{
		{Name: "b", Ipv4: netip.MustParseAddr("192.0.2.2"), Ipv6: netip.MustParseAddr("2001:db8::2")},
		{Name: "a", Ipv4: netip.MustParseAddr("192.0.2.1")},
		{Name: "c", Ipv6: netip.MustParseAddr("2001:db8::1")},
	}
	router := []DnsLbInterface{{Name: "b", Ipv4: netip.MustParseAddr("192.0.2.2")}}
	set := NewHealthySet(edge, router)
	cases := []struct {
		kind   DnsRecordKind
		rrType uint16
		want   []string
	}{
		{kind: DnsRecordKindEdge, rrType: dns.TypeA, want: []string{"192.0.2.1", "192.0.2.2"}},
		{kind: DnsRecordKindEdge, rrType: dns.TypeAAAA, want: []string{"2001:db8::1", "2001:db8::2"}},
		{kind: DnsRecordKindRouter, rrType: dns.TypeA, want: []string{"192.0.2.2"}},
		{kind: DnsRecordKindRouter, rrType: dns.TypeAAAA},
		{kind: DnsRecordKindUser, rrType: dns.TypeA},
		{kind: DnsRecordKindEdge, rrType: dns.TypeMX},
	}
	for _, c := range cases {
		texts := []string{}
		for _, address := range set.addresses(c.kind, c.rrType) {
			texts = append(texts, address.String())
		}
		if len(texts) != len(c.want) || (len(c.want) != 0 && !slices.Equal(texts, c.want)) {
			t.Errorf("%s %d: %v", c.kind, c.rrType, texts)
		}
	}
	var none *HealthySet
	if addresses := none.addresses(DnsRecordKindEdge, dns.TypeA); addresses != nil {
		t.Errorf("a nil set holds %v", addresses)
	}
}

// Two interfaces on one address answer it once, and an address on the wrong side is not answered.
func TestHealthySetDropsRepeatsAndMisfiledAddresses(t *testing.T) {
	set := NewHealthySet([]DnsLbInterface{
		{Ipv4: netip.MustParseAddr("192.0.2.1")},
		{Ipv4: netip.MustParseAddr("192.0.2.1")},
		{Ipv4: netip.MustParseAddr("2001:db8::1"), Ipv6: netip.MustParseAddr("192.0.2.9")},
		{Ipv4: netip.MustParseAddr("::ffff:192.0.2.2")},
	}, nil)
	if addresses := set.addresses(DnsRecordKindEdge, dns.TypeA); len(addresses) != 2 {
		t.Errorf("addresses %v", addresses)
	}
	if addresses := set.addresses(DnsRecordKindEdge, dns.TypeAAAA); len(addresses) != 0 {
		t.Errorf("addresses %v", addresses)
	}
}

// Rows comes back whole and stops when told.
func TestZoneRowsStopsWhenTold(t *testing.T) {
	view := newTestView(t, 1, append(testApexRows(), testTxt("a.zone.example.", "one"), testTxt("b.zone.example.", "two"))...)
	count := 0
	for range view.Rows() {
		count += 1
		break
	}
	if count != 1 {
		t.Errorf("count %d", count)
	}
	if rows := slices.Collect(view.Rows()); len(rows) != 3 {
		t.Errorf("rows %d", len(rows))
	}
}

// Readers on a published view while a writer applies and swaps, on the one pointer an edge holds: each
// read of two names written together sees them agree, however the two interleave. The assertion needs
// no schedule, and under -race this also proves an answer touches nothing a build writes.
func TestZoneReadersNeverSeeHalfARow(t *testing.T) {
	view := newTestView(t, 0, append(testApexRows(), testTxt("a.zone.example.", "0"), testTxt("b.zone.example.", "0"))...)
	published := atomic.Pointer[ZoneView]{}
	published.Store(view)
	done := atomic.Bool{}
	waitGroup := sync.WaitGroup{}
	read := func(view *ZoneView, owner string) string {
		reply := Answer(&DnsQuery{Message: testQuery(owner, dns.TypeTXT)}, view, nil)
		if len(reply.Answer) == 0 {
			return ""
		}
		return reply.Answer[0].(*dns.TXT).Txt[0]
	}
	for range 4 {
		waitGroup.Go(func() {
			for !done.Load() {
				held := published.Load()
				first := read(held, "a.zone.example.")
				second := read(held, "b.zone.example.")
				if first != second || strconv.FormatUint(held.Serial(), 10) != first {
					t.Errorf("serial %d reads %q and %q", held.Serial(), first, second)
					return
				}
			}
		})
	}
	for serial := 1; serial <= 500; serial += 1 {
		text := strconv.Itoa(serial)
		next, err := view.Apply([]DnsJournalRow{testRow(view, testTxt("a.zone.example.", text), testTxt("b.zone.example.", text))})
		if err != nil {
			t.Fatal(err)
		}
		view = next
		published.Store(view)
	}
	done.Store(true)
	waitGroup.Wait()
}
