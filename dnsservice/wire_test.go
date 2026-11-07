package dnsservice

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testRoot = "zone.example."

// A file under testdata/dns/journal, with the newline the file ends in taken off.
func journalGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "dns", "journal", name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(data, []byte("\n"))
}

func wantRoundTrip(t *testing.T, name string, value any, golden []byte) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, golden) {
		t.Errorf("%s:\n got %s\nwant %s", name, encoded, golden)
	}
}

func TestDnsJournalRowGolden(t *testing.T) {
	golden := journalGolden(t, "row.json")
	row, err := DecodeDnsJournalRow(golden)
	if err != nil {
		t.Fatal(err)
	}
	want := &DnsJournalRow{
		Format: 1,
		Root:   testRoot,
		Serial: 42,
		Upserts: []DnsRecordSet{
			{Owner: "blog.abcdefghij.zone.example.", Type: dns.TypeTXT, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{`"hello world"`}},
			{Owner: "*.abcdefghij.zone.example.", Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindEdge},
			{Owner: "_sip._tcp.blog.abcdefghij.zone.example.", Type: dns.TypeSRV, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{"10 5 5060 sip.other.example."}},
			{Owner: "blog.abcdefghij.zone.example.", Type: DnsCopyType, Kind: DnsRecordKindCopy},
		},
		Deletes: []DnsRecordKey{{Owner: "old.abcdefghij.zone.example.", Type: dns.TypeTXT}},
	}
	if !reflect.DeepEqual(row, want) {
		t.Errorf("row %+v", row)
	}
	wantRoundTrip(t, "row", row, golden)
}

func TestDnsFeedAnswerGoldens(t *testing.T) {
	golden := journalGolden(t, "answer_rows.json")
	answer, err := DecodeDnsFeedAnswer(golden)
	if err != nil {
		t.Fatal(err)
	}
	want := &DnsFeedAnswer{
		Format:        1,
		Root:          testRoot,
		Serial:        44,
		RestoreSerial: 16777216,
		Rows: []DnsJournalRow{
			{
				Format: 1, Root: testRoot, Serial: 43,
				Upserts: []DnsRecordSet{{Owner: "a.abcdefghij.zone.example.", Type: dns.TypeTXT, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{`"one"`}}},
			},
			{
				Format: 1, Root: testRoot, Serial: 44,
				Deletes: []DnsRecordKey{{Owner: "a.abcdefghij.zone.example.", Type: dns.TypeTXT}},
			},
		},
		Interfaces: []DnsLbInterface{
			{Name: "edge-1/eth0", Ipv4: netip.MustParseAddr("192.0.2.10"), Ipv6: netip.MustParseAddr("2001:db8::10")},
			{
				Name: "edge-2/eth0", Ipv4: netip.MustParseAddr("192.0.2.20"), Router: true, ReportedVersion: 7,
				ProbeName: "0123456789ab.map.probe.invalid", AddedHosts: []string{"www.customer.example."}, MapStale: true,
			},
		},
		KeyWindow: &DnsKeyWindow{
			Root:      testRoot,
			NotBefore: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:  time.Date(2026, time.January, 15, 0, 0, 0, 0, time.UTC),
			Dnskeys:   []string{"257 3 13 c3ludGhldGljLWtzay1ieXRlcw=="},
			Rrsigs:    []string{"DNSKEY 13 2 3600 20260115000000 20260101000000 12345 zone.example. c3ludGhldGljLXNpZ25hdHVyZQ=="},
		},
	}
	if !reflect.DeepEqual(answer, want) {
		t.Errorf("answer %+v", answer)
	}
	wantRoundTrip(t, "answer_rows", answer, golden)

	golden = journalGolden(t, "answer_reload.json")
	answer, err = DecodeDnsFeedAnswer(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Reload || answer.RestoreSerial != 16777216 || len(answer.Rows) != 0 || len(answer.Interfaces) != 1 {
		t.Errorf("reload answer %+v", answer)
	}
	wantRoundTrip(t, "answer_reload", answer, golden)

	golden = journalGolden(t, "answer_hold.json")
	answer, err = DecodeDnsFeedAnswer(golden)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Reload || len(answer.Rows) != 0 {
		t.Errorf("hold answer %+v", answer)
	}
	wantRoundTrip(t, "answer_hold", answer, golden)
}

func TestDnsReloadDiffGolden(t *testing.T) {
	golden := journalGolden(t, "reload_diff.json")
	diff := &DnsReloadDiff{}
	if err := json.Unmarshal(golden, diff); err != nil {
		t.Fatal(err)
	}
	want := &DnsReloadDiff{
		Root:           testRoot,
		ReplacedSerial: 44,
		Serial:         16777260,
		Rrsets: []DnsRecordKey{
			{Owner: "a.abcdefghij.zone.example.", Type: dns.TypeTXT},
			{Owner: "blog.abcdefghij.zone.example.", Type: DnsCopyType},
		},
	}
	if !reflect.DeepEqual(diff, want) {
		t.Errorf("diff %+v", diff)
	}
	wantRoundTrip(t, "reload_diff", diff, golden)
}

// §12.6's rule for N and N+1: N ignores a field N+1 adds, wherever N+1 adds it.
func TestDnsUnknownFieldsAreIgnored(t *testing.T) {
	row, err := DecodeDnsJournalRow(journalGolden(t, "row_unknown_field.json"))
	if err != nil {
		t.Fatal(err)
	}
	if row.Serial != 43 || len(row.Upserts) != 1 || row.Upserts[0].Rdata[0] != `"hello world"` {
		t.Errorf("row %+v", row)
	}
	answer, err := DecodeDnsFeedAnswer(journalGolden(t, "answer_unknown_field.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Rows) != 1 || len(answer.Rows[0].Deletes) != 1 || answer.Interfaces[0].Name != "edge-1/eth0" {
		t.Errorf("answer %+v", answer)
	}
}

// A higher format stops the reader even when the rest of the row has a shape this release cannot read,
// which would otherwise fail as something else and hide why.
func TestDnsHigherFormatIsRefused(t *testing.T) {
	if row, err := DecodeDnsJournalRow(journalGolden(t, "row_format_too_new.json")); !errors.Is(err, ErrDnsFormatTooNew) {
		t.Errorf("row %+v, err %v", row, err)
	}
	if answer, err := DecodeDnsFeedAnswer(journalGolden(t, "answer_row_format_too_new.json")); !errors.Is(err, ErrDnsFormatTooNew) {
		t.Errorf("a too-new row in an answer: answer %+v, err %v", answer, err)
	}
	if answer, err := DecodeDnsFeedAnswer([]byte(`{"format":2,"rows":"another shape"}`)); !errors.Is(err, ErrDnsFormatTooNew) {
		t.Errorf("a too-new answer: answer %+v, err %v", answer, err)
	}
	stream := `{"format":2,"root":{"another":"shape"}}` + "\n"
	if rows, err := NewDnsSnapshotReader(strings.NewReader(stream)); !errors.Is(err, ErrDnsFormatTooNew) {
		t.Errorf("a too-new snapshot: rows %v, err %v", rows, err)
	}
	row := DnsJournalRow{Format: DnsFormat + 1, Root: testRoot, Serial: 1, Deletes: []DnsRecordKey{{Owner: testRoot, Type: dns.TypeTXT}}}
	if err := row.Validate(); !errors.Is(err, ErrDnsFormatTooNew) {
		t.Errorf("a too-new row in memory: %v", err)
	}
}

func TestDnsRowsMalformed(t *testing.T) {
	txt := DnsRecordSet{Owner: "a.zone.example.", Type: dns.TypeTXT, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{`"one"`}}
	withSet := func(change func(set *DnsRecordSet)) *DnsJournalRow {
		set := txt.Clone()
		change(&set)
		return &DnsJournalRow{Format: DnsFormat, Root: testRoot, Serial: 1, Upserts: []DnsRecordSet{set}}
	}
	cases := []struct {
		name string
		row  *DnsJournalRow
	}{
		{name: "no format", row: &DnsJournalRow{Root: testRoot, Serial: 1, Upserts: []DnsRecordSet{txt}}},
		{name: "a root that is not canonical", row: &DnsJournalRow{Format: DnsFormat, Root: "Zone.example", Serial: 1, Upserts: []DnsRecordSet{txt}}},
		{name: "serial zero", row: &DnsJournalRow{Format: DnsFormat, Root: testRoot, Upserts: []DnsRecordSet{txt}}},
		{name: "empty", row: &DnsJournalRow{Format: DnsFormat, Root: testRoot, Serial: 1}},
		{name: "a key twice in upserts", row: &DnsJournalRow{Format: DnsFormat, Root: testRoot, Serial: 1, Upserts: []DnsRecordSet{txt, txt}}},
		{name: "a key in upserts and deletes", row: &DnsJournalRow{
			Format: DnsFormat, Root: testRoot, Serial: 1, Upserts: []DnsRecordSet{txt}, Deletes: []DnsRecordKey{txt.Key()},
		}},
		{name: "a delete outside the root", row: &DnsJournalRow{
			Format: DnsFormat, Root: testRoot, Serial: 1, Deletes: []DnsRecordKey{{Owner: "a.other.example.", Type: dns.TypeA}},
		}},
		{name: "a delete of a meta-type", row: &DnsJournalRow{
			Format: DnsFormat, Root: testRoot, Serial: 1, Deletes: []DnsRecordKey{{Owner: "a.zone.example.", Type: dns.TypeANY}},
		}},
		{name: "an owner outside the root", row: withSet(func(set *DnsRecordSet) { set.Owner = "a.other.example." })},
		{name: "a name that only ends like the root", row: withSet(func(set *DnsRecordSet) { set.Owner = "notzone.example." })},
		{name: "an owner in upper case", row: withSet(func(set *DnsRecordSet) { set.Owner = "A.zone.example." })},
		{name: "an owner not fully qualified", row: withSet(func(set *DnsRecordSet) { set.Owner = "a.zone.example" })},
		{name: "an owner with an escape", row: withSet(func(set *DnsRecordSet) { set.Owner = `a\.b.zone.example.` })},
		{name: "a kind this release does not know", row: withSet(func(set *DnsRecordSet) { set.Kind = "later" })},
		{name: "no kind", row: withSet(func(set *DnsRecordSet) { set.Kind = "" })},
		{name: "a ttl with its top bit", row: withSet(func(set *DnsRecordSet) { set.Ttl = 1 << 31 })},
		{name: "no rdata", row: withSet(func(set *DnsRecordSet) { set.Rdata = nil })},
		{name: "rdata that does not parse", row: withSet(func(set *DnsRecordSet) {
			set.Type = dns.TypeA
			set.Rdata = []string{"not an address"}
		})},
		{name: "a record repeated", row: withSet(func(set *DnsRecordSet) { set.Rdata = []string{`"one"`, `"one"`} })},
		{name: "a line break in rdata", row: withSet(func(set *DnsRecordSet) { set.Rdata = []string{"\"one\"\na.zone.example. IN A 192.0.2.1"} })},
		{name: "a meta-type", row: withSet(func(set *DnsRecordSet) { set.Type = dns.TypeAXFR })},
		{name: "a signer's type", row: withSet(func(set *DnsRecordSet) {
			set.Type = dns.TypeDNSKEY
			set.Rdata = []string{"256 3 13 c3ludGhldGlj"}
		})},
		{name: "a copy with rdata", row: withSet(func(set *DnsRecordSet) {
			set.Kind = DnsRecordKindCopy
			set.Type = DnsCopyType
		})},
		{name: "a copy with a type", row: withSet(func(set *DnsRecordSet) {
			set.Kind = DnsRecordKindCopy
			set.Rdata = nil
		})},
		{name: "an edge row that is no address", row: withSet(func(set *DnsRecordSet) {
			set.Kind = DnsRecordKindEdge
			set.Rdata = nil
		})},
		{name: "an edge row with an address of its own", row: withSet(func(set *DnsRecordSet) {
			set.Kind = DnsRecordKindEdge
			set.Type = dns.TypeA
			set.Rdata = []string{"192.0.2.1"}
		})},
		{name: "a router row of no address", row: withSet(func(set *DnsRecordSet) {
			set.Kind = DnsRecordKindRouter
			set.Type = dns.TypeMX
			set.Rdata = nil
		})},
	}
	for _, c := range cases {
		if err := c.row.Validate(); !errors.Is(err, ErrDnsRowMalformed) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// nothing of a malformed row comes back from its decoder either
	encoded, err := json.Marshal(cases[len(cases)-1].row)
	if err != nil {
		t.Fatal(err)
	}
	if row, err := DecodeDnsJournalRow(encoded); row != nil || !errors.Is(err, ErrDnsRowMalformed) {
		t.Errorf("row %+v, err %v", row, err)
	}
}

func TestDnsFeedAnswersMalformed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{name: "not json", data: `{`},
		{name: "no format", data: `{"root":"zone.example.","serial":1}`},
		{name: "a negative serial", data: `{"format":1,"root":"zone.example.","serial":-1}`},
		{name: "a root that is no name", data: `{"format":1,"root":"","serial":1}`},
		{name: "reload with rows", data: `{"format":1,"root":"zone.example.","serial":2,"reload":true,"rows":[{"format":1,"root":"zone.example.","serial":2,"deletes":[{"owner":"a.zone.example.","type":1}]}]}`},
		{name: "a row of another root", data: `{"format":1,"root":"zone.example.","serial":2,"rows":[{"format":1,"root":"other.example.","serial":2,"deletes":[{"owner":"a.other.example.","type":1}]}]}`},
		{name: "rows with a hole", data: `{"format":1,"root":"zone.example.","serial":4,"rows":[{"format":1,"root":"zone.example.","serial":2,"deletes":[{"owner":"a.zone.example.","type":1}]},{"format":1,"root":"zone.example.","serial":4,"deletes":[{"owner":"a.zone.example.","type":1}]}]}`},
		{name: "rows out of order", data: `{"format":1,"root":"zone.example.","serial":3,"rows":[{"format":1,"root":"zone.example.","serial":3,"deletes":[{"owner":"a.zone.example.","type":1}]},{"format":1,"root":"zone.example.","serial":2,"deletes":[{"owner":"a.zone.example.","type":1}]}]}`},
		{name: "an interface address that is none", data: `{"format":1,"root":"zone.example.","serial":1,"interfaces":[{"name":"a","ipv4":"not an address"}]}`},
	}
	for _, c := range cases {
		if answer, err := DecodeDnsFeedAnswer([]byte(c.data)); answer != nil || !errors.Is(err, ErrDnsRowMalformed) {
			t.Errorf("%s: answer %+v, err %v", c.name, answer, err)
		}
	}
}

func TestDnsRecordsParse(t *testing.T) {
	cases := []struct {
		set  DnsRecordSet
		want string
	}{
		{
			set:  DnsRecordSet{Owner: "a.zone.example.", Type: dns.TypeA, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: []string{"192.0.2.1"}},
			want: "a.zone.example.\t300\tIN\tA\t192.0.2.1",
		},
		{
			set:  DnsRecordSet{Owner: "*.a.zone.example.", Type: dns.TypeMX, Ttl: 300, Kind: DnsRecordKindSystem, Rdata: []string{"0 ."}},
			want: "*.a.zone.example.\t300\tIN\tMX\t0 .",
		},
		{
			set:  DnsRecordSet{Owner: "a.zone.example.", Type: dns.TypeTXT, Ttl: 60, Kind: DnsRecordKindChallenge, Rdata: []string{`"semi;colon" "two"`}},
			want: "a.zone.example.\t60\tIN\tTXT\t\"semi;colon\" \"two\"",
		},
		{
			set:  DnsRecordSet{Owner: "a.zone.example.", Type: 65280, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: []string{`\# 2 0102`}},
			want: "a.zone.example.\t60\tCLASS1\tTYPE65280\t\\# 2 0102",
		},
	}
	for _, c := range cases {
		if err := c.set.Validate(testRoot); err != nil {
			t.Errorf("%s: %v", c.want, err)
			continue
		}
		records, err := c.set.Records()
		if err != nil {
			t.Errorf("%s: %v", c.want, err)
			continue
		}
		if len(records) != 1 || records[0].String() != c.want {
			t.Errorf("records %v, want %q", records, c.want)
		}
	}
}

// An owner reaches the zone-file parser as nothing at all, so a name it would read as a directive
// parses like any other.
func TestDnsRecordsDoNotParseTheOwner(t *testing.T) {
	set := DnsRecordSet{Owner: "$origin.zone.example.", Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindSystem, Rdata: []string{"192.0.2.1"}}
	records, err := set.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Header().Name != set.Owner {
		t.Errorf("records %v", records)
	}
}

func TestDnsSnapshotGolden(t *testing.T) {
	golden := journalGolden(t, "snapshot.ndjson")
	stream, err := NewDnsSnapshotReader(bytes.NewReader(golden))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	want := DnsSnapshot{Format: 1, Root: testRoot, Serial: 44}
	if snapshot := stream.Snapshot(); snapshot != want {
		t.Errorf("snapshot %+v", snapshot)
	}
	rows := []DnsRecordSet{}
	for {
		row, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, *row)
	}
	if len(rows) != 2 || rows[0].Kind != DnsRecordKindEdge || rows[1].Type != dns.TypeSOA {
		t.Errorf("rows %+v", rows)
	}
	if _, err := stream.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("past the end: %v", err)
	}

	encoded := &bytes.Buffer{}
	writer, err := NewDnsSnapshotWriter(encoded, want)
	if err != nil {
		t.Fatal(err)
	}
	for index := range rows {
		if err := writer.Write(&rows[index]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSuffix(encoded.Bytes(), []byte("\n")), golden) {
		t.Errorf("snapshot:\n got %s\nwant %s", encoded.Bytes(), golden)
	}
}

// Every way a snapshot stream can fail leaves a reader with an error, never an early io.EOF, since a
// short zone served as whole would deny names that exist.
func TestDnsSnapshotStreamsMalformed(t *testing.T) {
	golden := string(journalGolden(t, "snapshot.ndjson"))
	lines := strings.Split(golden, "\n")
	header, row, end := lines[0], lines[1], lines[3]
	cases := []struct {
		name   string
		stream string
	}{
		{name: "cut short before the end line", stream: header + "\n" + row + "\n"},
		{name: "cut short inside a line", stream: header + "\n" + row[:10]},
		{name: "counting more rows than it holds", stream: header + "\n" + end + "\n"},
		{name: "counting fewer rows than it holds", stream: header + "\n" + row + "\n" + row + "\n" + lines[2] + "\n" + end + "\n"},
		{name: "a row past the end", stream: golden + "\n" + row + "\n"},
		{name: "a malformed row", stream: header + "\n" + `{"owner":"a.other.example.","type":1,"ttl":60,"kind":"edge"}` + "\n" + end + "\n"},
		{name: "a line that is not json", stream: header + "\nnot json\n"},
		{name: "a line past the limit", stream: header + "\n" + strings.Repeat("x", dnsSnapshotLineMaxByteCount+1) + "\n"},
	}
	for _, c := range cases {
		stream, err := NewDnsSnapshotReader(strings.NewReader(c.stream))
		if err != nil {
			t.Errorf("%s: at the first line: %v", c.name, err)
			continue
		}
		for {
			_, err = stream.Next()
			if err != nil {
				break
			}
		}
		if errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%s: read as whole", c.name)
		} else if !errors.Is(err, ErrDnsRowMalformed) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	for _, stream := range []string{"", "not json\n", `{"format":1,"root":"not canonical"}` + "\n"} {
		if rows, err := NewDnsSnapshotReader(strings.NewReader(stream)); !errors.Is(err, ErrDnsRowMalformed) {
			t.Errorf("first line %q: rows %v, err %v", stream, rows, err)
		}
	}
}

type closeCountingReader struct {
	io.Reader
	closeCount int
}

func (self *closeCountingReader) Close() error {
	self.closeCount += 1
	return nil
}

func TestDnsSnapshotReaderClosesItsSourceOnce(t *testing.T) {
	source := &closeCountingReader{Reader: bytes.NewReader(journalGolden(t, "snapshot.ndjson"))}
	stream, err := NewDnsSnapshotReader(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if source.closeCount != 1 {
		t.Errorf("closed %d times", source.closeCount)
	}
}

// A set bound for the wire keeps its key behind: only the window is ever marshalled.
func TestDnsKeySetDoesNotMarshalItsKey(t *testing.T) {
	zsk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(&DnsKeySet{Window: &DnsKeyWindow{Root: testRoot}, Zsk: zsk})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "Zsk") || strings.Contains(string(encoded), `"D"`) {
		t.Errorf("encoded %s", encoded)
	}
}

func TestDnsRecordSetCloneSharesNothing(t *testing.T) {
	set := DnsRecordSet{Owner: "a.zone.example.", Type: dns.TypeTXT, Rdata: []string{`"one"`}}
	clone := set.Clone()
	clone.Rdata[0] = `"two"`
	if set.Rdata[0] != `"one"` {
		t.Errorf("rdata %v", set.Rdata)
	}
}
