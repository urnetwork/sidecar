package dnsservice

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The most rows one input applies, so a run costs what the input's shape asks and not its length.
const fuzzFeedRowMaxCount = 32

// The seeds under the repository's testdata/fuzz/FuzzFeedAnswer, each one value in go test's corpus
// format, which go test reads only from beside the package, so this reads them here.
func addFuzzFeedSeeds(f *testing.F) {
	paths, err := filepath.Glob(filepath.Join("..", "testdata", "fuzz", "FuzzFeedAnswer", "*"))
	if err != nil {
		f.Fatal(err)
	}
	if len(paths) == 0 {
		f.Fatal("no seeds")
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 2 || lines[0] != "go test fuzz v1" {
			f.Fatalf("%s is not a corpus file of one value", path)
		}
		quoted, ok := strings.CutPrefix(lines[1], "[]byte(")
		if !ok || !strings.HasSuffix(quoted, ")") {
			f.Fatalf("%s: %q", path, lines[1])
		}
		value, err := strconv.Unquote(strings.TrimSuffix(quoted, ")"))
		if err != nil {
			f.Fatalf("%s: %v", path, err)
		}
		f.Add([]byte(value))
	}
}

// §22.6's DNS feed: an answer off the wire, decoded and applied as FeedLoop applies it. Nothing panics;
// an answer that does not decode, or rows that do not apply, leave the view as it was; and what does
// apply is the next serials whole, bounded by the rows given.
func FuzzFeedAnswer(f *testing.F) {
	addFuzzFeedSeeds(f)
	settings := answerTestSettings(f)
	baseRows := append(testApexRows(),
		DnsRecordSet{Owner: "a.abcdefghij." + testRoot, Type: dns.TypeTXT, Ttl: 300, Kind: DnsRecordKindUser, Rdata: []string{`"base"`}},
		DnsRecordSet{Owner: "*.abcdefghij." + testRoot, Type: dns.TypeA, Ttl: 60, Kind: DnsRecordKindEdge},
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		base, err := NewZoneView(settings, NewDnsSnapshotRows(DnsSnapshot{Format: DnsFormat, Root: testRoot, Serial: 42}, baseRows))
		if err != nil {
			t.Fatal(err)
		}
		baseCount := 0
		for range base.Rows() {
			baseCount += 1
		}
		answer, err := DecodeDnsFeedAnswer(data)
		if err != nil {
			if !errors.Is(err, ErrDnsRowMalformed) && !errors.Is(err, ErrDnsFormatTooNew) {
				t.Fatalf("an undecodable answer fails as %v", err)
			}
			return
		}
		if answer.Reload && len(answer.Rows) != 0 {
			t.Fatal("a reload with rows decoded")
		}
		if fuzzFeedRowMaxCount < len(answer.Rows) || answer.Root != testRoot {
			return
		}
		upsertCount := 0
		for index := range answer.Rows {
			upsertCount += len(answer.Rows[index].Upserts)
		}
		next, err := base.Apply(answer.Rows)
		after := 0
		for range base.Rows() {
			after += 1
		}
		if base.Serial() != 42 || after != baseCount {
			t.Fatal("applying changed the view applied onto")
		}
		if err != nil {
			if next != nil {
				t.Fatal("a refused apply gave a view")
			}
			return
		}
		if len(answer.Rows) == 0 {
			if next != base {
				t.Fatal("no rows gave another view")
			}
			return
		}
		if next.Serial() != answer.Rows[len(answer.Rows)-1].Serial {
			t.Fatalf("serial %d after rows to %d", next.Serial(), answer.Rows[len(answer.Rows)-1].Serial)
		}
		nextCount := 0
		for range next.Rows() {
			nextCount += 1
		}
		if baseCount+upsertCount < nextCount {
			t.Fatalf("%d rows from %d and %d upserts", nextCount, baseCount, upsertCount)
		}
		// the view answers, whatever the rows held
		query := &dns.Msg{}
		query.SetQuestion("x.abcdefghij."+testRoot, dns.TypeA)
		Answer(&DnsQuery{Message: query}, next, nil)
	})
}
