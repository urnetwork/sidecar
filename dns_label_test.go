// §12.5's label rules (DNS-M0-01), T1 on every leg: testdata/dns/labels.json's vectors, the reserved
// list held to the design's block, every reserved form refused, and label draws. The vectors and fuzz
// seeds are embedded, since the page Worker's leg has no file system to read them from.

package sidecar

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

//go:embed testdata/dns/labels.json testdata/fuzz/FuzzValidateDnsName
var testDnsLabelFiles embed.FS

// One vector of labels.json.
type testDnsLabelCase struct {
	Name       string `json:"name"`
	Error      string `json:"error"`
	Reserved   bool   `json:"reserved"`
	Brand      bool   `json:"brand"`
	WordNumber bool   `json:"word_number"`
	Why        string `json:"why"`
}

// The vectors' names for ValidateDnsName's answers.
var testDnsNameErrors = map[string]error{
	"":            nil,
	"invalid":     ErrDnsNameInvalid,
	"edge_hyphen": ErrDnsNameEdgeHyphen,
	"hyphens34":   ErrDnsNameHyphens34,
	"reserved":    ErrDnsNameReserved,
	"brand":       ErrDnsNameBrandConfusable,
}

// §12.5's block as the design writes it.
const testDnsReservedDesignBlock = `
www mail mx smtp imap pop dns ns ns1-ns9 edge acme canary rpt out mta-sts autoconfig autodiscover
  wpad isatap localhost
api app web connect mcp gossip grafana taskworker proxy alt monitor mmm lb auth login account admin
  status abuse postmaster security support billing evs gkm sockets tlsedge smtpedge mxedge certs
fuji cosmic fireside crisp gala snow jazz honey, plus every services.yml host label (a release check)
*-lb *-v4 *-v6 main-* beta-* canary-* community-* local-* by-*
ur urnetwork bringyour recurd burner, plus a curated list of the most-phished brands
`

// The network label's grammar.
var testDnsLabelPattern = regexp.MustCompile(`^[a-z][a-z0-9]{9}$`)

func testDnsLabelCases(t *testing.T) []testDnsLabelCase {
	t.Helper()
	data, err := testDnsLabelFiles.ReadFile("testdata/dns/labels.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors := struct {
		Cases []testDnsLabelCase `json:"cases"`
	}{}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) < 50 {
		t.Fatalf("%d vectors", len(vectors.Cases))
	}
	return vectors.Cases
}

// Each vector: ValidateDnsName's answer and each predicate's.
func TestDnsLabelVectors(t *testing.T) {
	for _, c := range testDnsLabelCases(t) {
		wantErr, ok := testDnsNameErrors[c.Error]
		if !ok {
			t.Fatalf("%q: unknown error %q", c.Name, c.Error)
		}
		if err := ValidateDnsName(c.Name); err != wantErr {
			t.Errorf("ValidateDnsName(%q) = %v, want %v (%s)", c.Name, err, wantErr, c.Why)
		}
		if reserved := IsReservedDnsLabel(c.Name); reserved != c.Reserved {
			t.Errorf("IsReservedDnsLabel(%q) = %t (%s)", c.Name, reserved, c.Why)
		}
		if brand := IsBrandConfusableDnsName(c.Name); brand != c.Brand {
			t.Errorf("IsBrandConfusableDnsName(%q) = %t (%s)", c.Name, brand, c.Why)
		}
		if wordNumber := IsWordNumberDnsLabel(c.Name); wordNumber != c.WordNumber {
			t.Errorf("IsWordNumberDnsLabel(%q) = %t (%s)", c.Name, wordNumber, c.Why)
		}
	}
}

// The file is the design's block: its words in order, ns1-ns9 written out, the two "plus" clauses
// left to the release check and the brand list.
func TestDnsReservedListIsTheDesignBlock(t *testing.T) {
	want := []string{}
	for _, line := range strings.Split(testDnsReservedDesignBlock, "\n") {
		line, _, _ = strings.Cut(line, ", plus")
		for _, word := range strings.Fields(line) {
			if word == "ns1-ns9" {
				for index := 1; index <= 9; index += 1 {
					want = append(want, "ns"+strconv.Itoa(index))
				}
				continue
			}
			want = append(want, word)
		}
	}
	if got := dnsListLines(dnsReservedLabelsText); !slices.Equal(got, want) {
		t.Fatalf("dns_reserved_labels.txt holds\n%v\nwant\n%v", got, want)
	}
}

// Every exact label and every pattern, at its shortest instance and a longer one, is reserved and
// refused as a name; the brands are reserved too.
func TestDnsReservedListRefusesEveryForm(t *testing.T) {
	labels := ReservedDnsLabels()
	patterns := ReservedDnsPatterns()
	if len(labels) < 100 || len(patterns) != 9 {
		t.Fatalf("%d labels and %d patterns", len(labels), len(patterns))
	}
	if !slices.IsSorted(labels) {
		t.Fatal("ReservedDnsLabels is not sorted")
	}
	forms := slices.Clone(labels)
	for _, pattern := range patterns {
		for _, fill := range []string{"x", "plenty"} {
			forms = append(forms, strings.Replace(pattern, "*", fill, 1))
		}
	}
	for _, label := range dnsListLines(dnsBrandLabelsText) {
		if !slices.Contains(labels, label) {
			t.Errorf("brand %q is not a reserved label", label)
		}
	}
	for _, form := range forms {
		if !IsReservedDnsLabel(form) || !IsReservedDnsLabel(strings.ToUpper(form)) {
			t.Errorf("%q is not reserved", form)
		}
		if err := ValidateDnsName(form); err == nil {
			t.Errorf("ValidateDnsName(%q) accepted a reserved name", form)
		}
	}
	// a copy, so a caller cannot change the list
	labels[0] = "changed"
	patterns[0] = "changed"
	if ReservedDnsLabels()[0] == "changed" || ReservedDnsPatterns()[0] == "changed" {
		t.Fatal("the lists share their backing arrays with callers")
	}
}

// Each mapping alone turns a brand's token into a refused one, in either token, and the mapping is
// applied to brands too, so a brand spelled with rn is matched by m.
func TestDnsBrandMappingEachSubstitution(t *testing.T) {
	cases := []struct {
		name  string
		brand bool
	}{
		{name: "g00gle", brand: true},
		{name: "faceb00k", brand: true},
		{name: "1inkedin", brand: true},
		{name: "netf1ix", brand: true},
		{name: "t3l3gram", brand: true},
		{name: "5antander", brand: true},
		{name: "hello-paypa1", brand: true},
		{name: "umetwork-cloud", brand: true},
		{name: "bumer", brand: true},
		{name: "googles", brand: false},
		{name: "g0-0gle", brand: false},
	}
	for _, c := range cases {
		if brand := IsBrandConfusableDnsName(c.name); brand != c.brand {
			t.Errorf("IsBrandConfusableDnsName(%q) = %t, want %t", c.name, brand, c.brand)
		}
	}
}

// A line that breaks either file's format refuses the whole list.
func TestDnsReservedListRefusesMalformedLines(t *testing.T) {
	refused := []struct {
		reserved string
		brands   string
	}{
		{reserved: "Upper\n"},
		{reserved: "has space\n"},
		{reserved: "-edge\n"},
		{reserved: "a*b\n"},
		{reserved: "*\n"},
		{reserved: "**\n"},
		{reserved: "*x*\n"},
		{reserved: "*-\n"},
		{reserved: "-*\n"},
		{reserved: "twice\ntwice\n"},
		{reserved: "*-lb\n*-lb\n"},
		{brands: "has-dash\n"},
		{brands: "Brand\n"},
		{brands: "twice\ntwice\n"},
	}
	for _, c := range refused {
		if _, err := parseDnsReservedList(c.reserved, c.brands); err == nil {
			t.Errorf("parsed reserved %q and brands %q", c.reserved, c.brands)
		}
	}
	list, err := parseDnsReservedList("# a comment\n\n  spaced  \nmain-*\n*-lb\n", "# brands\nacme\n")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(list.sortedLabels, []string{"acme", "spaced"}) || !slices.Equal(list.patterns, []string{"main-*", "*-lb"}) {
		t.Fatalf("labels %v, patterns %v", list.sortedLabels, list.patterns)
	}
}

// 10,000 draws from crypto/rand each match the grammar and none is reserved or confusable.
func TestNewDnsLabelDrawsTheGrammar(t *testing.T) {
	seen := map[string]bool{}
	for range 10000 {
		label, err := NewDnsLabel(rand.Reader)
		if errors.Is(err, ErrDnsLabelDrawRefused) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !testDnsLabelPattern.MatchString(label) {
			t.Fatalf("drew %q", label)
		}
		if IsReservedDnsLabel(label) || IsBrandConfusableDnsName(label) || ValidateDnsName(label) != nil {
			t.Fatalf("drew %q, which the rules refuse", label)
		}
		seen[label] = true
	}
	// 51 bits each: a repeat among 10,000 has probability below 2^-24
	if len(seen) < 9990 {
		t.Fatalf("%d distinct labels in 10,000 draws", len(seen))
	}
}

// A fixed reader gives a fixed label, and a byte at or past the largest multiple of the alphabet's
// size is skipped rather than folded in, which would bias the low characters.
func TestNewDnsLabelIsAFunctionOfItsBytes(t *testing.T) {
	random := make([]byte, dnsLabelDrawByteCount)
	// first character: 255, 250 and 234 are past 26*9 and skipped, then 25 is z; the rest: 252 is past
	// 36*7 and skipped, then 251 is 251%36 = 35, the digit 9, and 0 is a
	copy(random, []byte{255, 250, 234, 25, 252, 251, 0, 1, 2, 26, 27, 36, 72, 108})
	label, err := NewDnsLabel(bytes.NewReader(random))
	if err != nil {
		t.Fatal(err)
	}
	if label != "z9abc01aaa" {
		t.Fatalf("drew %q", label)
	}
	again, err := NewDnsLabel(bytes.NewReader(random))
	if err != nil || again != label {
		t.Fatalf("drew %q then %q (%v)", label, again, err)
	}
}

// A draw that lands on a reserved label is refused for the caller to draw again, as is one whose
// bytes run out before ten are kept, and a reader that ends early answers its error.
func TestNewDnsLabelRefusesWhatItCannotUse(t *testing.T) {
	random := make([]byte, dnsLabelDrawByteCount)
	// taskworker: t, then a s k w o r k e r at their places in the second alphabet
	copy(random, []byte{19, 0, 18, 10, 22, 14, 17, 10, 4, 17})
	if _, err := NewDnsLabel(bytes.NewReader(random)); !errors.Is(err, ErrDnsLabelDrawRefused) {
		t.Fatalf("a reserved draw answered %v", err)
	}
	if _, err := NewDnsLabel(bytes.NewReader(bytes.Repeat([]byte{255}, dnsLabelDrawByteCount))); !errors.Is(err, ErrDnsLabelDrawRefused) {
		t.Fatalf("a draw with no usable byte answered %v", err)
	}
	if _, err := NewDnsLabel(bytes.NewReader(make([]byte, dnsLabelDrawByteCount-1))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a short reader answered %v", err)
	}
	if _, err := NewDnsLabel(nil); err == nil {
		t.Fatal("drew with no reader")
	}
}

// One seed of testdata/fuzz/FuzzValidateDnsName.
func testDnsNameSeed(t *testing.T, name string, seed []byte) string {
	t.Helper()
	header, body, found := strings.Cut(string(seed), "\n")
	if !found || header != "go test fuzz v1" {
		t.Fatalf("%s: not a corpus file", name)
	}
	quoted, found := strings.CutPrefix(strings.TrimSpace(body), "string(")
	if !found {
		t.Fatalf("%s: not a string value", name)
	}
	value, err := strconv.Unquote(strings.TrimSuffix(quoted, ")"))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return value
}

// The seeds hold the fuzz target's property on every leg: go test runs them through
// FuzzValidateDnsName only where a file system lets it read them, and the Worker has none.
func TestDnsNameFuzzSeedsHold(t *testing.T) {
	const directory = "testdata/fuzz/FuzzValidateDnsName"
	entries, err := fs.ReadDir(testDnsLabelFiles, directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 8 {
		t.Fatalf("%d seeds", len(entries))
	}
	for _, entry := range entries {
		seed, err := testDnsLabelFiles.ReadFile(directory + "/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if failure := checkValidateDnsName(testDnsNameSeed(t, entry.Name(), seed)); failure != "" {
			t.Errorf("%s: %s", entry.Name(), failure)
		}
	}
}
