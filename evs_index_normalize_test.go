// Normalizer 1 and the trigram extractor against §22.5's vectors, and against a pipeline and an extractor written
// apart here, one whole string at a time, sharing none of the code they check.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const testNormalizeVectorPath = "testdata/index/normalize/vectors.json"

// One normalization case: want is worked by hand, not by this package.
type testNormalizeCase struct {
	name string
	text string
	want string
}

var testNormalizeCases = []testNormalizeCase{
	{name: "empty", text: "", want: ""},
	{name: "nfkc-ligature", text: "\uFB01ne", want: "fine"},
	{name: "nfkc-fullwidth", text: "\uFF21\uFF22\uFF23\uFF11\uFF12\uFF13", want: "abc123"},
	{name: "nfkc-superscript", text: "x\u00B2", want: "x2"},
	{name: "nfkc-circled", text: "\u2460", want: "1"},
	{name: "nfkc-halfwidth-kana", text: "\uFF76\uFF9E", want: "\u30AC"},
	{name: "nfkc-square", text: "\u3314", want: "\u30AD\u30ED"},
	{name: "nfkc-roman", text: "\u2167", want: "viii"},
	{
		name: "nfkc-widest",
		text: "\uFDFA",
		want: "\u0635\u0644\u0649 \u0627\u0644\u0644\u0647 \u0639\u0644\u064A\u0647 \u0648\u0633\u0644\u0645",
	},
	{name: "fold-sharp-s", text: "Stra\u00DFe", want: "strasse"},
	{name: "fold-capital-sharp-s", text: "STRA\u1E9EE", want: "strasse"},
	{name: "fold-final-sigma", text: "\u03C3\u03AF\u03C3\u03C5\u03C6\u03BF\u03C2", want: "\u03C3\u03B9\u03C3\u03C5\u03C6\u03BF\u03C3"},
	{name: "fold-capital-sigma", text: "\u03A3\u0399\u03A3\u03A5\u03A6\u039F\u03A3", want: "\u03C3\u03B9\u03C3\u03C5\u03C6\u03BF\u03C3"},
	{name: "fold-dotted-capital-i", text: "\u0130stanbul", want: "istanbul"},
	{name: "fold-dotless-i", text: "\u0131s\u0131", want: "\u0131s\u0131"},
	{name: "fold-kelvin", text: "\u212A", want: "k"},
	{name: "fold-angstrom", text: "\u212B", want: "a"},
	{name: "fold-ypogegrammeni", text: "\u1FB3", want: "\u03B1\u03B9"},
	{name: "fold-cherokee-capital", text: "\u13A0", want: "\u13A0"},
	{name: "fold-cherokee-small", text: "\uAB70", want: "\u13A0"},
	{name: "fold-cherokee-capital-end", text: "\u13F0", want: "\u13F0"},
	{name: "fold-cherokee-small-end", text: "\u13F8", want: "\u13F0"},
	{name: "marks-latin-precomposed", text: "caf\u00E9", want: "cafe"},
	{name: "marks-latin-combining", text: "cafe\u0301", want: "cafe"},
	{name: "marks-latin-stacked", text: "Vi\u1EC7t", want: "viet"},
	{name: "marks-latin-many", text: "a\u0301\u0323\u0308\u0328", want: "a"},
	{name: "marks-greek", text: "\u1F00\u03C1\u03C7\u03AE", want: "\u03B1\u03C1\u03C7\u03B7"},
	{name: "marks-cyrillic", text: "\u0439\u043E\u0434", want: "\u0438\u043E\u0434"},
	{name: "marks-arabic", text: "\u0645\u064E\u0631\u0652\u062D\u064E\u0628\u064B\u0627", want: "\u0645\u0631\u062D\u0628\u0627"},
	{name: "marks-hebrew", text: "\u05E9\u05C1\u05B8\u05DC\u05D5\u05B9\u05DD", want: "\u05E9\u05DC\u05D5\u05DD"},
	{name: "marks-kept-kana", text: "\u304C", want: "\u304C"},
	{name: "marks-kept-kana-combining", text: "\u304B\u3099", want: "\u304C"},
	{name: "marks-kept-thai", text: "\u0E01\u0E34\u0E19", want: "\u0E01\u0E34\u0E19"},
	{name: "marks-kept-devanagari", text: "\u0939\u093F\u0928\u094D\u0926\u0940", want: "\u0939\u093F\u0928\u094D\u0926\u0940"},
	{name: "marks-kept-hangul", text: "\uD55C\uAE00", want: "\uD55C\uAE00"},
	{name: "marks-hangul-jamo-compose", text: "\u1112\u1161\u11AB", want: "\uD55C"},
	{name: "marks-after-punctuation", text: ".\u0301", want: " \u0301"},
	{name: "marks-spacing-mark-between", text: "a\u0903\u0301", want: "a\u0903\u0301"},
	{name: "marks-stream-safe-kept", text: "\u0E01" + strings.Repeat("\u0301", 40), want: "\u0E01" + strings.Repeat("\u0301", 30) + "\u034F" + strings.Repeat("\u0301", 10)},
	{name: "marks-stream-safe-dropped", text: "a" + strings.Repeat("\u0301", 40), want: "a"},
	{name: "runs-dashes", text: "a--b", want: "a b"},
	{name: "runs-mixed", text: "a , . ; b", want: "a b"},
	{name: "runs-at-both-ends", text: "...x...", want: " x "},
	{name: "runs-whitespace-only", text: "\t\r\n ", want: " "},
	{name: "runs-symbol", text: "\u20AC100", want: " 100"},
	{name: "runs-underscore", text: "a_b", want: "a b"},
	{name: "runs-apostrophe", text: "don't", want: "don t"},
	{name: "runs-address", text: "user@example.com", want: "user example com"},
	{name: "runs-soft-hyphen", text: "soft\u00ADhyphen", want: "soft hyphen"},
	{name: "numbers-arabic-indic", text: "\u0663\u0664", want: "\u0663\u0664"},
	{name: "numbers-fraction", text: "\u00BD", want: "1 2"},
	{name: "invalid-middle", text: "a\xFFb", want: "a b"},
	{name: "invalid-alone", text: "\xC3", want: " "},
	{name: "invalid-cut-at-end", text: "a\xE2\x82", want: "a "},
	{name: "invalid-surrogate", text: "\xED\xA0\x80", want: " "},
	{name: "invalid-overlong", text: "\xC0\x80", want: " "},
	{name: "invalid-replacement-itself", text: "a\uFFFDb", want: "a b"},
	{name: "hebrew-gimel-dot", text: "\u05D2\u0307", want: "\u05D2"},
	{name: "hebrew-final-kaf-dot", text: "\u05DA\u0307", want: "\u05DA"},
	{name: "hebrew-gimel-dagesh-dot", text: "\uFB32\u0307", want: "\u05D2"},
	{name: "hebrew-final-kaf-dagesh-dot", text: "\uFB3A\u0307", want: "\u05DA"},
	{name: "linear-b-dot", text: "\U00010044\u0307", want: "\U00010044\u0307"},
}

// Steps 1-5 a whole string at a time, each step from its own library call or loop.
func testReferenceNormalize(text string) string {
	// step 1, by Go's own conversion, which writes one U+FFFD for each ill-formed byte
	text = string([]rune(text))
	text = norm.NFKC.String(text)
	text = cases.Fold().String(text)
	// CaseFolding.txt takes each Cherokee pair to its lower code point, which here is read off the Go tables' fold orbit
	text = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cherokee, r) {
			return min(r, unicode.SimpleFold(r))
		}
		return r
	}, text)
	text = norm.NFD.String(text)
	kept := []rune{}
	base := rune(-1)
	for _, r := range text {
		if !unicode.Is(unicode.Mn, r) {
			base = r
		} else if unicode.IsLetter(base) && (unicode.Is(unicode.Latin, base) || unicode.Is(unicode.Greek, base) ||
			unicode.Is(unicode.Cyrillic, base) || unicode.Is(unicode.Arabic, base) || unicode.Is(unicode.Hebrew, base)) {
			continue
		}
		kept = append(kept, r)
	}
	text = norm.NFC.String(string(kept))
	var folded strings.Builder
	spaces := 0
	for _, r := range text {
		if unicode.In(r, unicode.L, unicode.M, unicode.N) {
			folded.WriteRune(r)
			spaces = 0
			continue
		}
		if spaces == 0 {
			folded.WriteByte(' ')
		}
		spaces += 1
	}
	return folded.String()
}

// A key set found by looking at every window and remembering it, the extractor §22.6 asks for.
func testReferenceTrigrams(text []byte) indexKeySet {
	seen := map[[3]byte]bool{}
	for index := 0; index+3 <= len(text); index += 1 {
		seen[[3]byte(text[index:index+3])] = true
	}
	keys := indexKeySet{}
	for window := range seen {
		keys = append(keys, uint32(window[0])*65536+uint32(window[1])*256+uint32(window[2]))
	}
	slices.Sort(keys)
	return keys
}

// A text exercising every step at once, with invalid bytes, expansions and cut-sensitive sequences.
func testNormalizeMixedText() string {
	var text strings.Builder
	for _, c := range testNormalizeCases {
		text.WriteString(c.text)
		text.WriteByte(' ')
	}
	return text.String()
}

func TestNormalizationCases(t *testing.T) {
	for _, c := range testNormalizeCases {
		normalized, err := indexNormalize([]byte(c.text))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if string(normalized) != c.want {
			t.Errorf("%s: got %+q, want %+q", c.name, normalized, c.want)
		}
		if reference := testReferenceNormalize(c.text); reference != c.want {
			t.Errorf("%s: the reference reads %+q, want %+q", c.name, reference, c.want)
		}
	}
}

// D-TEST-15: linking normalizer 1's x/text is what keeps these out of the defect, so NFC is pinned by itself as well
// as through the pipeline, whose step 4 drops the Hebrew marks either way.
func TestLinkedNfcKeepsTheDefectivePairs(t *testing.T) {
	for _, text := range []string{"\u05D2\u0307", "\u05DA\u0307", "\U00010044\u0307"} {
		if got := norm.NFC.String(text); got != text {
			t.Errorf("NFC of %+q is %+q", text, got)
		}
	}
	for _, c := range []struct{ text, want string }{
		{text: "\uFB32\u0307", want: "\u05D2\u05BC\u0307"},
		{text: "\uFB3A\u0307", want: "\u05DA\u05BC\u0307"},
	} {
		if got := norm.NFC.String(c.text); got != c.want {
			t.Errorf("NFC of %+q is %+q, want %+q", c.text, got, c.want)
		}
	}
}

// Every leg reads these from its own build (D-TEST-15), so a toolchain or x/text bump fails here until a new
// normalizer is assigned. A test binary's build info carries x/text, the same as a release's.
func TestLinkedTablesAreNormalizerOne(t *testing.T) {
	tables := indexLinkedTables()
	want := indexTables{
		normVersion:       "17.0.0",
		casesVersion:      "17.0.0",
		unicodeVersion:    "17.0.0",
		textModuleVersion: "v0.43.0",
	}
	if tables != want {
		t.Errorf("linked %+v, want %+v", tables, want)
	}
	if !tables.isNormalizerOne() {
		t.Error("the linked tables are not normalizer 1's")
	}
}

// §11.14's tables row: another table or module is another normalizer, even with one version string the same.
func TestOtherTablesWriteNothing(t *testing.T) {
	cases := []func(tables *indexTables){
		func(tables *indexTables) { tables.normVersion = "15.0.0" },
		func(tables *indexTables) { tables.casesVersion = "15.0.0" },
		func(tables *indexTables) { tables.unicodeVersion = "15.0.0" },
		func(tables *indexTables) { tables.textModuleVersion = "v0.40.0" },
		func(tables *indexTables) { tables.textModuleVersion = "" },
	}
	for index, change := range cases {
		tables := indexLinkedTables()
		change(&tables)
		normalizer, err := indexNewNormalizer(tables)
		if !errors.Is(err, errIndexOtherNormalizer) || normalizer != nil {
			t.Errorf("case %d: got %v, %v", index, normalizer, err)
		}
	}
}

// plan-SEARCH-cherokee-fold's rule: every one of the 172 code points x/text's fold swaps comes out as the form
// CaseFolding.txt names, the pair of a capital and a small letter as one, so a query finds either.
func TestCherokeeFoldsToOneForm(t *testing.T) {
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	swapped := 0
	for _, block := range [][3]rune{{0x13A0, 0x13F5, 0x13A0}, {0x13F8, 0x13FD, 0x13F0}, {0xAB70, 0xABBF, 0x13A0}} {
		for r := block[0]; r <= block[1]; r += 1 {
			if once := cases.Fold().String(string(r)); once != string(r) && cases.Fold().String(once) == string(r) {
				swapped += 1
			}
			got, err := normalizer.normalize([]byte(string(r)))
			if err != nil {
				t.Fatal(err)
			}
			if want := string(block[2] + r - block[0]); string(got) != want {
				t.Errorf("%U reads %+q, want %+q", r, got, want)
			}
		}
	}
	if swapped != 172 {
		t.Errorf("the fold swaps %d code points, want 172", swapped)
	}
	document := testDocumentKeys(t, "\uAB70\uAB71")
	if len(indexTrigrams([]byte("\u13A0\u13A1")).without(document)) != 0 {
		t.Error("a query in one case does not find a document in the other")
	}
}

// A failed read is one text's: a normalizer kept across documents goes on, with no state left from the field it lost.
func TestAFailedReadLeavesTheNormalizerUsable(t *testing.T) {
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("the source broke")
	failing := io.MultiReader(strings.NewReader("half a do"), iotest.ErrReader(failure))
	if _, err := normalizer.documentKeys([]indexTextField{{number: indexFieldBody, text: failing}}); !errors.Is(err, failure) {
		t.Fatalf("got %v", err)
	}
	keys, err := normalizer.documentKeys([]indexTextField{{number: indexFieldBody, text: strings.NewReader("ab")}})
	if err != nil || !slices.Equal(keys, indexTrigrams([]byte(" ab "))) {
		t.Errorf("after a failed read: %x, %v", keys, err)
	}
	if got, err := normalizer.normalize([]byte("Clean")); err != nil || string(got) != "clean" {
		t.Errorf("after a failed read: %q, %v", got, err)
	}
}

// Marks run past the 30 non-starters x/text's stream-safe rule allows, and past a chain buffer, so a code path that
// only short text reaches cannot differ between the whole string and the stream.
func TestLongMarkRunsStreamAlike(t *testing.T) {
	for _, base := range []string{"a", "\u05D0", "\u0E01", "\u0915", "\u304B", " ", ".", "1", "\uD55C"} {
		for _, length := range []int{29, 30, 31, 60, 61, 1500, 5000} {
			text := base + strings.Repeat("\u0301\u0323", length)
			whole := testReferenceNormalize(text)
			normalizer, err := indexNewNormalizer(indexLinkedTables())
			if err != nil {
				t.Fatal(err)
			}
			streamed, err := io.ReadAll(normalizer.stream(iotest.HalfReader(strings.NewReader(text))))
			if err != nil {
				t.Fatal(err)
			}
			if string(streamed) != whole {
				t.Errorf("%+q x %d differs", base, length)
			}
			if testReferenceNormalize(whole) != whole {
				t.Errorf("%+q x %d is not idempotent", base, length)
			}
		}
	}
}

// SEARCH-M10-03's proof: the stream equals the whole string at every split of a text touching every step.
func TestStreamEqualsWholeAtEverySplit(t *testing.T) {
	text := []byte(testNormalizeMixedText())
	whole, err := indexNormalize(text)
	if err != nil {
		t.Fatal(err)
	}
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	for split := range text {
		streamed, err := io.ReadAll(normalizer.stream(io.MultiReader(bytes.NewReader(text[:split]), bytes.NewReader(text[split:]))))
		if err != nil {
			t.Fatalf("split %d: %v", split, err)
		}
		if !bytes.Equal(streamed, whole) {
			t.Fatalf("split %d differs", split)
		}
	}
	oneByte, err := io.ReadAll(normalizer.stream(iotest.OneByteReader(bytes.NewReader(text))))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oneByte, whole) {
		t.Error("a byte at a time differs")
	}
}

// One document's text as §11.14 assembles it.
func testDocumentText(t *testing.T, fields []indexTextField) string {
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	if err := normalizer.writeDocument(&text, fields); err != nil {
		t.Fatal(err)
	}
	return text.String()
}

func TestFieldsPadAndJoinInOrder(t *testing.T) {
	got := testDocumentText(t, []indexTextField{
		{number: indexFieldSubject, text: strings.NewReader("Re: Hello")},
		{number: indexFieldFrom, text: strings.NewReader("Ann <ann@example.com>")},
		{number: indexFieldTo, text: nil},
		{number: indexFieldTitle, text: strings.NewReader("")},
		{number: indexFieldBody, text: strings.NewReader("Body text.")},
	})
	if want := " re hello  ann ann example com   body text  "; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPunctuationOnlyFieldStaysAField(t *testing.T) {
	if got := testDocumentText(t, []indexTextField{{number: indexFieldBody, text: strings.NewReader("...")}}); got != "   " {
		t.Errorf("got %q", got)
	}
}

// Step 6: a 3-byte letter at the cut, so the 1,024th byte is inside a code point, and the body is never cut.
func TestHeaderFieldsCutOnACodePoint(t *testing.T) {
	long := strings.Repeat("\u3042", 500)
	for _, number := range []int{indexFieldSubject, indexFieldFrom, indexFieldTo, indexFieldTitle} {
		got := testDocumentText(t, []indexTextField{{number: number, text: strings.NewReader(long)}})
		if want := " " + strings.Repeat("\u3042", 341) + " "; got != want {
			t.Errorf("field %d kept %d bytes", number, len(got))
		}
	}
	exact := strings.Repeat("a", 1024)
	if got := testDocumentText(t, []indexTextField{{number: indexFieldSubject, text: strings.NewReader(exact)}}); got != " "+exact+" " {
		t.Errorf("exactly 1 KiB kept %d bytes", len(got))
	}
	got := testDocumentText(t, []indexTextField{{number: indexFieldBody, text: strings.NewReader(long)}})
	if want := " " + long + " "; got != want {
		t.Errorf("the body kept %d bytes", len(got))
	}
	got = testDocumentText(t, []indexTextField{{number: 6, text: strings.NewReader(long)}})
	if want := " " + long + " "; got != want {
		t.Errorf("field 6 kept %d bytes", len(got))
	}
}

func TestFieldsOutOfOrderAreRefused(t *testing.T) {
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	for _, numbers := range [][]int{{2, 1}, {1, 1}, {0}, {-1}, {16}} {
		fields := []indexTextField{}
		for _, number := range numbers {
			fields = append(fields, indexTextField{number: number})
		}
		if _, err := normalizer.documentKeys(fields); !errors.Is(err, errIndexFieldOrder) {
			t.Errorf("%v reads %v", numbers, err)
		}
	}
}

func TestTrigramsOfAText(t *testing.T) {
	cases := []struct {
		text string
		want indexKeySet
	}{
		{text: "", want: indexKeySet{}},
		{text: "ab", want: indexKeySet{}},
		{text: " a ", want: indexKeySet{0x206120}},
		{text: "abcd", want: indexKeySet{0x616263, 0x626364}},
		{text: "aaaa", want: indexKeySet{0x616161}},
		{text: "cba", want: indexKeySet{0x636261}},
		{text: "bab", want: indexKeySet{0x626162}},
	}
	for _, c := range cases {
		if got := indexTrigrams([]byte(c.text)); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %x, want %x", c.text, got, c.want)
		}
	}
}

// §11.14's cjk row: UTF-8's lead and continuation bytes are disjoint, so a 3-byte character is one exact key, two of
// them four, and a 4-byte character two.
func TestCjkQueriesResolveToWholeCharacters(t *testing.T) {
	one := indexTrigrams([]byte("\u6F22"))
	if !slices.Equal(one, indexKeySet{0xE6BCA2}) {
		t.Errorf("one character: %x", one)
	}
	if got := indexTrigrams([]byte("\u6F22\u5B57")); len(got) != 4 {
		t.Errorf("two characters: %x", got)
	}
	if got := indexTrigrams([]byte("\U0002000B")); len(got) != 2 {
		t.Errorf("a 4-byte character: %x", got)
	}
	document := testDocumentKeys(t, "\u65E5\u672C\u8A9E\u306E\u6F22\u5B57")
	for _, query := range []string{"\u6F22", "\u6F22\u5B57", "\u672C\u8A9E"} {
		if len(indexTrigrams([]byte(query)).without(document)) != 0 {
			t.Errorf("%q is not in the document", query)
		}
	}
}

// A body's key set.
func testDocumentKeys(t *testing.T, body string) indexKeySet {
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	keys, err := normalizer.documentKeys([]indexTextField{{number: indexFieldBody, text: strings.NewReader(body)}})
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// §22.5: every substring of three or more normalized bytes of a document yields only trigrams in its set, so a query
// for any of it finds the document.
func TestTrigramsAreComplete(t *testing.T) {
	text := testDocumentText(t, []indexTextField{
		{number: indexFieldSubject, text: strings.NewReader("Subject of 100%")},
		{number: indexFieldBody, text: strings.NewReader(testNormalizeMixedText())},
	})
	keys := indexTrigrams([]byte(text))
	if !slices.Equal(keys, testReferenceTrigrams([]byte(text))) {
		t.Error("the set is not the reference's")
	}
	for start := 0; start < len(text); start += 1 {
		for _, length := range []int{3, 4, 7, 31, 256} {
			if len(text) < start+length {
				continue
			}
			if missing := indexTrigrams([]byte(text[start : start+length])).without(keys); len(missing) != 0 {
				t.Fatalf("at %d: %x", start, missing)
			}
		}
	}
}

// The word boundaries §11.14's query row counts on, a short word matching through its padding: " a " and " go", "go ".
func TestShortWordsMatchThroughTheirPadding(t *testing.T) {
	keys := testDocumentKeys(t, "to go, a day")
	for _, window := range []string{" a ", " go", "go "} {
		if len(indexTrigrams([]byte(window)).without(keys)) != 0 {
			t.Errorf("%q is missing", window)
		}
	}
	if len(indexTrigrams([]byte(" o ")).without(keys)) == 0 {
		t.Error("a word that is not there matched")
	}
}

func TestCollectorEqualsTheReferenceAcrossWrites(t *testing.T) {
	text := []byte(testDocumentText(t, []indexTextField{{number: indexFieldBody, text: strings.NewReader(testNormalizeMixedText())}}))
	want := testReferenceTrigrams(text)
	collector := indexNewTrigramCollector()
	for split := 0; split <= len(text); split += 1 {
		collector.reset()
		collector.Write(text[:split])
		collector.Write(text[split:])
		if !slices.Equal(collector.keys(), want) {
			t.Fatalf("split %d differs", split)
		}
	}
	// reset forgets the window as well as the words, so one document's last bytes start no key in the next
	collector.reset()
	collector.Write([]byte("xy"))
	collector.reset()
	collector.Write([]byte("z"))
	if keys := collector.keys(); len(keys) != 0 {
		t.Errorf("a window crossed a reset: %x", keys)
	}
}

// One vector of testNormalizeVectorPath.
type testNormalizeVector struct {
	Name             string `json:"name"`
	TextHex          string `json:"text_hex"`
	NormalizedHex    string `json:"normalized_hex"`
	NormalizedSha256 string `json:"normalized_sha256"`
	KeySetSha256     string `json:"key_set_sha256"`
}

// What testNormalizeVectorPath holds: the tables it was written under, and each case's bytes and hashes.
type testNormalizeVectorFile struct {
	NormVersion       string                `json:"norm_version"`
	CasesVersion      string                `json:"cases_version"`
	UnicodeVersion    string                `json:"unicode_version"`
	TextModuleVersion string                `json:"text_module_version"`
	Vectors           []testNormalizeVector `json:"vectors"`
}

// The vector of a case, written from the reference and the hand-worked want, never from the code under test.
func testBuildNormalizeVector(t *testing.T, c testNormalizeCase) testNormalizeVector {
	if reference := testReferenceNormalize(c.text); reference != c.want {
		t.Fatalf("%s: the reference reads %+q", c.name, reference)
	}
	normalizedSum := sha256.Sum256([]byte(c.want))
	encoded, err := testReferenceTrigrams([]byte(" " + c.want + " ")).appendEncoded(nil)
	if err != nil {
		t.Fatal(err)
	}
	keySetSum := sha256.Sum256(encoded)
	return testNormalizeVector{
		Name:             c.name,
		TextHex:          hex.EncodeToString([]byte(c.text)),
		NormalizedHex:    hex.EncodeToString([]byte(c.want)),
		NormalizedSha256: hex.EncodeToString(normalizedSum[:]),
		KeySetSha256:     hex.EncodeToString(keySetSum[:]),
	}
}

// §22.5's normalization vectors, byte-equal on every leg (D-TEST-15): this file reads the same on each, so a leg that
// normalizes differently fails here.
func TestNormalizationVectors(t *testing.T) {
	tables := indexLinkedTables()
	file := testNormalizeVectorFile{}
	if os.Getenv(testWriteVectorsEnvironment) != "" {
		file = testNormalizeVectorFile{
			NormVersion:       tables.normVersion,
			CasesVersion:      tables.casesVersion,
			UnicodeVersion:    tables.unicodeVersion,
			TextModuleVersion: tables.textModuleVersion,
		}
		for _, c := range testNormalizeCases {
			file.Vectors = append(file.Vectors, testBuildNormalizeVector(t, c))
		}
		testWriteJson(t, testNormalizeVectorPath, file)
	} else {
		encoded, err := testIndexFiles.ReadFile(testNormalizeVectorPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &file); err != nil {
			t.Fatal(err)
		}
	}
	if file.NormVersion != tables.normVersion || file.CasesVersion != tables.casesVersion ||
		file.UnicodeVersion != tables.unicodeVersion || file.TextModuleVersion != tables.textModuleVersion {
		t.Errorf("the vectors were written under other tables: %s %s %s %s",
			file.NormVersion, file.CasesVersion, file.UnicodeVersion, file.TextModuleVersion)
	}
	if len(file.Vectors) != len(testNormalizeCases) {
		t.Errorf("%d vectors for %d cases", len(file.Vectors), len(testNormalizeCases))
	}
	normalizer, err := indexNewNormalizer(tables)
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range file.Vectors {
		text, err := hex.DecodeString(vector.TextHex)
		if err != nil {
			t.Fatal(err)
		}
		normalized, err := normalizer.normalize(text)
		if err != nil {
			t.Errorf("%s: %v", vector.Name, err)
			continue
		}
		if hex.EncodeToString(normalized) != vector.NormalizedHex {
			t.Errorf("%s: got %x, want %s", vector.Name, normalized, vector.NormalizedHex)
		}
		normalizedSum := sha256.Sum256(normalized)
		if hex.EncodeToString(normalizedSum[:]) != vector.NormalizedSha256 {
			t.Errorf("%s: normalized hash differs", vector.Name)
		}
		keys, err := normalizer.documentKeys([]indexTextField{{number: indexFieldBody, text: bytes.NewReader(text)}})
		if err != nil {
			t.Errorf("%s: %v", vector.Name, err)
			continue
		}
		// a case with no text at all is a field that adds nothing, not one of two spaces
		if len(text) == 0 {
			if len(keys) != 0 {
				t.Errorf("%s: %x", vector.Name, keys)
			}
			continue
		}
		encoded, err := keys.appendEncoded(nil)
		if err != nil {
			t.Fatal(err)
		}
		keySetSum := sha256.Sum256(encoded)
		if hex.EncodeToString(keySetSum[:]) != vector.KeySetSha256 {
			t.Errorf("%s: key set hash differs", vector.Name)
		}
	}
}

// The text fed to the reference is not assumed valid, so the two pipelines agree on what step 1 means too.
func TestInvalidUtf8HasOneRule(t *testing.T) {
	for _, text := range []string{"\xFF\xFE", "\xE2\x82", "a\xF0\x9F\x98", "\xC0\xAF", "\xED\xA0\x80"} {
		if utf8.ValidString(text) {
			t.Fatalf("%q is valid", text)
		}
		direct, err := indexNormalize([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		replaced, err := indexNormalize([]byte(string([]rune(text))))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(direct, replaced) {
			t.Errorf("%q: %q and %q", text, direct, replaced)
		}
	}
}

func TestNormalizeSeedFilesAreCurrent(t *testing.T) {
	for _, c := range testNormalizeCases {
		testCheckCorpusFile(t, "FuzzIndexNormalize", c.name, fmt.Sprintf("[]byte(%q)", c.text), "int(0)")
	}
	testCheckCorpusFile(t, "FuzzIndexNormalize", "mixed-text", fmt.Sprintf("[]byte(%q)", testNormalizeMixedText()), "int(17)")
}
