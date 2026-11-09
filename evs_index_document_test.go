// Documents: keys, chunks, the sniff, titles, the field registry, the never row and extractor 1 for files and mail,
// against testdata/index/extract/'s vectors and FS-79's document cases.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/urnetwork/sidecar/protocol"
)

const (
	testExtractVectorPath = "testdata/index/extract/vectors.json"
	testDocKeyVectorPath  = "testdata/index/extract/doc_keys.json"
)

// A normalizer on this build's tables, which TestLinkedTablesAreNormalizerOne holds to normalizer 1's.
func testIndexNormalizer(t testing.TB) *indexNormalizer {
	t.Helper()
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	return normalizer
}

// A document's key set, through prepare.
func testDocumentKeySet(t testing.TB, document *IndexDocument) indexKeySet {
	t.Helper()
	prepared, err := document.prepare(testIndexNormalizer(t), false, Id{})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.skipped {
		t.Fatal("a document skipped")
	}
	return prepared.keys
}

// Whether every key of a term's normalized text is in keys.
func testHoldsTerm(t testing.TB, keys indexKeySet, term string) bool {
	t.Helper()
	normalized, err := indexNormalize([]byte(term))
	if err != nil {
		t.Fatal(err)
	}
	return len(indexTrigrams(normalized).without(keys)) == 0
}

// §11.14's sniff row, FS-79's binary case: NUL or ill-formed UTF-8 in the first 8,000 bytes is a binary, a sequence
// cut by the 8,000th byte is not, and a UTF-16 byte-order mark selects the decoding.
func TestSniffFindsBinaries(t *testing.T) {
	euro := "€"
	cutAtTheWindow := strings.Repeat("a", indexSniffByteCount-1) + euro
	utf16Units := utf16.Encode([]rune("café \U0001F600"))
	bigEndian := append([]byte{}, indexUtf16BigEndianMark...)
	littleEndian := append([]byte{}, indexUtf16LittleEndianMark...)
	for _, unit := range utf16Units {
		bigEndian = append(bigEndian, byte(unit>>8), byte(unit))
		littleEndian = append(littleEndian, byte(unit), byte(unit>>8))
	}
	cases := []struct {
		name    string
		content []byte
		text    string
		isText  bool
	}{
		{name: "ascii", content: []byte("plain text\n"), text: "plain text\n", isText: true},
		{name: "empty", content: []byte{}, text: "", isText: true},
		{name: "a nul", content: []byte("ab\x00cd"), isText: false},
		{name: "a nul past 8,000 bytes", content: append([]byte(strings.Repeat("a", indexSniffByteCount)), 0), text: strings.Repeat("a", indexSniffByteCount) + "\x00", isText: true},
		{name: "latin-1", content: []byte("caf\xE9 au lait"), isText: false},
		{name: "a sequence the window cuts", content: []byte(cutAtTheWindow), text: cutAtTheWindow, isText: true},
		{name: "a lone continuation byte", content: []byte("a\x80b"), isText: false},
		{name: "a cut sequence at the end", content: []byte("ab\xE2\x82"), text: "ab\xE2\x82", isText: true},
		{name: "utf-16 big-endian", content: bigEndian, text: "café \U0001F600", isText: true},
		{name: "utf-16 little-endian", content: littleEndian, text: "café \U0001F600", isText: true},
		{name: "utf-16 with an odd byte", content: append(bytes.Clone(littleEndian), 'x'), text: "café \U0001F600�", isText: true},
	}
	for _, c := range cases {
		text, isText := indexSniff(c.content)
		if isText != c.isText || (isText && string(text) != c.text) {
			t.Errorf("%s: text %t %q", c.name, isText, text)
		}
		documents, ok := indexExtractFile([]byte("f"), c.content)
		if ok != c.isText || (ok && len(documents) != 1) {
			t.Errorf("%s: extracted %t, %d documents", c.name, ok, len(documents))
		}
	}
}

// A file's title: its first line with a letter or number, a heading's '#'s and spaces and its trailing spaces gone,
// 80 B cut on a code point.
func TestFileTitles(t *testing.T) {
	cases := []struct {
		text  string
		title string
	}{
		{text: "# The plan\nbody", title: "The plan"},
		{text: "\n\n---\n## Notes  \r\nmore", title: "Notes"},
		{text: "  indented line\t \r\n", title: "indented line"},
		{text: "!!!\n???\n", title: ""},
		{text: "", title: ""},
		{text: "#hashtag first", title: "hashtag first"},
		{text: "42", title: "42"},
		{text: strings.Repeat("é", 50), title: strings.Repeat("é", 40)},
		{text: "bad \xFF byte", title: "bad � byte"},
	}
	for _, c := range cases {
		if title := indexTitle([]byte(c.text)); title != c.title {
			t.Errorf("%q titled %q, want %q", c.text, title, c.title)
		}
	}
}

// FS-79: text past 1 MiB is one document per 1 MiB of the file, each with the next 256 B, every chunk keeping the
// title and path; a query within 256 B across a boundary is found, and one reaching further is in no document
// (plan-SEARCH-small-readings#2).
func TestTextPastOneMiBIsChunked(t *testing.T) {
	line := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit\n")
	content := []byte("# Long notes\n")
	for len(content) < 2*indexChunkByteCount+1000 {
		content = append(content, line...)
	}
	across := []byte("zebrafinch quokkawombat")
	boundary := indexChunkByteCount - 10
	copy(content[boundary:], across)
	reaching := []byte("platypus" + strings.Repeat("y", indexOverlapByteCount) + "narwhal")
	second := 2*indexChunkByteCount - 4
	copy(content[second:], reaching)
	documents, ok := indexExtractFile([]byte("notes/long.md"), content)
	if !ok || len(documents) != 3 {
		t.Fatalf("%d documents", len(documents))
	}
	for chunk, document := range documents {
		start := chunk * indexChunkByteCount
		end := min(len(content), start+indexChunkByteCount+indexOverlapByteCount)
		if document.Chunk != uint32(chunk) || !bytes.Equal(document.Fields[indexFieldBody], content[start:end]) {
			t.Errorf("chunk %d holds %d B", chunk, len(document.Fields[indexFieldBody]))
		}
		if string(document.Fields[indexFieldTitle]) != "Long notes" || document.ByteCount != uint64(len(content)) {
			t.Errorf("chunk %d titled %q of %d B", chunk, document.Fields[indexFieldTitle], document.ByteCount)
		}
	}
	first := testDocumentKeySet(t, documents[0])
	if !testHoldsTerm(t, first, string(across)) {
		t.Error("a term across the first boundary is not in the first chunk")
	}
	if !testHoldsTerm(t, testDocumentKeySet(t, documents[1]), "long notes notes long md") {
		t.Error("the second chunk lost its title and path")
	}
	for _, document := range documents {
		if testHoldsTerm(t, testDocumentKeySet(t, document), string(reaching)) {
			t.Errorf("a term reaching past the overlap is in chunk %d", document.Chunk)
		}
	}
}

// FS-79: a chunk whose key set would encode past 512 KiB is skipped, and one at it is kept. Ordinary text in any
// script stays far below the cap, so the boundary is held on key sets built to sit at it, and a whole chunk of prose
// is kept.
func TestChunkPastItsKeySetCapIsSkipped(t *testing.T) {
	// Every gap one byte and the count three: the set encodes to its key count plus 3.
	atCap := testIndexKeys(0, indexKeySetMaxByteCount-3, 1)
	if atCap.encodedByteCount() != indexKeySetMaxByteCount || indexKeySetSkipped(atCap) {
		t.Errorf("a set of %d B was skipped", atCap.encodedByteCount())
	}
	pastCap := testIndexKeys(0, indexKeySetMaxByteCount-2, 1)
	if !indexKeySetSkipped(pastCap) {
		t.Errorf("a set of %d B was kept", pastCap.encodedByteCount())
	}
	// Two-byte gaps reach the cap with fewer keys.
	sparse := testIndexKeys(0, indexKeySetMaxByteCount/2, 128)
	if !indexKeySetSkipped(sparse) {
		t.Errorf("a sparse set of %d B was kept", sparse.encodedByteCount())
	}
	prose := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog, again and again. "), indexChunkByteCount/62)
	document := &IndexDocument{Kind: IndexDocFile, Name: []byte("prose.txt"), ByteCount: uint64(len(prose))}
	document.Fields[indexFieldBody] = prose
	prepared, err := document.prepare(testIndexNormalizer(t), false, Id{})
	if err != nil || prepared.skipped || prepared.row == nil {
		t.Errorf("a chunk of prose: %+v %v", prepared, err)
	}
}

// D-KEYS-22: doc_key's bytes from a fixed K_ref, the same at every generation, since K_ref derives from RK_1, and
// over any path epoch, which no input of it names; a rename or another chunk is another key.
func TestDocKeyVectors(t *testing.T) {
	repoId := evsTestId("index repo")
	refId := evsTestId("main ref")
	keys := map[uint64][]byte{}
	for _, generation := range []uint64{1, 2, 5} {
		refKey, err := indexRefKey(evsTestRepoKey(repoId, generation))
		if err != nil {
			t.Fatal(err)
		}
		keys[generation] = refKey
	}
	if !bytes.Equal(keys[1], keys[2]) || !bytes.Equal(keys[1], keys[5]) {
		t.Fatal("K_ref moved with the generation")
	}
	type docKeyVector struct {
		Name   string `json:"name"`
		Chunk  uint32 `json:"chunk"`
		DocKey string `json:"doc_key"`
	}
	built := []docKeyVector{}
	for _, c := range []struct {
		name  string
		chunk uint32
	}{
		{name: "notes/plan.md", chunk: 0}, {name: "notes/plan.md", chunk: 1}, {name: "notes/plan2.md", chunk: 0},
		{name: "m/202611/ab/0123456789abcdef", chunk: 0}, {name: "run/0123456789abcdef0123456789abcdef", chunk: 0},
		{name: "", chunk: 0},
	} {
		docKey, err := indexDocKey(keys[1], refId, []byte(c.name), c.chunk)
		if err != nil {
			t.Fatal(err)
		}
		built = append(built, docKeyVector{Name: c.name, Chunk: c.chunk, DocKey: hex.EncodeToString(docKey[:])})
	}
	vectors := built
	if os.Getenv(testWriteVectorsEnvironment) != "" {
		testWriteJson(t, testDocKeyVectorPath, built)
	} else {
		encoded, err := testIndexFiles.ReadFile(testDocKeyVectorPath)
		if err != nil {
			t.Fatal(err)
		}
		vectors = nil
		if err := json.Unmarshal(encoded, &vectors); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(vectors, built) {
		t.Errorf("doc keys moved: %v", built)
	}
	seen := map[string]bool{}
	for _, vector := range built {
		if seen[vector.DocKey] {
			t.Errorf("two documents share %s", vector.DocKey)
		}
		seen[vector.DocKey] = true
	}
	// The doc key spelled out by hand: the label, ref_id, u16be length, name and u32be chunk under HMAC-SHA256.
	if built[1].DocKey != hex.EncodeToString(testHmacSha256(keys[1], append(append(append(append([]byte("UR evs 1.0 doc"), refId.Bytes()...), 0, 13), "notes/plan.md"...), 0, 0, 0, 1))[:indexIdByteCount]) {
		t.Error("doc_key is not its formula")
	}
	if _, err := indexDocKey(keys[1], refId, make([]byte, indexNameMaxByteCount+1), 0); !errors.Is(err, errIndexMalformed) {
		t.Errorf("a name past 65,535 B: %v", err)
	}
	if _, err := indexRefKey(&EvsRepoKey{repoId: repoId, generation: 3, repoKey: evsTestBytes("RK 3", evsKeyByteCount)}); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("K_ref without RK_1: %v", err)
	}
}

// HMAC-SHA256 written out, apart from indexDocKey's.
func testHmacSha256(key []byte, message []byte) []byte {
	block := make([]byte, sha256.BlockSize)
	copy(block, key)
	inner := sha256.New()
	outer := sha256.New()
	for index := range block {
		inner.Write([]byte{block[index] ^ 0x36})
		outer.Write([]byte{block[index] ^ 0x5c})
	}
	inner.Write(message)
	outer.Write(inner.Sum(nil))
	return outer.Sum(nil)
}

// INDEX-FORMAT.md's HTML rules, case by case.
func TestHtmlIsStrippedByItsRules(t *testing.T) {
	cases := []struct {
		html string
		text string
	}{
		{html: "<b>a</b>b", text: "ab"},
		{html: "<p>a</p><p>b</p>", text: " a  b "},
		{html: "x<br/>y<BR>z", text: "x y z"},
		{html: "a<script>var b = '</p>';</script>c", text: "ac"},
		{html: "a<STYLE type=x>p{}</Style >c", text: "ac"},
		{html: "a<script>never ends", text: "a"},
		{html: "a<scripts>b</scripts>c", text: "abc"},
		{html: "a<script>x</scriptx>y</script>z", text: "az"},
		{html: "a<!-- hidden -->b<!DOCTYPE html>c<?xml version='1'?>d", text: "abcd"},
		{html: "a<!-- never closed", text: "a"},
		{html: "&lt;b&gt; &amp; &eacute;", text: "<b> & é"},
		{html: "1 < 2 and 3 <4", text: "1 < 2 and 3 <4"},
		{html: "<a href=\"x>y\" title='z>w'>link</a>", text: "link"},
		{html: "<td>a</td><td>b</td>", text: " a  b "},
		{html: "a<b", text: "a"},
		{html: "<h1>Title</h1><h7>x</h7>", text: " Title x"},
	}
	for _, c := range cases {
		if text := string(indexStripHtml([]byte(c.html))); text != c.text {
			t.Errorf("%q stripped to %q, want %q", c.html, text, c.text)
		}
	}
}

// RFC 2047's encoded words in header values, charsets through htmlindex, and what is not a word staying text.
func TestEncodedWordsDecode(t *testing.T) {
	cases := []struct {
		value   string
		decoded string
	}{
		{value: "=?UTF-8?B?w6l0w6k=?=", decoded: "été"},
		{value: "=?utf-8?q?caf=C3=A9_au_lait?=", decoded: "café au lait"},
		{value: "=?ISO-8859-1?Q?caf=E9?= cr=?x", decoded: "café cr=?x"},
		{value: "=?UTF-8?Q?a?= =?UTF-8?Q?b?=", decoded: "ab"},
		{value: "=?UTF-8?Q?a?= \t =?UTF-8?Q?b?=", decoded: "ab"},
		{value: "=?UTF-8?Q?a?= and =?UTF-8?Q?b?=", decoded: "a and b"},
		{value: "plain =?UTF-8?B?SGk?= tail", decoded: "plain Hi tail"},
		{value: "=?UTF-8*en?Q?hello?=", decoded: "hello"},
		{value: "=?UTF-8?Z?abc?=", decoded: "=?UTF-8?Z?abc?="},
		{value: "=?UTF-8?Q?a b?=", decoded: "=?UTF-8?Q?a b?="},
		{value: "=?UTF-8?Q?bad=ZZ?=", decoded: "=?UTF-8?Q?bad=ZZ?="},
		{value: "=?unknown-charset?Q?abc?=", decoded: "abc"},
		{value: "=?Shift_JIS?B?k/qWe4zq?=", decoded: "日本語"},
		{value: "=?=?=?", decoded: "=?=?=?"},
	}
	for _, c := range cases {
		if decoded := indexDecodeEncodedWords(c.value); decoded != c.decoded {
			t.Errorf("%q decoded to %q, want %q", c.value, decoded, c.decoded)
		}
	}
}

// RFC 2231's parameters: extended values through their charset, continuations joined in order, and an extended
// value winning over a plain one.
func TestMediaParametersDecode(t *testing.T) {
	cases := []struct {
		value string
		name  string
		param string
	}{
		{value: "attachment; filename*=UTF-8''%E2%82%AC%20rates.pdf", name: "filename", param: "€ rates.pdf"},
		{value: "attachment; filename*0=\"part\"; filename*1=\"s.txt\"", name: "filename", param: "parts.txt"},
		{value: "attachment; filename*0*=UTF-8''%C3%A9t; filename*1*=%C3%A9.txt", name: "filename", param: "été.txt"},
		{value: "attachment; filename=\"plain.txt\"; filename*=UTF-8''fancy.txt", name: "filename", param: "fancy.txt"},
		{value: "attachment; filename*=UTF-8''bad%ZZ", name: "filename", param: "bad%ZZ"},
		{value: "text/plain; charset=\"ISO-8859-1\"; format=flowed", name: "charset", param: "ISO-8859-1"},
		{value: "multipart/mixed; boundary=\"a;b\\\"c\"", name: "boundary", param: "a;b\"c"},
		{value: "attachment; filename*0=\"a\"; filename*2=\"c\"", name: "filename", param: "a"},
		{value: "attachment; filename*=iso-8859-1'en'caf%E9", name: "filename", param: "café"},
	}
	for _, c := range cases {
		if param := indexParseMediaValue(c.value).param(c.name); param != c.param {
			t.Errorf("%q's %s read %q, want %q", c.value, c.name, param, c.param)
		}
	}
	if value := indexParseMediaValue(" Text/HTML ; charset=x").value; value != "text/html" {
		t.Errorf("a media type read %q", value)
	}
}

// A message built from parts, CRLF throughout as mail is.
func testMessage(header string, body string) []byte {
	return []byte(strings.ReplaceAll(header+"\n\n"+body, "\n", "\r\n"))
}

// What one message's attachment carries, which must reach no field.
const testAttachmentCanary = "attachmentcanaryqx7"

// The messages testdata/index/extract/ pins, and the files beside them.
type testExtractCase struct {
	name    string
	mail    bool
	path    string
	content []byte
}

func testExtractCases() []testExtractCase {
	encodedCanary := base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 " + testAttachmentCanary + " binary"))
	mixed := testMessage(
		"From: =?UTF-8?Q?Ann_Exampl=C3=A9?= <ann@example.com>\nTo: Bob <bob@example.com>,\n Carol <carol@example.org>\nCc: =?ISO-8859-1?Q?Dav=E9?= <dave@example.net>\nSubject: =?UTF-8?B?UXVhcnRlcmx5?= =?UTF-8?B?IG51bWJlcnM=?=\nReceived: from relay.example.net by mx.example.com\nAuthentication-Results: mx.example.com; dkim=pass\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"outer\"",
		"preamble is not a part\n--outer\nContent-Type: multipart/alternative; boundary=inner\n\n--inner\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\nThe totals are r=C3=A9ady, see the=\n attached sheet.\n--inner\nContent-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: base64\n\n"+
			base64.StdEncoding.EncodeToString([]byte("<html><style>p{color:red}</style><p>The totals are <b>ready</b>&nbsp;now</p><script>alert(1)</script></html>"))+
			"\n--inner--\n--outer\nContent-Type: application/pdf; name=\"q3.pdf\"\nContent-Disposition: attachment; filename*=UTF-8''Q3%20r%C3%A9sum%C3%A9.pdf\nContent-Transfer-Encoding: base64\n\n"+
			encodedCanary+"\n--outer\nContent-Type: text/plain; name=notes.txt\nContent-Disposition: attachment\n\n"+testAttachmentCanary+" in a text attachment\n--outer\nContent-Type: message/rfc822\n\nSubject: "+testAttachmentCanary+"\n\nforwarded "+testAttachmentCanary+"\n--outer--\nepilogue is not a part\n")
	latin := testMessage("From: a@example.com\nSubject: plain\nContent-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: 8bit", "Caf\xE9 cr\xE8me")
	noMime := testMessage("From: a@example.com\nTo: b@example.com\nSubject: hello\n\tworld", "Just text, no MIME header at all.\n")
	shiftJis := testMessage("From: =?Shift_JIS?B?k/qWe4zq?= <jp@example.com>\nSubject: =?ISO-2022-JP?B?GyRCRnxLXDhsGyhC?=\nContent-Type: text/plain; charset=Shift_JIS", "\x93\xfa\x96\x7b\x8c\xea")
	utf16File := []byte{0xFF, 0xFE, 'H', 0, 'i', 0, ' ', 0, 0x3A, 0x30, '\n', 0, 'x', 0}
	return []testExtractCase{
		{name: "mixed", mail: true, path: "m/202611/3f/0123456789abcdef", content: mixed},
		{name: "latin-1", mail: true, path: "m/202611/00/1", content: latin},
		{name: "no-mime", mail: true, path: "m/202611/00/2", content: noMime},
		{name: "shift-jis", mail: true, path: "m/202611/00/3", content: shiftJis},
		{name: "markdown", path: "docs/README.md", content: []byte("\n# Search  \nTrigrams over Été and 日本.\n")},
		{name: "utf-16", path: "notes/utf16.txt", content: utf16File},
	}
}

// One extract vector: each document's fields and the SHA-256 of its normalized text, the same bytes on every leg.
type testExtractVector struct {
	Name      string                      `json:"name"`
	Documents []testExtractVectorDocument `json:"documents"`
}

type testExtractVectorDocument struct {
	Chunk uint32 `json:"chunk"`
	// Each field's bytes in hex, by number.
	Fields     []string `json:"fields"`
	TextSha256 string   `json:"text_sha256"`
	KeyCount   int      `json:"key_count"`
}

// The vector of what a case extracts to.
func testExtractVectorOf(t testing.TB, c testExtractCase) testExtractVector {
	t.Helper()
	var documents []*IndexDocument
	if c.mail {
		documents = indexExtractMail([]byte(c.path), c.content)
	} else {
		var ok bool
		if documents, ok = indexExtractFile([]byte(c.path), c.content); !ok {
			t.Fatalf("%s sniffed as binary", c.name)
		}
	}
	vector := testExtractVector{Name: c.name}
	normalizer := testIndexNormalizer(t)
	for _, document := range documents {
		fields := []string{}
		for number := 1; number <= indexFieldLast; number += 1 {
			fields = append(fields, hex.EncodeToString(document.Fields[number]))
		}
		text := &bytes.Buffer{}
		if err := normalizer.writeDocument(text, document.textFields()); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(text.Bytes())
		vector.Documents = append(vector.Documents, testExtractVectorDocument{
			Chunk:      document.Chunk,
			Fields:     fields,
			TextSha256: hex.EncodeToString(sum[:]),
			KeyCount:   len(indexTrigrams(text.Bytes())),
		})
	}
	return vector
}

// D-TEST-15: base64, quoted-printable, HTML, RFC 2047 and 2231, charsets and UTF-16, extracted and normalized to the
// same bytes on every leg.
func TestExtractVectors(t *testing.T) {
	built := []testExtractVector{}
	for _, c := range testExtractCases() {
		built = append(built, testExtractVectorOf(t, c))
	}
	vectors := built
	if os.Getenv(testWriteVectorsEnvironment) != "" {
		testWriteJson(t, testExtractVectorPath, built)
	} else {
		encoded, err := testIndexFiles.ReadFile(testExtractVectorPath)
		if err != nil {
			t.Fatal(err)
		}
		vectors = nil
		if err := json.Unmarshal(encoded, &vectors); err != nil {
			t.Fatal(err)
		}
	}
	if len(vectors) != len(built) {
		t.Fatalf("%d vectors for %d cases", len(vectors), len(built))
	}
	for index := range built {
		a, _ := json.Marshal(vectors[index])
		b, _ := json.Marshal(built[index])
		if !bytes.Equal(a, b) {
			t.Errorf("%s: its extraction moved", built[index].Name)
		}
	}
}

// §15.7's text rule on one message: the four header values decoded, text parts and attachment names in MIME order,
// HTML stripped, and nothing of a transport header, an attachment's bytes, base64 or a message/rfc822 part.
func TestMailExtractsItsTextAndNamesOnly(t *testing.T) {
	c := testExtractCases()[0]
	documents := indexExtractMail([]byte(c.path), c.content)
	if len(documents) != 1 {
		t.Fatalf("%d documents", len(documents))
	}
	document := documents[0]
	want := map[int]string{
		indexFieldSubject: "Quarterly numbers",
		indexFieldFrom:    "Ann Examplé <ann@example.com>",
		indexFieldTo:      "Bob <bob@example.com>, Carol <carol@example.org> Davé <dave@example.net>",
		indexFieldBody:    "The totals are réady, see the attached sheet.  The totals are ready now  Q3 résumé.pdf notes.txt",
	}
	for number, value := range want {
		if string(document.Fields[number]) != value {
			t.Errorf("field %d is %q, want %q", number, document.Fields[number], value)
		}
	}
	for number, value := range document.Fields {
		for _, banned := range []string{testAttachmentCanary, "relay.example.net", "dkim", "alert", "color", "preamble", "epilogue", "forwarded"} {
			if strings.Contains(strings.ToLower(string(value)), banned) {
				t.Errorf("field %d holds %q", number, banned)
			}
		}
	}
	if document.Kind != IndexDocMail || document.ByteCount != uint64(len(c.content)) {
		t.Errorf("a %d document of %d B", document.Kind, document.ByteCount)
	}
}

// Nesting is read 16 multipart levels deep, and nothing past that.
func TestMimeNestingStopsAtSixteen(t *testing.T) {
	nested := func(depth int) []byte {
		body := "Content-Type: text/plain\n\ndeepest words"
		for level := depth; 0 < level; level -= 1 {
			boundary := "b" + strings.Repeat("x", level)
			body = "Content-Type: multipart/mixed; boundary=" + boundary + "\n\n--" + boundary + "\n" + body + "\n--" + boundary + "--"
		}
		return testMessage("From: a@example.com\n"+strings.SplitN(body, "\n\n", 2)[0], strings.SplitN(body, "\n\n", 2)[1])
	}
	if text := string(indexExtractMail([]byte("m/1"), nested(16))[0].Fields[indexFieldBody]); text != "deepest words" {
		t.Errorf("16 levels read %q", text)
	}
	if text := string(indexExtractMail([]byte("m/1"), nested(17))[0].Fields[indexFieldBody]); text != "" {
		t.Errorf("17 levels read %q", text)
	}
}

// §11.14's never row, decided before a version is read.
func TestNeverRowExcludes(t *testing.T) {
	general := protocol.RepoKind_REPO_KIND_GENERAL
	mailbox := protocol.RepoKind_REPO_KIND_MAILBOX
	cases := []struct {
		place    indexPlace
		excluded bool
		kind     IndexDocKind
	}{
		{place: indexPlace{repoKind: general, path: "notes/plan.md"}, excluded: false, kind: IndexDocFile},
		{place: indexPlace{repoKind: protocol.RepoKind_REPO_KIND_CONFIG, path: "notes/plan.md"}, excluded: true},
		{place: indexPlace{repoKind: protocol.RepoKind_REPO_KIND_MAILCFG, path: "x"}, excluded: true},
		{place: indexPlace{repoKind: protocol.RepoKind_REPO_KIND_SECRET, path: "token"}, excluded: true},
		{place: indexPlace{repoKind: protocol.RepoKind_REPO_KIND_UNSPECIFIED, path: "a"}, excluded: true},
		{place: indexPlace{repoKind: general, path: ".ur-index/i1/a/m"}, excluded: true},
		{place: indexPlace{repoKind: general, path: ".ur-index/x"}, excluded: true},
		{place: indexPlace{repoKind: general, path: ".ur-index"}, excluded: true},
		{place: indexPlace{repoKind: general, path: ".ur-indexes/notes.md"}, excluded: false, kind: IndexDocFile},
		{place: indexPlace{repoKind: general, indexRef: true, path: "i1/settings"}, excluded: true},
		{place: indexPlace{repoKind: general, path: "notes/plan.md", deposit: true}, excluded: true},
		{place: indexPlace{repoKind: mailbox, path: "m/202611/3f/1"}, excluded: false, kind: IndexDocMail},
		{place: indexPlace{repoKind: general, groupInbox: true, path: "m/202611/3f/1"}, excluded: false, kind: IndexDocMail},
		{place: indexPlace{repoKind: general, groupInbox: true, path: "i/202611/0"}, excluded: true},
		{place: indexPlace{repoKind: general, path: "m/202611/3f/1"}, excluded: false, kind: IndexDocFile},
		{place: indexPlace{repoKind: protocol.RepoKind_REPO_KIND_RECORD, path: "notes.md"}, excluded: false, kind: IndexDocFile},
	}
	for _, family := range []string{"i/202611/0", "r/202611/3f/1", "vault/3f/1", "o/3f/1", "or/3f/1", "p/0011", "forward", "ra/3f/x", "f/202611/0", "s/model"} {
		cases = append(cases, struct {
			place    indexPlace
			excluded bool
			kind     IndexDocKind
		}{place: indexPlace{repoKind: mailbox, path: family}, excluded: true})
	}
	for _, c := range cases {
		if excluded := indexExcluded(c.place); excluded != c.excluded {
			t.Errorf("%+v excluded %t", c.place, excluded)
		}
		if !c.excluded && indexExtractorKind(c.place) != c.kind {
			t.Errorf("%+v takes kind %d", c.place, indexExtractorKind(c.place))
		}
	}
}

// A prepared document's row: the locator its name, the shown values cut to their caps, n_d its key count, a
// companion row's ref_id, and a derived document's times and private marker.
func TestPreparedDocumentRows(t *testing.T) {
	refId := evsTestId("main ref")
	file, ok := indexExtractFile([]byte("docs/README.md"), []byte("# Search\nTrigrams.\n"))
	if !ok {
		t.Fatal("binary")
	}
	file[0].Version = 4
	file[0].Tainted = true
	prepared, err := file[0].prepare(testIndexNormalizer(t), false, refId)
	if err != nil {
		t.Fatal(err)
	}
	row := prepared.row
	if row.locator != "docs/README.md" || row.fields[indexFieldTitle] != "Search" || row.flags != indexRowTainted ||
		row.trigramCount != uint64(len(prepared.keys)) || row.refId != nil || row.docKind != indexDocFile {
		t.Errorf("a file's row: %+v", row)
	}
	if !testHoldsTerm(t, prepared.keys, "readme") || !testHoldsTerm(t, prepared.keys, "trigrams") {
		t.Error("a file's path or body is not indexed")
	}
	derived := &IndexDocument{
		Kind: IndexDocDerived, Name: []byte("run/0123"), Version: 9, ByteCount: 300, Private: true,
		StartedSeconds: 1800000000, ExpiresSeconds: 1800086400,
	}
	derived.Fields[indexFieldTitle] = []byte("Build the codec")
	derived.Fields[indexFieldBody] = []byte("prompt text " + strings.Repeat("x", 300))
	derived.Fields[9] = []byte(strings.Repeat("label ", 60))
	prepared, err = derived.prepare(testIndexNormalizer(t), true, refId)
	if err != nil {
		t.Fatal(err)
	}
	row = prepared.row
	if !bytes.Equal(row.refId, refId.Bytes()) || row.startedSeconds != 1800000000 || row.flags&indexRowPrivate == 0 ||
		len(row.fields[9]) != indexFieldMaxByteCount || row.flags&indexRowCutFlag(9) == 0 {
		t.Errorf("a derived row: %+v", row)
	}
	if err := indexRecordFieldRegistry().check(derived); err != nil {
		t.Errorf("a run card: %v", err)
	}
}

// The registries are §16.8's and §16.11's, and a class gives only what it registered.
func TestFieldRegistries(t *testing.T) {
	record := indexRecordFieldRegistry()
	directory := indexDirectoryFieldRegistry()
	for _, c := range []struct {
		registry *IndexFieldRegistry
		name     string
		field    int
	}{
		{registry: record, name: "kind", field: 6}, {registry: record, name: "agent", field: 9},
		{registry: record, name: "claim_state", field: 14}, {registry: record, name: "member_id", field: 0},
		{registry: directory, name: "member_id", field: 11}, {registry: directory, name: "state", field: 15},
		{registry: directory, name: "", field: 0},
	} {
		if field := c.registry.field(c.name); field != c.field {
			t.Errorf("%q is field %d", c.name, field)
		}
	}
	entry := func(mutate func(document *IndexDocument)) *IndexDocument {
		document := &IndexDocument{Kind: IndexDocRecord, Name: []byte("streams/claims/7")}
		document.Fields[indexFieldTitle] = []byte("Claim the codec")
		document.Fields[6] = []byte("claim")
		mutate(document)
		return document
	}
	if err := record.check(entry(func(document *IndexDocument) {})); err != nil {
		t.Errorf("a claim entry: %v", err)
	}
	refused := map[string]*IndexDocument{
		"field 15 of a record":        entry(func(document *IndexDocument) { document.Fields[15] = []byte("x") }),
		"a subject on a record":       entry(func(document *IndexDocument) { document.Fields[indexFieldSubject] = []byte("x") }),
		"a record under a run's name": entry(func(document *IndexDocument) { document.Name = []byte("run/7") }),
		"a run card under no prefix":  entry(func(document *IndexDocument) { document.Kind = IndexDocDerived }),
		"a file from a class":         entry(func(document *IndexDocument) { document.Kind = IndexDocFile; document.Fields[6] = nil }),
		"times on a record":           entry(func(document *IndexDocument) { document.StartedSeconds = 5 }),
		"a name past 65,535 B":        entry(func(document *IndexDocument) { document.Name = make([]byte, indexNameMaxByteCount+1) }),
		"a run card named only run/":  entry(func(document *IndexDocument) { document.Kind = IndexDocDerived; document.Name = []byte("run/") }),
	}
	for name, document := range refused {
		if err := record.check(document); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	file := &IndexDocument{Kind: IndexDocFile, Name: []byte("f")}
	file.Fields[7] = []byte("x")
	if err := file.check(); !errors.Is(err, errIndexMalformed) {
		t.Errorf("a registered field on a file: %v", err)
	}
	file.Fields[7] = nil
	file.Private = true
	if err := file.check(); !errors.Is(err, errIndexMalformed) {
		t.Errorf("a private file: %v", err)
	}
}
