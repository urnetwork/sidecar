// MAIL-M7-11's walk: base64, quoted-printable, RFC 2047 and RFC 2231 fixtures, the first text part, attachments and
// threads; each bound stopping its own work and still giving an entry, a zip-bomb-shaped nesting among them;
// malformed MIME read as far as it parses; a sender's CR and LF never reaching a value; and the fuzz target's
// property over its seeds, embedded since the page Worker's leg has no file system. Every name is synthetic.

package sidecar

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

//go:embed testdata/fuzz/FuzzMailParse
var testMailParseFiles embed.FS

// A message of header lines and a body, CRLF throughout.
func testMailMessage(headerLines []string, body string) string {
	return strings.Join(headerLines, "\r\n") + "\r\n\r\n" + body
}

// message walked under the default settings, failing the test on an error.
func testMailParse(t *testing.T, message string) *MailParsed {
	t.Helper()
	parsed, err := MailParseMessage(strings.NewReader(message), nil)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// A plain message: its header fields, its text and snippet, the whole message read and nothing cut.
func TestMailParsePlainMessage(t *testing.T) {
	message := testMailMessage([]string{
		"From: Ada Lovelace <ada@Sender.Example>",
		"To: grace@k3j4h5g6f7.root.example",
		"Subject: Lunch\ton   Tuesday",
		"Message-ID: <m1.2026@sender.example>",
		"Date: Mon, 09 Nov 2026 10:00:00 +0000",
	}, "Hi Grace,\r\n\r\nShall we meet at noon?\r\n")
	parsed := testMailParse(t, message)
	if parsed.From != "Ada Lovelace <ada@Sender.Example>" || parsed.FromDomain != "sender.example" {
		t.Errorf("from %q, domain %q", parsed.From, parsed.FromDomain)
	}
	if parsed.Subject != "Lunch on Tuesday" {
		t.Errorf("subject %q", parsed.Subject)
	}
	if parsed.MessageId != "m1.2026@sender.example" || parsed.ThreadMessageId != "m1.2026@sender.example" {
		t.Errorf("ids %q, %q", parsed.MessageId, parsed.ThreadMessageId)
	}
	if parsed.Text != "Hi Grace,\n\nShall we meet at noon?\n" || parsed.Snippet != "Hi Grace, Shall we meet at noon?" {
		t.Errorf("text %q, snippet %q", parsed.Text, parsed.Snippet)
	}
	if parsed.Cut != 0 || parsed.PartCount != 1 || parsed.ByteCount != uint64(len(message)) || len(parsed.Attachments) != 0 {
		t.Errorf("cut %b, parts %d, bytes %d of %d, attachments %d", parsed.Cut, parsed.PartCount, parsed.ByteCount, len(message), len(parsed.Attachments))
	}
}

// base64 and quoted-printable text, and RFC 2047's encoded words in UTF-8, ISO-8859-1 and a charset this does not
// map, whose bytes show as U+FFFD rather than as a guess.
func TestMailParseEncodings(t *testing.T) {
	cases := []struct {
		name     string
		headers  []string
		body     string
		subject  string
		from     string
		wantText string
	}{
		{
			name:     "base64 utf-8",
			headers:  []string{"Content-Type: text/plain; charset=UTF-8", "Content-Transfer-Encoding: base64"},
			body:     "R3LDvMOfZSBhdXMg5p2x5Lqs\r\nIQ==\r\n",
			wantText: "Grüße aus 東京!",
		},
		{
			name:     "base64 with spaces",
			headers:  []string{"Content-Type: text/plain", "Content-Transfer-Encoding: BASE64"},
			body:     "aGVs bG8g\td29y bGQ=\r\n",
			wantText: "hello world",
		},
		{
			name:     "quoted-printable",
			headers:  []string{"Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: quoted-printable"},
			body:     "caf=C3=A9 au lait, a soft=\r\n break and =3D sign\r\n",
			wantText: "café au lait, a soft break and = sign\n",
		},
		{
			name:     "latin-1 body",
			headers:  []string{"Content-Type: text/plain; charset=ISO-8859-1", "Content-Transfer-Encoding: quoted-printable"},
			body:     "Gr=FC=DFe\r\n",
			wantText: "Grüße\n",
		},
		{
			name:     "unknown charset",
			headers:  []string{"Content-Type: text/plain; charset=x-synthetic-8bit", "Content-Transfer-Encoding: quoted-printable"},
			body:     "caf=E9\r\n",
			wantText: "caf�\n",
		},
		{
			name:    "encoded words",
			headers: []string{"Subject: =?UTF-8?B?R3LDvMOfZQ==?= =?utf-8?q?_aus_T=C5=8Dky=C5=8D?=", "From: =?iso-8859-1?Q?Andr=E9?= <andre@sender.example>"},
			body:    "x",
			subject: "Grüße aus Tōkyō",
			from:    "André <andre@sender.example>",
		},
		{
			name:    "an unknown charset's word",
			headers: []string{"Subject: =?x-synthetic?Q?caf=E9?= ok"},
			body:    "x",
			subject: "caf� ok",
		},
	}
	for _, c := range cases {
		parsed := testMailParse(t, testMailMessage(c.headers, c.body))
		if c.wantText != "" && parsed.Text != c.wantText {
			t.Errorf("%s: text %q, want %q", c.name, parsed.Text, c.wantText)
		}
		if c.subject != "" && parsed.Subject != c.subject {
			t.Errorf("%s: subject %q, want %q", c.name, parsed.Subject, c.subject)
		}
		if c.from != "" && parsed.From != c.from {
			t.Errorf("%s: from %q, want %q", c.name, parsed.From, c.from)
		}
		if !utf8.ValidString(parsed.Text) || !utf8.ValidString(parsed.Subject) {
			t.Errorf("%s: invalid UTF-8 kept", c.name)
		}
	}
}

// A multipart message: text/plain over text/html, each attachment's name by RFC 2231 or by Content-Type's name, its
// type and its size as carried, never decoded, and a forwarded message counted, never entered.
func TestMailParseMultipart(t *testing.T) {
	forwarded := testMailMessage([]string{"From: other@sender.example", "Subject: inner"}, "inner text that must not become the snippet\r\n")
	message := testMailMessage([]string{
		"From: ada@sender.example",
		"Subject: Report",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="outer"`,
	}, "This is a multi-part message.\r\n"+
		"--outer\r\n"+
		"Content-Type: multipart/alternative; boundary=alt\r\n\r\n"+
		"--alt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>the html</p>\r\n"+
		"--alt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nthe plain text\r\n"+
		"--alt--\r\n"+
		"--outer\r\n"+
		"Content-Type: application/pdf\r\n"+
		"Content-Disposition: attachment; filename*0*=utf-8''r%C3%A9sum%C3%A9; filename*1=\" 2026.pdf\"\r\n"+
		"Content-Transfer-Encoding: base64\r\n\r\n"+
		"JVBERi0xLjQKJcOkw7zDtsOf\r\nCjEgMCBvYmoK\r\n"+
		"--outer\r\n"+
		"Content-Type: image/png; name=\"=?utf-8?q?ch=C3=A4rt.png?=\"\r\n"+
		"Content-Transfer-Encoding: base64\r\n\r\n"+
		"iVBORw0KGgo=\r\n"+
		"--outer\r\n"+
		"Content-Type: message/rfc822\r\n\r\n"+forwarded+"\r\n"+
		"--outer\r\n"+
		"Content-Type: text/plain\r\nContent-Disposition: attachment; filename=notes.txt\r\n\r\n"+
		"attached text\r\n"+
		"--outer--\r\nepilogue\r\n")
	parsed := testMailParse(t, message)
	if parsed.Text != "the plain text" {
		t.Errorf("text %q", parsed.Text)
	}
	want := []*protocol.MailAttachment{
		{Name: "résumé 2026.pdf", Type: "application/pdf", Size: uint64(len("JVBERi0xLjQKJcOkw7zDtsOf\r\nCjEgMCBvYmoK"))},
		{Name: "chärt.png", Type: "image/png", Size: uint64(len("iVBORw0KGgo="))},
		{Name: "", Type: "message/rfc822", Size: uint64(len(forwarded))},
		{Name: "notes.txt", Type: "text/plain", Size: uint64(len("attached text"))},
	}
	if len(parsed.Attachments) != len(want) {
		t.Fatalf("%d attachments: %v", len(parsed.Attachments), parsed.Attachments)
	}
	for index := range want {
		if !proto.Equal(parsed.Attachments[index], want[index]) {
			t.Errorf("attachment %d: %v, want %v", index, parsed.Attachments[index], want[index])
		}
	}
	if parsed.Cut != 0 || parsed.PartCount != 8 || parsed.AttachmentCount != 4 || parsed.ByteCount != uint64(len(message)) {
		t.Errorf("cut %b, parts %d, attachments %d, bytes %d of %d", parsed.Cut, parsed.PartCount, parsed.AttachmentCount, parsed.ByteCount, len(message))
	}
}

// With no text/plain, the first text/html part's text by INDEX-FORMAT.md's scanner: its markup, scripts, styles
// and comments gone and its entities decoded, a title's text kept as any other.
func TestMailParseHtmlText(t *testing.T) {
	html := "<!DOCTYPE html><html><head><title>Title</title><style>p { color: red }</style></head>" +
		"<body><!-- a <b>comment</b> --><p>Hello&nbsp;<b>world</b> &amp; you</p><SCRIPT>steal()</script>" +
		"<div>second&#33;</div></body></html>"
	message := testMailMessage([]string{
		"From: ada@sender.example",
		"Content-Type: multipart/alternative; boundary=b",
	}, "--b\r\nContent-Type: text/html\r\n\r\n"+html+"\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>later</p>\r\n--b--\r\n")
	parsed := testMailParse(t, message)
	if parsed.Snippet != "Title Hello world & you second!" {
		t.Errorf("snippet %q", parsed.Snippet)
	}
	if strings.Contains(parsed.Text, "steal") || strings.Contains(parsed.Text, "color") || strings.Contains(parsed.Text, "comment") {
		t.Errorf("text %q", parsed.Text)
	}
	// a later text/plain still wins over html taken first
	message = testMailMessage([]string{"Content-Type: multipart/alternative; boundary=b"},
		"--b\r\nContent-Type: text/html\r\n\r\n<p>html first</p>\r\n--b\r\nContent-Type: text/plain\r\n\r\nplain second\r\n--b--\r\n")
	if parsed := testMailParse(t, message); parsed.Text != "plain second" {
		t.Errorf("text %q", parsed.Text)
	}
}

// INDEX-FORMAT.md's HTML rules, which mailHtmlText reads through Extractor 1's own function (QD-694): a block tag
// leaves a space and any other nothing; a < that starts no tag is text; a > inside quotes ends no tag; entities decode
// after the tags are gone; a construct with no end ends the text.
func TestMailHtmlTextFollowsTheIndexFormat(t *testing.T) {
	cases := []struct {
		markup string
		want   string
	}{
		{markup: "<b>a</b>b", want: "ab"},
		{markup: "a<br>b<p>c</p>d", want: "a b c d"},
		{markup: "<H1>Big</H1>small", want: " Big small"},
		{markup: "a < b and 3<4", want: "a < b and 3<4"},
		{markup: `<a title="x>y" href='p>q'>link</a>`, want: "link"},
		{markup: "&lt;p&gt; stays &amp; text", want: "<p> stays & text"},
		{markup: "<?xml version=1?><!DOCTYPE x>body", want: "body"},
		{markup: "kept<!-- never closed", want: "kept"},
		{markup: "kept<script>never closed", want: "kept"},
		{markup: "kept<style>x</style >after", want: "keptafter"},
		{markup: "kept<script>x</SCRIPT>after", want: "keptafter"},
		{markup: "kept<div class=\"never closed", want: "kept"},
	}
	for _, c := range cases {
		if text := string(mailHtmlText([]byte(c.markup))); text != c.want {
			t.Errorf("%q: %q, want %q", c.markup, text, c.want)
		}
	}
}

// Charsets decode through Extractor 1's indexDecodeCharset (QD-694): a multibyte body and word, windows-1252's quotes
// under their own label and under ISO-8859-1's, which the web reads as windows-1252, and UTF-8 left as it is.
func TestMailParseCharsetsThroughHtmlindex(t *testing.T) {
	cases := []struct {
		headers []string
		body    string
		subject string
		text    string
	}{
		{headers: []string{"Subject: =?shift_jis?B?k/qWew==?=", "Content-Type: text/plain; charset=Shift_JIS", "Content-Transfer-Encoding: quoted-printable"},
			body: "=93=FA=96=7B", subject: "\u65e5\u672c", text: "\u65e5\u672c"},
		{headers: []string{"Content-Type: text/plain; charset=windows-1252", "Content-Transfer-Encoding: quoted-printable"},
			body: "=93quoted=94", text: "\u201cquoted\u201d"},
		{headers: []string{"Content-Type: text/plain; charset=iso-8859-1", "Content-Transfer-Encoding: quoted-printable"},
			body: "=93quoted=94 caf=E9", text: "\u201cquoted\u201d caf\u00e9"},
		{headers: []string{"Content-Type: text/plain; charset=utf-8"}, body: "\xff ok", text: "\ufffd ok"},
	}
	for index, c := range cases {
		parsed := testMailParse(t, testMailMessage(c.headers, c.body))
		if parsed.Text != c.text || (c.subject != "" && parsed.Subject != c.subject) {
			t.Errorf("case %d: text %q, subject %q", index, parsed.Text, parsed.Subject)
		}
	}
}

// QD-694: an i/ snippet reads HTML and charsets as search indexes them, by Extractor 1's functions and no copy of
// them. The three places the mail lane's copies read otherwise (DESIGN-DETAILS 11's list): a damaged reference, which
// html.UnescapeString left as written and E1-E4 decode; an iso-2022-kr label and a replacement label, which
// htmlindex's decoder turned into one U+FFFD and C2 leaves as bytes, so the ASCII in them is found.
func TestMailParseReadsHtmlAndCharsetsAsExtractorOne(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		charset     string
		body        string
		html        bool
		text        string
		snippet     string
	}{
		{name: "a damaged reference", contentType: "text/html", body: "<p>tab&#9 x and &#65 x</p>", html: true,
			text: " tab\t x and A x ", snippet: "tab x and A x"},
		{name: "a name html.UnescapeString lacks", contentType: "text/html", body: "<b>a &nLt; b</b>", html: true,
			text: "a \u226a\u20d2 b", snippet: "a \u226a\u20d2 b"},
		{name: "an iso-2022-kr label", contentType: "text/plain; charset=iso-2022-kr", charset: "iso-2022-kr",
			body: "code 4821 here", text: "code 4821 here", snippet: "code 4821 here"},
		{name: "a replacement label", contentType: "text/plain; charset=replacement", charset: "replacement",
			body: "code 4821 here", text: "code 4821 here", snippet: "code 4821 here"},
		{name: "an iso-2022-kr html part", contentType: "text/html; charset=ISO-2022-KR", charset: "ISO-2022-KR",
			body: "<div>code&#9 4821</div>", html: true, text: " code\t 4821 ", snippet: "code 4821"},
	}
	for _, c := range cases {
		parsed := testMailParse(t, testMailMessage([]string{"Content-Type: " + c.contentType}, c.body))
		if parsed.Text != c.text || parsed.Snippet != c.snippet {
			t.Errorf("%s: text %q, snippet %q", c.name, parsed.Text, parsed.Snippet)
		}
		// and it is the extractor's own reading of the same bytes, cleaned as every text is
		extracted := indexDecodeCharset(c.charset, []byte(c.body))
		if c.html {
			extracted = indexStripHtml(extracted)
		}
		if want := mailCleanText(extracted, len(extracted)+1); parsed.Text != want {
			t.Errorf("%s: text %q, extractor 1 reads %q", c.name, parsed.Text, want)
		}
	}
	// the functions the walk calls are the extractor's, on any input: a sweep of damaged markup and labels
	markups := []string{"&#9 x", "&#x;", "&#4294967361;", "&nGt;", "a<br/>b", "<script>x</script >y", "<STYLE>x</style\t>y", "<a b='>'>c", "x<!-- y", "<"}
	for _, markup := range markups {
		if got, want := mailHtmlText([]byte(markup)), indexStripHtml([]byte(markup)); string(got) != string(want) {
			t.Errorf("%q: %q, extractor 1 reads %q", markup, got, want)
		}
	}
	labels := []string{"", " utf-8 ", "replacement", "iso-2022-kr", "hz-gb-2312", "\u212aoi8-r", "koi8-r", "x-synthetic-8bit", "windows-1252"}
	for _, label := range labels {
		raw := []byte("caf\xe9 \x93q\x94 \x1b$)C")
		if got, want := mailDecodeCharset(label, raw), indexDecodeCharset(label, raw); string(got) != string(want) {
			t.Errorf("label %q: %q, extractor 1 reads %q", label, got, want)
		}
	}
}

// The thread's id: the first of References, else the first of In-Reply-To, else the Message-ID's, else the message's
// own id; and a Message-ID past 256 bytes kept for the thread but left out of MessageId.
func TestMailParseThreads(t *testing.T) {
	longId := strings.Repeat("x", 300) + "@sender.example"
	messageId := Id{0x01, 0x9a, 0x5b, 0x10}
	cases := []struct {
		headers   []string
		want      string
		wantId    string
		ownThread bool
	}{
		{headers: []string{"Message-ID: <c@x.example>", "In-Reply-To: <b@x.example>", "References: <a@x.example>\r\n <b@x.example>"}, want: "a@x.example", wantId: "c@x.example"},
		{headers: []string{"Message-ID: <c@x.example>", "In-Reply-To: <b@x.example> <q@x.example>"}, want: "b@x.example", wantId: "c@x.example"},
		{headers: []string{"Message-ID: <c@x.example>"}, want: "c@x.example", wantId: "c@x.example"},
		// some senders write no brackets
		{headers: []string{"Message-ID: bare@x.example"}, want: "bare@x.example", wantId: "bare@x.example"},
		{headers: []string{"References: <> <a@x.example>"}, want: "a@x.example"},
		{headers: []string{"Message-ID: <" + longId + ">"}, want: longId, wantId: ""},
		{headers: []string{"Subject: no ids"}, ownThread: true},
	}
	for index, c := range cases {
		parsed := testMailParse(t, testMailMessage(c.headers, "x"))
		if parsed.ThreadMessageId != c.want || parsed.MessageId != c.wantId {
			t.Errorf("case %d: thread %q, id %q", index, parsed.ThreadMessageId, parsed.MessageId)
		}
		key := parsed.ThreadKey(messageId)
		if len(key) != 16 {
			t.Errorf("case %d: a key of %d bytes", index, len(key))
		}
		if c.ownThread != (string(key) == string(messageId[:])) {
			t.Errorf("case %d: key %x", index, key)
		}
	}
	// two messages of one thread share a key
	first := testMailParse(t, testMailMessage([]string{"Message-ID: <root@x.example>"}, "x"))
	reply := testMailParse(t, testMailMessage([]string{"Message-ID: <r1@x.example>", "References: <root@x.example>"}, "x"))
	if string(first.ThreadKey(Id{1})) != string(reply.ThreadKey(Id{2})) {
		t.Error("a reply left its thread")
	}
}

// CR and LF a sender hides in an encoded word, a parameter or a file name never reach a value, and neither do
// bidi overrides.
func TestMailParseStripsLineBreaks(t *testing.T) {
	message := testMailMessage([]string{
		"From: =?utf-8?Q?Ada=0D=0ABcc:_victim@x.example?= <ada@sender.example>",
		"Subject: =?utf-8?Q?hi=0D=0ATo:_evil@attacker.example=0D=0A=0D=0Abody?=",
		"Content-Type: multipart/mixed; boundary=b",
	}, "--b\r\nContent-Type: application/octet-stream; name=\"=?utf-8?Q?invoice=E2=80=AEfdp.exe=0D=0AX:_y?=\"\r\n\r\nzz\r\n--b--\r\n")
	parsed := testMailParse(t, message)
	values := []string{parsed.From, parsed.Subject, parsed.Attachments[0].GetName()}
	for _, value := range values {
		if strings.ContainsAny(value, "\r\n‮") {
			t.Errorf("%q kept a line break or an override", value)
		}
	}
	if parsed.Subject != "hi To: evil@attacker.example body" {
		t.Errorf("subject %q", parsed.Subject)
	}
	if parsed.Attachments[0].GetName() != "invoicefdp.exe X: y" {
		t.Errorf("name %q", parsed.Attachments[0].GetName())
	}
}

// A zip-bomb-shaped nesting stops at MaxDepth, is read through whole, and the message still gives its entry.
func TestMailParseNestingStopsAtItsBound(t *testing.T) {
	const levels = 2000
	body := strings.Builder{}
	for level := range levels {
		fmt.Fprintf(&body, "--n%d\r\nContent-Type: multipart/mixed; boundary=n%d\r\n\r\n", level, level+1)
	}
	body.WriteString("--n2000\r\nContent-Type: text/plain\r\n\r\ndeep\r\n--n2000--\r\n")
	for level := levels - 1; 0 <= level; level -= 1 {
		fmt.Fprintf(&body, "--n%d--\r\n", level)
	}
	message := testMailMessage([]string{"From: ada@sender.example", "Subject: nested", "Content-Type: multipart/mixed; boundary=n0"}, body.String())
	settings := DefaultMailParseSettings()
	parsed := testMailParse(t, message)
	if parsed.Cut&MailParseCutDepth == 0 || parsed.PartCount != settings.MaxDepth+1 {
		t.Errorf("cut %b, parts %d", parsed.Cut, parsed.PartCount)
	}
	if parsed.Subject != "nested" || parsed.From != "ada@sender.example" || parsed.Text != "" {
		t.Errorf("subject %q, from %q, text %q", parsed.Subject, parsed.From, parsed.Text)
	}
	entry, err := MailBuildIndexEntry(&MailIndexEntryInput{Id: Id{9}, Deposit: testMailSameNetworkDeposit(), Parsed: parsed, ByteCount: uint64(len(message))})
	if err != nil || entry.GetSubject() != "nested" {
		t.Errorf("entry %v, %v", entry, err)
	}
}

// More parts than MaxPartCount stops the walk; more attachments than an IndexEntry lists are counted.
func TestMailParsePartAndAttachmentBounds(t *testing.T) {
	parts := func(count int) string {
		body := strings.Builder{}
		for index := range count {
			fmt.Fprintf(&body, "--b\r\nContent-Type: image/png; name=p%d.png\r\n\r\npng\r\n", index)
		}
		body.WriteString("--b--\r\n")
		return testMailMessage([]string{"From: ada@sender.example", "Content-Type: multipart/mixed; boundary=b"}, body.String())
	}
	settings := DefaultMailParseSettings()
	parsed := testMailParse(t, parts(40))
	if len(parsed.Attachments) != 32 || parsed.AttachmentCount != 40 || parsed.Cut != MailParseCutAttachments {
		t.Errorf("listed %d of %d, cut %b", len(parsed.Attachments), parsed.AttachmentCount, parsed.Cut)
	}
	if parsed.Attachments[31].GetName() != "p31.png" {
		t.Errorf("last listed %q", parsed.Attachments[31].GetName())
	}
	parsed = testMailParse(t, parts(settings.MaxPartCount+50))
	if parsed.Cut&MailParseCutParts == 0 || parsed.PartCount != settings.MaxPartCount || parsed.AttachmentCount != settings.MaxPartCount-1 {
		t.Errorf("cut %b, parts %d, attachments %d", parsed.Cut, parsed.PartCount, parsed.AttachmentCount)
	}
}

// The header's bound keeps what came before it and reads no body; a part header's bound stops the walk there, the
// parts before it kept; the decoded bound cuts the text.
func TestMailParseByteBounds(t *testing.T) {
	settings := DefaultMailParseSettings()
	huge := "X-Filler: " + strings.Repeat("f", settings.HeaderMaxByteCount+2*mailParseBufferByteCount)
	parsed := testMailParse(t, testMailMessage([]string{"From: ada@sender.example", huge, "Subject: after the cut"}, "body"))
	if parsed.Cut&MailParseCutHeader == 0 || parsed.From != "ada@sender.example" || parsed.Subject != "" || parsed.Text != "" {
		t.Errorf("cut %b, from %q, subject %q, text %q", parsed.Cut, parsed.From, parsed.Subject, parsed.Text)
	}

	partHeader := "X-Filler: " + strings.Repeat("p", settings.PartHeaderMaxByteCount+4*mailParseBufferByteCount)
	message := testMailMessage([]string{"From: ada@sender.example", "Content-Type: multipart/mixed; boundary=b"},
		"--b\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--b\r\n"+partHeader+"\r\nContent-Type: image/png\r\n\r\npng\r\n--b--\r\n")
	parsed = testMailParse(t, message)
	if parsed.Cut&MailParseCutPartHeader == 0 || parsed.Text != "first" || len(parsed.Attachments) != 0 {
		t.Errorf("cut %b, text %q, attachments %d", parsed.Cut, parsed.Text, len(parsed.Attachments))
	}

	long := strings.Repeat("0123456789", settings.DecodedMaxByteCount/5)
	parsed = testMailParse(t, testMailMessage([]string{"From: ada@sender.example"}, long))
	if parsed.Cut&MailParseCutDecoded == 0 || len(parsed.Text) != settings.DecodedMaxByteCount || parsed.ByteCount != uint64(len(testMailMessage([]string{"From: ada@sender.example"}, long))) {
		t.Errorf("cut %b, text %d B, read %d B", parsed.Cut, len(parsed.Text), parsed.ByteCount)
	}
	if len(parsed.Snippet) > 200 {
		t.Errorf("a snippet of %d B", len(parsed.Snippet))
	}
}

// Malformed MIME: a header line with no colon is passed over and later fields still read; a multipart with no
// boundary, or one past 70 bytes, is read through as opaque; a part cut short ends the walk. None is an error.
func TestMailParseMalformed(t *testing.T) {
	parsed := testMailParse(t, "From ada@sender.example Mon Nov  9 10:00:00 2026\r\nFrom: ada@sender.example\r\nno colon here\r\nSubject: still read\r\n\r\nbody\r\n")
	if parsed.Cut != MailParseCutMalformed || parsed.Subject != "still read" || parsed.From != "ada@sender.example" || parsed.Text != "body\n" {
		t.Errorf("cut %b, subject %q, from %q, text %q", parsed.Cut, parsed.Subject, parsed.From, parsed.Text)
	}
	for _, contentType := range []string{"multipart/mixed", "multipart/mixed; boundary=" + strings.Repeat("b", 71)} {
		parsed = testMailParse(t, testMailMessage([]string{"Content-Type: " + contentType}, "--b\r\n\r\nx\r\n--b--\r\n"))
		if parsed.Cut != MailParseCutMalformed || parsed.Text != "" {
			t.Errorf("%s: cut %b, text %q", contentType, parsed.Cut, parsed.Text)
		}
	}
	// a body that ends inside a part, and one that never reaches a boundary
	for _, body := range []string{"--b\r\nContent-Type: text/plain\r\n\r\ncut sho", "no boundary at all"} {
		parsed = testMailParse(t, testMailMessage([]string{"Subject: s", "Content-Type: multipart/mixed; boundary=b"}, body))
		if parsed.Subject != "s" {
			t.Errorf("%q: subject %q", body, parsed.Subject)
		}
	}
	// an unparseable Content-Type is text/plain (RFC 2045 §5.2), and an unknown transfer encoding is read as is
	parsed = testMailParse(t, testMailMessage([]string{"Content-Type: ;;;", "Content-Transfer-Encoding: x-synthetic"}, "as is"))
	if parsed.Text != "as is" {
		t.Errorf("text %q", parsed.Text)
	}
	// nothing at all, and a header with no body
	for _, message := range []string{"", "Subject: only a header"} {
		if _, err := MailParseMessage(strings.NewReader(message), nil); err != nil {
			t.Errorf("%q: %v", message, err)
		}
	}
}

// A reader that gives prefix, then fails.
type testMailFailingReader struct {
	prefix io.Reader
	err    error
}

// The prefix, then the error.
func (self *testMailFailingReader) Read(data []byte) (int, error) {
	count, err := self.prefix.Read(data)
	if err == io.EOF {
		return count, self.err
	}
	return count, err
}

// The reader's own failure is the walk's error, wherever it falls, so a caller retries rather than index a part.
func TestMailParseReaderError(t *testing.T) {
	failure := errors.New("store failed")
	message := testMailMessage([]string{"From: ada@sender.example", "Content-Type: multipart/mixed; boundary=b"},
		"--b\r\nContent-Type: text/plain\r\n\r\ntext\r\n--b\r\nContent-Type: image/png\r\n\r\n"+strings.Repeat("p", 10000)+"\r\n--b--\r\n")
	for _, at := range []int{0, 10, 60, 100, 5000, len(message) - 3} {
		reader := &testMailFailingReader{prefix: strings.NewReader(message[:at]), err: failure}
		if _, err := MailParseMessage(reader, nil); !errors.Is(err, failure) {
			t.Errorf("failing at %d: %v", at, err)
		}
	}
}

// Settings at zero or below walk nothing they bound, and never panic.
func TestMailParseZeroSettings(t *testing.T) {
	message := testMailMessage([]string{"From: ada@sender.example", "Content-Type: multipart/mixed; boundary=b"},
		"--b\r\nContent-Type: text/plain\r\n\r\ntext\r\n--b--\r\n")
	cases := []struct {
		settings *MailParseSettings
		want     MailParseCut
	}{
		{settings: &MailParseSettings{}, want: MailParseCutHeader},
		{settings: &MailParseSettings{HeaderMaxByteCount: -1, MaxPartCount: 9, MaxDepth: 9, DecodedMaxByteCount: 9, PartHeaderMaxByteCount: 99}, want: MailParseCutHeader},
		{settings: &MailParseSettings{HeaderMaxByteCount: 1024}, want: MailParseCutParts},
		{settings: &MailParseSettings{HeaderMaxByteCount: 1024, MaxPartCount: 9}, want: MailParseCutDepth},
		{settings: &MailParseSettings{HeaderMaxByteCount: 1024, MaxPartCount: 9, MaxDepth: 9}, want: MailParseCutDecoded},
	}
	for index, c := range cases {
		parsed, err := MailParseMessage(strings.NewReader(message), c.settings)
		if err != nil || parsed.Cut&c.want == 0 || parsed.Text != "" {
			t.Errorf("case %d: %+v, %v", index, parsed, err)
		}
	}
}

// The property FuzzMailParse holds over one input, or why not: no error from a reader that cannot fail, every
// value valid UTF-8 within its cap, no line break in a single-line value, the counts within their bounds, the read
// within the input, the IndexEntry built and encoded, the ingest headers unsplit, and memory within a fixed multiple
// of the input.
func checkMailParse(input []byte) string {
	settings := DefaultMailParseSettings()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	parsed, err := MailParseMessage(strings.NewReader(string(input)), settings)
	runtime.ReadMemStats(&after)
	if err != nil {
		return "an error from a reader that cannot fail: " + err.Error()
	}
	// a fixed cost per bound, and a multiple of the input
	allowed := uint64(16*1024*1024) + 16*uint64(len(input))
	if allocated := after.TotalAlloc - before.TotalAlloc; allowed < allocated {
		return fmt.Sprintf("allocated %d B for %d B", allocated, len(input))
	}
	lines := map[string]int{
		"from":    mailIndexFromMaxByteCount,
		"subject": mailIndexSubjectMaxByteCount,
		"snippet": mailIndexSnippetMaxByteCount,
		"domain":  dnsDomainMaxByteCount,
	}
	values := map[string]string{"from": parsed.From, "subject": parsed.Subject, "snippet": parsed.Snippet, "domain": parsed.FromDomain}
	for name, maxByteCount := range lines {
		value := values[name]
		if !utf8.ValidString(value) || maxByteCount < len(value) || strings.ContainsAny(value, "\r\n") {
			return name + " broke its cap or its line"
		}
	}
	for _, value := range []string{parsed.MessageId, parsed.ThreadMessageId} {
		if !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n") {
			return "an id broke its line"
		}
	}
	if mailIndexMessageIdMaxByteCount < len(parsed.MessageId) {
		return "a message id past its cap"
	}
	if !utf8.ValidString(parsed.Text) || settings.DecodedMaxByteCount < len(parsed.Text) || strings.Contains(parsed.Text, "\r") {
		return "text broke its cap"
	}
	if mailIndexAttachmentMaxCount < len(parsed.Attachments) || parsed.AttachmentCount < len(parsed.Attachments) {
		return "attachments past their count"
	}
	for _, attachment := range parsed.Attachments {
		if mailIndexAttachmentNameMaxByteCount < len(attachment.GetName()) || mailIndexAttachmentTypeMaxByteCount < len(attachment.GetType()) ||
			strings.ContainsAny(attachment.GetName()+attachment.GetType(), "\r\n") || uint64(len(input)) < attachment.GetSize() {
			return "an attachment broke its caps"
		}
	}
	if settings.MaxPartCount < parsed.PartCount || uint64(len(input)) < parsed.ByteCount {
		return "counts past their bounds"
	}
	deposit := testMailReceiverDeposit()
	entry, err := MailBuildIndexEntry(&MailIndexEntryInput{Id: Id{7}, Deposit: deposit, Parsed: parsed, ByteCount: uint64(len(input))})
	if err != nil {
		return "no entry: " + err.Error()
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		return "the entry does not encode: " + err.Error()
	}
	if 16*1024 <= len(encoded) {
		return fmt.Sprintf("an entry of %d B", len(encoded))
	}
	if failure := checkMailIngestHeaderLines(MailIngestHeaders(deposit, Id{7}, parsed.FromDomain)); failure != "" {
		return failure
	}
	return ""
}

// One seed of testdata/fuzz/FuzzMailParse: its bytes.
func testMailParseSeed(t *testing.T, name string, seed []byte) []byte {
	t.Helper()
	header, body, found := strings.Cut(string(seed), "\n")
	if !found || header != "go test fuzz v1" {
		t.Fatalf("%s: not a corpus file", name)
	}
	quoted, found := strings.CutPrefix(strings.TrimSpace(body), "[]byte(")
	if !found {
		t.Fatalf("%s: not a bytes value", name)
	}
	value, err := strconv.Unquote(strings.TrimSuffix(quoted, ")"))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return []byte(value)
}

// The seeds hold the fuzz target's property on every leg: go test runs them through FuzzMailParse only where a file
// system lets it read them, and the Worker has none.
func TestMailParseFuzzSeedsHold(t *testing.T) {
	const directory = "testdata/fuzz/FuzzMailParse"
	entries, err := fs.ReadDir(testMailParseFiles, directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 8 {
		t.Fatalf("%d seeds", len(entries))
	}
	for _, entry := range entries {
		seed, err := testMailParseFiles.ReadFile(directory + "/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if failure := checkMailParse(testMailParseSeed(t, entry.Name(), seed)); failure != "" {
			t.Errorf("%s: %s", entry.Name(), failure)
		}
	}
}
