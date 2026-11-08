//go:build !sidecar_http

package sidecar

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime/quotedprintable"
	"strings"
	"sync"
	"testing"
	"time"
)

// The domains and Message-ID a test assembles under: .example names only.
const (
	testAssembleDomain    = "n1.root.example"
	testAssembleMessageId = "aaaaaaaaaaaaaaaaaaaaaaaaaa@n1.root.example"
)

// A signing time whose t= and x= are ten digits.
var testAssembleNow = time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)

// An RSA-2048 key made once per run, never kept anywhere.
var testAssembleKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(cryptorand.Reader, SmtpDkimRsaKeyBitCount)
	if err != nil {
		panic(err)
	}
	return key
})

// A signer over the run's key, under a fixed selector.
type testAssembleSigner struct {
	selector string
	domain   string
}

func (self *testAssembleSigner) DkimSelector() string { return self.selector }
func (self *testAssembleSigner) DkimDomain() string   { return self.domain }
func (self *testAssembleSigner) SignDkim(digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(nil, testAssembleKey(), crypto.SHA256, digest)
}

func newTestAssembleSigner() *testAssembleSigner {
	return &testAssembleSigner{selector: "abcdefghijklmnopqrstuvwxya", domain: testAssembleDomain}
}

// Issued values in their exact forms.
func testAssembleIssued() *SmtpIssuedHeaders {
	return &SmtpIssuedHeaders{
		XUrRef:     "1." + smtpDkimBase32.EncodeToString(bytes.Repeat([]byte{0x5a}, 21)),
		FeedbackId: "n:c:" + smtpDkimBase32.EncodeToString(bytes.Repeat([]byte{0x33}, 16)) + ":urnetwork",
	}
}

// lines joined with CRLF, a message's form.
func testAssembleCrlf(lines ...string) []byte {
	return []byte(strings.Join(lines, "\r\n"))
}

// RFC 8463's example message, at the test's domain.
func testAssembleMessage() []byte {
	return testAssembleCrlf(
		"From: Joe SixPack <joe@n1.root.example>",
		"To: Suzie Q <suzie@shopping.example>",
		"Bcc: hidden@other.example",
		"Subject: Is dinner ready?",
		"Date: Fri, 11 Jul 2003 21:00:37 -0700",
		"Message-ID: <"+testAssembleMessageId+">",
		"",
		"Hi.",
		"",
		"We lost the game.  Are you hungry yet?",
		"",
		"Joe.",
		"",
	)
}

func testAssembleArgs(message []byte) *SmtpAssembleArgs {
	return &SmtpAssembleArgs{Message: message, HeaderFromDomain: testAssembleDomain, MessageIdDomain: testAssembleDomain, Now: testAssembleNow}
}

// Assembles and signs message, failing the test on any error.
func testAssembleSigned(t *testing.T, args *SmtpAssembleArgs) (*SmtpWireMessage, []byte) {
	t.Helper()
	wire, err := AssembleSmtpMessage(args)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SmtpDkimSign(wire, &SmtpDkimSignArgs{Signer: newTestAssembleSigner(), Issued: testAssembleIssued(), SignTime: testAssembleNow, ExpireTimeout: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return wire, signed
}

// message dot-stuffed as DATA carries it.
func testDotStuffed(message []byte) []byte {
	var out []byte
	lineStart := true
	for _, octet := range message {
		if lineStart && octet == '.' {
			out = append(out, '.')
		}
		out = append(out, octet)
		lineStart = octet == '\n'
	}
	return out
}

// The header block's lines and the body.
func testAssembleSplit(t *testing.T, signed []byte) ([]string, []byte) {
	t.Helper()
	index := bytes.Index(signed, []byte("\r\n\r\n"))
	if index < 0 {
		t.Fatal("no header block")
	}
	return strings.Split(string(signed[:index]), "\r\n"), signed[index+4:]
}

// SPEC.md Z5's rules, restated here apart from smtpproof's relation.go: the octet class, one each of
// From, Message-ID, X-UR-Ref and Feedback-ID in their literal forms with no continuation, and exactly
// one line bearing the fixed prefix with the declared d= and s=.
func checkTestZ5(t *testing.T, signed []byte, selector string) {
	t.Helper()
	lines, _ := testAssembleSplit(t, signed)
	for _, octet := range signed[:bytes.Index(signed, []byte("\r\n\r\n"))] {
		if octet != '\t' && octet != '\r' && octet != '\n' && (octet < ' ' || '~' < octet) {
			t.Fatalf("octet %#x in the header block", octet)
		}
	}
	issued := testAssembleIssued()
	literals := map[string]string{
		"message-id":  "Message-ID: <" + testAssembleMessageId + ">",
		"x-ur-ref":    "X-UR-Ref: " + issued.XUrRef,
		"feedback-id": "Feedback-ID: " + issued.FeedbackId,
	}
	counts := map[string]int{}
	fixedCount := 0
	for i, line := range lines {
		if line == "" {
			t.Fatal("an empty line inside the header block")
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name, _, found := strings.Cut(line, ":")
		if !found || name == "" || name[0] == '.' || strings.ContainsAny(name, " \t") {
			t.Fatalf("line %q", line)
		}
		lower := strings.ToLower(name)
		continued := i+1 < len(lines) && (lines[i+1][0] == ' ' || lines[i+1][0] == '\t')
		if literal, ok := literals[lower]; ok {
			counts[lower] += 1
			if line != literal || continued {
				t.Errorf("%s is %q", lower, line)
			}
		}
		if lower == "from" {
			counts[lower] += 1
			if !strings.HasPrefix(line, "From: ") || !strings.HasSuffix(line, "@"+testAssembleDomain+">") || continued {
				t.Errorf("from is %q", line)
			}
		}
		if strings.HasPrefix(line, "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; ") {
			fixedCount += 1
			if !strings.HasPrefix(line, "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; d="+testAssembleDomain+"; s="+selector+"; ") {
				t.Errorf("fixed signature %q", line)
			}
		}
	}
	for _, name := range []string{"from", "message-id", "x-ur-ref", "feedback-id"} {
		if counts[name] != 1 {
			t.Errorf("%d %s lines", counts[name], name)
		}
	}
	if fixedCount != 1 {
		t.Errorf("%d fixed signatures", fixedCount)
	}
}

// The message the relation accepts: Z5's header block, Bcc gone, and a body ending CRLF.
func TestAssembleSmtpMessageReachesZ5(t *testing.T) {
	wire, signed := testAssembleSigned(t, testAssembleArgs(testAssembleMessage()))
	checkTestZ5(t, signed, newTestAssembleSigner().selector)
	if bytes.Contains(signed, []byte("hidden@other.example")) || bytes.Contains(bytes.ToLower(signed), []byte("bcc:")) {
		t.Error("Bcc reached the wire")
	}
	if wire.MessageId() != testAssembleMessageId || wire.HeaderFromDomain() != testAssembleDomain {
		t.Errorf("%s %s", wire.MessageId(), wire.HeaderFromDomain())
	}
	lines, body := testAssembleSplit(t, signed)
	if !strings.HasPrefix(lines[0], "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=") {
		t.Errorf("the full signature opens %q", lines[0])
	}
	if !bytes.HasSuffix(body, []byte("Joe.\r\n")) {
		t.Errorf("body %q", body)
	}
}

// Z5.5's literal, byte for byte: h= ahead of d= and s=, as SPEC.md and relation.go have it. The body is
// RFC 8463's example, whose relaxed body hash that RFC publishes as this bh=.
func TestSmtpDkimFixedSignatureIsZ5sLiteral(t *testing.T) {
	_, signed := testAssembleSigned(t, testAssembleArgs(testAssembleMessage()))
	want := "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; d=n1.root.example; s=abcdefghijklmnopqrstuvwxya; t=1794139200; x=1794744000;\r\n\tbh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n"
	if !bytes.Contains(signed, []byte(want)) {
		t.Errorf("no %q in\n%s", want, signed)
	}
	if bytes.Count(signed, []byte(smtpDkimFixedPrefix)) != 1 {
		t.Error("the fixed prefix twice")
	}
}

// RFC 6376 §3.4.6's example, canonicalized relaxed.
func TestSmtpDkimRelaxedCanonicalizationVectors(t *testing.T) {
	for _, c := range []struct{ line, want string }{
		{line: "A: X", want: "a:X\r\n"},
		{line: "B : Y\t\r\n\tZ  ", want: "b:Y Z\r\n"},
		{line: "Subject:", want: "subject:\r\n"},
		{line: "X:  a \t b  ", want: "x:a b\r\n"},
	} {
		if got := smtpDkimRelaxedField(c.line); got != c.want {
			t.Errorf("%q: %q", c.line, got)
		}
	}
	for _, c := range []struct{ body, want string }{
		{body: " C \r\nD \t E\r\n\r\n\r\n", want: " C\r\nD E\r\n"},
		{body: "", want: ""},
		{body: "\r\n\r\n", want: ""},
		{body: "a\r\n \t\r\nb\r\n", want: "a\r\n\r\nb\r\n"},
		{body: "a  \r\n", want: "a\r\n"},
	} {
		if got := string(smtpDkimRelaxedBody([]byte(c.body))); got != c.want {
			t.Errorf("%q: %q", c.body, got)
		}
	}
}

// Both signatures verify under the key, over the relaxed forms RFC 6376 gives, by a check written
// here from the message's own octets.
func TestSmtpDkimSignaturesVerifyUnderTheKey(t *testing.T) {
	_, signed := testAssembleSigned(t, testAssembleArgs(testAssembleMessage()))
	lines, body := testAssembleSplit(t, signed)
	var fields []string
	for _, line := range lines {
		if line[0] == ' ' || line[0] == '\t' {
			fields[len(fields)-1] += "\r\n" + line
		} else {
			fields = append(fields, line)
		}
	}
	bodyHash := sha256.Sum256(smtpDkimRelaxedBody(body))
	verified := 0
	for i, field := range fields {
		if !strings.HasPrefix(field, "DKIM-Signature:") {
			continue
		}
		tags := map[string]string{}
		for _, spec := range strings.Split(strings.TrimPrefix(field, "DKIM-Signature:"), ";") {
			name, value, _ := strings.Cut(spec, "=")
			strip := func(s string) string {
				return strings.Map(func(r rune) rune { return map[bool]rune{true: -1, false: r}[strings.ContainsRune(" \t\r\n", r)] }, s)
			}
			tags[strip(name)] = strip(value)
		}
		if tags["bh"] != base64Std(bodyHash[:]) {
			t.Errorf("bh %s", tags["bh"])
		}
		var input strings.Builder
		taken := map[int]bool{i: true}
		for _, name := range strings.Split(tags["h"], ":") {
			for j := len(fields) - 1; 0 <= j; j -= 1 {
				fieldName, _, _ := strings.Cut(fields[j], ":")
				if !taken[j] && strings.EqualFold(fieldName, name) {
					taken[j] = true
					input.WriteString(smtpDkimRelaxedField(fields[j]))
					break
				}
			}
		}
		unsigned := field[:strings.LastIndex(field, "b=")+2]
		input.WriteString(strings.TrimSuffix(smtpDkimRelaxedField(unsigned), "\r\n"))
		signature, err := base64StdDecode(tags["b"])
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(input.String()))
		if err := rsa.VerifyPKCS1v15(&testAssembleKey().PublicKey, crypto.SHA256, digest[:], signature); err != nil {
			t.Errorf("signature %d: %v", verified, err)
		}
		verified += 1
	}
	if verified != 2 {
		t.Errorf("%d signatures", verified)
	}
}

// What ByteCount predicts before anything is issued is the length of what is signed after, BDAT's
// plain and DATA's dot-stuffed, whatever the issued values, the time and the body (TestPredictedByteCountIsExact
// of plan-SMTP-preamble-byte-count).
func TestPredictedByteCountIsExact(t *testing.T) {
	bodies := []string{
		"",
		"one line with no end",
		".a leading dot\r\n..two\r\n.\r\nend\r\n",
		strings.Repeat(".x\r\n", 300),
		"caf\xc3\xa9 au lait\r\n" + strings.Repeat("y", 1200) + "\r\n",
	}
	issuedValues := []*SmtpIssuedHeaders{
		testAssembleIssued(),
		{XUrRef: "1." + smtpDkimBase32.EncodeToString(make([]byte, 21)), FeedbackId: "b:t:" + smtpDkimBase32.EncodeToString(make([]byte, 16)) + ":urnetwork"},
	}
	for _, bulk := range []bool{false, true} {
		for i, body := range bodies {
			header := "From: \"Q. Public, Jr\" <q@n1.root.example>\r\nTo: a@b.example, \"C\" <c@d.example>\r\nSubject: S\r\nMessage-ID: <" + testAssembleMessageId + ">\r\n"
			args := testAssembleArgs(nil)
			if bulk {
				header += "List-Unsubscribe: <https://u.example/x>, <mailto:u@u.example>\r\n"
				args.Flags = SmtpFlagBulk
			}
			args.Message = []byte(header + "\r\n" + body)
			wire, err := AssembleSmtpMessage(args)
			if err != nil {
				t.Fatalf("body %d: %v", i, err)
			}
			bdat, err := wire.ByteCount(SmtpModeBdat)
			if err != nil {
				t.Fatal(err)
			}
			data, err := wire.ByteCount(SmtpModeData)
			if err != nil {
				t.Fatal(err)
			}
			for j, issued := range issuedValues {
				signTime := testAssembleNow.Add(time.Duration(j) * 37 * time.Second)
				signed, err := SmtpDkimSign(wire, &SmtpDkimSignArgs{Signer: newTestAssembleSigner(), Issued: issued, SignTime: signTime, ExpireTimeout: 7 * 24 * time.Hour})
				if err != nil {
					t.Fatal(err)
				}
				if uint64(len(signed)) != bdat || uint64(len(testDotStuffed(signed))) != data {
					t.Errorf("bulk %v body %d issued %d: predicted %d and %d, signed %d and %d", bulk, i, j, bdat, data, len(signed), len(testDotStuffed(signed)))
				}
			}
		}
	}
	wire, _ := testAssembleSigned(t, testAssembleArgs(testAssembleMessage()))
	if _, err := wire.ByteCount(SmtpModeUnknown); !errors.Is(err, ErrSmtpAssemble) {
		t.Errorf("unknown mode: %v", err)
	}
}

// MAIL FROM names no BODY=, so an 8-bit body is quoted-printable on the wire and decodes back to what
// was written.
func TestAssembleReencodesAnEightBitBody(t *testing.T) {
	text := "Caf\xc3\xa9 \xe2\x98\x95 on the terrace.\r\nA second line.\r\n"
	message := testAssembleCrlf("From: joe@n1.root.example", "Message-ID: <"+testAssembleMessageId+">", "Subject: x", "", "")
	message = append(message, text...)
	_, signed := testAssembleSigned(t, testAssembleArgs(message))
	lines, body := testAssembleSplit(t, signed)
	header := strings.Join(lines, "\r\n")
	for _, want := range []string{"\r\nContent-Transfer-Encoding: quoted-printable", "\r\nMIME-Version: 1.0", "\r\nContent-Type: text/plain; charset=utf-8"} {
		if !strings.Contains(header, want) {
			t.Errorf("no %q", want)
		}
	}
	for _, octet := range body {
		if 0x7f < octet {
			t.Fatal("an 8-bit octet on the wire")
		}
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != text {
		t.Errorf("decoded %q", decoded)
	}
}

// A 999-octet line is past what a DATA line holds (RFC 5321 §4.5.3.1.6), so it is wrapped.
func TestAssembleWrapsALongLine(t *testing.T) {
	long := strings.Repeat("w", 999)
	message := testAssembleCrlf("From: joe@n1.root.example", "Message-ID: <"+testAssembleMessageId+">", "", long, "")
	_, signed := testAssembleSigned(t, testAssembleArgs(message))
	for _, line := range strings.Split(string(signed), "\r\n") {
		if 998 < len(line) {
			t.Fatalf("a %d-octet line", len(line))
		}
	}
	_, body := testAssembleSplit(t, signed)
	decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
	if err != nil || string(decoded) != long+"\r\n" {
		t.Errorf("decoded %d octets: %v", len(decoded), err)
	}
	// 998 octets fit, and stay as they are
	fits := strings.Repeat("w", 998)
	message = testAssembleCrlf("From: joe@n1.root.example", "Message-ID: <"+testAssembleMessageId+">", "", fits, "")
	_, signed = testAssembleSigned(t, testAssembleArgs(message))
	if _, body := testAssembleSplit(t, signed); string(body) != fits+"\r\n" {
		t.Error("a 998-octet line was re-encoded")
	}
}

// The header block is one record: 17 KiB of it fails before the preamble, and 14 KiB, with the
// signatures and issued fields added, passes.
func TestAssembleRefusesASeventeenKibHeaderBlock(t *testing.T) {
	header := func(byteCount int) []byte {
		var words []string
		for total := 0; total < byteCount; total += 9 {
			words = append(words, "abcdefgh")
		}
		return testAssembleCrlf("From: joe@n1.root.example", "Message-ID: <"+testAssembleMessageId+">", "X-Notes: "+strings.Join(words, " "), "", "body", "")
	}
	if _, err := AssembleSmtpMessage(testAssembleArgs(header(17 * 1024))); !errors.Is(err, ErrSmtpAssemble) {
		t.Errorf("17 KiB: %v", err)
	}
	_, signed := testAssembleSigned(t, testAssembleArgs(header(14*1024)))
	if headerEnd := bytes.Index(signed, []byte("\r\n\r\n")) + 4; SmtpHeaderBlockMaxByteCount < headerEnd || headerEnd < 15*1024 {
		t.Errorf("a %d-octet header block", headerEnd)
	}
}

// What Z5 or §14.6 cannot take fails assembly, before any preamble.
func TestAssembleRefusesWhatTheRelationCannotTake(t *testing.T) {
	id := "Message-ID: <" + testAssembleMessageId + ">"
	for _, c := range []struct {
		name    string
		message []byte
		flags   uint32
	}{
		{name: "no From", message: testAssembleCrlf(id, "", "b")},
		{name: "two From", message: testAssembleCrlf("From: a@n1.root.example", "From: b@n1.root.example", id, "", "b")},
		{name: "From elsewhere", message: testAssembleCrlf("From: a@other.example", id, "", "b")},
		{name: "two addresses", message: testAssembleCrlf("From: a@n1.root.example, b@n1.root.example", id, "", "b")},
		{name: "quoted local part", message: testAssembleCrlf("From: \"a b\"@n1.root.example", id, "", "b")},
		{name: "no Message-ID", message: testAssembleCrlf("From: a@n1.root.example", "", "b")},
		{name: "a client's Message-ID", message: testAssembleCrlf("From: a@n1.root.example", "Message-ID: <x.y@client.example>", "", "b")},
		{name: "a Message-ID at another domain", message: testAssembleCrlf("From: a@n1.root.example", "Message-ID: <aaaaaaaaaaaaaaaaaaaaaaaaaa@n2.root.example>", "", "b")},
		{name: "two Date", message: testAssembleCrlf("From: a@n1.root.example", id, "Date: x", "Date: y", "", "b")},
		{name: "bare CR", message: testAssembleCrlf("From: a@n1.root.example", id, "", "a\rb")},
		{name: "dot field", message: testAssembleCrlf("From: a@n1.root.example", id, ".From: b@n1.root.example", "", "b")},
		{name: "leading continuation", message: testAssembleCrlf(" x", "From: a@n1.root.example", id, "", "b")},
		{name: "bulk without unsubscribe", message: testAssembleCrlf("From: a@n1.root.example", id, "", "b"), flags: SmtpFlagBulk},
		{name: "bulk with mailto only", message: testAssembleCrlf("From: a@n1.root.example", id, "List-Unsubscribe: <mailto:u@u.example>", "", "b"), flags: SmtpFlagBulk},
		{name: "8-bit structured field", message: testAssembleCrlf("From: a@n1.root.example", id, "In-Reply-To: <caf\xc3\xa9@x.example>", "", "b")},
		{name: "unknown flag", message: testAssembleMessage(), flags: 8},
	} {
		args := testAssembleArgs(c.message)
		args.Flags = c.flags
		if _, err := AssembleSmtpMessage(args); !errors.Is(err, ErrSmtpAssemble) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// BULK gains exactly one one-click line, and the full signature covers it and List-Unsubscribe
// (R-SMTP-11, RFC 8058 §4).
func TestAssembleBulkAddsOneClickUnsubscribe(t *testing.T) {
	message := testAssembleCrlf("From: a@n1.root.example", "Message-ID: <"+testAssembleMessageId+">", "List-Unsubscribe: <https://u.example/x>",
		"List-Unsubscribe-Post: List-Unsubscribe=One-Click", "List-Unsubscribe-Post: something else", "", "b", "")
	args := testAssembleArgs(message)
	args.Flags = SmtpFlagBulk
	_, signed := testAssembleSigned(t, args)
	if bytes.Count(signed, []byte("\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n")) != 1 || bytes.Contains(signed, []byte("something else")) {
		t.Errorf("one-click lines in\n%s", signed)
	}
	if !bytes.Contains(signed, []byte(":list-unsubscribe:list-unsubscribe-post:")) {
		t.Error("the full signature does not cover the unsubscribe fields")
	}
}

// What the edge issues and the fixed signature's prefix are the sidecar's alone to add.
func TestAssembleDropsWhatTheEdgeIssues(t *testing.T) {
	message := testAssembleCrlf("From: a@n1.root.example", "Message-ID: <"+testAssembleMessageId+">", "X-UR-Ref: 1.forged", "feedback-id: n:c:forged:urnetwork",
		"Return-Path: <x@y.example>", smtpDkimFixedPrefix+"d=n1.root.example; s=forged; bh=x; b=y", "DKIM-Signature: v=1; d=other.example; s=kept; b=z", "", "b", "")
	_, signed := testAssembleSigned(t, testAssembleArgs(message))
	for _, gone := range []string{"forged", "Return-Path"} {
		if bytes.Contains(signed, []byte(gone)) {
			t.Errorf("%s reached the wire", gone)
		}
	}
	if !bytes.Contains(signed, []byte("s=kept")) {
		t.Error("another signature was dropped")
	}
	checkTestZ5(t, signed, newTestAssembleSigner().selector)
}

// Z5.4's phrase: words of atext stand, and anything else becomes encoded words.
func TestAssembleFromPhraseForms(t *testing.T) {
	for _, c := range []struct{ from, want string }{
		{from: "Joe SixPack <joe@n1.root.example>", want: "From: Joe SixPack <joe@n1.root.example>"},
		{from: "joe@N1.Root.Example", want: "From: <joe@n1.root.example>"},
		{from: "\"J. Smith\" <j@n1.root.example>", want: "From: =?utf-8?b?Si4gU21pdGg=?= <j@n1.root.example>"},
		{from: "=?utf-8?q?Jos=C3=A9?= <j@n1.root.example>", want: "From: =?utf-8?b?Sm9zw6k=?= <j@n1.root.example>"},
		{from: "\"Doe, Jane\" <jane@n1.root.example>", want: "From: =?utf-8?b?RG9lLCBKYW5l?= <jane@n1.root.example>"},
	} {
		message := testAssembleCrlf("From: "+c.from, "Message-ID: <"+testAssembleMessageId+">", "", "b", "")
		_, signed := testAssembleSigned(t, testAssembleArgs(message))
		lines, _ := testAssembleSplit(t, signed)
		found := false
		for _, line := range lines {
			if strings.HasPrefix(line, "From:") {
				found = true
				if line != c.want {
					t.Errorf("%q: %q", c.from, line)
				}
			}
		}
		if !found {
			t.Errorf("%q: no From", c.from)
		}
		checkTestZ5(t, signed, newTestAssembleSigner().selector)
	}
}

// Non-ASCII in unstructured fields and address names becomes encoded words, so the header block keeps
// to Z5.1's octets.
func TestAssembleEncodesEightBitHeaders(t *testing.T) {
	message := testAssembleCrlf("From: a@n1.root.example", "Message-ID: <"+testAssembleMessageId+">", "Subject: caf\xc3\xa9", "To: Jos\xc3\xa9 <j@x.example>, k@y.example", "", "b", "")
	_, signed := testAssembleSigned(t, testAssembleArgs(message))
	if !bytes.Contains(signed, []byte("\r\nSubject: =?utf-8?b?Y2Fmw6k=?=\r\n")) || !bytes.Contains(signed, []byte("\r\nTo: =?utf-8?b?Sm9zw6k=?= <j@x.example>, <k@y.example>\r\n")) {
		t.Errorf("headers in\n%s", signed)
	}
	checkTestZ5(t, signed, newTestAssembleSigner().selector)
}

// A multipart message keeps its boundary and its 7-bit parts, and an 8-bit part is re-encoded.
func TestAssembleReencodesAMultipartPart(t *testing.T) {
	message := testAssembleCrlf(
		"From: a@n1.root.example", "Message-ID: <"+testAssembleMessageId+">", "MIME-Version: 1.0",
		"Content-Type: multipart/mixed; boundary=\"b1\"", "",
		"preamble", "--b1", "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: 8bit", "",
		"caf\xc3\xa9", "--b1", "Content-Type: application/octet-stream", "Content-Transfer-Encoding: base64", "",
		"AAEC", "--b1--", "epilogue", "")
	_, signed := testAssembleSigned(t, testAssembleArgs(message))
	_, body := testAssembleSplit(t, signed)
	for _, octet := range body {
		if 0x7f < octet {
			t.Fatal("an 8-bit octet on the wire")
		}
	}
	for _, want := range []string{"preamble\r\n--b1\r\n", "Content-Transfer-Encoding: quoted-printable\r\n\r\ncaf=C3=A9\r\n--b1\r\n", "\r\n\r\nAAEC\r\n--b1--\r\nepilogue\r\n"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("no %q in\n%s", want, body)
		}
	}
}

// The edge is untrusted, so an issued value outside its exact form never reaches a header, and a
// signer for another domain or a time past ten digits signs nothing.
func TestSmtpDkimSignRefusesWhatItCannotTrust(t *testing.T) {
	wire, err := AssembleSmtpMessage(testAssembleArgs(testAssembleMessage()))
	if err != nil {
		t.Fatal(err)
	}
	good := testAssembleIssued()
	for _, c := range []struct {
		name string
		args *SmtpDkimSignArgs
	}{
		{name: "an injected line", args: &SmtpDkimSignArgs{Signer: newTestAssembleSigner(), Issued: &SmtpIssuedHeaders{XUrRef: good.XUrRef[:30] + "\r\nBcc: x", FeedbackId: good.FeedbackId}, SignTime: testAssembleNow, ExpireTimeout: time.Hour}},
		{name: "an upper case X-UR-Ref", args: &SmtpDkimSignArgs{Signer: newTestAssembleSigner(), Issued: &SmtpIssuedHeaders{XUrRef: strings.ToUpper(good.XUrRef), FeedbackId: good.FeedbackId}, SignTime: testAssembleNow, ExpireTimeout: time.Hour}},
		{name: "a short Feedback-ID", args: &SmtpDkimSignArgs{Signer: newTestAssembleSigner(), Issued: &SmtpIssuedHeaders{XUrRef: good.XUrRef, FeedbackId: "n:c:short:urnetwork"}, SignTime: testAssembleNow, ExpireTimeout: time.Hour}},
		{name: "another class", args: &SmtpDkimSignArgs{Signer: newTestAssembleSigner(), Issued: &SmtpIssuedHeaders{XUrRef: good.XUrRef, FeedbackId: "x" + good.FeedbackId[1:]}, SignTime: testAssembleNow, ExpireTimeout: time.Hour}},
		{name: "another domain's signer", args: &SmtpDkimSignArgs{Signer: &testAssembleSigner{selector: "abcdefghijklmnopqrstuvwxya", domain: "n2.root.example"}, Issued: good, SignTime: testAssembleNow, ExpireTimeout: time.Hour}},
		{name: "a selector outside its form", args: &SmtpDkimSignArgs{Signer: &testAssembleSigner{selector: "sel", domain: testAssembleDomain}, Issued: good, SignTime: testAssembleNow, ExpireTimeout: time.Hour}},
		{name: "a time before 2001", args: &SmtpDkimSignArgs{Signer: newTestAssembleSigner(), Issued: good, SignTime: time.Unix(999999999, 0), ExpireTimeout: time.Hour}},
		{name: "no expiry", args: &SmtpDkimSignArgs{Signer: newTestAssembleSigner(), Issued: good, SignTime: testAssembleNow}},
	} {
		if _, err := SmtpDkimSign(wire, c.args); err == nil {
			t.Errorf("%s: signed", c.name)
		}
	}
}

func TestSplitSmtpEnvelopeAddress(t *testing.T) {
	for _, c := range []struct {
		address, local, domain string
		ok                     bool
	}{
		{address: "suzie@Shopping.Example", local: "suzie", domain: "shopping.example", ok: true},
		{address: "a.b+tag@x.example", local: "a.b+tag", domain: "x.example", ok: true},
		{address: "\"a b\"@x.example"},
		{address: "a..b@x.example"},
		{address: ".a@x.example"},
		{address: "a%b@x.example"},
		{address: "a!b@x.example"},
		{address: "caf\xc3\xa9@x.example"},
		{address: strings.Repeat("a", 65) + "@x.example"},
		{address: "a@x.example>"},
		{address: "no-at-sign"},
	} {
		local, domain, ok := SplitSmtpEnvelopeAddress(c.address)
		if ok != c.ok || local != c.local || domain != c.domain {
			t.Errorf("%q: %q %q %v", c.address, local, domain, ok)
		}
	}
}

func TestNewSmtpMessageIdIsTheSidecarsForm(t *testing.T) {
	seen := map[string]bool{}
	for range 4 {
		id, err := NewSmtpMessageId("quietfox.n1.root.example")
		if err != nil {
			t.Fatal(err)
		}
		random, domain, _ := strings.Cut(id, "@")
		if !smtpDkimSelectorForm(random) || domain != "quietfox.n1.root.example" || seen[id] {
			t.Errorf("id %q", id)
		}
		seen[id] = true
		if _, err := smtpMessageIdValue("<"+id+">", "quietfox.n1.root.example"); err != nil {
			t.Error(err)
		}
	}
	if _, err := NewSmtpMessageId("Bad Domain"); !errors.Is(err, ErrSmtpAssemble) {
		t.Errorf("err %v", err)
	}
}

// The test's own base64, so a slip in the code's use of it cannot cancel out.
func base64Std(octets []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(octets); i += 3 {
		chunk := []byte{0, 0, 0}
		count := copy(chunk, octets[i:])
		value := uint(chunk[0])<<16 | uint(chunk[1])<<8 | uint(chunk[2])
		for j := 0; j < 4; j += 1 {
			if j <= count {
				out.WriteByte(alphabet[value>>(18-6*j)&63])
			} else {
				out.WriteByte('=')
			}
		}
	}
	return out.String()
}

// Decodes what base64Std writes.
func base64StdDecode(text string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	text = strings.TrimRight(text, "=")
	var out []byte
	var value, bits uint
	for _, r := range text {
		index := strings.IndexRune(alphabet, r)
		if index < 0 {
			return nil, fmt.Errorf("base64 octet %q", r)
		}
		value = value<<6 | uint(index)
		bits += 6
		if 8 <= bits {
			bits -= 8
			out = append(out, byte(value>>bits))
		}
	}
	return out, nil
}

// The published key's form, which a key record's p= carries.
func TestAssembleKeyIsTheRecordsForm(t *testing.T) {
	publicKey, err := x509.MarshalPKIXPublicKey(&testAssembleKey().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !smtpDkimPublicKeyValid(publicKey) {
		t.Error("the run's key is not rsa-2048")
	}
}
