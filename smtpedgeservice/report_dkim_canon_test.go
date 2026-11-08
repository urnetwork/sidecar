// RFC 6376's canonicalization examples and RFC 8463's signed message, against the canonicalizer and the
// verifier directly.

package smtpedgeservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// TXT records from a map.
type mapTxtSource map[string][]string

// See SmtpDnsTxtSource.
func (self mapTxtSource) LookupTxt(ctx context.Context, name string) ([]string, error) {
	return self[name], nil
}

// A fixed time.
type fixedClock struct {
	now time.Time
}

// The fixed time.
func (self fixedClock) Now() time.Time {
	return self.now
}

// Never fires: nothing these tests wait on.
func (self fixedClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

// Never calls.
func (self fixedClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

var _ sidecar.Clock = fixedClock{}

// A body through a canonicalizer, one write.
func canonBody(body string, relaxed bool) string {
	var out bytes.Buffer
	canon := newSmtpDkimBodyCanon(relaxed, &recordingHash{out: &out})
	canon.write([]byte(body))
	canon.finish()
	return out.String()
}

// A hash.Hash that keeps what it is written, so a canonical body can be read back.
type recordingHash struct {
	out *bytes.Buffer
}

// Keeps it.
func (self *recordingHash) Write(data []byte) (int, error) { return self.out.Write(data) }

// The bytes kept.
func (self *recordingHash) Sum(b []byte) []byte { return append(b, self.out.Bytes()...) }

// Forgets them.
func (self *recordingHash) Reset() { self.out.Reset() }

// Unused.
func (self *recordingHash) Size() int { return 0 }

// Unused.
func (self *recordingHash) BlockSize() int { return 1 }

func TestDkimCanonicalizesRfc6376Examples(t *testing.T) {
	// §3.4.6's message
	header := "A: X\r\nB : Y\t\r\n\tZ  \r\n"
	body := " C \r\nD \t E\r\n\r\n\r\n"
	fields, err := smtpHeaderFields([]byte(header+"\r\n"), true)
	if err != nil || len(fields) != 2 {
		t.Fatalf("%d fields, %v", len(fields), err)
	}
	var relaxed, simple strings.Builder
	for _, field := range fields {
		relaxed.Write(smtpDkimCanonHeader(field, true))
		simple.Write(smtpDkimCanonHeader(field, false))
	}
	if relaxed.String() != "a:X\r\nb:Y Z\r\n" {
		t.Fatalf("relaxed header %q", relaxed.String())
	}
	if simple.String() != header {
		t.Fatalf("simple header %q", simple.String())
	}
	if got := canonBody(body, true); got != " C\r\nD E\r\n" {
		t.Fatalf("relaxed body %q", got)
	}
	if got := canonBody(body, false); got != " C \r\nD \t E\r\n" {
		t.Fatalf("simple body %q", got)
	}
}

func TestDkimEmptyBodyHashes(t *testing.T) {
	// the well-known bh= of an empty body: simple is one CRLF, relaxed is nothing (erratum 1384)
	cases := []struct {
		body    string
		relaxed bool
		want    string
	}{
		{body: "", relaxed: false, want: "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="},
		{body: "\r\n\r\n", relaxed: false, want: "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="},
		{body: "", relaxed: true, want: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="},
		{body: " \t\r\n\r\n", relaxed: true, want: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="},
	}
	for _, c := range cases {
		canon := newSmtpDkimBodyCanon(c.relaxed, sha256.New())
		canon.write([]byte(c.body))
		if got := base64.StdEncoding.EncodeToString(canon.finish()); got != c.want {
			t.Errorf("%q relaxed=%v: %s", c.body, c.relaxed, got)
		}
	}
}

func TestDkimBodyCanonIsTheSameAcrossWrites(t *testing.T) {
	random := rand.New(rand.NewPCG(3, 4))
	alphabet := []byte("ab \t\r\n")
	for range 200 {
		body := make([]byte, random.IntN(64))
		for i := range body {
			body[i] = alphabet[random.IntN(len(alphabet))]
		}
		for _, relaxed := range []bool{false, true} {
			whole := canonBody(string(body), relaxed)
			var out bytes.Buffer
			canon := newSmtpDkimBodyCanon(relaxed, &recordingHash{out: &out})
			for i := range body {
				canon.write(body[i : i+1])
			}
			canon.finish()
			if out.String() != whole {
				t.Fatalf("%q relaxed=%v: %q byte by byte, %q whole", body, relaxed, out.String(), whole)
			}
		}
	}
}

func TestDkimTagListRefusesRepeatsAndBareNames(t *testing.T) {
	if tags, ok := smtpDkimTagList(" v=1; a = rsa-sha256 ;\r\n\tb=AB CD ;"); !ok || tags["a"] != "rsa-sha256" || tags["b"] != "AB CD" {
		t.Fatalf("%v, %v", tags, ok)
	}
	for _, refused := range []string{"v=1; v=1", "v=1; bare", "=x"} {
		if _, ok := smtpDkimTagList(refused); ok {
			t.Errorf("%q parsed", refused)
		}
	}
}

func TestDkimSignatureFieldLosesOnlyItsBValue(t *testing.T) {
	field := []byte("DKIM-Signature: v=1; bh=QUFB;\r\n b=QUFB\r\n QkJC; d=x.example\r\n")
	fields, err := smtpHeaderFields(field, true)
	if err != nil || len(fields) != 1 {
		t.Fatal(err)
	}
	if got := string(smtpDkimCanonSignatureField(fields[0], false)); got != "DKIM-Signature: v=1; bh=QUFB;\r\n b=; d=x.example" {
		t.Fatalf("simple %q", got)
	}
	if got := string(smtpDkimCanonSignatureField(fields[0], true)); got != "dkim-signature:v=1; bh=QUFB; b=; d=x.example" {
		t.Fatalf("relaxed %q", got)
	}
}

func TestDkimVerifiesTheRfc8463Example(t *testing.T) {
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join("..", "testdata", "smtp", "dkim", name))
		if err != nil {
			t.Fatal(err)
		}
		return bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
	}
	message := read("rfc8463.eml")
	record := strings.TrimSpace(string(read("rfc8463.txt")))
	settings := reportTestSettings()
	verifier := NewSmtpDkimVerifier(settings, mapTxtSource{"brisbane._domainkey.football.example.com": {record}}, nil, fixedClock{now: time.Unix(1528637909, 0)})
	headerBlock, _, ok := smtpSplitHeaderBlock(message, settings.ReportHeaderByteCount)
	if !ok {
		t.Fatal("no header block")
	}
	bodyHash, err := verifier.NewBodyHash(headerBlock)
	if err != nil {
		t.Fatal(err)
	}
	bodyHash.Write(message)
	results, err := verifier.Verify(context.Background(), bodyHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Result != SmtpDkimResultPass || results[0].Domain != "football.example.com" || results[0].Selector != "brisbane" {
		t.Fatalf("%+v", results[0])
	}
	// one octet of the body changed fails the body hash
	tampered := bytes.Replace(message, []byte("hungry"), []byte("Hungry"), 1)
	bodyHash, _ = verifier.NewBodyHash(headerBlock)
	bodyHash.Write(tampered)
	if results, _ := verifier.Verify(context.Background(), bodyHash); results[0].Result != SmtpDkimResultFail {
		t.Fatalf("a changed body: %s", results[0].Result)
	}
}
