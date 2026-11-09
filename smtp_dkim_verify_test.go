//go:build !sidecar_http

// The sender's signatures checked by SMTP-M5-04's verifier in smtpedgeservice, whose canonicalizer
// was written apart from smtp_dkim_sign.go's: a receiver's whole verify, body hash included, and the
// header-only check §14.8's joins run on a report that masked recipients.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

const (
	testVerifyDomain   = "n1.root.example"
	testVerifySelector = "abcdefghijklmnopqrstuvwxya"
)

var testVerifyKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(cryptorand.Reader, sidecar.SmtpDkimRsaKeyBitCount)
	if err != nil {
		panic(err)
	}
	return key
})

// A signer over the run's key.
type testVerifySigner struct{}

func (self testVerifySigner) DkimSelector() string { return testVerifySelector }
func (self testVerifySigner) DkimDomain() string   { return testVerifyDomain }
func (self testVerifySigner) SignDkim(digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(nil, testVerifyKey(), crypto.SHA256, digest)
}

// URnetwork's own keys, as smtp_dkim_key would hold the run's.
type testVerifyLookups struct {
	key *smtpedgeservice.SmtpDkimKey
}

func (self *testVerifyLookups) FindDkimKey(ctx context.Context, selector string, domain string) (*smtpedgeservice.SmtpDkimKey, error) {
	if strings.EqualFold(selector, self.key.Selector) && strings.EqualFold(domain, self.key.Domain) {
		return self.key, nil
	}
	return nil, nil
}

func (self *testVerifyLookups) RecipientCount(ctx context.Context, networkId sidecar.Id, since time.Time) (uint64, error) {
	return 0, nil
}

// A verifier holding the run's key both in DNS and as URnetwork's own, reading time as signTime.
func newTestVerifier(t *testing.T, signTime time.Time) *smtpedgeservice.SmtpDkimVerifier {
	t.Helper()
	publicKey, err := x509.MarshalPKIXPublicKey(&testVerifyKey().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	txt := sidecartest.NewFakeSmtpDnsTxt()
	txt.Set(testVerifySelector+"._domainkey."+testVerifyDomain, "v=DKIM1; k=rsa; p="+base64.StdEncoding.EncodeToString(publicKey))
	lookups := &testVerifyLookups{key: &smtpedgeservice.SmtpDkimKey{
		Selector:  testVerifySelector,
		Domain:    testVerifyDomain,
		NetworkId: sidecar.NewId(),
		SidecarId: sidecar.NewId(),
		Algorithm: "rsa-sha256",
		PublicKey: publicKey,
	}}
	return smtpedgeservice.NewSmtpDkimVerifier(smtpedgeservice.DefaultSmtpEdgeSettings(), txt, lookups, sidecartest.NewFakeClock(signTime))
}

// A message assembled and signed as the sender does, with the issued values in their forms.
func testVerifySigned(t *testing.T, message string, flags uint32, signTime time.Time) []byte {
	t.Helper()
	wire, err := sidecar.AssembleSmtpMessage(&sidecar.SmtpAssembleArgs{
		Message:          []byte(strings.ReplaceAll(message, "\n", "\r\n")),
		HeaderFromDomain: testVerifyDomain,
		MessageIdDomain:  testVerifyDomain,
		Flags:            flags,
		Now:              signTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := sidecar.SmtpDkimSign(wire, &sidecar.SmtpDkimSignArgs{
		Signer: testVerifySigner{},
		Issued: &sidecar.SmtpIssuedHeaders{
			XUrRef:     "1.ljnfuws2ljnfuws2ljnfuws2ljnfuws2li",
			FeedbackId: "n:p:gmztgmztgmztgmztgmztgmztgm:urnetwork",
		},
		SignTime:      signTime,
		ExpireTimeout: sidecar.DefaultSmtpSenderSettings().DkimExpireTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// The messages each check runs over: text, a leading dot, trailing space and empty lines, 8-bit, a long
// line, BULK, and multipart.
func testVerifyMessages() []struct {
	message string
	flags   uint32
} {
	return []struct {
		message string
		flags   uint32
	}{
		{message: "From: Joe SixPack <joe@n1.root.example>\nTo: Suzie Q <suzie@shopping.example>\nCc: a@b.example\nSubject: Is dinner ready?\nMessage-ID: <aaaaaaaaaaaaaaaaaaaaaaaaaa@n1.root.example>\n\nHi.\n\nWe lost the game.  Are you hungry yet?\n\nJoe.\n"},
		{message: "From: a@n1.root.example\nMessage-ID: <aaaaaaaaaaaaaaaaaaaaaaaaaa@n1.root.example>\nSubject:   spaced\t out  \n\n.dot\n  lead \t \n\n\n"},
		{message: "From: a@n1.root.example\nMessage-ID: <aaaaaaaaaaaaaaaaaaaaaaaaaa@n1.root.example>\nSubject: caf\xc3\xa9\n\ncaf\xc3\xa9 \xe2\x98\x95\n" + strings.Repeat("z", 1500) + "\n"},
		{message: "From: a@n1.root.example\nMessage-ID: <aaaaaaaaaaaaaaaaaaaaaaaaaa@n1.root.example>\nList-Unsubscribe: <https://u.example/x>\n\nbulk\n", flags: sidecar.SmtpFlagBulk},
		{message: "From: a@n1.root.example\nMessage-ID: <aaaaaaaaaaaaaaaaaaaaaaaaaa@n1.root.example>\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=x\n\n--x\nContent-Type: text/plain\n\ncaf\xc3\xa9\n--x--\n"},
		{message: "From: a@n1.root.example\nMessage-ID: <aaaaaaaaaaaaaaaaaaaaaaaaaa@n1.root.example>\n"},
	}
}

// Each signature passes a receiver's whole verify, body hash and key from DNS included.
func TestSmtpDkimSignaturesPassTheEdgesVerifier(t *testing.T) {
	signTime := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	verifier := newTestVerifier(t, signTime.Add(time.Hour))
	for i, c := range testVerifyMessages() {
		signed := testVerifySigned(t, c.message, c.flags, signTime)
		headerEnd := bytes.Index(signed, []byte("\r\n\r\n")) + 4
		bodyHash, err := verifier.NewBodyHash(signed[:headerEnd])
		if err != nil {
			t.Fatal(err)
		}
		bodyHash.Write(signed)
		results, err := verifier.Verify(context.Background(), bodyHash)
		if err != nil {
			t.Fatal(err)
		}
		if len(results) != 2 {
			t.Fatalf("message %d: %d results", i, len(results))
		}
		for _, result := range results {
			if result.Result != smtpedgeservice.SmtpDkimResultPass || result.Domain != testVerifyDomain || result.Selector != testVerifySelector {
				t.Errorf("message %d: %+v", i, result)
			}
			if !result.ExpireTime.Equal(signTime.Add(7 * 24 * time.Hour)) {
				t.Errorf("message %d: x= %v", i, result.ExpireTime)
			}
		}
		headerResults, err := verifier.VerifyHeaders(context.Background(), signed[:headerEnd])
		if err != nil {
			t.Fatal(err)
		}
		for _, result := range headerResults {
			if result.Result != smtpedgeservice.SmtpDkimResultPass {
				t.Errorf("message %d headers: %+v", i, result)
			}
		}
	}
}

// §14.6: a report that masks the recipients breaks the full signature and leaves the fixed one, so a
// medium join still finds the network (§14.8).
func TestSmtpDkimSecondSignatureSurvivesAMaskedTo(t *testing.T) {
	signTime := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	verifier := newTestVerifier(t, signTime)
	signed := testVerifySigned(t, testVerifyMessages()[0].message, 0, signTime)
	masked := bytes.Replace(signed, []byte("To: Suzie Q <suzie@shopping.example>"), []byte("To: xxxxxxxx@redacted.example"), 1)
	masked = bytes.Replace(masked, []byte("Cc: <a@b.example>"), []byte("Cc: redacted"), 1)
	if bytes.Equal(masked, signed) {
		t.Fatal("nothing was masked")
	}
	headerEnd := bytes.Index(masked, []byte("\r\n\r\n")) + 4
	results, err := verifier.VerifyHeaders(context.Background(), masked[:headerEnd])
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Result != smtpedgeservice.SmtpDkimResultFail || results[1].Result != smtpedgeservice.SmtpDkimResultPass {
		t.Errorf("results %+v %+v", results[0], results[1])
	}
}
