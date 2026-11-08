// Both DKIM checks against sidecartest's signer, whose canonicalization is written apart from the
// verifier's: the reporter's whole verify, and VerifyHeaders over reported headers with no body.

package smtpedgeservice_test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// The time every signature here is made and checked at.
var dkimTestNow = time.Date(2026, time.November, 3, 10, 0, 0, 0, time.UTC)

// A message of a network's, with §14.6's two signatures' fields.
func dkimTestMessage() *sidecartest.SmtpFixtureMessage {
	return &sidecartest.SmtpFixtureMessage{
		FromDomain: "quietnet.root.example",
		MessageId:  "<aaaabbbbccccddddeeeeffffgg@quietnet.root.example>",
		XUrRef:     "1.abcdefghijklmnopqrstuvwxyz234567ab",
		FeedbackId: "n:c:abcdefghijklmnopqrstuvwxyz:urnetwork",
		Subject:    "an   example  subject",
		Body:       "Hello there,  \n\nthe body.\n\n\n",
		Date:       dkimTestNow,
	}
}

// The header block of a message, through its blank line.
func headerBlockOf(t *testing.T, message []byte) []byte {
	t.Helper()
	end := bytes.Index(message, []byte("\r\n\r\n"))
	if end < 0 {
		t.Fatal("no blank line")
	}
	return message[:end+4]
}

// The reporter's whole verify of message, its keys in txt.
func verifyWhole(t *testing.T, txt smtpedgeservice.SmtpDnsTxtSource, message []byte) []*smtpedgeservice.SmtpDkimResult {
	t.Helper()
	settings := testSettings()
	verifier := smtpedgeservice.NewSmtpDkimVerifier(settings, txt, nil, sidecartest.NewFakeClock(dkimTestNow))
	bodyHash, err := verifier.NewBodyHash(headerBlockOf(t, message))
	if err != nil {
		t.Fatal(err)
	}
	// fed in uneven pieces, as the intake's single pass may
	for start := 0; start < len(message); start += 7 {
		bodyHash.Write(message[start:min(start+7, len(message))])
	}
	results, err := verifier.Verify(context.Background(), bodyHash)
	if err != nil {
		t.Fatal(err)
	}
	return results
}

// VerifyHeaders of a header block, its keys in store.
func verifyHeaders(t *testing.T, store *sidecartest.FakeSmtpEdgeStore, headerBlock []byte) []*smtpedgeservice.SmtpDkimResult {
	t.Helper()
	verifier := smtpedgeservice.NewSmtpDkimVerifier(testSettings(), nil, store, sidecartest.NewFakeClock(dkimTestNow))
	results, err := verifier.VerifyHeaders(context.Background(), headerBlock)
	if err != nil {
		t.Fatal(err)
	}
	return results
}

// The verdicts of results, in order.
func verdicts(results []*smtpedgeservice.SmtpDkimResult) []string {
	words := []string{}
	for _, result := range results {
		words = append(words, result.Result)
	}
	return words
}

// Whether two word lists are equal.
func sameWords(a []string, b ...string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDkimVerifiesRsaAndEd25519UnderEachCanonicalization(t *testing.T) {
	txt := sidecartest.NewFakeSmtpDnsTxt()
	keys := []*sidecartest.SmtpDkimFixtureKey{
		sidecartest.NewSmtpDkimFixtureRsaKey("rsa1", "reporter.example"),
		sidecartest.NewSmtpDkimFixtureEd25519Key("dkim test", "ed1", "reporter.example"),
	}
	for _, key := range keys {
		txt.Set(key.RecordName(), key.TxtRecord())
	}
	for _, key := range keys {
		for _, headerRelaxed := range []bool{false, true} {
			for _, bodyRelaxed := range []bool{false, true} {
				options := &sidecartest.SmtpDkimFixtureOptions{HeaderRelaxed: headerRelaxed, BodyRelaxed: bodyRelaxed, SignTime: dkimTestNow, ExpireTime: dkimTestNow.Add(7 * 24 * time.Hour)}
				signed := sidecartest.SignSmtpDkimFixture(dkimTestMessage().Bytes(), key, options)
				results := verifyWhole(t, txt, signed)
				if !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultPass) || results[0].Domain != "reporter.example" {
					t.Errorf("%s header relaxed %v body relaxed %v: %v", key.Algorithm, headerRelaxed, bodyRelaxed, verdicts(results))
				}
			}
		}
	}
}

func TestDkimHeaderOnlyPassesWithTheBodyRemovedAndTheWholeCheckFails(t *testing.T) {
	key := sidecartest.NewSmtpDkimFixtureRsaKey("abcdefghijklmnopqrstuvwxyz", "quietnet.root.example")
	networkId := sidecar.NewId()
	store := sidecartest.NewFakeSmtpEdgeStore(nil, nil)
	store.PutDkimKey(key.StoredKey(networkId))
	txt := sidecartest.NewFakeSmtpDnsTxt()
	txt.Set(key.RecordName(), key.TxtRecord())
	signed := sidecartest.SignSmtpDkimFixture(dkimTestMessage().Bytes(), key, &sidecartest.SmtpDkimFixtureOptions{HeaderRelaxed: true, BodyRelaxed: true})
	headersOnly := headerBlockOf(t, signed)
	results := verifyHeaders(t, store, headersOnly)
	if !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultPass) || results[0].NetworkId != networkId {
		t.Fatalf("header-only: %v", verdicts(results))
	}
	// the same header block with no body: the whole check's body hash no longer matches
	if results := verifyWhole(t, txt, headersOnly); !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultFail) {
		t.Fatalf("the whole check of a bodiless message: %v", verdicts(results))
	}
}

func TestDkimTamperedFromFails(t *testing.T) {
	key := sidecartest.NewSmtpDkimFixtureEd25519Key("tamper", "abcdefghijklmnopqrstuvwxyz", "quietnet.root.example")
	store := sidecartest.NewFakeSmtpEdgeStore(nil, nil)
	store.PutDkimKey(key.StoredKey(sidecar.NewId()))
	signed := sidecartest.SignSmtpDkimFixture(dkimTestMessage().Bytes(), key, &sidecartest.SmtpDkimFixtureOptions{HeaderRelaxed: true})
	tampered := bytes.Replace(signed, []byte("From: Sender <sender@quietnet.root.example>"), []byte("From: Sender <sender@othernet.root.example>"), 1)
	if results := verifyHeaders(t, store, headerBlockOf(t, tampered)); !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultFail) {
		t.Fatalf("a tampered From: %v", verdicts(results))
	}
}

func TestDkimMaskedRecipientsLeaveTheSecondSignatureVerifying(t *testing.T) {
	key := sidecartest.NewSmtpDkimFixtureRsaKey("abcdefghijklmnopqrstuvwxyz", "quietnet.root.example")
	store := sidecartest.NewFakeSmtpEdgeStore(nil, nil)
	store.PutDkimKey(key.StoredKey(sidecar.NewId()))
	message := dkimTestMessage().Bytes()
	// §14.6's two: relaxed over the usual fields, then over the five that survive masking
	first := sidecartest.SignSmtpDkimFixture(message, key, &sidecartest.SmtpDkimFixtureOptions{HeaderRelaxed: true, BodyRelaxed: true})
	both := sidecartest.SignSmtpDkimFixture(first, key, &sidecartest.SmtpDkimFixtureOptions{
		HeaderRelaxed: true, BodyRelaxed: true, Headers: []string{"from", "date", "message-id", "x-ur-ref", "feedback-id"},
	})
	if results := verifyHeaders(t, store, headerBlockOf(t, both)); !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultPass, smtpedgeservice.SmtpDkimResultPass) {
		t.Fatalf("unmasked: %v", verdicts(results))
	}
	masked := bytes.Replace(both, []byte("To: recipient@receiver.example"), []byte("To: <redacted>"), 1)
	// the second signature was added last, so it sits first
	results := verifyHeaders(t, store, headerBlockOf(t, masked))
	if !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultPass, smtpedgeservice.SmtpDkimResultFail) {
		t.Fatalf("masked: %v", verdicts(results))
	}
}

func TestDkimRsaSha1AndLengthTagsRefused(t *testing.T) {
	key := sidecartest.NewSmtpDkimFixtureRsaKey("abcdefghijklmnopqrstuvwxyz", "quietnet.root.example")
	store := sidecartest.NewFakeSmtpEdgeStore(nil, nil)
	store.PutDkimKey(key.StoredKey(sidecar.NewId()))
	signed := sidecartest.SignSmtpDkimFixture(dkimTestMessage().Bytes(), key, nil)
	for _, refused := range [][2]string{{"a=rsa-sha256", "a=rsa-sha1"}, {"; h=", "; l=10; h="}} {
		altered := bytes.Replace(signed, []byte(refused[0]), []byte(refused[1]), 1)
		if results := verifyHeaders(t, store, headerBlockOf(t, altered)); !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultPolicy) {
			t.Errorf("%s: %v", refused[1], verdicts(results))
		}
	}
}

func TestDkimExpiredSignatureRefusedOnlyByTheWholeCheck(t *testing.T) {
	key := sidecartest.NewSmtpDkimFixtureEd25519Key("expired", "abcdefghijklmnopqrstuvwxyz", "quietnet.root.example")
	store := sidecartest.NewFakeSmtpEdgeStore(nil, nil)
	store.PutDkimKey(key.StoredKey(sidecar.NewId()))
	txt := sidecartest.NewFakeSmtpDnsTxt()
	txt.Set(key.RecordName(), key.TxtRecord())
	signed := sidecartest.SignSmtpDkimFixture(dkimTestMessage().Bytes(), key, &sidecartest.SmtpDkimFixtureOptions{
		SignTime: dkimTestNow.Add(-8 * 24 * time.Hour), ExpireTime: dkimTestNow.Add(-time.Hour),
	})
	if results := verifyWhole(t, txt, signed); !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultPolicy) {
		t.Fatalf("whole: %v", verdicts(results))
	}
	// a complaint can arrive after x=: VerifyHeaders reports it and leaves the call to attribution
	results := verifyHeaders(t, store, headerBlockOf(t, signed))
	if !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultPass) || !results[0].ExpireTime.Equal(dkimTestNow.Add(-time.Hour).Truncate(time.Second)) {
		t.Fatalf("header-only: %v", verdicts(results))
	}
}

func TestDkimKeyTroublesGiveTheirVerdicts(t *testing.T) {
	key := sidecartest.NewSmtpDkimFixtureRsaKey("rsa1", "reporter.example")
	signed := sidecartest.SignSmtpDkimFixture(dkimTestMessage().Bytes(), key, nil)
	txt := sidecartest.NewFakeSmtpDnsTxt()
	// no record
	if results := verifyWhole(t, txt, signed); !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultPermError) {
		t.Fatalf("no record: %v", verdicts(results))
	}
	// a revoked key
	txt.Set(key.RecordName(), "v=DKIM1; k=rsa; p=")
	if results := verifyWhole(t, txt, signed); !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultPermError) {
		t.Fatalf("revoked: %v", verdicts(results))
	}
	// an Ed25519 record for an RSA signature
	txt.Set(key.RecordName(), sidecartest.NewSmtpDkimFixtureEd25519Key("other", "rsa1", "reporter.example").TxtRecord())
	if results := verifyWhole(t, txt, signed); !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultPermError) {
		t.Fatalf("mismatched key type: %v", verdicts(results))
	}
	// DNS that does not answer
	txt.Set(key.RecordName(), key.TxtRecord())
	txt.SetFailing(key.RecordName(), true)
	if results := verifyWhole(t, txt, signed); !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultTempError) {
		t.Fatalf("a DNS timeout: %v", verdicts(results))
	}
	// a 512-bit key, which RFC 8301 forbids
	small := &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 511), big.NewInt(1)), E: 65537}
	der, err := x509.MarshalPKIXPublicKey(small)
	if err != nil {
		t.Fatal(err)
	}
	txt.SetFailing(key.RecordName(), false)
	txt.Set(key.RecordName(), "v=DKIM1; p="+base64.StdEncoding.EncodeToString(der))
	if results := verifyWhole(t, txt, signed); !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultPolicy) {
		t.Fatalf("a small key: %v", verdicts(results))
	}
}

func TestDkimVerifyHeadersIgnoresKeysNotUrnetworks(t *testing.T) {
	key := sidecartest.NewSmtpDkimFixtureRsaKey("abcdefghijklmnopqrstuvwxyz", "quietnet.root.example")
	signed := sidecartest.SignSmtpDkimFixture(dkimTestMessage().Bytes(), key, nil)
	// published in DNS but not in smtp_dkim_key: none, since only URnetwork's own keys count
	results := verifyHeaders(t, sidecartest.NewFakeSmtpEdgeStore(nil, nil), headerBlockOf(t, signed))
	if !sameWords(verdicts(results), smtpedgeservice.SmtpDkimResultNone) {
		t.Fatalf("%v", verdicts(results))
	}
}

func TestDkimSignatureCountBounded(t *testing.T) {
	key := sidecartest.NewSmtpDkimFixtureEd25519Key("many", "abcdefghijklmnopqrstuvwxyz", "quietnet.root.example")
	store := sidecartest.NewFakeSmtpEdgeStore(nil, nil)
	store.PutDkimKey(key.StoredKey(sidecar.NewId()))
	message := dkimTestMessage().Bytes()
	for range testSettings().ReportDkimSignatureCount + 3 {
		message = sidecartest.SignSmtpDkimFixture(message, key, nil)
	}
	if results := verifyHeaders(t, store, headerBlockOf(t, message)); len(results) != testSettings().ReportDkimSignatureCount {
		t.Fatalf("%d signatures checked", len(results))
	}
}

func TestDkimCheckableNeedsASignatureThatCanPass(t *testing.T) {
	verifier := smtpedgeservice.NewSmtpDkimVerifier(testSettings(), nil, nil, nil)
	bodyHash, err := verifier.NewBodyHash([]byte("From: a@reporter.example\r\n\r\n"))
	if err != nil || bodyHash.Checkable() {
		t.Fatalf("an unsigned message is checkable: %v", err)
	}
	signed := sidecartest.SignSmtpDkimFixture(dkimTestMessage().Bytes(), sidecartest.NewSmtpDkimFixtureRsaKey("s", "reporter.example"), nil)
	bodyHash, err = verifier.NewBodyHash(headerBlockOf(t, signed))
	if err != nil || !bodyHash.Checkable() {
		t.Fatalf("a signed message is not checkable: %v", err)
	}
}
