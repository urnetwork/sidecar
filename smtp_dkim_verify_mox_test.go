//go:build !sidecar_http && !js && !ios_extension

// The sender's signatures checked by a verifier written apart from this repo, mox's, which MAIL's
// inbound checks link (mail_auth_dkim.go), over smtp_dkim_verify_test.go's messages. Off js, as
// MAIL's checks are: mox's resolver does not build there.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/mjl-/mox/dkim"
	moxdns "github.com/mjl-/mox/dns"
)

// mox passes both signatures in the header block's order, body hash and b= alike, and on a masked To
// still passes the fixed one alone. Its only policy here is refusing l=, which §14.6 never signs; mox's
// default policy would also want Subject signed, which the fixed signature never is. mox reads x=
// against the wall clock, so the signing time is past any run's: a fixed input, not the time of the
// run.
func TestSmtpDkimSignaturesPassAnIndependentVerifier(t *testing.T) {
	signTime := time.Date(2200, time.January, 1, 0, 0, 0, 0, time.UTC)
	publicKey, err := x509.MarshalPKIXPublicKey(&testVerifyKey().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := moxdns.MockResolver{TXT: map[string][]string{
		testVerifySelector + "._domainkey." + testVerifyDomain + ".": {"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(publicKey)},
	}}
	policy := func(sig *dkim.Sig) error {
		if 0 <= sig.Length {
			return errors.New("an l= tag")
		}
		return nil
	}
	verify := func(message []byte) []dkim.Result {
		results, err := dkim.Verify(context.Background(), slog.New(slog.DiscardHandler), resolver, false, policy, bytes.NewReader(message), false)
		if err != nil {
			t.Fatal(err)
		}
		return results
	}
	fixedHeaders := []string{"from", "date", "message-id", "x-ur-ref", "feedback-id"}
	for i, c := range testVerifyMessages() {
		results := verify(testVerifySigned(t, c.message, c.flags, signTime))
		if len(results) != 2 {
			t.Fatalf("message %d: %d results", i, len(results))
		}
		for j, result := range results {
			if result.Status != dkim.StatusPass {
				t.Errorf("message %d signature %d: %s %v", i, j, result.Status, result.Err)
			}
		}
		if !slices.Equal(results[0].Sig.SignedHeaders, fixedHeaders) || slices.Equal(results[1].Sig.SignedHeaders, fixedHeaders) {
			t.Errorf("message %d: h= %q then %q", i, results[0].Sig.SignedHeaders, results[1].Sig.SignedHeaders)
		}
	}
	results := verify(testVerifyMasked(t, testVerifySigned(t, testVerifyMessages()[0].message, 0, signTime)))
	if len(results) != 2 || results[0].Status != dkim.StatusPass || results[1].Status != dkim.StatusFail {
		t.Errorf("masked: %+v", results)
	}
}
