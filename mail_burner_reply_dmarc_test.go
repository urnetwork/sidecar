//go:build !sidecar_http && !js

// MAIL-M9-03's strict-DMARC fixture (§15.9's replies, owner decision 79, D-SMTP-5): a burner's reply, under BURNER's
// header rules, assembled and signed as §14 does under the burner's own selector, passes DMARC at a receiver's checker
// (MAIL-M7-08's, on FakeMailZone) on strict DKIM alignment alone, since SPF's domain, the bounce address's, never
// equals the burner's; and another network's selector passes nothing for it, whether it signs under its own domain,
// which only relaxed alignment would take, or names this burner's. Every name, key and address is synthetic.

package sidecar_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The fixture's names: two networks of one root, a burner of each, and each network's bounce domain.
const (
	testBurnerReplyRoot       = "root.example"
	testBurnerReplyDomain     = "otter-4821.acme." + testBurnerReplyRoot
	testBurnerReplyBounce     = "b.acme." + testBurnerReplyRoot
	testBurnerReplyOther      = "heron-1907.other." + testBurnerReplyRoot
	testBurnerReplySelector   = "abcdefghijklmnopqrstuvwxya"
	testBurnerReplyOtherNamed = "bbbbbbbbbbbbbbbbbbbbbbbbba"
	// §12.7's policy, which every network's zone and the root publish
	testBurnerReplyPolicy = "v=DMARC1; p=reject; sp=reject; np=reject; adkim=s; aspf=s"
)

// When the fixture's signatures are made: mox, whose verifier the checker links, reads x= against the wall clock and
// not the checker's, so the time is past any run's, as smtp_dkim_verify_mox_test.go's is.
var testBurnerReplySignTime = time.Date(2200, time.January, 1, 0, 0, 0, 0, time.UTC)

// A selector of domain over key, as SmtpDkimKeys pins one.
type testBurnerReplySigner struct {
	selector string
	domain   string
	key      *rsa.PrivateKey
}

func (self *testBurnerReplySigner) DkimSelector() string { return self.selector }
func (self *testBurnerReplySigner) DkimDomain() string   { return self.domain }
func (self *testBurnerReplySigner) SignDkim(digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(nil, self.key, crypto.SHA256, digest)
}

// The selector's key record, as POST /smtp/dkim-keys publishes it.
func (self *testBurnerReplySigner) keyRecord(t *testing.T) string {
	t.Helper()
	publicKey, err := x509.MarshalPKIXPublicKey(&self.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(publicKey)
}

// A reply as a mail client wrote it, with what the header rules remove.
func testBurnerReplyDraft() []byte {
	return []byte(strings.Join([]string{
		"Received: from laptop.home.example ([203.0.113.7]) by submission; Sun, 08 Nov 2026 07:03:41 -0500",
		"From: shop <shop@" + testBurnerReplyDomain + ">",
		"To: Store <orders@store.example>",
		"Subject: Re: your order",
		"Date: Sun, 08 Nov 2026 07:03:41 -0500",
		"Message-ID: <client-made@laptop.home.example>",
		"User-Agent: A Mail Client 1.2",
		"X-Mailer: A Mail Client",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"Thanks, it arrived.",
		"",
	}, "\r\n"))
}

// The reply under BURNER's rules, assembled and signed by signer as §14's sender does.
func testBurnerReplySigned(t *testing.T, signer sidecar.SmtpDkimSigner, now time.Time) []byte {
	t.Helper()
	ruled, err := sidecar.NewMailBurnerHeaders(nil).Apply(testBurnerReplyDraft(), &sidecar.MailBurnerHeadersArgs{
		MessageId: "aaaaaaaaaaaaaaaaaaaaaaaaaa@" + testBurnerReplyDomain,
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sidecar.AssembleSmtpMessage(&sidecar.SmtpAssembleArgs{
		Message:          ruled,
		HeaderFromDomain: testBurnerReplyDomain,
		MessageIdDomain:  testBurnerReplyDomain,
		Flags:            sidecar.SmtpFlagBurner,
		Now:              now,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := sidecar.SmtpDkimSign(wire, &sidecar.SmtpDkimSignArgs{
		Signer: signer,
		Issued: &sidecar.SmtpIssuedHeaders{
			XUrRef:     "1.ljnfuws2ljnfuws2ljnfuws2ljnfuws2li",
			FeedbackId: "n:p:gmztgmztgmztgmztgmztgmztgm:urnetwork",
		},
		SignTime:      testBurnerReplySignTime,
		ExpireTimeout: sidecar.DefaultSmtpSenderSettings().DkimExpireTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// A receiver's world in which both networks publish §12.7's policy and SPF for their bounce domains, and the replying
// burner its selector.
func newTestBurnerReplyWorld(t *testing.T) (*mailAuthCheckWorld, *testBurnerReplySigner) {
	t.Helper()
	world := newMailAuthCheckWorld(t)
	for _, name := range []string{testBurnerReplyRoot, "acme." + testBurnerReplyRoot, "other." + testBurnerReplyRoot} {
		world.zone.AddTxt("_dmarc."+name, testBurnerReplyPolicy)
	}
	world.zone.AddTxt(testBurnerReplyBounce, "v=spf1 ip4:192.0.2.0/24 -all")
	signer := &testBurnerReplySigner{selector: testBurnerReplySelector, domain: testBurnerReplyDomain, key: testVerifyKey()}
	world.zone.AddTxt(sidecartest.MailDkimKeyName(signer.selector, signer.domain), signer.keyRecord(t))
	return world, signer
}

// A reply passes strict DMARC under the burner's own selector: DKIM aligned exactly, SPF passing for the bounce
// domain and aligning nothing; and nothing of the device, its client or its timezone is in what was signed.
func TestMailBurnerReplyPassesStrictDmarcUnderItsOwnSelector(t *testing.T) {
	world, signer := newTestBurnerReplyWorld(t)
	signed := testBurnerReplySigned(t, signer, world.clock.Now())
	for _, trace := range []string{"Received:", "laptop.home.example", "203.0.113.7", "User-Agent", "X-Mailer", "-0500", "07:03:41"} {
		if strings.Contains(string(signed), trace) {
			t.Errorf("the signed reply carries %q", trace)
		}
	}
	outcome := world.check(t, testMailAuthInput(signed, testBurnerReplyBounce))
	if outcome.Spf.GetResult() != protocol.SpfVerdict_SPF_PASS || outcome.Spf.GetDomain() != testBurnerReplyBounce {
		t.Errorf("spf %v", outcome.Spf)
	}
	if len(outcome.Dkim) == 0 {
		t.Fatal("no signature was checked")
	}
	for _, result := range outcome.Dkim {
		if result.GetResult() != protocol.DkimVerdict_DKIM_PASS || result.GetDomain() != testBurnerReplyDomain || result.GetSelector() != testBurnerReplySelector {
			t.Errorf("dkim %v", result)
		}
	}
	if outcome.Dmarc.GetResult() != protocol.DmarcVerdict_DMARC_PASS || outcome.Dmarc.GetP() != "reject" || outcome.Dmarc.GetAdkim() != "s" ||
		outcome.Dmarc.GetAlignment() != sidecar.MailDmarcAlignedDkim {
		t.Errorf("dmarc %v", outcome.Dmarc)
	}
}

// Another network's selector passes nothing for this network's burner: signed under its own burner's domain, DKIM
// verifies and aligns only relaxed, which the strict policy does not take; naming this burner's domain, its selector
// has no key there, and under this burner's selector name its key does not verify.
func TestMailBurnerReplyOtherNetworksSelectorFailsStrictDmarc(t *testing.T) {
	world, _ := newTestBurnerReplyWorld(t)
	otherKey := sidecartest.MailDkimRsaKey(2048)
	forged := []byte(strings.Join([]string{
		"From: shop <shop@" + testBurnerReplyDomain + ">",
		"To: Store <orders@store.example>",
		"Subject: Re: your order",
		"Date: Sun, 08 Nov 2026 12:03:00 +0000",
		"Message-ID: <bbbbbbbbbbbbbbbbbbbbbbbbbb@" + testBurnerReplyDomain + ">",
		"",
		"Not the burner's owner.",
		"",
	}, "\r\n"))
	cases := []struct {
		name     string
		domain   string
		selector string
		dkim     protocol.DkimVerdict
	}{
		// its own selector and domain, published: a pass that aligns only under relaxed rules
		{name: "its own domain", domain: testBurnerReplyOther, selector: testBurnerReplyOtherNamed, dkim: protocol.DkimVerdict_DKIM_PASS},
		// this burner's selector name, where this burner's key stands
		{name: "this burner's selector", domain: testBurnerReplyDomain, selector: testBurnerReplySelector, dkim: protocol.DkimVerdict_DKIM_FAIL},
	}
	for _, c := range cases {
		signer, err := sidecartest.NewMailDkimSigner(c.domain, c.selector, sidecartest.MailDkimRsaSha256, otherKey)
		if err != nil {
			t.Fatal(err)
		}
		if c.domain == testBurnerReplyOther {
			world.zone.AddTxt(sidecartest.MailDkimKeyName(c.selector, c.domain), signer.KeyRecord())
		}
		message, err := signer.Sign(forged)
		if err != nil {
			t.Fatal(err)
		}
		outcome := world.check(t, testMailAuthInput(message, "b.other."+testBurnerReplyRoot))
		if len(outcome.Dkim) != 1 || outcome.Dkim[0].GetResult() != c.dkim {
			t.Errorf("%s: dkim %v", c.name, outcome.Dkim)
		}
		if outcome.Dmarc.GetResult() != protocol.DmarcVerdict_DMARC_FAIL || outcome.Dmarc.GetAlignment() != 0 {
			t.Errorf("%s: dmarc %v", c.name, outcome.Dmarc)
		}
	}
	// its own selector name under this burner's domain: no key stands there
	signer, err := sidecartest.NewMailDkimSigner(testBurnerReplyDomain, testBurnerReplyOtherNamed, sidecartest.MailDkimRsaSha256, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	message, err := signer.Sign(forged)
	if err != nil {
		t.Fatal(err)
	}
	outcome := world.check(t, testMailAuthInput(message, "b.other."+testBurnerReplyRoot))
	if len(outcome.Dkim) != 1 || outcome.Dkim[0].GetResult() == protocol.DkimVerdict_DKIM_PASS {
		t.Errorf("a selector with no key: dkim %v", outcome.Dkim)
	}
	if outcome.Dmarc.GetResult() == protocol.DmarcVerdict_DMARC_PASS || outcome.Dmarc.GetAlignment() != 0 {
		t.Errorf("a selector with no key: dmarc %v", outcome.Dmarc)
	}
}
