package dnsservice

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestSelfCheckPassesAGoodKeySet(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	keys, err := SelfCheck(view, signing.keySet(), signing.anchors, testSigningNow)
	if err != nil {
		t.Fatal(err)
	}
	if keys.Window() != signing.window || keys.Zsk() != signing.zsk || !keys.NotAfter().Equal(signing.window.NotAfter) {
		t.Errorf("keys %+v", keys)
	}
	// a view of nothing but its apex has every shape asked of the built view instead
	if _, err := SelfCheck(newTestView(t, 1, testApexRows()...), signing.keySet(), signing.anchors, testSigningNow); err != nil {
		t.Errorf("an apex alone: %v", err)
	}
}

// §22.5's four: a key set failing self-check never serves.
func TestSelfCheckRefusesAWrongKsk(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	other := testDnskey(t, testRoot, dns.ZONE|dns.SEP, testP256Key(t, testOtherKeyScalarHex))
	if _, err := SelfCheck(view, signing.keySet(), []*dns.DNSKEY{other}, testSigningNow); !errors.Is(err, ErrDnsSelfCheck) {
		t.Errorf("another KSK as the anchor: %v", err)
	}
	if _, err := SelfCheck(view, signing.keySet(), nil, testSigningNow); !errors.Is(err, ErrDnsSelfCheck) {
		t.Errorf("no anchor: %v", err)
	}
	// the right key, configured as no KSK
	zskShaped := *signing.kskRecord
	zskShaped.Flags = dns.ZONE
	if _, err := SelfCheck(view, signing.keySet(), []*dns.DNSKEY{&zskShaped}, testSigningNow); !errors.Is(err, ErrDnsSelfCheck) {
		t.Errorf("an anchor without the SEP bit: %v", err)
	}
	// signed by the KSK, which the window does not publish
	signing.window = newTestWindow(t, testRoot, signing.window.NotBefore, signing.window.NotAfter, signing.ksk, signing.zskRecord)
	if _, err := SelfCheck(view, signing.keySet(), signing.anchors, testSigningNow); !errors.Is(err, ErrDnsSelfCheck) {
		t.Errorf("a KSK the window leaves out: %v", err)
	}
}

func TestSelfCheckRefusesAZskNotInTheWindow(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	keySet := &DnsKeySet{Window: signing.window, Zsk: testP256Key(t, testOtherKeyScalarHex)}
	_, err := SelfCheck(view, keySet, signing.anchors, testSigningNow)
	if !errors.Is(err, ErrDnsSelfCheck) || !errors.Is(err, ErrDnsKeyRefused) {
		t.Errorf("another ZSK: %v", err)
	}
	// the ZSK published as a key-signing key
	asKsk := testDnskey(t, testRoot, dns.ZONE|dns.SEP, signing.zsk)
	signing.window = newTestWindow(t, testRoot, signing.window.NotBefore, signing.window.NotAfter, signing.ksk, signing.kskRecord, asKsk)
	if _, err := SelfCheck(view, signing.keySet(), signing.anchors, testSigningNow); !errors.Is(err, ErrDnsKeyRefused) {
		t.Errorf("the ZSK with the SEP bit: %v", err)
	}
	if _, err := SelfCheck(view, &DnsKeySet{Window: signing.window}, signing.anchors, testSigningNow); !errors.Is(err, ErrDnsKeyRefused) {
		t.Errorf("no ZSK: %v", err)
	}
	if _, err := SelfCheck(view, &DnsKeySet{Zsk: signing.zsk}, signing.anchors, testSigningNow); !errors.Is(err, ErrDnsKeyRefused) {
		t.Errorf("no window: %v", err)
	}
}

func TestSelfCheckRefusesAWindowThatIsNotCurrent(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	for _, now := range []time.Time{signing.window.NotAfter, signing.window.NotAfter.Add(time.Hour), signing.window.NotBefore.Add(-time.Second)} {
		if _, err := SelfCheck(view, signing.keySet(), signing.anchors, now); !errors.Is(err, ErrDnsSelfCheck) {
			t.Errorf("at %v: %v", now, err)
		}
	}
	// a window whose RRSIG has expired though its own dates say otherwise
	expired := newTestWindow(t, testRoot, testSigningNow.Add(-48*time.Hour), testSigningNow.Add(-time.Hour), signing.ksk, signing.kskRecord, signing.zskRecord)
	expired.NotAfter = signing.window.NotAfter
	if _, err := SelfCheck(view, &DnsKeySet{Window: expired, Zsk: signing.zsk}, signing.anchors, testSigningNow); !errors.Is(err, ErrDnsSelfCheck) {
		t.Errorf("an expired signature: %v", err)
	}
}

func TestSelfCheckRefusesABadSignature(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	// one bit of the KSK's signature over the window flipped
	rrsig, err := dns.NewRR(testRoot + " 3600 IN RRSIG " + signing.window.Rrsigs[0])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(rrsig.(*dns.RRSIG).Signature)
	if err != nil {
		t.Fatal(err)
	}
	signature[5] ^= 1
	rrsig.(*dns.RRSIG).Signature = base64.StdEncoding.EncodeToString(signature)
	tampered := *signing.window
	tampered.Rrsigs = []string{testRdata(rrsig)}
	if _, err := SelfCheck(view, &DnsKeySet{Window: &tampered, Zsk: signing.zsk}, signing.anchors, testSigningNow); !errors.Is(err, ErrDnsSelfCheck) {
		t.Errorf("a tampered window signature: %v", err)
	}
	// a ZSK whose public half is in the window and whose signatures are another key's
	wrong := &DnsKeySet{Window: signing.window, Zsk: wrongSigner{public: signing.zsk.Public(), other: testP256Key(t, testOtherKeyScalarHex)}}
	if _, err := SelfCheck(view, wrong, signing.anchors, testSigningNow); !errors.Is(err, ErrDnsSelfCheck) {
		t.Errorf("answers that do not verify: %v", err)
	}
	// one that cannot sign at all
	failing := &DnsKeySet{Window: signing.window, Zsk: failingSigner{public: signing.zsk.Public()}}
	if _, err := SelfCheck(view, failing, signing.anchors, testSigningNow); !errors.Is(err, ErrDnsSelfCheck) {
		t.Errorf("a ZSK that fails: %v", err)
	}
}

func TestSelfCheckRefusesAViewItCannotServe(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	noSoa := newTestView(t, 100, signingTestRows()[1:]...)
	if _, err := SelfCheck(noSoa, signing.keySet(), signing.anchors, testSigningNow); !errors.Is(err, ErrDnsSelfCheck) {
		t.Errorf("no SOA: %v", err)
	}
	if _, err := SelfCheck(nil, signing.keySet(), signing.anchors, testSigningNow); !errors.Is(err, ErrDnsSelfCheck) {
		t.Errorf("no view: %v", err)
	}
	other := newTestSigning(t, "other.example.")
	if _, err := SelfCheck(newTestView(t, 100, signingTestRows()...), other.keySet(), other.anchors, testSigningNow); !errors.Is(err, ErrDnsKeyRefused) {
		t.Errorf("another root's window: %v", err)
	}
}

// The validator SelfCheck uses refuses each way a reply can be wrong, so a probe cannot pass by
// accident.
func TestVerifySignedReplyRefusesWhatAValidatorWould(t *testing.T) {
	signing := newTestSigning(t, testRoot)
	view := newTestView(t, 100, signingTestRows()...)
	keys := signing.checked(t, view)
	signer := NewSigner(signingTestSettings(t, 1000), newTestClock(testSigningNow), nil)
	answer := func(name string, rrType uint16) (*dns.Msg, dns.Question) {
		query := signedQuery(name, rrType, true)
		return signer.Answer(query, view, keys, signingTestHealthy()), query.Message.Question[0]
	}
	verify := func(reply *dns.Msg, question dns.Question) error {
		return verifyDnsSignedReply(reply, question, true, false, keys, signing.anchors, testSigningNow)
	}

	reply, question := answer("www.net1."+testRoot, dns.TypeA)
	reply.Answer = reply.Answer[:1]
	if verify(reply, question) == nil {
		t.Error("an unsigned RRset passed")
	}
	reply, question = answer("www.net1."+testRoot, dns.TypeA)
	reply.Answer[0].(*dns.A).A[3] ^= 1
	if verify(reply, question) == nil {
		t.Error("changed data passed")
	}
	reply, question = answer("www.net1."+testRoot, dns.TypeA)
	reply.Answer[1].(*dns.RRSIG).Labels -= 1
	if verify(reply, question) == nil {
		t.Error("a wildcard's labels passed")
	}
	reply, question = answer("www.net1."+testRoot, dns.TypeA)
	if err := verifyDnsSignedReply(reply, question, true, false, keys, signing.anchors, testSigningNow.Add(10*24*time.Hour)); err == nil {
		t.Error("an expired signature passed")
	}
	reply, question = answer("www.net1."+testRoot, dns.TypeA)
	reply.Ns = append(reply.Ns, reply.Answer[1])
	if verify(reply, question) == nil {
		t.Error("a signature over nothing passed")
	}
	reply, question = answer("nosuch."+testRoot, dns.TypeA)
	reply.Ns[2].(*dns.NSEC).NextDomain = "z." + testRoot
	if verify(reply, question) == nil {
		t.Error("an NSEC covering other names passed")
	}
	reply, question = answer("nosuch."+testRoot, dns.TypeA)
	reply.Rcode = dns.RcodeNameError
	if verify(reply, question) == nil {
		t.Error("NXDOMAIN without CO passed")
	}
	reply, question = answer("www.net1."+testRoot, dns.TypeTXT)
	reply.Ns[2].(*dns.NSEC).TypeBitMap = []uint16{dns.TypeA, dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC}
	if verify(reply, question) == nil {
		t.Error("an empty answer naming its own type passed")
	}
	reply, question = answer("www.net1."+testRoot, dns.TypeTXT)
	reply.Ns = reply.Ns[:2]
	if verify(reply, question) == nil {
		t.Error("a denial with no NSEC passed")
	}
	reply, question = answer(testRoot, dns.TypeDNSKEY)
	if err := verifyDnsSignedReply(reply, question, true, false, keys, nil, testSigningNow); err == nil {
		t.Error("a DNSKEY RRset with no anchor passed")
	}
	if verifyDnsSignedReply(nil, question, true, false, keys, signing.anchors, testSigningNow) == nil {
		t.Error("no reply passed")
	}
}
