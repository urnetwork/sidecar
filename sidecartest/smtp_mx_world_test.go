//go:build !sidecar_http

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
)

// A validator written on miekg/dns, which MxWorld signs with: what a chain from MxWorld must pass, and
// fail, before SMTP-M9-05's own parser is held to it. It checks every RRSIG under a DNSKEY it has
// already authenticated, every DS against the key it names, and the root's DNSKEY against the anchor.
func testValidateChain(chain []byte, anchorDs []byte, now time.Time) ([]dns.RR, error) {
	anchor, _, err := dns.UnpackRR(anchorDs, 0)
	if err != nil {
		return nil, err
	}
	var records []dns.RR
	for offset := 0; offset < len(chain); {
		rr, next, err := dns.UnpackRR(chain, offset)
		if err != nil {
			return nil, fmt.Errorf("at %d: %v", offset, err)
		}
		records = append(records, rr)
		offset = next
	}
	type setKey struct {
		name   string
		rrtype uint16
	}
	sets := map[setKey][]dns.RR{}
	signatures := map[setKey][]*dns.RRSIG{}
	var order []setKey
	for _, rr := range records {
		if signature, ok := rr.(*dns.RRSIG); ok {
			key := setKey{name: dns.CanonicalName(signature.Hdr.Name), rrtype: signature.TypeCovered}
			signatures[key] = append(signatures[key], signature)
			continue
		}
		key := setKey{name: dns.CanonicalName(rr.Header().Name), rrtype: rr.Header().Rrtype}
		if _, ok := sets[key]; !ok {
			order = append(order, key)
		}
		sets[key] = append(sets[key], rr)
	}
	// zones whose DNSKEY RRset is authenticated, from the root down
	trusted := map[string][]*dns.DNSKEY{}
	verify := func(key setKey) error {
		for _, signature := range signatures[key] {
			if !signature.ValidityPeriod(now) {
				continue
			}
			for _, dnskey := range trusted[dns.CanonicalName(signature.SignerName)] {
				if signature.Verify(dnskey, sets[key]) == nil {
					return nil
				}
			}
		}
		return fmt.Errorf("%s %s: no signature verifies", key.name, dns.TypeToString[key.rrtype])
	}
	selfSigned := func(zone string) error {
		var keys []*dns.DNSKEY
		for _, rr := range sets[setKey{name: zone, rrtype: dns.TypeDNSKEY}] {
			keys = append(keys, rr.(*dns.DNSKEY))
		}
		for _, signature := range signatures[setKey{name: zone, rrtype: dns.TypeDNSKEY}] {
			for _, dnskey := range keys {
				if signature.ValidityPeriod(now) && signature.Verify(dnskey, sets[setKey{name: zone, rrtype: dns.TypeDNSKEY}]) == nil {
					return nil
				}
			}
		}
		return fmt.Errorf("%s DNSKEY: not self-signed", zone)
	}
	dsMatches := func(zone string, dsSet []dns.RR) bool {
		for _, rr := range sets[setKey{name: zone, rrtype: dns.TypeDNSKEY}] {
			for _, ds := range dsSet {
				want := rr.(*dns.DNSKEY).ToDS(ds.(*dns.DS).DigestType)
				if want != nil && strings.EqualFold(want.Digest, ds.(*dns.DS).Digest) && want.KeyTag == ds.(*dns.DS).KeyTag {
					return true
				}
			}
		}
		return false
	}
	if !dsMatches(".", []dns.RR{anchor}) {
		return nil, errors.New("the root's DNSKEY does not match the anchor")
	}
	if err := selfSigned("."); err != nil {
		return nil, err
	}
	for _, rr := range sets[setKey{name: ".", rrtype: dns.TypeDNSKEY}] {
		trusted["."] = append(trusted["."], rr.(*dns.DNSKEY))
	}
	// walk down: a zone's DS verifies under its parent, matches its DNSKEY, which signs itself
	for changed := true; changed; {
		changed = false
		for key, dsSet := range sets {
			if key.rrtype != dns.TypeDS || trusted[key.name] != nil {
				continue
			}
			if verify(key) != nil {
				continue
			}
			if !dsMatches(key.name, dsSet) {
				return nil, fmt.Errorf("%s: no DNSKEY matches its DS", key.name)
			}
			if err := selfSigned(key.name); err != nil {
				return nil, err
			}
			for _, rr := range sets[setKey{name: key.name, rrtype: dns.TypeDNSKEY}] {
				trusted[key.name] = append(trusted[key.name], rr.(*dns.DNSKEY))
			}
			changed = true
		}
	}
	var answers []dns.RR
	for _, key := range order {
		if key.rrtype == dns.TypeDNSKEY || key.rrtype == dns.TypeDS {
			continue
		}
		if err := verify(key); err != nil {
			return nil, err
		}
		answers = append(answers, sets[key]...)
	}
	return answers, nil
}

func testMxWorld(t *testing.T) *MxWorld {
	t.Helper()
	world, err := NewMxWorld(nil)
	if err != nil {
		t.Fatal(err)
	}
	return world
}

func TestMxWorldsSignedChainValidatesUnderItsAnchor(t *testing.T) {
	world := testMxWorld(t)
	mx, err := NewScriptedMx(testMxHost, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := world.AddZone("mail.example", nil); err != nil {
		t.Fatal(err)
	}
	world.SetMx("mail.example", &sidecar.SmtpMxHost{Preference: 10, Host: testMxHost})
	world.AddMx(testMxHost, testMxAddress, mx, MxTlsaFor(mx.Certificate()))
	chain, err := world.Chain("mail.example", testMxHost)
	if err != nil {
		t.Fatal(err)
	}
	answers, err := testValidateChain(chain, world.TrustAnchorDs(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var mxSeen, tlsaSeen bool
	for _, rr := range answers {
		switch record := rr.(type) {
		case *dns.MX:
			mxSeen = record.Mx == testMxHost+"."
		case *dns.TLSA:
			tlsaSeen = record.Usage == 3 && record.Selector == 1 && record.MatchingType == 1
		}
	}
	if !mxSeen || !tlsaSeen {
		t.Errorf("answers %v", answers)
	}

	// another world's anchor takes nothing from this one
	other := testMxWorld(t)
	if _, err := testValidateChain(chain, other.TrustAnchorDs(), time.Now()); err == nil {
		t.Error("a chain validated under another root")
	}
	// and a chain is good only within its signatures' validity
	if _, err := testValidateChain(chain, world.TrustAnchorDs(), time.Now().Add(31*24*time.Hour)); err == nil {
		t.Error("a chain validated past its signatures")
	}
}

func TestMxWorldsBrokenChainsFailToValidate(t *testing.T) {
	for _, c := range []struct {
		name    string
		options *MxWorldZoneOptions
	}{
		{name: "an expired signature", options: &MxWorldZoneOptions{ExpiredSignatures: true}},
		{name: "an unpublished key", options: &MxWorldZoneOptions{WrongKey: true}},
		{name: "a broken DS", options: &MxWorldZoneOptions{BrokenDs: true}},
		{name: "an unsigned delegation", options: &MxWorldZoneOptions{Unsigned: true}},
	} {
		world := testMxWorld(t)
		if err := world.AddZone("mail.example", c.options); err != nil {
			t.Fatal(err)
		}
		world.SetMx("mail.example", &sidecar.SmtpMxHost{Preference: 10, Host: testMxHost})
		world.AddMx(testMxHost, testMxAddress, nil, &sidecar.SmtpTlsaRecord{Usage: 3, Selector: 1, MatchingType: 1, Data: make([]byte, 32)})
		chain, err := world.Chain("mail.example", testMxHost)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if _, err := testValidateChain(chain, world.TrustAnchorDs(), time.Now()); err == nil {
			t.Errorf("%s: validated", c.name)
		}
		// the resolver answers as a validating one would
		answer, err := world.LookupMx(context.Background(), "mail.example")
		if c.options.Unsigned {
			if err != nil || answer.Secure || answer.Chain != nil {
				t.Errorf("%s: %+v, %v", c.name, answer, err)
			}
		} else if !errors.Is(err, sidecar.ErrSmtpMxBogus) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// A host with no TLSA in a signed zone: the chain proves the absence by NSEC3, so a validator tells
// "no TLSA" from an insecure delegation (SMTP-M9-05).
func TestMxWorldDeniesAMissingTlsaByNsec3(t *testing.T) {
	world := testMxWorld(t)
	world.AddZone("mail.example", nil)
	world.SetMx("mail.example", &sidecar.SmtpMxHost{Preference: 10, Host: testMxHost})
	world.AddMx(testMxHost, testMxAddress, nil)
	answer, err := world.LookupTlsa(context.Background(), testMxHost)
	if err != nil || !answer.Secure || len(answer.Records) != 0 {
		t.Fatalf("%+v, %v", answer, err)
	}
	answers, err := testValidateChain(answer.Chain, world.TrustAnchorDs(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	name := "_25._tcp." + testMxHost + "."
	matchesEncloser, coversNextCloser, coversWildcard := false, false, false
	for _, rr := range answers {
		nsec3, ok := rr.(*dns.NSEC3)
		if !ok {
			t.Fatalf("a %s where only the denial belongs", dns.TypeToString[rr.Header().Rrtype])
		}
		matchesEncloser = matchesEncloser || nsec3.Match(testMxHost+".")
		coversNextCloser = coversNextCloser || nsec3.Cover("_tcp."+testMxHost+".")
		coversWildcard = coversWildcard || nsec3.Cover("*."+testMxHost+".")
		if nsec3.Match(name) {
			t.Error("an NSEC3 matches the missing name")
		}
	}
	if !matchesEncloser || !coversNextCloser || !coversWildcard {
		t.Errorf("an incomplete closest encloser proof: %v %v %v", matchesEncloser, coversNextCloser, coversWildcard)
	}
}

func TestMxWorldAnswersAsAValidatingResolver(t *testing.T) {
	world := testMxWorld(t)
	ctx := context.Background()
	world.AddZone("mail.example", nil)
	world.SetMx("mail.example", &sidecar.SmtpMxHost{Preference: 20, Host: "mx2.mail.example"}, &sidecar.SmtpMxHost{Preference: 10, Host: testMxHost})
	world.AddMx(testMxHost, testMxAddress, nil)
	world.AddZone("null.example", nil)
	world.SetNullMx("null.example")
	world.AddZone("implicit.example", nil)
	world.AddMx("implicit.example", netip.MustParseAddr("198.51.100.26"), nil)
	world.AddZone("wild.example", nil)
	world.SetMx("*.wild.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.wild.example"})

	answer, err := world.LookupMx(ctx, "mail.example")
	if err != nil || !answer.Secure || len(answer.Hosts) != 2 || answer.Hosts[0].Host != testMxHost || answer.Hosts[1].Preference != 20 {
		t.Errorf("mx: %+v, %v", answer, err)
	}
	if answer, err := world.LookupMx(ctx, "null.example"); err != nil || !answer.NullMx || len(answer.Hosts) != 0 {
		t.Errorf("null mx: %+v, %v", answer, err)
	}
	// no MX RRset: RFC 5321 §5.1's implicit MX, which the chain proves by NSEC3
	answer, err = world.LookupMx(ctx, "implicit.example")
	if err != nil || answer.NullMx || len(answer.Hosts) != 0 || !answer.Secure {
		t.Errorf("implicit mx: %+v, %v", answer, err)
	} else if _, err := testValidateChain(answer.Chain, world.TrustAnchorDs(), time.Now()); err != nil {
		t.Errorf("implicit mx's denial: %v", err)
	}
	// a wildcard MX expands to the name asked, and its RRSIG still verifies
	answer, err = world.LookupMx(ctx, "a.wild.example")
	if err != nil || len(answer.Hosts) != 1 || answer.Hosts[0].Host != "mx.wild.example" {
		t.Fatalf("wildcard: %+v, %v", answer, err)
	}
	answers, err := testValidateChain(answer.Chain, world.TrustAnchorDs(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(answers, func(rr dns.RR) bool { return rr.Header().Rrtype == dns.TypeMX && rr.Header().Name == "a.wild.example." }) {
		t.Errorf("wildcard answers %v", answers)
	}
	if _, err := world.LookupMx(ctx, "nowhere.example"); !errors.Is(err, sidecar.ErrSmtpMxNoSuchDomain) {
		t.Errorf("no such domain: %v", err)
	}
	if addresses, err := world.LookupAddresses(ctx, testMxHost); err != nil || len(addresses) != 1 || addresses[0] != testMxAddress {
		t.Errorf("addresses %v, %v", addresses, err)
	}
	if _, err := world.DialMx(ctx, testSendingAddress, netip.MustParseAddr("203.0.113.9")); err == nil {
		t.Error("dialed an address with nothing there")
	}
}

func TestMxWorldServesMtaStsPolicies(t *testing.T) {
	world := testMxWorld(t)
	world.AddZone("mail.example", nil)
	policy := "version: STSv1\nmode: enforce\nmx: *.mail.example\nmax_age: 86400\n"
	if err := world.SetMtaStsPolicy("mail.example", "20261108", policy); err != nil {
		t.Fatal(err)
	}
	texts, err := world.LookupTxt(context.Background(), "_mta-sts.mail.example")
	if err != nil || len(texts) != 1 || texts[0] != "v=STSv1; id=20261108" {
		t.Errorf("txt %q, %v", texts, err)
	}
	client := &http.Client{Transport: world.MtaStsTransport()}
	response, err := client.Get("https://mta-sts.mail.example/.well-known/mta-sts.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != policy {
		t.Errorf("%d %q", response.StatusCode, body)
	}
	if response, err := client.Get("https://mta-sts.other.example/.well-known/mta-sts.txt"); err != nil || response.StatusCode != http.StatusNotFound {
		t.Errorf("another domain: %v", err)
	}
}
