package sidecartest

import (
	"testing"

	"github.com/miekg/dns"
)

// R-DNS-7's path on T2 (DNS-M5-13): certs' challenge through POST acme-challenge reaches both edges at the
// serial the block answered, with no tick of the clock, so within the feed's hold: the raise wakes it.
// Its removal reaches both the same way.
func TestDnsChallengeReachesBothEdgesWithinTheHold(t *testing.T) {
	net := newTestNet(t)
	harness := newTestDnsHarness(t, net, "dns")
	name := "net1." + harness.Root()
	owner := "_acme-challenge." + name
	serial, err := harness.PutChallenge(t.Context(), harness.Root(), "*."+name, []string{"wildcard-digest", "apex-digest"})
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.AwaitServed(t.Context(), harness.Root(), serial); err != nil {
		t.Fatal(err)
	}
	for _, ns := range harness.Settings().Ns {
		rcode, rdatas := dnsHarnessTestAnswer(t, harness, ns, owner, dns.TypeTXT)
		if rcode != dns.RcodeSuccess || len(rdatas) != 2 {
			t.Errorf("%s: %s %v", ns, dns.RcodeToString[rcode], rdatas)
		}
	}
	removed, err := harness.PutChallenge(t.Context(), harness.Root(), name, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.AwaitServed(t.Context(), harness.Root(), removed); err != nil {
		t.Fatal(err)
	}
	for _, ns := range harness.Settings().Ns {
		if _, rdatas := dnsHarnessTestAnswer(t, harness, ns, owner, dns.TypeTXT); len(rdatas) != 0 {
			t.Errorf("%s still answers %v", ns, rdatas)
		}
	}
}
