package dnsservice

import (
	"strconv"
	"testing"

	"github.com/miekg/dns"
)

// What a signed answer costs on one core, from the cache and fresh. The fresh number is what sets
// signatures_per_second on a real host (§12.6), which is External: this host's number is not that one.
func BenchmarkSignedAnswer(b *testing.B) {
	signing := newTestSigning(b, testRoot)
	view := newTestView(b, 100, signingTestRows()...)
	keys := signing.checked(b, view)
	signer := NewSigner(signingTestSettings(b, 1000*1000*1000), newTestClock(testSigningNow), nil)
	healthy := signingTestHealthy()
	query := signedQuery("www.net1."+testRoot, dns.TypeA, false)
	signer.Answer(query, view, keys, healthy)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		signer.Answer(query, view, keys, healthy)
	}
}

// Each answer a name nothing has asked for, under the wildcard: one fresh signature every time, which
// a random-name flood forces.
func BenchmarkSignedAnswerFresh(b *testing.B) {
	signing := newTestSigning(b, testRoot)
	view := newTestView(b, 100, signingTestRows()...)
	keys := signing.checked(b, view)
	signer := NewSigner(signingTestSettings(b, 1000*1000*1000), newTestClock(testSigningNow), nil)
	healthy := signingTestHealthy()
	queries := make([]*DnsQuery, b.N)
	for index := range queries {
		queries[index] = signedQuery("r"+strconv.Itoa(index)+".net1."+testRoot, dns.TypeA, false)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for _, query := range queries {
		signer.Answer(query, view, keys, healthy)
	}
}

// A compact denial for a name nothing has asked for: one fresh NSEC signature, the SOA's cached.
func BenchmarkSignedDenialFresh(b *testing.B) {
	signing := newTestSigning(b, testRoot)
	view := newTestView(b, 100, signingTestRows()...)
	keys := signing.checked(b, view)
	signer := NewSigner(signingTestSettings(b, 1000*1000*1000), newTestClock(testSigningNow), nil)
	queries := make([]*DnsQuery, b.N)
	for index := range queries {
		queries[index] = signedQuery("r"+strconv.Itoa(index)+"."+testRoot, dns.TypeA, false)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for _, query := range queries {
		signer.Answer(query, view, keys, nil)
	}
}
