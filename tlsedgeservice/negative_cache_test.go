package tlsedgeservice

import (
	"fmt"
	"testing"
	"time"
)

// An entry refuses its key for exactly the ttl, and the key is free from then on.
func TestTlsNegativeCacheExpiresAtTtl(t *testing.T) {
	clock := newTestManualClock()
	cache := newTlsNegativeCache(30*time.Second, 16, clock)
	cache.Add("tls/443/blog", 443, []string{"h2", "http/1.1"}, TlsNegativeNoListener)
	clock.Advance(30*time.Second - time.Nanosecond)
	if reason, ok := cache.Lookup("tls/443/blog", 443, []string{"h2", "http/1.1"}); !ok || reason != TlsNegativeNoListener {
		t.Fatalf("lookup before the ttl: %q, %v", reason, ok)
	}
	clock.Advance(time.Nanosecond)
	if _, ok := cache.Lookup("tls/443/blog", 443, []string{"h2", "http/1.1"}); ok {
		t.Fatal("an entry outlived its ttl")
	}
}

// The ALPN set is part of the key and order-free: a scanner's bogus id caches only its own set, so a
// visitor offering a served id still reaches Find (reading 18), and the same set in another order hits.
func TestTlsNegativeCacheAlpnMismatchNeverBlocks(t *testing.T) {
	cache := newTlsNegativeCache(30*time.Second, 16, newTestManualClock())
	cache.Add("tls/443/blog", 443, []string{"bogus"}, TlsNegativeNoListener)
	if _, ok := cache.Lookup("tls/443/blog", 443, []string{"h2", "http/1.1"}); ok {
		t.Fatal("a bogus id's entry blocked a visitor offering served ids")
	}
	if _, ok := cache.Lookup("tls/443/blog", 443, []string{}); ok {
		t.Fatal("a bogus id's entry blocked a visitor offering no ALPN")
	}
	if _, ok := cache.Lookup("tls/443/blog", 8443, []string{"bogus"}); ok {
		t.Fatal("the entry blocked another port")
	}
	cache.Add("tls/443/shop", 443, []string{"http/1.1", "h2"}, TlsNegativeDenied)
	if reason, ok := cache.Lookup("tls/443/shop", 443, []string{"h2", "http/1.1"}); !ok || reason != TlsNegativeDenied {
		t.Fatalf("the same set in another order missed: %q, %v", reason, ok)
	}
	// ids written with their lengths, so a set never reads as another set's bytes
	cache.Add("tls/443/api", 443, []string{"ab", "c"}, TlsNegativeNoListener)
	if _, ok := cache.Lookup("tls/443/api", 443, []string{"a", "bc"}); ok {
		t.Fatal("two sets with the same joined bytes shared an entry")
	}
}

// Only no_listener and denied are cached.
func TestTlsNegativeCacheOnlyTwoReasons(t *testing.T) {
	cache := newTlsNegativeCache(30*time.Second, 16, newTestManualClock())
	cache.Add("tls/443/blog", 443, nil, TlsNegativeReason("busy"))
	if _, ok := cache.Lookup("tls/443/blog", 443, nil); ok || cache.Count() != 0 {
		t.Fatal("a busy answer was cached")
	}
}

// A scan of distinct names never holds more than the bound, the oldest going first, and what it
// evicts is counted.
func TestTlsNegativeCacheBoundedUnderScan(t *testing.T) {
	clock := newTestManualClock()
	cache := newTlsNegativeCache(30*time.Second, 64, clock)
	evictedCount := 0
	for index := range 10000 {
		evictedCount += cache.Add(fmt.Sprintf("tls/443/host%d", index), 443, []string{"h2"}, TlsNegativeNoListener)
		if 64 < cache.Count() {
			t.Fatalf("%d entries past a bound of 64", cache.Count())
		}
		clock.Advance(time.Millisecond)
	}
	if evictedCount != 10000-64 {
		t.Fatalf("%d evicted", evictedCount)
	}
	if _, ok := cache.Lookup("tls/443/host0", 443, []string{"h2"}); ok {
		t.Fatal("the oldest entry survived the bound")
	}
	if _, ok := cache.Lookup("tls/443/host9999", 443, []string{"h2"}); !ok {
		t.Fatal("the newest entry was evicted")
	}
	if len(cache.queue) > 2*64 {
		t.Fatalf("the queue holds %d items", len(cache.queue))
	}

	// expired entries leave first and are not counted as evictions
	clock.Advance(30 * time.Second)
	if evicted := cache.Add("tls/443/after", 443, nil, TlsNegativeDenied); evicted != 0 || cache.Count() != 1 {
		t.Fatalf("after expiry: %d evicted, %d held", evicted, cache.Count())
	}
}
