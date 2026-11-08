package dnsservice

import (
	"net/netip"
	"testing"
	"time"
)

// RRL settings with a rate of two, no debt and no slip, unless a test says otherwise.
func rrlTestSettings(t *testing.T) *DnsSettings {
	t.Helper()
	settings := answerTestSettings(t)
	settings.Rrl.ResponsesPerSecond = 2
	settings.Rrl.WindowSeconds = 0
	settings.Rrl.Slip = 0
	return settings
}

// How many of count responses to source in class go out at now.
func rrlSent(rrl *dnsRrl, source string, class string, count int, now time.Time) int {
	sent := 0
	for range count {
		if rrl.decide(netip.MustParseAddr(source), class, now) == dnsRrlSend {
			sent += 1
		}
	}
	return sent
}

func TestRrlBucketsIpv4ByPrefix(t *testing.T) {
	rrl := newDnsRrl(rrlTestSettings(t))
	if sent := rrlSent(rrl, "192.0.2.1", DnsRrlClassAnswer, 5, testSigningNow); sent != 2 {
		t.Errorf("one address sent %d", sent)
	}
	if sent := rrlSent(rrl, "192.0.2.200", DnsRrlClassAnswer, 5, testSigningNow); sent != 0 {
		t.Errorf("another address in the /24 sent %d", sent)
	}
	if sent := rrlSent(rrl, "::ffff:192.0.2.9", DnsRrlClassAnswer, 1, testSigningNow); sent != 0 {
		t.Errorf("a mapped address in the /24 sent %d", sent)
	}
	if sent := rrlSent(rrl, "198.51.100.1", DnsRrlClassAnswer, 5, testSigningNow); sent != 2 {
		t.Errorf("another /24 sent %d", sent)
	}
}

func TestRrlBucketsIpv6ByPrefix(t *testing.T) {
	rrl := newDnsRrl(rrlTestSettings(t))
	if sent := rrlSent(rrl, "2001:db8:0:1::1", DnsRrlClassAnswer, 5, testSigningNow); sent != 2 {
		t.Errorf("one address sent %d", sent)
	}
	if sent := rrlSent(rrl, "2001:db8:0:ff:ffff::9", DnsRrlClassAnswer, 5, testSigningNow); sent != 0 {
		t.Errorf("another address in the /56 sent %d", sent)
	}
	if sent := rrlSent(rrl, "2001:db8:0:100::1", DnsRrlClassAnswer, 5, testSigningNow); sent != 2 {
		t.Errorf("the next /56 sent %d", sent)
	}
}

// A flood of denials from a prefix spends its denial bucket, and its answers and errors still go.
func TestRrlCountsClassesApart(t *testing.T) {
	rrl := newDnsRrl(rrlTestSettings(t))
	rrlSent(rrl, "192.0.2.1", DnsRrlClassDenial, 100, testSigningNow)
	if sent := rrlSent(rrl, "192.0.2.1", DnsRrlClassAnswer, 2, testSigningNow); sent != 2 {
		t.Errorf("answers sent %d", sent)
	}
	if sent := rrlSent(rrl, "192.0.2.1", DnsRrlClassError, 2, testSigningNow); sent != 2 {
		t.Errorf("errors sent %d", sent)
	}
	settings := rrlTestSettings(t)
	settings.Rrl.Classes = []string{DnsRrlClassDenial}
	only := newDnsRrl(settings)
	if sent := rrlSent(only, "192.0.2.1", DnsRrlClassAnswer, 100, testSigningNow); sent != 100 {
		t.Errorf("a class not listed sent %d", sent)
	}
	if sent := rrlSent(only, "192.0.2.1", DnsRrlClassDenial, 100, testSigningNow); sent != 2 {
		t.Errorf("a listed class sent %d", sent)
	}
}

// slip: 2 sends every second dropped response out with TC.
func TestRrlSlipsEveryNthDrop(t *testing.T) {
	settings := rrlTestSettings(t)
	settings.Rrl.Slip = 2
	rrl := newDnsRrl(settings)
	source := netip.MustParseAddr("192.0.2.1")
	want := []dnsRrlAction{dnsRrlSend, dnsRrlSend, dnsRrlDrop, dnsRrlSlip, dnsRrlDrop, dnsRrlSlip}
	for index, action := range want {
		if got := rrl.decide(source, DnsRrlClassAnswer, testSigningNow); got != action {
			t.Errorf("response %d: %s, want %s", index, got.label(), action.label())
		}
	}
}

// A bucket earns its rate each second up to a second's worth, and owes at most window_s' worth, so a
// flood stays limited after it stops.
func TestRrlEarnsOnTheClockAndOwesTheWindow(t *testing.T) {
	settings := rrlTestSettings(t)
	settings.Rrl.WindowSeconds = 2
	rrl := newDnsRrl(settings)
	now := testSigningNow
	// two sent, then the balance floors at minus the window's four
	if sent := rrlSent(rrl, "192.0.2.1", DnsRrlClassAnswer, 100, now); sent != 2 {
		t.Fatalf("sent %d", sent)
	}
	// a second earns two: still owing
	now = now.Add(time.Second)
	if sent := rrlSent(rrl, "192.0.2.1", DnsRrlClassAnswer, 1, now); sent != 0 {
		t.Errorf("after a second sent %d", sent)
	}
	// three more seconds earn six from minus three: back to a second's two, never more
	now = now.Add(3 * time.Second)
	if sent := rrlSent(rrl, "192.0.2.1", DnsRrlClassAnswer, 5, now); sent != 2 {
		t.Errorf("after the window sent %d", sent)
	}
	// half a second earns one
	now = now.Add(500 * time.Millisecond)
	if sent := rrlSent(rrl, "192.0.2.1", DnsRrlClassAnswer, 5, now); sent != 0 {
		t.Errorf("half a second after a flood sent %d", sent)
	}
}

// The table never holds more than rrl.buckets, and lets go of a bucket idle past its window.
func TestRrlMemoryIsBounded(t *testing.T) {
	settings := rrlTestSettings(t)
	settings.Rrl.BucketCount = 3
	settings.Rrl.WindowSeconds = 5
	rrl := newDnsRrl(settings)
	for _, source := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1", "2001:db8:1::1"} {
		rrl.decide(netip.MustParseAddr(source), DnsRrlClassAnswer, testSigningNow)
	}
	if held := rrl.bucketsHeld(); held != 3 {
		t.Errorf("held %d", held)
	}
	rrl.decide(netip.MustParseAddr("192.0.2.1"), DnsRrlClassAnswer, testSigningNow.Add(7*time.Second))
	if held := rrl.bucketsHeld(); held != 1 {
		t.Errorf("after the window held %d", held)
	}
	if rrl.decide(netip.Addr{}, DnsRrlClassAnswer, testSigningNow) != dnsRrlSend {
		t.Error("a source with no address was limited")
	}
}
