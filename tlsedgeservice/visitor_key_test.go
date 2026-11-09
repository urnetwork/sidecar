package tlsedgeservice

import (
	"net/netip"
	"testing"
	"time"
)

// A visitor's /64 or /32 and the /48 or /24 above it key alike for every address inside them, an
// IPv4-mapped address keys as its IPv4 address, and no two prefixes share a key.
func TestTlsVisitorKeysPrefixes(t *testing.T) {
	keys := NewTlsVisitorKeys(newTestManualClock())
	capKeys := func(text string) *TlsVisitorCapKeys {
		t.Helper()
		capKeys, ok := keys.CapKeys(netip.MustParseAddr(text))
		if !ok {
			t.Fatalf("%s gave no keys", text)
		}
		return capKeys
	}
	a := capKeys("2001:db8:1:2:aaaa::1")
	sameVisitor := capKeys("2001:db8:1:2:bbbb::2")
	sameAggregate := capKeys("2001:db8:1:3::1")
	otherAggregate := capKeys("2001:db8:2:2::1")
	if a.Visitor != sameVisitor.Visitor || a.Aggregate != sameVisitor.Aggregate {
		t.Fatal("two addresses of one /64 keyed apart")
	}
	if a.Visitor == sameAggregate.Visitor || a.Aggregate != sameAggregate.Aggregate {
		t.Fatal("two /64s of one /48 keyed wrong")
	}
	if a.Aggregate == otherAggregate.Aggregate {
		t.Fatal("two /48s shared a key")
	}

	v4 := capKeys("192.0.2.1")
	mapped := capKeys("::ffff:192.0.2.1")
	if v4.Visitor != mapped.Visitor || v4.Aggregate != mapped.Aggregate {
		t.Fatal("an IPv4-mapped address keyed apart from its IPv4 address")
	}
	sameV4Aggregate := capKeys("192.0.2.200")
	if v4.Visitor == sameV4Aggregate.Visitor || v4.Aggregate != sameV4Aggregate.Aggregate {
		t.Fatal("two /32s of one /24 keyed wrong")
	}
	if v4.Visitor == v4.Aggregate {
		t.Fatal("a /32 and its /24 shared a key")
	}
	if _, ok := keys.CapKeys(netip.Addr{}); ok {
		t.Fatal("no address gave keys")
	}
	if hash := keys.RecordHash(netip.Addr{}); hash != nil {
		t.Fatal("no address gave a record hash")
	}
}

// The record hash is 16 bytes over the /24 or /48, and a UTC day's turn draws new keys: a new
// generation, new cap keys and new record hashes for the same visitor.
func TestTlsVisitorKeysRotateDaily(t *testing.T) {
	clock := newTestManualClock()
	keys := NewTlsVisitorKeys(clock)
	visitor := netip.MustParseAddr("198.51.100.7")
	before, _ := keys.CapKeys(visitor)
	recordBefore := keys.RecordHash(visitor)
	if len(recordBefore) != 16 {
		t.Fatalf("record hash of %d bytes", len(recordBefore))
	}
	if string(recordBefore) != string(keys.RecordHash(netip.MustParseAddr("198.51.100.99"))) {
		t.Fatal("two addresses of one /24 hashed apart")
	}

	// within the day nothing turns
	clock.Advance(11*time.Hour + 59*time.Minute)
	within, _ := keys.CapKeys(visitor)
	if within.Generation != before.Generation || within.Visitor != before.Visitor {
		t.Fatal("the keys turned within a day")
	}
	// the clock starts at noon, so this passes midnight UTC
	clock.Advance(2 * time.Minute)
	after, _ := keys.CapKeys(visitor)
	if after.Generation == before.Generation || after.Visitor == before.Visitor || after.Aggregate == before.Aggregate {
		t.Fatal("a new day kept yesterday's keys")
	}
	if string(keys.RecordHash(visitor)) == string(recordBefore) {
		t.Fatal("a new day kept yesterday's record hash")
	}
}

// The UTC day of a time, before the epoch included.
func TestTlsUtcDay(t *testing.T) {
	for _, c := range []struct {
		at  time.Time
		day int64
	}{
		{at: time.Unix(0, 0), day: 0},
		{at: time.Unix(86399, 0), day: 0},
		{at: time.Unix(86400, 0), day: 1},
		{at: time.Unix(-1, 0), day: -1},
		{at: time.Unix(-86400, 0), day: -1},
		{at: time.Unix(-86401, 0), day: -2},
	} {
		if day := tlsUtcDay(c.at); day != c.day {
			t.Errorf("%v: day %d", c.at, day)
		}
	}
}
