package tlsedgeservice

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
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

// A Redis holding only what the fleet key's read and create reach, failing while a test says so. Any other
// call reaches the nil interface and panics, which no test here makes.
type testFleetRedis struct {
	sidecar.Redis

	stateLock sync.Mutex
	values    map[string][]byte
	ttls      map[string]time.Duration
	failing   bool
}

var errTestFleetRedisDown = errors.New("redis down")

func newTestFleetRedis() *testFleetRedis {
	return &testFleetRedis{values: map[string][]byte{}, ttls: map[string]time.Duration{}}
}

func (self *testFleetRedis) setFailing(failing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failing = failing
}

func (self *testFleetRedis) Get(ctx context.Context, key string) ([]byte, bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return nil, false, errTestFleetRedisDown
	}
	value, ok := self.values[key]
	return bytes.Clone(value), ok, nil
}

func (self *testFleetRedis) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return false, errTestFleetRedisDown
	}
	if _, ok := self.values[key]; ok {
		return false, nil
	}
	self.values[key] = bytes.Clone(value)
	self.ttls[key] = ttl
	return true, nil
}

// plan-TLS-visitor-hash-key: the first process makes {vhk}tls:<yyyymmdd> with a 25 h ttl, the next reads it,
// and both then hash a visitor's /24 alike for records and for Find's affinity, the two keys apart, while
// their cap keys stay each its own.
func TestTlsVisitorKeysFleetKeyIsShared(t *testing.T) {
	clock := newTestManualClock()
	redis := newTestFleetRedis()
	first := NewTlsVisitorKeys(clock)
	second := NewTlsVisitorKeys(clock)
	ttl := DefaultTlsEdgeSettings().VisitorKeyTtl
	if result, err := first.Refresh(context.Background(), redis, ttl); err != nil || result != tlsVisitorKeyResultCreated {
		t.Fatalf("the first refresh: %s, %v", result, err)
	}
	if result, err := second.Refresh(context.Background(), redis, ttl); err != nil || result != tlsVisitorKeyResultRead {
		t.Fatalf("the second refresh: %s, %v", result, err)
	}
	name := "{vhk}tls:20261109"
	if value, ok := redis.values[name]; !ok || len(value) != 32 || redis.ttls[name] != 25*time.Hour {
		t.Fatalf("the fleet key: %d bytes, ttl %v", len(value), redis.ttls[name])
	}
	if !first.FleetHeld() || !second.FleetHeld() {
		t.Fatal("a process does not hold the fleet key it read")
	}
	visitor := netip.MustParseAddr("203.0.113.9")
	if !bytes.Equal(first.RecordHash(visitor), second.RecordHash(visitor)) {
		t.Fatal("two processes hash one visitor's records apart")
	}
	affinityKey := first.AffinityKey(visitor)
	if len(affinityKey) != 16 || !bytes.Equal(affinityKey, second.AffinityKey(visitor)) {
		t.Fatal("two processes give one visitor different affinity keys")
	}
	if !bytes.Equal(affinityKey, first.AffinityKey(netip.MustParseAddr("203.0.113.200"))) {
		t.Fatal("two addresses of one /24 have different affinity keys")
	}
	if bytes.Equal(affinityKey, first.AffinityKey(netip.MustParseAddr("198.51.100.9"))) {
		t.Fatal("two /24s share an affinity key")
	}
	if bytes.Equal(affinityKey, first.RecordHash(visitor)) {
		t.Fatal("the affinity key is the record hash")
	}
	v6 := first.AffinityKey(netip.MustParseAddr("2001:db8:1:2::1"))
	if !bytes.Equal(v6, second.AffinityKey(netip.MustParseAddr("2001:db8:1:ffff::9"))) {
		t.Fatal("two addresses of one /48 have different affinity keys")
	}
	if first.AffinityKey(netip.Addr{}) != nil {
		t.Fatal("no address gave an affinity key")
	}
	firstCaps, _ := first.CapKeys(visitor)
	secondCaps, _ := second.CapKeys(visitor)
	if firstCaps.Visitor == secondCaps.Visitor {
		t.Fatal("cap keys are shared across processes")
	}
}

// With Redis unreachable, or holding what nothing here writes, a process hashes under its own key for the
// day, so two processes' affinity keys differ, and once Redis answers they agree again.
func TestTlsVisitorKeysFleetKeyFallsBackToTheProcessKey(t *testing.T) {
	clock := newTestManualClock()
	redis := newTestFleetRedis()
	redis.setFailing(true)
	first := NewTlsVisitorKeys(clock)
	second := NewTlsVisitorKeys(clock)
	ttl := DefaultTlsEdgeSettings().VisitorKeyTtl
	if result, err := first.Refresh(context.Background(), redis, ttl); err == nil || result != tlsVisitorKeyResultFailed {
		t.Fatalf("a refresh on a down Redis: %s, %v", result, err)
	}
	visitor := netip.MustParseAddr("198.51.100.4")
	if first.FleetHeld() || bytes.Equal(first.AffinityKey(visitor), second.AffinityKey(visitor)) {
		t.Fatal("two processes agree with no fleet key")
	}
	if len(first.AffinityKey(visitor)) != 16 || len(first.RecordHash(visitor)) != 16 {
		t.Fatal("the process's own keys gave no hash")
	}

	redis.setFailing(false)
	redis.values["{vhk}tls:20261109"] = []byte("short")
	if result, err := first.Refresh(context.Background(), redis, ttl); !errors.Is(err, errTlsVisitorFleetKeyMalformed) || result != tlsVisitorKeyResultFailed {
		t.Fatalf("a refresh of a malformed key: %s, %v", result, err)
	}
	delete(redis.values, "{vhk}tls:20261109")
	first.Refresh(context.Background(), redis, ttl)
	second.Refresh(context.Background(), redis, ttl)
	if !bytes.Equal(first.AffinityKey(visitor), second.AffinityKey(visitor)) {
		t.Fatal("two processes still disagree once the fleet key is read")
	}
}

// The fleet key serves its own UTC day: past midnight the process's own key serves until a refresh reads the
// new day's key, under its new name, and no hash of yesterday's repeats.
func TestTlsVisitorKeysFleetKeyIsForItsDay(t *testing.T) {
	clock := newTestManualClock()
	redis := newTestFleetRedis()
	keys := NewTlsVisitorKeys(clock)
	ttl := DefaultTlsEdgeSettings().VisitorKeyTtl
	keys.Refresh(context.Background(), redis, ttl)
	visitor := netip.MustParseAddr("192.0.2.77")
	yesterday := keys.AffinityKey(visitor)
	if until := keys.untilNextDay(); until != 12*time.Hour {
		t.Fatalf("%v until the next day", until)
	}
	clock.Advance(12 * time.Hour)
	if keys.FleetHeld() {
		t.Fatal("yesterday's fleet key still serves")
	}
	if bytes.Equal(keys.AffinityKey(visitor), yesterday) {
		t.Fatal("the process's own key for today gave yesterday's affinity")
	}
	if result, err := keys.Refresh(context.Background(), redis, ttl); err != nil || result != tlsVisitorKeyResultCreated {
		t.Fatalf("today's refresh: %s, %v", result, err)
	}
	if _, ok := redis.values["{vhk}tls:20261110"]; !ok {
		t.Fatal("today's key is not under today's name")
	}
	if day, _ := keys.FleetDay(); day != tlsUtcDay(clock.Now()) || !keys.FleetHeld() {
		t.Fatalf("held day %d", day)
	}
	if bytes.Equal(keys.AffinityKey(visitor), yesterday) {
		t.Fatal("today's fleet key gave yesterday's affinity")
	}
}
