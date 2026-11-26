package controller

// Operation keys (BAL-M12-03; D-BAL-14): each derivation fixed by a vector, the UUIDv5 itself RFC 9562's, a search's
// attempts distinct in one minute and timed to it, an interval and an egress hour timed to their slots' starts, a
// refund's key the charge's alone, and a call's key random and never a derived one's version.

import (
	"errors"
	"testing"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// An id whose bytes count up from first.
func testOpKeyId(first byte) operator.Id {
	var id operator.Id
	for i := range id {
		id[i] = first + byte(i)
	}
	return id
}

// One derivation's pinned key and start.
type testOpKeyVector struct {
	name  string
	key   string
	start time.Time
	got   func() (operator.Id, time.Time, error)
}

// Each derivation's key and time, pinned: a change to the namespace or a layout fails here, since it would let an
// operation already booked be booked again.
func TestComputeOpKeyVectors(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	at := time.Date(2026, 11, 25, 13, 47, 31, 500, time.UTC)
	minute := time.Date(2026, 11, 25, 13, 47, 0, 0, time.UTC)
	search := func(attempt int16) func() (operator.Id, time.Time, error) {
		return func() (operator.Id, time.Time, error) {
			return ComputeOpKeyForSearch(settings, testOpKeyId(0x10), testOpKeyId(0x40), attempt, at)
		}
	}
	vectors := []testOpKeyVector{
		{name: "search attempt 1", key: "5b512e34-600d-5efd-b34d-dd6b12f096df", start: minute, got: search(1)},
		{name: "search attempt 2", key: "70184430-1ced-529f-abe7-2f5b3a6bfef4", start: minute, got: search(2)},
		{name: "search attempt 3", key: "5090f219-b92e-5cfa-85df-2414f3be78a4", start: minute, got: search(3)},
		{
			name: "interval", key: "3c63588c-5c3c-5d13-8d1c-439593a02587", start: time.Date(2026, 11, 25, 13, 40, 0, 0, time.UTC),
			got: func() (operator.Id, time.Time, error) {
				return ComputeOpKeyForInterval(settings, testOpKeyId(0x70), 3, at)
			},
		},
		{
			name: "egress hour", key: "a0eb2828-357a-5313-9573-fde8cc22558b", start: time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC),
			got: func() (operator.Id, time.Time, error) {
				return ComputeOpKeyForEgressHour(settings, testOpKeyId(0x70), 3, at)
			},
		},
		{
			name: "refund", key: "c1de57b6-b0c2-5c9d-8e32-22f1fe595717",
			got: func() (operator.Id, time.Time, error) {
				return ComputeOpKeyForRefund(testOpKeyId(0xa0)), time.Time{}, nil
			},
		},
		{
			name: "adjustment", key: "02205c34-120f-5a42-9bf3-369aaedf6f50",
			got: func() (operator.Id, time.Time, error) {
				return ComputeOpKeyForAdjustment(testOpKeyId(0xd0), 2), time.Time{}, nil
			},
		},
	}
	seen := map[operator.Id]string{}
	for _, vector := range vectors {
		key, start, err := vector.got()
		if err != nil {
			t.Fatalf("%s: %v", vector.name, err)
		}
		if key.String() != vector.key {
			t.Errorf("%s's key is %s, want %s", vector.name, key, vector.key)
		}
		if !start.Equal(vector.start) {
			t.Errorf("%s is timed to %v, want %v", vector.name, start, vector.start)
		}
		// a version-5 UUID of RFC 9562's variant
		if key[6]>>4 != 5 || key[8]>>6 != 2 {
			t.Errorf("%s's key %s is no UUIDv5", vector.name, key)
		}
		if other, ok := seen[key]; ok {
			t.Errorf("%s and %s share a key", vector.name, other)
		}
		seen[key] = vector.name
		// the same inputs derive the same key again
		again, _, _ := vector.got()
		if again != key {
			t.Errorf("%s derives two keys", vector.name)
		}
	}
}

// RFC 9562 Appendix A.4: www.example.com in the DNS namespace.
func TestComputeUuidV5MatchesTheRfc(t *testing.T) {
	dns := operator.Id{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	if got := computeUuidV5(dns, []byte("www.example.com")); got.String() != "2ed6657d-e927-568b-95e1-2665a8aea6a2" {
		t.Errorf("UUIDv5 gives %s", got)
	}
}

// A search's attempts 1 to 3 in one minute are three keys, each timed to that minute, and the same attempt anywhere in
// the minute is one key; another minute's attempt is still the same request's, so its key does not move, only its
// time.
func TestComputeOpKeySearchAttemptsAreDistinctInOneMinute(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	networkId, requestId := testOpKeyId(0x10), testOpKeyId(0x40)
	minute := time.Date(2026, 11, 25, 23, 59, 0, 0, time.UTC)
	keys := map[operator.Id]bool{}
	for attempt := int16(1); attempt <= 3; attempt += 1 {
		early, earlyStart, err := ComputeOpKeyForSearch(settings, networkId, requestId, attempt, minute.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		late, lateStart, err := ComputeOpKeyForSearch(settings, networkId, requestId, attempt, minute.Add(59*time.Second+999*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		if early != late || !earlyStart.Equal(minute) || !lateStart.Equal(minute) {
			t.Errorf("attempt %d: %s at %v and %s at %v within one minute", attempt, early, earlyStart, late, lateStart)
		}
		keys[early] = true
	}
	if len(keys) != 3 {
		t.Errorf("three attempts in one minute give %d keys", len(keys))
	}
	// another network's same request id and attempt is another key
	other, _, _ := ComputeOpKeyForSearch(settings, testOpKeyId(0x11), requestId, 1, minute)
	if keys[other] {
		t.Error("two networks' searches share a key")
	}
}

// A refund's key is the refunded charge's alone, so a retry at any time, past UTC midnight included, meets one row;
// two charges' refunds are two keys.
func TestComputeOpKeyRefundIsTheChargesAtAnyTime(t *testing.T) {
	chargeId := testOpKeyId(0xa0)
	if ComputeOpKeyForRefund(chargeId) != ComputeOpKeyForRefund(chargeId) {
		t.Error("one charge's refund derives two keys")
	}
	if ComputeOpKeyForRefund(chargeId) == ComputeOpKeyForRefund(testOpKeyId(0xa1)) {
		t.Error("two charges' refunds share a key")
	}
	// a refund's key is never the charge's own, nor an adjustment's of the same bytes
	if ComputeOpKeyForRefund(chargeId) == chargeId || ComputeOpKeyForRefund(chargeId) == ComputeOpKeyForAdjustment(chargeId, 0) {
		t.Error("a refund's key meets another kind's")
	}
}

// An interval's key moves with its slot on the 10-minute grid and with its incarnation, an egress hour's with its hour,
// and each is timed to its slot's start, UTC-aligned.
func TestComputeOpKeyIntervalAndHourFollowTheirGrid(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	enclaveId := testOpKeyId(0x70)
	start := time.Date(2026, 11, 25, 13, 50, 0, 0, time.UTC)
	first, firstStart, _ := ComputeOpKeyForInterval(settings, enclaveId, 1, start)
	same, sameStart, _ := ComputeOpKeyForInterval(settings, enclaveId, 1, start.Add(9*time.Minute+59*time.Second))
	next, nextStart, _ := ComputeOpKeyForInterval(settings, enclaveId, 1, start.Add(10*time.Minute))
	incarnation, _, _ := ComputeOpKeyForInterval(settings, enclaveId, 2, start)
	if first != same || !firstStart.Equal(start) || !sameStart.Equal(start) {
		t.Error("one slot gives two keys or another start")
	}
	if first == next || !nextStart.Equal(start.Add(10*time.Minute)) {
		t.Error("the next slot does not move the key or its start")
	}
	if first == incarnation {
		t.Error("two incarnations share an interval's key")
	}
	hour, hourStart, _ := ComputeOpKeyForEgressHour(settings, enclaveId, 1, start)
	if hour == first || !hourStart.Equal(time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC)) {
		t.Error("an egress hour's key meets an interval's, or is timed to another start")
	}
}

// Times before the epoch, negative attempts and incarnations, and a grid the settings do not give are refused.
func TestComputeOpKeyRefusesWhatHasNoSlot(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	before := time.Date(1969, 12, 31, 23, 0, 0, 0, time.UTC)
	now := time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC)
	if _, _, err := ComputeOpKeyForSearch(settings, testOpKeyId(1), testOpKeyId(2), -1, now); !errors.Is(err, ErrComputeOpKeyArgs) {
		t.Errorf("a negative attempt: %v", err)
	}
	if _, _, err := ComputeOpKeyForInterval(settings, testOpKeyId(1), -1, now); !errors.Is(err, ErrComputeOpKeyArgs) {
		t.Errorf("a negative incarnation: %v", err)
	}
	if _, _, err := ComputeOpKeyForEgressHour(settings, testOpKeyId(1), 1, before); !errors.Is(err, ErrComputeOpKeyArgs) {
		t.Errorf("a time before the epoch: %v", err)
	}
	broken := model.DefaultComputeLedgerSettings()
	broken.EnclaveInterval = 0
	if _, _, err := ComputeOpKeyForInterval(broken, testOpKeyId(1), 1, now); !errors.Is(err, ErrComputeOpKeyArgs) {
		t.Errorf("a grid of zero: %v", err)
	}
}

// A call's key is random, a version-4 UUID, so no call's key is ever a derived one's.
func TestComputeOpKeyForCallIsRandomVersionFour(t *testing.T) {
	seen := map[operator.Id]bool{}
	for i := 0; i < 64; i += 1 {
		key, err := ComputeOpKeyForCall()
		if err != nil {
			t.Fatal(err)
		}
		if key[6]>>4 != 4 || key[8]>>6 != 2 {
			t.Fatalf("%s is no UUIDv4", key)
		}
		if seen[key] {
			t.Fatalf("%s drawn twice", key)
		}
		seen[key] = true
	}
}
