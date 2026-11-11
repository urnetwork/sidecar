//go:build !sidecar_http

package sidecar

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// §13.6's tls and reading 2's four: a batch or lease names one of these and nothing else.
func TestQuotaMetersAreTheDesignsNames(t *testing.T) {
	meters := map[string]string{
		QuotaMeterTls:   "tls",
		QuotaMeterMx:    "mx",
		QuotaMeterSmtp:  "smtp",
		QuotaMeterEvs:   "evs",
		QuotaMeterRelay: "relay",
	}
	for meter, want := range meters {
		if meter != want {
			t.Errorf("meter %q, want %q", meter, want)
		}
		if !IsQuotaMeter(meter) {
			t.Errorf("%q is not a meter", meter)
		}
	}
	for _, meter := range []string{"", "TLS", "team_seats", "storage"} {
		if IsQuotaMeter(meter) {
			t.Errorf("%q is a meter", meter)
		}
	}
	for _, producer := range []string{"evs", "tlsedge", "mxedge", "smtpedge", "taskworker"} {
		if !IsQuotaProducer(producer) {
			t.Errorf("%q is not a producer", producer)
		}
	}
	for _, producer := range []string{"", "api", "gkm", "EVS"} {
		if IsQuotaProducer(producer) {
			t.Errorf("%q is a producer", producer)
		}
	}
}

// The expected ids are the first 16 bytes of shasum -a 256 over the input bytes, computed outside Go.
func TestNewUsageBatchIdVectors(t *testing.T) {
	counting := [16]byte{}
	for i := range counting {
		counting[i] = byte(i)
	}
	ones := [16]byte{}
	for i := range ones {
		ones[i] = 0xff
	}
	cases := []struct {
		instanceId [16]byte
		windowSeq  uint64
		want       string
	}{
		{instanceId: counting, windowSeq: 0, want: "818638ad150c9042a99f4e43bfd0f1b4"},
		{instanceId: ones, windowSeq: 1, want: "ad4da51042ff800c2f04c4e7206e7b3b"},
		{instanceId: counting, windowSeq: 0x0102030405060708, want: "234db4e93950f6fb9f8f0082da564fea"},
	}
	for _, c := range cases {
		batchId := NewUsageBatchId(c.instanceId, c.windowSeq)
		if got := hex.EncodeToString(batchId[:]); got != c.want {
			t.Errorf("instance %x seq %d: %s, want %s", c.instanceId, c.windowSeq, got, c.want)
		}
	}
}

// The cursors are length-prefixed, so ("ab", "c") and ("a", "bc") hash apart.
func TestNewDropUsageBatchIdVectors(t *testing.T) {
	scanId := connect.Id{}
	for i := range scanId {
		scanId[i] = byte(0x10 + i)
	}
	cases := []struct {
		cursorFrom []byte
		cursorTo   []byte
		want       string
	}{
		{cursorFrom: nil, cursorTo: []byte{0x01}, want: "ec717e8333662901a3432c453f70528f"},
		{cursorFrom: []byte("ab"), cursorTo: []byte("c"), want: "806a0fc0d5c80266a15218012cbf2da2"},
		{cursorFrom: []byte("a"), cursorTo: []byte("bc"), want: "32702112a87cc0e9248ee386ac1831c8"},
	}
	for _, c := range cases {
		batchId := NewDropUsageBatchId(scanId, c.cursorFrom, c.cursorTo)
		if got := hex.EncodeToString(batchId[:]); got != c.want {
			t.Errorf("cursors %q %q: %s, want %s", c.cursorFrom, c.cursorTo, got, c.want)
		}
	}
	// another instance resuming the same range reports the same id
	if NewDropUsageBatchId(scanId, []byte("ab"), []byte("c")) != NewDropUsageBatchId(scanId, []byte("ab"), []byte("c")) {
		t.Error("one range gave two ids")
	}
}

// Each constructor's key resolves to §20.7's row for it.
func TestQuotaRateKeysResolveToTheirRows(t *testing.T) {
	sidecarId := connect.NewId()
	repoId := connect.NewId()
	cases := []struct {
		key             string
		subjectId       connect.Id
		window          QuotaRateWindow
		limitKey        string
		fixedLimit      int64
		refusalLimitKey string
		paced           bool
		classOnly       bool
		tiered          bool
	}{
		{key: QuotaRateKeyClosureUpload(sidecarId), subjectId: sidecarId, window: QuotaRateWindowMinute, fixedLimit: 60, refusalLimitKey: "evs_closure_uploads_per_min", paced: true},
		{key: QuotaRateKeyClosureBytes(sidecarId), subjectId: sidecarId, window: QuotaRateWindowUtcDay, limitKey: "evs_closure_bytes_per_day", refusalLimitKey: "evs_closure_bytes_per_day"},
		{key: QuotaRateKeyErasurePush, window: QuotaRateWindowMinute, fixedLimit: 60, refusalLimitKey: "evs_erasure_pushes_per_min", classOnly: true},
		{key: QuotaRateKeyDrop, window: QuotaRateWindowUtcDay, limitKey: "evs_drops_per_day", refusalLimitKey: "evs_drops_per_day", tiered: true},
		{key: QuotaRateKeyDropPreview(repoId), subjectId: repoId, window: QuotaRateWindowUtcDay, limitKey: "evs_drop_previews_per_day", refusalLimitKey: "evs_drop_previews_per_day"},
		{key: QuotaRateKeyReadReceipt(repoId), subjectId: repoId, window: QuotaRateWindowUtcDay, limitKey: "evs_read_receipts_per_repo_day", refusalLimitKey: "evs_read_receipts_per_repo_day"},
	}
	for _, c := range cases {
		rule, err := ParseQuotaRateKey(c.key)
		if err != nil {
			t.Errorf("%s: %v", c.key, err)
			continue
		}
		if rule.Key != c.key || rule.SubjectId != c.subjectId || rule.Window != c.window || rule.LimitKey != c.limitKey ||
			rule.FixedLimit != c.fixedLimit || rule.RefusalLimitKey != c.refusalLimitKey || rule.Paced != c.paced ||
			rule.ClassOnly != c.classOnly || rule.Tiered != c.tiered {
			t.Errorf("%s: %+v", c.key, rule)
		}
		if family, _, _ := strings.Cut(c.key, ":"); rule.Family != family {
			t.Errorf("%s: family %q", c.key, rule.Family)
		}
	}
}

// One spelling per counter: anything else is the caller's bug, never a second counter.
func TestQuotaRateKeysRefuseOtherSpellings(t *testing.T) {
	id := connect.NewId()
	undashed := strings.ReplaceAll(id.String(), "-", "")
	for _, key := range []string{
		"",
		"a",
		"evs_drops:" + id.String(),
		"evs_drops:",
		"evs_erasure_pushes:x",
		"evs_closure_uploads",
		"evs_closure_uploads:",
		"evs_closure_uploads:" + strings.ToUpper(id.String()),
		"evs_closure_uploads:" + undashed,
		"evs_closure_uploads:" + connect.Id{}.String(),
		"evs_closure_bytes:" + id.String() + ":x",
		"evs_read_receipts:" + id.String() + ":2026-01-02",
		"EVS_DROPS",
	} {
		if rule, err := ParseQuotaRateKey(key); err == nil || !errors.Is(err, ErrQuotaRateKey) {
			t.Errorf("%q: %+v, %v", key, rule, err)
		}
	}
}

func TestQuotaRateWindowsTurnAtFixedInstants(t *testing.T) {
	at := time.Date(2026, time.January, 2, 3, 4, 5, 123*1000*1000, time.UTC)
	if end := QuotaRateWindowMinute.End(QuotaRateWindowMinute.Index(at)); !end.Equal(time.Date(2026, time.January, 2, 3, 5, 0, 0, time.UTC)) {
		t.Errorf("minute end %s", end)
	}
	if end := QuotaRateWindowUtcDay.End(QuotaRateWindowUtcDay.Index(at)); !end.Equal(time.Date(2026, time.January, 3, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("day end %s", end)
	}
	// a time held in another location turns at 00:00:00 UTC all the same
	elsewhere := time.Date(2026, time.January, 2, 22, 0, 0, 0, time.FixedZone("west", -5*60*60))
	if end := QuotaRateWindowUtcDay.End(QuotaRateWindowUtcDay.Index(elsewhere)); !end.Equal(time.Date(2026, time.January, 4, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("day end from elsewhere %s", end)
	}
	// the last instant of a day and the first of the next
	lastMs := time.Date(2026, time.January, 2, 23, 59, 59, 999*1000*1000, time.UTC)
	if QuotaRateWindowUtcDay.Index(lastMs)+1 != QuotaRateWindowUtcDay.Index(lastMs.Add(time.Millisecond)) {
		t.Error("the day did not turn at 00:00:00 UTC")
	}
	// before the epoch, windows still floor
	before := time.Unix(0, -500*1000*1000)
	if index := QuotaRateWindowMinute.Index(before); index != -1 {
		t.Errorf("index %d", index)
	}
	if end := QuotaRateWindowMinute.End(-1); !end.Equal(time.Unix(0, 0)) {
		t.Errorf("end %s", end)
	}
}

func TestQuotaRetryAfterMsRoundsUp(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		timeout time.Duration
		want    uint32
	}{
		{timeout: -time.Second, want: 1},
		{timeout: 0, want: 1},
		{timeout: 1, want: 1},
		{timeout: time.Millisecond, want: 1},
		{timeout: time.Millisecond + 1, want: 2},
		{timeout: 55 * time.Second, want: 55000},
		{timeout: 100 * 24 * time.Hour, want: math.MaxUint32},
	}
	for _, c := range cases {
		if got := QuotaRetryAfterMs(now, now.Add(c.timeout)); got != c.want {
			t.Errorf("%s: %d, want %d", c.timeout, got, c.want)
		}
	}
}

// The allowance never reads below the floor, nor the floor below one full re-key, whatever pro.yml, a
// row or §21 sets (owner decision 146); none stays none.
func TestQuotaRateLimitsReadTheFloor(t *testing.T) {
	sidecarId := connect.NewId()
	closureBytes, err := ParseQuotaRateKey(QuotaRateKeyClosureBytes(sidecarId))
	if err != nil {
		t.Fatal(err)
	}
	drops, err := ParseQuotaRateKey(QuotaRateKeyDrop)
	if err != nil {
		t.Fatal(err)
	}
	erasures, err := ParseQuotaRateKey(QuotaRateKeyErasurePush)
	if err != nil {
		t.Fatal(err)
	}
	mib := int64(1024 * 1024)
	cases := []struct {
		rule   *QuotaRateRule
		limits map[string]int64
		want   int64
	}{
		{rule: closureBytes, limits: nil, want: QuotaClosureUploadMaxByteCount},
		{rule: closureBytes, limits: map[string]int64{"evs_closure_bytes_per_day": 1, "evs_closure_bytes_floor": 4 * mib}, want: 4 * mib},
		{rule: closureBytes, limits: map[string]int64{"evs_closure_bytes_per_day": 64 * mib, "evs_closure_bytes_floor": 4 * mib}, want: 64 * mib},
		{rule: closureBytes, limits: map[string]int64{"evs_closure_bytes_per_day": 0, "evs_closure_bytes_floor": 1}, want: QuotaClosureUploadMaxByteCount},
		{rule: closureBytes, limits: map[string]int64{"evs_closure_bytes_per_day": -1}, want: -1},
		{rule: drops, limits: nil, want: 0},
		{rule: drops, limits: map[string]int64{"evs_drops_per_day": 7}, want: 7},
		{rule: drops, limits: map[string]int64{"evs_drops_per_day": -1}, want: -1},
		{rule: erasures, limits: map[string]int64{"evs_erasure_pushes_per_min": 1}, want: 60},
	}
	for _, c := range cases {
		limits := &QuotaLimits{Tier: "free", Limits: c.limits}
		if got := c.rule.Limit(limits); got != c.want {
			t.Errorf("%s under %v: %d, want %d", c.rule.Family, c.limits, got, c.want)
		}
	}
	if got := closureBytes.Limit(nil); got != QuotaClosureUploadMaxByteCount {
		t.Errorf("no limits at all: %d", got)
	}
}

// A refusal lifts when its window turns, names the key its row names, and says a higher tier lifts it
// only for a tier quota below Team.
func TestQuotaRateRefusalLiftsWhenItsWindowTurns(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	drops, err := ParseQuotaRateKey(QuotaRateKeyDrop)
	if err != nil {
		t.Fatal(err)
	}
	refusal := drops.Refusal(&QuotaLimits{Tier: "free", Limits: map[string]int64{"evs_drops_per_day": 20}}, 20, now)
	want := QuotaRefusal{LimitKey: "evs_drops_per_day", Limit: 20, Used: 20, RetryAfterMs: uint32((20*time.Hour + 55*time.Minute + 55*time.Second).Milliseconds()), Upgrade: true}
	if *refusal != want {
		t.Errorf("%+v, want %+v", refusal, want)
	}
	if drops.Refusal(&QuotaLimits{Tier: "pro"}, 0, now).Upgrade != true {
		t.Error("a Pro drop refusal says nothing lifts it")
	}
	if drops.Refusal(&QuotaLimits{Tier: "team"}, 0, now).Upgrade {
		t.Error("a Team drop refusal says a higher tier lifts it")
	}
	erasures, err := ParseQuotaRateKey(QuotaRateKeyErasurePush)
	if err != nil {
		t.Fatal(err)
	}
	refusal = erasures.Refusal(&QuotaLimits{Tier: "free"}, 60, now)
	want = QuotaRefusal{LimitKey: "evs_erasure_pushes_per_min", Limit: 60, Used: 60, RetryAfterMs: 55000}
	if *refusal != want {
		t.Errorf("%+v, want %+v", refusal, want)
	}
	closureBytes, err := ParseQuotaRateKey(QuotaRateKeyClosureBytes(connect.NewId()))
	if err != nil {
		t.Fatal(err)
	}
	if closureBytes.Refusal(&QuotaLimits{Tier: "free"}, 0, now).Upgrade {
		t.Error("an abuse allowance says a purchase lifts it")
	}
}

func TestQuotaClosurePacingPerSNeverReadsBelowFour(t *testing.T) {
	cases := []struct {
		limits map[string]int64
		want   int64
	}{
		{limits: nil, want: 4},
		{limits: map[string]int64{"evs_closure_uploads_per_s": 2}, want: 4},
		{limits: map[string]int64{"evs_closure_uploads_per_s": -1}, want: 4},
		{limits: map[string]int64{"evs_closure_uploads_per_s": 8}, want: 8},
	}
	for _, c := range cases {
		if got := QuotaClosurePacingPerS(&QuotaLimits{Limits: c.limits}); got != c.want {
			t.Errorf("%v: %d, want %d", c.limits, got, c.want)
		}
	}
}

// A pacing run: each eraser in askerIds asks every step, in order, and takes its turn whenever Ask allows. It
// answers each eraser's take times and the takes in each aligned second.
func runQuotaClosurePacing(pacing *QuotaClosurePacing, askerIds []connect.Id, start time.Time, step time.Duration, steps int, perS int64) (map[connect.Id][]time.Time, map[int64]int) {
	eraserTakeTimes := map[connect.Id][]time.Time{}
	secondTakeCounts := map[int64]int{}
	for i := range steps {
		now := start.Add(time.Duration(i) * step)
		for _, eraserId := range askerIds {
			if ok, _, _ := pacing.Ask(eraserId, now, perS); ok {
				pacing.Take(eraserId, now, perS)
				eraserTakeTimes[eraserId] = append(eraserTakeTimes[eraserId], now)
				secondTakeCounts[now.Unix()] += 1
			}
		}
	}
	return eraserTakeTimes, secondTakeCounts
}

// P2 (DESIGN-DETAILS 13.3): from the clock's second on, each second's seats, plus what it took if it is the
// current one, are at most perS.
func checkQuotaClosurePacingCells(pacing *QuotaClosurePacing, perS int64) error {
	secondSeatCounts := map[int64]int64{}
	for _, seat := range pacing.eraserTurns {
		secondSeatCounts[seat.Unix()] += 1
	}
	current := pacing.clock.Unix()
	secondSeatCounts[current] += 0
	for second, count := range secondSeatCounts {
		if second < current {
			return fmt.Errorf("a seat of second %d outlived it at %d", second, current)
		}
		if second == current {
			count += pacing.secondCount
		}
		if perS < count {
			return fmt.Errorf("second %d holds %d", second, count)
		}
	}
	return nil
}

// k erasers asking at once each take one upload every k/R s, none starved, the network at most R a second
// (FS-47's pacing clause).
func TestQuotaClosurePacingGivesEqualTurns(t *testing.T) {
	start := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	perS := int64(4)
	eraserIds := []connect.Id{}
	for range 5 {
		eraserIds = append(eraserIds, connect.NewId())
	}
	pacing := NewQuotaClosurePacing()
	eraserTakeTimes, secondTakeCounts := runQuotaClosurePacing(pacing, eraserIds, start, 10*time.Millisecond, 2000, perS)
	for second, count := range secondTakeCounts {
		if perS < int64(count) {
			t.Errorf("second %d took %d", second, count)
		}
	}
	turnTimeout := time.Duration(len(eraserIds)) * time.Second / time.Duration(perS)
	for index, eraserId := range eraserIds {
		takeTimes := eraserTakeTimes[eraserId]
		// 20 s at one turn every 1.25 s
		if len(takeTimes) < 15 {
			t.Errorf("eraser %d took %d turns", index, len(takeTimes))
			continue
		}
		// the first eraser took twice before the others asked; from then on every turn is k/R apart
		first := 0
		if index == 0 {
			first = 1
		}
		for i := first + 1; i < len(takeTimes); i += 1 {
			if gap := takeTimes[i].Sub(takeTimes[i-1]); gap != turnTimeout {
				t.Errorf("eraser %d: turn %d came %s after the last, want %s", index, i, gap, turnTimeout)
				break
			}
		}
	}
}

// An eraser that waits out a retry_after_ms over a minute keeps its place against erasers asking all the
// while: its seat, not its asking, holds it.
func TestQuotaClosurePacingKeepsAWaitingErasersPlace(t *testing.T) {
	start := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	perS := int64(4)
	pacing := NewQuotaClosurePacing()
	askerIds := []connect.Id{}
	for range 250 {
		askerIds = append(askerIds, connect.NewId())
	}
	for _, askerId := range askerIds {
		if ok, _, _ := pacing.Ask(askerId, start, perS); ok {
			pacing.Take(askerId, start, perS)
		}
	}
	waiterId := connect.NewId()
	ok, turnTime, _ := pacing.Ask(waiterId, start, perS)
	if ok {
		t.Fatal("the waiter went ahead of 250 erasers")
	}
	if wait := turnTime.Sub(start); wait <= time.Minute {
		t.Fatalf("the wait %s is not over a minute", wait)
	}
	// the others ask every 250 ms until the waiter's turn, taking theirs as they come
	steps := int(turnTime.Sub(start) / (250 * time.Millisecond))
	runQuotaClosurePacing(pacing, askerIds, start.Add(250*time.Millisecond), 250*time.Millisecond, steps-1, perS)
	if ok, liftTime, _ := pacing.Ask(waiterId, turnTime.Add(-time.Millisecond), perS); ok || !liftTime.Equal(turnTime) {
		t.Errorf("before its turn: %v, lift %s", ok, liftTime)
	}
	if ok, _, _ := pacing.Ask(waiterId, turnTime, perS); !ok {
		t.Error("the waiter lost its turn to erasers that kept asking")
	}
}

// A second with a free cell seats an asker in it, a cell behind the tail, never before now.
func TestQuotaClosurePacingSeatsInASecondWithAFreeCell(t *testing.T) {
	second := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	perS := int64(4)
	pacing := NewQuotaClosurePacing()
	now := second.Add(100 * time.Millisecond)
	// four cells of 250 ms fit from 100 ms on, the fifth is the next second's
	for index, want := range []time.Duration{100, 350, 600, 850, 1100} {
		ok, seatTime, taken := pacing.Ask(connect.NewId(), now, perS)
		if !seatTime.Equal(second.Add(want*time.Millisecond)) || ok != (index == 0) || taken != 0 {
			t.Errorf("asker %d: %v, seat %s, taken %d", index, ok, seatTime.Sub(second), taken)
		}
	}
	if err := checkQuotaClosurePacingCells(pacing, perS); err != nil {
		t.Error(err)
	}
}

// A second with no free cell seats no one: the seat goes to the next second's start, which is empty. Seats
// are a cell apart, so only a second filled at a higher R, as a tightened limit leaves it, has no free cell
// short of its end.
func TestQuotaClosurePacingPushesASeatOutOfAFullSecond(t *testing.T) {
	second := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	pacing := NewQuotaClosurePacing()
	// at R = 8 five erasers hold seats from 0 to 500 ms
	for index := range 5 {
		ok, seatTime, _ := pacing.Ask(connect.NewId(), second, 8)
		if !seatTime.Equal(second.Add(time.Duration(index)*125*time.Millisecond)) || ok != (index == 0) {
			t.Fatalf("asker %d at R = 8: %v, seat %s", index, ok, seatTime.Sub(second))
		}
	}
	// at R = 4 the next cell, 750 ms, lies in a second already holding five
	ok, seatTime, _ := pacing.Ask(connect.NewId(), second, 4)
	if ok || !seatTime.Equal(second.Add(time.Second)) {
		t.Errorf("pushed: %v, seat %s", ok, seatTime.Sub(second))
	}
	ok, seatTime, _ = pacing.Ask(connect.NewId(), second, 4)
	if ok || !seatTime.Equal(second.Add(time.Second+250*time.Millisecond)) {
		t.Errorf("behind the pushed seat: %v, seat %s", ok, seatTime.Sub(second))
	}
}

// A seat is good to its second's end and lapses with it: an eraser late within the second takes, one late
// past it is a newcomer, seated behind every seat since handed out.
func TestQuotaClosurePacingSeatLapsesWithItsSecond(t *testing.T) {
	second := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	perS := int64(4)
	pacing := NewQuotaClosurePacing()
	eraserIds := []connect.Id{}
	for range 8 {
		eraserId := connect.NewId()
		eraserIds = append(eraserIds, eraserId)
		if ok, _, _ := pacing.Ask(eraserId, second, perS); ok {
			pacing.Take(eraserId, second, perS)
		}
	}
	// seats: the first eraser at 250 ms after its take, the others at 500 ms, 750 ms, then 1 s to 2.25 s
	lateId := eraserIds[1]
	goneId := eraserIds[2]
	if ok, seatTime, _ := pacing.Ask(lateId, second.Add(time.Second-time.Microsecond), perS); !ok || !seatTime.Equal(second.Add(500*time.Millisecond)) {
		t.Errorf("late within its second: %v, seat %s", ok, seatTime.Sub(second))
	}
	ok, seatTime, _ := pacing.Ask(goneId, second.Add(time.Second), perS)
	// the tail was the last eraser's 1.75 s, and the late eraser's take put another seat at 2 s
	if ok || !seatTime.Equal(second.Add(2*time.Second+250*time.Millisecond)) {
		t.Errorf("late past its second: %v, seat %s", ok, seatTime.Sub(second))
	}
	if err := checkQuotaClosurePacingCells(pacing, perS); err != nil {
		t.Error(err)
	}
}

// An eraser whose seat lapsed is seated again like a newcomer: in the current second while it has a free
// cell, at the tail when it has none.
func TestQuotaClosurePacingReseatsALapsedEraser(t *testing.T) {
	second := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	perS := int64(4)
	pacing := NewQuotaClosurePacing()
	quietId := connect.NewId()
	if ok, _, _ := pacing.Ask(quietId, second, perS); !ok {
		t.Fatal("a lone eraser waited")
	}
	pacing.Take(quietId, second, perS)
	// the seat at 250 ms goes unused; a minute on the network is quiet, so the current second has cells
	back := second.Add(time.Minute + 600*time.Millisecond)
	ok, seatTime, taken := pacing.Ask(quietId, back, perS)
	if !ok || !seatTime.Equal(back) || taken != 0 {
		t.Errorf("back in a quiet second: %v, seat %s, taken %d", ok, seatTime.Sub(back), taken)
	}
	// a busy network: eight erasers hold the seats of the next two seconds
	busy := back.Add(time.Minute).Truncate(time.Second)
	for range 8 {
		pacing.Ask(connect.NewId(), busy, perS)
	}
	ok, seatTime, _ = pacing.Ask(quietId, busy.Add(time.Second), perS)
	if ok || !seatTime.Equal(busy.Add(2*time.Second)) {
		t.Errorf("back in a full second: %v, seat %s", ok, seatTime.Sub(busy))
	}
}

// Two callers' clocks: the network's is the latest either brought, so a caller behind it is judged at it,
// the second does not turn back and its takes are not forgotten.
func TestQuotaClosurePacingClockNeverRunsBack(t *testing.T) {
	second := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	perS := int64(4)
	pacing := NewQuotaClosurePacing()
	ahead := func(now time.Time) time.Time { return now }
	behind := func(now time.Time) time.Time { return now.Add(-3 * time.Millisecond) }
	eraserIds := []connect.Id{}
	for range 6 {
		eraserIds = append(eraserIds, connect.NewId())
	}
	secondTakeCounts := map[int64]int64{}
	for step := range 400 {
		now := second.Add(time.Duration(step) * 10 * time.Millisecond)
		for index, eraserId := range eraserIds {
			callerNow := ahead(now)
			if index%2 == 1 {
				callerNow = behind(now)
			}
			ok, seatTime, _ := pacing.Ask(eraserId, callerNow, perS)
			if pacing.Clock().Before(now) {
				t.Fatalf("the clock %s fell behind the latest caller %s", pacing.Clock(), now)
			}
			if ok {
				pacing.Take(eraserId, callerNow, perS)
				secondTakeCounts[pacing.Clock().Unix()] += 1
			} else if retry := QuotaRetryAfterMs(pacing.Clock(), seatTime); time.Duration(retry)*time.Millisecond > 2*time.Second {
				t.Fatalf("eraser %d told %d ms", index, retry)
			}
			if err := checkQuotaClosurePacingCells(pacing, perS); err != nil {
				t.Fatal(err)
			}
		}
	}
	for secondIndex, count := range secondTakeCounts {
		if perS < count {
			t.Errorf("second %d took %d", secondIndex, count)
		}
	}
	// the caller behind is told the wait from the network's clock, not its own
	lateId := connect.NewId()
	now := second.Add(time.Hour)
	pacing.Ask(connect.NewId(), now, perS)
	ok, seatTime, _ := pacing.Ask(lateId, behind(now), perS)
	if ok || !pacing.Clock().Equal(now) || QuotaRetryAfterMs(pacing.Clock(), seatTime) != uint32(seatTime.Sub(now).Milliseconds()) {
		t.Errorf("the caller behind: %v, seat %s, clock %s", ok, seatTime.Sub(now), pacing.Clock().Sub(now))
	}
}

// R not dividing 10^6 rounds a cell up to the microsecond, so R cells never fit in less than a second: P1
// and P2 hold for R = 3, 4 and 7 over a random run of asks, takes, obedient returns and lapses from a
// fixed seed.
func TestQuotaClosurePacingKeepsRateAndCellsForAnyR(t *testing.T) {
	for _, perS := range []int64{3, 4, 7} {
		random := rand.New(rand.NewPCG(uint64(perS), 146))
		pacing := NewQuotaClosurePacing()
		eraserIds := []connect.Id{}
		for range 9 {
			eraserIds = append(eraserIds, connect.NewId())
		}
		eraserAskTimes := map[connect.Id]time.Time{}
		secondTakeCounts := map[int64]int64{}
		now := time.Date(2026, time.January, 2, 3, 4, 5, 123456*1000, time.UTC)
		for range 20000 {
			now = now.Add(time.Duration(random.IntN(90*1000)) * time.Microsecond)
			eraserId := eraserIds[random.IntN(len(eraserIds))]
			// most asks obey the last answer, the rest come whenever
			if askTime, ok := eraserAskTimes[eraserId]; ok && random.IntN(4) != 0 {
				if now.Before(askTime) {
					now = askTime
				}
			}
			ok, seatTime, _ := pacing.Ask(eraserId, now, perS)
			if ok {
				pacing.Take(eraserId, now, perS)
				secondTakeCounts[pacing.Clock().Unix()] += 1
				delete(eraserAskTimes, eraserId)
			} else {
				eraserAskTimes[eraserId] = seatTime
			}
			if err := checkQuotaClosurePacingCells(pacing, perS); err != nil {
				t.Fatalf("R = %d: %v", perS, err)
			}
		}
		for second, count := range secondTakeCounts {
			if perS < count {
				t.Errorf("R = %d: second %d took %d", perS, second, count)
			}
		}
		if len(secondTakeCounts) == 0 {
			t.Errorf("R = %d: nothing took", perS)
		}
	}
}

// Fixed vectors of the seat arithmetic, cells rounded up to the microsecond, which server's {sq_} script must
// give for the same asks (quota_rate_pacing_test.go holds it to this type).
func TestQuotaClosurePacingVectors(t *testing.T) {
	second := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	type step struct {
		eraser int
		at     time.Duration
		ok     bool
		seat   time.Duration
		taken  int64
	}
	cases := []struct {
		perS  int64
		steps []step
	}{
		{
			// a cell of 333,334 µs
			perS: 3,
			steps: []step{
				{eraser: 0, at: 0, ok: true, seat: 0, taken: 0},
				{eraser: 1, at: 0, ok: false, seat: 666668 * time.Microsecond, taken: 1},
				{eraser: 2, at: 0, ok: false, seat: 1000002 * time.Microsecond, taken: 1},
				{eraser: 0, at: 333334 * time.Microsecond, ok: true, seat: 333334 * time.Microsecond, taken: 1},
				{eraser: 1, at: 666668 * time.Microsecond, ok: true, seat: 666668 * time.Microsecond, taken: 2},
				{eraser: 2, at: 1000002 * time.Microsecond, ok: true, seat: 1000002 * time.Microsecond, taken: 0},
				// the takes put the first eraser at 1,333,336 µs and the second at 1,666,670 µs
				{eraser: 0, at: 1000002 * time.Microsecond, ok: false, seat: 1333336 * time.Microsecond, taken: 1},
				{eraser: 1, at: 1999999 * time.Microsecond, ok: true, seat: 1666670 * time.Microsecond, taken: 1},
				// the first eraser's seat lapsed at 2 s: seated a cell behind the second's new 2,333,338 µs
				{eraser: 0, at: 2000000 * time.Microsecond, ok: false, seat: 2666672 * time.Microsecond, taken: 0},
			},
		},
		{
			// a cell of 142,858 µs; a caller 2 ms behind is judged at the network's clock
			perS: 7,
			steps: []step{
				{eraser: 0, at: 500 * time.Millisecond, ok: true, seat: 500 * time.Millisecond, taken: 0},
				{eraser: 1, at: 498 * time.Millisecond, ok: false, seat: 785716 * time.Microsecond, taken: 1},
				{eraser: 2, at: 500 * time.Millisecond, ok: false, seat: 928574 * time.Microsecond, taken: 1},
				{eraser: 3, at: 500 * time.Millisecond, ok: false, seat: 1071432 * time.Microsecond, taken: 1},
				{eraser: 0, at: 642858 * time.Microsecond, ok: true, seat: 642858 * time.Microsecond, taken: 1},
				{eraser: 1, at: 900 * time.Millisecond, ok: true, seat: 785716 * time.Microsecond, taken: 2},
				{eraser: 3, at: 999999 * time.Microsecond, ok: false, seat: 1071432 * time.Microsecond, taken: 3},
			},
		},
	}
	for _, c := range cases {
		pacing := NewQuotaClosurePacing()
		eraserIds := []connect.Id{}
		for range 4 {
			eraserIds = append(eraserIds, connect.NewId())
		}
		for index, s := range c.steps {
			now := second.Add(s.at)
			ok, seatTime, taken := pacing.Ask(eraserIds[s.eraser], now, c.perS)
			if ok != s.ok || !seatTime.Equal(second.Add(s.seat)) || taken != s.taken {
				t.Fatalf("R = %d, step %d: %v, seat %d µs, taken %d", c.perS, index, ok, seatTime.Sub(second).Microseconds(), taken)
			}
			if ok {
				pacing.Take(eraserIds[s.eraser], now, c.perS)
			}
		}
	}
}

// Erasers run against one pacing until end, each asking at its own next instant, those due at one instant in
// the fixed order of eraserIds. An obedient eraser asks next at the seat it was told, and after a take a moment
// later, for its next upload; a late one asks at the start of every second whatever it was told. It answers
// each eraser's take times, and fails at an obedient eraser refused at the seat it was told, or the network
// past perS in a second.
func runQuotaClosurePacingSchedule(t *testing.T, pacing *QuotaClosurePacing, eraserIds []connect.Id, lateIds map[connect.Id]bool, start time.Time, end time.Time, perS int64) map[connect.Id][]time.Time {
	t.Helper()
	eraserAskTimes := map[connect.Id]time.Time{}
	eraserTold := map[connect.Id]bool{}
	for _, eraserId := range eraserIds {
		eraserAskTimes[eraserId] = start
	}
	eraserTakeTimes := map[connect.Id][]time.Time{}
	secondTakeCounts := map[int64]int64{}
	for {
		var now time.Time
		for _, eraserId := range eraserIds {
			if askTime := eraserAskTimes[eraserId]; now.IsZero() || askTime.Before(now) {
				now = askTime
			}
		}
		if !now.Before(end) {
			return eraserTakeTimes
		}
		for _, eraserId := range eraserIds {
			if !eraserAskTimes[eraserId].Equal(now) {
				continue
			}
			ok, seatTime, _ := pacing.Ask(eraserId, now, perS)
			nextSecond := time.Unix(now.Unix()+1, 0).UTC()
			if !ok {
				if eraserTold[eraserId] && !lateIds[eraserId] {
					t.Fatalf("an obedient eraser was refused at the seat it was told, %s", now)
				}
				eraserTold[eraserId] = true
				eraserAskTimes[eraserId] = seatTime
				if lateIds[eraserId] {
					eraserAskTimes[eraserId] = nextSecond
				}
				continue
			}
			pacing.Take(eraserId, now, perS)
			eraserTakeTimes[eraserId] = append(eraserTakeTimes[eraserId], now)
			secondTakeCounts[now.Unix()] += 1
			if perS < secondTakeCounts[now.Unix()] {
				t.Fatalf("second %d took %d", now.Unix(), secondTakeCounts[now.Unix()])
			}
			eraserTold[eraserId] = false
			eraserAskTimes[eraserId] = now.Add(time.Microsecond)
			if lateIds[eraserId] {
				eraserAskTimes[eraserId] = nextSecond
			}
		}
	}
}

// P3 (DESIGN-DETAILS 13.3): from its first ask on, an eraser that asks when told takes within bound of each ask
// and of each take after it.
func checkQuotaClosurePacingTurns(start time.Time, end time.Time, takeTimes []time.Time, bound time.Duration) error {
	last := start
	for _, takeTime := range append(slices.Clone(takeTimes), end) {
		if wait := takeTime.Sub(last); bound < wait {
			return fmt.Errorf("a wait of %s from %s, past %s", wait, last, bound)
		}
		last = takeTime
	}
	return nil
}

// Twin PacingTwin-Arrival (DESIGN-DETAILS 13.1 A.1): twelve erasers that last asked at 23:59:30 come back at
// 00:00:00 UTC together and ask in the same order every time, each obeying every answer. Seats serve every one
// within P3's bound of (live seats + 2R) cells; a bucket that admits by arrival, once every slot was past due,
// let the first four take every turn and kept the other eight out.
func TestPacingAdmitsBySeatNotArrival(t *testing.T) {
	perS := int64(4)
	cell := quotaClosurePacingSpacing(perS)
	midnight := time.Date(2026, time.January, 3, 0, 0, 0, 0, time.UTC)
	pacing := NewQuotaClosurePacing()
	eraserIds := []connect.Id{}
	for range 12 {
		eraserId := connect.NewId()
		eraserIds = append(eraserIds, eraserId)
		pacing.Ask(eraserId, midnight.Add(-30*time.Second), perS)
	}
	end := midnight.Add(30 * time.Second)
	eraserTakeTimes := runQuotaClosurePacingSchedule(t, pacing, eraserIds, nil, midnight, end, perS)
	bound := time.Duration(int64(len(eraserIds))+2*perS) * cell
	for index, eraserId := range eraserIds {
		if err := checkQuotaClosurePacingTurns(midnight, end, eraserTakeTimes[eraserId], bound); err != nil {
			t.Errorf("eraser %d: %v", index, err)
		}
		// a turn every 12 cells, 3 s
		if count := len(eraserTakeTimes[eraserId]); count < 9 {
			t.Errorf("eraser %d took %d turns in 30 s", index, count)
		}
	}
}

// Twin PacingTwin-Tail (DESIGN-DETAILS 13.1 A.2): two erasers that ask at the start of every second, never at
// their seats, cannot take a second's cells from the obedient erasers whose seats lie inside it, so each obedient
// eraser takes at every seat it is told and keeps P3's bound. A bucket refusal sent to the tail lost an obedient
// eraser its place each time the late ones came first.
func TestPacingBucketRefusalKeepsThePlace(t *testing.T) {
	perS := int64(4)
	cell := quotaClosurePacingSpacing(perS)
	start := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	pacing := NewQuotaClosurePacing()
	lateIds := map[connect.Id]bool{}
	eraserIds := []connect.Id{}
	// the late two first in every instant's order, the order least kind to the obedient
	for range 2 {
		lateId := connect.NewId()
		lateIds[lateId] = true
		eraserIds = append(eraserIds, lateId)
	}
	obedientIds := []connect.Id{}
	for range 4 {
		obedientId := connect.NewId()
		obedientIds = append(obedientIds, obedientId)
		eraserIds = append(eraserIds, obedientId)
	}
	end := start.Add(30 * time.Second)
	eraserTakeTimes := runQuotaClosurePacingSchedule(t, pacing, eraserIds, lateIds, start, end, perS)
	bound := time.Duration(int64(len(eraserIds))+2*perS) * cell
	for index, obedientId := range obedientIds {
		if err := checkQuotaClosurePacingTurns(start, end, eraserTakeTimes[obedientId], bound); err != nil {
			t.Errorf("obedient eraser %d: %v", index, err)
		}
		// at most one turn every six cells, 1.5 s
		if count := len(eraserTakeTimes[obedientId]); count < 15 {
			t.Errorf("obedient eraser %d took %d turns in 30 s", index, count)
		}
	}
}
