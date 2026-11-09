//go:build !sidecar_http

package sidecar

import (
	"encoding/hex"
	"errors"
	"math"
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

// A pacing run: each eraser in askerIds asks every step, in order, and takes its turn whenever Ask
// allows. It answers each eraser's take times and the takes in each aligned second.
func runQuotaClosurePacing(pacing *QuotaClosurePacing, askerIds []connect.Id, start time.Time, step time.Duration, steps int, perS int64) (map[connect.Id][]time.Time, map[int64]int) {
	eraserTakeTimes := map[connect.Id][]time.Time{}
	secondTakeCounts := map[int64]int{}
	for i := range steps {
		now := start.Add(time.Duration(i) * step)
		for _, eraserId := range askerIds {
			if ok, _, _ := pacing.Ask(eraserId, now, perS, 5*time.Minute); ok {
				pacing.Take(eraserId, now, perS)
				eraserTakeTimes[eraserId] = append(eraserTakeTimes[eraserId], now)
				secondTakeCounts[now.Unix()] += 1
			}
		}
	}
	return eraserTakeTimes, secondTakeCounts
}

// k erasers asking at once each take one upload every k/R s, none starved, the network at most R a
// second (FS-47's pacing clause).
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

// An eraser that waits out a retry_after_ms over a minute keeps its place against erasers asking all
// the while: the slot, not the ask, holds it.
func TestQuotaClosurePacingKeepsAWaitingErasersPlace(t *testing.T) {
	start := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	perS := int64(4)
	pacing := NewQuotaClosurePacing()
	askerIds := []connect.Id{}
	for range 250 {
		askerIds = append(askerIds, connect.NewId())
	}
	for _, askerId := range askerIds {
		if ok, _, _ := pacing.Ask(askerId, start, perS, 5*time.Minute); ok {
			pacing.Take(askerId, start, perS)
		}
	}
	waiterId := connect.NewId()
	ok, turnTime, _ := pacing.Ask(waiterId, start, perS, 5*time.Minute)
	if ok {
		t.Fatal("the waiter went ahead of 250 erasers")
	}
	if wait := turnTime.Sub(start); wait <= time.Minute {
		t.Fatalf("the wait %s is not over a minute", wait)
	}
	// the others ask every 250 ms until the waiter's turn, taking theirs as they come
	steps := int(turnTime.Sub(start) / (250 * time.Millisecond))
	runQuotaClosurePacing(pacing, askerIds, start.Add(250*time.Millisecond), 250*time.Millisecond, steps-1, perS)
	if ok, liftTime, _ := pacing.Ask(waiterId, turnTime.Add(-time.Millisecond), perS, 5*time.Minute); ok || !liftTime.Equal(turnTime) {
		t.Errorf("before its turn: %v, lift %s", ok, liftTime)
	}
	if ok, _, _ := pacing.Ask(waiterId, turnTime, perS, 5*time.Minute); !ok {
		t.Error("the waiter lost its turn to erasers that kept asking")
	}
}

// Erasers whose turns all passed while they were away come back at once, as allowances reset at
// 00:00 UTC: at most R take in that second, and the rest wait for the next.
func TestQuotaClosurePacingBoundsErasersReturningTogether(t *testing.T) {
	start := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	perS := int64(4)
	pacing := NewQuotaClosurePacing()
	eraserIds := []connect.Id{}
	for range 12 {
		eraserId := connect.NewId()
		eraserIds = append(eraserIds, eraserId)
		if ok, _, _ := pacing.Ask(eraserId, start, perS, 5*time.Minute); ok {
			pacing.Take(eraserId, start, perS)
		}
	}
	back := start.Add(10 * time.Second)
	taken := 0
	for _, eraserId := range eraserIds {
		ok, liftTime, takenThisSecond := pacing.Ask(eraserId, back, perS, 5*time.Minute)
		if ok {
			pacing.Take(eraserId, back, perS)
			taken += 1
			continue
		}
		if takenThisSecond != perS || !liftTime.Equal(back.Add(time.Second)) {
			t.Errorf("refused with %d taken, lift %s", takenThisSecond, liftTime)
		}
		refusal := QuotaClosurePacingRefusal(&QuotaLimits{}, takenThisSecond, back, liftTime)
		if refusal.LimitKey != "evs_closure_uploads_per_s" || refusal.Limit != 4 || refusal.RetryAfterMs != 1000 || refusal.Upgrade {
			t.Errorf("refusal %+v", refusal)
		}
	}
	if int64(taken) != perS {
		t.Errorf("%d took in one second", taken)
	}
}

// A slot lapses its horizon past its turn: an eraser that went away asks again from the tail.
func TestQuotaClosurePacingLapsesAStaleSlot(t *testing.T) {
	start := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	perS := int64(4)
	horizon := 5 * time.Minute
	pacing := NewQuotaClosurePacing()
	takerId := connect.NewId()
	goneId := connect.NewId()
	if ok, _, _ := pacing.Ask(takerId, start, perS, horizon); !ok {
		t.Fatal("the first eraser waited")
	}
	pacing.Take(takerId, start, perS)
	ok, goneTurnTime, _ := pacing.Ask(goneId, start, perS, horizon)
	if ok {
		t.Fatal("the second eraser went at once")
	}
	// within its horizon the slot holds: back late, it goes at once
	within := goneTurnTime.Add(horizon)
	held := NewQuotaClosurePacing()
	*held = *pacing
	held.eraserTurns = map[connect.Id]time.Time{}
	for eraserId, turnTime := range pacing.eraserTurns {
		held.eraserTurns[eraserId] = turnTime
	}
	if ok, _, _ := held.Ask(goneId, within, perS, horizon); !ok {
		t.Error("a slot within its horizon did not hold")
	}
	// past it, the slot is gone, and a newcomer's ask sweeps it
	later := within.Add(time.Millisecond)
	newcomerId := connect.NewId()
	if ok, _, _ := pacing.Ask(newcomerId, later, perS, horizon); !ok {
		t.Fatal("the newcomer waited for slots that lapsed")
	}
	pacing.Take(newcomerId, later, perS)
	if count := pacing.EraserCount(); count != 1 {
		t.Errorf("%d erasers hold slots after the lapse", count)
	}
	if ok, liftTime, _ := pacing.Ask(goneId, later, perS, horizon); ok || !liftTime.After(later) {
		t.Errorf("the lapsed eraser kept its place: %v, lift %s", ok, liftTime)
	}
}
