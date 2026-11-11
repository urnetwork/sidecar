//go:build !sidecar_http && !ios_extension

// What engines and the hosted Quota share (§20.6, §20.7): the meters a lease or a usage batch counts on,
// the producers that send batches, how a batch's retry identity is made, and the grammar of CountRate's
// keys. CountRate takes a plain map, so a key's family, window and limit are fixed here, and
// sidecartest.FakeQuota and server's {sq_<network_id>} script both resolve a key through
// ParseQuotaRateKey, so neither counts a key the other reads differently. The closure pacing is here
// too, as plain state a Quota keeps per network, so the fake runs it and the script can be held to it.
//
// Nothing here reads a clock: each rule takes the time it is asked at, which is the Quota's own clock,
// so a fake clock moves every window.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/urnetwork/connect"
)

// Meters (§13.6; plan-QUOTA-small-readings reading 2). A lease and a UsageEvent each name one. Team's
// Stripe meters are taskworker's own and never reach a UsageEvent.
const (
	// tlsedge's lease spends (§13.6).
	QuotaMeterTls = "tls"
	// mxedge's lease spends (§15.6).
	QuotaMeterMx = "mx"
	// smtpedge's lease spends (§14.7).
	QuotaMeterSmtp = "smtp"
	// evs's transfer bytes and stored-byte deltas, which usage batches carry (§11.13).
	QuotaMeterEvs = "evs"
	// Relayed same-network sidecar bytes, which api debits from close reports by contract (§20.6).
	QuotaMeterRelay = "relay"
)

// Whether meter is one of the five above. A Quota refuses a lease or a batch naming any other.
func IsQuotaMeter(meter string) bool {
	switch meter {
	case QuotaMeterTls, QuotaMeterMx, QuotaMeterSmtp, QuotaMeterEvs, QuotaMeterRelay:
		return true
	}
	return false
}

// Whether a lease spends meter: tlsedge's, mxedge's and smtpedge's. A lease meter's bytes are debited only
// through their lease's carves (DESIGN-DETAILS 13.2.2, QD-653); evs's draw when their batch applies.
func IsQuotaLeaseMeter(meter string) bool {
	switch meter {
	case QuotaMeterTls, QuotaMeterMx, QuotaMeterSmtp:
		return true
	}
	return false
}

// Producers (§20.6): UsageBatch.Producer names the process that sent it.
const (
	QuotaProducerEvs      = "evs"
	QuotaProducerTlsEdge  = "tlsedge"
	QuotaProducerMxEdge   = "mxedge"
	QuotaProducerSmtpEdge = "smtpedge"
	// Evacuation's staged frees and the drop job's deletes and holds (§11.13).
	QuotaProducerTaskworker = "taskworker"
)

// Whether producer is one of the five above. A Quota refuses a batch from any other.
func IsQuotaProducer(producer string) bool {
	switch producer {
	case QuotaProducerEvs, QuotaProducerTlsEdge, QuotaProducerMxEdge, QuotaProducerSmtpEdge, QuotaProducerTaskworker:
		return true
	}
	return false
}

// The most events one batch carries. A Quota refuses a larger batch whole, and QuotaUsageBatcher
// splits a window past it into several batches, each with its own id, so one transaction at api
// stays bounded however many networks a process served in a minute.
const QuotaUsageBatchMaxEventCount = 1000

// A batch's retry identity (§20.6): the first 16 B of SHA-256(producerInstanceId || windowSeq),
// windowSeq as 8 bytes big-endian. producerInstanceId is 16 random bytes drawn at process start, so no
// two processes share an id, and a retry of one window keeps its own.
func NewUsageBatchId(producerInstanceId [16]byte, windowSeq uint64) connect.Id {
	var input [24]byte
	copy(input[0:16], producerInstanceId[:])
	binary.BigEndian.PutUint64(input[16:24], windowSeq)
	sum := sha256.Sum256(input[:])
	return connect.Id(sum[0:16])
}

// A drop job's batch id (§11.13's delete row; FI-13(a)): the first 16 B of SHA-256(scanId || cursor
// range), so another instance resuming the job reports the same id and api applies it once. The range
// is the job's cursor before the batch's deletes and after them, each as the job encodes its position
// and written after its length as 4 bytes big-endian, so two ranges never hash the same bytes.
func NewDropUsageBatchId(scanId connect.Id, cursorFrom []byte, cursorTo []byte) connect.Id {
	input := make([]byte, 0, 16+4+len(cursorFrom)+4+len(cursorTo))
	input = append(input, scanId[:]...)
	input = binary.BigEndian.AppendUint32(input, uint32(len(cursorFrom)))
	input = append(input, cursorFrom...)
	input = binary.BigEndian.AppendUint32(input, uint32(len(cursorTo)))
	input = append(input, cursorTo...)
	sum := sha256.Sum256(input)
	return connect.Id(sum[0:16])
}

// CountRate's keys for evs (§20.7's counters; §11.7, §11.12, §11.13), counted on the network's
// {sq_<network_id>}. A key is its family, then ':' and the id it names when it names one. The window a
// count lands in is the Quota's to tell from its clock, so no key carries a time. A debit id that passed
// answers pass again and counts nothing; one that was refused recorded nothing and is judged afresh
// (DESIGN-DETAILS 13.2.1, QD-652), so a caller asking again after a refusal's retry_after_ms keeps its
// debit id, and an upload whose answer was lost is charged once.
const (
	// The network's ERASE, CUT and CLOSURE pushes, 60 a minute. A refusal only classes the push: past
	// the rate it queues as P1 and still commits (§11.12's push row). Count it in a call of its own, since
	// under all-or-none its refusal would also stop the call's other keys.
	QuotaRateKeyErasurePush = "evs_erasure_pushes"
	// The network's drop-history actions, evs_drops_per_day a UTC day (§11.7). A cancel never counts,
	// and a drop spends no closure allowance (owner decision 146).
	QuotaRateKeyDrop = "evs_drops"
)

// One eraser's ?closure=1 uploads, the sidecar its token's ur_sidecar_id names: its own 60 a minute,
// and each upload takes its turn of the network's closure pacing (§20.7's closure row). Count 1 per
// upload.
func QuotaRateKeyClosureUpload(sidecarId connect.Id) string {
	return quotaRateFamilyClosureUploads + ":" + sidecarId.String()
}

// One eraser's closure bytes, its ?closure=1 uploads and its CLOSURE pushes' inline records, against its
// own evs_closure_bytes_per_day a UTC day, never below the floor (§20.7's allow row). No other sidecar
// spends it.
func QuotaRateKeyClosureBytes(sidecarId connect.Id) string {
	return quotaRateFamilyClosureBytes + ":" + sidecarId.String()
}

// A repo's drop dry runs, evs_drop_previews_per_day a UTC day (§11.13).
func QuotaRateKeyDropPreview(repoId connect.Id) string {
	return quotaRateFamilyDropPreviews + ":" + repoId.String()
}

// A repo's read receipts, evs_read_receipts_per_repo_day a UTC day (§11.12; QD-544), counted with the
// push's id as the debit id, so a retried push counts nothing twice.
func QuotaRateKeyReadReceipt(repoId connect.Id) string {
	return quotaRateFamilyReadReceipts + ":" + repoId.String()
}

const (
	quotaRateFamilyClosureUploads = "evs_closure_uploads"
	quotaRateFamilyClosureBytes   = "evs_closure_bytes"
	quotaRateFamilyDropPreviews   = "evs_drop_previews"
	quotaRateFamilyReadReceipts   = "evs_read_receipts"
)

// The QuotaLimits keys the grammar reads (§20.4), and the names its refusals give rates no pro.yml key
// sets.
const (
	quotaLimitKeyClosureUploadsPerS     = "evs_closure_uploads_per_s"
	quotaLimitKeyClosureUploadsPerMin   = "evs_closure_uploads_per_min"
	quotaLimitKeyClosureBytesPerDay     = "evs_closure_bytes_per_day"
	quotaLimitKeyClosureBytesFloor      = "evs_closure_bytes_floor"
	quotaLimitKeyErasurePushesPerMin    = "evs_erasure_pushes_per_min"
	quotaLimitKeyDropsPerDay            = "evs_drops_per_day"
	quotaLimitKeyDropPreviewsPerDay     = "evs_drop_previews_per_day"
	quotaLimitKeyReadReceiptsPerRepoDay = "evs_read_receipts_per_repo_day"

	// QuotaLimits' none (§20.4's `none`).
	quotaLimitNone = int64(-1)

	// The top tier, which no purchase lifts.
	quotaTierTeam = "team"
)

// One ?closure=1 upload's most: a padded segment of one padded record of a 1 MiB file, §15.7's largest
// i/ segment and §11.14's largest index file (§11.12's rekey row). It is also the least an eraser's
// allowance reads, so an eraser always has one full re-key a day (owner decision 146).
const QuotaClosureUploadMaxByteCount = 1088 * 1024

// The least evs_closure_uploads_per_s reads. Owner decision 146 fixes the pacing, §20.7's wait bounds
// are stated at it, and a lower value would slow every erasure.
const quotaClosurePacingMinPerS = int64(4)

// A rate window. Windows are fixed, never sliding: each turns at a fixed instant, counted from the Unix
// epoch, so a refusal's retry_after_ms runs to its window's end.
type QuotaRateWindow int

const (
	// From second :00 of each minute.
	QuotaRateWindowMinute QuotaRateWindow = iota + 1
	// From 00:00:00 UTC.
	QuotaRateWindowUtcDay
)

// The window's name in a trace.
func (self QuotaRateWindow) String() string {
	switch self {
	case QuotaRateWindowMinute:
		return "minute"
	case QuotaRateWindowUtcDay:
		return "utc-day"
	}
	return fmt.Sprintf("QuotaRateWindow(%d)", int(self))
}

// How long one window lasts.
func (self QuotaRateWindow) Duration() time.Duration {
	switch self {
	case QuotaRateWindowMinute:
		return 1 * time.Minute
	case QuotaRateWindowUtcDay:
		return 24 * time.Hour
	}
	panic(fmt.Sprintf("no such window: %d", int(self)))
}

// The window at holds, numbered from the Unix epoch, so a day's window turns at 00:00:00 UTC whatever
// at's location.
func (self QuotaRateWindow) Index(at time.Time) int64 {
	size := self.Duration().Milliseconds()
	ms := at.UnixMilli()
	index := ms / size
	if ms < 0 && ms%size != 0 {
		index -= 1
	}
	return index
}

// When the window at index ends, which is when the next begins.
func (self QuotaRateWindow) End(index int64) time.Time {
	return time.UnixMilli((index + 1) * self.Duration().Milliseconds()).UTC()
}

// retry_after_ms for a refusal at now that lifts at liftTime: whole milliseconds rounded up and at least
// 1, so a caller that waits it out never asks early, and at most a uint32's.
func QuotaRetryAfterMs(now time.Time, liftTime time.Time) uint32 {
	timeout := liftTime.Sub(now)
	if timeout <= 0 {
		return 1
	}
	ms := (timeout + time.Millisecond - 1) / time.Millisecond
	if math.MaxUint32 < int64(ms) {
		return math.MaxUint32
	}
	return max(uint32(ms), 1)
}

// What a rate key resolves to. Read only: ParseQuotaRateKey makes a fresh one each call.
type QuotaRateRule struct {
	// The key as given.
	Key string
	// The key before its ':'.
	Family string
	// The eraser's sidecar id or the repo id the key names. Zero for the network's own keys.
	SubjectId connect.Id
	// The window a count lands in.
	Window QuotaRateWindow
	// The QuotaLimits key holding one window's limit. Empty: FixedLimit is the limit.
	LimitKey string
	// The limit no pro.yml key sets: §20.7's 60 a minute.
	FixedLimit int64
	// What a refusal's limit_key names: LimitKey, or the fixed rate's own name.
	RefusalLimitKey string
	// The limit reads at least this key's value: the closure floor, which no row or §21 action lowers
	// (owner decision 146).
	FloorLimitKey string
	// The limit reads at least this, so an unusable value never stops erasure.
	MinLimit int64
	// Each count also takes a turn of the network's closure pacing (QuotaClosurePacing), so its amount
	// is 1 and one call counts at most one such key.
	Paced bool
	// A refusal only classes the request, which proceeds (§11.12's push row).
	ClassOnly bool
	// The limit grows with the tier (§20.4), so a refusal below Team says a higher tier lifts it.
	Tiered bool
}

// One row of §20.7's counters: whether its keys name an id, and the rule each resolves to.
type quotaRateFamily struct {
	// the key names an id after its ':'
	subject bool
	rule    QuotaRateRule
}

// §20.7's counters, row by row.
var quotaRateFamilies = map[string]*quotaRateFamily{
	quotaRateFamilyClosureUploads: {
		subject: true,
		rule: QuotaRateRule{
			Window:          QuotaRateWindowMinute,
			FixedLimit:      60,
			RefusalLimitKey: quotaLimitKeyClosureUploadsPerMin,
			Paced:           true,
		},
	},
	quotaRateFamilyClosureBytes: {
		subject: true,
		rule: QuotaRateRule{
			Window:          QuotaRateWindowUtcDay,
			LimitKey:        quotaLimitKeyClosureBytesPerDay,
			RefusalLimitKey: quotaLimitKeyClosureBytesPerDay,
			FloorLimitKey:   quotaLimitKeyClosureBytesFloor,
			MinLimit:        QuotaClosureUploadMaxByteCount,
		},
	},
	QuotaRateKeyErasurePush: {
		rule: QuotaRateRule{
			Window:          QuotaRateWindowMinute,
			FixedLimit:      60,
			RefusalLimitKey: quotaLimitKeyErasurePushesPerMin,
			ClassOnly:       true,
		},
	},
	QuotaRateKeyDrop: {
		rule: QuotaRateRule{
			Window:          QuotaRateWindowUtcDay,
			LimitKey:        quotaLimitKeyDropsPerDay,
			RefusalLimitKey: quotaLimitKeyDropsPerDay,
			Tiered:          true,
		},
	},
	quotaRateFamilyDropPreviews: {
		subject: true,
		rule: QuotaRateRule{
			Window:          QuotaRateWindowUtcDay,
			LimitKey:        quotaLimitKeyDropPreviewsPerDay,
			RefusalLimitKey: quotaLimitKeyDropPreviewsPerDay,
		},
	},
	quotaRateFamilyReadReceipts: {
		subject: true,
		rule: QuotaRateRule{
			Window:          QuotaRateWindowUtcDay,
			LimitKey:        quotaLimitKeyReadReceiptsPerRepoDay,
			RefusalLimitKey: quotaLimitKeyReadReceiptsPerRepoDay,
		},
	},
}

// A key no family names, or one spelled other than its constructor spells it. A Quota answers it as the
// caller's bug, with an error and nothing counted.
var ErrQuotaRateKey = errors.New("not a quota rate key")

// Resolves a CountRate key. A key naming an id must spell it as connect.Id.String does, so two
// spellings never count apart, and the id is never zero.
func ParseQuotaRateKey(key string) (*QuotaRateRule, error) {
	familyName, subject, hasSubject := strings.Cut(key, ":")
	family, ok := quotaRateFamilies[familyName]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrQuotaRateKey, key)
	}
	rule := family.rule
	rule.Key = key
	rule.Family = familyName
	if hasSubject != family.subject {
		return nil, fmt.Errorf("%w: %q", ErrQuotaRateKey, key)
	}
	if family.subject {
		subjectId, err := connect.ParseId(subject)
		if err != nil || subjectId == (connect.Id{}) || subjectId.String() != subject {
			return nil, fmt.Errorf("%w: %q", ErrQuotaRateKey, key)
		}
		rule.SubjectId = subjectId
	}
	return &rule, nil
}

// A key's value in limits, which reads 0 when absent: not included (§20.5).
func quotaLimitsValue(limits *QuotaLimits, limitKey string) int64 {
	if limits == nil {
		return 0
	}
	return limits.Limits[limitKey]
}

// One window's limit under limits, or -1 for none.
func (self *QuotaRateRule) Limit(limits *QuotaLimits) int64 {
	limit := self.FixedLimit
	if self.LimitKey != "" {
		limit = quotaLimitsValue(limits, self.LimitKey)
	}
	if limit == quotaLimitNone {
		return limit
	}
	if self.FloorLimitKey != "" {
		limit = max(limit, quotaLimitsValue(limits, self.FloorLimitKey))
	}
	return max(limit, self.MinLimit)
}

// Whether a purchase or a higher tier lifts a refusal under limits.
func (self *QuotaRateRule) Upgrade(limits *QuotaLimits) bool {
	return self.Tiered && limits != nil && limits.Tier != quotaTierTeam
}

// The refusal for a count that would pass the limit, used being what the window holding now has
// counted. It lifts when the window turns.
func (self *QuotaRateRule) Refusal(limits *QuotaLimits, used int64, now time.Time) *QuotaRefusal {
	return &QuotaRefusal{
		LimitKey:     self.RefusalLimitKey,
		Limit:        self.Limit(limits),
		Used:         used,
		RetryAfterMs: QuotaRetryAfterMs(now, self.Window.End(self.Window.Index(now))),
		Upgrade:      self.Upgrade(limits),
	}
}

// The network's closure pacing R (§20.7's closure row): evs_closure_uploads_per_s, never below 4, since
// §20.5 ignores a row that sets it and an unusable value must not slow erasure.
func QuotaClosurePacingPerS(limits *QuotaLimits) int64 {
	return max(quotaLimitsValue(limits, quotaLimitKeyClosureUploadsPerS), quotaClosurePacingMinPerS)
}

// One network's closure pacing (§20.7's closure row, as DESIGN-DETAILS 13.2.1 and QD-652 give it), the state a
// Quota keeps under {sq_<network_id>}. Each asking eraser holds one seat: a cell 1/R s wide, rounded up to the
// microsecond, at the tail of the network's seats, good from its instant to the end of its calendar second and
// lapsing with it. A seat is handed out only in a second that still has a free cell, its seats plus what it has
// taken if it is the current one being fewer than R; else at the start of the next second, which is empty,
// since no seat lies past the tail. An eraser whose seat is due takes and nothing else is checked, so the order
// asks arrive in decides only the order seatless erasers are seated in. The network takes at most R uploads in
// any second (P1), an eraser that asks at its seat's instant takes then whatever the others do (P3), a seat
// nobody uses costs its one cell (P4), and with k erasers asking each takes one upload every k/R s.
//
// Time is the network's clock, the latest any call brought, which never runs back: a caller behind it is judged
// as arriving at it. Every instant is kept in whole microseconds, as server's {sq_} script keeps them, so the
// two agree on any sequence of asks. Not safe for concurrent use: its Quota runs it under one lock or one script
// per network.
type QuotaClosurePacing struct {
	// the latest seat handed out
	tail time.Time
	// each asking eraser's seat
	eraserTurns map[connect.Id]time.Time
	// uploads taken in the second numbered secondIndex since the epoch
	secondIndex int64
	secondCount int64
	// the latest time any call brought
	clock time.Time
}

// A network's pacing with no eraser asking, as after a Redis loss.
func NewQuotaClosurePacing() *QuotaClosurePacing {
	return &QuotaClosurePacing{
		eraserTurns: map[connect.Id]time.Time{},
	}
}

// One cell at perS uploads a second: 10^6 / perS µs, rounded up, so R cells never fit in less than a second.
// A perS below 1 reads as 1.
func quotaClosurePacingSpacing(perS int64) time.Duration {
	perS = max(perS, 1)
	return time.Duration((1000*1000+perS-1)/perS) * time.Microsecond
}

// Moves the network's clock to now, in whole microseconds, when now is later; turns the second; and drops the
// seats of earlier seconds, which have lapsed. It answers the clock, which every rule reads as now.
func (self *QuotaClosurePacing) advance(now time.Time) time.Time {
	now = now.UTC().Truncate(time.Microsecond)
	if now.Before(self.clock) {
		now = self.clock
	}
	self.clock = now
	second := now.Unix()
	if self.secondIndex != second {
		self.secondIndex = second
		self.secondCount = 0
	}
	secondStart := time.Unix(second, 0).UTC()
	for eraserId, seat := range self.eraserTurns {
		if seat.Before(secondStart) {
			delete(self.eraserTurns, eraserId)
		}
	}
	return now
}

// Whether eraserId's seat is due at now (13.2.1's Ask). An eraser with no seat, or whose seat lapsed with its
// second, is seated first. False: the upload waits for seatTime, the refusal's retry_after_ms running to it from
// Clock, and the seat holds until its second ends. The answer counts nothing: Take does, once every other
// counter of the call passed. A Quota asks only when none refused, so an eraser its own rate or allowance
// refuses is given no seat.
func (self *QuotaClosurePacing) Ask(eraserId connect.Id, now time.Time, perS int64) (ok bool, seatTime time.Time, takenThisSecond int64) {
	now = self.advance(now)
	seat, holds := self.eraserTurns[eraserId]
	if !holds {
		seat = self.NextSeat(now, perS)
		self.eraserTurns[eraserId] = seat
	}
	return !now.Before(seat), seat, self.secondCount
}

// Takes the turn Ask allowed at now: counts the upload in its second and seats the eraser again at the tail,
// its seat removed before the new seat's second is counted, so the second's sum stays as it was (P2).
func (self *QuotaClosurePacing) Take(eraserId connect.Id, now time.Time, perS int64) {
	now = self.advance(now)
	self.secondCount += 1
	delete(self.eraserTurns, eraserId)
	self.eraserTurns[eraserId] = self.NextSeat(now, perS)
}

// A seat at the tail (13.2.1's NextSeat): a cell after the latest seat and never before now, moved to the start
// of the next second when its own second has no free cell. It moves the tail there and answers it. Ask and Take
// are the only callers that give the seat to an eraser; called alone, it spends a cell nobody holds.
func (self *QuotaClosurePacing) NextSeat(now time.Time, perS int64) time.Time {
	now = self.advance(now)
	perS = max(perS, 1)
	seat := self.tail.Add(quotaClosurePacingSpacing(perS))
	if seat.Before(now) {
		seat = now
	}
	second := seat.Unix()
	used := int64(0)
	for _, other := range self.eraserTurns {
		if other.Unix() == second {
			used += 1
		}
	}
	if second == now.Unix() {
		used += self.secondCount
	}
	if perS <= used {
		seat = time.Unix(second+1, 0).UTC()
	}
	self.tail = seat
	return seat
}

// How many erasers hold a seat, lapsed ones included until the next call drops them: k, while each asks.
func (self *QuotaClosurePacing) EraserCount() int {
	return len(self.eraserTurns)
}

// The network's clock: the latest time any call brought, which Ask judged at.
func (self *QuotaClosurePacing) Clock() time.Time {
	return self.clock
}

// The refusal for an upload asking before its seat: it lifts at liftTime, the seat, and now is the pacing's
// Clock. takenThisSecond is what the network took in the second of now.
func QuotaClosurePacingRefusal(limits *QuotaLimits, takenThisSecond int64, now time.Time, liftTime time.Time) *QuotaRefusal {
	return &QuotaRefusal{
		LimitKey:     quotaLimitKeyClosureUploadsPerS,
		Limit:        QuotaClosurePacingPerS(limits),
		Used:         takenThisSecond,
		RetryAfterMs: QuotaRetryAfterMs(now, liftTime),
	}
}
