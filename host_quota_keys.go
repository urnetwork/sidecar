//go:build !sidecar_http

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
// count lands in is the Quota's to tell from its clock, so no key carries a time. A replayed debit id
// answers its first result, a refusal included (QUOTA-M2-03), so a caller asking again after a refusal's
// retry_after_ms takes a new debit id.
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

// One network's closure pacing (§20.7's closure row; plan-QUOTA-small-readings reading 19), the state a
// Quota keeps under {sq_<network_id>}: each asking eraser holds one slot on a tail spaced 1/R apart; a
// refused ask keeps its slot, so an eraser that waits out a long retry_after_ms keeps its place against
// erasers asking every second; a taken turn takes a new slot at the tail; a slot lapses horizon past
// its turn; and a bucket of R a second bounds the network when erasers whose turns have passed come
// back together, as at 00:00 UTC. With k erasers asking, each takes one upload every k/R s, and none
// starves. Not safe for concurrent use: its Quota runs it under one lock or one script per network.
type QuotaClosurePacing struct {
	// the latest slot handed out
	tail time.Time
	// each asking eraser's slot: when its next turn comes
	eraserTurns map[connect.Id]time.Time
	// uploads taken in the second numbered secondIndex since the epoch
	secondIndex int64
	secondCount int64
}

// A network's pacing with no eraser asking, as after a Redis loss.
func NewQuotaClosurePacing() *QuotaClosurePacing {
	return &QuotaClosurePacing{
		eraserTurns: map[connect.Id]time.Time{},
	}
}

// The time between slots at perS uploads a second.
func quotaClosurePacingSpacing(perS int64) time.Duration {
	return time.Second / time.Duration(max(perS, 1))
}

// Whether eraserId may take an upload at now. An eraser with no slot, or one whose slot lapsed, takes
// one at the tail first. False: the upload waits until liftTime, its turn or the next second, and
// keeps its slot. The answer counts nothing: Take does, once every other count of the call passes.
func (self *QuotaClosurePacing) Ask(eraserId connect.Id, now time.Time, perS int64, horizon time.Duration) (ok bool, liftTime time.Time, takenThisSecond int64) {
	for otherId, turnTime := range self.eraserTurns {
		if turnTime.Add(horizon).Before(now) {
			delete(self.eraserTurns, otherId)
		}
	}
	turnTime, holds := self.eraserTurns[eraserId]
	if !holds {
		turnTime = self.nextSlot(now, perS)
		self.eraserTurns[eraserId] = turnTime
	}
	second := now.Unix()
	if self.secondIndex != second {
		self.secondIndex = second
		self.secondCount = 0
	}
	if now.Before(turnTime) {
		return false, turnTime, self.secondCount
	}
	if perS <= self.secondCount {
		return false, time.Unix(second+1, 0).UTC(), self.secondCount
	}
	return true, time.Time{}, self.secondCount
}

// Takes the turn Ask allowed: counts the upload in its second and gives the eraser its next slot, at
// the tail.
func (self *QuotaClosurePacing) Take(eraserId connect.Id, now time.Time, perS int64) {
	second := now.Unix()
	if self.secondIndex != second {
		self.secondIndex = second
		self.secondCount = 0
	}
	self.secondCount += 1
	self.eraserTurns[eraserId] = self.nextSlot(now, perS)
}

// A new slot at the tail: 1/R after the latest, and never before now.
func (self *QuotaClosurePacing) nextSlot(now time.Time, perS int64) time.Time {
	slot := self.tail.Add(quotaClosurePacingSpacing(perS))
	if slot.Before(now) {
		slot = now
	}
	self.tail = slot
	return slot
}

// How many erasers hold a slot: k, while each asks.
func (self *QuotaClosurePacing) EraserCount() int {
	return len(self.eraserTurns)
}

// The refusal for an upload asking before its turn, or past R this second: it lifts at liftTime.
// takenThisSecond is what the network took in the second of now.
func QuotaClosurePacingRefusal(limits *QuotaLimits, takenThisSecond int64, now time.Time, liftTime time.Time) *QuotaRefusal {
	return &QuotaRefusal{
		LimitKey:     quotaLimitKeyClosureUploadsPerS,
		Limit:        QuotaClosurePacingPerS(limits),
		Used:         takenThisSecond,
		RetryAfterMs: QuotaRetryAfterMs(now, liftTime),
	}
}
