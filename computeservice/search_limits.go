// A search's limits at the broker (DESIGN-COMPUTE §21.9, §9.11, §14.4; SRCH-M13-07), the second script of an
// admission, on slots of their own after the ledger's hold on {cmp_<network_id>} admits, so no script crosses a slot
// and either refusal undoes the hold (§14.4):
//
//	{cmpr_<network_id>}  the network's rate, 2 searches a second with bursts of 20, by GCRA (tat, the theoretical
//	                     arrival time in ms); its searches this UTC day (d, the day since the epoch, and c, its
//	                     count) against its limit, day_max where its policy sets one and 2,000 where it sets none,
//	                     never above §9.11's search cap, which the broker passes in; and the global window it last
//	                     searched in (w) with its count
//	                     there (wc), which {cmps}'s equal share reads. Refused: day, with the next UTC midnight;
//	                     rate, with the GCRA's wait. A key found absent is rebuilt from the day's search rows
//	                     (§9.7's lost cache), the script answering absent and the broker asking again with the day's
//	                     count
//	{cmps}               the payer's global rate in windows of GlobalWindow, GlobalWindowCount each: the window (w),
//	                     its searches (n), the networks active in it (a) and in the one before (pa), counts alone, no
//	                     network. A network takes a search while the window has room and its own count there is below
//	                     its equal share, the window's count over the networks active now or in the window before, so
//	                     every active network gets its share before any takes more. Refused: global, the window
//	                     full; share, the network past its share; each with the next window's start
//
// Both scripts take the broker's clock, which times the authorization's minute too, so a search's minute, its day and
// its window are one clock's. A {cmps} refusal refunds what {cmpr_<network_id>} took, so a refused search counts toward
// neither the network's rate nor its day.
//
// Numbers stay below 2^53 and leave Lua through string.format('%.0f'), as the projection's scripts keep them
// (model/compute_projection_scripts.go). Every command names KEYS[1], which sidecartest/crossslot reads. FakeRedis runs
// each script's Go twin (search_limits_twins_test.go), and T3 runs the Lua itself.
//
// Safe for concurrent use: the scripts are the serialization.

package computeservice

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// A UTC day, the unit {cmpr_<network_id>}'s count and day_max are of (§21.9): a fact of the calendar, not a tunable.
const computeSearchDay = 24 * time.Hour

// What the rate script answers.
type computeSearchRateOutcome string

const (
	computeSearchRateOk     computeSearchRateOutcome = "ok"
	computeSearchRateDay    computeSearchRateOutcome = "day"
	computeSearchRateRate   computeSearchRateOutcome = "rate"
	computeSearchRateAbsent computeSearchRateOutcome = "absent"
)

// What the limiter answers.
type computeSearchLimiterOutcome string

const (
	computeSearchLimiterOk     computeSearchLimiterOutcome = "ok"
	computeSearchLimiterGlobal computeSearchLimiterOutcome = "global"
	computeSearchLimiterShare  computeSearchLimiterOutcome = "share"
)

// The rate script. KEYS[1] {cmpr_<network_id>}. ARGV: now in ms, the GCRA's emission interval and tolerance in ms,
// the UTC day, the day's limit, the global window, the key's ttl in ms, and the day's count to seed an absent key
// with, empty to answer absent. Answers {outcome, retry ms, the day's count, the network's count in the window before
// this search, whether this is its first search there (1 or 0)}.
var computeSearchRateScript = &sidecar.RedisScript{
	Name: "compute_search_rate",
	Source: `
local function cs_int(value, what)
	if type(value) ~= 'string' or 16 < #value or not string.match(value, '^%d+$') then
		return error('compute search: ' .. what .. ' is no count')
	end
	return tonumber(value)
end
local function cs_str(number)
	return string.format('%.0f', number)
end
local now = cs_int(ARGV[1], 'now')
local emission = cs_int(ARGV[2], 'emission')
local tolerance = cs_int(ARGV[3], 'tolerance')
local day = ARGV[4]
local limit = cs_int(ARGV[5], 'limit')
local window = ARGV[6]
local ttl = cs_int(ARGV[7], 'ttl')
if redis.call('EXISTS', KEYS[1]) == 0 then
	if ARGV[8] == '' then
		return {'absent', '0', '0', '0', '0'}
	end
	redis.call('HSET', KEYS[1], 'd', day, 'c', cs_str(cs_int(ARGV[8], 'seed')))
end
local fields = redis.call('HMGET', KEYS[1], 'tat', 'd', 'c', 'w', 'wc')
local count = 0
if fields[2] == day and fields[3] then
	count = cs_int(fields[3], 'c')
end
if limit <= count then
	return {'day', '0', cs_str(count), '0', '0'}
end
local tat = now
if fields[1] then
	tat = math.max(now, cs_int(fields[1], 'tat'))
end
if tolerance < tat - now then
	return {'rate', cs_str(tat - tolerance - now), cs_str(count), '0', '0'}
end
local windowCount = 0
local first = '1'
if fields[4] == window and fields[5] then
	windowCount = cs_int(fields[5], 'wc')
	first = '0'
end
redis.call('HSET', KEYS[1], 'tat', cs_str(tat + emission), 'd', day, 'c', cs_str(count + 1), 'w', window, 'wc', cs_str(windowCount + 1))
redis.call('PEXPIRE', KEYS[1], ttl)
return {'ok', '0', cs_str(count + 1), cs_str(windowCount), first}
`,
}

// The rate script's refund of a search {cmps} refused. KEYS[1] {cmpr_<network_id>}. ARGV: the emission interval in
// ms, the UTC day and the window of the search. Answers 1 where the key stood, 0 where it did not.
var computeSearchRateRefundScript = &sidecar.RedisScript{
	Name: "compute_search_rate_refund",
	Source: `
local function cs_int(value, what)
	if type(value) ~= 'string' or 16 < #value or not string.match(value, '^%d+$') then
		return error('compute search: ' .. what .. ' is no count')
	end
	return tonumber(value)
end
local function cs_str(number)
	return string.format('%.0f', number)
end
local emission = cs_int(ARGV[1], 'emission')
if redis.call('EXISTS', KEYS[1]) == 0 then
	return 0
end
local fields = redis.call('HMGET', KEYS[1], 'tat', 'd', 'c', 'w', 'wc')
if fields[1] then
	redis.call('HSET', KEYS[1], 'tat', cs_str(math.max(0, cs_int(fields[1], 'tat') - emission)))
end
if fields[2] == ARGV[2] and fields[3] then
	redis.call('HSET', KEYS[1], 'c', cs_str(math.max(0, cs_int(fields[3], 'c') - 1)))
end
if fields[4] == ARGV[3] and fields[5] then
	redis.call('HSET', KEYS[1], 'wc', cs_str(math.max(0, cs_int(fields[5], 'wc') - 1)))
end
return 1
`,
}

// The global limiter. KEYS[1] {cmps}. ARGV: the window, its count, the network's count in the window before this
// search, whether this is its first search there (1 or 0), and the key's ttl in ms. Answers {outcome}.
var computeSearchLimiterScript = &sidecar.RedisScript{
	Name: "compute_search_limiter",
	Source: `
local function cs_int(value, what)
	if type(value) ~= 'string' or 16 < #value or not string.match(value, '^%d+$') then
		return error('compute search: ' .. what .. ' is no count')
	end
	return tonumber(value)
end
local function cs_str(number)
	return string.format('%.0f', number)
end
local window = cs_int(ARGV[1], 'window')
local capacity = cs_int(ARGV[2], 'capacity')
local own = cs_int(ARGV[3], 'own')
local ttl = cs_int(ARGV[5], 'ttl')
local fields = redis.call('HMGET', KEYS[1], 'w', 'n', 'a', 'pa')
local taken = 0
local active = 0
local previous = 0
if fields[1] then
	local stored = cs_int(fields[1], 'w')
	if stored == window then
		taken = cs_int(fields[2] or '0', 'n')
		active = cs_int(fields[3] or '0', 'a')
		previous = cs_int(fields[4] or '0', 'pa')
	elseif stored + 1 == window then
		previous = cs_int(fields[3] or '0', 'a')
	end
end
if ARGV[4] == '1' then
	active = active + 1
end
local share = math.max(1, math.floor(capacity / math.max(1, active, previous)))
local outcome = 'ok'
if capacity <= taken then
	outcome = 'global'
elseif share <= own then
	outcome = 'share'
else
	taken = taken + 1
end
redis.call('HSET', KEYS[1], 'w', cs_str(window), 'n', cs_str(taken), 'a', cs_str(active), 'pa', cs_str(previous))
redis.call('PEXPIRE', KEYS[1], ttl)
return {outcome}
`,
}

// What a network's rate script answered.
type computeSearchRateAnswer struct {
	outcome    computeSearchRateOutcome
	retryAfter time.Duration
	// The network's searches today, this one included where it was taken.
	dayCount int64
	// The network's searches in this global window before this one, and whether this is its first there.
	windowCount int64
	windowFirst bool
}

// One admission's place on the broker's clock: its UTC day, its global window, and when each next one starts.
type computeSearchClock struct {
	now         time.Time
	nowMs       int64
	day         int64
	nextDay     time.Time
	window      int64
	nextWindow  time.Time
	dayStr      string
	windowStr   string
	dayStartUtc time.Time
}

// The admission's day and window at now.
func (self *ComputeSearchSettings) clockAt(now time.Time) *computeSearchClock {
	nowMs := now.UnixMilli()
	dayMs := computeSearchDay.Milliseconds()
	windowMs := self.GlobalWindow.Milliseconds()
	day := nowMs / dayMs
	window := nowMs / windowMs
	return &computeSearchClock{
		now:         now,
		nowMs:       nowMs,
		day:         day,
		nextDay:     time.UnixMilli((day + 1) * dayMs).UTC(),
		window:      window,
		nextWindow:  time.UnixMilli((window + 1) * windowMs).UTC(),
		dayStr:      strconv.FormatInt(day, 10),
		windowStr:   strconv.FormatInt(window, 10),
		dayStartUtc: time.UnixMilli(day * dayMs).UTC(),
	}
}

// The reply's strings, at least count of them.
func computeSearchReplyStrings(reply *sidecar.RedisReply, count int) ([]string, error) {
	if reply == nil || reply.Kind != sidecar.RedisReplyArray || len(reply.Replies) < count {
		return nil, errors.New("compute search: a script's reply is not its array")
	}
	values := make([]string, len(reply.Replies))
	for i, value := range reply.Replies {
		if value == nil || value.Kind != sidecar.RedisReplyBulk {
			return nil, errors.New("compute search: a script's reply holds no string")
		}
		values[i] = string(value.Bulk)
	}
	return values, nil
}

// A count a script answered.
func computeSearchReplyCount(value string) (int64, error) {
	count, err := strconv.ParseInt(value, 10, 64)
	if err != nil || count < 0 {
		return 0, fmt.Errorf("compute search: a script answered %q for a count", value)
	}
	return count, nil
}

// A network's search cap as a broker instance last read it from the ledger (§9.11), each kept SearchCapCacheMaxAge.
// Safe for concurrent use.
type computeSearchCapCache struct {
	stateLock sync.Mutex
	// by network
	networkIdCaps map[sidecar.Id]*computeSearchCapEntry
}

// One network's cap and when it was read.
type computeSearchCapEntry struct {
	searchCap int64
	readTime  time.Time
}

// The broker's limits for one engine. Safe for concurrent use.
type computeSearchLimits struct {
	engine   *ComputeEngine
	settings *ComputeSearchSettings
	ledger   func() ComputeSearchLedger
	caps     computeSearchCapCache
}

// Takes one search of networkId's rate and day under limit, at clock (see the file header). seed is the day's count
// to rebuild an absent key with, nil to answer absent.
func (self *computeSearchLimits) rateTake(ctx context.Context, networkId sidecar.Id, clock *computeSearchClock, limit int64, seed *int64) (*computeSearchRateAnswer, error) {
	key := ComputeSearchRateRedisKey(networkId)
	redis, err := self.engine.MainRedis(key)
	if err != nil {
		return nil, err
	}
	emission, tolerance := self.settings.networkRateMillis()
	seedStr := ""
	if seed != nil {
		seedStr = strconv.FormatInt(max(0, *seed), 10)
	}
	reply, err := redis.RunScript(ctx, computeSearchRateScript, []string{key}, []string{
		strconv.FormatInt(clock.nowMs, 10),
		strconv.FormatInt(emission, 10),
		strconv.FormatInt(tolerance, 10),
		clock.dayStr,
		strconv.FormatInt(max(0, limit), 10),
		clock.windowStr,
		strconv.FormatInt(max(1, self.settings.NetworkRateKeyTtl.Milliseconds()), 10),
		seedStr,
	})
	if err != nil {
		return nil, err
	}
	values, err := computeSearchReplyStrings(reply, 5)
	if err != nil {
		return nil, err
	}
	answer := &computeSearchRateAnswer{outcome: computeSearchRateOutcome(values[0]), windowFirst: values[4] == "1"}
	retryMs, err := computeSearchReplyCount(values[1])
	if err != nil {
		return nil, err
	}
	answer.retryAfter = time.Duration(retryMs) * time.Millisecond
	if answer.dayCount, err = computeSearchReplyCount(values[2]); err != nil {
		return nil, err
	}
	if answer.windowCount, err = computeSearchReplyCount(values[3]); err != nil {
		return nil, err
	}
	switch answer.outcome {
	case computeSearchRateOk, computeSearchRateRate, computeSearchRateAbsent:
	case computeSearchRateDay:
		answer.retryAfter = clock.nextDay.Sub(clock.now)
	default:
		return nil, fmt.Errorf("compute search: the rate script answered %q", values[0])
	}
	return answer, nil
}

// Gives back what rateTake took at clock, after {cmps} refused the search.
func (self *computeSearchLimits) rateRefund(ctx context.Context, networkId sidecar.Id, clock *computeSearchClock) error {
	key := ComputeSearchRateRedisKey(networkId)
	redis, err := self.engine.MainRedis(key)
	if err != nil {
		return err
	}
	emission, _ := self.settings.networkRateMillis()
	_, err = redis.RunScript(ctx, computeSearchRateRefundScript, []string{key}, []string{
		strconv.FormatInt(emission, 10),
		clock.dayStr,
		clock.windowStr,
	})
	return err
}

// Takes one search of the payer's global rate in clock's window, for a network with windowCount searches there
// before it (see the file header).
func (self *computeSearchLimits) limiterTake(ctx context.Context, clock *computeSearchClock, windowCount int64, windowFirst bool) (computeSearchLimiterOutcome, error) {
	key := ComputeSearchLimiterRedisKey()
	redis, err := self.engine.MainRedis(key)
	if err != nil {
		return "", err
	}
	first := "0"
	if windowFirst {
		first = "1"
	}
	reply, err := redis.RunScript(ctx, computeSearchLimiterScript, []string{key}, []string{
		clock.windowStr,
		strconv.Itoa(self.settings.GlobalWindowCount),
		strconv.FormatInt(windowCount, 10),
		first,
		strconv.FormatInt(max(1, self.settings.LimiterKeyTtl.Milliseconds()), 10),
	})
	if err != nil {
		return "", err
	}
	values, err := computeSearchReplyStrings(reply, 1)
	if err != nil {
		return "", err
	}
	outcome := computeSearchLimiterOutcome(values[0])
	switch outcome {
	case computeSearchLimiterOk, computeSearchLimiterGlobal, computeSearchLimiterShare:
		return outcome, nil
	}
	return "", fmt.Errorf("compute search: the limiter answered %q", values[0])
}

// What the two scripts came to for one admission: taken, with the network's searches today, or refused.
type computeSearchLimitsAnswer struct {
	refusal  *ComputeRefusal
	dayCount int64
}

// The refusal reasons of rate_limited at the broker: which limit refused.
const (
	ComputeSearchRateLimitedReasonDay    = "day"
	ComputeSearchRateLimitedReasonRate   = "rate"
	ComputeSearchRateLimitedReasonGlobal = "global"
)

// Takes one search of networkId's limits at clock: its rate and day under the day's limit (dayMax where the policy
// sets one, else DefaultDayMaxCount, never above the search cap), then the payer's global rate, refunding the first
// where the second refuses.
// An absent rate key is rebuilt from the day's search rows and asked once more.
func (self *computeSearchLimits) take(ctx context.Context, networkId sidecar.Id, clock *computeSearchClock, dayMax uint32) (*computeSearchLimitsAnswer, error) {
	limit, err := self.dayLimit(ctx, networkId, dayMax, clock.now)
	if err != nil {
		return nil, err
	}
	rate, err := self.rateTake(ctx, networkId, clock, limit, nil)
	if err != nil {
		return nil, err
	}
	if rate.outcome == computeSearchRateAbsent {
		ledger := self.ledger()
		if ledger == nil {
			return nil, errComputeSearchNoLedger
		}
		count, err := ledger.SearchCount(ctx, networkId, clock.dayStartUtc)
		if err != nil {
			return nil, err
		}
		// the day's rows include this admission's own, held just before: the rebuilt count is the searches before it
		seed := max(0, count-1)
		if rate, err = self.rateTake(ctx, networkId, clock, limit, &seed); err != nil {
			return nil, err
		}
	}
	switch rate.outcome {
	case computeSearchRateOk:
	case computeSearchRateDay:
		return &computeSearchLimitsAnswer{refusal: &ComputeRefusal{Code: ComputeRefusalRateLimited, Reason: ComputeSearchRateLimitedReasonDay, RetryAfter: rate.retryAfter}}, nil
	case computeSearchRateRate:
		return &computeSearchLimitsAnswer{refusal: &ComputeRefusal{Code: ComputeRefusalRateLimited, Reason: ComputeSearchRateLimitedReasonRate, RetryAfter: rate.retryAfter}}, nil
	default:
		return nil, fmt.Errorf("compute search: the rate script answered %s for a seeded key", rate.outcome)
	}
	outcome, err := self.limiterTake(ctx, clock, rate.windowCount, rate.windowFirst)
	if err == nil && outcome == computeSearchLimiterOk {
		return &computeSearchLimitsAnswer{dayCount: rate.dayCount}, nil
	}
	// a refusal, or a limiter that did not answer: what the rate took goes back, and the search is not admitted
	if refundErr := self.rateRefund(ctx, networkId, clock); refundErr != nil {
		self.engine.alarm("search_rate_refund", "a network's search rate kept a search {cmps} refused")
	}
	if err != nil {
		return nil, err
	}
	return &computeSearchLimitsAnswer{refusal: &ComputeRefusal{Code: ComputeRefusalRateLimited, Reason: ComputeSearchRateLimitedReasonGlobal, RetryAfter: clock.nextWindow.Sub(clock.now)}}, nil
}

// The day's limit for networkId: the policy's day_max where it sets one (dayMax, 0 for none), else DefaultDayMaxCount,
// never above the search cap the ledger gives.
func (self *computeSearchLimits) dayLimit(ctx context.Context, networkId sidecar.Id, dayMax uint32, now time.Time) (int64, error) {
	searchCap, err := self.searchCap(ctx, networkId, now)
	if err != nil {
		return 0, err
	}
	limit := int64(self.settings.DefaultDayMaxCount)
	if 0 < dayMax {
		limit = int64(dayMax)
	}
	return min(limit, searchCap), nil
}

// networkId's search cap, from the cache while it is fresh, else the ledger's.
func (self *computeSearchLimits) searchCap(ctx context.Context, networkId sidecar.Id, now time.Time) (int64, error) {
	maxAge := self.settings.SearchCapCacheMaxAge
	cached := func() (int64, bool) {
		self.caps.stateLock.Lock()
		defer self.caps.stateLock.Unlock()
		entry := self.caps.networkIdCaps[networkId]
		if entry == nil || maxAge <= 0 || maxAge <= now.Sub(entry.readTime) {
			return 0, false
		}
		return entry.searchCap, true
	}
	if searchCap, ok := cached(); ok {
		return searchCap, nil
	}
	ledger := self.ledger()
	if ledger == nil {
		return 0, errComputeSearchNoLedger
	}
	searchCap, err := ledger.SearchCap(ctx, networkId)
	if err != nil {
		return 0, err
	}
	func() {
		self.caps.stateLock.Lock()
		defer self.caps.stateLock.Unlock()
		if self.caps.networkIdCaps == nil || self.settings.CacheMaxCount <= len(self.caps.networkIdCaps) {
			self.caps.networkIdCaps = map[sidecar.Id]*computeSearchCapEntry{}
		}
		self.caps.networkIdCaps[networkId] = &computeSearchCapEntry{searchCap: searchCap, readTime: now}
	}()
	return searchCap, nil
}

// No ledger to ask: an engine built with none, which answers capacity.
var errComputeSearchNoLedger = errors.New("compute search: no ledger")
