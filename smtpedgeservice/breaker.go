// §14.7's Community breaker (D-SMTP-14, plan-SMTP-shared-counters): Community connections are capped per
// UTC hour, across the fleet, at the larger of smtp_community_connections_per_hour and
// smtp_community_median_multiple times the trailing 7-day hourly median, which a taskworker job writes to
// {smg_median} each hour; a missing median means the floor. Each Community preamble the network's own
// quota passed counts on {smg_<yyyymmddhh>} with one single-key script, and past the cap the count is
// taken back and the preamble answered TRY_LATER until the next hour, the trip counted for §19's alert.
//
// The median is read off the path, each BreakerMedianRefreshInterval, so a preamble waits on one script.
// A counter whose script does not answer counts nothing and refuses nothing: Redis's loss restarts the
// counters, as §14.9 accepts. This is §14.7's breaker, not §21.5's, which the gate reads
// (SmtpBreakerState).
//
// Safe for concurrent use.

package smtpedgeservice

import (
	"context"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
)

// The trips' kinds, for §19's alert.
const (
	smtpBreakerTripCommunity   = "community"
	smtpBreakerTripDestination = "destination"
)

// The key a taskworker job writes the trailing median to (plan-SMTP-shared-counters#2).
const smtpBreakerMedianKey = "{smg_median}"

// The Community total's key for the UTC hour holding at.
func smtpBreakerHourKey(at time.Time) string {
	return "{smg_" + at.UTC().Format("2006010215") + "}"
}

// The UTC hour holding at, and how long its counter lives from now: until 2 h after the hour starts.
func smtpHourWindow(at time.Time, settings *SmtpEdgeSettings) (start time.Time, ttl time.Duration) {
	start = at.UTC().Truncate(time.Hour)
	return start, start.Add(settings.HourCounterTimeout).Sub(at)
}

// What the median read last found.
type smtpBreakerMedian struct {
	// Whether {smg_median} held a count.
	found bool
	value int64
	// Reads finished, so a test can await one.
	readCount int
}

// The Community hourly breaker of one edge process: the fleet counter it counts on and the median it
// reads, which a run loop refreshes.
type SmtpBreaker struct {
	redis    sidecar.Redis
	clock    sidecar.Clock
	settings *SmtpEdgeSettings
	trips    sidecar.MetricsCounter

	median   *sidecar.MonitorValue[smtpBreakerMedian]
	cancel   context.CancelFunc
	released chan struct{}
}

// Starts the median's refresh, which runs until ctx ends or Close.
func newSmtpBreaker(ctx context.Context, redis sidecar.Redis, clock sidecar.Clock, metrics sidecar.Metrics, settings *SmtpEdgeSettings) *SmtpBreaker {
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &SmtpBreaker{
		redis:    redis,
		clock:    clock,
		settings: settings,
		trips: metrics.Counter("urnetwork_smtpedge_breaker_trips_total",
			"Community preambles §14.7's fleet counters refused, by counter.", "kind"),
		median:   sidecar.NewMonitorValue(smtpBreakerMedian{}),
		cancel:   cancel,
		released: make(chan struct{}),
	}
	go self.run(cancelCtx)
	return self
}

// Reads the median now and each BreakerMedianRefreshInterval.
func (self *SmtpBreaker) run(ctx context.Context) {
	defer close(self.released)
	for {
		self.refreshMedian(ctx)
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(self.settings.BreakerMedianRefreshInterval):
		}
	}
}

// One read of {smg_median}. A read that fails keeps what the last found.
func (self *SmtpBreaker) refreshMedian(ctx context.Context) {
	callCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(self.settings.QuotaCallTimeout, cancel)
	value, found, err := self.redis.Get(callCtx, smtpBreakerMedianKey)
	stop()
	cancel()
	self.median.Update(func(median smtpBreakerMedian) smtpBreakerMedian {
		median.readCount += 1
		if err != nil {
			return median
		}
		median.found = false
		median.value = 0
		if found {
			if parsed, err := strconv.ParseInt(string(value), 10, 64); err == nil && 0 <= parsed {
				median.found = true
				median.value = parsed
			}
		}
		return median
	})
}

// The hour's cap under limits' sidecar_abuse: keys: max(floor, multiple × median), the floor alone with
// no median. -1 for none.
func (self *SmtpBreaker) Cap(limits *sidecar.QuotaLimits) int64 {
	floor := smtpLimit(limits, SmtpLimitCommunityConnectionsPerHour)
	if floor == -1 {
		return -1
	}
	median := self.median.Value()
	if !median.found {
		return floor
	}
	multiple := smtpLimit(limits, SmtpLimitCommunityMedianMultiple)
	if multiple == -1 {
		return -1
	}
	return max(floor, multiple*median.value)
}

// Counts one Community connection on the hour's total. False past the cap, with how long until the next
// hour; a script that does not answer passes.
func (self *SmtpBreaker) admit(ctx context.Context, limits *sidecar.QuotaLimits, now time.Time) (retryAfter time.Duration, ok bool) {
	hourStart, ttl := smtpHourWindow(now, self.settings)
	counted, err := runSmtpHourCount(ctx, self.redis, self.clock, self.settings, smtpBreakerHourKey(now), self.Cap(limits), ttl)
	if err != nil || counted {
		return 0, true
	}
	self.trips.Add(1, smtpBreakerTripCommunity)
	return hourStart.Add(time.Hour).Sub(now), false
}

// Stops the median's refresh and waits for it.
func (self *SmtpBreaker) Close() {
	self.cancel()
	<-self.released
}

// One hour counter's count: whether it counted, under QuotaCallTimeout.
func runSmtpHourCount(ctx context.Context, redis sidecar.Redis, clock sidecar.Clock, settings *SmtpEdgeSettings, key string, cap int64, ttl time.Duration) (bool, error) {
	callCtx, cancel := context.WithCancel(ctx)
	stop := clock.AfterFunc(settings.QuotaCallTimeout, cancel)
	defer func() {
		stop()
		cancel()
	}()
	reply, err := redis.RunScript(callCtx, SmtpHourCountScript, []string{key}, []string{
		strconv.FormatInt(cap, 10),
		strconv.FormatInt(max(ttl.Milliseconds(), 1), 10),
	})
	if err != nil {
		return false, err
	}
	if reply == nil || reply.Kind != sidecar.RedisReplyArray || len(reply.Replies) != 2 || reply.Replies[0].Kind != sidecar.RedisReplyInteger {
		return false, errSmtpHourCountReply
	}
	return reply.Replies[0].Integer == 1, nil
}
