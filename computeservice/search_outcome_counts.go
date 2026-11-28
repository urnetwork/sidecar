// {cmpo}, this hour's search outcome counts by class across all networks (DESIGN-COMPUTE §21.8, §14.4, compute-11;
// SRCH-M13-07): a device's unreported outcomes ride its next search authorization, or its daily report
// (SRCH-M13-09's POST compute/v1/search/outcomes), and the broker adds them at once to the hour's count of each class,
// the network seen in transit alone and kept nowhere: no field names a network, a sidecar or an agent. The hash's
// fields are <hour>:<class>, the hour its start in Unix seconds and the class §21.8's word, each outliving its last
// count by OutcomesKeyTtl, so compute_search_outcomes (SRCH-M13-09) moves a closed hour into
// compute_search_outcome_hour before its fields go. Each count is also urnetwork_compute_search_outcomes_total{class},
// which the monitor's failure rate reads (§14.7).
//
// The script names KEYS[1] in every command, which sidecartest/crossslot reads. Safe for concurrent use.

package computeservice

import (
	"context"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
)

// The outcome counts' script. KEYS[1] {cmpo}. ARGV: the hour, the fields' ttl in ms, then the counts of ok,
// provider_error, timeout and refused. Answers ok.
var computeSearchOutcomesScript = &sidecar.RedisScript{
	Name: "compute_search_outcomes",
	Source: `
local function cs_int(value, what)
	if type(value) ~= 'string' or 16 < #value or not string.match(value, '^%d+$') then
		return error('compute search: ' .. what .. ' is no count')
	end
	return tonumber(value)
end
local hour = cs_int(ARGV[1], 'hour')
local ttl = cs_int(ARGV[2], 'ttl')
local classes = {'ok', 'provider_error', 'timeout', 'refused'}
for i = 1, 4 do
	local count = cs_int(ARGV[2 + i], classes[i])
	if 0 < count then
		local field = string.format('%.0f', hour) .. ':' .. classes[i]
		redis.call('HINCRBY', KEYS[1], field, count)
		redis.call('HPEXPIRE', KEYS[1], ttl, 'FIELDS', 1, field)
	end
end
return 'ok'
`,
}

// The field of an hour's class in {cmpo}: <hour>:<class>.
func computeSearchOutcomeField(hour time.Time, outcome model.ComputeSearchOutcome) string {
	return strconv.FormatInt(hour.Unix(), 10) + ":" + outcome.String()
}

// The counts of outcomes by class.
func computeSearchOutcomeClassCounts(outcomes *protocol.SearchOutcomes) map[model.ComputeSearchOutcome]int64 {
	return map[model.ComputeSearchOutcome]int64{
		model.ComputeSearchOutcomeOk:            int64(outcomes.GetOk()),
		model.ComputeSearchOutcomeProviderError: int64(outcomes.GetProviderError()),
		model.ComputeSearchOutcomeTimeout:       int64(outcomes.GetTimeout()),
		model.ComputeSearchOutcomeRefused:       int64(outcomes.GetRefused()),
	}
}

// Their total.
func computeSearchOutcomesTotal(outcomes *protocol.SearchOutcomes) int64 {
	total := int64(0)
	for _, count := range computeSearchOutcomeClassCounts(outcomes) {
		total += count
	}
	return total
}

// The hour now falls in, its start.
func (self *ComputeSearchSettings) outcomeHourAt(now time.Time) time.Time {
	return now.UTC().Truncate(self.OutcomeHour)
}

// {cmpo} and the outcomes' counter for one engine. Safe for concurrent use.
type computeSearchOutcomeCounts struct {
	engine   *ComputeEngine
	settings *ComputeSearchSettings
	counter  sidecar.MetricsCounter
}

// The counts for engine, declaring the counter on its host's metrics.
func newComputeSearchOutcomeCounts(engine *ComputeEngine, settings *ComputeSearchSettings) *computeSearchOutcomeCounts {
	return &computeSearchOutcomeCounts{
		engine:   engine,
		settings: settings,
		counter:  engine.host.Metrics.Counter("urnetwork_compute_search_outcomes_total", "search outcome classes across all networks", "class"),
	}
}

// Adds outcomes to the hour of now, across all networks. Nothing to add writes nothing.
func (self *computeSearchOutcomeCounts) add(ctx context.Context, outcomes *protocol.SearchOutcomes, now time.Time) error {
	if outcomes == nil || computeSearchOutcomesTotal(outcomes) == 0 {
		return nil
	}
	key := ComputeSearchOutcomesRedisKey()
	redis, err := self.engine.MainRedis(key)
	if err != nil {
		return err
	}
	counts := computeSearchOutcomeClassCounts(outcomes)
	args := []string{
		strconv.FormatInt(self.settings.outcomeHourAt(now).Unix(), 10),
		strconv.FormatInt(max(1, self.settings.OutcomesKeyTtl.Milliseconds()), 10),
	}
	for _, outcome := range model.ComputeSearchOutcomes {
		args = append(args, strconv.FormatInt(counts[outcome], 10))
	}
	if _, err := redis.RunScript(ctx, computeSearchOutcomesScript, []string{key}, args); err != nil {
		return err
	}
	for _, outcome := range model.ComputeSearchOutcomes {
		if count := counts[outcome]; 0 < count {
			self.counter.Add(float64(count), outcome.String())
		}
	}
	return nil
}
