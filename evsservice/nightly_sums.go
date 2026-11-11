// The nightly count's sums in Redis and its closing job (§20.7's count row, §11.13's bytes row; owner decision 198;
// EVSB-M2-26). The nightly pass runs as shard jobs, one shard of one metadata cluster each, and a network's repos fall
// in every shard and on every metadata cluster, so no shard job holds a network's count. Each shard job that counted
// its whole shard replaces its sums for the night here, and the closing job writes each network's count once every
// shard of every metadata cluster has reported.
//
//	key      {evsn_<night>}, one hash a night (evs-9's row), <night> the nightly start's time in Unix ms, so a night's
//	         every write and read is on one slot
//	field    <cluster>:<shard>, the shard's report: the fields present are the set of shards that reported. A shard
//	         whose count takes several runs keeps the sums of the runs so far under <cluster>:<shard>#<part>, which
//	         the run after reads and the closing job never does
//	value    stored bytes by network: 24 B a network, its 16 B id then the count as a big-endian uint64, in id
//	         order, and nothing else (evs-9: network ids and byte counts); empty for a shard with no network, which
//	         is its marker
//	ttl      NightlySumsTtl, 48 h, from the night's first write (PEXPIRE NX), never more (§2.8's ttl); the family is
//	         soft state outside the rdb bundles (D-OPS-16), and a lost key costs one night's count
//
// A write is one script, HSET of one field and PEXPIRE NX of the key, so a rerun replaces what it wrote and never adds
// to it, and the key never stands without its ttl. The sums cross Lua only as the value's bytes, never as numbers.
//
// The closing job (RunNightlyClose) asks which expected shards have not reported, in one script of HEXISTS. While one
// has not it asks again every NightlyCloseRetryInterval until the night is NightlySumsTtl old, then ends and writes
// nothing, so an unfinished night keeps the old count. Once all have, it reads each shard's field and sums each
// network across them: a field gone between the two reads is a lost night, which writes nothing. Then it writes each
// summed network's count, and zero for each network holding a count that no sum names, through NightlyCountStore,
// which taskworker implements over model.SetNetworkStoredByteCount (CONTRACTS.md). It is the one writer of a count,
// and idempotent: a rerun reads the same sums and writes the same counts.

package evsservice

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The closing job's name in taskworker's registry.
const EvsNightlyCloseTaskName = "evs.nightly_close"

// §2.8's ttl for {evsn_}, which no setting passes.
const evsNightlySumsMaxTtl = 48 * time.Hour

// One network in a shard's value: its id, then its stored bytes.
const evsNightlySumsEntryByteCount = 16 + 8

// A shard's value that is no list of networks and counts in id order. Read again it is the same bytes, so the
// night is lost rather than retried.
var ErrNightlySumsValue = errors.New("evs nightly sums value unread")

// The count store is not there on this build: nothing to write to, so the closing job ends.
var ErrNightlyCountsUnavailable = errors.New("evs nightly counts unavailable")

// Where the closing job writes each network's stored count: server's network_quota_state, which taskworker gives
// through model (CONTRACTS.md: model.SetNetworkStoredByteCount), so no engine imports server. Either method answers
// ErrNightlyCountsUnavailable when this build has no such table.
type NightlyCountStore interface {
	// The network's stored count is storedByteCount, an absolute write.
	SetStoredByteCount(ctx context.Context, networkId sidecar.Id, storedByteCount int64) error
	// Up to limit networks whose stored count is above zero, in id order after after (nil: from the first).
	NetworkIdsWithStoredByteCount(ctx context.Context, after *sidecar.Id, limit int) ([]sidecar.Id, error)
}

var (
	// Writes one field of a night and gives the key its ttl if it has none. KEYS[1] {evsn_<night>}; ARGV the field,
	// its value, the ttl in ms. 1.
	nightlySumsWriteScript = &sidecar.RedisScript{
		Name: "evs_nightly_sums_write",
		Source: `
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3], 'NX')
return 1
`,
	}
	// The fields of ARGV the night's key lacks, in ARGV's order. KEYS[1] {evsn_<night>}; ARGV the fields expected.
	nightlySumsMissingScript = &sidecar.RedisScript{
		Name: "evs_nightly_sums_missing",
		Source: `
local missing = {}
for index = 1, #ARGV do
	if redis.call('HEXISTS', KEYS[1], ARGV[index]) == 0 then
		missing[#missing + 1] = ARGV[index]
	end
end
return missing
`,
	}
)

// {evsn_<night>}: the night's one key.
func NightlySumsKey(night int64) string {
	return "{evsn_" + strconv.FormatInt(night, 10) + "}"
}

// <cluster>:<shard>: a shard's report in its night's key.
func NightlyShardField(clusterId string, shard string) string {
	return clusterId + ":" + shard
}

// <cluster>:<shard>#<part>: the sums of a shard's first part runs, which its next run reads.
func nightlyShardPartField(clusterId string, shard string, part int) string {
	return NightlyShardField(clusterId, shard) + "#" + strconv.Itoa(part)
}

// A night's time.
func nightlyNightTime(night int64) time.Time {
	return time.UnixMilli(night)
}

// The value of a shard's field: each network's id and count, in id order. A negative count is refused.
func encodeNightlySums(networkByteCounts map[sidecar.Id]int64) ([]byte, error) {
	networkIds := slices.SortedFunc(maps.Keys(networkByteCounts), func(a sidecar.Id, b sidecar.Id) int {
		return bytes.Compare(a[:], b[:])
	})
	value := make([]byte, 0, len(networkIds)*evsNightlySumsEntryByteCount)
	for _, networkId := range networkIds {
		byteCount := networkByteCounts[networkId]
		if byteCount < 0 {
			return nil, fmt.Errorf("%w: a count of %d bytes", ErrNightlySumsValue, byteCount)
		}
		value = append(value, networkId[:]...)
		value = binary.BigEndian.AppendUint64(value, uint64(byteCount))
	}
	return value, nil
}

// A shard's field back to its counts. Anything but whole entries in strictly rising id order, each count within an
// int64, is ErrNightlySumsValue.
func decodeNightlySums(value []byte) (map[sidecar.Id]int64, error) {
	if len(value)%evsNightlySumsEntryByteCount != 0 {
		return nil, fmt.Errorf("%w: %d bytes", ErrNightlySumsValue, len(value))
	}
	networkByteCounts := map[sidecar.Id]int64{}
	var previous []byte
	for offset := 0; offset < len(value); offset += evsNightlySumsEntryByteCount {
		idBytes := value[offset : offset+16]
		if previous != nil && bytes.Compare(previous, idBytes) >= 0 {
			return nil, fmt.Errorf("%w: networks out of order", ErrNightlySumsValue)
		}
		byteCount := binary.BigEndian.Uint64(value[offset+16 : offset+evsNightlySumsEntryByteCount])
		if math.MaxInt64 < byteCount {
			return nil, fmt.Errorf("%w: a count past an int64", ErrNightlySumsValue)
		}
		networkId, err := sidecar.IdFromBytes(idBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNightlySumsValue, err)
		}
		networkByteCounts[networkId] = int64(byteCount)
		previous = idBytes
	}
	return networkByteCounts, nil
}

// Adds counts into into, refusing a sum past an int64.
func addNightlySums(into map[sidecar.Id]int64, counts map[sidecar.Id]int64) error {
	for networkId, byteCount := range counts {
		total := into[networkId]
		if math.MaxInt64-total < byteCount {
			return fmt.Errorf("%w: a network's sum past an int64", ErrNightlySumsValue)
		}
		into[networkId] = total + byteCount
	}
	return nil
}

// The nightly count's sums over Redis. Safe for concurrent use.
type NightlySums struct {
	redis    sidecar.Redis
	settings *NightlyPassSettings
}

// Sums on redis. settings nil: the defaults.
func NewNightlySums(redis sidecar.Redis, settings *NightlyPassSettings) (*NightlySums, error) {
	if redis == nil {
		return nil, errors.New("evs's nightly sums need Redis")
	}
	if settings == nil {
		settings = DefaultNightlyPassSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return &NightlySums{redis: redis, settings: settings}, nil
}

// One field of the night, written whole.
func (self *NightlySums) write(ctx context.Context, night int64, field string, networkByteCounts map[sidecar.Id]int64) error {
	value, err := encodeNightlySums(networkByteCounts)
	if err != nil {
		return err
	}
	ttlMs := max(int64(1), self.settings.NightlySumsTtl.Milliseconds())
	_, err = self.redis.RunScript(ctx, nightlySumsWriteScript, []string{NightlySumsKey(night)}, []string{field, string(value), strconv.FormatInt(ttlMs, 10)})
	return err
}

// One field of the night: found false while it is absent.
func (self *NightlySums) read(ctx context.Context, night int64, field string) (map[sidecar.Id]int64, bool, error) {
	value, found, err := self.redis.HashGet(ctx, NightlySumsKey(night), field)
	if err != nil || !found {
		return nil, found, err
	}
	networkByteCounts, err := decodeNightlySums(value)
	if err != nil {
		return nil, true, err
	}
	return networkByteCounts, true, nil
}

// Replaces a shard's sums for the night whole, and marks it reported, in one script: a rerun replaces and never adds.
// No network writes the shard's empty marker.
func (self *NightlySums) Report(ctx context.Context, night int64, clusterId string, shard string, networkByteCounts map[sidecar.Id]int64) error {
	return self.write(ctx, night, NightlyShardField(clusterId, shard), networkByteCounts)
}

// A shard's reported sums for the night, found false while it has not reported or its sums are gone.
func (self *NightlySums) Read(ctx context.Context, night int64, clusterId string, shard string) (map[sidecar.Id]int64, bool, error) {
	return self.read(ctx, night, NightlyShardField(clusterId, shard))
}

// The fields of shardFields that have not reported for the night, in shardFields' order: one script.
func (self *NightlySums) Missing(ctx context.Context, night int64, shardFields []string) ([]string, error) {
	if len(shardFields) == 0 {
		return []string{}, nil
	}
	reply, err := self.redis.RunScript(ctx, nightlySumsMissingScript, []string{NightlySumsKey(night)}, shardFields)
	if err != nil {
		return nil, err
	}
	if reply == nil || reply.Kind != sidecar.RedisReplyArray {
		return nil, errors.New("evs's nightly sums: the missing shards came back as no array")
	}
	missing := make([]string, 0, len(reply.Replies))
	for _, element := range reply.Replies {
		if element == nil || element.Kind != sidecar.RedisReplyBulk {
			return nil, errors.New("evs's nightly sums: a missing shard came back as no string")
		}
		missing = append(missing, string(element.Bulk))
	}
	return missing, nil
}

// Each network's stored count in a run's sums.
func nightlyStoredByteCounts(networkBytes map[sidecar.Id]*NightlyBytes) map[sidecar.Id]int64 {
	networkByteCounts := make(map[sidecar.Id]int64, len(networkBytes))
	for networkId, stored := range networkBytes {
		networkByteCounts[networkId] = stored.StoredByteCount()
	}
	return networkByteCounts
}

// After one run of a shard's chain: the sums of the chain so far, passed to the next run under the part after this
// one's, or, once the shard is listed to its end, reported. A chain reports only while every run of it counted every
// repo it listed with no read failing; one that did not runs on for the pass's other work and reports nothing, so
// its night keeps the old counts. The next run's args, when the run stopped at its bound. An error is a Redis read
// or write that did not answer, with nothing queued, so the run is retried with its own args.
func (self *NightlyPass) reportShard(ctx context.Context, sums *NightlySums, shardArgs *EvsNightlyShardArgs, result *NightlyResult, runErr error) (*EvsNightlyShardArgs, error) {
	whole := shardArgs.Whole && runErr == nil
	var networkByteCounts map[sidecar.Id]int64
	if whole {
		networkByteCounts = nightlyStoredByteCounts(result.NetworkBytes)
		if 0 < shardArgs.Part {
			carried, found, err := sums.read(ctx, shardArgs.Night, nightlyShardPartField(shardArgs.ClusterId, shardArgs.Shard, shardArgs.Part))
			switch {
			case errors.Is(err, ErrNightlySumsValue) || (err == nil && !found):
				// the chain's sums are gone, or unreadable: the shard cannot report tonight
				self.log.Errorf("[evs] alarm nightly_count_part_lost: night %d cluster %s shard %q part %d: %v", shardArgs.Night, shardArgs.ClusterId, shardArgs.Shard, shardArgs.Part, err)
				whole = false
			case err != nil:
				return nil, err
			default:
				if err := addNightlySums(networkByteCounts, carried); err != nil {
					self.log.Errorf("[evs] alarm nightly_count_part_lost: night %d cluster %s shard %q part %d: %v", shardArgs.Night, shardArgs.ClusterId, shardArgs.Shard, shardArgs.Part, err)
					whole = false
				}
			}
		}
	}
	if result.More {
		next := &EvsNightlyShardArgs{
			ClusterId:  shardArgs.ClusterId,
			Shard:      shardArgs.Shard,
			StartAfter: result.NextStartAfter,
			Night:      shardArgs.Night,
			Part:       shardArgs.Part + 1,
			Whole:      whole,
		}
		if whole {
			// written before the next run is queued, so the next run finds it
			if err := sums.write(ctx, shardArgs.Night, nightlyShardPartField(shardArgs.ClusterId, shardArgs.Shard, next.Part), networkByteCounts); err != nil {
				return nil, err
			}
		}
		return next, nil
	}
	if !whole {
		return nil, nil
	}
	if err := sums.Report(ctx, shardArgs.Night, shardArgs.ClusterId, shardArgs.Shard, networkByteCounts); err != nil {
		return nil, err
	}
	result.Reported = true
	return nil, nil
}

// The closing job's args: the night, and every shard the start queued.
type EvsNightlyCloseArgs struct {
	// The nightly start's time in Unix ms.
	Night int64
	// <cluster>:<shard> of each shard, every metadata cluster's.
	ShardFields []string
}

// The closing job's args as bytes: the night, then each shard's field, a line each. No field holds a line break.
func EvsNightlyCloseArgsBytes(args *EvsNightlyCloseArgs) []byte {
	return []byte(strings.Join(append([]string{strconv.FormatInt(args.Night, 10)}, args.ShardFields...), "\n"))
}

// The closing job's args from bytes. ok is false for bytes of another shape.
func ParseEvsNightlyCloseArgs(args []byte) (*EvsNightlyCloseArgs, bool) {
	lines := strings.Split(string(args), "\n")
	night, err := strconv.ParseInt(lines[0], 10, 64)
	if err != nil || night <= 0 || len(lines) < 2 {
		return nil, false
	}
	for _, field := range lines[1:] {
		if field == "" {
			return nil, false
		}
	}
	return &EvsNightlyCloseArgs{Night: night, ShardFields: lines[1:]}, true
}

// The closing job in the queue, once-keyed by its night, so a night has one closing job however often it is asked.
func EvsNightlyCloseTaskRequest(args *EvsNightlyCloseArgs, runAt time.Time, settings *NightlyPassSettings) *sidecar.TaskRequest {
	if settings == nil {
		settings = DefaultNightlyPassSettings()
	}
	return &sidecar.TaskRequest{
		Name:    EvsNightlyCloseTaskName,
		OnceKey: EvsNightlyCloseTaskName + "." + strconv.FormatInt(args.Night, 10),
		Args:    EvsNightlyCloseArgsBytes(args),
		RunAt:   runAt,
		MaxTime: settings.NightlyCloseMaxTime,
	}
}

// What the closing job runs on beyond its host.
type NightlyCloseDeps struct {
	// Where each network's count is written. Required.
	Counts NightlyCountStore
	// nil: the defaults.
	Settings *NightlyPassSettings
	// Alarms. nil discards.
	Log sidecar.Logger
	// a test's: called once every shard has reported, before their sums are read
	afterReported func()
}

// What one run of the closing job did, in counts with no id (I-13).
type NightlyCloseResult struct {
	Night      int64
	ShardCount int
	// Shards that had not reported, when the run waited or gave up.
	MissingShardFields []string
	// A shard had not reported and the night was younger than NightlySumsTtl: the job asked again.
	Waiting bool
	// The night ended and wrote nothing: a shard never reported before it was NightlySumsTtl old (Unfinished), or a
	// reported shard's sums were gone or unreadable (Lost). The old counts stand.
	Unfinished bool
	Lost       bool
	// This build holds no count store: nothing was written.
	CountsUnavailable bool
	// Networks written their sum, and networks holding a count that no sum named written zero.
	SetCount  int
	ZeroCount int
}

// One run of evs.nightly_close (see the file header). A non-nil error is one the run could not get past, a Redis or
// Postgres read or write: the host's backoff reruns it, which reads the same sums and writes the same counts.
func RunNightlyClose(ctx context.Context, host *sidecar.ServiceHost, deps *NightlyCloseDeps, args []byte) (*NightlyCloseResult, error) {
	if host == nil || host.Redis == nil || host.Tasks == nil {
		return nil, errors.New("evs's nightly closing job needs a host with Redis and a task queue")
	}
	if deps == nil || deps.Counts == nil {
		return nil, errors.New("evs's nightly closing job needs a count store")
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultNightlyPassSettings()
	}
	sums, err := NewNightlySums(host.Redis, settings)
	if err != nil {
		return nil, err
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	closeArgs, ok := ParseEvsNightlyCloseArgs(args)
	if !ok {
		return nil, fmt.Errorf("%w: evs.nightly_close args", ErrNightlyPassSettings)
	}
	night := closeArgs.Night
	result := &NightlyCloseResult{Night: night, ShardCount: len(closeArgs.ShardFields)}

	missing, err := sums.Missing(ctx, night, closeArgs.ShardFields)
	if err != nil {
		return result, err
	}
	if 0 < len(missing) {
		result.MissingShardFields = missing
		now := host.ClockOrReal().Now()
		if now.Before(nightlyNightTime(night).Add(settings.NightlySumsTtl)) {
			request := EvsNightlyCloseTaskRequest(closeArgs, now.Add(settings.NightlyCloseRetryInterval), settings)
			if err := host.Tasks.Schedule(ctx, request); err != nil {
				return result, err
			}
			result.Waiting = true
			return result, nil
		}
		result.Unfinished = true
		log.Errorf("[evs] alarm nightly_count_unfinished: night %d: %d of %d shards never reported; the old counts stand", night, len(missing), len(closeArgs.ShardFields))
		return result, nil
	}
	if deps.afterReported != nil {
		deps.afterReported()
	}

	totals := map[sidecar.Id]int64{}
	for _, field := range closeArgs.ShardFields {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		shardByteCounts, found, err := sums.read(ctx, night, field)
		if err == nil && found {
			err = addNightlySums(totals, shardByteCounts)
		}
		switch {
		case errors.Is(err, ErrNightlySumsValue) || (err == nil && !found):
			result.Lost = true
			log.Errorf("[evs] alarm nightly_count_lost: night %d: a reported shard's sums are gone or unreadable (%v); the old counts stand", night, err)
			return result, nil
		case err != nil:
			return result, err
		}
	}

	var firstErr error
	failed := func(err error) bool {
		if errors.Is(err, ErrNightlyCountsUnavailable) {
			result.CountsUnavailable = true
			return true
		}
		if firstErr == nil {
			firstErr = err
		}
		return false
	}
	networkIds := slices.SortedFunc(maps.Keys(totals), func(a sidecar.Id, b sidecar.Id) int {
		return bytes.Compare(a[:], b[:])
	})
	for _, networkId := range networkIds {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := deps.Counts.SetStoredByteCount(ctx, networkId, totals[networkId]); err != nil {
			if failed(err) {
				return result, nil
			}
			continue
		}
		result.SetCount += 1
	}
	// a network with a count and no sum tonight holds no repo the pass listed
	var after *sidecar.Id
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		page, err := deps.Counts.NetworkIdsWithStoredByteCount(ctx, after, settings.NightlyCloseZeroPageSize)
		if err != nil {
			if failed(err) {
				return result, nil
			}
			break
		}
		for _, networkId := range page {
			if _, summed := totals[networkId]; summed {
				continue
			}
			if err := deps.Counts.SetStoredByteCount(ctx, networkId, 0); err != nil {
				if failed(err) {
					return result, nil
				}
				continue
			}
			result.ZeroCount += 1
		}
		if len(page) < settings.NightlyCloseZeroPageSize {
			break
		}
		last := page[len(page)-1]
		after = &last
	}
	return result, firstErr
}
