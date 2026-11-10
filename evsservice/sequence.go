// {evsq_<repo_id>}, a repo's push sequence (§11.10's sequence row, evs-24): raised by one script after each commit,
// in step 8, before the commit's hints and its {evsh_} entry, which records the value this raise gave. The hint's
// version is the new value, so one past a client's names the only commit between and a skip sends it to the window;
// GET .../refs returns it.
//
// The script, exactly as §11.10 states it: if the key is absent, SET it to the master's TIME in µs x 1,000, as the
// strings of TIME's seconds, its microseconds zero-padded to six digits and "000" joined, so no arithmetic touches
// it; then INCR, PEXPIRE 30 d, and reply with GET's bulk string, never INCR's integer, which Lua holds as a double
// that loses the value near 1.8 x 10^18. evs parses the reply with strconv.ParseUint.
//
// Soft state outside the rdb bundles (owner decision 136): after a loss or expiry the sequence restarts from the
// master's clock, above every earlier value while that clock trails the old one's by less than the lost family's
// age less 1 µs per 1,000 raises, which clients see as a gap and resync; a crash before the raise leaves that commit
// to the hourly resync. A failure is a gap, never an alarm.

package evsservice

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
)

// §11.10's sequence row: the key lives 30 d past its last raise.
const evsPushSequenceTtl = 30 * 24 * time.Hour

// The family's hash tag prefix.
const pushSequenceKeyPrefix = "{evsq_"

// A repo's sequence key: {evsq_<repo_id>}.
func PushSequenceKey(repoId sidecar.Id) string {
	return pushSequenceKeyPrefix + sidecar.EvsKeyId(repoId) + "}"
}

// Raises the sequence. KEYS[1] the repo's key; ARGV[1] the ttl in ms. Replies with the new value as a bulk string.
var PushSequenceRaiseScript = &sidecar.RedisScript{
	Name: "evs_push_sequence_raise",
	Source: `
if redis.call('EXISTS', KEYS[1]) == 0 then
  local now = redis.call('TIME')
  redis.call('SET', KEYS[1], now[1] .. string.format('%06d', tonumber(now[2])) .. '000')
end
redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], ARGV[1])
return redis.call('GET', KEYS[1])
`,
}

// The repo's sequence raised once: its new value.
func RaisePushSequence(ctx context.Context, redis sidecar.Redis, repoId sidecar.Id) (uint64, error) {
	if redis == nil {
		return 0, fmt.Errorf("no redis for the push sequence")
	}
	reply, err := redis.RunScript(ctx, PushSequenceRaiseScript, []string{PushSequenceKey(repoId)},
		[]string{strconv.FormatInt(evsPushSequenceTtl.Milliseconds(), 10)})
	if err != nil {
		return 0, err
	}
	if reply.Kind != sidecar.RedisReplyBulk {
		return 0, fmt.Errorf("the push sequence answered a reply of kind %d, not a bulk string", reply.Kind)
	}
	return strconv.ParseUint(string(reply.Bulk), 10, 64)
}

// The repo's sequence as it stands, 0 when absent: GET .../refs's value (§11.9).
func ReadPushSequence(ctx context.Context, redis sidecar.Redis, repoId sidecar.Id) (uint64, error) {
	if redis == nil {
		return 0, nil
	}
	value, found, err := redis.Get(ctx, PushSequenceKey(repoId))
	if err != nil || !found {
		return 0, err
	}
	return strconv.ParseUint(string(value), 10, 64)
}
