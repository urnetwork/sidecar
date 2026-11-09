// §6.8's scripts on a client's slot: the two that are the only writes this package makes to ver, hint,
// n and ack, and the read of the hint stream's tail that a publisher's reset starts from. Each reads
// every key from KEYS and builds none (host_redis.go), and each holds a version or stream id only as a
// string: a comparison splits it into runs of at most 10 digits, each exact as a Lua double, by
// version.go's rule, so no whole value ever passes through tonumber or arithmetic (D-PROTO-12). The one
// arithmetic is HINCRBY, which Redis does on an int64, and its result is read back with HGET, never
// through a Lua number.
//
// sidecartest registers a Go twin of each under its Name for T2's FakeRedis, and PushStoreSuite runs
// both against the twin and against a real Redis, so the twin stays honest (D-TEST-2).

package pushservice

import (
	"github.com/urnetwork/sidecar"
)

// One hint. KEYS: ver, hint, n, tok, live, all of {scp_<C>}. ARGV: topic, version, kind, the hint's
// bytes, raise ("1" when the topic's version is a clock, which the script raises past the stored value
// by HINCRBY when not above it), the keys' ttl in seconds, and the stream's MAXLEN.
//
// In order: refuse a version that is not canonical; raise ver's field only if higher, or raise a
// clock past it; INCR n before XADD, since the entry stores its value as seq (plan-PROTO-small-readings
// reading 5); XADD the entry, trimming to about MAXLEN; EXPIRE NX all three keys, so each key's life
// starts once and its g event fires once per key generation; and return {stream id, version, seq, tok,
// live}, the version being what ver holds now, the last two read from the same slot and nil while
// absent. Only INCR emits an event production listens for (classes K, g, $, s and x): HSET and XADD
// emit none.
var HintScript = &sidecar.RedisScript{
	Name: "pushservice.hint",
	Source: `
local ver = KEYS[1]
local stream = KEYS[2]
local count = KEYS[3]
local tok = KEYS[4]
local live = KEYS[5]
local topic = ARGV[1]
local version = ARGV[2]

-- 1 to 20 digits, the first not 0
local function canonical(text)
  return #text <= 20 and string.find(text, '^[1-9][0-9]*$') ~= nil
end

-- a above b, both canonical: lengths, then the digits before the last 10, then the last 10, each run
-- exact as a double, never the whole value
local function higher(a, b)
  if #a ~= #b then
    return #a > #b
  end
  if #a > 10 then
    local aHigh = tonumber(string.sub(a, 1, #a - 10))
    local bHigh = tonumber(string.sub(b, 1, #b - 10))
    if aHigh ~= bHigh then
      return aHigh > bHigh
    end
    return tonumber(string.sub(a, -10)) > tonumber(string.sub(b, -10))
  end
  return tonumber(a) > tonumber(b)
end

if #topic == 0 or not canonical(version) then
  return redis.error_reply('ERR push hint topic or version not canonical')
end
local stored = redis.call('HGET', ver, topic)
if stored and not canonical(stored) then
  stored = false
end
if not stored or higher(version, stored) then
  redis.call('HSET', ver, topic, version)
elseif ARGV[5] == '1' then
  redis.call('HINCRBY', ver, topic, 1)
  version = redis.call('HGET', ver, topic)
else
  version = stored
end
local seq = redis.call('INCR', count)
local id = redis.call('XADD', stream, 'MAXLEN', '~', ARGV[7], '*', 'seq', seq, 'topic', topic, 'version', version, 'kind', ARGV[3], 'hint', ARGV[4])
redis.call('EXPIRE', ver, ARGV[6], 'NX')
redis.call('EXPIRE', stream, ARGV[6], 'NX')
redis.call('EXPIRE', count, ARGV[6], 'NX')
return {id, version, seq, redis.call('GET', tok), redis.call('GET', live)}
`,
}

// §18.7's step 3: raise ack to a batch's last stream id, only while a wake token exists. KEYS: ack, tok,
// both of {scp_<C>}. ARGV: the stream id, ack's ttl in seconds. Returns 1 when it raised ack, else 0;
// refuses a stream id that is not <ms>-<seq>. A stored ack that is malformed is replaced.
var HintAckScript = &sidecar.RedisScript{
	Name: "pushservice.hint_ack",
	Source: `
local ack = KEYS[1]
local tok = KEYS[2]
local id = ARGV[1]

-- 0, or 1 to 20 digits with no leading zero
local function decimal(text)
  return #text <= 20 and (text == '0' or string.find(text, '^[1-9][0-9]*$') ~= nil)
end

-- a above b, both decimals, by the hint script's rule
local function higher(a, b)
  if #a ~= #b then
    return #a > #b
  end
  if #a > 10 then
    local aHigh = tonumber(string.sub(a, 1, #a - 10))
    local bHigh = tonumber(string.sub(b, 1, #b - 10))
    if aHigh ~= bHigh then
      return aHigh > bHigh
    end
    return tonumber(string.sub(a, -10)) > tonumber(string.sub(b, -10))
  end
  return tonumber(a) > tonumber(b)
end

local idMs, idSeq = string.match(id, '^([0-9]+)%-([0-9]+)$')
if not idMs or not decimal(idMs) or not decimal(idSeq) then
  return redis.error_reply('ERR push ack stream id malformed')
end
if redis.call('EXISTS', tok) == 0 then
  return 0
end
local stored = redis.call('GET', ack)
if stored then
  local storedMs, storedSeq = string.match(stored, '^([0-9]+)%-([0-9]+)$')
  if storedMs and decimal(storedMs) and decimal(storedSeq) then
    if idMs == storedMs then
      if not higher(idSeq, storedSeq) then
        return 0
      end
    elseif not higher(idMs, storedMs) then
      return 0
    end
  end
end
redis.call('SET', ack, id, 'EX', ARGV[2])
return 1
`,
}

// The hint stream's last entry, which a publisher's reset reads before ver (PROTO-M1-08), so a hint
// that lands between the two reads repeats rather than vanishes. KEYS: hint, of {scp_<C>}. No ARGV.
// Returns nil while the stream is absent or empty, else the entry as XREVRANGE gives it: {id, {field,
// value, ...}}. XREVRANGE has no method on sidecar.Redis, and one script reads the tail alone, where
// XRANGE would read the whole stream to reach it. It writes nothing.
var HintTailScript = &sidecar.RedisScript{
	Name: "pushservice.hint_tail",
	Source: `
local last = redis.call('XREVRANGE', KEYS[1], '+', '-', 'COUNT', 1)
if #last == 0 then
  return false
end
return last[1]
`,
}
