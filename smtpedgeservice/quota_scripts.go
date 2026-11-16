// §14.7's Redis scripts. Each touches one key, so one hash tag holds each call and the CROSSSLOT lint has
// nothing to refuse: {smq_<networkId>} for a network's own counters, {smg_<yyyymmddhh>} and
// {smd_<hex(SHA-256(domain)[0:16])>_<yyyymmddhh>} for the fleet's Community counters
// (plan-SMTP-shared-counters). sidecartest's twins (smtp_quota_twins.go) do what each does, step for
// step, for FakeRedis, and RunSmtpQuotaScriptSuite runs both through fixed vectors.
//
// {smq_<networkId>} is one hash, its fields each with their own ttl:
//
//	c:<day> r:<day> b:<day>    connections and recipients debited at MAIL, bytes observed at close, on a
//	                           UTC day counted from the epoch; 48 h
//	t:<window>                 burst tokens taken in one smtp_burst_window, counted from the epoch; two
//	                           windows
//	cc:<member>                one live connection: "<day>:<recipients>:<debited>", its reservation of
//	                           one connection and its recipients until MAIL debits them; SmtpEdgeSettings'
//	                           QuotaMemberTimeout, renewed while the connection lives, so a crashed edge's
//	                           members lapse and its concurrency and reservations heal by themselves
//	h  h:<label>               a network's or a burner label's halt, as the ms it ends; until then
//
// Lua holds numbers as doubles, exact below 2^53; every count here stays far under it, and times are ms
// since the epoch. A script reads the master's clock (TIME), so every edge counts one UTC day.

package smtpedgeservice

import (
	"github.com/urnetwork/sidecar"
)

// The {smq_} answers' codes.
const (
	smtpQuotaScriptOk     = 1
	smtpQuotaScriptHalted = 2
	smtpQuotaScriptQuota  = 3
)

// KEYS[1] {smq_<networkId>}. ARGV: member, label (” for network mail), recipients, message bytes, then
// the limits smtp_connections_per_day, smtp_recipients_per_day, smtp_recipients_per_message,
// smtp_message_bytes, smtp_bytes_per_day, smtp_burst, smtp_burst_window in ms and
// smtp_concurrent_connections (-1 none, 0 not included), then the member's ttl and the key's ttl in ms.
// Answers {code, retry ms, day, reason, burst field}: 1 a reservation made, 2 halted, 3 quota. One
// preamble runs this once (§22.5).
var SmtpQuotaReserveScript = &sidecar.RedisScript{
	Name: "smtp_quota_reserve",
	Source: `
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
local day = math.floor(now / 86400000)
local function over(limit, value)
  return limit ~= -1 and limit < value
end
local haltEnd = tonumber(redis.call('HGET', KEYS[1], 'h') or '0')
if now < haltEnd then
  return {2, haltEnd - now, day, 'halt', ''}
end
if ARGV[2] ~= '' then
  local labelEnd = tonumber(redis.call('HGET', KEYS[1], 'h:' .. ARGV[2]) or '0')
  if now < labelEnd then
    return {2, labelEnd - now, day, 'label_halt', ''}
  end
end
local recipients = tonumber(ARGV[3])
if over(tonumber(ARGV[7]), recipients) then
  return {3, 0, day, 'recipients_per_message', ''}
end
if over(tonumber(ARGV[8]), tonumber(ARGV[4])) then
  return {3, 0, day, 'message_bytes', ''}
end
local members = 0
local reservedConnections = 0
local reservedRecipients = 0
local fields = redis.call('HGETALL', KEYS[1])
for i = 1, #fields, 2 do
  if string.sub(fields[i], 1, 3) == 'cc:' then
    members = members + 1
    local memberDay, memberRecipients, debited = string.match(fields[i + 1], '^(%d+):(%d+):(%d)$')
    if memberDay and tonumber(memberDay) == day and debited == '0' then
      reservedConnections = reservedConnections + 1
      reservedRecipients = reservedRecipients + tonumber(memberRecipients)
    end
  end
end
if over(tonumber(ARGV[12]), members + 1) then
  return {3, 0, day, 'concurrent_connections', ''}
end
local untilTomorrow = (day + 1) * 86400000 - now
local connections = tonumber(redis.call('HGET', KEYS[1], 'c:' .. day) or '0')
if over(tonumber(ARGV[5]), connections + reservedConnections + 1) then
  return {3, untilTomorrow, day, 'connections_per_day', ''}
end
local debitedRecipients = tonumber(redis.call('HGET', KEYS[1], 'r:' .. day) or '0')
if over(tonumber(ARGV[6]), debitedRecipients + reservedRecipients + recipients) then
  return {3, untilTomorrow, day, 'recipients_per_day', ''}
end
local bytesLimit = tonumber(ARGV[9])
local bytes = tonumber(redis.call('HGET', KEYS[1], 'b:' .. day) or '0')
if bytesLimit ~= -1 and bytesLimit <= bytes then
  return {3, untilTomorrow, day, 'bytes_per_day', ''}
end
local burstField = ''
local burst = tonumber(ARGV[10])
if burst ~= -1 then
  local window = tonumber(ARGV[11])
  local index = math.floor(now / window)
  burstField = 't:' .. index
  local used = tonumber(redis.call('HGET', KEYS[1], burstField) or '0')
  if burst < used + 1 then
    return {3, (index + 1) * window - now, day, 'burst', ''}
  end
  redis.call('HINCRBY', KEYS[1], burstField, 1)
  redis.call('HPEXPIRE', KEYS[1], 2 * window, 'FIELDS', 1, burstField)
end
local member = 'cc:' .. ARGV[1]
redis.call('HSET', KEYS[1], member, day .. ':' .. recipients .. ':0')
redis.call('HPEXPIRE', KEYS[1], tonumber(ARGV[13]), 'FIELDS', 1, member)
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[14]))
return {1, 0, day, '', burstField}
`,
}

// KEYS[1] {smq_<networkId>}. ARGV: member, its reservation's day, its recipients, the member's ttl and the
// key's ttl in ms. Debits the connection and its recipients on that day, once: a member already debited
// answers 0 and changes nothing, so a retried call debits nothing twice.
var SmtpQuotaDebitScript = &sidecar.RedisScript{
	Name: "smtp_quota_debit",
	Source: `
local member = 'cc:' .. ARGV[1]
local value = redis.call('HGET', KEYS[1], member)
if value and string.sub(value, -2) == ':1' then
  return 0
end
local connections = 'c:' .. ARGV[2]
local recipients = 'r:' .. ARGV[2]
redis.call('HINCRBY', KEYS[1], connections, 1)
redis.call('HINCRBY', KEYS[1], recipients, tonumber(ARGV[3]))
redis.call('HPEXPIRE', KEYS[1], tonumber(ARGV[5]), 'FIELDS', 2, connections, recipients)
if value then
  redis.call('HSET', KEYS[1], member, ARGV[2] .. ':' .. ARGV[3] .. ':1')
  redis.call('HPEXPIRE', KEYS[1], tonumber(ARGV[4]), 'FIELDS', 1, member)
end
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[5]))
return 1
`,
}

// KEYS[1] {smq_<networkId>}. ARGV: member, its reservation's day, the bytes observed, the key's ttl in ms.
// Ends the member, which returns any reservation MAIL never debited, and adds the bytes to that day's.
var SmtpQuotaCloseScript = &sidecar.RedisScript{
	Name: "smtp_quota_close",
	Source: `
redis.call('HDEL', KEYS[1], 'cc:' .. ARGV[1])
local bytes = tonumber(ARGV[3])
if 0 < bytes then
  local field = 'b:' .. ARGV[2]
  redis.call('HINCRBY', KEYS[1], field, bytes)
  redis.call('HPEXPIRE', KEYS[1], tonumber(ARGV[4]), 'FIELDS', 1, field)
  redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[4]))
end
return 1
`,
}

// KEYS[1] {smq_<networkId>}. ARGV: the halt's field, h or h:<label>, the ms it ends, the key's ttl in ms.
// Writes the halt unless it has ended or a later one stands: 1 written, 0 not.
var SmtpQuotaHaltScript = &sidecar.RedisScript{
	Name: "smtp_quota_halt",
	Source: `
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
local haltEnd = tonumber(ARGV[2])
if haltEnd <= now then
  return 0
end
local current = tonumber(redis.call('HGET', KEYS[1], ARGV[1]) or '0')
if haltEnd <= current then
  return 0
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
redis.call('HPEXPIRE', KEYS[1], haltEnd - now, 'FIELDS', 1, ARGV[1])
redis.call('PEXPIRE', KEYS[1], math.max(tonumber(ARGV[3]), haltEnd - now))
return 1
`,
}

// KEYS[1] one hour's counter, {smg_<yyyymmddhh>} or {smd_<domain hash>_<yyyymmddhh>}. ARGV: the cap (-1
// none) and the key's ttl in ms, set by the first count. Counts one connection, or past the cap takes
// it back: {1, count} counted, {0, count} refused.
var SmtpHourCountScript = &sidecar.RedisScript{
	Name: "smtp_hour_count",
	Source: `
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]))
end
local cap = tonumber(ARGV[1])
if cap ~= -1 and cap < count then
  redis.call('DECR', KEYS[1])
  return {0, count - 1}
end
return {1, count}
`,
}

// KEYS[1] one hour's counter. Takes back one connection a later refusal undid, never below zero.
var SmtpHourUncountScript = &sidecar.RedisScript{
	Name: "smtp_hour_uncount",
	Source: `
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
if 0 < count then
  return redis.call('DECR', KEYS[1])
end
return 0
`,
}
