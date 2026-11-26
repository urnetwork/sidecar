// The projection's scripts (DESIGN-COMPUTE §9.7, §14.4; BAL-M12-02): Lua that runs on the network's slot alone, each
// acting once per operation key, a repeat answering its first outcome. compute_projection.go builds every call's
// KEYS and ARGV and reads every reply; the layout of each is written above its script.
//
// What the scripts keep, every key under {cmp_<network_id>}, so production's Redis Cluster takes each call whole:
//
//	KEYS[1]  {cmp_<network_id>}, a hash: settled, unsettled (the open charges' sum), holds (the open holds' sum),
//	         promo, floor, accrued (the running enclaves' time in their current interval, BAL-M14-01's), state,
//	         version (a decimal string), rebuild (the mark: present while a rebuild is due); per operation key,
//	         h:<op> a hold, c:<op> an unsettled charge and x:<op> a finished operation's memo (v voided, s swept
//	         unconfirmed, d dropped once booked), which expires after ProjectionMemoTtl; ur:<subject>:<budget>:<period>
//	         the reservations of holds not yet confirmed; s:<subject> each subject with counters
//	KEYS[2]  {cmp_<network_id>}:u, a sorted set: the unconfirmed holds' operation keys by the Redis TIME each was
//	         taken, so a script finds those past UnconfirmedHoldMaxAge without reading every hold
//	KEYS[3…] {cmp_<network_id>}:b:<subject_id>, a hash per subject: r:<budget>:<period> its confirmed holds'
//	         reservations and c:<budget>:<period> its charges, per budget and UTC period (d:YYYYMMDD, m:YYYYMM),
//	         today's and yesterday's, this month's and the last, kept BudgetCounterTtl past the last write
//
// A hold field is state|kind|amount|reserve|time_ms|line count|subject|budget|period…: state u while unconfirmed,
// c once its operation row committed. An unconfirmed hold's reservations sit in the projection's own ur: fields,
// so a script drops one past its age with no other key; confirm moves them into the subjects' counters.
//
// Numbers: Lua holds numbers as doubles, exact below 2^53, so every amount, cap and time here stays below it
// (compute_projection.go refuses larger), sums move through HINCRBY, which Redis keeps in 64 bits, a number becomes
// a string through cmp_str and never Lua's own formatting, and the version stays a decimal string, compared by
// length and then by bytes (sidecar/host_redis.go's rule). An unconfirmed hold's age reads Redis TIME, never a
// caller's clock, and so do the hold's UTC day and month.
//
// No script reads or builds a key its call did not declare: a subject's counters are found among KEYS by name, and a
// call that declares none of a hold's subjects is an error, which changes nothing it has not already. The helpers
// take a key by its index in KEYS (cmp_get(1, …) for the projection, cmp_budget_index's answer for a subject's
// counters), so every command names KEYS[…] itself, which sidecartest/crossslot's lint reads.

package model

import (
	operator "github.com/urnetwork/operator-core"
)

// The Lua every hold script starts with, so the direct, search and interval branches are scripts of their own
// (BAL-M12-21, BAL-M13-02, BAL-M14-01) over one set of rules: numbers, periods, holds, the sweep of unconfirmed holds,
// the balance's and the budgets' checks, the take and a repeat's answer. Each is a local function, as Redis runs a
// script with no globals.
//
// cmp_check_balance takes a class: call (a remote call: held down to zero, refused in grace or worse), search (as a
// call, less the unexpired promotional credit, which pays no search, §9.11) and interval (an enclave interval: down
// to minus the floor, kept running in grace, refused once suspended); cmp_check_budgets bounds calls and searches,
// never an enclave's running time (§16.4), and answers budget with the index, from 0, of the first line refused, so
// the refusal names its budget and period (§6.6).
const computeHoldPrelude = `
local function cmp_int(value, what)
	if type(value) ~= 'string' or 16 < #value or not string.match(value, '^%-?%d+$') then
		return error('compute: ' .. what .. ' is no integer')
	end
	return tonumber(value)
end

local function cmp_str(number)
	if number == 0 then
		return '0'
	end
	return string.format('%.0f', number)
end

local function cmp_get(ki, field)
	local value = redis.call('HGET', KEYS[ki], field)
	if not value then
		return 0
	end
	return cmp_int(value, field)
end

local function cmp_add(ki, field, delta)
	if delta == 0 then
		return cmp_get(ki, field)
	end
	return redis.call('HINCRBY', KEYS[ki], field, cmp_str(delta))
end

local function cmp_add_or_delete(ki, field, delta)
	local value = cmp_add(ki, field, delta)
	if value <= 0 then
		redis.call('HDEL', KEYS[ki], field)
	end
	return value
end

local function cmp_now()
	local time = redis.call('TIME')
	return tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
end

local function cmp_civil(days)
	local z = days + 719468
	local era = math.floor(z / 146097)
	local doe = z - era * 146097
	local yoe = math.floor((doe - math.floor(doe / 1460) + math.floor(doe / 36524) - math.floor(doe / 146096)) / 365)
	local doy = doe - (365 * yoe + math.floor(yoe / 4) - math.floor(yoe / 100))
	local mp = math.floor((5 * doy + 2) / 153)
	local d = doy - math.floor((153 * mp + 2) / 5) + 1
	local m = mp + 3
	if 10 <= mp then
		m = mp - 9
	end
	local y = yoe + era * 400
	if m <= 2 then
		y = y + 1
	end
	return y, m, d
end

local function cmp_periods(ms)
	local days = math.floor(ms / 86400000)
	local y, m, d = cmp_civil(days)
	local py, pm, pd = cmp_civil(days - 1)
	local ly, lm = y, m - 1
	if lm == 0 then
		ly, lm = y - 1, 12
	end
	return {
		d = string.format('d:%04d%02d%02d', y, m, d),
		m = string.format('m:%04d%02d', y, m),
		pd = string.format('d:%04d%02d%02d', py, pm, pd),
		pm = string.format('m:%04d%02d', ly, lm),
	}
end

local function cmp_split(value, separator)
	local parts = {}
	local start = 1
	while true do
		local stop = string.find(value, separator, start, true)
		if not stop then
			table.insert(parts, string.sub(value, start))
			return parts
		end
		table.insert(parts, string.sub(value, start, stop - 1))
		start = stop + 1
	end
end

local function cmp_hold_parse(value)
	local parts = cmp_split(value, '|')
	local count = cmp_int(parts[6], 'a hold line count')
	if #parts ~= 6 + 3 * count then
		return error('compute: a malformed hold')
	end
	local hold = {
		state = parts[1], kind = parts[2], amount = cmp_int(parts[3], 'a hold amount'),
		reserve = cmp_int(parts[4], 'a hold reserve'), time = cmp_int(parts[5], 'a hold time'), lines = {},
	}
	for i = 0, count - 1 do
		table.insert(hold.lines, {subject = parts[7 + 3 * i], budget = parts[8 + 3 * i], period = parts[9 + 3 * i]})
	end
	return hold
end

local function cmp_hold_format(hold)
	local parts = {hold.state, hold.kind, cmp_str(hold.amount), cmp_str(hold.reserve), cmp_str(hold.time), tostring(#hold.lines)}
	for _, line in ipairs(hold.lines) do
		table.insert(parts, line.subject)
		table.insert(parts, line.budget)
		table.insert(parts, line.period)
	end
	return table.concat(parts, '|')
end

local function cmp_budget_index(subject)
	local wanted = KEYS[1] .. ':b:' .. subject
	for i = 3, #KEYS do
		if KEYS[i] == wanted then
			return i
		end
	end
	return error('compute: the counters of ' .. subject .. ' are not declared')
end

local function cmp_prune(ki, now)
	local periods = cmp_periods(now)
	for _, field in ipairs(redis.call('HKEYS', KEYS[ki])) do
		local period = string.match(field, '^[rc]:[%w_]+:(.+)$')
		if period ~= periods.d and period ~= periods.pd and period ~= periods.m and period ~= periods.pm then
			redis.call('HDEL', KEYS[ki], field)
		end
	end
end

local function cmp_touch(ki, now, ttl)
	cmp_prune(ki, now)
	if redis.call('EXISTS', KEYS[ki]) == 1 then
		redis.call('PEXPIRE', KEYS[ki], ttl)
	end
end

local function cmp_memo(op, outcome, ttl)
	redis.call('HSET', KEYS[1], 'x:' .. op, outcome)
	redis.call('HPEXPIRE', KEYS[1], ttl, 'FIELDS', 1, 'x:' .. op)
end

local function cmp_release_unconfirmed(hold)
	cmp_add(1, 'holds', -hold.amount)
	for _, line in ipairs(hold.lines) do
		cmp_add_or_delete(1, 'ur:' .. line.subject .. ':' .. line.budget .. ':' .. line.period, -hold.reserve)
	end
end

local function cmp_release_confirmed(hold)
	cmp_add(1, 'holds', -hold.amount)
	for _, line in ipairs(hold.lines) do
		cmp_add_or_delete(cmp_budget_index(line.subject), 'r:' .. line.budget .. ':' .. line.period, -hold.reserve)
	end
end

local function cmp_sweep(now, max_age, memo_ttl)
	local stale = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', '(' .. cmp_str(now - max_age))
	for _, op in ipairs(stale) do
		local value = redis.call('HGET', KEYS[1], 'h:' .. op)
		if value then
			local hold = cmp_hold_parse(value)
			if hold.state == 'u' then
				cmp_release_unconfirmed(hold)
				redis.call('HDEL', KEYS[1], 'h:' .. op)
				cmp_memo(op, 's', memo_ttl)
			end
		end
		redis.call('ZREM', KEYS[2], op)
	end
end

local function cmp_present()
	return redis.call('HEXISTS', KEYS[1], 'version') == 1
end

local function cmp_admits()
	return cmp_present() and redis.call('HEXISTS', KEYS[1], 'rebuild') == 0
end

local function cmp_lines(first)
	local count = cmp_int(ARGV[first], 'a line count')
	local lines = {}
	for i = 0, count - 1 do
		local at = first + 1 + 4 * i
		local letter = ARGV[at + 2]
		if letter ~= 'd' and letter ~= 'm' then
			return error('compute: a line period is d or m')
		end
		table.insert(lines, {subject = ARGV[at], budget = ARGV[at + 1], letter = letter, cap = cmp_int(ARGV[at + 3], 'a line cap')})
	end
	return lines
end

local function cmp_check_balance(class, amount)
	local state = cmp_get(1, 'state')
	local floor = 0
	if class == 'interval' then
		if state ~= 1 and state ~= 2 and state ~= 3 then
			return 'balance'
		end
		floor = cmp_get(1, 'floor')
	elseif state ~= 1 and state ~= 2 then
		return 'balance'
	end
	local promo = 0
	if class == 'search' then
		promo = cmp_get(1, 'promo')
	end
	local settled = cmp_get(1, 'settled')
	local unsettled = cmp_get(1, 'unsettled')
	local holds = cmp_get(1, 'holds')
	if settled - unsettled - holds - promo - amount < -floor then
		if -floor <= settled - unsettled - promo - amount then
			return 'held'
		end
		return 'balance'
	end
	return nil
end

local function cmp_check_budgets(lines, reserve, periods)
	local held = false
	for i, line in ipairs(lines) do
		local period = periods[line.letter]
		local ki = cmp_budget_index(line.subject)
		local charged = cmp_get(ki, 'c:' .. line.budget .. ':' .. period)
		local reserved = cmp_get(ki, 'r:' .. line.budget .. ':' .. period) +
			cmp_get(1, 'ur:' .. line.subject .. ':' .. line.budget .. ':' .. period)
		if line.cap < charged + reserve then
			return 'budget', i - 1
		end
		if line.cap < charged + reserved + reserve then
			held = true
		end
	end
	if held then
		return 'held'
	end
	return nil
end

local function cmp_take(op, kind, amount, reserve, lines, periods, now)
	local hold = {state = 'u', kind = kind, amount = amount, reserve = reserve, time = now, lines = {}}
	for _, line in ipairs(lines) do
		local period = periods[line.letter]
		table.insert(hold.lines, {subject = line.subject, budget = line.budget, period = period})
		cmp_add(1, 'ur:' .. line.subject .. ':' .. line.budget .. ':' .. period, reserve)
		redis.call('HSET', KEYS[1], 's:' .. line.subject, '1')
	end
	redis.call('HSET', KEYS[1], 'h:' .. op, cmp_hold_format(hold))
	cmp_add(1, 'holds', amount)
	redis.call('ZADD', KEYS[2], cmp_str(now), op)
end

local function cmp_repeat_hold(op)
	local value = redis.call('HGET', KEYS[1], 'h:' .. op)
	if value then
		return {'taken', '0', cmp_str(cmp_hold_parse(value).time)}
	end
	if redis.call('HEXISTS', KEYS[1], 'c:' .. op) == 1 then
		return {'taken', '0', '0'}
	end
	local memo = redis.call('HGET', KEYS[1], 'x:' .. op)
	if memo == 'd' then
		return {'dropped', '0', '0'}
	end
	if memo then
		return {'void', '0', '0'}
	end
	return nil
end
`

// The prelude's source: for a hold script of another path, and for the private stack's tests of the classes no built
// path takes yet.
func ComputeHoldPrelude() string {
	return computeHoldPrelude
}

var (
	// A remote TEE call's hold (§9.7, step 2): its worst case against the balance, held down to zero and refused in
	// grace or worse, and its reservation against each budget line, taken unconfirmed.
	//
	// KEYS: the projection, the unconfirmed set, each line's subject's counters.
	// ARGV: op, kind, amount, reserve, unconfirmed max age ms, memo ttl ms, held retry ms, rebuild retry ms, the line
	// count, then per line its subject, budget, period letter (d or m) and cap.
	// Reply: {outcome, retry ms, time ms}: taken (time is the hold's Redis TIME), held (with its retry: the
	// projection absent or marked, or open holds or reservations in the way), balance, budget, whose reply adds a
	// fourth value, the index of the line refused; a repeat answers taken, or void or dropped once the operation was
	// released or booked.
	computeProjectionHoldScript = &operator.RedisScript{
		Name: "compute-projection-hold",
		Source: computeHoldPrelude + `
local op = ARGV[1]
local kind = ARGV[2]
local amount = cmp_int(ARGV[3], 'the amount')
local reserve = cmp_int(ARGV[4], 'the reserve')
local max_age = cmp_int(ARGV[5], 'the unconfirmed age')
local memo_ttl = cmp_int(ARGV[6], 'the memo ttl')
local lines = cmp_lines(9)
local now = cmp_now()
if not cmp_admits() then
	return {'held', ARGV[8], cmp_str(now)}
end
cmp_sweep(now, max_age, memo_ttl)
local first = cmp_repeat_hold(op)
if first then
	return first
end
local periods = cmp_periods(now)
local refused = cmp_check_balance('call', amount)
local refusedLine = nil
if not refused then
	refused, refusedLine = cmp_check_budgets(lines, reserve, periods)
end
if refused == 'held' then
	return {'held', ARGV[7], cmp_str(now)}
end
if refused == 'budget' then
	return {refused, '0', cmp_str(now), cmp_str(refusedLine)}
end
if refused then
	return {refused, '0', cmp_str(now)}
end
cmp_take(op, kind, amount, reserve, lines, periods, now)
return {'taken', '0', cmp_str(now)}
`,
	}

	// The handoff's confirm (D-BAL-13): once the operation's row committed, its hold's reservations move into its
	// subjects' counters and it leaves the unconfirmed set.
	//
	// KEYS: the projection, the unconfirmed set, the counters of every subject the hold may name.
	// ARGV: op, unconfirmed max age ms, memo ttl ms, counter ttl ms.
	// Reply: {outcome}: confirmed (a repeat too, and a hold already settled), void (released, or swept past its
	// age before this ran), dropped, absent (no projection, or no hold of this key).
	computeProjectionConfirmScript = &operator.RedisScript{
		Name: "compute-projection-confirm",
		Source: computeHoldPrelude + `
local op = ARGV[1]
local now = cmp_now()
if not cmp_present() then
	return {'absent'}
end
cmp_sweep(now, cmp_int(ARGV[2], 'the unconfirmed age'), cmp_int(ARGV[3], 'the memo ttl'))
local value = redis.call('HGET', KEYS[1], 'h:' .. op)
if not value then
	if redis.call('HEXISTS', KEYS[1], 'c:' .. op) == 1 then
		return {'confirmed'}
	end
	local memo = redis.call('HGET', KEYS[1], 'x:' .. op)
	if memo == 'd' then
		return {'dropped'}
	end
	if memo then
		return {'void'}
	end
	return {'absent'}
end
local hold = cmp_hold_parse(value)
if hold.state == 'c' then
	return {'confirmed'}
end
local ttl = cmp_int(ARGV[4], 'the counter ttl')
for _, line in ipairs(hold.lines) do
	local ki = cmp_budget_index(line.subject)
	cmp_add_or_delete(1, 'ur:' .. line.subject .. ':' .. line.budget .. ':' .. line.period, -hold.reserve)
	cmp_add(ki, 'r:' .. line.budget .. ':' .. line.period, hold.reserve)
	cmp_touch(ki, now, ttl)
end
hold.state = 'c'
redis.call('HSET', KEYS[1], 'h:' .. op, cmp_hold_format(hold))
redis.call('ZREM', KEYS[2], op)
return {'confirmed'}
`,
	}

	// Settlement's first script (§9.7): the hold becomes an unsettled charge of the outcome's amount, never above the
	// hold for a kind held at its worst case, each counter moving from reservation to charge, capped at the
	// reservation. With no hold, as after a sweep or a lost write, the charge is still counted, at the periods of its
	// start, since its row committed.
	//
	// KEYS: the projection, the unconfirmed set, the counters of every subject the operation names.
	// ARGV: op, kind, amount, cap at the hold (1 or 0), reserve, start ms, unconfirmed max age ms, memo ttl ms,
	// counter ttl ms, the line count, then per line its subject, budget, period letter and cap (unread).
	// Reply: {outcome}: settled (a repeat too), void (released before it settled), dropped (booked), absent (no
	// projection).
	computeProjectionSettleScript = &operator.RedisScript{
		Name: "compute-projection-settle",
		Source: computeHoldPrelude + `
local op = ARGV[1]
local kind = ARGV[2]
local amount = cmp_int(ARGV[3], 'the amount')
local now = cmp_now()
if not cmp_present() then
	return {'absent'}
end
cmp_sweep(now, cmp_int(ARGV[7], 'the unconfirmed age'), cmp_int(ARGV[8], 'the memo ttl'))
if redis.call('HEXISTS', KEYS[1], 'c:' .. op) == 1 then
	return {'settled'}
end
local memo = redis.call('HGET', KEYS[1], 'x:' .. op)
if memo == 'd' then
	return {'dropped'}
end
if memo == 'v' then
	return {'void'}
end
local charged = amount
local reserve
local lines
local value = redis.call('HGET', KEYS[1], 'h:' .. op)
if value then
	local hold = cmp_hold_parse(value)
	if ARGV[4] == '1' and hold.amount < charged then
		charged = hold.amount
	end
	if hold.state == 'u' then
		cmp_release_unconfirmed(hold)
		redis.call('ZREM', KEYS[2], op)
	else
		cmp_release_confirmed(hold)
	end
	redis.call('HDEL', KEYS[1], 'h:' .. op)
	reserve = hold.reserve
	lines = hold.lines
else
	reserve = cmp_int(ARGV[5], 'the reserve')
	local periods = cmp_periods(cmp_int(ARGV[6], 'the start'))
	lines = {}
	for _, line in ipairs(cmp_lines(10)) do
		table.insert(lines, {subject = line.subject, budget = line.budget, period = periods[line.letter]})
	end
end
local counted = charged
if reserve < counted then
	counted = reserve
end
local ttl = cmp_int(ARGV[9], 'the counter ttl')
for _, line in ipairs(lines) do
	local ki = cmp_budget_index(line.subject)
	if 0 < counted then
		cmp_add(ki, 'c:' .. line.budget .. ':' .. line.period, counted)
	end
	redis.call('HSET', KEYS[1], 's:' .. line.subject, '1')
	cmp_touch(ki, now, ttl)
end
cmp_add(1, 'unsettled', charged)
redis.call('HSET', KEYS[1], 'c:' .. op, kind .. '|' .. cmp_str(charged))
return {'settled'}
`,
	}

	// A release at no charge (§9.7): the hold and its reservations dropped, the operation remembered as voided.
	//
	// KEYS: the projection, the unconfirmed set, the counters of every subject the hold may name.
	// ARGV: op, unconfirmed max age ms, memo ttl ms.
	// Reply: {outcome}: void (a repeat too, and one with no hold), settled (its charge stands: a settled operation
	// is never voided), dropped, absent (no projection).
	computeProjectionVoidScript = &operator.RedisScript{
		Name: "compute-projection-void",
		Source: computeHoldPrelude + `
local op = ARGV[1]
local now = cmp_now()
if not cmp_present() then
	return {'absent'}
end
local memo_ttl = cmp_int(ARGV[3], 'the memo ttl')
cmp_sweep(now, cmp_int(ARGV[2], 'the unconfirmed age'), memo_ttl)
if redis.call('HEXISTS', KEYS[1], 'c:' .. op) == 1 then
	return {'settled'}
end
local memo = redis.call('HGET', KEYS[1], 'x:' .. op)
if memo == 'd' then
	return {'dropped'}
end
if memo == 'v' then
	return {'void'}
end
local value = redis.call('HGET', KEYS[1], 'h:' .. op)
if value then
	local hold = cmp_hold_parse(value)
	if hold.state == 'u' then
		cmp_release_unconfirmed(hold)
		redis.call('ZREM', KEYS[2], op)
	else
		cmp_release_confirmed(hold)
	end
	redis.call('HDEL', KEYS[1], 'h:' .. op)
end
cmp_memo(op, 'v', memo_ttl)
return {'void'}
`,
	}

	// Settlement's last script (§9.7): for a booked batch, each operation's unsettled charge dropped, a hold it still
	// held released with its charge counted, and settled, promo, floor and state set from the committed account only
	// when the version passed is newer than the projection's.
	//
	// KEYS: the projection, the unconfirmed set, the counters of every subject the batch's operations name.
	// ARGV: version, settled, promo, floor, state, unconfirmed max age ms, memo ttl ms, counter ttl ms, the
	// operation count, then per operation its key and booked amount.
	// Reply: {outcome, dropped count, applied}: dropped, with how many charges it dropped and 1 where the account's
	// values were newer and taken; absent (no projection, which a rebuild makes).
	computeProjectionDropScript = &operator.RedisScript{
		Name: "compute-projection-drop",
		Source: computeHoldPrelude + `
local version = ARGV[1]
if not string.match(version, '^%d+$') or (1 < #version and string.sub(version, 1, 1) == '0') then
	return error('compute: the version is no decimal string')
end
local now = cmp_now()
if not cmp_present() then
	return {'absent', '0', '0'}
end
local memo_ttl = cmp_int(ARGV[7], 'the memo ttl')
cmp_sweep(now, cmp_int(ARGV[6], 'the unconfirmed age'), memo_ttl)
local ttl = cmp_int(ARGV[8], 'the counter ttl')
local count = cmp_int(ARGV[9], 'the operation count')
local dropped = 0
for i = 0, count - 1 do
	local op = ARGV[10 + 2 * i]
	local amount = cmp_int(ARGV[11 + 2 * i], 'a booked amount')
	local charge = redis.call('HGET', KEYS[1], 'c:' .. op)
	if charge then
		cmp_add(1, 'unsettled', -cmp_int(cmp_split(charge, '|')[2], 'a charge'))
		redis.call('HDEL', KEYS[1], 'c:' .. op)
		dropped = dropped + 1
	end
	local value = redis.call('HGET', KEYS[1], 'h:' .. op)
	if value then
		local hold = cmp_hold_parse(value)
		if hold.state == 'u' then
			cmp_release_unconfirmed(hold)
			redis.call('ZREM', KEYS[2], op)
		else
			cmp_release_confirmed(hold)
		end
		redis.call('HDEL', KEYS[1], 'h:' .. op)
		local counted = amount
		if hold.reserve < counted then
			counted = hold.reserve
		end
		for _, line in ipairs(hold.lines) do
			local ki = cmp_budget_index(line.subject)
			if 0 < counted then
				cmp_add(ki, 'c:' .. line.budget .. ':' .. line.period, counted)
			end
			cmp_touch(ki, now, ttl)
		end
	end
	cmp_memo(op, 'd', memo_ttl)
end
local held = redis.call('HGET', KEYS[1], 'version')
local applied = '0'
if #held < #version or (#held == #version and held < version) then
	redis.call('HSET', KEYS[1], 'version', version, 'settled', ARGV[2], 'promo', ARGV[3], 'floor', ARGV[4], 'state', ARGV[5])
	applied = '1'
end
return {'dropped', cmp_str(dropped), applied}
`,
	}

	// A lost cache's rebuild (§9.7, D-BAL-13): the whole projection, its holds, unsettled charges and counters,
	// written from a snapshot read under the network's fence, every key the call declares deleted first, and the
	// mark cleared, so the network admits again.
	//
	// KEYS: the projection, the unconfirmed set, the counters of every subject the snapshot names or the projection
	// listed.
	// ARGV: version, settled, promo, floor, state, accrued, counter ttl ms, the hold count, then per hold its key,
	// kind, amount, reserve, time ms and line count, then per line its subject, budget and period letter; the charge
	// count, then per charge its key, kind and amount; the counter count, then per counter its subject, budget,
	// period (d:YYYYMMDD or m:YYYYMM) and charged amount.
	// Reply: {rebuilt}.
	computeProjectionRebuildScript = &operator.RedisScript{
		Name: "compute-projection-rebuild",
		Source: computeHoldPrelude + `
local version = ARGV[1]
if not string.match(version, '^%d+$') or (1 < #version and string.sub(version, 1, 1) == '0') then
	return error('compute: the version is no decimal string')
end
for i = 1, #KEYS do
	redis.call('DEL', KEYS[i])
end
redis.call('HSET', KEYS[1], 'version', version, 'settled', ARGV[2], 'promo', ARGV[3], 'floor', ARGV[4], 'state', ARGV[5],
	'accrued', ARGV[6], 'unsettled', '0', 'holds', '0')
local ttl = cmp_int(ARGV[7], 'the counter ttl')
local at = 8
local count = cmp_int(ARGV[at], 'the hold count')
at = at + 1
for _ = 1, count do
	local op = ARGV[at]
	local hold = {
		state = 'c', kind = ARGV[at + 1], amount = cmp_int(ARGV[at + 2], 'a hold amount'),
		reserve = cmp_int(ARGV[at + 3], 'a hold reserve'), time = cmp_int(ARGV[at + 4], 'a hold time'), lines = {},
	}
	local periods = cmp_periods(hold.time)
	local lineCount = cmp_int(ARGV[at + 5], 'a hold line count')
	at = at + 6
	for _ = 1, lineCount do
		local letter = ARGV[at + 2]
		if letter ~= 'd' and letter ~= 'm' then
			return error('compute: a line period is d or m')
		end
		local line = {subject = ARGV[at], budget = ARGV[at + 1], period = periods[letter]}
		table.insert(hold.lines, line)
		cmp_add(cmp_budget_index(line.subject), 'r:' .. line.budget .. ':' .. line.period, hold.reserve)
		redis.call('HSET', KEYS[1], 's:' .. line.subject, '1')
		at = at + 3
	end
	redis.call('HSET', KEYS[1], 'h:' .. op, cmp_hold_format(hold))
	cmp_add(1, 'holds', hold.amount)
end
count = cmp_int(ARGV[at], 'the charge count')
at = at + 1
for _ = 1, count do
	local amount = cmp_int(ARGV[at + 2], 'a charge amount')
	redis.call('HSET', KEYS[1], 'c:' .. ARGV[at], ARGV[at + 1] .. '|' .. cmp_str(amount))
	cmp_add(1, 'unsettled', amount)
	at = at + 3
end
count = cmp_int(ARGV[at], 'the counter count')
at = at + 1
for _ = 1, count do
	local period = ARGV[at + 2]
	if not string.match(period, '^[dm]:%d+$') then
		return error('compute: a counter period is d:YYYYMMDD or m:YYYYMM')
	end
	cmp_add(cmp_budget_index(ARGV[at]), 'c:' .. ARGV[at + 1] .. ':' .. period, cmp_int(ARGV[at + 3], 'a counter'))
	redis.call('HSET', KEYS[1], 's:' .. ARGV[at], '1')
	at = at + 4
end
for i = 3, #KEYS do
	if redis.call('EXISTS', KEYS[i]) == 1 then
		redis.call('PEXPIRE', KEYS[i], ttl)
	end
end
return {'rebuilt'}
`,
	}

	// The mark a possibly lost projection carries until its rebuild (§9.7): admit nothing.
	//
	// KEYS: the projection. Reply: {marked}.
	computeProjectionMarkScript = &operator.RedisScript{
		Name: "compute-projection-mark",
		Source: `
redis.call('HSET', KEYS[1], 'rebuild', '1')
return {'marked'}
`,
	}

	// The projection's summary, for admission's and the states' readers (§9.7): no hold or charge field.
	//
	// KEYS: the projection.
	// Reply: {version, rebuild, settled, unsettled, holds, promo, floor, accrued, state}, nil for a field it lacks.
	computeProjectionReadScript = &operator.RedisScript{
		Name: "compute-projection-read",
		Source: `
return redis.call('HMGET', KEYS[1], 'version', 'rebuild', 'settled', 'unsettled', 'holds', 'promo', 'floor', 'accrued', 'state')
`,
	}
)
