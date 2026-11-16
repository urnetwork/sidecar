// The Go twins of smtpedgeservice's quota scripts for FakeRedis (fake_redis_script.go): each does what
// its Lua does, step for step, holding the fake's lock for the whole run, reading the master's clock as
// the Lua reads TIME. HINCRBY and DECR keep a field's or key's ttl as Redis does, so those two are done
// on the fake's state in place. RunSmtpQuotaScriptSuite runs a twin and the Lua through the same cases.

package sidecartest

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

var (
	errSmtpTwinArguments = errors.New("ERR wrong number of arguments")
	// what tonumber's nil makes of a comparison in the Lua
	errSmtpTwinNotNumber = errors.New("ERR attempt to compare nil with number")
)

// A live member's value, as the reserve script's string.match reads it.
var smtpTwinMemberPattern = regexp.MustCompile(`^(\d+):(\d+):(\d)$`)

// Registers every quota script's twin on redis.
func RegisterSmtpQuotaScripts(redis *FakeRedis) {
	redis.RegisterScript(smtpedgeservice.SmtpQuotaReserveScript.Name, smtpQuotaReserveTwin)
	redis.RegisterScript(smtpedgeservice.SmtpQuotaDebitScript.Name, smtpQuotaDebitTwin)
	redis.RegisterScript(smtpedgeservice.SmtpQuotaCloseScript.Name, smtpQuotaCloseTwin)
	redis.RegisterScript(smtpedgeservice.SmtpQuotaHaltScript.Name, smtpQuotaHaltTwin)
	redis.RegisterScript(smtpedgeservice.SmtpHourCountScript.Name, smtpHourCountTwin)
	redis.RegisterScript(smtpedgeservice.SmtpHourUncountScript.Name, smtpHourUncountTwin)
}

// tonumber of an argument.
func smtpTwinArg(call *FakeRedisScriptCall, index int) (int64, error) {
	value, err := strconv.ParseInt(call.Args[index], 10, 64)
	if err != nil {
		return 0, errSmtpTwinNotNumber
	}
	return value, nil
}

// tonumber(redis.call('HGET', key, field) or '0').
func smtpTwinHashNumber(call *FakeRedisScriptCall, key string, field string) (int64, error) {
	value, found, err := call.HashGet(key, field)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, nil
	}
	number, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return 0, errSmtpTwinNotNumber
	}
	return number, nil
}

// HINCRBY key field delta: the field raised in place, its ttl kept, an absent field from 0 with none.
func smtpTwinHashAdd(call *FakeRedisScriptCall, key string, field string, delta int64) (int64, error) {
	if err := call.check(key); err != nil {
		return 0, err
	}
	entry, err := call.redis.hashEntryWithLock(key)
	if err != nil {
		return 0, err
	}
	if entry == nil {
		entry = &fakeRedisEntry{kind: fakeRedisHash, fields: map[string]*fakeRedisField{}}
		call.redis.entries[key] = entry
	}
	current, ok := entry.fields[field]
	if !ok {
		current = &fakeRedisField{value: []byte("0")}
		entry.fields[field] = current
	}
	value, err := strconv.ParseInt(string(current.value), 10, 64)
	if err != nil {
		return 0, errors.New("ERR hash value is not an integer")
	}
	value += delta
	current.value = []byte(strconv.FormatInt(value, 10))
	return value, nil
}

// The Lua's reply array.
func smtpTwinReply(values ...any) *sidecar.RedisReply {
	replies := []*sidecar.RedisReply{}
	for _, value := range values {
		switch typed := value.(type) {
		case int64:
			replies = append(replies, RedisIntegerReply(typed))
		case string:
			replies = append(replies, RedisBulkReply([]byte(typed)))
		}
	}
	return RedisArrayReply(replies...)
}

// smtpedgeservice.SmtpQuotaReserveScript.
func smtpQuotaReserveTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 1 || len(call.Args) != 14 {
		return nil, errSmtpTwinArguments
	}
	key := call.Keys[0]
	now := call.Now().UnixMilli()
	day := now / 86400000
	over := func(limit int64, value int64) bool {
		return limit != -1 && limit < value
	}
	args := make([]int64, 14)
	for _, index := range []int{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13} {
		value, err := smtpTwinArg(call, index)
		if err != nil {
			return nil, err
		}
		args[index] = value
	}
	haltEnd, err := smtpTwinHashNumber(call, key, "h")
	if err != nil {
		return nil, err
	}
	if now < haltEnd {
		return smtpTwinReply(int64(2), haltEnd-now, day, "halt", ""), nil
	}
	if call.Args[1] != "" {
		labelEnd, err := smtpTwinHashNumber(call, key, "h:"+call.Args[1])
		if err != nil {
			return nil, err
		}
		if now < labelEnd {
			return smtpTwinReply(int64(2), labelEnd-now, day, "label_halt", ""), nil
		}
	}
	recipients := args[2]
	if over(args[6], recipients) {
		return smtpTwinReply(int64(3), int64(0), day, "recipients_per_message", ""), nil
	}
	if over(args[7], args[3]) {
		return smtpTwinReply(int64(3), int64(0), day, "message_bytes", ""), nil
	}
	fieldValues, err := call.HashGetAll(key)
	if err != nil {
		return nil, err
	}
	members := int64(0)
	reservedConnections := int64(0)
	reservedRecipients := int64(0)
	for field, value := range fieldValues {
		if !strings.HasPrefix(field, "cc:") {
			continue
		}
		members += 1
		match := smtpTwinMemberPattern.FindStringSubmatch(string(value))
		if match == nil {
			continue
		}
		memberDay, _ := strconv.ParseInt(match[1], 10, 64)
		memberRecipients, _ := strconv.ParseInt(match[2], 10, 64)
		if memberDay == day && match[3] == "0" {
			reservedConnections += 1
			reservedRecipients += memberRecipients
		}
	}
	if over(args[11], members+1) {
		return smtpTwinReply(int64(3), int64(0), day, "concurrent_connections", ""), nil
	}
	untilTomorrow := (day+1)*86400000 - now
	connections, err := smtpTwinHashNumber(call, key, fmt.Sprintf("c:%d", day))
	if err != nil {
		return nil, err
	}
	if over(args[4], connections+reservedConnections+1) {
		return smtpTwinReply(int64(3), untilTomorrow, day, "connections_per_day", ""), nil
	}
	debitedRecipients, err := smtpTwinHashNumber(call, key, fmt.Sprintf("r:%d", day))
	if err != nil {
		return nil, err
	}
	if over(args[5], debitedRecipients+reservedRecipients+recipients) {
		return smtpTwinReply(int64(3), untilTomorrow, day, "recipients_per_day", ""), nil
	}
	bytes, err := smtpTwinHashNumber(call, key, fmt.Sprintf("b:%d", day))
	if err != nil {
		return nil, err
	}
	if args[8] != -1 && args[8] <= bytes {
		return smtpTwinReply(int64(3), untilTomorrow, day, "bytes_per_day", ""), nil
	}
	burstField := ""
	if burst := args[9]; burst != -1 {
		window := args[10]
		if window <= 0 {
			// the Lua's division by zero makes no number a field can be named by
			return nil, errSmtpTwinNotNumber
		}
		index := now / window
		burstField = fmt.Sprintf("t:%d", index)
		used, err := smtpTwinHashNumber(call, key, burstField)
		if err != nil {
			return nil, err
		}
		if burst < used+1 {
			return smtpTwinReply(int64(3), (index+1)*window-now, day, "burst", ""), nil
		}
		if _, err := smtpTwinHashAdd(call, key, burstField, 1); err != nil {
			return nil, err
		}
		if err := call.HashExpire(key, []string{burstField}, time.Duration(2*window)*time.Millisecond); err != nil {
			return nil, err
		}
	}
	member := "cc:" + call.Args[0]
	if err := call.HashSet(key, map[string][]byte{member: []byte(fmt.Sprintf("%d:%d:0", day, recipients))}); err != nil {
		return nil, err
	}
	if err := call.HashExpire(key, []string{member}, time.Duration(args[12])*time.Millisecond); err != nil {
		return nil, err
	}
	if _, err := call.Expire(key, time.Duration(args[13])*time.Millisecond); err != nil {
		return nil, err
	}
	return smtpTwinReply(int64(1), int64(0), day, "", burstField), nil
}

// smtpedgeservice.SmtpQuotaDebitScript.
func smtpQuotaDebitTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 1 || len(call.Args) != 5 {
		return nil, errSmtpTwinArguments
	}
	key := call.Keys[0]
	member := "cc:" + call.Args[0]
	value, found, err := call.HashGet(key, member)
	if err != nil {
		return nil, err
	}
	if found && strings.HasSuffix(string(value), ":1") {
		return RedisIntegerReply(0), nil
	}
	recipients, err := smtpTwinArg(call, 2)
	if err != nil {
		return nil, err
	}
	memberTtl, err := smtpTwinArg(call, 3)
	if err != nil {
		return nil, err
	}
	keyTtl, err := smtpTwinArg(call, 4)
	if err != nil {
		return nil, err
	}
	connectionsField := "c:" + call.Args[1]
	recipientsField := "r:" + call.Args[1]
	if _, err := smtpTwinHashAdd(call, key, connectionsField, 1); err != nil {
		return nil, err
	}
	if _, err := smtpTwinHashAdd(call, key, recipientsField, recipients); err != nil {
		return nil, err
	}
	if err := call.HashExpire(key, []string{connectionsField, recipientsField}, time.Duration(keyTtl)*time.Millisecond); err != nil {
		return nil, err
	}
	if found {
		if err := call.HashSet(key, map[string][]byte{member: []byte(call.Args[1] + ":" + call.Args[2] + ":1")}); err != nil {
			return nil, err
		}
		if err := call.HashExpire(key, []string{member}, time.Duration(memberTtl)*time.Millisecond); err != nil {
			return nil, err
		}
	}
	if _, err := call.Expire(key, time.Duration(keyTtl)*time.Millisecond); err != nil {
		return nil, err
	}
	return RedisIntegerReply(1), nil
}

// smtpedgeservice.SmtpQuotaCloseScript.
func smtpQuotaCloseTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 1 || len(call.Args) != 4 {
		return nil, errSmtpTwinArguments
	}
	key := call.Keys[0]
	if err := call.HashDelete(key, []string{"cc:" + call.Args[0]}); err != nil {
		return nil, err
	}
	bytes, err := smtpTwinArg(call, 2)
	if err != nil {
		return nil, err
	}
	if 0 < bytes {
		keyTtl, err := smtpTwinArg(call, 3)
		if err != nil {
			return nil, err
		}
		field := "b:" + call.Args[1]
		if _, err := smtpTwinHashAdd(call, key, field, bytes); err != nil {
			return nil, err
		}
		if err := call.HashExpire(key, []string{field}, time.Duration(keyTtl)*time.Millisecond); err != nil {
			return nil, err
		}
		if _, err := call.Expire(key, time.Duration(keyTtl)*time.Millisecond); err != nil {
			return nil, err
		}
	}
	return RedisIntegerReply(1), nil
}

// smtpedgeservice.SmtpQuotaHaltScript.
func smtpQuotaHaltTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 1 || len(call.Args) != 3 {
		return nil, errSmtpTwinArguments
	}
	key := call.Keys[0]
	now := call.Now().UnixMilli()
	haltEnd, err := smtpTwinArg(call, 1)
	if err != nil {
		return nil, err
	}
	keyTtl, err := smtpTwinArg(call, 2)
	if err != nil {
		return nil, err
	}
	if haltEnd <= now {
		return RedisIntegerReply(0), nil
	}
	current, err := smtpTwinHashNumber(call, key, call.Args[0])
	if err != nil {
		return nil, err
	}
	if haltEnd <= current {
		return RedisIntegerReply(0), nil
	}
	if err := call.HashSet(key, map[string][]byte{call.Args[0]: []byte(call.Args[1])}); err != nil {
		return nil, err
	}
	if err := call.HashExpire(key, []string{call.Args[0]}, time.Duration(haltEnd-now)*time.Millisecond); err != nil {
		return nil, err
	}
	if _, err := call.Expire(key, time.Duration(max(keyTtl, haltEnd-now))*time.Millisecond); err != nil {
		return nil, err
	}
	return RedisIntegerReply(1), nil
}

// smtpedgeservice.SmtpHourCountScript.
func smtpHourCountTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 1 || len(call.Args) != 2 {
		return nil, errSmtpTwinArguments
	}
	key := call.Keys[0]
	cap, err := smtpTwinArg(call, 0)
	if err != nil {
		return nil, err
	}
	ttl, err := smtpTwinArg(call, 1)
	if err != nil {
		return nil, err
	}
	count, err := call.Increment(key, 0)
	if err != nil {
		return nil, err
	}
	if count == 1 {
		if _, err := call.Expire(key, time.Duration(ttl)*time.Millisecond); err != nil {
			return nil, err
		}
	}
	if cap != -1 && cap < count {
		if _, err := smtpTwinStringAdd(call, key, -1); err != nil {
			return nil, err
		}
		return smtpTwinReply(int64(0), count-1), nil
	}
	return smtpTwinReply(int64(1), count), nil
}

// smtpedgeservice.SmtpHourUncountScript.
func smtpHourUncountTwin(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
	if len(call.Keys) != 1 || len(call.Args) != 0 {
		return nil, errSmtpTwinArguments
	}
	value, found, err := call.Get(call.Keys[0])
	if err != nil {
		return nil, err
	}
	count := int64(0)
	if found {
		if count, err = strconv.ParseInt(string(value), 10, 64); err != nil {
			return nil, errSmtpTwinNotNumber
		}
	}
	if 0 < count {
		decremented, err := smtpTwinStringAdd(call, call.Keys[0], -1)
		if err != nil {
			return nil, err
		}
		return RedisIntegerReply(decremented), nil
	}
	return RedisIntegerReply(0), nil
}

// INCRBY or DECR of a string key in place, its ttl kept.
func smtpTwinStringAdd(call *FakeRedisScriptCall, key string, delta int64) (int64, error) {
	if err := call.check(key); err != nil {
		return 0, err
	}
	entry, err := call.redis.stringEntryWithLock(key)
	if err != nil {
		return 0, err
	}
	if entry == nil {
		entry = &fakeRedisEntry{kind: fakeRedisString, value: []byte("0")}
		call.redis.entries[key] = entry
	}
	value, err := strconv.ParseInt(string(entry.value), 10, 64)
	if err != nil {
		return 0, errors.New("ERR value is not an integer or out of range")
	}
	value += delta
	entry.value = strconv.AppendInt(nil, value, 10)
	return value, nil
}
