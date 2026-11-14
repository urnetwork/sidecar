// FakeRedis's scripts. This fake runs no Lua: each RedisScript has a Go twin, registered by the same
// Name, that does what its Source does. A twin holds the fake's lock for its whole run, which is what
// atomic on its slot means, and reaches only the keys its call declared, which is what the rule in
// RedisScript.Source says a script may touch.
//
// A twin is only as true as its author made it, so T3 runs the real Source through the same scenario
// (Q-TEST-1), and a divergence fails.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/urnetwork/sidecar"
)

// What a script does. A twin returns the reply the Lua would, and an error for its error_reply.
type FakeRedisScriptFunction func(call *FakeRedisScriptCall) (*sidecar.RedisReply, error)

// Binds a script's twin to its Name. Registering one twice is a bug in the test, so it panics.
func (self *FakeRedis) RegisterScript(name string, function FakeRedisScriptFunction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, exists := self.twins[name]; exists {
		panic(fmt.Sprintf("a second twin for script %q", name))
	}
	self.twins[name] = function
}

func (self *FakeRedis) RunScript(ctx context.Context, script *sidecar.RedisScript, keys []string, args []string) (*sidecar.RedisReply, error) {
	var reply *sidecar.RedisReply
	err := self.call(ctx, "script:"+script.Name, keys, func() error {
		twin, ok := self.twins[script.Name]
		if !ok {
			return fmt.Errorf("%w: %q", ErrRedisNoTwin, script.Name)
		}
		call := &FakeRedisScriptCall{redis: self, Keys: slices.Clone(keys), Args: slices.Clone(args)}
		var err error
		reply, err = twin(call)
		return err
	})
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// One run of a script: its KEYS, its ARGV and the fake's data, for the length of the run alone.
type FakeRedisScriptCall struct {
	redis *FakeRedis
	// KEYS, as declared. Read a key from here, as the Lua reads KEYS[n], and never build one.
	Keys []string
	// ARGV.
	Args []string
}

var errRedisKeyNotDeclared = errors.New("ERR Script attempted to access a key not in KEYS")

func (self *FakeRedisScriptCall) check(key string) error {
	if !slices.Contains(self.Keys, key) {
		self.redis.violateWithLock(fmt.Sprintf("a script reached %q, which its KEYS do not name", key))
		return errRedisKeyNotDeclared
	}
	return nil
}

// TIME: the master's clock, read inside the script.
func (self *FakeRedisScriptCall) Now() time.Time {
	return self.redis.clock.Now()
}

func (self *FakeRedisScriptCall) Get(key string) ([]byte, bool, error) {
	if err := self.check(key); err != nil {
		return nil, false, err
	}
	entry, err := self.redis.stringEntryWithLock(key)
	if err != nil || entry == nil {
		return nil, false, err
	}
	return bytes.Clone(entry.value), true, nil
}

func (self *FakeRedisScriptCall) Set(key string, value []byte, ttl time.Duration) error {
	if err := self.check(key); err != nil {
		return err
	}
	if err := checkRedisTtl(ttl); err != nil {
		return err
	}
	self.redis.setWithLock(key, value, ttl)
	return nil
}

func (self *FakeRedisScriptCall) Increment(key string, ttl time.Duration) (int64, error) {
	if err := self.check(key); err != nil {
		return 0, err
	}
	return self.redis.incrementWithLock(key, ttl)
}

func (self *FakeRedisScriptCall) Delete(key string) error {
	if err := self.check(key); err != nil {
		return err
	}
	if _, exists := self.redis.entries[key]; exists {
		delete(self.redis.entries, key)
		self.redis.subscriber.publish(key)
	}
	return nil
}

func (self *FakeRedisScriptCall) Expire(key string, ttl time.Duration) (bool, error) {
	if err := self.check(key); err != nil {
		return false, err
	}
	if ttl <= 0 {
		return false, fmt.Errorf("an expire of %v would delete the key", ttl)
	}
	entry, exists := self.redis.entries[key]
	if exists {
		self.redis.setExpiryWithLock(key, entry, ttl)
		self.redis.subscriber.publish(key)
	}
	return exists, nil
}

// EXPIRE NX: sets the key's ttl only while it has none, and fires the g event only then, as a master
// does, so a key's expiry starts once per key generation (§6.8).
func (self *FakeRedisScriptCall) ExpireIfNone(key string, ttl time.Duration) (bool, error) {
	if err := self.check(key); err != nil {
		return false, err
	}
	if ttl <= 0 {
		return false, fmt.Errorf("an expire of %v would delete the key", ttl)
	}
	entry, exists := self.redis.entries[key]
	if !exists || !entry.expiresAt.IsZero() {
		return false, nil
	}
	self.redis.setExpiryWithLock(key, entry, ttl)
	self.redis.subscriber.publish(key)
	return true, nil
}

// EXISTS of one key, of any kind.
func (self *FakeRedisScriptCall) Exists(key string) (bool, error) {
	if err := self.check(key); err != nil {
		return false, err
	}
	_, exists := self.redis.entries[key]
	return exists, nil
}

func (self *FakeRedisScriptCall) HashGet(key string, field string) ([]byte, bool, error) {
	if err := self.check(key); err != nil {
		return nil, false, err
	}
	entry, err := self.redis.hashEntryWithLock(key)
	if err != nil || entry == nil {
		return nil, false, err
	}
	value, ok := entry.fields[field]
	if !ok {
		return nil, false, nil
	}
	return bytes.Clone(value.value), true, nil
}

// HGETALL: an absent key is an empty map.
func (self *FakeRedisScriptCall) HashGetAll(key string) (map[string][]byte, error) {
	if err := self.check(key); err != nil {
		return nil, err
	}
	entry, err := self.redis.hashEntryWithLock(key)
	if err != nil {
		return nil, err
	}
	fieldValues := map[string][]byte{}
	if entry != nil {
		for field, value := range entry.fields {
			fieldValues[field] = bytes.Clone(value.value)
		}
	}
	return fieldValues, nil
}

func (self *FakeRedisScriptCall) HashSet(key string, fieldValues map[string][]byte) error {
	if err := self.check(key); err != nil {
		return err
	}
	return self.redis.hashSetWithLock(key, fieldValues)
}

func (self *FakeRedisScriptCall) HashDelete(key string, fields []string) error {
	if err := self.check(key); err != nil {
		return err
	}
	return self.redis.hashDeleteWithLock(key, fields)
}

func (self *FakeRedisScriptCall) HashExpire(key string, fields []string, ttl time.Duration) error {
	if err := self.check(key); err != nil {
		return err
	}
	if ttl <= 0 {
		return fmt.Errorf("a field ttl of %v", ttl)
	}
	return self.redis.hashExpireWithLock(key, fields, ttl)
}

// HINCRBY of one: the field raised in place, its own ttl kept as Redis keeps it, where HashSet clears it. An
// absent field counts from 0, and one that is no integer is Redis's error.
func (self *FakeRedisScriptCall) HashIncrement(key string, field string) (int64, error) {
	if err := self.check(key); err != nil {
		return 0, err
	}
	entry, err := self.redis.hashEntryWithLock(key)
	if err != nil {
		return 0, err
	}
	if entry == nil {
		entry = &fakeRedisEntry{kind: fakeRedisHash, fields: map[string]*fakeRedisField{}}
		self.redis.entries[key] = entry
	}
	current, ok := entry.fields[field]
	if !ok {
		entry.fields[field] = &fakeRedisField{value: []byte("1")}
		return 1, nil
	}
	value, err := strconv.ParseInt(string(current.value), 10, 64)
	if err != nil {
		return 0, errors.New("ERR hash value is not an integer")
	}
	value += 1
	current.value = []byte(strconv.FormatInt(value, 10))
	return value, nil
}

func (self *FakeRedisScriptCall) StreamAdd(key string, maxLength int64, fieldValues map[string][]byte) (string, error) {
	if err := self.check(key); err != nil {
		return "", err
	}
	return self.redis.streamAddWithLock(key, maxLength, fieldValues)
}

// XREVRANGE + - COUNT 1: the stream's last entry, found false while the stream is absent or empty.
func (self *FakeRedisScriptCall) StreamLast(key string) (*sidecar.RedisStreamEntry, bool, error) {
	if err := self.check(key); err != nil {
		return nil, false, err
	}
	entry, err := self.redis.streamEntryWithLock(key, false)
	if err != nil || entry == nil || len(entry.stream.entries) == 0 {
		return nil, false, err
	}
	return entry.stream.entries[len(entry.stream.entries)-1].reply(), true, nil
}

func (self *FakeRedis) violateWithLock(violation string) {
	self.violations = append(self.violations, violation)
	if self.settings.Report != nil {
		self.settings.Report(violation)
	}
}

// A bulk reply, as a script's string or a version comes back.
func RedisBulkReply(value []byte) *sidecar.RedisReply {
	return &sidecar.RedisReply{Kind: sidecar.RedisReplyBulk, Bulk: value}
}

func RedisIntegerReply(value int64) *sidecar.RedisReply {
	return &sidecar.RedisReply{Kind: sidecar.RedisReplyInteger, Integer: value}
}

func RedisNilReply() *sidecar.RedisReply {
	return &sidecar.RedisReply{Kind: sidecar.RedisReplyNil}
}

func RedisArrayReply(replies ...*sidecar.RedisReply) *sidecar.RedisReply {
	return &sidecar.RedisReply{Kind: sidecar.RedisReplyArray, Replies: replies}
}

// A version as a script must return one: a canonical decimal string in a bulk reply, never a Lua
// number (D-PROTO-12).
func RedisVersionReply(version uint64) *sidecar.RedisReply {
	return RedisBulkReply(strconv.AppendUint(nil, version, 10))
}
