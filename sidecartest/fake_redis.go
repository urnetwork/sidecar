// T2's ServiceHost.Redis (§22.4, §22.5): production's cluster in memory, with the injected clock for
// every ttl. It models 3 masters holding the 16384 slots, so what a one-node Redis lets pass fails
// here as it does in production:
//
//   - a call naming keys on two slots gets CROSSSLOT, and a call whose keys share a slot only by luck,
//     with no shared hash tag, gets the same refusal, which is §22.4's lint at run time;
//   - a script reaches only the keys it declares, and it must have a Go twin registered under its name,
//     since this fake runs no Lua: a script with no twin fails rather than do nothing;
//   - each call is counted by name, a script as script:<name>, for §22.5's op-counted hot paths;
//   - keyspace events fire on the shared subscriber's goroutine for production's classes only,
//     K, g, $, s and x, so SET, INCR, DEL, EXPIRE and an expiry notify, and HSET and XADD do not
//     (D-PROTO-12). They fire as a write applies, the way a master fires them inside the command, so a
//     write whose answer is lost still notifies, and as often as a master does: SET with a ttl twice,
//     once for the value and once for its expiry. A hash losing its last field fires the DEL it became.
//
// Faults come from the shared FaultQueue under FaultOpRedis, keyed by a call's first key. Everything
// here is safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

var (
	// What production's cluster answers. Also the lint's answer for keys that share a slot by luck.
	ErrRedisCrossSlot = errors.New("CROSSSLOT Keys in request don't hash to the same slot")
	// An operation on a key of another kind.
	ErrRedisWrongType = errors.New("WRONGTYPE Operation against a key holding the wrong kind of value")
	// A read of a stream group that does not exist.
	ErrRedisNoGroup = errors.New("NOGROUP No such consumer group for this key")
	// A script whose Name has no registered twin.
	ErrRedisNoTwin = errors.New("no Go twin registered for this script")
	// What a client sees when a fault plan drops a call: Redis did not answer.
	errRedisTransport = errors.New("redis connection reset by the fault plan")
)

const redisClusterSlotCount = 16384

// The XMODEM CRC16 of what Redis Cluster hashes.
func redisCrc16(data []byte) uint16 {
	crc := uint16(0)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for range 8 {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// The slot a key hashes to, the one production's cluster computes.
func RedisClusterSlot(key string) int {
	return int(redisCrc16([]byte(sidecar.RedisHashTag(key)))) % redisClusterSlotCount
}

// Which of the 3 masters holds a slot, as redis-cli --cluster create divides them: 0-5460, 5461-10922
// and 10923-16383.
func RedisClusterMaster(slot int) int {
	switch {
	case slot <= 5460:
		return 0
	case slot <= 10922:
		return 1
	}
	return 2
}

type FakeRedisSettings struct {
	// How long a parked call's caller waits before it gives up, on the clock.
	RequestTimeout time.Duration
	// Entries one radix node of a stream holds, which MAXLEN ~ trims by: Redis's stream-node-max-entries.
	StreamNodeEntryCount int
	// How long, in real time, a key event callback may run before it counts as blocking the shared
	// subscriber, which redis.go's contract forbids. Non-positive disables the check.
	CallbackTimeout time.Duration
	// Told each rule a caller broke, as it happens. nil: Violations alone holds them.
	Report func(violation string)
}

func DefaultFakeRedisSettings() *FakeRedisSettings {
	return &FakeRedisSettings{
		RequestTimeout:       5 * time.Second,
		StreamNodeEntryCount: 100,
		CallbackTimeout:      5 * time.Second,
	}
}

type fakeRedisKind int

const (
	fakeRedisString fakeRedisKind = iota + 1
	fakeRedisHash
	fakeRedisStream
)

type fakeRedisField struct {
	value     []byte
	expiresAt time.Time
}

type fakeRedisEntry struct {
	kind      fakeRedisKind
	value     []byte
	fields    map[string]*fakeRedisField
	stream    *fakeRedisStreamState
	expiresAt time.Time
	// raised whenever expiresAt changes, so a timer from an old ttl does nothing
	expireSeq uint64
}

type FakeRedis struct {
	clock    Clock
	faults   *FaultQueue
	barriers *BarrierDriver
	settings *FakeRedisSettings
	ctx      context.Context
	cancel   context.CancelFunc

	stateLock  sync.Mutex
	entries    map[string]*fakeRedisEntry
	twins      map[string]FakeRedisScriptFunction
	opCounts   map[string]int
	violations []string
	expireSeq  uint64
	// closed and replaced at every stream add, for a blocked group read
	streamAdded chan struct{}
	parked      []*parkedRedisCall

	subscriber *fakeKeyEventSubscriber
}

// A nil clock, faults or settings takes a fresh one or the defaults. barriers may be nil outside a
// schedule. The fake runs one goroutine, the shared subscriber's, until ctx ends or Close.
func NewFakeRedis(ctx context.Context, clock Clock, faults *FaultQueue, barriers *BarrierDriver, settings *FakeRedisSettings) *FakeRedis {
	if clock == nil {
		clock = NewFakeClock(DefaultClockStart())
	}
	if faults == nil {
		faults = NewFaultQueue()
	}
	if settings == nil {
		settings = DefaultFakeRedisSettings()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &FakeRedis{
		clock:       clock,
		faults:      faults,
		barriers:    barriers,
		settings:    settings,
		ctx:         cancelCtx,
		cancel:      cancel,
		entries:     map[string]*fakeRedisEntry{},
		twins:       map[string]FakeRedisScriptFunction{},
		opCounts:    map[string]int{},
		streamAdded: make(chan struct{}),
	}
	self.subscriber = newFakeKeyEventSubscriber(cancelCtx, settings, self.violate)
	return self
}

func (self *FakeRedis) Close() {
	self.cancel()
}

func (self *FakeRedis) Faults() *FaultQueue {
	return self.faults
}

func (self *FakeRedis) violate(violation string) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.violations = append(self.violations, violation)
	}()
	if self.settings.Report != nil {
		self.settings.Report(violation)
	}
}

// Every rule a caller broke: a cross-slot call is one even though the caller also got the error.
func (self *FakeRedis) Violations() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.violations)
}

// How often each operation ran, by name: a command's lowercase name, a script's script:<name>. An
// oracle's reads do not count.
func (self *FakeRedis) OpCounts() map[string]int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return maps.Clone(self.opCounts)
}

// Starts counting from zero, so a test can measure one hot path.
func (self *FakeRedis) ResetOpCounts() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clear(self.opCounts)
}

// Everything the fake holds, as Redis SCAN+DUMP would give it, for CC3's scan.
func (self *FakeRedis) Dump() map[string][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	dump := map[string][]byte{}
	for key, entry := range self.entries {
		var serialized bytes.Buffer
		switch entry.kind {
		case fakeRedisString:
			serialized.Write(entry.value)
		case fakeRedisHash:
			for _, field := range slices.Sorted(maps.Keys(entry.fields)) {
				serialized.WriteString(field)
				serialized.WriteByte(0)
				serialized.Write(entry.fields[field].value)
				serialized.WriteByte(0)
			}
		case fakeRedisStream:
			for _, streamEntry := range entry.stream.entries {
				serialized.WriteString(streamEntry.id.String())
				for _, field := range slices.Sorted(maps.Keys(streamEntry.fieldValues)) {
					serialized.WriteString(field)
					serialized.WriteByte(0)
					serialized.Write(streamEntry.fieldValues[field])
					serialized.WriteByte(0)
				}
			}
		}
		dump[key] = serialized.Bytes()
	}
	return dump
}

// Redis is lost, and everything with it (FS-62): soft state rebuilds, so a caller finds keys absent.
// The subscription survives a restart of the master only by resubscribing, so Resync goes out.
func (self *FakeRedis) LoseEverything() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		clear(self.entries)
	}()
	self.subscriber.resync()
}

// Keys under keyPrefix are lost, as a family's keys are on one master's restart.
func (self *FakeRedis) LoseKeys(keyPrefix string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	maps.DeleteFunc(self.entries, func(key string, entry *fakeRedisEntry) bool {
		return strings.HasPrefix(key, keyPrefix)
	})
}

func (self *FakeRedis) blocking(wait func()) {
	if self.barriers != nil {
		self.barriers.Blocking(wait)
		return
	}
	wait()
}

// One call that a Delay parked.
type parkedRedisCall struct {
	serve  func() error
	landed chan struct{}
	err    error
}

// Serves every parked call, in order, and returns how many.
func (self *FakeRedis) DeliverDelayed() int {
	var parked []*parkedRedisCall
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		parked = self.parked
		self.parked = nil
	}()
	for _, call := range parked {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			call.err = call.serve()
		}()
		close(call.landed)
	}
	return len(parked)
}

// One call through the fake: the slot check, its fault, then serve under the lock. op is its count
// name, and keys every key it names. events run after the lock is released.
func (self *FakeRedis) call(ctx context.Context, op string, keys []string, serve func() error) error {
	stopIfDead(ctx)
	if isInspecting(ctx) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.expireDueWithLock()
		return serve()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := self.checkSlots(op, keys); err != nil {
		return err
	}
	faultKey := ""
	if 0 < len(keys) {
		faultKey = keys[0]
	}
	plan := self.faults.take(ctx, FaultOpRedis, "", faultKey)
	result := FaultResult(0)
	if plan != nil {
		result = plan.Result
	}
	switch result {
	case FailBeforeApply:
		return errRedisTransport
	case CrashBeforeApply:
		crashCaller(ctx)
	case Delay:
		return self.callDelayed(ctx, op, plan, serve)
	}
	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.opCounts[op] += 1
		self.expireDueWithLock()
		return serve()
	}()
	switch result {
	case ApplyThenDrop:
		return errRedisTransport
	case CrashAfterApply:
		crashCaller(ctx)
	}
	return err
}

func (self *FakeRedis) callDelayed(ctx context.Context, op string, plan *FaultPlan, serve func() error) error {
	call := &parkedRedisCall{
		serve: func() error {
			self.opCounts[op] += 1
			self.expireDueWithLock()
			return serve()
		},
		landed: make(chan struct{}),
	}
	if plan.Delay != DelayNeverLands {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.parked = append(self.parked, call)
		}()
	}
	timedOut := self.clock.After(self.settings.RequestTimeout)
	var err error
	self.blocking(func() {
		select {
		case <-call.landed:
			err = call.err
		case <-ctx.Done():
			err = ctx.Err()
		case <-timedOut:
			err = errRedisTransport
		}
	})
	stopIfDead(ctx)
	return err
}

// CROSSSLOT, at run time: §22.4's lint. A call's keys must share a slot, as production demands, and
// must do so by a shared hash tag, not by luck, or the two keys part at the next reshard.
func (self *FakeRedis) checkSlots(op string, keys []string) error {
	if len(keys) < 2 {
		return nil
	}
	if !sidecar.RedisKeysShareTag(keys) {
		self.violate(fmt.Sprintf("%s: keys %q share no hash tag", op, keys))
		return ErrRedisCrossSlot
	}
	return nil
}

func (self *FakeRedis) nextExpireSeqWithLock() uint64 {
	self.expireSeq += 1
	return self.expireSeq
}

// Gives entry a ttl, or none at zero, and sets the timer that removes it. A timer is what fires an
// expiry's event, as Redis's active expiry would, at the moment a schedule moves the clock past it.
func (self *FakeRedis) setExpiryWithLock(key string, entry *fakeRedisEntry, ttl time.Duration) {
	entry.expireSeq = self.nextExpireSeqWithLock()
	if ttl == 0 {
		entry.expiresAt = time.Time{}
		return
	}
	entry.expiresAt = self.clock.Now().Add(ttl)
	expireSeq := entry.expireSeq
	self.clock.AfterFunc(ttl, func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if current, ok := self.entries[key]; ok && current == entry && entry.expireSeq == expireSeq {
			delete(self.entries, key)
			self.subscriber.publish(key)
		}
	})
}

// Removes what has expired before serving a call. Timers normally beat this, and it covers a call
// racing a clock move.
func (self *FakeRedis) expireDueWithLock() {
	now := self.clock.Now()
	for key, entry := range self.entries {
		if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
			delete(self.entries, key)
			self.subscriber.publish(key)
			continue
		}
		if entry.kind != fakeRedisHash {
			continue
		}
		for field, value := range entry.fields {
			if !value.expiresAt.IsZero() && !now.Before(value.expiresAt) {
				delete(entry.fields, field)
			}
		}
		if len(entry.fields) == 0 {
			delete(self.entries, key)
			self.subscriber.publish(key)
		}
	}
}

func (self *FakeRedis) stringEntryWithLock(key string) (*fakeRedisEntry, error) {
	entry, ok := self.entries[key]
	if !ok {
		return nil, nil
	}
	if entry.kind != fakeRedisString {
		return nil, ErrRedisWrongType
	}
	return entry, nil
}

func checkRedisTtl(ttl time.Duration) error {
	if ttl < 0 {
		return fmt.Errorf("a ttl of %v", ttl)
	}
	return nil
}

func (self *FakeRedis) setWithLock(key string, value []byte, ttl time.Duration) {
	entry := &fakeRedisEntry{kind: fakeRedisString, value: bytes.Clone(value)}
	self.entries[key] = entry
	self.setExpiryWithLock(key, entry, ttl)
	self.subscriber.publish(key)
	if 0 < ttl {
		self.subscriber.publish(key)
	}
}

func (self *FakeRedis) Get(ctx context.Context, key string) ([]byte, bool, error) {
	var value []byte
	var found bool
	err := self.call(ctx, "get", []string{key}, func() error {
		entry, err := self.stringEntryWithLock(key)
		if err != nil || entry == nil {
			return err
		}
		value, found = bytes.Clone(entry.value), true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return value, found, nil
}

func (self *FakeRedis) GetMany(ctx context.Context, keys []string) ([][]byte, error) {
	values := make([][]byte, len(keys))
	err := self.call(ctx, "mget", keys, func() error {
		for index, key := range keys {
			// MGET reads a key of another kind as absent
			if entry, ok := self.entries[key]; ok && entry.kind == fakeRedisString {
				values[index] = bytes.Clone(entry.value)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return values, nil
}

func (self *FakeRedis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := checkRedisTtl(ttl); err != nil {
		return err
	}
	return self.call(ctx, "set", []string{key}, func() error {
		self.setWithLock(key, value, ttl)
		return nil
	})
}

func (self *FakeRedis) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if err := checkRedisTtl(ttl); err != nil {
		return false, err
	}
	set := false
	err := self.call(ctx, "setnx", []string{key}, func() error {
		if _, exists := self.entries[key]; exists {
			return nil
		}
		self.setWithLock(key, value, ttl)
		set = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return set, nil
}

func (self *FakeRedis) CompareAndSet(ctx context.Context, key string, expected []byte, value []byte, ttl time.Duration) (bool, error) {
	if err := checkRedisTtl(ttl); err != nil {
		return false, err
	}
	set := false
	err := self.call(ctx, "cas", []string{key}, func() error {
		entry, err := self.stringEntryWithLock(key)
		if err != nil || entry == nil || !bytes.Equal(entry.value, expected) {
			return err
		}
		self.setWithLock(key, value, ttl)
		set = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return set, nil
}

func (self *FakeRedis) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	deleted := false
	err := self.call(ctx, "cad", []string{key}, func() error {
		entry, err := self.stringEntryWithLock(key)
		if err != nil || entry == nil || !bytes.Equal(entry.value, expected) {
			return err
		}
		delete(self.entries, key)
		self.subscriber.publish(key)
		deleted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return deleted, nil
}

func (self *FakeRedis) incrementWithLock(key string, ttl time.Duration) (int64, error) {
	entry, err := self.stringEntryWithLock(key)
	if err != nil {
		return 0, err
	}
	var value int64
	if entry != nil {
		value, err = strconv.ParseInt(string(entry.value), 10, 64)
		if err != nil {
			return 0, errors.New("ERR value is not an integer or out of range")
		}
	} else {
		entry = &fakeRedisEntry{kind: fakeRedisString}
		self.entries[key] = entry
	}
	value += 1
	entry.value = strconv.AppendInt(nil, value, 10)
	self.subscriber.publish(key)
	// EXPIRE NX: the first increment sets the key's life, and a later one leaves it
	if 0 < ttl && entry.expiresAt.IsZero() {
		self.setExpiryWithLock(key, entry, ttl)
		self.subscriber.publish(key)
	}
	return value, nil
}

func (self *FakeRedis) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if err := checkRedisTtl(ttl); err != nil {
		return 0, err
	}
	var value int64
	err := self.call(ctx, "incr", []string{key}, func() error {
		var err error
		value, err = self.incrementWithLock(key, ttl)
		return err
	})
	if err != nil {
		return 0, err
	}
	return value, nil
}

func (self *FakeRedis) Delete(ctx context.Context, keys []string) error {
	return self.call(ctx, "del", keys, func() error {
		for _, key := range keys {
			if _, exists := self.entries[key]; exists {
				delete(self.entries, key)
				self.subscriber.publish(key)
			}
		}
		return nil
	})
}

func (self *FakeRedis) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, fmt.Errorf("an expire of %v would delete the key", ttl)
	}
	found := false
	err := self.call(ctx, "expire", []string{key}, func() error {
		if entry, exists := self.entries[key]; exists {
			self.setExpiryWithLock(key, entry, ttl)
			self.subscriber.publish(key)
			found = true
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return found, nil
}

func (self *FakeRedis) hashEntryWithLock(key string) (*fakeRedisEntry, error) {
	entry, ok := self.entries[key]
	if !ok {
		return nil, nil
	}
	if entry.kind != fakeRedisHash {
		return nil, ErrRedisWrongType
	}
	return entry, nil
}

func (self *FakeRedis) HashGet(ctx context.Context, key string, field string) ([]byte, bool, error) {
	var value []byte
	var found bool
	err := self.call(ctx, "hget", []string{key}, func() error {
		entry, err := self.hashEntryWithLock(key)
		if err != nil || entry == nil {
			return err
		}
		if fieldValue, ok := entry.fields[field]; ok {
			value, found = bytes.Clone(fieldValue.value), true
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return value, found, nil
}

func (self *FakeRedis) HashGetAll(ctx context.Context, key string) (map[string][]byte, error) {
	fieldValues := map[string][]byte{}
	err := self.call(ctx, "hgetall", []string{key}, func() error {
		entry, err := self.hashEntryWithLock(key)
		if err != nil || entry == nil {
			return err
		}
		for field, value := range entry.fields {
			fieldValues[field] = bytes.Clone(value.value)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fieldValues, nil
}

func (self *FakeRedis) hashSetWithLock(key string, fieldValues map[string][]byte) error {
	if len(fieldValues) == 0 {
		return errors.New("ERR wrong number of arguments for 'hset' command")
	}
	entry, err := self.hashEntryWithLock(key)
	if err != nil {
		return err
	}
	if entry == nil {
		entry = &fakeRedisEntry{kind: fakeRedisHash, fields: map[string]*fakeRedisField{}}
		self.entries[key] = entry
	}
	for field, value := range fieldValues {
		// HSET clears a field's own ttl
		entry.fields[field] = &fakeRedisField{value: bytes.Clone(value)}
	}
	return nil
}

func (self *FakeRedis) HashSet(ctx context.Context, key string, fieldValues map[string][]byte) error {
	return self.call(ctx, "hset", []string{key}, func() error {
		return self.hashSetWithLock(key, fieldValues)
	})
}

func (self *FakeRedis) hashDeleteWithLock(key string, fields []string) error {
	entry, err := self.hashEntryWithLock(key)
	if err != nil || entry == nil {
		return err
	}
	for _, field := range fields {
		delete(entry.fields, field)
	}
	if len(entry.fields) == 0 {
		delete(self.entries, key)
		self.subscriber.publish(key)
	}
	return nil
}

func (self *FakeRedis) HashDelete(ctx context.Context, key string, fields []string) error {
	return self.call(ctx, "hdel", []string{key}, func() error {
		return self.hashDeleteWithLock(key, fields)
	})
}

func (self *FakeRedis) hashExpireWithLock(key string, fields []string, ttl time.Duration) error {
	entry, err := self.hashEntryWithLock(key)
	if err != nil || entry == nil {
		return err
	}
	expiresAt := self.clock.Now().Add(ttl)
	for _, field := range fields {
		value, ok := entry.fields[field]
		if !ok {
			continue
		}
		value.expiresAt = expiresAt
		self.clock.AfterFunc(ttl, func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			current, ok := self.entries[key]
			if !ok || current != entry || entry.fields[field] != value || value.expiresAt != expiresAt {
				return
			}
			delete(entry.fields, field)
			if len(entry.fields) == 0 {
				delete(self.entries, key)
				self.subscriber.publish(key)
			}
		})
	}
	return nil
}

func (self *FakeRedis) HashExpire(ctx context.Context, key string, fields []string, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("a field ttl of %v", ttl)
	}
	return self.call(ctx, "hexpire", []string{key}, func() error {
		return self.hashExpireWithLock(key, fields, ttl)
	})
}
