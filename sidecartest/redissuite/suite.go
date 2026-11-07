// The store conformance suite for ServiceHost.Redis (§22.4): what host_redis.go declares, run against
// FakeRedis here and against a real Redis Cluster by whoever hosts one, so the fake stays honest
// (D-TEST-2). Q-TEST-2's point is that a one-node Redis accepts what production refuses, so this suite
// only means something on a cluster of 3 masters: a target's Redis must hash its keys across masters,
// and the cross-slot case proves it does.
//
// A case is a plain function returning its first failure, and Run loops over them
// (connect/CODESTYLE.md:216). Every key lives under a tag of the run's own, so a run on a shared
// cluster touches nothing else.
//
// Time differs by store: a fake moves its clock, a real cluster waits, so ttl cases go through
// Target.Pass, and only those cases cost real time, and only on a real store.

package redissuite

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

type Target struct {
	Redis sidecar.Redis
	// Lets timeout pass for the store: a fake's Advance, or a real wait.
	Pass func(timeout time.Duration)
	// Stands a script's twin up on a fake. nil on a real store, which runs the Source.
	RegisterScript func(name string, function sidecartest.FakeRedisScriptFunction)
	// How long to wait, in real time, for a key event a fake delivers at once.
	EventTimeout time.Duration
	// Starts a read that blocks, then moves a fake's clock past its block once it waits. nil on a real
	// store, whose read waits out its block by itself.
	PassBlockedRead func(ctx context.Context, start func())
}

type suiteCase struct {
	name string
	run  func(ctx context.Context, target *Target, keys *keySpace) error
}

// A case's own keys: every one is under {<run>_<case>...}, so one tag holds a case together, and
// otherTag names a tag on another master.
type keySpace struct {
	run   string
	cased string
}

func (self *keySpace) key(name string) string {
	return fmt.Sprintf("{%s_%s}%s", self.run, self.cased, name)
}

// A key with a tag of its own, hashing to another master than self.key does.
func (self *keySpace) keyOnAnotherMaster(name string) string {
	home := sidecartest.RedisClusterMaster(sidecartest.RedisClusterSlot(self.key(name)))
	for index := 0; ; index += 1 {
		key := fmt.Sprintf("{%s_%s_%d}%s", self.run, self.cased, index, name)
		if sidecartest.RedisClusterMaster(sidecartest.RedisClusterSlot(key)) != home {
			return key
		}
	}
}

// A key with no shared tag that hashes to the slot of self.key: the luck §22.4's rule refuses.
func (self *keySpace) keyOnTheSameSlotByLuck(name string) string {
	slot := sidecartest.RedisClusterSlot(self.key(name))
	for index := 0; ; index += 1 {
		key := fmt.Sprintf("%s-%s-%s-%d", self.run, self.cased, name, index)
		if sidecartest.RedisClusterSlot(key) == slot {
			return key
		}
	}
}

func newRunId() string {
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(random[:])
}

func Run(t *testing.T, target *Target) {
	t.Helper()
	ctx := t.Context()
	runId := newRunId()
	if target.RegisterScript != nil {
		registerTwins(target.RegisterScript)
	}
	for _, c := range cases() {
		keys := &keySpace{run: runId, cased: strings.ReplaceAll(c.name, "-", "_")}
		if err := c.run(ctx, target, keys); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func cases() []*suiteCase {
	return []*suiteCase{
		{name: "absent-is-an-answer", run: caseAbsent},
		{name: "set-and-get-are-binary-safe", run: caseSetGet},
		{name: "get-many-keeps-order", run: caseGetMany},
		{name: "set-with-a-ttl-expires", run: caseSetTtl},
		{name: "ttl-zero-never-expires", run: caseTtlZero},
		{name: "negative-ttl-is-an-error", run: caseNegativeTtl},
		{name: "set-if-absent-once", run: caseSetIfAbsent},
		{name: "compare-and-set", run: caseCompareAndSet},
		{name: "compare-and-delete", run: caseCompareAndDelete},
		{name: "increment-sets-its-life-once", run: caseIncrement},
		{name: "delete-of-absent-keys", run: caseDelete},
		{name: "expire-needs-a-positive-ttl", run: caseExpire},
		{name: "hash-round-trip", run: caseHash},
		{name: "hash-absent-key", run: caseHashAbsent},
		{name: "hash-field-ttl", run: caseHashExpire},
		{name: "wrong-type-is-an-error", run: caseWrongType},
		{name: "stream-ids-ascend", run: caseStreamIds},
		{name: "stream-range-after", run: caseStreamRange},
		{name: "stream-maxlen-keeps-at-least", run: caseStreamMaxLength},
		{name: "stream-group-reads-only-new", run: caseStreamGroup},
		{name: "stream-group-create-twice", run: caseStreamGroupCreateTwice},
		{name: "stream-group-block-passes-empty", run: caseStreamBlock},
		{name: "stream-group-ack-and-claim", run: caseStreamClaim},
		{name: "stream-group-missing-is-an-error", run: caseStreamNoGroup},
		{name: "script-replies", run: caseScriptReplies},
		{name: "script-is-atomic-on-its-slot", run: caseScriptAtomic},
		{name: "script-error-is-the-calls-error", run: caseScriptError},
		{name: "version-stays-exact-through-a-script", run: caseScriptVersion},
		{name: "cross-slot-get-many-refused", run: caseCrossSlotGetMany},
		{name: "cross-slot-delete-refused", run: caseCrossSlotDelete},
		{name: "cross-slot-script-refused", run: caseCrossSlotScript},
		{name: "one-tag-spans-keys", run: caseOneTag},
		{name: "key-events-fire-for-set-and-increment", run: caseKeyEvents},
		{name: "key-events-skip-hash-and-stream", run: caseKeyEventsSkip},
		{name: "key-event-pattern-needs-a-star", run: caseKeyEventPattern},
		{name: "key-event-remove-stops-delivery", run: caseKeyEventRemove},
		{name: "key-event-fires-on-expiry", run: caseKeyEventExpiry},
	}
}

func caseAbsent(ctx context.Context, target *Target, keys *keySpace) error {
	value, found, err := target.Redis.Get(ctx, keys.key("absent"))
	if err != nil {
		return err
	}
	if found || value != nil {
		return fmt.Errorf("found %q", value)
	}
	return nil
}

func caseSetGet(ctx context.Context, target *Target, keys *keySpace) error {
	value := []byte{0, 1, 2, 0xff, '\r', '\n', 0}
	key := keys.key("binary")
	if err := target.Redis.Set(ctx, key, value, 0); err != nil {
		return err
	}
	got, found, err := target.Redis.Get(ctx, key)
	if err != nil {
		return err
	}
	if !found || !bytes.Equal(got, value) {
		return fmt.Errorf("got %q, found %v", got, found)
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseGetMany(ctx context.Context, target *Target, keys *keySpace) error {
	first, absent, last := keys.key("a"), keys.key("b"), keys.key("c")
	if err := target.Redis.Set(ctx, first, []byte("first"), 0); err != nil {
		return err
	}
	if err := target.Redis.Set(ctx, last, []byte("last"), 0); err != nil {
		return err
	}
	values, err := target.Redis.GetMany(ctx, []string{first, absent, last})
	if err != nil {
		return err
	}
	if len(values) != 3 || string(values[0]) != "first" || values[1] != nil || string(values[2]) != "last" {
		return fmt.Errorf("values %q", values)
	}
	return target.Redis.Delete(ctx, []string{first, last})
}

func caseSetTtl(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("ttl")
	if err := target.Redis.Set(ctx, key, []byte("v"), 200*time.Millisecond); err != nil {
		return err
	}
	if _, found, err := target.Redis.Get(ctx, key); err != nil || !found {
		return fmt.Errorf("before its ttl: found %v, %v", found, err)
	}
	target.Pass(250 * time.Millisecond)
	if _, found, err := target.Redis.Get(ctx, key); err != nil || found {
		return fmt.Errorf("after its ttl: found %v, %v", found, err)
	}
	return nil
}

func caseTtlZero(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("forever")
	if err := target.Redis.Set(ctx, key, []byte("v"), 100*time.Millisecond); err != nil {
		return err
	}
	// a later set with no ttl clears the first one's
	if err := target.Redis.Set(ctx, key, []byte("v"), 0); err != nil {
		return err
	}
	target.Pass(150 * time.Millisecond)
	if _, found, err := target.Redis.Get(ctx, key); err != nil || !found {
		return fmt.Errorf("found %v, %v", found, err)
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseNegativeTtl(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("negative")
	if err := target.Redis.Set(ctx, key, []byte("v"), -1*time.Second); err == nil {
		return errors.New("Set took a negative ttl")
	}
	if _, err := target.Redis.SetIfAbsent(ctx, key, []byte("v"), -1*time.Second); err == nil {
		return errors.New("SetIfAbsent took a negative ttl")
	}
	if _, err := target.Redis.Increment(ctx, key, -1*time.Second); err == nil {
		return errors.New("Increment took a negative ttl")
	}
	return nil
}

func caseSetIfAbsent(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("once")
	set, err := target.Redis.SetIfAbsent(ctx, key, []byte("first"), time.Minute)
	if err != nil || !set {
		return fmt.Errorf("first: %v, %v", set, err)
	}
	set, err = target.Redis.SetIfAbsent(ctx, key, []byte("second"), time.Minute)
	if err != nil || set {
		return fmt.Errorf("second: %v, %v", set, err)
	}
	value, _, err := target.Redis.Get(ctx, key)
	if err != nil || string(value) != "first" {
		return fmt.Errorf("value %q, %v", value, err)
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseCompareAndSet(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("lease")
	set, err := target.Redis.CompareAndSet(ctx, key, []byte("x"), []byte("y"), time.Minute)
	if err != nil || set {
		return fmt.Errorf("absent matched: %v, %v", set, err)
	}
	if _, found, err := target.Redis.Get(ctx, key); err != nil || found {
		return fmt.Errorf("absent created: %v, %v", found, err)
	}
	if err := target.Redis.Set(ctx, key, []byte("holder-a"), time.Minute); err != nil {
		return err
	}
	set, err = target.Redis.CompareAndSet(ctx, key, []byte("holder-b"), []byte("holder-b2"), time.Minute)
	if err != nil || set {
		return fmt.Errorf("a stale holder renewed: %v, %v", set, err)
	}
	set, err = target.Redis.CompareAndSet(ctx, key, []byte("holder-a"), []byte("holder-a2"), time.Minute)
	if err != nil || !set {
		return fmt.Errorf("the holder could not renew: %v, %v", set, err)
	}
	value, _, err := target.Redis.Get(ctx, key)
	if err != nil || string(value) != "holder-a2" {
		return fmt.Errorf("value %q, %v", value, err)
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseCompareAndDelete(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("lease")
	if err := target.Redis.Set(ctx, key, []byte("newer-holder"), time.Minute); err != nil {
		return err
	}
	deleted, err := target.Redis.CompareAndDelete(ctx, key, []byte("old-holder"))
	if err != nil || deleted {
		return fmt.Errorf("an old holder's release took a newer lease: %v, %v", deleted, err)
	}
	deleted, err = target.Redis.CompareAndDelete(ctx, key, []byte("newer-holder"))
	if err != nil || !deleted {
		return fmt.Errorf("the holder's release: %v, %v", deleted, err)
	}
	deleted, err = target.Redis.CompareAndDelete(ctx, keys.key("absent"), []byte("x"))
	if err != nil || deleted {
		return fmt.Errorf("absent: %v, %v", deleted, err)
	}
	return nil
}

// INCR with EXPIRE NX: the first increment sets the life, and later ones leave it.
func caseIncrement(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("n")
	for want := int64(1); want <= 3; want += 1 {
		value, err := target.Redis.Increment(ctx, key, 300*time.Millisecond)
		if err != nil {
			return err
		}
		if value != want {
			return fmt.Errorf("value %d, want %d", value, want)
		}
		target.Pass(50 * time.Millisecond)
	}
	target.Pass(200 * time.Millisecond)
	if _, found, err := target.Redis.Get(ctx, key); err != nil || found {
		return fmt.Errorf("a later increment extended the life: %v, %v", found, err)
	}
	return nil
}

func caseDelete(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("a")
	if err := target.Redis.Set(ctx, key, []byte("v"), 0); err != nil {
		return err
	}
	if err := target.Redis.Delete(ctx, []string{key, keys.key("absent")}); err != nil {
		return err
	}
	if _, found, err := target.Redis.Get(ctx, key); err != nil || found {
		return fmt.Errorf("found %v, %v", found, err)
	}
	return nil
}

func caseExpire(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("a")
	found, err := target.Redis.Expire(ctx, key, time.Minute)
	if err != nil || found {
		return fmt.Errorf("absent: %v, %v", found, err)
	}
	if err := target.Redis.Set(ctx, key, []byte("v"), 0); err != nil {
		return err
	}
	if _, err := target.Redis.Expire(ctx, key, 0); err == nil {
		return errors.New("a zero Expire passed")
	}
	if _, err := target.Redis.Expire(ctx, key, -1*time.Second); err == nil {
		return errors.New("a negative Expire passed")
	}
	if _, found, err := target.Redis.Get(ctx, key); err != nil || !found {
		return fmt.Errorf("a refused Expire deleted the key: %v, %v", found, err)
	}
	found, err = target.Redis.Expire(ctx, key, 100*time.Millisecond)
	if err != nil || !found {
		return fmt.Errorf("present: %v, %v", found, err)
	}
	target.Pass(150 * time.Millisecond)
	if _, found, err := target.Redis.Get(ctx, key); err != nil || found {
		return fmt.Errorf("after its ttl: %v, %v", found, err)
	}
	return nil
}

func caseHash(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("h")
	fieldValues := map[string][]byte{"a": []byte("1"), "b": {0, 0xff}}
	if err := target.Redis.HashSet(ctx, key, fieldValues); err != nil {
		return err
	}
	value, found, err := target.Redis.HashGet(ctx, key, "b")
	if err != nil || !found || !bytes.Equal(value, fieldValues["b"]) {
		return fmt.Errorf("b: %q, %v, %v", value, found, err)
	}
	if _, found, err := target.Redis.HashGet(ctx, key, "absent"); err != nil || found {
		return fmt.Errorf("an absent field: %v, %v", found, err)
	}
	all, err := target.Redis.HashGetAll(ctx, key)
	if err != nil {
		return err
	}
	if len(all) != 2 || !bytes.Equal(all["a"], fieldValues["a"]) {
		return fmt.Errorf("all %q", all)
	}
	if err := target.Redis.HashDelete(ctx, key, []string{"a", "absent"}); err != nil {
		return err
	}
	if _, found, err := target.Redis.HashGet(ctx, key, "a"); err != nil || found {
		return fmt.Errorf("a deleted field: %v, %v", found, err)
	}
	// the last field gone, the key goes too
	if err := target.Redis.HashDelete(ctx, key, []string{"b"}); err != nil {
		return err
	}
	all, err = target.Redis.HashGetAll(ctx, key)
	if err != nil || len(all) != 0 {
		return fmt.Errorf("all %q, %v", all, err)
	}
	return nil
}

func caseHashAbsent(ctx context.Context, target *Target, keys *keySpace) error {
	all, err := target.Redis.HashGetAll(ctx, keys.key("absent"))
	if err != nil {
		return err
	}
	if all == nil || len(all) != 0 {
		return fmt.Errorf("all %v, want an empty map", all)
	}
	if err := target.Redis.HashExpire(ctx, keys.key("absent"), []string{"f"}, time.Minute); err != nil {
		return fmt.Errorf("expire of an absent key: %w", err)
	}
	return nil
}

func caseHashExpire(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("leases")
	if err := target.Redis.HashSet(ctx, key, map[string][]byte{"short": []byte("1"), "long": []byte("2")}); err != nil {
		return err
	}
	if err := target.Redis.HashExpire(ctx, key, []string{"short", "absent-field"}, 100*time.Millisecond); err != nil {
		return err
	}
	if err := target.Redis.HashExpire(ctx, key, []string{"long"}, time.Minute); err != nil {
		return err
	}
	target.Pass(150 * time.Millisecond)
	if _, found, err := target.Redis.HashGet(ctx, key, "short"); err != nil || found {
		return fmt.Errorf("short: %v, %v", found, err)
	}
	if _, found, err := target.Redis.HashGet(ctx, key, "long"); err != nil || !found {
		return fmt.Errorf("long: %v, %v", found, err)
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseWrongType(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("string")
	if err := target.Redis.Set(ctx, key, []byte("v"), 0); err != nil {
		return err
	}
	if _, _, err := target.Redis.HashGet(ctx, key, "f"); err == nil {
		return errors.New("a hash read of a string passed")
	}
	if _, err := target.Redis.StreamAdd(ctx, key, 0, map[string][]byte{"f": []byte("v")}); err == nil {
		return errors.New("a stream add to a string passed")
	}
	return target.Redis.Delete(ctx, []string{key})
}

// <ms>-<seq> compared as two integers, ascending however fast entries arrive.
func caseStreamIds(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("s")
	previous := [2]uint64{}
	for index := range 5 {
		entryId, err := target.Redis.StreamAdd(ctx, key, 0, map[string][]byte{"n": strconv.AppendInt(nil, int64(index), 10)})
		if err != nil {
			return err
		}
		msText, seqText, found := strings.Cut(entryId, "-")
		if !found {
			return fmt.Errorf("id %q", entryId)
		}
		ms, err := strconv.ParseUint(msText, 10, 64)
		if err != nil {
			return err
		}
		seq, err := strconv.ParseUint(seqText, 10, 64)
		if err != nil {
			return err
		}
		if ms < previous[0] || (ms == previous[0] && seq <= previous[1]) {
			return fmt.Errorf("id %q after %v", entryId, previous)
		}
		previous = [2]uint64{ms, seq}
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseStreamRange(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("s")
	entryIds := []string{}
	for index := range 5 {
		entryId, err := target.Redis.StreamAdd(ctx, key, 0, map[string][]byte{"n": {byte('0' + index)}})
		if err != nil {
			return err
		}
		entryIds = append(entryIds, entryId)
	}
	entries, err := target.Redis.StreamRange(ctx, key, "", 100)
	if err != nil {
		return err
	}
	if len(entries) != 5 || entries[0].Id != entryIds[0] || string(entries[4].FieldValues["n"]) != "4" {
		return fmt.Errorf("from the start: %d entries", len(entries))
	}
	entries, err = target.Redis.StreamRange(ctx, key, entryIds[1], 2)
	if err != nil {
		return err
	}
	if len(entries) != 2 || entries[0].Id != entryIds[2] || entries[1].Id != entryIds[3] {
		return fmt.Errorf("after the second: %d entries", len(entries))
	}
	entries, err = target.Redis.StreamRange(ctx, keys.key("absent"), "", 10)
	if err != nil || len(entries) != 0 {
		return fmt.Errorf("an absent stream: %d, %v", len(entries), err)
	}
	return target.Redis.Delete(ctx, []string{key})
}

// MAXLEN ~ trims whole radix nodes, so it keeps at least maxLength and at most a node more.
func caseStreamMaxLength(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("s")
	const maxLength = 100
	const nodeEntryCount = 100
	for index := range 450 {
		if _, err := target.Redis.StreamAdd(ctx, key, maxLength, map[string][]byte{"n": strconv.AppendInt(nil, int64(index), 10)}); err != nil {
			return err
		}
	}
	entries, err := target.Redis.StreamRange(ctx, key, "", 1000)
	if err != nil {
		return err
	}
	if len(entries) < maxLength || maxLength+nodeEntryCount <= len(entries) {
		return fmt.Errorf("kept %d", len(entries))
	}
	if newest := entries[len(entries)-1]; string(newest.FieldValues["n"]) != "449" {
		return fmt.Errorf("newest %q", newest.FieldValues["n"])
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseStreamGroup(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("wakeq")
	if _, err := target.Redis.StreamAdd(ctx, key, 0, map[string][]byte{"n": []byte("before")}); err != nil {
		return err
	}
	if err := target.Redis.StreamGroupCreate(ctx, key, "senders"); err != nil {
		return err
	}
	entries, err := target.Redis.StreamGroupRead(ctx, key, "senders", "sender-1", 10, 0)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("a group made after an entry read %d", len(entries))
	}
	for _, name := range []string{"one", "two", "three"} {
		if _, err := target.Redis.StreamAdd(ctx, key, 0, map[string][]byte{"n": []byte(name)}); err != nil {
			return err
		}
	}
	entries, err = target.Redis.StreamGroupRead(ctx, key, "senders", "sender-1", 2, 0)
	if err != nil {
		return err
	}
	if len(entries) != 2 || string(entries[0].FieldValues["n"]) != "one" {
		return fmt.Errorf("first read: %d", len(entries))
	}
	// another consumer gets what the first was not given
	entries, err = target.Redis.StreamGroupRead(ctx, key, "senders", "sender-2", 10, 0)
	if err != nil {
		return err
	}
	if len(entries) != 1 || string(entries[0].FieldValues["n"]) != "three" {
		return fmt.Errorf("second read: %d", len(entries))
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseStreamGroupCreateTwice(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("wakeq")
	if err := target.Redis.StreamGroupCreate(ctx, key, "senders"); err != nil {
		return err
	}
	if err := target.Redis.StreamGroupCreate(ctx, key, "senders"); err != nil {
		return fmt.Errorf("the second create: %w", err)
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseStreamBlock(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("wakeq")
	if err := target.Redis.StreamGroupCreate(ctx, key, "senders"); err != nil {
		return err
	}
	type readResult struct {
		entries []*sidecar.RedisStreamEntry
		err     error
	}
	done := make(chan readResult, 1)
	start := func() {
		go func() {
			entries, err := target.Redis.StreamGroupRead(ctx, key, "senders", "sender-1", 1, 100*time.Millisecond)
			done <- readResult{entries: entries, err: err}
		}()
	}
	if target.PassBlockedRead != nil {
		target.PassBlockedRead(ctx, start)
	} else {
		start()
	}
	result := <-done
	if result.err != nil {
		return result.err
	}
	if len(result.entries) != 0 {
		return fmt.Errorf("read %d", len(result.entries))
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseStreamClaim(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("wakeq")
	if err := target.Redis.StreamGroupCreate(ctx, key, "senders"); err != nil {
		return err
	}
	entryIds := []string{}
	for _, name := range []string{"one", "two"} {
		entryId, err := target.Redis.StreamAdd(ctx, key, 0, map[string][]byte{"n": []byte(name)})
		if err != nil {
			return err
		}
		entryIds = append(entryIds, entryId)
	}
	if _, err := target.Redis.StreamGroupRead(ctx, key, "senders", "dead-sender", 10, 0); err != nil {
		return err
	}
	if err := target.Redis.StreamGroupAck(ctx, key, "senders", entryIds[:1]); err != nil {
		return err
	}

	// not idle long enough, so nothing moves
	entries, cursor, err := target.Redis.StreamGroupClaim(ctx, key, "senders", "live-sender", time.Hour, "", 10)
	if err != nil {
		return err
	}
	if len(entries) != 0 || cursor != "0-0" {
		return fmt.Errorf("claimed %d early, cursor %q", len(entries), cursor)
	}

	target.Pass(120 * time.Millisecond)
	entries, cursor, err = target.Redis.StreamGroupClaim(ctx, key, "senders", "live-sender", 100*time.Millisecond, "", 10)
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0].Id != entryIds[1] || cursor != "0-0" {
		return fmt.Errorf("claimed %d, cursor %q: the acknowledged one must not return", len(entries), cursor)
	}
	// claiming resets idle time, so a second claim finds nothing
	entries, _, err = target.Redis.StreamGroupClaim(ctx, key, "senders", "third-sender", 100*time.Millisecond, "", 10)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("claimed %d twice", len(entries))
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseStreamNoGroup(ctx context.Context, target *Target, keys *keySpace) error {
	if _, err := target.Redis.StreamGroupRead(ctx, keys.key("absent"), "senders", "sender-1", 1, 0); err == nil {
		return errors.New("a read of a missing group passed")
	}
	return nil
}

var (
	repliesScript = &sidecar.RedisScript{
		Name: "redissuite-replies",
		Source: `
if ARGV[1] == 'nil' then return false end
if ARGV[1] == 'integer' then return 42 end
if ARGV[1] == 'bulk' then return 'bulk' end
return {1, 'two', {3}}`,
	}
	addScript = &sidecar.RedisScript{
		Name: "redissuite-add",
		Source: `
local value = redis.call('GET', KEYS[1])
if not value then value = '0' end
local sum = tonumber(value) + tonumber(ARGV[1])
redis.call('SET', KEYS[1], tostring(sum))
redis.call('SET', KEYS[2], tostring(sum))
return sum`,
	}
	failScript = &sidecar.RedisScript{
		Name:   "redissuite-fail",
		Source: `return redis.error_reply('REFUSED no such thing')`,
	}
	versionScript = &sidecar.RedisScript{
		Name: "redissuite-version",
		Source: `
local stored = redis.call('GET', KEYS[1])
if not stored or #ARGV[1] > #stored or (#ARGV[1] == #stored and ARGV[1] > stored) then
	redis.call('SET', KEYS[1], ARGV[1])
	return ARGV[1]
end
return stored`,
	}
)

func registerTwins(register func(name string, function sidecartest.FakeRedisScriptFunction)) {
	register(repliesScript.Name, func(call *sidecartest.FakeRedisScriptCall) (*sidecar.RedisReply, error) {
		switch call.Args[0] {
		case "nil":
			return sidecartest.RedisNilReply(), nil
		case "integer":
			return sidecartest.RedisIntegerReply(42), nil
		case "bulk":
			return sidecartest.RedisBulkReply([]byte("bulk")), nil
		}
		return sidecartest.RedisArrayReply(
			sidecartest.RedisIntegerReply(1),
			sidecartest.RedisBulkReply([]byte("two")),
			sidecartest.RedisArrayReply(sidecartest.RedisIntegerReply(3)),
		), nil
	})
	register(addScript.Name, func(call *sidecartest.FakeRedisScriptCall) (*sidecar.RedisReply, error) {
		value, found, err := call.Get(call.Keys[0])
		if err != nil {
			return nil, err
		}
		sum := int64(0)
		if found {
			if sum, err = strconv.ParseInt(string(value), 10, 64); err != nil {
				return nil, err
			}
		}
		amount, err := strconv.ParseInt(call.Args[0], 10, 64)
		if err != nil {
			return nil, err
		}
		sum += amount
		for _, key := range call.Keys {
			if err := call.Set(key, strconv.AppendInt(nil, sum, 10), 0); err != nil {
				return nil, err
			}
		}
		return sidecartest.RedisIntegerReply(sum), nil
	})
	register(failScript.Name, func(call *sidecartest.FakeRedisScriptCall) (*sidecar.RedisReply, error) {
		return nil, errors.New("REFUSED no such thing")
	})
	register(versionScript.Name, func(call *sidecartest.FakeRedisScriptCall) (*sidecar.RedisReply, error) {
		stored, found, err := call.Get(call.Keys[0])
		if err != nil {
			return nil, err
		}
		offered := []byte(call.Args[0])
		if !found || len(stored) < len(offered) || (len(stored) == len(offered) && bytes.Compare(stored, offered) < 0) {
			if err := call.Set(call.Keys[0], offered, 0); err != nil {
				return nil, err
			}
			return sidecartest.RedisBulkReply(offered), nil
		}
		return sidecartest.RedisBulkReply(stored), nil
	})
}

func caseScriptReplies(ctx context.Context, target *Target, keys *keySpace) error {
	run := func(arg string) (*sidecar.RedisReply, error) {
		return target.Redis.RunScript(ctx, repliesScript, []string{keys.key("unused")}, []string{arg})
	}
	reply, err := run("nil")
	if err != nil {
		return err
	}
	if reply.Kind != sidecar.RedisReplyNil {
		return fmt.Errorf("nil: kind %v", reply.Kind)
	}
	reply, err = run("integer")
	if err != nil {
		return err
	}
	if reply.Kind != sidecar.RedisReplyInteger || reply.Integer != 42 {
		return fmt.Errorf("integer: %+v", reply)
	}
	reply, err = run("bulk")
	if err != nil {
		return err
	}
	if reply.Kind != sidecar.RedisReplyBulk || string(reply.Bulk) != "bulk" {
		return fmt.Errorf("bulk: %+v", reply)
	}
	reply, err = run("array")
	if err != nil {
		return err
	}
	if reply.Kind != sidecar.RedisReplyArray || len(reply.Replies) != 3 ||
		reply.Replies[0].Integer != 1 || string(reply.Replies[1].Bulk) != "two" ||
		reply.Replies[2].Kind != sidecar.RedisReplyArray || reply.Replies[2].Replies[0].Integer != 3 {
		return fmt.Errorf("array: %+v", reply)
	}
	return nil
}

func caseScriptAtomic(ctx context.Context, target *Target, keys *keySpace) error {
	first, second := keys.key("a"), keys.key("b")
	done := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := target.Redis.RunScript(ctx, addScript, []string{first, second}, []string{"1"})
			done <- err
		}()
	}
	for range 8 {
		if err := <-done; err != nil {
			return err
		}
	}
	values, err := target.Redis.GetMany(ctx, []string{first, second})
	if err != nil {
		return err
	}
	if string(values[0]) != "8" || string(values[1]) != "8" {
		return fmt.Errorf("values %q", values)
	}
	return target.Redis.Delete(ctx, []string{first, second})
}

func caseScriptError(ctx context.Context, target *Target, keys *keySpace) error {
	reply, err := target.Redis.RunScript(ctx, failScript, []string{keys.key("unused")}, nil)
	if err == nil {
		return fmt.Errorf("reply %+v, want the call's error", reply)
	}
	if !strings.Contains(err.Error(), "REFUSED") {
		return fmt.Errorf("err %v", err)
	}
	return nil
}

// §6.8: a version near 1.8 x 10^18 passes through a script as text, or Lua's doubles round it.
func caseScriptVersion(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("ver")
	versions := []string{"1800000000000000001", "1800000000000000003", "1800000000000000002"}
	want := []string{"1800000000000000001", "1800000000000000003", "1800000000000000003"}
	for index, version := range versions {
		reply, err := target.Redis.RunScript(ctx, versionScript, []string{key}, []string{version})
		if err != nil {
			return err
		}
		if reply.Kind != sidecar.RedisReplyBulk || string(reply.Bulk) != want[index] {
			return fmt.Errorf("offered %s: %+v", version, reply)
		}
	}
	return target.Redis.Delete(ctx, []string{key})
}

func wantCrossSlot(what string, err error) error {
	if err == nil {
		return fmt.Errorf("%s passed", what)
	}
	if !strings.Contains(err.Error(), "CROSSSLOT") {
		return fmt.Errorf("%s: %v, want CROSSSLOT", what, err)
	}
	return nil
}

func caseCrossSlotGetMany(ctx context.Context, target *Target, keys *keySpace) error {
	_, err := target.Redis.GetMany(ctx, []string{keys.key("a"), keys.keyOnAnotherMaster("a")})
	return wantCrossSlot("a cross-slot MGET", err)
}

func caseCrossSlotDelete(ctx context.Context, target *Target, keys *keySpace) error {
	err := target.Redis.Delete(ctx, []string{keys.key("a"), keys.keyOnAnotherMaster("a")})
	return wantCrossSlot("a cross-slot DEL", err)
}

func caseCrossSlotScript(ctx context.Context, target *Target, keys *keySpace) error {
	_, err := target.Redis.RunScript(ctx, addScript, []string{keys.key("a"), keys.keyOnAnotherMaster("a")}, []string{"1"})
	return wantCrossSlot("a cross-slot script", err)
}

func caseOneTag(ctx context.Context, target *Target, keys *keySpace) error {
	first, second := keys.key("a"), keys.key("b")
	if sidecartest.RedisClusterSlot(first) != sidecartest.RedisClusterSlot(second) {
		return errors.New("one tag hashed to two slots")
	}
	if !sidecar.RedisKeysShareTag([]string{first, second}) {
		return errors.New("one tag is not shared")
	}
	if _, err := target.Redis.GetMany(ctx, []string{first, second}); err != nil {
		return err
	}
	return target.Redis.Delete(ctx, []string{first, second})
}

// Waits for an event on key, in real time, because a real cluster's reach the subscriber on its own
// schedule. A fake's arrive at once, so this costs it nothing.
func (self *Target) awaitKey(ctx context.Context, events <-chan sidecar.RedisKeyEvent, key string) error {
	timeout := time.After(self.EventTimeout)
	for {
		select {
		case event := <-events:
			if event.Key == key {
				return nil
			}
		case <-timeout:
			return fmt.Errorf("no event for %s in %v", key, self.EventTimeout)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (self *keySpace) pattern() string {
	return fmt.Sprintf("{%s_%s}*", self.run, self.cased)
}

func caseKeyEvents(ctx context.Context, target *Target, keys *keySpace) error {
	events := make(chan sidecar.RedisKeyEvent, 16)
	remove, err := target.Redis.AddKeyEventCallback(keys.pattern(), func(event sidecar.RedisKeyEvent) {
		events <- event
	})
	if err != nil {
		return err
	}
	defer remove()

	key := keys.key("n")
	if _, err := target.Redis.Increment(ctx, key, time.Minute); err != nil {
		return err
	}
	if err := target.awaitKey(ctx, events, key); err != nil {
		return fmt.Errorf("after Increment: %w", err)
	}
	setKey := keys.key("killed")
	if err := target.Redis.Set(ctx, setKey, []byte("1"), time.Minute); err != nil {
		return err
	}
	if err := target.awaitKey(ctx, events, setKey); err != nil {
		return fmt.Errorf("after Set: %w", err)
	}
	return target.Redis.Delete(ctx, []string{key, setKey})
}

// D-PROTO-12: HSET and XADD emit nothing, so a fence key on the same slot, set after them, is the
// proof: its event reaches the subscriber after any theirs would have.
func caseKeyEventsSkip(ctx context.Context, target *Target, keys *keySpace) error {
	events := make(chan sidecar.RedisKeyEvent, 16)
	remove, err := target.Redis.AddKeyEventCallback(keys.pattern(), func(event sidecar.RedisKeyEvent) {
		events <- event
	})
	if err != nil {
		return err
	}
	defer remove()

	hashKey, streamKey, fenceKey := keys.key("ver"), keys.key("hints"), keys.key("n")
	if err := target.Redis.HashSet(ctx, hashKey, map[string][]byte{"f": []byte("1")}); err != nil {
		return err
	}
	if _, err := target.Redis.StreamAdd(ctx, streamKey, 0, map[string][]byte{"f": []byte("1")}); err != nil {
		return err
	}
	if err := target.Redis.Set(ctx, fenceKey, []byte("1"), time.Minute); err != nil {
		return err
	}
	timeout := time.After(target.EventTimeout)
	for {
		select {
		case event := <-events:
			if event.Key == fenceKey {
				return target.Redis.Delete(ctx, []string{hashKey, streamKey, fenceKey})
			}
			return fmt.Errorf("an event for %s", event.Key)
		case <-timeout:
			return errors.New("the fence's event never came")
		}
	}
}

func caseKeyEventPattern(ctx context.Context, target *Target, keys *keySpace) error {
	remove, err := target.Redis.AddKeyEventCallback(keys.key("one-client"), func(event sidecar.RedisKeyEvent) {})
	if err == nil {
		remove()
		return errors.New("a pattern naming one key passed")
	}
	return nil
}

func caseKeyEventRemove(ctx context.Context, target *Target, keys *keySpace) error {
	events := make(chan sidecar.RedisKeyEvent, 16)
	remove, err := target.Redis.AddKeyEventCallback(keys.pattern(), func(event sidecar.RedisKeyEvent) {
		events <- event
	})
	if err != nil {
		return err
	}
	fence := make(chan sidecar.RedisKeyEvent, 16)
	removeFence, err := target.Redis.AddKeyEventCallback(keys.pattern(), func(event sidecar.RedisKeyEvent) {
		fence <- event
	})
	if err != nil {
		return err
	}
	defer removeFence()

	remove()
	key := keys.key("n")
	if err := target.Redis.Set(ctx, key, []byte("1"), time.Minute); err != nil {
		return err
	}
	if err := target.awaitKey(ctx, fence, key); err != nil {
		return err
	}
	if 0 < len(events) {
		return errors.New("a removed callback heard an event")
	}
	return target.Redis.Delete(ctx, []string{key})
}

func caseKeyEventExpiry(ctx context.Context, target *Target, keys *keySpace) error {
	key := keys.key("gone")
	if err := target.Redis.Set(ctx, key, []byte("1"), 100*time.Millisecond); err != nil {
		return err
	}
	events := make(chan sidecar.RedisKeyEvent, 16)
	remove, err := target.Redis.AddKeyEventCallback(keys.pattern(), func(event sidecar.RedisKeyEvent) {
		events <- event
	})
	if err != nil {
		return err
	}
	defer remove()
	target.Pass(150 * time.Millisecond)
	// a read makes a real master notice the key has expired
	if _, found, err := target.Redis.Get(ctx, key); err != nil || found {
		return fmt.Errorf("after its ttl: %v, %v", found, err)
	}
	return target.awaitKey(ctx, events, key)
}
