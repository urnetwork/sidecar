// The conformance suite for §6.8's hint state (PROTO-M1-07): pushservice's writer and scripts on a store,
// run on FakeRedis with the Go twins here and on server's real Redis through its model adapter, so the
// twins stay honest (D-TEST-2). Every case uses client ids no other case shares, so one Redis serves the
// whole run and a shared database's other keys change no verdict.
//
// Time differs by store, as in redissuite: a fake moves its clock and a real store waits, so the cases
// that need a key to expire go through Target.Pass with Target.KeyTimeout, short on a real store, and
// only those cost real time. A keyspace event is waited for with a marker written after it in the same
// slot, never with a sleep.
//
// A case is a plain function returning its first failure, and RunPushStoreSuite loops over them
// (connect/CODESTYLE.md:216). A failure in one does not stop the next.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"math"
	mathrand "math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
)

// How long one case may take before it fails. Real time, only ever a failure's bound.
const pushSuiteCaseTimeout = 2 * time.Minute

// The store the suite runs on.
type PushStoreTarget struct {
	// The store, with pushservice.HintScript, HintAckScript and HintTailScript runnable on it.
	Redis pushservice.PublisherRedis
	// Moves time on by at least d: a fake clock's Advance, or a real wait on a real store.
	Pass func(d time.Duration)
	// The keys' ttl the cases' writers use: an hour on a fake clock, a few seconds on a real store, which
	// Pass then waits out.
	KeyTimeout time.Duration
	// Calls callback with the key of each keyspace event under {scp_*}, from production's classes only,
	// K, g, $, s and x, in order and one at a time, until stop.
	WatchKeys func(callback func(key string)) (stop func(), err error)
	// How long a case waits for an event, in real time: only ever a failure's bound.
	EventTimeout time.Duration
}

type pushSuiteEnv struct {
	ctx    context.Context
	target *PushStoreTarget
	writer *pushservice.HintWriter
}

type pushSuiteCase struct {
	name string
	run  func(env *pushSuiteEnv) error
}

// Runs every case on target, §18.7's wake token cases (push_token_suite.go) among them. t is a testing.TB
// so that server's test can run it inside its test environment's callback.
func RunPushStoreSuite(t testing.TB, target *PushStoreTarget) {
	t.Helper()
	for _, suiteCase := range slices.Concat(pushSuiteCases(), pushTokenSuiteCases()) {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), pushSuiteCaseTimeout)
			defer cancel()
			settings := pushservice.DefaultHintWriterSettings()
			settings.KeyTimeout = target.KeyTimeout
			writer, err := pushservice.NewHintWriter(target.Redis, settings, nil, nil)
			if err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
				return
			}
			if err := suiteCase.run(&pushSuiteEnv{ctx: ctx, target: target, writer: writer}); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
}

func pushSuiteCases() []pushSuiteCase {
	return []pushSuiteCase{
		{name: "a topic's version only rises, and each hint carries what ver holds", run: casePushVersionRises},
		{name: "concurrent writers never lower a version", run: casePushConcurrentWriters},
		{name: "versions at 2^53 and around it, near 1.8e18 and of 20 digits stay exact", run: casePushExactVersions},
		{name: "versions of different lengths compare by length first", run: casePushMixedLengths},
		{name: "the script refuses a version or topic that is not canonical and writes nothing", run: casePushNotCanonicalRefused},
		{name: "a raised clock goes past the stored value, and the hint carries the raised value", run: casePushClockRaised},
		{name: "seq is n's INCR, each entry's, rising by one", run: casePushSeqRises},
		{name: "the stream trims to about its length", run: casePushStreamTrims},
		{name: "the tail script reads the stream's last entry whole, nothing while it is absent", run: casePushTailReadsTheLastEntry},
		{name: "after the keys expire, ver and hint are gone and n restarts at 1", run: casePushExpiryRestartsSeq},
		{name: "each key's expiry starts once per generation, and only n's INCR is a trigger", run: casePushTriggerEvents},
		{name: "the script returns tok and live from the slot, nil while absent", run: casePushTokenAndLive},
		{name: "ack rises only while tok exists, and only upward", run: casePushAckRaise},
		{name: "every key of a script shares the client's tag", run: casePushKeysShareTag},
	}
}

// A new client id, which no other case uses.
func pushSuiteClientId() connect.Id {
	return connect.NewId()
}

// One hint, failing on an error.
func (self *pushSuiteEnv) hint(clientId connect.Id, topic string, version uint64) (*pushservice.PushHintResult, error) {
	return self.writer.HintClient(self.ctx, clientId, &sidecar.ClientHint{Topic: topic, Version: version, Kind: 0x1A01, Body: []byte{1, 2, 3}})
}

// What ver holds for topic, as its raw string, and whether it holds it.
func (self *pushSuiteEnv) storedVersion(clientId connect.Id, topic string) (string, bool, error) {
	fieldValues, err := self.target.Redis.HashGetAll(self.ctx, pushservice.HintVersionsKey(clientId))
	if err != nil {
		return "", false, err
	}
	value, ok := fieldValues[topic]
	return string(value), ok, nil
}

// Every entry of the client's hint stream, in order.
func (self *pushSuiteEnv) entries(clientId connect.Id) ([]*sidecar.RedisStreamEntry, error) {
	entries := []*sidecar.RedisStreamEntry{}
	after := ""
	for {
		page, err := self.target.Redis.StreamRange(self.ctx, pushservice.HintStreamKey(clientId), after, 1000)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return entries, nil
		}
		entries = append(entries, page...)
		after = page[len(page)-1].Id
	}
}

// Whether ver holds want for topic, exactly as its decimal.
func (self *pushSuiteEnv) expectStored(clientId connect.Id, topic string, want uint64) error {
	stored, found, err := self.storedVersion(clientId, topic)
	if err != nil {
		return err
	}
	if !found || stored != pushservice.FormatVersion(want) {
		return fmt.Errorf("ver holds %q (found %t) for %s, want %d", stored, found, topic, want)
	}
	return nil
}

func casePushVersionRises(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	writes := []struct {
		version uint64
		carried uint64
	}{
		{version: 5, carried: 5},
		{version: 3, carried: 5},
		{version: 5, carried: 5},
		{version: 7, carried: 7},
	}
	for _, write := range writes {
		result, err := env.hint(clientId, sidecar.PushTopicTeam, write.version)
		if err != nil {
			return err
		}
		if result.Version != write.carried {
			return fmt.Errorf("a hint of %d carries %d, want %d", write.version, result.Version, write.carried)
		}
	}
	if err := env.expectStored(clientId, sidecar.PushTopicTeam, 7); err != nil {
		return err
	}
	entries, err := env.entries(clientId)
	if err != nil {
		return err
	}
	if len(entries) != len(writes) {
		return fmt.Errorf("%d entries, want %d", len(entries), len(writes))
	}
	for index, entry := range entries {
		hint, err := pushservice.ParseHintEntry(entry)
		if err != nil {
			return err
		}
		if hint.Topic != sidecar.PushTopicTeam || hint.Version != writes[index].carried || hint.Kind != 0x1A01 || string(hint.Hint) != "\x01\x02\x03" {
			return fmt.Errorf("entry %d reads %v", index, hint)
		}
	}
	return nil
}

func casePushConcurrentWriters(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	const writerCount = 8
	const writeCount = 16
	topic := sidecar.PushTopicEvs(sidecar.NewId())
	var waitGroup sync.WaitGroup
	errs := make([]error, writerCount)
	highest := make([]uint64, writerCount)
	for writer := range writerCount {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			random := mathrand.New(mathrand.NewPCG(uint64(writer), 1))
			for range writeCount {
				// near evs's sequence, past what a double holds exactly
				version := 1_800_000_000_000_000_000 + random.Uint64N(1_000_000)
				highest[writer] = max(highest[writer], version)
				if _, err := env.hint(clientId, topic, version); err != nil {
					errs[writer] = err
					return
				}
			}
		}()
	}
	waitGroup.Wait()
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := env.expectStored(clientId, topic, slices.Max(highest)); err != nil {
		return err
	}
	// each entry carries what ver held when it was written, which never falls
	entries, err := env.entries(clientId)
	if err != nil {
		return err
	}
	previous := uint64(0)
	for _, entry := range entries {
		hint, err := pushservice.ParseHintEntry(entry)
		if err != nil {
			return err
		}
		if hint.Version < previous {
			return fmt.Errorf("an entry carries %d after one carrying %d", hint.Version, previous)
		}
		previous = hint.Version
	}
	return nil
}

func casePushExactVersions(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	// each pair is a value and the next above it, which a double rounds to one: the second must win
	pairs := [][2]uint64{
		{1<<53 - 1, 1 << 53},
		{1 << 53, 1<<53 + 1},
		{1_800_000_000_000_000_000, 1_800_000_000_000_000_001},
		{1_800_000_000_000_000_255, 1_800_000_000_000_000_256},
		{math.MaxUint64 - 1, math.MaxUint64},
		{10_000_000_000_000_000_000, 10_000_000_000_000_000_001},
	}
	for _, pair := range pairs {
		topic := sidecar.PushTopicEvs(sidecar.NewId())
		for _, version := range pair {
			result, err := env.hint(clientId, topic, version)
			if err != nil {
				return err
			}
			if result.Version != version {
				return fmt.Errorf("a hint of %d carries %d", version, result.Version)
			}
			if err := env.expectStored(clientId, topic, version); err != nil {
				return err
			}
		}
		// and the lower one after it changes nothing
		result, err := env.hint(clientId, topic, pair[0])
		if err != nil {
			return err
		}
		if result.Version != pair[1] {
			return fmt.Errorf("a lower hint of %d carries %d, want %d", pair[0], result.Version, pair[1])
		}
		if err := env.expectStored(clientId, topic, pair[1]); err != nil {
			return err
		}
	}
	return nil
}

func casePushMixedLengths(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	cases := []struct {
		first  uint64
		second uint64
		want   uint64
	}{
		{first: 999, second: 1000, want: 1000},
		{first: 1000, second: 999, want: 1000},
		{first: 9_999_999_999, second: 10_000_000_000, want: 10_000_000_000},
		{first: 10_000_000_000, second: 9_999_999_999, want: 10_000_000_000},
		{first: 9_999_999_999_999_999_999, second: 10_000_000_000_000_000_000, want: 10_000_000_000_000_000_000},
		{first: 10_000_000_000_000_000_000, second: 9_999_999_999_999_999_999, want: 10_000_000_000_000_000_000},
		// equal high parts, low parts compared: 10 low digits with leading zeros
		{first: 12_0000000001, second: 12_0000000010, want: 12_0000000010},
		{first: 12_0000000010, second: 11_9999999999, want: 12_0000000010},
	}
	for _, c := range cases {
		topic := sidecar.PushTopicEvs(sidecar.NewId())
		if _, err := env.hint(clientId, topic, c.first); err != nil {
			return err
		}
		if _, err := env.hint(clientId, topic, c.second); err != nil {
			return err
		}
		if err := env.expectStored(clientId, topic, c.want); err != nil {
			return fmt.Errorf("%d then %d: %w", c.first, c.second, err)
		}
	}
	return nil
}

// The script's keys and arguments for one hint, as the writer builds them, with version and topic as
// given rather than as a writer would ever pass them.
func pushSuiteRawHint(clientId connect.Id, topic string, version string, ttl time.Duration) ([]string, []string) {
	keys := []string{
		pushservice.HintVersionsKey(clientId),
		pushservice.HintStreamKey(clientId),
		pushservice.HintSeqKey(clientId),
		pushservice.HintTokenKey(clientId),
		pushservice.HintLiveKey(clientId),
	}
	args := []string{topic, version, "0", "", "0", fmt.Sprintf("%d", int64(ttl/time.Second)), "256"}
	return keys, args
}

func casePushNotCanonicalRefused(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	refused := []struct {
		topic   string
		version string
	}{
		{topic: sidecar.PushTopicSock, version: "007"},
		{topic: sidecar.PushTopicSock, version: "0"},
		{topic: sidecar.PushTopicSock, version: ""},
		{topic: sidecar.PushTopicSock, version: "12a"},
		{topic: sidecar.PushTopicSock, version: "-1"},
		{topic: sidecar.PushTopicSock, version: "1.5"},
		{topic: sidecar.PushTopicSock, version: " 12"},
		{topic: sidecar.PushTopicSock, version: "123456789012345678901"},
		{topic: "", version: "12"},
	}
	for _, c := range refused {
		keys, args := pushSuiteRawHint(clientId, c.topic, c.version, env.target.KeyTimeout)
		if _, err := env.target.Redis.RunScript(env.ctx, pushservice.HintScript, keys, args); err == nil {
			return fmt.Errorf("version %q on topic %q was taken", c.version, c.topic)
		}
	}
	// nothing was written by any of them
	fieldValues, err := env.target.Redis.HashGetAll(env.ctx, pushservice.HintVersionsKey(clientId))
	if err != nil {
		return err
	}
	if len(fieldValues) != 0 {
		return fmt.Errorf("ver holds %v", fieldValues)
	}
	entries, err := env.entries(clientId)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%d entries", len(entries))
	}
	// and the writer refuses 0, a topic outside the registry and a hint past 256 B before any script
	for _, hint := range []*sidecar.ClientHint{
		{Topic: sidecar.PushTopicSock, Version: 0},
		{Topic: "sockets", Version: 1},
		{Topic: "evs:not-an-id", Version: 1},
		{Topic: sidecar.PushTopicSock, Version: 1, Body: make([]byte, pushservice.DefaultPushFormatSettings().MaxHintByteCount+1)},
	} {
		if _, err := env.writer.HintClient(env.ctx, clientId, hint); !errors.Is(err, pushservice.ErrHintInvalid) {
			return fmt.Errorf("the writer took %q at %d: %v", hint.Topic, hint.Version, err)
		}
	}
	return nil
}

func casePushClockRaised(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	for _, topic := range []string{sidecar.PushTopicGkm, sidecar.PushTopicCore, sidecar.PushTopicMail, sidecar.PushTopicTls} {
		writes := []struct {
			version uint64
			carried uint64
		}{
			// µs clocks are past 10 digits, so the comparison splits them
			{version: 1_731_000_000_000_000, carried: 1_731_000_000_000_000},
			{version: 1_730_000_000_000_000, carried: 1_731_000_000_000_001},
			{version: 1_731_000_000_000_001, carried: 1_731_000_000_000_002},
			{version: 1_731_000_000_000_010, carried: 1_731_000_000_000_010},
		}
		for _, write := range writes {
			result, err := env.hint(clientId, topic, write.version)
			if err != nil {
				return err
			}
			if result.Version != write.carried {
				return fmt.Errorf("%s: a hint of %d carries %d, want %d", topic, write.version, result.Version, write.carried)
			}
		}
		if err := env.expectStored(clientId, topic, 1_731_000_000_000_010); err != nil {
			return err
		}
	}
	// a topic that is no raised clock keeps the stored value
	if _, err := env.hint(clientId, sidecar.PushTopicSock, 1000); err != nil {
		return err
	}
	result, err := env.hint(clientId, sidecar.PushTopicSock, 500)
	if err != nil {
		return err
	}
	if result.Version != 1000 {
		return fmt.Errorf("sock: a lower hint carries %d", result.Version)
	}
	return env.expectStored(clientId, sidecar.PushTopicSock, 1000)
}

func casePushSeqRises(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	for want := uint64(1); want <= 5; want += 1 {
		result, err := env.hint(clientId, sidecar.PushTopicDns, want)
		if err != nil {
			return err
		}
		if result.Seq != want {
			return fmt.Errorf("hint %d has seq %d", want, result.Seq)
		}
	}
	entries, err := env.entries(clientId)
	if err != nil {
		return err
	}
	for index, entry := range entries {
		hint, err := pushservice.ParseHintEntry(entry)
		if err != nil {
			return err
		}
		if hint.Seq != uint64(index+1) {
			return fmt.Errorf("entry %d has seq %d", index, hint.Seq)
		}
	}
	return nil
}

// The tail script reads nothing while the stream is absent, then the entry XRANGE ends on, whole, after
// writes and after a trim; and it writes nothing.
func casePushTailReadsTheLastEntry(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	if _, found, err := pushservice.ReadHintTail(env.ctx, env.target.Redis, clientId); err != nil || found {
		return fmt.Errorf("an absent stream's tail: found %t, %v", found, err)
	}
	for _, hintCount := range []uint64{1, 3, 400} {
		for version := uint64(1); version <= hintCount; version += 1 {
			if _, err := env.hint(clientId, sidecar.PushTopicDns, version); err != nil {
				return err
			}
		}
		entries, err := env.entries(clientId)
		if err != nil {
			return err
		}
		tail, found, err := pushservice.ReadHintTail(env.ctx, env.target.Redis, clientId)
		if err != nil || !found {
			return fmt.Errorf("the tail after %d hints: found %t, %v", hintCount, found, err)
		}
		last := entries[len(entries)-1]
		if tail.Id != last.Id || len(tail.FieldValues) != len(last.FieldValues) {
			return fmt.Errorf("the tail is %s with %d fields, XRANGE ends on %s with %d", tail.Id, len(tail.FieldValues), last.Id, len(last.FieldValues))
		}
		for field, value := range last.FieldValues {
			if string(tail.FieldValues[field]) != string(value) {
				return fmt.Errorf("the tail's %s is %q, XRANGE's %q", field, tail.FieldValues[field], value)
			}
		}
		again, err := env.entries(clientId)
		if err != nil {
			return err
		}
		if len(again) != len(entries) {
			return fmt.Errorf("reading the tail changed the stream: %d entries, then %d", len(entries), len(again))
		}
	}
	return nil
}

func casePushStreamTrims(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	const hintCount = 700
	for version := uint64(1); version <= hintCount; version += 1 {
		if _, err := env.hint(clientId, sidecar.PushTopicDns, version); err != nil {
			return err
		}
	}
	entries, err := env.entries(clientId)
	if err != nil {
		return err
	}
	// MAXLEN ~ drops whole nodes, of 100 entries by Redis's default: at least 256 stay, and fewer than 356
	if len(entries) < 256 || 256+100 <= len(entries) {
		return fmt.Errorf("%d entries after %d hints", len(entries), hintCount)
	}
	last, err := pushservice.ParseHintEntry(entries[len(entries)-1])
	if err != nil {
		return err
	}
	if last.Seq != hintCount || last.Version != hintCount {
		return fmt.Errorf("the last entry is %v", last)
	}
	return nil
}

func casePushExpiryRestartsSeq(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	for version := uint64(1); version <= 2; version += 1 {
		if _, err := env.hint(clientId, sidecar.PushTopicDns, version); err != nil {
			return err
		}
	}
	env.target.Pass(env.target.KeyTimeout + time.Second)
	fieldValues, err := env.target.Redis.HashGetAll(env.ctx, pushservice.HintVersionsKey(clientId))
	if err != nil {
		return err
	}
	if len(fieldValues) != 0 {
		return fmt.Errorf("ver outlived its ttl: %v", fieldValues)
	}
	entries, err := env.entries(clientId)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%d entries outlived the ttl", len(entries))
	}
	result, err := env.hint(clientId, sidecar.PushTopicDns, 3)
	if err != nil {
		return err
	}
	if result.Seq != 1 {
		return fmt.Errorf("n did not restart: seq %d", result.Seq)
	}
	return nil
}

// Counts the keyspace events of one client's keys until a marker of its own arrives, which a master
// sends after every event before it in the same slot.
type pushSuiteEventCounter struct {
	clientId connect.Id
	marker   string

	stateLock   sync.Mutex
	keyCounts   map[string]int
	markerCount int
	markerSeen  chan struct{}
}

func (self *pushSuiteEventCounter) see(key string) {
	if !strings.HasPrefix(key, pushservice.HintTag(self.clientId)) {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if key == self.marker {
		self.markerCount += 1
		if self.markerSeen != nil {
			close(self.markerSeen)
			self.markerSeen = nil
		}
		return
	}
	self.keyCounts[key] += 1
}

// Writes the marker and waits for its event, so every event of the slot before it has been counted.
func (self *pushSuiteEventCounter) settle(env *pushSuiteEnv) (map[string]int, error) {
	markerSeen := make(chan struct{})
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.markerSeen = markerSeen
	}()
	if err := env.target.Redis.Set(env.ctx, self.marker, []byte("1"), 0); err != nil {
		return nil, err
	}
	select {
	case <-markerSeen:
	case <-time.After(env.target.EventTimeout):
		return nil, errors.New("the marker's event never came")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	keyCounts := map[string]int{}
	for key, count := range self.keyCounts {
		keyCounts[key] = count
	}
	return keyCounts, nil
}

func casePushTriggerEvents(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	counter := &pushSuiteEventCounter{
		clientId: clientId,
		// a key of the slot in api-6's family, which nothing else here writes
		marker:    pushservice.HintPollKey(clientId),
		keyCounts: map[string]int{},
	}
	stop, err := env.target.WatchKeys(counter.see)
	if err != nil {
		return err
	}
	defer stop()

	versionsKey := pushservice.HintVersionsKey(clientId)
	streamKey := pushservice.HintStreamKey(clientId)
	seqKey := pushservice.HintSeqKey(clientId)
	expect := func(when string, want map[string]int) error {
		keyCounts, err := counter.settle(env)
		if err != nil {
			return err
		}
		for _, key := range []string{versionsKey, streamKey, seqKey} {
			if keyCounts[key] != want[key] {
				return fmt.Errorf("%s: %d events on %s, want %d (all: %v)", when, keyCounts[key], key, want[key], keyCounts)
			}
		}
		for key := range keyCounts {
			if want[key] == 0 {
				return fmt.Errorf("%s: an event on %s", when, key)
			}
		}
		return nil
	}

	// the first hint: HSET and XADD emit nothing; n's INCR and each key's first EXPIRE do
	if _, err := env.hint(clientId, sidecar.PushTopicGkm, 100); err != nil {
		return err
	}
	if err := expect("after the first hint", map[string]int{versionsKey: 1, streamKey: 1, seqKey: 2}); err != nil {
		return err
	}
	// later hints: the INCR alone, whether ver's field rose, was raised by HINCRBY or stayed
	if _, err := env.hint(clientId, sidecar.PushTopicGkm, 200); err != nil {
		return err
	}
	if _, err := env.hint(clientId, sidecar.PushTopicGkm, 50); err != nil {
		return err
	}
	if _, err := env.hint(clientId, sidecar.PushTopicTeam, 1); err != nil {
		return err
	}
	return expect("after three more hints", map[string]int{versionsKey: 1, streamKey: 1, seqKey: 5})
}

func casePushTokenAndLive(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	result, err := env.hint(clientId, sidecar.PushTopicCore, 1)
	if err != nil {
		return err
	}
	if result.Token != nil || result.Live {
		return fmt.Errorf("absent tok and live read as %q and %t", result.Token, result.Live)
	}
	if err := env.target.Redis.Set(env.ctx, pushservice.HintTokenKey(clientId), []byte("synthetic-token"), 0); err != nil {
		return err
	}
	if err := env.target.Redis.Set(env.ctx, pushservice.HintLiveKey(clientId), []byte("1"), 90*time.Second); err != nil {
		return err
	}
	result, err = env.hint(clientId, sidecar.PushTopicCore, 2)
	if err != nil {
		return err
	}
	if string(result.Token) != "synthetic-token" || !result.Live {
		return fmt.Errorf("tok and live read as %q and %t", result.Token, result.Live)
	}
	return nil
}

func casePushAckRaise(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	ackKey := pushservice.HintAckKey(clientId)
	raise := func(streamId string, want bool) error {
		raised, err := pushservice.RaiseHintAck(env.ctx, env.target.Redis, clientId, streamId, time.Hour)
		if err != nil {
			return err
		}
		if raised != want {
			return fmt.Errorf("ack to %s raised %t, want %t", streamId, raised, want)
		}
		return nil
	}
	expectAck := func(want string, wantFound bool) error {
		value, found, err := env.target.Redis.Get(env.ctx, ackKey)
		if err != nil {
			return err
		}
		if found != wantFound || string(value) != want {
			return fmt.Errorf("ack holds %q (found %t), want %q", value, found, want)
		}
		return nil
	}
	// no tok: nothing written
	if err := raise("1700000000000-5", false); err != nil {
		return err
	}
	if err := expectAck("", false); err != nil {
		return err
	}
	if err := env.target.Redis.Set(env.ctx, pushservice.HintTokenKey(clientId), []byte("synthetic-token"), 0); err != nil {
		return err
	}
	steps := []struct {
		streamId string
		raised   bool
		holds    string
	}{
		{streamId: "1700000000000-5", raised: true, holds: "1700000000000-5"},
		{streamId: "1700000000000-4", raised: false, holds: "1700000000000-5"},
		{streamId: "1700000000000-5", raised: false, holds: "1700000000000-5"},
		{streamId: "1700000000000-10", raised: true, holds: "1700000000000-10"},
		{streamId: "1699999999999-99", raised: false, holds: "1700000000000-10"},
		{streamId: "1700000000001-0", raised: true, holds: "1700000000001-0"},
		{streamId: "17000000000010-0", raised: true, holds: "17000000000010-0"},
	}
	for _, step := range steps {
		if err := raise(step.streamId, step.raised); err != nil {
			return err
		}
		if err := expectAck(step.holds, true); err != nil {
			return err
		}
	}
	for _, malformed := range []string{"", "5", "05-1", "5-01", "a-1", "5-1-2"} {
		if _, err := pushservice.RaiseHintAck(env.ctx, env.target.Redis, clientId, malformed, time.Hour); err == nil {
			return fmt.Errorf("an ack to %q was taken", malformed)
		}
	}
	return expectAck("17000000000010-0", true)
}

func casePushKeysShareTag(env *pushSuiteEnv) error {
	clientId := pushSuiteClientId()
	hintKeys, _ := pushSuiteRawHint(clientId, sidecar.PushTopicCore, "1", env.target.KeyTimeout)
	ackKeys := []string{pushservice.HintAckKey(clientId), pushservice.HintTokenKey(clientId)}
	tailKeys := []string{pushservice.HintStreamKey(clientId)}
	for _, keys := range [][]string{hintKeys, ackKeys, tailKeys} {
		if !sidecar.RedisKeysShareTag(keys) {
			return fmt.Errorf("%v do not share a tag", keys)
		}
		for _, key := range keys {
			if !strings.HasPrefix(key, pushservice.HintTag(clientId)) {
				return fmt.Errorf("%s is outside the client's slot", key)
			}
		}
	}
	if seqClientId, ok := pushservice.ParseHintSeqKey(pushservice.HintSeqKey(clientId)); !ok || seqClientId != clientId {
		return errors.New("n's key does not parse back to its client")
	}
	return nil
}
