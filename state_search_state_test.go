//go:build !ios_extension

package sidecar

// CORE-M10-03: §5.9's search state, search.state: written through and read back, kept through the cache's eviction
// and drops, holding no query, served records one row per requester, repo and UTC day (owner decision 294, QD-961)
// pruned by their day's timeout and their bound, the old one-search form read and folded, the file under its byte
// bound at the requester rate's ceiling, nothing changed while locked and a failed file never written over.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// A clock the test moves, whose timers fire, in order, as it passes them. Starts at the real time, so a context deadline
// set from it lies in the real future too.
type searchTestClock struct {
	stateLock sync.Mutex
	current   time.Time
	timers    []*searchTestTimer
	// closed and replaced each time a timer is armed, for a test waiting on one
	armed chan struct{}
}

// A timer armed on a searchTestClock.
type searchTestTimer struct {
	at   time.Time
	fire func()
	done bool
}

func newSearchTestClock() *searchTestClock {
	return &searchTestClock{current: time.Now(), armed: make(chan struct{})}
}

func (self *searchTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.current
}

func (self *searchTestClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	self.AfterFunc(timeout, func() { fired <- self.Now() })
	return fired
}

func (self *searchTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	self.stateLock.Lock()
	timer := &searchTestTimer{at: self.current.Add(timeout), fire: function}
	due := timeout <= 0
	if !due {
		self.timers = append(self.timers, timer)
		close(self.armed)
		self.armed = make(chan struct{})
	} else {
		timer.done = true
	}
	self.stateLock.Unlock()
	if due {
		go function()
	}
	return func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if timer.done {
			return false
		}
		timer.done = true
		return true
	}
}

// Moves the clock by timeout, firing each timer it passes, earliest first, outside the lock.
func (self *searchTestClock) advance(timeout time.Duration) {
	self.stateLock.Lock()
	self.current = self.current.Add(timeout)
	due := []*searchTestTimer{}
	kept := self.timers[:0]
	for _, timer := range self.timers {
		switch {
		case timer.done:
		case !timer.at.After(self.current):
			timer.done = true
			due = append(due, timer)
		default:
			kept = append(kept, timer)
		}
	}
	self.timers = kept
	self.stateLock.Unlock()
	slices.SortStableFunc(due, func(a *searchTestTimer, b *searchTestTimer) int { return a.at.Compare(b.at) })
	for _, timer := range due {
		timer.fire()
	}
}

// The timers armed and not yet fired or stopped.
func (self *searchTestClock) pending() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pendingWithLock()
}

func (self *searchTestClock) pendingWithLock() int {
	count := 0
	for _, timer := range self.timers {
		if !timer.done {
			count += 1
		}
	}
	return count
}

// Waits until count timers are pending, woken by each one armed, never by time passing.
func (self *searchTestClock) awaitPending(t *testing.T, count int) {
	t.Helper()
	for {
		armed, pending := func() (chan struct{}, int) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.armed, self.pendingWithLock()
		}()
		if count <= pending {
			return
		}
		select {
		case <-armed:
		case <-t.Context().Done():
			t.Fatalf("%d timers never armed", count)
		}
	}
}

// One network of an open instance in memory, with its search state on a clock the test moves.
type searchStateTestWorld struct {
	backend   SidecarStoreBackend
	instance  *SidecarInstance
	networkId Id
	settings  *SidecarSearchSettings
	clock     *searchTestClock
	state     *SidecarSearchState
	failed    int
}

func newSearchStateTestWorld(t *testing.T) *searchStateTestWorld {
	t.Helper()
	backend := NewSidecarMemoryBackend()
	instance := newInstanceOn(t, backend, newFakeKeyStore())
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	networkId := NewId()
	if _, err := instance.createKeychain(networkId); err != nil {
		t.Fatal(err)
	}
	world := &searchStateTestWorld{
		backend:   backend,
		instance:  instance,
		networkId: networkId,
		settings:  DefaultSidecarSettings().Search,
		clock:     newSearchTestClock(),
	}
	world.state = world.newState(t)
	return world
}

// A second state over the same network's store, as after a restart.
func (self *searchStateTestWorld) newState(t *testing.T) *SidecarSearchState {
	t.Helper()
	state, err := newSidecarSearchState(self.instance.Store(&self.networkId), self.settings, self.clock, NewNoopLogger(), func() {
		self.failed += 1
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// Moves the clock to the next UTC midnight, the start of a served row's day, and answers it.
func (self *searchStateTestWorld) toUtcMidnight() time.Time {
	now := self.clock.Now()
	midnight := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	self.clock.advance(midnight.Sub(now))
	return midnight
}

// Writes plaintext as search.state, as another build or a fault would have left it.
func (self *searchStateTestWorld) writePlaintext(t *testing.T, plaintext []byte) {
	t.Helper()
	store, err := self.instance.Store(&self.networkId).Directory("", SidecarSearchFileClass)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.Create(sidecarSearchStateName)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
}

// count new ids, in the byte order that breaks a day's ties among served rows.
func sortedTestIds(count int) []Id {
	ids := []Id{}
	for range count {
		ids = append(ids, NewId())
	}
	slices.SortFunc(ids, func(a Id, b Id) int { return bytes.Compare(a[:], b[:]) })
	return ids
}

// search.state's plaintext, nil when there is none.
func (self *searchStateTestWorld) plaintext(t *testing.T) []byte {
	t.Helper()
	store, err := self.instance.Store(&self.networkId).Directory("", SidecarSearchFileClass)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.Open(sidecarSearchStateName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

// Every change is on the medium when its call returns, and a fresh state over the same store reads it back.
func TestSearchStateRoundTrip(t *testing.T) {
	world := newSearchStateTestWorld(t)
	member, repo, indexer, requester := NewId(), NewId(), NewId(), NewId()
	if mode, err := world.state.Mode(); err != nil || mode != SearchRemoteOn {
		t.Fatalf("default mode %q %v", mode, err)
	}
	if err := world.state.SetMode(SearchRemoteOff); err != nil {
		t.Fatal(err)
	}
	if err := world.state.SetAnswer(&member, true); err != nil {
		t.Fatal(err)
	}
	if err := world.state.SetPolicy(&repo, SearchPolicyNever); err != nil {
		t.Fatal(err)
	}
	if err := world.state.NoteServed(indexer, repo); err != nil {
		t.Fatal(err)
	}
	if err := world.state.SetDistrustUntil(indexer, world.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := world.state.RecordServed(requester, repo); err != nil {
		t.Fatal(err)
	}

	reread := world.newState(t)
	if mode, err := reread.Mode(); err != nil || mode != SearchRemoteOff {
		t.Errorf("mode %q %v", mode, err)
	}
	if allow, answered, err := reread.Answer(member); err != nil || !answered || !allow {
		t.Errorf("answer %v %v %v", allow, answered, err)
	}
	if policy, err := reread.Policy(repo); err != nil || policy != SearchPolicyNever {
		t.Errorf("policy %q %v", policy, err)
	}
	if policy, err := reread.Policy(NewId()); err != nil || policy != "" {
		t.Errorf("another repo's policy %q %v", policy, err)
	}
	if served, err := reread.Served(indexer); err != nil || len(served) != 1 || served[repo].IsZero() {
		t.Errorf("served %v %v", served, err)
	}
	if until, err := reread.DistrustUntil(indexer); err != nil || until.IsZero() {
		t.Errorf("distrust %v %v", until, err)
	}
	if records, err := reread.ServedRecords(); err != nil || len(records) != 1 || records[0].RequesterId != requester || records[0].RepoId != repo || records[0].Count != 1 {
		t.Errorf("records %v %v", records, err)
	}
}

// A refused notice sets the mode to own in the same write; a nil member clears every answer and leaves the mode.
func TestSearchStateRefusalSetsOwn(t *testing.T) {
	world := newSearchStateTestWorld(t)
	allowed, refused := NewId(), NewId()
	if err := world.state.SetAnswer(&allowed, true); err != nil {
		t.Fatal(err)
	}
	if err := world.state.SetAnswer(&refused, false); err != nil {
		t.Fatal(err)
	}
	if mode, _ := world.state.Mode(); mode != SearchRemoteOwn {
		t.Errorf("mode %q after a refusal", mode)
	}
	if allow, answered, _ := world.state.Answer(refused); !answered || allow {
		t.Errorf("refusal read %v %v", allow, answered)
	}
	if err := world.state.SetAnswer(nil, true); err != nil {
		t.Fatal(err)
	}
	for _, member := range []Id{allowed, refused} {
		if _, answered, _ := world.state.Answer(member); answered {
			t.Errorf("an answer outlived the reset")
		}
	}
	if mode, _ := world.state.Mode(); mode != SearchRemoteOwn {
		t.Errorf("the reset moved the mode to %q", mode)
	}
}

// An every-repo override clears each repo's own; "" restores the host's default.
func TestSearchStatePolicyOverrides(t *testing.T) {
	world := newSearchStateTestWorld(t)
	repoA, repoB := NewId(), NewId()
	if err := world.state.SetPolicy(&repoA, SearchPolicyBackground); err != nil {
		t.Fatal(err)
	}
	if err := world.state.SetPolicy(nil, SearchPolicyOnDemand); err != nil {
		t.Fatal(err)
	}
	for _, repo := range []Id{repoA, repoB} {
		if policy, _ := world.state.Policy(repo); policy != SearchPolicyOnDemand {
			t.Errorf("policy %q under an every-repo override", policy)
		}
	}
	if err := world.state.SetPolicy(&repoB, ""); err != nil {
		t.Fatal(err)
	}
	if err := world.state.SetPolicy(nil, ""); err != nil {
		t.Fatal(err)
	}
	if policy, _ := world.state.Policy(repoA); policy != "" {
		t.Errorf("policy %q after the defaults came back", policy)
	}
	for _, bad := range []string{"always", "Background"} {
		if err := world.state.SetPolicy(&repoA, bad); !errors.Is(err, ErrSearchStateArgs) {
			t.Errorf("policy %q: %v", bad, err)
		}
	}
	if err := world.state.SetMode("hedge"); !errors.Is(err, ErrSearchStateArgs) {
		t.Errorf("mode hedge: %v", err)
	}
}

// §5.9's state row: `ur search sync --evict`, a drop and the bound's eviction all keep search.state, which sits beside
// the cache's directory and not in it.
func TestStateSurvivesEvict(t *testing.T) {
	world := newSearchStateTestWorld(t)
	cacheSettings := *world.settings
	cacheSettings.CacheByteCount = 1
	cache, err := NewSearchCache(context.Background(), world.instance.Store(&world.networkId), &cacheSettings, world.clock, NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cache.Close)
	member, repo, indexer, requester := NewId(), NewId(), NewId(), NewId()
	for _, change := range []func() error{
		func() error { return world.state.SetMode(SearchRemoteOwn) },
		func() error { return world.state.SetAnswer(&member, true) },
		func() error { return world.state.SetPolicy(&repo, SearchPolicyWifiCharging) },
		func() error { return world.state.NoteServed(indexer, repo) },
		func() error { return world.state.RecordServed(requester, repo) },
	} {
		if err := change(); err != nil {
			t.Fatal(err)
		}
	}
	before := world.plaintext(t)

	key := SearchCacheKey{RepoId: repo, RefId: NewId(), Path: ".ur-index/i1/a/0", Version: 1}
	kept := newTestSearchRecord(t, key, SearchCachePartition{All: true}, testSearchPlaintext("all", 6000))
	// past a bound of one byte, the put's own eviction takes the file at once
	if err := cache.PutRecord(t.Context(), kept.record); err != nil {
		t.Fatal(err)
	}
	if held, err := cache.Ref(key.RepoId, key.RefId); err != nil || (held != nil && 0 < len(held.Files)) {
		t.Fatalf("eviction kept %v %v", held, err)
	}
	if err := cache.DropRepo(repo); err != nil {
		t.Fatal(err)
	}
	if err := cache.DropAll(); err != nil {
		t.Fatal(err)
	}
	if after := world.plaintext(t); !bytes.Equal(before, after) {
		t.Fatalf("search.state changed under the cache's drops")
	}
	reread := world.newState(t)
	if mode, _ := reread.Mode(); mode != SearchRemoteOwn {
		t.Errorf("mode %q", mode)
	}
	if records, _ := reread.ServedRecords(); len(records) != 1 {
		t.Errorf("records %v", records)
	}
}

// The served record is a row {requester, repo, day, count, first time, last time} (owner decision 294, QD-961): a
// search under a canary query leaves no trace of it in search.state, whose rows carry no other key.
func TestServedRecordNamesNoQuery(t *testing.T) {
	world := newSearchStateTestWorld(t)
	canary := "q-canary-served-4c1e-okapi"
	requester, repo := NewId(), NewId()
	// the served record is written at page 0 of a search for canary: no call here can take it
	_ = canary
	if err := world.state.RecordServed(requester, repo); err != nil {
		t.Fatal(err)
	}
	plaintext := world.plaintext(t)
	if bytes.Contains(plaintext, []byte(canary)) {
		t.Fatal("the query reached search.state")
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(plaintext, &decoded); err != nil {
		t.Fatal(err)
	}
	records, ok := decoded["records"].([]any)
	if !ok || len(records) != 1 {
		t.Fatalf("records %v", decoded["records"])
	}
	record := records[0].(map[string]any)
	keys := []string{}
	for key := range record {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"count", "day", "first_ms", "last_ms", "repo", "requester"}) {
		t.Errorf("a served record holds %v", keys)
	}
	if err := world.state.RecordServed(Id{}, repo); !errors.Is(err, ErrSearchStateArgs) {
		t.Errorf("a record of no requester: %v", err)
	}
}

// The served memory goes at Search.RemoteServedTimeout and a distrust deadline once passed; a served row once its day
// ended Search.ServedRecordTimeout ago, not its search's time; and a write prunes what reads only hid.
func TestServedRecordExpires(t *testing.T) {
	world := newSearchStateTestWorld(t)
	requester, repo, indexer := NewId(), NewId(), NewId()
	midnight := world.toUtcMidnight()
	world.clock.advance(time.Hour)
	if err := world.state.RecordServed(requester, repo); err != nil {
		t.Fatal(err)
	}
	if err := world.state.NoteServed(indexer, repo); err != nil {
		t.Fatal(err)
	}
	if err := world.state.SetDistrustUntil(indexer, world.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	world.clock.advance(world.settings.RemoteServedTimeout)
	if served, _ := world.state.Served(indexer); len(served) != 1 {
		t.Errorf("served memory gone at its timeout: %v", served)
	}
	if until, _ := world.state.DistrustUntil(indexer); !until.IsZero() {
		t.Errorf("distrust %v past its deadline", until)
	}
	world.clock.advance(time.Millisecond)
	if served, _ := world.state.Served(indexer); len(served) != 0 {
		t.Errorf("served memory past its timeout: %v", served)
	}
	// past ServedRecordTimeout from its search, the row's day ended less long ago: it stays
	world.clock.advance(world.settings.ServedRecordTimeout - world.settings.RemoteServedTimeout)
	if records, _ := world.state.ServedRecords(); len(records) != 1 {
		t.Errorf("a row gone before its day's timeout: %v", records)
	}
	world.clock.advance(midnight.Add(24 * time.Hour).Add(world.settings.ServedRecordTimeout + time.Millisecond).Sub(world.clock.Now()))
	if records, _ := world.state.ServedRecords(); len(records) != 0 {
		t.Errorf("a row past its day's timeout: %v", records)
	}
	// a write prunes what reads only hid
	if err := world.state.RecordServed(requester, repo); err != nil {
		t.Fatal(err)
	}
	decoded := &searchStateWire{}
	if err := json.Unmarshal(world.plaintext(t), decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Records) != 1 || len(decoded.Served) != 0 || len(decoded.Distrust) != 0 {
		t.Errorf("after a write: %d records, %d served, %d distrust", len(decoded.Records), len(decoded.Served), len(decoded.Distrust))
	}
}

// A thousand searches by one reader in one repo in one day leave one row, of count 1,000, from the first search's time
// to the last's (owner decision 294, QD-961), and a fresh state reads it back.
func TestServedRowCountsADaysSearches(t *testing.T) {
	world := newSearchStateTestWorld(t)
	requester, repo := NewId(), NewId()
	midnight := world.toUtcMidnight()
	world.clock.advance(time.Hour)
	first := world.clock.Now()
	for i := range 1000 {
		if 0 < i {
			world.clock.advance(2 * time.Second)
		}
		if err := world.state.RecordServed(requester, repo); err != nil {
			t.Fatal(err)
		}
	}
	last := world.clock.Now()
	for _, state := range []*SidecarSearchState{world.state, world.newState(t)} {
		records, err := state.ServedRecords()
		if err != nil || len(records) != 1 {
			t.Fatalf("records %v %v", records, err)
		}
		record := records[0]
		if record.RequesterId != requester || record.RepoId != repo || !record.Day.Equal(midnight) || record.Count != 1000 {
			t.Errorf("row %v", record)
		}
		if record.First.UnixMilli() != first.UnixMilli() || record.Last.UnixMilli() != last.UnixMilli() {
			t.Errorf("row from %v to %v, searched from %v to %v", record.First, record.Last, first, last)
		}
	}
	decoded := &searchStateWire{}
	if err := json.Unmarshal(world.plaintext(t), decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Records) != 1 || decoded.Records[0].Count != 1000 {
		t.Errorf("the file holds %v", decoded.Records)
	}
}

// Two readers in two repos over three days leave twelve rows, one per requester, repo and day, each counting its own
// searches, answered the oldest day first and a day's by requester then repo whatever the order they were written in.
func TestServedRowsByRequesterRepoAndDay(t *testing.T) {
	world := newSearchStateTestWorld(t)
	requesters, repos := sortedTestIds(2), sortedTestIds(2)
	// each row's own count, by the indexes of its day, requester and repo
	countOf := func(dayIndex int, requesterIndex int, repoIndex int) int64 {
		return int64(1 + dayIndex + 2*requesterIndex + repoIndex)
	}
	midnights := []time.Time{}
	for dayIndex := range 3 {
		midnights = append(midnights, world.toUtcMidnight())
		world.clock.advance(time.Hour)
		for requesterIndex := len(requesters) - 1; 0 <= requesterIndex; requesterIndex -= 1 {
			for repoIndex := len(repos) - 1; 0 <= repoIndex; repoIndex -= 1 {
				for range countOf(dayIndex, requesterIndex, repoIndex) {
					world.clock.advance(time.Minute)
					if err := world.state.RecordServed(requesters[requesterIndex], repos[repoIndex]); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
	records, err := world.state.ServedRecords()
	if err != nil || len(records) != 12 {
		t.Fatalf("%d rows %v", len(records), err)
	}
	index := 0
	for dayIndex := range 3 {
		for requesterIndex := range requesters {
			for repoIndex := range repos {
				record := records[index]
				if record.RequesterId != requesters[requesterIndex] || record.RepoId != repos[repoIndex] || !record.Day.Equal(midnights[dayIndex]) ||
					record.Count != countOf(dayIndex, requesterIndex, repoIndex) {
					t.Errorf("row %d %v, wanted day %d's of requester %d in repo %d", index, record, dayIndex, requesterIndex, repoIndex)
				}
				index += 1
			}
		}
	}
}

// A search just after UTC midnight starts a new row: the day before keeps its own, and only the new day's rises.
func TestServedRowStartsAtUtcMidnight(t *testing.T) {
	world := newSearchStateTestWorld(t)
	requester, repo := NewId(), NewId()
	midnight := world.toUtcMidnight()
	world.clock.advance(24*time.Hour - time.Millisecond)
	lastOfDay := world.clock.Now()
	if err := world.state.RecordServed(requester, repo); err != nil {
		t.Fatal(err)
	}
	world.clock.advance(time.Millisecond)
	nextMidnight := world.clock.Now()
	if err := world.state.RecordServed(requester, repo); err != nil {
		t.Fatal(err)
	}
	world.clock.advance(time.Minute)
	if err := world.state.RecordServed(requester, repo); err != nil {
		t.Fatal(err)
	}
	records, err := world.state.ServedRecords()
	if err != nil || len(records) != 2 {
		t.Fatalf("records %v %v", records, err)
	}
	before, after := records[0], records[1]
	if !before.Day.Equal(midnight) || before.Count != 1 || before.First.UnixMilli() != lastOfDay.UnixMilli() || before.Last.UnixMilli() != lastOfDay.UnixMilli() {
		t.Errorf("the day before midnight %v", before)
	}
	if !after.Day.Equal(midnight.Add(24*time.Hour)) || after.Count != 2 || after.First.UnixMilli() != nextMidnight.UnixMilli() || after.Last.UnixMilli() != nextMidnight.Add(time.Minute).UnixMilli() {
		t.Errorf("the day after midnight %v", after)
	}
}

// A row is kept until its day ended Search.ServedRecordTimeout ago: read up to that instant, a write then keeping it,
// and hidden after it, the next write dropping it from the file.
func TestServedRowDropsPastItsTimeout(t *testing.T) {
	world := newSearchStateTestWorld(t)
	requester, other, repo := NewId(), NewId(), NewId()
	midnight := world.toUtcMidnight()
	world.clock.advance(23 * time.Hour)
	if err := world.state.RecordServed(requester, repo); err != nil {
		t.Fatal(err)
	}
	world.clock.advance(midnight.Add(24 * time.Hour).Add(world.settings.ServedRecordTimeout).Sub(world.clock.Now()))
	if err := world.state.RecordServed(other, repo); err != nil {
		t.Fatal(err)
	}
	if records, err := world.state.ServedRecords(); err != nil || len(records) != 2 || records[0].RequesterId != requester {
		t.Fatalf("at its day's timeout %v %v", records, err)
	}
	world.clock.advance(time.Millisecond)
	if records, err := world.state.ServedRecords(); err != nil || len(records) != 1 || records[0].RequesterId != other {
		t.Errorf("past its day's timeout %v %v", records, err)
	}
	fileRows := func() []searchStateRecordWire {
		decoded := &searchStateWire{}
		if err := json.Unmarshal(world.plaintext(t), decoded); err != nil {
			t.Fatal(err)
		}
		return decoded.Records
	}
	if rows := fileRows(); len(rows) != 2 {
		t.Errorf("a read dropped a row from the file: %v", rows)
	}
	if err := world.state.RecordServed(other, repo); err != nil {
		t.Fatal(err)
	}
	if rows := fileRows(); len(rows) != 1 || rows[0].Count != 2 {
		t.Errorf("after a write the file holds %v", rows)
	}
}

// Past Search.ServedRecordCount the oldest days' rows go first, a day's by requester then repo; a raise adds no row;
// and a new row the bound would drop at once is refused, nothing written, so the server answers that search
// fail-closed.
func TestServedRowsPastTheCountDropTheOldestDays(t *testing.T) {
	world := newSearchStateTestWorld(t)
	world.settings.ServedRecordCount = 3
	requesters, repo := sortedTestIds(4), NewId()
	midnights := []time.Time{}
	nextDay := func() {
		midnights = append(midnights, world.toUtcMidnight())
		world.clock.advance(time.Hour)
	}
	search := func(requesterIndex int) {
		t.Helper()
		world.clock.advance(time.Minute)
		if err := world.state.RecordServed(requesters[requesterIndex], repo); err != nil {
			t.Fatal(err)
		}
	}
	// a row by the indexes of its requester and day, with its count
	type wantRow struct {
		requesterIndex int
		dayIndex       int
		count          int64
	}
	expect := func(wants ...wantRow) {
		t.Helper()
		records, err := world.state.ServedRecords()
		if err != nil || len(records) != len(wants) {
			t.Fatalf("rows %v %v, wanted %v", records, err, wants)
		}
		for i, want := range wants {
			record := records[i]
			if record.RequesterId != requesters[want.requesterIndex] || !record.Day.Equal(midnights[want.dayIndex]) || record.Count != want.count {
				t.Errorf("row %d %v, wanted %v", i, record, want)
			}
		}
	}
	nextDay()
	search(2)
	search(1)
	nextDay()
	search(3)
	expect(wantRow{requesterIndex: 1, dayIndex: 0, count: 1}, wantRow{requesterIndex: 2, dayIndex: 0, count: 1}, wantRow{requesterIndex: 3, dayIndex: 1, count: 1})
	nextDay()
	search(1)
	expect(wantRow{requesterIndex: 2, dayIndex: 0, count: 1}, wantRow{requesterIndex: 3, dayIndex: 1, count: 1}, wantRow{requesterIndex: 1, dayIndex: 2, count: 1})
	search(2)
	expect(wantRow{requesterIndex: 3, dayIndex: 1, count: 1}, wantRow{requesterIndex: 1, dayIndex: 2, count: 1}, wantRow{requesterIndex: 2, dayIndex: 2, count: 1})
	search(1)
	expect(wantRow{requesterIndex: 3, dayIndex: 1, count: 1}, wantRow{requesterIndex: 1, dayIndex: 2, count: 2}, wantRow{requesterIndex: 2, dayIndex: 2, count: 1})
	search(3)
	expect(wantRow{requesterIndex: 1, dayIndex: 2, count: 2}, wantRow{requesterIndex: 2, dayIndex: 2, count: 1}, wantRow{requesterIndex: 3, dayIndex: 2, count: 1})
	// every row is today's now, and requester 0's would sort first among them: the bound would drop it at once
	before := world.plaintext(t)
	count, _ := world.state.Changes()
	if err := world.state.RecordServed(requesters[0], repo); !errors.Is(err, ErrSearchStateArgs) {
		t.Errorf("a row the bound drops at once: %v", err)
	}
	if !bytes.Equal(before, world.plaintext(t)) {
		t.Error("a refused row was written")
	}
	if next, _ := world.state.Changes(); next != count {
		t.Errorf("a refused row raised Changes")
	}
	search(3)
	expect(wantRow{requesterIndex: 1, dayIndex: 2, count: 2}, wantRow{requesterIndex: 2, dayIndex: 2, count: 1}, wantRow{requesterIndex: 3, dayIndex: 2, count: 2})
}

// QD-961's case: a reader's rate raises its row's count and adds no row, so under a bound of three rows one reader's
// hundred searches a day for three days keep all three days, exact, where a record a search kept only the last three
// searches.
func TestServedRowsKeepAReadersDaysWhateverItsRate(t *testing.T) {
	world := newSearchStateTestWorld(t)
	world.settings.ServedRecordCount = 3
	requester, repo := NewId(), NewId()
	midnights := []time.Time{}
	for range 3 {
		midnights = append(midnights, world.toUtcMidnight())
		for range 100 {
			world.clock.advance(time.Minute)
			if err := world.state.RecordServed(requester, repo); err != nil {
				t.Fatal(err)
			}
		}
	}
	records, err := world.state.ServedRecords()
	if err != nil || len(records) != 3 {
		t.Fatalf("records %v %v", records, err)
	}
	for i, record := range records {
		if !record.Day.Equal(midnights[i]) || record.Count != 100 {
			t.Errorf("day %d's row %v", i, record)
		}
		if record.First.UnixMilli() != midnights[i].Add(time.Minute).UnixMilli() || record.Last.UnixMilli() != midnights[i].Add(100*time.Minute).UnixMilli() {
			t.Errorf("day %d's row from %v to %v", i, record.First, record.Last)
		}
	}
}

// A search.state of the old one-search form loads: each record reads as a row of count 1 on its time's day, two of one
// requester, repo and day fold into one, one whose day ended past the timeout is hidden, and the next write leaves only
// rows, which a fresh state reads the same.
func TestServedRecordOldFormLoadsAndFolds(t *testing.T) {
	world := newSearchStateTestWorld(t)
	requesters, repo := sortedTestIds(2), NewId()
	midnight := world.toUtcMidnight()
	world.clock.advance(time.Hour)
	yesterday := midnight.Add(-24 * time.Hour)
	oldRecord := func(requester Id, at time.Time) string {
		return fmt.Sprintf(`{"requester":%q,"repo":%q,"at_ms":%d}`, hex.EncodeToString(requester[:]), hex.EncodeToString(repo[:]), at.UnixMilli())
	}
	// as the old form kept them, by time
	oldRecords := []string{
		oldRecord(requesters[0], midnight.Add(-40*24*time.Hour)),
		oldRecord(requesters[1], yesterday.Add(2*time.Hour)),
		oldRecord(requesters[0], yesterday.Add(3*time.Hour)),
		oldRecord(requesters[0], yesterday.Add(20*time.Hour)),
		oldRecord(requesters[0], midnight.Add(30*time.Minute)),
	}
	world.writePlaintext(t, []byte(`{"version":1,"mode":"own","records":[`+strings.Join(oldRecords, ",")+`]}`))
	// a row by its requester, day, count and times
	type wantRow struct {
		requesterId Id
		day         time.Time
		count       int64
		first       time.Time
		last        time.Time
	}
	wants := []wantRow{
		{requesterId: requesters[0], day: yesterday, count: 2, first: yesterday.Add(3 * time.Hour), last: yesterday.Add(20 * time.Hour)},
		{requesterId: requesters[1], day: yesterday, count: 1, first: yesterday.Add(2 * time.Hour), last: yesterday.Add(2 * time.Hour)},
		{requesterId: requesters[0], day: midnight, count: 1, first: midnight.Add(30 * time.Minute), last: midnight.Add(30 * time.Minute)},
	}
	expect := func(state *SidecarSearchState) {
		t.Helper()
		records, err := state.ServedRecords()
		if err != nil || len(records) != len(wants) {
			t.Fatalf("rows %v %v", records, err)
		}
		for i, want := range wants {
			record := records[i]
			if record.RequesterId != want.requesterId || record.RepoId != repo || !record.Day.Equal(want.day) || record.Count != want.count ||
				record.First.UnixMilli() != want.first.UnixMilli() || record.Last.UnixMilli() != want.last.UnixMilli() {
				t.Errorf("row %d %v, wanted %v", i, record, want)
			}
		}
	}
	state := world.newState(t)
	if mode, err := state.Mode(); err != nil || mode != SearchRemoteOwn {
		t.Fatalf("an old-form file read %q %v", mode, err)
	}
	expect(state)

	world.clock.advance(time.Minute)
	if err := state.RecordServed(requesters[0], repo); err != nil {
		t.Fatal(err)
	}
	wants[2].count, wants[2].last = 2, world.clock.Now()
	expect(state)
	decoded := map[string]any{}
	if err := json.Unmarshal(world.plaintext(t), &decoded); err != nil {
		t.Fatal(err)
	}
	rows, ok := decoded["records"].([]any)
	if !ok || len(rows) != len(wants) {
		t.Fatalf("the file's rows %v", decoded["records"])
	}
	for _, row := range rows {
		keys := []string{}
		for key := range row.(map[string]any) {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"count", "day", "first_ms", "last_ms", "repo", "requester"}) {
			t.Errorf("a row written as %v", keys)
		}
	}
	expect(world.newState(t))
}

// search.state stays under Search.StateByteCount whatever a requester's rate, computed and not slept (QD-961): a reader
// at RemoteRequesterRate's ceiling has one row a day, so forty days leave today's row and the 30 days' before it; and
// the most rows the file holds, Search.ServedRecordCount of them each at the ceiling's count of a day, encode under the
// bound, load, and take the next day's row.
func TestServedRowsStayUnderTheStateBound(t *testing.T) {
	world := newSearchStateTestWorld(t)
	settings := world.settings
	day := 24 * time.Hour
	// the most searches one requester makes in a day at the rate's ceiling: its burst, then its rate all day
	rate := settings.RemoteRequesterRate
	ceilingCount := int64(rate.Burst) + int64(rate.Count)*int64(day/rate.Interval)
	// a row is kept on its day and the ServedRecordTimeout after it
	keptDayCount := int(settings.ServedRecordTimeout/day) + 1
	encodedByteCount := func(wire *searchStateWire) int64 {
		encoded, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		return int64(len(encoded))
	}

	// one reader, searching at the first and the last instant of each of forty days
	requester, repo := NewId(), NewId()
	world.toUtcMidnight()
	for i := range 40 {
		if 0 < i {
			world.clock.advance(time.Millisecond)
		}
		if err := world.state.RecordServed(requester, repo); err != nil {
			t.Fatal(err)
		}
		world.clock.advance(day - time.Millisecond)
		if err := world.state.RecordServed(requester, repo); err != nil {
			t.Fatal(err)
		}
	}
	decoded := &searchStateWire{}
	if err := json.Unmarshal(world.plaintext(t), decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Records) != keptDayCount {
		t.Fatalf("%d rows after forty days, wanted %d", len(decoded.Records), keptDayCount)
	}
	// at the ceiling only each row's count is larger
	for i := range decoded.Records {
		decoded.Records[i].Count = ceilingCount
	}
	if byteCount := encodedByteCount(decoded); settings.StateByteCount < byteCount {
		t.Errorf("one reader at the ceiling for 30 days: %d bytes past %d", byteCount, settings.StateByteCount)
	}

	// the most the bound keeps: ServedRecordCount rows on the kept days, each at the ceiling's count across its day
	today := servedRowDayOf(world.clock.Now().UnixMilli())
	worst := &searchStateWire{Version: searchStateVersion}
	for i := range settings.ServedRecordCount {
		rowDay := today - int64(i%keptDayCount)
		rowRequesterId := NewId()
		worst.Records = append(worst.Records, searchStateRecordWire{
			Requester: hex.EncodeToString(rowRequesterId[:]),
			Repo:      hex.EncodeToString(repo[:]),
			Day:       rowDay,
			Count:     ceilingCount,
			FirstMs:   servedRowDayStartMs(rowDay),
			LastMs:    servedRowDayStartMs(rowDay+1) - 1,
		})
	}
	slices.SortFunc(worst.Records, compareServedRows)
	encoded, err := json.Marshal(worst)
	if err != nil {
		t.Fatal(err)
	}
	if settings.StateByteCount < int64(len(encoded)) {
		t.Fatalf("%d rows at the ceiling: %d bytes past %d", settings.ServedRecordCount, len(encoded), settings.StateByteCount)
	}
	world.writePlaintext(t, encoded)
	state := world.newState(t)
	if records, err := state.ServedRecords(); err != nil || len(records) != settings.ServedRecordCount {
		t.Fatalf("%d rows read %v", len(records), err)
	}
	// the next day's first search takes a row, the oldest day's first going
	world.clock.advance(time.Millisecond)
	newcomer := NewId()
	if err := state.RecordServed(newcomer, repo); err != nil {
		t.Fatal(err)
	}
	records, err := state.ServedRecords()
	if err != nil || len(records) != settings.ServedRecordCount || records[len(records)-1].RequesterId != newcomer {
		t.Fatalf("%d rows after the next day's search %v", len(records), err)
	}
	if oldest := records[0].RequesterId; hex.EncodeToString(oldest[:]) == worst.Records[0].Requester {
		t.Errorf("the oldest day's first row stayed")
	}
	if byteCount := int64(len(world.plaintext(t))); settings.StateByteCount < byteCount {
		t.Errorf("the file at the bound: %d bytes past %d", byteCount, settings.StateByteCount)
	}
}

// A served row that is not one, of no searches, with its times out of order or off its day, or carrying the old form's
// time besides, reads as a failed file, as any other that does not decode does; a well formed row beside them reads.
func TestServedRowMalformedFails(t *testing.T) {
	world := newSearchStateTestWorld(t)
	requester, repo := NewId(), NewId()
	midnight := world.toUtcMidnight()
	world.clock.advance(time.Hour)
	day, startMs := servedRowDayOf(midnight.UnixMilli()), midnight.UnixMilli()
	row := func(day int64, count int64, firstMs int64, lastMs int64, extra string) []byte {
		return fmt.Appendf(nil, `{"version":1,"records":[{"requester":%q,"repo":%q,"day":%d,"count":%d,"first_ms":%d,"last_ms":%d%s}]}`,
			hex.EncodeToString(requester[:]), hex.EncodeToString(repo[:]), day, count, firstMs, lastMs, extra)
	}
	world.writePlaintext(t, row(day, 1, startMs, startMs+1, ""))
	if records, err := world.newState(t).ServedRecords(); err != nil || len(records) != 1 || records[0].Count != 1 {
		t.Fatalf("a well formed row read %v %v", records, err)
	}
	cases := [][]byte{
		// of no searches, its times set
		row(day, 0, startMs, startMs, ""),
		row(day, -1, startMs, startMs, ""),
		// its times out of order
		row(day, 2, startMs+1, startMs, ""),
		// off its day, before it and after it
		row(day, 1, startMs-1, startMs, ""),
		row(day, 1, startMs, startMs+(24*time.Hour).Milliseconds(), ""),
		// the old form's time besides a row's
		row(day, 1, startMs, startMs, fmt.Sprintf(`,"at_ms":%d`, startMs)),
	}
	for _, content := range cases {
		world.writePlaintext(t, content)
		if _, err := world.newState(t).ServedRecords(); !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s read %v", content, err)
		}
	}
}

// While locked nothing is read or written; once open again the state reads as it was.
func TestSearchStateLockedChangesNothing(t *testing.T) {
	world := newSearchStateTestWorld(t)
	if err := world.state.SetMode(SearchRemoteOwn); err != nil {
		t.Fatal(err)
	}
	before := backendSnapshot(t, world.backend)
	world.instance.Lock()
	if err := world.state.SetMode(SearchRemoteOff); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("a change while locked: %v", err)
	}
	if _, err := world.state.Mode(); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("a read while locked: %v", err)
	}
	if err := world.state.RecordServed(NewId(), NewId()); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("a record while locked: %v", err)
	}
	after := backendSnapshot(t, world.backend)
	if len(after) != len(before) {
		t.Fatalf("a locked state wrote %d files", len(after)-len(before))
	}
	for path, content := range before {
		if !bytes.Equal(after[path], content) {
			t.Errorf("a locked state rewrote %s", path)
		}
	}
	if err := world.instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	if mode, err := world.state.Mode(); err != nil || mode != SearchRemoteOwn {
		t.Errorf("mode %q %v once open", mode, err)
	}
}

// A file that does not decode is the person's choices, not derived data: it alarms once, every call fails closed, and
// nothing is written over it.
func TestSearchStateFailedIsNeverOverwritten(t *testing.T) {
	world := newSearchStateTestWorld(t)
	world.writePlaintext(t, []byte(`{"version":1,"mode":"sometimes"}`))
	before := world.plaintext(t)
	if _, err := world.state.Mode(); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("a failed file read %v", err)
	}
	if err := world.state.SetMode(SearchRemoteOff); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("a change over a failed file: %v", err)
	}
	if err := world.state.RecordServed(NewId(), NewId()); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("a record over a failed file: %v", err)
	}
	if !bytes.Equal(before, world.plaintext(t)) {
		t.Error("a failed file was written over")
	}
	if world.failed != 1 {
		t.Errorf("%d alarms", world.failed)
	}
	// it is read again at each call: once the file reads well, the state works again, with no change lost
	world.writePlaintext(t, []byte(`{"version":1,"mode":"own"}`))
	if mode, err := world.state.Mode(); err != nil || mode != SearchRemoteOwn {
		t.Errorf("a mended file read %q %v", mode, err)
	}
	if world.failed != 1 {
		t.Errorf("%d alarms after the mend", world.failed)
	}
}

// Changes raises its count at each change, so the asker and the policy wake.
func TestSearchStateChangesRaise(t *testing.T) {
	world := newSearchStateTestWorld(t)
	count, changed := world.state.Changes()
	if err := world.state.SetMode(SearchRemoteOff); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	default:
		t.Fatal("no change raised")
	}
	if next, _ := world.state.Changes(); next != count+1 {
		t.Errorf("count %d after %d", next, count)
	}
}
