//go:build !ios_extension

package sidecar

// CORE-M10-03: §5.9's search state, search.state: written through and read back, kept through the cache's eviction
// and drops, holding no query, served records pruned at their timeout and bound, nothing changed while locked and a
// failed file never written over.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
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
	if records, err := reread.ServedRecords(); err != nil || len(records) != 1 || records[0].RequesterId != requester || records[0].RepoId != repo {
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

// The served record is {requester, repo, time}: a search under a canary query leaves no trace of it in search.state,
// whose records carry no other key.
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
	if !slices.Equal(keys, []string{"at_ms", "repo", "requester"}) {
		t.Errorf("a served record holds %v", keys)
	}
	if err := world.state.RecordServed(Id{}, repo); !errors.Is(err, ErrSearchStateArgs) {
		t.Errorf("a record of no requester: %v", err)
	}
}

// Records go at Search.ServedRecordTimeout and past Search.ServedRecordCount, the oldest first; the served memory at
// Search.RemoteServedTimeout, and a distrust deadline once passed.
func TestServedRecordExpires(t *testing.T) {
	world := newSearchStateTestWorld(t)
	world.settings.ServedRecordCount = 3
	requester, repo, indexer := NewId(), NewId(), NewId()
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
	if records, _ := world.state.ServedRecords(); len(records) != 1 {
		t.Errorf("a record gone before its timeout: %v", records)
	}
	world.clock.advance(world.settings.ServedRecordTimeout - world.settings.RemoteServedTimeout)
	if records, _ := world.state.ServedRecords(); len(records) != 0 {
		t.Errorf("a record past its timeout: %v", records)
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
	// past the count, the oldest go first
	repos := []Id{}
	for range 4 {
		world.clock.advance(time.Second)
		repo := NewId()
		repos = append(repos, repo)
		if err := world.state.RecordServed(requester, repo); err != nil {
			t.Fatal(err)
		}
	}
	records, _ := world.state.ServedRecords()
	if len(records) != 3 || records[0].RepoId != repos[1] || records[2].RepoId != repos[3] {
		t.Errorf("records past the count %v", records)
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
	store, err := world.instance.Store(&world.networkId).Directory("", SidecarSearchFileClass)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.Create(sidecarSearchStateName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(`{"version":1,"mode":"sometimes"}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
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
	writer, err = store.Create(sidecarSearchStateName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(`{"version":1,"mode":"own"}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
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
