// KEYS-M2-26's tests of ur evs rekey's job, over the write tests' stand-in evs (evs_plan_test.go): §22.7's "after ur
// evs rekey every file of the repo opens only under the current generation", read from each file's chain; pushes
// within the settings' entry-write and byte bounds; a kill before a push commits and one between a commit and its
// progress record, each resumed without skipping or rewriting a file twice; the rate on a clock the test owns; a file
// changed or removed under the job never put back; and what the job cannot write or list refused or skipped by name.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A clock whose waits pass at once by moving its time on, so a rate shows as time on this clock and no test sleeps.
type rekeyTestClock struct {
	stateLock sync.Mutex
	now       time.Time
	waits     []time.Duration
}

func newRekeyTestClock() *rekeyTestClock {
	return &rekeyTestClock{now: time.Date(2026, time.November, 10, 9, 0, 0, 0, time.UTC)}
}

func (self *rekeyTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *rekeyTestClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.waits = append(self.waits, timeout)
	self.now = self.now.Add(timeout)
	fired := make(chan time.Time, 1)
	fired <- self.now
	return fired
}

func (self *rekeyTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return true }
}

func (self *rekeyTestClock) waited() []time.Duration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]time.Duration{}, self.waits...)
}

// The write tests' gkm with a hook at each EnsureWritable, which a push calls after the job read its files and before
// the push plans: where another writer's change lands in these tests.
type rekeyTestGkm struct {
	gkmRefusingClient
	inner *evsTestWriteGkm

	stateLock sync.Mutex
	ensured   int
	onEnsure  func(call int)
}

func (self *rekeyTestGkm) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return self.inner.CurrentRepoKey(ctx, repoId)
}

func (self *rekeyTestGkm) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	return self.inner.RepoKey(ctx, repoId, generation)
}

func (self *rekeyTestGkm) EnsureWritable(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	call, hook := func() (int, func(call int)) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.ensured += 1
		return self.ensured, self.onEnsure
	}()
	if hook != nil {
		hook(call)
	}
	return self.inner.EnsureWritable(ctx, repoId)
}

func (self *rekeyTestGkm) setOnEnsure(onEnsure func(call int)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.ensured = 0
	self.onEnsure = onEnsure
}

// A store that refuses the creates a test names, by their order among the creates of the progress records: a kill
// between a push's commit and its record.
type rekeyTestStore struct {
	SidecarStore

	stateLock sync.Mutex
	created   int
	failAt    int
}

var errRekeyTestKilled = errors.New("killed before the record")

func (self *rekeyTestStore) Create(name string) (SidecarStoreWriter, error) {
	killed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.created += 1
		return self.created == self.failAt
	}()
	if killed {
		return nil, errRekeyTestKilled
	}
	return self.SidecarStore.Create(name)
}

// A repo of the write tests' world and a job over it.
type rekeyTest struct {
	t        *testing.T
	writer   *evsTestWriter
	gkm      *rekeyTestGkm
	store    *rekeyTestStore
	clock    *rekeyTestClock
	settings *GkmRekeySettings
	contents map[string][]byte
	// each file's entry version as the test last wrote it, before any rekey
	versions map[string]uint64
}

func newRekeyTest(t *testing.T) *rekeyTest {
	t.Helper()
	writer := newEvsTestWriter(t)
	gkm := &rekeyTestGkm{inner: writer.gkm}
	writer.test.client.args.Gkm = gkm
	return &rekeyTest{
		t: t, writer: writer, gkm: gkm, store: &rekeyTestStore{SidecarStore: newEvsTestStore(t)}, clock: newRekeyTestClock(),
		settings: DefaultGkmRekeySettings(), contents: map[string][]byte{}, versions: map[string]uint64{},
	}
}

// A job runner on the test's store, as a restarted daemon builds one.
func (self *rekeyTest) rekey() *GkmRekey {
	self.t.Helper()
	rekey, err := NewGkmRekey(&GkmRekeyArgs{Evs: self.writer.test.client, Store: self.store, Settings: self.settings, Clock: self.clock, Log: NewNoopLogger()})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(rekey.Close)
	return rekey
}

// Writes a file, byteCount bytes of it.
func (self *rekeyTest) write(path string, byteCount int) {
	self.t.Helper()
	self.writeContent(path, evsTestEdited(path, byteCount))
}

// Writes a file's content.
func (self *rekeyTest) writeContent(path string, content []byte) {
	self.t.Helper()
	result, err := self.writer.write(self.t, path, content)
	if err != nil {
		self.t.Fatal(err)
	}
	self.contents[path] = content
	self.versions[path] = result.PathVersion
}

// count small files under directory, named in walk order.
func (self *rekeyTest) writeFiles(directory string, count int) []string {
	self.t.Helper()
	paths := []string{}
	for i := 0; i < count; i += 1 {
		path := fmt.Sprintf("%s/%02d.txt", directory, i)
		self.write(path, 300+i)
		paths = append(paths, path)
	}
	return paths
}

// Moves the repo to a new generation of cause, as a rotation does.
func (self *rekeyTest) rotate(generation uint64, cause GkmCause) {
	self.writer.gkm.stateLock.Lock()
	self.writer.gkm.newest = generation
	self.writer.gkm.causes[generation] = cause
	self.writer.gkm.stateLock.Unlock()
	self.writer.world.generation = generation
}

// What path's chain holds, and its entry version.
func (self *rekeyTest) chain(path string) (*EvsChainState, uint64) {
	self.t.Helper()
	result, err := self.writer.repo.read(context.Background(), self.writer.world.refId, []string{path}, 0, true)
	if err != nil {
		self.t.Fatalf("%s: %v", path, err)
	}
	defer result.objects.close()
	verified := result.replies[0]
	if verified.Entry == nil || verified.Removal != nil {
		self.t.Fatalf("%s does not stand", path)
	}
	content, chain, _, err := self.writer.repo.readBase(context.Background(), result, verified)
	if err != nil {
		self.t.Fatalf("%s: %v", path, err)
	}
	content.close()
	return chain, verified.Entry.GetVersion()
}

// Holds every path to the chain generation 1 keyed, at the version the test wrote.
func (self *rekeyTest) requireUntouched(paths ...string) {
	self.t.Helper()
	for _, path := range paths {
		if chain, version := self.chain(path); chain.KeyGeneration != 1 || version != self.versions[path] {
			self.t.Errorf("%s: key generation %d, version %d; want generation 1, version %d", path, chain.KeyGeneration, version, self.versions[path])
		}
	}
}

// Holds every path to one whole checkpoint of generation, written once since the test's own write, its content as
// written.
func (self *rekeyTest) requireRekeyed(generation uint64, paths ...string) {
	self.t.Helper()
	for _, path := range paths {
		chain, entryVersion := self.chain(path)
		if version := self.versions[path] + 1; chain.KeyGeneration != generation || chain.RecordCount != 1 || chain.DiffCount != 0 || entryVersion != version {
			self.t.Errorf("%s: key generation %d, %d records, version %d; want generation %d, one record, version %d",
				path, chain.KeyGeneration, chain.RecordCount, entryVersion, generation, version)
		}
		read, _, err := self.writer.read(self.t, path)
		if err != nil || !bytes.Equal(read, self.contents[path]) {
			self.t.Errorf("%s read back: %v", path, err)
		}
	}
}

// The statements the stand-in was sent.
func (self *rekeyTest) posted() int {
	self.writer.server.stateLock.Lock()
	defer self.writer.server.stateLock.Unlock()
	return len(self.writer.server.postedStatements)
}

// The entry writes of each push committed from the from-th on.
func (self *rekeyTest) entryWriteCounts(from int) []int {
	self.writer.world.stateLock.Lock()
	defer self.writer.world.stateLock.Unlock()
	counts := []int{}
	for _, commit := range self.writer.world.commits[from:] {
		push := commit.parsed.Push
		count := len(push.GetChanges())
		if count == 0 {
			count = int(push.GetChangeCount())
		}
		counts = append(counts, count)
	}
	return counts
}

func (self *rekeyTest) commits() int {
	self.writer.world.stateLock.Lock()
	defer self.writer.world.stateLock.Unlock()
	return len(self.writer.world.commits)
}

// §22.7: after ur evs rekey every file walked opens only under the current generation. Files written under
// generation 1, inline and in segments, one with a diff on its checkpoint; a REQUEST rotation, after which the lazy
// rule rewrites nothing; then the job: every file under the path it was given is one whole checkpoint of generation 2
// with its content unchanged, a file outside the path keeps its old key, and a second run writes nothing.
func TestEvsRekeyBringsEveryFileToTheCurrentGeneration(t *testing.T) {
	test := newRekeyTest(t)
	test.write("d/a.txt", 400)
	test.write("d/b.bin", 20*1024)
	test.write("d/e/c.txt", 900)
	test.write("d/e/f/g.bin", 24*1024)
	test.write("other/x.bin", 20*1024)
	walked := []string{"d/a.txt", "d/b.bin", "d/e/c.txt", "d/e/f/g.bin"}

	test.rotate(2, GkmCauseRequest)
	// the twin: a write after a REQUEST generation is still a diff on the chain generation 1 keyed
	edited := append([]byte{}, test.contents["d/b.bin"]...)
	edited[5000] ^= 1
	test.writeContent("d/b.bin", edited)
	if chain, _ := test.chain("d/b.bin"); chain.KeyGeneration != 1 || chain.DiffCount != 1 {
		t.Fatalf("a write after a REQUEST generation: key generation %d, %d diffs", chain.KeyGeneration, chain.DiffCount)
	}
	for _, path := range append([]string{"other/x.bin"}, walked...) {
		if chain, _ := test.chain(path); chain.KeyGeneration != 1 {
			t.Fatalf("%s before the rekey: key generation %d", path, chain.KeyGeneration)
		}
	}

	rekey := test.rekey()
	request := &GkmRekeyRequest{RepoId: test.writer.world.repoId, Paths: []string{"d"}}
	commits := test.commits()
	progress, err := rekey.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if progress.State != GkmRekeyStateDone || progress.Generation != 2 || progress.RewrittenCount != 4 || progress.CurrentCount != 0 ||
		progress.PushCount != 1 || len(progress.SkippedRefs) != 0 || len(progress.Paths) != 1 || !bytes.Equal(progress.RefNames[0], EvsMainRefName) {
		t.Fatalf("the progress: %+v", progress)
	}
	if got := test.entryWriteCounts(commits); len(got) != 1 || got[0] != 4 {
		t.Errorf("the job's pushes carried %v entry writes", got)
	}
	test.requireRekeyed(2, walked...)
	// a file outside the path named keeps its key
	test.requireUntouched("other/x.bin")
	stored, ok, err := rekey.Progress(request.RepoId)
	if err != nil || !ok || stored.State != GkmRekeyStateDone || stored.RewrittenCount != 4 {
		t.Errorf("the stored progress: %+v %v", stored, err)
	}

	// a second run finds every file current and sends nothing
	posted := test.posted()
	again, err := rekey.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if again.State != GkmRekeyStateDone || again.RewrittenCount != 0 || again.CurrentCount != 4 || again.PushCount != 0 || test.posted() != posted {
		t.Errorf("a second run: %+v, %d statements more", again, test.posted()-posted)
	}
}

// §10.16's push bound: a push carries at most PushEntryWriteCount entry writes, 1,024 by default and never more, and
// at most PushByteCount of content.
func TestEvsRekeyPushesStayWithinTheSettings(t *testing.T) {
	defaults := DefaultGkmRekeySettings()
	if defaults.PushEntryWriteCount != 1024 || defaults.FileRate.Count != 50 || defaults.FileRate.Interval != time.Second || defaults.FileRate.Burst != 1 {
		t.Errorf("the defaults: %+v", defaults)
	}
	for _, change := range []func(settings *GkmRekeySettings){
		func(settings *GkmRekeySettings) { settings.PushEntryWriteCount = 1025 },
		func(settings *GkmRekeySettings) { settings.PushEntryWriteCount = 0 },
		func(settings *GkmRekeySettings) { settings.FileRate.Count = 0 },
		func(settings *GkmRekeySettings) { settings.PushByteCount = 0 },
	} {
		settings := DefaultGkmRekeySettings()
		change(settings)
		if err := settings.validate(); !errors.Is(err, errInvalidSettings) {
			t.Errorf("settings %+v: %v", settings, err)
		}
	}

	test := newRekeyTest(t)
	paths := test.writeFiles("p", 10)
	test.rotate(2, GkmCauseRemove)
	test.settings.PushEntryWriteCount = 4
	commits := test.commits()
	progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: test.writer.world.repoId, Paths: []string{"p"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := test.entryWriteCounts(commits); len(got) != 3 || got[0] != 4 || got[1] != 4 || got[2] != 2 {
		t.Errorf("entry writes a push: %v", got)
	}
	if progress.RewrittenCount != 10 || progress.PushCount != 3 {
		t.Errorf("the progress: %+v", progress)
	}
	test.requireRekeyed(2, paths...)

	// the byte bound closes a push before the count does
	bytesTest := newRekeyTest(t)
	for _, path := range []string{"q/0.txt", "q/1.txt", "q/2.txt"} {
		bytesTest.write(path, 3000)
	}
	bytesTest.rotate(2, GkmCauseRemove)
	bytesTest.settings.PushByteCount = 5000
	commits = bytesTest.commits()
	if _, err := bytesTest.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: bytesTest.writer.world.repoId, Paths: []string{"q"}}); err != nil {
		t.Fatal(err)
	}
	if got := bytesTest.entryWriteCounts(commits); len(got) != 2 || got[0] != 2 || got[1] != 1 {
		t.Errorf("entry writes a push under the byte bound: %v", got)
	}
}

// A kill before a push commits: the record names the last push that did, a restarted job goes on from there, and no
// file is rewritten twice or passed over.
func TestEvsRekeyResumesFromItsLastCommittedPush(t *testing.T) {
	test := newRekeyTest(t)
	paths := test.writeFiles("k", 10)
	test.rotate(2, GkmCauseRemove)
	test.settings.PushEntryWriteCount = 4
	repoId := test.writer.world.repoId
	// EnsureWritable's calls: the job's own, then one a push; the second push is refused and returns
	test.gkm.setOnEnsure(func(call int) {
		if call == 3 {
			test.writer.server.stateLock.Lock()
			defer test.writer.server.stateLock.Unlock()
			test.writer.server.pushRefusals = []*evsTestRefusal{{status: http.StatusInsufficientStorage, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL}}}
		}
	})
	rekey := test.rekey()
	progress, err := rekey.Run(context.Background(), &GkmRekeyRequest{RepoId: repoId, Paths: []string{"k"}})
	if !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL) {
		t.Fatalf("a job whose second push is refused: %v", err)
	}
	if progress.State != GkmRekeyStateStopped || progress.RewrittenCount != 4 || progress.PushCount != 1 {
		t.Fatalf("the progress at the kill: %+v", progress)
	}
	stored, ok, err := rekey.Progress(repoId)
	if err != nil || !ok || stored.State != GkmRekeyStateStopped || stored.RewrittenCount != 4 || stored.StopReason == "" {
		t.Fatalf("the stored progress at the kill: %+v %v", stored, err)
	}
	test.requireRekeyed(2, paths[:4]...)
	test.requireUntouched(paths[4:]...)

	// the restart: a new runner on the same store, asked for the repo alone
	test.gkm.setOnEnsure(nil)
	commits := test.commits()
	resumed, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: repoId})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.State != GkmRekeyStateDone || resumed.RewrittenCount != 10 || resumed.PushCount != 3 || resumed.CurrentCount != 0 ||
		resumed.Generation != 2 || len(resumed.Paths) != 1 || resumed.Paths[0] != "k" {
		t.Errorf("the resumed job: %+v", resumed)
	}
	if got := test.entryWriteCounts(commits); len(got) != 2 || got[0] != 4 || got[1] != 2 {
		t.Errorf("the resumed job's pushes: %v", got)
	}
	// each file rewritten once, never twice
	test.requireRekeyed(2, paths...)
}

// A kill between a push's commit and its progress record: the record still names the push before, and the restarted
// job finds the committed files current rather than rewriting them, so progress written only after a commit never
// skips a file and a lost record costs no second write.
func TestEvsRekeyAKillBeforeTheRecordRewritesNothingTwice(t *testing.T) {
	test := newRekeyTest(t)
	paths := test.writeFiles("k", 10)
	test.rotate(2, GkmCauseRemove)
	test.settings.PushEntryWriteCount = 4
	repoId := test.writer.world.repoId
	// the record's creates: the job's first, one after the first push, then the one after the second, which is killed
	test.store.failAt = 3
	progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: repoId, Paths: []string{"k"}})
	if !errors.Is(err, errRekeyTestKilled) {
		t.Fatalf("a job killed before its record: %v", err)
	}
	// what the run answers is the record as stored, never ahead of it
	if progress.State != GkmRekeyStateStopped || progress.RewrittenCount != 4 || progress.PushCount != 1 || progress.StopReason == "" {
		t.Fatalf("the progress at the kill: %+v", progress)
	}
	rekey := test.rekey()
	stored, ok, err := rekey.Progress(repoId)
	if err != nil || !ok || stored.State != GkmRekeyStateStopped || stored.RewrittenCount != 4 || stored.PushCount != 1 {
		t.Fatalf("the record after the kill names more than the first push: %+v %v", stored, err)
	}
	// the second push did commit
	test.requireRekeyed(2, paths[:8]...)

	commits := test.commits()
	resumed, err := rekey.Run(context.Background(), &GkmRekeyRequest{RepoId: repoId})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.State != GkmRekeyStateDone || resumed.RewrittenCount != 6 || resumed.CurrentCount != 4 || resumed.PushCount != 2 {
		t.Errorf("the resumed job: %+v", resumed)
	}
	if got := test.entryWriteCounts(commits); len(got) != 1 || got[0] != 2 {
		t.Errorf("the resumed job's pushes: %v", got)
	}
	test.requireRekeyed(2, paths...)
}

// §10.16's rate on a clock the test owns: each file takes a turn 1/50 s after the one before, so ten files take nine
// waits of 20 ms; the rate and its burst are the settings'.
func TestEvsRekeyHoldsToItsRateOnAFakeClock(t *testing.T) {
	cases := []struct {
		name  string
		rate  SidecarRate
		waits int
		wait  time.Duration
	}{
		{name: "50 a second", rate: DefaultGkmRekeySettings().FileRate, waits: 9, wait: 20 * time.Millisecond},
		{name: "5 a second", rate: SidecarRate{Count: 5, Burst: 1, Interval: time.Second}, waits: 9, wait: 200 * time.Millisecond},
		{name: "a burst of 3", rate: SidecarRate{Count: 50, Burst: 3, Interval: time.Second}, waits: 7, wait: 20 * time.Millisecond},
	}
	for _, c := range cases {
		test := newRekeyTest(t)
		paths := test.writeFiles("r", 10)
		test.rotate(2, GkmCauseRemove)
		test.settings.FileRate = c.rate
		started := test.clock.Now()
		if _, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: test.writer.world.repoId, Paths: []string{"r"}}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		waits := test.clock.waited()
		if len(waits) != c.waits {
			t.Errorf("%s: %d waits, want %d", c.name, len(waits), c.waits)
		}
		for _, wait := range waits {
			if wait != c.wait {
				t.Errorf("%s: a wait of %s, want %s", c.name, wait, c.wait)
			}
		}
		if elapsed, least := test.clock.Now().Sub(started), time.Duration(c.waits)*c.wait; elapsed < least {
			t.Errorf("%s: ten files in %s, under %s", c.name, elapsed, least)
		}
		test.requireRekeyed(2, paths...)
	}
	// a canceled job waits for no turn
	pacer := newGkmRekeyPacer(newRekeyTestClock(), DefaultGkmRekeySettings().FileRate)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pacer.take(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("a turn on a canceled job: %v", err)
	}
}

// Another writer's change between the job's read and its push: the changed file keeps the other writer's content,
// the removed file stays removed, and the rest are rewritten, the push built again from a fresh read.
func TestEvsRekeyNeverPutsAnOlderContentBack(t *testing.T) {
	test := newRekeyTest(t)
	paths := test.writeFiles("m", 6)
	test.rotate(2, GkmCauseRemove)
	repoId := test.writer.world.repoId
	theirs := []byte("another writer's content")
	test.gkm.setOnEnsure(func(call int) {
		// the first push's: after the job read every file, before the push plans
		if call == 2 {
			test.writer.world.push(&evsTestChange{path: paths[0], content: theirs}, &evsTestChange{path: paths[1]})
		}
	})
	progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: repoId, Paths: []string{"m"}})
	if err != nil {
		t.Fatal(err)
	}
	if progress.State != GkmRekeyStateDone || progress.RewrittenCount != 4 || progress.CurrentCount != 1 || progress.AbsentCount != 1 || progress.PushCount != 1 {
		t.Errorf("the progress: %+v", progress)
	}
	if read, _, err := test.writer.read(t, paths[0]); err != nil || !bytes.Equal(read, theirs) {
		t.Errorf("the file another writer changed: %q %v", read, err)
	}
	if _, _, err := test.writer.read(t, paths[1]); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("the file another writer removed: %v", err)
	}
	test.requireRekeyed(2, paths[2:]...)
}

// evs's own path-level CAS, a write landing between the push's plan and its commit: the batch is read and pushed
// again, at most MovedRetryCount times, after which the job stops and a later run finishes it.
func TestEvsRekeyRetriesAPathConflictAndThenStops(t *testing.T) {
	conflict := func() *evsTestRefusal {
		return &evsTestRefusal{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT}}
	}
	test := newRekeyTest(t)
	paths := test.writeFiles("c", 5)
	test.rotate(2, GkmCauseRemove)
	repoId := test.writer.world.repoId
	test.writer.server.pushRefusals = []*evsTestRefusal{conflict()}
	posted := test.posted()
	progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: repoId, Paths: []string{"c"}})
	if err != nil {
		t.Fatal(err)
	}
	if progress.RewrittenCount != 5 || progress.PushCount != 1 || test.posted()-posted != 2 {
		t.Errorf("after one conflict: %+v, %d statements", progress, test.posted()-posted)
	}
	test.requireRekeyed(2, paths...)

	stopped := newRekeyTest(t)
	stoppedPaths := stopped.writeFiles("c", 5)
	stopped.rotate(2, GkmCauseRemove)
	stopped.settings.MovedRetryCount = 1
	stopped.writer.server.pushRefusals = []*evsTestRefusal{conflict(), conflict()}
	progress, err = stopped.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: stopped.writer.world.repoId, Paths: []string{"c"}})
	if !errors.Is(err, ErrGkmRekeyMoved) || progress.State != GkmRekeyStateStopped || progress.RewrittenCount != 0 {
		t.Fatalf("past the retries: %v %+v", err, progress)
	}
	stopped.requireUntouched(stoppedPaths...)
	resumed, err := stopped.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: stopped.writer.world.repoId})
	if err != nil || resumed.State != GkmRekeyStateDone || resumed.RewrittenCount != 5 {
		t.Fatalf("the run after: %+v %v", resumed, err)
	}
	stopped.requireRekeyed(2, stoppedPaths...)
}

// What the job cannot list or write it does not claim: a request naming no path asks for the ref's root, which format
// 1 cannot list, and writes nothing; a git-mode ref is skipped by name; a malformed path is refused; and a repo runs
// one job at a time.
func TestEvsRekeyRefusesTheRootAndSkipsAGitModeRef(t *testing.T) {
	test := newRekeyTest(t)
	paths := test.writeFiles("s", 3)
	test.rotate(2, GkmCauseRemove)
	repoId := test.writer.world.repoId
	posted := test.posted()
	rekey := test.rekey()
	progress, err := rekey.Run(context.Background(), &GkmRekeyRequest{RepoId: repoId})
	if !errors.Is(err, ErrEvsTokenInvalid) || progress.State != GkmRekeyStateStopped || test.posted() != posted {
		t.Fatalf("a rekey from the root: %v %+v", err, progress)
	}
	for _, request := range []*GkmRekeyRequest{nil, {}, {RepoId: repoId, Paths: []string{"s//x"}}, {RepoId: repoId, Paths: []string{""}}} {
		if _, err := rekey.Run(context.Background(), request); err == nil {
			t.Errorf("a malformed request ran: %+v", request)
		}
	}

	// one job a repo: a second asked for while the first is inside its push
	var second error
	test.gkm.setOnEnsure(func(call int) {
		if call == 2 {
			_, second = rekey.Run(context.Background(), &GkmRekeyRequest{RepoId: repoId, Paths: []string{"s"}})
		}
	})
	// paths in any order, one inside another: walked once, in walk order; a path named that does not stand is
	// counted as gone, not passed over in silence
	progress, err = rekey.Run(context.Background(), &GkmRekeyRequest{RepoId: repoId, Paths: []string{paths[2], "s", "nowhere", paths[0]}})
	if err != nil || !errors.Is(second, ErrGkmRekeyRunning) {
		t.Fatalf("a job with a second asked for inside it: %v, the second %v", err, second)
	}
	if progress.RewrittenCount != 3 || progress.AbsentCount != 1 || len(progress.Paths) != 2 || progress.Paths[0] != "nowhere" || progress.Paths[1] != "s" {
		t.Errorf("the progress: %+v", progress)
	}
	test.requireRekeyed(2, paths...)

	git := newRekeyTest(t)
	git.writer.world.mode = protocol.EvsRefMode_EVS_REF_GIT
	git.writer.world.push(&evsTestChange{path: "tree.txt", content: []byte("tree")})
	git.writer.server.know("tree.txt")
	git.rotate(2, GkmCauseRemove)
	posted = git.posted()
	progress, err = git.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: git.writer.world.repoId, Paths: []string{"tree.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	if progress.State != GkmRekeyStateDone || progress.RewrittenCount != 0 || len(progress.SkippedRefs) != 1 ||
		progress.SkippedRefs[0].Reason != "git_mode" || !bytes.Equal(progress.SkippedRefs[0].RefName, EvsMainRefName) || git.posted() != posted {
		t.Errorf("a git-mode ref: %+v", progress)
	}
}

// Start runs a job on the runner's own goroutine: it shows as running, refuses a second, and Close ends it, after
// which a new runner finishes whatever it left.
func TestEvsRekeyStartRunsUntilClose(t *testing.T) {
	test := newRekeyTest(t)
	paths := test.writeFiles("a", 6)
	test.rotate(2, GkmCauseRemove)
	test.settings.PushEntryWriteCount = 2
	repoId := test.writer.world.repoId
	entered := make(chan struct{})
	release := make(chan struct{})
	test.gkm.setOnEnsure(func(call int) {
		if call == 2 {
			close(entered)
			<-release
		}
	})
	rekey := test.rekey()
	request := &GkmRekeyRequest{RepoId: repoId, Paths: []string{"a"}}
	started, err := rekey.Start(request)
	if err != nil || started.State != GkmRekeyStateRunning || started.Generation != 2 {
		t.Fatalf("the start: %+v %v", started, err)
	}
	<-entered
	if running, ok, err := rekey.Progress(repoId); err != nil || !ok || running.State != GkmRekeyStateRunning {
		t.Errorf("the progress of a running job: %+v %v", running, err)
	}
	if _, err := rekey.Start(request); !errors.Is(err, ErrGkmRekeyRunning) {
		t.Errorf("a second start: %v", err)
	}
	close(release)
	rekey.Close()
	if _, err := rekey.Start(request); err == nil {
		t.Error("a closed runner started a job")
	}
	// the job finished or was ended by the close: either way the next runner brings it to its end
	test.gkm.setOnEnsure(nil)
	finished, err := test.rekey().Run(context.Background(), request)
	if err != nil || finished.State != GkmRekeyStateDone {
		t.Fatalf("the run after the close: %+v %v", finished, err)
	}
	test.requireRekeyed(2, paths...)
}

// The planner's hold a rekey's writes carry (EvsPathWrite.IfVersion): a write made on an entry version the path no
// longer stands at, or on a path since removed, is refused before anything is sealed or sent, and one made on the
// standing version goes through.
func TestEvsWriteHeldToAVersionRefusesAMovedPath(t *testing.T) {
	writer := newEvsTestWriter(t)
	first, err := writer.write(t, "held.txt", []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := writer.write(t, "held.txt", []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	posted, uploads := len(writer.server.postedStatements), len(writer.server.uploads)
	held := func(version uint64, content []byte) error {
		write := &EvsPathWrite{Path: "held.txt", IfVersion: version, Remove: content == nil}
		if content != nil {
			write.Content = bytes.NewReader(content)
		}
		_, err := writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Writes: []*EvsPathWrite{write}})
		return err
	}
	if err := held(first.PathVersion, []byte("stale")); !errors.Is(err, ErrEvsPathMoved) {
		t.Fatalf("a write on a version since replaced: %v", err)
	}
	if err := held(first.PathVersion, nil); !errors.Is(err, ErrEvsPathMoved) {
		t.Fatalf("a removal on a version since replaced: %v", err)
	}
	if len(writer.server.postedStatements) != posted || len(writer.server.uploads) != uploads {
		t.Error("a refused write sent something")
	}
	if read, _, err := writer.read(t, "held.txt"); err != nil || string(read) != "two" {
		t.Errorf("the path after the refusals: %q %v", read, err)
	}
	if err := held(second.PathVersion, []byte("three")); err != nil {
		t.Fatalf("a write on the standing version: %v", err)
	}
	if _, err := writer.write(t, "held.txt", nil); err != nil {
		t.Fatal(err)
	}
	if err := held(second.PathVersion+1, []byte("back")); !errors.Is(err, ErrEvsPathMoved) {
		t.Errorf("a write held to a version of a removed path: %v", err)
	}
	if _, _, err := writer.read(t, "held.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("the removed path after the refusal: %v", err)
	}
}
