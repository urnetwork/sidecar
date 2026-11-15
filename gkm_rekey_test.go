//go:build !ios_extension

// KEYS-M2-26's tests of ur evs rekey's job, over the write tests' stand-in evs (evs_plan_test.go): §22.7's "after ur
// evs rekey every file of the repo opens only under the current generation", read from each file's chain; pushes
// within the settings' entry-write and byte bounds; a kill before a push commits and one between a commit and its
// progress record, each resumed without skipping or rewriting a file twice; the rate on a clock the test owns; a file
// changed or removed under the job never put back; and what the job cannot write or list refused or skipped by name.
//
// Under a repo's prefix rules (DESIGN-DETAILS 8.2.10's "Under prefix rules" and its report), over a world of
// evs_prefix_test.go: a held device's job re-checkpoints the files under its prefixes in one push and leaves the rest,
// counted and never rewritten or current, in file mode and in git mode; a device the set names for every path leaves
// none; a set the device cannot read stops the job; a refusal the planner gives at the push leaves that file alone; a
// resumed job counts a left file once; a file whose newest version the rules ignore is re-checkpointed from its
// effective version; and §22.7's row is asserted only where no file was left.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
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
	// how a file is read back, nil through a fresh reader with no prefix rules
	readBack func(path string) ([]byte, error)
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
		read, err := self.read(path)
		if err != nil || !bytes.Equal(read, self.contents[path]) {
			self.t.Errorf("%s read back: %v", path, err)
		}
	}
}

// path's content as a reader of the test's world reads it.
func (self *rekeyTest) read(path string) ([]byte, error) {
	self.t.Helper()
	if self.readBack != nil {
		return self.readBack(path)
	}
	read, _, err := self.writer.read(self.t, path)
	return read, err
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

// What the job cannot list or write it does not claim: a request naming no path walks the ref from its root, which
// lists its top-level names since EVS1-M2-46 (question evs1-m2-24-root-directory-names, option 1); a git-mode ref is
// rekeyed as the REKEY shape (EVS1-M2-48); a malformed path is refused; and a repo runs one job at a time.
func TestEvsRekeyRefusesTheRootAndRekeysAGitModeRef(t *testing.T) {
	root := newRekeyTest(t)
	rootPaths := root.writeFiles("r", 3)
	root.rotate(2, GkmCauseRemove)
	progress, err := root.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: root.writer.world.repoId})
	if err != nil || progress.State != GkmRekeyStateDone || progress.RewrittenCount != uint64(len(rootPaths)) {
		t.Fatalf("a rekey from the root: %v %+v", err, progress)
	}
	root.requireRekeyed(2, rootPaths...)

	test := newRekeyTest(t)
	paths := test.writeFiles("s", 3)
	test.rotate(2, GkmCauseRemove)
	repoId := test.writer.world.repoId
	rekey := test.rekey()
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

	// a git-mode ref, from this head-mode client: rekeyed through the REKEY shape, its tree unchanged (DESIGN-DETAILS
	// 8.2.10, question keys-m2-26-rekey-git-mode-refs)
	git := newRekeyTest(t)
	git.writer.world.mode = protocol.EvsRefMode_EVS_REF_GIT
	git.writer.world.push(&evsTestChange{path: "tree.txt", content: []byte("tree")})
	git.writer.server.know("tree.txt")
	git.contents["tree.txt"] = []byte("tree")
	git.versions["tree.txt"] = 1
	git.rotate(2, GkmCauseRemove)
	posted := git.posted()
	progress, err = git.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: git.writer.world.repoId, Paths: []string{"tree.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	if progress.State != GkmRekeyStateDone || progress.RewrittenCount != 1 || len(progress.SkippedRefs) != 0 || git.posted() != posted+1 {
		t.Errorf("a git-mode ref: %+v", progress)
	}
	git.requireRekeyed(2, "tree.txt")
	commit := git.writer.world.commits[len(git.writer.world.commits)-1]
	payload, err := ParseEvsPayload(commit.built.Payload)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := EvsOpenMetadata(evsTestKeys(t, git.writer.world.repoId, 2).manifest, payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.GetGit().GetShape() != protocol.EvsGitShape_EVS_GIT_REKEY || len(metadata.GetCommits()) != 0 ||
		len(metadata.GetGit().GetNewTip()) != 0 || commit.parsed.Push.GetFlags() != 0 {
		t.Errorf("the rekey's update: %v, flags %d", metadata.GetGit(), commit.parsed.Push.GetFlags())
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
		write := &EvsPathWrite{Path: "held.txt", IfVersion: &version, Remove: content == nil}
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

// §10.16's "multi-part pushes": a rekey push whose entry versions pass one part's megabyte goes in parts and a seal,
// as any push does (§11.8), one statement committing every file of it, within the entry-write bound.
func TestEvsRekeyPushPastAPartGoesInParts(t *testing.T) {
	test := newRekeyTest(t)
	const fileCount = 100
	writes := []*EvsPathWrite{}
	paths := []string{}
	for i := 0; i < fileCount; i += 1 {
		// 12 KiB each, small enough to ride inline in its entry version, so the push's own bytes pass 1 MiB
		path := fmt.Sprintf("big/%03d.bin", i)
		content := evsTestEdited(path, 12*1024, i)
		test.writer.server.know(path)
		writes = append(writes, &EvsPathWrite{Path: path, Content: bytes.NewReader(content)})
		test.contents[path] = content
		paths = append(paths, path)
	}
	created, err := test.writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Writes: writes})
	if err != nil {
		t.Fatal(err)
	}
	for i, path := range paths {
		test.versions[path] = created.PathVersions[i]
	}
	if chain := test.writer.entry(t, paths[0]).GetChain(); len(chain) != 1 || chain[0].GetKind() != uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE) {
		t.Fatalf("the files do not ride inline: %v", chain)
	}
	test.rotate(2, GkmCauseRemove)
	commits := test.commits()
	progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: test.writer.world.repoId, Paths: []string{"big"}})
	if err != nil {
		t.Fatal(err)
	}
	if progress.RewrittenCount != fileCount || progress.PushCount != 1 {
		t.Fatalf("the progress: %+v", progress)
	}
	if got := test.entryWriteCounts(commits); len(got) != 1 || got[0] != fileCount {
		t.Fatalf("the job's pushes carried %v entry writes", got)
	}
	test.writer.world.stateLock.Lock()
	partCount := test.writer.world.commits[commits].parsed.Push.GetPartCount()
	test.writer.world.stateLock.Unlock()
	if partCount < 2 {
		t.Errorf("a push of %d inline files of 12 KiB went in %d parts", fileCount, partCount)
	}
	test.requireRekeyed(2, paths...)
}

// A rekey test over a world under prefix rules (evs_prefix_test.go). Every reader judges a push by the world's set,
// filed at position 5, which names the writing device, an admin, for every path and the world's second writer for
// agents/build alone. The job's own device asks the planner's call of a real AclEngine over a state of its own (the
// engine world of acl_prefix_test.go), in which it is an agent tagged ci, in the repo the test chooses: held holds it to
// agents/build, everywhere names it for every path, and pending and newer put in force a set it cannot read.
type rekeyPrefixTest struct {
	*rekeyTest
	prefix        *evsPrefixTest
	engineWorld   *aclTestPrefixEngineWorld
	engineRepoIds map[string]Id
	engineSets    map[string][]*AclPrefixRuleSet

	stateLock  sync.Mutex
	engineRepo string
	// the planner's calls, and every path they drew, in order
	callCount int
	asked     []string
}

// A ruled rekey test whose device asks in engineRepo. No set is filed yet: a test writes its files, then files it.
func newRekeyPrefixTest(t *testing.T, engineRepo string) *rekeyPrefixTest {
	t.Helper()
	test := newRekeyTest(t)
	engineWorld, engineRepoIds := newAclTestPrefixEngineWorld(t, true, map[string][]uint64{
		"held": {10}, "everywhere": {10}, "pending": {10, 20}, "newer": {10, 20},
	})
	held := aclTestOpenedSet(10, engineWorld.adminId, aclTestPrefixRule(engineWorld.ci, "agents/build"), aclTestPrefixRule(engineWorld.adminId, ""))
	everywhere := aclTestOpenedSet(10, engineWorld.adminId, aclTestPrefixRule(AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED), ""))
	ruled := &rekeyPrefixTest{
		rekeyTest: test, prefix: newEvsPrefixTestOn(t, test.writer.world), engineWorld: engineWorld, engineRepoIds: engineRepoIds,
		engineSets: map[string][]*AclPrefixRuleSet{
			"held":       {held},
			"everywhere": {everywhere},
			"pending":    {held, {At: 20, Signer: engineWorld.adminId, State: AclPrefixSetPending, Generation: 4}},
			"newer":      {held, {At: 20, Signer: engineWorld.adminId, State: AclPrefixSetNewer, Generation: 1}},
		},
		engineRepo: engineRepo,
	}
	test.writer.test.client.EnablePrefixRules(&EvsPrefixRulesArgs{
		Sets: func(ctx context.Context, repoId Id) ([]*AclPrefixRuleSet, error) {
			return slices.Clone(ruled.prefix.sets), nil
		},
		AllowWrite: func(write *AclPrefixWrite) AclPrefixWriteDecision {
			asked := *write
			func() {
				ruled.stateLock.Lock()
				defer ruled.stateLock.Unlock()
				ruled.callCount += 1
				asked.RepoId, asked.Sets = ruled.engineRepoIds[ruled.engineRepo], ruled.engineSets[ruled.engineRepo]
			}()
			if paths := write.Paths; paths != nil {
				asked.Paths = func(yield func(string) bool) {
					for path := range paths {
						func() {
							ruled.stateLock.Lock()
							defer ruled.stateLock.Unlock()
							ruled.asked = append(ruled.asked, path)
						}()
						if !yield(path) {
							return
						}
					}
				}
			}
			return engineWorld.engine.AllowPrefixWrite(&asked)
		},
	})
	test.readBack = ruled.readRuled
	return ruled
}

// Files the world's set, which every push after it pins, with the device's installed state at its position.
func (self *rekeyPrefixTest) file() {
	self.prefix.file(5, AclPrefixSetOpened, "agents/build")
	self.writer.world.config.setPin(5)
}

// The repo the device's planner call is asked in from here.
func (self *rekeyPrefixTest) askIn(engineRepo string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.engineRepo = engineRepo
}

// How many times the planner's call drew path.
func (self *rekeyPrefixTest) askedCount(path string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, asked := range self.asked {
		if asked == path {
			count += 1
		}
	}
	return count
}

// The planner's calls, and the paths they drew.
func (self *rekeyPrefixTest) calls() (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.callCount, len(self.asked)
}

// path's content as a reader under the world's rules reads it, a fresh client's.
func (self *rekeyPrefixTest) readRuled(path string) ([]byte, error) {
	reader := self.prefix.reader("rekey check reader")
	reader.client.args.Gkm = self.writer.gkm
	reader.client.args.Transport = &evsTestTransport{handler: self.writer.server}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	out := &bytes.Buffer{}
	_, err := reader.client.Repo(self.writer.world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: path}, out)
	return out.Bytes(), err
}

// The repo's progress record as the store holds it.
func (self *rekeyTest) storedRecord(repoId Id) string {
	self.t.Helper()
	reader, err := self.store.Open(gkmRekeyDirectory + repoId.String())
	if err != nil {
		self.t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		self.t.Fatal(err)
	}
	return string(data)
}

// A held device's job (DESIGN-DETAILS 8.2.10's report), walking the whole ref: the files under its prefix are
// re-checkpointed in one push, and the files outside it that need a write are left, counted, each read and asked once
// and never planned. They count as neither rewritten nor current and keep their keys, while a file outside already of
// the generation is current. The job ends done with its count, so §22.7's row is not asserted for the ref: the left
// files still open under generation 1. No left path is in StopReason or the record the job ends with, and a second run
// leaves the same files and sends nothing.
func TestEvsRekeyOnAHeldDeviceLeavesTheFilesOutsideItsPrefixes(t *testing.T) {
	test := newRekeyPrefixTest(t, "held")
	under := []string{"agents/build/a.txt", "agents/build/b.bin", "agents/build/c/d.txt"}
	outside := []string{"docs/readme.txt", "src/main.go", "src/x.bin"}
	test.write(under[0], 400)
	test.write(under[1], 20*1024)
	test.write(under[2], 900)
	test.write(outside[0], 500)
	test.write(outside[1], 700)
	test.write(outside[2], 24*1024)
	test.rotate(2, GkmCauseRemove)
	test.write("docs/fresh.txt", 300)
	test.file()
	repoId := test.writer.world.repoId
	commits, posted := test.commits(), test.posted()
	rekey := test.rekey()
	progress, err := rekey.Run(context.Background(), &GkmRekeyRequest{RepoId: repoId})
	if err != nil {
		t.Fatal(err)
	}
	if progress.State != GkmRekeyStateDone || progress.Generation != 2 || progress.RewrittenCount != 3 || progress.LeftCount != 3 ||
		progress.CurrentCount != 1 || progress.AbsentCount != 0 || progress.PushCount != 1 || progress.StopReason != "" {
		t.Fatalf("the progress: %+v", progress)
	}
	if got := test.entryWriteCounts(commits); len(got) != 1 || got[0] != 3 || test.posted() != posted+1 {
		t.Errorf("the job's pushes carried %v entry writes in %d statements", got, test.posted()-posted)
	}
	test.requireRekeyed(2, under...)
	test.requireUntouched(outside...)
	if chain, version := test.chain("docs/fresh.txt"); chain.KeyGeneration != 2 || version != test.versions["docs/fresh.txt"] {
		t.Errorf("the current file outside the prefix: generation %d, version %d", chain.KeyGeneration, version)
	}
	// a left file is drawn once, by the job's own ask; a file under the prefix once by it and once by the one plan of
	// its push, which no left file reached
	for _, path := range outside {
		if count := test.askedCount(path); count != 1 {
			t.Errorf("%s drawn by the planner's call %d times", path, count)
		}
	}
	for _, path := range under {
		if count := test.askedCount(path); count != 2 {
			t.Errorf("%s drawn by the planner's call %d times", path, count)
		}
	}
	stored, ok, err := rekey.Progress(repoId)
	if err != nil || !ok || stored.State != GkmRekeyStateDone || stored.LeftCount != 3 || stored.RewrittenCount != 3 || stored.CurrentCount != 1 {
		t.Errorf("the stored progress: %+v %v", stored, err)
	}
	record := test.storedRecord(repoId)
	if !strings.Contains(record, `"left_count":3`) {
		t.Errorf("the record does not hold the count: %s", record)
	}
	for _, path := range outside {
		if strings.Contains(record, path) {
			t.Errorf("the record names a left file: %s", record)
		}
	}

	again, err := rekey.Run(context.Background(), &GkmRekeyRequest{RepoId: repoId})
	if err != nil || again.State != GkmRekeyStateDone || again.LeftCount != 3 || again.CurrentCount != 4 || again.RewrittenCount != 0 ||
		again.PushCount != 0 || test.posted() != posted+1 {
		t.Errorf("a second run: %+v %v, %d statements more", again, err, test.posted()-posted-1)
	}
}

// A device the set names for every path leaves none: every file the walk needs to write is re-checkpointed, the
// planner's call allowing each before it draws a path, and §22.7's row holds for every file of the ref. And a repo
// whose rows hold no set runs as it did before them: the call is never asked, though the device would be held.
func TestEvsRekeyOnADeviceNamedForEveryPathLeavesNone(t *testing.T) {
	test := newRekeyPrefixTest(t, "everywhere")
	paths := []string{"agents/build/a.txt", "docs/readme.txt", "src/main.go", "src/x.bin"}
	for i, path := range paths {
		test.write(path, 400+i*8*1024)
	}
	test.rotate(2, GkmCauseRemove)
	test.file()
	progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: test.writer.world.repoId})
	if err != nil {
		t.Fatal(err)
	}
	if progress.State != GkmRekeyStateDone || progress.RewrittenCount != uint64(len(paths)) || progress.LeftCount != 0 || progress.CurrentCount != 0 ||
		progress.PushCount != 1 {
		t.Fatalf("the progress: %+v", progress)
	}
	if callCount, drawn := test.calls(); callCount == 0 || drawn != 0 {
		t.Errorf("the planner's call: %d calls, %d paths drawn", callCount, drawn)
	}
	// none was left: every file of the ref opens only under the current generation
	test.requireRekeyed(2, paths...)

	plain := newRekeyPrefixTest(t, "held")
	plainPaths := plain.writeFiles("src", 3)
	plain.rotate(2, GkmCauseRemove)
	progress, err = plain.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: plain.writer.world.repoId, Paths: []string{"src"}})
	if err != nil || progress.State != GkmRekeyStateDone || progress.RewrittenCount != 3 || progress.LeftCount != 0 {
		t.Fatalf("a repo with no set: %+v %v", progress, err)
	}
	if callCount, _ := plain.calls(); callCount != 0 {
		t.Errorf("a repo with no set asked the planner's call %d times", callCount)
	}
	plain.requireRekeyed(2, plainPaths...)
}

// A set this device holds pending, or one of a later release, gives the planner's call no verdict, so the job cannot
// tell what to leave: it stops with that detail before anything is sent, its StopReason naming the code and the detail
// and no path, and resumes as any stopped job once the device can read the set in force. A refusal that names no path,
// from a state that does not hold the repo, says nothing of the file either and stops the job the same way.
func TestEvsRekeyStopsAtARuleSetItCannotRead(t *testing.T) {
	test := newRekeyPrefixTest(t, "pending")
	under := []string{"agents/build/a.txt", "agents/build/b.txt"}
	outside := []string{"src/main.go"}
	for _, path := range append(slices.Clone(under), outside...) {
		test.write(path, 600)
	}
	test.rotate(2, GkmCauseRemove)
	test.file()
	repoId := test.writer.world.repoId
	posted := test.posted()
	cases := []struct {
		engineRepo string
		detail     EvsPrefixDetail
	}{
		{engineRepo: "pending", detail: EvsPrefixDetailPending},
		{engineRepo: "newer", detail: EvsPrefixDetailUpdate},
		// a repo the engine's state does not hold: refused, with no path to name
		{engineRepo: "not held", detail: EvsPrefixDetailRefused},
	}
	for _, c := range cases {
		test.askIn(c.engineRepo)
		rekey := test.rekey()
		progress, err := rekey.Run(context.Background(), &GkmRekeyRequest{RepoId: repoId})
		if evsPrefixTestDetail(err) != c.detail {
			t.Fatalf("%s: %v", c.engineRepo, err)
		}
		if progress.State != GkmRekeyStateStopped || progress.RewrittenCount != 0 || progress.LeftCount != 0 ||
			!strings.Contains(progress.StopReason, "EVS_PREFIX_RULE") || !strings.Contains(progress.StopReason, "("+string(c.detail)+")") {
			t.Errorf("%s: the progress %+v", c.engineRepo, progress)
		}
		stored, ok, err := rekey.Progress(repoId)
		if err != nil || !ok || stored.State != GkmRekeyStateStopped || stored.StopReason != progress.StopReason {
			t.Errorf("%s: the stored progress %+v %v", c.engineRepo, stored, err)
		}
		for _, path := range append(slices.Clone(under), outside...) {
			if strings.Contains(progress.StopReason, path) {
				t.Errorf("%s: StopReason names a path: %q", c.engineRepo, progress.StopReason)
			}
		}
	}
	if test.posted() != posted {
		t.Errorf("a job stopped at a set it cannot read sent %d statements", test.posted()-posted)
	}
	test.requireUntouched(append(slices.Clone(under), outside...)...)

	// the set opens on this device: the stopped job resumes and finishes, leaving what the set holds back
	test.askIn("held")
	resumed, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: repoId})
	if err != nil || resumed.State != GkmRekeyStateDone || resumed.RewrittenCount != 2 || resumed.LeftCount != 1 || resumed.PushCount != 1 {
		t.Fatalf("the resumed job: %+v %v", resumed, err)
	}
	test.requireRekeyed(2, under...)
	test.requireUntouched(outside...)
}

// A set that comes in force between the job's ask and its push: the planner refuses a path the job was allowed, and
// the job leaves that file and pushes the rest, each refusal before anything was sealed or sent, so one path outside
// the device's prefixes does not refuse the push.
func TestEvsRekeyLeavesAFileThePlannerRefusesAtThePush(t *testing.T) {
	test := newRekeyPrefixTest(t, "everywhere")
	under := []string{"agents/build/a.txt", "agents/build/b.txt"}
	outside := []string{"docs/readme.txt", "src/main.go"}
	for _, path := range append(slices.Clone(under), outside...) {
		test.write(path, 600)
	}
	test.rotate(2, GkmCauseRemove)
	test.file()
	// EnsureWritable's calls: the job's own, then one for each attempt at its push, the first after every file was read
	test.gkm.setOnEnsure(func(call int) {
		if call == 2 {
			test.askIn("held")
		}
	})
	commits, posted := test.commits(), test.posted()
	progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: test.writer.world.repoId})
	if err != nil {
		t.Fatal(err)
	}
	if progress.State != GkmRekeyStateDone || progress.RewrittenCount != 2 || progress.LeftCount != 2 || progress.CurrentCount != 0 || progress.PushCount != 1 {
		t.Fatalf("the progress: %+v", progress)
	}
	if got := test.entryWriteCounts(commits); len(got) != 1 || got[0] != 2 || test.posted() != posted+1 {
		t.Errorf("the job's pushes carried %v entry writes in %d statements", got, test.posted()-posted)
	}
	test.requireRekeyed(2, under...)
	test.requireUntouched(outside...)
}

// A kill between the record of the job's push and the record that settles the ref: the push's record already passes
// the files the walk counted after the push's last path, a left and a current one among them, so the resumed job
// counts no file twice and sends nothing (8.2.10's report: the count is stored with the position that passes the file).
func TestEvsRekeyResumedCountsALeftFileOnce(t *testing.T) {
	test := newRekeyPrefixTest(t, "held")
	under := []string{"agents/build/a.txt", "agents/build/b.txt"}
	outside := []string{"docs/readme.txt", "src/main.go"}
	for _, path := range append(slices.Clone(under), outside...) {
		test.write(path, 600)
	}
	test.rotate(2, GkmCauseRemove)
	test.write("docs/fresh.txt", 300)
	test.file()
	repoId := test.writer.world.repoId
	// the record's creates: the job's first, the one after its push, then the one settling the ref, which is killed
	test.store.failAt = 3
	progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: repoId})
	if !errors.Is(err, errRekeyTestKilled) {
		t.Fatalf("a job killed before the ref's record: %v", err)
	}
	if progress.State != GkmRekeyStateStopped || progress.RewrittenCount != 2 || progress.LeftCount != 2 || progress.CurrentCount != 1 || progress.PushCount != 1 {
		t.Fatalf("the progress at the kill: %+v", progress)
	}
	posted := test.posted()
	resumed, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: repoId})
	if err != nil || resumed.State != GkmRekeyStateDone || resumed.RewrittenCount != 2 || resumed.LeftCount != 2 || resumed.CurrentCount != 1 ||
		resumed.PushCount != 1 || test.posted() != posted {
		t.Fatalf("the resumed job: %+v %v, %d statements", resumed, err, test.posted()-posted)
	}
	test.requireRekeyed(2, under...)
	test.requireUntouched(outside...)
}

// A file whose newest version at evs the rules ignore, a breach by the world's held writer outside its prefix, is
// re-checkpointed from its effective version (DESIGN-DETAILS 16.2.5) and never from the breach: the push is held to
// the effective version's number and takes the repair form (16.2.7), one checkpoint of the effective content on evs's
// newest, which a reader under the rules then reads. The breach is of the current generation and the effective
// version is not, so a job that judged evs's newest would count the file current. A file whose newest event is a
// removal the rules ignore, named to the job, stands as this device follows it and is written again from the version
// below the removal. A path a breach created is absent as this device follows it.
func TestEvsRekeyRewritesTheEffectiveVersionUnderAnIgnoredOne(t *testing.T) {
	test := newRekeyPrefixTest(t, "everywhere")
	test.write("src/main.go", 20*1024)
	test.write("src/util.go", 900)
	test.file()
	test.rotate(2, GkmCauseRemove)
	breached := bytes.Clone(test.contents["src/main.go"])
	breached[100] ^= 0xff
	test.writer.server.know("src/main.go", "src/new.txt", "src/util.go")
	test.prefix.pushAs(test.prefix.held, &evsTestChange{path: "src/main.go", content: breached, segment: true})
	test.prefix.pushAs(test.prefix.held, &evsTestChange{path: "src", children: []string{"new.txt"}},
		&evsTestChange{path: "src/new.txt", content: []byte("planted"), segment: true})
	test.prefix.pushAs(test.prefix.held, &evsTestChange{path: "src/util.go"})
	test.versions["src/main.go"] = test.writer.entry(t, "src/main.go").GetVersion()
	if chain, _ := test.chain("src/main.go"); chain.KeyGeneration != 2 {
		t.Fatalf("the breach: key generation %d", chain.KeyGeneration)
	}
	commits := test.commits()
	progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{
		RepoId: test.writer.world.repoId, Paths: []string{"src/main.go", "src/new.txt", "src/util.go"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if progress.State != GkmRekeyStateDone || progress.RewrittenCount != 2 || progress.CurrentCount != 0 || progress.AbsentCount != 1 ||
		progress.LeftCount != 0 || progress.PushCount != 1 {
		t.Fatalf("the progress: %+v", progress)
	}
	// the two files' versions and their parent's delta, which the repair form states each row in again
	if got := test.entryWriteCounts(commits); len(got) != 1 || got[0] != 3 {
		t.Errorf("the job's pushes carried %v entry writes", got)
	}
	// one checkpoint of generation 2 over the breach, whose content is the effective version's
	test.requireRekeyed(2, "src/main.go")
	if read, err := test.read("src/main.go"); err != nil || bytes.Equal(read, breached) {
		t.Errorf("the rekeyed file reads the breach: %v", err)
	}
	// the file under the ignored removal: created again at evs, one checkpoint of generation 2 of what it held
	if chain, _ := test.chain("src/util.go"); chain.KeyGeneration != 2 || chain.RecordCount != 1 || chain.DiffCount != 0 {
		t.Errorf("the file under an ignored removal: generation %d, %d records, %d diffs", chain.KeyGeneration, chain.RecordCount, chain.DiffCount)
	}
	if read, err := test.read("src/util.go"); err != nil || !bytes.Equal(read, test.contents["src/util.go"]) {
		t.Errorf("the file under an ignored removal read back: %v", err)
	}
	if _, err := test.read("src/new.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("the breach-created path: %v", err)
	}
}

// The same on a git-mode ref (8.2.10's where row): a held device's job seals the REKEY shape for the file under its
// prefix and leaves the file outside it, counted.
func TestEvsRekeyOfAGitModeRefLeavesTheFilesOutsideAHeldDevicesPrefixes(t *testing.T) {
	test := newRekeyPrefixTest(t, "held")
	under, outside := "agents/build/t.txt", "src/u.txt"
	// a git-mode ref from its first push, whose entries carry their blobs' oids, which a REKEY seals again
	world := test.writer.world
	world.stateLock.Lock()
	world.mode = protocol.EvsRefMode_EVS_REF_GIT
	world.stateLock.Unlock()
	for path, content := range map[string][]byte{under: evsTestEdited(under, 600), outside: evsTestEdited(outside, 700)} {
		test.contents[path] = content
		test.versions[path] = 1
	}
	world.push(&evsTestChange{path: "", children: []string{"agents", "src"}}, &evsTestChange{path: "agents", children: []string{"build"}},
		&evsTestChange{path: "agents/build", children: []string{"t.txt"}}, &evsTestChange{path: under, content: test.contents[under]},
		&evsTestChange{path: "src", children: []string{"u.txt"}}, &evsTestChange{path: outside, content: test.contents[outside]})
	test.writer.server.know(under, outside)
	test.rotate(2, GkmCauseRemove)
	test.file()
	commits := test.commits()
	progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: test.writer.world.repoId, Paths: []string{under, outside}})
	if err != nil {
		t.Fatal(err)
	}
	if progress.State != GkmRekeyStateDone || progress.RewrittenCount != 1 || progress.LeftCount != 1 || progress.PushCount != 1 || len(progress.SkippedRefs) != 0 {
		t.Fatalf("the progress: %+v", progress)
	}
	if got := test.entryWriteCounts(commits); len(got) != 1 || got[0] != 1 {
		t.Fatalf("the job's pushes carried %v entry writes", got)
	}
	commit := test.writer.world.commits[len(test.writer.world.commits)-1]
	payload, err := ParseEvsPayload(commit.built.Payload)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := EvsOpenMetadata(evsTestKeys(t, test.writer.world.repoId, 2).manifest, payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.GetGit().GetShape() != protocol.EvsGitShape_EVS_GIT_REKEY {
		t.Errorf("the rekey's update: %v", metadata.GetGit())
	}
	test.requireRekeyed(2, under)
	test.requireUntouched(outside)
}

// A directory whose removal the rules ignore stands as this device follows it, and neither a listing nor the job can
// walk what it holds: named to the job, or met by its walk, it stops the job with EVS_PREFIX_RULE detail unavailable,
// as List answers it, and nothing under it is claimed as rekeyed or gone.
func TestEvsRekeyStopsAtADirectoryUnderAnIgnoredRemoval(t *testing.T) {
	test := newRekeyPrefixTest(t, "everywhere")
	test.write("docs/a.txt", 600)
	test.write("src/main.go", 600)
	test.file()
	test.rotate(2, GkmCauseRemove)
	test.writer.server.know("docs/a.txt")
	test.prefix.pushAs(test.prefix.held, &evsTestChange{path: "docs"})
	repoId := test.writer.world.repoId
	posted := test.posted()
	for _, paths := range [][]string{{"docs"}, nil} {
		progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{RepoId: repoId, RefNames: [][]byte{EvsMainRefName}, Paths: paths})
		if evsPrefixTestDetail(err) != EvsPrefixDetailUnavailable {
			t.Fatalf("paths %q: %v", paths, err)
		}
		if progress.State != GkmRekeyStateStopped || progress.AbsentCount != 0 || progress.RewrittenCount != 0 || strings.Contains(progress.StopReason, "docs") {
			t.Errorf("paths %q: the progress %+v", paths, progress)
		}
	}
	if test.posted() != posted {
		t.Errorf("a stopped job sent %d statements", test.posted()-posted)
	}
	test.requireUntouched("docs/a.txt", "src/main.go")
}

// On a git-mode ref a REKEY can only seal the standing blob again (8.2.10), so where the version standing at a path is
// one the rules ignore, a breach by the world's held writer outside its prefix, the job writes nothing over it, which
// every head reader would then show as this device's, and stops before any push. The breach is of the old generation,
// so a job that judged evs's newest version would re-seal it. A removal the rules ignore stops the job the same way,
// rather than being counted gone while the file stands as this device follows it.
func TestEvsRekeyStopsAtAnIgnoredVersionOnAGitModeRef(t *testing.T) {
	test := newRekeyPrefixTest(t, "everywhere")
	world := test.writer.world
	world.stateLock.Lock()
	world.mode = protocol.EvsRefMode_EVS_REF_GIT
	world.stateLock.Unlock()
	world.push(&evsTestChange{path: "", children: []string{"src"}}, &evsTestChange{path: "src", children: []string{"u.txt", "v.txt"}},
		&evsTestChange{path: "src/u.txt", content: evsTestEdited("src/u.txt", 600)}, &evsTestChange{path: "src/v.txt", content: evsTestEdited("src/v.txt", 700)})
	test.writer.server.know("src/u.txt", "src/v.txt")
	test.file()
	test.prefix.pushAs(test.prefix.held, &evsTestChange{path: "src/u.txt", content: []byte("planted")})
	test.prefix.pushAs(test.prefix.held, &evsTestChange{path: "src/v.txt"})
	test.rotate(2, GkmCauseRemove)
	if chain, _ := test.chain("src/u.txt"); chain.KeyGeneration != 1 {
		t.Fatalf("the breach: key generation %d", chain.KeyGeneration)
	}
	posted := test.posted()
	for _, path := range []string{"src/u.txt", "src/v.txt"} {
		progress, err := test.rekey().Run(context.Background(), &GkmRekeyRequest{
			RepoId: world.repoId, RefNames: [][]byte{EvsMainRefName}, Paths: []string{path},
		})
		if !errors.Is(err, ErrGkmRekeyIgnoredVersion) {
			t.Fatalf("%s: %v", path, err)
		}
		if progress.State != GkmRekeyStateStopped || progress.RewrittenCount != 0 || progress.AbsentCount != 0 || strings.Contains(progress.StopReason, path) {
			t.Errorf("%s: the progress %+v", path, progress)
		}
	}
	if test.posted() != posted {
		t.Errorf("a job stopped at an ignored version sent %d statements", test.posted()-posted)
	}
}
