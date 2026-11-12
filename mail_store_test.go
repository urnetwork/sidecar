// MAIL-M7-06's store seam: an in-memory mailStore with evs's path CAS, which MAIL's tests run on, and mailEvsStore
// over the evs stand-in, reading what EvsRepo wrote and writing each path held to the version its writer read
// (QD-721), with two devices' writers racing one i/ segment.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// One file of the test store.
type mailTestFile struct {
	content []byte
	version uint64
}

// A mailStore in memory with evs's path CAS: a write's paths commit together or not at all, each only while it
// stands at its IfVersion, and a path's version rises by one at each write. beforeWrite, when set, runs once with no
// lock held at the start of the next write, so a test lands a racing write between a writer's read and its write.
type mailTestStore struct {
	stateLock   sync.Mutex
	files       map[string]*mailTestFile
	beforeWrite func()
	// A write fails with this, once, before any check.
	failWrite error
	// Every write attempted, and every read.
	writeCount int
	readCount  int
}

func newMailTestStore() *mailTestStore {
	return &mailTestStore{files: map[string]*mailTestFile{}}
}

func (self *mailTestStore) Read(ctx context.Context, path string, maxByteCount int) ([]byte, uint64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readCount += 1
	file := self.files[path]
	if file == nil {
		return nil, 0, ErrEvsPathAbsent
	}
	if maxByteCount < len(file.content) {
		return nil, 0, ErrMailStoreTooLarge
	}
	return bytes.Clone(file.content), file.version, nil
}

func (self *mailTestStore) List(ctx context.Context, directory string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for path := range self.files {
		rest, ok := strings.CutPrefix(path, directory+"/")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(rest, "/")
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, ErrEvsPathAbsent
	}
	slices.Sort(names)
	return names, nil
}

func (self *mailTestStore) Write(ctx context.Context, writes []*mailStoreWrite) ([]uint64, error) {
	hook := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		hook := self.beforeWrite
		self.beforeWrite = nil
		return hook
	}()
	if hook != nil {
		hook()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writeCount += 1
	if err := self.failWrite; err != nil {
		self.failWrite = nil
		return nil, err
	}
	conflicts := []string{}
	for _, write := range writes {
		current := uint64(0)
		if file := self.files[write.Path]; file != nil {
			current = file.version
		}
		if current != write.IfVersion {
			conflicts = append(conflicts, write.Path)
		}
	}
	if 0 < len(conflicts) {
		return nil, &MailStoreConflictError{Paths: conflicts}
	}
	versions := []uint64{}
	for _, write := range writes {
		file := self.files[write.Path]
		if file == nil {
			file = &mailTestFile{}
			self.files[write.Path] = file
		}
		file.content = bytes.Clone(write.Content)
		file.version += 1
		versions = append(versions, file.version)
	}
	return versions, nil
}

// The paths that stand, sorted.
func (self *mailTestStore) paths() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Sorted(maps.Keys(self.files))
}

// A file's content and version, nil where none stands.
func (self *mailTestStore) file(path string) *mailTestFile {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if file := self.files[path]; file != nil {
		return &mailTestFile{content: bytes.Clone(file.content), version: file.version}
	}
	return nil
}

// Sets a file outright, as a writer outside the code under test would.
func (self *mailTestStore) put(path string, content []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	file := self.files[path]
	if file == nil {
		file = &mailTestFile{}
		self.files[path] = file
	}
	file.content = bytes.Clone(content)
	file.version += 1
}

// The store's own CAS, which every MAIL-M7-06 test rests on: a stale or absent-read write conflicts, naming its paths,
// and commits nothing of the push.
func TestMailTestStoreWriteIsAPathCas(t *testing.T) {
	ctx := context.Background()
	store := newMailTestStore()
	versions, err := store.Write(ctx, []*mailStoreWrite{{Path: "i/202611/0", Content: []byte("a")}, {Path: "m/202611/00/x", Content: []byte("m")}})
	if err != nil || !slices.Equal(versions, []uint64{1, 1}) {
		t.Fatalf("%v, %v", versions, err)
	}
	_, err = store.Write(ctx, []*mailStoreWrite{{Path: "i/202611/0", Content: []byte("b"), IfVersion: 1}, {Path: "m/202611/00/x", Content: []byte("n")}})
	var conflict *MailStoreConflictError
	if !errors.As(err, &conflict) || !slices.Equal(conflict.Paths, []string{"m/202611/00/x"}) || !errors.Is(err, ErrMailStoreConflict) {
		t.Fatalf("a creation over a standing path: %v", err)
	}
	if file := store.file("i/202611/0"); string(file.content) != "a" || file.version != 1 {
		t.Error("a refused push committed part of itself")
	}
	if strings.Contains(err.Error(), "202611") {
		t.Error("a conflict's error names a path")
	}
}

// A mailStore that runs beforeWrite once, at the start of its next write: a racing write landed between a writer's
// read and its write.
type mailTestRacingStore struct {
	mailStore
	stateLock   sync.Mutex
	beforeWrite func()
}

func (self *mailTestRacingStore) Write(ctx context.Context, writes []*mailStoreWrite) ([]uint64, error) {
	hook := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		hook := self.beforeWrite
		self.beforeWrite = nil
		return hook
	}()
	if hook != nil {
		hook()
	}
	return self.mailStore.Write(ctx, writes)
}

// mailEvsStore reads what EvsRepo wrote, verified, with its version, lists a directory and holds a read to its
// bound. Its write is evs's path CAS from the writer's read: a creation only of an absent path, an update only on the
// version read, a conflict naming the store's own paths and committing nothing of the push.
func TestMailEvsStoreReadsAndWritesByPathCas(t *testing.T) {
	writer := newEvsTestWriter(t)
	first := mailSegmentAppend(nil, []byte{0x0a, 0x01, 0x01})
	if _, err := writer.write(t, "i/202611/0", first); err != nil {
		t.Fatal(err)
	}
	second := mailSegmentAppend(first, []byte{0x0a, 0x01, 0x02})
	if _, err := writer.write(t, "i/202611/0", second); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.write(t, "i/202611/1", first); err != nil {
		t.Fatal(err)
	}
	device := writer.otherWriter(t, "mail store device")
	store := newMailEvsStore(device.repo, nil, nil)
	ctx := context.Background()

	content, version, err := store.Read(ctx, "i/202611/0", mailIndexSegmentReadMaxByteCount)
	if err != nil || !bytes.Equal(content, second) {
		t.Fatalf("read back %x, %v", content, err)
	}
	if version != writer.entry(t, "i/202611/0").GetVersion() || version < 2 {
		t.Errorf("version %d", version)
	}
	names, err := store.List(ctx, "i/202611")
	if slices.Sort(names); err != nil || !slices.Equal(names, []string{"0", "1"}) {
		t.Errorf("listed %v, %v", names, err)
	}
	if _, _, err := store.Read(ctx, "i/202611/0", len(second)-1); !errors.Is(err, ErrMailStoreTooLarge) {
		t.Errorf("past the bound: %v", err)
	}
	if _, _, err := store.Read(ctx, "i/202611/9", mailIndexSegmentReadMaxByteCount); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("an absent segment: %v", err)
	}

	// a creation of an absent path, and an update on the version read, in one push
	writer.server.know("i/202611/2", "m/202611/00/x")
	third := mailSegmentAppend(second, []byte{0x0a, 0x01, 0x03})
	versions, err := store.Write(ctx, []*mailStoreWrite{{Path: "i/202611/2", Content: first}, {Path: "i/202611/0", Content: third, IfVersion: version}})
	if err != nil || len(versions) != 2 || versions[1] != version+1 {
		t.Fatalf("a write: %v, %v", versions, err)
	}
	if content, readVersion, err := store.Read(ctx, "i/202611/2", mailIndexSegmentReadMaxByteCount); err != nil || !bytes.Equal(content, first) || readVersion != versions[0] {
		t.Errorf("the created segment: %x at %d, %v", content, readVersion, err)
	}
	if content, readVersion, err := store.Read(ctx, "i/202611/0", mailIndexSegmentReadMaxByteCount); err != nil || !bytes.Equal(content, third) || readVersion != versions[1] {
		t.Errorf("the updated segment: %x at %d, %v", content, readVersion, err)
	}

	// a creation over a standing path and an update on a version since replaced conflict, naming their paths, and
	// the push's third path is not created
	posted, uploads := writer.server.sentCounts()
	_, err = store.Write(ctx, []*mailStoreWrite{
		{Path: "m/202611/00/x", Content: []byte("message")},
		{Path: "i/202611/2", Content: second},
		{Path: "i/202611/0", Content: second, IfVersion: version},
	})
	var conflict *MailStoreConflictError
	if !errors.As(err, &conflict) || !slices.Equal(conflict.Paths, []string{"i/202611/2", "i/202611/0"}) || !errors.Is(err, ErrMailStoreConflict) {
		t.Fatalf("a stale write: %v", err)
	}
	if strings.Contains(err.Error(), "202611") {
		t.Error("a conflict's error names a path")
	}
	if nowPosted, nowUploads := writer.server.sentCounts(); nowPosted != posted || nowUploads != uploads {
		t.Error("a refused write sent something")
	}
	if _, _, err := store.Read(ctx, "m/202611/00/x", 64); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("a refused push committed part of itself: %v", err)
	}
	if content, _, err := store.Read(ctx, "i/202611/0", mailIndexSegmentReadMaxByteCount); err != nil || !bytes.Equal(content, third) {
		t.Errorf("a refused push changed a segment: %x, %v", content, err)
	}
}

// Two devices' writers racing one i/ segment keep both entries (§15.7's "a racing i/ write gets a path 409 and
// re-reads"): the other's append lands between this writer's read and its write, at the segment's creation and then
// on a standing segment, and then between its plan and its push, where evs's own 5g refuses it; each time the writer
// gets a conflict on its segment, reads again and appends to what the other committed.
func TestMailEvsStoreRacingAppendsKeepBothEntries(t *testing.T) {
	phone := newEvsTestWriter(t)
	laptop := phone.otherWriter(t, "mail laptop")
	phone.server.know("i/202611/0")
	phoneStore := &mailTestRacingStore{mailStore: newMailEvsStore(phone.repo, nil, nil)}
	phoneWriter := NewMailIndexWriter(phoneStore, DefaultMailStoreSettings())
	laptopWriter := NewMailIndexWriter(newMailEvsStore(laptop.repo, nil, nil), DefaultMailStoreSettings())
	ctx := context.Background()
	day := testMailDayMillis(202611, 5)
	race := func(n uint64) func() {
		return func() {
			if _, err := laptopWriter.Append(ctx, testMailIndexEntry(n, day)); err != nil {
				t.Errorf("the racing append of %d: %v", n, err)
			}
		}
	}

	// both read no segment and create the month's first: the phone's creation meets the laptop's
	phoneStore.beforeWrite = race(2)
	appended, err := phoneWriter.Append(ctx, testMailIndexEntry(1, day))
	if err != nil || appended.Path != "i/202611/0" || appended.Present {
		t.Fatalf("an append racing the segment's creation: %+v %v", appended, err)
	}
	// both read the same standing version
	phoneStore.beforeWrite = race(4)
	if _, err := phoneWriter.Append(ctx, testMailIndexEntry(3, day)); err != nil {
		t.Fatalf("an append racing an append: %v", err)
	}
	// the laptop commits after the phone's plan read the segment and before its push arrives
	phone.server.raceNextPush(race(6))
	appended, err = phoneWriter.Append(ctx, testMailIndexEntry(5, day))
	if err != nil {
		t.Fatalf("an append racing a commit: %v", err)
	}

	segment, version, err := newMailEvsStore(laptop.repo, nil, nil).Read(ctx, "i/202611/0", mailIndexSegmentReadMaxByteCount)
	if err != nil || version != appended.Version {
		t.Fatalf("the segment at %d, the last append's %d: %v", version, appended.Version, err)
	}
	want := []Id{testMailId(2), testMailId(1), testMailId(4), testMailId(3), testMailId(6), testMailId(5)}
	if ids := testMailSegmentIds(t, segment); !slices.Equal(ids, want) {
		t.Errorf("the segment holds %d entries %v, not both writers' six", len(ids), ids)
	}
	if names, err := phoneStore.List(ctx, "i/202611"); err != nil || !slices.Equal(names, []string{"0"}) {
		t.Errorf("the month's segments: %v %v", names, err)
	}
}

// evs's 409 on a parent directory alone, which another device's creation in that directory raced, is no conflict on
// a path the writer read: the store plans the write again, still create-only, and both files stand. With no retry
// left the store gives evs's answer back, which is not ErrMailStoreConflict, since no path of the write moved.
func TestMailEvsStorePlansAgainOverARacedDirectory(t *testing.T) {
	phone := newEvsTestWriter(t)
	phone.seed(t)
	laptop := phone.otherWriter(t, "mail laptop")
	phone.server.know("m/202611/00/a", "m/202611/00/b", "m/202611/01/a", "m/202611/01/b")
	ctx := context.Background()
	laptopStore := newMailEvsStore(laptop.repo, nil, nil)
	race := func(path string) func() {
		return func() {
			if _, err := laptopStore.Write(ctx, []*mailStoreWrite{{Path: path, Content: []byte("theirs")}}); err != nil {
				t.Errorf("the racing creation: %v", err)
			}
		}
	}

	phone.server.raceNextPush(race("m/202611/00/b"))
	phoneStore := newMailEvsStore(phone.repo, nil, nil)
	if _, err := phoneStore.Write(ctx, []*mailStoreWrite{{Path: "m/202611/00/a", Content: []byte("mine")}}); err != nil {
		t.Fatalf("a creation beside a racing one: %v", err)
	}
	for path, want := range map[string]string{"m/202611/00/a": "mine", "m/202611/00/b": "theirs"} {
		if content, _, err := phoneStore.Read(ctx, path, 64); err != nil || string(content) != want {
			t.Errorf("%s reads %q %v", path, content, err)
		}
	}

	settings := DefaultMailStoreSettings()
	settings.DirectoryRetryCount = 0
	phone.server.raceNextPush(race("m/202611/01/b"))
	_, err := newMailEvsStore(phone.repo, nil, settings).Write(ctx, []*mailStoreWrite{{Path: "m/202611/01/a", Content: []byte("mine")}})
	if errors.Is(err, ErrMailStoreConflict) || !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT) {
		t.Fatalf("a raced directory with no retry left: %v", err)
	}
	if _, _, err := phoneStore.Read(ctx, "m/202611/01/a", 64); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("the refused creation: %v", err)
	}
}
