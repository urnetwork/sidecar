// MAIL-M7-06's store seam: an in-memory mailStore with evs's path CAS, which MAIL's tests run on, and mailEvsStore
// over the evs stand-in, reading what EvsRepo wrote and holding its own writes closed.

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

// mailEvsStore reads what EvsRepo wrote, verified, with its version, lists a directory, holds a read to its bound,
// and refuses every write, closed, until evs takes a writer's version (question mail-m7-06-evs-path-precondition).
func TestMailEvsStoreReadsAndHoldsWrites(t *testing.T) {
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
	reader := writer.world.reader(t, evsTestId("mail store reader"))
	reader.client.args.Gkm = writer.gkm
	reader.client.args.Transport = &evsTestTransport{handler: writer.server}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	store := newMailEvsStore(reader.client.Repo(writer.world.repoId), nil)
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
	if _, err := store.Write(ctx, []*mailStoreWrite{{Path: "i/202611/2", Content: first}}); !errors.Is(err, ErrMailStoreWriteHeld) {
		t.Errorf("a write: %v", err)
	}
	if _, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "i/202611/2"}, &bytes.Buffer{}); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("the held write reached evs: %v", err)
	}
	// the index writer meets the same refusal rather than appending
	if _, err := NewMailIndexWriter(store, DefaultMailStoreSettings()).Append(ctx, testMailIndexEntry(1, testMailDayMillis(202611, 5))); !errors.Is(err, ErrMailStoreWriteHeld) {
		t.Errorf("an append: %v", err)
	}
}
