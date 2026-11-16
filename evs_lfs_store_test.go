//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The git-lfs store on the client's stand-in evs (EVS2-M10-24): put, touch and remove; a second creation of one object
// read as success; a touch citing the stored content with no upload, by the upload counter, so content is stored once
// across touches; a touch racing a removal at path-level CAS, one winning; a locked repo writing versioning 0; a small
// object uploaded, never staged; an object past 2 GiB, or not its oid, refused before anything is sent; and ur/lfs
// taking the store's writes alone.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A writer whose client is in the format2 gate and reads format 2, and its store over the world's ur/lfs.
type evsTestLfsStore struct {
	writer *evsTestWriter
	world  *evsTestWorld
	store  *EvsLfsStore
}

func newEvsTestLfsStore(t *testing.T) *evsTestLfsStore {
	writer := newEvsTestWriter(t)
	writer.server.format2 = true
	writer.test.client.SetFormat2Source(func() bool { return true })
	writer.test.client.EnableFormat2Reader()
	world := writer.world.otherRef(EvsLfsRefName)
	return &evsTestLfsStore{writer: writer, world: world, store: NewEvsLfsStore(writer.repo)}
}

// An object's bytes and oid.
func evsTestLfsObject(label string, byteCount int) ([]byte, EvsLfsOid) {
	content := evsTestContent(label, byteCount)
	return content, EvsLfsOid(sha256.Sum256(content))
}

// Stores content under oid, registering its path with the stand-in.
func (self *evsTestLfsStore) put(t *testing.T, oid EvsLfsOid, content []byte) (*EvsLfsObject, error) {
	t.Helper()
	self.writer.server.know(EvsLfsPath(oid))
	return self.store.Put(context.Background(), oid, int64(len(content)), bytes.NewReader(content))
}

// The newest committed entry version of oid's path on ur/lfs.
func (self *evsTestLfsStore) entry(t *testing.T, oid EvsLfsOid) *protocol.EvsEntryVersion {
	t.Helper()
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	state := self.world.paths[EvsLfsPath(oid)]
	if state == nil || state.removal != nil {
		t.Fatalf("%s does not stand", oid)
	}
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(state.versions[state.newest].entryBytes, entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

// The stand-in's upload count.
func (self *evsTestLfsStore) uploads() int {
	self.writer.server.stateLock.Lock()
	defer self.writer.server.stateLock.Unlock()
	return len(self.writer.server.uploads)
}

// Put, Get, Touch and RemoveMany: a creation of versioning 1 uploaded once and never staged, read back by its oid; two
// touches citing that one upload; then the removal, after which Get names the object as pruned.
func TestEvsLfsStorePutTouchRemove(t *testing.T) {
	lfs := newEvsTestLfsStore(t)
	ctx := context.Background()
	content, oid := evsTestLfsObject("lfs object", 3000)
	object, err := lfs.put(t, oid, content)
	if err != nil {
		t.Fatal(err)
	}
	if !object.Present() || object.Version != 1 {
		t.Fatalf("put %+v", object)
	}
	entry := lfs.entry(t, oid)
	if entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS) || len(entry.GetChain()) != 1 ||
		entry.GetChain()[0].GetStaged() || entry.GetChain()[0].GetKind() != uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT) {
		t.Fatalf("the creation's entry %v", entry)
	}
	stored := entry.GetChain()[0].GetId()
	uploads := lfs.uploads()
	if uploads != 1 {
		t.Fatalf("a small object took %d uploads, want 1 and no staging", uploads)
	}
	out := &bytes.Buffer{}
	if _, err := lfs.store.Get(ctx, oid, out); err != nil || !bytes.Equal(out.Bytes(), content) {
		t.Fatalf("get: %v", err)
	}
	for touch := 0; touch < 2; touch += 1 {
		newest, err := lfs.store.Newest(ctx, []EvsLfsOid{oid}, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lfs.store.Touch(ctx, newest); err != nil {
			t.Fatal(err)
		}
		touched := lfs.entry(t, oid)
		if touched.GetVersion() != uint64(2+touch) || len(touched.GetChain()) != 1 || !bytes.Equal(touched.GetChain()[0].GetId(), stored) {
			t.Fatalf("touch %d: entry %v", touch, touched)
		}
	}
	if lfs.uploads() != uploads {
		t.Fatalf("a touch uploaded: %d uploads", lfs.uploads())
	}
	out.Reset()
	if _, err := lfs.store.Get(ctx, oid, out); err != nil || !bytes.Equal(out.Bytes(), content) {
		t.Fatalf("get after touches: %v", err)
	}
	newest, err := lfs.store.Newest(ctx, []EvsLfsOid{oid}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lfs.store.RemoveMany(ctx, newest); err != nil {
		t.Fatal(err)
	}
	removed, err := lfs.store.Newest(ctx, []EvsLfsOid{oid}, true)
	if err != nil || removed[0].Present() || !removed[0].Removed {
		t.Fatalf("after the removal: %+v %v", removed, err)
	}
	var missing *EvsLfsMissingError
	if _, err := lfs.store.Get(ctx, oid, &bytes.Buffer{}); !errors.As(err, &missing) || missing.RemovedAt.IsZero() {
		t.Fatalf("a removed object read: %v", err)
	}
}

// A second creation of a stored object, by a writer that read it absent, is read as success.
func TestEvsLfsStoreSecondCreationSucceeds(t *testing.T) {
	lfs := newEvsTestLfsStore(t)
	content, oid := evsTestLfsObject("shared object", 500)
	if _, err := lfs.put(t, oid, content); err != nil {
		t.Fatal(err)
	}
	// another writer, which never read the object
	other := NewEvsLfsStore(lfs.writer.repo)
	object, err := other.Put(context.Background(), oid, int64(len(content)), bytes.NewReader(content))
	if err != nil || !object.Present() || object.Version != 1 {
		t.Fatalf("the second creation: %+v %v", object, err)
	}
	if lfs.uploads() != 1 {
		t.Fatalf("the second creation uploaded: %d", lfs.uploads())
	}
}

// A touch and a removal held to one version: whichever lands first wins, and the other gets path-level CAS's conflict
// and writes nothing.
func TestEvsLfsStoreTouchRacesRemoval(t *testing.T) {
	lfs := newEvsTestLfsStore(t)
	ctx := context.Background()
	content, oid := evsTestLfsObject("raced object", 800)
	object, err := lfs.put(t, oid, content)
	if err != nil {
		t.Fatal(err)
	}
	read := *object
	if _, err := lfs.store.RemoveMany(ctx, []*EvsLfsObject{&read}); err != nil {
		t.Fatal(err)
	}
	var conflict *EvsPathConflictError
	if _, err := lfs.store.Touch(ctx, []*EvsLfsObject{object}); !errors.As(err, &conflict) {
		t.Fatalf("a touch over a removal it did not read: %v", err)
	}
	// the reverse: a put again, a touch, then the prune's removal of the version it read before the touch
	again, err := lfs.put(t, oid, content)
	if err != nil {
		t.Fatal(err)
	}
	pruneRead := *again
	if _, err := lfs.store.Touch(ctx, []*EvsLfsObject{again}); err != nil {
		t.Fatal(err)
	}
	if _, err := lfs.store.RemoveMany(ctx, []*EvsLfsObject{&pruneRead}); !errors.As(err, &conflict) {
		t.Fatalf("a removal of a version a touch replaced: %v", err)
	}
	if newest, err := lfs.store.Newest(ctx, []EvsLfsOid{oid}, true); err != nil || !newest[0].Present() {
		t.Fatalf("the touched object: %+v %v", newest, err)
	}
}

// In a locked repo the store writes versioning 0, so nothing it writes is purged.
func TestEvsLfsStoreLockedRepoWritesVersioningZero(t *testing.T) {
	lfs := newEvsTestLfsStore(t)
	lfs.writer.world.config.stateLock.Lock()
	repo := proto.Clone(lfs.writer.world.config.repo).(*protocol.AclRepo)
	repo.Lock = protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED
	lfs.writer.world.config.repo = repo
	lfs.writer.world.config.stateLock.Unlock()
	content, oid := evsTestLfsObject("locked object", 600)
	if _, err := lfs.put(t, oid, content); err != nil {
		t.Fatal(err)
	}
	if entry := lfs.entry(t, oid); entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
		t.Fatalf("a locked repo's creation wrote versioning %d", entry.GetVersioning())
	}
}

// An object past 2 GiB is refused by name, and one whose bytes are not its oid, before anything is read or sent.
func TestEvsLfsStoreRefusesBeforeSending(t *testing.T) {
	lfs := newEvsTestLfsStore(t)
	_, oid := evsTestLfsObject("huge", 1)
	var tooLarge *EvsLfsTooLargeError
	_, err := lfs.store.Put(context.Background(), oid, 2*1024*1024*1024+1, evsTestUnreadable{t: t})
	if !errors.As(err, &tooLarge) || !errors.Is(err, ErrEvsFileTooLarge) || tooLarge.Oid != oid {
		t.Fatalf("an object past 2 GiB: %v", err)
	}
	content, _ := evsTestLfsObject("bytes", 100)
	if _, err := lfs.put(t, oid, content); !errors.Is(err, ErrEvsLfsObjectInvalid) {
		t.Fatalf("bytes that are not their oid: %v", err)
	}
	if _, realOid := evsTestLfsObject("bytes", 100); true {
		if _, err := lfs.put(t, realOid, content[:99]); !errors.Is(err, ErrEvsLfsObjectInvalid) {
			t.Fatalf("a stream shorter than its size: %v", err)
		}
	}
	if lfs.uploads() != 0 || len(lfs.writer.server.postedStatements) != 0 {
		t.Fatal("a refused object reached evs")
	}
}

// ur/lfs takes the store's writes alone, and the store writes nowhere else.
func TestEvsLfsStoreIsTheOnlyWriterOfItsRef(t *testing.T) {
	lfs := newEvsTestLfsStore(t)
	ctx := context.Background()
	content, oid := evsTestLfsObject("plain", 10)
	lfs.writer.server.know(EvsLfsPath(oid))
	_, err := lfs.writer.repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: EvsLfsRefName, Writes: []*EvsPathWrite{{Path: EvsLfsPath(oid), Content: bytes.NewReader(content)}}})
	if !errors.Is(err, ErrEvsReservedPath) {
		t.Fatalf("a plain write on ur/lfs: %v", err)
	}
	_, err = lfs.writer.repo.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{{Path: "x", Content: bytes.NewReader(content), Options: evsLfsWriteOptions()}}})
	if !errors.Is(err, ErrEvsReservedPath) {
		t.Fatalf("the store's write on main: %v", err)
	}
	version := uint64(1)
	_, err = lfs.writer.repo.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{{Path: "x", Touch: true, IfVersion: &version}}})
	if !errors.Is(err, ErrEvsReservedPath) {
		t.Fatalf("a touch outside the store: %v", err)
	}
}

// A reader that fails the test if read.
type evsTestUnreadable struct {
	t *testing.T
}

func (self evsTestUnreadable) Read(p []byte) (int, error) {
	self.t.Error("a refused object was read")
	return 0, errors.New("read")
}
