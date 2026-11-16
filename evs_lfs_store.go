//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The git-lfs store (§11.11's store row; R-EVS-20, D-EVS-41, I-EVS-10, FS-73; EVS2-M10-24): one per repo, the shared
// file-mode ref ur/lfs, each object at <oid[0:2]>/<oid[2:4]>/<oid>, its names sealed and tokenized as any path's. The
// store is ur/lfs's only writer, through EvsWriteOptions.Reserved (EvsReservedLfs), and nothing else writes there: the
// planner refuses any other write on the ref and the store's write off it.
//
//	Put         the stream's SHA-256 checked against the oid as it spills, then a creation, versioning 1, or 0 in a
//	            locked repo (EvsVersioningFor's reserved and lock rows); a 409 means another writer stored it, which is
//	            success. Never staged, whatever the object's size, so a touch can always cite it
//	            (plan-EVS2-small-readings#8). An object past LfsObjectMaxByteCount (2 GiB, plan-EVS2-file-cap) is
//	            refused by name before anything is read
//	Get         a head read of the object's path, its bytes hashed against the oid as they stream; an object the store
//	            does not hold, or whose removal stands, answers *EvsLfsMissingError, naming when its prune committed
//	Touch       a new version of each object citing its stored content, no upload (EvsPathWrite.Touch), each naming
//	            the version read, all in one push, parts as the sender needs; a racing removal or touch loses or wins
//	            at path-level CAS, the loser getting the *EvsPathConflictError
//	Newest      each object's newest version by head reads of LfsHeadReadPathCount (64) paths a request, kept in a
//	            bounded cache that every Put, Touch and RemoveMany also fills
//	RemoveMany  one push removing each object, each naming its version, so a concurrent touch wins at path-level CAS;
//	            the purge deletes the content a minute after it commits (§11.13)
//
// A creation under a due path epoch waits as any general-repo creation does, ErrEvsPathEpochDue reaching the caller
// as retryable once the sender's waits end. Export skips ur/lfs (evs_export.go) and a DROP is refused on it
// (evs_drop_lineage.go by name, evs by versioning 1). A path or an oid with its path is never logged (I-13).
//
// Desktop legs only. Safe for concurrent use.

package sidecar

import (
	"container/list"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// An object's bytes are not its oid: the stream's SHA-256 or size differs from what git-lfs named.
	ErrEvsLfsObjectInvalid = errors.New("evs: a git-lfs object's bytes are not its oid")
	// An object the store does not hold: never stored, or its removal stands.
	ErrEvsLfsObjectMissing = errors.New("evs: a git-lfs object the store does not hold")
)

// An object past the store's bound, by name: ErrEvsFileTooLarge (EVS_FILE_TOO_LARGE, plan-EVS2-file-cap).
type EvsLfsTooLargeError struct {
	Oid  EvsLfsOid
	Size int64
}

// The oid and size, never a path.
func (self *EvsLfsTooLargeError) Error() string {
	return fmt.Sprintf("%v: git-lfs object %s is %d bytes", ErrEvsFileTooLarge, self.Oid, self.Size)
}

// ErrEvsFileTooLarge.
func (self *EvsLfsTooLargeError) Unwrap() error {
	return ErrEvsFileTooLarge
}

// An object the store does not hold, and when its prune committed if one did.
type EvsLfsMissingError struct {
	Oid EvsLfsOid
	// zero when the store never held it
	RemovedAt time.Time
}

// The oid and the prune's time, never a path.
func (self *EvsLfsMissingError) Error() string {
	if self.RemovedAt.IsZero() {
		return fmt.Sprintf("%v: %s was never stored", ErrEvsLfsObjectMissing, self.Oid)
	}
	return fmt.Sprintf("%v: %s was pruned at %s", ErrEvsLfsObjectMissing, self.Oid, self.RemovedAt.UTC().Format(time.RFC3339))
}

// ErrEvsLfsObjectMissing.
func (self *EvsLfsMissingError) Unwrap() error {
	return ErrEvsLfsObjectMissing
}

// An object's newest version on ur/lfs, as the store read or wrote it.
type EvsLfsObject struct {
	Oid EvsLfsOid
	// The newest version's path version: a creation's or a touch's, or the removal's. 0 for an object the store never
	// held.
	Version uint64
	// When the newest version's push was signed: its last upload or touch, or its removal.
	SignedAt time.Time
	// The object's removal stands: it was pruned at SignedAt.
	Removed bool
}

// Whether the store holds the object.
func (self *EvsLfsObject) Present() bool {
	return self.Version != 0 && !self.Removed
}

// An object's path on ur/lfs: <oid[0:2]>/<oid[2:4]>/<oid>, in lowercase hex.
func EvsLfsPath(oid EvsLfsOid) string {
	text := oid.String()
	return text[0:2] + "/" + text[2:4] + "/" + text
}

// One repo's git-lfs store.
type EvsLfsStore struct {
	repo     *EvsRepo
	settings *EvsSettings
	clock    Clock

	stateLock sync.Mutex
	// the newest versions read or written, by oid, the most recently used at the front, LfsNewestCacheCount at most
	cached map[EvsLfsOid]*list.Element
	order  *list.List
}

// The store of repo.
func NewEvsLfsStore(repo *EvsRepo) *EvsLfsStore {
	return &EvsLfsStore{
		repo: repo, settings: repo.client.settings, clock: repo.client.clock,
		cached: map[EvsLfsOid]*list.Element{}, order: list.New(),
	}
}

// The store's write options: the reserved writer, whose versioning EvsVersioningFor fixes.
func evsLfsWriteOptions() *EvsWriteOptions {
	return &EvsWriteOptions{Reserved: EvsReservedLfs}
}

// Stores an object of size bytes read from content: see the file header. A 409 answers the newest version another
// writer stored.
func (self *EvsLfsStore) Put(ctx context.Context, oid EvsLfsOid, size int64, content io.Reader) (*EvsLfsObject, error) {
	if size < 0 || self.settings.LfsObjectMaxByteCount < size {
		return nil, &EvsLfsTooLargeError{Oid: oid, Size: size}
	}
	spill := newEvsSpill(self.repo.client.args.Store, self.settings.DeltaBaseMemoryByteCount)
	defer spill.close()
	digest := sha256.New()
	// one byte past size shows a stream longer than git-lfs said
	copied, err := io.Copy(io.MultiWriter(spill, digest), io.LimitReader(content, size+1))
	if err != nil {
		return nil, err
	}
	if copied != size || EvsLfsOid(digest.Sum(nil)) != oid {
		return nil, fmt.Errorf("%w: %s", ErrEvsLfsObjectInvalid, oid)
	}
	zero := uint64(0)
	write := &EvsPathWrite{Path: EvsLfsPath(oid), Content: spill, IfVersion: &zero, Options: evsLfsWriteOptions()}
	written, err := self.repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: EvsLfsRefName, Writes: []*EvsPathWrite{write}})
	var conflict *EvsPathConflictError
	switch {
	case errors.As(err, &conflict):
		// another writer stored it first: the store holds it, which is all a put asks
		objects, err := self.newest(ctx, []EvsLfsOid{oid}, true)
		if err != nil {
			return nil, err
		}
		return objects[0], nil
	case err != nil:
		return nil, err
	}
	object := &EvsLfsObject{Oid: oid, Version: written.PathVersions[0], SignedAt: self.clock.Now()}
	self.keep(object)
	return object, nil
}

// Streams an object's bytes to out, checked against its oid as they pass: see the file header. out may hold the bytes
// of an object that then fails its check, which the caller drops.
func (self *EvsLfsStore) Get(ctx context.Context, oid EvsLfsOid, out io.Writer) (*EvsLfsObject, error) {
	digest := sha256.New()
	_, err := self.repo.ReadHead(ctx, &EvsReadArgs{RefName: EvsLfsRefName, Path: EvsLfsPath(oid)}, io.MultiWriter(out, digest))
	if errors.Is(err, ErrEvsPathAbsent) {
		objects, err := self.newest(ctx, []EvsLfsOid{oid}, true)
		if err != nil {
			return nil, err
		}
		missing := &EvsLfsMissingError{Oid: oid}
		if objects[0].Removed {
			missing.RemovedAt = objects[0].SignedAt
		}
		return objects[0], missing
	}
	if err != nil {
		return nil, err
	}
	if EvsLfsOid(digest.Sum(nil)) != oid {
		return nil, fmt.Errorf("%w: %s read back as other bytes", ErrEvsLfsObjectInvalid, oid)
	}
	objects, err := self.newest(ctx, []EvsLfsOid{oid}, false)
	if err != nil {
		return nil, err
	}
	return objects[0], nil
}

// Writes a new version of each object, citing its stored content with no upload, each held to the version given: see
// the file header. All go in one push; a version that moved answers the push's *EvsPathConflictError and writes
// nothing.
func (self *EvsLfsStore) Touch(ctx context.Context, objects []*EvsLfsObject) (*EvsWritePathsResult, error) {
	if len(objects) == 0 {
		return &EvsWritePathsResult{}, nil
	}
	writes := make([]*EvsPathWrite, 0, len(objects))
	for _, object := range objects {
		if !object.Present() {
			return nil, &EvsLfsMissingError{Oid: object.Oid, RemovedAt: object.removedAt()}
		}
		version := object.Version
		writes = append(writes, &EvsPathWrite{Path: EvsLfsPath(object.Oid), Touch: true, IfVersion: &version, Options: evsLfsWriteOptions()})
	}
	written, err := self.repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: EvsLfsRefName, Writes: writes})
	if err != nil {
		self.forget(objects)
		return nil, err
	}
	now := self.clock.Now()
	for i, object := range objects {
		self.keep(&EvsLfsObject{Oid: object.Oid, Version: written.PathVersions[i], SignedAt: now})
	}
	return written, nil
}

// Removes each object in one push, each held to its version: see the file header.
func (self *EvsLfsStore) RemoveMany(ctx context.Context, objects []*EvsLfsObject) (*EvsWritePathsResult, error) {
	if len(objects) == 0 {
		return &EvsWritePathsResult{}, nil
	}
	writes := make([]*EvsPathWrite, 0, len(objects))
	for _, object := range objects {
		if !object.Present() {
			return nil, &EvsLfsMissingError{Oid: object.Oid, RemovedAt: object.removedAt()}
		}
		version := object.Version
		writes = append(writes, &EvsPathWrite{Path: EvsLfsPath(object.Oid), Remove: true, IfVersion: &version, Options: evsLfsWriteOptions()})
	}
	written, err := self.repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: EvsLfsRefName, Writes: writes})
	if err != nil {
		self.forget(objects)
		return nil, err
	}
	now := self.clock.Now()
	for i, object := range objects {
		self.keep(&EvsLfsObject{Oid: object.Oid, Version: written.PathVersions[i] + 1, SignedAt: now, Removed: true})
	}
	return written, nil
}

// When a removed object's prune committed, zero for one present or never stored.
func (self *EvsLfsObject) removedAt() time.Time {
	if self.Removed {
		return self.SignedAt
	}
	return time.Time{}
}

// Each object's newest version, in oids' order: the cache's where it holds one and fresh is false, else head reads of
// LfsHeadReadPathCount paths a request.
func (self *EvsLfsStore) Newest(ctx context.Context, oids []EvsLfsOid, fresh bool) ([]*EvsLfsObject, error) {
	return self.newest(ctx, oids, fresh)
}

// Newest.
func (self *EvsLfsStore) newest(ctx context.Context, oids []EvsLfsOid, fresh bool) ([]*EvsLfsObject, error) {
	found := make([]*EvsLfsObject, len(oids))
	asked := []int{}
	for i, oid := range oids {
		if !fresh {
			if object, ok := self.lookup(oid); ok {
				found[i] = object
				continue
			}
		}
		asked = append(asked, i)
	}
	refId, err := self.repo.resolveRefId(ctx, EvsLfsRefName, nil)
	if err != nil {
		return nil, err
	}
	batch := max(1, self.settings.LfsHeadReadPathCount)
	for start := 0; start < len(asked); start += batch {
		indexes := asked[start:min(start+batch, len(asked))]
		paths := make([]string, 0, len(indexes))
		for _, i := range indexes {
			paths = append(paths, EvsLfsPath(oids[i]))
		}
		result, err := self.repo.read(ctx, refId, paths, 0, fresh)
		if err != nil {
			return nil, err
		}
		for j, i := range indexes {
			object := evsLfsObjectOf(oids[i], result.replies[j])
			self.keep(object)
			found[i] = object
		}
	}
	return found, nil
}

// What a verified head read shows of an object's path.
func evsLfsObjectOf(oid EvsLfsOid, verified *EvsVerifiedPath) *EvsLfsObject {
	object := &EvsLfsObject{Oid: oid}
	switch {
	case verified == nil || verified.Absent || verified.Ignored:
	case verified.Entry != nil && verified.Entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE):
		object.Version = verified.Entry.GetVersion()
		object.SignedAt = time.UnixMilli(verified.Statement.Push.GetTimeMs())
	case verified.Removal != nil:
		object.Version = verified.Removal.GetPathVersion()
		object.Removed = true
		object.SignedAt = time.UnixMilli(verified.Statement.Push.GetTimeMs())
	}
	return object
}

// The cache's entry for oid, moved to the front.
func (self *EvsLfsStore) lookup(oid EvsLfsOid) (*EvsLfsObject, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	element, ok := self.cached[oid]
	if !ok {
		return nil, false
	}
	self.order.MoveToFront(element)
	object := *element.Value.(*EvsLfsObject)
	return &object, true
}

// Keeps object as its oid's newest, least recently used out past the bound.
func (self *EvsLfsStore) keep(object *EvsLfsObject) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kept := *object
	if element, ok := self.cached[object.Oid]; ok {
		element.Value = &kept
		self.order.MoveToFront(element)
		return
	}
	self.cached[object.Oid] = self.order.PushFront(&kept)
	for self.settings.LfsNewestCacheCount < self.order.Len() {
		oldest := self.order.Back()
		self.order.Remove(oldest)
		delete(self.cached, oldest.Value.(*EvsLfsObject).Oid)
	}
}

// Drops what the cache holds of objects, after a write whose outcome says they moved or may have.
func (self *EvsLfsStore) forget(objects []*EvsLfsObject) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, object := range objects {
		if element, ok := self.cached[object.Oid]; ok {
			self.order.Remove(element)
			delete(self.cached, object.Oid)
		}
	}
}
