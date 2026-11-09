// A fake of indexRefStore (SEARCH-M10-08): one ref's index files held in memory, shared by every writer's handle, so
// the index's tasks test merges, roll-ups, erasures and races before format 2's writer lands. It models what the index
// relies on at evs: each path's CAS, with a write's version its base's plus one and a creation's past the push's base
// and any removal; the head's index_epoch, which every push but a CLOSURE must name and a CUT moves; versionless
// replacement, every path but <root>/settings keeping only its newest version readable; and push ids, a retry of an
// unknown outcome learning what the first attempt did. Refusals a schedule wants (429, a quota, an unknown outcome)
// are queued on the ref. Every ref version stays listable, so a view can be loaded at any push's base.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"
)

// A read of a version the ref no longer keeps: a versionless path's replaced version, evs's collected (§11.9).
var errTestIndexCollected = errors.New("test index store: version collected")

// One ref's index, shared by every handle. Safe for concurrent use.
type testIndexRef struct {
	stateLock sync.Mutex
	// By ref version, from 0: each version's files and head.
	states []*testIndexState
	// Committed pushes by id, so a retry of an unknown outcome answers what the first attempt did.
	committed map[Id]*indexCommitted
	// Each path's newest removal's version, which a later creation passes.
	removed map[string]uint64
	// Refusals the next commits answer, oldest first, before anything else.
	refusals []*testIndexQueuedRefusal
	// Runs before each commit takes the lock, with the push: a schedule holds a racing push here.
	beforeCommit func(push *indexPush)
}

// One ref version.
type testIndexState struct {
	head *indexRefHead
	// By path: every readable version, newest last. A versionless path holds one.
	files map[string][]*testIndexFile
}

// One stored version and its plaintext.
type testIndexFile struct {
	version   *indexFileVersion
	plaintext []byte
}

// A refusal queued for a coming commit. An unknown outcome may commit the push first.
type testIndexQueuedRefusal struct {
	refusal *indexRefusal
	commit  bool
}

// An empty ref at version 0.
func testNewIndexRef() *testIndexRef {
	return &testIndexRef{
		states:    []*testIndexState{{head: &indexRefHead{}, files: map[string][]*testIndexFile{}}},
		committed: map[Id]*indexCommitted{},
		removed:   map[string]uint64{},
	}
}

// One writer's handle: what it commits it signs.
type testIndexStore struct {
	ref    *testIndexRef
	signer Id
}

// A handle that signs as signer.
func (self *testIndexRef) store(signer Id) *testIndexStore {
	return &testIndexStore{ref: self, signer: signer}
}

// Queues a refusal for the next commit; commit says whether an unknown outcome commits the push before answering.
func (self *testIndexRef) refuseNext(refusal *indexRefusal, commit bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refusals = append(self.refusals, &testIndexQueuedRefusal{refusal: refusal, commit: commit})
}

// The newest state.
func (self *testIndexRef) headStateWithLock() *testIndexState {
	return self.states[len(self.states)-1]
}

// The state at refVersion, 0 being the head.
func (self *testIndexRef) stateAtWithLock(refVersion uint64) (*testIndexState, error) {
	if refVersion == 0 {
		return self.headStateWithLock(), nil
	}
	if uint64(len(self.states)) <= refVersion {
		return nil, errors.New("test index store: ref version past the head")
	}
	return self.states[refVersion], nil
}

// The ref's head.
func (self *testIndexStore) Head(ctx context.Context) (*indexRefHead, error) {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	head := *self.ref.headStateWithLock().head
	return &head, nil
}

// Every path's newest version at refVersion, by path.
func (self *testIndexStore) List(ctx context.Context, refVersion uint64) (*indexListing, error) {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	state, err := self.ref.stateAtWithLock(refVersion)
	if err != nil {
		return nil, err
	}
	head := *state.head
	listing := &indexListing{head: &head}
	for _, versions := range state.files {
		file := *versions[len(versions)-1].version
		listing.files = append(listing.files, &file)
	}
	slices.SortFunc(listing.files, func(a *indexFileVersion, b *indexFileVersion) int {
		return strings.Compare(a.path, b.path)
	})
	return listing, nil
}

// A path's readable versions at refVersion, newest first.
func (self *testIndexStore) History(ctx context.Context, path string, refVersion uint64) ([]*indexFileVersion, error) {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	state, err := self.ref.stateAtWithLock(refVersion)
	if err != nil {
		return nil, err
	}
	history := []*indexFileVersion{}
	for _, stored := range slices.Backward(state.files[path]) {
		file := *stored.version
		history = append(history, &file)
	}
	return history, nil
}

// The plaintext of a version the head still keeps, checked against its hash. A replaced versionless version is
// collected, as evs's purge leaves it.
func (self *testIndexStore) Read(ctx context.Context, file *indexFileVersion) ([]byte, error) {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	for _, stored := range self.ref.headStateWithLock().files[file.path] {
		if stored.version.version == file.version {
			if sha256.Sum256(stored.plaintext) != file.contentSha256 {
				return nil, errors.New("test index store: plaintext hash mismatch")
			}
			return bytes.Clone(stored.plaintext), nil
		}
	}
	return nil, errTestIndexCollected
}

// Commits push at the head, or refuses it: a queued refusal first; then a push id already committed answers its
// result; then the epoch, which every push but a CLOSURE names; then each path's CAS, every conflicting path named.
func (self *testIndexStore) Commit(ctx context.Context, push *indexPush) (*indexCommitted, error) {
	if self.ref.beforeCommit != nil {
		self.ref.beforeCommit(push)
	}
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	if 0 < len(self.ref.refusals) {
		queued := self.ref.refusals[0]
		self.ref.refusals = self.ref.refusals[1:]
		if queued.commit {
			if _, err := self.commitWithLock(push); err != nil {
				return nil, err
			}
		}
		refusal := *queued.refusal
		refusal.pushId = push.pushId
		return nil, &refusal
	}
	return self.commitWithLock(push)
}

// Commit's checks and write, the lock held.
func (self *testIndexStore) commitWithLock(push *indexPush) (*indexCommitted, error) {
	if committed, ok := self.ref.committed[push.pushId]; ok {
		return committed, nil
	}
	head := self.ref.headStateWithLock()
	if push.kind != indexPushClosure && push.indexEpoch != head.head.indexEpoch {
		return nil, &indexRefusal{kind: indexRefusalIndexEpoch}
	}
	conflicts := []string{}
	newest := func(path string) *indexFileVersion {
		versions := head.files[path]
		if len(versions) == 0 {
			return nil
		}
		return versions[len(versions)-1].version
	}
	for _, file := range push.files {
		if current := newest(file.path); (current == nil && file.replaces != 0) || (current != nil && current.version != file.replaces) {
			conflicts = append(conflicts, file.path)
		}
	}
	for _, removal := range push.removals {
		if current := newest(removal.path); current == nil || current.version != removal.version {
			conflicts = append(conflicts, removal.path)
		}
	}
	if 0 < len(conflicts) {
		slices.Sort(conflicts)
		return nil, &indexRefusal{kind: indexRefusalConflict, paths: slices.Compact(conflicts)}
	}

	version := head.head.version + 1
	chain := sha256.New()
	chain.Write(head.head.chain[:])
	chain.Write(push.pushId.Bytes())
	chain.Write(binary.BigEndian.AppendUint64(nil, version))
	next := &testIndexState{
		head: &indexRefHead{
			version:      version,
			chain:        [sha256.Size]byte(chain.Sum(nil)),
			indexEpoch:   head.head.indexEpoch,
			signedTimeMs: push.signedTimeMs,
		},
		files: map[string][]*testIndexFile{},
	}
	if push.kind == indexPushCut {
		next.head.indexEpoch = version
	}
	for path, versions := range head.files {
		next.files[path] = versions
	}
	for _, removal := range push.removals {
		delete(next.files, removal.path)
		self.ref.removed[removal.path] = removal.version + 1
	}
	committed := &indexCommitted{version: version}
	for _, file := range push.files {
		entryVersion := file.replaces + 1
		if file.replaces == 0 {
			entryVersion = max(push.baseVersion, self.ref.removed[file.path]) + 1
		}
		stored := &testIndexFile{
			version: &indexFileVersion{
				path:            file.path,
				version:         entryVersion,
				commitVersion:   version,
				contentSha256:   sha256.Sum256(file.plaintext),
				byteCount:       len(file.plaintext),
				signerSidecarId: self.signer,
				signedTimeMs:    push.signedTimeMs,
			},
			plaintext: bytes.Clone(file.plaintext),
		}
		if strings.HasSuffix(file.path, "/settings") {
			next.files[file.path] = append(slices.Clone(next.files[file.path]), stored)
		} else {
			next.files[file.path] = []*testIndexFile{stored}
		}
		written := *stored.version
		committed.files = append(committed.files, &written)
	}
	self.ref.states = append(self.ref.states, next)
	self.ref.committed[push.pushId] = committed
	return committed, nil
}

// A push of files and removals built at the head, naming its epoch, signed at signedTime.
func (self *testIndexStore) testPush(t testingT, signedTime time.Time, files []*indexPushFile, removals []*indexPushRemoval) *indexPush {
	head, err := self.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return &indexPush{
		pushId:       NewId(),
		baseVersion:  head.version,
		indexEpoch:   head.indexEpoch,
		signedTimeMs: signedTime.UnixMilli(),
		files:        files,
		removals:     removals,
	}
}

// Commits files at the head, failing the test on any refusal.
func (self *testIndexStore) testCommit(t testingT, signedTime time.Time, files ...*indexPushFile) *indexCommitted {
	committed, err := self.Commit(context.Background(), self.testPush(t, signedTime, files, nil))
	if err != nil {
		t.Fatal(err)
	}
	return committed
}

// The newest version of path at the head, or 0.
func (self *testIndexStore) testVersionOf(path string) uint64 {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	versions := self.ref.headStateWithLock().files[path]
	if len(versions) == 0 {
		return 0
	}
	return versions[len(versions)-1].version.version
}

// What the fake's helpers need of a test.
type testingT interface {
	Helper()
	Fatal(args ...any)
}
