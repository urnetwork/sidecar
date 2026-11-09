// The store seam (§11.14's head and commit rows; SEARCH-M10-08): what the index asks of a ref's committed state, and
// nothing more. No single index head exists: the listing of an index root at a ref version is the index's state, each
// file's plaintext SHA-256 in its entry version, so the index reads a head, lists, reads files and commits pushes of
// index files and removals, each file under its path's CAS. Format 2's writer is EVS2's, so this seam lets the index be
// built before it lands: SEARCH-M10-13 adapts EvsRepo to it, and the index's own tasks test on the fake in
// evs_index_fake_test.go, which models path CAS, index_epoch and versionless replacement.
//
// Every file but <root>/settings is versionless (versioning 2), so a store keeps only its newest version readable; the
// settings keep their history, since only a repo admin's version counts. Refusals are typed, so a builder can tell the
// one 409 it rebases (a head another of its own pushes changed) from INDEX_EPOCH, which rebuilds without the erasure
// set's documents (§11.14's conflict and epoch rows). A refusal's text names its kind and never a path (I-13).

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// A ref's head as the index reads it.
type indexRefHead struct {
	version uint64
	// C_v, the head's chain hash (§11.8), which a reader's pin names.
	chain [sha256.Size]byte
	// The version of the ref's newest CUT, else 0 (§11.12; EvsHead.index_epoch). Every index push but a CLOSURE names
	// it (I-EVS-17).
	indexEpoch uint64
	// The signed time_ms of the push that made the head.
	signedTimeMs int64
}

// One committed version of an index file, as a listing shows it.
type indexFileVersion struct {
	path string
	// The path's entry version (§11.7's versions), which its CAS names.
	version uint64
	// The ref version its push committed at.
	commitVersion uint64
	// The plaintext's SHA-256, from the entry version (§11.7's content_sha256).
	contentSha256 [sha256.Size]byte
	// The plaintext's length, pad included.
	byteCount int
	// The push's signer and signed time_ms.
	signerSidecarId Id
	signedTimeMs    int64
}

// Every index file at one ref version, and the head as of that version.
type indexListing struct {
	head  *indexRefHead
	files []*indexFileVersion
}

// One file a push writes.
type indexPushFile struct {
	path      string
	plaintext []byte
	// The version it replaces, which the path's CAS names: 0 creates the path, and a version is refused unless it is
	// the path's newest.
	replaces uint64
}

// One file a push removes, at the version it names.
type indexPushRemoval struct {
	path    string
	version uint64
}

// What an index push is to the epoch rule (§11.14's epoch row; I-EVS-17).
type indexPushKind int

const (
	// Names the head's index_epoch, and is refused 409 INDEX_EPOCH when another has moved it.
	indexPushIndex indexPushKind = iota
	// An erasure's CUT: names the epoch like any index push, and moves it to the version it commits at.
	indexPushCut
	// An eraser's CLOSURE, the one push that needs no epoch.
	indexPushClosure
)

// One push of index files and removals.
type indexPush struct {
	// A retry of an unknown outcome sends the same id, and learns whether the first attempt committed.
	pushId Id
	kind   indexPushKind
	// The ref version it was built at.
	baseVersion uint64
	// The head's index_epoch it was built at; a CLOSURE's is unread.
	indexEpoch   uint64
	signedTimeMs int64
	files        []*indexPushFile
	removals     []*indexPushRemoval
}

// A committed push: the ref version it committed at, and each file's new version.
type indexCommitted struct {
	version uint64
	files   []*indexFileVersion
}

// What the index reads and writes of one ref. Safe for concurrent use.
type indexRefStore interface {
	// The ref's head now.
	Head(ctx context.Context) (*indexRefHead, error)
	// Every file under the ref's index roots and its erasure set at refVersion, its newest version each, with the
	// head as of that version; 0 lists the head.
	List(ctx context.Context, refVersion uint64) (*indexListing, error)
	// One path's versions at refVersion, newest first: the history <root>/settings keeps, or a versionless path's
	// one readable version.
	History(ctx context.Context, path string, refVersion uint64) ([]*indexFileVersion, error)
	// The plaintext of one version, checked against its content_sha256 before it is returned.
	Read(ctx context.Context, file *indexFileVersion) ([]byte, error)
	// Commits push, or refuses it with an *indexRefusal.
	Commit(ctx context.Context, push *indexPush) (*indexCommitted, error)
}

// Why a push did not commit.
type indexRefusalKind int

const (
	// 409: a path's CAS failed, another push having changed it since the push's base.
	indexRefusalConflict indexRefusalKind = iota + 1
	// 409 INDEX_EPOCH: a CUT moved the head's index_epoch past the one the push names.
	indexRefusalIndexEpoch
	// 429: nothing refused; the same push may go again after retryAfter.
	indexRefusalRetry
	// A quota refused it (§20.7).
	indexRefusalQuota
	// The push may or may not have committed: a retry of the same push id resolves it (§11.8's outcomes).
	indexRefusalOutcomeUnknown
)

// A store's typed refusal of a push.
type indexRefusal struct {
	kind indexRefusalKind
	// A conflict's paths: those another push changed.
	paths []string
	// A retry's wait, and a quota refusal's where it names one.
	retryAfter time.Duration
	// A quota refusal's limit.
	quota *QuotaRefusal
	// An unknown outcome's push.
	pushId Id
}

// The kind only: a path is never in a message (I-13).
func (self *indexRefusal) Error() string {
	switch self.kind {
	case indexRefusalConflict:
		return fmt.Sprintf("index push refused: conflict on %d paths", len(self.paths))
	case indexRefusalIndexEpoch:
		return "index push refused: index epoch"
	case indexRefusalRetry:
		return fmt.Sprintf("index push refused: retry after %s", self.retryAfter)
	case indexRefusalQuota:
		return "index push refused: quota"
	case indexRefusalOutcomeUnknown:
		return "index push outcome unknown"
	}
	return "index push refused"
}

// The *indexRefusal err holds, and false for any other error.
func indexRefusalOf(err error) (*indexRefusal, bool) {
	var refusal *indexRefusal
	if errors.As(err, &refusal) {
		return refusal, true
	}
	return nil, false
}

// Whether err is a refusal of kind.
func isIndexRefusal(err error, kind indexRefusalKind) bool {
	refusal, ok := indexRefusalOf(err)
	return ok && refusal.kind == kind
}
