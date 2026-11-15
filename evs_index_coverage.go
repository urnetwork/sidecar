//go:build !ios_extension

// Coverage (§11.14's coverage row; D-EVS-49; FI-18; DESIGN-DETAILS 1.2.6 and 1.2.8; QD-209; QD-689's reading 4;
// DESIGN-DETAILS 16.2.5's search row; SEARCH-M10-12): which pushes of a content ref the index holds, read from the
// ref's statements and the index's heads, so a reader shows every later push as not yet searchable and never silently
// absent.
//
//	indexed    a push is indexed when it wrote its signer's head with its content (in-ref); or a coverage row reaches
//	           it: its signer's own row for the ref, or the ref's horizon, which a backfiller raises for every writer;
//	           or it changes no document, carrying index_none or making only changes §11.14's never row keeps out
//	           (.ur-index/ paths, a mailbox's paths but m/), which a reader classifies with no fetch (QD-209); or this
//	           device's prefix rules ignore every change it makes, since an ignored version is no change to this
//	           device and indexing it would publish what the device does not show (16.2.5)
//	rows       IndexFileHeader.coverage holds at most two rows a ref, its writer's own and a horizon (QD-689's reading
//	           4); a writer carries its rows forward in every slot it writes, so a row never falls and the newest of
//	           each kind over every file of the root is the reading
//	through    indexed_through is the newest version up to which every push is indexed: one below the oldest push no
//	           rule counts, or the version read to when every push is counted
//
// An old client or a phone that skips the index is the normal case, never an alarm: its pushes read unindexed until a
// backfill covers them (evs_index_backfill.go). A push whose documents were all superseded is covered by its
// committer's next own row. What a reader cannot judge, a push under a rule set this device does not hold, is counted
// by the other rules alone and stays unindexed until one reaches it.
//
// A path is this device's own plaintext and goes into no log or error's text (I-13). Not safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// A content ref's pushes as its reader gave them break their order: a version out of order, outside the range asked,
// or twice.
var errIndexContentPushes = errors.New("index content pushes out of order")

// A content ref's head as coverage and a backfill pin it.
type indexContentHead struct {
	version      uint64
	signedTimeMs int64
}

// One change of a content push, as its verified statement names it.
type indexContentChange struct {
	// The path, as this device names it; empty for a change the device cannot name, which the never row cannot keep
	// out.
	path string
	// The change as 16.2.4's verdict judges it; nil where the reader holds none, which the verdict reads as no
	// change.
	prefix *AclPrefixChange
}

// One push of a content ref, as its verified statement shows it.
type indexContentPush struct {
	// The ref version it committed at, and its signed time_ms and signer.
	version      uint64
	signedTimeMs int64
	signer       Id
	// The verified statement 16.2.4's verdict reads; nil where the reader holds none.
	statement *EvsStatement
	// It wrote its signer's head in the ref's own index in the same statement: an in-ref push indexed with its content.
	changesHead bool
	// Its sealed metadata carries index_none: an index-aware writer marked that it changes no document (QD-209).
	indexNone bool
	// A ref DELETE, which on ur/index journals a ref tombstone: never a push that changes no document.
	deletesRef bool
	changes    []*indexContentChange
}

// A path's state at a ref version, as the device reads it: its effective version (DESIGN-DETAILS 16.2.5), the newest
// one this device does not ignore under the repo's prefix rules, or its removal.
type indexContentState struct {
	// The path's entry version, or its removal's; 0 for a path that never stood at the version read.
	version uint64
	// The ref version of the push that made that version or removal.
	commitVersion uint64
	removed       bool
	// An ERASE destroyed the version's keys: its content cannot be opened (§11.12's after row).
	unopenable bool
	// A file's or message's bytes and their length; nil for a removal, an unopenable version and a registered class's
	// documents.
	content   io.ReaderAt
	byteCount uint64
	// A registered class's documents of the path, from its IndexDocumentSource (§16.8's record entries); nil for files
	// and mail.
	documents []*IndexDocument
	// From the push's provenance (§16.6): the writing run was tainted; mail from outside the network, or an EvsImport's
	// content.
	tainted bool
	outside bool
}

// What coverage and a backfill read of one content ref R (DESIGN-DETAILS 1.2.6): its head from evs, its pushes from
// their verified statements, a path's effective state and its paths. SEARCH-M10-13 and SEARCH-M10-14 adapt EvsRepo to
// it, reading R's statements and texts through the mirror and its prefix judge's effective reads; the index's own
// tests run on a fake. Safe for concurrent use.
type indexContentRef interface {
	// R's ref_id.
	RefId() Id
	// R's head read from evs now, never from a cache or the replica's pin.
	Head(ctx context.Context) (*indexContentHead, error)
	// R's pushes committed at versions in (afterVersion, throughVersion], oldest first.
	Pushes(ctx context.Context, afterVersion uint64, throughVersion uint64) ([]*indexContentPush, error)
	// path's effective state at refVersion.
	State(ctx context.Context, path string, refVersion uint64) (*indexContentState, error)
	// Visits every path that stands at refVersion, with its effective version's length in bytes.
	Paths(ctx context.Context, refVersion uint64, visit func(path string, byteCount uint64) error) error
}

// 16.2.4's verdict on one change of a content push, as this device's prefix judge gives it. Nil: the device holds no
// rule set, and every change is allowed.
type indexPrefixVerdict func(ctx context.Context, push *indexContentPush, change *indexContentChange) (AclPrefixVerdict, error)

// The verdict of EVS1-M6-04's judge on repo, which asks ACL-M6-04's PrefixVerdict of a change of a verified push of the
// ref refId. A push or change the reader holds no statement of is allowed, as the judge reads a change it cannot see;
// a repo whose rows hold no set is allowed; one ruled by a set this client holds no judge for waits.
func indexEvsPrefixVerdict(repo *EvsRepo, refId Id) indexPrefixVerdict {
	return func(ctx context.Context, push *indexContentPush, change *indexContentChange) (AclPrefixVerdict, error) {
		if push.statement == nil || change.prefix == nil {
			return AclPrefixVerdict{Outcome: AclPrefixAllowed, Reason: AclPrefixReasonNoChange}, nil
		}
		judge, err := repo.prefixJudge()
		var ruleErr *EvsPrefixRuleError
		switch {
		case errors.As(err, &ruleErr):
			return AclPrefixVerdict{Outcome: AclPrefixWait, Reason: AclPrefixReasonPending}, nil
		case err != nil:
			return AclPrefixVerdict{}, err
		case judge == nil:
			return AclPrefixVerdict{Outcome: AclPrefixAllowed, Reason: AclPrefixReasonNoSet}, nil
		}
		return judge.verdict(ctx, repo, refId, push.statement, change.prefix)
	}
}

// How coverage counts one push.
type indexPushCount int

const (
	// No rule reaches it: not yet searchable until a backfill covers it.
	indexPushUnindexed indexPushCount = iota
	// It wrote its signer's head with its content.
	indexPushInRef
	// Its signer's own row or the ref's horizon reaches it.
	indexPushCovered
	// It carries index_none, or every change it makes falls under the never row.
	indexPushNoDocument
	// The device's prefix rules ignore every change it makes that the never row lets in.
	indexPushIgnored
)

// One push as coverage counted it.
type indexCountedPush struct {
	push  *indexContentPush
	count indexPushCount
	// Some change of it is under a rule set this device cannot read, waiting or a later release's: the device cannot
	// say whether it would show the change, so a backfill indexes nothing at or above it.
	unjudged bool
	// The changes the rules ignore, by index into push.changes; nil where no verdict was asked.
	ignored []bool
}

// What coverage read of one content ref.
type indexCoverage struct {
	refId Id
	// The ref version read to: R's head, or the pin a backfill took.
	through uint64
	// indexed_through: every push at or below it is indexed.
	indexedThrough uint64
	// Pushes above indexed_through that no rule counts, the oldest of them at indexedThrough + 1.
	unindexedCount int
	// The newest horizon row for the ref in the index, and each writer's newest own row.
	horizon    uint64
	writerRows map[Id]uint64
	// Every push read, oldest first: those above the higher of the horizon and the reading's floor.
	pushes []*indexCountedPush
}

// What one coverage reading takes.
type indexCoverageArgs struct {
	// The index at the reading's base, and the root whose rows are read.
	view *indexView
	root *indexViewRoot
	// R and its reader. On a file-mode ref's own index R is the index's ref.
	content indexContentRef
	// Nil: no rule set.
	verdict indexPrefixVerdict
	// The ref version to read to: 0 reads R's head; a file-mode ref's own index reads to the view's base.
	through uint64
	// A version every push at or below is known indexed, from an earlier reading of this ref: indexed_through never
	// falls, since a row never does.
	floor uint64
	// A general repo laid out as a group inbox (§15.7), whose never row is a mailbox's.
	groupInbox bool
}

// The newest horizon row for refId over every file of root, and each writer's newest own row (QD-689's reading 4: at
// most two rows a ref in a file, its writer's own and a horizon).
func indexCoverageRows(root *indexViewRoot, refId Id) (uint64, map[Id]uint64) {
	horizon := uint64(0)
	writerRows := map[Id]uint64{}
	for _, bucket := range root.buckets {
		for _, writer := range bucket.writers {
			for _, file := range slices.Concat(writer.slots, writer.large) {
				for _, row := range file.slot.header.Coverage {
					if !bytes.Equal(row.RefId, refId.Bytes()) {
						continue
					}
					if row.Horizon {
						horizon = max(horizon, row.Version)
					} else {
						writerRows[writer.sidecarId] = max(writerRows[writer.sidecarId], row.Version)
					}
				}
			}
		}
	}
	return horizon, writerRows
}

// Whether the never row keeps change out of the index by its path alone, as a reader classifies it with no fetch:
// .ur-index/ paths, and a mailbox's or group inbox's every path but m/ (QD-209). A change the device cannot name is
// not kept out.
func indexCoverageExcluded(view *indexView, groupInbox bool, change *indexContentChange) bool {
	if change.path == "" {
		return false
	}
	return indexExcluded(indexPlace{repoKind: view.repoKind, groupInbox: groupInbox, path: change.path})
}

// Reads the coverage of one content ref at the view's base: the index's rows for it, then its pushes above the higher
// of the horizon and the floor, each counted by the rules above.
func indexCoverageOf(ctx context.Context, args *indexCoverageArgs) (*indexCoverage, error) {
	view := args.view
	coverage := &indexCoverage{refId: args.content.RefId()}
	coverage.horizon, coverage.writerRows = indexCoverageRows(args.root, coverage.refId)
	coverage.through = args.through
	switch {
	case coverage.through != 0:
	case !view.companion && coverage.refId == view.refId:
		// a file-mode ref's own index: R is the index's ref, and its pin is the base the view was read at
		coverage.through = view.head.version
	default:
		head, err := args.content.Head(ctx)
		if err != nil {
			return nil, err
		}
		coverage.through = head.version
	}
	after := max(coverage.horizon, args.floor)
	if coverage.through <= after {
		coverage.indexedThrough = coverage.through
		return coverage, nil
	}
	pushes, err := args.content.Pushes(ctx, after, coverage.through)
	if err != nil {
		return nil, err
	}
	previous := after
	firstUnindexed := uint64(0)
	for _, push := range pushes {
		if push.version <= previous || coverage.through < push.version {
			return nil, fmt.Errorf("%w: version %d after %d", errIndexContentPushes, push.version, previous)
		}
		previous = push.version
		counted, err := indexCountPush(ctx, args, coverage, push)
		if err != nil {
			return nil, err
		}
		coverage.pushes = append(coverage.pushes, counted)
		if counted.count != indexPushUnindexed {
			continue
		}
		coverage.unindexedCount += 1
		if firstUnindexed == 0 {
			firstUnindexed = push.version
		}
	}
	coverage.indexedThrough = coverage.through
	if firstUnindexed != 0 {
		coverage.indexedThrough = firstUnindexed - 1
	}
	return coverage, nil
}

// How coverage counts push: the rules in their order, a verdict asked only of a push no other rule counts.
func indexCountPush(ctx context.Context, args *indexCoverageArgs, coverage *indexCoverage, push *indexContentPush) (*indexCountedPush, error) {
	counted := &indexCountedPush{push: push}
	switch {
	case push.changesHead:
		counted.count = indexPushInRef
		return counted, nil
	case push.version <= coverage.horizon || push.version <= coverage.writerRows[push.signer]:
		counted.count = indexPushCovered
		return counted, nil
	case push.indexNone:
		counted.count = indexPushNoDocument
		return counted, nil
	}
	relevant := 0
	for _, change := range push.changes {
		if !indexCoverageExcluded(args.view, args.groupInbox, change) {
			relevant += 1
		}
	}
	if relevant == 0 && !push.deletesRef {
		counted.count = indexPushNoDocument
		return counted, nil
	}
	ignored := 0
	counted.ignored = make([]bool, len(push.changes))
	for index, change := range push.changes {
		if args.verdict == nil || indexCoverageExcluded(args.view, args.groupInbox, change) {
			continue
		}
		verdict, err := args.verdict(ctx, push, change)
		if err != nil {
			return nil, err
		}
		switch verdict.Outcome {
		case AclPrefixIgnored:
			counted.ignored[index] = true
			ignored += 1
		case AclPrefixWait, AclPrefixUpdate:
			counted.unjudged = true
		}
	}
	if 0 < relevant && ignored == relevant && !push.deletesRef {
		counted.count = indexPushIgnored
	}
	return counted, nil
}

// The coverage rows a writer's push carries: rows, its newest head's, each raised to raised's row of its kind for its
// ref where that is higher, and raised's rows the head lacks added, sorted as the format sorts them (QD-689's reading
// 4).
func indexRaiseCoverage(rows []*protocol.IndexCoverage, raised []*protocol.IndexCoverage) []*protocol.IndexCoverage {
	out := []*protocol.IndexCoverage{}
	for _, row := range rows {
		out = append(out, &protocol.IndexCoverage{RefId: bytes.Clone(row.RefId), Version: row.Version, Horizon: row.Horizon})
	}
	for _, row := range raised {
		index := slices.IndexFunc(out, func(held *protocol.IndexCoverage) bool {
			return bytes.Equal(held.RefId, row.RefId) && held.Horizon == row.Horizon
		})
		if index < 0 {
			out = append(out, &protocol.IndexCoverage{RefId: bytes.Clone(row.RefId), Version: row.Version, Horizon: row.Horizon})
			continue
		}
		out[index].Version = max(out[index].Version, row.Version)
	}
	slices.SortFunc(out, indexCompareCoverage)
	return out
}

// The coverage rows of writer's newest head in root: its head in the newest bucket it holds a slot in, nil for none.
func indexWriterNewestRows(root *indexViewRoot, writer Id) []*protocol.IndexCoverage {
	for _, bucket := range slices.Backward(root.buckets) {
		if held := bucket.writer(writer); held != nil {
			if head := held.head(); head != nil {
				return head.slot.header.Coverage
			}
		}
	}
	return nil
}

// A roll-up's I_R at a view's base (DESIGN-DETAILS 1.2.5's step 5): coverage's indexed_through for a content ref, read
// through contentOf, which answers nil for a ref the device cannot read; false then, or on any failure to read, and
// the roll-up carries S's own rows, a bound below I_R. A file-mode ref's own index reads to the view's base.
func indexCoverageIndexedThrough(ctx context.Context, contentOf func(refId Id) indexContentRef, verdictOf func(refId Id) indexPrefixVerdict, groupInbox bool) func(view *indexView, refId []byte) (uint64, bool) {
	return func(view *indexView, refId []byte) (uint64, bool) {
		id, err := IdFromBytes(refId)
		if err != nil {
			return 0, false
		}
		content := contentOf(id)
		if content == nil {
			return 0, false
		}
		var verdict indexPrefixVerdict
		if verdictOf != nil {
			verdict = verdictOf(id)
		}
		coverage, err := indexCoverageOf(ctx, &indexCoverageArgs{
			view: view, root: view.writeRoot(), content: content, verdict: verdict, groupInbox: groupInbox,
		})
		if err != nil {
			return 0, false
		}
		return coverage.indexedThrough, true
	}
}
