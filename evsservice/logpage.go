// Log pages (§11.8's objects row and step 6; §11.7's lag row): log/<repo>/<ref>/<n> holds versions 64n to 64n+63,
// page 0 from version 1, as one EvsLogPage: their 64 B window entries and Signed EvsPush statements as received, C
// before its first version and C at its last, at most ~70 KiB. A page-out at step 6 writes one once the window would
// pass 127 versions, after folding any of its versions still unfolded, and step 7's head then drops its entries from
// the window and moves window_base_chain to the page's last chain (EvsPageOut.Apply). Every writer builds a page alike
// from what the head names, so its create is If-None-Match and equal bytes on a 412 are success (PutImmutable).
//
// When the page-out cannot finish within step 7's 5 s rule (its budget says no, its deadline passes, a statement is
// out of reach), the commit pages nothing and the window grows, up to 255 versions; past that, pushes to the ref get
// 429 FOLD_BEHIND with retry_after_ms (EvsFoldBehindError).
//
// A page read back (ReadLogPage) is held to its shape and chain before use: one entry a version, each naming its
// statement by push id and hash prefix, every statement this repo's and ref's, and C carried forward from first_chain
// reaching last_chain, page 0's first chain being C_0. Pages never change, so a process keeps them (LogPageCache). A
// page that 404s was packed (§11.13): pidx/ finds it (EVSB-M2-10), and until that lands the read answers
// ErrEvsRecordEvacuated, as ReadRecord does.

package evsservice

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A log page's versions: 64n to 64n+63 (§11.8's objects row).
const EvsLogPageVersionCount = 64

// §11.8 step 6: a commit pages out once the window would pass this many entries, and §11.8's size row holds the head
// to it while folds keep up.
const EvsWindowPageOutEntryCount = 127

// A log page whose bytes break its shape or its chain: a fault that alarms, never a page to use.
var ErrEvsLogPageInvalid = errors.New("evs log page invalid")

// §11.7's lag row: the window would pass 255 versions and its page-out could not finish, so the push gets 429
// FOLD_BEHIND with retry_after_ms. It refuses nothing (§11.20).
type EvsFoldBehindError struct {
	RetryAfter time.Duration
}

// Says when to try again.
func (self *EvsFoldBehindError) Error() string {
	return fmt.Sprintf("evs folds behind, retry after %s", self.RetryAfter)
}

// retry_after_ms's value.
func (self *EvsFoldBehindError) RetryAfterMs() uint32 {
	return uint32(max(0, self.RetryAfter.Milliseconds()))
}

// The page holding version.
func EvsLogPageOf(version uint64) uint64 {
	return version / EvsLogPageVersionCount
}

// The first and last version of page: 64n to 64n+63, page 0 from version 1, since no version 0 exists.
func EvsLogPageVersions(page uint64) (uint64, uint64) {
	first := page * EvsLogPageVersionCount
	if page == 0 {
		first = 1
	}
	return first, page*EvsLogPageVersionCount + EvsLogPageVersionCount - 1
}

// One log page, held to its shape and chain.
type LogPage struct {
	Page uint64
	// C before its first version, and C at its last.
	FirstChain [sha256.Size]byte
	LastChain  [sha256.Size]byte
	// Its versions' window entries and Signed EvsPush statements, oldest first.
	Entries    []*sidecar.EvsWindowEntry
	Statements [][]byte
	// The EvsLogPage bytes as stored.
	Bytes []byte
}

// The version of the page's entry naming pushId, and whether one does.
func (self *LogPage) VersionOf(pushId sidecar.Id) (uint64, bool) {
	first, _ := EvsLogPageVersions(self.Page)
	for i, entry := range self.Entries {
		if entry.PushId == pushId {
			return first + uint64(i), true
		}
	}
	return 0, false
}

// The window entry and statement of version, and whether the page holds it.
func (self *LogPage) At(version uint64) (*sidecar.EvsWindowEntry, []byte, bool) {
	first, last := EvsLogPageVersions(self.Page)
	if version < first || last < version {
		return nil, nil, false
	}
	return self.Entries[version-first], self.Statements[version-first], true
}

// Page n of repoId's refId built from the chain before its first version, its versions' window entries as the head
// holds them and their statements as received: checked as ParseLogPage checks a page read back, and encoded
// deterministically, so every writer builds equal bytes.
func BuildLogPage(repoId sidecar.Id, refId sidecar.Id, page uint64, firstChain [sha256.Size]byte, window []byte, statements [][]byte) (*LogPage, error) {
	entries, lastChain, err := checkLogPageChain(repoId, refId, page, firstChain, window, statements)
	if err != nil {
		return nil, err
	}
	message := &protocol.EvsLogPage{
		Page:       page,
		FirstChain: firstChain[:],
		LastChain:  lastChain[:],
		Window:     bytes.Clone(window),
		Statements: statements,
	}
	pageBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, err
	}
	if sidecar.EvsLogPageMaxByteCount < len(pageBytes) {
		return nil, fmt.Errorf("%w: a page of %d bytes", ErrEvsLogPageInvalid, len(pageBytes))
	}
	return &LogPage{
		Page:       page,
		FirstChain: firstChain,
		LastChain:  lastChain,
		Entries:    entries,
		Statements: statements,
		Bytes:      pageBytes,
	}, nil
}

// A page's bytes read back, held to its number, shape and chain before use.
func ParseLogPage(repoId sidecar.Id, refId sidecar.Id, page uint64, pageBytes []byte) (*LogPage, error) {
	if sidecar.EvsLogPageMaxByteCount < len(pageBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrEvsLogPageInvalid, len(pageBytes))
	}
	message := &protocol.EvsLogPage{}
	if err := proto.Unmarshal(pageBytes, message); err != nil {
		return nil, fmt.Errorf("%w: does not parse", ErrEvsLogPageInvalid)
	}
	if message.GetPage() != page {
		return nil, fmt.Errorf("%w: page %d where %d belongs", ErrEvsLogPageInvalid, message.GetPage(), page)
	}
	firstChain, err := sidecar.EvsChainFromBytes(message.GetFirstChain())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsLogPageInvalid, err)
	}
	lastChain, err := sidecar.EvsChainFromBytes(message.GetLastChain())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsLogPageInvalid, err)
	}
	entries, computedChain, err := checkLogPageChain(repoId, refId, page, firstChain, message.GetWindow(), message.GetStatements())
	if err != nil {
		return nil, err
	}
	if computedChain != lastChain {
		return nil, fmt.Errorf("%w: its statements do not reach its last chain", ErrEvsLogPageInvalid)
	}
	return &LogPage{
		Page:       page,
		FirstChain: firstChain,
		LastChain:  lastChain,
		Entries:    entries,
		Statements: message.GetStatements(),
		Bytes:      pageBytes,
	}, nil
}

// A page's entries and the chain its statements carry firstChain to: one entry and one statement a version, each
// statement this repo's and ref's and the one its entry names, and page 0 starting from C_0.
func checkLogPageChain(repoId sidecar.Id, refId sidecar.Id, page uint64, firstChain [sha256.Size]byte, window []byte, statements [][]byte) ([]*sidecar.EvsWindowEntry, [sha256.Size]byte, error) {
	first, last := EvsLogPageVersions(page)
	count := int(last - first + 1)
	if page == 0 && firstChain != sidecar.EvsChainStart(repoId, refId) {
		return nil, [sha256.Size]byte{}, fmt.Errorf("%w: page 0 not from C_0", ErrEvsLogPageInvalid)
	}
	entries, err := sidecar.DecodeEvsWindow(window)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("%w: %v", ErrEvsLogPageInvalid, err)
	}
	if len(entries) != count || len(statements) != count {
		return nil, [sha256.Size]byte{}, fmt.Errorf("%w: %d entries and %d statements for %d versions", ErrEvsLogPageInvalid, len(entries), len(statements), count)
	}
	chain := firstChain
	for i, statementBytes := range statements {
		// a page holds its statements as committed, of either format (format1_guard.go)
		statement, err := sidecar.ParseEvsStatementFormat2(statementBytes)
		if err != nil {
			return nil, [sha256.Size]byte{}, fmt.Errorf("%w: version %d: %v", ErrEvsLogPageInvalid, first+uint64(i), err)
		}
		if !bytes.Equal(statement.Push.GetRepoId(), repoId.Bytes()) || !bytes.Equal(statement.Push.GetRefId(), refId.Bytes()) ||
			!entries[i].Names(sidecar.Id(statement.Push.GetPushId()), statement.Sha256) {
			return nil, [sha256.Size]byte{}, fmt.Errorf("%w: version %d's statement is not the one its entry names", ErrEvsLogPageInvalid, first+uint64(i))
		}
		chain = sidecar.EvsChainNext(chain, entries[i].PushId, statement.Sha256)
	}
	return entries, chain, nil
}

// One cached page in the cache's recency list.
type logPageCacheItem struct {
	key  string
	page *LogPage
}

// Log pages by cluster and key, least recently used out past LogPageCacheByteCount. Pages never change, so an entry
// is never stale. Safe for concurrent use.
type LogPageCache struct {
	settings *EvsSettings

	stateLock sync.Mutex
	keyItems  map[string]*list.Element
	recency   *list.List
	byteCount int64
}

// An empty cache.
func NewLogPageCache(settings *EvsSettings) *LogPageCache {
	return &LogPageCache{settings: settings, keyItems: map[string]*list.Element{}, recency: list.New()}
}

// A page's cache key: its cluster and object key.
func logPageCacheKey(clusterId string, repoId sidecar.Id, refId sidecar.Id, page uint64) string {
	return clusterId + " " + LogPageKey(repoId, refId, page)
}

// The page, if this process holds it.
func (self *LogPageCache) Get(clusterId string, repoId sidecar.Id, refId sidecar.Id, page uint64) (*LogPage, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	element, ok := self.keyItems[logPageCacheKey(clusterId, repoId, refId, page)]
	if !ok {
		return nil, false
	}
	self.recency.MoveToFront(element)
	return element.Value.(*logPageCacheItem).page, true
}

// Keeps a page that was checked, read or written.
func (self *LogPageCache) Put(clusterId string, repoId sidecar.Id, refId sidecar.Id, page *LogPage) {
	if self.settings.LogPageCacheByteCount < int64(len(page.Bytes)) {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := logPageCacheKey(clusterId, repoId, refId, page.Page)
	if element, ok := self.keyItems[key]; ok {
		self.recency.MoveToFront(element)
		return
	}
	self.keyItems[key] = self.recency.PushFront(&logPageCacheItem{key: key, page: page})
	self.byteCount += int64(len(page.Bytes))
	for self.settings.LogPageCacheByteCount < self.byteCount {
		oldest := self.recency.Back()
		item := oldest.Value.(*logPageCacheItem)
		self.recency.Remove(oldest)
		delete(self.keyItems, item.key)
		self.byteCount -= int64(len(item.page.Bytes))
	}
}

// Page n of repoId's refId: this process's cache, else one GET, held to ParseLogPage before it is kept.
// ErrEvsRecordEvacuated for a page that 404s, which a pack holds (§11.13; EVSB-M2-10's pidx/ lookup).
func ReadLogPage(ctx context.Context, cache *LogPageCache, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, page uint64) (*LogPage, error) {
	if cached, ok := cache.Get(cluster.ClusterId(), repoId, refId, page); ok {
		return cached, nil
	}
	object, err := cluster.Get(ctx, LogPageKey(repoId, refId, page))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, fmt.Errorf("%w: log page %d", ErrEvsRecordEvacuated, page)
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	pageBytes, err := io.ReadAll(io.LimitReader(object.Body, sidecar.EvsLogPageMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	logPage, err := ParseLogPage(repoId, refId, page, pageBytes)
	if err != nil {
		return nil, err
	}
	cache.Put(cluster.ClusterId(), repoId, refId, logPage)
	return logPage, nil
}

// What a page-out is asked at step 6.
type EvsPageOutRequest struct {
	// The ref's metadata cluster, its writes held to the budget.
	Cluster sidecar.BlobCluster
	RepoId  sidecar.Id
	RefId   sidecar.Id
	// Step 4's head, whether it came from {evsh_}, and when step 4 issued its cluster read: a fold relies on that
	// read, or reads the head from the cluster when step 4's came from the cache (§11.7's stale row).
	Head       *EvsStoredHead
	Cached     bool
	HeadReadAt time.Time
	// Past it, by this process's clock, the page-out gives up and pages nothing: step 7's 5 s from step 4's reads,
	// less what step 7 needs.
	Deadline time.Time
}

// What step 7's head takes from step 6's page-out.
type EvsPageOut struct {
	// A page went out: the window drops its entries. False leaves the window as it is, up to 255 entries.
	Paged bool
	Page  uint64
	// How many entries leave the window's front.
	EntryCount int
	// C at the page's last version: the next head's window_base_chain.
	BaseChain [sha256.Size]byte
	// The folded_through the commit carries: this process's folds over the head's horizon (Folder.Horizon).
	FoldedThrough uint64
}

// Applies the page-out to step 7's next head, whose window already holds the push's entry: the paged entries leave
// its front, window_base_chain moves to the page's last chain, and folded_through rises to what this process folded.
func (self *EvsPageOut) Apply(next *protocol.EvsHead) error {
	if self.Paged {
		cut := self.EntryCount * sidecar.EvsWindowEntryByteCount
		if len(next.GetWindow()) < cut {
			return fmt.Errorf("%w: paging %d entries out of a window of %d bytes", ErrEvsHeadRule, self.EntryCount, len(next.GetWindow()))
		}
		next.Window = bytes.Clone(next.GetWindow()[cut:])
		next.WindowBaseChain = bytes.Clone(self.BaseChain[:])
	}
	next.FoldedThrough = max(next.GetFoldedThrough(), self.FoldedThrough)
	return nil
}

// Step 6's page-out (§11.8; §11.7's when row (3) and lag row): when step 4's window would pass 127 versions with the
// push's own, it folds any of its oldest page's versions still unfolded, never waiting for budget, and writes that
// page, so step 7's head drops it. When that cannot finish by the request's deadline the push pages nothing, and past
// 255 versions it answers *EvsFoldBehindError. Every answer carries the horizon the commit raises folded_through to.
func (self *Folder) PageOut(ctx context.Context, request *EvsPageOutRequest) (*EvsPageOut, error) {
	head := request.Head.Head
	pageOut := &EvsPageOut{FoldedThrough: self.Horizon(request.RepoId, request.RefId, head)}
	entryCount := len(head.GetWindow()) / sidecar.EvsWindowEntryByteCount
	if entryCount+1 <= EvsWindowPageOutEntryCount {
		return pageOut, nil
	}
	behind := func(reason error) (*EvsPageOut, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if sidecar.EvsWindowMaxEntryCount < entryCount+1 {
			return nil, &EvsFoldBehindError{RetryAfter: self.settings.FoldBehindRetryAfter}
		}
		if self.log.V(1).Enabled() {
			self.log.Infof("[evs] page-out of repo %s ref %s deferred at %d entries: %v",
				sidecar.EvsKeyId(request.RepoId), sidecar.EvsKeyId(request.RefId), entryCount, reason)
		}
		return pageOut, nil
	}
	firstVersion := EvsHeadWindowFirstVersion(head)
	page := EvsLogPageOf(firstVersion)
	pageFirst, pageLast := EvsLogPageVersions(page)
	if firstVersion != pageFirst || head.GetVersion() < pageLast {
		self.log.Errorf("[evs] alarm window_page: repo %s ref %s's window starts at %d, inside page %d",
			sidecar.EvsKeyId(request.RepoId), sidecar.EvsKeyId(request.RefId), firstVersion, page)
		return behind(ErrEvsHeadInvalid)
	}

	// §11.7's when row (3): fold what the page holds first, on the cluster's head when step 4's came from the cache
	if pageOut.FoldedThrough < pageLast {
		foldHead, readAt := request.Head, request.HeadReadAt
		if request.Cached {
			foldHead, readAt = nil, time.Time{}
		}
		result, err := self.Fold(ctx, &EvsFoldRequest{
			Cluster:    request.Cluster,
			RepoId:     request.RepoId,
			RefId:      request.RefId,
			Head:       foldHead,
			HeadReadAt: readAt,
			Through:    pageLast,
			Rank:       sidecar.WriteP2RankPageOutFold,
			NoWait:     true,
			Deadline:   request.Deadline,
		})
		if err != nil {
			return behind(err)
		}
		if result.Superseded {
			// another fold passed step 4's horizon, so step 7's If-Match on that head fails and the rerun pages
			return behind(errEvsFoldSuperseded)
		}
		pageOut.FoldedThrough = self.Horizon(request.RepoId, request.RefId, head)
		if pageOut.FoldedThrough < pageLast {
			return behind(fmt.Errorf("folded through %d of %d", pageOut.FoldedThrough, pageLast))
		}
	}

	// the page, from step 4's window and the statements its entries name
	window, err := EvsHeadWindow(head)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsHeadInvalid, err)
	}
	firstChain, err := sidecar.EvsChainFromBytes(head.GetWindowBaseChain())
	if err != nil {
		return nil, fmt.Errorf("%w: a window base chain of %d bytes", ErrEvsHeadInvalid, len(head.GetWindowBaseChain()))
	}
	pushes := NewRecordPushSource(self.records, self.locator, request.Cluster, request.RepoId, request.RefId)
	statements := make([][]byte, 0, pageLast-pageFirst+1)
	for version := pageFirst; version <= pageLast; version += 1 {
		statement, err := pushes.statementAt(ctx, version, window[version-firstVersion])
		if err != nil {
			return behind(err)
		}
		statements = append(statements, statement.Bytes)
	}
	pageEntryCount := int(pageLast - pageFirst + 1)
	logPage, err := BuildLogPage(request.RepoId, request.RefId, page, firstChain, head.GetWindow()[:pageEntryCount*sidecar.EvsWindowEntryByteCount], statements)
	if err != nil {
		self.log.Errorf("[evs] alarm log_page: repo %s ref %s page %d: %v", sidecar.EvsKeyId(request.RepoId), sidecar.EvsKeyId(request.RefId), page, err)
		return behind(err)
	}
	if !request.Deadline.IsZero() && !self.clock.Now().Before(request.Deadline) {
		return behind(ErrEvsFoldDeferred)
	}
	price, err := self.priceTable.Price(WriteOperation{Kind: WriteOperationCreate, ObjectByteCount: int64(len(logPage.Bytes)), Count: 1})
	if err != nil {
		return nil, err
	}
	grant, ok, err := self.budget.TryAcquireP2(ctx, request.Cluster.ClusterId(), &sidecar.WriteP2Work{
		Rank:      sidecar.WriteP2RankPageOutFold,
		Due:       self.clock.Now(),
		ByteCount: price,
		Funded:    true,
		Recheck: func(ctx context.Context) error {
			return self.recheckRepo(ctx, request.Cluster, request.RepoId)
		},
	})
	if err != nil {
		return behind(err)
	}
	if !ok {
		return behind(ErrEvsFoldDeferred)
	}
	defer grant.Close()
	writeCtx := grant.Context()
	if !request.Deadline.IsZero() {
		writeCtx = sidecar.WithBlobDeadline(writeCtx, request.Deadline)
	}
	barrierKey := barrierRefKey(request.RepoId, request.RefId)
	testHookBarrier(BarrierLogPagePutBefore, barrierKey)
	_, err = sidecar.PutImmutable(writeCtx, request.Cluster, LogPageKey(request.RepoId, request.RefId, page), logPage.Bytes, nil)
	testHookBarrier(BarrierLogPagePutAfter, barrierKey)
	if errors.Is(err, sidecar.ErrBlobImmutableMismatch) {
		self.log.Errorf("[evs] alarm log_page_mismatch: repo %s ref %s page %d holds other bytes", sidecar.EvsKeyId(request.RepoId), sidecar.EvsKeyId(request.RefId), page)
	}
	if err != nil {
		return behind(err)
	}
	self.logPages.Put(request.Cluster.ClusterId(), request.RepoId, request.RefId, logPage)
	pageOut.Paged = true
	pageOut.Page = page
	pageOut.EntryCount = int(pageLast - firstVersion + 1)
	pageOut.BaseChain = logPage.LastChain
	return pageOut, nil
}

// §11.13's skip row for a P2 write of the repo: repo/, cached at most 5 s, active or deleted, and of a format this
// instance writes (format1_guard.go), so a rolled-back binary folds and pages nothing of a format-2 repo.
func (self *Folder) recheckRepo(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) error {
	read, err := self.repos.Read(ctx, cluster, repoId)
	if err != nil {
		return err
	}
	return checkRepoWritable(read, self.settings.InstanceFormat)
}
