//go:build sidecar_testhooks && !ios_extension && !js

// A search world for sidecartest's fault schedules and the sdk's T4 cells (SEARCH-M10-38; FS-77, FS-109, FS-110): one
// ref's index on an in-memory store standing for evs, and devices that each sync it into a SearchCache of their own
// through SearchSync, under a host's SearchPolicy and conditions, and search it with SearchEngine. A device reads the
// index through a source that seals each file as evs seals a record, takes its bytes at the device's rate on the
// world's clock, and keeps the trace of what it asked for, which is what a device asks evs (FI-23).
//
//	stands in for  evs and the sync engine's EvsRepo source (SEARCH-M10-19's draft builds none), so a schedule here
//	               proves the engines from the source up, and nothing of evs's own reads
//	writes         by the index's own code: a writer's push by indexPlanHead at the view of the head, and a bulk
//	               partition by the shard builder in a merge's key order with its manifest; documents by
//	               IndexDocument's prepare, keyed by doc_key under K_ref of the world's RK_1
//	keys           the world's repo key stands in for gkm's RK_1, which a device's gkm answers at every record it opens,
//	               the point a heap sampler takes (OnRecord)
//	slots          a device's engine admits its searches by Search.DaemonSearchCount's slots, which a heap sampler of
//	               searches at once holds through each collection (HoldSearchSlots)
//	turns          while a device's "search more" runs (Search, scope all), each of its reads waits until a page of the
//	               search waits on the download with nothing left to take: the fake clock moves by reads alone, so a
//	               read that went while a page worked, or between two pages, would charge the search's work with a
//	               read's time it does not take; so a hit's delay after its shard lands is what the page loop itself
//	               spends
//
// Only the sidecar_testhooks build has it, which no release leg is (§22.4). Safe for concurrent use but where a method
// says otherwise.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The world's clock: a fake one a schedule moves, and a device's reads move as they take their bytes.
type SearchTestClock interface {
	Clock
	Advance(timeout time.Duration)
}

// What a world is made of.
type SearchTestWorldArgs struct {
	RepoId Id
	RefId  Id
	Clock  SearchTestClock
	// The repo's kind; zero is a general repo. A config, mailcfg or secret world holds no index a reader follows, and
	// its builders write none (§11.14's never row).
	Kind protocol.RepoKind
}

// One ref's index and the documents written to it.
type SearchTestWorld struct {
	repoId  Id
	refId   Id
	kind    protocol.RepoKind
	clock   SearchTestClock
	format  *IndexFormatSettings
	repoKey *EvsRepoKey
	refKey  []byte
	padKey  *indexPadKey
	ref     *searchTestRef

	// the normalizer is one document at a time
	normalizerLock sync.Mutex
	normalizer     *indexNormalizer
}

// A world over an empty ref, its RK_1 derived from its repo's id.
func NewSearchTestWorld(args *SearchTestWorldArgs) (*SearchTestWorld, error) {
	if args == nil || args.Clock == nil || args.RepoId == (Id{}) || args.RefId == (Id{}) {
		return nil, errors.New("search test world: a repo, a ref and a clock")
	}
	digest := sha256.Sum256(append([]byte("search test world RK_1 "), args.RepoId.Bytes()...))
	repoKey := &EvsRepoKey{repoId: args.RepoId, generation: 1, repoKey: bytes.Clone(digest[:]), firstRepoKey: bytes.Clone(digest[:])}
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		return nil, err
	}
	padKey, err := indexNewPadKey(repoKey)
	if err != nil {
		return nil, err
	}
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return nil, err
	}
	kind := args.Kind
	if kind == protocol.RepoKind_REPO_KIND_UNSPECIFIED {
		kind = protocol.RepoKind_REPO_KIND_GENERAL
	}
	return &SearchTestWorld{
		repoId: args.RepoId, refId: args.RefId, kind: kind, clock: args.Clock, format: DefaultIndexFormatSettings(),
		repoKey: repoKey, refKey: refKey, padKey: padKey, ref: newSearchTestRef(), normalizer: normalizer,
	}, nil
}

// RK_1 as gkm would answer it: what an oracle's ledger keys the repo's doc keys by.
func (self *SearchTestWorld) RepoKey() *EvsRepoKey {
	return self.repoKey
}

// The world's repo.
func (self *SearchTestWorld) RepoId() Id {
	return self.repoId
}

// The world's ref.
func (self *SearchTestWorld) RefId() Id {
	return self.refId
}

// One version of a file, as its writer's push indexes it.
type SearchTestDocument struct {
	Path    string
	Version uint64
	// Field 4, which a file's row shows and a search confirms from without its text.
	Title string
	// The body, which only a host holding the text sees beside the keys.
	Text string
	// The push's signed time, which places the entry in its bucket.
	Time time.Time
}

// A prepared document: its doc_key, key set and row.
type searchTestPrepared struct {
	key  [indexIdByteCount]byte
	keys indexKeySet
	row  *indexRow
}

// The doc_key the world's documents take for path, as every reader of the repo derives it.
func (self *SearchTestWorld) DocKey(path string) ([indexIdByteCount]byte, error) {
	return indexDocKey(self.refKey, self.refId, []byte(path), 0)
}

// Prepares document as a writer does: IndexDocument's normalization, key set and row.
func (self *SearchTestWorld) prepare(document *SearchTestDocument) (*searchTestPrepared, error) {
	indexDocument := &IndexDocument{
		Kind: IndexDocFile, Name: []byte(document.Path), Version: document.Version,
		ByteCount: uint64(len(document.Title) + len(document.Text)),
	}
	indexDocument.Fields[indexFieldTitle] = []byte(document.Title)
	indexDocument.Fields[indexFieldBody] = []byte(document.Text)
	self.normalizerLock.Lock()
	prepared, err := indexDocument.prepare(self.normalizer, false, self.refId, self.format)
	self.normalizerLock.Unlock()
	if err != nil {
		return nil, err
	}
	if prepared.skipped {
		return nil, fmt.Errorf("search test world: %s is skipped by D6", document.Path)
	}
	key, err := self.DocKey(document.Path)
	if err != nil {
		return nil, err
	}
	return &searchTestPrepared{key: key, keys: prepared.keys, row: prepared.row}, nil
}

// The trigram keys a document of text holds and query's terms ask for both, as the index's normalizer and trigram
// extractor give them: a schedule's check that text cannot match query. Empty when they share none.
func (self *SearchTestWorld) QueryTrigramsShared(query string, text string) []string {
	queryDocument, err := self.prepare(&SearchTestDocument{Path: "query", Version: 1, Text: query})
	if err != nil {
		return []string{err.Error()}
	}
	textDocument, err := self.prepare(&SearchTestDocument{Path: "text", Version: 1, Text: text})
	if err != nil {
		return []string{err.Error()}
	}
	shared := []string{}
	for _, key := range queryDocument.keys {
		if slices.Contains(textDocument.keys, key) {
			shared = append(shared, fmt.Sprintf("%06x", key))
		}
	}
	return shared
}

// Every bucket document the head's shards hold, by doc_key, as its locator and version: what a build that collects the
// buckets' keys per search to judge its candidates holds while it searches, which D-EVS-52 forbids and FS-109 plants to
// show its check catches it.
func (self *SearchTestWorld) BucketRows() (map[[16]byte]string, error) {
	ref := self.ref
	ref.stateLock.Lock()
	head := ref.states[len(ref.states)-1]
	shards := map[string]*searchTestStored{}
	for path, stored := range head.files {
		if parsed, ok := indexParsePath(path, false); ok && parsed.kind == indexPathBucketShard {
			shards[path] = stored
		}
	}
	ref.stateLock.Unlock()
	rows := map[[16]byte]string{}
	for _, stored := range shards {
		shard, err := indexDecodeShard(stored.plaintext, stored.version.contentSha256[:], false)
		if err != nil {
			return nil, err
		}
		for _, document := range shard.documents {
			rows[document.key] = fmt.Sprintf("%s@%d", document.row.locator, document.version)
		}
	}
	return rows, nil
}

// The path of the head's shard, all's or a bucket's, holding path's document; an error where none does.
func (self *SearchTestWorld) ShardHolding(path string) (string, error) {
	key, err := self.DocKey(path)
	if err != nil {
		return "", err
	}
	ref := self.ref
	ref.stateLock.Lock()
	head := ref.states[len(ref.states)-1]
	shards := map[string]*searchTestStored{}
	for shardPath, stored := range head.files {
		if parsed, ok := indexParsePath(shardPath, false); ok && (parsed.kind == indexPathAllShard || parsed.kind == indexPathBucketShard) {
			shards[shardPath] = stored
		}
	}
	ref.stateLock.Unlock()
	for shardPath, stored := range shards {
		shard, err := indexDecodeShard(stored.plaintext, stored.version.contentSha256[:], false)
		if err != nil {
			return "", err
		}
		for _, document := range shard.documents {
			if document.key == key {
				return shardPath, nil
			}
		}
	}
	return "", fmt.Errorf("search test world: no shard holds %s", path)
}

// The paths of the world's file-mode index.
func (self *SearchTestWorld) paths() indexPaths {
	return indexNewPaths(false, indexRootNumber)
}

// writer's push of documents, planned by indexPlanHead at the view of the head and committed there, as a writer's
// companion of a content push does. A push the planner would merge first or inside, which only a bulk of entries
// asks, is refused: a schedule writes its bulk with WriteShards.
func (self *SearchTestWorld) PushDocuments(ctx context.Context, writer Id, at time.Time, documents []*SearchTestDocument) error {
	pending := []*indexPendingDocument{}
	for _, document := range documents {
		prepared, err := self.prepare(document)
		if err != nil {
			return err
		}
		pending = append(pending, &indexPendingDocument{
			kind: indexEntryFull, key: prepared.key, version: document.Version, keys: prepared.keys, row: prepared.row,
		})
	}
	store := self.ref.store(writer)
	view, err := indexLoadView(ctx, &indexViewArgs{
		store: store, repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, settings: self.format,
	})
	if err != nil {
		return err
	}
	plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: writer, signedTimeMs: at.UnixMilli(), tables: indexLinkedTables(),
		pending: pending, mayMerge: true,
	})
	if err != nil {
		return err
	}
	if plan.mergeFirst || plan.mergeInPush {
		return errors.New("search test world: a push that merges, which a schedule writes as shards")
	}
	_, err = store.Commit(ctx, &indexPush{
		pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: at.UnixMilli(),
		files: plan.files(), removals: plan.removals(),
	})
	return err
}

// Where WriteShards puts a partition.
type SearchTestPartition struct {
	// all's shards, rolled through RolledThroughDay; else a bucket's, of the window from StartDay.
	All              bool
	StartDay         uint32
	RolledThroughDay uint32
	// The most documents a shard takes before the next opens; a shard past the format's cap splits.
	ShardDocumentCount int
}

// A bulk of documents one key set and row share but for their locators, which WriteShards takes at the speed a
// merge needs: Count files at paths of Prefix and a number, version Version, all of Document's text.
type SearchTestBulk struct {
	Prefix   string
	Count    int
	Version  uint64
	Document *SearchTestDocument
}

// Writes documents and bulks as one partition's shards, in a merge's order (doc_key ascending), each shard by the
// shard builder under the world's pad key, and the partition's manifest naming them, in one push by writer: what a
// merge or a roll-up leaves, written at the speed a schedule's bulk needs. The partition must be new.
func (self *SearchTestWorld) WriteShards(ctx context.Context, writer Id, at time.Time, partition *SearchTestPartition, documents []*SearchTestDocument, bulks []*SearchTestBulk) error {
	if partition == nil || partition.ShardDocumentCount <= 0 {
		return errors.New("search test world: a partition and its shard size")
	}
	shardDocuments := []*indexShardDocument{}
	for _, document := range documents {
		prepared, err := self.prepare(document)
		if err != nil {
			return err
		}
		shardDocuments = append(shardDocuments, &indexShardDocument{
			key: prepared.key, version: document.Version, timeSeconds: uint64(document.Time.Unix()), row: prepared.row, keys: prepared.keys,
		})
	}
	for _, bulk := range bulks {
		prepared, err := self.prepare(bulk.Document)
		if err != nil {
			return err
		}
		for index := range bulk.Count {
			path := fmt.Sprintf("%s%d", bulk.Prefix, index)
			key, err := self.DocKey(path)
			if err != nil {
				return err
			}
			row := *prepared.row
			row.locator = path
			shardDocuments = append(shardDocuments, &indexShardDocument{
				key: key, version: bulk.Version, timeSeconds: uint64(bulk.Document.Time.Unix()), row: &row, keys: prepared.keys,
			})
		}
	}
	slices.SortFunc(shardDocuments, func(a *indexShardDocument, b *indexShardDocument) int {
		return bytes.Compare(a.key[:], b.key[:])
	})
	header := func() *protocol.IndexFileHeader {
		if partition.All {
			header := indexNewFileHeader(indexFileAllShard, indexLinkedTables())
			header.PadGeneration = self.padKey.generation
			return header
		}
		header := indexNewFileHeader(indexFileBucketShard, indexLinkedTables())
		header.BucketStartDay = partition.StartDay
		header.BucketDays = indexDefaultWindowDays
		header.PadGeneration = self.padKey.generation
		return header
	}
	files := []*indexPushFile{}
	manifest := &protocol.IndexManifest{}
	if partition.All {
		manifest.RolledThroughDay = partition.RolledThroughDay
	} else {
		manifest.StartDay, manifest.Days = partition.StartDay, indexDefaultWindowDays
	}
	builder := indexNewShardBuilder(false)
	var build func(batch []*indexShardDocument) error
	build = func(batch []*indexShardDocument) error {
		file, err := builder.build(&indexShard{header: header(), documents: batch}, self.padKey)
		if errors.Is(err, errIndexShardFull) && 1 < len(batch) {
			if err := build(batch[:len(batch)/2]); err != nil {
				return err
			}
			return build(batch[len(batch)/2:])
		}
		if err != nil {
			return err
		}
		n := uint32(len(manifest.Shards))
		path := self.paths().allShard(n)
		shard := &protocol.IndexShard{N: n, Docs: uint32(len(batch))}
		if !partition.All {
			path = self.paths().bucketShard(partition.StartDay, n)
		} else {
			first, last := indexDayOf(int64(batch[0].timeSeconds)*1000), indexDayOf(int64(batch[0].timeSeconds)*1000)
			for _, document := range batch {
				day := indexDayOf(int64(document.timeSeconds) * 1000)
				first, last = min(first, day), max(last, day)
			}
			shard.FirstDay, shard.LastDay = first, last
		}
		manifest.Shards = append(manifest.Shards, shard)
		files = append(files, &indexPushFile{path: path, plaintext: file})
		return nil
	}
	for start := 0; start < len(shardDocuments); start += partition.ShardDocumentCount {
		if err := build(shardDocuments[start:min(len(shardDocuments), start+partition.ShardDocumentCount)]); err != nil {
			return err
		}
	}
	manifestPath := self.paths().bucketManifest(partition.StartDay)
	if partition.All {
		manifestPath = self.paths().allManifest()
	}
	encoded, err := indexMarshalSmall(manifest)
	if err != nil {
		return err
	}
	files = append(files, &indexPushFile{path: manifestPath, plaintext: encoded})
	store := self.ref.store(writer)
	head, err := store.Head(ctx)
	if err != nil {
		return err
	}
	_, err = store.Commit(ctx, &indexPush{
		pushId: NewId(), baseVersion: head.version, indexEpoch: head.indexEpoch, signedTimeMs: at.UnixMilli(), files: files,
	})
	return err
}

// The bucket a time falls in, as a general repo's default windows (§11.14's settings row) lay them out from the epoch.
func SearchTestBucketStartDay(at time.Time) uint32 {
	day := indexDayOf(at.UnixMilli())
	return day / indexDefaultWindowDays * indexDefaultWindowDays
}

// The index files the ref holds at its head: path, version and plaintext length, by path.
type SearchTestFile struct {
	Path      string
	Version   uint64
	ByteCount int
	// all's shard, by its path
	AllShard bool
}

// Every file the head lists, by path.
func (self *SearchTestWorld) Files() []SearchTestFile {
	listing, err := self.ref.store(Id{}).List(context.Background(), 0)
	if err != nil {
		return nil
	}
	files := []SearchTestFile{}
	for _, file := range listing.files {
		parsed, ok := indexParsePath(file.path, false)
		files = append(files, SearchTestFile{
			Path: file.path, Version: file.version, ByteCount: file.byteCount, AllShard: ok && parsed.kind == indexPathAllShard,
		})
	}
	return files
}

// The bytes of all's shards at the head.
func (self *SearchTestWorld) AllByteCount() int64 {
	total := int64(0)
	for _, file := range self.Files() {
		if file.AllShard {
			total += int64(file.ByteCount)
		}
	}
	return total
}

// --- the ref, as evs holds it ---

// One ref's index: every version's files, so a replay diffs them. A path but <root>/settings keeps its newest version
// alone readable, as versionless paths do. Beside the index, the ref's content, which content pushes write
// (search_content_testhooks.go): each path's every version.
type searchTestRef struct {
	stateLock       sync.Mutex
	states          []*searchTestState
	removed         map[string]uint64
	contentVersions map[string][]*searchTestContentVersion
	// The store's faults (search_index_testhooks.go): the pushes refused at the storage limit, nil for none, and whether
	// the next commit loses its answer.
	refuse    func(shape SearchTestPushShape) bool
	loseReply bool
}

// One ref version: its head, the push's signer, and every path's readable version; and the content paths the push
// changed, and whether it wrote its signer's index files beside them, as an in-ref writer's push does.
type searchTestState struct {
	head         *indexRefHead
	signer       Id
	files        map[string]*searchTestStored
	contentPaths []string
	inRef        bool
}

// One stored version and its plaintext.
type searchTestStored struct {
	version   *indexFileVersion
	plaintext []byte
}

// An empty ref at version 0.
func newSearchTestRef() *searchTestRef {
	return &searchTestRef{
		states:          []*searchTestState{{head: &indexRefHead{}, files: map[string]*searchTestStored{}}},
		removed:         map[string]uint64{},
		contentVersions: map[string][]*searchTestContentVersion{},
	}
}

// A writer's handle.
type searchTestStore struct {
	ref    *searchTestRef
	signer Id
}

// A handle whose pushes signer signs.
func (self *searchTestRef) store(signer Id) *searchTestStore {
	return &searchTestStore{ref: self, signer: signer}
}

// The state at refVersion, 0 being the head, the lock held.
func (self *searchTestRef) stateAtWithLock(refVersion uint64) (*searchTestState, error) {
	if refVersion == 0 {
		return self.states[len(self.states)-1], nil
	}
	if uint64(len(self.states)) <= refVersion {
		return nil, errors.New("search test ref: past the head")
	}
	return self.states[refVersion], nil
}

// See indexRefStore.
func (self *searchTestStore) Head(ctx context.Context) (*indexRefHead, error) {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	head := *self.ref.states[len(self.ref.states)-1].head
	return &head, nil
}

// See indexRefStore.
func (self *searchTestStore) List(ctx context.Context, refVersion uint64) (*indexListing, error) {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	state, err := self.ref.stateAtWithLock(refVersion)
	if err != nil {
		return nil, err
	}
	head := *state.head
	listing := &indexListing{head: &head}
	for _, stored := range state.files {
		file := *stored.version
		listing.files = append(listing.files, &file)
	}
	slices.SortFunc(listing.files, func(a *indexFileVersion, b *indexFileVersion) int { return strings.Compare(a.path, b.path) })
	return listing, nil
}

// See indexRefStore: a path keeps its newest version alone, as a versionless path does.
func (self *searchTestStore) History(ctx context.Context, path string, refVersion uint64) ([]*indexFileVersion, error) {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	state, err := self.ref.stateAtWithLock(refVersion)
	if err != nil {
		return nil, err
	}
	stored := state.files[path]
	if stored == nil {
		return []*indexFileVersion{}, nil
	}
	file := *stored.version
	return []*indexFileVersion{&file}, nil
}

// See indexRefStore: a version the head no longer keeps is collected.
func (self *searchTestStore) Read(ctx context.Context, file *indexFileVersion) ([]byte, error) {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	stored := self.ref.states[len(self.ref.states)-1].files[file.path]
	if stored == nil || stored.version.version != file.version {
		return nil, fmt.Errorf("search test ref: %w", errIndexCollected)
	}
	return bytes.Clone(stored.plaintext), nil
}

// Commits at the head under each path's CAS and the head's index_epoch, as evs does; a CLOSURE goes elsewhere.
func (self *searchTestStore) Commit(ctx context.Context, push *indexPush) (*indexCommitted, error) {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	return self.ref.commitWithLock(self.signer, push, nil)
}

// Commits push by signer at the head with content's changes beside it, nil for none: one ref version under one CAS,
// each index path's and each content path's held to the version its builder read. A push that writes no index file
// is no index push and names no index_epoch.
func (self *searchTestRef) commitWithLock(signer Id, push *indexPush, content []*searchTestContentChange) (*indexCommitted, error) {
	head := self.states[len(self.states)-1]
	if push.kind == indexPushClosure {
		return nil, errors.New("search test ref: no CLOSURE here")
	}
	if (0 < len(push.files) || 0 < len(push.removals) || push.kind == indexPushCut) && push.indexEpoch != head.head.indexEpoch {
		return nil, &indexRefusal{kind: indexRefusalIndexEpoch}
	}
	if self.refuse != nil && self.refuse(SearchTestPushShape{FileCount: len(push.files), RemovalCount: len(push.removals), Content: 0 < len(content)}) {
		return nil, &indexRefusal{kind: indexRefusalQuota}
	}
	conflicts := []string{}
	for _, file := range push.files {
		current := head.files[file.path]
		if (current == nil && file.replaces != 0) || (current != nil && current.version.version != file.replaces) {
			conflicts = append(conflicts, file.path)
		}
	}
	for _, removal := range push.removals {
		if current := head.files[removal.path]; current == nil || current.version.version != removal.version {
			conflicts = append(conflicts, removal.path)
		}
	}
	for _, change := range content {
		if self.contentStandingWithLock(change.path, head.head.version) != change.replaces {
			conflicts = append(conflicts, change.path)
		}
	}
	if 0 < len(conflicts) {
		slices.Sort(conflicts)
		return nil, &indexRefusal{kind: indexRefusalConflict, paths: slices.Compact(conflicts)}
	}
	next := self.nextStateWithLock(head, push.pushId, push.signedTimeMs, signer)
	if push.kind == indexPushCut {
		next.head.indexEpoch = next.head.version
	}
	for _, removal := range push.removals {
		delete(next.files, removal.path)
		self.removed[removal.path] = removal.version + 1
	}
	committed := &indexCommitted{version: next.head.version}
	for _, file := range push.files {
		entryVersion := file.replaces + 1
		if file.replaces == 0 {
			entryVersion = max(push.baseVersion, self.removed[file.path]) + 1
		}
		stored := &searchTestStored{
			version: &indexFileVersion{
				path: file.path, version: entryVersion, commitVersion: next.head.version, contentSha256: sha256.Sum256(file.plaintext),
				byteCount: len(file.plaintext), signerSidecarId: signer, signedTimeMs: push.signedTimeMs,
			},
			plaintext: bytes.Clone(file.plaintext),
		}
		next.files[file.path] = stored
		written := *stored.version
		committed.files = append(committed.files, &written)
	}
	self.applyContentWithLock(next, content)
	next.inRef = 0 < len(content) && (0 < len(push.files) || 0 < len(push.removals))
	self.states = append(self.states, next)
	if self.loseReply {
		self.loseReply = false
		return nil, ErrSearchTestReplyLost
	}
	return committed, nil
}

// The ref version after head, its push's signed time and signer, holding head's files: what a push builds on. Not yet
// a state of the ref.
func (self *searchTestRef) nextStateWithLock(head *searchTestState, pushId Id, signedTimeMs int64, signer Id) *searchTestState {
	version := head.head.version + 1
	chain := sha256.New()
	chain.Write(head.head.chain[:])
	chain.Write(pushId.Bytes())
	chain.Write(binary.BigEndian.AppendUint64(nil, version))
	next := &searchTestState{
		head: &indexRefHead{
			version: version, chain: [sha256.Size]byte(chain.Sum(nil)), indexEpoch: head.head.indexEpoch,
			signedTimeMs: signedTimeMs,
		},
		signer: signer,
		files:  make(map[string]*searchTestStored, len(head.files)),
	}
	for path, stored := range head.files {
		next.files[path] = stored
	}
	return next
}

// --- a device ---

// One fetched file, as a device's source asked for it.
type SearchTestFetch struct {
	Path      string
	Version   uint64
	ByteCount int
	// When its read ended on the world's clock.
	At time.Time
}

// What a device is made of.
type SearchTestDeviceArgs struct {
	// The host class's search settings, §18.4's rows as the host sets them.
	Settings *SidecarSearchSettings
	// The host's reports, read at each decision.
	Conditions func() SearchConditions
	// Bytes a second a read takes on the world's clock; 0 takes none.
	ReadByteRate int64
	// The most one read asks for, §11.9's read limit (the evs client's 32 MiB). Required. A read moves the world's clock
	// at once, so a schedule timing reports at a shard's grain reads a shard at a time.
	ReadByteCount int64
	// Where the device's state lives; "" keeps it in memory.
	StateDirectory string
	// At every record a search opens, gkm being asked for its RK_g: the heap sampler's frame point.
	OnRecord func()
	// A delay each page holding hits spends on the world's clock before it answers: what FS-110 plants in the page loop
	// to show that its arrival clause fails a hit past the bound. Zero plants none.
	AnswerDelay time.Duration
	// The device reads indexed_through from the world's content, as SEARCH-M10-12's coverage reader does
	// (search_content_testhooks.go); false reads none, which claims nothing.
	Coverage bool
}

// One device following the world's ref for search.
type SearchTestDevice struct {
	world    *SearchTestWorld
	args     SearchTestDeviceArgs
	instance *SidecarInstance
	cache    *SearchCache
	sync     *SearchSync
	policy   *SearchPolicy
	engine   *SearchEngine
	source   *searchWorldSource
}

// A fresh device: its own state, cache, sync engine, policy and engine, following the world's ref.
func (self *SearchTestWorld) NewDevice(ctx context.Context, args *SearchTestDeviceArgs) (*SearchTestDevice, error) {
	if args == nil || args.Settings == nil || args.Conditions == nil || args.ReadByteCount <= 0 {
		return nil, errors.New("search test device: settings, conditions and a read limit")
	}
	backend := NewSidecarMemoryBackend()
	if args.StateDirectory != "" {
		var err error
		if backend, err = NewSidecarOsBackend(args.StateDirectory); err != nil {
			return nil, err
		}
	}
	settings := DefaultSidecarSettings()
	settings.Log = NewNoopLogger()
	settings.KeychainSettings.PassMemoryByteCount = 64 * 1024
	settings.KeychainSettings.PassIterationCount = 1
	settings.KeychainSettings.PassThreadCount = 1
	settings.KeychainSettings.AutoLockTimeout = 0
	instance, err := NewSidecarInstance(ctx, &SidecarInstanceArgs{Backend: backend, KeyStore: NewSidecarMemoryKeyStore(), Settings: settings})
	if err != nil {
		return nil, err
	}
	device := &SearchTestDevice{world: self, args: *args, instance: instance}
	fail := func(err error) (*SearchTestDevice, error) {
		device.Close()
		return nil, err
	}
	if err := instance.Unlock(nil); err != nil {
		return fail(err)
	}
	networkId := NewId()
	if _, err := instance.createKeychain(networkId); err != nil {
		return fail(err)
	}
	if device.cache, err = NewSearchCache(ctx, instance.Store(&networkId), args.Settings, self.clock, NewNoopLogger()); err != nil {
		return fail(err)
	}
	if device.policy, err = NewSearchPolicy(&SearchPolicyArgs{Settings: args.Settings, Conditions: args.Conditions, Clock: self.clock}); err != nil {
		return fail(err)
	}
	syncArgs := &searchSyncArgs{
		cache: device.cache, settings: args.Settings, format: self.format, clock: self.clock, log: NewNoopLogger(),
		readPathCount: DefaultEvsFormatSettings().ReadMaxPathCount, readByteCount: args.ReadByteCount, budget: device.policy,
	}
	if args.Coverage {
		syncArgs.coverage = self.contentCoverage
	}
	if device.sync, err = newSearchSync(syncArgs); err != nil {
		return fail(err)
	}
	device.source = &searchWorldSource{world: self, rate: args.ReadByteRate}
	err = device.sync.Follow(&searchSyncRefArgs{
		repoId: self.repoId, refId: self.refId, repoKind: self.kind, source: device.source,
		keepAll:  func() bool { return device.policy.KeepsAll(self.repoId, self.AllByteCount()) },
		mayErase: func(signer Id, signedTimeMs int64) bool { return false },
	})
	// a config, mailcfg or secret repo's index is never followed (FI-17): the device keeps none, and its rounds say so
	if err != nil && !errors.Is(err, ErrSearchSyncUnfollowed) {
		return fail(err)
	}
	gkm := &searchTestGkm{repoKey: self.repoKey, onRecord: args.OnRecord}
	device.engine, err = NewSearchEngine(&SearchEngineArgs{
		Settings: args.Settings, Cache: device.cache, Sync: device.sync, Policy: device.policy, Gkm: gkm, Clock: self.clock,
		Log: NewNoopLogger(), Scope: &searchTestScope{repoId: self.repoId, refId: self.refId, kind: self.kind},
	})
	if err != nil {
		return fail(err)
	}
	return device, nil
}

// Ends the device and its state.
func (self *SearchTestDevice) Close() {
	if self.engine != nil {
		self.engine.Close()
	}
	if self.sync != nil {
		self.sync.Close()
	}
	if self.cache != nil {
		self.cache.Close()
	}
	if self.instance != nil {
		self.instance.Close()
	}
}

// The device's engine, for a host to install on a Sidecar (Sidecar.InstallSearchEngine) so a search reaches it through
// the Sidecar's own calls, as the sdk's T4 cells drive it through the bound SidecarSearch (SDK-M10-06). A search through
// it takes no turns (the file header): its reads go as they come, so a schedule timing a download searches through
// Search.
func (self *SearchTestDevice) Engine() *SearchEngine {
	return self.engine
}

// One round of the ref now: the latest set, and all where the policy keeps it.
func (self *SearchTestDevice) Sync(ctx context.Context) error {
	return self.sync.RunRound(ctx, self.world.repoId, self.world.refId, false)
}

// The background window until ctx's deadline, as an OS grants one (SearchEngine.RunBackgroundSync).
func (self *SearchTestDevice) RunBackgroundSync(ctx context.Context) error {
	return self.engine.RunBackgroundSync(ctx)
}

// Drops the device's index cache, keeping its search state (§5.9's state row).
func (self *SearchTestDevice) DropCache() error {
	return self.engine.DropCache(nil)
}

// What the device fetched so far, in order.
func (self *SearchTestDevice) Fetches() []SearchTestFetch {
	return self.source.fetched()
}

// The cache's bytes in all.
func (self *SearchTestDevice) CacheByteCount() int64 {
	return self.cache.ByteCount()
}

// The most the version table's merges held at once, the ref's runs built at fetch (§5.9's versions row).
func (self *SearchTestDevice) VersionMergeHeldMax() int64 {
	self.sync.stateLock.Lock()
	ref := self.sync.refs[[2]Id{self.world.repoId, self.world.refId}]
	self.sync.stateLock.Unlock()
	if ref == nil || ref.table == nil {
		return 0
	}
	return ref.table.MergeHeldMax()
}

// Holds every free slot of the engine's Search.DaemonSearchCount, so no search of the device is admitted to an open or
// a page until release gives them back, and answers how many searches hold one meanwhile: what a heap sampler of
// searches at once (sidecartest.NewSearchHeapSamplerOfSearches) holds through each collection, so that no search works
// during it but one parked at a sample of its own. A slot frees at a page's end with no word to anyone, so the count
// may name a search letting its slot go as it is taken, which only makes a sampler wait for that search's next sample.
func (self *SearchTestDevice) HoldSearchSlots() (int, func()) {
	daemon := self.engine.limits.daemon
	takenCount := 0
	for full := false; !full; {
		select {
		case daemon <- struct{}{}:
			takenCount += 1
		default:
			full = true
		}
	}
	return cap(daemon) - takenCount, func() {
		for range takenCount {
			<-daemon
		}
	}
}

// The records of the version table's runs, as their metas count them.
func (self *SearchTestDevice) VersionRecordCount() (int64, error) {
	self.sync.stateLock.Lock()
	ref := self.sync.refs[[2]Id{self.world.repoId, self.world.refId}]
	self.sync.stateLock.Unlock()
	if ref == nil || ref.table == nil {
		return 0, nil
	}
	runIds, err := ref.table.RunIds()
	if err != nil {
		return 0, err
	}
	snapshot, err := ref.table.Snapshot(runIds)
	if err != nil {
		return 0, err
	}
	defer snapshot.Close()
	count := int64(0)
	for _, run := range snapshot.runs {
		count += int64(run.meta.Records)
	}
	return count, nil
}

// One page a search gave, and when.
type SearchTestPage struct {
	Hits     []SearchHit
	Progress SearchProgress
	Done     bool
	At       time.Time
}

// One progress report a search gave while it fetched, and when.
type SearchTestReport struct {
	Progress SearchProgress
	At       time.Time
}

// What a search gave, page by page.
type SearchTestSearch struct {
	Pages   []*SearchTestPage
	Reports []*SearchTestReport
	Started time.Time
}

// Every hit of every page, in order.
func (self *SearchTestSearch) Hits() []SearchHit {
	hits := []SearchHit{}
	for _, page := range self.Pages {
		hits = append(hits, page.Hits...)
	}
	return hits
}

// The last page's progress.
func (self *SearchTestSearch) Last() SearchProgress {
	if len(self.Pages) == 0 {
		return SearchProgress{}
	}
	return self.Pages[len(self.Pages)-1].Progress
}

// Runs request to its last page, or to a page that waits (metered, offline, update), within pageCount pages, recording
// each page and each progress report with the world's time. onPage runs after each page, on this goroutine. Meanwhile
// the device's reads take their turns (the file header).
func (self *SearchTestDevice) Search(ctx context.Context, request *SearchRequest, pageCount int, onPage func(page *SearchTestPage)) (*SearchTestSearch, error) {
	search := &SearchTestSearch{Started: self.world.clock.Now()}
	stream, err := self.engine.Search(ctx, request)
	if err != nil {
		return search, err
	}
	source, ok := stream.source.(*searchEngineStream)
	if !ok {
		stream.Close()
		return search, errors.New("search test device: the engine's stream is not its own")
	}
	if delay := self.args.AnswerDelay; 0 < delay {
		source.answerHook = func() {
			self.world.clock.Advance(delay)
		}
	}
	if request.Scope == SearchAll {
		// the turns end after the search does, so no read of its download goes outside them
		self.source.takeTurns(source)
		defer self.source.takeTurns(nil)
	}
	defer stream.Close()
	reportLock := sync.Mutex{}
	report := func(progress SearchProgress) {
		reportLock.Lock()
		defer reportLock.Unlock()
		search.Reports = append(search.Reports, &SearchTestReport{Progress: progress, At: self.world.clock.Now()})
	}
	for range pageCount {
		hits, progress, done, err := source.nextReporting(ctx, report)
		if err != nil {
			return search, err
		}
		page := &SearchTestPage{Hits: hits, Progress: progress, Done: done, At: self.world.clock.Now()}
		search.Pages = append(search.Pages, page)
		if onPage != nil {
			onPage(page)
		}
		if done || progress.Waiting != "" {
			// a search waiting (metered, offline, update) holds until the host repeats it, as an app shows it waiting
			return search, nil
		}
	}
	return search, errors.New("search test device: the search ran past its pages")
}

// A source over the world's ref: replay by diffing versions, a listing of the head, and fetches sealed as evs seals a
// record, each read taking its bytes at the device's rate on the world's clock, in its turn while a search runs.
type searchWorldSource struct {
	world *SearchTestWorld
	rate  int64

	stateLock sync.Mutex
	fetches   []SearchTestFetch
	// The search whose pages a read waits its turn for, nil while none runs, and a channel closed as it changes.
	turns        *searchEngineStream
	turnsChanged chan struct{}
}

// What the source fetched so far, in order.
func (self *searchWorldSource) fetched() []SearchTestFetch {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.fetches)
}

// Makes each read wait its turn on stream's pages from now, or, nil, on none, waking every read that waits.
func (self *searchWorldSource) takeTurns(stream *searchEngineStream) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.turns = stream
	if self.turnsChanged != nil {
		close(self.turnsChanged)
	}
	self.turnsChanged = make(chan struct{})
}

// Waits until a page of the running search, if one runs, waits on "search more" with nothing left to take, the search
// ends, or ctx does: a read's turn.
func (self *searchWorldSource) awaitTurn(ctx context.Context) error {
	for {
		self.stateLock.Lock()
		stream, turnsChanged := self.turns, self.turnsChanged
		self.stateLock.Unlock()
		if stream == nil {
			return nil
		}
		idle, changed := stream.more.idle()
		if idle {
			return nil
		}
		select {
		case <-changed:
		case <-turnsChanged:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// See searchSyncSource: each version after pin diffed against the one before.
func (self *searchWorldSource) Replay(ctx context.Context, pin SearchSyncPin) (*searchSyncReplay, error) {
	ref := self.world.ref
	ref.stateLock.Lock()
	states := slices.Clone(ref.states)
	ref.stateLock.Unlock()
	head := states[len(states)-1].head
	if head.version < pin.Version {
		return nil, errors.New("search test source: a pin past the head")
	}
	replay := &searchSyncReplay{head: head}
	for version := pin.Version + 1; version <= head.version; version += 1 {
		previous, current := states[version-1], states[version]
		statement := &searchSyncStatement{
			version: version, chain: current.head.chain, signedTimeMs: current.head.signedTimeMs, signer: current.signer,
			indexEpoch: previous.head.indexEpoch, cut: current.head.indexEpoch != previous.head.indexEpoch,
		}
		paths := []string{}
		for path, stored := range current.files {
			if old := previous.files[path]; old == nil || old.version.version != stored.version.version {
				paths = append(paths, path)
			}
		}
		for path := range previous.files {
			if current.files[path] == nil {
				paths = append(paths, path)
			}
		}
		slices.Sort(paths)
		for _, path := range paths {
			change := &searchSyncChange{path: path}
			if stored := current.files[path]; stored != nil {
				file := *stored.version
				change.file = &file
			}
			statement.changes = append(statement.changes, change)
		}
		replay.statements = append(replay.statements, statement)
	}
	return replay, nil
}

// See searchSyncSource.
func (self *searchWorldSource) List(ctx context.Context) (*indexListing, error) {
	return self.world.ref.store(Id{}).List(ctx, 0)
}

// See searchSyncSource: each file sealed as evs seals it, the read taking its bytes at the source's rate, in its turn.
func (self *searchWorldSource) Fetch(ctx context.Context, files []*indexFileVersion) ([]*searchSyncFetched, error) {
	if err := self.awaitTurn(ctx); err != nil {
		return nil, err
	}
	ref := self.world.ref
	ref.stateLock.Lock()
	head := ref.states[len(ref.states)-1]
	plaintexts := make([][]byte, len(files))
	for index, file := range files {
		if stored := head.files[file.path]; stored != nil && stored.version.version == file.version {
			plaintexts[index] = stored.plaintext
		}
	}
	ref.stateLock.Unlock()
	byteCount := 0
	fetched := []*searchSyncFetched{}
	for index, file := range files {
		plaintext := plaintexts[index]
		if plaintext == nil {
			fetched = append(fetched, &searchSyncFetched{file: file, collected: true})
			continue
		}
		byteCount += len(plaintext)
		record, err := self.world.seal(file, plaintext)
		if err != nil {
			return nil, err
		}
		fetched = append(fetched, &searchSyncFetched{file: file, record: record})
	}
	if 0 < self.rate && 0 < byteCount {
		self.world.clock.Advance(time.Duration(int64(byteCount) * int64(time.Second) / self.rate))
	}
	at := self.world.clock.Now()
	self.stateLock.Lock()
	for index, file := range files {
		self.fetches = append(self.fetches, SearchTestFetch{Path: file.path, Version: file.version, ByteCount: len(plaintexts[index]), At: at})
	}
	self.stateLock.Unlock()
	return fetched, nil
}

// file's plaintext sealed as evs seals a general repo's kind-5 record under generation 1: its header under
// manifest_1 and its object key's 72 B block under fek_1 (QD-524), with what opens it for the cache's check.
func (self *SearchTestWorld) seal(file *indexFileVersion, plaintext []byte) (*SearchCacheRecord, error) {
	manifestKey, err := NewEvsManifestKey(self.repoKey)
	if err != nil {
		return nil, err
	}
	fekKey, err := NewEvsFekKey(self.repoKey)
	if err != nil {
		return nil, err
	}
	objectKey := NewEvsObjectKey()
	wrapped, err := EvsWrapObjectKey(fekKey, objectKey)
	if err != nil {
		return nil, err
	}
	fileId := NewId()
	header := &EvsRecordHeader{
		RecordId: NewId(), Generation: 1, BodyLength: uint64(len(plaintext)), Kind: protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT,
		KeyRefKind: protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER, OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
	}
	oid := sha256.Sum256([]byte(file.path))
	copy(header.Oid[:20], oid[:20])
	out := &bytes.Buffer{}
	writer := NewEvsRecordWriter()
	if err := writer.Begin(out, manifestKey, objectKey, fileId, header); err != nil {
		return nil, err
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	sealed := out.Bytes()
	opened := writer.Header()
	return &SearchCacheRecord{
		Key:              SearchCacheKey{RepoId: self.repoId, RefId: self.refId, Path: file.path, Version: file.version},
		RefVersion:       file.commitVersion,
		ContentSha256:    sha256.Sum256(plaintext),
		SealedHeader:     sealed[:EvsRecordHeaderByteCount],
		SealedFrames:     sealed[EvsRecordHeaderByteCount:],
		Header:           &opened,
		ObjectKey:        objectKey,
		FileId:           fileId,
		WrappedObjectKey: wrapped,
	}, nil
}

// gkm as a reader of the world's repo holds it: RK_1, every record's key, at each record it opens.
type searchTestGkm struct {
	gkmRefusingClient
	repoKey  *EvsRepoKey
	onRecord func()
}

// See GkmClient: RK_1, the world's one generation.
func (self *searchTestGkm) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return self.RepoKey(ctx, repoId, 1)
}

// See GkmClient: RK_1 of the world's repo, the record hook told first; any other repo or generation is missing.
func (self *searchTestGkm) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	if repoId != self.repoKey.repoId || generation != 1 {
		return nil, ErrGkmKeyMissing
	}
	if self.onRecord != nil {
		self.onRecord()
	}
	return self.repoKey, nil
}

// The world's one repo, readable, its ref the default.
type searchTestScope struct {
	repoId Id
	refId  Id
	kind   protocol.RepoKind
}

// See SearchScopeSource.
func (self *searchTestScope) Repos(ctx context.Context) ([]*SearchScopeRepo, error) {
	return []*SearchScopeRepo{{
		RepoId: self.repoId, Kind: self.kind, Readable: true,
		Refs: []*SearchScopeRef{{RefId: self.refId, Default: true}},
	}}, nil
}
