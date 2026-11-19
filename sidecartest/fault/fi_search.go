// What the search invariants read (§22.8's FI-18 to FI-24; TEST-M10-02; D-TEST-14, D-TEST-16, I-19), and FI-18,
// FI-21, FI-23 and FI-24. A schedule hands its Net's SearchRecord what it ran, so FS-74 to FS-80, FS-83 and FS-107
// to FS-112 check these after every step instead of each asserting at its end:
//
//	indexes   each index ref's committed history (AddIndex): every push with the files it wrote, their plaintexts,
//	          and the paths it removed. The oracle replays it with its own codec (fi22.go), never the index's code,
//	          and FI-18's index clauses, FI-19, FI-20 and FI-22 read the replay
//	searches  each search a device ran (RecordSearch): its query, the scope SearchOracle judges it in, its hits as the
//	          engine gave them, what it fetched and asked of servers, and its sync state
//	remote    each remote search (RecordRemoteSearch): the indexer asked and those the rule allowed, the bodies' and
//	          the relay's sizes, and what each device asked of servers and stored while it ran
//
// FI-18, index results, over each recorded search, against SearchOracle (SEARCH-M10-07): every covered document whose
// newest version matches is among the hits; one not covered is a hit from local text or counted not yet searchable;
// every hit names its document's newest version in the scope, so none rests on a masked older one; a verified or
// confirmed hit's newest version matches, and a near hit names its correction; a refused query finds nothing. Over
// each index replay, at every committed version: each document's view, the newest entry over all and the buckets, is
// the newest entry ever committed for it (I3 and I5: no seal, merge, slot reuse, large-entry removal, promotion or
// roll-up changes a result set, and no entry lands below a version a roll-up moved or dropped), but where an erasure's
// CUT lists it; no all row is newer than the newest bucket entry of its key (I4); and no entry is of the reserved kind 2,
// which the codec refuses (I1 with full entries only, QD-1036).
//
// FI-21, search scope and taint, over each recorded search: every hit is from a repo the scope's reader reads, never a
// secret, config or mailcfg repo; a repo read by an EvsShare or as an audit reader shows hits only once its read
// receipts were acknowledged; and of what a search tool returned to a run, an untrusted hit (or one whose trust is
// unjudged, which reads untrusted) is a text-free stub unless its text was asked for, and a result carrying untrusted
// text returns only after the run's taint was fsynced. That no query, hit or cursor leaves the device but a
// remote search's is the capture's scan for query canaries (§22.7's query-canaries row), not re-done here.
//
// FI-23, fetch privacy: searches from one sync state fetch the same index objects in the same order and send servers the
// same requests (sidecartest.RequestTraceEqual), whatever their queries. A search recorded with no sync state cannot be
// compared and fails closed.
//
// FI-24, remote search, over each recorded remote search (§11.14's remote rows; owner decisions 175, 178, 609): the
// indexer asked is one the rule allowed at the send, for repos both devices read, an owner-bound repo only on a device
// its owner consented, another member's only after that member's notice; every hit names a repo the request named and the
// requester reads, and a verified hit matches by the oracle; each request body is 4,016 B and each reply steps x 16,384 B;
// neither device asks evs, api or gkm anything while it runs (an early sync before answering fails here); nothing either
// stores, nor the served record, holds the query or a hit; and searches of one kind show the relay one frame-size
// sequence (sidecartest.FrameSizesEqual), so an early short reply fails. C19's window accounting is gone (QD-1038): the
// pair's contracts report as any peer's, which nothing here reads.

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	_ = RegisterInvariant(18, func(ctx context.Context, oracle *Oracle) error {
		return checkFi18(ctx, oracle)
	})
	_ = RegisterInvariant(21, func(ctx context.Context, oracle *Oracle) error {
		return checkFi21(ctx, oracle)
	})
	_ = RegisterInvariant(23, func(ctx context.Context, oracle *Oracle) error {
		return checkFi23(ctx, oracle)
	})
	_ = RegisterInvariant(24, func(ctx context.Context, oracle *Oracle) error {
		return checkFi24(ctx, oracle)
	})
)

// One index ref's committed history, as its store holds it.
type SearchIndexSource interface {
	// Names the ref in a failure.
	Name() string
	// Every committed push of the ref from its first, in commit order. A source gives the same pushes again at every
	// look, those committed since after them.
	IndexPushes(ctx context.Context) ([]*SearchIndexPush, error)
}

// A source that holds its repo's keys, so FI-22 holds each fresh shard to its keyed pad.
type SearchIndexKeys interface {
	// RK_g of the repo, for K_index_g.
	IndexRepoKey(generation uint64) (*sidecar.EvsRepoKey, error)
}

// What an index push was, as the store's flags say.
type SearchIndexPushKind int

const (
	// A writer's push, a merge, a roll-up, a build or a backfill.
	SearchIndexPushIndex SearchIndexPushKind = 0
	// An erasure's CUT, which moves index_epoch.
	SearchIndexPushCut SearchIndexPushKind = 1
	// An erasure's CLOSURE, which rewrites committed files in place.
	SearchIndexPushClosure SearchIndexPushKind = 2
	// A DROP's rewrite of the index, in place.
	SearchIndexPushDrop SearchIndexPushKind = 3
)

// One committed push of an index ref.
type SearchIndexPush struct {
	RefVersion uint64
	SignerId   sidecar.Id
	SignedTime time.Time
	Kind       SearchIndexPushKind
	// The index files it wrote, and the index paths it removed.
	Written []*SearchIndexFile
	Removed []string
}

// One index file version as the store holds it.
type SearchIndexFile struct {
	Path string
	// The path's entry version.
	Version   uint64
	Plaintext []byte
	// What its entry version carries, nil where the source names none.
	ContentSha256 []byte
}

// One search a device ran.
type SearchRun struct {
	// Names the search in a failure: its host and a label for its query, never the query alone.
	Label string
	// The query as the person gave it, and the scope SearchOracle judges it in: the reader, its repos and the
	// partitions the device holds.
	Query string
	Scope *sidecartest.SearchScope
	// What its results are held to; nil is the Net's (Net.SearchOracle).
	Oracle *sidecartest.SearchOracle
	// Every hit of every page, as the engine gave them, and the last page's count of changes not yet searchable.
	Hits      []sidecar.SearchHit
	Uncovered int
	// The device's sync state when it ran, as sidecartest.RequestTrace's, its fetch rule and opened results in it;
	// the index objects it fetched while it ran, in order; and its requests of servers while it ran, as
	// PrivacyCapture.RequestLog gives them.
	SyncState string
	Fetches   []string
	Requests  []string
	// Each index source's ref version the device had synced when it ran, by the source's Name, which FI-19's CUT
	// clause reads: a device that applied the CUT returns no erased document.
	SyncedVersions map[string]uint64
	// The hits are what a search tool returned to a run, after §16.10's withhold, which FI-21's withhold and taint
	// clauses read; an engine's hits before the tool layer (SearchEngine.Search) are held to their scope alone.
	Returned bool
	// Whether the run asked for untrusted hits' text, and whether its taint was fsynced before this result returned
	// (I-9).
	TextAsked    bool
	TaintFsynced bool
	// The repos the reader reads by an EvsShare or as an audit reader, which need read receipts, and those whose
	// receipts evs acknowledged before the device decrypted their index objects.
	ReceiptRepoIds      []sidecar.Id
	AcknowledgedRepoIds []sidecar.Id
}

// One remote search, as both devices and the relay saw it.
type RemoteSearchRun struct {
	Label string
	Query string
	// The indexer the requester sent to, and those §11.14's rule let answer at the send.
	IndexerId          sidecar.Id
	EligibleIndexerIds []sidecar.Id
	// The repos the request named, and those the requester and the indexer read.
	NamedRepoIds     []sidecar.Id
	RequesterRepoIds []sidecar.Id
	IndexerRepoIds   []sidecar.Id
	// Each owner-bound repo among those named, with the devices its owner consented: the only ones that may answer
	// for it.
	OwnerBoundRepoDeviceIds map[sidecar.Id][]sidecar.Id
	// The indexer is another member's device, and whether that member's notice stood at the send.
	OtherMember bool
	NoticeStood bool
	// What came back, and the scope and oracle a verified hit is held to; a nil scope leaves that clause to FI-18's
	// recorded search.
	Hits   []sidecar.SearchHit
	Scope  *sidecartest.SearchScope
	Oracle *sidecartest.SearchOracle
	// The steps asked, each request body's size and each reply's.
	Steps             int
	RequestByteCounts []int
	ReplyByteCounts   []int
	// What the relay carried for the pair while it ran, and its kind (sidecartest.FrameSizesEqual).
	Frames *sidecartest.FrameSizeTrace
	// What each device asked of servers while it ran, as PrivacyCapture.RequestLog gives them.
	RequesterRequests []string
	IndexerRequests   []string
	// What either device stored while it ran, and the indexer's served record.
	Stored       [][]byte
	ServedRecord []byte
}

// The sizes and servers FI-24 holds a remote search to: the protocol's values (D-EVS-59), read here apart from the
// code that sends them.
type Fi24Settings struct {
	RequestByteCount int
	StepByteCount    int
	// The engines a remote search must not reach, by RequestLog's engine prefix.
	ForbiddenEngines []string
}

func DefaultFi24Settings() *Fi24Settings {
	return &Fi24Settings{RequestByteCount: 4016, StepByteCount: 16384, ForbiddenEngines: []string{"evs", "api", "gkm"}}
}

// A Net's search facts: see the file header. Safe for concurrent use.
type SearchRecord struct {
	net *Net

	stateLock sync.Mutex
	indexes   []SearchIndexSource
	searches  []*SearchRun
	remotes   []*RemoteSearchRun
	// erasures a schedule saw complete, by source name and erasure id hex
	completed map[string]map[string]bool
	format    *OracleIndexFormatSettings
	remote    *Fi24Settings
	// each source's replay, by source
	replays map[SearchIndexSource]*searchReplay
	// each recorded search's findings by FI-18 and FI-21, judged once, at the first check after it was recorded,
	// against the oracle's ledger as it stood when the search ran
	fi18Judged map[*SearchRun][]error
	fi21Judged map[*SearchRun][]error
}

var searchRecords sync.Map

// The Net's search record, made at first use; it goes with the Net.
func SearchRecordOf(net *Net) *SearchRecord {
	return netMemoryOf(&searchRecords, net, func() *SearchRecord {
		return &SearchRecord{
			net:        net,
			completed:  map[string]map[string]bool{},
			format:     DefaultOracleIndexFormatSettings(),
			remote:     DefaultFi24Settings(),
			replays:    map[SearchIndexSource]*searchReplay{},
			fi18Judged: map[*SearchRun][]error{},
			fi21Judged: map[*SearchRun][]error{},
		}
	})
}

// The findings of judge on each recorded search, each judged once and kept: a search is held to the oracle's ledger as
// it stood at the first check after the step that ran it, so a schedule records a search in a step of its own and
// changes the ledger after it.
func (self *SearchRecord) judgedOnce(judged map[*SearchRun][]error, judge func(run *SearchRun) []error) []error {
	_, searches, _, _ := self.snapshot()
	errs := []error{}
	for _, run := range searches {
		self.stateLock.Lock()
		findings, ok := judged[run]
		self.stateLock.Unlock()
		if !ok {
			findings = judge(run)
			self.stateLock.Lock()
			judged[run] = findings
			self.stateLock.Unlock()
		}
		errs = append(errs, findings...)
	}
	return errs
}

// Adds an index ref whose history FI-18, FI-19, FI-20 and FI-22 replay.
func (self *SearchRecord) AddIndex(source SearchIndexSource) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.indexes = append(self.indexes, source)
}

// Records a search a device ran, a copy.
func (self *SearchRecord) RecordSearch(run *SearchRun) {
	copied := *run
	copied.Hits = slices.Clone(run.Hits)
	copied.Fetches = slices.Clone(run.Fetches)
	copied.Requests = slices.Clone(run.Requests)
	copied.SyncedVersions = maps.Clone(run.SyncedVersions)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.searches = append(self.searches, &copied)
}

// Records a remote search, a copy.
func (self *SearchRecord) RecordRemoteSearch(run *RemoteSearchRun) {
	copied := *run
	copied.Hits = slices.Clone(run.Hits)
	copied.RequesterRequests = slices.Clone(run.RequesterRequests)
	copied.IndexerRequests = slices.Clone(run.IndexerRequests)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.remotes = append(self.remotes, &copied)
}

// Records that an erasure of source's ref completed, which FI-19 holds from then on; one the erasure set stops listing
// reads complete too.
func (self *SearchRecord) CompleteErasure(source string, erasureId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.completed[source] == nil {
		self.completed[source] = map[string]bool{}
	}
	self.completed[source][fmt.Sprintf("%x", erasureId.Bytes())] = true
}

// Sets the format limits the oracle reads the index with, and the sizes FI-24 holds remote search to.
func (self *SearchRecord) SetSettings(format *OracleIndexFormatSettings, remote *Fi24Settings) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if format != nil {
		self.format = format
	}
	if remote != nil {
		self.remote = remote
	}
}

func (self *SearchRecord) snapshot() ([]SearchIndexSource, []*SearchRun, []*RemoteSearchRun, *Fi24Settings) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.indexes), slices.Clone(self.searches), slices.Clone(self.remotes), self.remote
}

func (self *SearchRecord) completedErasures(source string) map[string]bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return maps.Clone(self.completed[source])
}

func (self *SearchRecord) oracleOf(oracle *sidecartest.SearchOracle) *sidecartest.SearchOracle {
	if oracle != nil {
		return oracle
	}
	return self.net.SearchOracle()
}

// --- the index replay ---

// One key's newest entry, as the replay judges it: a version, and whether it is live.
type searchNewest struct {
	version uint64
	live    bool
	// the entry, for a roll-up's moved postings
	entry *oracleIndexEntry
}

func (self searchNewest) String() string {
	if !self.live {
		return fmt.Sprintf("deleted at %d", self.version)
	}
	return fmt.Sprintf("live at %d", self.version)
}

// Whether a is newer than b: the higher version, and at one version a tombstone over a live entry.
func searchNewer(a *oracleIndexEntry, b *oracleIndexEntry) bool {
	if a.version != b.version {
		return b.version < a.version
	}
	return !a.live() && b.live()
}

// One key of one root.
type searchRootKey struct {
	root uint32
	key  [16]byte
}

// One erasure as the erasure set listed it.
type searchErasureSeen struct {
	id string
	// the ref version of the push that first listed it: its CUT
	cutVersion uint64
	docs       map[[16]byte]uint64
	// no longer listed
	dropped bool
	// held at the head once complete
	completionChecked bool
}

// What the replay holds of one source, carried across checks: the history is append-only, so each check replays only
// what committed since.
type searchReplay struct {
	name   string
	source SearchIndexSource
	keys   SearchIndexKeys
	// a read of the source that failed, which every check reports
	readErr  error
	replayed int
	// the head's files, decoded, by path; nil where a file did not decode
	files map[string]*oracleIndexFile
	// every key's newest committed entry, and the head's paths holding each key
	everNewest map[searchRootKey]*oracleIndexEntry
	keyPaths   map[searchRootKey]map[string]bool
	erasures   map[string]*searchErasureSeen
	// each erased doc_key's highest listed version, with the earliest CUT listing it
	erased map[[16]byte]uint64
	// the ref versions each bucket start was rolled at
	rolled map[uint32]uint64
	// each invariant's findings so far
	fi18Findings []error
	fi19Findings []error
	fi20Findings []error
	fi22Findings []error
	// the ref version replayed through
	refVersion uint64
}

func (self *SearchRecord) replayOf(source SearchIndexSource) *searchReplay {
	replay, ok := self.replays[source]
	if !ok {
		replay = &searchReplay{
			name:       source.Name(),
			source:     source,
			files:      map[string]*oracleIndexFile{},
			everNewest: map[searchRootKey]*oracleIndexEntry{},
			keyPaths:   map[searchRootKey]map[string]bool{},
			erasures:   map[string]*searchErasureSeen{},
			erased:     map[[16]byte]uint64{},
			rolled:     map[uint32]uint64{},
		}
		if keys, ok := source.(SearchIndexKeys); ok {
			replay.keys = keys
		}
		self.replays[source] = replay
	}
	return replay
}

// Every source's replay, brought to its source's newest push. One replay serves every search invariant at a check.
func searchReplaysOf(ctx context.Context, oracle *Oracle) []*searchReplay {
	record := SearchRecordOf(oracle.Net)
	record.stateLock.Lock()
	defer record.stateLock.Unlock()
	replays := []*searchReplay{}
	for _, source := range record.indexes {
		replay := record.replayOf(source)
		if replay.readErr == nil {
			pushes, err := source.IndexPushes(ctx)
			if err != nil {
				replay.readErr = err
			} else {
				for _, push := range pushes[min(replay.replayed, len(pushes)):] {
					replay.apply(push, record.format, record.completed[replay.name])
				}
				replay.replayed = max(replay.replayed, len(pushes))
			}
		}
		replays = append(replays, replay)
	}
	return replays
}

// The newest entry of key over the head's files holding it, erased versions masked, and over all and the buckets
// apart.
func (self *searchReplay) newestAt(rootKey searchRootKey) (*oracleIndexEntry, *oracleIndexEntry, *oracleIndexEntry) {
	var newest, allNewest, bucketNewest *oracleIndexEntry
	for path := range self.keyPaths[rootKey] {
		file := self.files[path]
		if file == nil {
			continue
		}
		for _, entry := range file.keyedEntries() {
			if entry.key != rootKey.key || entry.version <= self.erased[entry.key] {
				continue
			}
			if newest == nil || searchNewer(entry, newest) {
				newest = entry
			}
			if file.path.kind == oracleIndexPathAllShard {
				if allNewest == nil || searchNewer(entry, allNewest) {
					allNewest = entry
				}
			} else if bucketNewest == nil || searchNewer(entry, bucketNewest) {
				bucketNewest = entry
			}
		}
	}
	return newest, allNewest, bucketNewest
}

func searchNewestOf(entry *oracleIndexEntry) searchNewest {
	if entry == nil {
		return searchNewest{}
	}
	return searchNewest{version: entry.version, live: entry.live(), entry: entry}
}

// Whether two newest entries read alike to a search: both absent, or both live at one version.
func searchSameView(a *oracleIndexEntry, b *oracleIndexEntry) bool {
	aLive := a != nil && a.live()
	bLive := b != nil && b.live()
	if !aLive || !bLive {
		return aLive == bLive
	}
	return a.version == b.version
}

// Replays one push: FI-22 on what it wrote, then the head moves, then FI-19's, FI-20's and FI-18's index clauses on
// the keys it touched.
func (self *searchReplay) apply(push *SearchIndexPush, settings *OracleIndexFormatSettings, completed map[string]bool) {
	if push.RefVersion <= self.refVersion {
		self.fi22Findings = append(self.fi22Findings, fmt.Errorf("%s: ref version %d after %d", self.name, push.RefVersion, self.refVersion))
	}
	self.refVersion = push.RefVersion
	before := maps.Clone(self.files)
	touched := map[searchRootKey]bool{}
	touch := func(file *oracleIndexFile) {
		if file == nil {
			return
		}
		for _, entry := range file.keyedEntries() {
			touched[searchRootKey{root: file.path.root, key: entry.key}] = true
		}
	}
	unlink := func(path string) {
		file := self.files[path]
		touch(file)
		if file != nil {
			for _, entry := range file.keyedEntries() {
				rootKey := searchRootKey{root: file.path.root, key: entry.key}
				delete(self.keyPaths[rootKey], path)
			}
		}
		delete(self.files, path)
	}
	for _, path := range push.Removed {
		if _, ok := self.files[path]; !ok {
			self.fi22Findings = append(self.fi22Findings, fmt.Errorf("%s: ref version %d removes %s, which the head does not hold", self.name, push.RefVersion, path))
		}
		unlink(path)
	}
	written := map[string]*oracleIndexFile{}
	for _, file := range push.Written {
		read, err := oracleIndexDecode(file.Path, file.Plaintext, settings)
		self.fi22Findings = append(self.fi22Findings, fi22Judge(push, file, read, err, self.keys, settings)...)
		if err == nil && read != nil && !read.newer {
			canonical, encodeErr := oracleIndexEncode(read, settings)
			if encodeErr != nil || !bytes.Equal(canonical, file.Plaintext) {
				// what the bytes do not say canonically is not read: FI-22 names it
				read = nil
			}
		}
		if err != nil {
			read = nil
		}
		unlink(file.Path)
		self.files[file.Path] = read
		written[file.Path] = read
		if read == nil {
			self.fi18Findings = append(self.fi18Findings, fmt.Errorf("%s: ref version %d wrote %s, which the oracle cannot read, so no result over it is judged", self.name, push.RefVersion, file.Path))
			continue
		}
		touch(read)
		for _, entry := range read.keyedEntries() {
			rootKey := searchRootKey{root: read.path.root, key: entry.key}
			if self.keyPaths[rootKey] == nil {
				self.keyPaths[rootKey] = map[string]bool{}
			}
			self.keyPaths[rootKey][file.Path] = true
		}
	}
	self.fi19Apply(push, written, completed)
	self.fi20Apply(push, before, written)
	// FI-18's view: each touched key's newest entry ever committed, then the head's
	for _, file := range written {
		if file == nil {
			continue
		}
		for _, entry := range file.keyedEntries() {
			rootKey := searchRootKey{root: file.path.root, key: entry.key}
			if current := self.everNewest[rootKey]; current == nil || searchNewer(entry, current) {
				self.everNewest[rootKey] = entry
			}
		}
	}
	for _, rootKey := range slices.SortedFunc(maps.Keys(touched), func(a searchRootKey, b searchRootKey) int {
		if a.root != b.root {
			return int(a.root) - int(b.root)
		}
		return bytes.Compare(a.key[:], b.key[:])
	}) {
		expected := self.everNewest[rootKey]
		if expected != nil && expected.version <= self.erased[rootKey.key] {
			expected = nil
		}
		newest, allNewest, bucketNewest := self.newestAt(rootKey)
		if !searchSameView(newest, expected) {
			self.fi18Findings = append(self.fi18Findings, fmt.Errorf("%s: after ref version %d, doc_key %x reads %s where its newest committed entry is %s",
				self.name, push.RefVersion, rootKey.key, searchViewString(newest), searchViewString(expected)))
		}
		if allNewest != nil && allNewest.live() && bucketNewest != nil && bucketNewest.version < allNewest.version {
			self.fi18Findings = append(self.fi18Findings, fmt.Errorf("%s: after ref version %d, all's row of doc_key %x at %d is newer than its newest bucket entry at %d (I4)",
				self.name, push.RefVersion, rootKey.key, allNewest.version, bucketNewest.version))
		}
	}
}

func searchViewString(entry *oracleIndexEntry) string {
	if entry == nil {
		return "absent"
	}
	return searchNewestOf(entry).String()
}

// --- FI-18 ---

func checkFi18(ctx context.Context, oracle *Oracle) error {
	errs := []error{}
	for _, replay := range searchReplaysOf(ctx, oracle) {
		if replay.readErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", replay.name, replay.readErr))
			continue
		}
		errs = append(errs, replay.fi18Findings...)
	}
	record := SearchRecordOf(oracle.Net)
	errs = append(errs, record.judgedOnce(record.fi18Judged, func(run *SearchRun) []error { return fi18CheckSearch(record, run) })...)
	return errors.Join(errs...)
}

// A hit's document as the oracle keys it.
type searchDocument struct {
	repoId sidecar.Id
	refId  sidecar.Id
	docKey [16]byte
}

func searchDocumentOf(key *sidecartest.DocumentKey) searchDocument {
	return searchDocument{repoId: key.RepoId, refId: key.RefId, docKey: key.DocKey}
}

func searchHitDocument(hit *sidecar.SearchHit) searchDocument {
	return searchDocument{repoId: hit.Repo, refId: hit.Ref, docKey: hit.DocKey}
}

func fi18CheckSearch(record *SearchRecord, run *SearchRun) []error {
	searchOracle := record.oracleOf(run.Oracle)
	matches, covered, err := searchOracle.Judge(run.Query, run.Scope)
	refused := errors.Is(err, sidecartest.ErrSearchOracleQueryRefused)
	if err != nil && !refused {
		return []error{fmt.Errorf("%s: the oracle cannot judge it: %w", run.Label, err)}
	}
	documents, err := searchOracle.Documents(run.Scope)
	if err != nil {
		return []error{fmt.Errorf("%s: the oracle cannot judge it: %w", run.Label, err)}
	}
	errs := []error{}
	if refused {
		if 0 < len(run.Hits) {
			errs = append(errs, fmt.Errorf("%s: a query §16.10's limits refuse found %d hits", run.Label, len(run.Hits)))
		}
		return errs
	}
	newest := map[searchDocument]*sidecartest.DocumentKey{}
	for _, document := range documents {
		newest[searchDocumentOf(document)] = document
	}
	matching := map[searchDocument]*sidecartest.DocumentKey{}
	for _, match := range matches {
		matching[searchDocumentOf(match)] = match
	}
	isCovered := map[searchDocument]bool{}
	for _, document := range covered {
		isCovered[searchDocumentOf(document)] = true
	}
	hit := map[searchDocument]bool{}
	for index := range run.Hits {
		found := &run.Hits[index]
		document := searchHitDocument(found)
		hit[document] = true
		standing := newest[document]
		switch {
		case standing == nil:
			// a hit outside the scope's readable repos is FI-21's; any other document the scope does not hold is this
		case standing.Version != found.Version:
			errs = append(errs, fmt.Errorf("%s: a hit on %s at version %d rests on a masked version, the newest being %d", run.Label, found.Path, found.Version, standing.Version))
		}
		switch found.State {
		case sidecar.SearchVerified, sidecar.SearchConfirmed:
			if matching[document] == nil && found.Correction == "" {
				errs = append(errs, fmt.Errorf("%s: %s is labeled %d, and its newest version does not hold the query", run.Label, found.Path, found.State))
			}
		case sidecar.SearchNear:
			if found.Correction == "" {
				errs = append(errs, fmt.Errorf("%s: a near hit on %s names no correction", run.Label, found.Path))
			}
		}
	}
	missingUncovered := 0
	for _, match := range matches {
		document := searchDocumentOf(match)
		if hit[document] {
			continue
		}
		if isCovered[document] {
			errs = append(errs, fmt.Errorf("%s: %s, covered and holding the query at version %d, is among no hit", run.Label, match.Name, match.Version))
			continue
		}
		missingUncovered += 1
	}
	if 0 < missingUncovered && run.Uncovered == 0 {
		errs = append(errs, fmt.Errorf("%s: %d documents not yet covered hold the query, are among no hit, and the search reported nothing not yet searchable", run.Label, missingUncovered))
	}
	return errs
}

// --- FI-21 ---

func checkFi21(ctx context.Context, oracle *Oracle) error {
	record := SearchRecordOf(oracle.Net)
	return errors.Join(record.judgedOnce(record.fi21Judged, func(run *SearchRun) []error { return fi21CheckSearch(record, run) })...)
}

func fi21CheckSearch(record *SearchRecord, run *SearchRun) []error {
	searchOracle := record.oracleOf(run.Oracle)
	repoIds, err := searchOracle.ScopeRepoIds(run.Scope)
	if err != nil {
		return []error{fmt.Errorf("%s: the oracle cannot judge its scope: %w", run.Label, err)}
	}
	errs := []error{}
	untrustedText := false
	for index := range run.Hits {
		found := &run.Hits[index]
		if !slices.Contains(repoIds, found.Repo) {
			errs = append(errs, fmt.Errorf("%s: a hit on %s from repo %s, which the scope's reader does not read or which no search reaches", run.Label, found.Path, found.Repo))
		}
		if slices.Contains(run.ReceiptRepoIds, found.Repo) && !slices.Contains(run.AcknowledgedRepoIds, found.Repo) {
			errs = append(errs, fmt.Errorf("%s: a hit from repo %s, read by a share, before evs acknowledged its read receipts", run.Label, found.Repo))
		}
		untrusted := found.Trust == "" || found.Trust == sidecar.SearchTrustUntrusted
		hasText := found.Snippet != "" || slices.ContainsFunc(found.Fields, func(field sidecar.SearchField) bool { return field.Text != "" })
		if run.Returned && untrusted && hasText {
			untrustedText = true
			if !run.TextAsked {
				errs = append(errs, fmt.Errorf("%s: an untrusted hit on %s carries its text, which was not asked for", run.Label, found.Path))
			}
		}
	}
	if untrustedText && !run.TaintFsynced {
		errs = append(errs, fmt.Errorf("%s: a result carrying untrusted text returned before the run's taint was fsynced", run.Label))
	}
	return errs
}

// --- FI-23 ---

func checkFi23(ctx context.Context, oracle *Oracle) error {
	_, searches, _, _ := SearchRecordOf(oracle.Net).snapshot()
	errs := []error{}
	stateRuns := map[string][]*SearchRun{}
	states := []string{}
	for _, run := range searches {
		if run.SyncState == "" {
			errs = append(errs, fmt.Errorf("%s names no sync state, so its fetches cannot be compared", run.Label))
			continue
		}
		if _, ok := stateRuns[run.SyncState]; !ok {
			states = append(states, run.SyncState)
		}
		stateRuns[run.SyncState] = append(stateRuns[run.SyncState], run)
	}
	for _, state := range states {
		runs := stateRuns[state]
		if len(runs) < 2 {
			continue
		}
		fetches := []*sidecartest.RequestTrace{}
		requests := []*sidecartest.RequestTrace{}
		for _, run := range runs {
			fetches = append(fetches, &sidecartest.RequestTrace{Label: run.Label, SyncState: state, Requests: run.Fetches})
			requests = append(requests, &sidecartest.RequestTrace{Label: run.Label, SyncState: state, Requests: run.Requests})
		}
		if err := sidecartest.RequestTraceEqual(fetches...); err != nil {
			errs = append(errs, fmt.Errorf("fetches: %w", err))
		}
		if err := sidecartest.RequestTraceEqual(requests...); err != nil {
			errs = append(errs, fmt.Errorf("requests: %w", err))
		}
	}
	return errors.Join(errs...)
}

// --- FI-24 ---

func checkFi24(ctx context.Context, oracle *Oracle) error {
	record := SearchRecordOf(oracle.Net)
	_, _, remotes, settings := record.snapshot()
	errs := []error{}
	kindTraces := map[string][]*sidecartest.FrameSizeTrace{}
	kinds := []string{}
	for _, run := range remotes {
		errs = append(errs, fi24CheckRemote(record, run, settings)...)
		if run.Frames != nil {
			if _, ok := kindTraces[run.Frames.Kind]; !ok {
				kinds = append(kinds, run.Frames.Kind)
			}
			kindTraces[run.Frames.Kind] = append(kindTraces[run.Frames.Kind], run.Frames)
		} else {
			errs = append(errs, fmt.Errorf("%s: no relay capture, so its frame sizes cannot be compared", run.Label))
		}
	}
	for _, kind := range kinds {
		if traces := kindTraces[kind]; 2 <= len(traces) {
			if err := sidecartest.FrameSizesEqual(traces...); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func fi24CheckRemote(record *SearchRecord, run *RemoteSearchRun, settings *Fi24Settings) []error {
	errs := []error{}
	fail := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", run.Label, fmt.Sprintf(format, a...)))
	}
	if !slices.Contains(run.EligibleIndexerIds, run.IndexerId) {
		fail("the query left for indexer %s, which the rule did not let answer at the send", run.IndexerId)
	}
	if run.OtherMember && !run.NoticeStood {
		fail("the query left for another member's indexer before that member's notice")
	}
	for _, repoId := range run.NamedRepoIds {
		if !slices.Contains(run.RequesterRepoIds, repoId) || !slices.Contains(run.IndexerRepoIds, repoId) {
			fail("the request named repo %s, which both devices do not read", repoId)
		}
		if devices, ok := run.OwnerBoundRepoDeviceIds[repoId]; ok && !slices.Contains(devices, run.IndexerId) {
			fail("the request named owner-bound repo %s to a device its owner did not consent", repoId)
		}
	}
	for index := range run.Hits {
		found := &run.Hits[index]
		if !slices.Contains(run.NamedRepoIds, found.Repo) || !slices.Contains(run.RequesterRepoIds, found.Repo) {
			fail("a hit on %s names repo %s, which the request did not name or the requester does not read", found.Path, found.Repo)
		}
	}
	if run.Scope != nil {
		matches, _, err := record.oracleOf(run.Oracle).Judge(run.Query, run.Scope)
		if err != nil && !errors.Is(err, sidecartest.ErrSearchOracleQueryRefused) {
			fail("the oracle cannot judge it: %v", err)
		} else {
			for index := range run.Hits {
				found := &run.Hits[index]
				if found.State != sidecar.SearchVerified {
					continue
				}
				if !slices.ContainsFunc(matches, func(match *sidecartest.DocumentKey) bool {
					return searchDocumentOf(match) == searchHitDocument(found) && match.Version == found.Version
				}) {
					fail("a verified hit on %s at version %d whose newest version does not hold the query", found.Path, found.Version)
				}
			}
		}
	}
	if len(run.RequestByteCounts) == 0 || len(run.ReplyByteCounts) == 0 || run.Steps < 1 {
		fail("no request or reply sizes, or no steps, so its sizes cannot be judged")
	}
	for _, byteCount := range run.RequestByteCounts {
		if byteCount != settings.RequestByteCount {
			fail("a request body of %d B, not %d", byteCount, settings.RequestByteCount)
		}
	}
	for _, byteCount := range run.ReplyByteCounts {
		if byteCount != run.Steps*settings.StepByteCount {
			fail("a reply of %d B for %d steps, not %d", byteCount, run.Steps, run.Steps*settings.StepByteCount)
		}
	}
	for side, requests := range map[string][]string{"the requester": run.RequesterRequests, "the indexer": run.IndexerRequests} {
		for _, line := range requests {
			for _, engine := range settings.ForbiddenEngines {
				if strings.HasPrefix(line, engine) {
					fail("%s asked %q while it ran", side, line)
				}
			}
		}
	}
	needles := [][]byte{}
	if 0 < len(run.Query) {
		needles = append(needles, []byte(run.Query))
	}
	for index := range run.Hits {
		if run.Hits[index].Path != "" {
			needles = append(needles, []byte(run.Hits[index].Path))
		}
		if run.Hits[index].Snippet != "" {
			needles = append(needles, []byte(run.Hits[index].Snippet))
		}
	}
	for _, needle := range needles {
		for _, stored := range run.Stored {
			if bytes.Contains(stored, needle) {
				fail("a device stored the query or a hit while it ran")
			}
		}
		if bytes.Contains(run.ServedRecord, needle) {
			fail("the served record names the query or a hit")
		}
	}
	return errs
}
