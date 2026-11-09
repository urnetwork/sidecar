// D-TEST-14's search oracle (§22.4): what a search must find, judged from each repo's newest committed
// versions alone, under the index's published normalization tables, sharing no index code. Search
// schedules check their results against it (FI-18): a desktop's text-verified hits equal Matches, every
// device's candidates include Matches less what Covered leaves out, and each document outside Covered
// is found from local text or reported not yet searchable.
//
// What the oracle reads is the world's SearchLedger: every push a schedule saw commit, with its
// content, and the index facts a schedule observes: which pushes an index push reached and when, the
// erasures, the roll-ups and each ref's index settings. evs's reader does not run on T2 yet (EVS1's and
// EVS2's clients), so the ledger holds what writers committed rather than decrypting evs's objects
// back, and the T2 adapter that reads evs's stores into it is EVS1's and EVS2's to add. The doc_keys
// are the format's, from each repo's own K_ref, so a DocumentKey names the document the index names.
//
// The oracle's readings of what §11.14 and §16.10 leave open, beside those in search_oracle_extract.go:
//   - a term is matched within one document, one chunk with its 256 B overlap
//     (plan-SEARCH-small-readings#2);
//   - words and "quoted phrases" split at whitespace outside quotes, and each is normalized by steps
//     1 to 5 and trimmed of the spaces its edges' punctuation became; a term of 1 or 2 bytes then
//     matches as a whole word, " t " in the text, and a longer one as a substring;
//   - a OR b joins alternatives; -term drops a document whose text holds the term, as a host with the
//     text confirms it; subject:, from:, to: and title: confine a term to that row field, normalized;
//     a query with no term but negated ones matches nothing, and an empty one lists only with filters;
//   - a query whose normalized text passes 512 B, or that has more than 16 terms, is refused, and a
//     search must find nothing for it;
//   - a document's time, for since, until and its bucket, is its entry's: the signed time of the push
//     whose index entry reached it, else, uncovered, of its commit;
//   - network and all breadth search each repo's default ref; repo breadth the ref named, or the
//     default;
//   - an entry whose day falls in no bucket, which only a skewed clock at a boundary gives, goes to the
//     newest bucket starting at or before its day.
//
// Record-class documents (§16.8's entries, run cards, §16.11's directory) are not read yet: AddRepo
// refuses those kinds, so a schedule meeting them fails rather than passing on an empty answer.
//
// Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The format's values the oracle reads (§11.14, §16.10). Facts, not tunables.
const (
	searchOracleDocKeyLabel       = "UR evs 1.0 doc"
	searchOracleQueryByteCount    = 512
	searchOracleQueryTermCount    = 16
	searchOracleDefaultWindowDays = 30
	searchOracleDirectoryWindow   = 7
	searchOracleDayDuration       = 24 * time.Hour
	searchOracleMailboxPrefix     = "m/"
	searchOracleIndexPrefix       = ".ur-index/"
)

var (
	// A ledger change that breaks what evs would commit: an unknown repo, a ref version that does not
	// rise, a version below a path's.
	ErrSearchLedgerInvalid = errors.New("search ledger: invalid")
	// What the oracle does not judge yet; a schedule meeting it fails rather than passing.
	ErrSearchOracleUnsupported = errors.New("search oracle: not supported yet")
	// A query §16.10's limits refuse, for which a search must find nothing.
	ErrSearchOracleQueryRefused = errors.New("search oracle: query refused")
	// A scope that would make every answer empty whatever the ledger holds: no reader, no repo or no
	// network named. A schedule built on one would pass without checking anything.
	ErrSearchOracleScope = errors.New("search oracle: scope names nothing")
)

// A row's doc kind (INDEX-FORMAT.md's Rows).
type SearchDocKind uint8

const (
	SearchDocKindFile    SearchDocKind = 1
	SearchDocKindMail    SearchDocKind = 2
	SearchDocKindRecord  SearchDocKind = 3
	SearchDocKindDerived SearchDocKind = 4
)

// Which partitions a search reads (§5.4's SearchScope).
type SearchScopePartitions int

const (
	// The buckets, and all for the repos SearchScope.AllHeldRepoIds names (§5.4's default).
	SearchScopeCached SearchScopePartitions = 0
	// Phase 1: the buckets not rolled up, and the local layer.
	SearchScopeLatest SearchScopePartitions = 1
	// The buckets and all.
	SearchScopeAll SearchScopePartitions = 2
)

// Which repos a search reads (§16.10's scope; plan-SEARCH-small-readings#8).
type SearchBreadth int

const (
	// Every repo of the networks named that the reader reads, the default.
	SearchBreadthNetwork SearchBreadth = 0
	// The repos named.
	SearchBreadthRepo SearchBreadth = 1
	// Every repo of every network named, as the daemon hosts them.
	SearchBreadthAll SearchBreadth = 2
)

// §22.4's scope of an oracle judgment: partitions and breadth, the reader's rights, dates and filters.
type SearchScope struct {
	Partitions SearchScopePartitions
	// SearchScopeCached: the repos whose all the device holds current.
	AllHeldRepoIds []sidecar.Id
	Breadth        SearchBreadth
	// SearchBreadthRepo: the repos and refs named.
	Repos []*SearchScopeRepo
	// The networks network and all breadth search.
	NetworkIds []sidecar.Id
	// The sidecar searching, which reads a repo only where the ledger names it a reader.
	ReaderId sidecar.Id
	// Inclusive; zero is unbounded.
	Since time.Time
	Until time.Time
	// Nil: none.
	Filters *SearchScopeFilters
}

type SearchScopeRepo struct {
	RepoId sidecar.Id
	// Nil: the repo's default ref.
	RefId *sidecar.Id
}

// §16.10's doc-table filters the oracle reads.
type SearchScopeFilters struct {
	// The locator starts with it.
	PathPrefix string
	// Empty: any.
	DocKinds []SearchDocKind
	// Each holds in its row field.
	Fields []*SearchScopeField
}

// A field:text term: field 1 subject, 2 from, 3 to, 4 title (§11.14's fields).
type SearchScopeField struct {
	Field int
	Text  string
}

func (self *SearchScope) hasFilters() bool {
	return self.Filters != nil &&
		(self.Filters.PathPrefix != "" || 0 < len(self.Filters.DocKinds) || 0 < len(self.Filters.Fields))
}

// A document as §11.14 keys it, at the newest committed version the oracle judged.
type DocumentKey struct {
	RepoId sidecar.Id
	// The document's own ref, which ur/index's documents name too.
	RefId sidecar.Id
	// doc_key = HMAC-SHA256(K_ref, "UR evs 1.0 doc" || ref_id || u16be(len(name)) || name || u32be(chunk))[:16].
	DocKey [16]byte
	// The path or registered name and the chunk, for reading a failure.
	Name    string
	Chunk   uint32
	Version uint64
}

func (self *DocumentKey) String() string {
	return fmt.Sprintf("%s/%s/%s#%d@%d", self.RepoId, self.RefId, self.Name, self.Chunk, self.Version)
}

func compareDocumentKeys(a *DocumentKey, b *DocumentKey) int {
	if c := bytes.Compare(a.RepoId.Bytes(), b.RepoId.Bytes()); c != 0 {
		return c
	}
	if c := bytes.Compare(a.RefId.Bytes(), b.RefId.Bytes()); c != 0 {
		return c
	}
	return bytes.Compare(a.DocKey[:], b.DocKey[:])
}

// One repo as the ledger holds it.
type SearchLedgerRepo struct {
	RepoId    sidecar.Id
	NetworkId sidecar.Id
	Kind      protocol.RepoKind
	// The ref a search reads when none is named.
	DefaultRefId sidecar.Id
	// Any generation of the repo's key that holds RK_1, for K_ref (§10.5).
	Key *sidecar.EvsRepoKey
	// The sidecars that read the repo (RepoReaders, D-ACL-14); one that only deposits is not one.
	ReaderIds []sidecar.Id
}

// A ref's index settings from a time on (§11.14's settings row).
type SearchIndexSettings struct {
	Off bool
	// 0: the kind's default, 30 days, or 7 in the team directory.
	WindowDays uint32
}

// One committed push.
type SearchCommit struct {
	RepoId sidecar.Id
	RefId  sidecar.Id
	// The ref version it committed at, rising on the ref.
	RefVersion uint64
	// Its signed time_ms.
	Time     time.Time
	WriterId sidecar.Id
	Changes  []*SearchChange
	// A DELETE of the ref, a ref tombstone above every document version before it.
	DeleteRef bool
	// The push carried its changes' index entries, as an in-ref push does; false for one that skipped
	// the index, which a later Cover reaches.
	Indexed bool
}

// One path a push changed.
type SearchChange struct {
	Path string
	// The path's entry version (11.7's versions).
	Version uint64
	// The version's bytes; nil removes the path.
	Content []byte
}

// The world's committed state, as the oracle reads it. Schedules record into it what they saw commit.
type SearchLedger struct {
	stateLock   sync.Mutex
	repoIdRepos map[sidecar.Id]*searchLedgerRepo
}

type searchLedgerRepo struct {
	repo      *SearchLedgerRepo
	refKey    []byte
	refIdRefs map[sidecar.Id]*searchLedgerRef
}

type searchLedgerRef struct {
	refId   sidecar.Id
	commits []*searchLedgerCommit
	// commit indexes in the order their index entries landed
	coverOrder    []int
	settings      []*searchLedgerSettings
	erasedThrough map[string]uint64
	rolled        bool
	rolledDay     uint32
}

type searchLedgerCommit struct {
	commit *SearchCommit
	// zero until an index push reached it
	indexedAt time.Time
}

type searchLedgerSettings struct {
	at       time.Time
	settings SearchIndexSettings
}

func NewSearchLedger() *SearchLedger {
	return &SearchLedger{repoIdRepos: map[sidecar.Id]*searchLedgerRepo{}}
}

// Adds a repo. Record-class kinds are ErrSearchOracleUnsupported, since their documents are not read
// yet; config, mailcfg and secret repos are taken, and no search reaches them.
func (self *SearchLedger) AddRepo(repo *SearchLedgerRepo) error {
	switch repo.Kind {
	case protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_MAILBOX,
		protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG,
		protocol.RepoKind_REPO_KIND_SECRET:
	default:
		return fmt.Errorf("%w: %s's documents (§16.8, §16.11)", ErrSearchOracleUnsupported, repo.Kind)
	}
	if repo.Key == nil || repo.Key.RepoId() != repo.RepoId {
		return fmt.Errorf("%w: repo %s has no key of its own", ErrSearchLedgerInvalid, repo.RepoId)
	}
	refKey, err := repo.Key.DeriveKey(sidecar.EvsKeyPurposeRef, nil)
	if err != nil {
		return err
	}
	copied := *repo
	copied.ReaderIds = slices.Clone(repo.ReaderIds)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.repoIdRepos[repo.RepoId]; ok {
		return fmt.Errorf("%w: repo %s added twice", ErrSearchLedgerInvalid, repo.RepoId)
	}
	self.repoIdRepos[repo.RepoId] = &searchLedgerRepo{
		repo:      &copied,
		refKey:    refKey,
		refIdRefs: map[sidecar.Id]*searchLedgerRef{},
	}
	return nil
}

func (self *SearchLedger) refWithLock(repoId sidecar.Id, refId sidecar.Id) (*searchLedgerRef, error) {
	repo, ok := self.repoIdRepos[repoId]
	if !ok {
		return nil, fmt.Errorf("%w: no repo %s", ErrSearchLedgerInvalid, repoId)
	}
	ref, ok := repo.refIdRefs[refId]
	if !ok {
		ref = &searchLedgerRef{refId: refId, erasedThrough: map[string]uint64{}}
		repo.refIdRefs[refId] = ref
	}
	return ref, nil
}

// A ref's index settings from at on, as an admin's settings version (§11.14's settings row).
func (self *SearchLedger) SetIndexSettings(repoId sidecar.Id, refId sidecar.Id, settings *SearchIndexSettings, at time.Time) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref, err := self.refWithLock(repoId, refId)
	if err != nil {
		return err
	}
	if n := len(ref.settings); 0 < n && at.Before(ref.settings[n-1].at) {
		return fmt.Errorf("%w: settings at %s before the last", ErrSearchLedgerInvalid, at)
	}
	ref.settings = append(ref.settings, &searchLedgerSettings{at: at, settings: *settings})
	return nil
}

// Records a committed push.
func (self *SearchLedger) Commit(commit *SearchCommit) error {
	copied := *commit
	copied.Changes = []*SearchChange{}
	for _, change := range commit.Changes {
		changeCopy := *change
		if change.Content != nil {
			changeCopy.Content = bytes.Clone(change.Content)
		}
		copied.Changes = append(copied.Changes, &changeCopy)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref, err := self.refWithLock(commit.RepoId, commit.RefId)
	if err != nil {
		return err
	}
	if n := len(ref.commits); 0 < n && commit.RefVersion <= ref.commits[n-1].commit.RefVersion {
		return fmt.Errorf("%w: ref version %d does not rise", ErrSearchLedgerInvalid, commit.RefVersion)
	}
	newest := searchLedgerNewest(ref.commits)
	for _, change := range copied.Changes {
		if record, ok := newest[change.Path]; ok && change.Version <= record.version {
			return fmt.Errorf("%w: %s at version %d, not above %d", ErrSearchLedgerInvalid, change.Path, change.Version, record.version)
		}
	}
	entry := &searchLedgerCommit{commit: &copied}
	ref.commits = append(ref.commits, entry)
	if copied.Indexed {
		entry.indexedAt = copied.Time
		ref.coverOrder = append(ref.coverOrder, len(ref.commits)-1)
	}
	return nil
}

// An index push reached every commit of the ref at or below throughRefVersion, its entries signed at:
// a companion push or a backfill (§11.14's companion and coverage rows).
func (self *SearchLedger) Cover(repoId sidecar.Id, refId sidecar.Id, throughRefVersion uint64, at time.Time) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref, err := self.refWithLock(repoId, refId)
	if err != nil {
		return err
	}
	for i, entry := range ref.commits {
		if entry.commit.RefVersion <= throughRefVersion && entry.indexedAt.IsZero() {
			entry.indexedAt = at
			ref.coverOrder = append(ref.coverOrder, i)
		}
	}
	return nil
}

// An erasure's CUT listed path's versions through throughVersion: from here every search masks them
// (§11.14's cut row).
func (self *SearchLedger) Erase(repoId sidecar.Id, refId sidecar.Id, path string, throughVersion uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref, err := self.refWithLock(repoId, refId)
	if err != nil {
		return err
	}
	ref.erasedThrough[path] = max(ref.erasedThrough[path], throughVersion)
	return nil
}

// A roll-up committed: a/m's rolled_through_day is day, so every bucket starting at or before it is in
// all (§11.14's roll-up).
func (self *SearchLedger) RolledThrough(repoId sidecar.Id, refId sidecar.Id, day uint32) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref, err := self.refWithLock(repoId, refId)
	if err != nil {
		return err
	}
	if ref.rolled && day < ref.rolledDay {
		return fmt.Errorf("%w: rolled through %d after %d", ErrSearchLedgerInvalid, day, ref.rolledDay)
	}
	ref.rolled = true
	ref.rolledDay = day
	return nil
}

// A path's newest version, by version, among commits.
type searchLedgerRecord struct {
	version uint64
	// nil: removed
	content     []byte
	commitIndex int
}

func searchLedgerNewest(commits []*searchLedgerCommit) map[string]*searchLedgerRecord {
	newest := map[string]*searchLedgerRecord{}
	for i, entry := range commits {
		if entry.commit.DeleteRef {
			for _, record := range newest {
				record.content = nil
				record.commitIndex = i
			}
		}
		for _, change := range entry.commit.Changes {
			if record, ok := newest[change.Path]; ok && change.Version <= record.version {
				continue
			}
			newest[change.Path] = &searchLedgerRecord{version: change.Version, content: change.Content, commitIndex: i}
		}
	}
	return newest
}

// The oracle over a ledger.
type SearchOracle struct {
	ledger *SearchLedger

	stateLock sync.Mutex
	// each path version's documents, by repo, ref, path and version
	versionDocuments map[searchOracleVersionKey][]*searchOracleDocument
}

type searchOracleVersionKey struct {
	repoId  sidecar.Id
	refId   sidecar.Id
	path    string
	version uint64
}

func NewSearchOracle(ledger *SearchLedger) *SearchOracle {
	return &SearchOracle{
		ledger:           ledger,
		versionDocuments: map[searchOracleVersionKey][]*searchOracleDocument{},
	}
}

// The world's search oracle, over its SearchLedger.
func (self *Net) SearchOracle() *SearchOracle {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.searchOracle == nil {
		self.searchOracle = NewSearchOracle(self.searchLedgerWithLock())
	}
	return self.searchOracle
}

// What the world's searches are judged against: a schedule records each push it sees commit here.
func (self *Net) SearchLedger() *SearchLedger {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.searchLedgerWithLock()
}

func (self *Net) searchLedgerWithLock() *SearchLedger {
	if self.searchLedger == nil {
		self.searchLedger = NewSearchLedger()
	}
	return self.searchLedger
}

// What a search of query in scope must find (§22.4). A query §16.10's limits refuse must find nothing.
// A scope the oracle cannot judge, or a build not on normalizer 1's tables, panics: a schedule built on
// it is wrong where it was written.
func (self *SearchOracle) Matches(query string, scope *SearchScope) []*DocumentKey {
	matches, _, err := self.Judge(query, scope)
	if errors.Is(err, ErrSearchOracleQueryRefused) {
		return []*DocumentKey{}
	}
	if err != nil {
		panic(err)
	}
	return matches
}

// The documents in scope whose newest committed version the index covers (§22.4): what every device
// holding the scope's partitions answers from the index, the rest being found from local text or
// reported not yet searchable. Panics as Matches does.
func (self *SearchOracle) Covered(scope *SearchScope) []*DocumentKey {
	_, covered, err := self.Judge("", scope)
	if err != nil && !errors.Is(err, ErrSearchOracleQueryRefused) {
		panic(err)
	}
	return covered
}

// Matches and Covered at once, or why the oracle cannot judge. matches is empty with
// ErrSearchOracleQueryRefused when the query is refused, and covered stands either way.
func (self *SearchOracle) Judge(query string, scope *SearchScope) ([]*DocumentKey, []*DocumentKey, error) {
	if err := searchOracleTablesErr(); err != nil {
		return nil, nil, err
	}
	if scope == nil {
		scope = &SearchScope{}
	}
	parsed, queryErr := searchOracleParseQuery(query)
	candidates, err := self.candidates(scope)
	if err != nil {
		return nil, nil, err
	}
	matches := []*DocumentKey{}
	covered := []*DocumentKey{}
	for _, candidate := range candidates {
		if !candidate.inPartitions || !searchOracleFiltersHold(candidate.document, candidate.name, scope.Filters) {
			continue
		}
		if candidate.covered {
			covered = append(covered, candidate.key)
		}
		if queryErr != nil {
			continue
		}
		if parsed.empty() {
			if scope.hasFilters() {
				matches = append(matches, candidate.key)
			}
			continue
		}
		if parsed.holds(candidate.document) {
			matches = append(matches, candidate.key)
		}
	}
	slices.SortFunc(matches, compareDocumentKeys)
	slices.SortFunc(covered, compareDocumentKeys)
	return matches, covered, queryErr
}

// One document a scope reaches, before its query and filters.
type searchOracleCandidate struct {
	key      *DocumentKey
	name     string
	document *searchOracleDocument
	covered  bool
	// whether it is in the partitions the scope reads, after since and until
	inPartitions bool
}

// Every document of the repos and refs scope reaches, at its newest committed version.
func (self *SearchOracle) candidates(scope *SearchScope) ([]*searchOracleCandidate, error) {
	type refSnapshot struct {
		repo *SearchLedgerRepo
		// K_ref
		refKey   []byte
		refId    sidecar.Id
		commits  []searchLedgerCommit
		cover    []int
		settings []*searchLedgerSettings
		erased   map[string]uint64
		rolled   bool
		rolledAt uint32
	}
	snapshots := []*refSnapshot{}
	err := func() error {
		self.ledger.stateLock.Lock()
		defer self.ledger.stateLock.Unlock()
		refIds, err := searchOracleScopeRefs(self.ledger, scope)
		if err != nil {
			return err
		}
		for _, pair := range refIds {
			repo := self.ledger.repoIdRepos[pair.repoId]
			snapshot := &refSnapshot{repo: repo.repo, refKey: repo.refKey, refId: pair.refId, erased: map[string]uint64{}}
			if ref, ok := repo.refIdRefs[pair.refId]; ok {
				for _, entry := range ref.commits {
					snapshot.commits = append(snapshot.commits, *entry)
				}
				snapshot.cover = slices.Clone(ref.coverOrder)
				snapshot.settings = slices.Clone(ref.settings)
				maps.Copy(snapshot.erased, ref.erasedThrough)
				snapshot.rolled = ref.rolled
				snapshot.rolledAt = ref.rolledDay
			}
			snapshots = append(snapshots, snapshot)
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}
	allHeld := map[sidecar.Id]bool{}
	for _, repoId := range scope.AllHeldRepoIds {
		allHeld[repoId] = true
	}
	candidates := []*searchOracleCandidate{}
	for _, snapshot := range snapshots {
		commits := []*searchLedgerCommit{}
		for i := range snapshot.commits {
			commits = append(commits, &snapshot.commits[i])
		}
		indexOff := false
		if n := len(snapshot.settings); 0 < n {
			indexOff = snapshot.settings[n-1].settings.Off
		}
		if indexOff && scope.Breadth != SearchBreadthRepo {
			// outside repo scope, a ref whose index is off is not searched (§16.10's excluded row)
			continue
		}
		readAll := scope.Partitions == SearchScopeAll ||
			(scope.Partitions == SearchScopeCached && allHeld[snapshot.repo.RepoId])
		documentBuckets := self.placeEntries(snapshot.repo, snapshot.refKey, snapshot.refId, commits, snapshot.cover, snapshot.settings)
		newest := searchLedgerNewest(commits)
		for _, path := range slices.Sorted(maps.Keys(newest)) {
			record := newest[path]
			if record.content == nil || record.version <= snapshot.erased[path] {
				continue
			}
			entry := commits[record.commitIndex]
			documents := self.documents(snapshot.repo, snapshot.refId, path, record.version, record.content)
			for _, document := range documents {
				docKey := searchOracleDocKey(snapshot.refKey, snapshot.refId, path, document.chunk)
				covered := !indexOff && !entry.indexedAt.IsZero()
				at := entry.commit.Time
				if covered {
					at = entry.indexedAt
				}
				inPartitions := true
				switch {
				case indexOff:
					// a repo scope searches it as §11.14 does without an index: by its text
				case readAll:
				case covered:
					bucket, ok := documentBuckets[docKey]
					inPartitions = ok && !(snapshot.rolled && bucket.start <= snapshot.rolledAt)
				default:
					// uncovered: the local layer answers it in phase 1
				}
				if !scope.Since.IsZero() && at.Before(scope.Since) {
					inPartitions = false
				}
				if !scope.Until.IsZero() && at.After(scope.Until) {
					inPartitions = false
				}
				candidates = append(candidates, &searchOracleCandidate{
					key: &DocumentKey{
						RepoId:  snapshot.repo.RepoId,
						RefId:   snapshot.refId,
						DocKey:  docKey,
						Name:    path,
						Chunk:   document.chunk,
						Version: record.version,
					},
					name:         path,
					document:     document,
					covered:      covered,
					inPartitions: inPartitions,
				})
			}
		}
	}
	return candidates, nil
}

type searchOracleRefPair struct {
	repoId sidecar.Id
	refId  sidecar.Id
}

// The refs scope reaches, by its breadth and its reader's rights; never a config, mailcfg or secret
// repo (§16.10's excluded row).
func searchOracleScopeRefs(ledger *SearchLedger, scope *SearchScope) ([]*searchOracleRefPair, error) {
	readable := func(repo *SearchLedgerRepo) bool {
		switch repo.Kind {
		case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_SECRET:
			return false
		}
		return slices.Contains(repo.ReaderIds, scope.ReaderId)
	}
	if scope.ReaderId == (sidecar.Id{}) {
		return nil, fmt.Errorf("%w: no reader", ErrSearchOracleScope)
	}
	pairs := []*searchOracleRefPair{}
	switch scope.Breadth {
	case SearchBreadthRepo:
		if len(scope.Repos) == 0 {
			return nil, fmt.Errorf("%w: repo breadth names no repo", ErrSearchOracleScope)
		}
		for _, named := range scope.Repos {
			repo, ok := ledger.repoIdRepos[named.RepoId]
			if !ok {
				return nil, fmt.Errorf("%w: the scope names repo %s, which the ledger lacks", ErrSearchLedgerInvalid, named.RepoId)
			}
			if !readable(repo.repo) {
				continue
			}
			refId := repo.repo.DefaultRefId
			if named.RefId != nil {
				refId = *named.RefId
			}
			pairs = append(pairs, &searchOracleRefPair{repoId: named.RepoId, refId: refId})
		}
	case SearchBreadthNetwork, SearchBreadthAll:
		if scope.Breadth == SearchBreadthNetwork && len(scope.NetworkIds) != 1 {
			return nil, fmt.Errorf("%w: network breadth names one network, not %d", ErrSearchOracleScope, len(scope.NetworkIds))
		}
		if len(scope.NetworkIds) == 0 {
			return nil, fmt.Errorf("%w: all breadth names no network", ErrSearchOracleScope)
		}
		for _, repoId := range slices.SortedFunc(maps.Keys(ledger.repoIdRepos), func(a sidecar.Id, b sidecar.Id) int {
			return a.Cmp(b)
		}) {
			repo := ledger.repoIdRepos[repoId].repo
			if slices.Contains(scope.NetworkIds, repo.NetworkId) && readable(repo) {
				pairs = append(pairs, &searchOracleRefPair{repoId: repoId, refId: repo.DefaultRefId})
			}
		}
	default:
		return nil, fmt.Errorf("%w: breadth %d", ErrSearchOracleUnsupported, scope.Breadth)
	}
	if scope.Partitions < SearchScopeCached || SearchScopeAll < scope.Partitions {
		return nil, fmt.Errorf("%w: partitions %d", ErrSearchOracleUnsupported, scope.Partitions)
	}
	return pairs, nil
}

// A path version's documents, one a chunk: a mailbox's m/ messages and every other repo's text files;
// none for a mailbox's other paths, the index's own files or a binary (§11.14's never row).
func (self *SearchOracle) documents(repo *SearchLedgerRepo, refId sidecar.Id, path string, version uint64, content []byte) []*searchOracleDocument {
	key := searchOracleVersionKey{repoId: repo.RepoId, refId: refId, path: path, version: version}
	self.stateLock.Lock()
	documents, ok := self.versionDocuments[key]
	self.stateLock.Unlock()
	if ok {
		return documents
	}
	switch {
	case strings.HasPrefix(path, searchOracleIndexPrefix):
		documents = nil
	case repo.Kind == protocol.RepoKind_REPO_KIND_MAILBOX:
		if strings.HasPrefix(path, searchOracleMailboxPrefix) {
			documents = searchOracleMailDocuments(path, content)
		}
	default:
		documents = searchOracleFileDocuments(path, content)
	}
	kept := []*searchOracleDocument{}
	for _, document := range documents {
		// a chunk whose key set would encode past 512 KiB is skipped (§11.14's sniff row)
		if !searchOracleKeySetTooLarge(document.text) {
			kept = append(kept, document)
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.versionDocuments[key] = kept
	return kept
}

// doc_key (§11.14's key row): HMAC-SHA256(K_ref, "UR evs 1.0 doc" || ref_id || u16be(len(name)) || name
// || u32be(chunk)), its first 16 bytes.
func searchOracleDocKey(refKey []byte, refId sidecar.Id, name string, chunk uint32) [16]byte {
	mac := hmac.New(sha256.New, refKey)
	mac.Write([]byte(searchOracleDocKeyLabel))
	mac.Write(refId.Bytes())
	mac.Write(binary.BigEndian.AppendUint16(nil, uint16(len(name))))
	mac.Write([]byte(name))
	mac.Write(binary.BigEndian.AppendUint32(nil, chunk))
	var docKey [16]byte
	copy(docKey[:], mac.Sum(nil))
	return docKey
}

// One bucket's window: UTC days [start, start + days).
type searchOracleBucket struct {
	start uint32
	days  uint32
}

// Each document's bucket, as of its newest covered entry, by replaying the ref's covered commits in the
// order their entries landed (§11.14's buckets): the first bucket starts at ⌊day/W⌋·W, each next where
// the newest ends with whole empty windows skipped, W fixed when a bucket is made; an entry goes to the
// bucket of its day, or to the newest bucket already holding an entry of its document where that is
// newer.
func (self *SearchOracle) placeEntries(repo *SearchLedgerRepo, refKey []byte, refId sidecar.Id, commits []*searchLedgerCommit, cover []int, settings []*searchLedgerSettings) map[[16]byte]searchOracleBucket {
	buckets := []searchOracleBucket{}
	// each document's newest bucket holding any entry of it, where its next entry goes at least
	documentHeld := map[[16]byte]int{}
	// each document's highest version among its entries, and that entry's bucket
	type placedEntry struct {
		version uint64
		index   int
	}
	documentNewest := map[[16]byte]placedEntry{}
	windowAt := func(at time.Time) uint32 {
		days := uint32(0)
		for _, setting := range settings {
			if !setting.at.After(at) {
				days = setting.settings.WindowDays
			}
		}
		if days == 0 {
			if repo.Kind == protocol.RepoKind_REPO_KIND_DIRECTORY {
				return searchOracleDirectoryWindow
			}
			return searchOracleDefaultWindowDays
		}
		return days
	}
	type placing struct {
		docKey  [16]byte
		version uint64
	}
	place := func(day uint32, days uint32, entries []placing) {
		if len(buckets) == 0 {
			buckets = append(buckets, searchOracleBucket{start: day / days * days, days: days})
		} else if last := buckets[len(buckets)-1]; last.start+last.days <= day {
			end := last.start + last.days
			buckets = append(buckets, searchOracleBucket{start: end + (day-end)/days*days, days: days})
		}
		index := 0
		for i, bucket := range buckets {
			if bucket.start <= day {
				index = i
			}
		}
		for _, entry := range entries {
			entryIndex := index
			if held, ok := documentHeld[entry.docKey]; ok && entryIndex < held {
				entryIndex = held
			}
			documentHeld[entry.docKey] = entryIndex
			if newest, ok := documentNewest[entry.docKey]; !ok || newest.version <= entry.version {
				documentNewest[entry.docKey] = placedEntry{version: entry.version, index: entryIndex}
			}
		}
	}
	// each path's chunk count by version, so a removal or a shrink names the keys it tombstones
	pathChunks := map[string]map[uint64]int{}
	previousChunks := func(path string, version uint64) int {
		count := 0
		best := uint64(0)
		for seen, chunks := range pathChunks[path] {
			if seen < version && best <= seen {
				best = seen
				count = chunks
			}
		}
		return count
	}
	for _, entry := range commits {
		for _, change := range entry.commit.Changes {
			if pathChunks[change.Path] == nil {
				pathChunks[change.Path] = map[uint64]int{}
			}
			if change.Content != nil {
				pathChunks[change.Path][change.Version] = len(self.documents(repo, refId, change.Path, change.Version, change.Content))
			} else {
				pathChunks[change.Path][change.Version] = 0
			}
		}
	}
	for _, i := range cover {
		entry := commits[i]
		day := uint32(entry.indexedAt.Unix() / int64(searchOracleDayDuration/time.Second))
		// a ref DELETE's ref tombstone is an entry too, which may open a bucket
		entries := []placing{}
		for _, change := range entry.commit.Changes {
			chunks := max(pathChunks[change.Path][change.Version], previousChunks(change.Path, change.Version))
			for chunk := 0; chunk < chunks; chunk += 1 {
				entries = append(entries, placing{
					docKey:  searchOracleDocKey(refKey, refId, change.Path, uint32(chunk)),
					version: change.Version,
				})
			}
		}
		place(day, windowAt(entry.indexedAt), entries)
	}
	placed := map[[16]byte]searchOracleBucket{}
	for docKey, newest := range documentNewest {
		placed[docKey] = buckets[newest.index]
	}
	return placed
}

// A parsed query: every group must hold, a group holding when one of its terms does, and no negated
// term may hold.
type searchOracleQuery struct {
	groups  [][]*searchOracleTerm
	negated []*searchOracleTerm
}

type searchOracleTerm struct {
	// normalized and trimmed
	text string
	// 0 the document's text, else a row field (1 subject, 2 from, 3 to, 4 title)
	field int
}

var searchOracleQueryFields = map[string]int{"subject": 1, "from": 2, "to": 3, "title": 4}

func (self *searchOracleQuery) empty() bool {
	return len(self.groups) == 0 && len(self.negated) == 0
}

// A query by §16.10's grammar as the oracle reads it, or ErrSearchOracleQueryRefused past its limits.
func searchOracleParseQuery(query string) (*searchOracleQuery, error) {
	if searchOracleQueryByteCount < len(searchOracleNormalize([]byte(query))) {
		return nil, fmt.Errorf("%w: past %d B normalized", ErrSearchOracleQueryRefused, searchOracleQueryByteCount)
	}
	type token struct {
		text   string
		quoted bool
	}
	tokens := []*token{}
	var current *token
	quoting := false
	for _, r := range query {
		switch {
		case r == '"':
			if current == nil {
				current = &token{}
			}
			current.quoted = true
			quoting = !quoting
		case !quoting && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			if current != nil {
				tokens = append(tokens, current)
				current = nil
			}
		default:
			if current == nil {
				current = &token{}
			}
			current.text += string(r)
		}
	}
	if current != nil {
		tokens = append(tokens, current)
	}
	parsed := &searchOracleQuery{}
	termCount := 0
	joinNext := false
	for i, tok := range tokens {
		if tok.text == "OR" && !tok.quoted && 0 < i && i < len(tokens)-1 && 0 < len(parsed.groups) {
			joinNext = true
			continue
		}
		text := tok.text
		negated := false
		if strings.HasPrefix(text, "-") && 1 < len(text) {
			negated = true
			text = text[1:]
		}
		field := 0
		if name, rest, ok := strings.Cut(text, ":"); ok && rest != "" {
			if number, ok := searchOracleQueryFields[strings.ToLower(name)]; ok {
				field = number
				text = rest
			}
		}
		normalized := strings.Trim(searchOracleNormalize([]byte(text)), " ")
		if normalized == "" {
			joinNext = false
			continue
		}
		termCount += 1
		term := &searchOracleTerm{text: normalized, field: field}
		switch {
		case negated:
			parsed.negated = append(parsed.negated, term)
		case joinNext:
			parsed.groups[len(parsed.groups)-1] = append(parsed.groups[len(parsed.groups)-1], term)
		default:
			parsed.groups = append(parsed.groups, []*searchOracleTerm{term})
		}
		joinNext = false
	}
	if searchOracleQueryTermCount < termCount {
		return nil, fmt.Errorf("%w: %d terms, past %d", ErrSearchOracleQueryRefused, termCount, searchOracleQueryTermCount)
	}
	return parsed, nil
}

// Whether a document holds the query: no group without a term that holds, no negated term that holds,
// and at least one group.
func (self *searchOracleQuery) holds(document *searchOracleDocument) bool {
	if len(self.groups) == 0 {
		return false
	}
	for _, group := range self.groups {
		if !slices.ContainsFunc(group, func(term *searchOracleTerm) bool { return term.holdsIn(document) }) {
			return false
		}
	}
	return !slices.ContainsFunc(self.negated, func(term *searchOracleTerm) bool { return term.holdsIn(document) })
}

func (self *searchOracleTerm) holdsIn(document *searchOracleDocument) bool {
	text := document.text
	if 0 < self.field {
		text = " " + searchOracleNormalize([]byte(document.row[self.field])) + " "
	}
	return searchOracleHolds(text, self.text)
}

// Whether normalized text holds a term: a term of 1 or 2 bytes as a whole word, through its
// space-padded trigrams, and a longer one as a substring.
func searchOracleHolds(text string, term string) bool {
	if len(term) <= 2 {
		return strings.Contains(text, " "+term+" ")
	}
	return strings.Contains(text, term)
}

// Whether a document passes scope's doc-table filters.
func searchOracleFiltersHold(document *searchOracleDocument, name string, filters *SearchScopeFilters) bool {
	if filters == nil {
		return true
	}
	if filters.PathPrefix != "" && !strings.HasPrefix(name, filters.PathPrefix) {
		return false
	}
	if 0 < len(filters.DocKinds) && !slices.Contains(filters.DocKinds, document.kind) {
		return false
	}
	for _, field := range filters.Fields {
		if field.Field < 1 || 4 < field.Field {
			return false
		}
		term := strings.Trim(searchOracleNormalize([]byte(field.Text)), " ")
		if term == "" || !searchOracleHolds(" "+searchOracleNormalize([]byte(document.row[field.Field]))+" ", term) {
			return false
		}
	}
	return true
}
