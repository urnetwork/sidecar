//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-76 on T2 (§11.14's documents, buckets, commit path, reads and roll-up rows; §16.10's query and confirm rows; FI-18,
// FI-19, FI-22; D-TEST-14; DESIGN-DETAILS 11.7's note for SEARCH-M10-36; SEARCH-M10-36): sidecartest's generated corpus
// of mail and notes (SearchCorpus: ASCII, CJK, combining marks, NFKC and case-folding edge cases, punctuation runs and
// addresses; MIME with base64, quoted-printable, HTML, alternative, attachment and Latin-1 parts), written over 200 days
// of one fake clock by its four writers, with edits, renames, deletions, re-creations and commits that skip the index,
// into two search worlds, a mailbox whose m/ messages are mail and a general repo of notes; beside it every
// conformance vector under 64 KiB, mail.json's in the mailbox and file.json's among the notes, at fixed days of the
// 200, and five messages that only the canonical reading finds a word of (a soft line break, RFC 2231 sections, a word
// after a 4,096 B quoted-printable line, one behind &#9 and one in an unpadded base64 tail).
//
// At every bucket boundary 1 s before and after, at each barrier of every roll-up and after each erasure, the query set
// (sidecartest.SearchQuerySet's words, five-letter prefixes, four-letter infixes, two-word phrases, one- and
// two-character CJK and addresses, and the canonical terms) runs on the buckets and on buckets plus all, on a desktop
// holding the text, a phone and a desktop whose clock runs 10 min ahead, each world's devices synced first, and is held
// to SearchOracle (fs107_test.go's hold): the desktops' hits checked against their own text equal the oracle's covered
// matches; the phone's candidates include every covered match and rest on no version that newest-version masking, a
// tombstone or the ERASE mask hides; a document the index does not cover yet, a commit that skipped it until its
// backfill 10 min on, is reported not yet searchable. The skewed desktop computing the same answers is "a reader 10 min
// skewed computing the same ones", and the phone's coverage on the buckets spans 30 to 60 days once a roll-up has run.
// The conformance documents and the vectors' own words are searched after the last vector lands and at the end, which
// is FS-76's desktop equality over those documents. Every search is recorded for FI-18, and FI-18, FI-19 and FI-22 are
// read after every step. Each roll-up is reproduced by a host holding its inputs, which finds it equal; signed before
// its bucket's expiry, the same roll-up is index_mismatch there.
//
// The cases that run here are M10's alone: the team-record case (an entry past searchable_days masked at query time
// and still readable by id) waits for M6-out and the team record's index, the mailbox case for M7-out's delivered mail
// (this corpus's messages are m/ files written by the in-ref writer, not deposits), and the hold case (an erasure of a
// document a hold kept from before a REMOVE generation re-keyed it, or after a merge and a roll-up moved it) for
// M5-out's holds.
//
// Scopes network and all merge the two repos as the oracle does: at every bucket boundary and at the end a desktop
// holding both worlds' text and a phone, each following both refs (NewSearchTestNetworkDevice), search every repo of
// the network, held to a ledger holding both repos, judged at network and at all breadth alike.
//
// A writer's entries that drop or add a word of the version beside them, hide a live document behind a tombstone or
// sit at a version the path never held are caught by a host with the text, which raises index_mismatch naming the
// signer and keeps its own entry (TestFs76ForgedEntriesAreCaughtByAHostWithTheText, on a world of its own, since a
// device does not serve the host's own entry yet and the forged ones would break the corpus's equality).
//
// Not here, each named for what it waits on: a writer's push omitting a document caught by a host with the text (the
// check judges added entries alone: question search-m10-36-omitted-document-check); the host's own entry served in a
// mismatched one's place (the local layer, SEARCH-M10-25's, is not wired to a device); a build whose uploaded bytes
// differ (a forged build); an uncovered document found from a desktop's own text (the local layer's journal and
// overlay, SEARCH-M10-25 and SEARCH-M10-14, are not wired to a device); FS-76 on real engines and T3 (a device's
// search over EvsRepo, SEARCH-M10-19's source); and the corpus at production scale (this run writes the corpus's
// default 300 commits).

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What this T2 run of FS-76 takes beside the corpus's own settings.
type fs76Settings struct {
	corpus *sidecartest.SearchCorpusSettings
	// queries of each form the query set draws, and its seed
	perClass  int
	querySeed int64
	// the conformance vectors written as documents: those under this many bytes, in batches, spread over these days
	vectorMaxByteCount  int
	vectorBatchCount    int
	vectorFirstDay      int
	vectorLastDay       int
	vectorQueryMaxCount int
	// the day the canonical-reading messages are written
	canonicalDay int
	// the days an erasure runs in each world
	erasureDays []int
	// the skewed desktop's offset from the writers' clock
	skew time.Duration
	// the commits that skip the index, in each repo, searched before their backfill
	uncoveredCheckCount int
	// the bucket window the worlds' repos keep, §11.14's default
	windowDays uint32
}

// The row's settings at the corpus's own scale.
func defaultFs76Settings() *fs76Settings {
	return &fs76Settings{
		corpus:   sidecartest.DefaultSearchCorpusSettings(),
		perClass: 3, querySeed: 76,
		vectorMaxByteCount: 64 * 1024, vectorBatchCount: 12, vectorFirstDay: 3, vectorLastDay: 190, vectorQueryMaxCount: 12,
		canonicalDay:        20,
		erasureDays:         []int{100, 150},
		skew:                10 * time.Minute,
		uncoveredCheckCount: 3,
		windowDays:          30,
	}
}

// One device a world keeps across the run, synced before each search round.
type fs76Device struct {
	label  string
	host   *searchHost
	device *sidecar.SearchTestDevice
}

// One repo of the corpus on a search world of its own.
type fs76Repo struct {
	label   string
	kind    protocol.RepoKind
	world   *fsResultsWorld
	erasure *sidecar.SearchTestErasure
	source  *fsResultsIndex
	indexer sidecar.Id
	devices []*fs76Device
	// each corpus commit's world ref version, by the corpus's ref version
	worldRefVersions map[uint64]uint64
	// each standing path's entry version, which an erasure lists
	livePathVersions map[string]uint64
	// the bucket start days rolled so far, as the ledger learned them
	rolled uint32
	// told of each search held to the oracle
	onSearch func(found *fsResultsSearch)
	// the ref version each path was last changed at, removals included
	changedPathVersions map[string]uint64
	// the network's ledger, which every write to the world's ledger is written to as well
	network *fs76Network
}

// A clock skewed from the world's by offset: what a reader whose clock runs apart from the writers' reads.
type fs76SkewedClock struct {
	base   *sidecartest.FakeClock
	offset time.Duration
}

// See sidecar.Clock: the world's time, offset.
func (self *fs76SkewedClock) Now() time.Time {
	return self.base.Now().Add(self.offset)
}

// See sidecar.Clock: the world's timers, which the offset leaves alone.
func (self *fs76SkewedClock) After(timeout time.Duration) <-chan time.Time {
	return self.base.After(timeout)
}

// See sidecar.Clock.
func (self *fs76SkewedClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return self.base.AfterFunc(timeout, function)
}

// Moves the world's clock, which every clock of the run reads.
func (self *fs76SkewedClock) Advance(timeout time.Duration) {
	self.base.Advance(timeout)
}

// A repo of label and kind on its own world over clock, its erasure model slot-keyed, as a mailbox's and a vault's are.
func newFs76Repo(t *testing.T, label string, kind protocol.RepoKind, clock *sidecartest.FakeClock) *fs76Repo {
	world := newFsResultsWorldOn(t, "fs76 "+label, kind, clock)
	repo := &fs76Repo{
		label: label, kind: kind, world: world, erasure: world.index.NewErasure(nil), source: world.source("the fs76 " + label + " world's ref"),
		indexer: searchId("fs76 indexer " + label), worldRefVersions: map[uint64]uint64{}, livePathVersions: map[string]uint64{},
		changedPathVersions: map[string]uint64{},
	}
	return repo
}

// Makes the world's devices: a desktop holding the text, a phone, and a desktop skewed by skew.
func (self *fs76Repo) makeDevices(ctx context.Context, skew time.Duration) error {
	for _, made := range []struct {
		label string
		host  string
		skew  time.Duration
	}{{"desktop", "desktop", 0}, {"phone", "ios32", 0}, {"skewed desktop", "desktop", skew}} {
		host := searchHostNamed(made.host)
		conditions := host.conditions
		// one session runs every search of the run on a clock that stands between them: room for each one's cursor,
		// and no rate a person's typing would meet
		settings := host.settings()
		settings.SessionCursorCount = 1 << 20
		settings.SessionSearchRate = sidecar.SidecarRate{Count: 1 << 20, Burst: 1 << 20, Interval: time.Second}
		args := &sidecar.SearchTestDeviceArgs{
			Settings: settings, Conditions: func() sidecar.SearchConditions { return conditions },
			ReadByteCount: self.world.readByteCount, Coverage: true, Text: made.host == "desktop",
		}
		if made.skew != 0 {
			args.Clock = &fs76SkewedClock{base: self.world.clock, offset: made.skew}
		}
		device, err := self.world.index.NewDevice(ctx, args)
		if err != nil {
			return err
		}
		self.devices = append(self.devices, &fs76Device{label: made.label, host: host, device: device})
	}
	return nil
}

// Ends the world's devices.
func (self *fs76Repo) close() {
	for _, device := range self.devices {
		device.device.Close()
	}
}

// writer's push of changes at the world's clock now: an in-ref push, or one that skips the index, recorded in the
// ledger at the world's versions. A push whose writer is out of slots waits for a merge of the bucket, as an indexer's
// upkeep gives it, and goes again.
func (self *fs76Repo) commit(ctx context.Context, writer sidecar.Id, changes []*sidecar.SearchTestChange, indexed bool) (*sidecar.SearchTestCommit, error) {
	world := self.world
	push := func() (*sidecar.SearchTestCommit, error) {
		if indexed {
			return world.index.CommitIndexedMerging(ctx, writer, world.clock.Now(), changes)
		}
		return world.index.CommitContent(ctx, writer, world.clock.Now(), changes)
	}
	commit, err := push()
	if err != nil && strings.Contains(err.Error(), "a push that merges") {
		if _, mergeErr := world.index.Merge(ctx, self.indexer, 0); mergeErr != nil {
			return nil, mergeErr
		}
		commit, err = push()
	}
	if err != nil {
		return nil, err
	}
	if err := world.recordContent(writer, commit, changes); err != nil {
		return nil, err
	}
	if self.network != nil {
		networkCommit := &sidecartest.SearchCommit{
			RepoId: world.index.RepoId(), RefId: world.index.RefId(), RefVersion: commit.RefVersion, Time: commit.Time,
			WriterId: writer, Indexed: 0 < commit.IndexWriteCount,
		}
		for _, change := range changes {
			networkCommit.Changes = append(networkCommit.Changes, &sidecartest.SearchChange{
				Path: change.Path, Version: commit.Versions[change.Path], Content: change.Content,
			})
		}
		if err := self.network.ledger.Commit(networkCommit); err != nil {
			return nil, err
		}
	}
	for _, change := range changes {
		if change.Content == nil {
			delete(self.livePathVersions, change.Path)
		} else {
			self.livePathVersions[change.Path] = commit.Versions[change.Path]
		}
		self.changedPathVersions[change.Path] = commit.RefVersion
	}
	return commit, nil
}

// The ledger learns of every roll-up the world committed: a bucket gone from the head and not yet told.
func (self *fs76Repo) learnRolled(ctx context.Context, rolling uint32) error {
	windows, err := self.world.index.BucketWindows(ctx)
	if err != nil {
		return err
	}
	if rolling == 0 || rolling <= self.rolled {
		return nil
	}
	for _, window := range windows {
		if window.StartDay == rolling {
			return nil
		}
	}
	self.rolled = rolling
	if self.network != nil {
		if err := self.network.ledger.RolledThrough(self.world.index.RepoId(), self.world.index.RefId(), rolling); err != nil {
			return err
		}
	}
	return self.world.ledger.RolledThrough(self.world.index.RepoId(), self.world.index.RefId(), rolling)
}

// Every query on the world's device of index, synced first, on the buckets and on buckets plus all, each held to the
// oracle and recorded for FI-18; a step of its own each, so none passes the driver's bound on a step. rolling names a
// roll-up in flight, whose commit the ledger learns of first. staleUncovered leaves out of each search's holding the
// paths a commit above indexed_through changed (fsResultsSearch.waitingPaths), and records none for FI-18, whose
// masked-version clause does not tell an older version shown while its path's change waits for the backfill from a
// masked one.
func (self *fs76Repo) check(ctx context.Context, net *Net, label string, rolling uint32, queries []string, coverage bool, staleUncovered bool, index int) error {
	if err := self.learnRolled(ctx, rolling); err != nil {
		return err
	}
	waiting := map[string]bool{}
	if staleUncovered {
		indexedThrough, _, err := self.world.index.Coverage(ctx)
		if err != nil {
			return err
		}
		for path, refVersion := range self.changedPathVersions {
			if indexedThrough < refVersion {
				waiting[path] = true
			}
		}
	}
	for _, device := range self.devices[index : index+1] {
		if err := device.device.Sync(ctx); err != nil {
			return fmt.Errorf("%s: the %s's sync: %w", label, device.label, err)
		}
		for _, scope := range []sidecar.SearchScope{sidecar.SearchLatest, sidecar.SearchAll} {
			for _, query := range queries {
				found, err := fsResultsRun(ctx, device.device, device.host.name, query, scope)
				if err != nil {
					return fmt.Errorf("%s: the %s's search for %q: %w", label, device.label, query, err)
				}
				// the device's fetches across rounds are its sync's; FI-23's trace is not this row's
				found.fetches = nil
				found.waitingPaths = waiting
				if err := self.world.hold(found); err != nil {
					return fmt.Errorf("%s: %s %s: %w", self.label, label, device.label, err)
				}
				if self.onSearch != nil {
					self.onSearch(found)
				}
				if !staleUncovered {
					self.world.record(net, self.source, found, fmt.Sprintf("%s %s %s", self.label, label, device.label))
				}
			}
		}
		if coverage && device.label == "phone" {
			if err := self.checkCoverage(ctx, device, label); err != nil {
				return err
			}
		}
	}
	return nil
}

// The phone's coverage on the buckets spans 30 to 60 days of the window, with a day for the roll-up's lag.
func (self *fs76Repo) checkCoverage(ctx context.Context, device *fs76Device, label string) error {
	search, err := device.device.Search(ctx, &sidecar.SearchRequest{Text: "the", Scope: sidecar.SearchLatest, Remote: "off"}, 4096, nil)
	if err != nil {
		return err
	}
	from := search.Last().CoveredFrom
	if from.IsZero() {
		return fmt.Errorf("%s: %s: the phone's buckets report no coverage", self.label, label)
	}
	window := 30 * 24 * time.Hour
	span := self.world.clock.Now().Sub(from)
	if span < window-24*time.Hour || 2*window+24*time.Hour < span {
		return fmt.Errorf("%s: %s: the phone's buckets cover %s back, not 30 to 60 days", self.label, label, span)
	}
	return nil
}

// One erasure of a world's document, which runs as three steps (fs76Repo.erasure): its CUT, the eraser's rewrite to
// completion, and the completion recorded for FI-19, which holds the head at the first push after it.
type fs76Erasure struct {
	erasureId sidecar.Id
	path      string
	version   uint64
}

// The CUT of the world's oldest standing corpus document, the ledger forgetting it from there.
func (self *fs76Repo) cut(ctx context.Context, label string) (*fs76Erasure, error) {
	paths := []string{}
	for path := range self.livePathVersions {
		// one of the corpus's own documents, not a vector or a canonical message
		if !strings.Contains(path, "conformance/") && !strings.HasPrefix(path, "m/canonical/") {
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("%s: nothing stands to erase", label)
	}
	slices.Sort(paths)
	erasure := &fs76Erasure{erasureId: searchId(fmt.Sprintf("fs76 %s erasure %s", self.label, label)), path: paths[0], version: self.livePathVersions[paths[0]]}
	key, err := self.world.index.DocKey(erasure.path)
	if err != nil {
		return nil, err
	}
	eraser, err := self.erasure.NewEraser(&sidecar.SearchTestEraserArgs{})
	if err != nil {
		return nil, err
	}
	cut, err := eraser.Cut(ctx, &sidecar.IndexCutArgs{ErasureId: erasure.erasureId, Documents: []*sidecar.IndexCutDocument{{Key: key, Version: erasure.version}}})
	if err != nil {
		return nil, err
	}
	if !cut.Pushed {
		return nil, fmt.Errorf("%s: the CUT of %s pushed nothing", label, erasure.path)
	}
	if err := self.world.ledger.Erase(self.world.index.RepoId(), self.world.index.RefId(), erasure.path, erasure.version); err != nil {
		return nil, err
	}
	if self.network != nil {
		if err := self.network.ledger.Erase(self.world.index.RepoId(), self.world.index.RefId(), erasure.path, erasure.version); err != nil {
			return nil, err
		}
	}
	delete(self.livePathVersions, erasure.path)
	return erasure, nil
}

// The eraser's rewrite of erasure to completion, every file that held the document written again without it.
func (self *fs76Repo) rewrite(ctx context.Context, erasure *fs76Erasure, label string) error {
	eraser, err := self.erasure.NewEraser(&sidecar.SearchTestEraserArgs{})
	if err != nil {
		return err
	}
	rewrite, err := eraser.Rewrite(ctx, &sidecar.IndexRewriteArgs{ErasureId: erasure.erasureId, Complete: true, Note: []byte("fs76")})
	if err != nil {
		return err
	}
	if rewrite.Erasure == nil || rewrite.Erasure.State == sidecar.SidecarErasureWaiting {
		return fmt.Errorf("%s: the rewrite of %s waited: %+v", label, erasure.path, rewrite.Erasure)
	}
	self.world.markClosures(self.erasure)
	if !self.erasure.Complete(erasure.erasureId) {
		return fmt.Errorf("%s: the rewrite of %s did not complete: %+v", label, erasure.path, rewrite.Erasure)
	}
	if held, err := self.world.index.FilesHolding(erasure.path, 0); err != nil || 0 < len(held) {
		return fmt.Errorf("%s: after the erasure of %s@%d, %v hold it (%v)", label, erasure.path, erasure.version, held, err)
	}
	return nil
}

// The corpus's network as one device reads it: a ledger holding both repos, which SearchOracle judges at network and at
// all breadth, and a desktop holding both worlds' text and a phone, each following both refs.
type fs76Network struct {
	ledger    *sidecartest.SearchLedger
	oracle    *sidecartest.SearchOracle
	networkId sidecar.Id
	readerId  sidecar.Id
	repos     []*fs76Repo
	devices   []*fs76NetworkDevice
	// the repos the network devices' hits came from, so a run shows the repos merged
	hitRepoIds map[sidecar.Id]bool
}

// One device of the network, following every repo's ref.
type fs76NetworkDevice struct {
	label  string
	host   *searchHost
	device *sidecar.SearchTestNetworkDevice
}

// The network of repos: its ledger holds each repo, every later write mirrored there (fs76Repo.network).
func newFs76Network(repos []*fs76Repo) (*fs76Network, error) {
	network := &fs76Network{
		ledger: sidecartest.NewSearchLedger(), networkId: searchId("fs76 network"), readerId: searchId("fs76 network reader"),
		repos: repos, hitRepoIds: map[sidecar.Id]bool{},
	}
	for _, repo := range repos {
		err := network.ledger.AddRepo(&sidecartest.SearchLedgerRepo{
			RepoId: repo.world.index.RepoId(), NetworkId: network.networkId, Kind: repo.kind,
			DefaultRefId: repo.world.index.RefId(), Key: repo.world.index.RepoKey(), ReaderIds: []sidecar.Id{network.readerId},
		})
		if err != nil {
			return nil, err
		}
		repo.network = network
	}
	network.oracle = sidecartest.NewSearchOracle(network.ledger)
	return network, nil
}

// Makes the network's devices: a desktop holding every world's text, and a phone.
func (self *fs76Network) makeDevices(ctx context.Context) error {
	refs := []*sidecar.SearchTestNetworkRef{}
	texts := map[sidecar.Id]sidecar.SearchTextSource{}
	for _, repo := range self.repos {
		refs = append(refs, &sidecar.SearchTestNetworkRef{World: repo.world.index})
		texts[repo.world.index.RepoId()] = repo.world.index.TextSource()
	}
	for _, made := range []struct {
		label string
		host  string
	}{{"network desktop", "desktop"}, {"network phone", "ios32"}} {
		host := searchHostNamed(made.host)
		conditions := host.conditions
		settings := host.settings()
		settings.SessionCursorCount = 1 << 20
		settings.SessionSearchRate = sidecar.SidecarRate{Count: 1 << 20, Burst: 1 << 20, Interval: time.Second}
		args := &sidecar.SearchTestNetworkDeviceArgs{
			Settings: settings, Conditions: func() sidecar.SearchConditions { return conditions },
			ReadByteCount: 32 * 1024 * 1024, Refs: refs,
		}
		if made.host == "desktop" {
			args.Text = func(repoId sidecar.Id, refId sidecar.Id) sidecar.SearchTextSource { return texts[repoId] }
		}
		device, err := sidecar.NewSearchTestNetworkDevice(ctx, args)
		if err != nil {
			return err
		}
		self.devices = append(self.devices, &fs76NetworkDevice{label: made.label, host: host, device: device})
	}
	return nil
}

// Ends the network's devices.
func (self *fs76Network) close() {
	for _, device := range self.devices {
		device.device.Close()
	}
}

// A key across repos: the repo, then the document as one world keys it.
func fs76NetworkKey(repoId sidecar.Id, path string, docKey [16]byte, version uint64) string {
	return repoId.String() + "/" + fs79Key(path, docKey, version)
}

// Every query on the network's device of index, synced first, over every repo of the network on the buckets and on buckets plus
// all, held to the network's oracle: the oracle's network and all breadth give one set, merging the repos; every
// covered match is a hit, no hit twice; a desktop's hits are matches, verified against its text; a phone's each a
// document's newest live version; a match not covered yet found, or above the indexed_through its ref's coverage gave.
func (self *fs76Network) check(ctx context.Context, label string, queries []string, index int) error {
	repoOf := map[sidecar.Id]*fs76Repo{}
	for _, repo := range self.repos {
		repoOf[repo.world.index.RepoId()] = repo
	}
	for _, device := range self.devices[index : index+1] {
		if err := device.device.Sync(ctx); err != nil {
			return fmt.Errorf("%s: the %s's sync: %w", label, device.label, err)
		}
		for _, scope := range []sidecar.SearchScope{sidecar.SearchLatest, sidecar.SearchAll} {
			for _, query := range queries {
				at := fmt.Sprintf("%s: the %s's search for %q in scope %d", label, device.label, query, scope)
				stream, err := device.device.Engine().Search(ctx, &sidecar.SearchRequest{Text: query, Scope: scope, Remote: "off"})
				if err != nil {
					return fmt.Errorf("%s: %w", at, err)
				}
				hits := []sidecar.SearchHit{}
				var progress sidecar.SearchProgress
				for done := false; !done; {
					page, pageProgress, pageDone, err := stream.Next()
					if err != nil {
						stream.Close()
						return fmt.Errorf("%s: %w", at, err)
					}
					hits, progress, done = append(hits, page...), pageProgress, pageDone
				}
				stream.Close()
				indexedThrough := map[sidecar.Id]uint64{}
				for _, coverage := range progress.Coverage {
					indexedThrough[coverage.RepoId] = coverage.IndexedThrough
				}
				if err := self.hold(at, device.host.name, query, scope, hits, indexedThrough, repoOf); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// See check.
func (self *fs76Network) hold(at string, host string, query string, scope sidecar.SearchScope, found []sidecar.SearchHit, indexedThrough map[sidecar.Id]uint64, repoOf map[sidecar.Id]*fs76Repo) error {
	judge := func(breadth sidecartest.SearchBreadth) ([]*sidecartest.DocumentKey, []*sidecartest.DocumentKey, []*sidecartest.DocumentKey, error) {
		oracleScope := &sidecartest.SearchScope{
			Partitions: fsResultsPartitions(scope), Breadth: breadth, NetworkIds: []sidecar.Id{self.networkId}, ReaderId: self.readerId,
		}
		matches, covered, err := self.oracle.Judge(query, oracleScope)
		if err != nil && !errors.Is(err, sidecartest.ErrSearchOracleQueryRefused) {
			return nil, nil, nil, err
		}
		documents, err := self.oracle.Documents(oracleScope)
		return matches, covered, documents, err
	}
	matches, covered, documents, err := judge(sidecartest.SearchBreadthNetwork)
	if err != nil {
		return fmt.Errorf("%s: the oracle cannot judge it: %w", at, err)
	}
	allMatches, _, _, err := judge(sidecartest.SearchBreadthAll)
	if err != nil {
		return fmt.Errorf("%s: the oracle cannot judge it at all breadth: %w", at, err)
	}
	keysOf := func(keys []*sidecartest.DocumentKey) []string {
		named := []string{}
		for _, key := range keys {
			named = append(named, fs76NetworkKey(key.RepoId, key.Name, key.DocKey, key.Version))
		}
		slices.Sort(named)
		return named
	}
	if !slices.Equal(keysOf(matches), keysOf(allMatches)) {
		return fmt.Errorf("%s: the oracle's network breadth matched %v and its all breadth %v", at, keysOf(matches), keysOf(allMatches))
	}
	isCovered, live, matching := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, key := range keysOf(covered) {
		isCovered[key] = true
	}
	for _, key := range keysOf(documents) {
		live[key] = true
	}
	for _, key := range keysOf(matches) {
		matching[key] = true
	}
	hits := []string{}
	for _, hit := range found {
		if hit.State == sidecar.SearchNear {
			continue
		}
		key := fs76NetworkKey(hit.Repo, hit.Path, hit.DocKey, hit.Version)
		if slices.Contains(hits, key) {
			return fmt.Errorf("%s shows %s twice", at, key)
		}
		self.hitRepoIds[hit.Repo] = true
		hits = append(hits, key)
		switch {
		case host == "desktop" && !matching[key]:
			return fmt.Errorf("%s found %s, which the oracle does not match", at, key)
		case host == "desktop" && hit.State != sidecar.SearchVerified:
			return fmt.Errorf("%s left %s unverified, state %d, though it holds the text", at, key, hit.State)
		case !live[key]:
			return fmt.Errorf("%s found %s, which is no document's newest live version", at, key)
		}
	}
	for _, match := range matches {
		key := fs76NetworkKey(match.RepoId, match.Name, match.DocKey, match.Version)
		if slices.Contains(hits, key) {
			continue
		}
		if isCovered[key] {
			return fmt.Errorf("%s left out %s, covered and matching", at, key)
		}
		repo := repoOf[match.RepoId]
		through, reported := indexedThrough[match.RepoId]
		refVersion, ok := repo.world.refVersions[fmt.Sprintf("%s@%d", match.Name, match.Version)]
		if !ok || !reported || refVersion <= through {
			return fmt.Errorf("%s leaves %s silently absent: its push at %d, indexed through %d", at, key, refVersion, through)
		}
	}
	return nil
}

// A conformance vector as a document of the corpus: the bytes its input gives, under a path of the corpus's own.
type fs76Vector struct {
	name    string
	content []byte
	// the words of its documents' expected text
	words []string
}

type fs76VectorPart struct {
	T *string `json:"t"`
	X *string `json:"x"`
	N int     `json:"n"`
}

type fs76VectorValue struct {
	T *string `json:"t"`
}

type fs76VectorFile struct {
	Vectors []struct {
		Name      string            `json:"name"`
		Input     []*fs76VectorPart `json:"input"`
		Documents []struct {
			Text *fs76VectorValue `json:"text"`
		} `json:"documents"`
	} `json:"vectors"`
}

// Every vector of testdata/index/conformance/name under maxByteCount bytes of input, in the file's order.
func fs76Vectors(t *testing.T, name string, maxByteCount int) []*fs76Vector {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "..", "testdata", "index", "conformance", name))
	if err != nil {
		t.Fatal(err)
	}
	file := &fs76VectorFile{}
	if err := json.Unmarshal(encoded, file); err != nil {
		t.Fatal(err)
	}
	vectors := []*fs76Vector{}
	for _, vector := range file.Vectors {
		content := []byte{}
		for _, part := range vector.Input {
			piece := []byte{}
			switch {
			case part.T != nil:
				piece = []byte(*part.T)
			case part.X != nil:
				if piece, err = hex.DecodeString(*part.X); err != nil {
					t.Fatalf("%s's input: %v", vector.Name, err)
				}
			}
			for range max(part.N, 1) {
				content = append(content, piece...)
			}
		}
		if maxByteCount <= len(content) {
			continue
		}
		words := []string{}
		for _, document := range vector.Documents {
			if document.Text != nil && document.Text.T != nil {
				words = append(words, strings.Fields(*document.Text.T)...)
			}
		}
		vectors = append(vectors, &fs76Vector{name: vector.Name, content: content, words: words})
	}
	return vectors
}

// Words of the vectors' expected texts that make good queries: letters only, seven to 24 bytes, in at most two vectors,
// sorted, at most count, spread over the sorted words.
func fs76VectorQueries(vectors []*fs76Vector, count int) []string {
	seen := map[string]int{}
	for _, vector := range vectors {
		unique := map[string]bool{}
		for _, word := range vector.words {
			if len(word) < 7 || 24 < len(word) || strings.IndexFunc(word, func(r rune) bool { return !unicode.IsLetter(r) }) != -1 {
				continue
			}
			unique[word] = true
		}
		for word := range unique {
			seen[word] += 1
		}
	}
	words := []string{}
	for word, vectorCount := range seen {
		if vectorCount <= 2 {
			words = append(words, word)
		}
	}
	slices.Sort(words)
	if count < len(words) {
		// spread over the sorted words, so the run is the same each time
		spread := []string{}
		for index := range count {
			spread = append(spread, words[index*len(words)/count])
		}
		words = spread
	}
	return words
}

// The canonical-reading messages (DESIGN-DETAILS 11.7): each holds a word only extractor 1's own rules read, and the
// word that finds it.
func fs76CanonicalMessages() ([]*sidecar.SearchTestChange, []string) {
	header := func(subject string) string {
		return "From: ann@example.com\r\nTo: bob@example.com\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\n"
	}
	messages := map[string]string{
		// a soft line break joins the word's halves
		"m/canonical/soft-break": header("Soft break") +
			"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nthe sandpi=\r\nper runs\r\n",
		// a name from RFC 2231 sections
		"m/canonical/sections": header("Sections") + "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n" +
			"Content-Type: text/plain\r\n\r\nsee attached\r\n--b\r\nContent-Type: application/pdf\r\n" +
			"Content-Disposition: attachment; filename*0=kitti; filename*1=wake.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERg==\r\n--b--\r\n",
		// a word after a quoted-printable line past 4,096 B
		"m/canonical/long-line": header("Long line") +
			"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
			strings.Repeat("a", 4200) + "\r\nthe phalarope roosts\r\n",
		// a word behind a numeric reference of one digit
		"m/canonical/reference": header("Reference") +
			"Content-Type: text/html; charset=utf-8\r\n\r\n<p>shore&#9godwit flock</p>\r\n",
		// a word in an unpadded base64 tail
		"m/canonical/base64-tail": header("Tail") + "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
			base64.RawStdEncoding.EncodeToString([]byte("the last bird is a whimbrel")) + "\r\n",
	}
	changes := []*sidecar.SearchTestChange{}
	for _, path := range slices.Sorted(func(yield func(string) bool) {
		for path := range messages {
			if !yield(path) {
				return
			}
		}
	}) {
		changes = append(changes, &sidecar.SearchTestChange{Path: path, Content: []byte(messages[path])})
	}
	return changes, []string{"sandpiper", "kittiwake", "phalarope", "godwit", "whimbrel"}
}

// One event of FS-76's timeline: at its time, one of a corpus step, a batch of vectors, the canonical messages, a check,
// a roll-up or an erasure.
type fs76Event struct {
	at   time.Time
	kind string
	// a corpus step
	step *sidecartest.SearchCorpusStep
	// a batch of documents for one repo
	repo    *fs76Repo
	changes []*sidecar.SearchTestChange
	label   string
	// a roll-up's bucket
	startDay uint32
	// a check that some search reports a change not yet searchable
	uncovered bool
}

// The order of events at one time: writes before checks, checks before roll-ups and erasures.
func fs76EventRank(kind string) int {
	return map[string]int{"commit": 0, "cover": 1, "documents": 2, "check": 3, "rollup": 4, "erase": 5}[kind]
}

// FS-76's schedule (see the file header): the corpus, the vectors and the canonical messages on two worlds of one
// clock, with checks at every bucket boundary, every roll-up barrier and after each erasure, FI-18, FI-19 and FI-22
// read after every step.
func fs76Schedule(t *testing.T, settings *fs76Settings) *Schedule {
	clock := sidecartest.NewFakeClock(settings.corpus.Start)
	mailbox := newFs76Repo(t, "mailbox", protocol.RepoKind_REPO_KIND_MAILBOX, clock)
	notes := newFs76Repo(t, "notes", protocol.RepoKind_REPO_KIND_GENERAL, clock)
	repos := []*fs76Repo{mailbox, notes}
	network, err := newFs76Network(repos)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, repo := range repos {
			repo.close()
		}
		network.close()
	})
	corpus := sidecartest.NewSearchCorpus(settings.corpus)
	queries := []string{}
	for _, query := range sidecartest.NewSearchQuerySet(corpus, settings.querySeed, settings.perClass).Queries {
		queries = append(queries, query.Text)
	}
	canonical, canonicalQueries := fs76CanonicalMessages()
	queries = append(queries, canonicalQueries...)
	mailVectors := fs76Vectors(t, "mail.json", settings.vectorMaxByteCount)
	fileVectors := fs76Vectors(t, "file.json", settings.vectorMaxByteCount)
	vectorQueries := fs76VectorQueries(slices.Concat(mailVectors, fileVectors), settings.vectorQueryMaxCount)
	repoOf := map[sidecar.Id]*fs76Repo{corpus.Mailbox.RepoId: mailbox, corpus.Notes.RepoId: notes}
	day := func(index int) time.Time {
		return settings.corpus.Start.Add(time.Duration(index) * 24 * time.Hour)
	}
	end := settings.corpus.Start.Add(settings.corpus.Span)

	events := []*fs76Event{}
	uncoveredChecks := map[sidecar.Id]int{}
	for _, step := range corpus.Steps {
		kind := "commit"
		if step.Cover != nil {
			kind = "cover"
			// the first few commits that skip the index in each repo, searched before their backfill lands
			if uncoveredChecks[step.Cover.RepoId] < settings.uncoveredCheckCount {
				uncoveredChecks[step.Cover.RepoId] += 1
				events = append(events, &fs76Event{at: step.At.Add(-settings.corpus.BackfillDelay / 2), kind: "check", label: "a skipped commit before its backfill", uncovered: true})
			}
		}
		events = append(events, &fs76Event{at: step.At, kind: kind, step: step})
	}
	// the vectors in batches over their days, each repo its own, at their fixed days
	for _, batch := range []struct {
		repo    *fs76Repo
		vectors []*fs76Vector
		prefix  string
	}{{mailbox, mailVectors, "m/conformance/"}, {notes, fileVectors, "conformance/"}} {
		batches := (len(batch.vectors) + settings.vectorBatchCount - 1) / settings.vectorBatchCount
		for index := range batches {
			changes := []*sidecar.SearchTestChange{}
			for _, vector := range batch.vectors[index*settings.vectorBatchCount : min(len(batch.vectors), (index+1)*settings.vectorBatchCount)] {
				changes = append(changes, &sidecar.SearchTestChange{Path: batch.prefix + vector.name, Content: vector.content})
			}
			at := day(settings.vectorFirstDay + index*(settings.vectorLastDay-settings.vectorFirstDay)/max(1, batches-1)).Add(17 * time.Minute)
			events = append(events, &fs76Event{at: at, kind: "documents", repo: batch.repo, changes: changes, label: "vectors"})
		}
	}
	events = append(events, &fs76Event{at: day(settings.canonicalDay).Add(7 * time.Minute), kind: "documents", repo: mailbox, changes: canonical, label: "canonical"})
	// the bucket boundaries, a second either side, and each bucket's roll-up an hour past its expiry
	windowMs := int64(settings.windowDays) * 24 * 60 * 60 * 1000
	first := settings.corpus.Start.UnixMilli() / windowMs * windowMs
	for boundary := first + windowMs; boundary < end.UnixMilli(); boundary += windowMs {
		at := time.UnixMilli(boundary).UTC()
		events = append(events,
			&fs76Event{at: at.Add(-time.Second), kind: "check", label: "a second before the boundary"},
			&fs76Event{at: at.Add(time.Second), kind: "check", label: "a second after the boundary"},
		)
	}
	for start := first; start+2*windowMs < end.UnixMilli(); start += windowMs {
		startDay := uint32(start / (24 * 60 * 60 * 1000))
		for _, repo := range repos {
			events = append(events, &fs76Event{at: time.UnixMilli(start + 2*windowMs).UTC().Add(time.Hour), kind: "rollup", repo: repo, startDay: startDay})
		}
	}
	for _, erasureDay := range settings.erasureDays {
		for _, repo := range repos {
			events = append(events, &fs76Event{at: day(erasureDay).Add(31 * time.Minute), kind: "erase", repo: repo, label: fmt.Sprintf("day %d", erasureDay)})
		}
	}
	slices.SortStableFunc(events, func(a *fs76Event, b *fs76Event) int {
		if order := a.at.Compare(b.at); order != 0 {
			return order
		}
		return fs76EventRank(a.kind) - fs76EventRank(b.kind)
	})

	advanceTo := func(at time.Time) {
		if now := clock.Now(); now.Before(at) {
			clock.Advance(at.Sub(now))
		}
	}
	// a check point's steps: each repo's devices, a step each, and but at a stale check the network's
	deviceCount, networkDeviceCount := 3, 2
	checkSteps := func(label string, extra []string, coverage bool, staleUncovered bool) []*Step {
		steps := []*Step{}
		for _, repo := range repos {
			for index := range deviceCount {
				steps = append(steps, &Step{Actor: "check", Action: func(ctx context.Context, net *Net) error {
					return repo.check(ctx, net, label, 0, slices.Concat(queries, extra), coverage, staleUncovered, index)
				}})
			}
		}
		if !staleUncovered {
			for index := range networkDeviceCount {
				steps = append(steps, &Step{Actor: "check", Action: func(ctx context.Context, net *Net) error {
					return network.check(ctx, label, slices.Concat(queries, extra), index)
				}})
			}
		}
		return steps
	}
	repoSteps := func(repo *fs76Repo, label string, rolling uint32) []*Step {
		steps := []*Step{}
		for index := range deviceCount {
			steps = append(steps, &Step{Actor: "check", Action: func(ctx context.Context, net *Net) error {
				return repo.check(ctx, net, label, rolling, queries, false, false, index)
			}})
		}
		return steps
	}
	// searches that reported a change not yet searchable, which an uncovered check holds above zero
	uncoveredSearches := 0
	for _, repo := range repos {
		repo.onSearch = func(found *fsResultsSearch) {
			if 0 < found.uncovered {
				uncoveredSearches += 1
			}
		}
	}
	vectorsDone := false
	lastVector := time.Time{}
	for _, event := range events {
		if event.kind == "documents" && event.label == "vectors" && lastVector.Before(event.at) {
			lastVector = event.at
		}
	}
	steps := []*Step{{Actor: "oracle", Action: func(ctx context.Context, net *Net) error {
		for _, repo := range repos {
			SearchRecordOf(net).AddIndex(repo.source)
			if err := repo.makeDevices(ctx, settings.skew); err != nil {
				return err
			}
		}
		return network.makeDevices(ctx)
	}}}
	rollCount := 0
	for _, event := range events {
		event := event
		switch event.kind {
		case "commit":
			commit := event.step.Commit
			repo := repoOf[commit.RepoId]
			steps = append(steps, &Step{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
				advanceTo(event.at)
				changes := []*sidecar.SearchTestChange{}
				for _, change := range commit.Changes {
					changes = append(changes, &sidecar.SearchTestChange{Path: change.Path, Content: change.Content})
				}
				committed, err := repo.commit(ctx, commit.WriterId, changes, commit.Indexed)
				if err != nil {
					return fmt.Errorf("%s's commit at %s: %w", repo.label, event.at, err)
				}
				repo.worldRefVersions[commit.RefVersion] = committed.RefVersion
				return nil
			}})
		case "cover":
			cover := event.step.Cover
			repo := repoOf[cover.RepoId]
			steps = append(steps, &Step{Actor: "indexer", Action: func(ctx context.Context, net *Net) error {
				// a second past BackfillAge, so the push is due
				advanceTo(event.at.Add(time.Second))
				through := repo.worldRefVersions[cover.RefVersion]
				backfill, err := repo.world.index.Backfill(ctx, repo.indexer)
				if err != nil {
					return err
				}
				if backfill.Horizon < through {
					return fmt.Errorf("%s's backfill at %s raised the horizon to %d, below the skipped push at %d: %+v", repo.label, event.at, backfill.Horizon, through, backfill)
				}
				if err := repo.network.ledger.Cover(repo.world.index.RepoId(), repo.world.index.RefId(), backfill.Horizon, clock.Now()); err != nil {
					return err
				}
				return repo.world.ledger.Cover(repo.world.index.RepoId(), repo.world.index.RefId(), backfill.Horizon, clock.Now())
			}})
		case "documents":
			repo := event.repo
			steps = append(steps, &Step{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
				advanceTo(event.at)
				_, err := repo.commit(ctx, corpus.WriterIds[0], event.changes, true)
				return err
			}})
			if event.label == "vectors" && event.at.Equal(lastVector) && !vectorsDone {
				vectorsDone = true
				steps = append(steps, checkSteps("after the last vectors", vectorQueries, false, false)...)
			}
		case "check":
			coverage := !event.uncovered && !event.at.Before(time.UnixMilli(first+2*windowMs).Add(2*time.Hour))
			before := 0
			steps = append(steps, &Step{Actor: "clock", Action: func(ctx context.Context, net *Net) error {
				advanceTo(event.at)
				before = uncoveredSearches
				return nil
			}})
			steps = append(steps, checkSteps(event.label, nil, coverage, event.uncovered)...)
			if event.uncovered {
				steps = append(steps, &Step{Actor: "check", Action: func(ctx context.Context, net *Net) error {
					if uncoveredSearches == before {
						return fmt.Errorf("%s at %s: no search reported a change not yet searchable", event.label, event.at)
					}
					return nil
				}})
			}
		case "rollup":
			repo := event.repo
			rollCount += 1
			actor := fmt.Sprintf("roller%d", rollCount)
			label := fmt.Sprintf("%s's roll-up of %d", repo.label, event.startDay)
			steps = append(steps, &Step{Actor: "clock", Action: func(ctx context.Context, net *Net) error {
				advanceTo(event.at)
				return nil
			}})
			steps = append(steps, &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
				result, err := repo.world.index.RollUpResult(ctx, repo.indexer)
				if err == nil && (result.Version == 0 || result.StartDay != event.startDay) {
					err = fmt.Errorf("%s committed %+v", label, result)
				}
				return err
			}, Background: true})
			for _, barrier := range fs108RollUpBarriers() {
				steps = append(steps, &Step{Actor: actor, Await: barrier})
				steps = append(steps, repoSteps(repo, label+" at "+barrier, event.startDay)...)
				steps = append(steps, &Step{Release: []string{barrier}})
			}
			steps = append(steps,
				&Step{Actor: actor, Join: true},
				&Step{Actor: "check", Action: func(ctx context.Context, net *Net) error {
					if err := repo.learnRolled(ctx, event.startDay); err != nil {
						return err
					}
					if repo.rolled != event.startDay {
						return fmt.Errorf("%s left the bucket at the head", label)
					}
					return fs76Reproduce(ctx, repo, label)
				}},
			)
		case "erase":
			repo := event.repo
			var erasure *fs76Erasure
			steps = append(steps,
				&Step{Actor: "eraser", Action: func(ctx context.Context, net *Net) error {
					advanceTo(event.at)
					var err error
					erasure, err = repo.cut(ctx, event.label)
					return err
				}},
			)
			steps = append(steps, repoSteps(repo, "after the CUT of "+event.label, 0)...)
			steps = append(steps,
				&Step{Actor: "eraser", Action: func(ctx context.Context, net *Net) error {
					return repo.rewrite(ctx, erasure, event.label)
				}},
				&Step{Actor: "eraser", Action: func(ctx context.Context, net *Net) error {
					SearchRecordOf(net).CompleteErasure(repo.source.Name(), erasure.erasureId)
					return nil
				}},
			)
			steps = append(steps, repoSteps(repo, "after the erasure of "+event.label, 0)...)
		}
	}
	steps = append(steps, &Step{Actor: "clock", Action: func(ctx context.Context, net *Net) error {
		advanceTo(end)
		return nil
	}})
	steps = append(steps, checkSteps("at the end", vectorQueries, true, false)...)
	steps = append(steps, &Step{Actor: "check", Action: func(ctx context.Context, net *Net) error {
		// the equalities above found something: each canonical term matches its message, and each vector word a
		// conformance document, so the desktops' verified hits held those documents
		for _, query := range slices.Concat(canonicalQueries, vectorQueries) {
			matched := 0
			for _, repo := range repos {
				matched += len(repo.world.oracle.Matches(query, repo.world.scope(sidecartest.SearchScopeAll)))
			}
			if matched == 0 {
				return fmt.Errorf("%q matches no document of either world", query)
			}
		}
		if len(vectorQueries) == 0 {
			return errors.New("the vectors gave no query")
		}
		for _, repo := range repos {
			if !network.hitRepoIds[repo.world.index.RepoId()] {
				return fmt.Errorf("the network's devices found nothing of the %s", repo.label)
			}
		}
		return nil
	}})
	schedule := &Schedule{Id: "fs76", Steps: steps}
	for _, n := range []int{18, 19, 22} {
		schedule.Check = append(schedule.Check, FI(n))
	}
	return schedule
}

// The newest roll-up of repo's world, reproduced by a host holding its inputs: equal, it fetches nothing; signed before
// its bucket's expiry, it is index_mismatch (SEARCH-M10-21; §11.14's reproduce row).
func fs76Reproduce(ctx context.Context, repo *fs76Repo, label string) error {
	version, err := repo.world.index.HeadVersion(ctx)
	if err != nil {
		return err
	}
	for ; 0 < version; version -= 1 {
		reproduced, err := repo.world.index.ReproducePush(ctx, version, time.Time{})
		if err != nil {
			return err
		}
		if reproduced.Kind != "rollup" {
			continue
		}
		if reproduced.Mismatches != 0 || reproduced.Lacking || len(reproduced.Fetch) != 0 || len(reproduced.Matched) == 0 {
			return fmt.Errorf("%s: a host holding the roll-up's inputs reproduced %+v", label, reproduced)
		}
		early, err := repo.world.index.ReproducePush(ctx, version, time.UnixMilli(int64(repo.rolled)*24*60*60*1000))
		if err != nil {
			return err
		}
		if early.Mismatches == 0 {
			return fmt.Errorf("%s: the roll-up signed before its bucket's expiry reproduced %+v", label, early)
		}
		return nil
	}
	return errors.New(label + ": no roll-up to reproduce")
}

// FS-76's M10 case on T2: see the file header.
func TestFs76(t *testing.T) {
	wantPass(t, runFresh(t, fs76Schedule(t, defaultFs76Settings())))
}

// FS-76's forged-entries clause (§11.14's coverage row; D-EVS-56; SEARCH-M10-21's check by hosts with the text): every
// writer of a ref writes its index, so a writer can lie in its own head about the content its push commits. On a notes
// world an honest writer's pushes check clean on a host holding the text; then another writer's in-ref pushes carry an
// entry that drops a word of the version it commits, one that adds a word the version never held and a tombstone over
// a document the push keeps live, and its index-only push plants an entry at a version the path never held. Each is a
// lie a search shows (a fresh phone misses the dropped word and the hidden document, which the oracle matches), and
// each is caught by the host with the text: the entry mismatched, index_mismatch raised once naming the index file and
// the push's signer, and the host's own entry of the document's true version standing in its place. A desktop
// verifying against its own text finds no hit for the added word. An honest writer's push after them checks clean.
//
// Not here: a push that changes its writer's head and leaves a document it commits out of it, the row's "omits a
// document". The check judges the entries a push adds and coverage counts such a push indexed, so nothing catches it
// yet (question search-m10-36-omitted-document-check).
func TestFs76ForgedEntriesAreCaughtByAHostWithTheText(t *testing.T) {
	world := newFsResultsWorld(t, "forged", protocol.RepoKind_REPO_KIND_GENERAL)
	ctx := t.Context()
	honest, mallory := searchId("writer honest"), searchId("writer mallory")
	keyOf := func(path string) [16]byte {
		key, err := world.index.DocKey(path)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	checked := func(label string, refVersion uint64) *sidecar.SearchTestTextCheck {
		check, err := world.index.CheckPushWithText(ctx, refVersion)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		return check
	}
	clean := func(label string, refVersion uint64, count int) {
		check := checked(label, refVersion)
		if check.Checked != count || len(check.Mismatched) != 0 || len(check.Own) != 0 || len(check.Events) != 0 || len(check.Repairs) != 0 {
			t.Fatalf("%s: a host with the text made %+v of an honest push of %d entries", label, check, count)
		}
	}
	// the one entry of path the push at refVersion lied in: mismatched at entryVersion, the host's own entry of
	// ownVersion in its place, and one index_mismatch naming the forger's index file
	caught := func(label string, refVersion uint64, path string, entryVersion uint64, ownVersion uint64) {
		check := checked(label, refVersion)
		key := keyOf(path)
		if version, ok := check.Mismatched[key]; !ok || version != entryVersion || len(check.Mismatched) != 1 {
			t.Fatalf("%s: the host with the text mismatched %v, not %s at %d alone", label, check.Mismatched, path, entryVersion)
		}
		if version, ok := check.Own[key]; !ok || version != ownVersion || len(check.Own) != 1 {
			t.Fatalf("%s: the host's own entries are %v, not %s at %d alone", label, check.Own, path, ownVersion)
		}
		if len(check.Events) != 1 {
			t.Fatalf("%s: %d events raised", label, len(check.Events))
		}
		event := check.Events[0]
		if event.Kind != sidecar.SidecarEventIndexMismatch || event.SidecarId == nil || *event.SidecarId != mallory ||
			event.RepoId == nil || *event.RepoId != world.index.RepoId() || event.RefId == nil || *event.RefId != world.index.RefId() ||
			!strings.HasPrefix(event.Path, ".ur-index/") {
			t.Fatalf("%s: the event raised is %+v", label, event)
		}
	}
	search := func(host string, query string) *fsResultsSearch {
		device, err := world.fresh(ctx, searchHostNamed(host), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer device.Close()
		found, err := fsResultsRun(ctx, device, host, query, sidecar.SearchAll)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	// a lie a search shows: a fresh phone does not find query's document, which the oracle matches and holds covered
	shown := func(label string, query string) {
		found := search("ios32", query)
		if len(found.hits) != 0 {
			t.Fatalf("%s: a fresh phone found %v for %q, so the forged entry hides nothing", label, found.hits, query)
		}
		if err := world.hold(found); err == nil {
			t.Fatalf("%s: the oracle holds nothing against a phone finding nothing for %q", label, query)
		}
	}
	note := func(name string, title string, body string) *sidecar.SearchTestChange {
		return &sidecar.SearchTestChange{Path: "notes/" + name + ".md", Content: []byte(title + "\n" + body + "\n")}
	}
	lie := func(change *sidecar.SearchTestChange, claim *sidecar.SearchTestClaim) *sidecar.SearchTestCommit {
		commit, err := world.index.CommitIndexedClaiming(ctx, mallory, world.clock.Now(), []*sidecar.SearchTestChange{change}, []*sidecar.SearchTestClaim{claim})
		if err != nil {
			t.Fatal(err)
		}
		if err := world.recordContent(mallory, commit, []*sidecar.SearchTestChange{change}); err != nil {
			t.Fatal(err)
		}
		world.clock.Advance(time.Minute)
		return commit
	}

	first := []*sidecar.SearchTestChange{
		note("a", "Field log", "kestrel heron"), note("b", "Tide table", "plover curlew"),
		note("c", "Hedge walk", "wren dunnock"), note("d", "Garden list", "siskin linnet"),
		note("e", "Shore list", "turnstone knot"),
	}
	commit, err := world.commit(ctx, honest, first...)
	if err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(time.Minute)
	firstVersions := commit.Versions
	clean("the honest writer's first push", commit.RefVersion, len(first))
	queries := []string{"kestrel", "plover", "wren", "siskin", "turnstone"}
	if err := world.checkFresh(ctx, nil, nil, "before any forgery", sidecar.SearchAll, queries...); err != nil {
		t.Fatal(err)
	}

	// dropped: the version committed holds gannet, and the entry beside it is the old text's
	edit := note("a", "Field log", "kestrel heron gannet")
	commit = lie(edit, &sidecar.SearchTestClaim{Path: edit.Path, Content: first[0].Content})
	caught("an entry dropping a word", commit.RefVersion, edit.Path, commit.Versions[edit.Path], commit.Versions[edit.Path])
	shown("an entry dropping a word", "gannet")

	// added: the entry holds bittern, which the version committed does not
	edit = note("b", "Tide table", "plover curlew dunlin")
	commit = lie(edit, &sidecar.SearchTestClaim{Path: edit.Path, Content: note("b", "Tide table", "plover curlew dunlin bittern").Content})
	caught("an entry adding a word", commit.RefVersion, edit.Path, commit.Versions[edit.Path], commit.Versions[edit.Path])
	found := search("desktop", "bittern")
	if len(found.hits) != 0 {
		t.Fatalf("a desktop holding the text found %v for a word no document holds", found.hits)
	}
	if err := world.hold(found); err != nil {
		t.Fatal(err)
	}

	// hidden: a tombstone over a document the push keeps live
	edit = note("c", "Hedge walk", "wren dunnock firecrest")
	commit = lie(edit, &sidecar.SearchTestClaim{Path: edit.Path})
	caught("a tombstone hiding a live document", commit.RefVersion, edit.Path, commit.Versions[edit.Path], commit.Versions[edit.Path])
	shown("a tombstone hiding a live document", "firecrest")

	// planted: an index-only push's entry at a version the path never held
	standing := firstVersions["notes/d.md"]
	plantedVersion := standing + 5
	planned, err := world.index.PlanPush(ctx, mallory, world.clock.Now(), []*sidecar.SearchTestDocument{
		{Path: "notes/d.md", Version: plantedVersion, Title: "Garden list", Text: "smew goosander", Time: world.clock.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	plantedAt, err := planned.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(time.Minute)
	caught("an entry planted at a version never held", plantedAt, "notes/d.md", plantedVersion, standing)

	// an honest push after them checks clean, the forger's entries standing in the index beside it
	edit = note("e", "Shore list", "turnstone knot sanderling")
	commit, err = world.commit(ctx, honest, edit)
	if err != nil {
		t.Fatal(err)
	}
	clean("the honest writer's push after the forgeries", commit.RefVersion, 1)
}
