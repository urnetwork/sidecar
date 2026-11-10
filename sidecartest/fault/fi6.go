// FI-6, visibility (§22.8; I-EVS-2, I-EVS-4, I-EVS-5, I-EVS-6; D-TEST-10), on the store walk fi1.go makes. Each
// clause is read from the store and from §11's text alone:
//
//   - a file's newest committed version is where a reader finds it (§11.7's newest and horizon rows): the window
//     holds every version after folded_through, and a path whose newest committed change is at or below
//     folded_through has its entry hold it, in the current epoch or, while the head lists sources, in the source a
//     committed map's moves name for it (DESIGN-DETAILS 9.2.1's one home per path); a removal at or below
//     folded_through in the current epoch is its entry's marker until head.collect.done passes it;
//   - nothing uncommitted evicts it: every folded version and marker an idx/ entry holds is the version the head
//     history commits at that ref version, of that push and with those bytes;
//   - no directory delta leaves the window before its name table holds it: a directory's newest delta at or below
//     folded_through is at or below its entry's names_through, and on a ref that never changed epoch the table
//     holds exactly the rows its deltas leave there;
//   - every uncommitted object is reclaimable after its deadline, found without the log: a slot no committed version
//     names is listed as new by a record still in a batch once it is 26 h old (§11.8's objects table: a dead push's
//     slots live <= ~26 h), so evacuation's Resolve finds and deletes it; segments, path map parts and staged wraps
//     are found by their reclaimers' LISTs of their repo's or group's prefix, which no key escapes;
//   - nothing committed or unknown is reclaimed: between two checks, no DELETE takes a segment, slot or map part a
//     committed version named, nor a batch, slot or segment of a push that was pending at the first check and is
//     still pending (neither committed nor dead by §11.8's Resolve row) at the second; and no segment goes before
//     DESIGN-DETAILS 2.2.4's horizon passed its LastModified + 24 h 2 min, which is at least 25 h past that bound.
//
// Unknown is read from durable state, so it spans a kill: a record in a batch whose push the head history neither
// commits nor shows dead is pending, whatever the process that wrote it saw. FI-2's ledger (TEST-M2-04's
// fault.Ledger, not landed) is the client's view of the same operations; until it lands, FI-6 holds no client-side
// unknown that left no record, such as an upload whose response was lost, beyond the segment horizon rule.
//
// Deferred, failing closed or unchecked as each says: a table's rows across a path-epoch cut-over are checked by
// names_through alone; QD-011's orphan markers under idx/<repo>/<ref>/_o/, which carry format 2's ids, are left to
// FI-16 and FI-27; a batch written and deleted within one step, which no check saw, is not judged; a format-2
// repo's segment deletes (the versionless purge, a drop job) are FI-16's and FI-27's (TEST-M10-01), so the horizon
// clause skips a repo of format 2; a staged wrap's 24 h is gkm's reconciler's and is not checked here.

package fault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var _ = RegisterInvariant(6, func(ctx context.Context, oracle *Oracle) error {
	return checkFi6(ctx, oracle)
})

// Design values FI-6 holds evs to, each §11's or DESIGN-DETAILS 2's: facts of the invariant, not tunables.
const (
	// §11.8's objects table: a dead push's slots are gone within ~26 h.
	fi6DeadSlotDeadline = 26 * time.Hour
	// DESIGN-DETAILS 2.2.4's AdoptionBound, and the horizon's floor 25 h before its LIST.
	fi6AdoptionBound = 24*time.Hour + 2*time.Minute
	fi6HorizonFloor  = 25 * time.Hour
	// §11.8's Resolve row: a statement can no longer pass the time checks 35 min after its time_ms.
	fi6StatementLife = 35 * time.Minute
	// §11.8's Resolve row: a file-mode push commits within (b, b+64].
	fi6ResolveRange = 64
	// QD-011's orphan markers, idx/<repo>/<ref>/_o/, outside every epoch.
	fi6OrphanMarkerDirectory = "_o/"
)

// What FI-6 keeps from one check to the next.
type fi6Memory struct {
	// objects a committed version named at the last check, "cluster\x00key" -> what named it
	committedObjects map[string]string
	// objects of a push pending at the last check, "cluster\x00key" -> the push
	pendingObjects map[string]*fi6PendingPush
	// seg/ objects' LastModified at the last check, by cluster and key
	segmentTimes map[string]time.Time
	// whether the last check ran
	checked bool
}

func newFi6Memory() *fi6Memory {
	return &fi6Memory{committedObjects: map[string]string{}, pendingObjects: map[string]*fi6PendingPush{}, segmentTimes: map[string]time.Time{}}
}

type fi6PendingPush struct {
	repoId   sidecar.Id
	refId    sidecar.Id
	pushId   sidecar.Id
	batchKey string
	// what Resolve's dead rule reads of its statement, kept for when its record has gone
	baseVersion uint64
	timeMs      int64
	gitMode     bool
}

// A record in a batch, as the reclaim clauses read it.
type fi6BatchRecord struct {
	clusterId  string
	batchKey   string
	place      *protocol.EvsPlace
	record     *sidecar.EvsBatchRecord
	statement  *sidecar.EvsStatement
	segmentIds [][]byte
	slotIds    [][]byte
}

// What §11.8's Resolve row makes of a record on its ref's head.
type fi6Outcome int

const (
	fi6Pending fi6Outcome = iota
	fi6CommittedHere
	fi6CommittedElsewhere
	fi6Dead
)

func checkFi6(ctx context.Context, oracle *Oracle) error {
	repos, walkErrs := evsStoreWalkOf(ctx, oracle)
	memory := evsOracleMemoryOf(oracle.Net)
	errs := []error{}
	if 0 < len(walkErrs) {
		// what the walk could not read is FI-1's to name; FI-6 cannot judge past it, so it fails closed
		errs = append(errs, fmt.Errorf("the store walk could not read every repo, so FI-6 judges none of them whole: %w", walkErrs[0]))
	}
	repoById := map[sidecar.Id]*evsStoreRepo{}
	for _, repo := range repos {
		repoById[repo.repoId] = repo
		shredded, _ := fi1ShredAuthorized(repo, memory.authorizationView(repo.networkId()))
		if shredded || repo.walkedBy != oracle {
			// a walk reused from an earlier check changed in nothing its ref clauses read, and they held then
			continue
		}
		for _, ref := range repo.refs {
			errs = append(errs, fi6CheckRef(ctx, oracle, repo, ref)...)
		}
	}
	records, oldestBatch, batchErrs := fi6Batches(ctx, oracle, memory)
	errs = append(errs, batchErrs...)
	errs = append(errs, fi6CheckOrphanSlots(oracle, repos, records)...)
	errs = append(errs, fi6CheckReclaims(oracle, memory, repoById, records, oldestBatch)...)
	return errors.Join(errs...)
}

// One path of a ref through its history: its token path in each epoch it lived in, its newest committed change, and
// a directory's deltas.
type fi6Path struct {
	tokenPaths map[uint64]sidecar.EvsTokenPath
	newest     *fi6Change
	// a directory's deltas since its newest creation or removal, in version order
	deltas []*fi6Change
	// whether its newest change was a directory's
	directory bool
}

type fi6Change struct {
	version      uint64
	epoch        uint64
	pushId       sidecar.Id
	entrySha256  []byte
	entryVersion *protocol.EvsEntryVersion
	removal      bool
	// a removal of a directory above the path, not of the path itself
	prefixRemoval bool
}

// A ref's paths, replayed from its committed history.
type fi6Replay struct {
	paths   []*fi6Path
	byToken map[uint64]map[string]*fi6Path
	// the version of the newest committed PATH_EPOCH, 0 for none
	cutOver uint64
}

func (self *fi6Replay) path(epoch uint64, tokenPath sidecar.EvsTokenPath, create bool) *fi6Path {
	if self.byToken[epoch] == nil {
		self.byToken[epoch] = map[string]*fi6Path{}
	}
	key := string(tokenPath.Bytes())
	if path, ok := self.byToken[epoch][key]; ok || !create {
		return path
	}
	path := &fi6Path{tokenPaths: map[uint64]sidecar.EvsTokenPath{epoch: tokenPath}}
	self.byToken[epoch][key] = path
	self.paths = append(self.paths, path)
	return path
}

// The ref's committed history replayed path by path, its paths carried across each committed map.
func fi6ReplayRef(ctx context.Context, oracle *Oracle, repo *evsStoreRepo, ref *evsStoreRef) (*fi6Replay, error) {
	replay := &fi6Replay{byToken: map[uint64]map[string]*fi6Path{}}
	memory := evsOracleMemoryOf(oracle.Net)
	for _, version := range ref.versions {
		push := version.statement.Push
		epoch := push.GetPathEpoch()
		if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
			moves, err := fi1MapMoves(ctx, oracle.View, memory, repo, ref.refId, epoch, push.GetPathMapSha256())
			if err != nil {
				return nil, fmt.Errorf("the PATH_EPOCH at %d's map: %w", version.version, err)
			}
			for _, moveBytes := range version.payload.TailMoves {
				move := &protocol.EvsPathMove{}
				if err := proto.Unmarshal(moveBytes, move); err != nil {
					return nil, fmt.Errorf("the PATH_EPOCH at %d's tail: %w", version.version, err)
				}
				moves = append(moves, move)
			}
			for _, move := range moves {
				newPath, err := sidecar.ParseEvsTokenPath(move.GetNewTokenPath())
				if err != nil {
					return nil, fmt.Errorf("the PATH_EPOCH at %d moves to %w", version.version, err)
				}
				var path *fi6Path
				for _, source := range move.GetSources() {
					sourcePath, err := sidecar.ParseEvsTokenPath(source.GetTokenPath())
					if err != nil {
						continue
					}
					if path = replay.path(source.GetEpoch(), sourcePath, false); path != nil {
						break
					}
				}
				if path == nil {
					path = replay.path(epoch, newPath, true)
				}
				path.tokenPaths[epoch] = newPath
				if replay.byToken[epoch] == nil {
					replay.byToken[epoch] = map[string]*fi6Path{}
				}
				replay.byToken[epoch][string(newPath.Bytes())] = path
			}
			replay.cutOver = version.version
		}
		for i, change := range version.payload.Changes {
			path := replay.path(epoch, change.TokenPath, true)
			step := &fi6Change{version: version.version, epoch: epoch, pushId: version.entry.PushId}
			entryVersion := version.entryVersions[i]
			if entryVersion == nil {
				step.removal = true
				path.newest = step
				path.deltas = nil
				// every path below a removed directory is removed with it (§11.7's newest row)
				for _, below := range replay.paths {
					belowPath, ok := below.tokenPaths[epoch]
					if !ok || below == path || len(belowPath) <= len(change.TokenPath) || !belowPath.HasPrefix(change.TokenPath) {
						continue
					}
					if below.newest == nil || below.newest.version < version.version {
						below.newest = &fi6Change{version: version.version, epoch: epoch, pushId: version.entry.PushId, removal: true, prefixRemoval: true}
						below.deltas = nil
					}
				}
				continue
			}
			step.entrySha256 = change.Change.GetEntrySha256()
			step.entryVersion = entryVersion
			path.newest = step
			path.directory = protocol.EvsEntryKind(entryVersion.GetKind()) == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
			if path.directory {
				if change.Change.GetBaseEntryVersion() == 0 {
					path.deltas = nil
				}
				path.deltas = append(path.deltas, step)
			} else {
				path.deltas = nil
			}
		}
	}
	return replay, nil
}

// An idx/ entry read, nil when absent.
func fi6Entry(ctx context.Context, oracle *Oracle, repo *evsStoreRepo, key string) (*protocol.EvsIndexEntry, error) {
	object, err := oracle.View.Object(ctx, repo.clusterId, key)
	if err != nil || object == nil {
		return nil, err
	}
	value, err := evsOracleMemoryOf(oracle.Net).decodedObject(object, func(body []byte) (any, error) {
		entry := &protocol.EvsIndexEntry{}
		if err := proto.Unmarshal(body, entry); err != nil {
			return nil, err
		}
		return entry, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return value.(*protocol.EvsIndexEntry), nil
}

// The entry a reader finds for a path: its current epoch's, else, while the head lists sources, the newest
// source's that holds it. "" and nil when none holds it.
func fi6Home(ctx context.Context, oracle *Oracle, repo *evsStoreRepo, ref *evsStoreRef, path *fi6Path) (string, *protocol.EvsIndexEntry, error) {
	pathEpoch := ref.head.Head.GetPathEpoch()
	epochs := []uint64{pathEpoch.GetCurrent()}
	for _, source := range pathEpoch.GetSources() {
		epochs = append(epochs, source.GetEpoch())
	}
	for _, epoch := range epochs {
		tokenPath, ok := path.tokenPaths[epoch]
		if !ok {
			continue
		}
		key := evsOracleIndexKey(repo.repoId, ref.refId, epoch, tokenPath)
		entry, err := fi6Entry(ctx, oracle, repo, key)
		if err != nil {
			return "", nil, err
		}
		if entry != nil {
			return key, entry, nil
		}
	}
	return "", nil, nil
}

// The ref's clauses: the window covers the unfolded versions, every newest version at or below the horizon is in
// its entry, no entry holds an uncommitted version, and every directory's table holds its folded deltas.
func fi6CheckRef(ctx context.Context, oracle *Oracle, repo *evsStoreRepo, ref *evsStoreRef) []error {
	head := ref.head.Head
	version := head.GetVersion()
	if version == 0 {
		return nil
	}
	prefix := fmt.Sprintf("repo %s ref %s: ", repo.repoId, ref.refId)
	failf := func(format string, a ...any) error { return fmt.Errorf(prefix+format, a...) }
	errs := []error{}
	foldedThrough := head.GetFoldedThrough()
	windowFirst := version - uint64(len(head.GetWindow())/sidecar.EvsWindowEntryByteCount) + 1
	if version < foldedThrough {
		errs = append(errs, failf("folded_through %d is past the head's version %d", foldedThrough, version))
	}
	if foldedThrough+1 < windowFirst {
		errs = append(errs, failf("versions %d to %d left the window unfolded (folded_through %d)", foldedThrough+1, windowFirst-1, foldedThrough))
	}
	if !ref.complete {
		// its history could not be read whole (FI-1 names what is missing), so no clause below can be judged
		return append(errs, failf("its history could not be read whole, so its visibility cannot be judged"))
	}
	replay, err := fi6ReplayRef(ctx, oracle, repo, ref)
	if err != nil {
		return append(errs, failf("%v", err))
	}
	current := head.GetPathEpoch().GetCurrent()
	collectDone := head.GetCollect().GetDone()
	for _, path := range replay.paths {
		newest := path.newest
		if newest == nil || foldedThrough < newest.version {
			continue
		}
		key, entry, err := fi6Home(ctx, oracle, repo, ref, path)
		if err != nil {
			errs = append(errs, failf("%v", err))
			continue
		}
		name := fi6PathName(path, current)
		switch {
		case newest.removal:
			if newest.epoch != current || newest.version <= collectDone || newest.version <= replay.cutOver {
				// collected past the horizon, or removed before the cut-over: a reader reads it absent either way
				continue
			}
			marker := entry.GetMarker()
			if entry == nil || marker == nil || marker.GetRemovalVersion() < newest.version {
				errs = append(errs, failf("%s's removal at %d is folded (folded_through %d) and its entry holds no marker of it", name, newest.version, foldedThrough))
			}
		case path.directory:
			if entry == nil || entry.GetNamesThrough() < newest.version {
				errs = append(errs, failf("directory %s's delta at %d is folded (folded_through %d) and its name table is through %d: a delta left the window before its table held it", name, newest.version, foldedThrough, entry.GetNamesThrough()))
				continue
			}
			if replay.cutOver == 0 && len(head.GetPathEpoch().GetSources()) == 0 {
				if err := fi6CheckTable(path, entry); err != nil {
					errs = append(errs, failf("directory %s at %s: %v", name, key, err))
				}
			}
		default:
			if entry == nil {
				errs = append(errs, failf("%s's newest version at %d is folded (folded_through %d) and in no entry: the reader cannot find it", name, newest.version, foldedThrough))
				continue
			}
			versions := entry.GetVersions()
			if len(versions) == 0 || versions[0].GetCommitVersion() != newest.version || !bytes.Equal(versions[0].GetPushId(), newest.pushId.Bytes()) {
				held := "nothing"
				if 0 < len(versions) {
					held = fmt.Sprintf("the version at %d", versions[0].GetCommitVersion())
				}
				errs = append(errs, failf("%s's newest committed version is at %d and %s holds %s as its newest: it was evicted", name, newest.version, key, held))
				continue
			}
			if !versions[0].GetElided() {
				digest := sha256.Sum256(versions[0].GetEntryVersion())
				if !bytes.Equal(digest[:], newest.entrySha256) {
					errs = append(errs, failf("%s's newest version in %s is not the bytes its push committed at %d", name, key, newest.version))
				}
			}
		}
	}
	errs = append(errs, fi6CheckEntriesCommitted(ctx, oracle, repo, ref, replay)...)
	return errs
}

func fi6PathName(path *fi6Path, epoch uint64) string {
	if tokenPath, ok := path.tokenPaths[epoch]; ok {
		if len(tokenPath) == 0 {
			return "the root"
		}
		return tokenPath.KeyString()
	}
	for _, tokenPath := range path.tokenPaths {
		return tokenPath.KeyString()
	}
	return "a path"
}

// A directory's table against the rows its deltas leave through names_through, on a ref of one epoch.
func fi6CheckTable(path *fi6Path, entry *protocol.EvsIndexEntry) error {
	want := map[string]uint32{}
	for _, delta := range path.deltas {
		if entry.GetNamesThrough() < delta.version {
			break
		}
		names := delta.entryVersion.GetNames()
		for _, removed := range names.GetRemovedTokens() {
			delete(want, string(removed))
		}
		for _, row := range names.GetNames() {
			want[string(row.GetToken())] = row.GetKind()
		}
	}
	held := map[string]uint32{}
	for _, row := range entry.GetNames().GetNames() {
		held[string(row.GetToken())] = row.GetKind()
	}
	for token, kind := range want {
		if heldKind, ok := held[token]; !ok || heldKind != kind {
			return fmt.Errorf("its table lacks the row %x its deltas through %d leave", token, entry.GetNamesThrough())
		}
	}
	for token := range held {
		if _, ok := want[token]; !ok {
			return fmt.Errorf("its table holds a row %x no delta through %d leaves", token, entry.GetNamesThrough())
		}
	}
	return nil
}

// The epoch and token path an idx/ key under a ref names.
func fi6ParseIndexKey(refPrefix string, key string) (uint64, sidecar.EvsTokenPath, error) {
	rest, ok := strings.CutPrefix(key, refPrefix)
	if !ok {
		return 0, nil, fmt.Errorf("%s is not under %s", key, refPrefix)
	}
	rest, ok = strings.CutSuffix(rest, ".e")
	if !ok {
		return 0, nil, fmt.Errorf("%s is no entry", key)
	}
	components := strings.Split(rest, "/")
	epoch, err := strconv.ParseUint(components[0], 10, 64)
	if err != nil || len(components[0]) != 20 {
		return 0, nil, fmt.Errorf("%s names no epoch", key)
	}
	tokenPath := sidecar.EvsTokenPath{}
	for _, component := range components[1:] {
		token, err := sidecar.ParseEvsToken(component)
		if err != nil {
			return 0, nil, fmt.Errorf("%s: %w", key, err)
		}
		tokenPath = append(tokenPath, token)
	}
	return epoch, tokenPath, nil
}

// Every version and marker an idx/ entry of the ref holds is the one the head history commits at that ref version.
func fi6CheckEntriesCommitted(ctx context.Context, oracle *Oracle, repo *evsStoreRepo, ref *evsStoreRef, replay *fi6Replay) []error {
	refPrefix := evsOracleRefPrefix("idx/", repo.repoId, ref.refId)
	infos, err := oracle.View.List(ctx, repo.clusterId, refPrefix)
	if err != nil {
		return []error{err}
	}
	errs := []error{}
	for _, info := range infos {
		if strings.HasPrefix(info.Key, refPrefix+fi6OrphanMarkerDirectory) {
			// an orphan marker sits outside every epoch and holds a removed version's carried ids, format 2's
			// content (QD-011), which FI-16's and FI-27's oracles judge (TEST-M10-01)
			continue
		}
		epoch, tokenPath, err := fi6ParseIndexKey(refPrefix, info.Key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		entry, err := fi6Entry(ctx, oracle, repo, info.Key)
		if err != nil || entry == nil {
			if err != nil {
				errs = append(errs, err)
			}
			continue
		}
		path := replay.path(epoch, tokenPath, false)
		committedAt := func(commitVersion uint64, pushId []byte) *evsStoreVersion {
			committed := ref.at(commitVersion)
			if committed == nil || !bytes.Equal(committed.entry.PushId.Bytes(), pushId) {
				return nil
			}
			return committed
		}
		for _, held := range entry.GetVersions() {
			committed := committedAt(held.GetCommitVersion(), held.GetPushId())
			if committed == nil {
				errs = append(errs, fmt.Errorf("repo %s ref %s: %s holds a version of push %x at %d, which the head history does not commit there: an uncommitted version in the index", repo.repoId, ref.refId, info.Key, held.GetPushId(), held.GetCommitVersion()))
				continue
			}
			if held.GetElided() {
				continue
			}
			digest := sha256.Sum256(held.GetEntryVersion())
			matched := false
			for i, change := range committed.payload.Changes {
				if !bytes.Equal(change.Change.GetEntrySha256(), digest[:]) {
					continue
				}
				// held to its own path where the replay knows it, else to some change of that push
				if path == nil || slices.ContainsFunc(sortedTokenPaths(path), func(tokenPath sidecar.EvsTokenPath) bool {
					return tokenPath.Equal(committed.payload.Changes[i].TokenPath)
				}) {
					matched = true
				}
			}
			if !matched {
				errs = append(errs, fmt.Errorf("repo %s ref %s: %s holds bytes at %d that push %x did not commit for its path", repo.repoId, ref.refId, info.Key, held.GetCommitVersion(), held.GetPushId()))
			}
		}
		if marker := entry.GetMarker(); marker != nil && committedAt(marker.GetRemovalVersion(), marker.GetPushId()) == nil {
			errs = append(errs, fmt.Errorf("repo %s ref %s: %s holds a marker of push %x at %d, which the head history does not commit there", repo.repoId, ref.refId, info.Key, marker.GetPushId(), marker.GetRemovalVersion()))
		}
		if entry.GetNames() != nil && 0 < entry.GetNamesThrough() {
			if committed := ref.at(entry.GetNamesThrough()); committed == nil {
				errs = append(errs, fmt.Errorf("repo %s ref %s: %s's table is through %d, past the head history", repo.repoId, ref.refId, info.Key, entry.GetNamesThrough()))
			}
		}
	}
	return errs
}

func sortedTokenPaths(path *fi6Path) []sidecar.EvsTokenPath {
	tokenPaths := []sidecar.EvsTokenPath{}
	for _, tokenPath := range path.tokenPaths {
		tokenPaths = append(tokenPaths, tokenPath)
	}
	return tokenPaths
}

// Every record of every batch on every metadata cluster, with the objects it lists as new, and the oldest batch's
// minute. A batch of format 2 is FI-16's and FI-27's to read (TEST-M10-01).
func fi6Batches(ctx context.Context, oracle *Oracle, memory *evsOracleMemory) ([]*fi6BatchRecord, time.Time, []error) {
	records := []*fi6BatchRecord{}
	var oldest time.Time
	errs := []error{}
	for _, clusterId := range oracle.Net.Host().Blobs.MetadataClusterIds() {
		objects, err := oracle.View.Objects(ctx, clusterId, "pb/")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, object := range objects {
			minute, ok := evsOracleBatchKeyMinute(object.Key)
			if !ok {
				errs = append(errs, fmt.Errorf("%s is no batch key", object.Key))
				continue
			}
			if oldest.IsZero() || minute.Before(oldest) {
				oldest = minute
			}
			value, err := memory.decodedObject(object, func(body []byte) (any, error) {
				return sidecar.ParseEvsBatch(body)
			})
			if errors.Is(err, sidecar.ErrEvsFormatUnsupported) {
				continue
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", object.Key, err))
				continue
			}
			batch := value.(*sidecar.EvsBatch)
			for i, record := range batch.Records {
				read := &fi6BatchRecord{clusterId: clusterId, batchKey: object.Key, place: batch.Places[i], record: record}
				if err := read.decode(); err != nil {
					errs = append(errs, fmt.Errorf("%s's record %d: %w", object.Key, i, err))
					continue
				}
				records = append(records, read)
			}
		}
	}
	return records, oldest, errs
}

// The record's statement and the objects it lists as new: a push's or reseed's payload items, a part's sections and
// receipts; a seal lists none, its parts do (§11.8's record row).
func (self *fi6BatchRecord) decode() error {
	addNewObjects := func(sectionsBytes []byte) error {
		if len(sectionsBytes) == 0 {
			return nil
		}
		payload, err := sidecar.ParseEvsPayload(sectionsBytes)
		if err != nil {
			return err
		}
		objects, err := sidecar.EvsDecodeNewObjects(payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_NEW_OBJECTS))
		if err != nil {
			return err
		}
		for _, object := range objects {
			switch object.Kind {
			case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT:
				self.slotIds = append(self.slotIds, object.Id)
			default:
				self.segmentIds = append(self.segmentIds, object.Id)
			}
		}
		return nil
	}
	var statementBytes []byte
	var err error
	switch self.record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		var payloadBytes []byte
		if statementBytes, payloadBytes, err = sidecar.ParseEvsPushRecordBody(self.record.Body); err != nil {
			return err
		}
		if err := addNewObjects(payloadBytes); err != nil {
			return err
		}
	case protocol.EvsBatchRecordType_EVS_BATCH_PART:
		var partBytes []byte
		var receipts [][]byte
		if statementBytes, partBytes, receipts, _, err = sidecar.ParseEvsPartRecordBody(self.record.Body); err != nil {
			return err
		}
		part := &protocol.EvsPushPart{}
		if err := proto.Unmarshal(partBytes, part); err != nil {
			return err
		}
		if err := addNewObjects(part.GetSections()); err != nil {
			return err
		}
		for _, receiptBytes := range receipts {
			receipt := &protocol.EvsUploadReceipt{}
			if err := proto.Unmarshal(receiptBytes, receipt); err == nil && len(receipt.GetSegmentId()) == 32 {
				self.segmentIds = append(self.segmentIds, receipt.GetSegmentId())
			}
		}
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		if statementBytes, _, err = sidecar.ParseEvsSealRecordBody(self.record.Body); err != nil {
			return err
		}
	default:
		return fmt.Errorf("record type %d", self.record.Type)
	}
	self.statement, err = evsOracleParseStatement(statementBytes)
	return err
}

// §11.8's Resolve row, from its text: P is committed at u iff the head history names P at a version u in (b, b+64]
// (file mode) or at b+1 (git mode), here or at another place; dead iff not committed and the head is at or past b+64
// (git mode: b+1), or its statement can no longer pass the time checks (time_ms + 35 min) and the head's fence_ms is
// later than that; otherwise pending. A reseed record counts as committed, and a ref with no head leaves P pending.
func fi6Resolve(repo *evsStoreRepo, read *fi6BatchRecord) fi6Outcome {
	if read.record.Type == protocol.EvsBatchRecordType_EVS_BATCH_RESEED {
		return fi6CommittedHere
	}
	var ref *evsStoreRef
	if repo != nil {
		for _, each := range repo.refs {
			if each.refId == read.record.RefId {
				ref = each
			}
		}
	}
	if ref == nil {
		return fi6Pending
	}
	push := read.statement.Push
	base := push.GetBaseVersion()
	last := base + fi6ResolveRange
	if protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT {
		last = base + 1
	}
	for at := base + 1; at <= last; at += 1 {
		committed := ref.at(at)
		if committed == nil || committed.entry.PushId != read.record.PushId {
			continue
		}
		if read.record.Type == protocol.EvsBatchRecordType_EVS_BATCH_PART {
			// a part commits with its seal, which names its place
			return fi6CommittedHere
		}
		if evsOraclePlacesEqual(committed.entry.Place, read.place) {
			return fi6CommittedHere
		}
		return fi6CommittedElsewhere
	}
	head := ref.head.Head
	if last <= head.GetVersion() {
		return fi6Dead
	}
	if push.GetTimeMs()+fi6StatementLife.Milliseconds() < head.GetFenceMs() {
		return fi6Dead
	}
	return fi6Pending
}

func fi6ObjectKey(clusterId string, key string) string {
	return clusterId + "\x00" + key
}

// A slot no committed version names, once past a dead push's deadline, is listed as new by a record still in a
// batch, where evacuation's Resolve finds it: otherwise nothing ever reclaims it.
func fi6CheckOrphanSlots(oracle *Oracle, repos []*evsStoreRepo, records []*fi6BatchRecord) []error {
	listed := map[string]bool{}
	for _, read := range records {
		for _, slotId := range read.slotIds {
			listed[evsOracleSlotKey(read.record.RepoId, slotId)] = true
		}
	}
	now := oracle.Net.Clock().Now()
	errs := []error{}
	for _, repo := range repos {
		named := fi6NamedObjects(repo)
		for key, info := range repo.slotInfos {
			if named[key] || listed[key] || now.Before(info.LastModified.Add(fi6DeadSlotDeadline)) {
				continue
			}
			errs = append(errs, fmt.Errorf("repo %s: %s, which no committed version names, is %s old and no batch record lists it: no reclaimer finds it", repo.repoId, key, now.Sub(info.LastModified).Round(time.Minute)))
		}
	}
	return errs
}

// The seg/, slot/ and pmap/ keys a committed version of the repo names.
func fi6NamedObjects(repo *evsStoreRepo) map[string]bool {
	named := map[string]bool{}
	for _, ref := range repo.refs {
		for _, version := range ref.versions {
			if version == nil {
				continue
			}
			for _, entryVersion := range version.entryVersions {
				if entryVersion == nil {
					continue
				}
				for _, locator := range entryVersion.GetChain() {
					if len(locator.GetId()) != 0 {
						named[evsOracleSegmentKey(repo.repoId, locator.GetId())] = true
					}
				}
				for _, slotId := range entryVersion.GetSlotIds() {
					named[evsOracleSlotKey(repo.repoId, slotId)] = true
				}
			}
			push := version.statement.Push
			if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
				named[evsOracleMapPrefix(repo.repoId, ref.refId, push.GetPathEpoch(), push.GetPathMapSha256())] = true
			}
		}
	}
	return named
}

// Nothing committed or unknown is reclaimed between the last check and this one, and no segment goes before GC's
// horizon could pass it; then what this check found is kept for the next.
func fi6CheckReclaims(oracle *Oracle, memory *evsOracleMemory, repoById map[sidecar.Id]*evsStoreRepo, records []*fi6BatchRecord, oldestBatch time.Time) []error {
	segmentCluster, err := oracle.Net.Host().Blobs.SegmentCluster()
	if err != nil {
		return []error{err}
	}
	segmentClusterId := segmentCluster.ClusterId()
	memory.stateLock.Lock()
	previous := memory.fi6
	memory.stateLock.Unlock()
	errs := []error{}
	shreddedRepo := func(repoId sidecar.Id) bool {
		repo := repoById[repoId]
		if repo == nil {
			return false
		}
		shredded, _ := fi1ShredAuthorized(repo, memory.authorizationView(repo.networkId()))
		return shredded
	}
	if previous.checked {
		for _, entry := range oracle.Changed() {
			if entry.Op != sidecartest.BlobHistoryDelete || entry.Outcome != sidecartest.BlobOutcomeOk {
				continue
			}
			objectKey := fi6ObjectKey(entry.ClusterId, entry.Key)
			repoId, hasRepo := evsOracleKeyRepo(entry.Key)
			if hasRepo && shreddedRepo(repoId) {
				continue
			}
			namedBy, committed := previous.committedObjects[objectKey]
			if !committed && strings.HasPrefix(entry.Key, "pmap/") {
				for prefix, by := range previous.committedObjects {
					if strings.HasPrefix(objectKey, prefix) {
						namedBy, committed = by, true
					}
				}
			}
			if committed {
				errs = append(errs, fmt.Errorf("%s deleted %s on %s, which %s names: a committed object reclaimed", entry.Actor, entry.Key, entry.ClusterId, namedBy))
			}
			if pending := previous.pendingObjects[objectKey]; pending != nil {
				outcome := fi6Pending
				for _, read := range records {
					if read.record.PushId == pending.pushId {
						if resolved := fi6Resolve(repoById[pending.repoId], read); resolved != fi6Pending {
							outcome = resolved
						}
					}
				}
				if outcome == fi6Pending {
					// its record may be gone with the batch: resolve on the ref's history alone
					outcome = fi6ResolveGone(repoById[pending.repoId], pending)
				}
				if outcome == fi6Pending {
					errs = append(errs, fmt.Errorf("%s deleted %s on %s, which push %s, still pending, needs: an unknown outcome reclaimed", entry.Actor, entry.Key, entry.ClusterId, pending.pushId))
				}
			}
			if entry.ClusterId == segmentClusterId && strings.HasPrefix(entry.Key, "seg/") {
				repo := repoById[repoId]
				if repo != nil && repo.object != nil && repo.object.GetFormat() == sidecar.EvsRepoFormat2 {
					continue
				}
				lastModified, known := previous.segmentTimes[objectKey]
				if !known {
					continue
				}
				bound := lastModified.Add(fi6AdoptionBound)
				switch {
				case entry.Invoked.Before(bound.Add(fi6HorizonFloor)):
					errs = append(errs, fmt.Errorf("%s deleted %s %s after its upload: GC's horizon is never past its bound before %s (DESIGN-DETAILS 2.2.4)", entry.Actor, entry.Key, entry.Invoked.Sub(lastModified).Round(time.Minute), fi6AdoptionBound+fi6HorizonFloor))
				case !oldestBatch.IsZero() && oldestBatch.Before(bound):
					errs = append(errs, fmt.Errorf("%s deleted %s while a batch of %s, before its bound, was left: a push in it could still adopt it", entry.Actor, entry.Key, oldestBatch.Format(time.RFC3339)))
				}
			}
		}
	}

	next := newFi6Memory()
	next.checked = true
	for repoId, repo := range repoById {
		for key := range fi6NamedObjects(repo) {
			clusterId := repo.clusterId
			if strings.HasPrefix(key, "seg/") {
				clusterId = segmentClusterId
			}
			next.committedObjects[fi6ObjectKey(clusterId, key)] = "a committed version of repo " + repoId.String()
		}
		for key, info := range repo.segmentInfos {
			next.segmentTimes[fi6ObjectKey(segmentClusterId, key)] = info.LastModified
		}
	}
	for _, read := range records {
		repo := repoById[read.record.RepoId]
		if fi6Resolve(repo, read) != fi6Pending {
			continue
		}
		push := read.statement.Push
		pending := &fi6PendingPush{
			repoId: read.record.RepoId, refId: read.record.RefId, pushId: read.record.PushId, batchKey: read.batchKey,
			baseVersion: push.GetBaseVersion(), timeMs: push.GetTimeMs(),
			gitMode: protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT,
		}
		next.pendingObjects[fi6ObjectKey(read.clusterId, read.batchKey)] = pending
		clusterId := read.clusterId
		if repo != nil {
			clusterId = repo.clusterId
		}
		for _, slotId := range read.slotIds {
			next.pendingObjects[fi6ObjectKey(clusterId, evsOracleSlotKey(read.record.RepoId, slotId))] = pending
		}
		for _, segmentId := range read.segmentIds {
			next.pendingObjects[fi6ObjectKey(segmentClusterId, evsOracleSegmentKey(read.record.RepoId, segmentId))] = pending
		}
	}
	memory.stateLock.Lock()
	memory.fi6 = next
	memory.stateLock.Unlock()
	return errs
}

// A push pending at the last check whose record left with its batch, resolved by §11.8's Resolve row on what the last
// check kept of its statement: committed if the ref's history names it where it could commit, dead by the row's dead
// rule, else still pending.
func fi6ResolveGone(repo *evsStoreRepo, pending *fi6PendingPush) fi6Outcome {
	if repo == nil {
		return fi6Pending
	}
	for _, ref := range repo.refs {
		if ref.refId != pending.refId {
			continue
		}
		last := pending.baseVersion + fi6ResolveRange
		if pending.gitMode {
			last = pending.baseVersion + 1
		}
		for at := pending.baseVersion + 1; at <= last; at += 1 {
			if committed := ref.at(at); committed != nil && committed.entry.PushId == pending.pushId {
				return fi6CommittedHere
			}
		}
		head := ref.head.Head
		if last <= head.GetVersion() || pending.timeMs+fi6StatementLife.Milliseconds() < head.GetFenceMs() {
			return fi6Dead
		}
	}
	return fi6Pending
}
