// FI-27, drop history (§22.8; §11.7's action, rule, boundary and fence rows, §11.13's who, start, resolve, mark,
// verify, delete, young and holds rows; I-EVS-15, D-TEST-10, D-TEST-18; DESIGN-DETAILS 10.3's ClosureHolds and
// OnlyCandidates; TEST-M10-01), on fi16.go's reading of the store and the blob history.
//
// The oracle never reads a drop job's own state: not its list files, its cand, mark or del files, its verify, nor
// the drop table's phases. It finds each drop as readers find it, a committed DROP push (flag 256) in its ref's
// history with its EvsDropHistory, and works out what the drop lists itself (DESIGN-DETAILS 10.3's L1 and L2):
//
//	cover    per lineage, the versions of its ref committed before the DROP whose change at the lineage's token path
//	         in that entry's epoch writes an entry, below through_version, each by its entry hash; each older lineage
//	         entry a source of the next in that epoch's committed map or PATH_EPOCH tail
//	exact    the cover's count and SHA-256 over its ascending entry hashes are the lineage's count and listed_sha256,
//	         every lineage's link holding, else the drop is resolve's {mismatch} and executes nothing
//	cancel   a committed DROP of action 2 on the ref naming the drop and its version cancels it
//
// It then holds each DELETE fi16.go classes a drop's (one that may have removed an object some committed version
// names through a kind-1 locator, a slot of a kept path, or a git-mode push's new-objects list), at the check after
// its step, to the invariant's four conditions:
//
//	(1)(2)  every version naming the object, on any ref, is listed by a committed drop of the repo that is exact, not
//	        cancelled, and past its not_before_ms + §11.7's 25 min when the DELETE issued, and some listed version
//	        names it through a kind-1 locator or a slot (an object only kind-5 locators name is the purge's, never a
//	        drop's candidate); a git-mode push's history segment, which no drop lists, is never one
//	(3)     no hold covering the repo that stood when the DELETE issued (fi16.go's holdsAt) was placed while the
//	        object existed
//	(4)     evacuation's horizon on the repo's metadata cluster when the DELETE issued, the oldest pb/ batch the history
//	        leaves standing or the clock less 25 h, whichever is earlier (DESIGN-DETAILS 2.2.4), had passed the
//	        object's LastModified + 24 h 2 min, and the DELETE named that LastModified (sidecar.WithBlobUnmodified),
//	        whole seconds allowed
//
// and that it did not issue while §19.11's drop mode read observe throughout its step; a cancelled, refused or
// observed drop deletes nothing. At every check besides: no version first found after a drop's DROP commits naming a
// version it lists through its reuse list unless its push was validated against a head of the source ref below the
// DROP, the fence being the head step 4 read (QD-1146), which the oracle reads two ways:
//
//	window   its push reached evs before the DROP's head write and its own head write came within §11.8's 5 s of
//	         the DROP's answer, so it was validated before the fence and reran nothing at step 7 (QD-1105;
//	         reuseInsideTheWindow)
//	cached   its push read the source ref's head from the head cache, which the Net records beside the blob history:
//	         a get of that ref's entry after the push arrived answered a head below the DROP, written less than
//	         §11.9's 10 min before that read, and its own head write came within the 5 s of it (QD-701's cached reuse
//	         read, FS-91 (c); reuseOnACachedHead)
//
// so a push validated on a head showing the DROP, the cluster's or the cache's, that commits anyway is still a
// violation; and an object a drop's DELETE removed, once a check found it gone, never comes back, except where
// §19.10's close report names the drop as re-seeded from a stale mirror (CloseReport.Drops), which FI-5's dropped
// clause reads too.
//
// Readings and gaps, in TEST-M10-01's report: the horizon is the one at the DELETE, not the one the job's round read,
// which can only be later, so a job that read its horizon too early is not caught by it; a base or rename source
// naming a listed version after the fence is path-level CAS's, which FI-15 holds, and only the reuse list is read
// here; "a written boundary carries its base's oid and mode", "readers show a listed version as pending or dropped"
// and the lock voiding a drop at its start are not checked; equal delete sets across a crash, retry or stale instance
// are a schedule's twin comparison, and every DELETE outside the set is caught here.

package fault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var _ = RegisterInvariant(27, func(ctx context.Context, oracle *Oracle) error {
	return checkFi27(ctx, oracle)
})

// The tunables FI-27 checks with: §11.7's, §11.13's and §19.6's values.
type Fi27Settings struct {
	// How long after a drop's not_before_ms its job may delete: §11.7's 25 min (owner decision 183).
	StartDelay time.Duration
	// How far evacuation's horizon must pass an object's LastModified before a drop deletes it: owner decision 397's
	// 24 h 2 min.
	AdoptionBound time.Duration
	// How old a batch's minute may grow before evacuation takes it, which caps the horizon at the clock less it:
	// §11.13's 25 h.
	EvacuationMinuteAge time.Duration
	// How far before an object's LastModified the time a DELETE names may fall and still name it: §19.6's 1 s, a
	// HEAD's whole seconds.
	UnmodifiedSlack time.Duration
	// How old a deleter's read of hold/ may be: §11.13's 5 s.
	HoldReadAge time.Duration
	// How long after a push's validation its step 7 commits it with no rerun of 5h: §11.8's 5 s. A reuse copy
	// validated before a DROP committed may commit that long after it (QD-1105), and one validated on a cached head
	// below the DROP that long after its read of it (QD-1146).
	StepSevenWindow time.Duration
	// How long after its write a head cache entry serves: §11.9's 10 min (owner decision 397), from the earliest of
	// its head's write and the entry's put (DESIGN-DETAILS 10.2.7's cache stamp). A reuse copy validated on a cached
	// head below its DROP is let through only on an entry younger than this when the push read it (QD-1146).
	HeadCacheServeAge time.Duration
}

func DefaultFi27Settings() *Fi27Settings {
	return &Fi27Settings{
		StartDelay:          25 * time.Minute,
		AdoptionBound:       24*time.Hour + 2*time.Minute,
		EvacuationMinuteAge: 25 * time.Hour,
		UnmodifiedSlack:     sidecar.BlobUnmodifiedSlack,
		HoldReadAge:         5 * time.Second,
		StepSevenWindow:     5 * time.Second,
		HeadCacheServeAge:   10 * time.Minute,
	}
}

// Names the settings FI-27 checks net's schedules with; until one is named it takes the defaults.
func SetFi27Settings(net *Net, settings *Fi27Settings) {
	memory := evsFormat2MemoryOf(net)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	settingsCopy := *settings
	memory.fi27Settings = &settingsCopy
}

// One committed drop as the oracle reads it from its ref's history.
type fi27Drop struct {
	refId   sidecar.Id
	version uint64
	dropId  []byte
	history *protocol.EvsDropHistory
	// a committed cancel names it
	cancelled bool
	// why its lists are not its lineages' versions, empty when they are
	inexact string
	// the versions of its ref it lists, "<version> <entry hash hex>"
	listed map[string]bool
}

func (self *fi27Drop) String() string {
	return fmt.Sprintf("drop %x at version %d of ref %s", self.dropId, self.version, self.refId)
}

func (self *fi27Drop) lists(namer *evsNamer) bool {
	return namer.refId == self.refId && self.listed[fmt.Sprintf("%d %x", namer.version, namer.entrySha256)]
}

// Whether the drop may delete at at: exact, not cancelled, past its window and the job's start delay.
func (self *fi27Drop) executableAt(at time.Time, settings *Fi27Settings) (bool, string) {
	switch {
	case self.inexact != "":
		return false, fmt.Sprintf("%s is refused {mismatch}: %s", self, self.inexact)
	case self.cancelled:
		return false, fmt.Sprintf("%s is cancelled", self)
	}
	start := time.UnixMilli(self.history.GetNotBeforeMs()).Add(settings.StartDelay)
	if at.Before(start) {
		return false, fmt.Sprintf("%s deletes nothing before %s, its not_before_ms + %s", self, start.UTC().Format(time.RFC3339), settings.StartDelay)
	}
	return true, ""
}

// The repo's committed drops, their covers and cancels, read at first use at this check.
func (self *evsFormat2Check) dropsOf(repo *evsFormat2Repo) ([]*fi27Drop, []error) {
	if repo.dropsRead {
		return repo.drops, repo.dropErrs
	}
	repo.dropsRead = true
	cancels := map[string]bool{}
	for _, ref := range repo.store.refs {
		for _, version := range ref.versions {
			if version == nil || version.statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 {
				continue
			}
			if version.payload.Drop == nil || version.payload.Drop.History == nil {
				repo.dropErrs = append(repo.dropErrs, fmt.Errorf("repo %s ref %s: the DROP at %d carries no drop body", repo.store.repoId, ref.refId, version.version))
				continue
			}
			history := version.payload.Drop.History
			if version.payload.Drop.Cancel() {
				cancels[fmt.Sprintf("%s/%d/%x", ref.refId, history.GetCancelsVersion(), history.GetCancelsDropId())] = true
				continue
			}
			repo.drops = append(repo.drops, &fi27Drop{refId: ref.refId, version: version.version, dropId: history.GetDropId(), history: history, listed: map[string]bool{}})
		}
	}
	for _, drop := range repo.drops {
		drop.cancelled = cancels[fmt.Sprintf("%s/%d/%x", drop.refId, drop.version, drop.dropId)]
		self.coverOf(repo, drop)
	}
	return repo.drops, repo.dropErrs
}

// The drop's cover and whether its lists are exactly it (see the file header).
func (self *evsFormat2Check) coverOf(repo *evsFormat2Repo, drop *fi27Drop) {
	ref := repo.ref(drop.refId)
	if ref == nil {
		drop.inexact = "its ref is not in the walk"
		return
	}
	for p, path := range drop.history.GetPaths() {
		lineage := path.GetLineage()
		if len(lineage) == 0 {
			drop.inexact = fmt.Sprintf("lineage %d is empty", p)
			return
		}
		for i := 1; i < len(lineage); i += 1 {
			if err := self.linked(repo, ref, lineage[i-1], lineage[i]); err != nil {
				drop.inexact = fmt.Sprintf("lineage %d's entry %d: %v", p, i, err)
				return
			}
		}
		tokenPaths := []sidecar.EvsTokenPath{}
		for _, entry := range lineage {
			tokenPath, err := sidecar.ParseEvsTokenPath(entry.GetTokenPath())
			if err != nil {
				drop.inexact = fmt.Sprintf("lineage %d holds a token path that does not parse", p)
				return
			}
			tokenPaths = append(tokenPaths, tokenPath)
		}
		values := [][]byte{}
		for at := uint64(1); at < drop.version; at += 1 {
			version := ref.at(at)
			if version == nil {
				drop.inexact = fmt.Sprintf("version %d of its ref was not read", at)
				return
			}
			epoch := version.statement.Push.GetPathEpoch()
			for i, change := range version.payload.Changes {
				if !change.WritesEntry() {
					// a removal has no entry hash, so it is never listed
					continue
				}
				for e, entry := range lineage {
					if entry.GetEpoch() != epoch || !change.TokenPath.Equal(tokenPaths[e]) {
						continue
					}
					if entryVersion := version.entryVersions[i]; entryVersion == nil || path.GetThroughVersion() <= entryVersion.GetVersion() {
						continue
					}
					entrySha256 := change.Change.GetEntrySha256()
					values = append(values, entrySha256)
					drop.listed[fmt.Sprintf("%d %x", at, entrySha256)] = true
				}
			}
		}
		slices.SortFunc(values, bytes.Compare)
		digest := sha256.New()
		for _, value := range values {
			digest.Write(value)
		}
		if uint64(len(values)) != uint64(path.GetCount()) || !bytes.Equal(digest.Sum(nil), path.GetListedSha256()) {
			drop.inexact = fmt.Sprintf("lineage %d lists %d versions with listed_sha256 %x, and its versions below %d are %d with %x", p, path.GetCount(), path.GetListedSha256(), path.GetThroughVersion(), len(values), digest.Sum(nil))
			return
		}
	}
}

// Whether older is a source of newer in newer's epoch's committed map or PATH_EPOCH tail on ref.
func (self *evsFormat2Check) linked(repo *evsFormat2Repo, ref *evsStoreRef, newer *protocol.EvsSourcePath, older *protocol.EvsSourcePath) error {
	newerPath, err := sidecar.ParseEvsTokenPath(newer.GetTokenPath())
	if err != nil {
		return err
	}
	olderPath, err := sidecar.ParseEvsTokenPath(older.GetTokenPath())
	if err != nil {
		return err
	}
	for _, version := range ref.versions {
		if version == nil {
			continue
		}
		push := version.statement.Push
		if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) == 0 || push.GetPathEpoch() != newer.GetEpoch() {
			continue
		}
		moved, err := self.moveOf(repo, ref, version, older.GetEpoch(), olderPath)
		if err != nil {
			return err
		}
		if moved.Equal(newerPath) {
			return nil
		}
		return fmt.Errorf("epoch %d's cut-over moves %s of epoch %d to %s, not %s", newer.GetEpoch(), olderPath.KeyString(), older.GetEpoch(), moved.KeyString(), newerPath.KeyString())
	}
	return fmt.Errorf("no committed cut-over into epoch %d", newer.GetEpoch())
}

// Whether every namer of an object is listed by an exact, uncancelled drop of the repo, whose going FI-27 judges and
// whose absence FI-1 excuses.
func (self *evsFormat2Check) dropListed(repoId sidecar.Id, name string) bool {
	repo := self.repoById[repoId]
	if repo == nil {
		return false
	}
	namers := repo.namers[name]
	if len(namers) == 0 {
		return false
	}
	drops, _ := self.dropsOf(repo)
	for _, namer := range namers {
		listed := false
		for _, drop := range drops {
			listed = listed || (drop.inexact == "" && !drop.cancelled && drop.lists(namer))
		}
		if !listed {
			return false
		}
	}
	return true
}

// Evacuation's horizon on clusterId when the request at index issued: the oldest batch the history leaves standing
// or possibly standing there, or the clock less EvacuationMinuteAge, whichever is earlier.
func (self *evsFormat2Check) horizonAt(clusterId string, index int, settings *Fi27Settings) time.Time {
	issued := self.history[index]
	horizon := issued.Invoked.Add(-settings.EvacuationMinuteAge)
	standing := map[string]bool{}
	for _, entry := range self.history[:index] {
		if entry.ClusterId != clusterId || !strings.HasPrefix(entry.Key, "pb/") {
			continue
		}
		answered := entry.ReturnSeq != 0 && entry.ReturnSeq < issued.InvokeSeq
		switch entry.Op {
		case sidecartest.BlobHistoryPutIfNoneMatch, sidecartest.BlobHistoryPutIfMatch, sidecartest.BlobHistoryPutStream:
			if entry.Outcome == sidecartest.BlobOutcomeOk || entry.Outcome == sidecartest.BlobOutcomeUnknown || entry.Outcome == "" {
				standing[entry.Key] = true
			}
		case sidecartest.BlobHistoryDelete:
			if entry.Outcome == sidecartest.BlobOutcomeOk && answered {
				delete(standing, entry.Key)
			}
		}
	}
	for key := range standing {
		if minute, ok := evsOracleBatchKeyMinute(key); ok && minute.Before(horizon) {
			horizon = minute
		}
	}
	return horizon
}

// The object's LastModified when the request at index issued: the store's own time for the newest write of the key
// the history acknowledged before it, else the one a check last listed.
func (self *evsFormat2Check) lastModifiedAt(name string, index int) (time.Time, bool) {
	clusterId, key, _ := strings.Cut(name, " ")
	issued := self.history[index]
	var written time.Time
	for _, entry := range self.history[:index] {
		if entry.ClusterId != clusterId || entry.Key != key {
			continue
		}
		switch entry.Op {
		case sidecartest.BlobHistoryPutIfNoneMatch, sidecartest.BlobHistoryPutIfMatch, sidecartest.BlobHistoryPutStream:
			if entry.Outcome == sidecartest.BlobOutcomeOk && entry.ReturnSeq != 0 && entry.ReturnSeq < issued.InvokeSeq {
				written = entry.Returned
			}
		}
	}
	self.memory.stateLock.Lock()
	listed, ok := self.memory.lastModifieds[name]
	self.memory.stateLock.Unlock()
	// the newer of the two: a write the history acknowledged after the last listing made another object of the key
	if !written.IsZero() && (!ok || written.After(listed)) {
		return written, true
	}
	return listed, ok
}

func checkFi27(ctx context.Context, oracle *Oracle) error {
	check := evsFormat2Of(ctx, oracle)
	check.memory.stateLock.Lock()
	settings := *check.memory.fi27Settings
	check.memory.stateLock.Unlock()
	errs := slices.Clone(check.errs)
	for _, repo := range check.repos {
		if _, dropErrs := check.dropsOf(repo); 0 < len(dropErrs) {
			errs = append(errs, dropErrs...)
		}
	}
	for _, index := range check.dropDeletes {
		errs = append(errs, check.judgeDrop(index, &settings)...)
	}
	errs = append(errs, check.droppedStayGone("FI-27", nil, fi5ReseededDrops(oracle.Net))...)
	errs = append(errs, check.fencesHold(&settings)...)
	return errors.Join(errs...)
}

// FI-27's four conditions for one drop's DELETE: see the file header.
func (self *evsFormat2Check) judgeDrop(index int, settings *Fi27Settings) []error {
	entry := self.history[index]
	repo := self.deleteRepos[index]
	namers := self.deleteNamers[index]
	what := evsDeleteText(entry)
	if !repo.store.complete() {
		return []error{fmt.Errorf("%s: repo %s's history was not read whole, so its drop cannot be judged", what, repo.store.repoId)}
	}
	drops, _ := self.dropsOf(repo)
	errs := []error{}
	candidate := false
	for _, namer := range namers {
		if namer.kind == evsNameSegment || (namer.kind == evsNameSlot && !namer.versionless()) {
			candidate = true
		}
		if namer.kind == evsNameGitObject {
			errs = append(errs, fmt.Errorf("%s: %s names it, a history segment no drop lists: a drop deletes nothing but ids a listed version's chain names", what, namer))
			continue
		}
		whyNots := []string{}
		executable := false
		for _, drop := range drops {
			if !drop.lists(namer) {
				continue
			}
			ok, whyNot := drop.executableAt(entry.Invoked, settings)
			executable = executable || ok
			if !ok {
				whyNots = append(whyNots, whyNot)
			}
		}
		switch {
		case executable:
		case len(whyNots) == 0:
			errs = append(errs, fmt.Errorf("%s: %s names it, and no committed drop of the repo lists that version: a drop deletes only what listed versions alone name", what, namer))
		default:
			errs = append(errs, fmt.Errorf("%s: %s names it, and every drop listing it deletes nothing now: %s", what, namer, strings.Join(whyNots, "; ")))
		}
	}
	if !candidate {
		errs = append(errs, fmt.Errorf("%s: only kind-5 locators name it, which are the purge's and never a drop's candidate", what))
	}
	name := entry.ClusterId + " " + entry.Key
	lastModified, known := self.lastModifiedAt(name, index)
	created := self.createdAt(name, namers)
	records, unknown := self.holdsAt(repo, index, settings.HoldReadAge)
	if unknown {
		errs = append(errs, fmt.Errorf("%s: a hold whose terms no reader can read stood for the repo's network, which keeps everything", what))
	}
	for _, record := range records {
		if !created.After(record.PlaceTime) {
			errs = append(errs, fmt.Errorf("%s: hold %s, placed at %s, stood when the DELETE issued, and the object existed at its placement", what, record.CaseId, record.PlaceTime.UTC().Format(time.RFC3339)))
		}
	}
	switch {
	case !known:
		errs = append(errs, fmt.Errorf("%s: no check listed it and no write of it was answered, so its LastModified, which the DELETE must name, is unknown", what))
	default:
		// the batches are on the repo's metadata cluster, whichever cluster holds the object
		horizon := self.horizonAt(repo.store.clusterId, index, settings)
		if horizon.Before(lastModified.Add(settings.AdoptionBound)) {
			errs = append(errs, fmt.Errorf("%s: evacuation's horizon %s had not passed its LastModified %s + %s", what, horizon.UTC().Format(time.RFC3339), lastModified.UTC().Format(time.RFC3339Nano), settings.AdoptionBound))
		}
		switch {
		case entry.Unmodified.IsZero():
			errs = append(errs, fmt.Errorf("%s: names no LastModified, so it would take a newer object of the key", what))
		case lastModified.Before(entry.Unmodified) || !lastModified.Add(-settings.UnmodifiedSlack).Before(entry.Unmodified):
			errs = append(errs, fmt.Errorf("%s: names %s, not its LastModified %s", what, entry.Unmodified.UTC().Format(time.RFC3339Nano), lastModified.UTC().Format(time.RFC3339Nano)))
		}
	}
	if evsObservedThroughout(self.previousModesSet, self.previousDropMode, self.dropMode) {
		errs = append(errs, fmt.Errorf("%s: issued while §19.11's drop mode read observe, under which a job deletes nothing", what))
	}
	return errs
}

// An object a drop's DELETE removed, once a check found it gone, is never stored again, but where a close report
// names one of the repo's drops as re-seeded from a stale mirror (§19.10), reseeded by repo. FI-5 and FI-27 both read
// it: repoId nil for every repo.
func (self *evsFormat2Check) droppedStayGone(invariant string, repoId *sidecar.Id, reseeded map[sidecar.Id]bool) []error {
	self.memory.stateLock.Lock()
	names := []string{}
	for name, deletion := range self.memory.dropped {
		if deletion.gone && (repoId == nil || deletion.repoId == *repoId) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	deletions := map[string]*evsDeletion{}
	for _, name := range names {
		deletions[name] = self.memory.dropped[name]
	}
	self.memory.stateLock.Unlock()
	errs := []error{}
	for _, name := range names {
		deletion := deletions[name]
		if !self.objectListed(deletion.repoId, name) {
			continue
		}
		if reseeded[deletion.repoId] {
			// a stale mirror's return at a site-loss re-seed, until the re-seeded drop's job runs again
			continue
		}
		if repo := self.repoById[deletion.repoId]; repo != nil && fi27NamedAnew(repo.namers[name], deletion) {
			// a later push's upload of the same bytes is a new object, which a version the drop did not list names
			// (DESIGN-DETAILS 10.3): the dropped versions' content does not come back through it
			continue
		}
		_, key, _ := strings.Cut(name, " ")
		errs = append(errs, fmt.Errorf("%s: %s, which %s removed, is stored again: deleted content never returns but from a stale mirror at a re-seed the close report names", invariant, key, evsDeleteText(deletion.entry)))
	}
	return errs
}

// Whether a namer the deletion did not know, a version committed since, names the object again.
func fi27NamedAnew(namers []*evsNamer, deletion *evsDeletion) bool {
	for _, namer := range namers {
		if !deletion.namerKeys[namer.key()] {
			return true
		}
	}
	return false
}

// No version a check first finds after a drop's DROP was first found commits naming a version the drop lists in its
// reuse list (§11.7's fence), but one validated against a head of the source ref below the DROP: one §11.8's window
// lets commit (reuseInsideTheWindow), or one validated on a cached head below it (reuseOnACachedHead).
func (self *evsFormat2Check) fencesHold(settings *Fi27Settings) []error {
	errs := []error{}
	// the Net's record of the head cache, read once, and only for a copy the window does not let through
	var cacheHistory []*sidecartest.HeadCacheHistoryEntry
	cacheHistoryRead := false
	cached := func() []*sidecartest.HeadCacheHistoryEntry {
		if !cacheHistoryRead {
			cacheHistory = self.oracle.Net.HeadCacheHistory()
			cacheHistoryRead = true
		}
		return cacheHistory
	}
	for _, repo := range self.repos {
		drops, _ := self.dropsOf(repo)
		if len(drops) == 0 {
			continue
		}
		self.memory.stateLock.Lock()
		seen := func(refId sidecar.Id, version uint64) int {
			return self.memory.versionsSeen[fmt.Sprintf("%s/%s/%d", repo.store.repoId, refId, version)]
		}
		type sighting struct {
			ref     *evsStoreRef
			version *evsStoreVersion
			at      int
		}
		sightings := []*sighting{}
		for _, ref := range repo.store.refs {
			for _, version := range ref.versions {
				if version != nil && 0 < len(version.payload.ReuseList) {
					sightings = append(sightings, &sighting{ref: ref, version: version, at: seen(ref.refId, version.version)})
				}
			}
		}
		dropSeen := map[*fi27Drop]int{}
		for _, drop := range drops {
			dropSeen[drop] = seen(drop.refId, drop.version)
		}
		self.memory.stateLock.Unlock()
		for _, found := range sightings {
			for _, reuse := range found.version.payload.ReuseList {
				for _, drop := range drops {
					if reuse.RefId != drop.refId || found.at <= dropSeen[drop] {
						continue
					}
					listedVersion := drop.listsPathVersion(repo, reuse)
					if listedVersion == 0 || self.reuseInsideTheWindow(repo, found.ref.refId, found.version, drop, settings) {
						continue
					}
					if self.reuseOnACachedHead(repo, found.ref.refId, found.version, drop, cached(), settings) {
						continue
					}
					errs = append(errs, fmt.Errorf("repo %s: version %d of ref %s, first found after %s, reuses version %d of %s, which the drop lists, and no head of its ref below the DROP validated it, read from the cluster before the DROP's head write or from the cache: no version commits naming a listed version as a reuse source after its fence", repo.store.repoId, found.version.version, found.ref.refId, drop, listedVersion, reuse.TokenPath.KeyString()))
				}
			}
		}
	}
	return errs
}

// Whether version of refId, a reuse of a version drop lists that a check first found after the DROP, is one §11.8's
// window lets commit (QD-1105). Its push reached evs before the DROP's head write was issued, as the store arrival of
// the ledger's attempt that committed it says, so it may have been validated before the fence; and its own head write
// was issued within the window of the DROP's being answered, so its step 7 reran nothing. mark, waiting evacuation's
// horizon past the DROP, finds such a copy and keeps what it shares (§11.13), which conditions (1) and (2) hold every
// DELETE of the drop to. A push the ledger does not hold, an attempt of no known store arrival and a head write whose
// ETag no check read are not let through.
func (self *evsFormat2Check) reuseInsideTheWindow(repo *evsFormat2Repo, refId sidecar.Id, version *evsStoreVersion, drop *fi27Drop, settings *Fi27Settings) bool {
	dropIndex, dropWrite := self.headWrite(repo, drop.refId, drop.version)
	_, copyWrite := self.headWrite(repo, refId, version.version)
	if dropWrite == nil || copyWrite == nil {
		return false
	}
	if copyWrite.Invoked.After(dropWrite.Returned.Add(settings.StepSevenWindow)) {
		return false
	}
	for _, attempt := range self.committedAttempts(version) {
		if attempt.StoreArrival <= dropIndex {
			return true
		}
	}
	return false
}

// The ledger's attempts of version's push, the push id its statement names, that answered it committed at its
// version, each of a known store arrival.
func (self *evsFormat2Check) committedAttempts(version *evsStoreVersion) []*Operation {
	pushId, err := sidecar.IdFromBytes(version.statement.Push.GetPushId())
	if err != nil {
		return nil
	}
	attempts := []*Operation{}
	for _, push := range LedgerOf(self.oracle.Net).Pushes() {
		if push.PushId != pushId {
			continue
		}
		for _, attempt := range push.Attempts {
			if attempt.Outcome == OutcomeCommitted && attempt.Version == version.version && 0 < attempt.StoreArrival {
				attempts = append(attempts, attempt)
			}
		}
	}
	return attempts
}

// Whether version of refId, a reuse of a version drop lists that a check first found after the DROP, is one whose
// push was validated against a head of the source ref below the DROP that the head cache served (QD-1146; §11.7's
// fence row, §11.9's cache row, QD-701): §11.8's step 4 may take a reuse source's head from the cache, which serves
// it for 10 min after that head's own write, so a copy validated after the DROP committed against a cached head from
// before it commits, as FS-91 (c) has it, and the job's mark, waiting DESIGN-DETAILS 10.2.7's cite bound past the
// DROP, finds it and keeps what it names. For some attempt the ledger holds that answered it committed, cacheHistory,
// the Net's record of the cache, holds a read that lets it through (fi27CachedRead). A push validated on a head
// showing the DROP, from the cluster or from the cache, made no such read, so one that commits anyway is still a
// violation, and so is one validated on an entry past the cache's age. A push the ledger does not hold and a head
// write whose ETag no check read are not let through.
func (self *evsFormat2Check) reuseOnACachedHead(repo *evsFormat2Repo, refId sidecar.Id, version *evsStoreVersion, drop *fi27Drop, cacheHistory []*sidecartest.HeadCacheHistoryEntry, settings *Fi27Settings) bool {
	copyIndex, copyWrite := self.headWrite(repo, refId, version.version)
	if copyWrite == nil {
		return false
	}
	for _, attempt := range self.committedAttempts(version) {
		terms := &fi27CachedReadTerms{
			instance:     attempt.Instance,
			cacheArrival: attempt.CacheArrival,
			cacheKey:     fi27HeadCacheKey(repo.store.repoId),
			cacheField:   sidecar.EvsKeyId(drop.refId),
			clusterId:    repo.store.clusterId,
			headKey:      evsOracleRepoPrefix("head/", repo.store.repoId) + sidecar.EvsKeyId(drop.refId),
			dropVersion:  drop.version,
			copyIndex:    copyIndex,
			copyWrite:    copyWrite,
		}
		if fi27CachedRead(cacheHistory, self.history, terms, settings) != nil {
			return true
		}
	}
	return false
}

// A repo's head cache key as §11.9's cache row names it, {evsh_<repo_id>}, the id as evs's keys spell it.
func fi27HeadCacheKey(repoId sidecar.Id) string {
	return "{evsh_" + sidecar.EvsKeyId(repoId) + "}"
}

// What a copy's cached read is looked for by (fi27CachedRead).
type fi27CachedReadTerms struct {
	// the instance of the attempt that committed the copy, and how many head cache requests the Net's record held
	// when that attempt arrived
	instance     string
	cacheArrival int
	// the source ref's entry: the repo's {evsh_} key and the ref's field
	cacheKey   string
	cacheField string
	// the source ref's head on the repo's metadata cluster
	clusterId string
	headKey   string
	// the DROP's version of the source ref
	dropVersion uint64
	// the copy's head write and its index in the blob history
	copyIndex int
	copyWrite *sidecartest.BlobHistoryEntry
}

// The read in cacheHistory that lets a copy through by QD-1146's three conditions, nil for none, with blobHistory the
// history the cached head's own write is found in:
//
//	read     a get of the source ref's entry by the copy's instance, called once the attempt had arrived (an index at
//	         or past cacheArrival) and answered before the copy's head write was issued, that answered an entry whose
//	         head, at the entry's own version, is below the DROP's version
//	age      that entry was written less than HeadCacheServeAge before the get's answer (fi27CacheEntryWritten)
//	window   the copy's head write was issued within StepSevenWindow of the get's call, as §11.8's step 7 issues only
//	         within 5 s of step 4's reads
//
// The entry is decoded with the format's own decoders and none of evs's behaviour, as every oracle reads (fi1.go).
func fi27CachedRead(cacheHistory []*sidecartest.HeadCacheHistoryEntry, blobHistory []*sidecartest.BlobHistoryEntry, terms *fi27CachedReadTerms, settings *Fi27Settings) *sidecartest.HeadCacheHistoryEntry {
	for index := max(terms.cacheArrival, 0); index < len(cacheHistory); index += 1 {
		read := cacheHistory[index]
		if read.Op != sidecartest.HeadCacheHistoryGet || read.Outcome != sidecartest.HeadCacheOutcomeOk {
			continue
		}
		if read.Actor != terms.instance || read.Key != terms.cacheKey || read.Field != terms.cacheField {
			continue
		}
		if terms.copyIndex < read.StoreReturned {
			// answered after the copy's head write was issued
			continue
		}
		entry, ok := fi27ParseCacheEntry(read.Entry)
		if !ok || entry.version != entry.head.GetVersion() || terms.dropVersion <= entry.version {
			continue
		}
		written, ok := fi27CacheEntryWritten(cacheHistory, blobHistory, read, entry, terms)
		if !ok || !read.Returned.Before(written.Add(settings.HeadCacheServeAge)) {
			continue
		}
		if terms.copyWrite.Invoked.After(read.Invoked.Add(settings.StepSevenWindow)) {
			continue
		}
		return read
	}
	return nil
}

// A head cache entry as FI-27 reads it: its version and ETag fields and its head.
type fi27CacheEntry struct {
	version uint64
	etag    string
	head    *protocol.EvsHead
}

// The entry encoded holds, in evsservice/head_cache.go's layout: version, push sequence and cached_ms, 8 bytes each,
// the ETag's length, 2, all big-endian, then the ETag and the head's bytes. false for bytes too short for their
// lengths or a head that does not parse. cached_ms, the cache's own stamp, is not read: the entry's age is the
// oracle's to work out (fi27CacheEntryWritten).
func fi27ParseCacheEntry(encoded []byte) (*fi27CacheEntry, bool) {
	// the fixed part's byte count: the three 8-byte fields and the ETag's length
	fixedByteCount := 8 + 8 + 8 + 2
	if len(encoded) < fixedByteCount {
		return nil, false
	}
	etagByteCount := int(binary.BigEndian.Uint16(encoded[fixedByteCount-2 : fixedByteCount]))
	if len(encoded) < fixedByteCount+etagByteCount {
		return nil, false
	}
	head := &protocol.EvsHead{}
	if err := proto.Unmarshal(encoded[fixedByteCount+etagByteCount:], head); err != nil {
		return nil, false
	}
	return &fi27CacheEntry{
		version: binary.BigEndian.Uint64(encoded[0:8]),
		etag:    string(encoded[fixedByteCount : fixedByteCount+etagByteCount]),
		head:    head,
	}, true
}

// When the entry read answered was written, DESIGN-DETAILS 10.2.7's cache stamp read from outside: the earliest of its
// head's write, the blob history's conditional PUT of the source ref's head that wrote the entry's ETag; the head's
// own written_ms; and the call of the first put the record holds of the entry's bytes, so a put that came late serves
// no longer, and a head with no written_ms never. false where the history holds no such head write, so the entry
// names no head the store was given, or the record no such put, so it came from no write the record holds.
func fi27CacheEntryWritten(cacheHistory []*sidecartest.HeadCacheHistoryEntry, blobHistory []*sidecartest.BlobHistoryEntry, read *sidecartest.HeadCacheHistoryEntry, entry *fi27CacheEntry, terms *fi27CachedReadTerms) (time.Time, bool) {
	var headWrite *sidecartest.BlobHistoryEntry
	for _, blob := range blobHistory {
		if blob.ClusterId != terms.clusterId || blob.Key != terms.headKey || blob.WriteEtag != entry.etag {
			continue
		}
		if blob.Op != sidecartest.BlobHistoryPutIfNoneMatch && blob.Op != sidecartest.BlobHistoryPutIfMatch {
			continue
		}
		// a write that may have taken effect
		if blob.Outcome == sidecartest.BlobOutcomeOk || blob.Outcome == sidecartest.BlobOutcomeUnknown || blob.Outcome == "" {
			headWrite = blob
			break
		}
	}
	if headWrite == nil {
		return time.Time{}, false
	}
	var put *sidecartest.HeadCacheHistoryEntry
	for _, request := range cacheHistory {
		if request.Op != sidecartest.HeadCacheHistoryPut || request.Outcome == sidecartest.HeadCacheOutcomeKept {
			continue
		}
		if request.Key == read.Key && request.Field == read.Field && bytes.Equal(request.Entry, read.Entry) {
			put = request
			break
		}
	}
	if put == nil {
		return time.Time{}, false
	}
	written := headWrite.Invoked
	if stamped := time.UnixMilli(entry.head.GetWrittenMs()); stamped.Before(written) {
		written = stamped
	}
	if put.Invoked.Before(written) {
		written = put.Invoked
	}
	return written, true
}

// The head write that committed version of refId and its index in the blob history: the answered conditional PUT of
// the ref's head whose ETag a check read at that version; nil when no check read it there.
func (self *evsFormat2Check) headWrite(repo *evsFormat2Repo, refId sidecar.Id, version uint64) (int, *sidecartest.BlobHistoryEntry) {
	clusterId := repo.store.clusterId
	key := evsOracleRepoPrefix("head/", repo.store.repoId) + sidecar.EvsKeyId(refId)
	self.memory.stateLock.Lock()
	defer self.memory.stateLock.Unlock()
	for index, entry := range self.history {
		if entry.ClusterId != clusterId || entry.Key != key || entry.Outcome != sidecartest.BlobOutcomeOk || entry.ReturnSeq == 0 {
			continue
		}
		if entry.Op != sidecartest.BlobHistoryPutIfNoneMatch && entry.Op != sidecartest.BlobHistoryPutIfMatch {
			continue
		}
		if headVersion, ok := self.memory.headEtagVersions[clusterId+" "+key+" "+entry.WriteEtag]; ok && headVersion == version {
			return index, entry
		}
	}
	return 0, nil
}

// The ref version a reuse source names when the drop lists it, else 0: the source's path version is an entry
// version's version, so the version of its ref that wrote that path version at that token path.
func (self *fi27Drop) listsPathVersion(repo *evsFormat2Repo, reuse *sidecar.EvsReuse) uint64 {
	ref := repo.ref(self.refId)
	if ref == nil {
		return 0
	}
	for _, version := range ref.versions {
		if version == nil || self.version <= version.version {
			continue
		}
		for i, change := range version.payload.Changes {
			entryVersion := version.entryVersions[i]
			if entryVersion == nil || entryVersion.GetVersion() != reuse.EntryVersion || !change.TokenPath.Equal(reuse.TokenPath) {
				continue
			}
			if self.listed[fmt.Sprintf("%d %x", version.version, change.Change.GetEntrySha256())] {
				return version.version
			}
		}
	}
	return 0
}

// The repos a close report names as re-seeded with a drop from a stale mirror, whose deleted objects may return
// until the re-seeded drop's job runs again (§19.10's close report).
func fi5ReseededDrops(net *Net) map[sidecar.Id]bool {
	memory := netMemoryOf(&fi5Memories, net, newFi5Memory)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	return memory.reseededDropsWithLock()
}

// fi5ReseededDrops' answer, with FI-5's lock held, as its check holds it.
func (self *fi5Memory) reseededDropsWithLock() map[sidecar.Id]bool {
	reseeded := map[sidecar.Id]bool{}
	for _, report := range self.reports {
		for _, drop := range report.Drops {
			reseeded[drop.RepoId] = true
		}
	}
	return reseeded
}
