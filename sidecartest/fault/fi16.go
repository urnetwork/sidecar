// FI-16, purge (§22.8; §11.7's kind 5, staged, cite, keys and removal rows, §11.13's purge, who, holds and staged
// rows; I-EVS-9, R-TEST-10, D-TEST-10, D-TEST-12; TEST-M10-01), and the reading of format 2's content that FI-1,
// FI-5, FI-16, FI-17 and FI-27 share at one check.
//
// The reading is FI-1's walk (fi1.go) of every committed version, joined to the Net's blob history, so every rule is
// judged from the store and the requests clients saw, never from a purger's or a job's own bookkeeping (its queue, a
// record's purge list, a drop job's marks or files):
//
//	namers   for every seg/ and slot/ object, each committed version that names it and how: a kind-1 locator, an
//	         uploaded or a staged kind-5 locator, a slot id, or a git-mode push's new-objects list (I-EVS-15's
//	         names), with its ref, path, path epoch, versioning and entry hash
//	deletes  every DELETE the blob history holds since the previous check that may have removed an object a
//	         committed version names: answered, or unanswered, its key standing as the history replays it. One whose
//	         every namer is a versionless version, kind 5 or the slot of a versionless path, is a purge's, which this
//	         file judges; any other is a drop's, which fi27.go judges
//	heads    each head ETag a check read, with its version, so a write or read of the head in the history says which
//	         version a process was answered
//	holds    each hold/ object's body a check read, by its ETag, so the history says which holds stood when a DELETE
//	         issued, and on what terms
//	times    each seg/ and slot/ object's LastModified when a check first and last listed it
//	modes    §19.11's format2 purge and drop modes, as the host's gates read at each check
//
// FI-16 then holds each purge's DELETE, at the check after its step:
//
//	replaced  every version naming the object was replaced: a later version of its ref wrote or removed its path, a
//	          removal of a directory above it or the ref's DELETE included, a cut-over's move of the path followed
//	          into the next epoch; one not replaced is its path's newest, whose content stays
//	seen      that replacing version was answered to some process before the DELETE issued: the 200 of its head
//	          write, or a read of the head at or past it (a reread, or another process's Resolve), and an unknown
//	          or refused push is no replacement a process saw
//	allowance the DELETE issued at least 60 s after that first sight, by the Net's clock, less §19.6's 50 ms by which
//	          a process's checked clock may run ahead of it
//	holds     no hold of the repo's network covering the repo, live when the DELETE issued and acknowledged at least
//	          §11.13's 5 s cache before it, was placed when the object existed: an uploaded object by its first
//	          LastModified, a staged one by the start of the minute its record's batch names; a hold whose body no
//	          check read keeps everything
//	observe   it did not issue while the purge mode read observe at both the check before its step and this one
//
// and, at every check: every path's newest committed version that is versionless keeps all its content (its
// segments and slots stored, a staged locator in its record's tail or at seg/); a purged object, once a check found
// it gone, never comes back, a stale re-seed included; and no version a later check first finds names it.
//
// Readings and gaps, in TEST-M10-01's report: "seen" maps a head ETag to its version only for heads some check read,
// so a head written and overwritten within one step counts from the later write's answer, which can only make the
// allowance stricter; a cut-over that moves no such path fails closed; the newest-content clause judges each path in
// its epoch and leaves one a later cut-over moved to FI-1; each candidate going within the sweep's period, a
// liveness clause, is not checked.

package fault

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var _ = RegisterInvariant(16, func(ctx context.Context, oracle *Oracle) error {
	return checkFi16(ctx, oracle)
})

// The tunables FI-16 checks with: §11.13's and §19.6's values.
type Fi16Settings struct {
	// The readers' allowance from the replacing version's first sight to a purge's DELETE: §11.13's 60 s.
	Allowance time.Duration
	// How far ahead of the Net's clock a deleting process's checked clock may run: §19.6's 50 ms, by which a DELETE may
	// issue early on the Net's clock and still keep the allowance on its own.
	ClockBound time.Duration
	// How old a deleter's read of hold/ may be: §11.13's 5 s cache, so a hold acknowledged less than this before a
	// DELETE issued is not one the deleter must have read.
	HoldReadAge time.Duration
}

func DefaultFi16Settings() *Fi16Settings {
	return &Fi16Settings{
		Allowance:   60 * time.Second,
		ClockBound:  50 * time.Millisecond,
		HoldReadAge: 5 * time.Second,
	}
}

// Names the settings FI-16 checks net's schedules with; until one is named it takes the defaults.
func SetFi16Settings(net *Net, settings *Fi16Settings) {
	memory := evsFormat2MemoryOf(net)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	settingsCopy := *settings
	memory.fi16Settings = &settingsCopy
}

// How a committed version names a stored object (I-EVS-15's names).
type evsNameKind int

const (
	evsNameSegment evsNameKind = iota + 1
	evsNameVersionless
	evsNameStaged
	evsNameSlot
	evsNameGitObject
)

func (self evsNameKind) String() string {
	switch self {
	case evsNameSegment:
		return "a kind-1 locator"
	case evsNameVersionless:
		return "a kind-5 locator"
	case evsNameStaged:
		return "a staged kind-5 locator"
	case evsNameSlot:
		return "a slot id"
	case evsNameGitObject:
		return "its git-mode push's new-objects list"
	}
	return "an unknown name"
}

// One committed version naming an object.
type evsNamer struct {
	refId   sidecar.Id
	version uint64
	// the change that names it, -1 for a git-mode push's new-objects list
	changeIndex int
	tokenPath   sidecar.EvsTokenPath
	pathEpoch   uint64
	kind        evsNameKind
	versioning  uint32
	entrySha256 []byte
	// the start of the minute its record's batch names
	recordMinute time.Time
}

func (self *evsNamer) key() string {
	return fmt.Sprintf("%s/%d", self.refId, self.version)
}

func (self *evsNamer) String() string {
	if self.changeIndex < 0 {
		return fmt.Sprintf("version %d of ref %s, by %s", self.version, self.refId, self.kind)
	}
	return fmt.Sprintf("version %d of ref %s at %s (epoch %d, versioning %d), by %s", self.version, self.refId, self.tokenPath.KeyString(), self.pathEpoch, self.versioning, self.kind)
}

// Whether the namer is a versionless version's: kind 5, staged or uploaded, or a versionless path's slot.
func (self *evsNamer) versionless() bool {
	switch self.kind {
	case evsNameVersionless, evsNameStaged:
		return true
	case evsNameSlot:
		return self.versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)
	}
	return false
}

// One repo's format-2 reading at one check.
type evsFormat2Repo struct {
	store     *evsStoreRepo
	networkId sidecar.Id
	// each object's namers, by "<cluster id> <key>"
	namers map[string][]*evsNamer
	// FI-27's: the repo's drops, read at first use
	drops     []*fi27Drop
	dropsRead bool
	dropErrs  []error
}

// What a deleted object was, kept from the check that classed its DELETE.
type evsDeletion struct {
	entry *sidecartest.BlobHistoryEntry
	// the namers at that check, by key
	namerKeys map[string]bool
	// a later check found it gone
	gone bool
	// its repo
	repoId sidecar.Id
}

// What the format-2 oracles keep from one check to the next on one Net. Safe for concurrent use.
type evsFormat2Memory struct {
	stateLock    sync.Mutex
	fi16Settings *Fi16Settings
	fi27Settings *Fi27Settings
	// the newest check's reading, which every invariant at one check shares
	check      *evsFormat2Check
	checkCount int
	// each repo's reading, kept while its walk is the same
	repos map[sidecar.Id]*evsFormat2Repo
	// "<cluster> <key> <etag>" of each head a check read, to its version
	headEtagVersions map[string]uint64
	// "<key> <etag>" of each hold/ object a check read, to its record, nil for a body no reader parses
	holdRecords map[string]*sidecar.HoldRecord
	// "<cluster> <key>" of each seg/ and slot/ object a check listed, to its LastModified when first and last listed
	createdTimes  map[string]time.Time
	lastModifieds map[string]time.Time
	// §19.11's modes at the previous check
	purgeMode sidecar.Format2Mode
	dropMode  sidecar.Format2Mode
	modesSet  bool
	// "<repo>/<ref>/<version>" of each committed version, to the check that first found it
	versionsSeen map[string]int
	// each object a purge's or a drop's DELETE may have removed, by "<cluster> <key>"
	purged  map[string]*evsDeletion
	dropped map[string]*evsDeletion
}

var evsFormat2Memories sync.Map

func evsFormat2MemoryOf(net *Net) *evsFormat2Memory {
	return netMemoryOf(&evsFormat2Memories, net, func() *evsFormat2Memory {
		return &evsFormat2Memory{
			fi16Settings:     DefaultFi16Settings(),
			fi27Settings:     DefaultFi27Settings(),
			repos:            map[sidecar.Id]*evsFormat2Repo{},
			headEtagVersions: map[string]uint64{},
			holdRecords:      map[string]*sidecar.HoldRecord{},
			createdTimes:     map[string]time.Time{},
			lastModifieds:    map[string]time.Time{},
			versionsSeen:     map[string]int{},
			purged:           map[string]*evsDeletion{},
			dropped:          map[string]*evsDeletion{},
		}
	})
}

// One check's reading of format 2's content.
type evsFormat2Check struct {
	ctx    context.Context
	oracle *Oracle
	memory *evsFormat2Memory
	// this check's number, from 1
	count            int
	repos            []*evsFormat2Repo
	repoById         map[sidecar.Id]*evsFormat2Repo
	segmentClusterId string
	firstClusterId   string
	history          []*sidecartest.BlobHistoryEntry
	// the first history index since the previous check
	since int
	// indexes of the DELETEs since the previous check a purge or a drop made, and the namers of each
	purgeDeletes []int
	dropDeletes  []int
	deleteNamers map[int][]*evsNamer
	deleteRepos  map[int]*evsFormat2Repo
	// §19.11's modes now and at the previous check
	purgeMode         sidecar.Format2Mode
	dropMode          sidecar.Format2Mode
	previousPurgeMode sidecar.Format2Mode
	previousDropMode  sidecar.Format2Mode
	previousModesSet  bool
	// what the reading could not read
	errs []error
}

// The reading at oracle's check, made by the first invariant that asks.
func evsFormat2Of(ctx context.Context, oracle *Oracle) *evsFormat2Check {
	memory := evsFormat2MemoryOf(oracle.Net)
	memory.stateLock.Lock()
	if check := memory.check; check != nil && check.oracle == oracle {
		memory.stateLock.Unlock()
		return check
	}
	memory.checkCount += 1
	count := memory.checkCount
	memory.stateLock.Unlock()
	check := newEvsFormat2Check(ctx, oracle, memory, count)
	memory.stateLock.Lock()
	memory.check = check
	memory.stateLock.Unlock()
	return check
}

func newEvsFormat2Check(ctx context.Context, oracle *Oracle, memory *evsFormat2Memory, count int) *evsFormat2Check {
	check := &evsFormat2Check{
		ctx: ctx, oracle: oracle, memory: memory, count: count, repoById: map[sidecar.Id]*evsFormat2Repo{},
		deleteNamers: map[int][]*evsNamer{}, deleteRepos: map[int]*evsFormat2Repo{},
	}
	// the walk's own failures are FI-1's to name; a repo it could not read whole fails closed here where judged
	storeRepos, _ := evsStoreWalkOf(ctx, oracle)
	segmentCluster, err := oracle.Net.Host().Blobs.SegmentCluster()
	if err != nil {
		check.errs = append(check.errs, err)
	} else {
		check.segmentClusterId = segmentCluster.ClusterId()
	}
	if check.firstClusterId, err = oracle.View.FirstClusterId(); err != nil {
		check.errs = append(check.errs, err)
	}
	check.history = oracle.BlobHistory()
	check.since = min(oracle.previousHistoryCount, len(check.history))
	gate := oracle.Host().GatesOrClosed().Format2()
	check.purgeMode, check.dropMode = gate.Purge(), gate.Drop()

	memory.stateLock.Lock()
	check.previousPurgeMode, check.previousDropMode, check.previousModesSet = memory.purgeMode, memory.dropMode, memory.modesSet
	memory.purgeMode, memory.dropMode, memory.modesSet = check.purgeMode, check.dropMode, true
	for _, storeRepo := range storeRepos {
		repo := memory.repos[storeRepo.repoId]
		if repo == nil || repo.store != storeRepo {
			repo = newEvsFormat2Repo(storeRepo, check.segmentClusterId)
			memory.repos[storeRepo.repoId] = repo
		}
		check.repos = append(check.repos, repo)
		check.repoById[storeRepo.repoId] = repo
		for _, ref := range storeRepo.refs {
			memory.headEtagVersions[ref.head.ClusterId+" "+ref.head.Key+" "+ref.head.Etag] = ref.head.Head.GetVersion()
			for _, version := range ref.versions {
				if version == nil {
					continue
				}
				seenKey := fmt.Sprintf("%s/%s/%d", storeRepo.repoId, ref.refId, version.version)
				if _, ok := memory.versionsSeen[seenKey]; !ok {
					memory.versionsSeen[seenKey] = count
				}
			}
		}
		for key, info := range storeRepo.segmentInfos {
			name := check.segmentClusterId + " " + key
			if _, ok := memory.createdTimes[name]; !ok {
				memory.createdTimes[name] = info.LastModified
			}
			memory.lastModifieds[name] = info.LastModified
		}
		for key, info := range storeRepo.slotInfos {
			name := storeRepo.clusterId + " " + key
			if _, ok := memory.createdTimes[name]; !ok {
				memory.createdTimes[name] = info.LastModified
			}
			memory.lastModifieds[name] = info.LastModified
		}
	}
	memory.stateLock.Unlock()

	if check.firstClusterId != "" {
		holdObjects, err := oracle.View.Objects(ctx, check.firstClusterId, "hold/")
		if err != nil {
			check.errs = append(check.errs, fmt.Errorf("hold/: %w", err))
		}
		memory.stateLock.Lock()
		for _, object := range holdObjects {
			record, err := sidecar.ParseHoldRecord(object.Body)
			if err != nil || sidecar.HoldObjectKey(record.NetworkId, record.CaseId) != object.Key {
				// a body no reader can read as this key's hold covers its whole network with unknown terms
				record = nil
			}
			memory.holdRecords[object.Key+" "+object.Etag] = record
		}
		memory.stateLock.Unlock()
	}

	check.classifyDeletes()
	check.followDeletions()
	return check
}

// The repo's namers from its walk.
func newEvsFormat2Repo(storeRepo *evsStoreRepo, segmentClusterId string) *evsFormat2Repo {
	repo := &evsFormat2Repo{store: storeRepo, networkId: storeRepo.networkId(), namers: map[string][]*evsNamer{}}
	add := func(clusterId string, key string, namer *evsNamer) {
		name := clusterId + " " + key
		repo.namers[name] = append(repo.namers[name], namer)
	}
	for _, ref := range storeRepo.refs {
		for _, version := range ref.versions {
			if version == nil {
				continue
			}
			push := version.statement.Push
			recordMinute := time.Unix(int64(version.entry.Place.GetMinute())*60, 0).UTC()
			for i, entryVersion := range version.entryVersions {
				if entryVersion == nil {
					continue
				}
				change := version.payload.Changes[i]
				namerOf := func(kind evsNameKind) *evsNamer {
					return &evsNamer{
						refId: ref.refId, version: version.version, changeIndex: i, tokenPath: change.TokenPath,
						pathEpoch: push.GetPathEpoch(), kind: kind, versioning: entryVersion.GetVersioning(),
						entrySha256: change.Change.GetEntrySha256(), recordMinute: recordMinute,
					}
				}
				for _, locator := range entryVersion.GetChain() {
					switch protocol.EvsLocatorKind(locator.GetKind()) {
					case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
						add(segmentClusterId, evsOracleSegmentKey(storeRepo.repoId, locator.GetId()), namerOf(evsNameSegment))
					case protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
						kind := evsNameVersionless
						if locator.GetStaged() {
							kind = evsNameStaged
						}
						add(segmentClusterId, evsOracleSegmentKey(storeRepo.repoId, locator.GetId()), namerOf(kind))
					}
				}
				for _, slotId := range entryVersion.GetSlotIds() {
					add(storeRepo.clusterId, evsOracleSlotKey(storeRepo.repoId, slotId), namerOf(evsNameSlot))
				}
			}
			if protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT {
				// a git-mode push's history segments are named by its new-objects list alone (DESIGN-DETAILS 8.3's G11)
				for _, newObject := range version.payload.NewObjects {
					if newObject.Kind != protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT {
						continue
					}
					add(segmentClusterId, evsOracleSegmentKey(storeRepo.repoId, newObject.Id), &evsNamer{
						refId: ref.refId, version: version.version, changeIndex: -1, pathEpoch: push.GetPathEpoch(),
						kind: evsNameGitObject, recordMinute: recordMinute,
					})
				}
			}
		}
	}
	return repo
}

// Whether the history leaves the key standing, or possibly standing, when the request at index was invoked.
func (self *evsFormat2Check) mayExistAt(clusterId string, key string, index int) bool {
	invokeSeq := self.history[index].InvokeSeq
	present, maybe := false, false
	for _, entry := range self.history[:index] {
		if entry.ClusterId != clusterId || entry.Key != key {
			continue
		}
		answered := entry.ReturnSeq != 0 && entry.ReturnSeq < invokeSeq
		switch entry.Op {
		case sidecartest.BlobHistoryPutIfNoneMatch, sidecartest.BlobHistoryPutIfMatch, sidecartest.BlobHistoryPutStream:
			switch {
			case entry.Outcome == sidecartest.BlobOutcomeOk && answered:
				present, maybe = true, false
			case entry.Outcome == sidecartest.BlobOutcomeOk, entry.Outcome == sidecartest.BlobOutcomeUnknown, entry.Outcome == "":
				maybe = maybe || !present
			}
		case sidecartest.BlobHistoryDelete:
			switch {
			case entry.Outcome == sidecartest.BlobOutcomeOk && answered:
				present, maybe = false, false
			case entry.Outcome == sidecartest.BlobOutcomeOk, entry.Outcome == sidecartest.BlobOutcomeUnknown, entry.Outcome == "":
				maybe = maybe || present
			}
		}
	}
	return present || maybe
}

// Classes each DELETE since the previous check that may have removed an object a committed version names: a purge's
// when every namer is a versionless version's, else a drop's. Each object goes into memory as purged or dropped.
func (self *evsFormat2Check) classifyDeletes() {
	for index := self.since; index < len(self.history); index += 1 {
		entry := self.history[index]
		if entry.Op != sidecartest.BlobHistoryDelete {
			continue
		}
		switch entry.Outcome {
		case sidecartest.BlobOutcomeOk, sidecartest.BlobOutcomeUnknown, "":
		default:
			// a 412, a held key or a refusal took no effect
			continue
		}
		if !strings.HasPrefix(entry.Key, "seg/") && !strings.HasPrefix(entry.Key, "slot/") {
			continue
		}
		repoId, ok := evsOracleKeyRepo(entry.Key)
		if !ok {
			continue
		}
		repo := self.repoById[repoId]
		if repo == nil {
			continue
		}
		wantClusterId := repo.store.clusterId
		if strings.HasPrefix(entry.Key, "seg/") {
			wantClusterId = self.segmentClusterId
		}
		if entry.ClusterId != wantClusterId || !self.mayExistAt(entry.ClusterId, entry.Key, index) {
			continue
		}
		if state := repo.store.object.GetState(); state == protocol.EvsRepoState_EVS_REPO_SHREDDING || state == protocol.EvsRepoState_EVS_REPO_SHREDDED {
			// a shred's deletes are FI-5's
			continue
		}
		name := entry.ClusterId + " " + entry.Key
		namers := repo.namers[name]
		if len(namers) == 0 {
			// an orphan's, a dead record's or a collected marker's: no committed version names it
			continue
		}
		self.deleteNamers[index] = namers
		self.deleteRepos[index] = repo
		deletion := &evsDeletion{entry: entry, namerKeys: map[string]bool{}, repoId: repoId}
		for _, namer := range namers {
			deletion.namerKeys[namer.key()] = true
		}
		self.memory.stateLock.Lock()
		if evsAllVersionless(namers) {
			self.purgeDeletes = append(self.purgeDeletes, index)
			self.memory.purged[name] = deletion
		} else {
			self.dropDeletes = append(self.dropDeletes, index)
			self.memory.dropped[name] = deletion
		}
		self.memory.stateLock.Unlock()
	}
}

func evsAllVersionless(namers []*evsNamer) bool {
	for _, namer := range namers {
		if !namer.versionless() {
			return false
		}
	}
	return true
}

// Marks each deleted object a check finds gone.
func (self *evsFormat2Check) followDeletions() {
	self.memory.stateLock.Lock()
	defer self.memory.stateLock.Unlock()
	for _, deletions := range []map[string]*evsDeletion{self.memory.purged, self.memory.dropped} {
		for name, deletion := range deletions {
			if !self.objectListed(deletion.repoId, name) {
				deletion.gone = true
			}
		}
	}
}

// Whether this check's walk listed the object.
func (self *evsFormat2Check) objectListed(repoId sidecar.Id, name string) bool {
	repo := self.repoById[repoId]
	if repo == nil {
		return false
	}
	clusterId, key, _ := strings.Cut(name, " ")
	if strings.HasPrefix(key, "seg/") {
		return clusterId == self.segmentClusterId && repo.store.segmentInfos[key] != nil
	}
	return clusterId == repo.store.clusterId && repo.store.slotInfos[key] != nil
}

// The ref of the repo's walk.
func (self *evsFormat2Repo) ref(refId sidecar.Id) *evsStoreRef {
	for _, ref := range self.store.refs {
		if ref.refId == refId {
			return ref
		}
	}
	return nil
}

// The version that replaced namer's: the first later version of its ref that writes or removes its path, removes a
// directory above it, or deletes the ref, following a cut-over's move of the path into the next epoch. 0 when none.
func (self *evsFormat2Check) replacement(repo *evsFormat2Repo, namer *evsNamer) (uint64, error) {
	ref := repo.ref(namer.refId)
	if ref == nil {
		return 0, fmt.Errorf("ref %s is not in the walk", namer.refId)
	}
	tokenPath, epoch := namer.tokenPath, namer.pathEpoch
	for at := namer.version + 1; at <= uint64(len(ref.versions)); at += 1 {
		version := ref.at(at)
		if version == nil {
			return 0, fmt.Errorf("version %d of ref %s, after the namer, was not read", at, ref.refId)
		}
		push := version.statement.Push
		if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) != 0 {
			return at, nil
		}
		if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 && push.GetPathEpoch() != epoch {
			moved, err := self.moveOf(repo, ref, version, epoch, tokenPath)
			if err != nil {
				return 0, fmt.Errorf("the cut-over at version %d of ref %s: %w", at, ref.refId, err)
			}
			tokenPath, epoch = moved, push.GetPathEpoch()
			continue
		}
		if push.GetPathEpoch() != epoch {
			continue
		}
		for _, change := range version.payload.Changes {
			if change.TokenPath.Equal(tokenPath) {
				return at, nil
			}
			if !change.WritesEntry() && len(change.TokenPath) < len(tokenPath) && tokenPath.HasPrefix(change.TokenPath) {
				return at, nil
			}
		}
	}
	return 0, nil
}

// The token path a cut-over at version moves tokenPath of epoch to: its committed map's parts, then its tail.
func (self *evsFormat2Check) moveOf(repo *evsFormat2Repo, ref *evsStoreRef, version *evsStoreVersion, epoch uint64, tokenPath sidecar.EvsTokenPath) (sidecar.EvsTokenPath, error) {
	push := version.statement.Push
	moves, err := fi1MapMoves(self.ctx, self.oracle.View, evsOracleMemoryOf(self.oracle.Net), repo.store, ref.refId, push.GetPathEpoch(), push.GetPathMapSha256())
	if err != nil && len(push.GetPathMapSha256()) != 0 {
		return nil, err
	}
	for _, item := range version.payload.TailMoves {
		move := &protocol.EvsPathMove{}
		if err := proto.Unmarshal(item, move); err != nil {
			return nil, fmt.Errorf("a tail move: %w", err)
		}
		moves = append(moves, move)
	}
	for _, move := range moves {
		for _, source := range move.GetSources() {
			sourcePath, err := sidecar.ParseEvsTokenPath(source.GetTokenPath())
			if err != nil || source.GetEpoch() != epoch || !sourcePath.Equal(tokenPath) {
				continue
			}
			return sidecar.ParseEvsTokenPath(move.GetNewTokenPath())
		}
	}
	return nil, fmt.Errorf("it moves no path from %s of epoch %d", tokenPath.KeyString(), epoch)
}

// When a process was first answered version or a later one of refId's head, before the request at index was
// invoked: the 200 of a head write, or a read or listing of the head, whose ETag a check read at a version at or
// past it.
func (self *evsFormat2Check) headSeen(repo *evsFormat2Repo, refId sidecar.Id, version uint64, index int) (time.Time, bool) {
	clusterId := repo.store.clusterId
	key := evsOracleRepoPrefix("head/", repo.store.repoId) + sidecar.EvsKeyId(refId)
	invokeSeq := self.history[index].InvokeSeq
	self.memory.stateLock.Lock()
	defer self.memory.stateLock.Unlock()
	atOrPast := func(etag string) bool {
		headVersion, ok := self.memory.headEtagVersions[clusterId+" "+key+" "+etag]
		return ok && version <= headVersion
	}
	var seen time.Time
	found := false
	for _, entry := range self.history[:index] {
		if entry.ClusterId != clusterId || entry.Outcome != sidecartest.BlobOutcomeOk || entry.ReturnSeq == 0 || invokeSeq <= entry.ReturnSeq {
			continue
		}
		answered := false
		switch entry.Op {
		case sidecartest.BlobHistoryPutIfNoneMatch, sidecartest.BlobHistoryPutIfMatch:
			answered = entry.Key == key && atOrPast(entry.WriteEtag)
		case sidecartest.BlobHistoryGet, sidecartest.BlobHistoryGetRange, sidecartest.BlobHistoryHead:
			answered = entry.Key == key && atOrPast(entry.ReadEtag)
		case sidecartest.BlobHistoryList:
			if etag, ok := entry.ListedKeyEtags[key]; ok {
				answered = atOrPast(etag)
			}
		}
		if answered && (!found || entry.Returned.Before(seen)) {
			seen, found = entry.Returned, true
		}
	}
	return seen, found
}

// The holds of the repo's network covering the repo that stood for a deleter when the request at index issued:
// acknowledged at least readAge before, not removed by an acknowledged DELETE before it, and live at it. unknown is
// true when one whose terms no check read, or no reader parses, stood: it keeps everything.
func (self *evsFormat2Check) holdsAt(repo *evsFormat2Repo, index int, readAge time.Duration) ([]*sidecar.HoldRecord, bool) {
	if repo.networkId == (sidecar.Id{}) {
		// a repo whose network is not known is covered with unknown terms (plan-EVSB-repo-network)
		return nil, true
	}
	deletion := self.history[index]
	prefix := "hold/" + repo.networkId.String() + "/"
	standingEtags := map[string]string{}
	for _, entry := range self.history[:index] {
		if entry.ClusterId != self.firstClusterId || !strings.HasPrefix(entry.Key, prefix) {
			continue
		}
		switch entry.Op {
		case sidecartest.BlobHistoryPutIfNoneMatch, sidecartest.BlobHistoryPutIfMatch, sidecartest.BlobHistoryPutStream:
			at := entry.Returned
			switch entry.Outcome {
			case sidecartest.BlobOutcomeOk:
			case sidecartest.BlobOutcomeUnknown, "":
				// it may have landed: a doubt keeps data
				at = entry.Invoked
			default:
				continue
			}
			if !at.After(deletion.Invoked.Add(-readAge)) {
				standingEtags[entry.Key] = entry.WriteEtag
			}
		case sidecartest.BlobHistoryDelete:
			if entry.Outcome == sidecartest.BlobOutcomeOk && entry.ReturnSeq != 0 && entry.ReturnSeq < deletion.InvokeSeq {
				delete(standingEtags, entry.Key)
			}
		}
	}
	keys := []string{}
	for key := range standingEtags {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	self.memory.stateLock.Lock()
	defer self.memory.stateLock.Unlock()
	records := []*sidecar.HoldRecord{}
	unknown := false
	for _, key := range keys {
		record, read := self.memory.holdRecords[key+" "+standingEtags[key]]
		if !read || record == nil {
			unknown = true
			continue
		}
		if record.Live(deletion.Invoked) && record.Scope.Covers(repo.store.repoId) {
			records = append(records, record)
		}
	}
	return records, unknown
}

// When the object a DELETE names came to exist, for a hold's keep: a staged object's at the start of the minute its
// record's batch names, an uploaded one's at its first LastModified a check listed, or else at its first write in
// the history; the zero time when nothing says, which every hold keeps.
func (self *evsFormat2Check) createdAt(name string, namers []*evsNamer) time.Time {
	staged := 0 < len(namers)
	earliest := time.Time{}
	for _, namer := range namers {
		if namer.kind != evsNameStaged {
			staged = false
			break
		}
		if earliest.IsZero() || namer.recordMinute.Before(earliest) {
			earliest = namer.recordMinute
		}
	}
	if staged {
		return earliest
	}
	self.memory.stateLock.Lock()
	created, ok := self.memory.createdTimes[name]
	self.memory.stateLock.Unlock()
	if ok {
		return created
	}
	clusterId, key, _ := strings.Cut(name, " ")
	for _, entry := range self.history {
		if entry.ClusterId != clusterId || entry.Key != key {
			continue
		}
		switch entry.Op {
		case sidecartest.BlobHistoryPutIfNoneMatch, sidecartest.BlobHistoryPutIfMatch, sidecartest.BlobHistoryPutStream:
			if entry.Outcome == sidecartest.BlobOutcomeOk || entry.Outcome == sidecartest.BlobOutcomeUnknown {
				return entry.Invoked
			}
		}
	}
	return time.Time{}
}

// Whether a mode read observe at both the previous check and this one: the whole step ran under it.
func evsObservedThroughout(previousSet bool, previous sidecar.Format2Mode, now sidecar.Format2Mode) bool {
	return now == sidecar.Format2Observe && (!previousSet || previous == sidecar.Format2Observe)
}

// What a DELETE's line says of it.
func evsDeleteText(entry *sidecartest.BlobHistoryEntry) string {
	actor := entry.Actor
	if actor == "" {
		actor = "an unnamed actor"
	}
	return fmt.Sprintf("%s's DELETE of %s on %s at %s", actor, entry.Key, entry.ClusterId, entry.Invoked.UTC().Format(time.RFC3339Nano))
}

// Whether every namer of an object is a versionless version that a later version of its ref replaced: a purge's
// candidate, whose absence FI-1 excuses and FI-16 judges.
func (self *evsFormat2Check) purgeCandidate(repoId sidecar.Id, name string) bool {
	repo := self.repoById[repoId]
	if repo == nil {
		return false
	}
	namers := repo.namers[name]
	if len(namers) == 0 || !evsAllVersionless(namers) {
		return false
	}
	for _, namer := range namers {
		replaced, err := self.replacement(repo, namer)
		if err != nil || replaced == 0 {
			return false
		}
	}
	return true
}

func checkFi16(ctx context.Context, oracle *Oracle) error {
	check := evsFormat2Of(ctx, oracle)
	check.memory.stateLock.Lock()
	settings := *check.memory.fi16Settings
	check.memory.stateLock.Unlock()
	errs := slices.Clone(check.errs)
	for _, index := range check.purgeDeletes {
		errs = append(errs, check.judgePurge(index, &settings)...)
	}
	errs = append(errs, check.purgedStayGone()...)
	errs = append(errs, check.newestVersionlessKept()...)
	return errors.Join(errs...)
}

// FI-16's rules for one purge's DELETE: see the file header.
func (self *evsFormat2Check) judgePurge(index int, settings *Fi16Settings) []error {
	entry := self.history[index]
	repo := self.deleteRepos[index]
	namers := self.deleteNamers[index]
	what := evsDeleteText(entry)
	if !repo.store.complete() {
		return []error{fmt.Errorf("%s: repo %s's history was not read whole, so its purge cannot be judged", what, repo.store.repoId)}
	}
	errs := []error{}
	for _, namer := range namers {
		replaced, err := self.replacement(repo, namer)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %s: %w", what, namer, err))
			continue
		}
		if replaced == 0 {
			errs = append(errs, fmt.Errorf("%s: %s names it and is its path's newest, which keeps all its content: nothing is purged before its replacing version commits", what, namer))
			continue
		}
		seen, ok := self.headSeen(repo, namer.refId, replaced, index)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: version %d of ref %s replaced %s and was answered to no process before the DELETE issued, no 200 of its head write and no read of a head at or past it: an unknown push purges nothing", what, replaced, namer.refId, namer))
			continue
		}
		if entry.Invoked.Before(seen.Add(settings.Allowance - settings.ClockBound)) {
			errs = append(errs, fmt.Errorf("%s: issued %s after version %d of ref %s, which replaced %s, was first seen, inside the %s allowance", what, entry.Invoked.Sub(seen), replaced, namer.refId, namer, settings.Allowance))
		}
	}
	name := entry.ClusterId + " " + entry.Key
	created := self.createdAt(name, namers)
	records, unknown := self.holdsAt(repo, index, settings.HoldReadAge)
	if unknown {
		errs = append(errs, fmt.Errorf("%s: a hold whose terms no reader can read stood for the repo's network, which keeps everything", what))
	}
	for _, record := range records {
		if !created.After(record.PlaceTime) {
			errs = append(errs, fmt.Errorf("%s: hold %s, placed at %s, kept it, since it existed at the placement (from %s)", what, record.CaseId, record.PlaceTime.UTC().Format(time.RFC3339), created.UTC().Format(time.RFC3339)))
		}
	}
	if evsObservedThroughout(self.previousModesSet, self.previousPurgeMode, self.purgeMode) {
		errs = append(errs, fmt.Errorf("%s: issued while §19.11's purge mode read observe, which deletes nothing", what))
	}
	return errs
}

// A purged object, once gone, never returns, and no version a later check first finds names it.
func (self *evsFormat2Check) purgedStayGone() []error {
	self.memory.stateLock.Lock()
	names := []string{}
	for name := range self.memory.purged {
		names = append(names, name)
	}
	self.memory.stateLock.Unlock()
	slices.Sort(names)
	errs := []error{}
	for _, name := range names {
		self.memory.stateLock.Lock()
		deletion := self.memory.purged[name]
		gone := deletion.gone
		self.memory.stateLock.Unlock()
		_, key, _ := strings.Cut(name, " ")
		if gone && self.objectListed(deletion.repoId, name) {
			errs = append(errs, fmt.Errorf("%s, purged by %s, is stored again: purged content never returns, a stale re-seed included", key, evsDeleteText(deletion.entry)))
		}
		if repo := self.repoById[deletion.repoId]; repo != nil {
			for _, namer := range repo.namers[name] {
				if !deletion.namerKeys[namer.key()] {
					errs = append(errs, fmt.Errorf("%s, purged by %s, is named by %s, which committed after the purge", key, evsDeleteText(deletion.entry), namer))
				}
			}
		}
	}
	return errs
}

// Every path's newest committed version that is versionless keeps all its content: each segment its chain names is
// stored, a staged one in its record's tail or at seg/, and each slot it names is stored.
func (self *evsFormat2Check) newestVersionlessKept() []error {
	errs := []error{}
	for _, repo := range self.repos {
		if state := repo.store.object.GetState(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
			// a repo deleted, shredding or keying is FI-5's
			continue
		}
		for _, ref := range repo.store.refs {
			if ref.head.Head.GetDeleted() {
				continue
			}
			type newest struct {
				version *evsStoreVersion
				index   int
			}
			newestByPath := map[string]*newest{}
			cutOver := map[uint64]bool{}
			for _, version := range ref.versions {
				if version == nil {
					continue
				}
				push := version.statement.Push
				if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
					// a cut-over moves every path of the epochs before it: those are left to FI-1
					for epoch := uint64(0); epoch < push.GetPathEpoch(); epoch += 1 {
						cutOver[epoch] = true
					}
				}
				for i, change := range version.payload.Changes {
					pathKey := fmt.Sprintf("%d/%s", push.GetPathEpoch(), change.TokenPath.KeyString())
					newestByPath[pathKey] = &newest{version: version, index: i}
					if !change.WritesEntry() {
						// a removal also ends what is below it
						for otherKey, other := range newestByPath {
							otherPath := other.version.payload.Changes[other.index].TokenPath
							if otherKey != pathKey && other.version.statement.Push.GetPathEpoch() == push.GetPathEpoch() && len(change.TokenPath) < len(otherPath) && otherPath.HasPrefix(change.TokenPath) {
								delete(newestByPath, otherKey)
							}
						}
					}
				}
			}
			pathKeys := []string{}
			for pathKey := range newestByPath {
				pathKeys = append(pathKeys, pathKey)
			}
			slices.Sort(pathKeys)
			for _, pathKey := range pathKeys {
				found := newestByPath[pathKey]
				entryVersion := found.version.entryVersions[found.index]
				if entryVersion == nil || entryVersion.GetVersioning() == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) || cutOver[found.version.statement.Push.GetPathEpoch()] {
					continue
				}
				where := fmt.Sprintf("repo %s ref %s: version %d of %s, its path's newest and versionless", repo.store.repoId, ref.refId, found.version.version, found.version.payload.Changes[found.index].TokenPath.KeyString())
				for _, locator := range entryVersion.GetChain() {
					kind := protocol.EvsLocatorKind(locator.GetKind())
					if kind != protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT && kind != protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT {
						continue
					}
					idHex := hex.EncodeToString(locator.GetId())
					key := evsOracleSegmentKey(repo.store.repoId, locator.GetId())
					if locator.GetStaged() && found.version.stagedIds[idHex] {
						continue
					}
					if repo.store.segmentInfos[key] == nil {
						errs = append(errs, fmt.Errorf("%s, names %s, which neither its record nor %s holds: every path's newest committed version keeps all its content", where, key, self.segmentClusterId))
					}
				}
				for _, slotId := range entryVersion.GetSlotIds() {
					key := evsOracleSlotKey(repo.store.repoId, slotId)
					if repo.store.slotInfos[key] == nil {
						errs = append(errs, fmt.Errorf("%s, names %s, which is gone: every path's newest committed version keeps all its content", where, key))
					}
				}
			}
		}
	}
	return errs
}

// Whether every ref's history was read whole, and nothing the walk read failed.
func (self *evsStoreRepo) complete() bool {
	if 0 < len(self.missing) {
		return false
	}
	for _, ref := range self.refs {
		if !ref.complete {
			return false
		}
	}
	return true
}
