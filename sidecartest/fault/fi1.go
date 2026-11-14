// FI-1, closure (§22.8; I-EVS-1, I-EVS-5, I-EVS-7; D-TEST-10), and the store walk FI-6 shares (fi6.go).
//
// For every repo place/ names, on the metadata cluster place/ gives it, the walk reads each committed head's whole
// history the way a reader finds it in the store, with the format's own decoders and none of evsservice's behaviour
// (TEST-M2-01's trap: an oracle sharing evs's push or fold logic shares its bugs):
//
//   - every version 1..v: its window entry, from the head's window or from log page u/64, which is log/ or, once
//     packed, the pack a pidx/ entry lists it in; the chain C_0..C_v through each statement's bytes, to each page's
//     chains, the window's base chain and the head's;
//   - every version's record at the place its entry names: in its batch, else, once evacuated, in the pack or parcel
//     whose pidx/ entry lists that place at that version, found as a reader finds it (§11.8's read row, EVSB-M2-10):
//     the batch, then pidx/ by one LIST, a pack's entry before a parcel's, and on a 404 at a named container one more
//     LIST. A seal's parts the same way. Each record's statement is the one its entry names, and its payload checks
//     against it.
//
// FI-1 then holds the closure of what the walk found:
//
//   - every committed entry version's segments on the segment cluster and slots on the repo's cluster, each slot
//     keeping every key its introducing push's slot body held;
//   - every committed PATH_EPOCH's map: each part under pmap/, and the parts hashing to path_map_sha256;
//   - every generation a statement or a head pins: gen/<g> with the commitment pinned, and the ladder below it; and a
//     wrap of a group's newest generation, once seen, stays while that generation is the newest (gkm-7's ttl);
//   - every head seen stays, at no lower version;
//   - where the Net holds a current reader's keys (sidecar_testhooks), every committed file version decrypts for that
//     reader: its push's sealed metadata, its sealed fields, and each record of its chain, header and every frame,
//     inline or in a segment, container-keyed or slot-keyed, under the keys the ladder gives it. A current reader is a
//     named actor whose RK_g opens the repo's newest generation (StoreView.Open). With no named actor holding any of
//     the repo's keys, which is every schedule on a leg without the hooks, the decrypt clause does not run and the
//     closure is checked for retrievability alone; with some holding them and none holding the newest, it fails.
//
// The exceptions are read, never inferred from a missing object. A slot's key is excused only by a committed ERASE,
// visible in its ref's history, whose signature verifies under its signer's identity key at its own auth pin and
// whose signer the reader's ref rules take there (§11.8's refs table: a repo admin on the erasure ref, the owner on a
// record-class owned ref); a whole repo only by repo/ in shredding or shredded under the deletion id of the access
// log's RepoDelete, not restored. Both read the network's authorization state from the view a schedule names with
// SetAuthorizationView; with none named, nothing is excused, so an erasure or shred reads as missing objects. A
// format-2 executed drop (FI-27, TEST-M10-01) and a consumed deposit's deleted content excuse nothing yet, so a
// schedule meeting either fails closed.
//
// What the walk could not read or decode is FI-1's own violation. Cost: a repo is walked again only at a check after
// a step that wrote one of its keys, a batch one of its records was read from, or a gkm/ key of its group; decoded
// immutable objects are kept by key and ETag, so a walk reads only what changed.

package fault

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"weak"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var _ = RegisterInvariant(1, func(ctx context.Context, oracle *Oracle) error {
	return checkFi1(ctx, oracle)
})

// Names the authorization state FI-1 checks an erasure's or a shred's authority against for one network: §7.9's
// state as the network's readers verify it. A schedule whose log lives outside the store, as a FakeGkmAuthLog does,
// names it here; with none named, no erasure or shred is excused. Each state named is kept with when it was named on
// the Net's clock, which FI-3 judges a head CAS against (fi3.go) and FI-4 authenticates gen/ by (fi4.go), so a
// schedule names each state as it becomes current.
func SetAuthorizationView(net *Net, networkId sidecar.Id, view sidecar.GkmAuthView) {
	at := net.Clock().Now()
	memory := evsOracleMemoryOf(net)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	memory.authorizationViews[networkId] = view
	memory.authorizationHistory[networkId] = append(memory.authorizationHistory[networkId], &evsAuthorizationAt{view: view, at: at})
}

// One authorization state a schedule named, and when, on the Net's clock.
type evsAuthorizationAt struct {
	view sidecar.GkmAuthView
	at   time.Time
}

// What the evs oracles keep from one check to the next on one Net. Safe for concurrent use.
type evsOracleMemory struct {
	stateLock          sync.Mutex
	authorizationViews map[sidecar.Id]sidecar.GkmAuthView
	// every state named, by network, in the order named
	authorizationHistory map[sidecar.Id][]*evsAuthorizationAt
	// immutable objects as decoded, by cluster, key and ETag
	decoded map[string]any
	// each repo's walk at its last check, by repo id
	repoWalks map[sidecar.Id]*evsStoreRepo
	// the batch keys and gkm groups each repo's walk read, so a change there walks the repo again
	batchRepos map[string]map[sidecar.Id]bool
	groupRepos map[string]map[sidecar.Id]bool
	// the check whose walk this is, so FI-6 at the same check reads FI-1's
	walkOracle *Oracle
	walkErrs   []error
	// FI-1: each head's version seen, by repo and ref
	headVersions map[string]uint64
	// FI-1: each group's newest generation and the wraps of it seen
	newestGenerations map[sidecar.Id]uint64
	newestWraps       map[sidecar.Id]map[string]bool
	// FI-6's memory (fi6.go)
	fi6 *fi6Memory
	// the batch records the check batchOracle read, which FI-2 and FI-6 share (fi6Batches)
	batchOracle  *Oracle
	batchRecords []*fi6BatchRecord
	batchOldest  time.Time
	batchErrs    []error
}

var evsOracleMemories sync.Map

// The Net's memory, made at first use; it goes with the Net.
func evsOracleMemoryOf(net *Net) *evsOracleMemory {
	key := weak.Make(net)
	if memory, ok := evsOracleMemories.Load(key); ok {
		return memory.(*evsOracleMemory)
	}
	memory := &evsOracleMemory{
		authorizationViews:   map[sidecar.Id]sidecar.GkmAuthView{},
		authorizationHistory: map[sidecar.Id][]*evsAuthorizationAt{},
		decoded:              map[string]any{},
		repoWalks:            map[sidecar.Id]*evsStoreRepo{},
		batchRepos:           map[string]map[sidecar.Id]bool{},
		groupRepos:           map[string]map[sidecar.Id]bool{},
		headVersions:         map[string]uint64{},
		newestGenerations:    map[sidecar.Id]uint64{},
		newestWraps:          map[sidecar.Id]map[string]bool{},
		fi6:                  newFi6Memory(),
	}
	actual, loaded := evsOracleMemories.LoadOrStore(key, memory)
	if !loaded {
		// removed when the Net closes: the memory holds its walk's Oracle and so the Net, so a cleanup waiting for the
		// Net's collection never ran, and every Net's stores stayed (TestFs1 alone kept 17.5 GB)
		context.AfterFunc(net.Context(), func() { evsOracleMemories.Delete(key) })
	}
	return actual.(*evsOracleMemory)
}

func (self *evsOracleMemory) authorizationView(networkId sidecar.Id) sidecar.GkmAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.authorizationViews[networkId]
}

// Every state named for the network, in the order named.
func (self *evsOracleMemory) authorizationHistoryOf(networkId sidecar.Id) []*evsAuthorizationAt {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.authorizationHistory[networkId])
}

// Every network a state was named for, with its newest state.
func (self *evsOracleMemory) authorizationViewsNamed() map[sidecar.Id]sidecar.GkmAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	views := map[sidecar.Id]sidecar.GkmAuthView{}
	for networkId, view := range self.authorizationViews {
		views[networkId] = view
	}
	return views
}

// The refs of the repo whose heads an earlier check saw, from headVersions' keys.
func (self *evsOracleMemory) seenRefIds(repoId sidecar.Id) []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	prefix := repoId.String() + "/"
	refIds := []sidecar.Id{}
	for key := range self.headVersions {
		refText, ok := strings.CutPrefix(key, prefix)
		if !ok {
			continue
		}
		if refId, err := sidecar.ParseId(refText); err == nil {
			refIds = append(refIds, refId)
		}
	}
	return refIds
}

// An object decoded once, by cluster, key and ETag: immutable families never change under one ETag.
func (self *evsOracleMemory) decodedObject(object *StoreObject, decode func(body []byte) (any, error)) (any, error) {
	cacheKey := object.ClusterId + "\x00" + object.Key + "\x00" + object.Etag
	self.stateLock.Lock()
	value, ok := self.decoded[cacheKey]
	self.stateLock.Unlock()
	if ok {
		return value, nil
	}
	value, err := decode(object.Body)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	self.decoded[cacheKey] = value
	self.stateLock.Unlock()
	return value, nil
}

// Keys as protocol/EVS-FORMAT.md and §11.8's objects table write them, built here from the format's text, never
// through evsservice.

func evsOracleNumber(number uint64) string {
	return fmt.Sprintf("%020d", number)
}

func evsOracleRepoPrefix(family string, repoId sidecar.Id) string {
	return family + sidecar.EvsKeyId(repoId) + "/"
}

func evsOracleRefPrefix(family string, repoId sidecar.Id, refId sidecar.Id) string {
	return evsOracleRepoPrefix(family, repoId) + sidecar.EvsKeyId(refId) + "/"
}

func evsOracleLogPageKey(repoId sidecar.Id, refId sidecar.Id, page uint64) string {
	return evsOracleRefPrefix("log/", repoId, refId) + evsOracleNumber(page)
}

// pb/<yyyymmddhh>/<mm>/<instance>-<seq> of the batch a place names.
func evsOracleBatchKey(place *protocol.EvsPlace) string {
	at := time.Unix(int64(place.GetMinute())*60, 0).UTC()
	return "pb/" + at.Format("2006010215") + "/" + at.Format("04") + "/" + fmt.Sprintf("%08x-%08x", place.GetInstance(), place.GetSeq())
}

// The minute a pb/ key names, false for a key of another shape.
func evsOracleBatchKeyMinute(key string) (time.Time, bool) {
	parts := strings.Split(strings.TrimPrefix(key, "pb/"), "/")
	if !strings.HasPrefix(key, "pb/") || len(parts) != 3 {
		return time.Time{}, false
	}
	at, err := time.Parse("200601021504", parts[0]+parts[1])
	if err != nil {
		return time.Time{}, false
	}
	return at.UTC(), true
}

func evsOracleSegmentKey(repoId sidecar.Id, segmentId []byte) string {
	return evsOracleRepoPrefix("seg/", repoId) + hex.EncodeToString(segmentId)
}

func evsOracleSlotKey(repoId sidecar.Id, slotId []byte) string {
	return evsOracleRepoPrefix("slot/", repoId) + hex.EncodeToString(slotId)
}

func evsOracleMapPrefix(repoId sidecar.Id, refId sidecar.Id, epoch uint64, mapSha256 []byte) string {
	return evsOracleRefPrefix("pmap/", repoId, refId) + evsOracleNumber(epoch) + "/" + hex.EncodeToString(mapSha256) + "/"
}

func evsOracleIndexPrefix(repoId sidecar.Id, refId sidecar.Id, epoch uint64) string {
	return evsOracleRefPrefix("idx/", repoId, refId) + evsOracleNumber(epoch) + "/"
}

// idx/<repo>/<ref>/<p>/<t1>/.../<tn>.e, and the root's idx/<repo>/<ref>/<p>.e.
func evsOracleIndexKey(repoId sidecar.Id, refId sidecar.Id, epoch uint64, tokenPath sidecar.EvsTokenPath) string {
	if len(tokenPath) == 0 {
		return strings.TrimSuffix(evsOracleIndexPrefix(repoId, refId, epoch), "/") + ".e"
	}
	return evsOracleIndexPrefix(repoId, refId, epoch) + tokenPath.KeyString() + ".e"
}

func evsOraclePlacesEqual(a *protocol.EvsPlace, b *protocol.EvsPlace) bool {
	return a.GetMinute() == b.GetMinute() && a.GetInstance() == b.GetInstance() && a.GetSeq() == b.GetSeq() &&
		a.GetOffset() == b.GetOffset() && a.GetLength() == b.GetLength()
}

// The repo an object key names, for the families keyed by repo, false for any other.
func evsOracleKeyRepo(key string) (sidecar.Id, bool) {
	for _, family := range []string{"head/", "log/", "idx/", "slot/", "seg/", "pack/", "hp/", "pidx/", "pmap/", "repo/", "place/", "spidx/", "drops/"} {
		rest, ok := strings.CutPrefix(key, family)
		if !ok {
			continue
		}
		idHex, _, _ := strings.Cut(rest, "/")
		idBytes, err := hex.DecodeString(idHex)
		if err != nil || len(idBytes) != 16 {
			return sidecar.Id{}, false
		}
		return sidecar.Id(idBytes), true
	}
	return sidecar.Id{}, false
}

// One repo as the store holds it at one check.
type evsStoreRepo struct {
	repoId    sidecar.Id
	clusterId string
	// repo/, nil when absent
	object *protocol.EvsRepoObject
	refs   []*evsStoreRef
	// seg/<repo>/ and slot/<repo>/ as listed, by key
	segmentInfos map[string]*sidecar.BlobInfo
	slotInfos    map[string]*sidecar.BlobInfo
	// each slot a committed push introduced: its body as the push carried it, by slot id hex
	slotIntroductions map[string]*evsSlotIntroduction
	// the pb/ keys and gkm groups this walk read
	batchKeys map[string]bool
	groupIds  map[sidecar.Id]bool
	// what the walk could not retrieve, decode or match
	missing []error
	// the check that walked it: a later check reuses a walk no step since has changed, whose clauses passed then
	walkedBy *Oracle
}

type evsSlotIntroduction struct {
	version uint64
	refId   sidecar.Id
	body    *protocol.EvsSlotObject
}

// One ref's committed history as the store holds it.
type evsStoreRef struct {
	refId sidecar.Id
	head  *StoreHead
	// versions 1..v, at index u - 1; nil where the walk could not read one
	versions []*evsStoreVersion
	// every version's statement and record were read
	complete bool
}

// The version at u, nil when the walk did not read it.
func (self *evsStoreRef) at(version uint64) *evsStoreVersion {
	if version == 0 || uint64(len(self.versions)) < version {
		return nil
	}
	return self.versions[version-1]
}

// One committed version: its window entry, its statement and the payload its record holds.
type evsStoreVersion struct {
	version   uint64
	entry     *sidecar.EvsWindowEntry
	statement *sidecar.EvsStatement
	payload   *sidecar.EvsCheckedPayload
	// each change's entry version decoded, nil for a removal, in change order
	entryVersions []*protocol.EvsEntryVersion
}

// The walk of one check: every placed repo, each walked anew when a step changed what it reads and kept otherwise.
type evsStoreWalker struct {
	ctx    context.Context
	oracle *Oracle
	view   *StoreView
	memory *evsOracleMemory
	// this walk's pidx/ entries, by repo and ref
	pidxEntries map[string][]*evsPidxRead
}

type evsPidxRead struct {
	key   string
	entry *protocol.EvsPidxEntry
}

// Every placed repo at this check, and what the walk could not read. FI-1 and FI-6 at one check share one walk.
func evsStoreWalkOf(ctx context.Context, oracle *Oracle) ([]*evsStoreRepo, []error) {
	memory := evsOracleMemoryOf(oracle.Net)
	memory.stateLock.Lock()
	if memory.walkOracle == oracle {
		repos := slices.Collect(func(yield func(*evsStoreRepo) bool) {
			for _, repo := range memory.repoWalks {
				if !yield(repo) {
					return
				}
			}
		})
		errs := memory.walkErrs
		memory.stateLock.Unlock()
		sortEvsStoreRepos(repos)
		return repos, errs
	}
	memory.stateLock.Unlock()

	walker := &evsStoreWalker{ctx: ctx, oracle: oracle, view: oracle.View, memory: memory, pidxEntries: map[string][]*evsPidxRead{}}
	repos, errs := walker.walk()

	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	memory.walkOracle = oracle
	memory.walkErrs = errs
	return repos, errs
}

func sortEvsStoreRepos(repos []*evsStoreRepo) {
	sort.Slice(repos, func(i int, j int) bool { return bytes.Compare(repos[i].repoId[:], repos[j].repoId[:]) < 0 })
}

func (self *evsStoreWalker) walk() ([]*evsStoreRepo, []error) {
	firstClusterId, err := self.view.FirstClusterId()
	if err != nil {
		return nil, []error{err}
	}
	placeInfos, err := self.view.List(self.ctx, firstClusterId, "place/")
	if err != nil {
		return nil, []error{err}
	}
	changed := self.changedRepos()
	repos := []*evsStoreRepo{}
	errs := []error{}
	seen := map[sidecar.Id]bool{}
	for _, info := range placeInfos {
		repoId, ok := evsOracleKeyRepo(info.Key)
		if !ok {
			errs = append(errs, fmt.Errorf("%s names no repo", info.Key))
			continue
		}
		seen[repoId] = true
		self.memory.stateLock.Lock()
		previous := self.memory.repoWalks[repoId]
		self.memory.stateLock.Unlock()
		if previous != nil && changed != nil && !changed[repoId] {
			repos = append(repos, previous)
			continue
		}
		repo := self.walkRepo(repoId)
		repo.walkedBy = self.oracle
		self.memory.stateLock.Lock()
		self.memory.repoWalks[repoId] = repo
		for batchKey := range repo.batchKeys {
			if self.memory.batchRepos[batchKey] == nil {
				self.memory.batchRepos[batchKey] = map[sidecar.Id]bool{}
			}
			self.memory.batchRepos[batchKey][repoId] = true
		}
		for groupId := range repo.groupIds {
			groupKey := "gkm/" + sidecar.EvsKeyId(groupId) + "/"
			if self.memory.groupRepos[groupKey] == nil {
				self.memory.groupRepos[groupKey] = map[sidecar.Id]bool{}
			}
			self.memory.groupRepos[groupKey][repoId] = true
		}
		self.memory.stateLock.Unlock()
		repos = append(repos, repo)
	}
	self.memory.stateLock.Lock()
	for repoId := range self.memory.repoWalks {
		if !seen[repoId] {
			errs = append(errs, fmt.Errorf("repo %s: its place/ is gone, which is never deleted in v0 (§11.8)", repoId))
		}
	}
	self.memory.stateLock.Unlock()
	sortEvsStoreRepos(repos)
	return repos, errs
}

// The repos a step changed a key of, nil on a Net's first check, when every repo is walked.
func (self *evsStoreWalker) changedRepos() map[sidecar.Id]bool {
	self.memory.stateLock.Lock()
	defer self.memory.stateLock.Unlock()
	if len(self.memory.repoWalks) == 0 {
		return nil
	}
	changed := map[sidecar.Id]bool{}
	for _, keys := range self.oracle.ChangedKeys() {
		for _, key := range keys {
			if repoId, ok := evsOracleKeyRepo(key); ok {
				changed[repoId] = true
				continue
			}
			if strings.HasPrefix(key, "pb/") {
				for repoId := range self.memory.batchRepos[key] {
					changed[repoId] = true
				}
				// a batch none of whose records a walk read holds no committed record, but may hold a pending
				// one FI-6 follows, and FI-6 reads every batch itself
				continue
			}
			if strings.HasPrefix(key, "gkm/") {
				for groupKey, repoIds := range self.memory.groupRepos {
					if strings.HasPrefix(key, groupKey) {
						for repoId := range repoIds {
							changed[repoId] = true
						}
					}
				}
			}
		}
	}
	return changed
}

func (self *evsStoreRepo) fail(format string, a ...any) {
	self.missing = append(self.missing, fmt.Errorf("repo %s: "+format, append([]any{self.repoId}, a...)...))
}

func (self *evsStoreWalker) walkRepo(repoId sidecar.Id) *evsStoreRepo {
	repo := &evsStoreRepo{
		repoId:            repoId,
		segmentInfos:      map[string]*sidecar.BlobInfo{},
		slotInfos:         map[string]*sidecar.BlobInfo{},
		slotIntroductions: map[string]*evsSlotIntroduction{},
		batchKeys:         map[string]bool{},
		groupIds:          map[sidecar.Id]bool{},
	}
	clusterId, err := self.view.RepoClusterId(self.ctx, repoId)
	if err != nil {
		repo.fail("place/: %v", err)
		return repo
	}
	repo.clusterId = clusterId
	repoObject, err := self.view.Object(self.ctx, clusterId, sidecar.EvsRepoObjectKey(repoId))
	if err != nil {
		repo.fail("repo/: %v", err)
	} else if repoObject != nil {
		decoded := &protocol.EvsRepoObject{}
		if err := proto.Unmarshal(repoObject.Body, decoded); err != nil {
			repo.fail("repo/: %v", err)
		} else {
			repo.object = decoded
		}
	}
	segmentCluster, err := self.view.net.Host().Blobs.SegmentCluster()
	if err != nil {
		repo.fail("the segment cluster: %v", err)
		return repo
	}
	listInto := func(clusterId string, prefix string, into map[string]*sidecar.BlobInfo) {
		infos, err := self.view.List(self.ctx, clusterId, prefix)
		if err != nil {
			repo.fail("%v", err)
			return
		}
		for _, info := range infos {
			into[info.Key] = info
		}
	}
	listInto(segmentCluster.ClusterId(), evsOracleRepoPrefix("seg/", repoId), repo.segmentInfos)
	listInto(clusterId, evsOracleRepoPrefix("slot/", repoId), repo.slotInfos)

	heads, err := self.view.Heads(self.ctx, repoId)
	if err != nil {
		repo.fail("heads: %v", err)
		return repo
	}
	// On stock MinIO a LIST can leave out a key whose overwrite is in flight, every drive online, where a GET of the
	// key does not (question evs1-m2-41-list-drops-overwritten-key), and a reader reads a ref it knows by its key. So
	// a head an earlier check saw and this LIST left out is read by its key, and only one its key no longer holds is
	// gone.
	listedKeys := map[string]bool{}
	for _, head := range heads {
		listedKeys[head.Key] = true
	}
	for _, refId := range self.memory.seenRefIds(repoId) {
		if listedKeys[evsOracleRepoPrefix("head/", repoId)+sidecar.EvsKeyId(refId)] {
			continue
		}
		head, err := self.view.Head(self.ctx, repoId, refId)
		if err != nil {
			repo.fail("the head of ref %s: %v", refId, err)
			continue
		}
		if head != nil {
			heads = append(heads, head)
		}
	}
	slices.SortFunc(heads, func(a *StoreHead, b *StoreHead) int { return strings.Compare(a.Key, b.Key) })
	for _, head := range heads {
		refId, err := sidecar.IdFromBytes(head.RefId)
		if err != nil {
			repo.fail("%s: %v", head.Key, err)
			continue
		}
		ref := self.walkRef(repo, refId, head)
		repo.refs = append(repo.refs, ref)
	}
	return repo
}

// The ref's history from its head: the window's versions, then each older one from its log page, with every
// version's record, and the chain through them all.
func (self *evsStoreWalker) walkRef(repo *evsStoreRepo, refId sidecar.Id, head *StoreHead) *evsStoreRef {
	ref := &evsStoreRef{refId: refId, head: head, complete: true}
	version := head.Head.GetVersion()
	if version == 0 {
		// a placeholder head: no version, no closure
		return ref
	}
	if groupId, err := sidecar.IdFromBytes(head.Head.GetGroupId()); err == nil {
		repo.groupIds[groupId] = true
	}
	ref.versions = make([]*evsStoreVersion, version)
	failRef := func(format string, a ...any) {
		ref.complete = false
		repo.fail("ref %s: "+format, append([]any{refId}, a...)...)
	}
	window, err := sidecar.DecodeEvsWindow(head.Head.GetWindow())
	if err != nil {
		failRef("its window: %v", err)
		return ref
	}
	if version < uint64(len(window)) {
		failRef("a window of %d entries at version %d", len(window), version)
		return ref
	}
	firstWindowVersion := version - uint64(len(window)) + 1
	entries := make([]*sidecar.EvsWindowEntry, version+1)
	// statements known from log pages, by version, and the chain each page states
	pageStatements := map[uint64][]byte{}
	pageFirstChains := map[uint64][]byte{}
	pageLastChains := map[uint64][]byte{}
	// page n holds versions max(64n, 1) to 64n + 63, and the pages below the window hold every version before it
	for page := uint64(0); max(page*64, 1) < firstWindowVersion; page += 1 {
		logPage, err := self.logPage(repo, refId, page)
		if err != nil {
			failRef("log page %d: %v", page, err)
			continue
		}
		pageEntries, err := sidecar.DecodeEvsWindow(logPage.GetWindow())
		if err != nil {
			failRef("log page %d's window: %v", page, err)
			continue
		}
		first := max(page*64, 1)
		if len(pageEntries) != len(logPage.GetStatements()) || uint64(len(pageEntries)) != page*64+64-first {
			failRef("log page %d holds %d entries and %d statements", page, len(pageEntries), len(logPage.GetStatements()))
			continue
		}
		for i, entry := range pageEntries {
			at := first + uint64(i)
			if at < firstWindowVersion {
				entries[at] = entry
				pageStatements[at] = logPage.GetStatements()[i]
			}
		}
		pageFirstChains[page] = logPage.GetFirstChain()
		pageLastChains[page] = logPage.GetLastChain()
	}
	for i, entry := range window {
		entries[firstWindowVersion+uint64(i)] = entry
	}

	chain := sidecar.EvsChainStart(repo.repoId, refId)
	chainBroken := false
	for at := uint64(1); at <= version; at += 1 {
		if at%64 == 0 || at == 1 {
			page := at / 64
			if want, ok := pageFirstChains[page]; ok && !bytes.Equal(want, chain[:]) {
				failRef("log page %d's first chain is not C_%d", page, max(page*64, 1)-1)
			}
		}
		if at == firstWindowVersion && !bytes.Equal(head.Head.GetWindowBaseChain(), chain[:]) {
			failRef("window_base_chain is not C_%d", at-1)
		}
		entry := entries[at]
		if entry == nil {
			failRef("version %d has no window entry in the head or a log page", at)
			chainBroken = true
			continue
		}
		storeVersion, err := self.readVersion(repo, refId, at, entry)
		if err != nil {
			failRef("version %d: %v", at, err)
		}
		statementBytes := pageStatements[at]
		if storeVersion != nil {
			if statementBytes != nil && !bytes.Equal(statementBytes, storeVersion.statement.Bytes) {
				failRef("version %d's log page holds another statement than its record", at)
			}
			statementBytes = storeVersion.statement.Bytes
			ref.versions[at-1] = storeVersion
		}
		if statementBytes == nil {
			chainBroken = true
			continue
		}
		statementSha256 := sidecar.EvsStatementSha256(statementBytes)
		if !entry.Names(entry.PushId, statementSha256) {
			failRef("version %d's statement does not hash to its entry's prefix", at)
		}
		if !chainBroken {
			chain = sidecar.EvsChainNext(chain, entry.PushId, statementSha256)
		}
		if lastChain, ok := pageLastChains[at/64]; ok && at%64 == 63 && !chainBroken && !bytes.Equal(lastChain, chain[:]) {
			failRef("log page %d's last chain is not C_%d", at/64, at)
		}
	}
	if !chainBroken && !bytes.Equal(head.Head.GetChain(), chain[:]) {
		failRef("the head's chain is not C_%d through its statements", version)
	}
	if chainBroken {
		ref.complete = false
	}
	return ref
}

// Log page n: log/ on the repo's cluster, else from the pack a pidx/ entry of the ref lists it in.
func (self *evsStoreWalker) logPage(repo *evsStoreRepo, refId sidecar.Id, page uint64) (*protocol.EvsLogPage, error) {
	decode := func(body []byte) (any, error) {
		logPage := &protocol.EvsLogPage{}
		if err := proto.Unmarshal(body, logPage); err != nil {
			return nil, err
		}
		if logPage.GetPage() != page {
			return nil, fmt.Errorf("it holds page %d", logPage.GetPage())
		}
		return logPage, nil
	}
	object, err := self.view.Object(self.ctx, repo.clusterId, evsOracleLogPageKey(repo.repoId, refId, page))
	if err != nil {
		return nil, err
	}
	if object != nil {
		value, err := self.memory.decodedObject(object, decode)
		if err != nil {
			return nil, err
		}
		return value.(*protocol.EvsLogPage), nil
	}
	for attempt := 0; attempt < 2; attempt += 1 {
		entries, err := self.pidx(repo, refId, 0 < attempt)
		if err != nil {
			return nil, err
		}
		for _, read := range entries {
			if read.entry.GetContainerKind() != protocol.EvsContainerKind_EVS_CONTAINER_PACK {
				continue
			}
			for _, held := range read.entry.GetLogPages() {
				if held.GetPage() != page {
					continue
				}
				pageBytes, found, err := self.containerRange(repo, read.entry, held.GetOffset(), uint64(held.GetLength()))
				if err != nil {
					return nil, err
				}
				if !found {
					continue
				}
				value, err := decode(pageBytes)
				if err != nil {
					return nil, fmt.Errorf("in pack %x: %w", read.entry.GetContainerId(), err)
				}
				return value.(*protocol.EvsLogPage), nil
			}
		}
	}
	return nil, errors.New("neither log/ nor a pack a pidx/ entry names holds it")
}

// The ref's pidx/ entries, by one LIST, packs before parcels; relist reads them again.
func (self *evsStoreWalker) pidx(repo *evsStoreRepo, refId sidecar.Id, relist bool) ([]*evsPidxRead, error) {
	cacheKey := repo.repoId.String() + "/" + refId.String()
	if entries, ok := self.pidxEntries[cacheKey]; ok && !relist {
		return entries, nil
	}
	objects, err := self.view.Objects(self.ctx, repo.clusterId, evsOracleRefPrefix("pidx/", repo.repoId, refId))
	if err != nil {
		return nil, err
	}
	entries := []*evsPidxRead{}
	for _, object := range objects {
		value, err := self.memory.decodedObject(object, func(body []byte) (any, error) {
			entry := &protocol.EvsPidxEntry{}
			if err := proto.Unmarshal(body, entry); err != nil {
				return nil, err
			}
			return entry, nil
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", object.Key, err)
		}
		entries = append(entries, &evsPidxRead{key: object.Key, entry: value.(*protocol.EvsPidxEntry)})
	}
	sort.SliceStable(entries, func(i int, j int) bool {
		return entries[i].entry.GetContainerKind() == protocol.EvsContainerKind_EVS_CONTAINER_PACK &&
			entries[j].entry.GetContainerKind() != protocol.EvsContainerKind_EVS_CONTAINER_PACK
	})
	self.pidxEntries[cacheKey] = entries
	return entries, nil
}

// length bytes at offset in the container a pidx/ entry names: a pack on the segment cluster, a parcel on the repo's.
// found is false when the container is gone.
func (self *evsStoreWalker) containerRange(repo *evsStoreRepo, entry *protocol.EvsPidxEntry, offset uint64, length uint64) ([]byte, bool, error) {
	var clusterId string
	var key string
	switch entry.GetContainerKind() {
	case protocol.EvsContainerKind_EVS_CONTAINER_PACK:
		segmentCluster, err := self.view.net.Host().Blobs.SegmentCluster()
		if err != nil {
			return nil, false, err
		}
		clusterId = segmentCluster.ClusterId()
		key = evsOracleRepoPrefix("pack/", repo.repoId) + hex.EncodeToString(entry.GetContainerId())
	case protocol.EvsContainerKind_EVS_CONTAINER_PARCEL:
		clusterId = repo.clusterId
		key = evsOracleRepoPrefix("hp/", repo.repoId) + hex.EncodeToString(entry.GetContainerId())
	default:
		return nil, false, fmt.Errorf("a pidx/ entry of container kind %d", entry.GetContainerKind())
	}
	object, err := self.view.Object(self.ctx, clusterId, key)
	if err != nil || object == nil {
		return nil, false, err
	}
	if uint64(len(object.Body)) < offset+length {
		return nil, false, fmt.Errorf("%s holds %d bytes, short of %d at %d", key, len(object.Body), length, offset)
	}
	return object.Body[offset : offset+length], true, nil
}

// The record bytes at place for a version committed at version: its batch on the repo's cluster, else the container
// a pidx/ entry lists that place in at that version.
func (self *evsStoreWalker) recordAt(repo *evsStoreRepo, refId sidecar.Id, version uint64, place *protocol.EvsPlace) ([]byte, error) {
	batchKey := evsOracleBatchKey(place)
	repo.batchKeys[batchKey] = true
	object, err := self.view.Object(self.ctx, repo.clusterId, batchKey)
	if err != nil {
		return nil, err
	}
	if object != nil {
		end := uint64(place.GetOffset()) + uint64(place.GetLength())
		if uint64(len(object.Body)) < end || place.GetOffset() < sidecar.EvsBatchHeaderByteCount {
			return nil, fmt.Errorf("%s holds no record at %d+%d", batchKey, place.GetOffset(), place.GetLength())
		}
		return object.Body[place.GetOffset():end], nil
	}
	for attempt := 0; attempt < 2; attempt += 1 {
		entries, err := self.pidx(repo, refId, 0 < attempt)
		if err != nil {
			return nil, err
		}
		for _, read := range entries {
			for _, held := range read.entry.GetRecords() {
				if held.GetVersion() != version || !evsOraclePlacesEqual(held.GetPlace(), place) {
					continue
				}
				recordBytes, found, err := self.containerRange(repo, read.entry, held.GetOffset(), uint64(held.GetLength()))
				if err != nil {
					return nil, err
				}
				if found {
					return recordBytes, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("its record at %s is in no batch and in no container a pidx/ entry names", batchKey)
}

// A statement of either format, held to its shape.
func evsOracleParseStatement(statementBytes []byte) (*sidecar.EvsStatement, error) {
	statement, err := sidecar.ParseEvsStatement(statementBytes)
	if errors.Is(err, sidecar.ErrEvsFormatUnsupported) {
		return sidecar.ParseEvsStatementFormat2(statementBytes)
	}
	return statement, err
}

// Version u's statement and payload, from its record at the place its entry names, checked against each other.
func (self *evsStoreWalker) readVersion(repo *evsStoreRepo, refId sidecar.Id, version uint64, entry *sidecar.EvsWindowEntry) (*evsStoreVersion, error) {
	recordBytes, err := self.recordAt(repo, refId, version, entry.Place)
	if err != nil {
		return nil, err
	}
	record, err := sidecar.ParseEvsBatchRecord(recordBytes)
	if err != nil {
		return nil, fmt.Errorf("its record: %w", err)
	}
	if record.RepoId != repo.repoId || record.RefId != refId || record.PushId != entry.PushId {
		return nil, errors.New("its place holds a record of another repo, ref or push")
	}
	var statementBytes []byte
	var payload *sidecar.EvsCheckedPayload
	var statement *sidecar.EvsStatement
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		var payloadBytes []byte
		statementBytes, payloadBytes, err = sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		if statement, err = evsOracleParseStatement(statementBytes); err != nil {
			return nil, err
		}
		if payload, err = sidecar.EvsCheckStoredPayload(statement, payloadBytes); err != nil {
			return nil, fmt.Errorf("its payload: %w", err)
		}
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		var parts []*sidecar.EvsSealPart
		statementBytes, parts, err = sidecar.ParseEvsSealRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		if statement, err = evsOracleParseStatement(statementBytes); err != nil {
			return nil, err
		}
		partBodies := [][]byte{}
		for k, part := range parts {
			partRecordBytes, err := self.recordAt(repo, refId, version, part.Place)
			if err != nil {
				return nil, fmt.Errorf("part %d: %w", k+1, err)
			}
			partRecord, err := sidecar.ParseEvsBatchRecord(partRecordBytes)
			if err != nil {
				return nil, fmt.Errorf("part %d: %w", k+1, err)
			}
			if partRecord.Type != protocol.EvsBatchRecordType_EVS_BATCH_PART || partRecord.PushId != entry.PushId {
				return nil, fmt.Errorf("part %d's place holds another record", k+1)
			}
			partStatement, partBytes, _, _, err := sidecar.ParseEvsPartRecordBody(partRecord.Body)
			if err != nil {
				return nil, fmt.Errorf("part %d: %w", k+1, err)
			}
			if !bytes.Equal(partStatement, statementBytes) {
				return nil, fmt.Errorf("part %d carries another statement", k+1)
			}
			partBodies = append(partBodies, partBytes)
		}
		if payload, _, err = sidecar.EvsCheckStoredSeal(statement, partBodies); err != nil {
			return nil, fmt.Errorf("its parts: %w", err)
		}
	default:
		return nil, fmt.Errorf("its place holds a record of type %d", record.Type)
	}
	if !entry.Names(record.PushId, statement.Sha256) || !bytes.Equal(statement.Push.GetPushId(), record.PushId.Bytes()) {
		return nil, errors.New("its record's statement is not the one its entry names")
	}
	storeVersion := &evsStoreVersion{version: version, entry: entry, statement: statement, payload: payload}
	for _, change := range payload.Changes {
		if !change.WritesEntry() {
			storeVersion.entryVersions = append(storeVersion.entryVersions, nil)
			continue
		}
		entryVersion := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entryVersion); err != nil {
			return nil, fmt.Errorf("an entry version: %w", err)
		}
		storeVersion.entryVersions = append(storeVersion.entryVersions, entryVersion)
	}
	if groupId, err := sidecar.IdFromBytes(statement.Push.GetGroupId()); err == nil {
		repo.groupIds[groupId] = true
	}
	// the slots this push introduced, with their bodies, in the order its kind-3 items list them
	slotIndex := 0
	for _, newObject := range payload.NewObjects {
		if newObject.Kind != protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
			continue
		}
		if slotIndex < len(payload.SlotBodies) {
			body, err := sidecar.EvsDecodeSlotObject(payload.SlotBodies[slotIndex])
			if err == nil {
				repo.slotIntroductions[hex.EncodeToString(newObject.Id)] = &evsSlotIntroduction{version: version, refId: refId, body: body}
			}
		}
		slotIndex += 1
	}
	return storeVersion, nil
}

// The keys a committed, authorized ERASE destroyed in a repo, "<slot id hex>/<key index>", and every ERASE the walk
// found that its authority does not hold, as violations of their own.
func fi1ErasedKeys(repo *evsStoreRepo, view sidecar.GkmAuthView) (map[string]bool, []error) {
	erased := map[string]bool{}
	errs := []error{}
	for _, ref := range repo.refs {
		for _, version := range ref.versions {
			if version == nil || version.statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) == 0 {
				continue
			}
			if err := fi1EraseAuthority(view, repo, ref, version.statement); err != nil {
				errs = append(errs, fmt.Errorf("repo %s ref %s: the ERASE at %d is not authorized, so it excuses nothing: %w", repo.repoId, ref.refId, version.version, err))
				continue
			}
			for _, key := range version.payload.Erased {
				erased[fmt.Sprintf("%x/%d", key.SlotId[:], key.KeyIndex)] = true
			}
		}
	}
	return erased, errs
}

// Whether an ERASE's authority holds as a reader judges it (§11.8's refs table, §11.12): its signer admitted with
// the key that signed it at its own auth pin, and there a repo admin on the repo's erasure ref, or the owner of a
// record-class owned ref.
func fi1EraseAuthority(view sidecar.GkmAuthView, repo *evsStoreRepo, ref *evsStoreRef, statement *sidecar.EvsStatement) error {
	if view == nil {
		return errors.New("no authorization view is named for the repo's network")
	}
	push := statement.Push
	state, err := view.At(push.GetAuth())
	if err != nil {
		return fmt.Errorf("its auth pin: %w", err)
	}
	signerId, err := sidecar.IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return errors.New("it names no signer")
	}
	identityKey := state.IdentityKey(signerId)
	if len(identityKey) == 0 {
		return errors.New("its signer was never admitted")
	}
	if err := statement.Verify(identityKey); err != nil {
		return fmt.Errorf("its signature: %w", err)
	}
	aclRepo := state.Repo(repo.repoId)
	if aclRepo == nil {
		return errors.New("the state holds no such repo")
	}
	switch protocol.EvsRefKind(push.GetRefKind()) {
	case protocol.EvsRefKind_EVS_REF_ERASURE:
		if sidecar.EvsErasureRefId(repo.repoId) != ref.refId {
			return errors.New("an erasure ref at another id")
		}
		for _, admin := range aclRepo.GetAdmins() {
			if sidecar.AclRepoAdminStands(admin) && bytes.Equal(admin.GetSidecarId(), signerId.Bytes()) {
				return nil
			}
		}
		return errors.New("its signer is no repo admin at its pin")
	case protocol.EvsRefKind_EVS_REF_OWNED:
		if sidecar.EvsRepoKindRecordClass(aclRepo.GetKind()) && bytes.Equal(push.GetOwnerSidecarId(), signerId.Bytes()) &&
			slices.Contains(state.RepoWriters(repo.repoId), signerId) {
			return nil
		}
		return errors.New("an owned ref's ERASE not by its writing owner in a record-class repo")
	}
	return fmt.Errorf("an ERASE on a ref of kind %d", push.GetRefKind())
}

// Whether the repo's shred is authorized: repo/ shredding or shredded under the deletion id of the access log's
// newest RepoDelete, not restored. An authorized shred excuses the repo's whole closure (§11.12's phases).
func fi1ShredAuthorized(repo *evsStoreRepo, view sidecar.GkmAuthView) (bool, error) {
	if repo.object == nil {
		return false, nil
	}
	switch repo.object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_SHREDDING, protocol.EvsRepoState_EVS_REPO_SHREDDED:
	default:
		return false, nil
	}
	if view == nil {
		return false, errors.New("repo/ shows a shred and no authorization view is named for its network")
	}
	aclRepo := view.Repo(repo.repoId)
	deletion := aclRepo.GetDeletion()
	if aclRepo == nil || deletion == nil || len(deletion.GetDeletionId()) == 0 {
		return false, errors.New("repo/ shows a shred the access log holds no RepoDelete for")
	}
	if !bytes.Equal(deletion.GetDeletionId(), repo.object.GetDeletionId()) {
		return false, errors.New("repo/ shows a shred under another deletion id than the access log's RepoDelete")
	}
	if deletion.GetRestoredAt() != 0 {
		return false, errors.New("repo/ shows a shred of a deletion the access log restored")
	}
	return true, nil
}

func (self *evsStoreRepo) networkId() sidecar.Id {
	if self.object == nil {
		return sidecar.Id{}
	}
	networkId, _ := sidecar.IdFromBytes(self.object.GetNetworkId())
	return networkId
}

func checkFi1(ctx context.Context, oracle *Oracle) error {
	repos, errs := evsStoreWalkOf(ctx, oracle)
	memory := evsOracleMemoryOf(oracle.Net)
	segmentCluster, err := oracle.Net.Host().Blobs.SegmentCluster()
	if err != nil {
		return err
	}
	for _, repo := range repos {
		if repo.walkedBy != oracle {
			// nothing it reads changed since the check that walked it, whose clauses held
			continue
		}
		view := memory.authorizationView(repo.networkId())
		shredded, err := fi1ShredAuthorized(repo, view)
		if err != nil {
			errs = append(errs, fmt.Errorf("repo %s: %w", repo.repoId, err))
		}
		if shredded {
			continue
		}
		errs = append(errs, repo.missing...)
		erased, eraseErrs := fi1ErasedKeys(repo, view)
		errs = append(errs, eraseErrs...)
		errs = append(errs, fi1CheckContent(ctx, oracle, repo, segmentCluster.ClusterId(), erased)...)
		errs = append(errs, fi1CheckMaps(ctx, oracle, repo)...)
		errs = append(errs, fi1CheckGenerations(ctx, oracle, memory, repo)...)
		errs = append(errs, fi1CheckDecrypt(ctx, oracle, repo, erased)...)
	}
	errs = append(errs, fi1CheckHeadsStay(memory, repos)...)
	return errors.Join(errs...)
}

// Every committed entry version's segments and slots are stored, and each slot keeps the keys its introducing push
// gave it but what an authorized ERASE destroyed.
func fi1CheckContent(ctx context.Context, oracle *Oracle, repo *evsStoreRepo, segmentClusterId string, erased map[string]bool) []error {
	errs := []error{}
	checkedSlots := map[string]bool{}
	for _, ref := range repo.refs {
		for _, version := range ref.versions {
			if version == nil {
				continue
			}
			for i, entryVersion := range version.entryVersions {
				if entryVersion == nil {
					continue
				}
				path := version.payload.Changes[i].TokenPath
				for _, locator := range entryVersion.GetChain() {
					switch protocol.EvsLocatorKind(locator.GetKind()) {
					case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT, protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
						if locator.GetStaged() {
							continue
						}
						key := evsOracleSegmentKey(repo.repoId, locator.GetId())
						if repo.segmentInfos[key] == nil {
							errs = append(errs, fmt.Errorf("repo %s ref %s: version %d of %s names %s, which %s does not hold", repo.repoId, ref.refId, version.version, path.KeyString(), key, segmentClusterId))
						}
					case protocol.EvsLocatorKind_EVS_LOCATOR_INLINE:
						if len(locator.GetInline()) == 0 {
							errs = append(errs, fmt.Errorf("repo %s ref %s: version %d of %s has an empty inline record", repo.repoId, ref.refId, version.version, path.KeyString()))
						}
					}
				}
				for _, slotId := range entryVersion.GetSlotIds() {
					slotHex := hex.EncodeToString(slotId)
					if checkedSlots[slotHex] {
						continue
					}
					checkedSlots[slotHex] = true
					errs = append(errs, fi1CheckSlot(ctx, oracle, repo, slotId, erased)...)
				}
			}
		}
	}
	return errs
}

func fi1CheckSlot(ctx context.Context, oracle *Oracle, repo *evsStoreRepo, slotId []byte, erased map[string]bool) []error {
	key := evsOracleSlotKey(repo.repoId, slotId)
	introduction := repo.slotIntroductions[hex.EncodeToString(slotId)]
	if repo.slotInfos[key] != nil && introduction == nil {
		// a slot no committed push in the walk introduced: its presence is all that is known of it
		return nil
	}
	// read by its key, so a slot the LIST left out is gone only when its key holds nothing: an ERASE rewrites a slot in
	// place, and a LIST can leave out a key whose overwrite is in flight (walkRepo)
	object, err := oracle.View.Object(ctx, repo.clusterId, key)
	if err != nil {
		return []error{err}
	}
	if object == nil {
		return []error{fmt.Errorf("repo %s: %s, which a committed version names, is gone", repo.repoId, key)}
	}
	if introduction == nil {
		return nil
	}
	slot, err := sidecar.EvsDecodeSlotObject(object.Body)
	if err != nil {
		return []error{fmt.Errorf("repo %s: %s: %w", repo.repoId, key, err)}
	}
	errs := []error{}
	for _, introduced := range introduction.body.GetKeys() {
		if _, ok := sidecar.EvsSlotKeyAt(slot, introduced.GetKeyIndex()); ok {
			continue
		}
		if erased[fmt.Sprintf("%x/%d", slotId, introduced.GetKeyIndex())] {
			continue
		}
		errs = append(errs, fmt.Errorf("repo %s: %s lost key %d, which no authorized, committed ERASE names", repo.repoId, key, introduced.GetKeyIndex()))
	}
	return errs
}

// Every committed PATH_EPOCH's map: its parts under pmap/, numbered 1 to their count, hashing to path_map_sha256.
func fi1CheckMaps(ctx context.Context, oracle *Oracle, repo *evsStoreRepo) []error {
	errs := []error{}
	memory := evsOracleMemoryOf(oracle.Net)
	for _, ref := range repo.refs {
		for _, version := range ref.versions {
			if version == nil || version.statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) == 0 {
				continue
			}
			push := version.statement.Push
			if _, err := fi1MapMoves(ctx, oracle.View, memory, repo, ref.refId, push.GetPathEpoch(), push.GetPathMapSha256()); err != nil {
				errs = append(errs, fmt.Errorf("repo %s ref %s: the PATH_EPOCH at %d: %w", repo.repoId, ref.refId, version.version, err))
			}
		}
	}
	return errs
}

// A committed map's moves, every part read and the parts' hash checked.
func fi1MapMoves(ctx context.Context, view *StoreView, memory *evsOracleMemory, repo *evsStoreRepo, refId sidecar.Id, epoch uint64, mapSha256 []byte) ([]*protocol.EvsPathMove, error) {
	objects, err := view.Objects(ctx, repo.clusterId, evsOracleMapPrefix(repo.repoId, refId, epoch, mapSha256))
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return nil, errors.New("its map has no part under pmap/")
	}
	partBodies := [][]byte{}
	moves := []*protocol.EvsPathMove{}
	for i, object := range objects {
		value, err := memory.decodedObject(object, func(body []byte) (any, error) {
			_, pathMap, err := sidecar.ParseEvsPathMap(body)
			return pathMap, err
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", object.Key, err)
		}
		pathMap := value.(*protocol.EvsPathMap)
		if pathMap.GetPart() != uint32(i+1) || pathMap.GetParts() != uint32(len(objects)) {
			return nil, fmt.Errorf("its parts under pmap/ are %d where part %d of %d is", len(objects), pathMap.GetPart(), pathMap.GetParts())
		}
		partBodies = append(partBodies, object.Body)
		moves = append(moves, pathMap.GetMoves()...)
	}
	if !bytes.Equal(sidecar.EvsPathMapSha256(partBodies), mapSha256) {
		return nil, errors.New("its parts do not hash to path_map_sha256")
	}
	return moves, nil
}

// Every generation a committed statement or a head pins is gen/<g> with the commitment pinned, the ladder below the
// newest is whole, and a wrap of a group's newest generation, once seen, stays while that generation is the newest.
func fi1CheckGenerations(ctx context.Context, oracle *Oracle, memory *evsOracleMemory, repo *evsStoreRepo) []error {
	errs := []error{}
	pins := map[sidecar.Id]map[uint64][]byte{}
	pin := func(groupBytes []byte, generation uint64, commitment []byte) {
		groupId, err := sidecar.IdFromBytes(groupBytes)
		if err != nil || generation == 0 {
			return
		}
		if pins[groupId] == nil {
			pins[groupId] = map[uint64][]byte{}
		}
		pins[groupId][generation] = commitment
	}
	for _, ref := range repo.refs {
		if 0 < ref.head.Head.GetVersion() {
			pin(ref.head.Head.GetGroupId(), ref.head.Head.GetGeneration(), ref.head.Head.GetGenerationCommitment())
		}
		for _, version := range ref.versions {
			if version != nil {
				push := version.statement.Push
				pin(push.GetGroupId(), push.GetGeneration(), push.GetGenerationCommitment())
			}
		}
	}
	for groupId, generationCommitments := range pins {
		ladder, err := oracle.View.Generations(ctx, groupId)
		if err != nil {
			errs = append(errs, fmt.Errorf("repo %s: group %s's generations: %w", repo.repoId, groupId, err))
			continue
		}
		byGeneration := map[uint64]*sidecar.GkmGeneration{}
		newest := uint64(0)
		for _, generation := range ladder {
			byGeneration[generation.Rotate.GetGeneration()] = generation
			newest = max(newest, generation.Rotate.GetGeneration())
		}
		for g := uint64(1); g <= newest; g += 1 {
			if byGeneration[g] == nil {
				errs = append(errs, fmt.Errorf("repo %s: gen/%d of group %s is gone below gen/%d", repo.repoId, g, groupId, newest))
			}
		}
		for g, commitment := range generationCommitments {
			generation := byGeneration[g]
			if generation == nil {
				errs = append(errs, fmt.Errorf("repo %s: gen/%d of group %s, which a committed statement pins, is not stored", repo.repoId, g, groupId))
				continue
			}
			if !bytes.Equal(generation.Rotate.GetCommitment(), commitment) {
				errs = append(errs, fmt.Errorf("repo %s: gen/%d of group %s holds another commitment than a committed statement pins", repo.repoId, g, groupId))
			}
		}
		if generation := byGeneration[newest]; generation != nil {
			errs = append(errs, fi1CheckWraps(ctx, oracle, memory, repo, groupId, newest, generation.Rotate.GetCommitment())...)
		}
	}
	return errs
}

func fi1CheckWraps(ctx context.Context, oracle *Oracle, memory *evsOracleMemory, repo *evsStoreRepo, groupId sidecar.Id, newest uint64, commitment []byte) []error {
	firstClusterId, err := oracle.View.FirstClusterId()
	if err != nil {
		return []error{err}
	}
	if len(commitment) < 8 {
		return []error{fmt.Errorf("repo %s: gen/%d of group %s has a commitment of %d bytes", repo.repoId, newest, groupId, len(commitment))}
	}
	prefix := "gkm/" + sidecar.EvsKeyId(groupId) + "/wrap/" + evsOracleNumber(newest) + "/" + hex.EncodeToString(commitment[:8]) + "/"
	infos, err := oracle.View.List(ctx, firstClusterId, prefix)
	if err != nil {
		return []error{err}
	}
	present := map[string]bool{}
	for _, info := range infos {
		present[info.Key] = true
	}
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	errs := []error{}
	if memory.newestGenerations[groupId] == newest {
		for key := range memory.newestWraps[groupId] {
			if !present[key] {
				errs = append(errs, fmt.Errorf("repo %s: %s, a wrap of its group's newest generation, is gone while gen/%d is newest", repo.repoId, key, newest))
			}
		}
	}
	memory.newestGenerations[groupId] = newest
	memory.newestWraps[groupId] = present
	return errs
}

// Every head seen stays, at no lower version, unless its repo's shred is authorized.
func fi1CheckHeadsStay(memory *evsOracleMemory, repos []*evsStoreRepo) []error {
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	errs := []error{}
	current := map[string]uint64{}
	shredded := map[string]bool{}
	for _, repo := range repos {
		repoShredded, _ := fi1ShredAuthorized(repo, memory.authorizationViews[repo.networkId()])
		for _, ref := range repo.refs {
			key := repo.repoId.String() + "/" + ref.refId.String()
			current[key] = ref.head.Head.GetVersion()
			shredded[key] = repoShredded
		}
		if repoShredded {
			for key := range memory.headVersions {
				if strings.HasPrefix(key, repo.repoId.String()+"/") {
					shredded[key] = true
				}
			}
		}
	}
	for key, seen := range memory.headVersions {
		if shredded[key] {
			continue
		}
		version, ok := current[key]
		switch {
		case !ok && 0 < seen:
			errs = append(errs, fmt.Errorf("ref %s: its head at version %d is gone", key, seen))
		case ok && version < seen:
			errs = append(errs, fmt.Errorf("ref %s: its head fell from version %d to %d", key, seen, version))
		}
	}
	for key, version := range current {
		memory.headVersions[key] = max(memory.headVersions[key], version)
	}
	return errs
}

// A reader's keys for one group, opened down its ladder as a current reader opens them.
type fi1Keys struct {
	view      *StoreView
	reader    string
	ladder    []*sidecar.GkmGeneration
	manifests map[uint64]*sidecar.EvsManifestKey
	feks      map[uint64]*sidecar.EvsFekKey
}

func (self *fi1Keys) open(generation uint64) (*sidecar.EvsManifestKey, *sidecar.EvsFekKey, error) {
	if manifest, ok := self.manifests[generation]; ok {
		return manifest, self.feks[generation], nil
	}
	repoKey, err := self.view.Open(self.reader, self.ladder, generation)
	if err != nil {
		return nil, nil, err
	}
	manifest, err := sidecar.NewEvsManifestKey(repoKey)
	if err != nil {
		return nil, nil, err
	}
	fek, err := sidecar.NewEvsFekKey(repoKey)
	if err != nil {
		return nil, nil, err
	}
	self.manifests[generation] = manifest
	self.feks[generation] = fek
	return manifest, fek, nil
}

// The repo's current reader for a group, "" with no error when no named actor holds any of its keys, which leaves the
// decrypt clause unrun.
func fi1CurrentReader(oracle *Oracle, ladder []*sidecar.GkmGeneration) (string, error) {
	newest := uint64(0)
	for _, generation := range ladder {
		newest = max(newest, generation.Rotate.GetGeneration())
	}
	if newest == 0 {
		return "", errors.New("its group has no generation")
	}
	holdsAny := false
	for _, actor := range oracle.View.HeldSecrets().Actors() {
		if actor == "" {
			// what an oracle's own opens and unattributed goroutines derived, no reader's
			continue
		}
		if _, err := oracle.View.Open(actor, ladder, newest); err == nil {
			return actor, nil
		}
		for g := uint64(1); g < newest; g += 1 {
			if _, err := oracle.View.Open(actor, ladder, g); err == nil {
				holdsAny = true
				break
			}
		}
	}
	if holdsAny {
		return "", fmt.Errorf("no named actor that held its keys opens gen/%d, the newest", newest)
	}
	return "", nil
}

// Where a current reader's keys exist, every committed file version decrypts for it.
func fi1CheckDecrypt(ctx context.Context, oracle *Oracle, repo *evsStoreRepo, erased map[string]bool) []error {
	if !sidecartest.HooksLinked {
		return nil
	}
	errs := []error{}
	keysByGroup := map[sidecar.Id]*fi1Keys{}
	keysOf := func(groupBytes []byte) (*fi1Keys, error) {
		groupId, err := sidecar.IdFromBytes(groupBytes)
		if err != nil {
			return nil, errors.New("a statement names no group")
		}
		if keys, ok := keysByGroup[groupId]; ok {
			return keys, nil
		}
		ladder, err := oracle.View.Generations(ctx, groupId)
		if err != nil {
			return nil, err
		}
		reader, err := fi1CurrentReader(oracle, ladder)
		if err != nil {
			return nil, err
		}
		if reader == "" {
			keysByGroup[groupId] = nil
			return nil, nil
		}
		keys := &fi1Keys{view: oracle.View, reader: reader, ladder: ladder, manifests: map[uint64]*sidecar.EvsManifestKey{}, feks: map[uint64]*sidecar.EvsFekKey{}}
		keysByGroup[groupId] = keys
		return keys, nil
	}
	for _, ref := range repo.refs {
		if protocol.EvsRefKind(ref.head.Head.GetRefKind()) == protocol.EvsRefKind_EVS_REF_DEPOSIT {
			// a deposit opens under its drop key's K_dep, which this clause does not derive yet
			continue
		}
		for _, version := range ref.versions {
			if version == nil {
				continue
			}
			push := version.statement.Push
			keys, err := keysOf(push.GetGroupId())
			if err != nil {
				errs = append(errs, fmt.Errorf("repo %s ref %s: version %d: %w", repo.repoId, ref.refId, version.version, err))
				continue
			}
			if keys == nil {
				continue
			}
			manifest, fek, err := keys.open(push.GetGeneration())
			if err != nil {
				errs = append(errs, fmt.Errorf("repo %s ref %s: version %d: %s cannot open gen/%d: %w", repo.repoId, ref.refId, version.version, keys.reader, push.GetGeneration(), err))
				continue
			}
			if metadata := version.payload.SealedMetadata; len(metadata) != 0 {
				if _, err := sidecar.EvsOpenMetadata(manifest, metadata); err != nil {
					errs = append(errs, fmt.Errorf("repo %s ref %s: version %d's sealed metadata does not open for %s: %w", repo.repoId, ref.refId, version.version, keys.reader, err))
				}
			}
			for i, entryVersion := range version.entryVersions {
				if entryVersion == nil || protocol.EvsEntryKind(entryVersion.GetKind()) != protocol.EvsEntryKind_EVS_ENTRY_FILE {
					continue
				}
				if err := fi1DecryptFile(ctx, oracle, repo, keys, manifest, fek, entryVersion, erased); err != nil {
					errs = append(errs, fmt.Errorf("repo %s ref %s: version %d of %s does not decrypt for %s: %w", repo.repoId, ref.refId, version.version, version.payload.Changes[i].TokenPath.KeyString(), keys.reader, err))
				}
			}
		}
	}
	return errs
}

// A file version's sealed fields and every record of its chain, each header opened and every frame read.
func fi1DecryptFile(ctx context.Context, oracle *Oracle, repo *evsStoreRepo, keys *fi1Keys, manifest *sidecar.EvsManifestKey, fek *sidecar.EvsFekKey, entryVersion *protocol.EvsEntryVersion, erased map[string]bool) error {
	fields, err := sidecar.EvsOpenFields(manifest, entryVersion.GetSealedFields())
	if err != nil {
		return fmt.Errorf("its sealed fields: %w", err)
	}
	fileId, err := sidecar.IdFromBytes(fields.GetFileId())
	if err != nil {
		return errors.New("its sealed fields name no file id")
	}
	segmentCluster, err := oracle.Net.Host().Blobs.SegmentCluster()
	if err != nil {
		return err
	}
	var chainKey *sidecar.EvsObjectKey
	for index, locator := range entryVersion.GetChain() {
		switch protocol.EvsLocatorKind(locator.GetKind()) {
		case protocol.EvsLocatorKind_EVS_LOCATOR_INLINE:
			var inlineFek *sidecar.EvsFekKey
			if index == 0 || chainKey == nil {
				inlineFek = fek
				chainKey = nil
			}
			_, _, objectKey, err := sidecar.EvsOpenInlineRecord(manifest, inlineFek, chainKey, fileId, locator.GetInline())
			if err != nil {
				return fmt.Errorf("its inline record %d: %w", index, err)
			}
			chainKey = objectKey
		case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
			object, err := oracle.View.Object(ctx, segmentCluster.ClusterId(), evsOracleSegmentKey(repo.repoId, locator.GetId()))
			if err != nil {
				return err
			}
			if object == nil {
				return fmt.Errorf("segment %x is gone", locator.GetId())
			}
			skipped, err := fi1DecryptSegmentRecord(ctx, oracle, repo, keys, object.Body, locator, fileId, erased)
			if err != nil {
				return fmt.Errorf("its record %d in segment %x: %w", index, locator.GetId(), err)
			}
			if skipped {
				// an authorized ERASE destroyed its key: the rest of the chain is that erasure's too
				return nil
			}
		default:
			// a kind-5 segment is format 2's, whose decrypt clause is TEST-M10-01's
			return nil
		}
	}
	return nil
}

// One segment record opened as a current reader opens it; skipped when an authorized ERASE took its slot key.
func fi1DecryptSegmentRecord(ctx context.Context, oracle *Oracle, repo *evsStoreRepo, keys *fi1Keys, segment []byte, locator *protocol.EvsLocator, fileId sidecar.Id, erased map[string]bool) (bool, error) {
	if len(segment) < sidecar.EvsSegmentHeaderByteCount {
		return false, errors.New("a segment shorter than its header")
	}
	segmentHeader, err := sidecar.ParseEvsSegmentHeader(segment[:sidecar.EvsSegmentHeaderByteCount])
	if err != nil {
		return false, err
	}
	if segmentHeader.RepoId != repo.repoId {
		return false, errors.New("a segment of another repo")
	}
	end := uint64(locator.GetOffset()) + uint64(locator.GetLength())
	if uint64(len(segment)) < end || locator.GetLength() < sidecar.EvsRecordHeaderByteCount {
		return false, errors.New("a locator past its segment's bytes")
	}
	recordBytes := segment[locator.GetOffset():end]
	manifest, fek, err := keys.open(segmentHeader.Generation)
	if err != nil {
		return false, fmt.Errorf("gen/%d, its segment's: %w", segmentHeader.Generation, err)
	}
	header, err := sidecar.EvsOpenRecordHeader(manifest, recordBytes[:sidecar.EvsRecordHeaderByteCount])
	if err != nil {
		return false, err
	}
	if sidecar.EvsRecordByteCount(header.BodyLength) != uint64(locator.GetLength()) {
		return false, errors.New("a record whose length is not its locator's")
	}
	var objectKey *sidecar.EvsObjectKey
	switch header.KeyRefKind {
	case protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER:
		keyedEnd := sidecar.EvsSegmentHeaderByteCount + sidecar.EvsWrappedKeyByteCount
		if len(segment) < keyedEnd {
			return false, errors.New("a segment with no key block")
		}
		if objectKey, err = sidecar.EvsUnwrapObjectKey(fek, segment[sidecar.EvsSegmentHeaderByteCount:keyedEnd]); err != nil {
			return false, err
		}
	default:
		slotKeyName := evsOracleSlotKey(repo.repoId, header.SlotId.Bytes())
		object, err := oracle.View.Object(ctx, repo.clusterId, slotKeyName)
		if err != nil {
			return false, err
		}
		if object == nil {
			return false, fmt.Errorf("%s is gone", slotKeyName)
		}
		slot, err := sidecar.EvsDecodeSlotObject(object.Body)
		if err != nil {
			return false, err
		}
		slotKey, ok := sidecar.EvsSlotKeyAt(slot, uint32(header.KeyIndex))
		if !ok {
			if erased[fmt.Sprintf("%x/%d", header.SlotId[:], header.KeyIndex)] {
				return true, nil
			}
			return false, fmt.Errorf("%s holds no key %d, and no authorized ERASE took it", slotKeyName, header.KeyIndex)
		}
		_, slotFek, err := keys.open(slotKey.GetGeneration())
		if err != nil {
			return false, err
		}
		if objectKey, err = sidecar.EvsOpenSlotKey(slotFek, slotKey); err != nil {
			return false, err
		}
	}
	reader := sidecar.NewEvsRecordReader()
	if err := reader.Begin(bytes.NewReader(recordBytes[sidecar.EvsRecordHeaderByteCount:]), header, objectKey, repo.repoId, fileId); err != nil {
		return false, err
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return false, err
	}
	return false, nil
}
