//go:build !sidecar_http && !ios_extension

// RECORD-M10-05's format 2 half of the directory's erasure, on sidecartest's fakes with a model of evs's part of it:
// FS-87's index case, after a directory admin's erasure of an announcement no stored card or index version holding it
// has a readable key; a revoke seeded with cards and index documents, the repo file's versions below the marker and a
// run's card rewritten under fresh keys once its writer wrote the run private, a later-signed card naming the repo
// caught at a later sync, and nothing sent twice; FS-99's cards and index case, a CUT, a CLOSURE and an ERASE below
// admin refused before any rewrite; a kill between a CLOSURE and its ERASE resumed from evs's state by another
// device; and two runners racing, one CLOSURE committing.
//
// The model (testErasureEvs) stands in for evs's eraser routes over the cards ref and for the index's erasers: a
// path's versions share one key until a CLOSURE draws another, a removal ends a key's life, and an ERASE destroys the
// keys it names. The world's cards are held as under a preservation hold, so every version a path ever had stays
// stored. The real routes and the index's own erasers run in RECORD-M10-06's schedules.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One CLOSURE or ERASE the model took.
type testErasurePush struct {
	erasureId sidecar.Id
	signerId  sidecar.Id
	// a CLOSURE's path, on the cards ref or an index file's name
	path     string
	keys     []sidecar.EvsErasedKey
	complete bool
	note     []byte
}

// evs's part of a format 2 erasure over the world's cards ref, and its two index refs.
type testErasureEvs struct {
	world *testDirectoryWorld

	stateLock sync.Mutex
	// whom evs mints admin
	admins map[sidecar.Id]bool
	// each path's versions a CLOSURE wrote, where a new key's life begins
	closedVersions map[string][]uint64
	closures       []*testErasurePush
	erases         []*testErasurePush
	erased         map[sidecar.EvsErasedKey]bool
	// ERASEs of the cards ref's keys to fail, as a kill between a CLOSURE and its ERASE
	failEraseCount int
	// calls refused below admin
	refusedCount int
	// every push taken, in order, by kind and ref
	order []string

	cardsIndex   *testErasureIndex
	streamsIndex *testErasureIndex
}

func newTestErasureEvs(world *testDirectoryWorld) *testErasureEvs {
	evs := &testErasureEvs{world: world, admins: map[sidecar.Id]bool{}, closedVersions: map[string][]uint64{}, erased: map[sidecar.EvsErasedKey]bool{}}
	evs.cardsIndex = newTestErasureIndex(evs, "cards")
	evs.streamsIndex = newTestErasureIndex(evs, "ur/index")
	return evs
}

// A world whose cards ref keeps every version, as under a preservation hold, at format 2.
func newTestErasureWorld(t *testing.T) (*testDirectoryWorld, *testErasureEvs) {
	t.Helper()
	settings := sidecartest.DefaultFakeDirectoryCardsSettings()
	settings.PurgeDelay = 1000 * 24 * time.Hour
	world := newTestDirectoryWorld(t, settings)
	return world, newTestErasureEvs(world)
}

// A directory admin's device that evs mints admin to, its erasers bound.
func (self *testErasureEvs) adminDevice(t *testing.T) *testDirectoryDevice {
	t.Helper()
	device := self.world.adminDevice()
	self.admit(device)
	return device
}

// Mints device admin at evs and binds its erasers.
func (self *testErasureEvs) admit(device *testDirectoryDevice) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.admins[device.writer.sidecarId] = true
	}()
	self.bind(device)
}

// Binds device's erasers, whatever evs mints it.
func (self *testErasureEvs) bind(device *testDirectoryDevice) {
	device.client.BindEraser(device.record.Eraser().Erase)
	device.client.BindErasureFiles(&testErasureClient{evs: self, sidecarId: device.writer.sidecarId})
}

// The refusal evs gives a caller below admin, counted.
func (self *testErasureEvs) checkAdmin(sidecarId sidecar.Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.admins[sidecarId] {
		self.refusedCount += 1
		return &sidecar.RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE}
	}
	return nil
}

// The key of a path's life.
func testErasureKey(path string, life int) sidecar.EvsErasedKey {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s#%d", path, life)))
	return sidecar.EvsErasedKey{SlotId: sidecar.Id(sum[:16])}
}

// One stored version of a cards ref path with the key that opens it.
type testErasureVersion struct {
	path    string
	version uint64
	content []byte
	key     sidecar.EvsErasedKey
}

// Every version the cards ref ever stored of its d/ and r/ paths, each with its key: a path's versions share a key
// until a CLOSURE's version or a creation after a removal draws another.
func (self *testErasureEvs) storedVersions(t testing.TB) []*testErasureVersion {
	t.Helper()
	changes, err := self.world.cards.For(self.world.readerId).ReadCards(context.Background(), self.world.directoryId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if changes.More {
		t.Fatal("the model reads the cards ref in one page")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lives := map[string]int{}
	removed := map[string]bool{}
	stored := []*testErasureVersion{}
	for _, file := range changes.Files {
		if !strings.HasPrefix(file.Path, "d/") && !strings.HasPrefix(file.Path, "r/") {
			continue
		}
		if file.Removed {
			removed[file.Path] = true
			continue
		}
		if removed[file.Path] || slices.Contains(self.closedVersions[file.Path], file.Version) {
			lives[file.Path] += 1
			removed[file.Path] = false
		}
		stored = append(stored, &testErasureVersion{path: file.Path, version: file.Version, content: file.Content, key: testErasureKey(file.Path, lives[file.Path])})
	}
	return stored
}

// The stored card and repo file versions holding text whose key still stands, as path@version.
func (self *testErasureEvs) readable(t testing.TB, text string) []string {
	t.Helper()
	stored := self.storedVersions(t)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	readable := []string{}
	for _, version := range stored {
		if bytes.Contains(version.content, []byte(text)) && !self.erased[version.key] {
			readable = append(readable, fmt.Sprintf("%s@%d", version.path, version.version))
		}
	}
	return readable
}

// The stored versions holding text, readable or not.
func (self *testErasureEvs) holding(t testing.TB, text string) int {
	t.Helper()
	count := 0
	for _, version := range self.storedVersions(t) {
		if bytes.Contains(version.content, []byte(text)) {
			count += 1
		}
	}
	return count
}

// The pushes taken, by kind.
func (self *testErasureEvs) counts() (closures int, erases int, cuts int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.closures) + len(self.cardsIndex.closures) + len(self.streamsIndex.closures),
		len(self.erases) + len(self.cardsIndex.erases) + len(self.streamsIndex.erases),
		self.cardsIndex.cutCount + self.streamsIndex.cutCount
}

// The cards ref's CLOSUREs taken.
func (self *testErasureEvs) cardClosures() []*testErasurePush {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.closures)
}

// Every ERASE taken, the cards ref's and the index refs'.
func (self *testErasureEvs) allErases() []*testErasurePush {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Concat(self.erases, self.cardsIndex.erases, self.streamsIndex.erases)
}

// One sidecar's reach into the model: sidecar.DirectoryErasureFiles.
type testErasureClient struct {
	evs       *testErasureEvs
	sidecarId sidecar.Id
}

var _ sidecar.DirectoryErasureFiles = (*testErasureClient)(nil)

func (self *testErasureClient) CardsIndex(ctx context.Context, repoId sidecar.Id) (sidecar.DirectoryErasureIndex, error) {
	return &testErasureIndexClient{index: self.evs.cardsIndex, sidecarId: self.sidecarId}, nil
}

func (self *testErasureClient) StreamsIndex(ctx context.Context, repoId sidecar.Id) (sidecar.DirectoryErasureIndex, error) {
	return &testErasureIndexClient{index: self.evs.streamsIndex, sidecarId: self.sidecarId}, nil
}

func (self *testErasureClient) CardKeys(ctx context.Context, repoId sidecar.Id, paths []string) ([]*sidecar.EvsErasedKey, error) {
	keys := []*sidecar.EvsErasedKey{}
	named := map[sidecar.EvsErasedKey]bool{}
	for _, version := range self.evs.storedVersions(self.evs.world.t) {
		if slices.Contains(paths, version.path) && !named[version.key] {
			named[version.key] = true
			key := version.key
			keys = append(keys, &key)
		}
	}
	return keys, nil
}

func (self *testErasureClient) CloseCard(ctx context.Context, repoId sidecar.Id, erasureId sidecar.Id, write *sidecar.DirectoryCardWrite, keys []*sidecar.EvsErasedKey) (uint64, error) {
	if err := self.evs.checkAdmin(self.sidecarId); err != nil {
		return 0, err
	}
	// evs takes a CLOSURE only if its list names every slot the versions it replaces name
	owed, _ := self.CardKeys(ctx, repoId, []string{write.Path})
	for _, key := range owed {
		if !slices.ContainsFunc(keys, func(listed *sidecar.EvsErasedKey) bool { return *listed == *key }) {
			return 0, &sidecar.RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID}
		}
	}
	version, err := self.evs.world.cards.For(self.sidecarId).PutCard(ctx, repoId, write)
	if err != nil {
		return 0, err
	}
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	self.evs.closedVersions[write.Path] = append(self.evs.closedVersions[write.Path], version)
	push := &testErasurePush{erasureId: erasureId, signerId: self.sidecarId, path: write.Path}
	for _, key := range keys {
		push.keys = append(push.keys, *key)
	}
	self.evs.closures = append(self.evs.closures, push)
	self.evs.order = append(self.evs.order, "closure:cards")
	return version, nil
}

func (self *testErasureClient) EraseCardKeys(ctx context.Context, repoId sidecar.Id, args *sidecar.EvsEraseArgs) error {
	if err := self.evs.checkAdmin(self.sidecarId); err != nil {
		return err
	}
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	if 0 < self.evs.failEraseCount {
		self.evs.failEraseCount -= 1
		return errors.New("the device died before its ERASE")
	}
	push := &testErasurePush{erasureId: args.ErasureId, signerId: self.sidecarId, complete: args.Complete, note: args.Note}
	for _, key := range args.Keys {
		if !self.evs.erased[*key] {
			push.keys = append(push.keys, *key)
		}
	}
	if len(push.keys) == 0 {
		// NOTHING_TO_ERASE: done, and nothing commits
		return nil
	}
	for _, key := range push.keys {
		self.evs.erased[key] = true
	}
	self.evs.erases = append(self.evs.erases, push)
	self.evs.order = append(self.evs.order, "erase:cards")
	return nil
}

func (self *testErasureClient) OrphanCardKeys(ctx context.Context, repoId sidecar.Id, erasureId sidecar.Id) ([]*sidecar.EvsErasedKey, error) {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	orphans := []*sidecar.EvsErasedKey{}
	for _, closure := range self.evs.closures {
		if closure.erasureId != erasureId {
			continue
		}
		for _, key := range closure.keys {
			if !self.evs.erased[key] {
				orphans = append(orphans, &sidecar.EvsErasedKey{SlotId: key.SlotId, KeyIndex: key.KeyIndex})
			}
		}
	}
	return orphans, nil
}

// One index file of the model: the documents it holds at their versions, and how many CLOSUREs rewrote it.
type testErasureIndexFile struct {
	documents map[string]uint64
	life      int
}

// One version an index file ever had: its documents and its key.
type testErasureIndexVersion struct {
	file      string
	documents map[string]uint64
	key       sidecar.EvsErasedKey
}

// One index ref of the model: its files, its erasure set and its eraser's pushes. Its lock is the evs's.
type testErasureIndex struct {
	evs  *testErasureEvs
	name string
	// file name -> what it holds now
	files map[string]*testErasureIndexFile
	// every version a CLOSURE replaced
	replaced []*testErasureIndexVersion
	// the erasure set: per erasure each document's doc_key, name and newest version erased
	listed   map[sidecar.Id]map[string]uint64
	cutCount int
	closures []*testErasurePush
	erases   []*testErasurePush
	// rewrites to stop between a CLOSURE and its ERASE
	failEraseCount int
}

func newTestErasureIndex(evs *testErasureEvs, name string) *testErasureIndex {
	return &testErasureIndex{evs: evs, name: name, files: map[string]*testErasureIndexFile{}, listed: map[sidecar.Id]map[string]uint64{}}
}

// Enters a document in a file, as the writer whose push carried it did.
func (self *testErasureIndex) enter(file string, name []byte, version uint64) {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	held, ok := self.files[file]
	if !ok {
		held = &testErasureIndexFile{documents: map[string]uint64{}}
		self.files[file] = held
	}
	held.documents[string(name)] = version
}

func (self *testErasureIndex) key(file string, life int) sidecar.EvsErasedKey {
	return testErasureKey(self.name+"/"+file, life)
}

// The stored file versions holding the document whose key still stands, as file#life.
func (self *testErasureIndex) readable(name []byte) []string {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	readable := []string{}
	for _, version := range self.replaced {
		if _, ok := version.documents[string(name)]; ok && !self.evs.erased[version.key] {
			readable = append(readable, version.file+" replaced")
		}
	}
	for file, held := range self.files {
		if _, ok := held.documents[string(name)]; ok && !self.evs.erased[self.key(file, held.life)] {
			readable = append(readable, file)
		}
	}
	slices.Sort(readable)
	return readable
}

// The newest version the set lists a document erased at, for an erasure.
func (self *testErasureIndex) listedVersion(erasureId sidecar.Id, name []byte) uint64 {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	return self.listed[erasureId][string(testErasureDocKey(self.name, name))]
}

// The doc_key the model draws a name under on a ref, and the name it stands for.
func testErasureDocKey(ref string, name []byte) []byte {
	sum := sha256.Sum256([]byte(ref + "\x00" + string(name)))
	return sum[:16]
}

// One sidecar's eraser of one index ref of the model: sidecar.DirectoryErasureIndex.
type testErasureIndexClient struct {
	index     *testErasureIndex
	sidecarId sidecar.Id
}

func (self *testErasureIndexClient) DocKey(name []byte) ([16]byte, error) {
	return [16]byte(testErasureDocKey(self.index.name, name)), nil
}

func (self *testErasureIndexClient) Cut(ctx context.Context, args *sidecar.IndexCutArgs) (*sidecar.IndexCutResult, error) {
	index := self.index
	if err := index.evs.checkAdmin(self.sidecarId); err != nil {
		return nil, err
	}
	index.evs.stateLock.Lock()
	defer index.evs.stateLock.Unlock()
	listed, ok := index.listed[args.ErasureId]
	if !ok {
		listed = map[string]uint64{}
		index.listed[args.ErasureId] = listed
	}
	result := &sidecar.IndexCutResult{}
	for _, document := range args.Documents {
		if listed[string(document.Key[:])] < document.Version {
			listed[string(document.Key[:])] = document.Version
			result.Pushed = true
		}
	}
	if result.Pushed {
		index.cutCount += 1
		index.evs.order = append(index.evs.order, "cut:"+index.name)
	}
	return result, nil
}

func (self *testErasureIndexClient) Rewrite(ctx context.Context, args *sidecar.IndexRewriteArgs) (*sidecar.IndexRewriteResult, error) {
	index := self.index
	if err := index.evs.checkAdmin(self.sidecarId); err != nil {
		return nil, err
	}
	index.evs.stateLock.Lock()
	defer index.evs.stateLock.Unlock()
	listed, ok := index.listed[args.ErasureId]
	if !ok {
		return nil, sidecar.ErrIndexEraseNotCut
	}
	result := &sidecar.IndexRewriteResult{}
	erase := func(keys []sidecar.EvsErasedKey, complete bool) {
		push := &testErasurePush{erasureId: args.ErasureId, signerId: self.sidecarId, keys: keys, complete: complete}
		if complete {
			push.note = args.Note
		}
		for _, key := range keys {
			index.evs.erased[key] = true
		}
		index.erases = append(index.erases, push)
		index.evs.order = append(index.evs.order, "erase:"+index.name)
		result.KeyCount += len(keys)
		result.Completed = result.Completed || complete
	}
	// the reconcile row: an ERASE first for each CLOSURE no ERASE followed
	for _, closure := range index.closures {
		if closure.erasureId != args.ErasureId {
			continue
		}
		orphans := slices.DeleteFunc(slices.Clone(closure.keys), func(key sidecar.EvsErasedKey) bool { return index.evs.erased[key] })
		if 0 < len(orphans) {
			erase(orphans, false)
		}
	}
	files := []string{}
	for file, held := range index.files {
		for name, version := range held.documents {
			if erasedThrough, ok := listed[string(testErasureDocKey(index.name, []byte(name)))]; ok && version <= erasedThrough {
				files = append(files, file)
				break
			}
		}
	}
	slices.Sort(files)
	for at, file := range files {
		held := index.files[file]
		oldKey := index.key(file, held.life)
		index.replaced = append(index.replaced, &testErasureIndexVersion{file: file, documents: held.documents, key: oldKey})
		kept := map[string]uint64{}
		for name, version := range held.documents {
			if erasedThrough, ok := listed[string(testErasureDocKey(index.name, []byte(name)))]; !ok || erasedThrough < version {
				kept[name] = version
			}
		}
		index.files[file] = &testErasureIndexFile{documents: kept, life: held.life + 1}
		index.closures = append(index.closures, &testErasurePush{erasureId: args.ErasureId, signerId: self.sidecarId, path: file, keys: []sidecar.EvsErasedKey{oldKey}})
		index.evs.order = append(index.evs.order, "closure:"+index.name)
		if 0 < index.failEraseCount {
			index.failEraseCount -= 1
			return nil, errors.New("the device died before its ERASE")
		}
		erase([]sidecar.EvsErasedKey{oldKey}, args.Complete && at == len(files)-1)
		result.PairCount += 1
		result.FileCount += 1
	}
	state := sidecar.SidecarErasureRewriting
	if result.Completed {
		state = sidecar.SidecarErasureDone
	}
	result.Erasure = &sidecar.SidecarErasure{ErasureId: args.ErasureId, State: state}
	return result, nil
}

// An announcement document's name as the directory's index registers it: a/ || writer || announcement_id for a run or
// worker item, a/ || announcement_id for a repo's.
func testAnnouncementDocumentName(writerId *sidecar.Id, announcementId sidecar.Id) []byte {
	name := "a/"
	if writerId != nil {
		name += fmt.Sprintf("%x", writerId[:])
	}
	return []byte(name + fmt.Sprintf("%x", announcementId[:]))
}

// A run item of writerId's naming repoId under project, private or not, at version.
func testRunItemIn(world *testDirectoryWorld, writerId sidecar.Id, memberId sidecar.Id, announcementId sidecar.Id, repoId sidecar.Id, version uint64, project string, private bool) *protocol.Announcement {
	item := testRunItem(writerId, &memberId, announcementId, version, world.clock.Now().UnixMilli())
	item.Where = &protocol.AnnounceWhere{RepoId: repoId.Bytes(), Project: project, Branch: "main"}
	if private {
		item.Where = &protocol.AnnounceWhere{RepoId: repoId.Bytes(), Private: true}
	}
	return item
}

// Each ERASE's note as its ErasureBody, failing the test on one that names another erasure than its own.
func testErasureNotes(t *testing.T, erases []*testErasurePush) []*protocol.ErasureBody {
	t.Helper()
	bodies := []*protocol.ErasureBody{}
	for _, erase := range erases {
		if len(erase.note) == 0 {
			// the index's ERASEs short of the completing one carry no caller bytes
			continue
		}
		body := &protocol.ErasureBody{}
		if err := proto.Unmarshal(erase.note, body); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body.GetErasureId(), erase.erasureId[:]) {
			t.Fatalf("an ERASE of %s whose note names %x", erase.erasureId, body.GetErasureId())
		}
		bodies = append(bodies, body)
	}
	return bodies
}

// A repo whose announcement moved from its M6 entry onto its r/ file at format 2, with a run of another member's
// device on its card naming the repo: what a revocation finds seeded.
type testErasureSeed struct {
	world    *testDirectoryWorld
	evs      *testErasureEvs
	owner    *testDirectoryDevice
	repoId   sidecar.Id
	daemon   *testDirectoryDevice
	memberId sidecar.Id
	runId    sidecar.Id
	// the documents' names
	repoDocument []byte
	runDocument  []byte
}

const (
	testErasureRepoTitle = "design notes"
	testErasureProject   = "example.org/team/vault-rewrite"
)

func newTestErasureSeed(t *testing.T) *testErasureSeed {
	t.Helper()
	world, evs := newTestErasureWorld(t)
	seed := &testErasureSeed{world: world, evs: evs, memberId: sidecar.NewId(), runId: sidecar.NewId()}
	seed.owner, seed.repoId = world.announcedRepo(testErasureRepoTitle)
	world.cards.RaiseFormat(world.directoryId)
	seed.owner.mustSync(t)
	if writes, err := seed.owner.client.MaintainRepos(t.Context()); err != nil || len(writes) != 1 {
		t.Fatalf("the move onto the r/ file: %+v %v", writes, err)
	}
	seed.daemon = world.device(world.memberWriter(seed.memberId))
	world.publish()
	daemonId := seed.daemon.writer.sidecarId
	seed.daemon.writeCard(t, testRunItemIn(world, daemonId, seed.memberId, seed.runId, seed.repoId, 1, testErasureProject, false))
	// the index as the files' pushes and the entry's companion push left it
	seed.repoDocument = testAnnouncementDocumentName(nil, sidecar.DirectoryRepoAnnouncementId(seed.repoId))
	seed.runDocument = testAnnouncementDocumentName(&daemonId, seed.runId)
	evs.cardsIndex.enter("s/owner", seed.repoDocument, 2)
	evs.cardsIndex.enter("s/daemon", seed.runDocument, 1)
	evs.cardsIndex.enter("s/daemon", []byte("a/another"), 1)
	evs.streamsIndex.enter("s/owner", seed.repoDocument, 1)
	return seed
}

// The owner's revocation, pushed: the marker over the r/ file and the request.
func (self *testErasureSeed) revoke(t *testing.T) *sidecar.DirectoryRevocation {
	t.Helper()
	self.owner.mustSync(t)
	revocation, err := self.owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: self.repoId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	self.owner.flush(t)
	return revocation
}

// The daemon's card again with its run at version, private or naming the repo.
func (self *testErasureSeed) writeRun(t *testing.T, version uint64, private bool) {
	t.Helper()
	self.world.clock.Advance(time.Minute)
	self.world.publish()
	self.daemon.writeCard(t, testRunItemIn(self.world, self.daemon.writer.sidecarId, self.memberId, self.runId, self.repoId, version, testErasureProject, private))
}

// FS-87's index case: after a directory admin's erasure of an announcement, no stored index or card version holding it
// has a readable key. The card that still held the item goes by moderation's removal, its keys by the ERASE; the CUT
// comes first; the card's other run comes back with its writer's next write, under a new key.
func TestDirectoryFormat2AdminErasesAnAnnouncement(t *testing.T) {
	world, evs := newTestErasureWorld(t)
	world.cards.RaiseFormat(world.directoryId)
	memberId := sidecar.NewId()
	device := world.device(world.memberWriter(memberId))
	world.publish()
	writerId := device.writer.sidecarId
	erasedId, keptId := sidecar.NewId(), sidecar.NewId()
	erasedItem := testRunItem(writerId, &memberId, erasedId, 1, world.clock.Now().UnixMilli())
	erasedItem.What.Title = "ship the launch plan"
	keptItem := testRunItem(writerId, &memberId, keptId, 1, world.clock.Now().UnixMilli())
	keptItem.What.Title = "tidy the changelog"
	device.writeCard(t, erasedItem, keptItem)
	// a content change, so two stored versions of the card hold the item under the path's one key
	world.clock.Advance(time.Minute)
	world.publish()
	changed := proto.Clone(erasedItem).(*protocol.Announcement)
	changed.Version = 2
	changed.Where.Branch = "launch"
	device.writeCard(t, changed, keptItem)
	erasedDocument := testAnnouncementDocumentName(&writerId, erasedId)
	keptDocument := testAnnouncementDocumentName(&writerId, keptId)
	evs.cardsIndex.enter("s/writer", erasedDocument, 2)
	evs.cardsIndex.enter("s/writer", keptDocument, 1)
	if held := evs.holding(t, "ship the launch plan"); held != 2 {
		t.Fatalf("%d stored card versions hold the item before the erasure", held)
	}

	admin := evs.adminDevice(t)
	admin.mustSync(t)
	// with no binding nothing is erased
	admin.client.BindErasureFiles(nil)
	if _, err := admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: erasedId, Confirmed: true}); !errors.Is(err, sidecar.ErrDirectoryErasureFilesUnbound) {
		t.Fatalf("an erasure with no binding: %v", err)
	}
	if closures, erases, cuts := evs.counts(); closures+erases+cuts != 0 {
		t.Fatalf("an unbound erasure sent %d closures, %d erases, %d cuts", closures, erases, cuts)
	}
	evs.bind(admin)

	result, err := admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: erasedId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	cardPath := sidecar.DirectoryCardPath(writerId)
	if result.Reason != sidecar.RecordErasureReasonModeration || result.Files == nil || !slices.Equal(result.Files.RemovedPaths, []string{cardPath}) {
		t.Fatalf("the erasure: %+v, files %+v", result, result.Files)
	}
	if !result.Files.Complete || result.Files.CutCount != 1 {
		t.Fatalf("the erasure's files: %+v", result.Files)
	}
	if evs.order[0] != "cut:cards" {
		t.Fatalf("the first push was %s, not the CUT", evs.order[0])
	}
	if version := evs.cardsIndex.listedVersion(result.ErasureId, erasedDocument); version != 2 {
		t.Fatalf("the CUT lists the document at %d", version)
	}
	if readable := evs.readable(t, "ship the launch plan"); len(readable) != 0 {
		t.Fatalf("stored card versions holding the item still open: %v", readable)
	}
	if readable := evs.cardsIndex.readable(erasedDocument); len(readable) != 0 {
		t.Fatalf("stored index versions holding the document still open: %v", readable)
	}
	if readable := evs.cardsIndex.readable(keptDocument); !slices.Equal(readable, []string{"s/writer"}) {
		t.Fatalf("the other document's index file: %v", readable)
	}
	for _, body := range testErasureNotes(t, evs.allErases()) {
		if sidecar.RecordErasureReason(body.GetReason()) != sidecar.RecordErasureReasonModeration || len(body.GetRequestId()) != 0 {
			t.Fatalf("an ERASE's note: %v", body)
		}
	}
	if world.cardFileVersion(cardPath) != 0 {
		t.Fatal("the card still stands")
	}

	// the same id again finds nothing left
	admin.mustSync(t)
	if _, err := admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: erasedId, Confirmed: true}); !errors.Is(err, sidecar.ErrDirectoryItemNone) {
		t.Fatalf("a second erasure: %v", err)
	}
	// the writer's next write brings its other run back, under a key the ERASE never named
	world.clock.Advance(time.Minute)
	world.publish()
	device.writeCard(t, keptItem)
	reader := world.reader(nil)
	reader.mustSync(t)
	shown := testItemsOf(t, reader, writerId)
	if len(shown) != 1 || shown[keptId] == nil {
		t.Fatalf("after the writer's next card: %d items", len(shown))
	}
	if readable := evs.readable(t, "tidy the changelog"); len(readable) != 1 {
		t.Fatalf("the rewritten card's versions that open: %v", readable)
	}
	if readable := evs.readable(t, "ship the launch plan"); len(readable) != 0 {
		t.Fatalf("after the rewrite: %v", readable)
	}
}

// An announcement that stands on its repo's file is its owner's to revoke: a directory admin's erase refuses before
// anything is cut or erased.
func TestDirectoryFormat2AdminEraseRefusesAStandingRepoFile(t *testing.T) {
	seed := newTestErasureSeed(t)
	admin := seed.evs.adminDevice(t)
	admin.mustSync(t)
	announcementId := sidecar.DirectoryRepoAnnouncementId(seed.repoId)
	if _, err := admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: announcementId, Confirmed: true}); !errors.Is(err, sidecar.ErrDirectoryEraseStanding) {
		t.Fatalf("an erase of a standing repo file's announcement: %v", err)
	}
	if closures, erases, cuts := seed.evs.counts(); closures+erases+cuts != 0 {
		t.Fatalf("the refused erase sent %d closures, %d erases, %d cuts", closures, erases, cuts)
	}
	if live := admin.liveAnnouncements(t); len(live) != 1 {
		t.Fatalf("%d announce entries with a key after the refusal", len(live))
	}
}

// A revoke seeded with cards and index documents (FS-87, FS-99): the runner erases the repo's announce entry, cuts
// the documents on both refs, rewrites the index files and the repo file under fresh keys, and waits for the card
// that still names the repo; once its writer wrote the run private the card is rewritten too; a later-signed card
// naming the repo is caught the same way; a pass with nothing new sends nothing; and readers, a fresh one included,
// take the rewrites in silence.
func TestDirectoryFormat2RevokeErasesCardsAndIndex(t *testing.T) {
	seed := newTestErasureSeed(t)
	world, evs := seed.world, seed.evs
	reader := world.reader(nil)
	reader.mustSync(t)
	revocation := seed.revoke(t)
	if revocation.MarkerVersion != 3 {
		t.Fatalf("the marker at version %d", revocation.MarkerVersion)
	}
	if held := evs.holding(t, testErasureRepoTitle); held != 1 {
		t.Fatalf("%d stored repo file versions hold the title", held)
	}
	admin := evs.adminDevice(t)
	runner, _ := admin.runner(t, 0, nil)
	repoPath := sidecar.DirectoryRepoPath(seed.repoId)
	cardPath := sidecar.DirectoryCardPath(seed.daemon.writer.sidecarId)

	pass := admin.pass(t, runner)
	files := pass.Files[revocation.RequestId]
	if len(pass.Erased[revocation.RequestId]) != 1 || files == nil {
		t.Fatalf("the first pass: erased %v, files %+v", pass.Erased, files)
	}
	if !slices.Equal(files.ClosedPaths, []string{repoPath}) || !slices.Equal(files.WaitingPaths, []string{cardPath}) || files.CutCount != 2 || files.Complete {
		t.Fatalf("the first pass's files: %+v", files)
	}
	if !slices.Equal(pass.Waiting, []sidecar.Id{revocation.RequestId}) {
		t.Fatalf("the requests waiting for a card's writer: %v", pass.Waiting)
	}
	if evs.cardsIndex.listedVersion(revocation.RequestId, seed.repoDocument) != 2 || evs.cardsIndex.listedVersion(revocation.RequestId, seed.runDocument) != 1 ||
		evs.streamsIndex.listedVersion(revocation.RequestId, seed.repoDocument) != 1 {
		t.Fatal("the CUTs do not list the documents at the versions that named the repo")
	}
	for _, document := range [][]byte{seed.repoDocument, seed.runDocument} {
		if readable := evs.cardsIndex.readable(document); len(readable) != 0 {
			t.Fatalf("the cards ref's index still opens %s in %v", document, readable)
		}
	}
	if readable := evs.streamsIndex.readable(seed.repoDocument); len(readable) != 0 {
		t.Fatalf("ur/index still opens the repo's document in %v", readable)
	}
	if readable := evs.cardsIndex.readable([]byte("a/another")); len(readable) != 1 {
		t.Fatalf("another document's index file: %v", readable)
	}
	if readable := evs.readable(t, testErasureRepoTitle); len(readable) != 0 {
		t.Fatalf("repo file versions holding the title still open: %v", readable)
	}
	// the card still names the repo at its standing version: only its writer rewrites it
	if readable := evs.readable(t, testErasureProject); len(readable) != 1 {
		t.Fatalf("the card naming the repo: %v", readable)
	}
	// each CUT precedes its ref's first CLOSURE
	for _, ref := range []string{"cards", "ur/index"} {
		if cut, closure := slices.Index(evs.order, "cut:"+ref), slices.Index(evs.order, "closure:"+ref); cut < 0 || closure < cut {
			t.Fatalf("on %s the CUT at %d and the first CLOSURE at %d of %v", ref, cut, closure, evs.order)
		}
	}

	// the daemon reads the marker and writes its run private, at a raised version
	seed.writeRun(t, 2, true)
	pass = admin.pass(t, runner)
	files = pass.Files[revocation.RequestId]
	if files == nil || !slices.Equal(files.ClosedPaths, []string{cardPath}) || len(files.WaitingPaths) != 0 || !files.Complete || files.CutCount != 0 {
		t.Fatalf("the pass after the daemon's rewrite: %+v", files)
	}
	if readable := evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("card versions naming the repo still open: %v", readable)
	}
	for _, body := range testErasureNotes(t, evs.allErases()) {
		if sidecar.RecordErasureReason(body.GetReason()) != sidecar.RecordErasureReasonRevocation || !bytes.Equal(body.GetRequestId(), revocation.RequestId[:]) {
			t.Fatalf("an ERASE's note: %v", body)
		}
	}
	for _, closure := range evs.cardClosures() {
		if closure.erasureId != revocation.RequestId {
			t.Fatalf("a CLOSURE of %s, not the request", closure.erasureId)
		}
	}

	// a pass with nothing new sends nothing
	closures, erases, cuts := evs.counts()
	for range 2 {
		pass = admin.pass(t, runner)
		if files := pass.Files[revocation.RequestId]; files != nil {
			t.Fatalf("a pass with nothing new: %+v", files)
		}
	}
	if againClosures, againErases, againCuts := evs.counts(); againClosures != closures || againErases != erases || againCuts != cuts {
		t.Fatalf("idle passes sent pushes: %d %d %d, were %d %d %d", againClosures, againErases, againCuts, closures, erases, cuts)
	}
	// the daemon's renewals change nothing either: no version since the CLOSURE named the repo
	seed.writeRun(t, 2, true)
	admin.pass(t, runner)
	if againClosures, _, _ := evs.counts(); againClosures != closures {
		t.Fatalf("a renewal brought %d closures, were %d", againClosures, closures)
	}

	// a later-signed card naming the repo: cut at the sync that shows it, rewritten once its writer has
	seed.writeRun(t, 3, false)
	pass = admin.pass(t, runner)
	files = pass.Files[revocation.RequestId]
	if files == nil || files.CutCount != 1 || !slices.Equal(files.WaitingPaths, []string{cardPath}) || len(files.ClosedPaths) != 0 {
		t.Fatalf("the pass that shows a later-signed card: %+v", files)
	}
	if evs.cardsIndex.listedVersion(revocation.RequestId, seed.runDocument) != 3 {
		t.Fatal("the later version is not cut")
	}
	seed.writeRun(t, 4, true)
	pass = admin.pass(t, runner)
	files = pass.Files[revocation.RequestId]
	if files == nil || !slices.Equal(files.ClosedPaths, []string{cardPath}) {
		t.Fatalf("the pass after the later card's rewrite: %+v", files)
	}
	if readable := evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("card versions naming the repo still open: %v", readable)
	}

	// readers take the rewrites in silence and show what stands: the marker, and the run private
	fresh := world.reader(nil)
	for _, each := range []*testDirectoryReader{reader, fresh, seed.daemon.testDirectoryReader, seed.owner.testDirectoryReader} {
		each.mustSync(t)
		if reasons := each.alarmReasons(); len(reasons) != 0 {
			t.Fatalf("a reader alarmed: %v", reasons)
		}
		item := testRepoItemShown(t, each, seed.repoId)
		if item == nil || !item.Announcement.GetWhere().GetPrivate() || item.Announcement.GetVersion() != 3 {
			t.Fatalf("the repo's item after the rewrites: %+v", item)
		}
		run := testItemsOf(t, each, seed.daemon.writer.sidecarId)[seed.runId]
		if run == nil || !run.Announcement.GetWhere().GetPrivate() || run.Announcement.GetVersion() != 4 {
			t.Fatalf("the run's item after the rewrites: %+v", run)
		}
	}
	// neither rightful writer repairs a path an admin's CLOSURE left
	for _, each := range []*testDirectoryDevice{seed.daemon, seed.owner} {
		repaired, err := each.client.Repair(t.Context())
		if err != nil || repaired.Card != nil || len(repaired.RepoFiles) != 0 {
			t.Fatalf("a repair after the rewrites: %+v %v", repaired, err)
		}
	}
}

// FS-99's cards and index case: a device the state names a directory admin, to which evs mints no admin, has its CUT
// refused before any rewrite, and its CLOSURE and ERASE refused when sent alone; every stored version keeps its key
// and the request stays pending.
func TestDirectoryFormat2ErasureBelowAdminRefused(t *testing.T) {
	seed := newTestErasureSeed(t)
	world, evs := seed.world, seed.evs
	revocation := seed.revoke(t)
	seed.writeRun(t, 2, true)
	// the state names it a directory admin; evs mints it rw alone
	below := world.adminDevice()
	evs.bind(below)
	runner, _ := below.runner(t, 0, nil)
	below.mustSync(t)
	repoVersion := world.cardFileVersion(sidecar.DirectoryRepoPath(seed.repoId))
	cardVersion := world.cardFileVersion(sidecar.DirectoryCardPath(seed.daemon.writer.sidecarId))

	_, err := runner.Pass(t.Context())
	if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
		t.Fatalf("the pass below admin: %v", err)
	}
	client := &testErasureClient{evs: evs, sidecarId: below.writer.sidecarId}
	keys, err := client.CardKeys(t.Context(), world.directoryId, []string{sidecar.DirectoryRepoPath(seed.repoId)})
	if err != nil || len(keys) != 1 {
		t.Fatalf("the repo file's keys: %v %v", keys, err)
	}
	_, err = client.CloseCard(t.Context(), world.directoryId, revocation.RequestId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: sidecar.DirectoryRepoPath(seed.repoId), IfVersion: repoVersion, Content: []byte("rewritten"), AuthPin: world.directoryAuth.Tip().Pin(),
	}, keys)
	if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
		t.Fatalf("a CLOSURE below admin: %v", err)
	}
	err = client.EraseCardKeys(t.Context(), world.directoryId, &sidecar.EvsEraseArgs{ErasureId: revocation.RequestId, Keys: keys})
	if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
		t.Fatalf("an ERASE below admin: %v", err)
	}
	index, _ := client.CardsIndex(t.Context(), world.directoryId)
	if _, err := index.Rewrite(t.Context(), &sidecar.IndexRewriteArgs{ErasureId: revocation.RequestId}); err == nil {
		t.Fatal("an index rewrite below admin was taken")
	}

	if closures, erases, cuts := evs.counts(); closures+erases+cuts != 0 {
		t.Fatalf("below admin: %d closures, %d erases, %d cuts", closures, erases, cuts)
	}
	if world.cardFileVersion(sidecar.DirectoryRepoPath(seed.repoId)) != repoVersion || world.cardFileVersion(sidecar.DirectoryCardPath(seed.daemon.writer.sidecarId)) != cardVersion {
		t.Fatal("a refused push rewrote a file")
	}
	if readable := evs.readable(t, testErasureRepoTitle); len(readable) != 1 {
		t.Fatalf("the repo file's earlier version: %v", readable)
	}
	if readable := evs.readable(t, testErasureProject); len(readable) != 1 {
		t.Fatalf("the card's earlier version: %v", readable)
	}
	for _, document := range [][]byte{seed.repoDocument, seed.runDocument} {
		if readable := evs.cardsIndex.readable(document); len(readable) != 1 {
			t.Fatalf("the index's file of %s: %v", document, readable)
		}
	}
	if evs.refusedCount == 0 {
		t.Fatal("no call was refused below admin")
	}
}

// A runner killed between a file's CLOSURE and its ERASE, and between an index file's: another directory admin's
// device, which holds nothing of the first one's ledger, resumes from evs's state, erasing the keys the CLOSUREs
// listed and rewriting no file twice.
func TestDirectoryFormat2ErasureResumesFromEvsState(t *testing.T) {
	seed := newTestErasureSeed(t)
	evs := seed.evs
	revocation := seed.revoke(t)
	seed.writeRun(t, 2, true)
	first := evs.adminDevice(t)
	firstRunner, _ := first.runner(t, 0, nil)
	// the index's first pair dies after its CLOSURE
	evs.cardsIndex.failEraseCount = 1
	first.mustSync(t)
	if _, err := firstRunner.Pass(t.Context()); err == nil {
		t.Fatal("the pass killed in the index's pair returned no error")
	}
	if len(evs.cardsIndex.closures) != 1 || len(evs.cardsIndex.erases) != 0 {
		t.Fatalf("the index after the kill: %d closures, %d erases", len(evs.cardsIndex.closures), len(evs.cardsIndex.erases))
	}
	// the next pass carries the index on, and dies after the first file's CLOSURE
	evs.failEraseCount = 1
	first.mustSync(t)
	if _, err := firstRunner.Pass(t.Context()); err == nil {
		t.Fatal("the pass killed after a file's CLOSURE returned no error")
	}
	if closures := evs.cardClosures(); len(closures) != 1 {
		t.Fatalf("%d CLOSUREs of the cards ref after the kill", len(closures))
	}
	closedPath := evs.cardClosures()[0].path
	unerased := evs.readable(t, testErasureProject)
	if closedPath == sidecar.DirectoryRepoPath(seed.repoId) {
		unerased = evs.readable(t, testErasureRepoTitle)
	}
	if len(unerased) == 0 {
		t.Fatal("the CLOSURE's old key went without its ERASE")
	}
	for _, document := range [][]byte{seed.repoDocument, seed.runDocument} {
		if readable := evs.cardsIndex.readable(document); len(readable) != 0 {
			t.Fatalf("the resumed index still opens %s in %v", document, readable)
		}
	}

	// another admin's device, with no ledger of the first's
	second := evs.adminDevice(t)
	secondRunner, _ := second.runner(t, 0, nil)
	pass := second.pass(t, secondRunner)
	files := pass.Files[revocation.RequestId]
	if files == nil || files.ErasedKeyCount == 0 {
		t.Fatalf("the resuming pass: %+v", files)
	}
	if readable := evs.readable(t, testErasureRepoTitle); len(readable) != 0 {
		t.Fatalf("repo file versions holding the title still open: %v", readable)
	}
	if readable := evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("card versions naming the repo still open: %v", readable)
	}
	paths := []string{}
	for _, closure := range evs.cardClosures() {
		paths = append(paths, closure.path)
	}
	slices.Sort(paths)
	if want := []string{sidecar.DirectoryCardPath(seed.daemon.writer.sidecarId), sidecar.DirectoryRepoPath(seed.repoId)}; !slices.Equal(paths, slices.Sorted(slices.Values(want))) {
		t.Fatalf("the cards ref's CLOSUREs: %v", paths)
	}
	// the first device, started again, finds nothing left
	closures, erases, cuts := evs.counts()
	restarted := seed.world.restarted(first)
	evs.admit(restarted)
	restartedRunner, _ := restarted.runner(t, 0, nil)
	restarted.pass(t, restartedRunner)
	restarted.pass(t, restartedRunner)
	if againClosures, againErases, againCuts := evs.counts(); againClosures != closures || againErases != erases || againCuts != cuts {
		t.Fatalf("the restarted device sent pushes: %d %d %d, were %d %d %d", againClosures, againErases, againCuts, closures, erases, cuts)
	}
}

// Two runners race: both read the same state and both send; one CLOSURE a file commits, the other's meets the path's
// CAS and rewrites nothing, and each key is erased once.
func TestDirectoryFormat2TwoRunnersRace(t *testing.T) {
	seed := newTestErasureSeed(t)
	evs := seed.evs
	revocation := seed.revoke(t)
	seed.writeRun(t, 2, true)
	first := evs.adminDevice(t)
	second := evs.adminDevice(t)
	firstRunner, _ := first.runner(t, 0, nil)
	secondRunner, _ := second.runner(t, 0, nil)
	first.mustSync(t)
	second.mustSync(t)
	if _, err := firstRunner.Pass(t.Context()); err != nil {
		t.Fatal(err)
	}
	// the second has not read the first's pushes
	pass, err := secondRunner.Pass(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	files := pass.Files[revocation.RequestId]
	if files == nil || len(files.ClosedPaths) != 0 || len(files.ConflictPaths) != 2 || files.CutCount != 0 {
		t.Fatalf("the racing pass: %+v", files)
	}
	if closures := evs.cardClosures(); len(closures) != 2 {
		t.Fatalf("%d CLOSUREs of the cards ref from two runners", len(closures))
	}
	erasedOnce := map[sidecar.EvsErasedKey]int{}
	for _, erase := range evs.allErases() {
		for _, key := range erase.keys {
			erasedOnce[key] += 1
		}
	}
	for key, count := range erasedOnce {
		if count != 1 {
			t.Fatalf("key %v erased %d times", key, count)
		}
	}
	// once it reads them it has nothing to send
	closures, erases, cuts := evs.counts()
	second.pass(t, secondRunner)
	second.pass(t, secondRunner)
	if againClosures, againErases, againCuts := evs.counts(); againClosures != closures || againErases != erases || againCuts != cuts {
		t.Fatalf("the second runner sent pushes after its sync: %d %d %d, were %d %d %d", againClosures, againErases, againCuts, closures, erases, cuts)
	}
	if readable := evs.readable(t, testErasureRepoTitle); len(readable) != 0 {
		t.Fatalf("repo file versions holding the title still open: %v", readable)
	}
	if readable := evs.readable(t, testErasureProject); len(readable) != 0 {
		t.Fatalf("card versions naming the repo still open: %v", readable)
	}
}

// What a reader takes of a push at a card's path from another sidecar than its writer: a directory admin's CLOSURE
// of the very bytes the card stands at, in silence; nothing else. A member's push of those bytes is a path_rule
// breach as before; an admin's push of the writer's earlier card, which would bring an erased item back, and of a
// card the admin signed itself are refused and alarm, and the writer's standing card keeps standing.
func TestDirectoryFormat2ClosurePushRules(t *testing.T) {
	world, _ := newTestErasureWorld(t)
	world.cards.RaiseFormat(world.directoryId)
	aMember, bMember := sidecar.NewId(), sidecar.NewId()
	a := world.memberWriter(aMember)
	b := world.memberWriter(bMember)
	world.publish()
	admin := world.adminDevice().writer
	now := world.clock.Now().UnixMilli()
	path := sidecar.DirectoryCardPath(a.sidecarId)
	pin := world.directoryAuth.Tip().Pin()
	one := testRunItem(a.sidecarId, &aMember, sidecar.NewId(), 1, now)
	two := testRunItem(a.sidecarId, &aMember, sidecar.NewId(), 1, now)
	first := world.cardContent(a, a.sidecarId, 1, pin, one, two)
	standing := world.cardContent(a, a.sidecarId, 2, pin, one)
	world.putFile(a.sidecarId, path, first, pin)
	world.putFile(a.sidecarId, path, standing, pin)
	reader := world.reader(nil)
	reader.mustSync(t)
	requireOne := func(name string) {
		t.Helper()
		if shown := testItemsOf(t, reader, a.sidecarId); len(shown) != 1 {
			t.Fatalf("%s: the reader shows %d of A's items", name, len(shown))
		}
	}
	requireOne("before any push")

	// an admin's CLOSURE of the standing bytes
	world.putFile(admin.sidecarId, path, standing, pin)
	reader.mustSync(t)
	if reasons := reader.alarmReasons(); len(reasons) != 0 {
		t.Fatalf("an admin's CLOSURE of the standing card alarmed: %v", reasons)
	}
	requireOne("after the CLOSURE")
	// a reader that never saw the writer's own push takes the CLOSURE's version as the writer's card
	fresh := world.reader(nil)
	fresh.mustSync(t)
	if shown := testItemsOf(t, fresh, a.sidecarId); len(shown) != 1 {
		t.Fatalf("a fresh reader shows %d of A's items after the CLOSURE", len(shown))
	}

	// a member's push of the same bytes
	world.putFile(b.sidecarId, path, standing, pin)
	reader.mustSync(t)
	if count := reader.alarmsNaming(sidecar.SidecarRecordAlarmPathRule, b.sidecarId); count != 1 {
		t.Fatalf("a member's push at A's path: %d path_rule alarms, %v", count, reader.alarmReasons())
	}
	requireOne("after a member's push")

	// an admin's push of the writer's earlier card, and of a card it signed itself
	before := len(reader.alarmReasons())
	world.putFile(admin.sidecarId, path, first, pin)
	reader.mustSync(t)
	if after := len(reader.alarmReasons()); after != before+1 {
		t.Fatalf("an admin's push of A's earlier card: %d alarms, were %d: %v", after, before, reader.alarmReasons())
	}
	requireOne("after an admin's replay")
	world.putFile(admin.sidecarId, path, world.cardContent(admin, a.sidecarId, 3, pin, one, two), pin)
	reader.mustSync(t)
	if after := len(reader.alarmReasons()); after != before+2 {
		t.Fatalf("an admin's push of a card it signed: %d alarms, were %d: %v", after, before, reader.alarmReasons())
	}
	requireOne("after an admin's own card")
}

// The evs binding of format 2's erasure is made only over the directory's evs binding and its admins.
func TestDirectoryEvsErasureNeedsItsBinding(t *testing.T) {
	if _, err := sidecar.NewDirectoryEvsErasure(nil); !errors.Is(err, sidecar.ErrDirectoryCardsUnavailable) {
		t.Fatalf("a binding on nothing: %v", err)
	}
	if _, err := sidecar.NewDirectoryEvsErasure(&sidecar.DirectoryEvsErasureArgs{IsAdmin: func(sidecar.Id) bool { return true }}); !errors.Is(err, sidecar.ErrDirectoryCardsUnavailable) {
		t.Fatalf("a binding with no evs binding: %v", err)
	}
}
