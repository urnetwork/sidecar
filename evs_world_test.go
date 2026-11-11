// A stand-in evs for the verifying reader's and the reads' tests: one repo's main ref whose pushes are real signed
// statements over real sealed entries, records and segments, served as POST .../read and GET .../log answer them
// (§11.9), with knobs that make it lie the ways a malicious server would.
//
// Path epochs (DESIGN-DETAILS 9.2.4's route) as evs keeps them: each path's entry has a home epoch, the current one
// or a listed source, where a read finds it only by the token path the request names in that epoch; a read naming no
// token path in the current epoch is answered stale_epoch; an entry served from a source carries entry_epoch, its
// table's rows sealed there untagged and older ones carried; every statement's change is proven under the path's token
// path in that statement's own epoch, and a later statement of an epoch the request names none in gets no proof. A
// cut-over (cutOver) leaves entries where they are, and the copy (copyAll) moves them all, translating carried rows,
// and drops the sources.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The verified config state of the world: one state that judges every pin.
type evsTestConfig struct {
	stateLock sync.Mutex
	// what At answers, nil for this one state
	atErr        error
	identityKeys map[Id][]byte
	writers      []Id
	readers      []Id
	repo         *protocol.AclRepo
}

func (self *evsTestConfig) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: 1, Chain: evsTestBytes("auth chain", 32)}
}
func (self *evsTestConfig) At(pin *bridge.AuthPin) (GkmAuthView, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.atErr != nil {
		return nil, self.atErr
	}
	return self, nil
}
func (self *evsTestConfig) OnChain(pin *bridge.AuthPin) bool { return true }
func (self *evsTestConfig) IdentityKey(sidecarId Id) []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.identityKeys[sidecarId]
}
func (self *evsTestConfig) Repo(repoId Id) *protocol.AclRepo { return self.repo }
func (self *evsTestConfig) RepoReaders(repoId Id) []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.readers)
}
func (self *evsTestConfig) RepoWriters(repoId Id) []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.writers)
}
func (self *evsTestConfig) RepoReadersAt(repoId Id, at time.Time) []Id {
	return self.RepoReaders(repoId)
}
func (self *evsTestConfig) SidecarRow(sidecarId Id) *bridge.SidecarRow        { return nil }
func (self *evsTestConfig) Member(memberId Id) *bridge.MemberRow              { return nil }
func (self *evsTestConfig) Delegations() []*bridge.DelegationRow              { return nil }
func (self *evsTestConfig) ReposGrantedToAtoms(atoms []Id, at time.Time) []Id { return nil }
func (self *evsTestConfig) CascadeVoids(signer []byte, at uint64) bool        { return false }

// A gkm client that holds every generation of the world's repo.
type evsTestReadGkm struct {
	gkmRefusingClient
	newest uint64
}

func (self *evsTestReadGkm) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return evsTestRepoKey(repoId, self.newest), nil
}
func (self *evsTestReadGkm) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	return evsTestRepoKey(repoId, generation), nil
}

// One committed push.
type evsTestCommit struct {
	statement []byte
	parsed    *EvsStatement
	built     *EvsBuiltPush
	chain     [sha256.Size]byte
}

// One path version.
type evsTestVersion struct {
	entryBytes    []byte
	commitVersion uint64
	pushId        []byte
}

// One path's state.
type evsTestPath struct {
	versions map[uint64]*evsTestVersion
	newest   uint64
	removal  *protocol.EvsRemovalMarker
	// a directory's folded rows, each with the epoch it is sealed in as its epoch field, 0 for 1
	rows []*protocol.EvsName
	// the epoch whose idx/ holds its entry, 0 for 1
	home uint64
}

// What a test asks a push to change.
type evsTestChange struct {
	path string
	// nil removes
	content []byte
	// written to a segment rather than inline
	segment bool
	// a directory whose delta names these children, which the same push creates
	children []string
}

// The world.
type evsTestWorld struct {
	t          testing.TB
	repoId     Id
	refId      Id
	signer     *evsTestSigner
	config     *evsTestConfig
	gkm        *evsTestReadGkm
	generation uint64

	stateLock sync.Mutex
	commits   []*evsTestCommit
	paths     map[string]*evsTestPath
	segments  map[string][]byte
	// how many statements a read serves after its pin before it answers behind
	window int
	// lies
	omitVersion    uint64
	serveVersion   map[string]uint64
	missingObjects bool
	mutatePath     func(reply *protocol.EvsReadPathReply)
	headOverride   *protocol.EvsHeadSummary
	logPageCount   int
	reads          int
	// a git-mode world's ref mode, its tree as git would hash it, and the next push's sealed metadata
	mode         protocol.EvsRefMode
	gitState     map[string]EvsGitOid
	nextMetadata []byte
	// the next push's payload sections 15 and 16, a creating push's sealed ref name and base
	nextRefName []byte
	nextBase    *protocol.EvsOverlay
	// a git-mode head's copies of its creating push's sections 15 and 16, whether a DELETE stands, and whether its
	// creation set IMMUTABLE, as the stand-in's commits keep them
	sealedRefName []byte
	base          *protocol.EvsOverlay
	deleted       bool
	immutable     bool
	// a ref a request names that the world never made is made empty on first use, as helper refs an import names
	autoRefs bool
	// the next push's flags, and the new objects it introduces beside its entries' segments
	nextFlags      uint32
	nextNewObjects []*EvsNewObject
	// other refs of the repo, each a world of its own sharing the repo, keys, signer, config and segments, served by
	// the ref id a request names (otherRef)
	others map[Id]*evsTestWorld
	// the head's current path epoch, 0 for 1: a PATH_EPOCH the world's pushes never made, as a subscription's
	// leases follow it; and the source epochs it lists, newest first
	currentEpoch uint64
	sourceEpochs []uint64
	// every token path a request named, in order: each read path's by epoch, each push's changes, source paths and
	// delta rows (the capture of DESIGN-DETAILS 9.6)
	captured []*evsTestCaptured
	// a version of an epoch the request names no token path in is answered with its statement alone, as evs answers
	// a version it can place by neither leaf place nor token path
	statementAloneUnnamed bool
	// the due the head records, nil for none: its generation, block and due_by_ms
	due *protocol.EvsPathEpoch
}

// One token path a request showed evs, by the epoch it named it in, with the current epoch then.
type evsTestCaptured struct {
	epoch     uint64
	tokenPath EvsTokenPath
	current   uint64
	// a row of a delta names only the child's last token
	row bool
}

// The world's current epoch, under stateLock.
func (self *evsTestWorld) currentWithLock() uint64 {
	return max(1, self.currentEpoch)
}

// A row stored in the epoch it is sealed in, 0 for 1.
func evsTestStoredRow(row *protocol.EvsName, epoch uint64) *protocol.EvsName {
	stored := proto.Clone(row).(*protocol.EvsName)
	stored.Epoch = 0
	if 1 < epoch {
		stored.Epoch = epoch
	}
	return stored
}

// A directory's rows as served from a copy in tableEpoch: sealed there untagged, sealed in an older epoch carried.
func evsTestServedRows(rows []*protocol.EvsName, tableEpoch uint64) []*protocol.EvsName {
	served := []*protocol.EvsName{}
	for _, row := range rows {
		copied := proto.Clone(row).(*protocol.EvsName)
		copied.Epoch = max(1, row.GetEpoch())
		if copied.Epoch == tableEpoch {
			copied.Epoch = 0
		}
		served = append(served, copied)
	}
	return served
}

// Cuts the ref over to epoch: the current one listed first among its sources, every entry left where it is.
func (self *evsTestWorld) cutOver(epoch uint64) {
	self.generation = max(self.generation, epoch)
	self.pushPathEpoch(epoch)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sourceEpochs = append([]uint64{self.currentWithLock()}, self.sourceEpochs...)
	self.currentEpoch = epoch
	for _, state := range self.paths {
		if state.home == 0 {
			state.home = 1
		}
	}
}

// Commits a PATH_EPOCH push to epoch on the head, as a mapper's commits, its map's parts standing on no store here:
// the statement that lets every later one declare the new epoch.
func (self *evsTestWorld) pushPathEpoch(epoch uint64) {
	self.t.Helper()
	baseVersion, baseChain := self.head()
	version := baseVersion + 1
	pushId := evsTestId(fmt.Sprint("world path epoch ", version, " ", epoch))
	plan := &EvsPushPlan{
		RepoId: self.repoId, RefId: self.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED,
		RefMode: self.mode, PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain,
		Generation: self.generation, GroupId: evsTestId("world group"), GenerationCommitment: evsTestBytes(fmt.Sprint("commitment ", self.generation), 32),
		PathEpoch: epoch, Auth: &bridge.AuthPin{Version: 1, Chain: evsTestBytes("auth chain", 32)},
		SignerSidecarId: self.signer.sidecarId, ClientId: evsTestId("world client"), TimeMs: 1767225600000 + int64(version),
		Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH), PathMapSha256: evsTestBytes(fmt.Sprint("map ", epoch), 32),
		MapSourceVersion: baseVersion, MapSourceChain: baseChain[:],
		SealedMetadata: append(evsTestBytes(fmt.Sprint("metadata ", version), 32), evsTestBytes("metadata tail", 16)...),
	}
	built, err := NewEvsStatementBuilder(self.signer.sign).Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	chain := EvsChainNext(baseChain, pushId, built.Statement.Sha256)
	self.commits = append(self.commits, &evsTestCommit{statement: built.Statement.Bytes, parsed: built.Statement, built: built, chain: chain})
}

// The copy, finished: every entry moved to the current epoch, every row older than it translated, sealed again under
// the current epoch's keys, and the sources dropped.
func (self *evsTestWorld) copyAll() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	current := self.currentWithLock()
	keys := evsTestKeys(self.t, self.repoId, current)
	for directory, state := range self.paths {
		state.home = current
		for i, row := range state.rows {
			rowEpoch := max(1, row.GetEpoch())
			if rowEpoch == current {
				continue
			}
			for path := range self.paths {
				parent, name := evsSplitParent(path)
				if path == "" || parent != directory || self.tokensAt(path, rowEpoch).Last() != EvsToken(row.GetToken()) {
					continue
				}
				childToken := self.tokensAt(path, current).Last()
				sealed, err := EvsNameSeal(keys.manifest, self.tokensAt(directory, current).Last(), childToken, name)
				if err != nil {
					self.t.Fatal(err)
				}
				state.rows[i] = evsTestStoredRow(&protocol.EvsName{Token: childToken.Bytes(), Kind: row.GetKind(), SealedName: sealed}, current)
			}
		}
	}
	self.sourceEpochs = nil
}

// The token paths captured so far.
func (self *evsTestWorld) capturedTokenPaths() []*evsTestCaptured {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.captured)
}

func newEvsTestWorld(t testing.TB) *evsTestWorld {
	t.Helper()
	repoId := evsTestId("world repo")
	signer := newEvsTestSigner("world writer")
	world := &evsTestWorld{
		t:          t,
		repoId:     repoId,
		signer:     signer,
		generation: 1,
		config: &evsTestConfig{
			identityKeys: map[Id][]byte{signer.sidecarId: signer.publicKey()},
			writers:      []Id{signer.sidecarId},
			readers:      []Id{signer.sidecarId},
			repo:         &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
		},
		gkm:          &evsTestReadGkm{newest: 1},
		paths:        map[string]*evsTestPath{},
		segments:     map[string][]byte{},
		window:       127,
		serveVersion: map[string]uint64{},
		mode:         protocol.EvsRefMode_EVS_REF_FILE,
		gitState:     map[string]EvsGitOid{},
	}
	refKey, err := NewEvsRefKey(evsTestRepoKey(repoId, 1))
	if err != nil {
		t.Fatal(err)
	}
	world.refId, err = EvsRefId(refKey, EvsMainRefName)
	if err != nil {
		t.Fatal(err)
	}
	return world
}

// The head's version and chain.
func (self *evsTestWorld) head() (uint64, [sha256.Size]byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.commits) == 0 {
		return 0, EvsChainStart(self.repoId, self.refId)
	}
	return uint64(len(self.commits)), self.commits[len(self.commits)-1].chain
}

// A path's token path in epoch 1, the root's "" empty.
func (self *evsTestWorld) tokens(path string) EvsTokenPath {
	return self.tokensAt(path, 1)
}

// A path's token path in epoch, the root's "" empty in every epoch.
func (self *evsTestWorld) tokensAt(path string, epoch uint64) EvsTokenPath {
	names := [][]byte{}
	for _, name := range strings.Split(path, "/") {
		if path != "" {
			names = append(names, []byte(name))
		}
	}
	tokenPath, err := EvsPathTokens(evsTestPathKey(self.t, self.repoId, max(1, epoch)), names)
	if err != nil {
		self.t.Fatal(err)
	}
	return tokenPath
}

// A file's entry version, its content in an inline record or a segment of the world's generation.
func (self *evsTestWorld) fileEntry(content []byte, segment bool, version uint64, pushId Id, baseVersion uint64, prev *evsTestVersion) []byte {
	keys := evsTestKeys(self.t, self.repoId, self.generation)
	fileId := NewEvsSlotId()
	oid, err := EvsGitBlobOid(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		self.t.Fatal(err)
	}
	sealedFields, err := EvsSealFields(keys.manifest, &protocol.EvsSealedFields{
		FileId: fileId.Bytes(), Mode: 0o100644, GitOid: oid[:], OidKind: protocol.EvsOidKind_EVS_OID_SHA1, Size: uint64(len(content)),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	header := &EvsRecordHeader{
		RecordId:   NewEvsSlotId(),
		Generation: self.generation,
		Kind:       protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT,
		KeyRefKind: protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER,
		OidKind:    protocol.EvsOidKind_EVS_OID_SHA1,
	}
	copy(header.Oid[:], oid[:])
	var locator *protocol.EvsLocator
	if segment {
		locator = self.segmentRecord(keys, fileId, header, content)
	} else {
		inline, _, err := EvsSealInlineRecord(keys.manifest, keys.fek, nil, fileId, header, content)
		if err != nil {
			self.t.Fatal(err)
		}
		locator = &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: inline}
	}
	entry := &protocol.EvsEntryVersion{
		Version: version, PushId: pushId.Bytes(), BaseVersion: baseVersion, TimeMs: 1767225600000 + int64(version),
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: EvsPadme(uint64(len(content))),
		SealedFields: sealedFields, Chain: []*protocol.EvsLocator{locator},
	}
	if prev != nil {
		entry.PrevPushId = prev.pushId
		entry.PrevCommitVersion = prev.commitVersion
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	return entryBytes
}

// One record in a new segment of keys' generation, stored, and its locator.
func (self *evsTestWorld) segmentRecord(keys *evsTestGenerationKeys, fileId Id, header *EvsRecordHeader, body []byte) *protocol.EvsLocator {
	out := &bytes.Buffer{}
	builder, err := NewEvsSegmentBuilder(out, keys.manifest, keys.fek)
	if err != nil {
		self.t.Fatal(err)
	}
	header.BodyLength = uint64(len(body))
	writer, err := builder.BeginRecord(fileId, header)
	if err != nil {
		self.t.Fatal(err)
	}
	writer.Write(body)
	if err := writer.Close(); err != nil {
		self.t.Fatal(err)
	}
	summary, err := builder.Finish()
	if err != nil {
		self.t.Fatal(err)
	}
	self.stateLock.Lock()
	self.segments[string(summary.Id[:])] = out.Bytes()
	self.stateLock.Unlock()
	return &protocol.EvsLocator{
		Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: summary.Id[:],
		Offset: summary.Places[0].Offset, Length: summary.Places[0].Length,
	}
}

// Commits one push of changes on the head, as its signer builds it, and answers its version.
func (self *evsTestWorld) push(changes ...*evsTestChange) uint64 {
	self.t.Helper()
	baseVersion, baseChain := self.head()
	version := baseVersion + 1
	pushId := evsTestId(fmt.Sprint("world push ", version, " ", self.generation))
	keys := evsTestKeys(self.t, self.repoId, self.generation)
	self.stateLock.Lock()
	current := self.currentWithLock()
	self.stateLock.Unlock()
	plan := &EvsPushPlan{
		RepoId: self.repoId, RefId: self.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED,
		RefMode: self.mode, PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain,
		Generation: self.generation, GroupId: evsTestId("world group"), GenerationCommitment: evsTestBytes(fmt.Sprint("commitment ", self.generation), 32),
		PathEpoch: current, Auth: &bridge.AuthPin{Version: 1, Chain: evsTestBytes("auth chain", 32)},
		SignerSidecarId: self.signer.sidecarId, ClientId: evsTestId("world client"), TimeMs: 1767225600000 + int64(version),
		SealedMetadata: append(evsTestBytes(fmt.Sprint("metadata ", version), 32), evsTestBytes("metadata tail", 16)...),
	}
	if self.nextMetadata != nil {
		plan.SealedMetadata = self.nextMetadata
		self.nextMetadata = nil
	}
	plan.RefName, plan.Base, plan.Flags, plan.NewObjects = self.nextRefName, self.nextBase, self.nextFlags, self.nextNewObjects
	self.nextRefName, self.nextBase, self.nextFlags, self.nextNewObjects = nil, nil, 0, nil
	type pending struct {
		key     string
		version uint64
		entry   []byte
		removal *protocol.EvsRemovalMarker
		rows    []*protocol.EvsName
	}
	pendings := []*pending{}
	for _, change := range changes {
		key := change.path
		self.stateLock.Lock()
		state := self.paths[key]
		self.stateLock.Unlock()
		baseEntryVersion := uint64(0)
		var prev *evsTestVersion
		if state != nil && state.removal == nil {
			baseEntryVersion = state.newest
			prev = state.versions[state.newest]
		}
		entryVersion := baseEntryVersion + 1
		if baseEntryVersion == 0 {
			entryVersion = baseVersion + 1
			if state != nil && state.removal != nil {
				entryVersion = max(baseVersion, state.removal.GetPathVersion()) + 1
			}
		}
		p := &pending{key: key, version: entryVersion}
		switch {
		case change.children != nil:
			table := &protocol.EvsNameTable{}
			parent := self.tokensAt(change.path, current).Last()
			for _, child := range change.children {
				childPath := child
				if change.path != "" {
					childPath = change.path + "/" + child
				}
				childToken := self.tokensAt(childPath, current).Last()
				sealed, err := EvsNameSeal(keys.manifestOfEpoch(self.t, self.repoId, current), parent, childToken, []byte(child))
				if err != nil {
					self.t.Fatal(err)
				}
				row := &protocol.EvsName{Token: childToken.Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: sealed}
				table.Names = append(table.Names, row)
				p.rows = append(p.rows, evsTestStoredRow(row, current))
			}
			entry := &protocol.EvsEntryVersion{
				Version: entryVersion, PushId: pushId.Bytes(), BaseVersion: baseVersion, TimeMs: plan.TimeMs,
				Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY), Names: table,
			}
			if prev != nil {
				entry.PrevPushId, entry.PrevCommitVersion = prev.pushId, prev.commitVersion
			}
			p.entry, _ = proto.MarshalOptions{Deterministic: true}.Marshal(entry)
		case change.content != nil:
			p.entry = self.fileEntry(change.content, change.segment, entryVersion, pushId, baseVersion, prev)
		default:
			if state == nil || state.removal != nil {
				self.t.Fatalf("removing an absent %s", change.path)
			}
			p.version = state.newest + 1
			p.removal = &protocol.EvsRemovalMarker{PushId: pushId.Bytes(), RemovalVersion: version, PathVersion: state.newest + 1}
		}
		plan.Changes = append(plan.Changes, &EvsPlannedChange{
			TokenPath: self.tokensAt(change.path, current), BaseEntryVersion: baseEntryVersion, EntryVersion: p.entry,
		})
		pendings = append(pendings, p)
	}
	built, err := NewEvsStatementBuilder(self.signer.sign).Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	statement := built.Statement
	chain := EvsChainNext(baseChain, pushId, statement.Sha256)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	// what this push showed evs
	for _, change := range plan.Changes {
		self.captured = append(self.captured, &evsTestCaptured{epoch: current, tokenPath: change.TokenPath, current: current})
	}
	for _, p := range pendings {
		for _, row := range p.rows {
			self.captured = append(self.captured, &evsTestCaptured{epoch: current, tokenPath: EvsTokenPath{EvsToken(row.GetToken())}, current: current, row: true})
		}
	}
	self.commits = append(self.commits, &evsTestCommit{statement: statement.Bytes, parsed: statement, built: built, chain: chain})
	for _, p := range pendings {
		state := self.paths[p.key]
		if state == nil {
			state = &evsTestPath{versions: map[uint64]*evsTestVersion{}}
			self.paths[p.key] = state
		}
		state.home = current
		if p.removal != nil {
			state.removal = p.removal
			state.newest = p.version
			continue
		}
		state.removal = nil
		state.versions[p.version] = &evsTestVersion{entryBytes: p.entry, commitVersion: version, pushId: pushId.Bytes()}
		state.newest = p.version
		state.rows = append(state.rows, p.rows...)
	}
	return version
}

// manifest_p, which seals names of path epoch p.
func (self *evsTestGenerationKeys) manifestOfEpoch(t testing.TB, repoId Id, epoch uint64) *EvsManifestKey {
	return evsTestKeys(t, repoId, epoch).manifest
}

// The head summary a read answers.
func (self *evsTestWorld) headSummaryWithLock() *protocol.EvsHeadSummary {
	if self.headOverride != nil {
		return self.headOverride
	}
	head := &protocol.EvsHeadSummary{
		RefId: self.refId.Bytes(), RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: self.mode,
		GroupId: evsTestId("world group").Bytes(), Generation: self.generation,
		PathEpoch:     &protocol.EvsPathEpoch{Current: max(1, self.currentEpoch)},
		SealedRefName: self.sealedRefName, Base: self.base, Deleted: self.deleted,
	}
	for _, source := range self.sourceEpochs {
		head.PathEpoch.Sources = append(head.PathEpoch.Sources, &protocol.EvsEpochSource{Epoch: source})
	}
	if self.due != nil {
		head.PathEpoch.DueGeneration, head.PathEpoch.DueBlocksCreation = self.due.GetDueGeneration(), self.due.GetDueBlocksCreation()
		head.PathEpoch.DueByMs, head.PathEpoch.BlockUntilMs = self.due.GetDueByMs(), self.due.GetBlockUntilMs()
	}
	if len(self.commits) == 0 {
		chain := EvsChainStart(self.repoId, self.refId)
		head.Chain = chain[:]
		return head
	}
	last := self.commits[len(self.commits)-1]
	head.Version = uint64(len(self.commits))
	head.Chain = last.chain[:]
	head.PushId = last.parsed.Push.GetPushId()
	return head
}

// The index of tokenPath in a push's change tree, false when the push did not change it.
func evsTestTreePosition(tree *EvsChangeTree, tokenPath EvsTokenPath) (int, int, bool) {
	return tree.position(tokenPath)
}

// The reply for one path at its newest version, or version, with the proofs a reader needs from pin on: named holds
// the token path the request names in each epoch, the current one's among them, and each statement's change is found
// under the path's token path in that statement's epoch (see the file header).
func (self *evsTestWorld) pathReplyWithLock(named map[uint64]EvsTokenPath, version uint64, pin uint64) (*protocol.EvsReadPathReply, []*protocol.EvsLocator, error) {
	current := self.currentWithLock()
	tokenPath := named[current]
	var key string
	var state *evsTestPath
	for path, candidate := range self.paths {
		if self.tokensAt(path, current).Equal(tokenPath) {
			key, state = path, candidate
		}
	}
	entryEpoch := uint64(0)
	if state != nil {
		home := max(1, state.home)
		if home != current {
			// a source's copy, found only by the token path the request names in its epoch; the root, which has no
			// token, in every listed source
			sourceNamed, ok := named[home]
			switch {
			case !slices.Contains(self.sourceEpochs, home):
				state = nil
			case key == "":
				entryEpoch = home
			case !ok || !sourceNamed.Equal(self.tokensAt(key, home)):
				state = nil
			default:
				entryEpoch = home
			}
		}
	}
	// the path's token path in each later statement's epoch, as the request names it, nil for none
	namedAt := func(later uint64) EvsTokenPath {
		tokenPath, ok := named[max(1, self.commits[later-1].parsed.Push.GetPathEpoch())]
		if !ok {
			return nil
		}
		return tokenPath
	}
	// a statement's own epoch's token path of the path
	tokenPathAt := func(commitVersion uint64) EvsTokenPath {
		return self.tokensAt(key, self.commits[commitVersion-1].parsed.Push.GetPathEpoch())
	}
	reply := &protocol.EvsReadPathReply{TokenPath: tokenPath.Components(), EntryEpoch: entryEpoch}
	if state == nil && self.base != nil {
		// an overlay's path it holds no version of: its base, which the reader reads instead (§11.7)
		reply.Base = self.base
		return reply, nil, nil
	}
	if state == nil {
		// never written: absent, with the proofs that no later statement's change list holds it
		for later := uint64(1); later <= uint64(len(self.commits)); later += 1 {
			tree := self.commits[later-1].built.ChangeTree
			laterPath := namedAt(later)
			if tree == nil || laterPath == nil {
				continue
			}
			for _, absentPath := range EvsAbsencePaths(self.commits[later-1].parsed.ChangedPrefixes, laterPath) {
				absence, err := tree.AbsenceProof(absentPath)
				if err != nil {
					continue
				}
				absence.Version = later
				reply.Absences = append(reply.Absences, absence)
			}
		}
		return reply, nil, nil
	}
	commitVersion := uint64(0)
	var locators []*protocol.EvsLocator
	if served, ok := self.serveVersion[key]; ok && version == 0 {
		version = served
	}
	if state.removal != nil && version == 0 {
		reply.Removal = state.removal
		commitVersion = state.removal.GetRemovalVersion()
	} else {
		if version == 0 {
			version = state.newest
		}
		held := state.versions[version]
		if held == nil {
			return nil, nil, fmt.Errorf("no such version")
		}
		reply.Version = &protocol.EvsIndexVersion{PushId: held.pushId, CommitVersion: held.commitVersion, EntryVersion: held.entryBytes}
		commitVersion = held.commitVersion
		entry := &protocol.EvsEntryVersion{}
		proto.Unmarshal(held.entryBytes, entry)
		locators = entry.GetChain()
		if entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
			reply.Names = &protocol.EvsNameTable{Names: evsTestServedRows(state.rows, max(1, state.home))}
			reply.NamesThrough = held.commitVersion
		}
	}
	commit := self.commits[commitVersion-1]
	if _, ok := named[max(1, commit.parsed.Push.GetPathEpoch())]; !ok && self.statementAloneUnnamed {
		// a version or removal evs cannot place in its statement for this request: the statement alone
		alone := &protocol.EvsReadPathReply{TokenPath: tokenPath.Components(), Statement: commit.statement}
		if self.mutatePath != nil {
			self.mutatePath(alone)
		}
		return alone, nil, nil
	}
	if commitVersion <= pin {
		reply.Statement = commit.statement
	}
	if commit.built.ChangeTree != nil {
		part, index, present := evsTestTreePosition(commit.built.ChangeTree, tokenPathAt(commitVersion))
		if !present && reply.Removal == nil {
			return nil, nil, fmt.Errorf("the path is not in its push")
		}
		if present {
			proofs, err := commit.built.ChangeTree.InclusionProof(part, index)
			if err != nil {
				return nil, nil, err
			}
			reply.Proof = proofs
		}
	}
	for later := commitVersion + 1; later <= uint64(len(self.commits)); later += 1 {
		tree := self.commits[later-1].built.ChangeTree
		laterPath := namedAt(later)
		if tree == nil || laterPath == nil {
			continue
		}
		for _, absentPath := range EvsAbsencePaths(self.commits[later-1].parsed.ChangedPrefixes, laterPath) {
			absence, err := tree.AbsenceProof(absentPath)
			if err != nil {
				continue
			}
			absence.Version = later
			reply.Absences = append(reply.Absences, absence)
		}
	}
	if self.mutatePath != nil {
		self.mutatePath(reply)
	}
	return reply, locators, nil
}

// Serves POST .../read and GET .../log.
func (self *evsTestWorld) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if other := self.otherOf(request); other != nil {
		other.ServeHTTP(writer, request)
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch {
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/read"):
		self.reads += 1
		body, _ := io.ReadAll(request.Body)
		read := &protocol.EvsReadRequest{}
		if err := proto.Unmarshal(body, read); err != nil || !bytes.Equal(read.GetRefId(), self.refId.Bytes()) {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		frames := []*protocol.EvsReadFrame{{Head: self.headSummaryWithLock()}}
		head := uint64(len(self.commits))
		first := read.GetPinVersion() + 1
		if self.window < int(head)-int(read.GetPinVersion()) {
			first = head - uint64(self.window) + 1
			frames = append(frames, &protocol.EvsReadFrame{Behind: read.GetPinVersion() + 1})
		}
		for version := first; version <= head; version += 1 {
			if version == self.omitVersion {
				continue
			}
			frames = append(frames, &protocol.EvsReadFrame{Statement: &protocol.EvsReadStatement{Version: version, Statement: self.commits[version-1].statement}})
		}
		locators := []*protocol.EvsLocator{}
		for _, path := range read.GetPaths() {
			named := map[uint64]EvsTokenPath{}
			var first EvsTokenPath
			for _, sourcePath := range path.GetTokenPaths() {
				tokenPath, err := ParseEvsChangedTokenPath(sourcePath.GetTokenPath())
				if err != nil {
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				named[sourcePath.GetEpoch()] = tokenPath
				if first == nil {
					first = tokenPath
				}
				self.captured = append(self.captured, &evsTestCaptured{epoch: sourcePath.GetEpoch(), tokenPath: tokenPath, current: self.currentWithLock()})
			}
			if _, ok := named[self.currentWithLock()]; !ok {
				frames = append(frames, &protocol.EvsReadFrame{Path: &protocol.EvsReadPathReply{TokenPath: first.Components(), StaleEpoch: true}})
				continue
			}
			reply, pathLocators, err := self.pathReplyWithLock(named, path.GetVersion(), read.GetPinVersion())
			if err != nil {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			frames = append(frames, &protocol.EvsReadFrame{Path: reply})
			locators = append(locators, pathLocators...)
		}
		for _, readPush := range read.GetPushes() {
			if record, ok := self.pushRecordWithLock(readPush.GetPushId(), readPush.GetVersion(), readPush.GetPart()); ok {
				// a record past 1 MiB spans frames, each the next slice at its own offset
				for at := 0; at == 0 || at < len(record); at += 1024 * 1024 {
					frames = append(frames, &protocol.EvsReadFrame{Object: &protocol.EvsReadObject{
						Kind: protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD, Id: readPush.GetPushId(), Number: uint64(readPush.GetPart()),
						Offset: uint32(at), Body: record[at:min(len(record), at+1024*1024)],
					}})
				}
			}
		}
		for _, readRange := range read.GetRanges() {
			locators = append(locators, &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: readRange.GetSegmentId(), Offset: readRange.GetOffset(), Length: readRange.GetLength()})
		}
		for _, locator := range locators {
			if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT {
				continue
			}
			segment, ok := self.segments[string(locator.GetId())]
			if !ok || self.missingObjects {
				frames = append(frames, &protocol.EvsReadFrame{Object: &protocol.EvsReadObject{Kind: protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT, Id: locator.GetId(), Missing: true}})
				continue
			}
			for _, part := range [][2]uint32{{0, evsSegmentKeyedHeaderByteCount}, {locator.GetOffset(), locator.GetLength()}} {
				// a range past 1 MiB spans frames, each the next slice at its own offset
				for at := part[0]; at < part[0]+part[1]; at += 1024 * 1024 {
					end := min(part[0]+part[1], at+1024*1024)
					frames = append(frames, &protocol.EvsReadFrame{Object: &protocol.EvsReadObject{
						Kind: protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT, Id: locator.GetId(), Offset: at,
						Body: segment[at:end],
					}})
				}
			}
		}
		frames = append(frames, &protocol.EvsReadFrame{End: true})
		writer.WriteHeader(http.StatusOK)
		for _, frame := range frames {
			encoded, err := EncodeEvsReadFrame(frame)
			if err != nil {
				self.t.Error(err)
				return
			}
			writer.Write(encoded)
		}
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/log"):
		self.logPageCount += 1
		since, _ := strconv.ParseUint(request.URL.Query().Get("since"), 10, 64)
		reply := &protocol.EvsLogReply{}
		head := uint64(len(self.commits))
		pageSize := uint64(16)
		for version := since; version <= head && version < since+pageSize; version += 1 {
			if version == self.omitVersion {
				continue
			}
			reply.Statements = append(reply.Statements, &protocol.EvsReadStatement{Version: version, Statement: self.commits[version-1].statement})
		}
		if since+pageSize <= head {
			reply.NextVersion = since + pageSize
		}
		body, _ := proto.Marshal(reply)
		writer.WriteHeader(http.StatusOK)
		writer.Write(body)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

// A reader of the world: a client whose config and gkm are the world's, on a sealed store.
func (self *evsTestWorld) reader(t *testing.T, readerId Id) *evsTestClient {
	t.Helper()
	test := newEvsTestClient(t, self, newEvsTestStore(t))
	test.client.args.Gkm = self.gkm
	test.client.args.Config = func() GkmAuthView { return self.config }
	identity := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: readerId, ClientId: evsTestId("reader client")}
	test.client.args.Identity = func() *SidecarIdentity { return identity }
	return test
}

// The events a test client saw of kind.
func (self *evsTestClient) eventsOf(kind SidecarEventKind) []SidecarEvent {
	events := []SidecarEvent{}
	for _, event := range *self.events {
		if event.Kind == kind {
			events = append(events, event)
		}
	}
	return events
}

// The push record the world serves for a push: its statement and payload as items, or for a part of a push in parts
// that part's record, its statement and the part as items.
func (self *evsTestWorld) pushRecordWithLock(pushId []byte, version uint64, part uint32) ([]byte, bool) {
	if version == 0 || uint64(len(self.commits)) < version {
		return nil, false
	}
	commit := self.commits[version-1]
	if !bytes.Equal(commit.parsed.Push.GetPushId(), pushId) {
		return nil, false
	}
	// the batch record as its place holds it
	record := &EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: self.repoId, RefId: self.refId, PushId: Id(pushId),
		SignerSidecarId: Id(commit.parsed.Push.GetSignerSidecarId()), TimeMs: commit.parsed.Push.GetTimeMs(),
		Body: evsJoinItems([][]byte{commit.statement, commit.built.Payload}),
	}
	if part != 0 {
		if len(commit.built.Parts) < int(part) {
			return nil, false
		}
		record.Type = protocol.EvsBatchRecordType_EVS_BATCH_PART
		record.Body = EvsPartRecordBody(commit.statement, commit.built.Parts[part-1], nil, version)
	}
	return record.encode(), true
}

// Another ref of the world's repo by its name, made on first use: a world of its own whose pushes are its ref's,
// sharing the repo, keys, signer, config, gkm and segments, served by the ref id a request names.
func (self *evsTestWorld) otherRef(refName []byte) *evsTestWorld {
	self.t.Helper()
	refKey, err := NewEvsRefKey(evsTestRepoKey(self.repoId, 1))
	if err != nil {
		self.t.Fatal(err)
	}
	refId, err := EvsRefId(refKey, refName)
	if err != nil {
		self.t.Fatal(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.others == nil {
		self.others = map[Id]*evsTestWorld{}
	}
	if other := self.others[refId]; other != nil {
		return other
	}
	other := &evsTestWorld{
		t: self.t, repoId: self.repoId, refId: refId, signer: self.signer, config: self.config, gkm: self.gkm,
		generation: self.generation, paths: map[string]*evsTestPath{}, segments: self.segments, window: self.window,
		serveVersion: map[string]uint64{}, mode: self.mode, gitState: map[string]EvsGitOid{},
	}
	self.others[refId] = other
	return other
}

// The other ref a request names, nil for the world's own: a read's by its body's ref id, which is left for the
// handler to read again, and a log's by its ref query.
func (self *evsTestWorld) otherOf(request *http.Request) *evsTestWorld {
	self.stateLock.Lock()
	others := self.others
	autoRefs := self.autoRefs
	self.stateLock.Unlock()
	if len(others) == 0 && !autoRefs {
		return nil
	}
	switch {
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/read"):
		body, _ := io.ReadAll(request.Body)
		request.Body = io.NopCloser(bytes.NewReader(body))
		read := &protocol.EvsReadRequest{}
		if proto.Unmarshal(body, read) != nil {
			return nil
		}
		refId, err := IdFromBytes(read.GetRefId())
		if err != nil {
			return nil
		}
		return self.otherOfId(refId)
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/log"):
		for refId, other := range others {
			if request.URL.Query().Get("ref") == evsUrlId(refId) {
				return other
			}
		}
	}
	return nil
}

// The other ref of refId, nil for the world's own; with autoRefs, one the world never saw is made empty, as a ref a
// push will create reads at evs.
func (self *evsTestWorld) otherOfId(refId Id) *evsTestWorld {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if refId == self.refId {
		return nil
	}
	if other := self.others[refId]; other != nil || !self.autoRefs {
		return other
	}
	if self.others == nil {
		self.others = map[Id]*evsTestWorld{}
	}
	other := &evsTestWorld{
		t: self.t, repoId: self.repoId, refId: refId, signer: self.signer, config: self.config, gkm: self.gkm,
		generation: self.generation, paths: map[string]*evsTestPath{}, segments: self.segments, window: self.window,
		serveVersion: map[string]uint64{}, mode: self.mode, gitState: map[string]EvsGitOid{},
	}
	self.others[refId] = other
	return other
}
