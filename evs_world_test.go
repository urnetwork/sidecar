// A stand-in evs for the verifying reader's and the reads' tests: one repo's main ref whose pushes are real signed
// statements over real sealed entries, records and segments, served as POST .../read and GET .../log answer them
// (§11.9), with knobs that make it lie the ways a malicious server would.

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
	// a directory's folded rows
	rows []*protocol.EvsName
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

// A path's token path in epoch 1.
func (self *evsTestWorld) tokens(path string) EvsTokenPath {
	names := [][]byte{}
	for _, name := range strings.Split(path, "/") {
		names = append(names, []byte(name))
	}
	tokenPath, err := EvsPathTokens(evsTestPathKey(self.t, self.repoId, 1), names)
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
	plan := &EvsPushPlan{
		RepoId: self.repoId, RefId: self.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED,
		RefMode: self.mode, PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain,
		Generation: self.generation, GroupId: evsTestId("world group"), GenerationCommitment: evsTestBytes(fmt.Sprint("commitment ", self.generation), 32),
		PathEpoch: 1, Auth: &bridge.AuthPin{Version: 1, Chain: evsTestBytes("auth chain", 32)},
		SignerSidecarId: self.signer.sidecarId, ClientId: evsTestId("world client"), TimeMs: 1767225600000 + int64(version),
		SealedMetadata: append(evsTestBytes(fmt.Sprint("metadata ", version), 32), evsTestBytes("metadata tail", 16)...),
	}
	if self.nextMetadata != nil {
		plan.SealedMetadata = self.nextMetadata
		self.nextMetadata = nil
	}
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
			parent := self.tokens(change.path).Last()
			for _, child := range change.children {
				childToken := self.tokens(change.path + "/" + child).Last()
				sealed, err := EvsNameSeal(keys.manifestOfEpoch(self.t, self.repoId, 1), parent, childToken, []byte(child))
				if err != nil {
					self.t.Fatal(err)
				}
				row := &protocol.EvsName{Token: childToken.Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: sealed}
				table.Names = append(table.Names, row)
				p.rows = append(p.rows, row)
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
			TokenPath: self.tokens(change.path), BaseEntryVersion: baseEntryVersion, EntryVersion: p.entry,
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
	self.commits = append(self.commits, &evsTestCommit{statement: statement.Bytes, parsed: statement, built: built, chain: chain})
	for _, p := range pendings {
		state := self.paths[p.key]
		if state == nil {
			state = &evsTestPath{versions: map[uint64]*evsTestVersion{}}
			self.paths[p.key] = state
		}
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
		PathEpoch: &protocol.EvsPathEpoch{Current: 1},
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

// The reply for one path at its newest version, or version, with the proofs a reader needs from pin on.
func (self *evsTestWorld) pathReplyWithLock(tokenPath EvsTokenPath, version uint64, pin uint64) (*protocol.EvsReadPathReply, []*protocol.EvsLocator, error) {
	var key string
	var state *evsTestPath
	for path, candidate := range self.paths {
		if self.tokens(path).Equal(tokenPath) {
			key, state = path, candidate
		}
	}
	reply := &protocol.EvsReadPathReply{TokenPath: tokenPath.Components()}
	if state == nil {
		// never written: absent, with the proofs that no later statement's change list holds it
		for later := uint64(1); later <= uint64(len(self.commits)); later += 1 {
			tree := self.commits[later-1].built.ChangeTree
			if tree == nil {
				continue
			}
			for _, absentPath := range EvsAbsencePaths(self.commits[later-1].parsed.ChangedPrefixes, tokenPath) {
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
			reply.Names = &protocol.EvsNameTable{Names: state.rows}
			reply.NamesThrough = held.commitVersion
		}
	}
	commit := self.commits[commitVersion-1]
	if commitVersion <= pin {
		reply.Statement = commit.statement
	}
	if commit.built.ChangeTree != nil {
		part, index, present := evsTestTreePosition(commit.built.ChangeTree, tokenPath)
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
		if tree == nil {
			continue
		}
		for _, absentPath := range EvsAbsencePaths(self.commits[later-1].parsed.ChangedPrefixes, tokenPath) {
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
			tokenPath, _ := ParseEvsTokenPath(path.GetTokenPaths()[0].GetTokenPath())
			reply, pathLocators, err := self.pathReplyWithLock(tokenPath, path.GetVersion(), read.GetPinVersion())
			if err != nil {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			frames = append(frames, &protocol.EvsReadFrame{Path: reply})
			locators = append(locators, pathLocators...)
		}
		for _, readPush := range read.GetPushes() {
			if record, ok := self.pushRecordWithLock(readPush.GetPushId(), readPush.GetVersion()); ok {
				frames = append(frames, &protocol.EvsReadFrame{Object: &protocol.EvsReadObject{
					Kind: protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD, Id: readPush.GetPushId(), Body: record,
				}})
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

// The push record the world serves for a push: its statement and payload as items.
func (self *evsTestWorld) pushRecordWithLock(pushId []byte, version uint64) ([]byte, bool) {
	if version == 0 || uint64(len(self.commits)) < version {
		return nil, false
	}
	commit := self.commits[version-1]
	if !bytes.Equal(commit.parsed.Push.GetPushId(), pushId) {
		return nil, false
	}
	return evsJoinItems([][]byte{commit.statement, commit.built.Payload}), true
}
