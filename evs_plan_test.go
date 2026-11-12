// EVS1-M2-25's tests: the checkpoint rules as tables, chains never past N + 1 locators, chunks rewritten only where
// touched, a creation after a removal continuing its versions, reserved names refused, directory deltas for parents,
// and every plan's bytes read back through EVS1-M2-24's verifying reader, over a stand-in evs that commits what the
// push sender posts into the read tests' world.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A gkm client holding every generation of the world's repo, under the world's group and commitments, each
// generation's cause as the test sets it.
type evsTestWriteGkm struct {
	gkmRefusingClient
	stateLock sync.Mutex
	newest    uint64
	causes    map[uint64]GkmCause
	// each generation's GenRotate auth pin version, 0 unset
	auths   map[uint64]uint64
	ensured int
}

func newEvsTestWriteGkm() *evsTestWriteGkm {
	return &evsTestWriteGkm{newest: 1, causes: map[uint64]GkmCause{}, auths: map[uint64]uint64{}}
}

func (self *evsTestWriteGkm) key(repoId Id, generation uint64) *EvsRepoKey {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := evsTestRepoKey(repoId, generation)
	key.groupId = evsTestId("world group")
	key.commitment = evsTestBytes(fmt.Sprint("commitment ", generation), 32)
	key.cause = self.causes[generation]
	key.auth = &bridge.AuthPin{Version: self.auths[generation]}
	return key
}

func (self *evsTestWriteGkm) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	self.stateLock.Lock()
	newest := self.newest
	self.stateLock.Unlock()
	return self.key(repoId, newest), nil
}

func (self *evsTestWriteGkm) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	return self.key(repoId, generation), nil
}

func (self *evsTestWriteGkm) EnsureWritable(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	self.stateLock.Lock()
	self.ensured += 1
	newest := self.newest
	self.stateLock.Unlock()
	return self.key(repoId, newest), nil
}

// A refusal the stand-in answers instead of handling a request.
type evsTestRefusal struct {
	status int
	reply  *protocol.EvsRefusalReply
}

// The stand-in evs: the world's reads, and the segment, part, lease and push routes, which check what they take as
// evs's codecs do and commit it into the world, path by path by the plaintext names the test registers.
type evsTestPushServer struct {
	t     *testing.T
	world *evsTestWorld

	stateLock  sync.Mutex
	knownPaths []string
	// parts by push id and part number
	parts map[string]map[uint32][]byte
	// committed push ids and their versions
	committed map[Id]uint64
	// refusals answered, in order, to the next push and seal posts
	pushRefusals []*evsTestRefusal
	// refusals answered to the next part posts
	partRefusals []*evsTestRefusal
	// commits whose answer is lost as a 503 of unknown outcome
	dropAnswers int
	// what was posted: each push or seal's statement bytes, each upload's segment id, each part's number
	postedStatements [][]byte
	uploads          []string
	postedParts      []uint32
	leases           int
	// called as each part arrives, before it is held
	onPart func(k uint32)
	// called as each push or seal arrives, before 5e's epoch is checked: what a test cuts the world over in
	onPush func(statement *EvsStatement)
	// the upload time receipts name, 0 for 2026-01-01
	uploadMs int64
	// map parts by path_map_sha256 and part, the PATH_EPOCHs committed with their parts, the blocks asked for, and
	// how many uploads each part took
	mapParts     map[string]map[uint32][]byte
	committedMap [][][]byte
	blocks       int
	partUploads  map[uint32]int
	// called as each map part arrives; an error answers 503 for it
	onMapPart func(part uint32) error
}

func newEvsTestPushServer(t *testing.T, world *evsTestWorld) *evsTestPushServer {
	return &evsTestPushServer{t: t, world: world, parts: map[string]map[uint32][]byte{}, committed: map[Id]uint64{}}
}

// Registers the plaintext paths a test writes, parents included, so a commit can name each change's path.
func (self *evsTestPushServer) know(paths ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, path := range paths {
		components := strings.Split(path, "/")
		for depth := 1; depth <= len(components); depth += 1 {
			self.knownPaths = append(self.knownPaths, strings.Join(components[:depth], "/"))
		}
	}
}

// Answers a refusal.
func evsTestRefuse(writer http.ResponseWriter, refusal *evsTestRefusal) {
	body, _ := proto.Marshal(refusal.reply)
	writer.WriteHeader(refusal.status)
	writer.Write(body)
}

func (self *evsTestPushServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	path := request.URL.Path
	switch {
	case request.Method == http.MethodPut && strings.Contains(path, "/segments/"):
		self.serveSegment(writer, request)
	case request.Method == http.MethodPost && strings.HasSuffix(path, "/lease"):
		self.stateLock.Lock()
		self.leases += 1
		self.stateLock.Unlock()
		writer.WriteHeader(http.StatusOK)
	case request.Method == http.MethodPost && strings.HasSuffix(path, "/path-epoch/block"):
		self.stateLock.Lock()
		self.blocks += 1
		self.stateLock.Unlock()
		writer.WriteHeader(http.StatusOK)
	case request.Method == http.MethodPost && strings.HasSuffix(path, "/path-epoch"):
		self.serveMapPart(writer, request)
	case request.Method == http.MethodPost && strings.Contains(path, "/push/"):
		self.servePart(writer, request)
	case request.Method == http.MethodPost && strings.HasSuffix(path, "/push"):
		self.servePush(writer, request)
	default:
		self.world.ServeHTTP(writer, request)
	}
}

// PUT .../segments/<sid>: the bytes must hash to their id; a receipt answers.
func (self *evsTestPushServer) serveSegment(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	segmentId := sha256.Sum256(body)
	sid := request.URL.Path[strings.LastIndex(request.URL.Path, "/")+1:]
	if hex.EncodeToString(segmentId[:]) != sid || len(request.URL.Query().Get("push")) != 32 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	self.stateLock.Lock()
	self.uploads = append(self.uploads, sid)
	uploadMs := self.uploadMs
	self.stateLock.Unlock()
	if uploadMs == 0 {
		uploadMs = 1767225600000
	}
	self.world.stateLock.Lock()
	self.world.segments[string(segmentId[:])] = body
	self.world.stateLock.Unlock()
	receipt := &protocol.EvsUploadReceipt{
		RepoId: self.world.repoId.Bytes(), SegmentId: segmentId[:], PaddedSize: uint64(len(body)), UploadMs: uploadMs,
		UploaderSidecarId: self.world.signer.sidecarId.Bytes(), KeyId: 1, Mac: make([]byte, 16),
	}
	reply, _ := proto.Marshal(receipt)
	writer.WriteHeader(http.StatusOK)
	writer.Write(reply)
}

// POST .../push/<P>/<k>: a part held until its seal.
func (self *evsTestPushServer) servePart(writer http.ResponseWriter, request *http.Request) {
	segments := strings.Split(request.URL.Path, "/")
	k, err := strconv.Atoi(segments[len(segments)-1])
	pushIdText := segments[len(segments)-2]
	body, _ := io.ReadAll(request.Body)
	part := &protocol.EvsPartRequest{}
	if err != nil || proto.Unmarshal(body, part) != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	self.stateLock.Lock()
	onPart := self.onPart
	self.stateLock.Unlock()
	if onPart != nil {
		onPart(uint32(k))
	}
	self.stateLock.Lock()
	if 0 < len(self.partRefusals) {
		refusal := self.partRefusals[0]
		self.partRefusals = self.partRefusals[1:]
		self.stateLock.Unlock()
		evsTestRefuse(writer, refusal)
		return
	}
	if self.parts[pushIdText] == nil {
		self.parts[pushIdText] = map[uint32][]byte{}
	}
	self.parts[pushIdText][uint32(k)] = part.GetPart()
	self.postedParts = append(self.postedParts, uint32(k))
	self.stateLock.Unlock()
	reply, _ := proto.Marshal(&protocol.EvsPushReply{Place: &protocol.EvsPlace{Seq: uint32(k), Length: uint32(len(part.GetPart()))}})
	writer.WriteHeader(http.StatusOK)
	writer.Write(reply)
}

// POST .../push: a one-part push or a seal, checked as evs's codecs and a plain path-level CAS check it, then committed.
func (self *evsTestPushServer) servePush(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	pushRequest := &protocol.EvsPushRequest{}
	if err := proto.Unmarshal(body, pushRequest); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	statement, err := ParseEvsStatement(pushRequest.GetStatement())
	if err != nil {
		self.t.Errorf("a push whose statement does not parse: %v", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	// any signer the world's config holds, as evs's projection would take it (EVS1-M3-01's second writer)
	signerId, _ := IdFromBytes(statement.Push.GetSignerSidecarId())
	if err := statement.Verify(self.world.config.IdentityKey(signerId)); err != nil {
		self.t.Errorf("a push whose signature does not verify: %v", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	pushId := Id(statement.Push.GetPushId())
	self.stateLock.Lock()
	self.postedStatements = append(self.postedStatements, pushRequest.GetStatement())
	if version, ok := self.committed[pushId]; ok {
		self.stateLock.Unlock()
		reply, _ := proto.Marshal(&protocol.EvsPushReply{Version: version})
		writer.WriteHeader(http.StatusOK)
		writer.Write(reply)
		return
	}
	if 0 < len(self.pushRefusals) {
		refusal := self.pushRefusals[0]
		self.pushRefusals = self.pushRefusals[1:]
		self.stateLock.Unlock()
		refusal.reply.PushId = pushId.Bytes()
		evsTestRefuse(writer, refusal)
		return
	}
	onPush := self.onPush
	self.stateLock.Unlock()
	if onPush != nil {
		onPush(statement)
	}
	if statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
		version, refusal := self.commitPathEpoch(statement, pushRequest.GetPayload())
		if refusal != nil {
			refusal.reply.PushId = pushId.Bytes()
			evsTestRefuse(writer, refusal)
			return
		}
		self.stateLock.Lock()
		self.committed[pushId] = version
		self.stateLock.Unlock()
		reply, _ := proto.Marshal(&protocol.EvsPushReply{Version: version})
		writer.WriteHeader(http.StatusOK)
		writer.Write(reply)
		return
	}
	world := self.worldOf(Id(statement.Push.GetRefId()))
	world.stateLock.Lock()
	current := max(1, world.currentEpoch)
	headVersion := uint64(len(world.commits))
	world.stateLock.Unlock()
	epoch := statement.Push.GetPathEpoch()
	switch {
	case 0 < headVersion && statement.Push.GetBaseVersion() == 0:
		// 5e's once line: a push planned on no head commits only as the push that creates the ref (DESIGN-DETAILS
		// 9.2.6), before its epoch is compared
		evsTestRefuse(writer, &evsTestRefusal{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{
			PushId: pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE,
		}})
		return
	case headVersion == 0 && epoch != 0 && epoch <= statement.Push.GetGeneration():
		// a ref's first push names the epoch it starts in
	case headVersion == 0 || epoch != current:
		// 5e: final for the statement, which can never commit
		evsTestRefuse(writer, &evsTestRefusal{status: http.StatusPreconditionFailed, reply: &protocol.EvsRefusalReply{
			PushId: pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH,
		}})
		return
	}
	self.stateLock.Lock()
	var checked *EvsCheckedPayload
	var tree *EvsChangeTree
	parts := [][]byte{}
	if 0 < len(pushRequest.GetPartPlaces()) {
		held := self.parts[evsUrlId(pushId)]
		for _, place := range pushRequest.GetPartPlaces() {
			partBytes, ok := held[place.GetSeq()]
			if !ok {
				self.stateLock.Unlock()
				evsTestRefuse(writer, &evsTestRefusal{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING}})
				return
			}
			parts = append(parts, partBytes)
		}
		var checkedParts []*EvsCheckedPart
		checked, checkedParts, err = EvsCheckSeal(statement, parts)
		if err == nil {
			partLeaves := [][][]byte{}
			for _, checkedPart := range checkedParts {
				// a changeless part is no leaf of the root (DESIGN-DETAILS 8.2.2's parts row)
				if checkedPart.HoldsChanges() {
					partLeaves = append(partLeaves, checkedPart.changeLeaves)
				}
			}
			tree, err = NewEvsPartedChangeTree(partLeaves)
		}
	} else {
		checked, err = EvsCheckPayload(statement, pushRequest.GetPayload())
		if err == nil && len(statement.Push.GetChangesRoot()) != 0 {
			leaves := [][]byte{}
			for _, change := range checked.Changes {
				leaves = append(leaves, change.Leaf)
			}
			tree, err = NewEvsChangeTree(leaves)
		}
	}
	self.stateLock.Unlock()
	if err != nil {
		self.t.Errorf("a push whose payload does not check: %v", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	version, refusal := self.commit(world, statement, pushRequest.GetPayload(), parts, checked, tree)
	if refusal != nil {
		refusal.reply.PushId = pushId.Bytes()
		evsTestRefuse(writer, refusal)
		return
	}
	self.stateLock.Lock()
	self.committed[pushId] = version
	drop := 0 < self.dropAnswers
	if drop {
		self.dropAnswers -= 1
	}
	self.stateLock.Unlock()
	if drop {
		evsTestRefuse(writer, &evsTestRefusal{status: http.StatusServiceUnavailable, reply: &protocol.EvsRefusalReply{
			PushId: pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE, Outcome: protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN,
		}})
		return
	}
	reply, _ := proto.Marshal(&protocol.EvsPushReply{Version: version})
	writer.WriteHeader(http.StatusOK)
	writer.Write(reply)
}

// The registered plaintext path whose tokens in epoch are tokenPath.
func (self *evsTestPushServer) pathOf(tokenPath EvsTokenPath, epoch uint64) (string, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(tokenPath) == 0 {
		// the root, whose table a top-level creation or removal changes
		return "", true
	}
	for _, path := range self.knownPaths {
		if self.world.tokensAt(path, epoch).Equal(tokenPath) {
			return path, true
		}
	}
	return "", false
}

// The world of the ref a push names: the world's own, or another ref the test made (otherRef).
func (self *evsTestPushServer) worldOf(refId Id) *evsTestWorld {
	if refId == self.world.refId {
		return self.world
	}
	if other := self.world.otherOfId(refId); other != nil {
		return other
	}
	self.t.Fatalf("a push to a ref the test did not make")
	return nil
}

// Commits a checked push into its ref's world after 5f's base and 5g's CAS on each file path, or answers their 409.
// A git-mode push commits only on the head (TIP, else 409 NON_FAST_FORWARD), takes a creation over a standing path
// of the other kind, and copies a creating push's sections 15 and 16 into the head; a DELETE marks the head deleted
// and an IMMUTABLE ref takes nothing but a DELETE (§11.8's refs table).
func (self *evsTestPushServer) commit(world *evsTestWorld, statement *EvsStatement, payload []byte, parts [][]byte, checked *EvsCheckedPayload, tree *EvsChangeTree) (uint64, *evsTestRefusal) {
	paths := make([]string, len(checked.Changes))
	for i, change := range checked.Changes {
		path, ok := self.pathOf(change.TokenPath, statement.Push.GetPathEpoch())
		if !ok {
			self.t.Fatalf("a change to a path the test did not register")
		}
		paths[i] = path
	}
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	push := statement.Push
	head := uint64(len(world.commits))
	gitMode := protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT
	baseChain := EvsChainStart(world.repoId, world.refId)
	if 0 < push.GetBaseVersion() && push.GetBaseVersion() <= head {
		baseChain = world.commits[push.GetBaseVersion()-1].chain
	}
	if head < push.GetBaseVersion() || push.GetBaseVersion()+63 < head || !bytes.Equal(push.GetBaseChain(), baseChain[:]) {
		return 0, &evsTestRefusal{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE}}
	}
	flags := push.GetFlags()
	if gitMode {
		if push.GetBaseVersion() != head {
			return 0, &evsTestRefusal{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD}}
		}
		if world.immutable && flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) == 0 {
			return 0, &evsTestRefusal{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE}}
		}
		creating := head == 0 || world.deleted
		if (len(checked.RefName) != 0 || checked.Base != nil) && !creating {
			return 0, &evsTestRefusal{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE}}
		}
		if creating && len(checked.RefName) != 0 {
			world.sealedRefName, world.base = bytes.Clone(checked.RefName), checked.Base
		}
	}
	if head == 0 {
		// step 7 starts the ref's head in the epoch its first push names, in the mode its first push states
		world.currentEpoch = max(1, push.GetPathEpoch())
		world.mode = protocol.EvsRefMode(push.GetRefMode())
	}
	current := world.currentWithLock()
	// what the push showed evs: each change's token path, source paths and delta rows
	for _, change := range checked.Changes {
		world.captured = append(world.captured, &evsTestCaptured{epoch: push.GetPathEpoch(), tokenPath: change.TokenPath, current: current})
		for epoch, tokenPath := range evsTestSourcePathsOf(change) {
			world.captured = append(world.captured, &evsTestCaptured{epoch: epoch, tokenPath: tokenPath, current: current})
		}
		if change.WritesEntry() {
			entry := &protocol.EvsEntryVersion{}
			proto.Unmarshal(change.EntryVersion, entry)
			for _, row := range entry.GetNames().GetNames() {
				world.captured = append(world.captured, &evsTestCaptured{epoch: push.GetPathEpoch(), tokenPath: EvsTokenPath{EvsToken(row.GetToken())}, current: current, row: true})
			}
		}
	}
	conflicts := []*protocol.EvsTokenPath{}
	for i, change := range checked.Changes {
		state := world.paths[paths[i]]
		if state != nil && paths[i] != "" && max(1, state.home) != current {
			// 5g reads the current entry and the source copies the change names: one homed elsewhere is not seen
			sources := evsTestSourcePathsOf(change)
			if sourcePath, ok := sources[max(1, state.home)]; !ok || !sourcePath.Equal(world.tokensAt(paths[i], max(1, state.home))) {
				state = nil
			}
		}
		newest := uint64(0)
		directory := false
		if state != nil && state.removal == nil {
			newest = state.newest
			entry := &protocol.EvsEntryVersion{}
			proto.Unmarshal(state.versions[state.newest].entryBytes, entry)
			directory = entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)
		}
		if directory && change.Change.GetBaseEntryVersion() != 0 {
			continue
		}
		if gitMode && change.Change.GetBaseEntryVersion() == 0 && change.WritesEntry() && 0 < newest {
			// a creation over a standing path of the other kind (DESIGN-DETAILS 8.2.2's kinds row)
			entry := &protocol.EvsEntryVersion{}
			proto.Unmarshal(change.EntryVersion, entry)
			if (entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)) != directory {
				continue
			}
		}
		if change.Change.GetBaseEntryVersion() != newest {
			conflicts = append(conflicts, change.TokenPath.Proto())
		}
	}
	if 0 < len(conflicts) {
		return 0, &evsTestRefusal{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, Paths: conflicts}}
	}
	version := head + 1
	chain := EvsChainNext(baseChain, Id(push.GetPushId()), statement.Sha256)
	if 0 < head {
		chain = EvsChainNext(world.commits[head-1].chain, Id(push.GetPushId()), statement.Sha256)
	}
	world.commits = append(world.commits, &evsTestCommit{
		statement: statement.Bytes, parsed: statement, chain: chain,
		built: &EvsBuiltPush{Statement: statement, Payload: payload, Parts: parts, ChangeTree: tree},
	})
	if gitMode {
		world.deleted = flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) != 0
		if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE) != 0 {
			world.immutable = true
		}
		if world.deleted {
			world.immutable = false
		}
	}
	for i, change := range checked.Changes {
		state := world.paths[paths[i]]
		if state == nil {
			state = &evsTestPath{versions: map[uint64]*evsTestVersion{}}
			world.paths[paths[i]] = state
		}
		// the fold writes the current entry and deletes the source copies the push named
		state.home = current
		if !change.WritesEntry() {
			state.newest = change.Change.GetBaseEntryVersion() + 1
			state.removal = &protocol.EvsRemovalMarker{PushId: push.GetPushId(), RemovalVersion: version, PathVersion: state.newest}
			state.rows = nil
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		proto.Unmarshal(change.EntryVersion, entry)
		if change.Change.GetBaseEntryVersion() == 0 {
			state.rows = nil
		}
		for _, removed := range entry.GetNames().GetRemovedTokens() {
			kept := []*protocol.EvsName{}
			for _, row := range state.rows {
				if !bytes.Equal(row.GetToken(), removed) {
					kept = append(kept, row)
				}
			}
			state.rows = kept
		}
		for _, row := range entry.GetNames().GetNames() {
			state.rows = append(state.rows, evsTestStoredRow(row, current))
		}
		state.removal = nil
		state.versions[entry.GetVersion()] = &evsTestVersion{entryBytes: change.EntryVersion, commitVersion: version, pushId: push.GetPushId()}
		state.newest = entry.GetVersion()
	}
	return version, nil
}

// A writer of the world: a client signing as the world's signer, with a gkm that writes, over the stand-in.
type evsTestWriter struct {
	world  *evsTestWorld
	server *evsTestPushServer
	gkm    *evsTestWriteGkm
	test   *evsTestClient
	repo   *EvsRepo
}

func newEvsTestWriter(t *testing.T) *evsTestWriter {
	world := newEvsTestWorld(t)
	server := newEvsTestPushServer(t, world)
	gkm := newEvsTestWriteGkm()
	test := newEvsTestClient(t, server, newEvsTestStore(t))
	test.client.args.Gkm = gkm
	test.client.args.Config = func() GkmAuthView { return world.config }
	test.client.args.Sign = world.signer.sign
	identity := &SidecarIdentity{NetworkId: testNetworkId, SidecarId: world.signer.sidecarId, ClientId: evsTestId("world client")}
	test.client.args.Identity = func() *SidecarIdentity { return identity }
	return &evsTestWriter{world: world, server: server, gkm: gkm, test: test, repo: test.client.Repo(world.repoId)}
}

// Writes content to path, or removes it with nil.
func (self *evsTestWriter) write(t *testing.T, path string, content []byte) (*EvsWriteResult, error) {
	t.Helper()
	self.server.know(path)
	args := &EvsWriteArgs{Path: path, Remove: content == nil}
	if content != nil {
		args.Content = bytes.NewReader(content)
		args.Size = int64(len(content))
	}
	return self.repo.Write(context.Background(), args)
}

// Reads path back through the verifying reader, a fresh client's so nothing the writer cached helps it.
func (self *evsTestWriter) read(t *testing.T, path string) ([]byte, *EvsFileInfo, error) {
	t.Helper()
	reader := self.world.reader(t, evsTestId("check reader"))
	reader.client.args.Gkm = self.gkm
	reader.client.args.Transport = &evsTestTransport{handler: self.server}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	out := &bytes.Buffer{}
	info, err := reader.client.Repo(self.world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: path}, out)
	return out.Bytes(), info, err
}

// The newest committed entry version of path.
func (self *evsTestWriter) entry(t *testing.T, path string) *protocol.EvsEntryVersion {
	t.Helper()
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	state := self.world.paths[path]
	if state == nil || state.removal != nil {
		t.Fatalf("%s does not stand", path)
	}
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(state.versions[state.newest].entryBytes, entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

// Content of byteCount bytes from a label, with a byte changed at each of edits.
func evsTestEdited(label string, byteCount int, edits ...int) []byte {
	content := evsTestContent(label, byteCount)
	for _, at := range edits {
		content[at] ^= 0x5a
	}
	return content
}

// The checkpoint rules as a table: each rule and its twin a diff passes.
func TestEvsCheckpointRules(t *testing.T) {
	chain := func(diffs int, diffBytes uint64, keyGeneration uint64) *EvsChainState {
		return &EvsChainState{RecordCount: 1 + diffs, DiffCount: diffs, DiffByteCount: diffBytes, KeyGeneration: keyGeneration, Size: 4096}
	}
	cases := []struct {
		name string
		args *EvsCheckpointArgs
		want EvsCheckpointReason
	}{
		{name: "a diff", args: &EvsCheckpointArgs{Previous: chain(3, 300, 1), Size: 4096, Generation: 1, DiffMaxByteCount: 8 << 20}},
		{name: "a new file", args: &EvsCheckpointArgs{Size: 4096, Generation: 1, DiffMaxByteCount: 8 << 20}, want: EvsCheckpointNewFile},
		{name: "15 diffs", args: &EvsCheckpointArgs{Previous: chain(15, 300, 1), Size: 4096, Generation: 1, DiffMaxByteCount: 8 << 20}},
		{name: "16 diffs", args: &EvsCheckpointArgs{Previous: chain(16, 300, 1), Size: 4096, Generation: 1, DiffMaxByteCount: 8 << 20}, want: EvsCheckpointChainFull},
		{name: "a REMOVE generation past the chain's key", args: &EvsCheckpointArgs{Previous: chain(1, 10, 1), Size: 4096, RemoveSince: true, Generation: 2, DiffMaxByteCount: 8 << 20}, want: EvsCheckpointRemoveGeneration},
		{name: "forced", args: &EvsCheckpointArgs{Previous: chain(1, 10, 1), Size: 4096, Force: true, Generation: 1, DiffMaxByteCount: 8 << 20}, want: EvsCheckpointForced},
		{name: "past the phone's 1 MiB", args: &EvsCheckpointArgs{Previous: chain(1, 10, 1), Size: 2 << 20, Generation: 1, DiffMaxByteCount: 1 << 20}, want: EvsCheckpointNoDiff},
		{name: "at the phone's 1 MiB", args: &EvsCheckpointArgs{Previous: &EvsChainState{RecordCount: 1, Size: 1 << 20}, Size: 1 << 20, Generation: 1, DiffMaxByteCount: 1 << 20}},
		{name: "past 8 MiB", args: &EvsCheckpointArgs{Previous: chain(1, 10, 1), Size: 8<<20 + 1, Generation: 1, DiffMaxByteCount: 8 << 20}, want: EvsCheckpointChunked},
		{name: "a record past one segment", args: &EvsCheckpointArgs{Previous: chain(1, 10, 1), Size: 8<<20 - 1024, Generation: 1, DiffMaxByteCount: 8 << 20}, want: EvsCheckpointChunked},
		{name: "after chunks", args: &EvsCheckpointArgs{Previous: &EvsChainState{RecordCount: 3, Chunked: true, Size: 9 << 20}, Size: 4096, Generation: 1, DiffMaxByteCount: 8 << 20}, want: EvsCheckpointChunked},
		{name: "an inline chain of another generation", args: &EvsCheckpointArgs{Previous: &EvsChainState{RecordCount: 1, Inline: true, InlineGeneration: 1, Size: 100}, Size: 100, Generation: 2, DiffMaxByteCount: 8 << 20}, want: EvsCheckpointInlineGeneration},
		{name: "an inline chain of this generation", args: &EvsCheckpointArgs{Previous: &EvsChainState{RecordCount: 1, Inline: true, InlineGeneration: 2, Size: 100}, Size: 100, Generation: 2, DiffMaxByteCount: 8 << 20}},
	}
	for _, c := range cases {
		if got := EvsCheckpointBefore(c.args); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	after := []struct {
		name     string
		previous *EvsChainState
		delta    uint64
		size     uint64
		want     EvsCheckpointReason
	}{
		{name: "a small delta", previous: chain(2, 100, 1), delta: 100, size: 4096},
		{name: "diffs at half the file", previous: chain(2, 1948, 1), delta: 100, size: 4096},
		{name: "diffs past half the file", previous: chain(2, 1948, 1), delta: 101, size: 4096, want: EvsCheckpointDiffsHeavy},
		{name: "a delta outgrowing the file", previous: chain(0, 0, 1), delta: 4096, size: 4096, want: EvsCheckpointDeltaOutgrows},
	}
	for _, c := range after {
		if got := EvsCheckpointAfter(c.previous, c.delta, c.size); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

// A file written, then changed byte by byte: each write after the first a diff while the rules allow, the chain
// never past N + 1 locators, the 17th version a checkpoint again, and every version read back whole.
func TestEvsWriteChainNeverPassesNPlusOne(t *testing.T) {
	writer := newEvsTestWriter(t)
	const size = 20 * 1024
	content := evsTestEdited("chain", size)
	if _, err := writer.write(t, "chain.txt", content); err != nil {
		t.Fatal(err)
	}
	if chain := writer.entry(t, "chain.txt").GetChain(); len(chain) != 1 || chain[0].GetKind() != uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT) {
		t.Fatalf("the first version's chain: %v", chain)
	}
	for i := 1; i <= 2*EvsChainMaxRecordCount; i += 1 {
		content = append([]byte{}, content...)
		content[(i*997)%size] ^= byte(i)
		result, err := writer.write(t, "chain.txt", content)
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if result.PathVersion != uint64(i+1) {
			t.Fatalf("write %d: path version %d", i, result.PathVersion)
		}
		chain := writer.entry(t, "chain.txt").GetChain()
		if EvsChainMaxRecordCount < len(chain) {
			t.Fatalf("write %d: a chain of %d locators", i, len(chain))
		}
		if want := (i % EvsChainMaxRecordCount) + 1; len(chain) != want {
			t.Fatalf("write %d: a chain of %d locators, want %d", i, len(chain), want)
		}
		read, _, err := writer.read(t, "chain.txt")
		if err != nil || !bytes.Equal(read, content) {
			t.Fatalf("write %d read back: %v", i, err)
		}
	}
}

// A small file rides inline, its diffs too while the chain stays within 16 KiB; read back whole each time.
func TestEvsWriteSmallFileInline(t *testing.T) {
	writer := newEvsTestWriter(t)
	content := evsTestEdited("small", 2000)
	if _, err := writer.write(t, "small.txt", content); err != nil {
		t.Fatal(err)
	}
	content[10] ^= 1
	if _, err := writer.write(t, "small.txt", content); err != nil {
		t.Fatal(err)
	}
	chain := writer.entry(t, "small.txt").GetChain()
	if len(chain) != 2 {
		t.Fatalf("a chain of %d", len(chain))
	}
	for _, locator := range chain {
		if locator.GetKind() != uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE) {
			t.Fatalf("a locator of kind %d", locator.GetKind())
		}
	}
	read, info, err := writer.read(t, "small.txt")
	if err != nil || !bytes.Equal(read, content) || info.Size != 2000 || info.Mode != EvsGitModeFile {
		t.Fatalf("read back: %v %+v", err, info)
	}
}

// A file past 8 MiB is 4 MiB chunks; a change inside one chunk rewrites only that chunk, the others cited as they
// stood; a REMOVE generation since rewrites every chunk.
func TestEvsWriteChunkedRewritesOnlyTouchedChunks(t *testing.T) {
	writer := newEvsTestWriter(t)
	const size = 9*1024*1024 + 123
	content := evsTestEdited("chunked", size)
	if _, err := writer.write(t, "big.bin", content); err != nil {
		t.Fatal(err)
	}
	first := writer.entry(t, "big.bin").GetChain()
	if len(first) != 3 {
		t.Fatalf("%d chunks", len(first))
	}
	uploads := len(writer.server.uploads)
	content = append([]byte{}, content...)
	content[5*1024*1024] ^= 1
	if _, err := writer.write(t, "big.bin", content); err != nil {
		t.Fatal(err)
	}
	second := writer.entry(t, "big.bin").GetChain()
	if len(second) != 3 || !proto.Equal(first[0], second[0]) || proto.Equal(first[1], second[1]) || !proto.Equal(first[2], second[2]) {
		t.Fatal("chunks other than the touched one were rewritten, or it was not")
	}
	if got := len(writer.server.uploads) - uploads; got != 1 {
		t.Errorf("%d uploads for one touched chunk", got)
	}
	read, _, err := writer.read(t, "big.bin")
	if err != nil || !bytes.Equal(read, content) {
		t.Fatalf("read back: %v", err)
	}
	// a REMOVE generation since the chain's key: every chunk anew
	writer.gkm.stateLock.Lock()
	writer.gkm.newest = 2
	writer.gkm.causes[2] = GkmCauseRemove
	writer.gkm.stateLock.Unlock()
	writer.world.generation = 2
	content[0] ^= 1
	if _, err := writer.write(t, "big.bin", content); err != nil {
		t.Fatal(err)
	}
	third := writer.entry(t, "big.bin").GetChain()
	for i := range third {
		if proto.Equal(third[i], second[i]) {
			t.Errorf("chunk %d kept past a REMOVE generation", i)
		}
	}
}

// A creation after a removal continues the path's versions at max(b, m) + 1; a removal is one of its versions.
func TestEvsWriteCreationAfterRemovalContinuesVersions(t *testing.T) {
	writer := newEvsTestWriter(t)
	for i := 0; i < 3; i += 1 {
		if _, err := writer.write(t, "x.txt", evsTestEdited("x", 100, i)); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := writer.write(t, "x.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	if removed.PathVersion != 4 {
		t.Errorf("the removal's path version %d", removed.PathVersion)
	}
	if _, _, err := writer.read(t, "x.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("a removed path read: %v", err)
	}
	created, err := writer.write(t, "x.txt", evsTestEdited("x again", 100))
	if err != nil {
		t.Fatal(err)
	}
	if want := max(removed.Version, 4) + 1; created.PathVersion != want {
		t.Errorf("re-created at %d, want %d", created.PathVersion, want)
	}
	if _, err := writer.write(t, "never.txt", nil); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("a removal of a path never written: %v", err)
	}
}

// Reserved names and refs, versioning off, and a git-mode ref are refused before anything is sent.
func TestEvsWriteRefusesReservedAndUnsupported(t *testing.T) {
	writer := newEvsTestWriter(t)
	reads := writer.world.reads
	cases := []struct {
		name string
		args *EvsWriteArgs
		is   error
	}{
		{name: ".ur-index/", args: &EvsWriteArgs{Path: ".ur-index/postings", Content: bytes.NewReader([]byte("x")), Size: 1}, is: ErrEvsReservedPath},
		{name: "ur/index", args: &EvsWriteArgs{RefName: []byte("ur/index"), Path: "a", Content: bytes.NewReader([]byte("x")), Size: 1}, is: ErrEvsReservedPath},
		{name: "ur/lfs", args: &EvsWriteArgs{RefName: []byte("ur/lfs"), Path: "a", Content: bytes.NewReader([]byte("x")), Size: 1}, is: ErrEvsReservedPath},
		{name: "versioning off", args: &EvsWriteArgs{Path: "a", Content: bytes.NewReader([]byte("x")), Size: 1, Versioning: "off"}, is: ErrEvsFormatUnsupported},
		{name: "content shorter than its size", args: &EvsWriteArgs{Path: "a", Content: bytes.NewReader([]byte("x")), Size: 2}, is: ErrEvsWriteInvalid},
	}
	for _, c := range cases {
		if _, err := writer.repo.Write(context.Background(), c.args); !errors.Is(err, c.is) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if writer.world.reads != reads || 0 < len(writer.server.postedStatements) {
		t.Error("a refused write sent something")
	}
	if _, err := writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Writes: []*EvsPathWrite{
		{Path: "a", Content: bytes.NewReader([]byte("x"))}, {Path: "a", Content: bytes.NewReader([]byte("y"))},
	}}); !errors.Is(err, ErrEvsWriteInvalid) {
		t.Errorf("a path written twice: %v", err)
	}
}

// A file created under directories that do not stand creates each below the root, each naming its child; a second
// file under them adds a row to the deepest only; removing a file removes its row.
func TestEvsWriteDirectoryDeltas(t *testing.T) {
	writer := newEvsTestWriter(t)
	if _, err := writer.write(t, "d/e/one.txt", []byte("one")); err != nil {
		t.Fatal(err)
	}
	d := writer.entry(t, "d")
	e := writer.entry(t, "d/e")
	if d.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) || len(d.GetNames().GetNames()) != 1 ||
		len(e.GetNames().GetNames()) != 1 || !bytes.Equal(e.GetNames().GetNames()[0].GetToken(), writer.world.tokens("d/e/one.txt").Last().Bytes()) {
		t.Fatalf("the directories created: %v %v", d, e)
	}
	if _, err := writer.write(t, "d/e/two.txt", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if e := writer.entry(t, "d/e"); e.GetVersion() != 2 || len(e.GetNames().GetNames()) != 1 {
		t.Errorf("the second file's delta: %v", e)
	}
	if d2 := writer.entry(t, "d"); d2.GetVersion() != d.GetVersion() {
		t.Error("a standing parent's parent changed")
	}
	if _, err := writer.write(t, "d/e/one.txt", nil); err != nil {
		t.Fatal(err)
	}
	if e := writer.entry(t, "d/e"); len(e.GetNames().GetRemovedTokens()) != 1 {
		t.Errorf("the removal's delta: %v", e)
	}
	// a removal below the root, its parent's delta beside it in one statement, reads as the path's own removal
	if _, _, err := writer.read(t, "d/e/one.txt"); !errors.Is(err, ErrEvsPathAbsent) {
		t.Errorf("a removed file below a directory read: %v", err)
	}
	if read, _, err := writer.read(t, "d/e/two.txt"); err != nil || string(read) != "two" {
		t.Errorf("read back: %v", err)
	}
	// a removed file's name takes a directory, created on the removal's versions
	if _, err := writer.write(t, "d/e/one.txt/under", []byte("x")); err != nil {
		t.Errorf("a path created under a removed file's name: %v", err)
	}
	if read, _, err := writer.read(t, "d/e/one.txt/under"); err != nil || string(read) != "x" {
		t.Errorf("read back under a removed file's name: %v", err)
	}
	if one := writer.entry(t, "d/e/one.txt"); one.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) || one.GetVersion() <= 2 {
		t.Errorf("the directory on a removed file's name: %v", one)
	}
	if _, err := writer.write(t, "d/e/two.txt/under", []byte("x")); !errors.Is(err, ErrEvsPathKind) {
		t.Errorf("a path created under a file: %v", err)
	}
}

// Question evs1-m2-24-root-directory-names, option 1: a top-level creation adds the name's row to the root's table,
// the first creating the root, a creation under a new top-level directory adds the directory's, and a top-level
// removal drops its token; the root lists the names standing, and a write of the root itself is refused.
func TestEvsWriteTopLevelPathsChangeTheRoot(t *testing.T) {
	writer := newEvsTestWriter(t)
	if _, err := writer.write(t, "top.txt", []byte("top")); err != nil {
		t.Fatal(err)
	}
	root := writer.entry(t, "")
	if root.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) || len(root.GetNames().GetNames()) != 1 ||
		!bytes.Equal(root.GetNames().GetNames()[0].GetToken(), writer.world.tokens("top.txt").Last().Bytes()) {
		t.Fatalf("the root after a top-level creation: %v", root)
	}
	if _, err := writer.write(t, "d/x.txt", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if root := writer.entry(t, ""); len(root.GetNames().GetNames()) != 1 || root.GetVersion() <= 1 {
		t.Fatalf("the root's delta for a new top-level directory: %v", root)
	}
	before := writer.entry(t, "").GetVersion()
	if _, err := writer.write(t, "d/y.txt", []byte("y")); err != nil {
		t.Fatal(err)
	}
	if after := writer.entry(t, "").GetVersion(); after != before {
		t.Fatal("a write below a standing directory changed the root")
	}
	if _, err := writer.write(t, "top.txt", nil); err != nil {
		t.Fatal(err)
	}
	if root := writer.entry(t, ""); len(root.GetNames().GetRemovedTokens()) != 1 {
		t.Fatalf("the root's delta for a top-level removal: %v", root)
	}
	reader := writer.world.reader(t, evsTestId("root reader"))
	reader.client.args.Gkm = writer.gkm
	reader.client.args.Transport = &evsTestTransport{handler: writer.server}
	reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
	listing, err := reader.client.Repo(writer.world.repoId).List(context.Background(), &EvsReadArgs{Path: ""})
	if err != nil || len(listing.Entries) != 1 || string(listing.Entries[0].Name) != "d" {
		t.Fatalf("the root's listing: %v %v", listing, err)
	}
	if _, err := writer.write(t, "", []byte("root")); !errors.Is(err, ErrEvsTokenInvalid) {
		t.Fatalf("a write of the root itself: %v", err)
	}
}

// A change may name the root only as a directory's delta: a file written at the empty token path and a removal of it
// are refused by the payload's checks.
func TestEvsTheRootTakesOnlyADirectorysDelta(t *testing.T) {
	world := newEvsTestWorld(t)
	file := &EvsPushPlan{
		RepoId: world.repoId, RefId: world.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: evsTestId("root push"), BaseChain: EvsChainStart(world.repoId, world.refId), Generation: 1,
		GroupId: evsTestId("world group"), GenerationCommitment: evsTestBytes("commitment 1", 32), PathEpoch: 1,
		Auth: &bridge.AuthPin{Version: 1, Chain: evsTestBytes("auth chain", 32)}, SignerSidecarId: world.signer.sidecarId,
		ClientId: evsTestId("world client"), TimeMs: 1767225600000, SealedMetadata: append(evsTestBytes("metadata", 32), evsTestBytes("metadata tail", 16)...),
		Changes: []*EvsPlannedChange{{TokenPath: EvsTokenPath{}, EntryVersion: world.fileEntry([]byte("a file"), false, 1, evsTestId("root push"), 0, nil)}},
	}
	built, err := NewEvsStatementBuilder(world.signer.sign).Build(file)
	if err == nil {
		_, err = EvsCheckPayload(built.Statement, built.Payload)
	}
	if !errors.Is(err, ErrEvsPushInvalid) {
		t.Fatalf("a file at the root: %v", err)
	}
	removal := &EvsPushPlan{
		RepoId: world.repoId, RefId: world.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: evsTestId("root removal"), BaseVersion: 0, BaseChain: EvsChainStart(world.repoId, world.refId), Generation: 1,
		GroupId: evsTestId("world group"), GenerationCommitment: evsTestBytes("commitment 1", 32), PathEpoch: 1,
		Auth: &bridge.AuthPin{Version: 1, Chain: evsTestBytes("auth chain", 32)}, SignerSidecarId: world.signer.sidecarId,
		ClientId: evsTestId("world client"), TimeMs: 1767225600000, SealedMetadata: append(evsTestBytes("metadata", 32), evsTestBytes("metadata tail", 16)...),
		Changes: []*EvsPlannedChange{{TokenPath: EvsTokenPath{}, BaseEntryVersion: 1}},
	}
	built, err = NewEvsStatementBuilder(world.signer.sign).Build(removal)
	if err == nil {
		_, err = EvsCheckPayload(built.Statement, built.Payload)
	}
	if !errors.Is(err, ErrEvsPushInvalid) {
		t.Fatalf("a removal of the root: %v", err)
	}
}

// The epochs and token paths a checked change's source paths name.
func evsTestSourcePathsOf(change *EvsCheckedChange) map[uint64]EvsTokenPath {
	sources := map[uint64]EvsTokenPath{}
	for _, encoded := range change.SourcePaths {
		sourcePath := &protocol.EvsSourcePath{}
		if proto.Unmarshal(encoded, sourcePath) != nil {
			continue
		}
		if tokenPath, err := ParseEvsChangedTokenPath(sourcePath.GetTokenPath()); err == nil {
			sources[sourcePath.GetEpoch()] = tokenPath
		}
	}
	return sources
}

// POST .../path-epoch: a part, its signature the world signer's, held under its map's hash; another part under its key
// answers MAP_SOURCE, as evs does.
func (self *evsTestPushServer) serveMapPart(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	mapRequest := &protocol.EvsPathMapRequest{}
	if err := proto.Unmarshal(body, mapRequest); err != nil || len(mapRequest.GetPathMapSha256()) != 32 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	signed, pathMap, err := ParseEvsPathMap(mapRequest.GetPart())
	if err != nil || !ed25519Verify(self.world.signer.publicKey(), signed) {
		self.t.Errorf("a map part that does not check: %v", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	self.stateLock.Lock()
	onMapPart := self.onMapPart
	self.stateLock.Unlock()
	if onMapPart != nil {
		if err := onMapPart(pathMap.GetPart()); err != nil {
			evsTestRefuse(writer, &evsTestRefusal{status: http.StatusServiceUnavailable, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE}})
			return
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.mapParts == nil {
		self.mapParts, self.partUploads = map[string]map[uint32][]byte{}, map[uint32]int{}
	}
	key := hex.EncodeToString(mapRequest.GetPathMapSha256())
	if self.mapParts[key] == nil {
		self.mapParts[key] = map[uint32][]byte{}
	}
	if held, ok := self.mapParts[key][pathMap.GetPart()]; ok && !bytes.Equal(held, mapRequest.GetPart()) {
		evsTestRefuse(writer, &evsTestRefusal{status: http.StatusConflict, reply: &protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE}})
		return
	}
	self.mapParts[key][pathMap.GetPart()] = mapRequest.GetPart()
	self.partUploads[pathMap.GetPart()] += 1
	writer.WriteHeader(http.StatusOK)
}

// A PATH_EPOCH as 5e checks it and step 7 commits it: a newer epoch, a free source slot, every part present under the
// map's hash in order, its source at or below the head with its chain and of the current epoch (the between fence),
// and its tail moving every path a version after the source created; then the cut-over.
func (self *evsTestPushServer) commitPathEpoch(statement *EvsStatement, payload []byte) (uint64, *evsTestRefusal) {
	refuse := func(status int, code protocol.EvsRefusalCode, paths ...*protocol.EvsTokenPath) (uint64, *evsTestRefusal) {
		return 0, &evsTestRefusal{status: status, reply: &protocol.EvsRefusalReply{Code: code, Paths: paths}}
	}
	push := statement.Push
	checked, err := EvsCheckPayload(statement, payload)
	if err != nil {
		self.t.Errorf("a PATH_EPOCH whose payload does not check: %v", err)
		return refuse(http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	}
	self.stateLock.Lock()
	parts := self.mapParts[hex.EncodeToString(push.GetPathMapSha256())]
	self.stateLock.Unlock()
	world := self.world
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	current := world.currentWithLock()
	switch {
	case push.GetPathEpoch() <= current:
		return refuse(http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH)
	case 3 <= len(world.sourceEpochs):
		return refuse(http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_EPOCH_SOURCES_FULL)
	}
	ordered := [][]byte{}
	for k := uint32(1); ; k += 1 {
		part, ok := parts[k]
		if !ok {
			break
		}
		ordered = append(ordered, part)
	}
	if len(ordered) == 0 || !bytes.Equal(EvsPathMapSha256(ordered), push.GetPathMapSha256()) {
		return refuse(http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_MAP_PARTS)
	}
	head := uint64(len(world.commits))
	source := push.GetMapSourceVersion()
	sourceChain := EvsChainStart(world.repoId, world.refId)
	sourceEpoch := uint64(1)
	if 0 < source && source <= head {
		sourceChain = world.commits[source-1].chain
		sourceEpoch = max(1, world.commits[source-1].parsed.Push.GetPathEpoch())
	}
	if head < source || !bytes.Equal(sourceChain[:], push.GetMapSourceChain()) || sourceEpoch != current {
		return refuse(http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE)
	}
	moved := map[string]bool{}
	for _, item := range checked.TailMoves {
		move := &protocol.EvsPathMove{}
		proto.Unmarshal(item, move)
		for _, sourcePath := range move.GetSources() {
			if sourcePath.GetEpoch() == current {
				tokenPath, _ := ParseEvsChangedTokenPath(sourcePath.GetTokenPath())
				moved[tokenPath.KeyString()] = true
			}
		}
	}
	uncovered := []*protocol.EvsTokenPath{}
	for version := source + 1; version <= head; version += 1 {
		for _, change := range world.commits[version-1].parsed.Changes {
			if change.Change.GetBaseEntryVersion() == 0 && change.WritesEntry() && 0 < len(change.TokenPath) && !moved[change.TokenPath.KeyString()] {
				uncovered = append(uncovered, change.TokenPath.Proto())
			}
		}
		if tree := world.commits[version-1].built.ChangeTree; tree != nil {
			self.t.Errorf("the stand-in's tail check reads inline lists only")
		}
	}
	if 0 < len(uncovered) {
		return refuse(http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, uncovered...)
	}
	var baseChain [32]byte = EvsChainStart(world.repoId, world.refId)
	if 0 < head {
		baseChain = world.commits[head-1].chain
	}
	if push.GetBaseVersion() != head || !bytes.Equal(push.GetBaseChain(), baseChain[:]) {
		if world.mode == protocol.EvsRefMode_EVS_REF_GIT {
			// 5f's TIP
			return refuse(http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD)
		}
		return refuse(http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
	}
	chain := EvsChainNext(baseChain, Id(push.GetPushId()), statement.Sha256)
	world.commits = append(world.commits, &evsTestCommit{
		statement: statement.Bytes, parsed: statement, chain: chain,
		built: &EvsBuiltPush{Statement: statement, Payload: payload},
	})
	world.sourceEpochs = append([]uint64{current}, world.sourceEpochs...)
	world.currentEpoch = push.GetPathEpoch()
	world.generation = max(world.generation, push.GetGeneration())
	world.due = nil
	for _, state := range world.paths {
		if state.home == 0 {
			state.home = 1
		}
	}
	self.stateLock.Lock()
	self.committedMap = append(self.committedMap, ordered)
	self.stateLock.Unlock()
	return uint64(len(world.commits)), nil
}

// Whether signed's signature verifies under publicKey as a path map part's.
func ed25519Verify(publicKey []byte, signed *bridge.Signed) bool {
	return bridge.VerifySigned(signed, "evs-path-epoch", bridge.SignedType_SIGNED_EVS_PATH_MAP, bridge.SignedKeyAlgEd25519, publicKey) == nil
}

// DESIGN-DETAILS 8.2.10's rekey on a git-mode ref, at the planner: a rekey write, a forced checkpoint held to the
// version it read, re-checkpoints the standing blob as the REKEY shape; one whose new blob or mode is not the standing
// version's is ErrEvsRekeyChanged, and any other write ErrEvsGitRef; neither sends anything.
func TestEvsPlanTakesOnlyRekeyWritesOnAGitModeRef(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.world.mode = protocol.EvsRefMode_EVS_REF_GIT
	writer.world.push(&evsTestChange{path: "tree.txt", content: []byte("tree")})
	writer.server.know("tree.txt")
	rekey := func(content []byte, mode uint32) error {
		_, err := writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Writes: []*EvsPathWrite{{
			Path: "tree.txt", Content: bytes.NewReader(content), Mode: mode, ForceCheckpoint: true, IfVersion: 1,
		}}})
		return err
	}
	if err := rekey([]byte("another tree"), 0); !errors.Is(err, ErrEvsRekeyChanged) {
		t.Errorf("a rekey write changing the oid: %v", err)
	}
	if err := rekey([]byte("tree"), EvsGitModeExecutable); !errors.Is(err, ErrEvsRekeyChanged) {
		t.Errorf("a rekey write changing the mode: %v", err)
	}
	unforced, err := writer.repo.WritePaths(context.Background(), &EvsWritePathsArgs{Writes: []*EvsPathWrite{{
		Path: "tree.txt", Content: bytes.NewReader([]byte("tree")), IfVersion: 1,
	}}})
	if !errors.Is(err, ErrEvsGitRef) || unforced != nil {
		t.Errorf("a write that is no rekey: %v", err)
	}
	if len(writer.server.postedStatements) != 0 || len(writer.server.uploads) != 0 {
		t.Fatal("a refused write sent something")
	}
	if err := rekey([]byte("tree"), 0); err != nil {
		t.Fatalf("the rekey write: %v", err)
	}
	read, info, err := writer.read(t, "tree.txt")
	if err != nil || string(read) != "tree" || info.Version != 2 {
		t.Errorf("read back: %q at %d: %v", read, info.Version, err)
	}
}
