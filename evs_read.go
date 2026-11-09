// Head reads (§11.9): ReadHead's and List's round trips to POST /evs/v1/repos/<id>/read, the verifying reader's checks
// over what comes back, the pin and read records it raises, and the receipt gate before anything is decrypted.
//
// A read names its ref by id, which any reader derives from K_ref for a named ref (§11.6), and its path by tokens in
// the ref's current path epoch and each listed source, computed here from the plaintext path, which never leaves the
// device (I-13, X2). The current epoch comes from the last verified head; a ref this client has not read yet takes
// one round for its head first. A path read before is read from its read record's pin, so every statement since that
// read is checked against it (g0-recheck-0-head-reader-read-paths#1), and a version below the record is refused and
// alarmed as tampering. A hint naming a newer version sends the read past evs's head cache.
//
// Objects the reply carries (segment ranges, slots) stream into spills (evs_reconstruct.go), never a whole reply in
// memory. Nothing is decrypted before the head and the path verify and the head is pinned, and nothing at all of an
// owner-bound repo this sidecar does not write until EVS1-M2-29's receipt gate deposits a read receipt: until that
// gate is wired such reads are refused, as §8.19's owner-bound shares stay closed.
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A read of an owner-bound repo by a sidecar that does not write it needs a read receipt deposited first
	// (§16.8, D-MCP-18), and the gate that deposits it (EVS1-M2-29) is not wired: the read is refused.
	ErrEvsReceiptGate = errors.New("evs: read receipt gate not wired")
	// The path is not there at the version read: never created, or removed, its removal's evidence checked.
	ErrEvsPathAbsent = errors.New("evs: path absent")
	// An overlay's path the overlay holds no version of: its base ref answers it, which head mode does not read.
	ErrEvsOverlayBase = errors.New("evs: path on the overlay's base")
)

// Called before any object of a read is decrypted, with the ids of the objects it names (segments and slots): the
// receipt gate EVS1-M2-29 fills, which deposits a read receipt and awaits evs's 200 (§16.8). An error refuses the
// read.
type EvsPreDecryptFunction func(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error

// Installs the receipt gate. nil leaves the default, which refuses reads of owner-bound repos this sidecar does not
// write.
func (self *EvsClient) SetPreDecrypt(preDecrypt EvsPreDecryptFunction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.preDecryptHook = preDecrypt
}

// The receipt gate before decrypting objectIds of a read.
func (self *EvsClient) preDecrypt(ctx context.Context, repoId Id, refId Id, objectIds [][]byte) error {
	hook := func() EvsPreDecryptFunction {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.preDecryptHook
	}()
	if hook != nil {
		return hook(ctx, repoId, refId, objectIds)
	}
	state, err := self.verifier.config()
	if err != nil {
		return err
	}
	repo := state.Repo(repoId)
	if repo == nil {
		return fmt.Errorf("%w: a repo the state does not hold", ErrEvsNoConfig)
	}
	if aclRepoKindOwnerBound(repo.GetKind()) && !slices.Contains(state.RepoWriters(repoId), self.args.Identity().SidecarId) {
		return ErrEvsReceiptGate
	}
	return nil
}

// A path as its raw names, refusing an empty component.
func evsPathNames(path string) ([][]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: the root has no entry in format 1 (question evs1-m2-24-root-directory-names)", ErrEvsTokenInvalid)
	}
	names := [][]byte{}
	for _, name := range strings.Split(path, "/") {
		if err := checkEvsPathName([]byte(name)); err != nil {
			return nil, err
		}
		names = append(names, []byte(name))
	}
	return names, nil
}

// The repo keys one read uses, each generation asked of gkm once.
type evsReadKeys struct {
	repo         *EvsRepo
	generations  map[uint64]*EvsRepoKey
	manifestKeys map[uint64]*EvsManifestKey
	fekKeys      map[uint64]*EvsFekKey
	pathKeys     map[uint64]*EvsPathKey
}

// A read's keys, none asked yet.
func newEvsReadKeys(repo *EvsRepo) *evsReadKeys {
	return &evsReadKeys{
		repo:         repo,
		generations:  map[uint64]*EvsRepoKey{},
		manifestKeys: map[uint64]*EvsManifestKey{},
		fekKeys:      map[uint64]*EvsFekKey{},
		pathKeys:     map[uint64]*EvsPathKey{},
	}
}

// RK_g, through the ladder from what this sidecar holds (§10.5).
func (self *evsReadKeys) repoKey(ctx context.Context, generation uint64) (*EvsRepoKey, error) {
	if key := self.generations[generation]; key != nil {
		return key, nil
	}
	key, err := self.repo.client.args.Gkm.RepoKey(ctx, self.repo.repoId, generation)
	if err != nil {
		return nil, err
	}
	self.generations[generation] = key
	return key, nil
}

// manifest_g.
func (self *evsReadKeys) manifest(ctx context.Context, generation uint64) (*EvsManifestKey, error) {
	if key := self.manifestKeys[generation]; key != nil {
		return key, nil
	}
	repoKey, err := self.repoKey(ctx, generation)
	if err != nil {
		return nil, err
	}
	key, err := NewEvsManifestKey(repoKey)
	if err != nil {
		return nil, err
	}
	self.manifestKeys[generation] = key
	return key, nil
}

// fek_g.
func (self *evsReadKeys) fek(ctx context.Context, generation uint64) (*EvsFekKey, error) {
	if key := self.fekKeys[generation]; key != nil {
		return key, nil
	}
	repoKey, err := self.repoKey(ctx, generation)
	if err != nil {
		return nil, err
	}
	key, err := NewEvsFekKey(repoKey)
	if err != nil {
		return nil, err
	}
	self.fekKeys[generation] = key
	return key, nil
}

// K_path_p.
func (self *evsReadKeys) path(ctx context.Context, epoch uint64) (*EvsPathKey, error) {
	if key := self.pathKeys[epoch]; key != nil {
		return key, nil
	}
	repoKey, err := self.repoKey(ctx, epoch)
	if err != nil {
		return nil, err
	}
	key, err := NewEvsPathKey(repoKey)
	if err != nil {
		return nil, err
	}
	self.pathKeys[epoch] = key
	return key, nil
}

// The ref a read names: its id, from K_ref for a named ref.
func (self *EvsRepo) resolveRefId(ctx context.Context, refName []byte, refId *Id) (Id, error) {
	if refId != nil {
		return *refId, nil
	}
	if refName == nil {
		refName = EvsMainRefName
	}
	repoKey, err := self.client.args.Gkm.CurrentRepoKey(ctx, self.repoId)
	if err != nil {
		return Id{}, err
	}
	refKey, err := NewEvsRefKey(repoKey)
	if err != nil {
		return Id{}, err
	}
	return EvsRefId(refKey, refName)
}

// One path a read asks for: its plaintext, its names, and its token path in each epoch asked.
type evsReadPath struct {
	path  string
	names [][]byte
	// the current epoch's, then each source's
	epochPaths []*protocol.EvsSourcePath
	current    EvsTokenPath
	record     *EvsReadRecord
}

// What one verified read gives its caller.
type evsReadResult struct {
	refId   Id
	head    *EvsVerifiedHead
	keys    *evsReadKeys
	paths   []*evsReadPath
	replies []*EvsVerifiedPath
	objects *evsReadObjects
}

// Reads paths of a ref at version (0 the newest): the head first when the ref's path epoch is not known, then the
// paths; verifies the head and every path, checks the read records, pins the head and raises the records, all before
// the caller decrypts anything. A path's own failure fails the read: the caller asked for it.
func (self *EvsRepo) read(ctx context.Context, refId Id, paths []string, version uint64, fresh bool) (*evsReadResult, error) {
	keys := newEvsReadKeys(self)
	epoch := self.client.refEpoch(self.repoId, refId)
	if epoch == nil && 0 < len(paths) {
		// one round for the head alone, which gives the epoch the paths' tokens are asked in; nothing of it is
		// trusted or pinned, since the next round's head is verified and a moved epoch asks again
		request := &protocol.EvsReadRequest{RefId: refId.Bytes(), Fresh: fresh}
		if pin, ok, err := self.client.pins.Pin(self.repoId, refId); err == nil && ok {
			request.PinVersion = pin.Version
		}
		reply, objects, err := self.client.postRead(ctx, self.repoId, request)
		if err != nil {
			return nil, err
		}
		objects.close()
		epoch = reply.head.GetPathEpoch()
	}
	readPaths := []*evsReadPath{}
	for _, path := range paths {
		readPath, err := self.tokenize(ctx, keys, refId, path, epoch)
		if err != nil {
			return nil, err
		}
		readPaths = append(readPaths, readPath)
	}
	result, err := self.readRound(ctx, refId, keys, readPaths, version, fresh)
	if err != nil {
		return nil, err
	}
	if !evsSamePathEpoch(epoch, result.head.Head.GetPathEpoch()) && 0 < len(paths) {
		// the epoch moved between the rounds: the tokens asked are an older epoch's, which a source may still hold,
		// but a reader asks again in the current one
		result.objects.close()
		return self.read(ctx, refId, paths, version, true)
	}
	return result, nil
}

// Whether two path epochs name the same current epoch and sources.
func evsSamePathEpoch(a *protocol.EvsPathEpoch, b *protocol.EvsPathEpoch) bool {
	if a.GetCurrent() != b.GetCurrent() || len(a.GetSources()) != len(b.GetSources()) {
		return false
	}
	for i, source := range a.GetSources() {
		if source.GetEpoch() != b.GetSources()[i].GetEpoch() {
			return false
		}
	}
	return true
}

// A path's tokens in the current epoch and each source, and its read record.
func (self *EvsRepo) tokenize(ctx context.Context, keys *evsReadKeys, refId Id, path string, epoch *protocol.EvsPathEpoch) (*evsReadPath, error) {
	names, err := evsPathNames(path)
	if err != nil {
		return nil, err
	}
	readPath := &evsReadPath{path: path, names: names}
	epochs := []uint64{max(1, epoch.GetCurrent())}
	for _, source := range epoch.GetSources() {
		epochs = append(epochs, source.GetEpoch())
	}
	for i, pathEpoch := range epochs {
		pathKey, err := keys.path(ctx, pathEpoch)
		if err != nil {
			return nil, err
		}
		tokenPath, err := EvsPathTokens(pathKey, names)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			readPath.current = tokenPath
		}
		readPath.epochPaths = append(readPath.epochPaths, &protocol.EvsSourcePath{Epoch: pathEpoch, TokenPath: tokenPath.Components()})
	}
	record, ok, err := self.client.pins.ReadRecord(self.repoId, refId, path)
	if err != nil {
		return nil, err
	}
	if ok {
		readPath.record = record
	}
	return readPath, nil
}

// One round: the request, its framed reply, the head's and every path's checks, the read records' rule, then the
// pin and the records raised.
func (self *EvsRepo) readRound(ctx context.Context, refId Id, keys *evsReadKeys, paths []*evsReadPath, version uint64, fresh bool) (*evsReadResult, error) {
	fromVersion := uint64(0)
	fromChain := EvsChainStart(self.repoId, refId)
	pin, pinned, err := self.client.pins.Pin(self.repoId, refId)
	if err != nil {
		return nil, err
	}
	if pinned {
		fromVersion, fromChain = pin.Version, pin.Chain
	}
	for _, path := range paths {
		// a recorded path reads from its last read's pin, so every statement since is checked against it
		if path.record != nil && path.record.PinVersion < fromVersion && path.record.PinChain != nil {
			fromVersion, fromChain = path.record.PinVersion, *path.record.PinChain
		}
	}
	if pinned && pin.Version < self.client.hintedVersion(self.repoId, refId) {
		fresh = true
	}
	request := &protocol.EvsReadRequest{RefId: refId.Bytes(), PinVersion: fromVersion, Fresh: fresh}
	for _, path := range paths {
		request.Paths = append(request.Paths, &protocol.EvsReadPath{TokenPaths: path.epochPaths, Version: version})
	}
	reply, objects, err := self.client.postRead(ctx, self.repoId, request)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			objects.close()
		}
	}()
	head, err := self.client.verifier.VerifyHead(ctx, &EvsHeadRead{
		RepoId:      self.repoId,
		RefId:       refId,
		Head:        reply.head,
		FromVersion: fromVersion,
		FromChain:   fromChain,
		Statements:  reply.statements,
		Behind:      reply.behind,
	})
	if err != nil {
		return nil, err
	}
	if len(reply.paths) != len(paths) {
		return nil, fmt.Errorf("%w: %d path replies for %d paths", ErrEvsReplyInvalid, len(reply.paths), len(paths))
	}
	verifiedPaths := []*EvsVerifiedPath{}
	for i, path := range paths {
		verified, err := self.client.verifier.VerifyPath(head, path.current, reply.paths[i])
		if err != nil {
			return nil, err
		}
		// an older version asked for by number is history, not a rollback
		if version == 0 && path.record != nil && verified.Entry != nil && verified.Entry.GetVersion() < path.record.EntryVersion {
			self.client.alarm(self.repoId, refId, SidecarEvsAlarmTamper, path.path, nil)
			return nil, fmt.Errorf("%w: a version below the one this device read", ErrEvsEntryRefused)
		}
		verifiedPaths = append(verifiedPaths, verified)
	}
	if err := self.client.verifier.Pin(head); err != nil {
		return nil, err
	}
	self.client.setRefEpoch(self.repoId, refId, head.Head.GetPathEpoch())
	records := []*EvsReadRecord{}
	for i, path := range paths {
		if version != 0 || verifiedPaths[i].Entry == nil {
			continue
		}
		chain := head.Chain
		records = append(records, &EvsReadRecord{
			RefId:        refId,
			Path:         path.path,
			EntryVersion: verifiedPaths[i].Entry.GetVersion(),
			PinVersion:   head.Version,
			PinChain:     &chain,
			UsedAt:       self.client.clock.Now(),
		})
	}
	if err := self.client.pins.RaiseReadRecords(self.repoId, records); err != nil {
		return nil, err
	}
	keep = true
	return &evsReadResult{refId: refId, head: head, keys: keys, paths: paths, replies: verifiedPaths, objects: objects}, nil
}

// A read reply's parts as they arrived.
type evsReadReply struct {
	head       *protocol.EvsHeadSummary
	statements []*protocol.EvsReadStatement
	behind     uint64
	paths      []*protocol.EvsReadPathReply
}

// POST /evs/v1/repos/<id>/read, its frames read one at a time: the head first, then statements, paths and objects,
// each object's bytes into a spill as they come.
func (self *EvsClient) postRead(ctx context.Context, repoId Id, request *protocol.EvsReadRequest) (*evsReadReply, *evsReadObjects, error) {
	response, err := self.http.send(ctx, &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/read",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(repoId) + "/read",
		repoId: repoId,
		role:   evsScopeRead,
		body:   request,
		retry:  true,
	})
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	objects := newEvsReadObjects(self)
	reply := &evsReadReply{}
	frames := NewEvsReadFrames(response.Body)
	for {
		frame, err := frames.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			objects.close()
			return nil, nil, err
		}
		if frame.GetHead() != nil {
			if reply.head != nil {
				objects.close()
				return nil, nil, fmt.Errorf("%w: a second head", ErrEvsReplyInvalid)
			}
			reply.head = frame.GetHead()
		}
		if frame.GetStatement() != nil {
			reply.statements = append(reply.statements, frame.GetStatement())
		}
		if frame.GetBehind() != 0 {
			reply.behind = frame.GetBehind()
		}
		if frame.GetPath() != nil {
			reply.paths = append(reply.paths, frame.GetPath())
		}
		if frame.GetObject() != nil {
			if err := objects.add(frame.GetObject()); err != nil {
				objects.close()
				return nil, nil, err
			}
		}
	}
	if reply.head == nil {
		objects.close()
		return nil, nil, fmt.Errorf("%w: a read reply with no head", ErrEvsReplyInvalid)
	}
	return reply, objects, nil
}

// The ref's path epoch as the last verified head gave it, nil when this client has read none.
func (self *EvsClient) refEpoch(repoId Id, refId Id) *protocol.EvsPathEpoch {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refEpochs[evsRefKey{repoId: repoId, refId: refId}]
}

// Keeps the ref's path epoch from a verified head.
func (self *EvsClient) setRefEpoch(repoId Id, refId Id, epoch *protocol.EvsPathEpoch) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refEpochs[evsRefKey{repoId: repoId, refId: refId}] = epoch
}

// Reads the newest committed version of a file, or an older one (args.Version), verified and pinned, then
// reconstructed, its oid checked, and only then written to out (§11.7's reconstruction row).
func (self *EvsRepo) ReadHead(ctx context.Context, args *EvsReadArgs, out io.Writer) (*EvsFileInfo, error) {
	refId, err := self.resolveRefId(ctx, args.RefName, args.RefId)
	if err != nil {
		return nil, err
	}
	result, err := self.read(ctx, refId, []string{args.Path}, args.Version, args.Fresh)
	if err != nil {
		return nil, err
	}
	defer result.objects.close()
	verified := result.replies[0]
	switch {
	case verified.Base != nil:
		return nil, ErrEvsOverlayBase
	case verified.Removal != nil:
		return nil, ErrEvsPathAbsent
	case verified.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE):
		return nil, fmt.Errorf("%w: a directory, which List reads", ErrEvsTokenInvalid)
	}
	info, err := self.reconstruct(ctx, result, verified, out)
	if err != nil {
		return nil, err
	}
	info.Path = args.Path
	return info, nil
}

// The file info a verified version gives, before its sealed fields are opened.
func evsFileInfoOf(refId Id, head *EvsVerifiedHead, verified *EvsVerifiedPath) *EvsFileInfo {
	push := verified.Statement.Push
	info := &EvsFileInfo{
		RefId:         refId,
		Version:       verified.Entry.GetVersion(),
		CommitVersion: verified.CommitVersion,
		Time:          evsTime(verified.Entry.GetTimeMs()),
		Kind:          protocol.EvsEntryKind(verified.Entry.GetKind()),
		HeadVersion:   head.Version,
	}
	info.PushId, _ = IdFromBytes(push.GetPushId())
	info.SignerSidecarId, _ = IdFromBytes(push.GetSignerSidecarId())
	info.ClientId, _ = IdFromBytes(push.GetClientId())
	return info
}
