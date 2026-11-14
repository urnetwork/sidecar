// Head reads (§11.9): ReadHead's and List's round trips to POST /evs/v1/repos/<id>/read, the verifying reader's checks
// over what comes back, the pin and read records it raises, and the receipt gate before anything is decrypted.
//
// A read names its ref by id, which any reader derives from K_ref for a named ref (§11.6), and its path by tokens
// computed here from the plaintext path, which never leaves the device (I-13, X2), in the epochs DESIGN-DETAILS
// 9.2.3's rules let it name: the current epoch, and the listed sources and other epochs at or above the path's floor;
// a path with no floor is a new name, looked up through its parent's table where the rules hold it back. The loop
// that chooses them, verifies each round and starts again on a head of another epoch state is evs_epoch_read.go's;
// a ref this client has not verified a head of takes one round for its head first. A path read before is read from
// its read record's pin, so every statement since that read is checked against it
// (g0-recheck-0-head-reader-read-paths#1), and a version below the record is refused and alarmed as tampering. A hint
// naming a newer version sends the read past evs's head cache.
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

// A path as its raw names, refusing an empty component, and the empty path, which only a read names (the root).
func evsPathNames(path string) ([][]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: the empty path, which names the root only to a read", ErrEvsTokenInvalid)
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

// A path a read names as its raw names: the empty path is the ref's root, with no names, whose token path is empty in
// every epoch (question evs1-m2-24-root-directory-names, option 1; DESIGN-DETAILS 9.2.8); any other as evsPathNames.
func evsReadPathNames(path string) ([][]byte, error) {
	if path == "" {
		return [][]byte{}, nil
	}
	return evsPathNames(path)
}

// The repo keys one read uses, each generation asked of gkm once.
type evsReadKeys struct {
	repo         *EvsRepo
	generations  map[uint64]*EvsRepoKey
	manifestKeys map[uint64]*EvsManifestKey
	fekKeys      map[uint64]*EvsFekKey
	pathKeys     map[uint64]*EvsPathKey
	// a deposit's slot key and K_dep, set once its slot is opened, which take manifest's and the slot's place for
	// its generation (evs_consume.go)
	deposit *evsDepositKeys
}

// A deposit's keys for one read: its slot's object key and the K_dep it derives, which take the slot's and
// manifest's place for that slot and generation (EVS-FORMAT.md's deposits; evs_consume.go sets them).
type evsDepositKeys struct {
	slotId     Id
	generation uint64
	objectKey  *EvsObjectKey
	manifest   *EvsManifestKey
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

// manifest_g, or a deposit's K_dep in its generation's place.
func (self *evsReadKeys) manifest(ctx context.Context, generation uint64) (*EvsManifestKey, error) {
	if self.deposit != nil && self.deposit.generation == generation {
		return self.deposit.manifest, nil
	}
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

// A path's token path in epoch, from its raw names and K_path of that epoch: the root's is empty in every epoch.
func (self *evsReadKeys) tokenPathIn(ctx context.Context, names [][]byte, epoch uint64) (EvsTokenPath, error) {
	if len(names) == 0 {
		return EvsTokenPath{}, nil
	}
	pathKey, err := self.path(ctx, epoch)
	if err != nil {
		return nil, err
	}
	return EvsPathTokens(pathKey, names)
}

// One path a read asks for: its plaintext and names, the version asked, and what the rounds named and learned of it
// (evs_epoch_read.go).
type evsReadPath struct {
	path  string
	names [][]byte
	// 0 the newest version, else that older version; the ref version its push committed at when known (history's
	// prev_commit_version), and the push the newer version names as its predecessor, which E4 reads
	version       uint64
	commitVersion uint64
	prevPushId    []byte
	// its token path in the current epoch, and the epochs and token paths the last round named it in
	current    EvsTokenPath
	epochs     []uint64
	epochPaths []*protocol.EvsSourcePath
	named      map[uint64]bool
	record     *EvsReadRecord
	// the floor the call gathered, 0 none
	floor uint64
	// epochs the verifier needs proofs in, asked once more
	more      []uint64
	moreAsked bool
	// a lookup ran for it in this call
	lookedUp bool
	// the reply as verified, or the absence a lookup settled with no token of the path sent
	verified *EvsVerifiedPath
	settled  *EvsVerifiedPath
	// a deposit's or the erasure ref's entry, named by its random id in token's place, on a ref that stays at epoch 1
	// (evsEpochExempt): no names, record, floor or lookup
	token EvsTokenPath
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

// One round's reply: its parts as they arrived and their objects, its head verified but not pinned, and the ref pin
// it read from, which a path with no record is walked from (DESIGN-DETAILS 9.2.4's pin(X)).
type evsReadRound struct {
	reply         *evsReadReply
	objects       *evsReadObjects
	head          *EvsVerifiedHead
	keys          *evsReadKeys
	refPinVersion uint64
}

// Reads paths of a ref at version (0 the newest), each by DESIGN-DETAILS 9.2.4's loop (evs_epoch_read.go): verifies
// the head and every path, checks the read records, pins the head and raises the records, all before the caller
// decrypts anything. A path's own failure fails the read: the caller asked for it.
func (self *EvsRepo) read(ctx context.Context, refId Id, paths []string, version uint64, fresh bool) (*evsReadResult, error) {
	readPaths := make([]*evsReadPath, 0, len(paths))
	for _, path := range paths {
		readPaths = append(readPaths, &evsReadPath{path: path, version: version})
	}
	return self.readPaths(ctx, refId, readPaths, fresh)
}

// One round: the request naming each path in the epochs the loop chose, its framed reply, and the head's check from
// the pin, or from the oldest read record's pin of the paths asked, so every statement since is walked. The paths'
// checks, the pin and the records are the loop's.
func (self *EvsRepo) readRound(ctx context.Context, refId Id, keys *evsReadKeys, paths []*evsReadPath, fresh bool) (*evsReadRound, error) {
	return self.readRoundFromPin(ctx, refId, keys, paths, fresh, true)
}

// readRound, taking a head below the pin under the ref's EvsReseed at most once (reseed): the round after one reads
// from the lowered pin and refuses a head below that.
func (self *EvsRepo) readRoundFromPin(ctx context.Context, refId Id, keys *evsReadKeys, paths []*evsReadPath, fresh bool, reseed bool) (*evsReadRound, error) {
	fromVersion := uint64(0)
	fromChain := EvsChainStart(self.repoId, refId)
	pin, pinned, err := self.client.pins.Pin(self.repoId, refId)
	if err != nil {
		return nil, err
	}
	refPinVersion := uint64(0)
	if pinned {
		fromVersion, fromChain, refPinVersion = pin.Version, pin.Chain, pin.Version
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
		readPath := &protocol.EvsReadPath{TokenPaths: path.epochPaths, Version: path.version}
		if path.version != 0 {
			readPath.CommitVersion = path.commitVersion
		}
		request.Paths = append(request.Paths, readPath)
	}
	reply, objects, err := self.client.postRead(ctx, self.repoId, request)
	if err != nil {
		return nil, err
	}
	if reseed && pinned && reply.head.GetVersion() < pin.Version {
		again, err := self.acceptReseedBelowPin(ctx, refId, pin, reply, fromVersion)
		if err != nil {
			objects.close()
			return nil, err
		}
		if again {
			// the pin now stands at the re-seeded head, or the head has passed the pin since: the round again
			objects.close()
			return self.readRoundFromPin(ctx, refId, keys, paths, fresh, false)
		}
	}
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
		objects.close()
		return nil, err
	}
	return &evsReadRound{reply: reply, objects: objects, head: head, keys: keys, refPinVersion: refPinVersion}, nil
}

// A head served below this device's pin of the ref (§11.9's reader row; §11.13's re-seed row, §19.10): the shorter
// history a site loss left, which the device takes only under the ref's Signed EvsReseed, a repo admin's, naming
// exactly the head served (EvsVerifier.AcceptReseed). evs serves the statement after a head below the request's
// pin_version (QD-725), so a round that asked from an older path record's pin asks once more from the ref's. True
// when the caller is to read again: the pin stands lowered to the re-seeded head, kept as a loss, or the head has
// passed the pin while this asked. False with no statement or one that does not verify: nothing changed, and the
// caller's own check refuses the head and alarms, as it does without this.
func (self *EvsRepo) acceptReseedBelowPin(ctx context.Context, refId Id, pin *EvsPin, reply *evsReadReply, askedVersion uint64) (bool, error) {
	head, statement := reply.head, reply.reseed
	if statement == nil && askedVersion < pin.Version {
		again, objects, err := self.client.postRead(ctx, self.repoId, &protocol.EvsReadRequest{RefId: refId.Bytes(), PinVersion: pin.Version, Fresh: true})
		if err != nil {
			return false, err
		}
		objects.close()
		head, statement = again.head, again.reseed
		if pin.Version <= head.GetVersion() {
			return true, nil
		}
	}
	if statement == nil {
		return false, nil
	}
	if err := self.client.verifier.AcceptReseed(statement, self.repoId, refId, head); err != nil {
		if errors.Is(err, ErrEvsStatementRefused) {
			self.client.log.Warningf("[evs]the reseed served for repo %s ref %s is refused: %v", self.repoId, refId, err)
			return false, nil
		}
		return false, err
	}
	self.client.forgetRefHead(self.repoId, refId)
	return true, nil
}

// A read reply's parts as they arrived.
type evsReadReply struct {
	head       *protocol.EvsHeadSummary
	statements []*protocol.EvsReadStatement
	behind     uint64
	paths      []*protocol.EvsReadPathReply
	// The ref's Signed EvsReseed as evs keeps it, served after a head below the request's pin_version (§11.13;
	// QD-725); nil when the reply carried none. Unverified: EvsVerifier.AcceptReseed checks it.
	reseed []byte
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
		if object := frame.GetObject(); object != nil && object.GetKind() == protocol.EvsReadObjectKind_EVS_READ_OBJECT_RESEED {
			// one frame, whole, within the statement's bound: never spilled, and never read as a path's object
			if reply.reseed != nil || object.GetMissing() || object.GetOffset() != 0 || len(object.GetBody()) == 0 ||
				frames.format.ReseedStatementMaxByteCount < len(object.GetBody()) {
				objects.close()
				return nil, nil, fmt.Errorf("%w: a reseed frame", ErrEvsReplyInvalid)
			}
			reply.reseed = object.GetBody()
		} else if object != nil {
			if err := objects.add(object); err != nil {
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
	if state := self.refEpochState(repoId, refId); state != nil {
		return state.epoch
	}
	return nil
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
	case verified.Removal != nil, verified.Absent:
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
