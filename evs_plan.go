// The write planner (§11.7, EVS1-M2-25): from what a write asks of each path and what a verified read of the ref
// shows, an EvsWritePlan (proposed name): per path the records a push will seal, the entry version it makes and the
// change it states. The push sender (evs_push.go) seals and sends it, and on a rebuild plans again from a fresh read.
//
//	versions   a write's version is its base_entry_version + 1; a creation's, on base 0, max(b, m) + 1, b the head's
//	           version the push is based on and m the version of the removal the read shows standing, so a path's
//	           versions never restart (I-EVS-8); a removal states the version it removes
//	file       its sealed fields {file_id, mode, git oid, size}: file_id random for a new file, never derived, and kept
//	           from the previous version for life; its chain a checkpoint, diffs after it, or chunks (evs_checkpoint.go,
//	           evs_chunk.go), at most N + 1 locators; a diff is a git pack delta against the previous version, which the
//	           read reconstructs and checks against its oid first
//	inline     a chain whose records pad to at most 16 KiB in all rides inline in its entry version, else in segments;
//	           a chain stays one or the other, so a diff that would take an inline chain past 16 KiB checkpoints
//	directory  each parent below the root takes a delta {names added, child tokens removed} (evs_directory.go)
//	reserved   format 1 writes nothing under .ur-index/ on a file-mode ref, nor on the ur/index and ur/lfs refs,
//	           which are format 2's index and v1's lfs store (§11.7, §11.14), and only versioning 0
//
// The plan is the push's content, not yet its bytes: sealWrite (evs_upload.go) seals its records under the
// generation GkmClient.EnsureWritable returned, which the plan was checked against (rule 4 and an inline chain's
// generation), and each sealed path renders its entry version under one push id (evs_push.go). A large write reads
// in batches of 64 paths, the push based on the first batch's head. Where M10's index writer joins (§11.20) is the
// client's EvsWritePlanHook, run on every plan before it is sealed.
//
// Not built here, and failing closed: writes to record-class repos, whose records name slot keys (EVS1-M2-29, -30
// and §15, §16's writers); rename and copy, which keep a file's chain under another path through the reuse list;
// writes while the head lists source epochs, whose changes carry source paths (EVS1-M2-28).
//
// On every leg. Not safe for concurrent use: one plan at a time per write.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// The directory format 1 never writes on a file-mode ref, and the refs it never writes: format 2's search index and
// v1's lfs store (§11.7's traps, §11.14).
var (
	evsReservedIndexDirectory = []byte(".ur-index")
	evsReservedRefNames       = [][]byte{[]byte("ur/index"), []byte("ur/lfs")}
)

var (
	// A write to a git-mode ref from head mode, which cannot build a git tree: §18.5's EVS_GIT_REF (§11.7).
	ErrEvsGitRef = errors.New("evs: EVS_GIT_REF: a git-mode ref takes writes only through the local tier")
	// A write to a path or ref format 1 reserves.
	ErrEvsReservedPath = errors.New("evs: a reserved path or ref")
	// A write that names a path twice, a removal with content, or content with none.
	ErrEvsWriteInvalid = errors.New("evs: write invalid")
	// A write of a file where a directory stands, or under a path that stands as a file.
	ErrEvsPathKind = errors.New("evs: a path of another kind")
	// What a format-1 write cannot do yet: named in the error, nothing sent.
	ErrEvsWriteNotBuilt = errors.New("evs: write not built")
	// A plan whose read batches met two path epochs: the write plans again from a fresh read.
	errEvsPlanEpochMoved = errors.New("evs: the path epoch moved while the plan read")
)

// The most paths one read names (§11.9's request row).
const EvsReadMaxPathCount = 64

// What one path's write asks.
type EvsPathWrite struct {
	// Raw names joined by /, never normalized (§11.6).
	Path string
	// The new content, read at any offset; nil with Remove.
	Content EvsGitDeltaSource
	// git's mode: 0 keeps the previous version's, or a regular file's for a new one.
	Mode   uint32
	Remove bool
	// A whole checkpoint under a fresh key even where a diff would do: KEYS-M2-26's ur evs rekey.
	ForceCheckpoint bool
}

// What a plan is made against.
type EvsPlanArgs struct {
	// The ref's name bytes, and its id.
	RefName []byte
	RefId   Id
	Writes  []*EvsPathWrite
	// The generation this push seals to, from GkmClient.EnsureWritable.
	Generation uint64
	// Reads the cluster's head, not evs's cache.
	Fresh bool
}

// A planned push. See the file header.
type EvsWritePlan struct {
	RepoId  Id
	RefId   Id
	RefKind protocol.EvsRefKind
	RefMode protocol.EvsRefMode
	// An owned ref's owner, this sidecar.
	OwnerSidecarId *Id
	// The head the plan was made on: v and C_v, the push's base.
	BaseVersion uint64
	BaseChain   [32]byte
	// The head the plan read, whose pins a push must not fall below (§11.8 5d).
	Head       *protocol.EvsHeadSummary
	PathEpoch  uint64
	Generation uint64
	Paths      []*EvsPlannedPath
	// The changes' token paths, in the head's current epoch.
	pathKey *EvsPathKey
}

// One path's part of a push.
type EvsPlannedPath struct {
	Path      string
	TokenPath EvsTokenPath
	// What the change writes: a file or a directory delta; for a removal, what stood.
	Kind   protocol.EvsEntryKind
	Remove bool
	// The change's base_entry_version, 0 creating the path.
	BaseEntryVersion uint64
	// The version it writes, 0 for a removal.
	Version uint64
	// The version it replaces, for history walks.
	PrevPushId        []byte
	PrevCommitVersion uint64
	// A file's sealed fields, its chain and why it checkpoints, if it does.
	Fields     *protocol.EvsSealedFields
	Checkpoint EvsCheckpointReason
	Chain      []*EvsPlannedLink
	// Whether the chain rides inline.
	Inline bool
	// A directory's delta: the rows it adds, each sealed, and the child tokens it removes.
	Names         []*protocol.EvsName
	RemovedTokens [][]byte
}

// One link of a new chain: a locator the previous version cites, kept as it stands, or a record this push writes.
type EvsPlannedLink struct {
	Kept   *protocol.EvsLocator
	Record *EvsPlannedRecord
}

// A record this push writes: its kind, its id and a diff's base, the file's oid, and its body's plaintext.
type EvsPlannedRecord struct {
	Kind         protocol.EvsRecordKind
	RecordId     Id
	BaseRecordId Id
	Oid          EvsGitOid
	Body         EvsGitDeltaSource
}

// Where M10's index writer joins a push (§11.20, §11.14): it sees each plan before it is sealed and may add its own
// paths. Nil until M10.
type EvsWritePlanHook func(ctx context.Context, plan *EvsWritePlan) error

// Sets where M10's index writer joins every write's plan; nil removes it.
func (self *EvsClient) SetWritePlanHook(hook EvsWritePlanHook) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writeHook = hook
}

// The hook SetWritePlanHook set.
func (self *EvsClient) writePlanHook() EvsWritePlanHook {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.writeHook
}

// Plans args' writes on the ref, from one verified read of the head, every written path and each parent directory
// below the root. See the file header.
func (self *EvsRepo) PlanWrite(ctx context.Context, args *EvsPlanArgs) (*EvsWritePlan, error) {
	if len(args.Writes) == 0 {
		return nil, fmt.Errorf("%w: no path", ErrEvsWriteInvalid)
	}
	for _, reserved := range evsReservedRefNames {
		if bytes.Equal(args.RefName, reserved) {
			return nil, fmt.Errorf("%w: a format-2 or v1 ref", ErrEvsReservedPath)
		}
	}
	repoKind, err := self.repoKind()
	if err != nil {
		return nil, err
	}
	if EvsRepoKindRecordClass(repoKind) {
		return nil, fmt.Errorf("%w: a record-class repo's slot-keyed records (EVS1-M2-29, EVS1-M2-30)", ErrEvsWriteNotBuilt)
	}
	writePaths := map[string]bool{}
	readPaths := []string{}
	for _, write := range args.Writes {
		names, err := evsPathNames(write.Path)
		if err != nil {
			return nil, err
		}
		if writePaths[write.Path] {
			return nil, fmt.Errorf("%w: a path written twice", ErrEvsWriteInvalid)
		}
		if write.Remove != (write.Content == nil) {
			return nil, fmt.Errorf("%w: a removal with content, or a write with none", ErrEvsWriteInvalid)
		}
		if write.Content != nil && EvsFileMaxByteCount < write.Content.Size() {
			return nil, fmt.Errorf("%w: %d bytes", ErrEvsFileTooLarge, write.Content.Size())
		}
		if bytes.Equal(names[0], evsReservedIndexDirectory) {
			return nil, fmt.Errorf("%w: under .ur-index/", ErrEvsReservedPath)
		}
		writePaths[write.Path] = true
		readPaths = append(readPaths, write.Path)
	}
	for _, directory := range evsParentDirectories(readPaths) {
		if !writePaths[directory] {
			readPaths = append(readPaths, directory)
		}
	}
	writes := map[string]*EvsPathWrite{}
	for _, write := range args.Writes {
		writes[write.Path] = write
	}
	var plan *EvsWritePlan
	var nameKey *EvsManifestKey
	planned := map[string]*EvsPlannedPath{}
	directories := map[string]*evsDirectoryRead{}
	// a read names at most 64 paths (§11.9), so a large write reads in batches, each verified, the push based on the
	// first one's head; every path's own newest is what its batch read, which 5g holds it to at commit
	for start := 0; start < len(readPaths); start += EvsReadMaxPathCount {
		batch := readPaths[start:min(len(readPaths), start+EvsReadMaxPathCount)]
		err := func() error {
			result, err := self.read(ctx, args.RefId, batch, 0, args.Fresh || 0 < start)
			if err != nil {
				return err
			}
			defer result.objects.close()
			head := result.head.Head
			if plan == nil {
				plan = &EvsWritePlan{
					RepoId: self.repoId, RefId: args.RefId, BaseVersion: result.head.Version, BaseChain: result.head.Chain,
					Head: head, PathEpoch: max(1, head.GetPathEpoch().GetCurrent()), Generation: args.Generation,
				}
				if 0 < len(head.GetPathEpoch().GetSources()) {
					return fmt.Errorf("%w: a write while the head lists source epochs (EVS1-M2-28)", ErrEvsWriteNotBuilt)
				}
				if err := plan.setRef(head, args.RefName, self.client.args.Identity().SidecarId); err != nil {
					return err
				}
				if plan.pathKey, err = result.keys.path(ctx, plan.PathEpoch); err != nil {
					return err
				}
				if nameKey, err = result.keys.manifest(ctx, plan.PathEpoch); err != nil {
					return err
				}
			} else if max(1, head.GetPathEpoch().GetCurrent()) != plan.PathEpoch || 0 < len(head.GetPathEpoch().GetSources()) {
				return errEvsPlanEpochMoved
			}
			for i, readPath := range result.paths {
				write := writes[readPath.path]
				if write == nil {
					directories[readPath.path] = evsDirectoryReadOf(readPath, result.replies[i])
					continue
				}
				path, err := self.planPath(ctx, plan, result, readPath, result.replies[i], write)
				if err != nil {
					return err
				}
				planned[write.Path] = path
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	for _, write := range args.Writes {
		plan.Paths = append(plan.Paths, planned[write.Path])
	}
	directoryPaths, err := evsDirectoryChanges(plan, planned, directories, nameKey)
	if err != nil {
		return nil, err
	}
	plan.Paths = append(plan.Paths, directoryPaths...)
	if hook := self.client.writePlanHook(); hook != nil {
		if err := hook(ctx, plan); err != nil {
			return nil, err
		}
	}
	return plan, nil
}

// The repo's kind, from the newest verified config state.
func (self *EvsRepo) repoKind() (protocol.RepoKind, error) {
	state, err := self.client.verifier.config()
	if err != nil {
		return 0, err
	}
	repo := state.Repo(self.repoId)
	if repo == nil {
		return 0, fmt.Errorf("%w: a repo the state does not hold", ErrEvsNoConfig)
	}
	return repo.GetKind(), nil
}

// The ref's kind, mode and owner: the head's once a push set them, else a file-mode ref named by refName, owned for
// ur/<this sidecar>/..., shared otherwise. A git-mode ref is ErrEvsGitRef; another sidecar's owned ref, a deposit or the
// erasure ref take no Write.
func (self *EvsWritePlan) setRef(head *protocol.EvsHeadSummary, refName []byte, sidecarId Id) error {
	self.RefKind = head.GetRefKind()
	self.RefMode = head.GetRefMode()
	if self.RefKind == protocol.EvsRefKind_EVS_REF_KIND_UNSPECIFIED {
		self.RefKind = protocol.EvsRefKind_EVS_REF_SHARED
		self.RefMode = protocol.EvsRefMode_EVS_REF_FILE
		if ownerId, ok := EvsOwnedRefOwner(refName); ok {
			self.RefKind = protocol.EvsRefKind_EVS_REF_OWNED
			self.OwnerSidecarId = &ownerId
		}
	} else if 0 < len(head.GetOwnerSidecarId()) {
		ownerId, err := IdFromBytes(head.GetOwnerSidecarId())
		if err != nil {
			return fmt.Errorf("%w: the head's owner", ErrEvsReplyInvalid)
		}
		self.OwnerSidecarId = &ownerId
	}
	if self.RefMode == protocol.EvsRefMode_EVS_REF_GIT {
		return ErrEvsGitRef
	}
	switch self.RefKind {
	case protocol.EvsRefKind_EVS_REF_SHARED:
	case protocol.EvsRefKind_EVS_REF_OWNED:
		if self.OwnerSidecarId == nil || *self.OwnerSidecarId != sidecarId {
			return fmt.Errorf("%w: another sidecar's owned ref", ErrEvsWriteInvalid)
		}
	default:
		return fmt.Errorf("%w: a %s ref takes its own pushes", ErrEvsWriteInvalid, self.RefKind)
	}
	return nil
}

// Every directory below the root holding one of paths, each once, parents before children.
func evsParentDirectories(paths []string) []string {
	seen := map[string]bool{}
	directories := []string{}
	for _, path := range paths {
		components := strings.Split(path, "/")
		for depth := 1; depth < len(components); depth += 1 {
			directory := strings.Join(components[:depth], "/")
			if !seen[directory] {
				seen[directory] = true
				directories = append(directories, directory)
			}
		}
	}
	return directories
}

// One written path's plan: a removal of what stands, or a file version on its previous one.
func (self *EvsRepo) planPath(ctx context.Context, plan *EvsWritePlan, result *evsReadResult, readPath *evsReadPath, verified *EvsVerifiedPath, write *EvsPathWrite) (*EvsPlannedPath, error) {
	if verified.Base != nil {
		return nil, ErrEvsOverlayBase
	}
	planned := &EvsPlannedPath{Path: write.Path, TokenPath: readPath.current, Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE}
	stands := verified.Entry != nil
	if stands {
		planned.PrevPushId = verified.Statement.Push.GetPushId()
		planned.PrevCommitVersion = verified.CommitVersion
	}
	if write.Remove {
		if !stands {
			return nil, ErrEvsPathAbsent
		}
		planned.Remove = true
		planned.Kind = protocol.EvsEntryKind(verified.Entry.GetKind())
		planned.BaseEntryVersion = evsVerifiedNewestVersion(verified)
		return planned, nil
	}
	if stands && verified.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
		return nil, fmt.Errorf("%w: a file where a directory stands", ErrEvsPathKind)
	}
	if stands {
		planned.BaseEntryVersion = verified.Entry.GetVersion()
		planned.Version = planned.BaseEntryVersion + 1
	} else {
		removalVersion := uint64(0)
		if verified.Removal != nil {
			removalVersion = verified.Removal.GetPathVersion()
		}
		planned.Version = max(plan.BaseVersion, removalVersion) + 1
	}
	oid, err := EvsGitBlobOid(io.NewSectionReader(write.Content, 0, write.Content.Size()), write.Content.Size())
	if err != nil {
		return nil, err
	}
	planned.Fields = &protocol.EvsSealedFields{
		FileId: NewEvsSlotId().Bytes(), Mode: EvsGitModeFile, GitOid: oid[:], OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
		Size: uint64(write.Content.Size()),
	}
	var previous *EvsChainState
	var previousContent *evsSpill
	if stands {
		content, state, fields, err := self.readBase(ctx, result, verified)
		if err != nil {
			return nil, err
		}
		defer content.close()
		previous, previousContent = state, content
		planned.Fields.FileId = fields.GetFileId()
		planned.Fields.Mode = fields.GetMode()
	}
	if write.Mode != 0 {
		planned.Fields.Mode = write.Mode
	}
	if !evsFileModeValid(planned.Fields.GetMode()) {
		return nil, fmt.Errorf("%w: mode %o is no file's", ErrEvsWriteInvalid, planned.Fields.GetMode())
	}
	if err := self.planChain(ctx, plan, planned, write, verified, previous, previousContent, oid); err != nil {
		return nil, err
	}
	return planned, nil
}

// A standing path's newest version: a file's, or a directory's newest delta's.
func evsVerifiedNewestVersion(verified *EvsVerifiedPath) uint64 {
	version := verified.Entry.GetVersion()
	for _, delta := range verified.Deltas {
		if delta.Entry != nil {
			version = max(version, delta.Entry.GetVersion())
		}
	}
	return version
}

// A file version's chain: chunks, a checkpoint, or the previous chain and a diff.
func (self *EvsRepo) planChain(ctx context.Context, plan *EvsWritePlan, planned *EvsPlannedPath, write *EvsPathWrite, verified *EvsVerifiedPath, previous *EvsChainState, previousContent *evsSpill, oid EvsGitOid) error {
	content := write.Content
	size := uint64(content.Size())
	removeSince := false
	if previous != nil {
		var err error
		removeSince, err = evsRemoveGenerationSince(ctx, self.client.args.Gkm, self.repoId, previous.KeyGeneration, plan.Generation)
		if err != nil {
			return err
		}
	}
	reason := EvsCheckpointBefore(&EvsCheckpointArgs{
		Previous: previous, Size: size, Force: write.ForceCheckpoint, RemoveSince: removeSince, Generation: plan.Generation,
		DiffMaxByteCount: uint64(self.client.settings.DiffMaxByteCount),
	})
	planned.Checkpoint = reason
	if reason == EvsCheckpointChunked && EvsChunked(size) {
		var previousSource EvsGitDeltaSource
		var previousChain []*protocol.EvsLocator
		if previous != nil && previous.Chunked {
			previousSource, previousChain = previousContent, verified.Entry.GetChain()
		}
		chunks, err := EvsPlanChunks(content, previousSource, previousChain, write.ForceCheckpoint || removeSince)
		if err != nil {
			return err
		}
		for _, chunk := range chunks {
			if chunk.Kept != nil {
				planned.Chain = append(planned.Chain, &EvsPlannedLink{Kept: chunk.Kept})
				continue
			}
			planned.Chain = append(planned.Chain, &EvsPlannedLink{Record: &EvsPlannedRecord{
				Kind: protocol.EvsRecordKind_EVS_RECORD_CHUNK, RecordId: NewEvsSlotId(), Oid: oid,
				Body: io.NewSectionReader(content, chunk.Offset, chunk.Length),
			}})
		}
		return nil
	}
	if reason == EvsCheckpointNone {
		delta := &evsBoundedBuffer{limit: int(size)}
		err := EvsGitDeltaEncode(previousContent, content, delta, DefaultEvsGitDeltaSettings())
		switch {
		case errors.Is(err, errEvsBoundedBufferFull):
			reason = EvsCheckpointDeltaOutgrows
		case err != nil:
			return err
		default:
			reason = EvsCheckpointAfter(previous, uint64(delta.Len()), size)
		}
		if reason == EvsCheckpointNone && previous.Inline &&
			EvsInlineMaxByteCount < previous.InlineByteCount+int(EvsPadme(EvsRecordByteCount(uint64(delta.Len())))) {
			reason = EvsCheckpointInlineFull
		}
		if reason == EvsCheckpointNone {
			for _, locator := range verified.Entry.GetChain() {
				planned.Chain = append(planned.Chain, &EvsPlannedLink{Kept: locator})
			}
			planned.Inline = previous.Inline
			planned.Chain = append(planned.Chain, &EvsPlannedLink{Record: &EvsPlannedRecord{
				Kind: protocol.EvsRecordKind_EVS_RECORD_DIFF, RecordId: NewEvsSlotId(), BaseRecordId: previous.LastRecordId,
				Oid: oid, Body: bytes.NewReader(delta.Bytes()),
			}})
			return nil
		}
		planned.Checkpoint = reason
	}
	planned.Inline = EvsPadme(EvsWrappedKeyByteCount+EvsRecordByteCount(size)) <= EvsInlineMaxByteCount
	planned.Chain = []*EvsPlannedLink{{Record: &EvsPlannedRecord{
		Kind: protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, RecordId: NewEvsSlotId(), Oid: oid, Body: content,
	}}}
	return nil
}

// A buffer that refuses to grow past its limit, which ends a delta that outgrows its file.
type evsBoundedBuffer struct {
	bytes.Buffer
	limit int
}

// The delta outgrew its file.
var errEvsBoundedBufferFull = errors.New("evs: delta past its file")

// Appends p, or refuses past the limit.
func (self *evsBoundedBuffer) Write(p []byte) (int, error) {
	if self.limit < self.Len()+len(p) {
		return 0, errEvsBoundedBufferFull
	}
	return self.Buffer.Write(p)
}

// The previous version's content, reconstructed and checked against its sealed fields' oid and size, its fields,
// and what its chain holds: the facts the checkpoint rules read.
func (self *EvsRepo) readBase(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath) (*evsSpill, *EvsChainState, *protocol.EvsSealedFields, error) {
	state := &EvsChainState{RecordCount: len(verified.Entry.GetChain())}
	pushGeneration := verified.Statement.Push.GetGeneration()
	onRecord := func(header *EvsRecordHeader, locator *protocol.EvsLocator) {
		if state.KeyGeneration == 0 || header.Generation < state.KeyGeneration {
			state.KeyGeneration = header.Generation
		}
		switch header.Kind {
		case protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT:
			state.DiffCount, state.DiffByteCount = 0, 0
		case protocol.EvsRecordKind_EVS_RECORD_DIFF:
			state.DiffCount += 1
			state.DiffByteCount += header.BodyLength
		case protocol.EvsRecordKind_EVS_RECORD_CHUNK:
			state.Chunked = true
		}
		if protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_INLINE {
			state.Inline = true
			state.InlineGeneration = pushGeneration
			state.InlineByteCount += len(locator.GetInline())
		}
		state.LastRecordId = header.RecordId
	}
	content, fields, _, err := self.reconstructContent(ctx, result, verified, onRecord)
	if err != nil {
		return nil, nil, nil, err
	}
	state.Size = uint64(content.Size())
	return content, state, fields, nil
}
