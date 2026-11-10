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
// Path epochs (DESIGN-DETAILS 9.2.5). The plan reads every path by 9.2.4's rules and takes each one's floor from that
// read. A creation is planned only where the read found the path absent, looked up in its parent's table when it has
// no floor, and on a blocking ref under immediate pressure not at all (ErrEvsPathEpochDue, no token of it sent). A
// change names its path in the current epoch and, as source paths, in each listed source at or above its floor; a
// removal lowers the path's floor to its row's epoch and its parent's delta removes the child's token in the current
// epoch and in each such source, so a fold drops a carried row too. A push refused 412 PATH_EPOCH is made again by
// Retoken.
//
// Not built here, and failing closed: writes to record-class repos, whose records name slot keys (EVS1-M2-29, -30
// and §15, §16's writers); rename and copy, which keep a file's chain under another path through the reuse list.
//
// On every leg. Not safe for concurrent use: one plan at a time per write.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

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
	// A write held to an entry version (EvsPathWrite.IfVersion) the path no longer stands at.
	ErrEvsPathMoved = errors.New("evs: the path moved past the version the write was made on")
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
	// The entry version the path must stand at, 0 for any. A write whose content came from an earlier read of that
	// version, as ur evs rekey's does, is refused with ErrEvsPathMoved once another write or a removal landed
	// between, rather than putting the older content back; evs then holds the push to the version the plan read (5g).
	IfVersion uint64
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
	Head *protocol.EvsHeadSummary
	// The head's current path epoch, which every change's token path is in, and the epochs it lists as sources,
	// newest first, in which a change names its path at or above its floor (DESIGN-DETAILS 9.2.5).
	PathEpoch  uint64
	Sources    []uint64
	Generation uint64
	Paths      []*EvsPlannedPath
	// The changes' token paths, in the head's current epoch, and manifest_p of that epoch, which seals a delta's rows.
	pathKey *EvsPathKey
	nameKey *EvsManifestKey
	// every epoch's keys, as the read reached them
	keys *evsReadKeys
	// each path's floor by its plaintext path, 0 for none (DESIGN-DETAILS 9.2.3): what the reads showed, lowered by a
	// refusal that answered the push (E3)
	floors map[string]uint64
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
	// The change's source paths while the head lists sources: its token path in each one at or above its floor, as
	// EvsSourcePath bytes (payload section 12; DESIGN-DETAILS 9.2.2's source paths row).
	SourcePaths [][]byte

	// the path's raw names, which give its token path in any epoch
	names [][]byte
	// a creation's standing removal version m, which max(b, m) + 1 counts again on a retoken's base
	removalVersion uint64
	// a directory delta's children, whose rows a retoken seals again in its epoch
	children []*evsChildChange
}

// Whether the change creates its path, as a creation's version is max(b, m) + 1 on the push's base.
func (self *EvsPlannedPath) creates() bool {
	return !self.Remove && self.BaseEntryVersion == 0
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
	planned := map[string]*EvsPlannedPath{}
	directories := map[string]*evsDirectoryRead{}
	// a read names at most 64 paths (§11.9), so a large write reads in batches, each verified, the push based on the
	// first one's head; every path's own newest is what its batch read, which 5g holds it to at commit
	readBatch := func(batch []string, fresh bool) error {
		return func() error {
			result, err := self.read(ctx, args.RefId, batch, 0, fresh)
			if err != nil {
				return err
			}
			defer result.objects.close()
			head := result.head.Head
			if plan == nil {
				plan = &EvsWritePlan{
					RepoId: self.repoId, RefId: args.RefId, BaseVersion: result.head.Version, BaseChain: result.head.Chain,
					Head: head, PathEpoch: evsCurrentEpoch(head.GetPathEpoch()), Sources: evsSourceEpochs(head.GetPathEpoch()),
					Generation: args.Generation, keys: result.keys, floors: map[string]uint64{},
				}
				if err := plan.setRef(head, args.RefName, self.client.args.Identity().SidecarId); err != nil {
					return err
				}
				if plan.pathKey, err = result.keys.path(ctx, plan.PathEpoch); err != nil {
					return err
				}
				if plan.nameKey, err = result.keys.manifest(ctx, plan.PathEpoch); err != nil {
					return err
				}
			} else if !evsSamePathEpoch(head.GetPathEpoch(), plan.Head.GetPathEpoch()) {
				return errEvsPlanEpochMoved
			}
			for i, readPath := range result.paths {
				if readPath.path != "" {
					// the floor the read gathered (DESIGN-DETAILS 9.2.3)
					plan.floors[readPath.path] = evsLowerFloor(plan.floors[readPath.path], readPath.floor)
				}
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
	}
	for start := 0; start < len(readPaths); start += EvsReadMaxPathCount {
		batch := readPaths[start:min(len(readPaths), start+EvsReadMaxPathCount)]
		if err := readBatch(batch, args.Fresh || 0 < start); err != nil {
			return nil, err
		}
	}
	if evsNeedsRoot(planned, directories) && directories[""] == nil {
		// a top-level creation or removal changes the root's table, read after the rest (DESIGN-DETAILS 9.2.8)
		if err := readBatch([]string{""}, true); err != nil {
			return nil, err
		}
	}
	for _, write := range args.Writes {
		plan.Paths = append(plan.Paths, planned[write.Path])
	}
	if err := self.planEpochs(ctx, plan); err != nil {
		return nil, err
	}
	directoryPaths, err := evsDirectoryChanges(ctx, plan, planned, directories)
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

// Whether the plan's writes change the root's table: a top-level path created or removed, or a top-level directory
// the plan creates, which a written path below it needs.
func evsNeedsRoot(planned map[string]*EvsPlannedPath, directories map[string]*evsDirectoryRead) bool {
	for path, change := range planned {
		if !strings.Contains(path, "/") && (change.Remove || change.BaseEntryVersion == 0) {
			return true
		}
	}
	for path, read := range directories {
		if path != "" && !strings.Contains(path, "/") && !read.directory && !read.file {
			return true
		}
	}
	return false
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
	planned := &EvsPlannedPath{Path: write.Path, TokenPath: readPath.current, Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE, names: readPath.names}
	stands := verified.Entry != nil
	if stands {
		planned.PrevPushId = verified.Statement.Push.GetPushId()
		planned.PrevCommitVersion = verified.CommitVersion
	}
	if write.IfVersion != 0 && (!stands || evsVerifiedNewestVersion(verified) != write.IfVersion) {
		return nil, ErrEvsPathMoved
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
		if verified.Removal != nil {
			planned.removalVersion = verified.Removal.GetPathVersion()
		}
		planned.Version = max(plan.BaseVersion, planned.removalVersion) + 1
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

// A path's token path in epoch, from its raw names and K_path of that epoch: the root's is empty in every epoch.
func (self *EvsWritePlan) tokenPathIn(ctx context.Context, names [][]byte, epoch uint64) (EvsTokenPath, error) {
	if len(names) == 0 {
		return EvsTokenPath{}, nil
	}
	if epoch == self.PathEpoch && self.pathKey != nil {
		return EvsPathTokens(self.pathKey, names)
	}
	pathKey, err := self.keys.path(ctx, epoch)
	if err != nil {
		return nil, err
	}
	return EvsPathTokens(pathKey, names)
}

// The listed sources at or above a path's floor, newest first: the epochs a change, a source path or a removed token
// names it in beside the current one (DESIGN-DETAILS 9.2.5). None for a path with no floor, which is a new name, and
// none for the root, which has no token and moves last.
func (self *EvsWritePlan) sourcesOf(path string) []uint64 {
	floor := self.floors[path]
	if path == "" || floor == 0 {
		return nil
	}
	sources := []uint64{}
	for _, source := range self.Sources {
		if floor <= source {
			sources = append(sources, source)
		}
	}
	return sources
}

// The change's source paths: its token path in each source sourcesOf names, as EvsSourcePath bytes.
func (self *EvsWritePlan) sourcePathsOf(ctx context.Context, planned *EvsPlannedPath) ([][]byte, error) {
	sourcePaths := [][]byte{}
	for _, source := range self.sourcesOf(planned.Path) {
		tokenPath, err := self.tokenPathIn(ctx, planned.names, source)
		if err != nil {
			return nil, err
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsSourcePath{Epoch: source, TokenPath: tokenPath.Components()})
		if err != nil {
			return nil, err
		}
		sourcePaths = append(sourcePaths, encoded)
	}
	return sourcePaths, nil
}

// Lowers to epoch the floor of every path the plan's push names: in a change, a source path or a delta's row. What a
// refusal of that push shows, since evs answered a request naming each there (DESIGN-DETAILS 9.2.3's E3).
func (self *EvsWritePlan) lowerFloors(epoch uint64) {
	for _, planned := range self.Paths {
		if planned.Path != "" {
			self.floors[planned.Path] = evsLowerFloor(self.floors[planned.Path], epoch)
		}
		for _, child := range planned.children {
			self.floors[child.path] = evsLowerFloor(self.floors[child.path], epoch)
		}
	}
}

// A retoken whose head's generation is past the plan's: the gate refuses the generation, so the write is sealed again
// as after 412 GATE_CLOSED rather than re-tokenized.
var errEvsRetokenSealsAgain = errors.New("evs: the head's generation is past the sealed one")

// Makes the plan again on head, a verified head whose current epoch is above the plan's, for a push refused 412
// PATH_EPOCH (DESIGN-DETAILS 9.2.5's retoken). Made again: every token path in the new epoch; source paths and
// removed tokens by the floors, which the refusal lowered first (lowerFloors); the rows a delta adds, sealed in the
// new epoch; a creation's version max(b, m) + 1 on the new base; the base itself. Kept: what is sealed, records,
// fields and chains, and each change's base_entry_version, so no path is read again: 5g holds each base, and a path
// that moved since the plan answers 409 as on any push. A head whose generation is past the plan's answers
// errEvsRetokenSealsAgain, since the gate would refuse it.
func (self *EvsWritePlan) Retoken(ctx context.Context, head *EvsVerifiedHead) error {
	current := evsCurrentEpoch(head.Head.GetPathEpoch())
	if current <= self.PathEpoch {
		return fmt.Errorf("%w: a retoken on a head of epoch %d, the plan's %d", ErrEvsWriteInvalid, current, self.PathEpoch)
	}
	if self.Generation < current || self.Generation < head.Head.GetGeneration() {
		return errEvsRetokenSealsAgain
	}
	pathKey, err := self.keys.path(ctx, current)
	if err != nil {
		return err
	}
	nameKey, err := self.keys.manifest(ctx, current)
	if err != nil {
		return err
	}
	self.BaseVersion, self.BaseChain, self.Head = head.Version, head.Chain, head.Head
	self.PathEpoch, self.Sources = current, evsSourceEpochs(head.Head.GetPathEpoch())
	self.pathKey, self.nameKey = pathKey, nameKey
	for _, planned := range self.Paths {
		if planned.TokenPath, err = self.tokenPathIn(ctx, planned.names, current); err != nil {
			return err
		}
		if planned.SourcePaths, err = self.sourcePathsOf(ctx, planned); err != nil {
			return err
		}
		if planned.creates() {
			planned.Version = max(self.BaseVersion, planned.removalVersion) + 1
		}
	}
	for _, planned := range self.Paths {
		if planned.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY && !planned.Remove {
			if err := self.directoryRows(ctx, planned); err != nil {
				return err
			}
		}
	}
	return nil
}

// The plan's path-epoch rules over its written paths (DESIGN-DETAILS 9.2.5): a creation on a blocking ref under
// immediate pressure waits for the epoch, ErrEvsPathEpochDue, nothing sent; while the head lists sources, a removal
// lowers its path's floor to its row's epoch (E2), which its parent's delta then names the child's token in; and each
// written path's source paths by its floor. A directory change takes its own in evsDirectoryChanges.
func (self *EvsRepo) planEpochs(ctx context.Context, plan *EvsWritePlan) error {
	if creates := slices.ContainsFunc(plan.Paths, (*EvsPlannedPath).creates); creates || 0 < len(plan.Sources) {
		state := &evsRefEpoch{refId: plan.RefId, epoch: plan.Head.GetPathEpoch(), version: plan.BaseVersion,
			generation: plan.Head.GetGeneration(), refKind: plan.RefKind}
		if creates {
			quiet, err := self.quiet(ctx, state)
			if err != nil {
				return err
			}
			if !quiet {
				return ErrEvsPathEpochDue
			}
		}
	}
	if 0 < len(plan.Sources) {
		for _, planned := range plan.Paths {
			if !planned.Remove {
				continue
			}
			row, err := self.lookup(ctx, plan.RefId, planned.Path)
			if err != nil {
				return err
			}
			if row != nil {
				plan.floors[planned.Path] = evsLowerFloor(plan.floors[planned.Path], row.epoch)
			}
		}
	}
	for _, planned := range plan.Paths {
		sourcePaths, err := plan.sourcePathsOf(ctx, planned)
		if err != nil {
			return err
		}
		planned.SourcePaths = sourcePaths
	}
	return nil
}
