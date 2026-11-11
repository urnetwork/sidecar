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
// Retoken. On a ref with no head the read sends no path and every write creates; the plan, made in the epoch an
// absent head reads as, moves whole to the epoch its ref starts in (firstEpoch; DESIGN-DETAILS 9.2.3, QD-632), and its
// push commits only as the one that creates the ref.
//
// Record-class repos (slot-keyed: §11.6's object key row) keep each chain's object key in a deletable slot/ object
// rather than in its segment: a new chain, a checkpoint or chunks, draws a fresh key in a new slot as it is sealed
// (evs_upload.go), and a diff appended to a chain seals under the chain's own slot key, which the plan opens from the
// previous version's slot, so one ERASE of that key ends every record of the chain. Their chains never ride inline:
// format 1's inline record carries its own key block (EVS-FORMAT.md), which a slot-keyed chain must not, so a
// slot-keyed inline record is left to a format change and every chain goes in slot-keyed segments.
//
// A git-mode ref takes a write through PlanWrite only as a rekey (DESIGN-DETAILS 8.2.10; question
// keys-m2-26-rekey-git-mode-refs): every write a forced checkpoint held to the version it read, none a removal, each new
// blob the standing version's with its mode, a gitlink's empty chain re-sealed as it stands; the sender seals the
// REKEY shape. Any other write to a git-mode ref is ErrEvsGitRef: the local tier plans a git ref update through
// PlanGitUpdate (below), sharing the chain rules, with a rename keeping its file's chain.
//
// Not built here, and failing closed: a file-mode rename or copy, which would keep a file's chain under another path
// through the reuse list.
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
	// A rekey write to a git-mode ref whose new blob, or mode, is not the standing version's: a rekey changes no tree
	// (DESIGN-DETAILS 8.2.10).
	ErrEvsRekeyChanged = errors.New("evs: a rekey write that changes a git-mode file's oid or mode")
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
	// What the push carries beside its changes: its flags (CLOSURE, ERASE), the keys its erased list names, and the
	// token scope it goes under, rw when empty (evs_erase.go, evs_closure.go).
	Flags  uint32
	Erased []*EvsErasedKey
	scope  string
	// a git-mode push's update, which the sender seals as EvsSealedMetadata.git: a rekey's REKEY shape, set by setRef
	gitUpdate *protocol.EvsGitUpdate
	// planned on a ref with no head, in the epoch firstEpoch gave: a refusal is answered by planning again, never by a
	// retoken, and lowers no floor (DESIGN-DETAILS 9.2.3)
	firstPush bool
	// the repo keeps its object keys in slots, a record-class repo's (see the file header)
	slotKeyed bool
	// a git plan's: where its writes' bytes come from, the spills they are held in until sealed, and what the push
	// seals beside its update (evs_push.go's evsGitPushExtras)
	blobs     EvsGitBlobSource
	contents  []*evsSpill
	gitExtras *evsGitPushExtras
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
	// slot-keyed repos: the key a diff appended to the previous chain seals under, its slot's; and the slots the
	// records of the locators this version keeps name, in chain order
	chainKey    *evsChainKey
	keptSlotIds []Id
}

// A slot-keyed chain's object key and where its slot holds it.
type evsChainKey struct {
	slotId     Id
	keyIndex   uint16
	generation uint64
	objectKey  *EvsObjectKey
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
	// every write a rekey write: the one write a git-mode ref takes here (DESIGN-DETAILS 8.2.10)
	rekeyOnly := true
	for _, write := range args.Writes {
		rekeyOnly = rekeyOnly && write.ForceCheckpoint && write.IfVersion != 0 && !write.Remove
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
					slotKeyed: EvsRepoKindRecordClass(repoKind),
				}
				if err := plan.setRef(head, args.RefName, self.client.args.Identity().SidecarId, rekeyOnly); err != nil {
					return err
				}
				// a ref with no head, which the read sent no path of: the push commits only as the one that creates
				// the ref, in the epoch it starts in (DESIGN-DETAILS 9.2.3's first push), which the plan moves to whole
				// once it is made
				plan.firstPush = result.head.Version == 0
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
	if plan.firstPush {
		epoch, err := self.firstEpoch(ctx, plan.RefKind, nil, args.Generation)
		if err != nil {
			return nil, err
		}
		if err := plan.tokenizeIn(ctx, epoch); err != nil {
			return nil, err
		}
	}
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
// ur/<this sidecar>/..., shared otherwise. A git-mode ref is ErrEvsGitRef but for a rekey's writes, rekeyOnly, which
// seal the REKEY shape; another sidecar's owned ref, a deposit or the erasure ref take no Write.
func (self *EvsWritePlan) setRef(head *protocol.EvsHeadSummary, refName []byte, sidecarId Id, rekeyOnly bool) error {
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
		if !rekeyOnly {
			return ErrEvsGitRef
		}
		self.gitUpdate = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_REKEY}
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
	var previousKeys *evsChainKeys
	if stands {
		content, state, keys, fields, err := self.readBaseKeys(ctx, result, verified)
		if err != nil {
			return nil, err
		}
		defer content.close()
		previous, previousContent, previousKeys = state, content, keys
		planned.Fields.FileId = fields.GetFileId()
		planned.Fields.Mode = fields.GetMode()
		if plan.RefMode == protocol.EvsRefMode_EVS_REF_GIT {
			// a rekey: the standing blob and mode again under the plan's generation (DESIGN-DETAILS 8.2.10)
			if write.Mode != 0 && write.Mode != fields.GetMode() {
				return nil, fmt.Errorf("%w: mode %o over %o", ErrEvsRekeyChanged, write.Mode, fields.GetMode())
			}
			if fields.GetMode() == EvsGitModeGitlink {
				// a gitlink has no content: its fields are sealed again with its empty chain
				if write.Content.Size() != 0 {
					return nil, fmt.Errorf("%w: content for a gitlink", ErrEvsRekeyChanged)
				}
				planned.Fields = proto.Clone(fields).(*protocol.EvsSealedFields)
				planned.Checkpoint = EvsCheckpointForced
				return planned, nil
			}
			if !bytes.Equal(oid[:], fields.GetGitOid()) {
				return nil, fmt.Errorf("%w: a new blob over the standing one", ErrEvsRekeyChanged)
			}
		}
	}
	if write.Mode != 0 {
		planned.Fields.Mode = write.Mode
	}
	if !evsFileModeValid(planned.Fields.GetMode()) {
		return nil, fmt.Errorf("%w: mode %o is no file's", ErrEvsWriteInvalid, planned.Fields.GetMode())
	}
	if err := self.planChain(ctx, plan, planned, write, verified, previous, previousContent, previousKeys, oid); err != nil {
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

// A file version's chain: chunks, a checkpoint, or the previous chain and a diff. In a slot-keyed repo a diff goes
// only on a chain whose one slot key the plan opened, and nothing rides inline (see the file header).
func (self *EvsRepo) planChain(ctx context.Context, plan *EvsWritePlan, planned *EvsPlannedPath, write *EvsPathWrite, verified *EvsVerifiedPath, previous *EvsChainState, previousContent *evsSpill, previousKeys *evsChainKeys, oid EvsGitOid) error {
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
	forced := write.ForceCheckpoint
	if plan.slotKeyed && previous != nil && !previous.Chunked && (previous.Inline || previousKeys == nil || previousKeys.chain == nil) {
		// a chain under no one slot key of its own takes no diff here: it starts again in a slot
		forced = true
	}
	reason := EvsCheckpointBefore(&EvsCheckpointArgs{
		Previous: previous, Size: size, Force: forced, RemoveSince: removeSince, Generation: plan.Generation,
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
				if plan.slotKeyed {
					slotId, ok := previousKeys.slotOf(chunk.Kept)
					if !ok {
						return fmt.Errorf("%w: a kept chunk under no slot key", ErrEvsWriteInvalid)
					}
					planned.keptSlotIds = append(planned.keptSlotIds, slotId)
				}
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
			if plan.slotKeyed {
				planned.chainKey = previousKeys.chain
				for range verified.Entry.GetChain() {
					planned.keptSlotIds = append(planned.keptSlotIds, previousKeys.chain.slotId)
				}
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
	planned.Inline = !plan.slotKeyed && EvsPadme(EvsWrappedKeyByteCount+EvsRecordByteCount(size)) <= EvsInlineMaxByteCount
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

// The keys a previous version's chain is under, in a slot-keyed repo: each record's slot by its locator, and the
// chain's one slot key, opened, when every record is under it.
type evsChainKeys struct {
	slots map[*protocol.EvsLocator]Id
	chain *evsChainKey
}

// The slot locator's record names, false for none.
func (self *evsChainKeys) slotOf(locator *protocol.EvsLocator) (Id, bool) {
	if self == nil {
		return Id{}, false
	}
	slotId, ok := self.slots[locator]
	return slotId, ok
}

// The previous version's content, reconstructed and checked against its sealed fields' oid and size, its fields,
// and what its chain holds: the facts the checkpoint rules read.
func (self *EvsRepo) readBase(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath) (*evsSpill, *EvsChainState, *protocol.EvsSealedFields, error) {
	content, state, _, fields, err := self.readBaseKeys(ctx, result, verified)
	return content, state, fields, err
}

// readBase, with the keys the chain is under in a slot-keyed repo.
func (self *EvsRepo) readBaseKeys(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath) (*evsSpill, *EvsChainState, *evsChainKeys, *protocol.EvsSealedFields, error) {
	state := &EvsChainState{RecordCount: len(verified.Entry.GetChain())}
	pushGeneration := verified.Statement.Push.GetGeneration()
	keys := &evsChainKeys{slots: map[*protocol.EvsLocator]Id{}}
	// the slot key every record so far is under, false once two differ or one is the container's
	var oneKey *EvsRecordHeader
	oneSlot := true
	onRecord := func(header *EvsRecordHeader, locator *protocol.EvsLocator) {
		if header.KeyRefKind == protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT {
			keys.slots[locator] = header.SlotId
		}
		switch {
		case header.KeyRefKind != protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT:
			oneSlot = false
		case oneKey == nil:
			copied := *header
			oneKey = &copied
		case oneKey.SlotId != header.SlotId || oneKey.KeyIndex != header.KeyIndex || oneKey.Generation != header.Generation:
			oneSlot = false
		}
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
		return nil, nil, nil, nil, err
	}
	state.Size = uint64(content.Size())
	if oneSlot && oneKey != nil {
		objectKey, err := self.slotKey(ctx, result, oneKey)
		if err != nil {
			content.close()
			return nil, nil, nil, nil, err
		}
		keys.chain = &evsChainKey{slotId: oneKey.SlotId, keyIndex: oneKey.KeyIndex, generation: oneKey.Generation, objectKey: objectKey}
	}
	return content, state, keys, fields, nil
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
	self.BaseVersion, self.BaseChain, self.Head = head.Version, head.Chain, head.Head
	self.Sources = evsSourceEpochs(head.Head.GetPathEpoch())
	if err := self.tokenizeIn(ctx, current); err != nil {
		return err
	}
	for _, planned := range self.Paths {
		if planned.creates() {
			planned.Version = max(self.BaseVersion, planned.removalVersion) + 1
		}
	}
	return nil
}

// Makes every path's token path and source paths, and every directory's rows, again in epoch, the plan's keys moved
// there: a retoken's work on its new head, and a first push's, made in the epoch an absent head reads as, on the epoch
// its ref starts in (DESIGN-DETAILS 9.2.3). What is sealed stays.
func (self *EvsWritePlan) tokenizeIn(ctx context.Context, epoch uint64) error {
	pathKey, err := self.keys.path(ctx, epoch)
	if err != nil {
		return err
	}
	nameKey, err := self.keys.manifest(ctx, epoch)
	if err != nil {
		return err
	}
	self.PathEpoch, self.pathKey, self.nameKey = epoch, pathKey, nameKey
	for _, planned := range self.Paths {
		if planned.TokenPath, err = self.tokenPathIn(ctx, planned.names, epoch); err != nil {
			return err
		}
		if planned.SourcePaths, err = self.sourcePathsOf(ctx, planned); err != nil {
			return err
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

// A git update whose net change does not match what evs's entries say the tree the path state stands at is: a path
// the old tree holds that evs does not, or the reverse. The update is refused before any evs write; a replaying reader
// holds every version to its tree (DESIGN-DETAILS 8.2.7's G4), so this is a fault, never a race.
var ErrEvsGitStateDiffers = errors.New("evs: a git update's tree and the ref's entries differ")

// A git update past §11.19's directory bounds on its new tree, or past a push's entry writes: refused before any evs
// write, naming the path (DESIGN-DETAILS 8.2.4's limits row, `ng <ref> DIRECTORY_FULL <path>`).
var ErrEvsDirectoryFull = errors.New("evs: DIRECTORY_FULL")

// The most entries one push writes: 1,024 parts of 1,024 entry writes (§11.8's parts row).
const EvsPushMaxEntryWriteCount = EvsMaxPartCount * EvsPartMaxEntryWriteCount

// A git plan's read found the ref's head past the version the update is built on (DESIGN-DETAILS 8.2.5's 409 row):
// the caller judges the versions between, a PATH_EPOCH or a rekey alone leaving the tip where it was, before it
// builds again.
type EvsGitHeadMovedError struct {
	// The head the read verified.
	Head *EvsVerifiedHead
	// The version the update was built on.
	BaseVersion uint64
}

func (self *EvsGitHeadMovedError) Error() string {
	return fmt.Sprintf("evs: the ref's head is at %d, past the update's base %d", self.Head.Version, self.BaseVersion)
}

// One path of a git ref update's net change (DESIGN-DETAILS 8.2.4), what PlanGitUpdate plans: a file written or
// removed, a directory created, given a delta or removed, and a path that changes kind created as its new kind. The
// local tier makes these from its trees with the tree reader (evs_local_publish.go). A path's kind, mode and oids are
// the trees', which evs cannot see: the plan holds evs's entries to them and refuses a mismatch.
type EvsGitPathChange struct {
	// Raw names joined by /, never normalized; "" is the root.
	Path string
	// What the tree the path state stands at held there, and what the new tree holds: a file, a directory, or
	// UNSPECIFIED for nothing. A removal holds nothing; a path whose two kinds differ is a creation of the new one
	// over the old (8.2.2's kinds row). The root is read from evs, whose root stands once any push created it.
	Stood protocol.EvsEntryKind
	Kind  protocol.EvsEntryKind
	// A file's canon mode and blob oid in the new tree; for one that stood, its blob there, which a rename pairs by.
	Mode     uint32
	Oid      EvsGitOid
	StoodOid EvsGitOid
	// A directory in the new tree: every child it has, which its creation lists, and the children its delta adds,
	// new or of another kind, and the names it removes.
	Children []*EvsGitChild
	Added    []*EvsGitChild
	Removed  [][]byte
}

// A directory's child in a tree: its raw name and its kind.
type EvsGitChild struct {
	Name []byte
	Kind protocol.EvsEntryKind
}

// Whether the change removes its path.
func (self *EvsGitPathChange) removes() bool {
	return self.Kind == protocol.EvsEntryKind_EVS_ENTRY_KIND_UNSPECIFIED
}

// Where a git plan reads a write's bytes: an object store that checks each blob against its oid as it streams it, the
// mount's bare repository (EvsLocalObjects).
type EvsGitBlobSource interface {
	CopyBlob(ctx context.Context, oid EvsGitOid, out io.Writer) (int64, error)
}

// What PlanGitUpdate plans against.
type EvsGitPlanArgs struct {
	// The ref's name bytes, and its id.
	RefName []byte
	RefId   Id
	// The update the push seals as its sealed metadata's git (8.2.3), and the net change its changes state, every
	// path once. A tag ref's and a DELETE's are empty.
	Update  *protocol.EvsGitUpdate
	Changes []*EvsGitPathChange
	// The version the update is built on, whose tip is the update's old one: a head past it is EvsGitHeadMovedError.
	BaseVersion uint64
	// A creating push's overlay base, payload section 16, nil for none.
	Base *protocol.EvsOverlay
	// Each write's new bytes, by its oid.
	Blobs EvsGitBlobSource
	// The generation this push seals to, from GkmClient.EnsureWritable.
	Generation uint64
	// Reads the cluster's head, not evs's cache.
	Fresh bool
}

// Plans a git ref update on its ref (DESIGN-DETAILS 8.2.4's planner, beside PlanWrite and sharing its chain rules):
//
//	reads      each changed path's standing entry read from evs, 64 a request, under section 9's floors, every batch
//	           on the one head the first read verified, which must be the update's base; a ref with no head reads
//	           nothing, so every change is a creation at version b + 1
//	content    a write's new bytes from Blobs by its oid, hashed as they are read; its previous version's, which a
//	           diff applies to, reconstructed from evs and checked against its own oid
//	chain      the planner's rules unchanged: a diff on the path's previous version, else a checkpoint by rules (1)
//	           to (4); past 8 MiB in chunks; an inline chain to 16 KiB
//	kinds      a path that changes kind is a creation of the new kind over the standing entry, base_entry_version 0,
//	           and a removed directory takes no delta of its own, its paths removed by their own changes
//	rename     a removed file and a created file with one blob oid, in one push: the created path takes the removed
//	           one's file_id and, where the checkpoint rules let a diff stand, its chain whole, so nothing is
//	           uploaded; several candidates pair in path order
//	gitlink    mode 160000: its sealed fields and an empty chain
//	versions   versioning 0 on every entry: git mode is never versionless
//	limits     32 components a path, 4,096 children and 448 KiB of names a directory of the new tree, 1,048,576
//	           entry writes a push, all before any evs write (ErrEvsDirectoryFull)
//	epochs     a creation on a blocking ref under immediate pressure waits (ErrEvsPathEpochDue); while sources stand
//	           each change names its source paths by its floor, as PlanWrite's do; a ref's first push moves whole to
//	           the epoch it starts in (firstEpoch: an overlay's is its base ref's current one, read fresh)
//
// Not built here, and failing closed: an overlay's paths (ErrEvsOverlayBase), which read through the base ref, and
// the reuse list, which cites a base's or a source's standing chain.
func (self *EvsRepo) PlanGitUpdate(ctx context.Context, args *EvsGitPlanArgs) (*EvsWritePlan, error) {
	for _, reserved := range evsReservedRefNames {
		if bytes.Equal(args.RefName, reserved) {
			return nil, fmt.Errorf("%w: a format-2 or v1 ref", ErrEvsReservedPath)
		}
	}
	if args.Update == nil || args.Blobs == nil {
		return nil, fmt.Errorf("%w: a git plan with no update or no blobs", ErrEvsWriteInvalid)
	}
	if err := evsGitCheckLimits(args.Changes); err != nil {
		return nil, err
	}
	repoKind, err := self.repoKind()
	if err != nil {
		return nil, err
	}
	if EvsRepoKindRecordClass(repoKind) {
		return nil, fmt.Errorf("%w: a git-mode ref in a slot-keyed repo", ErrEvsWriteNotBuilt)
	}
	changes := map[string]*EvsGitPathChange{}
	for _, change := range args.Changes {
		if changes[change.Path] != nil {
			return nil, fmt.Errorf("%w: a path changed twice", ErrEvsWriteInvalid)
		}
		changes[change.Path] = change
	}
	renames := evsGitRenames(args.Changes)
	plan := (*EvsWritePlan)(nil)
	planned := map[string]*EvsPlannedPath{}
	contents := []*evsSpill{}
	keep := false
	defer func() {
		if !keep {
			for _, content := range contents {
				content.close()
			}
		}
	}()
	readBatch := func(batch []string, fresh bool) error {
		result, err := self.read(ctx, args.RefId, batch, 0, fresh)
		if err != nil {
			return err
		}
		defer result.objects.close()
		head := result.head.Head
		if plan == nil {
			if result.head.Version != args.BaseVersion {
				return &EvsGitHeadMovedError{Head: result.head, BaseVersion: args.BaseVersion}
			}
			plan = &EvsWritePlan{
				RepoId: self.repoId, RefId: args.RefId, BaseVersion: result.head.Version, BaseChain: result.head.Chain,
				Head: head, PathEpoch: evsCurrentEpoch(head.GetPathEpoch()), Sources: evsSourceEpochs(head.GetPathEpoch()),
				Generation: args.Generation, keys: result.keys, floors: map[string]uint64{}, gitUpdate: args.Update,
				blobs: args.Blobs,
			}
			if err := plan.setGitRef(head, args.RefName, self.client.args.Identity().SidecarId); err != nil {
				return err
			}
			plan.firstPush = result.head.Version == 0
			if plan.pathKey, err = result.keys.path(ctx, plan.PathEpoch); err != nil {
				return err
			}
			if plan.nameKey, err = result.keys.manifest(ctx, plan.PathEpoch); err != nil {
				return err
			}
		} else if result.head.Version != plan.BaseVersion {
			return &EvsGitHeadMovedError{Head: result.head, BaseVersion: plan.BaseVersion}
		} else if !evsSamePathEpoch(head.GetPathEpoch(), plan.Head.GetPathEpoch()) {
			return errEvsPlanEpochMoved
		}
		verifieds := map[string]*EvsVerifiedPath{}
		for i, readPath := range result.paths {
			if readPath.path != "" {
				plan.floors[readPath.path] = evsLowerFloor(plan.floors[readPath.path], readPath.floor)
			}
			verifieds[readPath.path] = result.replies[i]
		}
		for i, readPath := range result.paths {
			var from *evsGitRenameSource
			if source, ok := renames[readPath.path]; ok {
				from = &evsGitRenameSource{path: source, verified: verifieds[source]}
			}
			path, err := self.planGitPath(ctx, plan, result, readPath, result.replies[i], changes[readPath.path], from, &contents)
			if err != nil {
				return err
			}
			planned[readPath.path] = path
		}
		return nil
	}
	batches := evsGitReadBatches(args.Changes, renames)
	if len(batches) == 0 {
		// an update that changes no path, a tag's, a DELETE's or a branch's at a tree it holds: the head alone
		batches = [][]string{nil}
	}
	for i, batch := range batches {
		if err := readBatch(batch, args.Fresh || 0 < i); err != nil {
			return nil, err
		}
	}
	for _, change := range args.Changes {
		if path := planned[change.Path]; path != nil {
			plan.Paths = append(plan.Paths, path)
		}
	}
	if err := self.planEpochs(ctx, plan); err != nil {
		return nil, err
	}
	for _, path := range plan.Paths {
		if path.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY && !path.Remove {
			if err := plan.directoryRows(ctx, path); err != nil {
				return nil, err
			}
		}
	}
	if plan.firstPush {
		epoch, err := self.firstEpoch(ctx, plan.RefKind, args.Base, args.Generation)
		if err != nil {
			return nil, err
		}
		if err := plan.tokenizeIn(ctx, epoch); err != nil {
			return nil, err
		}
	}
	plan.contents = contents
	keep = true
	return plan, nil
}

// The ref's kind, mode and owner for a git update: the head's once a push set them, which must be git mode, else a
// git-mode ref named by refName, owned for ur/<this sidecar>/..., shared otherwise. Another sidecar's owned ref, a
// deposit and the erasure ref take no git update.
func (self *EvsWritePlan) setGitRef(head *protocol.EvsHeadSummary, refName []byte, sidecarId Id) error {
	self.RefKind = head.GetRefKind()
	self.RefMode = head.GetRefMode()
	if self.RefKind == protocol.EvsRefKind_EVS_REF_KIND_UNSPECIFIED {
		self.RefKind = protocol.EvsRefKind_EVS_REF_SHARED
		self.RefMode = protocol.EvsRefMode_EVS_REF_GIT
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
	if self.RefMode != protocol.EvsRefMode_EVS_REF_GIT {
		return fmt.Errorf("%w: a git update of a file-mode ref", ErrEvsWriteInvalid)
	}
	switch self.RefKind {
	case protocol.EvsRefKind_EVS_REF_SHARED:
	case protocol.EvsRefKind_EVS_REF_OWNED:
		if self.OwnerSidecarId == nil || *self.OwnerSidecarId != sidecarId {
			return fmt.Errorf("%w: another sidecar's owned ref", ErrEvsWriteInvalid)
		}
	default:
		return fmt.Errorf("%w: a %s ref takes no git update", ErrEvsWriteInvalid, self.RefKind)
	}
	return nil
}

// Closes the spills a git plan holds its writes' bytes in, once they are sealed.
func (self *EvsWritePlan) closeContents() {
	for _, content := range self.contents {
		content.close()
	}
	self.contents = nil
}

// The removed file a created file takes its file_id and chain from, as its batch read it.
type evsGitRenameSource struct {
	path     string
	verified *EvsVerifiedPath
}

// Each created file whose blob a removed file of the update held, mapped to that removed file: candidates of one oid
// pair in path order (DESIGN-DETAILS 8.2.4's rename row). A gitlink has no content and takes no rename.
func evsGitRenames(changes []*EvsGitPathChange) map[string]string {
	oidRemoved := map[EvsGitOid][]string{}
	for _, change := range changes {
		if change.removes() && change.Stood == protocol.EvsEntryKind_EVS_ENTRY_FILE && change.Path != "" {
			oidRemoved[change.StoodOid] = append(oidRemoved[change.StoodOid], change.Path)
		}
	}
	renames := map[string]string{}
	if len(oidRemoved) == 0 {
		return renames
	}
	created := []*EvsGitPathChange{}
	for _, change := range changes {
		if change.Kind == protocol.EvsEntryKind_EVS_ENTRY_FILE && change.Stood == protocol.EvsEntryKind_EVS_ENTRY_KIND_UNSPECIFIED &&
			change.Mode != EvsGitModeGitlink {
			created = append(created, change)
		}
	}
	slices.SortFunc(created, func(a *EvsGitPathChange, b *EvsGitPathChange) int { return strings.Compare(a.Path, b.Path) })
	for removed := range oidRemoved {
		slices.Sort(oidRemoved[removed])
	}
	for _, change := range created {
		candidates := oidRemoved[change.Oid]
		if len(candidates) == 0 {
			continue
		}
		renames[change.Path] = candidates[0]
		oidRemoved[change.Oid] = candidates[1:]
	}
	return renames
}

// The changes' paths in read batches of at most 64, a rename's removed path in the batch of the path created from it,
// so one read serves both.
func evsGitReadBatches(changes []*EvsGitPathChange, renames map[string]string) [][]string {
	sourceTargets := map[string]string{}
	for target, source := range renames {
		sourceTargets[source] = target
	}
	batches := [][]string{}
	batch := []string{}
	add := func(paths ...string) {
		if EvsReadMaxPathCount < len(batch)+len(paths) {
			batches = append(batches, batch)
			batch = []string{}
		}
		batch = append(batch, paths...)
	}
	for _, change := range changes {
		switch {
		case renames[change.Path] != "":
			add(renames[change.Path], change.Path)
		case sourceTargets[change.Path] != "":
			// read with its target
		default:
			add(change.Path)
		}
	}
	if 0 < len(batch) {
		batches = append(batches, batch)
	}
	return batches
}

// §11.19's bounds on the new tree, checked on every directory the update changes, and the push's entry writes.
func evsGitCheckLimits(changes []*EvsGitPathChange) error {
	if EvsPushMaxEntryWriteCount < len(changes) {
		return fmt.Errorf("%w: %d entry writes in one update", ErrEvsDirectoryFull, len(changes))
	}
	for _, change := range changes {
		if change.Path != "" {
			names, err := evsPathNames(change.Path)
			if err != nil {
				return err
			}
			if EvsTokenPathMaxLength < len(names) {
				return fmt.Errorf("%w: %s holds %d components", ErrEvsDirectoryFull, change.Path, len(names))
			}
		}
		if change.Kind != protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
			continue
		}
		if EvsDirectoryMaxChildCount < len(change.Children) {
			return fmt.Errorf("%w: %q holds %d children", ErrEvsDirectoryFull, change.Path, len(change.Children))
		}
		boundByteCount := 0
		for _, child := range change.Children {
			boundByteCount += evsNameRowBoundByteCount(child.Name, child.Kind)
		}
		if EvsNameTableMaxBoundByteCount < boundByteCount {
			return fmt.Errorf("%w: %q holds %d bytes of names", ErrEvsDirectoryFull, change.Path, boundByteCount)
		}
	}
	return nil
}

// What one child's row counts against a table's 448 KiB, as EvsNameTableBoundByteCount counts it once sealed: its
// token, its kind and its name padded and sealed (EvsNameSeal).
func evsNameRowBoundByteCount(name []byte, kind protocol.EvsEntryKind) int {
	paddedLength := (len(name)/evsNamePadByteCount + 1) * evsNamePadByteCount
	row := &protocol.EvsName{Token: make([]byte, EvsTokenByteCount), Kind: uint32(kind), SealedName: make([]byte, paddedLength+evsSealOverhead)}
	rowByteCount := proto.Size(row)
	return 1 + evsVarintByteCount(uint64(rowByteCount)) + rowByteCount
}

// One changed path's plan from its read on the ref: see PlanGitUpdate. from is a created file's rename source, nil for
// none. A write's bytes are spilled into contents, which the plan closes once they are sealed.
func (self *EvsRepo) planGitPath(ctx context.Context, plan *EvsWritePlan, result *evsReadResult, readPath *evsReadPath, verified *EvsVerifiedPath, change *EvsGitPathChange, from *evsGitRenameSource, contents *[]*evsSpill) (*EvsPlannedPath, error) {
	if verified.Base != nil {
		return nil, ErrEvsOverlayBase
	}
	planned := &EvsPlannedPath{Path: change.Path, TokenPath: readPath.current, Kind: change.Kind, names: readPath.names}
	stood := protocol.EvsEntryKind_EVS_ENTRY_KIND_UNSPECIFIED
	if verified.Entry != nil {
		stood = protocol.EvsEntryKind(verified.Entry.GetKind())
		planned.PrevPushId = verified.Statement.Push.GetPushId()
		planned.PrevCommitVersion = verified.CommitVersion
	}
	if change.Path != "" && stood != change.Stood {
		return nil, fmt.Errorf("%w: %q stands as kind %d where the tree has %d", ErrEvsGitStateDiffers, change.Path, stood, change.Stood)
	}
	// a write on the standing entry of its own kind, else a creation over what stands, or over nothing
	writesOver := stood != protocol.EvsEntryKind_EVS_ENTRY_KIND_UNSPECIFIED && stood == change.Kind
	if change.removes() {
		if stood == protocol.EvsEntryKind_EVS_ENTRY_KIND_UNSPECIFIED {
			return nil, fmt.Errorf("%w: a removal of %q, which does not stand", ErrEvsGitStateDiffers, change.Path)
		}
		planned.Remove = true
		planned.Kind = stood
		planned.BaseEntryVersion = evsVerifiedNewestVersion(verified)
		return planned, nil
	}
	if writesOver {
		planned.BaseEntryVersion = evsVerifiedNewestVersion(verified)
		planned.Version = planned.BaseEntryVersion + 1
	} else {
		if verified.Removal != nil {
			planned.removalVersion = verified.Removal.GetPathVersion()
		}
		planned.Version = max(plan.BaseVersion, planned.removalVersion) + 1
	}
	if change.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
		children := change.Children
		removed := [][]byte{}
		if writesOver {
			children, removed = change.Added, change.Removed
		}
		parentPath := change.Path
		for _, child := range children {
			planned.children = append(planned.children, &evsChildChange{path: evsGitJoin(parentPath, child.Name), name: child.Name, kind: child.Kind})
		}
		for _, name := range removed {
			planned.children = append(planned.children, &evsChildChange{path: evsGitJoin(parentPath, name), name: name, removed: true})
		}
		return planned, nil
	}
	if change.Kind != protocol.EvsEntryKind_EVS_ENTRY_FILE || !evsFileModeValid(change.Mode) {
		return nil, fmt.Errorf("%w: %q of kind %d, mode %o", ErrEvsWriteInvalid, change.Path, change.Kind, change.Mode)
	}
	if change.Mode == EvsGitModeGitlink {
		// a gitlink has no content: its sealed fields and an empty chain (DESIGN-DETAILS 8.2.2's gitlink row)
		planned.Fields = &protocol.EvsSealedFields{
			FileId: NewEvsSlotId().Bytes(), Mode: EvsGitModeGitlink, GitOid: bytes.Clone(change.Oid[:]), OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
		}
		if writesOver {
			fields, err := self.openStandingFields(ctx, result, verified)
			if err != nil {
				return nil, err
			}
			planned.Fields.FileId = fields.GetFileId()
		}
		planned.Checkpoint = EvsCheckpointNewFile
		return planned, nil
	}
	content := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
	*contents = append(*contents, content)
	size, err := self.copyGitBlob(ctx, plan, change.Oid, content)
	if err != nil {
		return nil, err
	}
	if EvsFileMaxByteCount < size {
		return nil, fmt.Errorf("%w: %d bytes", ErrEvsFileTooLarge, size)
	}
	write := &EvsPathWrite{Path: change.Path, Content: content, Mode: change.Mode}
	planned.Fields = &protocol.EvsSealedFields{
		FileId: NewEvsSlotId().Bytes(), Mode: change.Mode, GitOid: bytes.Clone(change.Oid[:]), OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
		Size: uint64(size),
	}
	var previous *EvsChainState
	var previousContent *evsSpill
	var previousVerified *EvsVerifiedPath
	switch {
	case writesOver:
		previousVerified = verified
	case from != nil && from.verified != nil && from.verified.Entry != nil &&
		from.verified.Entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE):
		// a rename: the removed file's file_id, and its chain where the rules let a diff stand on it
		previousVerified = from.verified
	}
	if previousVerified != nil {
		previousBytes, state, _, fields, err := self.readBaseKeys(ctx, result, previousVerified)
		if err != nil {
			return nil, err
		}
		defer previousBytes.close()
		previous, previousContent = state, previousBytes
		planned.Fields.FileId = fields.GetFileId()
		if !writesOver {
			// a rename: its chain whole where the rules let it stand, else a checkpoint under the kept file_id
			kept, err := self.planGitRename(ctx, plan, planned, previousVerified, state, fields)
			if err != nil || kept {
				return planned, err
			}
			previous, previousContent, previousVerified = nil, nil, nil
		}
	}
	if err := self.planChain(ctx, plan, planned, write, previousVerified, previous, previousContent, nil, change.Oid); err != nil {
		return nil, err
	}
	return planned, nil
}

// A renamed file's chain, the removed path's whole, when checkpoint rules (1) to (4) let a diff stand on it: the
// created path keeps its file_id and its own mode, and uploads nothing; kept answers whether it did. An inline chain
// sealed under another generation, which a reader opens under the push's own, and a chain a rule would checkpoint are
// not kept, and the caller plans a checkpoint of the same content under the kept file_id.
func (self *EvsRepo) planGitRename(ctx context.Context, plan *EvsWritePlan, planned *EvsPlannedPath, removed *EvsVerifiedPath, state *EvsChainState, fields *protocol.EvsSealedFields) (bool, error) {
	removeSince, err := evsRemoveGenerationSince(ctx, self.client.args.Gkm, self.repoId, state.KeyGeneration, plan.Generation)
	if err != nil {
		return false, err
	}
	reason := EvsCheckpointBefore(&EvsCheckpointArgs{
		Previous: state, Size: planned.Fields.GetSize(), RemoveSince: removeSince, Generation: plan.Generation,
		DiffMaxByteCount: uint64(self.client.settings.DiffMaxByteCount),
	})
	if state.Inline && state.InlineGeneration != plan.Generation {
		return false, nil
	}
	if reason != EvsCheckpointNone && !(reason == EvsCheckpointChunked && state.Chunked) {
		return false, nil
	}
	for _, locator := range removed.Entry.GetChain() {
		planned.Chain = append(planned.Chain, &EvsPlannedLink{Kept: locator})
	}
	planned.Inline = state.Inline
	planned.Fields.Size = fields.GetSize()
	return true, nil
}

// Streams oid's blob from the plan's source into out, its oid checked by the source, and answers its size.
func (self *EvsRepo) copyGitBlob(ctx context.Context, plan *EvsWritePlan, oid EvsGitOid, out io.Writer) (int64, error) {
	if plan.blobs == nil {
		return 0, fmt.Errorf("%w: a git plan with no blob source", ErrEvsWriteInvalid)
	}
	return plan.blobs.CopyBlob(ctx, oid, out)
}

// A standing file's sealed fields, opened under the manifest key of the generation its push sealed to.
func (self *EvsRepo) openStandingFields(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath) (*protocol.EvsSealedFields, error) {
	manifest, err := result.keys.manifest(ctx, verified.Statement.Push.GetGeneration())
	if err != nil {
		return nil, err
	}
	return EvsOpenFields(manifest, verified.Entry.GetSealedFields())
}

// A path's child path: parent "" is the root.
func evsGitJoin(parent string, name []byte) string {
	if parent == "" {
		return string(name)
	}
	return parent + "/" + string(name)
}
