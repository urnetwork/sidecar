//go:build !ios_extension

// The format-2 half of the push sender (§11.7's Versionless rows, §11.8's parts row; R-EVS-20, R-CTX-34, D-EVS-38,
// D-EVS-42, FS-64, FS-68; EVS2-M10-16): what Write, WritePaths and the sender add to format 1's once a version is
// versionless.
//
//	setting   a write that carries EvsWriteOptions has each plan decide its version's versioning through
//	          EvsVersioningFor over the plan's own read of the path: "" keeps the path's and gives a new path its
//	          rules' setting, "on" and "off" set it, as §18.5 spells them. An explicit "off" outside §19.11's format2
//	          gate is ErrEvsFormatUnsupported, nothing sent; everything else EvsVersioningFor decides and refuses
//	          nothing (a lock writes 0, never a refusal)
//	kind 5    a versionless record is a one-record kind-5 segment whose header names its push, so the sealed write
//	          keeps the record and seals its segment once the sender has drawn the push id, and again under every
//	          push id after it: a retoken's and a rebuild's push re-upload it under the new push, since evs adopts no
//	          kind-5 segment whose header names another (409 VERSIONING, a caller error, never retried)
//	staged    a record whose segment pads to at most 16 KiB rides the push's body, or its part's, with no upload and
//	          no receipt: one kind-2 new-objects item each, in the changes' order, which is the order the parts'
//	          staged bytes join in. The statement builder counts each change's staged bytes against the 1 MiB of a
//	          one-part push and of a part, so a push whose staged bytes pass one part goes in parts
//	          (plan-EVS2-small-readings#13). A retry of a push id sends the same bytes
//	removal   a removal of a directory lists each versionless file below it as a file removal of its own (§11.7's
//	          removal row), from the verified listings a head-mode client holds
//	command   SetVersioning is ur evs versioning on|off: every file its paths and globs name takes a new version with
//	          the setting and its content unchanged, in one push, each held to the version its content was read from
//	409       a racing write to a versionless path gets path-level CAS's 409 like any write. It goes back as an
//	          *EvsPathConflictError that is ErrEvsVersionlessConflict as well, which every caller surfaces and none
//	          answers by writing its content again over the winner's: no history holds what that would replace
//
// On every leg but ios_extension. Safe for concurrent use as the write it serves is.

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

// A write to a versionless path that another write won (§11.7's writers row): the *EvsPathConflictError it rides is
// surfaced, never answered by rebasing, since the loser's content would replace the winner's with no history to
// recover it from.
var ErrEvsVersionlessConflict = errors.New("evs: a versionless path another write replaced; nothing keeps what a rebase would overwrite")

// Sets where a new path's versioning rules come from: EvsConfigVersioningRules over the composition's config state
// and the repo's own opened rules. nil, the default, reads as no rule, so new paths are created versioned.
func (self *EvsClient) SetVersioningRules(rules func(repoId Id, filePath string, size uint64) (uint32, error)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.versioningRules = rules
}

// The versioning of the version write makes over what the plan read of its path: EvsVersioningFor's answer for these
// options (evs_plan.go's evsWriteVersioning).
func (self *EvsWriteOptions) writeVersioning(repo *EvsRepo, plan *EvsWritePlan, write *EvsPathWrite, verified *EvsVerifiedPath) (uint32, error) {
	admitted := repo.client.Format2Admitted()
	if self.Versioning == EvsVersioningOff && !admitted {
		return 0, fmt.Errorf("%w: versioning off is format 2's, outside this network's gate", ErrEvsFormatUnsupported)
	}
	state, err := repo.client.verifier.config()
	if err != nil {
		return 0, err
	}
	rules := func() func(repoId Id, filePath string, size uint64) (uint32, error) {
		repo.client.stateLock.Lock()
		defer repo.client.stateLock.Unlock()
		return repo.client.versioningRules
	}()
	args := &EvsVersioningArgs{
		Options: self, RepoId: repo.repoId, RepoKind: plan.repoKind, RefName: plan.refName, RefMode: plan.RefMode,
		CreatesOnly:     evsEpochExempt(plan.RefKind) || (plan.RefKind == protocol.EvsRefKind_EVS_REF_OWNED && EvsRepoKindRecordClass(plan.repoKind)),
		Path:            write.Path,
		Locked:          state.Repo(repo.repoId).GetLock() == protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED,
		Format2Admitted: admitted,
		Rules:           rules,
	}
	if write.Content != nil {
		args.Size = uint64(write.Content.Size())
	}
	if verified != nil && verified.Entry != nil {
		args.Newest = verified.Entry
	}
	versioning, err := EvsVersioningFor(args)
	if errors.Is(err, ErrEvsVersioningSetting) {
		return 0, fmt.Errorf("%w: %w", ErrEvsWriteInvalid, err)
	}
	return versioning, err
}

// Whether the write is the search index's reserved writer's (evsWriteVersioning).
func (self *EvsWriteOptions) reservedIndex() bool {
	return self != nil && self.Reserved == EvsReservedIndex
}

// A kept link's locator as the new version names it: as it stands, or relabeled to the link's kind, a kind-5 segment
// adopted as kind 1 when versioning turns on (§11.7's on row).
func evsKeptLocator(link *EvsPlannedLink) *protocol.EvsLocator {
	if link.Kind == 0 || protocol.EvsLocatorKind(link.Kept.GetKind()) == link.Kind {
		return link.Kept
	}
	relabeled := proto.Clone(link.Kept).(*protocol.EvsLocator)
	relabeled.Kind = uint32(link.Kind)
	return relabeled
}

// One versionless record of a sealed write: what its kind-5 segment is sealed from under each push id, and the
// segment sealed for the push the write is bound to.
type evsSealedKind5 struct {
	path   *EvsSealedPath
	fileId Id
	record *EvsPlannedRecord
	staged bool
	// a slot-keyed repo's: the path's one key
	chainKey *evsChainKey
	// the locator the path's chain holds, whose id and place each sealing sets
	locator *protocol.EvsLocator
	// the segment as sealed for the bound push: uploaded, or its bytes staged
	segment     *EvsSealedSegment
	stagedBytes []byte
}

// Notes a versionless record of path, under chainKey in a slot-keyed repo, and gives the kind-5 locator its chain
// holds, which bindPush fills.
func (self *EvsSealedWrite) addKind5(path *EvsSealedPath, fileId Id, link *EvsPlannedLink, chainKey *evsChainKey) (*protocol.EvsLocator, error) {
	if self.Plan.slotKeyed != (chainKey != nil) {
		return nil, fmt.Errorf("%w: a versionless record's key is its segment's in a general repo and its path's slot's in a slot-keyed one", ErrEvsWriteInvalid)
	}
	locator := &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Staged: link.Staged}
	self.kind5 = append(self.kind5, &evsSealedKind5{
		path: path, fileId: fileId, record: link.Record, staged: link.Staged, chainKey: chainKey, locator: locator,
	})
	return locator, nil
}

// Whether the push carries a format-2 value: a version that is not versioning 0, or a kind-5 record.
func (self *EvsSealedWrite) format2() bool {
	if 0 < len(self.kind5) {
		return true
	}
	return slices.ContainsFunc(self.Paths, func(path *EvsSealedPath) bool {
		return path.Planned.Versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)
	})
}

// Seals every versionless record's kind-5 segment under pushId, dropping the ones sealed for another push, whose
// headers name it: an unstaged one joins the segments to upload, with no receipt, and a staged one is held as bytes.
// Nothing happens for a write with no versionless record, or one already bound to pushId.
func (self *EvsClient) bindPush(sealed *EvsSealedWrite, pushId Id) error {
	if len(sealed.kind5) == 0 || sealed.kind5PushId == pushId {
		return nil
	}
	manifest, err := NewEvsManifestKey(sealed.RepoKey)
	if err != nil {
		return err
	}
	fek, err := NewEvsFekKey(sealed.RepoKey)
	if err != nil {
		return err
	}
	// the segments sealed for another push go, their spills with them
	sealed.Segments = slices.DeleteFunc(sealed.Segments, func(segment *EvsSealedSegment) bool {
		if segment.versionless && segment.content != nil {
			segment.content.close()
		}
		return segment.versionless
	})
	sealed.kind5PushId = Id{}
	for _, kind5 := range sealed.kind5 {
		kind5.segment, kind5.stagedBytes = nil, nil
		record := kind5.record
		header := &EvsRecordHeader{
			RecordId: record.RecordId, BaseRecordId: record.BaseRecordId, Generation: sealed.RepoKey.Generation(),
			BodyLength: uint64(record.Body.Size()), Kind: record.Kind, KeyRefKind: protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER,
			OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
		}
		copy(header.Oid[:], record.Oid[:])
		var out io.Writer
		var spill *evsSpill
		stagedOut := &bytes.Buffer{}
		if kind5.staged {
			out = stagedOut
		} else {
			spill = newEvsSpill(self.args.Store, self.settings.DeltaBaseMemoryByteCount)
			out = spill
		}
		summary, err := func() (*EvsSegmentSummary, error) {
			var builder *EvsSegmentBuilder
			var writer io.WriteCloser
			var err error
			if kind5.chainKey != nil {
				if builder, err = NewEvsSlotKeyedKind5SegmentBuilder(out, manifest, pushId); err != nil {
					return nil, err
				}
				header.KeyRefKind = protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT
				header.SlotId, header.KeyIndex, header.Generation = kind5.chainKey.slotId, kind5.chainKey.keyIndex, kind5.chainKey.generation
				writer, err = builder.BeginSlotRecord(manifest, kind5.chainKey.objectKey, kind5.fileId, header)
			} else {
				if builder, err = NewEvsKind5SegmentBuilder(out, manifest, fek, pushId); err != nil {
					return nil, err
				}
				writer, err = builder.BeginRecord(kind5.fileId, header)
			}
			if err != nil {
				return nil, err
			}
			if _, err := io.Copy(writer, io.NewSectionReader(record.Body, 0, record.Body.Size())); err != nil {
				return nil, err
			}
			if err := writer.Close(); err != nil {
				return nil, err
			}
			return builder.Finish()
		}()
		if err != nil {
			if spill != nil {
				spill.close()
			}
			return err
		}
		kind5.locator.Id = summary.Id[:]
		kind5.locator.Offset = summary.Places[0].Offset
		kind5.locator.Length = summary.Places[0].Length
		if kind5.staged {
			if EvsStagedSegmentMaxByteCount < summary.PaddedSize || uint64(stagedOut.Len()) != summary.PaddedSize {
				return fmt.Errorf("%w: a staged segment of %d bytes", ErrEvsWriteInvalid, summary.PaddedSize)
			}
			kind5.stagedBytes = stagedOut.Bytes()
			continue
		}
		kind5.segment = &EvsSealedSegment{Id: summary.Id, PaddedSize: summary.PaddedSize, content: spill, versionless: true}
		sealed.Segments = append(sealed.Segments, kind5.segment)
	}
	sealed.kind5PushId = pushId
	return nil
}

// The staged segments of the bound push by their ids, and each sealed path's, in its chain's order.
func (self *EvsSealedWrite) stagedOf() (map[string][]byte, map[*EvsSealedPath][][]byte) {
	idStaged := map[string][]byte{}
	pathStaged := map[*EvsSealedPath][][]byte{}
	for _, kind5 := range self.kind5 {
		if kind5.staged {
			idStaged[string(kind5.locator.GetId())] = kind5.stagedBytes
			pathStaged[kind5.path] = append(pathStaged[kind5.path], kind5.stagedBytes)
		}
	}
	return idStaged, pathStaged
}

// What segments take of a push's or a part's staged bytes: each one's length and bytes.
func evsStagedByteCount(segments [][]byte) int {
	byteCount := 0
	for _, segment := range segments {
		byteCount += 4 + len(segment)
	}
	return byteCount
}

// The staged ids an entry version's chain names, in chain order.
func evsEntryStagedIds(entryBytes []byte) []string {
	if entryBytes == nil {
		return nil
	}
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		return nil
	}
	stagedIds := []string{}
	for _, locator := range entry.GetChain() {
		if locator.GetStaged() {
			stagedIds = append(stagedIds, string(locator.GetId()))
		}
	}
	return stagedIds
}

// The staged segments changes name, in the changes' order and each chain's.
func evsChangesStaged(changes []*EvsCheckedChange, idStaged map[string][]byte) ([][]byte, error) {
	segments := [][]byte{}
	for _, change := range changes {
		for _, stagedId := range evsEntryStagedIds(change.EntryVersion) {
			segment, ok := idStaged[stagedId]
			if !ok {
				return nil, fmt.Errorf("%w: a staged locator naming no segment the write sealed", ErrEvsWriteInvalid)
			}
			segments = append(segments, segment)
		}
	}
	return segments, nil
}

// evs's 409 PATH_CONFLICT to a push of plan as conflict, which is ErrEvsVersionlessConflict as well when a written
// path it names is versionless, by the version the push wrote or the one it was held to.
func evsVersionlessConflict(conflict *EvsPathConflictError, plan *EvsWritePlan) {
	for _, planned := range plan.Paths {
		if planned.Kind != protocol.EvsEntryKind_EVS_ENTRY_FILE || !slices.Contains(conflict.Paths, planned.Path) {
			continue
		}
		if planned.Versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) || planned.baseVersionless {
			conflict.causes = append(conflict.causes, ErrEvsVersionlessConflict)
			return
		}
	}
}

// The tree a removal walks on a head-mode client: each directory's verified listing with its files' settings.
type evsRemoveListings struct {
	repo    *EvsRepo
	refName []byte
}

// A directory's children as the newest verified head lists them, the index files' root among them.
func (self *evsRemoveListings) Children(ctx context.Context, directory string) ([]*EvsPlanRemoveChild, error) {
	listing, err := self.repo.List(ctx, &EvsReadArgs{RefName: self.refName, Path: directory, Fresh: true, Settings: true, IndexFiles: true})
	if err != nil {
		return nil, err
	}
	children := []*EvsPlanRemoveChild{}
	for _, entry := range listing.Entries {
		path := string(entry.Name)
		if directory != "" {
			path = directory + "/" + path
		}
		children = append(children, &EvsPlanRemoveChild{
			Path: path, Directory: entry.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY, Versioning: entry.Versioning,
		})
	}
	return children, nil
}

// writes with what §11.7's removal row adds: for each removal of a path that stands as a directory, a file removal of
// every versionless file below it, the paths the push writes again excepted, so the commit names every version it
// replaces. Outside the format2 gate no version is versionless and writes go back as they are.
func (self *EvsRepo) withRemovalLists(ctx context.Context, refName []byte, writes []*EvsPathWrite) ([]*EvsPathWrite, error) {
	if !self.client.Format2Admitted() || !slices.ContainsFunc(writes, func(write *EvsPathWrite) bool { return write.Remove }) {
		return writes, nil
	}
	written := map[string]bool{}
	for _, write := range writes {
		written[write.Path] = true
	}
	tree := &evsRemoveListings{repo: self, refName: refName}
	listed := slices.Clone(writes)
	for _, write := range writes {
		if !write.Remove {
			continue
		}
		removals, err := EvsPlanRemove(ctx, tree, write.Path, written)
		switch {
		case errors.Is(err, ErrEvsPathAbsent), errors.Is(err, ErrEvsTokenInvalid):
			// a file, or nothing: the plan's own read answers it
			continue
		case err != nil:
			return nil, err
		}
		for _, removal := range removals {
			written[removal.Path] = true
			listed = append(listed, removal)
		}
	}
	return listed, nil
}

// What SetVersioning changes: the setting, and the files it reaches.
type EvsSetVersioningArgs struct {
	// The ref's name bytes: nil is main.
	RefName []byte
	// Each a file's path, a directory's, which names every file below it, or a glob: '/'-separated segments matched
	// one by one, `**` matching any number of them, as a versioning rule's path_glob does.
	Patterns []string
	// EvsVersioningOn or EvsVersioningOff.
	Versioning string
}

// What a SetVersioning did.
type EvsSetVersioningResult struct {
	// The push that wrote the new versions and the ref version it committed at; zero when no file needed one.
	PushId  Id
	Version uint64
	// The files given a new version with the setting, and the ones that matched and already had it, each sorted.
	Changed   []string
	Unchanged []string
}

// A pattern that matched no file.
var ErrEvsVersioningNoMatch = errors.New("evs: a path or glob that names no file")

// ur evs versioning on|off (§11.7's cli and choose rows): gives every file the patterns name a new version with the
// setting and its content unchanged, all in one push, by the transitions of evs_plan_transition.go, so off uploads
// nothing where the newest version's records can be cited and on starts history there. Each write is held to the
// version this read its content from, so a file another write replaced meanwhile fails the push with its 409 rather
// than taking older content. A file already at the setting is left as it is; the index's own files are never named.
func (self *EvsRepo) SetVersioning(ctx context.Context, args *EvsSetVersioningArgs) (*EvsSetVersioningResult, error) {
	want := uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)
	switch args.Versioning {
	case EvsVersioningOn:
	case EvsVersioningOff:
		want = uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
		if !self.client.Format2Admitted() {
			return nil, fmt.Errorf("%w: versioning off is format 2's, outside this network's gate", ErrEvsFormatUnsupported)
		}
	default:
		return nil, fmt.Errorf("%w: %q", ErrEvsVersioningSetting, args.Versioning)
	}
	if len(args.Patterns) == 0 {
		return nil, fmt.Errorf("%w: no path", ErrEvsWriteInvalid)
	}
	// every file of the ref with its setting, from verified listings, the index files' root left out
	fileVersioning := map[string]uint32{}
	directories := map[string]bool{"": true}
	level := []string{""}
	for depth := 0; 0 < len(level); depth += 1 {
		if EvsTokenPathMaxLength < depth {
			return nil, fmt.Errorf("%w: %d levels", ErrEvsPlanRemoveDepth, depth)
		}
		next := []string{}
		for _, directory := range level {
			listing, err := self.List(ctx, &EvsReadArgs{RefName: args.RefName, Path: directory, Fresh: depth == 0, Settings: true})
			if err != nil {
				return nil, err
			}
			for _, entry := range listing.Entries {
				path := string(entry.Name)
				if directory != "" {
					path = directory + "/" + path
				}
				if entry.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
					directories[path] = true
					next = append(next, path)
				} else {
					fileVersioning[path] = entry.Versioning
				}
			}
		}
		level = next
	}
	matched := map[string]bool{}
	for _, pattern := range args.Patterns {
		trimmed := strings.Trim(pattern, "/")
		count := 0
		for path := range fileVersioning {
			ok := path == trimmed || (directories[trimmed] && (trimmed == "" || strings.HasPrefix(path, trimmed+"/")))
			if !ok {
				var err error
				if ok, err = configGlobMatch(pattern, path); err != nil {
					return nil, fmt.Errorf("%w: glob %q", ErrEvsWriteInvalid, pattern)
				}
			}
			if ok {
				matched[path] = true
				count += 1
			}
		}
		if count == 0 {
			return nil, fmt.Errorf("%w: %q", ErrEvsVersioningNoMatch, pattern)
		}
	}
	result := &EvsSetVersioningResult{}
	writes := []*EvsPathWrite{}
	spills := []*evsSpill{}
	defer func() {
		for _, spill := range spills {
			spill.close()
		}
	}()
	paths := make([]string, 0, len(matched))
	for path := range matched {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		switch fileVersioning[path] {
		case want:
			result.Unchanged = append(result.Unchanged, path)
			continue
		case uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX):
			// an index file under another name's root: only §11.14's mechanisms write it
			return nil, fmt.Errorf("%w: an index file", ErrEvsReservedPath)
		}
		spill := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
		spills = append(spills, spill)
		info, err := self.ReadHead(ctx, &EvsReadArgs{RefName: args.RefName, Path: path}, spill)
		if err != nil {
			return nil, err
		}
		version := info.Version
		writes = append(writes, &EvsPathWrite{
			Path: path, Content: spill, IfVersion: &version, Options: &EvsWriteOptions{Versioning: args.Versioning},
		})
		result.Changed = append(result.Changed, path)
	}
	if len(writes) == 0 {
		return result, nil
	}
	written, err := self.WritePaths(ctx, &EvsWritePathsArgs{RefName: args.RefName, Writes: writes})
	if err != nil {
		return nil, err
	}
	result.PushId, result.Version = written.PushId, written.Version
	return result, nil
}

// A versioning value as ur evs ls -l and §18.5 spell it.
func EvsVersioningName(versioning uint32) string {
	switch protocol.EvsVersioning(versioning) {
	case protocol.EvsVersioning_EVS_VERSIONING_KEPT:
		return EvsVersioningOn
	case protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS:
		return EvsVersioningOff
	case protocol.EvsVersioning_EVS_VERSIONING_INDEX:
		return "index"
	}
	return fmt.Sprintf("versioning %d", versioning)
}
