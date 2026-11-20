//go:build !ios_extension

// indexRefStore over EvsRepo (§11.14's head and commit rows; §11.9; SEARCH-M10-13): what every index builder reads and
// writes of one ref through the verifying reader and the push sender, so merges, roll-ups, backfills, companion pushes
// and the CUT run on the real path as they run on the fake.
//
//	Head     the ref's verified head: its version, chain and index_epoch, and its push's signed time where the
//	         read's walk holds that statement (0 where it does not, which nothing in the index reads)
//	List     the index's directories walked at the head, one verified read a directory, then every file's entry
//	         version a ReadMaxPathCount at a time: its version, its push's commit version, signer and signed time,
//	         and its plaintext's length and content_sha256 from its sealed fields. The settings, the one versioned
//	         file, carry no content_sha256, so its content is read and hashed, which is what Read holds it to.
//	         EvsRepo reads a directory or a file at the ref's head, or at a version of the path itself, never at an
//	         older ref version, so a listing asked at a ref version is the head's, and where the head is no longer
//	         that version, or moves while the walk reads, the index moved under its reader: errIndexCollected, on
//	         which a builder reruns from its read, and errEvsIndexMoved, on which a hooked push is planned again,
//	         never a state other than the one asked for under its name
//	History  a path's versions at the head, newest first, those a push after the ref version asked for wrote left
//	         out, each read and hashed the same way
//	Read     one version's plaintext, reconstructed and verified by evs's reader, then held to its content_sha256
//	         where the version carries one; a replaced versionless version answers errIndexCollected. A version the
//	         eraser's Retained names from History carries none, and is held to what evs's reader held it to, its
//	         entry's own sealed size, git oid and content_sha256 (QD-1110), so a writer's head file at its second
//	         version reads its first
//	Commit   one push of index files and removals through EvsRepo's sender, each write the index's reserved
//	         writer's (versioning 2, staged under 16 KiB; the settings versioning 0) held to the version its builder
//	         read (IfVersion, so 5g's path CAS spans the build to the commit), naming the push's index_epoch, its
//	         signed time the builder's own, a CUT flagged; refusals come back as *indexRefusal
//
// A CLOSURE goes through the eraser's seam at the end of this file (indexEraseStore's Closure, over EvsRepo.Closure,
// which seals its erasure note), so Commit refuses one. Paths stay on the device (I-13). Safe for concurrent use as
// EvsRepo is.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// The index of one ref on EvsRepo: a file-mode ref's .ur-index/, or ur/index.
type indexEvsStore struct {
	repo *EvsRepo
	// The content ref's name, or ur/index.
	refName   []byte
	companion bool
}

// The store of a file-mode ref's own index (refName nil is main), or of the repo's ur/index (companion).
func newIndexEvsStore(repo *EvsRepo, refName []byte, companion bool) *indexEvsStore {
	if companion {
		refName = evsIndexRefName
	} else if refName == nil {
		refName = EvsMainRefName
	}
	return &indexEvsStore{repo: repo, refName: refName, companion: companion}
}

// The directory the index's files sit under: .ur-index on a file-mode ref, the root of ur/index.
func (self *indexEvsStore) rootDirectory() string {
	if self.companion {
		return ""
	}
	return strings.TrimSuffix(indexFileModePrefix, "/")
}

// The ref's id, from its name.
func (self *indexEvsStore) refId(ctx context.Context) (Id, error) {
	return self.repo.RefIdOf(ctx, self.refName)
}

// The head a read verified, as the index reads it.
func indexHeadOfEvs(head *EvsVerifiedHead) *indexRefHead {
	indexHead := &indexRefHead{version: head.Version, chain: head.Chain, indexEpoch: head.Head.GetIndexEpoch()}
	if statement, ok := head.StatementAt(head.Version); ok && statement.Statement != nil {
		indexHead.signedTimeMs = statement.Statement.Push.GetTimeMs()
	}
	return indexHead
}

// See indexRefStore.
func (self *indexEvsStore) Head(ctx context.Context) (*indexRefHead, error) {
	refId, err := self.refId(ctx)
	if err != nil {
		return nil, err
	}
	result, err := self.repo.read(ctx, refId, []string{""}, 0, true)
	if err != nil {
		return nil, err
	}
	defer result.objects.close()
	return indexHeadOfEvs(result.head), nil
}

// The index moved under a read asked at a ref version that is no longer the head (see the file header).
func indexEvsMoved(refVersion uint64, headVersion uint64) error {
	return fmt.Errorf("%w: %w: read at %d, the head at %d", errIndexCollected, errEvsIndexMoved, refVersion, headVersion)
}

// See indexRefStore, and the file header's List row.
func (self *indexEvsStore) List(ctx context.Context, refVersion uint64) (*indexListing, error) {
	refId, err := self.refId(ctx)
	if err != nil {
		return nil, err
	}
	// the head every read of the walk must show, the one asked for where one was
	walkVersion := refVersion
	held := func(headVersion uint64) error {
		if walkVersion == 0 {
			walkVersion = headVersion
		}
		if headVersion != walkVersion {
			return indexEvsMoved(walkVersion, headVersion)
		}
		return nil
	}
	directories := []string{self.rootDirectory()}
	filePaths := []string{}
	for 0 < len(directories) {
		directory := directories[0]
		directories = directories[1:]
		listing, err := self.repo.List(ctx, &EvsReadArgs{RefId: &refId, Path: directory, IndexFiles: true})
		if errors.Is(err, ErrEvsPathAbsent) && directory == self.rootDirectory() {
			// no index on the ref yet
			break
		}
		if err != nil {
			return nil, err
		}
		if err := held(listing.HeadVersion); err != nil {
			return nil, err
		}
		for _, entry := range listing.Entries {
			child := string(entry.Name)
			if directory != "" {
				child = directory + "/" + child
			}
			switch entry.Kind {
			case protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY:
				directories = append(directories, child)
			default:
				filePaths = append(filePaths, child)
			}
		}
	}
	indexListing := &indexListing{}
	batchCount := DefaultEvsFormatSettings().ReadMaxPathCount
	for start := 0; start < len(filePaths) || indexListing.head == nil; start += batchCount {
		batch := filePaths[start:min(len(filePaths), start+batchCount)]
		if len(batch) == 0 {
			// the head alone, for an index with no file
			batch = []string{self.rootDirectory()}
		}
		files, head, err := self.fileVersions(ctx, refId, batch)
		if err != nil {
			return nil, err
		}
		if err := held(head.version); err != nil {
			return nil, err
		}
		if indexListing.head == nil {
			indexListing.head = head
		}
		indexListing.files = append(indexListing.files, files...)
		if len(filePaths) <= start+batchCount {
			break
		}
	}
	return indexListing, nil
}

// The entry versions of paths at the head, each with its sealed fields' length and content_sha256, and the head the
// read verified. A path that does not stand, a directory among them, is left out.
func (self *indexEvsStore) fileVersions(ctx context.Context, refId Id, paths []string) ([]*indexFileVersion, *indexRefHead, error) {
	result, err := self.repo.read(ctx, refId, paths, 0, false)
	if err != nil {
		return nil, nil, err
	}
	defer result.objects.close()
	if err := self.repo.client.preDecrypt(ctx, self.repo.repoId, refId, nil); err != nil {
		return nil, nil, err
	}
	files := []*indexFileVersion{}
	for index, verified := range result.replies {
		if verified.Entry == nil || verified.Removal != nil || verified.Absent ||
			verified.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
			continue
		}
		file, err := self.fileVersion(ctx, result, paths[index], verified)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, file)
	}
	return files, indexHeadOfEvs(result.head), nil
}

// One verified entry version as the index reads it.
func (self *indexEvsStore) fileVersion(ctx context.Context, result *evsReadResult, path string, verified *EvsVerifiedPath) (*indexFileVersion, error) {
	entry := verified.Entry
	push := verified.Statement.Push
	manifest, err := result.keys.manifest(ctx, push.GetGeneration())
	if err != nil {
		return nil, err
	}
	var fields *protocol.EvsSealedFields
	if entry.GetVersioning() == 0 {
		fields, err = EvsOpenFields(manifest, entry.GetSealedFields())
	} else {
		fields, err = EvsOpenFieldsFormat2(manifest, entry.GetSealedFields(), entry.GetVersioning())
	}
	if err != nil {
		return nil, err
	}
	signer, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: a statement's signer", ErrEvsSealInvalid)
	}
	file := &indexFileVersion{
		path: path, version: entry.GetVersion(), commitVersion: verified.CommitVersion, byteCount: int(fields.GetSize()),
		signerSidecarId: signer, signedTimeMs: push.GetTimeMs(),
	}
	if len(fields.GetContentSha256()) == sha256.Size {
		copy(file.contentSha256[:], fields.GetContentSha256())
		return file, nil
	}
	// a versioned file, the settings: its content, verified by evs's reader, is what its hash is of
	plaintext, err := self.readVerified(ctx, result.refId, path, file.version)
	if err != nil {
		return nil, err
	}
	file.contentSha256 = sha256.Sum256(plaintext)
	return file, nil
}

// One version's plaintext as evs's reader reconstructs and verifies it; errIndexCollected wrapped for a replaced
// versionless version.
func (self *indexEvsStore) readVerified(ctx context.Context, refId Id, path string, version uint64) ([]byte, error) {
	buffer := &bytes.Buffer{}
	if _, err := self.repo.ReadVersion(ctx, &EvsReadArgs{RefId: &refId, Path: path, Version: version}, buffer); err != nil {
		if errors.Is(err, ErrEvsCollected) {
			return nil, fmt.Errorf("%w: %w", errIndexCollected, err)
		}
		return nil, err
	}
	return buffer.Bytes(), nil
}

// See indexRefStore, and the file header's History row.
func (self *indexEvsStore) History(ctx context.Context, path string, refVersion uint64) ([]*indexFileVersion, error) {
	refId, err := self.refId(ctx)
	if err != nil {
		return nil, err
	}
	history, err := self.repo.History(ctx, &EvsReadArgs{RefId: &refId, Path: path})
	if err != nil {
		return nil, err
	}
	files := []*indexFileVersion{}
	for _, version := range history.Versions {
		if version.Removed || version.State != "" && version.State != "kept" {
			continue
		}
		if 0 < refVersion && refVersion < version.CommitVersion {
			// written after the version asked for
			continue
		}
		plaintext, err := self.readVerified(ctx, refId, path, version.Version)
		if errors.Is(err, errIndexCollected) {
			continue
		}
		if err != nil {
			return nil, err
		}
		files = append(files, &indexFileVersion{
			path: path, version: version.Version, commitVersion: version.CommitVersion, contentSha256: sha256.Sum256(plaintext),
			byteCount: len(plaintext), signerSidecarId: version.SignerSidecarId, signedTimeMs: version.Time.UnixMilli(),
		})
	}
	return files, nil
}

// See indexRefStore. A version Retained named carries no hash: its history gives none, and evs's reader has held the
// bytes to the entry's own sealed fields.
func (self *indexEvsStore) Read(ctx context.Context, file *indexFileVersion) ([]byte, error) {
	refId, err := self.refId(ctx)
	if err != nil {
		return nil, err
	}
	plaintext, err := self.readVerified(ctx, refId, file.path, file.version)
	if err != nil {
		return nil, err
	}
	if file.contentSha256 != ([sha256.Size]byte{}) && sha256.Sum256(plaintext) != file.contentSha256 {
		return nil, fmt.Errorf("%w: plaintext hash mismatch", ErrEvsSealInvalid)
	}
	return plaintext, nil
}

// See indexRefStore.
func (self *indexEvsStore) Commit(ctx context.Context, push *indexPush) (*indexCommitted, error) {
	extras := &evsPushExtras{indexEpoch: push.indexEpoch, signedTimeMs: push.signedTimeMs}
	switch push.kind {
	case indexPushCut:
		// evs takes a CUT only from an admin, refusing one below it 403 before any write (§11.12's cut and directory
		// rows), so it goes under the admin scope, as a CLOSURE does (EvsRepo.Closure)
		extras.flags, extras.scope = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT), evsScopeAdmin
	case indexPushClosure:
		return nil, fmt.Errorf("%w: a CLOSURE goes through the eraser", ErrEvsWriteInvalid)
	}
	writes := []*EvsPathWrite{}
	for _, file := range push.files {
		replaces := file.replaces
		options := &EvsWriteOptions{Reserved: EvsReservedIndex}
		if parsed, ok := indexParsePath(file.path, self.companion); ok && parsed.kind == indexPathSettings {
			// the settings keep every version, since only a repo admin's counts (§11.14's settings row)
			options.Versioning = EvsVersioningOn
		}
		writes = append(writes, &EvsPathWrite{Path: file.path, Content: bytes.NewReader(file.plaintext), IfVersion: &replaces, Options: options})
	}
	for _, removal := range push.removals {
		version := removal.version
		writes = append(writes, &EvsPathWrite{Path: removal.path, Remove: true, IfVersion: &version, Options: &EvsWriteOptions{Reserved: EvsReservedIndex}})
	}
	if len(writes) == 0 {
		return nil, fmt.Errorf("%w: an index push of nothing", ErrEvsWriteInvalid)
	}
	result, err := self.repo.writePaths(ctx, &EvsWritePathsArgs{RefName: self.refName, Writes: writes}, extras)
	if err != nil {
		return nil, indexRefusalOfEvs(err)
	}
	signer := self.repo.client.args.Identity().SidecarId
	committed := &indexCommitted{version: result.Version}
	for index, file := range push.files {
		committed.files = append(committed.files, &indexFileVersion{
			path: file.path, version: result.PathVersions[index], commitVersion: result.Version,
			contentSha256: sha256.Sum256(file.plaintext), byteCount: len(file.plaintext), signerSidecarId: signer,
			signedTimeMs: push.signedTimeMs,
		})
	}
	return committed, nil
}

// The eraser's seam over EvsRepo (indexEraseStore; SEARCH-M10-17): a CLOSURE through EvsRepo.Closure, each file the
// index's reserved writer's, held to the version its eraser read and padded already to that version's length; an
// ERASE through EvsRepo.Erase; the keys through SlotKeysOf, which fails closed past a path's walked history; the
// erasure's progress from the ref's CLOSUREs and the erasure ref's ERASEs, by their notes. Retained walks each live
// index path's history for the versions it keeps beside its newest, but names no removed path, since EvsRepo walks no
// ref's removed paths by name yet: it answers incomplete, so no erasure on the real store says complete until it does.
// A version whose every slot a committed ERASE named opens under no key, its staged bytes with it, and evs still lists
// it kept and refuses its read for the key: Retained leaves it out, nothing being left there to hold, so the walk of
// an erasure resumed after another's ERASE goes on (QD-1110; question mail-m10-04-index-eraser-history-reads).
var _ indexEraseStore = (*indexEvsStore)(nil)

// A refusal of an eraser's push as the index reads it, with the allowance a 429 or a quota names.
func indexEraseRefusalOfEvs(err error) error {
	refusal := indexRefusalOfEvs(err)
	typed, ok := refusal.(*indexRefusal)
	if !ok || typed.kind != indexRefusalRetry && typed.kind != indexRefusalQuota {
		return refusal
	}
	if evsError, ok := EvsErrorOf(err); ok && evsError.Quota != nil {
		typed.quota = &QuotaRefusal{
			LimitKey: evsError.Quota.GetLimitKey(), Limit: evsError.Quota.GetLimit(), Used: evsError.Quota.GetUsed(),
			RetryAfterMs: evsError.Quota.GetRetryAfterMs(), Upgrade: evsError.Quota.GetUpgrade(),
		}
	}
	return typed
}

// See indexEraseStore.
func (self *indexEvsStore) Closure(ctx context.Context, closure *indexClosurePush) (*indexCommitted, error) {
	writes := make([]*EvsPathWrite, 0, len(closure.files))
	for _, file := range closure.files {
		replaces := file.replaces
		writes = append(writes, &EvsPathWrite{
			Path: file.path, Content: bytes.NewReader(file.plaintext), IfVersion: &replaces,
			Options: &EvsWriteOptions{Reserved: EvsReservedIndex},
		})
	}
	result, err := self.repo.Closure(ctx, &EvsClosureArgs{
		ErasureId: closure.erasureId, RefName: self.refName, Writes: writes, Erased: closure.erased,
	})
	if err != nil {
		return nil, indexEraseRefusalOfEvs(err)
	}
	signer := self.repo.client.args.Identity().SidecarId
	committed := &indexCommitted{version: result.Version}
	for index, file := range closure.files {
		committed.files = append(committed.files, &indexFileVersion{
			path: file.path, version: result.PathVersions[index], commitVersion: result.Version,
			contentSha256: sha256.Sum256(file.plaintext), byteCount: len(file.plaintext), signerSidecarId: signer,
			signedTimeMs: closure.signedTimeMs,
		})
	}
	return committed, nil
}

// See indexEraseStore.
func (self *indexEvsStore) Erase(ctx context.Context, erase *indexErasePush) error {
	_, err := self.repo.Erase(ctx, &EvsEraseArgs{ErasureId: erase.erasureId, Keys: erase.keys, Complete: erase.complete, Note: erase.note})
	if err != nil {
		return indexEraseRefusalOfEvs(err)
	}
	return nil
}

// See indexEraseStore.
func (self *indexEvsStore) KeysOf(ctx context.Context, paths []string) ([]*EvsErasedKey, error) {
	return self.repo.SlotKeysOf(ctx, self.refName, paths)
}

// See indexEraseStore, and the seam's comment above: incomplete, every live path's kept versions beside its newest.
func (self *indexEvsStore) Retained(ctx context.Context) (*indexRetained, error) {
	listing, err := self.List(ctx, 0)
	if err != nil {
		return nil, err
	}
	refId, err := self.refId(ctx)
	if err != nil {
		return nil, err
	}
	retained := &indexRetained{}
	// the slots a committed ERASE names a key of, read once a path shows a version beside its newest: a version whose
	// every slot is among them opens under no key, its staged bytes with it, so it is none the ref still stores
	var erasedSlots map[Id]bool
	keyErased := func(version *EvsHistoryVersion) (bool, error) {
		if len(version.SlotIds) == 0 {
			return false, nil
		}
		if erasedSlots == nil {
			erasures, err := self.repo.ReadErasures(ctx, 0)
			if err != nil {
				return false, err
			}
			erasedSlots = map[Id]bool{}
			for _, erasure := range erasures {
				for _, key := range erasure.Keys {
					if key.KeyIndex == evsChainSlotKeyIndex {
						erasedSlots[key.SlotId] = true
					}
				}
			}
		}
		for _, slotId := range version.SlotIds {
			if !erasedSlots[slotId] {
				return false, nil
			}
		}
		return true, nil
	}
	for _, file := range listing.files {
		parsed, ok := indexParsePath(file.path, self.companion)
		if !ok || !indexPathHoldsDocuments(parsed.kind) {
			continue
		}
		history, err := self.repo.History(ctx, &EvsReadArgs{RefId: &refId, Path: file.path})
		if err != nil {
			return nil, err
		}
		// newest first: each version past the live one, replaced by the version before it in the list
		for index := 1; index < len(history.Versions); index += 1 {
			version, replacer := history.Versions[index], history.Versions[index-1]
			if version.Removed {
				continue
			}
			if erased, err := keyErased(version); err != nil {
				return nil, err
			} else if erased {
				continue
			}
			retained.versions = append(retained.versions, &indexRetainedVersion{
				file: &indexFileVersion{
					path: file.path, version: version.Version, commitVersion: version.CommitVersion,
					signerSidecarId: version.SignerSidecarId, signedTimeMs: version.Time.UnixMilli(),
				},
				readable:        version.State == "kept",
				replacedVersion: replacer.CommitVersion,
				replacedMs:      replacer.Time.UnixMilli(),
			})
		}
	}
	// a removed index path's versions are not named here: no erasure through this store is proven complete
	retained.complete = false
	return retained, nil
}

// See indexEraseStore.
func (self *indexEvsStore) Progress(ctx context.Context, erasureId Id) (*indexEraseProgress, error) {
	closures, err := self.repo.ReadClosures(ctx, self.refName, 0)
	if err != nil {
		return nil, err
	}
	erasures, err := self.repo.ReadErasures(ctx, 0)
	if err != nil {
		return nil, err
	}
	progress := &indexEraseProgress{}
	for _, closure := range closures {
		if closure.ErasureId == erasureId {
			progress.closures = append(progress.closures, &indexEraseClosed{version: closure.Version, keys: closure.Keys})
		}
	}
	for _, erasure := range erasures {
		if erasure.ErasureId == erasureId {
			progress.erases = append(progress.erases, &indexEraseErased{keys: erasure.Keys, complete: erasure.Complete, timeMs: erasure.Time.UnixMilli()})
		}
	}
	return progress, nil
}
