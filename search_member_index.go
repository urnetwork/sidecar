//go:build !ios_extension

// Index synchronization reads verified EVS heads and keeps the actual encrypted checkpoints and slot bindings.
package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// One content ref's verified index. No method runs on a keystroke.
type memberIndexSource struct {
	member     *memberSearchSource
	store      *indexEvsStore
	kind       protocol.RepoKind
	contentRef Id
}

// A changed head is re-listed through EVS's verifying reader. A matching pin needs neither a listing nor content.
func (self *memberIndexSource) Replay(ctx context.Context, pin SearchSyncPin) (*searchSyncReplay, error) {
	if !self.readable() {
		return nil, ErrAclShareReadRefused
	}
	if self.kind == protocol.RepoKind_REPO_KIND_DIRECTORY {
		if err := self.member.record.Reader().Sync(ctx, self.store.repo.repoId); err != nil {
			return nil, err
		}
	}
	id, err := self.store.refId(ctx)
	if err != nil {
		return nil, err
	}
	verified, err := self.store.repo.readHeadAlone(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if verified.Head.GetRefMode() != protocol.EvsRefMode_EVS_REF_FILE || (verified.Head.GetRefKind() != protocol.EvsRefKind_EVS_REF_SHARED && verified.Head.GetRefKind() != protocol.EvsRefKind_EVS_REF_OWNED) {
		return nil, ErrSearchSyncUnfollowed
	}
	head := indexHeadOfEvs(verified)
	switch {
	case head.version < pin.Version:
		return nil, ErrEvsPinLower
	case head.version == pin.Version && head.version != 0 && head.chain != pin.Chain:
		return nil, ErrEvsPinFork
	}
	return &searchSyncReplay{head: head, catchUp: pin.Version == 0 || pin.Version != head.version}, nil
}

// No retained file survives the withdrawal of its governing grant, or a new prefix policy the index cannot verify.
func (self *memberIndexSource) readable() bool {
	state := self.member.state()
	if state == nil {
		return false
	}
	acl, err := state.Acl()
	if err != nil {
		return false
	}
	id := self.store.repo.repoId
	row := acl.Repo(id)
	if row == nil || len(row.GetPrefixRules()) != 0 || row.Kind != self.kind || indexRepoExcluded(row.Kind) {
		return false
	}
	rights := acl.EvsAccess(AclSidecarSubject(self.member.record.writer.sidecarId), id, AclTokenAudienceEvs, self.member.host.running.clock.Now()).Rights
	return rights.Has(AclEvsRead) && (!aclRepoKindOwnerBound(row.Kind) || rights.Has(AclEvsWrite))
}

// An in-ref head written by its own signer in the content commit proves that commit indexed. A held, validated
// horizon covers preceding commits. Only a contiguous prefix counts. Missing or collected evidence leaves a gap.
func (self *memberIndexSource) inRefCoverage(manifest *SearchManifest, rows []*SearchManifestCoverage) uint64 {
	var through uint64
	for _, row := range rows {
		if row.Horizon {
			through = max(through, min(row.Version, manifest.Pin.Version))
		}
	}
	commits := map[uint64]bool{}
	listedByPath := make(map[string]*SearchSyncWanted, len(manifest.Listing))
	for _, listed := range manifest.Listing {
		listedByPath[listed.Path] = listed
	}
	for _, file := range manifest.Files {
		if file.State != SearchManifestHeld {
			continue
		}
		path, ok := indexParsePath(file.Path, false)
		if !ok || path.kind != indexPathSlot || Id(path.writerSidecarId) != file.Signer {
			continue
		}
		listed := listedByPath[file.Path]
		if listed != nil && listed.Version == file.Version && listed.Signer == file.Signer {
			commits[listed.CommitVersion] = true
		}
	}
	for through < manifest.Pin.Version && commits[through+1] {
		through++
	}
	return through
}

// The newest supported admin-signed settings version governs, even if an ordinary writer replaced that file.
func (self *memberIndexSource) List(ctx context.Context) (*indexListing, error) {
	if !self.readable() {
		return nil, ErrAclShareReadRefused
	}
	listing, err := self.store.List(ctx, 0)
	if err != nil {
		return nil, err
	}
	judge, err := self.store.repo.indexAdmins()
	if err != nil {
		return nil, err
	}
	files := make([]*indexFileVersion, 0, len(listing.files))
	for _, f := range listing.files {
		path, ok := indexParsePath(f.path, self.store.companion)
		if !ok || path.kind != indexPathSettings {
			files = append(files, f)
			continue
		}
		view := &indexView{store: self.store, repoKind: self.kind, companion: self.store.companion, settings: self.member.syncer.args.format}
		root := &indexViewRoot{number: path.rootNumber, paths: indexNewPaths(self.store.companion, path.rootNumber)}
		if err := view.loadSettings(ctx, root, listing.head.version, judge); err != nil {
			return nil, err
		}
		for _, alarm := range view.alarms {
			self.member.host.running.raiseIndexMalformed(self.store.repo.repoId, self.contentRef, alarm.path, alarm.signerSidecarId)
		}
		if root.settingsFile != nil {
			files = append(files, root.settingsFile)
		}
	}
	listing.files = files
	return listing, nil
}

// Each file is checked at its named version, never accepted merely because the server retained its locator.
func (self *memberIndexSource) Fetch(ctx context.Context, files []*indexFileVersion) ([]*searchSyncFetched, error) {
	if !self.readable() {
		return nil, ErrAclShareReadRefused
	}
	repo := self.store.repo
	ref, err := self.store.refId(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*searchSyncFetched, 0, len(files))
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !self.readable() {
			return nil, ErrAclShareReadRefused
		}
		found := &searchSyncFetched{file: file}
		path, ok := indexParsePath(file.path, self.store.companion)
		if !ok {
			return nil, ErrSearchCacheArgs
		}
		if path.kind == indexPathSettings {
			found.settings, err = self.store.Read(ctx, file)
		} else {
			found.record, err = self.checkpoint(ctx, repo, ref, file)
		}
		if errors.Is(err, ErrEvsCollected) || errors.Is(err, errIndexCollected) {
			found.collected = true
		} else if err != nil {
			return nil, err
		}
		out = append(out, found)
	}
	return out, nil
}

// Reconstruction checks the complete file, including its oid, SHA-256, slots, receipts and erasure state. The cache
// then takes the original encrypted range and exactly the wrapped key that reopened this checkpoint.
func (self *memberIndexSource) checkpoint(ctx context.Context, repo *EvsRepo, ref Id, file *indexFileVersion) (*SearchCacheRecord, error) {
	if file.byteCount < 0 || int64(file.byteCount) > self.member.syncer.args.readByteCount {
		return nil, ErrSearchCacheContent
	}
	result, err := repo.read(ctx, ref, []string{file.path}, file.version, false)
	if err != nil {
		return nil, err
	}
	defer result.objects.close()
	v := result.replies[0]
	if v.Absent || v.Removal != nil || v.Entry == nil || v.Entry.Version != file.version {
		return nil, errIndexCollected
	}
	if v.CommitVersion != file.commitVersion || v.Statement == nil || !bytes.Equal(v.Statement.Push.GetSignerSidecarId(), file.signerSidecarId[:]) || len(v.Entry.Chain) != 1 {
		return nil, ErrSearchCacheContent
	}
	content, fields, _, err := repo.reconstructContent(ctx, result, v, nil)
	if err != nil {
		return nil, err
	}
	defer content.close()
	if fields.Size != uint64(file.byteCount) || !bytes.Equal(fields.ContentSha256, file.contentSha256[:]) {
		return nil, ErrSearchCacheContent
	}
	fileId, err := IdFromBytes(fields.FileId)
	if err != nil {
		return nil, err
	}
	record := &SearchCacheRecord{FileId: fileId}
	locator := v.Entry.Chain[0]
	generation := v.Statement.Push.Generation
	var sealed io.Reader
	switch protocol.EvsLocatorKind(locator.Kind) {
	case protocol.EvsLocatorKind_EVS_LOCATOR_INLINE:
		data := locator.GetInline()
		if len(data) < EvsWrappedKeyByteCount {
			return nil, ErrSearchCacheContent
		}
		record.WrappedObjectKey = bytes.Clone(data[:EvsWrappedKeyByteCount])
		sealed = bytes.NewReader(data[EvsWrappedKeyByteCount:])
	case protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT, protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
		headerRange, ok := result.objects.segmentRange(locator.Id, 0, evsSegmentKeyedHeaderByteCount)
		if !ok {
			return nil, ErrEvsObjectMissing
		}
		header, err := io.ReadAll(headerRange)
		if err != nil {
			return nil, err
		}
		offset := EvsSegmentHeaderByteCount
		if header[4] == evsSegmentFormat2 {
			headerRange, ok = result.objects.segmentRange(locator.Id, 0, evsKind5KeyedRecordOffset)
			if !ok {
				return nil, ErrEvsObjectMissing
			}
			header, err = io.ReadAll(headerRange)
			if err != nil {
				return nil, err
			}
			h, err := ParseEvsKind5SegmentHeader(header)
			if err != nil {
				return nil, err
			}
			generation = h.Generation
			offset = EvsKind5SegmentHeaderByteCount
		} else {
			h, err := ParseEvsSegmentHeader(header)
			if err != nil {
				return nil, err
			}
			generation = h.Generation
		}
		if len(header) < offset+EvsWrappedKeyByteCount {
			return nil, ErrSearchCacheContent
		}
		record.WrappedObjectKey = bytes.Clone(header[offset : offset+EvsWrappedKeyByteCount])
		sealed, ok = result.objects.segmentRange(locator.Id, locator.Offset, locator.Length)
		if !ok {
			return nil, ErrEvsObjectMissing
		}
	default:
		return nil, ErrSearchCacheContent
	}
	record.SealedHeader = make([]byte, EvsRecordHeaderByteCount)
	if _, err := io.ReadFull(sealed, record.SealedHeader); err != nil {
		return nil, err
	}
	manifest, err := result.keys.manifest(ctx, generation)
	if err != nil {
		return nil, err
	}
	record.Header, err = EvsOpenRecordHeader(manifest, record.SealedHeader)
	if err != nil {
		return nil, err
	}
	if record.Header.Kind != protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT || record.Header.BodyLength != fields.Size {
		return nil, ErrSearchCacheContent
	}
	if record.Header.KeyRefKind == protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT {
		raw, ok := result.objects.slot(record.Header.SlotId[:])
		if !ok {
			return nil, ErrEvsObjectMissing
		}
		slot, err := EvsDecodeSlotObject(raw)
		if err != nil {
			return nil, err
		}
		if err = record.SetSlotKey(slot, generation); err != nil {
			return nil, err
		}
	}
	fek, err := result.keys.fek(ctx, record.Header.Generation)
	if err != nil {
		return nil, err
	}
	record.ObjectKey, err = EvsUnwrapObjectKey(fek, record.WrappedObjectKey)
	if err != nil {
		return nil, err
	}
	record.SealedFrames = make([]byte, EvsRecordByteCount(record.Header.BodyLength)-EvsRecordHeaderByteCount)
	if _, err := io.ReadFull(sealed, record.SealedFrames); err != nil {
		return nil, err
	}
	return record, nil
}

// Settings are versioned and may be a delta chain. Their verified, bounded plaintext belongs in the sealed manifest.
func (self *SearchSync) memberSettings(ref *searchSyncRef, wanted *SearchSyncWanted, data []byte) (*SearchManifestFile, error) {
	parsed, ok := indexParsePath(wanted.Path, ref.args.companion)
	if !ok || parsed.kind != indexPathSettings {
		return nil, ErrSearchCacheArgs
	}
	if sha256.Sum256(data) != wanted.ContentSha256 {
		return nil, ErrSearchCacheContent
	}
	if _, err := indexValidateFile(parsed, indexBytesFrames(data), wanted.ContentSha256[:], self.args.format); err != nil {
		return nil, err
	}
	return &SearchManifestFile{Path: wanted.Path, Version: wanted.Version, ContentSha256: wanted.ContentSha256, ByteCount: wanted.ByteCount,
		Signer: wanted.Signer, Partition: wanted.Partition, State: SearchManifestHeld, Small: slices.Clone(data)}, nil
}
