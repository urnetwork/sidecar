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
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// One content ref's verified index. No method runs on a keystroke.
type memberIndexSource struct {
	member     *memberSearchSource
	store      *indexEvsStore
	kind       protocol.RepoKind
	contentRef Id
	nonWriter  bool
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
	if self.store.companion {
		// Discover stream ids from their signed heads without opening a record body. Pins survive a restart.
		streams := self.member.record.writer.boundStreams()
		if streams == nil {
			return nil, ErrRecordStreamsUnavailable
		}
		if _, err := streams.Streams(ctx, self.store.repo.repoId); err != nil {
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
	kind := verified.Head.GetRefKind()
	fileRef := kind == protocol.EvsRefKind_EVS_REF_SHARED || !self.store.companion && kind == protocol.EvsRefKind_EVS_REF_OWNED
	if verified.Version != 0 && (verified.Head.GetRefMode() != protocol.EvsRefMode_EVS_REF_FILE || !fileRef) {
		return nil, ErrSearchSyncUnfollowed
	}
	head := indexHeadOfEvs(verified)
	switch {
	case head.version < pin.Version:
		return nil, ErrEvsPinLower
	case head.version == pin.Version && head.version != 0 && head.chain != pin.Chain:
		return nil, ErrEvsPinFork
	}
	return &searchSyncReplay{head: head, catchUp: pin.Version != head.version}, nil
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
	if (AclRepoIsInbox(row) || row.Kind == protocol.RepoKind_REPO_KIND_MAILBOX) && self.member.heldMail(id) == nil {
		return false
	}
	rights := acl.EvsAccess(AclSidecarSubject(self.member.record.writer.sidecarId), id, AclTokenAudienceEvs, self.member.host.running.clock.Now()).Rights
	return rights.Has(AclEvsRead) && (aclRepoKindOwnerBound(row.Kind) && !rights.Has(AclEvsWrite)) == self.nonWriter
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
		if self.nonWriter {
			settings, err := self.protectedSettings(ctx, f, listing.head.version, judge)
			if err != nil {
				return nil, err
			}
			if settings != nil {
				files = append(files, settings)
			}
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
			if self.nonWriter {
				found.settings, err = self.readProtectedSettings(ctx, ref, file)
			} else {
				found.settings, err = self.store.Read(ctx, file)
			}
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
	if self.nonWriter {
		if err := self.bindSearchReceipt(ctx, result, v, file); err != nil {
			return nil, err
		}
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

// The two authenticated size and digest values of a supported settings encoding.
type memberSettingsHash struct {
	size   uint64
	digest [sha256.Size]byte
}

// Versioned settings attest a Git blob OID and size. For the supported canonical encodings this fixes their SHA-256
// before a body fetch. The table contains only identifiers and is built once per process.
var memberSearchSettingsDigests = sync.OnceValue(newMemberSearchSettingsDigests)

// The table, at its first read. A function of its own, not a literal in the variable's initializer: the ios_extension
// legs' closure (check/legs_closure_test.go) reads every call an initializer holds as run at start, and evsGitObjectOid
// is on the legs, so a literal calling it would take this file and the index it reads into the closure.
func newMemberSearchSettingsDigests() map[EvsGitOid]memberSettingsHash {
	table := make(map[EvsGitOid]memberSettingsHash)
	for days := uint32(0); days <= indexMaxWindowDays; days++ {
		for _, off := range []bool{false, true} {
			data, err := indexEncodeSettings(&protocol.IndexSettings{Off: off, WindowDays: days})
			if err == nil {
				table[evsGitObjectOid(evsGitBlobKind, data)] = memberSettingsHash{size: uint64(len(data)), digest: sha256.Sum256(data)}
			}
		}
	}
	return table
}

// Only the sealed fields of the signed settings version can identify a supported input for its receipt.
func memberSearchSettingsDigest(fields *protocol.EvsSealedFields) [sha256.Size]byte {
	if fields.GetOidKind() == protocol.EvsOidKind_EVS_OID_SHA1 && len(fields.GetGitOid()) == len(EvsGitOid{}) {
		item, ok := memberSearchSettingsDigests()[EvsGitOid(fields.GetGitOid())]
		if ok && item.size == fields.GetSize() {
			return item.digest
		}
	}
	return [sha256.Size]byte{}
}

// Finds the governing admin version by verified history alone. Unrecognized settings cannot be safely fetched.
func (self *memberIndexSource) protectedSettings(ctx context.Context, newest *indexFileVersion, head uint64, judge func(*indexFileVersion) bool) (*indexFileVersion, error) {
	if judge == nil {
		return nil, errSearchSyncReceipt
	}
	file := newest
	if !judge(file) {
		ref, err := self.store.refId(ctx)
		if err != nil {
			return nil, err
		}
		history, err := self.store.repo.History(ctx, &EvsReadArgs{RefId: &ref, Path: newest.path})
		if err != nil {
			return nil, err
		}
		file = nil
		for _, version := range history.Versions {
			if version.Removed || version.CommitVersion > head || version.State != "" && version.State != "kept" {
				continue
			}
			if !judge(&indexFileVersion{signerSidecarId: version.SignerSidecarId, signedTimeMs: version.Time.UnixMilli()}) {
				self.member.host.running.raiseIndexMalformed(self.store.repo.repoId, self.contentRef, newest.path, version.SignerSidecarId)
				continue
			}
			result, err := self.store.repo.read(ctx, ref, []string{newest.path}, version.Version, false)
			if err != nil {
				return nil, err
			}
			defer result.objects.close()
			v := result.replies[0]
			if v.Entry == nil || v.Entry.Version != version.Version || v.CommitVersion != version.CommitVersion {
				return nil, errIndexCollected
			}
			file, err = self.store.fileVersion(ctx, result, newest.path, v)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	if file != nil && file.contentSha256 == ([sha256.Size]byte{}) {
		return nil, errSearchSyncReceipt
	}
	return file, nil
}

// Opens exactly the settings version its prior receipt named, then verifies its actual read bytes before use.
func (self *memberIndexSource) readProtectedSettings(ctx context.Context, ref Id, file *indexFileVersion) ([]byte, error) {
	repo := self.store.repo
	result, err := repo.read(ctx, ref, []string{file.path}, file.version, false)
	if err != nil {
		return nil, err
	}
	defer result.objects.close()
	v := result.replies[0]
	if v.Entry == nil || v.Entry.Version != file.version || v.CommitVersion != file.commitVersion || v.Statement == nil ||
		!bytes.Equal(v.Statement.Push.GetSignerSidecarId(), file.signerSidecarId[:]) {
		return nil, errIndexCollected
	}
	if err := self.bindSearchReceipt(ctx, result, v, file); err != nil {
		return nil, err
	}
	content, _, _, err := repo.reconstructContent(ctx, result, v, nil)
	if err != nil {
		return nil, err
	}
	defer content.close()
	if content.Size() != int64(file.byteCount) || content.Size() > self.member.syncer.args.readByteCount {
		return nil, ErrSearchCacheContent
	}
	data, err := io.ReadAll(content.reader())
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(data) != file.contentSha256 {
		return nil, ErrSearchCacheContent
	}
	return data, nil
}

// Binds the named hash to this read's verified entry before any content reconstruction or additional object fetch.
func (self *memberIndexSource) bindSearchReceipt(ctx context.Context, result *evsReadResult, path *EvsVerifiedPath, wanted *indexFileVersion) error {
	if !self.store.searchMetadata || wanted.contentSha256 == ([sha256.Size]byte{}) {
		return errSearchSyncReceipt
	}
	verified, err := self.store.fileVersion(ctx, result, wanted.path, path)
	if err != nil {
		return err
	}
	if verified.version != wanted.version || verified.commitVersion != wanted.commitVersion || verified.signerSidecarId != wanted.signerSidecarId ||
		verified.contentSha256 != wanted.contentSha256 || verified.byteCount != wanted.byteCount {
		return errSearchSyncReceipt
	}
	result.searchReceipt = &wanted.contentSha256
	return nil
}
