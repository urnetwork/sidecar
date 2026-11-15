//go:build !ios_extension

// RECORD-M10-02's repo files (§16.11's ref cards block and its repo file, caps, path rules and repair rows; D-MCP-28,
// D-MCP-35, I-EVS-14, FI-25, FS-84, FS-101): from the directory's format 2 a repo's item rides one file, r/<h>/<repo>
// on the shared cards ref, in place of announce entries. RECORD-M10-03 routes the repo writes there; here a repo file
// is written when asked and judged as every reader judges it.
//
//	file    a Signed RepoAnnouncement, by a repo admin's identity key under purpose directory, SIGNED_DIRECTORY_REPO:
//	        network_id, repo_id, seq one above the last this copy accepted at the path or this device wrote there, at
//	        (§7.9's pin as written) and the repo's item, an announcement or a private marker, its announcement_id
//	        derived from repo_id; at most 4 KiB, stored padded to 2 KiB steps alike, so evs cannot tell the two apart
//	write   WriteRepoFile: a device holding D-MCP-35's right on the repo now, for an item that passes DirectoryCheckItem
//	        as this sidecar's; the seq journaled before the put; a path conflict syncs once and puts again
//	read    a version counts only by its push's signer and auth pin (I-EVS-14): the Signed's signer is the push's, both
//	        signatures verifying, network_id this network's, repo_id the path's, seq above the last version this copy
//	        accepted there, at within 4,096 positions before its push's auth pin and on the reader's chain, and its
//	        signer holding the right at that push pin's position by retained history, as directory_repo.go's repo file
//	        row judges an announce entry at its push's pin; never for a config, mailcfg or directory repo. Removed by a
//	        repo admin at its push's pin, or by any writer once the repo is deleted. Any other version is ignored with
//	        an alarm, once, and the copy goes on showing the version it accepted last
//
// Barriers: directory.repo_file.before and .after around a put, keyed by the repo's id, with no lock held. Safe for
// concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The copy's name for the seq this device journaled for a repo's file, and its document's version.
const (
	directoryRepoFileWrittenPrefix = "repo_file/"
	directoryRepoFileWrittenKept   = 1
)

// A repo file as stored.
type StoredDirectoryRepoFile struct {
	File   *protocol.RepoAnnouncement
	Signed *bridge.Signed
	// As received, never re-encoded.
	Bytes []byte
}

// A repo file's content, r/<h>/<repo>: within RepoFileByteCount, a Signed of type SIGNED_DIRECTORY_REPO by an identity
// key, whose body parses as a RepoAnnouncement that passes DirectoryCheckRepoFile. The signature, who the item names
// against its signer, the signer's right and the network are the reader's to judge.
func DirectoryDecodeRepoFile(content []byte, settings *DirectoryCardSettings) (*StoredDirectoryRepoFile, error) {
	if settings == nil {
		settings = DefaultDirectoryCardSettings()
	}
	signed, err := directoryDecodeSignedFile("a repo file", content, settings.RepoFileByteCount, bridge.SignedType_SIGNED_DIRECTORY_REPO)
	if err != nil {
		return nil, err
	}
	file := &protocol.RepoAnnouncement{}
	if err := proto.Unmarshal(signed.GetBody(), file); err != nil {
		return nil, directoryRefusal("a repo file body that does not parse: %v", err)
	}
	if err := DirectoryCheckRepoFile(file); err != nil {
		return nil, err
	}
	return &StoredDirectoryRepoFile{File: file, Signed: signed, Bytes: bytes.Clone(content)}, nil
}

// Holds a repo file to §16.11's repo file row and directory.proto's form: its ids, a seq, a pin and a repo item for
// its repo_id that passes DirectoryCheckItem, an announcement or a private marker.
func DirectoryCheckRepoFile(file *protocol.RepoAnnouncement) error {
	if file == nil {
		return directoryRefusal("no repo file")
	}
	switch {
	case !directoryIdValid(file.GetNetworkId(), false), !directoryIdValid(file.GetRepoId(), false):
		return directoryRefusal("a repo file with a network_id of %d bytes and a repo_id of %d", len(file.GetNetworkId()), len(file.GetRepoId()))
	case file.GetSeq() == 0:
		return directoryRefusal("a repo file at seq 0")
	case !directoryPinValid(file.GetAt()):
		return directoryRefusal("a repo file with no pin")
	}
	item := file.GetItem()
	if err := DirectoryCheckItem(item); err != nil {
		return err
	}
	if DirectoryAnnouncementKind(item.GetKind()) != DirectoryAnnouncementKindRepo || !bytes.Equal(item.GetWhere().GetRepoId(), file.GetRepoId()) {
		return directoryRefusal("a repo file holding another item than its repo's")
	}
	return nil
}

// The leaf a repo file's item folds under: the file's bytes, apart from every entry's.
func directoryRepoFileLeaf(content []byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte(directoryRepoFileLeafDomain))
	hash.Write([]byte{0})
	hash.Write(content)
	var leaf [sha256.Size]byte
	hash.Sum(leaf[:0])
	return leaf
}

// An accepted repo file's item as the fold holds a version: its signer's, its push's pin standing for an entry's push
// pin, where D-MCP-35's right is judged.
func directoryRepoFileVersion(taken *directoryAcceptedFile) *directoryVersion {
	file := taken.repo.File
	item := file.GetItem()
	pushPin := taken.file.AuthPin
	return &directoryVersion{
		key:            DirectoryItemKey{Kind: DirectoryAnnouncementKindRepo, AnnouncementId: recordIdOf(item.GetAnnouncementId())},
		leaf:           directoryRepoFileLeaf(taken.repo.Bytes),
		writerId:       recordIdOf(taken.repo.Signed.GetSignerId()),
		seq:            file.GetSeq(),
		pushPin:        &bridge.AuthPin{Version: pushPin.GetVersion(), Chain: bytes.Clone(pushPin.GetChain())},
		pushTimeMillis: taken.file.TimeMillis,
		item:           item,
	}
}

// An r/ path's written version by §16.11's path rules and repo file row: see the file's header's read row.
func (self *directoryFiles) judgeRepoFile(auth DirectoryAuthView, recordAuth RecordAuthView, judge *directoryJudge, file *DirectoryCardFile) directoryFileJudgement {
	repoId, _ := directoryRepoPathRepo(file.Path)
	settings := self.client.cardSettings()
	stored, err := DirectoryDecodeRepoFile(file.Content, settings)
	if err != nil {
		return directoryFileRefusal(SidecarRecordAlarmOverCap)
	}
	repoFile := stored.File
	signerId := recordIdOf(stored.Signed.GetSignerId())
	if recordIdOf(repoFile.GetRepoId()) != repoId || signerId != file.SignerSidecarId {
		// another repo's file at this path, or one the push's signer did not sign
		return directoryFileRefusal(SidecarRecordAlarmPathRule)
	}
	networkId := self.client.networkId
	if networkId == (Id{}) {
		return directoryFileJudgement{verdict: directoryFilePending}
	}
	if recordIdOf(repoFile.GetNetworkId()) != networkId {
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	}
	pushPin := file.AuthPin
	if !directoryPinValid(pushPin) {
		return directoryFileRefusal(SidecarRecordAlarmPathRule)
	}
	readerPin := auth.Pin()
	if readerPin == nil || readerPin.GetVersion() < pushPin.GetVersion() {
		return directoryFileJudgement{verdict: directoryFilePending}
	}
	if repo, ok := auth.Repo(repoId); ok && directoryRepoFileIgnored(repo.Kind) {
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	}
	key := recordAuth.IdentityKey(signerId)
	if len(key) == 0 || bridge.VerifySigned(stored.Signed, DirectorySignedPurpose, bridge.SignedType_SIGNED_DIRECTORY_REPO, bridge.SignedKeyAlgEd25519, key) != nil {
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	}
	if repoFile.GetSeq() <= self.seqAt(file.Path) {
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	}
	at := repoFile.GetAt()
	if pushPin.GetVersion() < at.GetVersion() || settings.PinPositionCount < pushPin.GetVersion()-at.GetVersion() {
		// at past its push's pin, or more than 4,096 positions before it
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	}
	if _, err := auth.At(at); errors.Is(err, ErrDirectoryAuthOffChain) {
		return directoryFileRefusal(SidecarRecordAlarmBadEntry)
	}
	version := directoryRepoFileVersion(&directoryAcceptedFile{file: file, seq: repoFile.GetSeq(), repo: stored})
	switch judgement := judge.repo(version); judgement.verdict {
	case directoryVerdictPending:
		return directoryFileJudgement{verdict: directoryFilePending}
	case directoryVerdictRefused:
		return directoryFileRefusal(judgement.alarm)
	}
	return directoryFileJudgement{verdict: directoryFileAccepted, taken: &directoryAcceptedFile{file: file, seq: repoFile.GetSeq(), repo: stored}}
}

// An r/ path's removal by its path rule: by a repo admin of the repo at its push's pin, or by any writer once the repo
// is deleted. Any other is a breach.
func (self *directoryFiles) judgeRepoFileRemoval(auth DirectoryAuthView, file *DirectoryCardFile) directoryFileJudgement {
	repoId, _ := directoryRepoPathRepo(file.Path)
	removed := &directoryAcceptedFile{file: file, seq: self.seqAt(file.Path)}
	if repo, ok := auth.Repo(repoId); !ok || !repo.Live {
		return directoryFileJudgement{verdict: directoryFileAccepted, taken: removed}
	}
	right, err := auth.RepoAdminRight(repoId, file.SignerSidecarId, file.AuthPin.GetVersion())
	switch {
	case errors.Is(err, ErrDirectoryAuthAhead), errors.Is(err, ErrDirectoryAuthUnavailable):
		return directoryFileJudgement{verdict: directoryFilePending}
	case err == nil && right:
		return directoryFileJudgement{verdict: directoryFileAccepted, taken: removed}
	}
	return directoryFileRefusal(SidecarRecordAlarmPathRule)
}

// What WriteRepoFile put.
type DirectoryRepoFileWritten struct {
	Path        string
	Seq         uint64
	PathVersion uint64
	Item        *protocol.Announcement
	// The Signed's bytes, and the size the binding stores them at, a whole number of steps.
	ByteCount       int
	StoredByteCount int
}

// The seq this device journaled for a repo's file.
type directoryRepoFileWrittenDocument struct {
	Version int    `json:"version"`
	Seq     uint64 `json:"seq"`
}

// The copy's name for repoId's journaled seq.
func directoryRepoFileWrittenName(repoId Id) string {
	return directoryRepoFileWrittenPrefix + hex.EncodeToString(repoId[:])
}

// The seq this device journaled for repoId's file, 0 for none.
func (self *DirectoryClient) readRepoFileWritten(repoId Id) (uint64, error) {
	content, err := self.store.readFile(directoryRepoFileWrittenName(repoId))
	if err != nil || content == nil {
		return 0, err
	}
	document := &directoryRepoFileWrittenDocument{}
	if err := json.Unmarshal(content, document); err != nil || document.Version != directoryRepoFileWrittenKept {
		return 0, fmt.Errorf("%w: a repo file's seq", ErrDirectoryStoreCorrupt)
	}
	return document.Seq, nil
}

// Puts a repo's file holding item, a repo item or its private marker as this sidecar's, from the version the copy
// read: see the file's header's write row. The caller builds item, redacted, at the version it means (RECORD-M10-03's
// repo writes, the repair's rewrite).
func (self *DirectoryClient) WriteRepoFile(ctx context.Context, item *protocol.Announcement) (*DirectoryRepoFileWritten, error) {
	if self.readOnly {
		return nil, ErrDirectoryReadOnly
	}
	if self.sign == nil || self.networkId == (Id{}) {
		return nil, ErrDirectoryCardUnbound
	}
	auth := self.auth()
	if _, ok := auth.Directory(); !ok {
		return nil, ErrDirectoryNone
	}
	if err := DirectoryCheckItem(item); err != nil {
		return nil, err
	}
	if DirectoryAnnouncementKind(item.GetKind()) != DirectoryAnnouncementKindRepo || !bytes.Equal(item.GetWho().GetSidecarId(), self.sidecarId[:]) {
		return nil, fmt.Errorf("%w: a repo file holds its repo's item as its signer's", ErrDirectoryFormatInvalid)
	}
	repoId := recordIdOf(item.GetWhere().GetRepoId())
	repo, ok := auth.Repo(repoId)
	if !ok || !repo.Live {
		return nil, fmt.Errorf("%w: a repo this state does not hold live", ErrDirectoryRepoRight)
	}
	if directoryRepoFileIgnored(repo.Kind) {
		return nil, ErrDirectoryRepoKind
	}
	if err := self.holdsRepoRight(auth, repoId); err != nil {
		return nil, err
	}
	settings := self.cardSettings()
	path := DirectoryRepoPath(repoId)
	hookKey := recordChainIdText(repoId)
	writer := self.cardWriter()
	writer.writeLock.Lock()
	defer writer.writeLock.Unlock()
	for attempt := 0; ; attempt += 1 {
		journaled, err := self.readRepoFileWritten(repoId)
		if err != nil {
			return nil, err
		}
		seq := max(journaled, self.files().seqAt(path)) + 1
		if err := self.store.writeDocument(directoryRepoFileWrittenName(repoId), &directoryRepoFileWrittenDocument{Version: directoryRepoFileWrittenKept, Seq: seq}); err != nil {
			return nil, err
		}
		pin := self.auth().Pin()
		if !directoryPinValid(pin) {
			return nil, ErrDirectoryAuthUnavailable
		}
		repoFile := &protocol.RepoAnnouncement{
			NetworkId: self.networkId.Bytes(),
			RepoId:    repoId.Bytes(),
			Seq:       seq,
			At:        &bridge.AuthPin{Version: pin.GetVersion(), Chain: bytes.Clone(pin.GetChain())},
			Item:      proto.Clone(item).(*protocol.Announcement),
		}
		if err := DirectoryCheckRepoFile(repoFile); err != nil {
			return nil, err
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(repoFile)
		if err != nil {
			return nil, err
		}
		signed, err := self.sign(DirectorySignedPurpose, bridge.SignedType_SIGNED_DIRECTORY_REPO, body, nil)
		if err != nil {
			return nil, fmt.Errorf("directory repo file: sign: %w", err)
		}
		content, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil {
			return nil, err
		}
		if settings.RepoFileByteCount < len(content) {
			return nil, fmt.Errorf("%w: a repo file of %d bytes, past %d", ErrDirectoryFormatInvalid, len(content), settings.RepoFileByteCount)
		}
		testHookBarrier("directory.repo_file.before", hookKey)
		pathVersion, err := self.PutCard(ctx, &DirectoryCardWrite{
			PushId: NewId(), Path: path, IfVersion: self.cardPathVersion(path), Content: content, AuthPin: repoFile.GetAt(),
		})
		testHookBarrier("directory.repo_file.after", hookKey)
		if err != nil && directoryPathConflict(err) && attempt == 0 {
			if err := self.Sync(ctx); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.repoWrittenVersions[repoId] = max(self.repoWrittenVersions[repoId], item.GetVersion())
		}()
		return &DirectoryRepoFileWritten{
			Path: path, Seq: seq, PathVersion: pathVersion, Item: repoFile.GetItem(), ByteCount: len(content),
			StoredByteCount: settings.StoredByteCount(len(content)),
		}, nil
	}
}

// Removes repoId's file from the version the copy read, as a repo admin, or as any writer once the repo is deleted.
func (self *DirectoryClient) removeRepoFile(ctx context.Context, repoId Id) error {
	path := DirectoryRepoPath(repoId)
	ifVersion := self.cardPathVersion(path)
	if ifVersion == 0 {
		return nil
	}
	hookKey := recordChainIdText(repoId)
	testHookBarrier("directory.repo_file.before", hookKey)
	err := self.RemoveCard(ctx, &DirectoryCardWrite{PushId: NewId(), Path: path, IfVersion: ifVersion, AuthPin: self.auth().Pin()})
	testHookBarrier("directory.repo_file.after", hookKey)
	return err
}
