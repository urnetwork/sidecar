//go:build !ios_extension

// Export in format 2 (§11.12's export row; R-EVS-10, D-EVS-22, D-EVS-38, D-EVS-63, FI-9, FS-73, FS-89;
// plan-EVS2-small-readings#7; EVS2-M10-19): what a file-mode ref's replay writes for a versionless version and for a
// version a drop took, so two exporters at one head write equal oids whatever either holds.
//
//	pointer   a replaced versionless version, one a later change of its path or a DELETE of its ref passed, exports
//	          as the git-lfs pointer to its content_sha256 and size, whether or not its bytes survive in a store, a
//	          batch or a cache, and no device uses a local copy of it; its commit's note names it (lfs-pointer <token
//	          path> <content_sha256>). Only a path's newest version exports its content, read through ReadVersion
//	dropped   a version an executed DROP lists (its window passed by this device's clock, no committed cancel of it in
//	          the ref's history, evs not reporting it refused) exports as the stub `ur-dropped <drop id hex> <entry
//	          hash hex>\n` with its entry version's mode, and its commit's note names it (dropped <token path> <drop
//	          id> <entry hash>); a pending drop's versions, and a cancelled or refused drop's, export their content
//	erased    a version whose key a committed ERASE destroyed, the path's newest versionless one or a kept one, exports as
//	          format 1's erased stub, `ur-erased <token path hex> <entry hash hex>\n` under its entry version's mode
//	          (§11.12's retention row; evs_export_file.go), and the replay goes on; a replaced versionless version
//	          stays its pointer and a dropped one its drop's stub, which read no content, whatever their keys
//	exact     export replays the ref's whole history, so it is a replaying reader: each executed drop's lists are held
//	          to the history it replayed (EvsCheckDropExact), and a drop whose body and list disagree fails the export
//	          with history_drop invalid naming its signer, rather than leave its stubs in commits already written
//	skipped   .ur-index/ files, ur/index and ur/lfs as format 1 skips them; a git-mode ref's pointers are its own
//	          blobs and pass through unchanged
//
// The scan reads each push's record once more before the replay writes anything, so a pointer or a stub is decided
// before the commit holding it is written. Not built, failing closed: a record whose entry versions evs zeroed for a
// dropped version that holds an inline record (DESIGN-DETAILS 10.2.9's records row) fails its payload check, so such a
// ref's export fails; a file-mode ref past a path epoch refuses, as format 1's does.
//
// On every leg but ios_extension; only a desktop host runs it.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// What a format-2 export decides before it replays a file-mode ref.
type evsExportFormat2 struct {
	// each token path's last change, write or removal, by its ref version, and the ref's last DELETE
	lastChanged map[string]uint64
	lastDelete  uint64
	// the executed drops, oldest first
	drops []*evsExportDrop
	// each version with an entry the replay passed, for the exactness check
	replayed []*evsExportReplayed
}

// One executed drop.
type evsExportDrop struct {
	version uint64
	dropId  Id
	signer  Id
	lists   *EvsDropLists
}

// One version the replay passed, with the ref version it committed at.
type evsExportReplayed struct {
	commitVersion uint64
	version       *EvsDropReplayVersion
}

// The git-lfs pointer of content whose SHA-256 is sum and whose size is size bytes (git-lfs's spec v1).
func EvsLfsPointerText(sum []byte, size uint64) []byte {
	return fmt.Appendf(nil, "version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", hex.EncodeToString(sum), size)
}

// The stub a dropped version exports as (FS-89).
func EvsExportDroppedStub(dropId Id, entrySha256 []byte) []byte {
	return []byte("ur-dropped " + hex.EncodeToString(dropId.Bytes()) + " " + hex.EncodeToString(entrySha256) + "\n")
}

// The scan of a file-mode ref's statements: every path's last change, and its drops, executed ones kept.
func (self *EvsRepo) exportFormat2Scan(ctx context.Context, head *EvsVerifiedHead) (*evsExportFormat2, error) {
	scan := &evsExportFormat2{lastChanged: map[string]uint64{}}
	found := []*evsExportDrop{}
	cancelled := map[string]bool{}
	for _, statement := range head.Statements {
		push := statement.Statement.Push
		flags := push.GetFlags()
		switch {
		case flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) != 0:
			scan.lastDelete = statement.Version
			continue
		case flags&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 || 1 < push.GetPathEpoch():
			// the replay refuses such a ref
			return scan, nil
		}
		payload, err := self.pushContent(ctx, head, statement)
		if err != nil {
			return nil, err
		}
		for _, change := range payload.Changes {
			scan.lastChanged[string(change.TokenPath.Bytes())] = statement.Version
		}
		if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 || payload.Drop == nil {
			continue
		}
		lists, err := NewEvsDropLists(push, payload.Drop.Body)
		if err != nil {
			return nil, err
		}
		history := lists.History()
		if history.GetAction() == evsDropActionCancel {
			cancelled[fmt.Sprintf("%x/%d", history.GetCancelsDropId(), history.GetCancelsVersion())] = true
			continue
		}
		dropId, err := IdFromBytes(history.GetDropId())
		if err != nil {
			return nil, fmt.Errorf("%w: a drop id", ErrEvsDropInvalid)
		}
		signerId, _ := IdFromBytes(push.GetSignerSidecarId())
		found = append(found, &evsExportDrop{version: statement.Version, dropId: dropId, signer: signerId, lists: lists})
	}
	refused := self.refusedDrops(ctx, head.RefId)
	now := self.client.clock.Now()
	for _, drop := range found {
		notBefore := evsTime(drop.lists.History().GetNotBeforeMs())
		if cancelled[fmt.Sprintf("%x/%d", drop.dropId.Bytes(), drop.version)] || refused[drop.dropId] || now.Before(notBefore) {
			continue
		}
		scan.drops = append(scan.drops, drop)
	}
	return scan, nil
}

// The drops evs reports refused on the ref: unsigned, so they only let content still stored export (§11.7's states
// row). A listing that fails reports none.
func (self *EvsRepo) refusedDrops(ctx context.Context, refId Id) map[Id]bool {
	refused := map[Id]bool{}
	drops, err := self.Drops(ctx, &EvsDropsArgs{})
	if err != nil {
		return refused
	}
	for _, drop := range drops {
		status := drop.Status
		if status.GetState() != protocol.EvsDropState_EVS_DROP_REFUSED || !bytes.Equal(status.GetRefId(), refId.Bytes()) {
			continue
		}
		if dropId, err := IdFromBytes(status.GetDropId()); err == nil {
			refused[dropId] = true
		}
	}
	return refused
}

// The executed drop listing the version at tokenPath in epoch, nil for none.
func (self *evsExportFormat2) dropOf(epoch uint64, tokenPath EvsTokenPath, version uint64) *evsExportDrop {
	for _, drop := range self.drops {
		if _, listed := drop.lists.Lists(epoch, tokenPath, version, false); listed {
			return drop
		}
	}
	return nil
}

// Whether the version a change committed at commitVersion wrote is replaced: a later change of its path, or a DELETE.
func (self *evsExportFormat2) replaced(tokenPath EvsTokenPath, commitVersion uint64) bool {
	return commitVersion < self.lastChanged[string(tokenPath.Bytes())] || commitVersion < self.lastDelete
}

// One file change of a format-2 export: true when it wrote the path's blob here, a stub, a pointer or a versionless
// newest version's content; false leaves it to exportBlob. Every version with an entry joins the replayed history.
func (self *EvsRepo) exportFormat2File(ctx context.Context, writer *evsGitObjectWriter, head *EvsVerifiedHead, scan *evsExportFormat2, statement *EvsVerifiedStatement, change *EvsCheckedChange, entry *protocol.EvsEntryVersion, fieldsKey *EvsManifestKey, pathNames [][]byte, state evsExportState) (bool, string, error) {
	epoch := max(1, statement.Statement.Push.GetPathEpoch())
	scan.replayed = append(scan.replayed, &evsExportReplayed{commitVersion: statement.Version, version: &EvsDropReplayVersion{
		Epoch: epoch, TokenPath: change.TokenPath, Version: entry.GetVersion(), EntrySha256: change.Change.GetEntrySha256(),
	}})
	versioning := entry.GetVersioning()
	fields, err := EvsOpenFieldsFormat2(fieldsKey, entry.GetSealedFields(), versioning)
	if err != nil {
		self.client.alarm(self.repoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
		return false, "", err
	}
	tokenHex := hex.EncodeToString(change.TokenPath.Bytes())
	if drop := scan.dropOf(epoch, change.TokenPath, entry.GetVersion()); drop != nil {
		oid, err := writer.write("blob", EvsExportDroppedStub(drop.dropId, change.Change.GetEntrySha256()))
		if err != nil {
			return false, "", err
		}
		state[evsExportKey(pathNames)] = &evsExportPath{names: pathNames, mode: fields.GetMode(), oid: oid}
		return true, fmt.Sprintf("dropped %s %s %x", tokenHex, hex.EncodeToString(drop.dropId.Bytes()), change.Change.GetEntrySha256()), nil
	}
	if versioning == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
		return false, "", nil
	}
	if scan.replaced(change.TokenPath, statement.Version) {
		oid, err := writer.write("blob", EvsLfsPointerText(fields.GetContentSha256(), fields.GetSize()))
		if err != nil {
			return false, "", err
		}
		state[evsExportKey(pathNames)] = &evsExportPath{names: pathNames, mode: fields.GetMode(), oid: oid}
		return true, fmt.Sprintf("lfs-pointer %s %x", tokenHex, fields.GetContentSha256()), nil
	}
	// the path's newest version: its content, read as any reader reads it
	spill := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
	defer spill.close()
	refId := head.RefId
	path := string(bytes.Join(pathNames, []byte("/")))
	info, err := self.ReadVersion(ctx, &EvsReadArgs{RefId: &refId, Path: path, Version: entry.GetVersion()}, spill)
	if errors.Is(err, ErrEvsErased) {
		// its key a committed ERASE destroyed: the erased stub, and the replay goes on (see the file header)
		oid, err := writer.writeErasedStub(change)
		if err != nil {
			return false, "", err
		}
		state[evsExportKey(pathNames)] = &evsExportPath{names: pathNames, mode: fields.GetMode(), oid: oid}
		return true, "", nil
	}
	if err != nil {
		return false, "", err
	}
	oid, err := writer.writeFrom("blob", spill.reader(), spill.Size())
	if err != nil {
		return false, "", err
	}
	if oid != info.GitOid {
		return false, "", fmt.Errorf("%w: a versionless version whose blob is not its oid", ErrEvsSealInvalid)
	}
	state[evsExportKey(pathNames)] = &evsExportPath{names: pathNames, mode: fields.GetMode(), oid: oid}
	return true, "", nil
}

// The exactness check of each executed drop against the history the replay passed below it: a disagreement raises
// history_drop invalid naming its signer and fails the export.
func (self *EvsRepo) exportFormat2Exact(head *EvsVerifiedHead, scan *evsExportFormat2) error {
	for _, drop := range scan.drops {
		versions := []*EvsDropReplayVersion{}
		for _, replayed := range scan.replayed {
			if replayed.commitVersion < drop.version {
				versions = append(versions, replayed.version)
			}
		}
		if err := EvsCheckDropExact(drop.lists.History(), versions); err != nil {
			signerId := drop.signer
			self.client.raiseHistoryDropOnce(&SidecarHistoryDrop{
				RepoId: self.repoId, RefId: head.RefId, DropId: drop.dropId, State: SidecarDropInvalid, SignerSidecarId: &signerId,
			})
			return fmt.Errorf("%w: %w", ErrEvsExport, err)
		}
	}
	return nil
}

// The note lines a commit's format-2 blobs add, joined for its note.
func evsExportNoteLines(lines []string) string {
	kept := []string{}
	for _, line := range lines {
		if line != "" {
			kept = append(kept, line+"\n")
		}
	}
	return strings.Join(kept, "")
}
