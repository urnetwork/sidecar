// Export (§11.12's export row, R-EVS-10, FI-9): plain git rebuilt from evs, into a new bare repository, with git's
// own oids. Each ref's whole history is read from version 1 and verified as a replaying reader does (the walk from C_0
// to the head, every statement's signer and rules), then rebuilt push by push from each push's record:
//
//   - a git-mode ref's push carries every commit of its update, sealed with each commit's changes against its first
//     parent (EvsSealedCommit), so export rebuilds each tree from its parent's, checks it hashes to the tree its commit
//     names, and writes the commit's exact bytes, which reproduce the original oid; blobs come from the push's own
//     entries, each reconstructed and its oid checked;
//   - a file-mode ref gets one deterministic commit per version (evs_export_file.go), which needs every path's name,
//     the top level's included, and format 1 gives the root no entry: so file-mode export refuses until question
//     evs1-m2-24-root-directory-names is answered.
//
// Provenance goes in refs/notes/ur (evs_export_notes.go). ur/index and ur/lfs are derived or stores, never exported, and
// .ur-index/ files are left out of every tree. A push in parts, and a format-2 repo's collected or dropped versions
// (M10's), refuse.
//
// Refs are named by the names the caller holds, since a head's sealed ref name is not stored yet
// (questions/evs1-m2-01-ref-creation-fields.md): nil exports main.
//
// On every leg; only a desktop host runs it. Safe for concurrent use with other calls; one export at a time per
// target.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The refs export leaves out (§11.11, §11.14).
var evsExportSkippedRefNames = [][]byte{[]byte("ur/index"), []byte("ur/lfs")}

// The top-level directory of the search index's files, which export leaves out of every tree.
const evsExportSkippedDirectory = ".ur-index"

// Rebuilds plain git from the repo's refs into args.Dir.
func (self *EvsRepo) Export(ctx context.Context, args *EvsExportArgs) (*EvsExportResult, error) {
	writer, err := newEvsGitObjectWriter(args.Dir)
	if err != nil {
		return nil, err
	}
	refNames := args.RefNames
	if refNames == nil {
		refNames = [][]byte{EvsMainRefName}
	}
	result := &EvsExportResult{}
	notes := []*evsExportNote{}
	for _, refName := range refNames {
		skipped := false
		for _, skip := range evsExportSkippedRefNames {
			skipped = skipped || bytes.Equal(refName, skip)
		}
		if skipped {
			continue
		}
		refId, err := self.resolveRefId(ctx, refName, nil)
		if err != nil {
			return nil, err
		}
		gitRef := EvsGitRefOfName(refName)
		exported, refNotes, err := self.exportRef(ctx, writer, refId, gitRef)
		if err != nil {
			return nil, err
		}
		if exported != nil {
			result.Refs = append(result.Refs, exported)
		}
		notes = append(notes, refNotes...)
	}
	if err := writer.writeNotes(notes); err != nil {
		return nil, err
	}
	return result, nil
}

// One ref's whole history, verified from C_0 and pinned, then rebuilt into writer under gitRef.
func (self *EvsRepo) exportRef(ctx context.Context, writer *evsGitObjectWriter, refId Id, gitRef string) (*EvsExportedRef, []*evsExportNote, error) {
	reply, objects, err := self.client.postRead(ctx, self.repoId, &protocol.EvsReadRequest{RefId: refId.Bytes(), Fresh: true})
	if err != nil {
		return nil, nil, err
	}
	objects.close()
	head := reply.head
	headChain, err := EvsChainFromBytes(head.GetChain())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the head's chain", ErrEvsReplyInvalid)
	}
	if err := self.client.verifier.checkPin(self.repoId, refId, head.GetVersion(), headChain); err != nil {
		return nil, nil, err
	}
	statements, err := self.client.readLog(ctx, self.repoId, refId, 1, head.GetVersion())
	if err != nil {
		return nil, nil, err
	}
	start := EvsChainStart(self.repoId, refId)
	walked, err := self.client.verifier.walk(self.repoId, refId, 0, start, statements, head.GetVersion())
	if err != nil {
		return nil, nil, err
	}
	reached := start
	if 0 < len(walked) {
		reached = walked[len(walked)-1].Chain
	}
	if reached != headChain {
		return nil, nil, fmt.Errorf("%w: the history does not chain to the head", ErrEvsChainBroken)
	}
	verified := &EvsVerifiedHead{RepoId: self.repoId, RefId: refId, Head: head, Version: head.GetVersion(), Chain: headChain, Statements: walked}
	if err := self.client.verifier.Pin(verified); err != nil {
		return nil, nil, err
	}
	if len(walked) == 0 {
		return nil, nil, nil
	}
	switch protocol.EvsRefMode(head.GetRefMode()) {
	case protocol.EvsRefMode_EVS_REF_GIT:
		return self.exportGitRef(ctx, writer, verified, gitRef)
	case protocol.EvsRefMode_EVS_REF_FILE:
		return nil, nil, fmt.Errorf("%w: a file-mode ref's tree needs its root's names (question evs1-m2-24-root-directory-names)", ErrEvsExport)
	default:
		return nil, nil, fmt.Errorf("%w: ref mode %d", ErrEvsExport, head.GetRefMode())
	}
}

// A git-mode ref, push by push: each push's sealed commits rebuilt on their first parents' trees, their oids checked.
func (self *EvsRepo) exportGitRef(ctx context.Context, writer *evsGitObjectWriter, head *EvsVerifiedHead, gitRef string) (*EvsExportedRef, []*evsExportNote, error) {
	keys := newEvsReadKeys(self)
	states := map[EvsGitOid]evsExportState{}
	var tip *EvsGitOid
	notes := []*evsExportNote{}
	for _, statement := range head.Statements {
		push := statement.Statement.Push
		flags := push.GetFlags()
		if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
			continue
		}
		if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) != 0 {
			tip = nil
			continue
		}
		if push.GetPartCount() != 0 {
			return nil, nil, fmt.Errorf("%w: a push in parts, which this draft does not read back", ErrEvsExport)
		}
		payload, err := self.pushPayload(ctx, head, statement)
		if err != nil {
			return nil, nil, err
		}
		manifest, err := keys.manifest(ctx, push.GetGeneration())
		if err != nil {
			return nil, nil, err
		}
		metadata, err := EvsOpenMetadata(manifest, payload.SealedMetadata)
		if err != nil {
			self.client.alarm(self.repoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
			return nil, nil, err
		}
		for _, change := range payload.Changes {
			if !change.WritesEntry() {
				continue
			}
			if err := self.exportBlob(ctx, writer, head, keys, statement, change); err != nil {
				return nil, nil, err
			}
		}
		for _, sealed := range metadata.GetCommits() {
			commit, err := EvsGitCommitDecode(sealed.GetObject())
			if err != nil {
				return nil, nil, err
			}
			state := evsExportState{}
			if 0 < len(commit.ParentOids) {
				parent, ok := states[commit.ParentOids[0]]
				if !ok {
					return nil, nil, fmt.Errorf("%w: a commit whose first parent this export did not rebuild", ErrEvsExport)
				}
				state = parent.clone()
			}
			for _, change := range sealed.GetChanges() {
				names := change.GetPath()
				if len(names) == 0 || bytes.Equal(names[0], []byte(evsExportSkippedDirectory)) {
					continue
				}
				if len(change.GetGitOid()) == 0 {
					delete(state, evsExportKey(names))
					continue
				}
				oid := EvsGitOid(change.GetGitOid())
				if !writer.has(oid) {
					return nil, nil, fmt.Errorf("%w: a commit naming a blob no push carries", ErrEvsExport)
				}
				state[evsExportKey(names)] = &evsExportPath{names: names, mode: change.GetMode(), oid: oid}
			}
			treeOid, err := writer.writeTree(state)
			if err != nil {
				return nil, nil, err
			}
			if treeOid != commit.TreeOid {
				self.client.alarm(self.repoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
				return nil, nil, fmt.Errorf("%w: a commit's tree does not rebuild from its changes", ErrEvsExport)
			}
			commitOid, err := writer.write("commit", sealed.GetObject())
			if err != nil {
				return nil, nil, err
			}
			states[commitOid] = state
			tip = &commitOid
		}
		if tip != nil {
			notes = append(notes, &evsExportNote{commit: *tip, statement: statement})
		}
	}
	if tip == nil {
		return nil, notes, nil
	}
	if err := writer.setRef(gitRef, *tip); err != nil {
		return nil, nil, err
	}
	return &EvsExportedRef{GitRef: gitRef, Tip: *tip, Versions: head.Version}, notes, nil
}

// The push record of one verified statement, read by its push id and version, its statement equal to the one
// verified and its payload checked against it (§11.6's checks row).
func (self *EvsRepo) pushPayload(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (*EvsCheckedPayload, error) {
	request := &protocol.EvsReadRequest{
		RefId:      head.RefId.Bytes(),
		PinVersion: head.Version,
		Pushes:     []*protocol.EvsReadPush{{PushId: statement.Statement.Push.GetPushId(), Version: statement.Version}},
	}
	_, objects, err := self.client.postRead(ctx, self.repoId, request)
	if err != nil {
		return nil, err
	}
	defer objects.close()
	var record []byte
	for key, spill := range objects.objects {
		if key.kind == protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD && key.number == 0 {
			record, err = io.ReadAll(spill.reader())
			if err != nil {
				return nil, err
			}
		}
	}
	if record == nil {
		return nil, fmt.Errorf("%w: a push record evs did not serve", ErrEvsObjectMissing)
	}
	items, err := EvsPayloadItems(record)
	if err != nil || len(items) < 2 || !bytes.Equal(items[0], statement.Statement.Bytes) {
		return nil, fmt.Errorf("%w: a push record of another statement", ErrEvsEntryRefused)
	}
	return EvsCheckPayload(statement.Statement, items[1])
}

// One entry of a push reconstructed into a blob, its oid checked by reconstruction.
func (self *EvsRepo) exportBlob(ctx context.Context, writer *evsGitObjectWriter, head *EvsVerifiedHead, keys *evsReadKeys, statement *EvsVerifiedStatement, change *EvsCheckedChange) error {
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
		return fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
	}
	if entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
		return nil
	}
	result := &evsReadResult{refId: head.RefId, head: head, keys: keys, objects: newEvsReadObjects(self.client)}
	defer result.objects.close()
	verified := &EvsVerifiedPath{TokenPath: change.TokenPath, EntryBytes: change.EntryVersion, Entry: entry, Statement: statement.Statement, CommitVersion: statement.Version}
	spill := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
	defer spill.close()
	if _, err := self.reconstruct(ctx, result, verified, spill); err != nil {
		return err
	}
	_, err := writer.writeFrom("blob", spill.reader(), spill.Size())
	return err
}
