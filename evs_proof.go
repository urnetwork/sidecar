// A head reader's check of one path's reply against its statements (§11.9's reader row): the version evs serves hashes
// to the entry_sha256 its statement names for exactly that path, directly from an inline change list or by a Merkle
// proof to changes_root (part level last); a removal's statement removes the path or a prefix holding it; and no
// statement after the version's own, among those the reader walked, changes the path or a prefix holding it again. A
// statement whose changes are inline answers that from its list; one under changes_root answers it only where a
// covering prefix matches, and then by the adjacent-leaf proofs evs sends for the path and each such prefix, never
// the whole list (§11.6's merkle row).
//
// What a statement at or below the read's pin says is checked against that statement, signed by a writer, but nothing
// shows it was the version current at the pin: for a path this device never read, or no longer remembers, that is
// evs's word (Q-EVS-6, §2.8, g0-recheck-0-head-reader-read-paths#2). A read record moves the pin back to the path's
// last read, so a recorded path's later statements are all checked.
//
// Format 2's read states and settings answer ErrEvsFormatUnsupported for that path alone, never a fork, so the
// caller reads the rest (EVS1-M2-39).
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One path's reply as the reader verified it.
type EvsVerifiedPath struct {
	TokenPath EvsTokenPath
	// A version that stands: its bytes, its parse, the statement that wrote it and the ref version it committed at.
	EntryBytes    []byte
	Entry         *protocol.EvsEntryVersion
	Statement     *EvsStatement
	CommitVersion uint64
	// A removal that stands, from its marker or the window, and the statement that made it.
	Removal *protocol.EvsRemovalMarker
	// An overlay's path it holds no version of: the base ref and version to read instead (§11.7).
	Base *protocol.EvsOverlay
	// A directory's folded table as of NamesThrough, and its deltas after it, each verified as a version is.
	Names        *protocol.EvsNameTable
	NamesThrough uint64
	Deltas       []*EvsVerifiedPath
}

// Checks reply for tokenPath against head's walk.
func (self *EvsVerifier) VerifyPath(head *EvsVerifiedHead, tokenPath EvsTokenPath, reply *protocol.EvsReadPathReply) (*EvsVerifiedPath, error) {
	if reply.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED || len(reply.GetDropId()) != 0 ||
		reply.GetNotBeforeMs() != 0 || reply.GetDropVersion() != 0 || len(reply.GetDropStatement()) != 0 {
		return nil, fmt.Errorf("%w: a format-2 read state", ErrEvsFormatUnsupported)
	}
	replyPath, err := ParseEvsTokenPath(reply.GetTokenPath())
	if err != nil || !replyPath.Equal(tokenPath) {
		return nil, fmt.Errorf("%w: a reply for another path", ErrEvsEntryRefused)
	}
	verified := &EvsVerifiedPath{TokenPath: tokenPath}
	switch {
	case reply.GetBase() != nil:
		if reply.GetVersion() != nil || reply.GetRemoval() != nil {
			return nil, fmt.Errorf("%w: an overlay base beside a version", ErrEvsEntryRefused)
		}
		verified.Base = reply.GetBase()
		return verified, nil
	case reply.GetRemoval() != nil:
		if reply.GetVersion() != nil {
			return nil, fmt.Errorf("%w: a removal beside a version", ErrEvsEntryRefused)
		}
		if err := self.verifyRemoval(head, tokenPath, reply, verified); err != nil {
			return nil, err
		}
	case reply.GetVersion() != nil:
		if err := self.verifyVersion(head, tokenPath, reply.GetVersion(), reply.GetStatement(), reply.GetProof(), verified); err != nil {
			return nil, err
		}
		if verified.Entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
			if err := self.verifyDeltas(head, tokenPath, reply, verified); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("%w: a reply with no version, removal or base", ErrEvsEntryRefused)
	}
	// a directory's own later writes are its deltas, each of which the walk must account for
	deltaVersions := map[uint64]bool{}
	for _, delta := range verified.Deltas {
		deltaVersions[delta.CommitVersion] = true
	}
	if err := self.verifyUnchangedSince(head, tokenPath, verified.CommitVersion, reply.GetAbsences(), deltaVersions); err != nil {
		return nil, err
	}
	return verified, nil
}

// The statement committed at version: from the walk when it holds it, which then must name pushId, else the
// statement evs sent beside the reply, verified on its own.
func (self *EvsVerifier) statementAt(head *EvsVerifiedHead, version uint64, pushId []byte, sent []byte) (*EvsStatement, error) {
	if head.Version < version || version == 0 {
		return nil, fmt.Errorf("%w: a version past the head", ErrEvsEntryRefused)
	}
	if walked, ok := head.StatementAt(version); ok {
		if !bytes.Equal(walked.Statement.Push.GetPushId(), pushId) {
			return nil, fmt.Errorf("%w: a version its committed push did not write", ErrEvsEntryRefused)
		}
		return walked.Statement, nil
	}
	if len(sent) == 0 {
		return nil, fmt.Errorf("%w: no statement for a version below the walk", ErrEvsEntryRefused)
	}
	statement, err := self.VerifyStatement(sent, head.RepoId, head.RefId)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(statement.Push.GetPushId(), pushId) {
		return nil, fmt.Errorf("%w: a statement of another push", ErrEvsEntryRefused)
	}
	return statement, nil
}

// The change statement makes to tokenPath, from its inline list or by proofs to its changes_root.
func evsChangeOf(statement *EvsStatement, tokenPath EvsTokenPath, proofs []*protocol.EvsMerkleProof, prefixOk bool) (*protocol.EvsChange, EvsTokenPath, error) {
	push := statement.Push
	if len(push.GetChangesRoot()) == 0 {
		for _, change := range statement.Changes {
			if change.TokenPath.Equal(tokenPath) || (prefixOk && tokenPath.HasPrefix(change.TokenPath)) {
				return change.Change, change.TokenPath, nil
			}
		}
		return nil, nil, fmt.Errorf("%w: a statement that does not change the path", ErrEvsEntryRefused)
	}
	change, changedPath, err := EvsVerifyChangeInclusion(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), proofs)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrEvsEntryRefused, err)
	}
	if !changedPath.Equal(tokenPath) && !(prefixOk && tokenPath.HasPrefix(changedPath)) {
		return nil, nil, fmt.Errorf("%w: a proof of another path", ErrEvsEntryRefused)
	}
	return change, changedPath, nil
}

// Checks a version: its statement, its entry hash to that statement's change of exactly tokenPath, its push and base,
// and format 1's shape.
func (self *EvsVerifier) verifyVersion(head *EvsVerifiedHead, tokenPath EvsTokenPath, version *protocol.EvsIndexVersion, sent []byte, proofs []*protocol.EvsMerkleProof, verified *EvsVerifiedPath) error {
	if version.GetElided() || len(version.GetEntryVersion()) == 0 {
		return fmt.Errorf("%w: an elided version", ErrEvsEntryRefused)
	}
	statement, err := self.statementAt(head, version.GetCommitVersion(), version.GetPushId(), sent)
	if err != nil {
		return err
	}
	change, _, err := evsChangeOf(statement, tokenPath, proofs, false)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(version.GetEntryVersion())
	if !bytes.Equal(digest[:], change.GetEntrySha256()) {
		self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
		return fmt.Errorf("%w: an entry that does not hash to its statement's", ErrEvsEntryRefused)
	}
	if _, err := checkEvsEntryVersion(version.GetEntryVersion(), statement.Push); err != nil {
		return err
	}
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(version.GetEntryVersion(), entry); err != nil {
		return fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
	}
	if change.GetBaseEntryVersion() != 0 && entry.GetVersion() != change.GetBaseEntryVersion()+1 {
		self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmVersionRule, "", nil)
		return fmt.Errorf("%w: a write not at its base + 1", ErrEvsVersionRule)
	}
	if change.GetBaseEntryVersion() == 0 && entry.GetVersion() <= statement.Push.GetBaseVersion() {
		self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmVersionRule, "", nil)
		return fmt.Errorf("%w: a creation at or below its push's base", ErrEvsVersionRule)
	}
	verified.EntryBytes = version.GetEntryVersion()
	verified.Entry = entry
	verified.Statement = statement
	verified.CommitVersion = version.GetCommitVersion()
	return nil
}

// Checks a removal: its statement removes tokenPath, or a prefix holding it, at the marker's versions.
func (self *EvsVerifier) verifyRemoval(head *EvsVerifiedHead, tokenPath EvsTokenPath, reply *protocol.EvsReadPathReply, verified *EvsVerifiedPath) error {
	removal := reply.GetRemoval()
	statement, err := self.statementAt(head, removal.GetRemovalVersion(), removal.GetPushId(), reply.GetStatement())
	if err != nil {
		return err
	}
	change, changedPath, err := evsChangeOf(statement, tokenPath, reply.GetProof(), true)
	if err != nil {
		return err
	}
	if len(change.GetEntrySha256()) != 0 {
		return fmt.Errorf("%w: a removal whose statement writes the path", ErrEvsEntryRefused)
	}
	if changedPath.Equal(tokenPath) && removal.GetPathVersion() != change.GetBaseEntryVersion()+1 {
		self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmVersionRule, "", nil)
		return fmt.Errorf("%w: a removal not one past the path's last", ErrEvsVersionRule)
	}
	if len(removal.GetSegmentIds()) != 0 || len(removal.GetSlotIds()) != 0 {
		return fmt.Errorf("%w: a marker carrying format 2's ids", ErrEvsFormatUnsupported)
	}
	verified.Removal = removal
	verified.Statement = statement
	verified.CommitVersion = removal.GetRemovalVersion()
	return nil
}

// Checks a directory's deltas after its folded table: each a version of the directory, in version order, after the
// table's names_through, verified as a version is. The table itself is evs's fold, whose names List checks against
// their tokens.
func (self *EvsVerifier) verifyDeltas(head *EvsVerifiedHead, tokenPath EvsTokenPath, reply *protocol.EvsReadPathReply, verified *EvsVerifiedPath) error {
	verified.Names = reply.GetNames()
	verified.NamesThrough = reply.GetNamesThrough()
	last := reply.GetNamesThrough()
	for _, delta := range reply.GetDeltas() {
		if delta.GetCommitVersion() <= last {
			return fmt.Errorf("%w: deltas out of version order", ErrEvsEntryRefused)
		}
		last = delta.GetCommitVersion()
		deltaPath := &EvsVerifiedPath{TokenPath: tokenPath}
		// a delta's statement after the pin is in the walk; one below it travels as the reply's own statement is
		// not, so it is refused unless the walk holds it
		if err := self.verifyVersion(head, tokenPath, delta, nil, nil, deltaPath); err != nil {
			return err
		}
		verified.Deltas = append(verified.Deltas, deltaPath)
	}
	return nil
}

// Checks that no walked statement after version since changes tokenPath or a prefix holding it: an inline list by its
// changes, a change list under changes_root by the adjacent-leaf proofs evs sent for each path its covering prefixes
// reach (EvsAbsencePaths). A directory's own later writes are its deltas, at deltaVersions, already verified; any
// other is a delta evs left out.
func (self *EvsVerifier) verifyUnchangedSince(head *EvsVerifiedHead, tokenPath EvsTokenPath, since uint64, absences []*protocol.EvsAbsenceProof, deltaVersions map[uint64]bool) error {
	for _, walked := range head.Statements {
		if walked.Version <= since || deltaVersions[walked.Version] {
			continue
		}
		push := walked.Statement.Push
		if len(push.GetChangesRoot()) == 0 {
			for _, change := range walked.Statement.Changes {
				if tokenPath.HasPrefix(change.TokenPath) {
					self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
					return fmt.Errorf("%w: a later statement changes the path, served as unchanged", ErrEvsEntryRefused)
				}
			}
			continue
		}
		for _, absentPath := range EvsAbsencePaths(walked.Statement.ChangedPrefixes, tokenPath) {
			proven := false
			for _, absence := range absences {
				absencePath, err := ParseEvsTokenPath(absence.GetTokenPath())
				if absence.GetVersion() != walked.Version || err != nil || !absencePath.Equal(absentPath) {
					continue
				}
				if err := EvsVerifyChangeAbsence(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), absentPath, absence); err != nil {
					self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
					return fmt.Errorf("%w: %w", ErrEvsEntryRefused, err)
				}
				proven = true
				break
			}
			if !proven {
				return fmt.Errorf("%w: a later statement's change list with no proof the path is absent", ErrEvsEntryRefused)
			}
		}
	}
	return nil
}
