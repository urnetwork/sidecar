// A head reader's check of one path's reply against its statements (§11.9's reader row): the version evs serves hashes
// to the entry_sha256 its statement names for exactly that path, directly from an inline change list or by a Merkle
// proof to changes_root (part level last); a removal's statement removes the path or a prefix holding it; and no
// statement after the version's own, among those the reader walked, changes the path or a prefix holding it again. A
// statement whose changes are inline answers that from its list; one under changes_root answers it only where a
// covering prefix matches, and then by the adjacent-leaf proofs evs sends for the path and each such prefix, never
// the whole list (§11.6's merkle row). A strict prefix such a statement changed by a delta, which does not end the
// path (§11.7's newest row), has no adjacent leaves: evs sends that delta's inclusion proof in the absence's present,
// which the reader takes for a strict prefix whose change writes an entry and refuses for the path itself or a
// removal; and each of a directory's deltas after its table comes with its own proof, delta_proofs (QD-681).
//
// What a statement at or below the read's pin says is checked against that statement, signed by a writer, but nothing
// shows it was the version current at the pin: for a path this device never read, or no longer remembers, that is
// evs's word (Q-EVS-6, §2.8, g0-recheck-0-head-reader-read-paths#2). A read record moves the pin back to the path's
// last read, so a recorded path's later statements are all checked.
//
// Path epochs (DESIGN-DETAILS 9.2.4's reader). A statement names its changes by token paths in the epoch it declares,
// so every statement is checked under the path's token path in that statement's own epoch, tp(X, e), which the
// reader derives from the name and the ladder and never takes from a reply: the served version, removal or delta at u
// under tp(X, e(u)), its proof's leaf compared with it, and each walked statement after it under tp(X, e(w)). A
// rooted statement of an epoch the request named no token path in has no proof evs could give: the reader asks once
// more naming that epoch, which is at or above e(u) and so at or above the path's floor. A directory's untagged rows
// open under the epoch whose copy served them (entry_epoch), its carried rows under their own, a delta's under its
// statement's (evs_list.go).
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
	"slices"

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
	// A path the ref never wrote, or none evs holds a version or removal of, unchanged through the walk.
	Absent bool
	// A directory's folded table as of NamesThrough, and its deltas after it, each verified as a version is.
	Names        *protocol.EvsNameTable
	NamesThrough uint64
	Deltas       []*EvsVerifiedPath
	// The epoch whose copy served the version, table or marker, 0 the head's current one (DESIGN-DETAILS 9.2.2's
	// entry_epoch): a folded table's untagged rows open under it.
	EntryEpoch uint64
	// The lowest epoch whose statement, verified, names the path's own token path in it (DESIGN-DETAILS 9.2.3's E1),
	// 0 for none.
	Floor uint64
	// evs answered with the statement alone, verified, of a version or removal it could not place in it
	// (question evs1-m2-45-inline-leaf-place; 9.2.4's history): the reader asks again naming its epoch, and nothing
	// else of the reply stands.
	StatementAlone *EvsStatement
}

// A path as the verifier checks it: its token path in any epoch, derived by the reader from its name, never taken from
// a reply (DESIGN-DETAILS 9.2.4's reader), and the epochs the request named it in.
type EvsPathEpochs struct {
	TokenPathIn func(epoch uint64) (EvsTokenPath, error)
	Named       map[uint64]bool
	// An older version asked for by number: history, not a rollback, so the walk after it is not checked (§11.9's
	// "older ones on request").
	History bool
	// The path's own pin, its record's PinVersion, else the ref pin before this read: the walk checks statements after
	// it and after the version's own (DESIGN-DETAILS 9.2.4's since = max(u, pin(X))).
	Since uint64
}

// Checks reply for a path against head's walk, every statement under the path's token path in that statement's own
// epoch (DESIGN-DETAILS 9.2.4's verifyPath): a version, removal or delta at u under tp(X, e(u)), which E1 makes the
// path's floor; each walked statement after it under tp(X, e(w)), a rooted one by the absence proofs evs sent for
// that epoch. A rooted statement of an epoch the request did not name, with no proof, adds that epoch to the epochs
// answered, which the reader asks once more naming; of one it named, it refuses.
func (self *EvsVerifier) VerifyPath(head *EvsVerifiedHead, epochs *EvsPathEpochs, reply *protocol.EvsReadPathReply) (*EvsVerifiedPath, []uint64, error) {
	if reply.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED || len(reply.GetDropId()) != 0 ||
		reply.GetNotBeforeMs() != 0 || reply.GetDropVersion() != 0 || len(reply.GetDropStatement()) != 0 || len(reply.GetDropBody()) != 0 {
		return nil, nil, fmt.Errorf("%w: a format-2 read state", ErrEvsFormatUnsupported)
	}
	current := evsCurrentEpoch(head.Head.GetPathEpoch())
	if reply.GetStaleEpoch() {
		// only a request naming no token path in the head's current epoch is answered stale (9.2.4's route)
		return nil, nil, fmt.Errorf("%w: a stale_epoch reply to a request naming the current epoch", ErrEvsReplyInvalid)
	}
	tokenPath, err := epochs.TokenPathIn(current)
	if err != nil {
		return nil, nil, err
	}
	replyPath, err := ParseEvsChangedTokenPath(reply.GetTokenPath())
	if err != nil || !replyPath.Equal(tokenPath) {
		return nil, nil, fmt.Errorf("%w: a reply for another path", ErrEvsEntryRefused)
	}
	if reply.GetEntryEpoch() != 0 {
		// a listed source the request named the path in; the root, which has no token, from any listed source
		listed := false
		for _, source := range evsSourceEpochs(head.Head.GetPathEpoch()) {
			listed = listed || source == reply.GetEntryEpoch()
		}
		if !listed || (len(tokenPath) != 0 && !epochs.Named[reply.GetEntryEpoch()]) {
			return nil, nil, fmt.Errorf("%w: an entry served from an epoch not listed or not named", ErrEvsEntryRefused)
		}
	}
	verified := &EvsVerifiedPath{TokenPath: tokenPath, EntryEpoch: reply.GetEntryEpoch()}
	switch {
	case reply.GetBase() != nil:
		if reply.GetVersion() != nil || reply.GetRemoval() != nil {
			return nil, nil, fmt.Errorf("%w: an overlay base beside a version", ErrEvsEntryRefused)
		}
		verified.Base = reply.GetBase()
		return verified, nil, nil
	case reply.GetRemoval() != nil:
		if reply.GetVersion() != nil {
			return nil, nil, fmt.Errorf("%w: a removal beside a version", ErrEvsEntryRefused)
		}
		if err := self.verifyRemoval(head, epochs, reply, verified); err != nil {
			return nil, nil, err
		}
	case reply.GetVersion() != nil:
		if err := self.verifyVersion(head, epochs, reply.GetVersion(), reply.GetStatement(), reply.GetProof(), verified); err != nil {
			return nil, nil, err
		}
		if verified.Entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
			if err := self.verifyDeltas(head, epochs, reply, verified); err != nil {
				return nil, nil, err
			}
		}
	case len(reply.GetStatement()) != 0 && len(reply.GetNames().GetNames()) == 0 && len(reply.GetDeltas()) == 0 &&
		len(reply.GetDeltaProofs()) == 0 && len(reply.GetProof()) == 0:
		// the statement alone, of a version or removal evs could not place: its epoch is the reader's to name
		statement, err := self.VerifyStatement(reply.GetStatement(), head.RepoId, head.RefId)
		if err != nil {
			return nil, nil, err
		}
		verified.StatementAlone = statement
		return verified, nil, nil
	case len(reply.GetNames().GetNames()) != 0 || len(reply.GetDeltas()) != 0 || len(reply.GetDeltaProofs()) != 0 ||
		len(reply.GetStatement()) != 0 || len(reply.GetProof()) != 0:
		return nil, nil, fmt.Errorf("%w: a reply with no version, removal or base beside what only those carry", ErrEvsEntryRefused)
	default:
		// a path never written: no walked statement may change it (below); before the walk it is evs's word, which a
		// writer's push meets at evs's own CAS (§11.8's 5g) and which a read record of a version refutes (evs_read.go)
		verified.Absent = true
	}
	if epochs.History {
		return verified, nil, nil
	}
	// a directory's own later writes are its deltas, each of which the walk must account for
	deltaVersions := map[uint64]bool{}
	for _, delta := range verified.Deltas {
		deltaVersions[delta.CommitVersion] = true
	}
	more, err := self.verifyUnchangedSince(head, epochs, verified.CommitVersion, reply.GetAbsences(), deltaVersions, verified.Absent)
	if err != nil {
		return nil, nil, err
	}
	return verified, more, nil
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
		// the path's own change first; else, where a prefix may stand for it, the removal of a prefix holding it, never
		// a prefix's delta, which a removal below the root carries beside it
		var prefixRemoval *EvsCheckedChange
		for _, change := range statement.Changes {
			if change.TokenPath.Equal(tokenPath) {
				return change.Change, change.TokenPath, nil
			}
			if prefixOk && prefixRemoval == nil && tokenPath.HasPrefix(change.TokenPath) && !change.WritesEntry() {
				prefixRemoval = change
			}
		}
		if prefixRemoval != nil {
			return prefixRemoval.Change, prefixRemoval.TokenPath, nil
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

// The path's token path in a statement's own epoch, which the reader derives.
func evsTokenPathOfStatement(epochs *EvsPathEpochs, statement *EvsStatement) (EvsTokenPath, uint64, error) {
	epoch := max(1, statement.Push.GetPathEpoch())
	tokenPath, err := epochs.TokenPathIn(epoch)
	return tokenPath, epoch, err
}

// Checks a version: its statement, its entry hash to that statement's change of exactly the path's token path in the
// statement's epoch, its push and base, format 1's shape, and the refs table over the change with its entry, which a
// creates-only stream's write on a base needs (VerifyPayloadRefRules).
func (self *EvsVerifier) verifyVersion(head *EvsVerifiedHead, epochs *EvsPathEpochs, version *protocol.EvsIndexVersion, sent []byte, proofs []*protocol.EvsMerkleProof, verified *EvsVerifiedPath) error {
	if version.GetElided() || len(version.GetEntryVersion()) == 0 {
		return fmt.Errorf("%w: an elided version", ErrEvsEntryRefused)
	}
	statement, err := self.statementAt(head, version.GetCommitVersion(), version.GetPushId(), sent)
	if err != nil {
		return err
	}
	tokenPath, epoch, err := evsTokenPathOfStatement(epochs, statement)
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
	// the refs table with this change's entry at hand, which the statement read alone lacked: on a creates-only stream
	// a write on a base is a directory's add-only delta or nothing (QD-722)
	held := &EvsCheckedChange{Change: change, TokenPath: tokenPath, EntryVersion: version.GetEntryVersion()}
	if err := self.VerifyPayloadRefRules(statement, head.RepoId, head.RefId, []*EvsCheckedChange{held}, nil); err != nil {
		self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmTamper, "", evsSignerOf(statement.Bytes))
		return err
	}
	verified.EntryBytes = version.GetEntryVersion()
	verified.Entry = entry
	verified.Statement = statement
	verified.CommitVersion = version.GetCommitVersion()
	verified.Floor = evsLowerFloor(verified.Floor, epoch)
	return nil
}

// Checks a removal: its statement removes the path's token path in its epoch, or a prefix holding it, at the
// marker's versions.
func (self *EvsVerifier) verifyRemoval(head *EvsVerifiedHead, epochs *EvsPathEpochs, reply *protocol.EvsReadPathReply, verified *EvsVerifiedPath) error {
	removal := reply.GetRemoval()
	statement, err := self.statementAt(head, removal.GetRemovalVersion(), removal.GetPushId(), reply.GetStatement())
	if err != nil {
		return err
	}
	tokenPath, epoch, err := evsTokenPathOfStatement(epochs, statement)
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
	if changedPath.Equal(tokenPath) {
		// a prefix's removal names the prefix's token, not the path's
		verified.Floor = evsLowerFloor(verified.Floor, epoch)
	}
	return nil
}

// Checks a directory's deltas after its folded table: each a version of the directory, in version order, after the
// table's names_through, verified as a version is under the directory's token path in its own statement's epoch.
// The table itself is evs's fold, whose names List checks against their tokens.
//
// A delta that is the served version, which evs lists again while the table holds nothing folded, was verified with
// that version's proof. Any other walked delta is checked against its own statement's change: an inline list by the
// list, one under changes_root by the delta's entry of delta_proofs, one a delta in order (QD-681). A reply carries
// either no delta proofs, which stands only where every walked delta's list is inline, or one a delta; a rooted
// statement's delta with no proof fails closed rather than take the delta on evs's word.
func (self *EvsVerifier) verifyDeltas(head *EvsVerifiedHead, epochs *EvsPathEpochs, reply *protocol.EvsReadPathReply, verified *EvsVerifiedPath) error {
	verified.Names = reply.GetNames()
	verified.NamesThrough = reply.GetNamesThrough()
	deltaProofs := reply.GetDeltaProofs()
	if len(deltaProofs) != 0 && len(deltaProofs) != len(reply.GetDeltas()) {
		return fmt.Errorf("%w: %d delta proofs for %d deltas", ErrEvsEntryRefused, len(deltaProofs), len(reply.GetDeltas()))
	}
	last := reply.GetNamesThrough()
	for i, delta := range reply.GetDeltas() {
		if delta.GetCommitVersion() <= last {
			return fmt.Errorf("%w: deltas out of version order", ErrEvsEntryRefused)
		}
		last = delta.GetCommitVersion()
		deltaPath := &EvsVerifiedPath{TokenPath: verified.TokenPath}
		if delta.GetCommitVersion() == verified.CommitVersion && !delta.GetElided() && bytes.Equal(delta.GetEntryVersion(), verified.EntryBytes) {
			deltaPath.EntryBytes, deltaPath.Entry, deltaPath.CommitVersion = verified.EntryBytes, verified.Entry, verified.CommitVersion
			deltaPath.Statement, deltaPath.Floor = verified.Statement, verified.Floor
			verified.Deltas = append(verified.Deltas, deltaPath)
			continue
		}
		if _, walked := head.StatementAt(delta.GetCommitVersion()); !walked {
			// a delta at or below the read's pin carries no statement: what it adds is evs's word, as a never-read
			// path's version is (Q-EVS-6), and its names are still checked against their tokens
			entry := &protocol.EvsEntryVersion{}
			if delta.GetElided() || proto.Unmarshal(delta.GetEntryVersion(), entry) != nil ||
				entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) || head.Version < delta.GetCommitVersion() {
				return fmt.Errorf("%w: a delta that is not a directory's", ErrEvsEntryRefused)
			}
			deltaPath.EntryBytes, deltaPath.Entry, deltaPath.CommitVersion = delta.GetEntryVersion(), entry, delta.GetCommitVersion()
			verified.Deltas = append(verified.Deltas, deltaPath)
			continue
		}
		var proofs []*protocol.EvsMerkleProof
		if i < len(deltaProofs) {
			proofs = deltaProofs[i].GetProof()
		}
		if err := self.verifyVersion(head, epochs, delta, nil, proofs, deltaPath); err != nil {
			return err
		}
		if deltaPath.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
			return fmt.Errorf("%w: a delta that is not a directory's", ErrEvsEntryRefused)
		}
		verified.Deltas = append(verified.Deltas, deltaPath)
	}
	return nil
}

// Checks that no walked statement after version since changes the path or a prefix holding it, each under the path's
// token path in its own epoch: an inline list by its changes, a change list under changes_root by the adjacent-leaf
// proofs evs sent for each path its covering prefixes reach (EvsAbsencePaths). A directory's own later writes are its
// deltas, at deltaVersions, already verified; any other is a delta evs left out. A rooted statement with no proof, of
// an epoch the request did not name, adds that epoch to the epochs answered: the reader asks once more naming it.
// A rooted statement that changed a prefix of the path by a delta, which does not end the path, has no adjacent
// leaves around that prefix: its absence carries the delta's inclusion proof in present (QD-681), taken only for a
// strict prefix whose change writes an entry, as an inline list's own delta is, and refused for the path itself or a
// removal, either of which ends what the reply served.
func (self *EvsVerifier) verifyUnchangedSince(head *EvsVerifiedHead, epochs *EvsPathEpochs, since uint64, absences []*protocol.EvsAbsenceProof, deltaVersions map[uint64]bool, absent bool) ([]uint64, error) {
	more := []uint64{}
	for _, walked := range head.Statements {
		if walked.Version <= max(since, epochs.Since) || deltaVersions[walked.Version] {
			continue
		}
		push := walked.Statement.Push
		tokenPath, epoch, err := evsTokenPathOfStatement(epochs, walked.Statement)
		if err != nil {
			return nil, err
		}
		if len(push.GetChangesRoot()) == 0 {
			for _, change := range walked.Statement.Changes {
				// the path itself, or a prefix's removal, which ends every path below it; a prefix's delta does not
				// change the path (§11.7's newest row)
				// a path served absent stays absent through a prefix's removal, which only a standing path contradicts
				removesPrefix := tokenPath.HasPrefix(change.TokenPath) && len(change.Change.GetEntrySha256()) == 0 && !absent
				if change.TokenPath.Equal(tokenPath) || removesPrefix {
					self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
					return nil, fmt.Errorf("%w: a later statement changes the path, served as unchanged", ErrEvsEntryRefused)
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
				if len(absence.GetPresent()) != 0 {
					if err := evsVerifyPrefixDelta(push, tokenPath, absentPath, absence); err != nil {
						self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
						return nil, err
					}
					proven = true
					break
				}
				if err := EvsVerifyChangeAbsence(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), absentPath, absence); err != nil {
					self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
					return nil, fmt.Errorf("%w: %w", ErrEvsEntryRefused, err)
				}
				proven = true
				break
			}
			if proven {
				continue
			}
			if epochs.Named[epoch] {
				return nil, fmt.Errorf("%w: a later statement's change list with no proof the path is absent", ErrEvsEntryRefused)
			}
			if !slices.Contains(more, epoch) {
				more = append(more, epoch)
			}
		}
	}
	return more, nil
}

// Checks an absence's present (QD-681): the inclusion proof, to push's changes_root, of the change push makes to
// prefix, which must be a strict prefix of tokenPath and whose change must write an entry, a directory's delta. The
// path's own change, a removal, a proof of another path, or one beside below or above is refused.
func evsVerifyPrefixDelta(push *protocol.EvsPush, tokenPath EvsTokenPath, prefix EvsTokenPath, absence *protocol.EvsAbsenceProof) error {
	if len(absence.GetBelow()) != 0 || len(absence.GetAbove()) != 0 {
		return fmt.Errorf("%w: a present change beside the leaves around it", ErrEvsEntryRefused)
	}
	if len(tokenPath) <= len(prefix) || !tokenPath.HasPrefix(prefix) {
		return fmt.Errorf("%w: a later statement changes the path, served as unchanged", ErrEvsEntryRefused)
	}
	change, changedPath, err := EvsVerifyChangeInclusion(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), absence.GetPresent())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEvsEntryRefused, err)
	}
	if !changedPath.Equal(prefix) {
		return fmt.Errorf("%w: a proof of another path's change", ErrEvsEntryRefused)
	}
	if len(change.GetEntrySha256()) == 0 {
		return fmt.Errorf("%w: a later statement removes a prefix of the path, served as unchanged", ErrEvsEntryRefused)
	}
	return nil
}
