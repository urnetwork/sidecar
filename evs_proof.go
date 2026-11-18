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
// A path served holding no version, never written or removed (its own removal or a prefix's), stays so through a
// later removal of a prefix holding it, which adds no removal of its own (§11.7's removal row): evs answers such a
// path's removal at r though the walk holds a prefix's removal after r, and only a walked change of the path itself
// contradicts that reply (QD-978). A prefix's removal under changes_root is shown by no proof (§11.9's reply row), and
// nothing a statement does to a strict prefix makes such a path stand, so its strict prefixes need none: a proof evs
// sends for one is still checked, a present of a prefix's removal taken, and the path itself still needs its own.
//
// A path served plain absent, with no version, removal or base, is held to the walk's order rather than to its
// silence (QD-979): once a collection took a removal's marker and the window paged the removal out, evs names nothing
// of it, and a reader pinned below it walks the removal's statement. The reply agrees with the walk when the walk's
// newest change of the path, or of a prefix holding it, is a removal; only a walked write of the path with no walked
// removal of it or of a prefix after it refutes the reply, with the tamper alarm. The proof of absence is then the
// walk's signed statements: an inline list's own changes, or under changes_root a present of the path's own change,
// which the reader takes for a path served absent alone, a write as well as a removal, since the walk's order judges
// it. evs sends that present for such a path, and a strict prefix's removal's, in each rooted statement's absence
// (QD-1043); a rooted statement that changed the path with no present beside it leaves the reply with no proof, which
// is refused with no alarm, as a reply evs sent before QD-1043 is. A prefix's removal counts only where the reader can
// show it: inline, or by a present; a walked write followed by a rooted statement reaching a strict prefix that evs
// showed by nothing is refused, but with no alarm, since that prefix's removal is neither shown nor ruled out. The
// walked removal the reply agrees with is kept on the verified path (WalkedRemoval), which a path this device read a
// version of needs to read as absent (evs_epoch_read.go's finishRead), unless a gap head's re-pin passed its record's
// pin (QD-1041). A creation on such a reply takes max(b, m) + 1 with no m, b being past any collected removal (§11.8),
// so the planner is unchanged.
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
// caller reads the rest (EVS1-M2-39), to a reader of format 1 alone (EvsClient.format2Reader). A reader of format 2
// takes versioning 1 and 2 and kind-5 and staged locators, each version judged where it sits (evs_verify_format2.go;
// EVS2-M10-17), `collected` for a version's content, and a drop's states by the drop's own checks
// (evs_drop_verify.go; EVS2-M10-22).
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
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
	// The statement's change that wrote the version or removed the path, and that change's own token path in the
	// statement's epoch: the path's, or for a removal the path's or a directory's above it, which is what a prefix
	// rule judges (DESIGN-DETAILS 16.2.4).
	Change     *protocol.EvsChange
	ChangePath EvsTokenPath
	// A removal that stands, from its marker or the window, and the statement that made it.
	Removal *protocol.EvsRemovalMarker
	// An overlay's path it holds no version of: the base ref and version to read instead (§11.7).
	Base *protocol.EvsOverlay
	// A path the ref never wrote, or none evs holds a version or removal of, whose walk's newest change, if any, is a
	// removal of it or of a prefix holding it (QD-979).
	Absent bool
	// For a path served absent: that removal, the walk's newest change of the path, when the walk holds one; nil for
	// a walk that changes neither the path nor a prefix holding it in a way the reader can show. The prefix judge does
	// not rule on it yet: QD-1042's reading (evs_prefix.go's effective takes it as v) waits with the prefix rules,
	// which QD-1032 defers.
	WalkedRemoval *EvsWalkedRemoval
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
	// Format 2: evs answered `collected` for the content of a versionless version asked for by number (§11.9's
	// collected row), its entry version and statement verified as any version's. evs's word, unsigned: whether the
	// version is replaced is its reader's to learn from a fresh head read (evs_read_versionless.go). For a path's
	// newest version, or a version that keeps its content, VerifyPath alarms and refuses instead.
	Collected bool
	// Format 2: evs served a version its reader ignores where it sits (evs_verify_format2.go's ignored rows), which
	// alarmed. The path reads as Absent.
	Ignored bool
	// Format 2: the version is listed by a DROP that passed this reader's checks (evs_drop_verify.go): drop_pending or
	// dropped by this device's clock; nil for every other version, one whose drop failed them among them.
	Drop *EvsDropState
}

// A removal of a path, or of a prefix holding it, that the reader's own walk holds and evs no longer names: the
// statement, the ref version it committed at, and its change with that change's token path in the statement's epoch,
// the path's or a prefix's (QD-979).
type EvsWalkedRemoval struct {
	CommitVersion uint64
	Statement     *EvsStatement
	Change        *protocol.EvsChange
	ChangePath    EvsTokenPath
}

// What a reply served of a path, which each walked statement after it is held to (verifyUnchangedSince).
type evsServedAs int

const (
	// A version: the path's own later change, or a prefix's later removal, contradicts it.
	evsServedStanding evsServedAs = iota
	// Its own removal or a prefix's: a prefix's later removal leaves it as served, and the path's own later change
	// contradicts it (QD-978).
	evsServedRemoved
	// No version, removal or base: the walk's newest change of the path, if any, must be a removal (QD-979).
	evsServedAbsent
)

// A path as the verifier checks it: its token path in any epoch, derived by the reader from its name, never taken from
// a reply (DESIGN-DETAILS 9.2.4's reader), and the epochs the request named it in.
type EvsPathEpochs struct {
	TokenPathIn func(epoch uint64) (EvsTokenPath, error)
	Named       map[uint64]bool
	// The path's raw names as the reader asked for it, nil for a path it names by a token alone (a deposit's or the
	// erasure ref's entry), and the reserved ref it sits on: what format 2's ignored rows judge (evs_verify_format2.go).
	Names    [][]byte
	Reserved EvsReservedRef
	// An older version asked for by number: history, not a rollback, so the walk after it is not checked (§11.9's
	// "older ones on request").
	History bool
	// That version's number, 0 for the newest: what a drop's checks judge (DESIGN-DETAILS 10.2.3's H3).
	Version uint64
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
	dropState := reply.GetState() == protocol.EvsReadPathState_EVS_READ_PATH_DROP_PENDING ||
		reply.GetState() == protocol.EvsReadPathState_EVS_READ_PATH_DROPPED
	if reader := self.client.format2Reader(); dropState && reader != nil {
		// a version a DROP lists, judged by the drop's own checks (evs_drop_verify.go; EVS2-M10-22)
		verified, err := reader.verifyDropPath(self, head, epochs, reply)
		return verified, nil, err
	}
	collected := reply.GetState() == protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED && self.client.format2Reader() != nil
	if (reply.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED && !collected) || len(reply.GetDropId()) != 0 ||
		reply.GetNotBeforeMs() != 0 || reply.GetDropVersion() != 0 || len(reply.GetDropStatement()) != 0 || len(reply.GetDropBody()) != 0 {
		// a drop's states are EVS2-M10-22's, and every state a format-1 reader's
		return nil, nil, fmt.Errorf("%w: a format-2 read state", ErrEvsFormatUnsupported)
	}
	if collected && reply.GetVersion() == nil {
		// collected speaks for a version's content: its signed entry version and statement come with it (§11.9)
		return nil, nil, fmt.Errorf("%w: collected with no version", ErrEvsEntryRefused)
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
	verified := &EvsVerifiedPath{TokenPath: tokenPath, EntryEpoch: reply.GetEntryEpoch(), Collected: collected}
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
			if errors.Is(err, ErrEvsVersionIgnored) {
				// format 2's ignored rows: the version alarmed, and its path reads as holding none
				return &EvsVerifiedPath{TokenPath: tokenPath, Absent: true, Ignored: true}, nil, nil
			}
			return nil, nil, err
		}
		if collected && (!epochs.History || verified.Entry.GetVersioning() == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)) {
			// only a replaced versionless version's content is collected, and a head read answers a path's newest
			// version, whose content evs holds (I-EVS-1): for any other it is a missing segment (§11.9's collected row)
			self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmMissingSegment, "", nil)
			return nil, nil, fmt.Errorf("%w: collected answered for a version whose content is kept", ErrEvsObjectMissing)
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
		// a path never written, or one whose removal evs no longer names: the walk's newest change of it, if any, must
		// be a removal (below, QD-979); before the walk it is evs's word, which a writer's push meets at evs's own CAS
		// (§11.8's 5g) and which a read record of a version refutes unless the walk holds the removal (finishRead)
		verified.Absent = true
	}
	if epochs.History {
		return verified, nil, nil
	}
	more, err := self.verifyUnchangedSince(head, epochs, reply.GetAbsences(), verified)
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
	reader := self.client.format2Reader()
	if _, err := checkEvsEntryVersionOf(version.GetEntryVersion(), statement.Push, reader != nil); err != nil {
		return err
	}
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(version.GetEntryVersion(), entry); err != nil {
		return fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
	}
	if reader != nil {
		// a format-2 reader judges every version where it sits: a versioned file under an index root is as wrong as a
		// versionless one outside it (EVS2-M10-17)
		if err := reader.verifyVersion(self, head.RepoId, head.RefId, statement, epochs.Names, epochs.Reserved, entry); err != nil {
			return err
		}
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
	verified.Change, verified.ChangePath = change, tokenPath
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
	verified.Change, verified.ChangePath = change, changedPath
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
			deltaPath.Change, deltaPath.ChangePath = verified.Change, verified.ChangePath
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

// Checks each walked statement after the version the reply served, and after the path's own pin, against what it
// served, each under the path's token path in its own epoch: an inline list by its changes, a change list under
// changes_root by the adjacent-leaf proofs evs sent for each path its covering prefixes reach (EvsAbsencePaths). A
// directory's own later writes are its deltas, already verified; any other is a delta evs left out. A rooted statement
// with no proof, of an epoch the request did not name, adds that epoch to the epochs answered: the reader asks once
// more naming it. A rooted statement that changed a prefix of the path by a delta, which does not end the path, has no
// adjacent leaves around that prefix: its absence carries the delta's inclusion proof in present (QD-681), taken for
// a strict prefix whose change writes an entry, as an inline list's own delta is.
//
// What a statement may do to the path turns on what the reply served (evsServedAs). A version: no change of the path
// and no removal of a prefix holding it. A removal: a prefix's removal leaves it so, and a strict prefix needs no proof
// at all, since evs shows a prefix's removal by none and nothing a statement does to a strict prefix makes the path
// stand (QD-978; see the file header); the path's own change refutes it. Absent: as a removal, and the path's own
// change, inline or in a present, is taken in the walk's order, the reply refuted only where a write of the path is
// the newest change the walk shows, no removal of it or of a prefix after it (QD-979): with the tamper alarm where no
// later statement could have removed a prefix unseen, and with none where a later rooted statement reached a strict
// prefix that evs showed by nothing, its removal neither shown nor ruled out. Its removal, the newest change where the
// walk ends on one, goes to verified.WalkedRemoval, a removal of the path's own token path lowering the floor (E1).
// The path's own absence is needed in every case where the statement did not change it.
func (self *EvsVerifier) verifyUnchangedSince(head *EvsVerifiedHead, epochs *EvsPathEpochs, absences []*protocol.EvsAbsenceProof, verified *EvsVerifiedPath) ([]uint64, error) {
	served := evsServedStanding
	switch {
	case verified.Absent:
		served = evsServedAbsent
	case verified.Removal != nil:
		served = evsServedRemoved
	}
	// a directory's own later writes are its deltas, each of which the walk must account for
	deltaVersions := map[uint64]bool{}
	for _, delta := range verified.Deltas {
		deltaVersions[delta.CommitVersion] = true
	}
	tampered := func(err error) ([]uint64, error) {
		self.client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
		return nil, err
	}
	more := []uint64{}
	// for a path served absent: the walk's newest write of the path, where no removal came after it, with whether a
	// later rooted statement reached a strict prefix of it that evs showed by nothing, and so may have removed it; and
	// the walk's newest removal of the path or a prefix, where no write came after it
	var written *EvsVerifiedStatement
	writtenUnshown := false
	var removal *EvsWalkedRemoval
	removalEpoch := uint64(0)
	for _, walked := range head.Statements {
		if walked.Version <= max(verified.CommitVersion, epochs.Since) || deltaVersions[walked.Version] {
			continue
		}
		push := walked.Statement.Push
		tokenPath, epoch, err := evsTokenPathOfStatement(epochs, walked.Statement)
		if err != nil {
			return nil, err
		}
		// what the statement does to the path, as far as the reader can show it: the path's own change, and the
		// removal of a strict prefix holding it, which ends every path below it; a prefix's delta does not change the
		// path (§11.7's newest row)
		var own, prefixRemoval *EvsCheckedChange
		unshown := false
		if len(push.GetChangesRoot()) == 0 {
			for _, change := range walked.Statement.Changes {
				switch {
				case change.TokenPath.Equal(tokenPath):
					own = change
				case prefixRemoval == nil && tokenPath.HasPrefix(change.TokenPath) && !change.WritesEntry():
					prefixRemoval = change
				}
			}
		} else {
			for _, absentPath := range EvsAbsencePaths(walked.Statement.ChangedPrefixes, tokenPath) {
				absence := evsAbsenceAt(absences, walked.Version, absentPath)
				switch {
				case absence != nil && len(absence.GetPresent()) != 0:
					change, err := evsVerifyPresent(push, tokenPath, absentPath, absence, served)
					if err != nil {
						return tampered(err)
					}
					shown := &EvsCheckedChange{Change: change, TokenPath: absentPath}
					switch {
					case len(absentPath) == len(tokenPath):
						own = shown
					case prefixRemoval == nil && !shown.WritesEntry():
						prefixRemoval = shown
					}
				case absence != nil:
					if err := EvsVerifyChangeAbsence(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), absentPath, absence); err != nil {
						return tampered(fmt.Errorf("%w: %w", ErrEvsEntryRefused, err))
					}
				case served != evsServedStanding && len(absentPath) < len(tokenPath):
					// a strict prefix of a path served holding no version needs no proof: whether the statement left it
					// alone, wrote it or removed it, which evs shows by nothing, the path stands no more than served,
					// and a removal it does not show is one the walk does not count
					unshown = true
				case epochs.Named[epoch]:
					return nil, fmt.Errorf("%w: a later statement's change list with no proof the path is absent", ErrEvsEntryRefused)
				case !slices.Contains(more, epoch):
					more = append(more, epoch)
				}
			}
		}
		switch {
		case own != nil && served != evsServedAbsent, prefixRemoval != nil && served == evsServedStanding:
			// the path's own change ends a version or removal served, and a prefix's removal a version
			return tampered(fmt.Errorf("%w: a later statement changes the path, served as unchanged", ErrEvsEntryRefused))
		case own != nil && own.WritesEntry():
			written, writtenUnshown, removal = walked, false, nil
		case own != nil:
			written, removal, removalEpoch = nil, &EvsWalkedRemoval{CommitVersion: walked.Version, Statement: walked.Statement, Change: own.Change, ChangePath: own.TokenPath}, epoch
		case prefixRemoval != nil:
			written, removal, removalEpoch = nil, &EvsWalkedRemoval{CommitVersion: walked.Version, Statement: walked.Statement, Change: prefixRemoval.Change, ChangePath: prefixRemoval.TokenPath}, 0
		case unshown && written != nil:
			writtenUnshown = true
		}
	}
	if written != nil {
		switch {
		case 0 < len(more):
			// a statement after the write whose proof the next ask names may show its removal
			return more, nil
		case writtenUnshown:
			// a prefix's removal after the write is neither shown nor ruled out, evs having sent no present of it
			// (QD-1043): refused as a reply with no proof is, with no alarm
			return nil, fmt.Errorf("%w: a later statement's change list with no proof whether it removed a prefix of the path", ErrEvsEntryRefused)
		}
		return tampered(fmt.Errorf("%w: a later statement writes the path, served as absent", ErrEvsEntryRefused))
	}
	if removal != nil && served == evsServedAbsent {
		verified.WalkedRemoval = removal
		if removalEpoch != 0 {
			// E1: a verified removal of the path names its token path in the statement's epoch
			verified.Floor = evsLowerFloor(verified.Floor, removalEpoch)
		}
	}
	return more, nil
}

// The first absence evs sent for path at version, nil for none.
func evsAbsenceAt(absences []*protocol.EvsAbsenceProof, version uint64, path EvsTokenPath) *protocol.EvsAbsenceProof {
	for _, absence := range absences {
		absencePath, err := ParseEvsTokenPath(absence.GetTokenPath())
		if absence.GetVersion() == version && err == nil && absencePath.Equal(path) {
			return absence
		}
	}
	return nil
}

// Checks an absence's present (QD-681): the inclusion proof, to push's changes_root, of the change push makes to
// absentPath, with below and above empty, and what that change may be beside what the reply served: a strict prefix's
// delta for any reply; a strict prefix's removal for a path served holding no version, which leaves it as served
// (QD-978); and the path's own change, a write or a removal, for a path served absent alone, which the walk's order
// then judges (QD-979). The proven change, or the refusal: the path's own change beside a version or a removal
// served, a removal of a prefix of a standing path, a proof of another path's change, a path that is neither the one
// read nor a prefix of it, or a present beside below or above.
func evsVerifyPresent(push *protocol.EvsPush, tokenPath EvsTokenPath, absentPath EvsTokenPath, absence *protocol.EvsAbsenceProof, served evsServedAs) (*protocol.EvsChange, error) {
	if len(absence.GetBelow()) != 0 || len(absence.GetAbove()) != 0 {
		return nil, fmt.Errorf("%w: a present change beside the leaves around it", ErrEvsEntryRefused)
	}
	if !tokenPath.HasPrefix(absentPath) || (len(tokenPath) == len(absentPath) && served != evsServedAbsent) {
		return nil, fmt.Errorf("%w: a later statement changes the path, served as unchanged", ErrEvsEntryRefused)
	}
	change, changedPath, err := EvsVerifyChangeInclusion(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), absence.GetPresent())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsEntryRefused, err)
	}
	if !changedPath.Equal(absentPath) {
		return nil, fmt.Errorf("%w: a proof of another path's change", ErrEvsEntryRefused)
	}
	if len(change.GetEntrySha256()) == 0 && served == evsServedStanding {
		return nil, fmt.Errorf("%w: a later statement removes a prefix of the path, served as unchanged", ErrEvsEntryRefused)
	}
	return change, nil
}
