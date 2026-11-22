//go:build !ios_extension

// A head reader's check of a version evs answers in a drop's state (§11.7's states row, §11.9's reply and trusts rows;
// D-EVS-63, D-EVS-65, I-4, FI-27, FS-89, FS-95; DESIGN-DETAILS 10.2.3 and 10.7's note; EVS2-M10-22), on the name and
// version this device asked for, neither of which the server chooses.
//
//	H0  a drop state for a path's newest version is refused as tampering: a drop never takes the head
//	H1  the DROP's statement: its signature and writer as any statement's; flags exactly 256; the ref read; its signer a
//	    repo admin at its own auth pin, in an owner-bound repo a consented device of the owner, and no lock standing
//	    there (AclState.MayDrop and RepoLockAllowsDrop over that state's rows); above the reader's pin it must be the
//	    statement the chain check placed at drop_version, below it it is taken as any statement below a pin
//	H2  the body: within DropMaxBodyByteCount on its length, SHA-256 equal to drop_sha256, the payload's shape rules,
//	    action 1, not_before_ms one of its two values (NewEvsDropLists); a body this device holds for the drop is the
//	    one it checked before
//	H3  the version's statement as any version's: its change names tp(X, e(V)), the reader's own token for X in the
//	    statement's epoch; where evs withheld the entry version (a dropped version whose chain names an inline
//	    record), the change's inclusion alone, a write, on base k - 1 or a creation
//	H4  a path of the body whose lineage holds (e(V), tp(X, e(V)))
//	H5  every entry (e, t) of that lineage has t = tp(X, e): the lineage is this name's. An entry another name's, or in
//	    an epoch this device holds no key for, makes the DROP invalid
//	H6  k below the lineage's through_version, and the version's statement's base below drop_version where placed
//	H7  no cancel of the drop this device holds: a kept body of action 2 naming its drop_id at its version
//	verdict
//	    H1 or H2 fails       the reply is refused with a tamper alarm: nothing shown as dropped
//	    H5 fails             history_drop in state invalid, naming the signer; nothing dropped for this reader, and a
//	                         withheld entry version, or a 404 of the content, alarms as a missing segment
//	    H3 fails             as any version whose statement does not name its path
//	    H4, H6 or H7 fails   evs's state ignored: the version is read as any version
//	    all hold             EvsVerifiedPath.Drop: drop_pending before not_before_ms by this device's clock, dropped
//	                         from then on (evs_drop_state.go); history_drop raised once for each state it reads
//
// A body is checked once and kept sealed on storage (evs_drop_state.go), so a later read names it in held_drops and
// evs sends it no more. H7 sees only cancels whose bodies this device holds, which evs's read replies never carry:
// a cancel evs hides is evs's word against nothing, and a lying server can at most hide content (§11.9's trusts
// row). A replaying reader's exactness check, from its own history with no list fetched, is EvsCheckDropExact.
//
// On every leg but ios_extension. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// A DROP that fails a reader's checks of its lineage, its list or its boundary: history_drop in state invalid.
var ErrEvsDropInvalid = errors.New("evs: a DROP that fails this reader's checks")

// One checked DROP as a read found it.
type evsReadDrop struct {
	statement *EvsStatement
	// its ref version, 0 where this device could not place it
	version uint64
	lists   *EvsDropLists
	dropId  Id
	signer  Id
}

// The client's store of checked bodies, made on first use.
func (self *EvsClient) dropBodies() *evsDropBodies {
	drops := self.dropClient()
	drops.stateLock.Lock()
	defer drops.stateLock.Unlock()
	if drops.bodies == nil {
		drops.bodies = newEvsDropBodies(self.args.Store, self.settings.DropBodyKeepByteCount)
	}
	return drops.bodies
}

// Raises history_drop for a drop's state once: a later read of the same state raises nothing.
func (self *EvsClient) raiseHistoryDropOnce(drop *SidecarHistoryDrop) {
	drops := self.dropClient()
	key := drop.RepoId.String() + "/" + drop.RefId.String() + "/" + drop.DropId.String()
	raise := func() bool {
		drops.stateLock.Lock()
		defer drops.stateLock.Unlock()
		if drops.raised == nil {
			drops.raised = map[string]SidecarDropState{}
		}
		if drops.raised[key] == drop.State {
			return false
		}
		drops.raised[key] = drop.State
		return true
	}()
	if raise {
		if err := self.raiseHistoryDrop(drop); err != nil {
			self.log.Warningf("[evs]history_drop: %s", err)
		}
	}
}

// The ref versions of the bodies this device keeps for a ref, at most a request's held_drops.
func (self *evsFormat2Rules) heldDrops(client *EvsClient, repoId Id, refId Id) []uint64 {
	return client.dropBodies().heldVersions(repoId, refId, DefaultEvsFormatSettings().HeldDropMaxCount)
}

// A path's reply in a drop's state: see the file header.
func (self *evsFormat2Rules) verifyDropPath(verifier *EvsVerifier, head *EvsVerifiedHead, epochs *EvsPathEpochs, reply *protocol.EvsReadPathReply) (*EvsVerifiedPath, error) {
	client := verifier.client
	tamper := func(detail string) error {
		client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
		return fmt.Errorf("%w: %s", ErrEvsEntryRefused, detail)
	}
	if !epochs.History {
		// H0
		return nil, tamper("a drop state for a path's newest version")
	}
	if reply.GetVersion() == nil || reply.GetRemoval() != nil || reply.GetBase() != nil || len(reply.GetDropId()) != 16 {
		return nil, fmt.Errorf("%w: a drop state with no version or no drop", ErrEvsEntryRefused)
	}
	current := evsCurrentEpoch(head.Head.GetPathEpoch())
	tokenPath, err := epochs.TokenPathIn(current)
	if err != nil {
		return nil, err
	}
	replyPath, err := ParseEvsChangedTokenPath(reply.GetTokenPath())
	if err != nil || !replyPath.Equal(tokenPath) {
		return nil, fmt.Errorf("%w: a reply for another path", ErrEvsEntryRefused)
	}
	drop, err := self.dropOf(verifier, head, reply)
	if err != nil {
		return nil, err
	}
	// H3: the version as any version's
	verified := &EvsVerifiedPath{TokenPath: tokenPath, EntryEpoch: reply.GetEntryEpoch()}
	version := reply.GetVersion()
	withheld := len(version.GetEntryVersion()) == 0 && !version.GetElided()
	var statement *EvsStatement
	k := epochs.Version
	if withheld {
		if reply.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_DROPPED || k == 0 {
			return nil, fmt.Errorf("%w: an entry version withheld for a version not dropped", ErrEvsEntryRefused)
		}
		if statement, err = verifier.statementAt(head, version.GetCommitVersion(), version.GetPushId(), reply.GetStatement()); err != nil {
			return nil, err
		}
		versionPath, _, err := evsTokenPathOfStatement(epochs, statement)
		if err != nil {
			return nil, err
		}
		change, changedPath, err := evsChangeOf(statement, versionPath, reply.GetProof(), false)
		if err != nil {
			return nil, err
		}
		if !changedPath.Equal(versionPath) || len(change.GetEntrySha256()) == 0 ||
			(change.GetBaseEntryVersion() != k-1 && change.GetBaseEntryVersion() != 0) {
			return nil, fmt.Errorf("%w: a withheld version's change is not the path's version %d", ErrEvsEntryRefused, k)
		}
		verified.Statement, verified.CommitVersion, verified.Change = statement, version.GetCommitVersion(), change
		// the entry stands for its number and push alone, which History lists; nothing of it is read (Drop.Withheld)
		verified.Entry = &protocol.EvsEntryVersion{
			Version: k, PushId: version.GetPushId(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE),
		}
	} else {
		if err := verifier.verifyVersion(head, epochs, version, reply.GetStatement(), reply.GetProof(), verified); err != nil {
			return nil, err
		}
		statement, k = verified.Statement, verified.Entry.GetVersion()
	}
	ignored := func() (*EvsVerifiedPath, error) {
		if withheld {
			// evs hid the entry of a version no valid drop covers: as a missing segment
			client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmMissingSegment, "", nil)
			return nil, fmt.Errorf("%w: an entry version withheld under no drop that stands", ErrEvsObjectMissing)
		}
		return verified, nil
	}
	epoch := max(1, statement.Push.GetPathEpoch())
	versionPath, err := epochs.TokenPathIn(epoch)
	if err != nil {
		return nil, err
	}
	// H4: the lineage holding the version's own token path in its epoch
	history := drop.lists.History()
	var listing *protocol.EvsDropPath
	for _, path := range history.GetPaths() {
		for _, entry := range path.GetLineage() {
			if entry.GetEpoch() == epoch && bytes.Equal(bytes.Join(entry.GetTokenPath(), nil), versionPath.Bytes()) {
				listing = path
			}
		}
		if listing != nil {
			break
		}
	}
	if listing == nil {
		return ignored()
	}
	// H5: every entry of the lineage is this name's
	if !evsDropLineageNamed(listing, epochs.TokenPathIn) {
		signerId := drop.signer
		client.raiseHistoryDropOnce(&SidecarHistoryDrop{
			RepoId: head.RepoId, RefId: head.RefId, DropId: drop.dropId, State: SidecarDropInvalid,
			SignerSidecarId: &signerId, Path: string(bytes.Join(epochs.Names, []byte("/"))),
		})
		return ignored()
	}
	// H6 and H7
	if !evsDropListsVersion(listing, k, drop.version, statement.Push.GetBaseVersion()) || self.dropCancelled(client, head, drop) {
		return ignored()
	}
	notBefore := evsTime(history.GetNotBeforeMs())
	verified.Drop = &EvsDropState{
		DropId: drop.dropId, DropVersion: drop.version, SignerSidecarId: drop.signer, NotBefore: notBefore, Withheld: withheld,
	}
	state := SidecarDropPending
	if verified.Drop.Dropped(client.clock.Now()) {
		state = SidecarDropDone
	}
	signerId := drop.signer
	client.raiseHistoryDropOnce(&SidecarHistoryDrop{
		RepoId: head.RepoId, RefId: head.RefId, DropId: drop.dropId, State: state, SignerSidecarId: &signerId,
		Path: string(bytes.Join(epochs.Names, []byte("/"))), NotBefore: notBefore,
	})
	return verified, nil
}

// H5: whether every entry (e, t) of a lineage has t = tp(X, e), X the name tokenPathIn derives for; an epoch it holds
// no key for is not this name's.
func evsDropLineageNamed(listing *protocol.EvsDropPath, tokenPathIn func(epoch uint64) (EvsTokenPath, error)) bool {
	for _, entry := range listing.GetLineage() {
		named, err := tokenPathIn(entry.GetEpoch())
		if err != nil || !bytes.Equal(bytes.Join(entry.GetTokenPath(), nil), named.Bytes()) {
			return false
		}
	}
	return true
}

// H6: whether the lineage lists the path's version k, below through_version, whose statement's base is below the
// DROP's ref version where that is placed (dropVersion 0: unplaced).
func evsDropListsVersion(listing *protocol.EvsDropPath, k uint64, dropVersion uint64, baseVersion uint64) bool {
	return k < listing.GetThroughVersion() && (dropVersion == 0 || baseVersion < dropVersion)
}

// The DROP a reply names, H1 and H2 checked, its body kept once checked.
func (self *evsFormat2Rules) dropOf(verifier *EvsVerifier, head *EvsVerifiedHead, reply *protocol.EvsReadPathReply) (*evsReadDrop, error) {
	client := verifier.client
	tamper := func(detail string) error {
		client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
		return fmt.Errorf("%w: %s", ErrEvsStatementRefused, detail)
	}
	dropId, err := IdFromBytes(reply.GetDropId())
	if err != nil {
		return nil, fmt.Errorf("%w: a drop id", ErrEvsEntryRefused)
	}
	bodies := client.dropBodies()
	body := reply.GetDropBody()
	version := reply.GetDropVersion()
	var heldStatement []byte
	held := false
	if len(body) == 0 {
		heldBody, heldVersion, statementBytes, ok, err := bodies.get(head.RepoId, head.RefId, dropId)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errEvsDropBodyMissing
		}
		body, held, heldStatement = heldBody, true, statementBytes
		if version == 0 {
			version = heldVersion
		}
	}
	// H1: the statement, placed by the chain check above the pin, else taken as any statement below it
	statementBytes := reply.GetDropStatement()
	if len(statementBytes) == 0 && version != 0 {
		if walked, ok := head.StatementAt(version); ok {
			statementBytes = walked.Statement.Bytes
		}
	}
	if len(statementBytes) == 0 && version == 0 {
		// a pending drop's statement the reply's walk holds: the walked DROP whose drop_sha256 is the body's
		digest := sha256.Sum256(body)
		for _, walked := range head.Statements {
			if bytes.Equal(walked.Statement.Push.GetDropSha256(), digest[:]) {
				statementBytes, version = walked.Statement.Bytes, walked.Version
			}
		}
	}
	if len(statementBytes) == 0 {
		statementBytes = heldStatement
	}
	if version == 0 {
		// a statement the walk holds is placed by it, whichever way it came
		for _, walked := range head.Statements {
			if bytes.Equal(walked.Statement.Bytes, statementBytes) {
				version = walked.Version
			}
		}
	}
	if len(statementBytes) == 0 {
		return nil, tamper("a drop state with no DROP statement")
	}
	statement, err := verifier.VerifyStatement(statementBytes, head.RepoId, head.RefId)
	if err != nil {
		return nil, err
	}
	if head.FromVersion < version {
		walked, ok := head.StatementAt(version)
		if !ok || !bytes.Equal(walked.Statement.Bytes, statement.Bytes) {
			return nil, tamper("a DROP statement that is not the one the chain holds at its version")
		}
	}
	push := statement.Push
	if push.GetFlags() != uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) {
		return nil, tamper("a DROP statement with flags other than 256")
	}
	// H2: the body, on its length first, then its hash, shape and window
	lists, err := NewEvsDropLists(push, body)
	if err != nil {
		return nil, tamper(err.Error())
	}
	history := lists.History()
	if history.GetAction() != evsDropActionDrop || !bytes.Equal(history.GetDropId(), dropId.Bytes()) {
		return nil, tamper("a body that is not the drop named")
	}
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return nil, tamper("a DROP's signer")
	}
	if err := evsDropSignedBy(verifier, statement, head.RepoId, false); err != nil {
		client.alarm(head.RepoId, head.RefId, SidecarEvsAlarmTamper, "", &signerId)
		return nil, err
	}
	if !held || heldStatement == nil {
		if err := bodies.put(head.RepoId, head.RefId, dropId, version, statement.Bytes, body); err != nil {
			client.log.Warningf("[evs]a checked DROP body not kept: %s", err)
		}
	}
	return &evsReadDrop{statement: statement, version: version, lists: lists, dropId: dropId, signer: signerId}, nil
}

// Whether the DROP's signer may sign it at the statement's own auth pin: a repo admin; in an owner-bound repo a
// consented device of its owner; for a drop, no lock standing there (AclState.MayDrop and RepoLockAllowsDrop over that
// state's rows). An error refuses the statement. A pin before what the reader retains is not judged (QD-1178): the
// statement, which VerifyStatement took on its signature, still may not drop in a config or mailcfg repo, the kind its
// creation fixed, and nothing else of its signer is judged.
func evsDropSignedBy(verifier *EvsVerifier, statement *EvsStatement, repoId Id, cancel bool) error {
	newest, err := verifier.config()
	if err != nil {
		return err
	}
	push := statement.Push
	state, err := newest.At(push.GetAuth())
	unjudged := errors.Is(err, ErrGkmAuthNotRetained)
	switch {
	case unjudged:
		state = newest
	case err != nil:
		return fmt.Errorf("%w: its authorization pin: %w", ErrEvsStatementRefused, err)
	}
	repo := state.Repo(repoId)
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	switch {
	case err != nil || repo == nil:
		return fmt.Errorf("%w: a DROP of a repo the state does not hold", ErrEvsStatementRefused)
	case repo.GetKind() == protocol.RepoKind_REPO_KIND_CONFIG || repo.GetKind() == protocol.RepoKind_REPO_KIND_MAILCFG:
		return fmt.Errorf("%w: a DROP in a config or mailcfg repo", ErrEvsStatementRefused)
	case unjudged:
		return nil
	case !evsRepoAdmin(state, repo, signerId):
		return fmt.Errorf("%w: a DROP by a non-admin", ErrEvsStatementRefused)
	case aclRepoKindOwnerBound(repo.GetKind()) && !evsDropOwnerDevice(state, repo, signerId):
		return fmt.Errorf("%w: an owner-bound repo's DROP by another device", ErrEvsStatementRefused)
	case !cancel && repo.GetLock() == protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED:
		return fmt.Errorf("%w: a drop under a lock", ErrEvsStatementRefused)
	}
	return nil
}

// H7: whether a body this device holds is a cancel of the drop at its version; of a drop this device could not place,
// a cancel naming its drop_id, which is drawn at random per statement.
func (self *evsFormat2Rules) dropCancelled(client *EvsClient, head *EvsVerifiedHead, drop *evsReadDrop) bool {
	bodies := client.dropBodies()
	for _, held := range bodies.list(head.RepoId, head.RefId) {
		if held.dropId == drop.dropId || (drop.version != 0 && held.version != 0 && held.version <= drop.version) {
			continue
		}
		body, _, statementBytes, ok, err := bodies.get(head.RepoId, head.RefId, held.dropId)
		if err != nil || !ok {
			continue
		}
		statement, err := ParseEvsStatementFormat2(statementBytes)
		if err != nil {
			continue
		}
		lists, err := NewEvsDropLists(statement.Push, body)
		if err != nil {
			continue
		}
		history := lists.History()
		if history.GetAction() == evsDropActionCancel && bytes.Equal(history.GetCancelsDropId(), drop.dropId.Bytes()) &&
			(drop.version == 0 || history.GetCancelsVersion() == drop.version) {
			return true
		}
	}
	return false
}

// One version a replaying reader holds: its path epoch and token path there, its path version, and its entry hash,
// empty for a removal.
type EvsDropReplayVersion struct {
	Epoch       uint64
	TokenPath   EvsTokenPath
	Version     uint64
	EntrySha256 []byte
}

// A replaying reader's exactness check of a DROP's body against the history it replayed, no list byte fetched
// (DESIGN-DETAILS 10.2.3): for each path, the versions with an entry of its lineage's token paths below
// through_version, their entry hashes sorted, counted and hashed, equal to its count and listed_sha256. versions is
// every version of the DROP's ref the reader replayed below the DROP. A difference is ErrEvsDropInvalid, naming the
// path's index: history_drop invalid, and nothing dropped for this reader.
func EvsCheckDropExact(history *protocol.EvsDropHistory, versions []*EvsDropReplayVersion) error {
	for i, path := range history.GetPaths() {
		lineage := map[string]bool{}
		for _, entry := range path.GetLineage() {
			lineage[fmt.Sprint(entry.GetEpoch(), "/", string(bytes.Join(entry.GetTokenPath(), nil)))] = true
		}
		listed := [][]byte{}
		for _, version := range versions {
			if len(version.EntrySha256) == 0 || path.GetThroughVersion() <= version.Version ||
				!lineage[fmt.Sprint(version.Epoch, "/", string(version.TokenPath.Bytes()))] {
				continue
			}
			listed = append(listed, version.EntrySha256)
		}
		computed := &protocol.EvsDropPath{}
		if 0 < len(listed) {
			if _, err := EvsBuildDropLists([]*protocol.EvsDropPath{computed}, [][][]byte{listed}); err != nil {
				return fmt.Errorf("%w: path %d: %w", ErrEvsDropInvalid, i, err)
			}
		}
		if computed.GetCount() != path.GetCount() || !bytes.Equal(computed.GetListedSha256(), path.GetListedSha256()) {
			return fmt.Errorf("%w: path %d lists %d versions where its history holds %d", ErrEvsDropInvalid, i, path.GetCount(), computed.GetCount())
		}
	}
	return nil
}
