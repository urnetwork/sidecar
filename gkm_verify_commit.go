// §10.9's committer and check rows for one commit, with the roster rule and the GenWrap rule of DESIGN-DETAILS
// 6.2.3 (R1 to R4): what every member runs on a commit it received before it adopts it, and what a committer runs
// on its own staged commit before it uploads it, since a bad commit leaks the moment it stands at epoch/<n>.
//
//	judged     at the header's auth pin (R1): above the tip waits, off the chain is a fork, before what is retained
//	           is not judged
//	floors     the header's auth is at or past the previous epoch's and the carried generation's, and its
//	           generation at or past the previous epoch's (R2)
//	committer  Add: a writer leaf, or in the config and directory groups the admission's signer from its leaf;
//	           Remove: a writer leaf, or in those groups a standing leaf that is not read_only, never the target;
//	           path-only: any leaf; external: the sidecar itself, a resync removing at most its own old leaf or a
//	           recovery-admitted device's self-join; a read_only leaf commits a path and nothing else
//	Add        the credential admitted, standing and pinned; a member device that reads the repo at the pin, so a
//	           leaf among the key holders; in an owner-bound repo the owner's device only if consented; in the config
//	           and directory groups only a leaf-entitled device; at most GkmSeatCount leaves
//	Remove     its input at the pin: the target no longer a key holder (a revocation, park, Suspend, grant end or
//	           expiry), its loss of leaf entitlement in the config and directory groups, staleness by the credential's
//	           not_after (gkmStaleRemoveValid), a resync's own old leaf, or a re-add in the same commit (the Welcome
//	           that never appeared)
//	roster     the new tree lies within KeyHolders at the header's pin and time (R3), but a recovery self-join with
//	           generation 0, which may leave the lost devices' leaves; a tree that breaks it poisons the generation its
//	           GenWrap carried
//	GenWrap    opens under the new epoch's KEK to RK matching gen/<g>'s C_g (R4); none at generation 0, which only
//	           that self-join carries
//
// Readings where the rows give less than §10.9's words: the rows keep no revocation's signer, so in the config and
// directory groups a Remove is held to its input and to a standing committer leaf that is not read_only, not to "the
// revocation's signer"; a commit's header carries no time, so the roster is judged at the time the caller gives, the
// committer's clock or gkm's stamp of the epoch object, never before the carried generation's own signed time and
// never after this device's clock, so a stamp a server chose can neither hide a drop the generation's claim saw nor
// make a holder look expired; "KeyPackage claimed for this group" and "outside URnetwork platform networks" are
// gkm's and api's to hold, since neither shows in a tree. The seam shows no GroupContextExtensions proposal, which
// the subset holds to an unchanged ur_group itself, so that row's committer is not judged here.
//
// Pure functions over GkmAuthView, on every leg. FS-104's oracle (KEYS-M2-29) is deliberately separate code.

package sidecar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The most leaves a group's tree holds: MLS's 1,000 (D-KEYS-2), which every member holds alike, so it is a format
// value and GkmSettings.SeatCount, a committer's own bound, never passes it.
const GkmSeatCount = aclRepoSeatCount

// What a commit's check reads beside the state, the group and the staged commit.
type GkmCommitCheckArgs struct {
	RepoId Id
	// epoch/<n-1>'s header as this device adopted it: the floor of the commit's auth pin and generation (R2). For
	// epoch 1 of a re-formed group, the form's generation with gen/<form.generation>'s auth.
	PreviousHeader *protocol.GkmCommitHeader
	// gen/<header.generation> as this device parsed and judged it (CheckRotation), nil only at generation 0.
	Generation *GkmGeneration
	// GenWrap_n as the epoch object or the request carries it; empty only at generation 0.
	GenWrap []byte
	// When the roster is judged: the committer's clock for its own commit, gkm's time_ms of the epoch object for
	// a received one. See the file header for its bounds.
	Time time.Time
	// This device's clock.
	Now time.Time
}

// What CheckCommit found. Key is RK_g as the GenWrap opened it, when the verdict passed and the commit carries one.
type GkmCommitCheck struct {
	Verdict GkmVerdict
	Header  *protocol.GkmCommitHeader
	// The new epoch's leaves, as the commit's Adds and Removes make them from the group's roster.
	Roster []MlsMember
	Key    *EvsRepoKey
}

// §7.9's stale_leaf_days at a state, which TEAM's ConfigState answers; false where the head cannot be opened. A
// state that does not answer it refuses every stale Remove.
type GkmStaleLeafView interface {
	StaleLeafDays() (uint32, bool)
}

// Whether an encoded commit is an external one: an MLSMessage whose wire format is PublicMessage (RFC 9420 §6),
// which a member's commit, a PrivateMessage, never is.
func GkmCommitIsExternal(message []byte) bool {
	return 4 <= len(message) && binary.BigEndian.Uint16(message[2:4]) == mlsWireFormatPublicMessage
}

// §10.9's stale row as the owner settled it (plan-KEYS-stale-remove-evidence): a stale Remove is valid iff the
// target's credential in the prior epoch's tree has not_after - 90 days + stale_leaf_days at or before this clock
// plus 60 s. The credential's not_after is its last signing plus 90 days, and every path and external join re-signs
// it, so the tree carries each leaf's last change and a one-day joiner and an old member agree. The one place the
// rule lives.
func gkmStaleRemoveValid(credentialNotAfterMs int64, staleLeafDays uint32, now time.Time) bool {
	if credentialNotAfterMs <= 0 || staleLeafDays == 0 {
		return false
	}
	lastChangeMs := credentialNotAfterMs - gkmCredentialLifetime.Milliseconds()
	staleAtMs := lastChangeMs + int64(staleLeafDays)*(24*time.Hour).Milliseconds()
	return staleAtMs <= now.Add(GkmMemberClockSkew).UnixMilli()
}

// Whether a leaf is stale at a state and this clock: gkmStaleRemoveValid over its credential, with the state's
// stale_leaf_days. A state that cannot answer the setting, or a credential that does not parse, is not stale.
func GkmLeafStale(view GkmAuthView, member MlsMember, now time.Time) bool {
	staleView, ok := view.(GkmStaleLeafView)
	if !ok {
		return false
	}
	staleLeafDays, ok := staleView.StaleLeafDays()
	if !ok {
		return false
	}
	credential := &protocol.UrMlsCredential{}
	if err := proto.Unmarshal(member.Credential, credential); err != nil {
		return false
	}
	return gkmStaleRemoveValid(credential.GetNotAfter(), staleLeafDays, now)
}

// Whether a row's admission was signed by one of its member's recovery bindings: §10.8's recovery-admitted device,
// the only one a generation-0 self-join is taken from.
func gkmRecoveryAdmitted(view GkmAuthView, row *bridge.SidecarRow) bool {
	if !gkmRowMemberDevice(row) {
		return false
	}
	memberId, err := IdFromBytes(row.GetMemberId())
	if err != nil {
		return false
	}
	member := view.Member(memberId)
	if member == nil {
		return false
	}
	for _, signer := range row.GetAdmissionSigners() {
		if 0 < len(member.GetRecoveryKeySha256()) && bytes.Equal(signer, member.GetRecoveryKeySha256()) {
			return true
		}
		for _, binding := range member.GetBindings() {
			if bytes.Equal(signer, binding.GetKeySha256()) {
				return true
			}
		}
	}
	return false
}

// The time a commit's roster is judged at: the caller's, never before the carried generation's signed time nor
// after this clock.
func gkmCommitRosterTime(args *GkmCommitCheckArgs) time.Time {
	at := args.Time
	if at.IsZero() || args.Now.Before(at) {
		at = args.Now
	}
	if args.Generation != nil && args.Generation.Rotate != nil {
		if generationTime := time.UnixMilli(args.Generation.Rotate.GetTimeMs()); at.Before(generationTime) {
			at = generationTime
		}
	}
	return at
}

// §10.9's checks of one commit staged on group, this device's own before it uploads it or one it received, at the
// commit's own auth pin (R1 to R4). The error is a wait or a state that cannot answer, never a refusal: ErrGkmAuthAhead
// while the pin is above view, ErrGkmTimeAhead never (a commit carries no time), anything else fails closed. A verdict
// that does not pass means never adopt the commit; Poisoned names the generation its GenWrap carried into a tree
// that holds a non-holder.
func CheckCommit(view GkmAuthView, group MlsGroup, staged MlsStagedCommit, args *GkmCommitCheckArgs) (*GkmCommitCheck, error) {
	if group == nil || staged == nil || args == nil || args.Now.IsZero() {
		return nil, fmt.Errorf("%w: a commit check needs the group, the commit and a clock", ErrGkmMalformed)
	}
	check := &GkmCommitCheck{}
	refuse := func(verdict GkmVerdict) (*GkmCommitCheck, error) {
		check.Verdict = verdict
		return check, nil
	}
	header := &protocol.GkmCommitHeader{}
	if err := proto.Unmarshal(staged.AuthenticatedData(), header); err != nil {
		return refuse(gkmRefuse(GkmRefusalMalformed, "the commit's header does not parse"))
	}
	check.Header = header
	if staged.Epoch() != group.Epoch()+1 {
		return refuse(gkmRefuse(GkmRefusalMalformed, "a commit to epoch %d on epoch %d", staged.Epoch(), group.Epoch()))
	}
	at, verdict, err := gkmJudgedView(view, header.GetAuth())
	if err != nil {
		return nil, err
	}
	if !verdict.Passed() {
		return refuse(verdict)
	}
	repo := at.Repo(args.RepoId)
	if repo == nil {
		return refuse(gkmRefuse(GkmRefusalRoster, "the state at the pin holds no such repo"))
	}

	// R2: the pin and the generation never fall along the epoch chain
	generation := header.GetGeneration()
	if previous := args.PreviousHeader; previous != nil {
		if header.GetAuth().GetVersion() < previous.GetAuth().GetVersion() {
			return refuse(gkmRefuse(GkmRefusalPinFloor, "pin %d below the previous epoch's %d", header.GetAuth().GetVersion(), previous.GetAuth().GetVersion()))
		}
		if generation != 0 && generation < previous.GetGeneration() {
			return refuse(gkmRefuse(GkmRefusalGenWrap, "generation %d below the previous epoch's %d", generation, previous.GetGeneration()))
		}
	}
	if generation != 0 {
		if args.Generation == nil || args.Generation.Rotate == nil || args.Generation.Rotate.GetGeneration() != generation {
			return nil, fmt.Errorf("%w: gen/%d to check the commit's GenWrap against", ErrGkmKeyMissing, generation)
		}
		if header.GetAuth().GetVersion() < args.Generation.Rotate.GetAuth().GetVersion() {
			return refuse(gkmRefuse(GkmRefusalPinFloor, "pin %d below gen/%d's %d", header.GetAuth().GetVersion(), generation, args.Generation.Rotate.GetAuth().GetVersion()))
		}
	}

	rosterTime := gkmCommitRosterTime(args)
	holders, err := KeyHolders(at, args.RepoId, rosterTime)
	if err != nil {
		return nil, err
	}
	leafRanked := gkmGroupLeafRanked(repo)
	// a leaf the state lets stand in the tree: a key holder as a member device and, where §7.9's leaves rule seats
	// the group, leaf-entitled
	holderLeaf := func(sidecarId Id) bool {
		return holders.Contains(GkmHolderLeaf, sidecarId.Bytes())
	}
	entitled := func(sidecarId Id) bool {
		return !leafRanked || GkmLeafEntitled(at, args.RepoId, sidecarId, rosterTime)
	}

	oldRoster := group.Roster()
	committer := staged.Committer()
	added := staged.Added()
	removed := staged.Removed()
	external := GkmCommitIsExternal(staged.Message())
	oldLeafOf := func(sidecarId Id) *MlsMember {
		for index := range oldRoster {
			if oldRoster[index].SidecarId == sidecarId {
				return &oldRoster[index]
			}
		}
		return nil
	}

	// the new tree, from the old one
	removedSidecarIds := map[Id]bool{}
	for _, member := range removed {
		if oldLeafOf(member.SidecarId) == nil {
			return refuse(gkmRefuse(GkmRefusalRemove, "a Remove of no leaf"))
		}
		removedSidecarIds[member.SidecarId] = true
	}
	roster := []MlsMember{}
	for _, member := range oldRoster {
		if !removedSidecarIds[member.SidecarId] {
			roster = append(roster, member)
		}
	}
	joiners := slices.Clone(added)
	if external {
		joiners = append(joiners, committer)
	}
	for _, joiner := range joiners {
		if slices.ContainsFunc(roster, func(member MlsMember) bool { return member.SidecarId == joiner.SidecarId }) {
			return refuse(gkmRefuse(GkmRefusalAdd, "an Add of a sidecar that is a leaf"))
		}
		roster = append(roster, joiner)
	}
	check.Roster = roster

	// the committer rows
	committerRow := at.SidecarRow(committer.SidecarId)
	selfJoin := false
	switch {
	case external:
		if 0 < len(added) {
			return refuse(gkmRefuse(GkmRefusalCommitter, "an external commit that adds another"))
		}
		for _, member := range removed {
			if member.SidecarId != committer.SidecarId {
				return refuse(gkmRefuse(GkmRefusalCommitter, "an external commit removing another's leaf"))
			}
		}
		if generation == 0 {
			// §10.8's self-join: a recovery-admitted device, in the config group if leaf-entitled, else in a group
			// it writes
			if !gkmRecoveryAdmitted(at, committerRow) || !(leafRanked || gkmWrites(at, args.RepoId, committer.SidecarId)) {
				return refuse(gkmRefuse(GkmRefusalCommitter, "a generation-0 commit that is no recovery self-join"))
			}
			selfJoin = true
		}
	default:
		if oldLeafOf(committer.SidecarId) == nil {
			return refuse(gkmRefuse(GkmRefusalCommitter, "a commit by no leaf of its epoch"))
		}
		if generation == 0 {
			return refuse(gkmRefuse(GkmRefusalGenWrap, "generation 0 on a member's commit"))
		}
		if 0 < len(added) || 0 < len(removed) {
			if !gkmRowStanding(committerRow) || gkmRowReadOnly(committerRow) || !gkmRowMemberDevice(committerRow) {
				return refuse(gkmRefuse(GkmRefusalCommitter, "an Add or Remove by a leaf that may commit none"))
			}
			writer := gkmWrites(at, args.RepoId, committer.SidecarId)
			if 0 < len(removed) && !writer && !leafRanked {
				return refuse(gkmRefuse(GkmRefusalCommitter, "a Remove by a leaf that does not write the repo"))
			}
			if 0 < len(added) && !writer {
				if !leafRanked {
					return refuse(gkmRefuse(GkmRefusalCommitter, "an Add by a leaf that does not write the repo"))
				}
				// owner decisions 128, 182: the admission's signer commits the Add it requires
				for _, member := range added {
					row := at.SidecarRow(member.SidecarId)
					if row == nil || !slices.ContainsFunc(row.GetAdmissionSigners(), func(signer []byte) bool {
						return bytes.Equal(signer, committer.SidecarId.Bytes())
					}) {
						return refuse(gkmRefuse(GkmRefusalCommitter, "an Add by neither a writer nor the admission's signer"))
					}
				}
			}
		}
	}

	// the Add row, for each new leaf
	for _, joiner := range joiners {
		credential, err := CheckUrMlsCredential(joiner.Credential)
		if err != nil || !bytes.Equal(credential.GetSidecarId(), joiner.SidecarId.Bytes()) {
			return refuse(gkmRefuse(GkmRefusalCredential, "a new leaf's credential does not verify"))
		}
		if err := GkmCredentialStanding(at, credential); err != nil {
			if errors.Is(err, ErrGkmNotAdmitted) {
				return refuse(gkmRefuse(GkmRefusalCredential, "%v", err))
			}
			return nil, err
		}
		row := at.SidecarRow(joiner.SidecarId)
		if !gkmRowMemberDevice(row) {
			return refuse(gkmRefuse(GkmRefusalAdd, "a leaf for a sidecar that is no member device"))
		}
		if !holderLeaf(joiner.SidecarId) {
			return refuse(gkmRefuse(GkmRefusalAdd, "a leaf for a device that does not read the repo at the pin"))
		}
		if ownerMemberId := repo.GetOwnerMemberId(); 0 < len(ownerMemberId) && bytes.Equal(ownerMemberId, row.GetMemberId()) {
			// §8.5: an owner-bound repo takes the owner's devices only once consented; another member's reads by
			// an EvsShare, which the holders already require
			if !slices.ContainsFunc(repo.GetConsentedSidecarIds(), func(consented []byte) bool {
				return bytes.Equal(consented, joiner.SidecarId.Bytes())
			}) {
				return refuse(gkmRefuse(GkmRefusalAdd, "an unconsented device in an owner-bound repo"))
			}
		}
		if !entitled(joiner.SidecarId) {
			return refuse(gkmRefuse(GkmRefusalAdd, "a leaf for a device that is not leaf-entitled"))
		}
	}
	if 0 < len(joiners) && GkmSeatCount < len(roster) {
		return refuse(gkmRefuse(GkmRefusalAdd, "a tree of %d leaves", len(roster)))
	}

	// the Remove row: each Remove's input at the pin
	for _, member := range removed {
		switch {
		case !holderLeaf(member.SidecarId):
			// a revocation, park, Suspend, grant end or expiry
		case !entitled(member.SidecarId):
			// §7.9's move: it reads on by wraps
		case external && member.SidecarId == committer.SidecarId:
			// a resync's own old leaf
		case slices.ContainsFunc(added, func(readded MlsMember) bool { return readded.SidecarId == member.SidecarId }):
			// the re-add of a joiner whose Welcome never appeared (§10.6)
		case GkmLeafStale(at, member, args.Now):
			// §10.9's stale row
		default:
			return refuse(gkmRefuse(GkmRefusalRemove, "a Remove with no input at the pin"))
		}
	}

	// R3: the new tree within the key holders, the self-join's lost leaves aside
	for _, member := range roster {
		if selfJoin && member.SidecarId != committer.SidecarId {
			continue
		}
		if !holderLeaf(member.SidecarId) {
			verdict := gkmRefuse(GkmRefusalRoster, "the new tree holds a leaf that is no key holder at the pin")
			verdict.Poisoned = generation
			return refuse(verdict)
		}
		if !entitled(member.SidecarId) {
			return refuse(gkmRefuse(GkmRefusalRoster, "the new tree holds a leaf that is not leaf-entitled"))
		}
	}

	// R4: the GenWrap
	if generation == 0 {
		if 0 < len(args.GenWrap) {
			return refuse(gkmRefuse(GkmRefusalGenWrap, "a GenWrap at generation 0"))
		}
		return check, nil
	}
	groupId := group.GroupId()
	if !bytes.Equal(args.Generation.Rotate.GetRepoId(), args.RepoId.Bytes()) {
		return refuse(gkmRefuse(GkmRefusalGenWrap, "gen/%d of another repo", generation))
	}
	kek, err := MlsKek(staged, args.RepoId)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	key, err := OpenGkmGenWrap(args.Generation, groupId, staged.Epoch(), kek, args.GenWrap)
	if err != nil {
		if errors.Is(err, ErrGkmAuthentication) || errors.Is(err, ErrGkmMalformed) || errors.Is(err, ErrGkmKeyMissing) {
			return refuse(gkmRefuse(GkmRefusalGenWrap, "the GenWrap does not open to gen/%d's key", generation))
		}
		return nil, err
	}
	check.Key = key
	return check, nil
}
