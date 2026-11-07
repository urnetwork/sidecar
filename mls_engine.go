// The seam over §10.4's MLS subset: what gkm's client asks of one sidecar's MLS state. The real engine on mls_*
// (KEYS-M2-08) and sidecartest.FakeMls both implement it, so §7.9, §11 and §16 build before the subset is whole
// (§23.5), and sidecartest/mlssuite holds the two to one behavior.
//
// A commit is staged, then adopted only once gkm has answered 200 for its epoch object, or discarded on a 409,
// after which the group processes the winner (RFC 9420 §14, D-KEYS-5, KF6). A received commit is staged too: the
// caller judges it at its auth pin (§10.9) and adopts it only if it passes, so a member never encrypts to an epoch
// it refused. The subset itself judges no authority.
//
// A Welcome join takes two phases (§10.6). gkm stores a Welcome without the ratchet tree, so a joiner first opens
// the Welcome, which gives its epoch's exporter and so KEK_e; it opens GenWrap_e for RK_g, accepted only against
// gen/<g>'s C_g (OpenGkmGenWrap); it derives K_groupinfo and opens the sealed GroupInfo; and only then does
// Complete verify the GroupInfo's signature and tree against the Welcome. Nothing the Welcome says is trusted
// before both checks pass. A server can replay any Welcome, so a one-time KeyPackage joins one Welcome, its private
// key gone once that join completes (RFC 9420 §16.8; §10.6's KeyPackages), and no join, a Welcome's or an external
// commit's, takes a group to an epoch at or below the newest this engine reached of it, held or since left (I-16).
// The last-resort KeyPackage, which is kept, is held back by that second rule alone.
//
// ParseMlsHeader is the one MLS parse gkm runs, with no key (I-1). It reads a member's commit, a PrivateMessage,
// and refuses a PublicMessage, an external commit, until KEYS-M2-05's framing reads one; so gkm refuses every
// resync and recovery self-join until then, failing closed.
//
// On every leg, with no connect import. MlsKek hooks the KEK it exports, and the engines hook their own secrets.
// An engine's methods are safe for concurrent use; a group, a pending join and a staged commit are not, and one
// owner drives each.

package sidecar

import (
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// MLSMessage's version and wire formats (RFC 9420 §6, §17.2), and the one content §10.4 frames.
const (
	mlsHeaderWireFormatPublicMessage  uint16 = 0x0001
	mlsHeaderWireFormatPrivateMessage uint16 = 0x0002
	mlsHeaderContentTypeCommit        uint8  = 3
)

var (
	// No state of this group is held here: never joined, forgotten, or left at a Remove.
	ErrMlsGroupUnknown = errors.New("mls: group unknown")
	// This sidecar is no leaf of the epoch: a commit removed it, or it was never added.
	ErrMlsNotMember = errors.New("mls: not a member")
)

// What a commit's MLSMessage shows with no key, which is all gkm reads of one (§10.6, I-1). Nothing here is
// authenticated, since a server has no key to authenticate it with: members check the same values when they
// open the commit.
type MlsHeader struct {
	GroupId []byte
	// The epoch the commit is sent in, so it makes epoch Epoch + 1.
	Epoch uint64
	// 3, a commit, since anything else is refused.
	ContentType uint8
	// The commit's GkmCommitHeader, left encoded (D-KEYS-3).
	AuthenticatedData []byte
}

// The clear header of an encoded MLSMessage, with no key: a member's commit, framed as a PrivateMessage. Refuses
// what the subset refuses (application data and standalone proposals) and every other wire format, and refuses a
// PublicMessage until KEYS-M2-05's framing reads an external commit's.
func ParseMlsHeader(encoded []byte) (*MlsHeader, error) {
	decoder := &mlsDecoder{remaining: encoded}
	version := decoder.readUint16()
	wireFormat := decoder.readUint16()
	if decoder.err != nil {
		return nil, decoder.err
	}
	if version != mlsProtocolVersion10 {
		return nil, fmt.Errorf("%w: protocol version %d", errMlsRefused, version)
	}
	switch wireFormat {
	case mlsHeaderWireFormatPrivateMessage:
	case mlsHeaderWireFormatPublicMessage:
		return nil, fmt.Errorf("%w: an external commit's header is read once its framing lands (KEYS-M2-05)", errMlsRefused)
	default:
		return nil, fmt.Errorf("%w: wire format %d is no commit", errMlsRefused, wireFormat)
	}
	header := &MlsHeader{}
	header.GroupId = decoder.readVector()
	header.Epoch = decoder.readUint64()
	header.ContentType = decoder.readUint8()
	header.AuthenticatedData = decoder.readVector()
	// encrypted_sender_data and ciphertext, which only a member opens
	decoder.readVector()
	decoder.readVector()
	if err := decoder.finish(); err != nil {
		return nil, err
	}
	if header.ContentType != mlsHeaderContentTypeCommit {
		return nil, fmt.Errorf("%w: content type %d", errMlsRefused, header.ContentType)
	}
	return header, nil
}

// ur_group, what a group is for (§10.5; QD-469), fixed at its creation and bound by its key schedule.
type MlsUrGroup struct {
	NetworkId Id
	RepoId    Id
	Kind      protocol.RepoKind
	// The member an owner-bound repo belongs to, nil for any other.
	OwnerMemberId *Id
}

// A KeyPackage this sidecar made (§10.6's KeyPackages).
type MlsKeyPackage struct {
	// Its MLSMessage, which gkm stores at kp/<sidecar_id>/<ref>.
	Encoded []byte
	// Its KeyPackageRef (RFC 9420 §5.2), <ref> in gkm's keys.
	Ref []byte
	// The one that is served when no one-time KeyPackage remains, and never deleted.
	LastResort bool
}

// One leaf of an epoch's tree.
type MlsMember struct {
	LeafIndex uint32
	SidecarId Id
	// The leaf's credential, UrMlsCredential's encoding (§10.4).
	Credential []byte
}

// One epoch's MLS-Exporter (RFC 9420 §8.5). An engine hooks what it exports, and MlsKek hooks KEK_e again.
type MlsExporter interface {
	// length bytes for label and context, which every member of the epoch derives alike and no one else can.
	Exporter(label string, context []byte, length int) ([]byte, error)
}

// KEK_e of an epoch for repoId: MLS-Exporter("UR evs 1.0 kek", repo_id, 32) (§10.5), which seals GenWrap_e and
// LeafWraps.
func MlsKek(exporter MlsExporter, repoId Id) ([]byte, error) {
	kek, err := exporter.Exporter(gkmKekLabel, repoId.Bytes(), gkmKekByteCount)
	if err != nil {
		return nil, err
	}
	if len(kek) != gkmKekByteCount {
		return nil, fmt.Errorf("mls: a KEK of %d bytes", len(kek))
	}
	testHookSecret("KEK_e", kek)
	return kek, nil
}

// What a commit changes, which its committer asks for and every member judges (§10.9).
type MlsCommitArgs struct {
	// KeyPackages, as claims returned them, of the devices the commit adds.
	Adds [][]byte
	// Leaves the commit removes. Never the committer's own (RFC 9420 §12.2), but for an external commit's old leaf.
	Removes []uint32
	// Whether the commit carries an UpdatePath. One with a Remove always does (§10.4), and one with neither Adds
	// nor Removes is a self-update, which is only its path.
	Path bool
	// The commit's GkmCommitHeader, encoded, which goes in the clear as its authenticated_data and is bound into
	// its AEAD and signature (D-KEYS-3).
	AuthenticatedData []byte
}

// A commit staged on an epoch, this sidecar's or one received, which changes nothing until Adopt. Its exporter is
// the new epoch's, so a committer seals GenWrap_{e+1} and GroupInfo_{e+1} before it uploads the commit.
type MlsStagedCommit interface {
	MlsExporter
	// The commit's MLSMessage, which gkm stores at epoch/<n>.
	Message() []byte
	// The epoch the commit makes.
	Epoch() uint64
	// The new epoch's epoch_authenticator, which pushes pin (§11.6).
	EpochAuthenticator() []byte
	// Who committed: a leaf of the old epoch, or for an external commit the joiner's new leaf.
	Committer() MlsMember
	// The leaves the commit adds, in the new epoch.
	Added() []MlsMember
	// The leaves it removes, as they were in the old epoch.
	Removed() []MlsMember
	// GkmCommitHeader's encoding, as the commit authenticated it.
	AuthenticatedData() []byte
	// The Welcome of its Adds, without the ratchet tree (§10.6): this sidecar's own commit only, nil without Adds.
	Welcome() []byte
	// The new epoch's GroupInfo, ratchet_tree and external_pub included, signed by this sidecar's leaf: what is
	// sealed into epoch/<n> at 16 leaves or fewer (§10.6).
	GroupInfo() ([]byte, error)
	// Makes the new epoch the group's: this sidecar's commit once gkm answered 200, or a received one once it
	// passed §10.9's checks. ErrMlsNotMember when the commit removed this sidecar, whose state of the group is
	// then gone, all but the epoch it reached, which no later join goes back to or below.
	Adopt() (MlsGroup, error)
	// Leaves the group at its epoch: a 409's loser (KF6), or a commit its checks refused. Safe to call again.
	Discard()
}

// One group as this sidecar last adopted it.
type MlsGroup interface {
	MlsExporter
	GroupId() Id
	Epoch() uint64
	// epoch_authenticator (RFC 9420 §8.7).
	EpochAuthenticator() []byte
	// This sidecar's leaf.
	Self() MlsMember
	// Every leaf of the epoch, by index.
	Roster() []MlsMember
	// The epoch's GroupInfo, ratchet_tree and external_pub included, signed by this sidecar's leaf, for a join or
	// resync above 16 leaves (§10.6).
	GroupInfo() ([]byte, error)
	// Stages this sidecar's commit on the epoch.
	Commit(args *MlsCommitArgs) (MlsStagedCommit, error)
	// Opens another's commit in this epoch, a member's or an external one, and stages it for the caller to judge.
	Process(message []byte) (MlsStagedCommit, error)
}

// A Welcome join between its two phases (§10.6). Its exporter is the joined epoch's, which gives KEK_e.
type MlsPendingJoin interface {
	MlsExporter
	GroupId() Id
	Epoch() uint64
	// The second phase: groupInfo, opened from the epoch's sealed GroupInfo, supplies the tree the Welcome left out.
	// Its signature, its tree and their agreement with the Welcome are verified before the group exists. Refused for
	// an epoch at or below the newest this engine reached of the group, and once its one-time KeyPackage has joined.
	Complete(groupInfo []byte) (MlsGroup, error)
}

// One sidecar's MLS: what it creates, joins and holds (§10.4).
type MlsEngine interface {
	// A KeyPackage for this sidecar's leaf: one-time, which joins one Welcome, or its one last-resort KeyPackage,
	// which joins any number.
	CreateKeyPackage(lastResort bool) (*MlsKeyPackage, error)
	// A group at epoch 0 whose only leaf is this sidecar's (KF1), its ur_group fixed for its life.
	CreateGroup(groupId Id, urGroup *MlsUrGroup) (MlsGroup, error)
	// The first phase of a Welcome join, under one of this sidecar's KeyPackages.
	JoinWelcome(welcome []byte) (MlsPendingJoin, error)
	// An external commit joining from groupInfo, the newest epoch's, opened under the generation it names: a resync,
	// whose args.Removes names this sidecar's old leaf, or a recovery self-join (KF5, §10.8). It is adopted, as any
	// commit, once gkm answers 200.
	JoinExternal(groupInfo []byte, args *MlsCommitArgs) (MlsStagedCommit, error)
	// The group as this sidecar last adopted it (§10.5: one tree loaded at a time).
	LoadGroup(groupId Id) (MlsGroup, error)
}
