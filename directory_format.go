// §16.11's format values for the team directory, on every leg: what every reader applies alike, so none is a setting
// (§5.4's SidecarDirectorySettings comment; connect/CODESTYLE.md's exceptions). Item expiry and staleness, the pin and
// right bounds a card or repo file is judged by, the files' sizes and padding, the values directory.proto's uint32
// fields carry, a repo item's announcement_id, and one function for each path under the cards ref, so that an answer
// changing a path changes one line.
//
//	d/<h>/<sid>          a sidecar's card, from format 2
//	r/<h>/<repo>         a repo file, from format 2
//	q/<h>/<tgt>/<rid>    the notice of request <rid> to <tgt>, which approvers lease by its prefix, q/<h>/<tgt>/
//
// Every id in a path is 32 lowercase hex characters, never Id.String()'s dashed form (plan-RECORD-stream-names#2). A
// repo's or a worker's <tgt> is its id; a socket's is 32 lowercase hex of SHA-256(name_token)[:16], so it changes when
// K_sock rotates (plan-RECORD-stream-names#3). <h> is two lowercase hex digits, the first byte of SHA-256 of the name
// it shards as its path text (§15.7's shards rule, plan-RECORD-notice-path-bound): 256 shards, each under §11.7's
// bound for about 917,000 names in all.
//
// Announcements, requests, decisions and erasure requests ride sealed in a RecordEntry whose header the writer's
// identity key signs, so none takes a SignedType of its own; only a card and a repo file are Signed, as 0x1805 and
// 0x1806 under purpose directory.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// §16.11's times and bounds, which every reader applies alike.
const (
	// A run item lapses this long after its last renewal: its expires_millis is renewed_millis plus this.
	DirectoryRunExpiry = 90 * time.Minute
	// A worker item's, which renews daily.
	DirectoryWorkerExpiry = 26 * time.Hour
	// How long readers show an expired item as stale, and never as active, before they stop showing it.
	DirectoryStaleShowTime = 24 * time.Hour
	// How long an ended or handed-off item stays on its card before the card's next write drops it.
	DirectoryEndedKeepTime = 24 * time.Hour
	// A card's at lies within this many log positions of the reader's state, and a repo file's within this many
	// before the auth pin of the push that wrote it.
	DirectoryPinPositionCount = 4096
	// A log entry after a repo file's push pin ending its signer's right counts against the file only when it is
	// more than this before the push's time_ms, since evs bounds a push's pin only by its ref's head pin.
	DirectoryRightBound = 10 * time.Minute
	// A request's own expiry, not_after_millis: this long after filing by default, and never more than
	// DirectoryRequestMaxExpiry after.
	DirectoryRequestDefaultExpiry = 7 * 24 * time.Hour
	DirectoryRequestMaxExpiry     = 30 * 24 * time.Hour
	// Past a request's not_after by this, any writer may remove its notice, and its decider stops resuming the
	// decision (§16.11's q/ path rule and decide row).
	DirectoryNoticeGrace = 24 * time.Hour
)

// §16.11's sizes, which are format values.
const (
	// A notice, padded to exactly this.
	DirectoryNoticeByteCount = 256
	// The decisions a notice names: at most a requests rule's two approvals, or its one denial.
	DirectoryNoticeDecisionCount = 2
	// A card's items, at most one worker item and then runs, in at most DirectoryCardItemsByteCount.
	DirectoryCardItemCount      = 16
	DirectoryCardItemsByteCount = 16208
	// A repo file: an announcement or a private marker.
	DirectoryRepoFileByteCount = 4 * 1024
	// Cards and repo files pad in steps of this, so a card's size shows at most whether its sidecar has more than
	// about two runs.
	DirectoryFileStepByteCount = 2 * 1024
	// A kind-repo announce entry, an announcement or a private marker alike, fills its marshaled Announcement to a
	// multiple of this, so evs cannot tell which new repos are private (plan-RECORD-m6-carrier#2).
	DirectoryRepoEntryStepByteCount = 2 * 1024
)

// The domain of a repo item's announcement_id.
const directoryRepoAnnouncementDomain = "urnetwork-sidecar-v1/directory-repo"

// Announcement.pad's field number, which DirectoryPadRepoAnnouncement sizes its tag by.
const directoryAnnouncementPadField = 14

// A RequestTarget, an Announcement or a value one carries that no reader takes: a refusal before anything is signed,
// and what a decoder ignores with an alarm.
var ErrDirectoryFormatInvalid = errors.New("directory format invalid")

// Announcement.kind.
type DirectoryAnnouncementKind uint32

const (
	DirectoryAnnouncementKindRun    DirectoryAnnouncementKind = 1
	DirectoryAnnouncementKindWorker DirectoryAnnouncementKind = 2
	DirectoryAnnouncementKindRepo   DirectoryAnnouncementKind = 3
)

// Whether §16.11 names the kind.
func (self DirectoryAnnouncementKind) Known() bool {
	return DirectoryAnnouncementKindRun <= self && self <= DirectoryAnnouncementKindRepo
}

// Announcement.state. Withdrawn is terminal and only a run's or a worker's: readers fold it over the item at once and
// never show the item, and announcing again takes a new announcement_id (plan-RECORD-m6-carrier#1).
type DirectoryAnnouncementState uint32

const (
	DirectoryAnnouncementStateActive    DirectoryAnnouncementState = 1
	DirectoryAnnouncementStateEnded     DirectoryAnnouncementState = 2
	DirectoryAnnouncementStateHandedOff DirectoryAnnouncementState = 3
	DirectoryAnnouncementStateWithdrawn DirectoryAnnouncementState = 4
)

// Whether §16.11 names the state for an item of kind: withdrawn for runs and workers alone.
func (self DirectoryAnnouncementState) KnownFor(kind DirectoryAnnouncementKind) bool {
	switch self {
	case DirectoryAnnouncementStateActive, DirectoryAnnouncementStateEnded, DirectoryAnnouncementStateHandedOff:
		return kind.Known()
	case DirectoryAnnouncementStateWithdrawn:
		return kind == DirectoryAnnouncementKindRun || kind == DirectoryAnnouncementKindWorker
	}
	return false
}

// AnnounceWhat.requests: whether a worker or repo takes requests.
type DirectoryRequests uint32

const (
	DirectoryRequestsOpen   DirectoryRequests = 1
	DirectoryRequestsClosed DirectoryRequests = 2
)

// Claim.state.
type DirectoryClaimState uint32

const (
	DirectoryClaimStateActive    DirectoryClaimState = 1
	DirectoryClaimStateReleased  DirectoryClaimState = 2
	DirectoryClaimStateHandedOff DirectoryClaimState = 3
)

// Service.kind: an application socket, a published TLS host, or a bridge port, tcp:<port>.
type DirectoryServiceKind uint32

const (
	DirectoryServiceKindSocket     DirectoryServiceKind = 1
	DirectoryServiceKindTlsHost    DirectoryServiceKind = 2
	DirectoryServiceKindBridgePort DirectoryServiceKind = 3
)

// DirectoryRequest.filed_by: a person by a /dev/tty command or an app's UI, an agent, or a tagged sidecar.
type DirectoryFiledBy uint32

const (
	DirectoryFiledByPerson        DirectoryFiledBy = 1
	DirectoryFiledByAgent         DirectoryFiledBy = 2
	DirectoryFiledByTaggedSidecar DirectoryFiledBy = 3
)

// DirectoryDecision.outcome, whose first two DirectoryNotice.outcome takes; a cancel removes the notice.
type DirectoryOutcome uint32

const (
	DirectoryOutcomeApproved  DirectoryOutcome = 1
	DirectoryOutcomeDenied    DirectoryOutcome = 2
	DirectoryOutcomeCancelled DirectoryOutcome = 3
)

// DirectoryNotice.state.
type DirectoryNoticeState uint32

const (
	DirectoryNoticeStatePending DirectoryNoticeState = 1
	DirectoryNoticeStateDecided DirectoryNoticeState = 2
)

// What a RequestTarget names: exactly one of a repo, a worker or a socket.
type DirectoryTargetKind int

const (
	DirectoryTargetKindRepo DirectoryTargetKind = iota + 1
	DirectoryTargetKindWorker
	DirectoryTargetKindSocket
)

// The target's kind, with exactly one of repo_id, sidecar_id and socket_token set at its length: a repo's or a
// worker's id 16 bytes, a socket's name token one to eight 16-byte segments (§9.4). tcp_ports go only with a worker.
func DirectoryRequestTargetKind(target *protocol.RequestTarget) (DirectoryTargetKind, error) {
	if target == nil {
		return 0, fmt.Errorf("%w: no target", ErrDirectoryFormatInvalid)
	}
	kinds := []DirectoryTargetKind{}
	if len(target.GetRepoId()) != 0 {
		if len(target.GetRepoId()) != recordIdByteCount {
			return 0, fmt.Errorf("%w: a repo_id of %d bytes", ErrDirectoryFormatInvalid, len(target.GetRepoId()))
		}
		kinds = append(kinds, DirectoryTargetKindRepo)
	}
	if len(target.GetSidecarId()) != 0 {
		if len(target.GetSidecarId()) != recordIdByteCount {
			return 0, fmt.Errorf("%w: a sidecar_id of %d bytes", ErrDirectoryFormatInvalid, len(target.GetSidecarId()))
		}
		kinds = append(kinds, DirectoryTargetKindWorker)
	}
	if token := target.GetSocketToken(); len(token) != 0 {
		if len(token)%socketTokenByteCount != 0 || socketNameMaxSegmentCount*socketTokenByteCount < len(token) {
			return 0, fmt.Errorf("%w: a socket token of %d bytes", ErrDirectoryFormatInvalid, len(token))
		}
		kinds = append(kinds, DirectoryTargetKindSocket)
	}
	if len(kinds) != 1 {
		return 0, fmt.Errorf("%w: a target naming %d of a repo, a worker and a socket", ErrDirectoryFormatInvalid, len(kinds))
	}
	if len(target.GetTcpPorts()) != 0 && kinds[0] != DirectoryTargetKindWorker {
		return 0, fmt.Errorf("%w: ports on a target that is no worker", ErrDirectoryFormatInvalid)
	}
	return kinds[0], nil
}

// Whether a request to target may ask role (plan-RECORD-small-readings#4): to a repo, RepoGrantRole's deposit, reader
// or writer; to a worker or a socket, AclAction's dial. 0 never, nor anything for a target that does not parse.
func DirectoryRequestRoleAllowed(target *protocol.RequestTarget, role uint32) bool {
	kind, err := DirectoryRequestTargetKind(target)
	if err != nil {
		return false
	}
	switch kind {
	case DirectoryTargetKindRepo:
		return DirectoryOfferedRoleAllowed(role)
	case DirectoryTargetKindWorker, DirectoryTargetKindSocket:
		return protocol.AclAction(role) == protocol.AclAction_ACL_ACTION_DIAL
	}
	return false
}

// Whether a repo item may offer role in AnnounceWhat.roles: RepoGrantRole's deposit, reader or writer, never 0.
func DirectoryOfferedRoleAllowed(role uint32) bool {
	switch protocol.RepoGrantRole(role) {
	case protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
		protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER:
		return true
	}
	return false
}

// A repo item's announcement_id, SHA-256("urnetwork-sidecar-v1/directory-repo" || repo_id)[:16]: one id for all its
// admins, so their items fold together.
func DirectoryRepoAnnouncementId(repoId Id) Id {
	hash := sha256.New()
	hash.Write([]byte(directoryRepoAnnouncementDomain))
	hash.Write(repoId[:])
	return Id(hash.Sum(nil)[:16])
}

// An item's expires_millis for a renewal at renewedMillis: a run's 90 min on, a worker's 26 h on, and a repo item's
// none, 0. False for a kind §16.11 does not name.
func DirectoryAnnouncementExpiresMillis(kind DirectoryAnnouncementKind, renewedMillis int64) (int64, bool) {
	switch kind {
	case DirectoryAnnouncementKindRun:
		return renewedMillis + DirectoryRunExpiry.Milliseconds(), true
	case DirectoryAnnouncementKindWorker:
		return renewedMillis + DirectoryWorkerExpiry.Milliseconds(), true
	case DirectoryAnnouncementKindRepo:
		return 0, true
	}
	return 0, false
}

// Sets a kind-repo announce entry's pad, zero bytes, so its Announcement marshals to the next multiple of 2,048 B,
// an announcement and a private marker alike, which a full item under its caps fills in exactly 2,048 B
// (plan-RECORD-m6-carrier#2). A run or worker item leaves pad empty, so one is refused. Returns the marshaled length.
func DirectoryPadRepoAnnouncement(announcement *protocol.Announcement) (int, error) {
	if announcement == nil || DirectoryAnnouncementKind(announcement.GetKind()) != DirectoryAnnouncementKindRepo {
		return 0, fmt.Errorf("%w: only a repo item is padded", ErrDirectoryFormatInvalid)
	}
	announcement.Pad = nil
	marshal := proto.MarshalOptions{Deterministic: true}
	unpadded := marshal.Size(announcement)
	tagByteCount := protowire.SizeTag(directoryAnnouncementPadField)
	// the pad field's own tag and length move the total, and a length's varint grows at 128, so a target the
	// lengths step over goes on to the next multiple
	// an empty pad would not be marshaled at all, so the pad holds at least one byte
	for target := DirectoryRepoEntryStepByteCount; ; target += DirectoryRepoEntryStepByteCount {
		if target < unpadded+tagByteCount+2 {
			continue
		}
		for lengthByteCount := 1; lengthByteCount <= 3; lengthByteCount += 1 {
			padByteCount := target - unpadded - tagByteCount - lengthByteCount
			if 0 < padByteCount && protowire.SizeVarint(uint64(padByteCount)) == lengthByteCount {
				announcement.Pad = make([]byte, padByteCount)
				if size := marshal.Size(announcement); size != target {
					return 0, fmt.Errorf("%w: padded to %d bytes, not %d", ErrDirectoryFormatInvalid, size, target)
				}
				return target, nil
			}
		}
	}
}

// An id as a path names it: 32 lowercase hex characters.
func directoryIdText(id Id) string {
	return hex.EncodeToString(id[:])
}

// <h> for a name: the first byte of SHA-256 of its path text, as two lowercase hex digits.
func directoryShard(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:1])
}

// d/<h>/<sid>: the card sidecarId writes, from format 2.
func DirectoryCardPath(sidecarId Id) string {
	name := directoryIdText(sidecarId)
	return "d/" + directoryShard(name) + "/" + name
}

// r/<h>/<repo>: the repo file of repoId, from format 2.
func DirectoryRepoPath(repoId Id) string {
	name := directoryIdText(repoId)
	return "r/" + directoryShard(name) + "/" + name
}

// <tgt>: a repo's or a worker's id, or for a socket 32 lowercase hex of SHA-256(name_token)[:16].
func DirectoryNoticeTarget(target *protocol.RequestTarget) (string, error) {
	kind, err := DirectoryRequestTargetKind(target)
	if err != nil {
		return "", err
	}
	switch kind {
	case DirectoryTargetKindRepo:
		return directoryIdText(Id(target.GetRepoId())), nil
	case DirectoryTargetKindWorker:
		return directoryIdText(Id(target.GetSidecarId())), nil
	default:
		sum := sha256.Sum256(target.GetSocketToken())
		return hex.EncodeToString(sum[:16]), nil
	}
}

// q/<h>/<tgt>/: the prefix every notice to target sits under, which its approvers lease (§11.10).
func DirectoryNoticePrefix(target *protocol.RequestTarget) (string, error) {
	name, err := DirectoryNoticeTarget(target)
	if err != nil {
		return "", err
	}
	return "q/" + directoryShard(name) + "/" + name + "/", nil
}

// q/<h>/<tgt>/<rid>: the notice of request requestId to target, which its requester leases.
func DirectoryNoticePath(target *protocol.RequestTarget, requestId Id) (string, error) {
	prefix, err := DirectoryNoticePrefix(target)
	if err != nil {
		return "", err
	}
	return prefix + directoryIdText(requestId), nil
}
