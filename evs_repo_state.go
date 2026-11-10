//go:build !sidecar_http

// repo/<repo> (§11.8's repo/ row, §11.12, D-EVS-11, D-EVS-19, evs-1): one repo's server-held record on its metadata
// cluster: its kind and owner, fixed at creation from the projection, its network (plan-EVSB-repo-network), its object
// format (§11.6), its sealed display name and its lifecycle state. evs writes it, and evs, gkm and taskworker reread
// it before they act (§10.6's checks row, §11.13's skip row), so the codec and the state machine live here, in the
// root, where each engine imports them.
//
// The state machine (§11.12's deletion rows), every transition one If-Match on repo/:
//
//	keying    -> active                         activate, once KF1's group has its first generation
//	active    -> deleted{id, time, signer}      DELETE with its projected RepoDelete
//	active    -> shredding{id, time}            DELETE with its projected RepoDelete{now}
//	deleted   -> active                         restore with a projected RepoRestore of its deletion id
//	deleted   -> shredding{id, time}            the 7-day start, or DELETE under a newer RepoDelete{now}
//	shredding -> shredded{id, time}             the shred's last step: a tombstone kept with place/
//
// Every state past active carries the deletion id of the RepoDelete that began it, the incarnation a shred job
// rereads, so a stale job of an earlier deletion deletes nothing. The repo id, kind, owner and network never change,
// and the format only rises, from 1 to 2. A parse is lenient about which state carries which deletion fields, since
// a reader acts on the state alone and a shred acts only on a matching deletion id, which a missing one never is; a
// transition is held to them.
//
// A host file's tag, as evs_repo_place.go's: it names BlobCluster. Package-level functions are safe for concurrent
// use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The family's prefix, on each repo's own metadata cluster.
const EvsRepoObjectKeyPrefix = "repo/"

// §11.8's bound on repo/'s bytes.
const EvsRepoObjectMaxByteCount = 4 * 1024

// The formats a repo may be in (§11.6): 1, and 2 from its first push carrying a format-2 value.
const (
	EvsRepoFormat1 = 1
	EvsRepoFormat2 = 2
)

var (
	// No repo/ object: a placed repo whose create has not written it yet, or a key never created.
	ErrEvsRepoNotFound = errors.New("evs repo not found")
	// A repo/ object whose bytes break its shape: a fault that alarms, never a state to act on.
	ErrEvsRepoInvalid = errors.New("evs repo object invalid")
	// A next repo/ the state machine does not take from the prior one: the caller's bug, never written.
	ErrEvsRepoTransition = errors.New("evs repo transition refused")
)

// repo/<repo_id>.
func EvsRepoObjectKey(repoId Id) string {
	return EvsRepoObjectKeyPrefix + EvsKeyId(repoId)
}

// Whether kind is one of acl.proto's nine (§11.12's kinds table).
func EvsRepoKindKnown(kind protocol.RepoKind) bool {
	_, ok := protocol.RepoKind_name[int32(kind)]
	return ok && kind != protocol.RepoKind_REPO_KIND_UNSPECIFIED
}

// Whether kind binds an owner member (D-EVS-11): vault, mailbox and secret.
func EvsRepoKindOwnerBound(kind protocol.RepoKind) bool {
	return aclRepoKindOwnerBound(kind)
}

// repo/'s bytes held to their shape: its bound, a 16-byte repo id equal to the key's, a kind acl.proto has, a state
// EvsRepoState has, format 1 or 2, and ids of 16 bytes or none: the network (plan-EVSB-repo-network: absent reads as
// held), the owner, the deletion id and the deletion's signer.
func ParseEvsRepoObject(repoId Id, objectBytes []byte) (*protocol.EvsRepoObject, error) {
	if EvsRepoObjectMaxByteCount < len(objectBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrEvsRepoInvalid, len(objectBytes))
	}
	object := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(objectBytes, object); err != nil {
		return nil, fmt.Errorf("%w: does not parse", ErrEvsRepoInvalid)
	}
	if !bytes.Equal(object.GetRepoId(), repoId.Bytes()) {
		return nil, fmt.Errorf("%w: another repo's id", ErrEvsRepoInvalid)
	}
	if !EvsRepoKindKnown(object.GetKind()) {
		return nil, fmt.Errorf("%w: kind %d", ErrEvsRepoInvalid, object.GetKind())
	}
	if object.GetState() < protocol.EvsRepoState_EVS_REPO_KEYING || protocol.EvsRepoState_EVS_REPO_SHREDDED < object.GetState() {
		return nil, fmt.Errorf("%w: state %d", ErrEvsRepoInvalid, object.GetState())
	}
	if object.GetFormat() != EvsRepoFormat1 && object.GetFormat() != EvsRepoFormat2 {
		return nil, fmt.Errorf("%w: format %d", ErrEvsRepoInvalid, object.GetFormat())
	}
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{name: "network id", value: object.GetNetworkId()},
		{name: "owner", value: object.GetOwnerMemberId()},
		{name: "deletion id", value: object.GetDeletionId()},
		{name: "deletion's signer", value: object.GetStateSigner()},
	} {
		if length := len(field.value); length != 0 && length != 16 {
			return nil, fmt.Errorf("%w: a %s of %d bytes", ErrEvsRepoInvalid, field.name, length)
		}
	}
	return object, nil
}

// repo/'s bytes for object, deterministic, held to ParseEvsRepoObject's shape.
func MarshalEvsRepoObject(object *protocol.EvsRepoObject) ([]byte, error) {
	objectBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(object)
	if err != nil {
		return nil, err
	}
	repoId, err := IdFromBytes(object.GetRepoId())
	if err != nil {
		return nil, fmt.Errorf("%w: a repo id of %d bytes", ErrEvsRepoInvalid, len(object.GetRepoId()))
	}
	if _, err := ParseEvsRepoObject(repoId, objectBytes); err != nil {
		return nil, err
	}
	return objectBytes, nil
}

// Whether next is a write the state machine takes over prior (see the file header): the same repo id, kind, owner
// and network; a format that does not fall; and a state change on its edges, each state past active naming its
// deletion id, a deleted one its signer too, keying and active naming none. Equal states are a write that changes
// no state (a format rising), which keeps the deletion fields.
func CheckEvsRepoTransition(prior *protocol.EvsRepoObject, next *protocol.EvsRepoObject) error {
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrEvsRepoTransition, fmt.Sprintf(format, args...))
	}
	if !bytes.Equal(prior.GetRepoId(), next.GetRepoId()) || prior.GetKind() != next.GetKind() ||
		!bytes.Equal(prior.GetOwnerMemberId(), next.GetOwnerMemberId()) || !bytes.Equal(prior.GetNetworkId(), next.GetNetworkId()) {
		return refuse("the repo id, kind, owner and network never change")
	}
	if next.GetFormat() < prior.GetFormat() {
		return refuse("format %d after %d", next.GetFormat(), prior.GetFormat())
	}
	from, to := prior.GetState(), next.GetState()
	deletionFields := func() error {
		switch to {
		case protocol.EvsRepoState_EVS_REPO_KEYING, protocol.EvsRepoState_EVS_REPO_ACTIVE:
			if len(next.GetDeletionId()) != 0 || len(next.GetStateSigner()) != 0 {
				return refuse("%s naming a deletion", to)
			}
		case protocol.EvsRepoState_EVS_REPO_DELETED:
			if len(next.GetDeletionId()) != 16 || len(next.GetStateSigner()) != 16 {
				return refuse("deleted naming no deletion or signer")
			}
		default:
			if len(next.GetDeletionId()) != 16 {
				return refuse("%s naming no deletion", to)
			}
		}
		return nil
	}
	if from == to {
		if !bytes.Equal(prior.GetDeletionId(), next.GetDeletionId()) || prior.GetStateMs() != next.GetStateMs() {
			return refuse("a write in %s changing its deletion", to)
		}
		return nil
	}
	if err := deletionFields(); err != nil {
		return err
	}
	switch {
	case from == protocol.EvsRepoState_EVS_REPO_KEYING && to == protocol.EvsRepoState_EVS_REPO_ACTIVE:
	case from == protocol.EvsRepoState_EVS_REPO_ACTIVE && to == protocol.EvsRepoState_EVS_REPO_DELETED:
	case from == protocol.EvsRepoState_EVS_REPO_ACTIVE && to == protocol.EvsRepoState_EVS_REPO_SHREDDING:
	case from == protocol.EvsRepoState_EVS_REPO_DELETED && to == protocol.EvsRepoState_EVS_REPO_ACTIVE:
	case from == protocol.EvsRepoState_EVS_REPO_DELETED && to == protocol.EvsRepoState_EVS_REPO_SHREDDING:
	case from == protocol.EvsRepoState_EVS_REPO_SHREDDING && to == protocol.EvsRepoState_EVS_REPO_SHREDDED:
		if !bytes.Equal(prior.GetDeletionId(), next.GetDeletionId()) {
			return refuse("a shred finishing another deletion")
		}
	default:
		return refuse("%s to %s", from, to)
	}
	return nil
}

// repo/ as one cluster read finds it, with the ETag a transition's If-Match names. ErrEvsRepoNotFound for a 404,
// ErrEvsRepoInvalid for bytes that break its shape.
func ReadEvsRepoObject(ctx context.Context, cluster BlobCluster, repoId Id) (*protocol.EvsRepoObject, string, error) {
	object, err := cluster.Get(ctx, EvsRepoObjectKey(repoId))
	if errors.Is(err, ErrBlobNotFound) {
		return nil, "", ErrEvsRepoNotFound
	}
	if err != nil {
		return nil, "", err
	}
	defer object.Body.Close()
	objectBytes, err := io.ReadAll(io.LimitReader(object.Body, EvsRepoObjectMaxByteCount+1))
	if err != nil {
		return nil, "", err
	}
	parsed, err := ParseEvsRepoObject(repoId, objectBytes)
	if err != nil {
		return nil, "", err
	}
	return parsed, object.Etag, nil
}
