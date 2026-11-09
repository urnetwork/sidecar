// GET /gkm/welcomes (§10.6's Welcomes row, QD-526 row 4): each Welcome pointer gkm/welcome/<sidecar_id>/<ref> of the
// token's own sidecar, on the first cluster, with the Welcome gkm/<group_id>/welcome/<n> it points to, on the group's
// repo's cluster, which no other route serves.
//
// A pointer is answered only where the token reaches its group: r, rw or admin on the repo whose GroupForms name
// it, honored by the newest verified state, as every group read is. A client whose repos span several tokens
// (§7.8's 64 scopes) asks once with each. A pointer whose Welcome is not there, which only a crash between the two
// writes leaves (KEYS-M2-14 writes the Welcome first), is passed over; the reconciler removes pointers once every
// recipient acked, at most 90 days (gkm-5, KEYS-M2-16), and a device skips a Welcome it has joined.

package gkmservice

import (
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The most keys one sidecar's welcome/ prefix may hold before a read of it alarms.
const gkmWelcomePointerListMaxCount = 64 * 1024

// GET /gkm/welcomes: a GkmWelcomesReply.
func (self *GkmEngine) serveWelcomes(request *GkmRequest) {
	cluster, err := self.firstCluster()
	if err != nil {
		request.Unavailable()
		return
	}
	prefix := GkmWelcomePointerPrefix(request.SidecarId)
	infos, err := listGkmKeys(request.Ctx, cluster, prefix, self.settings.ListPageCount, gkmWelcomePointerListMaxCount)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	reply := &protocol.GkmWelcomesReply{}
	now := request.Now()
	candidateRepoIds := request.scopes.reposWith(gkmRepoAccessRights)
	for _, info := range infos {
		if self.settings.WelcomesReplyMaxCount <= len(reply.GetWelcomes()) {
			break
		}
		ref, ok := parseGkmWelcomePointerKey(prefix, info.Key)
		if !ok {
			continue
		}
		pointerBytes, _, err := readGkmObject(request.Ctx, cluster, info.Key, self.settings.ObjectMaxByteCount)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			continue
		}
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		pointer := &protocol.GkmWelcomePointer{}
		if err := proto.Unmarshal(pointerBytes, pointer); err != nil {
			self.alarm("welcome_pointer_invalid", err)
			continue
		}
		groupId, err := sidecar.IdFromBytes(pointer.GetGroupId())
		if err != nil {
			self.alarm("welcome_pointer_invalid", err)
			continue
		}
		repoId, found, err := self.resolveGroup(request.Ctx, groupId, candidateRepoIds, false)
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		if !found {
			// this token does not reach the group: another of the client's tokens may
			continue
		}
		right := gkmStrongestRight(request.scopes.repoIdRights[repoId] & gkmRepoAccessRights)
		switch self.deps.AuthState.HonorScope(request.Principal, repoId, right, now) {
		case GkmAuthAllowed:
		case GkmAuthDenied:
			continue
		default:
			request.Unavailable()
			return
		}
		groupCluster, _, err := self.places.Cluster(request.Ctx, repoId)
		if err != nil {
			request.Unavailable()
			return
		}
		welcome, _, err := readGkmObject(request.Ctx, groupCluster, GkmWelcomeKey(groupId, pointer.GetEpoch()), self.settings.ObjectMaxByteCount)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			continue
		}
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		reply.Welcomes = append(reply.Welcomes, &protocol.GkmWelcomeEntry{
			KeyPackageRef: ref,
			Pointer:       pointer,
			Welcome:       welcome,
		})
	}
	request.Reply(reply)
}
