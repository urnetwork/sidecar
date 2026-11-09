// GET /gkm/welcomes (§10.6's Welcomes row, QD-526 row 4): each Welcome pointer gkm/welcome/<sidecar_id>/<ref> of the
// token's own sidecar, on the first cluster, with the Welcome gkm/<group_id>/welcome/<n> it points to, on the group's
// repo's cluster, which no other route serves.
//
// A pointer is answered only where the token reaches its group: r, rw or admin on the repo whose GroupForms name
// it, honored by the newest verified state, as every group read is. A client whose repos span several tokens
// (§7.8's 64 scopes) asks once with each. A pointer whose Welcome is not there, which only a crash between the two
// writes leaves (KEYS-M2-14 writes the Welcome first), is passed over; the reconciler removes pointers once every
// recipient acked, at most 90 days (gkm-5, KEYS-M2-16), and a device skips a Welcome it has joined.
//
// POST /gkm/groups/<id>/welcome/<n> (KEYS-M2-14) writes them: a Welcome is written only after its epoch object, by
// that epoch's uploader, so a 409's loser never has one (§10.6's Welcomes row, KF6), at gkm/<group_id>/welcome/<n>
// If-None-Match, then one pointer {group_id, n} per recipient at gkm/welcome/<sidecar_id>/<ref> If-None-Match, each
// recipient a reader of the repo in gkm's newest state, and a welcome hint to each. Equal bytes answer success, so a
// retry finishes what a crash left. A pointer key another Welcome already holds is never overwritten: that is a
// last-resort KeyPackage serving two Adds before its first was acked, which question
// keys-m2-13-last-resort-welcome-pointer asks about, and until it is answered the standing pointer keeps its Welcome
// reachable, the second join waits for §10.6's re-add after 10 minutes, and the collision is counted and alarmed.

package gkmservice

import (
	"bytes"
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

// POST /gkm/groups/<id>/welcome/<n>: a GkmWelcomeRequest, epoch n's Welcome and its recipients, by n's uploader.
func (self *GkmEngine) serveWelcomeWrite(request *GkmRequest) {
	groupId := *request.GroupId
	epoch, err := parseGkmNumber(request.Http.PathValue(gkmPathValueEpoch))
	if err != nil || epoch == 0 {
		request.BadRequest()
		return
	}
	welcomeRequest := &protocol.GkmWelcomeRequest{}
	if !request.ReadMessage(welcomeRequest, self.settings.RequestBodyMaxByteCount) {
		return
	}
	welcome := welcomeRequest.GetWelcome()
	recipients := welcomeRequest.GetRecipients()
	if len(welcome) == 0 || self.settings.ObjectMaxByteCount < int64(len(welcome)) ||
		len(recipients) == 0 || self.settings.WelcomeRecipientMaxCount < len(recipients) {
		request.BadRequest()
		return
	}
	type pointerTarget struct {
		sidecarId sidecar.Id
		key       string
	}
	targets := make([]*pointerTarget, 0, len(recipients))
	seenKeys := map[string]bool{}
	for _, recipient := range recipients {
		sidecarId, err := sidecar.IdFromBytes(recipient.GetSidecarId())
		if err != nil || sidecarId == (sidecar.Id{}) {
			request.BadRequest()
			return
		}
		key, err := GkmWelcomePointerKey(sidecarId, recipient.GetKeyPackageRef())
		if err != nil || seenKeys[key] {
			request.BadRequest()
			return
		}
		seenKeys[key] = true
		targets = append(targets, &pointerTarget{sidecarId: sidecarId, key: key})
	}
	now := request.Now()
	for _, target := range targets {
		// a joiner reads the repo in gkm's newest state, or no Welcome of its group is any of its business
		switch self.deps.AuthState.Reads(request.Principal, request.RepoId, target.sidecarId, now) {
		case GkmAuthAllowed:
		case GkmAuthDenied:
			request.Forbidden()
			return
		default:
			request.Unavailable()
			return
		}
	}
	epochObject, _, err := self.readEpoch(request.Ctx, request.Cluster, groupId, epoch)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		// written only after its epoch object
		request.NotFound()
		return
	}
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if !bytes.Equal(epochObject.GetUploader(), request.SidecarId.Bytes()) {
		// by its uploader only
		request.Forbidden()
		return
	}
	if !request.CheckRepoWritable() {
		return
	}
	barrierKey := gkmBarrierNumberKey(groupId, epoch)
	testHookBarrier(BarrierWelcomePutBefore, barrierKey)
	winner, err := createGkmObject(request.Ctx, request.Cluster, GkmWelcomeKey(groupId, epoch), welcome, self.settings.ObjectMaxByteCount)
	testHookBarrier(BarrierWelcomePutAfter, barrierKey)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if winner != nil {
		request.Conflict(winner)
		return
	}
	firstCluster, err := self.firstCluster()
	if err != nil {
		request.Unavailable()
		return
	}
	pointerBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmWelcomePointer{GroupId: groupId.Bytes(), Epoch: epoch})
	if err != nil {
		request.Unavailable()
		return
	}
	hintedSidecarIds := []sidecar.Id{}
	for _, target := range targets {
		winner, err := createGkmObject(request.Ctx, firstCluster, target.key, pointerBytes, self.settings.ObjectMaxByteCount)
		if err != nil {
			// a retry finds the Welcome and the pointers written so far standing, and writes the rest
			self.answerStoreError(request, err)
			return
		}
		if winner != nil {
			self.alarm("welcome_pointer_taken", errors.New("a Welcome pointer's key holds another Welcome's pointer"))
			continue
		}
		hintedSidecarIds = append(hintedSidecarIds, target.sidecarId)
	}
	self.hintWork(hintedSidecarIds, protocol.GkmHintKind_GKM_HINT_WELCOME, &groupId, epoch, nil)
	request.Reply(nil)
}
