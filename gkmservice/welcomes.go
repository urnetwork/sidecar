// GET /gkm/welcomes (§10.6's Welcomes row, QD-526 row 4): each Welcome pointer
// gkm/welcome/<sidecar_id>/<group_id>/<n> of the token's own sidecar, on the first cluster, with the Welcome
// gkm/<group_id>/welcome/<n> it points to, on the group's repo's cluster, which no other route serves.
//
// A pointer is answered only where the token reaches its group: r, rw or admin on the repo whose GroupForms name
// it, honored by the newest verified state, as every group read is. A client whose repos span several tokens
// (§7.8's 64 scopes) asks once with each. A pointer whose Welcome is not there, which only a crash between the two
// writes leaves (KEYS-M2-14 writes the Welcome first), is passed over; the reconciler removes a pointer at its
// recipient's first ack past its epoch, at most 90 days (gkm-5, KEYS-M2-16), and a device holding several pointers
// for one group takes the one with the highest epoch above the newest it reached and skips the rest.
//
// POST /gkm/groups/<id>/welcome/<n> (KEYS-M2-14) writes them: a Welcome is written only after its epoch object, by
// that epoch's uploader, so a 409's loser never has one (§10.6's Welcomes row, KF6), at gkm/<group_id>/welcome/<n>
// If-None-Match, then one pointer {group_id, n, ref} per recipient If-None-Match, each recipient a reader of the
// repo in gkm's newest state, and a welcome hint to each. Equal bytes answer success, so a retry finishes what a
// crash left. A pointer is keyed by its group and epoch, never by the KeyPackageRef its Add used (DESIGN-DETAILS
// 6.2.2): one Welcome, one key, so a last-resort KeyPackage that served two Adds leaves two pointers, and the ref
// rides in the pointer for the joiner to open the Welcome with. A pointer key that holds other bytes is the same
// epoch's Welcome naming another KeyPackage for the recipient, which only its one uploader could send: 409.
//
// HEAD /gkm/groups/<id>/welcome/<n> (QD-747) answers whether epoch n's Welcome stands, 200 or 404 with no body, under
// rw: what a writer leaf that adopted an Add another leaf uploaded asks once after WelcomeTimeout, before it removes
// and adds the joiner again (§10.6's Welcomes row). It discloses nothing beyond gkm-5's Welcome objects, whose keys
// every reader can compute. gkm originates nothing here that a client acts on unchecked: a false 200 leaves the
// joiner waiting, and a false 404 costs one Remove and Add, which every member checks as any commit.

package gkmservice

import (
	"bytes"
	"errors"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// GET /gkm/welcomes: a GkmWelcomesReply.
func (self *GkmEngine) serveWelcomes(request *GkmRequest) {
	cluster, err := self.firstCluster()
	if err != nil {
		request.Unavailable()
		return
	}
	prefix := GkmWelcomePointerPrefix(request.SidecarId)
	infos, err := listGkmKeys(request.Ctx, cluster, prefix, self.settings.ListPageCount, self.settings.WelcomePointerListMaxCount)
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
		keyGroupId, keyEpoch, ok := parseGkmWelcomePointerKey(prefix, info.Key)
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
		if groupId != keyGroupId || pointer.GetEpoch() != keyEpoch || len(pointer.GetKeyPackageRef()) != gkmKeyPackageRefByteCount {
			// a pointer names what its key does, and the ref its Welcome opens with
			self.alarm("welcome_pointer_invalid", errors.New("a Welcome pointer that disagrees with its key"))
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
			KeyPackageRef: pointer.GetKeyPackageRef(),
			Pointer:       pointer,
			Welcome:       welcome,
		})
	}
	request.Reply(reply)
}

// HEAD /gkm/groups/<id>/welcome/<n>: 200 when gkm/<group_id>/welcome/<n> exists, 404 when it does not, no body
// either way. A store that does not answer is 503, never a 404, so a leaf removes no joiner on a fault.
func (self *GkmEngine) serveWelcomeStands(request *GkmRequest) {
	groupId := *request.GroupId
	epoch, err := parseGkmNumber(request.Http.PathValue(gkmPathValueEpoch))
	if err != nil || epoch == 0 {
		// epoch 0 is a creation's, which adds no one
		request.BadRequest()
		return
	}
	_, err = request.Cluster.Head(request.Ctx, GkmWelcomeKey(groupId, epoch))
	switch {
	case err == nil:
		request.ReplyBytes(http.StatusOK, nil)
	case errors.Is(err, sidecar.ErrBlobNotFound):
		request.NotFound()
	default:
		self.answerStoreError(request, err)
	}
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
		ref       []byte
	}
	targets := make([]*pointerTarget, 0, len(recipients))
	seenKeys := map[string]bool{}
	for _, recipient := range recipients {
		sidecarId, err := sidecar.IdFromBytes(recipient.GetSidecarId())
		if err != nil || sidecarId == (sidecar.Id{}) {
			request.BadRequest()
			return
		}
		ref := recipient.GetKeyPackageRef()
		key := GkmWelcomePointerKey(sidecarId, groupId, epoch)
		if len(ref) != gkmKeyPackageRefByteCount || seenKeys[key] {
			// one leaf per recipient in one commit, each under a KeyPackage's ref
			request.BadRequest()
			return
		}
		seenKeys[key] = true
		targets = append(targets, &pointerTarget{sidecarId: sidecarId, key: key, ref: ref})
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
	// Welcomes and their pointers are §11.13's P1, the Welcome on the repo's cluster and the pointers on the first
	// (budget.go)
	welcomeCtx, ok := request.SpendWrites(request.Cluster, "", self.settings.Prices.create(len(welcome)))
	if !ok || !request.CheckRepoWritable() {
		return
	}
	barrierKey := gkmBarrierNumberKey(groupId, epoch)
	testHookBarrier(BarrierWelcomePutBefore, barrierKey)
	winner, err := createGkmObject(welcomeCtx, request.Cluster, GkmWelcomeKey(groupId, epoch), welcome, self.settings.ObjectMaxByteCount)
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
	pointerBytes := make([][]byte, 0, len(targets))
	pointersPrice := int64(0)
	for _, target := range targets {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmWelcomePointer{
			GroupId:       groupId.Bytes(),
			Epoch:         epoch,
			KeyPackageRef: target.ref,
		})
		if err != nil {
			request.Unavailable()
			return
		}
		pointerBytes = append(pointerBytes, encoded)
		pointersPrice += self.settings.Prices.create(len(encoded))
	}
	pointersCtx, ok := request.SpendWrites(firstCluster, "", pointersPrice)
	if !ok {
		// a retry finds the Welcome standing and writes the pointers
		return
	}
	hintedSidecarIds := []sidecar.Id{}
	for i, target := range targets {
		winner, err := createGkmObject(pointersCtx, firstCluster, target.key, pointerBytes[i], self.settings.ObjectMaxByteCount)
		if err != nil {
			// a retry finds the Welcome and the pointers written so far standing, and writes the rest
			self.answerStoreError(request, err)
			return
		}
		if winner != nil {
			// this epoch's Welcome already points the recipient at another KeyPackage: the uploader's own earlier
			// request with other recipients, never another Welcome's pointer
			request.Conflict(winner)
			return
		}
		hintedSidecarIds = append(hintedSidecarIds, target.sidecarId)
	}
	self.hintWork(hintedSidecarIds, protocol.GkmHintKind_GKM_HINT_WELCOME, &groupId, epoch, nil)
	request.Reply(nil)
}
