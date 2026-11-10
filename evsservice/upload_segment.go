// PUT /evs/v1/repos/<id>/segments/<sid>?push=<push_id>[&closure=1] (§11.13's uploads table, §11.20; EVSB-M2-09):
// a client's segment, streamed straight to seg/<repo>/<sid> on the segment cluster, If-None-Match with its id as
// its checksum, never held in memory. The route takes rw or deposit; ?closure=1 takes admin, the team directory's
// included, refused before any write (I-EVS-16). In order, before the body moves:
//
//  1. the repo's facts from the projection, and the body's length, known and within a segment's 8 MiB;
//  2. the storage gate (quota_gate.go): a closure upload through ChargeClosure, any other through CheckUpload,
//     §20.7's QuotaRefusal on a refusal;
//  3. 507 CLUSTER_FULL, which EVSB-M3-02 adds;
//  4. the segment cluster's HDD share (hdd_admission.go): 503 with Retry-After past its line, an authorization or
//     closure upload exempt;
//  5. the 32 B public header: "URvs", format 1 with no flags, this repo and a generation; format 1 refuses a kind-5
//     header FORMAT_UNSUPPORTED {needs_format: 2}, and format 2 adds 409 VERSIONING and the versionless mark at M10.
//
// A stored segment answers 200 {EvsUploadReceipt} (upload_receipt.go), adds its size to the repo network's stored
// bytes through the usage batcher, counts toward the segment cluster's PUTs a second (HddAdmission.CountPut), and
// writes nothing to the metadata cluster. One that exists (412) is HEADed once: its LastModified is upload_ms, or
// 409 SEGMENT_STALE past 23 h, so the client re-seals. The checksum is the store's to verify, and a body that is
// not the id it names writes nothing (400).

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §11.6's segment: at most 8 MiB, a 32 B public header, format 2's kind-5 header 48 B.
const (
	evsSegmentMaxByteCount        = 8 * 1024 * 1024
	evsSegmentHeaderByteCount     = 32
	evsSegmentHeaderFormat1       = 1
	evsSegmentHeaderFormatKind5   = 2
	evsSegmentPathValue           = "segment_id"
	evsUploadClosureQueryValue    = "1"
	evsUploadClosureDebitDomain   = "UR evs 1.0 closure debit"
	evsSegmentHeaderMagic         = "URvs"
	evsUploadSegmentRouteTemplate = "PUT /evs/v1/repos/{repo_id}/segments/{segment_id}"
)

// What the upload route needs beyond the engine's. A nil one, or one missing its keys, gate or batcher, answers
// every upload 503.
type EvsUploadDeps struct {
	Keys  *ReceiptKeys
	Quota *QuotaGate
	// The segment cluster's HDD share. nil admits every upload, as a cluster with no measured capacity does.
	Hdd   *HddAdmission
	Usage *UsageBatcher
	// nil takes the defaults.
	Settings *UploadReceiptSettings
}

// The upload route.
func (self *EvsEngine) uploadRoutes() []*EvsRoute {
	return []*EvsRoute{
		{
			Method:        http.MethodPut,
			Pattern:       evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}/segments/{" + evsSegmentPathValue + "}",
			Name:          evsUploadSegmentRouteTemplate,
			Rights:        sidecar.AclEvsWrite | sidecar.AclEvsDeposit | sidecar.AclEvsAdmin,
			Write:         true,
			Placed:        true,
			RefuseDeleted: true,
			Serve:         self.serveUploadSegment,
		},
	}
}

// A segment id in a path: 64 lowercase hex characters.
func parseEvsSegmentId(text string) ([32]byte, bool) {
	var segmentId [32]byte
	if len(text) != 64 || strings.ToLower(text) != text {
		return segmentId, false
	}
	if _, err := hex.Decode(segmentId[:], []byte(text)); err != nil {
		return segmentId, false
	}
	return segmentId, true
}

// §20.7's QuotaRefusal as evs answers it: 429 RESOURCE_EXHAUSTED for a rate's, 402 QUOTA_PAYMENT where a purchase
// lifts it, else QUOTA_LIMIT.
func evsQuotaRefusalReply(refusal *sidecar.QuotaRefusal) *protocol.EvsRefusalReply {
	code := protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT
	switch {
	case 0 < refusal.RetryAfterMs:
		code = protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED
	case refusal.Upgrade:
		code = protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT
	}
	return &protocol.EvsRefusalReply{
		Code:         code,
		RetryAfterMs: refusal.RetryAfterMs,
		Quota: &protocol.EvsQuotaRefusal{
			LimitKey:     refusal.LimitKey,
			Limit:        refusal.Limit,
			Used:         refusal.Used,
			RetryAfterMs: refusal.RetryAfterMs,
			Upgrade:      refusal.Upgrade,
		},
	}
}

// See the file header.
func (self *EvsEngine) serveUploadSegment(request *EvsRequest) {
	deps := self.deps.Uploads
	if deps == nil || deps.Keys == nil || deps.Quota == nil || deps.Usage == nil {
		request.Unavailable(nil)
		return
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultUploadReceiptSettings()
	}
	segmentId, ok := parseEvsSegmentId(request.Http.PathValue(evsSegmentPathValue))
	if !ok {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	query := request.Http.URL.Query()
	if _, err := parseEvsHexId(query.Get("push")); err != nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	closure := query.Get("closure") == evsUploadClosureQueryValue
	if closure && !request.RequireRights(sidecar.AclEvsAdmin) {
		return
	}
	facts, answer := self.deps.AuthState.Repo(request.Principal, request.RepoId)
	switch answer {
	case EvsAuthAllowed:
	case EvsAuthDenied:
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING)
		return
	default:
		request.Unavailable(nil)
		return
	}
	byteCount := request.Http.ContentLength
	if byteCount < evsSegmentHeaderByteCount || evsSegmentMaxByteCount < byteCount {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	networkId := connect.Id(facts.NetworkId)

	if closure {
		debitSum := sha256.Sum256(append(append([]byte(evsUploadClosureDebitDomain), segmentId[:]...), request.SidecarId[:]...))
		refusal, err := deps.Quota.ChargeClosure(request.Ctx, networkId, connect.Id(request.SidecarId), byteCount, connect.Id(debitSum[:16]))
		if err != nil {
			request.Unavailable(nil)
			return
		}
		if refusal != nil {
			request.Refuse(evsQuotaRefusalReply(refusal))
			return
		}
	} else if refusal := deps.Quota.CheckUpload(networkId, self.host.GatesOrClosed().Reseed()); refusal != nil {
		request.Refuse(evsQuotaRefusalReply(refusal))
		return
	}

	if deps.Hdd != nil {
		class := HddUploadOrdinary
		switch {
		case closure:
			class = HddUploadClosure
		case facts.Kind == protocol.RepoKind_REPO_KIND_CONFIG || facts.Kind == protocol.RepoKind_REPO_KIND_MAILCFG:
			class = HddUploadAuthorization
		}
		var hddRefusal *HddRefusal
		if err := deps.Hdd.Admit(networkId, byteCount, class); errors.As(err, &hddRefusal) {
			request.Unavailable(&protocol.EvsRefusalReply{RetryAfterMs: uint32(max(0, hddRefusal.RetryAfter.Milliseconds()))})
			return
		}
	}

	header := make([]byte, evsSegmentHeaderByteCount)
	if _, err := io.ReadFull(request.Http.Body, header); err != nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	switch {
	case string(header[0:4]) != evsSegmentHeaderMagic:
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	case header[4] == evsSegmentHeaderFormatKind5:
		request.Refuse(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED, NeedsFormat: 2})
		return
	case header[4] != evsSegmentHeaderFormat1 || header[5] != 0 || header[6] != 0 || header[7] != 0:
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	case sidecar.Id(header[8:24]) != request.RepoId:
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	case binary.BigEndian.Uint64(header[24:32]) == 0:
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}

	segmentCluster, err := self.blobs.SegmentCluster()
	if err != nil {
		request.Unavailable(nil)
		return
	}
	key := SegmentKey(request.RepoId, segmentId)
	uploadTime := request.Now()
	_, err = segmentCluster.PutStream(request.Ctx, key, io.MultiReader(bytes.NewReader(header), request.Http.Body), byteCount, segmentId[:])
	stored := err == nil
	if stored && deps.Hdd != nil {
		// the cluster took the PUT whatever the answer below
		deps.Hdd.CountPut()
	}
	switch {
	case err == nil:
	case errors.Is(err, sidecar.ErrBlobChecksum):
		// the bytes are not the id the path names: nothing was written
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	case errors.Is(err, sidecar.ErrBlobPrecondition):
		// a re-upload: one HEAD, only now, for when it was stored
		info, headErr := segmentCluster.Head(request.Ctx, key)
		if headErr != nil {
			request.Unavailable(nil)
			return
		}
		if settings.ExistingMaxAge < request.Now().Sub(info.LastModified) {
			request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_STALE)
			return
		}
		uploadTime = info.LastModified
	default:
		request.Unavailable(nil)
		return
	}
	receipt, err := IssueUploadReceipt(deps.Keys, request.RepoId, segmentId, uint64(byteCount), uploadTime, request.SidecarId, false, request.Now())
	if err != nil {
		request.Unavailable(nil)
		return
	}
	if stored {
		// a re-upload's bytes were counted when they were first stored; a batcher that will not take them loses
		// them to the nightly count, which corrects the drift (§20.7)
		if err := deps.Usage.AddStored(networkId, byteCount); err != nil {
			self.log.Infof("[evs]stored bytes of an upload not counted: %v\n", err)
		}
	}
	request.Reply(receipt)
}
