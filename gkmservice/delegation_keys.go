// A forwarding Delegation's reader key at gkm (KEYS-M8-01; D-KEYS-16, D-KEYS-24; owner decision 197; DESIGN-DETAILS
// 4.2.2): PUT and GET /gkm/delegation-keys/<delegation_id>, over gkm/dkey/<delegation_id> on the first cluster, which
// holds the Delegation's 1,216 B X-Wing public key as its statement names it. The Delegation's row carries the key's
// SHA-256 alone, since 1,216 B a device would pass §8.8's 4 MiB of rows at about 2,600 app devices.
//
//   - An upload is the Delegation's own sidecar's: the row in gkm's newest verified state names the token's sidecar
//     as the forwarding Delegation's, and the body's SHA-256 is the row's reader_key_sha256. Until that state holds
//     the row the upload answers 409, which the signer's setup sends again once it does (DESIGN-DETAILS 4.2.6's S3).
//     The object is created once, If-None-Match: the same bytes again answer 200, so a retry after a lost answer is
//     safe, and other bytes cannot stand there, since only bytes that hash to the one digest are ever written.
//   - A read is any token that reads the network's config repo, a forwarding Delegation's whole reach, and serves the
//     stored bytes as they are: gkm proves nothing by serving them, and a sealer holds them to the row's digest
//     before it seals to them (sidecar.GkmForwardingReaderKey).
//   - The reconciler deletes the object 24 h after its Delegation ended or was superseded (reconciler.go).
//
// A Delegation that does not forward keeps its key in its row, so it takes no object here.

package gkmservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/urnetwork/sidecar"
)

// The object's bytes: an X-Wing public key (§10.6's sizes), a format value.
const gkmDelegationKeyByteCount = 1216

// The bytes of a delegation_id (§10.5: SHA-256 of the Signed Delegation), a format value.
const gkmDelegationIdByteCount = 32

// A delegation_id in a path: 64 lowercase hex characters, the form object keys take (QD-442).
func parseGkmDelegationId(text string) ([]byte, error) {
	if len(text) != 2*gkmDelegationIdByteCount || strings.ToLower(text) != text {
		return nil, fmt.Errorf("%w: not 64 lowercase hex characters", sidecar.ErrGkmMalformed)
	}
	delegationId, err := hex.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("%w: not hex", sidecar.ErrGkmMalformed)
	}
	return delegationId, nil
}

// The route's delegation_id. false once it has answered 400.
func readGkmDelegationIdPath(request *GkmRequest) ([]byte, bool) {
	delegationId, err := parseGkmDelegationId(request.Http.PathValue(gkmPathValueDelegationId))
	if err != nil {
		request.BadRequest()
		return nil, false
	}
	return delegationId, true
}

// What gkm's newest state holds of the Delegation's reader key, answering Unknown with 503. ok false once it has
// answered; found false for a Delegation the state holds no row of.
func (self *GkmEngine) delegationKeyFacts(request *GkmRequest, delegationId []byte) (facts *GkmDelegationKeyFacts, found bool, ok bool) {
	facts, answer := self.deps.AuthState.DelegationKey(request.Principal, delegationId)
	switch answer {
	case GkmAuthAllowed:
		if facts == nil || len(facts.ReaderKeySha256) != sha256.Size {
			// a state that answers with no digest cannot be told apart from one that is wrong
			request.Unavailable()
			return nil, false, false
		}
		return facts, true, true
	case GkmAuthDenied:
		return nil, false, true
	}
	request.Unavailable()
	return nil, false, false
}

// PUT /gkm/delegation-keys/<delegation_id>: a forwarding Delegation's reader key, by the sidecar that signed it.
func (self *GkmEngine) serveDelegationKeyUpload(request *GkmRequest) {
	delegationId, ok := readGkmDelegationIdPath(request)
	if !ok {
		return
	}
	body, ok := request.ReadBody(gkmDelegationKeyByteCount)
	if !ok {
		return
	}
	if len(body) != gkmDelegationKeyByteCount {
		request.BadRequest()
		return
	}
	facts, found, ok := self.delegationKeyFacts(request, delegationId)
	switch {
	case !ok:
		return
	case !found:
		// gkm's state does not hold the row yet: the signer sends the same bytes again once it does
		request.Conflict(nil)
		return
	case facts.ForwardSidecarId == nil || *facts.ForwardSidecarId != request.SidecarId:
		// a Delegation that does not forward keeps its key in its row, and only its own sidecar uploads one's
		request.Forbidden()
		return
	case !bytes.Equal(sha256Of(body), facts.ReaderKeySha256):
		// not the key the row names
		request.Forbidden()
		return
	}
	cluster, err := self.firstCluster()
	if err != nil {
		request.Unavailable()
		return
	}
	key, err := GkmDelegationKeyKey(delegationId)
	if err != nil {
		request.BadRequest()
		return
	}
	// a delegation key is §11.13's P1, on the first cluster, as a ReaderKey is (budget.go)
	writeCtx, ok := request.SpendWrites(cluster, "", self.settings.Prices.create(len(body)))
	if !ok {
		return
	}
	barrierKey := hex.EncodeToString(delegationId)
	testHookBarrier(BarrierDelegationKeyPutBefore, barrierKey)
	winner, err := createGkmObject(writeCtx, cluster, key, body, gkmDelegationKeyByteCount)
	testHookBarrier(BarrierDelegationKeyPutAfter, barrierKey)
	switch {
	case err != nil:
		self.answerStoreError(request, err)
	case winner != nil:
		// every stored object was held to the one digest, so other bytes there are the store's fault
		self.alarm("delegation_key_conflict", errors.New("a forwarding Delegation's key object holds other bytes"))
		request.Conflict(winner)
	default:
		request.Reply(nil)
	}
}

// GET /gkm/delegation-keys/<delegation_id>: a forwarding Delegation's reader key, byte for byte, to a token that
// reads the network's config repo.
func (self *GkmEngine) serveDelegationKeyRead(request *GkmRequest) {
	delegationId, ok := readGkmDelegationIdPath(request)
	if !ok {
		return
	}
	facts, found, ok := self.delegationKeyFacts(request, delegationId)
	switch {
	case !ok:
		return
	case !found || facts.ForwardSidecarId == nil:
		// a row gkm's state does not hold, or a Delegation whose key is in its row: no object to serve
		request.NotFound()
		return
	}
	if !request.AuthorizeRepo(facts.ConfigRepoId) {
		return
	}
	cluster, err := self.firstCluster()
	if err != nil {
		request.Unavailable()
		return
	}
	key, err := GkmDelegationKeyKey(delegationId)
	if err != nil {
		request.BadRequest()
		return
	}
	held, _, err := readGkmObject(request.Ctx, cluster, key, gkmDelegationKeyByteCount)
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
		request.NotFound()
	case err != nil:
		self.answerStoreError(request, err)
	default:
		request.ReplyBytes(200, held)
	}
}
