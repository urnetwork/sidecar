//go:build !sidecar_http

// HeadCheckProof (§6.4's auth and proven rows, §6.5; D-PROTO-17): how a device shows a peer the
// authorization entries api withholds from it, and how it asks for them.
//
// Serving: HeadCheckProofRequest{after} is answered from the retained tail (§7.9's retain row, which
// every sidecar keeps, phones included): the entries after position after up to this device's proven
// pin, else its auth pin, verbatim, a base as its header only (its rows go by hash from api), at most
// HeadCheckMaxProofByteCount of entries in all. The auth source cuts them (ConfigClient.HeadCheckProof);
// while this device sends a withheld tip as proven, the proof it verified for that tip carries on past
// its own pin, so a peer behind it reaches the tip through it. Kept entries that do not reach back to
// after within the cap answer Error{NOT_FOUND}.
//
// Asking: once api has not served a pin past this device's by HeadCheckFetchTimeout, the transport asks
// the pin's claimant. A proof is acted on only after the auth source verifies it, chain and signatures,
// from this device's A_n to the claimed pin (VerifyAuthProof). Verified, it is proof of withholding;
// anything else, an error, NOT_FOUND, an over-cap or malformed proof, leaves the pin UNVERIFIED.

package sidecar

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The entries' byte count, as the cap counts them.
func headCheckProofByteCount(entries [][]byte) int {
	byteCount := 0
	for _, entry := range entries {
		byteCount += len(entry)
	}
	return byteCount
}

// An entry's position, or false for bytes that are no AuthEntry.
func headCheckEntryPosition(entryBytes []byte) (uint64, bool) {
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil || entry.GetN() == 0 {
		return 0, false
	}
	return entry.GetN(), true
}

// What this device serves a requester at position after: its own kept entries after it through its pin,
// then, while it holds a withheld tip, the verified proof's entries past both. NOT_FOUND past the cap, or
// when the kept entries do not reach back to after.
func (self *headCheckTransport) proofFor(after uint64) ([][]byte, error) {
	entries, err := self.sources.Auth.AuthProof(after)
	if err != nil {
		if errors.Is(err, ErrHeadCheckProofNotFound) {
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_NOT_FOUND}
		}
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
	}
	if served := self.stop.servedProof(); len(served) != 0 {
		through := max(after, self.sources.Auth.Pin().GetVersion())
		for _, entryBytes := range served {
			if position, ok := headCheckEntryPosition(entryBytes); ok && through < position {
				entries = append(entries, entryBytes)
			}
		}
	}
	if HeadCheckMaxProofByteCount < headCheckProofByteCount(entries) {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_NOT_FOUND}
	}
	return entries, nil
}

// HEAD_CHECK_PROOF_REQUEST's handler: any admitted peer may ask, and gets this device's proof or
// NOT_FOUND.
func (self *headCheckTransport) handleProofRequest(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
	if request.Peer == nil {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAUTHENTICATED}
	}
	proofRequest := &protocol.HeadCheckProofRequest{}
	if err := proto.Unmarshal(request.Body, proofRequest); err != nil {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT}
	}
	if !headCheckStanding(self.sources.Peers.HeadCheckPeer(request.Peer.SidecarId)) {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_PERMISSION_DENIED}
	}
	entries, err := self.proofFor(proofRequest.GetAfter())
	if err != nil {
		return nil, err
	}
	self.noteExchanged(request.Peer.SidecarId)
	return proto.Marshal(&protocol.HeadCheckProof{Entries: entries})
}

// Asks the claimant act names for a proof of act.pin from this device's position, verifies what it
// answers, and feeds the outcome to the stop state (headCheckProved): proof of withholding when it
// verifies, the pin UNVERIFIED otherwise.
func (self *headCheckTransport) askProof(ctx context.Context, act headCheckAct) headCheckStep {
	entries, verified := func() ([][]byte, bool) {
		clientId, err := self.resolve(ctx, act.peerId)
		if err != nil {
			return nil, false
		}
		body, err := proto.Marshal(&protocol.HeadCheckProofRequest{After: act.after})
		if err != nil {
			return nil, false
		}
		answer, err := self.subprotocol.Call(ctx, Id(clientId), protocol.MessageType_HEAD_CHECK_PROOF_REQUEST, body, &CallOptions{Timeout: self.settings.HeadCheckTimeout})
		if err != nil {
			return nil, false
		}
		proof := &protocol.HeadCheckProof{}
		if err := proto.Unmarshal(answer, proof); err != nil || HeadCheckMaxProofByteCount < headCheckProofByteCount(proof.GetEntries()) {
			return nil, false
		}
		verifyErr := self.sources.Auth.VerifyAuthProof(ctx, proof.GetEntries(), act.pin)
		testHookBarrier("rpc.head_proof_verified", act.peerId.String())
		return proof.GetEntries(), verifyErr == nil
	}()
	return self.stop.proved(act.pin, act.peerId, entries, verified)
}
