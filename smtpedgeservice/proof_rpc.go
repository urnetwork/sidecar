// The SMTP_PROOF and SMTP_HANDSHAKE handlers (§14.5, DESIGN-DETAILS 3.2.5 and 3.7; SMTP-M9-13): a sidecar's RPCs
// to the edge's platform client, each naming its send. A handler finds the live connection by send_id, takes
// the call only from that connection's dialer, as connect authenticated the source, and hands the part to the
// session, writing any record it clears to the MX in the session's order (connection.go). SHTS takes the same
// route. A request past ProofMaxByteCount is refused before it is decoded, and when its send_id names a live
// connection of the caller's, that connection ends: a part is under 3 KiB, so a larger one is no honest part.
//
// The handlers decode SmtpProof's thirteen fields and know nothing of a part's kind: that is the session's.
// SmtpProofResult answers OK, or INVALID once the session refused, which ended the connection; a refusal that
// ErrSmtpRecordCut names is §14.7's cut. Neither handler keeps a proof, a record or the SHTS past the call
// (D-SMTP-10), and neither logs anything of one.
//
// Safe for concurrent use: the dispatcher runs each request on a goroutine of its own.

package smtpedgeservice

import (
	"context"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// SmtpProof's and SmtpHandshake's send_id field, which both put first: an identifier of the wire.
const smtpProofSendIdField = 1

// The send_id field of an encoded SmtpProof or SmtpHandshake, read without decoding the rest, or nil.
func smtpSendIdOf(body []byte) []byte {
	for 0 < len(body) {
		number, kind, length := protowire.ConsumeTag(body)
		if length < 0 {
			return nil
		}
		body = body[length:]
		if number == smtpProofSendIdField && kind == protowire.BytesType {
			value, length := protowire.ConsumeBytes(body)
			if length < 0 {
				return nil
			}
			return value
		}
		length = protowire.ConsumeFieldValue(number, kind, body)
		if length < 0 {
			return nil
		}
		body = body[length:]
	}
	return nil
}

// The live connection the caller dialed, or nil: another source's call never reaches a connection.
func (self *SmtpEdgeService) callerConnection(sourceId sidecar.Id, sendId []byte) *smtpEdgeConnection {
	if len(sendId) != SmtpSendIdByteCount {
		return nil
	}
	connection := self.connection(sendId)
	if connection == nil || connection.stream.ClientId != sourceId {
		return nil
	}
	return connection
}

// Refuses a request past ProofMaxByteCount, ending the caller's connection it names. Whether it was past.
func (self *SmtpEdgeService) refuseOversized(request *sidecar.SubprotocolRequest) bool {
	if len(request.Body) <= self.settings.ProofMaxByteCount {
		return false
	}
	if connection := self.callerConnection(request.SourceId, smtpSendIdOf(request.Body)); connection != nil {
		connection.end(smtpConnectionResultEnded)
	}
	return true
}

// SMTP_PROOF's handler.
func (self *SmtpEdgeService) handleProof(ctx context.Context, request *sidecar.SubprotocolRequest) ([]byte, error) {
	invalid := func() ([]byte, error) {
		return proto.Marshal(&protocol.SmtpProofResult{Code: uint32(protocol.SmtpProofCode_SMTP_PROOF_INVALID)})
	}
	if self.refuseOversized(request) {
		return invalid()
	}
	proof := &protocol.SmtpProof{}
	if err := proto.Unmarshal(request.Body, proof); err != nil {
		if connection := self.callerConnection(request.SourceId, smtpSendIdOf(request.Body)); connection != nil {
			connection.end(smtpConnectionResultEnded)
		}
		return invalid()
	}
	connection := self.callerConnection(request.SourceId, proof.GetSendId())
	if connection == nil {
		return invalid()
	}
	part := &sidecar.SmtpProofPart{
		SendId:            proof.GetSendId(),
		Index:             proof.GetIndex(),
		Mode:              proof.GetMode(),
		FirstRecord:       proof.GetFirstRecord(),
		LastRecord:        proof.GetLastRecord(),
		Proof:             proof.GetProof(),
		Last:              proof.GetLast(),
		ServerRecordCount: proof.GetServerRecordCount(),
		Records:           proof.GetRecords(),
		KeyCommitment:     proof.GetKeyCommitment(),
		ReplyCount:        proof.GetReplyCount(),
		HeaderRecordCount: proof.GetHeaderRecordCount(),
		Carry:             proof.GetCarry(),
	}
	if err := connection.verifyPart(ctx, part); err != nil {
		return invalid()
	}
	return proto.Marshal(&protocol.SmtpProofResult{Code: uint32(protocol.SmtpProofCode_SMTP_PROOF_OK)})
}

// SMTP_HANDSHAKE's handler: E2 over the disclosed SHTS, which the session uses and forgets.
func (self *SmtpEdgeService) handleHandshake(ctx context.Context, request *sidecar.SubprotocolRequest) ([]byte, error) {
	invalid := func() ([]byte, error) {
		return proto.Marshal(&protocol.SmtpHandshakeResult{Code: uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_INVALID)})
	}
	if self.refuseOversized(request) {
		return invalid()
	}
	handshake := &protocol.SmtpHandshake{}
	if err := proto.Unmarshal(request.Body, handshake); err != nil {
		return invalid()
	}
	connection := self.callerConnection(request.SourceId, handshake.GetSendId())
	if connection == nil {
		return invalid()
	}
	if err := connection.discloseShts(handshake.GetShts()); err != nil {
		return invalid()
	}
	return proto.Marshal(&protocol.SmtpHandshakeResult{Code: uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_OK)})
}
