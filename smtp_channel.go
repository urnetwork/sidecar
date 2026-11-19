//go:build !sidecar_http && !ios_extension

// SmtpProofChannel over §6's RPCs (§14.5, SMTP-M9-07): a send's parts and TLS 1.3's disclosed SHTS go to the
// edge that holds its stream, the client its ur/ ticket names as listener, as SMTP_PROOF and SMTP_HANDSHAKE
// calls, each answered by its result's code. SubmitPart encodes every field of SmtpProofPart, the four of
// DESIGN-DETAILS 3.2.5 among them, and decodes nothing but the code.
//
// A call that timed out goes again with its request_id, up to ProofCallAttemptCount calls: a part resent
// under its send_id and index, byte for byte, is idempotent at the edge, and a verified part is never
// replaced (§14.5), so a retry can only find the first answer. INVALID is the edge's refusal, after which it
// ends the connection, and a code of 0 or one this version does not know is §6.11's protocol error: both
// fail the send, and the prover sends nothing more.
//
// Nothing here logs, and no error quotes a part, a record or the SHTS (D-SMTP-10).
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The edge answered INVALID: a part or the SHTS failed its check there, and the edge has ended or cut the
	// connection (§14.7).
	ErrSmtpProofRefused = errors.New("smtp proof refused by the edge")
	// The edge's answer broke §6.11: a code of 0, or one this version does not know.
	errSmtpProofAnswer = errors.New("smtp proof: an answer outside the protocol")
)

// Where the channel's calls go: §6's dispatcher of the generation that opened the stream (Subprotocol.Call),
// or a test's.
type smtpEdgeCaller interface {
	Call(ctx context.Context, clientId Id, messageType protocol.MessageType, body []byte, options *CallOptions) ([]byte, error)
}

var _ smtpEdgeCaller = (*Subprotocol)(nil)

// One send's channel to its edge.
type smtpProofChannel struct {
	caller smtpEdgeCaller
	// the listener the stream's ticket names: the edge that holds the connection
	edgeClientId Id
	sendId       []byte
	settings     *SmtpSenderSettings
}

var _ SmtpProofChannel = (*smtpProofChannel)(nil)

// The channel for sendId, through caller to edgeClientId, under settings, which must have passed validate.
func newSmtpProofChannel(caller smtpEdgeCaller, edgeClientId Id, sendId []byte, settings *SmtpSenderSettings) *smtpProofChannel {
	return &smtpProofChannel{caller: caller, edgeClientId: edgeClientId, sendId: bytes.Clone(sendId), settings: settings}
}

// One call, sent again with its request_id while it times out, up to ProofCallAttemptCount calls.
func (self *smtpProofChannel) call(ctx context.Context, messageType protocol.MessageType, body []byte) ([]byte, error) {
	options := &CallOptions{Timeout: self.settings.ProofCallTimeout}
	for attempt := 1; ; attempt += 1 {
		answer, err := self.caller.Call(ctx, self.edgeClientId, messageType, body, options)
		if err == nil {
			return answer, nil
		}
		var subprotocolError *SubprotocolError
		timedOut := errors.As(err, &subprotocolError) && subprotocolError.Code == protocol.ErrorCode_ERR_DEADLINE_EXCEEDED
		if !timedOut || self.settings.ProofCallAttemptCount <= attempt || ctx.Err() != nil {
			return nil, err
		}
		options = &CallOptions{Timeout: self.settings.ProofCallTimeout, RequestId: subprotocolError.RequestId}
	}
}

// The error a result code answers: nil for OK, ErrSmtpProofRefused for INVALID, else the protocol's.
func smtpProofCodeError(code uint32, okCode uint32, invalidCode uint32, what string) error {
	switch code {
	case okCode:
		return nil
	case invalidCode:
		return fmt.Errorf("%w: %s", ErrSmtpProofRefused, what)
	}
	return fmt.Errorf("%w: %s answered code %d", errSmtpProofAnswer, what, code)
}

// SMTP_HANDSHAKE: TLS 1.3's SHTS, which the edge uses for E2 and forgets (D-SMTP-10).
func (self *smtpProofChannel) DiscloseShts(ctx context.Context, shts []byte) error {
	body, err := proto.Marshal(&protocol.SmtpHandshake{SendId: self.sendId, Shts: shts})
	if err != nil {
		return err
	}
	answer, err := self.call(ctx, protocol.MessageType_SMTP_HANDSHAKE, body)
	if err != nil {
		return err
	}
	result := &protocol.SmtpHandshakeResult{}
	if err := proto.Unmarshal(answer, result); err != nil {
		return fmt.Errorf("%w: the handshake's result does not decode", errSmtpProofAnswer)
	}
	return smtpProofCodeError(result.GetCode(), uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_OK),
		uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_INVALID), "the handshake")
}

// SMTP_PROOF: one part, every field of it.
func (self *smtpProofChannel) SubmitPart(ctx context.Context, part *SmtpProofPart) error {
	if part == nil {
		return fmt.Errorf("%w: no part", errSmtpProofAnswer)
	}
	body, err := proto.Marshal(smtpProofOf(self.sendId, part))
	if err != nil {
		return err
	}
	answer, err := self.call(ctx, protocol.MessageType_SMTP_PROOF, body)
	if err != nil {
		return err
	}
	result := &protocol.SmtpProofResult{}
	if err := proto.Unmarshal(answer, result); err != nil {
		return fmt.Errorf("%w: a part's result does not decode", errSmtpProofAnswer)
	}
	return smtpProofCodeError(result.GetCode(), uint32(protocol.SmtpProofCode_SMTP_PROOF_OK),
		uint32(protocol.SmtpProofCode_SMTP_PROOF_INVALID), fmt.Sprintf("part %d", part.Index))
}

// The wire form of part under the channel's send_id: all thirteen fields (§14.5, DESIGN-DETAILS 3.2.5). The
// channel's send_id stands for the part's, so a part names no other send.
func smtpProofOf(sendId []byte, part *SmtpProofPart) *protocol.SmtpProof {
	return &protocol.SmtpProof{
		SendId:            sendId,
		Index:             part.Index,
		Mode:              part.Mode,
		FirstRecord:       part.FirstRecord,
		LastRecord:        part.LastRecord,
		Proof:             part.Proof,
		Last:              part.Last,
		ServerRecordCount: part.ServerRecordCount,
		Records:           part.Records,
		KeyCommitment:     part.KeyCommitment,
		ReplyCount:        part.ReplyCount,
		HeaderRecordCount: part.HeaderRecordCount,
		Carry:             part.Carry,
	}
}
