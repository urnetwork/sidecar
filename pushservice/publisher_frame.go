// The frames a publisher sends (§6.8): each push message is one Envelope of type PUSH_RESET or
// PUSH_HINT, flagged NO_REPLY and never chunked, since a reset part of 48 versions and a hint of 256 B
// each fit one (§6.5), wrapped as connect's SubprotocolMessage for id 21842. A resident sends it from
// ControlId, and the client's dispatcher admits service 0x01's types from there only over a platform
// carrier (D-PROTO-8).
//
// connect's buildSubprotocolFrame is unexported, so the frame is connect.ToFrame's of the wrapper, whose
// bytes are the ones connect's own sends hand-roll (connect/subprotocol.go), in a pool buffer: the caller
// owns it until a Send that answers true takes it.

package pushservice

import (
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A push message past one envelope, which only a bug makes: a reset part holds at most 48 versions of
// registry topics, and a hint's bytes are bounded at 256.
var errPushFrameTooLarge = errors.New("sidecar publisher: a push message past one envelope")

// The frame of one push message, whose bytes are a pool buffer the caller owns. requestId only tells
// envelopes apart: nothing answers a push. A resident's publisher sends these, and sidecartest's residents
// send them by hand, so a test's frame is byte for byte one a resident would send.
func PushFrame(messageType protocol.MessageType, message proto.Message, requestId uint64) (*connectprotocol.Frame, error) {
	body, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}
	if sidecar.MaxEnvelopeBodyByteCount < len(body) {
		return nil, errPushFrameTooLarge
	}
	envelopeBytes, err := proto.Marshal(&protocol.Envelope{
		Version:   sidecar.WireVersionMajor,
		Type:      uint32(messageType),
		RequestId: requestId,
		Flags:     sidecar.EnvelopeFlagNoReply,
		Body:      body,
	})
	if err != nil {
		return nil, err
	}
	if sidecar.MaxEnvelopeByteCount < len(envelopeBytes) {
		return nil, errPushFrameTooLarge
	}
	return connect.ToFrame(&connectprotocol.SubprotocolMessage{
		SubprotocolId: sidecar.SubprotocolId,
		MessageBytes:  envelopeBytes,
	}, connect.DefaultProtocolVersion)
}
