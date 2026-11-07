//go:build !sidecar_http

// §6.5's size rule on connect's codec, which connect.ProtoCodec lacks. This stays ProtoCodec underneath
// until §22 justifies a pooled codec (D-PROTO-11).

package sidecar

import (
	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// connect's proto codec for an envelope, with no state, so one serves every call.
var protoEnvelopeCodec = connect.ProtoCodec[*protocol.Envelope]()

// What RegisterSubprotocol takes for SubprotocolId. A sender's envelope past MaxEnvelopeByteCount, or
// with a body past MaxEnvelopeBodyByteCount, is errEnvelopeTooLarge, and on receive the same envelope
// fails to decode, so connect counts it and drops it (§6.5). Safe for concurrent use.
type envelopeCodec struct{}

// The size connect sizes its buffer from, which marshalling then holds to the limit.
func (self envelopeCodec) Size(m *protocol.Envelope) int {
	return protoEnvelopeCodec.Size(m)
}

// Appends m to b, or leaves b as it was and refuses. connect owns b either way, and b is what it gets
// back, so a refusal returns its pool buffer once.
func (self envelopeCodec) MarshalAppend(b []byte, m *protocol.Envelope) ([]byte, error) {
	if MaxEnvelopeBodyByteCount < len(m.GetBody()) {
		return b, errEnvelopeTooLarge
	}
	encoded, err := protoEnvelopeCodec.MarshalAppend(b, m)
	if err != nil {
		return encoded, err
	}
	if MaxEnvelopeByteCount < len(encoded)-len(b) {
		return b, errEnvelopeTooLarge
	}
	return encoded, nil
}

// Decodes b into m, refusing what a sender here would have refused. The length comes first, so a frame
// past the limit costs no decode.
func (self envelopeCodec) Unmarshal(b []byte, m *protocol.Envelope) error {
	if MaxEnvelopeByteCount < len(b) {
		return errEnvelopeTooLarge
	}
	if err := protoEnvelopeCodec.Unmarshal(b, m); err != nil {
		return err
	}
	if MaxEnvelopeBodyByteCount < len(m.Body) {
		return errEnvelopeTooLarge
	}
	return nil
}
