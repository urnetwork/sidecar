//go:build !sidecar_http

// The frames ahead of the raw TLS on a stream to smtpedge (D-SMTP-3, plan-SMTP-wire-gaps#3): each is
// u32be body length ‖ u16be MessageType ‖ body, the body at most 65,536 B. Only SmtpPreamble, from the
// sidecar, and SmtpPreambleResult, from the edge, travel this way. Raw TLS follows an OK result, and
// any other result ends the stream after its frame. A bad length or type, a body that does not decode,
// or a result code of 0 resets the stream with PROTOCOL (§6.11's zero rule).
//
// A read takes exactly one frame's octets from the stream, with no buffer past them, because the
// sidecar's ClientHello follows the result on the same stream. A length over the bound is refused
// before anything is allocated for it.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Format values (plan-SMTP-wire-gaps#3), not settings: both ends must agree on them.
const (
	// The length and the type.
	SmtpFrameHeaderByteCount = 4 + 2
	// The most a body holds.
	SmtpFrameMaxBodyByteCount = 64 * 1024
)

// The stream resets with PROTOCOL: a frame with a bad length or type, a body that does not decode, or
// a value §6.11 makes a protocol error. errors.Is finds it under the wrapped detail.
var ErrSmtpFrameProtocol = errors.New("smtp frame protocol error")

// One frame, decoded no further than its type.
type SmtpFrame struct {
	// SMTP_PREAMBLE or SMTP_PREAMBLE_RESULT.
	Type protocol.MessageType
	// The message, at most SmtpFrameMaxBodyByteCount octets.
	Body []byte
}

// Whether a type may travel as a frame.
func smtpFrameType(messageType protocol.MessageType) bool {
	return messageType == protocol.MessageType_SMTP_PREAMBLE || messageType == protocol.MessageType_SMTP_PREAMBLE_RESULT
}

// Writes one frame in a single write, so the header and the body never go out apart.
func WriteSmtpFrame(writer io.Writer, frame *SmtpFrame) error {
	if !smtpFrameType(frame.Type) {
		return fmt.Errorf("%w: type %#x travels in no frame", ErrSmtpFrameProtocol, int32(frame.Type))
	}
	if SmtpFrameMaxBodyByteCount < len(frame.Body) {
		return fmt.Errorf("%w: a %d B body is past the bound", ErrSmtpFrameProtocol, len(frame.Body))
	}
	encoded := make([]byte, SmtpFrameHeaderByteCount, SmtpFrameHeaderByteCount+len(frame.Body))
	binary.BigEndian.PutUint32(encoded[0:4], uint32(len(frame.Body)))
	binary.BigEndian.PutUint16(encoded[4:6], uint16(frame.Type))
	encoded = append(encoded, frame.Body...)
	_, err := writer.Write(encoded)
	return err
}

// Reads exactly one frame of type want, and nothing after it. A stream that ends inside a frame
// returns io.ErrUnexpectedEOF, and one that ends before a frame starts io.EOF, each a reset.
func ReadSmtpFrame(reader io.Reader, want protocol.MessageType) (*SmtpFrame, error) {
	var header [SmtpFrameHeaderByteCount]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	bodyByteCount := binary.BigEndian.Uint32(header[0:4])
	frameType := protocol.MessageType(binary.BigEndian.Uint16(header[4:6]))
	if SmtpFrameMaxBodyByteCount < bodyByteCount {
		return nil, fmt.Errorf("%w: a %d B body is past the bound", ErrSmtpFrameProtocol, bodyByteCount)
	}
	if frameType != want {
		return nil, fmt.Errorf("%w: type %#x where %#x belongs", ErrSmtpFrameProtocol, int32(frameType), int32(want))
	}
	body := make([]byte, bodyByteCount)
	if _, err := io.ReadFull(reader, body); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return &SmtpFrame{Type: frameType, Body: body}, nil
}

// One message as a frame body, in protobuf's deterministic order.
func marshalSmtpFrameBody(message proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}

// The sidecar's first frame.
func WriteSmtpPreamble(writer io.Writer, preamble *protocol.SmtpPreamble) error {
	body, err := marshalSmtpFrameBody(preamble)
	if err != nil {
		return err
	}
	return WriteSmtpFrame(writer, &SmtpFrame{Type: protocol.MessageType_SMTP_PREAMBLE, Body: body})
}

// The edge's first read. What the preamble declares is the gate's to judge (§14.5); this refuses only
// what does not decode.
func ReadSmtpPreamble(reader io.Reader) (*protocol.SmtpPreamble, error) {
	frame, err := ReadSmtpFrame(reader, protocol.MessageType_SMTP_PREAMBLE)
	if err != nil {
		return nil, err
	}
	preamble := &protocol.SmtpPreamble{}
	if err := proto.Unmarshal(frame.Body, preamble); err != nil {
		return nil, fmt.Errorf("%w: the preamble does not decode", ErrSmtpFrameProtocol)
	}
	return preamble, nil
}

// The edge's one frame. A dnssec_chain that would take the body past the bound is sent empty, so TL1
// is not available on that connection (plan-SMTP-wire-gaps#3); anything else that passes it is
// refused. result is not changed.
func WriteSmtpPreambleResult(writer io.Writer, result *protocol.SmtpPreambleResult) error {
	if !smtpPreambleCodeKnown(result.GetCode()) {
		return fmt.Errorf("%w: code %d", ErrSmtpFrameProtocol, result.GetCode())
	}
	body, err := marshalSmtpFrameBody(result)
	if err != nil {
		return err
	}
	if SmtpFrameMaxBodyByteCount < len(body) && len(result.GetDnssecChain()) != 0 {
		withoutChain := proto.CloneOf(result)
		withoutChain.DnssecChain = nil
		if body, err = marshalSmtpFrameBody(withoutChain); err != nil {
			return err
		}
	}
	return WriteSmtpFrame(writer, &SmtpFrame{Type: protocol.MessageType_SMTP_PREAMBLE_RESULT, Body: body})
}

// The sidecar's one read before TLS. A code of 0 or one this version does not know resets the
// stream: a sender must never read it as retry, refusal or success (§6.11).
func ReadSmtpPreambleResult(reader io.Reader) (*protocol.SmtpPreambleResult, error) {
	frame, err := ReadSmtpFrame(reader, protocol.MessageType_SMTP_PREAMBLE_RESULT)
	if err != nil {
		return nil, err
	}
	result := &protocol.SmtpPreambleResult{}
	if err := proto.Unmarshal(frame.Body, result); err != nil {
		return nil, fmt.Errorf("%w: the result does not decode", ErrSmtpFrameProtocol)
	}
	if !smtpPreambleCodeKnown(result.GetCode()) {
		return nil, fmt.Errorf("%w: code %d", ErrSmtpFrameProtocol, result.GetCode())
	}
	return result, nil
}

// OK to TRY_LATER, never 0.
func smtpPreambleCodeKnown(code uint32) bool {
	return uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK) <= code && code <= uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER)
}
