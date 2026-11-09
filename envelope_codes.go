// §6's codes as they come off the wire, on every leg, so no caller compares a raw zero (§6.11,
// D-PROTO-20). Every code but ErrorCode starts at an UNSPECIFIED 0 no sender sets, and a
// default-constructed code must never read as retry, drain or success. An unknown code fails its call
// or stream without retry (§6.4), so these give an unknown number the zero's reading.

package sidecar

import (
	"errors"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// An envelope or body past §6.5's limits: a sender's refusal, and on receive a frame connect counts
	// and drops.
	errEnvelopeTooLarge = errors.New("envelope too large")
	// A body that would pass a reassembly cap (§6.6).
	errReassemblyExhausted = errors.New("reassembly over a cap")
	// A chunk that does not extend its group, or a group that fails its hash: the group is gone, nothing
	// answers, and the sender's retry owns recovery.
	errReassemblyDropped = errors.New("reassembly dropped")
)

// The ErrorCode one of this layer's refusals answers as, and false for any other error.
func envelopeErrorCode(err error) (protocol.ErrorCode, bool) {
	switch {
	case errors.Is(err, errEnvelopeTooLarge):
		return protocol.ErrorCode_ERR_TOO_LARGE, true
	case errors.Is(err, errReassemblyExhausted):
		return protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED, true
	}
	return protocol.ErrorCode_ERR_OK, false
}

// Whether a sender may have set code. A wire number past int32 wraps negative, which no enum holds.
func senderCode(codeNames map[int32]string, code uint32) bool {
	_, named := codeNames[int32(code)]
	return named && code != 0
}

// An Error's code, or false for one that fails its call as unknown, without retry: ERR_OK, which is
// never sent, and any number the registry does not hold (§6.5).
func readErrorCode(code uint32) (protocol.ErrorCode, bool) {
	if !senderCode(protocol.ErrorCode_name, code) {
		return protocol.ErrorCode_ERR_OK, false
	}
	return protocol.ErrorCode(code), true
}

// A StreamReject's code. Zero and an unknown number read as INVALID, never as retry (§6.11).
func readStreamRejectCode(code uint32) protocol.StreamRejectCode {
	if !senderCode(protocol.StreamRejectCode_name, code) {
		return protocol.StreamRejectCode_SR_INVALID
	}
	return protocol.StreamRejectCode(code)
}

// A StreamReset's code. Zero and an unknown number read as PROTOCOL, never as drain (§6.11).
func readStreamResetCode(code uint32) protocol.StreamResetCode {
	if !senderCode(protocol.StreamResetCode_name, code) {
		return protocol.StreamResetCode_RST_PROTOCOL
	}
	return protocol.StreamResetCode(code)
}

// An SmtpPreambleResult's code, or false for zero or an unknown number, on which the receiver resets
// the stream with PROTOCOL (§6.11).
func readSmtpPreambleCode(code uint32) (protocol.SmtpPreambleCode, bool) {
	if !senderCode(protocol.SmtpPreambleCode_name, code) {
		return protocol.SmtpPreambleCode_SMTP_PREAMBLE_CODE_UNSPECIFIED, false
	}
	return protocol.SmtpPreambleCode(code), true
}

// An SmtpProofResult's code, or false as readSmtpPreambleCode gives it.
func readSmtpProofCode(code uint32) (protocol.SmtpProofCode, bool) {
	if !senderCode(protocol.SmtpProofCode_name, code) {
		return protocol.SmtpProofCode_SMTP_PROOF_CODE_UNSPECIFIED, false
	}
	return protocol.SmtpProofCode(code), true
}

// The Error a refusal of code carries. VERSION alone carries this side's range of wire majors, with
// Hello's meaning (plan-PROTO-version-error-range, QD-459), so the peer learns what this side speaks.
func refusalError(code protocol.ErrorCode) *protocol.Error {
	refusal := &protocol.Error{Code: uint32(code)}
	if code == protocol.ErrorCode_ERR_VERSION {
		refusal.MinVersion = WireVersionMajor
		refusal.MaxVersion = WireVersionMajor
	}
	return refusal
}
