// §22.5's zero rule: a code left at zero is a protocol error wherever it is read, never retry, drain or
// success, and an unknown one reads the same (§6.4, §6.11).

package sidecar

import (
	"errors"
	"math"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

func TestErrorZeroAndUnknownFailTheirCall(t *testing.T) {
	for _, code := range []uint32{0, 15, 0x7FFFFFFF, 0x80000000, math.MaxUint32} {
		if got, ok := readErrorCode(code); ok {
			t.Errorf("%d read as %s", code, got)
		}
	}
}

func TestEveryErrorCodeASenderSetsReadsAsItself(t *testing.T) {
	for number, name := range protocol.ErrorCode_name {
		code, ok := readErrorCode(uint32(number))
		if number == int32(protocol.ErrorCode_ERR_OK) {
			if ok {
				t.Errorf("%s reads as a code", name)
			}
			continue
		}
		if !ok || int32(code) != number {
			t.Errorf("%s read as %s", name, code)
		}
	}
}

func TestStreamRejectZeroAndUnknownReadAsInvalid(t *testing.T) {
	for _, code := range []uint32{0, 6, 0x80000000, math.MaxUint32} {
		if got := readStreamRejectCode(code); got != protocol.StreamRejectCode_SR_INVALID {
			t.Errorf("%d read as %s", code, got)
		}
	}
	for number, name := range protocol.StreamRejectCode_name {
		if number != 0 && int32(readStreamRejectCode(uint32(number))) != number {
			t.Errorf("%s did not read as itself", name)
		}
	}
}

func TestStreamResetZeroAndUnknownReadAsProtocol(t *testing.T) {
	for _, code := range []uint32{0, 9, 0x80000000, math.MaxUint32} {
		if got := readStreamResetCode(code); got != protocol.StreamResetCode_RST_PROTOCOL {
			t.Errorf("%d read as %s", code, got)
		}
	}
	for number, name := range protocol.StreamResetCode_name {
		if number != 0 && int32(readStreamResetCode(uint32(number))) != number {
			t.Errorf("%s did not read as itself", name)
		}
	}
}

func TestEdgeResultZeroAndUnknownResetTheStream(t *testing.T) {
	// 8 is KEYS (DESIGN-DETAILS 3.2.5), so 9 is the first preamble code no version knows
	for _, code := range []uint32{0, 9, 0x80000000, math.MaxUint32} {
		if got, ok := readSmtpPreambleCode(code); ok {
			t.Errorf("a preamble code of %d read as %s", code, got)
		}
		if got, ok := readSmtpProofCode(code); ok {
			t.Errorf("a proof code of %d read as %s", code, got)
		}
	}
	for number, name := range protocol.SmtpPreambleCode_name {
		if code, ok := readSmtpPreambleCode(uint32(number)); number != 0 && (!ok || int32(code) != number) {
			t.Errorf("%s did not read as itself", name)
		}
	}
	for number, name := range protocol.SmtpProofCode_name {
		if code, ok := readSmtpProofCode(uint32(number)); number != 0 && (!ok || int32(code) != number) {
			t.Errorf("%s did not read as itself", name)
		}
	}
}

func TestOnlyThisLayersRefusalsNameACode(t *testing.T) {
	if code, ok := envelopeErrorCode(errReassemblyExhausted); !ok || code != protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED {
		t.Errorf("a cap answers %s", code)
	}
	for _, err := range []error{nil, errReassemblyDropped, errors.New("another")} {
		if code, ok := envelopeErrorCode(err); ok {
			t.Errorf("%v answers %s", err, code)
		}
	}
}
