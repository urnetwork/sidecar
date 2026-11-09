//go:build !sidecar_http

// §9.9's errors (D-SOCK-8): what Dial, Listen, Accept and a SocketConn return, each a *net.OpError with
// Net "ur" wrapping one of the values below, so Go code written for TCP and its retry logic work
// unchanged. errors.Is reaches the value and, where §9.9 names one, the syscall errno beneath it: no
// listener and busy are ECONNREFUSED, denied EACCES, reset ECONNRESET. A refusal that tells a caller
// how long to wait carries it in SocketCodeError.RetryAfter, as no_listener, busy, quota and
// unavailable do (§9.9). No error repeats a name, which may be a private one (I-13).
//
// They name connect types through net.OpError's addresses, so they stay off the sidecar_http leg with
// the listeners and dialers that use them.

package sidecar

import (
	"fmt"
	"syscall"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One of §9.9's values: its text and the errno errors.Is reaches beneath it, 0 for none.
type socketErrorValue struct {
	text  string
	errno syscall.Errno
}

// The text alone.
func (self *socketErrorValue) Error() string {
	return self.text
}

// The errno, so errors.Is(err, syscall.ECONNREFUSED) holds for no listener and busy.
func (self *socketErrorValue) Unwrap() error {
	if self.errno == 0 {
		return nil
	}
	return self.errno
}

// §9.9's values, in §9.6's step order as Find's errors, then the stream's reset.
var (
	// Find's pick found nothing live and matching, or every ticket's listener refused or timed out
	// without a better answer.
	ErrSocketNoListener error = &socketErrorValue{text: "socket has no listener", errno: syscall.ECONNREFUSED}
	// Every matching listener is at max_streams.
	ErrSocketBusy error = &socketErrorValue{text: "socket listeners are busy", errno: syscall.ECONNREFUSED}
	// The projection, or the listener's own evaluation of its config, does not allow the dial.
	ErrSocketDenied error = &socketErrorValue{text: "socket dial denied", errno: syscall.EACCES}
	// The stream was reset, by the peer or by revocation, drain or a timeout (§6.7).
	ErrSocketReset error = &socketErrorValue{text: "socket stream reset", errno: syscall.ECONNRESET}
	// The service is overloaded, bounded, or has not loaded the network's projection (§9.10).
	ErrSocketUnavailable error = &socketErrorValue{text: "socket service unavailable"}
	// The paying network is spent (§20.6).
	ErrSocketQuota error = &socketErrorValue{text: "socket network quota spent"}
)

// One of §9.9's values with what came with it. A *net.OpError wraps this, and this wraps the value.
type SocketCodeError struct {
	// One of the ErrSocket values.
	Err error
	// How long the service or the listener asked the caller to wait. 0: no time was given.
	RetryAfter time.Duration
	// With ErrSocketReset, the StreamReset's code (§6.7). RST_UNSPECIFIED otherwise.
	ResetCode protocol.StreamResetCode
}

// The value's text, with the wait or the reset code when there is one.
func (self *SocketCodeError) Error() string {
	switch {
	case self.ResetCode != protocol.StreamResetCode_RST_UNSPECIFIED:
		return fmt.Sprintf("%v: %s", self.Err, self.ResetCode)
	case 0 < self.RetryAfter:
		return fmt.Sprintf("%v: retry after %v", self.Err, self.RetryAfter)
	}
	return self.Err.Error()
}

// The value, so errors.Is(err, ErrSocketBusy) holds.
func (self *SocketCodeError) Unwrap() error {
	return self.Err
}

// The error a Find's refusal is (§9.6, §9.9). A code a Find never answers, such as a page's stale, or
// one this client does not know, reads as denied, which stops a dial rather than inviting a retry loop.
func socketFindError(refusal *SocketError) *SocketCodeError {
	retryAfter := time.Duration(refusal.RetryAfterMs) * time.Millisecond
	switch refusal.Code {
	case SocketErrorCodeNoListener:
		return &SocketCodeError{Err: ErrSocketNoListener, RetryAfter: retryAfter}
	case SocketErrorCodeBusy:
		return &SocketCodeError{Err: ErrSocketBusy, RetryAfter: retryAfter}
	case SocketErrorCodeQuota:
		return &SocketCodeError{Err: ErrSocketQuota, RetryAfter: retryAfter}
	case SocketErrorCodeUnavailable:
		return &SocketCodeError{Err: ErrSocketUnavailable, RetryAfter: retryAfter}
	}
	return &SocketCodeError{Err: ErrSocketDenied}
}

// The error a listener's StreamReject is once a dialer has no ticket left to try (§9.6): busy, denied
// and quota as themselves, and retry, invalid, or a code taken as invalid (SocketRejectCode) as no
// listener, since nothing admitted the dial.
func socketRejectError(code uint32, retryAfterMs uint32) *SocketCodeError {
	retryAfter := time.Duration(retryAfterMs) * time.Millisecond
	switch SocketRejectCode(code) {
	case protocol.StreamRejectCode_SR_BUSY:
		return &SocketCodeError{Err: ErrSocketBusy, RetryAfter: retryAfter}
	case protocol.StreamRejectCode_SR_DENIED:
		return &SocketCodeError{Err: ErrSocketDenied}
	case protocol.StreamRejectCode_SR_QUOTA:
		return &SocketCodeError{Err: ErrSocketQuota, RetryAfter: retryAfter}
	}
	return &SocketCodeError{Err: ErrSocketNoListener, RetryAfter: retryAfter}
}
