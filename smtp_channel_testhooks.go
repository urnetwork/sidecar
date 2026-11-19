//go:build sidecar_testhooks && !sidecar_http && !ios_extension

// The sender's own SmtpProofChannel over a test's caller, for a T3 that has no exchange (SMTP-M9-31): server's run of
// S6 and FS-123 on the smtpedge block hands each stream to the engine itself, so a send's parts and SHTS go through
// smtpProofChannel's encoding, its retries and its reading of the answers, as smtp_channel.go has them, and the test
// caller lands each call on the handler the engine registers for its type, standing in for §6's dispatch alone.
//
// Only the sidecar_testhooks build has this, which no release leg is (§22.4). Nothing here holds or derives a key.

package sidecar

import (
	"context"

	"github.com/urnetwork/sidecar/protocol"
)

// Where a test's channel sends its calls: to clientId, the edge the stream's ticket names as listener.
type SmtpProofTestCaller interface {
	Call(ctx context.Context, clientId Id, messageType protocol.MessageType, body []byte, options *CallOptions) ([]byte, error)
}

// The channel for sendId's parts and SHTS, through caller to edgeClientId, under settings, which must have passed
// validate (NewSmtpSender's do).
func NewSmtpProofTestChannel(caller SmtpProofTestCaller, edgeClientId Id, sendId []byte, settings *SmtpSenderSettings) SmtpProofChannel {
	return newSmtpProofChannel(caller, edgeClientId, sendId, settings)
}
