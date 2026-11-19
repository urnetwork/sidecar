//go:build !sidecar_http && !ios_extension

// A bridge for SMTP-M9-07's and SMTP-M9-08's external tests: one connection run as Send runs each, and the units
// Check prices a send at.

package sidecar

import "context"

// What one connection is asked to send.
type SmtpConnectionArgsForTest = smtpConnectionArgs

// Runs one connection of sender's, as Send runs each.
func (self *SmtpSender) RunConnectionForTest(ctx context.Context, args *SmtpConnectionArgsForTest) *SmtpConnectionResult {
	return self.connection.Run(ctx, args)
}

// DESIGN-DETAILS 3.2.6's units, as Check prices a send.
func SmtpSendUnitsForTest(recipientCount int, headerByteCount uint64, mode SmtpMode, measure *SmtpProverMeasure) uint64 {
	return smtpSendUnits(recipientCount, headerByteCount, mode, measure)
}

// The header block's length the signed message will hold.
func SmtpWireHeaderByteCountForTest(wire *SmtpWireMessage) (uint64, error) {
	return wire.headerByteCount()
}
