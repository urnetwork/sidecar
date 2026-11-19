//go:build sidecar_http && !ios_extension

// The queue step on the page Worker's leg, which sends no internet mail (§18.10): mail_send_queue.go's twin. Its
// internet recipients answer internet_waits and nothing is queued, and no Lookup is registered, since no entry is
// ever written here.

package sidecar

import (
	"context"
)

// No outbox on this leg.
func (self *MailClient) registerOutboxLookup(gate MailConfigGate) {
}

// No queue on this leg: internet recipients wait for a leg that sends.
func (self *MailClient) prepareQueue(ctx context.Context, plan *mailSendPlan) (mailSendQueue, MailSendOutcome) {
	return nil, MailSendInternetWaits
}
