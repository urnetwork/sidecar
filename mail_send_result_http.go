//go:build sidecar_http && !ios_extension

// A send's check and its results on the page Worker's leg, which sends no mail and runs no component (§18.10):
// mail_send_result.go's twin, each answering ErrMailSendUnavailable, which an app reads as MAIL_UNAVAILABLE.

package sidecar

import (
	"context"
	"fmt"
)

// No check on this leg.
func (self *MailClient) checkSend(ctx context.Context, args *MailSendArgs) (*SmtpSendCheck, error) {
	return nil, fmt.Errorf("%w: a page Worker sends no mail", ErrMailSendUnavailable)
}

// No send's result on this leg.
func (self *MailClient) sendResult(ctx context.Context, sendId Id) (*SmtpSendResult, error) {
	return nil, fmt.Errorf("%w: a page Worker sends no mail", ErrMailSendUnavailable)
}
