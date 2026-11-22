//go:build !sidecar_http && !js && !ios_extension

// A bridge for the receiver composition's external tests (mail_receiver_resolver_test.go): the lookups a receiver
// composed on given settings runs in this test binary, as newMailSidecarReceiverFactory builds them.

package sidecar

import (
	"context"
	"testing"
)

// The reception-time checks, mail.strict's chain where no zone watch holds it (for the zone's root given), and the
// release of the resolver under both, of a receiver composed on settings here, its time on clock.
func MailReceiverLookupsForTest(settings *MailReceiveSettings, clock Clock) (*MailAuthChecker, func(ctx context.Context, root string, sniHost string, recipientDomains []string, spkiSha256 []byte) bool, func(), error) {
	lookups, err := newMailReceiverLookups(settings, clock, testing.Testing())
	if err != nil {
		return nil, nil, nil, err
	}
	return lookups.checker, lookups.strictChain, lookups.close, nil
}
