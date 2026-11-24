//go:build !sidecar_http && !ios_extension

// What a desktop sender's lookups go over (§14.4, §14.6, §2.8 ext-3): TL2's _mta-sts TXT lookup and TL3's independent
// MX lookup, both from the device and never through the edge, and the DKIM domain answers a Team custom domain's new
// selector awaits (QD-1130), with the anchors TL1 validates the edge's dnssec_chain to. MailSendSettings'
// ResolverFactory builds one for each sender the mail component composes, which owns it (CODESTYLE's DoH rule: one
// owner, one cache).
//
// A nil ResolverFactory, the default and every host's, gives each sender a DohCache of its own over connect's default
// resolvers, under the DNS root's keys (mail_component_smtp.go), as production asks. A test sends nothing off the
// machine, so in a test binary that default is refused with ErrMailSenderPublicResolver before anything is built, and
// a test names a DNS of its own: the e2e world its own signed DNS, a unit test a fake zone.

package sidecar

import "errors"

// A sender in a test binary on the public resolvers it asks by default: refused, so no test sends a query off the
// machine.
var ErrMailSenderPublicResolver = errors.New("mail sender: a sender in a test asks no public DoH resolver; set MailSendSettings.ResolverFactory to the test's own DNS")

// One sender's resolver, which that sender alone asks.
type MailSenderResolver struct {
	// What TL2's _mta-sts lookup, TL3's MX lookup and the DKIM domain answers ask. Required.
	Doh SmtpDohForwarder
	// What TL1 validates the edge's dnssec_chain to; nil takes DefaultSmtpDnssecAnchors, the DNS root's keys.
	Anchors *SmtpDnssecAnchors
	// Releases Doh once the sender and its workers have ended; nil releases nothing.
	Close func()
}
