//go:build !sidecar_http && !ios_extension

// What a receiver's lookups go over (§15.5, §2.8 ext-3): the reception-time checks' raw answers through its MailDnsStub
// (SPF, the DKIM and ARC keys, DMARC, the sender's forward-confirmed PTR, the SNI host's TLSA), and under mail.strict
// the DNSSEC-OK answers its chain validates, with the anchors that chain validates to. MailReceiveSettings'
// ResolverFactory builds one for each receiver, which owns it (CODESTYLE's DoH rule: one owner, one cache).
//
// A nil ResolverFactory, the default and every host's, gives each receiver a DohCache of its own over connect's
// default resolvers, under the DNS root's keys (mail_component_receive.go), as production asks. A test sends nothing
// off the machine, so in a test binary that default is refused with ErrMailReceiverPublicResolver before anything is
// built, and a test names a DNS of its own: the e2e world its own signed DNS, a unit test a fake zone.

package sidecar

import "errors"

// A receiver in a test binary on the public resolvers it asks by default: refused, so no test sends a query off the
// machine.
var ErrMailReceiverPublicResolver = errors.New("mail receiver: a receiver in a test asks no public DoH resolver; set MailReceiveSettings.ResolverFactory to the test's own DNS")

// Forward and ForwardDnssec as connect's DohCache answers them: the raw RFC 8484 reply to qType for a domain given
// without its final dot, the second asked with EDNS0's DO bit, and whether a usable reply came. Safe for concurrent
// use.
type MailReceiverDoh interface {
	MailDohForwarder
	DnsWatchDnssecForwarder
}

// One receiver's resolver, which that receiver alone asks.
type MailReceiverResolver struct {
	// What every lookup of the receiver asks. Required.
	Doh MailReceiverDoh
	// What mail.strict's chain validates to; nil takes DefaultSmtpDnssecAnchors, the DNS root's keys.
	Anchors *SmtpDnssecAnchors
	// Releases Doh once the receiver and its sessions have ended; nil releases nothing.
	Close func()
}
