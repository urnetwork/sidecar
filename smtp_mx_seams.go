//go:build !sidecar_http && !ios_extension

// The edge's two ways out to the world (§14.4), as seams: a DNSSEC-validating resolver for MX, TLSA
// and addresses, and a TCP 25 dialer bound to a sending address. smtpedge's engine resolves and dials
// through them (SMTP-M9-12), server supplies the real ones (SMTP-M9-20), and sidecartest.MxWorld
// stands in for both, with no port 25 and no sleep. The sidecar never names an IP and never dials an
// MX: only the edge holds these (D-SMTP-1, R-SMTP-9).
//
// A chain here is §14.5's dnssec_chain material: uncompressed wire-format RRs, each RRset followed by
// its RRSIGs, in RFC 9102's order, the answer first and then every zone cut's DNSKEY and DS up to the
// root's DNSKEY (plan-SMTP-small-readings#2). The edge joins the MX chain and the TLSA chain into the
// one it sends.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

var (
	// The name does not exist: no MX and no address, so the preamble answers NO_MX.
	ErrSmtpMxNoSuchDomain = errors.New("smtp mx: no such domain")
	// A lookup failed for now (timeout, SERVFAIL): TRY_LATER with no debit (§14.9).
	ErrSmtpMxTemporary = errors.New("smtp mx: temporary failure")
	// The answer did not validate, so it may be forged: TRY_LATER, never an unsigned retreat.
	ErrSmtpMxBogus = errors.New("smtp mx: dnssec validation failed")
)

// One MX target, by preference.
type SmtpMxHost struct {
	Preference uint16
	// Lowercase, with no trailing dot.
	Host string
}

// What one recipient domain's MX lookup found.
type SmtpMxAnswer struct {
	// By preference, lowest first. Empty with NullMx false is no MX RRset at all, where RFC 5321
	// §5.1's implicit MX applies and the domain is its own host (plan-SMTP-small-readings#13).
	Hosts []*SmtpMxHost
	// RFC 7505's null MX: the domain takes no mail, NO_MX.
	NullMx bool
	// The answer, or its absence, validated to the root. False is an insecure answer, never a bogus
	// one, which is ErrSmtpMxBogus.
	Secure bool
	// The MX RRset (or its denial) and its chain, when Secure. Nil otherwise.
	Chain []byte
}

// One TLSA record (RFC 6698), as TL1 matches it.
type SmtpTlsaRecord struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Data         []byte
}

// What _25._tcp.<mx_host>'s TLSA lookup found.
type SmtpTlsaAnswer struct {
	// Empty when none exists.
	Records []*SmtpTlsaRecord
	// The records, or their denial, validated to the root.
	Secure bool
	// The TLSA RRset or its NSEC or NSEC3 denial, and its chain, when Secure. Nil otherwise.
	Chain []byte
}

// A validating resolver, as the edge reaches DNS. Safe for concurrent use.
type SmtpMxResolver interface {
	// domain's MX RRset. ErrSmtpMxNoSuchDomain, ErrSmtpMxTemporary or ErrSmtpMxBogus, else an answer.
	LookupMx(ctx context.Context, domain string) (*SmtpMxAnswer, error)
	// host's TLSA RRset at port 25.
	LookupTlsa(ctx context.Context, host string) (*SmtpTlsaAnswer, error)
	// host's A and AAAA addresses. The edge dials only public unicast IPv4 among them (owner
	// decision 34).
	LookupAddresses(ctx context.Context, host string) ([]netip.Addr, error)
}

// TCP 25 out of the edge, bound to one of its host's sending addresses (by fwmark on a real host).
// Safe for concurrent use.
type SmtpMxDialer interface {
	DialMx(ctx context.Context, sendingAddress netip.Addr, mxAddress netip.Addr) (net.Conn, error)
}
