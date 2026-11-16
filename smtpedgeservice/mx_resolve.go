// MX resolution and the dial (§14.4, D-SMTP-1, D-SMTP-2): the edge, never the sidecar, resolves the
// recipient domain's MX with a DNSSEC-validating resolver and dials it, so the sidecar never names an
// IP, the edge is no port-25 proxy, and the proofs keep ORIGO's no-MITM assumption. RFC 7505's null MX
// answers NO_MX; with no MX RRset, RFC 5321 §5.1's implicit MX makes the domain its own host
// (plan-SMTP-small-readings#13), and NO_MX answers only when it has no address either. MXs are walked in
// preference order, at most MxHostMaxCount of them, and each only on public unicast IPv4 (owner decision
// 34): an address in MxRefusedPrefixes or an IPv6 one is never dialed. A host whose TLSA lookup is bogus
// is skipped, as RFC 7672 §2.2 has a DANE client skip it; a host a 421 banner backed off is skipped
// until MxBannerBackoffTimeout ends, in this edge's memory.
//
// Each dial binds a usable sending address (SmtpSendingSet) and runs the edge's pre-TLS dialog
// (mx_pretls.go) under PreTlsTimeout, on the edge's clock. The answer when no MX is reached:
//
//	NO_MX       the domain does not exist, a null MX, or no host has an address the edge may dial
//	NO_TLS      every MX that answered offered no STARTTLS, and none failed for now
//	TRY_LATER   anything for now: DNS, a bogus answer, a dial, a refusing banner or STARTTLS, a back-off,
//	            no usable sending address; with no debit (§14.9)
//
// Only mx_host leaves here for the send record, never the MX's IP (D-SMTP-10). Safe for concurrent use.

package smtpedgeservice

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The connector's reasons for an answer other than OK, a closed set for metrics and the edge's own log.
const (
	smtpMxReasonNoDomain   = "no_domain"
	smtpMxReasonNullMx     = "null_mx"
	smtpMxReasonDns        = "dns"
	smtpMxReasonNoAddress  = "no_address"
	smtpMxReasonNoStartTls = "no_starttls"
	smtpMxReasonUnreached  = "unreached"
	smtpMxReasonBackoff    = "backoff"
	smtpMxReasonNoSending  = "no_sending_address"
)

// What a dial reached: an MX past STARTTLS's 220, the ClientHello next.
type smtpMxConnection struct {
	conn net.Conn
	// Lowercase, no trailing dot: the one MX name the send record keeps.
	mxHost string
	// Memory only: never stored, never logged (D-SMTP-10).
	mxAddress      netip.Addr
	sendingAddress SmtpSendingAddress
	// The pre-TLS EHLO keywords, hints only.
	keywords []string
	// The joined MX and TLSA chain, nil when either answer did not validate.
	chain []byte
	// Gives back the destination concurrency slot, once.
	release func()
}

// Closes the MX connection and gives back its slot.
func (self *smtpMxConnection) close() {
	self.conn.Close()
	self.release()
}

// One edge's way to an MX: the resolver, the dialer, the sending set and the caps, and the hosts a 421
// backed off.
type smtpMxConnector struct {
	settings   *SmtpEdgeSettings
	clock      sidecar.Clock
	resolver   sidecar.SmtpMxResolver
	dialer     sidecar.SmtpMxDialer
	sendingSet *SmtpSendingSet
	caps       *SmtpDestinationCaps
	// mxedge's router interfaces by the host LAN (lan_splice.go); nil when settings name none
	lan *smtpLanDialer

	stateLock sync.Mutex
	// MX hosts a 421 banner backed off, until when
	mxHostBackoffs map[string]time.Time
}

func newSmtpMxConnector(settings *SmtpEdgeSettings, clock sidecar.Clock, resolver sidecar.SmtpMxResolver, dialer sidecar.SmtpMxDialer, sendingSet *SmtpSendingSet, caps *SmtpDestinationCaps, lan *smtpLanDialer) *smtpMxConnector {
	return &smtpMxConnector{
		settings:       settings,
		clock:          clock,
		resolver:       resolver,
		dialer:         dialer,
		sendingSet:     sendingSet,
		caps:           caps,
		lan:            lan,
		mxHostBackoffs: map[string]time.Time{},
	}
}

// Whether the edge may dial address: public unicast IPv4 outside MxRefusedPrefixes.
func (self *SmtpEdgeSettings) mxDialable(address netip.Addr) bool {
	address = address.Unmap()
	if !address.Is4() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() ||
		address.IsLinkLocalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range self.MxRefusedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// When the MX host's back-off ends, or zero.
func (self *smtpMxConnector) backoff(mxHost string, now time.Time) time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	end, ok := self.mxHostBackoffs[mxHost]
	if !ok {
		return time.Time{}
	}
	if !now.Before(end) {
		delete(self.mxHostBackoffs, mxHost)
		return time.Time{}
	}
	return end
}

// Backs mxHost off for MxBannerBackoffTimeout, holding at most MxBackoffMaxCount hosts.
func (self *smtpMxConnector) backOff(mxHost string, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.mxHostBackoffs[mxHost]; !ok && self.settings.MxBackoffMaxCount <= len(self.mxHostBackoffs) {
		for host, end := range self.mxHostBackoffs {
			if !now.Before(end) {
				delete(self.mxHostBackoffs, host)
			}
		}
		if self.settings.MxBackoffMaxCount <= len(self.mxHostBackoffs) {
			return
		}
	}
	self.mxHostBackoffs[mxHost] = now.Add(self.settings.MxBannerBackoffTimeout)
}

// A context ended by timeout on the connector's clock, and the call that ends it.
func (self *smtpMxConnector) timeoutContext(ctx context.Context, timeout time.Duration) (context.Context, func()) {
	timeoutCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(timeout, cancel)
	return timeoutCtx, func() {
		stop()
		cancel()
	}
}

// Resolves domain and reaches one of its MXs, or answers why not. limits are the gate's, whose
// smtp_destination_concurrency bounds the dial.
func (self *smtpMxConnector) connect(ctx context.Context, domain string, limits *sidecar.QuotaLimits) (*smtpMxConnection, protocol.SmtpPreambleCode, time.Duration, string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	tryLater := func(reason string) (*smtpMxConnection, protocol.SmtpPreambleCode, time.Duration, string) {
		return nil, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, self.settings.MxRetryTimeout, reason
	}
	answer, err := func() (*sidecar.SmtpMxAnswer, error) {
		lookupCtx, done := self.timeoutContext(ctx, self.settings.MxLookupTimeout)
		defer done()
		return self.resolver.LookupMx(lookupCtx, domain)
	}()
	switch {
	case errors.Is(err, sidecar.ErrSmtpMxNoSuchDomain):
		return nil, protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX, 0, smtpMxReasonNoDomain
	case err != nil:
		return tryLater(smtpMxReasonDns)
	case answer.NullMx:
		return nil, protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX, 0, smtpMxReasonNullMx
	}
	hosts := slices.Clone(answer.Hosts)
	implicit := len(hosts) == 0
	if implicit {
		hosts = []*sidecar.SmtpMxHost{{Host: domain}}
	}
	slices.SortStableFunc(hosts, func(a *sidecar.SmtpMxHost, b *sidecar.SmtpMxHost) int {
		return cmp.Compare(a.Preference, b.Preference)
	})
	if self.settings.MxHostMaxCount < len(hosts) {
		hosts = hosts[:self.settings.MxHostMaxCount]
	}

	now := self.clock.Now()
	// what the walk met, which decides the answer when no MX is reached
	transient := false
	noStartTls := false
	anyDialable := false
	noSending := false
	var earliestBackoff time.Time
	for _, host := range hosts {
		mxHost := strings.TrimSuffix(strings.ToLower(host.Host), ".")
		if !self.settings.ldhName(mxHost) {
			continue
		}
		if end := self.backoff(mxHost, now); !end.IsZero() {
			transient = true
			if earliestBackoff.IsZero() || end.Before(earliestBackoff) {
				earliestBackoff = end
			}
			continue
		}
		addresses, err := func() ([]netip.Addr, error) {
			lookupCtx, done := self.timeoutContext(ctx, self.settings.MxLookupTimeout)
			defer done()
			return self.resolver.LookupAddresses(lookupCtx, mxHost)
		}()
		if err != nil {
			if !errors.Is(err, sidecar.ErrSmtpMxNoSuchDomain) {
				transient = true
			}
			continue
		}
		dialable := []netip.Addr{}
		for _, address := range addresses {
			if self.settings.mxDialable(address) && len(dialable) < self.settings.MxAddressMaxCount {
				dialable = append(dialable, address.Unmap())
			}
		}
		if len(dialable) == 0 {
			continue
		}
		anyDialable = true
		var chain []byte
		if answer.Secure {
			tlsa, err := func() (*sidecar.SmtpTlsaAnswer, error) {
				lookupCtx, done := self.timeoutContext(ctx, self.settings.MxLookupTimeout)
				defer done()
				return self.resolver.LookupTlsa(lookupCtx, mxHost)
			}()
			switch {
			case errors.Is(err, sidecar.ErrSmtpMxBogus):
				// a DANE client never uses a host whose TLSA answer is bogus (RFC 7672 §2.2)
				transient = true
				continue
			case err != nil && !errors.Is(err, sidecar.ErrSmtpMxNoSuchDomain):
				transient = true
				continue
			case err == nil && tlsa.Secure:
				chain = joinSmtpChains(self.settings, answer.Chain, tlsa.Chain)
			}
		}
		for _, address := range dialable {
			connection, err := self.dial(ctx, mxHost, address, limits)
			switch {
			case err == nil:
				connection.chain = chain
				return connection, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, 0, ""
			case errors.Is(err, errSmtpMxNoSendingAddress):
				noSending = true
				transient = true
			case errors.Is(err, errSmtpPreTlsBackoff):
				self.backOff(mxHost, self.clock.Now())
				transient = true
			case errors.Is(err, errSmtpPreTlsNoStartTls):
				noStartTls = true
			default:
				transient = true
			}
			if errors.Is(err, errSmtpPreTlsBackoff) || errors.Is(err, errSmtpPreTlsNoStartTls) {
				// the host answered for all its addresses
				break
			}
		}
	}
	switch {
	case !anyDialable && !transient:
		return nil, protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX, 0, smtpMxReasonNoAddress
	case noStartTls && !transient:
		return nil, protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_TLS, 0, smtpMxReasonNoStartTls
	case noSending:
		return tryLater(smtpMxReasonNoSending)
	case !earliestBackoff.IsZero() && !anyDialable:
		return nil, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, earliestBackoff.Sub(now), smtpMxReasonBackoff
	}
	return tryLater(smtpMxReasonUnreached)
}

// A dial the real dialer refuses before a socket opens: a sending address not in the set, or an MX
// address the edge may not dial.
var errSmtpMxDialRefused = errors.New("smtp mx dial: refused")

// The fwmark of sendingAddress, one of settings' sending addresses, for a dial to mxAddress, which must be
// dialable.
func smtpSendingFwmark(settings *SmtpEdgeSettings, sendingAddress netip.Addr, mxAddress netip.Addr) (int, error) {
	if !settings.mxDialable(mxAddress) {
		return 0, fmt.Errorf("%w: an MX address the edge may not dial", errSmtpMxDialRefused)
	}
	for _, candidate := range settings.SendingAddresses {
		if candidate.Address == sendingAddress.Unmap() {
			return candidate.Fwmark, nil
		}
	}
	return 0, fmt.Errorf("%w: not a sending address", errSmtpMxDialRefused)
}

// No usable sending address has a slot to the MX's /24.
var errSmtpMxNoSendingAddress = errors.New("smtp mx: no usable sending address")

// Dials one MX address from a picked sending address and runs the pre-TLS dialog, both under
// PreTlsTimeout on the connector's clock.
func (self *smtpMxConnector) dial(ctx context.Context, mxHost string, mxAddress netip.Addr, limits *sidecar.QuotaLimits) (*smtpMxConnection, error) {
	sendingAddress, release, ok := self.sendingSet.pick(mxAddress, self.caps, smtpLimit(limits, SmtpLimitDestinationConcurrency))
	if !ok {
		return nil, errSmtpMxNoSendingAddress
	}
	dialCtx, done := self.timeoutContext(ctx, self.settings.PreTlsTimeout)
	defer done()
	dialer := self.dialer
	if self.lan.routes(mxAddress) {
		// a host cannot hairpin to its own lb address (D-SMTP-13)
		dialer = self.lan
	}
	conn, err := dialer.DialMx(dialCtx, sendingAddress.Address, mxAddress)
	if err != nil {
		release()
		return nil, err
	}
	// the timeout closes the connection, which ends a read the dialog is blocked in
	stopClose := context.AfterFunc(dialCtx, func() { conn.Close() })
	keywords, err := smtpPreTls(conn, sendingAddress.HeloName, self.settings)
	if !stopClose() {
		err = errors.Join(err, context.Cause(dialCtx))
	}
	if err != nil {
		conn.Close()
		release()
		return nil, err
	}
	return &smtpMxConnection{
		conn:           conn,
		mxHost:         mxHost,
		mxAddress:      mxAddress,
		sendingAddress: *sendingAddress,
		keywords:       keywords,
		release:        release,
	}, nil
}
