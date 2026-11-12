//go:build !sidecar_http && !ios_extension

// §14.4's TLS policy (D-SMTP-2, R-SMTP-13, X7): the check behind SmtpProofJob.VerifyPeer, which decides
// how the sidecar, as TLS client, authenticated the MX the edge spliced it to, best level first.
//
//   - TL1, DANE (smtp_dane.go): the edge's dnssec_chain validates to the sidecar's own anchors and a
//     usable TLSA record matches what the MX presented. A validated TLSA RRset matching nothing refuses
//     the MX outright (RFC 7672 §2.2), and no other level overrides that (RFC 8461 §2).
//   - TL2, MTA-STS (smtp_mtasts.go): the recipient domain's policy, which the sidecar finds over its own
//     DoH and fetches itself, is in mode enforce, lists mx_host, and PKIX holds for mx_host. An enforced
//     policy that does not list the MX, or whose MX fails PKIX, refuses that MX outright, since RFC 8461
//     §5 forbids delivery to it. Modes testing and none are not TL2.
//   - TL3, independent MX: the sidecar's own DoH MX lookup of the recipient domain names mx_host, or
//     finds no MX RRset and mx_host is the domain itself (RFC 5321 §5.1's implicit MX,
//     plan-SMTP-small-readings#13), and PKIX holds for mx_host.
//   - TL4: nothing.
//
// Then what may refuse the level reached, in this order: a level below the host's pin (SmtpPinStore), a
// refused downgrade; a REQUIRETLS message at neither TL1 nor TL2 (plan-SMTP-small-readings#12); and TL4
// for a recipient domain the user has not allowed (owner decision 38, an outward action under I-8).
// The allowance is its own action, mail_tls_unauthenticated with the domain as host (QD-729):
// AllowUnauthenticated passes it through Sidecar.Authorize, and its effect keeps the allowance in the
// desktop's store until it ends (smtp_tls_allowance.go). TL4 then passes for a domain with an allowance
// that holds, or for a message whose verified outbox entry names the domain in tl4_domains
// (plan-SMTP-small-readings#11), the composing device's approval, and for nothing else: an approval of
// a mail_send to the domain is consent to that message, never to TL4. What passes raises or refreshes
// the host's pin before the handshake goes on.
//
// The refusal comes inside the handshake, as VerifyPeer's error, so no application byte reaches the MX:
// no data, then a retry, then a DSN (§14.4). SendSmtp returns only that error, so the
// SmtpTlsAuthentication VerifyPeer belongs to records the level reached and any refusal, which the
// sender reads for the outcome (tls_refused), the DSN's reason, SmtpOutcome's downgrade_refused and the
// level every sent copy records (I-11), with EX4's label at TL4.
//
// Traps: the edge's ehlo_keywords are hints and count for nothing, so nothing here reads them; the policy
// fetch and both DoH lookups go from the device, never through the edge; and a receiver with no §13
// certificate reaches only TL1 with no case of its own, because PKIX simply fails for it. PKIX checks
// against roots, the system's when nil, at the injected clock's time.
//
// Every lookup that needs the network runs in Authenticate, before the ClientHello, so VerifyPeer does
// only checks, a read of the domain's allowance at TL4 and one pin write. Nothing here logs, and no
// error names a host or domain (I-13).
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// connect's own cache is what a daemon hands the policy.
var _ SmtpDohForwarder = (*connect.DohCache)(nil)

// RFC 3463's enhanced status a DSN for a TLS refusal carries: missing TLS authentication, the status
// plan-SMTP-small-readings#12 gives REQUIRETLS's, as RFC 8689 does.
const SmtpTlsRefusalStatus = "5.7.10"

var (
	// The MX was refused inside the handshake. errors.As finds the *SmtpTlsRefusal saying why.
	ErrSmtpTlsRefused = errors.New("smtp tls: mx refused")
	// A recipient domain or MX host outside RFC 5321's Domain, or flags this version does not know.
	ErrSmtpTlsRequest = errors.New("smtp tls: invalid request")
	// The allowance's action passed the gate and the store holds no allowance for the domain: its effect
	// did not happen, its outcome is not known, or the allowance has since ended.
	ErrSmtpTlsAllowanceNotKept = errors.New("smtp tls: the allowance was not kept")
	// One connection's peer is checked once.
	errSmtpTlsCheckedTwice = errors.New("smtp tls: a connection's peer checked twice")
)

// The device's own DoH, which TL2's _mta-sts lookup and TL3's MX lookup take (§2.8 ext-3): connect's
// DohCache.Forward, the raw RFC 8484 response to qType for a domain given without a trailing dot, and
// whether a usable one came. The sender owns its own cache (connect/CODESTYLE.md's DoH rule). Safe for
// concurrent use.
type SmtpDohForwarder interface {
	Forward(ctx context.Context, qType dnsmessage.Type, domain string) (response []byte, usable bool)
}

// Why an MX was refused.
type SmtpTlsRefusalKind uint32

const (
	// Never a refusal.
	SmtpTlsRefusalUnspecified SmtpTlsRefusalKind = 0
	// TL4, and the user has not allowed the recipient domain (owner decision 38).
	SmtpTlsRefusalUnauthenticated SmtpTlsRefusalKind = 1
	// A level below the host's pin: a refused downgrade (D-SMTP-2).
	SmtpTlsRefusalBelowPin SmtpTlsRefusalKind = 2
	// A validated TLSA RRset matched nothing the MX presented (RFC 7672 §2.2).
	SmtpTlsRefusalDaneMismatch SmtpTlsRefusalKind = 3
	// The domain's enforced MTA-STS policy does not list the MX, or PKIX fails for it (RFC 8461 §5).
	SmtpTlsRefusalMtaSts SmtpTlsRefusalKind = 4
	// A REQUIRETLS message at neither TL1 nor TL2 (RFC 8689, plan-SMTP-small-readings#12).
	SmtpTlsRefusalRequireTls SmtpTlsRefusalKind = 5
)

// A refused MX: no application byte was sent. It is an error that Is ErrSmtpTlsRefused, and names no
// host or domain.
type SmtpTlsRefusal struct {
	Kind SmtpTlsRefusalKind
	// The level the MX reached before the refusal, TL1 to TL4; unreached when DANE or MTA-STS refused it
	// outright.
	Level SmtpTlsLevel
	// The pin's level, for a refused downgrade.
	PinLevel SmtpTlsLevel
}

// The kind in words, with the levels where they say why.
func (self *SmtpTlsRefusal) Error() string {
	switch self.Kind {
	case SmtpTlsRefusalUnauthenticated:
		return "smtp tls: mx refused: unauthenticated, and not allowed"
	case SmtpTlsRefusalBelowPin:
		return fmt.Sprintf("smtp tls: mx refused: level %d below a level %d pin", self.Level, self.PinLevel)
	case SmtpTlsRefusalDaneMismatch:
		return "smtp tls: mx refused: no tlsa record matches"
	case SmtpTlsRefusalMtaSts:
		return "smtp tls: mx refused: the enforced mta-sts policy fails"
	case SmtpTlsRefusalRequireTls:
		return fmt.Sprintf("smtp tls: mx refused: requiretls at level %d", self.Level)
	}
	return "smtp tls: mx refused"
}

// Whether target is ErrSmtpTlsRefused.
func (self *SmtpTlsRefusal) Is(target error) bool {
	return target == ErrSmtpTlsRefused
}

// Whether the refusal kept the send off a level below the host's pin, SmtpOutcome's downgrade_refused.
func (self *SmtpTlsRefusal) DowngradeRefused() bool {
	return self.Kind == SmtpTlsRefusalBelowPin
}

// The reason a DSN gives the sender, in words, beside the recipient domain the DSN names (§14.4).
func (self *SmtpTlsRefusal) Reason() string {
	switch self.Kind {
	case SmtpTlsRefusalUnauthenticated:
		return "The receiving mail server could not be authenticated, by DANE, an enforced MTA-STS policy or a " +
			"valid certificate for its name, so an active URnetwork edge could have read the message. Sending " +
			"to this domain without authentication has not been allowed, so the message was not sent."
	case SmtpTlsRefusalBelowPin:
		return "The receiving mail server authenticated less strongly than it has before, which an attack on " +
			"the connection would cause, so the message was not sent."
	case SmtpTlsRefusalDaneMismatch:
		return "The receiving mail server's certificate does not match the domain's DANE (TLSA) records, so " +
			"the message was not sent."
	case SmtpTlsRefusalMtaSts:
		return "The receiving mail server does not meet the domain's enforced MTA-STS policy, so the message " +
			"was not sent."
	case SmtpTlsRefusalRequireTls:
		return "The message requires TLS (REQUIRETLS), and the receiving mail server could not be " +
			"authenticated by DANE or an enforced MTA-STS policy, so the message was not sent."
	}
	return "The receiving mail server was refused, so the message was not sent."
}

// What one connection's check is decided from: the recipient domain, and what the edge's
// SmtpPreambleResult named.
type SmtpTlsRequest struct {
	RecipientDomain string
	// mx_host: the MX the edge resolved and dialed, which the ClientHello's SNI names.
	MxHost string
	// dnssec_chain, empty when the edge sent none.
	DnssecChain []byte
	// SmtpPreamble.flags: SmtpFlagRequireTls takes TL1 or TL2 only.
	Flags uint32
	// The recipient domains this message's own approval lets go at TL4: SmtpOutboundMessage.Tl4Domains,
	// only ever from an outbox entry whose signature the prover host verified (plan-SMTP-small-readings#11).
	MessageTl4Domains []string
}

// §5.4's gate as the policy asks it for a TL4 allowance: Sidecar.Authorize, the one entry point every
// outward action passes (I-8). Safe for concurrent use.
type SmtpTlsAuthorizer interface {
	// nil once the action's effect has an outcome, in action.Outcome; *ApprovalPendingError while it
	// waits for a person; any other error refuses. decision may be nil.
	Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error
}

var _ SmtpTlsAuthorizer = (*Sidecar)(nil)

// One network sender's TLS policy. Safe for concurrent use.
type SmtpTlsPolicy struct {
	dane       *SmtpDane
	mtaSts     *SmtpMtaSts
	pins       *SmtpPinStore
	allowances *SmtpTlsAllowanceStore
	authorizer SmtpTlsAuthorizer
	doh        SmtpDohForwarder
	roots      *x509.CertPool
	settings   *SmtpSenderSettings
	clock      Clock
}

// The policy over TL1's dane, TL2's mtaSts, the device's own doh for TL3, pins, and TL4's allowances,
// which only an action that passed authorizer makes, checking PKIX against roots (nil is the system's),
// under settings, which must have passed validate, on clock (nil is real time). A nil authorizer
// refuses every allowance, as a sidecar with no gate does. Only roots and authorizer may be nil.
func NewSmtpTlsPolicy(dane *SmtpDane, mtaSts *SmtpMtaSts, pins *SmtpPinStore, allowances *SmtpTlsAllowanceStore, authorizer SmtpTlsAuthorizer, doh SmtpDohForwarder, roots *x509.CertPool, settings *SmtpSenderSettings, clock Clock) *SmtpTlsPolicy {
	if authorizer == nil {
		authorizer = sidecarGateDeny{}
	}
	return &SmtpTlsPolicy{
		dane:       dane,
		mtaSts:     mtaSts,
		pins:       pins,
		allowances: allowances,
		authorizer: authorizer,
		doh:        doh,
		roots:      roots,
		settings:   settings,
		clock:      clockOrReal(clock),
	}
}

// What the device's own DoH says the recipient domain's MX hosts are (TL3).
type smtpTlsMxView struct {
	// Lowercase, with no trailing dot.
	hosts []string
	// RFC 7505's null MX was among them: the domain takes no mail.
	nullMx bool
	// The domain exists and has no MX RRset, so it is its own MX.
	implicit bool
}

// Whether the view names mxHost as one of domain's MXs.
func (self *smtpTlsMxView) agrees(domain string, mxHost string) bool {
	if self == nil || self.nullMx {
		return false
	}
	if self.implicit {
		return mxHost == domain
	}
	return slices.Contains(self.hosts, mxHost)
}

// The domain's MX view by the device's own DoH, nil when no usable answer came or the domain does not
// exist: then nothing agrees, and TL3 is out of reach for the send.
func (self *SmtpTlsPolicy) lookupMx(ctx context.Context, domain string) *smtpTlsMxView {
	if self.doh == nil {
		return nil
	}
	answer, ok := smtpDohLookup(ctx, self.doh, self.clock, self.settings.TlsLookupTimeout, dnsmessage.TypeMX, domain)
	if !ok || !answer.exists {
		return nil
	}
	view := &smtpTlsMxView{implicit: len(answer.resources) == 0}
	for _, resource := range answer.resources {
		mx, ok := resource.Body.(*dnsmessage.MXResource)
		if !ok {
			continue
		}
		host := smtpDohName(mx.MX)
		if host == "" {
			view.nullMx = true
			continue
		}
		if host, ok := smtpTlsName(host); ok {
			view.hosts = append(view.hosts, host)
		}
	}
	return view
}

// Readies one connection's check: the names held to their form, the host's pin read, and TL2's policy
// and TL3's MX view looked up from the device, side by side. Its errors are ErrSmtpTlsRequest, the
// store's, on which the sender holds the send, since a pin or policy it cannot read could be one that
// refuses this MX, and ctx's once it has ended. A DoH or HTTPS failure is no error: the level it would
// have given is out of reach.
func (self *SmtpTlsPolicy) Authenticate(ctx context.Context, request *SmtpTlsRequest) (*SmtpTlsAuthentication, error) {
	if request == nil || request.Flags&^SmtpFlagsKnown != 0 {
		return nil, ErrSmtpTlsRequest
	}
	domain, domainOk := smtpTlsName(request.RecipientDomain)
	mxHost, hostOk := smtpTlsName(request.MxHost)
	if !domainOk || !hostOk {
		return nil, ErrSmtpTlsRequest
	}
	if _, err := self.pins.Pin(mxHost); err != nil {
		return nil, err
	}
	authentication := &SmtpTlsAuthentication{
		policy:      self,
		domain:      domain,
		mxHost:      mxHost,
		dnssecChain: slices.Clone(request.DnssecChain),
		requireTls:  request.Flags&SmtpFlagRequireTls != 0,
	}
	for _, allowed := range request.MessageTl4Domains {
		if allowed, ok := smtpTlsName(allowed); ok && allowed == domain {
			authentication.messageAllowed = true
		}
	}
	var policyErr error
	var lookups sync.WaitGroup
	lookups.Go(func() {
		authentication.mtaStsPolicy, policyErr = self.mtaSts.Policy(ctx, domain)
	})
	lookups.Go(func() {
		authentication.mxView = self.lookupMx(ctx, domain)
	})
	lookups.Wait()
	if policyErr != nil {
		return nil, policyErr
	}
	// a lookup the caller ended found nothing, which must not read as a domain without a policy or an MX
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return authentication, nil
}

// The effect of one allowance's action: the store keeps the domain's allowance under the use's key.
type smtpTlsAllowanceEffect struct {
	allowances *SmtpTlsAllowanceStore
	domain     string
	expireTime time.Time
}

// Keeps the allowance, idempotent per effectKey, and answers its reference. An allowance that has
// already ended, or one the store has no room for, proves no effect happened; a store that failed
// leaves the use uncertain, for a retry under the same key.
func (self *smtpTlsAllowanceEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	var approvalId *Id
	if spend, ok := ApprovalSpendFromContext(ctx); ok {
		approvalId = &spend.ApprovalId
	}
	allowance, err := self.allowances.allow(self.domain, self.expireTime, effectKey, approvalId)
	if errors.Is(err, ErrSmtpTlsAllowanceEnded) || errors.Is(err, ErrSmtpTlsAllowanceFull) {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	if err != nil {
		return nil, err
	}
	return allowance.effectRef(), nil
}

// The user's allowance to send to recipientDomain at TL4 until expireTime, the zero time for an
// allowance that does not end (§14.4, owner decision 38, QD-729): the outward action
// mail_tls_unauthenticated, built here from the domain in its one form, lowercase with no trailing
// dot, and the expiry, never from an agent's words, and passed through Sidecar.Authorize (I-8) with
// decision, which may be nil. Its effect keeps the allowance in the store per recipient domain
// (plan-SMTP-small-readings#11), where VerifyPeer finds it until it ends, and the mail it lets through
// carries EX4's label.
//
// nil once the store holds the domain's allowance. *ApprovalPendingError while the action waits for a
// person: the same domain and expiry are the same action, so the call after the approval names both
// again. ErrSmtpTlsRequest for a name outside RFC 5321's Domain, ErrSmtpTlsAllowanceEnded for an expiry
// not ahead of now, ErrSmtpTlsAllowanceFull when the store has no room, each before any gate is asked,
// so no approval is spent on them; ErrSmtpTlsAllowanceNotKept when the gate passed the action and no
// allowance holds; any other error is the gate's or the store's. The approval binds this action's
// bytes, so one of a mail_send to the domain, or of another domain's allowance, spends nothing here.
func (self *SmtpTlsPolicy) AllowUnauthenticated(ctx context.Context, recipientDomain string, expireTime time.Time, decision *bridge.Signed) error {
	domain, ok := smtpTlsName(recipientDomain)
	if !ok {
		return ErrSmtpTlsRequest
	}
	expiresMillis := int64(0)
	if !expireTime.IsZero() {
		expiresMillis = expireTime.UnixMilli()
		// 0 on the wire is an allowance that does not end, which an expiry must never read as
		if expiresMillis <= 0 || expiresMillis <= self.clock.Now().UnixMilli() {
			return ErrSmtpTlsAllowanceEnded
		}
		expireTime = time.UnixMilli(expiresMillis)
	}
	if err := self.allowances.checkRoom(domain); err != nil {
		return err
	}
	stored, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind:          uint32(SidecarActionMailTlsUnauthenticated),
		Host:          domain,
		ExpiresMillis: expiresMillis,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSmtpTlsRequest, err)
	}
	// the user's own act, in no run: nothing here is an agent's, so nothing raises the risk
	action, err := NewSidecarAction(stored, SidecarRiskNormal, SidecarRiskUnspecified, nil, nil)
	if err != nil {
		return err
	}
	action.Effect = &smtpTlsAllowanceEffect{allowances: self.allowances, domain: domain, expireTime: expireTime}
	if err := self.authorizer.Authorize(ctx, action, decision); err != nil {
		return err
	}
	if outcome := action.Outcome; outcome != nil && outcome.State != ApprovalOutcomeDone {
		if outcome.Err != nil {
			return fmt.Errorf("%w: %w", ErrSmtpTlsAllowanceNotKept, outcome.Err)
		}
		return fmt.Errorf("%w: its use is %s", ErrSmtpTlsAllowanceNotKept, outcome.State)
	}
	// a gate's nil is not taken on its word: the allowance is in the store, or there is none
	allowance, err := self.allowances.Allowance(domain)
	if err != nil {
		return err
	}
	if allowance == nil {
		return ErrSmtpTlsAllowanceNotKept
	}
	return nil
}

// The allowance that holds for recipientDomain now, or nil when none does (§14.4).
func (self *SmtpTlsPolicy) UnauthenticatedAllowance(recipientDomain string) (*SmtpTlsAllowance, error) {
	return self.allowances.Allowance(recipientDomain)
}

// mail_tls_unauthenticated's Lookup (§16.6's spend step 5, plan-MCP-effect-seam), which the sender's
// host registers with Sidecar.RegisterEffectLookup: done, with the effect's reference, where the store
// holds the allowance made under effectKey for the action's domain; else uncertain, since an allowance
// a later one replaced is no longer found by its key, so a retry of the same action completes the use
// under the same key. An action of another kind is an error.
func (self *SmtpTlsPolicy) Lookup(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
	stored, err := ParseStoredCanonicalAction(canonical)
	if err != nil {
		return nil, err
	}
	if SidecarActionKind(stored.Action.GetKind()) != SidecarActionMailTlsUnauthenticated {
		return nil, fmt.Errorf("%w: kind %d is no tls allowance", ErrSidecarActionInvalid, stored.Action.GetKind())
	}
	allowance, err := self.allowances.effect(effectKey)
	if err != nil {
		return nil, err
	}
	if allowance != nil && allowance.RecipientDomain == stored.Action.GetHost() {
		return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: allowance.effectRef()}, nil
	}
	return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
}

// Whether chain's leaf holds for host under the policy's roots at now, through chain's other
// certificates, for server authentication (RFC 8461 §4.2, RFC 6125 §6.3).
func (self *SmtpTlsPolicy) pkixHolds(chain []*x509.Certificate, host string, now time.Time) bool {
	if len(chain) == 0 {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         self.roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
}

// One connection's check, from Authenticate: VerifyPeer is SmtpProofJob.VerifyPeer, and what it decided
// stays here for the sender to read once SendSmtp returns. Safe for concurrent use.
type SmtpTlsAuthentication struct {
	policy         *SmtpTlsPolicy
	domain         string
	mxHost         string
	dnssecChain    []byte
	requireTls     bool
	messageAllowed bool
	// TL2's policy, nil when none applies
	mtaStsPolicy *SmtpMtaStsPolicy
	// TL3's view, nil when no usable answer came
	mxView *smtpTlsMxView

	stateLock sync.Mutex
	checked   bool
	level     SmtpTlsLevel
	refusal   *SmtpTlsRefusal
}

// The level chain reaches at now before the pin and allowance rules, or the refusal DANE or MTA-STS
// gives that MX outright.
func (self *SmtpTlsAuthentication) reach(chain []*x509.Certificate, now time.Time) (SmtpTlsLevel, *SmtpTlsRefusal) {
	dane, err := self.policy.dane.Authenticate(self.domain, self.mxHost, self.dnssecChain, chain)
	if err != nil {
		return SmtpTlsLevelUnreached, &SmtpTlsRefusal{Kind: SmtpTlsRefusalDaneMismatch}
	}
	if dane.Status == SmtpDaneStatusAuthenticated {
		return SmtpTlsLevelDane, nil
	}
	pkixChecked, pkixHeld := false, false
	pkix := func() bool {
		if !pkixChecked {
			pkixChecked, pkixHeld = true, self.policy.pkixHolds(chain, self.mxHost, now)
		}
		return pkixHeld
	}
	if self.mtaStsPolicy != nil && self.mtaStsPolicy.Enforced() && now.Before(self.mtaStsPolicy.ExpireTime()) {
		if !self.mtaStsPolicy.MatchesMx(self.mxHost) || !pkix() {
			return SmtpTlsLevelUnreached, &SmtpTlsRefusal{Kind: SmtpTlsRefusalMtaSts}
		}
		return SmtpTlsLevelMtaSts, nil
	}
	if self.mxView.agrees(self.domain, self.mxHost) && pkix() {
		return SmtpTlsLevelIndependentMx, nil
	}
	return SmtpTlsLevelUnauthenticated, nil
}

// Decides the level of the chain the MX presented, leaf first, as SmtpProofJob.VerifyPeer, inside the
// handshake: nil once the level passes and the host's pin has been raised to it or refreshed, so the
// handshake goes on; a *SmtpTlsRefusal when the MX is refused, so no application byte is sent; any other
// error is the store's, which records no level and holds the send. TL4 passes for a message whose own
// approval names the domain, or for a domain whose allowance holds now, read from the store here, so
// one that ended since Authenticate lets nothing through. It decides once: a second call is refused.
func (self *SmtpTlsAuthentication) VerifyPeer(chain []*x509.Certificate) error {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.checked {
			return false
		}
		self.checked = true
		return true
	}()
	if !first {
		return errSmtpTlsCheckedTwice
	}
	refuse := func(refusal *SmtpTlsRefusal) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.refusal = refusal
		return refusal
	}
	level, refusal := self.reach(chain, self.policy.clock.Now())
	if refusal != nil {
		return refuse(refusal)
	}
	pin, err := self.policy.pins.Pin(self.mxHost)
	if err != nil {
		return err
	}
	switch {
	case pin != nil && pin.Level < level:
		return refuse(&SmtpTlsRefusal{Kind: SmtpTlsRefusalBelowPin, Level: level, PinLevel: pin.Level})
	case self.requireTls && SmtpTlsLevelMtaSts < level:
		return refuse(&SmtpTlsRefusal{Kind: SmtpTlsRefusalRequireTls, Level: level})
	}
	if level == SmtpTlsLevelUnauthenticated && !self.messageAllowed {
		// an allowance the store cannot read is neither one that holds nor none: the send is held
		allowance, err := self.policy.allowances.Allowance(self.domain)
		if err != nil {
			return err
		}
		if allowance == nil {
			return refuse(&SmtpTlsRefusal{Kind: SmtpTlsRefusalUnauthenticated, Level: level})
		}
	}
	// the check and the raise are one step in the store, so a pin another send raised since the read
	// above still refuses this one
	if _, err := self.policy.pins.Raise(self.mxHost, level); err != nil {
		if errors.Is(err, ErrSmtpPinBelow) {
			pinLevel := SmtpTlsLevelUnreached
			if pin, pinErr := self.policy.pins.Pin(self.mxHost); pinErr == nil && pin != nil {
				pinLevel = pin.Level
			}
			return refuse(&SmtpTlsRefusal{Kind: SmtpTlsRefusalBelowPin, Level: level, PinLevel: pinLevel})
		}
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.level = level
	return nil
}

// The level VerifyPeer passed, which the sent copy records (I-11), or unreached when it refused or never
// ran.
func (self *SmtpTlsAuthentication) Level() SmtpTlsLevel {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.level
}

// Why VerifyPeer refused the MX, nil when it did not: the send's outcome is then tls_refused, and its
// DSN gives Reason.
func (self *SmtpTlsAuthentication) Refusal() *SmtpTlsRefusal {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refusal
}

// Whether VerifyPeer refused a level below the host's pin, SmtpOutcome's downgrade_refused.
func (self *SmtpTlsAuthentication) DowngradeRefused() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refusal != nil && self.refusal.DowngradeRefused()
}

// Records the post-TLS mode of the session, once its EHLO reply inside TLS chose it, for the host's pin
// and the recipient domain's last session, which Check reports (§14.5). Nothing is recorded for a
// connection VerifyPeer did not pass, or for unknown.
func (self *SmtpTlsAuthentication) RecordMode(mode SmtpMode) error {
	if self.Level() == SmtpTlsLevelUnreached {
		return nil
	}
	return self.policy.pins.RecordMode(self.domain, self.mxHost, mode)
}

// What one DoH lookup proved.
type smtpDohAnswer struct {
	// The name exists: NOERROR, where false is NXDOMAIN.
	exists bool
	// The answer's records of the type asked, at the name or where its CNAMEs lead.
	resources []dnsmessage.Resource
}

// A name as every comparison here reads it: lowercase, with no trailing dot, and the root empty.
func smtpDohName(name dnsmessage.Name) string {
	return strings.ToLower(strings.TrimSuffix(name.String(), "."))
}

// Asks doh for name's qType records, within timeout on clock: false when no usable answer came, as
// for a failed, refused, truncated or malformed reply, one to another question, or the timeout.
func smtpDohLookup(ctx context.Context, doh SmtpDohForwarder, clock Clock, timeout time.Duration, qType dnsmessage.Type, name string) (*smtpDohAnswer, bool) {
	lookupCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := clock.AfterFunc(timeout, cancel)
	defer stop()
	response, usable := doh.Forward(lookupCtx, qType, name)
	if !usable || lookupCtx.Err() != nil {
		return nil, false
	}
	return parseSmtpDohResponse(response, qType, name)
}

// A DoH response to (name, qType), held to that question: the records of qType at name, or at the end
// of the CNAMEs the answer carries from it.
func parseSmtpDohResponse(response []byte, qType dnsmessage.Type, name string) (*smtpDohAnswer, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil || !header.Response || header.Truncated {
		return nil, false
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0].Type != qType || questions[0].Class != dnsmessage.ClassINET ||
		smtpDohName(questions[0].Name) != name {
		return nil, false
	}
	switch header.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return &smtpDohAnswer{}, true
	default:
		return nil, false
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return nil, false
	}
	// one hop a record at most, so a loop of CNAMEs ends
	current := name
	for range answers {
		next := ""
		for _, answer := range answers {
			cname, ok := answer.Body.(*dnsmessage.CNAMEResource)
			if ok && answer.Header.Class == dnsmessage.ClassINET && smtpDohName(answer.Header.Name) == current {
				next = smtpDohName(cname.CNAME)
				break
			}
		}
		if next == "" {
			break
		}
		current = next
	}
	answer := &smtpDohAnswer{exists: true}
	for _, resource := range answers {
		if resource.Header.Type == qType && resource.Header.Class == dnsmessage.ClassINET && smtpDohName(resource.Header.Name) == current {
			answer.resources = append(answer.resources, resource)
		}
	}
	return answer, true
}
