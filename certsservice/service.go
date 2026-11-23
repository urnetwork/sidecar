// The certs engine (§13.8, §13.15; D-TLS-6, D-TLS-7): it proxies devices' CSRs to the CAs, queues their
// orders under one shared budget, and alone writes DNS-01 records in URnetwork zones. certs never holds a
// private key: a device's key stays in its keychain, and what arrives here is the public key, its names
// and the device's attestation of both (X1, R-TLS-4). Every statement a device acts on is its own or a
// CA's; certs originates only refusals (I-4).
//
// It runs in no service of its own. api hosts its routes (TLS-M5-16) and taskworker its chains
// (TLS-M5-17), each building a CertsService over the same store, so this package keeps the extender
// pattern (server/taskworker/work/extender_measurement_work.go) that sidecar cannot import: the row
// written before the order (order.go), a queue admitted under the policy (queue.go, ca_policy.go), a
// weekly new-set cap below the CA's counted in Redis (budget.go), and Retry-After holds.
//
// What lives where:
//
//   - settings.go, CertsSettings.
//   - store.go, CertsStore: network_tls_cert and network_tls_name_backoff, the only way this engine
//     reaches Postgres.
//   - order.go, POST /tls/cert-order's acceptance.
//   - ca_policy.go, the policy's pure rules.
//   - budget.go, CertsBudget, {tcb_<ca>_<registered_domain>}.
//   - queue.go, the admission pass.
//   - service.go, the service, its seams to DNS and the CAs, and the routes' reads.
//   - run.go, the chains' passes: orders, renewals and the revocation sweep (TLS-M5-17).
//   - hints.go, TlsHint on topic tls.
//
// A CA's Retry-After and each name's failed authorizations of the hour are held in the process, as the
// extender's hold is: a restart forgets them, and the CA's next refusal holds again. So is a challenge
// name dns refused a write at past dns_challenges_per_name_hour (QD-1204): its orders wait until dns's
// Retry-After, when the name's oldest write in the window leaves it, or NameWritesHold when dns named
// none, so a set past the cap costs one newOrder a refusal rather than one a pass; a restart forgets the
// hold, and dns's next refusal sets it again. A name's failure backoff at each CA (QD-857) is the
// store's, so a restart keeps it: each failed authorization there doubles the name's wait there up to
// FailureBackoffMax, and a success there ends it.

package certsservice

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// GET /dns/ready's answers (plan-TLS-canary-signal).
type CertsDnsReadiness string

const (
	// A restore moved the zone below the serial: write the same values again and wait on the new one.
	CertsDnsStale CertsDnsReadiness = "stale"
	// Every running NS serves the serial and §12.6's canary is clean.
	CertsDnsReady CertsDnsReadiness = "ready"
	// Every NS serves it, and the canary fails: an order keeps waiting, with no rewrite.
	CertsDnsCanaryFailing CertsDnsReadiness = "canary_failing"
)

// What a CertsDns or CertsAcme answers when the host gave none, so nothing reaches a zone or a CA.
var (
	ErrCertsDnsUnavailable  = errors.New("certs has no DNS client")
	ErrCertsAcmeUnavailable = errors.New("certs has no ACME client")
)

// POST /dns/acme-challenge refused a write because the name's writes this hour reached
// dns_challenges_per_name_hour (§12.8; D-DNS-8): dns's 429. It is ErrCertsDnsWriteRefused too, a refusal
// of the path that wrote nothing, but one of its own, on which the service holds the name's orders until
// dns's Retry-After rather than let each pass send a newOrder that the refused write then fails (QD-1204).
var ErrCertsDnsWriteRateLimited = fmt.Errorf("%w: the name's writes this hour are spent", ErrCertsDnsWriteRefused)

// A challenge write dns refused past dns_challenges_per_name_hour, as data for the policy (QD-1204): the
// challenge name it was for and dns's Retry-After. It is ErrCertsDnsWriteRateLimited.
type CertsDnsWriteRateLimitError struct {
	// The name whose _acme-challenge label the write was for, certsChallengeNameOf's form. Empty: the
	// client did not say, and every challenge name of the order is held.
	Name string
	// dns's Retry-After: how long until the name takes a write again, once the write whose leaving brings
	// its count in the window below the cap has left it. Zero: dns named none.
	RetryAfter time.Duration
}

func (self *CertsDnsWriteRateLimitError) Error() string {
	return ErrCertsDnsWriteRateLimited.Error()
}

func (self *CertsDnsWriteRateLimitError) Unwrap() error {
	return ErrCertsDnsWriteRateLimited
}

// §12.8's /dns/* routes as certs drives them, the only writer of DNS-01 in URnetwork zones (D-DNS-8):
// TLS-M5-16's server.NewCertsDnsClient on api's routes with the internal-certs bearer
// (plan-TLS-internal-credentials), driven by TLS-M5-15's solver. Safe for concurrent use.
type CertsDns interface {
	// POST /dns/acme-challenge: the TXT values at _acme-challenge.<name>, at most 2, TTL 60, gone after 1 h,
	// at most 10 writes per name per hour. Answers the serial they were committed at. A 503 while a
	// restore runs is an error its caller retries with backoff. A write past the hour's 10 is a
	// *CertsDnsWriteRateLimitError naming name and dns's Retry-After.
	WriteAcmeChallenge(ctx context.Context, name string, values []string) (serial uint64, err error)
	// Takes them out, however the order ended.
	RemoveAcmeChallenge(ctx context.Context, name string) error
	// GET /dns/ready?serial=s.
	Ready(ctx context.Context, serial uint64) (CertsDnsReadiness, error)
	// Whether §12.6's monitor canary is clean at serial: Ready answers ready. Anything else, an error
	// included, is not clean, so no order asks a CA to validate on a doubt (plan-TLS-canary-signal).
	CanaryClean(ctx context.Context, serial uint64) (bool, error)
}

// The CertsDns of a host that has no client: every write and read refused, the canary never clean.
type ClosedCertsDns struct{}

var _ CertsDns = ClosedCertsDns{}

func (ClosedCertsDns) WriteAcmeChallenge(ctx context.Context, name string, values []string) (uint64, error) {
	return 0, ErrCertsDnsUnavailable
}

func (ClosedCertsDns) RemoveAcmeChallenge(ctx context.Context, name string) error {
	return ErrCertsDnsUnavailable
}

func (ClosedCertsDns) Ready(ctx context.Context, serial uint64) (CertsDnsReadiness, error) {
	return "", ErrCertsDnsUnavailable
}

func (ClosedCertsDns) CanaryClean(ctx context.Context, serial uint64) (bool, error) {
	return false, ErrCertsDnsUnavailable
}

// A revocation's reason code (RFC 5280 §5.3.1).
type CertsRevocationReason int

const (
	CertsRevocationUnspecified          CertsRevocationReason = 0
	CertsRevocationKeyCompromise        CertsRevocationReason = 1
	CertsRevocationCessationOfOperation CertsRevocationReason = 5
)

// One order as it goes to a CA.
type CertsAcmeOrder struct {
	Ca      CertsCa
	Profile string
	// The row's CSR, in DER: a renewal sends the stored one, so an offline device still renews.
	Csr []byte
	// RFC 9773's certificate id of the certificate a renewal replaces. Empty otherwise.
	Replaces string
}

// What a CA issued.
type CertsAcmeIssued struct {
	// Each certificate in DER, leaf first.
	Chain      [][]byte
	AccountUri string
	// CertsSerialText's form.
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
}

// A CA's refusal under a rate limit, as data for the policy: its Retry-After, zero when it named none.
type CertsAcmeRateLimitError struct {
	Ca         CertsCa
	RetryAfter time.Time
}

func (self *CertsAcmeRateLimitError) Error() string {
	return "the CA refused under a rate limit"
}

// Authorizations the CA refused, by name, which hold those names (LE's 5 failed authorizations an
// identifier and account an hour, one back each 12 min; its rate-limits page, read 2026-11-15).
type CertsAcmeAuthorizationError struct {
	Ca    CertsCa
	Names []string
}

func (self *CertsAcmeAuthorizationError) Error() string {
	return "the CA refused an authorization"
}

// The CAs behind acmez, TLS-M5-15's NewCertsAcme: orders by DNS-01 through CertsDns, ARI and revocation.
// A refusal on a limit is a *CertsAcmeRateLimitError, a failed authorization a
// *CertsAcmeAuthorizationError. Safe for concurrent use, and no lock is held across its I/O.
type CertsAcme interface {
	Order(ctx context.Context, order *CertsAcmeOrder) (*CertsAcmeIssued, error)
	// RFC 9773's suggested window for a leaf in DER.
	RenewalInfo(ctx context.Context, ca CertsCa, leaf []byte) (windowStart time.Time, windowEnd time.Time, err error)
	Revoke(ctx context.Context, ca CertsCa, leaf []byte, reason CertsRevocationReason) error
}

// The CertsAcme of a host that has none: every call refused, so no order reaches a CA.
type ClosedCertsAcme struct{}

var _ CertsAcme = ClosedCertsAcme{}

func (ClosedCertsAcme) Order(ctx context.Context, order *CertsAcmeOrder) (*CertsAcmeIssued, error) {
	return nil, ErrCertsAcmeUnavailable
}

func (ClosedCertsAcme) RenewalInfo(ctx context.Context, ca CertsCa, leaf []byte) (time.Time, time.Time, error) {
	return time.Time{}, time.Time{}, ErrCertsAcmeUnavailable
}

func (ClosedCertsAcme) Revoke(ctx context.Context, ca CertsCa, leaf []byte, reason CertsRevocationReason) error {
	return ErrCertsAcmeUnavailable
}

// The engine. Safe for concurrent use.
type CertsService struct {
	store    CertsStore
	dns      CertsDns
	acme     CertsAcme
	budget   *CertsBudget
	settings *CertsSettings
	clock    sidecar.Clock
	// the host's hints, nil on a host with none: no TlsHint is published (hints.go)
	push sidecar.Push

	stateLock sync.Mutex
	// the newest cert_id minted here (newCertId)
	lastCertId sidecar.Id
	// each CA's Retry-After, its margin added
	caHolds map[CertsCa]time.Time
	// each name's failed authorizations inside the window
	nameFailures map[string][]time.Time
	// each challenge name dns refused a write at past its writes an hour, held until when (QD-1204)
	nameWritesHolds map[string]time.Time
}

// A service over store, with host's Redis for the budget and its clock. A nil dns or acme refuses every
// call, so a host that has not wired them reaches no zone and no CA. The service starts nothing: api and
// taskworker call it.
func NewCertsService(
	ctx context.Context,
	host *sidecar.ServiceHost,
	store CertsStore,
	dns CertsDns,
	acme CertsAcme,
	settings *CertsSettings,
) (*CertsService, error) {
	if host == nil || host.Redis == nil {
		return nil, errors.New("certs needs a host with Redis")
	}
	if store == nil {
		return nil, errors.New("certs needs a store")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if dns == nil {
		dns = ClosedCertsDns{}
	}
	if acme == nil {
		acme = ClosedCertsAcme{}
	}
	return &CertsService{
		store:           store,
		dns:             dns,
		acme:            acme,
		budget:          NewCertsBudget(host.Redis, store, settings),
		settings:        settings,
		clock:           host.ClockOrReal(),
		push:            host.Push,
		caHolds:         map[CertsCa]time.Time{},
		nameFailures:    map[string][]time.Time{},
		nameWritesHolds: map[string]time.Time{},
	}, nil
}

// The seams the order chains drive (TLS-M5-17).
func (self *CertsService) Dns() CertsDns {
	return self.dns
}

func (self *CertsService) Acme() CertsAcme {
	return self.acme
}

func (self *CertsService) Budget() *CertsBudget {
	return self.budget
}

// A context bounded by CallTimeout on the service's clock, and the call that ends it.
func (self *CertsService) callContext(ctx context.Context) (context.Context, func()) {
	callCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(self.settings.CallTimeout, cancel)
	return callCtx, func() {
		stop()
		cancel()
	}
}

// Holds every order a limit counts at ca until retryAfter and the margin, or DefaultRetryAfter from now
// when the CA named none: a CA's refusal on a limit (a *CertsAcmeRateLimitError). Renewals go on, since
// no rate limit of LE's counts an ARI renewal, and so do revocations, which order nothing. A later hold
// never shortens an earlier one.
func (self *CertsService) HoldCa(ca CertsCa, retryAfter time.Time) {
	now := self.clock.Now()
	until := now.Add(self.settings.DefaultRetryAfter)
	if !retryAfter.IsZero() {
		until = retryAfter.Add(self.settings.RetryAfterMargin)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if until.After(self.caHolds[ca]) {
		self.caHolds[ca] = until
	}
}

// Holds every order whose CSR holds name's challenge name, at every CA, for retryAfter and the margin from
// now, or NameWritesHold from now when dns named no Retry-After: dns's refusal of a challenge write past
// dns_challenges_per_name_hour (a *CertsDnsWriteRateLimitError; QD-1204). Renewals wait too, since they
// write the same name and dns refuses theirs alike. A later hold never shortens an earlier one, and holds
// that have ended are dropped as another is set, so the process keeps only those of the last window.
func (self *CertsService) HoldChallengeName(name string, retryAfter time.Duration) {
	name = certsChallengeNameOf(name)
	if name == "" {
		return
	}
	now := self.clock.Now()
	until := now.Add(self.settings.NameWritesHold)
	if 0 < retryAfter {
		until = now.Add(retryAfter + self.settings.RetryAfterMargin)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for heldName, heldUntil := range self.nameWritesHolds {
		if !now.Before(heldUntil) {
			delete(self.nameWritesHolds, heldName)
		}
	}
	if until.After(self.nameWritesHolds[name]) {
		self.nameWritesHolds[name] = until
	}
}

// Holds the challenge name that dns's refusal of row's order names (a *CertsDnsWriteRateLimitError), or
// every challenge name of row's CSR when the refusal names none, ErrCertsDnsWriteRateLimited alone
// among them.
func (self *CertsService) holdRefusedChallengeNames(row *sidecar.TlsCertRecord, err error) {
	var refusal *CertsDnsWriteRateLimitError
	if errors.As(err, &refusal) && refusal.Name != "" {
		self.HoldChallengeName(refusal.Name, refusal.RetryAfter)
		return
	}
	retryAfter := time.Duration(0)
	if refusal != nil {
		retryAfter = refusal.RetryAfter
	}
	// the CA was sent this CSR, so it parsed
	names, _ := certsCsrNames(row.Csr)
	for _, name := range names {
		self.HoldChallengeName(name, retryAfter)
	}
}

// Until when dns's refusals hold an order whose CSR names names, zero when none does at now: the latest
// hold of their challenge names that is still ahead.
func (self *CertsService) nameWritesHeldUntil(names []string, now time.Time) time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	until := time.Time{}
	for _, name := range names {
		if heldUntil := self.nameWritesHolds[certsChallengeNameOf(name)]; now.Before(heldUntil) && heldUntil.After(until) {
			until = heldUntil
		}
	}
	return until
}

// Counts a failed authorization of each name at ca at now (a *CertsAcmeAuthorizationError) twice: in the
// process, where FailedAuthorizationCount of them inside the window hold the name at every CA, and in the
// store, where they back the name off at ca alone (QD-857), which a restart keeps. The store's count is
// written on a bound of its own, so a pass that ends as its CA answers still counts what the CA refused.
// Returns what the store refused; the process counts every name whatever it answers.
func (self *CertsService) RecordAuthorizationFailures(ctx context.Context, ca CertsCa, names []string) error {
	now := self.clock.Now()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, name := range names {
			kept := []time.Time{}
			for _, failureTime := range self.nameFailures[name] {
				if now.Sub(failureTime) < self.settings.FailedAuthorizationWindow {
					kept = append(kept, failureTime)
				}
			}
			self.nameFailures[name] = append(kept, now)
		}
	}()
	callCtx, cancel := self.callContext(context.WithoutCancel(ctx))
	defer cancel()
	errs := []error{}
	for _, name := range names {
		testHookBarrier("certs.name_backoff.add", name)
		if _, err := self.store.AddNameFailure(callCtx, name, ca, now, self.settings.failureBackoffWait); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Counts an order's failed authorization at ca against the names of row's CSR the CA refused, or all of
// them when it named none of them (certsRefusedNames).
func (self *CertsService) recordOrderFailure(ctx context.Context, row *sidecar.TlsCertRecord, ca CertsCa, refusedNames []string) error {
	// the CA was sent this CSR, so it parsed
	csrNames, _ := certsCsrNames(row.Csr)
	return self.RecordAuthorizationFailures(ctx, ca, certsRefusedNames(csrNames, refusedNames))
}

// Ends the backoff at ca of the names of row, whose order there just issued: a success starts the CA's
// count of their consecutive failed authorizations again (QD-857). The hour's hold in the process stays,
// since a success hands back none of the CA's hourly failures. Written on a bound of its own, as a
// failure is.
func (self *CertsService) resetNameBackoffs(ctx context.Context, row *sidecar.TlsCertRecord, ca CertsCa) error {
	names, err := certsCsrNames(row.Csr)
	if err != nil || len(names) == 0 {
		return err
	}
	callCtx, cancel := self.callContext(context.WithoutCancel(ctx))
	defer cancel()
	testHookBarrier("certs.name_backoff.clear", row.CertId.String())
	_, err = self.store.ClearNameBackoffs(callCtx, names, ca)
	return err
}

// Until when the backoffs of row's names hold an order for it at ca, zero when none does now: an order
// admitted before one of its names failed at ca, or left under way by a pass that ended, waits out the
// backoff as one admitted now would. A CSR that does not parse names nothing, and its order fails at the
// CA as before.
func (self *CertsService) nameBackoffUntil(ctx context.Context, row *sidecar.TlsCertRecord, ca CertsCa) (time.Time, error) {
	names, err := certsCsrNames(row.Csr)
	if err != nil || len(names) == 0 {
		return time.Time{}, nil
	}
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	backoffs, err := self.store.ListNameBackoffs(callCtx, names)
	if err != nil {
		return time.Time{}, err
	}
	return certsNameBackoffUntil(backoffs, ca, self.clock.Now()), nil
}

// ca's hold, zero when it has none.
func (self *CertsService) caHold(ca CertsCa) time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.caHolds[ca]
}

// A copy of a name's failed authorizations.
func (self *CertsService) nameFailureTimes(name string) []time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]time.Time{}, self.nameFailures[name]...)
}

// Whether a state is one an order is still under way in.
func certsOrderOpen(state sidecar.TlsCertState) bool {
	return state == sidecar.TlsCertStateQueued || state == sidecar.TlsCertStateOrdering || state == sidecar.TlsCertStateWaitingDns
}

// GET /tls/cert-order/<id>: the caller's own order, ErrCertsNotFound for anyone else's. The chain is
// the row's, written when its order issued (run.go) and kept until ChainRetention past the
// certificate's end, so it is read the same after a restart and by a device that was offline.
func (self *CertsService) OrderStatus(ctx context.Context, networkId sidecar.Id, clientId sidecar.Id, certId sidecar.Id) (*sidecar.TlsCertOrderStatus, error) {
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	row, err := self.store.GetCert(callCtx, certId)
	if err != nil {
		return nil, err
	}
	if row.NetworkId != networkId || row.ClientId != clientId {
		return nil, ErrCertsNotFound
	}
	status := &sidecar.TlsCertOrderStatus{
		State:          row.State,
		Chain:          row.Chain,
		AriWindowStart: row.AriWindowStart,
		AriWindowEnd:   row.AriWindowEnd,
	}
	if certsOrderOpen(row.State) {
		status.RetryAfterMs = uint32(self.settings.OrderRetryAfter.Milliseconds())
	}
	return status, nil
}

// GET /tls/certs: the network's certificates and attestations, for the CT watch (D-TLS-8) and a device
// checking its row survived a restore. A CSR is shown only among a custom domain's queued CSRs (v1),
// which M5 has none of.
func (self *CertsService) Certs(ctx context.Context, networkId sidecar.Id) (*sidecar.TlsCertsResult, error) {
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	rows, err := self.store.ListNetworkCerts(callCtx, networkId)
	if err != nil {
		return nil, err
	}
	result := &sidecar.TlsCertsResult{Certs: []*sidecar.TlsCertRecord{}}
	for _, row := range rows {
		shown := *row
		shown.Csr = nil
		result.Certs = append(result.Certs, &shown)
	}
	return result, nil
}

// What one purge removed.
type CertsPurgeReport struct {
	// Rows that lost their chain and stay.
	ChainCount int
	// Rows deleted.
	RowCount int
	// Names' failure backoffs deleted.
	NameBackoffCount int
}

// Drops the chains past ChainRetention from their certificate's expiry or revocation, then deletes the
// rows past RowRetention from their expiry, revocation or failure, then the names' failure backoffs past
// FailureBackoffRetention from the time each held orders until (cert-1; CertsStore.PurgeChains,
// CertsStore.PurgeEnded, CertsStore.PurgeNameBackoffs). An error ends it with what it has done.
func (self *CertsService) Purge(ctx context.Context) (*CertsPurgeReport, error) {
	report := &CertsPurgeReport{}
	now := self.clock.Now()
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	chainCount, err := self.store.PurgeChains(callCtx, now.Add(-self.settings.ChainRetention))
	if err != nil {
		return report, err
	}
	report.ChainCount = chainCount
	rowCount, err := self.store.PurgeEnded(callCtx, now.Add(-self.settings.RowRetention))
	if err != nil {
		return report, err
	}
	report.RowCount = rowCount
	backoffCount, err := self.store.PurgeNameBackoffs(callCtx, now.Add(-self.settings.FailureBackoffRetention))
	if err != nil {
		return report, err
	}
	report.NameBackoffCount = backoffCount
	return report, nil
}
