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
//   - store.go, CertsStore: network_tls_cert, the only way this engine reaches Postgres.
//   - order.go, POST /tls/cert-order's acceptance.
//   - ca_policy.go, the policy's pure rules.
//   - budget.go, CertsBudget, {tcb_<ca>_<registered_domain>}.
//   - queue.go, the admission pass.
//   - service.go, the service, its seams to DNS and the CAs, and the routes' reads.
//
// A CA's Retry-After and the names' failed authorizations are held in the process, as the extender's
// hold is: a restart forgets them, and the CA's next refusal holds again.

package certsservice

import (
	"context"
	"errors"
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

// §12.8's /dns/* routes as certs drives them, the only writer of DNS-01 in URnetwork zones (D-DNS-8):
// TLS-M5-16's server.NewCertsDnsClient on api's routes with the internal-certs bearer
// (plan-TLS-internal-credentials), driven by TLS-M5-15's solver. Safe for concurrent use.
type CertsDns interface {
	// POST /dns/acme-challenge: the TXT values at _acme-challenge.<name>, at most 2, TTL 60, gone after 1 h,
	// at most 10 writes per name per hour. Answers the serial they were committed at. A 503 while a
	// restore runs is an error its caller retries with backoff.
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

// Authorizations the CA refused, by name, which hold those names (LE's 5 per identifier per hour).
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

	stateLock sync.Mutex
	// each CA's Retry-After, its margin added
	caHolds map[CertsCa]time.Time
	// each name's failed authorizations inside the window
	nameFailures map[string][]time.Time
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
		store:        store,
		dns:          dns,
		acme:         acme,
		budget:       NewCertsBudget(host.Redis, store, settings),
		settings:     settings,
		clock:        host.ClockOrReal(),
		caHolds:      map[CertsCa]time.Time{},
		nameFailures: map[string][]time.Time{},
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
// when the CA named none: a CA's refusal on a limit (a *CertsAcmeRateLimitError). Renewals and
// revocations go on. A later hold never shortens an earlier one.
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

// Counts a failed authorization of each name at now (a *CertsAcmeAuthorizationError), which holds a
// name at FailedAuthorizationCount inside the window.
func (self *CertsService) RecordAuthorizationFailures(names []string) {
	now := self.clock.Now()
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

// GET /tls/cert-order/<id>: the caller's own order, ErrCertsNotFound for anyone else's. A row holds a
// chain only for a custom domain (cert-1), so a URnetwork-zone order's chain is not served here until
// tls-m5-05-cert-row-values settles where an issued chain waits.
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

// Deletes the rows past RowRetention from their end, as the store can count it (CertsStore.PurgeEnded).
func (self *CertsService) Purge(ctx context.Context) (int, error) {
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	return self.store.PurgeEnded(callCtx, self.clock.Now().Add(-self.settings.RowRetention))
}
