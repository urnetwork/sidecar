// CertsAcme on acmez v3 (§13.8; Apache-2.0, https://github.com/mholt/acmez): orders from a stored CSR by
// DNS-01 alone, through CertsDnsSolver's fenced block, on URnetwork's account at each CA; ARI windows;
// revocation with a reason; and the accounts' rollover and deactivation. It never sees a private key but
// its accounts': a device's key stays on the device, and what certs sends a CA is the device's CSR.
//
// What a CA says no with is data for the policy (ca_policy.go): a refusal on a rate limit comes back as
// *CertsAcmeRateLimitError with the CA's Retry-After, which acmez does not surface, so the HTTP client
// keeps the Retry-After of every 429 it sees for the call that made it; a failed authorization comes back
// as *CertsAcmeAuthorizationError naming its identifiers. A bad nonce is acmez's to retry and never
// reaches here as a failure.
//
// Never HTTP-01 and never TLS-ALPN-01: the only solver is dns-01's, so a CA that offers nothing else
// is told no and the order fails.
//
// acmez polls on real time, so an order's own bound is a context on the service's clock. Safe for
// concurrent use; no lock is held across ACME I/O.

package certsservice

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"

	"github.com/urnetwork/sidecar"
)

// What certs calls itself to a CA, so a CA's operators can tell its traffic from another client's.
const certsUserAgent = "urnetwork-certs"

// What NewCertsAcme needs beyond its settings.
type CertsAcmeDeps struct {
	// The accounts, one per CA.
	Accounts *CertsAccountSet
	// §12.8's routes, which CertsDnsSolver writes and waits on.
	Dns CertsDns
	// nil is real time.
	Clock sidecar.Clock
	// How every CA is reached. nil takes a client on the default transport, the system's roots; a test
	// gives Pebble's.
	HttpClient *http.Client
}

// The Retry-After of the last 429 one call met.
type certsRetryAfter struct {
	stateLock sync.Mutex
	at        time.Time
}

func (self *certsRetryAfter) set(at time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if at.After(self.at) {
		self.at = at
	}
}

func (self *certsRetryAfter) get() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.at
}

type certsRetryAfterKey struct{}

// Reads the Retry-After of each 429 into the call's certsRetryAfter, which acmez's errors do not carry.
type certsRetryAfterTransport struct {
	base  http.RoundTripper
	clock sidecar.Clock
}

func (self *certsRetryAfterTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := self.base.RoundTrip(request)
	if err != nil || response.StatusCode != http.StatusTooManyRequests {
		return response, err
	}
	recorder, ok := request.Context().Value(certsRetryAfterKey{}).(*certsRetryAfter)
	if !ok {
		return response, err
	}
	if at, ok := certsParseRetryAfter(response.Header.Get("Retry-After"), self.clock.Now()); ok {
		recorder.set(at)
	}
	return response, err
}

// RFC 9110 §10.2.3's Retry-After: delay seconds or an HTTP date.
func certsParseRetryAfter(value string, now time.Time) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
		return now.Add(time.Duration(seconds) * time.Second), true
	}
	if at, err := http.ParseTime(value); err == nil {
		return at, true
	}
	return time.Time{}, false
}

// The CAs behind acmez, CertsAcme and the accounts' own changes. See the file header.
type CertsAcmeClient struct {
	settings *CertsSettings
	accounts *CertsAccountSet
	dns      CertsDns
	clock    sidecar.Clock
	solver   *CertsDnsSolver

	stateLock sync.Mutex
	// one acme client per CA, which keeps that CA's directory and nonces
	clients map[CertsCa]*acme.Client
	// the transport every client shares
	httpClient *http.Client
}

var _ CertsAcme = (*CertsAcmeClient)(nil)

// The CAs of settings, each with its account in deps.Accounts, DNS-01 through deps.Dns. A CA with no
// DirectoryUrl or no account refuses every order, so nothing reaches a CA certs has not been given.
func NewCertsAcme(settings *CertsSettings, deps *CertsAcmeDeps) (*CertsAcmeClient, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if deps == nil || deps.Accounts == nil || deps.Dns == nil {
		return nil, errors.New("certs' ACME needs accounts and a DNS client")
	}
	clock := deps.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	base := http.DefaultTransport
	httpClient := &http.Client{}
	if deps.HttpClient != nil {
		*httpClient = *deps.HttpClient
		if deps.HttpClient.Transport != nil {
			base = deps.HttpClient.Transport
		}
	}
	httpClient.Transport = &certsRetryAfterTransport{base: base, clock: clock}
	httpClient.Timeout = settings.AcmeRequestTimeout
	return &CertsAcmeClient{
		settings:   settings,
		accounts:   deps.Accounts,
		dns:        deps.Dns,
		clock:      clock,
		solver:     NewCertsDnsSolver(deps.Dns, settings, clock),
		clients:    map[CertsCa]*acme.Client{},
		httpClient: httpClient,
	}, nil
}

// The CA's client, made on first use.
func (self *CertsAcmeClient) client(ca CertsCa) (*acme.Client, error) {
	caSettings, ok := self.settings.Cas[ca]
	if !ok || caSettings == nil || caSettings.DirectoryUrl == "" {
		return nil, ErrCertsAcmeUnavailable
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	client, ok := self.clients[ca]
	if !ok {
		client = &acme.Client{
			Directory:    caSettings.DirectoryUrl,
			HTTPClient:   self.httpClient,
			UserAgent:    certsUserAgent,
			PollInterval: self.settings.AcmePollInterval,
			PollTimeout:  self.settings.AcmePollTimeout,
		}
		self.clients[ca] = client
	}
	return client, nil
}

// A context ending at timeout on the service's clock, which acmez's own real-time waits honor.
func (self *CertsAcmeClient) boundedContext(ctx context.Context, timeout time.Duration) (context.Context, func()) {
	boundedCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(timeout, cancel)
	return boundedCtx, func() {
		stop()
		cancel()
	}
}

// The account at ca, resolved at the CA on first use: by its current key, else by its next key, which
// a rollover before a restart left the CA holding, else new under the current key, bound by EAB when
// the file gives one.
func (self *CertsAcmeClient) account(ctx context.Context, ca CertsCa) (acme.Account, *acme.Client, error) {
	client, err := self.client(ca)
	if err != nil {
		return acme.Account{}, nil, err
	}
	state, err := self.accounts.state(ca)
	if err != nil {
		return acme.Account{}, nil, err
	}
	if state.account != nil {
		account := *state.account
		account.PrivateKey = state.key
		return account, client, nil
	}
	keys := []crypto.Signer{state.key}
	if state.nextKey != nil {
		keys = append(keys, state.nextKey)
	}
	for _, key := range keys {
		existing, err := client.GetAccount(ctx, acme.Account{PrivateKey: key, Contact: state.contact})
		if err == nil {
			if existing.Status != acme.StatusValid {
				self.accounts.markDeactivated(ca)
				return acme.Account{}, nil, ErrCertsAccountDeactivated
			}
			existing.PrivateKey = key
			self.accounts.resolved(ca, existing, key)
			return existing, client, nil
		}
		var problem acme.Problem
		if !errors.As(err, &problem) || problem.Type != acme.ProblemTypeAccountDoesNotExist {
			return acme.Account{}, nil, err
		}
	}
	account := acme.Account{PrivateKey: state.key, Contact: state.contact, TermsOfServiceAgreed: true}
	if state.eab != nil {
		if err := account.SetExternalAccountBinding(ctx, client, *state.eab); err != nil {
			return acme.Account{}, nil, err
		}
	}
	created, err := client.NewAccount(ctx, account)
	if err != nil {
		return acme.Account{}, nil, err
	}
	created.PrivateKey = state.key
	self.accounts.resolved(ca, created, state.key)
	return created, client, nil
}

// A certificate with only an RFC 9773 certificate id's two parts, the authority key id and the serial,
// which is all acmez reads of the certificate an order replaces.
func certsReplacedCertificate(certificateId string) (*x509.Certificate, error) {
	akiText, serialText, found := strings.Cut(certificateId, ".")
	if !found {
		return nil, errors.New("not an ARI certificate id")
	}
	aki, err := base64.RawURLEncoding.DecodeString(akiText)
	if err != nil {
		return nil, errors.New("not an ARI certificate id")
	}
	serialBytes, err := base64.RawURLEncoding.DecodeString(serialText)
	if err != nil || len(serialBytes) == 0 {
		return nil, errors.New("not an ARI certificate id")
	}
	return &x509.Certificate{AuthorityKeyId: aki, SerialNumber: new(big.Int).SetBytes(serialBytes)}, nil
}

// The DER blocks of a PEM chain, leaf first.
func certsChainDer(chainPem []byte) ([][]byte, error) {
	chain := [][]byte{}
	for {
		var block *pem.Block
		block, chainPem = pem.Decode(chainPem)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, errors.New("the CA's chain holds no certificate")
	}
	return chain, nil
}

// What an ACME error is to the policy: a rate limit with the call's Retry-After, a failed
// authorization with its identifiers, or itself.
func (self *CertsAcmeClient) policyError(ca CertsCa, err error, retryAfter *certsRetryAfter, names []string) error {
	var problem acme.Problem
	if !errors.As(err, &problem) {
		return err
	}
	switch {
	case problem.Type == acme.ProblemTypeRateLimited || problem.Status == http.StatusTooManyRequests:
		return &CertsAcmeRateLimitError{Ca: ca, RetryAfter: retryAfter.get()}
	}
	if authz, ok := problem.Resource.(acme.Authorization); ok {
		return &CertsAcmeAuthorizationError{Ca: ca, Names: []string{authz.IdentifierValue()}}
	}
	switch problem.Type {
	case acme.ProblemTypeUnauthorized, acme.ProblemTypeDNS, acme.ProblemTypeIncorrectResponse, acme.ProblemTypeCAA:
		return &CertsAcmeAuthorizationError{Ca: ca, Names: names}
	}
	return err
}

// See CertsAcme. Orders order.Csr's names at order.Ca by DNS-01 and returns the first chain the CA
// offers, leaf first.
func (self *CertsAcmeClient) Order(ctx context.Context, order *CertsAcmeOrder) (*CertsAcmeIssued, error) {
	csr, err := x509.ParseCertificateRequest(order.Csr)
	if err != nil {
		return nil, fmt.Errorf("the stored CSR does not parse: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the stored CSR's signature: %w", err)
	}
	orderCtx, cancel := self.boundedContext(ctx, self.settings.AcmeOrderTimeout)
	defer cancel()
	retryAfter := &certsRetryAfter{}
	orderCtx = context.WithValue(orderCtx, certsRetryAfterKey{}, retryAfter)

	account, client, err := self.account(orderCtx, order.Ca)
	if err != nil {
		return nil, self.policyError(order.Ca, err, retryAfter, csr.DNSNames)
	}
	params, err := acmez.OrderParametersFromCSR(account, csr)
	if err != nil {
		return nil, err
	}
	params.Profile = order.Profile
	if order.Replaces != "" {
		replaced, err := certsReplacedCertificate(order.Replaces)
		if err != nil {
			return nil, err
		}
		params.Replaces = replaced
	}
	orderer := &acmez.Client{
		Client:           client,
		ChallengeSolvers: map[string]acmez.Solver{acme.ChallengeTypeDNS01: self.solver},
	}
	testHookBarrier("certs.acme_order.before", "")
	chains, err := orderer.ObtainCertificate(orderCtx, params)
	testHookBarrier("certs.acme_order.after", "")
	if err != nil {
		return nil, self.policyError(order.Ca, err, retryAfter, csr.DNSNames)
	}
	if len(chains) == 0 {
		return nil, errors.New("the CA offered no chain")
	}
	chain, err := certsChainDer(chains[0].ChainPEM)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("the CA's leaf does not parse: %w", err)
	}
	return &CertsAcmeIssued{
		Chain:      chain,
		AccountUri: account.Location,
		Serial:     CertsSerialText(leaf.SerialNumber),
		NotBefore:  leaf.NotBefore,
		NotAfter:   leaf.NotAfter,
	}, nil
}

// See CertsAcme: RFC 9773's suggested window for leaf, through acmez. An error, a CA with no ARI
// included, leaves the caller to renew at two thirds of the lifetime (renew.go).
func (self *CertsAcmeClient) RenewalInfo(ctx context.Context, ca CertsCa, leaf []byte) (time.Time, time.Time, error) {
	certificate, err := x509.ParseCertificate(leaf)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	callCtx, cancel := self.boundedContext(ctx, self.settings.AcmeRequestTimeout)
	defer cancel()
	client, err := self.client(ca)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	info, err := client.GetRenewalInfo(callCtx, certificate)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return info.SuggestedWindow.Start, info.SuggestedWindow.End, nil
}

// See CertsAcme: revokes leaf at ca with reason (RFC 8555 §7.6, RFC 5280 §5.3.1), signed by the
// account, since certs never holds the certificate's key. A certificate already revoked answers nil.
func (self *CertsAcmeClient) Revoke(ctx context.Context, ca CertsCa, leaf []byte, reason CertsRevocationReason) error {
	certificate, err := x509.ParseCertificate(leaf)
	if err != nil {
		return err
	}
	callCtx, cancel := self.boundedContext(ctx, self.settings.AcmeRequestTimeout)
	defer cancel()
	account, client, err := self.account(callCtx, ca)
	if err != nil {
		return err
	}
	err = client.RevokeCertificate(callCtx, account, certificate, nil, int(reason))
	var problem acme.Problem
	if errors.As(err, &problem) && problem.Type == acme.ProblemTypeAlreadyRevoked {
		return nil
	}
	return err
}

// Rolls ca's account over to the next key its file holds (RFC 8555 §7.3.5), signed by both keys. The
// account keeps its URI, so CAA's accounturi and every replaces it ordered stay its.
func (self *CertsAcmeClient) RolloverAccount(ctx context.Context, ca CertsCa) error {
	callCtx, cancel := self.boundedContext(ctx, self.settings.AcmeRequestTimeout)
	defer cancel()
	account, client, err := self.account(callCtx, ca)
	if err != nil {
		return err
	}
	state, err := self.accounts.state(ca)
	if err != nil {
		return err
	}
	if state.nextKey == nil {
		return fmt.Errorf("%w: CA %s's file holds no next_private_key", ErrCertsAccountFileRefused, ca)
	}
	rolled, err := client.AccountKeyRollover(callCtx, account, state.nextKey)
	if err != nil {
		return err
	}
	self.accounts.rolledOver(ca, rolled, self.clock.Now())
	return nil
}

// Deactivates ca's account (RFC 8555 §7.3.6), on its key's compromise. No order uses it again.
func (self *CertsAcmeClient) DeactivateAccount(ctx context.Context, ca CertsCa) error {
	callCtx, cancel := self.boundedContext(ctx, self.settings.AcmeRequestTimeout)
	defer cancel()
	account, client, err := self.account(callCtx, ca)
	if err != nil {
		return err
	}
	account.Status = acme.StatusDeactivated
	if _, err := client.UpdateAccount(callCtx, account); err != nil {
		return err
	}
	self.accounts.markDeactivated(ca)
	return nil
}

// The account URI at ca, as CAA's accounturi names it (§13.8), resolving the account at the CA if this
// process has not yet.
func (self *CertsAcmeClient) AccountUri(ctx context.Context, ca CertsCa) (string, error) {
	callCtx, cancel := self.boundedContext(ctx, self.settings.AcmeRequestTimeout)
	defer cancel()
	account, _, err := self.account(callCtx, ca)
	if err != nil {
		return "", err
	}
	return account.Location, nil
}
