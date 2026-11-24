//go:build !sidecar_http && !ios_extension

// A Team custom domain's ordering desktop (TLS-M6-05; DESIGN-DETAILS 17.2.3, 17.2.6, 17.2.7, 17.2.9, 17.2.12, 17.2.13;
// §13.8, D-TLS-11): TlsCustomDomainOrderer orders, registers and revokes the custom hosts' certificates of the
// devices of its network under the customer's own ACME account, whose key it reads from a secret repo's key file,
// and makes the account and changes its key. It reaches the CA only through TlsAcmeClient, which cli/ implements on
// acmez (QD-288), and DNS only through TlsCustomResolver, so no sdk leg links either.
//
// Three rules carry the order, each local to the holder of the account's lock (17.2.7):
//
//   - one newOrder a grant: a newOrder is sent only on a claim's may_order, once; a refused or unknown newOrder ends
//     the grant;
//   - finalize only the recorded order: an order is finalized only after the server answered 200 to its
//     order_recorded, or handed its URL over in a claim;
//   - a recorded order is replaced only when dead: order_invalid is sent only when the CA itself answers for that URL
//     a 404 or a status other than pending, ready, processing and valid, or for a refused newOrder with nothing
//     recorded; never on a timeout or a 5xx.
//
// A holder that must give a live order up kills it, deactivating its authorizations, so no stalled holder can
// finalize it after (A13). The orderer trusts nothing the server says of a row before step 3 has checked it against
// its own verified config: the attestation, the CSR's key and its one name under the account's domain. It does not
// walk CAA: the CA does, and certs' checks (TLS-M6-04) already say whether the pin stands.
//
// The account key never leaves the desktop's keychain and the secret repo: no route, log or metric carries it. A new
// key is committed to a repo the remaining holders read before the CA is asked to require it, and the row's key_seq
// moves last (17.2.13, C8). Durations on the wire are milliseconds from the answer: no desktop clock is compared
// with the server's. Every wait is on the orderer's clock, and every wait under a claim renews it each third of its
// lease (17.2.6), so the lock lapses only under a holder that stalled or lost the server. A wait or a failed read ends
// nothing by itself: the claim is released where 17.2.7 says, an attempt at the latest at its OrderDeadline.
//
// A custom route whose service token could not be had sent nothing, and is read by why (sidecarServiceTokenRefusalOf):
// one that may change, a keychain still locked or the exchange's 503 say, is no answer, tried again as one is; one for
// good, invalid_grant or no enrolled client, lets no request of the row's go until it changes, so the holder's work on
// the row ends with its hold lost and the claim left to lapse.

package sidecar

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// RFC 8737's and RFC 8555's challenge types an order's authorization offers.
const (
	TlsAcmeChallengeTlsAlpn = "tls-alpn-01"
	TlsAcmeChallengeDns     = "dns-01"
)

// An ACME order's and authorization's statuses (RFC 8555 §7.1.6).
const (
	TlsAcmeStatusPending     = "pending"
	TlsAcmeStatusReady       = "ready"
	TlsAcmeStatusProcessing  = "processing"
	TlsAcmeStatusValid       = "valid"
	TlsAcmeStatusInvalid     = "invalid"
	TlsAcmeStatusDeactivated = "deactivated"
)

// RFC 8555's problem types, without the urn:ietf:params:acme:error: prefix, that 17.2.7's table names.
const (
	TlsAcmeProblemRateLimited         = "rateLimited"
	TlsAcmeProblemAlreadyReplaced     = "alreadyReplaced"
	TlsAcmeProblemUnauthorized        = "unauthorized"
	TlsAcmeProblemAccountDoesNotExist = "accountDoesNotExist"
	TlsAcmeProblemRejectedIdentifier  = "rejectedIdentifier"
	TlsAcmeProblemCaa                 = "caa"
	TlsAcmeProblemOrderNotReady       = "orderNotReady"
	TlsAcmeProblemBadCsr              = "badCSR"
	TlsAcmeProblemBadPublicKey        = "badPublicKey"
	TlsAcmeProblemAlreadyRevoked      = "alreadyRevoked"
)

// The local alarms only a desktop sees (17.2.14).
const (
	TlsCustomAlarmKeyMismatch = "tls_account_key_mismatch"
	TlsCustomAlarmAccountLost = "tls_account_lost"
	TlsCustomAlarmOrderStuck  = "tls_custom_order_stuck"
	TlsCustomAlarmForeign     = "tls_custom_foreign_certificate"
	TlsCustomAlarmCaRefused   = "tls_custom_ca_refused"
)

// GET /tls/custom-challenge/<id>'s readiness, /dns/ready's answers passed through (QD-175).
const (
	TlsCustomReadinessReady = "ready"
	TlsCustomReadinessStale = "stale"
)

// The key file's format number and path, the label a delegated DNS-01 name sits under, and RFC 5280's reason codes
// a revocation sends.
const (
	tlsCustomKeyFileFormat       = 1
	tlsCustomKeyFilePathPrefix   = "tls/acme/"
	tlsCustomKeyFilePathSuffix   = ".json"
	tlsCustomAcmeChallengeLabel  = "_acme-challenge."
	tlsCustomRevocationCessation = 5
	tlsCustomRevocationKeyComp   = 1
)

// An order 404s at the CA: dead, as invalid is.
var ErrTlsAcmeGone = errors.New("acme order gone")

// A CA's refusal (17.7): RFC 8555's problem type without its urn prefix, the status and Retry-After. Any other error
// of a TlsAcmeClient is "outcome unknown".
type TlsAcmeProblem struct {
	Type       string
	Status     int
	RetryAfter time.Duration
}

// The problem's type and status.
func (self *TlsAcmeProblem) Error() string {
	return fmt.Sprintf("acme problem %s (%d)", self.Type, self.Status)
}

// The problem behind err, nil for an outcome unknown.
func tlsAcmeProblemOf(err error) *TlsAcmeProblem {
	var problem *TlsAcmeProblem
	if errors.As(err, &problem) {
		return problem
	}
	return nil
}

// One ACME order as the client reads it.
type TlsAcmeOrder struct {
	Url            string
	Status         string
	Authorizations []string
	Finalize       string
	Certificate    string
}

// One authorization and its challenges.
type TlsAcmeAuthorization struct {
	Url        string
	Status     string
	Challenges []*TlsAcmeChallenge
	// the problem's type when invalid
	ProblemType string
}

// One challenge of an authorization.
type TlsAcmeChallenge struct {
	Type   string
	Url    string
	Token  string
	Status string
}

// The CA, as cli/'s acmez client reaches it (17.7). Every request retries a badNonce with the fresh nonce up to
// TlsCustomSettings.NonceRetryCount times inside the client.
type TlsAcmeClient interface {
	NewAccount(ctx context.Context, key crypto.Signer, onlyReturnExisting bool) (accountUri string, err error)
	Account(ctx context.Context, key crypto.Signer, accountUri string) error
	KeyChange(ctx context.Context, accountUri string, oldKey crypto.Signer, newKey crypto.Signer) error
	Deactivate(ctx context.Context, key crypto.Signer, accountUri string) error
	NewOrder(ctx context.Context, key crypto.Signer, accountUri string, name string, profile string, replacesLeaf []byte) (*TlsAcmeOrder, error)
	Order(ctx context.Context, key crypto.Signer, accountUri string, orderUrl string) (*TlsAcmeOrder, error)
	Authorization(ctx context.Context, key crypto.Signer, accountUri string, url string) (*TlsAcmeAuthorization, error)
	Challenge(ctx context.Context, key crypto.Signer, accountUri string, url string) error
	Finalize(ctx context.Context, key crypto.Signer, accountUri string, order *TlsAcmeOrder, csr []byte) (*TlsAcmeOrder, error)
	Certificate(ctx context.Context, key crypto.Signer, accountUri string, url string) ([][]byte, error)
	RenewalInfo(ctx context.Context, leaf []byte) (start time.Time, end time.Time, err error)
	Revoke(ctx context.Context, key crypto.Signer, accountUri string, leaf []byte, reason int) error
	DeactivateAuthorization(ctx context.Context, key crypto.Signer, accountUri string, url string) error
	// The key authorization of a challenge token under key (RFC 8555 §8.1).
	KeyAuthorization(key crypto.Signer, token string) (string, error)
}

// Public DNS, as the desktop's system resolver answers (17.7).
type TlsCustomResolver interface {
	LookupCname(ctx context.Context, name string) (string, error)
	LookupTxt(ctx context.Context, name string) ([]string, error)
}

// The custom routes as the desktop calls them, its certs token naming it. A refusal is a *TlsCustomError.
type TlsCustomApi interface {
	Work(ctx context.Context) (*TlsCertsResult, error)
	Claim(ctx context.Context, args *TlsCustomClaimArgs) (*TlsCustomClaimResult, error)
	Progress(ctx context.Context, args *TlsCustomProgressArgs) (*TlsCustomClaimResult, error)
	Register(ctx context.Context, args *TlsCertRegisterArgs) error
	Account(ctx context.Context, args *TlsCustomAccountArgs) (*TlsCustomAccount, error)
	Challenge(ctx context.Context, args *TlsCustomChallengeArgs) (*TlsCustomChallengeResult, error)
	ChallengeStatus(ctx context.Context, challengeId uint64) (*TlsCustomChallengeResult, error)
}

// The account key file's next key while a change is in flight.
type TlsCustomKeyFileNext struct {
	KeySeq uint64 `json:"key_seq"`
	// PKCS #8 DER.
	Key []byte `json:"key"`
}

// The account key file, tls/acme/<domain>.json in a secret repo (17.2.3). Never on a server.
type TlsCustomKeyFile struct {
	Format     int    `json:"format"`
	Domain     string `json:"domain"`
	Ca         string `json:"ca"`
	AccountUri string `json:"account_uri"`
	KeySeq     uint64 `json:"key_seq"`
	// PKCS #8 DER.
	Key  []byte                `json:"key"`
	Next *TlsCustomKeyFileNext `json:"next"`
	// The repo's holders_shrunk_at (§10.6) when this key was made.
	ShrunkAt uint64 `json:"shrunk_at"`
}

// The file's path in its repo.
func TlsCustomKeyFilePath(domain string) string {
	return tlsCustomKeyFilePathPrefix + domain + tlsCustomKeyFilePathSuffix
}

// Reads a key file, refusing one of another format or domain, or whose keys are not P-256 PKCS #8.
func ParseTlsCustomKeyFile(data []byte, domain string) (*TlsCustomKeyFile, error) {
	file := &TlsCustomKeyFile{}
	if err := json.Unmarshal(data, file); err != nil {
		return nil, errors.New("the account key file does not parse")
	}
	if file.Format != tlsCustomKeyFileFormat || file.Domain != domain || file.KeySeq == 0 {
		return nil, errors.New("the account key file is of another format or domain")
	}
	if _, err := tlsCustomParseKey(file.Key); err != nil {
		return nil, err
	}
	if file.Next != nil {
		if file.Next.KeySeq != file.KeySeq+1 {
			return nil, errors.New("the account key file's next key is not the one after")
		}
		if _, err := tlsCustomParseKey(file.Next.Key); err != nil {
			return nil, err
		}
	}
	return file, nil
}

// The file's bytes.
func (self *TlsCustomKeyFile) Marshal() ([]byte, error) {
	return json.Marshal(self)
}

// A P-256 key from PKCS #8 DER.
func tlsCustomParseKey(der []byte) (*ecdsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("an account key that is not PKCS #8")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("an account key that is not P-256")
	}
	testHookSecret("tls_custom_account_key", der)
	return key, nil
}

// A new P-256 account key in PKCS #8 DER.
func NewTlsCustomAccountKey() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	testHookSecret("tls_custom_account_key", der)
	return der, nil
}

// RFC 7638's SHA-256 thumbprint of a P-256 key's public JWK: a public value.
func TlsCustomKeyThumbprint(publicKey *ecdsa.PublicKey) []byte {
	pad := func(value *big.Int) string {
		bytes := make([]byte, (publicKey.Curve.Params().BitSize+7)/8)
		value.FillBytes(bytes)
		return base64.RawURLEncoding.EncodeToString(bytes)
	}
	// the required members in lexicographic order, no whitespace (RFC 7638 §3.2)
	jwk := `{"crv":"P-256","kty":"EC","x":"` + pad(publicKey.X) + `","y":"` + pad(publicKey.Y) + `"}`
	thumbprint := sha256.Sum256([]byte(jwk))
	return thumbprint[:]
}

// Which of a key file's keys an account row accepts (17.2.3): the current one when (key_seq, thumbprint) is the
// row's, or the next one when the row records it as next at key_seq + 1, a key change whose last step is owed. nil
// when neither, and the desktop does not use the file.
func (self *TlsCustomKeyFile) KeyFor(account *TlsCustomAccount) (*ecdsa.PrivateKey, uint64) {
	key, err := tlsCustomParseKey(self.Key)
	if err != nil {
		return nil, 0
	}
	if self.KeySeq == account.KeySeq && bytes.Equal(TlsCustomKeyThumbprint(&key.PublicKey), account.KeyThumbprint) {
		return key, self.KeySeq
	}
	// the file at s+1 and the row at s with that key as its next: R6 was done, R7 is owed
	if self.KeySeq == account.KeySeq+1 && bytes.Equal(TlsCustomKeyThumbprint(&key.PublicKey), account.NextKeyThumbprint) {
		return key, self.KeySeq
	}
	return nil, 0
}

// The desktop's own verified view (§8, the config projection): never a server's answer.
type TlsCustomDevices interface {
	// The identity key the projection admits sidecarId under in this network, and whether that sidecar holds an
	// active approved publish grant on a tls/ name of ownerLabel now. nil for a sidecar not admitted.
	Device(sidecarId Id, ownerLabel string) (identityPublicKey []byte, granted bool)
	// Whether this desktop holds an active approved publish grant on tls/443/<ownerLabel> now: its TLS-ALPN-01 path.
	Holds443(ownerLabel string) bool
	// The network's sidecar id and network id of this desktop.
	SidecarId() Id
	NetworkId() Id
}

// The key files this desktop can read: a secret repo's, through evs, and its local copy (17.2.3).
type TlsCustomKeyStore interface {
	// The key file of domain in repoId's secret repo. ErrTlsCustomKeyUnavailable when this desktop cannot read it.
	ReadKeyFile(ctx context.Context, repoId Id, domain string) ([]byte, error)
	// Writes the key file to repoId's secret repo and returns once the push has committed.
	WriteKeyFile(ctx context.Context, repoId Id, domain string, data []byte) error
	// The local copy beside the device key, nil for none, and its replacement.
	LocalKeyFile(domain string) []byte
	SetLocalKeyFile(domain string, data []byte) error
}

// A key file this desktop cannot read.
var ErrTlsCustomKeyUnavailable = errors.New("tls custom account key unavailable")

// The TLS-ALPN-01 path through the desktop's own front and registration (17.2.9).
type TlsCustomAlpnPath interface {
	// Sets the challenge for host on tls/443/<ownerLabel> under claimSeq until expireTime, and returns once the
	// registration's page listing it as an ACME name answered 200.
	Serve(ctx context.Context, host string, ownerLabel string, keyAuthorization string, expireTime time.Time, claimSeq uint64) error
	// Ends it; the next page drops the ACME name.
	Clear(host string)
	// Dials host on port 443 by public DNS offering only acme-tls/1, and reads back the challenge certificate this
	// desktop serves for keyAuthorization, byte for byte, within timeout.
	Probe(ctx context.Context, host string, keyAuthorization string, timeout time.Duration) error
}

// The ordering desktop's tunables (17.2.15). DefaultTlsCustomSettings is the only source of a default.
type TlsCustomSettings struct {
	// The loop (Run) runs again PollInterval, moved by up to PollJitter of it either way, after a pass that listed
	// work, and IdlePollInterval after one that did not or failed. Both positive; PollJitter a fifth, at least 0 and
	// below 1.
	PollInterval     time.Duration
	IdlePollInterval time.Duration
	PollJitter       float64
	// How often an order or authorization is read again while processing or pending.
	OrderPollInterval time.Duration
	// The holder's local deadline is the claim's send plus lease_ms less this.
	LeaseMargin time.Duration
	// While it waits between requests, in any of its waiting loops, the holder renews its claim once this fraction of
	// lease_ms has passed since the claim it holds, or its last renewal, was sent: 17.2.6's LockLease / 3, a third. A
	// longer wait is cut at each renewal, and a renewal left unanswered is tried again OrderPollInterval on. Not
	// positive renews at both ends of every wait; 1 or more lets the local deadline pass first.
	LeaseRenewFraction float64
	// An attempt at one order lasts at most this; past it the holder releases, the order staying recorded.
	OrderDeadline time.Duration
	// How long a challenge is served.
	ChallengeLifetime time.Duration
	// A badNonce is retried this many times with the fresh nonce: one request to the CA's limits.
	NonceRetryCount int
	// The probe must read its challenge back ProbeCount times in a row, ProbeTimeout each.
	ProbeCount   int
	ProbeTimeout time.Duration
	// Every this long the accounts' live certificates' renewal windows are read again.
	AriRefreshInterval time.Duration
	// A kill deactivates and reads the order again at most this many times.
	DeactivateTryCount int
	// The longest key file a read takes from a secret repo: 16 KiB, far past a file's two P-256 keys in base64. A
	// longer one is a key file this desktop cannot read.
	KeyFileMaxByteCount int
	// The ACME profile every order names: tlsserver's 45 days and 7 h authorization reuse (A1, A2).
	Profile string
	// A2, read only by tests.
	AuthorizationReuse time.Duration
	// The CA's directory: certs' Let's Encrypt value, which a test points at Pebble. No default: a production URL.
	DirectoryUrl string
}

// 17.2.15's numbers.
func DefaultTlsCustomSettings() *TlsCustomSettings {
	return &TlsCustomSettings{
		PollInterval:        60 * time.Second,
		IdlePollInterval:    5 * time.Minute,
		PollJitter:          1.0 / 5.0,
		OrderPollInterval:   2 * time.Second,
		LeaseMargin:         10 * time.Second,
		LeaseRenewFraction:  1.0 / 3.0,
		OrderDeadline:       10 * time.Minute,
		ChallengeLifetime:   10 * time.Minute,
		NonceRetryCount:     3,
		ProbeCount:          2,
		ProbeTimeout:        10 * time.Second,
		AriRefreshInterval:  6 * time.Hour,
		DeactivateTryCount:  3,
		KeyFileMaxByteCount: 16 * 1024,
		Profile:             "tlsserver",
		AuthorizationReuse:  7 * time.Hour,
	}
}

// What the orderer runs on.
type TlsCustomDomainOrdererDeps struct {
	Api      TlsCustomApi
	Acme     TlsAcmeClient
	Resolver TlsCustomResolver
	Devices  TlsCustomDevices
	Keys     TlsCustomKeyStore
	// nil: no TLS-ALPN-01 path, DNS-01 alone.
	Alpn TlsCustomAlpnPath
	// certs' roots, under none of which a custom host sits.
	Roots []string
	Clock Clock
	// The desktop's local alarms (17.2.14). nil drops them.
	Alarm func(name string)
	// The key repos a key change reads (17.2.13): with them each pass makes a due change this desktop may make and
	// reports one it may not; nil leaves key changes to RollAccount's callers.
	Repos TlsCustomKeyRepos
}

// See the file header. Safe for concurrent use: one pass runs at a time.
type TlsCustomDomainOrderer struct {
	deps     *TlsCustomDomainOrdererDeps
	settings *TlsCustomSettings
	clock    Clock

	passLock sync.Mutex
	// Each domain's rollover_due as sent, at its row's key sequence plus one, so a standing due change is reported
	// once a key sequence. Under passLock.
	rolloverDueSent map[string]uint64
}

// An orderer on deps, settings nil taking the defaults. It starts nothing: RunOnce is one pass of the loop.
func NewTlsCustomDomainOrderer(deps *TlsCustomDomainOrdererDeps, settings *TlsCustomSettings) (*TlsCustomDomainOrderer, error) {
	if deps == nil || deps.Api == nil || deps.Acme == nil || deps.Devices == nil || deps.Keys == nil || len(deps.Roots) == 0 {
		return nil, errors.New("the custom-domain orderer needs its api, CA, devices, keys and roots")
	}
	if settings == nil {
		settings = DefaultTlsCustomSettings()
	}
	// a wait that is not positive would spin the loop and the order's polls
	if settings.PollInterval <= 0 || settings.IdlePollInterval <= 0 || settings.OrderPollInterval <= 0 || !(0 <= settings.PollJitter && settings.PollJitter < 1) {
		return nil, errors.New("the custom-domain orderer's waits are not positive")
	}
	clock := deps.Clock
	if clock == nil {
		clock = RealClock{}
	}
	return &TlsCustomDomainOrderer{deps: deps, settings: settings, clock: clock, rolloverDueSent: map[string]uint64{}}, nil
}

// Raises a local alarm (17.2.14), when the host takes them.
func (self *TlsCustomDomainOrderer) alarm(name string) {
	if self.deps.Alarm != nil {
		self.deps.Alarm(name)
	}
}

// Waits timeout on the orderer's clock, or until ctx ends. ctx's error once ctx has ended, a timer that fired as it
// ended included, and nil only for a timeout passed with ctx live, so neither Run's loop nor a holder's pause goes on
// past its context; a context already ended asks the clock for nothing.
func (self *TlsCustomDomainOrderer) wait(ctx context.Context, timeout time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
	case <-self.clock.After(timeout):
	}
	// select takes either of two ready cases at random: a timer that fired as ctx ended reads as the end
	return ctx.Err()
}

// The account's key from the key file this desktop reads, from the account's repo or its local copy, checked
// against the row (17.2.3); the local copy is replaced after each read that passes.
func (self *TlsCustomDomainOrderer) accountKey(ctx context.Context, account *TlsCustomAccount) (*TlsCustomKeyFile, *ecdsa.PrivateKey, uint64, error) {
	candidates := [][]byte{}
	for _, repoId := range []Id{account.KeyRepoId, account.NextKeyRepoId} {
		if repoId == (Id{}) {
			continue
		}
		if data, err := self.deps.Keys.ReadKeyFile(ctx, repoId, account.Domain); err == nil {
			candidates = append(candidates, data)
		}
	}
	if local := self.deps.Keys.LocalKeyFile(account.Domain); local != nil {
		candidates = append(candidates, local)
	}
	for _, data := range candidates {
		file, err := ParseTlsCustomKeyFile(data, account.Domain)
		if err != nil {
			continue
		}
		key, keySeq := file.KeyFor(account)
		if key == nil {
			// a key file at the next sequence, while the row still records the current key: R5 done, R6 owed
			if file.Next != nil && file.KeySeq == account.KeySeq {
				if nextKey, err := tlsCustomParseKey(file.Next.Key); err == nil && bytes.Equal(TlsCustomKeyThumbprint(&nextKey.PublicKey), account.NextKeyThumbprint) {
					currentKey, err := tlsCustomParseKey(file.Key)
					if err == nil && bytes.Equal(TlsCustomKeyThumbprint(&currentKey.PublicKey), account.KeyThumbprint) {
						self.deps.Keys.SetLocalKeyFile(account.Domain, data)
						return file, currentKey, file.KeySeq, nil
					}
				}
			}
			continue
		}
		self.deps.Keys.SetLocalKeyFile(account.Domain, data)
		return file, key, keySeq, nil
	}
	return nil, nil, 0, ErrTlsCustomKeyUnavailable
}

// The challenge path this desktop has for row: TLS-ALPN-01 when its host is ready and this desktop holds port 443's
// publish grant on its owner, else DNS-01 when the customer delegated _acme-challenge.<host> to the account's
// acme name; "" for none (17.2.9).
func (self *TlsCustomDomainOrderer) challengePath(ctx context.Context, account *TlsCustomAccount, row *TlsCertRecord) string {
	if row.HostReady && self.deps.Alpn != nil && self.deps.Devices.Holds443(row.Owner) {
		local, live := self.deps.Alpn.(interface {
			CanServe(ctx context.Context, host, owner string) bool
		})
		if !live || local.CanServe(ctx, row.CustomHost, row.Owner) {
			return TlsAcmeChallengeTlsAlpn
		}
	}
	if self.deps.Resolver != nil && account.AcmeName != "" {
		target, err := self.deps.Resolver.LookupCname(ctx, tlsCustomAcmeChallengeLabel+row.CustomHost)
		normalize := func(name string) string {
			return strings.ToLower(strings.TrimSuffix(name, "."))
		}
		if err == nil && normalize(target) == normalize(account.AcmeName) {
			return TlsAcmeChallengeDns
		}
	}
	return ""
}

// 17.2.7's step 3: the row checked against this desktop's own verified config, trusting nothing the server said:
// the attestation verifies for a device holding a publish grant on the host's owner; the CSR is self-signed by the
// attested P-256 key and names exactly one dNSName, a canonical name under the account's domain and under no root.
// The failure's custom reason, "" when the row checks.
func (self *TlsCustomDomainOrderer) checkRow(account *TlsCustomAccount, row *TlsCertRecord) string {
	csr, err := x509.ParseCertificateRequest(row.Csr)
	if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 1 || 0 < len(csr.IPAddresses) || 0 < len(csr.EmailAddresses) || 0 < len(csr.URIs) {
		return TlsCustomReasonCsr
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return TlsCustomReasonCsr
	}
	host := csr.DNSNames[0]
	set, err := TlsCustomIdentifierSet(host, self.deps.Roots)
	if err != nil || host != row.CustomHost || (host != account.Domain && !strings.HasSuffix(host, "."+account.Domain)) {
		return TlsCustomReasonCsr
	}
	identityPublicKey, granted := self.deps.Devices.Device(row.SidecarId, row.Owner)
	if identityPublicKey == nil || !granted {
		return TlsCustomReasonAttestation
	}
	setSha256, err := TlsIdentifierSetHash(set)
	if err != nil {
		return TlsCustomReasonCsr
	}
	spkiSha256 := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	if _, err := VerifyTlsKeyAttestation(row.Attestation, identityPublicKey, self.deps.Devices.NetworkId(), row.SidecarId, spkiSha256, setSha256); err != nil {
		return TlsCustomReasonAttestation
	}
	return ""
}

// One claim held: renews it by the same claim call, refusing once refused or past the local deadline.
type tlsCustomHold struct {
	orderer  *TlsCustomDomainOrderer
	account  *TlsCustomAccount
	args     *TlsCustomClaimArgs
	claim    *TlsCustomClaimResult
	deadline time.Time
	// when a holder waiting between requests renews the claim next (keep)
	renewTime time.Time
	// when the order's attempt began, which lasts at most OrderDeadline (17.2.7); zero outside one
	attemptStart time.Time
	lost         bool
}

// Takes the claim, answering the hold or the claim's refusal.
func (self *TlsCustomDomainOrderer) claim(ctx context.Context, account *TlsCustomAccount, args *TlsCustomClaimArgs) (*tlsCustomHold, error) {
	sent := self.clock.Now()
	claim, err := self.deps.Api.Claim(ctx, args)
	if err != nil {
		return nil, err
	}
	hold := &tlsCustomHold{
		orderer: self,
		account: account,
		args:    args,
		claim:   claim,
	}
	hold.held(sent, claim)
	return hold, nil
}

// The local deadline and the next renewal, from a claim answered to the call sent at sent.
func (self *tlsCustomHold) held(sent time.Time, claim *TlsCustomClaimResult) {
	lease := time.Duration(claim.LeaseMs) * time.Millisecond
	self.deadline = sent.Add(lease - self.orderer.settings.LeaseMargin)
	self.renewTime = sent.Add(time.Duration(float64(lease) * self.orderer.settings.LeaseRenewFraction))
}

// Renews the claim immediately before a request that changes something at the CA (17.2.6); false once the hold is
// lost. Any failure loses it, an unanswered renewal included: such a request goes out only under a renewal the server
// answered, which keeps a stalled holder's reach to one request.
func (self *tlsCustomHold) renew(ctx context.Context) bool {
	if self.lost || !self.orderer.clock.Now().Before(self.deadline) {
		self.lost = true
		return false
	}
	sent := self.orderer.clock.Now()
	claim, err := self.orderer.deps.Api.Claim(ctx, self.args)
	if err != nil || claim.ClaimSeq != self.claim.ClaimSeq {
		self.lost = true
		return false
	}
	self.held(sent, claim)
	return true
}

// Renews the claim while the holder waits between requests, once its renewal is due (17.2.6: every LockLease / 3), so
// the lock does not lapse under a holder still working on the row. A renewal refused, or answered under another claim,
// loses the hold, as a passed local deadline does (17.2.6). One left unanswered, with no reply or a server's failure,
// leaves the hold standing, to be tried again OrderPollInterval on, until that deadline passes. false once the hold is
// lost.
func (self *tlsCustomHold) keep(ctx context.Context) bool {
	now := self.orderer.clock.Now()
	if self.lost || !now.Before(self.deadline) {
		self.lost = true
		return false
	}
	if now.Before(self.renewTime) {
		return true
	}
	claim, err := self.orderer.deps.Api.Claim(ctx, self.args)
	switch {
	case err == nil && claim != nil && claim.ClaimSeq == self.claim.ClaimSeq:
		self.held(now, claim)
		return true
	case err != nil && tlsCustomUnanswered(err):
		self.renewTime = now.Add(self.orderer.settings.OrderPollInterval)
		return true
	}
	self.lost = true
	return false
}

// Waits timeout between requests, renewing the claim each time its renewal falls due on the way (17.2.6: every
// LockLease / 3, as LeaseRenewFraction sets), so no wait under a claim outlasts that fraction of the lease unrenewed: a
// longer wait is cut at each renewal, and at the local deadline. Every waiting loop of a holder waits here. false once
// ctx ended or the hold was lost, with nothing more to send for the row.
func (self *tlsCustomHold) pause(ctx context.Context, timeout time.Duration) bool {
	clock := self.orderer.clock
	end := clock.Now().Add(timeout)
	earlier := func(a time.Time, b time.Time) time.Time {
		if b.Before(a) {
			return b
		}
		return a
	}
	for {
		// an overdue renewal goes before the wait
		if !self.keep(ctx) {
			return false
		}
		now := clock.Now()
		if !now.Before(end) {
			return true
		}
		next := earlier(end, self.deadline)
		if now.Before(self.renewTime) {
			next = earlier(next, self.renewTime)
		}
		if self.orderer.wait(ctx, next.Sub(now)) != nil {
			return false
		}
	}
}

// pause inside an order's attempt, which lasts at most OrderDeadline (17.2.7): a wait that would reach the attempt's
// end releases the claim instead, the order staying recorded for the next claim. false once the work on the row ended.
func (self *tlsCustomHold) poll(ctx context.Context, timeout time.Duration) bool {
	now := self.orderer.clock.Now()
	if self.lost || !now.Before(self.deadline) {
		self.lost = true
		return false
	}
	if !self.attemptStart.IsZero() && !now.Add(timeout).Before(self.attemptStart.Add(self.orderer.settings.OrderDeadline)) {
		self.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
		return false
	}
	return self.pause(ctx, timeout)
}

// Whether a custom route's request was left unanswered rather than refused: no reply, a reply that does not parse, or
// a server's failure (5xx, or a 429 before the route), which the same request may get past later. A custom route's
// refusal, any other 4xx and a request refused before it was sent are answers. A request that never went for want of
// its service token (errTlsCustomNoServiceToken) is read by why (sidecarServiceTokenRefusalOf): unanswered where that
// may change, a keychain still locked or the exchange's 503 say, and answered where it is for good, invalid_grant or no
// enrolled client, since no request of the row's goes until it changes.
func tlsCustomUnanswered(err error) bool {
	if errors.Is(err, errTlsCustomNoServiceToken) {
		return !sidecarServiceTokenRefusalOf(err).final
	}
	var refusal *TlsCustomError
	if errors.As(err, &refusal) {
		return http.StatusInternalServerError <= refusal.Status
	}
	var apiErr *SidecarApiError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusTooManyRequests || !(http.StatusOK < apiErr.Status && apiErr.Status < http.StatusInternalServerError)
	}
	return !errors.Is(err, ErrSidecarApiArgs)
}

// Whether a custom route's request never went because its service token was refused for good, invalid_grant or no
// enrolled client say (sidecarServiceTokenRefusalOf): no request of the row's, a release included, goes until that
// changes, so the holder's work on the row ends with its hold lost and the claim left to lapse.
func tlsCustomTokenRefusedForGood(err error) bool {
	return errors.Is(err, errTlsCustomNoServiceToken) && sidecarServiceTokenRefusalOf(err).final
}

// A progress event under the hold's claim.
func (self *tlsCustomHold) progress(ctx context.Context, args *TlsCustomProgressArgs) (*TlsCustomClaimResult, error) {
	args.Domain = self.account.Domain
	args.ClaimSeq = self.claim.ClaimSeq
	args.CertId = self.args.CertId
	result, err := self.orderer.deps.Api.Progress(ctx, args)
	var refusal *TlsCustomError
	if errors.As(err, &refusal) && refusal.Refusal.Reason == TlsCustomRefusalClaim {
		self.lost = true
	}
	return result, err
}

// What one pass did, for the loop's cadence and the tests.
type TlsCustomPassReport struct {
	// Rows a pass worked on, and whether any listed work was left.
	Worked    []Id
	Issued    []Id
	Revoked   []Id
	Failed    []Id
	WorkSeen  bool
	NewOrders int
	// Accounts whose key changed in the pass, and those whose due change it reported as one it may not make.
	Rolled      []string
	RolloverDue []string
}

// One pass of 17.2.7's loop: the work list; for each account whose key file checks, the first row with no wait this
// desktop can serve, claimed and worked on. Errors of one account are said in the report's absence and the pass goes
// on to the next.
func (self *TlsCustomDomainOrderer) RunOnce(ctx context.Context) (*TlsCustomPassReport, error) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	report := &TlsCustomPassReport{}
	work, err := self.deps.Api.Work(ctx)
	if err != nil {
		return report, err
	}
	report.WorkSeen = 0 < len(work.QueuedCsrs)
	for _, account := range work.Accounts {
		file, key, keySeq, err := self.accountKey(ctx, account)
		if err != nil {
			continue
		}
		if self.rollover(ctx, report, account, file) {
			// the next pass orders under the key the row then names
			continue
		}
		for _, row := range work.QueuedCsrs {
			if row.CustomDomain != account.Domain || 0 < row.WaitMs {
				continue
			}
			purpose := TlsCustomPurposeOrder
			if row.State == TlsCertStateCustomRevoking {
				purpose = TlsCustomPurposeRevoke
			} else if self.challengePath(ctx, account, row) == "" {
				continue
			}
			worked := self.work(ctx, report, account, key, keySeq, row, purpose, true)
			if worked {
				break
			}
		}
	}
	return report, nil
}

// Claims a work row and works on it (17.2.7 steps 2 to 8, 17.2.12). Whether it held a claim.
func (self *TlsCustomDomainOrderer) work(ctx context.Context, report *TlsCustomPassReport, account *TlsCustomAccount, key *ecdsa.PrivateKey, keySeq uint64, workRow *TlsCertRecord, purpose string, followInFlight bool) bool {
	certId := workRow.CertId
	hold, err := self.claim(ctx, account, &TlsCustomClaimArgs{Domain: account.Domain, Purpose: purpose, CertId: certId, KeySeq: keySeq})
	var refusal *TlsCustomError
	if errors.As(err, &refusal) && refusal.Refusal.Reason == TlsCustomRefusalInFlight && followInFlight && refusal.Refusal.CertId != (Id{}) {
		// claim the named row instead, once, for the purpose its state asks: a revoking one first in line
		inFlight := self.workRow(ctx, refusal.Refusal.CertId)
		if inFlight == nil {
			return false
		}
		inFlightPurpose := TlsCustomPurposeOrder
		if inFlight.State == TlsCertStateCustomRevoking {
			inFlightPurpose = TlsCustomPurposeRevoke
		}
		return self.work(ctx, report, account, key, keySeq, inFlight, inFlightPurpose, false)
	}
	if err != nil {
		return false
	}
	if hold.claim.Record != nil {
		// what the work list said of the row's host: its owner label and readiness
		hold.claim.Record.Owner = workRow.Owner
		hold.claim.Record.HostReady = workRow.HostReady
	}
	report.Worked = append(report.Worked, certId)
	if purpose == TlsCustomPurposeRevoke {
		self.revokePass(ctx, report, hold, key)
		return true
	}
	if hold.claim.Record == nil {
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
		return true
	}
	if reason := self.checkRow(account, hold.claim.Record); reason != "" {
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventFailed, Reason: reason})
		report.Failed = append(report.Failed, certId)
		return true
	}
	self.order(ctx, report, hold, key)
	return true
}

// The work list's row certId, nil for none: what an in_flight refusal's row is claimed as.
func (self *TlsCustomDomainOrderer) workRow(ctx context.Context, certId Id) *TlsCertRecord {
	work, err := self.deps.Api.Work(ctx)
	if err != nil {
		return nil
	}
	for _, row := range work.QueuedCsrs {
		if row.CertId == certId {
			return row
		}
	}
	return nil
}

// Steps 4 to 8 of 17.2.7 for a claimed, checked row.
func (self *TlsCustomDomainOrderer) order(ctx context.Context, report *TlsCustomPassReport, hold *tlsCustomHold, key *ecdsa.PrivateKey) {
	acme := self.deps.Acme
	accountUri := hold.account.AccountUri
	row := hold.claim.Record
	attemptStart := self.clock.Now()
	hold.attemptStart = attemptStart
	release := func() {
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
	}
	var order *TlsAcmeOrder
	// 4: resume what is recorded, or send the one newOrder the claim grants
	for {
		switch {
		case hold.claim.OrderUrl != "":
			resumed, err := acme.Order(ctx, key, accountUri, hold.claim.OrderUrl)
			if err != nil && !errors.Is(err, ErrTlsAcmeGone) {
				if problem := tlsAcmeProblemOf(err); problem != nil && problem.Status == 429 {
					hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRateLimited, RetryAfterMs: uint32(problem.RetryAfter.Milliseconds())})
					return
				}
				release()
				return
			}
			if errors.Is(err, ErrTlsAcmeGone) || tlsAcmeOrderDead(resumed) {
				granted, err := hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventOrderInvalid})
				if err != nil || granted == nil || !granted.MayOrder {
					return
				}
				hold.claim = &TlsCustomClaimResult{ClaimSeq: hold.claim.ClaimSeq, LeaseMs: granted.LeaseMs, Record: row, MayOrder: true, ReplacesLeaf: granted.ReplacesLeaf}
				continue
			}
			order = resumed
		case hold.claim.MayOrder:
			if !hold.renew(ctx) {
				return
			}
			report.NewOrders += 1
			hold.claim.MayOrder = false
			created, err := acme.NewOrder(ctx, key, accountUri, row.CustomHost, self.settings.Profile, hold.claim.ReplacesLeaf)
			if err != nil {
				self.newOrderRefused(ctx, report, hold, err)
				return
			}
			// recorded before anything else is sent to the CA
			if _, err := hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventOrderRecorded, OrderUrl: created.Url}); err != nil {
				return
			}
			hold.claim.OrderUrl = created.Url
			order = created
		default:
			// a restart met its own unlapsed claim with nothing recorded
			release()
			return
		}
		break
	}

	// 5: by the order's status, until valid. Each wait renews the claim as it comes due, and a read with no answer is
	// read again; the attempt's OrderDeadline releases the claim, the order staying recorded
	for {
		if self.settings.OrderDeadline <= self.clock.Now().Sub(attemptStart) {
			release()
			return
		}
		switch order.Status {
		case TlsAcmeStatusPending:
			next, done := self.authorize(ctx, report, hold, key, order)
			if done {
				return
			}
			order = next
		case TlsAcmeStatusReady:
			if !hold.renew(ctx) {
				return
			}
			finalized, err := acme.Finalize(ctx, key, accountUri, order, row.Csr)
			if err == nil && finalized != nil {
				order = finalized
				continue
			}
			problem := tlsAcmeProblemOf(err)
			switch {
			case problem != nil && (problem.Type == TlsAcmeProblemBadCsr || problem.Type == TlsAcmeProblemBadPublicKey):
				hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventFailed, Reason: TlsCustomReasonCaRefused})
				self.alarm(TlsCustomAlarmCaRefused)
				report.Failed = append(report.Failed, row.CertId)
				return
			case problem != nil && problem.Status == 429:
				hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRateLimited, RetryAfterMs: uint32(problem.RetryAfter.Milliseconds())})
				return
			}
			// 403 orderNotReady, or an outcome unknown: the order is read again a poll on, until the CA answers, and
			// acted on by its status. It is never finalized again unread
			if !hold.poll(ctx, self.settings.OrderPollInterval) {
				return
			}
			if order = self.reread(ctx, hold, key, order.Url); order == nil {
				return
			}
		case TlsAcmeStatusProcessing:
			if !hold.poll(ctx, self.settings.OrderPollInterval) {
				return
			}
			if order = self.reread(ctx, hold, key, order.Url); order == nil {
				return
			}
		case TlsAcmeStatusValid:
			self.download(ctx, report, hold, key, order)
			return
		default:
			// dead: another order if the budgets grant one, next pass
			hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventOrderInvalid})
			return
		}
	}
}

// The order read again until the CA answers, a poll apart, the claim renewed as it comes due meanwhile: an unknown
// outcome is read again until the attempt's OrderDeadline, which releases the claim (17.2.7). A 404 answers the order
// as invalid, which is dead. nil once the work on the row ended.
func (self *TlsCustomDomainOrderer) reread(ctx context.Context, hold *tlsCustomHold, key *ecdsa.PrivateKey, orderUrl string) *TlsAcmeOrder {
	for {
		read, err := self.deps.Acme.Order(ctx, key, hold.account.AccountUri, orderUrl)
		switch {
		case err == nil && read != nil:
			return read
		case errors.Is(err, ErrTlsAcmeGone):
			return &TlsAcmeOrder{Url: orderUrl, Status: TlsAcmeStatusInvalid}
		}
		if !hold.poll(ctx, self.settings.OrderPollInterval) {
			return nil
		}
	}
}

// Whether the CA calls an order dead: any status but pending, ready, processing and valid.
func tlsAcmeOrderDead(order *TlsAcmeOrder) bool {
	if order == nil {
		return true
	}
	switch order.Status {
	case TlsAcmeStatusPending, TlsAcmeStatusReady, TlsAcmeStatusProcessing, TlsAcmeStatusValid:
		return false
	}
	return true
}

// A refused or unknown newOrder, by 17.2.7's table: the grant ends either way.
func (self *TlsCustomDomainOrderer) newOrderRefused(ctx context.Context, report *TlsCustomPassReport, hold *tlsCustomHold, err error) {
	problem := tlsAcmeProblemOf(err)
	switch {
	case problem == nil:
		// outcome unknown (5xx, timeout): an order may exist that no row names; it lapses unfinalized
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
	case problem.Status == 429 || problem.Type == TlsAcmeProblemRateLimited:
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRateLimited, RetryAfterMs: uint32(problem.RetryAfter.Milliseconds())})
	case problem.Type == TlsAcmeProblemAlreadyReplaced || (problem.Status == 409 && 0 < len(hold.claim.ReplacesLeaf)):
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventNotExempt})
	case problem.Type == TlsAcmeProblemUnauthorized || problem.Type == TlsAcmeProblemAccountDoesNotExist:
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
		self.alarm(TlsCustomAlarmKeyMismatch)
	case problem.Type == TlsAcmeProblemRejectedIdentifier || problem.Type == TlsAcmeProblemCaa:
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventFailed, Reason: TlsCustomReasonCaRefused})
		self.alarm(TlsCustomAlarmCaRefused)
		report.Failed = append(report.Failed, hold.args.CertId)
	default:
		// a refusal with nothing recorded: the granted newOrder was refused
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventOrderInvalid})
	}
}

// The pending order's one authorization (17.2.9): valid waits for ready; pending is challenged on this desktop's
// path after the probe, then polled; invalid is an authz_failed and an order_invalid. Answers the order read again,
// or done once the row was handed back.
func (self *TlsCustomDomainOrderer) authorize(ctx context.Context, report *TlsCustomPassReport, hold *tlsCustomHold, key *ecdsa.PrivateKey, order *TlsAcmeOrder) (*TlsAcmeOrder, bool) {
	acme := self.deps.Acme
	accountUri := hold.account.AccountUri
	row := hold.claim.Record
	if len(order.Authorizations) != 1 {
		self.kill(ctx, hold, key, order, TlsCustomReasonNoPath)
		return nil, true
	}
	authorization, err := acme.Authorization(ctx, key, accountUri, order.Authorizations[0])
	if err != nil || authorization == nil {
		// an outcome unknown: the pending order's round comes again a poll on, under the claim
		if !hold.poll(ctx, self.settings.OrderPollInterval) {
			return nil, true
		}
		return order, false
	}
	switch authorization.Status {
	case TlsAcmeStatusValid:
		// wait for ready
		if !hold.poll(ctx, self.settings.OrderPollInterval) {
			return nil, true
		}
		reread := self.reread(ctx, hold, key, order.Url)
		return reread, reread == nil
	case TlsAcmeStatusPending:
	default:
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventAuthzFailed, Reason: authorization.ProblemType})
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventOrderInvalid})
		return nil, true
	}
	path := self.challengePath(ctx, hold.account, row)
	var challenge *TlsAcmeChallenge
	for _, offered := range authorization.Challenges {
		if offered.Type == path {
			challenge = offered
		}
	}
	if path == "" || challenge == nil {
		self.kill(ctx, hold, key, order, TlsCustomReasonNoPath)
		return nil, true
	}
	keyAuthorization, err := acme.KeyAuthorization(key, challenge.Token)
	if err != nil {
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
		return nil, true
	}
	switch path {
	case TlsAcmeChallengeTlsAlpn:
		if err := self.deps.Alpn.Serve(ctx, row.CustomHost, row.Owner, keyAuthorization, self.clock.Now().Add(self.settings.ChallengeLifetime), hold.claim.ClaimSeq); err != nil {
			hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
			return nil, true
		}
		defer self.deps.Alpn.Clear(row.CustomHost)
		for range self.settings.ProbeCount {
			probeCtx, cancel := context.WithTimeout(ctx, self.settings.ProbeTimeout)
			err := self.deps.Alpn.Probe(probeCtx, row.CustomHost, keyAuthorization, self.settings.ProbeTimeout)
			cancel()
			if err != nil {
				self.kill(ctx, hold, key, order, TlsCustomReasonNoRoute)
				return nil, true
			}
		}
	case TlsAcmeChallengeDns:
		digest := sha256.Sum256([]byte(keyAuthorization))
		value := base64.RawURLEncoding.EncodeToString(digest[:])
		written, done := self.challengeWrite(ctx, hold, value)
		if done {
			return nil, true
		}
		writtenTime := self.clock.Now()
		for {
			status, err := self.deps.Api.ChallengeStatus(ctx, written.ChallengeId)
			if err == nil && status.Readiness == TlsCustomReadinessReady {
				break
			}
			if tlsCustomTokenRefusedForGood(err) {
				// no read goes until the token keeper's refusal changes: nothing more is sent for the row
				hold.lost = true
				return nil, true
			}
			if err == nil && status.Readiness == TlsCustomReadinessStale {
				// stale confirmed for this serial: the same digest again, under the same claim, at a new serial
				if written, done = self.challengeWrite(ctx, hold, value); done {
					return nil, true
				}
			}
			if self.settings.ChallengeLifetime <= self.clock.Now().Sub(writtenTime) {
				// the edges never served it: no validation is asked on a doubt
				self.kill(ctx, hold, key, order, TlsCustomReasonNoRoute)
				return nil, true
			}
			// kept while the edges catch up, so a POST after a stale verdict comes under the claim its receipt is
			// kept for; a lapsed lock would make the next claim's a new receipt and a new write
			if !hold.pause(ctx, self.settings.OrderPollInterval) {
				return nil, true
			}
		}
		for range self.settings.ProbeCount {
			values, err := self.deps.Resolver.LookupTxt(ctx, tlsCustomAcmeChallengeLabel+row.CustomHost)
			if err != nil || !slices.Contains(values, value) {
				self.kill(ctx, hold, key, order, TlsCustomReasonNoRoute)
				return nil, true
			}
		}
	}
	if !hold.renew(ctx) {
		return nil, true
	}
	if err := acme.Challenge(ctx, key, accountUri, challenge.Url); err != nil {
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
		return nil, true
	}
	// the authorization polled until the CA decides it, under the claim renewed as it comes due; a read with no answer
	// is asked again, and the attempt's OrderDeadline, not the challenge's time, ends the poll, releasing the claim
	for {
		if !hold.poll(ctx, self.settings.OrderPollInterval) {
			return nil, true
		}
		polled, err := acme.Authorization(ctx, key, accountUri, authorization.Url)
		if err != nil || polled == nil || polled.Status == TlsAcmeStatusPending {
			continue
		}
		if polled.Status == TlsAcmeStatusValid {
			reread := self.reread(ctx, hold, key, order.Url)
			return reread, reread == nil
		}
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventAuthzFailed, Reason: polled.ProblemType})
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventOrderInvalid})
		return nil, true
	}
}

// POST /tls/custom-challenge under the hold's claim (17.2.9's DNS-01 steps 1 and 2; owner decision 680): the answer
// naming the serial the write took, or done once the row was handed back or the hold lost. api keeps one receipt for
// the domain and claim, which answers a POST sent again under the same claim with the write already made or still
// owed, never a second one, and owes a new write of the same digest only after GET confirmed a stale verdict for its
// serial. So a failed POST is sent again under the claim, which the holder keeps meanwhile:
//
//   - no answer, or the server's failure, such as 503 with the write still owed: again after OrderPollInterval;
//   - 409 in_flight, another digest's write under the claim not yet settled, and 429 budget, the name's writes of the
//     hour spent: again once the answer's retry_after has passed, at least OrderPollInterval on;
//   - 409 claim, the lock another's, and 403, the caller no longer an orderer of the domain: the hold is lost, and
//     nothing more is sent for the row;
//   - a service token refused for good, invalid_grant or no enrolled client (tlsCustomTokenRefusedForGood): nothing
//     went, and no request goes, a release included, until that changes, so the hold is lost as above; a token that
//     may yet be had, a keychain still locked or the exchange's 503 or 429, goes again as no answer or a 429 does;
//   - any other refusal, which no retry under the claim changes and for which nothing was written: progress release.
//
// The claim is released otherwise only where 17.2.7 ends the attempt: once its OrderDeadline has passed, or would
// before the next try, the order staying recorded.
func (self *TlsCustomDomainOrderer) challengeWrite(ctx context.Context, hold *tlsCustomHold, value string) (*TlsCustomChallengeResult, bool) {
	release := func() {
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
	}
	for {
		written, err := self.deps.Api.Challenge(ctx, &TlsCustomChallengeArgs{Domain: hold.account.Domain, Value: value})
		if err == nil {
			return written, false
		}
		if ctx.Err() != nil {
			return nil, true
		}
		wait := self.settings.OrderPollInterval
		retryAfter := func(retryAfterMs uint32) {
			wait = max(wait, time.Duration(retryAfterMs)*time.Millisecond)
		}
		var refusal *TlsCustomError
		var apiErr *SidecarApiError
		switch {
		case tlsCustomTokenRefusedForGood(err):
			hold.lost = true
			return nil, true
		case errors.As(err, &refusal):
			switch {
			case refusal.Refusal.Reason == TlsCustomRefusalClaim || refusal.Status == http.StatusForbidden:
				hold.lost = true
				return nil, true
			case refusal.Refusal.Reason == TlsCustomRefusalInFlight || refusal.Refusal.Reason == TlsCustomRefusalBudget:
				retryAfter(refusal.Refusal.RetryAfterMs)
			case refusal.Status < http.StatusInternalServerError:
				release()
				return nil, true
			}
		case errors.As(err, &apiErr):
			switch {
			case apiErr.Status == http.StatusTooManyRequests:
				retryAfter(apiErr.RetryAfterMs)
			case http.StatusOK < apiErr.Status && apiErr.Status < http.StatusInternalServerError:
				release()
				return nil, true
			}
		case errors.Is(err, ErrSidecarApiArgs):
			// refused here, before any request: the same request would be again
			release()
			return nil, true
		}
		// a wait that would reach the attempt's end releases instead, the order recorded for the next claim; a longer
		// retry_after than a third of the lease is cut at each renewal
		if !hold.poll(ctx, wait) {
			return nil, true
		}
	}
}

// Kills a live order a holder must give up (17.2.7): deactivates each authorization and reads the order again, up to
// DeactivateTryCount times. Dead: order_invalid with reason. Valid, another holder having finalized it: its chain is
// registered. Still live: release, and tls_custom_order_stuck.
func (self *TlsCustomDomainOrderer) kill(ctx context.Context, hold *tlsCustomHold, key *ecdsa.PrivateKey, order *TlsAcmeOrder, reason string) {
	acme := self.deps.Acme
	accountUri := hold.account.AccountUri
	for range self.settings.DeactivateTryCount {
		for _, url := range order.Authorizations {
			acme.DeactivateAuthorization(ctx, key, accountUri, url)
		}
		reread, err := acme.Order(ctx, key, accountUri, order.Url)
		if errors.Is(err, ErrTlsAcmeGone) || (err == nil && tlsAcmeOrderDead(reread)) {
			hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventOrderInvalid, Reason: reason})
			return
		}
		if err == nil && reread.Status == TlsAcmeStatusValid {
			self.download(ctx, &TlsCustomPassReport{}, hold, key, reread)
			return
		}
	}
	hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
	self.alarm(TlsCustomAlarmOrderStuck)
}

// Steps 6 to 8 of 17.2.7: the CA's chain, checked, its window, and the register. A download with an unknown outcome is
// retried until the attempt's OrderDeadline, and a register with no answer is sent again while the claim renews; each
// wait renews the claim as it comes due, and the attempt's end releases it, the next claim resuming at step 4.
func (self *TlsCustomDomainOrderer) download(ctx context.Context, report *TlsCustomPassReport, hold *tlsCustomHold, key *ecdsa.PrivateKey, order *TlsAcmeOrder) {
	acme := self.deps.Acme
	accountUri := hold.account.AccountUri
	row := hold.claim.Record
	var chain [][]byte
	for {
		var err error
		if chain, err = acme.Certificate(ctx, key, accountUri, order.Certificate); err == nil {
			break
		}
		if !hold.poll(ctx, self.settings.OrderPollInterval) {
			return
		}
	}
	leaf, ok := self.checkChain(row, chain)
	if !ok {
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventFailed, Reason: TlsCustomReasonForeign})
		self.alarm(TlsCustomAlarmForeign)
		report.Failed = append(report.Failed, row.CertId)
		return
	}
	start, end, err := acme.RenewalInfo(ctx, chain[0])
	if err != nil {
		start, end = time.Time{}, time.Time{}
	}
	args := &TlsCertRegisterArgs{
		CertId:         row.CertId,
		ClaimSeq:       hold.claim.ClaimSeq,
		Chain:          chain,
		AccountUri:     accountUri,
		AriWindowStart: start,
		AriWindowEnd:   end,
	}
	for {
		err := self.deps.Api.Register(ctx, args)
		var refusal *TlsCustomError
		switch {
		case err == nil:
			report.Issued = append(report.Issued, row.CertId)
			return
		case errors.As(err, &refusal) && refusal.Refusal.Reason == TlsCustomRefusalState:
			// the row ended under its order: revoke the chain at once, and free the lock, so the revoke pass that
			// settles the row is not held up by this claim's lease (17.2.12 step 4)
			acme.Revoke(ctx, key, accountUri, leaf.Raw, tlsCustomRevocationCessation)
			hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
			return
		case errors.As(err, &refusal) && refusal.Refusal.Reason == TlsCustomRefusalClaim:
			// another holder registers it
			hold.lost = true
			return
		case !tlsCustomUnanswered(err):
			// a refusal no retry under the claim changes: the next claim resumes at step 4
			return
		}
		if !hold.poll(ctx, self.settings.OrderPollInterval) {
			return
		}
	}
}

// The chain's check (17.2.7 step 6): the leaf's key is the CSR's, its names exactly the row's one name, not_after
// ahead, each certificate signed by the next.
func (self *TlsCustomDomainOrderer) checkChain(row *TlsCertRecord, chainDer [][]byte) (*x509.Certificate, bool) {
	if len(chainDer) == 0 {
		return nil, false
	}
	certificates := []*x509.Certificate{}
	for _, der := range chainDer {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, false
		}
		certificates = append(certificates, certificate)
	}
	for index := 0; index+1 < len(certificates); index += 1 {
		if certificates[index].CheckSignatureFrom(certificates[index+1]) != nil {
			return nil, false
		}
	}
	leaf := certificates[0]
	csr, err := x509.ParseCertificateRequest(row.Csr)
	if err != nil || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return nil, false
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != row.CustomHost || 0 < len(leaf.IPAddresses) || 0 < len(leaf.EmailAddresses) || 0 < len(leaf.URIs) {
		return nil, false
	}
	if !self.clock.Now().Before(leaf.NotAfter) {
		return nil, false
	}
	return leaf, true
}

// 17.2.12 for a claimed custom_revoking row: a chain is revoked under the account key; a row with no chain that ended
// under its order has the order settled, killed or its certificate revoked, before the account orders again.
func (self *TlsCustomDomainOrderer) revokePass(ctx context.Context, report *TlsCustomPassReport, hold *tlsCustomHold, key *ecdsa.PrivateKey) {
	acme := self.deps.Acme
	accountUri := hold.account.AccountUri
	row := hold.claim.Record
	if row == nil {
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
		return
	}
	revoke := func(leaf []byte) bool {
		if !hold.renew(ctx) {
			return false
		}
		reason := tlsCustomRevocationCessation
		if row.RevocationReason == TlsCertRevocationReasonKeyCompromise {
			reason = tlsCustomRevocationKeyComp
		}
		err := acme.Revoke(ctx, key, accountUri, leaf, reason)
		problem := tlsAcmeProblemOf(err)
		switch {
		case err == nil, problem != nil && problem.Type == TlsAcmeProblemAlreadyRevoked:
			return true
		case problem != nil && problem.Type == TlsAcmeProblemUnauthorized:
			self.alarm(TlsCustomAlarmKeyMismatch)
		}
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
		return false
	}
	if 0 < len(row.Chain) {
		if revoke(row.Chain[0]) {
			hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRevoked})
			report.Revoked = append(report.Revoked, row.CertId)
		}
		return
	}
	if hold.claim.OrderUrl == "" {
		// nothing was ever ordered for it
		hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRevoked})
		report.Revoked = append(report.Revoked, row.CertId)
		return
	}
	for range self.settings.DeactivateTryCount {
		order, err := acme.Order(ctx, key, accountUri, hold.claim.OrderUrl)
		switch {
		case errors.Is(err, ErrTlsAcmeGone), err == nil && tlsAcmeOrderDead(order):
			hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRevoked})
			report.Revoked = append(report.Revoked, row.CertId)
			return
		case err != nil:
			hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
			return
		case order.Status == TlsAcmeStatusValid:
			chain, err := acme.Certificate(ctx, key, accountUri, order.Certificate)
			if err != nil || len(chain) == 0 {
				hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
				return
			}
			if revoke(chain[0]) {
				hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRevoked})
				report.Revoked = append(report.Revoked, row.CertId)
			}
			return
		case order.Status == TlsAcmeStatusProcessing:
			if !hold.pause(ctx, self.settings.OrderPollInterval) {
				return
			}
		default:
			// pending or ready: deactivated, after which no finalize of it succeeds (A13)
			for _, url := range order.Authorizations {
				acme.DeactivateAuthorization(ctx, key, accountUri, url)
			}
		}
	}
	self.alarm(TlsCustomAlarmOrderStuck)
	hold.progress(ctx, &TlsCustomProgressArgs{Event: TlsCustomEventRelease})
}

// What a key change's resume found (17.2.13).
type tlsCustomRollState int

const (
	tlsCustomRollNotMade tlsCustomRollState = iota
	tlsCustomRollMade
	tlsCustomRollLost
)

// The key repos a key change reads and writes, from this desktop's own view (17.2.13). Safe for concurrent use.
type TlsCustomKeyRepos interface {
	// Whether a key change is due for the key file in repoId made at shrunkAt: its holders shrank since, or its
	// owner is no longer a member; and whether this desktop may make it: a network admin's, the repo owner's while
	// the owner is a member, any admin holder's once not.
	RolloverDue(repoId Id, shrunkAt uint64) (due bool, mayRoll bool)
	// The repo a key change writes to: repoId itself when this desktop's user owns it, else this user's own secret
	// repo, created if there is none and shared by EvsShare with every subject of repoId's shares that still
	// stands, returning once the log admits them (R2). With its holders_shrunk_at.
	RollTarget(ctx context.Context, repoId Id) (targetRepoId Id, shrunkAt uint64, err error)
}

// Makes the account (17.2.13's creation) for a verified domain with no account row, with this admin's own secret
// repo repoId, whose holders_shrunk_at is shrunkAt: the key file before the CA hears of the key, the account URI in
// it before the row, and the row last. A file with no URI from a run that crashed after newAccount is resumed with
// onlyReturnExisting. 409 exists answers ErrTlsCustomAccountExists after this account is deactivated.
func (self *TlsCustomDomainOrderer) CreateAccount(ctx context.Context, domain string, repoId Id, shrunkAt uint64) (*TlsCustomAccount, error) {
	var file *TlsCustomKeyFile
	if data, err := self.deps.Keys.ReadKeyFile(ctx, repoId, domain); err == nil {
		if existing, err := ParseTlsCustomKeyFile(data, domain); err == nil && existing.KeySeq == 1 && existing.Next == nil {
			file = existing
		}
	}
	if file == nil {
		key, err := NewTlsCustomAccountKey()
		if err != nil {
			return nil, err
		}
		file = &TlsCustomKeyFile{Format: tlsCustomKeyFileFormat, Domain: domain, Ca: "letsencrypt", KeySeq: 1, Key: key, ShrunkAt: shrunkAt}
		if err := self.writeKeyFile(ctx, repoId, file); err != nil {
			return nil, err
		}
	}
	key, err := tlsCustomParseKey(file.Key)
	if err != nil {
		return nil, err
	}
	if file.AccountUri == "" {
		// a crash after newAccount left the file with no URI: the key's own account answers
		accountUri, err := self.deps.Acme.NewAccount(ctx, key, false)
		if err != nil {
			accountUri, err = self.deps.Acme.NewAccount(ctx, key, true)
			if err != nil {
				return nil, err
			}
		}
		file.AccountUri = accountUri
		if err := self.writeKeyFile(ctx, repoId, file); err != nil {
			return nil, err
		}
	}
	account, err := self.deps.Api.Account(ctx, &TlsCustomAccountArgs{
		Domain:        domain,
		Op:            TlsCustomAccountCreate,
		AccountUri:    file.AccountUri,
		KeyThumbprint: TlsCustomKeyThumbprint(&key.PublicKey),
		KeyRepoId:     repoId,
	})
	var refusal *TlsCustomError
	if errors.As(err, &refusal) && refusal.Refusal.Reason == TlsCustomRefusalExists {
		// another admin won: this account goes, and its file with it
		self.deps.Acme.Deactivate(ctx, key, file.AccountUri)
		return nil, ErrTlsCustomAccountExists
	}
	if err != nil {
		return nil, err
	}
	self.deps.Keys.SetLocalKeyFile(domain, mustMarshalTlsCustomKeyFile(file))
	return account, nil
}

// Another admin made the domain's account first.
var ErrTlsCustomAccountExists = errors.New("the domain's account exists")

// The file's bytes, nil when they do not marshal, which a key file always does.
func mustMarshalTlsCustomKeyFile(file *TlsCustomKeyFile) []byte {
	data, err := file.Marshal()
	if err != nil {
		return nil
	}
	return data
}

// Writes file to repoId's secret repo, returning once the push committed, and keeps the local copy.
func (self *TlsCustomDomainOrderer) writeKeyFile(ctx context.Context, repoId Id, file *TlsCustomKeyFile) error {
	data, err := file.Marshal()
	if err != nil {
		return err
	}
	if err := self.deps.Keys.WriteKeyFile(ctx, repoId, file.Domain, data); err != nil {
		return err
	}
	return self.deps.Keys.SetLocalKeyFile(file.Domain, data)
}

// 17.2.13's key change R1 to R7, with its resume, for account whose current key file this desktop holds: the new
// key committed where the remaining holders read it before the CA is asked to require it, and the row's key_seq
// moved last. ErrTlsCustomKeyUnavailable when neither key is the account's: tls_account_lost, which nothing on our
// side recovers.
func (self *TlsCustomDomainOrderer) RollAccount(ctx context.Context, account *TlsCustomAccount, repos TlsCustomKeyRepos) error {
	file, _, _, err := self.accountKey(ctx, account)
	if err != nil {
		return err
	}
	currentKey, err := tlsCustomParseKey(file.Key)
	if err != nil {
		return err
	}
	s := account.KeySeq
	// R1: the rollover claim, under which no order is in flight
	hold, err := self.claim(ctx, account, &TlsCustomClaimArgs{Domain: account.Domain, Purpose: TlsCustomPurposeRollover, KeySeq: file.KeySeq})
	if err != nil {
		return err
	}
	accountOp := func(op string, thumbprint []byte, repoId Id) (*TlsCustomAccount, error) {
		return self.deps.Api.Account(ctx, &TlsCustomAccountArgs{
			Domain:        account.Domain,
			Op:            op,
			AccountUri:    account.AccountUri,
			KeySeq:        s,
			KeyThumbprint: thumbprint,
			KeyRepoId:     repoId,
			ClaimSeq:      hold.claim.ClaimSeq,
		})
	}
	// resume: the file at s + 1 and the row at s with that key as its next: R6 was done, R7 is owed
	if file.KeySeq == s+1 {
		_, err := accountOp(TlsCustomAccountRollEnd, TlsCustomKeyThumbprint(&currentKey.PublicKey), account.NextKeyRepoId)
		return err
	}
	// resume: what the CA and the files say of a change in flight
	if file.Next != nil || account.NextKeyThumbprint != nil {
		state, nextKey := self.rollState(ctx, account, file)
		switch state {
		case tlsCustomRollLost:
			self.alarm(TlsCustomAlarmAccountLost)
			return ErrTlsCustomKeyUnavailable
		case tlsCustomRollMade:
			targetRepoId := account.NextKeyRepoId
			if targetRepoId == (Id{}) {
				targetRepoId = account.KeyRepoId
			}
			return self.rollFinish(ctx, account, accountOp, targetRepoId, nextKey, file.ShrunkAt)
		}
		if nextKey == nil || account.NextKeyThumbprint == nil {
			// the row names a next the file lacks, or the file one the row lacks: start again
			if account.NextKeyThumbprint != nil {
				if _, err := accountOp(TlsCustomAccountRollAbort, nil, Id{}); err != nil {
					return err
				}
				return nil
			}
		} else {
			return self.rollChange(ctx, hold, account, accountOp, currentKey, nextKey, account.NextKeyRepoId, file.ShrunkAt)
		}
	}
	// R2: the repo the remaining holders read
	targetRepoId, shrunkAt, err := repos.RollTarget(ctx, account.KeyRepoId)
	if err != nil {
		return err
	}
	// R3: K', durable beside K_s before anyone asks the CA for it
	nextDer, err := NewTlsCustomAccountKey()
	if err != nil {
		return err
	}
	nextKey, err := tlsCustomParseKey(nextDer)
	if err != nil {
		return err
	}
	staged := &TlsCustomKeyFile{
		Format:     tlsCustomKeyFileFormat,
		Domain:     account.Domain,
		Ca:         file.Ca,
		AccountUri: account.AccountUri,
		KeySeq:     s,
		Key:        file.Key,
		Next:       &TlsCustomKeyFileNext{KeySeq: s + 1, Key: nextDer},
		ShrunkAt:   shrunkAt,
	}
	if err := self.writeKeyFile(ctx, targetRepoId, staged); err != nil {
		return err
	}
	// R4: the row records the next key
	if _, err := accountOp(TlsCustomAccountRollBegin, TlsCustomKeyThumbprint(&nextKey.PublicKey), targetRepoId); err != nil {
		return err
	}
	return self.rollChange(ctx, hold, account, accountOp, currentKey, nextKey, targetRepoId, shrunkAt)
}

// R5 to R7: the CA asked to require K', then the file at s + 1, then the row.
func (self *TlsCustomDomainOrderer) rollChange(ctx context.Context, hold *tlsCustomHold, account *TlsCustomAccount, accountOp func(op string, thumbprint []byte, repoId Id) (*TlsCustomAccount, error), currentKey *ecdsa.PrivateKey, nextKey *ecdsa.PrivateKey, targetRepoId Id, shrunkAt uint64) error {
	if !hold.renew(ctx) {
		return errors.New("the rollover claim was lost before the key change")
	}
	if err := self.deps.Acme.KeyChange(ctx, account.AccountUri, currentKey, nextKey); err != nil {
		return err
	}
	return self.rollFinish(ctx, account, accountOp, targetRepoId, nextKey, shrunkAt)
}

// R6 and R7.
func (self *TlsCustomDomainOrderer) rollFinish(ctx context.Context, account *TlsCustomAccount, accountOp func(op string, thumbprint []byte, repoId Id) (*TlsCustomAccount, error), targetRepoId Id, nextKey *ecdsa.PrivateKey, shrunkAt uint64) error {
	nextDer, err := x509.MarshalPKCS8PrivateKey(nextKey)
	if err != nil {
		return err
	}
	finished := &TlsCustomKeyFile{
		Format:     tlsCustomKeyFileFormat,
		Domain:     account.Domain,
		Ca:         "letsencrypt",
		AccountUri: account.AccountUri,
		KeySeq:     account.KeySeq + 1,
		Key:        nextDer,
		ShrunkAt:   shrunkAt,
	}
	if err := self.writeKeyFile(ctx, targetRepoId, finished); err != nil {
		return err
	}
	_, err = accountOp(TlsCustomAccountRollEnd, TlsCustomKeyThumbprint(&nextKey.PublicKey), targetRepoId)
	return err
}

// Whether a change in flight was made at the CA (17.2.13's resume): K_s still the account's is not made; K' the
// account's is made; neither is lost.
func (self *TlsCustomDomainOrderer) rollState(ctx context.Context, account *TlsCustomAccount, file *TlsCustomKeyFile) (tlsCustomRollState, *ecdsa.PrivateKey) {
	currentKey, err := tlsCustomParseKey(file.Key)
	if err != nil {
		return tlsCustomRollLost, nil
	}
	var nextKey *ecdsa.PrivateKey
	if file.Next != nil {
		nextKey, _ = tlsCustomParseKey(file.Next.Key)
	}
	if self.deps.Acme.Account(ctx, currentKey, account.AccountUri) == nil {
		return tlsCustomRollNotMade, nextKey
	}
	if nextKey != nil {
		if accountUri, err := self.deps.Acme.NewAccount(ctx, nextKey, true); err == nil && accountUri == account.AccountUri {
			return tlsCustomRollMade, nextKey
		}
	}
	return tlsCustomRollLost, nil
}

// 17.2.7's loop until ctx ends: a pass, then PollInterval moved by up to PollJitter of it either way after a pass that
// listed work, else IdlePollInterval, the same after a pass that failed. No pass starts once ctx has ended, before
// the first or at a wait whose timer fired with the end. report, when not nil, takes each pass's report and error, nil
// for no failure.
func (self *TlsCustomDomainOrderer) Run(ctx context.Context, report func(passReport *TlsCustomPassReport, err error)) {
	for ctx.Err() == nil {
		passReport, err := self.RunOnce(ctx)
		if report != nil {
			report(passReport, err)
		}
		wait := self.settings.IdlePollInterval
		if err == nil && passReport.WorkSeen {
			wait = self.settings.PollInterval
			if spread := time.Duration(self.settings.PollJitter * float64(wait)); 0 < spread {
				wait += time.Duration(mathrand.Int64N(int64(2*spread)+1)) - spread
			}
		}
		if self.wait(ctx, wait) != nil {
			return
		}
	}
}

// What `ur tls account status` shows of one account: the server's row, which of its keys this desktop's key file
// gives, and whether a key change is due and may be made here (17.2.13).
type TlsCustomAccountStatus struct {
	Account *TlsCustomAccount
	// The key sequence of the key this desktop holds for the row, 0 for none: the row's key_seq, or one more while a
	// key change owes its last step.
	KeySeq uint64
	// A key change is due for the key file this desktop holds, and whether this desktop may make it.
	RolloverDue bool
	MayRoll     bool
	// The account's rows on the work list.
	WorkCount int
}

// Each account of the work list, with domain "" for all, as this desktop holds it.
func (self *TlsCustomDomainOrderer) AccountStatus(ctx context.Context, domain string, repos TlsCustomKeyRepos) ([]*TlsCustomAccountStatus, error) {
	work, err := self.deps.Api.Work(ctx)
	if err != nil {
		return nil, err
	}
	statuses := []*TlsCustomAccountStatus{}
	for _, account := range work.Accounts {
		if domain != "" && account.Domain != domain {
			continue
		}
		status := &TlsCustomAccountStatus{Account: account}
		for _, row := range work.QueuedCsrs {
			if row.CustomDomain == account.Domain {
				status.WorkCount += 1
			}
		}
		if file, _, keySeq, err := self.accountKey(ctx, account); err == nil {
			status.KeySeq = keySeq
			if repos != nil {
				status.RolloverDue, status.MayRoll = repos.RolloverDue(account.KeyRepoId, file.ShrunkAt)
			}
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// The account of the work list for domain, nil for none.
func (self *TlsCustomDomainOrderer) Account(ctx context.Context, domain string) (*TlsCustomAccount, error) {
	work, err := self.deps.Api.Work(ctx)
	if err != nil {
		return nil, err
	}
	for _, account := range work.Accounts {
		if account.Domain == domain {
			return account, nil
		}
	}
	return nil, nil
}

// The secret repos' key files as the host reaches evs: TlsCustomKeyStore's repo half, which cli/ gives the orderer
// (DESIGN-DETAILS 17.2.3). Safe for concurrent use.
type TlsCustomRepoFiles interface {
	// The key file of domain in repoId. ErrTlsCustomKeyUnavailable when this desktop cannot read it.
	ReadKeyFile(ctx context.Context, repoId Id, domain string) ([]byte, error)
	// Writes it, returning once the push has committed.
	WriteKeyFile(ctx context.Context, repoId Id, domain string, data []byte) error
}

// A custom route's call whose service token could not be had, so no request went: carried with the token keeper's
// error, which sidecarServiceTokenRefusalOf reads (tlsCustomUnanswered, tlsCustomTokenRefusedForGood).
var errTlsCustomNoServiceToken = errors.New("no service token")

// TlsCustomApi on api's routes, each call under a service token for aud certs from token: Sidecar.certsServiceToken
// for SidecarTlsSettings.CertsResource, which asks again within its bound what may change, through ServiceToken, which
// caches it. A call whose token could not be had sends nothing and answers an error carrying errTlsCustomNoServiceToken.
type sidecarTlsCustomApi struct {
	api   *SidecarApi
	token func(ctx context.Context) (string, error)
}

// TlsCustomApi on api, each call under token's service token.
func NewTlsCustomApi(api *SidecarApi, token func(ctx context.Context) (string, error)) TlsCustomApi {
	return &sidecarTlsCustomApi{api: api, token: token}
}

// The call's service token, or the token keeper's error carrying errTlsCustomNoServiceToken.
func (self *sidecarTlsCustomApi) serviceToken(ctx context.Context) (string, error) {
	serviceToken, err := self.token(ctx)
	if err != nil {
		return "", fmt.Errorf("tls custom route: %w: %w", errTlsCustomNoServiceToken, err)
	}
	return serviceToken, nil
}

// See TlsCustomApi.
func (self *sidecarTlsCustomApi) Work(ctx context.Context) (*TlsCertsResult, error) {
	serviceToken, err := self.serviceToken(ctx)
	if err != nil {
		return nil, err
	}
	return self.api.TlsCustomWork(ctx, serviceToken)
}

// See TlsCustomApi.
func (self *sidecarTlsCustomApi) Claim(ctx context.Context, args *TlsCustomClaimArgs) (*TlsCustomClaimResult, error) {
	serviceToken, err := self.serviceToken(ctx)
	if err != nil {
		return nil, err
	}
	return self.api.TlsCustomClaim(ctx, serviceToken, args)
}

// See TlsCustomApi.
func (self *sidecarTlsCustomApi) Progress(ctx context.Context, args *TlsCustomProgressArgs) (*TlsCustomClaimResult, error) {
	serviceToken, err := self.serviceToken(ctx)
	if err != nil {
		return nil, err
	}
	return self.api.TlsCustomProgress(ctx, serviceToken, args)
}

// See TlsCustomApi.
func (self *sidecarTlsCustomApi) Register(ctx context.Context, args *TlsCertRegisterArgs) error {
	serviceToken, err := self.serviceToken(ctx)
	if err != nil {
		return err
	}
	return self.api.TlsCertRegister(ctx, serviceToken, args)
}

// See TlsCustomApi.
func (self *sidecarTlsCustomApi) Account(ctx context.Context, args *TlsCustomAccountArgs) (*TlsCustomAccount, error) {
	serviceToken, err := self.serviceToken(ctx)
	if err != nil {
		return nil, err
	}
	return self.api.TlsCustomAccount(ctx, serviceToken, args)
}

// See TlsCustomApi.
func (self *sidecarTlsCustomApi) Challenge(ctx context.Context, args *TlsCustomChallengeArgs) (*TlsCustomChallengeResult, error) {
	serviceToken, err := self.serviceToken(ctx)
	if err != nil {
		return nil, err
	}
	return self.api.TlsCustomChallenge(ctx, serviceToken, args)
}

// See TlsCustomApi.
func (self *sidecarTlsCustomApi) ChallengeStatus(ctx context.Context, challengeId uint64) (*TlsCustomChallengeResult, error) {
	serviceToken, err := self.serviceToken(ctx)
	if err != nil {
		return nil, err
	}
	return self.api.TlsCustomChallengeStatus(ctx, serviceToken, challengeId)
}

// The name a key file's local copy has in the keychain's tls namespace, beside the device key (17.2.3).
func tlsCustomLocalKeyName(domain string) string {
	return "acme/" + domain + ".json"
}

// TlsCustomKeyStore on the host's repo files and this Sidecar's keychain, whose tls namespace keeps each key file's
// local copy beside the device key (17.2.3).
type sidecarTlsCustomKeyStore struct {
	files   TlsCustomRepoFiles
	secrets SidecarSecrets
}

// See TlsCustomKeyStore.
func (self *sidecarTlsCustomKeyStore) ReadKeyFile(ctx context.Context, repoId Id, domain string) ([]byte, error) {
	return self.files.ReadKeyFile(ctx, repoId, domain)
}

// See TlsCustomKeyStore.
func (self *sidecarTlsCustomKeyStore) WriteKeyFile(ctx context.Context, repoId Id, domain string, data []byte) error {
	return self.files.WriteKeyFile(ctx, repoId, domain, data)
}

// The local copy, nil for none or while the keychain is locked.
func (self *sidecarTlsCustomKeyStore) LocalKeyFile(domain string) []byte {
	data, err := self.secrets.Get(tlsCustomLocalKeyName(domain))
	if err != nil || len(data) == 0 {
		return nil
	}
	return data
}

// See TlsCustomKeyStore.
func (self *sidecarTlsCustomKeyStore) SetLocalKeyFile(domain string, data []byte) error {
	return self.secrets.Put(tlsCustomLocalKeyName(domain), data)
}

// TlsCustomDevices and TlsCustomKeyRepos on this Sidecar's own verified view: the authority's admissions and the
// config follower's AclState, never a server's answer (17.2.7 step 3, 17.2.13). With no state standing yet every
// device reads as unadmitted and every grant as absent, the closed direction.
type sidecarTlsCustomDevices struct {
	sidecar   *Sidecar
	networkId Id
	sidecarId Id
}

// The verified AclState, nil while none stands.
func (self *sidecarTlsCustomDevices) state() *AclState {
	follower := self.sidecar.ConfigFollower()
	if follower == nil {
		return nil
	}
	engine := follower.AclEngine()
	if engine == nil {
		return nil
	}
	return engine.State()
}

// The tls/ ports a publish names (§13.10), on any of which a device serves its custom host.
var tlsCustomPublishPorts = []int{443, 8443, 8883, 5671}

// Whether sidecarId holds an active approved publish grant on tls/<port>/<ownerLabel> for one of ports, in either
// mode.
func (self *sidecarTlsCustomDevices) granted(sidecarId Id, ownerLabel string, ports []int) bool {
	return tlsDevicePublishGrant(self.state(), sidecarId, ownerLabel, ports, self.sidecar.clock.Now())
}

// Requires a publish grant on one of the ports and, for a scoped owner label, permission in that team scope.
func tlsDevicePublishGrant(state *AclState, sidecarId Id, ownerLabel string, ports []int, now time.Time) bool {
	if state == nil || ownerLabel == "" {
		return false
	}
	subject := AclSubject{Kind: AclSubjectSidecar, Id: sidecarId}
	if _, label, scoped := strings.Cut(ownerLabel, "."); scoped {
		config, ok := state.View().(*ConfigState)
		if !ok {
			return false
		}
		scope, declared := config.TeamScope(label)
		if !declared || !state.MayPublishInScope(subject, ownerLabel, scope, now).Allowed {
			return false
		}
	}
	for _, port := range ports {
		socketName := "tls/" + strconv.Itoa(port) + "/" + ownerLabel
		for _, appMode := range []protocol.AclAppMode{protocol.AclAppMode_ACL_APP_MODE_HTTP, protocol.AclAppMode_ACL_APP_MODE_RAW} {
			if _, decision := state.PublishGrant(subject, socketName, appMode, now); decision.Allowed {
				return true
			}
		}
	}
	return false
}

// See TlsCustomDevices: a revoked or parked admission is none.
func (self *sidecarTlsCustomDevices) Device(sidecarId Id, ownerLabel string) ([]byte, bool) {
	authority := self.sidecar.authority()
	if authority == nil {
		return nil, false
	}
	admission := authority.Admission(sidecarId)
	if admission == nil || admission.Row == nil || admission.Row.GetRevokedAt() != 0 || admission.Row.GetParkedAt() != 0 {
		return nil, false
	}
	return admission.Row.GetIdentityPublicKey(), self.granted(sidecarId, ownerLabel, tlsCustomPublishPorts)
}

// See TlsCustomDevices.
func (self *sidecarTlsCustomDevices) Holds443(ownerLabel string) bool {
	return self.granted(self.sidecarId, ownerLabel, []int{443})
}

// See TlsCustomDevices.
func (self *sidecarTlsCustomDevices) SidecarId() Id {
	return self.sidecarId
}

// See TlsCustomDevices.
func (self *sidecarTlsCustomDevices) NetworkId() Id {
	return self.networkId
}

// This desktop's member, zero for a tagged admission, which names none, or no admission.
func (self *sidecarTlsCustomDevices) memberId() Id {
	authority := self.sidecar.authority()
	if authority == nil {
		return Id{}
	}
	admission := authority.Admission(self.sidecarId)
	if admission == nil {
		return Id{}
	}
	return admission.MemberId
}

// See TlsCustomKeyRepos. A repo the state does not hold is due, and no desktop may roll it from here.
func (self *sidecarTlsCustomDevices) RolloverDue(repoId Id, shrunkAt uint64) (bool, bool) {
	state := self.state()
	if state == nil {
		return false, false
	}
	repo := state.Repo(repoId)
	if repo == nil {
		return true, false
	}
	ownerId, err := IdFromBytes(repo.GetOwnerMemberId())
	ownerMember := err == nil && state.view.Member(ownerId) != nil
	due := shrunkAt < repo.GetHoldersShrunkAt() || !ownerMember
	memberId := self.memberId()
	mayRoll := memberId != (Id{}) && state.memberAdmin(memberId) && (!ownerMember || memberId == ownerId)
	return due, mayRoll
}

// See TlsCustomKeyRepos: repoId when this desktop's member owns it. Moving the key into this user's own secret repo,
// shared by EvsShare with repoId's standing subjects (R2), waits on EvsShare filing from the ordering desktop, so it
// is refused, the closed direction: such a change is left due.
func (self *sidecarTlsCustomDevices) RollTarget(ctx context.Context, repoId Id) (Id, uint64, error) {
	state := self.state()
	if state == nil {
		return Id{}, 0, ErrTlsCustomRollTarget
	}
	repo := state.Repo(repoId)
	if repo == nil {
		return Id{}, 0, ErrTlsCustomRollTarget
	}
	ownerId, err := IdFromBytes(repo.GetOwnerMemberId())
	if err != nil || ownerId != self.memberId() {
		return Id{}, 0, ErrTlsCustomRollTarget
	}
	return repoId, repo.GetHoldersShrunkAt(), nil
}

// A key change that would move the key into another repo, which waits on EvsShare filing (17.2.13's R2).
var ErrTlsCustomRollTarget = errors.New("the key change moves the key into another secret repo, which waits on EvsShare filing")

// This member's own secret repo in the verified state, the first by id that is not deleted (17.2.13's creation step
// 1). A zero RepoId when the member has none yet, which the host creates; a zero MemberId while this sidecar's
// admission names no member or no state stands.
func (self *sidecarTlsCustomDevices) secretRepo() *TlsCustomSecretRepo {
	secret := &TlsCustomSecretRepo{MemberId: self.memberId()}
	state := self.state()
	if state == nil || secret.MemberId == (Id{}) {
		return &TlsCustomSecretRepo{}
	}
	for _, repoId := range state.RepoIds() {
		repo := state.Repo(repoId)
		deletion := repo.GetDeletion()
		if repo.GetKind() != protocol.RepoKind_REPO_KIND_SECRET || (deletion != nil && deletion.GetDeletedAt() != 0 && deletion.GetRestoredAt() == 0) {
			continue
		}
		if ownerId, err := IdFromBytes(repo.GetOwnerMemberId()); err == nil && ownerId == secret.MemberId {
			secret.RepoId = repoId
			secret.ShrunkAt = repo.GetHoldersShrunkAt()
			return secret
		}
	}
	return secret
}

// What an ordering desktop's orderer takes from this Sidecar (DESIGN-DETAILS 17.2.7): the custom routes under a
// service token for aud certs (certsServiceToken, which asks again within its bound what may change and ends a call at
// once on a refusal for good), its own verified view of the network's devices and grants, each key file's local copy
// beside the device key, the network's root from its zone, its clock, and its local alarms, which it logs. The host
// gives the CA (cli/'s acmez client), the resolver and the secret repos' key files (cli/'s evs), so no sdk leg links
// them. The TLS-ALPN-01 path uses this device's active listener for the exact mapped owner. ErrTlsCertsUnconfigured with
// no certs audience configured, as for the device's own orders.
func (self *Sidecar) TlsCustomOrdererDeps(ctx context.Context, acme TlsAcmeClient, resolver TlsCustomResolver, files TlsCustomRepoFiles) (*TlsCustomDomainOrdererDeps, TlsCustomKeyRepos, error) {
	if acme == nil || resolver == nil || files == nil {
		return nil, nil, fmt.Errorf("%w: the orderer needs its CA, resolver and key files", errInvalidSettings)
	}
	resource := self.settings.Tls.CertsResource
	if resource == "" {
		return nil, nil, ErrTlsCertsUnconfigured
	}
	networkId := self.enrolledNetworkId()
	identity := self.currentIdentity()
	if networkId == nil || identity == nil || self.instance == nil {
		return nil, nil, fmt.Errorf("%w: the orderer needs an enrolled network", errInvalidSettings)
	}
	names, err := self.tlsCertNames(ctx)
	if err != nil {
		return nil, nil, err
	}
	devices := &sidecarTlsCustomDevices{sidecar: self, networkId: *networkId, sidecarId: identity.SidecarId}
	deps := &TlsCustomDomainOrdererDeps{
		Api: NewTlsCustomApi(self.sidecarApi, func(ctx context.Context) (string, error) {
			return self.certsServiceToken(ctx, resource, nil)
		}),
		Acme:     acme,
		Resolver: resolver,
		Alpn:     &sidecarTlsCustomAlpn{sidecar: self, claims: map[string]*tlsDesktopChallenge{}},
		Devices:  devices,
		Keys:     &sidecarTlsCustomKeyStore{files: files, secrets: self.instance.secrets(*networkId, tlsSecretsNamespace)},
		Roots:    []string{names.Root},
		Clock:    self.clock,
		Repos:    devices,
		// a name only, never a host, a key or a path (I-13)
		Alarm: func(name string) {
			self.log.Warningf("[tls]custom-domain alarm %s\n", name)
		},
	}
	return deps, devices, nil
}

// A member's own secret repo, where a new account's key file goes (17.2.13's creation step 1).
type TlsCustomSecretRepo struct {
	// The member, whom a new secret repo names as owner; zero while this sidecar's admission names none.
	MemberId Id
	// The repo, zero when the member has none yet, which the host creates; and its holders_shrunk_at.
	RepoId   Id
	ShrunkAt uint64
}

// This sidecar's member's own secret repo in its verified view (17.2.13's creation step 1).
func (self *Sidecar) TlsCustomSecretRepo() *TlsCustomSecretRepo {
	networkId := self.enrolledNetworkId()
	identity := self.currentIdentity()
	if networkId == nil || identity == nil {
		return &TlsCustomSecretRepo{}
	}
	devices := &sidecarTlsCustomDevices{sidecar: self, networkId: *networkId, sidecarId: identity.SidecarId}
	return devices.secretRepo()
}

// 17.2.13's change in a pass, due when the key file's repo's holders shrank since the key was made or its owner left
// (owner decision 425): made now when this desktop may make it, so the first admin desktop online makes it within one
// poll, a change in flight resumed the same way, and a due change it may not make, or may make only by moving the key
// into another repo (ErrTlsCustomRollTarget), reported once a key sequence as rollover_due, which the server raises as
// tls_account_rollover_due. Whether the account's key moved, so the pass orders nothing more under the old one.
func (self *TlsCustomDomainOrderer) rollover(ctx context.Context, report *TlsCustomPassReport, account *TlsCustomAccount, file *TlsCustomKeyFile) bool {
	if self.deps.Repos == nil {
		return false
	}
	due, mayRoll := self.deps.Repos.RolloverDue(account.KeyRepoId, file.ShrunkAt)
	inFlight := 0 < len(account.NextKeyThumbprint)
	if !due && !inFlight {
		return false
	}
	if mayRoll {
		err := self.RollAccount(ctx, account, self.deps.Repos)
		if err == nil {
			report.Rolled = append(report.Rolled, account.Domain)
			return true
		}
		if !errors.Is(err, ErrTlsCustomRollTarget) {
			// the next pass tries again; ordering goes on under the key the row names
			return false
		}
	}
	// sent once for each key sequence the row names, so a standing due change is not reported each poll
	if due && self.rolloverDueSent[account.Domain] != account.KeySeq+1 {
		if _, err := self.deps.Api.Progress(ctx, &TlsCustomProgressArgs{Domain: account.Domain, Event: TlsCustomEventRolloverDue}); err == nil {
			self.rolloverDueSent[account.Domain] = account.KeySeq + 1
			report.RolloverDue = append(report.RolloverDue, account.Domain)
		}
	}
	return false
}
