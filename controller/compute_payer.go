// The ledger's keyed hashes (DESIGN-COMPUTE §9.11, §14.4, compute-2; BAL-M12-07): the payer and promotion hash keys,
// which the host holds in vault and gives through ComputeLedgerSecrets (server's ComputeServerSecrets), and the payer's
// hash, which keys §9.11's limits to the money's source rather than to the network a fraudster made.
//
//	payer      HMAC-SHA256 under the payer key of a domain word, a zero byte and the source: a Stripe card's
//	           fingerprint (one card across customers and networks) or an App Store purchase's appTransactionId (one
//	           Apple Account in the app). A Play purchase names no account and counts to its network alone, so it has
//	           no payer and asks for none.
//	promotion  HMAC-SHA256 under the promotion key of the code, its case folded (compute_promo.go)
//
// The domain word keeps a card's fingerprint and an account's id apart, so one never stands for the other, and the two
// keys keep a payer's hash and a code's apart. No key is logged or kept beyond the call; each read of one passes the
// test seam, so the privacy harness can look for it where it must not be.
//
// The host's secrets are registered once, from server's own file (RegisterComputeLedgerSecrets); every function that
// needs them takes them as its argument, so a test gives its own. Unset, every purchase and redemption refuses.

package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"unicode/utf8"
)

// The host's payer and promotion hash keys (§9.11): vault's on the server. Implementations are safe for concurrent
// use and read their keys on each call, so a vault fix takes effect without a restart.
type ComputeLedgerSecrets interface {
	// The key payer hashes are made under; an error where the host holds none.
	PayerHashKey() ([]byte, error)
	// The key promotion codes are hashed under; an error where the host holds none.
	PromoHashKey() ([]byte, error)
}

// No payer or promotion hash key: every purchase and redemption refuses (fails closed).
var ErrComputeLedgerSecretsUnset = errors.New("compute ledger: no payer or promotion hash key is set, so purchases and redemptions refuse")

// The shortest key a keyed hash takes: SHA-256's own size, an identifier of the hash, not a tunable.
const computeLedgerKeyMinByteCount = sha256.Size

var (
	computeLedgerSecretsLock sync.Mutex
	computeLedgerSecrets     ComputeLedgerSecrets
)

// Registers the host's secrets, once, from the host's own file at its start. A second registration, or a nil one, is a
// build error, which panics.
func RegisterComputeLedgerSecrets(secrets ComputeLedgerSecrets) {
	if secrets == nil {
		panic("compute ledger: nil secrets")
	}
	computeLedgerSecretsLock.Lock()
	defer computeLedgerSecretsLock.Unlock()
	if computeLedgerSecrets != nil {
		panic("compute ledger: the secrets are registered once")
	}
	computeLedgerSecrets = secrets
}

// The host's registered secrets, nil until registered: what a route hands the ledger's calls.
func ComputeRegisteredLedgerSecrets() ComputeLedgerSecrets {
	computeLedgerSecretsLock.Lock()
	defer computeLedgerSecretsLock.Unlock()
	return computeLedgerSecrets
}

// A key get answers, checked: an error wrapping ErrComputeLedgerSecretsUnset for no key or a key too short to key a
// hash. Names no byte of it.
func computeLedgerKeyChecked(kind string, get func() ([]byte, error)) ([]byte, error) {
	key, err := get()
	if err != nil {
		return nil, fmt.Errorf("%w: the %s key: %w", ErrComputeLedgerSecretsUnset, kind, err)
	}
	if len(key) < computeLedgerKeyMinByteCount {
		return nil, fmt.Errorf("%w: the %s key holds %d bytes, under %d", ErrComputeLedgerSecretsUnset, kind, len(key), computeLedgerKeyMinByteCount)
	}
	return key, nil
}

// The host's payer key, checked; unset secrets are ErrComputeLedgerSecretsUnset.
func computePayerKey(secrets ComputeLedgerSecrets) ([]byte, error) {
	if secrets == nil {
		return nil, ErrComputeLedgerSecretsUnset
	}
	key, err := computeLedgerKeyChecked("payer", secrets.PayerHashKey)
	if err != nil {
		return nil, err
	}
	testHookSecret("compute_payer_hash_key", key)
	return key, nil
}

// The host's promotion key, checked; unset secrets are ErrComputeLedgerSecretsUnset.
func computePromoKey(secrets ComputeLedgerSecrets) ([]byte, error) {
	if secrets == nil {
		return nil, ErrComputeLedgerSecretsUnset
	}
	key, err := computeLedgerKeyChecked("promotion", secrets.PromoHashKey)
	if err != nil {
		return nil, err
	}
	testHookSecret("compute_promo_hash_key", key)
	return key, nil
}

// HMAC-SHA256 under key of a domain word, a zero byte and value.
func computeKeyedHash(key []byte, domain string, value string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

// Where a payer's identity comes from (§9.11).
type ComputePayerSource int

const (
	// A Stripe card's fingerprint: one card across customers and networks.
	ComputePayerStripeCard ComputePayerSource = 1
	// An App Store purchase's appTransactionId: one Apple Account in the app.
	ComputePayerAppStoreAccount ComputePayerSource = 2
)

// The domain words of the payer hash, one a source: identifiers, so a hash never changes meaning.
const (
	computePayerDomainStripeCard      = "compute_payer_stripe_card"
	computePayerDomainAppStoreAccount = "compute_payer_app_store_account"
)

// A payer the ledger cannot hash: no secrets, a source it does not know, or an empty or malformed value.
var ErrComputePayerArgs = errors.New("compute payer: arguments refused")

// The payer's keyed hash of value, a Stripe card's fingerprint or an App Store appTransactionId (see the file header):
// what compute_payer keeps and ComputePurchaseCheck and ComputeCreditLot take. A Play purchase has no payer and is
// refused here; unset secrets refuse every hash.
func ComputePayerHash(secrets ComputeLedgerSecrets, source ComputePayerSource, value string) ([]byte, error) {
	var domain string
	switch source {
	case ComputePayerStripeCard:
		domain = computePayerDomainStripeCard
	case ComputePayerAppStoreAccount:
		domain = computePayerDomainAppStoreAccount
	default:
		return nil, fmt.Errorf("%w: no payer source %d (a Play purchase counts to its network alone)", ErrComputePayerArgs, source)
	}
	if value == "" || !utf8.ValidString(value) {
		return nil, fmt.Errorf("%w: an empty or malformed payer", ErrComputePayerArgs)
	}
	key, err := computePayerKey(secrets)
	if err != nil {
		return nil, err
	}
	return computeKeyedHash(key, domain, value), nil
}
