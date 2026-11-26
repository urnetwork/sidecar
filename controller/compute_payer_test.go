package controller

// The payer's keyed hash and the host's secrets (BAL-M12-07; DESIGN-COMPUTE §9.11): a fixed vector, a card's and an
// account's hashes kept apart, no payer for a Play purchase, and unset or short keys refusing every hash, purchase
// check and credit that needs them before anything is read.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// Secrets a test sets: each key, or an error for it.
type testLedgerSecrets struct {
	payerKey []byte
	promoKey []byte
	err      error
}

func (self *testLedgerSecrets) PayerHashKey() ([]byte, error) {
	return self.payerKey, self.err
}

func (self *testLedgerSecrets) PromoHashKey() ([]byte, error) {
	return self.promoKey, self.err
}

// A synthetic network.
var testComputeLotNetworkId = operator.Id{0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x01}

// Synthetic keys, test only.
func newTestLedgerSecrets() *testLedgerSecrets {
	return &testLedgerSecrets{
		payerKey: []byte("synthetic compute payer hash key, test only!"),
		promoKey: []byte("synthetic compute promo hash key, test only!"),
	}
}

// The hash of a fixed card's fingerprint under a fixed key: HMAC-SHA256 of the domain word, a zero byte and the
// fingerprint. A change here changes every stored payer, so the vector pins it.
func TestComputePayerHashVectors(t *testing.T) {
	secrets := newTestLedgerSecrets()
	hash, err := ComputePayerHash(secrets, ComputePayerStripeCard, "fp_test_synthetic_0001")
	if err != nil {
		t.Fatal(err)
	}
	if want := computeKeyedHash(secrets.payerKey, "compute_payer_stripe_card", "fp_test_synthetic_0001"); !bytes.Equal(hash, want) || len(hash) != 32 {
		t.Fatalf("the hash is %x", hash)
	}
	if got := hex.EncodeToString(hash); got != "90ab72a1fc8db7d77a951052d4fa8d24b54bef7390c3b2cd7f05f2e3f0d6041e" {
		t.Fatalf("the vector moved: %s", got)
	}
	// the same value as an App Store account's is another payer, and another key another hash
	account, err := ComputePayerHash(secrets, ComputePayerAppStoreAccount, "fp_test_synthetic_0001")
	if err != nil || bytes.Equal(account, hash) {
		t.Fatalf("a card and an account meet: %x, %v", account, err)
	}
	other := newTestLedgerSecrets()
	other.payerKey = []byte("another synthetic compute payer key, test only")
	if again, err := ComputePayerHash(other, ComputePayerStripeCard, "fp_test_synthetic_0001"); err != nil || bytes.Equal(again, hash) {
		t.Fatalf("two keys made one hash: %v", err)
	}
	// the key's bytes reach no hash in the clear
	if bytes.Contains(hash, secrets.payerKey[:8]) {
		t.Fatal("the hash carries its key")
	}
}

// A Play purchase names no payer; an empty or malformed value is none; unset, failing and short keys refuse.
func TestComputePayerHashRefusals(t *testing.T) {
	secrets := newTestLedgerSecrets()
	if _, err := ComputePayerHash(secrets, ComputePayerSource(3), "GPA.0000-0000-0000-00000"); !errors.Is(err, ErrComputePayerArgs) {
		t.Errorf("a Play order hashed: %v", err)
	}
	for _, value := range []string{"", string([]byte{0xff, 0xfe})} {
		if _, err := ComputePayerHash(secrets, ComputePayerStripeCard, value); !errors.Is(err, ErrComputePayerArgs) {
			t.Errorf("the value %q hashed: %v", value, err)
		}
	}
	for label, refused := range map[string]ComputeLedgerSecrets{
		"no secrets":  nil,
		"a key error": &testLedgerSecrets{err: errors.New("no vault file")},
		"a short key": &testLedgerSecrets{payerKey: []byte("short")},
	} {
		if _, err := ComputePayerHash(refused, ComputePayerStripeCard, "fp_test_synthetic_0001"); !errors.Is(err, ErrComputeLedgerSecretsUnset) {
			t.Errorf("%s hashed: %v", label, err)
		}
	}
}

// Unset secrets refuse a purchase before the database is asked.
func TestComputePurchaseCheckRefusesWithoutSecrets(t *testing.T) {
	env := newTestLedgerEnv()
	request := &ComputePurchaseRequest{NetworkId: testComputeLotNetworkId, AmountNanoUsd: 10 * model.ComputeCreditNanoUsd}
	if _, err := ComputePurchaseCheck(env, t.Context(), model.DefaultComputeLedgerSettings(), nil, request); !errors.Is(err, ErrComputeLedgerSecretsUnset) {
		t.Fatalf("a purchase without secrets: %v", err)
	}
	if env.db.callCount != 0 {
		t.Fatal("the database was asked")
	}
}

// The host's secrets register once; a second registration and a nil one panic.
func TestComputeLedgerSecretsRegisterOnce(t *testing.T) {
	computeLedgerSecretsLock.Lock()
	saved := computeLedgerSecrets
	computeLedgerSecrets = nil
	computeLedgerSecretsLock.Unlock()
	t.Cleanup(func() {
		computeLedgerSecretsLock.Lock()
		defer computeLedgerSecretsLock.Unlock()
		computeLedgerSecrets = saved
	})
	if ComputeRegisteredLedgerSecrets() != nil {
		t.Fatal("secrets before any registration")
	}
	secrets := newTestLedgerSecrets()
	RegisterComputeLedgerSecrets(secrets)
	if ComputeRegisteredLedgerSecrets() != secrets {
		t.Fatal("the registered secrets do not read back")
	}
	for label, register := range map[string]func(){
		"twice": func() { RegisterComputeLedgerSecrets(newTestLedgerSecrets()) },
		"nil":   func() { RegisterComputeLedgerSecrets(nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s registered", label)
				}
			}()
			register()
		}()
	}
}

// A credit the ledger cannot take is refused before the database is asked: a promotion off its market or without
// its lapse, a payer on a promotion, a store purchase on Stripe.
func TestComputeCreditRefusesMalformedLots(t *testing.T) {
	env := newTestLedgerEnv()
	settings := model.DefaultComputeLedgerSettings()
	expire := env.clock.now.Add(settings.PromoLapse)
	usd := 10 * model.ComputeCreditNanoUsd
	for label, request := range map[string]*ComputeCreditRequest{
		"no reference":                  {NetworkId: testComputeLotNetworkId, Kind: model.ComputeLotKindPurchase, Market: model.ComputeMarketStripe, AmountNanoUsd: usd},
		"no amount":                     {NetworkId: testComputeLotNetworkId, Kind: model.ComputeLotKindPurchase, Market: model.ComputeMarketStripe, MarketRef: "pi_1"},
		"a promotion off market":        {NetworkId: testComputeLotNetworkId, Kind: model.ComputeLotKindPromotion, Market: model.ComputeMarketStripe, MarketRef: "r", AmountNanoUsd: usd, ExpireTime: &expire},
		"a promotion that never lapses": {NetworkId: testComputeLotNetworkId, Kind: model.ComputeLotKindPromotion, Market: model.ComputeMarketPromotion, MarketRef: "r", AmountNanoUsd: usd},
		"a purchase that lapses":        {NetworkId: testComputeLotNetworkId, Kind: model.ComputeLotKindPurchase, Market: model.ComputeMarketStripe, MarketRef: "pi_1", AmountNanoUsd: usd, ExpireTime: &expire},
		"a payer on a promotion":        {NetworkId: testComputeLotNetworkId, Kind: model.ComputeLotKindPromotion, Market: model.ComputeMarketPromotion, MarketRef: "r", AmountNanoUsd: usd, ExpireTime: &expire, PayerHash: []byte{1}},
		"a store purchase on Stripe":    {NetworkId: testComputeLotNetworkId, Kind: model.ComputeLotKindPurchase, Market: model.ComputeMarketStripe, MarketRef: "pi_1", AmountNanoUsd: usd, Store: true},
	} {
		if _, err := ComputeCreditLot(env, t.Context(), settings, request); !errors.Is(err, ErrComputeLedgerArgs) {
			t.Errorf("%s: %v", label, err)
		}
	}
	if _, err := ComputeReverseLot(env, t.Context(), settings, &ComputeReverseRequest{Market: model.ComputeMarketPromotion, MarketRef: "r"}); !errors.Is(err, ErrComputeLedgerArgs) {
		t.Errorf("a promotion reversed: %v", err)
	}
	if env.db.callCount != 0 {
		t.Fatal("the database was asked")
	}
}
