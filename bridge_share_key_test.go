//go:build !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	mathrand "math/rand/v2"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A keyring over a store of its own, a seeded random and a clock a test moves.
type testBridgeShareKeys struct {
	store   *testBridgeFileStore
	clock   *identityTestClock
	keyring *BridgeShareKeyring
}

func newTestBridgeShareKeys(t testing.TB) *testBridgeShareKeys {
	t.Helper()
	store := newTestBridgeFileStore()
	keyStore, err := NewBridgeShareKeyLocalStore(store)
	if err != nil {
		t.Fatal(err)
	}
	clock := newIdentityTestClock()
	clock.current = time.UnixMilli(1_800_000_000_000)
	keyring, err := NewBridgeShareKeyring(&BridgeShareKeyringArgs{Store: keyStore, Random: mathrand.NewChaCha8([32]byte{0x5e}), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return &testBridgeShareKeys{store: store, clock: clock, keyring: keyring}
}

// Create keeps one ShareKey a share: a second accept, or a resumed one, answers the key the first made, and a keyring
// opened again over the store holds it.
func TestAShareKeyIsCreatedOnce(t *testing.T) {
	keys := newTestBridgeShareKeys(t)
	ctx := context.Background()
	shareId, otherId := testConfigId("share key share"), testConfigId("share key other")
	first, err := keys.keyring.Create(ctx, shareId)
	if err != nil {
		t.Fatal(err)
	}
	second, err := keys.keyring.Create(ctx, shareId)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("a second create answered another key: %v", err)
	}
	other, err := keys.keyring.Create(ctx, otherId)
	if err != nil || bytes.Equal(first, other) {
		t.Fatalf("another share's key: %v", err)
	}
	keyStore, _ := NewBridgeShareKeyLocalStore(keys.store)
	reopened, err := NewBridgeShareKeyring(&BridgeShareKeyringArgs{Store: keyStore, Clock: keys.clock})
	if err != nil {
		t.Fatal(err)
	}
	if again, err := reopened.PublicKey(ctx, shareId); err != nil || !bytes.Equal(first, again) {
		t.Fatalf("a reopened keyring: %v", err)
	}
	shares, err := reopened.Shares(ctx)
	if err != nil || len(shares) != 2 {
		t.Fatalf("the shares held: %v, %v", shares, err)
	}
	if _, err := keys.keyring.PublicKey(ctx, testConfigId("share key absent")); !errors.Is(err, ErrBridgeShareKeyAbsent) {
		t.Errorf("a share not held: %v", err)
	}
	if _, err := keys.keyring.Create(ctx, Id{}); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("no share: %v", err)
	}
}

// Certify makes a new ShareSigner seed for every cert, each certified by the ShareKey for its generation and running
// 7 days, which a host's VerifyShareCert admits under the pinned key; a share whose key this device does not hold is
// not certified.
func TestCertifyMakesANewSeedEachCert(t *testing.T) {
	keys := newTestBridgeShareKeys(t)
	ctx := context.Background()
	shareId := testConfigId("certify share")
	sharePublicKey, err := keys.keyring.Create(ctx, shareId)
	if err != nil {
		t.Fatal(err)
	}
	first, err := keys.keyring.Certify(ctx, shareId, 7)
	if err != nil {
		t.Fatal(err)
	}
	second, err := keys.keyring.Certify(ctx, shareId, 7)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.GetSignerSeed(), second.GetSignerSeed()) || bytes.Equal(first.GetShareCert(), second.GetShareCert()) {
		t.Fatal("two certs of one generation share a seed")
	}
	nowMs := keys.clock.Now().UnixMilli()
	for _, file := range []*bridge.BridgeShareSigner{first, second} {
		cert, err := bridge.VerifyShareCert(file.GetShareCert(), &bridge.ShareCertCheck{
			ShareId: shareId.Bytes(), SharePublicKey: sharePublicKey, NowMs: nowMs, Generation: 7,
		})
		if err != nil {
			t.Fatal(err)
		}
		if cert.GetConfigGeneration() != 7 || file.GetConfigGeneration() != 7 || cert.GetNotAfterMs() != nowMs+(168*time.Hour).Milliseconds() {
			t.Errorf("the cert: %v", cert)
		}
		if !bytes.Equal(cert.GetSignerPublicKey(), ed25519.NewKeyFromSeed(file.GetSignerSeed()).Public().(ed25519.PublicKey)) {
			t.Error("the cert certifies another key than the file's seed")
		}
	}
	if _, err := keys.keyring.Certify(ctx, testConfigId("certify absent"), 7); !errors.Is(err, ErrBridgeShareKeyAbsent) {
		t.Errorf("a share not held: %v", err)
	}
	if _, err := keys.keyring.Certify(ctx, shareId, 0); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("no generation: %v", err)
	}
}
