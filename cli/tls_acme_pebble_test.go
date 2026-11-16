// The ordering desktop's CA client against Pebble (TLS-M6-05; T2, §22.9, 5% bad nonces): an account made and found
// again by its key alone, one order for one custom host taken through DNS-01 to a chain on the device's key, its
// renewal window, a revocation, a dead order after its authorization is deactivated, and the account key changed
// with the old key no longer the account's. Pebble neither reuses orders nor limits, so those are the scripted CA's.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestTlsAcmeClientOrdersOnPebble(t *testing.T) {
	pebble := sidecartest.StartPebble(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	settings := sidecar.DefaultTlsCustomSettings()
	settings.Profile = sidecartest.PebbleProfileTlsServer
	client, err := newUrTlsAcmeClient(pebble.DirectoryUrl, pebble.HttpClient, settings)
	if err != nil {
		t.Fatal(err)
	}
	accountKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	accountUri, err := client.NewAccount(ctx, accountKey, false)
	if err != nil || accountUri == "" {
		t.Fatalf("%q, %v", accountUri, err)
	}
	if again, err := client.NewAccount(ctx, accountKey, true); err != nil || again != accountUri {
		t.Fatalf("onlyReturnExisting: %q, %v", again, err)
	}
	if err := client.Account(ctx, accountKey, accountUri); err != nil {
		t.Fatal(err)
	}
	// one order, by DNS-01
	host := "www.customer.example"
	order, err := client.NewOrder(ctx, accountKey, accountUri, host, settings.Profile, nil)
	if err != nil || order.Status != sidecar.TlsAcmeStatusPending || len(order.Authorizations) != 1 {
		t.Fatalf("%+v, %v", order, err)
	}
	authorization, err := client.Authorization(ctx, accountKey, accountUri, order.Authorizations[0])
	if err != nil {
		t.Fatal(err)
	}
	var challenge *sidecar.TlsAcmeChallenge
	for _, offered := range authorization.Challenges {
		if offered.Type == sidecar.TlsAcmeChallengeDns {
			challenge = offered
		}
	}
	if challenge == nil {
		t.Fatalf("no dns-01 among %+v", authorization.Challenges)
	}
	keyAuthorization, err := client.KeyAuthorization(accountKey, challenge.Token)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(keyAuthorization))
	if _, err := pebble.Dns.WriteAcmeChallenge(ctx, host, []string{base64.RawURLEncoding.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	if err := client.Challenge(ctx, accountKey, accountUri, challenge.Url); err != nil {
		t.Fatal(err)
	}
	// Pebble validates and issues on its own goroutines with no sleep (PEBBLE_VA_NOSLEEP): each read is a request,
	// and the context's deadline fails a run that never gets there
	poll := func(read func() (string, error), want string) {
		t.Helper()
		for ctx.Err() == nil {
			status, err := read()
			if err == nil && status == want {
				return
			}
		}
		t.Fatalf("never %s: %v", want, ctx.Err())
	}
	poll(func() (string, error) {
		read, err := client.Order(ctx, accountKey, accountUri, order.Url)
		if err != nil {
			return "", err
		}
		order = read
		return read.Status, nil
	}, sidecar.TlsAcmeStatusReady)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Finalize(ctx, accountKey, accountUri, order, csr); err != nil {
		t.Fatal(err)
	}
	poll(func() (string, error) {
		read, err := client.Order(ctx, accountKey, accountUri, order.Url)
		if err != nil {
			return "", err
		}
		order = read
		return read.Status, nil
	}, sidecar.TlsAcmeStatusValid)
	chain, err := client.Certificate(ctx, accountKey, accountUri, order.Certificate)
	if err != nil || len(chain) == 0 {
		t.Fatalf("%d certificates, %v", len(chain), err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	deviceSpki, _ := x509.MarshalPKIXPublicKey(&deviceKey.PublicKey)
	if string(leaf.RawSubjectPublicKeyInfo) != string(deviceSpki) || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != host {
		t.Fatalf("a chain for %v on another key", leaf.DNSNames)
	}
	if _, _, err := client.RenewalInfo(ctx, chain[0]); err != nil {
		t.Logf("Pebble gave no renewal window: %v", err)
	}
	if err := client.Revoke(ctx, accountKey, accountUri, chain[0], 5); err != nil {
		t.Fatal(err)
	}
	if reason, revoked := pebble.RevocationReason(chain[0]); !revoked || reason != 5 {
		t.Fatalf("revoked %v with %d", revoked, reason)
	}
	// a second order killed by deactivating its authorization is dead at the CA (A13)
	killed, err := client.NewOrder(ctx, accountKey, accountUri, "api.customer.example", settings.Profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.DeactivateAuthorization(ctx, accountKey, accountUri, killed.Authorizations[0]); err != nil {
		t.Fatal(err)
	}
	if read, err := client.Order(ctx, accountKey, accountUri, killed.Url); err == nil && read.Status != sidecar.TlsAcmeStatusInvalid && read.Status != sidecar.TlsAcmeStatusDeactivated {
		t.Fatalf("a killed order: %+v", read)
	}
	// the key change: the new key is the account's, the old one no longer
	nextKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := client.KeyChange(ctx, accountUri, accountKey, nextKey); err != nil {
		t.Fatal(err)
	}
	if err := client.Account(ctx, nextKey, accountUri); err != nil {
		t.Fatalf("the new key: %v", err)
	}
	err = client.Account(ctx, accountKey, accountUri)
	var problem *sidecar.TlsAcmeProblem
	if err == nil || (!errors.As(err, &problem) && !errors.Is(err, sidecar.ErrTlsAcmeGone)) {
		t.Fatalf("the old key: %v", err)
	}
}
