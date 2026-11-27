//go:build !ios_extension && !sidecar_http

package sidecar_test

// The seal between a device and searchsigner (SRCH-M13-01; compute-plan-websearch-seal-format): the payee opens only
// to the signer's key under the binding the device sealed it with, and the authorization sealed back opens only under
// the device's own request, to the same bytes each time.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A test signer key pair from a label.
func testWebSearchSignerKey(t *testing.T, label string) hpke.PrivateKey {
	t.Helper()
	key, err := hpke.MLKEM768X25519().DeriveKeyPair(testSyntheticBytes(label, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testWebSearchPayee() *protocol.SearchPayee {
	return &protocol.SearchPayee{PayTo: testSyntheticBytes("test gateway payee", 20), Nonce: testSyntheticBytes("test device nonce", 32)}
}

func testWebSearchBinding(t *testing.T) *sidecar.WebSearchSealBinding {
	t.Helper()
	asset, err := sidecar.WebSearchAddressOf(testSyntheticBytes("test usdc contract", 20))
	if err != nil {
		t.Fatal(err)
	}
	return &sidecar.WebSearchSealBinding{Amount: 10000, Asset: asset, Network: "eip155:84532"}
}

// The device's payee opens at the signer to the same payee, and the authorization the signer seals back opens at the
// device to the same authorization; nothing of the wrong sizes or under another suite is sealed.
func TestWebSearchSealRoundTrip(t *testing.T) {
	settings := sidecar.DefaultWebSearchSettings()
	signerKey := testWebSearchSignerKey(t, "test signer key")
	binding := testWebSearchBinding(t)
	payee := testWebSearchPayee()
	sealed, deviceKey, err := sidecar.WebSearchSealPayee(signerKey.PublicKey(), payee, binding, settings)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, payee.PayTo) || bytes.Contains(sealed, payee.Nonce) {
		t.Fatal("the sealed bytes hold the payee or the nonce")
	}
	opened, signerAnswerKey, err := sidecar.WebSearchOpenPayee(signerKey, sealed, binding, settings)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(opened, payee) {
		t.Fatalf("opened %v, want %v", opened, payee)
	}
	authorization := testWebSearchAuthorization(10000, 1767225600)
	authorization.To = payee.PayTo
	authorization.Nonce = payee.Nonce
	authorization.Signature = testSyntheticBytes("test signature", 65)
	answer, err := sidecar.WebSearchSealAuthorization(signerAnswerKey, authorization)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(answer, payee.PayTo) || bytes.Contains(answer, payee.Nonce) {
		t.Fatal("the sealed answer holds the payee or the nonce")
	}
	back, err := sidecar.WebSearchOpenAuthorization(deviceKey, answer)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(back, authorization) {
		t.Fatalf("the answer opened to %v, want %v", back, authorization)
	}

	for i, planted := range []*protocol.SearchPayee{
		nil,
		{PayTo: payee.PayTo[:19], Nonce: payee.Nonce},
		{PayTo: payee.PayTo, Nonce: payee.Nonce[:16]},
		{PayTo: append(bytes.Clone(payee.PayTo), 0), Nonce: payee.Nonce},
	} {
		if _, _, err := sidecar.WebSearchSealPayee(signerKey.PublicKey(), planted, binding, settings); !errors.Is(err, sidecar.ErrWebSearchSealArgs) {
			t.Errorf("planted payee %d: %v", i, err)
		}
	}
	other, err := hpke.DHKEM(ecdh.X25519()).GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sidecar.WebSearchSealPayee(other.PublicKey(), payee, binding, settings); !errors.Is(err, sidecar.ErrWebSearchSealArgs) {
		t.Errorf("a key of another suite: %v", err)
	}
	if _, _, err := sidecar.WebSearchSealPayee(signerKey.PublicKey(), payee, &sidecar.WebSearchSealBinding{Amount: 1}, settings); !errors.Is(err, sidecar.ErrWebSearchSealArgs) {
		t.Errorf("a binding with no network: %v", err)
	}
}

// A sealed payee moved to another amount, asset or network does not open, nor under another signer key, nor with a
// byte changed: so the broker, relaying it, can neither read it nor move it.
func TestWebSearchSealRefusesMovedAad(t *testing.T) {
	settings := sidecar.DefaultWebSearchSettings()
	signerKey := testWebSearchSignerKey(t, "test signer key")
	binding := testWebSearchBinding(t)
	sealed, _, err := sidecar.WebSearchSealPayee(signerKey.PublicKey(), testWebSearchPayee(), binding, settings)
	if err != nil {
		t.Fatal(err)
	}
	otherAsset, _ := sidecar.WebSearchAddressOf(testSyntheticBytes("another contract", 20))
	moved := []*sidecar.WebSearchSealBinding{
		{Amount: binding.Amount + 1, Asset: binding.Asset, Network: binding.Network},
		{Amount: 15000, Asset: binding.Asset, Network: binding.Network},
		{Amount: binding.Amount, Asset: otherAsset, Network: binding.Network},
		{Amount: binding.Amount, Asset: binding.Asset, Network: "eip155:1"},
	}
	for i, planted := range moved {
		if _, _, err := sidecar.WebSearchOpenPayee(signerKey, sealed, planted, settings); !errors.Is(err, sidecar.ErrWebSearchSealInvalid) {
			t.Errorf("moved %d opened: %v", i, err)
		}
	}
	if _, _, err := sidecar.WebSearchOpenPayee(testWebSearchSignerKey(t, "another signer key"), sealed, binding, settings); !errors.Is(err, sidecar.ErrWebSearchSealInvalid) {
		t.Errorf("another key opened it: %v", err)
	}
	for _, at := range []int{0, 1119, 1120, len(sealed) - 1} {
		planted := bytes.Clone(sealed)
		planted[at] ^= 0x01
		if _, _, err := sidecar.WebSearchOpenPayee(signerKey, planted, binding, settings); !errors.Is(err, sidecar.ErrWebSearchSealInvalid) {
			t.Errorf("a byte changed at %d opened: %v", at, err)
		}
	}
	for _, planted := range [][]byte{nil, sealed[:1120], sealed[:len(sealed)-1]} {
		if _, _, err := sidecar.WebSearchOpenPayee(signerKey, planted, binding, settings); !errors.Is(err, sidecar.ErrWebSearchSealInvalid) {
			t.Errorf("%d bytes opened: %v", len(planted), err)
		}
	}
}

// The same sealed payee always yields the same answer bytes, however often the signer opens it, and another request's
// answer does not open under this one's key, nor an answer changed by a byte.
func TestWebSearchSealedAnswerDeterministic(t *testing.T) {
	settings := sidecar.DefaultWebSearchSettings()
	signerKey := testWebSearchSignerKey(t, "test signer key")
	binding := testWebSearchBinding(t)
	payee := testWebSearchPayee()
	sealed, deviceKey, err := sidecar.WebSearchSealPayee(signerKey.PublicKey(), payee, binding, settings)
	if err != nil {
		t.Fatal(err)
	}
	authorization := testWebSearchAuthorization(10000, 1767225600)
	authorization.Signature = testSyntheticBytes("test signature", 65)
	answers := [][]byte{}
	for range 3 {
		_, answerKey, err := sidecar.WebSearchOpenPayee(signerKey, sealed, binding, settings)
		if err != nil {
			t.Fatal(err)
		}
		answer, err := sidecar.WebSearchSealAuthorization(answerKey, authorization)
		if err != nil {
			t.Fatal(err)
		}
		answers = append(answers, answer)
	}
	for _, answer := range answers[1:] {
		if !bytes.Equal(answer, answers[0]) {
			t.Fatal("one sealed payee yielded two answers")
		}
	}
	// another authorization under the same context takes another nonce, never the first's
	_, answerKey, _ := sidecar.WebSearchOpenPayee(signerKey, sealed, binding, settings)
	otherAuthorization := proto.Clone(authorization).(*protocol.ComputeSearchAuthorization)
	otherAuthorization.ValidAfterS += 60
	otherAuthorization.ValidBeforeS += 60
	otherAnswer, err := sidecar.WebSearchSealAuthorization(answerKey, otherAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(otherAnswer[:12], answers[0][:12]) {
		t.Fatal("two authorizations under one context share a nonce")
	}
	if opened, err := sidecar.WebSearchOpenAuthorization(deviceKey, otherAnswer); err != nil || !proto.Equal(opened, otherAuthorization) {
		t.Fatalf("the other answer opened to %v, %v", opened, err)
	}
	// another request's key opens neither
	_, otherDeviceKey, err := sidecar.WebSearchSealPayee(signerKey.PublicKey(), payee, binding, settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.WebSearchOpenAuthorization(otherDeviceKey, answers[0]); !errors.Is(err, sidecar.ErrWebSearchSealInvalid) {
		t.Errorf("another request's key opened the answer: %v", err)
	}
	for _, at := range []int{0, 11, 12, len(answers[0]) - 1} {
		planted := bytes.Clone(answers[0])
		planted[at] ^= 0x01
		if _, err := sidecar.WebSearchOpenAuthorization(deviceKey, planted); !errors.Is(err, sidecar.ErrWebSearchSealInvalid) {
			t.Errorf("an answer changed at %d opened: %v", at, err)
		}
	}
	if _, err := sidecar.WebSearchOpenAuthorization(deviceKey, answers[0][:27]); !errors.Is(err, sidecar.ErrWebSearchSealInvalid) {
		t.Errorf("a cut answer: %v", err)
	}
	if _, err := sidecar.WebSearchOpenAuthorization(nil, answers[0]); !errors.Is(err, sidecar.ErrWebSearchSealArgs) {
		t.Errorf("no key: %v", err)
	}
}
