//go:build !ios_extension && !sidecar_http

// The seal between a device and searchsigner (DESIGN-COMPUTE §21.5, D-SRCH-2, D-SRCH-12, IC-15; SRCH-M13-01;
// compute-plan-websearch-seal-format, QD-1383): the device seals its payee and nonce to the signer's key, and the signer
// seals the authorization it signs back under the same request, so the broker, which relays both, reads neither.
//
//	suite      HPKE base mode, the repository's one suite: X-Wing (MLKEM768X25519), HKDF-SHA256, AES-128-GCM, as
//	           evs_slot.go's deposit keys take it
//	payee      SearchPayee, deterministic protobuf, sealed single-shot by HPKE to the signer's key in the policy's
//	           search line, info "ur websearch payee v1": the encapsulation, then the ciphertext
//	binding    the payee's AAD, which the device and the signer both hold and the broker cannot change: the challenge's
//	           network (one byte of length, then its CAIP-2 name), its asset's 20 bytes and its amount, 8 bytes
//	           big-endian. The signer opens with the amount the broker admitted and the policy's asset and network, so
//	           a payee moved to another amount or asset does not open
//	answer     the signer's ComputeSearchAuthorization, deterministic protobuf, sealed under 32 bytes the same HPKE
//	           context exports, label "ur websearch authorization v1": an AES-128-GCM key, the first 16, and a nonce
//	           key, the last 16; the nonce is the first 12 bytes of HMAC-SHA256 under the nonce key of the plaintext,
//	           sent before the ciphertext. The same sealed payee and the same authorization always seal to the same
//	           bytes, which a retry under one request id and attempt relies on, and two different authorizations under
//	           one context never share a nonce. The opener holds the nonce to its plaintext's
//
// The answer's key is the "fresh key the device sends in the request" of compute-plan-websearch-seal-format's answer:
// the device's encapsulation is drawn fresh for each request, and only the device and the signer hold what it opens.
// That answer also named the broker's ticket as the AAD, which the device never learns; binding the request id and
// attempt, as the plan wrote, would give the signer the inputs of the broker's durable operation key (D-BAL-14), a
// second key between the two where D-SRCH-12 allows the ticket alone. The binding above is
// srch-m13-01-websearch-seal-binding's answer (QD-1453). The bytes stay proposed until the signed policy carries a
// search line (G-SRCH-parallel), before which no device seals a payee, and the external review of searchsigner reads
// them.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The seal's labels and sizes: identifiers and cryptographic constants of the format.
const (
	webSearchPayeeHpkeInfo        = "ur websearch payee v1"
	webSearchAuthorizationLabel   = "ur websearch authorization v1"
	webSearchAnswerAeadKeyCount   = 16
	webSearchAnswerNonceKeyCount  = 16
	webSearchAnswerNonceByteCount = 12
)

var (
	// A seal that does not open: another key, another binding, or bytes changed. Nothing in it is read.
	ErrWebSearchSealInvalid = errors.New("web search: the seal does not open")
	// What would be sealed is not of its format: a payee that is not 20 bytes, a nonce of the wrong size, a key that is
	// not X-Wing.
	ErrWebSearchSealArgs = errors.New("web search: nothing of the seal's format to seal")
)

// What a payee's seal binds besides the signer's key (see the file header's binding row): the challenge's facts, which
// the device's request names and the signer reads from the broker's request and the policy.
type WebSearchSealBinding struct {
	// In USDC's 6 decimals.
	Amount  uint64
	Asset   WebSearchAddress
	Network string
}

// The binding's bytes.
func (self *WebSearchSealBinding) aad(settings *WebSearchSettings) ([]byte, error) {
	if self == nil || self.Network == "" || settings.NetworkMaxByteCount < len(self.Network) || 0xff < len(self.Network) {
		return nil, fmt.Errorf("%w: a binding without a network of at most %d bytes", ErrWebSearchSealArgs, settings.NetworkMaxByteCount)
	}
	aad := make([]byte, 0, 1+len(self.Network)+len(self.Asset)+8)
	aad = append(aad, byte(len(self.Network)))
	aad = append(aad, self.Network...)
	aad = append(aad, self.Asset[:]...)
	return binary.BigEndian.AppendUint64(aad, self.Amount), nil
}

// The key one request's answer is sealed under, which the device keeps from its seal and the signer from its open.
// Never logged or sent.
type WebSearchAnswerKey struct {
	aeadKey  []byte
	nonceKey []byte
}

// The answer key the context exports.
func webSearchAnswerKeyOf(export func(label string, length int) ([]byte, error)) (*WebSearchAnswerKey, error) {
	secret, err := export(webSearchAuthorizationLabel, webSearchAnswerAeadKeyCount+webSearchAnswerNonceKeyCount)
	if err != nil {
		return nil, fmt.Errorf("%w: the answer key does not export: %v", ErrWebSearchSealInvalid, err)
	}
	testHookSecret("websearch_answer_key", secret)
	return &WebSearchAnswerKey{aeadKey: secret[:webSearchAnswerAeadKeyCount], nonceKey: secret[webSearchAnswerAeadKeyCount:]}, nil
}

// Whether payee's fields are of their sizes.
func webSearchPayeeWhole(payee *protocol.SearchPayee, settings *WebSearchSettings) bool {
	return payee != nil && len(payee.GetPayTo()) == webSearchAddressByteCount && len(payee.GetNonce()) == settings.NonceByteCount
}

// The device's seal of payee to the signer's key under binding: its bytes, which the request carries, and the key the
// signer's answer opens under.
func WebSearchSealPayee(signerKey hpke.PublicKey, payee *protocol.SearchPayee, binding *WebSearchSealBinding, settings *WebSearchSettings) ([]byte, *WebSearchAnswerKey, error) {
	if signerKey == nil || signerKey.KEM().ID() != hpke.MLKEM768X25519().ID() {
		return nil, nil, fmt.Errorf("%w: a signer key that is not X-Wing", ErrWebSearchSealArgs)
	}
	if !webSearchPayeeWhole(payee, settings) {
		return nil, nil, fmt.Errorf("%w: a payee that is not 20 bytes or a nonce that is not %d", ErrWebSearchSealArgs, settings.NonceByteCount)
	}
	aad, err := binding.aad(settings)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.SearchPayee{PayTo: payee.GetPayTo(), Nonce: payee.GetNonce()})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrWebSearchSealArgs, err)
	}
	encapsulation, sender, err := hpke.NewSender(signerKey, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(webSearchPayeeHpkeInfo))
	if err != nil {
		return nil, nil, fmt.Errorf("web search: payee hpke setup: %w", err)
	}
	ciphertext, err := sender.Seal(aad, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("web search: payee hpke seal: %w", err)
	}
	answerKey, err := webSearchAnswerKeyOf(sender.Export)
	if err != nil {
		return nil, nil, err
	}
	return append(encapsulation, ciphertext...), answerKey, nil
}

// The signer's open of a sealed payee under binding: the payee, its sizes held, and the key its answer is sealed under.
// ErrWebSearchSealInvalid for anything that does not open, or opens to a payee not of its sizes.
func WebSearchOpenPayee(signerKey hpke.PrivateKey, sealed []byte, binding *WebSearchSealBinding, settings *WebSearchSettings) (*protocol.SearchPayee, *WebSearchAnswerKey, error) {
	if signerKey == nil || signerKey.KEM().ID() != hpke.MLKEM768X25519().ID() {
		return nil, nil, fmt.Errorf("%w: no X-Wing signer key", ErrWebSearchSealArgs)
	}
	aad, err := binding.aad(settings)
	if err != nil {
		return nil, nil, err
	}
	if len(sealed) <= gkmXWingEncapsulationByteCount {
		return nil, nil, fmt.Errorf("%w: %d bytes", ErrWebSearchSealInvalid, len(sealed))
	}
	recipient, err := hpke.NewRecipient(sealed[:gkmXWingEncapsulationByteCount], signerKey, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(webSearchPayeeHpkeInfo))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: setup", ErrWebSearchSealInvalid)
	}
	plaintext, err := recipient.Open(aad, sealed[gkmXWingEncapsulationByteCount:])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the payee does not open", ErrWebSearchSealInvalid)
	}
	payee := &protocol.SearchPayee{}
	if err := proto.Unmarshal(plaintext, payee); err != nil || !webSearchPayeeWhole(payee, settings) {
		return nil, nil, fmt.Errorf("%w: the payee is not of its sizes", ErrWebSearchSealInvalid)
	}
	answerKey, err := webSearchAnswerKeyOf(recipient.Export)
	if err != nil {
		return nil, nil, err
	}
	return payee, answerKey, nil
}

// The AEAD the answer key opens.
func (self *WebSearchAnswerKey) aead() (cipher.AEAD, error) {
	if self == nil || len(self.aeadKey) != webSearchAnswerAeadKeyCount || len(self.nonceKey) != webSearchAnswerNonceKeyCount {
		return nil, fmt.Errorf("%w: no answer key", ErrWebSearchSealArgs)
	}
	block, err := aes.NewCipher(self.aeadKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// The nonce an answer's plaintext takes: its HMAC under the nonce key, cut to GCM's 12 bytes.
func (self *WebSearchAnswerKey) nonce(plaintext []byte) []byte {
	mac := hmac.New(sha256.New, self.nonceKey)
	mac.Write(plaintext)
	return mac.Sum(nil)[:webSearchAnswerNonceByteCount]
}

// The signer's seal of authorization under key: the nonce, then the ciphertext (see the file header's answer row).
func WebSearchSealAuthorization(key *WebSearchAnswerKey, authorization *protocol.ComputeSearchAuthorization) ([]byte, error) {
	aead, err := key.aead()
	if err != nil {
		return nil, err
	}
	if authorization == nil {
		return nil, fmt.Errorf("%w: no authorization", ErrWebSearchSealArgs)
	}
	plaintext, err := proto.MarshalOptions{Deterministic: true}.Marshal(authorization)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWebSearchSealArgs, err)
	}
	nonce := key.nonce(plaintext)
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// The device's open of the signer's answer under key. ErrWebSearchSealInvalid for anything that does not open, or whose
// nonce is not its plaintext's.
func WebSearchOpenAuthorization(key *WebSearchAnswerKey, sealed []byte) (*protocol.ComputeSearchAuthorization, error) {
	aead, err := key.aead()
	if err != nil {
		return nil, err
	}
	if len(sealed) < webSearchAnswerNonceByteCount+aead.Overhead() {
		return nil, fmt.Errorf("%w: an answer of %d bytes", ErrWebSearchSealInvalid, len(sealed))
	}
	nonce, ciphertext := sealed[:webSearchAnswerNonceByteCount], sealed[webSearchAnswerNonceByteCount:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: the answer does not open", ErrWebSearchSealInvalid)
	}
	if subtle.ConstantTimeCompare(nonce, key.nonce(plaintext)) != 1 {
		return nil, fmt.Errorf("%w: the answer's nonce is not its own", ErrWebSearchSealInvalid)
	}
	authorization := &protocol.ComputeSearchAuthorization{}
	if err := proto.Unmarshal(plaintext, authorization); err != nil {
		return nil, fmt.Errorf("%w: the answer does not read", ErrWebSearchSealInvalid)
	}
	return authorization, nil
}
