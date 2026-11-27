//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The gateway's reasoning blob (DESIGN-COMPUTE §8.5's reasoning across turns, §24.8's reasoning row; D-GW-2; GW-M12-03):
// Codex sends each turn's reasoning items back with encrypted_content, and Claude Code its thinking blocks with a
// signature; neither is readable by an open model, and the gateway keeps no state between calls, so it fills both with
// its own sealed blob.
//
//	blob      urgw1. and base64url of a 24-byte nonce and the XChaCha20-Poly1305 seal, under the network's gateway
//	          reasoning key, of version 1, the session node that recorded the reasoning (§24.8: a replayed blob names
//	          the node it came from) and the reasoning text; the purpose is the seal's additional data
//	open      a blob opens only under the key it was sealed with: a blob from anywhere else, OpenAI's or Anthropic's
//	          own, a forged one, or one sealed on another network, is ignored, never an error, and gives the model
//	          nothing (gateway_translate.go)
//	key       32 random bytes in the network's keychain (gateway/reasoning), drawn at its first use and kept for the
//	          network's life, so blobs open across the daemon's restarts; read from the keychain at each use, never held
//	          past a call, so a lock leaves none in memory. testHookSecret runs at its draw and each read
//
// Safe for concurrent use.

package sidecar

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

// The blob's format and the key's place: identifiers and cryptographic constants.
const (
	gatewayReasoningBlobPrefix  = "urgw1."
	gatewayReasoningBlobVersion = 1
	gatewayReasoningPurpose     = "urnetwork-sidecar-v1/gateway-reasoning"
	gatewayKeysNamespace        = "gateway"
	gatewayKeyReasoning         = "reasoning"
	gatewayKeyByteCount         = chacha20poly1305.KeySize
	gatewayKeysComponentName    = "gateway_keys"
)

// The network holds no gateway key now: it is locked, or not enrolled.
var ErrGatewayKeyUnavailable = errors.New("the gateway's key is not available")

// One reasoning blob's content: the text, and the session node that recorded it.
type GatewayReasoningBlob struct {
	// The node ResponseItem answered for the reasoning item (§24.8); zero where none was recorded.
	NodeId Id
	Text   string
}

// The blob sealed under key, with a nonce from random (crypto/rand's reader when nil).
func (self *GatewayReasoningBlob) Seal(key []byte, random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	plaintext := make([]byte, 0, 1+len(self.NodeId.Bytes())+len(self.Text))
	plaintext = append(plaintext, gatewayReasoningBlobVersion)
	plaintext = append(plaintext, self.NodeId.Bytes()...)
	plaintext = append(plaintext, self.Text...)
	defer clear(plaintext)
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, plaintext, []byte(gatewayReasoningPurpose))
	return gatewayReasoningBlobPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// The blob's content where it opens under key; false for a blob from anywhere else, which is ignored.
func OpenGatewayReasoningBlob(key []byte, blob string) (*GatewayReasoningBlob, bool) {
	encoded, ok := strings.CutPrefix(blob, gatewayReasoningBlobPrefix)
	if !ok {
		return nil, false
	}
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil || len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, false
	}
	plaintext, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(gatewayReasoningPurpose))
	if err != nil {
		return nil, false
	}
	defer clear(plaintext)
	idByteCount := len(Id{})
	if len(plaintext) < 1+idByteCount || plaintext[0] != gatewayReasoningBlobVersion || !utf8.Valid(plaintext[1+idByteCount:]) {
		return nil, false
	}
	nodeId, err := IdFromBytes(plaintext[1 : 1+idByteCount])
	if err != nil {
		return nil, false
	}
	return &GatewayReasoningBlob{NodeId: nodeId, Text: string(plaintext[1+idByteCount:])}, true
}

// What gives a network's gateway keys: *Sidecar, from its keychain.
type GatewayKeyNetwork interface {
	// The 32-byte key of purpose, drawn on its first use and kept in the keychain: a copy, which the caller clears.
	GatewayKey(purpose string) ([]byte, error)
}

// Each Sidecar of the daemon's legs holds its draws of the gateway's keys behind one lock, so two first uses draw one
// key.
type gatewayKeys struct {
	drawLock sync.Mutex
}

func init() {
	registerComputeComponent(gatewayKeysComponentName, func(sidecar *Sidecar) (*gatewayKeys, error) {
		return &gatewayKeys{}, nil
	}, nil)
}

// See GatewayKeyNetwork: the key in the network's keychain under gateway/<purpose>, drawn where there is none.
func (self *Sidecar) GatewayKey(purpose string) ([]byte, error) {
	keys, err := sidecarComputeComponent[gatewayKeys](self, gatewayKeysComponentName)
	if err != nil {
		return nil, err
	}
	networkId := self.knownNetworkId()
	if self.instance == nil || networkId == nil {
		return nil, fmt.Errorf("%w: no network is enrolled", ErrGatewayKeyUnavailable)
	}
	secrets := self.instance.secrets(*networkId, gatewayKeysNamespace)
	return gatewayKeyOf(secrets, &keys.drawLock, purpose, rand.Reader)
}

// The key of purpose in secrets, drawn from random under drawLock where there is none.
func gatewayKeyOf(secrets SidecarSecrets, drawLock *sync.Mutex, purpose string, random io.Reader) ([]byte, error) {
	key, err := secrets.Get(purpose)
	if err == nil {
		if len(key) != gatewayKeyByteCount {
			clear(key)
			return nil, fmt.Errorf("%w: the keychain's %s key is not %d bytes", ErrGatewayKeyUnavailable, purpose, gatewayKeyByteCount)
		}
		testHookSecret("gateway_reasoning_key", key)
		return key, nil
	}
	if !errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, fmt.Errorf("%w: %w", ErrGatewayKeyUnavailable, err)
	}
	drawLock.Lock()
	defer drawLock.Unlock()
	// another draw may have landed while this one waited
	if key, err := secrets.Get(purpose); err == nil && len(key) == gatewayKeyByteCount {
		testHookSecret("gateway_reasoning_key", key)
		return key, nil
	}
	key = make([]byte, gatewayKeyByteCount)
	if _, err := io.ReadFull(random, key); err != nil {
		return nil, err
	}
	testHookSecret("gateway_reasoning_key", key)
	if err := secrets.Put(purpose, key); err != nil {
		clear(key)
		return nil, fmt.Errorf("%w: %w", ErrGatewayKeyUnavailable, err)
	}
	// the keychain kept its own copy
	return key, nil
}
