//go:build !ios_extension && !sidecar_http

// The cache salts (DESIGN-COMPUTE §6.6, Q-INFER-3, R2-12; INFER-M12-02): the first line a device writes in a remote
// call's system text, so a prompt prefix shared with anyone else never matches theirs in a provider's shared cache.
// Each derives from a cache secret (infer_cache_secret.go): the member's S_m, or a tagged sidecar's own, or a device's
// own while it holds no copy of the member's.
//
//	TEE path     [ur:<32 hex>], the hex of 16 bytes of HKDF-SHA256(secret, info
//	             "urnetwork-sidecar-v1/compute-cache-salt" ‖ provider_id), per member and provider: the member's runs on
//	             each of their devices keep their cache hits, and Chutes, which ignores a client's cache_salt (issue #78),
//	             holds them apart from every other account's
//	direct path  the same line of HKDF-SHA256(secret, info "urnetwork-sidecar-v1/compute-cache-salt-direct" ‖ run_id),
//	             per run, since there the provider and its machines read it: cache hits stay within a conversation and
//	             no value the device adds links one run to the next; a gateway call takes the run §8.9 records it in,
//	             one with no run handle the session its headers name, else a fresh random salt per call
//
// HKDF is RFC 5869's with no salt, the secret its input keying material and its info the label's bytes followed by the
// provider's slug or the run's (or session's) 16 id bytes. Nothing here derives from K_sock or a member id, which other
// sidecars hold, so no other member derives a salt of the member's from a run id the Team's directory announces
// (DESIGN §16.11). The line is the system text's first line, never appended (§6.6).
//
// Package-level functions, safe for concurrent use. testHookSecret sees every salt derived.

package sidecar

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// The line's frame, the HKDF info labels and the salt's size: identifiers and cryptographic constants of §6.6's
// format, which change only with the format's version in the labels.
const (
	inferCacheSaltLinePrefix = "[ur:"
	inferCacheSaltLineSuffix = "]"
	inferCacheSaltTeeInfo    = "urnetwork-sidecar-v1/compute-cache-salt"
	inferCacheSaltDirectInfo = "urnetwork-sidecar-v1/compute-cache-salt-direct"
	// 16 bytes, 32 hex characters in the line.
	inferCacheSaltByteCount = 16
)

// A salt asked of a secret that is no cache secret, or for a provider that is no slug.
var errInferCacheSalt = errors.New("cache salt refused")

// The TEE path's line for a call to the provider of slug providerId: [ur:<32 hex>] of HKDF-SHA256(secret, info
// "urnetwork-sidecar-v1/compute-cache-salt" ‖ providerId).
func inferCacheSaltTee(secret []byte, providerId string) (string, error) {
	if len(secret) != inferCacheSecretByteCount {
		return "", fmt.Errorf("%w: a secret of %d bytes", errInferCacheSalt, len(secret))
	}
	if !inferValidProvider(providerId) {
		return "", fmt.Errorf("%w: a provider that is no slug", errInferCacheSalt)
	}
	salt, err := hkdf.Key(sha256.New, secret, nil, inferCacheSaltTeeInfo+providerId, inferCacheSaltByteCount)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errInferCacheSalt, err)
	}
	testHookSecret("cache_salt_tee", salt)
	return inferCacheSaltLine(salt), nil
}

// The direct path's line for a call bound to scopeId, the run the call is recorded in or, for a gateway call with no
// run handle, the session its headers name: [ur:<32 hex>] of HKDF-SHA256(secret, info
// "urnetwork-sidecar-v1/compute-cache-salt-direct" ‖ the id's 16 bytes). A nil scopeId, a call bound to neither, takes
// a fresh salt of random's, which links it to no other call.
func inferCacheSaltDirect(secret []byte, scopeId *Id, random io.Reader) (string, error) {
	if len(secret) != inferCacheSecretByteCount {
		return "", fmt.Errorf("%w: a secret of %d bytes", errInferCacheSalt, len(secret))
	}
	var salt []byte
	if scopeId == nil {
		salt = make([]byte, inferCacheSaltByteCount)
		if _, err := io.ReadFull(random, salt); err != nil {
			return "", fmt.Errorf("%w: no fresh salt: %w", errInferCacheSalt, err)
		}
	} else {
		var err error
		salt, err = hkdf.Key(sha256.New, secret, nil, inferCacheSaltDirectInfo+string(scopeId.Bytes()), inferCacheSaltByteCount)
		if err != nil {
			return "", fmt.Errorf("%w: %w", errInferCacheSalt, err)
		}
	}
	testHookSecret("cache_salt_direct", salt)
	return inferCacheSaltLine(salt), nil
}

// [ur:<hex of salt>].
func inferCacheSaltLine(salt []byte) string {
	return inferCacheSaltLinePrefix + hex.EncodeToString(salt) + inferCacheSaltLineSuffix
}
