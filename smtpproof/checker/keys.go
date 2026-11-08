package checker

import (
	"crypto/aes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
)

// The TLS key schedules and keystreams Z1 and Z2 name (SPEC.md section 7), from RFC 8446 §7 and
// RFC 5246 §5, §6.3 and §7.4.9.

const (
	versionTls12 uint16 = 0x0303
	versionTls13 uint16 = 0x0304

	suiteAes128GcmSha256           uint16 = 0x1301
	suiteChacha20Poly1305Sha256    uint16 = 0x1303
	suiteEcdheRsaAes128GcmSha256   uint16 = 0xc02f
	suiteEcdheEcdsaAes128GcmSha256 uint16 = 0xc02b

	secretBytes = 32
	tagBytes    = 16
	// 1.2's explicit nonce, carried in each record.
	explicitNonceBytes = 8
)

// HKDF-Expand-Label with SHA-256 (RFC 8446 §7.1).
func expandLabel(secret []byte, label string, context []byte, size int) []byte {
	info := []byte{byte(size >> 8), byte(size), byte(len("tls13 ") + len(label))}
	info = append(info, "tls13 "+label...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out, err := hkdf.Expand(sha256.New, secret, string(info), size)
	if err != nil {
		panic(err)
	}
	return out
}

func hmacSha256(key []byte, message ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, part := range message {
		mac.Write(part)
	}
	return mac.Sum(nil)
}

// MS from HS: HKDF-Extract(Derive-Secret(HS, "derived", ""), 0^32).
func masterSecret13(handshakeSecret []byte) []byte {
	empty := sha256.Sum256(nil)
	derived := expandLabel(handshakeSecret, "derived", empty[:], secretBytes)
	return hmacSha256(derived, make([]byte, secretBytes))
}

func keyBytesOf(suite uint16) int {
	if suite == suiteChacha20Poly1305Sha256 {
		return 32
	}
	return 16
}

// A 1.3 direction's key and IV from its traffic secret (RFC 8446 §7.3).
func trafficKeys13(suite uint16, secret []byte) ([]byte, []byte) {
	return expandLabel(secret, "key", nil, keyBytesOf(suite)), expandLabel(secret, "iv", nil, 12)
}

// P_SHA256 (RFC 5246 §5).
func prf12(secret []byte, label string, seed []byte, size int) []byte {
	labelSeed := append([]byte(label), seed...)
	var out []byte
	a := labelSeed
	for len(out) < size {
		a = hmacSha256(secret, a)
		out = append(out, hmacSha256(secret, a, labelSeed)...)
	}
	return out[:size]
}

// A 1.2 Finished's plaintext: its handshake header and verify_data.
func finished12(masterSecret []byte, label string, handshakeHash []byte) []byte {
	return append([]byte{20, 0, 0, 12}, prf12(masterSecret, label, handshakeHash, 12)...)
}

// The nonce of a record at a sequence number: 1.3 XORs it into the IV; 1.2 takes the salt and the
// record's own explicit nonce.
func recordNonce(version uint16, iv []byte, seq uint64, record []byte) ([]byte, error) {
	if version == versionTls13 {
		nonce := append([]byte{}, iv...)
		for i := range 8 {
			nonce[len(nonce)-1-i] ^= byte(seq >> (8 * i))
		}
		return nonce, nil
	}
	if len(record) < recordHeaderBytes+explicitNonceBytes {
		return nil, errors.New("record too short for its explicit nonce")
	}
	return append(append([]byte{}, iv...), record[recordHeaderBytes:recordHeaderBytes+explicitNonceBytes]...), nil
}

// The ciphertext a record's plaintext is XORed with: after the header, and in 1.2 the explicit nonce,
// and before the tag.
func recordCiphertext(version uint16, record []byte) ([]byte, error) {
	start := recordHeaderBytes
	if version == versionTls12 {
		start += explicitNonceBytes
	}
	if len(record) < start+tagBytes {
		return nil, errors.New("record too short for its tag")
	}
	return record[start : len(record)-tagBytes], nil
}

// The keystream for size octets under a key and nonce: AES-GCM's counter blocks from 2, or ChaCha20's
// blocks from counter 1 (RFC 5288, RFC 8439 §2.8). No tag is checked, as Z2 states.
func keystream(suite uint16, key []byte, nonce []byte, size int) ([]byte, error) {
	out := make([]byte, size)
	if suite == suiteChacha20Poly1305Sha256 {
		cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			return nil, err
		}
		cipher.SetCounter(1)
		cipher.XORKeyStream(out, out)
		return out, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	counter := make([]byte, 16)
	copy(counter, nonce)
	pad := make([]byte, 16)
	for offset, j := 0, uint32(2); offset < size; offset, j = offset+16, j+1 {
		binary.BigEndian.PutUint32(counter[12:], j)
		block.Encrypt(pad, counter)
		copy(out[offset:], pad)
	}
	return out, nil
}

// A record's plaintext under a key: its ciphertext XORed with the keystream at its sequence number.
func openRecord(version uint16, suite uint16, key []byte, iv []byte, seq uint64, record []byte) ([]byte, error) {
	ciphertext, err := recordCiphertext(version, record)
	if err != nil {
		return nil, err
	}
	nonce, err := recordNonce(version, iv, seq, record)
	if err != nil {
		return nil, err
	}
	stream, err := keystream(suite, key, nonce, len(ciphertext))
	if err != nil {
		return nil, err
	}
	for i := range stream {
		stream[i] ^= ciphertext[i]
	}
	return stream, nil
}
