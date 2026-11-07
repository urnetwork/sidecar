package smtpproof

import (
	"github.com/consensys/gnark/frontend"
)

// Z1 in the circuit (SPEC.md section 7): from a private secret and the edge's public handshake inputs
// to the keys of the connection. Nothing here leaves the circuit but what it binds.

// The keys a part uses, as wires. In 1.2 the IVs are the 4-octet salts.
type circuitKeys struct {
	clientKey []circuitByte
	clientIv  []circuitByte
	serverKey []circuitByte
	serverIv  []circuitByte
}

func assertBytesEqual(api frontend.API, a []circuitByte, b []circuitByte) {
	for i := range a {
		for bit := range a[i] {
			api.AssertIsEqual(a[i][bit], b[i][bit])
		}
	}
}

// Z1 for TLS 1.3. HS is bound to the disclosed SHTS through H_shts, which fixes it as the MX's by
// collision resistance (SPEC.md 9.2), and everything else follows from HS and the edge's H_sf.
//
// A part that opens no server record leaves the server's keys out: 21 compressions rather than 29.
func tls13CircuitKeys(api frontend.API, handshakeSecret []circuitByte, shtsHash []circuitByte, helloHash []circuitByte, finishedHash []circuitByte, keyBytes int, needServerKeys bool) *circuitKeys {
	secret := newCircuitHmacKey(api, handshakeSecret)
	shts := secret.expandLabel(api, "s hs traffic", helloHash, tlsSecretBytes)
	assertBytesEqual(api, sha256Sum(api, shts), shtsHash)

	derived := secret.expandLabel(api, "derived", bytesConstant(tlsEmptyHash()), tlsSecretBytes)
	master := newCircuitHmacKey(api, newCircuitHmacKey(api, derived).sum(api, bytesConstant(make([]byte, tlsSecretBytes))))

	traffic := func(label string) ([]circuitByte, []circuitByte) {
		secret := newCircuitHmacKey(api, master.expandLabel(api, label, finishedHash, tlsSecretBytes))
		return secret.expandLabel(api, "key", nil, keyBytes), secret.expandLabel(api, "iv", nil, tlsIv13Bytes)
	}
	keys := &circuitKeys{}
	keys.clientKey, keys.clientIv = traffic("c ap traffic")
	if needServerKeys {
		keys.serverKey, keys.serverIv = traffic("s ap traffic")
	}
	return keys
}

// The TLS 1.2 PRF, from a key's pad states (RFC 5246 §5). label is constant, seed may be wires.
func (self *circuitHmacKey) prf(api frontend.API, label string, seed []circuitByte, size int) []circuitByte {
	labelSeed := append(bytesConstant([]byte(label)), seed...)
	out := make([]circuitByte, 0, size+tlsSecretBytes)
	a := labelSeed
	for len(out) < size {
		a = self.sum(api, a)
		out = append(out, self.sum(api, append(append([]circuitByte{}, a...), labelSeed...))...)
	}
	return out[:size]
}

// Z1's public inputs for TLS 1.2, as wires. SF's explicit nonce and ciphertext open under the keys
// this derives; everything else is the edge's own (SPEC.md section 5).
type circuitInputs12 struct {
	clientRandom []circuitByte
	serverRandom []circuitByte
	// SHA-256 finished from S_ckx: the transcript hash the client's Finished signs.
	clientFinishedHash []circuitByte
	// S_ckx's chaining value.
	chaining circuitHashState
	// Two blocks holding S_ckx's unhashed tail, a gap for the client's Finished, then padding.
	resumeBase []circuitByte
	// How far into resumeBase the client's Finished goes: the tail's length, in 6 public bits.
	resumeShift []frontend.Variable
	// 1 if the padded message takes both blocks.
	resumeTwoBlocks frontend.Variable
}

// Places octets at a public offset in a longer array, by a barrel shifter whose select bits are
// public. The tail's length varies per connection, so the offset cannot be a circuit constant, and
// this costs a few thousand constraints rather than a selection at every position.
func shiftBytes(api frontend.API, octets []circuitByte, shift []frontend.Variable, size int) []circuitByte {
	current := make([]circuitByte, size)
	for i := range current {
		if i < len(octets) {
			current[i] = octets[i]
		} else {
			current[i] = byteConstant(0)
		}
	}
	for stage, selected := range shift {
		distance := 1 << stage
		next := make([]circuitByte, size)
		for i := range next {
			for bit := range next[i] {
				shifted := frontend.Variable(uint(0))
				if distance <= i {
					shifted = current[i-distance][bit]
				}
				next[i][bit] = api.Select(selected, shifted, current[i][bit])
			}
		}
		current = next
	}
	return current
}

// Z1 for TLS 1.2 (D-SMTP-21): no secret is disclosed, so master_secret is bound by the MX's own
// Finished instead. SF must open, under a key from this secret, to the verify_data this secret gives
// the relayed handshake, resumed through the client's Finished, which is itself private because it
// depends on the secret. Returns the server Finished's expected plaintext for the caller to compare
// with the record opened under the returned keys.
func tls12CircuitKeys(api frontend.API, masterSecret []circuitByte, inputs *circuitInputs12) (*circuitKeys, []circuitByte) {
	master := newCircuitHmacKey(api, masterSecret)
	seed := append(append([]circuitByte{}, inputs.serverRandom...), inputs.clientRandom...)
	keyBlock := master.prf(api, tlsLabelKeyExpansion, seed, 2*tlsAes128KeyBytes+2*tlsSalt12Bytes)
	// a 1.2 nonce is the 4-octet salt and an explicit part; the explicit part is public and enters
	// through the counter wire, so the IV's other 8 octets are zero
	salt := func(octets []circuitByte) []circuitByte {
		return append(append([]circuitByte{}, octets...), bytesConstant(make([]byte, tlsExplicitNonceBytes))...)
	}
	keys := &circuitKeys{
		clientKey: keyBlock[:tlsAes128KeyBytes],
		serverKey: keyBlock[tlsAes128KeyBytes : 2*tlsAes128KeyBytes],
		clientIv:  salt(keyBlock[2*tlsAes128KeyBytes : 2*tlsAes128KeyBytes+tlsSalt12Bytes]),
		serverIv:  salt(keyBlock[2*tlsAes128KeyBytes+tlsSalt12Bytes:]),
	}

	finishedHeader := bytesConstant([]byte{tlsHandshakeFinished, 0, 0, tlsVerifyData12Bytes})
	clientFinished := append(append([]circuitByte{}, finishedHeader...), master.prf(api, tlsLabelClientFinished, inputs.clientFinishedHash, tlsVerifyData12Bytes)...)

	// resume S_ckx over the tail and the client's Finished
	placed := shiftBytes(api, clientFinished, inputs.resumeShift, 2*sha256BlockBytes)
	blocks := make([]circuitByte, len(placed))
	for i := range blocks {
		for bit := range blocks[i] {
			// disjoint by the edge's construction of resumeBase, so a sum is a bit
			blocks[i][bit] = api.Add(inputs.resumeBase[i][bit], placed[i][bit])
		}
	}
	first := sha256Compress(api, inputs.chaining, blocks[:sha256BlockBytes])
	second := sha256Compress(api, first, blocks[sha256BlockBytes:])
	var resumed circuitHashState
	for i := range resumed {
		for bit := range resumed[i] {
			resumed[i][bit] = api.Select(inputs.resumeTwoBlocks, second[i][bit], first[i][bit])
		}
	}
	serverFinished := append(append([]circuitByte{}, finishedHeader...), master.prf(api, tlsLabelServerFinished, hashStateBytes(resumed), tlsVerifyData12Bytes)...)
	return keys, serverFinished
}
