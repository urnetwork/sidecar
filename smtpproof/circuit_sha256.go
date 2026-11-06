package smtpproof

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/consensys/gnark/frontend"
)

// SHA-256 and HMAC in R1CS, over boolean wires. This is this module's own gadget because gnark
// v0.15.0's rests on std/math/uints, which is unsound (SPEC.md 10.1). About 26,500 constraints per
// compression; a block of constants costs less, since every function folds them.

var sha256RoundConstants = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

var sha256InitialState = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// A chaining value in wires.
type circuitHashState [8]circuitWord

func hashStateConstant(values [8]uint32) circuitHashState {
	var state circuitHashState
	for i, value := range values {
		state[i] = wordConstant(value)
	}
	return state
}

func wordRotateRight(word circuitWord, count int) circuitWord {
	var rotated circuitWord
	for i := range rotated {
		rotated[i] = word[(i+count)%len(word)]
	}
	return rotated
}

func wordShiftRight(word circuitWord, count int) circuitWord {
	var shifted circuitWord
	for i := range shifted {
		if i+count < len(word) {
			shifted[i] = word[i+count]
		} else {
			shifted[i] = uint(0)
		}
	}
	return shifted
}

func wordXor3(api frontend.API, a circuitWord, b circuitWord, c circuitWord) circuitWord {
	var out circuitWord
	for i := range out {
		out[i] = bitXor(api, bitXor(api, a[i], b[i]), c[i])
	}
	return out
}

// The compression function over a 64-octet block, big-endian as FIPS 180-4 has it.
func sha256Compress(api frontend.API, state circuitHashState, block []circuitByte) circuitHashState {
	var schedule [64]circuitWord
	for i := range 16 {
		for octet := range 4 {
			copy(schedule[i][8*octet:8*octet+8], block[4*i+3-octet][:])
		}
	}
	for i := 16; i < 64; i++ {
		v := schedule[i-15]
		s0 := wordXor3(api, wordRotateRight(v, 7), wordRotateRight(v, 18), wordShiftRight(v, 3))
		v = schedule[i-2]
		s1 := wordXor3(api, wordRotateRight(v, 17), wordRotateRight(v, 19), wordShiftRight(v, 10))
		schedule[i] = wordFromSum(api, api.Add(wordValue(api, schedule[i-16]), wordValue(api, s0), wordValue(api, schedule[i-7]), wordValue(api, s1)), 34)
	}
	a, b, c, d := state[0], state[1], state[2], state[3]
	e, f, g, h := state[4], state[5], state[6], state[7]
	for i := range 64 {
		s1 := wordXor3(api, wordRotateRight(e, 6), wordRotateRight(e, 11), wordRotateRight(e, 25))
		var choice circuitWord
		for j := range choice {
			// g + e(f - g): each result is a bit because its inputs are, and it feeds only a sum. f - g
			// is not itself a bit, so this is a plain product, which gnark folds when an operand is constant
			choice[j] = api.Add(g[j], api.Mul(e[j], api.Sub(f[j], g[j])))
		}
		s0 := wordXor3(api, wordRotateRight(a, 2), wordRotateRight(a, 13), wordRotateRight(a, 22))
		var majority circuitWord
		for j := range majority {
			// bc + a(b + c - 2bc), two constraints
			product := api.Mul(b[j], c[j])
			majority[j] = api.Add(product, api.Mul(a[j], api.Sub(api.Add(b[j], c[j]), api.Mul(product, 2))))
		}
		t1 := api.Add(wordValue(api, h), wordValue(api, s1), wordValue(api, choice), sha256RoundConstants[i], wordValue(api, schedule[i]))
		newE := wordFromSum(api, api.Add(t1, wordValue(api, d)), 35)
		newA := wordFromSum(api, api.Add(t1, wordValue(api, s0), wordValue(api, majority)), 35)
		h, g, f, e, d, c, b, a = g, f, e, newE, c, b, a, newA
	}
	var out circuitHashState
	for i, word := range [8]circuitWord{a, b, c, d, e, f, g, h} {
		out[i] = wordFromSum(api, api.Add(wordValue(api, state[i]), wordValue(api, word)), 33)
	}
	return out
}

// The FIPS 180-4 padding for a message of totalBytes octets, appended to what remains of it.
func sha256Padded(tail []circuitByte, totalBytes int) []circuitByte {
	padded := append([]circuitByte{}, tail...)
	padded = append(padded, byteConstant(0x80))
	for len(padded)%sha256.BlockSize != sha256.BlockSize-8 {
		padded = append(padded, byteConstant(0))
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(totalBytes)*8)
	return append(padded, bytesConstant(length[:])...)
}

// Runs a padded message through the compression function.
func sha256Absorb(api frontend.API, state circuitHashState, padded []circuitByte) circuitHashState {
	for offset := 0; offset < len(padded); offset += sha256.BlockSize {
		state = sha256Compress(api, state, padded[offset:offset+sha256.BlockSize])
	}
	return state
}

// The state as the 32 octets of a digest.
func hashStateBytes(state circuitHashState) []circuitByte {
	octets := make([]circuitByte, 0, sha256.Size)
	for _, word := range state {
		for octet := 3; 0 <= octet; octet -= 1 {
			var value circuitByte
			copy(value[:], word[8*octet:8*octet+8])
			octets = append(octets, value)
		}
	}
	return octets
}

// SHA-256 of a message whose length is fixed in the circuit.
func sha256Sum(api frontend.API, message []circuitByte) []circuitByte {
	return hashStateBytes(sha256Absorb(api, hashStateConstant(sha256InitialState), sha256Padded(message, len(message))))
}

// An HMAC-SHA-256 key's two pad states, computed once: each costs a compression, and TLS's key
// schedule reuses them across the labels of one secret.
type circuitHmacKey struct {
	inner circuitHashState
	outer circuitHashState
}

func newCircuitHmacKey(api frontend.API, key []circuitByte) *circuitHmacKey {
	pad := func(value byte) circuitHashState {
		block := make([]circuitByte, sha256.BlockSize)
		for i := range block {
			if i < len(key) {
				for bit := range block[i] {
					block[i][bit] = bitXor(api, key[i][bit], uint((value>>bit)&1))
				}
			} else {
				block[i] = byteConstant(value)
			}
		}
		return sha256Compress(api, hashStateConstant(sha256InitialState), block)
	}
	return &circuitHmacKey{inner: pad(0x36), outer: pad(0x5c)}
}

// HMAC of a message, from the key's pad states.
func (self *circuitHmacKey) sum(api frontend.API, message []circuitByte) []circuitByte {
	inner := sha256Absorb(api, self.inner, sha256Padded(message, sha256.BlockSize+len(message)))
	digest := hashStateBytes(inner)
	return hashStateBytes(sha256Absorb(api, self.outer, sha256Padded(digest, sha256.BlockSize+sha256.Size)))
}

// HKDF-Expand-Label for an output of at most one hash length, which is one HMAC of the label
// structure and a counter octet. context's length is fixed in the circuit.
func (self *circuitHmacKey) expandLabel(api frontend.API, label string, context []circuitByte, size int) []circuitByte {
	// the structure around context is constant; only context can be wires
	head := tlsExpandLabelInfo(label, nil, size)
	head[len(head)-1] = byte(len(context))
	info := bytesConstant(head)
	info = append(info, context...)
	info = append(info, byteConstant(1))
	return self.sum(api, info)[:size]
}
