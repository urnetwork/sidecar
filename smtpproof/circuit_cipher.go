package smtpproof

import (
	"crypto/aes"

	"github.com/consensys/gnark/frontend"
)

// AES-128 and ChaCha20 keystream in R1CS, over boolean wires, with no lookups (SPEC.md 10.1).
//
// AES costs most. Its S-box is a multilinear polynomial in the input's bits, split by nibble so that
// one product per high-nibble monomial covers all eight output bits at once: 22 products build the
// monomials and 15 combine them, then 9 constraints unpack the octet. MixColumns is multi-term
// parities (bitParity), which beat chained XORs. About 11,600 constraints per 16 octets; ChaCha20
// about 22,000 per 64, a third of AES per octet.

// The AES S-box, built from its definition, so that no table is typed in by hand.
// TestAesGadgetMatchesCryptoAes checks the result against crypto/aes.
var aesSbox = func() [256]byte {
	var table [256]byte
	// walks the multiplicative group by 3 and its inverse, so p * q = 1 throughout
	p, q := byte(1), byte(1)
	for {
		// multiply p by 3 in GF(2^8)
		high := p & 0x80
		p ^= p << 1
		if high != 0 {
			p ^= 0x1b
		}
		// divide q by 3
		q ^= q << 1
		q ^= q << 2
		q ^= q << 4
		if q&0x80 != 0 {
			q ^= 0x09
		}
		rotate := func(value byte, count uint) byte {
			return value<<count | value>>(8-count)
		}
		table[p] = q ^ rotate(q, 1) ^ rotate(q, 2) ^ rotate(q, 3) ^ rotate(q, 4) ^ 0x63
		if p == 1 {
			break
		}
	}
	table[0] = 0x63
	return table
}()

// A table of 256 values as coefficients over the monomials of two nibbles: entry [h][l] multiplies
// the product of the high bits named by h and the low bits named by l.
type nibbleCoefficients [16][16]int64

// The Möbius transform over both nibbles, which turns a table into multilinear coefficients over the
// integers. They reproduce the table exactly at every boolean input.
func newNibbleCoefficients(table func(index int) int64) *nibbleCoefficients {
	coefficients := &nibbleCoefficients{}
	for high := range 16 {
		for low := range 16 {
			coefficients[high][low] = table(high<<4 | low)
		}
	}
	for bit := range 4 {
		for high := range 16 {
			for low := range 16 {
				if low&(1<<bit) != 0 {
					coefficients[high][low] -= coefficients[high][low^(1<<bit)]
				}
			}
		}
		for high := range 16 {
			if high&(1<<bit) != 0 {
				for low := range 16 {
					coefficients[high][low] -= coefficients[high^(1<<bit)][low]
				}
			}
		}
	}
	return coefficients
}

var aesSboxCoefficients = newNibbleCoefficients(func(index int) int64 {
	return int64(aesSbox[index])
})

// Every product of four bits' subsets, indexed by the subset: 11 constraints.
func nibbleMonomials(api frontend.API, bits []frontend.Variable) [16]frontend.Variable {
	var monomials [16]frontend.Variable
	monomials[0] = 1
	monomials[1], monomials[2], monomials[4], monomials[8] = bits[0], bits[1], bits[2], bits[3]
	monomials[3] = api.Mul(bits[0], bits[1])
	monomials[5] = api.Mul(bits[0], bits[2])
	monomials[9] = api.Mul(bits[0], bits[3])
	monomials[6] = api.Mul(bits[1], bits[2])
	monomials[10] = api.Mul(bits[1], bits[3])
	monomials[12] = api.Mul(bits[2], bits[3])
	monomials[7] = api.Mul(monomials[3], bits[2])
	monomials[11] = api.Mul(monomials[3], bits[3])
	monomials[13] = api.Mul(monomials[5], bits[3])
	monomials[14] = api.Mul(monomials[6], bits[3])
	monomials[15] = api.Mul(monomials[3], monomials[12])
	return monomials
}

// Evaluates a table at an octet's two nibbles' monomials. One product per nonzero high monomial.
func nibbleEvaluate(api frontend.API, coefficients *nibbleCoefficients, high *[16]frontend.Variable, low *[16]frontend.Variable) frontend.Variable {
	terms := []frontend.Variable{}
	for h := range 16 {
		combination := []frontend.Variable{}
		for l := range 16 {
			if coefficients[h][l] != 0 {
				combination = append(combination, api.Mul(low[l], coefficients[h][l]))
			}
		}
		if len(combination) == 0 {
			continue
		}
		sum := combination[0]
		if 1 < len(combination) {
			sum = api.Add(combination[0], combination[1], combination[2:]...)
		}
		terms = append(terms, api.Mul(high[h], sum))
	}
	if len(terms) == 1 {
		return terms[0]
	}
	return api.Add(terms[0], terms[1], terms[2:]...)
}

func aesSubByte(api frontend.API, octet circuitByte) circuitByte {
	low := nibbleMonomials(api, octet[:4])
	high := nibbleMonomials(api, octet[4:])
	value := nibbleEvaluate(api, aesSboxCoefficients, &high, &low)
	var out circuitByte
	copy(out[:], bitsOf(api, value, len(out)))
	return out
}

// The eleven round keys.
func aesExpandKey(api frontend.API, key []circuitByte) [11][16]circuitByte {
	var words [44][4]circuitByte
	for i := range 4 {
		copy(words[i][:], key[4*i:4*i+4])
	}
	rcon := byte(1)
	for i := 4; i < len(words); i++ {
		last := words[i-1]
		if i%4 == 0 {
			last = [4]circuitByte{
				aesSubByte(api, words[i-1][1]),
				aesSubByte(api, words[i-1][2]),
				aesSubByte(api, words[i-1][3]),
				aesSubByte(api, words[i-1][0]),
			}
			for bit := range last[0] {
				last[0][bit] = bitXor(api, last[0][bit], uint((rcon>>bit)&1))
			}
			high := rcon & 0x80
			rcon <<= 1
			if high != 0 {
				rcon ^= 0x1b
			}
		}
		for octet := range 4 {
			for bit := range last[octet] {
				words[i][octet][bit] = bitXor(api, words[i-4][octet][bit], last[octet][bit])
			}
		}
	}
	var roundKeys [11][16]circuitByte
	for round := range roundKeys {
		for i := range 16 {
			roundKeys[round][i] = words[4*round+i/4][i%4]
		}
	}
	return roundKeys
}

// The terms of bit j of 2 * a in GF(2^8).
func aesDoubleTerms(octet circuitByte, bit int) []frontend.Variable {
	terms := []frontend.Variable{}
	if 0 < bit {
		terms = append(terms, octet[bit-1])
	}
	if bit == 0 || bit == 1 || bit == 3 || bit == 4 {
		terms = append(terms, octet[7])
	}
	return terms
}

// One AES-128 encryption under expanded keys.
func aesEncrypt(api frontend.API, roundKeys *[11][16]circuitByte, block []circuitByte) []circuitByte {
	var state [16]circuitByte
	for i := range state {
		for bit := range state[i] {
			state[i][bit] = bitXor(api, block[i][bit], roundKeys[0][i][bit])
		}
	}
	for round := 1; round <= 10; round++ {
		var shifted [16]circuitByte
		for column := range 4 {
			for row := range 4 {
				shifted[4*column+row] = aesSubByte(api, state[4*((column+row)%4)+row])
			}
		}
		key := &roundKeys[round]
		if round == 10 {
			for i := range state {
				for bit := range state[i] {
					state[i][bit] = bitXor(api, shifted[i][bit], key[i][bit])
				}
			}
			break
		}
		for column := range 4 {
			a := shifted[4*column : 4*column+4]
			for row := range 4 {
				for bit := range 8 {
					// out_row = 2 a_row + 3 a_row+1 + a_row+2 + a_row+3
					terms := aesDoubleTerms(a[row], bit)
					terms = append(terms, aesDoubleTerms(a[(row+1)%4], bit)...)
					terms = append(terms, a[(row+1)%4][bit], a[(row+2)%4][bit], a[(row+3)%4][bit], key[4*column+row][bit])
					state[4*column+row][bit] = bitParity(api, terms...)
				}
			}
		}
	}
	out := make([]circuitByte, aes.BlockSize)
	copy(out, state[:])
	return out
}

// The words of "expand 32-byte k".
var chachaConstants = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

func wordRotateLeft(word circuitWord, count int) circuitWord {
	return wordRotateRight(word, len(word)-count)
}

func wordXor(api frontend.API, a circuitWord, b circuitWord) circuitWord {
	var out circuitWord
	for i := range out {
		out[i] = bitXor(api, a[i], b[i])
	}
	return out
}

func wordAdd(api frontend.API, a circuitWord, b circuitWord) circuitWord {
	return wordFromSum(api, api.Add(wordValue(api, a), wordValue(api, b)), 33)
}

// The little-endian word of four octets.
func wordFromBytesLittle(octets []circuitByte) circuitWord {
	var word circuitWord
	for octet := range 4 {
		copy(word[8*octet:8*octet+8], octets[octet][:])
	}
	return word
}

// One 64-octet ChaCha20 keystream block (RFC 8439).
func chachaBlock(api frontend.API, key []circuitByte, counter circuitWord, nonce []circuitByte) []circuitByte {
	var initial [16]circuitWord
	for i, constant := range chachaConstants {
		initial[i] = wordConstant(constant)
	}
	for i := range 8 {
		initial[4+i] = wordFromBytesLittle(key[4*i : 4*i+4])
	}
	initial[12] = counter
	for i := range 3 {
		initial[13+i] = wordFromBytesLittle(nonce[4*i : 4*i+4])
	}
	state := initial
	quarterRound := func(a int, b int, c int, d int) {
		state[a] = wordAdd(api, state[a], state[b])
		state[d] = wordRotateLeft(wordXor(api, state[d], state[a]), 16)
		state[c] = wordAdd(api, state[c], state[d])
		state[b] = wordRotateLeft(wordXor(api, state[b], state[c]), 12)
		state[a] = wordAdd(api, state[a], state[b])
		state[d] = wordRotateLeft(wordXor(api, state[d], state[a]), 8)
		state[c] = wordAdd(api, state[c], state[d])
		state[b] = wordRotateLeft(wordXor(api, state[b], state[c]), 7)
	}
	for range 10 {
		quarterRound(0, 4, 8, 12)
		quarterRound(1, 5, 9, 13)
		quarterRound(2, 6, 10, 14)
		quarterRound(3, 7, 11, 15)
		quarterRound(0, 5, 10, 15)
		quarterRound(1, 6, 11, 12)
		quarterRound(2, 7, 8, 13)
		quarterRound(3, 4, 9, 14)
	}
	out := make([]circuitByte, 0, 64)
	for i := range state {
		word := wordAdd(api, state[i], initial[i])
		for octet := range 4 {
			var value circuitByte
			copy(value[:], word[8*octet:8*octet+8])
			out = append(out, value)
		}
	}
	return out
}
