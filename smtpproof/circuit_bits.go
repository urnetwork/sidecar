package smtpproof

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// Boolean wires, the base every gadget here builds on. SPEC.md 10.1 forbids gnark's std packages in
// this module: its v0.15.0 std/math/uints trusts lookup results, so nothing here uses a lookup, a
// commitment or a std gadget. TestCircuitsImportNoGnarkStd and TestCircuitsUseNoCommitments enforce
// that. A wire holding a bit is constrained boolean once, where it is created.
//
// A constant bit is a Go 0 or 1, which every function here folds, so padding and fixed labels cost
// nothing. Bits are least significant first.

func init() {
	solver.RegisterHint(hintHighBits)
	solver.RegisterHint(hintIdentity)
}

// A running value as one wire. A scanner's sum carried as a linear combination gains a term per
// octet, and every constraint on it then costs that many terms, so N octets would cost N^2. One
// constraint here resets that.
func pinWire(api frontend.API, value frontend.Variable) frontend.Variable {
	if _, ok := api.Compiler().ConstantValue(value); ok {
		return value
	}
	pinned, err := api.Compiler().NewHint(hintIdentity, 1, value)
	if err != nil {
		panic(err)
	}
	api.AssertIsEqual(pinned[0], value)
	return pinned[0]
}

// Its input. Prover-side only: pinWire's constraint is what makes the result sound.
func hintIdentity(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	outputs[0].Set(inputs[0])
	return nil
}

// The value of a constant wire, if it is one.
func bitConstant(api frontend.API, wire frontend.Variable) (uint, bool) {
	value, ok := api.Compiler().ConstantValue(wire)
	if !ok {
		return 0, false
	}
	return uint(value.Uint64()), true
}

// a XOR b, one constraint unless either is constant.
func bitXor(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	if value, ok := bitConstant(api, a); ok {
		if value == 0 {
			return b
		}
		return api.Sub(1, b)
	}
	if value, ok := bitConstant(api, b); ok {
		if value == 0 {
			return a
		}
		return api.Sub(1, a)
	}
	return api.Xor(a, b)
}

// The XOR of boolean terms. A chain costs a constraint per term; this costs ceil(log2(n + 1)): the
// sum's high bits come from a hint, and the parity is what remains, which is forced to be a bit. So
// 8 terms cost 4. Sound because a sum below 2^k has one representation as parity + 2 * high.
func bitParity(api frontend.API, terms ...frontend.Variable) frontend.Variable {
	variables := make([]frontend.Variable, 0, len(terms))
	constant := uint(0)
	for _, term := range terms {
		if value, ok := bitConstant(api, term); ok {
			constant ^= value
			continue
		}
		variables = append(variables, term)
	}
	var parity frontend.Variable
	switch len(variables) {
	case 0:
		return constant
	case 1:
		parity = variables[0]
	case 2:
		parity = api.Xor(variables[0], variables[1])
	default:
		sum := api.Add(variables[0], variables[1], variables[2:]...)
		highBits := 1
		for (1 << (highBits + 1)) <= len(variables) {
			highBits += 1
		}
		highs, err := api.Compiler().NewHint(hintHighBits, highBits, sum)
		if err != nil {
			panic(err)
		}
		parity = sum
		for i, high := range highs {
			api.AssertIsBoolean(high)
			parity = api.Sub(parity, api.Mul(high, new(big.Int).Lsh(big.NewInt(1), uint(i+1))))
		}
		api.AssertIsBoolean(parity)
	}
	if constant == 1 {
		return api.Sub(1, parity)
	}
	return parity
}

// The bits of its input above the lowest, least significant first. Prover-side only: bitParity's
// constraints are what make the result sound.
func hintHighBits(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	for i := range outputs {
		outputs[i].SetUint64(uint64(inputs[0].Bit(i + 1)))
	}
	return nil
}

// A 32-bit word, least significant bit first.
type circuitWord [32]frontend.Variable

// An octet, least significant bit first.
type circuitByte [8]frontend.Variable

func wordConstant(value uint32) circuitWord {
	var word circuitWord
	for i := range word {
		word[i] = uint((value >> i) & 1)
	}
	return word
}

func byteConstant(value byte) circuitByte {
	var octet circuitByte
	for i := range octet {
		octet[i] = uint((value >> i) & 1)
	}
	return octet
}

func bytesConstant(values []byte) []circuitByte {
	octets := make([]circuitByte, len(values))
	for i, value := range values {
		octets[i] = byteConstant(value)
	}
	return octets
}

// The word's value as a linear combination, which costs no constraint.
func wordValue(api frontend.API, word circuitWord) frontend.Variable {
	terms := make([]frontend.Variable, 0, len(word))
	for i, bit := range word {
		terms = append(terms, api.Mul(bit, new(big.Int).Lsh(big.NewInt(1), uint(i))))
	}
	return api.Add(terms[0], terms[1], terms[2:]...)
}

// The octet's value as a linear combination.
func byteValue(api frontend.API, octet circuitByte) frontend.Variable {
	terms := make([]frontend.Variable, 0, len(octet))
	for i, bit := range octet {
		terms = append(terms, api.Mul(bit, 1<<i))
	}
	return api.Add(terms[0], terms[1], terms[2:]...)
}

// The low 32 bits of a sum below 2^bitCount.
func wordFromSum(api frontend.API, sum frontend.Variable, bitCount int) circuitWord {
	if value, ok := api.Compiler().ConstantValue(sum); ok {
		return wordConstant(uint32(new(big.Int).And(value, big.NewInt(0xffffffff)).Uint64()))
	}
	bits := api.ToBinary(sum, bitCount)
	var word circuitWord
	copy(word[:], bits[:len(word)])
	return word
}

// Bits of a wire already known to fit in count bits, each constrained boolean.
func bitsOf(api frontend.API, wire frontend.Variable, count int) []frontend.Variable {
	return api.ToBinary(wire, count)
}

// octets of a wire holding a big-endian value of len(octets) octets.
func bytesOfWire(api frontend.API, wire frontend.Variable, octetCount int) []circuitByte {
	bits := bitsOf(api, wire, 8*octetCount)
	octets := make([]circuitByte, octetCount)
	for i := range octets {
		copy(octets[octetCount-1-i][:], bits[8*i:8*i+8])
	}
	return octets
}
