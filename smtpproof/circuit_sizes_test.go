// What each gadget costs in constraints, held to the figures SPEC.md 11.2 prints: a gadget alone,
// with what its test harness adds taken off, or for Z1 the difference between a shape and its twin
// without Z1. A harness adds one constraint per boolean it asserts on an input or output bit and one
// per output bit it compares, so what is taken off is exact, and it is written beside each circuit. A
// change to a gadget fails here until SPEC.md 11.2 says what it costs now.

package smtpproof

import (
	"crypto/sha256"
	"strconv"
	"testing"

	"github.com/consensys/gnark/frontend"
)

// AES blocks under one key schedule, so a block's cost separates from the schedule's.
type testAesBlocksCircuit struct {
	Key    []frontend.Variable
	Blocks [][]frontend.Variable
	Outs   [][]frontend.Variable `gnark:",public"`
}

func (self *testAesBlocksCircuit) Define(api frontend.API) error {
	roundKeys := aesExpandKey(api, testByteWires(api, self.Key))
	for i := range self.Blocks {
		testAssertBytesEqual(api, aesEncrypt(api, &roundKeys, testByteWires(api, self.Blocks[i])), testByteWires(api, self.Outs[i]))
	}
	return nil
}

func newTestAesBlocksCircuit(blocks int) *testAesBlocksCircuit {
	circuit := &testAesBlocksCircuit{Key: make([]frontend.Variable, 128)}
	for range blocks {
		circuit.Blocks = append(circuit.Blocks, make([]frontend.Variable, 128))
		circuit.Outs = append(circuit.Outs, make([]frontend.Variable, 128))
	}
	return circuit
}

// One HMAC key's pad states from a private key and nothing more, so the setup separates from a sum.
type testHmacKeyCircuit struct {
	Key   []frontend.Variable
	Inner []frontend.Variable `gnark:",public"`
	Outer []frontend.Variable `gnark:",public"`
}

func (self *testHmacKeyCircuit) Define(api frontend.API) error {
	key := newCircuitHmacKey(api, testByteWires(api, self.Key))
	testAssertBytesEqual(api, hashStateBytes(key.inner), testByteWires(api, self.Inner))
	testAssertBytesEqual(api, hashStateBytes(key.outer), testByteWires(api, self.Outer))
	return nil
}

// SPEC.md 11.2's measured rows, by gadget, as gnark v0.15.0 compiles them.
var testSpecGadgetSizes = map[string]int{
	"sha256 compression":            26480,
	"hmac pad states":               51208,
	"hmac sum":                      51770,
	"expand label":                  51789,
	"prf key block":                 337761,
	"aes key schedule":              3136,
	"aes block":                     11504,
	"chacha20 block":                21664,
	"aes keystream block":           11665,
	"chacha20 keystream block":      21825,
	"z1 tls13 both directions":      708498,
	"z1 tls12 server finished open": 669147,
	// DESIGN-DETAILS 3.2.2's gadget, booleans of its bits and blind included (SMTP-M9-36)
	"commitment opening, aes keys":      3026,
	"commitment opening, chacha20 keys": 4133,
	"commitment opening, a carry":       1186,
}

func TestGadgetSizesAreSpecMds(t *testing.T) {
	expect := func(gadget string, constraints int) {
		t.Helper()
		t.Logf("%s: %d constraints", gadget, constraints)
		if want := testSpecGadgetSizes[gadget]; constraints != want {
			t.Errorf("%s: %d constraints, SPEC.md 11.2 says %d", gadget, constraints, want)
		}
	}

	expect("sha256 compression", testCompileCompress(t).GetNbConstraints()-testCompressHarnessConstraints)

	// the key's bits, then both pad states as outputs, each boolean and compared
	hmacKey := testCompile(t, &testHmacKeyCircuit{
		Key:   make([]frontend.Variable, 8*tlsSecretBytes),
		Inner: make([]frontend.Variable, 8*sha256.Size),
		Outer: make([]frontend.Variable, 8*sha256.Size),
	}).GetNbConstraints() - (8*tlsSecretBytes + 2*2*8*sha256.Size)
	expect("hmac pad states", hmacKey)

	// a sum over up to 55 octets after the pad states: the key's and message's bits, and the MAC's
	message := make([]frontend.Variable, 8*34)
	hmacWhole := testCompile(t, &testHmacCircuit{
		Key:     make([]frontend.Variable, 8*tlsSecretBytes),
		Message: message,
		Mac:     make([]frontend.Variable, 8*sha256.Size),
	}).GetNbConstraints() - (8*tlsSecretBytes + len(message) + 2*8*sha256.Size)
	expect("hmac sum", hmacWhole-hmacKey)

	// HKDF-Expand-Label to 32 octets over a 32-octet context, the shape of nearly every label in Z1
	expand := testCompile(t, &testExpandCircuit{
		Secret:  make([]frontend.Variable, 8*tlsSecretBytes),
		Context: make([]frontend.Variable, 8*sha256.Size),
		Out:     make([]frontend.Variable, 8*tlsSecretBytes),
		label:   "c ap traffic",
	}).GetNbConstraints() - (8*tlsSecretBytes + 8*sha256.Size + 2*8*tlsSecretBytes)
	expect("expand label", expand-hmacKey)

	// the 1.2 key block, 40 octets from a 48-octet secret and a 64-octet seed, pad states included
	keyBlockBytes := 2*tlsAes128KeyBytes + 2*tlsSalt12Bytes
	expect("prf key block", testCompile(t, &testPrfCircuit{
		label:  tlsLabelKeyExpansion,
		Secret: make([]frontend.Variable, 8*tlsMasterSecretBytes),
		Seed:   make([]frontend.Variable, 8*2*tlsRandomBytes),
		Out:    make([]frontend.Variable, 8*keyBlockBytes),
	}).GetNbConstraints()-(8*tlsMasterSecretBytes+8*2*tlsRandomBytes+2*8*keyBlockBytes))

	// AES: one block and two under one schedule; the key's bits once, then each block's input bits
	// and its output bits, boolean and compared
	aesOne := testCompile(t, newTestAesBlocksCircuit(1)).GetNbConstraints() - (128 + 3*128)
	aesTwo := testCompile(t, newTestAesBlocksCircuit(2)).GetNbConstraints() - (128 + 2*3*128)
	aesBlock := aesTwo - aesOne
	expect("aes key schedule", aesOne-aesBlock)
	expect("aes block", aesBlock)

	// ChaCha20: the key's, nonce's and counter's bits, and the 64 output octets' bits
	expect("chacha20 block", testCompile(t, &testChachaCircuit{
		Key:   make([]frontend.Variable, 256),
		Nonce: make([]frontend.Variable, 96),
		Out:   make([]frontend.Variable, 512),
	}).GetNbConstraints()-(256+96+32+2*512))

	// Z2's keystream as a part runs it, its nonce formed from the private IV and the public counter:
	// the key's and IV's bits, then each block's output bits, boolean and compared. AES's schedule is
	// the part's, shared by every block, so it is taken off
	for _, suite := range []uint16{tlsSuiteAes128GcmSha256, tlsSuiteChacha20Poly1305Sha256} {
		shape := testKeystreamShape(suite)
		compiled, err := testCompileKeystream(t, shape)
		if err != nil {
			t.Fatal(err)
		}
		octets := testKeystreamBlocks * shape.blockBytes()
		keystream := compiled.GetNbConstraints() - (8*shape.keyBytes() + 8*tlsIv13Bytes + 2*8*octets)
		gadget := "chacha20 keystream block"
		if suite != tlsSuiteChacha20Poly1305Sha256 {
			gadget = "aes keystream block"
			keystream -= aesOne - aesBlock
		}
		if keystream%testKeystreamBlocks != 0 {
			t.Errorf("%s: %d constraints over %d blocks", gadget, keystream, testKeystreamBlocks)
		}
		expect(gadget, keystream/testKeystreamBlocks)
		t.Logf("%s: %s constraints per octet", gadget, strconv.FormatFloat(float64(keystream)/float64(octets), 'f', 1, 64))
	}

	// Z1 as a part spends it: a shape against its twin that takes the keys as private bits instead,
	// whose booleans are added back. The public hashes cost 512 booleans here that the isolated
	// circuit of TestZ1CircuitDerivesARealConnectionsKeys asserts in its harness: gnark's Xor asserts
	// its inputs boolean, and H_sh and H_sf enter HMAC messages. A 1.2 IV is the salt and 8 zero
	// octets, so the real shape's nonce takes the explicit nonce for free where the twin's private IV
	// costs a XOR per bit: 64 a pool block, added back too
	z1 := func(shape *partShape) int {
		without := *shape
		without.withoutKeySchedule = true
		keyBooleans := 2 * 8 * (shape.keyBytes() + tlsIv13Bytes)
		twinNonceXors := 0
		twinBindings := 0
		if shape.version == tlsVersion12 {
			twinNonceXors = 8 * tlsExplicitNonceBytes * shape.clientBlocks
			// the twin reads no 1.2 input, so it binds ResumeTwoBlocks, a wire of every shape, to 0
			twinBindings = 1
		}
		return testCompileShape(t, shape).GetNbConstraints() - testCompileShape(t, &without).GetNbConstraints() + keyBooleans + twinNonceXors + twinBindings
	}
	// the key part's shapes, which other tests compile too: the key part derives both directions always,
	// since C commits to both (DESIGN-DETAILS 3.2.3), and no later part derives anything
	expect("z1 tls13 both directions", z1(partShapes()[1]))
	// a 1.2 key part's IVs end in 8 zero octets its derivation makes constants, so its opening of C is
	// cheaper than its twin's, whose IVs are private bits: that saving comes off what z1 reads
	keyGenerators, scanGenerators := commitGeneratorSets()
	keyBits := 8 * (2*tlsAes128KeyBytes + 2*tlsIv13Bytes)
	zero := make([]bool, keyBits)
	for direction := range 2 {
		start := 8 * (direction*(tlsAes128KeyBytes+tlsIv13Bytes) + tlsAes128KeyBytes + tlsSalt12Bytes)
		for i := range 8 * tlsExplicitNonceBytes {
			zero[start+i] = true
		}
	}
	whole := testCompile(t, newTestCommitCircuit(keyGenerators, keyBits)).GetNbConstraints()
	salted := testCompile(t, newTestCommitLayoutCircuit(keyGenerators, zero)).GetNbConstraints()
	expect("z1 tls12 server finished open", z1(test12Shape())+whole-salted-2*8*tlsExplicitNonceBytes)

	// the commitment gadget alone: its bits' and blind's booleans stay in, the two comparisons of its
	// output come off
	for _, c := range []struct {
		gadget     string
		generators *commitGenerators
		bitCount   int
	}{
		{gadget: "commitment opening, aes keys", generators: keyGenerators, bitCount: 8 * (2*tlsAes128KeyBytes + 2*tlsIv13Bytes)},
		{gadget: "commitment opening, chacha20 keys", generators: keyGenerators, bitCount: 8 * (2*tlsChachaKeyBytes + 2*tlsIv13Bytes)},
		{gadget: "commitment opening, a carry", generators: scanGenerators, bitCount: carryStateBits},
	} {
		expect(c.gadget, testCompile(t, newTestCommitCircuit(c.generators, c.bitCount)).GetNbConstraints()-2)
	}
}

// A commitment whose bits at the zero positions are the constant 0, as a 1.2 key part's derived IVs end
// in 8 zero octets. Booleans on the other bits only.
type testCommitLayoutCircuit struct {
	generators *commitGenerators
	zero       []bool
	Bits       []frontend.Variable
	BlindBits  []frontend.Variable
	Commitment []frontend.Variable `gnark:",public"`
}

func newTestCommitLayoutCircuit(generators *commitGenerators, zero []bool) *testCommitLayoutCircuit {
	return &testCommitLayoutCircuit{
		generators: generators,
		zero:       zero,
		Bits:       make([]frontend.Variable, len(zero)),
		BlindBits:  make([]frontend.Variable, commitBlindBits),
		Commitment: make([]frontend.Variable, 2),
	}
}

func (self *testCommitLayoutCircuit) Define(api frontend.API) error {
	bits := make([]frontend.Variable, len(self.Bits))
	for i, bit := range self.Bits {
		if self.zero[i] {
			bits[i] = 0
			continue
		}
		api.AssertIsBoolean(bit)
		bits[i] = bit
	}
	for _, bit := range self.BlindBits {
		api.AssertIsBoolean(bit)
	}
	assertCommitment(api, self.generators, bits, self.BlindBits, self.Commitment)
	return nil
}
