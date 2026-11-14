// Evidence for the gadgets that does not lean on this module's own code: published vectors, the real
// AEADs, and a compression function written out here, so that a wrong result cannot pass by agreeing
// with itself. A mutated value sits beside each.

package smtpproof

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"math/bits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"golang.org/x/crypto/chacha20poly1305"
)

func testHex(t testing.TB, text string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestAesGadgetMatchesFips197(t *testing.T) {
	// FIPS 197 appendix C.1
	key := testHex(t, "000102030405060708090a0b0c0d0e0f")
	plaintext := testHex(t, "00112233445566778899aabbccddeeff")
	want := testHex(t, "69c4e0d86a7b0430d8cdb78070b4c55a")
	compiled := testCompile(t, &testAesCircuit{
		Key:   make([]frontend.Variable, 128),
		Block: make([]frontend.Variable, 128),
		Out:   make([]frontend.Variable, 128),
	})
	if err := testSolved(t, compiled, &testAesCircuit{Key: testAssignBits(key), Block: testAssignBits(plaintext), Out: testAssignBits(want)}); err != nil {
		t.Error(err)
	}
	want[15] ^= 0x80
	if err := testSolved(t, compiled, &testAesCircuit{Key: testAssignBits(key), Block: testAssignBits(plaintext), Out: testAssignBits(want)}); err == nil {
		t.Error("accepted a wrong block")
	}
}

func TestChachaGadgetMatchesRfc8439(t *testing.T) {
	// RFC 8439 §2.3.2
	key := testHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	nonce := testHex(t, "000000090000004a00000000")
	want := testHex(t, "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
	stream, err := recordKeystream(tlsSuiteChacha20Poly1305Sha256, key, nonce, len(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stream, want) {
		t.Fatalf("recordKeystream gives %x", stream)
	}
	compiled := testCompile(t, &testChachaCircuit{
		Key:   make([]frontend.Variable, 256),
		Nonce: make([]frontend.Variable, 96),
		Out:   make([]frontend.Variable, 512),
	})
	assignment := func(out []byte) *testChachaCircuit {
		circuit := &testChachaCircuit{Key: testAssignBits(key), Nonce: testAssignBits(nonce), Out: testAssignBits(out)}
		for i := range circuit.Counter {
			circuit.Counter[i] = 0
		}
		circuit.Counter[0] = 1
		return circuit
	}
	if err := testSolved(t, compiled, assignment(want)); err != nil {
		t.Error(err)
	}
	want[63] ^= 1
	if err := testSolved(t, compiled, assignment(want)); err == nil {
		t.Error("accepted a wrong block")
	}
}

// Consecutive keystream blocks of one record through the circuit's own source, as Z2 uses it.
type testKeystreamCircuit struct {
	shape    *partShape
	Key      []frontend.Variable
	Iv       []frontend.Variable
	Counters []frontend.Variable `gnark:",public"`
	Stream   []frontend.Variable `gnark:",public"`
}

func (self *testKeystreamCircuit) Define(api frontend.API) error {
	stream := newCircuitKeystream(api, self.shape, testByteWires(api, self.Key), testByteWires(api, self.Iv))
	want := testByteWires(api, self.Stream)
	for i, counter := range self.Counters {
		block := stream.block(api, counter)
		testAssertBytesEqual(api, block, want[i*len(block):(i+1)*len(block)])
	}
	return nil
}

// What an AEAD's own encryption of zeros gives, which is its keystream from the first data block.
func testAeadKeystream(t testing.TB, suite uint16, key []byte, nonce []byte, size int) []byte {
	t.Helper()
	var aead cipher.AEAD
	var err error
	if suite == tlsSuiteChacha20Poly1305Sha256 {
		aead, err = chacha20poly1305.New(key)
	} else {
		var block cipher.Block
		if block, err = aes.NewCipher(key); err == nil {
			aead, err = cipher.NewGCM(block)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	return aead.Seal(nil, nonce, make([]byte, size), nil)[:size]
}

const testKeystreamBlocks = 3

func testKeystreamShape(suite uint16) *partShape {
	return &partShape{version: testVersionOf(suite), suite: suite}
}

func testCompileKeystream(t testing.TB, shape *partShape) (constraint.ConstraintSystem, error) {
	t.Helper()
	testNeedCircuits(t)
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testKeystreamCircuit{
		shape:    shape,
		Key:      make([]frontend.Variable, 8*shape.keyBytes()),
		Iv:       make([]frontend.Variable, 8*tlsIv13Bytes),
		Counters: make([]frontend.Variable, testKeystreamBlocks),
		Stream:   make([]frontend.Variable, 8*testKeystreamBlocks*shape.blockBytes()),
	})
}

// The wires of a record at high, which is seq in 1.3 and the explicit nonce in 1.2.
func testKeystreamAssignment(shape *partShape, key []byte, iv []byte, high uint64, stream []byte) *testKeystreamCircuit {
	circuit := &testKeystreamCircuit{
		shape:    shape,
		Key:      testAssignBits(key),
		Iv:       testAssignBits(iv),
		Counters: make([]frontend.Variable, testKeystreamBlocks),
		Stream:   testAssignBits(stream),
	}
	for i := range circuit.Counters {
		counter := new(big.Int).SetUint64(high)
		counter.Lsh(counter, 32)
		counter.Add(counter, new(big.Int).SetUint64(shape.firstCounter()+uint64(i)))
		circuit.Counters[i] = counter
	}
	return circuit
}

func TestKeystreamGadgetMatchesTheAeads(t *testing.T) {
	// multi-block records against the real AEADs, at the sequence numbers that cross a word
	for _, suite := range []uint16{tlsSuiteAes128GcmSha256, tlsSuiteChacha20Poly1305Sha256, tlsSuiteEcdheEcdsaAes128GcmSha256} {
		shape := testKeystreamShape(suite)
		compiled, err := testCompileKeystream(t, shape)
		if err != nil {
			t.Fatal(err)
		}
		key := make([]byte, shape.keyBytes())
		iv := make([]byte, tlsIv13Bytes)
		for i := range key {
			key[i] = byte(13*i + 5)
		}
		for i := range iv {
			iv[i] = byte(29*i + 3)
		}
		if shape.version == tlsVersion12 {
			// a 1.2 IV is the salt, and the wires' other 8 octets stay zero
			clear(iv[tlsSalt12Bytes:])
		}
		for _, high := range []uint64{0, 1, 1 << 32} {
			var nonce []byte
			if shape.version == tlsVersion13 {
				nonce = tls13Nonce(iv, high)
			} else {
				nonce = binary.BigEndian.AppendUint64(bytes.Clone(iv[:tlsSalt12Bytes]), high)
			}
			want := testAeadKeystream(t, suite, key, nonce, testKeystreamBlocks*shape.blockBytes())
			if err := testSolved(t, compiled, testKeystreamAssignment(shape, key, iv, high, want)); err != nil {
				t.Errorf("suite %#x at %d: %v", suite, high, err)
			}

			// a key bit, a nonce bit and a position are each part of what the stream depends on
			wrongKey := bytes.Clone(key)
			wrongKey[0] ^= 1
			if err := testSolved(t, compiled, testKeystreamAssignment(shape, wrongKey, iv, high, want)); err == nil {
				t.Errorf("suite %#x at %d: a wrong key bit: accepted", suite, high)
			}
			wrongIv := bytes.Clone(iv)
			wrongIv[0] ^= 1
			if err := testSolved(t, compiled, testKeystreamAssignment(shape, key, wrongIv, high, want)); err == nil {
				t.Errorf("suite %#x at %d: a wrong nonce bit: accepted", suite, high)
			}
			if err := testSolved(t, compiled, testKeystreamAssignment(shape, key, iv, high+1, want)); err == nil {
				t.Errorf("suite %#x at %d: another record's position: accepted", suite, high)
			}
		}
	}
}

type testPrfCircuit struct {
	label  string
	Secret []frontend.Variable
	Seed   []frontend.Variable
	Out    []frontend.Variable `gnark:",public"`
}

func (self *testPrfCircuit) Define(api frontend.API) error {
	key := newCircuitHmacKey(api, testByteWires(api, self.Secret))
	testAssertBytesEqual(api, key.prf(api, self.label, testByteWires(api, self.Seed), len(self.Out)/8), testByteWires(api, self.Out))
	return nil
}

func TestPrfGadgetMatchesTheTls12Prf(t *testing.T) {
	secret := make([]byte, tlsMasterSecretBytes)
	for i := range secret {
		secret[i] = byte(7*i + 11)
	}
	cases := []struct {
		label     string
		seedBytes int
		size      int
	}{
		{label: tlsLabelKeyExpansion, seedBytes: 2 * tlsRandomBytes, size: 2*tlsAes128KeyBytes + 2*tlsSalt12Bytes},
		{label: tlsLabelClientFinished, seedBytes: tlsSecretBytes, size: tlsVerifyData12Bytes},
		{label: tlsLabelServerFinished, seedBytes: tlsSecretBytes, size: tlsVerifyData12Bytes},
	}
	for _, c := range cases {
		seed := make([]byte, c.seedBytes)
		for i := range seed {
			seed[i] = byte(3*i + 1)
		}
		out := tls12Prf(secret, c.label, seed, c.size)
		compiled := testCompile(t, &testPrfCircuit{
			label:  c.label,
			Secret: make([]frontend.Variable, 8*len(secret)),
			Seed:   make([]frontend.Variable, 8*len(seed)),
			Out:    make([]frontend.Variable, 8*c.size),
		})
		assignment := func(out []byte) *testPrfCircuit {
			return &testPrfCircuit{label: c.label, Secret: testAssignBits(secret), Seed: testAssignBits(seed), Out: testAssignBits(out)}
		}
		if err := testSolved(t, compiled, assignment(out)); err != nil {
			t.Errorf("%s: %v", c.label, err)
		}
		out[len(out)-1] ^= 1
		if err := testSolved(t, compiled, assignment(out)); err == nil {
			t.Errorf("%s: accepted a wrong output", c.label)
		}
	}
}

// One compression over a state of bits, so that nothing folds as a constant would.
type testCompressCircuit struct {
	State []frontend.Variable
	Block []frontend.Variable
	Out   []frontend.Variable `gnark:",public"`
}

func (self *testCompressCircuit) Define(api frontend.API) error {
	var state circuitHashState
	for i := range state {
		for j := range state[i] {
			api.AssertIsBoolean(self.State[32*i+j])
			state[i][j] = self.State[32*i+j]
		}
	}
	testAssertBytesEqual(api, hashStateBytes(sha256Compress(api, state, testByteWires(api, self.Block))), testByteWires(api, self.Out))
	return nil
}

func testCompileCompress(t testing.TB) constraint.ConstraintSystem {
	t.Helper()
	testNeedCircuits(t)
	compiled, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &testCompressCircuit{
		State: make([]frontend.Variable, 256),
		Block: make([]frontend.Variable, 8*sha256BlockBytes),
		Out:   make([]frontend.Variable, 256),
	})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// FIPS 180-4 §6.2.2, written out here so that a chaining value can be compared with something other
// than crypto/sha256's own marshaled form.
func testReferenceCompress(state [8]uint32, block []byte) [8]uint32 {
	var schedule [64]uint32
	for i := range 16 {
		schedule[i] = binary.BigEndian.Uint32(block[4*i:])
	}
	for i := 16; i < 64; i++ {
		v := schedule[i-15]
		s0 := bits.RotateLeft32(v, -7) ^ bits.RotateLeft32(v, -18) ^ v>>3
		v = schedule[i-2]
		s1 := bits.RotateLeft32(v, -17) ^ bits.RotateLeft32(v, -19) ^ v>>10
		schedule[i] = schedule[i-16] + s0 + schedule[i-7] + s1
	}
	a, b, c, d, e, f, g, h := state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]
	for i := range 64 {
		t1 := h + (bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)) + (e&f ^ ^e&g) + sha256RoundConstants[i] + schedule[i]
		t2 := (bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)) + (a&b ^ a&c ^ b&c)
		h, g, f, e, d, c, b, a = g, f, e, d+t1, c, b, a, t1+t2
	}
	for i, value := range [8]uint32{a, b, c, d, e, f, g, h} {
		state[i] += value
	}
	return state
}

func testHashStateBytes(state [8]uint32) []byte {
	octets := make([]byte, 0, 32)
	for _, word := range state {
		octets = binary.BigEndian.AppendUint32(octets, word)
	}
	return octets
}

func testHashStateBits(state [8]uint32) []frontend.Variable {
	wires := make([]frontend.Variable, 0, 256)
	for _, word := range state {
		for i := range 32 {
			wires = append(wires, (word>>i)&1)
		}
	}
	return wires
}

// What testCompressCircuit adds around the gadget: a boolean constraint on each input and output bit
// and an equality on each output bit.
const testCompressHarnessConstraints = 256 + 512 + 256 + 256

func TestCompressGadgetMatchesTheReferenceAndItsBudget(t *testing.T) {
	compiled := testCompileCompress(t)
	// SPEC.md 11.2's figure, which every Z1 figure multiplies
	constraints := compiled.GetNbConstraints() - testCompressHarnessConstraints
	if 26482 < constraints {
		t.Errorf("%d constraints, past 26,482", constraints)
	}
	t.Logf("sha256: %d constraints per compression", constraints)
	block := make([]byte, sha256BlockBytes)
	for i := range block {
		block[i] = byte(5*i + 9)
	}
	state := sha256InitialState
	state[3] ^= 0xdeadbeef
	want := testHashStateBytes(testReferenceCompress(state, block))
	assignment := func(out []byte) *testCompressCircuit {
		return &testCompressCircuit{State: testHashStateBits(state), Block: testAssignBits(block), Out: testAssignBits(out)}
	}
	if err := testSolved(t, compiled, assignment(want)); err != nil {
		t.Error(err)
	}
	want[0] ^= 1
	if err := testSolved(t, compiled, assignment(want)); err == nil {
		t.Error("accepted a wrong state")
	}
}

func TestSha256StateIsTheChainingValueAcrossAGoUpgrade(t *testing.T) {
	// S_ckx is SPEC.md's encoding, and newSha256State reads it out of crypto/sha256's MarshalBinary,
	// which is Go's to change. So it is compared with the compression written out above, and with a
	// fixed vector: the state after one block of zeros
	zeros := make([]byte, sha256BlockBytes)
	state, err := newSha256State(zeros)
	if err != nil {
		t.Fatal(err)
	}
	fixed := testHex(t, "da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8")
	if got := testHashStateBytes(state.chaining); !bytes.Equal(got, fixed) {
		t.Errorf("after one zero block: %x", got)
	}

	for _, size := range []int{0, 1, 63, 64, 65, 127, 128, 129} {
		message := make([]byte, size)
		for i := range message {
			message[i] = byte(11*i + size)
		}
		state, err := newSha256State(message)
		if err != nil {
			t.Fatal(err)
		}
		want := sha256InitialState
		full := size - size%sha256BlockBytes
		for offset := 0; offset < full; offset += sha256BlockBytes {
			want = testReferenceCompress(want, message[offset:offset+sha256BlockBytes])
		}
		if state.chaining != want {
			t.Errorf("size %d: chaining value %x, want %x", size, state.chaining, want)
		}
		if !bytes.Equal(state.tail, message[full:]) || state.length != uint64(size) {
			t.Errorf("size %d: tail %x, length %d", size, state.tail, state.length)
		}
	}
}

func TestZ1CircuitRefusesTheKeyThatOpensARecordBenignly(t *testing.T) {
	t.Parallel()
	// the headline attack (SPEC.md 9.2), through the circuit: a record authored to open to the honest
	// EHLO under a key of the sidecar's choosing. Everything but Z1 is satisfied by that key, which is
	// what makes the record dangerous, so the shape with Z1 left out must take it and the real one not
	for _, c := range []struct {
		leg  *testTlsLeg
		full *partShape
	}{
		{leg: testTlsLegs()[1], full: partShapes()[1]},
		{leg: testTlsLegs()[2], full: test12Shape()},
	} {
		capture := testBdatCapture(t, c.leg)
		statement, witness := capture.part(t, 1)
		substitute := testCloneWitness(witness)
		substitute.clientKey[0] ^= 1
		testSeal(t, statement, statement.clientRecords[0], substitute.clientKey, bytes.Clone(witness.clientIv), witness.clientPlaintexts[0])
		// the key part publishes its own C, so the sidecar commits to the key it chose
		forged, err := commitKeys(substitute.clientKey, substitute.clientIv, substitute.serverKey, substitute.serverIv, substitute.keyBlind)
		if err != nil {
			t.Fatal(err)
		}
		statement.keyCommitment = encodeCommitment(forged)

		quick := testQuickShape(c.leg.suites[0], false)
		if err := testPartSolved(t, testCompileShape(t, quick), testPartAssignment(t, quick, statement, substitute)); err != nil {
			t.Errorf("%s: the substitute did not open the record: %v", c.leg.name, err)
		}
		// the handshake's secret gives the honest key, whichever key the witness claims beside it
		if err := testPartSolved(t, testCompileShape(t, c.full), testPartAssignment(t, c.full, statement, witness)); err == nil {
			t.Errorf("%s: Z1 let the record through under the handshake's key", c.leg.name)
		}
		if err := testPartSolved(t, testCompileShape(t, c.full), testPartAssignment(t, c.full, statement, substitute)); err == nil {
			t.Errorf("%s: Z1 let the record through under the substitute's commitment", c.leg.name)
		}
	}
}

func BenchmarkCircuitSha256Compress(b *testing.B) {
	compiled := testCompileCompress(b)
	block := make([]byte, sha256BlockBytes)
	full, err := frontend.NewWitness(&testCompressCircuit{
		State: testHashStateBits(sha256InitialState),
		Block: testAssignBits(block),
		Out:   testAssignBits(testHashStateBytes(testReferenceCompress(sha256InitialState, block))),
	}, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if err := compiled.IsSolved(full); err != nil {
			b.Fatal(err)
		}
	}
	// after the loop: its first call resets what was reported before it
	b.ReportMetric(float64(compiled.GetNbConstraints()-testCompressHarnessConstraints), "constraints")
}

func BenchmarkCircuitKeystream(b *testing.B) {
	for _, suite := range []uint16{tlsSuiteAes128GcmSha256, tlsSuiteChacha20Poly1305Sha256} {
		shape := testKeystreamShape(suite)
		compiled, err := testCompileKeystream(b, shape)
		if err != nil {
			b.Fatal(err)
		}
		key := make([]byte, shape.keyBytes())
		iv := make([]byte, tlsIv13Bytes)
		want := testAeadKeystream(b, suite, key, tls13Nonce(iv, 1), testKeystreamBlocks*shape.blockBytes())
		full, err := frontend.NewWitness(testKeystreamAssignment(shape, key, iv, 1, want), ecc.BN254.ScalarField())
		if err != nil {
			b.Fatal(err)
		}
		name := "aes128"
		if suite == tlsSuiteChacha20Poly1305Sha256 {
			name = "chacha20"
		}
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if err := compiled.IsSolved(full); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(compiled.GetNbConstraints())/float64(len(want)), "constraints/octet")
		})
	}
}
