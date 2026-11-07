// The gadgets against the standard library, and a mutated value beside each: a gadget that accepts a
// wrong output is worth nothing however well it computes the right one.

package smtpproof

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func testCompile(t *testing.T, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	compiled, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

// Whether an assignment satisfies a compiled circuit.
func testSolved(t *testing.T, compiled constraint.ConstraintSystem, assignment frontend.Circuit) error {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return compiled.IsSolved(witness)
}

// Octets as wire values, for an assignment: one wire per bit.
func testAssignBits(values []byte) []frontend.Variable {
	bits := make([]frontend.Variable, 0, 8*len(values))
	for _, value := range values {
		for i := range 8 {
			bits = append(bits, (value>>i)&1)
		}
	}
	return bits
}

// A slice of bit wires as octets, each bit constrained boolean.
func testByteWires(api frontend.API, bits []frontend.Variable) []circuitByte {
	octets := make([]circuitByte, len(bits)/8)
	for i := range octets {
		for j := range octets[i] {
			api.AssertIsBoolean(bits[8*i+j])
			octets[i][j] = bits[8*i+j]
		}
	}
	return octets
}

func testAssertBytesEqual(api frontend.API, got []circuitByte, want []circuitByte) {
	for i := range want {
		for j := range want[i] {
			api.AssertIsEqual(got[i][j], want[i][j])
		}
	}
}

type testSha256Circuit struct {
	Message []frontend.Variable
	Digest  []frontend.Variable `gnark:",public"`
}

func (self *testSha256Circuit) Define(api frontend.API) error {
	testAssertBytesEqual(api, sha256Sum(api, testByteWires(api, self.Message)), testByteWires(api, self.Digest))
	return nil
}

func TestSha256GadgetMatchesCryptoSha256(t *testing.T) {
	// lengths around the padding's block boundaries
	for _, size := range []int{0, 1, 55, 56, 63, 64, 65, 119, 120} {
		message := make([]byte, size)
		for i := range message {
			message[i] = byte(7*i + size)
		}
		digest := sha256.Sum256(message)
		compiled := testCompile(t, &testSha256Circuit{Message: make([]frontend.Variable, 8*size), Digest: make([]frontend.Variable, 8*sha256.Size)})
		if err := testSolved(t, compiled, &testSha256Circuit{Message: testAssignBits(message), Digest: testAssignBits(digest[:])}); err != nil {
			t.Errorf("size %d: %v", size, err)
		}
		// a mutated witness: the same message under another digest
		digest[0] ^= 1
		if err := testSolved(t, compiled, &testSha256Circuit{Message: testAssignBits(message), Digest: testAssignBits(digest[:])}); err == nil {
			t.Errorf("size %d: accepted a wrong digest", size)
		}
	}
}

type testHmacCircuit struct {
	Key     []frontend.Variable
	Message []frontend.Variable
	Mac     []frontend.Variable `gnark:",public"`
}

func (self *testHmacCircuit) Define(api frontend.API) error {
	key := newCircuitHmacKey(api, testByteWires(api, self.Key))
	testAssertBytesEqual(api, key.sum(api, testByteWires(api, self.Message)), testByteWires(api, self.Mac))
	return nil
}

func TestHmacGadgetMatchesCryptoHmac(t *testing.T) {
	// a 32-octet key is TLS 1.3's, a 48-octet key TLS 1.2's master secret
	for _, keySize := range []int{tlsSecretBytes, tlsMasterSecretBytes} {
		key := make([]byte, keySize)
		for i := range key {
			key[i] = byte(i)
		}
		message := []byte("a synthetic message for the gadget")
		mac := hmac.New(sha256.New, key)
		mac.Write(message)
		sum := mac.Sum(nil)
		compiled := testCompile(t, &testHmacCircuit{
			Key:     make([]frontend.Variable, 8*keySize),
			Message: make([]frontend.Variable, 8*len(message)),
			Mac:     make([]frontend.Variable, 8*sha256.Size),
		})
		assignment := &testHmacCircuit{Key: testAssignBits(key), Message: testAssignBits(message), Mac: testAssignBits(sum)}
		if err := testSolved(t, compiled, assignment); err != nil {
			t.Errorf("key size %d: %v", keySize, err)
		}
		key[0] ^= 1
		assignment = &testHmacCircuit{Key: testAssignBits(key), Message: testAssignBits(message), Mac: testAssignBits(sum)}
		if err := testSolved(t, compiled, assignment); err == nil {
			t.Errorf("key size %d: accepted a wrong key", keySize)
		}
	}
}

type testExpandCircuit struct {
	Secret  []frontend.Variable
	Context []frontend.Variable
	Out     []frontend.Variable `gnark:",public"`
	label   string
}

func (self *testExpandCircuit) Define(api frontend.API) error {
	key := newCircuitHmacKey(api, testByteWires(api, self.Secret))
	testAssertBytesEqual(api, key.expandLabel(api, self.label, testByteWires(api, self.Context), len(self.Out)/8), testByteWires(api, self.Out))
	return nil
}

func TestExpandLabelGadgetMatchesTheKeySchedule(t *testing.T) {
	secret := make([]byte, tlsSecretBytes)
	context := make([]byte, sha256.Size)
	for i := range secret {
		secret[i] = byte(3 * i)
		context[i] = byte(5 * i)
	}
	cases := []struct {
		label   string
		context []byte
		size    int
	}{
		{label: "s hs traffic", context: context, size: tlsSecretBytes},
		{label: "c ap traffic", context: context, size: tlsSecretBytes},
		{label: "key", size: tlsAes128KeyBytes},
		{label: "key", size: tlsChachaKeyBytes},
		{label: "iv", size: tlsIv13Bytes},
	}
	for _, c := range cases {
		out := tlsExpandLabel(secret, c.label, c.context, c.size)
		compiled := testCompile(t, &testExpandCircuit{
			Secret:  make([]frontend.Variable, 8*len(secret)),
			Context: make([]frontend.Variable, 8*len(c.context)),
			Out:     make([]frontend.Variable, 8*c.size),
			label:   c.label,
		})
		if err := testSolved(t, compiled, &testExpandCircuit{Secret: testAssignBits(secret), Context: testAssignBits(c.context), Out: testAssignBits(out)}); err != nil {
			t.Errorf("%s: %v", c.label, err)
		}
		out[0] ^= 1
		if err := testSolved(t, compiled, &testExpandCircuit{Secret: testAssignBits(secret), Context: testAssignBits(c.context), Out: testAssignBits(out)}); err == nil {
			t.Errorf("%s: accepted a wrong output", c.label)
		}
	}
}

type testParityCircuit struct {
	Terms  []frontend.Variable
	Parity frontend.Variable `gnark:",public"`
}

func (self *testParityCircuit) Define(api frontend.API) error {
	for _, term := range self.Terms {
		api.AssertIsBoolean(term)
	}
	api.AssertIsEqual(bitParity(api, self.Terms...), self.Parity)
	return nil
}

func TestBitParityIsTheXorOfItsTerms(t *testing.T) {
	for size := 1; size <= 9; size++ {
		compiled := testCompile(t, &testParityCircuit{Terms: make([]frontend.Variable, size)})
		for pattern := range 1 << size {
			terms := make([]frontend.Variable, size)
			parity := 0
			for i := range terms {
				bit := (pattern >> i) & 1
				terms[i] = bit
				parity ^= bit
			}
			if err := testSolved(t, compiled, &testParityCircuit{Terms: terms, Parity: parity}); err != nil {
				t.Errorf("%d terms, pattern %b: %v", size, pattern, err)
			}
			// the hint is the prover's, so a wrong parity must be unsatisfiable, not merely unsuggested
			if err := testSolved(t, compiled, &testParityCircuit{Terms: terms, Parity: 1 - parity}); err == nil {
				t.Errorf("%d terms, pattern %b: accepted the wrong parity", size, pattern)
			}
		}
	}
}

// SPEC.md 10.1: gnark v0.15.0's std/math/uints is unsound, and std/permutation/sha2 and std/hash/sha2
// are built on it with source identical to the fixed release, so nothing may reach them by accident.
func TestCircuitsImportNoGnarkStd(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	for _, name := range files {
		file, err := parser.ParseFile(fileSet, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			if strings.HasPrefix(strings.Trim(spec.Path.Value, `"`), "github.com/consensys/gnark/std") {
				t.Errorf("%s imports %s", name, spec.Path.Value)
			}
		}
	}
}

func TestGoModPinsGnarkToServersVersions(t *testing.T) {
	// a move past v0.15.0 raises gnark-crypto, bitset, go-colorable and go-isatty past server's and
	// sn's pins, which §4.7 forbids without a coordinated bump
	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"github.com/consensys/gnark v0.15.0", "github.com/consensys/gnark-crypto v0.20.1"} {
		if !strings.Contains(string(goMod), line) {
			t.Errorf("go.mod lacks %q", line)
		}
	}
}

func TestRootNeverRequiresThisModule(t *testing.T) {
	goMod, err := os.ReadFile(filepath.Join("..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(goMod), "smtpproof") {
		t.Error("the root's go.mod names smtpproof (D-REPO-2)")
	}
}

type testAesCircuit struct {
	Key   []frontend.Variable
	Block []frontend.Variable
	Out   []frontend.Variable `gnark:",public"`
}

func (self *testAesCircuit) Define(api frontend.API) error {
	roundKeys := aesExpandKey(api, testByteWires(api, self.Key))
	testAssertBytesEqual(api, aesEncrypt(api, &roundKeys, testByteWires(api, self.Block)), testByteWires(api, self.Out))
	return nil
}

func TestAesGadgetMatchesCryptoAes(t *testing.T) {
	compiled := testCompile(t, &testAesCircuit{
		Key:   make([]frontend.Variable, 128),
		Block: make([]frontend.Variable, 128),
		Out:   make([]frontend.Variable, 128),
	})
	t.Logf("aes: %d constraints with its key schedule", compiled.GetNbConstraints())
	for seed := range 8 {
		key := make([]byte, aes.BlockSize)
		block := make([]byte, aes.BlockSize)
		for i := range key {
			key[i] = byte(31*seed + 7*i)
			block[i] = byte(17*seed + 3*i + 1)
		}
		cipher, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, aes.BlockSize)
		cipher.Encrypt(out, block)
		if err := testSolved(t, compiled, &testAesCircuit{Key: testAssignBits(key), Block: testAssignBits(block), Out: testAssignBits(out)}); err != nil {
			t.Errorf("seed %d: %v", seed, err)
		}
		out[seed] ^= 1
		if err := testSolved(t, compiled, &testAesCircuit{Key: testAssignBits(key), Block: testAssignBits(block), Out: testAssignBits(out)}); err == nil {
			t.Errorf("seed %d: accepted a wrong block", seed)
		}
	}
}

func TestAesSboxCoefficientsReproduceTheTable(t *testing.T) {
	// over the integers, at every boolean input, independently of any circuit
	for input := range 256 {
		sum := int64(0)
		for high := range 16 {
			for low := range 16 {
				if input>>4&high == high && input&15&low == low {
					sum += aesSboxCoefficients[high][low]
				}
			}
		}
		if sum != int64(aesSbox[input]) {
			t.Errorf("input %#x: %d, want %#x", input, sum, aesSbox[input])
		}
	}
}

type testChachaCircuit struct {
	Key     []frontend.Variable
	Nonce   []frontend.Variable
	Counter [32]frontend.Variable
	Out     []frontend.Variable `gnark:",public"`
}

func (self *testChachaCircuit) Define(api frontend.API) error {
	var counter circuitWord
	for i := range counter {
		api.AssertIsBoolean(self.Counter[i])
		counter[i] = self.Counter[i]
	}
	testAssertBytesEqual(api, chachaBlock(api, testByteWires(api, self.Key), counter, testByteWires(api, self.Nonce)), testByteWires(api, self.Out))
	return nil
}

func TestChachaGadgetMatchesXCrypto(t *testing.T) {
	compiled := testCompile(t, &testChachaCircuit{
		Key:   make([]frontend.Variable, 256),
		Nonce: make([]frontend.Variable, 96),
		Out:   make([]frontend.Variable, 512),
	})
	t.Logf("chacha20: %d constraints per block", compiled.GetNbConstraints())
	key := make([]byte, tlsChachaKeyBytes)
	nonce := make([]byte, tlsIv13Bytes)
	for i := range key {
		key[i] = byte(5*i + 1)
	}
	for i := range nonce {
		nonce[i] = byte(9*i + 2)
	}
	keystream, err := recordKeystream(tlsSuiteChacha20Poly1305Sha256, key, nonce, 64)
	if err != nil {
		t.Fatal(err)
	}
	assignment := func(out []byte) *testChachaCircuit {
		circuit := &testChachaCircuit{Key: testAssignBits(key), Nonce: testAssignBits(nonce), Out: testAssignBits(out)}
		for i := range circuit.Counter {
			circuit.Counter[i] = 0
		}
		// recordKeystream starts at counter 1, as ChaCha20-Poly1305's data does
		circuit.Counter[0] = 1
		return circuit
	}
	if err := testSolved(t, compiled, assignment(keystream)); err != nil {
		t.Error(err)
	}
	keystream[0] ^= 1
	if err := testSolved(t, compiled, assignment(keystream)); err == nil {
		t.Error("accepted a wrong block")
	}
}

type testKeys13Circuit struct {
	HandshakeSecret []frontend.Variable
	ClientKey       []frontend.Variable
	ClientIv        []frontend.Variable
	ServerKey       []frontend.Variable
	ServerIv        []frontend.Variable
	ShtsHash        []frontend.Variable `gnark:",public"`
	HelloHash       []frontend.Variable `gnark:",public"`
	FinishedHash    []frontend.Variable `gnark:",public"`
}

func (self *testKeys13Circuit) Define(api frontend.API) error {
	keys := tls13CircuitKeys(api, testByteWires(api, self.HandshakeSecret), testByteWires(api, self.ShtsHash),
		testByteWires(api, self.HelloHash), testByteWires(api, self.FinishedHash), len(self.ClientKey)/8, true)
	testAssertBytesEqual(api, keys.clientKey, testByteWires(api, self.ClientKey))
	testAssertBytesEqual(api, keys.clientIv, testByteWires(api, self.ClientIv))
	testAssertBytesEqual(api, keys.serverKey, testByteWires(api, self.ServerKey))
	testAssertBytesEqual(api, keys.serverIv, testByteWires(api, self.ServerIv))
	return nil
}

// A real connection's Z1 inputs as an assignment: HS against a live crypto/tls server's handshake.
func testKeys13Assignment(statement *partStatement, witness *partWitness) *testKeys13Circuit {
	return &testKeys13Circuit{
		HandshakeSecret: testAssignBits(witness.handshakeSecret),
		ClientKey:       testAssignBits(witness.clientKey),
		ClientIv:        testAssignBits(witness.clientIv),
		ServerKey:       testAssignBits(witness.serverKey),
		ServerIv:        testAssignBits(witness.serverIv),
		ShtsHash:        testAssignBits(statement.session.shtsHash),
		HelloHash:       testAssignBits(statement.session.helloHash),
		FinishedHash:    testAssignBits(statement.session.finishedHash),
	}
}

func TestZ1CircuitDerivesARealConnectionsKeys(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 2)
		compiled := testCompile(t, &testKeys13Circuit{
			HandshakeSecret: make([]frontend.Variable, 8*tlsSecretBytes),
			ClientKey:       make([]frontend.Variable, 8*len(witness.clientKey)),
			ClientIv:        make([]frontend.Variable, 8*tlsIv13Bytes),
			ServerKey:       make([]frontend.Variable, 8*len(witness.serverKey)),
			ServerIv:        make([]frontend.Variable, 8*tlsIv13Bytes),
			ShtsHash:        make([]frontend.Variable, 8*sha256.Size),
			HelloHash:       make([]frontend.Variable, 8*sha256.Size),
			FinishedHash:    make([]frontend.Variable, 8*sha256.Size),
		})
		t.Logf("%s: Z1 is %d constraints with both directions", leg.name, compiled.GetNbConstraints())
		if err := testSolved(t, compiled, testKeys13Assignment(statement, witness)); err != nil {
			t.Fatalf("%s: %v", leg.name, err)
		}

		// mutated witnesses: each of these is refused in the circuit as relation_test.go refuses it
		mutations := []struct {
			name   string
			mutate func(statement *partStatement, witness *partWitness)
		}{
			{name: "another HS", mutate: func(statement *partStatement, witness *partWitness) { witness.handshakeSecret[0] ^= 1 }},
			{name: "a substituted client key", mutate: func(statement *partStatement, witness *partWitness) { witness.clientKey[0] ^= 1 }},
			{name: "a substituted client iv", mutate: func(statement *partStatement, witness *partWitness) { witness.clientIv[0] ^= 1 }},
			{name: "a substituted server key", mutate: func(statement *partStatement, witness *partWitness) { witness.serverKey[0] ^= 1 }},
			{name: "another H_shts", mutate: func(statement *partStatement, witness *partWitness) {
				statement.session.shtsHash = bytes.Clone(statement.session.shtsHash)
				statement.session.shtsHash[0] ^= 1
			}},
			{name: "another H_sf", mutate: func(statement *partStatement, witness *partWitness) {
				statement.session.finishedHash = bytes.Clone(statement.session.finishedHash)
				statement.session.finishedHash[0] ^= 1
			}},
		}
		for _, mutation := range mutations {
			statement, witness := capture.part(t, 2)
			witness.clientIv = bytes.Clone(witness.clientIv)
			witness.serverKey = bytes.Clone(witness.serverKey)
			mutation.mutate(statement, witness)
			if err := testSolved(t, compiled, testKeys13Assignment(statement, witness)); err == nil {
				t.Errorf("%s: %s: accepted", leg.name, mutation.name)
			}
		}

		// a HelloRetryRequest moves H_sh and H_sf onto a message_hash, which the edge must follow
		retried := *leg
		retried.name += " after a retry"
		retried.serverTls = func(t *testing.T) *tls.Config {
			config := leg.serverTls(t)
			config.CurvePreferences = []tls.CurveID{tls.CurveP256}
			return config
		}
		statement, witness = testBdatCapture(t, &retried).part(t, 2)
		if err := testSolved(t, compiled, testKeys13Assignment(statement, witness)); err != nil {
			t.Errorf("%s: %v", retried.name, err)
		}
	}
}
