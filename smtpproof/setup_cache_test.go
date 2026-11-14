// A prover host's cache (DESIGN-DETAILS 3.2.7, steps 3 and 7), held to ProofKeys.tla's twins: an entry of
// another circuit's digest is no key (3.1 E, StaleCache), a torn or partial write is no entry
// (PartialStands), and a changed file is no key.

package smtpproof

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// One shape's set, checked on a host whose cache then holds its entry.
func testCheckedShape(t *testing.T, newCircuit func() frontend.Circuit) (*keyHost, *KeySet, *keySetCircuit) {
	t.Helper()
	circuit := testKeySetCircuit(t, 0, &ShapeSettings{Kind: ShapeKindKey, Family: ShapeFamilyChacha20, Version: tlsVersion13, ClientBlocks: 1}, newCircuit)
	made := testMakeKeySet(t, []*keySetCircuit{circuit})
	host := testHostHolding(t, testKeySettings(), made.id, made.files(t))
	keySet := testOpenOnHost(t, host, made.id, []*keySetCircuit{circuit})
	if err := keySet.ensureShape(context.Background(), circuit); err != nil {
		t.Fatal(err)
	}
	return host, keySet, circuit
}

// The paths of a shape's cache entry.
func testCachePaths(host *keyHost, keySet *KeySet, circuit *keySetCircuit) (string, string, string) {
	stem := filepath.Join(host.cache.directory, keyCacheShapeStem(circuit.digest, keySet.shapeEntry(circuit.name).ProvingKey.Sha256))
	return stem + ".ok", stem + ".pk", stem + ".r1cs"
}

// 3.1 E, as ProofKeysWritten-StaleCache reaches it: a build of circuit c1 checks set A and caches its key;
// a build of circuit c2 that still pins A is installed over it. The file c1's check wrote is there, and
// c2 neither proves under it nor takes it at its check.
func TestCacheEntryOfAnotherCircuitIsNoKey(t *testing.T) {
	host, keySet, square := testCheckedShape(t, testSquareCircuit)
	okPath, _, _ := testCachePaths(host, keySet, square)
	if _, err := keySet.backend.keysFor(square.shape); err != nil {
		t.Fatalf("c1's own keys: %v", err)
	}
	// the same shape compiled from another source: its table names c2's digest
	cube := testKeySetCircuit(t, 0, square.entry, testCubeCircuit)
	if cube.digest == square.digest {
		t.Fatal("the two circuits share a digest")
	}
	upgraded := testOpenOnHost(t, host, keySet.id, []*keySetCircuit{cube})
	if _, err := upgraded.backend.keysFor(cube.shape); !errors.Is(err, errNoKeys) {
		t.Errorf("c2 took c1's key: %v", err)
	}
	if err := upgraded.ensureShape(context.Background(), cube); !isKeyRefusal(err) {
		t.Errorf("c2's check of a set made for c1: %v", err)
	}
	if _, err := upgraded.backend.keysFor(cube.shape); !errors.Is(err, errNoKeys) {
		t.Errorf("c2 took c1's key after its check: %v", err)
	}
	// c1's entry stands, untaken, for a build of c1
	if _, err := os.Stat(okPath); err != nil {
		t.Errorf("c1's entry: %v", err)
	}
	if !host.cache.shapeReady(square.digest, keySet.shapeEntry(square.name).ProvingKey.Sha256) {
		t.Error("c1's entry is not ready")
	}
}

// ProofKeysTwin-PartialStands: a crash between the writes leaves no entry, and the next check writes one.
func TestAPartialFileIsNoEntry(t *testing.T) {
	host, keySet, circuit := testCheckedShape(t, testSquareCircuit)
	okPath, pkPath, r1csPath := testCachePaths(host, keySet, circuit)
	pk, err := os.ReadFile(pkPath)
	if err != nil {
		t.Fatal(err)
	}
	// the process died after the dump's partial file, before the renames and the .ok
	for _, path := range []string{okPath, pkPath, r1csPath} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	partialPath := pkPath + keyCachePartialMark + "0123456789abcdef"
	if err := os.WriteFile(partialPath, pk, 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := testOpenOnHost(t, host, keySet.id, []*keySetCircuit{circuit})
	if _, err := fresh.backend.keysFor(circuit.shape); !errors.Is(err, errNoKeys) {
		t.Errorf("a partial file gave keys: %v", err)
	}
	// the same with every file renamed and no .ok
	if err := os.WriteFile(pkPath, pk, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.backend.keysFor(circuit.shape); !errors.Is(err, errNoKeys) {
		t.Errorf("an entry with no .ok gave keys: %v", err)
	}
	// the next run's check sweeps the partial file away and writes the entry again
	host.cache = newKeyCache(host.cache.directory)
	if err := fresh.ensureShape(context.Background(), circuit); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(partialPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the partial file stayed: %v", err)
	}
	if _, err := fresh.backend.keysFor(circuit.shape); err != nil {
		t.Errorf("after the check: %v", err)
	}
}

// A torn or changed file under a whole .ok is no key, and the shape is checked again.
func TestACachedFileIsTakenOnlyWhileItIsTheOneItsOkRecords(t *testing.T) {
	for name, damage := range map[string]func(path string, content []byte) []byte{
		"a torn dump":    func(path string, content []byte) []byte { return content[:len(content)/2] },
		"a changed dump": func(path string, content []byte) []byte { content[len(content)/2] ^= 1; return content },
		"a torn circuit": func(path string, content []byte) []byte { return content[:len(content)-1] },
		"a record of another key": func(path string, content []byte) []byte {
			return []byte(strings.Replace(string(content), "\"proving_key_sha256\":\"", "\"proving_key_sha256\":\"0", 1))
		},
	} {
		host, keySet, circuit := testCheckedShape(t, testSquareCircuit)
		okPath, pkPath, r1csPath := testCachePaths(host, keySet, circuit)
		path := pkPath
		switch {
		case strings.Contains(name, "circuit"):
			path = r1csPath
		case strings.Contains(name, "record"):
			path = okPath
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, damage(path, content), 0o600); err != nil {
			t.Fatal(err)
		}
		fresh := testOpenOnHost(t, host, keySet.id, []*keySetCircuit{circuit})
		_, err = fresh.backend.keysFor(circuit.shape)
		ready := host.cache.shapeReady(circuit.digest, keySet.shapeEntry(circuit.name).ProvingKey.Sha256)
		if !errors.Is(err, errNoKeys) || ready {
			t.Errorf("%s: %v, ready %v", name, err, ready)
		}
		// its check writes the entry again
		if err := fresh.ensureShape(context.Background(), circuit); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := fresh.backend.keysFor(circuit.shape); err != nil {
			t.Errorf("%s, checked again: %v", name, err)
		}
	}
}

// An entry's circuit is the one its digest names, and its key is gnark's dump, which loads as it was.
func TestTheCacheHoldsTheCheckedCircuitAndTheKeysDump(t *testing.T) {
	host, keySet, circuit := testCheckedShape(t, testSquareCircuit)
	_, _, r1csPath := testCachePaths(host, keySet, circuit)
	record, err := host.cache.shapeRecord(circuit.digest, keySet.shapeEntry(circuit.name).ProvingKey.Sha256)
	if err != nil {
		t.Fatal(err)
	}
	if record.Files[1].Sha256 != circuit.digest || filepath.Base(r1csPath) != record.Files[1].Name {
		t.Errorf("the circuit's record %+v", record.Files[1])
	}
	r1cs, provingKey, err := host.cache.loadShape(circuit.digest, keySet.shapeEntry(circuit.name).ProvingKey.Sha256)
	if err != nil {
		t.Fatal(err)
	}
	edge := (&testKeySetMade{directory: keySet.directory, id: keySet.id, circuits: []*keySetCircuit{circuit}}).open(t)
	verifyingKeys, err := edge.verifyingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := testProveSquare(t, &shapeKeys{compiled: r1cs, provingKey: provingKey}, verifyingKeys[*circuit.shape].verifyingKey); err != nil {
		t.Errorf("a proof from the loaded entry: %v", err)
	}
	// a record that names another digest's circuit is no record of this entry
	if _, _, err := host.cache.loadShape(circuit.digest[:63]+"0", keySet.shapeEntry(circuit.name).ProvingKey.Sha256); !errors.Is(err, errNoKeys) {
		t.Errorf("another digest's load: %v", err)
	}
}

// The phase 1 commons a check cached is taken for another shape's check, and a changed one is not.
func TestPhase1CommonsAreCachedAndCheckedWhenTaken(t *testing.T) {
	host, keySet, _ := testCheckedShape(t, testSquareCircuit)
	phase1 := keySet.manifest.Phase1[0]
	phase1Sha256 := keyCachePhase1Hash(phase1.DomainSize, keySet.beacon, phase1.Contributions)
	if _, ok := host.cache.loadPhase1(phase1Sha256, phase1.DomainSize); !ok {
		t.Fatal("no commons")
	}
	if _, ok := host.cache.loadPhase1(phase1Sha256, 2*phase1.DomainSize); ok {
		t.Error("took commons for another domain")
	}
	path := filepath.Join(host.cache.directory, "phase1-"+phase1Sha256+".commons")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-1] ^= 1
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := host.cache.loadPhase1(phase1Sha256, phase1.DomainSize); ok {
		t.Error("took changed commons")
	}
	// another beacon or another contribution is another phase 1
	if keyCachePhase1Hash(phase1.DomainSize, []byte("another beacon"), phase1.Contributions) == phase1Sha256 ||
		keyCachePhase1Hash(2*phase1.DomainSize, keySet.beacon, phase1.Contributions) == phase1Sha256 {
		t.Error("two phase 1s share a hash")
	}
}

// A load that finds the cache wrong sends the shape back to the idle check (DESIGN-DETAILS 3.5), which
// writes it again.
func TestALostCacheFileSendsTheShapeBackToTheCheck(t *testing.T) {
	host, keySet, circuit := testCheckedShape(t, testSquareCircuit)
	_, pkPath, _ := testCachePaths(host, keySet, circuit)
	if err := os.Remove(pkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := keySet.backend.keysFor(circuit.shape); !errors.Is(err, errNoKeys) {
		t.Errorf("keys with the dump gone: %v", err)
	}
	if keySet.shapeState(circuit.name).ready {
		t.Error("the shape stayed ready")
	}
	if err := keySet.ensureShape(context.Background(), circuit); err != nil {
		t.Fatal(err)
	}
	if _, err := keySet.backend.keysFor(circuit.shape); err != nil {
		t.Errorf("after the check: %v", err)
	}
}

// Bits whose parity, through both hints, is public.
type testHintCircuit struct {
	Bits   [5]frontend.Variable
	Parity frontend.Variable `gnark:",public"`
}

func (self *testHintCircuit) Define(api frontend.API) error {
	for _, bit := range self.Bits {
		api.AssertIsBoolean(bit)
	}
	parity := bitParity(api, self.Bits[0], self.Bits[1], self.Bits[2], self.Bits[3], self.Bits[4])
	api.AssertIsEqual(pinWire(api, parity), self.Parity)
	return nil
}

// A circuit read back from the cache solves with its hints, which it names by their fixed ids alone, and
// its octets are the same after the trip: what a send proves with is what the check hashed.
func TestACachedCircuitSolvesWithItsHints(t *testing.T) {
	compiled := testCompile(t, &testHintCircuit{})
	encoded, digest, err := circuitDigest(compiled)
	if err != nil {
		t.Fatal(err)
	}
	read := groth16.NewCS(ecc.BN254)
	if _, err := read.ReadFrom(bytes.NewReader(encoded)); err != nil {
		t.Fatal(err)
	}
	again, againDigest, err := circuitDigest(read)
	if err != nil || againDigest != digest || !bytes.Equal(again, encoded) {
		t.Errorf("the trip changed the circuit: %v", err)
	}
	hints := map[solver.HintID]string{}
	for id, name := range read.(*cs.R1CS).MHintsDependencies {
		hints[id] = name
	}
	if len(hints) != 2 || hints[hintIdIdentity] == "" || hints[hintIdHighBits] == "" || bytes.Contains(encoded, []byte("smtpproof")) {
		t.Errorf("hints %v", hints)
	}
	for _, c := range []struct {
		bits   [5]int
		parity int
		solves bool
	}{
		{bits: [5]int{1, 0, 1, 1, 0}, parity: 1, solves: true},
		{bits: [5]int{1, 1, 1, 1, 0}, parity: 0, solves: true},
		{bits: [5]int{1, 1, 1, 1, 0}, parity: 1, solves: false},
	} {
		assignment := &testHintCircuit{Parity: c.parity}
		for i, bit := range c.bits {
			assignment.Bits[i] = bit
		}
		if err := testSolved(t, read, assignment); (err == nil) != c.solves {
			t.Errorf("%v parity %d: %v", c.bits, c.parity, err)
		}
	}
}
