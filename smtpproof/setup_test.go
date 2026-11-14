// A release's KeySet end to end, over two circuits small enough for a real ceremony in a test: the
// edge's setup writes it, a prover host verifies each transcript against the circuit it compiled and
// caches the keys that check produced, and anything the check did not produce is refused.

package smtpproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// A Verifier with no KeySet, as server holds one until a production setup exists.
func testNoKeysVerifier(t *testing.T) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(DefaultVerifierSettings(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

// Two tiny circuits, each under a shape of its own that no production shape equals.
func testKeySetCircuits() []*keySetCircuit {
	compile := func(circuit frontend.Circuit) func() (constraint.ConstraintSystem, error) {
		return func() (constraint.ConstraintSystem, error) {
			return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		}
	}
	return []*keySetCircuit{
		{name: "square", shape: &partShape{kind: 101}, compile: compile(&testSetupCircuit{})},
		{name: "cube", shape: &partShape{kind: 102}, compile: compile(&testSetupOtherCircuit{})},
	}
}

// A KeySet directory written by the edge's ceremony, opened under its pin.
func testKeySet(t *testing.T) (*KeySet, []byte) {
	t.Helper()
	testNeedCircuits(t)
	directory := t.TempDir()
	pin, err := runKeySetSetup(context.Background(), directory, []byte("a synthetic beacon"), testKeySetCircuits())
	if err != nil {
		t.Fatal(err)
	}
	keySet, err := openKeySet(directory, pin, testKeySetCircuits())
	if err != nil {
		t.Fatal(err)
	}
	return keySet, pin
}

// Rewrites keyset.json through edit, and opens the result under its new pin, as a release pinning a
// tampered KeySet would.
func testRepinned(t *testing.T, keySet *KeySet, edit func(manifest *keySetManifest)) *KeySet {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(keySet.directory, keySetManifestName))
	if err != nil {
		t.Fatal(err)
	}
	manifest := &keySetManifest{}
	if err := json.Unmarshal(encoded, manifest); err != nil {
		t.Fatal(err)
	}
	edit(manifest)
	if encoded, err = json.Marshal(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keySet.directory, keySetManifestName), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(encoded)
	repinned, err := openKeySet(keySet.directory, pin[:], keySet.circuits)
	if err != nil {
		t.Fatal(err)
	}
	return repinned
}

// Proves a satisfying assignment of the square circuit and verifies it under the given verifying key.
func testProveSquare(t *testing.T, keys *shapeKeys, verifyingKey groth16.VerifyingKey) error {
	t.Helper()
	full, err := frontend.NewWitness(&testSetupCircuit{Secret: 3, Public: 9}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(keys.compiled, keys.provingKey, full)
	if err != nil {
		t.Fatal(err)
	}
	public, err := full.Public()
	if err != nil {
		t.Fatal(err)
	}
	return groth16.Verify(proof, verifyingKey, public)
}

func TestAKeySetTheProverVerifiedProvesUnderTheEdgesKeys(t *testing.T) {
	keySet, _ := testKeySet(t)
	cache := t.TempDir()
	circuits := keySet.circuits
	source := newCachedProvingKeys(keySet, cache)
	// before its check, a prover host holds no proving key, however complete the directory is
	if _, err := source.keysFor(circuits[0].shape); err != errNoKeys {
		t.Fatalf("keys before the transcript was checked: %v", err)
	}
	if err := keySet.VerifyProvingKeys(context.Background(), cache); err != nil {
		t.Fatal(err)
	}
	keys, err := source.keysFor(circuits[0].shape)
	if err != nil {
		t.Fatal(err)
	}
	verifyingKeys, err := keySet.verifyingKeys()
	if err != nil {
		t.Fatal(err)
	}
	if err := testProveSquare(t, keys, verifyingKeys[*circuits[0].shape].verifyingKey); err != nil {
		t.Errorf("a proof under the verified key failed the edge's key: %v", err)
	}
	// a second check finds the cache and leaves it
	if err := keySet.VerifyProvingKeys(context.Background(), cache); err != nil {
		t.Fatal(err)
	}

	// the constructors take the same KeySet
	verifier, err := NewVerifier(DefaultVerifierSettings(), keySet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.backend.(*groth16Backend).keysFor(circuits[1].shape); err != nil {
		t.Errorf("the verifier holds no key for the second circuit: %v", err)
	}
	prover := NewProver(DefaultProverSettings(), keySet, cache)
	if _, err := prover.backend.(*groth16Backend).keysFor(circuits[1].shape); err != nil {
		t.Errorf("the prover holds no key for the second circuit: %v", err)
	}
}

func TestOpenKeySetRefusesAnythingButItsPin(t *testing.T) {
	keySet, pin := testKeySet(t)
	other := sha256.Sum256([]byte("another release"))
	for name, candidate := range map[string][]byte{"no pin": nil, "a short pin": pin[:31], "another pin": other[:]} {
		if _, err := openKeySet(keySet.directory, candidate, keySet.circuits); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, err := OpenKeySet(t.TempDir(), pin); err == nil {
		t.Error("opened an empty directory")
	}
}

func TestAKeySetRefusesATamperedFile(t *testing.T) {
	keySet, _ := testKeySet(t)
	entry := keySet.manifest.Shapes[0]
	flip := func(file *keySetFile) {
		path := filepath.Join(keySet.directory, file.Name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		content[len(content)/2] ^= 1
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	flip(entry.VerifyingKey)
	if _, err := keySet.verifyingKeys(); err == nil {
		t.Error("the edge took a tampered verifying key")
	}
	flip(entry.Contributions[0])
	if err := keySet.VerifyProvingKeys(context.Background(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "is not the file") {
		t.Errorf("a tampered contribution: %v", err)
	}
}

func TestAKeySetRefusesATranscriptOfAnotherCircuit(t *testing.T) {
	// the square's entry naming the cube's phase 2: the check runs against the circuit compiled here, so
	// a transcript made for another fails however well formed it is
	keySet, _ := testKeySet(t)
	repinned := testRepinned(t, keySet, func(manifest *keySetManifest) {
		manifest.Shapes[0].Contributions = manifest.Shapes[1].Contributions
	})
	if err := repinned.VerifyProvingKeys(context.Background(), t.TempDir()); err == nil {
		t.Error("verified a transcript of another circuit")
	}
}

func TestAKeySetRefusesKeysItsTranscriptDoesNotFix(t *testing.T) {
	// a well-formed proving key of another circuit, named by its true hash: the transcript fixes other
	// keys, so the published one is refused and nothing is cached
	keySet, _ := testKeySet(t)
	repinned := testRepinned(t, keySet, func(manifest *keySetManifest) {
		manifest.Shapes[0].ProvingKey = manifest.Shapes[1].ProvingKey
	})
	cache := t.TempDir()
	if err := repinned.VerifyProvingKeys(context.Background(), cache); err == nil || !strings.Contains(err.Error(), "not the ones keyset.json names") {
		t.Errorf("err %v", err)
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Errorf("cached %d files", len(entries))
	}
}

func TestAKeySetRefusesAFileOutsideItsDirectory(t *testing.T) {
	keySet, _ := testKeySet(t)
	for _, name := range []string{"../keyset.json", keySetManifestName, filepath.Join("sub", "file")} {
		if _, err := keySet.readFile(&keySetFile{Name: name, Sha256: hex.EncodeToString(make([]byte, sha256.Size))}); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

func TestACachedKeyIsTrustedOnlyWhileItIsTheVerifiedOne(t *testing.T) {
	keySet, _ := testKeySet(t)
	cache := t.TempDir()
	if err := keySet.VerifyProvingKeys(context.Background(), cache); err != nil {
		t.Fatal(err)
	}
	path := cachedProvingKeyPath(cache, keySet.manifest.Shapes[0])
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)/2] ^= 1
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newCachedProvingKeys(keySet, cache).keysFor(keySet.circuits[0].shape); err != errNoKeys {
		t.Errorf("a changed cache file gave keys: %v", err)
	}
}

func TestProductionShapesHaveDistinctKeySetNames(t *testing.T) {
	seen := map[string]bool{}
	for _, circuit := range productionKeySetCircuits() {
		if seen[circuit.name] {
			t.Errorf("%s twice", circuit.name)
		}
		seen[circuit.name] = true
	}
}

// The ceremony and verification over a real shape, pi1 under ChaCha20, then a proof of a real EHLO
// that the edge's key accepts. It takes minutes, so it stays out of the ordinary run: set
// SMTPPROOF_FULL to run it.
func TestAKeySetProvesARealEhlo(t *testing.T) {
	if os.Getenv("SMTPPROOF_FULL") == "" {
		t.Skip("set SMTPPROOF_FULL to run a ceremony at a real shape's size")
	}
	testNeedCircuits(t)
	shape := partShapes()[1]
	circuits := []*keySetCircuit{productionKeySetCircuits()[1]}
	directory := t.TempDir()
	pin, err := runKeySetSetup(context.Background(), directory, []byte("a synthetic beacon"), circuits)
	if err != nil {
		t.Fatal(err)
	}
	keySet, err := openKeySet(directory, pin, circuits)
	if err != nil {
		t.Fatal(err)
	}
	cache := t.TempDir()
	if err := keySet.VerifyProvingKeys(context.Background(), cache); err != nil {
		t.Fatal(err)
	}
	prover := NewProver(DefaultProverSettings(), keySet, cache)
	verifier, err := NewVerifier(DefaultVerifierSettings(), keySet)
	if err != nil {
		t.Fatal(err)
	}
	statement, witness := testBdatCapture(t, testTlsLegs()[1]).part(t, 1)
	if found, err := partShapeFor(statement); err != nil || *found != *shape {
		t.Fatalf("pi1 fits %+v, %v", found, err)
	}
	proof, err := prover.backend.provePart(context.Background(), statement, witness)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.backend.verifyPart(context.Background(), statement, proof); err != nil {
		t.Errorf("the edge refused a proof under keys from its own KeySet: %v", err)
	}
}

func TestAKeySetRefusesAManifestOutOfShape(t *testing.T) {
	// even pinned, a keyset.json whose hash could name a path, or whose shape lacks a key, is refused
	// before anything reads a file it names
	for name, edit := range map[string]func(manifest *keySetManifest){
		"a hash that walks out of the cache": func(manifest *keySetManifest) { manifest.Shapes[0].ProvingKey.Sha256 = "../../outside" },
		"an upper-case hash": func(manifest *keySetManifest) {
			manifest.Shapes[0].VerifyingKey.Sha256 = strings.ToUpper(manifest.Shapes[0].VerifyingKey.Sha256)
		},
		"no proving key":                 func(manifest *keySetManifest) { manifest.Shapes[0].ProvingKey = nil },
		"no contribution":                func(manifest *keySetManifest) { manifest.Shapes[1].Contributions = nil },
		"a shape twice":                  func(manifest *keySetManifest) { manifest.Shapes[1].Name = manifest.Shapes[0].Name },
		"a phase 1 with no contribution": func(manifest *keySetManifest) { manifest.Phase1[0].Contributions = nil },
	} {
		keySet, _ := testKeySet(t)
		encoded, err := os.ReadFile(filepath.Join(keySet.directory, keySetManifestName))
		if err != nil {
			t.Fatal(err)
		}
		manifest := &keySetManifest{}
		if err := json.Unmarshal(encoded, manifest); err != nil {
			t.Fatal(err)
		}
		edit(manifest)
		if encoded, err = json.Marshal(manifest); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keySet.directory, keySetManifestName), encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		pin := sha256.Sum256(encoded)
		if _, err := openKeySet(keySet.directory, pin[:], keySet.circuits); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}
