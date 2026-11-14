// Key sets end to end (DESIGN-DETAILS 3.2.7), over circuits small enough for a real ceremony in a test:
// the edge's setup writes a set, -extend adds to it, the edge opens it, a prover host checks each shape's
// transcript against the circuit it compiled and caches the keys that check produced, and anything the
// check did not produce is refused. setup_cache_test.go holds the cache's own cases, and
// setup_fetch_test.go the fetch's.

package smtpproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/urnetwork/sidecar"
)

// The domain every test key set's phase 1 is for, which each test circuit fits.
const testKeySetDomainSize = 8

// A tiny circuit standing for one catalog shape, by entry's name, kind, family and version, under a part
// shape of its own that no production shape equals, with the digest a table of this build would give it.
func testKeySetCircuit(t testing.TB, index int, entry *ShapeSettings, newCircuit func() frontend.Circuit) *keySetCircuit {
	t.Helper()
	compile := func() (constraint.ConstraintSystem, error) {
		return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, newCircuit())
	}
	compiled, err := compile()
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := circuitDigest(compiled)
	if err != nil {
		t.Fatal(err)
	}
	return &keySetCircuit{name: entry.Name(), entry: entry, shape: &partShape{kind: partKind(100 + index)}, compile: compile, digest: digest}
}

func testSquareCircuit() frontend.Circuit {
	return &testSetupCircuit{}
}

func testCubeCircuit() frontend.Circuit {
	return &testSetupOtherCircuit{}
}

// Both families whole, each shape a square circuit: aes128gcm's with TLS 1.2's key shape, and chacha20's,
// in the catalog's order.
func testFamilyKeySetCircuits(t testing.TB) []*keySetCircuit {
	t.Helper()
	entries := []*ShapeSettings{
		{Kind: ShapeKindKey, Family: ShapeFamilyAes128Gcm, Version: tlsVersion13, ClientBlocks: 1},
		{Kind: ShapeKindKey, Family: ShapeFamilyChacha20, Version: tlsVersion13, ClientBlocks: 1},
		{Kind: ShapeKindKey, Family: ShapeFamilyAes128Gcm, Version: tlsVersion12, ClientBlocks: 1},
		{Kind: ShapeKindEnvelope, Family: ShapeFamilyAes128Gcm, ClientBlocks: 1},
		{Kind: ShapeKindMessage, Family: ShapeFamilyAes128Gcm, ClientBlocks: 1},
		{Kind: ShapeKindHeader, Family: ShapeFamilyAes128Gcm, RestBlocks: 1},
		{Kind: ShapeKindBody, Family: ShapeFamilyAes128Gcm, BodyBlocks: 1},
		{Kind: ShapeKindEnvelope, Family: ShapeFamilyChacha20, ClientBlocks: 1},
		{Kind: ShapeKindMessage, Family: ShapeFamilyChacha20, ClientBlocks: 1},
		{Kind: ShapeKindHeader, Family: ShapeFamilyChacha20, RestBlocks: 1},
		{Kind: ShapeKindBody, Family: ShapeFamilyChacha20, BodyBlocks: 1},
	}
	var circuits []*keySetCircuit
	for i, entry := range entries {
		circuits = append(circuits, testKeySetCircuit(t, i, entry, testSquareCircuit))
	}
	return circuits
}

// The circuits of one family in a family list.
func testFamilyOf(circuits []*keySetCircuit, family ShapeFamily) []*keySetCircuit {
	return slices.DeleteFunc(slices.Clone(circuits), func(circuit *keySetCircuit) bool { return circuit.entry.Family != family })
}

// A key set the edge's ceremony wrote over circuits: its directory and id.
type testKeySetMade struct {
	directory string
	id        []byte
	circuits  []*keySetCircuit
}

func testMakeKeySet(t *testing.T, circuits []*keySetCircuit) *testKeySetMade {
	t.Helper()
	testNeedCircuits(t)
	directory := t.TempDir()
	id, err := runKeySetSetup(context.Background(), directory, []byte("a synthetic beacon"), testKeySetDomainSize, circuits)
	if err != nil {
		t.Fatal(err)
	}
	return &testKeySetMade{directory: directory, id: id, circuits: circuits}
}

// The set as the edge opens it.
func (self *testKeySetMade) open(t *testing.T) *KeySet {
	t.Helper()
	keySet, err := openKeySet(self.directory, self.id, DefaultProofSettings(), testKeySetDomainSize, self.circuits)
	if err != nil {
		t.Fatal(err)
	}
	return keySet
}

// Every file of the set's directory by name.
func (self *testKeySetMade) files(t *testing.T) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(self.directory)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(self.directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = content
	}
	return files
}

// Key settings for a test host: the defaults, its transcripts kept unless a test says otherwise.
func testKeySettings() *KeySettings {
	settings := DefaultKeySettings()
	settings.KeepTranscripts = true
	return settings
}

// A prover host that fetches nothing, its key directory holding files as a set published them.
func testHostHolding(t *testing.T, settings *KeySettings, id []byte, files map[string][]byte) *keyHost {
	t.Helper()
	host := newKeyHost(settings, t.TempDir())
	directory := host.keySetDirectory(id)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return host
}

// The set opened on a host, over circuits.
func testOpenOnHost(t *testing.T, host *keyHost, id []byte, circuits []*keySetCircuit) *KeySet {
	t.Helper()
	keySet, err := host.openKeySet(context.Background(), id, DefaultProofSettings(), testKeySetDomainSize, circuits)
	if err != nil {
		t.Fatal(err)
	}
	return keySet
}

// Rewrites keyset.json through edit and returns the edited set under its new id, as a release pinning a
// tampered set would.
func testRepinned(t *testing.T, made *testKeySetMade, edit func(manifest *keySetManifest)) *testKeySetMade {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(made.directory, keySetManifestName))
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
	if err := os.WriteFile(filepath.Join(made.directory, keySetManifestName), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	id := sha256.Sum256(encoded)
	return &testKeySetMade{directory: made.directory, id: id[:], circuits: made.circuits}
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

// A Verifier holding one key set with no keys, as server would hold a set whose shapes its build lacks:
// it opens sessions under the set's id and refuses every part.
func testNoKeysVerifier(t *testing.T) (*Verifier, []byte) {
	t.Helper()
	id := sha256.Sum256([]byte("a key set with no keys"))
	proof := DefaultProofSettings()
	verifier := &Verifier{settings: DefaultVerifierSettings(), now: time.Now, keySets: map[string]*verifierKeySet{
		hex.EncodeToString(id[:]): {id: id[:], proof: proof, backend: newGroth16Backend(proof)},
	}}
	return verifier, id[:]
}

func TestAKeySetTheHostCheckedProvesUnderTheEdgesKeys(t *testing.T) {
	circuits := testFamilyKeySetCircuits(t)
	made := testMakeKeySet(t, circuits)
	// the ceremony publishes no proving key
	for name := range made.files(t) {
		if strings.HasSuffix(name, ".pk") {
			t.Errorf("the ceremony wrote %s", name)
		}
	}
	host := testHostHolding(t, testKeySettings(), made.id, made.files(t))
	keySet := testOpenOnHost(t, host, made.id, circuits)
	chacha := testFamilyOf(circuits, ShapeFamilyChacha20)
	// before its check, a prover host holds no proving key, however complete the directory is
	if _, err := keySet.backend.keysFor(chacha[0].shape); !errors.Is(err, errNoKeys) {
		t.Fatalf("keys before the transcript was checked: %v", err)
	}
	if err := keySet.EnsureKeys(context.Background(), ShapeFamilyChacha20); err != nil {
		t.Fatal(err)
	}
	edge := made.open(t)
	verifyingKeys, err := edge.verifyingKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, circuit := range chacha {
		keys, err := keySet.backend.keysFor(circuit.shape)
		if err != nil {
			t.Fatalf("%s: %v", circuit.name, err)
		}
		if err := testProveSquare(t, keys, verifyingKeys[*circuit.shape].verifyingKey); err != nil {
			t.Errorf("%s: a proof under the cached key failed the edge's key: %v", circuit.name, err)
		}
	}
	// the other family was never checked
	if _, err := keySet.backend.keysFor(testFamilyOf(circuits, ShapeFamilyAes128Gcm)[0].shape); !errors.Is(err, errNoKeys) {
		t.Errorf("keys of a family nothing checked: %v", err)
	}
	// a second check finds the cache and leaves it
	if err := keySet.EnsureKeys(context.Background(), ShapeFamilyChacha20); err != nil {
		t.Fatal(err)
	}
	// the edge's key set carries no prover host's cache
	if err := edge.EnsureKeys(context.Background(), ShapeFamilyChacha20); err == nil {
		t.Error("the edge's key set checked keys")
	}
}

func TestOpenKeySetRefusesAnythingButItsId(t *testing.T) {
	made := testMakeKeySet(t, testFamilyKeySetCircuits(t)[:1])
	other := sha256.Sum256([]byte("another release"))
	for name, candidate := range map[string][]byte{"no id": nil, "a short id": made.id[:31], "another id": other[:]} {
		if _, err := openKeySet(made.directory, candidate, DefaultProofSettings(), testKeySetDomainSize, made.circuits); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, err := OpenKeySet(t.TempDir(), made.id); err == nil {
		t.Error("opened an empty directory")
	}
	// a set made for another domain than this build's is no set of its
	if _, err := openKeySet(made.directory, made.id, DefaultProofSettings(), 2*testKeySetDomainSize, made.circuits); err == nil {
		t.Error("opened a set of another domain")
	}
}

func TestAKeySetRefusesATamperedFile(t *testing.T) {
	circuits := testFamilyKeySetCircuits(t)[:1]
	made := testMakeKeySet(t, circuits)
	edge := made.open(t)
	entry := edge.manifest.Shapes[0]
	flip := func(directory string, name string) {
		path := filepath.Join(directory, name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		content[len(content)/2] ^= 1
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	host := testHostHolding(t, testKeySettings(), made.id, made.files(t))
	flip(made.directory, entry.VerifyingKey.Name)
	if _, err := edge.verifyingKeys(); err == nil || !strings.Contains(err.Error(), "is not the file") {
		t.Errorf("the edge took a tampered verifying key: %v", err)
	}
	// on the host, a tampered contribution is deleted before anything parses it; with nothing to fetch
	// it again, the shape's files are absent, and nothing is cached
	keySet := testOpenOnHost(t, host, made.id, circuits)
	flip(keySet.directory, entry.Contributions[0].Name)
	err := keySet.ensureShape(context.Background(), circuits[0])
	if !errors.Is(err, errKeyFilesAbsent) || !strings.Contains(err.Error(), "is not the file") {
		t.Errorf("a tampered contribution: %v", err)
	}
	if _, err := os.Stat(filepath.Join(keySet.directory, entry.Contributions[0].Name)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the tampered contribution was kept: %v", err)
	}
	if state := keySet.shapeState(circuits[0].name); state.ready || !state.absent {
		t.Errorf("state %+v", state)
	}
}

func TestAKeySetRefusesATranscriptOfAnotherCircuit(t *testing.T) {
	// the square's entry naming the cube's phase 2: the check runs against the circuit compiled here, so a
	// transcript made for another fails however well formed it is
	square := testKeySetCircuit(t, 0, &ShapeSettings{Kind: ShapeKindKey, Family: ShapeFamilyChacha20, Version: tlsVersion13, ClientBlocks: 1}, testSquareCircuit)
	cube := testKeySetCircuit(t, 1, &ShapeSettings{Kind: ShapeKindEnvelope, Family: ShapeFamilyChacha20, ClientBlocks: 1}, testCubeCircuit)
	made := testMakeKeySet(t, []*keySetCircuit{square, cube})
	repinned := testRepinned(t, made, func(manifest *keySetManifest) {
		manifest.Shapes[0].Contributions = manifest.Shapes[1].Contributions
		manifest.Shapes[1].Contributions = nil
		manifest.Shapes = manifest.Shapes[:1]
	})
	host := testHostHolding(t, testKeySettings(), repinned.id, repinned.files(t))
	keySet := testOpenOnHost(t, host, repinned.id, repinned.circuits)
	if err := keySet.ensureShape(context.Background(), square); !isKeyRefusal(err) {
		t.Errorf("verified a transcript of another circuit: %v", err)
	}
	if state := keySet.shapeState(square.name); state.refused == nil {
		t.Errorf("state %+v", state)
	}
}

func TestAKeySetRefusesKeysItsTranscriptDoesNotFix(t *testing.T) {
	// a proving key of another shape, named by its true hash: the transcript fixes other keys, so the
	// named one is refused and nothing is cached
	circuits := testFamilyKeySetCircuits(t)[:2]
	made := testMakeKeySet(t, circuits)
	repinned := testRepinned(t, made, func(manifest *keySetManifest) {
		manifest.Shapes[0].ProvingKey = manifest.Shapes[1].ProvingKey
	})
	host := testHostHolding(t, testKeySettings(), repinned.id, repinned.files(t))
	keySet := testOpenOnHost(t, host, repinned.id, circuits)
	err := keySet.ensureShape(context.Background(), circuits[0])
	if !isKeyRefusal(err) || !strings.Contains(err.Error(), "not the ones keyset.json names") {
		t.Errorf("err %v", err)
	}
	if entries, _ := filepath.Glob(filepath.Join(host.cache.directory, "*.ok")); slices.ContainsFunc(entries, func(name string) bool {
		return !strings.Contains(filepath.Base(name), "phase1-")
	}) {
		t.Errorf("cached %v", entries)
	}
	// the other shape's own keys pass
	if err := keySet.ensureShape(context.Background(), circuits[1]); err != nil {
		t.Errorf("the other shape: %v", err)
	}
}

// A transcript keyset.json names by its true hash, but not in a contribution's form, is refused before
// gnark reads it, whatever count it declares: such a file costs a host a refusal, never its memory or its
// process (DESIGN-DETAILS 3.5).
func TestAKeySetRefusesATranscriptOutOfForm(t *testing.T) {
	circuits := testFamilyKeySetCircuits(t)[:1]
	// phase 1's domain size follows three update proofs, and phase 2's key count its commitment count and δ
	phase1CountOffset := 3 * (setupG1Bytes + setupG2Bytes)
	phase2CountOffset := 2 + setupG1Bytes
	for name, malform := range map[string]func(phase1 []byte, phase2 []byte) ([]byte, []byte){
		"a phase 1 of a vast domain": func(phase1 []byte, phase2 []byte) ([]byte, []byte) {
			binary.BigEndian.PutUint64(phase1[phase1CountOffset:], 1<<40)
			return phase1, phase2
		},
		"a phase 1 with a point not compressed": func(phase1 []byte, phase2 []byte) ([]byte, []byte) {
			phase1[0] &^= setupPointMask
			return phase1, phase2
		},
		"a phase 1 cut short": func(phase1 []byte, phase2 []byte) ([]byte, []byte) { return phase1[:len(phase1)/2], phase2 },
		"a phase 2 of a vast key count": func(phase1 []byte, phase2 []byte) ([]byte, []byte) {
			binary.BigEndian.PutUint32(phase2[phase2CountOffset:], 0xffffffff)
			return phase1, phase2
		},
		"a phase 2 with a commitment": func(phase1 []byte, phase2 []byte) ([]byte, []byte) {
			binary.BigEndian.PutUint16(phase2, 1)
			return phase1, phase2
		},
		"a phase 2 with an octet after it": func(phase1 []byte, phase2 []byte) ([]byte, []byte) { return phase1, append(phase2, 0) },
		"no contribution at all": func(phase1 []byte, phase2 []byte) ([]byte, []byte) {
			return phase1, bytes.Repeat([]byte{0xff}, len(phase2))
		},
	} {
		made := testMakeKeySet(t, circuits)
		edge := made.open(t)
		files := made.files(t)
		phase1Name := edge.manifest.Phase1[0].Contributions[0].Name
		phase2Name := edge.manifest.Shapes[0].Contributions[0].Name
		phase1, phase2 := malform(bytes.Clone(files[phase1Name]), bytes.Clone(files[phase2Name]))
		records := map[string]*keySetFile{}
		for fileName, content := range map[string][]byte{phase1Name: phase1, phase2Name: phase2} {
			record, err := writeKeySetFile(made.directory, fileName, content)
			if err != nil {
				t.Fatal(err)
			}
			records[fileName] = record
		}
		repinned := testRepinned(t, made, func(manifest *keySetManifest) {
			manifest.Phase1[0].Contributions = []*keySetFile{records[phase1Name]}
			manifest.Shapes[0].Contributions = []*keySetFile{records[phase2Name]}
		})
		host := testHostHolding(t, testKeySettings(), repinned.id, repinned.files(t))
		keySet := testOpenOnHost(t, host, repinned.id, circuits)
		err := keySet.ensureShape(context.Background(), circuits[0])
		phase := name[:len("a phase 1")]
		if name == "no contribution at all" {
			phase = "a phase 2"
		}
		if !isKeyRefusal(err) || !strings.Contains(err.Error(), phase+" ") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := keySet.backend.keysFor(circuits[0].shape); !errors.Is(err, errNoKeys) {
			t.Errorf("%s: keys %v", name, err)
		}
	}
}

func TestAKeySetRefusesAFileOutsideItsDirectory(t *testing.T) {
	made := testMakeKeySet(t, testFamilyKeySetCircuits(t)[:1])
	keySet := made.open(t)
	for _, name := range []string{"../keyset.json", keySetManifestName, filepath.Join("sub", "file"), "x" + keyFetchPartialSuffix, "x" + keyCachePartialMark + "1"} {
		if _, err := keySet.readFile(&keySetFile{Name: name, Sha256: hex.EncodeToString(make([]byte, sha256.Size)), ByteCount: 1}); err == nil {
			t.Errorf("%s: read", name)
		}
	}
}

func TestAKeySetRefusesAManifestOutOfShape(t *testing.T) {
	// even pinned, a keyset.json whose hash could name a path, or whose shape lacks what a check needs, is
	// refused before anything reads a file it names
	for name, edit := range map[string]func(manifest *keySetManifest){
		"a hash that walks out of the cache": func(manifest *keySetManifest) { manifest.Shapes[0].ProvingKey.Sha256 = "../../outside" },
		"an upper-case hash": func(manifest *keySetManifest) {
			manifest.Shapes[0].VerifyingKey.Sha256 = strings.ToUpper(manifest.Shapes[0].VerifyingKey.Sha256)
		},
		"a file that is a path": func(manifest *keySetManifest) { manifest.Shapes[0].VerifyingKey.Name = "../outside.vk" },
		"a file named twice": func(manifest *keySetManifest) {
			manifest.Shapes[1].VerifyingKey.Name = manifest.Shapes[0].VerifyingKey.Name
		},
		"no proving key":                 func(manifest *keySetManifest) { manifest.Shapes[0].ProvingKey = nil },
		"no circuit digest":              func(manifest *keySetManifest) { manifest.Shapes[0].CircuitSha256 = "" },
		"no length":                      func(manifest *keySetManifest) { manifest.Shapes[0].Contributions[0].ByteCount = 0 },
		"no contribution":                func(manifest *keySetManifest) { manifest.Shapes[1].Contributions = nil },
		"a shape twice":                  func(manifest *keySetManifest) { manifest.Shapes[1].Name = manifest.Shapes[0].Name },
		"a shape of another domain":      func(manifest *keySetManifest) { manifest.Shapes[0].DomainSize *= 2 },
		"a phase 1 with no contribution": func(manifest *keySetManifest) { manifest.Phase1[0].Contributions = nil },
		"a second phase 1": func(manifest *keySetManifest) {
			manifest.Phase1 = append(manifest.Phase1, &keySetPhase1{DomainSize: 2 * testKeySetDomainSize, Contributions: manifest.Phase1[0].Contributions})
		},
		"another version": func(manifest *keySetManifest) { manifest.Version = 1 },
		"no beacon":       func(manifest *keySetManifest) { manifest.Beacon = "" },
	} {
		made := testMakeKeySet(t, testFamilyKeySetCircuits(t)[:2])
		repinned := testRepinned(t, made, edit)
		_, err := openKeySet(repinned.directory, repinned.id, DefaultProofSettings(), testKeySetDomainSize, repinned.circuits)
		if !isKeyRefusal(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestProductionShapesHaveDistinctKeySetNames(t *testing.T) {
	seen := map[string]bool{}
	for _, circuit := range productionKeySetCircuits(DefaultProofSettings()) {
		if seen[circuit.name] {
			t.Errorf("%s twice", circuit.name)
		}
		seen[circuit.name] = true
	}
}

// smtpShapeDigests is this build's: each catalog shape compiles to the digest the table names, and the
// table names no other shape. A circuit's encoding holds no package path, so the release's /v2026 rewrite
// (§4.9) leaves every digest as it is: a hint named by its function would put one there.
func TestShapeDigestsAreThisBuilds(t *testing.T) {
	testNeedCircuits(t)
	proof := DefaultProofSettings()
	packagePath := reflect.TypeOf(partShape{}).PkgPath()
	names := map[string]bool{}
	for _, circuit := range productionKeySetCircuits(proof) {
		names[circuit.name] = true
		compiled, err := circuit.compile()
		if err != nil {
			t.Fatal(err)
		}
		encoded, digest, err := circuitDigest(compiled)
		if err != nil {
			t.Fatal(err)
		}
		if digest != smtpShapeDigests[circuit.name] {
			t.Errorf("%s compiles to %s and the table names %q: run go generate, which runs setup -digests", circuit.name, digest, smtpShapeDigests[circuit.name])
		}
		if circuit.digest != digest {
			t.Errorf("%s: the circuit carries %q", circuit.name, circuit.digest)
		}
		if bytes.Contains(encoded, []byte(packagePath)) {
			t.Errorf("%s's circuit holds the package path %s", circuit.name, packagePath)
		}
	}
	for name := range smtpShapeDigests {
		if !names[name] {
			t.Errorf("the table names %s, which the catalog does not", name)
		}
	}
}

func TestABuildWhoseTableNamesAnotherDigestRefusesTheShape(t *testing.T) {
	circuits := testFamilyKeySetCircuits(t)[:1]
	made := testMakeKeySet(t, circuits)
	// a build whose source compiles the circuit the set was made for, and whose table names another
	stale := *circuits[0]
	otherDigest := sha256.Sum256([]byte("another build's circuit"))
	stale.digest = hex.EncodeToString(otherDigest[:])
	host := testHostHolding(t, testKeySettings(), made.id, made.files(t))
	keySet := testOpenOnHost(t, host, made.id, []*keySetCircuit{&stale})
	err := keySet.ensureShape(context.Background(), &stale)
	if !isKeyRefusal(err) || !strings.Contains(err.Error(), "not the one the key set was made for") {
		t.Errorf("err %v", err)
	}
	if _, err := keySet.backend.keysFor(stale.shape); !errors.Is(err, errNoKeys) {
		t.Errorf("keys %v", err)
	}
	// a ceremony refuses the same circuit too
	if _, err := runKeySetSetup(context.Background(), t.TempDir(), []byte("a synthetic beacon"), testKeySetDomainSize, []*keySetCircuit{&stale}); err == nil || !strings.Contains(err.Error(), "setup -digests") {
		t.Errorf("the ceremony took it: %v", err)
	}
}

func TestExtendLeavesEveryEntryAsItIs(t *testing.T) {
	circuits := testFamilyKeySetCircuits(t)
	aes := testFamilyOf(circuits, ShapeFamilyAes128Gcm)
	made := testMakeKeySet(t, aes)
	before := made.files(t)
	old := made.open(t)
	newId, err := extendKeySetSetup(context.Background(), made.directory, DefaultProofSettings(), testKeySetDomainSize, circuits)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(newId, made.id) {
		t.Fatal("an extended set kept its id")
	}
	extended := &testKeySetMade{directory: made.directory, id: newId, circuits: circuits}
	after := extended.files(t)
	for name, content := range before {
		if name != keySetManifestName && !bytes.Equal(after[name], content) {
			t.Errorf("%s changed", name)
		}
	}
	keySet := extended.open(t)
	if !reflect.DeepEqual(keySet.manifest.Phase1, old.manifest.Phase1) || keySet.manifest.Beacon != old.manifest.Beacon {
		t.Error("the phase 1 or the beacon changed")
	}
	if len(keySet.manifest.Shapes) != len(circuits) {
		t.Fatalf("%d shapes", len(keySet.manifest.Shapes))
	}
	for i, entry := range old.manifest.Shapes {
		was, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		is, err := json.Marshal(keySet.manifest.Shapes[i])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(was, is) {
			t.Errorf("%s's entry changed", entry.Name)
		}
	}
	// a set that lacks nothing keeps its id and its keyset.json
	again, err := extendKeySetSetup(context.Background(), made.directory, DefaultProofSettings(), testKeySetDomainSize, circuits)
	if err != nil || !bytes.Equal(again, newId) || !bytes.Equal(extended.files(t)[keySetManifestName], after[keySetManifestName]) {
		t.Errorf("a second extension: %x, %v", again, err)
	}

	// a host that checked the old set's aes128gcm family takes it from its cache under the new id, with no
	// phase 2 of it on the host, and checks chacha20 on the old phase 1's cached commons, with no phase 1
	settings := testKeySettings()
	host := testHostHolding(t, settings, made.id, before)
	if err := testOpenOnHost(t, host, made.id, circuits).EnsureKeys(context.Background(), ShapeFamilyAes128Gcm); err != nil {
		t.Fatal(err)
	}
	newFiles := map[string][]byte{}
	for name, content := range after {
		newFiles[name] = content
	}
	for _, entry := range old.manifest.Shapes {
		delete(newFiles, entry.Contributions[0].Name)
	}
	delete(newFiles, old.manifest.Phase1[0].Contributions[0].Name)
	directory := host.keySetDirectory(newId)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range newFiles {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	newSet := testOpenOnHost(t, host, newId, circuits)
	for _, family := range []ShapeFamily{ShapeFamilyAes128Gcm, ShapeFamilyChacha20} {
		if err := newSet.EnsureKeys(context.Background(), family); err != nil {
			t.Errorf("%s under the new id: %v", family, err)
		}
	}
}

// What a host offers: the suites of the families ready in the set a job names, in the client's order. A
// family's TLS 1.2 suites wait for its TLS 1.2 key shape, and a set none of whose families is ready is no
// set a job may name.
func TestAFamilyIsOfferedOnlyWhenReady(t *testing.T) {
	circuits := testFamilyKeySetCircuits(t)
	made := testMakeKeySet(t, circuits)
	host := testHostHolding(t, testKeySettings(), made.id, made.files(t))
	keySet := testOpenOnHost(t, host, made.id, circuits)
	clientSuites := defaultTlsClientSettings().suites
	if suites := keySet.readySuites(clientSuites); len(suites) != 0 {
		t.Errorf("suites before any check: %x", suites)
	}
	if err := keySet.EnsureKeys(context.Background(), ShapeFamilyChacha20); err != nil {
		t.Fatal(err)
	}
	if suites := keySet.readySuites(clientSuites); !slices.Equal(suites, []uint16{tlsSuiteChacha20Poly1305Sha256}) {
		t.Errorf("chacha20 ready: %x", suites)
	}
	// aes128gcm's TLS 1.3 shapes without its TLS 1.2 key shape
	aes := testFamilyOf(circuits, ShapeFamilyAes128Gcm)
	for _, circuit := range aes {
		if circuit.entry.Kind == ShapeKindKey && circuit.entry.Version == tlsVersion12 {
			continue
		}
		if err := keySet.ensureShape(context.Background(), circuit); err != nil {
			t.Fatal(err)
		}
	}
	if suites := keySet.readySuites(clientSuites); !slices.Equal(suites, []uint16{tlsSuiteAes128GcmSha256, tlsSuiteChacha20Poly1305Sha256}) {
		t.Errorf("TLS 1.3 ready: %x", suites)
	}
	if err := keySet.EnsureKeys(context.Background(), ShapeFamilyAes128Gcm); err != nil {
		t.Fatal(err)
	}
	if suites := keySet.readySuites(clientSuites); !slices.Equal(suites, clientSuites) {
		t.Errorf("all ready: %x", suites)
	}
}

// The suites a job's ClientHello offers.
func testClientHelloSuites(t *testing.T, prover *Prover, job *sidecar.SmtpProofJob) ([]uint16, error) {
	t.Helper()
	client, server := net.Pipe()
	offered := make(chan []uint16, 1)
	go func() {
		defer server.Close()
		conn := tls.Server(server, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			offered <- slices.Clone(hello.CipherSuites)
			return nil, errors.New("captured")
		}})
		conn.Handshake()
		close(offered)
	}()
	_, err := prover.SendSmtp(context.Background(), client, job, nil)
	client.Close()
	return <-offered, err
}

// A Prover over test key sets pinned in order, on a host that fetches nothing and holds each set's files.
func testProverOver(t *testing.T, circuits []*keySetCircuit, mades ...*testKeySetMade) *Prover {
	t.Helper()
	settings := testKeySettings()
	var pins [][]byte
	for _, made := range mades {
		pins = append(pins, made.id)
	}
	keys := newProverKeys(DefaultProofSettings(), settings, pins, t.TempDir(), circuits, defaultTlsClientSettings().suites)
	keys.domainSize = testKeySetDomainSize
	for _, made := range mades {
		directory := keys.host.keySetDirectory(made.id)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, content := range made.files(t) {
			if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return &Prover{settings: DefaultProverSettings(), backend: &proverKeysBackend{keys: keys}, keys: keys}
}

// PrepareKeys until nothing is left, one shape a call, and the readiness it ends on.
func testPrepareAll(t *testing.T, prover *Prover) (*sidecar.SmtpProverReadiness, int) {
	t.Helper()
	for calls := 1; calls <= 100; calls += 1 {
		readiness, err := prover.PrepareKeys(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if readiness.Done {
			return readiness, calls
		}
	}
	t.Fatal("PrepareKeys never finished")
	return nil, 0
}

func TestAJobsClientHelloOffersOnlyItsSetsReadyFamilies(t *testing.T) {
	circuits := testFamilyKeySetCircuits(t)
	// the set holds chacha20 alone
	made := testMakeKeySet(t, testFamilyOf(circuits, ShapeFamilyChacha20))
	prover := testProverOver(t, circuits, made)
	job := testJob("body\r\n", "bob")
	job.KeySet = made.id
	// before the check, the set is no set a job may name, and nothing reaches the MX
	if suites, err := testClientHelloSuites(t, prover, job); !errors.Is(err, sidecar.ErrSmtpProofKeySet) || suites != nil {
		t.Errorf("before the check: %x, %v", suites, err)
	}
	readiness, calls := testPrepareAll(t, prover)
	// one shape a call: the chacha20 family's five, the fifth leaving nothing to check
	if calls != 5 || len(readiness.KeySets) != 1 || !bytes.Equal(readiness.KeySets[0].Id, made.id) ||
		!slices.Equal(readiness.KeySets[0].ReadySuites, []uint16{tlsSuiteChacha20Poly1305Sha256}) {
		t.Errorf("after %d calls: %+v", calls, readiness)
	}
	if !bytes.Equal(prover.KeySet(), made.id) {
		t.Errorf("KeySet %x", prover.KeySet())
	}
	suites, err := testClientHelloSuites(t, prover, job)
	if err == nil || !slices.Equal(suites, []uint16{tlsSuiteChacha20Poly1305Sha256}) {
		t.Errorf("offered %x, %v", suites, err)
	}
	// a set this host does not pin, or none, is refused before an octet goes out
	for _, keySet := range [][]byte{nil, bytes.Repeat([]byte{7}, sha256.Size)} {
		job.KeySet = keySet
		if suites, err := testClientHelloSuites(t, prover, job); !errors.Is(err, sidecar.ErrSmtpProofKeySet) || suites != nil {
			t.Errorf("%x: %x, %v", keySet, suites, err)
		}
	}
}

func TestKeySetIsTheNewestPinWithAReadyFamily(t *testing.T) {
	circuits := testFamilyKeySetCircuits(t)
	older := testMakeKeySet(t, testFamilyOf(circuits, ShapeFamilyChacha20))
	newer := testMakeKeySet(t, circuits)
	prover := testProverOver(t, circuits, newer, older)
	// the newer pin's files are gone, so only the older can become ready on this host
	if err := os.RemoveAll(prover.keys.host.keySetDirectory(newer.id)); err != nil {
		t.Fatal(err)
	}
	readiness, _ := testPrepareAll(t, prover)
	if len(readiness.KeySets) != 1 || !bytes.Equal(readiness.KeySets[0].Id, older.id) || !bytes.Equal(prover.KeySet(), older.id) {
		t.Errorf("readiness %+v, KeySet %x", readiness, prover.KeySet())
	}

	// with both there, the newer is named, and the older stays ready for a job the edge refused under it
	prover = testProverOver(t, circuits, newer, older)
	readiness, _ = testPrepareAll(t, prover)
	if len(readiness.KeySets) != 2 || !bytes.Equal(readiness.KeySets[0].Id, newer.id) || !bytes.Equal(readiness.KeySets[1].Id, older.id) ||
		!bytes.Equal(prover.KeySet(), newer.id) {
		t.Errorf("readiness %+v", readiness)
	}
	if !slices.Equal(readiness.KeySets[0].ReadySuites, defaultTlsClientSettings().suites) {
		t.Errorf("newer suites %x", readiness.KeySets[0].ReadySuites)
	}
}

func TestTheVerifierTakesSeveralKeySetsAndDropsOnePastItsNotAfter(t *testing.T) {
	circuits := testFamilyKeySetCircuits(t)[:2]
	retired := testMakeKeySet(t, circuits).open(t)
	current := testMakeKeySet(t, circuits).open(t)
	later := testMakeKeySet(t, circuits).open(t)
	now := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	settings := DefaultVerifierSettings()
	verifier, err := newVerifierAt(settings, []*VerifierKeySet{
		{KeySet: retired, NotAfter: now.Add(-time.Hour)},
		{KeySet: current},
		{KeySet: later, NotAfter: now.Add(time.Hour)},
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.HoldsKeySet(retired.Id()) || !verifier.HoldsKeySet(current.Id()) || !verifier.HoldsKeySet(later.Id()) || verifier.HoldsKeySet(nil) {
		t.Error("held sets")
	}
	preamble := testJob("body\r\n", "bob").Preamble
	preamble.ProofKeySet = retired.Id()
	if _, err := verifier.NewSmtpProofSession(preamble); !errors.Is(err, sidecar.ErrSmtpProofKeySet) {
		t.Errorf("a session under the retired set: %v", err)
	}
	// a session verifies under the set its preamble names and no other
	for _, keySet := range []*KeySet{current, later} {
		preamble.ProofKeySet = keySet.Id()
		session, err := verifier.NewSmtpProofSession(preamble)
		if err != nil {
			t.Fatal(err)
		}
		edge := session.(*edgeSession)
		if edge.verifier != verifier.keySets[hex.EncodeToString(keySet.Id())].backend || !bytes.Equal(edge.keySet, keySet.Id()) {
			t.Error("a session under another set's keys")
		}
	}
	// each set's keys are its own: a proof under one set's key fails the other's
	prover := testHostHolding(t, testKeySettings(), current.Id(), (&testKeySetMade{directory: current.directory}).files(t))
	proverSet := testOpenOnHost(t, prover, current.Id(), circuits)
	if err := proverSet.ensureShape(context.Background(), circuits[0]); err != nil {
		t.Fatal(err)
	}
	keys, err := proverSet.backend.keysFor(circuits[0].shape)
	if err != nil {
		t.Fatal(err)
	}
	currentKeys, _ := verifier.keySets[hex.EncodeToString(current.Id())].backend.(*groth16Backend).keysFor(circuits[0].shape)
	laterKeys, _ := verifier.keySets[hex.EncodeToString(later.Id())].backend.(*groth16Backend).keysFor(circuits[0].shape)
	if err := testProveSquare(t, keys, currentKeys.verifyingKey); err != nil {
		t.Errorf("its own set: %v", err)
	}
	if err := testProveSquare(t, keys, laterKeys.verifyingKey); err == nil {
		t.Error("another set's key passed")
	}
	// a not_after that passes while the edge runs ends the set for new sessions too
	now = now.Add(2 * time.Hour)
	if verifier.HoldsKeySet(later.Id()) || !verifier.HoldsKeySet(current.Id()) {
		t.Error("a set past its not_after is held")
	}

	// no more sets than KeySetMaxCount, and none twice
	settings.KeySetMaxCount = 2
	if _, err := newVerifierAt(settings, []*VerifierKeySet{{KeySet: retired}, {KeySet: current}, {KeySet: later}}, clock); err == nil {
		t.Error("took three sets past a bound of two")
	}
	settings.KeySetMaxCount = 4
	if _, err := newVerifierAt(settings, []*VerifierKeySet{{KeySet: current}, {KeySet: current}}, clock); err == nil {
		t.Error("took a set twice")
	}
}

// The ceremony and the host's check over a real shape, the TLS 1.3 ChaCha20 key shape, then a proof of a
// real EHLO that the edge's key accepts. It takes minutes, so it stays out of the ordinary run: set
// SMTPPROOF_FULL to run it.
func TestAKeySetProvesARealEhlo(t *testing.T) {
	if os.Getenv("SMTPPROOF_FULL") == "" {
		t.Skip("set SMTPPROOF_FULL to run a ceremony at a real shape's size")
	}
	testNeedCircuits(t)
	proof := DefaultProofSettings()
	circuit := productionKeySetCircuits(proof)[1]
	made := &testKeySetMade{directory: t.TempDir(), circuits: []*keySetCircuit{circuit}}
	id, err := runKeySetSetup(context.Background(), made.directory, []byte("a synthetic beacon"), uint64(proof.DomainSize), made.circuits)
	if err != nil {
		t.Fatal(err)
	}
	made.id = id
	host := testHostHolding(t, testKeySettings(), id, made.files(t))
	keySet, err := host.openKeySet(context.Background(), id, proof, uint64(proof.DomainSize), made.circuits)
	if err != nil {
		t.Fatal(err)
	}
	if err := keySet.ensureShape(context.Background(), circuit); err != nil {
		t.Fatal(err)
	}
	edge, err := openKeySet(made.directory, id, proof, uint64(proof.DomainSize), made.circuits)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(DefaultVerifierSettings(), []*VerifierKeySet{{KeySet: edge}})
	if err != nil {
		t.Fatal(err)
	}
	statement, witness := testBdatCapture(t, testTlsLegs()[1]).part(t, 1)
	if found, err := partShapeFor(keySet.proof, statement); err != nil || *found != *circuit.shape {
		t.Fatalf("the key part fits %+v, %v", found, err)
	}
	encoded, err := keySet.backend.provePart(context.Background(), statement, witness)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.keySets[hex.EncodeToString(id)].backend.verifyPart(context.Background(), statement, encoded); err != nil {
		t.Errorf("the edge refused a proof under keys from its own key set: %v", err)
	}
}
