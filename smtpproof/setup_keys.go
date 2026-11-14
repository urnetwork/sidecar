package smtpproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
)

// A release's keys (SPEC.md 10.3): per shape, its setup transcript and the keys that transcript
// fixes, each named by its SHA-256 in keyset.json, which the release pins by hash. The edge loads only
// verifying keys, which it made itself. A prover host takes a proving key only from its own check of
// the transcript against the circuit it compiled (SPEC.md 10.2), once per release, and then from its
// cache of what that check produced; a key it did not verify is never used.
//
// Where the files come from is the host's business. The owner's answer to
// smtpproof-start-key-distribution puts them on a public ur.io path, which needs its §2.8 row before
// anything fetches from it, so nothing here downloads: a host points OpenKeySet at a directory.

// keyset.json's name in a KeySet directory.
const keySetManifestName = "keyset.json"

// keyset.json's format version.
const keySetVersion = 1

// keyset.json.
type keySetManifest struct {
	Version int    `json:"version"`
	Beacon  string `json:"beacon"`
	// Phase 1 once per domain size, shared by every shape of that size.
	Phase1 []*keySetPhase1 `json:"phase1"`
	Shapes []*keySetShape  `json:"shapes"`
}

type keySetPhase1 struct {
	DomainSize    uint64        `json:"domain_size"`
	Contributions []*keySetFile `json:"contributions"`
}

type keySetShape struct {
	Name          string        `json:"name"`
	DomainSize    uint64        `json:"domain_size"`
	Contributions []*keySetFile `json:"contributions"`
	ProvingKey    *keySetFile   `json:"proving_key"`
	VerifyingKey  *keySetFile   `json:"verifying_key"`
}

// A file of the KeySet directory and its hash.
type keySetFile struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
}

// A circuit a KeySet can hold keys for, by its stable name.
type keySetCircuit struct {
	name    string
	shape   *partShape
	compile func() (constraint.ConstraintSystem, error)
}

// A shape's name in keyset.json, its catalog entry's (DESIGN-DETAILS 3.2.6): kind, family, version for a
// key shape, and every pool, so that a changed shape has another name.
func partShapeName(shape *partShape) string {
	return shape.entry().Name()
}

// The circuits this build proves: the catalog's shapes, compiled from this build's own source.
func productionKeySetCircuits(proof *ProofSettings) []*keySetCircuit {
	var circuits []*keySetCircuit
	for _, shape := range partShapes(proof) {
		circuits = append(circuits, &keySetCircuit{
			name:  partShapeName(shape),
			shape: shape,
			compile: func() (constraint.ConstraintSystem, error) {
				return compilePartShape(shape)
			},
		})
	}
	return circuits
}

// An opened KeySet: keyset.json checked against its pin, and the directory its files are in.
type KeySet struct {
	directory string
	manifest  *keySetManifest
	beacon    []byte
	circuits  []*keySetCircuit
}

// Opens a KeySet directory whose keyset.json hashes to pin. A release pins it; with no pin there is
// no KeySet, and a host with none proves and passes nothing.
func OpenKeySet(directory string, pin []byte) (*KeySet, error) {
	return openKeySet(directory, pin, productionKeySetCircuits(DefaultProofSettings()))
}

func openKeySet(directory string, pin []byte, circuits []*keySetCircuit) (*KeySet, error) {
	if len(pin) != sha256.Size {
		return nil, errors.New("smtpproof: no KeySet is pinned")
	}
	encoded, err := os.ReadFile(filepath.Join(directory, keySetManifestName))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	if !bytes.Equal(sum[:], pin) {
		return nil, errors.New("smtpproof: keyset.json is not the pinned one")
	}
	manifest := &keySetManifest{}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(manifest); err != nil {
		return nil, fmt.Errorf("smtpproof: keyset.json: %w", err)
	}
	if manifest.Version != keySetVersion {
		return nil, fmt.Errorf("smtpproof: keyset.json version %d", manifest.Version)
	}
	beacon, err := hex.DecodeString(manifest.Beacon)
	if err != nil || len(beacon) == 0 {
		return nil, errors.New("smtpproof: keyset.json has no beacon")
	}
	if err := checkKeySetManifest(manifest); err != nil {
		return nil, fmt.Errorf("smtpproof: keyset.json: %w", err)
	}
	return &KeySet{directory: directory, manifest: manifest, beacon: beacon, circuits: circuits}, nil
}

// A pinned keyset.json is the release's, but its shape is still checked before anything follows it:
// every file is named with a hash of 64 hex digits, since a proving key's hash names its cache file,
// and every shape names its contributions and both keys, once.
func checkKeySetManifest(manifest *keySetManifest) error {
	fileForm := func(file *keySetFile) bool {
		if file == nil || len(file.Sha256) != 2*sha256.Size {
			return false
		}
		decoded, err := hex.DecodeString(file.Sha256)
		return err == nil && hex.EncodeToString(decoded) == file.Sha256
	}
	for _, phase1 := range manifest.Phase1 {
		if len(phase1.Contributions) == 0 || slices.IndexFunc(phase1.Contributions, func(file *keySetFile) bool { return !fileForm(file) }) != -1 {
			return fmt.Errorf("phase 1 of domain size %d", phase1.DomainSize)
		}
	}
	names := map[string]bool{}
	for _, entry := range manifest.Shapes {
		if names[entry.Name] || len(entry.Contributions) == 0 || !fileForm(entry.ProvingKey) || !fileForm(entry.VerifyingKey) ||
			slices.IndexFunc(entry.Contributions, func(file *keySetFile) bool { return !fileForm(file) }) != -1 {
			return fmt.Errorf("shape %q", entry.Name)
		}
		names[entry.Name] = true
	}
	return nil
}

// Reads a KeySet file, and refuses it unless it hashes to what keyset.json says.
func (self *KeySet) readFile(file *keySetFile) ([]byte, error) {
	if file == nil || filepath.Base(file.Name) != file.Name || file.Name == keySetManifestName {
		return nil, errors.New("smtpproof: keyset.json names a file outside its directory")
	}
	content, err := os.ReadFile(filepath.Join(self.directory, file.Name))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != file.Sha256 {
		return nil, fmt.Errorf("smtpproof: %s is not the file keyset.json names", file.Name)
	}
	return content, nil
}

func (self *KeySet) shapeEntry(name string) *keySetShape {
	for _, entry := range self.manifest.Shapes {
		if entry.Name == name {
			return entry
		}
	}
	return nil
}

// The transcript keyset.json gives a shape: its domain size's phase 1 and its own phase 2.
func (self *KeySet) transcript(entry *keySetShape) (*SetupTranscript, error) {
	transcript := &SetupTranscript{Beacon: self.beacon}
	for _, phase1 := range self.manifest.Phase1 {
		if phase1.DomainSize != entry.DomainSize {
			continue
		}
		for _, file := range phase1.Contributions {
			content, err := self.readFile(file)
			if err != nil {
				return nil, err
			}
			transcript.Phase1 = append(transcript.Phase1, content)
		}
	}
	for _, file := range entry.Contributions {
		content, err := self.readFile(file)
		if err != nil {
			return nil, err
		}
		transcript.Phase2 = append(transcript.Phase2, content)
	}
	return transcript, nil
}

// The edge's keys: each shape's verifying key, by its hash. The edge ran the setup, so its own
// contribution is what soundness rests on, and it needs no transcript check.
func (self *KeySet) verifyingKeys() (map[partShape]*shapeKeys, error) {
	keys := map[partShape]*shapeKeys{}
	for _, circuit := range self.circuits {
		entry := self.shapeEntry(circuit.name)
		if entry == nil || circuit.shape == nil {
			continue
		}
		content, err := self.readFile(entry.VerifyingKey)
		if err != nil {
			return nil, err
		}
		verifyingKey := groth16.NewVerifyingKey(ecc.BN254)
		if _, err := verifyingKey.ReadFrom(bytes.NewReader(content)); err != nil {
			return nil, fmt.Errorf("smtpproof: %s: %w", circuit.name, err)
		}
		keys[*circuit.shape] = &shapeKeys{shape: circuit.shape, verifyingKey: verifyingKey}
	}
	return keys, nil
}

// A verified proving key's file in a prover host's cache, named by the hash keyset.json gives it.
// Only VerifyProvingKeys writes there, and only what it derived itself.
func cachedProvingKeyPath(cacheDirectory string, entry *keySetShape) string {
	return filepath.Join(cacheDirectory, entry.ProvingKey.Sha256+".pk")
}

// Checks every shape's transcript against the circuit this build compiles, takes the proving key the
// transcript fixes, and caches it once it is the key keyset.json names. It runs once per release, at
// idle: a production shape's check takes minutes. A shape that fails is refused, and the error says
// which, so no key the check did not produce is ever used (SPEC.md 10.2).
func (self *KeySet) VerifyProvingKeys(ctx context.Context, cacheDirectory string) error {
	if err := os.MkdirAll(cacheDirectory, 0o700); err != nil {
		return err
	}
	for _, circuit := range self.circuits {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry := self.shapeEntry(circuit.name)
		if entry == nil {
			continue
		}
		if _, err := os.Stat(cachedProvingKeyPath(cacheDirectory, entry)); err == nil {
			continue
		}
		if err := self.verifyProvingKey(circuit, entry, cacheDirectory); err != nil {
			return fmt.Errorf("smtpproof: %s: %w", circuit.name, err)
		}
	}
	return nil
}

func (self *KeySet) verifyProvingKey(circuit *keySetCircuit, entry *keySetShape, cacheDirectory string) error {
	compiled, err := circuit.compile()
	if err != nil {
		return err
	}
	if setupDomainSize(compiled) != entry.DomainSize {
		return errors.New("keyset.json's domain size is not this circuit's")
	}
	transcript, err := self.transcript(entry)
	if err != nil {
		return err
	}
	provingKey, verifyingKey, err := VerifySetupTranscript(compiled, transcript)
	if err != nil {
		return err
	}
	// both of the transcript's keys must be the published ones, or the edge holds a verifying key no
	// proof here would pass, and the cache would hold a key keyset.json does not name
	var encodedProvingKey []byte
	for _, check := range []struct {
		key  io.WriterTo
		file *keySetFile
	}{
		{key: provingKey, file: entry.ProvingKey},
		{key: verifyingKey, file: entry.VerifyingKey},
	} {
		encoded, err := encodeContribution(check.key)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(encoded)
		if hex.EncodeToString(sum[:]) != check.file.Sha256 {
			return errors.New("the transcript's keys are not the ones keyset.json names")
		}
		if check.file == entry.ProvingKey {
			encodedProvingKey = encoded
		}
	}
	// written whole under another name first, so a cut write never stands as verified
	path := cachedProvingKeyPath(cacheDirectory, entry)
	if err := os.WriteFile(path+".partial", encodedProvingKey, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".partial", path)
}

// Loads a shape's verified proving key from a prover host's cache, and compiles the circuit to prove
// it with. A shape VerifyProvingKeys has not yet passed has no keys, so its parts are refused and the
// host queues its mail. Safe for concurrent use.
type cachedProvingKeys struct {
	keySet         *KeySet
	cacheDirectory string

	stateLock sync.Mutex
	loads     map[partShape]*cachedProvingLoad
}

// One shape's load, which a caller wanting the same shape meanwhile waits on rather than repeats.
type cachedProvingLoad struct {
	done chan struct{}
	keys *shapeKeys
	err  error
}

func newCachedProvingKeys(keySet *KeySet, cacheDirectory string) *cachedProvingKeys {
	return &cachedProvingKeys{keySet: keySet, cacheDirectory: cacheDirectory, loads: map[partShape]*cachedProvingLoad{}}
}

// keysFor of shapeKeySource.
func (self *cachedProvingKeys) keysFor(shape *partShape) (*shapeKeys, error) {
	load, waiting := func() (*cachedProvingLoad, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if load, ok := self.loads[*shape]; ok {
			return load, true
		}
		load := &cachedProvingLoad{done: make(chan struct{})}
		self.loads[*shape] = load
		return load, false
	}()
	if waiting {
		<-load.done
		return load.keys, load.err
	}
	load.keys, load.err = self.load(shape)
	if load.err != nil {
		// a shape not verified yet may be soon, so a failure is not kept
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.loads, *shape)
		}()
	}
	close(load.done)
	return load.keys, load.err
}

func (self *cachedProvingKeys) load(shape *partShape) (*shapeKeys, error) {
	var circuit *keySetCircuit
	for _, candidate := range self.keySet.circuits {
		if candidate.shape != nil && *candidate.shape == *shape {
			circuit = candidate
		}
	}
	if circuit == nil {
		return nil, errNoKeys
	}
	entry := self.keySet.shapeEntry(circuit.name)
	if entry == nil || entry.ProvingKey == nil {
		return nil, errNoKeys
	}
	content, err := os.ReadFile(cachedProvingKeyPath(self.cacheDirectory, entry))
	if err != nil {
		return nil, errNoKeys
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != entry.ProvingKey.Sha256 {
		return nil, errNoKeys
	}
	provingKey := groth16.NewProvingKey(ecc.BN254)
	if _, err := provingKey.ReadFrom(bytes.NewReader(content)); err != nil {
		return nil, err
	}
	compiled, err := circuit.compile()
	if err != nil {
		return nil, err
	}
	return &shapeKeys{shape: shape, compiled: compiled, provingKey: provingKey}, nil
}

// Runs the edge's one-party ceremony (SPEC.md 10.3) for every production shape and writes a KeySet
// directory: phase 1 once per domain size, phase 2 per shape, and the keys each transcript fixes, as
// VerifySetupTranscript derives them. It returns keyset.json's hash, which a release pins. A
// production run takes hours and gigabytes, and belongs on the controlled host.
func RunSetup(ctx context.Context, directory string, beacon []byte) ([]byte, error) {
	return runKeySetSetup(ctx, directory, beacon, productionKeySetCircuits(DefaultProofSettings()))
}

func runKeySetSetup(ctx context.Context, directory string, beacon []byte, circuits []*keySetCircuit) ([]byte, error) {
	if len(beacon) == 0 {
		return nil, errors.New("smtpproof: a setup needs a public beacon")
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, err
	}
	manifest := &keySetManifest{Version: keySetVersion, Beacon: hex.EncodeToString(beacon)}
	write := func(name string, content []byte) (*keySetFile, error) {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o644); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(content)
		return &keySetFile{Name: name, Sha256: hex.EncodeToString(sum[:])}, nil
	}
	phase1s := map[uint64]*SetupTranscript{}
	for _, circuit := range circuits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		compiled, err := circuit.compile()
		if err != nil {
			return nil, err
		}
		r1cs, err := setupR1cs(compiled)
		if err != nil {
			return nil, fmt.Errorf("smtpproof: %s: %w", circuit.name, err)
		}
		domainSize := setupDomainSize(compiled)
		transcript, ok := phase1s[domainSize]
		if !ok {
			first := mpcsetup.NewPhase1(domainSize)
			first.Contribute()
			encoded, err := encodeContribution(first)
			if err != nil {
				return nil, err
			}
			transcript = &SetupTranscript{Beacon: beacon, Phase1: [][]byte{encoded}}
			phase1s[domainSize] = transcript
			file, err := write(fmt.Sprintf("phase1-%d-0.bin", domainSize), encoded)
			if err != nil {
				return nil, err
			}
			manifest.Phase1 = append(manifest.Phase1, &keySetPhase1{DomainSize: domainSize, Contributions: []*keySetFile{file}})
		}
		commons, err := verifyPhase1(compiled, transcript)
		if err != nil {
			return nil, err
		}
		second := &mpcsetup.Phase2{}
		second.Initialize(r1cs, commons)
		second.Contribute()
		encoded, err := encodeContribution(second)
		if err != nil {
			return nil, err
		}
		entry := &keySetShape{Name: circuit.name, DomainSize: domainSize}
		file, err := write(circuit.name+"-phase2-0.bin", encoded)
		if err != nil {
			return nil, err
		}
		entry.Contributions = []*keySetFile{file}
		provingKey, verifyingKey, err := VerifySetupTranscript(compiled, &SetupTranscript{Beacon: beacon, Phase1: transcript.Phase1, Phase2: [][]byte{encoded}})
		if err != nil {
			return nil, err
		}
		for _, key := range []struct {
			name  string
			value io.WriterTo
			file  **keySetFile
		}{
			{name: circuit.name + ".pk", value: provingKey, file: &entry.ProvingKey},
			{name: circuit.name + ".vk", value: verifyingKey, file: &entry.VerifyingKey},
		} {
			content, err := encodeContribution(key.value)
			if err != nil {
				return nil, err
			}
			if *key.file, err = write(key.name, content); err != nil {
				return nil, err
			}
		}
		manifest.Shapes = append(manifest.Shapes, entry)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, err := write(keySetManifestName, encoded); err != nil {
		return nil, err
	}
	pin := sha256.Sum256(encoded)
	return pin[:], nil
}
