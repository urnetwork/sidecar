package smtpproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"

	"github.com/urnetwork/sidecar"
)

// A release's key sets (DESIGN-DETAILS 3.2.7; SPEC.md 10.3). A key set is the published record of one
// ceremony: keyset.json, whose SHA-256 is the set's id, a release's pin and a preamble's proof_key_set,
// naming one phase 1 for the one domain every shape proves over and, per shape, the digest of the circuit
// it was set up for, its phase 2 contributions and the two keys the transcript fixes, every file by hash
// and length. The edge loads only verifying keys, which it made itself. A prover host takes a proving key
// only from its own check of the transcript against the circuit this build compiles (SPEC.md 10.2), and
// from its cache of what that check produced (setup_cache.go): no proving key is published, and none is
// read from a key set. The host fetches what it checks from ur.io (setup_fetch.go), and only a release's
// pins tell it what to trust there.

// keyset.json's name in a key set's directory.
const keySetManifestName = "keyset.json"

// keyset.json's format version.
const keySetVersion = 2

// Where a prover host keeps each pinned set's fetched files, and its cache, under its directory.
const (
	keyHostKeySetsName = "keys"
	keyHostCacheName   = "cache"
)

// The form of a name keyset.json gives a file or a shape: a plain name, never a path.
var keySetNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// A key set or shape no retry makes usable, because the release pinned a set this build cannot take
// (DESIGN-DETAILS 3.5). The host only queues the families it refuses.
type keyRefusal struct {
	err error
}

func (self *keyRefusal) Error() string {
	return self.err.Error()
}

func (self *keyRefusal) Unwrap() error {
	return self.err
}

func keyRefused(format string, args ...any) error {
	return &keyRefusal{err: fmt.Errorf("smtpproof: "+format, args...)}
}

func isKeyRefusal(err error) bool {
	var refusal *keyRefusal
	return errors.As(err, &refusal)
}

// A file a check needs is not on the host, and nothing fetches it.
var errKeyFilesAbsent = errors.New("smtpproof: a key set's file is not here, and nothing fetches it")

// keyset.json.
type keySetManifest struct {
	Version int    `json:"version"`
	Beacon  string `json:"beacon"`
	// One phase 1, for the one domain size every shape proves over.
	Phase1 []*keySetPhase1 `json:"phase1"`
	Shapes []*keySetShape  `json:"shapes"`
}

type keySetPhase1 struct {
	DomainSize    uint64        `json:"domain_size"`
	Contributions []*keySetFile `json:"contributions"`
}

type keySetShape struct {
	Name string `json:"name"`
	// SHA-256 of the shape's compiled circuit as gnark's WriteTo writes it.
	CircuitSha256 string        `json:"circuit_sha256"`
	DomainSize    uint64        `json:"domain_size"`
	Contributions []*keySetFile `json:"contributions"`
	// Its WriteTo encoding, by hash and length alone: the file is not published.
	ProvingKey   *keySetKey  `json:"proving_key"`
	VerifyingKey *keySetFile `json:"verifying_key"`
}

// A file of a key set's directory, and its hash and length.
type keySetFile struct {
	Name      string `json:"name"`
	Sha256    string `json:"sha256"`
	ByteCount int64  `json:"byte_count"`
}

// A key named by its encoding's hash and length alone.
type keySetKey struct {
	Sha256    string `json:"sha256"`
	ByteCount int64  `json:"byte_count"`
}

func keySetHashOk(value string) bool {
	if len(value) != 2*sha256.Size {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

// Whether a name is one a key set or the cache may give a file: a plain name, which no partial file of a
// fetch or the cache can take.
func keySetFileNameOk(name string) bool {
	return keySetNamePattern.MatchString(name) && name != keySetManifestName &&
		!bytes.HasSuffix([]byte(name), []byte(keyFetchPartialSuffix)) && !bytes.Contains([]byte(name), []byte(keyCachePartialMark))
}

// A pinned keyset.json is the release's, but its form is still checked before anything follows it: one
// phase 1, of this build's domain size, which every shape takes; every hash 64 hex digits, since hashes
// name cache files; every length positive; every name plain, and named once; every shape with its
// circuit's digest, its contributions and both keys.
func checkKeySetManifest(manifest *keySetManifest, domainSize uint64) error {
	if len(manifest.Phase1) != 1 || manifest.Phase1[0] == nil {
		return errors.New("not one phase 1")
	}
	phase1 := manifest.Phase1[0]
	if phase1.DomainSize != domainSize {
		return fmt.Errorf("phase 1 is for a domain of %d points, not this build's %d", phase1.DomainSize, domainSize)
	}
	names := map[string]bool{}
	fileOk := func(file *keySetFile) bool {
		if file == nil || !keySetFileNameOk(file.Name) || !keySetHashOk(file.Sha256) || file.ByteCount <= 0 || names[file.Name] {
			return false
		}
		names[file.Name] = true
		return true
	}
	if len(phase1.Contributions) == 0 || slices.IndexFunc(phase1.Contributions, func(file *keySetFile) bool { return !fileOk(file) }) != -1 {
		return fmt.Errorf("phase 1 of domain size %d", phase1.DomainSize)
	}
	shapeNames := map[string]bool{}
	for _, entry := range manifest.Shapes {
		if entry == nil || !keySetNamePattern.MatchString(entry.Name) || shapeNames[entry.Name] || !keySetHashOk(entry.CircuitSha256) ||
			entry.DomainSize != phase1.DomainSize || len(entry.Contributions) == 0 ||
			entry.ProvingKey == nil || !keySetHashOk(entry.ProvingKey.Sha256) || entry.ProvingKey.ByteCount <= 0 ||
			!fileOk(entry.VerifyingKey) || slices.IndexFunc(entry.Contributions, func(file *keySetFile) bool { return !fileOk(file) }) != -1 {
			name := ""
			if entry != nil {
				name = entry.Name
			}
			return fmt.Errorf("shape %q", name)
		}
		shapeNames[entry.Name] = true
	}
	return nil
}

// A circuit this build can hold keys for: a catalog shape, by its KeySet name.
type keySetCircuit struct {
	name string
	// Its catalog entry: its kind, family and version. Nil for a circuit of no family.
	entry   *ShapeSettings
	shape   *partShape
	compile func() (constraint.ConstraintSystem, error)
	// The digest smtpShapeDigests gives it, in hex, which a key set's entry must name. Empty takes none.
	digest string
}

// A shape's name in keyset.json, its catalog entry's (DESIGN-DETAILS 3.2.6): kind, family, version for a
// key shape, and every pool, so that a changed shape has another name.
func partShapeName(shape *partShape) string {
	return shape.entry().Name()
}

// The circuits this build proves: the catalog's shapes, compiled from this build's own source, each with
// the digest the release's table gives it.
func productionKeySetCircuits(proof *ProofSettings) []*keySetCircuit {
	var circuits []*keySetCircuit
	for _, entry := range proof.Shapes {
		shape := newPartShape(proof, entry)
		circuits = append(circuits, &keySetCircuit{
			name:  entry.Name(),
			entry: entry,
			shape: shape,
			compile: func() (constraint.ConstraintSystem, error) {
				return compilePartShape(shape)
			},
			digest: smtpShapeDigests[entry.Name()],
		})
	}
	return circuits
}

// What a prover host's check found of one shape of a set.
type keyShapeState struct {
	ready bool
	// Why the shape is refused for this set, which no retry changes.
	refused error
	// Its files are not here and nothing fetches them, so no check of it ends while this process runs.
	absent bool
}

// An opened key set: keyset.json checked against its id, and the directory its files are in. Safe for
// concurrent use.
type KeySet struct {
	id        []byte
	directory string
	manifest  *keySetManifest
	beacon    []byte
	// The set's catalog: this build's circuits it holds, in keyset.json's order, which is the order a
	// prover and an edge each take a part's first fit from (3.2.5 step 12); and the proofs' settings with
	// that catalog in place of the build's. A shape the set holds and this build does not is no use here.
	catalog []*keySetCircuit
	proof   *ProofSettings
	// A prover host's means, and the backend a send under this set proves with. Nil at the edge.
	host    *keyHost
	backend *groth16Backend

	stateLock   sync.Mutex
	shapeStates map[string]*keyShapeState
}

// Opens a key set's directory, whose keyset.json must hash to id: the id smtpedge.yml lists, or a
// release's pin. Every other file is checked against keyset.json when it is read.
func OpenKeySet(directory string, id []byte) (*KeySet, error) {
	proof := DefaultProofSettings()
	return openKeySet(directory, id, proof, uint64(proof.DomainSize), productionKeySetCircuits(proof))
}

func openKeySet(directory string, id []byte, proof *ProofSettings, domainSize uint64, circuits []*keySetCircuit) (*KeySet, error) {
	if len(id) != sha256.Size {
		return nil, errors.New("smtpproof: no key set is named")
	}
	encoded, err := os.ReadFile(filepath.Join(directory, keySetManifestName))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	if !bytes.Equal(sum[:], id) {
		return nil, errors.New("smtpproof: keyset.json is not the named one")
	}
	return parseKeySet(directory, id, encoded, proof, domainSize, circuits)
}

// A key set from keyset.json's octets, which already hash to its id. A malformed one is a refusal: its
// pin names it, so no retry changes it.
func parseKeySet(directory string, id []byte, encoded []byte, proof *ProofSettings, domainSize uint64, circuits []*keySetCircuit) (*KeySet, error) {
	manifest := &keySetManifest{}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(manifest); err != nil {
		return nil, keyRefused("keyset.json: %v", err)
	}
	if manifest.Version != keySetVersion {
		return nil, keyRefused("keyset.json version %d", manifest.Version)
	}
	beacon, err := hex.DecodeString(manifest.Beacon)
	if err != nil || len(beacon) == 0 {
		return nil, keyRefused("keyset.json has no beacon")
	}
	if err := checkKeySetManifest(manifest, domainSize); err != nil {
		return nil, keyRefused("keyset.json: %v", err)
	}
	circuitsByName := map[string]*keySetCircuit{}
	for _, circuit := range circuits {
		circuitsByName[circuit.name] = circuit
	}
	setProof := *proof
	setProof.Shapes = nil
	var catalog []*keySetCircuit
	for _, entry := range manifest.Shapes {
		circuit, ok := circuitsByName[entry.Name]
		if !ok {
			continue
		}
		catalog = append(catalog, circuit)
		if circuit.entry != nil {
			setProof.Shapes = append(setProof.Shapes, circuit.entry)
		}
	}
	return &KeySet{
		id:          bytes.Clone(id),
		directory:   directory,
		manifest:    manifest,
		beacon:      beacon,
		catalog:     catalog,
		proof:       &setProof,
		shapeStates: map[string]*keyShapeState{},
	}, nil
}

// keyset.json's SHA-256: the set's id, as a pin and a preamble's proof_key_set name it.
func (self *KeySet) Id() []byte {
	return bytes.Clone(self.id)
}

// Reads a file of the set's directory, and refuses it unless it is the length and hash keyset.json gives
// it. Nothing reads a file it names before this passes.
func (self *KeySet) readFile(file *keySetFile) ([]byte, error) {
	if file == nil || !keySetFileNameOk(file.Name) {
		return nil, errors.New("smtpproof: keyset.json names a file outside its directory")
	}
	path := filepath.Join(self.directory, file.Name)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() != file.ByteCount {
		return nil, fmt.Errorf("smtpproof: %s is %d octets, not the file keyset.json names", file.Name, info.Size())
	}
	content, err := os.ReadFile(path)
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

// The edge's keys: the verifying key of each shape of the set's catalog. The edge ran the setup, so its
// own contribution is what soundness rests on, and it needs no transcript check.
func (self *KeySet) verifyingKeys() (map[partShape]*shapeKeys, error) {
	keys := map[partShape]*shapeKeys{}
	for _, circuit := range self.catalog {
		entry := self.shapeEntry(circuit.name)
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

// Runs the edge's one-party ceremony (SPEC.md 10.3) over every production shape and writes a key set's
// directory: one phase 1 for the one domain size, a phase 2 per shape, and each shape's circuit digest,
// verifying key and proving key's hash, as VerifySetupTranscript derives them. It writes no proving
// key, since each prover host derives its own. It returns keyset.json's SHA-256, which a release pins.
// A shape whose circuit is not the one smtpShapeDigests names is refused: setup -digests writes the
// table first. A production run takes hours and gigabytes, and belongs on the controlled host.
func RunSetup(ctx context.Context, directory string, beacon []byte) ([]byte, error) {
	proof := DefaultProofSettings()
	return runKeySetSetup(ctx, directory, beacon, uint64(proof.DomainSize), productionKeySetCircuits(proof))
}

func runKeySetSetup(ctx context.Context, directory string, beacon []byte, domainSize uint64, circuits []*keySetCircuit) ([]byte, error) {
	if len(beacon) == 0 {
		return nil, errors.New("smtpproof: a setup needs a public beacon")
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, err
	}
	manifest := &keySetManifest{Version: keySetVersion, Beacon: hex.EncodeToString(beacon)}
	first := mpcsetup.NewPhase1(domainSize)
	first.Contribute()
	encoded, err := encodeContribution(first)
	if err != nil {
		return nil, err
	}
	file, err := writeKeySetFile(directory, fmt.Sprintf("phase1-%d-0.bin", domainSize), encoded)
	if err != nil {
		return nil, err
	}
	manifest.Phase1 = []*keySetPhase1{{DomainSize: domainSize, Contributions: []*keySetFile{file}}}
	commons, err := verifyPhase1At(domainSize, beacon, [][]byte{encoded})
	if err != nil {
		return nil, err
	}
	for _, circuit := range circuits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry, err := setupKeySetShape(directory, beacon, domainSize, commons, circuit)
		if err != nil {
			return nil, err
		}
		manifest.Shapes = append(manifest.Shapes, entry)
	}
	return writeKeySetManifest(directory, manifest)
}

// Adds to the key set in directory an entry for each catalog shape it lacks, on its phase 1 and beacon
// (setup -extend), and leaves every entry it has as it is: their files, and their octets in keyset.json.
// It returns the extended keyset.json's SHA-256, a new id under which the old shapes keep their keys, so
// a host's cache of them stands. A set that lacks nothing keeps its id.
func ExtendSetup(ctx context.Context, directory string) ([]byte, error) {
	proof := DefaultProofSettings()
	return extendKeySetSetup(ctx, directory, proof, uint64(proof.DomainSize), productionKeySetCircuits(proof))
}

func extendKeySetSetup(ctx context.Context, directory string, proof *ProofSettings, domainSize uint64, circuits []*keySetCircuit) ([]byte, error) {
	encoded, err := os.ReadFile(filepath.Join(directory, keySetManifestName))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	keySet, err := parseKeySet(directory, sum[:], encoded, proof, domainSize, circuits)
	if err != nil {
		return nil, err
	}
	var missing []*keySetCircuit
	for _, circuit := range circuits {
		if keySet.shapeEntry(circuit.name) == nil {
			missing = append(missing, circuit)
		}
	}
	if len(missing) == 0 {
		return sum[:], nil
	}
	phase1 := keySet.manifest.Phase1[0]
	var contributions [][]byte
	for _, file := range phase1.Contributions {
		content, err := keySet.readFile(file)
		if err != nil {
			return nil, err
		}
		contributions = append(contributions, content)
	}
	commons, err := verifyPhase1At(phase1.DomainSize, keySet.beacon, contributions)
	if err != nil {
		return nil, err
	}
	manifest := keySet.manifest
	for _, circuit := range missing {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry, err := setupKeySetShape(directory, keySet.beacon, phase1.DomainSize, commons, circuit)
		if err != nil {
			return nil, err
		}
		manifest.Shapes = append(manifest.Shapes, entry)
	}
	return writeKeySetManifest(directory, manifest)
}

// One shape's phase 2 over phase 1's commons: its contribution, and the entry naming its circuit's digest
// and the keys the transcript fixes, as a prover host's check will derive them.
func setupKeySetShape(directory string, beacon []byte, domainSize uint64, commons *mpcsetup.SrsCommons, circuit *keySetCircuit) (*keySetShape, error) {
	compiled, err := circuit.compile()
	if err != nil {
		return nil, err
	}
	r1cs, err := setupR1cs(compiled)
	if err != nil {
		return nil, fmt.Errorf("smtpproof: %s: %w", circuit.name, err)
	}
	if domainSize < setupDomainSize(compiled) {
		return nil, fmt.Errorf("smtpproof: %s does not fit a domain of %d points", circuit.name, domainSize)
	}
	_, digest, err := circuitDigest(compiled)
	if err != nil {
		return nil, err
	}
	if digest != circuit.digest {
		return nil, fmt.Errorf("smtpproof: %s compiles to %s, where smtpShapeDigests names %q: run setup -digests first", circuit.name, digest, circuit.digest)
	}
	second := &mpcsetup.Phase2{}
	second.Initialize(r1cs, commons)
	second.Contribute()
	encoded, err := encodeContribution(second)
	if err != nil {
		return nil, err
	}
	contribution, err := writeKeySetFile(directory, circuit.name+"-phase2-0.bin", encoded)
	if err != nil {
		return nil, err
	}
	provingKey, verifyingKey, err := verifyPhase2(r1cs, commons, beacon, [][]byte{encoded})
	if err != nil {
		return nil, err
	}
	encodedProvingKey, err := encodeContribution(provingKey)
	if err != nil {
		return nil, err
	}
	provingKeySum := sha256.Sum256(encodedProvingKey)
	encodedVerifyingKey, err := encodeContribution(verifyingKey)
	if err != nil {
		return nil, err
	}
	verifyingFile, err := writeKeySetFile(directory, circuit.name+".vk", encodedVerifyingKey)
	if err != nil {
		return nil, err
	}
	return &keySetShape{
		Name:          circuit.name,
		CircuitSha256: digest,
		DomainSize:    domainSize,
		Contributions: []*keySetFile{contribution},
		ProvingKey:    &keySetKey{Sha256: hex.EncodeToString(provingKeySum[:]), ByteCount: int64(len(encodedProvingKey))},
		VerifyingKey:  verifyingFile,
	}, nil
}

func writeKeySetFile(directory string, name string, content []byte) (*keySetFile, error) {
	if err := os.WriteFile(filepath.Join(directory, name), content, 0o644); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	return &keySetFile{Name: name, Sha256: hex.EncodeToString(sum[:]), ByteCount: int64(len(content))}, nil
}

// Writes keyset.json whole under another name and renames it into place, and returns its SHA-256.
func writeKeySetManifest(directory string, manifest *keySetManifest) ([]byte, error) {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := keyFetchWriteWhole(filepath.Join(directory, keySetManifestName), encoded); err != nil {
		return nil, err
	}
	pin := sha256.Sum256(encoded)
	return pin[:], nil
}

// Writes shape_digests.go: each catalog shape's circuit digest as this build compiles it, which a
// ceremony writes into every entry it makes and a host requires of a cached circuit (DESIGN-DETAILS
// 3.2.7). setup -digests runs it beside a ceremony, after any change to a circuit.
func WriteShapeDigests(writer io.Writer) error {
	proof := DefaultProofSettings()
	source := &bytes.Buffer{}
	source.WriteString("package smtpproof\n\n")
	source.WriteString("// Each catalog shape's circuit digest: the SHA-256 of its compiled circuit as gnark's WriteTo writes it\n")
	source.WriteString("// (DESIGN-DETAILS 3.2.7). setup -digests writes this file beside a key set's pin, and\n")
	source.WriteString("// TestShapeDigestsAreThisBuilds holds it to the source, so a circuit changed without it fails there,\n")
	source.WriteString("// and a host proves nothing for a shape whose digest is not this one. A send loads a shape's cached\n")
	source.WriteString("// circuit by it without compiling.\n")
	source.WriteString("//\n//go:generate go run ./setup -digests shape_digests.go\n")
	source.WriteString("var smtpShapeDigests = map[string]string{\n")
	for _, entry := range proof.Shapes {
		compiled, err := compilePartShape(newPartShape(proof, entry))
		if err != nil {
			return err
		}
		_, digest, err := circuitDigest(compiled)
		if err != nil {
			return err
		}
		fmt.Fprintf(source, "\t%q: %q,\n", entry.Name(), digest)
	}
	source.WriteString("}\n")
	formatted, err := format.Source(source.Bytes())
	if err != nil {
		return err
	}
	_, err = writer.Write(formatted)
	return err
}

// A prover host's means to take keys, which every set it pins shares: its settings, its directory, its
// cache and, given a base url, its fetch; one check slot per VerifyConcurrency; and when each set may be
// tried again after a failure. Safe for concurrent use.
type keyHost struct {
	settings  *KeySettings
	directory string
	cache     *keyCache
	// Nil fetches nothing.
	fetch  *keyFetch
	checks chan struct{}
	// The Prover's loader, through which every set's backend proves, so one memory budget bounds them all
	// (prover_load.go). Nil, as tests of the check hold a host, loads each shape once and keeps it.
	loader *proverLoader
	// The clock and the wait, which tests replace.
	now  func() time.Time
	wait func(ctx context.Context, duration time.Duration) error

	stateLock sync.Mutex
	// By set id in hex, a set's failures in a row.
	retries map[string]*keyHostRetry
}

// When a set may be tried again, and the interval its next failure doubles.
type keyHostRetry struct {
	time     time.Time
	interval time.Duration
}

func newKeyHost(settings *KeySettings, directory string) *keyHost {
	host := &keyHost{
		settings:  settings,
		directory: directory,
		cache:     newKeyCache(filepath.Join(directory, keyHostCacheName)),
		checks:    make(chan struct{}, max(1, settings.VerifyConcurrency)),
		retries:   map[string]*keyHostRetry{},
		now:       time.Now,
		wait: func(ctx context.Context, duration time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(duration):
				return nil
			}
		},
	}
	if settings.BaseUrl != "" {
		host.fetch = newKeyFetch(settings)
	}
	return host
}

// The directory a pinned set's files are fetched to.
func (self *keyHost) keySetDirectory(id []byte) string {
	return filepath.Join(self.directory, keyHostKeySetsName, hex.EncodeToString(id))
}

// When a set may be tried again: the zero time once it may.
func (self *keyHost) retryTime(id []byte) time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if retry, ok := self.retries[hex.EncodeToString(id)]; ok {
		return retry.time
	}
	return time.Time{}
}

// Waits out the interval after a set's last failure, if it has not passed.
func (self *keyHost) waitRetry(ctx context.Context, id []byte) error {
	if remaining := self.retryTime(id).Sub(self.now()); 0 < remaining {
		return self.wait(ctx, remaining)
	}
	return nil
}

// A failure to retry: the set's next try waits FetchRetryInterval, doubling with each failure in a row to
// FetchRetryMaxInterval.
func (self *keyHost) failed(id []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	retry, ok := self.retries[hex.EncodeToString(id)]
	if !ok {
		retry = &keyHostRetry{}
		self.retries[hex.EncodeToString(id)] = retry
	}
	if retry.interval <= 0 {
		retry.interval = self.settings.FetchRetryInterval
	} else {
		retry.interval = min(2*retry.interval, self.settings.FetchRetryMaxInterval)
	}
	retry.time = self.now().Add(retry.interval)
}

func (self *keyHost) succeeded(id []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.retries, hex.EncodeToString(id))
}

// Records how a try at a set ended: a failure to retry backs the set off, and an outcome resets it. A
// refusal and absent files are outcomes, and so is a cancellation, which says nothing of the set.
func (self *keyHost) tried(id []byte, err error) {
	switch {
	case err == nil || isKeyRefusal(err) || errors.Is(err, errKeyFilesAbsent):
		self.succeeded(id)
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
	default:
		self.failed(id)
	}
}

// keyset.json from a pinned set's directory: at most ManifestMaxByteCount octets.
func (self *keyHost) readManifest(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, self.settings.ManifestMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	if self.settings.ManifestMaxByteCount < int64(len(encoded)) {
		return nil, fmt.Errorf("smtpproof: %s is longer than %d octets", path, self.settings.ManifestMaxByteCount)
	}
	return encoded, nil
}

// Step 1: a pinned set's keyset.json, fetched to keys/<id>/ when it is not there and kept only if it
// hashes to the pin, and opened on this host. errKeyFilesAbsent when it is not there and nothing fetches
// it; a refusal when it is the pin's and malformed.
func (self *keyHost) openKeySet(ctx context.Context, id []byte, proof *ProofSettings, domainSize uint64, circuits []*keySetCircuit) (*KeySet, error) {
	directory := self.keySetDirectory(id)
	path := filepath.Join(directory, keySetManifestName)
	encoded, err := self.readManifest(path)
	if errors.Is(err, os.ErrNotExist) {
		if self.fetch == nil {
			return nil, errKeyFilesAbsent
		}
		if err := self.waitRetry(ctx, id); err != nil {
			return nil, err
		}
		if err := self.fetch.fetchManifest(ctx, id, path); err != nil {
			return nil, err
		}
		encoded, err = self.readManifest(path)
	}
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	sum := sha256.Sum256(encoded)
	if !bytes.Equal(sum[:], id) {
		// not the pin's: deleted, and fetched again
		os.Remove(path)
		return nil, errors.New("smtpproof: keyset.json is not the pinned one")
	}
	keySet, err := parseKeySet(directory, id, encoded, proof, domainSize, circuits)
	if err != nil {
		return nil, err
	}
	keySet.host = self
	keySet.backend = newGroth16Backend(keySet.proof)
	cached := newCachedProvingKeys(keySet)
	if self.loader != nil {
		keySet.backend.loading = &shapeLoading{loader: self.loader, prefix: hex.EncodeToString(id) + "/", load: cached.load}
	} else {
		keySet.backend.source = cached
	}
	return keySet, nil
}

// A shape a host took as ready whose cache entry a load then found wrong: checked again, as if new.
func (self *KeySet) unready(name string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if state, ok := self.shapeStates[name]; ok && state.ready {
		delete(self.shapeStates, name)
	}
}

func (self *KeySet) shapeState(name string) keyShapeState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if state, ok := self.shapeStates[name]; ok {
		return *state
	}
	return keyShapeState{}
}

// The shapes a family needs in this set, in the set's order, and whether the set holds each kind a send
// may take: TLS 1.3's key shape, env, msg, hdr and body. TLS 1.2's key shapes come apart, since they add
// TLS 1.2's suites to a ready family and take nothing from one.
func (self *KeySet) familyCircuits(family ShapeFamily) ([]*keySetCircuit, []*keySetCircuit, bool) {
	var core []*keySetCircuit
	var tls12 []*keySetCircuit
	kinds := map[ShapeKind]bool{}
	for _, circuit := range self.catalog {
		if circuit.entry == nil || circuit.entry.Family != family {
			continue
		}
		if circuit.entry.Kind == ShapeKindKey && circuit.entry.Version == tlsVersion12 {
			tls12 = append(tls12, circuit)
			continue
		}
		if circuit.entry.Kind == ShapeKindKey && circuit.entry.Version != tlsVersion13 {
			continue
		}
		core = append(core, circuit)
		kinds[circuit.entry.Kind] = true
	}
	whole := kinds[ShapeKindKey] && kinds[ShapeKindEnvelope] && kinds[ShapeKindMessage] && kinds[ShapeKindHeader] && kinds[ShapeKindBody]
	return core, tls12, whole
}

// Whether every shape of a family is ready in this set, and whether TLS 1.2's key shapes are too
// (DESIGN-DETAILS 3.2.7's "a family is ready").
func (self *KeySet) familyReady(family ShapeFamily) (bool, bool) {
	core, tls12, whole := self.familyCircuits(family)
	if !whole {
		return false, false
	}
	allReady := func(circuits []*keySetCircuit) bool {
		for _, circuit := range circuits {
			if !self.shapeState(circuit.name).ready {
				return false
			}
		}
		return true
	}
	if !allReady(core) {
		return false, false
	}
	return true, 0 < len(tls12) && allReady(tls12)
}

// The suites of clientSuites, in their order, that this set can prove: TLS 1.3's once its family is
// ready, TLS 1.2's once its key shape is too. The TLS client offers only these (3.2.7).
func (self *KeySet) readySuites(clientSuites []uint16) []uint16 {
	ready := map[ShapeFamily][2]bool{}
	var suites []uint16
	for _, suite := range clientSuites {
		family := suiteFamily(suite)
		states, ok := ready[family]
		if !ok {
			familyReady, tls12Ready := self.familyReady(family)
			states = [2]bool{familyReady, tls12Ready}
			ready[family] = states
		}
		switch {
		case tlsSuiteCovered(tlsVersion13, suite) && states[0]:
			suites = append(suites, suite)
		case tlsSuiteCovered(tlsVersion12, suite) && states[0] && states[1]:
			suites = append(suites, suite)
		}
	}
	return suites
}

// The next shape a host's check takes, family by family in FamilyOrder: the first neither ready, refused
// nor absent, in a family none of whose shapes is refused or absent and which the set holds whole. Nil
// when none is left.
func (self *KeySet) nextShape() *keySetCircuit {
	for _, family := range self.host.settings.FamilyOrder {
		core, tls12, whole := self.familyCircuits(family)
		if !whole {
			continue
		}
		var next *keySetCircuit
		blocked := false
		for _, circuit := range append(slices.Clone(core), tls12...) {
			state := self.shapeState(circuit.name)
			if state.refused != nil || state.absent {
				// a family missing a core shape cannot be ready, and its TLS 1.2 shape adds nothing
				if slices.Contains(core, circuit) {
					blocked = true
				}
				continue
			}
			if !state.ready && next == nil {
				next = circuit
			}
		}
		if !blocked && next != nil {
			return next
		}
	}
	return nil
}

// Checks every shape of a family in this set, one at a time, as a prover host does at idle (DESIGN-DETAILS
// 3.2.7), and returns nil once the family is ready. A refused or absent shape, or a failure to retry, is
// the error. TLS 1.2's key shapes are checked too, and their refusal costs only TLS 1.2's suites.
func (self *KeySet) EnsureKeys(ctx context.Context, family ShapeFamily) error {
	if self.host == nil {
		return errors.New("smtpproof: a key set opened at the edge has no prover host's cache")
	}
	core, tls12, whole := self.familyCircuits(family)
	if !whole {
		return keyRefused("the key set does not hold every kind of %s's shapes", family)
	}
	for _, circuit := range core {
		state := self.shapeState(circuit.name)
		switch {
		case state.ready:
			continue
		case state.refused != nil:
			return state.refused
		}
		if err := self.ensureShape(ctx, circuit); err != nil {
			return err
		}
	}
	for _, circuit := range tls12 {
		if state := self.shapeState(circuit.name); state.ready || state.refused != nil {
			continue
		}
		if err := self.ensureShape(ctx, circuit); err != nil && !isKeyRefusal(err) {
			return err
		}
	}
	return nil
}

// Steps 2 to 8 for one shape of the set, and what they found, kept: ready, refused for this set, or its
// files absent. A failure to retry, a fetch's or the disk's, keeps nothing, backs the host off, and is
// returned.
func (self *KeySet) ensureShape(ctx context.Context, circuit *keySetCircuit) error {
	select {
	case self.host.checks <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() {
		<-self.host.checks
	}()
	if err := self.host.waitRetry(ctx, self.id); err != nil {
		return err
	}
	err := self.checkShape(ctx, circuit)
	self.host.tried(self.id, err)
	// what the check found becomes what the host offers and loads
	testHookBarrier("setup_keys.shape_state.before", circuit.name)
	defer testHookBarrier("setup_keys.shape_state.after", circuit.name)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		switch {
		case err == nil:
			self.shapeStates[circuit.name] = &keyShapeState{ready: true}
		case isKeyRefusal(err):
			self.shapeStates[circuit.name] = &keyShapeState{refused: err}
		case errors.Is(err, errKeyFilesAbsent):
			self.shapeStates[circuit.name] = &keyShapeState{absent: true}
		}
	}()
	return err
}

// DESIGN-DETAILS 3.2.7's steps 2 to 8, in order. Step 1, keyset.json by its pin, opened the set.
func (self *KeySet) checkShape(ctx context.Context, circuit *keySetCircuit) error {
	entry := self.shapeEntry(circuit.name)
	if entry == nil {
		return keyRefused("the key set holds no %s", circuit.name)
	}
	// 2: this build's circuit, whose digest must be the entry's and the release's table's
	compiled, err := circuit.compile()
	if err != nil {
		return err
	}
	r1cs, err := setupR1cs(compiled)
	if err != nil {
		return keyRefused("%s: %v", circuit.name, err)
	}
	encodedCircuit, digest, err := circuitDigest(compiled)
	if err != nil {
		return err
	}
	if digest != entry.CircuitSha256 || digest != circuit.digest {
		return keyRefused("%s: this build's circuit is not the one the key set was made for", circuit.name)
	}
	if entry.DomainSize < setupDomainSize(compiled) {
		return keyRefused("%s: the circuit does not fit the key set's domain", circuit.name)
	}
	// 3: the cache's entry for this circuit's digest and this key
	if self.host.cache.shapeReady(digest, entry.ProvingKey.Sha256) {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// 4: phase 1's commons, checked once for every shape and set on it
	commons, err := self.phase1Commons(ctx)
	if err != nil {
		return err
	}
	// 5: phase 2 over this circuit
	contributions, err := self.files(ctx, entry.Contributions)
	if err != nil {
		return err
	}
	provingKey, verifyingKey, err := verifyPhase2(r1cs, commons, self.beacon, contributions)
	if err != nil {
		return keyRefused("%s: %v", circuit.name, err)
	}
	// 6: both keys the transcript fixes are the ones keyset.json names, or the edge holds a verifying key no
	// proof made here would pass
	for _, check := range []struct {
		key       io.WriterTo
		sha256    string
		byteCount int64
	}{
		{key: provingKey, sha256: entry.ProvingKey.Sha256, byteCount: entry.ProvingKey.ByteCount},
		{key: verifyingKey, sha256: entry.VerifyingKey.Sha256, byteCount: entry.VerifyingKey.ByteCount},
	} {
		encoded, err := encodeContribution(check.key)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(encoded)
		if hex.EncodeToString(sum[:]) != check.sha256 || int64(len(encoded)) != check.byteCount {
			return keyRefused("%s: the transcript's keys are not the ones keyset.json names", circuit.name)
		}
	}
	// 7: the dump and the circuit, each whole and renamed, then the .ok
	if err := self.host.cache.storeShape(digest, entry.ProvingKey.Sha256, encodedCircuit, provingKey); err != nil {
		return err
	}
	// 8: the transcript, which no send reads
	if !self.host.settings.KeepTranscripts {
		self.removeFiles(entry.Contributions)
	}
	return nil
}

// Step 4: the commons of the set's one phase 1, from the cache, or checked once from its contributions and
// cached, so every later shape, of this set or another on the same phase 1, takes them as they are.
func (self *KeySet) phase1Commons(ctx context.Context) (*mpcsetup.SrsCommons, error) {
	phase1 := self.manifest.Phase1[0]
	phase1Sha256 := keyCachePhase1Hash(phase1.DomainSize, self.beacon, phase1.Contributions)
	if commons, ok := self.host.cache.loadPhase1(phase1Sha256, phase1.DomainSize); ok {
		return commons, nil
	}
	contributions, err := self.files(ctx, phase1.Contributions)
	if err != nil {
		return nil, err
	}
	commons, err := verifyPhase1At(phase1.DomainSize, self.beacon, contributions)
	if err != nil {
		return nil, keyRefused("%v", err)
	}
	if err := self.host.cache.storePhase1(phase1Sha256, commons); err != nil {
		return nil, err
	}
	if !self.host.settings.KeepTranscripts {
		self.removeFiles(phase1.Contributions)
	}
	return commons, nil
}

// The files a check reads, from the set's directory when they are there whole, else fetched. One that is
// there and is not the file keyset.json names is deleted before anything parses it.
func (self *KeySet) files(ctx context.Context, files []*keySetFile) ([][]byte, error) {
	var contents [][]byte
	for _, file := range files {
		if self.host.settings.FetchFileMaxByteCount < file.ByteCount {
			return nil, keyRefused("%s is %d octets, past the %d a host takes", file.Name, file.ByteCount, self.host.settings.FetchFileMaxByteCount)
		}
		content, err := self.readFile(file)
		if err != nil {
			path := filepath.Join(self.directory, file.Name)
			if !errors.Is(err, os.ErrNotExist) {
				os.Remove(path)
			}
			if self.host.fetch == nil {
				return nil, fmt.Errorf("%w: %s: %v", errKeyFilesAbsent, file.Name, err)
			}
			if err := self.host.fetch.fetchFile(ctx, self.id, file, path); err != nil {
				return nil, err
			}
			if content, err = self.readFile(file); err != nil {
				return nil, err
			}
		}
		contents = append(contents, content)
	}
	return contents, nil
}

func (self *KeySet) removeFiles(files []*keySetFile) {
	for _, file := range files {
		if keySetFileNameOk(file.Name) {
			os.Remove(filepath.Join(self.directory, file.Name))
		}
	}
}

// Loads a shape's proving key and circuit from a prover host's cache for sends under one key set: the
// entry for this build's digest, from smtpShapeDigests, and the key the set names, both files hashing to
// what its .ok records, with nothing compiled (DESIGN-DETAILS 3.2.7's load). A shape with no such entry has
// no keys, so its parts are refused and the host queues its mail. Safe for concurrent use.
type cachedProvingKeys struct {
	keySet *KeySet

	stateLock sync.Mutex
	loads     map[partShape]*cachedProvingLoad
}

// One shape's load, which a caller wanting the same shape meanwhile waits on rather than repeats.
type cachedProvingLoad struct {
	done chan struct{}
	keys *shapeKeys
	err  error
}

func newCachedProvingKeys(keySet *KeySet) *cachedProvingKeys {
	return &cachedProvingKeys{keySet: keySet, loads: map[partShape]*cachedProvingLoad{}}
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
		// a shape not cached yet may be soon, so a failure is not kept
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
	for _, candidate := range self.keySet.catalog {
		if candidate.shape != nil && *candidate.shape == *shape {
			circuit = candidate
		}
	}
	if circuit == nil || circuit.digest == "" {
		return nil, errNoKeys
	}
	entry := self.keySet.shapeEntry(circuit.name)
	if entry == nil || entry.CircuitSha256 != circuit.digest {
		return nil, errNoKeys
	}
	r1cs, provingKey, err := self.keySet.host.cache.loadShape(circuit.digest, entry.ProvingKey.Sha256)
	if err != nil {
		// a changed or lost cache file: the shape is checked again at idle (DESIGN-DETAILS 3.5)
		self.keySet.unready(circuit.name)
		return nil, errNoKeys
	}
	return &shapeKeys{shape: shape, compiled: r1cs, provingKey: provingKey}, nil
}

// A prover host's pinned key sets, newest first, and what its checks have made ready (DESIGN-DETAILS
// 3.2.7). Safe for concurrent use.
type proverKeys struct {
	host       *keyHost
	proof      *ProofSettings
	domainSize uint64
	circuits   []*keySetCircuit
	// The suites the TLS client offers, in its order, of which a set offers those it can prove.
	suites []uint16
	// One per pin, in the release's order.
	sets []*proverKeySet
}

// One pinned set on a prover host.
type proverKeySet struct {
	id []byte

	stateLock sync.Mutex
	// Once its keyset.json is here and is the pin's.
	keySet *KeySet
	// Its keyset.json is the pin's and malformed, which no retry changes.
	refused error
	// Its keyset.json is not here and nothing fetches it.
	absent bool
}

func newProverKeys(proof *ProofSettings, settings *KeySettings, pins [][]byte, directory string, circuits []*keySetCircuit, suites []uint16) *proverKeys {
	keys := &proverKeys{
		host:       newKeyHost(settings, directory),
		proof:      proof,
		domainSize: uint64(proof.DomainSize),
		circuits:   circuits,
		suites:     suites,
	}
	for _, pin := range pins {
		keys.sets = append(keys.sets, &proverKeySet{id: bytes.Clone(pin)})
	}
	return keys
}

// The set as far as the host has it: open, refused or absent.
func (self *proverKeySet) state() (*KeySet, error, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.keySet, self.refused, self.absent
}

// Step 1 for a pinned set the host has not opened: its keyset.json, fetched if need be.
func (self *proverKeys) open(ctx context.Context, set *proverKeySet) (*KeySet, error) {
	keySet, err := self.host.openKeySet(ctx, set.id, self.proof, self.domainSize, self.circuits)
	if err != nil {
		self.host.tried(set.id, err)
	}
	set.stateLock.Lock()
	defer set.stateLock.Unlock()
	switch {
	case err == nil:
		set.keySet = keySet
	case isKeyRefusal(err):
		set.refused = err
	case errors.Is(err, errKeyFilesAbsent):
		set.absent = true
	}
	return keySet, err
}

// Advances the host's check by one shape at most, newest pinned set first, and reports what is ready
// after it. A set backing off after a failure is passed over for the next set with work, so a newer pin
// whose files are not yet published leaves an older one to be checked, and only when every set with work
// is backing off does it wait for the first. A refused set or shape, or absent files, is an outcome kept
// in the readiness and no error; a failure to retry is returned beside the readiness, and backs that set
// off.
func (self *proverKeys) prepare(ctx context.Context) (*sidecar.SmtpProverReadiness, error) {
	self.host.cache.sweepPartials()
	for {
		var retryTime time.Time
		for _, set := range self.sets {
			keySet, refused, absent := set.state()
			if refused != nil || absent || (keySet != nil && keySet.nextShape() == nil) {
				continue
			}
			if setRetryTime := self.host.retryTime(set.id); self.host.now().Before(setRetryTime) {
				if retryTime.IsZero() || setRetryTime.Before(retryTime) {
					retryTime = setRetryTime
				}
				continue
			}
			if keySet == nil {
				var err error
				if keySet, err = self.open(ctx, set); err != nil {
					if isKeyRefusal(err) || errors.Is(err, errKeyFilesAbsent) {
						continue
					}
					return self.readiness(), err
				}
			}
			circuit := keySet.nextShape()
			if circuit == nil {
				continue
			}
			err := keySet.ensureShape(ctx, circuit)
			if err != nil && (isKeyRefusal(err) || errors.Is(err, errKeyFilesAbsent)) {
				err = nil
			}
			return self.readiness(), err
		}
		if retryTime.IsZero() {
			return self.readiness(), nil
		}
		if err := self.host.wait(ctx, retryTime.Sub(self.host.now())); err != nil {
			return self.readiness(), err
		}
	}
}

// The pinned sets with a ready family, newest first, each with the suites it can prove, and whether
// nothing is left that a check could advance.
func (self *proverKeys) readiness() *sidecar.SmtpProverReadiness {
	readiness := &sidecar.SmtpProverReadiness{Done: true}
	for _, set := range self.sets {
		keySet, refused, absent := set.state()
		if refused != nil || absent {
			continue
		}
		if keySet == nil {
			readiness.Done = false
			continue
		}
		if suites := keySet.readySuites(self.suites); 0 < len(suites) {
			readiness.KeySets = append(readiness.KeySets, &sidecar.SmtpProverKeySet{Id: keySet.Id(), ReadySuites: suites})
		}
		if keySet.nextShape() != nil {
			readiness.Done = false
		}
	}
	return readiness
}

// The newest pinned set with a ready family, or nil.
func (self *proverKeys) current() *KeySet {
	for _, set := range self.sets {
		if keySet, _, _ := set.state(); keySet != nil && 0 < len(keySet.readySuites(self.suites)) {
			return keySet
		}
	}
	return nil
}

// The set a job names and the suites it can prove, when it is a pinned set with a ready family.
func (self *proverKeys) forJob(id []byte) (*KeySet, []uint16, bool) {
	for _, set := range self.sets {
		if !bytes.Equal(set.id, id) {
			continue
		}
		keySet, _, _ := set.state()
		if keySet == nil {
			return nil, nil, false
		}
		suites := keySet.readySuites(self.suites)
		return keySet, suites, 0 < len(suites)
	}
	return nil, nil, false
}

// The partProver a Prover with key sets measures with: the newest pinned set with a ready family, at the
// moment it proves.
type proverKeysBackend struct {
	keys *proverKeys
}

// provePart of partProver.
func (self *proverKeysBackend) provePart(ctx context.Context, statement *partStatement, witness *partWitness) ([]byte, error) {
	keySet := self.keys.current()
	if keySet == nil {
		return nil, errNoKeys
	}
	return keySet.backend.provePart(ctx, statement, witness)
}
