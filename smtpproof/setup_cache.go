package smtpproof

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
)

// A prover host's cache of what its own checks produced (DESIGN-DETAILS 3.2.7, steps 3, 4 and 7), in one
// directory:
//
//	<d>-<k>.ok, .pk, .r1cs   a shape's entry: the proving key the check derived, as gnark's dump, and the
//	                         circuit it was checked against, under an .ok naming the circuit's digest d
//	                         and the proving key's hash k, and recording both files' hashes
//	phase1-<h>.ok, .commons  a phase 1's commons, h the hash of its beacon and contributions
//
// An entry is named by the circuit's digest as well as the key's hash, and a build takes only the entry
// of its own circuit's digest, which is what keeps a key checked against one circuit from proving
// another's witness (3.1 E; ProofKeys.tla's StaleCache). Every file is written under a partial name,
// synced and renamed, and the .ok last, so a crash leaves no entry, and a file is taken only when it
// hashes to what its .ok records. Nothing here leaves the host, which is why a dump, this platform's
// memory, suits it. Safe for concurrent use.

// What a partial file's name holds, between the final name and a random suffix.
const keyCachePartialMark = ".partial."

// The random octets a partial file's name ends in, in hex: enough that two writers never take one name.
const keyCachePartialRandomOctets = 8

// A phase 1 commons' hash, ahead of its domain size, beacon and contributions' hashes.
const keyCachePhase1Tag = "smtpproof phase 1 commons v1"

type keyCache struct {
	directory string

	// Stray partial files are deleted once a process, before its first write.
	sweep sync.Once
}

// An .ok file: what it names, and each file of the entry by name, hash and length.
type keyCacheRecord struct {
	CircuitSha256    string        `json:"circuit_sha256,omitempty"`
	ProvingKeySha256 string        `json:"proving_key_sha256,omitempty"`
	Phase1Sha256     string        `json:"phase1_sha256,omitempty"`
	Files            []*keySetFile `json:"files"`
}

func newKeyCache(directory string) *keyCache {
	return &keyCache{directory: directory}
}

func keyCacheShapeStem(circuitSha256 string, provingKeySha256 string) string {
	return circuitSha256 + "-" + provingKeySha256
}

// The phase 1 a key set's shapes share: SHA-256 over a tag, the domain size, the beacon and each
// contribution's hash in order, so two key sets on one phase 1 share its commons.
func keyCachePhase1Hash(domainSize uint64, beacon []byte, contributions []*keySetFile) string {
	digest := sha256.New()
	digest.Write([]byte(keyCachePhase1Tag))
	digest.Write(binary.BigEndian.AppendUint64(nil, domainSize))
	digest.Write(binary.BigEndian.AppendUint64(nil, uint64(len(beacon))))
	digest.Write(beacon)
	for _, file := range contributions {
		digest.Write([]byte(file.Sha256))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// Deletes the partial files a crash left. Another process's write in flight loses its partial file and
// fails, and is checked again.
func (self *keyCache) sweepPartials() {
	self.sweep.Do(func() {
		entries, err := os.ReadDir(self.directory)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if strings.Contains(entry.Name(), keyCachePartialMark) {
				os.Remove(filepath.Join(self.directory, entry.Name()))
			}
		}
	})
}

// Writes a file under a partial name, syncs it and renames it to name, and returns its hash and length.
func (self *keyCache) writeFile(name string, write func(writer io.Writer) error) (*keySetFile, error) {
	self.sweepPartials()
	if err := os.MkdirAll(self.directory, 0o700); err != nil {
		return nil, err
	}
	suffix := make([]byte, keyCachePartialRandomOctets)
	if _, err := rand.Read(suffix); err != nil {
		return nil, err
	}
	partialPath := filepath.Join(self.directory, name+keyCachePartialMark+hex.EncodeToString(suffix))
	file, err := os.OpenFile(partialPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	written, err := func() (*keySetFile, error) {
		defer file.Close()
		digest := sha256.New()
		counter := &keyCacheCounter{}
		if err := write(io.MultiWriter(file, digest, counter)); err != nil {
			return nil, err
		}
		if err := file.Sync(); err != nil {
			return nil, err
		}
		return &keySetFile{Name: name, Sha256: hex.EncodeToString(digest.Sum(nil)), ByteCount: counter.count}, nil
	}()
	if err == nil {
		// the file is whole and synced, and appears under its name here: an .ok, last, makes an entry
		testHookBarrier("setup_cache.rename.before", name)
		err = os.Rename(partialPath, filepath.Join(self.directory, name))
		testHookBarrier("setup_cache.rename.after", name)
	}
	if err != nil {
		os.Remove(partialPath)
		return nil, err
	}
	return written, nil
}

// Counts what passes through it.
type keyCacheCounter struct {
	count int64
}

func (self *keyCacheCounter) Write(octets []byte) (int, error) {
	self.count += int64(len(octets))
	return len(octets), nil
}

// Reads a file the cache wrote, refusing it unless it is the length and hash its record names. Its
// octets are read whole before any is parsed, since a dump is read without checks.
func (self *keyCache) readFile(file *keySetFile) ([]byte, error) {
	if !keySetFileNameOk(file.Name) {
		return nil, errors.New("a cache record names a file outside the cache")
	}
	path := filepath.Join(self.directory, file.Name)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() != file.ByteCount {
		return nil, fmt.Errorf("%s is %d octets, not %d", file.Name, info.Size(), file.ByteCount)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != file.Sha256 {
		return nil, fmt.Errorf("%s is not the file its record names", file.Name)
	}
	return content, nil
}

// Hashes a file the cache wrote without holding it, as a ready check does.
func (self *keyCache) fileOk(file *keySetFile) bool {
	if !keySetFileNameOk(file.Name) {
		return false
	}
	handle, err := os.Open(filepath.Join(self.directory, file.Name))
	if err != nil {
		return false
	}
	defer handle.Close()
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(handle, file.ByteCount+1))
	return err == nil && count == file.ByteCount && hex.EncodeToString(digest.Sum(nil)) == file.Sha256
}

// Reads an .ok, refusing one that names anything but what is asked of it.
func (self *keyCache) readRecord(name string, want func(record *keyCacheRecord) bool) (*keyCacheRecord, error) {
	encoded, err := os.ReadFile(filepath.Join(self.directory, name))
	if err != nil {
		return nil, err
	}
	record := &keyCacheRecord{}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(record); err != nil {
		return nil, err
	}
	if !want(record) {
		return nil, fmt.Errorf("%s names another entry", name)
	}
	return record, nil
}

func (self *keyCache) writeRecord(name string, record *keyCacheRecord) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = self.writeFile(name, func(writer io.Writer) error {
		_, err := writer.Write(encoded)
		return err
	})
	return err
}

// A shape's .ok, if it names exactly this circuit and this proving key and its two files: the dump, then
// the circuit.
func (self *keyCache) shapeRecord(circuitSha256 string, provingKeySha256 string) (*keyCacheRecord, error) {
	stem := keyCacheShapeStem(circuitSha256, provingKeySha256)
	return self.readRecord(stem+".ok", func(record *keyCacheRecord) bool {
		return record.CircuitSha256 == circuitSha256 && record.ProvingKeySha256 == provingKeySha256 && record.Phase1Sha256 == "" &&
			len(record.Files) == 2 && record.Files[0] != nil && record.Files[0].Name == stem+".pk" &&
			record.Files[1] != nil && record.Files[1].Name == stem+".r1cs" &&
			// the circuit file is the circuit whose digest names the entry
			record.Files[1].Sha256 == circuitSha256
	})
}

// Step 3's test: an entry for exactly this circuit's digest and this proving key, both of whose files
// hash to what its .ok records.
func (self *keyCache) shapeReady(circuitSha256 string, provingKeySha256 string) bool {
	record, err := self.shapeRecord(circuitSha256, provingKeySha256)
	if err != nil {
		return false
	}
	for _, file := range record.Files {
		if !self.fileOk(file) {
			return false
		}
	}
	return true
}

// Loads a shape's entry for a send: step 3's test and nothing less, with nothing compiled. Anything
// else is no keys, and the shape is checked again at idle.
func (self *keyCache) loadShape(circuitSha256 string, provingKeySha256 string) (constraint.ConstraintSystem, groth16.ProvingKey, error) {
	record, err := self.shapeRecord(circuitSha256, provingKeySha256)
	if err != nil {
		return nil, nil, errNoKeys
	}
	dump, err := self.readFile(record.Files[0])
	if err != nil {
		return nil, nil, errNoKeys
	}
	encodedCircuit, err := self.readFile(record.Files[1])
	if err != nil {
		return nil, nil, errNoKeys
	}
	provingKey := groth16.NewProvingKey(ecc.BN254)
	if err := provingKey.ReadDump(bytes.NewReader(dump)); err != nil {
		return nil, nil, errNoKeys
	}
	// gnark's own form for reading a circuit back: a system with nothing in it yet
	r1cs := groth16.NewCS(ecc.BN254)
	if _, err := r1cs.ReadFrom(bytes.NewReader(encodedCircuit)); err != nil {
		return nil, nil, errNoKeys
	}
	if _, err := setupR1cs(r1cs); err != nil {
		return nil, nil, errNoKeys
	}
	return r1cs, provingKey, nil
}

// Step 7: the proving key as gnark's dump and the circuit it was checked against, each written whole
// and renamed, then the .ok that names both, last.
func (self *keyCache) storeShape(circuitSha256 string, provingKeySha256 string, encodedCircuit []byte, provingKey groth16.ProvingKey) error {
	stem := keyCacheShapeStem(circuitSha256, provingKeySha256)
	dumpFile, err := self.writeFile(stem+".pk", func(writer io.Writer) error {
		return provingKey.WriteDump(writer)
	})
	if err != nil {
		return err
	}
	circuitFile, err := self.writeFile(stem+".r1cs", func(writer io.Writer) error {
		_, err := writer.Write(encodedCircuit)
		return err
	})
	if err != nil {
		return err
	}
	return self.writeRecord(stem+".ok", &keyCacheRecord{
		CircuitSha256:    circuitSha256,
		ProvingKeySha256: provingKeySha256,
		Files:            []*keySetFile{dumpFile, circuitFile},
	})
}

// Step 4's cache: a phase 1's commons for a domain of domainSize points, if its .ok names it, the file
// hashes to the record, and it declares that domain before gnark allocates for it.
func (self *keyCache) loadPhase1(phase1Sha256 string, domainSize uint64) (*mpcsetup.SrsCommons, bool) {
	name := "phase1-" + phase1Sha256
	record, err := self.readRecord(name+".ok", func(record *keyCacheRecord) bool {
		return record.Phase1Sha256 == phase1Sha256 && record.CircuitSha256 == "" && record.ProvingKeySha256 == "" &&
			len(record.Files) == 1 && record.Files[0] != nil && record.Files[0].Name == name+".commons"
	})
	if err != nil {
		return nil, false
	}
	encoded, err := self.readFile(record.Files[0])
	if err != nil || len(encoded) < 8 || binary.BigEndian.Uint64(encoded) != domainSize {
		return nil, false
	}
	commons := &mpcsetup.SrsCommons{}
	if _, err := commons.ReadFrom(bytes.NewReader(encoded)); err != nil {
		return nil, false
	}
	return commons, true
}

func (self *keyCache) storePhase1(phase1Sha256 string, commons *mpcsetup.SrsCommons) error {
	name := "phase1-" + phase1Sha256
	commonsFile, err := self.writeFile(name+".commons", func(writer io.Writer) error {
		_, err := commons.WriteTo(writer)
		return err
	})
	if err != nil {
		return err
	}
	return self.writeRecord(name+".ok", &keyCacheRecord{Phase1Sha256: phase1Sha256, Files: []*keySetFile{commonsFile}})
}
