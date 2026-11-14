package smtpproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// The setup (SPEC.md 10.2, 10.3), by gnark's two-phase ceremony. The edge is the party soundness
// protects, so it may contribute alone. Zero knowledge against that same edge cannot rest on its
// honesty, so a prover host takes keys only from its own check of the transcript against the circuit
// it compiled itself, which recomputes them. A key that verification did not produce is never used.
// setup_keys.go holds a release's key sets and the ceremony over every production shape, setup_cache.go
// what a host keeps of its checks, and setup_fetch.go how it fetches what it checks.

// A ceremony's public record for one shape, which is all a prover needs to trust its keys. It holds
// contributions as bytes because gnark's verification assumes what ReadFrom checks, and modifies the
// last contribution it is given: so each verification decodes its own copies.
type SetupTranscript struct {
	// A public value fixed after contributions end, so no contributor can grind the result.
	Beacon []byte
	// The domain the phase 1 contributions are for, a power of two the circuit fits in; 0 for the
	// circuit's own, the least that holds it. A key set's one phase 1 serves every shape (DESIGN-DETAILS
	// 3.2.7), so a smaller shape takes the larger domain.
	DomainSize uint64
	// Each contribution in order, as gnark's mpcsetup encodes it: phase 1 for the domain, then phase 2
	// for the shape.
	Phase1 [][]byte
	Phase2 [][]byte
}

// The form gnark's WriteTo gives a contribution, which checkPhase1Form and checkPhase2Form hold one to
// before gnark reads it: gnark allocates whatever count an encoding declares before it reads a point, so a
// file that hashes to its pin and is malformed would otherwise ask a host for terabytes and end the process
// where it should refuse the shape. Each point is compressed, its first octet's top two bits marking how.
const (
	setupG1Bytes           = bn254.SizeOfG1AffineCompressed
	setupG2Bytes           = bn254.SizeOfG2AffineCompressed
	setupPointMask         = byte(0b11 << 6)
	setupPointUncompressed = byte(0b00 << 6)
)

// A walk over a contribution's octets that allocates nothing. The first flaw it meets is its error.
type setupForm struct {
	encoded []byte
	offset  int
	err     error
}

func (self *setupForm) take(count uint64) []byte {
	if self.err != nil {
		return nil
	}
	if uint64(len(self.encoded)-self.offset) < count {
		self.err = errors.New("shorter than its form")
		return nil
	}
	taken := self.encoded[self.offset : self.offset+int(count)]
	self.offset += int(count)
	return taken
}

// A big-endian count of octets octets.
func (self *setupForm) count(octets uint64) uint64 {
	taken := self.take(octets)
	value := uint64(0)
	for _, octet := range taken {
		value = value<<8 | uint64(octet)
	}
	return value
}

// count compressed points of size octets each.
func (self *setupForm) points(size uint64, count uint64) {
	for i := uint64(0); i < count && self.err == nil; i += 1 {
		if taken := self.take(size); taken != nil && taken[0]&setupPointMask == setupPointUncompressed {
			self.err = errors.New("a point not compressed")
		}
	}
}

// A slice of compressed points, its count first, which must be want.
func (self *setupForm) slice(size uint64, want uint64) {
	if count := self.count(4); self.err == nil && count != want {
		self.err = fmt.Errorf("%d points where its form has %d", count, want)
	}
	self.points(size, want)
}

// What a contribution ends in: the challenge it was made over, a 1-octet length and its octets, and
// nothing after.
func (self *setupForm) end() error {
	self.take(self.count(1))
	if self.err == nil && self.offset != len(self.encoded) {
		self.err = errors.New("longer than its form")
	}
	return self.err
}

// Phase 1's form for a domain of domainSize points: three update proofs, the commons of that domain, and
// the challenge.
func checkPhase1Form(encoded []byte, domainSize uint64) error {
	form := &setupForm{encoded: encoded}
	for i := 0; i < 3; i += 1 {
		form.points(setupG1Bytes, 1)
		form.points(setupG2Bytes, 1)
	}
	if declared := form.count(8); form.err == nil && declared != domainSize {
		return fmt.Errorf("a phase 1 for %d points, not %d", declared, domainSize)
	}
	// [β]₂, [τⁱ]₁ to 2N-2, [τⁱ]₂ to N-1, [βτⁱ]₁ and [ατⁱ]₁ to N-1
	form.points(setupG2Bytes, 1)
	form.points(setupG1Bytes, 2*domainSize-2)
	form.points(setupG2Bytes, domainSize-1)
	form.points(setupG1Bytes, 2*domainSize)
	if err := form.end(); err != nil {
		return fmt.Errorf("a phase 1 contribution: %w", err)
	}
	return nil
}

// Phase 2's form for a circuit with privateCount private wires over a domain of domainSize points: no
// commitment, δ, a key per private wire, the domain's Z, δ in G2, the update proof, and the challenge.
func checkPhase2Form(encoded []byte, privateCount uint64, domainSize uint64) error {
	form := &setupForm{encoded: encoded}
	if commitments := form.count(2); form.err == nil && commitments != 0 {
		return fmt.Errorf("a phase 2 with %d commitments", commitments)
	}
	form.points(setupG1Bytes, 1)
	form.slice(setupG1Bytes, privateCount)
	form.slice(setupG1Bytes, domainSize-1)
	form.points(setupG2Bytes, 1)
	form.points(setupG1Bytes, 1)
	form.points(setupG2Bytes, 1)
	if err := form.end(); err != nil {
		return fmt.Errorf("a phase 2 contribution: %w", err)
	}
	return nil
}

func encodeContribution(contribution io.WriterTo) ([]byte, error) {
	var encoded bytes.Buffer
	if _, err := contribution.WriteTo(&encoded); err != nil {
		return nil, err
	}
	return encoded.Bytes(), nil
}

func decodePhase1(encoded [][]byte) ([]*mpcsetup.Phase1, error) {
	contributions := make([]*mpcsetup.Phase1, 0, len(encoded))
	for _, bytesOf := range encoded {
		contribution := &mpcsetup.Phase1{}
		if _, err := contribution.ReadFrom(bytes.NewReader(bytesOf)); err != nil {
			return nil, err
		}
		contributions = append(contributions, contribution)
	}
	return contributions, nil
}

func decodePhase2(encoded [][]byte) ([]*mpcsetup.Phase2, error) {
	contributions := make([]*mpcsetup.Phase2, 0, len(encoded))
	for _, bytesOf := range encoded {
		contribution := &mpcsetup.Phase2{}
		if _, err := contribution.ReadFrom(bytes.NewReader(bytesOf)); err != nil {
			return nil, err
		}
		contributions = append(contributions, contribution)
	}
	return contributions, nil
}

// The least power of two a shape's ceremony must cover.
func setupDomainSize(compiled constraint.ConstraintSystem) uint64 {
	size := uint64(compiled.GetNbConstraints() + compiled.GetNbPublicVariables())
	return 1 << bits.Len64(size-1)
}

func setupR1cs(compiled constraint.ConstraintSystem) (*cs.R1CS, error) {
	r1cs, ok := compiled.(*cs.R1CS)
	if !ok {
		return nil, errors.New("not a BN254 R1CS")
	}
	if commitments := compiled.GetCommitments(); commitments != nil && len(commitments.CommitmentIndexes()) != 0 {
		// SPEC.md 10.2's argument is vanilla Groth16's, and a commitment would need its own
		return nil, errors.New("circuit carries a commitment")
	}
	return r1cs, nil
}

// A compiled circuit as gnark's WriteTo writes it, and its SHA-256 in hex: a shape's circuit_sha256
// (DESIGN-DETAILS 3.2.7). The encoding is deterministic, and holds no name the release's module path
// rewrite changes (circuit_bits.go's hint ids), which TestShapeDigestsAreThisBuilds holds.
func circuitDigest(compiled constraint.ConstraintSystem) ([]byte, string, error) {
	encoded, err := encodeContribution(compiled)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(encoded)
	return encoded, hex.EncodeToString(sum[:]), nil
}

// Runs a one-contributor ceremony for one shape at its own domain size, as the edge does. Its secrets
// live and die inside gnark's Contribute, which draws them from crypto/rand.
func runSetup(compiled constraint.ConstraintSystem, beacon []byte) (*SetupTranscript, error) {
	r1cs, err := setupR1cs(compiled)
	if err != nil {
		return nil, err
	}
	transcript := &SetupTranscript{Beacon: beacon}
	first := mpcsetup.NewPhase1(setupDomainSize(compiled))
	first.Contribute()
	encoded, err := encodeContribution(first)
	if err != nil {
		return nil, err
	}
	transcript.Phase1 = [][]byte{encoded}
	commons, err := verifyPhase1(compiled, transcript)
	if err != nil {
		return nil, err
	}
	second := &mpcsetup.Phase2{}
	second.Initialize(r1cs, commons)
	second.Contribute()
	if encoded, err = encodeContribution(second); err != nil {
		return nil, err
	}
	transcript.Phase2 = [][]byte{encoded}
	return transcript, nil
}

// Checks phase 1's contributions for a domain of domainSize points and seals them with the beacon:
// the commons every shape of that domain is set up over.
func verifyPhase1At(domainSize uint64, beacon []byte, encoded [][]byte) (*mpcsetup.SrsCommons, error) {
	if domainSize < 2 || domainSize&(domainSize-1) != 0 {
		return nil, fmt.Errorf("smtpproof: phase 1: a domain of %d points", domainSize)
	}
	for _, contribution := range encoded {
		if err := checkPhase1Form(contribution, domainSize); err != nil {
			return nil, fmt.Errorf("smtpproof: phase 1: %w", err)
		}
	}
	contributions, err := decodePhase1(encoded)
	if err != nil {
		return nil, fmt.Errorf("smtpproof: phase 1: %w", err)
	}
	commons, err := mpcsetup.VerifyPhase1(domainSize, beacon, contributions...)
	if err != nil {
		return nil, fmt.Errorf("smtpproof: phase 1: %w", err)
	}
	return &commons, nil
}

// The domain a transcript's phase 1 is for, which the circuit must fit.
func transcriptDomainSize(compiled constraint.ConstraintSystem, transcript *SetupTranscript) (uint64, error) {
	if transcript.DomainSize == 0 {
		return setupDomainSize(compiled), nil
	}
	if transcript.DomainSize < setupDomainSize(compiled) {
		return 0, fmt.Errorf("smtpproof: a circuit of %d points does not fit a domain of %d", setupDomainSize(compiled), transcript.DomainSize)
	}
	return transcript.DomainSize, nil
}

func verifyPhase1(compiled constraint.ConstraintSystem, transcript *SetupTranscript) (*mpcsetup.SrsCommons, error) {
	domainSize, err := transcriptDomainSize(compiled, transcript)
	if err != nil {
		return nil, err
	}
	return verifyPhase1At(domainSize, transcript.Beacon, transcript.Phase1)
}

// Checks phase 2's contributions for a circuit over phase 1's commons, and returns the keys they fix.
// The circuit must fit the commons' domain, which gnark would otherwise panic on.
func verifyPhase2(r1cs *cs.R1CS, commons *mpcsetup.SrsCommons, beacon []byte, encoded [][]byte) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	domainSize := uint64(len(commons.G1.AlphaTau))
	if domainSize < setupDomainSize(r1cs) {
		return nil, nil, errors.New("smtpproof: phase 2: the circuit does not fit phase 1's domain")
	}
	internalCount, secretCount, _ := r1cs.GetNbVariables()
	for _, contribution := range encoded {
		if err := checkPhase2Form(contribution, uint64(internalCount+secretCount), domainSize); err != nil {
			return nil, nil, fmt.Errorf("smtpproof: phase 2: %w", err)
		}
	}
	contributions, err := decodePhase2(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("smtpproof: phase 2: %w", err)
	}
	provingKey, verifyingKey, err := mpcsetup.VerifyPhase2(r1cs, commons, beacon, contributions...)
	if err != nil {
		return nil, nil, fmt.Errorf("smtpproof: phase 2: %w", err)
	}
	return provingKey, verifyingKey, nil
}

// Checks a transcript against a circuit compiled from this build's own source, and returns the keys
// it fixes. Those keys have the form Groth16's zero knowledge needs, for whatever trapdoor the
// contributors hold (SPEC.md 10.2). Any flaw is an error, and no keys.
func VerifySetupTranscript(compiled constraint.ConstraintSystem, transcript *SetupTranscript) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	r1cs, err := setupR1cs(compiled)
	if err != nil {
		return nil, nil, err
	}
	if len(transcript.Phase1) == 0 || len(transcript.Phase2) == 0 {
		return nil, nil, errors.New("smtpproof: setup transcript holds no contribution")
	}
	commons, err := verifyPhase1(compiled, transcript)
	if err != nil {
		return nil, nil, err
	}
	return verifyPhase2(r1cs, commons, transcript.Beacon, transcript.Phase2)
}
