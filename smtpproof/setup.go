package smtpproof

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/bits"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

// The setup (SPEC.md 10.2, 10.3), by gnark's two-phase ceremony. The edge is the party soundness
// protects, so it may contribute alone. Zero knowledge against that same edge cannot rest on its
// honesty, so a prover host takes keys only from verifySetup, which recomputes them from a transcript
// over the circuit it compiled itself. A key that verification did not produce is never used.

// A ceremony's public record for one shape, which is all a prover needs to trust its keys. It holds
// contributions as bytes because gnark's verification assumes what ReadFrom checks, and modifies the
// last contribution it is given: so each verification decodes its own copies.
type setupTranscript struct {
	// A public value fixed after contributions end, so no contributor can grind the result.
	beacon []byte
	phase1 [][]byte
	phase2 [][]byte
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

// The power of two a shape's ceremony must cover.
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

// Runs a one-contributor ceremony, as the edge does. Its secrets live and die inside gnark's
// Contribute, which draws them from crypto/rand.
func runSetup(compiled constraint.ConstraintSystem, beacon []byte) (*setupTranscript, error) {
	r1cs, err := setupR1cs(compiled)
	if err != nil {
		return nil, err
	}
	transcript := &setupTranscript{beacon: beacon}
	first := mpcsetup.NewPhase1(setupDomainSize(compiled))
	first.Contribute()
	encoded, err := encodeContribution(first)
	if err != nil {
		return nil, err
	}
	transcript.phase1 = [][]byte{encoded}
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
	transcript.phase2 = [][]byte{encoded}
	return transcript, nil
}

func verifyPhase1(compiled constraint.ConstraintSystem, transcript *setupTranscript) (*mpcsetup.SrsCommons, error) {
	contributions, err := decodePhase1(transcript.phase1)
	if err != nil {
		return nil, fmt.Errorf("smtpproof: phase 1: %w", err)
	}
	commons, err := mpcsetup.VerifyPhase1(setupDomainSize(compiled), transcript.beacon, contributions...)
	if err != nil {
		return nil, fmt.Errorf("smtpproof: phase 1: %w", err)
	}
	return &commons, nil
}

// Checks a transcript against a circuit compiled from this build's own source, and returns the keys
// it fixes. Those keys have the form Groth16's zero knowledge needs, for whatever trapdoor the
// contributors hold (SPEC.md 10.2). Any flaw is an error, and no keys.
func verifySetup(compiled constraint.ConstraintSystem, transcript *setupTranscript) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	r1cs, err := setupR1cs(compiled)
	if err != nil {
		return nil, nil, err
	}
	if len(transcript.phase1) == 0 || len(transcript.phase2) == 0 {
		return nil, nil, errors.New("smtpproof: setup transcript holds no contribution")
	}
	commons, err := verifyPhase1(compiled, transcript)
	if err != nil {
		return nil, nil, err
	}
	contributions, err := decodePhase2(transcript.phase2)
	if err != nil {
		return nil, nil, fmt.Errorf("smtpproof: phase 2: %w", err)
	}
	provingKey, verifyingKey, err := mpcsetup.VerifyPhase2(r1cs, commons, transcript.beacon, contributions...)
	if err != nil {
		return nil, nil, fmt.Errorf("smtpproof: phase 2: %w", err)
	}
	return provingKey, verifyingKey, nil
}
