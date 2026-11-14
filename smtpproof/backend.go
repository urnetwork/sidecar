package smtpproof

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
)

// Groth16 over BN254 (SPEC.md 10.1). A shape with no key behind it, or a part with no shape, proves
// and verifies nothing: both fail closed.

func init() {
	// a process holding keys and plaintext does not chatter, and gnark logs at debug by default
	logger.Disable()
}

var (
	errNoCircuit = errors.New("no circuit covers this part")
	errNoKeys    = errors.New("no keys are loaded for this part's circuit")
)

const (
	// gnark's count of commitments, ahead of the proof of knowledge of them.
	proofCountBytes = 4
	// A proof of a circuit with no commitment, as decodeProof reads it.
	proofBytes = 3*bn254.SizeOfG1AffineCompressed + bn254.SizeOfG2AffineCompressed + proofCountBytes
)

// The shapes this build proves: ProofSettings' catalog (DESIGN-DETAILS 3.2.6), each filling one domain.
// A part outside them is refused, on both sides.
func partShapes(proof *ProofSettings) []*partShape {
	shapes := make([]*partShape, 0, len(proof.Shapes))
	for _, entry := range proof.Shapes {
		shapes = append(shapes, newPartShape(proof, entry))
	}
	return shapes
}

// The shape a statement proves under, if any (DESIGN-DETAILS 3.2.6's first fit): its kind from the roles
// of the records it opens, its family from the suite, and of the catalog's shapes of that kind and family
// (and version, for a key part) the first whose pools hold its records. The prover and the edge call this
// over the same public values.
func partShapeFor(proof *ProofSettings, statement *partStatement) (*partShape, error) {
	roles, err := partRoles(statement)
	if err != nil {
		return nil, err
	}
	kind, err := partKindOf(statement, roles)
	if err != nil {
		return nil, err
	}
	family := suiteFamily(statement.session.suite)
	for _, shape := range partShapes(proof) {
		if shape.kind != kind || shape.family != family {
			continue
		}
		if kind == partKindKey && shape.version != statement.session.version {
			continue
		}
		if _, err := partAssignment(shape, statement); err == nil {
			return shape, nil
		}
	}
	return nil, errNoCircuit
}

// Compiles a shape. Every prover and verifier does this from its own source: nothing about a circuit
// comes from the edge (SPEC.md 10.2).
func compilePartShape(shape *partShape) (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, newPartCircuit(shape))
}

// One shape's compiled circuit and keys. A prover needs provingKey and compiled, a verifier only
// verifyingKey.
type shapeKeys struct {
	shape        *partShape
	compiled     constraint.ConstraintSystem
	provingKey   groth16.ProvingKey
	verifyingKey groth16.VerifyingKey
}

// Where a backend finds keys it does not hold, such as a prover host's cache of verified keys. It
// answers errNoKeys for a shape it has none for. Safe for concurrent use.
type shapeKeySource interface {
	keysFor(shape *partShape) (*shapeKeys, error)
}

// Proves and verifies parts under the keys it holds or its source gives, and refuses every other
// part. Safe for concurrent use.
type groth16Backend struct {
	// The catalog and limits the shapes come from.
	proof *ProofSettings

	stateLock sync.Mutex
	keys      map[partShape]*shapeKeys
	source    shapeKeySource
}

func newGroth16Backend(proof *ProofSettings) *groth16Backend {
	return &groth16Backend{proof: proof, keys: map[partShape]*shapeKeys{}}
}

func (self *groth16Backend) addKeys(keys *shapeKeys) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.keys[*keys.shape] = keys
}

func (self *groth16Backend) keysFor(shape *partShape) (*shapeKeys, error) {
	keys, source := func() (*shapeKeys, shapeKeySource) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.keys[*shape], self.source
	}()
	if keys != nil {
		return keys, nil
	}
	if source == nil {
		return nil, errNoKeys
	}
	return source.keysFor(shape)
}

// provePart of partProver. r and s come from crypto/rand inside gnark: a repeated pair would break
// zero knowledge (SPEC.md 10.2), and nothing here seeds them.
func (self *groth16Backend) provePart(ctx context.Context, statement *partStatement, witness *partWitness) ([]byte, error) {
	shape, err := partShapeFor(self.proof, statement)
	if err != nil {
		return nil, err
	}
	keys, err := self.keysFor(shape)
	if err != nil {
		return nil, err
	}
	if keys.provingKey == nil || keys.compiled == nil {
		return nil, errNoKeys
	}
	circuit, err := partAssignment(shape, statement)
	if err != nil {
		return nil, err
	}
	assignWitness(circuit, statement, witness)
	full, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	proof, err := groth16.Prove(keys.compiled, keys.provingKey, full)
	if err != nil {
		// not wrapped: gnark's solver writes wire values into its errors, and here those are keys and
		// plaintext. The relation has already passed, so this says the circuit and it disagree
		return nil, fmt.Errorf("smtpproof: part %d satisfies the relation and not its circuit", statement.index)
	}
	var encoded bytes.Buffer
	if _, err := proof.WriteTo(&encoded); err != nil {
		return nil, err
	}
	return encoded.Bytes(), nil
}

// verifyPart of partVerifier. The statement here is the edge's own, so the public wires are too.
func (self *groth16Backend) verifyPart(ctx context.Context, statement *partStatement, encoded []byte) error {
	shape, err := partShapeFor(self.proof, statement)
	if err != nil {
		return err
	}
	keys, err := self.keysFor(shape)
	if err != nil {
		return err
	}
	if keys.verifyingKey == nil {
		return errNoKeys
	}
	circuit, err := partAssignment(shape, statement)
	if err != nil {
		return err
	}
	public, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	proof, err := decodeProof(encoded)
	if err != nil {
		return fmt.Errorf("smtpproof: malformed proof: %w", err)
	}
	return groth16.Verify(proof, keys.verifyingKey, public)
}

// Reads a proof from a sidecar. gnark's ReadFrom would allocate whatever count of commitments the
// octets declare before reading one, which a hostile sidecar could set to ask for 256 GiB, and a point
// marked uncompressed moves that count elsewhere, so a length check alone is not enough. These circuits
// carry no commitment, so a proof has exactly one form: Ar, Bs and Krs compressed, a count of zero, and
// the empty proof of knowledge. SetBytes also refuses a point off the curve or outside its subgroup.
func decodeProof(encoded []byte) (*groth16bn254.Proof, error) {
	if len(encoded) != proofBytes {
		return nil, fmt.Errorf("%d octets, want %d", len(encoded), proofBytes)
	}
	proof := &groth16bn254.Proof{}
	offset := 0
	if _, err := proof.Ar.SetBytes(encoded[offset : offset+bn254.SizeOfG1AffineCompressed]); err != nil {
		return nil, err
	}
	offset += bn254.SizeOfG1AffineCompressed
	if _, err := proof.Bs.SetBytes(encoded[offset : offset+bn254.SizeOfG2AffineCompressed]); err != nil {
		return nil, err
	}
	offset += bn254.SizeOfG2AffineCompressed
	if _, err := proof.Krs.SetBytes(encoded[offset : offset+bn254.SizeOfG1AffineCompressed]); err != nil {
		return nil, err
	}
	offset += bn254.SizeOfG1AffineCompressed
	var noProofOfKnowledge bn254.G1Affine
	empty := noProofOfKnowledge.Bytes()
	if !bytes.Equal(encoded[offset:offset+proofCountBytes], make([]byte, proofCountBytes)) || !bytes.Equal(encoded[offset+proofCountBytes:], empty[:]) {
		return nil, errors.New("proof declares a commitment")
	}
	return proof, nil
}
