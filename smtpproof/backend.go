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

// The shapes this build proves. A part outside them is refused, on both sides.
func partShapes() []*partShape {
	return []*partShape{
		{kind: partKindEhlo, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 4},
		{kind: partKindEhlo, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 1},
		// sized for D-SMTP-16's 10 recipients and a typical EHLO reply
		{kind: partKindEnvelope, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 48, serverBlocks: 24, localOctets: true},
		{kind: partKindEnvelope, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 12, serverBlocks: 6, localOctets: true},
		// D-SMTP-16's 4 KiB header block, the envelope's replies, and BDAT and QUIT or DATA's end
		{kind: partKindMessage, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 4, serverBlocks: 24, headerBlocks: 256},
		{kind: partKindMessage, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 2, serverBlocks: 6, headerBlocks: 64},
		// DATA with a 2 KiB first body part beside the header block
		{kind: partKindMessage, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 4, serverBlocks: 24, headerBlocks: 256, bodyBlocks: 128},
		{kind: partKindMessage, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 2, serverBlocks: 6, headerBlocks: 64, bodyBlocks: 32},
		// a later DATA part. A server record in one has no circuit yet, so it fails closed
		{kind: partKindBody, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 2, bodyBlocks: 128},
		{kind: partKindBody, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 2, bodyBlocks: 32},
		// TLS 1.2, for Exchange Online among others: AES-128-GCM alone, under each of its two suites
		{kind: partKindEhlo, version: tlsVersion12, suite: tlsSuiteEcdheRsaAes128GcmSha256, clientBlocks: 4},
		{kind: partKindEhlo, version: tlsVersion12, suite: tlsSuiteEcdheEcdsaAes128GcmSha256, clientBlocks: 4},
		{kind: partKindEnvelope, version: tlsVersion12, suite: tlsSuiteEcdheRsaAes128GcmSha256, clientBlocks: 48, serverBlocks: 24, localOctets: true},
		{kind: partKindEnvelope, version: tlsVersion12, suite: tlsSuiteEcdheEcdsaAes128GcmSha256, clientBlocks: 48, serverBlocks: 24, localOctets: true},
		{kind: partKindMessage, version: tlsVersion12, suite: tlsSuiteEcdheRsaAes128GcmSha256, clientBlocks: 4, serverBlocks: 24, headerBlocks: 256},
		{kind: partKindMessage, version: tlsVersion12, suite: tlsSuiteEcdheEcdsaAes128GcmSha256, clientBlocks: 4, serverBlocks: 24, headerBlocks: 256},
		{kind: partKindMessage, version: tlsVersion12, suite: tlsSuiteEcdheRsaAes128GcmSha256, clientBlocks: 4, serverBlocks: 24, headerBlocks: 256, bodyBlocks: 128},
		{kind: partKindMessage, version: tlsVersion12, suite: tlsSuiteEcdheEcdsaAes128GcmSha256, clientBlocks: 4, serverBlocks: 24, headerBlocks: 256, bodyBlocks: 128},
		{kind: partKindBody, version: tlsVersion12, suite: tlsSuiteEcdheRsaAes128GcmSha256, clientBlocks: 2, bodyBlocks: 128},
		{kind: partKindBody, version: tlsVersion12, suite: tlsSuiteEcdheEcdsaAes128GcmSha256, clientBlocks: 2, bodyBlocks: 128},
	}
}

// Which circuit a part's index calls for.
func partKindOf(statement *partStatement) partKind {
	switch statement.index {
	case 1:
		return partKindEhlo
	case 2:
		return partKindEnvelope
	case 3:
		return partKindMessage
	default:
		return partKindBody
	}
}

// The shape a statement proves under, if any: the first whose blocks its records fit.
func partShapeFor(statement *partStatement) (*partShape, error) {
	session := statement.session
	for _, shape := range partShapes() {
		if shape.version != session.version || shape.suite != session.suite {
			continue
		}
		if shape.kind != partKindOf(statement) {
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

// Proves and verifies parts under the keys it holds, and refuses every other part. Safe for
// concurrent use.
type groth16Backend struct {
	stateLock sync.Mutex
	keys      map[partShape]*shapeKeys
}

func newGroth16Backend() *groth16Backend {
	return &groth16Backend{keys: map[partShape]*shapeKeys{}}
}

func (self *groth16Backend) addKeys(keys *shapeKeys) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.keys[*keys.shape] = keys
}

func (self *groth16Backend) keysFor(shape *partShape) (*shapeKeys, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	keys, ok := self.keys[*shape]
	if !ok {
		return nil, errNoKeys
	}
	return keys, nil
}

// provePart of partProver. r and s come from crypto/rand inside gnark: a repeated pair would break
// zero knowledge (SPEC.md 10.2), and nothing here seeds them.
func (self *groth16Backend) provePart(ctx context.Context, statement *partStatement, witness *partWitness) ([]byte, error) {
	shape, err := partShapeFor(statement)
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
		return nil, fmt.Errorf("smtpproof: proving part %d: %w", statement.index, err)
	}
	var encoded bytes.Buffer
	if _, err := proof.WriteTo(&encoded); err != nil {
		return nil, err
	}
	return encoded.Bytes(), nil
}

// verifyPart of partVerifier. The statement here is the edge's own, so the public wires are too.
func (self *groth16Backend) verifyPart(ctx context.Context, statement *partStatement, encoded []byte) error {
	shape, err := partShapeFor(statement)
	if err != nil {
		return err
	}
	keys, err := self.keysFor(shape)
	if err != nil {
		return err
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
