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
//
// Every record starts a fresh keystream block, so blocks count records as well as octets. A one-line
// reply takes one or two of AES's 16-octet blocks and one of ChaCha20's 64-octet blocks, so ChaCha20's
// 12 server blocks hold as many such replies as AES's 24, and its 12 client blocks as many commands of
// up to 63 octets as AES's 48.
func partShapes() []*partShape {
	return []*partShape{
		{kind: partKindKey, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 4},
		{kind: partKindKey, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 1},
		// sized for D-SMTP-16's 10 recipients and a typical EHLO reply, whole or a line per record
		{kind: partKindEnvelope, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 48, serverBlocks: 24, localOctets: true},
		{kind: partKindEnvelope, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 12, serverBlocks: 12, localOctets: true},
		// D-SMTP-16's 4 KiB header block, the envelope's 1 + 10 replies and DATA's 354, each in a record
		// of its own, and BDAT and QUIT or DATA's end
		{kind: partKindMessage, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 4, serverBlocks: 24, headerBlocks: 256},
		{kind: partKindMessage, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 2, serverBlocks: 12, headerBlocks: 64},
		// DATA with a 2 KiB first body part beside the header block
		{kind: partKindMessage, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 4, serverBlocks: 24, headerBlocks: 256, bodyBlocks: 128},
		{kind: partKindMessage, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 2, serverBlocks: 12, headerBlocks: 64, bodyBlocks: 32},
		// a later DATA part
		{kind: partKindBody, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 2, bodyBlocks: 128},
		{kind: partKindBody, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 2, bodyBlocks: 32},
		// a later DATA part over a late NewSessionTicket. No reply may come during the body (Z8), so the
		// only server record such a part can cover is a ticket: these hold one of up to 255 octets. A part
		// with no server record takes the cheaper shape above, which comes first. 1.2 has no ticket here
		{kind: partKindBody, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 2, serverBlocks: 16, bodyBlocks: 128},
		{kind: partKindBody, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 2, serverBlocks: 4, bodyBlocks: 32},
		// TLS 1.2, for Exchange Online among others: AES-128-GCM alone, under each of its two suites
		{kind: partKindKey, version: tlsVersion12, suite: tlsSuiteEcdheRsaAes128GcmSha256, clientBlocks: 4},
		{kind: partKindKey, version: tlsVersion12, suite: tlsSuiteEcdheEcdsaAes128GcmSha256, clientBlocks: 4},
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
		return partKindKey
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

// Where a backend finds keys it does not hold, such as a prover host's cache of verified keys. It
// answers errNoKeys for a shape it has none for. Safe for concurrent use.
type shapeKeySource interface {
	keysFor(shape *partShape) (*shapeKeys, error)
}

// Proves and verifies parts under the keys it holds or its source gives, and refuses every other
// part. Safe for concurrent use.
type groth16Backend struct {
	stateLock sync.Mutex
	keys      map[partShape]*shapeKeys
	source    shapeKeySource
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
	shape, err := partShapeFor(statement)
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
