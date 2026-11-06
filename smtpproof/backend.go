package smtpproof

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
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

// The shapes this build proves. A part outside them is refused, on both sides.
func partShapes() []*partShape {
	return []*partShape{
		{kind: partKindEhlo, version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, clientBlocks: 4},
		{kind: partKindEhlo, version: tlsVersion13, suite: tlsSuiteChacha20Poly1305Sha256, clientBlocks: 1},
	}
}

// The shape a statement proves under, if any: the first whose blocks its records fit.
func partShapeFor(statement *partStatement) (*partShape, error) {
	session := statement.session
	for _, shape := range partShapes() {
		if shape.version != session.version || shape.suite != session.suite {
			continue
		}
		if statement.index == 1 && shape.kind == partKindEhlo {
			if _, err := partAssignment(shape, statement); err == nil {
				return shape, nil
			}
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
	assignWitness(circuit, witness)
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
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(encoded)); err != nil {
		return fmt.Errorf("smtpproof: malformed proof: %w", err)
	}
	return groth16.Verify(proof, keys.verifyingKey, public)
}
