//go:build sidecar_testhooks

// A proof system for tests in other modules that compose this module's Prover, Verifier and gate with an engine, where
// Groth16 has no keys to run on (no setup has run, SMTP-M9-27), such as server's T3 of FS-31 (SMTP-M9-30;
// server/cli/smtpedge/fs31_test.go): a key set whose proof is a handle on the witness its part was proven with, valid
// in this process alone, and whose verifier holds the part to the reference relation over the edge's own statement,
// as session_test.go's backend does. Everything around the proof is the real thing: the TLS client, the planner, the
// parts, the gate and every check of E1 to E3.
//
// Only the sidecar_testhooks build has this, which no release leg is (§22.4), so no shipped Verifier ever holds such a
// set. Safe for concurrent use.

package smtpproof

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// A key set whose proofs only this process can check, by the relation.
type RelationKeySet struct {
	id      []byte
	backend *relationBackend
}

// A part the set's verifier refused: its index and the relation's first failing check, E1 to E3 or Z1 to Z9.
type RelationRefusal struct {
	Index uint32
	Check string
}

// A new set under a random id of keyset.json's width.
func NewRelationKeySet() (*RelationKeySet, error) {
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &RelationKeySet{id: id, backend: &relationBackend{witnesses: map[string]*partWitness{}}}, nil
}

// The id a preamble names to prove under this set.
func (self *RelationKeySet) Id() []byte {
	return bytes.Clone(self.id)
}

// A Verifier holding this set alone, under settings, nil for DefaultVerifierSettings'.
func (self *RelationKeySet) NewVerifier(settings *VerifierSettings) *Verifier {
	if settings == nil {
		settings = DefaultVerifierSettings()
	}
	return &Verifier{
		settings: settings,
		now:      time.Now,
		keySets: map[string]*verifierKeySet{
			hex.EncodeToString(self.id): {id: bytes.Clone(self.id), proof: settings.Proof, backend: self.backend},
		},
	}
}

// A prover naming this set and proving every part under it, under settings, nil for DefaultProverSettings'.
func (self *RelationKeySet) NewProver(settings *ProverSettings) sidecar.SmtpProver {
	if settings == nil {
		settings = DefaultProverSettings()
	}
	return &relationProver{prover: &Prover{settings: settings, backend: self.backend}, keySet: bytes.Clone(self.id)}
}

// Every part the set's verifier refused, in order.
func (self *RelationKeySet) Refusals() []*RelationRefusal {
	self.backend.stateLock.Lock()
	defer self.backend.stateLock.Unlock()
	return slices.Clone(self.backend.refusals)
}

// The set's backend: a proof is a handle on the witness, and verifying runs the relation over it.
type relationBackend struct {
	stateLock sync.Mutex
	witnesses map[string]*partWitness
	refusals  []*RelationRefusal
}

func (self *relationBackend) provePart(ctx context.Context, statement *partStatement, witness *partWitness) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	proof := binary.BigEndian.AppendUint64(nil, uint64(len(self.witnesses)))
	self.witnesses[string(proof)] = witness
	return proof, nil
}

func (self *relationBackend) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	witness, ok := self.witnesses[string(proof)]
	if !ok {
		self.refusals = append(self.refusals, &RelationRefusal{Index: statement.index, Check: string(checkZ1)})
		return errors.New("no witness behind the proof")
	}
	if failures := relationCheckPart(statement, witness); 0 < len(failures) {
		self.refusals = append(self.refusals, &RelationRefusal{Index: statement.index, Check: string(failures[0].check)})
		return failures[0]
	}
	return nil
}

// A prover that names its set as its key set: a Prover with no keys proves a job naming none under its own backend,
// so the job goes to it with the set's id taken off, after the id is checked.
type relationProver struct {
	prover *Prover
	keySet []byte
}

func (self *relationProver) SendSmtp(ctx context.Context, conn net.Conn, job *sidecar.SmtpProofJob, channel sidecar.SmtpProofChannel) (*sidecar.SmtpProofResult, error) {
	if !bytes.Equal(job.KeySet, self.keySet) {
		return nil, sidecar.ErrSmtpProofKeySet
	}
	unnamed := *job
	unnamed.KeySet = nil
	return self.prover.SendSmtp(ctx, conn, &unnamed, channel)
}

// A relation's set holds no keys to time a unit with.
func (self *relationProver) Measure(ctx context.Context) (*sidecar.SmtpProverMeasure, error) {
	return nil, errors.New("smtpproof: a relation key set holds no keys to measure")
}

func (self *relationProver) KeySet() []byte {
	return bytes.Clone(self.keySet)
}

func (self *relationProver) PrepareKeys(ctx context.Context) (*sidecar.SmtpProverReadiness, error) {
	return &sidecar.SmtpProverReadiness{
		KeySets: []*sidecar.SmtpProverKeySet{{Id: bytes.Clone(self.keySet), ReadySuites: slices.Clone(self.prover.settings.SuiteOrder)}},
		Done:    true,
	}, nil
}
