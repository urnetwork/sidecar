//go:build !sidecar_http

// T2's sidecar.SmtpProofVerifier, for the engine and StubSmtpEdge before the real verifier, which
// lives in smtpproof and which this module cannot import. A session admits by a script, not by
// reading records: it has no keys and checks no proof, so nothing it passes means a check passed. It
// records every call, so a test can show the engine wrote exactly what a session cleared, in order,
// and nothing after a refusal.
//
// Holding follows E3's shape by counts. The first HoldAfterClientRecords client records, the
// handshake's, pass at once; every later one needs credit, and each verified part adds its
// LastRecord-FirstRecord+1 records of credit and releases what was held, oldest first; a part that opens
// no record (LastRecord = FirstRecord - 1, DESIGN-DETAILS 3.2.5) adds none. A zero script holds nothing.
// A script can refuse key sets, which HoldsKeySet and NewSmtpProofSession then answer as an edge
// without that set does. Safe for concurrent use; a session's methods may run one goroutine per direction.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/urnetwork/sidecar"
)

var _ sidecar.SmtpProofVerifier = (*FakeSmtpProofVerifier)(nil)
var _ sidecar.SmtpProofSession = (*FakeSmtpProofSession)(nil)

var errFakeSmtpProofSessionEnded = errors.New("smtp proof session ended")

// What every session of a verifier does. Record numbers count from 1 across a session's client
// records, the handshake's included.
type FakeSmtpProofScript struct {
	// Client records that pass with no part: 0 holds nothing at all.
	HoldAfterClientRecords int
	// The error VerifyPart returns for a part's index, which ends the session. ErrSmtpRecordCut makes
	// it a cut.
	RefuseParts map[uint32]error
	// The client record on which the session cuts, ending with ErrSmtpRecordCut. 0 never.
	CutAtClientRecord int
	// The error DiscloseShts returns, which ends the session.
	RefuseShts error
	// The client record whose release makes MailForwarded true, the engine's cue to charge a unit.
	// 0 never.
	MailForwardedAtClientRecord int
	// Key sets the verifier does not hold: HoldsKeySet answers false and NewSmtpProofSession
	// ErrSmtpProofKeySet for a preamble naming one. Every other set, none included, is held.
	RefuseKeySets [][]byte
}

// Whether the script holds keySet.
func (self *FakeSmtpProofScript) holdsKeySet(keySet []byte) bool {
	for _, refused := range self.RefuseKeySets {
		if bytes.Equal(refused, keySet) {
			return false
		}
	}
	return true
}

// One call a session took, with what it returned.
type FakeSmtpProofCall struct {
	// ClientRecord, ServerRecord, ServerClosed, DiscloseShts or VerifyPart.
	Method string
	// The record or SHTS passed, copied.
	Data []byte
	// The part passed, copied.
	Part *sidecar.SmtpProofPart
	// The records returned for the MX, copied.
	Released [][]byte
	Err      error
}

// Hands each new session the script it holds.
type FakeSmtpProofVerifier struct {
	stateLock sync.Mutex
	script    *FakeSmtpProofScript
	// returned by NewSmtpProofSession instead of a session
	refuseSessions error
	sessions       []*FakeSmtpProofSession
}

// A nil script holds nothing and refuses nothing.
func NewFakeSmtpProofVerifier(script *FakeSmtpProofScript) *FakeSmtpProofVerifier {
	if script == nil {
		script = &FakeSmtpProofScript{}
	}
	return &FakeSmtpProofVerifier{script: script}
}

// Sessions opened after this get script.
func (self *FakeSmtpProofVerifier) SetScript(script *FakeSmtpProofScript) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.script = script
}

// Every later NewSmtpProofSession fails with err, nil restoring sessions.
func (self *FakeSmtpProofVerifier) RefuseSessions(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refuseSessions = err
}

// Every session opened, in order.
func (self *FakeSmtpProofVerifier) Sessions() []*FakeSmtpProofSession {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*FakeSmtpProofSession(nil), self.sessions...)
}

// HoldsKeySet of sidecar.SmtpProofVerifier, by the script.
func (self *FakeSmtpProofVerifier) HoldsKeySet(keySet []byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.script.holdsKeySet(keySet)
}

func (self *FakeSmtpProofVerifier) NewSmtpProofSession(preamble *sidecar.SmtpProofPreamble) (sidecar.SmtpProofSession, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.refuseSessions != nil {
		return nil, self.refuseSessions
	}
	if !self.script.holdsKeySet(preamble.ProofKeySet) {
		return nil, sidecar.ErrSmtpProofKeySet
	}
	keptPreamble := *preamble
	keptPreamble.ProofKeySet = bytes.Clone(preamble.ProofKeySet)
	session := &FakeSmtpProofSession{script: self.script, preamble: &keptPreamble}
	self.sessions = append(self.sessions, session)
	return session, nil
}

// One connection's gate, by script.
type FakeSmtpProofSession struct {
	script   *FakeSmtpProofScript
	preamble *sidecar.SmtpProofPreamble

	stateLock sync.Mutex
	calls     []*FakeSmtpProofCall
	ended     bool
	// client records seen
	clientRecordCount int
	// records cleared ahead, by verified parts
	credit int
	// numbered records waiting for credit, oldest first
	held          [][]byte
	heldNumbers   []int
	mailForwarded bool
}

// The preamble the session was opened for.
func (self *FakeSmtpProofSession) Preamble() *sidecar.SmtpProofPreamble {
	return self.preamble
}

// Every call, in the order the session took them.
func (self *FakeSmtpProofSession) Calls() []*FakeSmtpProofCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*FakeSmtpProofCall(nil), self.calls...)
}

// Every record the session returned for the MX, in order: what the engine must have written.
func (self *FakeSmtpProofSession) Released() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var released [][]byte
	for _, call := range self.calls {
		released = append(released, call.Released...)
	}
	return released
}

// Whether a refusal or a cut ended the session.
func (self *FakeSmtpProofSession) Ended() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.ended
}

func (self *FakeSmtpProofSession) recordWithLock(call *FakeSmtpProofCall) {
	kept := &FakeSmtpProofCall{Method: call.Method, Data: bytes.Clone(call.Data), Err: call.Err}
	if call.Part != nil {
		part := *call.Part
		part.SendId = bytes.Clone(call.Part.SendId)
		part.Proof = bytes.Clone(call.Part.Proof)
		part.KeyCommitment = bytes.Clone(call.Part.KeyCommitment)
		part.Carry = bytes.Clone(call.Part.Carry)
		part.Records = nil
		for _, record := range call.Part.Records {
			part.Records = append(part.Records, bytes.Clone(record))
		}
		kept.Part = &part
	}
	for _, record := range call.Released {
		kept.Released = append(kept.Released, bytes.Clone(record))
	}
	self.calls = append(self.calls, kept)
}

// Moves held records out while credit lasts.
func (self *FakeSmtpProofSession) releaseWithLock() [][]byte {
	var released [][]byte
	for 0 < len(self.held) && 0 < self.credit {
		released = append(released, self.held[0])
		self.noteReleasedWithLock(self.heldNumbers[0])
		self.held = self.held[1:]
		self.heldNumbers = self.heldNumbers[1:]
		self.credit -= 1
	}
	return released
}

func (self *FakeSmtpProofSession) noteReleasedWithLock(number int) {
	if self.script.MailForwardedAtClientRecord != 0 && number == self.script.MailForwardedAtClientRecord {
		self.mailForwarded = true
	}
}

func (self *FakeSmtpProofSession) ClientRecord(record []byte) ([][]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	call := &FakeSmtpProofCall{Method: "ClientRecord", Data: record}
	defer func() { self.recordWithLock(call) }()
	if self.ended {
		call.Err = errFakeSmtpProofSessionEnded
		return nil, call.Err
	}
	self.clientRecordCount += 1
	number := self.clientRecordCount
	if number == self.script.CutAtClientRecord {
		self.ended = true
		call.Err = sidecar.ErrSmtpRecordCut
		return nil, call.Err
	}
	if self.script.HoldAfterClientRecords == 0 || number <= self.script.HoldAfterClientRecords {
		self.noteReleasedWithLock(number)
		call.Released = [][]byte{bytes.Clone(record)}
		return call.Released, nil
	}
	self.held = append(self.held, bytes.Clone(record))
	self.heldNumbers = append(self.heldNumbers, number)
	call.Released = self.releaseWithLock()
	return call.Released, nil
}

func (self *FakeSmtpProofSession) ServerRecord(record []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	call := &FakeSmtpProofCall{Method: "ServerRecord", Data: record}
	defer func() { self.recordWithLock(call) }()
	if self.ended {
		call.Err = errFakeSmtpProofSessionEnded
		return call.Err
	}
	return nil
}

func (self *FakeSmtpProofSession) ServerClosed() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.recordWithLock(&FakeSmtpProofCall{Method: "ServerClosed"})
}

func (self *FakeSmtpProofSession) DiscloseShts(shts []byte) ([][]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	call := &FakeSmtpProofCall{Method: "DiscloseShts", Data: shts}
	defer func() { self.recordWithLock(call) }()
	if self.ended {
		call.Err = errFakeSmtpProofSessionEnded
		return nil, call.Err
	}
	if self.script.RefuseShts != nil {
		self.ended = true
		call.Err = self.script.RefuseShts
		return nil, call.Err
	}
	return nil, nil
}

func (self *FakeSmtpProofSession) VerifyPart(ctx context.Context, part *sidecar.SmtpProofPart) ([][]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	call := &FakeSmtpProofCall{Method: "VerifyPart", Part: part}
	defer func() { self.recordWithLock(call) }()
	if err := ctx.Err(); err != nil {
		call.Err = err
		return nil, err
	}
	if self.ended {
		call.Err = errFakeSmtpProofSessionEnded
		return nil, call.Err
	}
	if err := self.script.RefuseParts[part.Index]; err != nil {
		self.ended = true
		call.Err = err
		return nil, err
	}
	if part.FirstRecord <= part.LastRecord {
		self.credit += int(part.LastRecord - part.FirstRecord + 1)
	}
	call.Released = self.releaseWithLock()
	return call.Released, nil
}

func (self *FakeSmtpProofSession) MailForwarded() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.mailForwarded
}
