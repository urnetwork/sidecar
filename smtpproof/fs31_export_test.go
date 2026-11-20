// A bridge from FS-31's fixture (fs31_fixture_test.go) to its engine edge (fs31_engine_test.go), which sits in the
// external test package because a client package's own files may not import a <svc>service (§4.4), and the engine is
// smtpedgeservice. The engine edge registers its maker here, and gets from here the verifier over a row's backend, the
// forging MX socket and the one fact of a session it reads. Compiled only into this package's tests.

package smtpproof

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What an engine edge is made from: fs31EdgeArgs, as the external package reads it.
type ExportedFs31EdgeArgs struct {
	T  *testing.T
	Mx sidecartest.MxServer
	// The cell's TLS version, as crypto/tls numbers it, and its suite.
	Version uint16
	Suite   uint16
	// As fs31EdgeArgs': the MX's application record a malicious edge forges from, and the recipients a message may
	// name where a row raises Pro's.
	ForgeServerFrom int
	RecipientLimit  int
	// The recipient domain FS-31's preambles name and its MX's host.
	RecipientDomain string
	MxHost          string
	backend         *fs31Backend
}

// A Verifier holding FS-31's key set over the row's backend, its clock now.
func (self *ExportedFs31EdgeArgs) NewVerifier(now func() time.Time) sidecar.SmtpProofVerifier {
	return &Verifier{
		settings: DefaultVerifierSettings(),
		now:      now,
		keySets: map[string]*verifierKeySet{
			hex.EncodeToString(fs31KeySetId): {id: bytes.Clone(fs31KeySetId), proof: DefaultProofSettings(), backend: self.backend},
		},
	}
}

// fs31Declared, as the external package reads it.
type ExportedFs31Declared struct {
	RecipientDomain  string
	RecipientCount   uint32
	MessageId        string
	HeaderFromDomain string
	DkimSelector     string
	MessageByteCount uint64
	KeySet           []byte
}

// fs31Opened with fs31Issued's values, as the external package fills it.
type ExportedFs31Opened struct {
	Conn    net.Conn
	Channel sidecar.SmtpProofChannel
	// The preamble's answer when it was not OK, and why; else 0.
	Code   uint32
	Reason string
	// The issued values, when the answer was OK.
	SendId         []byte
	HeloName       string
	XUrRef         string
	FeedbackId     string
	MxHost         string
	EnvelopeDomain string
}

// An edge the external package makes: fs31Edge's methods, as functions.
type ExportedFs31Edge struct {
	Name          string
	Open          func(ctx context.Context, declared *ExportedFs31Declared) (*ExportedFs31Opened, error)
	QuitForwarded func() <-chan struct{}
	Done          func() <-chan struct{}
	End           func()
	Wait          func()
	Refusal       func() error
}

// Makes every row's edge with maker from now on: the engine's, where the leg links it.
func SetFs31EngineEdge(maker func(args *ExportedFs31EdgeArgs) *ExportedFs31Edge) {
	fs31EngineEdge = func(args *fs31EdgeArgs) fs31Edge {
		return &fs31ExportedEdge{edge: maker(&ExportedFs31EdgeArgs{
			T:               args.t,
			Mx:              args.mx,
			Version:         args.cell.leg.version,
			Suite:           args.cell.leg.suites[0],
			ForgeServerFrom: args.forgeServerFrom,
			RecipientLimit:  args.recipientLimit,
			RecipientDomain: testRecipientDomain,
			MxHost:          testMxHost,
			backend:         args.backend,
		})}
	}
}

// An external package's edge as the fixture drives one.
type fs31ExportedEdge struct {
	edge *ExportedFs31Edge
}

func (self *fs31ExportedEdge) open(ctx context.Context, declared *fs31Declared) (*fs31Opened, error) {
	opened, err := self.edge.Open(ctx, &ExportedFs31Declared{
		RecipientDomain:  declared.recipientDomain,
		RecipientCount:   declared.recipientCount,
		MessageId:        declared.messageId,
		HeaderFromDomain: declared.headerFromDomain,
		DkimSelector:     declared.dkimSelector,
		MessageByteCount: declared.messageByteCount,
		KeySet:           declared.keySet,
	})
	if err != nil {
		return nil, err
	}
	result := &fs31Opened{conn: opened.Conn, channel: opened.Channel, code: opened.Code, reason: opened.Reason}
	if opened.Code == 0 {
		result.issued = &fs31Issued{
			sendId:         opened.SendId,
			heloName:       opened.HeloName,
			xUrRef:         opened.XUrRef,
			feedbackId:     opened.FeedbackId,
			mxHost:         opened.MxHost,
			envelopeDomain: opened.EnvelopeDomain,
		}
	}
	return result, nil
}

func (self *fs31ExportedEdge) quitForwarded() <-chan struct{} {
	return self.edge.QuitForwarded()
}

func (self *fs31ExportedEdge) done() <-chan struct{} {
	return self.edge.Done()
}

func (self *fs31ExportedEdge) end() {
	self.edge.End()
}

func (self *fs31ExportedEdge) wait() {
	self.edge.Wait()
}

func (self *fs31ExportedEdge) refusal() error {
	return self.edge.Refusal()
}

func (self *fs31ExportedEdge) name() string {
	return self.edge.Name
}

// Whether a session the Verifier opened has handed its caller the last part's QUIT, after which it forwards nothing.
func ExportSessionFinished(session sidecar.SmtpProofSession) bool {
	gate, ok := session.(*edgeSession)
	if !ok {
		return false
	}
	gate.stateLock.Lock()
	defer gate.stateLock.Unlock()
	return gate.finished
}

// The edge's MX socket as fs31MxConn has it: forging the MX's application records from forgeFrom on under TLS 1.2,
// and each write noted to wrote.
func ExportFs31MxConn(conn net.Conn, forgeFrom int, suite uint16, secure bool, wrote func(data []byte)) net.Conn {
	return newFs31MxConn(conn, forgeFrom, suite, secure, wrote)
}

// The index of the MX's reply to the message among its replies inside TLS, 1 the EHLO reply's.
func ExportFs31MessageReplyIndex(data bool, recipientCount int) int {
	cell := &fs31Cell{leg: &testMxLeg{version: tls.VersionTLS12}, data: data}
	return fs31MessageReplyIndex(cell, recipientCount)
}
