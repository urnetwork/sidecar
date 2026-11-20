// FS-31's world (SMTP-M9-30; §22.5's FS-31 row, D-SMTP-16's adversarial corpus, DESIGN-DETAILS 3.6): one
// connection from a prover, honest or not, through an edge to one of sidecartest's MXs, and what the MX took.
// The MX is the point: ScriptedMx behind crypto/tls, or RecordMx behind a TLS server written apart from this
// module, each recording every command it accepted and every transaction it took, so "fails before any effect"
// is an assertion on that record and not on the edge's own account of itself.
//
// The edge is the real engine where the leg links its cross-module entry (fs31_engine_test.go, under
// sidecar_testhooks): the preamble's gate, quota and issued values, the MX dialed in an MxWorld with its pre-TLS
// dialog, the splice, and smtpproof's Verifier, whose session is edgeSession. In the plain leg it is edgeSession
// alone between two relays, as session_test.go has it, and there each part's circuit also runs on gnark's
// solver (fs31Backend), the leg that compiles circuits (testNeedCircuits). So each row runs once a leg: through
// the engine with the relation as its proof system, and through the gate with the relation and the circuits.
//
// The prover is this package's Prover over a backend whose proofs are handles on witnesses; a malicious sender is
// that prover with the hooks adversary_test.go gives it. Names are .example and addresses RFC 5737's.

package smtpproof

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The DKIM selector FS-31's messages are signed under: 26 lowercase base32 characters, the engine's form
// (plan-SMTP-small-readings #5).
const fs31Selector = "fsaaaaaaaaaaaaaaaaaaaaaaaa"

// How long an FS-31 connection may wait: a guard, never a pause, since each wait ends at the event it waits on. The
// connection's work is its parts': the prover submits each once the one before it is answered, and the edge's
// verification of it, in the leg that compiles circuits, compiles the part's shape, queued behind every other test's
// compile (testCompiledLock), and solves it. That takes seconds a part alone and grows with the package's tests and
// the lanes' running beside it, so one bound on the whole connection failed a send of seven parts under load that
// was only slow. The bound follows the parts the case runs instead, as QD-1101's barrier bound follows its holder:
// each part's answer has PartTimeout from its submission, and every other wait, before the first part, between two
// and after the last, has ConnectionTimeout. A hang ends at the first allowance it passes, with a cause naming the
// wait. Start from defaultFs31GuardSettings.
type fs31GuardSettings struct {
	// A wait with no part at the edge: the preamble, the MX's dialog and handshake, a part's proof, here a handle
	// on its witness, the replies and the close after QUIT, each well under a second: 60 s.
	ConnectionTimeout time.Duration
	// One part's answer from the edge, from its submission: 10 min, well past the 13 s the slowest part took with
	// the whole package running at load averages of 24 to 35 and the 4 s it took alone, and inside make check's
	// 30 min for the package, so a hang in the edge's verification still fails the cell it hangs.
	PartTimeout time.Duration
}

func defaultFs31GuardSettings() *fs31GuardSettings {
	return &fs31GuardSettings{
		ConnectionTimeout: 60 * time.Second,
		PartTimeout:       10 * time.Minute,
	}
}

// One connection's guard: its context ends, with a cause naming the wait, once a wait passes its allowance
// (fs31GuardSettings). The connection's recording channel tells it of each part's submission and answer. Each
// wait's allowance is a generation of its own, so a timer left from one wait never ends the next. Safe for
// concurrent use.
type fs31Guard struct {
	settings *fs31GuardSettings
	clock    sidecar.Clock
	ctx      context.Context
	cancel   context.CancelCauseFunc

	stateLock  sync.Mutex
	generation uint64
	// stops the timer of the allowance running now
	stopTimer func() bool
	// parts submitted and answered, and the index of the last submitted
	submitted     int
	answered      int
	lastPartIndex uint32
	// the wait that passed its allowance, once one has
	expiredErr error
	ended      bool
}

func newFs31Guard(settings *fs31GuardSettings, clock sidecar.Clock) *fs31Guard {
	ctx, cancel := context.WithCancelCause(context.Background())
	guard := &fs31Guard{settings: settings, clock: clock, ctx: ctx, cancel: cancel}
	guard.arm()
	return guard
}

// What every wait of the connection takes.
func (self *fs31Guard) context() context.Context {
	return self.ctx
}

// A part went to the edge: its answer has PartTimeout.
func (self *fs31Guard) partSubmitted(index uint32) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.submitted += 1
		self.lastPartIndex = index
	}()
	self.arm()
}

// The edge answered a part, taking or refusing it: the wait after it has its own allowance.
func (self *fs31Guard) partAnswered() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.answered += 1
	}()
	self.arm()
}

// Starts the allowance of the wait the connection is in now, in place of the last one's. The clock may call back at
// once, so no lock is held across it.
func (self *fs31Guard) arm() {
	var generation uint64
	var timeout time.Duration
	var wait string
	var stopLast func() bool
	over := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.generation += 1
		generation = self.generation
		stopLast, self.stopTimer = self.stopTimer, nil
		over = self.ended || self.expiredErr != nil
		switch {
		case self.answered < self.submitted:
			timeout = self.settings.PartTimeout
			wait = fmt.Sprintf("part %d's answer from the edge", self.lastPartIndex)
		case self.submitted == 0:
			timeout = self.settings.ConnectionTimeout
			wait = "the connection before its first part"
		default:
			timeout = self.settings.ConnectionTimeout
			wait = fmt.Sprintf("the connection after part %d's answer", self.lastPartIndex)
		}
	}()
	if stopLast != nil {
		stopLast()
	}
	if over {
		return
	}
	stop := self.clock.AfterFunc(timeout, func() {
		self.expire(generation, fmt.Errorf("FS-31's guard: %s waited past %s", wait, timeout))
	})
	current := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if generation != self.generation || self.ended {
			return false
		}
		self.stopTimer = stop
		return true
	}()
	if !current {
		stop()
	}
}

// A wait's allowance passed: unless a later wait has begun, the connection's context ends with err as its cause.
func (self *fs31Guard) expire(generation uint64, err error) {
	current := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if generation != self.generation || self.ended || self.expiredErr != nil {
			return false
		}
		self.expiredErr = err
		return true
	}()
	if current {
		self.cancel(err)
	}
}

// The wait that passed its allowance, nil while none has.
func (self *fs31Guard) expired() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.expiredErr
}

// Ends the guard with its connection: its timer stops and its context ends.
func (self *fs31Guard) end() {
	var stop func() bool
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.ended = true
		self.generation += 1
		stop, self.stopTimer = self.stopTimer, nil
	}()
	if stop != nil {
		stop()
	}
	self.cancel(nil)
}

// The circuit's answer on a part, where it was asked.
const (
	fs31CircuitAccepted = "accepted"
	fs31CircuitRefused  = "refused"
)

// One cell of FS-31's matrix: a TLS leg, as sidecartest's MXs serve it, and a mode.
type fs31Cell struct {
	leg  *testMxLeg
	data bool
}

func (self *fs31Cell) String() string {
	mode := "BDAT"
	if self.data {
		mode = "DATA"
	}
	return self.leg.name + " " + mode
}

func (self *fs31Cell) tls12() bool {
	return self.leg.version == tls.VersionTLS12
}

// Every cell: each of E1's four legs, in each mode.
func fs31Cells() []*fs31Cell {
	var cells []*fs31Cell
	for _, leg := range testMxLegs() {
		for _, data := range []bool{false, true} {
			cells = append(cells, &fs31Cell{leg: leg, data: data})
		}
	}
	return cells
}

// What FS-31 reads of an MX: ScriptedMx's and RecordMx's record.
type fs31Mx interface {
	sidecartest.MxServer
	Accepted() []string
	Transactions() []*sidecartest.MxTransaction
	Events() []*sidecartest.MxEvent
	PipeliningViolated() bool
	Certificate() *x509.Certificate
}

// One part as the verifier took it.
type fs31Verdict struct {
	index uint32
	// The relation's failing checks, in the order it found them; none where it holds.
	checks []relationCheck
	// The circuit's answer, fs31CircuitAccepted or fs31CircuitRefused, or empty where it was not asked.
	circuit string
}

// FS-31's proof system. A proof is a handle on the witness its part was proven with, which the verifier holds to
// the relation over the edge's own statement and, in the leg that compiles circuits, to the part's circuit on
// gnark's solver: a test shape sized to the part with Z1 left out, or the key part's production shape with Z1 in
// it. A part passes only where every reader asked passes it, and a reader that disagrees with the relation fails
// the row on its own (expectAgreement). Never reachable outside tests. Safe for concurrent use.
type fs31Backend struct {
	t *testing.T
	// Solves every part's circuit, where only those the relation refuses would be: the honest controls'.
	solveAll bool

	stateLock sync.Mutex
	witnesses map[string]*partWitness
	// The key part's witness, which holds the connection's keys.
	keys *partWitness
	// A malicious sender's change to each part's witness, after the prover checked it, if the prover did.
	mutate   func(statement *partStatement, witness *partWitness)
	verdicts []*fs31Verdict
}

func newFs31Backend(t *testing.T, solveAll bool) *fs31Backend {
	return &fs31Backend{t: t, solveAll: solveAll, witnesses: map[string]*partWitness{}}
}

// A witness copied deep enough that a change to it leaves the prover's own untouched.
func fs31CloneWitness(witness *partWitness) *partWitness {
	clone := *witness
	clone.clientPlaintexts = make([][]byte, 0, len(witness.clientPlaintexts))
	for _, plaintext := range witness.clientPlaintexts {
		clone.clientPlaintexts = append(clone.clientPlaintexts, bytes.Clone(plaintext))
	}
	clone.serverPlaintexts = make([][]byte, 0, len(witness.serverPlaintexts))
	for _, plaintext := range witness.serverPlaintexts {
		clone.serverPlaintexts = append(clone.serverPlaintexts, bytes.Clone(plaintext))
	}
	return &clone
}

func (self *fs31Backend) provePart(ctx context.Context, statement *partStatement, witness *partWitness) ([]byte, error) {
	held := fs31CloneWitness(witness)
	self.stateLock.Lock()
	mutate := self.mutate
	if statement.index == 1 && self.keys == nil {
		self.keys = fs31CloneWitness(witness)
	}
	self.stateLock.Unlock()
	if mutate != nil {
		mutate(statement, held)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	proof := binary.BigEndian.AppendUint64(nil, uint64(len(self.witnesses)))
	self.witnesses[string(proof)] = held
	return proof, nil
}

// The connection's keys, from the key part's witness as the prover made it, once it is proven.
func (self *fs31Backend) connectionKeys() *partWitness {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.keys
}

func (self *fs31Backend) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	witness := func() *partWitness {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.witnesses[string(proof)]
	}()
	verdict := &fs31Verdict{index: statement.index}
	if witness == nil {
		verdict.checks = []relationCheck{checkZ1}
		self.addVerdict(verdict)
		return errors.New("no witness behind the proof")
	}
	failures := relationCheckPart(statement, witness)
	for _, failure := range failures {
		if !slices.Contains(verdict.checks, failure.check) {
			verdict.checks = append(verdict.checks, failure.check)
		}
	}
	if testCircuitsRun && (self.solveAll || 0 < len(failures)) {
		verdict.circuit = self.solve(statement, witness)
	}
	self.addVerdict(verdict)
	switch {
	case 0 < len(failures):
		return failures[0]
	case verdict.circuit == fs31CircuitRefused:
		return errors.New("the circuit refuses a part the relation holds")
	}
	return nil
}

func (self *fs31Backend) addVerdict(verdict *fs31Verdict) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.verdicts = append(self.verdicts, verdict)
}

// The circuit's answer on a part: its statement assigned to a shape that holds it, the witness solved. A part no
// shape holds, or one no assignment of its statement fits, has no satisfying plaintext, so it counts as refused.
func (self *fs31Backend) solve(statement *partStatement, witness *partWitness) string {
	var shape *partShape
	var err error
	if statement.index == 1 {
		shape, err = partShapeFor(DefaultProofSettings(), statement)
	} else {
		shape, err = testShapeFitting(statement, 0, 8)
	}
	if err != nil {
		return fs31CircuitRefused
	}
	compiled := testCompileShape(self.t, shape)
	circuit, err := partAssignment(shape, statement)
	if err != nil {
		return fs31CircuitRefused
	}
	assignWitness(circuit, statement, witness)
	if err := testSolved(self.t, compiled, circuit); err != nil {
		return fs31CircuitRefused
	}
	return fs31CircuitAccepted
}

// Every verification, in order.
func (self *fs31Backend) verdictList() []*fs31Verdict {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.verdicts)
}

// What the issuing edge filled into the job: on the engine, its SmtpPreambleResult's values; on the gate alone,
// this test's own.
type fs31Issued struct {
	sendId         []byte
	heloName       string
	xUrRef         string
	feedbackId     string
	mxHost         string
	envelopeDomain string
}

// The gate's issued values: session_test.go's.
func fs31GateIssued() *fs31Issued {
	return &fs31Issued{
		sendId:         []byte("synthetic-send-id"),
		heloName:       testHeloName,
		xUrRef:         testXUrRef,
		feedbackId:     testFeedbackId,
		mxHost:         testMxHost,
		envelopeDomain: testEnvelopeDomain,
	}
}

// A header block that meets Z5 in SMTP-M9-04's order: the single fields and the fixed signature first, so that
// they lie in the header block's first record, then extra, lines each ending in CRLF, then the final CRLF.
func fs31HeaderBlock(issued *fs31Issued, extra string) string {
	return literalXUrRefPrefix + issued.xUrRef + "\r\n" +
		literalFeedbackPrefix + issued.feedbackId + "\r\n" +
		"From: Alice Example <alice@" + testNetworkDomain + ">\r\n" +
		literalMessageIdPrefix + testMessageId + ">\r\n" +
		literalDkimPrefix + literalDkimDomain + testNetworkDomain + literalDkimSelector + fs31Selector + literalDkimEnd +
		"t=1; x=2; bh=AAAA; b=BBBB\r\n" +
		"To: <bob@" + testRecipientDomain + ">\r\n" +
		"Subject: A synthetic message\r\n" +
		"Date: Fri, 06 Nov 2026 12:00:00 +0000\r\n" +
		extra +
		"\r\n"
}

// One connection's message, decided before the preamble: a function of the issued values, whose lengths are fixed
// before they are known (plan-SMTP-preamble-byte-count), so the declared count can be.
type fs31Message struct {
	// The header block's lines after the single fields and the signature, each ending in CRLF; or, when
	// headerBlock is set, the whole header block from the issued values and the cell.
	extraHeaders string
	headerBlock  func(cell *fs31Cell, issued *fs31Issued) string
	body         string
	recipients   []string
	// The envelope's group bound, as the sender's retry after EnvelopeRetry sets it; 0 for what fits.
	envelopeGroupMaxCount int
}

func (self *fs31Message) message(cell *fs31Cell, issued *fs31Issued) []byte {
	block := fs31HeaderBlock(issued, self.extraHeaders)
	if self.headerBlock != nil {
		block = self.headerBlock(cell, issued)
	}
	return []byte(block + self.body)
}

// The octets the preamble declares for the mode the cell expects: BDAT's the message's, DATA's its stuffed length.
func (self *fs31Message) byteCount(cell *fs31Cell) uint64 {
	message := self.message(cell, fs31GateIssued())
	if cell.data {
		return uint64(len(dotStuffed(message)))
	}
	return uint64(len(message))
}

// An honest message to bob and carol.
func fs31DefaultMessage() *fs31Message {
	return &fs31Message{body: "one line\r\nanother line\r\nand a third\r\n", recipients: []string{"bob", "carol"}}
}

// The declared values a preamble names, before the edge issues the rest.
type fs31Declared struct {
	recipientDomain  string
	recipientCount   uint32
	messageId        string
	headerFromDomain string
	dkimSelector     string
	messageByteCount uint64
	keySet           []byte
}

// What a connection reaches once its edge has answered the preamble: the stream to splice TLS over, the channel to
// the edge's parts, and the issued values. Nil code means the edge answered OK.
type fs31Opened struct {
	conn    net.Conn
	channel sidecar.SmtpProofChannel
	issued  *fs31Issued
	// The preamble's answer when it was not OK, and why.
	code   uint32
	reason string
}

// One edge for one connection: the engine, or the gate alone.
type fs31Edge interface {
	// Answers the preamble and, where it is OK, reaches the MX and returns the stream. ctx bounds the wait.
	open(ctx context.Context, declared *fs31Declared) (*fs31Opened, error)
	// Closed once the gate has handed the MX the last part's QUIT, after which it forwards nothing.
	quitForwarded() <-chan struct{}
	// Closed once the edge's end of the connection has ended.
	done() <-chan struct{}
	// Ends the connection from the edge's side, as a limit does, where neither the MX nor the sidecar will.
	end()
	// Waits for the edge's end of the connection and the MX's, once the connection has ended.
	wait()
	// The gate's first refusal, nil where it refused nothing.
	refusal() error
	// The edge's name in the matrix.
	name() string
}

// How a row's edge is made: by fs31_engine_test.go's maker where the leg has the engine, else the gate alone.
type fs31EdgeArgs struct {
	t       *testing.T
	cell    *fs31Cell
	mx      fs31Mx
	backend *fs31Backend
	// Has the edge forge the MX's application records from this one on, 1 the first: a malicious edge,
	// holding no key, whose forgeries the prover's TLS client must refuse.
	forgeServerFrom int
	// The tier's own changes to the network's limits, for a row past Pro's: the 100-recipient control.
	recipientLimit int
}

// Set by fs31_engine_test.go where the leg links the engine's cross-module entry.
var fs31EngineEdge func(args *fs31EdgeArgs) fs31Edge

func newFs31Edge(args *fs31EdgeArgs) fs31Edge {
	if fs31EngineEdge != nil {
		return fs31EngineEdge(args)
	}
	return newFs31GateEdge(args)
}

// The gate alone between two relays, as testRunSendToMx has it: edgeSession over this test's issued values, the
// MX's pre-TLS dialog run by hand, and parts landing straight on the session.
type fs31GateEdge struct {
	args   *fs31EdgeArgs
	edge   *testEdge
	mxDone chan struct{}

	quitOnce  sync.Once
	quit      chan struct{}
	relayDone chan struct{}

	stateLock sync.Mutex
	// the first refusal of a part or the SHTS, which the relay does not keep
	callErr error
}

func newFs31GateEdge(args *fs31EdgeArgs) *fs31GateEdge {
	return &fs31GateEdge{args: args, quit: make(chan struct{}), relayDone: make(chan struct{})}
}

func (self *fs31GateEdge) name() string {
	return "gate"
}

func (self *fs31GateEdge) open(ctx context.Context, declared *fs31Declared) (*fs31Opened, error) {
	issued := fs31GateIssued()
	sidecarConn, edgeSidecarConn := testPipe()
	edgeMxConn, mxConn := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	self.mxDone = make(chan struct{})
	go func() {
		defer close(self.mxDone)
		self.args.mx.ServeMx(mxConn)
	}()
	if err := fs31PreTls(edgeMxConn); err != nil {
		edgeMxConn.Close()
		<-self.mxDone
		return nil, err
	}
	preamble := &sidecar.SmtpProofPreamble{
		RecipientDomain:  declared.recipientDomain,
		RecipientCount:   declared.recipientCount,
		MessageId:        declared.messageId,
		HeaderFromDomain: declared.headerFromDomain,
		DkimSelector:     declared.dkimSelector,
		MessageByteCount: declared.messageByteCount,
		HeloName:         issued.heloName,
		XUrRef:           issued.xUrRef,
		FeedbackId:       issued.feedbackId,
		EnvelopeDomain:   issued.envelopeDomain,
		MxHost:           issued.mxHost,
		ProofKeySet:      declared.keySet,
	}
	var mxConnOfEdge net.Conn = edgeMxConn
	if 0 < self.args.forgeServerFrom {
		if !self.args.cell.tls12() {
			edgeMxConn.Close()
			<-self.mxDone
			return nil, errors.New("an edge forges records only where their types are public, under TLS 1.2")
		}
		mxConnOfEdge = newFs31MxConn(edgeMxConn, self.args.forgeServerFrom, self.args.cell.leg.suites[0], true, nil)
	}
	self.edge = &testEdge{
		session:     newEdgeSession(defaultEdgeSettings(), newSessionPreamble(preamble, DefaultProofSettings()), issued.mxHost, self.args.backend),
		sidecarConn: edgeSidecarConn,
		mxConn:      mxConnOfEdge,
	}
	self.edge.afterForward = func() {
		self.edge.session.stateLock.Lock()
		finished := self.edge.session.finished
		self.edge.session.stateLock.Unlock()
		if finished {
			self.quitOnce.Do(func() { close(self.quit) })
		}
	}
	self.edge.run()
	go func() {
		self.edge.relays.Wait()
		close(self.relayDone)
	}()
	return &fs31Opened{conn: sidecarConn, channel: &fs31GateChannel{gate: self}, issued: issued}, nil
}

// The prover's side of the RPC straight into the gate, its first refusal kept.
type fs31GateChannel struct {
	gate *fs31GateEdge
}

func (self *fs31GateChannel) keep(err error) error {
	if err != nil {
		self.gate.stateLock.Lock()
		defer self.gate.stateLock.Unlock()
		if self.gate.callErr == nil {
			self.gate.callErr = err
		}
	}
	return err
}

func (self *fs31GateChannel) DiscloseShts(ctx context.Context, shts []byte) error {
	return self.keep(self.gate.edge.DiscloseShts(ctx, shts))
}

func (self *fs31GateChannel) SubmitPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	return self.keep(self.gate.edge.SubmitPart(ctx, part))
}

func (self *fs31GateEdge) quitForwarded() <-chan struct{} {
	return self.quit
}

func (self *fs31GateEdge) done() <-chan struct{} {
	return self.relayDone
}

func (self *fs31GateEdge) end() {
	if self.edge != nil {
		self.edge.fail(nil)
	}
}

func (self *fs31GateEdge) wait() {
	if self.edge == nil {
		return
	}
	<-self.relayDone
	<-self.mxDone
}

func (self *fs31GateEdge) refusal() error {
	if self.edge == nil {
		return nil
	}
	self.stateLock.Lock()
	callErr := self.callErr
	self.stateLock.Unlock()
	if callErr != nil {
		return callErr
	}
	return self.edge.failure()
}

// The edge's pre-TLS dialog by hand, as testMxPreTls runs it, returning what went wrong.
func fs31PreTls(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	expect := func(code string) error {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			if !strings.HasPrefix(line, code) {
				return fmt.Errorf("%q where %s belongs", line, code)
			}
			if len(line) < 4 || line[3] == ' ' {
				return nil
			}
		}
	}
	if err := expect("220"); err != nil {
		return err
	}
	conn.Write([]byte("EHLO " + testHeloName + "\r\n"))
	if err := expect("250"); err != nil {
		return err
	}
	conn.Write([]byte("STARTTLS\r\n"))
	if err := expect("220"); err != nil {
		return err
	}
	if 0 < reader.Buffered() {
		return errors.New("octets after STARTTLS's 220")
	}
	return nil
}

// What one FS-31 connection came to.
type fs31Outcome struct {
	cell     *fs31Cell
	edgeName string
	job      *sidecar.SmtpProofJob
	result   *sidecar.SmtpProofResult
	err      error
	// The preamble's answer where it was not OK.
	preambleCode uint32
	// The gate's first refusal, the part whose submission it refused, 0 for none, and every verification in
	// order.
	refusal      error
	refusedIndex uint32
	verdicts     []*fs31Verdict
	// The parts the edge took, in order.
	acceptedParts []*sidecar.SmtpProofPart
	mx            fs31Mx
	attack        *fs31Attack
}

// What a connection runs with: its MX, message, prover settings and adversary.
type fs31Connection struct {
	cell      *fs31Cell
	mx        fs31Mx
	message   *fs31Message
	solveAll  bool
	adversary *fs31Adversary
	// As fs31EdgeArgs'.
	forgeServerFrom int
	recipientLimit  int
	// Ends the connection once the gate has handed the MX QUIT: an MX still counting a chunk's octets then waits
	// for octets that never come, and so does the prover for its reply.
	endAtQuit bool
	// Changes to the cell's prover settings.
	settings func(settings *ProverSettings)
}

// The prover settings a cell sends under: DATA forced in its DATA column, in small parts as ExportCapture sends it,
// so that a short body takes several.
func fs31ProverSettings(cell *fs31Cell) *ProverSettings {
	settings := DefaultProverSettings()
	if cell.data {
		settings.ForceData = true
		settings.testDataRecordByteCount = 12
	}
	return settings
}

// Runs one connection to its end on the leg's edge: the preamble, then the prover over the stream the edge spliced,
// a malicious sender's hooks in place where the connection names one, then the edge's and the MX's ends.
func fs31Run(t *testing.T, connection *fs31Connection) *fs31Outcome {
	t.Helper()
	cell := connection.cell
	backend := newFs31Backend(t, connection.solveAll)
	edge := newFs31Edge(&fs31EdgeArgs{
		t:               t,
		cell:            cell,
		mx:              connection.mx,
		backend:         backend,
		forgeServerFrom: connection.forgeServerFrom,
		recipientLimit:  connection.recipientLimit,
	})
	outcome := &fs31Outcome{cell: cell, edgeName: edge.name(), mx: connection.mx}
	guardSettings := defaultFs31GuardSettings()
	guard := newFs31Guard(guardSettings, sidecar.RealClock{})
	defer guard.end()
	ctx := guard.context()

	message := connection.message
	declared := &fs31Declared{
		recipientDomain:  testRecipientDomain,
		recipientCount:   uint32(len(message.recipients)),
		messageId:        testMessageId,
		headerFromDomain: testNetworkDomain,
		dkimSelector:     fs31Selector,
		messageByteCount: message.byteCount(cell),
		keySet:           fs31KeySetId,
	}
	opened, err := edge.open(ctx, declared)
	if err != nil {
		t.Fatalf("%s: the edge: %v", cell, errors.Join(err, guard.expired()))
	}
	if opened.code != 0 {
		outcome.preambleCode = opened.code
		outcome.err = fmt.Errorf("the preamble was answered %d: %s", opened.code, opened.reason)
		edge.wait()
		return outcome
	}
	issued := opened.issued
	job := &sidecar.SmtpProofJob{
		SendId: issued.sendId,
		Preamble: &sidecar.SmtpProofPreamble{
			RecipientDomain:  declared.recipientDomain,
			RecipientCount:   declared.recipientCount,
			MessageId:        declared.messageId,
			HeaderFromDomain: declared.headerFromDomain,
			DkimSelector:     declared.dkimSelector,
			MessageByteCount: declared.messageByteCount,
			HeloName:         issued.heloName,
			XUrRef:           issued.xUrRef,
			FeedbackId:       issued.feedbackId,
			EnvelopeDomain:   issued.envelopeDomain,
			MxHost:           issued.mxHost,
			ProofKeySet:      declared.keySet,
		},
		SenderLocal:           "bounce-1",
		RecipientLocals:       message.recipients,
		Message:               message.message(cell, issued),
		VerifyPeer:            testVerifyAny,
		EnvelopeGroupMaxCount: message.envelopeGroupMaxCount,
	}
	outcome.job = job
	if declared.messageByteCount != message.byteCount(cell) || (uint64(len(job.Message)) != declared.messageByteCount && uint64(len(dotStuffed(job.Message))) != declared.messageByteCount) {
		t.Fatalf("%s: the issued values changed the message's length", cell)
	}

	settings := fs31ProverSettings(cell)
	if connection.settings != nil {
		connection.settings(settings)
	}
	conn := opened.conn
	recorder := &fs31RecordingChannel{inner: opened.channel, guard: guard}
	var channel sidecar.SmtpProofChannel = recorder
	if connection.adversary != nil {
		outcome.attack = newFs31Attack(t, cell, backend, connection.adversary)
		settings.testAdversary = connection.adversary.prover
		backend.mutate = outcome.attack.mutateWitness
		conn = outcome.attack.conn(conn)
		channel = outcome.attack.channel(channel)
	}
	prover := &Prover{settings: settings, backend: backend, tlsSuites: cell.leg.suites}
	proved := make(chan struct{})
	go func() {
		defer close(proved)
		outcome.result, outcome.err = prover.SendSmtp(ctx, conn, job, channel)
	}()
	var quit <-chan struct{}
	if connection.endAtQuit {
		quit = edge.quitForwarded()
	}
	select {
	case <-proved:
	case <-quit:
		opened.conn.Close()
		<-proved
	}
	// a wait past its allowance is a hang, whatever the row expects of the send
	if err := guard.expired(); err != nil {
		t.Errorf("%s on %s: %v", cell, edge.name(), err)
	}
	accepted := outcome.err == nil && outcome.result != nil && outcome.result.Accepted
	if accepted && !connection.endAtQuit {
		// an accepted send's connection ends at the MX's close after QUIT, and the sidecar closes its end after
		// that
		select {
		case <-edge.done():
		case <-time.After(guardSettings.ConnectionTimeout):
			t.Errorf("%s: the connection did not end after an accepted send's QUIT", cell)
		}
	}
	// any other leaves its end at once, and the edge ends the connection, as a limit would where the MX waits on
	opened.conn.Close()
	edge.end()
	edge.wait()
	outcome.refusal = edge.refusal()
	outcome.refusedIndex, outcome.acceptedParts = recorder.refused()
	outcome.verdicts = backend.verdictList()
	return outcome
}

// The channel as the edge answers it, the parts it took and the first it refused kept, each part's submission and
// answer told to the connection's guard.
type fs31RecordingChannel struct {
	inner sidecar.SmtpProofChannel
	guard *fs31Guard

	stateLock     sync.Mutex
	refusedIndex  uint32
	acceptedParts []*sidecar.SmtpProofPart
}

func (self *fs31RecordingChannel) DiscloseShts(ctx context.Context, shts []byte) error {
	return self.inner.DiscloseShts(ctx, shts)
}

func (self *fs31RecordingChannel) SubmitPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	self.guard.partSubmitted(part.Index)
	err := self.inner.SubmitPart(ctx, part)
	self.guard.partAnswered()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch {
	case err == nil && self.refusedIndex == 0:
		self.acceptedParts = append(self.acceptedParts, part)
	case err != nil && self.refusedIndex == 0:
		self.refusedIndex = part.Index
	}
	return err
}

func (self *fs31RecordingChannel) refused() (uint32, []*sidecar.SmtpProofPart) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refusedIndex, slices.Clone(self.acceptedParts)
}

// The key set FS-31's preambles name, which the engine's verifier holds with the row's backend behind it.
var fs31KeySetId = bytes.Repeat([]byte{0x31}, 32)

// The commands an honest sender's parts prove after TLS, in order, as the MX's record spells them.
func fs31HonestCommands(outcome *fs31Outcome) []string {
	job := outcome.job
	commands := []string{"EHLO " + job.Preamble.HeloName, "MAIL FROM:<" + job.SenderLocal + "@" + job.Preamble.EnvelopeDomain + ">"}
	for _, local := range job.RecipientLocals {
		commands = append(commands, "RCPT TO:<"+local+"@"+job.Preamble.RecipientDomain+">")
	}
	if outcome.cell.data {
		return append(commands, "DATA")
	}
	return append(commands, "BDAT "+strconv.FormatUint(job.Preamble.MessageByteCount, 10)+" LAST")
}

// The commands the MX accepted after STARTTLS: what it would act on inside TLS.
func fs31SecureAccepted(mx fs31Mx) []string {
	var accepted []string
	for _, event := range mx.Events() {
		if event.Secure && event.Accepted {
			accepted = append(accepted, event.Command)
		}
	}
	return accepted
}

// The part the edge refused and the check that refused it: the relation's first failing check on that part, or
// the gate's own refusal's check where it refused the part before verifying it; empty where the circuit alone
// refused it or the refusal names no check.
func fs31Refused(outcome *fs31Outcome) (uint32, relationCheck) {
	for _, verdict := range outcome.verdicts {
		if verdict.index == outcome.refusedIndex && 0 < len(verdict.checks) {
			return outcome.refusedIndex, verdict.checks[0]
		}
	}
	var failure *relationFailure
	if errors.As(outcome.refusal, &failure) {
		return outcome.refusedIndex, failure.check
	}
	return outcome.refusedIndex, ""
}

// Fails where the relation and the circuit disagree on a part they were both asked about.
func fs31ExpectAgreement(t *testing.T, name string, outcome *fs31Outcome) {
	t.Helper()
	for _, verdict := range outcome.verdicts {
		if verdict.circuit == "" {
			continue
		}
		if (len(verdict.checks) == 0) != (verdict.circuit == fs31CircuitAccepted) {
			t.Errorf("%s: at part %d the relation fails %v and the circuit %s", name, verdict.index, verdict.checks, verdict.circuit)
		}
	}
}

// One line of the matrix report: a row in a cell, on a tier and edge, and what it came to.
type fs31MatrixEntry struct {
	row    string
	cell   string
	tier   string
	result string
}

// The report this process's rows add to, written at the end of TestFs31Matrix.
var fs31Matrix = struct {
	stateLock sync.Mutex
	entries   []*fs31MatrixEntry
}{}

func fs31Report(row string, outcome *fs31Outcome, result string) {
	tier := "T2 " + outcome.edgeName
	if testCircuitsRun {
		tier += ", circuits on the solver"
	}
	fs31Matrix.stateLock.Lock()
	defer fs31Matrix.stateLock.Unlock()
	fs31Matrix.entries = append(fs31Matrix.entries, &fs31MatrixEntry{row: row, cell: outcome.cell.String(), tier: tier, result: result})
}

// The report as a table, sorted by row and cell. Where SMTPPROOF_FS31_MATRIX names a file, it is written there too.
func fs31MatrixTable(t *testing.T) string {
	t.Helper()
	fs31Matrix.stateLock.Lock()
	entries := slices.Clone(fs31Matrix.entries)
	fs31Matrix.stateLock.Unlock()
	sort.SliceStable(entries, func(i int, j int) bool {
		if entries[i].row != entries[j].row {
			return entries[i].row < entries[j].row
		}
		return entries[i].cell < entries[j].cell
	})
	var table strings.Builder
	table.WriteString("| Row | Cell | Tier | Result |\n|---|---|---|---|\n")
	for _, entry := range entries {
		fmt.Fprintf(&table, "| %s | %s | %s | %s |\n", entry.row, entry.cell, entry.tier, entry.result)
	}
	if path := os.Getenv("SMTPPROOF_FS31_MATRIX"); path != "" {
		if err := os.WriteFile(path, []byte(table.String()), 0o644); err != nil {
			t.Error(err)
		}
	}
	return table.String()
}

// The edge's MX socket. With a forger on it, over TLS 1.2, whose record types are public, the pre-TLS dialog and
// the handshake pass as they are, and from the chosen application record on each the MX sends reaches the edge
// forged, of the same length: a reply of 250 sealed under a key the forger made up, which is all an edge holding
// no key can send. Each write is noted to wrote. Read runs on one goroutine at a time, the edge's reader of the MX.
type fs31MxConn struct {
	net.Conn
	reader    *bufio.Reader
	forgeFrom int
	suite     uint16
	wrote     func(data []byte)

	// STARTTLS has gone to the MX; once its 220 is read, what follows is records
	startTlsSent atomic.Bool
	tls          bool
	pending      []byte
	// server records of type application_data so far
	applicationRecords int
}

// The MX socket conn as an edge reads and writes it. secure says the pre-TLS dialog is already over.
func newFs31MxConn(conn net.Conn, forgeFrom int, suite uint16, secure bool, wrote func(data []byte)) *fs31MxConn {
	return &fs31MxConn{Conn: conn, reader: bufio.NewReader(conn), forgeFrom: forgeFrom, suite: suite, tls: secure, wrote: wrote}
}

func (self *fs31MxConn) Write(data []byte) (int, error) {
	if bytes.Contains(data, []byte("STARTTLS\r\n")) {
		self.startTlsSent.Store(true)
	}
	n, err := self.Conn.Write(data)
	if err == nil && self.wrote != nil {
		self.wrote(data)
	}
	return n, err
}

func (self *fs31MxConn) Read(buffer []byte) (int, error) {
	if self.forgeFrom <= 0 {
		return self.reader.Read(buffer)
	}
	for len(self.pending) == 0 {
		if !self.tls {
			line, err := self.reader.ReadString('\n')
			if line == "" {
				return 0, err
			}
			self.pending = append(self.pending, line...)
			if self.startTlsSent.Load() && 4 <= len(line) && line[:3] == "220" && line[3] == ' ' {
				self.tls = true
			}
			continue
		}
		header := make([]byte, tlsRecordHeaderBytes)
		if _, err := io.ReadFull(self.reader, header); err != nil {
			return 0, err
		}
		record := make([]byte, tlsRecordHeaderBytes+int(binary.BigEndian.Uint16(header[3:5])))
		copy(record, header)
		if _, err := io.ReadFull(self.reader, record[tlsRecordHeaderBytes:]); err != nil {
			return 0, err
		}
		self.pending = append(self.pending, self.forged(record)...)
	}
	n := copy(buffer, self.pending)
	self.pending = self.pending[n:]
	return n, nil
}

// One record as the edge gets it: forged once the chosen application record is reached.
func (self *fs31MxConn) forged(record []byte) []byte {
	if record[0] != tlsRecordApplicationData {
		return record
	}
	self.applicationRecords += 1
	if self.applicationRecords < self.forgeFrom {
		return record
	}
	// 1.2's server Finished took sequence number 0
	seq := uint64(self.applicationRecords)
	contentBytes := len(record) - tlsRecordHeaderBytes - tlsExplicitNonceBytes - tlsAeadTagBytes
	content := []byte("250 2.0.0 Ok: queued\r\n")
	if contentBytes < len(content) {
		content = content[:max(contentBytes, 1)]
	} else {
		content = append(content, bytes.Repeat([]byte{' '}, contentBytes-len(content))...)
	}
	forged, err := fs31ForgedServerRecord(tlsVersion12, self.suite, seq, content)
	if err != nil {
		return record
	}
	return forged
}
