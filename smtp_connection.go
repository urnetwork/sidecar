//go:build !sidecar_http && !ios_extension

// One connection's worth of a send (§14.4's outer steps, D-SMTP-1, D-SMTP-3, X7; SMTP-M9-07): one message to
// one recipient domain, from the stream to smtpedge to the outcome the prover reports. Everything inside TLS is
// the prover's (SmtpProver.SendSmtp); this is what surrounds it.
//
//	dial      ur/smtpedge, a Required, Service-mode §6 stream (§9.4, §6.10.1), through SmtpEdgeDialer: the
//	          Sidecar's Dial in a daemon, StubSmtpEdge or the engine in tests. The sender never dials port 25
//	          and never names an IP (R-SMTP-9): the edge resolves and dials the MX
//	preamble  the frame of SmtpPreamble, naming the selector pinned for the send, the declared byte count for
//	          the expected mode and the key set SmtpProver.KeySet() names, then SmtpPreambleResult's frame
//	envelope  OK names the envelope_domain the edge derived (QD-1154): one other than MAIL FROM's resets the stream
//	          before any record, EnvelopeRefused, which the sender holds; MAIL FROM is never moved to the edge's
//	codes     OK goes on; HALTED, QUOTA and TRY_LATER hold the message with retry_after_ms; NO_MX, NO_TLS and
//	          DENIED end it; KEYS holds it as KeysRefused, never a failure (DESIGN-DETAILS 3.7); a code of 0
//	          or one this version does not know resets the stream as §6.11's protocol error
//	tls       SmtpTlsPolicy.Authenticate over the MX the edge named and its dnssec_chain; the policy's
//	          VerifyPeer decides TL1 to TL4 inside the handshake, so a refused MX gets no application byte
//	sign      the message gains the issued X-UR-Ref and Feedback-ID and §14.6's two signatures under the
//	          pinned selector (SmtpDkimSign), and SmtpProofJob carries it, the key set the preamble named and
//	          the envelope group bound
//	send      SendSmtp over the same stream, its parts and SHTS through the stream's SmtpProofChannel; ctx
//	          ends it at any point, the stream reset under it, so a 2 h DATA send stays cancellable
//	report    the post-TLS mode goes to the pin store, and SmtpOutcome (§14.4's step 5) to the edge's listener
//	          after the stream ends, a NO_REPLY envelope
//
// A daemon's stream reaches its edge's listener, the client its ur/ ticket names, through §6's dispatcher with no
// Hello, which an edge carries no binding to answer (§6.4, owner decision 624): the parts and SHTS as calls marked
// for the edge (smtp_channel.go) and the outcome by Subprotocol.SendEdge. The verified ticket is the edge's identity,
// as for the stream.
//
// An empty key set makes no connection: the host has no ready family, and the send reports NoProver, which the
// sender queues (DESIGN-DETAILS 3.7). An edge crash ends the stream: one that ends before the preamble's answer
// is dialed again at once, which reaches the §9 backup ticket, up to EdgeResetRetryCount times; one that ends
// later holds the send for its next retry, since the MX may have seen MAIL (§14.9's failure row).
//
// Barriers: smtp.preamble once SmtpPreambleResult is read, and smtp.send just before SendSmtp, after which the
// first TLS byte goes; both keyed by the hex of the send's effect key, an opaque id. No proof, key, recipient,
// subject or reply text reaches a log or an error here (I-13, D-SMTP-10).
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Format values (§9.4, §14.4, §14.6): identifiers, not settings.
const (
	// The ur/ name of smtpedge's platform listener.
	SmtpEdgeAddress = "ur/smtpedge"
	// SmtpPreambleResult.send_id's width: 12 random octets, which X-UR-Ref carries.
	SmtpSendIdByteCount = 12
)

var (
	// The edge issued values outside their forms: a send_id, MX host or HELO name a send cannot use.
	errSmtpPreambleIssued = errors.New("smtp preamble: the edge issued values outside their forms")
	// What a connection was handed does not hold together.
	errSmtpConnectionArgs = errors.New("smtp connection: invalid send")
)

// One stream to smtpedge as a connection runs one send over it: the preamble's frames, then the TLS the edge
// splices to the MX. Safe for concurrent use as net.Conn is.
type SmtpEdgeStream interface {
	net.Conn
	// The channel for the SHTS and parts of the send sendId names, to the edge this stream reached.
	ProofChannel(sendId []byte) SmtpProofChannel
	// The send's self-report (§14.4's step 5), to the edge's listener once the stream has ended.
	SendOutcome(ctx context.Context, outcome *protocol.SmtpOutcome) error
	// Ends the stream with a reset, as §6.11's protocol errors and a cancelled send do.
	Abort() error
}

// How a sender reaches smtpedge: NewSidecarSmtpEdgeDialer's over the Sidecar's sockets, or a test's. Safe for
// concurrent use.
type SmtpEdgeDialer interface {
	// A new stream to one edge: each call Finds anew, so a crashed edge's stream gives way to the backup ticket.
	DialSmtpEdge(ctx context.Context) (SmtpEdgeStream, error)
}

// What a daemon's stream reaches its edge's listener through: §6's dispatcher of the generation the stream opened on
// (Subprotocol), or a test's.
type smtpEdgeSubprotocol interface {
	smtpEdgeCaller
	SendEdge(ctx context.Context, clientId Id, messageType protocol.MessageType, body []byte) error
}

var _ smtpEdgeSubprotocol = (*Subprotocol)(nil)

// SmtpEdgeDialer over a Sidecar: Sidecar.Dial of ur/smtpedge, whose ticket names the edge's client, and the
// RPCs to that client through the dispatcher of the generation the stream opened on.
type sidecarSmtpEdgeDialer struct {
	sidecar  *Sidecar
	settings *SmtpSenderSettings
}

// The dialer a daemon's sender uses, over sidecar's sockets, under settings, which must have passed validate.
func NewSidecarSmtpEdgeDialer(sidecar *Sidecar, settings *SmtpSenderSettings) SmtpEdgeDialer {
	return &sidecarSmtpEdgeDialer{sidecar: sidecar, settings: settings}
}

// See SmtpEdgeDialer.
func (self *sidecarSmtpEdgeDialer) DialSmtpEdge(ctx context.Context) (SmtpEdgeStream, error) {
	conn, err := self.sidecar.Dial(ctx, SmtpEdgeAddress, nil)
	if err != nil {
		return nil, err
	}
	var subprotocol smtpEdgeSubprotocol
	if component := self.sidecar.socketComponent(); component != nil {
		if generation, _, _ := component.current(); generation != nil && generation.subprotocol != nil {
			subprotocol = generation.subprotocol
		}
	}
	if subprotocol == nil {
		conn.Abort()
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	stream, err := newSidecarSmtpEdgeStream(conn, subprotocol, self.settings)
	if err != nil {
		// a nil interface, never one holding a nil stream
		return nil, err
	}
	return stream, nil
}

// One ur/smtpedge stream of a Sidecar.
type sidecarSmtpEdgeStream struct {
	*SocketConn
	subprotocol smtpEdgeSubprotocol
	// the listener conn's ticket names: the edge that holds the connection
	edgeClientId Id
	settings     *SmtpSenderSettings
}

// The stream over conn, a dialed ur/smtpedge stream, reaching the listener its ticket names through subprotocol,
// under settings. A ticket that names no listener aborts conn.
func newSidecarSmtpEdgeStream(conn *SocketConn, subprotocol smtpEdgeSubprotocol, settings *SmtpSenderSettings) (*sidecarSmtpEdgeStream, error) {
	edgeClientId, err := IdFromBytes(conn.Ticket().GetListenerClientId())
	if err != nil {
		conn.Abort()
		return nil, err
	}
	return &sidecarSmtpEdgeStream{SocketConn: conn, subprotocol: subprotocol, edgeClientId: edgeClientId, settings: settings}, nil
}

// See SmtpEdgeStream. The calls go to the ticket's listener, marked for an edge, so they run no Hello.
func (self *sidecarSmtpEdgeStream) ProofChannel(sendId []byte) SmtpProofChannel {
	return newSmtpProofChannel(self.subprotocol, self.edgeClientId, sendId, self.settings)
}

// See SmtpEdgeStream: a NO_REPLY envelope of type SMTP_OUTCOME to the ticket's listener (SendEdge), which waits for
// connect until ctx ends. nil says connect took it, never that the edge did.
func (self *sidecarSmtpEdgeStream) SendOutcome(ctx context.Context, outcome *protocol.SmtpOutcome) error {
	body, err := proto.Marshal(outcome)
	if err != nil {
		return err
	}
	return self.subprotocol.SendEdge(ctx, self.edgeClientId, protocol.MessageType_SMTP_OUTCOME, body)
}

// One send a connection runs.
type smtpConnectionArgs struct {
	// D-MCP-11's key of the send, whose hex keys the barriers.
	EffectKey []byte
	Wire      *SmtpWireMessage
	// The envelope sender at b.<net>.<root> (§14.6).
	SenderAddress string
	// Lowercase, with no trailing dot.
	RecipientDomain string
	// Each recipient's local part, all at RecipientDomain, at most smtp_recipients_per_message.
	RecipientLocals []string
	Flags           uint32
	// The recipient domains this message's own approval lets go at TL4, from a verified outbox entry.
	MessageTl4Domains []string
	// The mode the declared count is for: the domain's pin's, else BDAT (plan-SMTP-preamble-byte-count).
	Mode SmtpMode
	// The earlier connection's send_id when this one retries it, else empty.
	RetryOfSendId []byte
	// The key set the preamble names, empty when the host has none ready.
	KeySet []byte
	// SmtpProofJob.EnvelopeGroupMaxCount: 0 for what fits.
	EnvelopeGroupMaxCount int
	// SmtpOutcome's counts of DSNs made or received since the last outcome sent.
	DsnCount        uint32
	HardBounceCount uint32
}

// What one connection came to. Exactly one of these holds: NoProver; Err with no PreambleCode; a PreambleCode
// other than OK; or OK, with the TLS level, any refusal and the prover's result or error.
type SmtpConnectionResult struct {
	// No key set or current measurement was available. This host only queues (D-SMTP-18, QD-483).
	NoProver bool
	// The edge's answer, OK or the refusal that ended the stream before any MX byte; UNSPECIFIED when the
	// connection ended before one came.
	PreambleCode protocol.SmtpPreambleCode
	// HALTED, QUOTA and TRY_LATER's retry_after_ms.
	RetryAfterMillis uint32
	// KEYS: the edge does not accept the key set the preamble named. A hold, never a failure: the sender
	// tries the next older ready set once, else defers for KeysRetryTimeout (DESIGN-DETAILS 3.7).
	KeysRefused bool
	// OK named an envelope_domain other than MAIL FROM's (QD-1154): the edge's facts and the strict domains the
	// sender read differ, so the stream was reset before any client record, which Z4 would have failed and the edge
	// cut (§14.7). A hold, never a failure: the sender reads the set again after EnvelopeRetryTimeout.
	EnvelopeRefused bool
	// What OK issued.
	SendId []byte
	MxHost string
	// The level VerifyPeer passed, which the sent copy records (I-11), or unreached.
	TlsLevel SmtpTlsLevel
	// Why VerifyPeer refused the MX, nil when it did not: tls_refused, its DSN giving the refusal's Reason.
	TlsRefusal *SmtpTlsRefusal
	// The prover's result, nil when SendSmtp failed or never ran.
	Proof *SmtpProofResult
	// The connection's own failure: the dial, the frames, a reset, the store, a DKIM selector, the prover.
	// Never wraps a reply's or a message's text.
	Err error
	// Streams that ended before their preamble's answer and were dialed again at once.
	EdgeResetCount int
	// The send's SmtpOutcome went to the edge's listener.
	OutcomeSent bool
}

// Whether the connection may have spent a unit: the MX may have seen MAIL (§14.7). A preamble refusal, KEYS,
// an EHLO refusal, a missing REQUIRETLS extension, a too_large and a mode's reconnect all end before MAIL.
// A send that failed after OK without saying how far it got may have spent a unit.
func (self *SmtpConnectionResult) MailMayHaveGone() bool {
	if self.NoProver || self.EnvelopeRefused || self.PreambleCode != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
		return false
	}
	if self.TlsRefusal != nil {
		return false
	}
	if self.Proof == nil {
		return true
	}
	return self.Proof.Mode != 0 && !self.Proof.RequireTlsMissing && !self.Proof.TooLarge && self.Proof.ReconnectByteCount == 0
}

// SmtpOutcome's form of a send that got a send_id (§14.4's step 5): the level, the mode, every reply code the
// sidecar read inside TLS, the DSN counts, and whether a downgrade was refused. No text and no address.
func (self *SmtpConnectionResult) outcome(dsnCount uint32, hardBounceCount uint32) *protocol.SmtpOutcome {
	outcome := &protocol.SmtpOutcome{
		SendId:           self.SendId,
		TlsLevel:         uint32(self.TlsLevel),
		DsnCount:         dsnCount,
		HardBounceCount:  hardBounceCount,
		DowngradeRefused: self.TlsRefusal != nil,
	}
	if self.Proof != nil {
		outcome.Mode = self.Proof.Mode
		outcome.ReplyCodes = self.Proof.ReplyCodes
	}
	return outcome
}

// The connection driver of one network's sender, its parts shared by every send. Safe for concurrent use.
type smtpConnection struct {
	dialer   SmtpEdgeDialer
	prover   SmtpProver
	policy   *SmtpTlsPolicy
	dkim     *SmtpDkimKeys
	frame    *SmtpFrameSettings
	settings *SmtpSenderSettings
	clock    Clock
	log      Logger
}

// Runs one send to its end, or to ctx's: see the file header. Never panics on what the edge sends.
func (self *smtpConnection) Run(ctx context.Context, args *smtpConnectionArgs) *SmtpConnectionResult {
	result := &SmtpConnectionResult{}
	if len(args.KeySet) == 0 || self.prover == nil {
		result.NoProver = true
		return result
	}
	senderLocal, envelopeDomain, ok := SplitSmtpEnvelopeAddress(args.SenderAddress)
	if !ok || args.Wire == nil || len(args.RecipientLocals) == 0 || !smtpDomainForm(args.RecipientDomain) {
		result.Err = errSmtpConnectionArgs
		return result
	}
	for _, local := range args.RecipientLocals {
		if !smtpLocalPartForm(local) {
			result.Err = errSmtpConnectionArgs
			return result
		}
	}
	byteCount, err := args.Wire.ByteCount(args.Mode)
	if err != nil {
		result.Err = err
		return result
	}
	// the selector the preamble declares, held past any rotation until the send ends
	selector, err := self.dkim.Current(ctx, args.Wire.HeaderFromDomain())
	if err != nil {
		result.Err = err
		return result
	}
	defer selector.Release()
	preamble := &protocol.SmtpPreamble{
		Version:          SmtpPreambleVersion,
		RecipientDomain:  args.RecipientDomain,
		RecipientCount:   uint32(len(args.RecipientLocals)),
		MessageId:        args.Wire.MessageId(),
		HeaderFromDomain: args.Wire.HeaderFromDomain(),
		DkimSelector:     selector.DkimSelector(),
		MessageByteCount: byteCount,
		RetryOfSendId:    args.RetryOfSendId,
		Flags:            args.Flags,
		ProofKeySet:      args.KeySet,
	}
	barrierKey := hex.EncodeToString(args.EffectKey)
	for {
		stream, err := self.dialer.DialSmtpEdge(ctx)
		if err != nil {
			result.Err = err
			return result
		}
		reset := self.runStream(ctx, stream, preamble, args, senderLocal, envelopeDomain, selector, barrierKey, result)
		if !reset || self.settings.EdgeResetRetryCount <= result.EdgeResetCount || ctx.Err() != nil {
			return result
		}
		// the edge went before it answered: the next Find reaches the backup ticket
		result.EdgeResetCount += 1
		result.Err = nil
	}
}

// One stream's preamble and send. Returns whether the stream ended before the preamble's answer, which is
// worth an immediate redial.
func (self *smtpConnection) runStream(
	ctx context.Context,
	stream SmtpEdgeStream,
	preamble *protocol.SmtpPreamble,
	args *smtpConnectionArgs,
	senderLocal string,
	envelopeDomain string,
	selector *SmtpDkimSelector,
	barrierKey string,
	result *SmtpConnectionResult,
) (resetBeforeAnswer bool) {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// a cancelled send resets its stream, which ends every read and write the prover is in
	stopAbort := context.AfterFunc(streamCtx, func() { stream.Abort() })
	defer stopAbort()
	closed := false
	closeStream := func() {
		if !closed {
			closed = true
			stream.Close()
		}
	}
	defer closeStream()

	var timedOut atomic.Bool
	stopTimeout := self.clock.AfterFunc(self.settings.PreambleResultTimeout, func() {
		timedOut.Store(true)
		stream.Abort()
	})
	if err := WriteSmtpPreamble(stream, preamble, self.frame); err != nil {
		stopTimeout()
		result.Err = err
		return ctx.Err() == nil && !timedOut.Load()
	}
	preambleResult, err := ReadSmtpPreambleResult(stream, self.frame)
	stopTimeout()
	if err != nil {
		result.Err = err
		if errors.Is(err, ErrSmtpFrameProtocol) {
			// §6.11's zero rule: a code of 0, an unknown code or a bad frame resets the stream
			stream.Abort()
			return false
		}
		return ctx.Err() == nil && !timedOut.Load()
	}
	testHookBarrier("smtp.preamble", barrierKey)
	code := protocol.SmtpPreambleCode(preambleResult.GetCode())
	result.PreambleCode = code
	switch code {
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA,
		protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER:
		result.RetryAfterMillis = preambleResult.GetRetryAfterMs()
		return false
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS:
		result.KeysRefused = true
		return false
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK:
	default:
		// NO_MX, NO_TLS and DENIED end the message
		return false
	}

	sendId := preambleResult.GetSendId()
	mxHost, mxHostOk := smtpTlsName(preambleResult.GetMxHost())
	heloName, heloNameOk := smtpTlsName(preambleResult.GetHeloName())
	if len(sendId) != SmtpSendIdByteCount || !mxHostOk || !heloNameOk {
		stream.Abort()
		result.Err = errSmtpPreambleIssued
		return false
	}
	// the envelope the edge derived, which the session holds MAIL FROM to (QD-1154): another than this send's resets
	// before any record, so nothing is cut, and the send waits for the edge's next facts. An edge that names none
	// predates the check, and this send's own is sent as before; the edge's value is never sent at
	if issued := preambleResult.GetEnvelopeDomain(); issued != "" && !strings.EqualFold(issued, envelopeDomain) {
		stream.Abort()
		result.EnvelopeRefused = true
		return false
	}
	result.SendId = sendId
	result.MxHost = mxHost
	authentication, err := self.policy.Authenticate(ctx, &SmtpTlsRequest{
		RecipientDomain:   args.RecipientDomain,
		MxHost:            mxHost,
		DnssecChain:       preambleResult.GetDnssecChain(),
		Flags:             args.Flags,
		MessageTl4Domains: args.MessageTl4Domains,
	})
	if err != nil {
		// a pin or policy the store cannot read could be one that refuses this MX: the send is held
		stream.Abort()
		result.Err = err
		return false
	}
	// the issued values are untrusted, so signing holds each to its exact form
	message, err := SmtpDkimSign(args.Wire, &SmtpDkimSignArgs{
		Signer:        selector,
		Issued:        &SmtpIssuedHeaders{XUrRef: preambleResult.GetXUrRef(), FeedbackId: preambleResult.GetFeedbackId()},
		SignTime:      self.clock.Now(),
		ExpireTimeout: self.settings.DkimExpireTimeout,
	})
	if err != nil {
		stream.Abort()
		result.Err = err
		return false
	}
	job := &SmtpProofJob{
		SendId: sendId,
		Preamble: &SmtpProofPreamble{
			RecipientDomain:  preamble.RecipientDomain,
			RecipientCount:   preamble.RecipientCount,
			MessageId:        preamble.MessageId,
			HeaderFromDomain: preamble.HeaderFromDomain,
			DkimSelector:     preamble.DkimSelector,
			MessageByteCount: preamble.MessageByteCount,
			Flags:            preamble.Flags,
			HeloName:         heloName,
			XUrRef:           preambleResult.GetXUrRef(),
			FeedbackId:       preambleResult.GetFeedbackId(),
			EnvelopeDomain:   envelopeDomain,
			MxHost:           mxHost,
			ProofKeySet:      args.KeySet,
		},
		SenderLocal:           senderLocal,
		RecipientLocals:       args.RecipientLocals,
		Message:               message,
		VerifyPeer:            authentication.VerifyPeer,
		KeySet:                args.KeySet,
		EnvelopeGroupMaxCount: args.EnvelopeGroupMaxCount,
	}
	testHookBarrier("smtp.send", barrierKey)
	proofResult, err := self.prover.SendSmtp(ctx, stream, job, stream.ProofChannel(sendId))
	testHookBarrier("smtp.send.after", barrierKey)
	result.TlsLevel = authentication.Level()
	result.TlsRefusal = authentication.Refusal()
	result.Proof = proofResult
	if errors.Is(err, ErrSmtpProverUnmeasured) {
		result.NoProver = true
	} else if err != nil {
		result.Err = err
	}
	if proofResult != nil && proofResult.Mode != 0 {
		if err := authentication.RecordMode(SmtpMode(proofResult.Mode)); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[smtp]send %s: the post-tls mode was not recorded: %v\n", barrierKey, err)
		}
	}
	closeStream()

	// the self-report, once the stream has ended; it only tightens, so one that cannot go is dropped
	outcomeCtx, outcomeCancel := context.WithCancel(context.WithoutCancel(ctx))
	stopOutcome := self.clock.AfterFunc(self.settings.OutcomeSendTimeout, outcomeCancel)
	err = stream.SendOutcome(outcomeCtx, result.outcome(args.DsnCount, args.HardBounceCount))
	stopOutcome()
	outcomeCancel()
	result.OutcomeSent = err == nil
	if err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[smtp]send %s: the outcome did not go: %v\n", barrierKey, err)
	}
	return false
}

// The error a result's Err holds, wrapped with what the connection was doing, for a log: never a reply's text.
func (self *SmtpConnectionResult) describe() string {
	switch {
	case self.NoProver:
		return "no prover"
	case self.KeysRefused:
		return "keys refused"
	case self.EnvelopeRefused:
		return "the edge derived another envelope"
	case self.Err != nil && self.PreambleCode == protocol.SmtpPreambleCode_SMTP_PREAMBLE_CODE_UNSPECIFIED:
		return fmt.Sprintf("before the preamble's answer: %v", self.Err)
	case self.Err != nil:
		return fmt.Sprintf("preamble %s, then: %v", self.PreambleCode, self.Err)
	}
	return fmt.Sprintf("preamble %s", self.PreambleCode)
}
