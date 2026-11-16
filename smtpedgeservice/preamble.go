// One preamble's path at the edge (§14.5, §14.7, D-SMTP-1): the frame read, its version and field bounds,
// the send gate, the halts and the quota, the key set, the MX and its pre-TLS dialog, then the issued
// values and the proof session, and the result frame. Every refusal is answered before any byte reaches
// an MX: DENIED, HALTED, QUOTA or KEYS before a dial, NO_MX, NO_TLS or TRY_LATER after one that reached no
// MX, and in each case nothing of the sidecar's has been forwarded. A code of 0 is never written (§6.11).
//
// Nothing here touches Postgres (I-12, §22.5): the gate answers from memory, the quota with one script on
// {smq_} (three for Community), the world through the resolver and the dialer. The edge reads the network,
// client and sidecar from the ticket (smtpPreambleStream), never from the sidecar. The key set is asked of
// the verifier before any dial, so KEYS dials nothing (DESIGN-DETAILS 3.2.5), and the session, which
// needs the MX the dial chose, opens after it; a session that refuses the key set then still answers
// KEYS, with the MX closed and the reservation released. A refusal after the reservation releases it, so
// only the burst token is spent (§14.7, §14.9).
//
// What an OK outcome holds, the MX connection past STARTTLS's 220, the reservation, the session and the
// send record's fields, is the splice's (SMTP-M9-13), which debits at MAIL, closes the quota at the end
// and batches the record. The MX's IP stays in memory; the record keeps mx_host alone (D-SMTP-10).
//
// Safe for concurrent use: one call per stream.

package smtpedgeservice

import (
	"context"
	"errors"
	"io"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// plan-SMTP-small-readings#5: a selector is 26 lowercase base32 characters, one label.
var smtpDkimSelectorPattern = regexp.MustCompile(`^[a-z2-7]{26}$`)

// A Message-ID's left side (RFC 5322 §3.6.4's dot-atom-text): atext and dots.
var smtpMessageIdLeftPattern = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$")

// The preamble path's reasons, beside the gate's, the quota's and the connector's.
const (
	smtpPreambleReasonBounds  = "bounds"
	smtpPreambleReasonKeys    = "keys"
	smtpPreambleReasonQuota   = "quota_unanswered"
	smtpPreambleReasonIssue   = "issue"
	smtpPreambleReasonSession = "session"
)

// What the stream's listener knows of its dialer, from the ticket (§14.5): never from the sidecar.
type smtpPreambleStream struct {
	NetworkId sidecar.Id
	ClientId  sidecar.Id
	// The dialer's sidecar, the §8 subject of mail_send (QD-040's sidecar_id claim).
	SidecarId sidecar.Id
}

// What one preamble came to.
type smtpPreambleOutcome struct {
	// The answer, its code never 0.
	Result *protocol.SmtpPreambleResult
	// Which check answered, a word from a closed set: never sent.
	Reason string

	// The rest only on OK.
	Mx          *smtpMxConnection
	Session     sidecar.SmtpProofSession
	Reservation *SmtpQuotaReservation
	// The send record's fields known now; the splice sets EndTime, ByteCount, TlsVersion, TlsLevel and
	// Result.
	Send *SmtpSendRecord
}

// Gives back what an OK outcome holds when its stream cannot use it: the MX closed, its slot and the
// reservation released.
func (self *smtpPreambleOutcome) abandon(ctx context.Context, quota *SmtpQuota) {
	if self.Mx != nil {
		self.Mx.close()
	}
	if self.Reservation != nil {
		quota.Release(ctx, self.Reservation)
	}
}

// Everything one edge's preamble path reads.
type smtpPreambleHandler struct {
	settings *SmtpEdgeSettings
	frame    *sidecar.SmtpFrameSettings
	clock    sidecar.Clock
	abuse    sidecar.AbuseGate
	gate     SmtpGate
	quota    *SmtpQuota
	mx       *smtpMxConnector
	verifier sidecar.SmtpProofVerifier
	issuer   *smtpIssuer
	metrics  *smtpMetrics
}

// The preamble's version and field bounds, the first row (§14.5). A preamble that passes is returned
// with its names lowercased; one that does not, nil.
func checkSmtpPreamble(preamble *protocol.SmtpPreamble, settings *SmtpEdgeSettings) *protocol.SmtpPreamble {
	if preamble.GetVersion() != sidecar.SmtpPreambleVersion {
		return nil
	}
	recipientDomain := strings.ToLower(preamble.GetRecipientDomain())
	if !settings.ldhName(recipientDomain) || !strings.Contains(recipientDomain, ".") {
		return nil
	}
	if preamble.GetRecipientCount() == 0 {
		return nil
	}
	messageId := preamble.GetMessageId()
	left, right, found := strings.Cut(messageId, "@")
	if !found || settings.PreambleMessageIdMaxByteCount < len(messageId) || !smtpMessageIdLeftPattern.MatchString(left) || !settings.ldhName(right) {
		return nil
	}
	headerFromDomain := strings.ToLower(preamble.GetHeaderFromDomain())
	if !settings.ldhName(headerFromDomain) || !strings.Contains(headerFromDomain, ".") {
		return nil
	}
	if !smtpDkimSelectorPattern.MatchString(preamble.GetDkimSelector()) {
		return nil
	}
	if preamble.GetMessageByteCount() == 0 {
		return nil
	}
	if retryOf := preamble.GetRetryOfSendId(); len(retryOf) != 0 && len(retryOf) != SmtpSendIdByteCount {
		return nil
	}
	if preamble.GetFlags()&^sidecar.SmtpFlagsKnown != 0 {
		return nil
	}
	return &protocol.SmtpPreamble{
		Version:          preamble.GetVersion(),
		RecipientDomain:  recipientDomain,
		RecipientCount:   preamble.GetRecipientCount(),
		MessageId:        messageId,
		HeaderFromDomain: headerFromDomain,
		DkimSelector:     preamble.GetDkimSelector(),
		MessageByteCount: preamble.GetMessageByteCount(),
		RetryOfSendId:    preamble.GetRetryOfSendId(),
		Flags:            preamble.GetFlags(),
		ProofKeySet:      preamble.GetProofKeySet(),
	}
}

// A refusal's outcome. retryAfter rides only HALTED, QUOTA and TRY_LATER.
func (self *smtpPreambleHandler) refuse(code protocol.SmtpPreambleCode, retryAfter time.Duration, reason string) *smtpPreambleOutcome {
	result := &protocol.SmtpPreambleResult{Code: uint32(code)}
	switch code {
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER:
		result.RetryAfterMs = uint32(min(max(retryAfter.Milliseconds(), 1), math.MaxUint32))
	}
	return &smtpPreambleOutcome{Result: result, Reason: reason}
}

// The metric's word for a code.
func smtpPreambleResultWord(code protocol.SmtpPreambleCode) string {
	switch code {
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK:
		return smtpPreambleResultOk
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED:
		return smtpPreambleResultHalted
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA:
		return smtpPreambleResultQuota
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED:
		return smtpPreambleResultDenied
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX:
		return smtpPreambleResultNoMx
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_TLS:
		return smtpPreambleResultNoTls
	case protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS:
		return smtpPreambleResultKeys
	}
	return smtpPreambleResultTryLater
}

// Judges one decoded preamble from stream and, on OK, reaches its MX. The outcome's code is never 0.
func (self *smtpPreambleHandler) handle(ctx context.Context, stream *smtpPreambleStream, preamble *protocol.SmtpPreamble) *smtpPreambleOutcome {
	outcome := self.decide(ctx, stream, preamble)
	self.metrics.preambles.Add(1, smtpPreambleResultWord(protocol.SmtpPreambleCode(outcome.Result.GetCode())))
	return outcome
}

func (self *smtpPreambleHandler) decide(ctx context.Context, stream *smtpPreambleStream, preamble *protocol.SmtpPreamble) *smtpPreambleOutcome {
	preamble = checkSmtpPreamble(preamble, self.settings)
	if preamble == nil {
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, 0, smtpPreambleReasonBounds)
	}
	now := self.clock.Now()
	gate := checkSmtpGate(self.gate, self.abuse, &SmtpGateRequest{
		NetworkId:        stream.NetworkId,
		SidecarId:        stream.SidecarId,
		HeaderFromDomain: preamble.GetHeaderFromDomain(),
		Flags:            preamble.GetFlags(),
	}, now, self.settings)
	if gate.Code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
		return self.refuse(gate.Code, gate.RetryAfter, gate.Reason)
	}

	quota, err := self.quota.Reserve(ctx, &SmtpQuotaRequest{
		NetworkId:        stream.NetworkId,
		Label:            gate.Label,
		RecipientCount:   preamble.GetRecipientCount(),
		MessageByteCount: preamble.GetMessageByteCount(),
		RecipientDomain:  preamble.GetRecipientDomain(),
		Limits:           gate.Limits,
		Community:        gate.Community,
	})
	if err != nil {
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, self.settings.QuotaRetryTimeout, smtpPreambleReasonQuota)
	}
	if quota.Code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
		return self.refuse(quota.Code, quota.RetryAfter, quota.Reason)
	}
	reservation := quota.Reservation
	release := func() {
		self.quota.Release(ctx, reservation)
	}

	// KEYS dials no MX and debits nothing (DESIGN-DETAILS 3.2.5)
	if self.verifier == nil || !self.verifier.HoldsKeySet(preamble.GetProofKeySet()) {
		release()
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS, 0, smtpPreambleReasonKeys)
	}

	mx, code, retryAfter, reason := self.mx.connect(ctx, preamble.GetRecipientDomain(), gate.Limits)
	if code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
		release()
		return self.refuse(code, retryAfter, reason)
	}

	issued, err := self.issuer.issue(stream.NetworkId, gate.Burner, gate.Tier, gate.Facts.ReportToken, now)
	if err != nil {
		mx.close()
		release()
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, self.settings.GateRetryTimeout, smtpPreambleReasonIssue)
	}
	session, err := self.verifier.NewSmtpProofSession(&sidecar.SmtpProofPreamble{
		RecipientDomain:  preamble.GetRecipientDomain(),
		RecipientCount:   preamble.GetRecipientCount(),
		MessageId:        preamble.GetMessageId(),
		HeaderFromDomain: preamble.GetHeaderFromDomain(),
		DkimSelector:     preamble.GetDkimSelector(),
		MessageByteCount: preamble.GetMessageByteCount(),
		Flags:            preamble.GetFlags(),
		HeloName:         mx.sendingAddress.HeloName,
		XUrRef:           issued.XUrRef,
		FeedbackId:       issued.FeedbackId,
		EnvelopeDomain:   gate.EnvelopeDomain,
		MxHost:           mx.mxHost,
		ProofKeySet:      preamble.GetProofKeySet(),
	})
	if err != nil {
		mx.close()
		release()
		if errors.Is(err, sidecar.ErrSmtpProofKeySet) {
			return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS, 0, smtpPreambleReasonKeys)
		}
		return self.refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, self.settings.GateRetryTimeout, smtpPreambleReasonSession)
	}

	return &smtpPreambleOutcome{
		Result: &protocol.SmtpPreambleResult{
			Code:         uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK),
			SendId:       issued.SendId,
			XUrRef:       issued.XUrRef,
			FeedbackId:   issued.FeedbackId,
			HeloName:     mx.sendingAddress.HeloName,
			MxHost:       mx.mxHost,
			DnssecChain:  mx.chain,
			EhloKeywords: mx.keywords,
		},
		Mx:          mx,
		Session:     session,
		Reservation: reservation,
		Send: &SmtpSendRecord{
			SendId:           issued.SendId,
			NetworkId:        stream.NetworkId,
			ClientId:         stream.ClientId,
			SendingAddress:   mx.sendingAddress.Address,
			RecipientDomain:  preamble.GetRecipientDomain(),
			MxHost:           mx.mxHost,
			StartTime:        now,
			MessageIdHash:    SmtpMessageIdHash(preamble.GetMessageId()),
			XUrRefKeyId:      issued.KeyId,
			RecipientCount:   preamble.GetRecipientCount(),
			MessageByteCount: preamble.GetMessageByteCount(),
			RetryOfSendId:    preamble.GetRetryOfSendId(),
		},
	}
}

// Reads the stream's preamble frame within PreambleTimeout, answers it, and writes the result frame. An
// error is a reset: a frame that breaks the protocol, a stream that ended, or a timeout; nothing held is
// kept then. On OK the outcome's MX connection waits for the splice, the result already written.
func (self *smtpPreambleHandler) serve(ctx context.Context, stream *smtpPreambleStream, conn io.ReadWriteCloser) (*smtpPreambleOutcome, error) {
	stopTimeout := self.clock.AfterFunc(self.settings.PreambleTimeout, func() { conn.Close() })
	preamble, err := sidecar.ReadSmtpPreamble(conn, self.frame)
	if !stopTimeout() {
		return nil, errors.Join(err, errSmtpPreambleTimeout)
	}
	if err != nil {
		return nil, err
	}
	outcome := self.handle(ctx, stream, preamble)
	if err := sidecar.WriteSmtpPreambleResult(conn, outcome.Result, self.frame); err != nil {
		outcome.abandon(ctx, self.quota)
		return nil, err
	}
	return outcome, nil
}

// A stream that sent no preamble within PreambleTimeout.
var errSmtpPreambleTimeout = errors.New("smtp preamble: none within the timeout")
