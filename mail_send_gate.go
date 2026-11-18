//go:build !ios_extension

// §15.10's step 1 for a send a host submits (QD-853, owner decision 288; R-MAIL-1, I-8, I-9, I-13): what ur daemon's
// mail.send runs (mail_send_daemon.go), the daemon's gate holding a message for an I-8 approval as a submission is
// held. MailClient.SubmitSend starts where Send starts (planSend), so a send the gate holds was refused for no shape,
// zone or From, and then:
//
//	members   a message to this network's own addresses alone is W: Send at once, with no approval
//	          (plan-MCP-approved-recipients: mail to members stays W)
//	outside   a message naming any other recipient is an outward action (I-8): the whole message waits on §5.4's gate
//	          as one mail_send action, and nothing is kept or deposited, its member part included, until the gate
//	          passes it. MAIL-M9-01's approval records (§15.10's rcpt/, MailApprovedRecipients) are not on sidecar,
//	          so every outside recipient takes the gate, the closed direction of QD-034's interim
//	action    MCP-M3-02's mail_send row: every recipient, Bcc included, distinct and lowercase in the order Send names
//	          them (To, Cc, Bcc); the From in its one form as from_alias; body_sha256, SHA-256 over the subject, a CRLF
//	          and the text as the draft gives them (a subject holds no line break, so its first CRLF ends it); and a
//	          preview of both within MailSendSettings.PreviewMaxByteCount, which an approver renders as untrusted text.
//	          The same draft builds the same bytes, so the call sent again after `ur approve <id>` meets its decision,
//	          and a draft that changes anything is another action
//	effect    once the gate passes it, Send of the same draft: the member part deposits, and each outside recipient
//	          answers internet_waits, nothing sent to it, until MAIL-M9-01 and MAIL-M9-02 queue internet mail at o/
//	          under the use's effect key. Send keeps no effect key, so a run the gate repeats after an uncertain
//	          outcome (AU4) deposits again. The real gate (record_gate.go) refuses kind mail before its Reserve until
//	          MAIL-M9-02's MailOutbox.Lookup is registered for it, so before then only a standing grant's run, which
//	          keeps no ledger row, reaches the effect
//	answer    the effect's MailSendResult; *ApprovalPendingError while a person's decision is awaited; a retry of a
//	          send whose use is done answers its send_id alone, the effect not run again (AU4)
//
// The call carries no run binding: a host's submission, an app's call or a typed ur command, is no run and so
// untainted (§16.6's spend step 1); MCP's mail_send (MCP-M7-01) carries its run's own and the tainted run's rule. A
// same-uid process may submit as ur does (owner decision 47), and the gate still holds what is outward. Nothing here
// logs an address, a subject or a byte of the text (I-13). Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"slices"
	"sync"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

// The mark a preview cut at its bound ends with, so an approver knows more follows.
const mailSendPreviewCutMark = "…"

// Sends args as a host's submission (see the file header): at once when every recipient is this network's own, else
// only once §5.4's gate passes the send's mail_send action. *ApprovalPendingError while it waits for a person, with
// nothing kept or deposited; the gate's refusal, or the effect's, otherwise.
func (self *MailClient) SubmitSend(ctx context.Context, args *MailSendArgs) (*MailSendResult, error) {
	plan, err := self.planSend(args)
	if err != nil {
		return nil, err
	}
	outside := slices.ContainsFunc(plan.recipients, func(address string) bool {
		_, own := mailSendOwnRecipient(plan.row, address)
		return !own
	})
	if !outside {
		return self.deliverSend(ctx, args, plan)
	}
	gate := plan.binding.Gate
	if gate == nil {
		return nil, ErrSidecarGateDenied
	}
	stored, err := mailSendAction(args, plan, self.sendSettings())
	if err != nil {
		return nil, err
	}
	effect := &mailSendEffect{client: self, args: mailSendCopyArgs(args)}
	action := &SidecarAction{
		Kind:      SidecarActionMail,
		Canonical: stored.Bytes,
		Risk:      CanonicalActionRisk(stored, SidecarRiskNormal, SidecarRiskNormal),
		Effect:    effect,
	}
	testHookBarrier("mail.send.gate.before", "")
	err = gate.Authorize(ctx, action, nil)
	testHookBarrier("mail.send.gate.after", "")
	if err != nil {
		return nil, err
	}
	outcome := action.Outcome
	switch {
	case outcome == nil:
		return nil, fmt.Errorf("%w: the gate answered no outcome", ErrMailSendUncertain)
	case outcome.State == ApprovalOutcomeDone:
		if result := effect.answer(); result != nil {
			return result, nil
		}
		// a retry the gate answered from the recorded outcome: the effect did not run again
		sendId, err := IdFromBytes(outcome.EffectRef)
		if err != nil {
			return nil, fmt.Errorf("%w: the recorded outcome names no send", ErrMailSendUncertain)
		}
		return &MailSendResult{SendId: sendId}, nil
	case outcome.State == ApprovalOutcomeNotDone:
		if outcome.Err != nil {
			return nil, outcome.Err
		}
		return nil, ErrSidecarEffectNotDone
	case outcome.Err != nil:
		return nil, fmt.Errorf("%w: %w", ErrMailSendUncertain, outcome.Err)
	}
	return nil, ErrMailSendUncertain
}

// The mail_send action plan's send of args passes the gate as (the file header's action row), held to its kind's
// row by NewCanonicalAction.
func mailSendAction(args *MailSendArgs, plan *mailSendPlan, settings *MailSendSettings) (*StoredCanonicalAction, error) {
	bodyHash := sha256.New()
	io.WriteString(bodyHash, args.Subject)
	io.WriteString(bodyHash, "\r\n")
	io.WriteString(bodyHash, args.Text)
	return NewCanonicalAction(&protocol.CanonicalAction{
		Kind:       uint32(SidecarActionMail),
		Recipients: slices.Clone(plan.recipients),
		BodySha256: bodyHash.Sum(nil),
		Preview:    mailSendPreview(args, settings.PreviewMaxByteCount),
		Alias:      plan.fromAddress,
	})
}

// What an approver sees of the message: its subject, a blank line and its text, cut at a rune within maxByteCount
// bytes and then ending with mailSendPreviewCutMark where the mark fits.
func mailSendPreview(args *MailSendArgs, maxByteCount int) string {
	preview := "Subject: " + args.Subject + "\n\n" + args.Text
	if len(preview) <= maxByteCount {
		return preview
	}
	mark := mailSendPreviewCutMark
	if maxByteCount < len(mark) {
		mark = ""
	}
	cut := maxByteCount - len(mark)
	for 0 < cut && !utf8.RuneStart(preview[cut]) {
		cut -= 1
	}
	return preview[:cut] + mark
}

// A copy of args whose lists are its own, so the effect sends the draft the action was built over.
func mailSendCopyArgs(args *MailSendArgs) *MailSendArgs {
	copied := *args
	copied.To, copied.Cc, copied.Bcc = slices.Clone(args.To), slices.Clone(args.Cc), slices.Clone(args.Bcc)
	return &copied
}

// A submitted send's effect, which the gate runs once it passes the action (plan-MCP-effect-seam): Send of the draft
// the action was built over, its answer kept for SubmitSend. Safe for concurrent use.
type mailSendEffect struct {
	client *MailClient
	args   *MailSendArgs

	stateLock sync.Mutex
	result    *MailSendResult
}

// See SidecarEffect. The effect key is unused until MAIL-M9-02's o/ entries carry it (the file header's effect row).
// Send's error is the whole send's, nothing deposited, so it proves the effect did not happen.
func (self *mailSendEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	result, err := self.client.Send(ctx, self.args)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.result = result
	}()
	return result.SendId.Bytes(), nil
}

// What the effect's run answered, nil where it did not run.
func (self *mailSendEffect) answer() *MailSendResult {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.result
}
