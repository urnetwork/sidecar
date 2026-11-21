//go:build !ios_extension

// §15.10's step 1 for a send that is an outward action (QD-853, owner decision 288; R-MAIL-1, I-8, I-9, I-13;
// MAIL-M9-01): a send naming any internet recipient, or a tainted run's (mail_send.go's gate row), waits on §5.4's gate
// as one mail_send action, whether Send's draft, a host's submission through ur daemon's mail.send
// (mail_send_daemon.go) or a mail client's on the submission port (MailClient.SubmitMessage). Each starts from the
// same plan, so a send the gate holds was refused for no shape, zone or From, and then:
//
//	action    MCP-M3-02's mail_send row: every recipient, Bcc included, distinct with its delivery spelling in the order Send names
//	          them (To, Cc, Bcc; a submission's envelope order); the From in its one form as from_alias; body_sha256,
//	          for a draft SHA-256 over the subject, a CRLF and the text as the draft gives them (a subject holds no line
//	          break, so its first CRLF ends it), for a submission SHA-256 over the message's bytes as submitted; and a
//	          preview of the subject and text within MailSendSettings.PreviewMaxByteCount, which an approver renders as
//	          untrusted text. The same draft or the same submitted bytes build the same action, so a send made again
//	          after `ur approve <id>` meets its decision, and one that changes anything is another action
//	gate      the run and agent a decision binds, the agent's words and a decision in hand, from the send's
//	          MailConfigActionArgs; a submission and a host's call carry none, which is no run and so untainted
//	          (§16.6's spend step 1). A same-uid process may submit as ur does (owner decision 47), and the gate still
//	          holds what is outward
//	effect    once the gate passes it, the send planned again, so a From that policy no longer grants at the spend is
//	          refused there, and then its delivery under the use's effect key: the member part deposits and the
//	          internet part queues at o/<h>/<effect_key> (mail_outbox.go), created only if absent, so a run the gate
//	          repeats after its queue committed (AU4) reads the receipt before keeping or depositing again. The outbox's
//	          Lookup, which the client registers on its gate for kind mail, reconciles a reserved use at a restart
//	answer    the delivery's MailSendResult; *ApprovalPendingError while a person's decision is awaited; a retry of a
//	          send whose use is done answers its send_id alone, the effect not run again (AU4)
//
// Nothing here logs an address, a subject or a byte of the text (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

// The mark a preview cut at its bound ends with, so an approver knows more follows.
const mailSendPreviewCutMark = "…"

// Runs a planned send through the gate (see the file header), answering its delivery once the gate passes it.
func (self *MailClient) gatedSend(ctx context.Context, plan *mailSendPlan, content *mailSendContent, actionArgs MailConfigActionArgs, replan func() (*mailSendPlan, error)) (*MailSendResult, error) {
	gate := plan.binding.Gate
	if gate == nil {
		return nil, ErrSidecarGateDenied
	}
	self.registerOutboxLookup(gate)
	var stored *StoredCanonicalAction
	var err error
	if content.draft != nil {
		stored, err = mailSendAction(content.draft, plan, self.sendSettings())
	} else {
		stored, err = self.mailSubmitAction(content.raw, plan)
	}
	if err != nil {
		return nil, err
	}
	effect := &mailSendEffect{client: self, replan: replan, content: content, approved: stored.Action}
	action := &SidecarAction{
		Kind:      SidecarActionMail,
		Canonical: stored.Bytes,
		Risk:      CanonicalActionRisk(stored, SidecarRiskNormal, actionArgs.Risk),
		RunId:     actionArgs.RunId,
		AgentId:   actionArgs.AgentId,
		Summary:   actionArgs.Summary,
		Effect:    effect,
	}
	testHookBarrier("mail.send.gate.before", "")
	err = gate.Authorize(ctx, action, actionArgs.Decision)
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
		// Earlier gate rows may hold a different id from the queue, or none after removal.
		if replay, err := self.priorSend(ctx, plan, content, outcome.effectKey); err != nil || replay != nil {
			return replay, err
		}
		if len(outcome.EffectRef) == 0 {
			return content.replayedSend(Id{}, nil)
		}
		sendId, err := IdFromBytes(outcome.EffectRef)
		if err != nil {
			return nil, fmt.Errorf("%w: the recorded outcome names no send", ErrMailSendUncertain)
		}
		return content.replayedSend(sendId, nil)
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

// The mail_send action of a submitted message (the file header's action row): its bytes hashed whole, its subject
// and first text part previewed.
func (self *MailClient) mailSubmitAction(message []byte, plan *mailSendPlan) (*StoredCanonicalAction, error) {
	parseSettings := self.settings.Ingest.Parse
	if parseSettings == nil {
		parseSettings = DefaultMailParseSettings()
	}
	parsed, err := MailParseMessage(bytes.NewReader(message), parseSettings)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMailSendInvalid, err)
	}
	bodySha256 := sha256.Sum256(message)
	return NewCanonicalAction(&protocol.CanonicalAction{
		Kind:       uint32(SidecarActionMail),
		Recipients: slices.Clone(plan.recipients),
		BodySha256: bodySha256[:],
		Preview:    mailSendPreview(&MailSendArgs{Subject: parsed.Subject, Text: parsed.Text}, self.sendSettings().PreviewMaxByteCount),
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

// The latest not_after among the decisions a use spends under, whence its o/ entry's retry window: zero under a
// standing grant or a send records approve, which spend none.
func mailSendApprovalNotAfter(ctx context.Context) time.Time {
	spend, ok := ApprovalSpendFromContext(ctx)
	if !ok {
		return time.Time{}
	}
	notAfter := time.Time{}
	for _, storedSigned := range spend.Decisions {
		decision, err := ParseStoredApprovalDecision(storedSigned)
		if err != nil || decision.Decision == nil {
			continue
		}
		if decisionNotAfter := time.UnixMilli(decision.Decision.GetNotAfterMillis()); notAfter.Before(decisionNotAfter) {
			notAfter = decisionNotAfter
		}
	}
	return notAfter
}

// A gated send's effect, which the gate runs once it passes the action (plan-MCP-effect-seam): the delivery of the
// content the action was built over under the use's effect key, its answer kept for gatedSend. Safe for concurrent
// use.
type mailSendEffect struct {
	client *MailClient
	// the send's plan made again at the spend, held to policy as it stands then
	replan   func() (*mailSendPlan, error)
	content  *mailSendContent
	approved *protocol.CanonicalAction

	stateLock sync.Mutex
	result    *MailSendResult
}

// See SidecarEffect. A standing grant has no ledger row and acquires its own fresh key. A reserved use records its
// plan first, so an error after that point can be reconciled against its checkpoint and queue.
func (self *mailSendEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	var checkpointName string
	if len(effectKey) == 0 {
		effectKey = mailSendStandingEffectKey()
	} else if len(effectKey) == mailEffectKeyByteCount {
		checkpointName = mailSendCheckpointName(effectKey)
		release, err := self.client.lockSendUse(ctx, checkpointName)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMailSendUncertain, err)
		}
		defer release()
	}
	plan, err := self.replan()
	if err == nil && (plan.fromAddress != self.approved.GetAlias() || !slices.Equal(plan.recipients, self.approved.GetRecipients())) {
		err = errors.New("the delivery addresses changed after approval")
	}
	if err != nil {
		if checkpointName != "" {
			if held, readErr := self.client.readSendCheckpoint(checkpointName); readErr != nil || held != nil {
				return nil, fmt.Errorf("%w: %w", ErrMailSendUncertain, err)
			}
		}
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	result, err := self.client.deliverSend(ctx, plan, self.content, effectKey, checkpointName)
	if errors.Is(err, ErrMailSendUncertain) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	// a use on a device or presence decision approves its internet recipients from now on (owner decision 280)
	if spend, ok := ApprovalSpendFromContext(ctx); ok {
		queued := []string{}
		for _, recipient := range result.Recipients {
			if recipient.Outcome == MailSendQueued {
				queued = append(queued, recipient.Address)
			}
		}
		if 0 < len(queued) {
			self.client.ApprovedRecipients().Record(ctx, plan.fromAddress, queued, spend.Decisions, spend.Action)
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.result = result
	}()
	// A sent copy alone does not prove delivery. A retry sees only this ref, without the first call's
	// per-recipient failures.
	if result.SendId != (Id{}) && (result.replayed || len(result.EffectKey) != 0 || len(result.Delivered()) != 0) {
		return result.SendId.Bytes(), nil
	}
	return nil, nil
}

// What the effect's run answered, nil where it did not run.
func (self *mailSendEffect) answer() *MailSendResult {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.result
}
