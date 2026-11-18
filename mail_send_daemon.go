//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's send methods (QD-853, owner decision 288; §5.8, §14.5, §15.10, §18.5, D-CORE-13, I-7, I-8, I-13):
// mail.check_send, mail.send_result and mail.send, what a remote-mode app's SidecarMail.CheckSend, GetSendResult and
// Send call, so a desktop app on ur daemon composes, sends and follows mail as a phone's app does in its own core.
// Each acts on the call's network (§5.8's network rule) through its Sidecar's MailClient:
//
//	check_send    the draft's fields in, the root's SmtpSendCheck out as JSON: per recipient domain the mode, the
//	              encoded bytes, the DATA cap, the expected delay in ms and the prediction, each enum by its number.
//	              A plain read that signs and sends nothing, so no Confirm (D-CORE-13). MailClient's check (MAIL-M9-01
//	              over SMTP-M9-08's SmtpSender.Check) is not on sidecar yet, so the default backend answers
//	              ErrMailSendUnavailable, which an app reads as MAIL_UNAVAILABLE, until it lands and the default
//	              takes it
//	send_result   a send_id in, the root's SmtpSendResult out as JSON: per recipient domain the outcome with what it
//	              carries, in or/'s MailOutcome names and numbers, and a send no device of the member wrote is
//	              ErrMailSendUnknown. A plain read too. A send's outcomes by send_id (MAIL-M9-02, from or/) are not on
//	              sidecar yet, so the default backend answers ErrMailSendUnavailable until they land
//	send          the draft's fields in, through MailClient.SubmitSend (mail_send_gate.go): a send to the network's own
//	              addresses deposits at once, and one naming any outside recipient waits on the daemon's gate as a
//	              submission waits (§15.10's step 1), answered with the approval it waits on and nothing kept or sent;
//	              once a person approves on another approval-capable device (`ur approve <id>`), the same draft sent
//	              again goes. Not a Confirm method: I-8's approval is the gate's, and the caller's word adds nothing
//
// Params are read strictly. A reply carries ids, the addresses the person named, outcome words and numbers, never a
// key or a token, which the reply walk holds it to (I-7). Addresses and subjects go only between the app and its
// daemon: nothing here logs one, and no refusal names one (I-13). ur daemon registers the methods (cli's
// daemon_mail_send.go); ur native-host relays none of them. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
)

// The methods.
const (
	// A remote-mode app's SidecarMail.CheckSend.
	DaemonMethodMailCheckSend = "mail.check_send"
	// A remote-mode app's SidecarMail.GetSendResult.
	DaemonMethodMailSendResult = "mail.send_result"
	// A remote-mode app's SidecarMail.Send.
	DaemonMethodMailSend = "mail.send"
)

// mail.check_send's and mail.send's params: a draft's fields, as MailSendArgs holds them, and the call's network.
type DaemonMailDraftParams struct {
	// The call's network, empty for .ur's or the only one (§5.8).
	Network string `json:"network,omitempty"`
	// One of the network's addresses this device may send as.
	From string `json:"from"`
	// The recipients, each an RFC 5321 address; at least one among the three.
	To  []string `json:"to,omitempty"`
	Cc  []string `json:"cc,omitempty"`
	Bcc []string `json:"bcc,omitempty"`
	// The subject and the plain-text body, UTF-8.
	Subject string `json:"subject,omitempty"`
	Text    string `json:"text,omitempty"`
}

// The draft as MailSendArgs, ErrMailSendInvalid where it names no From or no recipient: the rest of its shape is the
// backend's to hold it to, as Send holds a draft.
func (self *DaemonMailDraftParams) sendArgs() (*MailSendArgs, error) {
	if self.From == "" || len(self.To)+len(self.Cc)+len(self.Bcc) == 0 {
		return nil, fmt.Errorf("%w: a message needs a From and a recipient", ErrMailSendInvalid)
	}
	return &MailSendArgs{From: self.From, To: self.To, Cc: self.Cc, Bcc: self.Bcc, Subject: self.Subject, Text: self.Text}, nil
}

// mail.send_result's params.
type DaemonMailSendResultParams struct {
	// The call's network, empty for .ur's or the only one (§5.8).
	Network string `json:"network,omitempty"`
	// The send, as mail.send answered it.
	SendId *Id `json:"send_id"`
}

// mail.check_send's reply: SmtpSendCheck, an entry a recipient domain in the order each first appears among the
// recipients.
type DaemonMailSendCheckReply struct {
	Domains []*DaemonMailDomainCheck `json:"domains"`
}

// One recipient domain's prediction (SmtpDomainCheck).
type DaemonMailDomainCheck struct {
	Domain string `json:"domain"`
	// SmtpMode's number: 0 unknown, 1 bdat, 2 data.
	Mode uint32 `json:"mode"`
	// The message's encoded bytes, and the DATA cap, 0 where no host recorded one.
	ByteCount    uint64 `json:"byte_count"`
	CapByteCount uint64 `json:"cap_byte_count"`
	// ExpectedDelay, in milliseconds.
	ExpectedDelayMillis int64 `json:"expected_delay_ms"`
	// SmtpCheckPrediction's number: 1 ok, 2 too_large, 3 unknown.
	Prediction uint32 `json:"prediction"`
}

// mail.send_result's reply: SmtpSendResult's outcomes, an entry a recipient domain in the order each first appears
// among the recipients.
type DaemonMailSendResultReply struct {
	Domains []*DaemonMailDomainOutcome `json:"domains"`
}

// One recipient domain's outcome (SmtpDomainOutcome), in or/'s MailOutcome names and numbers.
type DaemonMailDomainOutcome struct {
	Domain string `json:"domain"`
	// SmtpMode's number.
	Mode uint32 `json:"mode"`
	// too_large: the message's encoded bytes and the DATA cap it passed.
	ByteCount    uint64 `json:"byte_count"`
	CapByteCount uint64 `json:"cap_byte_count"`
	// SmtpOutcomeKind's number: 1 sent, 2 queued, 3 deferred, 4 too_large, 5 refused, 6 tls_refused, 7 failed.
	Outcome uint32 `json:"outcome"`
	// refused: the MX's reply code.
	ReplyCode uint32 `json:"reply_code"`
	// deferred: how long the queue holds the message from the result's write, in milliseconds.
	RetryAfterMillis int64 `json:"retry_after_ms"`
	// The sending device's last write of this domain's result, in unix milliseconds; 0 for unknown.
	UpdateTimeMillis int64 `json:"update_time_ms"`
	// SmtpTlsLevel's number: 0 for none reached, 1 to 4 for TL1 to TL4.
	TlsLevel uint32 `json:"tls_level"`
}

// mail.send's reply: the send, or the approval it waits on.
type DaemonMailSendReply struct {
	// The send's id, its sent copy's and its Message-ID's left side (MailSendResult.SendId); nil while it waits.
	SendId *Id `json:"send_id,omitempty"`
	// The approval §5.4's gate holds the send for, which `ur approve` names; nil once the send went.
	ApprovalId *Id `json:"approval_id,omitempty"`
	// Each distinct recipient's outcome, To then Cc then Bcc; none for a retry the gate answered from its record.
	Recipients []*DaemonMailSendRecipient `json:"recipients,omitempty"`
	// The sent copy was kept in this device's member's mailbox.
	SentCopy bool `json:"sent_copy,omitempty"`
}

// One recipient's outcome of a send.
type DaemonMailSendRecipient struct {
	// As the caller named it, lowercase.
	Address string `json:"address"`
	// MailSendOutcome's word: delivered, unknown, member_refused, refused, internet_waits or failed.
	Outcome string `json:"outcome"`
}

// What the send methods act through, for the call's Sidecar. A nil Send takes the Sidecar's MailClient.SubmitSend. A
// nil Check or Result answers ErrMailSendUnavailable, naming what it waits on, until MailClient carries MAIL-M9-01's
// check and MAIL-M9-02's outcomes and the defaults here take them.
type DaemonMailSendBackends struct {
	// The check of the message a send of args would make (§14.5's Check).
	Check func(ctx context.Context, sidecar *Sidecar, args *MailSendArgs) (*SmtpSendCheck, error)
	// The outcomes of the send sendId names, ErrMailSendUnknown for none.
	Result func(ctx context.Context, sidecar *Sidecar, sendId Id) (*SmtpSendResult, error)
	// A host's submission of args, *ApprovalPendingError while the gate holds it.
	Send func(ctx context.Context, sidecar *Sidecar, args *MailSendArgs) (*MailSendResult, error)
}

// The daemon's send methods over backends: mail.check_send, mail.send_result and mail.send, each on its call's network
// and none a Confirm one (the file header). The daemon's composition registers them with RegisterMethod.
func DaemonMailSendMethods(backends *DaemonMailSendBackends) []*DaemonMethod {
	if backends == nil {
		backends = &DaemonMailSendBackends{}
	}
	checkOf := backends.Check
	if checkOf == nil {
		checkOf = func(ctx context.Context, sidecar *Sidecar, args *MailSendArgs) (*SmtpSendCheck, error) {
			return nil, fmt.Errorf("%w: check a send (MailClient's check over SmtpSender.Check)", ErrMailSendUnavailable)
		}
	}
	resultOf := backends.Result
	if resultOf == nil {
		resultOf = func(ctx context.Context, sidecar *Sidecar, sendId Id) (*SmtpSendResult, error) {
			return nil, fmt.Errorf("%w: read a send's result (MailClient's outcomes from or/)", ErrMailSendUnavailable)
		}
	}
	sendOf := backends.Send
	if sendOf == nil {
		sendOf = func(ctx context.Context, sidecar *Sidecar, args *MailSendArgs) (*MailSendResult, error) {
			client, err := sidecar.Mail()
			if err != nil {
				// no network or identity yet, which an app reads as unavailable
				return nil, fmt.Errorf("%w: %w", ErrMailUnbound, err)
			}
			return client.SubmitSend(ctx, args)
		}
	}
	// the params, strictly, a draft holding a From and a recipient
	decode := func(call *DaemonCall, params any) error {
		if err := decodeDaemonSocketParams(call, params); err != nil {
			return fmt.Errorf("%w: %w", ErrMailSendInvalid, err)
		}
		if call.Sidecar == nil {
			return ErrMailUnbound
		}
		return nil
	}
	draftOf := func(call *DaemonCall) (*MailSendArgs, error) {
		params := &DaemonMailDraftParams{}
		if err := decode(call, params); err != nil {
			return nil, err
		}
		return params.sendArgs()
	}
	return []*DaemonMethod{
		{
			Name:    DaemonMethodMailCheckSend,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				args, err := draftOf(call)
				if err != nil {
					return nil, err
				}
				check, err := checkOf(ctx, call.Sidecar, args)
				if err != nil {
					return nil, err
				}
				if check == nil {
					return nil, fmt.Errorf("%w: the check answered nothing", ErrMailSendUnavailable)
				}
				return newDaemonMailSendCheckReply(check), nil
			},
		},
		{
			Name:    DaemonMethodMailSendResult,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonMailSendResultParams{}
				if err := decode(call, params); err != nil {
					return nil, err
				}
				if params.SendId == nil || *params.SendId == (Id{}) {
					return nil, fmt.Errorf("%w: a send's result names its send_id", ErrMailSendInvalid)
				}
				result, err := resultOf(ctx, call.Sidecar, *params.SendId)
				if err != nil {
					return nil, err
				}
				if result == nil {
					return nil, ErrMailSendUnknown
				}
				return newDaemonMailSendResultReply(result), nil
			},
		},
		{
			Name:    DaemonMethodMailSend,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				args, err := draftOf(call)
				if err != nil {
					return nil, err
				}
				result, err := sendOf(ctx, call.Sidecar, args)
				var pending *ApprovalPendingError
				if errors.As(err, &pending) {
					approvalId := pending.ApprovalId
					return &DaemonMailSendReply{ApprovalId: &approvalId}, nil
				}
				if err != nil {
					return nil, err
				}
				if result == nil {
					return nil, fmt.Errorf("%w: the send answered nothing", ErrMailSendUncertain)
				}
				return newDaemonMailSendReply(result), nil
			},
		},
	}
}

// check's reply: its bound domains in order, an empty list for none.
func newDaemonMailSendCheckReply(check *SmtpSendCheck) *DaemonMailSendCheckReply {
	reply := &DaemonMailSendCheckReply{Domains: []*DaemonMailDomainCheck{}}
	for _, domain := range check.Domains {
		if domain == nil {
			continue
		}
		reply.Domains = append(reply.Domains, &DaemonMailDomainCheck{
			Domain:              domain.Domain,
			Mode:                uint32(domain.Mode),
			ByteCount:           domain.ByteCount,
			CapByteCount:        domain.CapByteCount,
			ExpectedDelayMillis: max(domain.ExpectedDelay.Milliseconds(), 0),
			Prediction:          uint32(domain.Prediction),
		})
	}
	return reply
}

// result's reply: its bound domains in order, an empty list for none. A time before the epoch reads unknown, as or/
// keeps none.
func newDaemonMailSendResultReply(result *SmtpSendResult) *DaemonMailSendResultReply {
	reply := &DaemonMailSendResultReply{Domains: []*DaemonMailDomainOutcome{}}
	for _, outcome := range result.Domains {
		if outcome == nil {
			continue
		}
		updateTimeMillis := int64(0)
		if !outcome.UpdateTime.IsZero() {
			updateTimeMillis = max(outcome.UpdateTime.UnixMilli(), 0)
		}
		reply.Domains = append(reply.Domains, &DaemonMailDomainOutcome{
			Domain:           outcome.Domain,
			Mode:             uint32(outcome.Mode),
			ByteCount:        outcome.ByteCount,
			CapByteCount:     outcome.CapByteCount,
			Outcome:          uint32(outcome.Outcome),
			ReplyCode:        outcome.ReplyCode,
			RetryAfterMillis: max(outcome.RetryAfter.Milliseconds(), 0),
			UpdateTimeMillis: updateTimeMillis,
			TlsLevel:         uint32(outcome.TlsLevel),
		})
	}
	return reply
}

// result's reply: the send and each recipient's outcome.
func newDaemonMailSendReply(result *MailSendResult) *DaemonMailSendReply {
	sendId := result.SendId
	reply := &DaemonMailSendReply{SendId: &sendId, SentCopy: result.SentCopy}
	for _, recipient := range result.Recipients {
		if recipient == nil {
			continue
		}
		reply.Recipients = append(reply.Recipients, &DaemonMailSendRecipient{Address: recipient.Address, Outcome: string(recipient.Outcome)})
	}
	return reply
}
