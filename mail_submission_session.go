//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// One submission session (mail_submission.go's auth, rcpt and data rows; MAIL-M9-01), on go-smtp's Session and
// AuthSession, and what it submits through: MailClient.SubmitMessage, a mail client's message taken through §15.10's
// steps as Send takes a draft, and MailClient.CheckSubmitRecipient, the RCPT check. No reply names an address, a
// subject or a credential, and nothing here logs one (I-7, I-13).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// A same-network recipient no honored record holds, refused at RCPT.
var ErrMailSubmitUnknownRecipient = errors.New("mail submission: no such recipient here")

// The session's replies, as their codes say (RFC 3463, RFC 4954).
var (
	mailSubmitReplyAuthRequired = &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "Authentication required"}
	mailSubmitReplyNoMail       = &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "MAIL first"}
	mailSubmitReplyTooMany      = &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "Too many recipients"}
	mailSubmitReplyBadAddress   = &smtp.SMTPError{Code: 501, EnhancedCode: smtp.EnhancedCode{5, 1, 3}, Message: "Bad recipient address syntax"}
	mailSubmitReplyUnknown      = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "No such recipient here"}
	mailSubmitReplyTryLater     = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Try again later"}
	mailSubmitReplyFromRefused  = &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "This account may not send as that From"}
	mailSubmitReplyInvalid      = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: "The message is not one this server sends"}
	mailSubmitReplyRefused      = &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Refused"}
	mailSubmitReplySomeRefused  = &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Some recipients were refused"}
)

// One session. Its methods run on the connection's goroutine, one at a time, but Logout may race a closing server,
// so its state is guarded.
type mailSubmissionSession struct {
	server *MailSubmissionServer
	client netip.Addr

	stateLock  sync.Mutex
	account    *MailSubmissionAccount
	mailTaken  bool
	recipients []string
	loggedOut  bool
}

// A session on conn.
func newMailSubmissionSession(server *MailSubmissionServer, conn *smtp.Conn) *mailSubmissionSession {
	return &mailSubmissionSession{server: server, client: mailImapClient(conn.Conn())}
}

var (
	_ smtp.Session     = (*mailSubmissionSession)(nil)
	_ smtp.AuthSession = (*mailSubmissionSession)(nil)
)

// PLAIN alone: the one credential is a user name and a secret.
func (self *mailSubmissionSession) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

// The local credential's check (mail_local_credential.go): the matching secret names the session's network, and a
// refusal answers only after the client's cost has passed.
func (self *mailSubmissionSession) Auth(mechanism string) (sasl.Server, error) {
	if mechanism != sasl.Plain {
		return nil, smtp.ErrAuthUnknownMechanism
	}
	return sasl.NewPlainServer(func(identity string, username string, password string) error {
		if identity != "" && identity != username {
			return smtp.ErrAuthFailed
		}
		accounts := self.server.accounts()
		credentials := make([]*MailLocalCredential, len(accounts))
		for index, account := range accounts {
			credentials[index] = account.Credential
		}
		matched := self.server.login.Check(self.server.ctx, self.client, username, password, credentials)
		if matched < 0 {
			return smtp.ErrAuthFailed
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.account = accounts[matched]
		return nil
	}), nil
}

// The session's account, nil before AUTH.
func (self *mailSubmissionSession) authenticated() *MailSubmissionAccount {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.account
}

// Starts a transaction. The envelope's reverse path is not the message's sender and is not used (the server's data
// row), so it is not read.
func (self *mailSubmissionSession) Mail(from string, opts *smtp.MailOptions) error {
	if self.authenticated() == nil {
		return mailSubmitReplyAuthRequired
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.mailTaken = true
	self.recipients = nil
	return nil
}

// Names one recipient (the server's rcpt row).
func (self *mailSubmissionSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	account := self.authenticated()
	if account == nil {
		return mailSubmitReplyAuthRequired
	}
	mailTaken, recipientCount := func() (bool, int) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.mailTaken, len(self.recipients)
	}()
	if !mailTaken {
		return mailSubmitReplyNoMail
	}
	if self.server.settings.RecipientMaxCount <= recipientCount {
		return mailSubmitReplyTooMany
	}
	address := dnsAsciiLower(strings.TrimSpace(to))
	parsed, err := mail.ParseAddress(address)
	if err != nil || parsed.Address != address || parsed.Name != "" || strings.ContainsAny(address, "\r\n<>,") {
		return mailSubmitReplyBadAddress
	}
	ctx, done := self.server.submitContext()
	defer done()
	if err := account.Submitter.CheckSubmitRecipient(ctx, address); err != nil {
		if errors.Is(err, ErrMailSubmitUnknownRecipient) {
			return mailSubmitReplyUnknown
		}
		return mailSubmitReplyTryLater
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !slices.Contains(self.recipients, address) {
		self.recipients = append(self.recipients, address)
	}
	return nil
}

// Takes the message and sends it (the server's data row).
func (self *mailSubmissionSession) Data(reader io.Reader) error {
	account := self.authenticated()
	if account == nil {
		return mailSubmitReplyAuthRequired
	}
	recipients := func() []string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.Clone(self.recipients)
	}()
	// go-smtp's reader stops at MaxMessageBytes with its own 552, which it answers itself
	message, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if len(recipients) == 0 {
		return mailSubmitReplyNoMail
	}
	ctx, done := self.server.submitContext()
	defer done()
	result, err := account.Submitter.SubmitMessage(ctx, &MailSubmitArgs{Message: message, Recipients: recipients})
	var pending *ApprovalPendingError
	switch {
	case errors.As(err, &pending):
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 7, 1},
			Message:      fmt.Sprintf("Held for approval %s: run ur approve %s, then send again", pending.ApprovalId, pending.ApprovalId),
		}
	case errors.Is(err, ErrMailSendFromRefused):
		return mailSubmitReplyFromRefused
	case errors.Is(err, ErrMailSendInvalid):
		return mailSubmitReplyInvalid
	case errors.Is(err, ErrMailSendUncertain), errors.Is(err, ErrMailSendCopyFailed):
		return mailSubmitReplyTryLater
	case err != nil:
		// the gate's refusal, or the effect's at the spend
		if errors.Is(err, ErrSidecarEffectNotDone) && !errors.Is(err, ErrMailSendFromRefused) && !errors.Is(err, ErrMailSendInvalid) {
			return mailSubmitReplyTryLater
		}
		return mailSubmitReplyRefused
	}
	refused := false
	for _, recipient := range result.Recipients {
		switch recipient.Outcome {
		case MailSendDelivered, MailSendQueued:
		case MailSendFailed:
			return mailSubmitReplyTryLater
		default:
			refused = true
		}
	}
	if refused {
		return mailSubmitReplySomeRefused
	}
	return nil
}

// Discards the transaction.
func (self *mailSubmissionSession) Reset() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.mailTaken = false
	self.recipients = nil
}

// The session's end, giving its place back once.
func (self *mailSubmissionSession) Logout() error {
	loggedOut := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		loggedOut := self.loggedOut
		self.loggedOut = true
		return loggedOut
	}()
	if !loggedOut {
		self.server.sessionClosed()
	}
	return nil
}

// What SubmitMessage sends.
type MailSubmitArgs struct {
	// The message as its client wrote it, RFC 5322.
	Message []byte
	// The envelope's recipients, RCPT TO's addresses: who gets it, Bcc included.
	Recipients []string
}

// The one From address of message's header, lowercase: ErrMailSendInvalid where it names none or several.
func mailSubmitFrom(message []byte) (string, error) {
	parsed, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		return "", fmt.Errorf("%w: no header", ErrMailSendInvalid)
	}
	addresses, err := parsed.Header.AddressList("From")
	if err != nil || len(addresses) != 1 {
		return "", fmt.Errorf("%w: not one From", ErrMailSendInvalid)
	}
	return dnsAsciiLower(addresses[0].Address), nil
}

// Sends a submitted message to its envelope's recipients through §15.10's steps (mail_send.go): its From held to
// mail:<alias>#send, its member part deposited, its internet part queued at o/ once the gate passes the send. A
// submission is no run, so untainted (§16.6's spend step 1).
func (self *MailClient) SubmitMessage(ctx context.Context, args *MailSubmitArgs) (*MailSendResult, error) {
	settings := self.sendSettings()
	if args == nil || len(args.Message) == 0 || settings.MessageMaxByteCount < len(args.Message) {
		return nil, fmt.Errorf("%w: no message, or one past its bound", ErrMailSendInvalid)
	}
	recipients, err := mailSendAddressList(settings, args.Recipients)
	if err != nil {
		return nil, err
	}
	from, err := mailSubmitFrom(args.Message)
	if err != nil {
		return nil, err
	}
	plan, err := self.planSendFrom(from, recipients, "")
	if err != nil {
		return nil, err
	}
	content := &mailSendContent{raw: bytes.Clone(args.Message)}
	return self.sendPlanned(ctx, plan, content, MailConfigActionArgs{}, func() (*mailSendPlan, error) {
		return self.planSendFrom(from, recipients, "")
	})
}

// Whether a submission may name recipient (mail_submission.go's rcpt row): an internet address is taken, and a
// same-network one only where a record a receiver honors holds it.
func (self *MailClient) CheckSubmitRecipient(ctx context.Context, recipient string) error {
	binding, _, _, err := self.state()
	if err != nil {
		return err
	}
	row := self.networkRow()
	if binding.Network != nil {
		row = binding.Network()
	}
	parsed, own := mailSendOwnRecipient(row, recipient)
	if !own {
		return nil
	}
	config, err := self.syncedConfig(ctx)
	if err != nil {
		return err
	}
	lookup, err := config.Resolve(ctx, parsed)
	if err != nil {
		return err
	}
	if !lookup.Known {
		return ErrMailSubmitUnknownRecipient
	}
	return nil
}
