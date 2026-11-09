// A platform session after TLS: go-smtp's backend and session for the platform role (platform.go). go-smtp
// parses the commands and enforces SIZE, so what is here is who the listener answers for, what a
// message may cost this process, and the hand to PlatformIntake.
//
// A recipient is checked at RCPT: one the listener does not answer for gets 550 5.1.1, and with no
// intake, or the mxedge gate closed, a recipient it does answer for gets 451 4.3.0, so nothing is read.
// At DATA or BDAT the message is read into memory, up to PlatformMessageByteCount (552 5.3.4 past it)
// and within the process's PlatformBufferByteCount (452 4.3.1), then handed to the intake once per
// recipient. Any intake error answers 451 4.3.0 for the whole message, and the sender's retry repeats it
// for every recipient, which the intake's own once-per-report rule absorbs for aggregates. A message
// whose every recipient is role mail the intake left unread answers 550 5.7.1 (plan-ABUSE-auto-reply);
// any other ends 250.
//
// Nothing here keeps the sender's address, logs a line naming a recipient or a byte of a message, or
// returns an error whose text could reach the sender, since go-smtp writes a plain error's text.

package mxedgeservice

import (
	"errors"
	"io"

	"github.com/emersion/go-smtp"
)

// How much of a message one read takes, as the buffer grows. Not a bound: PlatformMessageByteCount and
// PlatformBufferByteCount are.
const mxPlatformReadByteCount = 64 * 1024

// How a recipient was answered.
const (
	mxPlatformRecipientResultTaken   = "taken"
	mxPlatformRecipientResultUnknown = "unknown"
	mxPlatformRecipientResultClosed  = "closed"
	mxPlatformRecipientResultTooMany = "too_many"
)

// How a message was answered.
const (
	// 250: the intake took it for every recipient, or for one at least that is not unread role mail.
	mxPlatformMessageResultTaken = "taken"
	// 550 5.7.1: role mail the intake left unread.
	mxPlatformMessageResultUnread = "unread"
	// 552 5.3.4: past PlatformMessageByteCount.
	mxPlatformMessageResultTooLarge = "too_large"
	// 452 4.3.1: past PlatformBufferByteCount.
	mxPlatformMessageResultBufferFull = "buffer_full"
	// 451 4.3.0: the intake did not finish, or the message did not arrive whole.
	mxPlatformMessageResultFailed = "failed"
)

// One session per connection, made at EHLO or HELO.
type mxPlatformBackend struct {
	platform *mxPlatform
}

// See smtp.Backend.
func (self *mxPlatformBackend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	return &mxPlatformSession{platform: self.platform}, nil
}

// One connection's transactions. go-smtp calls it from the connection's goroutine alone.
type mxPlatformSession struct {
	platform *mxPlatform
	// The transaction's recipients, lowercased. Memory only (§2.8 mx-4).
	recipients []string
}

// See smtp.Session.
func (self *mxPlatformSession) Reset() {
	self.recipients = nil
}

// See smtp.Session.
func (self *mxPlatformSession) Logout() error {
	self.recipients = nil
	return nil
}

// A transaction begins. The reverse path is not kept: the intake reads a report's own headers, and a
// role mail's reporter is no one this listener answers.
func (self *mxPlatformSession) Mail(from string, options *smtp.MailOptions) error {
	self.recipients = nil
	return nil
}

// See the file's comment.
func (self *mxPlatformSession) Rcpt(to string, options *smtp.RcptOptions) error {
	platform := self.platform
	metrics := platform.service.metrics
	recipient, ok := platform.recipients.take(to)
	if !ok {
		metrics.platformRecipients.Add(1, mxPlatformRecipientResultUnknown)
		return platform.replies.unknownRecipient
	}
	gateOpen := platform.service.deps.GateOpen != nil && platform.service.deps.GateOpen()
	if platform.intake == nil || !gateOpen {
		metrics.platformRecipients.Add(1, mxPlatformRecipientResultClosed)
		return platform.replies.noIntake
	}
	if platform.service.settings.PlatformRecipientCount <= len(self.recipients) {
		metrics.platformRecipients.Add(1, mxPlatformRecipientResultTooMany)
		return platform.replies.tooManyRecipient
	}
	self.recipients = append(self.recipients, recipient)
	metrics.platformRecipients.Add(1, mxPlatformRecipientResultTaken)
	return nil
}

// See the file's comment. go-smtp reads on to the end of the message after a refusal, so a sender
// always gets the one reply.
func (self *mxPlatformSession) Data(reader io.Reader) error {
	platform := self.platform
	metrics := platform.service.metrics
	raw, heldByteCount, result := self.read(reader)
	defer platform.buffers.release(heldByteCount)
	switch result {
	case mxPlatformMessageResultTooLarge:
		metrics.platformMessages.Add(1, result)
		return smtp.ErrDataTooLarge
	case mxPlatformMessageResultBufferFull:
		metrics.platformMessages.Add(1, result)
		return platform.replies.bufferFull
	case mxPlatformMessageResultFailed:
		metrics.platformMessages.Add(1, result)
		return platform.replies.retry
	}

	arrivalTime := platform.service.clock.Now()
	unreadCount := 0
	for _, recipient := range self.recipients {
		testHookBarrier("mxedge.platform_accept.before", "")
		outcome, err := platform.intake.Accept(platform.service.ctx, &PlatformMessage{
			Recipient:   recipient,
			ArrivalTime: arrivalTime,
			Raw:         raw,
		})
		testHookBarrier("mxedge.platform_accept.after", "")
		if err != nil {
			// the error may quote a statement or a name, so only the fact is logged
			platform.service.log.Info("[mxedge]a platform message could not be taken; the sender retries")
			metrics.platformMessages.Add(1, mxPlatformMessageResultFailed)
			return platform.replies.retry
		}
		if outcome == PlatformOutcomeUnread && platform.recipients.role(recipient) {
			unreadCount += 1
		}
	}
	if 0 < len(self.recipients) && unreadCount == len(self.recipients) {
		metrics.platformMessages.Add(1, mxPlatformMessageResultUnread)
		return platform.replies.unread
	}
	metrics.platformMessages.Add(1, mxPlatformMessageResultTaken)
	return nil
}

// Reads the message into one buffer, growing it as bytes come and holding each growth against the
// process's bound first. Answers the bytes, what is held for them, and a result word when the message
// cannot go on: too large, the process's buffers full, or a message that ended other than at its end.
func (self *mxPlatformSession) read(reader io.Reader) (raw []byte, heldByteCount int64, result string) {
	buffers := self.platform.buffers
	messageByteCount := self.platform.service.settings.PlatformMessageByteCount
	chunk := make([]byte, mxPlatformReadByteCount)
	for {
		byteCount, err := reader.Read(chunk)
		if 0 < byteCount {
			if cap(raw) < len(raw)+byteCount {
				// at most the cap and one read past it, which go-smtp refuses before this sees more
				grownCapacity := min(max(2*cap(raw), len(raw)+byteCount), messageByteCount+mxPlatformReadByteCount)
				grownCapacity = max(grownCapacity, len(raw)+byteCount)
				if !buffers.reserve(int64(grownCapacity - cap(raw))) {
					return nil, heldByteCount, mxPlatformMessageResultBufferFull
				}
				heldByteCount += int64(grownCapacity - cap(raw))
				grown := make([]byte, len(raw), grownCapacity)
				copy(grown, raw)
				raw = grown
			}
			raw = append(raw, chunk[:byteCount]...)
		}
		if errors.Is(err, io.EOF) {
			return raw, heldByteCount, ""
		}
		if errors.Is(err, smtp.ErrDataTooLarge) {
			return nil, heldByteCount, mxPlatformMessageResultTooLarge
		}
		if err != nil {
			return nil, heldByteCount, mxPlatformMessageResultFailed
		}
	}
}
