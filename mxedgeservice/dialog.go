// The pre-TLS dialog on TCP 25 (D-MAIL-2, §15.4), the one thing mxedge says in the clear: a banner,
// EHLO and HELO, QUIT, STARTTLS, and refusals of everything else. It is a state machine that does no
// I/O, so FuzzMxDialog drives it directly: bytes in, the reply to write and the next step out.
//
// The trap is the CVE-2011-0411 class, where bytes queued behind STARTTLS are read as commands once TLS
// is up. Lines are taken one at a time and STARTTLS is answered only with nothing behind it in the
// buffer, so no byte a sender wrote before its 220 can reach what follows. service.go then waits a
// moment for a byte still on its way, which this machine cannot see.
//
// No reply holds a byte a sender sent, so nothing here can be made to echo. Not safe for concurrent
// use: one session owns each dialog.

package mxedgeservice

import (
	"bytes"
	"fmt"
)

// §15.4's limits. connect's own are unexported (connect/ip_smtp_policy.go:29-30), so they are restated
// here as the protocol constants they are.
const (
	// All a sender may send before TLS.
	mxDialogMaxByteCount = 2048
	// A command line without its CRLF: RFC 5321's 512 with the CRLF.
	mxDialogMaxLineByteCount = 510
	// RFC 5321 §4.5.3.1.2's longest domain, which EHLO and HELO carry.
	mxEhloNameMaxByteCount = 255
)

// The replies that name nothing of this host. Reading 6 gives 502 to what §15.4 does not name. Syntax
// errors in the commands it does name get RFC 5321's and RFC 3207's 501.
const (
	mxReplyStartTls    = "220 2.0.0 Ready to start TLS\r\n"
	mxReplyQuit        = "221 2.0.0 Bye\r\n"
	mxReplyRetry       = "451 4.7.0 TLS required, try again later\r\n"
	mxReplySyntax      = "501 5.5.4 Syntax error\r\n"
	mxReplyUnknown     = "502 5.5.1 Command not implemented\r\n"
	mxReplyBadSequence = "503 5.5.1 Bad sequence of commands\r\n"
)

// What to do after a Receive.
type mxDialogStep int

const (
	// Write the reply and read on.
	mxDialogStepRead mxDialogStep = iota + 1
	// Write the reply, whose last line is STARTTLS's 220, and hand over: the next byte is TLS. Only
	// a STARTTLS line with nothing behind it gives this step.
	mxDialogStepTls
	// Write the reply, then close: the sender said QUIT.
	mxDialogStepQuit
	// Write the reply, then close: the sender passed a limit or broke a line.
	mxDialogStepClose
	// Reset the connection, writing nothing: a byte came behind STARTTLS.
	mxDialogStepReset
)

// The replies that name this host, built once from settings.
type mxDialogReplies struct {
	banner         []byte
	bannerRefused  []byte
	ehlo           []byte
	helo           []byte
	mustStartTls   []byte
	overCap        []byte
	serviceClosing []byte
}

// Settings have passed validate, so nothing here can carry a CR or LF into a reply.
func newMxDialogReplies(settings *MxEdgeSettings) *mxDialogReplies {
	hostName := settings.BannerHostName
	return &mxDialogReplies{
		banner:        fmt.Appendf(nil, "220 %s ESMTP\r\n", hostName),
		bannerRefused: fmt.Appendf(nil, "554 5.7.1 %s Service refused\r\n", hostName),
		// no PIPELINING: a sender must wait for each reply, so STARTTLS is answered alone
		ehlo:           fmt.Appendf(nil, "250-%s\r\n250-ENHANCEDSTATUSCODES\r\n250 STARTTLS\r\n", hostName),
		helo:           fmt.Appendf(nil, "250 %s\r\n", hostName),
		mustStartTls:   fmt.Appendf(nil, "530 5.7.0 Must issue a STARTTLS command first, see %s\r\n", settings.DeviationUrl),
		overCap:        fmt.Appendf(nil, "421 4.7.0 %s Too many sessions, try again later\r\n", hostName),
		serviceClosing: fmt.Appendf(nil, "421 4.3.2 %s Service closing, try again later\r\n", hostName),
	}
}

// One session's dialog.
type mxDialog struct {
	replies *mxDialogReplies
	// Whether a plaintext transaction gets 451 rather than 530. It may do I/O, and Receive asks it
	// at most once a session, the first time a sender tries one.
	askRecent func() bool
	// Answered 554 at the banner, so only QUIT does anything (RFC 5321 §3.1).
	bannerRefused bool

	recentAsked bool
	recent      bool
	// Every byte received, in order: the limit fits the buffer, so it never moves or grows, and a
	// dialog's memory is this array whatever a sender does.
	buffer    [mxDialogMaxByteCount]byte
	byteCount int
	// Where the first line not yet answered starts.
	lineStart int
	// The last EHLO or HELO name, for MailIngress. Never logged (I-13).
	ehloName string
	finished bool
}

// A dialog at its start, before the banner.
func newMxDialog(replies *mxDialogReplies, askRecent func() bool, bannerRefused bool) *mxDialog {
	return &mxDialog{
		replies:       replies,
		askRecent:     askRecent,
		bannerRefused: bannerRefused,
	}
}

// What opens the session.
func (self *mxDialog) Banner() []byte {
	if self.bannerRefused {
		return self.replies.bannerRefused
	}
	return self.replies.banner
}

// Takes one read's bytes. Lines complete in data are answered in order, and a line left unfinished
// waits for the next call. A byte past the limit is never looked at: what comes before it is answered,
// then the session closes. After any step but mxDialogStepRead the dialog is over, and a further call
// resets and writes nothing, so a caller's mistake cannot reach TLS.
func (self *mxDialog) Receive(data []byte) (reply []byte, step mxDialogStep) {
	if self.finished {
		return nil, mxDialogStepReset
	}
	takenByteCount := min(len(data), mxDialogMaxByteCount-self.byteCount)
	overLimit := takenByteCount < len(data)
	copy(self.buffer[self.byteCount:], data[:takenByteCount])
	self.byteCount += takenByteCount

	finish := func(step mxDialogStep) ([]byte, mxDialogStep) {
		self.finished = true
		return reply, step
	}
	for {
		unread := self.buffer[self.lineStart:self.byteCount]
		lineByteCount, complete, valid := mxDialogNextLine(unread)
		if !valid {
			return finish(mxDialogStepClose)
		}
		if !complete {
			if overLimit {
				return finish(mxDialogStepClose)
			}
			return reply, mxDialogStepRead
		}
		line := unread[:lineByteCount]
		self.lineStart += lineByteCount + len("\r\n")
		verb, argument := mxDialogVerbOf(line)

		if self.bannerRefused && verb != mxDialogVerbQuit {
			reply = append(reply, mxReplyBadSequence...)
			continue
		}
		switch verb {
		case mxDialogVerbEhlo, mxDialogVerbHelo:
			ehloName, ok := mxEhloNameOf(argument)
			if !ok {
				reply = append(reply, mxReplySyntax...)
				continue
			}
			self.ehloName = ehloName
			if verb == mxDialogVerbEhlo {
				reply = append(reply, self.replies.ehlo...)
			} else {
				reply = append(reply, self.replies.helo...)
			}
		case mxDialogVerbStartTls:
			if !mxDialogNoArgument(argument) {
				reply = append(reply, mxReplySyntax...)
				continue
			}
			if self.lineStart != self.byteCount || overLimit {
				reply = nil
				return finish(mxDialogStepReset)
			}
			reply = append(reply, mxReplyStartTls...)
			return finish(mxDialogStepTls)
		case mxDialogVerbQuit:
			if !mxDialogNoArgument(argument) {
				reply = append(reply, mxReplySyntax...)
				continue
			}
			reply = append(reply, mxReplyQuit...)
			return finish(mxDialogStepQuit)
		case mxDialogVerbTransaction:
			// one session asks once, so a run of refused commands costs one answer, not one each
			if !self.recentAsked {
				self.recentAsked = true
				self.recent = self.askRecent()
			}
			if self.recent {
				reply = append(reply, mxReplyRetry...)
			} else {
				reply = append(reply, self.replies.mustStartTls...)
			}
		default:
			reply = append(reply, mxReplyUnknown...)
		}
	}
}

// The first line of unread, by RFC 5321's CRLF and nothing else. complete says one is there, of
// byteCount bytes before its CRLF. valid is false for what no more bytes can mend: a bare CR or LF,
// which connect refuses too, or more than a line's limit. A CR at the very end may yet become a CRLF,
// so it waits.
func mxDialogNextLine(unread []byte) (byteCount int, complete bool, valid bool) {
	end := bytes.IndexAny(unread, "\r\n")
	switch {
	case end < 0:
		return 0, false, len(unread) <= mxDialogMaxLineByteCount
	case unread[end] == '\n':
		return 0, false, false
	case end+1 == len(unread):
		return 0, false, end <= mxDialogMaxLineByteCount
	case unread[end+1] != '\n':
		return 0, false, false
	}
	return end, true, end <= mxDialogMaxLineByteCount
}

// What a line asks for.
type mxDialogVerb int

const (
	// Anything §15.4 does not name.
	mxDialogVerbOther mxDialogVerb = iota
	mxDialogVerbEhlo
	mxDialogVerbHelo
	mxDialogVerbStartTls
	mxDialogVerbQuit
	// MAIL, RCPT, DATA or BDAT.
	mxDialogVerbTransaction
)

// A line's verb and what follows the first space or tab.
func mxDialogVerbOf(line []byte) (verb mxDialogVerb, argument []byte) {
	name := line
	if end := bytes.IndexAny(line, " \t"); 0 <= end {
		name, argument = line[:end], line[end+1:]
	}
	switch {
	case mxDialogNameIs(name, "EHLO"):
		return mxDialogVerbEhlo, argument
	case mxDialogNameIs(name, "HELO"):
		return mxDialogVerbHelo, argument
	case mxDialogNameIs(name, "STARTTLS"):
		return mxDialogVerbStartTls, argument
	case mxDialogNameIs(name, "QUIT"):
		return mxDialogVerbQuit, argument
	case mxDialogNameIs(name, "MAIL"), mxDialogNameIs(name, "RCPT"),
		mxDialogNameIs(name, "DATA"), mxDialogNameIs(name, "BDAT"):
		return mxDialogVerbTransaction, argument
	}
	return mxDialogVerbOther, argument
}

// Whether name is upperName in any ASCII case. Not bytes.EqualFold: that folds Unicode, so it would
// take the two bytes of U+017F for an S and read a command the sender's MTA never sent.
func mxDialogNameIs(name []byte, upperName string) bool {
	if len(name) != len(upperName) {
		return false
	}
	for i, c := range name {
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c != upperName[i] {
			return false
		}
	}
	return true
}

// Whether only spaces and tabs follow the verb, as RFC 3207 §4 and RFC 5321 §4.1.1.10 ask.
func mxDialogNoArgument(argument []byte) bool {
	return len(bytes.Trim(argument, " \t")) == 0
}

// The name EHLO or HELO gave: the first word of argument, which must be printable ASCII within RFC
// 5321's limit, since MailIngress carries it on and a proto string must be valid UTF-8. What follows
// that word is ignored, as MTAs do.
func mxEhloNameOf(argument []byte) (string, bool) {
	name := bytes.TrimLeft(argument, " \t")
	if end := bytes.IndexAny(name, " \t"); 0 <= end {
		name = name[:end]
	}
	if len(name) == 0 || mxEhloNameMaxByteCount < len(name) {
		return "", false
	}
	for _, c := range name {
		if c <= ' ' || 0x7f <= c {
			return "", false
		}
	}
	return string(name), true
}
