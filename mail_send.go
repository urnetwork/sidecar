//go:build !ios_extension

// MailClient.Send for same-network recipients (§15.10 steps 1 and 2, §15.8's same-network mail; R-MAIL-5, D-MAIL-8,
// I-5, I-8, X7; MAIL-M7-18): the data behind mail_send's W tier, which needs no approval, since mail to the network's
// own addresses crosses no edge (plan-MCP-approved-recipients: mail to members stays W).
//
//	from      one of this network's own addresses (its label's, its alias's or a scope's), held to
//	          mail:<alias>#send for this device (D-ACL-12) by the rule ingest holds the deposit's signer to, so a
//	          message the sender may not send as its From is refused here and, if forged, shown as outside mail there.
//	          A burner's From is a reply, which comes with M9's sending (§15.9), and a bounce or reverse alias is no
//	          From
//	split     each recipient is an address of this network or not. One that is not is outside mail, whose path is
//	          §14's smtpedge from M9 (MAIL-M9-01): here it is answered MailSendInternetWaits and nothing is sent to it,
//	          so a mixed list delivers its same-network part only. A same-network address is never routed to the
//	          internet path, whatever form the sender's alias has outside
//	resolve   a same-network recipient goes through the signed mailcfg (MailConfig.Resolve): unknown, burned and
//	          paused alike are MailSendUnknown; a known one's repo is judged by MailSendAuthority.MayDeposit
//	copy      the message, with its headers, is kept in this device's member's mailbox as an ordinary m/ and i/ entry
//	          labeled sent in f/ (plan-MAIL-small-readings#9), before any deposit, so a copy that cannot be kept sends
//	          nothing. A device with no mailbox it writes, an agent's or an unconsented device's, keeps none
//	deposit   then one deposit a repo (mail_send_local.go), each answered delivered once evs confirmed it, else failed.
//	          A Send is no outward action and keeps no effect key: sending again after a failure deposits again to
//	          the repos that took it, so a caller sends only the recipients that failed
//
// The message is plain text, UTF-8, quoted-printable, with From, To, Cc, Subject, Date and a Message-ID under the
// From's domain; a Bcc recipient is deposited to and named in no header. Nothing here logs an address, a subject or
// a byte of a message (I-13).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// What Send was given is out of shape: no From, no recipient, past a bound, a header line break, or an address
	// that does not parse. Names no address.
	ErrMailSendInvalid = errors.New("mail send: invalid")
	// The From is no address this device may send as: outside this network, a burner's before M9's replies, a bounce
	// or reverse alias, or one policy grants this device no mail:<alias>#send for.
	ErrMailSendFromRefused = errors.New("mail send: this device may not send as that From")
	// The sent copy could not be kept in this device's mailbox, so nothing was sent.
	ErrMailSendCopyFailed = errors.New("mail send: the sent copy was not kept, so nothing was sent")
)

// What became of one recipient of a Send.
type MailSendOutcome string

const (
	// Deposited to the recipient's repo, and evs confirmed it.
	MailSendDelivered MailSendOutcome = "delivered"
	// No record a receiver honors holds the address, or it is a burned or paused burner's (§15.9).
	MailSendUnknown MailSendOutcome = "unknown"
	// Another member's mailbox, which a device has no deposit right in until QD-136's cell is in §8.5's rows
	// (plan-MAIL-member-deposit's interim): refused, closed.
	MailSendMemberRefused MailSendOutcome = "member_refused"
	// Policy gives this device no deposit or write in the recipient's repo.
	MailSendNoDepositRight MailSendOutcome = "refused"
	// Outside this network: §14's sending, which comes with M9 (MAIL-M9-01). Nothing was sent to it.
	MailSendInternetWaits MailSendOutcome = "internet_waits"
	// The deposit did not commit: send to this recipient again.
	MailSendFailed MailSendOutcome = "failed"
)

// What a Send is held to (MAIL-M7-18). Every value must be positive.
type MailSendSettings struct {
	// The most distinct recipients one send names: a deposit's trailer holds at most ingest's 100
	// (MailIngestSettings.RecipientMaxCount, §20.4's mail_inbound_recipients), which a repo of all of them must pass.
	RecipientMaxCount int
	// The most bytes of an address: RFC 5321's 254 of a path's mailbox.
	AddressMaxByteCount int
	// The most bytes of the subject, before encoding: under RFC 5322's 998-byte line once encoded words fold.
	SubjectMaxByteCount int
	// The most bytes of the text, before encoding: far under a deposit's 50 MiB bound
	// (MailIngestSettings.DepositMaxByteCount), since quoted-printable may triple it.
	TextMaxByteCount int
}

// The one default.
func DefaultMailSendSettings() *MailSendSettings {
	return &MailSendSettings{
		RecipientMaxCount:   DefaultMailIngestSettings().RecipientMaxCount,
		AddressMaxByteCount: 254,
		SubjectMaxByteCount: 512,
		TextMaxByteCount:    8 * 1024 * 1024,
	}
}

// Whether every value is in range.
func (self *MailSendSettings) valid() bool {
	return self != nil && 0 < self.RecipientMaxCount && 0 < self.AddressMaxByteCount && 0 < self.SubjectMaxByteCount &&
		0 < self.TextMaxByteCount
}

// What Send sends.
type MailSendArgs struct {
	// One of this network's addresses this device may send as.
	From string
	// The recipients, each an RFC 5321 address; at least one among the three.
	To  []string
	Cc  []string
	Bcc []string
	// The subject and the plain-text body, UTF-8.
	Subject string
	Text    string
}

// One recipient's outcome.
type MailSendRecipient struct {
	// As the caller named it, lowercase.
	Address string
	Outcome MailSendOutcome
}

// What Send answers.
type MailSendResult struct {
	// The message's id: its sent copy's, and its Message-ID's left side.
	SendId Id
	// Each distinct recipient, in the order named, To then Cc then Bcc.
	Recipients []*MailSendRecipient
	// Whether the sent copy was kept in this device's member's mailbox.
	SentCopy bool
}

// The recipients Delivered, in order.
func (self *MailSendResult) Delivered() []string {
	delivered := []string{}
	for _, recipient := range self.Recipients {
		if recipient.Outcome == MailSendDelivered {
			delivered = append(delivered, recipient.Address)
		}
	}
	return delivered
}

// What a send reaches beyond MailClient's parts, where a test's parts stand in: the authority and the deposits.
type mailSendParts interface {
	sendAuthority() MailSendAuthority
	depositRepo(repoId Id) mailSendDepositRepo
}

// The send's settings, the defaults where none were set.
func (self *MailClient) sendSettings() *MailSendSettings {
	if self.settings.Send != nil {
		return self.settings.Send
	}
	return DefaultMailSendSettings()
}

// Sends a message to this network's own addresses (see the file header). An error is the whole send's: nothing was
// sent. Otherwise each recipient's outcome is in the answer, outside ones answered MailSendInternetWaits.
func (self *MailClient) Send(ctx context.Context, args *MailSendArgs) (*MailSendResult, error) {
	settings := self.sendSettings()
	if args == nil {
		return nil, fmt.Errorf("%w: no message", ErrMailSendInvalid)
	}
	binding, parts, _, err := self.state()
	if err != nil {
		return nil, err
	}
	row := self.networkRow()
	if binding.Network != nil {
		row = binding.Network()
	}
	if row.Root == "" || row.Label == "" {
		return nil, ErrMailConfigNoZone
	}
	recipients, err := mailSendRecipients(args, settings)
	if err != nil {
		return nil, err
	}
	if strings.ContainsAny(args.Subject, "\r\n") || settings.SubjectMaxByteCount < len(args.Subject) || !utf8.ValidString(args.Subject) ||
		settings.TextMaxByteCount < len(args.Text) || !utf8.ValidString(args.Text) {
		return nil, fmt.Errorf("%w: a subject or text out of shape", ErrMailSendInvalid)
	}

	authority := MailSendAuthority(&MailSendAclAuthority{
		Engine: binding.Engine,
		Root:   row.Root,
		OwnZone: func(zone MailZone) bool {
			return zone.OfNetwork(row)
		},
		Clock: self.clock,
	})
	depositRepo := func(repoId Id) mailSendDepositRepo {
		if binding.Evs == nil {
			return nil
		}
		if repo := binding.Evs.Repo(repoId); repo != nil {
			return repo
		}
		return nil
	}
	if sendParts, ok := parts.(mailSendParts); ok {
		authority = sendParts.sendAuthority()
		depositRepo = sendParts.depositRepo
	}

	// from: one of the network's own addresses, which policy lets this device send as
	from, err := ParseMailRecipient(row.Root, args.From)
	if err != nil || !from.Zone.OfNetwork(row) || (from.Kind != MailAddressKindName && from.Kind != MailAddressKindAdmin) {
		return nil, ErrMailSendFromRefused
	}
	fromAddress := from.Address()
	if !authority.MaySendAs(self.sidecarId, fromAddress) {
		return nil, ErrMailSendFromRefused
	}

	// split and resolve
	result := &MailSendResult{SendId: NewId()}
	targets := []*mailSendTarget{}
	targetIndexes := map[*MailSendRecipient]int{}
	var config *MailConfig
	for _, address := range recipients {
		recipient := &MailSendRecipient{Address: address, Outcome: MailSendInternetWaits}
		result.Recipients = append(result.Recipients, recipient)
		parsed, err := ParseMailRecipient(row.Root, address)
		if err != nil || !parsed.Zone.OfNetwork(row) {
			// outside this network: §14's path, from M9
			continue
		}
		if config == nil {
			if config, err = self.syncedConfig(ctx); err != nil {
				return nil, err
			}
		}
		lookup, err := config.Resolve(ctx, parsed)
		if err != nil {
			return nil, err
		}
		if !lookup.Known {
			recipient.Outcome = MailSendUnknown
			continue
		}
		if outcome := authority.MayDeposit(self.sidecarId, lookup.MailboxRepoId); outcome != MailSendDelivered {
			recipient.Outcome = outcome
			continue
		}
		index := slices.IndexFunc(targets, func(target *mailSendTarget) bool { return target.repoId == lookup.MailboxRepoId })
		if index < 0 {
			index = len(targets)
			targets = append(targets, &mailSendTarget{repoId: lookup.MailboxRepoId})
		}
		targets[index].recipients = append(targets[index].recipients, parsed.Address())
		targetIndexes[recipient] = index
	}
	if len(targets) == 0 {
		// nothing to deposit: no copy is kept of a message that went nowhere
		return result, nil
	}

	now := self.clock.Now()
	message, err := mailSendBuildMessage(args, fromAddress, from.Domain(), result.SendId, now)
	if err != nil {
		return nil, err
	}
	// copy: before any deposit, so one that cannot be kept sends nothing
	if mailboxId, err := self.mailboxId(); err == nil && authority.Writes(self.sidecarId, mailboxId) {
		if err := self.keepSentCopy(ctx, parts.store(mailboxId), result.SendId, message, fromAddress, now); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMailSendCopyFailed, err)
		}
		result.SentCopy = true
	}
	outcomes := mailSendDeposit(ctx, depositRepo, message, fromAddress, targets)
	for recipient, index := range targetIndexes {
		recipient.Outcome = outcomes[index]
	}
	return result, nil
}

// The distinct recipients of args, lowercase, To then Cc then Bcc, each parsing as a bare RFC 5322 address, within
// the settings' bounds.
func mailSendRecipients(args *MailSendArgs, settings *MailSendSettings) ([]string, error) {
	recipients := []string{}
	for _, list := range [][]string{args.To, args.Cc, args.Bcc} {
		for _, address := range list {
			address = dnsAsciiLower(strings.TrimSpace(address))
			if address == "" || settings.AddressMaxByteCount < len(address) || strings.ContainsAny(address, "\r\n<>,") {
				return nil, fmt.Errorf("%w: a recipient out of shape", ErrMailSendInvalid)
			}
			parsed, err := mail.ParseAddress(address)
			if err != nil || parsed.Address != address || parsed.Name != "" {
				return nil, fmt.Errorf("%w: a recipient that is no address", ErrMailSendInvalid)
			}
			if !slices.Contains(recipients, address) {
				recipients = append(recipients, address)
			}
		}
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%w: no recipient", ErrMailSendInvalid)
	}
	if settings.RecipientMaxCount < len(recipients) {
		return nil, fmt.Errorf("%w: past %d recipients", ErrMailSendInvalid, settings.RecipientMaxCount)
	}
	return recipients, nil
}

// The message a send deposits and keeps: plain text, UTF-8, quoted-printable, CRLF lines (see the file header).
func mailSendBuildMessage(args *MailSendArgs, fromAddress string, fromDomain string, sendId Id, now time.Time) ([]byte, error) {
	lowerAll := func(addresses []string) []string {
		lowered := []string{}
		for _, address := range addresses {
			if address = dnsAsciiLower(strings.TrimSpace(address)); address != "" && !slices.Contains(lowered, address) {
				lowered = append(lowered, address)
			}
		}
		return lowered
	}
	message := &bytes.Buffer{}
	header := func(name string, value string) {
		message.WriteString(name)
		message.WriteString(": ")
		message.WriteString(value)
		message.WriteString("\r\n")
	}
	header("From", fromAddress)
	if to := lowerAll(args.To); 0 < len(to) {
		header("To", strings.Join(to, ", "))
	}
	if cc := lowerAll(args.Cc); 0 < len(cc) {
		header("Cc", strings.Join(cc, ", "))
	}
	if args.Subject != "" {
		header("Subject", mime.QEncoding.Encode("utf-8", args.Subject))
	}
	header("Date", now.UTC().Format(time.RFC1123Z))
	header("Message-ID", "<"+strings.ToLower(sendId.String())+"@"+fromDomain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	message.WriteString("\r\n")
	// lines end CRLF before encoding, so the encoder keeps them as hard breaks
	text := strings.ReplaceAll(strings.ReplaceAll(args.Text, "\r\n", "\n"), "\r", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n")
	writer := quotedprintable.NewWriter(message)
	if _, err := writer.Write([]byte(text)); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if !bytes.HasSuffix(message.Bytes(), []byte("\r\n")) {
		message.WriteString("\r\n")
	}
	return message.Bytes(), nil
}

// Keeps message as the send's copy in store, this device's member's mailbox: its m/ file and i/ row in one push, then
// the label sent in f/ (plan-MAIL-small-readings#9). The row's address is the From, the address it belongs to here.
func (self *MailClient) keepSentCopy(ctx context.Context, store mailStore, sendId Id, message []byte, fromAddress string, now time.Time) error {
	parseSettings := self.settings.Ingest.Parse
	if parseSettings == nil {
		parseSettings = DefaultMailParseSettings()
	}
	parsed, err := MailParseMessage(bytes.NewReader(message), parseSettings)
	if err != nil {
		return err
	}
	nowMillis := uint64(max(now.UnixMilli(), 0))
	entry, err := MailBuildIndexEntry(&MailIndexEntryInput{
		Id:             sendId,
		Deposit:        &protocol.MailDeposit{Version: mailFormatVersion, MailFrom: []byte(fromAddress), Recipients: []string{fromAddress}},
		PushTimeMillis: nowMillis,
		ByteCount:      uint64(len(message)),
		Parsed:         parsed,
	})
	if err != nil {
		return err
	}
	month := MailYearMonthOf(entry.GetTime())
	messagePath := MailMessagePath(month, sendId)
	testHookBarrier("mail.send.copy.before", "")
	_, err = NewMailIndexWriter(store, self.settings.Store).Append(ctx, entry, &mailStoreWrite{Path: messagePath, Content: message})
	testHookBarrier("mail.send.copy.after", "")
	if err != nil {
		return err
	}
	_, err = NewMailFlagWriter(store, NewMailHlc(self.clock), self.sidecarId, self.settings.Store).Apply(ctx, []*MailFlagChange{{
		Month: month, MessageId: sendId, Kind: protocol.MailFlagKind_MAIL_FLAG_LABEL, Set: true, Label: MailLabelSent,
	}})
	return err
}
