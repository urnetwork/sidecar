//go:build !sidecar_http && !ios_extension

// Forwarding (§15.10's forwarding, owner decision 53; R-MAIL-6, D-MAIL-14, I-8, I-9; MAIL-M9-04): a burner's mail goes
// on to one external address the member confirmed, and replies from that address go back through the burner.
//
//	confirm  one external address a mailbox, confirmed by a code of CodeDigitCount digits sent to it through §14:
//	         SetForward draws the code, keeps its hash in this device's sealed store, and sends it From
//	         forward@<blabel> of the first opted-in burner, a reply's send through the gate, since it is mail to an
//	         outside address (I-8); ConfirmForward takes the code within CodeLifetime and CodeAttemptMaxCount tries and
//	         writes the mailbox's signed forward entry, MailForward{address, burners, verified_time_ms}. An address
//	         under <root> is refused, so forwards never go back into URnetwork's own zones
//	forward  a reader that ingests mail to an opted-in burner forwards it only if it scores below the spam threshold
//	         with no DMARC fail as received, from the sealed evidence (D-MAIL-14), and never a message that carries
//	         X-UR-Forwarded, which stops loops. The forward is a new message From r-<token>@<blabel>.<net>.<root>
//	         (MailReverseAlias), To the confirmed address, the original's subject, references and body, with BURNER's
//	         header rules and then X-UR-Forwarded, queued at o/ for a prover host under a key derived from the
//	         message's id, so racing readers queue one, and signed under the burner's selector like a reply
//	relay    mail to r-<token> from the confirmed address, passing DMARC as received, is relayed From the burner to the
//	         original sender ra/ names, under a key derived from its id; mail from any other address, or failing
//	         DMARC, stays in the mailbox and is relayed nowhere
//	quota    each code, forward or relay is a connection, against the daily connection quota at smtpedge (owner
//	         decision 30)
//
// A forward or relay is the member's standing choice, made once with a person's approval of the code's send, so
// each runs with no approval of its own and an o/ entry with no approval window. Nothing here logs an address, a
// label or a byte of a message (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/mail"
	"slices"
	"strings"
	"time"

	cryptorand "crypto/rand"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The header a forward carries, and whose presence stops a message from being forwarded again.
const MailForwardedHeader = "X-UR-Forwarded"

// The sealed store's file holding a forwarding address's pending code.
const mailForwardPendingFileName = "forward-pending.json"

// The labels a forward's and a relay's effect keys are derived under.
const (
	mailForwardEffectKeyLabel = "urnetwork-sidecar-v1/mail-forward"
	mailRelayEffectKeyLabel   = "urnetwork-sidecar-v1/mail-relay"
)

var (
	// The address cannot take forwards: not an address, or one under the user root.
	ErrMailForwardAddressRefused = errors.New("mail forward: that address cannot take forwards")
	// A burner named is none of this member's live burners, or none was named.
	ErrMailForwardBurnerRefused = errors.New("mail forward: no such burner of this member's")
	// No code is pending, or the pending one is past its life or its tries.
	ErrMailForwardNoCode = errors.New("mail forward: no code is pending")
	// The code given is not the one sent. Names no code.
	ErrMailForwardCodeWrong = errors.New("mail forward: wrong code")
)

// The forwarder's settings, the defaults where none were set.
func (self *MailClient) forwardSettings() *MailForwardSettings {
	if self.settings.Forward != nil {
		return self.settings.Forward
	}
	return DefaultMailForwardSettings()
}

// What SetForward asks for.
type MailSetForwardArgs struct {
	// The external address forwards go to.
	Address string
	// The burners whose mail is forwarded, each its label or address: at least one, this member's, live.
	Burners []string
	// What the code's send carries to the gate (I-8).
	Action MailConfigActionArgs
}

// A code sent and waiting, as this device keeps it.
type mailForwardPending struct {
	Address string   `json:"address"`
	Burners []string `json:"burners"`
	// SHA-256 over Salt's bytes and the code's digits, hex
	CodeSha256 string `json:"code_sha256"`
	Salt       string `json:"salt"`
	SentMillis int64  `json:"sent_ms"`
	Attempts   int    `json:"attempts"`
}

// What SetForward answers: the address and burners pending, and when the code stops being good.
type MailForwardPending struct {
	Address   string
	Burners   []string
	ExpiresAt time.Time
	// The code's send, whose internet recipient answers queued once the gate passes it.
	Send *MailSendResult
}

// Whether address may take forwards: one addr-spec, under no part of root.
func mailForwardAddressAllowed(root string, address string) bool {
	parsed, err := mail.ParseAddress(address)
	if err != nil || parsed.Address != address || parsed.Name != "" {
		return false
	}
	_, domain, found := strings.Cut(address, "@")
	if !found || domain == "" {
		return false
	}
	root = canonicalNetworkLabelRoot(root)
	return domain != root && !strings.HasSuffix(domain, "."+root)
}

// The labels of burners, each this member's live burner, in order, at least one.
func (self *MailClient) forwardBurnerLabels(ctx context.Context, burners []string) ([]string, error) {
	if len(burners) == 0 {
		return nil, ErrMailForwardBurnerRefused
	}
	mine, err := self.Burners(ctx)
	if err != nil {
		return nil, err
	}
	labels := []string{}
	for _, burner := range burners {
		label, err := self.burnerLabelOf(burner)
		if err != nil {
			return nil, ErrMailForwardBurnerRefused
		}
		live := slices.ContainsFunc(mine, func(info *MailBurnerInfo) bool {
			return info.Label == label && info.State == protocol.MailBurnerState_MAIL_BURNER_LIVE
		})
		if !live {
			return nil, ErrMailForwardBurnerRefused
		}
		if !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
	}
	return labels, nil
}

// A uniform code of digitCount digits.
func newMailForwardCode(digitCount int) (string, error) {
	limit := big.NewInt(1)
	for range digitCount {
		limit.Mul(limit, big.NewInt(10))
	}
	number, err := cryptorand.Int(cryptorand.Reader, limit)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", digitCount, number), nil
}

// The pending code's hash under salt.
func mailForwardCodeSha256(salt []byte, code string) []byte {
	hash := sha256.New()
	hash.Write(salt)
	io.WriteString(hash, code)
	return hash.Sum(nil)
}

// Sets the mailbox's forwarding address, pending its code (see the file header's confirm row): the code is drawn and
// sent, and ConfirmForward takes it. *ApprovalPendingError while the code's send waits for a person's decision, with
// nothing kept; a SetForward again replaces a code still pending.
func (self *MailClient) SetForward(ctx context.Context, args *MailSetForwardArgs) (*MailForwardPending, error) {
	if args == nil {
		return nil, ErrMailForwardAddressRefused
	}
	row := self.networkRow()
	if binding, _, err := self.bound(); err == nil && binding.Network != nil {
		row = binding.Network()
	}
	address := dnsAsciiLower(strings.TrimSpace(args.Address))
	if !mailForwardAddressAllowed(row.Root, address) {
		return nil, ErrMailForwardAddressRefused
	}
	labels, err := self.forwardBurnerLabels(ctx, args.Burners)
	if err != nil {
		return nil, err
	}
	settings := self.forwardSettings()
	code, err := newMailForwardCode(settings.CodeDigitCount)
	if err != nil {
		return nil, err
	}
	testHookSecret("mail_forward_code", []byte(code))
	from := "forward@" + self.burnerDomain(labels[0])
	send, err := self.Reply(ctx, &MailReplyArgs{
		From:    from,
		To:      []string{address},
		Subject: "Your forwarding code",
		Text:    "Enter this code to forward mail to this address: " + code + "\n\nIf you did not ask for this, ignore this message.",
		Action:  args.Action,
	})
	if err != nil {
		return nil, err
	}
	salt := NewEvsRandomToken()
	now := self.clock.Now()
	pending := &mailForwardPending{
		Address:    address,
		Burners:    labels,
		CodeSha256: hex.EncodeToString(mailForwardCodeSha256(salt[:], code)),
		Salt:       hex.EncodeToString(salt[:]),
		SentMillis: now.UnixMilli(),
	}
	if err := self.putForwardPending(pending); err != nil {
		return nil, err
	}
	return &MailForwardPending{Address: address, Burners: labels, ExpiresAt: now.Add(settings.CodeLifetime), Send: send}, nil
}

// Keeps pending in the sealed store, replacing any before; nil removes it.
func (self *MailClient) putForwardPending(pending *mailForwardPending) error {
	if pending == nil {
		return self.store.Remove(mailForwardPendingFileName)
	}
	data, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(mailForwardPendingFileName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// The pending code, nil for none.
func (self *MailClient) forwardPending() (*mailForwardPending, error) {
	reader, err := self.store.Open(mailForwardPendingFileName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	pending := &mailForwardPending{}
	if err := json.Unmarshal(data, pending); err != nil {
		return nil, nil
	}
	return pending, nil
}

// The mailbox's forwarding as its signed entry holds it, nil for none.
func (self *MailClient) Forward(ctx context.Context) (*protocol.MailForward, error) {
	mailboxId, err := self.mailboxId()
	if err != nil {
		return nil, err
	}
	_, parts, err := self.bound()
	if err != nil {
		return nil, err
	}
	forward, _, err := mailForwardRead(ctx, parts.store(mailboxId), self.outboxSettings())
	return forward, err
}

// The forward entry in store and its version, nil and 0 for none.
func mailForwardRead(ctx context.Context, store mailStore, settings *MailOutboxSettings) (*protocol.MailForward, uint64, error) {
	content, version, err := store.Read(ctx, MailForwardPath, settings.ProverRecordMaxByteCount)
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	forward := &protocol.MailForward{}
	if err := proto.Unmarshal(content, forward); err != nil || forward.GetAddress() == "" {
		return nil, version, nil
	}
	return forward, version, nil
}

// Confirms the pending address with code (see the file header's confirm row), writing the mailbox's forward entry:
// ErrMailForwardCodeWrong for another code, which counts a try, and ErrMailForwardNoCode for none pending or one past
// its life or tries.
func (self *MailClient) ConfirmForward(ctx context.Context, code string) (*protocol.MailForward, error) {
	settings := self.forwardSettings()
	pending, err := self.forwardPending()
	if err != nil {
		return nil, err
	}
	now := self.clock.Now()
	if pending == nil || settings.CodeAttemptMaxCount <= pending.Attempts ||
		settings.CodeLifetime < now.Sub(time.UnixMilli(pending.SentMillis)) {
		return nil, ErrMailForwardNoCode
	}
	salt, saltErr := hex.DecodeString(pending.Salt)
	want, wantErr := hex.DecodeString(pending.CodeSha256)
	if saltErr != nil || wantErr != nil {
		return nil, ErrMailForwardNoCode
	}
	if subtle.ConstantTimeCompare(mailForwardCodeSha256(salt, strings.TrimSpace(code)), want) != 1 {
		pending.Attempts += 1
		if err := self.putForwardPending(pending); err != nil {
			return nil, err
		}
		return nil, ErrMailForwardCodeWrong
	}
	mailboxId, err := self.mailboxId()
	if err != nil {
		return nil, err
	}
	_, parts, err := self.bound()
	if err != nil {
		return nil, err
	}
	forward := &protocol.MailForward{Address: pending.Address, Burners: slices.Clone(pending.Burners), VerifiedTimeMs: uint64(max(now.UnixMilli(), 0))}
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(forward)
	if err != nil {
		return nil, err
	}
	store := parts.store(mailboxId)
	for attempt := 0; ; attempt += 1 {
		_, version, err := mailForwardRead(ctx, store, self.outboxSettings())
		if err != nil {
			return nil, err
		}
		_, err = store.Write(ctx, []*mailStoreWrite{{Path: MailForwardPath, Content: content, IfVersion: version}})
		if err == nil {
			break
		}
		if !mailStoreConflictOn(err, MailForwardPath) || self.outboxSettings().WriteRetryCount <= attempt {
			return nil, err
		}
	}
	if err := self.putForwardPending(nil); err != nil {
		return nil, err
	}
	return forward, nil
}

// A forward's or a relay's effect key: SHA-256 over its label and the message's id, so every reader of the message
// derives the one key and queues one entry.
func mailForwardEffectKey(label string, messageId Id) []byte {
	hash := sha256.New()
	io.WriteString(hash, label)
	hash.Write([]byte{0})
	hash.Write(messageId[:])
	return hash.Sum(nil)
}

// What considerForward did with one message, for the tests.
type mailForwardDecision string

const (
	mailForwardNone      mailForwardDecision = ""
	mailForwardForwarded mailForwardDecision = "forwarded"
	mailForwardRelayed   mailForwardDecision = "relayed"
	mailForwardRefused   mailForwardDecision = "refused"
)

// Forwards or relays one message ingest wrote, where the file header's forward or relay row lets it: the decision,
// and an error where the queue did not take what it should have. Called for each message of the member's mailbox.
func (self *MailClient) considerForward(ctx context.Context, message *MailMessage) (mailForwardDecision, error) {
	if message == nil || message.Entry == nil {
		return mailForwardNone, nil
	}
	row := self.networkRow()
	binding, parts, err := self.bound()
	if err != nil {
		return mailForwardNone, err
	}
	if binding.Network != nil {
		row = binding.Network()
	}
	recipient, err := ParseMailRecipient(row.Root, message.Entry.GetAddress())
	if err != nil || !recipient.Zone.OfNetwork(row) || (recipient.Kind != MailAddressKindBurner && recipient.Kind != MailAddressKindReverseAlias) {
		return mailForwardNone, nil
	}
	store := parts.store(message.RepoId)
	forward, _, err := mailForwardRead(ctx, store, self.outboxSettings())
	if err != nil || forward == nil || !slices.Contains(forward.GetBurners(), recipient.BurnerLabel) {
		return mailForwardNone, err
	}
	original, _, err := store.Read(ctx, MailMessagePath(message.Month, message.Id), self.settings.ReadMaxByteCount)
	if err != nil {
		return mailForwardNone, err
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(original))
	if err != nil {
		return mailForwardRefused, nil
	}
	fromAddresses, err := parsed.Header.AddressList("From")
	if err != nil || len(fromAddresses) != 1 {
		return mailForwardRefused, nil
	}
	sender := dnsAsciiLower(fromAddresses[0].Address)
	dmarc := message.Entry.GetAuthResults().GetDmarc()
	switch recipient.Kind {
	case MailAddressKindBurner:
		// the forward row: below the spam threshold, no DMARC fail, no loop, no target in URnetwork's zones
		if self.settings.Store.SpamScoreThreshold <= message.Entry.GetSpamScore() || dmarc == protocol.DmarcVerdict_DMARC_FAIL ||
			parsed.Header.Get(MailForwardedHeader) != "" || !mailForwardAddressAllowed(row.Root, forward.GetAddress()) {
			return mailForwardRefused, nil
		}
		aliases := newMailReverseAlias(store, self.secrets, self.outboxSettings())
		token, err := aliases.Ensure(ctx, sender, recipient.Address())
		if err != nil {
			return mailForwardNone, err
		}
		from := mailReverseAliasPrefix + token + "@" + recipient.Domain()
		outgoing, err := self.forwardedMessage(original, from, forward.GetAddress(), recipient.Domain(), true)
		if err != nil {
			return mailForwardRefused, nil
		}
		return mailForwardForwarded, self.queueForward(ctx, mailForwardEffectKey(mailForwardEffectKeyLabel, message.Id), forward.GetAddress(), outgoing)
	default:
		// the relay row: from the confirmed address, passing DMARC as received, to a sender ra/ names
		record, err := newMailReverseAlias(store, self.secrets, self.outboxSettings()).Find(ctx, recipient.Token)
		if errors.Is(err, ErrMailReverseAliasAbsent) {
			return mailForwardRefused, nil
		}
		if err != nil {
			return mailForwardNone, err
		}
		if sender != dnsAsciiLower(forward.GetAddress()) || dmarc != protocol.DmarcVerdict_DMARC_PASS ||
			!strings.HasSuffix(record.GetBurnerAddress(), "@"+recipient.Domain()) {
			return mailForwardRefused, nil
		}
		outgoing, err := self.forwardedMessage(original, record.GetBurnerAddress(), record.GetOriginalSender(), recipient.Domain(), false)
		if err != nil {
			return mailForwardRefused, nil
		}
		return mailForwardRelayed, self.queueForward(ctx, mailForwardEffectKey(mailRelayEffectKeyLabel, message.Id), record.GetOriginalSender(), outgoing)
	}
}

// The header fields a forward or a relay keeps of the original: what the message says, never who carried it, signed
// it or was meant to get it.
var mailForwardKeptFields = []string{
	"subject", "date", "message-id", "in-reply-to", "references", "mime-version", "content-type",
	"content-transfer-encoding", "content-language", "content-disposition",
}

// original as a forward or a relay: From from and To to, the kept fields, the body, then BURNER's rules under
// domain's random id and, for a forward, X-UR-Forwarded.
func (self *MailClient) forwardedMessage(original []byte, from string, to string, domain string, forwarded bool) ([]byte, error) {
	fields, lineEnd, body, err := mailBurnerSplit(original, DefaultMailBurnerHeadersSettings().HeaderMaxByteCount)
	if err != nil {
		return nil, err
	}
	rebuilt := &bytes.Buffer{}
	rebuilt.WriteString("From: " + from)
	rebuilt.Write(lineEnd)
	rebuilt.WriteString("To: " + to)
	rebuilt.Write(lineEnd)
	for _, field := range fields {
		if slices.Contains(mailForwardKeptFields, field.name) {
			rebuilt.Write(field.raw)
		}
	}
	rebuilt.Write(lineEnd)
	rebuilt.Write(body)
	sendId := newMailOutboxSendId()
	ruled, err := self.burnerHeaders().Apply(rebuilt.Bytes(), &MailBurnerHeadersArgs{MessageId: MailOutboxMessageId(sendId, domain), Now: self.clock.Now()})
	if err != nil {
		return nil, err
	}
	if !forwarded {
		return ruled, nil
	}
	// after the rules, which strip every X-* field a client wrote
	return append([]byte(MailForwardedHeader+": 1"+string(lineEnd)), ruled...), nil
}

// Queues outgoing to recipient under effectKey, flag BURNER, with no approval window: the outbox's, its standing
// read, and the mailbox's bounce address as the envelope sender.
func (self *MailClient) queueForward(ctx context.Context, effectKey []byte, recipient string, outgoing []byte) error {
	binding, _, err := self.bound()
	if err != nil {
		return err
	}
	outbox, err := self.memberOutbox(binding.Standing)
	if err != nil {
		return err
	}
	sender, err := self.BounceRecipient(ctx)
	if err != nil {
		return err
	}
	testHookBarrier("mail.forward.queue.before", "")
	_, err = outbox.Queue(ctx, &MailOutboxQueueArgs{
		EffectKey:  effectKey,
		Sender:     sender,
		Recipients: []string{recipient},
		Message:    outgoing,
		Flags:      SmtpFlagBurner,
	})
	testHookBarrier("mail.forward.queue.after", "")
	return err
}
