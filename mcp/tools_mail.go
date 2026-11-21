//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's mail tools (MCP-M7-01, MCP-M9-01; R-MCP-9, R-CTX-26, D-MCP-11, D-MCP-13, D-MCP-17, I-8, I-9, TS1, AU1) over
// the network's MailClient, which decides what each one does (mail_read.go, mail_send.go, mail_client.go): mail_list,
// mail_read and mail_aliases at R, mail_send at W that may act outward, and mail_alias_create and mail_alias_delete at
// O. ur://mail/{alias}, and the message an over-limit mail_read names, are resources_mail.go's.
//
//	list     mail_list(alias?, unread?, cursor?): the member's mailbox newest first, the group messages its references
//	         name among them, or one address's messages alone (MailClient.ListAddress), every folder but trash;
//	         unread leaves out what a flag marks seen; a page is cut where its result would pass ResultByteCount, its
//	         next_cursor then the last message kept
//	read     mail_read(id or hit): id as mail_list names it, <yyyymm>/<message id>, or a mail document's search hit
//	         standing alone (§16.10's open row), which opens only the message the hit names in the repo it names; the
//	         message's header fields, its text and its attachments as links, never their bytes (MailClient.Read); an
//	         over-limit result names the message's resource (D-MCP-13)
//	trust    outside mail is untrusted (MailEntryUntrusted, MailReadResult.Trust): a page or a message holding any taints
//	         the call's run, write-ahead and fsynced, before any of it is put in the result, the call failing when the
//	         taint fails (D-MCP-16), and every string its sender wrote, header values, from, subject, snippet, its
//	         recipient address, attachment names and types, goes out between the markers. Same-network mail whose
//	         signer may send as its From, and this member's sent copies, are a member's (D-MAIL-8); a trust the
//	         client reports that is neither reads untrusted
//	send     mail_send(from_alias, to, cc, bcc, subject, text, in_reply_to?, uses?): MailClient.Send with the call's
//	         run, its session's agent and the uses the call names (McpUses). Mail to members alone in an untainted
//	         run, or to internet recipients that each hold an approval record that verifies (§15.10's rcpt/; owner
//	         decision 280), goes at once; any other send waits on §5.4's gate as one mail_send action listing every
//	         recipient, Bcc included, a tainted run's on a fresh, tainted request (TS1), answering approval_pending
//	         with the request's id, the template's where uses is 2 or more (owner decision 613), until a person
//	         decides, and the same call again spends the decision. A send answers each recipient's outcome:
//	         same-network mail is deposited (MCP-M7-01), internet mail queued at o/<h>/<effect_key> under the use's
//	         effect key, created only if absent, its §14 outcomes following as the mail_send event (MCP-M9-01; §14.5).
//	         The W call goes to the sink as a tool_call entry naming every recipient, Bcc included
//	aliases  mail_aliases(): the addresses mailcfg's records hold, each with its kind, its mailbox and whether policy
//	         still grants its creator; members wrote them
//	alias    mail_alias_create(alias, group?) and mail_alias_delete(alias), alias a local part under the network's
//	         zone: each an outward action whose mailcfg record is written, or removed, only once the gate passes it,
//	         created only if absent under the use's effect_key, which MAIL's Lookup finds (mail_config_write.go), so a
//	         retry or a restart's reconcile writes nothing twice; pending answers approval_pending
//	access   none names a §8 grant to the framework: the client holds each to its own, a read to the member's keys, a
//	         From to mail:<alias>#send, an alias to mail:<alias>#listen and to a device that may change its record
//
// Errors are constant: none names an address, a subject or a byte of a message (I-13).

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The calls the mail tools make: *sidecar.MailClient, or a test's.
type McpMailClient interface {
	List(ctx context.Context, args *sidecar.MailListArgs) (*sidecar.MailListPage, error)
	ListAddress(ctx context.Context, address string, args *sidecar.MailListArgs) (*sidecar.MailListPage, error)
	Read(ctx context.Context, args *sidecar.MailReadArgs) (*sidecar.MailReadResult, error)
	Aliases(ctx context.Context) ([]*sidecar.MailAddressLookup, error)
	CreateAlias(ctx context.Context, args *sidecar.MailAliasCreateArgs) (*sidecar.MailAddressLookup, error)
	DeleteAlias(ctx context.Context, localPart string, action sidecar.MailConfigActionArgs) error
	Send(ctx context.Context, args *sidecar.MailSendArgs) (*sidecar.MailSendResult, error)
	// A revision that rises at each message this device's ingest writes, and a channel that closes at the next.
	ImapHints() (uint64, chan struct{})
}

var _ McpMailClient = (*sidecar.MailClient)(nil)

// One network as the mail tools read it.
type McpMailNetwork interface {
	McpToolNetwork
	// The network's mail, an error while the daemon holds none.
	McpMail() (McpMailClient, error)
}

// The hosted Sidecar's mail.
func (self *mcpSidecarNetwork) McpMail() (McpMailClient, error) {
	client, err := self.Sidecar.Mail()
	if err != nil {
		return nil, err
	}
	return client, nil
}

// The tools' statuses.
const (
	mcpMailStatusSent            = "sent"
	mcpMailStatusPartial         = "partial"
	mcpMailStatusNotSent         = "not_sent"
	mcpMailStatusCreated         = "created"
	mcpMailStatusDeleted         = "deleted"
	mcpMailStatusApprovalPending = "approval_pending"
)

// The tools' refusals, each constant.
var (
	errMcpMailUnavailable = NewMcpError(McpCodeUnavailable,
		"this network's mail is not ready on this daemon: run ur mail status in your own terminal", true)
	errMcpMailId = NewMcpError(McpCodeInvalidArguments,
		"id is a message's id as mail_list names it, <yyyymm>/<message id>", false)
	errMcpMailIdOrHit = NewMcpError(McpCodeInvalidArguments,
		"mail_read takes a message's id or a search hit, one of them", false)
	errMcpMailCursor = NewMcpError(McpCodeInvalidArguments,
		"cursor is a next_cursor an earlier mail_list answered", false)
	errMcpMailAbsent = NewMcpError(McpCodeFailedPrecondition,
		"no message of this member's mail has that id", false)
	errMcpMailTooLarge = NewMcpError(McpCodeFailed,
		"the message is past what a read through MCP holds: read it in your own mail client", false)
	errMcpMailSendArguments = NewMcpError(McpCodeInvalidArguments,
		"mail_send takes from_alias, an address of this network; at least one recipient among to, cc and bcc, each an address; a subject on one line; and UTF-8 text, each within its bound", false)
	errMcpMailFromRefused = NewMcpError(McpCodeRefused,
		"this device may not send as from_alias: name an address of this network that policy lets it send as", false)
	errMcpMailHeld = NewMcpError(McpCodeRefused,
		"no approval of this could be spent: it was denied, cancelled, spent or expired, or no rule lets this sidecar ask", false)
	errMcpMailNotSent = NewMcpError(McpCodeFailedPrecondition,
		"nothing was sent: the mail's From or recipients no longer hold as approved, or its mailbox refused it", false)
	errMcpMailUncertain = NewMcpError(McpCodeFailed,
		"whether the mail went is not known yet: send the same call again, which sends nothing twice", true)
	errMcpMailCopyFailed = NewMcpError(McpCodeFailed,
		"the sent copy could not be kept, so nothing was sent: send the same call again", true)
	errMcpMailAliasArguments = NewMcpError(McpCodeInvalidArguments,
		"alias is a local part this network may take, not a reserved one, and group a group alias's local part", false)
	errMcpMailAliasTaken = NewMcpError(McpCodeFailedPrecondition,
		"the alias is taken", false)
	errMcpMailAliasAbsent = NewMcpError(McpCodeFailedPrecondition,
		"no alias, or no group, of this network has that name", false)
	errMcpMailAliasRefused = NewMcpError(McpCodeRefused,
		"the network's policy does not let this device take or change that alias", false)
	errMcpMailAliasUncertain = NewMcpError(McpCodeFailed,
		"the alias's write may have landed: send the same call again, which writes nothing twice", true)
	errMcpMailAliasMoved = NewMcpError(McpCodeFailedPrecondition,
		"nothing was written: the alias's record moved under the write; read mail_aliases and ask again", false)
)

// mail_list's arguments.
type mcpMailListIn struct {
	// One of this network's addresses, as mail_aliases names it: its messages alone. Omitted, the member's mail.
	Alias string `json:"alias,omitempty"`
	// Leaves out the messages a flag marks seen.
	Unread bool `json:"unread,omitempty"`
	// An earlier page's next_cursor.
	Cursor string `json:"cursor,omitempty"`
}

// One message as mail_list shows it.
type mcpMailMessageOut struct {
	// What mail_read takes: <yyyymm>/<message id>.
	Id string `json:"id"`
	// The repo the message is in: the member's mailbox, or a group's.
	Repo string `json:"repo"`
	// The recipient address in that repo, between the markers for outside mail.
	Address    string `json:"address"`
	TimeMillis uint64 `json:"time_millis"`
	From       string `json:"from"`
	Subject    string `json:"subject"`
	// The text's first line, at most 200 bytes.
	Snippet         string   `json:"snippet"`
	Size            uint64   `json:"size"`
	AttachmentCount int      `json:"attachment_count"`
	Seen            bool     `json:"seen"`
	Flagged         bool     `json:"flagged"`
	Spam            bool     `json:"spam"`
	Labels          []string `json:"labels"`
	// member or untrusted
	Trust string `json:"trust"`
	// validated, opportunistic, member-signed or no label (§15.5)
	TlsLabel string `json:"tls_label"`
}

// mail_list's data, and ur://mail/{alias}'s.
type mcpMailListOut struct {
	Messages   []*mcpMailMessageOut `json:"messages"`
	NextCursor string               `json:"next_cursor,omitempty"`
	// Records the page read past that do not read, never shown.
	Unreadable int `json:"unreadable"`
}

// mail_read's arguments: a message's id, or a search hit standing for it.
type mcpMailReadIn struct {
	Id string `json:"id,omitempty"`
	// A mail document's search hit, its hit_id, in place of id (§16.10's open row).
	Hit string `json:"hit,omitempty"`
}

// One header field.
type mcpMailHeaderOut struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// One attachment: what it is and where it is, never its bytes.
type mcpMailAttachmentOut struct {
	Index     int    `json:"index"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	ByteCount uint64 `json:"byte_count"`
	Link      string `json:"link"`
}

// mail_read's data, and the message resource's.
type mcpMailReadOut struct {
	Id         string `json:"id"`
	Repo       string `json:"repo"`
	Address    string `json:"address"`
	TimeMillis uint64 `json:"time_millis"`
	// From, Sender, Reply-To, To, Cc, Subject, Date, Message-ID, In-Reply-To, References and
	// Authentication-Results, in that order, each one line.
	Headers []*mcpMailHeaderOut `json:"headers"`
	// The first text part's text, decoded.
	Text        string                  `json:"text"`
	Attachments []*mcpMailAttachmentOut `json:"attachments"`
	// More attachments than attachments lists.
	AttachmentCount int      `json:"attachment_count"`
	Seen            bool     `json:"seen"`
	Flagged         bool     `json:"flagged"`
	Spam            bool     `json:"spam"`
	Labels          []string `json:"labels"`
	Trust           string   `json:"trust"`
	TlsLabel        string   `json:"tls_label"`
	// The words stated beside the label: its basis, never a claim of path confidentiality (§15.5).
	TlsStatement string `json:"tls_statement"`
}

// mail_send's arguments.
type mcpMailSendIn struct {
	// An address of this network, as mail_aliases names it, that this device may send as.
	FromAlias string   `json:"from_alias"`
	To        []string `json:"to"`
	Cc        []string `json:"cc,omitempty"`
	Bcc       []string `json:"bcc,omitempty"`
	Subject   string   `json:"subject"`
	Text      string   `json:"text"`
	// The Message-ID replied to, without its brackets.
	InReplyTo string `json:"in_reply_to,omitempty"`
}

// One recipient's outcome.
type mcpMailRecipientOut struct {
	Address string `json:"address"`
	// delivered, queued, unknown, member_refused, refused, internet_refused, internet_waits or failed
	Outcome string `json:"outcome"`
}

// mail_send's data.
type mcpMailSendOut struct {
	// sent, partial or not_sent by its recipients' outcomes, or approval_pending with approval_id.
	Status string `json:"status"`
	// The send's id, which a queued message's Message-ID carries and the mail_send event names.
	MessageId  string                 `json:"message_id,omitempty"`
	ApprovalId string                 `json:"approval_id,omitempty"`
	Recipients []*mcpMailRecipientOut `json:"recipients"`
	// Whether the sent copy was kept in the member's mailbox.
	SentCopy bool `json:"sent_copy"`
}

// mail_aliases takes nothing but the network.
type mcpMailAliasesIn struct{}

// One address of the network.
type mcpMailAliasOut struct {
	Address string `json:"address"`
	// Its local part, what mail_alias_create and mail_alias_delete name.
	Alias string `json:"alias"`
	// id, group, agent, admin or bounce
	Kind string `json:"kind"`
	// The repo its mail goes to.
	Mailbox string   `json:"mailbox"`
	Members []string `json:"members"`
	Creator string   `json:"creator"`
	// Whether mail for it is taken: policy still grants its creator.
	Known bool `json:"known"`
}

// mail_aliases' data.
type mcpMailAliasesOut struct {
	Aliases []*mcpMailAliasOut `json:"aliases"`
}

// mail_alias_create's arguments.
type mcpMailAliasCreateIn struct {
	// A local part under the network's zone.
	Alias string `json:"alias"`
	// A group alias's local part, whose repo the new alias delivers to; omitted, the member's mailbox.
	Group string `json:"group,omitempty"`
}

// mail_alias_delete's arguments.
type mcpMailAliasDeleteIn struct {
	Alias string `json:"alias"`
}

// What an alias write answers.
type mcpMailAliasWriteOut struct {
	// created or deleted, or approval_pending with approval_id, the same call again spending the decision once a
	// person has made it.
	Status     string `json:"status"`
	ApprovalId string `json:"approval_id,omitempty"`
	// A created alias's address.
	Address string `json:"address,omitempty"`
}

func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		addMailTools(catalog)
	})
}

// The call's network's mail client, an error where it has none.
func mcpMailClientOf(call *McpCall) (McpMailClient, error) {
	network, ok := call.Network.(McpMailNetwork)
	if !ok {
		return nil, errMcpMailUnavailable
	}
	client, err := network.McpMail()
	if err != nil || client == nil {
		return nil, errMcpMailUnavailable
	}
	return client, nil
}

// Whether err says the network's mail cannot serve now: no binding, mailbox, mailcfg, zone, gate or state yet.
func mcpMailUnavailableError(err error) bool {
	for _, unavailable := range []error{
		sidecar.ErrMailUnbound, sidecar.ErrMailNoMailbox, sidecar.ErrMailNoConfig, sidecar.ErrMailSendUnavailable,
		sidecar.ErrMailConfigNotSynced, sidecar.ErrMailConfigNoZone, sidecar.ErrMailConfigNoGate, sidecar.ErrMailConfigUnseated,
		sidecar.ErrMailReposNoState, sidecar.ErrApprovalNoState,
	} {
		if errors.Is(err, unavailable) {
			return true
		}
	}
	return false
}

// Whether err is §5.4's gate holding an action back: a refused, denied, cancelled, spent or expired decision, a kind
// with no lookup, a template presented as itself, or no gate at all.
func mcpMailHeldError(err error) bool {
	var refusal *sidecar.SpendRefusal
	if errors.As(err, &refusal) {
		return true
	}
	for _, held := range []error{
		sidecar.ErrApprovalDenied, sidecar.ErrApprovalExpired, sidecar.ErrApprovalSpent, sidecar.ErrApprovalCancelled,
		sidecar.ErrApprovalNoLookup, sidecar.ErrApprovalTemplateUse, sidecar.ErrApprovalRefused,
		sidecar.ErrApprovalVersionUnknown, sidecar.ErrSidecarGateDenied,
	} {
		if errors.Is(err, held) {
			return true
		}
	}
	return false
}

// A read's error as mail_list, mail_read and the mail resources answer it, by constant text.
func mcpMailReadError(err error) error {
	switch {
	case errors.Is(err, sidecar.ErrMailViewEntryAbsent), errors.Is(err, sidecar.ErrEvsPathAbsent):
		return errMcpMailAbsent
	case errors.Is(err, sidecar.ErrMailStoreTooLarge):
		return errMcpMailTooLarge
	case errors.Is(err, sidecar.ErrEvsReceiptGate):
		return errMcpEvsReceipt
	case errors.Is(err, sidecar.ErrMailClientInvalid), errors.Is(err, sidecar.ErrMailViewArgsInvalid):
		return errMcpInvalidArguments
	case mcpMailUnavailableError(err):
		return errMcpMailUnavailable
	}
	return err
}

// A send's error as mail_send answers it, by constant text; pending is the caller's.
func mcpMailSendError(err error) error {
	switch {
	case errors.Is(err, sidecar.ErrMailSendInvalid), errors.Is(err, sidecar.ErrMailRecipientInvalid):
		return errMcpMailSendArguments
	case errors.Is(err, sidecar.ErrMailSendFromRefused):
		return errMcpMailFromRefused
	case errors.Is(err, sidecar.ErrMailSendCopyFailed):
		return errMcpMailCopyFailed
	case errors.Is(err, sidecar.ErrMailSendUncertain):
		return errMcpMailUncertain
	case errors.Is(err, sidecar.ErrSidecarEffectNotDone):
		return errMcpMailNotSent
	case mcpMailUnavailableError(err):
		return errMcpMailUnavailable
	case mcpMailHeldError(err):
		return errMcpMailHeld
	}
	return err
}

// An alias write's error as mail_alias_create and mail_alias_delete answer it, by constant text; pending is the
// caller's.
func mcpMailAliasError(err error) error {
	switch {
	case errors.Is(err, sidecar.ErrMailConfigInvalid), errors.Is(err, sidecar.ErrMailLocalPartInvalid),
		errors.Is(err, sidecar.ErrMailLocalPartReserved), errors.Is(err, sidecar.ErrMailRecipientInvalid),
		errors.Is(err, sidecar.ErrMailClientInvalid):
		return errMcpMailAliasArguments
	case errors.Is(err, sidecar.ErrMailConfigAddressTaken):
		return errMcpMailAliasTaken
	case errors.Is(err, sidecar.ErrMailConfigAddressAbsent):
		return errMcpMailAliasAbsent
	case errors.Is(err, sidecar.ErrMailConfigNoGrant), errors.Is(err, sidecar.ErrMailConfigNotOwner):
		return errMcpMailAliasRefused
	case errors.Is(err, sidecar.ErrMailConfigUncertain):
		return errMcpMailAliasUncertain
	case errors.Is(err, sidecar.ErrSidecarEffectNotDone):
		return errMcpMailAliasMoved
	case mcpMailUnavailableError(err):
		return errMcpMailUnavailable
	case mcpMailHeldError(err):
		return errMcpMailHeld
	}
	return err
}

// The run and agent a decision binds for call: its run, and its session's agent in the network (owner decision 470).
func mcpMailAction(call *McpCall) sidecar.MailConfigActionArgs {
	runId := call.RunId
	return sidecar.MailConfigActionArgs{RunId: &runId, AgentId: mcpCallAgentId(call)}
}

// ctx carrying the read's purpose and run, which an owner-bound repo's receipt is deposited under (D-MCP-18).
func mcpMailReadContext(ctx context.Context, call *McpCall) context.Context {
	runId := call.RunId
	return sidecar.WithEvsReadContext(ctx, &sidecar.EvsReadContext{Purpose: sidecar.RecordReadPurposeRead, RunId: &runId})
}

// A message's id as mail_list names it.
func mcpMailIdText(month sidecar.MailYearMonth, messageId sidecar.Id) string {
	return month.String() + "/" + messageId.String()
}

// The month and message id of an id mail_list named.
func mcpMailParseId(text string) (sidecar.MailYearMonth, sidecar.Id, error) {
	monthText, idText, ok := strings.Cut(text, "/")
	if !ok {
		return 0, sidecar.Id{}, errMcpMailId
	}
	month, ok := sidecar.ParseMailYearMonth(monthText)
	if !ok {
		return 0, sidecar.Id{}, errMcpMailId
	}
	messageId, err := sidecar.ParseId(idText)
	if err != nil || messageId == (sidecar.Id{}) {
		return 0, sidecar.Id{}, errMcpMailId
	}
	return month, messageId, nil
}

// A list's place as next_cursor names it: <time ms>.<message id>.
func mcpMailCursorText(cursor *sidecar.MailListCursor) string {
	return strconv.FormatUint(cursor.Time, 10) + "." + cursor.Id.String()
}

// The place a next_cursor names.
func mcpMailParseCursor(text string) (*sidecar.MailListCursor, error) {
	timeText, idText, ok := strings.Cut(text, ".")
	if !ok {
		return nil, errMcpMailCursor
	}
	timeMillis, err := strconv.ParseUint(timeText, 10, 64)
	if err != nil {
		return nil, errMcpMailCursor
	}
	messageId, err := sidecar.ParseId(idText)
	if err != nil {
		return nil, errMcpMailCursor
	}
	return &sidecar.MailListCursor{Time: timeMillis, Id: messageId}, nil
}

// A label's name, as §15.5 states it.
func mcpMailTlsLabelName(label protocol.MailTlsLabel) string {
	switch label {
	case protocol.MailTlsLabel_MAIL_TLS_VALIDATED:
		return "validated"
	case protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC:
		return "opportunistic"
	case protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED:
		return "member-signed"
	}
	return "no label"
}

// An address kind's name: id, group, agent, admin, burner or bounce.
func mcpMailAddressKindName(kind protocol.MailAddressKind) string {
	return strings.TrimPrefix(strings.ToLower(kind.String()), "mail_address_")
}

// The bytes a result may hold before it becomes a link (D-MCP-13).
func mcpResultByteCount(call *McpCall) int {
	if call == nil || call.Session == nil || call.Session.server == nil {
		return sidecar.DefaultSidecarSettings().Mcp.ResultByteCount
	}
	return call.Session.server.settings.Mcp.ResultByteCount
}

// One page as mail_list and ur://mail/{alias} answer it (the file header's list and trust rows): the run tainted first
// where any message kept is outside mail, each one's sender's words fenced then, and the page cut where its result
// would pass the result bound.
func mcpMailPage(ctx context.Context, call *McpCall, page *sidecar.MailListPage, unread bool, source string, result *McpResult) (*mcpMailListOut, error) {
	result.SetSource(source)
	entries := []*sidecar.MailViewEntry{}
	for _, entry := range page.Entries {
		if entry == nil || entry.Entry == nil {
			continue
		}
		if unread && entry.Flags != nil && entry.Flags.Seen {
			continue
		}
		entries = append(entries, entry)
	}
	switch {
	case slices.ContainsFunc(entries, func(entry *sidecar.MailViewEntry) bool { return sidecar.MailEntryUntrusted(entry.Entry) }):
		// taint before data: the run file is fsynced before any outside words are put in the result (D-MCP-16)
		if err := result.Untrusted(ctx); err != nil {
			return nil, err
		}
	case 0 < len(entries):
		result.Member()
	}
	out := &mcpMailListOut{Messages: []*mcpMailMessageOut{}, Unreadable: page.Unreadable}
	for _, entry := range entries {
		out.Messages = append(out.Messages, mcpMailMessageOf(entry, result))
	}
	if page.Next != nil {
		out.NextCursor = mcpMailCursorText(page.Next)
	}
	limit := mcpResultByteCount(call)
	fits := func() bool {
		data, err := json.Marshal(out)
		if err != nil {
			return false
		}
		// the envelope the framework would wrap it in, at its widest
		envelope, err := json.Marshal(&mcpResultEnvelope{
			Trust: McpTrustUntrusted, Source: source, MeteredBytes: math.MaxInt64, MarkerBroken: true, Data: data,
		})
		return err == nil && len(envelope) <= limit
	}
	for 1 < len(out.Messages) && !fits() {
		keep := len(out.Messages) / 2
		out.Messages = out.Messages[:keep]
		last := entries[keep-1].Entry
		lastId, _ := sidecar.IdFromBytes(last.GetId())
		out.NextCursor = mcpMailCursorText(&sidecar.MailListCursor{Time: last.GetTime(), Id: lastId})
	}
	return out, nil
}

// One message of a list, its sender's words fenced where it is outside mail. The run is tainted already where it is.
func mcpMailMessageOf(viewEntry *sidecar.MailViewEntry, result *McpResult) *mcpMailMessageOut {
	entry := viewEntry.Entry
	messageId, _ := sidecar.IdFromBytes(entry.GetId())
	out := &mcpMailMessageOut{
		Id:              mcpMailIdText(sidecar.MailYearMonthOf(entry.GetTime()), messageId),
		Repo:            viewEntry.RepoId.String(),
		TimeMillis:      entry.GetTime(),
		Size:            entry.GetSize(),
		AttachmentCount: len(entry.GetAttachments()),
		Spam:            viewEntry.Spam,
		Labels:          []string{},
		Trust:           string(sidecar.MailTrustMember),
		TlsLabel:        mcpMailTlsLabelName(entry.GetTlsLabel()),
	}
	if flags := viewEntry.Flags; flags != nil {
		out.Seen, out.Flagged = flags.Seen, flags.Flagged
		out.Labels = append(out.Labels, flags.Labels...)
	}
	words := func(text string) string { return text }
	if sidecar.MailEntryUntrusted(entry) {
		out.Trust = string(sidecar.MailTrustUntrusted)
		words = result.Fence
	}
	out.Address, out.From, out.Subject, out.Snippet = words(entry.GetAddress()), words(entry.GetFrom()), words(entry.GetSubject()), words(entry.GetSnippet())
	return out
}

// The message a mail_read names, by id or by hit: its month and id, and for a hit the repo the hit names.
func mcpMailReadOf(call *McpCall, in *mcpMailReadIn) (sidecar.MailYearMonth, sidecar.Id, *sidecar.Id, error) {
	switch {
	case in.Hit != "" && in.Id != "":
		return 0, sidecar.Id{}, nil, errMcpHitAlone
	case in.Hit != "":
		ref, err := mcpHitOfKind(call, in.Hit, sidecar.IndexDocMail)
		if err != nil {
			return 0, sidecar.Id{}, nil, err
		}
		month, messageId, ok := sidecar.ParseMailMessagePath(ref.Path)
		if !ok || ref.RefName != "" {
			return 0, sidecar.Id{}, nil, errMcpHitKind
		}
		repoId := ref.RepoId
		return month, messageId, &repoId, nil
	case in.Id != "":
		month, messageId, err := mcpMailParseId(in.Id)
		return month, messageId, nil, err
	}
	return 0, sidecar.Id{}, nil, errMcpMailIdOrHit
}

// One message as mail_read and its resource answer it (the file header's read and trust rows): read, then, for
// outside mail, the run tainted before any of it is put in the result and its sender's words fenced. repoId, where
// set, is the repo the message must be in, mismatch the answer where it is in another. The message's resource is
// named for an over-limit result.
func mcpMailRead(ctx context.Context, call *McpCall, client McpMailClient, month sidecar.MailYearMonth, messageId sidecar.Id, repoId *sidecar.Id, mismatch error, result *McpResult) (*mcpMailReadOut, error) {
	read, err := client.Read(mcpMailReadContext(ctx, call), &sidecar.MailReadArgs{Month: month, Id: messageId})
	if err != nil {
		return nil, mcpMailReadError(err)
	}
	if read == nil || read.Entry == nil {
		return nil, errMcpMailAbsent
	}
	if repoId != nil && read.RepoId != *repoId {
		// the member's mail holds the id in another repo than the one named: nothing of it is shown
		return nil, mismatch
	}
	result.SetSource("mail:" + read.RepoId.String())
	result.SetResource(McpMailMessageUri(read.RepoId, month, messageId))
	words := func(text string) string { return text }
	trust := sidecar.MailTrustMember
	if read.Trust != sidecar.MailTrustMember || sidecar.MailEntryUntrusted(read.Entry) {
		// taint before data (D-MCP-16)
		if err := result.Untrusted(ctx); err != nil {
			return nil, err
		}
		words = result.Fence
		trust = sidecar.MailTrustUntrusted
	} else {
		result.Member()
	}
	out := &mcpMailReadOut{
		Id:              mcpMailIdText(month, messageId),
		Repo:            read.RepoId.String(),
		Address:         words(read.Entry.GetAddress()),
		TimeMillis:      read.Entry.GetTime(),
		Headers:         []*mcpMailHeaderOut{},
		Text:            words(read.Text),
		Attachments:     []*mcpMailAttachmentOut{},
		AttachmentCount: read.AttachmentCount,
		Spam:            read.Spam,
		Labels:          []string{},
		Trust:           string(trust),
		TlsLabel:        read.Label,
		TlsStatement:    read.LabelStatement,
	}
	if flags := read.Flags; flags != nil {
		out.Seen, out.Flagged = flags.Seen, flags.Flagged
		out.Labels = append(out.Labels, flags.Labels...)
	}
	for _, header := range read.Headers {
		if header == nil {
			continue
		}
		out.Headers = append(out.Headers, &mcpMailHeaderOut{Name: header.Name, Value: words(header.Value)})
	}
	for _, attachment := range read.Attachments {
		if attachment == nil {
			continue
		}
		out.Attachments = append(out.Attachments, &mcpMailAttachmentOut{
			Index: attachment.Index, Name: words(attachment.Name), Type: words(attachment.Type), ByteCount: attachment.ByteCount,
			Link: attachment.Link,
		})
	}
	McpMeter(ctx, int64(read.Entry.GetSize()))
	return out, nil
}

// What a send answered, as mail_send's data: its status by its recipients' outcomes.
func mcpMailSendOutOf(sent *sidecar.MailSendResult) *mcpMailSendOut {
	out := &mcpMailSendOut{Status: mcpMailStatusSent, Recipients: []*mcpMailRecipientOut{}}
	if sent == nil {
		return out
	}
	if sent.SendId != (sidecar.Id{}) {
		out.MessageId = sent.SendId.String()
	}
	out.SentCopy = sent.SentCopy
	accepted := 0
	for _, recipient := range sent.Recipients {
		if recipient == nil {
			continue
		}
		out.Recipients = append(out.Recipients, &mcpMailRecipientOut{Address: recipient.Address, Outcome: string(recipient.Outcome)})
		if recipient.Outcome == sidecar.MailSendDelivered || recipient.Outcome == sidecar.MailSendQueued {
			accepted += 1
		}
	}
	// a retry of a done use answers its send alone, no recipient listed: it went (AU4)
	switch {
	case len(out.Recipients) == 0:
	case accepted == 0:
		out.Status = mcpMailStatusNotSent
	case accepted < len(out.Recipients):
		out.Status = mcpMailStatusPartial
	}
	return out
}

// An address's local part.
func mcpMailLocalPart(address string) string {
	localPart, _, _ := strings.Cut(address, "@")
	return localPart
}

// Registers the six mail tools on catalog.
func addMailTools(catalog *McpCatalog) {
	AddTool(catalog, &McpToolSpec[mcpMailListIn]{
		Name:        "mail_list",
		Tier:        McpTierRead,
		Description: "Lists the member's mail newest first, or one address's: each message's id, sender, subject, snippet, flags and label. Outside mail comes back marked untrusted, and listing it taints the run.",
		Access:      func(call *McpCall, in *mcpMailListIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpMailListIn, result *McpResult) (*mcpMailListOut, error) {
		client, err := mcpMailClientOf(call)
		if err != nil {
			return nil, err
		}
		args := &sidecar.MailListArgs{Folder: sidecar.MailFolderAll}
		if in.Cursor != "" {
			if args.After, err = mcpMailParseCursor(in.Cursor); err != nil {
				return nil, err
			}
		}
		ctx = mcpMailReadContext(ctx, call)
		var page *sidecar.MailListPage
		if in.Alias != "" {
			page, err = client.ListAddress(ctx, in.Alias, args)
		} else {
			page, err = client.List(ctx, args)
		}
		if err != nil {
			return nil, mcpMailReadError(err)
		}
		if page == nil {
			page = &sidecar.MailListPage{}
		}
		return mcpMailPage(ctx, call, page, in.Unread, "mail:list", result)
	})

	AddTool(catalog, &McpToolSpec[mcpMailReadIn]{
		Name:        "mail_read",
		Tier:        McpTierRead,
		Description: "Reads one message by the id mail_list names, or the message a search hit names by its hit id: its header fields, its text and its attachments as links. Outside mail comes back marked untrusted, and reading it taints the run.",
		Access:      func(call *McpCall, in *mcpMailReadIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpMailReadIn, result *McpResult) (*mcpMailReadOut, error) {
		month, messageId, repoId, err := mcpMailReadOf(call, in)
		if err != nil {
			return nil, err
		}
		client, err := mcpMailClientOf(call)
		if err != nil {
			return nil, err
		}
		return mcpMailRead(ctx, call, client, month, messageId, repoId, errMcpHitUnknown, result)
	})

	AddTool(catalog, &McpToolSpec[mcpMailSendIn]{
		Name:     "mail_send",
		Tier:     McpTierWrite,
		MayAct:   true,
		MultiUse: true,
		Description: "Sends a plain-text message from one of this network's addresses. Mail to members alone goes at once; " +
			"mail to anyone else, or from a run that read untrusted content, is outward and may answer approval_pending until a person decides.",
		Access: func(call *McpCall, in *mcpMailSendIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpMailSendIn, result *McpResult) (*mcpMailSendOut, error) {
		client, err := mcpMailClientOf(call)
		if err != nil {
			return nil, err
		}
		result.SetSource("mail:send")
		sent, err := client.Send(ctx, &sidecar.MailSendArgs{
			From:      in.FromAlias,
			To:        slices.Clone(in.To),
			Cc:        slices.Clone(in.Cc),
			Bcc:       slices.Clone(in.Bcc),
			Subject:   in.Subject,
			Text:      in.Text,
			InReplyTo: in.InReplyTo,
			Action:    mcpMailAction(call),
			// 2 or more asks for a template of From and every recipient, filed in this mail's place (owner decision 613)
			Uses: McpUses(ctx),
		})
		if err != nil {
			var pending *sidecar.ApprovalPendingError
			if errors.As(err, &pending) {
				// the template's id where uses asked for one, which the gate files in this mail's place
				return &mcpMailSendOut{Status: mcpMailStatusApprovalPending, ApprovalId: pending.ApprovalId.String(), Recipients: []*mcpMailRecipientOut{}}, nil
			}
			return nil, mcpMailSendError(err)
		}
		McpMeter(ctx, int64(len(in.Subject)+len(in.Text)))
		return mcpMailSendOutOf(sent), nil
	})

	AddTool(catalog, &McpToolSpec[mcpMailAliasesIn]{
		Name:        "mail_aliases",
		Tier:        McpTierRead,
		Description: "Lists this network's addresses as its mail config records them: each address, its local part, its kind, the repo its mail goes to and whether its mail is taken.",
		Access:      func(call *McpCall, in *mcpMailAliasesIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpMailAliasesIn, result *McpResult) (*mcpMailAliasesOut, error) {
		client, err := mcpMailClientOf(call)
		if err != nil {
			return nil, err
		}
		lookups, err := client.Aliases(ctx)
		if err != nil {
			return nil, mcpMailReadError(err)
		}
		result.Member()
		result.SetSource("mail:aliases")
		out := &mcpMailAliasesOut{Aliases: []*mcpMailAliasOut{}}
		for _, lookup := range lookups {
			if lookup == nil {
				continue
			}
			alias := &mcpMailAliasOut{
				Address: lookup.Address, Alias: mcpMailLocalPart(lookup.Address), Kind: mcpMailAddressKindName(lookup.Kind),
				Mailbox: lookup.MailboxRepoId.String(), Members: []string{}, Creator: lookup.CreatorSidecarId.String(), Known: lookup.Known,
			}
			for _, memberId := range lookup.MemberIds {
				alias.Members = append(alias.Members, memberId.String())
			}
			out.Aliases = append(out.Aliases, alias)
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpMailAliasCreateIn]{
		Name:        "mail_alias_create",
		Tier:        McpTierOutward,
		Description: "Takes a new address of this network, delivering to the member's mailbox or to a group's; outward, so it may answer approval_pending until a person decides.",
		Access:      func(call *McpCall, in *mcpMailAliasCreateIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpMailAliasCreateIn, result *McpResult) (*mcpMailAliasWriteOut, error) {
		if in.Alias == "" || strings.Contains(in.Alias, "@") || strings.Contains(in.Group, "@") {
			return nil, errMcpMailAliasArguments
		}
		client, err := mcpMailClientOf(call)
		if err != nil {
			return nil, err
		}
		result.SetSource("mail:aliases")
		lookup, err := client.CreateAlias(ctx, &sidecar.MailAliasCreateArgs{LocalPart: in.Alias, Group: in.Group, Action: mcpMailAction(call)})
		if err != nil {
			var pending *sidecar.ApprovalPendingError
			if errors.As(err, &pending) {
				return &mcpMailAliasWriteOut{Status: mcpMailStatusApprovalPending, ApprovalId: pending.ApprovalId.String()}, nil
			}
			return nil, mcpMailAliasError(err)
		}
		out := &mcpMailAliasWriteOut{Status: mcpMailStatusCreated}
		if lookup != nil {
			out.Address = lookup.Address
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpMailAliasDeleteIn]{
		Name:        "mail_alias_delete",
		Tier:        McpTierOutward,
		Description: "Removes an address of this network, by its local part; outward, so it may answer approval_pending until a person decides.",
		Access:      func(call *McpCall, in *mcpMailAliasDeleteIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpMailAliasDeleteIn, result *McpResult) (*mcpMailAliasWriteOut, error) {
		if in.Alias == "" || strings.Contains(in.Alias, "@") {
			return nil, errMcpMailAliasArguments
		}
		client, err := mcpMailClientOf(call)
		if err != nil {
			return nil, err
		}
		result.SetSource("mail:aliases")
		if err := client.DeleteAlias(ctx, in.Alias, mcpMailAction(call)); err != nil {
			var pending *sidecar.ApprovalPendingError
			if errors.As(err, &pending) {
				return &mcpMailAliasWriteOut{Status: mcpMailStatusApprovalPending, ApprovalId: pending.ApprovalId.String()}, nil
			}
			return nil, mcpMailAliasError(err)
		}
		return &mcpMailAliasWriteOut{Status: mcpMailStatusDeleted}, nil
	})
}
