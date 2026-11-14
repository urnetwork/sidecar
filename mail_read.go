//go:build !ios_extension

// §15.7's reads (R-MAIL-10, R-MAIL-13, I-7, I-9, I-11; MAIL-M7-17): MailClient's List, Read and ListAddress, the data
// behind mail_list, mail_read and ur://mail/{alias}. They link no connect, go-smtp or mox, so the page Worker reads
// mail as the daemon does, over the bound EvsClient's head reads (§18.4), and decide nothing: every label, score and
// result is what ingest sealed (D-MAIL-14).
//
//	list     the member's mailbox through MailView: its i/ entries and the group messages its r/ references name,
//	         with f/'s flags, newest first, a page at a time
//	read     one message: its text (the first text part, decoded), its header fields, its attachments as links to
//	         fetch, never their bytes, the label with its stated basis (MailLabelOfEntry), and a trust mark. Outside
//	         mail is untrusted, so §16 taints a run that reads it before any byte of it reaches an agent (R-MAIL-10,
//	         I-9); a same-network message whose signer may send as its From is a member's (D-MAIL-8)
//	address  the entries of one address, for ur://mail/{alias}, reading at most AddressScanMaxCount entries a page
//
// A header value is one line, its encoded words decoded, held to ReadHeaderValueMaxByteCount, since a header is a
// sender's text. Nothing here names a credential (I-7) or logs an address (I-13).

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"mime"
	"net/textproto"
	"strings"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

// Whether a message may be acted on as a person's: outside mail never is (R-MAIL-10).
type MailTrust string

const (
	// Outside mail: §16 taints a run that reads it (I-9).
	MailTrustUntrusted MailTrust = "untrusted"
	// A same-network deposit whose signer may send as its From (D-MAIL-8).
	MailTrustMember MailTrust = "member"
)

// The header fields Read returns, in this order, each as often as the message carries it.
var mailReadHeaderNames = []string{
	"From", "Sender", "Reply-To", "To", "Cc", "Subject", "Date", "Message-ID", "In-Reply-To", "References",
	"Authentication-Results",
}

// What Read reads: a message as a list named it.
type MailReadArgs struct {
	Month MailYearMonth
	Id    Id
}

// One header field as Read returns it.
type MailReadHeader struct {
	Name  string
	Value string
}

// One attachment as Read returns it: what it is and where to fetch it, never its bytes.
type MailReadAttachment struct {
	// Its place among the message's attachments, from 0.
	Index     int
	Name      string
	Type      string
	ByteCount uint64
	// ur://mail/<repo>/<yyyymm>/<message>/<index>: the message's repo, month and id, which the bytes stay inside
	// (§15.7: attachments are never extracted, since content addressing would leak equality).
	Link string
}

// One message as Read returns it.
type MailReadResult struct {
	// The repo the message is in: the mailbox, or a group's.
	RepoId Id
	Entry  *protocol.IndexEntry
	Flags  *MailFlags
	Spam   bool
	// The first text part's text, decoded, at most the parse's bound.
	Text        string
	Headers     []*MailReadHeader
	Attachments []*MailReadAttachment
	// More attachments than Attachments lists.
	AttachmentCount int
	Trust           MailTrust
	// The label's name and the words stated beside it (§15.5): its basis, never a claim of path confidentiality.
	Label          string
	LabelStatement string
}

// The mailbox's view over the bound repos, built once a mailbox.
func (self *MailClient) view() (*MailView, error) {
	mailboxId, err := self.mailboxId()
	if err != nil {
		return nil, err
	}
	_, parts, err := self.bound()
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if view := self.views[mailboxId]; view != nil {
		return view, nil
	}
	view := NewMailView(&MailViewArgs{
		MailboxId: mailboxId,
		Mailbox:   parts.store(mailboxId),
		Groups: func(ctx context.Context, repoId Id) (mailStore, error) {
			return parts.store(repoId), nil
		},
		Settings: self.settings.Store,
	})
	self.views[mailboxId] = view
	return view, nil
}

// One page of the member's mail (mail_list), newest first.
func (self *MailClient) List(ctx context.Context, args *MailListArgs) (*MailListPage, error) {
	view, err := self.view()
	if err != nil {
		return nil, err
	}
	return view.List(ctx, args)
}

// The entries of one address (ur://mail/{alias}): the folder's pages read through until a page's worth of address's
// entries, at most AddressScanMaxCount entries read, so a mailbox of other mail costs a bounded read. address is
// compared as an IndexEntry holds it, lowercase. Next resumes where the scan stopped.
func (self *MailClient) ListAddress(ctx context.Context, address string, args *MailListArgs) (*MailListPage, error) {
	if address == "" {
		return nil, fmt.Errorf("%w: no address", ErrMailClientInvalid)
	}
	address = strings.ToLower(address)
	view, err := self.view()
	if err != nil {
		return nil, err
	}
	scan := &MailListArgs{}
	if args != nil {
		copied := *args
		scan = &copied
	}
	limit := scan.Limit
	if limit <= 0 {
		limit = self.settings.Store.PageEntryCount
	}
	result := &MailListPage{}
	scanned := 0
	for {
		page, err := view.List(ctx, scan)
		if err != nil {
			return nil, err
		}
		result.Unreadable += page.Unreadable
		for _, entry := range page.Entries {
			scanned += 1
			if strings.ToLower(entry.Entry.GetAddress()) == address {
				result.Entries = append(result.Entries, entry)
			}
			if limit <= len(result.Entries) || self.settings.AddressScanMaxCount <= scanned {
				result.Next = &MailListCursor{Time: entry.Entry.GetTime(), Id: mailEntryId(entry.Entry)}
				return result, nil
			}
		}
		if page.Next == nil {
			return result, nil
		}
		scan.After = page.Next
	}
}

// entry's message id, zero where it holds none.
func mailEntryId(entry *protocol.IndexEntry) Id {
	id, _ := IdFromBytes(entry.GetId())
	return id
}

// One message (mail_read): see the file header's read row.
func (self *MailClient) Read(ctx context.Context, args *MailReadArgs) (*MailReadResult, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no message", ErrMailClientInvalid)
	}
	view, err := self.view()
	if err != nil {
		return nil, err
	}
	viewEntry, err := view.Entry(ctx, args.Month, args.Id)
	if err != nil {
		return nil, err
	}
	binding, parts, err := self.bound()
	if err != nil {
		return nil, err
	}
	raw, _, err := parts.store(viewEntry.RepoId).Read(ctx, MailMessagePath(args.Month, args.Id), self.settings.ReadMaxByteCount)
	if err != nil {
		return nil, err
	}
	parsed, err := MailParseMessage(bytes.NewReader(raw), self.settings.Ingest.Parse)
	if err != nil {
		return nil, err
	}
	entry := viewEntry.Entry
	result := &MailReadResult{
		RepoId:          viewEntry.RepoId,
		Entry:           entry,
		Flags:           viewEntry.Flags,
		Spam:            viewEntry.Spam,
		Text:            parsed.Text,
		Headers:         mailReadHeaders(raw, self.settings.ReadHeaderMaxCount, self.settings.ReadHeaderValueMaxByteCount),
		AttachmentCount: parsed.AttachmentCount,
		Trust:           MailTrustMember,
	}
	if MailEntryUntrusted(entry) {
		result.Trust = MailTrustUntrusted
	}
	for index, attachment := range parsed.Attachments {
		result.Attachments = append(result.Attachments, &MailReadAttachment{
			Index:     index,
			Name:      attachment.GetName(),
			Type:      attachment.GetType(),
			ByteCount: attachment.GetSize(),
			Link:      fmt.Sprintf("ur://mail/%s/%s/%s/%d", viewEntry.RepoId, args.Month, args.Id, index),
		})
	}
	burner := false
	if binding.Network != nil {
		if recipient, err := ParseMailRecipient(binding.Network().Root, entry.GetAddress()); err == nil {
			burner = recipient.Kind == MailAddressKindBurner
		}
	}
	// whether the recipient's domain publishes an MTA-STS policy is not known here, so no basis cites one
	label := MailLabelOfEntry(entry, nil, burner, false)
	result.Label = mailLabelName(label.Label)
	result.LabelStatement = label.Statement()
	return result, nil
}

// The header fields of raw that Read returns, in mailReadHeaderNames' order, at most maxCount, each one line of its
// decoded value held to maxByteCount bytes of valid UTF-8. A header that does not parse gives what parsed before it.
func mailReadHeaders(raw []byte, maxCount int, maxByteCount int) []*MailReadHeader {
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
	header, _ := reader.ReadMIMEHeader()
	decoder := &mime.WordDecoder{}
	headers := []*MailReadHeader{}
	for _, name := range mailReadHeaderNames {
		for _, value := range header.Values(name) {
			if maxCount <= len(headers) {
				return headers
			}
			decoded, err := decoder.DecodeHeader(value)
			if err != nil {
				decoded = value
			}
			headers = append(headers, &MailReadHeader{Name: name, Value: mailReadHeaderValue(decoded, maxByteCount)})
		}
	}
	return headers
}

// value as one line: CR, LF and other controls as spaces, runs of space as one, invalid UTF-8 replaced, and at most
// maxByteCount bytes, cut on a rune's edge.
func mailReadHeaderValue(value string, maxByteCount int) string {
	builder := strings.Builder{}
	space := false
	for _, r := range strings.ToValidUTF8(value, "�") {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		if r == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		if maxByteCount < builder.Len()+utf8.RuneLen(r) {
			break
		}
		builder.WriteRune(r)
	}
	return strings.TrimSpace(builder.String())
}
