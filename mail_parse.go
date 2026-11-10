//go:build !ios_extension

// §15.7's message walk (R-MAIL-1, D-MAIL-5, D-MAIL-14): what an IndexEntry, a reader's list, the spam score and
// the code check take from a message's bytes, by one bounded pass with emersion/go-message's textproto. It keeps
// From, Subject, Message-ID and the thread's first id from the header, the first text part's start, and each
// attachment's name, media type and size as carried. It never decodes an attachment, never enters a message/rfc822
// part, and never looks anything up: a message is judged from the evidence sealed at reception (D-MAIL-14), so
// nothing here reaches DNS.
//
// The walk is bounded in settings (MailParseSettings): the header section's bytes, each part header's bytes, the
// multipart nesting, the parts visited and the bytes decoded. A bound stops only what it bounds, and the message
// still yields what was read before it, so a zip-bomb-shaped nesting gives an entry with its cut marked
// (MailParsed.Cut). Malformed MIME is read as far as it parses, never an error: a header line that does not parse
// is passed over, and a part that does not parse ends the walk. An error is only the reader's own, such as a store
// failing mid-read, which the caller retries.
//
// The first text part is the first text/plain body part, else the first text/html one with its markup stripped.
// Its transfer encoding is undone (base64, quoted-printable), its charset decoded as mail_parse_text.go says, and
// every value cleaned there before it is kept, since each is a sender's and reaches IMAP clients, agents and
// indexes. go-message's charset package, which sets a process-wide reader, is not linked, and nothing here reads
// message.CharsetReader.
//
// On every leg: a page Worker reads messages too (R-MAIL-13). This is the one file that links go-message. Safe for
// concurrent use.

package sidecar

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"

	"github.com/emersion/go-message/textproto"

	"github.com/urnetwork/sidecar/protocol"
)

// A thread key's bytes (MAIL-FORMAT.md). A format value.
const mailThreadKeyByteCount = 16

// RFC 2046 §5.1.1's longest boundary. A longer one makes its multipart opaque, since go-message's 4,096-byte scan
// window must hold a boundary to find it.
const mailBoundaryMaxByteCount = 70

// The most of a From value the address parser reads: an address and a display name's worth. The rest of a longer
// one names no address a list shows.
const mailFromParseMaxByteCount = 4 * 1024

// The bytes one buffered reader reads ahead: go-message's multipart scan window, and this walk's own header reader.
const mailParseBufferByteCount = 4 * 1024

// Bounds on one message's walk (MAIL-M7-11). The defaults hold a walk of a 50 MiB message to one read of its bytes
// and about 1 MiB of memory at most, most of it a header at its bound.
type MailParseSettings struct {
	// The most bytes of the top-level header section read, beside one buffer's read-ahead. §15.5's checks read
	// 256 KiB of it, and so does this. Past it the walk keeps the fields it read and reads no body, since the
	// fields that say what the body is may come after the cut. Non-positive reads nothing.
	HeaderMaxByteCount int
	// The most bytes of one part's header section, beside one buffer's read-ahead per level. Real part headers
	// take well under 1 KiB. Past it the walk stops, since a multipart reader cannot resume past a header it did
	// not finish. Non-positive stops at the first part.
	PartHeaderMaxByteCount int
	// The deepest multipart the walk enters, a multipart message's own parts being depth 1. Real mail nests 3 or
	// 4 deep. A multipart past it is read through whole, its parts unvisited. Non-positive enters none.
	MaxDepth int
	// The most parts the walk visits, the message's own entity and multiparts among them, past which it stops.
	// Non-positive visits none.
	MaxPartCount int
	// The most bytes decoded from text parts, which are all the walk decodes: the first text part's text that
	// MailParsed.Text keeps, enough for a snippet, a code and a spam score. Non-positive decodes none.
	DecodedMaxByteCount int
}

// The bounds every caller takes unless it has a reason not to.
func DefaultMailParseSettings() *MailParseSettings {
	return &MailParseSettings{
		HeaderMaxByteCount:     256 * 1024,
		PartHeaderMaxByteCount: 16 * 1024,
		MaxDepth:               8,
		MaxPartCount:           256,
		DecodedMaxByteCount:    64 * 1024,
	}
}

// What a bound or malformed MIME cut from a walk. None means the walk read the whole message.
type MailParseCut uint32

const (
	// The header section passed HeaderMaxByteCount: its later fields and the body went unread.
	MailParseCutHeader MailParseCut = 1 << iota
	// A part's header passed PartHeaderMaxByteCount, and the walk stopped there.
	MailParseCutPartHeader
	// A multipart nested past MaxDepth, which the walk read through unvisited.
	MailParseCutDepth
	// The message had more parts than MaxPartCount, and the walk stopped there.
	MailParseCutParts
	// Text passed DecodedMaxByteCount, and the rest went undecoded.
	MailParseCutDecoded
	// More attachments than an IndexEntry lists, the rest counted and not listed.
	MailParseCutAttachments
	// MIME that did not parse: a header line passed over, or a multipart or part the walk stopped at.
	MailParseCutMalformed
)

// What a walk kept of one message. Every string is cleaned for re-emission and within its IndexEntry cap.
type MailParsed struct {
	// The first From field's value, its encoded words decoded, one line.
	From string
	// The domain of the first From address, lowercase, or empty where it does not parse as one: DMARC's From
	// domain, which ingest's Authentication-Results names.
	FromDomain string
	// The first Subject field's value, its encoded words decoded, one line.
	Subject string
	// The Message-ID's id without its brackets, or empty where it has none or one past 256 bytes, since a cut id
	// matches nothing.
	MessageId string
	// The id the thread key hashes (MAIL-FORMAT.md): the first of References, else the first of In-Reply-To, else
	// the Message-ID's, whatever its length. Empty where there is none, and the thread key is the message's id.
	ThreadMessageId string
	// The first text part's text, decoded and cleaned, line breaks kept, at most DecodedMaxByteCount bytes.
	Text string
	// Text as one line of at most 200 bytes (§15.7).
	Snippet string
	// The first 32 attachments, in the message's order.
	Attachments []*protocol.MailAttachment
	// Every attachment the walk met, listed or not.
	AttachmentCount int
	// The parts the walk visited, the message's own entity among them.
	PartCount int
	// The bytes the walk read: the message's length when Cut is 0.
	ByteCount uint64
	Cut       MailParseCut
}

// The thread key of the message whose IndexEntry id is messageId (MAIL-FORMAT.md): the first 16 bytes of SHA-256
// over ThreadMessageId, or messageId itself where there is none.
func (self *MailParsed) ThreadKey(messageId Id) []byte {
	if self.ThreadMessageId == "" {
		return messageId.Bytes()
	}
	sum := sha256.Sum256([]byte(self.ThreadMessageId))
	return sum[:mailThreadKeyByteCount]
}

// A limit the walk set was met. Never returned to a caller: it marks a cut.
var errMailParseLimit = errors.New("mail parse: a bound was met")

// The message's bytes as the walk reads them: counted, the reader's first error kept apart from the end of input,
// and held to a limit the walk sets while go-message reads a header, which it reads to the end however long.
type mailParseSource struct {
	reader    io.Reader
	byteCount uint64
	// whether limitByteCount holds
	limiting       bool
	limitByteCount int64
	// a Read met the limit since it was set
	limited bool
	// the reader's first error other than io.EOF
	err error
}

// Reads at most what the limit leaves, then errMailParseLimit.
func (self *mailParseSource) Read(data []byte) (int, error) {
	if self.limiting {
		if self.limitByteCount <= 0 {
			self.limited = true
			return 0, errMailParseLimit
		}
		if self.limitByteCount < int64(len(data)) {
			data = data[:self.limitByteCount]
		}
	}
	count, err := self.reader.Read(data)
	self.byteCount += uint64(count)
	if self.limiting {
		self.limitByteCount -= int64(count)
	}
	if err != nil && err != io.EOF && self.err == nil {
		self.err = err
	}
	return count, err
}

// Holds the next reads to byteCount, beside what the buffered readers between this and the header may read
// ahead: bufferCount of them.
func (self *mailParseSource) limit(byteCount int, bufferCount int) {
	self.limiting = true
	self.limited = false
	self.limitByteCount = int64(max(byteCount, 0)) + int64(bufferCount)*mailParseBufferByteCount
}

// Lifts the limit.
func (self *mailParseSource) unlimit() {
	self.limiting = false
}

// One walk's state.
type mailParseWalk struct {
	settings *MailParseSettings
	source   *mailParseSource
	parsed   *MailParsed
	// the text kept so far, and whether it came from text/plain
	text      []byte
	textPlain bool
	// bytes decoded so far
	decodedByteCount int
}

// A walk of message under settings, nil taking DefaultMailParseSettings. A reader's own error, such as a store
// failing mid-read, is the only error: a malformed message or a bound gives what was read, its cut marked.
func MailParseMessage(message io.Reader, settings *MailParseSettings) (*MailParsed, error) {
	if settings == nil {
		settings = DefaultMailParseSettings()
	}
	walk := &mailParseWalk{
		settings: settings,
		source:   &mailParseSource{reader: message},
		parsed:   &MailParsed{Attachments: []*protocol.MailAttachment{}},
	}
	walk.message()
	if walk.source.err != nil {
		return nil, walk.source.err
	}
	walk.parsed.ByteCount = walk.source.byteCount
	walk.parsed.Text = mailCleanText(walk.text, max(settings.DecodedMaxByteCount, 0))
	walk.parsed.Snippet = mailSnippet(walk.parsed.Text)
	return walk.parsed, nil
}

// The top-level entity: its header, then its body as a multipart or a leaf.
func (self *mailParseWalk) message() {
	if self.settings.HeaderMaxByteCount <= 0 {
		self.parsed.Cut |= MailParseCutHeader
		return
	}
	buffered := bufio.NewReaderSize(self.source, mailParseBufferByteCount)
	// the first value of each field, by lowercase name
	values := map[string]string{}
	get := func(key string) string {
		return values[strings.ToLower(key)]
	}
	self.source.limit(self.settings.HeaderMaxByteCount, 1)
	// each call that fails passes over the line it failed on, so the limit ends the loop; the count is a second
	// stop, and either leaves the header's end unfound
	ended := false
	for range self.settings.HeaderMaxByteCount {
		header, err := textproto.ReadHeader(buffered)
		fields := header.Fields()
		for fields.Next() {
			key := strings.ToLower(fields.Key())
			if _, ok := values[key]; !ok {
				values[key] = fields.Value()
			}
		}
		if err == nil {
			ended = true
			break
		}
		if self.source.limited || self.source.err != nil {
			break
		}
		self.parsed.Cut |= MailParseCutMalformed
	}
	self.source.unlimit()
	self.headerFields(get)
	if !ended {
		if self.source.err == nil {
			self.parsed.Cut |= MailParseCutHeader
		}
		return
	}
	if self.settings.MaxPartCount <= 0 {
		self.parsed.Cut |= MailParseCutParts
		return
	}
	self.parsed.PartCount = 1
	self.entity(get, buffered, 0)
}

// From, Subject, Message-ID and the thread's first id, from the top-level header.
func (self *mailParseWalk) headerFields(get func(string) string) {
	from := get("From")
	self.parsed.From = mailCleanLine(mailDecodeWords(from), mailIndexFromMaxByteCount)
	self.parsed.FromDomain = mailFromDomain(from)
	self.parsed.Subject = mailCleanLine(mailDecodeWords(get("Subject")), mailIndexSubjectMaxByteCount)
	// each id cleaned whole, as the thread key hashes it, and empties dropped
	ids := func(key string) []string {
		cleanIds := []string{}
		for _, id := range mailMessageIds(get(key)) {
			if clean := mailCleanLine(id, math.MaxInt); clean != "" {
				cleanIds = append(cleanIds, clean)
			}
		}
		return cleanIds
	}
	messageId := ""
	if messageIds := ids("Message-Id"); len(messageIds) != 0 {
		messageId = messageIds[0]
	}
	if len(messageId) <= mailIndexMessageIdMaxByteCount {
		self.parsed.MessageId = messageId
	}
	self.parsed.ThreadMessageId = messageId
	if threadIds := ids("References"); len(threadIds) != 0 {
		self.parsed.ThreadMessageId = threadIds[0]
	} else if threadIds := ids("In-Reply-To"); len(threadIds) != 0 {
		self.parsed.ThreadMessageId = threadIds[0]
	}
}

// The domain of a From value's first address, lowercase, when it is an LDH domain name; else empty.
func mailFromDomain(from string) string {
	if from == "" || mailFromParseMaxByteCount < len(from) {
		return ""
	}
	parser := &mail.AddressParser{WordDecoder: mailWordDecoder}
	addresses, err := parser.ParseList(from)
	if err != nil || len(addresses) == 0 {
		return ""
	}
	at := strings.LastIndexByte(addresses[0].Address, '@')
	if at < 0 {
		return ""
	}
	domain := dnsAsciiLower(addresses[0].Address[at+1:])
	if domain == "" || dnsDomainMaxByteCount < len(domain) {
		return ""
	}
	for _, label := range strings.Split(domain, ".") {
		if !isDnsLowerLdhLabel(label) {
			return ""
		}
	}
	return domain
}

// A media type and its parameters, from a Content-Type or Content-Disposition value. Parameters that do not parse
// leave the type; a type that does not parse is defaultType, as RFC 2045 §5.2 has for Content-Type. Parameter
// values have their encoded words decoded, which RFC 2047 does not allow but senders write.
func mailMediaType(value string, defaultType string) (string, map[string]string) {
	if strings.TrimSpace(value) == "" {
		return defaultType, map[string]string{}
	}
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil && !errors.Is(err, mime.ErrInvalidMediaParameter) {
		return defaultType, map[string]string{}
	}
	if params == nil {
		params = map[string]string{}
	}
	for key, param := range params {
		params[key] = mailDecodeWords(param)
	}
	return mediaType, params
}

// One entity, its header fields by get: a multipart is walked, a leaf read as text or counted as an attachment.
// depth is the multipart nesting it sits at, 0 for the message itself.
func (self *mailParseWalk) entity(get func(string) string, body io.Reader, depth int) {
	mediaType, params := mailMediaType(get("Content-Type"), "text/plain")
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" || mailBoundaryMaxByteCount < len(boundary) {
			self.parsed.Cut |= MailParseCutMalformed
			io.Copy(io.Discard, body)
			return
		}
		if self.settings.MaxDepth <= depth {
			self.parsed.Cut |= MailParseCutDepth
			io.Copy(io.Discard, body)
			return
		}
		self.multipart(body, boundary, depth+1)
		return
	}
	self.leaf(get, body, mediaType, params)
}

// A multipart's parts, at depth. It stops at the first part it cannot read, and at MaxPartCount.
func (self *mailParseWalk) multipart(body io.Reader, boundary string, depth int) {
	reader := textproto.NewMultipartReader(body, boundary)
	for {
		if self.settings.MaxPartCount <= self.parsed.PartCount {
			self.parsed.Cut |= MailParseCutParts
			return
		}
		// this walk's header reader and one multipart reader a level read ahead
		self.source.limit(self.settings.PartHeaderMaxByteCount, depth+1)
		part, err := reader.NextPart()
		self.source.unlimit()
		if err == io.EOF {
			// a nested multipart's part runs on past the multipart's close, its epilogue, which is read through
			io.Copy(io.Discard, body)
			return
		}
		if err != nil {
			if self.source.limited {
				self.parsed.Cut |= MailParseCutPartHeader
			} else if self.source.err == nil {
				self.parsed.Cut |= MailParseCutMalformed
			}
			return
		}
		self.parsed.PartCount += 1
		self.entity(part.Header.Get, part, depth)
		if self.source.err != nil || self.parsed.Cut&(MailParseCutParts|MailParseCutPartHeader) != 0 {
			return
		}
		// what entity left unread, so the next boundary is found
		io.Copy(io.Discard, part)
	}
}

// A leaf: the first text body part's text kept, an attachment counted and listed, anything else read through.
func (self *mailParseWalk) leaf(get func(string) string, body io.Reader, mediaType string, params map[string]string) {
	disposition, dispositionParams := mailMediaType(get("Content-Disposition"), "")
	name := dispositionParams["filename"]
	if name == "" {
		name = params["name"]
	}
	text := (mediaType == "text/plain" || mediaType == "text/html") && disposition != "attachment" && name == ""
	if !text {
		self.attachment(body, mediaType, name)
		return
	}
	// text/plain wins over text/html, and the first of each over later ones
	if self.textPlain || (mediaType == "text/html" && len(self.text) != 0) {
		io.Copy(io.Discard, body)
		return
	}
	self.decodeText(get, body, mediaType, params["charset"])
}

// Reads an attachment through, counting its bytes as carried, and lists it while the IndexEntry has room.
func (self *mailParseWalk) attachment(body io.Reader, mediaType string, name string) {
	size, _ := io.Copy(io.Discard, body)
	self.parsed.AttachmentCount += 1
	if mailIndexAttachmentMaxCount <= len(self.parsed.Attachments) {
		self.parsed.Cut |= MailParseCutAttachments
		return
	}
	self.parsed.Attachments = append(self.parsed.Attachments, &protocol.MailAttachment{
		Name: mailCleanLine(name, mailIndexAttachmentNameMaxByteCount),
		Type: mailCleanLine(mediaType, mailIndexAttachmentTypeMaxByteCount),
		Size: uint64(size),
	})
}

// Decodes a text body part within what DecodedMaxByteCount leaves and keeps it as the text, html's markup
// stripped, then reads the rest of the part through.
func (self *mailParseWalk) decodeText(get func(string) string, body io.Reader, mediaType string, charset string) {
	remaining := self.settings.DecodedMaxByteCount - self.decodedByteCount
	if remaining <= 0 {
		self.parsed.Cut |= MailParseCutDecoded
		io.Copy(io.Discard, body)
		return
	}
	decoder := mailTransferDecoder(get("Content-Transfer-Encoding"), body)
	// one byte past what is left tells a cut from an end
	decoded, _ := io.ReadAll(io.LimitReader(decoder, int64(remaining)+1))
	if remaining < len(decoded) {
		decoded = decoded[:remaining]
		self.parsed.Cut |= MailParseCutDecoded
	}
	io.Copy(io.Discard, body)
	self.decodedByteCount += len(decoded)
	decoded = mailDecodeCharset(charset, decoded)
	if mediaType == "text/html" {
		decoded = mailHtmlText(decoded)
	} else {
		self.textPlain = true
	}
	self.text = decoded
}

// body with its Content-Transfer-Encoding undone: base64, whitespace ignored, and quoted-printable. 7bit, 8bit,
// binary and anything unknown are read as they are. A decoder stops at its first error, keeping what came before.
func mailTransferDecoder(encoding string, body io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, &mailBase64Reader{reader: body})
	case "quoted-printable":
		return quotedprintable.NewReader(body)
	}
	return body
}

// A base64 body without the spaces and tabs base64's decoder refuses, beside the line breaks it skips itself.
type mailBase64Reader struct {
	reader io.Reader
}

// Reads, dropping spaces and tabs. A read of nothing but them reads again, so a short read is never empty
// without an error, unless the reader's own read was.
func (self *mailBase64Reader) Read(data []byte) (int, error) {
	for {
		count, err := self.reader.Read(data)
		kept := 0
		for _, value := range data[:count] {
			if value != ' ' && value != '\t' {
				data[kept] = value
				kept += 1
			}
		}
		if kept != 0 || err != nil || count == 0 {
			return kept, err
		}
	}
}
