//go:build !sidecar_http

// The octets a send's relation accepts (SPEC.md section 4.2's normal form, Z5 and Z6), made in two
// steps. AssembleSmtpMessage runs before the preamble: it takes MAIL's finished message (§15.10's step
// 4, with BURNER's header rules already applied), puts every header field in the form Z5 proves, drops
// what the edge issues and what no recipient may see, and makes the body 7-bit with lines a DATA
// transaction carries, since MAIL FROM names no BODY= (SPEC.md 4.2). SmtpDkimSign (smtp_dkim_sign.go)
// runs once the preamble is answered OK: it adds the issued X-UR-Ref and Feedback-ID and §14.6's two
// signatures, and its octets are SmtpProofJob.Message.
//
// Everything added after the preamble has a fixed length: X-UR-Ref 36 characters and Feedback-ID 40
// (plan-SMTP-small-readings#3, #4), a selector 26 (#5), t= and x= 10 digits each, bh= 44 and an
// RSA-2048 b= 344. So ByteCount is exact before the edge has issued anything, as the preamble's
// message_byte_count must be (plan-SMTP-preamble-byte-count), and assembly refuses a header block
// past one TLS record before anything is sent.
//
// Assembly is strict where the relation is: one From in Z5.4's form at the declared domain, one
// Message-ID in §14.6's form, a header block of HTAB and printable octets, and nothing else bearing
// the fixed signature's prefix. What it cannot bring into form is ErrSmtpAssemble, which fails the
// send before the preamble, and the sender files a DSN.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Format values (SPEC.md 4.2, §14.6, RFC 5322, RFC 2045, RFC 2047), not settings.
const (
	// The header block is one TLS record's content (SPEC.md 4.2), its final CRLF CRLF included.
	SmtpHeaderBlockMaxByteCount = 16 * 1024
	// RFC 5322 §2.1.1: the most octets in a line, CRLF excluded, which a DATA line also keeps to.
	smtpLineMaxByteCount = 998
	// The issued values' lengths (plan-SMTP-small-readings#3, #4).
	SmtpXUrRefLength     = 36
	SmtpFeedbackIdLength = 40
	// A Message-ID's random part: the lowercase unpadded base32 of 16 random octets, as a selector.
	smtpMessageIdRandomByteCount = 16
	// SPEC.md 4.2: a local part's most octets.
	smtpLocalMaxByteCount = 64
	// RFC 2047 §2: an encoded word's most characters.
	smtpEncodedWordMaxLength = 75
	// RFC 2045 §6.7 and §6.8: an encoded body line's most characters.
	smtpEncodedLineMaxLength = 76
	// The deepest multipart nesting assembly re-encodes, so a hostile message cannot run it out of stack.
	smtpMimeMaxDepth = 16
)

// A message assembly cannot bring into the relation's form. The wrapped detail says what, and never
// quotes the message.
var ErrSmtpAssemble = errors.New("smtp assemble: message refused")

// What AssembleSmtpMessage takes.
type SmtpAssembleArgs struct {
	// RFC 5322 octets as MAIL hands them over (§15.10's step 4): a header block, a blank line, a body.
	// A bare LF is read as CRLF. A bare CR is refused.
	Message []byte
	// d=, which the From's domain must equal: <net>.<root>, a burner's <blabel>.<net>.<root>, or a
	// verified Team domain (§14.6).
	HeaderFromDomain string
	// The domain the Message-ID must name: <net>.<root>, or <blabel>.<net>.<root> for a burner (§14.6).
	MessageIdDomain string
	// SmtpFlagBulk, SmtpFlagRequireTls and SmtpFlagBurner.
	Flags uint32
	// What a Date field says when the message has none.
	Now time.Time
}

// One header field as assembly keeps it: its name as written, its value unfolded and trimmed.
type smtpWireField struct {
	name  string
	value string
}

// Whether the field is named name, compared without case.
func (self *smtpWireField) is(name string) bool {
	return strings.EqualFold(self.name, name)
}

// The field's line: name, colon, space and value, with no CRLF and no fold.
func (self *smtpWireField) line() string {
	if self.value == "" {
		return self.name + ":"
	}
	return self.name + ": " + self.value
}

// A message ready for the preamble: its header fields in Z5's form, its body 7-bit, and room for the
// issued headers and both signatures, so its byte count is known before they exist. Immutable, and
// so safe for concurrent use.
type SmtpWireMessage struct {
	fields []*smtpWireField
	// CRLF throughout, ending in CRLF unless empty, unstuffed.
	body             []byte
	messageId        string
	headerFromDomain string
	flags            uint32
	// The full signature's h=, From oversigned.
	signedFieldNames []string
}

// The Message-ID without its angle brackets, as the preamble's message_id carries it.
func (self *SmtpWireMessage) MessageId() string {
	return self.messageId
}

// d= and the From's domain, as the preamble's header_from_domain carries it.
func (self *SmtpWireMessage) HeaderFromDomain() string {
	return self.headerFromDomain
}

// The preamble's message_byte_count for mode: BDAT's n, the signed message's length, or DATA's octets
// before the end mark, its dot-stuffed length (§14.5, Z4, Z6). Exact before the edge has issued
// anything, since what is added after has fixed lengths. SmtpModeUnknown is refused: the caller
// declares its pin's mode, else BDAT's (plan-SMTP-preamble-byte-count).
func (self *SmtpWireMessage) ByteCount(mode SmtpMode) (uint64, error) {
	if mode != SmtpModeBdat && mode != SmtpModeData {
		return 0, fmt.Errorf("%w: no byte count for mode %d", ErrSmtpAssemble, mode)
	}
	message, err := self.render(smtpDkimPlaceholderValues(), nil)
	if err != nil {
		return 0, err
	}
	if mode == SmtpModeData {
		return smtpDotStuffedByteCount(message), nil
	}
	return uint64(len(message)), nil
}

// The octets message takes in DATA mode: each line starting with a dot gains one (RFC 5321 §4.5.2),
// which is how the prover stuffs it. Z5.3 refuses a header line starting with a dot, so only body lines
// count.
func smtpDotStuffedByteCount(message []byte) uint64 {
	count := uint64(len(message))
	lineStart := true
	for _, octet := range message {
		if lineStart && octet == '.' {
			count += 1
		}
		lineStart = octet == '\n'
	}
	return count
}

// A fresh Message-ID for domain without its angle brackets: 26 lowercase base32 characters of 16
// random octets, @, domain (§14.6). domain is <net>.<root>, or <blabel>.<net>.<root> for a burner.
// MAIL calls this when it writes the sent copy, so the copy and every delivered copy share it.
func NewSmtpMessageId(domain string) (string, error) {
	if !smtpDkimDomainForm(domain) {
		return "", fmt.Errorf("%w: a message id domain outside its form", ErrSmtpAssemble)
	}
	random := make([]byte, smtpMessageIdRandomByteCount)
	if _, err := cryptorand.Read(random); err != nil {
		return "", err
	}
	return smtpDkimBase32.EncodeToString(random) + "@" + domain, nil
}

// Whether an octet is in SPEC.md 4.2's local set: RFC 5321's atext and dot, less % and !.
func smtpLocalOctet(octet byte) bool {
	switch {
	case 'a' <= octet && octet <= 'z', 'A' <= octet && octet <= 'Z', '0' <= octet && octet <= '9':
		return true
	}
	return strings.IndexByte("#$&'*+-/=?^_`{|}~.", octet) != -1
}

// Whether a local part is one MAIL, RCPT or From can carry (SPEC.md 4.2): 1 to 64 octets of the local
// set, with no leading, trailing or doubled dot, which the sidecar keeps to though the relation does
// not.
func smtpLocalPartForm(local string) bool {
	if local == "" || smtpLocalMaxByteCount < len(local) || local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for i := range len(local) {
		if !smtpLocalOctet(local[i]) {
			return false
		}
	}
	return true
}

// An envelope address split as SPEC.md 4.2 takes it: its local part, and its domain in lowercase. Not
// ok for a quoted local part, a source route, a non-ASCII address, or anything else no MAIL or RCPT
// template can express; such a recipient gets a DSN instead of a place in the transaction.
func SplitSmtpEnvelopeAddress(address string) (local string, domain string, ok bool) {
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return "", "", false
	}
	local, domain = address[:at], strings.ToLower(address[at+1:])
	if !smtpLocalPartForm(local) || !smtpDomainForm(domain) {
		return "", "", false
	}
	return local, domain, true
}

// Whether a phrase word may stand as written in Z5.4's From: RFC 5322's atext within the local set,
// which leaves out the dot RFC 5322 reads as obsolete syntax.
func smtpPhraseWordForm(word string) bool {
	if word == "" || strings.Contains(word, "=?") {
		return false
	}
	for i := range len(word) {
		if word[i] == '.' || !smtpLocalOctet(word[i]) {
			return false
		}
	}
	return true
}

// text as RFC 2047 B encoded words in UTF-8, each at most 75 characters and split on rune boundaries,
// separated by single spaces. Every character of the result is in SPEC.md 4.2's local set or a space,
// so it fits Z5.4's phrase and any unstructured field.
func smtpEncodeWords(text string) string {
	const prefix, suffix = "=?utf-8?b?", "?="
	// base64 of 3 octets is 4 characters, so this many octets fill a word
	chunkByteCount := (smtpEncodedWordMaxLength - len(prefix) - len(suffix)) / 4 * 3
	var words []string
	for 0 < len(text) {
		end := min(chunkByteCount, len(text))
		for end < len(text) && !utf8.RuneStart(text[end]) {
			end -= 1
		}
		words = append(words, prefix+base64.StdEncoding.EncodeToString([]byte(text[:end]))+suffix)
		text = text[end:]
	}
	return strings.Join(words, " ")
}

// Whether a value holds an octet the header block may not: anything but HTAB and SP to ~ (Z5.1).
func smtpHeaderValueNeedsEncoding(value string) bool {
	for i := range len(value) {
		if octet := value[i]; octet != '\t' && (octet < ' ' || '~' < octet) {
			return true
		}
	}
	return false
}

// The phrase of Z5.4's From for a display name: as written when every word may stand in it, else
// encoded words.
func smtpFromPhrase(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("%w: the From name is not utf-8", ErrSmtpAssemble)
	}
	words := strings.Split(name, " ")
	plain := true
	for _, word := range words {
		plain = plain && smtpPhraseWordForm(word)
	}
	if plain {
		return name, nil
	}
	return smtpEncodeWords(name), nil
}

// Z5.4's From line for value at domain: From: [phrase SP] <local@domain>, one address on one line.
func smtpFromLine(value string, domain string) (string, error) {
	address, err := mail.ParseAddress(value)
	if err != nil {
		return "", fmt.Errorf("%w: From is not one address", ErrSmtpAssemble)
	}
	at := strings.LastIndexByte(address.Address, '@')
	if at < 0 || !strings.EqualFold(address.Address[at+1:], domain) {
		return "", fmt.Errorf("%w: From is not in the signing domain", ErrSmtpAssemble)
	}
	local := address.Address[:at]
	if !smtpLocalPartForm(local) {
		return "", fmt.Errorf("%w: From's local part is outside its set", ErrSmtpAssemble)
	}
	phrase, err := smtpFromPhrase(address.Name)
	if err != nil {
		return "", err
	}
	angle := "<" + local + "@" + domain + ">"
	if phrase != "" {
		angle = phrase + " " + angle
	}
	if smtpLineMaxByteCount < len("From: ")+len(angle) {
		return "", fmt.Errorf("%w: From passes one line", ErrSmtpAssemble)
	}
	return angle, nil
}

// The Message-ID's value without its angle brackets, held to §14.6's form at domain.
func smtpMessageIdValue(value string, domain string) (string, error) {
	value = strings.Trim(value, " \t")
	if len(value) < 2 || value[0] != '<' || value[len(value)-1] != '>' {
		return "", fmt.Errorf("%w: Message-ID is not one angle address", ErrSmtpAssemble)
	}
	id := value[1 : len(value)-1]
	random, idDomain, found := strings.Cut(id, "@")
	if !found || idDomain != domain || !smtpDkimSelectorForm(random) {
		return "", fmt.Errorf("%w: Message-ID is not the sidecar's", ErrSmtpAssemble)
	}
	return id, nil
}

// Header fields whose value is a list of addresses, which may be re-encoded address by address.
var smtpAddressFieldNames = []string{"to", "cc", "reply-to", "sender", "resent-to", "resent-cc", "resent-from", "resent-sender"}

// Whether a field's value is unstructured text, which encoded words may carry whole (RFC 2047 §5).
func smtpUnstructuredField(name string) bool {
	lower := strings.ToLower(name)
	return lower == "subject" || lower == "comments" || lower == "keywords" || strings.HasPrefix(lower, "x-")
}

// A field's value with every octet the header block may not hold encoded: encoded words for
// unstructured text, each address re-encoded for an address list. Anything else holding such an octet
// is refused.
func smtpEncodeFieldValue(field *smtpWireField) (string, error) {
	if !smtpHeaderValueNeedsEncoding(field.value) {
		return field.value, nil
	}
	if !utf8.ValidString(field.value) {
		return "", fmt.Errorf("%w: a header field is not utf-8", ErrSmtpAssemble)
	}
	if smtpUnstructuredField(field.name) {
		return smtpEncodeWords(field.value), nil
	}
	if slices.Contains(smtpAddressFieldNames, strings.ToLower(field.name)) {
		addresses, err := mail.ParseAddressList(field.value)
		if err != nil {
			return "", fmt.Errorf("%w: an address field does not parse", ErrSmtpAssemble)
		}
		encoded := make([]string, 0, len(addresses))
		for _, address := range addresses {
			// no SMTPUTF8: an address itself must be ASCII
			if smtpHeaderValueNeedsEncoding(address.Address) {
				return "", fmt.Errorf("%w: an address is not ascii", ErrSmtpAssemble)
			}
			text := address.String()
			if address.Name != "" {
				phrase, err := smtpFromPhrase(address.Name)
				if err != nil {
					return "", err
				}
				text = phrase + " <" + address.Address + ">"
			}
			encoded = append(encoded, text)
		}
		return strings.Join(encoded, ", "), nil
	}
	return "", fmt.Errorf("%w: a structured header field holds non-ascii octets", ErrSmtpAssemble)
}

// A field's line folded before whitespace so no line passes 998 octets, CRLF ending each. A word longer
// than a line is refused.
func smtpFoldLine(line string) ([]byte, error) {
	var out bytes.Buffer
	for smtpLineMaxByteCount < len(line) {
		cut := strings.LastIndexAny(line[:smtpLineMaxByteCount+1], " \t")
		if cut <= 0 {
			return nil, fmt.Errorf("%w: a header word passes one line", ErrSmtpAssemble)
		}
		out.WriteString(line[:cut])
		out.WriteString("\r\n")
		line = line[cut:]
	}
	out.WriteString(line)
	out.WriteString("\r\n")
	return out.Bytes(), nil
}

// message with every bare LF made CRLF, or ErrSmtpAssemble for a bare CR.
func smtpNormalizeLines(message []byte) ([]byte, error) {
	normalized := make([]byte, 0, len(message)+len(message)/64)
	for i, octet := range message {
		switch octet {
		case '\r':
			if i+1 == len(message) || message[i+1] != '\n' {
				return nil, fmt.Errorf("%w: a bare CR", ErrSmtpAssemble)
			}
		case '\n':
			if i == 0 || message[i-1] != '\r' {
				normalized = append(normalized, '\r')
			}
		}
		normalized = append(normalized, octet)
	}
	return normalized, nil
}

// The header fields of a header block (CRLF normalized, without its blank line), unfolded and
// trimmed. A line before any field opens with whitespace, or a line with no field name, is refused,
// as is a field name of anything but 21-7E or opening with a dot (Z5.3).
func smtpParseFields(header []byte) ([]*smtpWireField, error) {
	var fields []*smtpWireField
	if len(header) == 0 {
		return fields, nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(header), "\r\n"), "\r\n") {
		if line != "" && (line[0] == ' ' || line[0] == '\t') {
			if len(fields) == 0 {
				return nil, fmt.Errorf("%w: the header block opens with a continuation", ErrSmtpAssemble)
			}
			last := fields[len(fields)-1]
			last.value += line
			continue
		}
		name, value, found := strings.Cut(line, ":")
		name = strings.TrimRight(name, " \t")
		if !found || name == "" || name[0] == '.' {
			return nil, fmt.Errorf("%w: a header line has no field name", ErrSmtpAssemble)
		}
		for i := range len(name) {
			if name[i] <= ' ' || '~' < name[i] {
				return nil, fmt.Errorf("%w: a field name outside 21-7E", ErrSmtpAssemble)
			}
		}
		fields = append(fields, &smtpWireField{name: name, value: value})
	}
	for _, field := range fields {
		field.value = strings.Trim(field.value, " \t")
	}
	return fields, nil
}

// A header block and its body, split at the first empty line. A message with no empty line is all
// header.
func smtpSplitMessage(message []byte) (header []byte, body []byte) {
	if bytes.HasPrefix(message, []byte("\r\n")) {
		return nil, message[2:]
	}
	if index := bytes.Index(message, []byte("\r\n\r\n")); 0 <= index {
		return message[:index+2], message[index+4:]
	}
	return message, nil
}

// The first value of name among fields, or empty.
func smtpFieldValue(fields []*smtpWireField, name string) string {
	for _, field := range fields {
		if field.is(name) {
			return field.value
		}
	}
	return ""
}

// fields with every one named name replaced by one of value, or with one added at the end.
func smtpSetField(fields []*smtpWireField, name string, value string) []*smtpWireField {
	kept := make([]*smtpWireField, 0, len(fields)+1)
	for _, field := range fields {
		if !field.is(name) {
			kept = append(kept, field)
		}
	}
	return append(kept, &smtpWireField{name: name, value: value})
}

// Whether a body may go as it is: no NUL and nothing past 7F, no bare CR or LF, and no line past 998
// octets (RFC 5321 §4.5.3.1.6, RFC 2045 §2.7).
func smtpBodySafe(body []byte) bool {
	lineByteCount := 0
	for i, octet := range body {
		switch {
		case octet == 0 || 0x7f < octet:
			return false
		case octet == '\r':
			if i+1 == len(body) || body[i+1] != '\n' {
				return false
			}
		case octet == '\n':
			if i == 0 || body[i-1] != '\r' {
				return false
			}
			lineByteCount = -1
		}
		lineByteCount += 1
		// the CR of a line's end is counted, so a line of exactly 998 octets reaches 999 here
		if smtpLineMaxByteCount+1 < lineByteCount {
			return false
		}
	}
	return true
}

// A body's octets under its transfer encoding, decoded.
func smtpDecodeTransfer(encoding string, body []byte) ([]byte, error) {
	switch encoding {
	case "", "7bit", "8bit", "binary":
		return body, nil
	case "quoted-printable":
		decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		if err != nil {
			return nil, fmt.Errorf("%w: a quoted-printable body does not decode", ErrSmtpAssemble)
		}
		return decoded, nil
	case "base64":
		stripped := bytes.Map(func(r rune) rune {
			if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, body)
		decoded, err := base64.StdEncoding.DecodeString(string(stripped))
		if err != nil {
			return nil, fmt.Errorf("%w: a base64 body does not decode", ErrSmtpAssemble)
		}
		return decoded, nil
	}
	return nil, fmt.Errorf("%w: an unknown transfer encoding", ErrSmtpAssemble)
}

// raw encoded for a 7-bit transaction: quoted-printable for text, which keeps it readable, else base64,
// either wrapped at 76 characters. Returns the octets and the encoding's name.
func smtpEncodeTransfer(mediaType string, raw []byte) ([]byte, string, error) {
	var out bytes.Buffer
	if strings.HasPrefix(mediaType, "text/") {
		writer := quotedprintable.NewWriter(&out)
		if _, err := writer.Write(raw); err != nil {
			return nil, "", err
		}
		if err := writer.Close(); err != nil {
			return nil, "", err
		}
		return out.Bytes(), "quoted-printable", nil
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	for 0 < len(encoded) {
		take := min(len(encoded), smtpEncodedLineMaxLength)
		out.WriteString(encoded[:take])
		out.WriteString("\r\n")
		encoded = encoded[take:]
	}
	return out.Bytes(), "base64", nil
}

// One MIME entity's fields and body made 7-bit, recursing through multipart bodies. topLevel is the
// message itself, whose defaults differ from a part's: a message re-encoded gains MIME-Version, and a
// Content-Type naming UTF-8 where it had none.
func smtpWireEntity(fields []*smtpWireField, body []byte, topLevel bool, depth int) ([]*smtpWireField, []byte, error) {
	if smtpBodySafe(body) {
		return fields, body, nil
	}
	if smtpMimeMaxDepth < depth {
		return nil, nil, fmt.Errorf("%w: MIME nests too deep", ErrSmtpAssemble)
	}
	contentType := smtpFieldValue(fields, "Content-Type")
	mediaType, params := "text/plain", map[string]string{}
	if contentType != "" {
		if parsed, parsedParams, err := mime.ParseMediaType(contentType); err == nil {
			mediaType, params = parsed, parsedParams
		}
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		reencoded, err := smtpWireMultipart(body, params["boundary"], depth)
		return fields, reencoded, err
	}
	if strings.HasPrefix(mediaType, "message/") {
		return nil, nil, fmt.Errorf("%w: an enclosed message is not 7-bit", ErrSmtpAssemble)
	}
	encoding := strings.ToLower(strings.Trim(smtpFieldValue(fields, "Content-Transfer-Encoding"), " \t"))
	raw, err := smtpDecodeTransfer(encoding, body)
	if err != nil {
		return nil, nil, err
	}
	encoded, newEncoding, err := smtpEncodeTransfer(mediaType, raw)
	if err != nil {
		return nil, nil, err
	}
	fields = smtpSetField(fields, "Content-Transfer-Encoding", newEncoding)
	if topLevel {
		if smtpFieldValue(fields, "MIME-Version") == "" {
			fields = smtpSetField(fields, "MIME-Version", "1.0")
		}
		if contentType == "" {
			fields = smtpSetField(fields, "Content-Type", "text/plain; charset=utf-8")
		}
	}
	return fields, encoded, nil
}

// A multipart body with each part made 7-bit. The boundary, the delimiters and a 7-bit preamble and
// epilogue stay as they were (RFC 2046 §5.1.1).
func smtpWireMultipart(body []byte, boundary string, depth int) ([]byte, error) {
	if boundary == "" {
		return nil, fmt.Errorf("%w: a multipart body has no boundary", ErrSmtpAssemble)
	}
	delimiter := "--" + boundary
	lines := strings.Split(string(body), "\r\n")
	var out bytes.Buffer
	var part []string
	inPart, closed := false, false
	flush := func() error {
		if !inPart {
			// the preamble
			preamble := strings.Join(part, "\r\n")
			if !smtpBodySafe([]byte(preamble)) {
				return fmt.Errorf("%w: a multipart preamble is not 7-bit", ErrSmtpAssemble)
			}
			out.WriteString(preamble)
			return nil
		}
		header, partBody := smtpSplitMessage([]byte(strings.Join(part, "\r\n")))
		partFields, err := smtpParseFields(header)
		if err != nil {
			return err
		}
		for _, field := range partFields {
			if smtpHeaderValueNeedsEncoding(field.value) {
				return fmt.Errorf("%w: a part's header is not 7-bit", ErrSmtpAssemble)
			}
		}
		partFields, partBody, err = smtpWireEntity(partFields, partBody, false, depth+1)
		if err != nil {
			return err
		}
		for _, field := range partFields {
			folded, err := smtpFoldLine(field.line())
			if err != nil {
				return err
			}
			out.Write(folded)
		}
		out.WriteString("\r\n")
		out.Write(bytes.TrimSuffix(partBody, []byte("\r\n")))
		return nil
	}
	for i, line := range lines {
		if closed {
			// the epilogue, kept as written
			epilogue := strings.Join(lines[i:], "\r\n")
			if !smtpBodySafe([]byte(epilogue)) {
				return nil, fmt.Errorf("%w: a multipart epilogue is not 7-bit", ErrSmtpAssemble)
			}
			out.WriteString("\r\n")
			out.WriteString(epilogue)
			break
		}
		trimmed := strings.TrimRight(line, " \t")
		if trimmed == delimiter || trimmed == delimiter+"--" {
			if err := flush(); err != nil {
				return nil, err
			}
			if out.Len() != 0 || inPart {
				out.WriteString("\r\n")
			}
			out.WriteString(trimmed)
			if trimmed == delimiter+"--" {
				closed = true
			} else {
				out.WriteString("\r\n")
			}
			inPart = true
			part = part[:0]
			continue
		}
		part = append(part, line)
	}
	if !closed {
		return nil, fmt.Errorf("%w: a multipart body never closes", ErrSmtpAssemble)
	}
	if !bytes.HasSuffix(out.Bytes(), []byte("\r\n")) {
		out.WriteString("\r\n")
	}
	return out.Bytes(), nil
}

// The full signature's h=: each field §14.6's first signature covers, once per instance the message
// holds, then From once more, so a From added later breaks it (oversigning).
func smtpSignedFieldNames(fields []*smtpWireField) []string {
	covered := []string{
		"from", "to", "cc", "subject", "date", "message-id", "reply-to", "in-reply-to", "references",
		"mime-version", "content-type", "content-transfer-encoding", "list-id", "list-unsubscribe",
		"list-unsubscribe-post",
	}
	var names []string
	for _, name := range covered {
		for _, field := range fields {
			if field.is(name) {
				names = append(names, name)
			}
		}
	}
	// the issued fields, which render adds, each once
	names = append(names, "x-ur-ref", "feedback-id")
	return append(names, "from")
}

// Builds the message for the preamble (this file's header). args.Message is MAIL's; the result holds
// no reference to it.
func AssembleSmtpMessage(args *SmtpAssembleArgs) (*SmtpWireMessage, error) {
	if args == nil || !smtpDkimDomainForm(args.HeaderFromDomain) || !smtpDkimDomainForm(args.MessageIdDomain) {
		return nil, fmt.Errorf("%w: a domain outside its form", ErrSmtpAssemble)
	}
	if args.Flags&^SmtpFlagsKnown != 0 {
		return nil, fmt.Errorf("%w: unknown flags %#x", ErrSmtpAssemble, args.Flags)
	}
	normalized, err := smtpNormalizeLines(args.Message)
	if err != nil {
		return nil, err
	}
	header, body := smtpSplitMessage(normalized)
	parsed, err := smtpParseFields(header)
	if err != nil {
		return nil, err
	}
	wire := &SmtpWireMessage{headerFromDomain: args.HeaderFromDomain, flags: args.Flags}
	bulk := args.Flags&SmtpFlagBulk != 0
	var fields []*smtpWireField
	var fromCount, messageIdCount, dateCount, unsubscribeCount int
	for _, field := range parsed {
		switch {
		// what no recipient sees, what an MTA adds, and what the edge issues
		case field.is("Bcc"), field.is("Return-Path"), field.is("X-UR-Ref"), field.is("Feedback-ID"):
			continue
		// RFC 8689 §4.1: a REQUIRETLS message carries no TLS-Required: No
		case field.is("TLS-Required") && args.Flags&SmtpFlagRequireTls != 0:
			continue
		// Z5.6 counts exactly one, which a BULK message gains below
		case field.is("List-Unsubscribe-Post") && bulk:
			continue
		// Z5.5 counts exactly one line with the fixed prefix, which SmtpDkimSign adds
		case field.is("DKIM-Signature") && strings.HasPrefix(field.line(), smtpDkimFixedPrefix):
			continue
		case field.is("From"):
			fromCount += 1
			value, err := smtpFromLine(field.value, args.HeaderFromDomain)
			if err != nil {
				return nil, err
			}
			fields = append(fields, &smtpWireField{name: "From", value: value})
			continue
		case field.is("Message-ID"):
			messageIdCount += 1
			id, err := smtpMessageIdValue(field.value, args.MessageIdDomain)
			if err != nil {
				return nil, err
			}
			wire.messageId = id
			fields = append(fields, &smtpWireField{name: "Message-ID", value: "<" + id + ">"})
			continue
		case field.is("Date"):
			dateCount += 1
		case field.is("List-Unsubscribe"):
			unsubscribeCount += 1
			if bulk && !strings.Contains(strings.ToLower(field.value), "<https://") {
				return nil, fmt.Errorf("%w: a BULK List-Unsubscribe has no https uri", ErrSmtpAssemble)
			}
		}
		value, err := smtpEncodeFieldValue(field)
		if err != nil {
			return nil, err
		}
		fields = append(fields, &smtpWireField{name: field.name, value: value})
	}
	if fromCount != 1 || messageIdCount != 1 || 1 < dateCount {
		return nil, fmt.Errorf("%w: %d From, %d Message-ID and %d Date fields", ErrSmtpAssemble, fromCount, messageIdCount, dateCount)
	}
	if dateCount == 0 {
		fields = append(fields, &smtpWireField{name: "Date", value: args.Now.UTC().Format(time.RFC1123Z)})
	}
	if bulk {
		// R-SMTP-11 and RFC 8058: one-click unsubscribe, whose fields the full signature covers
		if unsubscribeCount != 1 {
			return nil, fmt.Errorf("%w: a BULK message needs one List-Unsubscribe", ErrSmtpAssemble)
		}
		fields = append(fields, &smtpWireField{name: "List-Unsubscribe-Post", value: "List-Unsubscribe=One-Click"})
	}
	fields, body, err = smtpWireEntity(fields, body, true, 0)
	if err != nil {
		return nil, err
	}
	if 0 < len(body) && !bytes.HasSuffix(body, []byte("\r\n")) {
		body = append(body, '\r', '\n')
	}
	for _, field := range fields {
		if smtpHeaderValueNeedsEncoding(field.value) {
			return nil, fmt.Errorf("%w: a header field is not 7-bit", ErrSmtpAssemble)
		}
	}
	wire.fields = fields
	wire.body = body
	wire.signedFieldNames = smtpSignedFieldNames(fields)
	// the header block's length is fixed now, issued values and signatures included
	message, err := wire.render(smtpDkimPlaceholderValues(), nil)
	if err != nil {
		return nil, err
	}
	if headerEnd := bytes.Index(message, []byte("\r\n\r\n")) + 4; SmtpHeaderBlockMaxByteCount < headerEnd {
		return nil, fmt.Errorf("%w: a %d-octet header block passes one record", ErrSmtpAssemble, headerEnd)
	}
	return wire, nil
}
