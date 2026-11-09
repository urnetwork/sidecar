//go:build !sidecar_http

// §14.6's two DKIM signatures over a SmtpWireMessage, after the preamble's OK. Both are rsa-sha256,
// relaxed/relaxed, with no l= and x= 7 days after t=, and neither covers the other:
//
//   - the full signature, d= and s= first, covers the fields §14.6 lists that the message holds and
//     the issued ones, with From oversigned, so a From added later breaks it;
//   - the fixed signature covers only from:date:message-id:x-ur-ref:feedback-id, so it survives a
//     report that masks recipients (§14.8), and its first line opens with SPEC.md Z5.5's constant
//     prefix, h= ahead of d= and s=, which is how the circuit finds it. SPEC.md's order wins over the
//     plan's, which put d= and s= first.
//
// Each field is folded in one fixed way, and every value in it but bh= is of a fixed length, so the
// octets differ from ByteCount's placeholder rendering only in value, never in length. The issued
// X-UR-Ref and Feedback-ID come from the edge, which is untrusted, so each is held to its exact form
// before it reaches a header: a value holding CRLF would otherwise add fields of the edge's choosing.
//
// The canonicalization here is written from RFC 6376 §3.4 alone, apart from smtpedgeservice's
// verifier, so a slip in either fails the other's tests rather than cancelling out.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Format values (§14.6, SPEC.md Z5.5), not settings.
const (
	// The fixed signature's first octets, which exactly one header line carries (Z5.5).
	smtpDkimFixedPrefix = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; "
	// The full signature's first octets, which differ from the fixed prefix before its h=.
	smtpDkimFullPrefix = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d="
	// t= and x= are decimal seconds of exactly this many digits, 2001 to 2286, so their length is fixed.
	smtpDkimTimeDigitCount = 10
	// An RSA-2048 signature's octets, whose base64 is 344 characters.
	smtpDkimSignatureByteCount = SmtpDkimRsaKeyBitCount / 8
	// b= is folded into lines of this many base64 characters.
	smtpDkimSignatureLineLength = 72
	// X-UR-Ref: 1. then the base32 of 21 octets (plan-SMTP-small-readings#3).
	smtpXUrRefVersion      = "1."
	smtpXUrRefOctetCount   = 21
	smtpNetTokenOctetCount = 16
	smtpFeedbackIdSuffix   = "urnetwork"
)

// What signs a DKIM digest. SmtpDkimSelector is the one a send uses, its key kept in the keychain. Safe
// for concurrent use.
type SmtpDkimSigner interface {
	// s=, SmtpDkimSelectorLength characters.
	DkimSelector() string
	// d=.
	DkimDomain() string
	// RSASSA-PKCS1-v1_5 over a SHA-256 digest, SmtpDkimRsaKeyBitCount bits.
	SignDkim(digest []byte) ([]byte, error)
}

// The values the edge issued in SmtpPreambleResult that the header block carries (§14.6).
type SmtpIssuedHeaders struct {
	XUrRef     string
	FeedbackId string
}

// What SmtpDkimSign takes beside the message.
type SmtpDkimSignArgs struct {
	// The selector the preamble declared, pinned at it.
	Signer SmtpDkimSigner
	Issued *SmtpIssuedHeaders
	// t=, in whole seconds.
	SignTime time.Time
	// x= less t=: §14.6's 7 days, SmtpSenderSettings.DkimExpireTimeout.
	ExpireTimeout time.Duration
}

// Whether a value is the lowercase unpadded base32 of octetCount octets in its one spelling.
func smtpLowerBase32Form(value string, octetCount int) bool {
	decoded, err := smtpDkimBase32.DecodeString(value)
	return err == nil && len(decoded) == octetCount && smtpDkimBase32.EncodeToString(decoded) == value
}

// Whether a value is X-UR-Ref's 36 characters (plan-SMTP-small-readings#3).
func smtpXUrRefForm(value string) bool {
	token, found := strings.CutPrefix(value, smtpXUrRefVersion)
	return found && len(value) == SmtpXUrRefLength && smtpLowerBase32Form(token, smtpXUrRefOctetCount)
}

// Whether a value is Feedback-ID's 40 characters: n or b, then c, p or t, then the network's report
// token, then urnetwork (plan-SMTP-small-readings#4).
func smtpFeedbackIdForm(value string) bool {
	fields := strings.Split(value, ":")
	return len(value) == SmtpFeedbackIdLength && len(fields) == 4 &&
		(fields[0] == "n" || fields[0] == "b") &&
		(fields[1] == "c" || fields[1] == "p" || fields[1] == "t") &&
		smtpLowerBase32Form(fields[2], smtpNetTokenOctetCount) &&
		fields[3] == smtpFeedbackIdSuffix
}

// The values render writes after the preamble: real ones, or ByteCount's placeholders of equal length.
type smtpDkimValues struct {
	selector   string
	xUrRef     string
	feedbackId string
	signTime   string
	expireTime string
}

// Placeholders of the real values' lengths, for ByteCount and assembly's header block bound.
func smtpDkimPlaceholderValues() *smtpDkimValues {
	return &smtpDkimValues{
		selector:   strings.Repeat("a", SmtpDkimSelectorLength),
		xUrRef:     smtpXUrRefVersion + strings.Repeat("a", SmtpXUrRefLength-len(smtpXUrRefVersion)),
		feedbackId: strings.Repeat("a", SmtpFeedbackIdLength),
		signTime:   strings.Repeat("1", smtpDkimTimeDigitCount),
		expireTime: strings.Repeat("1", smtpDkimTimeDigitCount),
	}
}

// RFC 6376 §3.4.2: the name lowercased, the value unfolded with each run of WSP one space and none at
// either end, then CRLF. line is one field's lines, CRLF between them and none at the end.
func smtpDkimRelaxedField(line string) string {
	name, value, _ := strings.Cut(line, ":")
	value = strings.ReplaceAll(value, "\r\n", "")
	words := strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == '\t' })
	return strings.ToLower(strings.TrimRight(name, " \t")) + ":" + strings.Join(words, " ") + "\r\n"
}

// RFC 6376 §3.4.4 over a CRLF body: each run of WSP one space, none at a line's end, no empty line at
// the end, and a non-empty body ending in one CRLF; an empty body is empty (erratum 1384).
func smtpDkimRelaxedBody(body []byte) []byte {
	lines := strings.Split(string(body), "\r\n")
	var out bytes.Buffer
	pendingEmpty := 0
	for i, line := range lines {
		if i == len(lines)-1 && line == "" {
			break
		}
		words := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
		canonical := strings.Join(words, " ")
		if 0 < len(line) && (line[0] == ' ' || line[0] == '\t') && canonical != "" {
			canonical = " " + canonical
		}
		if canonical == "" {
			pendingEmpty += 1
			continue
		}
		for ; 0 < pendingEmpty; pendingEmpty -= 1 {
			out.WriteString("\r\n")
		}
		out.WriteString(canonical)
		out.WriteString("\r\n")
	}
	return out.Bytes()
}

// b='s value folded into lines, the first continuing the tag's line.
func smtpDkimFoldSignature(signature []byte) string {
	encoded := base64.StdEncoding.EncodeToString(signature)
	var folded strings.Builder
	for 0 < len(encoded) {
		if folded.Len() != 0 {
			folded.WriteString("\r\n\t")
		}
		take := min(len(encoded), smtpDkimSignatureLineLength)
		folded.WriteString(encoded[:take])
		encoded = encoded[take:]
	}
	return folded.String()
}

// The message's octets: both signatures, the issued fields, the message's fields, the blank line and
// the body. sign nil writes b= as zeros of a signature's length, which is all ByteCount needs.
func (self *SmtpWireMessage) render(values *smtpDkimValues, sign func(digest []byte) ([]byte, error)) ([]byte, error) {
	var fieldLines []string
	fieldLines = append(fieldLines, "X-UR-Ref: "+values.xUrRef, "Feedback-ID: "+values.feedbackId)
	for _, field := range self.fields {
		fieldLines = append(fieldLines, field.line())
	}
	bodyHash := sha256.Sum256(smtpDkimRelaxedBody(self.body))
	encodedBodyHash := base64.StdEncoding.EncodeToString(bodyHash[:])
	domain := self.headerFromDomain
	unsignedFull := smtpDkimFullPrefix + domain + "; s=" + values.selector + ";\r\n" +
		"\tt=" + values.signTime + "; x=" + values.expireTime + ";\r\n" +
		"\th=" + strings.Join(self.signedFieldNames, ":") + ";\r\n" +
		"\tbh=" + encodedBodyHash + ";\r\n" +
		"\tb="
	unsignedFixed := smtpDkimFixedPrefix + "d=" + domain + "; s=" + values.selector + "; t=" + values.signTime + "; x=" + values.expireTime + ";\r\n" +
		"\tbh=" + encodedBodyHash + ";\r\n" +
		"\tb="
	signed := func(unsigned string, names []string) (string, error) {
		// each name takes the bottom-most instance not yet taken, and one absent adds nothing (§5.4.2)
		var input strings.Builder
		taken := make([]bool, len(fieldLines))
		for _, name := range names {
			for i := len(fieldLines) - 1; 0 <= i; i -= 1 {
				fieldName, _, _ := strings.Cut(fieldLines[i], ":")
				if taken[i] || !strings.EqualFold(fieldName, name) {
					continue
				}
				taken[i] = true
				input.WriteString(smtpDkimRelaxedField(fieldLines[i]))
				break
			}
		}
		input.WriteString(strings.TrimSuffix(smtpDkimRelaxedField(unsigned), "\r\n"))
		signature := make([]byte, smtpDkimSignatureByteCount)
		if sign != nil {
			digest := sha256.Sum256([]byte(input.String()))
			var err error
			if signature, err = sign(digest[:]); err != nil {
				return "", err
			}
			if len(signature) != smtpDkimSignatureByteCount {
				return "", fmt.Errorf("smtp dkim: a %d-octet signature", len(signature))
			}
		}
		return unsigned + smtpDkimFoldSignature(signature), nil
	}
	full, err := signed(unsignedFull, self.signedFieldNames)
	if err != nil {
		return nil, err
	}
	fixed, err := signed(unsignedFixed, []string{"from", "date", "message-id", "x-ur-ref", "feedback-id"})
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString(full)
	out.WriteString("\r\n")
	out.WriteString(fixed)
	out.WriteString("\r\n")
	for _, line := range fieldLines {
		folded, err := smtpFoldLine(line)
		if err != nil {
			return nil, err
		}
		out.Write(folded)
	}
	out.WriteString("\r\n")
	out.Write(self.body)
	return out.Bytes(), nil
}

// The message's final octets, SmtpProofJob.Message: wire with the issued fields and both of §14.6's
// signatures, under the selector the preamble declared. Its length is wire.ByteCount(SmtpModeBdat) and
// its dot-stuffed length wire.ByteCount(SmtpModeData). Refuses issued values outside their exact
// forms, a signer for another domain, and times whose t= or x= would not be ten digits.
func SmtpDkimSign(wire *SmtpWireMessage, args *SmtpDkimSignArgs) ([]byte, error) {
	if wire == nil || args == nil || args.Signer == nil || args.Issued == nil {
		return nil, errors.New("smtp dkim: nothing to sign")
	}
	selector := args.Signer.DkimSelector()
	if !smtpDkimSelectorForm(selector) || args.Signer.DkimDomain() != wire.headerFromDomain {
		return nil, errors.New("smtp dkim: the signer is not the message's selector")
	}
	if !smtpXUrRefForm(args.Issued.XUrRef) || !smtpFeedbackIdForm(args.Issued.FeedbackId) {
		return nil, errors.New("smtp dkim: an issued value is outside its form")
	}
	signTime := args.SignTime.Unix()
	expireTime := args.SignTime.Add(args.ExpireTimeout).Unix()
	signText, expireText := strconv.FormatInt(signTime, 10), strconv.FormatInt(expireTime, 10)
	if args.ExpireTimeout <= 0 || len(signText) != smtpDkimTimeDigitCount || len(expireText) != smtpDkimTimeDigitCount {
		return nil, errors.New("smtp dkim: a signing time outside ten digits")
	}
	values := &smtpDkimValues{
		selector:   selector,
		xUrRef:     args.Issued.XUrRef,
		feedbackId: args.Issued.FeedbackId,
		signTime:   signText,
		expireTime: expireText,
	}
	return wire.render(values, args.Signer.SignDkim)
}
