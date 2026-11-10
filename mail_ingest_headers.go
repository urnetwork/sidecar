//go:build !ios_extension

// The header fields ingest puts above a received message in m/ (§15.7, D-MAIL-14): Authentication-Results (RFC
// 8601) and Received (RFC 5321 §4.4), rendered only from the deposit's sealed MailIngress and MailAuthEvidence and
// the message's own From, never from a lookup made later, so a reader sees the verdicts reception sealed. They are
// added only at ingest and only above the message: the bytes below stay the bytes as received, which
// MailAuthEvidence.message_sha256 names.
//
// Every value here but the verdicts is a sender's or rests on one: the EHLO name, DKIM's d= and s=, SPF's domain,
// the From domain, even a PTR name. So each is cleaned to one line and capped, and written bare only where it is a
// host name or a token; anything else is a quoted string with its quotes and backslashes dropped, and a comment
// holds no parenthesis or backslash. A field is folded only at its own clause breaks, so no value can open a field
// of its own, and with every value capped no line passes RFC 5322's 998 bytes.
//
// A same-network deposit (D-MAIL-8), which names no receiver, gets no field: its sender's signature stands in for a
// reception, and a reader shows it as from a member. A receiver's deposit with no evidence gets an
// Authentication-Results of none, saying the evidence was unavailable.
//
// An Authentication-Results the sender wrote further down, under the same authserv-id, stays as it was received:
// RFC 8601 §5 has a receiver remove those, but that would change the bytes message_sha256 names. Readers that
// render authentication take the first field, which is ingest's.
//
// No connect, go-smtp or mox: on every leg. Safe for concurrent use.

package sidecar

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The authserv-id of a receiver's deposit whose SNI is no host name, such as one with no MailIngress: a name under
// RFC 2606's .invalid, which no reader can mistake for a receiver it trusts.
const mailUnknownAuthservId = "unknown.invalid"

// The protocol a Received field names: ESMTP under STARTTLS (RFC 3848), which is the only way mail reaches a
// receiver (§15.4).
const mailReceivedProtocol = "ESMTPS"

// RFC 5322 §3.3's date-time, in UTC.
const mailReceivedDateLayout = "Mon, 02 Jan 2006 15:04:05 -0700"

// Whether value is a host name a field can carry bare: lowercase LDH labels, dot-separated, at most 253 bytes.
func isMailHostName(value string) bool {
	if value == "" || dnsDomainMaxByteCount < len(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !isDnsLowerLdhLabel(label) {
			return false
		}
	}
	return true
}

// Whether value is an RFC 8601 token, which a pvalue may be bare: printable ASCII, no space and none of RFC 2045's
// tspecials.
func isMailHeaderToken(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character <= ' ' || 0x7f <= character || strings.IndexByte(`()<>@,;:\"/[]?=`, character) != -1 {
			return false
		}
	}
	return true
}

// value as a property's value: one line within its cap, bare where a host name or a token, else a quoted string
// without the quotes and backslashes that could end or escape it.
func mailHeaderValue(value string) string {
	value = mailCleanLine(value, mailHeaderValueMaxByteCount)
	if isMailHostName(dnsAsciiLower(value)) {
		return dnsAsciiLower(value)
	}
	if isMailHeaderToken(value) {
		return value
	}
	return `"` + strings.NewReplacer(`"`, "", `\`, "").Replace(value) + `"`
}

// value as a comment's text: one line within its cap, with no parenthesis or backslash to end or escape it.
func mailHeaderComment(value string) string {
	value = mailCleanLine(value, mailHeaderValueMaxByteCount)
	return strings.Map(func(character rune) rune {
		if character == '(' || character == ')' || character == '\\' {
			return -1
		}
		return character
	}, value)
}

// The authserv-id: the SNI that routed the session, which names this network's mx host, lowercase; else
// mailUnknownAuthservId.
func mailAuthservId(deposit *protocol.MailDeposit) string {
	sni := dnsAsciiLower(deposit.GetIngress().GetSni())
	if isMailHostName(sni) {
		return sni
	}
	return mailUnknownAuthservId
}

// One method's result words: RFC 8601's result, and an incomplete check as temperror for SPF and DKIM and none for
// ARC, the verdicts RFC 8601 has nearest to no result, each with reason "incomplete". Empty for an unspecified
// verdict, which a field leaves out.
func mailSpfResult(verdict protocol.SpfVerdict) string {
	switch verdict {
	case protocol.SpfVerdict_SPF_PASS:
		return "pass"
	case protocol.SpfVerdict_SPF_FAIL:
		return "fail"
	case protocol.SpfVerdict_SPF_SOFTFAIL:
		return "softfail"
	case protocol.SpfVerdict_SPF_NEUTRAL:
		return "neutral"
	case protocol.SpfVerdict_SPF_NONE:
		return "none"
	case protocol.SpfVerdict_SPF_TEMPERROR:
		return "temperror"
	case protocol.SpfVerdict_SPF_PERMERROR:
		return "permerror"
	case protocol.SpfVerdict_SPF_INCOMPLETE:
		return `temperror reason="incomplete"`
	}
	return ""
}

// DKIM's, as mailSpfResult says.
func mailDkimResult(verdict protocol.DkimVerdict) string {
	switch verdict {
	case protocol.DkimVerdict_DKIM_PASS:
		return "pass"
	case protocol.DkimVerdict_DKIM_FAIL:
		return "fail"
	case protocol.DkimVerdict_DKIM_PERMERROR:
		return "permerror"
	case protocol.DkimVerdict_DKIM_TEMPERROR:
		return "temperror"
	case protocol.DkimVerdict_DKIM_INCOMPLETE:
		return `temperror reason="incomplete"`
	}
	return ""
}

// DMARC's, as mailSpfResult says.
func mailDmarcResult(verdict protocol.DmarcVerdict) string {
	switch verdict {
	case protocol.DmarcVerdict_DMARC_PASS:
		return "pass"
	case protocol.DmarcVerdict_DMARC_FAIL:
		return "fail"
	case protocol.DmarcVerdict_DMARC_NONE:
		return "none"
	case protocol.DmarcVerdict_DMARC_TEMPERROR:
		return "temperror"
	}
	return ""
}

// ARC's, as mailSpfResult says.
func mailArcResult(verdict protocol.ArcVerdict) string {
	switch verdict {
	case protocol.ArcVerdict_ARC_NONE:
		return "none"
	case protocol.ArcVerdict_ARC_PASS:
		return "pass"
	case protocol.ArcVerdict_ARC_FAIL:
		return "fail"
	case protocol.ArcVerdict_ARC_INCOMPLETE:
		return `none reason="incomplete"`
	}
	return ""
}

// An address as a Received field's address literal: [192.0.2.1] or [IPv6:2001:db8::1]. Empty for anything that
// is not 4 or 16 bytes.
func mailAddressLiteral(ip []byte) string {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ""
	}
	if address.Is4() || address.Is4In6() {
		return "[" + address.Unmap().String() + "]"
	}
	return "[IPv6:" + address.String() + "]"
}

// A TLS version's name in a Received comment, from its IANA number.
func mailTlsVersionName(version uint32) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("0x%04x", version)
}

// The fields ingest puts above a received message in m/, each ending CRLF, Authentication-Results first. fromDomain
// is MailParsed.FromDomain, which DMARC's result names, or empty. messageId is the deposit's id, which Received
// carries. nil for a same-network deposit.
func MailIngestHeaders(deposit *protocol.MailDeposit, messageId Id, fromDomain string) []byte {
	if !mailReceiverDeposit(deposit) {
		return nil
	}
	authservId := mailAuthservId(deposit)
	fields := &strings.Builder{}

	// Authentication-Results: one clause a method, each on its own folded line
	clauses := []string{}
	evidence := deposit.GetEvidence()
	if evidence != nil {
		if result := mailSpfResult(evidence.GetSpf().GetResult()); result != "" {
			property := "smtp.mailfrom"
			if len(deposit.GetMailFrom()) == 0 {
				property = "smtp.helo"
			}
			clause := "spf=" + result
			if domain := evidence.GetSpf().GetDomain(); domain != "" {
				clause += " " + property + "=" + mailHeaderValue(domain)
			}
			clauses = append(clauses, clause)
		}
		for _, dkim := range evidence.GetDkim() {
			result := mailDkimResult(dkim.GetResult())
			if result == "" {
				continue
			}
			clause := "dkim=" + result
			if domain := dkim.GetDomain(); domain != "" {
				clause += " header.d=" + mailHeaderValue(domain)
			}
			if selector := dkim.GetSelector(); selector != "" {
				clause += " header.s=" + mailHeaderValue(selector)
			}
			clauses = append(clauses, clause)
		}
		if result := mailDmarcResult(evidence.GetDmarc().GetResult()); result != "" {
			clause := "dmarc=" + result
			if fromDomain != "" {
				clause += " header.from=" + mailHeaderValue(fromDomain)
			}
			clauses = append(clauses, clause)
		}
		if result := mailArcResult(evidence.GetArc().GetCv()); result != "" {
			clauses = append(clauses, "arc="+result)
		}
		if ptrName := evidence.GetPtrName(); ptrName != "" {
			clause := "iprev=pass"
			if address, ok := netip.AddrFromSlice(deposit.GetIngress().GetSenderIp()); ok {
				clause += " policy.iprev=" + mailHeaderValue(address.Unmap().String())
			}
			clause += " (" + mailHeaderComment(ptrName) + ")"
			clauses = append(clauses, clause)
		}
	}
	fields.WriteString("Authentication-Results: " + authservId)
	switch {
	case evidence == nil:
		fields.WriteString("; none (evidence unavailable)")
	case len(clauses) == 0:
		fields.WriteString("; none")
	default:
		for _, clause := range clauses {
			fields.WriteString(";\r\n\t" + clause)
		}
	}
	if evidence.GetLimits() != nil {
		fields.WriteString("\r\n\t(checks incomplete)")
	}
	fields.WriteString("\r\n")

	// Received: from what the sender said and where it was, by this network's host, then the sealed time
	ingress := deposit.GetIngress()
	if ingress != nil {
		from := "unknown"
		if ehloName := dnsAsciiLower(ingress.GetEhloName()); isMailHostName(ehloName) {
			from = ehloName
		}
		ptrName := "unknown"
		if name := dnsAsciiLower(evidence.GetPtrName()); isMailHostName(name) {
			ptrName = name
		}
		tcpInfo := ptrName
		if literal := mailAddressLiteral(ingress.GetSenderIp()); literal != "" {
			tcpInfo += " " + literal
		}
		received := MailDepositReceiveTime(deposit, 0)
		fields.WriteString("Received: from " + from + " (" + tcpInfo + ")\r\n\tby " + authservId + " with " + mailReceivedProtocol)
		if deposit.GetTlsVersion() != 0 {
			tlsInfo := mailTlsVersionName(deposit.GetTlsVersion())
			if suite := deposit.GetTlsSuite(); suite != 0 && suite <= 0xffff {
				tlsInfo += " " + tls.CipherSuiteName(uint16(suite))
			} else if suite != 0 {
				tlsInfo += fmt.Sprintf(" 0x%x", suite)
			}
			fields.WriteString(" (" + mailHeaderComment(tlsInfo) + ")")
		}
		fields.WriteString("\r\n\tid " + mailBinaryName(messageId[:]))
		fields.WriteString(";\r\n\t" + time.UnixMilli(int64(min(received, mailLastMillis))).UTC().Format(mailReceivedDateLayout) + "\r\n")
	}
	return []byte(fields.String())
}
