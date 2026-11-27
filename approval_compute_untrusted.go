//go:build !ios_extension

// How an approver's device shows a version-5 action's text (DESIGN-COMPUTE §16.3's "Canonical text shows" column,
// §23.9, §25.10, §28.8; D-MCP-17, IC-16, IC-20; CACL-M12-02): every string of fields 42 to 60 and 80 is untrusted text,
// an agent's or a sender's words that the daemon only carries, so none may pass for the daemon's own. Where versions 1
// to 4 drop what could move the cursor (ApprovalPrintable), version 5 escapes it visibly, so the person sees it was
// there:
//
//	escaped    C0 and DEL, C1, every format character (Cf: the bidi controls, the zero-width joiners, the tag
//	           characters among them), Unicode's other default-ignorable code points and variation selectors, and the
//	           line and paragraph separators, each as \u{XXXX} in uppercase hex, at least four digits; a byte that is
//	           not UTF-8 as \x{XX}; and the backslash itself as \\, so every \u{ a person reads is the render's
//	lines      a section's text, a send's or a body's, keeps its line feeds as the section's own line breaks, each line
//	           escaped as above and prefixed by the render, so no line an agent writes can stand at the margin
//	hosts      in punycode by IDNA 2008's lookup profile (golang.org/x/net/idna), the form a resolver asks for, so a host
//	           whose letters imitate another's shows its xn-- labels; an IP address as it is; a host that does not
//	           convert shown escaped and flagged
//
// MAILCAL's kind-25 cards use the same helpers for their titles, descriptions and attendees (MAILCAL-M13-06).
//
// Package-level functions, safe for concurrent use. On every leg but the ios_extension legs, as the render is.

package sidecar

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Whether r is one a version-5 render escapes rather than shows: see the file header.
func approvalUntrustedEscaped(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, 0x80 <= r && r <= 0x9f:
		return true
	case r == utf8.RuneError:
		// shown as itself where it was written as U+FFFD; an invalid byte is escaped apart
		return false
	}
	return unicode.In(r, unicode.Cf, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector,
		unicode.Zl, unicode.Zp)
}

// Writes text escaped to builder: see the file header's escaped row.
func approvalUntrustedWrite(builder *strings.Builder, text string) {
	for len(text) != 0 {
		r, size := utf8.DecodeRuneInString(text)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(builder, `\x{%02X}`, text[0])
		case r == '\\':
			builder.WriteString(`\\`)
		case approvalUntrustedEscaped(r):
			fmt.Fprintf(builder, `\u{%04X}`, r)
		default:
			builder.WriteString(text[:size])
		}
		text = text[size:]
	}
}

// text as one line an approver's device may print: every character the file header names escaped visibly, the line
// feed among them, nothing dropped.
func ApprovalUntrustedText(text string) string {
	builder := strings.Builder{}
	approvalUntrustedWrite(&builder, text)
	return builder.String()
}

// text as the lines of a section of its own: split at each line feed, each line escaped as ApprovalUntrustedText
// escapes, a carriage return included. A text ending in a line feed ends in an empty line, so the person sees it; an
// empty text is one empty line.
func ApprovalUntrustedLines(text string) []string {
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		lines = append(lines, ApprovalUntrustedText(line))
	}
	return lines
}

// Whether text holds anything ApprovalUntrustedText escapes, so a render can say a value held hidden characters.
func ApprovalUntrustedHidden(text string) bool {
	for len(text) != 0 {
		r, size := utf8.DecodeRuneInString(text)
		if (r == utf8.RuneError && size == 1) || approvalUntrustedEscaped(r) {
			return true
		}
		text = text[size:]
	}
	return false
}

// A host as an approver's device shows it (the file header's hosts row): an IP address as it is, a name in punycode,
// lowercase, by IDNA 2008's lookup profile, and true; or, for a host that does not convert, the host escaped as
// ApprovalUntrustedText escapes it and false, which a render flags.
func ApprovalUntrustedHost(host string) (string, bool) {
	if address, err := netip.ParseAddr(host); err == nil && address.Zone() == "" {
		return address.String(), true
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" || ApprovalUntrustedHidden(ascii) {
		return ApprovalUntrustedText(host), false
	}
	return ascii, true
}

// The host of an absolute URL as ApprovalUntrustedHost shows it, and whether it converted; "" and false for a URL
// that names no host this device can read.
func ApprovalUntrustedUrlHost(rawUrl string) (string, bool) {
	parsed, err := url.Parse(rawUrl)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" {
		return "", false
	}
	return ApprovalUntrustedHost(parsed.Hostname())
}

// An address, local@domain, as an approver's device shows it: the local part escaped, the domain in punycode, and
// whether the domain converted; one with no @ is shown escaped and false. For MAILCAL's attendees (§23.9).
func ApprovalUntrustedAddress(address string) (string, bool) {
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return ApprovalUntrustedText(address), false
	}
	domain, ok := ApprovalUntrustedHost(address[at+1:])
	return ApprovalUntrustedText(address[:at]) + "@" + domain, ok
}
