//go:build !ios_extension && !sidecar_http

// What untrusted text may put on a terminal (DESIGN-COMPUTE §7.11, §7.6's no remote loads): nothing but printable
// characters. Every string the terminal renderer prints from an event (a model's text and its markdown's links, a
// tool's arguments and output, a page, an inbox message, a card's lines, all text relayed from a remote Harness) passes
// HarnessSanitize first, which drops ESC, every other C0 control, DEL, every C1 control and the bidi controls
// (ApprovalPrintable's set), so no text can write the clipboard (OSC 52), plant a link (OSC 8), move the cursor or
// clear the screen (CSI, in its 8-bit form 0x9b too), or reorder what the person reads. A byte that is not UTF-8 shows
// as U+FFFD, so a lone 0x9b cannot reach a terminal in an 8-bit mode either. Newlines stay as line breaks and a tab is
// a space; nothing else of the text changes.
//
// The renderer's own escapes (its styles and its OSC 8 links) are added after, around sanitized text, and a link
// carries only a URL HarnessCheckedUrl passed: https, a host, no credentials, printable ASCII alone, so nothing in it
// can end the escape it rides in.
//
// `ur harness --json` prints events raw: JSON already writes every C0 control as an escape, and
// HarnessJsonTerminalSafe writes DEL, C1 and the bidi controls as escapes too, the same JSON value, so a raw line read
// on a terminal drives it no more than the rendered one does.
//
// Everything here is a function of its arguments, so safe for concurrent use.

package sidecar

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// text as a terminal may print it: every line through ApprovalPrintable's rule, tabs as spaces, a lone carriage
// return dropped, the newlines kept.
func HarnessSanitize(text string) string {
	if harnessSanitizeClean(text) {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = HarnessSanitizeLine(line)
	}
	return strings.Join(lines, "\n")
}

// One line as a terminal may print it: HarnessSanitize with the newlines dropped too, a tab a space.
func HarnessSanitizeLine(text string) string {
	if harnessSanitizeClean(text) && !strings.ContainsAny(text, "\n") {
		return text
	}
	return ApprovalPrintable(strings.ReplaceAll(text, "\t", " "))
}

// Whether text is printable ASCII and newlines alone, which every sanitizing leaves as it is.
func harnessSanitizeClean(text string) bool {
	for i := 0; i < len(text); i += 1 {
		c := text[i]
		if (c < 0x20 && c != '\n') || 0x7f <= c {
			return false
		}
	}
	return true
}

// Whether r is a code point HarnessJsonTerminalSafe writes as an escape: DEL, C1 and the bidi controls, beside the C0
// controls JSON escapes already.
func harnessJsonEscaped(r rune) bool {
	return r == 0x7f || (0x80 <= r && r <= 0x9f) || r == 0x061c || r == 0x200e || r == 0x200f ||
		(0x202a <= r && r <= 0x202e) || (0x2066 <= r && r <= 0x2069)
}

// line, one JSON value, with DEL, every C1 control and the bidi controls written as \u escapes and any byte that is
// not UTF-8 as �: the same JSON value for every reader that decodes it, which no terminal reads as a control. Such
// code points can only stand inside a JSON string, so the rewrite never touches the value's structure.
func HarnessJsonTerminalSafe(line []byte) []byte {
	clean := true
	for i := 0; i < len(line); i += 1 {
		if 0x7f <= line[i] {
			clean = false
			break
		}
	}
	if clean {
		return line
	}
	out := make([]byte, 0, len(line)+16)
	for 0 < len(line) {
		r, size := utf8.DecodeRune(line)
		switch {
		case r == utf8.RuneError && size == 1:
			out = append(out, `�`...)
		case harnessJsonEscaped(r):
			out = append(out, fmt.Sprintf(`\u%04x`, r)...)
		default:
			out = append(out, line[:size]...)
		}
		line = line[size:]
	}
	return out
}

// raw as a link's target where the renderer may link it: an absolute https URL with a host, no user or password, at
// most maxByteCount bytes, every byte printable ASCII (an internationalized host or path arrives percent-encoded or in
// punycode), so nothing in it can end an OSC 8 escape. False for anything else, which the renderer prints as text.
func HarnessCheckedUrl(raw string, maxByteCount int) (string, bool) {
	if raw == "" || maxByteCount < len(raw) {
		return "", false
	}
	for i := 0; i < len(raw); i += 1 {
		if raw[i] <= 0x20 || 0x7f <= raw[i] {
			return "", false
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" {
		return "", false
	}
	// a backslash, which some parsers take as a slash, is refused rather than read one way here and another there
	if strings.ContainsAny(raw, `\`) {
		return "", false
	}
	return raw, true
}
