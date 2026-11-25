//go:build !ios_extension && !sidecar_http

// Untrusted text in a model's context (DESIGN-COMPUTE §7.8, I-9, IC-12): the Harness puts what an untrusted writer
// wrote between untrusted-data markers, with the writer's verified name, so a model reads it as data and never as an
// instruction. The markers are MCP's (mcp/result.go, DESIGN §16.6), so the recURd skill teaches one form:
//
//	BEGIN UNTRUSTED DATA (from <sender>)
//	...
//	END UNTRUSTED DATA
//
// No text may end its own fence: every run of either marker's words inside it, in any case and spacing, is broken by
// joining its words with underscores, as MCP's Fence does, and the sender is held to one line with no marker in it.
// Fencing taints nothing: the caller taints the run first (HarnessRun.Taint), write-ahead, before the text reaches the
// model.

package sidecar

import (
	"regexp"
	"strings"
	"unicode"
)

// The fixed markers around untrusted text (§16.6).
const (
	HarnessUntrustedBegin = "BEGIN UNTRUSTED DATA"
	HarnessUntrustedEnd   = "END UNTRUSTED DATA"
)

// A marker's words with any whitespace between them, in any case, and the whitespace a break replaces.
var (
	harnessUntrustedMarkerPattern = regexp.MustCompile(`(?i)(BEGIN|END)\s+UNTRUSTED\s+DATA`)
	harnessUntrustedSpacePattern  = regexp.MustCompile(`\s+`)
)

// text with every marker in it broken, so it cannot open or close a fence.
func harnessUntrustedBreakMarkers(text string) string {
	return harnessUntrustedMarkerPattern.ReplaceAllStringFunc(text, func(marker string) string {
		return harnessUntrustedSpacePattern.ReplaceAllString(marker, "_")
	})
}

// The sender as the fence names it: one line, no control character, no marker.
func harnessUntrustedSender(sender string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, sender)
	cleaned = strings.TrimSpace(harnessUntrustedBreakMarkers(cleaned))
	cleaned = strings.ReplaceAll(cleaned, ")", "]")
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}

// text between the untrusted-data markers, naming its verified sender, with every marker inside it broken.
func HarnessUntrustedText(sender string, text string) string {
	return HarnessUntrustedBegin + " (from " + harnessUntrustedSender(sender) + ")\n" +
		harnessUntrustedBreakMarkers(text) + "\n" + HarnessUntrustedEnd
}

// text as the run's model reads untrusted text from sender (HarnessUntrustedText). The caller has tainted the run.
func (self *HarnessRun) Untrusted(sender string, text string) string {
	return HarnessUntrustedText(sender, text)
}
