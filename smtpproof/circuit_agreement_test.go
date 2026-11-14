// The circuits beside the gate and the independent checker, over the same breaks of one real
// connection's header block: SMTP-M9-23's differential table. The gate's verifier is the relation, the
// checker reads SPEC.md apart from both and imports nothing from this module, and the circuit is
// gnark's solver over the edge's own statement, Z1 left out. Each break must be named Z5 by the first two,
// and refused at the msg part by the third. A header record's CR and LF are Z5's alone in either mode:
// DATA's framing of the body starts after the header block (DESIGN-DETAILS 3.2.3), and Z5's rule 1 is the
// same rule over the header records.

package smtpproof_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpproof"
)

// A break of the header block, made over its lines, each with its CRLF, under the capture's preamble.
type testHeaderBreak struct {
	name string
	bulk bool
	// The break also breaks a DATA record's framing (Z6).
	framing bool
	edit    func(lines []string, preamble *sidecar.SmtpProofPreamble) []string
}

func testHeaderBreaks() []*testHeaderBreak {
	// the first line whose prefix is given, or -1
	find := func(lines []string, prefix string) int {
		return slices.IndexFunc(lines, func(line string) bool { return strings.HasPrefix(line, prefix) })
	}
	inserted := func(lines []string, at int, added ...string) []string {
		return slices.Insert(slices.Clone(lines), at, added...)
	}
	replaced := func(lines []string, prefix string, old string, new string) []string {
		lines = slices.Clone(lines)
		i := find(lines, prefix)
		lines[i] = strings.Replace(lines[i], old, new, 1)
		return lines
	}
	return []*testHeaderBreak{
		{name: "no Feedback-ID", edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			return slices.Delete(slices.Clone(lines), find(lines, "Feedback-ID:"), find(lines, "Feedback-ID:")+1)
		}},
		{name: "a duplicate X-UR-Ref", edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			i := find(lines, "X-UR-Ref:")
			return inserted(lines, i, lines[i])
		}},
		{name: "a second From", edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			return inserted(lines, 0, lines[find(lines, "From:")])
		}},
		{name: "a smuggled folded From", edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			return inserted(lines, find(lines, "From:")+1, " <x@victim.example>\r\n")
		}},
		{name: "From before a colon-spaced name", edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			return inserted(lines, 0, "From : <x@victim.example>\r\n")
		}},
		{name: "a bare CR", framing: true, edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			return replaced(lines, "Subject:", "Subject: ", "Subject:\r")
		}},
		{name: "a bare LF", framing: true, edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			return replaced(lines, "Subject:", "Subject: ", "Subject:\nFrom: <x@victim.example>\r\nX: ")
		}},
		{name: "an empty line before the end", edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			return inserted(lines, find(lines, "Subject:"), "\r\n")
		}},
		{name: "a wrong Message-ID", edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			return replaced(lines, "Message-ID:", preamble.MessageId, "other@"+preamble.HeaderFromDomain)
		}},
		{name: "a DKIM prefix with another d=", edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			return replaced(lines, "DKIM-Signature:", "d="+preamble.HeaderFromDomain, "d=victim.example")
		}},
		{name: "BULK without List-Unsubscribe-Post", bulk: true, edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			return lines
		}},
		{name: "BULK with List-Unsubscribe-Post continued", bulk: true, edit: func(lines []string, preamble *sidecar.SmtpProofPreamble) []string {
			return inserted(lines, 0, "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n", " x\r\n")
		}},
	}
}

// Breaks pi3's header block, sealed again under the client key, in the part, its witness and the
// stream. A sidecar that lengthens the block also declares the count of what it sends, in the preamble
// and in BDAT's opened command, since a block past the count is E3's in DATA mode and Z6's in BDAT, and
// what is under test is the break itself.
func testBreakHeaderBlock(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture, b *testHeaderBreak) {
	t.Helper()
	preamble := *capture.Preamble
	if b.bulk {
		preamble.Flags |= sidecar.SmtpFlagBulk
	}
	message := testPartEvents(capture)[3]
	data := capture.Events[message].Part.Mode != 1
	header := 1
	if data {
		header = 0
	}
	plaintext := capture.Witnesses[message].ClientPlaintexts[header]
	if !c.tls12 {
		plaintext = plaintext[:len(plaintext)-1]
	}
	broken := strings.Join(b.edit(strings.SplitAfter(string(plaintext), "\r\n"), &preamble), "")
	if grown := len(broken) - len(plaintext); 0 < grown {
		preamble.MessageByteCount += uint64(grown)
		if !data {
			testRewriteClientRecord(t, c, capture, message, 0, []byte(fmt.Sprintf("BDAT %d LAST\r\n", preamble.MessageByteCount)))
		}
	}
	capture.Preamble = &preamble
	testRewriteClientRecord(t, c, capture, message, header, []byte(broken))
}

func TestHeaderCircuitTheGateAndTheCheckerRefuseAlike(t *testing.T) {
	smtpproof.ExportNeedCircuits(t)
	t.Parallel()
	// both versions, both suites and both modes among three legs: Z5's automaton is one, and what the
	// legs change is the keystream under it and DATA's framing beside it
	for _, c := range testLegCases() {
		if c.name != "tls13 aes bdat" && c.name != "tls13 chacha data" && c.name != "tls12 aes data" {
			continue
		}
		honest := smtpproof.ExportCapture(t, c.leg, c.data)
		if part, err := smtpproof.ExportCircuitVerdict(t, honest); part != 0 || err != nil {
			t.Fatalf("%s: the circuits refuse an honest send at part %d: %v", c.name, part, err)
		}
		for _, b := range testHeaderBreaks() {
			capture := smtpproof.ExportCapture(t, c.leg, c.data)
			testBreakHeaderBlock(t, c, capture, b)
			want := []string{"Z5"}
			name := fmt.Sprintf("%s: %s", c.name, b.name)
			if gate := testGateVerdict(capture); !slices.Equal(gate, want) {
				t.Errorf("%s: the gate names %v, want %v", name, gate, want)
			}
			if ours := testCheckerVerdict(capture); !slices.Equal(ours, want) {
				t.Errorf("%s: the checker names %v, want %v", name, ours, want)
			}
			if part, err := smtpproof.ExportCircuitVerdict(t, capture); part != 3 || err != nil {
				t.Errorf("%s: the circuits refuse part %d (%v), want the msg part, 3", name, part, err)
			}
		}
	}
}
