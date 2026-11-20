// FS-31 row by row (SMTP-M9-30; §22.5's FS-31 row, D-SMTP-16's adversarial corpus, DESIGN-DETAILS 3.6): scripted MXs
// with no CHUNKING, pre-TLS-only CHUNKING, no PIPELINING, MAIL or RCPT refused, mixed recipients, no 354 and a late
// NewSessionTicket; a malicious sender's key substitution, record splits, replayed server replies, a pipelined second
// transaction, smuggled headers, an early or bare-LF DATA end and a second transaction in the alleged BDAT body; the
// five rows of DESIGN-DETAILS 3.6 over parts bound to one key part; padded and KeyUpdate BDAT body records; and an
// honest TLS 1.2 MX answering 451 while the edge forges 250. Each row runs in every cell it applies to, both TLS
// versions and both modes, on the leg's edge (fs31_fixture_test.go).
//
// The assertion on every mismatch between what was proved and what an MX would act on is the MX's own record: no
// transaction, and no command accepted inside TLS but the honest dialog's, in its order, none past what the parts
// before the refused one opened. Honest controls pass in each cell, a 100-recipient send and a 16 KiB header block
// among them. TestFs31MatrixTable holds the rows to testdata/fs31/matrix.md, the evidence table of cell, tier and
// result that M9's review reads.

package smtpproof

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What a row holds each cell to.
type fs31Expect struct {
	// The MX took the message: exactly one transaction, the job's, and the prover reports it accepted.
	delivered bool
	// The MX took at most the honest message and nothing past the commands the parts proved: padded and KeyUpdate
	// BDAT bodies, and a second transaction sent past the message, may fail the send but smuggle nothing.
	smuggleNothing bool
	// The part the edge refuses, and the check that refuses it, empty where the row leaves it to the gate. 0 where
	// the MX, the prover or nothing ends the send.
	refusedPart  uint32
	refusedCheck relationCheck
	// The reply that ended the send at the MX, as the prover reports it.
	refusedCode string
	// The prover's TLS client refuses what the edge forged, so the send fails and the sender keeps the message.
	proverFails bool
}

// One row of FS-31.
type fs31Row struct {
	name string
	// The row's group in the matrix: control, mx, sender, bound parts, body records or edge.
	group string
	// FS-31's words the row answers.
	clause  string
	applies func(cell *fs31Cell) bool
	// The MX's script, changed from DefaultMxScript's.
	script func(cell *fs31Cell, script *sidecartest.MxScript)
	// RecordMx's settings where the row needs what crypto/tls cannot send; else a ScriptedMx serves the cell.
	recordMx func(cell *fs31Cell) *sidecartest.RecordMxSettings
	// The message; nil is fs31DefaultMessage's.
	message func(cell *fs31Cell) *fs31Message
	// The malicious sender; nil is an honest one.
	adversary func(cell *fs31Cell) *fs31Adversary
	// Changes to the cell's prover settings.
	settings func(cell *fs31Cell, settings *ProverSettings)
	// Solves every part's circuit in the leg that compiles circuits, not only those the relation refuses.
	solveAll        bool
	forgeServerFrom func(cell *fs31Cell) int
	recipientLimit  int
	endAtQuit       bool
	// Whether server/cli/smtpedge's fs31_test.go reruns the row at T3: a ScriptedMx row whose sender needs only the
	// relation key set's prover and its wire.
	t3     bool
	expect func(cell *fs31Cell) *fs31Expect
	// What else the row holds an outcome to.
	check func(t *testing.T, name string, outcome *fs31Outcome)
}

func fs31Every(cell *fs31Cell) bool { return true }
func fs31Bdat(cell *fs31Cell) bool  { return !cell.data }
func fs31Data(cell *fs31Cell) bool  { return cell.data }
func fs31Tls13(cell *fs31Cell) bool { return !cell.tls12() }
func fs31Tls12(cell *fs31Cell) bool { return cell.tls12() }

func fs31Bdat13(cell *fs31Cell) bool { return !cell.data && !cell.tls12() }

func fs31Delivered(cell *fs31Cell) *fs31Expect      { return &fs31Expect{delivered: true} }
func fs31SmuggleNothing(cell *fs31Cell) *fs31Expect { return &fs31Expect{smuggleNothing: true} }

func fs31RefusedAt(part uint32, check relationCheck) func(cell *fs31Cell) *fs31Expect {
	return func(cell *fs31Cell) *fs31Expect { return &fs31Expect{refusedPart: part, refusedCheck: check} }
}

func fs31MxRefuses(code string) func(cell *fs31Cell) *fs31Expect {
	return func(cell *fs31Cell) *fs31Expect { return &fs31Expect{refusedCode: code} }
}

func fs31ProverFails(cell *fs31Cell) *fs31Expect { return &fs31Expect{proverFails: true} }

// keywords without keyword.
func fs31Without(keywords []string, keyword string) []string {
	return slices.DeleteFunc(slices.Clone(keywords), func(offered string) bool {
		return strings.EqualFold(strings.Fields(offered + " ")[0], keyword)
	})
}

// The cell's MX for a row.
func (self *fs31Row) newMx(t *testing.T, cell *fs31Cell) fs31Mx {
	t.Helper()
	script := sidecartest.DefaultMxScript()
	if self.script != nil {
		self.script(cell, script)
	}
	if self.recordMx != nil {
		mx, err := sidecartest.NewRecordMx(testMxHost, script, self.recordMx(cell))
		if err != nil {
			t.Fatal(err)
		}
		return mx
	}
	mx, err := sidecartest.NewScriptedMx(testMxHost, script, &sidecartest.ScriptedMxSettings{
		MinVersion:   cell.leg.version,
		MaxVersion:   cell.leg.version,
		CipherSuites: []uint16{cell.leg.suite},
		RsaKey:       cell.leg.suite == tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	return mx
}

// RecordMx serving the cell's leg as the honest server.
func fs31RecordMxOf(cell *fs31Cell) *sidecartest.RecordMxSettings {
	return &sidecartest.RecordMxSettings{Version: cell.leg.version, Suite: cell.leg.suite}
}

// The index of the MX's reply to the message among its replies inside TLS, 1 the EHLO reply's: EHLO, MAIL, each RCPT,
// and in DATA mode the 354 before it.
func fs31MessageReplyIndex(cell *fs31Cell, recipientCount int) int {
	if cell.data {
		return 4 + recipientCount
	}
	return 3 + recipientCount
}

// A message to bob and carol with body in place of the default's.
func fs31BodyMessage(body string) func(cell *fs31Cell) *fs31Message {
	return func(cell *fs31Cell) *fs31Message {
		message := fs31DefaultMessage()
		message.body = body
		return message
	}
}

// A header block of exactly the most octets one may hold, 16 KiB: the single fields and the signature first, then
// fillers of 800 octets a line.
func fs31LongHeaderBlock(cell *fs31Cell, issued *fs31Issued) string {
	base := strings.TrimSuffix(fs31HeaderBlock(issued, ""), "\r\n")
	remaining := DefaultProofSettings().HeaderBlockMaxByteCount - len(base) - len("\r\n")
	var extra strings.Builder
	line := func(count int) {
		prefix := fmt.Sprintf("X-Filler-%02d: ", strings.Count(extra.String(), "\r\n"))
		extra.WriteString(prefix + strings.Repeat("f", count-len(prefix)-len("\r\n")) + "\r\n")
	}
	for 1600 < remaining {
		line(800)
		remaining -= 800
	}
	if 800 < remaining {
		line(remaining / 2)
		remaining -= remaining / 2
	}
	line(remaining)
	return base + extra.String() + "\r\n"
}

// A header block of two records under the cell's suite whose first record ends inside a field's name, as
// testCutHeaderBlock builds one, over the issued values.
func fs31SplitNameHeaderBlock(cell *fs31Cell, issued *fs31Issued) string {
	base := strings.TrimSuffix(fs31HeaderBlock(issued, ""), "\r\n")
	prefix := "X-Filler: "
	filler := testHeadBytes(cell.leg.suites[0]) - testSplitNameOctets - len(base) - len(prefix) - len("\r\n")
	return base + prefix + strings.Repeat("f", filler) + "\r\n" + testSplitNameTail + "\r\n"
}

// The plaintext a witness holds for a record of content in the cell's version.
func fs31Plaintext(cell *fs31Cell, content string) []byte {
	if cell.tls12() {
		return []byte(content)
	}
	return append([]byte(content), tlsRecordApplicationData)
}

// A second transaction, as commands a smuggler hides where a parser might read them.
const fs31SmuggledTransaction = "MAIL FROM:<mallory@other.example>\r\nRCPT TO:<victim@other.example>\r\nDATA\r\n"

// Every row of FS-31.
func fs31Rows() []*fs31Row {
	return []*fs31Row{
		// honest controls
		{
			name: "an honest send", group: "control", clause: "positive controls passing", applies: fs31Every, solveAll: true, t3: true,
			expect: fs31Delivered,
		},
		{
			name: "an honest send to 100 recipients", group: "control", clause: "a 100-recipient send", applies: fs31Every, recipientLimit: 100, t3: true,
			message: func(cell *fs31Cell) *fs31Message {
				message := fs31DefaultMessage()
				message.recipients = nil
				for i := range 100 {
					message.recipients = append(message.recipients, fmt.Sprintf("r%03d", i))
				}
				return message
			},
			expect: fs31Delivered,
		},
		{
			name: "an honest send with a 16 KiB header block", group: "control", clause: "a 16 KiB header block", applies: fs31Every, t3: true,
			message: func(cell *fs31Cell) *fs31Message {
				message := fs31DefaultMessage()
				message.headerBlock = fs31LongHeaderBlock
				return message
			},
			expect: fs31Delivered,
			check: func(t *testing.T, name string, outcome *fs31Outcome) {
				headerEnd := bytes.Index(outcome.job.Message, []byte("\r\n\r\n")) + len("\r\n\r\n")
				if headerEnd != DefaultProofSettings().HeaderBlockMaxByteCount {
					t.Errorf("%s: a header block of %d octets", name, headerEnd)
				}
			},
		},
		{
			name: "an honest send through RecordMx", group: "control", clause: "positive controls passing", applies: fs31Every,
			recordMx: fs31RecordMxOf, expect: fs31Delivered,
		},

		// scripted MXs, the sender honest
		{
			name: "an MX without CHUNKING", group: "mx", clause: "no CHUNKING", applies: fs31Data, t3: true,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) {
				script.Keywords = fs31Without(script.Keywords, "CHUNKING")
			},
			settings: func(cell *fs31Cell, settings *ProverSettings) { settings.ForceData = false },
			expect:   fs31Delivered,
			check:    fs31ExpectMode(partModeData),
		},
		{
			name: "an MX offering CHUNKING only before TLS", group: "mx", clause: "pre-TLS-only CHUNKING", applies: fs31Data, t3: true,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) {
				script.PreTlsKeywords = append(slices.Clone(script.PreTlsKeywords), "CHUNKING")
				script.Keywords = fs31Without(script.Keywords, "CHUNKING")
			},
			settings: func(cell *fs31Cell, settings *ProverSettings) { settings.ForceData = false },
			expect:   fs31Delivered,
			check:    fs31ExpectMode(partModeData),
		},
		{
			name: "an MX without PIPELINING, refusing a command sent ahead of a reply", group: "mx", clause: "no PIPELINING", applies: fs31Every, t3: true,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) {
				script.Keywords = fs31Without(script.Keywords, "PIPELINING")
				script.RefusePipelining = true
			},
			expect: fs31Delivered,
			check: func(t *testing.T, name string, outcome *fs31Outcome) {
				if outcome.mx.PipeliningViolated() {
					t.Errorf("%s: a command reached the MX ahead of a reply", name)
				}
			},
		},
		{
			name: "an MX refusing MAIL", group: "mx", clause: "MAIL refused", applies: fs31Every, t3: true,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) {
				script.Replies["MAIL"] = "550 5.7.1 Sender refused"
			},
			expect: fs31MxRefuses("550"),
		},
		{
			name: "an MX refusing every RCPT", group: "mx", clause: "RCPT refused", applies: fs31Every, t3: true,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) {
				script.RcptReplies["bob"] = "550 5.1.1 Recipient refused"
				script.RcptReplies["carol"] = "550 5.1.1 Recipient refused"
			},
			expect: fs31MxRefuses("550"),
		},
		{
			name: "an MX refusing one RCPT of two", group: "mx", clause: "mixed recipients", applies: fs31Every, t3: true,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) {
				script.RcptReplies["carol"] = "550 5.1.1 Recipient refused"
			},
			expect: fs31MxRefuses("550"),
			check: func(t *testing.T, name string, outcome *fs31Outcome) {
				if outcome.result != nil && !slices.Equal(outcome.result.RecipientReplyCodes, []uint32{250, 550}) {
					t.Errorf("%s: the recipients' replies %v", name, outcome.result.RecipientReplyCodes)
				}
			},
		},
		{
			name: "an MX answering DATA with no 354", group: "mx", clause: "no 354", applies: fs31Data, t3: true,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) {
				script.Replies["DATA"] = "554 5.5.1 Transaction failed"
			},
			expect: fs31MxRefuses("554"),
		},
		{
			name: "a late NewSessionTicket before MAIL's reply", group: "mx", clause: "a late NewSessionTicket", applies: fs31Tls13,
			recordMx: func(cell *fs31Cell) *sidecartest.RecordMxSettings {
				settings := fs31RecordMxOf(cell)
				settings.TicketBeforeReply = 2
				return settings
			},
			expect: fs31Delivered,
		},
		{
			name: "a late NewSessionTicket before the message's reply", group: "mx", clause: "a late NewSessionTicket", applies: fs31Tls13,
			recordMx: func(cell *fs31Cell) *sidecartest.RecordMxSettings {
				settings := fs31RecordMxOf(cell)
				settings.TicketBeforeReply = fs31MessageReplyIndex(cell, 2)
				return settings
			},
			expect: fs31Delivered,
		},
		{
			name: "an MX answering the message 451", group: "mx", clause: "an honest MX answers 451", applies: fs31Every, t3: true,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) { script.MessageReply = "451 4.3.0 Try again later" },
			expect: fs31MxRefuses("451"),
		},

		// a malicious sender, the MX honest
		{
			name: "key substitution: the key part's secret one bit off, its keys kept", group: "sender", clause: "key substitution", applies: fs31Every,
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{witness: func(attack *fs31Attack, statement *partStatement, witness *partWitness) {
					if statement.index != 1 {
						return
					}
					if attack.cell.tls12() {
						witness.masterSecret = bytes.Clone(witness.masterSecret)
						witness.masterSecret[0] ^= 1
					} else {
						witness.handshakeSecret = bytes.Clone(witness.handshakeSecret)
						witness.handshakeSecret[0] ^= 1
					}
				}}
			},
			expect: fs31RefusedAt(1, checkZ1),
		},
		{
			name: "a record split: MAIL across two records", group: "sender", clause: "record splits", applies: fs31Every,
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{prover: &proverAdversary{skipSelfCheck: true, commands: func(commands []string) []string {
					mail := commands[0]
					return append([]string{mail[:len(mail)/2], mail[len(mail)/2:]}, commands[1:]...)
				}}}
			},
			expect: fs31RefusedAt(2, checkE3),
		},
		{
			name: "two commands in one record: MAIL and the first RCPT", group: "sender", clause: "record splits", applies: fs31Every,
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{prover: &proverAdversary{skipSelfCheck: true, commands: func(commands []string) []string {
					return append([]string{commands[0] + commands[1]}, commands[2:]...)
				}}}
			},
			// in DATA mode the DATA command then sits where carol's RCPT belongs, whose template no length has
			expect: func(cell *fs31Cell) *fs31Expect {
				if cell.data {
					return fs31RefusedAt(2, checkE3)(cell)
				}
				return fs31RefusedAt(2, checkZ4)(cell)
			},
		},
		{
			name: "a replayed server reply: an RCPT the MX refused proven by the 250 before it", group: "sender", clause: "replayed server replies", applies: fs31Every,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) {
				script.RcptReplies["carol"] = "550 5.1.1 Recipient refused"
			},
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{
					prover: &proverAdversary{skipSelfCheck: true, ignoreRefusals: true},
					witness: func(attack *fs31Attack, statement *partStatement, witness *partWitness) {
						if statement.index != 3 {
							return
						}
						for i, plaintext := range witness.serverPlaintexts {
							if bytes.HasPrefix(plaintext, []byte("550")) && 0 < i {
								witness.serverPlaintexts[i] = bytes.Clone(witness.serverPlaintexts[i-1])
								return
							}
						}
						attack.t.Errorf("the msg part covers no refused RCPT's reply")
					},
				}
			},
			expect: fs31RefusedAt(3, checkZ2),
		},
		{
			name: "an RCPT the MX refused, proven anyway", group: "sender", clause: "mixed recipients", applies: fs31Every,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) {
				script.RcptReplies["carol"] = "550 5.1.1 Recipient refused"
			},
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{prover: &proverAdversary{skipSelfCheck: true, ignoreRefusals: true}}
			},
			expect: fs31RefusedAt(3, checkZ8),
		},
		{
			name: "a pipelined second transaction sent past the message", group: "sender", clause: "a pipelined second transaction", applies: fs31Every,
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{record: func(attack *fs31Attack, seq uint64, record []byte) [][]byte {
					last := attack.lastPart()
					if last == nil || seq+1 != last.LastRecord {
						return [][]byte{record}
					}
					return [][]byte{record, attack.sealClient(last.LastRecord, fs31Plaintext(attack.cell, "MAIL FROM:<mallory@other.example>\r\n"))}
				}}
			},
			expect: fs31SmuggleNothing,
		},
		{
			name: "smuggled headers: a second From", group: "sender", clause: "smuggled headers", applies: fs31Every,
			message: func(cell *fs31Cell) *fs31Message {
				message := fs31DefaultMessage()
				message.extraHeaders = "From: Mallory Example <mallory@" + testNetworkDomain + ">\r\n"
				return message
			},
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{prover: &proverAdversary{skipSelfCheck: true}}
			},
			expect: fs31RefusedAt(3, checkZ5),
		},
		{
			name: "smuggled headers: a From behind a leading dot", group: "sender", clause: "smuggled headers", applies: fs31Every,
			message: func(cell *fs31Cell) *fs31Message {
				message := fs31DefaultMessage()
				message.extraHeaders = ".From: Mallory Example <mallory@other.example>\r\n"
				return message
			},
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{prover: &proverAdversary{skipSelfCheck: true}}
			},
			expect: fs31RefusedAt(3, checkZ5),
		},
		{
			name: "an early DATA end: an unstuffed dot line, a second transaction after it", group: "sender", clause: "a smuggled DATA terminator", applies: fs31Data,
			message:  fs31BodyMessage("a line\r\nX\r\n" + fs31SmuggledTransaction),
			settings: func(cell *fs31Cell, settings *ProverSettings) { settings.testDataRecordByteCount = 0 },
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{prover: &proverAdversary{skipSelfCheck: true, content: func(seq uint64, content []byte) []byte {
					return bytes.Replace(content, []byte("\r\nX\r\n"), []byte("\r\n.\r\n"), 1)
				}}}
			},
			expect: fs31RefusedAt(4, checkZ6),
		},
		{
			name: "a bare-LF DATA end to an MX that takes one", group: "sender", clause: "a bare-LF DATA terminator", applies: fs31Data,
			script:   func(cell *fs31Cell, script *sidecartest.MxScript) { script.LaxDataEnd = true },
			message:  fs31BodyMessage("a line\r\nXX\r\n" + fs31SmuggledTransaction),
			settings: func(cell *fs31Cell, settings *ProverSettings) { settings.testDataRecordByteCount = 0 },
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{prover: &proverAdversary{skipSelfCheck: true, content: func(seq uint64, content []byte) []byte {
					return bytes.Replace(content, []byte("\r\nXX\r\n"), []byte("\r\n.\n\r\n"), 1)
				}}}
			},
			expect: fs31RefusedAt(4, checkZ6),
		},
		{
			name: "a second transaction in the BDAT body, the MX offering CHUNKING", group: "sender", clause: "a second transaction in the alleged BDAT body", applies: fs31Bdat, t3: true,
			message: fs31BodyMessage("a line\r\n.\r\n" + fs31SmuggledTransaction),
			expect:  fs31Delivered,
			check:   fs31ExpectOneMail,
		},
		{
			name: "BDAT to an MX without CHUNKING, a second transaction in its body", group: "sender", clause: "a second transaction in the alleged BDAT body", applies: fs31Bdat,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) {
				script.Keywords = fs31Without(script.Keywords, "CHUNKING")
			},
			message: fs31BodyMessage("a line\r\n.\r\n" + fs31SmuggledTransaction),
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{prover: &proverAdversary{skipSelfCheck: true, forceMode: partModeBdat}}
			},
			expect: fs31RefusedAt(2, checkZ9),
		},
		{
			name: "BDAT to an MX offering CHUNKING only before TLS", group: "sender", clause: "pre-TLS-only CHUNKING", applies: fs31Bdat,
			script: func(cell *fs31Cell, script *sidecartest.MxScript) {
				script.PreTlsKeywords = append(slices.Clone(script.PreTlsKeywords), "CHUNKING")
				script.Keywords = fs31Without(script.Keywords, "CHUNKING")
			},
			message: fs31BodyMessage("a line\r\n.\r\n" + fs31SmuggledTransaction),
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{prover: &proverAdversary{skipSelfCheck: true, forceMode: partModeBdat}}
			},
			expect: fs31RefusedAt(2, checkZ9),
		},

		// DESIGN-DETAILS 3.6's rows over parts bound to one key part
		{
			name: "a later part under other keys than the key part's", group: "bound parts", clause: "a later part under other keys than the key part committed", applies: fs31Every,
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{witness: func(attack *fs31Attack, statement *partStatement, witness *partWitness) {
					if statement.index == 2 {
						fs31OtherKeysWitness(attack, statement, witness)
					}
				}}
			},
			expect: fs31RefusedAt(2, checkZ1),
		},
		{
			name: "a header record scanned from a forged state, a single field's name split across two records", group: "bound parts", clause: "a header record scanned from a forged state", applies: fs31Every,
			message: func(cell *fs31Cell) *fs31Message {
				message := fs31DefaultMessage()
				message.headerBlock = fs31SplitNameHeaderBlock
				return message
			},
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{witness: func(attack *fs31Attack, statement *partStatement, witness *partWitness) {
					if statement.index == 4 {
						fs31ForgedCarryWitness(attack, statement, witness)
					}
				}}
			},
			expect: fs31RefusedAt(4, checkZ5),
		},
		{
			name: "a body record scanned from a forged state", group: "bound parts", clause: "a body record scanned from a forged state in DATA mode", applies: fs31Data,
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{witness: func(attack *fs31Attack, statement *partStatement, witness *partWitness) {
					if statement.index == 5 {
						fs31ForgedCarryWitness(attack, statement, witness)
					}
				}}
			},
			expect: fs31RefusedAt(5, checkZ6),
		},
		{
			name: "reply_count one fewer than the records hold, the envelope one command a group", group: "bound parts", clause: "a reply count the records do not hold", applies: fs31Every, t3: true,
			message: func(cell *fs31Cell) *fs31Message {
				message := fs31DefaultMessage()
				message.envelopeGroupMaxCount = 1
				return message
			},
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{part: func(attack *fs31Attack, part *sidecar.SmtpProofPart) {
					if part.Index == 3 {
						part.ReplyCount -= 1
					}
				}}
			},
			expect: fs31RefusedAt(3, checkZ8),
		},
		{
			name: "reply_count one more than the records hold", group: "bound parts", clause: "a reply count the records do not hold", applies: fs31Every, t3: true,
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{part: func(attack *fs31Attack, part *sidecar.SmtpProofPart) {
					if part.Index == 3 {
						part.ReplyCount += 1
					}
				}}
			},
			expect: fs31RefusedAt(3, checkE3),
		},
		{
			name: "a message record before the envelope's replies are proven", group: "bound parts", clause: "a message record submitted before the envelope's replies are proven", applies: fs31Every, t3: true,
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return &fs31Adversary{
					witness: func(attack *fs31Attack, statement *partStatement, witness *partWitness) {
						if statement.index == 3 {
							witness.serverPlaintexts = nil
						}
					},
					part: func(attack *fs31Attack, part *sidecar.SmtpProofPart) {
						if part.Index == 3 {
							part.ServerRecordCount = attack.part(2).ServerRecordCount
							part.ReplyCount = 0
						}
					},
				}
			},
			expect: fs31RefusedAt(3, checkE3),
		},

		// BDAT's unopened body (SPEC.md 9.5)
		{
			name: "BDAT body records padded past QUIT, a second transaction in them", group: "body records", clause: "padded BDAT body records", applies: fs31Bdat13, endAtQuit: true,
			message: fs31BodyMessage(strings.Repeat("a body line, unopened as BDAT's body is\r\n", 8)),
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return fs31BodyRewriter(func(content []byte) []byte {
					smuggled := "\r\n.\r\n" + fs31SmuggledTransaction
					carried := len(content) - 64
					inner := []byte(smuggled + strings.Repeat("x", carried-len(smuggled)))
					return append(append(inner, tlsRecordApplicationData), make([]byte, 64)...)
				})
			},
			expect: fs31SmuggleNothing,
			check:  fs31ExpectNoTransaction,
		},
		{
			name: "BDAT body records padded short of QUIT", group: "body records", clause: "padded BDAT body records", applies: fs31Bdat13, endAtQuit: true,
			message: fs31BodyMessage(strings.Repeat("a body line, unopened as BDAT's body is\r\n", 8)),
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return fs31BodyRewriter(func(content []byte) []byte {
					inner := bytes.Clone(content[:len(content)-2])
					return append(append(inner, tlsRecordApplicationData), 0, 0)
				})
			},
			expect: fs31SmuggleNothing,
		},
		{
			name: "a KeyUpdate in place of a BDAT body record", group: "body records", clause: "KeyUpdate BDAT body records", applies: fs31Bdat13, endAtQuit: true,
			message: fs31BodyMessage(strings.Repeat("a body line, unopened as BDAT's body is\r\n", 8)),
			adversary: func(cell *fs31Cell) *fs31Adversary {
				return fs31BodyRewriter(func(content []byte) []byte {
					keyUpdate := []byte{tlsHandshakeKeyUpdate, 0, 0, 1, 0, tlsRecordHandshake}
					return append(keyUpdate, make([]byte, len(content)+tlsInnerTypeBytes-len(keyUpdate))...)
				})
			},
			expect: fs31SmuggleNothing,
			check:  fs31ExpectNoTransaction,
		},

		// a malicious edge, the MX honest
		{
			name: "an honest TLS 1.2 MX answers 451 while the edge forges 250", group: "edge", clause: "an honest TLS 1.2 MX answers 451 while the edge forges 250", applies: fs31Tls12,
			script:          func(cell *fs31Cell, script *sidecartest.MxScript) { script.MessageReply = "451 4.3.0 Try again later" },
			forgeServerFrom: func(cell *fs31Cell) int { return fs31MessageReplyIndex(cell, 2) },
			expect:          fs31ProverFails,
			check: func(t *testing.T, name string, outcome *fs31Outcome) {
				// the MX's answer was its own 451, which no transaction followed
				replied451 := false
				for _, event := range outcome.mx.Events() {
					if event.Secure && strings.HasPrefix(event.Reply, "451") {
						replied451 = true
					}
				}
				if !replied451 {
					t.Errorf("%s: the MX never answered the message", name)
				}
			},
		},
		{
			name: "an honest TLS 1.2 MX while the edge forges its EHLO reply and every reply after", group: "edge", clause: "the edge forges 250 and EHLO replies", applies: fs31Tls12,
			forgeServerFrom: func(cell *fs31Cell) int { return 1 },
			expect:          fs31ProverFails,
		},
	}
}

// The send went in mode.
func fs31ExpectMode(mode uint32) func(t *testing.T, name string, outcome *fs31Outcome) {
	return func(t *testing.T, name string, outcome *fs31Outcome) {
		if outcome.result != nil && outcome.result.Mode != mode {
			t.Errorf("%s: mode %d, want %d", name, outcome.result.Mode, mode)
		}
	}
}

// The MX accepted one MAIL, the honest one: what the body held stayed the body.
func fs31ExpectOneMail(t *testing.T, name string, outcome *fs31Outcome) {
	mails := 0
	for _, command := range fs31SecureAccepted(outcome.mx) {
		if strings.HasPrefix(strings.ToUpper(command), "MAIL FROM:") {
			mails += 1
		}
	}
	if mails != 1 {
		t.Errorf("%s: the MX accepted %d MAIL commands", name, mails)
	}
}

// The MX took no transaction.
func fs31ExpectNoTransaction(t *testing.T, name string, outcome *fs31Outcome) {
	if transactions := outcome.mx.Transactions(); len(transactions) != 0 {
		t.Errorf("%s: the MX took %d transactions", name, len(transactions))
	}
}

// A malicious sender rewriting the one BDAT body record: rewrite returns its new inner plaintext, type octet and any
// padding included, as long as the honest record's content and type octet; the proven QUIT goes straight after it,
// without waiting for the MX's reply to the chunk, as a sender trying to end the chunk early would (SPEC.md 9.5).
func fs31BodyRewriter(rewrite func(content []byte) []byte) *fs31Adversary {
	return &fs31Adversary{record: func(attack *fs31Attack, seq uint64, record []byte) [][]byte {
		last := attack.lastPart()
		// the last part opens BDAT, the header block's one record and QUIT, past the unopened body between
		if last == nil || seq <= last.FirstRecord+1 || last.LastRecord <= seq {
			return [][]byte{record}
		}
		plaintext := attack.openClient(seq, record)
		content := plaintext[:len(plaintext)-tlsInnerTypeBytes]
		inner := rewrite(content)
		if len(inner) != len(plaintext) {
			attack.t.Errorf("a rewritten body record of %d octets for %d", len(inner), len(plaintext))
			return [][]byte{record}
		}
		keys := attack.backend.connectionKeys()
		opener, err := newTlsCipher(tlsVersion13, attack.cell.leg.suites[0], keys.clientKey, keys.clientIv)
		if err != nil {
			attack.t.Error(err)
			return [][]byte{record}
		}
		header := bytes.Clone(record[:tlsRecordHeaderBytes])
		sent := [][]byte{opener.aead.Seal(header, tls13Nonce(keys.clientIv, seq), inner, header)}
		if seq+1 == last.LastRecord {
			sent = append(sent, last.Records[len(last.Records)-1])
		}
		return sent
	}}
}

// How many of the honest dialog's commands inside TLS the parts the edge took opened: the MX may have accepted
// these and none after them.
func fs31OpenedCommandCount(outcome *fs31Outcome, accepted []*sidecar.SmtpProofPart) int {
	first := firstApplicationSeq(tlsVersion13)
	if outcome.cell.tls12() {
		first = firstApplicationSeq(tlsVersion12)
	}
	count := 0
	for _, part := range accepted {
		if len(part.Records) == 0 {
			continue
		}
		count = max(count, int(part.LastRecord-first)+1)
	}
	return min(count, len(fs31HonestCommands(outcome)))
}

// Holds an outcome to its row and returns what it came to, for the matrix.
func fs31Check(t *testing.T, row *fs31Row, outcome *fs31Outcome, accepted []*sidecar.SmtpProofPart) string {
	t.Helper()
	name := fmt.Sprintf("%s, %s on the %s", row.name, outcome.cell, outcome.edgeName)
	expect := row.expect(outcome.cell)
	fs31ExpectAgreement(t, name, outcome)
	if outcome.preambleCode != 0 {
		t.Errorf("%s: %v", name, outcome.err)
		return "preamble answered " + strconv.FormatUint(uint64(outcome.preambleCode), 10)
	}
	transactions := outcome.mx.Transactions()
	honest := fs31HonestCommands(outcome)
	// every command the MX accepted inside TLS is the honest dialog's, in its order, each once, beside QUIT and
	// the message itself
	limit := len(honest)
	if expect.refusedPart != 0 {
		limit = fs31OpenedCommandCount(outcome, accepted)
	}
	next := 0
	for _, command := range fs31SecureAccepted(outcome.mx) {
		if command == "QUIT" || strings.HasPrefix(command, "<data ") {
			continue
		}
		at := slices.Index(honest[next:min(limit, len(honest))], command)
		if at < 0 {
			t.Errorf("%s: the MX accepted %q, past what the parts the edge took opened of %q", name, command, honest[:limit])
			continue
		}
		next += at + 1
	}
	refusedIndex, refusedCheck := fs31Refused(outcome)
	result := ""
	switch {
	case expect.delivered:
		if outcome.err != nil || outcome.result == nil || !outcome.result.Accepted {
			t.Errorf("%s: not delivered: %+v, %v (edge: %v)", name, outcome.result, outcome.err, outcome.refusal)
		}
		if len(transactions) != 1 || !bytes.Equal(transactions[0].Message, outcome.job.Message) || len(transactions[0].Recipients) != len(outcome.job.RecipientLocals) {
			t.Errorf("%s: the MX took %d transactions", name, len(transactions))
		}
		if refusedIndex != 0 || outcome.refusal != nil {
			t.Errorf("%s: the edge refused part %d: %v", name, refusedIndex, outcome.refusal)
		}
		// the key part, an env part and the msg part at least, each verified
		if len(outcome.verdicts) < 3 || len(outcome.verdicts) != len(accepted) {
			t.Errorf("%s: %d verifications for %d parts the edge took", name, len(outcome.verdicts), len(accepted))
		}
		result = fmt.Sprintf("delivered, one transaction, %d parts", len(accepted))
	case expect.smuggleNothing:
		headerEnd := bytes.Index(outcome.job.Message, []byte("\r\n\r\n")) + len("\r\n\r\n")
		for _, transaction := range transactions {
			if !bytes.HasPrefix(transaction.Message, outcome.job.Message[:headerEnd]) || len(transaction.Recipients) != len(outcome.job.RecipientLocals) {
				t.Errorf("%s: the MX took a transaction the parts did not prove", name)
			}
		}
		if 1 < len(transactions) {
			t.Errorf("%s: the MX took %d transactions", name, len(transactions))
		}
		result = fmt.Sprintf("%d transaction, nothing smuggled", len(transactions))
	default:
		if len(transactions) != 0 {
			t.Errorf("%s: the MX took %d transactions", name, len(transactions))
		}
		if outcome.result != nil && outcome.result.Accepted {
			t.Errorf("%s: the send was reported accepted", name)
		}
	}
	if expect.refusedPart != 0 {
		if refusedIndex != expect.refusedPart || (expect.refusedCheck != "" && refusedCheck != expect.refusedCheck) {
			t.Errorf("%s: the edge refused part %d by %q (%v), want part %d by %q", name, refusedIndex, refusedCheck, outcome.refusal, expect.refusedPart, expect.refusedCheck)
		}
		result = fmt.Sprintf("refused at part %d by %s, no effect", refusedIndex, refusedCheck)
	}
	if expect.refusedCode != "" {
		if outcome.err != nil || outcome.result == nil || outcome.result.RefusedCode != expect.refusedCode {
			t.Errorf("%s: %+v, %v, want the MX's %s", name, outcome.result, outcome.err, expect.refusedCode)
		}
		if outcome.refusal != nil {
			t.Errorf("%s: the edge refused: %v", name, outcome.refusal)
		}
		result = "the MX's " + expect.refusedCode + " ends the send, no effect"
	}
	if expect.proverFails {
		if outcome.err == nil {
			t.Errorf("%s: the prover took a forged record: %+v", name, outcome.result)
		}
		result = "the prover refuses the forged record, no effect, the message kept"
	}
	if row.check != nil {
		row.check(t, name, outcome)
	}
	return result
}

// Runs a row in every cell it applies to, on the leg's edge, and reports each.
func fs31RunRow(t *testing.T, row *fs31Row) {
	t.Helper()
	ran := 0
	for _, cell := range fs31Cells() {
		if !row.applies(cell) {
			continue
		}
		message := fs31DefaultMessage()
		if row.message != nil {
			message = row.message(cell)
		}
		connection := &fs31Connection{
			cell:           cell,
			mx:             row.newMx(t, cell),
			message:        message,
			solveAll:       row.solveAll,
			recipientLimit: row.recipientLimit,
			endAtQuit:      row.endAtQuit,
		}
		if row.adversary != nil {
			connection.adversary = row.adversary(cell)
			if connection.adversary.prover == nil {
				connection.adversary.prover = &proverAdversary{}
			}
		}
		if row.forgeServerFrom != nil {
			connection.forgeServerFrom = row.forgeServerFrom(cell)
		}
		if row.settings != nil {
			connection.settings = func(settings *ProverSettings) { row.settings(cell, settings) }
		}
		outcome := fs31Run(t, connection)
		result := fs31Check(t, row, outcome, outcome.acceptedParts)
		fs31Report(row.name, outcome, result)
		ran += 1
	}
	if ran == 0 {
		t.Fatalf("%s ran in no cell", row.name)
	}
}

// Runs every row of a group.
func fs31RunGroup(t *testing.T, group string) {
	t.Helper()
	t.Parallel()
	ran := 0
	for _, row := range fs31Rows() {
		if row.group == group {
			fs31RunRow(t, row)
			ran += 1
		}
	}
	if ran == 0 {
		t.Fatalf("no row in group %s", group)
	}
	for _, entry := range strings.Split(fs31MatrixTable(t), "\n") {
		if strings.Contains(entry, "| ") {
			t.Log(entry)
		}
	}
}

func TestFs31HonestControls(t *testing.T) {
	fs31RunGroup(t, "control")
}

func TestFs31ScriptedMxs(t *testing.T) {
	fs31RunGroup(t, "mx")
}

func TestFs31MaliciousSender(t *testing.T) {
	fs31RunGroup(t, "sender")
}

func TestFs31PartsBoundToOneKeyPart(t *testing.T) {
	fs31RunGroup(t, "bound parts")
}

func TestFs31BdatBodyRecords(t *testing.T) {
	fs31RunGroup(t, "body records")
}

func TestFs31MaliciousEdge(t *testing.T) {
	fs31RunGroup(t, "edge")
}

// Where each row runs: the T2 legs, and T3 where server reruns it.
func fs31RowTiers(row *fs31Row) string {
	tiers := "T2 engine (sidecar_testhooks), T2 gate with circuits on the solver (plain)"
	if row.t3 {
		tiers += ", T3 engine on server's stores"
	}
	return tiers
}

// What a row asserts in a cell, as the matrix states it.
func fs31ExpectedResult(row *fs31Row, cell *fs31Cell) string {
	expect := row.expect(cell)
	switch {
	case expect.refusedPart != 0 && expect.refusedCheck != "":
		return fmt.Sprintf("refused at part %d by %s before any effect", expect.refusedPart, expect.refusedCheck)
	case expect.refusedPart != 0:
		return fmt.Sprintf("refused at part %d before any effect", expect.refusedPart)
	case expect.refusedCode != "":
		return "the MX's " + expect.refusedCode + " ends the send; no effect"
	case expect.proverFails:
		return "the prover refuses the forged record; no effect; the message kept"
	case expect.smuggleNothing:
		return "at most the proven transaction; nothing smuggled"
	}
	return "delivered: one transaction, the proven one"
}

// The evidence table: one line a row and cell, with where it runs and what it asserts.
func fs31MatrixDocument() string {
	var table strings.Builder
	table.WriteString("# FS-31's matrix (SMTP-M9-30)\n\n")
	table.WriteString("Written by `TestFs31MatrixTable` from `fs31_test.go`'s rows, which fails when this file differs; set `SMTPPROOF_WRITE_FS31` to rewrite it. ")
	table.WriteString("Each row runs in every cell it names, through the leg's edge: the real engine (`smtpedgeservice`) with smtpproof's Verifier, whose session is `edgeSession`, under `sidecar_testhooks`, and `edgeSession` alone with each part's circuit on gnark's solver beside the relation in the plain leg; a row marked T3 also runs on server's stores through `server/cli/smtpedge/fs31_test.go`. ")
	table.WriteString("Every row's MX is sidecartest's ScriptedMx or RecordMx, whose record of accepted commands and transactions is the assertion: a row that is not delivered leaves no transaction and no command accepted inside TLS but the honest dialog's, none past what the parts before the refused one opened. ")
	table.WriteString("A run's own results, with the tier it ran on, go to its log, and to the file `SMTPPROOF_FS31_MATRIX` names.\n\n")
	table.WriteString("| Row | FS-31 | Cell | Tiers | Asserts |\n|---|---|---|---|---|\n")
	for _, row := range fs31Rows() {
		for _, cell := range fs31Cells() {
			if row.applies(cell) {
				fmt.Fprintf(&table, "| %s | %s | %s | %s | %s |\n", row.name, row.clause, cell, fs31RowTiers(row), fs31ExpectedResult(row, cell))
			}
		}
	}
	return table.String()
}

// The rows against testdata/fs31/matrix.md, and every clause of FS-31 against a row.
func TestFs31MatrixTable(t *testing.T) {
	path := filepath.Join("testdata", "fs31", "matrix.md")
	document := fs31MatrixDocument()
	if os.Getenv("SMTPPROOF_WRITE_FS31") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(document), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != document {
		t.Errorf("%s differs from fs31_test.go's rows; set SMTPPROOF_WRITE_FS31 to rewrite it", path)
	}
	// §22.5's FS-31 row and DESIGN-DETAILS 3.6's additions, each answered by a row
	for _, clause := range []string{
		"no CHUNKING", "pre-TLS-only CHUNKING", "no PIPELINING", "MAIL refused", "RCPT refused", "no 354", "mixed recipients",
		"a late NewSessionTicket", "a second transaction in the alleged BDAT body", "record splits", "replayed server replies",
		"a smuggled DATA terminator", "a bare-LF DATA terminator", "key substitution", "a pipelined second transaction", "smuggled headers",
		"a later part under other keys than the key part committed", "a header record scanned from a forged state",
		"a body record scanned from a forged state in DATA mode", "a reply count the records do not hold",
		"a message record submitted before the envelope's replies are proven", "padded BDAT body records", "KeyUpdate BDAT body records",
		"positive controls passing", "a 100-recipient send", "a 16 KiB header block",
		"an honest TLS 1.2 MX answers 451 while the edge forges 250", "the edge forges 250 and EHLO replies",
	} {
		if !slices.ContainsFunc(fs31Rows(), func(row *fs31Row) bool { return row.clause == clause }) {
			t.Errorf("no row answers %q", clause)
		}
	}
	// both TLS versions and both modes
	for _, version := range []bool{false, true} {
		for _, data := range []bool{false, true} {
			found := false
			for _, row := range fs31Rows() {
				for _, cell := range fs31Cells() {
					found = found || (row.applies(cell) && cell.tls12() == version && cell.data == data && row.group != "control")
				}
			}
			if !found {
				t.Errorf("no adversarial row runs under TLS 1.2 %t and DATA %t", version, data)
			}
		}
	}
}
