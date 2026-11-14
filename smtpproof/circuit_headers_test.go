// Z5 in the circuit beside the relation: the header block, read by a per-octet automaton over private
// content (SPEC.md Z5). What the sender's assembly makes must pass both, every break of Z5 must fail
// both, and what the scan costs an octet is held to SPEC.md 11.2. The external test of
// circuit_agreement_test.go holds the circuit to the independent checker as well.

package smtpproof

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// One message the sender assembled and signed, with the preamble values its header block carries.
type testAssembledBlock struct {
	name             string
	block            []byte
	flags            uint32
	messageId        string
	headerFromDomain string
}

// Messages MAIL might hand over (§15.10's step 4), through AssembleSmtpMessage and SmtpDkimSign as
// SMTP-M9-04 makes them, each cut at its header block's end.
func testAssembledHeaderBlocks(t *testing.T) []*testAssembledBlock {
	t.Helper()
	signTime := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	from := "<a@" + testAssembleRelationDomain + ">"
	id := "Message-ID: <" + testAssembleRelationId + ">\n"
	var blocks []*testAssembledBlock
	for _, c := range []struct {
		name    string
		message string
		flags   uint32
	}{
		{name: "a plain message", message: "From: Joe SixPack <joe@n1.root.example>\nTo: Suzie Q <suzie@shopping.example>\nBcc: b@c.example\nSubject: Is dinner ready?\n" + id + "\nHi.\n"},
		{name: "a quoted phrase and an 8-bit subject", message: "From: \"J. Smith, Esq\" <j@n1.root.example>\n" + id + "Subject: caf\xc3\xa9\n\n.leading dot\n"},
		{name: "a bulk message", message: "From: " + from + "\n" + id + "List-Unsubscribe: <https://u.example/x>\n\nbulk\n", flags: sidecar.SmtpFlagBulk | sidecar.SmtpFlagRequireTls},
		{name: "a message of no body", message: "From: " + from + "\n" + id},
		{name: "an 8-bit phrase", message: "From: Al\xc3\xadce <alice@n1.root.example>\nTo: <b@shopping.example>, <c@shopping.example>\n" + id + "\nbody\n"},
		{name: "a reply", message: "From: " + from + "\nTo: <b@shopping.example>\nCc: <c@shopping.example>\nSubject: Re: plans\nIn-Reply-To: <x1@shopping.example>\nReferences: <x0@shopping.example> <x1@shopping.example>\n" + id + "\nyes\n"},
		{name: "a MIME message", message: "From: " + from + "\n" + id + "MIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=\"b1\"\n\n--b1\nContent-Type: text/plain; charset=utf-8\n\nplain\n--b1--\n"},
		{name: "a folded subject", message: "From: " + from + "\n" + id + "Subject: a subject\n written over\n\tthree lines\n\nbody\n"},
	} {
		wire, err := sidecar.AssembleSmtpMessage(&sidecar.SmtpAssembleArgs{
			Message:          []byte(strings.ReplaceAll(c.message, "\n", "\r\n")),
			HeaderFromDomain: testAssembleRelationDomain,
			MessageIdDomain:  testAssembleRelationDomain,
			Flags:            c.flags,
			Now:              signTime,
		})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		signed, err := sidecar.SmtpDkimSign(wire, &sidecar.SmtpDkimSignArgs{
			Signer:        testAssembleRelationSigner{},
			Issued:        &sidecar.SmtpIssuedHeaders{XUrRef: testAssembleRelationXUrRef, FeedbackId: testAssembleRelationFeedback},
			SignTime:      signTime,
			ExpireTimeout: 7 * 24 * time.Hour,
		})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		end := bytes.Index(signed, []byte(literalCrlf+literalCrlf)) + 2*len(literalCrlf)
		blocks = append(blocks, &testAssembledBlock{
			name:             c.name,
			block:            signed[:end],
			flags:            c.flags,
			messageId:        wire.MessageId(),
			headerFromDomain: wire.HeaderFromDomain(),
		})
	}
	return blocks
}

// Part 3 of a real connection, its header block one the sender assembled and its preamble that
// message's.
func testAssembledPart(t *testing.T, capture *testCapturedParts, assembled *testAssembledBlock) (*partStatement, *partWitness) {
	t.Helper()
	statement, witness := capture.part(t, 3)
	preamble := statement.session.preamble
	preamble.messageId = assembled.messageId
	preamble.headerFromDomain = assembled.headerFromDomain
	preamble.dkimSelector = testAssembleRelationSelector
	preamble.xUrRef = testAssembleRelationXUrRef
	preamble.feedbackId = testAssembleRelationFeedback
	preamble.flags = assembled.flags
	testAuthorHeaderBlock(t, statement, witness, string(assembled.block))
	return statement, witness
}

func TestHeaderCircuitAcceptsWhatTheSenderAssembles(t *testing.T) {
	t.Parallel()
	testNeedCircuits(t)
	assembled := testAssembledHeaderBlocks(t)
	largest := assembled[0]
	for _, entry := range assembled {
		if len(largest.block) < len(entry.block) {
			largest = entry
		}
	}
	// the two 1.3 suites: 1.2 reads the same block under AES, and TestHeaderCircuitAgreesWithTheRelation
	// runs every leg
	for _, leg := range testTlsLegs()[:2] {
		capture := testBdatCapture(t, leg)
		statement, _ := testAssembledPart(t, capture, largest)
		// one shape holds the whole corpus: a block fits any shape with room for it
		shape := testFitShape(t, statement, 0)
		compiled := testCompileShape(t, shape)
		t.Logf("%s: header blocks of up to %d octets, %d constraints", leg.name, len(largest.block), compiled.GetNbConstraints())
		for _, entry := range assembled {
			statement, witness := testAssembledPart(t, capture, entry)
			testCircuitAgrees(t, leg.name+": "+entry.name, shape, compiled, statement, witness, true)
		}
	}
}

// A header block of testHeaderBlock's with one change, under flags, and whether Z5 takes it.
type testHeaderBlockCase struct {
	name   string
	block  string
	flags  uint32
	accept bool
}

// Breaks of Z5 that testSmuggledHeaders does not hold, each beside an honest twin: SMTP-M9-23's list.
func testHeaderBlockCases(t *testing.T) []*testHeaderBlockCase {
	t.Helper()
	header := testHeaderBlock()
	fromLine := "From: Alice Example <alice@" + testNetworkDomain + ">\r\n"
	messageIdLine := literalMessageIdPrefix + testMessageId + ">\r\n"
	xUrRefLine := literalXUrRefPrefix + testXUrRef + "\r\n"
	feedbackLine := literalFeedbackPrefix + testFeedbackId + "\r\n"
	unsubscribeLine := literalUnsubscribePost + literalCrlf
	replaced := func(old string, new string) string {
		if !strings.Contains(header, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(header, old, new, 1)
	}
	return []*testHeaderBlockCase{
		{name: "the honest block", block: header, accept: true},
		{name: "no Feedback-ID", block: replaced(feedbackLine, "")},
		{name: "a second Feedback-ID", block: replaced(feedbackLine, feedbackLine+feedbackLine)},
		{name: "a continued Feedback-ID", block: replaced(feedbackLine, feedbackLine+" x\r\n")},
		{name: "no X-UR-Ref", block: replaced(xUrRefLine, "")},
		{name: "a duplicate X-UR-Ref", block: replaced(xUrRefLine, xUrRefLine+xUrRefLine)},
		{name: "a continued X-UR-Ref", block: replaced(xUrRefLine, xUrRefLine+"\tx\r\n")},
		{name: "no Message-ID", block: replaced(messageIdLine, "")},
		{name: "a continued Message-ID", block: replaced(messageIdLine, messageIdLine+" <x@"+testNetworkDomain+">\r\n")},
		{name: "a Message-ID in lower case", block: replaced("Message-ID: <", "message-id: <")},
		{name: "a Message-ID without its brackets", block: replaced(messageIdLine, "Message-ID: "+testMessageId+"\r\n")},
		{name: "From in upper case", block: replaced(fromLine, "FROM: Alice Example <alice@"+testNetworkDomain+">\r\n")},
		{name: "From with a trailing comment", block: replaced(fromLine, "From: Alice <alice@"+testNetworkDomain+"> (work)\r\n")},
		{name: "From of 64-octet local part", block: replaced(fromLine, "From: <"+strings.Repeat("a", 64)+"@"+testNetworkDomain+">\r\n"), accept: true},
		{name: "From of 65-octet local part", block: replaced(fromLine, "From: <"+strings.Repeat("a", 65)+"@"+testNetworkDomain+">\r\n")},
		{name: "From with an empty local part", block: replaced(fromLine, "From: <@"+testNetworkDomain+">\r\n")},
		{name: "From whose phrase is spaces", block: replaced(fromLine, "From:  <alice@"+testNetworkDomain+">\r\n"), accept: true},
		{name: "From whose phrase holds a quote", block: replaced(fromLine, "From: \"Alice\" <alice@"+testNetworkDomain+">\r\n")},
		{name: "From with no space before the address", block: replaced(fromLine, "From: Alice<alice@"+testNetworkDomain+">\r\n")},
		{name: "the fixed signature in lower case", block: replaced("DKIM-Signature: v=1;", "dkim-signature: v=1;")},
		{name: "the fixed signature's tags in another order", block: replaced("d="+testNetworkDomain+"; s="+testSelector+";", "s="+testSelector+"; d="+testNetworkDomain+";")},
		{name: "the fixed signature under another selector of the same length", block: replaced("s="+testSelector+";", "s=x"+testSelector[1:]+";")},
		{name: "BULK without List-Unsubscribe-Post", block: header, flags: preambleFlagBulk},
		{name: "BULK with List-Unsubscribe-Post", block: unsubscribeLine + header, flags: preambleFlagBulk, accept: true},
		{name: "BULK with two List-Unsubscribe-Post", block: unsubscribeLine + unsubscribeLine + header, flags: preambleFlagBulk},
		{name: "BULK with List-Unsubscribe-Post in lower case", block: "list-unsubscribe-post: List-Unsubscribe=One-Click\r\n" + header, flags: preambleFlagBulk},
		// RFC 8058's single key/value pair: a continuation, or a second field, leaves no one-click field
		{name: "BULK with List-Unsubscribe-Post continued", block: unsubscribeLine + " x\r\n" + header, flags: preambleFlagBulk},
		{name: "BULK with a second List-Unsubscribe-Post of another value", block: unsubscribeLine + "List-Unsubscribe-Post: x\r\n" + header, flags: preambleFlagBulk},
		{name: "BULK with List-Unsubscribe-Post of another value", block: "List-Unsubscribe-Post: List-Unsubscribe=One-Click, x\r\n" + header, flags: preambleFlagBulk},
		{name: "List-Unsubscribe-Post without BULK", block: unsubscribeLine + header, accept: true},
		{name: "List-Unsubscribe-Post continued without BULK", block: unsubscribeLine + " x\r\n" + header, accept: true},
		{name: "two List-Unsubscribe-Post without BULK", block: unsubscribeLine + "list-unsubscribe-post: y\r\n" + header, accept: true},
	}
}

func TestHeaderCircuitAgreesWithTheRelation(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		shape := testQuickMessageShape(leg.suites[0])
		compiled := testCompileShape(t, shape)
		capture := testBdatCapture(t, leg)
		for _, c := range testHeaderBlockCases(t) {
			statement, witness := capture.part(t, 3)
			statement.session.preamble.flags |= c.flags
			testAuthorHeaderBlock(t, statement, witness, c.block)
			var checks []relationCheck
			if !c.accept {
				checks = []relationCheck{checkZ5}
			}
			testCircuitAgrees(t, leg.name+": "+c.name, shape, compiled, statement, witness, c.accept, checks...)
		}
	}
}

func TestHeaderCircuitAgreesWithTheRelationInDataMode(t *testing.T) {
	t.Parallel()
	// DATA reads the same block with Z6's line rules beside Z5's, so the breaks that are also DATA
	// framing fail both, and the rest Z5 alone. One leg: the automaton is the one the BDAT table runs
	// on every leg, and what DATA adds is the framing beside it
	for _, leg := range testTlsLegs()[1:2] {
		shape := testQuickMessageShape(leg.suites[0])
		compiled := testCompileShape(t, shape)
		capture := testDataCapture(t, leg)
		cases := append(testHeaderBlockCases(t), &testHeaderBlockCase{name: "a bare LF", block: strings.Replace(testHeaderBlock(), "Subject: A", "Subject:\nA", 1)})
		for _, c := range cases {
			statement, witness := capture.part(t, 3)
			statement.session.preamble.flags |= c.flags
			testAuthorClientRecord(t, statement, witness, 0, []byte(c.block))
			// the declared count follows the block, so the count decides nothing here
			statement.session.preamble.messageByteCount = 100000
			testCircuitAgrees(t, leg.name+": "+c.name, shape, compiled, statement, witness, c.accept)
		}
	}
}

// What the header scans cost, SPEC.md 11.2's measured rows, held here: two shapes 64 header octets
// apart, Z1 left out, so the difference is 64 octets of Z5's scan and Z2's keystream. The first record's
// scan reads the single fields' literal forms and From's parts; a later record's reads none.
var testSpecHeaderOctetCosts = map[string]int{
	"aes first":      57264,
	"chacha20 first": 32429,
	"aes later":      52513,
	"chacha20 later": 27678,
}

func TestHeaderScanCostIsSpecMds(t *testing.T) {
	t.Parallel()
	for _, suite := range []uint16{tlsSuiteAes128GcmSha256, tlsSuiteChacha20Poly1305Sha256} {
		for _, first := range []bool{true, false} {
			name := "aes"
			keystream := testSpecGadgetSizes["aes keystream block"] * 4
			if suite == tlsSuiteChacha20Poly1305Sha256 {
				name = "chacha20"
				keystream = testSpecGadgetSizes["chacha20 keystream block"]
			}
			blocks := 16
			if suite == tlsSuiteChacha20Poly1305Sha256 {
				blocks = 4
			}
			shape := testPartShape(partKindHeader, suiteFamily(suite), 0)
			shape.clientBlocks = 1
			shape.restBlocks = blocks
			name += " later"
			if first {
				shape = testPartShape(partKindMessage, suiteFamily(suite), 0)
				shape.clientBlocks = 1
				shape.serverBlocks = 1
				shape.headBlocks = blocks
				name = strings.Replace(name, "later", "first", 1)
			}
			wider := *shape
			if first {
				wider.headBlocks += 64 / shape.blockBytes()
			} else {
				wider.restBlocks += 64 / shape.blockBytes()
			}
			cost := testCompileShape(t, &wider).GetNbConstraints() - testCompileShape(t, shape).GetNbConstraints()
			t.Logf("%s: 64 header octets cost %d constraints, %d beyond the keystream, %.1f an octet", name, cost, cost-keystream, float64(cost-keystream)/64)
			if want := testSpecHeaderOctetCosts[name]; cost != want {
				t.Errorf("%s: 64 header octets cost %d constraints, SPEC.md 11.2 says %d", name, cost, want)
			}
		}
	}
}
