// The scans across records (DESIGN-DETAILS 3.2.4) beside their single passes: a header block or a DATA
// body cut into records anywhere the gate allows is accepted record by record, carries chained, exactly
// when the single pass over the whole accepts it and, for a header block, its single fields and fixed
// signature lie in the first record. Each cut DESIGN-DETAILS 3.6 names is here, through the relation
// over every length and through the circuit at the boundary cases.

package smtpproof

import (
	"bytes"
	"strings"
	"testing"

	"github.com/consensys/gnark/constraint"
)

// A header block as SMTP-M9-04 orders it: the single fields and the fixed signature first.
func testOrderedHeaderBlock(filler int) string {
	return strings.TrimSuffix(testHeaderBlock(), "\r\n") + strings.Repeat("X-Padding: a line of filler past the first record\r\n", filler) + "\r\n"
}

// The verdict of the scan by records cut at the given lengths, carries chained, and the states between.
func testScanHeaderCut(preamble *sessionPreamble, block []byte, cuts []int) ([]scanState, error) {
	var states []scanState
	state := scanStart
	start := 0
	for i := 0; i <= len(cuts); i += 1 {
		end := len(block)
		if i < len(cuts) {
			end = cuts[i]
		}
		var err error
		if state, err = scanHeaderRecord(preamble, block[start:end], state, i == 0, i == len(cuts)); err != nil {
			return states, err
		}
		states = append(states, state)
		start = end
	}
	return states, nil
}

// Whether the single fields' lines and the fixed signature's line through its tags end by octet end.
func testSinglesWithin(preamble *sessionPreamble, block []byte, end int) bool {
	first := block[:end]
	for _, literal := range []string{
		literalMessageIdPrefix + preamble.messageId + ">" + literalCrlf,
		literalXUrRefPrefix + preamble.xUrRef + literalCrlf,
		literalFeedbackPrefix + preamble.feedbackId + literalCrlf,
		literalDkimPrefix + dkimTags(preamble),
	} {
		if !bytes.Contains(first, []byte(literal)) {
			return false
		}
	}
	from := bytes.Index(block, []byte(literalFromPrefix))
	return 0 <= from && bytes.Contains(first[from:], []byte(literalCrlf))
}

func TestHeaderRecordScanAgreesWithTheSinglePassAtEveryCut(t *testing.T) {
	preamble := newSessionPreamble(testJob("", "bob").Preamble, DefaultProofSettings())
	proof := preamble.proof
	block := []byte(testOrderedHeaderBlock(30))
	whole := checkHeaderBlock(block, preamble)
	if whole != nil {
		t.Fatal(whole)
	}
	for cut := proof.HeaderRecordMinByteCount; cut <= len(block)-proof.HeaderLastRecordMinByteCount; cut += 1 {
		_, err := testScanHeaderCut(preamble, block, []int{cut})
		if want := testSinglesWithin(preamble, block, cut); (err == nil) != want {
			t.Errorf("a cut at %d: %v, want accepted %t", cut, err, want)
		}
	}
	// three records, at every first cut past the fixed signature and a second 200 octets on
	for cut := 700; cut+200 <= len(block)-proof.HeaderLastRecordMinByteCount; cut += 1 {
		if _, err := testScanHeaderCut(preamble, block, []int{cut, cut + 200}); err != nil {
			t.Errorf("cuts at %d and %d: %v", cut, cut+200, err)
		}
	}
}

func TestHeaderRecordScanRefusesALiteralAcrossABoundary(t *testing.T) {
	preamble := newSessionPreamble(testJob("", "bob").Preamble, DefaultProofSettings())
	block := testOrderedHeaderBlock(30)
	signature := strings.Index(block, "DKIM-Signature:")
	// the fixed prefix cut at each of its octets, across the first boundary
	for at := 1; at < len(literalDkimPrefix); at += 1 {
		if _, err := testScanHeaderCut(preamble, []byte(block), []int{signature + at}); err == nil {
			t.Errorf("the fixed prefix cut after %d octets: accepted", at)
		}
	}
	// each single field's name cut at each of its octets across the first boundary, and a second copy of
	// it cut across a later one
	for _, name := range []string{"Message-ID:", "X-UR-Ref:", "Feedback-ID:", "From:"} {
		at := strings.Index(block, name)
		for octet := 1; octet < len(name); octet += 1 {
			if _, err := testScanHeaderCut(preamble, []byte(block), []int{at + octet}); err == nil && at+octet >= 128 {
				t.Errorf("%s cut after %d octets across the first boundary: accepted", name, octet)
			}
		}
		smuggled := strings.TrimSuffix(block, "\r\n") + name + " smuggled\r\n" + strings.Repeat("X-Tail: more\r\n", 12) + "\r\n"
		later := strings.LastIndex(smuggled, name)
		for octet := 1; octet < len(name); octet += 1 {
			if _, err := testScanHeaderCut(preamble, []byte(smuggled), []int{900, later + octet}); err == nil {
				t.Errorf("a second %s cut after %d octets across a later boundary: accepted", name, octet)
			}
		}
		// and whole inside a later record
		if _, err := testScanHeaderCut(preamble, []byte(smuggled), []int{900, later - 10}); err == nil {
			t.Errorf("a second %s inside a later record: accepted", name)
		}
	}
}

func TestHeaderRecordScanRefusesASingleFieldContinuedAcrossTheBoundary(t *testing.T) {
	preamble := newSessionPreamble(testJob("", "bob").Preamble, DefaultProofSettings())
	// Feedback-ID moved after the fixed signature, to end the first record
	line := literalFeedbackPrefix + preamble.feedbackId + literalCrlf
	block := strings.Replace(testOrderedHeaderBlock(30), line, "", 1)
	signature := strings.Index(block, "DKIM-Signature:")
	signatureEnd := signature + strings.Index(block[signature:], literalCrlf) + len(literalCrlf)
	block = block[:signatureEnd] + line + block[signatureEnd:]
	end := signatureEnd + len(line)
	continued := block[:end] + " a continuation\r\n" + block[end:]
	if _, err := testScanHeaderCut(preamble, []byte(continued), []int{end}); err == nil {
		t.Error("a single field ending at the first record's end, then a continuation: accepted")
	}
	if _, err := testScanHeaderCut(preamble, []byte(block), []int{end}); err != nil {
		t.Errorf("a single field ending at the first record's end, then a field: %v", err)
	}
}

func TestHeaderRecordScanTakesCrAndLfEitherSideOfABoundary(t *testing.T) {
	preamble := newSessionPreamble(testJob("", "bob").Preamble, DefaultProofSettings())
	block := testOrderedHeaderBlock(30)
	crlf := strings.LastIndex(block[:1200], "\r\n")
	for _, cut := range []int{crlf, crlf + 1, crlf + 2} {
		states, err := testScanHeaderCut(preamble, []byte(block), []int{cut})
		if err != nil {
			t.Errorf("a cut at %d beside a CRLF: %v", cut, err)
			continue
		}
		if want := map[int]uint32{crlf: scanPosLine, crlf + 1: scanPosCr, crlf + 2: scanPosLf}[cut]; states[0].pos() != want {
			t.Errorf("a cut at %d leaves pos %d, want %d", cut, states[0].pos(), want)
		}
	}
	// a bare CR before the boundary, answered by no LF after it
	broken := []byte(block)
	broken[crlf+1] = 'x'
	if _, err := testScanHeaderCut(preamble, broken, []int{crlf + 1}); err == nil {
		t.Error("a CR at a boundary with no LF after it: accepted")
	}
}

func TestHeaderRecordScanRefusesAFinalCrlfCrlfCut(t *testing.T) {
	preamble := newSessionPreamble(testJob("", "bob").Preamble, DefaultProofSettings())
	block := []byte(testOrderedHeaderBlock(30))
	for octets := 1; octets < 4; octets += 1 {
		// the gate refuses a last record under 4 octets; the scan, a last record that is not CRLF CRLF
		if _, err := testScanHeaderCut(preamble, block, []int{len(block) - octets}); err == nil {
			t.Errorf("a last record of the final %d octets: accepted", octets)
		}
	}
	if _, err := testScanHeaderCut(preamble, block, []int{len(block) - 4}); err != nil {
		t.Errorf("a last record of CRLF CRLF: %v", err)
	}
}

// The verdict of DATA's body scan by records cut at the given lengths, carries chained.
func testScanBodyCut(body []byte, cuts []int) error {
	state := scanStart
	start := 0
	for i := 0; i <= len(cuts); i += 1 {
		end := len(body)
		if i < len(cuts) {
			end = cuts[i]
		}
		var err error
		if state, err = scanBodyRecord(body[start:end], state, i == len(cuts)); err != nil {
			return err
		}
		start = end
	}
	return nil
}

func TestBodyRecordScanAgreesWithTheSinglePassAtEveryCut(t *testing.T) {
	bodies := []string{
		"first\r\n..\r\n.leading dot\r\nlast\r\n",
		"first\r\n.\r\nMAIL FROM:<x@" + testEnvelopeDomain + ">\r\n",
		"first\n.\nlast\r\n",
		"first\r.\r\n",
		"a\r\n.\r\n",
		".\r\nb\r\n",
		"first\r\nunfinished",
	}
	for _, body := range bodies {
		want := checkDataLines([]byte(body))
		for cut := 1; cut < len(body); cut += 1 {
			if err := testScanBodyCut([]byte(body), []int{cut}); (err == nil) != (want == nil) {
				t.Errorf("%q cut at %d: %v, the single pass says %v", body, cut, err, want)
			}
		}
	}
}

func TestBodyRecordScanCarriesTheDotRuleAcrossABoundary(t *testing.T) {
	// a "." line cut after its LF's line start, after the ".", and after the CR
	body := []byte("first\r\n.\r\nafter\r\n")
	for _, cut := range []int{7, 8, 9} {
		if err := testScanBodyCut(body, []int{cut}); err == nil {
			t.Errorf("a dot line cut at %d: accepted", cut)
		}
	}
	// a bare LF first in a record, after a record that ended in no CR
	if err := testScanBodyCut([]byte("first\nsecond\r\n"), []int{5}); err == nil {
		t.Error("a bare LF first in a record: accepted")
	}
}

// A BDAT send whose header block takes two records: its msg part (BDAT, header record 1) and its hdr
// part (header record 2, QUIT).
func testTwoRecordHeaderCapture(t *testing.T, leg *testTlsLeg) *testCapturedParts {
	t.Helper()
	job := testJob("", "bob")
	job.Message = []byte(testOrderedHeaderBlock(24) + "one line\r\n")
	job.Preamble.MessageByteCount = uint64(len(job.Message))
	capture := testCapture(t, leg, testMxDefaults(), DefaultProverSettings(), job)
	if statement, _ := capture.part(t, 3); statement.headerRecordCount != 2 {
		t.Fatalf("%s: the header block takes %d records", leg.name, statement.headerRecordCount)
	}
	return capture
}

// The msg and hdr parts with the header block cut into first and second, re-sealed under the true key,
// each carry the true state under a fresh blind, as a sidecar would commit them.
func testAuthorHeaderRecords(t *testing.T, capture *testCapturedParts, first string, second string) ([]*partStatement, []*partWitness) {
	t.Helper()
	message, messageWitness := capture.part(t, 3)
	header, headerWitness := capture.part(t, 4)
	testAuthorClientRecord(t, message, messageWitness, 1, []byte(first))
	testAuthorClientRecord(t, header, headerWitness, 0, []byte(second))
	preamble := message.session.preamble
	carry := func(state scanState) *proverCarry {
		carry, err := newProverCarry(state)
		if err != nil {
			t.Fatal(err)
		}
		return carry
	}
	outFirst, err := scanHeaderRecord(preamble, []byte(first), scanStart, true, false)
	if err != nil {
		outFirst = 0
	}
	carryFirst := carry(outFirst)
	message.carryOut, messageWitness.carryOutBlind = carryFirst.commitment, carryFirst.blind
	header.carryIn, headerWitness.carryInState, headerWitness.carryInBlind = carryFirst.commitment, carryFirst.state, carryFirst.blind
	outSecond, err := scanHeaderRecord(preamble, []byte(second), outFirst, false, true)
	if err != nil {
		outSecond = 0
	}
	carrySecond := carry(outSecond)
	header.carryOut, headerWitness.carryOutBlind = carrySecond.commitment, carrySecond.blind
	return []*partStatement{message, header}, []*partWitness{messageWitness, headerWitness}
}

func TestHeaderRecordCircuitsAgreeWithTheRelationAcrossABoundary(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		capture := testTwoRecordHeaderCapture(t, leg)
		honestFirst, _ := capture.part(t, 3)
		honestSecond, _ := capture.part(t, 4)
		_, firstWitness := capture.part(t, 3)
		_, secondWitness := capture.part(t, 4)
		version := honestFirst.session.version
		first := string(clientContent(version, firstWitness.clientPlaintexts[1]))
		second := string(clientContent(version, secondWitness.clientPlaintexts[0]))
		block := first + second
		cut := len(first)
		crlf := strings.LastIndex(block[:cut], "\r\n")
		shapes := []*partShape{testFitShape(t, honestFirst, 8), testFitShape(t, honestSecond, 8)}
		for i, shape := range shapes {
			// room for a record a few blocks longer than the honest one
			shape.headBlocks += map[bool]int{true: 8}[0 < shape.headBlocks]
			shape.restBlocks += map[bool]int{true: 8}[0 < shape.restBlocks]
			shapes[i] = shape
		}
		compiled := []constraint.ConstraintSystem{testCompileShape(t, shapes[0]), testCompileShape(t, shapes[1])}
		cases := []struct {
			name   string
			first  string
			second string
			accept bool
		}{
			{name: "the sender's cut", first: first, second: second, accept: true},
			{name: "a cut 40 octets later", first: block[:cut+40], second: block[cut+40:], accept: true},
			{name: "a CR ending the first record", first: block[:crlf+1], second: block[crlf+1:], accept: true},
			{name: "an LF ending the first record", first: block[:crlf+2], second: block[crlf+2:], accept: true},
			{name: "a second Message-ID across the boundary", first: block[:crlf+2] + "Message-I", second: "D: <evil@victim.example>\r\n" + block[crlf+2:]},
			{name: "a continuation after a single field ending the first record",
				first:  strings.Replace(block[:crlf+2], literalFeedbackPrefix+capture.statements[0].session.preamble.feedbackId+literalCrlf, "", 1) + literalFeedbackPrefix + capture.statements[0].session.preamble.feedbackId + literalCrlf,
				second: " continued\r\n" + block[crlf+2:]},
		}
		for _, c := range cases {
			statements, witnesses := testAuthorHeaderRecords(t, capture, c.first, c.second)
			accepted := true
			for i := range statements {
				if 0 < len(relationCheckPart(statements[i], witnesses[i])) {
					accepted = false
				}
			}
			if accepted != c.accept {
				t.Errorf("%s: %s: the relation says %t", leg.name, c.name, accepted)
			}
			solved := true
			for i := range statements {
				circuit, err := partAssignment(shapes[i], statements[i])
				if err != nil {
					t.Fatalf("%s: %s: part %d: %v", leg.name, c.name, statements[i].index, err)
				}
				assignWitness(circuit, statements[i], witnesses[i])
				if err := testSolved(t, compiled[i], circuit); err != nil {
					solved = false
				}
			}
			if solved != c.accept {
				t.Errorf("%s: %s: the circuit says %t", leg.name, c.name, solved)
			}
		}
		// a carry the part before did not publish: the state opened is the true one or nothing
		statements, witnesses := testAuthorHeaderRecords(t, capture, first, second)
		witnesses[1].carryInState ^= 1 << scanNameShift
		if failures := relationCheckPart(statements[1], witnesses[1]); len(failures) != 1 || failures[0].check != checkZ5 {
			t.Errorf("%s: a forged carry in: the relation says %v", leg.name, failures)
		}
		circuit, err := partAssignment(shapes[1], statements[1])
		if err != nil {
			t.Fatal(err)
		}
		assignWitness(circuit, statements[1], witnesses[1])
		if err := testSolved(t, compiled[1], circuit); err == nil {
			t.Errorf("%s: a forged carry in: the circuit accepted", leg.name)
		}
	}
}
