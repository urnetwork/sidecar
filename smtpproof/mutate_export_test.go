// What the mutation table's cells of DESIGN-DETAILS 3.6 need beyond export_test.go's bridge: sends whose
// header block takes two records, the first ending at a chosen octet of what follows the single fields and
// the fixed signature, and sends of a chosen body, through this package's MX or one of sidecartest's; the
// state every scan starts from; whether a header or body record's scan passes from a state on its own; and
// the kind the gate gives each part. Compiled only into this package's tests.

package smtpproof

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The state every scan starts from (DESIGN-DETAILS 3.2.4), which a forged carry in claims.
const ExportScanStart = uint32(scanStart)

// The body ExportCapture sends.
const testExportBody = "one line\r\nanother line\r\nand a third\r\n"

// The split-name header block's tail, and how far into its first field's name the first record ends.
const (
	testSplitNameTail   = "X-Spanning-Name: a field whose name the first record's end cuts\r\nX-Tail: the rest of the header block\r\n"
	testSplitNameOctets = 5
)

// The TLS version a suite runs under.
func testSuiteVersion(suite uint16) uint16 {
	if suite == tlsSuiteAes128GcmSha256 || suite == tlsSuiteChacha20Poly1305Sha256 {
		return tlsVersion13
	}
	return tlsVersion12
}

// The octets of a header block's first record under a suite: what its family's msg shape's head holds,
// which is headerSplit's first size.
func testHeadBytes(suite uint16) int {
	shape := DefaultProofSettings().shape(ShapeKindMessage, suiteFamily(suite), 0)
	return shape.recordContentBytes(shape.HeadBlocks, testSuiteVersion(suite))
}

// A header block of two records under a suite whose first record ends cut octets into tail: the single
// fields and the fixed signature first, as SMTP-M9-04 orders them, one filler line that brings tail's
// start to cut octets before the first record's end, tail, whose lines end in CRLF, and the final CRLF.
func testCutHeaderBlock(suite uint16, tail string, cut int) string {
	base := strings.TrimSuffix(testHeaderBlock(), "\r\n")
	prefix := "X-Filler: "
	filler := testHeadBytes(suite) - cut - len(base) - len(prefix) - len("\r\n")
	if filler < 0 {
		return ""
	}
	return base + prefix + strings.Repeat("f", filler) + "\r\n" + tail + "\r\n"
}

// The header block ExportCutHeaderCapture sends on a leg; empty when the cut is too far into tail for
// any filler.
func ExportCutHeaderBlock(legIndex int, tail string, cut int) string {
	leg := testTlsLegs()[legIndex%len(testTlsLegs())]
	return testCutHeaderBlock(leg.suites[0], tail, cut)
}

// A header block of two records on a leg whose first record ends with the line of the single field
// named, moved there from its place among the others, then a field after it in the second record: the
// scan's state at the cut is a line's start just after a single field's line. Empty for a name testHeaderBlock
// has no line of.
func ExportSingleEndsHeaderBlock(legIndex int, name string) string {
	leg := testTlsLegs()[legIndex%len(testTlsLegs())]
	var line string
	var kept []string
	for _, candidate := range strings.SplitAfter(strings.TrimSuffix(testHeaderBlock(), "\r\n"), "\r\n") {
		switch {
		case strings.HasPrefix(candidate, name+":"):
			line = candidate
		case candidate != "":
			kept = append(kept, candidate)
		}
	}
	rest := strings.Join(kept, "")
	prefix := "X-Filler: "
	filler := testHeadBytes(leg.suites[0]) - len(rest) - len(prefix) - len("\r\n") - len(line)
	if line == "" || filler < 0 {
		return ""
	}
	return rest + prefix + strings.Repeat("f", filler) + "\r\n" + line + "X-After: a field after the first record\r\n\r\n"
}

// testJob's job carrying message whole in place of its own.
func testMessageJob(message string, data bool) *sidecar.SmtpProofJob {
	job := testJob("", "bob", "carol")
	job.Message = []byte(message)
	job.Preamble.MessageByteCount = uint64(len(job.Message))
	if data {
		job.Preamble.MessageByteCount = uint64(len(dotStuffed(job.Message)))
	}
	return job
}

// Fails unless the part that names the header block's record count names want.
func testExpectHeaderRecords(t *testing.T, name string, parts []*sidecar.SmtpProofPart, want uint32) {
	t.Helper()
	for _, part := range parts {
		if part.HeaderRecordCount != 0 {
			if part.HeaderRecordCount != want {
				t.Fatalf("%s: the header block takes %d records, want %d", name, part.HeaderRecordCount, want)
			}
			return
		}
	}
	t.Fatalf("%s: no part names the header block's record count", name)
}

// As ExportCapture, sending message whole, its header block in headerRecords records.
func ExportMessageCapture(t *testing.T, legIndex int, data bool, message string, headerRecords uint32) *ExportedCapture {
	t.Helper()
	leg := testTlsLegs()[legIndex%len(testTlsLegs())]
	settings := DefaultProverSettings()
	if data {
		settings.ForceData = true
		settings.testDataRecordByteCount = 12
	}
	job := testMessageJob(message, data)
	send := testRunSend(t, leg, testMxDefaults(), settings, job)
	testExpectOneTransaction(t, leg, send, job)
	testExpectHeaderRecords(t, leg.name, send.edge.parts, headerRecords)
	fixture := &testGateFixture{leg: leg, preamble: newSessionPreamble(job.Preamble, DefaultProofSettings()), trace: send.edge.trace, parts: send.edge.parts}
	return exportCapture(t, fixture, job, send.backend)
}

// As ExportCapture, with a header block of two records whose first ends cut octets into tail.
func ExportCutHeaderCapture(t *testing.T, legIndex int, data bool, tail string, cut int) *ExportedCapture {
	t.Helper()
	block := ExportCutHeaderBlock(legIndex, tail, cut)
	if block == "" {
		t.Fatalf("no header block ends its first record %d octets into its tail", cut)
	}
	return ExportMessageCapture(t, legIndex, data, block+testExportBody, 2)
}

// As ExportCapture, with the header block in two records, the first ending inside a field's name.
func ExportSplitNameCapture(t *testing.T, legIndex int, data bool) *ExportedCapture {
	t.Helper()
	return ExportCutHeaderCapture(t, legIndex, data, testSplitNameTail, testSplitNameOctets)
}

// As ExportCapture, with the header block of ExportCapture's message and body in its place.
func ExportBodyCapture(t *testing.T, legIndex int, data bool, body string) *ExportedCapture {
	t.Helper()
	return ExportMessageCapture(t, legIndex, data, testHeaderBlock()+body, 1)
}

// As ExportMxCapture, with the header block in two records, the first ending inside a field's name.
func ExportSplitNameMxCapture(t *testing.T, legName string, data bool, mx sidecartest.MxServer) *ExportedCapture {
	t.Helper()
	var leg *testMxLeg
	for _, candidate := range testMxLegs() {
		if candidate.name == legName {
			leg = candidate
		}
	}
	if leg == nil {
		t.Fatalf("no leg %s", legName)
	}
	job := testMessageJob(testCutHeaderBlock(leg.suite, testSplitNameTail, testSplitNameOctets)+testExportBody, data)
	send := testRunSendToMx(t, leg.suites, mx, testMxModeSettings(data), job)
	if send.err != nil || !send.result.Accepted {
		t.Fatalf("%s: %+v, %v (edge: %v)", legName, send.result, send.err, send.edge.failure())
	}
	testExpectHeaderRecords(t, legName, send.edge.parts, 2)
	fixture := &testGateFixture{leg: &testTlsLeg{name: leg.name}, preamble: newSessionPreamble(job.Preamble, DefaultProofSettings()), trace: send.edge.trace, parts: send.edge.parts}
	return exportCapture(t, fixture, job, send.backend)
}

// A verifier that names each part's kind as the gate reads it, and passes a part only where the relation
// does, so that a replay of an honest capture runs to its end.
type exportedKindVerifier struct {
	witness *partWitness
	kinds   map[uint32]string
}

func (self *exportedKindVerifier) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	roles, err := partRoles(statement)
	if err != nil {
		return err
	}
	kind, err := partKindOf(statement, roles)
	if err != nil {
		return err
	}
	self.kinds[statement.index] = map[partKind]string{
		partKindKey:      string(ShapeKindKey),
		partKindEnvelope: string(ShapeKindEnvelope),
		partKindMessage:  string(ShapeKindMessage),
		partKindHeader:   string(ShapeKindHeader),
		partKindBody:     string(ShapeKindBody),
	}[kind]
	if self.witness == nil || 0 < len(relationCheckPart(statement, self.witness)) {
		return errors.New("the relation refuses the part")
	}
	return nil
}

// The kind DESIGN-DETAILS 3.2.5's step 8 gives each part of a capture, by index, as its catalog shape names
// it ("key", "env", "msg", "hdr" or "body"), for the parts a fresh gate takes before it first refuses.
func ExportPartKinds(capture *ExportedCapture) map[uint32]string {
	preamble := newSessionPreamble(capture.Preamble, DefaultProofSettings())
	verifier := &exportedKindVerifier{kinds: map[uint32]string{}}
	if checkSessionPreamble(preamble) != nil {
		return verifier.kinds
	}
	gate := newEdgeSession(defaultEdgeSettings(), preamble, capture.Preamble.MxHost, verifier)
	for i, event := range capture.Events {
		var err error
		switch {
		case event.Part != nil:
			verifier.witness = nil
			if witness := capture.Witnesses[i]; witness != nil {
				verifier.witness = importedWitness(witness)
			}
			_, err = gate.VerifyPart(context.Background(), event.Part)
		case event.Shts != nil:
			_, err = gate.DiscloseShts(event.Shts)
		case event.ClientRecord != nil:
			_, err = gate.ClientRecord(event.ClientRecord)
		default:
			err = gate.ServerRecord(event.ServerRecord)
		}
		if err != nil {
			break
		}
	}
	return verifier.kinds
}

// Whether the header or body record a part opens scans to its end from the given state on its own, by
// DESIGN-DETAILS 3.2.4's rules for that record and nothing else: no carry is opened. A mutation that forges
// a carry's opening uses it to show that the carry, and not the scan, is what refuses.
func ExportRecordScansFrom(capture *ExportedCapture, index uint32, state uint32) bool {
	preamble := newSessionPreamble(capture.Preamble, DefaultProofSettings())
	version := tlsVersion13
	var witness *ExportedWitness
	var part *sidecar.SmtpProofPart
	headerCount := uint32(0)
	for i, event := range capture.Events {
		if event.Part == nil {
			continue
		}
		if event.Part.HeaderRecordCount != 0 {
			headerCount = event.Part.HeaderRecordCount
		}
		if event.Part.Index == 1 && event.Part.FirstRecord == 1 {
			version = tlsVersion12
		}
		if event.Part.Index == index {
			part, witness = event.Part, capture.Witnesses[i]
		}
	}
	if part == nil || witness == nil {
		return false
	}
	headerFirst := firstApplicationSeq(version) + 3 + uint64(preamble.recipientCount)
	for i, plaintext := range witness.ClientPlaintexts {
		seq := part.FirstRecord + uint64(i)
		content := clientContent(version, plaintext)
		switch {
		case seq < headerFirst:
		case seq < headerFirst+uint64(headerCount):
			ordinal := seq - headerFirst + 1
			_, err := scanHeaderRecord(preamble, content, scanState(state), ordinal == 1, ordinal == uint64(headerCount))
			return err == nil
		case part.Mode == partModeData:
			_, err := scanBodyRecord(content, scanState(state), part.Last)
			return err == nil
		}
	}
	return false
}
