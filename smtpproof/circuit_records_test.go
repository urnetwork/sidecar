// Z2 to Z4 in the circuit beside the relation: one command per record, each opened against the
// template its public length fixes (SPEC.md 4.2 and section 5). Every case goes through
// relationCheckPart and the constraint solver alike, and both must give the answer the case expects,
// so a circuit that refuses what the relation accepts, or the reverse, fails here as a bug in one of
// the two. The shapes leave Z1 out and take the keys as a witness: Z1 has tests of its own, and what
// is under test is the opening of records against their templates.

package smtpproof

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark/constraint"
)

// The smallest test shape, Z1 left out, whose blocks hold a statement's records, plus slack more of
// each kind of block the statement uses, so that mutations of one length share one compile.
func testFitShape(t *testing.T, statement *partStatement, slack int) *partShape {
	t.Helper()
	shape, err := testShapeFitting(statement, slack, 1)
	if err != nil {
		t.Fatal(err)
	}
	return shape
}

// As testFitShape, each count of blocks then rounded up to a multiple of round, or an error for a
// statement whose records have no roles, which no shape could take.
func testShapeFitting(statement *partStatement, slack int, round int) (*partShape, error) {
	session := statement.session
	shape := &partShape{kind: partKindOf(statement), version: session.version, suite: session.suite, withoutKeySchedule: true}
	blockBytes := shape.blockBytes()
	roles, err := partRoles(statement)
	if err != nil {
		return nil, err
	}
	blocks := func(record *partRecord) (int, error) {
		ciphertext, err := recordCiphertext(session.version, record.raw)
		if err != nil {
			return 0, err
		}
		return (len(ciphertext) + blockBytes - 1) / blockBytes, nil
	}
	for i, role := range roles {
		count, err := blocks(statement.clientRecords[i])
		if err != nil {
			return nil, err
		}
		switch role {
		case recordRoleHeaderBlock:
			shape.headerBlocks += count
		case recordRoleBody:
			shape.bodyBlocks += count
		default:
			shape.clientBlocks += count
			if role == recordRoleMail || role == recordRoleRcpt {
				shape.localOctets = true
			}
		}
	}
	for _, record := range statement.serverRecords {
		count, err := blocks(record)
		if err != nil {
			return nil, err
		}
		shape.serverBlocks += count
	}
	for _, count := range []*int{&shape.clientBlocks, &shape.serverBlocks, &shape.headerBlocks, &shape.bodyBlocks} {
		if 0 < *count {
			*count = (*count + slack + round - 1) / round * round
		}
	}
	return shape, nil
}

// Holds the relation and the circuit to one answer for a statement and witness, and the relation, when
// checks is set, to failing exactly those checks. A part its shape cannot be assigned has no template
// any plaintext of its records' lengths could fill, which the edge refuses before any proof (SPEC.md
// reading 23), so it counts as the circuit's refusal.
func testCircuitAgrees(t *testing.T, name string, shape *partShape, compiled constraint.ConstraintSystem, statement *partStatement, witness *partWitness, accept bool, checks ...relationCheck) {
	t.Helper()
	failures := relationCheckPart(statement, witness)
	if (len(failures) == 0) != accept {
		t.Errorf("%s: the relation says %v, want accepted %t", name, failures, accept)
	}
	if 0 < len(checks) {
		var named []relationCheck
		for _, failure := range failures {
			named = append(named, failure.check)
		}
		if fmt.Sprint(named) != fmt.Sprint(checks) {
			t.Errorf("%s: the relation names %v, want %v", name, named, checks)
		}
	}
	circuit, err := partAssignment(shape, statement)
	if err != nil {
		if accept {
			t.Errorf("%s: no assignment: %v", name, err)
		}
		return
	}
	assignWitness(circuit, statement, witness)
	if err := testPartSolved(t, compiled, circuit); (err == nil) != accept {
		t.Errorf("%s: the circuit says %v, want accepted %t", name, err, accept)
	}
}

// Replaces client record i's whole plaintext, 1.3's type octet and any padding included, under the
// true key: what a malicious sidecar can send.
func testAuthorClientPlaintext(t *testing.T, statement *partStatement, witness *partWitness, i int, plaintext []byte) {
	t.Helper()
	witness.clientPlaintexts[i] = plaintext
	testSeal(t, statement, statement.clientRecords[i], witness.clientKey, witness.clientIv, plaintext)
}

// Recipients' local parts r0, r1 and so on.
func testRecipientLocals(count int) []string {
	locals := make([]string, 0, count)
	for i := range count {
		locals = append(locals, "r"+strconv.Itoa(i))
	}
	return locals
}

func TestEnvelopeCircuitAcceptsOneTenAndAHundredRecipients(t *testing.T) {
	t.Parallel()
	// D-SMTP-16's ten, one, and smtp_recipients_per_message's most, 100 on Team (§20.4). A shape for
	// 100 is a test's here: partShapes holds about ten (SPEC.md 10.4), and this shows that nothing in
	// the pool or its templates depends on the count. A hundred under AES is a 3.8M-constraint compile,
	// so those circuits are dropped after use rather than kept for other tests, and run on one leg of
	// each block size: 1.2 frames each record as 1.3 does but for its nonce, which ten already cover
	testNeedCircuits(t)
	for _, count := range []int{1, 10, 100} {
		legs := testTlsLegs()
		if 10 < count {
			legs = legs[:2]
		}
		for _, leg := range legs {
			name := fmt.Sprintf("%s, %d recipients", leg.name, count)
			capture := testCapture(t, leg, testMxDefaults(), DefaultProverSettings(), testJob("one line\r\n", testRecipientLocals(count)...))
			for _, index := range []uint32{1, 2} {
				statement, witness := capture.part(t, index)
				if index == 2 && len(statement.clientRecords) != 1+count {
					t.Fatalf("%s: part 2 opens %d records", name, len(statement.clientRecords))
				}
				shape := testFitShape(t, statement, 0)
				var compiled constraint.ConstraintSystem
				if 10 < count {
					compiled = testCompile(t, newPartCircuit(shape))
				} else {
					compiled = testCompileShape(t, shape)
				}
				testCircuitAgrees(t, fmt.Sprintf("%s, part %d", name, index), shape, compiled, statement, witness, true)
			}
		}
	}
}

// One malicious client record, or an honest twin, with what the relation and the circuit must say.
type testRecordCase struct {
	name string
	// Which part, and which of its records, the case rewrites, under the true key.
	index  uint32
	record int
	// The record's content, to which 1.3's type octet is appended, or its whole plaintext.
	content   string
	plaintext []byte
	// The preamble's flags, OR'ed in.
	flags  uint32
	data   bool
	accept bool
	// What the relation must name, when set.
	checks []relationCheck
	// 1.2 has no inner type octet, so padding and other inner types are 1.3's alone.
	tls13Only bool
}

func testRecordCases() []*testRecordCase {
	rcpt := func(path string) string { return "RCPT TO:<" + path + ">\r\n" }
	mail := func(path string, parameters string) string { return "MAIL FROM:<" + path + ">" + parameters + "\r\n" }
	sender := "bounce-1@" + testEnvelopeDomain
	return []*testRecordCase{
		{name: "an honest EHLO", index: 1, record: 0, content: literalEhloPrefix + testHeloName + literalCrlf, accept: true},
		{name: "HELO for EHLO", index: 1, record: 0, content: "HELO " + testHeloName + literalCrlf, checks: []relationCheck{checkZ4}},
		{name: "another HELO name of the same length", index: 1, record: 0, content: literalEhloPrefix + "x" + testHeloName[1:] + literalCrlf, checks: []relationCheck{checkZ4}},

		{name: "an honest RCPT", index: 2, record: 1, content: rcpt("bob@" + testRecipientDomain), accept: true},
		{name: "a second recipient domain of the same length", index: 2, record: 1, content: rcpt("bob@x" + testRecipientDomain[1:]), checks: []relationCheck{checkZ4}},
		{name: "a second recipient domain of another length", index: 2, record: 1, content: rcpt("bob@another-domain.example"), checks: []relationCheck{checkZ4}},
		{name: "a percent route", index: 2, record: 1, content: rcpt("bob%other.example@" + testRecipientDomain), checks: []relationCheck{checkZ4}},
		{name: "a bang route", index: 2, record: 1, content: rcpt("other.example!bob@" + testRecipientDomain), checks: []relationCheck{checkZ4}},
		{name: "a source route", index: 2, record: 1, content: rcpt("@other.example:bob@" + testRecipientDomain), checks: []relationCheck{checkZ4}},
		{name: "a quoted local part", index: 2, record: 1, content: rcpt("\"bob carol\"@" + testRecipientDomain), checks: []relationCheck{checkZ4}},
		{name: "two paths in one RCPT", index: 2, record: 1, content: "RCPT TO:<x@other.example>,<bob@" + testRecipientDomain + ">\r\n", checks: []relationCheck{checkZ4}},
		{name: "two RCPT commands in one record", index: 2, record: 1, content: rcpt("bob@"+testRecipientDomain) + rcpt("carol@"+testRecipientDomain), checks: []relationCheck{checkZ4}},
		{name: "MAIL and RCPT in one record", index: 2, record: 0, content: mail(sender, "") + rcpt("bob@"+testEnvelopeDomain), checks: []relationCheck{checkZ4}},
		{name: "an RCPT in lower case", index: 2, record: 1, content: "rcpt to:<bob@" + testRecipientDomain + ">\r\n", checks: []relationCheck{checkZ4}},
		{name: "a local part of 64 octets", index: 2, record: 1, content: rcpt(strings.Repeat("b", 64) + "@" + testRecipientDomain), accept: true},
		{name: "a local part of 65 octets", index: 2, record: 1, content: rcpt(strings.Repeat("b", 65) + "@" + testRecipientDomain), checks: []relationCheck{checkZ4}},
		{name: "an empty local part", index: 2, record: 1, content: rcpt("@" + testRecipientDomain), checks: []relationCheck{checkZ4}},
		{name: "a padded RCPT", index: 2, record: 1, plaintext: append([]byte(rcpt("bob@"+testRecipientDomain)), tlsRecordApplicationData, 0), checks: []relationCheck{checkZ3, checkZ4}, tls13Only: true},
		{name: "an RCPT of another inner type", index: 2, record: 1, plaintext: append([]byte(rcpt("bob@"+testRecipientDomain)), tlsRecordHandshake), checks: []relationCheck{checkZ3}, tls13Only: true},

		{name: "an honest MAIL", index: 2, record: 0, content: mail(sender, ""), accept: true},
		{name: "a MAIL naming another domain", index: 2, record: 0, content: mail("bounce-1@x"+testEnvelopeDomain[1:], ""), checks: []relationCheck{checkZ4}},
		{name: "a MAIL with a parameter", index: 2, record: 0, content: mail(sender, " SIZE=100"), checks: []relationCheck{checkZ4}},
		{name: "REQUIRETLS without the flag", index: 2, record: 0, content: mail(sender, literalRequireTls), checks: []relationCheck{checkZ4}},
		{name: "REQUIRETLS with the flag", index: 2, record: 0, content: mail(sender, literalRequireTls), flags: preambleFlagRequireTls, accept: true},
		{name: "the flag without REQUIRETLS", index: 2, record: 0, content: mail(sender, ""), flags: preambleFlagRequireTls, checks: []relationCheck{checkZ4}},
		{name: "the flag with another parameter beside REQUIRETLS", index: 2, record: 0, content: mail(sender, literalRequireTls+" SIZE=1"), flags: preambleFlagRequireTls, checks: []relationCheck{checkZ4}},

		{name: "an honest DATA", index: 2, record: 3, content: literalData, data: true, accept: true},
		{name: "DATB for DATA", index: 2, record: 3, content: "DATB\r\n", data: true, checks: []relationCheck{checkZ4}},
		{name: "DATA in lower case", index: 2, record: 3, content: "data\r\n", data: true, checks: []relationCheck{checkZ4}},
		{name: "RSET in DATA's place", index: 2, record: 3, content: "RSET\r\n", data: true, checks: []relationCheck{checkZ4}},
		{name: "a second MAIL in DATA's place", index: 2, record: 3, content: mail(sender, ""), data: true, checks: []relationCheck{checkZ4}},

		{name: "RSET in QUIT's place", index: 3, record: 2, content: "RSET\r\n", checks: []relationCheck{checkZ6}},
	}
}

func TestRecordCircuitAgreesWithTheRelation(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		envelope, envelopeCompiled := testEnvelopeCircuit(t, leg)
		message := testQuickMessageShape(leg.suites[0], 0)
		messageCompiled := testCompileShape(t, message)
		ehlo := testQuickShape(leg.suites[0], false)
		ehloCompiled := testCompileShape(t, ehlo)
		captures := map[bool]*testCapturedParts{false: testBdatCapture(t, leg), true: testDataCapture(t, leg)}
		for _, c := range testRecordCases() {
			if c.tls13Only && leg.suites[0] == tlsSuiteEcdheEcdsaAes128GcmSha256 {
				continue
			}
			statement, witness := captures[c.data].part(t, c.index)
			statement.session.preamble.flags |= c.flags
			if c.plaintext != nil {
				testAuthorClientPlaintext(t, statement, witness, c.record, bytes.Clone(c.plaintext))
			} else {
				testAuthorClientRecord(t, statement, witness, c.record, []byte(c.content))
			}
			shape, compiled := envelope, envelopeCompiled
			switch c.index {
			case 1:
				shape, compiled = ehlo, ehloCompiled
			case 3:
				shape, compiled = message, messageCompiled
			}
			testCircuitAgrees(t, leg.name+": "+c.name, shape, compiled, statement, witness, c.accept, c.checks...)
		}
	}
}

func TestRecordCircuitChecksTheChunkCount(t *testing.T) {
	t.Parallel()
	// Z4's BDAT n is message_byte_count's decimal: another count of the same length is a literal off,
	// and one of another length no template of that length can hold
	for _, leg := range testTlsLegs() {
		shape := testQuickMessageShape(leg.suites[0], 0)
		compiled := testCompileShape(t, shape)
		capture := testBdatCapture(t, leg)
		honest, _ := capture.part(t, 3)
		count := strconv.FormatUint(honest.session.preamble.messageByteCount, 10)
		changed := count[:len(count)-1] + string('0'+(count[len(count)-1]-'0'+1)%10)
		for _, c := range []struct {
			name    string
			content string
			accept  bool
		}{
			{name: "the declared count", content: literalBdatPrefix + count + literalBdatSuffix, accept: true},
			{name: "another count of the same length", content: literalBdatPrefix + changed + literalBdatSuffix},
			{name: "the count with a leading zero", content: literalBdatPrefix + "0" + count + literalBdatSuffix},
			{name: "the count one octet short", content: literalBdatPrefix + count[1:] + literalBdatSuffix},
			{name: "a chunk that is not the last", content: literalBdatPrefix + count + " LAZT\r\n"},
		} {
			statement, witness := capture.part(t, 3)
			testAuthorClientRecord(t, statement, witness, 0, []byte(c.content))
			testCircuitAgrees(t, leg.name+": "+c.name, shape, compiled, statement, witness, c.accept)
		}
	}
}

func TestRecordTemplatesHoldALocalPartOfOneToSixtyFourOctets(t *testing.T) {
	// SPEC.md section 5: a record whose length leaves the local part outside 1 to 64 octets has no
	// template, so no shape takes the part, and the edge refuses it before verifying anything
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		for _, c := range []struct {
			local  int
			assign bool
		}{
			{local: 0},
			{local: 1, assign: true},
			{local: 64, assign: true},
			{local: 65},
		} {
			statement, witness := capture.part(t, 2)
			testAuthorClientRecord(t, statement, witness, 1, []byte("RCPT TO:<"+strings.Repeat("b", c.local)+"@"+testRecipientDomain+">\r\n"))
			_, err := clientRecordTemplate(statement.session, recordRoleRcpt, statement.clientRecords[1])
			if (err == nil) != c.assign {
				t.Errorf("%s: a %d-octet local part: template %v", leg.name, c.local, err)
			}
			if _, err := partShapeFor(statement); (err == nil) != c.assign {
				t.Errorf("%s: a %d-octet local part: shape %v", leg.name, c.local, err)
			}
			if failures := relationCheckPart(statement, witness); (len(failures) == 0) != c.assign {
				t.Errorf("%s: a %d-octet local part: the relation says %v", leg.name, c.local, failures)
			}
		}
	}
}

// What one block of the client pool costs, SPEC.md 11.2's measured rows, held here: two shapes a
// block apart, Z1 left out, so the difference is one keystream block and its octets' opening and
// template, with the local table (an envelope's pool) and without it (pi1's and pi3's).
var testSpecPoolBlockCosts = map[string]int{
	"aes, local table":        12545,
	"aes, literals only":      11969,
	"chacha20, local table":   25345,
	"chacha20, literals only": 23041,
}

func TestRecordPoolCostIsSpecMds(t *testing.T) {
	t.Parallel()
	for _, suite := range []uint16{tlsSuiteAes128GcmSha256, tlsSuiteChacha20Poly1305Sha256} {
		for _, local := range []bool{true, false} {
			shape := &partShape{kind: partKindEhlo, version: tlsVersion13, suite: suite, clientBlocks: 2, withoutKeySchedule: true}
			name := "aes"
			keystream := testSpecGadgetSizes["aes keystream block"]
			if suite == tlsSuiteChacha20Poly1305Sha256 {
				name = "chacha20"
				keystream = testSpecGadgetSizes["chacha20 keystream block"]
			}
			if local {
				shape.kind = partKindEnvelope
				shape.serverBlocks = 1
				shape.localOctets = true
				name += ", local table"
			} else {
				name += ", literals only"
			}
			wider := *shape
			wider.clientBlocks += 1
			cost := testCompileShape(t, &wider).GetNbConstraints() - testCompileShape(t, shape).GetNbConstraints()
			t.Logf("%s: a pool block costs %d constraints, %d beyond the keystream, %.1f an octet", name, cost, cost-keystream, float64(cost-keystream)/float64(shape.blockBytes()))
			if want := testSpecPoolBlockCosts[name]; cost != want {
				t.Errorf("%s: a pool block costs %d constraints, SPEC.md 11.2 says %d", name, cost, want)
			}
		}
	}
}

func TestSpecMdNamesEveryProductionShape(t *testing.T) {
	// SMTP-M9-22: the classes are stated in SPEC.md 10.4, one row per shape by its KeySet name, and the
	// count in its first paragraph, so the document cannot drift from partShapes unseen
	spec, err := os.ReadFile("SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(spec, []byte("### 10.4 Shapes\n"))
	end := bytes.Index(spec, []byte("## 11. Costs\n"))
	if start < 0 || end < start {
		t.Fatal("SPEC.md has no section 10.4 before section 11")
	}
	section := string(spec[start:end])
	var stated []string
	for _, match := range regexp.MustCompile("`(kind[0-9]+-v[0-9a-f]{4}-s[0-9a-f]{4}-client[0-9]+-server[0-9]+-header[0-9]+-body[0-9]+-local(?:true|false))`").FindAllStringSubmatch(section, -1) {
		stated = append(stated, match[1])
	}
	var built []string
	for _, shape := range partShapes() {
		built = append(built, partShapeName(shape))
	}
	slices.Sort(stated)
	slices.Sort(built)
	if !slices.Equal(stated, built) {
		t.Errorf("SPEC.md 10.4 names %v, partShapes %v", stated, built)
	}
	if !strings.Contains(section, "this build's "+strconv.Itoa(len(built))+".") {
		t.Errorf("SPEC.md 10.4 does not say this build has %d shapes", len(built))
	}
}
